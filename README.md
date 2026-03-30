# auto_nxc
> Automated nmap → NetExec pipeline for internal penetration tests.  
> Scan a scope, extract live hosts per protocol, pre-check credentials, and run all relevant NetExec modules concurrently — with structured JSON/CSV output.

---

## Overview

`nmap2nxc` is a two-stage automation toolkit for internal network assessments:

| Script | Language | Purpose |
|--------|----------|---------|
| `nmap_scan.sh` | Bash | Runs nmap against a scope file, saves per-host output to `nmap/` |
| `nxc_scan.py` | Python 3 | Reads nmap output, extracts hosts by protocol, runs NetExec modules concurrently |

Designed to be run sequentially on an internal engagement:

```
scope.txt  →  nmap_scan.sh  →  nmap/  →  nxc_scan.py  →  netexecscan/
```

---

## Features

### nmap_scan.sh
- Reads IPs, CIDRs, and FQDNs from `scope.txt` — one per line, `#` comments supported
- Runs `nmap -vvv -sT -sC -O -A -Pn -p- -T5` against each target
- Saves output per host to `nmap/<target>` via `-oN`
- Accurate target counter (ignores blanks and comment lines)
- Per-host elapsed time and overall total scan time
- Tracks and summarises failed targets at the end

### nxc_scan.py
- Parses nmap output and extracts hosts per protocol: SMB, LDAP, MSSQL, SSH, WinRM, RDP, FTP, WMI, VNC, NFS
- Interactive wizard **or** full CLI — no prompts needed for automation
- Authentication: password · NTLM hash (PtH) · Kerberos ccache · auto-generate TGT
- Pre-auth check per protocol before running modules
- **Concurrent module execution** via `ThreadPoolExecutor` (default 6 workers)
- SMB tiered: low-privilege only or all modules (admin: SAM, LSA, NTDS, lsassy, etc.)
- Auto-detects attacker IP (`tun0` → `eth0` → fallback) for `coerce_plus`
- `coerce_plus` in two passes: check-only (no traffic), then active with listener IP
- Optional Responder or ntlmrelayx listener launched in background
- **Structured output**: one `.txt` per module + `scan_report.json` + `scan_report.csv`

---

## Requirements

```
nmap
netexec (nxc)    # https://github.com/Pennyw0rth/NetExec
python3 >= 3.10
bash >= 4.0
responder        # optional — coerce capture
impacket         # optional — ntlmrelayx relay
```

No Python dependencies beyond the standard library.

---

## Installation

```bash
git clone https://github.com/gpheheise/nmap2nxc
cd nmap2nxc
chmod +x nmap_scan.sh
```

---

## Usage

### Stage 1 — nmap_scan.sh

Create `scope.txt` with one target per line:

```
# Internal scope
10.10.10.0/24
192.168.1.50
dc01.corp.local
```

Run as root (required for `-O` OS detection):

```bash
sudo ./nmap_scan.sh
```

Output is saved to `nmap/<target>` — one file per host.

Terminal summary on completion:

```
══════════════════════════════════════════════
[*] All scans complete
[*] Results saved to : /opt/engagement/nmap/
[*] Targets scanned  : 12/12
[*] Total time       : 00h:41m:08s
[*] Finished         : 2026-03-30 15:03:09

[!] Failed targets (1):
    ✗ 10.10.10.99
══════════════════════════════════════════════
```

---

### Stage 2 — nxc_scan.py

**Interactive wizard:**

```bash
python3 nxc_scan.py
```

The wizard prompts for:
1. nmap results directory
2. Domain (optional, for AD)
3. KDC / DC IP (optional, for Kerberos)
4. Auth mode: password / NTLM hash / Kerberos ccache / generate TGT
5. Local auth toggle
6. SMB scan mode: low-privilege or all (admin) modules
7. Listener IP for `coerce_plus` (auto-detected from `tun0`)
8. Optional listener: none / Responder / ntlmrelayx

**Full CLI (no prompts):**

```bash
# Password auth
python3 nxc_scan.py -u administrator -p 'P@ssw0rd!' -d corp.local --smb-all

# Pass-the-Hash
python3 nxc_scan.py -u administrator -H aad3b435b51404eeaad3b435b51404ee:ntlmhash -d corp.local

# Kerberos ccache
export KRB5CCNAME=/tmp/administrator.ccache
python3 nxc_scan.py -u administrator --use-kcache -d corp.local --kdc 10.10.10.1

# Custom thread count
python3 nxc_scan.py -u administrator -p 'P@ss!' -d corp.local -t 10
```

**All CLI flags:**

```
-u, --username      Username
-p, --password      Password
-H, --hash          NTLM hash (LM:NT or NT only)
    --use-kcache    Use Kerberos ccache (KRB5CCNAME)
-d, --domain        Domain (e.g. corp.local)
    --kdc           KDC / DC IP
    --local-auth    Use --local-auth on all modules
    --smb-all       Run admin SMB modules (SAM, LSA, NTDS, lsassy, etc.)
    --nmap-dir      Path to nmap output (default: nmap)
    --output-dir    Output directory (default: netexecscan)
-t, --threads       Concurrent workers (default: 6)
```

---

## Output

```
nmap/                                        # Stage 1 output
├── 10.10.10.1
├── 10.10.10.5
└── dc01.corp.local

netexecscan/                                 # Stage 2 output
├── open_smb_ports_all_hosts.txt
├── open_ldap_ports_all_hosts.txt
├── open_rdp_ports_all_hosts.txt
├── ...
├── Module_SMB_users.txt
├── Module_SMB_shares.txt
├── Module_SMB_M_lsassy.txt
├── Module_LDAP_kerberoast.txt
├── Module_LDAP_bloodhound.txt
├── Module_SMB_M_coerce_active.txt
├── ...
├── asreproast_hashes.txt
├── kerberoast_hashes.txt
├── relay_targets.txt
├── scan_report.json
└── scan_report.csv
```

---

## SMB Module Tiers

| Tier | Flag | Modules |
|------|------|---------|
| Low-privilege | *(default)* | users, groups, shares, sessions, pass-pol, rid-brute, spider_plus, gpp_password, enum_av, webdav, spooler, vuln checks, coerce_plus |
| Admin | `--smb-all` | SAM, LSA, NTDS, DPAPI, lsassy, nanodump, ntdsutil, msol, veeam, keepass, putty, winscp, wifi, impersonate, teams_localdb |

---

## Protocols Covered

`smb` · `ldap` · `mssql` · `ssh` · `winrm` · `rdp` · `ftp` · `wmi` · `vnc` · `nfs`

NetExec wiki: [https://www.netexec.wiki](https://www.netexec.wiki)

---

## Disclaimer

This tool is intended for **authorised penetration testing and security assessments only**.  
Always ensure you have written permission before scanning any network or system.  
The author accepts no responsibility for unauthorised or illegal use.

---

## Author

**gpheheise** — [github.com/gpheheise](https://github.com/gpheheise)
