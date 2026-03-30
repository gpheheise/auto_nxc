# nmap2nxc

> Automated nmap → NetExec pipeline for internal penetration tests.  
> Scan a scope, extract live hosts per protocol, pre-check credentials, and run all relevant NetExec modules concurrently — with structured JSON/CSV output.

---

## Overview

`nmap2nxc` is a two-stage automation toolkit for internal network assessments:

| Script | Language | Purpose |
|--------|----------|---------|
| `nmap_scan.sh` | Bash | Runs nmap against a scope file, saves per-host output |
| `nxc_scan.py` | Python 3 | Reads nmap output, extracts hosts by protocol, runs NetExec modules concurrently |

Designed to be run sequentially on an internal engagement:

```
scope.txt → nmap_scan.sh → nmap/ → nxc_scan.py → netexecscan/
```

---

## Features

- **nmap_scan.sh**
  - Reads IPs and FQDNs line-by-line from `scope.txt`
  - Runs `nmap -vvv -sT -sC -O -A -Pn -p- -T5`
  - Saves output per host as `nmap/<target>`

- **nxc_scan.py**
  - Parses nmap output and extracts hosts per protocol (SMB, LDAP, MSSQL, SSH, WinRM, RDP, FTP, WMI, VNC, NFS)
  - Interactive wizard **or** full CLI mode — no prompts needed for automation
  - Authentication: password · NTLM hash (PtH) · Kerberos ccache · auto-generate TGT
  - Pre-auth check per protocol before running modules
  - **Concurrent module execution** via `ThreadPoolExecutor` (default 6 workers)
  - SMB tiered: low-privilege only or all modules (admin: SAM, LSA, NTDS, lsassy, etc.)
  - Auto-detects attacker IP (`tun0` → `eth0` → fallback) for `coerce_plus`
  - `coerce_plus` runs in two passes: check-only (no traffic), then active with listener IP
  - Optional Responder or ntlmrelayx listener launched in background
  - **Structured output**: one `.txt` per module + `scan_report.json` + `scan_report.csv`

---

## Requirements

```
nmap
netexec (nxc)       # https://github.com/Pennyw0rth/NetExec
python3 >= 3.10
responder           # optional, for coerce capture
impacket            # optional, for ntlmrelayx
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

### Stage 1 — nmap

Create a `scope.txt` with one IP, CIDR, or FQDN per line:

```
# scope.txt
10.10.10.0/24
192.168.1.50
dc01.corp.local
```

Run the scanner:

```bash
sudo ./nmap_scan.sh
```

Output is saved to `nmap/<target>` — one file per host.

---

### Stage 2 — NetExec modules

**Interactive wizard:**

```bash
python3 nxc_scan.py
```

The wizard prompts for:
1. nmap results directory
2. Domain (optional, for AD)
3. KDC/DC IP (optional, for Kerberos)
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
netexecscan/
├── open_smb_ports_all_hosts.txt     # host lists per protocol
├── open_ldap_ports_all_hosts.txt
├── open_rdp_ports_all_hosts.txt
├── ...
├── Module_SMB_users.txt             # one file per module
├── Module_SMB_shares.txt
├── Module_SMB_M_lsassy.txt
├── Module_LDAP_kerberoast.txt
├── Module_LDAP_bloodhound.txt
├── Module_SMB_M_coerce_active.txt
├── ...
├── asreproast_hashes.txt            # ready for hashcat/john
├── kerberoast_hashes.txt
├── relay_targets.txt                # SMB signing disabled hosts
├── scan_report.json                 # full structured report
└── scan_report.csv                  # flat table, one row per module
```

`scan_report.json` includes per-module metadata:

```json
{
  "label": "SMB_M_lsassy",
  "protocol": "smb",
  "success": true,
  "pwned": true,
  "duration_s": 3.8,
  "output_file": "Module_SMB_M_lsassy.txt"
}
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
