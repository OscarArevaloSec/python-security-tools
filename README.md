# Python Security Tools

Python scripts for security enumeration, log analysis, and network reconnaissance. Each script is self-contained with `--help` flags and inline comments explaining the security concept it demonstrates.

Built for use in authorized lab environments — HackTheBox, TryHackMe, and home labs.

---

## Scripts

| Script | Purpose | Status |
|---|---|---|
| `port_scanner.py` | Multi-threaded TCP port scanner with banner grabbing and service hints | ✅ Ready |
| `subdomain_enum.py` | DNS subdomain brute-forcer (dnspython or socket fallback) | ✅ Ready |
| `dir_enum.py` | Web directory and file brute-forcer with status/size filtering | ✅ Ready |
| `smb_enum.py` | SMB share enumeration, null session checks, RPC user/group enum | ✅ Ready |
| `user_enum.py` | Username enumeration via HTTP response analysis or SMB/RID brute force | ✅ Ready |
| `log_parser.py` | Auth.log / syslog / Windows event log parser with brute-force detection | ✅ Ready |
| `hash_checker.py` | Hash files/strings across MD5–SHA512; compare and identify CTF hashes | ✅ Ready |
| `ioc_parser.py` | Extract and defang IOCs (IPs, domains, hashes, URLs, CVEs) from text | ✅ Ready |

---

## Requirements

```
python3 >= 3.10
```

Optional (install for enhanced functionality):

```bash
pip install requests   # dir_enum.py, user_enum.py (HTTP mode)
pip install dnspython  # subdomain_enum.py (faster, more reliable DNS)
sudo apt install smbclient  # smb_enum.py, user_enum.py (SMB mode)
```

---

## Quick Usage

### Port Scanner
```bash
python port_scanner.py --target 10.10.10.10 --ports 1-1024
python port_scanner.py --target 10.10.10.10 --ports 1-65535 --threads 300 --timeout 0.5
python port_scanner.py --target 10.10.10.10 --ports 22,80,443,8080 --output ports.txt
```

### Subdomain Enumeration
```bash
python subdomain_enum.py --domain example.htb --wordlist /usr/share/wordlists/subdomains-top1mil.txt
python subdomain_enum.py --domain target.thm --wordlist subs.txt --threads 50 --output found.txt
```

### Directory Enumeration
```bash
python dir_enum.py --url http://10.10.10.10 --wordlist /usr/share/wordlists/dirb/common.txt
python dir_enum.py --url http://10.10.10.10 --wordlist big.txt --extensions .php,.html,.txt
python dir_enum.py --url http://10.10.10.10 --wordlist raft-medium.txt --status 200,301,302,403
```

### SMB Enumeration
```bash
python smb_enum.py --target 10.10.10.10
python smb_enum.py --target 10.10.10.10 --shares
python smb_enum.py --target 10.10.10.10 --shares --rpc
python smb_enum.py --target 10.10.10.10 --user oscar --password Password1 --shares
```

### User Enumeration
```bash
# SMB null session
python user_enum.py --target 10.10.10.10 --mode smb

# SMB with RID brute force (find users even when enumdomusers is restricted)
python user_enum.py --target 10.10.10.10 --mode smb --rid-brute --rid-range 500-1200

# HTTP login form
python user_enum.py --target 10.10.10.10 --mode http \
  --url http://10.10.10.10/login \
  --wordlist /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
```

### Log Parser
```bash
python log_parser.py --file /var/log/auth.log
python log_parser.py --file /var/log/auth.log --filter failed --brute-threshold 5
python log_parser.py --file auth.log --type auth --output report.txt
```

### Hash Checker
```bash
# Hash a file
python hash_checker.py --file malware_sample.exe --algorithm sha256

# Verify integrity
python hash_checker.py --file download.iso --hash <known_hash> --algorithm sha256

# Hash a string (CTF password cracking)
python hash_checker.py --string "password123" --algorithm all

# Identify an unknown hash
python hash_checker.py --identify 5f4dcc3b5aa765d61d8327deb882cf99
```

### IOC Parser
```bash
python ioc_parser.py --file threat_report.txt
python ioc_parser.py --file malware_log.txt --type ip,url,sha256 --output iocs.txt
python ioc_parser.py --text "attacker at 192.168.1.100 hit https://evil.com"
```

---

## Recommended Wordlists

These scripts work best with [SecLists](https://github.com/danielmiessler/SecLists):

```bash
sudo apt install seclists
# or
git clone https://github.com/danielmiessler/SecLists /opt/SecLists
```

Useful paths:
- Subdomains: `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- Directories: `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
- Usernames: `/usr/share/seclists/Usernames/top-usernames-shortlist.txt`
- Passwords: `/usr/share/seclists/Passwords/Common-Credentials/top-1000.txt`

---

## Disclaimer

These tools are for **educational purposes and authorized testing only**. Never run against systems you do not own or have explicit written permission to test. Unauthorized scanning is illegal.
