# Python Security Tools

This repository contains small Python scripts for security learning, analyst automation, log review, IOC extraction, hash checking, and authorized lab enumeration. The blue-team purpose is to show that I can use Python to support repeatable investigation workflows.

These scripts are for educational use in authorized labs such as home labs, Hack The Box, TryHackMe, and intentionally vulnerable environments. They must not be used against systems without explicit permission.

## Script Index

| Script | Purpose | Defensive or Learning Value | Status |
|---|---|---|---|
| `log_parser.py` | Parse auth.log, syslog, or Windows-style event logs and identify brute-force patterns. | Supports suspicious-login triage and timeline building. | Ready |
| `ioc_parser.py` | Extract and defang IPs, domains, URLs, hashes, emails, and CVEs from text. | Supports phishing, malware, and threat-intel workflows. | Ready |
| `hash_checker.py` | Hash files or strings and compare known hashes. | Supports file integrity review and malware triage basics. | Ready |
| `port_scanner.py` | Multi-threaded TCP port scanner with banner grabbing. | Supports authorized lab discovery and understanding service exposure. | Ready |
| `subdomain_enum.py` | DNS subdomain brute-forcer with dnspython or socket fallback. | Supports authorized DNS discovery practice. | Ready |
| `dir_enum.py` | Web directory and file brute-forcer with status and size filtering. | Supports web lab enumeration and defensive log-awareness. | Ready |
| `smb_enum.py` | SMB share enumeration and RPC user or group enumeration. | Supports Windows and SMB lab practice. | Ready |
| `user_enum.py` | Username enumeration via HTTP response analysis or SMB/RID brute force. | Supports understanding authentication weaknesses in labs. | Ready |

## Requirements

| Requirement | Notes |
|---|---|
| Python | Python 3.10 or newer is recommended. |
| Optional Python packages | `requests` for HTTP tools and `dnspython` for DNS enumeration. |
| Optional system tools | `smbclient` for SMB workflows. |

Install optional packages only in your own lab environment:

```bash
pip install requests dnspython
sudo apt install smbclient
```

## Blue-Team Workflows

| Workflow | Example Command |
|---|---|
| Suspicious login review | `python log_parser.py --file samples/auth_sample.log --filter failed --brute-threshold 3` |
| IOC extraction from a report | `python ioc_parser.py --file samples/threat_report_sample.txt` |
| File hash verification | `python hash_checker.py --file suspicious.bin --algorithm sha256` |
| Authorized lab service discovery | `python port_scanner.py --target 10.10.10.10 --ports 1-1024` |

More workflow notes are available in [Analyst Workflows](docs/analyst-workflows.md).

## Quick Usage

### Log Parser

```bash
python log_parser.py --file /var/log/auth.log
python log_parser.py --file /var/log/auth.log --filter failed --brute-threshold 5
python log_parser.py --file samples/auth_sample.log --type auth --output report.txt
```

### IOC Parser

```bash
python ioc_parser.py --file samples/threat_report_sample.txt
python ioc_parser.py --text "attacker at 192.168.1.100 hit https://evil.example/login"
python ioc_parser.py --file malware_log.txt --type ip,url,sha256 --output iocs.txt
```

### Hash Checker

```bash
python hash_checker.py --file malware_sample.exe --algorithm sha256
python hash_checker.py --string "password123" --algorithm all
python hash_checker.py --identify 5f4dcc3b5aa765d61d8327deb882cf99
```

### Authorized Lab Enumeration

```bash
python port_scanner.py --target 10.10.10.10 --ports 1-1024
python subdomain_enum.py --domain example.htb --wordlist subs.txt
python dir_enum.py --url http://10.10.10.10 --wordlist common.txt --extensions .php,.html,.txt
```

## Repository Standard

Each tool should include help output, safe usage examples, expected input, expected output, and a short explanation of the security concept it demonstrates.

## Disclaimer

These tools are for **educational purposes and authorized testing only**. Never run them against systems you do not own or do not have explicit written permission to test. Unauthorized scanning, enumeration, or access attempts are illegal and unethical.
