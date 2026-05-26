# Python Security Tools

This repository contains small Python scripts for security learning, analyst automation, log review, IOC extraction, hash checking, and **authorized defensive enumeration**. The blue-team purpose is to show that I can use Python to support repeatable investigation workflows, asset visibility, and evidence-based reporting.

These scripts are for educational use in authorized labs such as home labs, Hack The Box, TryHackMe, and intentionally vulnerable environments. They must not be used against systems without explicit permission.

## Script Index

| Script | Purpose | Defensive or Learning Value | Status |
|---|---|---|---|
| `log_parser.py` | Parse auth.log, syslog, or Windows-style event logs and identify brute-force patterns. | Supports suspicious-login triage and timeline building. | Ready |
| `ioc_parser.py` | Extract and defang IPs, domains, URLs, hashes, emails, and CVEs from text. | Supports phishing, malware, and threat-intel workflows. | Ready |
| `hash_checker.py` | Hash files or strings and compare known hashes. | Supports file integrity review and malware triage basics. | Ready |
| `asset_discovery.py` | Identify responsive assets in an authorized scope using conservative TCP probes. | Supports asset inventory, service exposure review, and blue-team visibility. | Ready |
| `port_scanner.py` | Review open TCP services across authorized hosts, host lists, or small CIDR ranges. | Supports authorized service exposure review with TXT, HTML, CSV, JSON, and Markdown reporting for enumeration notes. | Ready |
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
| Authorized asset discovery | `python asset_discovery.py --scope 127.0.0.1/32 --ports 22,80,443 --format md --output inventory.md` |
| Authorized service exposure review | `python port_scanner.py --target-file samples/authorized_scope_sample.txt --ports 22,80,443,445,3389 --format html --output exposure.html` |

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

### Authorized Defensive Enumeration

```bash
python asset_discovery.py --scope 127.0.0.1/32 --ports 22,80,443 --include-inactive
python asset_discovery.py --scope-file samples/authorized_scope_sample.txt --format csv --output asset_inventory.csv
python port_scanner.py --target 127.0.0.1 --ports 22,80,443
python port_scanner.py --targets 127.0.0.1,localhost --ports 22,80,443 --format txt --output service_exposure.txt
python port_scanner.py --target-file samples/authorized_scope_sample.txt --ports 22,80,443,445,3389 --format html --output service_exposure.html
python port_scanner.py --target-file samples/authorized_scope_sample.txt --ports 22,80,443,445,3389 --format json --output service_exposure.json
```

The enumeration tools are intentionally framed around **authorized asset visibility** and **service exposure documentation**. The goal is not to make a stealthy scanner. The goal is to demonstrate that I understand scope, reporting, basic automation, and how discovery findings turn into analyst follow-up questions.

## Sample Evidence Artifacts

| Artifact | Purpose |
|---|---|
| `samples/authorized_scope_sample.txt` | Demonstrates how an analyst defines testing scope before running discovery. |
| `samples/asset_inventory_sample.csv` | Shows the type of asset inventory output a recruiter can inspect quickly. |
| `samples/port_exposure_sample.md` | Shows how raw service discovery becomes a short defensive review report. |
| `service_exposure.txt` or `service_exposure.html` | Recommended local output names when you want enumeration-phase reference notes from `port_scanner.py`. |

## Repository Standard

Each tool should include help output, safe usage examples, expected input, expected output, and a short explanation of the security concept it demonstrates. For enumeration tools, each example should clearly state that it is for an **owned lab or explicitly authorized scope**.

## Disclaimer

These tools are for **educational purposes and authorized testing only**. Never run them against systems you do not own or do not have explicit written permission to test. Unauthorized scanning, enumeration, or access attempts are illegal and unethical.
