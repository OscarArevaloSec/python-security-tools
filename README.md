# Python Security Tools

Python scripts for security automation, log analysis, and network fundamentals. Each script is documented with purpose, usage, and the security concept it demonstrates.

## Scripts

| Script | Purpose | Status |
|---|---|---|
| `port_scanner.py` | TCP port scanner using socket library | Planned |
| `log_parser.py` | Parse auth.log for failed logins and anomalies | Planned |
| `hash_checker.py` | Compute and compare MD5/SHA256 file hashes | Planned |
| `ioc_parser.py` | Extract IPs, domains, and hashes from text | Planned |

## Requirements

```
python3 >= 3.10
```

No external dependencies for core scripts. Install optional packages with:

```bash
pip install -r requirements.txt
```

## Usage

Each script includes a `--help` flag and inline comments explaining the security context.

```bash
python3 port_scanner.py --target 192.168.1.1 --ports 1-1024
```

## Disclaimer

These tools are for educational purposes and authorized testing only. Never run against systems you do not own or have explicit permission to test.
