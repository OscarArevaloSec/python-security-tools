# Analyst Workflows for Python Security Tools

This document explains how the scripts in this repository can support blue-team learning and analyst workflows in authorized lab environments.

## Workflow 1 — Suspicious Login Review

| Step | Tool | Purpose |
|---|---|---|
| 1 | `log_parser.py` | Parse authentication logs and identify failed-login patterns. |
| 2 | `ioc_parser.py` | Extract IP addresses or domains from notes and alerts. |
| 3 | Incident report template | Document timeline, affected account, evidence, severity, and recommendations. |

Example command:

```bash
python log_parser.py --file samples/auth_sample.log --filter failed --brute-threshold 3
```

## Workflow 2 — Phishing IOC Extraction

| Step | Tool | Purpose |
|---|---|---|
| 1 | `ioc_parser.py` | Extract URLs, domains, IP addresses, hashes, and CVEs from a suspicious message or report. |
| 2 | `hash_checker.py` | Verify or identify hashes when appropriate. |
| 3 | IOC template | Record indicators with context and action taken. |

Example command:

```bash
python ioc_parser.py --file samples/threat_report_sample.txt
```

## Workflow 3 — Authorized Lab Enumeration

| Step | Tool | Purpose |
|---|---|---|
| 1 | `port_scanner.py` | Identify open TCP ports in an authorized lab. |
| 2 | `subdomain_enum.py` | Practice DNS discovery against a permitted lab domain. |
| 3 | `dir_enum.py` | Practice web content discovery in authorized environments. |

## Professional Framing

These tools are not meant to replace enterprise security platforms. They show Python fundamentals, analyst curiosity, and the ability to automate small repetitive tasks.
