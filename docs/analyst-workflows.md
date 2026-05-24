# Analyst Workflows

This document explains how the scripts in this repository can support blue-team learning and analyst workflows in authorized lab environments. The goal is not to replace enterprise tools. The goal is to show repeatable thinking: define scope, collect evidence, summarize findings, and document reasonable next steps.

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

The analyst should be able to explain what happened, which account or source IP was involved, whether the behavior appears isolated or repeated, and what containment or follow-up action would be reasonable.

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

This workflow demonstrates the ability to convert messy text into structured indicators that can be searched, blocked, or escalated.

## Workflow 3 — Authorized Asset Discovery and Service Exposure Review

This is the strongest enumeration workflow for a blue-team portfolio because it is framed around **asset visibility** and **defensive exposure review** instead of unsanctioned scanning. Before running discovery, the analyst should define the approved scope in a file such as `samples/authorized_scope_sample.txt`.

| Step | Tool | Purpose |
|---|---|---|
| 1 | Scope file | Document the lab subnet, hosts, or training targets that are explicitly authorized. |
| 2 | `asset_discovery.py` | Identify responsive assets using conservative TCP probes. |
| 3 | `port_scanner.py` | Review exposed TCP services on identified or approved hosts. |
| 4 | Markdown or CSV report | Convert findings into an inventory or exposure review artifact. |
| 5 | Analyst notes | Record ownership, expected services, remote admin exposure, and follow-up questions. |

Example commands:

```bash
python asset_discovery.py --scope-file samples/authorized_scope_sample.txt --format csv --output asset_inventory.csv
python port_scanner.py --target-file samples/authorized_scope_sample.txt --ports 22,80,443,445,3389 --format md --output service_exposure.md
```

A recruiter should be able to inspect the resulting report and see more than open ports. The report should answer what was in scope, which assets responded, which services were exposed, why those services matter defensively, and what questions an analyst would ask next.

## Workflow 4 — Authorized Lab Enumeration

| Step | Tool | Purpose |
|---|---|---|
| 1 | `port_scanner.py` | Identify open TCP ports in an authorized lab. |
| 2 | `subdomain_enum.py` | Practice DNS discovery against a permitted lab domain. |
| 3 | `dir_enum.py` | Practice web content discovery in authorized environments. |

This workflow is useful for TryHackMe, Hack The Box, and home-lab practice. It should be documented carefully so the defensive takeaway is clear. For example, after using enumeration tools in a lab, summarize what the defender could log, alert on, harden, or monitor.

## Professional Framing

These tools are not meant to replace enterprise security platforms. They show Python fundamentals, analyst curiosity, and the ability to automate small repetitive tasks. The best GitHub signal is not just the code; it is the combination of code, safe scope definition, sample output, and clear analyst notes.
