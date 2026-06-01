#!/usr/bin/env python3
"""
nmap_scanner.py — Authorized Nmap-based service enumeration reporter.

Purpose:
    Run Nmap against explicitly authorized targets, parse the XML output, and
    create a plain-text report that can be used during the enumeration phase.
    This script is intentionally conservative and designed for portfolio/lab use.

Usage:
    python nmap_scanner.py --target 127.0.0.1 --ports 22,80,443 --output enumeration.txt
    python nmap_scanner.py --targets 192.168.56.10,192.168.56.11 --ports 1-1024 --output enumeration.txt
    python nmap_scanner.py --target-file samples/authorized_scope_sample.txt --ports 22,80,443,445,3389 --output exposure.txt

Disclaimer:
    Use only on systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

from common import expand_target, parse_ports, read_lines

EXPOSURE_NOTES = {
    21: "FTP service; verify anonymous access, encryption requirements, and business need.",
    22: "SSH service; verify key policy, MFA or compensating controls, and source restrictions.",
    23: "Telnet is unencrypted; remove it or isolate it unless there is a documented exception.",
    25: "SMTP service; verify relay restrictions, TLS posture, and expected exposure.",
    53: "DNS service; verify zone transfer controls, recursion policy, and intended exposure.",
    80: "HTTP service; verify redirect to HTTPS and identify application owner.",
    139: "NetBIOS service; verify segmentation and legacy dependency.",
    445: "SMB service; verify signing, share permissions, patching, and network scope.",
    3389: "RDP service; verify MFA, VPN or jump-host requirement, and lockout policy.",
    5985: "WinRM over HTTP; verify trusted network scope and hardening.",
    5986: "WinRM over HTTPS; verify certificate configuration and administrative access controls.",
    6379: "Redis service; verify authentication, binding, and non-public exposure.",
    9200: "Elasticsearch service; verify authentication and network restrictions.",
    27017: "MongoDB service; verify authentication and network restrictions.",
}


def collect_targets(args: argparse.Namespace) -> list[str]:
    """Collect targets from CLI arguments and preserve order while de-duplicating."""
    raw_targets: list[str] = []
    if args.target:
        raw_targets.append(args.target)
    if args.targets:
        raw_targets.extend([target.strip() for target in args.targets.split(",") if target.strip()])
    if args.target_file:
        raw_targets.extend(read_lines(args.target_file))
    if not raw_targets:
        raise ValueError("Provide --target, --targets, or --target-file.")

    expanded: list[str] = []
    for value in raw_targets:
        expanded.extend(expand_target(value, args.max_hosts))
    return list(dict.fromkeys(expanded))


def analyst_note(port: int) -> str:
    """Return a defensive follow-up note for a discovered open port."""
    return EXPOSURE_NOTES.get(
        port,
        "Review service owner, business need, patch level, authentication posture, and expected exposure.",
    )


def build_nmap_command(args: argparse.Namespace, targets: list[str], xml_output: str) -> list[str]:
    """Build a controlled Nmap command suitable for authorized lab enumeration."""
    ports = ",".join(str(port) for port in parse_ports(args.ports))
    command = [
        args.nmap_path,
        "-oX",
        xml_output,
        "-p",
        ports,
        f"-T{args.timing}",
    ]

    if args.pn:
        command.append("-Pn")
    if args.version_detection:
        command.append("-sV")
    else:
        command.append("-sT")
    if args.reason:
        command.append("--reason")

    command.extend(targets)
    return command


def run_nmap(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Execute Nmap and return the completed process."""
    return subprocess.run(command, capture_output=True, text=True, check=False)


def parse_nmap_xml(xml_path: str) -> list[dict]:
    """Parse Nmap XML output into open-port findings."""
    root = ET.parse(xml_path).getroot()
    findings: list[dict] = []

    for host in root.findall("host"):
        status = host.find("status")
        host_state = status.get("state", "unknown") if status is not None else "unknown"
        addresses = [addr.get("addr", "") for addr in host.findall("address") if addr.get("addr")]
        ip = addresses[0] if addresses else ""
        hostnames = [name.get("name", "") for name in host.findall("hostnames/hostname") if name.get("name")]
        hostname = ", ".join(hostnames)

        for port in host.findall("ports/port"):
            state_element = port.find("state")
            state = state_element.get("state", "unknown") if state_element is not None else "unknown"
            if state != "open":
                continue
            service_element = port.find("service")
            port_number = int(port.get("portid", "0"))
            service_name = service_element.get("name", "unknown") if service_element is not None else "unknown"
            product = service_element.get("product", "") if service_element is not None else ""
            version = service_element.get("version", "") if service_element is not None else ""
            extrainfo = service_element.get("extrainfo", "") if service_element is not None else ""
            service_details = " ".join(part for part in [product, version, extrainfo] if part).strip()
            reason = state_element.get("reason", "") if state_element is not None else ""
            findings.append(
                {
                    "ip": ip,
                    "hostname": hostname,
                    "host_state": host_state,
                    "port": port_number,
                    "protocol": port.get("protocol", "tcp"),
                    "state": state,
                    "reason": reason,
                    "service": service_name,
                    "service_details": service_details,
                    "analyst_note": analyst_note(port_number),
                }
            )

    findings.sort(key=lambda item: (item["ip"], item["port"]))
    return findings


def write_txt_report(findings: list[dict], output: str, metadata: dict, nmap_stdout: str, nmap_stderr: str) -> None:
    """Write a plain-text enumeration report from parsed Nmap findings."""
    lines = [
        "Nmap Authorized Service Enumeration Report",
        "=" * 44,
        "",
        f"Generated: {metadata['generated_at']}",
        f"Targets reviewed: {metadata['targets_reviewed']}",
        f"Ports requested: {metadata['ports']}",
        f"Open services found: {len(findings)}",
        f"Nmap command: {metadata['nmap_command']}",
        "",
        "Scope Reminder:",
        "  This report is intended for explicitly authorized enumeration only.",
        "",
        "Open Services:",
        "-" * 14,
    ]

    if findings:
        for item in findings:
            lines.extend(
                [
                    f"IP: {item['ip']}",
                    f"Hostname: {item['hostname'] or 'N/A'}",
                    f"Host State: {item['host_state']}",
                    f"Port/Protocol: {item['port']}/{item['protocol']}",
                    f"State: {item['state']}",
                    f"Reason: {item['reason'] or 'N/A'}",
                    f"Service: {item['service']}",
                    f"Service Details: {item['service_details'] or 'N/A'}",
                    f"Analyst Note: {item['analyst_note']}",
                    "",
                ]
            )
    else:
        lines.extend(["No open services identified in the requested scope.", ""])

    lines.extend(
        [
            "Enumeration Follow-Up Questions:",
            "1. Is every exposed service expected for this host's role?",
            "2. Which service should be enumerated next based on attack surface and business context?",
            "3. Is administrative access restricted to trusted management networks?",
            "4. Are software versions, patch status, and service owners documented?",
            "5. Should HTTP, SMB, SSH, DNS, RDP, or database-specific enumeration be performed next?",
            "",
        ]
    )

    if nmap_stdout.strip():
        lines.extend(["Nmap Standard Output:", "-" * 21, nmap_stdout.strip(), ""])
    if nmap_stderr.strip():
        lines.extend(["Nmap Standard Error:", "-" * 20, nmap_stderr.strip(), ""])

    Path(output).write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_summary(findings: list[dict], metadata: dict) -> None:
    """Print a concise terminal summary."""
    print(f"\n[+] Nmap scan completed at {metadata['generated_at']}")
    print(f"[+] Targets reviewed: {metadata['targets_reviewed']} | Ports requested: {metadata['ports']}")
    print(f"[+] Open services found: {len(findings)}\n")
    print(f"{'IP':<16} {'PORT':<10} {'SERVICE':<18} {'DETAILS'}")
    print("-" * 90)
    for item in findings:
        details = item["service_details"] or ""
        print(f"{item['ip']:<16} {str(item['port']) + '/' + item['protocol']:<10} {item['service']:<18} {details}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authorized Nmap-based service enumeration with TXT reporting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python nmap_scanner.py --target 127.0.0.1 --ports 22,80,443 --output enumeration.txt\n"
            "  python nmap_scanner.py --targets 192.168.56.10,192.168.56.11 --ports 1-1024 --output lab_enum.txt\n"
            "  python nmap_scanner.py --target-file samples/authorized_scope_sample.txt --ports 22,80,443,445,3389 --output exposure.txt"
        ),
    )
    parser.add_argument("--target", help="Single target IP or hostname")
    parser.add_argument("--targets", help="Comma-separated targets or CIDR ranges")
    parser.add_argument("--target-file", help="File containing authorized targets, one per line")
    parser.add_argument("--ports", default="1-1024", help="Port range or comma list. Default: 1-1024")
    parser.add_argument("--output", required=True, help="TXT report output path")
    parser.add_argument("--max-hosts", type=int, default=256, help="Maximum hosts allowed after CIDR expansion. Default: 256")
    parser.add_argument("--timing", type=int, choices=range(0, 6), default=3, help="Nmap timing template 0-5. Default: 3")
    parser.add_argument("--nmap-path", default="nmap", help="Path to the Nmap executable. Default: nmap")
    parser.add_argument("--no-pn", dest="pn", action="store_false", help="Disable -Pn host discovery skip. Default uses -Pn for lab reliability")
    parser.add_argument("--no-version-detection", dest="version_detection", action="store_false", help="Disable -sV service/version detection")
    parser.add_argument("--reason", action="store_true", help="Ask Nmap to include port state reasons")
    parser.set_defaults(pn=True, version_detection=True)
    args = parser.parse_args()

    print("[!] Authorized use only. Confirm scope before scanning any network or host.")

    if Path(args.output).suffix.lower() != ".txt":
        print("[!] Output must be a .txt file because this scanner intentionally supports TXT reports only.")
        return 2

    if not shutil.which(args.nmap_path):
        print("[!] Nmap was not found. Install it first, for example: sudo apt install nmap")
        return 3

    try:
        targets = collect_targets(args)
        parse_ports(args.ports)
    except Exception as exc:
        print(f"[!] Input error: {exc}")
        return 2

    start_time = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory() as temp_dir:
        xml_output = str(Path(temp_dir) / "nmap_output.xml")
        command = build_nmap_command(args, targets, xml_output)
        print(f"[*] Running Nmap against {len(targets)} authorized target(s) at {start_time.strftime('%Y-%m-%d %H:%M:%SZ')}")
        completed = run_nmap(command)

        if completed.returncode not in (0, 1):
            print(f"[!] Nmap failed with return code {completed.returncode}")
            if completed.stderr:
                print(completed.stderr.strip())
            return completed.returncode

        try:
            findings = parse_nmap_xml(xml_output)
        except Exception as exc:
            print(f"[!] Could not parse Nmap XML output: {exc}")
            return 4

    metadata = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "targets_reviewed": len(targets),
        "ports": args.ports,
        "nmap_command": " ".join(command),
        "tool": "nmap_scanner.py",
        "purpose": "authorized Nmap-based service enumeration",
    }

    print_summary(findings, metadata)
    write_txt_report(findings, args.output, metadata, completed.stdout, completed.stderr)
    print(f"\n[+] TXT report saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
