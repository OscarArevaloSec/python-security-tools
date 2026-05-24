#!/usr/bin/env python3
"""
port_scanner.py — Defensive TCP service exposure review tool.

Purpose:
    This script supports authorized asset inventory and service exposure review in
    home labs, training ranges, and environments where you have explicit written
    permission to test. It is intentionally simple and transparent so a junior
    analyst can explain every step.

Usage:
    python port_scanner.py --target <host> --ports <range|list> [options]
    python port_scanner.py --targets 192.168.56.10,192.168.56.11 --ports 22,80,443 --format md --output report.md
    python port_scanner.py --target-file samples/authorized_scope_sample.txt --ports 1-1024 --format csv --output exposure.csv

Disclaimer:
    Use only on systems you own or are explicitly authorized to assess.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 512: "rexec",
    513: "rlogin", 514: "RSH", 587: "SMTP-TLS", 631: "IPP", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit/Lab", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9200: "Elasticsearch",
    27017: "MongoDB",
}

EXPOSURE_NOTES = {
    21: "Legacy file transfer service; verify business need and encryption requirements.",
    22: "Remote administration service; verify MFA, key policy, and source restrictions.",
    23: "Telnet is unencrypted; this should be removed or isolated.",
    80: "HTTP service; verify redirect to HTTPS and expected application owner.",
    139: "Legacy NetBIOS exposure; verify segmentation and necessity.",
    445: "SMB exposure; verify patching, signing, share permissions, and network scope.",
    3389: "RDP exposure; verify MFA, VPN/jump-host requirement, and account lockout policy.",
    5985: "WinRM over HTTP; verify trusted network scope and hardening.",
    5986: "WinRM over HTTPS; verify certificate and administrative access controls.",
    6379: "Redis service; verify authentication, binding, and non-public exposure.",
    9200: "Elasticsearch service; verify authentication and network restrictions.",
    27017: "MongoDB service; verify authentication and network restrictions.",
}

COMMON_ADMIN_PORTS = {22, 23, 445, 3389, 5985, 5986}


def parse_ports(port_str: str) -> list[int]:
    """Parse a port range or comma-separated list into validated integers."""
    ports: set[int] = set()
    for part in port_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    invalid = [p for p in ports if p < 1 or p > 65535]
    if invalid:
        raise ValueError(f"Ports must be between 1 and 65535. Invalid: {invalid[:5]}")
    return sorted(ports)


def load_target_file(path: str) -> list[str]:
    """Load target values from a scope file."""
    target_path = Path(path)
    if not target_path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")
    targets = []
    for line in target_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    return targets


def expand_target_value(value: str, max_hosts: int) -> list[str]:
    """Expand a hostname, IP address, or CIDR into target strings."""
    value = value.strip()
    if not value:
        return []
    try:
        network = ipaddress.ip_network(value, strict=False)
        hosts = [str(host) for host in network.hosts()]
        if network.num_addresses == 1:
            hosts = [str(network.network_address)]
        if len(hosts) > max_hosts:
            raise ValueError(
                f"CIDR {value} expands to {len(hosts)} hosts, which exceeds --max-hosts {max_hosts}. "
                "Use a smaller authorized scope."
            )
        return hosts
    except ValueError as exc:
        if "/" in value:
            raise exc
        return [value]


def collect_targets(args: argparse.Namespace) -> list[str]:
    """Collect targets from --target, --targets, and --target-file."""
    raw_targets: list[str] = []
    if args.target:
        raw_targets.append(args.target)
    if args.targets:
        raw_targets.extend([item.strip() for item in args.targets.split(",") if item.strip()])
    if args.target_file:
        raw_targets.extend(load_target_file(args.target_file))

    if not raw_targets:
        raise ValueError("Provide --target, --targets, or --target-file.")

    expanded: list[str] = []
    for value in raw_targets:
        expanded.extend(expand_target_value(value, args.max_hosts))

    # Preserve order while removing duplicates.
    return list(dict.fromkeys(expanded))


def resolve_target(target: str) -> tuple[str, str]:
    """Resolve a target to an IP address while preserving the original value."""
    try:
        ip = socket.gethostbyname(target)
        return target, ip
    except socket.gaierror:
        return target, "UNRESOLVED"


def reverse_dns(ip: str) -> str:
    """Attempt reverse DNS lookup for reporting context."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def service_name(port: int) -> str:
    """Return a service hint from the static map or socket service database."""
    if port in SERVICE_MAP:
        return SERVICE_MAP[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except OSError:
        return "unknown"


def grab_banner(sock: socket.socket, port: int, timeout: float = 1.0) -> str:
    """Attempt a light banner grab for analyst context."""
    try:
        sock.settimeout(timeout)
        if port in {80, 8080, 8000, 8008, 8443, 8888}:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return banner.split("\n")[0][:100]
    except Exception:
        return ""


def exposure_note(port: int) -> str:
    """Return a short defensive review note for common ports."""
    if port in EXPOSURE_NOTES:
        return EXPOSURE_NOTES[port]
    if port in COMMON_ADMIN_PORTS:
        return "Administrative service; verify ownership, access controls, and segmentation."
    return "Review service owner, business need, patch level, and expected exposure."


def scan_port(target: str, ip: str, hostname: str, port: int, timeout: float, banner: bool) -> dict | None:
    """Attempt TCP connection to one port and return a structured result."""
    if ip == "UNRESOLVED":
        return None
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner_text = grab_banner(sock, port, min(timeout, 1.5)) if banner else ""
                return {
                    "target": target,
                    "ip": ip,
                    "hostname": hostname,
                    "port": port,
                    "protocol": "tcp",
                    "service": service_name(port),
                    "banner": banner_text,
                    "analyst_note": exposure_note(port),
                }
    except OSError:
        return None
    return None


def write_csv(results: list[dict], output: str) -> None:
    fields = ["target", "ip", "hostname", "port", "protocol", "service", "banner", "analyst_note"]
    with open(output, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def write_json(results: list[dict], output: str, metadata: dict) -> None:
    payload = {"metadata": metadata, "results": results}
    Path(output).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_markdown(results: list[dict], output: str, metadata: dict) -> None:
    lines = [
        "# Authorized Service Exposure Review",
        "",
        f"**Generated:** {metadata['generated_at']}",
        f"**Targets reviewed:** {metadata['targets_reviewed']}",
        f"**Ports reviewed:** {metadata['ports_reviewed']}",
        f"**Open services found:** {len(results)}",
        "",
        "> This report is intended for authorized asset inventory and defensive service exposure review.",
        "",
        "| Target | IP | Hostname | Port | Service | Banner | Analyst Note |",
        "|---|---|---|---:|---|---|---|",
    ]
    if results:
        for item in results:
            banner = (item.get("banner") or "").replace("|", "/")
            note = item.get("analyst_note", "").replace("|", "/")
            lines.append(
                f"| {item['target']} | {item['ip']} | {item.get('hostname', '')} | "
                f"{item['port']} | {item['service']} | {banner} | {note} |"
            )
    else:
        lines.append("| No open services identified |  |  |  |  |  |  |")
    lines.extend([
        "",
        "## Follow-Up Questions",
        "",
        "1. Is each exposed service expected for this asset's role?",
        "2. Is administrative access restricted to approved management networks?",
        "3. Are service owners, patch status, and compensating controls documented?",
    ])
    Path(output).write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_results(results: list[dict], metadata: dict) -> None:
    print(f"\n[+] Scan completed at {metadata['generated_at']}")
    print(f"[+] Targets reviewed: {metadata['targets_reviewed']} | Ports reviewed: {metadata['ports_reviewed']}")
    print(f"[+] Open services found: {len(results)}\n")
    print(f"{'TARGET':<22} {'IP':<16} {'PORT':<8} {'SERVICE':<14} {'BANNER'}")
    print("-" * 90)
    for item in results:
        banner = f"[{item['banner']}]" if item.get("banner") else ""
        print(f"{item['target']:<22} {item['ip']:<16} {item['port']:<8} {item['service']:<14} {banner}")


def cap_threads(requested: int) -> int:
    """Keep concurrency realistic for a learning portfolio tool."""
    if requested < 1:
        return 1
    if requested > 200:
        print("[!] Thread count capped at 200 for safe lab usage.")
        return 200
    return requested


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Defensive TCP service exposure review for authorized assets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python port_scanner.py --target 127.0.0.1 --ports 22,80,443\n"
            "  python port_scanner.py --targets 192.168.56.10,192.168.56.11 --ports 1-1024 --format md --output report.md\n"
            "  python port_scanner.py --target-file samples/authorized_scope_sample.txt --ports 22,80,443 --format csv --output exposure.csv"
        ),
    )
    parser.add_argument("--target", help="Single target IP or hostname")
    parser.add_argument("--targets", help="Comma-separated targets or CIDR ranges")
    parser.add_argument("--target-file", help="File containing authorized targets, one per line")
    parser.add_argument("--ports", default="1-1024", help="Port range or comma list. Default: 1-1024")
    parser.add_argument("--threads", type=int, default=50, help="Worker threads. Default: 50; capped at 200")
    parser.add_argument("--timeout", type=float, default=1.0, help="Socket timeout in seconds. Default: 1.0")
    parser.add_argument("--max-hosts", type=int, default=256, help="Maximum hosts allowed after CIDR expansion. Default: 256")
    parser.add_argument("--no-banner", action="store_true", help="Disable light banner grabbing")
    parser.add_argument("--format", choices=["text", "json", "csv", "md"], default="text", help="Output format")
    parser.add_argument("--output", help="Save structured results to a file")
    args = parser.parse_args()

    print("[!] Authorized use only. Confirm scope before scanning any network or host.")

    try:
        targets = collect_targets(args)
        ports = parse_ports(args.ports)
    except Exception as exc:
        print(f"[!] Input error: {exc}")
        return 2

    threads = cap_threads(args.threads)
    start_time = datetime.now(timezone.utc)
    resolved = [resolve_target(target) for target in targets]
    unresolved = [target for target, ip in resolved if ip == "UNRESOLVED"]
    if unresolved:
        print(f"[!] Unresolved targets skipped: {', '.join(unresolved)}")

    hostnames = {ip: reverse_dns(ip) for _, ip in resolved if ip != "UNRESOLVED"}
    jobs = [(target, ip, hostnames.get(ip, ""), port) for target, ip in resolved if ip != "UNRESOLVED" for port in ports]

    print(f"[*] Targets: {len(targets)} | Resolved: {len(resolved) - len(unresolved)} | Ports: {len(ports)} | Checks: {len(jobs)}")
    print(f"[*] Threads: {threads} | Timeout: {args.timeout}s | Started: {start_time.strftime('%Y-%m-%d %H:%M:%SZ')}")

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, target, ip, hostname, port, args.timeout, not args.no_banner): (target, ip, port)
            for target, ip, hostname, port in jobs
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda item: (item["ip"], item["port"]))
    metadata = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "targets_reviewed": len(targets),
        "ports_reviewed": len(ports),
        "checks_performed": len(jobs),
        "tool": "port_scanner.py",
        "purpose": "authorized defensive service exposure review",
    }

    print_results(results, metadata)

    if args.output:
        if args.format == "csv":
            write_csv(results, args.output)
        elif args.format == "json":
            write_json(results, args.output, metadata)
        elif args.format == "md":
            write_markdown(results, args.output, metadata)
        else:
            write_markdown(results, args.output, metadata)
        print(f"\n[+] Results saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
