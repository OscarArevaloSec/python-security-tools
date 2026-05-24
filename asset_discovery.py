#!/usr/bin/env python3
"""
asset_discovery.py — Authorized asset discovery and inventory helper.

Purpose:
    This tool helps a blue-team learner create a lightweight inventory of live
    assets in an authorized lab or owned network. It performs conservative TCP
    connect probes against common ports, optional reverse DNS lookup, and writes
    structured output for analyst notes.

Examples:
    python asset_discovery.py --scope 192.168.56.0/24 --output inventory.csv --format csv
    python asset_discovery.py --scope-file samples/authorized_scope_sample.txt --ports 22,80,443 --format md --output inventory.md

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

DEFAULT_PROBE_PORTS = [22, 80, 135, 139, 443, 445, 3389, 5985]


def parse_ports(text: str) -> list[int]:
    ports: set[int] = set()
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Invalid port range: {item}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError("Ports must be between 1 and 65535.")
    return sorted(ports)


def load_scope_file(path: str) -> list[str]:
    scope_path = Path(path)
    if not scope_path.is_file():
        raise FileNotFoundError(f"Scope file not found: {path}")
    return [
        line.strip()
        for line in scope_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def expand_scope(scope_items: list[str], max_hosts: int) -> list[str]:
    hosts: list[str] = []
    for item in scope_items:
        try:
            network = ipaddress.ip_network(item, strict=False)
            if network.num_addresses == 1:
                network_hosts = [str(network.network_address)]
            else:
                network_hosts = [str(host) for host in network.hosts()]
            if len(network_hosts) > max_hosts:
                raise ValueError(
                    f"Scope {item} expands to {len(network_hosts)} hosts and exceeds --max-hosts {max_hosts}."
                )
            hosts.extend(network_hosts)
        except ValueError as exc:
            if "/" in item:
                raise exc
            hosts.append(item)
    return list(dict.fromkeys(hosts))


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def tcp_probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def classify_asset(open_ports: list[int]) -> str:
    ports = set(open_ports)
    if ports & {445, 139, 135, 3389, 5985}:
        return "windows_or_admin_surface"
    if ports & {22}:
        return "linux_or_network_device_candidate"
    if ports & {80, 443, 8080, 8443}:
        return "web_service_candidate"
    if open_ports:
        return "active_service_detected"
    return "no_probe_response"


def make_recommendation(open_ports: list[int]) -> str:
    if not open_ports:
        return "No configured TCP probes responded; verify with passive inventory or approved scanner if expected."
    if 23 in open_ports:
        return "Telnet observed; validate business need and replace with encrypted administration where possible."
    if 3389 in open_ports:
        return "RDP observed; verify MFA, VPN or jump-host access, and account lockout controls."
    if 445 in open_ports:
        return "SMB observed; verify patching, share permissions, signing, and network segmentation."
    if 22 in open_ports:
        return "SSH observed; verify key policy, MFA or bastion access, and source restrictions."
    return "Document owner, expected service exposure, patch status, and monitoring coverage."


def discover_host(host: str, ports: list[int], timeout: float, include_inactive: bool) -> dict | None:
    open_ports = [port for port in ports if tcp_probe(host, port, timeout)]
    if not open_ports and not include_inactive:
        return None
    return {
        "host": host,
        "reverse_dns": reverse_dns(host),
        "status": "responsive" if open_ports else "no_probe_response",
        "open_probe_ports": ",".join(str(port) for port in open_ports),
        "asset_hint": classify_asset(open_ports),
        "recommendation": make_recommendation(open_ports),
    }


def write_csv(results: list[dict], path: str) -> None:
    fields = ["host", "reverse_dns", "status", "open_probe_ports", "asset_hint", "recommendation"]
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(results)


def write_json(results: list[dict], path: str, metadata: dict) -> None:
    Path(path).write_text(json.dumps({"metadata": metadata, "assets": results}, indent=2), encoding="utf-8")


def write_markdown(results: list[dict], path: str, metadata: dict) -> None:
    lines = [
        "# Authorized Asset Discovery Report",
        "",
        f"**Generated:** {metadata['generated_at']}",
        f"**Scope hosts reviewed:** {metadata['hosts_reviewed']}",
        f"**Probe ports:** {metadata['probe_ports']}",
        f"**Responsive assets:** {sum(1 for item in results if item['status'] == 'responsive')}",
        "",
        "> This report supports defensive asset inventory and should be used only for authorized scopes.",
        "",
        "| Host | Reverse DNS | Status | Open Probe Ports | Asset Hint | Recommendation |",
        "|---|---|---|---|---|---|",
    ]
    if results:
        for item in results:
            lines.append(
                f"| {item['host']} | {item['reverse_dns']} | {item['status']} | "
                f"{item['open_probe_ports']} | {item['asset_hint']} | {item['recommendation']} |"
            )
    else:
        lines.append("| No responsive assets detected |  |  |  |  |  |")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def print_table(results: list[dict]) -> None:
    print(f"\n{'HOST':<16} {'STATUS':<18} {'PORTS':<20} {'ASSET HINT'}")
    print("-" * 80)
    for item in results:
        print(f"{item['host']:<16} {item['status']:<18} {item['open_probe_ports']:<20} {item['asset_hint']}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Authorized asset discovery and inventory helper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python asset_discovery.py --scope 127.0.0.1/32 --format md --output inventory.md\n"
            "  python asset_discovery.py --scope-file samples/authorized_scope_sample.txt --ports 22,80,443 --format csv --output inventory.csv"
        ),
    )
    parser.add_argument("--scope", help="Single host, hostname, or CIDR range")
    parser.add_argument("--scope-file", help="File containing authorized hosts or CIDR ranges")
    parser.add_argument("--ports", default=",".join(str(port) for port in DEFAULT_PROBE_PORTS), help="Comma-separated TCP probe ports")
    parser.add_argument("--threads", type=int, default=50, help="Worker threads. Default: 50; capped at 200")
    parser.add_argument("--timeout", type=float, default=0.75, help="TCP timeout in seconds. Default: 0.75")
    parser.add_argument("--max-hosts", type=int, default=256, help="Maximum hosts after CIDR expansion. Default: 256")
    parser.add_argument("--include-inactive", action="store_true", help="Include hosts where configured probes did not respond")
    parser.add_argument("--format", choices=["text", "csv", "json", "md"], default="text", help="Output format")
    parser.add_argument("--output", help="Output file path")
    args = parser.parse_args()

    print("[!] Authorized use only. Confirm written scope before running discovery.")

    scope_items: list[str] = []
    if args.scope:
        scope_items.append(args.scope)
    if args.scope_file:
        scope_items.extend(load_scope_file(args.scope_file))
    if not scope_items:
        print("[!] Provide --scope or --scope-file.")
        return 2

    try:
        hosts = expand_scope(scope_items, args.max_hosts)
        ports = parse_ports(args.ports)
    except Exception as exc:
        print(f"[!] Input error: {exc}")
        return 2

    threads = min(max(args.threads, 1), 200)
    started = datetime.now(timezone.utc)
    print(f"[*] Hosts: {len(hosts)} | Probe ports: {ports} | Threads: {threads}")
    print(f"[*] Started: {started.strftime('%Y-%m-%d %H:%M:%SZ')}")

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(discover_host, host, ports, args.timeout, args.include_inactive): host
            for host in hosts
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    def sort_key(item: dict) -> tuple[int, str]:
        try:
            return (0, ipaddress.ip_address(item["host"]).compressed)
        except ValueError:
            return (1, item["host"])

    results.sort(key=sort_key)
    metadata = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "hosts_reviewed": len(hosts),
        "probe_ports": ",".join(str(port) for port in ports),
        "tool": "asset_discovery.py",
        "purpose": "authorized defensive asset inventory",
    }

    print_table(results)
    print(f"\n[+] Responsive assets: {sum(1 for item in results if item['status'] == 'responsive')} / {len(hosts)}")

    if args.output:
        if args.format == "csv":
            write_csv(results, args.output)
        elif args.format == "json":
            write_json(results, args.output, metadata)
        elif args.format == "md":
            write_markdown(results, args.output, metadata)
        else:
            write_markdown(results, args.output, metadata)
        print(f"[+] Results saved to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
