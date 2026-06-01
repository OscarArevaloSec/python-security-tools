#!/usr/bin/env python3
"""
common.py — Shared helpers for the python-security-tools suite.

Centralises logic that several tools previously duplicated: port-range parsing,
scope/target file loading, CIDR/host expansion, reverse DNS, and subprocess
execution. Keeping one canonical copy means a fix lands everywhere at once.

Disclaimer: For authorized testing and educational use only.
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
from pathlib import Path


def parse_ports(port_str: str) -> list[int]:
    """Parse a port range or comma-separated list into validated, sorted ints.

    Accepts forms like "22,80,443" and "1-1024" (mixed allowed). Raises
    ValueError on malformed ranges, out-of-bounds ports, or empty input.
    """
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
    if not ports:
        raise ValueError("At least one valid port is required.")
    return sorted(ports)


def read_lines(path: str) -> list[str]:
    """Read a file, returning stripped non-blank lines that aren't comments."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {path}")
    return [
        line.strip()
        for line in file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def expand_target(value: str, max_hosts: int) -> list[str]:
    """Expand a single host, hostname, or CIDR into a list of target strings.

    A bare hostname is returned unchanged. A CIDR is expanded to its host
    addresses (or the single network address for a /32 or /128), raising
    ValueError if it would exceed ``max_hosts``.
    """
    value = value.strip()
    if not value:
        return []
    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses == 1:
            hosts = [str(network.network_address)]
        else:
            hosts = [str(host) for host in network.hosts()]
        if len(hosts) > max_hosts:
            raise ValueError(
                f"{value} expands to {len(hosts)} hosts, which exceeds --max-hosts {max_hosts}. "
                "Use a smaller authorized scope."
            )
        return hosts
    except ValueError as exc:
        # A value containing "/" was meant to be a network: surface the error.
        if "/" in value:
            raise exc
        return [value]


def reverse_dns(ip: str) -> str:
    """Best-effort reverse DNS lookup; returns '' on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def run_cmd(cmd: list[str], timeout: int = 15) -> tuple[str, str]:
    """Run an external command, returning (stdout, stderr), both stripped.

    Never raises: a missing binary or timeout is reported in the stderr slot.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return "", f"[!] Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return "", "[!] Command timed out"
