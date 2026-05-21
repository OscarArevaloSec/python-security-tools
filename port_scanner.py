#!/usr/bin/env python3
"""
port_scanner.py — Multi-threaded TCP port scanner with banner grabbing.

Usage:
    python port_scanner.py --target <host> --ports <range|list> [options]

Examples:
    python port_scanner.py --target 10.10.10.10 --ports 1-1024
    python port_scanner.py --target 10.10.10.10 --ports 22,80,443,8080,8443
    python port_scanner.py --target 10.10.10.10 --ports 1-65535 --threads 300 --timeout 0.5

Disclaimer: For authorized testing and educational use only.
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Common service name hints
SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 512: "rexec", 513: "rlogin",
    514: "RSH", 587: "SMTP-TLS", 631: "IPP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL",
    3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL", 5900: "VNC",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Dev",
    9200: "Elasticsearch", 27017: "MongoDB",
}


def parse_ports(port_str: str) -> list[int]:
    """Parse port string: range (1-1024) or comma list (22,80,443)."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def grab_banner(sock: socket.socket, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner."""
    try:
        sock.settimeout(timeout)
        # Send a generic probe for services that respond to it
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
        return banner.split("\n")[0][:80]  # First line, max 80 chars
    except Exception:
        try:
            banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            return banner.split("\n")[0][:80]
        except Exception:
            return ""


def scan_port(target: str, port: int, timeout: float) -> dict | None:
    """Attempt TCP connection to a single port. Returns result dict or None."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = SERVICE_MAP.get(port, "unknown")
            banner = grab_banner(sock)
            sock.close()
            return {"port": port, "service": service, "banner": banner}
        sock.close()
    except (socket.error, OSError):
        pass
    return None


def resolve_target(target: str) -> str:
    """Resolve hostname to IP."""
    try:
        ip = socket.gethostbyname(target)
        if ip != target:
            print(f"[*] Resolved {target} → {ip}")
        return ip
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP port scanner with banner grabbing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python port_scanner.py --target 10.10.10.10 --ports 1-1024\n  python port_scanner.py --target 10.10.10.10 --ports 22,80,443"
    )
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--ports", default="1-1024",
                        help="Port range (1-1024) or comma list (22,80,443). Default: 1-1024")
    parser.add_argument("--threads", type=int, default=150,
                        help="Number of threads (default: 150)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("--output", help="Save results to file")
    args = parser.parse_args()

    ip = resolve_target(args.target)
    ports = parse_ports(args.ports)
    start_time = datetime.now()

    print(f"\n[*] Scanning {ip} | {len(ports)} ports | {args.threads} threads | timeout {args.timeout}s")
    print(f"[*] Started at {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    print(f"{'PORT':<10} {'SERVICE':<16} {'BANNER'}")
    print("-" * 70)

    open_ports = []

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_port, ip, port, args.timeout): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
                banner_str = f"  [{result['banner']}]" if result['banner'] else ""
                print(f"{result['port']:<10} {result['service']:<16}{banner_str}")

    open_ports.sort(key=lambda x: x["port"])
    elapsed = (datetime.now() - start_time).total_seconds()
    print(f"\n[+] Found {len(open_ports)} open port(s) in {elapsed:.2f}s")

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"# Port scan results for {ip}\n")
            f.write(f"# Scanned at {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for r in open_ports:
                f.write(f"{r['port']}/{r['service']}")
                if r['banner']:
                    f.write(f"  [{r['banner']}]")
                f.write("\n")
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
