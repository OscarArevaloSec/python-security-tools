#!/usr/bin/env python3
"""
subdomain_enum.py — DNS subdomain brute-forcer.

Usage:
    python subdomain_enum.py --domain <domain> --wordlist <file> [options]

Examples:
    python subdomain_enum.py --domain example.htb --wordlist /usr/share/wordlists/subdomains-top1mil.txt
    python subdomain_enum.py --domain target.thm --wordlist subs.txt --threads 50 --output found.txt

Install dnspython for better results (optional):
    pip install dnspython

Disclaimer: For authorized testing and educational use only.
"""

import argparse
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from common import cap_threads

# Try to use dnspython for better DNS resolution; fall back to socket
try:
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# Module-level resolver, configured once in main() so a custom --resolver
# nameserver is actually honored by every worker thread.
_RESOLVER = None


def configure_resolver(nameserver: str | None = None) -> None:
    """Build the shared dnspython resolver (optionally with a custom nameserver)."""
    global _RESOLVER
    _RESOLVER = dns.resolver.Resolver()
    _RESOLVER.timeout = 2
    _RESOLVER.lifetime = 2
    if nameserver:
        _RESOLVER.nameservers = [nameserver]


def resolve_subdomain_dns(subdomain: str) -> list[str] | None:
    """Resolve using dnspython (more reliable, supports custom resolvers)."""
    resolver = _RESOLVER if _RESOLVER is not None else dns.resolver.Resolver()
    try:
        answers = resolver.resolve(subdomain, "A")
        return [str(r) for r in answers]
    except Exception:
        return None


def resolve_subdomain_socket(subdomain: str) -> list[str] | None:
    """Resolve using stdlib socket (fallback)."""
    try:
        infos = socket.getaddrinfo(subdomain, None, socket.AF_INET)
        ips = list({info[4][0] for info in infos})
        return ips if ips else None
    except socket.gaierror:
        return None


def resolve_subdomain(subdomain: str) -> list[str] | None:
    """Resolve a subdomain, using dnspython if available."""
    if HAS_DNSPYTHON:
        return resolve_subdomain_dns(subdomain)
    return resolve_subdomain_socket(subdomain)


def load_wordlist(path: str) -> list[str]:
    """Load words from a wordlist file, stripping comments and blanks."""
    if not os.path.isfile(path):
        print(f"[!] Wordlist not found: {path}")
        sys.exit(1)
    with open(path, errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(
        description="DNS subdomain brute-forcer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python subdomain_enum.py --domain example.htb --wordlist subs.txt"
    )
    parser.add_argument("--domain", required=True, help="Target domain (e.g. example.htb)")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("--threads", type=int, default=50,
                        help="Number of threads (default: 50)")
    parser.add_argument("--output", help="Save found subdomains to file")
    parser.add_argument("--resolver", help="Custom DNS resolver IP (requires dnspython)")
    args = parser.parse_args()

    if HAS_DNSPYTHON:
        configure_resolver(args.resolver)
    elif args.resolver:
        print("[!] --resolver requires dnspython; install with: pip install dnspython")

    args.threads = cap_threads(args.threads)

    resolver_mode = "dnspython" if HAS_DNSPYTHON else "socket (install dnspython for better results)"
    print(f"\n[*] Target domain : {args.domain}")
    print(f"[*] Resolver mode : {resolver_mode}")
    print(f"[*] Threads       : {args.threads}")

    words = load_wordlist(args.wordlist)
    print(f"[*] Wordlist words : {len(words)}")
    print(f"[*] Started at     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print(f"{'SUBDOMAIN':<45} {'IP(s)'}")
    print("-" * 70)

    found = []

    def check(word: str):
        fqdn = f"{word}.{args.domain}"
        ips = resolve_subdomain(fqdn)
        if ips:
            return (fqdn, ips)
        return None

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check, w): w for w in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                fqdn, ips = result
                ip_str = ", ".join(ips)
                print(f"{fqdn:<45} {ip_str}")
                found.append((fqdn, ips))

    found.sort(key=lambda x: x[0])
    print(f"\n[+] Found {len(found)} subdomain(s)")

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"# Subdomain enumeration: {args.domain}\n")
            f.write(f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for fqdn, ips in found:
                f.write(f"{fqdn}  {', '.join(ips)}\n")
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
