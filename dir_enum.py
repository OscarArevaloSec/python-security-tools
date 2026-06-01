#!/usr/bin/env python3
"""
dir_enum.py — Web directory and file brute-forcer.

Usage:
    python dir_enum.py --url <url> --wordlist <file> [options]

Examples:
    python dir_enum.py --url http://10.10.10.10 --wordlist /usr/share/wordlists/dirb/common.txt
    python dir_enum.py --url http://10.10.10.10 --wordlist common.txt --extensions .php,.html,.txt
    python dir_enum.py --url http://10.10.10.10 --wordlist big.txt --threads 40 --status 200,301,302

Install dependency:
    pip install requests

Disclaimer: For authorized testing and educational use only.
"""

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

try:
    import requests
    import urllib3
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    print("[!] requests library not found. Install with: pip install requests")
    sys.exit(1)


def load_wordlist(path: str) -> list[str]:
    if not os.path.isfile(path):
        print(f"[!] Wordlist not found: {path}")
        sys.exit(1)
    with open(path, errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def probe(session: requests.Session, url: str, timeout: float, verify: bool = True) -> dict | None:
    """Make a GET request and return result dict."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=False,
                           verify=verify)
        return {
            "url": url,
            "status": resp.status_code,
            "length": len(resp.content),
            "redirect": resp.headers.get("Location", ""),
        }
    except requests.exceptions.ConnectionError:
        return None
    except requests.exceptions.Timeout:
        return None
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Web directory and file brute-forcer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python dir_enum.py --url http://10.10.10.10 --wordlist common.txt --extensions .php,.html"
    )
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://10.10.10.10)")
    parser.add_argument("--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("--extensions", default="",
                        help="Comma-separated extensions to append (e.g. .php,.html,.txt)")
    parser.add_argument("--threads", type=int, default=30,
                        help="Number of threads (default: 30)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="Request timeout in seconds (default: 5.0)")
    parser.add_argument("--status", default="200,204,301,302,307,401,403",
                        help="Comma-separated status codes to show (default: 200,204,301,302,307,401,403)")
    parser.add_argument("--output", help="Save results to file")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (compatible; DirEnum/1.0)",
                        help="Custom User-Agent string")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification (for self-signed lab targets)")
    args = parser.parse_args()

    verify = not args.insecure
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    base_url = args.url.rstrip("/")
    show_codes = {int(c.strip()) for c in args.status.split(",") if c.strip()}
    extensions = [""] + [e if e.startswith(".") else f".{e}"
                         for e in args.extensions.split(",") if e.strip()]

    words = load_wordlist(args.wordlist)

    # Build full URL list
    targets = []
    for word in words:
        for ext in extensions:
            targets.append(f"{base_url}/{word}{ext}")

    print(f"\n[*] Target    : {base_url}")
    print(f"[*] Wordlist  : {len(words)} words × {len(extensions)} extension(s) = {len(targets)} requests")
    print(f"[*] Threads   : {args.threads}")
    print(f"[*] Show codes: {sorted(show_codes)}")
    print(f"[*] Started   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    print(f"{'STATUS':<8} {'SIZE':<10} {'URL'}")
    print("-" * 70)

    found = []
    session = requests.Session()
    session.headers["User-Agent"] = args.user_agent

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(probe, session, url, args.timeout, verify): url
                   for url in targets}
        for future in as_completed(futures):
            result = future.result()
            if result and result["status"] in show_codes:
                found.append(result)
                redirect = f" → {result['redirect']}" if result["redirect"] else ""
                print(f"{result['status']:<8} {result['length']:<10} {result['url']}{redirect}")

    found.sort(key=lambda x: (x["status"], x["url"]))
    print(f"\n[+] Found {len(found)} result(s)")

    if args.output:
        with open(args.output, "w") as f:
            f.write(f"# Directory enumeration: {base_url}\n")
            f.write(f"# {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            for r in found:
                redirect = f"   → {r['redirect']}" if r['redirect'] else ""
                f.write(f"{r['status']}  {r['length']:<10}  {r['url']}{redirect}\n")
        print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
