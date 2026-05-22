#!/usr/bin/env python3
"""
ioc_parser.py — Extract and defang Indicators of Compromise (IOCs) from text.

Extracts:
  - IPv4 and IPv6 addresses
  - Domains and FQDNs
  - URLs (http/https/ftp)
  - Email addresses
  - MD5, SHA1, SHA256 hashes
  - CVE identifiers (CVE-YYYY-NNNNN)
  - Windows file paths (C:\\, D:\\, etc.)
  - Windows registry keys (HKLM, HKCU, etc.)

All output is defanged by default:
  . → [.]   @ → [@]   http → hxxp   ftp → fxp

Usage:
    python ioc_parser.py --file <path> [options]
    python ioc_parser.py --text "raw string" [options]

Examples:
    python ioc_parser.py --file threat_report.txt
    python ioc_parser.py --file malware_log.txt --type ip,url --output iocs.txt
    python ioc_parser.py --text "attacker at 192.168.1.100 used https://evil.com"

Disclaimer: For authorized testing and educational use only.
"""

import argparse
import re
import os
import sys
from collections import defaultdict


# ─── IOC REGEX PATTERNS ──────────────────────────────────────────────────────

IOC_PATTERNS = {
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
        r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
        r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
    ),
    "url": re.compile(
        r"https?://[^\s\"'<>]+|ftp://[^\s\"'<>]+",
        re.IGNORECASE,
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)"
        r"+(?:com|net|org|edu|gov|mil|int|info|biz|io|co|uk|de|fr|ru|cn|htb|thm|local|internal)"
        r"\b",
        re.IGNORECASE,
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "win_path": re.compile(r"[A-Za-z]:\\(?:[^\\\s\"]+\\)*[^\\\s\"]*", re.IGNORECASE),
    "registry": re.compile(
        r"\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_USERS|HKU|"
        r"HKEY_CLASSES_ROOT|HKCR|HKEY_CURRENT_CONFIG|HKCC)"
        r"(?:\\[^\s\"'<>]+)+",
        re.IGNORECASE,
    ),
}

# Noise filters — suppress common false positives
NOISE_IPS = {
    "0.0.0.0", "127.0.0.1", "255.255.255.255", "255.255.255.0",
    "10.0.0.0", "192.168.0.0", "172.16.0.0",
}
NOISE_HASHES = {
    "00000000000000000000000000000000",
    "0000000000000000000000000000000000000000",
    "0" * 64,
    "f" * 32, "f" * 40, "f" * 64,
}
# Version-like patterns to suppress (e.g., 1.2.3.4 in version strings)
VERSION_PATTERN = re.compile(r"\bv?(\d+\.\d+\.\d+\.\d+)\b")


def defang(value: str, ioc_type: str) -> str:
    """Defang an IOC for safe sharing."""
    value = value.replace(".", "[.]")
    if ioc_type in ("url",):
        value = re.sub(r"^hxxp", "hxxp", value, flags=re.IGNORECASE)
        value = re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE)
        value = re.sub(r"^ftp", "fxp", value, flags=re.IGNORECASE)
    if ioc_type == "email":
        value = value.replace("@", "[@]")
    return value


def extract_iocs(text: str, types: list[str], defang_output: bool = True) -> dict:
    results = defaultdict(list)

    for ioc_type in types:
        if ioc_type not in IOC_PATTERNS:
            continue
        matches = IOC_PATTERNS[ioc_type].findall(text)
        seen = set()
        for match in matches:
            m = match.strip()
            if not m or m in seen:
                continue
            seen.add(m)

            # Apply noise filters
            if ioc_type == "ip":
                if m in NOISE_IPS:
                    continue
                # Skip version strings like 1.2.3.4
                if VERSION_PATTERN.match(m):
                    continue

            if ioc_type in ("md5", "sha1", "sha256"):
                if m.lower() in NOISE_HASHES:
                    continue

            # Remove domains that are actually part of URLs (avoid duplicates)
            if ioc_type == "domain":
                # Skip if domain looks like a version number
                if re.match(r"^\d+\.\d+", m):
                    continue

            display = defang(m, ioc_type) if defang_output else m
            results[ioc_type].append((m, display))

    return results


def print_iocs(results: dict, defang_output: bool = True):
    total = sum(len(v) for v in results.values())
    print(f"\n[+] Extracted {total} unique IOC(s)\n")

    type_labels = {
        "ip": "IPv4 Addresses",
        "ipv6": "IPv6 Addresses",
        "url": "URLs",
        "domain": "Domains",
        "email": "Email Addresses",
        "md5": "MD5 Hashes",
        "sha1": "SHA1 Hashes",
        "sha256": "SHA256 Hashes",
        "cve": "CVE Identifiers",
        "win_path": "Windows File Paths",
        "registry": "Registry Keys",
    }

    for ioc_type, items in results.items():
        if not items:
            continue
        label = type_labels.get(ioc_type, ioc_type.upper())
        print(f"  ── {label} ({len(items)}) ──")
        for original, displayed in items:
            note = ""
            if defang_output and original != displayed:
                pass  # defanged version already shown
            print(f"    {displayed}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="Extract and defang IOCs from text or log files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python ioc_parser.py --file threat_report.txt\n"
               "  python ioc_parser.py --file log.txt --type ip,url,sha256 --output iocs.txt\n"
               "  python ioc_parser.py --text \"192.168.1.5 connected to https://evil.com\""
    )
    parser.add_argument("--file", help="Input file to scan")
    parser.add_argument("--text", help="Inline text to scan")
    parser.add_argument("--type", default="all",
                        help=f"IOC types to extract (comma-separated or 'all'). "
                             f"Options: {', '.join(IOC_PATTERNS.keys())}. Default: all")
    parser.add_argument("--output", help="Save defanged IOCs to file")
    parser.add_argument("--no-defang", action="store_true",
                        help="Output raw IOCs without defanging")
    args = parser.parse_args()

    if not args.file and not args.text:
        parser.print_help()
        sys.exit(1)

    # Load input
    if args.file:
        if not os.path.isfile(args.file):
            print(f"[!] File not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r", errors="ignore") as f:
            text = f.read()
        print(f"\n[*] Scanning file: {args.file}  ({len(text):,} chars)")
    else:
        text = args.text
        print(f"\n[*] Scanning inline text ({len(text)} chars)")

    # Determine types
    if args.type.lower() == "all":
        types = list(IOC_PATTERNS.keys())
    else:
        types = [t.strip().lower() for t in args.type.split(",")]
        invalid = [t for t in types if t not in IOC_PATTERNS]
        if invalid:
            print(f"[!] Unknown IOC type(s): {invalid}. Valid: {list(IOC_PATTERNS.keys())}")
            sys.exit(1)

    defang_output = not args.no_defang

    results = extract_iocs(text, types, defang_output)
    print_iocs(results, defang_output)

    if args.output:
        with open(args.output, "w") as f:
            f.write("# IOC Extraction Report\n")
            f.write(f"# Source: {args.file or 'inline text'}\n\n")
            for ioc_type, items in results.items():
                if items:
                    f.write(f"## {ioc_type.upper()}\n")
                    for _, displayed in items:
                        f.write(f"{displayed}\n")
                    f.write("\n")
        print(f"[+] Saved to {args.output}")


if __name__ == "__main__":
    main()
