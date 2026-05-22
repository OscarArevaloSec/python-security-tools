#!/usr/bin/env python3
"""
log_parser.py — Linux auth.log / syslog / Windows event log text analyser.

Detects:
  - Failed SSH login attempts (with IP extraction)
  - Successful SSH logins
  - Sudo command usage
  - su (switch user) events
  - New user/group creation
  - Account lockouts
  - Brute-force pattern detection (many failures from same IP)

Usage:
    python log_parser.py --file <log> [options]

Examples:
    python log_parser.py --file /var/log/auth.log
    python log_parser.py --file /var/log/auth.log --filter failed --brute-threshold 5
    python log_parser.py --file auth.log --type auth --output report.txt
    python log_parser.py --file secure.log --type auth --filter all

Disclaimer: For authorized testing and educational use only.
"""

import argparse
import re
import os
import sys
from collections import defaultdict
from datetime import datetime


# ─── REGEX PATTERNS ──────────────────────────────────────────────────────────

PATTERNS = {
    "ssh_fail": re.compile(
        r"(?P<date>\w+\s+\d+\s+[\d:]+).*Failed password for (?i:invalid user )?(?P<user>\S+) from (?P<ip>[\d\.]+)",
        re.IGNORECASE,
    ),
    "ssh_success": re.compile(
        r"(?P<date>\w+\s+\d+\s+[\d:]+).*Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d\.]+)",
        re.IGNORECASE,
    ),
    "sudo": re.compile(
        r"(?P<date>\w+\s+\d+\s+[\d:]+).*sudo.*:\s+(?P<user>\S+)\s+:.*COMMAND=(?P<cmd>.+)",
        re.IGNORECASE,
    ),
    "su": re.compile(
        r"(?P<date>\w+\s+\d+\s+[\u:]+).*su\[.*\].*session (?P<action>opened|closed) for user (?P<user>\S+)",
        re.IGNORECASE,
    ),
    "new_user": re.compile(
        r"(?P<date>\w+\s+\d+\s+[\d:]+).*useradd.*new user.*name=(?P<user>\S+)",
        re.IGNORECASE,
    ),
    "new_group": re.compile(
        r"(?P<date>\w+\s+\d+\s+[\u:]+).*groupadd.*new group.*name=(?P<group>\S+)",
        re.IGNORECASE,
    ),
    "lockout": re.compile(
        r"(?P<date>\w+\s+\d+\s+[\d:]+).*pam_faillock.*user (?P<user>\S+) .*(locked|unlock)",
        re.IGNORECASE,
    ),
    # Windows Event Log text export patterns
    "win_logon_fail": re.compile(
        r"An account failed to log on.*?Account Name:\s+(?P<user>\S+).*?Source Network Address:\s+(?P<ip>[\d\.]+)",
        re.DOTALL | re.IGNORECASE,
    ),
    "win_logon_success": re.compile(
        r"An account was successfully logged on.*?Account Name:\s+(?P<user>\S+).*?Source Network Address:\s+(?P<ip>[\d\.]+)",
        re.DOTALL | re.IGNORECASE,
    ),
}


def parse_file(path: str, filter_type: str, brute_threshold: int, log_type: str) -> dict:
    """Parse a log file and return categorised events."""
    results = {
        "ssh_fail": [],
        "ssh_success": [],
        "sudo": [],
        "su": [],
        "new_user": [],
        "new_group": [],
        "lockout": [],
        "win_logon_fail": [],
        "win_logon_success": [],
        "brute_force": [],
    }
    ip_fail_count: dict[str, int] = defaultdict(int)
    ip_fail_users: dict[str, set] = defaultdict(set)

    if not os.path.isfile(path):
        print(f"[!] File not found: {path}")
        sys.exit(1)

    with open(path, "r", errors="ignore") as f:
        content = f.read()

    lines = content.splitlines()
    total_lines = len(lines)

    # For Windows logs the content may span multiple lines per event
    if log_type == "windows":
        # Match block patterns across the whole file
        for key in ("win_logon_fail", "win_logon_success"):
            for m in PATTERNS[key].finditer(content):
                results[key].append(m.groupdict())
    else:
        for line in lines:
            for key, pattern in PATTERNS.items():
                if key.startswith("win_"):
                    continue
                m = pattern.search(line)
                if m:
                    data = m.groupdict()
                    results[key].append(data)
                    if key == "ssh_fail" and "ip" in data:
                        ip_fail_count[data["ip"]] += 1
                        if "user" in data:
                            ip_fail_users[data["ip"]].add(data["user"])

    # Brute-force detection
    for ip, count in ip_fail_count.items():
        if count >= brute_threshold:
            results["brute_force"].append({
                "ip": ip,
                "count": count,
                "users": sorted(ip_fail_users[ip]),
            })
    results["brute_force"].sort(key=lambda x: x["count"], reverse=True)

    return results, total_lines


def print_section(title: str, items: list, keys: list[str], labels: list[str]):
    if not items:
        print(f"  None detected.")
        return
    header = "  " + "  ".join(f"{l:<20}" for l in labels)
    print(header)
    print("  " + "-" * (len(header) - 2))
    for item in items[:50]:  # cap display at 50 per section
        row = "  " + "  ".join(f"{a4r(item.get(k, '')):<20}" for k in keys)
        print(row)
    if len(items) > 50:
        print(f"  ... and {len(items) - 50} more")


def main():
    parser = argparse.ArgumentParser(
        description="Linux auth.log / syslog / Windows event log analyser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python log_parser.py --file /var/log/auth.log --filter failed --brute-threshold 5"
    )
    parser.add_argument("--file", required=True, help="Path to log file")
    parser.add_argument("--type", choices=["auth", "syslog", "windows"], default="auth",
                        help="Log type (default: auth)")
    parser.add_argument("--filter", choices=["failed", "success", "all"], default="all",
                        help="Filter events to show (default: all)")
    parser.add_argument("--brute-threshold", type=int, default=5,
                        help="Failures from same IP to flag as brute force (default: 5)")
    parser.add_argument("--output", help="Save report to file")
    args = parser.parse_args()

    print(f"\n[*] Log Parser")
    print(f"    File      : {args.file}")
    print(f"    Type      : {args.type}")
    print(f"    Filter    : {args.filter}")
    print(f"    Brute thr.: {args.brute_threshold} failures/IP\n")

    results, total_lines = parse_file(args.file, args.filter, args.brute_threshold, args.type)

    report_lines = []

    def out(line=""):
        print(line)
        report_lines.append(line)

    out(f"{'='*60}")
    out(f" Log Analysis Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    out(f" File: {args.file}  |  Lines: {total_lines}")
    out(f"{'='*60}")

    if args.filter in ("failed", "all"):
        out(f"\n[SSH FAILED LOGINS]  ({len(results['ssh_fail'])} events)")
        if results["ssh_fail"]:
            out(f"  {'DATE':<20}  { 'USER':<20}  { 'SOURCE IP'}")
            out("  " + "-" * 55)
            for e in results["ssh_fail"][:50]:
                out(f"  {e.get('date',''):<20}  {e.get('user',''):<20}  {e.get('ip','')}")
            if len(results["ssh_fail"]) > 50:
                out(f"  ... and {len(results['ssh_fail']) - 50} more")
        else:
            out("  None detected.")

        out(f"\n[BRUTE FORCE DETECTION]  (threshold: ≥{args.brute_threshold} failures/IP)")
        if results["brute_force"]:
            out(f"  {'SOURCE IP':<20}  {'FAILURES':<12}  TARGETED USERS")
            out("  " + "-" * 60)
            for e in results["brute_force"]:
                users_str = ", ".join(e["users"])[:40]
                out(f"  {e['ip']:<20}  {e['count']:<12}  {users_str}")
        else:
            out(f"  No IPs exceeded threshold of {args.brute_threshold}.")

    if args.filter in ("success", "all"):
        out(f"\n[SSH SUCCESSFUL LOGINS]  ({len(results['ssh_success'])} events)")
        if results["ssh_success"]:
            out(f"  {'DATE':<20}  {'USER':<20}  {'SOURCE IP'}")
            out("  " + "-" * 55)
            for e in results["ssh_success"][:50]:
                out(f"  {e.get('date',''):<20}  {e.get('user',''):<20}  {e.get('ip','')}")
        else:
            out("  None detected.")

    if args.filter == "all":
        out(f"\n[SUDO USAGE]  ({len(results['sudo'])} events)")
        if results["sudo"]:
            out(f"  {'DATE':<20}  {'USER':<20}  COMMAND")
            out("  " + "-" * 70)
            for e in results["sudo"][:30]:
                cmd_str = str(e.get("cmd", ""))[:40]
                out(f"  {e.get('date',''):<20}  {e.get('user',''):<20}  {cmd_str}")
        else:
            out("  None detected.")

        out(f"\n[NEW USER/GROUP CREATION]")
        for e in results["new_user"]:
            out(f"  [+] New user  : {e.get('user','')} at {e.get('date','')}")
        for e in results["new_group"]:
            out(f"  [+] New group : {e.get('group','')} at {e.get('date','')}")
        if not results["new_user"] and not results["new_group"]:
            out("  None detected.")

        out(f"\n[ACCOUNT LOCKOUTS]  ({len(results['lockout'])} events)")
        if results["lockout"]:
            for e in results["lockout"][:20]:
                out(f"  {e.get('date','')}  {e.get('user','')}")
        else:
            out("  None detected.")

    out(f"\n{'='*60}")
    out(f" Summary:")
    out(f"   SSH failures       : {len(results['ssh_fail'])}")
    out(f"   SSH successes      : {len(results['ssh_success'])}")
    out(f"   Brute-force IPs    : {len(results['brute_force'])}")
    out(f"   Sudo events        : {len(results['sudo'])}")
    out(f"   New users created  : {len(results['new_user'])}")
    out(f"   Lockouts           : {len(results['lockout'])}")
    out(f"{'='*60}\n")

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(report_lines))
        print(f"[+] Report saved to {args.output}")


if __name__ == "__main__":
    main()
