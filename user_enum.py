#!/usr/bin/env python3
"""
user_enum.py — Username enumeration via HTTP response analysis or SMB/RPC.

Modes:
  http  — POST usernames to a login endpoint; detect valid users via response
          length/keyword differences or timing deviations.
  smb   — Enumerate users via rpcclient null session (enumdomusers), with
          optional RID brute-force fallback (--rid-brute).

Usage:
    python user_enum.py --target <ip> --mode <http|smb> --wordlist <file> [options]

Examples:
    python user_enum.py --target 10.10.10.10 --mode smb --wordlist /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
    python user_enum.py --target 10.10.10.10 --mode smb --rid-brute --rid-range 500-1200
    python user_enum.py --target 10.10.10.10 --mode http --wordlist users.txt --url http://10.10.10.10/login --user-field username --pass-field password

Install dependency for HTTP mode:
    pip install requests

Disclaimer: For authorized testing and educational use only.
"""

import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from common import cap_threads, run_cmd

try:
    import requests
    import urllib3
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def load_wordlist(path: str) -> list[str]:
    if not os.path.isfile(path):
        print(f"[!] Wordlist not found: {path}")
        sys.exit(1)
    with open(path, errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# ─── HTTP MODE ────────────────────────────────────────────────────────────────

INVALID_USER_KEYWORDS = [
    "no account", "user not found", "invalid user", "does not exist",
    "unknown user", "no such user", "account not found",
]
WRONG_PASS_KEYWORDS = [
    "wrong password", "incorrect password", "bad password",
    "invalid password", "invalid credentials", "authentication failed",
    "login failed",
]


def calibrate(session, url: str, user_field: str, pass_field: str,
              fake_user: str = "zz_nonexistent_user_zz123", verify: bool = True) -> dict:
    """Measure baseline response for a definitely-invalid user."""
    data = {user_field: fake_user, pass_field: "x"}
    t0 = time.perf_counter()
    resp = session.post(url, data=data, timeout=10, verify=verify,
                        allow_redirects=False)
    elapsed = time.perf_counter() - t0
    return {
        "status": resp.status_code,
        "length": len(resp.content),
        "time": elapsed,
        "text": resp.text.lower(),
    }


def classify_http(resp_text: str, resp_len: int, resp_time: float,
                  baseline: dict, time_threshold: float = 0.3,
                  len_threshold: int = 50) -> str:
    """Return 'valid', 'invalid', or 'unknown'."""
    text_lower = resp_text.lower()

    for kw in WRONG_PASS_KEYWORDS:
        if kw in text_lower:
            return "valid"

    for kw in INVALID_USER_KEYWORDS:
        if kw in text_lower:
            return "invalid"

    # Length deviation
    len_diff = abs(resp_len - baseline["length"])
    if len_diff > len_threshold:
        return "valid"

    # Timing deviation
    time_diff = resp_time - baseline["time"]
    if time_diff > time_threshold:
        return "valid"

    return "unknown"


def http_enum(args):
    if not HAS_REQUESTS:
        print("[!] requests library required. pip install requests")
        sys.exit(1)

    if not args.url:
        print("[!] --url required for HTTP mode")
        sys.exit(1)

    session = requests.Session()
    verify = not getattr(args, "insecure", False)
    if not verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    words = load_wordlist(args.wordlist)

    print("\n[*] HTTP User Enumeration")
    print(f"    Target URL   : {args.url}")
    print(f"    User field   : {args.user_field}")
    print(f"    Pass field   : {args.pass_field}")
    print(f"    Wordlist     : {len(words)} usernames\n")

    print("[*] Calibrating baseline response...")
    try:
        baseline = calibrate(session, args.url, args.user_field, args.pass_field, verify=verify)
    except Exception as e:
        print(f"[!] Calibration failed: {e}")
        sys.exit(1)
    print(f"    Baseline: status={baseline['status']} len={baseline['length']} time={baseline['time']:.3f}s\n")

    print(f"{'USERNAME':<25} {'STATUS':<8} {'LEN':<8} {'TIME':<8} {'VERDICT'}")
    print("-" * 65)

    valid_users = []

    def probe_user(username: str):
        data = {args.user_field: username, args.pass_field: "x"}
        try:
            t0 = time.perf_counter()
            resp = session.post(args.url, data=data, timeout=10,
                                verify=verify, allow_redirects=False)
            elapsed = time.perf_counter() - t0
            verdict = classify_http(resp.text, len(resp.content), elapsed, baseline)
            return {
                "user": username,
                "status": resp.status_code,
                "length": len(resp.content),
                "time": elapsed,
                "verdict": verdict,
            }
        except Exception:
            return {"user": username, "status": 0, "length": 0, "time": 0, "verdict": "error"}

    threads = cap_threads(args.threads)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probe_user, w): w for w in words}
        for future in as_completed(futures):
            r = future.result()
            if r["verdict"] in ("valid", "unknown"):
                marker = "[+]" if r["verdict"] == "valid" else "[?]"
                print(f"{r['user']:<25} {r['status']:<8} {r['length']:<8} {r['time']:.3f}s   {r['verdict']} {marker}")
                if r["verdict"] == "valid":
                    valid_users.append(r["user"])

    print(f"\n[+] Likely valid users: {valid_users if valid_users else 'none detected'}")


# ─── SMB MODE ─────────────────────────────────────────────────────────────────

def smb_enumdomusers(target: str) -> list[str]:
    print("[*] Trying enumdomusers (null session)...")
    out, err = run_cmd(["rpcclient", "-U", "%", "-N", target, "-c", "enumdomusers"])
    users = []
    if out:
        for line in out.splitlines():
            # Format: user:[username] rid:[0x...]
            if "user:[" in line:
                try:
                    user = line.split("user:[")[1].split("]")[0]
                    users.append(user)
                    print(f"    [+] {user}")
                except IndexError:
                    pass
    else:
        print(f"    [-] Failed: {err[:80]}")
    return users


def rid_brute(target: str, rid_range: str) -> list[str]:
    """Brute-force RIDs to enumerate user accounts."""
    try:
        start, end = (int(x) for x in rid_range.split("-", 1))
    except ValueError:
        print(f"[!] Invalid --rid-range '{rid_range}'. Expected format: START-END (e.g. 500-1200)")
        return []
    if start > end:
        print(f"[!] --rid-range start ({start}) is greater than end ({end}).")
        return []
    print(f"\n[*] RID Brute Force: {start}–{end} (looking for user/group SIDs)")

    users = []
    # Resolve the domain SID first, then enumerate by appending each RID.
    out, err = run_cmd(["rpcclient", "-U", "%", "-N", target, "-c", "lsaquery"])
    domain_sid = None
    for line in out.splitlines():
        if "Domain Sid:" in line:
            domain_sid = line.split("Domain Sid:")[1].strip()
            print(f"    [*] Domain SID: {domain_sid}")
            break

    if not domain_sid:
        print("    [-] Could not get domain SID for RID brute force")
        return []

    for rid in range(start, end + 1):
        full_sid = f"{domain_sid}-{rid}"
        out, err = run_cmd(["rpcclient", "-U", "%", "-N", target,
                            "-c", f"lookupsids {full_sid}"], timeout=5)
        if out and "UNKNOWN" not in out.upper() and out.strip():
            # Format: S-1-5-... domain\username (type)
            parts = out.split()
            if len(parts) >= 2:
                name = parts[1]
                stype = parts[2] if len(parts) > 2 else ""
                if "User" in stype or "Group" in stype:
                    print(f"    [+] RID {rid}: {name} ({stype})")
                    users.append(name)

    return users


def smb_enum_mode(args):
    target = args.target
    print("\n[*] SMB User Enumeration")
    print(f"    Target: {target}\n")

    found = smb_enumdomusers(target)

    if args.rid_brute:
        rid_range = args.rid_range or "500-1200"
        found += rid_brute(target, rid_range)

    found = list(set(found))
    print(f"\n[+] Total users found: {len(found)}")
    if found:
        print("    " + "\n    ".join(sorted(found)))

    if args.output and found:
        with open(args.output, "w") as f:
            for u in sorted(found):
                f.write(u + "\n")
        print(f"\n[+] Saved to {args.output}")


# ─── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Username enumeration via HTTP response analysis or SMB/RPC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python user_enum.py --target 10.10.10.10 --mode smb --rid-brute\n"
               "  python user_enum.py --target 10.10.10.10 --mode http --url http://10.10.10.10/login --wordlist users.txt"
    )
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--mode", required=True, choices=["http", "smb"],
                        help="Enumeration mode: http or smb")
    parser.add_argument("--wordlist", help="Username wordlist (required for http mode)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Threads for HTTP mode (default: 10)")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS verification in HTTP mode (self-signed lab targets)")
    parser.add_argument("--output", help="Save found usernames to file")

    # HTTP options
    parser.add_argument("--url", help="Login URL for HTTP mode")
    parser.add_argument("--user-field", default="username",
                        help="HTML form field name for username (default: username)")
    parser.add_argument("--pass-field", default="password",
                        help="HTML form field name for password (default: password)")

    # SMB options
    parser.add_argument("--rid-brute", action="store_true",
                        help="Enable RID brute force in SMB mode")
    parser.add_argument("--rid-range", default="500-1200",
                        help="RID range for brute force (default: 500-1200)")

    args = parser.parse_args()

    if args.mode == "http":
        if not args.wordlist:
            print("[!] --wordlist required for HTTP mode")
            sys.exit(1)
        http_enum(args)
    else:
        smb_enum_mode(args)


if __name__ == "__main__":
    main()
