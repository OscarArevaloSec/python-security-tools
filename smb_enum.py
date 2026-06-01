#!/usr/bin/env python3
"""
smb_enum.py — SMB enumeration helper.

Layers multiple techniques:
  1. Pure Python: port 445 TCP check (always runs, no tools needed)
  2. nmblookup: NetBIOS name lookup (part of samba-common package)
  3. smbclient: share listing and null-session access check (--shares)
  4. rpcclient: domain user/group enumeration (--rpc)

Usage:
    python smb_enum.py --target <ip> [options]

Examples:
    python smb_enum.py --target 10.10.10.10
    python smb_enum.py --target 10.10.10.10 --shares
    python smb_enum.py --target 10.10.10.10 --shares --rpc
    python smb_enum.py --target 10.10.10.10 --user oscar --password Password1 --shares

Install samba tools (Kali/Ubuntu):
    sudo apt install smbclient

Disclaimer: For authorized testing and educational use only.
"""

import argparse
import shutil
import socket
import sys

from common import run_cmd

BANNER = """
╔══════════════════════════════════╗
║         SMB Enumerator           ║
╚══════════════════════════════════╝"""


def check_port(target: str, port: int = 445, timeout: float = 3.0) -> bool:
    """Pure Python TCP check for SMB port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def tool_check(name: str) -> bool:
    found = shutil.which(name) is not None
    status = "✓ available" if found else "✗ not found (sudo apt install smbclient)"
    print(f"    {name:<15} {status}")
    return found


def netbios_lookup(target: str):
    print("\n[*] NetBIOS Name Lookup (nmblookup)")
    print("-" * 40)
    out, err = run_cmd(["nmblookup", "-A", target])
    if out:
        print(out)
    elif err:
        print(err)
    else:
        print("[!] No response")


def list_shares(target: str, user: str, password: str):
    print("\n[*] Share Enumeration (smbclient)")
    print("-" * 40)

    # Try null session first, then credentials
    auth_modes = []
    if user:
        auth_modes.append(("credentials", ["-U", f"{user}%{password}" if password else f"{user}%"]))
    auth_modes.append(("null session", ["-U", "%", "-N"]))

    for label, auth_args in auth_modes:
        print(f"\n    Trying {label}...")
        cmd = ["smbclient", "-L", f"//{target}/"] + auth_args
        out, err = run_cmd(cmd)

        if out:
            print(out)
            # Try accessing each share
            shares = []
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[1] in ("Disk", "IPC", "Printer"):
                    shares.append(parts[0])

            if shares:
                print(f"\n[*] Probing {len(shares)} share(s) for access:")
                for share in shares:
                    probe_cmd = ["smbclient", f"//{target}/{share}", "-c", "dir"] + auth_args
                    pout, perr = run_cmd(probe_cmd, timeout=10)
                    if pout and "NT_STATUS" not in pout:
                        print(f"    [+] Accessible: {share}")
                    else:
                        print(f"    [-] Denied: {share}")
            break
        else:
            print(f"    [-] Failed ({err[:80] if err else 'no output'})")


def rpc_enum(target: str, user: str, password: str):
    print("\n[*] RPC Enumeration (rpcclient)")
    print("-" * 40)

    auth_str = f"{user}%{password}" if user and password else "%"
    auth_args = ["-U", auth_str]
    if not user:
        auth_args += ["-N"]

    commands = [
        ("Server info",       "srvinfo"),
        ("Domain users",      "enumdomusers"),
        ("Domain groups",     "enumdomgroups"),
        ("Password policy",   "getdompwinfo"),
        ("OS info",           "lsaquery"),
    ]

    for label, rpc_cmd in commands:
        cmd = ["rpcclient", target] + auth_args + ["-c", rpc_cmd]
        out, err = run_cmd(cmd, timeout=10)
        print(f"\n    [{label}]")
        if out:
            for line in out.splitlines()[:20]:  # cap at 20 lines per command
                print(f"    {line}")
        else:
            print(f"    [-] No output ({err[:60] if err else 'no response'})")


def main():
    parser = argparse.ArgumentParser(
        description="SMB enumeration helper (null sessions, shares, RPC)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n  python smb_enum.py --target 10.10.10.10 --shares --rpc"
    )
    parser.add_argument("--target", required=True, help="Target IP or hostname")
    parser.add_argument("--user", default="", help="Username (optional, for authenticated enum)")
    parser.add_argument("--password", default="", help="Password (optional)")
    parser.add_argument("--shares", action="store_true", help="Enumerate shares via smbclient")
    parser.add_argument("--rpc", action="store_true", help="Enumerate users/groups via rpcclient")
    args = parser.parse_args()

    print(BANNER)
    print(f"\n[*] Target: {args.target}")

    # Tool availability check
    print("\n[*] Tool Check:")
    has_nmblooup = tool_check("nmblookup")
    has_smbclient = tool_check("smbclient")
    has_rpcclient = tool_check("rpcclient")

    # Port check
    print("\n[*] Port Check:")
    for port in [139, 445]:
        open_ = check_port(args.target, port)
        status = "OPEN" if open_ else "closed"
        print(f"    TCP/{port:<6} {status}")

    if not check_port(args.target, 445) and not check_port(args.target, 139):
        print("\n[!] Neither 139 nor 445 appear open. SMB may be blocked or not running.")
        sys.exit(1)

    # NetBIOS
    if has_nmblooup:
        netbios_lookup(args.target)
    else:
        print("\n[-] Skipping NetBIOS lookup (nmblookup not found)")

    # Shares
    if args.shares:
        if has_smbclient:
            list_shares(args.target, args.user, args.password)
        else:
            print("\n[-] Cannot list shares: smbclient not found")

    # RPC
    if args.rpc:
        if has_rpcclient:
            rpc_enum(args.target, args.user, args.password)
        else:
            print("\n[-] Cannot run RPC enum: rpcclient not found")

    print("\n[+] SMB enumeration complete.")


if __name__ == "__main__":
    main()
