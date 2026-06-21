#!/usr/bin/env python3
"""
hash_checker.py — Compute, compare, and identify cryptographic hashes.

Features:
  - Hash a file or string with MD5, SHA1, SHA224, SHA256, SHA384, SHA512
  - Compare computed hash against a known value (file integrity check)
  - CTF mode: guess hash algorithm from hash length/format (--identify)
  - Recursive directory hashing (--recursive)

Usage:
    python hash_checker.py [options]

Examples:
    python hash_checker.py --file download.iso --algorithm sha256
    python hash_checker.py --file binary.exe --hash abc123... --algorithm md5
    python hash_checker.py --string "password" --algorithm all
    python hash_checker.py --identify 5f4dcc3b5aa765d61d8327deb882cf99
    python hash_checker.py --file /var/www/html --recursive

Disclaimer: For authorized testing and educational use only.
"""

import argparse
import hashlib
import os
import re
import sys

ALGORITHMS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"]

# Hash identification by length (hex chars)
HASH_ID_MAP = {
    32:  ["MD5", "NTLM (Windows password hash — 32 hex)"],
    40:  ["SHA1", "MySQL 4.1+ (*hash)"],
    48:  ["SHA224 (partial)", "Tiger-192"],
    56:  ["SHA224"],
    64:  ["SHA256", "Keccak-256"],
    96:  ["SHA384", "SHA3-384"],
    128: ["SHA512", "SHA3-512", "Whirlpool"],
}

HASH_FORMAT_PATTERNS = {
    r"^\$2[aby]\$\d+\$": "bcrypt",
    r"^\$1\$": "MD5-crypt (Unix)",
    r"^\$5\$": "SHA256-crypt (Unix)",
    r"^\$6\$": "SHA512-crypt (Unix)",
    r"^\$apr1\$": "MD5-APR (Apache)",
    r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$": "NTLM:LM (Windows old-style)",
    r"^\*[0-9A-F]{40}$": "MySQL SHA1 (*hash)",
}


def hash_data(data: bytes, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_file(path: str, algorithm: str, chunk_size: int = 65536) -> str:
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def identify_hash(hash_str: str) -> list[str]:
    """Guess the hash algorithm based on length and format patterns."""
    hash_str = hash_str.strip()
    candidates = []

    # Check format patterns first (bcrypt, crypt, etc.)
    for pattern, name in HASH_FORMAT_PATTERNS.items():
        if re.match(pattern, hash_str, re.IGNORECASE):
            candidates.append(name)

    # Check hex length
    if re.match(r"^[0-9a-fA-F]+$", hash_str):
        length = len(hash_str)
        if length in HASH_ID_MAP:
            candidates.extend(HASH_ID_MAP[length])

    return candidates if candidates else ["Unknown / not a standard hash format"]


def main():
    parser = argparse.ArgumentParser(
        description="Hash files, strings, and identify CTF hashes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python hash_checker.py --file binary.exe --algorithm sha256\n"
               "  python hash_checker.py --string password --algorithm all\n"
               "  python hash_checker.py --identify 5f4dcc3b5aa765d61d8327deb882cf99\n"
               "  python hash_checker.py --file /etc --recursive"
    )
    parser.add_argument("--file", help="File or directory to hash")
    parser.add_argument("--string", help="String to hash instead of a file")
    parser.add_argument("--algorithm", default="sha256",
                        help=f"Algorithm(s): {', '.join(ALGORITHMS)}, or 'all'. Default: sha256")
    parser.add_argument("--hash", help="Known hash value to compare against")
    parser.add_argument("--identify", help="Identify the algorithm of an unknown hash")
    parser.add_argument("--recursive", action="store_true",
                        help="Hash all files in a directory recursively")
    args = parser.parse_args()

    # ── IDENTIFY MODE ────────────────────────────────────────────────────────
    if args.identify:
        print(f"\n[*] Hash identification: {args.identify}")
        print(f"    Length : {len(args.identify)} characters")
        guesses = identify_hash(args.identify)
        print(f"    Likely : {', '.join(guesses)}")
        print("\n    Tip: Try cracking with hashcat or john the ripper")
        print("         hashcat -m <mode> hash.txt wordlist.txt")
        return

    # Determine algorithms
    if args.algorithm.lower() == "all":
        algos = ALGORITHMS
    else:
        algos = [a.strip().lower() for a in args.algorithm.split(",")]
        for a in algos:
            if a not in ALGORITHMS:
                print(f"[!] Unknown algorithm: {a}. Choose from: {', '.join(ALGORITHMS)}")
                sys.exit(1)

    # ── STRING MODE ──────────────────────────────────────────────────────────
    if args.string:
        data = args.string.encode("utf-8")
        print(f"\n[*] Hashing string: \"{args.string}\"")
        print(f"    Encoding: UTF-8  |  Bytes: {len(data)}\n")
        print(f"  {'ALGORITHM':<12}  HASH")
        print("  " + "-" * 70)
        for algo in algos:
            h = hash_data(data, algo)
            print(f"  {algo.upper():<12}  {h}")
        if args.hash:
            match = any(hash_data(data, a) == args.hash.lower() for a in algos)
            print(f"\n  [{'MATCH' if match else 'NO MATCH'}] Provided hash: {args.hash}")
        return

    # ── FILE / DIRECTORY MODE ────────────────────────────────────────────────
    if not args.file:
        parser.print_help()
        sys.exit(1)

    if os.path.isdir(args.file):
        if not args.recursive:
            print(f"[!] {args.file} is a directory. Use --recursive to hash all files.")
            sys.exit(1)

        print(f"\n[*] Recursive hash of directory: {args.file}")
        print(f"    Algorithm: {', '.join(a.upper() for a in algos)}\n")
        print(f"  {'ALGORITHM':<12}  {'FILE':<50}  HASH")
        print("  " + "-" * 90)
        for root, dirs, files in os.walk(args.file):
            dirs.sort()
            for fname in sorted(files):
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, args.file)
                for algo in algos:
                    try:
                        h = hash_file(fpath, algo)
                        print(f"  {algo.upper():<12}  {rel:<50}  {h}")
                    except (PermissionError, OSError) as e:
                        print(f"  {algo.upper():<12}  {rel:<50}  [ERROR: {e}]")
        return

    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}")
        sys.exit(1)

    file_size = os.path.getsize(args.file)
    print(f"\n[*] File      : {args.file}")
    print(f"    Size      : {file_size:,} bytes")
    print(f"    Algorithm : {', '.join(a.upper() for a in algos)}\n")
    print(f"  {'ALGORITHM':<12}  HASH")
    print("  " + "-" * 75)

    computed = {}
    for algo in algos:
        try:
            h = hash_file(args.file, algo)
        except (PermissionError, OSError) as e:
            print(f"  {algo.upper():<12}  [ERROR: {e}]")
            continue
        computed[algo] = h
        print(f"  {algo.upper():<12}  {h}")

    if args.hash:
        known = args.hash.strip().lower()
        print()
        matched_algo = None
        for algo, h in computed.items():
            if h == known:
                matched_algo = algo
                break
        if matched_algo:
            print(f"  [✓ MATCH]  Hash matches {matched_algo.upper()} — file integrity verified.")
        else:
            print("  [✗ NO MATCH]  Provided hash does not match any computed value.")
            print(f"               Provided : {known}")
            guesses = identify_hash(known)
            print(f"               Hash type: {', '.join(guesses)}")


if __name__ == "__main__":
    main()
