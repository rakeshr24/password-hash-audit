#!/usr/bin/env python3
"""
hash_audit.py — Password Hash Audit Tool

Identifies the likely algorithm behind a set of password hashes, attempts to
crack weak ones against a wordlist, and produces a report with hardening
recommendations.

Educational project. Only run against hashes you are authorized to test
(your own lab data, CTF material, or an engagement you have written
permission for).

Usage:
    python3 hash_audit.py --hashes data/hashes.txt --wordlist data/wordlist.txt
    python3 hash_audit.py --hashes data/hashes.txt --wordlist data/wordlist.txt --report report.md
"""

import argparse
import hashlib
import re
import sys
from collections import Counter
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Hash identification
# ---------------------------------------------------------------------------
# Each entry maps a human-readable name to the length (in hex characters) and
# a regex the hash must match. Length alone is ambiguous (MD5 and NTLM are both
# 32 hex chars), so we keep ordering deliberate and report ambiguity honestly.
HASH_SIGNATURES = [
    ("MD5",     32, re.compile(r"^[a-fA-F0-9]{32}$")),
    ("NTLM",    32, re.compile(r"^[a-fA-F0-9]{32}$")),
    ("SHA-1",   40, re.compile(r"^[a-fA-F0-9]{40}$")),
    ("SHA-224", 56, re.compile(r"^[a-fA-F0-9]{56}$")),
    ("SHA-256", 64, re.compile(r"^[a-fA-F0-9]{64}$")),
    ("SHA-384", 96, re.compile(r"^[a-fA-F0-9]{96}$")),
    ("SHA-512", 128, re.compile(r"^[a-fA-F0-9]{128}$")),
]

# Algorithms we can actually compute with the standard library, so we know
# which identified hashes we can attempt to crack.
CRACKABLE = {
    "MD5": lambda w: hashlib.md5(w.encode()).hexdigest(),
    "SHA-1": lambda w: hashlib.sha1(w.encode()).hexdigest(),
    "SHA-224": lambda w: hashlib.sha224(w.encode()).hexdigest(),
    "SHA-256": lambda w: hashlib.sha256(w.encode()).hexdigest(),
    "SHA-384": lambda w: hashlib.sha384(w.encode()).hexdigest(),
    "SHA-512": lambda w: hashlib.sha512(w.encode()).hexdigest(),
    "NTLM": lambda w: hashlib.new("md4", w.encode("utf-16le")).hexdigest(),
}


def identify(hash_str):
    """Return a list of candidate algorithm names for a single hash string."""
    candidates = [name for name, length, pattern in HASH_SIGNATURES
                  if pattern.match(hash_str)]
    return candidates or ["UNKNOWN"]


def load_lines(path):
    """Read a file into a list of stripped, non-empty, non-comment lines."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh
                    if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        sys.exit(f"[!] File not found: {path}")


def crack(hash_str, candidates, wordlist):
    """
    Try every word in the wordlist against each candidate algorithm.
    Returns (plaintext, algorithm) on the first match, or (None, None).
    """
    for algo in candidates:
        compute = CRACKABLE.get(algo)
        if not compute:
            continue
        target = hash_str.lower()
        for word in wordlist:
            if compute(word).lower() == target:
                return word, algo
    return None, None


def build_report(results, wordlist_size):
    """Assemble a Markdown report string from the per-hash results."""
    cracked = [r for r in results if r["plaintext"] is not None]
    algo_counts = Counter(c for r in results for c in r["candidates"])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append("# Password Hash Audit Report")
    lines.append("")
    lines.append(f"- Generated: {now}")
    lines.append(f"- Hashes analyzed: {len(results)}")
    lines.append(f"- Wordlist entries tried: {wordlist_size}")
    lines.append(f"- Hashes cracked: {len(cracked)} "
                 f"({len(cracked) / len(results) * 100:.0f}% of total)")
    lines.append("")

    lines.append("## Algorithms observed")
    lines.append("")
    lines.append("| Algorithm | Count |")
    lines.append("| --- | --- |")
    for algo, count in algo_counts.most_common():
        lines.append(f"| {algo} | {count} |")
    lines.append("")

    lines.append("## Results")
    lines.append("")
    lines.append("| Hash (truncated) | Likely algorithm | Cracked | Plaintext |")
    lines.append("| --- | --- | --- | --- |")
    for r in results:
        short = r["hash"][:16] + "..."
        algo = r["matched_algo"] or " / ".join(r["candidates"])
        if r["plaintext"] is not None:
            lines.append(f"| `{short}` | {algo} | yes | `{r['plaintext']}` |")
        else:
            lines.append(f"| `{short}` | {algo} | no | — |")
    lines.append("")

    lines.append("## Findings & hardening recommendations")
    lines.append("")
    weak_algos = {"MD5", "SHA-1", "NTLM"} & set(algo_counts)
    if weak_algos:
        lines.append(f"- **Weak/fast algorithms in use:** {', '.join(sorted(weak_algos))}. "
                     "These are unsalted, fast to compute, and unsuitable for storing "
                     "passwords. An attacker with the hash file can try billions of "
                     "guesses per second on commodity GPUs.")
    if cracked:
        lines.append(f"- **{len(cracked)} password(s) recovered from a small wordlist.** "
                     "Any hash cracked this quickly reflects a weak, common, or reused "
                     "password — not just a weak algorithm.")
    lines.append("- **Use a slow, salted password hash** designed for the job: "
                 "bcrypt, scrypt, or Argon2id. These add a per-user salt and a tunable "
                 "work factor, so cracking stays expensive even if the database leaks.")
    lines.append("- **Enforce length over complexity.** A 14+ character passphrase "
                 "beats a short string with symbol substitutions against modern cracking.")
    lines.append("- **Block known-breached passwords** at set time (e.g. check against "
                 "the Have I Been Pwned range API) and **enable MFA** so a cracked "
                 "password alone is not enough.")
    lines.append("")
    lines.append("---")
    lines.append("*Generated by hash_audit.py. For authorized testing and education only.*")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Identify password hashes and crack weak ones against a wordlist.")
    parser.add_argument("--hashes", required=True,
                        help="File with one hash per line.")
    parser.add_argument("--wordlist", required=True,
                        help="Wordlist file, one candidate password per line.")
    parser.add_argument("--report", default=None,
                        help="Optional path to write a Markdown report.")
    args = parser.parse_args()

    hashes = load_lines(args.hashes)
    wordlist = load_lines(args.wordlist)

    if not hashes:
        sys.exit("[!] No hashes found to analyze.")

    print(f"[*] Loaded {len(hashes)} hashes and {len(wordlist)} wordlist entries.\n")

    results = []
    for h in hashes:
        candidates = identify(h)
        plaintext, matched_algo = crack(h, candidates, wordlist)
        results.append({
            "hash": h,
            "candidates": candidates,
            "plaintext": plaintext,
            "matched_algo": matched_algo,
        })
        status = f"CRACKED -> {plaintext}" if plaintext else "not cracked"
        print(f"  {h[:16]}...  [{' / '.join(candidates)}]  {status}")

    cracked = sum(1 for r in results if r["plaintext"])
    print(f"\n[*] Done. Cracked {cracked}/{len(results)}.")

    report = build_report(results, len(wordlist))
    if args.report:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write(report)
        print(f"[*] Report written to {args.report}")


if __name__ == "__main__":
    main()
