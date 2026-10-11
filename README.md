# Password Hash Audit

A Python tool that identifies the likely algorithm behind a set of password
hashes, attempts to crack weak ones against a wordlist, and produces a
report with hardening recommendations.

Built as a hands-on cybersecurity lab to demonstrate why fast, unsalted hash
algorithms are unsuitable for storing passwords.

## What it does

1. **Identifies** each hash by length and format (MD5, NTLM, SHA-1,
   SHA-224/256/384/512).
2. **Cracks** weak hashes by computing the hash of every word in a wordlist
   and comparing (a dictionary attack).
3. **Reports** which passwords were recovered and recommends stronger
   practices (bcrypt/scrypt/Argon2id, length over complexity, breach checks,
   MFA).

## Usage

```bash
python3 hash_audit.py --hashes hashes.txt --wordlist wordlist.txt
python3 hash_audit.py --hashes hashes.txt --wordlist wordlist.txt --report report.md
```

## Example output

```
  482c811da5d5b4bc...  [MD5 / NTLM]  CRACKED -> password123
  b1b3773a05c0ed01...  [SHA-1]       CRACKED -> qwerty
  1c8bfe8f801d7974...  [SHA-256]     CRACKED -> letmein
  032d033b3b161220...  [SHA-256]     not cracked

[*] Done. Cracked 8/9.
```

The one hash that doesn't crack uses a long, uncommon passphrase — it isn't in
the wordlist, which is exactly the point: a strong password resists a
dictionary attack even when the algorithm is weak.

## How it works

- `identify()` matches each hash against known length/format signatures.
  MD5 and NTLM are both 32 hex characters, so the tool reports both
  candidates honestly rather than guessing.
- `crack()` runs a dictionary attack: for each candidate algorithm it hashes
  every wordlist entry and compares against the target. This is fast because
  MD5/SHA are designed to be fast — the same property that makes them a bad
  choice for passwords.
- `build_report()` summarizes the algorithms seen, the crack rate, and
  concrete hardening steps.

## Why this matters (the security lesson)

Fast hashes like MD5 and SHA-256 can be computed billions of times per second
on a GPU. If a password database using them leaks, common passwords fall
almost instantly. Password storage should use a **slow, salted** algorithm —
bcrypt, scrypt, or Argon2id — with a per-user salt and a tunable work factor,
so cracking stays expensive even after a breach.

## Files

```
hash_audit.py    # the tool
hashes.txt       # sample hashes (generated from test passwords)
wordlist.txt     # small demo wordlist of common passwords
```

## Responsible use

Everything here is generated from throwaway test passwords and is safe to
publish. Only run this against hashes you are authorized to test: your own lab
data, CTF material, or an engagement you have written permission for.
