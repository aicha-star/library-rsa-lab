#!/usr/bin/env python3
"""
Generates unique RSA lab parameters for a CyberRangeCZ sandbox.
Called by Ansible during provisioning; writes secrets to /opt/rsalab/secrets.json
(root-only) and a student-readable params.txt to ~/rsalab/params.txt.

Usage:
  python3 gen_params.py --flag0 F0 --flag1 F1 --flag2 F2 \\
                        --flag3 F3 --flag4 F4 --flag5 F5 --flag6 F6
"""

import argparse, json, os, random, sys
from math import gcd

SECRETS_PATH = "/opt/rsalab/secrets.json"
LAB_DIR      = "/home/ubuntu/rsalab"

# ─── Primality (Miller-Rabin, 20 rounds — no library dependencies) ──────────

def _is_prime(n, rounds=20):
    if n < 2: return False
    if n < 4: return True
    if n % 2 == 0 or n % 3 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True

def _gen_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1))   # ensure MSB is set (correct bit-length)
        n |= 1                    # ensure odd
        if _is_prime(n):
            return n

def _modinv(a, m):
    """Extended Euclidean Algorithm — returns a^-1 mod m."""
    if m == 1: return 0
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m; m, a = a % m, m; x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

def _hex(n):
    """Return uppercase hex string without 0x prefix."""
    return format(n, 'X')

# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    for i in range(7):
        parser.add_argument(f'--flag{i}', required=True)
    args = parser.parse_args()
    flags = {str(i): getattr(args, f'flag{i}') for i in range(7)}

    E = 0x10001  # Public exponent (65537)

    # ── Static data (identical for all sandboxes, as in the original PDF) ──
    M2_text = "A top secret!"
    M2_hex  = M2_text.encode().hex()
    M2      = int(M2_hex, 16)

    M4_text  = "I owe you $2000."
    M4b_text = "I owe you $3000."
    M4_hex   = M4_text.encode().hex()
    M4b_hex  = M4b_text.encode().hex()
    M4       = int(M4_hex, 16)

    # Task 5: static Alice keys from the SEED lab PDF
    e5  = 0x010001
    n5  = 0xAE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115
    M5_text = "Launch a missile."
    M5_hex  = M5_text.encode().hex()
    M5      = int(M5_hex, 16)
    S5      = 0x643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F
    # Corrupted: last byte 0x2F → 0x3F  (one bit flip, as in the PDF)
    S5c     = (S5 & ~0xFF) | 0x3F

    # ── Unique RSA-128 key pair per sandbox ──────────────────────────────────
    # The flag for Task 3 (flag_t3_decrypt) is encoded as the RSA plaintext,
    # so the student's decrypted ciphertext IS the flag value directly.
    M3_text = flags["3"]                # e.g. "xK3mP9qR"  (12 printable chars)
    M3_hex  = M3_text.encode().hex()
    M3      = int(M3_hex, 16)

    while True:
        p = _gen_prime(128)
        q = _gen_prime(128)
        if p == q: continue
        n   = p * q
        phi = (p - 1) * (q - 1)
        if gcd(E, phi) != 1: continue
        d   = _modinv(E, phi)
        if (E * d) % phi != 1: continue    # sanity check
        # All messages must be < n (true for 128-bit messages and 256-bit n,
        # but verify to be safe)
        if any(m >= n for m in (M2, M3, M4)):
            continue
        break

    # ── Compute answers ──────────────────────────────────────────────────────
    C2 = pow(M2, E, n)   # encrypt "A top secret!"
    C3 = pow(M3, E, n)   # encrypt the unique flag (student must decrypt this)
    S4 = pow(M4, d, n)   # sign   "I owe you $2000."

    # Verify Task 5 (static)
    r5_valid    = "VALID"   if pow(S5,  e5, n5) == M5 else "INVALID"
    r5_corrupt  = "VALID"   if pow(S5c, e5, n5) == M5 else "INVALID"

    # ── Write /opt/rsalab/secrets.json (root-only) ───────────────────────────
    os.makedirs(os.path.dirname(SECRETS_PATH), exist_ok=True)
    secrets = {
        "flags":   flags,
        "params":  {"p": _hex(p), "q": _hex(q), "e": "10001",
                    "n": _hex(n), "d": _hex(d)},
        "answers": {
            "1": _hex(d),
            "2": _hex(C2),
            "3": M3_text,                        # the plaintext IS the flag
            "4": _hex(S4),
            "5": f"{r5_valid}:{r5_corrupt}",
            "6": "TBD",                          # filled in after cert generation
        },
    }
    with open(SECRETS_PATH, "w") as f:
        json.dump(secrets, f, indent=2)
    os.chmod(SECRETS_PATH, 0o600)

    # ── Write ~/rsalab/params.txt (student-readable) ─────────────────────────
    os.makedirs(LAB_DIR, exist_ok=True)
    answers_dir = os.path.join(LAB_DIR, "answers")
    os.makedirs(answers_dir, exist_ok=True)
    for i in range(7):
        p_ = os.path.join(answers_dir, f"task{i}.txt")
        if not os.path.exists(p_):
            with open(p_, "w") as f:
                f.write(f"# Write your answer for Task {i} here\n")

    sep = "=" * 62
    with open(os.path.join(LAB_DIR, "params.txt"), "w") as f:
        f.write(sep + "\n")
        f.write("RSA Lab — YOUR unique parameters (unique per sandbox)\n")
        f.write(sep + "\n\n")
        f.write("Copy the hex values below EXACTLY into your C programs.\n\n")

        f.write("── Task 1 : Derive the Private Key ─────────────────────────\n")
        f.write(f"p = {_hex(p)}\n")
        f.write(f"q = {_hex(q)}\n")
        f.write(f"e = 010001\n\n")

        f.write("── Tasks 2, 3, 4 : Common Keys ─────────────────────────────\n")
        f.write(f"n = {_hex(n)}\n")
        f.write(f"e = 010001\n")
        f.write(f"d = {_hex(d)}\n")
        f.write(f"   (d is given here so you can verify your Task 1 result)\n\n")

        f.write("── Task 2 : Encrypt ─────────────────────────────────────────\n")
        f.write(f'M = "A top secret!"\n')
        f.write(f"M (hex) = {M2_hex}\n\n")

        f.write("── Task 3 : Decrypt ─────────────────────────────────────────\n")
        f.write(f"C = {_hex(C3)}\n")
        f.write(f"   (Decrypt this ciphertext — the plaintext IS your flag)\n\n")

        f.write("── Task 4 : Sign ────────────────────────────────────────────\n")
        f.write(f'M  = "I owe you $2000."  (hex: {M4_hex})\n')
        f.write(f'M2 = "I owe you $3000."  (hex: {M4b_hex})\n\n')

        f.write("── Task 5 : Verify (FIXED — same for every sandbox) ─────────\n")
        f.write(f'M         = "Launch a missile." (hex: {M5_hex})\n')
        f.write(f"S         = {_hex(S5)}\n")
        f.write(f"e         = 010001\n")
        f.write(f"n         = {_hex(n5)}\n")
        f.write(f"S_corrupt = {_hex(S5c)}  (last byte 0x2F→0x3F)\n\n")

        f.write("── Task 6 : X.509 Certificate ───────────────────────────────\n")
        f.write("Certificates are in ~/rsalab/task6/\n")
        f.write("  c0.pem : server certificate (the one to verify)\n")
        f.write("  c1.pem : CA certificate   (issuer, provides the public key)\n\n")
        f.write("Quick-start commands:\n")
        f.write("  # Extract modulus (n) of the CA:\n")
        f.write("  openssl x509 -in ~/rsalab/task6/c1.pem -noout -modulus\n")
        f.write("  # Print all fields (find the exponent e):\n")
        f.write("  openssl x509 -in ~/rsalab/task6/c1.pem -text -noout\n")
        f.write("  # Print server cert fields (find the signature block):\n")
        f.write("  openssl x509 -in ~/rsalab/task6/c0.pem -text -noout\n")
        f.write("  # Extract the cert body (without the signature block):\n")
        f.write("  openssl asn1parse -i -in ~/rsalab/task6/c0.pem -strparse 4 -out /tmp/c0_body.bin -noout\n")
        f.write("  # Compute SHA-256 of the cert body:\n")
        f.write("  sha256sum /tmp/c0_body.bin\n")

    print("RSA parameters generated successfully.")
    print(f"  Secrets  : {SECRETS_PATH}")
    print(f"  Params   : {os.path.join(LAB_DIR, 'params.txt')}")

if __name__ == "__main__":
    main()
