#!/usr/bin/env python3
"""
Computes the SHA-256 hash of an X.509 certificate body (without the
signature block, using openssl asn1parse -strparse 4) and stores it
in the RSA lab secrets.json under answers["6"].

Usage:  python3 store_cert_hash.py <c0.pem> <secrets.json>
"""
import hashlib, json, subprocess, sys, tempfile, os

def main():
    if len(sys.argv) != 3:
        print("Usage: store_cert_hash.py <c0.pem> <secrets.json>", file=sys.stderr)
        sys.exit(1)
    cert_path    = sys.argv[1]
    secrets_path = sys.argv[2]

    # Extract cert body (DER bytes, without the signature block)
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        subprocess.run(
            ["openssl", "asn1parse", "-i", "-in", cert_path,
             "-strparse", "4", "-out", tmp_path, "-noout"],
            check=True, capture_output=True)

        with open(tmp_path, "rb") as f:
            body = f.read()
        cert_hash = hashlib.sha256(body).hexdigest().upper()

        with open(secrets_path) as f:
            secrets = json.load(f)
        secrets["answers"]["6"] = cert_hash
        with open(secrets_path, "w") as f:
            json.dump(secrets, f, indent=2)
        os.chmod(secrets_path, 0o600)
        print(f"cert body SHA-256 stored: {cert_hash}")
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

if __name__ == "__main__":
    main()
