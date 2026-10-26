#!/usr/bin/env python3
"""
Extract CertID parameters (issuer name and key) from an X.509 certificate
in exactly the same format that hoike sign uses internally.

Matches the extraction logic from hoike-cli/src/main.rs lines 1238-1256:
- issuer_name_b64: base64(issuer_cert.tbs_certificate.subject.to_der())
- issuer_key_b64: base64(issuer_cert.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes())
"""

import sys
from pathlib import Path
from base64 import b64encode
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def extract_certid_params(cert_path):
    """Extract issuer name and key bytes for CertID computation."""
    cert_bytes = Path(cert_path).read_bytes()

    # Load certificate (DER or PEM)
    try:
        cert = x509.load_der_x509_certificate(cert_bytes, default_backend())
    except Exception:
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

    # Extract issuer name (Subject) as DER bytes
    # The subject is encoded as a Name type in DER
    issuer_name_der = cert.subject.public_bytes(default_backend())

    # Extract issuer public key raw bytes (the BIT STRING value, no DER wrapper)
    # This is the actual public key bytes without the SPKI structure
    issuer_key_bytes = cert.public_key().public_bytes(
        encoding=serialization.Encoding.X962,  # For EC keys, X9.62 uncompressed point
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Base64-encode both
    issuer_name_b64 = b64encode(issuer_name_der).decode('ascii')
    issuer_key_b64 = b64encode(issuer_key_bytes).decode('ascii')

    return issuer_name_b64, issuer_key_b64


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} CERT_FILE", file=sys.stderr)
        sys.exit(1)

    cert_path = sys.argv[1]
    name_b64, key_b64 = extract_certid_params(cert_path)

    # Output in a format the shell script can eval
    print(f"ISSUER_NAME_B64='{name_b64}'")
    print(f"ISSUER_KEY_B64='{key_b64}'")
