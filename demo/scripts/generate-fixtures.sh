#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Generate test CA, certificates, and CRL for hoike demo.
# Uses OpenSSL to create a self-contained fixture set.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"
FIXTURES_DIR="$DEMO_DIR/fixtures"

mkdir -p "$FIXTURES_DIR"
cd "$FIXTURES_DIR"

# --crl-only: regenerate just the CRL from the existing CA/certs, leaving the CA
# and end-entity keys untouched. run.sh calls this on every run so the CRL's
# thisUpdate is always current — otherwise pre-signed OCSP responses inherit a
# stale source window and hoike refuses to emit them ("generated response would
# already be expired"). Keeping the CA stable also preserves the cached CertID
# params (.issuer-*-b64) derived from the issuer key.
CRL_ONLY=0
if [[ "${1:-}" == "--crl-only" ]]; then
    CRL_ONLY=1
fi

echo "──────────────────────────────────────────────────"
if [[ "$CRL_ONLY" == "1" ]]; then
    echo "Refreshing CRL only (reusing existing CA and certs)"
else
    echo "Generating test CA and fixtures for hoike demo"
fi
echo "──────────────────────────────────────────────────"

if [[ "$CRL_ONLY" == "1" ]]; then
    if [[ ! -f ca-cert.pem || ! -f issuer.der || ! -f cert-0A.pem ]]; then
        echo "ERROR: --crl-only requires an existing CA (ca-cert.pem, issuer.der, cert-0A.pem)." >&2
        echo "       Run without --crl-only first to generate the full fixture set." >&2
        exit 1
    fi
    echo "[crl-only] Reusing existing CA and certificates."
else

# ── Step 1: Generate CA private key and self-signed certificate ──
if [[ ! -f ca-key.pem ]]; then
    echo "[1/6] Generating CA private key (ECDSA P-256)..."
    openssl ecparam -genkey -name prime256v1 -noout -out ca-key.pem
    echo "       → ca-key.pem"
fi

if [[ ! -f ca-cert.pem ]]; then
    echo "[2/6] Generating CA self-signed certificate..."
    openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 3650 \
        -subj "/CN=hoike Demo CA/O=hoike Demo/C=US" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    echo "       → ca-cert.pem"
fi

# ── Step 2: Convert CA cert to DER (required by hoike --issuer) ──
if [[ ! -f issuer.der ]]; then
    echo "[3/6] Converting CA cert to DER format..."
    openssl x509 -in ca-cert.pem -outform DER -out issuer.der
    echo "       → issuer.der"
fi

# ── Step 3: Generate end-entity certificate keys and requests ──
echo "[4/6] Generating end-entity certificates..."

# Good certificates (serials 01-05)
for serial in 01 02 03 04 05; do
    if [[ ! -f "cert-${serial}-key.pem" ]]; then
        openssl ecparam -genkey -name prime256v1 -noout -out "cert-${serial}-key.pem"
        openssl req -new -key "cert-${serial}-key.pem" -out "cert-${serial}.csr" \
            -subj "/CN=demo-cert-${serial}/O=hoike Demo/C=US"
        openssl x509 -req -in "cert-${serial}.csr" -CA ca-cert.pem -CAkey ca-key.pem \
            -set_serial "0x${serial}" -out "cert-${serial}.pem" -days 365 \
            -extfile <(echo "extendedKeyUsage=serverAuth")
        rm "cert-${serial}.csr"
    fi
done

# Revoked certificate (serial 0A)
if [[ ! -f cert-0A-key.pem ]]; then
    openssl ecparam -genkey -name prime256v1 -noout -out cert-0A-key.pem
    openssl req -new -key cert-0A-key.pem -out cert-0A.csr \
        -subj "/CN=demo-cert-REVOKED/O=hoike Demo/C=US"
    openssl x509 -req -in cert-0A.csr -CA ca-cert.pem -CAkey ca-key.pem \
        -set_serial 0x0A -out cert-0A.pem -days 365 \
        -extfile <(echo "extendedKeyUsage=serverAuth")
    rm cert-0A.csr
fi

echo "       → cert-01.pem through cert-05.pem (good)"
echo "       → cert-0A.pem (will be revoked)"

fi  # end CA/cert generation (skipped in --crl-only mode)

# ── Step 4: Create CRL with revoked certificate ── (always runs — fresh thisUpdate)
echo "[5/6] Generating CRL with revoked certificate (serial 0A)..."

# OpenSSL needs a database and serial file for CRL generation
touch crl-index.txt
echo "01" > crl-serial.txt

# Create a minimal openssl.cnf for CRL generation
cat > openssl-crl.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
database = ${FIXTURES_DIR}/crl-index.txt
crlnumber = ${FIXTURES_DIR}/crl-serial.txt
default_md = sha256
default_crl_days = 365
certificate = ${FIXTURES_DIR}/ca-cert.pem
private_key = ${FIXTURES_DIR}/ca-key.pem

[ crl_ext ]
authorityKeyIdentifier=keyid:always
EOF

# Revoke certificate 0A
openssl ca -config openssl-crl.cnf -revoke cert-0A.pem \
    -crl_reason keyCompromise 2>/dev/null || true

# Generate the CRL
openssl ca -config openssl-crl.cnf -gencrl -out crl.pem \
    -crlexts crl_ext

rm openssl-crl.cnf
echo "       → crl.pem (contains revoked serial 0A)"

# ── Step 5: Create good-serials.txt for authoritative-complete bundles ──
echo "[6/6] Creating good-serials.txt..."
cat > good-serials.txt <<EOF
# Known-good certificate serials (hex, one per line)
# Used by hoike sign --good-serials to produce authoritative-complete bundles
01
02
03
04
05
EOF
echo "       → good-serials.txt"

echo "──────────────────────────────────────────────────"
echo "Fixture generation complete!"
echo "Files created in: $FIXTURES_DIR"
echo ""
echo "Summary:"
echo "  CA cert:       ca-cert.pem (PEM), issuer.der (DER)"
echo "  CRL:           crl.pem (1 revoked: serial 0A)"
echo "  Good certs:    01, 02, 03, 04, 05"
echo "  Revoked certs: 0A (keyCompromise)"
echo "──────────────────────────────────────────────────"
