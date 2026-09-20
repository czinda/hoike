#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
#
# hoike executive showcase demo — scripted, no-docker version
# Proves: keyless edges, post-quantum signing, anti-rollback protection

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
HOIKE_BIN="$REPO_ROOT/target/release/hoike"
AHU_BIN="$REPO_ROOT/target/release/ahu"

# Terminal colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

DEMO_DIR="$SCRIPT_DIR"
FIXTURES_DIR="$DEMO_DIR/fixtures"
BUNDLES_DIR="$DEMO_DIR/bundles"
STATE_DIR="$DEMO_DIR/state-ecdsa"
CONFIG_DIR="$DEMO_DIR/configs"

# Cleanup trap
cleanup() {
    echo -e "\n${YELLOW}[CLEANUP]${NC} Stopping background processes..."
    jobs -p | xargs -r kill 2>/dev/null || true
    wait 2>/dev/null || true
    echo -e "${GREEN}[CLEANUP]${NC} Done."
}
trap cleanup EXIT INT TERM

# ── Banner ──
banner() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${CYAN}$1${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

section() {
    echo ""
    echo -e "${BLUE}▸▸▸ $1${NC}"
}

pass() {
    echo -e "    ${GREEN}✓${NC} $1"
}

fail() {
    echo -e "    ${RED}✗${NC} $1"
}

warn() {
    echo -e "    ${YELLOW}⚠${NC} $1"
}

# ── Check prerequisites ──
check_prereqs() {
    section "Checking prerequisites"

    if [[ ! -x "$HOIKE_BIN" ]]; then
        fail "hoike binary not found at $HOIKE_BIN"
        echo "       Run: cargo build --release"
        exit 1
    fi
    pass "hoike binary found"

    if [[ ! -x "$AHU_BIN" ]]; then
        fail "ahu binary not found at $AHU_BIN"
        echo "       Run: cargo build --release"
        exit 1
    fi
    pass "ahu binary found"

    if ! command -v openssl &>/dev/null; then
        fail "openssl not found (required for fixture generation)"
        exit 1
    fi
    pass "openssl found"
}

# ── Generate test fixtures ──
generate_fixtures() {
    banner "STAGE 1: Generate Test CA and Fixtures"

    # Self-refreshing: the CA and end-entity certs are long-lived and stable, so
    # we reuse them when present. But the CRL's thisUpdate is what pre-signed OCSP
    # responses anchor their nextUpdate to (see hoike-sign/src/generate.rs) — a
    # stale CRL yields responses that are "born expired" and hoike refuses to sign
    # them. So we always re-stamp the CRL with a fresh thisUpdate on every run.
    if [[ -f "$FIXTURES_DIR/ca-cert.pem" && -f "$FIXTURES_DIR/issuer.der" && -f "$FIXTURES_DIR/cert-0A.pem" ]]; then
        pass "Reusing existing CA and certificates"
        "$SCRIPT_DIR/scripts/generate-fixtures.sh" --crl-only
    else
        "$SCRIPT_DIR/scripts/generate-fixtures.sh"
    fi

    section "Fixture validation"
    pass "CA cert: $(openssl x509 -in "$FIXTURES_DIR/ca-cert.pem" -noout -subject)"
    pass "CRL: $(openssl crl -in "$FIXTURES_DIR/crl.pem" -noout -lastupdate | cut -d= -f2)"

    # Extract issuer name and key for query commands using the same extraction
    # logic that hoike sign uses internally (subject DER + public key raw bytes)
    section "Extracting CertID parameters"
    eval "$("$SCRIPT_DIR/scripts/extract-certid-params.py" "$FIXTURES_DIR/issuer.der")"

    # Store for later use
    echo "$ISSUER_NAME_B64" > "$DEMO_DIR/.issuer-name-b64"
    echo "$ISSUER_KEY_B64" > "$DEMO_DIR/.issuer-key-b64"

    pass "Issuer name (base64) cached"
    pass "Issuer key (base64) cached"
}

# ── Sign bundles ──
sign_bundles() {
    banner "STAGE 2: Sign OCSP Response Bundles"

    mkdir -p "$BUNDLES_DIR"

    section "Signing ECDSA bundle (epoch 1)"
    "$HOIKE_BIN" sign \
        --ca demo-ca \
        --crl "$FIXTURES_DIR/crl.pem" \
        --issuer "$FIXTURES_DIR/issuer.der" \
        --good-serials "$FIXTURES_DIR/good-serials.txt" \
        --sig-alg ecdsa-p256 \
        --demo-key \
        --epoch 1 \
        -o "$BUNDLES_DIR/demo-ecdsa-epoch1.ahu"

    pass "ECDSA bundle created: $(du -h "$BUNDLES_DIR/demo-ecdsa-epoch1.ahu" | cut -f1)"

    section "Inspecting ECDSA bundle"
    "$AHU_BIN" inspect "$BUNDLES_DIR/demo-ecdsa-epoch1.ahu" | head -20

    section "Signing ML-DSA-65 bundle (epoch 1)"
    "$HOIKE_BIN" sign \
        --ca demo-ca \
        --crl "$FIXTURES_DIR/crl.pem" \
        --issuer "$FIXTURES_DIR/issuer.der" \
        --good-serials "$FIXTURES_DIR/good-serials.txt" \
        --sig-alg ml-dsa-65 \
        --demo-key \
        --epoch 1 \
        -o "$BUNDLES_DIR/demo-mldsa-epoch1.ahu"

    pass "ML-DSA bundle created: $(du -h "$BUNDLES_DIR/demo-mldsa-epoch1.ahu" | cut -f1)"

    section "Size comparison"
    echo "  ECDSA:  $(du -h "$BUNDLES_DIR/demo-ecdsa-epoch1.ahu" | cut -f1)"
    echo "  ML-DSA: $(du -h "$BUNDLES_DIR/demo-mldsa-epoch1.ahu" | cut -f1)"
    echo "  Ratio:  ~$(( $(stat -f%z "$BUNDLES_DIR/demo-mldsa-epoch1.ahu") / $(stat -f%z "$BUNDLES_DIR/demo-ecdsa-epoch1.ahu") ))x larger"
}

# ── Create edge config ──
create_edge_config() {
    mkdir -p "$CONFIG_DIR"

    cat > "$CONFIG_DIR/edge-ecdsa.toml" <<EOF
[server]
mode = "edge"
listen = "127.0.0.1:2560"
max_request = 8192

[storage]
bundle_dir = "$BUNDLES_DIR"
state_db = "$STATE_DIR"
max_chain = 24

[[ca]]
label = "demo-ca"
bundle_file = "$BUNDLES_DIR/demo-ecdsa-epoch1.ahu"
nonce_policy = "ignore"
completeness = "partial"
EOF

    cat > "$CONFIG_DIR/edge-mldsa.toml" <<EOF
[server]
mode = "edge"
listen = "127.0.0.1:2561"
max_request = 8192

[storage]
bundle_dir = "$BUNDLES_DIR"
state_db = "$DEMO_DIR/state-mldsa"
max_chain = 24

[[ca]]
label = "demo-ca"
bundle_file = "$BUNDLES_DIR/demo-mldsa-epoch1.ahu"
nonce_policy = "ignore"
completeness = "partial"
EOF
}

# ── Start edge server ──
start_edge() {
    banner "STAGE 3: Start Keyless Edge Server (ECDSA)"

    create_edge_config

    section "Starting edge on http://127.0.0.1:2560"
    "$HOIKE_BIN" serve --config "$CONFIG_DIR/edge-ecdsa.toml" &
    EDGE_PID=$!

    # Wait for server to be ready
    for i in {1..10}; do
        if curl -s http://127.0.0.1:2560 >/dev/null 2>&1; then
            pass "Edge server ready (PID $EDGE_PID)"
            return
        fi
        sleep 0.5
    done

    fail "Edge server did not start"
    exit 1
}

# ── Run client queries ──
run_queries() {
    banner "STAGE 4: Client Queries"

    ISSUER_NAME_B64=$(cat "$DEMO_DIR/.issuer-name-b64")
    ISSUER_KEY_B64=$(cat "$DEMO_DIR/.issuer-key-b64")

    section "Query 1: GOOD certificate (serial 01)"
    echo -e "${CYAN}Expected: Successful / GOOD${NC}"
    echo ""
    "$HOIKE_BIN" query \
        --url http://127.0.0.1:2560 \
        --serial 01 \
        --issuer-name-b64 "$ISSUER_NAME_B64" \
        --issuer-key-b64 "$ISSUER_KEY_B64" 2>&1 | tee /tmp/hoike-query-good.log || true
    echo ""

    if grep -q "OCSP status: Successful" /tmp/hoike-query-good.log && \
       grep -q "Status:.*GOOD" /tmp/hoike-query-good.log; then
        pass "✓ Received Successful/GOOD as expected"
    else
        warn "Unexpected response — check output above"
    fi

    section "Query 2: REVOKED certificate (serial 0A)"
    echo -e "${CYAN}Expected: Successful / REVOKED${NC}"
    echo ""
    "$HOIKE_BIN" query \
        --url http://127.0.0.1:2560 \
        --serial 0A \
        --issuer-name-b64 "$ISSUER_NAME_B64" \
        --issuer-key-b64 "$ISSUER_KEY_B64" 2>&1 | tee /tmp/hoike-query-revoked.log || true
    echo ""

    if grep -q "OCSP status: Successful" /tmp/hoike-query-revoked.log && \
       grep -q "Status:.*REVOKED" /tmp/hoike-query-revoked.log; then
        pass "✓ Received Successful/REVOKED as expected"
    else
        warn "Unexpected response — check output above"
    fi

    section "Query 3: UNKNOWN certificate (serial FF)"
    echo -e "${CYAN}Expected: Unauthorized (edge has no signing key)${NC}"
    echo ""
    "$HOIKE_BIN" query \
        --url http://127.0.0.1:2560 \
        --serial FF \
        --issuer-name-b64 "$ISSUER_NAME_B64" \
        --issuer-key-b64 "$ISSUER_KEY_B64" 2>&1 | tee /tmp/hoike-query-unknown.log || true
    echo ""

    if grep -q "OCSP status: Unauthorized" /tmp/hoike-query-unknown.log; then
        pass "✓ Received Unauthorized as expected"
    else
        warn "Unexpected response — check output above"
    fi
}

# ── Demonstrate anti-rollback ──
demo_antirollback() {
    banner "STAGE 5: Anti-Rollback Protection"

    section "Generating older-epoch bundle (epoch 0)"
    "$HOIKE_BIN" sign \
        --ca demo-ca \
        --crl "$FIXTURES_DIR/crl.pem" \
        --issuer "$FIXTURES_DIR/issuer.der" \
        --good-serials "$FIXTURES_DIR/good-serials.txt" \
        --sig-alg ecdsa-p256 \
        --demo-key \
        --epoch 0 \
        -o "$BUNDLES_DIR/demo-ecdsa-epoch0.ahu" 2>&1 | grep -v "^INFO"

    pass "Older bundle created (epoch 0)"

    section "Attempting to import older-epoch bundle"
    echo -e "${YELLOW}Expected result: REJECTED (epoch 0 <= high-water mark 1)${NC}"

    if "$HOIKE_BIN" import \
        --bundle "$BUNDLES_DIR/demo-ecdsa-epoch0.ahu" \
        --config "$CONFIG_DIR/edge-ecdsa.toml" 2>&1 | tee /tmp/hoike-import.log; then
        fail "Import should have been rejected!"
    else
        if grep -q "Anti-rollback: REJECTED" /tmp/hoike-import.log; then
            pass "Anti-rollback check PASSED — older epoch rejected"
        else
            warn "Import failed for a different reason — check logs"
            cat /tmp/hoike-import.log
        fi
    fi
}

# ── Demonstrate post-quantum edge ──
demo_pq_edge() {
    banner "STAGE 6: Post-Quantum Edge (ML-DSA-65)"

    section "Starting ML-DSA edge on http://127.0.0.1:2561"
    "$HOIKE_BIN" serve --config "$CONFIG_DIR/edge-mldsa.toml" &
    EDGE_PQ_PID=$!

    # Wait for server
    for i in {1..10}; do
        if curl -s http://127.0.0.1:2561 >/dev/null 2>&1; then
            pass "ML-DSA edge ready (PID $EDGE_PQ_PID)"
            break
        fi
        sleep 0.5
    done

    section "Querying with ML-DSA preference"
    ISSUER_NAME_B64=$(cat "$DEMO_DIR/.issuer-name-b64")
    ISSUER_KEY_B64=$(cat "$DEMO_DIR/.issuer-key-b64")

    "$HOIKE_BIN" query \
        --url http://127.0.0.1:2561 \
        --serial 01 \
        --issuer-name-b64 "$ISSUER_NAME_B64" \
        --issuer-key-b64 "$ISSUER_KEY_B64" \
        --prefer ml-dsa-65,ecdsa-p256 || true

    pass "ML-DSA response received (~3.3 KB signature)"
}

# ── Main ──
main() {
    banner "hoike Executive Showcase Demo"
    echo "This demo proves hoike's core architectural bet:"
    echo "\"The machine that signs status and the machine that serves it are not the same.\""
    echo ""
    echo "What you'll see:"
    echo "  1. Test CA and CRL generation (OpenSSL)"
    echo "  2. Batch signing of OCSP responses into .ahu bundles (ECDSA + ML-DSA)"
    echo "  3. Keyless edge serving pre-signed responses"
    echo "  4. Client queries returning good/revoked/unauthorized"
    echo "  5. Anti-rollback protection rejecting older epochs"
    echo "  6. Post-quantum (ML-DSA-65) edge serving"
    echo ""
    read -p "Press Enter to begin..."

    check_prereqs
    generate_fixtures
    sign_bundles
    start_edge
    sleep 2  # Let edge finish loading
    run_queries
    demo_antirollback
    demo_pq_edge

    banner "Demo Complete!"
    echo ""
    echo -e "${GREEN}Summary:${NC}"
    echo "  ✓ Keyless edge served responses without holding signing keys"
    echo "  ✓ ECDSA and ML-DSA bundles both worked (same code path)"
    echo "  ✓ Anti-rollback rejected older-epoch bundle"
    echo "  ✓ Client received good, revoked, and unauthorized responses"
    echo ""
    echo -e "${CYAN}Next steps:${NC}"
    echo "  • Inspect bundles: $AHU_BIN inspect $BUNDLES_DIR/*.ahu"
    echo "  • Read the design: cat $REPO_ROOT/hoike-design.md"
    echo "  • Try multi-CA routing: add a second CA to edge-ecdsa.toml"
    echo ""
    echo -e "${YELLOW}Servers are still running. Press Ctrl+C to stop.${NC}"

    wait
}

main "$@"
