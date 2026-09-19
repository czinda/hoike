# hoike Executive Showcase Demo

**One-command technical demonstration of hoike's core architectural bet:**

> "The machine that signs certificate status and the machine that serves it should not be the same machine."

## What This Demo Proves

This demo shows hoike's three key differentiators in action:

1. **Keyless Edge Serving** — The edge node holds no signing keys. A compromise cannot forge status.
2. **Post-Quantum Ready** — ML-DSA-65/87 signatures as a first-class configuration, not a bolt-on.
3. **Anti-Rollback Protection** — Epoch chains prevent stale-generation replay attacks.

## Prerequisites

- **Docker** and **docker-compose** (for containerized demo), OR
- **Rust toolchain** + **OpenSSL** (for scripted demo)
- **curl** or **hoike query** CLI for testing

## Quick Start (Docker)

```bash
cd demo
docker compose up
```

Watch the logs — you'll see:
1. **Signer** tier produces `.ahu` bundles (ECDSA and ML-DSA)
2. **Edge** nodes (keyless) load and serve them
3. **Client** queries return `good`, `revoked`, and `unauthorized` responses

## Quick Start (Script)

```bash
cd demo
./run.sh
```

The script:
1. Generates a test CA, certificates, and CRL
2. Signs bundles with ECDSA and ML-DSA
3. Starts a keyless edge server
4. Runs client queries showing all response types
5. Demonstrates anti-rollback by rejecting an older-epoch bundle

## Architecture Walkthrough

```
Test CA + CRL           ┌─────────────────┐
  (fixtures/)    ───────▶│  SIGNER TIER    │
                         │  • Reads CRL    │
                         │  • Signs OCSP   │
                         │  • Seals .ahu   │
                         └────────┬────────┘
                                  │ bundles
                    ┌─────────────┼─────────────┐
              ┌─────▼──────┐           ┌────▼──────┐
              │ EDGE (ECDSA)│           │EDGE (ML-DSA)│
              │  keyless    │           │  keyless    │
              └─────┬───────┘           └────┬────────┘
                    └────── clients ─────────┘
```

### Stage 1: Fixture Generation

**What:** OpenSSL generates a test CA, issues certificates, and creates a CRL with one revoked serial.

**Why this matters:** Real production hoike would consume CRLs from Dogtag PKI, Red Hat Certificate System, or another CA. This demo uses OpenSSL to make it self-contained.

**Files created:**
- `fixtures/ca-key.pem` — Test CA private key
- `fixtures/ca-cert.pem` — Test CA certificate
- `fixtures/issuer.der` — DER-encoded issuer certificate (required by hoike)
- `fixtures/crl.pem` — Certificate Revocation List with one revoked cert (serial `0A`)
- `fixtures/good-serials.txt` — Known-good certificate serials (for authoritative-complete bundles)

### Stage 2: Bundle Signing (Classical)

**Command:**
```bash
hoike sign \
  --ca demo-ca \
  --crl fixtures/crl.pem \
  --issuer fixtures/issuer.der \
  --good-serials fixtures/good-serials.txt \
  --sig-alg ecdsa-p256 \
  --demo-key \
  --epoch 1 \
  -o bundles/demo-ecdsa-epoch1.ahu
```

**What happens:**
1. `hoike sign` reads the CRL and good-serials list
2. Generates pre-signed OCSP responses for every entry (good and revoked)
3. Seals them into an `.ahu` bundle with a CMS SignedData signature
4. Writes the bundle to disk

**What to look for:**
- Bundle size (typically ~500 bytes per response for ECDSA P-256)
- Entry count (matching the good + revoked certificate count)
- Epoch number (1 — this is generation 1 for this CA)

**Why the seal matters:** The seal proves this specific producer assembled this specific set at this epoch. A mirror loading it will verify the seal before serving any responses.

### Stage 3: Bundle Signing (Post-Quantum)

**Command:**
```bash
hoike sign \
  --ca demo-ca \
  --crl fixtures/crl.pem \
  --issuer fixtures/issuer.der \
  --good-serials fixtures/good-serials.txt \
  --sig-alg ml-dsa-65 \
  --demo-key \
  --epoch 1 \
  -o bundles/demo-mldsa-epoch1.ahu
```

**What's different:**
- `--sig-alg ml-dsa-65` — Uses NIST's ML-DSA (FIPS 204) instead of ECDSA
- Bundle size is ~3x larger (~3.5 KB per response) due to ML-DSA-65 signatures

**Why this matters:** Post-quantum cryptography is not a future migration — it's a configuration choice today. The same signer, same edge code, same bundle format.

### Stage 4: Keyless Edge Serving (ECDSA)

**Config:** `edge-ecdsa.toml`
```toml
[server]
mode = "edge"              # Edge mode — no signing keys
listen = "127.0.0.1:2560"

[storage]
bundle_dir = "demo/bundles"
state_db = "demo/state-ecdsa"
max_chain = 24

[[ca]]
label = "demo-ca"
bundle_file = "demo/bundles/demo-ecdsa-epoch1.ahu"
nonce_policy = "ignore"    # Pre-signed responses have no nonce
completeness = "partial"   # CRL-sourced bundles cannot assert completeness
```

**Command:**
```bash
hoike serve --config edge-ecdsa.toml
```

**What happens:**
1. Edge loads the bundle and verifies the CMS seal
2. Builds an in-memory index (mmap + binary search)
3. Starts HTTP listener on port 2560
4. Serves pre-signed responses verbatim — no parsing, no re-encoding, no signing

**What to look for:**
- Log line: `bundle loaded: epoch=1, entries=N`
- Log line: `hoike OCSP responder starting` (mode=edge)
- **No signing key mentioned** — the edge holds none

### Stage 5: Client Queries

**Extracting CertID Parameters:**

The query command needs the exact issuer name and key bytes that the signer used. The demo includes a Python helper to extract these:

```bash
eval "$(python3 scripts/extract-certid-params.py fixtures/issuer.der)"
# Sets ISSUER_NAME_B64 and ISSUER_KEY_B64 env vars
```

**Query for a GOOD certificate (serial `01`):**
```bash
hoike query \
  --url http://localhost:2560 \
  --serial 01 \
  --issuer-name-b64 "$ISSUER_NAME_B64" \
  --issuer-key-b64 "$ISSUER_KEY_B64"
```

**Expected response:**
```
── Response ──
  HTTP status: 200 OK
  Body size:   395 bytes
  OCSP status: Successful
  Algorithm:   ecdsa-p256-sha256
  Signature:   70 bytes
  Responses:   2
    [0] Status: GOOD
    [1] Status: GOOD
```

**Query for a REVOKED certificate (serial `0A`):**
```bash
hoike query --url http://localhost:2560 --serial 0A --issuer-name-b64 <BASE64> --issuer-key-b64 <BASE64>
```

**Expected response:**
```
── Response ──
  HTTP status: 200 OK
  Body size:   443 bytes
  OCSP status: Successful
  Algorithm:   ecdsa-p256-sha256
  Signature:   72 bytes
  Responses:   2
    [0] Status: REVOKED
        Reason: KeyCompromise
    [1] Status: REVOKED
        Reason: KeyCompromise
```

**Query for an UNKNOWN certificate (serial `FF`):**
```bash
hoike query --url http://localhost:2560 --serial FF --issuer-name-b64 <BASE64> --issuer-key-b64 <BASE64>
```

**Expected response:**
```
OCSP status: Unauthorized
```

**Why `unauthorized`?** The edge doesn't have this serial in its bundle. For a `partial` bundle (CRL-sourced), the correct answer is "I don't know" (unsigned `unauthorized`), not a signed `revoked` or `good`. This is the property that makes keyless edges safe: they can say "I don't have this" without holding a key.

### Stage 6: Post-Quantum Edge + Dual-Algorithm Bundles

**Config:** `edge-mldsa.toml` (same structure, points to `demo-mldsa-epoch1.ahu`)

**Command:**
```bash
hoike serve --config edge-mldsa.toml &  # Runs on port 2561
```

**Query with algorithm preference:**
```bash
hoike query \
  --url http://localhost:2561 \
  --serial 01 \
  --issuer-name-b64 <BASE64> \
  --issuer-key-b64 <BASE64> \
  --prefer ml-dsa-65,ecdsa-p256
```

**Expected response:**
```
OCSP status: Successful
  Algorithm:   ml-dsa-65
  Signature:   3309 bytes
  Status:      GOOD
```

**What happened:** The client sent a `PreferredSignatureAlgorithms` extension (RFC 6960 §4.4.7.1). The responder returned an ML-DSA-signed response because it was in the client's preference list and available in the bundle.

**Dual-algorithm bundles:** If you create a bundle with `--dual-alg ml-dsa-87`, the bundle contains *both* ECDSA and ML-DSA responses for every certificate. The index uses `ALIAS` records to point both CertID hashes (SHA-1 and SHA-256) at the same payload. One signature, one payload, two index entries — storage-efficient compared to generating two complete bundles.

### Stage 7: Anti-Rollback Protection

**Generate an older-epoch bundle:**
```bash
hoike sign \
  --ca demo-ca \
  --crl fixtures/crl.pem \
  --issuer fixtures/issuer.der \
  --good-serials fixtures/good-serials.txt \
  --sig-alg ecdsa-p256 \
  --demo-key \
  --epoch 0 \   # <--- Older epoch
  -o bundles/demo-ecdsa-epoch0.ahu
```

**Try to load it on the running edge:**
```bash
# Option 1: hoike import (if available)
hoike import --bundle bundles/demo-ecdsa-epoch0.ahu --config edge-ecdsa.toml

# Option 2: Replace the bundle file and reload (future feature)
# cp bundles/demo-ecdsa-epoch0.ahu bundles/demo-ecdsa-epoch1.ahu
# kill -HUP <hoike-pid>
```

**Expected result:**
```
Anti-rollback: REJECTED — epoch 0 <= high-water mark 1
```

**Why this matters:** An attacker with write access to the bundle directory (or the ability to inject a stale bundle via gossip) cannot replay an old generation. The edge persists a high-water mark per `(producer_id, CA)` tuple in `state_db`. Any bundle with epoch ≤ high-water is rejected at load, before it ever reaches the serving path.

**Fork detection:** If two bundles claim the same epoch but have different `prev_manifest_digest` values, the edge detects a fork and refuses both. This prevents a malicious producer (or a split-brain signer) from publishing conflicting generations.

## What the Demo Does NOT Show

This is a technical proof-of-concept, not a production qualification. Missing from this demo:

- **PKCS#11 HSM signing** — The signer uses `--demo-key` (ephemeral software keys). Production should use `signing_key.type = "pkcs11"` with a hardware security module.
- **Real CA integration** — Fixtures are OpenSSL-generated. Production reads from Dogtag PKI, Red Hat Certificate System, or 389 DS syncrepl.
- **TLS** — The demo runs plaintext HTTP. Production should use TLS for the admin/management channel (`server.admin_tls`) and gossip over an authenticated/encrypted channel.
- **Gossip** — Fleet membership and generation propagation are implemented but not shown in this single-node demo. Multi-node demos would show `GenerationAnnouncement` broadcasts and automatic bundle pull-on-announce.
- **Prometheus metrics** — Available via `--features metrics` and `server.metrics_listen`, but not wired in this demo.

## Docker Compose Architecture

The `docker-compose.yml` orchestrates:
- **signer** service: Runs `hoike sign` to produce bundles
- **edge-ecdsa** service: Keyless edge serving the ECDSA bundle
- **edge-mldsa** service: Keyless edge serving the ML-DSA bundle
- **client** service: Runs `hoike query` and prints results

**Key point:** The `edge-*` services do NOT have the signing keys mounted. They only see the sealed `.ahu` bundles. A `docker exec` into an edge container and `find / -name "*.p8"` returns nothing — no keys on disk, no keys in memory.

## Troubleshooting

**Bundle load failure:**
```
Failed to initialize responder: seal verification failed
```
→ The edge's `seal_signer_pins` config does not match the seal certificate embedded in the bundle. For demo use, leave `seal_signer_pins` empty (permissive admission). For production, pin the exact signer certificate.

**Unauthorized on a known-good serial:**
```
OCSP status: Unauthorized
```
→ The serial isn't in the bundle. Check:
1. Is the serial in `good-serials.txt` or the CRL?
2. Does the CertID hash (issuer name + key) match what the client sent?
3. Run `ahu inspect bundles/demo-ecdsa-epoch1.ahu` to see entry count and manifest details.

**Cannot connect to responder:**
```
HTTP request failed: Connection refused
```
→ The edge isn't running or is bound to a different port. Check `hoike serve` logs and `server.listen` in the config.

## Next Steps

- **Multi-CA routing:** Add a second CA to the same edge. The edge routes by `(hashAlg, issuerNameHash, issuerKeyHash)` — one responder, many CAs.
- **Delta bundles:** Produce a second bundle with `--epoch 2` and only changed entries. The edge applies it over the epoch-1 base.
- **Nonce live-signing:** Configure `nonce_policy = "live"` on a combined or signer node to show on-demand nonce-bearing responses (requires signing key access, so incompatible with keyless edges).
- **Gossip mesh:** Run 3+ edges with `gossip.enabled = true`, show SWIM membership and `GenerationAnnouncement` propagation in the fleet view (`/api/admin/gossip`).

## Files in This Demo

```
demo/
├── README.md                 # This file
├── docker-compose.yml        # Containerized demo orchestration
├── run.sh                    # Scripted demo (no Docker)
├── fixtures/
│   ├── ca-key.pem
│   ├── ca-cert.pem
│   ├── issuer.der
│   ├── crl.pem
│   └── good-serials.txt
├── scripts/
│   └── generate-fixtures.sh  # OpenSSL commands to create test CA/CRL
├── configs/
│   ├── edge-ecdsa.toml
│   ├── edge-mldsa.toml
│   └── signer.toml           # (Combined mode demo config)
├── bundles/                  # .ahu bundles written here
└── state-ecdsa/              # Edge anti-rollback high-water marks
    └── state.json
```

## License

Demo fixtures and scripts: Apache-2.0 OR MIT (matching the `ahu` crate).
hoike server code: GPL-3.0-or-later.

## Attribution

Assisted-by: Claude Code (claude.ai/code)
