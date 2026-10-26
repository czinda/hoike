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

## Quick Start (Docker / Podman)

**Docker Compose v2:**

```bash
cd demo
docker compose up --build
```

**Podman — use detached mode** (`up -d`), then read the client log:

```bash
cd demo
podman compose up -d --build
podman compose logs client        # the four query results
```

Watch the logs — you'll see:
1. **fixture-gen** generates the CA, certs, and a fresh CRL (runs once, exits)
2. **Signer** tier produces `.ahu` bundles (ECDSA and ML-DSA), then exits
3. **state-init** explicitly initializes the state volumes (first run only)
4. **Edge** nodes (keyless) load and serve them
5. **Client** queries return `good`, `revoked`, and `unauthorized` responses

The one-shot services (`fixture-gen`, `signer`, `client`) use
`depends_on: { condition: service_completed_successfully }` so the chain advances
in order; the edges are gated on `service_healthy`.

> **Why `-d` under Podman?** The Python `podman-compose` provider (1.6.0)
> serializes on log attachment in *foreground* `up` and stalls on this stack's
> diamond dependency (the client waits on **both** edges), starting only one edge.
> Detached `up -d` hands health-condition resolution to Podman itself and starts
> every branch reliably. Docker Compose v2 (Go) handles both modes. If you ever
> see one edge stuck in `Created`, `podman compose up -d` (or
> `podman start demo_edge-mldsa_1`) unblocks it.

### Resetting the containerized demo

Container state (the anti-rollback high-water marks and the signed bundles) lives
in **named volumes**, never bind-mounted from the host. This is deliberate: hoike's
anti-rollback store records *absolute* bundle paths for committed generations, so
sharing a state directory between a host `./run.sh` run and the containers would
poison it (host paths don't resolve inside the container) and edges would fail to
start. To wipe all container state and start completely fresh:

```bash
podman compose down -v          # -v also removes the named volumes
```

Omit `-v` to stop the stack but keep the epoch high-water marks. Note that a
later `up` re-runs the signer, which produces a **new epoch-1 generation**
(fresh CRL window, ephemeral keys) — the preserved marks correctly reject that
new generation at the same epoch, and the edges exit with an anti-rollback
error. Keeping state across `up`s only works if the bundles are unchanged; to
rerun the containerized demo end-to-end, use `podman compose down -v`.

## Quick Start (Script)

```bash
cd demo
./run.sh
```

The script:
1. Generates a test CA, certificates, CRL, and a fresh demo seal pair
2. Signs bundles with ECDSA and ML-DSA (sealed by the persistent demo seal pair)
3. Authenticates the seals against the pinned demo certificate
   (`configs/trusted-edge.toml`), and shows tampered/unpinned input failing
4. Starts a keyless edge server (authenticated bundle admission)
5. Runs client queries showing all response types
6. Demonstrates anti-rollback by rejecting an older-epoch bundle via offline
   `hoike import`, then restarting the edge over the preserved state

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

**Self-refreshing:** The CA and end-entity certificates are long-lived and are
reused across runs (so the CertID stays stable), but the **CRL is regenerated
with a fresh `thisUpdate` on every run**. This is deliberate: a pre-signed OCSP
response anchors its `nextUpdate` to the CRL's `thisUpdate` (source freshness),
not to wall-clock now, so a stale committed CRL would produce responses that are
"born expired" and `hoike sign` would refuse to emit them. Because of this, the
CRL and its OpenSSL bookkeeping files are **not** committed (see `demo/.gitignore`)
— only the stable identity fixtures are. The demo **seal pair** is regenerated
for the same reason: a committed seal certificate would carry a fixed expiry
window that eventually fails admission closed. To force a full regeneration from
scratch: `rm -rf demo/fixtures/ca-* demo/fixtures/cert-* demo/fixtures/issuer.der`.

**Files created:**
- `fixtures/ca-key.pem` — Test CA private key
- `fixtures/ca-cert.pem` — Test CA certificate
- `fixtures/issuer.der` — DER-encoded issuer certificate (required by hoike)
- `fixtures/crl.pem` — Certificate Revocation List with one revoked cert (serial `0A`)
- `fixtures/seal-key.p8` + `fixtures/seal-cert.pem` — Demo seal pair (P-256,
  regenerated with a fresh validity window every run, never committed) used to
  seal the demo bundles and pinned by `configs/trusted-edge.toml`
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
  --seal-key fixtures/seal-key.p8 \
  --seal-cert fixtures/seal-cert.pem \
  --epoch 1 \
  -o bundles/demo-ecdsa-epoch1.ahu
```

**What happens:**
1. `hoike sign` reads the CRL and good-serials list
2. Generates pre-signed OCSP responses for every entry (good and revoked) with
   the ephemeral `--demo-key`
3. Seals them into an `.ahu` bundle with a CMS `SignedData` signature from the
   persistent demo seal pair — a key distinct from the OCSP signing key, as
   production configuration requires
4. Writes the bundle to disk

**What to look for:**
- Bundle size (typically ~500 bytes per response for ECDSA P-256)
- Entry count (matching the good + revoked certificate count)
- Epoch number (1 — this is generation 1 for this CA)

**Why the seal matters:** the seal authenticates the producer and binds the
bundle contents to its epoch. The demo pins the seal certificate in
`configs/trusted-edge.toml` and the edge configs, so `ahu verify --config` and
edge admission perform real authenticated verification. The OCSP signing key
remains ephemeral (`--demo-key`) — that is the demo shortcut, not the seal.

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
  --seal-key fixtures/seal-key.p8 \
  --seal-cert fixtures/seal-cert.pem \
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
seal_signer_pins = ["demo/fixtures/seal-cert.pem"]  # authenticated admission

[[ca]]
label = "demo-ca"
bundle_file = "demo/bundles/demo-ecdsa-epoch1.ahu"
nonce_policy = "ignore"    # Pre-signed responses have no nonce
completeness = "partial"   # CRL-sourced bundles cannot assert completeness
```

**Command:**
```bash
hoike init-state --config edge-ecdsa.toml   # once, when the state dir is new
hoike serve --config edge-ecdsa.toml
```

**What happens:**
1. `hoike init-state` explicitly acknowledges the new state directory — it refuses an existing state file or a directory holding recovery material, and there is no `--force` reset
2. Edge authenticates the CMS seal against the pinned seal certificate, then checks structure and digests
3. Builds an in-memory index over the loaded bundle (binary search; the `ahu`
   crate's zero-copy `MmapBundle` reader is library support, not the deployed
   serving path)
4. Starts HTTP listener on port 2560
5. Serves pre-signed responses verbatim — no parsing, no re-encoding, no signing
6. Holds an exclusive OS writer lock (`.writer.lock` in the state directory) for the whole process lifetime — a second `hoike serve` on the same state directory is rejected

A restart reuses the existing state directory as-is: it never initializes, resets, or deletes it. `hoike serve` on a missing state directory fails with a pointer to `hoike init-state` instead of silently starting a fresh anti-rollback timeline.

**What to look for:**
- Log line: `CMS seal authenticated against configured trust policy`
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
  --seal-key fixtures/seal-key.p8 \
  --seal-cert fixtures/seal-cert.pem \
  --epoch 0 \
  -o bundles/demo-ecdsa-epoch0.ahu
```

**Try to install it with the offline importer:**
```bash
# Import is offline by design — stop the edge first (it holds the writer lock):
kill <hoike-serve-pid>
hoike import --bundle bundles/demo-ecdsa-epoch0.ahu --ca demo-ca --config edge-ecdsa.toml
```

**Expected result:**
```
Import failed: epoch rollback: scope hoike-cli:<issuer-key-hash prefix> epoch 0 <= high-water 1
```

**Why this matters:** An attacker with write access to the bundle directory (or the ability to inject a stale bundle via gossip) cannot replay an old generation. The edge persists a high-water mark per `(producer_id, CA)` tuple in `state_db`. Any bundle with epoch ≤ high-water is rejected at load, before it ever reaches the serving path. The import authenticates the CMS seal under the configured pins (the demo flag never relaxes import) and refuses to run while the edge holds the writer lock — run it offline.

**Restart continuity:** after the rejected import, `run.sh` restarts the edge on
the unchanged state directory. The identical committed generation reloads
idempotently over the preserved marks — the restart serves the same responses,
and a *different* bundle at the same epoch would be rejected as a fork.

**Fork detection:** If two bundles claim the same epoch but have different `prev_manifest_digest` values, the edge detects a fork and refuses both. This prevents a malicious producer (or a split-brain signer) from publishing conflicting generations.

## What the Demo Does NOT Show

This is a technical proof-of-concept, not a production qualification. Missing from this demo:

- **PKCS#11 HSM signing** — The signer uses `--demo-key` (ephemeral software keys) for OCSP signatures. Production should use `signing_key.type = "pkcs11"` with a hardware security module. The demo *seal* pair is a real persistent P-256 software pair, matching the current configured-seal backend.
- **Real CA integration** — Fixtures are OpenSSL-generated. Production reads from Dogtag PKI, Red Hat Certificate System, or 389 DS syncrepl.
- **TLS** — The demo runs plaintext HTTP. Production should use TLS for the admin/management channel (`server.admin_tls`); gossip broadcasts are authenticated (Ed25519) but the channel is not encrypted.
- **Gossip** — Fleet membership and generation propagation are implemented but not shown in this single-node demo. A multi-node demo would show `GenerationAnnouncement` propagation in the fleet view; bundles are *not* automatically pulled on announce (that remains future work).
- **Prometheus metrics** — Available via `--features metrics` and `server.metrics_listen`, but not wired in this demo.
- **Containerized admission posture** — The `docker compose` path signs with `--demo-key` only (ephemeral seal) and serves with `allow_unauthenticated_bundles = true`; the native `./run.sh` path is the one that demonstrates authenticated admission with the pinned seal pair.

## Docker Compose Architecture

The `docker-compose.yml` orchestrates:
- **fixture-gen** service: Runs `generate-fixtures.sh` to produce the CA, certs, and a fresh CRL (one-shot)
- **signer** service: Runs `hoike sign` to produce bundles (one-shot)
- **state-init** service: Runs `hoike init-state` for state directories that do not exist yet (one-shot; a restart with existing state skips initialization and preserves all marks)
- **edge-ecdsa** service: Keyless edge serving the ECDSA bundle
- **edge-mldsa** service: Keyless edge serving the ML-DSA bundle
- **client** service: Runs `hoike query` and prints results (one-shot)

**Key point:** The `edge-*` services do NOT have the signing keys mounted. They only see the sealed `.ahu` bundles. A `podman exec` into an edge container and `find / -name "*.p8"` returns nothing — no keys on disk, no keys in memory.

**Volumes:** `fixtures/`, `scripts/`, and `configs/` are bind-mounted from the host
(they are inputs). The signed **`bundles`** and the two **`state-*`** stores are
**named volumes** shared only among the containers — see [Resetting the
containerized demo](#resetting-the-containerized-demo) for why, and how to wipe them.

**Client CertID extraction:** `hoike query` needs the byte-exact issuer name and
key that the signer hashed into each CertID. The runtime image has `openssl` but
not Python, so the client derives them with `openssl` alone: the subject Name is
the second-to-last bare `d=2` SEQUENCE in the certificate (offset-free — extensions
sit under a tagged `[3]` wrapper), and the key is the trailing 65-byte X9.62
uncompressed point of the P-256 SPKI. The native `./run.sh` path instead uses
`scripts/extract-certid-params.py` (Python `cryptography`), which is the reference
implementation both methods are validated against.

## Troubleshooting

**Bundle load failure:**
```
Failed to initialize responder: seal verification failed
```
→ Check that the seal is valid and that `seal_signer_pins` or `seal_trust_anchors`
authorizes its signer. Normal admission rejects missing trust. The supplied demo
configs use `allow_unauthenticated_bundles = true` with no pins, anchors, or
authorizations. That flag never bypasses a configured trust policy or a
verification error. For production, provision the correct trust material.

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

**Containerized build/up fails with `exit status 101`, or an edge exits with
`Failed to initialize responder` / `No such file or directory`:**
→ Poisoned anti-rollback state. This happens if a `state_db` was bind-mounted
from the host and a native `./run.sh` wrote committed-generation pointers with
*absolute host paths* that don't exist inside the container. The current
`docker-compose.yml` avoids this by using **named volumes** for state, but if you
have an older checkout or hand-edited the compose file, reset with:
```bash
podman compose down -v          # drop containers AND the state named volumes
podman compose up -d --build
```

**One edge stuck in `Created` under Podman:**
→ `podman-compose` foreground `up` can stall on the diamond dependency. Use
`podman compose up -d` (detached), or nudge it with `podman start demo_edge-mldsa_1`.

## Next Steps

- **Multi-CA routing:** Add a second CA to the same edge. The edge routes by `(hashAlg, issuerNameHash, issuerKeyHash)` — one responder, many CAs.
- **Delta bundles:** The *serving path rejects delta profiles* — admission accepts only full, uncompressed bundles. To use deltas, materialize them offline with `ahu apply` (authenticating inputs and resealing with an authorized key) and install the resulting full bundle.
- **Nonce live-signing:** Configure `nonce_policy = "live"` on a combined or signer node to show on-demand nonce-bearing responses (requires signing key access, so incompatible with keyless edges).
- **Gossip mesh:** Run 3+ edges with `gossip.enabled = true`, show SWIM membership and `GenerationAnnouncement` propagation in the fleet view (`/api/admin/gossip`).

## Files in This Demo

```
demo/
├── README.md                 # This file
├── docker-compose.yml        # Containerized demo orchestration
├── run.sh                    # Scripted demo (no Docker); --fresh resets runtime state
├── .gitignore                # Excludes regenerated CRL/seal pair + all runtime outputs
├── fixtures/
│   ├── ca-key.pem            # committed (stable identity)
│   ├── ca-cert.pem           # committed
│   ├── issuer.der            # committed
│   ├── cert-0[1-5].pem, cert-0A.pem  # committed
│   ├── good-serials.txt      # committed
│   ├── crl.pem               # REGENERATED each run (not committed)
│   ├── seal-key.p8           # REGENERATED each run (not committed) — demo seal pair
│   └── seal-cert.pem         # REGENERATED each run (not committed) — pinned by trusted-edge.toml
├── scripts/
│   └── generate-fixtures.sh  # OpenSSL commands; `--crl-only` re-stamps the CRL and seal pair
├── configs/
│   ├── edge-ecdsa.toml       # generated by run.sh (not committed)
│   ├── edge-mldsa.toml       # generated by run.sh (not committed)
│   ├── trusted-edge.toml     # generated by run.sh (not committed) — seal pin for `ahu verify --config`
│   └── *-docker.toml         # committed (hand-maintained)
├── bundles/                  # .ahu bundles from ./run.sh (not committed; containers use a named volume)
└── state-ecdsa/              # Edge anti-rollback high-water marks from ./run.sh
    ├── state.json            #   (not committed; containers use the state-ecdsa named volume)
    ├── generations/          #   immutable committed snapshots, restored together with state.json
    └── .writer.lock          #   OS writer lock file (never unlinked; the kernel lock is the lock)
```

**Re-running the script demo:** every run signs a *new* epoch-1 generation
(fresh CRL window and seal pair), so committed anti-rollback marks correctly
reject a re-run over existing state. `run.sh` detects this and tells you to
rerun with `./run.sh --fresh`, which removes the disposable runtime outputs
(`bundles/`, `state-ecdsa/`, `state-mldsa/`); the identity fixtures are kept.

> The `bundles/`, `state-ecdsa/`, and `state-mldsa/` directories are created by the
> **native `./run.sh`** path. The **containerized** path keeps the equivalent state
> in named volumes (`bundles`, `state-ecdsa`, `state-mldsa`) so host and container
> runs never share — and never poison — the same anti-rollback store.

## License

Demo fixtures and scripts: Apache-2.0 OR MIT (matching the `ahu` crate).
hoike server code: GPL-3.0-or-later.

## Attribution

Assisted-by: Claude Code (claude.ai/code)
