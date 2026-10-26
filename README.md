# hoike

**A Rust OCSP responder for pre-signed, replayable, multi-CA, highly available certificate status.**

*Hoike* (Hawaiian: to show, to exhibit, to testify) is an OCSP responder built
around a single architectural bet: **the machine that signs status and the
machine that serves it should not be the same machine.**

## Why this exists

The CA/Browser Forum made OCSP optional for the public Web PKI (SC-063), and
Let's Encrypt shut its responders down in August 2025. But OCSP is alive and
contractually required in enterprise, federal, DoD, device/IoT PKI, and
802.1X/EAP-TLS environments where CRL size makes CRLs impractical.

Dogtag PKI's built-in OCSP subsystem signs every response live at request time,
requiring HSM access on every serving node. hoike separates signing from serving:

- **Signer tier** — holds keys (PKCS#11 HSM or software), reads revocation
  state, batch-produces CMS-sealed bundles of pre-signed responses. Handles
  live nonce-bearing requests on demand.
- **Edge tier** — holds no keys, loads bundles, serves stored bytes verbatim.
  Horizontally scalable, anycast-friendly, air-gap-capable.

## Architecture

```
   revocation source              ┌───────────────────┐
   (CRL, 389 DS syncrepl,        │  SIGNER TIER      │
    akamu planned)          ────▶│  • reads status   │
                                  │  • batch signs    │
                                  │  • CMS seals .ahu │
                                  └────────┬──────────┘
                                           │ ahu bundles
                         ┌─────────────────┼─────────────────┐
                   ┌─────▼──────┐    ┌─────▼──────┐    ┌─────▼──────┐
                   │ EDGE NODE  │    │ EDGE NODE  │    │ EDGE NODE  │
                   │  (keyless) │    │  (keyless) │    │  (keyless) │
                   └─────┬──────┘    └─────┬──────┘    └─────┬──────┘
                         └────── clients ──┴──────────────────┘
```

## Standards

| RFC | Role |
|-----|------|
| RFC 6960 | Base OCSP protocol |
| RFC 9919 | Primary operating profile (pre-production, caching, SHA-256 CertID) |
| RFC 9654 | Nonce length rules |
| RFC 5280 | AIA, responder certificate profile |
| RFC 5652 | CMS SignedData (bundle seal) |

Validated by a 20-check conformance test suite in `crates/hoike-server/tests/conformance.rs`.

For the Common Criteria view — how hoike maps to the **NIAP Protection Profile
for Certification Authorities v2.1 (PP 420)** and the TLS Functional Package
v1.1, including the transport-hardening trusted-path/trusted-channel SFRs — see
[`docs/niap-ppca-gap-matrix.md`](docs/niap-ppca-gap-matrix.md).

## The ahu bundle format

The **ahu** (Hawaiian: a cairn, a trail marker) format is a portable container of
pre-signed OCSP responses. Bundles are sealed with CMS `SignedData`, designed
for zero-copy serving via `mmap` + binary search, and verified against
configured signer certificate pins or CA anchors on load.

See [`ahu-format-spec.md`](ahu-format-spec.md) for the full specification.

## Building from source

Install a C compiler, CMake and pkg-config as well as the repository Rust
toolchain. The signing crate uses AWS-LC for RSA CRL verification, including
builds without TLS. On Debian-based builders these packages are
`build-essential cmake pkg-config`.

```bash
cargo build --release

# With PKCS#11 HSM support (requires PKCS#11 C library at link time)
cargo build --release --features pkcs11
```

Binaries:
- `target/release/hoike` — the OCSP responder (~8 MB)
- `target/release/ahu` — bundle inspection and management tool (~1 MB)

Running tests (147 tests across 6 crates):

```bash
cargo test --workspace
```

## Quick start

```bash
# Produce a bundle from a CRL (requires explicit key source and seal pair)
hoike sign --ca my-ca --crl revoked.crl --issuer issuer.der \
  --signing-key responder.p8 --seal-key seal.p8 --seal-cert seal-cert.pem -o bundle.ahu

# Or with ML-DSA post-quantum signing (demo key for testing)
hoike sign --ca my-ca --crl revoked.crl --issuer issuer.der --sig-alg ml-dsa-65 --demo-key -o bundle.ahu

# Inspect the bundle
ahu inspect bundle.ahu

# Check structural integrity only (does not authenticate the bundle)
ahu verify bundle.ahu --structure-only

# Authenticate after provisioning seal trust in hoike.toml
ahu verify bundle.ahu --config hoike.toml

# Start the responder (initialize the state directory once, first)
hoike init-state --config hoike.toml
hoike serve --config hoike.toml

# Validate configuration before deploying
hoike check --config hoike.toml

# Query a running responder
hoike query --url http://localhost:2560 --serial 0A1B2C --issuer-name-b64 ... --issuer-key-b64 ...

# Query with post-quantum algorithm preference
hoike query --url http://localhost:2560 --serial 0A1B2C --issuer-name-b64 ... --issuer-key-b64 ... --prefer ml-dsa-87
```

## CLI reference

### hoike

| Command | Description |
|---------|-------------|
| `hoike serve --config PATH` | Start the OCSP responder (requires an initialized state directory; holds the exclusive writer lock) |
| `hoike init-state --config PATH` | Explicitly initialize a fresh state directory (refuses existing state) |
| `hoike check --config PATH` | Read-only config and bundle trust checks; report cert expiry |
| `hoike sign --ca LABEL --crl FILE [OPTIONS]` | Produce a signed ahu bundle from a CRL |
| `hoike import --bundle PATH --ca LABEL --config PATH` | Offline authenticated installation into the selected CA destination (fails while a server holds the writer lock) |
| `hoike query --url URL --serial HEX [OPTIONS]` | Query a running OCSP responder |

**`hoike sign` options:**
- `--signing-key PATH`: PKCS#8 PEM or DER signing key file (mutually exclusive with `--demo-key`)
- `--demo-key`: use an ephemeral key for testing (NOT FOR PRODUCTION)
- `--sig-alg`: `ecdsa-p256` (default), `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`
- `--certid-compat`: `dual` (default, SHA-1 + SHA-256), `sha256`, `sha1`
- `--epoch N`: epoch number for this generation
- `--good-serials FILE`: hex serial numbers to mark as good (one per line)
- `--issuer-name-b64`: base64-encoded DER issuer name (for correct CertID hashes)
- `--issuer-key-b64`: base64-encoded issuer public key bytes
- `--issuer PATH`: issuer certificate (DER) for CertID computation
- `--seal-key PATH`: PKCS#8 PEM or DER P-256 seal key file — required together with `--seal-cert` for file-key signing (any algorithm); must hold a key distinct from the OCSP signing key
- `--seal-cert PATH`: PEM or DER seal certificate matching the seal key
- `--dual-alg ALG`: produce a dual-algorithm bundle (e.g. `ml-dsa-87`) alongside the classical `--sig-alg`
- `--pq-signing-key PATH`: PKCS#8 PEM or DER PQ signing key file (for `--dual-alg`)

File-key signing requires a complete persistent seal pair: provide both
`--seal-key` and `--seal-cert` or neither. A half-configured pair is always an
error, the signing key is never implicitly reused for sealing, and a seal key
whose public key equals the OCSP signing key is rejected even when configured
under a different file name. `--demo-key` (with no seal inputs) generates a
distinct ephemeral seal pair for testing only.

### ahu

| Command | Description |
|---------|-------------|
| `ahu inspect FILE` | Display manifest, scopes, epochs, counts |
| `ahu verify FILE --config PATH [--entries]` | Authenticate the CMS seal and scope authorization; check structure and optionally OCSP signatures |
| `ahu verify FILE --structure-only` | Check structure and digests without authenticating the bundle |
| `ahu extract FILE --certid HEX` | Extract a single response by entry key |
| `ahu diff A B` | Show differences between two generations |
| `ahu apply BASE DELTAS... -o OUT` | Apply delta bundles to a base, producing a materialized full bundle |

Verification requires an explicit mode. Bare `ahu verify FILE` fails; it does not
discover configuration. `--structure-only` conflicts with `--config` and
`--entries`, and prints `Structure valid; authenticity not checked.` on success.

Authenticated verification requires `storage.seal_signer_pins` or
`storage.seal_trust_anchors`. It checks the seal certificate's current validity
and supported profile, plus any configured `seal_authorizations`. The demo
admission flag never bypasses these checks for `ahu verify --config`.
Successful output states `Installation eligibility not checked.`: verification
does not establish freshness or rollback eligibility and does not install a bundle.

`--entries` checks signatures using embedded responder keys, not general
responder-chain PKIX validation. Successful OCSP responses without embedded
certificates make the command fail as incomplete. Protocol-defined unsigned OCSP
error responses are counted separately from verified signatures.

`hoike check` checks the configured bundle candidates with the same admission
trust policy, without creating state, changing rollback marks, or installing
snapshots. Explicit demo mode reports `Unauthenticated demo admission; authenticity
not checked.` It does not substitute a committed snapshot for a failing candidate.

The admin `POST /api/admin/bundles/verify` route uses the running server's trust
policy. A structurally valid but untrusted upload returns HTTP 200 with
`overall_ok: false`, `trust_status: "failed"`, a `trust_error`, and a null
`signer_sha256`. Authenticated results report `trust_status: "authenticated"`,
a null `trust_error`, and the signer's DER certificate SHA-256 fingerprint.
`overall_ok` also requires all structural checks to pass. Malformed input returns
HTTP 400. Inspection only reports seal presence; it does not authenticate a seal.

## Configuration

A keyless edge needs bundle storage and explicit seal trust. Paths below are
operator-provisioned examples; see the [remediation migration guide](docs/review-remediation.md)
before upgrading existing state or configuration. The state directory must be
initialized once with `hoike init-state --config hoike.toml` before the first
`serve`; `serve` never creates it implicitly, and exactly one writer process
per state directory is enforced with an OS lock.

```toml
[server]
mode = "edge"
listen = "0.0.0.0:2560"
max_request = 8192

[storage]
bundle_dir = "/var/lib/hoike/bundles"
state_db = "/var/lib/hoike/state"
allow_unauthenticated_bundles = false
# Exact signer certificate pins (PEM or DER), not SPKI hashes:
seal_signer_pins = ["/etc/hoike/seal-signer.pem"]
# Alternative: dedicated CA anchors for the supported direct-issuer profile.
# seal_trust_anchors = ["/etc/hoike/seal-ca.pem"]
# Restrict trusted signers to producer/CA scopes with [[storage.seal_authorizations]].
# See migration guide for DER certificate fingerprint and dual-scope rules.

[[ca]]
label = "enterprise-issuing-01"
bundle_file = "/var/lib/hoike/bundles/enterprise-issuing-01.ahu"
nonce_policy = "ignore"
completeness = "partial"

[gossip]
enabled = false
bind = "0.0.0.0:7946"
seeds = []
node_name = "edge-01"
# Before enabling authenticated gossip, provision the local signing key and
# mappings for each authorized origin (including this node where needed):
# identity_key = "/etc/hoike/gossip/edge-01.ed25519.p8"
# [gossip.peer_identities]
# edge-01 = "/etc/hoike/gossip/edge-01.pub.pem"
# edge-02 = "/etc/hoike/gossip/edge-02.pub.pem"
```

Bundle admission requires configured seal trust by default, including startup,
hot reload, and recovery from committed snapshots. Existing deployments with no
trust policy must provision `seal_signer_pins` or `seal_trust_anchors` before
upgrading. Embedded signer certificates do not establish trust by themselves.
An empty `seal_authorizations` list leaves trusted signers unrestricted by scope;
when configured, it must authorize every scope, including both SHA-1 and SHA-256
scopes in dual-CertID bundles.

For local demos only, set `storage.allow_unauthenticated_bundles = true` with no
pins, anchors, or authorizations. This mode checks structure and digests but does
not authenticate the seal. Each demo admission emits an `audit` warning with
`trust = "unauthenticated_demo"`. Any configured trust still applies, even with
the flag enabled: invalid seals, unreadable trust files, and unauthorized scopes
are rejected. Authorizations without pins or anchors are also rejected.

Admission accepts only the supported serving profile: full, uncompressed
bundles. The ahu format can *represent* deltas, tombstones, Zstd compression,
and delta chains, but the responder implements no runtime delta overlays or
decompression, so admission rejects those profiles before any durable state
changes — including startup, hot reload, `hoike check`, and `hoike import`.
A correctly sealed delta or compressed bundle is still inspectable with
`ahu verify --config`; to serve one, materialize it into a full, uncompressed
bundle first with `ahu apply` (an authenticated, resealed output must still
satisfy predecessor continuity against the actual destination). The obsolete
`storage.max_chain` setting was removed: accepting a chain-limit promise that
was never implemented is misleading. Configurations that still set it fail to
parse with an unknown-field error; remove the line when upgrading.

`hoike import --bundle PATH --ca LABEL --config PATH` is an offline,
recoverable authenticated installation, not a staging copy. The label is
required: it selects the configured destination (the CA's `bundle_file`, or
`bundle_dir/<label>.ahu`); unknown labels, legacy unscoped configuration, and
destinations shared by another configured label are rejected. The input is
always authenticated under the configured seal trust and serving profile —
the `allow_unauthenticated_bundles` demo flag never relaxes import — and
rollback/predecessor checks run against the committed state, which must have
been initialized with `hoike init-state`. The commit order is: immutable
snapshot write+fsync, then the atomic state-descriptor commit (the
installation commit point), then publication of the configured bundle path.
A failure before the descriptor commit leaves the previous generation
untouched; if the descriptor's directory fsync fails after its rename, the
error is `DurabilityUncertain` and the operator must stop and reopen state;
if the post-commit path publication fails, the import still reports success
with a warning, startup recovers from the committed snapshot, and retrying
the identical import repairs the path. Import is offline by design — a
running server holds the exclusive writer lock and makes it fail promptly —
and completion tells the operator to start the server (there is no SIGHUP
path and no `--force` override). The authenticated admin reload endpoint is
unaffected.

For a signer or combined process, configure the CA's signing key,
`responder_cert`, separate `seal_key`/`seal_cert`, source, and refresh cadence.
`seal_key` and `seal_cert` must be configured together — a half-configured pair
fails validation, and persistent signing keys (file or PKCS#11) require the
complete pair. Only `type = "demo"` signing may omit both, which generates a
distinct ephemeral seal pair for testing. `seal_cert` may be PEM or DER; it is
normalized to DER and the seal
key/certificate pair is proven with a real CMS preflight seal before anything
is published — and re-proven on every signing pass (background loop, on-demand
signing, post-rotation material reload), so a mismatched or expired
replacement certificate fails closed and leaves the previous generation in
place. The OCSP signing key and the seal key must be distinct: an ECDSA
signer whose signature over the domain-separated separation message verifies
under the seal public key is rejected before production, even when the same
key material is configured under different file names. (An ML-DSA OCSP signer
is algorithm-distinct from the configured P-256 seal key.) CRL sources
require an independently authorized issuer certificate;
its identity is used when explicit issuer-name/key bytes are not configured:

```toml
# Add to the relevant [[ca]] table, before its nested source/signing tables:
responder_cert = "/etc/hoike/responder-01.pem"
seal_key = "/etc/hoike/seal-key.p8"
seal_cert = "/etc/hoike/seal-signer.pem"

[ca.source]
type = "crl"
path = "/var/lib/hoike/crls/enterprise.crl"
issuer_cert = "/etc/hoike/issuer.der"

[ca.signing_key]
type = "pkcs11"
module = "/usr/lib64/pkcs11/libkryoptic_pkcs11.so"
token_label = "hoike-ocsp"
key_label = "ocsp-signing"
pin_env = "HOIKE_HSM_PIN"
```

Build with `pkcs11` for that signing key, `dogtag-sync` for directory sources,
and `tls` when configuring TLS/mTLS. A configured security feature that is not
available must fail rather than fall back. `nonce_policy = "forward"` requires
an HTTPS `forward_to`; `live` belongs on signer/combined nodes. CRL enumeration
cannot establish authoritative completeness. Dogtag's `authoritative-complete`
mode additionally requires a successful complete source refresh; see the migration
guide for source-bound snapshot/cookie checkpoints and full-refresh requirements.

The live/seal backend matrix is deliberately narrow: configured bundle seals
are P-256 software keys (`seal_key` PKCS#8 file; ML-DSA seals remain available
through the library and `ahu apply --seal-key` path), batch OCSP signing
covers ECDSA software, ECDSA PKCS#11, and ML-DSA software keys, and live nonce
signing covers the configured ECDSA software key. ML-DSA live nonce signing
and HSM-backed seal keys are separate extensions, not implied by the signing
key's backend.

## Workspace layout

```
hoike/
├── crates/
│   ├── ahu/            # Bundle format: read, write, verify, CMS seal, mmap zero-copy (Apache-2.0 OR MIT)
│   ├── hoike-core/     # CertID routing, request parsing, config, anti-rollback state store
│   ├── hoike-sign/     # CRL + syncrepl adapters, OCSP response generation, CMS seal creation,
│   │                   # live nonce signing, PKCS#11 bridge, ML-DSA bridge, key rotation
│   ├── hoike-server/   # HTTP request path (axum), nonce policy dispatch
│   ├── hoike-gossip/   # SWIM membership + generation announcements (foca)
│   └── hoike-cli/      # hoike + ahu binaries
├── ahu-format-spec.md  # Bundle format specification
├── hoike-design.md     # Architecture and design document (roadmap)
└── testdata/           # Test configs
```

## Milestones

These statuses describe feature implementation, not production qualification.
The [29-finding remediation ledger](docs/review-remediation.md) records corrective
changes, regression evidence, migration requirements, and remaining release gates.

| | Scope | Status |
|--|-------|--------|
| **M0** | `ahu` crate: read, write, verify, CLI | Done |
| **M1** | Single-CA edge server: GET/POST, RFC 9919 headers | Done |
| **M2** | Signer tier: CRL adapter, ECDSA/ML-DSA signing, batch production | Done |
| **M3** | Multi-CA routing, nonce policies (ignore/forward/live), combined mode | Done |
| **M4** | Gossip (SWIM/foca), enclave import, anti-rollback persistence | Done |
| **M5** | ML-DSA-44/65/87, batching benchmarks, RFC 9919/9654 conformance suite | Done |
| **Post** | CMS seal, PKCS#11 HSM, delegated cert, key rotation, 389 DS syncrepl | Done |
| **Ops** | On-demand signing API, Prometheus `/metrics` + audit log, gossip fleet view (members + generation propagation), ahu diff/extract/apply over admin API + web UI | Done |

## Known limitations

- **Gossip: broadcasts signed, channel not encrypted** — generation/urgent-revocation
  broadcasts are Ed25519-signed and verified by named-origin mappings
  (`gossip.identity_key` + `gossip.peer_identities`, design §6.3). Enforced mode
  rejects unsigned, forged, or misattributed broadcasts. Not yet
  covered: payload *confidentiality* and authentication of foca's SWIM liveness traffic
  (pings/acks).
- **Bounded CMS trust profile** — explicit certificate pins or direct-issued
  seal certificates under configured CA anchors. General intermediate-chain PKIX
  validation is unsupported. Configure producer/CA authorizations where needed.
- **CRL profile** — authenticated direct complete CRLs only; unsupported algorithms,
  delta/indirect CRLs and unsupported critical extensions reject explicitly.
- **Serving profile** — only full, uncompressed bundles are admitted. Deltas,
  tombstones, Zstd compression, and nonempty delta-chain metadata are ahu
  *format* features the serving path rejects at admission; runtime delta
  overlays and decompression are not implemented. Materialize deltas offline
  with `ahu apply` first.
- **Delta apply output** — unsigned intermediate by default; authenticate inputs and
  use an authorized real CMS sealing callback before trusted installation.
- **Multi-CertID requests** — only the first `CertID` in a multi-Request
  `OCSPRequest` is answered. Defensible under RFC 9919's single-Request profile
  but provides no signal to the client.
- **SCVP** — Server-based Certificate Validation Protocol (RFC 5055) is not
  implemented. Separate protocol, niche use case.
- **No production deployments** — lab-tested only.

## License

- **`ahu` crate**: Apache-2.0 OR MIT (matching the RustCrypto ecosystem)
- **`hoike` server crates**: GPL-3.0-or-later

## Attribution

Assisted-by: Claude Code (claude.ai/code)

See [REDHAT.md](REDHAT.md) for AI attribution policy.
