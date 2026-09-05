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
configured trust anchors on load.

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
# Produce a bundle from a CRL (requires explicit key source)
hoike sign --ca my-ca --crl revoked.crl --issuer issuer.der --signing-key responder.p8 -o bundle.ahu

# Or with ML-DSA post-quantum signing (demo key for testing)
hoike sign --ca my-ca --crl revoked.crl --issuer issuer.der --sig-alg ml-dsa-65 --demo-key -o bundle.ahu

# Inspect the bundle
ahu inspect bundle.ahu

# Inspect structural integrity; trusted admission also needs configured seal trust
ahu verify bundle.ahu

# Start the responder
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
| `hoike serve --config PATH` | Start the OCSP responder |
| `hoike check --config PATH` | Validate config, bundle, cert expiry |
| `hoike sign --ca LABEL --crl FILE [OPTIONS]` | Produce a signed ahu bundle from a CRL |
| `hoike import --bundle PATH [--config PATH] [--force]` | Import a bundle for enclave/air-gap deployments |
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
- `--seal-key PATH`: PKCS#8 PEM or DER P-256 seal key file (separate from signing key)
- `--dual-alg ALG`: produce a dual-algorithm bundle (e.g. `ml-dsa-87`) alongside the classical `--sig-alg`
- `--pq-signing-key PATH`: PKCS#8 PEM or DER PQ signing key file (for `--dual-alg`)

### ahu

| Command | Description |
|---------|-------------|
| `ahu inspect FILE` | Display manifest, scopes, epochs, counts |
| `ahu verify FILE [--entries]` | Verify CMS seal, digests, sort order; optionally verify each OCSP response signature |
| `ahu extract FILE --certid HEX` | Extract a single response by entry key |
| `ahu diff A B` | Show differences between two generations |
| `ahu apply BASE DELTAS... -o OUT` | Apply delta bundles to a base, producing a materialized full bundle |

## Configuration

A keyless edge needs bundle storage and explicit seal trust. Paths below are
operator-provisioned examples; see the [remediation migration guide](docs/review-remediation.md)
before upgrading existing state or configuration.

```toml
[server]
mode = "edge"
listen = "0.0.0.0:2560"
max_request = 8192

[storage]
bundle_dir = "/var/lib/hoike/bundles"
state_db = "/var/lib/hoike/state"
max_chain = 24
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

For a signer or combined process, configure the CA's signing key,
`responder_cert`, separate `seal_key`/`seal_cert`, source, and refresh cadence.
CRL sources require an independently authorized issuer certificate; its identity
is used when explicit issuer-name/key bytes are not configured:

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
