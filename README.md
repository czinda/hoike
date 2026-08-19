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

- **Signer tier** — holds keys, reads revocation state, batch-produces bundles
  of pre-signed responses on a configurable cadence.
- **Edge tier** — holds no keys, loads bundles, serves stored bytes verbatim.
  Horizontally scalable, anycast-friendly, air-gap-capable.

## Architecture

```
   revocation source              ┌───────────────────┐
   (CRL today; Dogtag REST,      │  SIGNER TIER      │
    389 DS, akamu planned)  ────▶│  • reads status   │
                                  │  • batch signs    │
                                  │  • produces .ahu  │
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

Validated by a 20-check conformance test suite in `crates/hoike-server/tests/conformance.rs`.

## The ahu bundle format

The **ahu** (Hawaiian: a cairn, a trail marker) format is a portable container of
pre-signed OCSP responses. Bundles are self-describing and designed for zero-copy
serving via `mmap` + binary search.

See [`ahu-format-spec.md`](ahu-format-spec.md) for the full specification.

## Building from source

```bash
cargo build --release
```

Binaries:
- `target/release/hoike` — the OCSP responder (~8 MB)
- `target/release/ahu` — bundle inspection and management tool (~1 MB)

Running tests (81 tests across 6 crates):

```bash
cargo test --workspace
```

## Quick start

```bash
# Produce a bundle from a CRL
hoike sign --ca my-ca --crl revoked.crl -o bundle.ahu

# Or with ML-DSA post-quantum signing
hoike sign --ca my-ca --crl revoked.crl --sig-alg ml-dsa-65 -o bundle.ahu

# Inspect the bundle
ahu inspect bundle.ahu

# Verify bundle integrity
ahu verify bundle.ahu

# Start the responder
hoike serve --config hoike.toml

# Validate configuration before deploying
hoike check --config hoike.toml
```

## CLI reference

### hoike

| Command | Description |
|---------|-------------|
| `hoike serve --config PATH` | Start the OCSP responder |
| `hoike check --config PATH` | Validate config, bundle, and connectivity |
| `hoike sign --ca LABEL --crl FILE [OPTIONS]` | Produce a signed ahu bundle from a CRL |
| `hoike import --bundle PATH [--config PATH] [--force]` | Import a bundle for enclave/air-gap deployments |

**`hoike sign` options:**
- `--sig-alg`: `ecdsa-p256` (default), `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`
- `--certid-compat`: `dual` (default, SHA-1 + SHA-256), `sha256`, `sha1`
- `--epoch N`: epoch number for this generation
- `--good-serials FILE`: hex serial numbers to mark as good (one per line)

### ahu

| Command | Description |
|---------|-------------|
| `ahu inspect FILE` | Display manifest, scopes, epochs, counts |
| `ahu verify FILE [--entries]` | Verify seal, digests, sort order |
| `ahu extract FILE --certid HEX` | Extract a single response by entry key |
| `ahu diff A B` | Show differences between two generations |
| `ahu apply BASE DELTAS... -o OUT` | Apply delta bundles to a base, producing a materialized full bundle |

## Configuration

```toml
[server]
mode        = "edge"            # "signer" | "edge" | "combined"
listen      = "0.0.0.0:2560"
max_request = 8192              # bytes

[storage]
bundle_dir = "/var/lib/hoike/bundles"
state_db   = "/var/lib/hoike/state"   # epoch high-water marks
max_chain  = 24                       # max delta chain before requiring full bundle

[[ca]]
label          = "enterprise-issuing-01"
bundle_file    = "/var/lib/hoike/bundles/enterprise.ahu"  # optional; auto-detects newest .ahu
nonce_policy   = "ignore"                                 # "ignore" or "forward"
completeness   = "authoritative-complete"                 # or "partial" for CRL-only
forward_to     = "https://signer.pki.example:2560"        # required when nonce_policy = "forward"

# For combined/signer mode: revocation source
[ca.source]
type = "crl"
path = "/var/lib/hoike/crls/enterprise.crl"

# Optional: gossip for edge fleet coordination
[gossip]
enabled   = true
bind      = "0.0.0.0:7946"
seeds     = ["edge-a.pki.example:7946", "edge-b.pki.example:7946"]
node_name = "edge-01"
```

## Workspace layout

```
hoike/
├── crates/
│   ├── ahu/            # Bundle format: read, write, verify (Apache-2.0 OR MIT)
│   ├── hoike-core/     # CertID routing, request parsing, config, state store
│   ├── hoike-sign/     # Signing, CRL adapter, OCSP response generation
│   ├── hoike-server/   # HTTP request path (axum)
│   ├── hoike-gossip/   # SWIM membership + generation announcements (foca)
│   └── hoike-cli/      # hoike + ahu binaries
├── ahu-format-spec.md  # Bundle format specification
├── hoike-design.md     # Architecture and design document (roadmap)
└── testdata/           # Test configs
```

## Milestones

| | Scope | Status |
|--|-------|--------|
| **M0** | `ahu` crate: read, write, verify, CLI | Done |
| **M1** | Single-CA edge server: GET/POST, RFC 9919 headers | Done |
| **M2** | Signer tier: CRL adapter, ECDSA/ML-DSA signing, batch production | Done |
| **M3** | Multi-CA routing, nonce forward policy, combined mode | Done |
| **M4** | Gossip (SWIM/foca), enclave import, anti-rollback persistence | Done |
| **M5** | ML-DSA-44/65/87, batching benchmarks, RFC 9919/9654 conformance suite | Done |

## Known limitations

The following items from the [design document](hoike-design.md) are not yet implemented:

- **CMS seal** — the bundle seal is currently a SHA-256 hash placeholder, not a
  CMS `SignedData` signature. OCSP responses within bundles are properly signed
  (their own signatures are real), but the container itself is not
  cryptographically sealed. This means anti-rollback checks operate on
  unauthenticated manifest data.
- **PKCS#11 / HSM integration** — no `cryptoki` dependency exists. Signing uses
  software keys (ephemeral ECDSA or ML-DSA generated at startup).
- **Dogtag REST adapter** — only the CRL ingest adapter is implemented. The
  design doc lists Dogtag, 389 DS, akamu, and SQL adapters as planned.
- **Live nonce signing** — `nonce_policy = "live"` is rejected at config
  validation. Only `ignore` and `forward` are available.
- **Delegated signing** — only CA-direct signing is implemented. The design
  doc's `responder_cert` / `responder_key` config has no code behind it.
- **`--issuer` flag** — accepted by `hoike sign` but currently ignored. Use
  `--issuer-name-b64` and `--issuer-key-b64` for correct CertID hashes, or
  configure `issuer_name_der_b64` / `issuer_key_bytes_b64` in `[[ca]]` blocks.
- **Gossip messages are unsigned** — the design doc (§6.3) requires every gossip
  message to be signed. The current implementation uses foca's postcard codec
  with no authentication.
- **Multi-CertID requests** — only the first `CertID` in a multi-Request
  `OCSPRequest` is answered. Subsequent CertIDs are silently dropped. This is
  defensible under RFC 9919's single-Request profile but provides no signal to
  the client.

## License

- **`ahu` crate**: Apache-2.0 OR MIT (matching the RustCrypto ecosystem)
- **`hoike` server crates**: GPL-3.0-or-later

## Attribution

Assisted-by: Claude Code (claude.ai/code)

See [REDHAT.md](REDHAT.md) for AI attribution policy.
