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

- **Signer tier** — holds keys, reads revocation state, batch-produces sealed
  bundles of pre-signed responses on a configurable cadence.
- **Edge tier** — holds no keys, loads bundles, serves stored bytes verbatim.
  Horizontally scalable, anycast-friendly, air-gap-capable.

## Architecture

```
   revocation source              ┌───────────────────┐
   (Dogtag / RHCS, 389 DS,       │  SIGNER TIER      │
    CRL, akamu, database)  ─────▶│  • reads status   │
                                  │  • batch signs    │
                                  │  • seals bundles  │
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

## The ahu bundle format

The **ahu** (Hawaiian: a cairn, a trail marker) format is a portable container of
pre-signed OCSP responses. Bundles are self-describing, sealed with CMS
`SignedData`, and designed for zero-copy serving via `mmap` + binary search.

See [`ahu-format-spec.md`](ahu-format-spec.md) for the full specification.

## Building

```bash
cargo build --release
```

Binaries:
- `target/release/hoike` — the OCSP responder
- `target/release/ahu` — bundle inspection and management tool

## Quick start

```bash
# Inspect a bundle
ahu inspect path/to/bundle.ahu

# Verify bundle integrity
ahu verify path/to/bundle.ahu

# Start the responder
hoike serve --config hoike.toml

# Validate configuration before starting
hoike check --config hoike.toml
```

## CLI reference

### hoike

| Command | Description |
|---------|-------------|
| `hoike serve --config PATH` | Start the OCSP responder |
| `hoike check --config PATH` | Validate config, bundle, and connectivity |

### ahu

| Command | Description |
|---------|-------------|
| `ahu inspect FILE` | Display manifest, scopes, epochs, counts |
| `ahu verify FILE [--entries]` | Verify seal, digests, sort order |
| `ahu extract FILE --certid HEX` | Extract a single response by entry key |
| `ahu diff A B` | Show differences between two generations |

## Configuration

```toml
[server]
mode   = "edge"          # "signer" | "edge" | "combined"
listen = "0.0.0.0:2560"

[storage]
bundle_dir = "/var/lib/hoike/bundles"
state_db   = "/var/lib/hoike/state"

[[ca]]
label        = "enterprise-issuing-01"
nonce_policy = "ignore"
completeness = "authoritative-complete"
```

## Workspace layout

```
hoike/
├── crates/
│   ├── ahu/            # Bundle format: read, write, verify (Apache-2.0 OR MIT)
│   ├── hoike-core/     # CertID routing, request parsing, policy
│   ├── hoike-sign/     # PKCS#11, signing, generation production
│   ├── hoike-server/   # HTTP request path (axum)
│   ├── hoike-gossip/   # SWIM membership + announcements
│   └── hoike-cli/      # hoike + ahu binaries
├── spec/               # Format specification
└── testdata/           # Test vectors and configs
```

## Milestones

| | Scope | Status |
|--|-------|--------|
| **M0** | `ahu` crate: read, write, verify, CLI | Done |
| **M1** | Single-CA edge server: GET/POST, RFC 9919 headers | Done |
| **M2** | Signer tier: Dogtag adapter, PKCS#11, batch production | In progress |
| **M3** | Multi-CA routing, nonce policies, combined mode | Planned |
| **M4** | Gossip, enclave import, anti-rollback persistence | Planned |
| **M5** | ML-DSA post-quantum, batching benchmarks, Infrared conformance | Planned |

## License

- **`ahu` crate**: Apache-2.0 OR MIT (matching the RustCrypto ecosystem)
- **`hoike` server crates**: GPL-3.0-or-later

## Attribution

Assisted-by: Claude Code (claude.ai/code)

See [REDHAT.md](REDHAT.md) for AI attribution policy.
