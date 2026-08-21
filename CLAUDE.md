# hoike — Agent Context

## What this project is

hoike is a Rust OCSP responder serving pre-signed responses from `ahu` bundles.
The design separates signing (signer tier) from serving (edge tier, keyless,
horizontally scalable). See `hoike-design.md` for the full architecture roadmap
and `ahu-format-spec.md` for the bundle format specification.

## Build and test

```bash
cargo build                          # build all crates
cargo build --features pkcs11        # with PKCS#11 HSM support
cargo test --workspace               # 103 tests: unit, integration, e2e, conformance
cargo run --bin ahu -- inspect test.ahu
cargo run --bin hoike -- serve --config testdata/hoike-test.toml
cargo run --bin hoike -- sign --ca test --crl test.crl --demo-key -o test.ahu
```

## Workspace structure

| Crate | Purpose | License |
|-------|---------|---------|
| `ahu` | Bundle format, CMS seal verification (no runtime deps) | Apache-2.0 OR MIT |
| `hoike-core` | Request parsing, CertID routing, config, anti-rollback state store | GPL-3.0+ |
| `hoike-server` | HTTP handlers (axum), nonce policy dispatch, live signing | GPL-3.0+ |
| `hoike-sign` | CRL + syncrepl adapters, OCSP response generation, CMS seal creation, live nonce, PKCS#11, ML-DSA bridge, key rotation | GPL-3.0+ |
| `hoike-gossip` | SWIM membership via foca, generation gossip | GPL-3.0+ |
| `hoike-cli` | `hoike` and `ahu` binaries | GPL-3.0+ |

## Key dependency notes

- `x509-ocsp` 0.2.1 depends on `der` 0.7, while `ahu` uses `der` 0.8. Any crate
  that parses or constructs OCSP types must use `der` 0.7 (matching x509-ocsp).
  The `ahu` crate uses `der` 0.8 and must not directly encode/decode x509-ocsp types.
- `ml-dsa` 0.1.1 uses `signature` v3, while `x509-ocsp` builder uses `signature` v2.
  `hoike-sign/src/ml_dsa_bridge.rs` bridges them with a wrapper type.
- `cms` 0.3.0-pre.2 uses `der` 0.8. CMS seal creation in `hoike-sign/src/seal.rs`
  bridges: signs with the `der` 0.7 key, embeds raw bytes into `der` 0.8 CMS structures.
- `cryptoki` 0.12 is behind the `pkcs11` feature flag (links against C library).

## Conventions

- Entry key = SHA-256(DER of CertID) — used throughout for index lookups
- CBOR manifest uses integer keys in ascending order (deterministic encoding)
- Error OCSP responses are static 5-byte DER constants (no signing needed)
- Seal key must be distinct from OCSP signing key (different lifetimes)
- When `responder_cert` is configured, ResponderID uses the cert's SPKI key hash

## What is implemented

- **CMS seal**: Real CMS `SignedData` seal. Produced by `hoike-sign/src/seal.rs`,
  verified by `ahu/src/seal.rs` (behind `seal-verify` default feature). Verified
  on bundle load when `seal_trust_anchors` is configured in storage config.
- **Signing keys**: PKCS#8 file (`--signing-key`), PKCS#11/HSM (`signing_key.type = "pkcs11"`,
  behind `--features pkcs11`), or ephemeral demo (`--demo-key`). CLI refuses to
  sign without explicit key source. PKCS#11 PIN resolved via: interactive prompt → env var → config.
- **Live nonce signing**: `nonce_policy = "live"` on signer/combined nodes. Signs fresh
  responses on demand with the client's nonce embedded.
- **Delegated signing**: Responder cert embedded in `BasicOCSPResponse.certs` per
  RFC 9919 §3.2.2. ResponderID computed from the cert's SPKI key hash.
- **Revocation sources**: CRL ingest adapter + 389 DS syncrepl adapter (`dogtag-sync`
  feature). Syncrepl provides positive issuance for `authoritative-complete` bundles.
- **Key rotation**: Monitors responder cert expiry, logs warnings, executes
  `rotation_command` when configured.

## What is NOT implemented

- **Gossip authentication**: Messages are unauthenticated; design doc requires signing.
- **Seal trust anchor chain validation**: Verifies CMS signature integrity, but doesn't
  build a full PKIX path against trust anchors. Self-referential verification only.
- **SCVP**: Server-based Certificate Validation Protocol — separate protocol, not planned.
- **Issuer identity from cert**: `--issuer-name-b64` / `--issuer-key-b64` flags provide
  issuer DER and key bytes. No automatic extraction from an issuer certificate file.

## Current state

All five milestones (M0–M5) plus post-milestone features (CMS seal, PKCS#11,
delegated cert, live nonce, key rotation, syncrepl) are implemented. The design
doc (`hoike-design.md`) is the roadmap — it describes the target architecture
including features not yet built. The README describes what runs today.

103 tests. 12,000+ lines of Rust. 37+ commits.
