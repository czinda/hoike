# hoike — Agent Context

## What this project is

hoike is a Rust OCSP responder serving pre-signed responses from `ahu` bundles.
The design separates signing (signer tier, HSM access) from serving (edge tier,
keyless, horizontally scalable). See `hoike-design.md` for the full architecture
and `ahu-format-spec.md` for the bundle format specification.

## Build and test

```bash
cargo build              # build all crates
cargo test --workspace   # run all tests (23 tests: 12 unit, 7 integration, 4 e2e)
cargo run --bin ahu -- inspect test.ahu    # inspect a bundle
cargo run --bin hoike -- serve --config testdata/hoike-test.toml  # run server
```

## Workspace structure

| Crate | Purpose | License |
|-------|---------|---------|
| `ahu` | Bundle format (no runtime deps) | Apache-2.0 OR MIT |
| `hoike-core` | Request parsing, CertID routing, config | GPL-3.0+ |
| `hoike-server` | HTTP handlers (axum) | GPL-3.0+ |
| `hoike-sign` | PKCS#11 signing, batch production | GPL-3.0+ |
| `hoike-gossip` | SWIM membership, generation gossip | GPL-3.0+ |
| `hoike-cli` | `hoike` and `ahu` binaries | GPL-3.0+ |

## Key dependency note

`x509-ocsp` 0.2.1 depends on `der` 0.7, while `ahu` uses `der` 0.8. Any crate
that parses OCSP types must use `der` 0.7 (matching x509-ocsp). The `ahu` crate
uses `der` 0.8 and must not directly encode/decode x509-ocsp types.

## Conventions

- Entry key = SHA-256(DER of CertID) — used throughout for index lookups
- CBOR manifest uses integer keys in ascending order (deterministic encoding)
- Error OCSP responses are static 5-byte DER constants (no signing needed)
- Tests use `Sha256::digest(manifest)` as a dummy seal (real CMS in M2+)

## Current milestones

- M0 (ahu crate): Done
- M1 (edge server): Done
- M2 (signer tier): In progress
- M3-M5: Planned
