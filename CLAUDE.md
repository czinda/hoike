# hoike — Agent Context

## What this project is

hoike is a Rust OCSP responder serving pre-signed responses from `ahu` bundles.
The design separates signing (signer tier) from serving (edge tier, keyless,
horizontally scalable). See `hoike-design.md` for the full architecture roadmap
and `ahu-format-spec.md` for the bundle format specification.

## Build and test

```bash
cargo build              # build all crates
cargo test --workspace   # 81 tests: unit, integration, e2e, conformance
cargo run --bin ahu -- inspect test.ahu
cargo run --bin hoike -- serve --config testdata/hoike-test.toml
cargo run --bin hoike -- sign --ca test --crl test.crl -o test.ahu
```

## Workspace structure

| Crate | Purpose | License |
|-------|---------|---------|
| `ahu` | Bundle format (no runtime deps) | Apache-2.0 OR MIT |
| `hoike-core` | Request parsing, CertID routing, config, state store | GPL-3.0+ |
| `hoike-server` | HTTP handlers (axum) | GPL-3.0+ |
| `hoike-sign` | CRL adapter, OCSP response generation, ECDSA + ML-DSA signing | GPL-3.0+ |
| `hoike-gossip` | SWIM membership via foca, generation gossip | GPL-3.0+ |
| `hoike-cli` | `hoike` and `ahu` binaries | GPL-3.0+ |

## Key dependency notes

- `x509-ocsp` 0.2.1 depends on `der` 0.7, while `ahu` uses `der` 0.8. Any crate
  that parses or constructs OCSP types must use `der` 0.7 (matching x509-ocsp).
  The `ahu` crate uses `der` 0.8 and must not directly encode/decode x509-ocsp types.
- `ml-dsa` 0.1.1 uses `signature` v3, while `x509-ocsp` builder uses `signature` v2.
  `hoike-sign/src/ml_dsa_bridge.rs` bridges them with a wrapper type.

## Conventions

- Entry key = SHA-256(DER of CertID) — used throughout for index lookups
- CBOR manifest uses integer keys in ascending order (deterministic encoding)
- Error OCSP responses are static 5-byte DER constants (no signing needed)

## What is placeholder / not yet implemented

- **Seal**: Uses `Sha256::digest(manifest)` as a dummy seal, not CMS `SignedData`.
  The `cms` crate is declared as a dependency but never imported. Responses within
  bundles are properly signed; the container itself is not cryptographically sealed.
- **Signing key**: Three options — PKCS#8 file (`--signing-key`), PKCS#11/HSM
  (`signing_key.type = "pkcs11"`, behind `--features pkcs11`), or ephemeral demo
  (`--demo-key`). CLI refuses to sign without explicit key source. PKCS#11 PIN
  resolved via: interactive prompt (production) → env var → config file.
- **Issuer identity**: `--issuer-name-b64` and `--issuer-key-b64` CLI flags are
  wired for `hoike sign`. Without them, CertID hashes use synthetic bytes from
  the CA label (with a warning). Combined mode uses `issuer_name_der_b64` and
  `issuer_key_bytes_b64` config fields.
- **`nonce_policy = "live"`**: Rejected at config validation (not implemented).
- **Revocation sources**: Only CRL ingest. Dogtag REST, 389 DS, akamu, SQL are
  described in `hoike-design.md` but not coded.
- **Delegated signing**: Only CA-direct. `responder_cert` / `responder_key` config
  fields are not wired.
- **Gossip authentication**: Messages are unauthenticated; design doc requires signing.

### Mitigations for unauthenticated seal

Since the CMS seal is a placeholder, the manifest is unauthenticated:
- `MAX_EPOCH_JUMP` (10,000) prevents a poisoned bundle from setting
  `epoch = u64::MAX` and permanently locking a CA's high-water mark.
- `nextUpdate` enforcement now rejects expired bundles at serve time.
- Epoch uses a persisted counter (high_water + 1), not wall-clock time.

## Current state

All five milestones (M0–M5) are implemented at the prototype level. The design
doc (`hoike-design.md`) is the roadmap — it describes the target architecture
including features not yet built. The README describes what runs today.
