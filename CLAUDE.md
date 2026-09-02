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
cargo test --workspace               # 131 tests: unit, integration, e2e, conformance
cargo run --bin ahu -- inspect test.ahu
cargo run --bin hoike -- serve --config testdata/hoike-test.toml
cargo run --bin hoike -- sign --ca test --crl test.crl --demo-key -o test.ahu
cargo run --bin hoike -- query --url http://localhost:2560 --serial 0A --issuer-name-b64 ... --issuer-key-b64 ...
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
- **ML-DSA post-quantum signing**: ML-DSA-44/65/87 via PKCS#8 key loading with
  auto-detection (`MlDsaSignerVariant`). Dual-algorithm bundles with RFC 6960
  §4.4.7.1 PreferredSignatureAlgorithms negotiation. PKCS#11 ML-DSA via
  CKM_ML_DSA. ML-DSA CMS seals. Bridged via `hoike-sign/src/ml_dsa_bridge.rs`.
- **MmapBundle**: Zero-copy `MAP_PRIVATE` bundle reader in `ahu/src/mmap_bundle.rs`
  for large-scale serving. Binary search directly on mmap'd index region.
- **Bundle signature verification**: `hoike-sign/src/verify.rs` verifies OCSP
  response signatures (ECDSA and ML-DSA).
- **OCSP query client**: `hoike query` CLI diagnostic tool with `--prefer` for
  algorithm negotiation.
- **389 DS syncrepl adapter**: RFC 4533 Content Synchronization source for Dogtag
  certificate databases in `hoike-sign/src/dogtag_sync.rs`. Persistent cookie,
  positive issuance for `authoritative-complete` bundles.
- **On-demand signing endpoint**: `POST /api/admin/sign/{label}` and `/api/admin/sign`
  produce a bundle and hot-reload it, sharing the background loop's `SignerContext`
  mutex so epoch derivation and `.ahu` writes never race. Orchestration lives in
  `hoike-sign/src/orchestrate.rs`.
- **ahu bundle tooling over admin API**: `diff`, `extract`, and `apply` exposed as
  admin routes (`hoike-server/src/admin/bundles.rs`) and UI pages, backed by the pure
  computation in `ahu/src/ops.rs`.
- **Observability**: Prometheus `/metrics` on a dedicated listener (`server.metrics_listen`,
  `--features metrics`) covering requests, latency, CertID algs, nonce outcomes, bundle
  freshness/epoch/load-failures, signer-generation latency, and gossip membership. Facade
  in `hoike-server/src/obs.rs` compiles to no-ops without the feature. Structured audit
  log on the `audit` tracing target (always on).
- **Gossip fleet view (M4)**: SWIM membership (`GossipNode::members`) plus generation
  propagation. Signer passes and on-demand signing broadcast `GenerationAnnouncement`s
  (stamped with the announcing node via a `#[serde(default)]` `origin_node` field —
  backward-compatible across a mixed fleet); receivers fold them into a per-(node, scope)
  generation table. Admin `/api/admin/gossip` returns members + per-node epoch and
  staleness (`epochs_behind`, last-heard age); the Gossip UI page renders both with
  color-coding.

## What is NOT implemented

- **Gossip message authentication**: Membership and generation propagation work, but
  messages are still unauthenticated (`identity_key` sign/verify per design §6.3 is the
  remaining M4 sub-task).
- **Gossip bundle pull-on-announce**: Receiving a `GenerationAnnouncement` records it in
  the generation table but does not yet fetch/verify/swap the peer's bundle.
- **Seal trust anchor chain validation**: Verifies CMS signature integrity, but doesn't
  build a full PKIX path against trust anchors. Self-referential verification only.
- **SCVP**: Server-based Certificate Validation Protocol — separate protocol, not planned.

## Current state

All five milestones (M0–M5) plus post-milestone features (CMS seal, PKCS#11,
delegated cert, live nonce, key rotation, syncrepl, on-demand signing, Prometheus
metrics + audit log, ahu admin tooling, and the M4 gossip fleet view) are
implemented. The design doc (`hoike-design.md`) is the roadmap — it describes the
target architecture including features not yet built (gossip message signing,
bundle pull-on-announce). The README describes what runs today.

147 tests. ~15,000 lines of Rust.
