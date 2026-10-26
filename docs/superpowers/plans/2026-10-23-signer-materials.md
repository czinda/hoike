# Signer Material Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close F07–F08 with valid PEM/DER seal inputs and enforced separation of production seal/OCSP keys.

**Architecture:** Keep material loading in `hoike-sign`; validate using existing certificate/CMS implementations and check separation against the loaded signer. Both configured orchestration and one-shot CLI use the same helpers.

**Tech Stack:** Existing P-256/ML-DSA/CMS code, der 0.8 for seal certificates, signature/spki 0.7-side bridges for OCSP, feature-gated PKCS#11.

**Spec:** [Design S6 and S10](../specs/2026-10-23-audit-remediation-design.md); [execution order](2026-10-23-audit-remediation.md).

## Global Constraints

- Keep `ahu` runtime-independent; do not introduce server/runtime/HSM dependencies into it.
- Keep the declared Rust floor `1.85`, the pinned development toolchain `1.97`, and the existing `der` 0.7/0.8 boundary.
- Edge nodes must hold no OCSP or seal private key.
- Use synthetic fixtures and current source windows for admission/production tests.
- Configured trust must never fall back to permissive behavior after a validation error.
- A failed pre-commit operation must preserve the previously committed generation and rollback marks.

## Review Focus

- The same valid seal certificate in PEM and DER must work through actual configured production: B1.
- A valid but mismatched or expired seal certificate must fail before output publication: B1.
- Renaming/copying the same OCSP key must not bypass separation: B2.
- A PKCS#11-shaped signer must propagate signing/encoding errors and cannot conceal reuse behind a different configuration type: B2.
- One-shot, on-demand, rotation, demo, and dual-algorithm paths must apply the same material rules: B1/B2.

---

## Ownership

`seal.rs` owns certificate normalization and seal key/certificate proof. `orchestrate.rs` owns configured material requirements and the loaded-signer dispatch boundary. CLI code adds the missing certificate argument and delegates. Keep the existing library-level `SealKey` variants; no new HSM seal provider or generic signer service is introduced by this work.

### Task 6: B1 — PEM/DER normalization and seal-pair preflight — F08

**Files:** Modify `crates/hoike-sign/src/{seal.rs,orchestrate.rs,lib.rs}`, `crates/hoike-cli/src/main.rs`, `crates/hoike-server/tests/e2e.rs`, `README.md`; create `crates/hoike-sign/tests/seal_materials.rs`.

**Interfaces:** Add `load_seal_certificate(path: &Path) -> hoike_sign::Result<Vec<u8>>` and `validate_seal_materials(key: &SealKey, cert_der: &[u8], now: u64) -> hoike_sign::Result<()>`. Both result aliases are already exported. Preserve `load_seal_materials(&CaConfig) -> Result<(SealKey, Vec<u8>), String>` for orchestration; normalize and validate before returning. Export the two new helpers from `lib.rs` for CLI reuse.

- [ ] **Write** `configured_pem_and_der_seal_certificates_are_equivalent`, `seal_pair_mismatch_fails_before_publication`, and `replacement_expired_seal_certificate_is_rejected`. Use the same fresh certificate encoded in both forms, a second unrelated key/cert, and an expired replacement. Assert:
  ```rust
  assert_eq!(load_seal_certificate(&pem_path).unwrap(), load_seal_certificate(&der_path).unwrap());
  assert!(validate_seal_materials(&key, &other_cert, now).is_err());
  assert!(validate_seal_materials(&key, &expired_cert, now).is_err());
  assert_eq!(std::fs::read(&output_path).unwrap(), prior_bytes);
  ```
  Include ordinary PEM line endings/whitespace and malformed input. A real configured `sign_ca_scope`/on-demand call must produce a seal accepted by the pinned loader for both encodings; comparing decoded bytes alone is insufficient.
- [ ] **Run red:** `cargo test -p hoike-sign --locked --test seal_materials` plus the targeted on-demand server test.
- [ ] **Implement** normalization with the existing der 0.8/X.509 certificate APIs. Validate actual key/certificate binding by creating a CMS seal over `b"hoike:seal-preflight:v1"` and calling existing `ahu::verify_seal_with_pins` with that configured certificate and `now`. Propagate failures before bundle publication. Invoke the same preflight after material reload/rotation and on-demand signing; do not merely cache a startup verdict forever.
- [ ] **Run green:** the focused test, `cargo test -p hoike-sign --locked`, and `cargo test -p hoike-server --locked --test e2e`. Keep the documented `.pem` signer example and prove it works.
- [ ] **Commit:** `fix: normalize and validate configured seal certificates`.

### Task 7: B2 — Explicit production seal pair and loaded-key separation — F07

**Files:** Modify `crates/hoike-sign/src/{orchestrate.rs,seal.rs,lib.rs}`, `crates/hoike-core/src/config.rs`, `crates/hoike-core/tests/config_validation.rs`, `crates/hoike-cli/src/main.rs`, `crates/hoike-sign/tests/seal_materials.rs`, `crates/hoike-server/tests/e2e.rs`, `README.md`, `docs/review-remediation.md`, and affected synthetic/demo fixture setup; create `crates/hoike-cli/tests/sign_materials.rs`.

**Interfaces:** Consumes B1. Adds `--seal-cert PATH` to `hoike sign`; extends the internal `run_sign` parameters with `seal_cert_path: Option<PathBuf>`. Add:

```rust
pub fn ensure_distinct_ecdsa_seal_key<S, Sig>(signer: &S, seal: &SealKey)
    -> hoike_sign::error::Result<()>
where
    S: signature::Signer<Sig>,
    Sig: spki::SignatureBitStringEncoding;
```

Define this helper in `seal.rs` and re-export it from `lib.rs` for the CLI. It applies to the ECDSA branches already using those traits. P-256 software and `Pkcs11SignerBridge` implement them; ML-DSA OCSP is algorithm-distinct from configured P-256 seals. Specify `Sig = p256::ecdsa::DerSignature` for software callers and `Sig = hoike_sign::Pkcs11EcdsaSignature` for the PKCS#11 bridge to avoid ambiguous generic inference.

- [ ] **Write** `production_requires_a_complete_seal_pair`, `same_public_key_under_different_paths_is_rejected`, `demo_generates_distinct_seal_material`, and `loaded_signer_errors_fail_separation_preflight`. Assert:
  ```rust
  assert!(load_seal_materials(&production_without_seal_pair).is_err());
  assert!(ensure_distinct_ecdsa_seal_key::<_, p256::ecdsa::DerSignature>(&ocsp_key, &same_key_seal).is_err());
  assert!(ensure_distinct_ecdsa_seal_key::<_, p256::ecdsa::DerSignature>(&ocsp_key, &independent_seal).is_ok());
  assert!(ensure_distinct_ecdsa_seal_key::<_, p256::ecdsa::DerSignature>(&failing_signer, &independent_seal).is_err());
  assert!(!one_shot_missing_seal_cert.success());
  ```
  Use a software-backed implementation of the existing PKCS#11 signature bridge shape with real ECDSA bytes for unit proof, plus file-key/CLI end-to-end tests. Cover an explicitly half-specified demo pair, same-key symlink/copy aliases, the ECDSA branch of dual-algorithm production, and no modification of the previous output on failure.
- [ ] **Run red:** `cargo test -p hoike-sign --locked --test seal_materials`, `cargo test -p hoike-cli --locked --test sign_materials`, and the targeted config validation cases.
- [ ] **Implement** S6 requirements in config validation, the shared loader, loaded-signer branches, and CLI. Use fallible `try_sign` on the exact S6 separation message; convert with the existing bit-string encoding, parse as a valid DER P-256 signature, and reject if it verifies under the seal public key. Propagate signer/encoding failures. Generate an independent ephemeral pair only for explicit demo mode with neither seal input supplied. Remove implicit reuse and non-demo ephemeral fallback. Enforce the check before invoking production/publishing through every applicable ECDSA backend.
- [ ] **Run green:** `cargo test -p hoike-sign -p hoike-cli --locked`, then `cargo test -p hoike-sign -p hoike-cli --locked --features pkcs11`. Exercise both CLI file signing with a separate pair and explicit demo signing. Preserve positive ML-DSA/dual generation coverage. Hardware qualification remains a deployment test, not a claim from the feature build.
- [ ] **Commit:** `fix: require separate persistent production seal material`.

## Done for plan B

Equivalent PEM/DER inputs succeed through production; invalid pairs and key reuse fail before publication; file/HSM production cannot silently select demo seal material. Document the actual live/seal backend matrix rather than implying HSM/PQ batch signing provides every live/seal combination.
