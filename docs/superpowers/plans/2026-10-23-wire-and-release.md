# Wire Profile and Release Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close F12 and finish all 12 findings with tested migration, accurate claims, and recorded evidence.

**Architecture:** Freeze the existing draft wire encoding instead of making an unnecessary incompatible format change. Treat documentation, configuration examples, and the actual CLI/server integration tests as part of each delivered contract.

**Tech Stack:** Existing Rust parsers/verifiers, independent byte fixtures, Cargo checks, existing web UI TypeScript/Vite build, GitHub/GitLab CI.

**Spec:** [Design S9–S10](../specs/2026-10-23-audit-remediation-design.md); [execution order](2026-10-23-audit-remediation.md).

## Global Constraints

- Keep `ahu` runtime-independent; do not introduce server/runtime/HSM dependencies into it.
- Keep the declared Rust floor `1.85`, the pinned development toolchain `1.97`, and the existing `der` 0.7/0.8 boundary.
- Edge nodes must hold no OCSP or seal private key.
- Use synthetic fixtures and current source windows for admission/production tests.
- A failed pre-commit operation must preserve the previously committed generation and rollback marks.
- Existing valid full, uncompressed bundles and well-formed persisted state remain readable.

## Review Focus

- Package version, header 0.1, and CBOR format version 1 must not be confused in independent vectors: D1.
- Same-key/different-discriminator records must decode, while duplicate key/discriminator pairs reject: D1.
- CMS content-type attributes must remain consistent with the documented detached `id-data` profile: D1.
- Identical-epoch restart must remain safe while same-epoch changed contents reject: D1 checks A4/existing regression evidence.
- Published command/config examples must work with the new trust/init/key defaults, including repeat startup: D2.

---

### Task 11: D1 — Document and freeze the actual wire profile — F12

**Files:** Modify `ahu-format-spec.md`, `hoike-design.md`, `crates/ahu/tests/{integration.rs,seal_verification.rs}`, and `crates/ahu/src/index.rs` documentation; create `crates/ahu/tests/wire_profile.rs`, `testdata/wire-profile-0.1/README.md`, and independently encoded `testdata/wire-profile-0.1/{minimal-full,dual-algorithm}.ahu` fixtures.

**Interfaces:** Preserve existing `FileHeader`, `IndexRecord`, `Bundle`, CMS verifier APIs, and emitted bytes. The specification is corrected to header `FORMAT_MAJOR = 0`, `FORMAT_MINOR = 1`, CBOR `format_version = 1`, `id-data`, and the existing discriminator layout. No allocation of a fictitious OID or unannounced version bump.

- [ ] **Write** `independent_0_1_vectors_decode`, `dual_algorithm_pairs_follow_documented_order`, and `cms_profile_attributes_are_required`. Commit fixture bytes produced independently of `BundleBuilder`, with decoded field values, SHA-256 checksums, and generation instructions in the fixture README. Use a fixed test verification time within the recorded seal-certificate window only for these immutable vectors. Assert:
  ```rust
  assert_eq!((bundle.header.format_major, bundle.header.format_minor), (0, 1));
  assert_eq!(bundle.manifest.format_version, 1);
  assert!(duplicate_pair_validation.is_err());
  assert!(distinct_discriminator_validation.is_ok());
  assert!(ahu::verify_seal(&manifest, &mismatched_content_type_seal).is_err());
  ```
  Also independently inspect the bytes at index offset +46 and the CMS content type. Retain existing tampered-signature/digest tests; do not make expected vectors by round-tripping through the same writer under test.
- [ ] **Check the current contract:** `cargo test -p ahu --locked --test wire_profile --test integration --test seal_verification`. Many byte-contract assertions should already pass; this task fixes documentation drift, so do not alter correct implementation just to manufacture a red test. A new negative assertion fails only if it exposes an actual profile-enforcement gap; handle that as a scoped regression.
- [ ] **Update** S9's normative text, duplicate-pair rules, discriminator/reserved-value behavior, and identical-generation reload exception. State that index decoding preserves unknown `u16` discriminators and includes them in ordering without implying support for their signature algorithm. Separate optional format representations from S3's serving profile. Explain materialized-output predecessor continuity and remove the contradictory “partial delta without base” serving implication.
- [ ] **Verify:** repeat the focused ahu commands; run `cargo test -p hoike-core --locked --test anti_rollback` for restart/fork behavior. Compare actual fixture checksums and decoded fields with the published README. `cargo check -p ahu --no-default-features --lib --locked` must pass independently of dev-feature unification.
- [ ] **Commit:** `docs: specify the implemented ahu 0.1 wire profile` with the supporting compatibility fixtures/tests.

### Task 12: D2 — Migration, claims, and integrated release evidence

**Files:** Modify `README.md`, `SECURITY.md`, `AGENTS.md` (and its `CLAUDE.md` alias only if it is a distinct file), `hoike-design.md`, `docs/review-remediation.md`, `docs/niap-ppca-gap-matrix.md`, `docs/security-target/{README.md,hoike-st-ppca-v2.1.md,hoike-st-app-pp-v1.4.md,hoike-st-tls-fp-v1.1.md}`, `demo/{README.md,VERIFICATION.md,run.sh,docker-compose.yml}`, affected checked-in TOML examples, `.github/workflows/ci.yml`, and `.gitlab-ci.yml`; create `docs/audit-remediation-2026-10-23.md`.

**Interfaces:** Consumes completed A1–C3 and D1. No new runtime surface. The new ledger records F01–F12, responsible task/commit, regression test names, commands/results, migration actions, and remaining qualification.

- [ ] **Validate the migration contract** against the current CLI and fresh synthetic fixtures: strict config + persistent independent seal pair + existing state succeeds; new empty state fails until `init-state`; valid state restarts unchanged; import succeeds offline and fails under an active writer; legacy `max_chain`, `--force`, and bare `ahu verify` produce actionable failures. These are the existing A/B subprocess tests, not a second mirrored test suite. Record exact test names in the ledger.
- [ ] **Update public claims**: broadcast authentication exists; SWIM/confidentiality/pull/fencing do not; trust is bounded; live signing is software P-256; configured seals are software P-256; batching/mmap library support is not deployed hot-path support. Correct legacy `peer_keys`, system-root advice, and claims that FIPS is solved by build flags alone. Preserve the historical audit as historical evidence and link to the closure ledger. Inspect the user's pre-existing untracked presentation before editing; if it has not been supplied to the execution worktree, record its mmap wording as pending rather than claiming it fixed.
- [ ] **Wire platform evidence into CI** using the existing jobs. Default and feature suites must discover new integration tests without ignored cases. Add a Linux/macOS job or matrix for `cargo test -p hoike-core --locked --test state_lock --test anti_rollback --test installation`, including the normal C/CMake prerequisites. Preserve existing release parser and minimal-library checks. Keep the embedded-UI build dependent on an actual UI build. Update GitLab equivalents where this repository uses them; do not publish CI or content changes before the normal review gate.
- [ ] **Run the integrated checks** after all source changes are complete:
  ```sh
  cargo test --workspace --locked
  cargo test --workspace --locked --features tls,metrics,pkcs11,dogtag-sync
  cargo check -p ahu --no-default-features --lib --locked
  cargo test -p ahu --no-default-features --locked
  cargo test -p ahu --release --locked --test integration overflowing_entry_offsets_never_panic_in_heap_or_mmap
  cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
  cargo fmt --all -- --check
  git diff --check
  ```
  Before all-feature checks, run `npm ci`, `npm exec tsc -- --noEmit`, and `npm run build` from `webui/` so `embed-webui` has actual build output. Run the updated demo in disposable state with fresh CRLs and verify the documented OCSP queries, restart, and rollback rejection. Use `--offline` only where dependencies are already available; do not treat an offline dependency-resolution failure as an implementation failure. The currently missing ESLint configuration is a separate known tooling issue; do not record UI lint as passing unless it actually runs.
- [ ] **Review evidence and commit:** ensure every finding has its intended corrected assertion and actual successful command output; record any unexecuted platform/hardware qualifications explicitly. Commit the focused closure changes as `docs: record audit remediation and migration evidence`. Obtain a whole-branch review before merge; live HSM/389 DS, real power-loss, and broader independent-client qualification remain deployment work unless actually exercised.

## Release outcome

The release is eligible for review when all 12 finding closures are evidenced, examples reflect supported behavior, and configuration/state migrations are executable. No release date or production/certification claim follows from this plan alone.
