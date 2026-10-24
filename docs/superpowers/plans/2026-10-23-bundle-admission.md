# Bundle Admission and Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close F01–F06 across trusted loading, CLI/admin verification, state recovery, and enclave installation.

**Architecture:** Extract existing trust enforcement into one core module, restrict serving to supported full/uncompressed inputs, and reuse immutable snapshots as the durable installation authority. Enforce an explicit initialization and offline single-writer workflow.

**Tech Stack:** Rust, existing `ahu` CMS verifier, serde/clap/axum, rustix 1.1.4, std filesystem operations.

**Spec:** [Design S1–S5 and S10](../specs/2026-10-23-audit-remediation-design.md); [execution order](2026-10-23-audit-remediation.md).

## Global Constraints

- Keep `ahu` runtime-independent; do not introduce server/runtime/HSM dependencies into it.
- Keep the declared Rust floor `1.85`, the pinned development toolchain `1.97`, and the existing `der` 0.7/0.8 boundary.
- Edge nodes must hold no OCSP or seal private key.
- Use synthetic fixtures and current source windows for admission/production tests.
- Keep one writer per state directory; use a local filesystem with qualified rename/fsync semantics.
- Configured trust must never fall back to permissive behavior after a validation error.
- A failed pre-commit operation must preserve the previously committed generation and rollback marks.
- Existing valid full, uncompressed bundles and well-formed persisted state remain readable.

## Review Focus

- A demo flag combined with configured trust cannot bypass a corrupt/untrusted/wrong-scope seal: A1.
- CLI or HTTP callers must not receive a success verdict for a skipped authentication step: A2.
- A valid signature on an unsupported delta/compression profile must not authorize serving it: A3.
- Missing individual marks, missing snapshots, and missing state after a prior generation must require recovery: A4.
- Concurrent import and failures before/after descriptor rename must leave an identifiable coherent generation: A5.

---

## Ownership and test fixtures

- New `crates/hoike-core/src/admission.rs`: artifact authentication and serving-profile validation.
- New `crates/hoike-core/src/storage.rs`: durable byte publication and process-scoped writer lock.
- New `crates/hoike-core/src/install.rs`: offline installation transaction; no HTTP or key ownership.
- Existing `router.rs` and `state.rs`: active working set and persistent marks/snapshots.
- Existing CLI/admin handlers: parse options and render verdicts; delegate enforcement.
- Exact existing example paths: `testdata/hoike-test.toml`, `demo/configs/{edge-ecdsa-docker.toml,edge-mldsa-docker.toml,test-edge.toml}`, and the generated TOML blocks in `demo/run.sh`. Include all of these where a task says demo/test TOML fixtures.
- Existing test fixtures in `hoike-server/tests/e2e.rs`, `ahu/tests/seal_verification.rs`, and the audit's P01–P04/P09 define the starting cases. Build synthetic signed bundles with independent keys, fresh certificate/source windows, and explicit pins. The audit's temporary project is reference evidence, not a required dependency of the permanent suite.

Use the native test helpers in each owning crate. Where core integration tests need signed fixtures, add `hoike-sign` only as a **dev-dependency**; Cargo permits a dev-only back-edge. Keep the production dependency graph unchanged and retain the separate minimal `ahu` library check to catch feature-unification masking. Assertions below specify test contracts; setup belongs in the test module, not a new production fixture framework.

### Task 1: A1 — Shared authenticated admission and explicit demo mode — F02

**Files:** Create `crates/hoike-core/src/admission.rs`, `crates/hoike-core/tests/admission.rs`; modify `crates/hoike-core/{Cargo.toml,src/lib.rs,src/config.rs,src/router.rs}`, `Cargo.lock`, affected test setup in `crates/hoike-core/tests/{anti_rollback,bundle_selection,config_validation}.rs` and `crates/hoike-server/tests/{e2e,conformance}.rs`, `README.md`, `SECURITY.md`, and demo/test TOML fixtures.

**Interfaces:** Produces `authenticate_bundle(&Bundle, &StorageConfig, u64) -> Result<ahu::SealVerification>` and `admit_bundle(&Bundle, &StorageConfig, u64) -> Result<AdmissionTrust>` as defined in S1; adds `StorageConfig::allow_unauthenticated_bundles: bool = false`. A3 adds the profile checks to `admit_bundle` later.

- [ ] **Write rejection tests** `missing_trust_rejects_normal_admission` and `configured_trust_never_downgrades_to_demo`. For a structurally valid unsigned bundle and empty trust, assert:
  ```rust
  assert!(admit_bundle(&unsigned, &storage, now).is_err());
  storage.allow_unauthenticated_bundles = true;
  assert!(matches!(admit_bundle(&unsigned, &storage, now), Ok(AdmissionTrust::UnauthenticatedDemo)));
  assert!(authenticate_bundle(&unsigned, &storage, now).is_err());
  ```
  Then configure a valid pin while keeping the demo flag and assert corrupt, wrong-key, and wrong-scope variants all fail. Include a valid directly issued anchor case and dual-scope authorization rejection.
- [ ] **Run red:** `cargo test -p hoike-core --locked --test admission`. First failure may be the missing interface; after extracting the interface, the old permissive behavior must fail the behavioral assertions.
- [ ] **Implement** the S1 signatures by moving `router.rs::verify_bundle_seal` policy logic; retain exact pin/anchor/profile/scope semantics. Have every normal and recovery load call the shared admission function. If trust exists, errors propagate without a demo fallback. Update fixture choices explicitly: trusted tests get real pins; intentionally mocked serving tests opt into demo admission. Do not blanket-enable demo mode in application defaults. If adding the dev dependency, run `cargo check -p hoike-core --tests --offline` once to update the lockfile edge and reject unrelated package-version changes before the locked green run.
- [ ] **Run green:** `cargo test -p hoike-core --locked` and `cargo test -p hoike-server --locked --test e2e --test conformance`. Confirm the existing CMS authorization and failed-reload tests still pass; update public/demo examples in this same task.
- [ ] **Commit** only this task's files: `fix: centralize authenticated bundle admission`, with the attribution trailer from the parent plan.

### Task 2: A2 — Honest CLI/admin verification — F01

**Files:** Modify `crates/hoike-cli/src/{ahu_main.rs,ahu_commands.rs,main.rs}`, `crates/hoike-server/src/admin/bundles.rs`, `webui/src/api/bundles.ts`, `webui/src/pages/Bundles/Inspect.tsx`, `README.md`, `demo/run.sh`, `demo/VERIFICATION.md`; create `crates/hoike-cli/tests/verify.rs` and `crates/hoike-server/tests/bundle_verification.rs`.

**Interfaces:** Consumes A1 `authenticate_bundle`. Change CLI helper to `verify(path: &Path, config_path: Option<&Path>, structure_only: bool, verify_entries: bool) -> Result<()>` using its existing CLI result alias. Admin handler adds `State<AppState>` and the S2 response fields. Retain `verifyBundle(file: File): Promise<VerifyResult>`; change the result contract, not its call shape.

- [ ] **Write subprocess/HTTP tests** `verify_rejects_corrupt_or_untrusted_cms`, `verify_requires_an_explicit_mode`, `structure_only_never_claims_authentication`, `entries_rejects_unchecked_successful_responses`, and `admin_verify_uses_running_trust_policy`. Using real CLI binaries and a freshly sealed fixture:
  ```rust
  assert!(!corrupt_cli_status.success());
  assert!(!no_mode_status.success());
  assert!(structural_stdout.contains("Structure valid; authenticity not checked."));
  assert_eq!(admin_bad["overall_ok"], false);
  assert_eq!(admin_bad["trust_status"], "failed");
  assert_eq!(admin_good["trust_status"], "authenticated");
  ```
  Also reject expired seal certificates and wrong-scope input; verify the state directory is unchanged by both read-only entry points. A test with no embedded responder cert must not let `--entries` claim complete success.
- [ ] **Run red:** `cargo test -p hoike-cli --locked --test verify` and `cargo test -p hoike-server --locked --test bundle_verification`.
- [ ] **Implement** S2 modes, mutually exclusive CLI flags, authenticated admin verdicts, and read-only `hoike check` reuse. Label seal presence in the inspect UI as `Seal present (not verified)` without implying a successful authentication. Successful authenticated CLI output must say that installation eligibility was not checked. Keep parser/transport errors distinct from a failed authentication verdict.
- [ ] **Run green:** repeat the two focused commands; run `npm exec tsc -- --noEmit` from `webui/`. Exercise `--help`, bare verify, authenticated verify, and structure-only in the subprocess tests; update every in-scope documented invocation.
- [ ] **Commit:** `fix: authenticate bundle verification verdicts`.

### Task 3: A3 — Reject unsupported serving profiles — F03 and F06

**Files:** Modify `crates/hoike-core/src/{admission.rs,config.rs}`, `crates/hoike-core/tests/{admission,config_validation}.rs`, `crates/hoike-server/tests/e2e.rs`, `crates/hoike-cli/src/main.rs`, `README.md`, `ahu-format-spec.md`, `hoike-design.md`, and demo/test TOML examples containing `max_chain`.

**Interfaces:** Produces `validate_serving_profile(&ahu::Bundle) -> Result<()>`; A1 `admit_bundle` now calls it. `authenticate_bundle` remains usable for inspecting authenticated deltas without pretending they can be installed. Removes the obsolete `StorageConfig::max_chain` field and its check output.

- [ ] **Write** `signed_orphan_delta_is_not_a_working_set`, `compressed_bundle_is_rejected_before_activation`, and `full_bundle_profile_is_explicit`. Use correctly pinned input with a nonexistent base/chain length 100, Zstd bytes, a dictionary, a full-bundle tombstone, and full-bundle nonzero chain length. Assert:
  ```rust
  assert!(validate_serving_profile(&delta).is_err());
  assert!(validate_serving_profile(&zstd_bundle).is_err());
  assert!(validate_serving_profile(&full_uncompressed).is_ok());
  assert_eq!(std::fs::read(&state_path).unwrap(), original_state);
  ```
  Test an ordinary full bundle with no compression map and one with explicit `none`; both pass. Existing live state stays queryable after a rejected reload. A TOML config still setting `max_chain = 1` fails parsing with migration guidance in the docs.
- [ ] **Run red:** `cargo test -p hoike-core --locked --test admission --test config_validation` and the new targeted e2e reload test.
- [ ] **Implement** the S3 checks at the shared admission boundary. Do not decompress in the HTTP handler or load a delta as a full set. Update the format/README distinction between representable format features and supported serving profiles, including the predecessor requirement for materialized output.
- [ ] **Run green:** focused core tests and `cargo test -p hoike-server --locked --test e2e`. Preserve existing `ahu apply` tests; the core serving restriction must not remove the format/materialization tooling.
- [ ] **Commit:** `fix: reject unsupported bundle serving profiles`.

### Task 4: A4 — Explicit state bootstrap and process exclusion — F04

**Files:** Create `crates/hoike-core/src/storage.rs`, `crates/hoike-core/tests/state_lock.rs`, `crates/hoike-cli/tests/state_initialization.rs`; modify `crates/hoike-core/{Cargo.toml,src/lib.rs,src/state.rs,src/router.rs,src/error.rs,tests/anti_rollback.rs}`, `Cargo.lock`, `crates/hoike-cli/src/main.rs`, `crates/hoike-sign/src/orchestrate.rs` tests, all `ResponderState::load` callers and serving test setup, `demo/run.sh`, `demo/docker-compose.yml`, `demo/README.md`, and `docs/review-remediation.md`.

**Interfaces:** `StateStore::open(&Path) -> Result<Self>` becomes strict/read-existing; add `StateStore::initialize(&Path) -> Result<Self>` and `StateDirectoryLock::acquire(&Path) -> Result<Self>`. Change `ResponderState::load(config: Config, guard: Arc<StateDirectoryLock>) -> Result<Self>` and retain the guard in the responder. The lock guard stores the canonical state directory and open lock file, enabling load/A5 to validate their destination. No lock is reacquired by `sign_ca_scope`'s read-only state access.

- [ ] **Write** `missing_state_after_epoch_99_rejects_epoch_5`, `initialization_refuses_existing_or_orphaned_state`, `incomplete_committed_state_requires_recovery`, and `state_directory_lock_is_process_exclusive`. Assertions include:
  ```rust
  assert!(StateStore::open(&missing_state).is_err());
  assert!(StateStore::initialize(&existing_state).is_err());
  assert_eq!(std::fs::read(&existing_state).unwrap(), before);
  assert!(!second_writer_status.success());
  assert!(writer_after_first_process_exit.success());
  ```
  Use two actual subprocesses with a pipe handshake, not sleep-based timing or PID-file presence. Corrupt JSON, a missing mark for an active snapshot, a mismatched snapshot digest, and a missing snapshot must fail. Add `writer_guard_outlives_listener_owner`: retain a writer/responder clone after dropping its original owner and verify the second process remains excluded until the final clone drops. Retain identical-manifest reload success and changed-manifest/same-epoch rejection.
- [ ] **Run red:** `cargo test -p hoike-core --locked --test anti_rollback --test state_lock`; `cargo test -p hoike-cli --locked --test state_initialization`.
- [ ] **Implement** S4. Add the already-locked rustix version as a direct Unix dependency with `fs`; run `cargo check -p hoike-core --tests --offline` to refresh its lockfile edge and inspect the diff. Acquire the server guard and validate existing state before preflight/signing/source mutations; acquire it for initialization. Keep the guard alive in every active writer through `ResponderState`/`Arc`, including during listener shutdown. Preserve existing valid state without resetting marks. Add `init-state` help and an error pointing to explicit initialization/recovery when open fails. Update tests to initialize only their newly created fixture directories and drop old writer guards before simulating a process restart. Demo preparation may explicitly initialize a newly allocated run directory; demo restart must not initialize a missing existing state file or delete old marks.
- [ ] **Run green:** core/CLI tests above, `cargo test -p hoike-sign --locked`, and `cargo test -p hoike-server --locked --test e2e --test conformance`. Manually exercise the prepared demo's initial start and restart in disposable directories. Both Linux and macOS lock tests are required by D2 before release.
- [ ] **Commit:** `fix: require explicit state initialization and exclusive writers`.

### Task 5: A5 — Offline, recoverable authenticated import — F05

**Files:** Create `crates/hoike-core/src/install.rs`, `crates/hoike-core/tests/installation.rs`, `crates/hoike-cli/tests/import.rs`; modify `crates/hoike-core/src/{lib.rs,config.rs,state.rs,storage.rs,error.rs}`, `crates/hoike-sign/src/orchestrate.rs`, `crates/hoike-cli/src/main.rs`, `README.md`, and `docs/review-remediation.md`.

**Interfaces:** Consumes A1–A4. Adds:

```rust
Config::bundle_destination(&self, label: &str) -> hoike_core::error::Result<PathBuf>;
pub fn write_atomic(path: &Path, bytes: &[u8]) -> hoike_core::error::Result<()>;
pub fn install_bundle(
    config: &Config, label: &str, bytes: &[u8], guard: &StateDirectoryLock,
) -> hoike_core::error::Result<InstallResult>;
```

`InstallResult` is exactly the S5 type. A typed `CoreError::DurabilityUncertain { path: PathBuf, reason: String }` distinguishes directory-fsync failure **after** rename from failure before replacement; it must not be collapsed into a generic “nothing changed” message. State transaction helpers remain crate-private.

- [ ] **Write** `import_rejects_untrusted_input_without_changes`, `import_uses_selected_ca_destination`, `import_rejects_active_writer_and_force`, and `import_recovers_committed_snapshot_when_alias_publish_fails`. Add state-owned fault tests at snapshot write, descriptor pre-rename, descriptor post-rename/fsync, and alias publication. Assert:
  ```rust
  assert_eq!(std::fs::read(&old_destination).unwrap(), old_bytes); // rejected/pre-commit
  assert_eq!(std::fs::read(&state_path).unwrap(), old_state);     // rejected/pre-commit
  assert_eq!(committed.destination, configured_destination);
  assert!(committed.publication_warning.is_some());              // post-commit alias failure
  assert_eq!(restarted_epoch, new_epoch);                        // recover committed snapshot
  ```
  Also cover another label remaining intact, unknown/duplicate destination labels, wrong guard directory, rollback, same-epoch fork, missing predecessor, source-path replacement after the input buffer was read, and retry of an identical committed import. Indeterminate fsync returns the typed error; after reopen, state and snapshots must be coherent, with no claimed rollback.
- [ ] **Run red:** `cargo test -p hoike-core --locked --test installation` and `cargo test -p hoike-cli --locked --test import`. Add unit fault tests in the owning storage/state modules using test-only injection, not a production filesystem abstraction.
- [ ] **Implement** S5's exact commit order. Consolidate durable write code in `storage.rs`, and make the signer delegate to it and to `Config::bundle_destination`. Preserve existing snapshots for non-target labels in the installation candidate; full reload explicitly builds a replacement working set. The CLI reads once, acquires/validates the writer guard, invokes installation, prints a committed warning when appropriate, and never suggests SIGHUP. Remove `--force`; normal import always authenticates, even with the serving demo flag.
- [ ] **Run green:** focused import/installation tests, `cargo test -p hoike-core --locked`, and `cargo test -p hoike-sign --locked publication_tests`. Re-run existing failed-multi-bundle-reload/restart tests after the transaction-helper change. Check that a running server excludes offline import and that restarting after a committed import serves the selected generation.
- [ ] **Commit:** `fix: install enclave bundles through authenticated durable state`.

## Done for plan A

All six findings have owned regressions, shared policy covers normal/recovery/verification/import entry points, and migration instructions match the actual commands. Finish with the integration gates in plan D; do not claim closure solely because the old audit probes still observe their old behavior.
