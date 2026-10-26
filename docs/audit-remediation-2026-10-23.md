# October 2026 audit remediation — closure ledger

This ledger closes the twelve-finding October 2026 security audit of the hoike
OCSP responder (worktree branch `fix/audit-remediation`, private tracker
GHSA-7vcp-p3rm-jf24). It records, for each finding F01–F12: the corrected
behavior, the responsible task and commits, the owned regression tests, the
migration actions operators must take, and the integrated release-evidence
commands with their actual results. It complements — and does not replace —
the [September 29-finding remediation ledger](review-remediation.md) and the
[original audit](promise-audit-2026-10-23.md), which are preserved as
historical evidence.

**Status: implemented and locally evidenced; not deployed, not certified.**
No production deployment, CC/FIPS validation, or independent security review
follows from this document alone. Live HSM, live 389 DS, real power-loss
recovery, and multi-host qualification were **not** exercised (see
[Remaining qualification](#remaining-qualification-not-performed)).

Branch baseline: `c866700` (audited showcase state). Closure range:
`d143608..` (this document's commit). All commands below ran on macOS
(aarch64, Darwin) with the pinned toolchain `1.97` unless noted; Linux
coverage of the state-machine suites is wired into CI (both platforms
required before release).

---

## Finding closure table

| ID | Corrected behavior | Task / commits | Owned regression tests (file::name) |
|----|--------------------|----------------|--------------------------------------|
| **F01** | `ahu verify` requires an explicit mode. `--config` authenticates the CMS seal under configured pins/anchors and scope authorizations; `--structure-only` checks structure/digests and prints `Structure valid; authenticity not checked.`; bare invocation fails. `hoike check` authenticates without creating or changing state. The admin verify route reports `trust_status`/`trust_error`/`signer_sha256` and returns `overall_ok: false` for untrusted input. | A2 / `61a3509` | `crates/hoike-cli/tests/verify.rs::verify_rejects_corrupt_or_untrusted_cms`, `::verify_requires_an_explicit_mode`, `::structure_only_never_claims_authentication`, `::entries_rejects_unchecked_successful_responses`, `::entries_report_unsigned_errors_separately_and_verify_embedded_keys`, `::check_authenticates_without_creating_or_changing_state`; `crates/hoike-server/tests/bundle_verification.rs::admin_verify_uses_running_trust_policy`, `::admin_demo_mode_cannot_claim_authentication` |
| **F02** | Bundle admission is fail-closed: with no configured trust, normal admission is an error; only explicit `storage.allow_unauthenticated_bundles = true` (with no trust/authorization configuration) enables demo admission, and configured trust never downgrades to it. Decoded manifests are bound to the authenticated bytes. | A1 / `d12b6c3`, `ceae9d0` | `crates/hoike-core/tests/admission.rs::missing_trust_rejects_normal_admission`, `::configured_trust_never_downgrades_to_demo`, `::embedded_signer_is_not_trust_without_configuration`, `::authorizations_alone_never_enable_demo_admission`, `::decoded_digests_cannot_authenticate_modified_contents`, `::decoded_authorization_metadata_cannot_override_signed_identity`, `::decoded_scope_removal_cannot_bypass_all_scope_authorizations`, `::normal_and_recovery_loads_require_trust`, `::failed_authentication_keeps_committed_state_and_recovery_rechecks_trust` |
| **F03** | The serving loader rejects unsupported serving profiles: signed orphan deltas, delta chains, tombstones, and compressed (Zstd) bundles are refused before any durable state change. The never-implemented `storage.max_chain` setting is removed; configurations that set it fail to parse. | A3 / `fd176e2`, `57f2e3e` | `crates/hoike-core/tests/admission.rs::signed_orphan_delta_is_not_a_working_set`, `::compressed_bundle_is_rejected_before_activation`, `::full_bundle_profile_is_explicit`; `crates/hoike-core/tests/config_validation.rs::max_chain_is_no_longer_a_configurable_field` |
| **F04** | Losing the state file no longer silently resets anti-rollback protection. `StateStore::open` is strict (missing/corrupt/incoherent state is a recovery error), `hoike init-state` is the explicit one-time bootstrap (no `--force`), and one writer per state directory is enforced with an OS exclusive `flock` held for the full process lifetime. | A4 / `c2ad580` | `crates/hoike-core/tests/state_lock.rs::missing_state_after_epoch_99_rejects_epoch_5`, `::initialization_refuses_existing_or_orphaned_state`, `::incomplete_committed_state_requires_recovery`, `::state_directory_lock_is_process_exclusive`, `::writer_guard_outlives_listener_owner` (real subprocesses); `crates/hoike-cli/tests/state_initialization.rs::init_state_initializes_once_and_never_resets`, `::serve_requires_explicit_state_initialization`, `::serve_is_process_exclusive_and_restart_preserves_state`, `::check_stays_read_only_without_state` |
| **F05** | `hoike import --bundle PATH --ca LABEL --config PATH` is an offline, recoverable, authenticated installation: label-selected destination, single-read source, immutable snapshot → atomic state-descriptor commit → configured-path publication, with typed `DurabilityUncertain` and `publication_warning` outcomes. `--force` is removed; a running server excludes the import via the writer lock. | A5 / `5b654ec` | `crates/hoike-core/tests/installation.rs::import_rejects_untrusted_input_without_changes`, `::import_uses_selected_ca_destination`, `::import_recovers_committed_snapshot_when_alias_publish_fails`, `::install_always_authenticates_even_with_demo_serving_flag`, `::install_requires_an_initialized_state_directory`, `::retrying_an_identical_committed_import_is_idempotent`, `::single_label_install_preserves_other_labels` (plus commit-order fault injection in `install::fault_tests`/`storage::tests`); `crates/hoike-cli/tests/import.rs::import_requires_a_label_and_rejects_unknown_labels`, `::import_rejects_untrusted_input_without_changes`, `::import_requires_initialized_state`, `::import_rejects_active_writer_and_force`, `::import_offline_install_and_restart_serves_selected_generation`, `::import_reports_committed_warning_when_publication_fails_and_retry_repairs` |
| **F06** | Zstd-marked payloads are never served as raw compressed bytes: compression is an ahu *format* feature, and admission rejects compressed bundles before activation (same gate as F03). | A3 / `fd176e2`, `57f2e3e` | `crates/hoike-core/tests/admission.rs::compressed_bundle_is_rejected_before_activation` |
| **F07** | Seal/OCSP key separation is enforced: signer/combined CAs with persistent signing keys must configure a complete `seal_key` + `seal_cert` pair (half-pairs and implicit OCSP-key reuse are errors); ECDSA signers prove separation by signing a domain-separated message verified under the seal public key (same key under different paths/symlinks is rejected); demo signing generates a distinct ephemeral seal pair. | B2 / `ed81bfc`, `0b49fa6` | `crates/hoike-cli/tests/sign_materials.rs::one_shot_missing_seal_cert_fails_before_production`, `::one_shot_half_configured_seal_pair_is_rejected`, `::one_shot_file_signing_with_separate_pair_succeeds`, `::one_shot_same_key_under_different_paths_is_rejected`, `::one_shot_demo_key_generates_distinct_seal_material`, `::one_shot_dual_algorithm_classical_signer_is_separation_checked`; `crates/hoike-sign/tests/seal_materials.rs::production_requires_a_complete_seal_pair`, `::same_public_key_under_different_paths_is_rejected`, `::demo_generates_distinct_seal_material`, `::loaded_signer_errors_fail_separation_preflight`; `crates/hoike-core/tests/config_validation.rs::seal_pair_must_be_complete_for_production_and_optional_only_in_demo` |
| **F08** | Configured PEM `seal_cert` material is normalized (PEM or DER) and the key/certificate pair is proven with a real CMS preflight seal on every load/signing pass — the documented PEM example now works, and a mismatched or expired replacement fails closed before publication. | B1 / `a3616a3` | `crates/hoike-sign/tests/seal_materials.rs::configured_pem_and_der_seal_certificates_are_equivalent`, `::seal_pair_mismatch_fails_before_publication`, `::replacement_expired_seal_certificate_is_rejected` |
| **F09** | Gossip authentication is an explicit policy: `gossip.auth_mode = "required"` (default) or `"permissive"`, with per-node Ed25519 identities authorized through `gossip.peer_identities` (legacy `peer_keys` rejected). Required mode drops unsigned/unknown/forged broadcasts; permissive (rollout) accepts unsigned legacy but still rejects forged/unknown signatures. Invalid enabled configuration aborts startup and fails `hoike check`. | C2 / `f5e2829`, `d62ff1b` | `crates/hoike-gossip/src/crypto.rs::tests::permissive_accepts_known_signed_and_unsigned_peers`, `::permissive_rejects_unknown_and_forged_signed_frames`, `::required_rejects_unsigned_and_missing_identity`, `::local_identity_conflict_rejects`, `::authenticated_peer_cannot_claim_another_origin`; `crates/hoike-gossip/src/node.rs::tests::loopback_transition_permissive_signing_to_required`; `crates/hoike-cli/tests/gossip_startup.rs::enabled_gossip_key_failure_aborts_startup`, `::disabled_gossip_requires_no_key_material`, `::partitioned_gossip_peers_never_stop_ocsp_serving`, `::check_reports_effective_gossip_auth_mode`; `crates/hoike-core/tests/config_validation.rs::gossip_auth_mode_defaults_to_required_and_rejects_unknown_values`, `::gossip_legacy_peer_keys_rejected` |
| **F10** | Forwarding trust is per CA and startup-validated: `forward_ca` pins a private PEM root bundle for that CA's client only (built-in WebPKI roots disabled, hostname/validity checking kept on); a CA without `forward_ca` uses the bundled WebPKI roots — never the system trust store. Unreadable/empty/malformed roots, a root on a non-HTTPS target, or duplicate labels fail startup and `hoike check`. | C3 / `bed0bde` | `crates/hoike-server/tests/forward_tls.rs::configured_private_root_succeeds`, `::private_roots_are_isolated_per_ca`, `::wrong_hostname_and_wrong_root_reject`, `::invalid_root_configuration_fails_startup`, `::forwarding_handler_serves_authenticated_upstream_response` (real loopback TLS listeners); `crates/hoike-server/tests/e2e.rs` handlers regressions `cleartext_forwarding_requires_explicit_opt_in`, `redirects_are_not_followed`, `chunked_response_is_rejected_before_unbounded_buffering` |
| **F11** | `GenerationAnnouncement`s carry the **manifest** digest, not the index digest, so metadata-only generation changes are distinguishable. | C1 / `53ef76f` | `crates/hoike-server/tests/gossip_announcements.rs::announcement_identifies_manifest_not_index` (two valid bundles with identical index bytes and different manifest metadata) |
| **F12** | The wire specification matches produced bundles: header `FORMAT_MAJOR = 0`/`FORMAT_MINOR = 1`, CBOR `format_version = 1`, `id-data`, documented discriminator layout; independently hand-assembled golden vectors decode. | D1 / `b7de3f4` | `crates/ahu/tests/wire_profile.rs::seal_verified::independent_0_1_vectors_decode`, `::dual_algorithm_pairs_follow_documented_order`, `::seal_verified::cms_profile_attributes_are_required` (fixtures in `testdata/wire-profile-0.1/`) |

## Migration contract validation

The configuration/state migration is executable and covered by the existing
A/B subprocess suites (no mirrored second suite). Exact names, all passing in
the integrated run below:

- **Strict config + persistent independent seal pair + existing state succeeds**:
  `sign_materials.rs::one_shot_file_signing_with_separate_pair_succeeds`,
  `seal_materials.rs::configured_pem_and_der_seal_certificates_are_equivalent`,
  `state_initialization.rs::serve_is_process_exclusive_and_restart_preserves_state`,
  `anti_rollback.rs::identical_chained_bundle_passes_continuity_after_restart`.
- **New empty state fails until `init-state`**:
  `state_initialization.rs::serve_requires_explicit_state_initialization`,
  `state_lock.rs::missing_state_after_epoch_99_rejects_epoch_5`.
- **Valid state restarts unchanged**:
  `state_initialization.rs::serve_is_process_exclusive_and_restart_preserves_state`,
  `anti_rollback.rs::same_epoch_identical_bundle_reload_allowed`,
  `anti_rollback.rs::identical_chained_bundle_passes_continuity_after_restart`.
- **Import succeeds offline and fails under an active writer**:
  `import.rs::import_offline_install_and_restart_serves_selected_generation`,
  `import.rs::import_rejects_active_writer_and_force`.
- **Legacy `max_chain` produces an actionable failure**:
  `config_validation.rs::max_chain_is_no_longer_a_configurable_field`
  (unknown-field parse error; migration action: remove the line).
- **`--force` and bare `ahu verify` produce actionable failures**:
  `import.rs::import_rejects_active_writer_and_force` (no `--force` escape hatch),
  `verify.rs::verify_requires_an_explicit_mode` (mode selection guidance).
- **Gossip `peer_keys` migration**:
  `config_validation.rs::gossip_legacy_peer_keys_rejected` (migration action:
  replace with `peer_identities` named mappings).

Operator migration actions are consolidated in
[review-remediation.md](review-remediation.md) (CRL issuer authorization, CMS
pins/anchors/authorizations, seal-pair requirement, explicit `init-state`,
offline import, per-CA forwarding roots, gossip rollout sequence, delta
output).

## Integrated release evidence

All commands were run from the closure commit on macOS (aarch64) with the
pinned `1.97` toolchain. Full transcripts are kept in the private plan
workspace (`.superpowers/sdd/2026-10-23-audit-remediation/logs/task-12/`);
summaries:

| Command | Result |
|---------|--------|
| `npm ci --no-audit --no-fund` (webui/) | exit 0 (193 packages; install-script warnings recorded, pre-existing) |
| `npm exec tsc -- --noEmit` (webui/) | exit 0 |
| `npm run build` (webui/) | exit 0 (vite production build → `webui/dist/`) |
| `npm run lint` | **not run** — the project has no ESLint configuration (known tooling gap; not claimed as passing) |
| `cargo test --workspace --locked` | **305 passed, 0 failed** (34 result sections, 0 ignored) |
| `cargo test --workspace --locked --features tls,metrics,pkcs11,dogtag-sync` | **332 passed, 0 failed** (34 result sections, 0 ignored) |
| `cargo check -p ahu --no-default-features --lib --locked` | exit 0 |
| `cargo test -p ahu --no-default-features --locked` | **55 passed, 0 failed** |
| `cargo test -p ahu --release --locked --test integration overflowing_entry_offsets_never_panic_in_heap_or_mmap` | **1 passed** (7 filtered out) |
| `cargo test -p hoike-cli --locked --test state_initialization --test import --test verify --test sign_materials --test gossip_startup` | **31 passed, 0 failed** (migration-contract A/B subprocess suites) |
| `cargo test -p hoike-core --locked --test state_lock --test anti_rollback --test installation` | **26 passed, 0 failed** (platform state-machine suites, macOS leg) |
| `cargo test -p hoike-core --locked --test config_validation` | **16 passed, 0 failed** |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | exit 0 after three fixes: the ledgered `map_clone` in `crates/hoike-cli/tests/sign_materials.rs` (→ `extra.to_vec()`), a latent `unnecessary_cast` in feature-gated `crates/hoike-sign/src/dogtag_sync.rs` (previously outside the non-all-features gate), and a `needless_borrow` that surfaced in `check_bundles` after the selection/check split |
| `cargo fmt --all -- --check` | exit 0 (clean) |
| `git diff --check` | exit 0 (clean) |
| `demo/run.sh` (disposable state, fresh CRL + seal pair) | all stages passed — see below |

**Scripted demo run** (macOS, release binaries built from the closure source;
transcript `demo-run.log`): fresh fixtures (CRL `thisUpdate` Oct 26 2026,
fresh P-256 seal pair); ECDSA + ML-DSA bundles signed with `--demo-key` OCSP
keys and the persistent seal pair; both bundles **authenticated** against
`configs/trusted-edge.toml` (`CMS seal: authenticated`, signer SHA-256
`d55ca07f…`); tampered bundle **rejected** (data digest mismatch); wrong-pin
verification **rejected** (`signer certificate does not match an explicit
pin`); `hoike check` reported `Seal: authenticated`; `hoike init-state` then
`serve` admitted the bundle with `trust=Authenticated`; queries returned
GOOD (serial 01, dual CertID), REVOKED/KeyCompromise (serial 0A), and
Unauthorized (serial FF, unsigned 5-byte response); the edge was stopped and
the offline `hoike import` of the epoch-0 bundle was **rejected** with
`Import failed: epoch rollback: scope hoike-cli:942ed9ca26d9c8eb epoch 0 <= high-water 1`;
the restarted edge served the identical committed generation (GOOD after
restart); the ML-DSA edge served an `ml-dsa-65` response (3309-byte
signature) under `--prefer ml-dsa-65,ecdsa-p256`.

## CI wiring

GitHub Actions (`.github/workflows/ci.yml`) is authoritative:

- The `check` job now builds the web UI first (`npm ci`, `tsc --noEmit`,
  `npm run build`) and then runs **all-features** clippy
  (`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`),
  so the `embed-webui` feature always compiles against a real UI build.
- A new `platform` job runs
  `cargo test -p hoike-core --locked --test state_lock --test anti_rollback --test installation`
  on a **Linux + macOS matrix** (flock/strict-reopen/durable-install behavior
  is kernel-dependent; both platforms are required before release), with the
  normal C/CMake prerequisites on Linux.
- Existing default/feature test suites, the release-mode parser regression,
  and the minimal-library (`ahu --no-default-features`) checks are unchanged;
  the default and feature suites discover the new integration tests without
  ignored cases.
- The UI `npm run lint` cannot run (no ESLint configuration in the project);
  it is intentionally **not** wired into CI and is not claimed as passing.

The GitLab mirror (`.gitlab-ci.yml`) gained the equivalent Linux
`state-platform-tests` job. The UI-dependent all-features clippy gate and the
macOS leg run on GitHub Actions only. Nothing was pushed; both files await
the normal review gate.

## Residual must-fix items closed by this task (D2)

1. **`map_clone` clippy warning** at `crates/hoike-cli/tests/sign_materials.rs:199`
   (introduced by task 7's `ed81bfc`): fixed — the `.iter().map(|s| *s)`
   collection became `extra.to_vec()`; the integrated all-features clippy gate
   passes with `-D warnings` (two further lints surfaced and were fixed during
   the same gate: a latent `unnecessary_cast` in feature-gated
   `dogtag_sync.rs`, and a `needless_borrow` after the `hoike check` label
   split).
2. **foca 2.0.0 `rust-version = 1.88` vs the declared workspace floor 1.85**:
   the floor stays `1.85` (contract constraint) and is now documented as
   **source-level for first-party code**; building `hoike-gossip` requires
   rustc ≥ 1.88 in practice because cargo enforces foca's declared
   requirement against the invoking toolchain. Documented in the workspace
   `Cargo.toml` and `AGENTS.md`; the pinned development toolchain remains
   1.97.
3. **`docs/security-target/hoike-st-tls-fp-v1.1.md` forward_ca gap described
   as open**: updated to the implemented per-CA forwarding roots (F10), with
   the remaining partials (ciphersuite pinning, reference-identifier
   assertion, revocation checking) kept explicit.
4. **`demo/VERIFICATION.md` referenced nonexistent `configs/trusted-edge.toml`**:
   the file is now real — `run.sh` generates it with a pin to the per-run
   demo seal certificate, and the demo signs its bundles with a persistent
   seal pair so authenticated verification (success, tampered, and wrong-pin
   failure modes) actually executes.
5. **`hoike check` config errors labeled `Bundle: FAIL`**: bundle *selection*
   (configuration) errors now print `Bundle selection: FAIL — …`; per-bundle
   verification failures keep `Bundle: FAIL`.
6. **Task 6's missing verbose evidence logs**: this ledger's evidence section
   records actual command/output for every gate (transcripts under
   `logs/task-12/`), replacing the earlier task's unverifiable inline claims.

## Public claims corrected in this pass

- **Broadcast authentication exists; SWIM/confidentiality/pull/fencing do
  not** — README, SECURITY.md, design doc, gap matrix, and ST files state the
  boundary: Ed25519-signed broadcasts with named-origin authorization; no
  payload encryption; foca SWIM liveness not authenticated; no automatic
  bundle pull-on-announce; writer exclusion is single-host flock, not
  distributed fencing.
- **Trust is bounded** — pins or direct-issued CA anchors only; no general
  PKIX path building (unchanged from earlier tasks, restated where stale).
- **Live signing and configured seals are software P-256** — the
  live/seal backend matrix is stated as such (batch OCSP also covers ECDSA
  PKCS#11 and ML-DSA software keys).
- **Batching/mmap are library support, not deployed hot-path support** —
  README, design doc §5 (implementation-status note), security-target README,
  and demo docs now say the serving path loads bundles into memory;
  `ahu::MmapBundle` is library support.
- **Legacy `peer_keys`, system-root advice, and FIPS-by-build-flags claims
  corrected** — forwarding uses per-CA private roots or bundled WebPKI roots
  (never the system trust store); FIPS wording everywhere now states that
  `aws-lc-rs/fips` + `rustls/fips` flags are necessary but not sufficient
  (validation covers module build, boundary, and environment); SECURITY.md's
  broken references to nonexistent `docs/compliance/` and a "FIPS status page
  on hoike.dev" were replaced with links to the real security-target package.
- Fixed test-count claims (147 tests / 175 test functions / LoC) were removed
  in favor of suite references.

## Remaining qualification (NOT performed)

- **Live HSM/PKCS#11** against real hardware (feature tests use the software
  bridge and encoding checks only).
- **Live 389 DS** syncrepl integration: delete/present/restart/stale-cookie
  behavior against a real directory (the reducer is regression-tested in
  isolation).
- **Real power-loss / storage-fault recovery** on the intended filesystem
  (fault injection is thread-local, not a storage qualification).
- **Multi-host / distributed qualification**: gossip is loopback-tested only;
  writer fencing is single-host; no multi-node bundle distribution exists
  (no pull-on-announce).
- **mmap serving is library support only** (`ahu::MmapBundle`); it is not
  deployed in the responder hot path and no hot-path performance claim is
  made. **Pending:** the user's pre-existing untracked presentation
  (`demo/presentation/hoike-ciso-briefing.html`, not present in this
  execution worktree) still says "Keyless edge nodes verify the seal, mmap
  the bundle, and serve responses verbatim" — recorded as **pending**,
  not fixed; it must be corrected wherever that presentation is maintained.
- **ESLint** for the web UI cannot run (no configuration file exists); UI
  lint is not claimed.
- A fresh independent security review of the closure range.

## Release outcome

All twelve findings are closed with owned regressions and integrated local
evidence on macOS; Linux execution of the state-machine suites is wired into
CI but has not yet been observed on this branch (CI was not pushed). The
branch is eligible for whole-branch review. No release date, production
deployment, or certification claim follows from this document.
