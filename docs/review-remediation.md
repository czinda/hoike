# September 2026 bug and security remediation

This ledger tracks the 29 findings reviewed against commit `912989b32b5f01289865669e76790ce2b8b72cf7`. It describes the remediation branch, not a deployed or independently certified release. The original review and comprehensive plan remain review artifacts; this document records the implemented behavior and remaining validation work.

## Finding ledger

“Regression” identifies executable coverage in this repository. An implemented change is not automatically production-qualified. Test names are supplied so results can be reproduced without relying on historic total test counts.

| ID | Finding and implemented change | Evidence / qualification |
|---|---|---|
| 1 | Live extraction matches the complete requested CertID; missing/duplicate/Unknown evidence cannot become Good. | `e2e::batched_live_responses_preserve_requested_status_and_source_window`; actual decoded signed statuses. |
| 2 | A failed CMS signature is an error; loader admission enforces it. | `seal_verification::mismatched_embedded_key_is_an_error_not_false_success`; `e2e::responder_load_enforces_cms_integrity_anchor_and_scope_authorization`. |
| 3 | Explicit signer-certificate pins and a bounded direct-issuer CA-anchor policy authenticate seals; optional producer/CA authorization further restricts them. | `seal_verification::authenticates_direct_issuer_and_rejects_wrong_anchor_and_expiry`, `explicit_pin_accepts_demo_cert_but_does_not_trust_another_key`; loader regression. Not general PKIX path building. |
| 4 | Explicit TLS/mTLS requirements fail startup in a binary lacking TLS support. | `configured_tls_never_degrades_to_plaintext` config regression; actual TLS handshake/deployment qualification remains a release check. |
| 5 | Live signing rejects stale/future source evidence and caps nextUpdate to source validity. | `e2e::live_signing_rejects_stale_or_future_source`; batched live regression. |
| 6 | Dogtag stages UUID-based updates/deletes/present sets and replaces the population on full refresh. Excluded statuses remove positive issuance. | `dogtag_sync::tests::sync_reducer_deletes_replaces_and_prunes_only_staged_state`; live 389 DS integration pending. |
| 7 | Source-bound snapshot and cookie are persisted together with atomic replacement; legacy cookie-only state cannot resume an empty population. Only syncRefreshRequired triggers full retry. | `checkpoint_restores_population_and_rejects_foreign_or_legacy_cookie`; live restart/stale-cookie integration pending. |
| 8 | CRLs require an independently provisioned issuer certificate, valid issuer/key binding and cryptographic signature, valid times, and supported extensions/semantics. | `crl::tests::authenticated_crl_accepts_only_matching_issuer_and_signature`, `authenticated_crl_rejects_delta_semantics`, `rsa_crls_verify_sha256_sha384_sha512_and_reject_tampering`; signed CRL endpoint fixture. |
| 9 | Generation rejects expired/missing/inconsistent source windows, caps jitter and validity, and uses checked/widened arithmetic. Both generation paths apply the policy. | `generate::tests::source_expiry_caps_every_signed_entry_even_with_large_jitter`, `expired_source_is_rejected_before_signing`; `source::tests::freshness_boundaries`. |
| 10 | Login bounds request body/time, concurrent bcrypt work, and process-wide request rate. Cancellation does not release a running blocking job's permit. | `auth::tests::cancelled_waiter_does_not_release_blocking_job_admission`; sustained load and tuning remain release checks. |
| 11 | Live responder identity uses raw subjectPublicKey bytes and hashes exactly once. | `e2e::configured_live_material_uses_raw_responder_key_and_refreshes_pair`. |
| 12 | Live signer selection is per CA; matching configured key/certificate material is refreshed. | `e2e::live_signers_are_selected_by_ca_and_reload_matching_material`; configured-material regression. |
| 13 | Expiry is checked after selecting the requested CA, rather than using the first loaded CA. | `e2e::expired_first_ca_does_not_block_fresh_second_ca`. |
| 14 | HTTP cache lifetime is capped to remaining validity without a minimum that outlives nextUpdate. | `e2e::cache_lifetime_is_capped_by_remaining_validity`. |
| 15 | Identical current chained generations are idempotent across reload/restart. | `anti_rollback::identical_chained_bundle_passes_continuity_after_restart`. |
| 16 | Multi-bundle admission stages state; durable immutable bundle snapshots and marks form a coherent commit before publication. Persistence failure does not mutate active marks. | `failed_persist_does_not_change_in_memory_marks`, `failed_multi_bundle_reload_keeps_marks_and_recovers_committed_snapshots`; real power-loss/storage qualification pending. |
| 17 | Heap/mmap bundle access uses checked offsets/conversions and safe slicing. | `integration::overflowing_entry_offsets_never_panic_in_heap_or_mmap`, including a release-mode CI invocation. Exhaustive fuzzing not claimed. |
| 18 | Delta materialization conservatively derives validity from retained payload provenance. | `ops::tests::delta_validity_tracks_retained_payloads_and_output_is_unsigned`. |
| 19 | Default apply emits an explicitly unsigned intermediate; `apply_sealed` accepts a real sealing callback. Admin result labels output unsealed. | `seal_verification::delta_materialization_supports_a_real_cms_sealing_callback`; delta unsigned-output regression. |
| 20 | Every delta must reference the correct base, producer, and CA scopes, independently of optional predecessor links. | `every_delta_must_reference_base_even_without_predecessor`, `delta_cannot_change_producer_or_ca_scope`. |
| 21 | Missing/unknown Dogtag status is an explicit error, never implicit VALID. | `missing_status_is_never_good_and_invalid_is_explicit`. |
| 22 | Decimal serial parsing uses bounded arbitrary-width conversion and canonicalizes bytes; values above 128 bits are supported up to 20 bytes. Invalid input fails the refresh. | `large_serials_are_supported_and_bounded`. |
| 23 | Rotation uses the PEM/DER loader, reports failures, renews expired material before startup, refreshes valid external replacements, and prevents generation after rejected live key/certificate replacement. | `rotation::regression_tests::pem_and_der_have_identical_rotation_status_and_invalid_cert_fails`, `rotation_preflight_tests::expired_live_certificate_is_renewed_before_startup_and_bad_pair_rejected` and configured live pair refresh; real renewal command/HSM integration pending. |
| 24 | Signer and loader resolve explicit bundle paths or the same per-CA `<label>.ahu` default; publication uses durable temporary-file/rename replacement. | `orchestrate::publication_tests::configured_bundle_destination_is_respected_and_failure_preserves_old_file`, `e2e::default_bundle_paths_keep_ca_scope_and_live_key_together`, signed endpoint round-trip and transactional loader regressions; storage-specific power-loss tests pending. |
| 25 | Forward transport policy is enforced at serving startup/request time; redirects are disabled and upstream body reads are incrementally bounded. | `handlers` regressions `cleartext_forwarding_requires_explicit_opt_in`, `redirects_are_not_followed`, `chunked_response_is_rejected_before_unbounded_buffering`; production transport qualification remains pending. |
| 26 | Gossip limits retained generations, expires old records, and bounds accepted announcement payloads. | `node::tests::generation_storage_is_bounded_and_expires`; no sustained fleet load claimed. |
| 27 | Trusted gossip keys are authorized for named origins; another member cannot claim that identity. | `crypto::tests::authenticated_peer_cannot_claim_another_origin`. |
| 28 | Partial is the configuration default. Authoritative completeness requires successful source evidence and is carried into the signed manifest. CRL-only sources cannot claim positive issuance completeness. | Source completeness implementation and signing integration; live 389 DS completeness qualification pending. |
| 29 | Corrected big-endian scalar test positions and verified conversion of a real signature. | `pkcs11::tests::raw_ecdsa_to_der_valid`, `raw_ecdsa_conversion_preserves_a_real_signature`; not hardware execution. |

## Configuration and state migration

### CRL source authorization and freshness

Provide `issuer_cert` (PEM or DER) for every configured CRL source. The standalone sign command requires `--issuer`. The issuer certificate is trusted configuration, not an arbitrary certificate supplied alongside an untrusted CRL. Its subject and subjectPublicKey must match the configured CA identity. CRL signature authentication supports ECDSA P-256/SHA-256, RSA PKCS#1 v1.5 SHA-256/384/512 with 2048–8192-bit keys, and ML-DSA-44/65/87. Other algorithms, including RSA-PSS and P-384, fail explicitly. Delta/indirect CRLs and unsupported critical extensions are rejected; do not silently use them as complete CRLs.

Sources must provide a fresh, ordered thisUpdate/nextUpdate interval. Configured response lifetime and jitter cannot extend it. Short source windows can require a faster refresh cadence. CRL enumeration establishes revocations, not the complete issued population: keep `completeness = "partial"`. Configure `authoritative-complete` only for a successfully synchronized authoritative Dogtag population whose directory base, filter, and permissions cover the intended CA.

### CMS trust and scope

`storage.seal_signer_pins` contains paths to **exact DER-equivalent signer certificates**, supplied as PEM or DER. These are certificate pins, not SPKI hashes. Certificate renewal therefore requires staging the new certificate pin before changing the producer and removing the old pin after fleet convergence. Expired or unsupported-profile certificates reject.

`storage.seal_trust_anchors` remains a distinct CA-anchor policy. The implemented profile accepts a configured CA itself or a signer directly issued by it, with ECDSA P-256 or ML-DSA signatures. It requires CA basic constraints on anchors, applicable key usage, valid times, and only the supported extension profile. Intermediate-chain building, general policy processing, and arbitrary certificate extensions are not supported. Provision compatible dedicated seal certificates or use explicit pins; do not relabel an arbitrary signer certificate as a CA trust anchor.

Configure `[[storage.seal_authorizations]]` to restrict each signer to `producer_id`, `issuer_key_hash` (hex of the manifest scope hash), and `signer_sha256` (SHA-256 of the **DER certificate**, hex). When configured, every scope needs a matching authorization; dual SHA-1/SHA-256 issuer scopes need matching entries for each hash. Without authorization entries, a trusted seal signer is allowed across configured scopes. Normal admission requires anchors or pins. Only explicit `storage.allow_unauthenticated_bundles = true` with no trust or authorization configuration enables unauthenticated demo admission; configured trust failures never fall back to that mode.

### Seal material pairing and key separation (October audit F07)

Signer/combined CAs with a persistent signing key (`type = "file"` or `type = "pkcs11"`) must configure a complete `seal_key` + `seal_cert` pair per CA; configuration validation rejects a missing or half-configured pair. The previous implicit fallbacks — reusing the OCSP signing key as the seal key, and generating an ephemeral seal key for non-demo configurations — are removed. Only `type = "demo"` signing may omit both seal inputs, in which case a distinct ephemeral seal pair is generated for that signing pass (testing only; it is never pinned across generations). The one-shot `hoike sign` command mirrors this: `--seal-key` and `--seal-cert` must be provided together for file-key signing, and `--demo-key` generates distinct ephemeral seal material.

The OCSP signing key and the seal key must be distinct. ECDSA signers (software file keys, the PKCS#11 bridge, and the dual-algorithm classical signer) prove separation by signing the domain-separated message `hoike:seal-ocsp-key-separation:v1`; a signature that verifies under the seal public key — the same key material configured under different file names or a symlink — fails the signing pass before anything is produced or published, as does any signer or encoding error. An ML-DSA OCSP signer is algorithm-distinct from the configured P-256 seal key. Generated demo certificates now carry a fresh validity window anchored at generation time instead of a fixed 2024–2034 range. Configure the live/seal backend matrix explicitly: configured seals are P-256 software keys, batch OCSP covers ECDSA software/PKCS#11 and ML-DSA software keys, and live nonce signing covers the configured ECDSA software key; other combinations are separate extensions.

### Read-only verification (October audit F01)

Migrate bare `ahu verify FILE` invocations to one of these explicit modes:

- `ahu verify FILE --config PATH [--entries]` authenticates the seal with the
  supplied trust/profile and producer/CA authorization policy. Missing trust,
  corrupt seals, expired seal certificates, and unauthorized scopes fail.
- `ahu verify FILE --structure-only` checks structure and digests, and prints
  `Structure valid; authenticity not checked.` This mode conflicts with
  `--config` and `--entries`; no configuration is discovered implicitly.

`--entries` uses embedded responder keys, not general responder-chain PKIX
validation. Successful responses without certificates fail as incomplete;
protocol-defined unsigned errors are counted separately. Authenticated success
states `Installation eligibility not checked.` Freshness and rollback eligibility
remain installation checks.

The admin verify route uses the running configuration, preserving structural
fields and adding `trust_status`, `trust_error`, and `signer_sha256`. Structurally
valid but untrusted input returns HTTP 200 with `trust_status: "failed"` and
`overall_ok: false`; malformed input returns HTTP 400. Inspection reports only
seal presence. `hoike check` uses the same admission policy without opening or
writing rollback state or installing snapshots; demo admission is explicitly
reported as unauthenticated.

Entry-point regressions: CLI `verify_rejects_corrupt_or_untrusted_cms`,
`verify_requires_an_explicit_mode`, `structure_only_never_claims_authentication`,
`entries_rejects_unchecked_successful_responses`, and
`check_authenticates_without_creating_or_changing_state`; admin HTTP
`admin_verify_uses_running_trust_policy`. These cover fresh synthetic inputs,
expired certificates, scope failures, and read-only state preservation. They do
not qualify a deployment or extend the supported certificate profile.

### Explicit state initialization and exclusive writers (October audit F04)

State directories are now operator-acknowledged state, not a cache. `StateStore::open` is strict: a missing state file is an error pointing at explicit initialization or recovery, never a silently fresh timeline that would forget recorded high-water marks and accept an older epoch. Committed state is validated on open — high-water marks must be paired with manifest-digest records, and every committed snapshot must exist, hash to the digest in its filename, and carry marks at or above its epoch. Corrupt JSON, a missing mark for an active snapshot, a mismatched snapshot digest, and a missing snapshot are all recovery failures. Valid legacy JSON remains readable.

`hoike init-state --config PATH` (or `StateStore::initialize`) is the explicit bootstrap: it refuses an existing state file and refuses a directory containing any recovery material, ignoring only the `.writer.lock` file when checking emptiness. There is no automatic reset and no `--force` escape hatch; recovery means restoring marks and snapshots together. `hoike check`, `serve`, and restarts never initialize implicitly, and `ahu verify` remains read-only. Signer epoch derivation (`sign_ca_scope`) reads state with the same strictness — a signer never starts a fresh timeline silently.

One writer per state directory is enforced in addition to being documented. `hoike serve`, `hoike init-state`, and offline `hoike import` hold an OS advisory exclusive nonblocking `flock` on `.writer.lock` inside the state directory for their full lifetime; a second process is rejected immediately. The lock file is never unlinked (removing a live lock inode would let a new writer bypass exclusion), and a persistent PID file is not used. `ResponderState::load(config, guard)` validates that its guard protects the configured directory and retains the guard, so every detached writer (background signer loop, admin on-demand signing) keeps the lock held until it finishes; a listener exit does not release it while writers still run. Read-only paths (`hoike check`, `sign_ca_scope`'s state read) do not take or reacquire the lock. This enforces the single-host writer rule; it is not distributed signer fencing.

Deployment migration: initialize each new state directory once with `hoike init-state` before the first `serve`. Existing valid state continues to work unchanged. Stop the previous writer process before starting a new one against the same state directory. Back up and restore the state directory (marks, snapshots, and lock file) as one unit.

Entry-point regressions: `state_lock::missing_state_after_epoch_99_rejects_epoch_5`, `initialization_refuses_existing_or_orphaned_state`, `incomplete_committed_state_requires_recovery`, `state_directory_lock_is_process_exclusive`, and `writer_guard_outlives_listener_owner` (real subprocesses with a pipe handshake); `state_initialization::init_state_initializes_once_and_never_resets`, `serve_requires_explicit_state_initialization`, and `serve_is_process_exclusive_and_restart_preserves_state` at the CLI boundary; `orchestrate::urgent_tests::sign_ca_scope_requires_existing_state` for signer epoch derivation. flock behavior is exercised on macOS and Linux by the same tests; both platforms are required before release.

### Offline authenticated import (October audit F05)

`hoike import --bundle PATH --ca LABEL --config PATH` is now an offline, recoverable authenticated installation (`hoike-core/src/install.rs::install_bundle`), not a staging copy. The label is required and selects the destination through `Config::bundle_destination` — the CA's `bundle_file` when selected, otherwise `bundle_dir/<label>.ahu`; never a name inferred from the uploaded file. Unknown labels, legacy unscoped configuration (no `[[ca]]` entries), unsafe label components, and a destination shared with another configured label are rejected. The signer (`orchestrate::write_bundle`) resolves destinations through the same method and publishes through the same durable primitive.

Import always authenticates the input under the configured CMS seal trust and scope authorizations and enforces the supported serving profile, even when `allow_unauthenticated_bundles` permits unauthenticated demo *serving*; rollback and predecessor-continuity checks run against the committed state, which must already have been initialized. The source is read exactly once before installation, so everything published comes from the checked bytes even if the source path changes afterwards. The commit order is fixed: write and fsync the immutable generation snapshot, atomically commit the state descriptor (the installation commit point), then publish the configured bundle path. A failure before the descriptor commit preserves the previous generation byte-for-byte — marks, snapshots, and configured files. If the descriptor's directory fsync fails after its rename, installation returns the typed `CoreError::DurabilityUncertain` instructing the operator to stop and reopen the state descriptor; it never claims a rollback or undoes marks, and reopening yields a coherent generation. If the post-commit publication of the configured path fails, the import still succeeds with a `publication_warning` (the CLI prints it); startup recovers from the committed snapshot and retrying the identical import repairs the path. A single-label installation preserves every other label's committed snapshots and marks; a full reload explicitly rebuilds a replacement working set. Import holds the exclusive writer lock for its full lifetime, so a running server excludes it; `--force` is removed, and completion instructs the operator to start the server — no SIGHUP is suggested. The authenticated admin reload endpoint is unchanged.

Entry-point regressions: `installation::import_rejects_untrusted_input_without_changes`, `import_uses_selected_ca_destination`, `import_recovers_committed_snapshot_when_alias_publish_fails`, plus destination/guard/rollback/fork/predecessor/buffer-replacement/idempotent-retry/other-label coverage in the same suite; commit-order fault injection at snapshot write, descriptor pre-rename, descriptor post-rename fsync, and alias publication in `install::fault_tests` and `storage::tests` (test-only thread-local injection, no production filesystem abstraction); CLI subprocess regressions `import::import_requires_a_label_and_rejects_unknown_labels`, `import_rejects_untrusted_input_without_changes`, `import_requires_initialized_state`, `import_rejects_active_writer_and_force`, `import_offline_install_and_restart_serves_selected_generation`, and `import_reports_committed_warning_when_publication_fails_and_retry_repairs`. Storage-specific power-loss recovery remains a deployment qualification gate, not a test claim.

### Directory checkpoints and durable state

Dogtag checkpoints use source-identity-qualified filenames derived from the configured cookie path. The identity includes endpoint, base/filter, requested attributes, bind identity, transport configuration, and CA identity; passwords are excluded. The checkpoint stores the population and cookie together. Old cookie-only files are ignored and a full refresh is required. A failed or malformed refresh does not publish partial updates. Rebuild capacity must accommodate a full directory refresh before enabling the source after migration.

Use one writer process per state directory and one active signer per CA; the exclusive `.writer.lock` described above now rejects a second writer process, while in-process serialization fences competing threads. The state directory includes immutable committed bundle snapshots referenced by rollback marks; back it up and restore it as one coherent unit. Do not delete high-water marks to recover from failures, and do not re-initialize over recovery material — restore marks and snapshots together. Old binaries are not qualified to read the new snapshot state. Use a local filesystem whose rename and fsync semantics have been qualified for the deployment; network filesystems and real power-cut recovery were not tested here, and flock exclusion is not qualified on them either.

### Gossip, transport, and administration

Replace legacy `gossip.peer_keys` with `gossip.peer_identities`, mapping exact node names to their public-key files. Nonempty legacy peer lists fail configuration. Stage authorized node/key mappings consistently across the fleet; unsigned permissive mode is not equivalent to authenticated operation. This authenticates broadcast origins, not SWIM liveness traffic, and does not add confidentiality or automatic bundle pulling.

Build with `tls` when configuring TLS/mTLS and with `dogtag-sync`/`pkcs11` when using those sources/keys. No configured TLS requirement may fall back to plaintext. HTTPS forwarding requires a valid endpoint certificate; redirects are not followed. Login currently admits at most four active jobs, sixty attempts per minute process-wide, and a 4096-byte body with a five-second read timeout. These bounds are safety limits, not capacity claims; monitor legitimate administrative access before production rollout.

### Delta output

`ahu apply`/default library `apply` produces an unsigned intermediate, not an installable authenticated bundle. Authenticate every input using the deployment trust policy, then use an authorized signer through `apply_sealed` before installation. A checksum is not a CMS seal. The CLI supports `ahu apply --seal-key KEY --seal-cert CERT --input-signer-pin INPUT_CERT` (repeat the pin for multiple input signers). Signed output requires authenticated inputs and a matching output key/certificate. The admin UI explicitly labels unsigned output. Keyless edges do not gain signing keys to perform this operation.

## Validation record and remaining release gates

`cargo test -p hoike-sign --features dogtag-sync,pkcs11 --offline` passed **69 library tests and all 6 ML-DSA bundle integration tests** after updating historical integration fixtures to fresh source windows. This includes AWS-LC RSA verification and PEM/DER issuer equivalence, real-signature PKCS#11 encoding, atomic output destination/failure, and PEM rotation regressions. Final local validation also passed:

- Default workspace: **197 tests**.
- Workspace with `tls,metrics,pkcs11,dogtag-sync,hoike-server/embed-webui`: **221 tests**.
- `ahu --no-default-features`: **48 tests**, plus a separate production-library `cargo check --no-default-features --lib` to avoid dev-dependency feature unification masking the minimal build.
- Release-mode heap/mmap overflow regression: **1 test**.
- Web UI production build and TypeScript `tsc --noEmit`.
- Rust all-target, all-feature Clippy with `-D warnings`, formatting, and whitespace checks.

The UI `npm run lint` command cannot execute because the existing project has no ESLint configuration file; this is a tooling follow-up, not a passing lint result. CI requests default workspace tests, TLS/metrics/PKCS#11/Dogtag feature tests, no-default-feature ahu tests, and release-mode parser regression. Feature-enabled unit tests do not exercise real 389 DS or a hardware HSM.

Still required before qualifying a deployment: live 389 DS delete/present/restart/stale-cookie tests; intended HSM and key-renewal integration; process restart and real power-loss recovery on the intended filesystem; adversarial upstream and login load; independent-client interoperability; configuration migration/canary; and a fresh security review. No production deployment or certification is asserted.

## Dependency audit

`cargo audit --json` against the final remediation lockfile reported **zero known vulnerabilities** across 402 dependencies using RustSec database commit `5a0ebedfe8bdd2e295b171f4162f8c977bcad9a5` (September 2, 2026). An intermediate RSA verification implementation introduced `rsa 0.9.10` and its Marvin private-key timing advisory; it was replaced with the existing AWS-LC backend, including synthetic test signing, and the `rsa` dependency was removed entirely. No advisory suppression was added.

Warnings identify unmaintained `rustls-pemfile 2.2.0` and yanked `chacha20 0.10.1` and `wnaf 0.14.0`. Dependency migration and fresh audit review remain follow-up work; yanked is not itself a vulnerability claim. The audit describes known dependency advisories, not application security or cryptographic module validation.
