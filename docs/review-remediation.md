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

Configure `[[storage.seal_authorizations]]` to restrict each signer to `producer_id`, `issuer_key_hash` (hex of the manifest scope hash), and `signer_sha256` (SHA-256 of the **DER certificate**, hex). When configured, every scope needs a matching authorization; dual SHA-1/SHA-256 issuer scopes need matching entries for each hash. Without authorization entries, a trusted seal signer is allowed across configured scopes. Without anchors or pins, authenticated seal enforcement remains disabled; that mode is unsuitable when bundle input is not already trusted. A successful `ahu verify` alone does not establish your deployment's signer authorization policy.

### Directory checkpoints and durable state

Dogtag checkpoints use source-identity-qualified filenames derived from the configured cookie path. The identity includes endpoint, base/filter, requested attributes, bind identity, transport configuration, and CA identity; passwords are excluded. The checkpoint stores the population and cookie together. Old cookie-only files are ignored and a full refresh is required. A failed or malformed refresh does not publish partial updates. Rebuild capacity must accommodate a full directory refresh before enabling the source after migration.

Use one writer process per state directory and one active signer per CA. In-process serialization does not fence competing processes. The state directory includes immutable committed bundle snapshots referenced by rollback marks; back it up and restore it as one coherent unit. Do not delete high-water marks to recover from failures. Old binaries are not qualified to read the new snapshot state. Use a local filesystem whose rename and fsync semantics have been qualified for the deployment; network filesystems and real power-cut recovery were not tested here.

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
