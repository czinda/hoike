# hoike promise-to-code audit

- **Reviewed:** 2026-10-23
- **Baseline:** `c866700ed32910b66cf16af0d7d16b272797d240` (`demo/executive-showcase`)
- **Scope:** README, design, ahu format specification, security/remediation documents, CLI/server entry points, and the local demo presentation.

## Result

**The capabilities are not all complete end to end.** This audit identifies **12 actionable mismatches: 5 High, 5 Medium, and 2 Low**. Nine have isolated executable reproductions; the other three are source-traced. Severity describes operational/security impact under the stated conditions, not a CVSS rating.

For the four capabilities that prompted the review:

- **Gossip signing exists.** Ed25519 signatures and named-origin authorization protect custom broadcasts when enforcement is configured. SWIM liveness authentication, confidentiality, and automatic bundle retrieval are absent. The staged signing-only rollout has a compatibility gap (F09).
- **Seal trust anchors exist.** Exact certificate pins and a bounded direct-issued CA profile are implemented, including certificate validity/profile and optional producer/CA authorization checks. Several operator entry points do not use that policy (F01, F02, F05).
- **General PKIX validation is absent.** Intermediate-chain building and general policy/constraint processing are explicitly unsupported; this is a disclosed limitation, not a missing implementation of the documented bounded profile.
- **SCVP is absent.** It is a separate, explicitly excluded protocol. Its absence is not an OCSP defect.

The default workspace run passed **200 tests**; the TLS/metrics/PKCS#11/Dogtag-sync run passed **222 tests**. These are overlapping configurations, not 422 distinct tests. **All nine audit probes also passed, meaning they confirmed the gaps below, not that the gaps were fixed.**

## High-priority findings

### F01 — Verification can report success without verifying the CMS seal

- **Severity:** High.
- **Promise:** The [CLI reference](../README.md#L149-L155) and [command help](../crates/hoike-cli/src/ahu_main.rs#L20-L26) promise seal verification. The [quick start](../README.md#L102-L106) more accurately calls this structural inspection, so the public descriptions disagree.
- **Location:** [`ahu_commands.rs:157–270`](../crates/hoike-cli/src/ahu_commands.rs#L157-L270); [`admin/bundles.rs:111–142`](../crates/hoike-server/src/admin/bundles.rs#L111-L142).
- **Finding:** `ahu verify` calls `verify_structure`, reports seal presence, and prints `Verification passed.` without calling any CMS verifier. The admin endpoint similarly derives `overall_ok` entirely from structural checks and has no configured trust-policy input.
- **Evidence:** Probe P01 corrupts an otherwise valid CMS signature. `ahu::verify_seal` rejects it, while the actual CLI `verify` implementation returns success. The admin behavior is source-traced, not HTTP-reproduced. `--entries` is a separate OCSP signature check; it does not authenticate the container or authorize its producer.
- **Impact:** An operator can mistake a checksum-consistent, unauthenticated artifact for an authenticated import candidate. This does not defeat the separately configured trusted server loader.
- **Suggestion:** Expose structural validity, CMS signature validity, and signer/scope authorization as distinct results. Use the same trust-policy enforcement as admission when claiming trusted verification; require corrupt, unsigned, untrusted, and wrong-scope inputs to fail that mode.

### F02 — Missing seal trust disables authentication instead of failing admission

- **Severity:** High, conditional on deployment without pins or anchors.
- **Promise:** [Security model](../SECURITY.md#L16-L23) and [format loading rules](../ahu-format-spec.md#L295-L312) require authenticated container admission.
- **Location:** [`router.rs:503–594`](../crates/hoike-core/src/router.rs#L503-L594).
- **Finding:** If both trust lists are empty, a nonempty seal produces a warning and no signature check; an absent seal also succeeds. The resulting bundle can become the active working set.
- **Evidence:** P02 loads both corrupt-seal and unsigned bundles under no-trust configuration. Configuring the correct certificate pin makes the corrupt-seal case fail. The permissive mode is explicitly disclosed in the [migration guide](review-remediation.md#L49-L55); the README now recommends explicit trust. The remaining problem is enforcement and contradictory unconditional security wording.
- **Impact:** A party able to supply bundle files can rewrite container metadata and digests without producer authentication in this mode. Relying-party OCSP signature checking remains a separate protection; this is not a demonstration of forging signed `good` responses.
- **Suggestion:** Require configured trust for normal operation and reserve permissive admission for an explicit demo/test choice. Preserve the current fail-closed pin/anchor behavior and add no-trust startup/admission coverage. The compatibility policy for existing permissive deployments needs an explicit decision.

### F03 — The serving loader accepts orphan deltas and ignores `max_chain`

- **Severity:** High.
- **Promise:** [Loading step 6](../ahu-format-spec.md#L295-L312) requires a loaded matching base; [delta rules](../ahu-format-spec.md#L341-L359) define materialization and a configured chain limit.
- **Location:** [`router.rs:334–466`](../crates/hoike-core/src/router.rs#L334-L466), [`router.rs:479–500`](../crates/hoike-core/src/router.rs#L479-L500), and [`verify.rs`](../crates/ahu/src/verify.rs).
- **Finding:** Admission validates structure, configured seal trust, rollback, and optional predecessor continuity, then registers the supplied bundle directly. It does not resolve/materialize a delta's base or enforce `storage.max_chain`.
- **Evidence:** P03 admits a correctly pinned delta naming a nonexistent base, with `chain_length = 100` and `max_chain = 1`. It becomes a one-entry working set. The separate [delta-apply library](../crates/ahu/src/ops.rs#L114-L255) has base/chain checks; the serving loader does not invoke it.
- **Impact:** Trusting the producer's signature does not ensure that the served working set includes unchanged base entries. A delta can be installed as an incomplete replacement, and the configured chain bound has no admission effect.
- **Suggestion:** Reject delta bundles at serving admission until a complete authenticated materialization path is supported. Keep materialization/resealing with an authorized producer; a keyless edge must not acquire a seal key. Add missing-base, tombstone, retained-entry, and chain-limit acceptance tests. Reconcile the draft's earlier [partial-completeness example](../ahu-format-spec.md#L200-L209), which mentions a delta without its base, with its mandatory base-matching loading rule.

### F04 — Losing the state file silently resets anti-rollback protection

- **Severity:** High, conditional on state loss or an incorrect restore/state path.
- **Promise:** [Format §6.3](../ahu-format-spec.md#L444-L452) requires operator acknowledgment when high-water state is missing.
- **Location:** [`state.rs:40–71`](../crates/hoike-core/src/state.rs#L40-L71); [`router.rs:71–74`](../crates/hoike-core/src/router.rs#L71-L74).
- **Finding:** A missing `state.json` is treated as fresh empty state. There is no explicit bootstrap/recovery acknowledgment separating a new deployment from lost prior state.
- **Evidence:** P04 records epoch 99, confirms epoch 5 is rejected, deletes only the synthetic state file, then successfully loads the unchanged, still-fresh epoch-5 bundle with a valid pin. Ordinary restarts with intact state are covered and do preserve marks.
- **Impact:** A missing, mis-mounted, or incompletely restored state directory can re-admit an older signed generation. This is not a remote state-deletion exploit.
- **Suggestion:** Make first initialization and loss-of-state recovery explicit operations, validate committed snapshots and marks together, and test missing/corrupt/mismatched restored state. Retain the existing single-writer and coherent-backup requirements.

### F05 — Enclave import is a staging copy, not authenticated installation

- **Severity:** High for an import workflow relied on as a trust boundary.
- **Promise:** [`hoike import` and M4](../README.md#L125-L131), [enclave design](../hoike-design.md#L422-L426), and the [format's loading/import rules](../ahu-format-spec.md#L293-L337).
- **Location:** [`main.rs:1006–1094`](../crates/hoike-cli/src/main.rs#L1006-L1094).
- **Finding:** Import checks structure and, unless forced, rollback. It does not authenticate CMS, apply scope authorization, check predecessor/base continuity, advance the committed installation state, resolve the configured CA destination, or trigger a reload. It copies the source basename using `std::fs::copy`, rather than atomic publication of the checked bytes. Its final message suggests SIGHUP while acknowledging that it is unimplemented.
- **Evidence:** Source trace of the complete command. No destructive live import or power-loss experiment was performed.
- **Impact:** Import can report success for an untrusted artifact that the correctly configured loader will later reject; a differently named file can miss the configured CA path entirely. Overwriting an active path also lacks the publication guarantees already used by the signer. This is not a bypass of configured loader trust.
- **Suggestion:** Give import an explicit staging/install contract. An installation operation should reuse admission policy, resolve its CA destination, atomically publish the authenticated bytes, and coordinate state/reload with the existing single writer. Test rejection, destination selection, failed publication, and recovery.

## Medium-priority findings

### F06 — Zstd-marked payloads are served as compressed bytes

- **Severity:** Medium.
- **Promise:** [Format §2.5](../ahu-format-spec.md#L275-L289) defines independently compressed entries whose delivered OCSP content is DER.
- **Location:** [`bundle.rs`](../crates/ahu/src/bundle.rs), [`router.rs:140–175`](../crates/hoike-core/src/router.rs#L140-L175), and [`handlers.rs:453`](../crates/hoike-server/src/handlers.rs#L453).
- **Finding:** The manifest supports Zstd, but the production lookup path neither decompresses entries nor rejects the unsupported profile.
- **Evidence:** P09 supplies a correctly pinned bundle containing Zstd-compressed OCSP DER. Loading succeeds; `ResponderState::lookup` returns the compressed bytes. The HTTP handler forwards those lookup bytes. The HTTP leg was source-traced.
- **Impact:** A format-conforming compressed input yields an invalid OCSP body. Current built-in producers do not enable compression, limiting routine exposure.
- **Suggestion:** Reject compressed profiles during admission until bounded per-entry decompression and dictionary handling are implemented. Cover both supported uncompressed inputs and explicit rejection of unsupported compression.

### F07 — Seal/OCSP key separation is optional in the implementation

- **Severity:** Medium.
- **Promise:** [Format §2.3](../ahu-format-spec.md#L217-L227) says the seal key **MUST** be distinct; [README configuration](../README.md#L199-L208) asks for separate material.
- **Location:** [`orchestrate.rs:639–683`](../crates/hoike-sign/src/orchestrate.rs#L639-L683); analogous one-shot fallback in [`main.rs:1536–1565`](../crates/hoike-cli/src/main.rs#L1536-L1565).
- **Finding:** Without `seal_key`, an ECDSA file signing key is reused for sealing. Other configurations can fall back to ephemeral seal keys. Explicitly configuring the same key twice is not prevented by a public-key separation check.
- **Evidence:** P06 compares the loaded OCSP and fallback seal public keys and confirms they are identical. Ephemeral fallbacks are source-traced.
- **Impact:** Independent seal/OCSP compromise and rotation boundaries are not enforced. Ephemeral fallback also prevents stable configured signer pinning across generations.
- **Suggestion:** Require persistent, explicit seal material for non-demo production and reject equivalent OCSP/seal public keys, even if configured through different paths. Add key-equivalence and missing-material checks at the shared orchestration boundary.

### F08 — The documented PEM `seal_cert` example fails sealing

- **Severity:** Medium.
- **Promise:** The [signer example](../README.md#L204-L220) uses `seal_cert = "/etc/hoike/seal-signer.pem"`.
- **Location:** [`orchestrate.rs:676–681`](../crates/hoike-sign/src/orchestrate.rs#L676-L681); [`seal.rs`](../crates/hoike-sign/src/seal.rs).
- **Finding:** Configured seal certificates are read verbatim, then consumed as DER by CMS creation. The configured producer does not normalize PEM as the trust loader does.
- **Evidence:** P05 succeeds with a DER certificate and fails with the same certificate in PEM: `CMS seal error: parse seal cert: unknown/unsupported ASN.1 DER tag: 0x2d at DER byte 1`.
- **Impact:** The documented signer configuration cannot produce a bundle even with valid key/certificate material.
- **Suggestion:** Reuse PEM/DER certificate normalization before sealing and validate the configured key/certificate pair during preflight. Test equivalent encodings through the actual configured production path.

### F09 — Signing-only gossip rollout drops other upgraded peers

- **Severity:** Medium.
- **Promise:** The [crypto rollout policy](../crates/hoike-gossip/src/crypto.rs#L20-L25) and [historical mixed-fleet guidance](niap-ppca-gap-matrix.md#L62) describe staged compatibility.
- **Location:** [`node.rs:156–192`](../crates/hoike-gossip/src/node.rs#L156-L192); [`crypto.rs:166–203`](../crates/hoike-gossip/src/crypto.rs#L166-L203).
- **Finding:** `identity_key` with empty `peer_identities` constructs a permissive verifier trusting only the local key. It accepts unsigned messages but rejects correctly signed messages from other newly signing nodes. Adding any peer mapping switches to required mode, which drops unsigned peers.
- **Evidence:** P07 exercises the exact verifier/identity set selected by that startup configuration: unsigned peer input passes; the same payload correctly signed by a different peer fails. This is a policy-level reproduction, not a multi-process fleet rollout test.
- **Impact:** A purportedly incremental upgrade can partition announcement visibility as nodes enable signing. A frame tag provides decoding compatibility, not an adequate trust rollout strategy.
- **Suggestion:** Define and test a supported fleet migration sequence and make the configuration express its intended verification policy. Preserve required-mode rejection of unauthenticated input. The newer [migration guide](review-remediation.md#L63-L65) correctly calls for consistent identity provisioning, but older guidance still promises more.

### F10 — Private-CA forwarding guidance does not match the TLS client

- **Severity:** Medium.
- **Promise:** [`forward_ca` documentation](../crates/hoike-core/src/config.rs#L179-L186) and [`hoike check`](../crates/hoike-cli/src/main.rs#L1244-L1249) say the private CA can be installed in the system trust store as the current workaround.
- **Location:** [`handlers.rs:285–300`](../crates/hoike-server/src/handlers.rs#L285-L300); [`hoike-server/Cargo.toml:23`](../crates/hoike-server/Cargo.toml#L23).
- **Finding:** `forward_ca` is not wired into the client. The production dependency uses `reqwest 0.12.28` with `default-features = false` and `rustls-tls`; that feature selects bundled WebPKI roots, not native/system roots. No custom trust material is installed by `forward_client`.
- **Evidence:** Source trace, the locked production Cargo feature tree, and [the locked reqwest feature definitions](https://docs.rs/crate/reqwest/0.12.28/features). A private-CA TLS handshake was not run.
- **Impact:** Following the advertised system-store workaround does not make an enterprise-only upstream trusted in this build. Validation fails closed; this is an availability/configuration gap, not TLS verification being disabled.
- **Suggestion:** Implement the configured per-target CA policy in the forwarding-client owner and reject unusable configured roots at startup. Correct the system-root advice and test a private-root upstream plus a wrong-root rejection.

## Low-priority contract findings

### F11 — Gossip's `manifest_digest` contains the index digest

- **Severity:** Low at the current implementation stage; it becomes a correctness dependency for future pulling.
- **Promise:** [Generation announcements](../hoike-design.md#L396-L405) identify a generation by its manifest digest.
- **Location:** [`hoike-server/src/lib.rs:20–38`](../crates/hoike-server/src/lib.rs#L20-L38).
- **Finding:** `announce_bundle_scopes` assigns `bundle.manifest.integrity.index_digest` to the `manifest_digest` field.
- **Evidence:** P08 invokes the real announcer, captures its locally delivered message, and confirms the value equals the index digest and differs from `ahu::manifest_digest(&bundle.manifest_bytes)`. The announcer also supplies no bundle URL.
- **Impact:** An index checksum does not commit to the manifest's epochs, scopes, or windows. Future consumers comparing advertised and downloaded manifest digests will disagree. The current consumer only records generation metadata, so this is not an observed bundle-admission bypass.
- **Suggestion:** Use the existing manifest-digest helper and test the field against the exact serialized manifest. Add a retrievable locator as part of the separately pending distribution work.

### F12 — The draft wire specification differs from produced bundles

- **Severity:** Low while the format remains explicitly draft; resolve before independent implementation or stabilization.
- **Promise:** [Seal profile](../ahu-format-spec.md#L217-L227) and [index profile](../ahu-format-spec.md#L240-L273).
- **Location:** [`seal.rs:24–28`](../crates/hoike-sign/src/seal.rs#L24-L28) and [`index.rs`](../crates/ahu/src/index.rs).
- **Finding:** CMS creation uses `id-data` instead of the draft's `id-ct-ahuManifest`. Dual-algorithm records reuse the two draft-reserved bytes for a discriminator and allow duplicate entry keys across discriminators; the draft requires those bytes to be zero and entry keys to be unique.
- **Evidence:** Source trace and passing discriminator/index round-trip tests. The manifest OID is itself still a registration item in [spec §7](../ahu-format-spec.md#L480-L491), so this is an unresolved format contract rather than evidence that an assigned OID was ignored.
- **Impact:** An independent reader built literally from the draft can reject the implementation's dual-algorithm bundles or expect a different CMS content type.
- **Suggestion:** Publish an explicit versioned wire profile matching the supported behavior, settle the content-type/OID decision, and add independent golden-format fixtures. Also document the intentional identical-generation reload exception to the draft's strict `epoch <= high_water` rejection rule.

## Capability inventory and unfinished integration

These observations explain where an existing library mechanism is narrower than a complete deployable feature. They are not additional reproductions or extra severity-counted findings.

### Implemented within stated bounds

- **CMS and trust:** [`ahu/src/seal.rs:200–355`](../crates/ahu/src/seal.rs#L200-L355) authenticates pins/direct-issued anchors and checks certificate profile and time. [`router.rs:572–587`](../crates/hoike-core/src/router.rs#L572-L587) enforces configured producer/issuer/signer authorizations. Without authorization entries, a trusted signer is allowed across scopes; that is documented policy, not implicit per-CA restriction.
- **Broadcast authentication:** [`crypto.rs`](../crates/hoike-gossip/src/crypto.rs) and [`broadcast.rs`](../crates/hoike-gossip/src/broadcast.rs) sign and verify messages and reject key/origin mismatches in enforced mode. Generation storage is bounded and expiring. Tests cover forged, tampered, unsigned, and misattributed messages. This does not authenticate SWIM pings/acks.
- **OCSP serving:** GET/POST, dual SHA-1/SHA-256 CertID indexing, expiry/caching headers, static errors, nonce validation, and preferred signature algorithms exist. The [20-check conformance suite](../crates/hoike-server/tests/conformance.rs) exercises defined cases. Multi-CertID requests answer only the first request, as [disclosed](../README.md#L280-L282).
- **Signing/source mechanisms:** ECDSA and ML-DSA OCSP generation, delegated certificate embedding, PKCS#11 adapters, authenticated CRL ingestion, and feature-gated Dogtag sync/checkpoints exist. These are supported by unit/integration fixtures; hardware HSM and live directory qualification remain separate.
- **Operations:** Shared in-process signer serialization, atomic signer output, committed snapshot/rollback state, on-demand signing, admin roles, TLS/mTLS, metrics, audit events, fleet visibility, and bundle diff/extract/apply APIs exist. This statement does not remove the entry-point gaps above or establish crash/deployment qualification.

### Missing end-to-end capabilities

- **Fleet distribution and urgent refresh:** [`main.rs:304–342`](../crates/hoike-cli/src/main.rs#L304-L342) records generation announcements and logs that it “would pull delta.” There is no fetch/authenticate/install/swap path. [`announce_bundle_scopes`](../crates/hoike-server/src/lib.rs#L20-L38) supplies `bundle_url = None`; the server has no artifact-download/catalog route. The built-in generators produce full bundles, not off-cycle deltas. This is explicitly acknowledged in [design §6.3](../hoike-design.md#L387-L405), but is easy to miss in the README's M4/“generation propagation” wording. Fleet visibility does not establish fleet convergence.
- **Signer election/fencing:** [Design §6.2](../hoike-design.md#L378-L385) describes a shared lease and warm standby. The implementation provides an in-process mutex, not a distributed lease or cross-process fence. [Operational guidance](review-remediation.md#L57-L61) requires one writer and one active signer per CA. Automated signer failover needs external coordination or new implementation.
- **Gossip availability policy:** [`main.rs:347–349`](../crates/hoike-cli/src/main.rs#L347-L349) logs startup failure and continues without gossip, including failure to load gossip key material. It does not silently switch to unsigned transport, but configured participation is not a startup requirement. Operator-facing health/check behavior should make this degraded state unmistakable.
- **Live signing matrix:** The live signer uses a software P-256 key. [`Config::validate_for_mode`](../crates/hoike-core/src/config.rs) rejects ML-DSA live signing, and [`live.rs`](../crates/hoike-sign/src/live.rs) rejects PKCS#11 live material. The broad signer-tier description needs this qualification: batch HSM/PQ support does not imply live nonce support with those keys.
- **Seal signing matrix:** [`SealKey`](../crates/hoike-sign/src/seal.rs) and verification support ML-DSA, but configured seal loading accepts P-256 software files only ([`load_seal_materials`](../crates/hoike-sign/src/orchestrate.rs#L639-L683)). There is no configured HSM seal backend. An HSM-held OCSP key therefore does not imply an HSM-held or PQ seal key.
- **Batching controls:** [`GenerationConfig::bucket_size`](../crates/hoike-sign/src/generate.rs#L18-L71), batched generation tests, and [the batching benchmark](../crates/hoike-sign/examples/bench_batching.rs) exist. `CaConfig` exposes no bucket-size setting; normal orchestration inherits the single-entry default. Preproduction of many responses exists, but operator-configurable multi-entry response batching does not.
- **Memory-mapped serving:** [`MmapBundle`](../crates/ahu/src/mmap_bundle.rs) exists and is tested. The production router stores heap `Bundle`s and [copies lookup results](../crates/hoike-core/src/router.rs#L140-L175); the HTTP path [clones the body](../crates/hoike-server/src/handlers.rs#L453). Metrics mode also [parses the response](../crates/hoike-server/src/handlers.rs#L269-L282). The local demo's “edges mmap the bundle” claim is not true of this serving path. No throughput or allocation benchmark was run in this audit.
- **Additional sources:** CRL and Dogtag/389 DS sync are implemented. Dogtag REST, akamu, and SQL adapters remain roadmap concepts in the design; [`orchestrate.rs`](../crates/hoike-sign/src/orchestrate.rs) does not instantiate them.
- **General PKIX and SCVP:** Keep the [bounded trust limitation](../README.md#L273-L275) and [SCVP exclusion](../README.md#L283-L284) explicit. Neither should be promoted to an implemented feature based on the presence of X.509/CMS dependencies.

## Documentation corrections warranted now

1. Reconcile “verify” wording across README, CLI help, and admin UI with F01. Make configured trust and scope policy prerequisites visible wherever authenticated admission is claimed.
2. Add a short supported-capability matrix for live signing, OCSP signing backends, seal backends, batching controls, compression, and actual serving storage. Avoid implying that all combinations of individually implemented features work.
3. State in the README that gossip currently provides membership/announcement visibility, not automatic artifact distribution or signer failover. Retain the existing security-remediation caveats.
4. Correct [the design's opening status](../hoike-design.md#L9-L12), which still says gossip authentication remains planned despite the implemented broadcast protection.
5. Retire stale [`peer_keys` and mixed-fleet guidance](niap-ppca-gap-matrix.md#L62); nonempty legacy key lists now fail. Preserve named-origin provisioning guidance.
6. Correct [the matrix's FIPS follow-on language](niap-ppca-gap-matrix.md#L80-L80): enabling AWS-LC/rustls flags alone does not validate the whole application. OCSP/CMS/gossip use other crypto implementations; production forwarding also enables reqwest's ring provider. The matrix's header already disclaims certification and labels its “Met” rows historical. This audit does not claim a certification misrepresentation or perform a formal module-boundary assessment.
7. Update the untracked local [`demo/presentation/hoike-ciso-briefing.html:215`](../demo/presentation/hoike-ciso-briefing.html#L215) before using its mmap claim. That directory was pre-existing user work and is not part of the reviewed commit. Describe edges as holding no **OCSP/seal** private keys; authenticated gossip uses a separate Ed25519 node identity key.

## Evidence and reproducibility

Commands run against the baseline:

```sh
cargo test --workspace --locked --offline
cargo test --workspace --locked --offline --features tls,metrics,pkcs11,dogtag-sync
cargo tree --locked --offline -p hoike-cli -e features,no-dev -i reqwest
```

Results: **200 default tests passed**, **222 feature-enabled tests passed**; zero failed or ignored in either run. The production reqwest feature tree includes `rustls-tls-webpki-roots` and `__rustls-ring`.

The isolated probe project is outside the repository at:

`/private/var/folders/54/xqgr865x2890sy_h0pxqh3kw0000gn/T/opencode/hoike-capability-probes/`

Its `Cargo.toml` references the actual workspace crates, and `src/lib.rs` includes the actual CLI `ahu_commands.rs` rather than a copied verifier. Keys, certificates, bundles, UDP traffic, and state are synthetic/local. State deletion affects only a probe-created temporary directory. The probe source is a local audit artifact, not part of the committed regression suite.

```sh
CARGO_TARGET_DIR=/Users/czinda/git/hoike/target cargo test \
  --manifest-path /private/var/folders/54/xqgr865x2890sy_h0pxqh3kw0000gn/T/opencode/hoike-capability-probes/Cargo.toml \
  --offline -- --nocapture
```

Nine passing probes, mapped to findings:

- **P01 → F01:** `reproduces_cli_verification_accepting_a_corrupt_cms_signature`
- **P02 → F02:** `reproduces_default_admission_bypassing_seal_authentication`
- **P03 → F03:** `reproduces_trusted_orphan_delta_admission_and_ignored_max_chain`
- **P04 → F04:** `reproduces_missing_state_reset_without_operator_acknowledgment`
- **P05 → F08:** `reproduces_advertised_pem_seal_certificate_failing_production`
- **P06 → F07:** `reproduces_ocsp_key_reused_for_seal_without_distinct_key_requirement`
- **P07 → F09:** `reproduces_rollout_accepting_unsigned_but_rejecting_other_signed_peers`
- **P08 → F11:** `reproduces_generation_announcement_using_index_instead_of_manifest_digest`
- **P09 → F06:** `reproduces_compressed_bundle_serving_stored_zstd_bytes_as_ocsp`

Useful existing negative coverage includes `responder_load_enforces_cms_integrity_anchor_and_scope_authorization`, `mismatched_embedded_key_is_an_error_not_false_success`, `authenticates_direct_issuer_and_rejects_wrong_anchor_and_expiry`, `authenticated_peer_cannot_claim_another_origin`, and `failed_multi_bundle_reload_keeps_marks_and_recovers_committed_snapshots`. Their presence establishes important configured paths; it does not cover the different paths exercised by the probes.

**Qualification limits:** This was a source/contract audit with local tests, not an exhaustive vulnerability assessment or production qualification. No real HSM, live 389 DS, multi-host rollout, power-cut recovery, or broad independent-client interoperability was tested. The `embed-webui` feature, UI build, fresh dependency advisory scan, and standards certification were not evaluated here. Context7 was unavailable due to quota; reqwest behavior was checked against official versioned Docs.rs and the cached locked source.

## Recommended order

1. Close the admission/verification/import boundary gaps (F01–F05), with explicit bootstrap and permissive-mode policy decisions.
2. Make documented configurations and supported profiles reliable (F06–F10).
3. Correct the manifest identifier and settle the draft wire contract (F11–F12).
4. Scope separate work for automatic distribution, signer fencing, HSM/PQ live/seal support, and memory-mapped serving. Update claims to the current supported behavior as that work is prioritized.
