# Audit remediation design

## Intent and evidence

Resolve F01–F12 in the [2026-10-23 audit](../../promise-audit-2026-10-23.md), with executable rejection tests at the operator entry points that failed. Baseline: `c866700ed32910b66cf16af0d7d16b272797d240`. The previous 200/222-test runs and nine audit probes are baseline evidence, not acceptance of this future implementation.

The user delegated planning choices with “use your judgement” and approved subagent-driven execution of this design and its plan. Private execution tracker: [GHSA-7vcp-p3rm-jf24](https://github.com/czinda/hoike/security/advisories/GHSA-7vcp-p3rm-jf24).

## Global constraints

- Keep `ahu` runtime-independent; do not introduce server/runtime/HSM dependencies into it.
- Keep the declared Rust floor `1.85`, the pinned development toolchain `1.97`, and the existing `der` 0.7/0.8 boundary.
- Edge nodes must hold no OCSP or seal private key.
- Use synthetic fixtures and current source windows for admission/production tests.
- Keep one writer per state directory; use a local filesystem with qualified rename/fsync semantics.
- Configured trust must never fall back to permissive behavior after a validation error.
- A failed pre-commit operation must preserve the previously committed generation and rollback marks.
- Existing valid full, uncompressed bundles and well-formed persisted state remain readable.

## S1. One owner for bundle trust

Extract the current pin/anchor/profile/scope enforcement from `hoike-core/src/router.rs` into `hoike-core/src/admission.rs`. Reuse the existing `ahu` CMS verifier; do not implement another PKIX engine or another signature checker.

Define these interfaces using `hoike_core::error::Result`:

```rust
pub fn authenticate_bundle(
    bundle: &ahu::Bundle,
    storage: &StorageConfig,
    now: u64,
) -> Result<ahu::SealVerification>;

pub fn validate_serving_profile(bundle: &ahu::Bundle) -> Result<()>;

pub enum AdmissionTrust {
    Authenticated { signer_sha256: String },
    UnauthenticatedDemo,
}

pub fn admit_bundle(
    bundle: &ahu::Bundle,
    storage: &StorageConfig,
    now: u64,
) -> Result<AdmissionTrust>;
```

`authenticate_bundle` checks structure/digests, seal signature, configured pins/anchors, and every configured scope authorization. It requires a nonempty trust policy even if demo admission is enabled. It is read-only and does not assert freshness, rollback acceptance, or installation.

`admit_bundle` also validates the serving profile. Add `storage.allow_unauthenticated_bundles: bool`, default `false`. Only an explicit `true` with **no** pins, anchors, or authorizations allows structure-only demo admission. If any trust is configured, all its checks apply; a corrupt signature cannot fall through to demo mode. Emit an unambiguous audit/startup event for demo admission. Reuse existing diagnostics instead of adding a new policy service.

Retain the bounded trust model: exact certificate pins or directly issued certificates under dedicated anchors. Optional authorizations retain their current meaning; this project does not silently make an empty authorization list deny all already trusted signers.

## S2. Verification means authenticated verification

- `ahu verify FILE --config PATH [--entries]` requires S1 authentication and exits nonzero on failure.
- `ahu verify FILE --structure-only` checks structure only and prints exactly `Structure valid; authenticity not checked.` It conflicts with `--config` and `--entries`.
- Plain `ahu verify FILE` fails with guidance to select one of those modes; there is no implicit config discovery.
- `--entries` must not report complete success if successful OCSP responses lacked certificates and were skipped. Protocol-defined unsigned error responses are reported separately. This remains embedded-key signature checking, not general responder-chain PKIX validation.
- The admin verification route consumes the running server's `Config`. Preserve existing structural fields and add `trust_status: "authenticated" | "failed"`, `trust_error: string | null`, and `signer_sha256: string | null`. `overall_ok` is true only after structural and authorized-seal verification. For parseable, structurally valid but untrusted input, return HTTP 200 with a failed verdict; malformed input is HTTP 400. Inspection remains available separately.
- `hoike check` uses the same trust/profile checks without creating state, changing marks, or installing bundles. In explicit demo mode it reports unauthenticated admission, never authenticated success.

There is currently no UI caller of `verifyBundle`; update its TypeScript contract and the existing inspect wording, rather than inventing a new verification page.

## S3. Supported serving profile

Admit only full, uncompressed bundles. Allow either an absent compression map or algorithm `none` with no dictionary. Reject Zstd, dictionary requirements, delta bundles, full-bundle tombstones, a full bundle's nonempty base reference, and nonzero full-bundle `chain_length` before changing durable state.

Remove `storage.max_chain` from server configuration and examples: accepting a security limit that is not implemented is misleading. Old configurations must remove it; unknown-field rejection provides a clear migration failure. The separate delta materializer continues to exist. Authenticated, resealed full output must still satisfy predecessor continuity against the actual destination; resealing is not permission to replace that check. A bundle naming an unseen predecessor is not automatically an installable checkpoint.

This closes unsafe admission of unsupported profiles. It does not claim that runtime delta overlays or decompression have been implemented. Full runtime support is a later feature decision.

## S4. Explicit state initialization and exclusive writers

Change `StateStore::open(path)` to read existing state only. Missing or malformed state is an error, including on signer startup and epoch derivation. Preserve valid legacy JSON; validate paired high-water/digest records and the existence/integrity of referenced committed snapshots. A missing record referenced by a committed snapshot is recovery failure, not a new scope. New producer/scope enrollment that is not in existing state remains allowed under configured trust.

Add `StateStore::initialize(path: &Path) -> Result<Self>` and `hoike init-state --config PATH`. Initialization is the explicit operator acknowledgment: it must refuse an existing state file or a directory containing recovery material. Creating the directory does not authorize resetting it. Recovery means restoring marks and snapshots together; this release introduces no automatic reset or `--force` escape hatch. Check/serve/restart never initialize implicitly.

Add `StateDirectoryLock::acquire(state_dir: &Path) -> Result<Self>` in `hoike-core/src/storage.rs`. Hold an OS advisory exclusive nonblocking lock on `.writer.lock` for the full lifetime of `serve`, `init-state`, and offline import. The lock file remains in place; never unlink a live lock inode. Initialization may ignore this one lock file when checking that a new directory is empty. Use already-locked `rustix 1.1.4` with its `fs` feature and `flock(..., NonBlockingLockExclusive)` on supported Linux/macOS targets. A persistent PID file is not a lock. The guard stores the open file; dropping it releases the OS lock. Read-only checks do not take a writer lock.

Acquire the server guard and successfully reopen/validate existing state before rotation, initial signing, source checkpoint updates, or other mutations. Change `ResponderState::load` to `load(config: Config, guard: Arc<StateDirectoryLock>) -> Result<Self>`; it validates the guard's canonical directory and retains it in the responder. Initial signing holds the same guard locally; all background/admin writers retain the responder or the same guard until they finish. A listener exit must not release the lock while detached writers can still run. Internal `StateStore` reads during signing do not reacquire it. Keep the existing in-process signer mutex. This enforces the current single-host writer rule; it is not distributed signer fencing.

## S5. Offline authenticated installation

`hoike import --bundle PATH --ca LABEL --config PATH` installs into the selected configured CA destination. Require the label, reject unknown labels and legacy unscoped configuration, and remove `--force`. This is an offline operation: a running server's state lock makes it fail promptly. Completion instructs the operator to start the server; do not suggest SIGHUP. The existing authenticated admin reload endpoint retains its current purpose.

Move durable file publication to `hoike-core/src/storage.rs::write_atomic(path, bytes) -> Result<()>`, consolidating the state/signer implementations. Add `Config::bundle_destination(label: &str) -> Result<PathBuf>`; both signer and importer use it. The selected `bundle_file` wins; otherwise use `bundle_dir/<label>.ahu`. Never infer a destination from the uploaded filename. Reject a selected destination shared by another configured CA label in this first import implementation, rather than ambiguously replacing multiple labels.

Add `hoike-core/src/install.rs::install_bundle(config, label, bytes, guard) -> Result<InstallResult>` where:

```rust
pub struct InstallResult {
    pub destination: PathBuf,
    pub publication_warning: Option<String>,
}
```

The guard must belong to `config.storage.state_db`. Read the source once before calling installation; all published data comes from those checked bytes. The operation:

1. Authenticates the input with S1 even if the config allows unauthenticated demo serving; validates S3 and target resolution.
2. Opens existing state, checks rollback and predecessor continuity, and stages changes while retaining other labels' committed snapshots.
3. Writes/fsyncs the new immutable snapshot, then atomically commits the descriptor with all marks and snapshot references. That descriptor is the installation commit point.
4. Publishes the configured bundle path atomically **after** the commit. If this convenience-path update fails, return a committed result with `publication_warning`, not an error falsely claiming no installation. Startup must recover from the committed snapshot; retrying the identical import repairs the path.

Failure before the descriptor commit leaves old marks and configured files intact. If descriptor rename succeeds but directory fsync fails, treat the outcome as indeterminate: return an explicit error instructing the operator to stop and inspect/reopen the descriptor; do not report rollback, undo marks, or continue writing. Reopening must select a coherent old or new generation. Failure after commit must never be reported as an uncommitted rejection. Do not implement a two-file pseudo-transaction or delete old recovery material before commitment. Adapt `StateStore::transaction` so full reload can explicitly clear the working set while single-label installation preserves other labels.

## S6. Explicit, valid, separate seal material

Normal signer/combined and one-shot file/HSM signing require a persistent `seal_key` and `seal_cert` pair. Add `hoike sign --seal-cert PATH`; eliminate implicit OCSP-key reuse and ephemeral fallback outside explicit `SigningKeyConfig::Demo` / `--demo-key`. Demo mode may generate a distinct ephemeral seal pair only when neither seal input is supplied. A half-configured pair is always an error.

Normalize one PEM/DER certificate to DER in `hoike-sign`; check certificate/key pairing, validity, and the supported certificate profile before publication. Use the existing CMS creation and `ahu::verify_seal_with_pins` on a fixed synthetic preflight payload, so the proof exercises the actual signing algorithm and certificate. Revalidate after material changes, including on-demand signing and rotation.

Reject the same OCSP/seal public key even through different filenames. Keep this at the loaded-signer boundary, not a path comparison. For ECDSA file and PKCS#11 signers, a common helper can sign the domain-separated public bytes `hoike:seal-ocsp-key-separation:v1` using the existing fallible `Signer`/`SignatureBitStringEncoding` bridge. A signature that verifies under the seal public key proves prohibited reuse; any signing/encoding error fails preflight. This avoids exporting HSM private keys or assuming public-key attributes are readable. An algorithm-distinct ML-DSA OCSP signer cannot equal the configured P-256 seal key.

Configured seal support stays P-256 software; existing library ML-DSA seals remain available. HSM/PQ seal configuration and HSM/PQ live nonce signing are separate extensions.

## S7. Explicit gossip policy and correct generation identity

Add `gossip.auth_mode = "required" | "permissive"`, default `required`. Trust mappings no longer select the policy implicitly. Required mode needs a local identity key, verifies every origin, and rejects unsigned/unknown/forged input. A single-node required configuration may trust its own key without peer mappings. Reject a conflicting mapping for the local node name.

Permissive mode explicitly permits unsigned legacy input while verifying signed input against provisioned named identities. Unknown or forged signed frames still reject, including when the trusted set is empty; make the broadcast handler require a verifier instead of retaining the no-verifier signed-frame bypass. Provision peer mappings before enabling outbound signatures. After all nodes send valid signatures, switch to required mode. Limit this migration claim to frame-aware versions; a wire tag does not make every historical binary compatible.

Use one auth-loading helper for `hoike check` and `GossipNode::start`. Invalid enabled configuration or key loading is a startup failure, not a warning-and-continue. Runtime partitions still leave OCSP serving independent of gossip.

Announce `ahu::manifest_digest(&bundle.manifest_bytes)`, not the index digest. Keep `bundle_url = None` until there is an actual retrieval route. Authentication of SWIM liveness, confidentiality, and automatic bundle retrieval remain explicit limitations.

## S8. Forwarding trust belongs to each configured CA

Build reusable reqwest clients once in `hoike-server`, keyed by unique CA label. With `forward_ca`, parse a nonempty PEM root bundle, disable built-in roots, and trust only those configured roots. Without it, preserve the actual bundled WebPKI-root behavior and describe it accurately. Continue hostname/time checking; never enable invalid-certificate or invalid-hostname acceptance.

Use the locked reqwest `0.12.28` APIs `Certificate::from_pem_bundle`, `ClientBuilder::tls_built_in_root_certs(false)`, and `add_root_certificate`. Keep the existing 10-second timeout, no-redirect policy, response size cap, content-type/status checks, and explicit `forward_insecure` HTTP exception. Reject an unreadable/empty/malformed CA file at startup and in `hoike check`. A configured `forward_ca` with a non-HTTPS target is a configuration error.

Add `forwarding.rs::build_forward_clients(config: &Config) -> Result<HashMap<String, reqwest::Client>, String>` and store the map in `AppState`. Make `AppState::new` fallible and update every caller; do not hide errors behind `expect`. Select by the already-resolved `ca_label`, so two CAs cannot accidentally share trust policies.

## S9. Freeze the actual draft wire profile

Document the existing **header version 0.1**, distinct from CBOR `format_version = 1` and package version 0.2. The current profile uses detached CMS `id-data` with matching content-type and message-digest signed attributes. The reader already enforces these CMS attributes; preserve that code instead of inventing an unallocated ahu OID.

Describe index bytes 46–47 as the algorithm discriminator (`0`, `2`, `3`, `4` for the currently defined algorithms), lexicographic sorting by `(entry_key, discriminator)`, and rejection of duplicate pairs. The existing index decoder preserves other `u16` discriminator values and includes them in ordering; preserving such a value does not advertise support for its signature algorithm. Retain current on-disk bytes; any future assigned content OID or incompatible layout requires a new explicit profile/version.

Publish independent golden wire vectors and correct the documented identical-generation restart exception: equal epoch is accepted only for the identical manifest digest; equal epoch with different contents rejects. Distinguish the format's optional delta/compression representations from the responder's restricted S3 serving profile. The draft's partial-completeness example cannot override the serving admission rule.

## S10. Verification and claim closure

Promote the nine audit reproductions into owned regression tests with the corrected expectation. Add real CLI subprocess and admin HTTP tests, per-CA TLS handshake tests, two-process lock/restart tests, and publication fault tests. Do not copy “bug reproduction passes” assertions into the permanent regression suite.

Dynamic admission fixtures use fresh validity windows, distinct synthetic OCSP/seal keys, and configured pins. Keep mocked structural fixtures only behind explicit demo admission where that is the behavior under test. Golden wire vectors may use an explicit fixed test verification time within their recorded certificate window; production clocks stay real.

Update README, CLI help, configuration examples, remediation/security documents, and demo instructions with each behavior change. The final ledger must distinguish implemented fixes from deployment qualification and deferred features. No fixed target test count is an acceptance criterion.

## Follow-on capability work

After F01–F12 are closed, prioritize automatic authenticated **full-bundle** distribution: configured peer endpoints, bounded download to temporary storage, existing admission/continuity checks, serialized installation, and continued serving during fetch failure/partition. A packet-supplied URL is not authorization to fetch arbitrary hosts. An urgent announcement initially uses this same full-bundle path.

Then consider mmap-backed payload ownership and benchmarks, live/seal backend expansion, and operator batching controls according to demand. Distributed signer fencing needs a separate deployment/coordinator design; the local state lock does not solve it. General PKIX, SWIM transport protection, and additional source adapters remain separately scoped work. SCVP remains excluded. Completing this remediation must not be described as implementing those capabilities.
