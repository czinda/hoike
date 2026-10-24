# Gossip and Forwarding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close F09–F11 with correct generation identifiers, explicit gossip rollout policy, and working per-CA TLS roots.

**Architecture:** Keep payload identity/authentication in `hoike-gossip` and announcement construction in `hoike-server`. Replace the global default forwarding client with startup-validated clients keyed by resolved CA label.

**Tech Stack:** Existing foca/Ed25519, serde, reqwest 0.12.28, rustls/axum test listeners.

**Spec:** [Design S7–S8 and S10](../specs/2026-10-23-audit-remediation-design.md); [execution order](2026-10-23-audit-remediation.md).

## Global Constraints

- Keep the declared Rust floor `1.85`, the pinned development toolchain `1.97`, and the existing `der` 0.7/0.8 boundary.
- Edge nodes must hold no OCSP or seal private key.
- Use synthetic fixtures and current source windows for admission/production tests.
- Configured trust must never fall back to permissive behavior after a validation error.
- Existing valid full, uncompressed bundles and well-formed persisted state remain readable.

## Review Focus

- An index-identical generation with changed manifest metadata must have a different advertised manifest digest: C1.
- Unknown signed frames must fail even when unsigned compatibility is explicitly enabled: C2.
- Conflicting local identity mappings and unreadable configured keys must fail before serving, while runtime partitions must not stop OCSP service: C2.
- Two CA labels with different private roots must remain isolated even when their endpoints use the same hostname: C3.
- A private-root change must preserve hostname checking, no redirects, body caps, content-type checks, and timeouts: C3.

---

### Task 8: C1 — Announce the actual manifest digest — F11

**Files:** Modify `crates/hoike-server/src/lib.rs`; create `crates/hoike-server/tests/gossip_announcements.rs`.

**Interfaces:** Preserve `announce_bundle_scopes(&hoike_gossip::GossipNode, &[u8])`; consume existing `ahu::manifest_digest(&[u8]) -> [u8; 32]`.

- [ ] **Write** `announcement_identifies_manifest_not_index`. Start a local ephemeral gossip node and capture the real announcer's delivered message, as in audit P08. Construct two valid full bundles with identical index bytes and different epoch/window metadata. Assert:
  ```rust
  assert_eq!(advertised_a, ahu::manifest_digest(&bundle_a.manifest_bytes));
  assert_eq!(advertised_b, ahu::manifest_digest(&bundle_b.manifest_bytes));
  assert_ne!(advertised_a, advertised_b);
  assert!(bundle_url.is_none());
  ```
  Assert one announcement per manifest scope. This exercises construction and delivery, not only the digest helper.
- [ ] **Run red:** `cargo test -p hoike-server --locked --test gossip_announcements`.
- [ ] **Implement** the existing manifest helper in the announcer; correct its doc comment. Do not fabricate a URL for a route that does not exist.
- [ ] **Run green:** repeat the focused command and `cargo test -p hoike-gossip --locked`.
- [ ] **Commit:** `fix: announce serialized manifest digests`.

### Task 9: C2 — Explicit gossip authentication policy and migration — F09

**Files:** Modify `crates/hoike-gossip/src/{config.rs,crypto.rs,node.rs,broadcast.rs,lib.rs}`, `crates/hoike-core/src/config.rs`, `crates/hoike-core/tests/config_validation.rs`, `crates/hoike-cli/src/main.rs`, `crates/hoike-server/tests/gossip_announcements.rs`, `README.md`, `docs/review-remediation.md`, `docs/niap-ppca-gap-matrix.md`, and affected test/demo gossip configuration; create `crates/hoike-cli/tests/gossip_startup.rs`.

**Interfaces:** Add exported `AuthMode::{Required, Permissive}`, serde lowercase/default Required, to `hoike-gossip`. Add `auth_mode: AuthMode` to its `GossipConfig`. The core TOML section uses `auth_mode: String` with default `"required"`, validated against those two values; CLI bridges it with `AuthMode::from_str`. Add:

```rust
pub fn load_authentication(config: &GossipConfig)
    -> Result<(Option<GossipSigner>, GossipVerifier), GossipCryptoError>;
```

Extend the existing crypto error enum with `Config(String)` for invalid policy/identity configuration. `AuthMode::from_str` uses that error type. `GossipNode::start` and `hoike check` call this helper for enabled gossip. Change `HoikeBroadcastHandler::new(tx: tokio::sync::mpsc::Sender<GossipMessage>, verifier: GossipVerifier) -> Self` and its field to require a verifier, removing the `Option` bypass. Preserve the existing verifier's named-origin checks.

- [ ] **Write** `permissive_accepts_known_signed_and_unsigned_peers`, `permissive_rejects_unknown_and_forged_signed_frames`, `required_rejects_unsigned_and_missing_identity`, `local_identity_conflict_rejects`, and `enabled_gossip_key_failure_aborts_startup`. Use keys A/B, both provisioned, and an unprovisioned key C. Assert:
  ```rust
  assert!(matches!(permissive.check(&b_signed), VerifyOutcome::Accept(_)));
  assert!(matches!(permissive.check(&unsigned), VerifyOutcome::Accept(_)));
  assert!(matches!(permissive.check(&c_signed), VerifyOutcome::Reject(_)));
  assert!(matches!(required.check(&unsigned), VerifyOutcome::Reject(_)));
  assert!(!missing_configured_key_exit.success());
  ```
  Repeat the unknown-signed rejection with an empty peer set. Preserve forged-origin and bounded-message/table tests. Add a loopback two-node transition test with a channel-based deadline: mapped peers remain visible during permissive signing rollout; unsigned traffic rejects after required mode. With a correctly configured node and unavailable peers, a valid local OCSP query must still succeed.
- [ ] **Run red:** `cargo test -p hoike-gossip --locked`; `cargo test -p hoike-cli --locked --test gossip_startup`.
- [ ] **Implement** S7: explicit policy, always-present verifier, local key/name consistency, and fatal enabled-config/key startup failures. Disabled gossip does not require unused key material. Keep packet loss/partition handling independent of serving. Update `hoike check` to print effective mode and unsigned acceptance accurately. Update C1's local fixture to provide a real identity or explicit permissive mode. Document the provision → permissive → sign → required sequence and its frame-aware-version prerequisite.
- [ ] **Run green:** gossip and startup tests, core config tests, and C1's server test. Verify CLI help/config errors and that no `peer_keys` example still claims enforcement. Retain rejection of nonempty legacy `peer_keys`.
- [ ] **Commit:** `fix: make gossip authentication rollout explicit`.

### Task 10: C3 — Startup-validated per-CA forwarding clients — F10

**Files:** Create `crates/hoike-server/src/forwarding.rs`, `crates/hoike-server/tests/forward_tls.rs`; modify `crates/hoike-server/src/{lib.rs,state.rs,handlers.rs}`, `crates/hoike-core/src/config.rs`, `crates/hoike-cli/src/main.rs`, all existing `AppState::new` callers, `README.md`, and `docs/review-remediation.md`.

**Interfaces:** Export `build_forward_clients(&Config) -> Result<HashMap<String, reqwest::Client>, String>` for startup/check reuse; retain no root material in global process state. Add `AppState::forward_client_for(&self, label: &str) -> Option<&reqwest::Client>` backed by an `Arc<HashMap<...>>`. Change `AppState::new(ResponderState, Config) -> Result<Self, String>`. Change the private request helper to `forward_request(client: &reqwest::Client, url: &str, der_bytes: &[u8], allow_insecure: bool) -> Response`.

- [ ] **Write** `configured_private_root_succeeds`, `private_roots_are_isolated_per_ca`, `wrong_hostname_and_wrong_root_reject`, and `invalid_root_configuration_fails_startup`. Build two fresh synthetic P-256 TLS CA/leaf sets with a `localhost` SAN using the existing X.509/signing dependencies in test code. Start actual loopback TLS listeners under `#[cfg(feature = "tls")]`; no invalid-cert test bypass. Assert:
  ```rust
  assert!(client_a.get(&url_a).send().await.is_ok());
  assert!(client_b.get(&url_a).send().await.is_err());
  assert!(client_a.get(&wrong_hostname_url).send().await.is_err());
  assert!(build_forward_clients(&empty_root_config).is_err());
  assert!(build_forward_clients(&http_with_root_config).is_err());
  ```
  Test the actual OCSP forwarding handler with one authenticated upstream response, not only raw reqwest calls. Preserve the existing redirect, chunked body-cap, cleartext opt-in, and wrong-content-type checks. A non-forwarding CA does not require a client. Duplicate labels reject rather than overwriting a root policy.
- [ ] **Run red:** `cargo test -p hoike-server --locked --features tls --test forward_tls`; run default server unit forwarding regressions as well.
- [ ] **Implement** S8 with one reused client per forward-enabled label. For custom roots, call `Certificate::from_pem_bundle`, reject an empty parsed bundle, disable built-in roots, and add each configured root. Without custom roots, use the existing bundled WebPKI defaults. Keep timeout 10 seconds, no redirects, and all existing response validation. Propagate constructor errors through CLI/tests; select the client by the resolved lookup's `ca_label`. `hoike check` invokes client construction without opening a listener or sending a request. Remove the system-root workaround text.
- [ ] **Run green:** the real TLS test above, `cargo test -p hoike-server --locked`, and `cargo test -p hoike-cli --locked`. Compile all updated constructor callers. The feature-enabled test in plan D also repeats the handshake cases in the integrated build.
- [ ] **Commit:** `fix: honor per-CA forwarding trust roots`.

## Dependency evidence

The locked reqwest source exposes `from_pem_bundle`, `tls_built_in_root_certs`, and `add_root_certificate`; `rustls-tls` selects WebPKI roots. Context7 was quota-limited during planning, so those choices were checked against the installed 0.12.28 source and its [versioned feature documentation](https://docs.rs/crate/reqwest/0.12.28/features). Recheck if the lockfile changes before implementation.
