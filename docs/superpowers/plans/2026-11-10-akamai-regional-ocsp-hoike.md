# Hoike + Akamai EdgeWorkers Regional OCSP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make no-nonce OCSP responses safely cacheable worldwide (Akamai), while keeping nonce-bearing OCSP responses uncacheable and routed to Hoike’s live signer network, with revocation visibility target <5 minutes.

**Architecture:** Add an absolute `max-age` cap for cacheable responses and (optionally) emit Akamai `Surrogate-Key` tags for cacheable responses so a CDN can purge by key. Keep nonce-bearing responses `no-store`.

**Tech Stack:** Rust, axum (`hoike-server`), hoike-core request parsing, HTTP header shaping.

**Spec:** `docs/superpowers/specs/2026-11-10-akamai-regional-ocsp-hoike-design.md`

## Global Constraints

- Revocation visibility target: **< 5 minutes** (cache behavior must not exceed this).
- Akamai-specific behavior must be **optional** and **disabled by default**.
- Nonce-bearing responses must be **uncacheable**.

## Review Focus

- `max-age` must never exceed the configured cap (test asserts `max-age <= cap`).
- `Surrogate-Key` must not appear unless Akamai mode is enabled.
- Nonce-bearing responses remain `no-store` regardless of Akamai mode.
- Changes must not break existing conformance/e2e tests.

---

### Task 1: Add max-age cap to server config and enforce in success responses

**Files:**
- Modify: `crates/hoike-core/src/config.rs`
- Modify: `crates/hoike-server/src/handlers.rs`
- Test: `crates/hoike-server/tests/conformance.rs`

**Interfaces:**
- Produces: new config field `server.max_age_cap_secs: u64` (default `240`).
- Produces: success responses enforce `max_age = min(max_age, server.max_age_cap_secs)`.

- [ ] **Step 1: Write failing test asserting max-age is capped**

Add to `crates/hoike-server/tests/conformance.rs` near the existing cache-control test:

```rust
#[tokio::test]
async fn conformance_http_cache_control_is_capped() {
    // Using the standard test config, assert max-age <= 240.
    // Parse cache-control max-age value and compare.
    assert!(true == false, "implement");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --workspace -q conformance_http_cache_control_is_capped`
Expected: FAIL (test not found / assertion fails).

- [ ] **Step 3: Implement config default + enforcement**

In `hoike-core` config:
- add `server.max_age_cap_secs` with `#[serde(default = "...")]` and default `240`.

In `hoike-server`:
- apply cap when building the cache-control header for cacheable success responses.

- [ ] **Step 4: Run focused tests**

Run: `cargo test --workspace -q conformance_http_cache_control_is_capped`
Expected: PASS

Run: `cargo test --workspace -q conformance_http_cache_control`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/hoike-core/src/config.rs crates/hoike-server/src/handlers.rs crates/hoike-server/tests/conformance.rs
git commit -m "feat: cap OCSP cache max-age for CDN safety"
```

### Task 2: Add optional Akamai surrogate-key tagging for cacheable responses

**Files:**
- Modify: `crates/hoike-core/src/config.rs`
- Modify: `crates/hoike-server/src/handlers.rs`
- Test: `crates/hoike-server/tests/conformance.rs`
- Create: `docs/akamai-edgeworkers.md`

**Interfaces:**
- Produces: config `server.akamai.enabled: bool` default `false`.
- Produces: config `server.akamai.surrogate_key_prefix: String` default `"hoike-ocsp"`.
- Produces: when enabled, cacheable (no-nonce) success responses include:
  - `Surrogate-Key: <prefix>-<ca_label>-<entry_key_hex>`

- [ ] **Step 1: Write failing test: Surrogate-Key only when enabled**

```rust
#[tokio::test]
async fn conformance_surrogate_key_only_when_enabled() {
    // With default config, successful responses must NOT include Surrogate-Key.
    // With an alternate config enabling server.akamai.enabled, they MUST include it.
    assert!(true == false, "implement");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --workspace -q conformance_surrogate_key_only_when_enabled`
Expected: FAIL.

- [ ] **Step 3: Implement config + header emission**

- Add `server.akamai` config struct under the server config.
- In request handling, only for cacheable success responses, compute entry key hex from parsed `CertID.entry_key` and set `Surrogate-Key` when enabled.

- [ ] **Step 4: Add docs for EdgeWorkers**

Create `docs/akamai-edgeworkers.md` describing:
- Expected behavior: cache no-nonce responses; do not cache nonce-bearing.
- How to purge by `Surrogate-Key` (high level, no credentials).

- [ ] **Step 5: Run focused tests**

Run: `cargo test --workspace -q conformance_surrogate_key_only_when_enabled`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add crates/hoike-core/src/config.rs crates/hoike-server/src/handlers.rs crates/hoike-server/tests/conformance.rs docs/akamai-edgeworkers.md
git commit -m "feat: optional Akamai surrogate-key tagging for OCSP responses"
```

### Task 3: Full verification

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: PASS

- [ ] **Step 2: Commit any remaining fixes**

```bash
git add -A
git commit -m "test: ensure Akamai OCSP changes pass conformance"
```
