# hoike Audit Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Resolve all 12 audited mismatches with regression evidence, safe migration, and accurate capability claims.

**Architecture:** Put authenticated bundle admission in `hoike-core`, reuse existing CMS and transactional snapshot mechanisms, and make unsupported serving profiles reject explicitly. Keep signing-material policy in `hoike-sign` and transport policy in its existing gossip/server owners. Deliver small reviewed changes rather than adding a new coordination service.

**Tech Stack:** Existing Rust workspace, axum, reqwest 0.12.28, RustCrypto/CMS, rustix 1.1.4 for OS file locking, existing React/PatternFly UI types.

**Spec:** [Audit remediation design](../specs/2026-10-23-audit-remediation-design.md); evidence: [F01–F12 audit](../../promise-audit-2026-10-23.md).

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

- Trust plus a demo flag must still reject a bad seal: A1.
- Missing state after prior service must fail, even if an old signed bundle is still fresh: A4.
- Import failure at the descriptor commit boundary must recover a coherent generation and report its actual outcome: A5.
- Two CAs using different private roots must not share forwarding trust: C3.
- Enabling gossip signing incrementally must not discard legitimate preprovisioned peers or accept unknown signed origins: C2.

---

## Order and independently reviewable plans

The work spans separate ownership boundaries, so the executable detail is split into four plans. Each contains exact files, interfaces, regression contracts, checks, and commit-sized tasks.

1. **[A — Admission, verification, recovery, and import](2026-10-23-bundle-admission.md)**: five tasks; F01–F06. This is the release-critical path.
2. **[B — Signer material](2026-10-23-signer-materials.md)**: two tasks; F07–F08. Complete before switching production examples to strict signing.
3. **[C — Gossip and forwarding](2026-10-23-transport-remediation.md)**: three tasks; F09–F11. Independent after common configuration edits settle.
4. **[D — Wire contract and release closure](2026-10-23-wire-and-release.md)**: two tasks; F12 and final cross-cutting evidence.

Recommended merge order: **A1 → A2 → A3 → A4 → A5 → B1 → B2 → C1 → C2 → C3 → D1 → D2**. Every task carries its own tests and affected documentation. B/C research can proceed independently, but serialize edits to `main.rs`, `config.rs`, and shared fixtures rather than having simultaneous writers.

### Findings to deliverables

- F01 → A2: CLI/admin verification uses configured authentication; structural inspection is explicit.
- F02 → A1: missing trust fails normal admission; demo bypass is explicit and cannot override trust.
- F03 → A3: direct deltas reject; obsolete `storage.max_chain` configuration is removed.
- F04 → A4: explicit initialization, strict reopen, consistency checks, and exclusive state writer.
- F05 → A5: offline, authenticated, destination-aware, recoverable installation.
- F06 → A3: unsupported compressed input rejects before activation.
- F07 → B2: explicit production seal pair and loaded-key separation.
- F08 → B1: equivalent PEM/DER certificates and early key/certificate validation.
- F09 → C2: explicit required/permissive gossip modes and tested migration.
- F10 → C3: per-CA forwarding clients with working private-root configuration.
- F11 → C1: announcements identify the actual manifest bytes.
- F12 → D1: documented 0.1 wire profile and independent compatibility vectors.

## Preparation and execution tracking

- [x] Link approved private issue(s) to these tasks before implementation: [GHSA-7vcp-p3rm-jf24](https://github.com/czinda/hoike/security/advisories/GHSA-7vcp-p3rm-jf24), a private draft created with explicit user approval. Publication remains a separate decision.
- [x] Create isolated worktree `audit-remediation` on `fix/audit-remediation` at the audited baseline; copy the approved audit/spec/plans. Original presentation and audit artifacts remain in the original checkout.
- [ ] Recheck the current commit and relevant files against the baseline before each task; line numbers in the audit are evidence, not patch coordinates.
- [ ] Complete A1–A5 with failing-then-passing regression evidence.
- [ ] Complete B1–B2 with failing-then-passing regression evidence.
- [ ] Complete C1–C3 with failing-then-passing regression evidence.
- [ ] Complete D1–D2 and the release gates below.

Commit only the task's files, with the accurate `Assisted-by: Codex (Codex.ai/code)` trailer. No AI co-author trailer. Commands in the subplans describe future execution; this planning change implements none of the fixes.

## Migration sequence

1. Stop writers and back up the existing state directory, its immutable snapshots, configured bundle paths, and configuration as a coherent set.
2. Provision distinct persistent seal keys/certificates and matching pins/anchors. Migrate production commands to include `--seal-cert`; use explicit demo inputs only in lab fixtures.
3. Remove `storage.max_chain`; materialize and authenticate/reseal deltas outside edges if needed. Preserve predecessor continuity; do not turn a resealed output into an implicit history reset. Use full uncompressed inputs.
4. For an existing deployment, reuse its valid state. For a genuinely new state directory, run the explicit `hoike init-state --config PATH`. If prior state is missing, restore it instead of letting startup manufacture empty marks.
5. Stage gossip identity mappings with explicit permissive mode, enable signing across the frame-aware fleet, then move to required mode. Validate configured private forwarding roots.
6. Run read-only `hoike check`, authenticated `ahu verify`, and a canary restart/query. Perform imports while the selected state writer is stopped; start after a committed import.

**Rollback rule:** Preserve the latest high-water state. Do not restore an older snapshot merely to make an older binary accept it. Keep the descriptor schema compatible in this work; if implementation requires a schema change, stop and add a versioned migration before shipping. If a post-commit import path refresh fails, repair the alias from the committed generation rather than rolling back marks. A directory-fsync error at commitment requires stopping and inspecting persisted state.

## Completion evidence

- Every F01–F12 entry has an owned regression or wire/documentation contract check, a reviewed change, and updated user guidance.
- Default and `tls,metrics,pkcs11,dogtag-sync` workspace tests pass; production `ahu --no-default-features --lib` still builds.
- CLI subprocess/admin HTTP tests prove actual entry-point behavior; two-process tests prove state exclusion; TLS handshakes prove root isolation.
- Invalid inputs never mutate active state; fault injection proves coherent restart across pre-commit, committed, and indeterminate-fsync outcomes.
- Existing demo flows pass with explicit initialization and explicit trust/demo choices. UI API types and production build pass.
- Clippy, formatting, whitespace, and affected cross-platform CI checks pass. Run broad checks once after the integrated changes, repeating only for relevant changes or failures.
- Update the remediation ledger with actual commands/results and remaining live HSM/389 DS/power-loss qualification. Passing unit tests does not close those deployment gates.

## Follow-on roadmap

After this release, the next useful capability is verified full-bundle distribution between nodes, with bounded transfers, configured peer endpoints, admission reuse, and serialized online installation. Then evaluate mmap serving and live/seal backend expansion. Distributed signer leases, general PKIX, encrypted/authenticated SWIM, and new source adapters need their own requirements and plans. SCVP remains outside the product scope. These are recorded as feature work rather than being counted as completed by the 12-finding remediation.

## Plan self-review

- [x] Every design section S1–S10 and finding F01–F12 maps to an executable task.
- [x] Task interfaces agree across plans; no production API is called before its owning task creates it.
- [x] Each review-focus condition has an owned test with an observable assertion.
- [x] Each behavioral task has a meaningful fail/pass check and a focused commit boundary; D1/D2 verify existing byte/documentation contracts without manufacturing failures.
- [x] Migration, recovery, and post-commit error semantics are explicit; no security setting is silently ignored.

Coverage checked: S1→A1, S2→A2, S3→A3, S4→A4, S5→A5, S6→B1/B2, S7→C1/C2, S8→C3, S9→D1, S10→D2 plus each task's regressions. Self-review tightened writer-guard lifetime across background tasks, bootstrap ordering before signer/source side effects, explicit signature type arguments, the verifier-required gossip handler, and the distinction between pre-commit failure and post-rename durability uncertainty. Implementation and release checkboxes remain intentionally open.
