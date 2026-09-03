# Security Target — hoike against the Protection Profile for Application Software v1.4

**Status:** Evaluation-ready architecture, not an evaluated product. See the
[package posture disclaimer](README.md#posture-disclaimer-read-first).

**Conformance claim:** Exact conformance to the *NIAP Protection Profile for
Application Software, Version 1.4* (App PP v1.4). The TOE is a software application
(hoike) running on a general-purpose OS platform.

---

## 1. ST introduction

### 1.1 ST reference

| Field | Value |
|-------|-------|
| ST title | Security Target — hoike vs. App PP v1.4 |
| TOE | hoike 0.2.0 (OCSP responder) |
| PP | App PP v1.4 (exact conformance) |
| Evaluation status | Not evaluated (architecture-level ST) |

### 1.2 TOE overview

hoike is a Rust OCSP responder that serves pre-signed OCSP responses from `ahu`
bundles. Evaluated under the App PP, hoike is a **software application**: it runs as an
unprivileged process on a Linux/macOS host or in a distroless container
(`gcr.io/distroless/cc-debian12:nonroot`, `USER nonroot`, `Containerfile:26`),
consumes only network and filesystem resources of its platform, and uses the
platform's OS services for process isolation, ASLR, and (where configured) disk
encryption. See the [shared TOE definition](README.md#shared-toe-definition-normative-for-all-three-sts).

### 1.3 TOE description — platform interactions

| Resource class | Use | Evidence |
|----------------|-----|----------|
| Network (inbound) | OCSP HTTP (`0.0.0.0:2560`, plaintext by design); optional admin+UI TLS listener; optional metrics TLS listener; optional gossip UDP (`0.0.0.0:7946`) | `config.rs:314-316,64-67,57,37-39` |
| Network (outbound) | Nonce forwarding to upstream OCSP (`https://` enforced); 389 DS LDAP/LDAPS syncrepl; gossip peers | `handlers.rs:213-221`, `config.rs:145-155,269-296` |
| Filesystem | Read config TOML, bundle dir, signing keys, seal certs/anchors, gossip keys; write bundle dir, state DB, sync cookie | `config.rs:118-129`, `state.rs:179-202`, `dogtag_sync.rs:607-615` |
| Hardware | Optional PKCS#11 HSM via vendor shared library | `config.rs:229-249`, `pkcs11.rs` |
| Sensitive peripherals | **None** — no camera, microphone, or location access | (absent by inspection) |

---

## 2. Security problem definition

### 2.1 Threats (from App PP v1.4)

| Threat | Applicability to hoike |
|--------|------------------------|
| **T.NETWORK_ATTACK** | An attacker on the network attempts to man-in-the-middle admin credentials/sessions or inter-component traffic. Countered by TLS on management + inter-component channels; OCSP data plane is authenticated by response signatures, not transport. |
| **T.NETWORK_EAVESDROP** | Eavesdropping on admin/metrics/syncrepl channels to recover credentials or operational data. Countered by TLS (FTP_DIT_EXT.1). |
| **T.LOCAL_ATTACK** | Malicious/compromised platform apps attempt to exploit hoike via crafted input. Countered by Rust memory safety and bounded input parsing (MAX_REQUEST_SIZE). |
| **T.PHYSICAL_ACCESS** | Attacker with local disk access reads sensitive data at rest. **Partially** countered — hoike relies on platform disk encryption; it does not encrypt data at rest itself (FDP_DAR_EXT.1). |

### 2.2 Assumptions (from App PP v1.4)

| Assumption | Notes |
|------------|-------|
| **A.PLATFORM** | The OS platform is uncompromised and provides ASLR/DEP, process isolation, and (if relied on for DAR) disk encryption. hoike inherits anti-exploitation from platform + rustc defaults. |
| **A.PROPER_USER** | The operator does not deliberately misuse the TOE (e.g. does not set `--demo-key`, `forward_insecure`, or plaintext `ldap://` with a bind password in production). |
| **A.PROPER_ADMIN** | The administrator provisions operator bcrypt hashes, TLS material, and HSM/key custody competently and follows guidance. |

### 2.3 Organizational security policies

| OSP | Notes |
|-----|-------|
| **P.ALGORITHMS** | Only approved algorithms (ECDSA P-256, ML-DSA, SHA-256, AES/TLS suites from aws-lc-rs) are used for security functions. |
| **P.NO_PII** | The TOE does not collect end-user PII (no client IP capture). |

---

## 3. Security objectives

### 3.1 Objectives for the TOE

- **O.PROTECTED_COMMS** — protect management + inter-component data in transit (TLS).
- **O.INTEGRITY** — memory-safe implementation; bounded parsing; integrity-sealed
  bundles.
- **O.MANAGEMENT** — authenticated, role-based management; secure-by-default config.
- **O.QUALITY** — approved algorithms; vetted third-party libraries.
- **O.PROTECTED_STORAGE** — protect stored secrets *(Partial — see FCS_STO_EXT.1)*.

### 3.2 Objectives for the operational environment

- **OE.PLATFORM** — the OS provides ASLR/DEP, isolation, and disk encryption.
- **OE.PROPER_USER / OE.PROPER_ADMIN** — competent, non-hostile operation.
- **OE.TRUSTED_UPDATE** — because the TOE does not verify update signatures itself,
  the environment must obtain artifacts over an authenticated channel and verify
  provenance out of band *(compensates for the FPT_TUD_EXT.1 gap)*.

---

## 4. Extended components

The App PP defines the extended SFRs used below (all `_EXT`): FCS_RBG_EXT,
FCS_STO_EXT, FDP_DEC_EXT, FDP_NET_EXT, FDP_DAR_EXT, FMT_CFG_EXT, FMT_MEC_EXT,
FPR_ANO_EXT, FPT_AEX_EXT, FPT_API_EXT, FPT_IDV_EXT, FPT_LIB_EXT, FPT_TUD_EXT,
FTP_DIT_EXT. No new extended components are defined by this ST.

---

## 5. Security functional requirements

Status legend as in the [package README](README.md#cross-pp-sfr-index).

### 5.1 Cryptographic support (FCS)

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FCS_RBG_EXT.1** | Random bit generation | **Partial** | Platform RBG via `getrandom` (session tokens `auth.rs:128-133`; ML-DSA demo seed `ml_dsa_bridge.rs:141-143`); TLS DRBG from `aws-lc-rs`. ECDSA uses deterministic RFC 6979. Not a *claimed/validated* entropy source. |
| **FCS_STO_EXT.1** | Storage of credentials | **Partial** | Operator secrets are stored as **bcrypt hashes only** (`config.rs:103-116`), never plaintext passwords. **But** HSM PIN and LDAP bind password can be given as plaintext in TOML (indirection via `*_env` preferred: PIN `orchestrate.rs:602-627`, LDAP `orchestrate.rs:452-470`). No encrypted keystore/keyring; **no `zeroize` of key material** (transitive dep only). |
| **FCS_COP.1/SigGen** | Signature generation | **Met** | ECDSA P-256 (`verify.rs:14`, `seal.rs:30`); ML-DSA-44/65/87 (`ml_dsa_bridge.rs:27-29`, OIDs 2.16.840.1.101.3.4.3.17/18/19). |
| **FCS_COP.1/Hash** | Hashing | **Met** | SHA-256 (`sha2`); SHA-1 retained for RFC-compat CertID/ResponderID only (`generate.rs:86`). SHA-384/512 not used. |
| **FCS_CKM_EXT.1** | Key generation / no plaintext key export | **Partial** | Keys loaded from PKCS#8 files (`keyfile.rs:60-93`) or PKCS#11 HSM (`pkcs11.rs`). No production keygen in-app; demo key is a **hardcoded seed `[42u8;32]`** (`keyfile.rs:96-99`), reachable only via explicit `--demo-key`/`type='demo'` with a runtime warning. |

### 5.2 User data protection (FDP)

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FDP_DEC_EXT.1** | Access to platform resources | **Met** | Uses only network + filesystem (+ optional PKCS#11); **no sensitive peripherals** (no camera/mic/location). Enumerated §1.3. |
| **FDP_NET_EXT.1** | Network communications | **Met** | Inbound/outbound channels enumerated and operator-configured (`config.rs`); no undocumented connections. |
| **FDP_DAR_EXT.1** | Encryption of sensitive data at rest | **Partial** | **No application-layer encryption at rest.** ahu bundles are CMS-**signed, not encrypted** (`orchestrate.rs:256`); state DB (`state.rs:179-202`) and sync cookie (`dogtag_sync.rs:607-615`) are plaintext JSON/bytes. Private keys are not written by hoike (delegated to FS/HSM). DAR relies on **platform disk encryption** (OE.PLATFORM). |

### 5.3 Identification, authentication, security management (FIA / FMT)

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FMT_CFG_EXT.1** | Secure by default | **Met** | No default/hardcoded production credentials; `AdminConfig.operators` defaults empty (`config.rs:96-101`); admin returns 503 when unconfigured (`auth.rs:34-43`); default role is least-privileged `viewer` (`config.rs:114-116`); demo key is opt-in + warned; file perms are the platform's responsibility. |
| **FMT_MEC_EXT.1** | Use of supported config mechanism | **Met** (with note) | Single read-only TOML file (`Config::from_file`, `config.rs:342-346`); hoike never rewrites its config. App PP prefers the *platform's* config mechanism; hoike uses a conventional file — documented deviation. |
| **FMT_SMF.1** | Specification of management functions | **Met** | Admin API (`admin/mod.rs:19-45`): login/logout, status, bundles reload/inspect/verify/diff/extract/apply, sign, rotate, gossip, config, state, query. CLI: `serve`, `check`, `sign`, `query`, `import` (`main.rs:18-110`). |

### 5.4 Privacy (FPR)

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FPR_ANO_EXT.1** | User consent for transmission of PII | **Met (N/A by design)** | hoike collects **no client PII** — no `ConnectInfo`/`peer_addr`/`X-Forwarded-*` handling (grep-confirmed across handlers/admin). It processes certificate-status objects, not user records. Certificate serials (identifiers, not PII) appear in audit/debug (`handlers.rs:255`). |

### 5.5 Protection of the TSF (FPT)

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FPT_AEX_EXT.1** | Anti-exploitation | **Partial** | Primary control is **Rust memory safety** (edition 2024, toolchain 1.97 `rust-toolchain.toml:2`); exactly **one** audited `unsafe` block — the mmap syscall with a documented SAFETY invariant (`mmap_bundle.rs:56-62`). **But** there is **no `[profile.release]`** and **no `.cargo/config.toml`/RUSTFLAGS** — no explicit LTO, `panic=abort`, `overflow-checks`, RELRO, PIE, or stack-protector. ASLR/DEP/NX rely on rustc + platform defaults. Container `strip`s binaries (`Containerfile:17`). |
| **FPT_API_EXT.1** | Use of supported platform APIs | **Met** | Uses documented Rust std + platform syscalls via vetted crates (tokio, axum, rustls); no undocumented/private APIs. |
| **FPT_IDV_EXT.1** | Software identification (versioning) | **Gap** | Crates declare `0.2.0` (`*/Cargo.toml:3`) but the clap CLI wires **no `version`** attribute (`main.rs:6-10`, `ahu_main.rs:7`) — `hoike --version`/`ahu --version` do not print a version. Closing work: add `#[command(version)]` from `CARGO_PKG_VERSION`. |
| **FPT_LIB_EXT.1** | Use of third-party libraries | **Met** | `Cargo.lock` pins 402 packages; security-relevant set inventoried (rustls 0.23.43, aws-lc-rs 1.18.1, ml-dsa 0.1.1, x509-ocsp 0.2.1, cms 0.3.0-pre.2, cryptoki 0.12, ldap3 0.12.1, ed25519-dalek 2.2.0, bcrypt 0.17.1). Monthly `cargo audit` in CI (`ci.yml:9,233-246`). Intentional major-version duplicates (der 0.7/0.8, p256 0.13/0.14) documented in crate manifests. |
| **FPT_TUD_EXT.1/.2** | Trusted update | **Gap** | Releases ship cross-built tarballs + container images with **unsigned SHA-256 checksums only** (`ci.yml:137-141`, `.gitlab-ci.yml:122`). **No signature verification** — no cosign/sigstore/GPG/minisign anywhere. **No in-product update** mechanism (operator-driven binary/image replacement). Closing work: sign artifacts + images; document verification. Compensated by OE.TRUSTED_UPDATE. |

### 5.6 Trusted path/channels (FTP)

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FTP_DIT_EXT.1** | Protection of data in transit | **Met** (management/inter-component) | TLS 1.2 floor + 1.3 on admin (`tls.rs:29-72`) and metrics listeners; `https://` enforced on the forward client with a real root store (`handlers.rs:287-296`); LDAPS/StartTLS-before-bind for syncrepl so the bind password never crosses cleartext (`dogtag_sync.rs:190-216`). Gossip broadcasts Ed25519-signed (`crypto.rs`). **OCSP data plane is plaintext by design** (signed responses; App PP allows no-DIT where no sensitive data transits — here the sensitive data is authenticated end to end). See §7 rationale. |

> **Cross-reference:** the TLS mechanism claimed here satisfies FCS_TLSS_EXT.1 in the
> [PPCA ST](hoike-st-ppca-v2.1.md) and the [TLS FP ST](hoike-st-tls-fp-v1.1.md).

### 5.7 Security audit (FAU)

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FAU_GEN.1** | Audit generation | **Met** | `audit!` macro → `tracing` `audit` target, always on (`obs.rs:20-25`). Events: `request_rejected` (bundle_expired / unauthorized w/ serial, `handlers.rs:137-142,252-257`), `bundle_load_failed`, `signer_generation(_failed)`, bundle-admin ops. |
| **FAU_GEN.2** | User identity association | **Partial** | Events record `ca`, `epoch`, `serial`, `reason` but **omit operator identity** on management/signing actions; the session carries `operator_name` (`state.rs:44`) but it is not threaded into `audit!`. Closing work: add `operator_name` to admin-action audit calls. |

---

## 6. Security assurance requirements

The App PP mandates the **EAL1-equivalent** package with PP-specific assurance
activities. For this architecture-level ST the SARs are addressed by design evidence,
not an evaluation lab:

| SAR class | How addressed here |
|-----------|--------------------|
| ADV_FSP.1 (basic functional spec) | This ST §5 + `hoike-design.md` + `ahu-format-spec.md`. |
| AGD_OPE.1 / AGD_PRE.1 (guidance) | `README.md`, `CLAUDE.md`, `hoike check`, config comments. |
| ALC_CMC.1 / ALC_CMS.1 (config mgmt) | Git + `Cargo.lock`; per-crate versioning (but see FPT_IDV_EXT.1 gap). |
| ALC_TSU_EXT.1 (timely security updates) | Monthly `cargo audit`; **update authenticity is a gap** (FPT_TUD_EXT.1). |
| ATE_IND.1 (independent testing) | 175 test functions; 20-check OCSP conformance suite. |
| AVA_VAN.1 (vulnerability survey) | Rust memory safety; `cargo audit`; single audited `unsafe`. |

---

## 7. TOE summary specification (rationale highlights)

- **T.NETWORK_ATTACK / T.NETWORK_EAVESDROP → FTP_DIT_EXT.1.** All credential-bearing
  and operational channels (admin, metrics, syncrepl, forward) are TLS-protected or
  refuse to run in cleartext under `hoike check`. The OCSP data plane carries only
  signed, self-authenticating responses, so it is left plaintext deliberately — an
  evaluator should assess this against the App PP's "sensitive data" definition: the
  OCSP payload's integrity/authenticity is provided by FCO_NRO_EXT.2, and it contains
  no confidential data.
- **T.LOCAL_ATTACK → FPT_AEX_EXT.1 / FPT_API_EXT.1.** Rust eliminates the memory-safety
  vulnerability classes that dominate CVE data for native network daemons. The residual
  risk is the single `unsafe` mmap block and the *absence* of explicit build hardening;
  the closing work (release profile + RUSTFLAGS) is low-effort and named in the gap
  table.
- **T.PHYSICAL_ACCESS → FDP_DAR_EXT.1.** Honestly **Partial**: hoike leans on platform
  disk encryption. The most sensitive at-rest artifacts are private keys, which hoike
  does not write (delegated to the FS/HSM); the state DB and sync cookie are
  non-secret operational data.
- **P.ALGORITHMS → FCS_COP.1.** Only approved algorithms are wired; the valid
  signature-alg set is constrained in config (`config.rs:361`) and unknown algs are
  rejected.
- **P.NO_PII → FPR_ANO_EXT.1.** Confirmed by the absence of any client-IP capture path.

### App PP conformance summary

| Verdict | SFRs |
|---------|------|
| **Met** | FCS_COP.1/SigGen, FCS_COP.1/Hash, FDP_DEC_EXT.1, FDP_NET_EXT.1, FMT_CFG_EXT.1, FMT_MEC_EXT.1, FMT_SMF.1, FPR_ANO_EXT.1, FPT_API_EXT.1, FPT_LIB_EXT.1, FTP_DIT_EXT.1, FAU_GEN.1 |
| **Partial** | FCS_RBG_EXT.1, FCS_STO_EXT.1, FCS_CKM_EXT.1, FDP_DAR_EXT.1, FPT_AEX_EXT.1, FAU_GEN.2 |
| **Gap** | FPT_IDV_EXT.1, FPT_TUD_EXT.1/.2 |

**Bottom line:** hoike's App PP posture is strong on communications, memory safety,
secure defaults, and dependency hygiene, and weak on **trusted update authenticity**
and **runtime version reporting** (two clear gaps), with honest Partials on at-rest
encryption, key-material zeroization, and build hardening. None of the gaps are
architectural — each has a low-to-moderate-effort closing path named above.
