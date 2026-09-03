# Security Target — hoike against the Protection Profile for Certification Authorities v2.1 (PP 420)

**Status:** Evaluation-ready architecture, not an evaluated product. See the
[package posture disclaimer](README.md#posture-disclaimer-read-first).

**Conformance claim:** Demonstrable conformance to the *NIAP Protection Profile for
Certification Authorities, Version 2.1* (PP 420), **scoped to the OCSP-responder role**.
hoike implements the profile's certificate-status / proof-of-origin obligations; SFRs
about certificate issuance, lifecycle, and CA-key custody are claimed **N/A (issuing-CA
scope)** with rationale. This ST supersedes the tabular
[`../niap-ppca-gap-matrix.md`](../niap-ppca-gap-matrix.md) as the formal document.

---

## 1. ST introduction

### 1.1 ST reference

| Field | Value |
|-------|-------|
| ST title | Security Target — hoike vs. PPCA v2.1 (PP 420) |
| TOE | hoike 0.2.0 (OCSP responder) |
| PP | PPCA v2.1 (PP 420) + dependent Functional Package for TLS v1.1 |
| Evaluation status | Not evaluated (architecture-level ST) |

### 1.2 TOE overview and PPCA scoping

**hoike is not a Certification Authority.** It does not issue certificates, run a
CMP/EST/ACME enrollment interface, decide revocation, or custody a CA key that signs
end-entity certificates. In a PPCA evaluation, hoike is the **certificate-status
provider** — the component satisfying FDP_OCSPG_EXT and FCO_NRO_EXT — while the issuing
CA (Dogtag/RHCS in the reference lab) is a separate TOE. See the
[shared TOE definition](README.md#shared-toe-definition-normative-for-all-three-sts)
and the N/A scoping in §5.6.

### 1.3 TOE type

An OCSP responder with a two-tier architecture: a **signer tier** (holds keys, generates
+ CMS-seals `ahu` bundles from CRL / 389 DS syncrepl revocation data) and a **keyless
edge tier** (serves pre-signed responses). This separation is itself a security property:
the horizontally-scalable serving surface holds no private key.

---

## 2. Security problem definition

### 2.1 Threats

| Threat (PPCA idiom) | Applicability |
|---------------------|---------------|
| **T.PRIVILEGED_USER_ERROR** | Operator misconfiguration exposes management or inter-component channels. Countered by secure defaults + `hoike check` diagnostics. |
| **T.TSF_COMPROMISE / T.UNAUTHORIZED_ACCESS** | Attacker reaches the management surface to forge/reload bundles or rotate keys. Countered by TLS trusted path + bcrypt/RBAC. |
| **T.UNAUTHORIZED_UPDATE (status data)** | Attacker replays stale/rolled-back revocation status. Countered by the anti-rollback high-water store. |
| **T.WEAK_CRYPTO** | Weak/forged signatures on status responses. Countered by approved sig algs + enforced proof of origin. |
| **T.NETWORK_DISCLOSURE** | Credentials (LDAP bind, admin session) cross the wire in cleartext. Countered by LDAPS/StartTLS + admin TLS. |

### 2.2 Assumptions

| Assumption | Notes |
|------------|-------|
| **A.TRUSTED_ISSUER** | The upstream issuing CA and its revocation feed (CRL / 389 DS) are authoritative and trustworthy. |
| **A.PHYSICAL / A.PLATFORM** | The host and HSM are physically protected; the OS is uncompromised. |
| **A.TRUSTED_ADMIN** | Administrators are competent and non-hostile. |

### 2.3 Organizational security policies

| OSP | Notes |
|-----|-------|
| **P.ACCESS_BANNER / P.AUDIT** | Security-relevant events are audited (FAU_GEN.1). |
| **P.ALGORITHMS** | Approved signature/hash algorithms only. |
| **P.INTEGRITY** | Status responses carry enforced proof of origin (signatures). |

---

## 3. Security objectives

### 3.1 For the TOE

- **O.CORRECT_STATUS** — RFC 6960-conformant status with bounded validity windows.
- **O.PROOF_OF_ORIGIN** — every status response is signed (FCO_NRO_EXT.2).
- **O.ANTI_ROLLBACK** — monotonic status epochs; reject rolled-back bundles.
- **O.PROTECTED_MGMT** — TLS trusted path + authenticated RBAC management.
- **O.PROTECTED_CHANNELS** — authenticated/encrypted inter-component channels.
- **O.KEY_PROTECTION** — private keys in HSM or protected files; seal key distinct
  from signing key *(Partial in lab posture)*.

### 3.2 For the operational environment

- **OE.ISSUING_CA** — a separate, trustworthy CA performs issuance/revocation
  decisioning and supplies revocation data.
- **OE.HSM** — a validated HSM provides key custody (lab uses SoftHSM — Partial).
- **OE.PLATFORM / OE.PHYSICAL / OE.TRUSTED_ADMIN**.

---

## 4. Extended components

Uses the PPCA extended families FDP_OCSPG_EXT (OCSP generation) and FCO_NRO_EXT
(enforced proof of origin), plus FCS_TLSS_EXT / FCS_TLSC_EXT from the TLS FP and
FPT_ITT.1 for inter-node TSF-data protection. No new extended components defined here.

---

## 5. Security functional requirements

Status legend as in the [package README](README.md#cross-pp-sfr-index).

### 5.1 Certificate status & proof of origin (core OCSP obligations)

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FDP_OCSPG_EXT.1** | OCSP response generation per RFC 6960 | **Met** | Pre-signed responses from `ahu` bundles (`router.rs:84-137`, `handlers.rs:80-261`); live/on-demand signing (`live.rs:39-98`, `orchestrate.rs`); request parse w/ 8 KiB cap + entry-key = SHA-256(CertID DER) (`request.rs:8,63-68`); RFC 6960/9919 conformance suite (`tests/conformance.rs`). |
| **FCO_NRO_EXT.2** | Enforced proof of origin | **Met** | Every `BasicOCSPResponse` is signed (`generate.rs:547-590`); delegated responder cert per RFC 9919 §3.2.2 (`generate.rs:564-584`); ResponderID = SHA-1(SPKI) key hash (`generate.rs:592-602`). Error responses are the static unsigned 5-byte DER RFC 6960 permits (`response.rs:1-33`). |
| **Response validity windows** | Bounded thisUpdate–nextUpdate | **Met** | Batch window + `validity_secs` (`config.rs`); expiry guard refuses stale bundles (`handlers.rs:124-145`); freshness gauges (`obs.rs`). |
| **Anti-rollback of status data** | Monotonic status epochs | **Met** | Persistent high-water store, continuity + rollback checks on load (`state.rs:105-145`, `MAX_EPOCH_JUMP=10000` `state.rs:11-15`); durable fsync+atomic-rename persist (`state.rs:175-217`); applied at routing (`router.rs:278-325`); epoch from high-water, not wall-clock (`orchestrate.rs:165-177`). |

### 5.2 Trusted path & trusted channels (transport hardening)

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FCS_TLSS_EXT.1** | TLS server, server authentication | **Met** | rustls 0.23 + explicit `aws_lc_rs` provider, TLS 1.2 floor + 1.3 (`tls.rs:29-72`, `tls.rs:34,39-41`), `tls` feature; terminates on admin + metrics listeners. |
| **FCS_TLSS_EXT.2** | TLS server, mutual (client-cert) auth | **Partial** | Wired but off by default: `admin_tls.client_ca` builds a `WebPkiClientVerifier` (`tls.rs:43-62`); flip-the-flag, no code change. |
| **FTP_TRP.1** | Trusted path for remote administration | **Met** | Admin API + UI on a dedicated TLS listener (`admin_listen`/`admin_tls`; `build_admin_router_standalone` `lib.rs:136-142`); bcrypt/RBAC login over TLS; `hoike check` warns on admin-on-OCSP-port cleartext (`main.rs:1005-1029`). |
| **FTP_ITC.1** | Trusted channel between TOE components | **Met** | *Forward proxy:* `https://` enforced, shared TLS-verified client (`handlers.rs:287-296`; `hoike check` hard-fails cleartext w/o `forward_insecure` `main.rs:1045-1071`). *Syncrepl:* LDAPS / StartTLS-before-bind so bind password never crosses cleartext (`dogtag_sync.rs:190-216`, `client_config_with_ca:210-251`). *Gossip:* Ed25519-signed — see FPT_ITT.1. |
| **FPT_ITT.1** | Protection of TSF data between nodes | **Met** (broadcasts) | Generation / urgent-revocation broadcasts Ed25519-signed at the payload boundary, verified on receive; forged/unsigned dropped before re-propagation (`crypto.rs:9-42,112-120,161-188`; `broadcast.rs:150-183`). `gossip.identity_key` signs; `gossip.peer_keys` = trusted set + enforcement flip. **Note 1:** SWIM liveness (foca ping/ack) is **not** authenticated and payloads are **not** encrypted — signing covers the trust-bearing broadcasts only. **Note 2 (rollout caveat):** the verifier's *trust set* and *enforcement stance* are coupled to one field (`node.rs:184-189`): a signing node with empty `peer_keys` is `Permissive` but trusts **only its own key** (`node.rs:177-178`), and a signed frame must match a trusted key regardless of policy (`crypto.rs:161-178`). Consequently two signing-but-not-yet-peered nodes reject each other's signed announcements — there is no single config that simultaneously accepts unsigned-legacy traffic *and* signed traffic from peers, so the "mixed-fleet upgrade without partitioning" property is **not** fully achieved. Closing work: a `require_signed` knob decoupling trust set from enforcement. |

> **OCSP data plane is intentionally plaintext** (`server.listen`): responses are
> signature-authenticated end to end (FCO_NRO_EXT.2), so transport encryption adds cost
> without a security property. A deliberate non-goal, not a gap.

### 5.3 Cryptographic support

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FCS_COP.1 (signature)** | Approved signature algorithms | **Met** | ECDSA P-256 (p256 0.13; OID 1.2.840.10045.4.3.2 `verify.rs:14`); ML-DSA-44/65/87 (`ml_dsa_bridge.rs:27-29`) with RFC 6960 §4.4.7.1 PreferredSignatureAlgorithms negotiation (`request.rs:147-174`, `index.rs:142-157`). |
| **FCS_COP.1 (hashing)** | Approved hashes | **Met** | SHA-256 CertID (entry key); SHA-1 CertID retained for RFC-compat routing only (`generate.rs:86`). |
| **FCS_CKM.1 / FCS_CKM.2** | Key generation / establishment | **Partial** | Signing keys via PKCS#8 file (`keyfile.rs:60-93`), PKCS#11/HSM (`pkcs11.rs`), or ephemeral demo; TLS key establishment via `aws-lc-rs`. Lab uses one SoftHSM EC P-256 key across scopes. No in-app production keygen. |
| **FCS_CKM_EXT / FPT_SKP_EXT.1** | Protection of secret/private keys | **Partial** | HSM custody available (PKCS#11 incl. CKM_ML_DSA `pkcs11.rs:232-302`); seal key kept distinct from signing key (`config.rs:181-187`). **But no `zeroize`** of key material (transitive dep only); PIN redacted in `Debug` only (`pkcs11.rs:82-93`); lab posture is SoftHSM, not validated. |
| **FCS_RBG_EXT.1** | Random bit generation | **Partial** | OS RNG via `getrandom`; TLS DRBG from `aws-lc-rs`; ECDSA deterministic RFC 6979. Not a claimed/validated entropy source in the lab. |
| **FCS_COP crypto-module validation (FIPS)** | Validated cryptographic module | **Gap (by posture)** | `aws-lc-rs` is FIPS-capable but not built in `fips` mode. Closing work = build-profile change (`aws-lc-rs/fips` + `rustls/fips`), not code. |

### 5.4 Identification, authentication & management

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FIA_UAU.* / FIA_UID.*** | Admin I&A | **Met** | bcrypt password hashes + role (`config.rs:103-116`); `bcrypt::verify` in spawn_blocking with a constant DUMMY_HASH timing defense against user enumeration (`auth.rs:10-14,50-68`); 256-bit session tokens, 3600 s TTL (`auth.rs:128-133`, `config.rs:111-113`). Over TLS once FTP_TRP.1 configured. |
| **FMT_SMR.* / FMT_MOF.* / FMT_SMF.1** | Roles & functions | **Met** | Ranked RBAC Administrator(3) > Operator(2) > Viewer(1) (`state.rs:49-69`), enforced by `require_role`/`has_at_least` (`rbac.rs:20-22`): read = Viewer, mutation/signing = Operator, `rotate_ca` = Administrator (`signing.rs:210`). Management surface = admin API + UI. |
| **FMT_MTD.*** | Management of TSF data | **Met** | Bundle production/reload share the signer mutex so epoch derivation + `.ahu` writes never race (`orchestrate.rs`); `import --force` anti-rollback override for air-gap (`main.rs:18-110`). |

### 5.5 Security audit

| SFR | Requirement | Status | Evidence |
|-----|-------------|--------|----------|
| **FAU_GEN.1** | Audit record generation | **Met** | `audit!` → `tracing` `audit` target, always on (`obs.rs:20-25`); request-rejected (w/ serial), bundle-load-failed, signer-generation(-failed), bundle-admin events. |
| **FAU_GEN.2** | User identity association | **Partial** | Events omit operator identity on management/signing actions; session carries `operator_name` (`state.rs:44`) but not threaded into `audit!`. Closing work: add `operator_name`. |
| **FAU_STG / export** | Audit storage / export | **Partial** | Emitted via `tracing`; durable storage/rotation is deployment-provided (journald/collector). |

### 5.6 Explicitly out of scope — N/A (issuing-CA scope)

| Item | Disposition |
|------|-------------|
| **FDP_CER_EXT / certificate issuance, revocation decisioning, CA-key custody** | **N/A** — hoike consumes revocation data (CRL, 389 DS syncrepl); it does not decide revocation or issue certs. |
| **CMP / EST / ACME enrollment interfaces** | **N/A (issuing-CA scope).** |
| **CRL *generation*** | **N/A** — hoike ingests CRLs, it does not publish them. |
| **SCVP (RFC 5055)** | **N/A** — separate protocol, not planned. |

---

## 6. Security assurance requirements

PPCA v2.1 draws its SARs from the CC and its own assurance activities. Addressed at the
architecture level:

| SAR area | How addressed |
|----------|---------------|
| Functional spec / design (ADV) | This ST §5, `hoike-design.md` (§2.2 trust boundary, §6.3 gossip), `ahu-format-spec.md`. |
| Guidance (AGD) | `README.md`, config comments, `hoike check` operator diagnostics. |
| Life-cycle (ALC) | Git + `Cargo.lock`; monthly `cargo audit`; **update authenticity is a gap** (cf. App PP FPT_TUD_EXT.1). |
| Tests (ATE) | 175 test functions incl. anti-rollback, TLS config, gossip verify, and the 20-check OCSP conformance suite. |
| Vulnerability (AVA) | Rust memory safety; keyless edge tier; single audited `unsafe`. |

---

## 7. TOE summary specification (rationale highlights)

- **O.CORRECT_STATUS / O.PROOF_OF_ORIGIN → FDP_OCSPG_EXT.1 + FCO_NRO_EXT.2.** These are
  the PPCA obligations hoike exists to satisfy, and they are its strongest claims: every
  served response is a signed, RFC-6960-conformant object, verified by the conformance
  suite; error responses use the static unsigned DER the RFC explicitly allows.
- **T.UNAUTHORIZED_UPDATE → anti-rollback store.** The high-water design makes serving a
  rolled-back bundle a detected error at load, with a bounded `MAX_EPOCH_JUMP` guard
  against a forged forward jump; epochs derive from data high-water, not the clock, so a
  skewed host cannot be tricked into accepting stale status.
- **T.TSF_COMPROMISE / T.NETWORK_DISCLOSURE → FTP_TRP.1 + FTP_ITC.1 + FIA/FMT.** The
  management surface was deliberately moved off the public OCSP port onto a TLS listener;
  the LDAP bind password rides StartTLS/LDAPS; `hoike check` refuses to certify a
  cleartext forward channel. The keyless edge tier shrinks the compromise blast radius —
  a breached edge node holds no signing key.
- **P.ALGORITHMS → FCS_COP.1.** Approved algorithms only, with ML-DSA available *ahead*
  of the profile; dual-algorithm bundles let a fleet migrate to PQC without a flag day.
- **Honest Partials/Gap.** Key custody (SoftHSM, no zeroize), RBG validation, and FIPS
  module validation are **lab-posture** limitations, not design defects — each closes
  with a validated-HSM deployment and a `fips` build. FAU_GEN.2 operator attribution is
  a small code change.

### PPCA conformance summary

| Verdict | SFRs |
|---------|------|
| **Met** | FDP_OCSPG_EXT.1, FCO_NRO_EXT.2, response-validity, anti-rollback, FCS_TLSS_EXT.1, FTP_TRP.1, FTP_ITC.1, FPT_ITT.1, FCS_COP.1 (sig & hash), FIA_UAU/UID, FMT_SMR/MOF/SMF, FMT_MTD, FAU_GEN.1 |
| **Partial** | FCS_TLSS_EXT.2, FCS_CKM.1/.2, FCS_CKM_EXT/FPT_SKP_EXT.1, FCS_RBG_EXT.1, FAU_GEN.2, FAU_STG |
| **Gap (by posture)** | FIPS crypto-module validation |
| **N/A (issuing-CA scope)** | FDP_CER_EXT / issuance, CMP/EST/ACME, CRL generation, SCVP |

**Bottom line:** for the OCSP-responder role, hoike **meets the core PPCA
certificate-status and trusted-channel obligations**. The residual items are
lab-posture crypto validation (SoftHSM → validated HSM, `fips` build) and a small
audit-attribution enhancement — not gaps in the profile's certificate-status contract.
