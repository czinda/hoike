# hoike — NIAP PPCA v2.1 SFR Gap Matrix

**Scope of this document.** This maps hoike against the security functional
requirements (SFRs) of the **NIAP Protection Profile for Certification
Authorities, Version 2.1 (PP 420)** and its dependent **Functional Package for
TLS, Version 1.1**, restricted to the requirements that apply to an **OCSP
responder** deployed alongside — but distinct from — the issuing CA.

hoike is **not** a Certification Authority. It does not issue certificates, run
a CMP/EST/ACME enrollment interface, or manage a CA private key that signs
end-entity certificates. In a PPCA evaluation hoike is the component that
implements the profile's **certificate status / OCSP** obligations
(FDP_OCSPG_EXT, FCO_NRO_EXT) while the CA proper (e.g. Dogtag/RHCS in the
reference lab) is the issuing TOE. SFRs that are purely about certificate
*issuance*, lifecycle, or CA-key custody are therefore marked **N/A (issuing CA
scope)**.

> **Posture disclaimer.** This is an *evaluation-ready architecture*, not an
> evaluated instance. The reference deployment (koza-1 `cert-revocation-lab`)
> uses lab-issued/self-signed TLS certificates and a single SoftHSM-backed
> EC P-256 key. Nothing here has been through CC evaluation, and the crypto is
> **not** running as a CC/FIPS-validated module. `aws-lc-rs` is *FIPS-capable*
> (it has a validated mode), but hoike does not build it in `fips` mode by
> default. See [Crypto notes](#crypto-notes).

Status legend:

| Status | Meaning |
|--------|---------|
| **Met** | Implemented and exercised by tests / in the reference deployment. |
| **Partial** | Implemented but disabled by default, incomplete, or lab-posture only. |
| **Gap** | Not implemented; tracked below with the closing work. |
| **N/A** | Out of scope for an OCSP responder (issuing-CA function, or explicitly not planned). |

---

## 1. Certificate status & proof of origin (core OCSP obligations)

| SFR | Requirement | Status | Evidence / notes |
|-----|-------------|--------|------------------|
| **FDP_OCSPG_EXT.1** | OCSP response generation per RFC 6960 | **Met** | Pre-signed responses served from `ahu` bundles (`crates/hoike-core/src/router.rs::lookup`, `crates/hoike-server/src/handlers.rs`); live/on-demand signing (`crates/hoike-sign/src/orchestrate.rs`, `hoike-sign` response generation). RFC 6960/9919 conformance suite: `crates/hoike-server/tests/conformance.rs`. |
| **FCO_NRO_EXT.2** | Enforced proof of origin (signed responses) | **Met** | Every `BasicOCSPResponse` is signed (ECDSA P-256 or ML-DSA). Delegated responder cert embedded per RFC 9919 §3.2.2; ResponderID from cert SPKI hash. Error responses are the static unsigned 5-byte DER that RFC 6960 permits. |
| **Response validity / thisUpdate–nextUpdate windows** | Bounded response freshness | **Met** | Batch window + `validity_secs` (`crates/hoike-core/src/config.rs`); freshness gauges in `crates/hoike-server/src/obs.rs`. |
| **Anti-replay / anti-rollback of status data** | Monotonic status epochs | **Met** | Persistent anti-rollback state store (`crates/hoike-core/src/state.rs`), continuity + rollback checks on bundle load. |

## 2. Trusted path & trusted channels (the transport-hardening focus)

| SFR | Requirement | Status | Evidence / notes |
|-----|-------------|--------|------------------|
| **FCS_TLSS_EXT.1** | TLS server, server authentication | **Met** | rustls 0.23 on the `aws-lc-rs` provider, TLS 1.3 + 1.2 floor (`crates/hoike-server/src/tls.rs`), behind the `tls` feature. Terminates on the admin + metrics management listeners. |
| **FCS_TLSS_EXT.2** | TLS server, mutual (client-cert) authentication | **Partial** | Wired but off by default: set `admin_tls.client_ca` and a `WebPkiClientVerifier` requires client certs (`tls.rs::server_config`). Flip-the-flag to enable; no code change needed. |
| **FTP_TRP.1** | Trusted path for remote administration | **Met** | Admin API + web UI moved off the OCSP port onto a dedicated TLS listener (`server.admin_listen` + `server.admin_tls`; router split in `crates/hoike-server/src/lib.rs::build_admin_router_standalone`). Existing bcrypt/RBAC login now runs over TLS. `hoike check` warns if admin rides the cleartext OCSP port. |
| **FTP_ITC.1** | Trusted channel between TOE components | **Met** | *Forward proxy:* `https://` enforced at config-validation (`hoike check`), TLS-verified shared client (`handlers.rs::forward_client`). *Syncrepl:* LDAPS / StartTLS-before-bind so the bind password never crosses cleartext (`crates/hoike-sign/src/dogtag_sync.rs::connect`, `tls`/`ca_cert` config). *Gossip:* Ed25519-signed broadcasts — see FPT_ITT.1. |
| **FPT_ITT.1** | Protection of TSF data between nodes (gossip) | **Met** | Generation/urgent-revocation broadcasts are Ed25519-signed at the payload boundary and verified on receive (`crates/hoike-gossip/src/crypto.rs`, `broadcast.rs::receive_item`); forged/unsigned messages are dropped before re-propagation. `gossip.identity_key` signs; `gossip.peer_keys` sets the trusted set and flips enforcement (empty = permissive rollout, populated = drop-unsigned). Backward-compatible one-byte frame tag lets a mixed fleet upgrade without partitioning. **Note:** SWIM liveness traffic (foca pings/acks) and the payload *confidentiality* are not yet covered — this authenticates the trust-bearing broadcasts, it does not encrypt the channel. |
| **TLS Functional Package v1.1** | TLS 1.2 floor, approved ciphersuites, version negotiation | **Met** | TLS 1.3 + 1.2 only (`tls.rs`); ciphersuites from the `aws-lc-rs` provider. OCSP-for-TLS-stapling is downstream consumer concern, not this TOE. |

> **OCSP data plane is intentionally plaintext.** `server.listen` serves OCSP
> over plain HTTP by design: responses are CMS/signature-authenticated end to
> end (FCO_NRO_EXT.2), so a transport wrapper there adds cost without a security
> property. RFC 6960 clients POST/GET plaintext DER. This is a deliberate
> non-goal, not a gap.

## 3. Cryptographic support

| SFR | Requirement | Status | Evidence / notes |
|-----|-------------|--------|------------------|
| **FCS_COP.1 (signature)** | Approved signature algorithms | **Met** | ECDSA P-256 (`hoike-sign`, x509-ocsp builder); ML-DSA-44/65/87 (`crates/hoike-sign/src/ml_dsa_bridge.rs`) with RFC 6960 §4.4.7.1 PreferredSignatureAlgorithms negotiation. |
| **FCS_COP.1 (hashing)** | Approved hashes | **Met** | SHA-256 CertID (entry key = SHA-256 of DER CertID); SHA-1 CertID supported only for RFC-compat routing. |
| **FCS_CKM.1 / FCS_CKM.2** | Key generation / establishment | **Partial** | Signing keys via PKCS#8 file, PKCS#11/HSM (`signing_key.type="pkcs11"`), or ephemeral demo. TLS key establishment via `aws-lc-rs`. Lab uses one SoftHSM EC P-256 key across scopes. |
| **FCS_CKM_EXT / FPT_SKP_EXT.1** | Protection of secret/private keys | **Partial** | HSM custody available (PKCS#11, incl. CKM_ML_DSA); seal key kept distinct from OCSP signing key. Lab posture is SoftHSM, not a validated HSM. |
| **FCS_RBG_EXT.1** | Random bit generation | **Partial** | OS RNG via `getrandom`; TLS DRBG from `aws-lc-rs`. Not a claimed/validated entropy source in the lab. |
| **Crypto module validation (FIPS)** | Validated cryptographic module | **Gap (by posture)** | `aws-lc-rs` is FIPS-capable but not built in `fips` mode here. Closing work is a build-profile change (`aws-lc-rs/fips` + `rustls/fips`), not a code change — see [Crypto notes](#crypto-notes). |

## 4. Identification, authentication & management

| SFR | Requirement | Status | Evidence / notes |
|-----|-------------|--------|------------------|
| **FIA_UAU / FIA_UID** | Administrator identification & authentication | **Met** | bcrypt password hashes + role (`config.rs::OperatorConfig`), session TTL; enforced by the admin API. Over TLS once FTP_TRP.1 is configured. |
| **FMT_SMR / FMT_MOF / FMT_SMF** | Management roles & functions | **Met** | RBAC roles (viewer/admin/operator); management surface = admin API + web UI (on-demand signing, bundle diff/extract/apply, gossip fleet view). |
| **FMT_MTD** | Management of TSF data | **Met** | Admin routes for bundle production/reload sharing the signer mutex (`hoike-sign/src/orchestrate.rs`). |

## 5. Security audit

| SFR | Requirement | Status | Evidence / notes |
|-----|-------------|--------|------------------|
| **FAU_GEN.1 / FAU_GEN.2** | Audit record generation | **Met** | Structured audit log on the `audit` tracing target (always on), incl. request-rejected events with serial (`handlers.rs`, `obs.rs`). |
| **FAU_STG / export** | Audit storage / export | **Partial** | Emitted via `tracing`; durable storage/rotation is deployment-provided (journald/collector). Prometheus `/metrics` for operational telemetry. |

## 6. Explicitly out of scope

| Item | Disposition |
|------|-------------|
| **FDP_CER_EXT / certificate issuance, revocation decisioning, CA key custody** | **N/A (issuing CA scope)** — hoike consumes revocation data (CRL, 389 DS syncrepl); it does not decide revocation or issue certs. |
| **CMP / EST / ACME enrollment interfaces** | **N/A (issuing CA scope).** |
| **SCVP (RFC 5055)** | **N/A** — separate protocol, not planned. |
| **CRL *generation*** | **N/A (issuing CA scope)** — hoike ingests CRLs, does not publish them. |

---

## Crypto notes

- **Provider unification.** All TLS (server-side management listeners, the
  reqwest forward client, and LDAPS/StartTLS syncrepl) runs on the `aws-lc-rs`
  rustls provider, giving one crypto boundary. `crates/hoike-server/src/tls.rs`
  builds the `ServerConfig` with an *explicit* provider so it is unaffected by
  whichever provider a client-side dependency pulls in.
- **FIPS follow-on.** A validated posture is a build change, not new code: enable
  `aws-lc-rs/fips` and `rustls/fips`. This is heavier to build (validated module
  toolchain) and is not required for the lab.
- **PQC.** ML-DSA-44/65/87 signing is available today (file keys and PKCS#11
  `CKM_ML_DSA`), ahead of the profile — dual-algorithm bundles let a fleet
  migrate without a flag day.

## Closing-work summary (Partial / Gap items)

| SFR | Work to close |
|-----|---------------|
| FCS_TLSS_EXT.2 | Set `admin_tls.client_ca`; verifier already wired. |
| FPT_ITT.1 (confidentiality / SWIM leg) | Broadcasts are now signed; adding payload encryption and authenticating SWIM liveness traffic would close the remaining gossip surface. |
| FCS_CKM / FPT_SKP_EXT.1 | Deploy against a validated HSM instead of SoftHSM; distinct per-scope keys. |
| FCS_RBG_EXT.1 | Claim/validate an entropy source in the target environment. |
| FIPS validation | Build with `aws-lc-rs/fips` + `rustls/fips`. |
| FAU_STG | Wire audit export to a durable collector with rotation. |

## References

- NIAP *Protection Profile for Certification Authorities, v2.1* (PP 420).
- NIAP *Functional Package for TLS, v1.1*.
- hoike architecture: [`hoike-design.md`](../hoike-design.md) (§6.3 gossip, §2.2 trust boundary).
- Transport hardening implementation: `crates/hoike-server/src/tls.rs`,
  `crates/hoike-sign/src/dogtag_sync.rs`, `crates/hoike-server/src/handlers.rs`.
