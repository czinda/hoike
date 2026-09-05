# Security Target — hoike against the Functional Package for TLS v1.1

> **Remediation status (September 2026):** The security review found defects in
> implemented status, trust, freshness, rollback, and transport mechanisms.
> The historical “Met”/conformance statements below are not current release
> acceptance evidence. Consult the [remediation ledger](../review-remediation.md) for corrections,
> tests and outstanding qualification. No CC/FIPS certification is claimed;
> enabling a dependency feature alone does not establish an evaluated deployment.


**Status:** Evaluation-ready architecture, not an evaluated product. See the
[package posture disclaimer](README.md#posture-disclaimer-read-first).

**Conformance claim:** Conformance to the *NIAP Functional Package for TLS, Version
1.1*, as invoked by the [App PP](hoike-st-app-pp-v1.4.md) and
[PPCA](hoike-st-ppca-v2.1.md) STs. hoike acts as a **TLS server** on its management
surfaces (admin, metrics) and as a **TLS client** on its inter-component egress (forward
proxy, LDAPS syncrepl). The OCSP data plane is out of scope for this package — it is
plaintext HTTP by design (signed responses).

> **Key honesty finding up front.** hoike does **not** explicitly pin its ciphersuite
> list, key-exchange groups, or signature-algorithm list — it inherits the **aws-lc-rs
> default provider** set. The TLS FP requires the ST to *select and enumerate* the exact
> ciphersuites offered/accepted. Until hoike restricts the provider to an explicit FP
> selection, several requirements below are **Partial** on that basis, even though the
> underlying library only offers approved suites for TLS 1.2/1.3.

---

## 1. Package instantiation

| Field | Value |
|-------|-------|
| TLS library | rustls **0.23.43** on the **aws-lc-rs 1.18.1** crypto provider |
| Provider selection | Explicit per-`ServerConfig` `builder_with_provider(aws_lc_rs::default_provider())` (`tls.rs:34,39-41`) — not `install_default`, so unaffected by any client dep's provider |
| Feature gate | `tls` cargo feature |
| Roles claimed | TLS **server** (FCS_TLSS_EXT.1) + TLS **client** (FCS_TLSC_EXT.1) |
| Protocol versions | **TLS 1.2 (floor) + TLS 1.3** only (`tls.rs:39-41`) — SSLv3/TLS 1.0/1.1 not offered |

---

## 2. TLS server requirements (FCS_TLSS_EXT)

### 2.1 FCS_TLSS_EXT.1 — TLS server protocol

| Element | Status | Evidence / note |
|---------|--------|-----------------|
| TLS 1.2 + 1.3, older versions refused | **Met** | Version floor set to TLS 1.2, 1.3 enabled (`tls.rs:39-41`). aws-lc-rs offers no SSLv3/1.0/1.1. |
| Ciphersuite selection enumerated by the ST | **Partial** | **Not explicitly restricted** — inherits aws-lc-rs defaults (`tls.rs:28`). The default set for TLS 1.3 is `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`; for TLS 1.2, ECDHE-ECDSA/RSA with AES-GCM and CHACHA20-POLY1305 (all AEAD, all FP-approved). **The ST must pin these** to satisfy the FP's "select the ciphersuites" element. |
| Key establishment groups | **Partial** | Not explicitly restricted; aws-lc-rs defaults are X25519 + secp256r1/384r1/521r1. FP-approved, but not pinned. |
| Session resumption / tickets | **Partial** | rustls defaults (TLS 1.3 tickets / 1.2 session cache); not explicitly configured or disabled — should be an explicit ST selection. |
| Server certificate / key loading | **Met** | PEM via `rustls-pemfile` in the shared loader (`tls.rs:29-72`); one helper feeds admin + metrics listeners. |
| ALPN | **Partial (N/A-leaning)** | No ALPN configured (`tls.rs`). HTTP/1.1 over TLS; not required by the profile for this surface, but the ST should state it explicitly. |

### 2.2 FCS_TLSS_EXT.2 — mutual (client-certificate) authentication

| Element | Status | Evidence |
|---------|--------|----------|
| Require and validate client certs | **Partial** | Wired but off by default: when `admin_tls.client_ca` is set, a `WebPkiClientVerifier` requires + path-validates client certs (`tls.rs:43-62`); unset → server-auth only (`tls.rs:63-67`). Flip-the-flag to enable, no code change. |

---

## 3. TLS client requirements (FCS_TLSC_EXT)

### 3.1 FCS_TLSC_EXT.1 — TLS client protocol & server-cert validation

| Element | Status | Evidence / note |
|---------|--------|-----------------|
| Forward-proxy client validates server cert | **Partial** | Shared reqwest client with the system trust store validates the upstream OCSP server cert; `https://` enforced (`handlers.rs:287-296`; `hoike check` hard-fails cleartext w/o `forward_insecure` `main.rs:1045-1071`). **Gap within:** a custom `forward_ca` root is **not** wired into the forward client (`main.rs:1064-1069`, `handlers.rs:281-287`) — only the system store is used. |
| Syncrepl (LDAPS/StartTLS) client validates server cert | **Met** | `client_config_with_ca` builds a rustls (aws-lc-rs) config with the configured CA; StartTLS-before-bind or LDAPS (`dogtag_sync.rs:190-216,210-251`); `none` = default plaintext (Partial by config). |
| Reference identifier / SAN matching | **Partial** | Delegated to rustls/webpki defaults (hostname verification on); not independently asserted or pinned by hoike. |
| Ciphersuite / group selection enumerated | **Partial** | Same as server: inherits aws-lc-rs defaults, not pinned. |
| Certificate revocation checking of the *peer's* cert (CRL/OCSP) | **Gap** | The TLS clients do not perform revocation checking of the peer's TLS certificate. (Notable irony for an OCSP responder — but out of the OCSP data-plane scope.) |

---

## 4. Supporting cryptography (shared with App PP / PPCA)

| SFR | Status | Evidence |
|-----|--------|----------|
| **FCS_COP.1/SigGen** (ECDSA P-256, ML-DSA) | **Met** | `verify.rs:14`, `ml_dsa_bridge.rs:27-29`. |
| **FCS_COP.1/Hash** (SHA-256; SHA-1 compat only) | **Met** | `sha2`; SHA-1 `generate.rs:86`. |
| **FCS_COP.1/DataEnc** (AES-GCM in TLS records) | **Met (via provider)** | aws-lc-rs AEAD suites; not directly invoked by hoike. |
| **FCS_RBG_EXT.1** | **Partial** | aws-lc-rs DRBG for TLS; `getrandom` elsewhere; not a validated entropy source in the lab. |
| **FIPS module validation** | **Gap (by posture)** | aws-lc-rs not built `fips`; closing work = `aws-lc-rs/fips` + `rustls/fips`. |

---

## 5. Conformance summary & closing work

| Verdict | Elements |
|---------|----------|
| **Met** | TLS 1.2+1.3 version floor; server cert/key loading; syncrepl client cert validation; supporting sig/hash crypto |
| **Partial** | Ciphersuite/group/resumption/ALPN **not explicitly pinned** (inherit aws-lc-rs defaults); FCS_TLSS_EXT.2 mTLS (off by default); FCS_TLSC_EXT.1 forward-client custom-CA + reference-identifier assertion; FCS_RBG_EXT.1 |
| **Gap** | Peer-TLS-cert revocation checking on the client; `forward_ca` not wired into forward client; FIPS module validation |

**Closing work to satisfy the FP as written:**

1. **Pin an explicit ciphersuite + group + signature-algorithm list** on the rustls
   `ServerConfig`/`ClientConfig` (restrict `provider.cipher_suites` / `kx_groups`) and
   enumerate them in the ST — the single highest-value change for FP conformance.
2. **Wire `forward_ca`** into the forward reqwest client so a private root can be pinned
   (`main.rs:1064-1069`).
3. **Enable mTLS** on the admin listener (`admin_tls.client_ca`) for FCS_TLSS_EXT.2.
4. **Build `aws-lc-rs/fips` + `rustls/fips`** for a validated module.
5. Explicitly configure (or disable) **session resumption/tickets** and **ALPN**, and
   assert **reference-identifier** matching, rather than relying on defaults.

**Bottom line:** hoike's TLS *implementation* uses an FP-approved library restricted to
TLS 1.2/1.3, and the actual bytes on the wire are approved suites. The FP *conformance*
gap is almost entirely about **making the selection explicit and enumerable** rather than
inheriting library defaults — a configuration/enumeration exercise, not an algorithm
substitution — plus the two genuine client-side gaps (forward custom-CA wiring, peer-cert
revocation checking).
