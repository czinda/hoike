# hoike — Security Target Package (NIAP Common Criteria)

This directory is the **Security Target (ST) package** for **hoike**, evaluated as a
composite claim (a **PP-Configuration**) against three NIAP documents:

| Document | This ST |
|----------|---------|
| Protection Profile for Application Software, **v1.4** | [`hoike-st-app-pp-v1.4.md`](hoike-st-app-pp-v1.4.md) |
| Protection Profile for Certification Authorities, **v2.1** (PP 420) | [`hoike-st-ppca-v2.1.md`](hoike-st-ppca-v2.1.md) |
| Functional Package for TLS, **v1.1** | [`hoike-st-tls-fp-v1.1.md`](hoike-st-tls-fp-v1.1.md) |

The predecessor gap analysis, [`../niap-ppca-gap-matrix.md`](../niap-ppca-gap-matrix.md),
remains the fast SFR-status table; these three documents are the formal ST-style
elaboration (TOE description, security problem definition, objectives, SFRs, SARs, and
a TOE Summary Specification mapping every SFR to `file:line` evidence).

---

## Posture disclaimer (read first)

**This is an *evaluation-ready architecture*, not an evaluated product.**

- Nothing here has undergone CC evaluation by a NIAP-approved lab, and no
  certificate has been issued. These STs are engineering artifacts: they state what
  hoike *would* claim and expose exactly where it falls short today.
- The reference deployment (koza-1 `cert-revocation-lab`) uses **lab-issued /
  self-signed** TLS certificates and a **single SoftHSM-backed EC P-256 key** across
  scopes. That is a lab convenience, not a certifiable key-management posture.
- The crypto is **not** running as a CC/FIPS-validated module. `aws-lc-rs` is
  *FIPS-capable* (it has a validated mode), but hoike does **not** build it with the
  `fips` feature by default. A validated posture is a build-profile change, not new
  code.
- Where an SFR is claimed **Met**, the TSS cites the implementing code. Where it is
  **Partial** or **Gap**, the TSS says so plainly and names the closing work. An ST
  that overclaims is worse than useless — a NIAP evaluator rejects it on the first
  unsupported assurance activity.

---

## Shared TOE definition (normative for all three STs)

All three STs describe **the same TOE**. This section is the single source of truth;
each ST restates the boundary briefly and refers here for detail.

### TOE identification

| Field | Value |
|-------|-------|
| TOE name | **hoike** |
| TOE version | **0.2.0** (per-crate; see FPT_IDV_EXT.1 note below) |
| TOE type | OCSP responder (RFC 6960 / 9654 / 9919) with a pre-signed-bundle serving model |
| Developer | hoike project |
| Form factor | Rust workspace, 6 crates, ~19,076 LoC, 175 test functions; two binaries (`hoike`, `ahu`) |
| Platforms | Linux (x86_64/aarch64, gnu + musl), macOS (aarch64); distroless container (`gcr.io/distroless/cc-debian12:nonroot`) |

> **FPT_IDV_EXT.1 caveat.** The crate manifests declare version `0.2.0`, but the clap
> CLI does **not** wire a `version` attribute, so `hoike --version` / `ahu --version`
> do **not** print a version at runtime. This is a **Gap** carried in the App PP ST.

### TOE architecture and tiers

hoike deliberately splits **signing** from **serving**:

- **Signer tier** (`hoike-sign`) — ingests revocation data (CRL files; 389 DS RFC 4533
  syncrepl), generates and signs OCSP responses (ECDSA P-256 or ML-DSA-44/65/87),
  seals them into `ahu` bundles with a CMS `SignedData` envelope, and holds the
  private keys (PKCS#8 files or PKCS#11/HSM).
- **Edge tier** (`hoike-server`) — **keyless**, horizontally scalable. Serves
  pre-signed responses from `ahu` bundles by binary-searching an mmap'd index. Holds
  no OCSP signing key.
- **Gossip plane** (`hoike-gossip`) — SWIM membership (foca) + generation
  announcements; trust-bearing broadcasts are Ed25519-signed.

### TOE boundary — what is inside vs. outside

**Inside the TOE (TSF):**

- OCSP request parsing, CertID routing, response serving, nonce policy
  (`hoike-core`, `hoike-server`).
- OCSP response generation, CMS seal creation, key loading, PKCS#11 bridge, ML-DSA
  bridge, revocation-source adapters, key-rotation monitor (`hoike-sign`).
- The `ahu` bundle format + CMS seal verification (`ahu`).
- Admin API + web UI (bcrypt auth, RBAC, management functions) and its TLS listener.
- Prometheus metrics listener; structured audit log.
- Gossip membership + signed broadcasts (`hoike-gossip`).
- The TLS server stack for the management surfaces (rustls 0.23 / aws-lc-rs).

**Outside the TOE (operational environment):**

- The **issuing CA** (e.g. Dogtag/RHCS) — hoike consumes its revocation data; it does
  not issue certificates. *(PPCA scoping — see below.)*
- The **HSM** reached over PKCS#11 (key custody delegated to it).
- The **389 Directory Server** (syncrepl source) and any upstream OCSP responder
  (nonce forwarding target).
- The **host OS / container platform** (ASLR, disk encryption, filesystem
  permissions, journald/log collector, process isolation).
- **TLS certificates and CA trust anchors** provisioned by the operator.

### hoike is NOT a Certification Authority (PPCA scoping)

hoike does not issue certificates, run CMP/EST/ACME enrollment, decide revocation, or
custody a CA key that signs end-entity certificates. In a PPCA evaluation hoike is the
component that implements the profile's **certificate-status / proof-of-origin**
obligations (FDP_OCSPG_EXT, FCO_NRO_EXT); SFRs about issuance, certificate lifecycle,
or CA-key custody are marked **N/A (issuing-CA scope)** in the PPCA ST.

### OCSP data plane is intentionally plaintext

`server.listen` (default `0.0.0.0:2560`) serves OCSP over plain HTTP **by design**:
every response is signature-authenticated end to end (FCO_NRO_EXT.2), so a transport
wrapper adds cost without a security property, and RFC 6960 clients POST/GET plaintext
DER. TLS is applied to the **management** surfaces (admin, metrics) and the
**inter-component** channels (forward proxy, syncrepl), not the OCSP data plane. This
is a deliberate non-goal, not a gap.

---

## Cross-PP SFR index

A single mechanism often satisfies requirements in more than one profile. This index
is the map; each ST is authoritative for its own column.

| Mechanism (evidence) | App PP v1.4 | PPCA v2.1 | TLS FP v1.1 |
|----------------------|-------------|-----------|-------------|
| OCSP response generation (`hoike-core/router.rs`, `hoike-server/handlers.rs`) | — | FDP_OCSPG_EXT.1 **Met** | — |
| Signed responses / proof of origin (`hoike-sign/generate.rs`) | — | FCO_NRO_EXT.2 **Met** | — |
| TLS server stack, rustls 0.23 / aws-lc-rs (`hoike-server/tls.rs`) | FTP_DIT_EXT.1 **Met** | FCS_TLSS_EXT.1 **Met**, FTP_TRP.1 **Met** | FCS_TLSS_EXT.1 **Met** |
| TLS mutual auth (`tls.rs` `client_ca` → WebPkiClientVerifier) | — | FCS_TLSS_EXT.2 **Partial** | FCS_TLSC/TLSS mutual **Partial** |
| Inter-component channels (`handlers.rs` forward, `dogtag_sync.rs` LDAPS) | FTP_DIT_EXT.1 **Met** | FTP_ITC.1 **Met** | FCS_TLSC_EXT.1 (client) **Partial** |
| Gossip broadcast auth, Ed25519 (`hoike-gossip/crypto.rs`) | — | FPT_ITT.1 **Met** | — |
| Approved signature algs — ECDSA P-256, ML-DSA (`hoike-sign/ml_dsa_bridge.rs`) | FCS_COP.1/1 **Met** | FCS_COP.1 (sig) **Met** | FCS_COP.1/SigGen **Met** |
| Approved hashing — SHA-256 (SHA-1 compat only) | FCS_COP.1/4 **Met** | FCS_COP.1 (hash) **Met** | FCS_COP.1/Hash **Met** |
| Key storage — PKCS#8 file / PKCS#11 HSM (`keyfile.rs`, `pkcs11.rs`) | FCS_STO_EXT.1 **Partial** | FCS_CKM_EXT / FPT_SKP_EXT.1 **Partial** | — |
| RBG — getrandom / aws-lc-rs DRBG | FCS_RBG_EXT.1 **Partial** | FCS_RBG_EXT.1 **Partial** | FCS_RBG_EXT.1 **Partial** |
| Admin authn — bcrypt + RBAC (`admin/auth.rs`, `admin/rbac.rs`) | FMT_CFG_EXT.1 **Met** | FIA_UAU/FIA_UID, FMT_SMR/SMF **Met** | — |
| Audit log (`obs.rs`, `handlers.rs`) | FAU_GEN.1 **Met** / FAU_GEN.2 **Partial** | FAU_GEN.1 **Met** / FAU_GEN.2 **Partial** | — |
| Memory-safe build, 1 audited `unsafe` (`ahu/mmap_bundle.rs`) | FPT_AEX_EXT.1 **Partial** | — | — |
| Third-party lib inventory (`Cargo.lock`, `cargo audit` CI) | FPT_LIB_EXT.1 **Met** | — | — |
| Trusted update (checksums only, unsigned) | FPT_TUD_EXT.1/.2 **Gap** | — | — |
| Runtime version output (`hoike --version` not wired) | FPT_IDV_EXT.1 **Gap** | — | — |
| Data at rest (no app-layer encryption) | FDP_DAR_EXT.1 **Partial** | — | — |
| No PII / client-IP collection (`handlers.rs`) | FPR_ANO_EXT.1 **Met** | — | — |

Legend: **Met** = implemented + evidenced; **Partial** = implemented but default-off,
incomplete, or lab-posture only; **Gap** = not implemented (closing work named);
**N/A** = out of scope. Full rationale and citations are in each ST's TSS.

---

## Top gaps at a glance (union across all three STs)

| # | SFR | Profile | Nature of gap | Closing work |
|---|-----|---------|---------------|--------------|
| 1 | FPT_TUD_EXT.1/.2 | App PP | Updates ship with **unsigned** SHA-256 checksums; no signature verification; no in-product update | Sign release artifacts/images (cosign/sigstore or GPG) and document verification |
| 2 | FPT_IDV_EXT.1 | App PP | `hoike --version` / `ahu --version` not wired in clap | Add `#[command(version)]` sourced from `CARGO_PKG_VERSION` |
| 3 | FCS_STO_EXT.1 / FPT_SKP_EXT.1 | App PP / PPCA | No key-material zeroization (`zeroize` is transitive only); plaintext HSM PIN / LDAP password possible in TOML | Zeroize key buffers; require `*_env`/secret-manager indirection; validated HSM |
| 4 | FDP_DAR_EXT.1 | App PP | No app-layer encryption at rest; state DB + sync cookie are plaintext (bundles are CMS-*signed*, not encrypted) | Rely on platform disk encryption (document) or add at-rest encryption |
| 5 | FPT_AEX_EXT.1 | App PP | No `[profile.release]`/hardening flags; relies on rustc/platform defaults | Add release profile (LTO, `panic=abort`, `overflow-checks`), RELRO/PIE via RUSTFLAGS |
| 6 | FAU_GEN.2 | App PP / PPCA | Audit events omit operator identity on management actions | Thread `operator_name` from the session into `audit!` calls |
| 7 | FIPS validation | PPCA / TLS FP | aws-lc-rs not built in `fips` mode | Build `aws-lc-rs/fips` + `rustls/fips` |
| 8 | FCS_TLSS_EXT.2 | PPCA / TLS FP | mTLS wired but off by default | Set `admin_tls.client_ca` (verifier already wired) |

---

## References

- NIAP *Protection Profile for Application Software, v1.4*.
- NIAP *Protection Profile for Certification Authorities, v2.1* (PP 420).
- NIAP *Functional Package for TLS, v1.1*.
- hoike architecture: [`../../hoike-design.md`](../../hoike-design.md);
  bundle format: [`../../ahu-format-spec.md`](../../ahu-format-spec.md).
- Predecessor gap analysis: [`../niap-ppca-gap-matrix.md`](../niap-ppca-gap-matrix.md).
