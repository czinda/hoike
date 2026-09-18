# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| 0.1.x   | No — upgrade; 0.1 bundles and sync cookies are read by 0.2 with a full refresh |

## Reporting a vulnerability

Report vulnerabilities through [GitHub Security Advisories](https://github.com/czinda/hoike/security/advisories/new). Do not open a public issue for a suspected vulnerability.

Include a description, steps to reproduce, affected versions, and your assessment of impact. We acknowledge reports within 48 hours and aim to ship a fix or mitigation within 7 days for critical issues. Coordinated disclosure is appreciated; we will credit reporters in the advisory unless asked not to.

## Security model

hoike is a PKI component. Its security rests on three properties:

1. **Response integrity.** Every OCSP response carries a signature from the CA or a delegated responder, verified by relying parties. hoike cannot forge a response for a key it does not hold.
2. **Container integrity.** Every ahu bundle carries a CMS `SignedData` seal. Edge nodes verify the seal against a configured trust policy (certificate pins or CA anchors, optionally restricted per producer and scope) before loading, and enforce monotonic epochs with persisted high-water marks so an older generation cannot be replayed.
3. **Keyless edge.** Edge nodes hold no signing keys. Compromising an edge cannot produce a false `good`; it can only deny service or replay a still-valid generation until `nextUpdate`.

The signer tier holds keys and is the asset to protect. Production signing keys belong in an HSM (`signing_key.type = "pkcs11"`).

## Known limitations

These are documented design boundaries, not defects, and are not eligible for advisories:

- **Gossip is authenticated, not encrypted.** Generation and urgent-revocation broadcasts are Ed25519-signed and verified against named peer identities. SWIM liveness traffic (pings and acks) is not authenticated, and no gossip traffic is encrypted. Gossip is never authoritative for certificate status.
- **Bounded seal trust profile.** Seal verification accepts exact certificate pins or certificates directly issued by a configured CA anchor. General PKIX path building, intermediates, and policy processing are not implemented.
- **Bounded CRL profile.** Complete, direct CRLs only, signed with ECDSA P-256, RSA PKCS#1 v1.5, or ML-DSA. Delta and indirect CRLs and unknown critical extensions are rejected.
- **Delta output is unsigned by default.** `ahu apply` produces an unsigned intermediate; use `apply_sealed` or the `--seal-key`/`--seal-cert` options to produce an installable bundle.
- **Multi-request OCSP.** Only the first `CertID` in a multi-request `OCSPRequest` is answered.
- **Cryptography is not FIPS-validated.** All cryptographic operations execute in Rust crates outside any validated module. HSM-produced signatures are the exception. See `docs/compliance/` and the FIPS status page on hoike.dev for the migration plan.
- **Admin authentication is basic.** Per-account lockout, password policy, idle timeout, and operator identity in audit events are not yet implemented. Put the admin listener behind mutual TLS on a management network.

## Verifying releases

Releases and container images currently ship with SHA-256 checksums only. Signed artifacts are planned. Until then, build from source with `cargo build --release --locked` to obtain a binary you can attest to.

## Scope

In scope: the `hoike` and `ahu` binaries, the six workspace crates, the web UI, and the container image. Out of scope: the issuing CA, the HSM, the directory server, and the host operating system, whose security hoike depends on but does not control.
