# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Report vulnerabilities via [GitHub Security Advisories](https://github.com/czinda/hoike/security/advisories/new) (preferred) or by email to the maintainer listed in [MAINTAINERS.md](MAINTAINERS.md) if that file exists, otherwise via a private GitHub issue.

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Impact assessment

We will acknowledge receipt within 48 hours and aim to provide a fix or
mitigation within 7 days for critical issues.

## Known security gaps

The following are known and documented in the README's "Known limitations"
section. They are not eligible for security advisory reports but are tracked
for resolution:

- **CMS seal is a placeholder** — the bundle seal is currently a SHA-256 hash,
  not a cryptographic CMS `SignedData` signature. OCSP responses within bundles
  carry their own valid signatures, but the container's anti-rollback checks
  operate on unauthenticated manifest data. A party with write access to
  `bundle_dir` can craft a poisoned epoch.

- **Signing key is ephemeral** — `hoike sign` and combined mode use a hardcoded
  seed for key generation. There is no key-loading path or HSM integration.

- **Gossip messages are unsigned** — the design document (§6.3) specifies that
  every gossip message must be signed. The current implementation uses foca's
  postcard codec with no authentication layer.

## Scope

hoike is a PKI component. Its security model depends on:

1. **Response integrity** — each OCSP response carries its own signature from
   the CA or a delegated responder. This is intact and verified by relying
   parties, not by hoike.

2. **Container integrity** — the ahu bundle seal should ensure that a mirror
   cannot forge, omit, or replay entries undetected. This is currently a
   placeholder (see above).

3. **Edge node safety** — an edge node holds no signing keys and cannot produce
   a false `good` status. This property holds by construction.
