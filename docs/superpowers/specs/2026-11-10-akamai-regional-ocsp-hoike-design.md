# Hoike + Akamai EdgeWorkers: Regional OCSP Delivery Design

## Goal

Enable a deployment where **no-nonce** OCSP traffic is cacheable worldwide via **Akamai**, while **nonce-bearing** OCSP traffic is never cached and reaches Hoike’s own global responder/signer network.

Target: revocation visibility worldwide in **< 5 minutes**.

## What already exists in hoike

- Pre-signed responses served from `.ahu` bundles (edge tier).
- Nonce policy dispatch (`ignore`, `live`, `forward`) and live nonce signing support.
- Success responses already emit `Cache-Control: max-age=..., public, no-transform, must-revalidate`.
- Nonce/live and error responses emit `Cache-Control: no-cache, no-store`.

## Design additions (Akamai-specific, optional)

1) **Max-Age hard cap**

Even if a bundle’s validity window is long, cap HTTP `max-age` to a safe upper bound (default **240s**).

2) **Optional Akamai cache tagging**

When enabled, emit a `Surrogate-Key` header for cacheable (no-nonce) success responses. The key is derived from the CA label and the entry key (SHA-256(DER(CertID))) so Akamai can purge by surrogate key if desired.

This is optional and disabled by default.

## Nonce vs no-nonce behavior

- If request contains a nonce:
  - Hoike serves a live-signed or forwarded response per `nonce_policy`.
  - Response must be **uncacheable** (`no-store`).

- If request does not contain a nonce:
  - Hoike serves a pre-signed response from bundles.
  - Response may be cached (subject to max-age cap).

## Akamai EdgeWorkers contract (informational)

- Akamai should respect `Cache-Control` and never cache nonce-bearing responses.
- If using surrogate-key purges, configure EdgeWorkers/Property Manager to store and purge by `Surrogate-Key` values.
