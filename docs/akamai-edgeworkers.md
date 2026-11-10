# Akamai EdgeWorkers integration

hoike can optionally tag **cacheable** OCSP success responses with an Akamai
`Surrogate-Key` header to support targeted purges.

## Cache behavior

hoike emits two classes of OCSP HTTP responses:

- **Cacheable success responses (no nonce):**
  - `Cache-Control: max-age=…, public, no-transform, must-revalidate`
  - Stable content suitable for CDN caching.

- **Not cacheable (nonce-bearing or error responses):**
  - `Cache-Control: no-cache, no-store`
  - These must not be cached.

EdgeWorkers should respect hoike's cache headers:

- Cache only when `Cache-Control` contains a positive `max-age` and does **not**
  contain `no-store`.
- Bypass caching when `no-store` is present.

## Surrogate-Key tagging

When enabled, hoike adds:

```
Surrogate-Key: <prefix>-<ca_label>-<entry_key_hex>
```

Only **cacheable** success responses receive this header. Nonce-bearing responses
and error responses never include `Surrogate-Key`.

### Configuration

```toml
[server.akamai]
enabled = true
surrogate_key_prefix = "hoike-ocsp" # default
```

## Purging (high level)

Use Akamai's purge tooling to purge by **surrogate key**. The key is derived from:

- `ca_label`: the hoike CA label that served the response
- `entry_key_hex`: SHA-256 of the DER-encoded OCSP `CertID` (hoike's entry key)

This enables purging a single OCSP object (or a small set) without flushing the
entire cache.
