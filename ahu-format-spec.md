# The ahu Pre-Signed OCSP Response Bundle Format

**Version:** 0.1 (draft — not yet stable)
**Status:** Working draft for review
**Editor:** Chris Zinda
**Companion implementation:** `hoike` (see `hoike-design.md`)

---

## 1. Introduction

An **ahu** bundle is a portable, self-describing container of pre-signed OCSP
responses. It exists so that the entity that *signs* certificate status and the
entity that *serves* it can be different machines, in different networks, under
different administrative control, possibly separated by an air gap.

The name is from the Hawaiian *ahu*: a cairn, a stack of stones left along a
trail as a marker for whoever comes next.

### 1.1 Design principles

1. **Responses are already self-authenticating.** Every entry in an ahu bundle
   is a complete, DER-encoded `OCSPResponse` signed by an authority the relying
   party already trusts. The container adds no trust to the response and is not
   required to validate one.

2. **The container defends against the mirror, not the client.** A mirror that
   holds no signing key cannot forge a status. It *can* omit entries, serve an
   old set, or replay a superseded generation. The manifest and its seal exist
   solely to detect those three attacks.

3. **Byte-for-byte replay.** A serving node returns the stored octets verbatim.
   It never parses, re-encodes, or re-signs a response. This eliminates an
   entire class of DER canonicalization bugs at the edge and makes the serving
   path trivially auditable.

4. **Mirrors hold no key material.** A node that only serves ahu bundles needs
   no HSM, no PKCS#11, and no secret. This is the property that makes wide
   geographic distribution and third-party mirroring safe.

5. **Readable by anyone.** The format is specified so that responders other than
   `hoike` can consume and serve ahu bundles. It is deliberately not coupled to
   the reference implementation.

### 1.2 Scope

In scope: container layout, manifest schema, integrity and anti-rollback rules,
delta encoding, distribution conventions.

Out of scope: how responses are produced, what revocation data source is
authoritative, the wire protocol between responder and client (that is
RFC 6960 and RFC 9919), and cluster membership (that is the responder's
concern).

### 1.3 Conventions

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described in BCP 14 (RFC 2119, RFC 8174) when in all capitals.

All multi-byte integers in the fixed binary structures are **big-endian**.
All hashes are SHA-256 unless a field explicitly carries an algorithm identifier.

### 1.4 Terminology

| Term | Meaning |
|---|---|
| **Producer** | The entity that generates and seals a bundle. Holds the seal key. |
| **Signer** | The entity that signs the OCSP responses. Often but not necessarily the same host as the producer. |
| **Mirror** | Any node that loads a bundle and serves responses from it. Holds no keys. |
| **CA scope** | The set of issuing CAs whose certificates a bundle covers. |
| **Entry** | One stored `OCSPResponse`. |
| **Entry key** | SHA-256 over the DER encoding of the `CertID` that addresses an entry. |
| **Epoch** | Monotonic counter, per (producer, CA), identifying a generation. |
| **Generation** | One full or delta bundle at a given epoch. |

---

## 2. Container layout

An ahu bundle is a single file, or an equivalent byte range in object storage.

```
+--------------------------------------------------+  offset 0
|  FILE HEADER            (64 bytes, fixed)         |
+--------------------------------------------------+
|  MANIFEST               (deterministic CBOR)      |
+--------------------------------------------------+
|  SEAL                   (CMS SignedData, detached)|
+--------------------------------------------------+
|  INDEX                  (sorted fixed-width recs) |
+--------------------------------------------------+
|  DATA                   (entry payloads)          |
+--------------------------------------------------+
```

Sections are contiguous and in this order. The header carries the offset and
length of each subsequent section, so a reader performs exactly one small read
before it knows the whole layout.

### 2.1 File header

```
Offset  Size  Field
------  ----  ---------------------------------------------------
  0      4    magic            = 0x41 0x48 0x55 0x31  ("AHU1")
  4      2    format_major     = 0x0000  (0 while draft)
  6      2    format_minor     = 0x0001
  8      8    manifest_offset
 16      4    manifest_length
 20      8    seal_offset
 28      4    seal_length
 32      8    index_offset
 40      8    index_length
 48      8    data_offset
 56      8    data_length
------  ----  ---------------------------------------------------
                                                    total 64 bytes
```

A reader MUST reject a file whose magic does not match, and MUST reject a
`format_major` it does not implement. A reader MUST tolerate an unknown
`format_minor` by ignoring manifest fields it does not recognize — minor
versions are additive only.

Header fields are **not** directly covered by the seal. They are validated
indirectly: the manifest carries digests of the index and data sections, so a
tampered offset either fails a digest check or points outside the file.

### 2.2 Manifest

Deterministic CBOR per RFC 8949 §4.2 (definite lengths, canonical map ordering,
shortest-form integers). Determinism is REQUIRED so that the manifest bytes can
be re-derived and digested reproducibly.

```
manifest = {
  1: uint,            ; format_version
  2: bstr .size 16,   ; bundle_id  (UUIDv7 RECOMMENDED — time-ordered)
  3: tstr,            ; producer_id (stable, e.g. "signer-a.pki.example")
  4: uint,            ; created_at (epoch seconds, UTC)
  5: uint,            ; bundle_type: 0 = full, 1 = delta
  6: [+ ca_scope],    ; one entry per issuing CA covered
  7: window,
  8: integrity,
  9: uint,            ; entry_count
 10: continuity,
 11: ? shard,
 12: ? compression,
 13: ? { * tstr => any }   ; producer extensions (advisory only)
}

ca_scope = {
  1: ~oid,            ; CertID hashAlgorithm this scope's keys were built with
  2: bstr,            ; issuerNameHash
  3: bstr,            ; issuerKeyHash
  4: uint,            ; epoch — monotonic for (producer_id, this CA)
  5: responder_id,
  6: ? [+ bstr],      ; responder cert chain, DER, leaf first
  7: ~oid,            ; signature algorithm used on responses in this scope
  8: uint             ; completeness: 0 = partial, 1 = authoritative-complete
}

responder_id = {
  1: uint,            ; 0 = byName, 1 = byKey  (byKey REQUIRED for new scopes)
  2: bstr             ; DER of the ResponderID CHOICE value
}

window = {
  1: uint,            ; produced_at        — earliest producedAt in the bundle
  2: uint,            ; this_update_min
  3: uint,            ; next_update_min    — bundle is useless after this
  4: uint             ; next_update_max
}

integrity = {
  1: bstr .size 32,   ; index_digest — SHA-256 over the INDEX section
  2: bstr .size 32    ; data_digest  — SHA-256 over the DATA section
}

continuity = {
  1: ? bstr .size 32, ; prev_manifest_digest — SHA-256 of the prior manifest
  2: ? bstr .size 32, ; base_manifest_digest — REQUIRED when bundle_type = 1
  3: uint             ; chain_length — generations since the last full bundle
}

shard = {
  1: uint,            ; shard_index
  2: uint,            ; shard_count
  3: uint             ; shard_fn: 0 = leading bits of entry key
}

compression = {
  1: uint,            ; 0 = none, 1 = zstd
  2: ? bstr .size 32  ; dictionary digest, if a shared dictionary is in use
}
```

#### Notes on specific fields

**`ca_scope.completeness`** is the field that determines mirror behavior on a
miss, and it is the most important semantic in the format:

- `authoritative-complete` — the producer asserts that every unexpired,
  non-revoked-and-not-yet-purged certificate issued by this CA is represented.
  A mirror that misses a lookup in this scope MUST answer `unauthorized`
  (RFC 9919 §3.2.3) and MUST NOT forward.
- `partial` — the bundle covers a subset (a shard, a hot set, a delta applied
  without its base). A mirror that misses MAY forward upstream, and MUST answer
  `unauthorized` if it cannot.

**`ca_scope.epoch`** is per-CA, not per-bundle, because one bundle can carry
several CAs whose generations advance at different rates.

**`window.next_update_min`** lets a mirror decide at load time whether a bundle
is already worthless, without walking every entry.

### 2.3 Seal

The seal is a **detached CMS `SignedData`** (RFC 5652) whose `eContent` is the
manifest octets exactly as they appear in the file.

- `eContentType` MUST be `id-ct-ahuManifest` (see §7).
- The `SignerInfo` MUST include the `content-type` and `message-digest` signed
  attributes.
- The seal certificate chain SHOULD be carried in `certificates`.
- The seal key MUST be distinct from any OCSP response signing key. They have
  different lifetimes, different threat exposure, and different rotation cadence.

CMS is chosen over COSE because the deploying audience already operates X.509
chain validation, PKCS#11 signing, and CMS tooling, and because ML-DSA in CMS
is being standardized on the same track as ML-DSA in certificates. A COSE
profile MAY be defined later as an alternative seal encoding; if so it gets a
distinct `format_minor` and a distinct media type parameter.

> **Open decision.** Whether the seal should instead be a bare COSE_Sign1 to
> keep the format usable in constrained environments with no ASN.1 stack. The
> counter-argument is that any consumer of this format is already parsing DER
> OCSP responses, so it has an ASN.1 parser by definition.

### 2.4 Index

A packed array of fixed-width records, sorted ascending by `entry_key`, byte
comparison. Fixed width plus sort order means a mirror binary-searches an
`mmap`ed region — no deserialization, no database, no allocation on the hot path.

```
Offset  Size  Field
------  ----  ---------------------------------------------------
  0     32    entry_key      = SHA-256(DER of CertID)
 32      8    data_offset    (relative to data_offset in header)
 40      4    data_length
 44      2    flags
 46      2    reserved (MUST be zero)
------  ----  ---------------------------------------------------
                                                    total 48 bytes
```

`flags` bit assignments:

| Bit | Name | Meaning |
|---|---|---|
| 0 | `MULTI` | The payload contains more than one `SingleResponse`. |
| 1 | `ALIAS` | Another index record points at the same payload. |
| 2 | `TOMBSTONE` | Delta only: remove this key from the working set. |
| 3–15 | — | Reserved, MUST be zero, readers MUST ignore if set. |

Two index records MAY point at the same payload. This is how RFC 9919 §3.2.1
dual-CertID responses work: one `BasicOCSPResponse` carrying a SHA-1 `CertID`
`SingleResponse` and a SHA-256 one is indexed under both entry keys, stored
once, and served to either generation of client. Both records set `ALIAS`.

Duplicate `entry_key` values MUST NOT appear. A reader that encounters a
non-ascending or duplicate key MUST reject the bundle.

### 2.5 Data

Each entry payload is a complete DER-encoded `OCSPResponse` — that is, the
outer `SEQUENCE` with `responseStatus` and `responseBytes`, not a bare
`BasicOCSPResponse`. A mirror can therefore write the bytes straight to the
socket after the HTTP headers.

If `compression.algorithm` is `zstd`, each payload is independently compressed
so that a single entry can be decompressed without touching its neighbors.
`data_length` in the index is the **stored** length. Producers SHOULD measure
before enabling compression: DER OCSP responses over classical signatures
compress poorly, and post-quantum signatures are effectively incompressible.
Compression is most useful for the embedded responder certificate chain, which
is highly repetitive across entries — a shared zstd dictionary trained on the
chain is the case where it pays.

---

## 3. Loading and serving rules

A mirror loading a bundle MUST, in this order:

1. Validate the header magic and `format_major`.
2. Parse the manifest and verify the seal, including chain validation of the
   seal certificate to a locally configured trust anchor. A mirror MUST NOT
   accept a seal chain solely because it was carried in the bundle.
3. Verify `integrity.index_digest` and `integrity.data_digest`.
4. For each `ca_scope`: compare `epoch` against the locally recorded high-water
   mark for `(producer_id, issuerKeyHash)`. **A mirror MUST reject a scope whose
   epoch is less than or equal to its high-water mark.** This is the anti-rollback
   rule and it is not optional.
5. If `continuity.prev_manifest_digest` is present, verify it matches the
   manifest digest the mirror recorded for the previous generation. A mismatch
   indicates a fork — the mirror MUST refuse the bundle and raise an alarm
   rather than choosing a branch.
6. For a delta, verify `base_manifest_digest` matches a bundle already loaded.
7. Verify the index is sorted and free of duplicates.
8. Atomically swap the working set and advance the high-water marks.

While serving, a mirror:

- MUST return stored octets unmodified.
- MUST NOT serve an entry after its `nextUpdate` has passed. Enforcement MAY be
  done at bundle granularity using `window.next_update_min`, which is simpler
  and fails safe.
- MUST answer `unauthorized` for a miss in an `authoritative-complete` scope.
- MUST NOT add, remove, or rewrite a nonce, and MUST NOT re-sign.
- SHOULD emit HTTP headers per RFC 9919 §6 and §7.2, deriving `Expires` from the
  response's `nextUpdate` and `ETag` from the SHA-256 of the response octets.

### 3.1 Verification depth

A mirror is NOT REQUIRED to validate the signature on each stored response. The
seal already establishes that the producer vouched for the set, and the client
performs the authoritative check. Validating every response at load time is
expensive at scale and is prohibitively so with post-quantum signatures.

However, a mirror SHOULD offer a `--verify-entries` mode that does exactly that,
for acceptance testing, for the first load after a producer key rotation, and
for import across a trust boundary such as an air gap. Operators moving bundles
into a classified or otherwise isolated enclave SHOULD run full verification on
import, since that is the one moment where the cost is acceptable and the
provenance is least certain.

---

## 4. Delta bundles

A delta carries only entries that were added, replaced, or removed since its
base. `bundle_type = 1`, `continuity.base_manifest_digest` is REQUIRED.

- **Add / replace** — an ordinary index record and payload. Applying it
  overwrites any entry with the same key in the working set.
- **Remove** — an index record with `TOMBSTONE` set and `data_length = 0`.
  Applying it deletes the key. Removals occur when a certificate passes its
  archive cutoff and the producer stops asserting status for it.

`continuity.chain_length` counts generations since the last full bundle. A
mirror SHOULD refuse to extend a chain beyond a configured maximum and demand a
full bundle, so that a mirror can never drift arbitrarily far from a known-good
snapshot. A reasonable default is 24.

Applying deltas is deterministic: for a given base and an ordered set of deltas
every mirror reaches an identical working set. Producers SHOULD publish the
expected working-set digest in `producer extensions` so mirrors can self-check.

---

## 5. Distribution

Transport is out of scope, but these conventions make independent
implementations interoperate.

**Media type:** `application/vnd.hoike.ahu` (vendor tree; see §7).
**File extension:** `.ahu`

**Discovery.** A producer SHOULD publish a JSON document describing available
generations:

```
GET /.well-known/ahu/catalog.json

{
  "producer_id": "signer-a.pki.example",
  "generations": [
    {
      "bundle_id":       "0192f3c8-...",
      "type":            "full",
      "epochs":          { "a1b2c3...": 4417 },
      "manifest_digest": "sha256:9f86d0...",
      "next_update_min": 1755561600,
      "size":            734003200,
      "url":             "/ahu/full/0192f3c8.ahu"
    },
    {
      "bundle_id":       "0192f3d1-...",
      "type":            "delta",
      "base":            "sha256:9f86d0...",
      "manifest_digest": "sha256:2c26b4...",
      "url":             "/ahu/delta/0192f3d1.ahu"
    }
  ]
}
```

The catalog is a convenience and carries no authority. Every claim in it is
re-verified from the sealed manifest after download. A mirror MUST NOT act on
catalog contents alone — in particular, it MUST NOT treat a catalog entry as
evidence that an epoch advanced.

**HTTP.** Producers SHOULD support conditional requests and `Range`, so a mirror
resuming a large full bundle does not restart. Bundles are immutable once
published; a corrected generation gets a new `bundle_id` and a new epoch, never
a rewrite in place.

**Offline transfer.** Because the bundle is a single sealed file, moving a
generation across an air gap is a file copy. Nothing in the format assumes
network availability, and no step of §3 requires reaching the producer.

---

## 6. Security considerations

### 6.1 What the seal does and does not do

The seal proves that a specific producer assembled a specific set of entries at
a specific epoch. It does **not** make the responses more trustworthy — their
own signatures do that — and a relying party never sees the seal.

Consequences worth stating plainly:

- A compromised mirror cannot forge a `good` for a revoked certificate. It has
  no key that any client trusts for that purpose.
- A compromised mirror *can* deny service, and can serve a stale-but-still-valid
  generation until `nextUpdate` expires. Short `nextUpdate` windows are the only
  real mitigation, and they trade directly against bundle regeneration cost.
- A compromised **producer** is a full compromise of status for its CA scopes.
  Producer key protection is therefore equivalent in importance to responder key
  protection, and both should be HSM-resident.

### 6.2 Selective omission

A mirror can drop entries and answer `unauthorized`. Clients typically treat
`unauthorized` as a soft failure, so this is a downgrade path. The
`authoritative-complete` flag plus `entry_count` in the sealed manifest lets an
auditing mirror or monitor detect a systematically short working set, but
nothing prevents omission at serve time. Deployments that care should monitor
the ratio of `unauthorized` responses per CA scope and alert on deviation.

### 6.3 Rollback

The epoch high-water rule in §3 step 4 and the `prev_manifest_digest` chain in
step 5 are what make replaying an old generation detectable. High-water marks
MUST be persisted across restarts — a mirror that forgets its high-water mark on
reboot has no rollback protection at all, and an attacker who can restart the
process can therefore strip it. Store them in the same durable state as the
loaded bundle, and treat a missing high-water record as a condition requiring
operator acknowledgment rather than silent acceptance.

### 6.4 Nonces

An ahu entry cannot satisfy an RFC 9654 nonce. Serving from a bundle means
serving without a nonce, which RFC 9919 §3.2.1 explicitly permits and which
conformant clients fall back from by validating on time. Deployments that
require nonce binding need a live-signing path, which by definition is not a
mirror. See the responder design document.

### 6.5 Privacy

Bundles are, collectively, the full serial-number space of the covered CAs.
Publishing one publicly discloses issuance volume and revocation patterns that
a per-query responder discloses only piecemeal. For a private or federal PKI
this may be a meaningful disclosure. Producers SHOULD consider whether bundles
should be distributed only to authenticated mirrors, and shard/partial bundles
exist partly so that a given mirror need not hold the whole space.

### 6.6 Time

Every rule in this document that involves `nextUpdate` assumes reasonable clock
synchronization on the mirror. A mirror with a badly slow clock will serve
expired generations. Mirrors SHOULD refuse to serve if they cannot establish a
trustworthy time source, and MUST log the condition.

---

## 7. Registrations and identifiers

These are placeholders until allocated. Obtain a Private Enterprise Number from
IANA before publishing anything that another implementation will encode against.

```
id-hoike           OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 <PEN> }
id-ct-ahuManifest  OBJECT IDENTIFIER ::= { id-hoike 1 1 }
```

Media type registration target: `application/vnd.hoike.ahu`, with an optional
`seal` parameter (`cms` | `cose`) if a second seal encoding is defined.

---

## 8. Test vectors

To be supplied with the reference implementation. The set should include, at
minimum:

1. Minimal full bundle — one CA, one entry, classical signature.
2. Dual-CertID aliasing — one payload, two index records.
3. Multi-CA bundle with divergent epochs.
4. Delta with add, replace, and tombstone.
5. Rollback attempt — a bundle at epoch N−1 that a conformant mirror MUST reject.
6. Fork attempt — mismatched `prev_manifest_digest`.
7. Truncated data section — digest mismatch.
8. Post-quantum bundle signed with ML-DSA, for size and parsing regression.

---

## 9. Open questions

1. **Seal encoding** — CMS as specified, or COSE_Sign1 for lighter consumers.
2. **Whether `TOMBSTONE` belongs in the index at all**, or whether removals
   should be a separate manifest list. Index tombstones keep one code path;
   a separate list keeps the index purely a lookup structure.
3. **Shared compression dictionaries** — real gains on repeated responder
   certificate chains, but a dictionary is now a distribution dependency.
4. **Whether to carry the responder certificate chain in the manifest rather
   than in every response.** It would cut post-quantum bundle size dramatically,
   but RFC 9919 §3.2.2 requires a delegated responder certificate to be
   referenced in `BasicOCSPResponse.certs`, so it can only be an optimization
   for CA-direct signing, not for delegated signing.
5. **Sharding function** — leading bits of the entry key distributes evenly but
   destroys serial-number locality. If operators want "shard by CA and serial
   range," that is a different function and should be enumerated now.
