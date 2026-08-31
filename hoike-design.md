# hoike — Design Document

**A Rust OCSP responder for pre-signed, replayable, multi-CA, highly available status.**

**Version:** 0.2
**Author:** Chris Zinda
**Companion:** `ahu-format-spec.md`

> **Implementation status:** Most features described here are implemented in
> v0.2.0. For remaining gaps, see [README.md](README.md) — specifically the
> Known Limitations section. Gossip authentication, full PKIX seal chain
> validation, and several revocation source adapters remain planned.

---

## 1. What this is and why

*Hōʻike* — to show, to exhibit, to testify. An OCSP responder does exactly one
thing: it testifies to the status of someone else's certificate.

`hoike` is a responder built around a single architectural bet: **the machine
that signs status and the machine that serves it should not be the same
machine.** Everything else in this design follows from that.

### 1.1 Goals

- Full RFC 6960 and RFC 9919 conformance, RFC 9654 nonce handling.
- Pre-signed responses, packaged as `ahu` bundles, servable by any conformant
  responder — not just this one.
- One responder instance serving many CAs.
- High availability with no single point of failure in the serving path.
- Keyless edge nodes.
- Post-quantum ready: ML-DSA response signing as a first-class configuration,
  not a patch.
- Usable in air-gapped and disconnected enclaves without degradation.

### 1.2 Non-goals

- Being a CA. Issuance is `akamu`'s and Dogtag's job.
- Being a CRL distribution point. Complementary, separate concern.
- Chasing the public Web PKI. The CA/Browser Forum made OCSP optional and
  mandated CRLs in SC-063, and Let's Encrypt shut its responders down in
  August 2025. The market for this is enterprise, federal and DoD, device and
  IoT PKI, and 802.1X/EAP-TLS — environments where OCSP is contractually
  required and where CRL size makes CRLs impractical. Say so in the README so
  nobody mistakes the intent.

### 1.3 Standards conformance targets

| Document | Role |
|---|---|
| RFC 6960 | Base protocol. Full request/response, all status values, extensions. |
| RFC 9919 | Primary operating profile. Pre-production, `unauthorized` semantics, `byKey` ResponderID, SHA-256 CertID, HTTP caching. |
| RFC 9654 | Nonce length rules and rejection behavior. |
| RFC 5280 | AIA `id-ad-ocsp`, responder certificate profile, `id-pkix-ocsp-nocheck`. |
| RFC 9846 / RFC 6066 §8 | Stapling context. Note RFC 6961 `status_request_v2` is obsoleted — do not implement it. |
| RFC 7633 | TLS Feature / must-staple awareness for operator tooling. |
| RFC 4806 | Optional: OCSP in IKEv2, if the IPsec use case is pursued. |

---

## 2. Architecture

### 2.1 Tiers

```
        revocation source                    ┌───────────────────┐
   (Dogtag / RHCS, 389 DS, CRL,              │  SIGNER TIER      │
    akamu, kipuka, database)  ───────────────▶│                   │
                                             │  • reads status   │
                                             │  • batch windows  │
                                             │  • signs (HSM)    │
                                             │  • seals bundles  │
                                             └─────────┬─────────┘
                                                       │ ahu bundles
                              ┌────────────────────────┼────────────────────────┐
                              │                        │                        │
                        ┌─────▼──────┐          ┌──────▼─────┐          ┌───────▼──────┐
                        │ EDGE NODE  │◀──gossip─▶│ EDGE NODE  │◀──gossip─▶│  EDGE NODE   │
                        │  keyless   │          │  keyless   │          │  keyless     │
                        └─────┬──────┘          └──────┬─────┘          └───────┬──────┘
                              │                        │                        │
                              └────────────── clients ─┴────────────────────────┘

                        ┌──────────────────────────────────────────┐
                        │ AIR-GAPPED ENCLAVE                       │
                        │   edge node, bundle imported from media  │
                        │   no gossip, no upstream, identical code │
                        └──────────────────────────────────────────┘
```

**Signer tier.** Holds keys. Reads authoritative revocation state. Produces and
seals bundles on a batch cadence. Active/standby per CA. Not on the request path.

**Edge tier.** Holds no keys. Loads bundles, serves bytes, returns
`unauthorized` on a miss. Stateless apart from its loaded working set and its
persisted epoch high-water marks. Horizontally scalable, anycast-friendly.

**All-in-one.** For small deployments — a lab, a single enterprise CA — one
process runs both tiers. Same code paths, `mode = "combined"`. This is what
makes the design approachable rather than only correct at scale.

### 2.2 The trust boundary

The property to protect: **an edge node compromise must not produce a false
`good`.** It cannot, because it has no key any client trusts for OCSP signing.
The realistic attacks on an edge are denial of service, stale-generation replay
within `nextUpdate`, and selective omission. Section 6 addresses each.

A corollary worth internalizing during implementation: any feature that requires
an edge node to hold a signing key breaks the model. Nonce live-signing is the
one such feature, and it is why nonce policy is a per-CA configuration decision
rather than a global toggle.

---

## 3. Data model

### 3.1 CA context

Each configured CA yields a context:

```rust
struct CaContext {
    label:            String,
    issuer_name_hash: HashMap<HashAlg, Vec<u8>>,   // SHA-1 and SHA-256
    issuer_key_hash:  HashMap<HashAlg, Vec<u8>>,
    responder_id:     ResponderId,                 // byKey for new deployments
    responder_chain:  Option<Vec<Certificate>>,    // delegated signing only
    signing:          SigningMode,                 // Delegated | CaDirect
    sig_alg:          AlgorithmIdentifier,
    nonce_policy:     NoncePolicy,
    validity:         ValidityPolicy,
    archive_cutoff:   Option<Duration>,
    source:           RevocationSource,
}
```

### 3.2 Routing and the issuerKeyHash multimap

Requests carry a `CertID`, not a CA name. Routing is a lookup on
`(hashAlgorithm, issuerNameHash, issuerKeyHash)`.

This **must** be a multimap. Cases that produce collisions:

- A re-keyed CA that retained its subject DN — same `issuerNameHash`, different
  `issuerKeyHash`.
- A cross-signed CA — same key, several issuer DNs.
- Two CAs deliberately sharing a key across a hierarchy migration.

On a collision the responder resolves by serial number: consult every matching
context, and answer from whichever holds an entry. If more than one holds an
entry for the same serial, that is a misconfiguration — log loudly, answer from
the first by configuration order, and expose a metric. Silently picking one is
how you end up debugging a "wrong status" ticket for a week.

Because a `BasicOCSPResponse` carries a single signature, a multi-`CertID`
request that spans two CAs cannot be answered in one response. Answer only the
`CertID`s covered by one signer and omit the rest; RFC 9919 profiles requests to
a single `Request` anyway, so this is an edge case, but it must not panic.

### 3.3 Revocation sources

An adapter trait, so the signer tier is not coupled to one CA product:

```rust
trait RevocationSource {
    async fn snapshot(&self, ca: &CaContext) -> Result<StatusSnapshot>;
    async fn changes_since(&self, ca: &CaContext, since: Epoch)
        -> Result<Vec<StatusChange>>;
    fn supports_streaming(&self) -> bool;
}
```

Planned adapters:

| Adapter | Status | Notes |
|---|---|---|
| CRL ingest | **Implemented** | Lowest common denominator. Works against any CA. Cannot distinguish "unknown" from "not issued". |
| Red Hat Directory Server / 389 DS syncrepl | **Implemented** | RFC 4533 Content Synchronization against the CA's certificate repository. Provides positive issuance for `authoritative-complete` bundles. |
| Red Hat Certificate System / Dogtag REST | Planned | REST; the primary target. Also the source of issued-but-not-revoked enumeration. |
| akamu | Planned | Native event feed from the ACME CA. |
| SQL | Planned | Generic table contract for bespoke PKIs. |

Note the CRL-ingest asymmetry: from a CRL you learn who is revoked but not who
was ever issued, so a CRL-sourced scope cannot be `authoritative-complete` and
cannot safely return `good` for an arbitrary serial. It can only mark a scope
`partial` and answer `unauthorized` on a miss — unless paired with an issuance
feed. This is a real limitation and should be surfaced in configuration
validation, not discovered in production.

---

## 4. Response production

### 4.1 Batch windows

The signer produces on a fixed cadence per CA. Defaults:

```
batch_interval  = 1h        # how often a generation is produced
validity        = 24h       # nextUpdate - thisUpdate
max_age_fraction = 0.5      # Cache-Control max-age as a fraction of validity
urgent_revocation = true    # revocations trigger an off-cycle delta
```

Timestamp rules, straight from RFC 9919 §3.2.4 — all GeneralizedTime, Zulu,
seconds present, no fractional seconds:

- `thisUpdate` — when the status was known correct, i.e. the snapshot instant.
- `nextUpdate` — REQUIRED under this profile. Never omit it.
- `producedAt` — when signed. Usually equal to `thisUpdate`.

**Jitter.** Clients refresh at `nextUpdate`, so identical `nextUpdate` values
across millions of responses produce a synchronized stampede. Spread
`nextUpdate` deterministically across the window by hashing the entry key:

```
next_update = this_update + validity + jitter(entry_key, jitter_window)
```

Deterministic jitter means the same certificate lands in the same slot every
generation, so a client's refresh rhythm stays stable instead of walking.

`Cache-Control: max-age` must be earlier than `nextUpdate` and later than
`thisUpdate`, and the responder must have refreshed before `max-age` elapses —
RFC 9919 §7.1 makes that a MUST, and it is the constraint that ties
`batch_interval` to `validity`.

### 4.2 Dual CertID

Per RFC 9919 §3.2.1, one `BasicOCSPResponse` may carry two `SingleResponse`
elements for the same certificate, one with a SHA-1 `CertID` and one with
SHA-256. For pre-production this is strictly better than generating two
responses: one signature, one payload, two index records in the bundle.

Make it a per-CA switch (`certid_compat = "dual" | "sha256" | "sha1"`), default
`dual`, and log the CertID hash algorithm on every request so operators can see
when their last SHA-1 client goes away and turn it off. RFC 9919 §3.2.1
recommends exactly that logging.

### 4.3 Non-issued and unknown

Three distinct outcomes, frequently conflated:

| Situation | Answer | Why |
|---|---|---|
| Known, not revoked | `good` | Normal. |
| Known, revoked | `revoked` + reason + time | Normal. |
| Serial never issued by this CA | `revoked`, `certificateHold` **or** `unauthorized` | Never `good`. RFC 6960 §2.2 permits `revoked` for non-issued; the CA/Browser Forum forbids `good`. |
| Not in the working set | `unauthorized` | RFC 9919 §3.2.3. Unsigned, cheap, correct for a mirror. |

The fourth row is the one that makes keyless edges viable: the correct answer
for "I don't have this" is an unsigned status code, so an edge never needs a key
to say it.

### 4.4 Nonce policy

Per CA, one of:

- **`ignore`** (default) — serve the pre-signed response without a nonce.
  Conformant clients fall back to time-based freshness. RFC 9919 §3.2.1
  explicitly blesses this.
- **`live`** — sign a fresh response carrying the nonce. Requires key access,
  therefore only available on a signer-tier or combined node. Configuring
  `live` on an edge is a startup error, not a runtime surprise.
- **`forward`** — proxy nonce-bearing requests to a node configured for `live`.
  RFC 9919 §3.2.1 permits this explicitly.

RFC 9654 length rules are enforced regardless of policy:

| Nonce length | Behavior |
|---|---|
| 0 octets | `malformedRequest` |
| 1–15 | MAY omit nonce from response |
| 16–32 | MUST be accepted |
| 33–128 | MAY omit nonce from response |
| > 128 | `malformedRequest` |

### 4.5 Post-quantum sizing

The problem with ML-DSA here is not speed — signing is fast and precomputation
is a batch job. It is size, and it lands on storage and bandwidth.

Approximate, order-of-magnitude, for one `SingleResponse`:

| Signing | Signature | Response, no cert | Response + delegated responder cert |
|---|---|---|---|
| ECDSA P-256 | ~72 B | ~0.4 KB | ~1.4 KB |
| RSA-3072 | 384 B | ~0.7 KB | ~2.3 KB |
| ML-DSA-44 | 2,420 B | ~2.8 KB | ~9 KB |
| ML-DSA-65 | 3,309 B | ~3.7 KB | ~12 KB |
| ML-DSA-87 | 4,627 B | ~5.0 KB | ~16 KB |

At 10 million certificates, ML-DSA-87 with a delegated responder certificate is
roughly 160 GB per full generation. That is the number that should drive
engineering decisions, and it suggests three levers:

1. **CA-direct signing** omits the responder certificate from `certs` entirely,
   cutting size by roughly two thirds. RFC 9919 §3.2.2 requires the responder
   certificate in `certs` only when signing is *delegated*, so this is available
   only if you accept the CA key in the signing tier. With an HSM that is often
   acceptable in a private PKI; in a public-facing one it is usually not.
2. **Batching `SingleResponse` elements** — one signature covering N
   certificates in a `CertID`-prefix bucket amortizes the signature cost across
   the bucket. Storage drops nearly linearly with bucket size; single-lookup
   response size rises. RFC 9919 §3.2.1 permits multiple `SingleResponse`
   elements for exactly this reason. Make bucket size a tunable and publish the
   curve — this is a genuinely useful benchmark nobody has published.
3. **Delta-only distribution** to steady-state mirrors, with full bundles only
   on join or chain-length exhaustion.

Given Red Hat Certificate System 11.0 shipping ML-DSA support, a PQC
interoperability demonstration between it and `hoike` is within reach and would
be the most compelling thing you could show.

---

## 5. Request path

```
HTTP request
   │
   ├─ GET  → base64-decode + URL-decode path segment (RFC 9919 §6)
   └─ POST → body, Content-Type: application/ocsp-request
   │
   ├─ size guard, then DER parse (strict; reject non-minimal lengths)
   ├─ profile checks → malformedRequest on violation
   ├─ nonce validation per §4.4
   │
   ├─ route: (hashAlg, issuerNameHash, issuerKeyHash) → CaContext(s)
   │      └─ no match → unauthorized
   │
   ├─ lookup: entry_key = SHA-256(DER CertID) → binary search mmap index
   │      ├─ hit  → write stored octets verbatim
   │      └─ miss → authoritative-complete ? unauthorized : forward-or-unauthorized
   │
   └─ HTTP headers per RFC 9919 §6/§7.2:
        Content-Type: application/ocsp-response
        Last-Modified: thisUpdate
        Expires: nextUpdate
        ETag: "<hex SHA-256 of response octets>"
        Cache-Control: max-age=<n>, public, no-transform, must-revalidate
```

Two implementation notes that will save time later.

**Strict DER on input, canonical DER on output.** Enforce minimal-length
encoding on parse and assert it on everything emitted, including everything an
HSM hands back. Non-minimal DER length encoding from an HSM is a real, shipped
bug class that surfaces as an opaque failure three layers away from its cause.
A cheap canonical-form assertion at the signing boundary turns a week of
debugging into a log line.

**Never allocate per request on the hot path.** The response is already bytes in
an `mmap`ed region. `writev` the headers and the slice. No parse, no copy, no
re-encode.

---

## 6. High availability and gossip

### 6.1 What is actually stateful

| Component | State | Failure impact |
|---|---|---|
| Edge node | Loaded working set + epoch high-water marks | None; peers absorb load |
| Signer | Batch position, HSM session | Generations stop advancing; existing responses stay valid until `nextUpdate` |
| Revocation source | Authoritative | Signer degrades to last snapshot |

The system fails soft in the direction you want. A total signer outage does not
take status offline; it freezes it, and `validity` sets how long that is
tolerable. That relationship — signer outage budget equals `validity` minus
`batch_interval` — should be stated in the operations documentation, because it
is the single number an operator needs.

### 6.2 Signer election

One active signer per CA, standbys warm. A lease in shared state (etcd,
Consul, or a database row with a fencing token) is sufficient — this does not
need Raft. If two signers briefly overlap, the failure mode is duplicate
generations at the same epoch, which mirrors detect via the anti-rollback and
continuity rules and refuse. Prefer a stall over a fork; make the lease
conservative.

### 6.3 Gossip

SWIM via `foca`, or Scuttlebutt via `chitchat`. Three uses, and nothing else:

1. **Membership and failure detection.** Who is up, who left, who to route to.
2. **Generation announcements.** "I hold epoch N for CA X, manifest digest D."
   Followed by anti-entropy pull from any peer that has it. This is what turns
   bundle distribution from a hub-and-spoke fetch into a fleet that converges on
   its own, and it is why the producer's link does not have to serve every node.
3. **Urgent revocation notice.** A signed, minimal object announcing "an
   off-cycle delta exists for CA X." It shortens the window between a revocation
   and its visibility without waiting for the next batch.

**Rules that keep gossip from becoming an attack surface:**

- Gossip is **never authoritative for status**. It announces the existence of
  signed artifacts; it never carries status claims. A node acts on gossip only
  by fetching and validating a sealed bundle.
- Every message is signed. An unsigned "revoked" rumor is a denial-of-service
  primitive against a certificate holder; an unsigned "good" rumor would be
  worse. Signing removes both.
- Epoch high-water rules from the format spec apply to gossip-sourced bundles
  identically. There is no fast path that skips validation because a peer
  vouched for it.
- Membership churn must not affect the serving path. A node partitioned from the
  gossip mesh keeps serving its current working set. Availability of status must
  never depend on cluster consensus.

**Enclave mode.** Gossip is disabled entirely and bundles arrive on removable
media. The serving code path is byte-identical to a connected node; only
acquisition differs. Given the DISA and air-gapped work, this should be a
first-class tested configuration with its own CI job, not a documented
possibility.

---

## 7. Configuration sketch

```toml
[server]
mode          = "edge"              # "signer" | "edge" | "combined"
listen        = "0.0.0.0:2560"
max_request   = 8192                # bytes; RFC 9919 GETs are ≤255

[storage]
bundle_dir    = "/var/lib/hoike/bundles"
state_db      = "/var/lib/hoike/state"   # epoch high-water marks — MUST persist
max_chain     = 24                       # deltas before demanding a full bundle

[gossip]
enabled       = true
bind          = "0.0.0.0:7946"
seeds         = ["edge-a.pki.example:7946", "edge-b.pki.example:7946"]
identity_key  = "/etc/hoike/gossip.key"

[[ca]]
label          = "enterprise-issuing-01"
source         = { type = "dogtag", url = "https://ca01.pki.example:8443",
                   auth = "mtls", cert = "/etc/hoike/ra.pem" }
signing        = "delegated"
responder_cert = "/etc/hoike/responder-01.pem"
responder_key  = { pkcs11 = "pkcs11:token=luna;object=hoike-responder-01" }
sig_alg        = "ml-dsa-65"
responder_id   = "by-key"
certid_compat  = "dual"
nonce_policy   = "ignore"
validity       = "24h"
batch_interval = "1h"
jitter         = "2h"
archive_cutoff = "1y"
completeness   = "authoritative-complete"

[[ca]]
label          = "iot-issuing-01"
source         = { type = "crl", url = "http://crl.pki.example/iot.crl" }
completeness   = "partial"          # CRL source cannot assert completeness
nonce_policy   = "forward"
forward_to     = "https://signer-a.pki.example:2560"
```

---

## 8. CLI surface

```
hoike serve [--config PATH]
hoike sign      --ca LABEL [--full|--delta]     # signer tier: produce a generation
hoike check     --config PATH                   # validate config, HSM, sources
hoike query     URL --cert FILE --issuer FILE   # diagnostic client

ahu inspect  FILE                  # manifest, scopes, epochs, counts
ahu verify   FILE [--entries]      # seal, digests, sort order, optional per-entry
ahu extract  FILE --certid HEX     # pull one response out
ahu diff     A B                   # what changed between generations
ahu apply    BASE DELTA... -o OUT  # materialize a working set offline
```

`ahu` shipping as a standalone binary matters: it is what lets an operator on
the far side of an air gap confirm what they received before importing it.

---

## 9. Observability

Metrics (Prometheus):

```
hoike_requests_total{ca,method,status}          # status: good|revoked|unknown|unauthorized|malformed
hoike_request_duration_seconds{ca}
hoike_certid_hash_alg_total{ca,alg}             # watch SHA-1 decline to zero
hoike_nonce_requests_total{ca,policy,outcome}
hoike_bundle_epoch{ca,producer}                 # gauge; alert on staleness
hoike_bundle_entries{ca}
hoike_bundle_age_seconds{ca}
hoike_bundle_next_update_seconds{ca}            # alert well before this hits 0
hoike_bundle_load_failures_total{ca,reason}     # reason: rollback|fork|digest|seal
hoike_gossip_members{state}
hoike_signer_generation_duration_seconds{ca}
```

The two alerts that matter most: `bundle_next_update_seconds` trending toward
zero (status is about to go stale) and any nonzero
`bundle_load_failures_total{reason="rollback"}` or `reason="fork"` (someone is
either attacking you or your signer forked — both need a human immediately).

Audit log: every bundle load with manifest digest, epoch transitions, every
rejected bundle with reason, every signer generation with entry counts.

---

## 10. Workspace layout

```
hoike/
├── Cargo.toml                # workspace
├── crates/
│   ├── ahu/                  # format: read, write, verify.  Apache-2.0 OR MIT
│   ├── hoike-core/           # CertID routing, policy, response assembly
│   ├── hoike-sign/           # PKCS#11, signing, generation production
│   ├── hoike-server/         # HTTP, request path
│   ├── hoike-gossip/         # SWIM membership + announcements
│   └── hoike-cli/            # hoike + ahu binaries
├── ahu-format-spec.md        # versioned independently of the daemon
└── testdata/                 # vectors from spec §8
```

**The `ahu` crate must not depend on tokio, hyper, PKCS#11, or anything else in
the server's runtime.** DER in, DER out, plus the manifest schema and the epoch
rules. If it will not build with `--no-default-features` in a constrained
context, the boundary has leaked and the format has quietly become
implementation-specific.

### 10.1 Dependencies

| Need | Candidate | Note |
|---|---|---|
| OCSP types | `x509-ocsp` (RustCrypto) | Self-described as early-stage; expect to contribute upstream. `rasn-ocsp` is the alternative. |
| X.509 / DER | `x509-cert`, `der` | Same ecosystem, consistent. |
| HTTP | `axum` / `hyper` | |
| Gossip | `foca` (SWIM) or `chitchat` | |
| Index store | `mmap` + custom, or `redb` | The format is designed for the former. |
| CBOR | `ciborium` | Must produce deterministic encoding per RFC 8949 §4.2. |
| CMS | `cms` (RustCrypto) | For the seal. |
| HSM | `cryptoki` | PKCS#11 v3; ML-DSA via the vendor's v3.2 mechanisms. |
| Compression | `zstd` | |

### 10.2 Licensing

kipuka is GPL-3.0-or-later. Applying that to `ahu` would mean no differently
licensed responder can implement against the reference reader — which defeats
the reason the format exists. Recommended split: **`ahu` under Apache-2.0 OR
MIT** (matching the RustCrypto ecosystem it depends on), **`hoike` server crates
under GPL-3.0-or-later** (matching kipuka), spec text under a permissive
documentation license. Confirm with someone who does licensing professionally
before contributors arrive — relicensing after the fact is painful.

---

## 11. Testing and conformance

**Interoperability targets.** Every one of these has quirks worth discovering
early: OpenSSL `ocsp`, NSS `ocspclnt`, Go `crypto/x509` + `golang.org/x/crypto/ocsp`,
Java `PKIXRevocationChecker`, Windows CryptoAPI, `certmonger`, Red Hat Certificate
System's own client, and the .NET stack — which, notably, stopped sending nonces
because responders choke on them.

**Conformance suite.** An RFC 9919 / RFC 9654 conformance module is a natural
addition to Infrared, and it does double duty: it validates `hoike` and it
validates everyone else's responder. Checks worth encoding:

- `nextUpdate` present, GeneralizedTime Zulu with seconds, no fractional seconds
- `byKey` ResponderID on new responders
- SHA-256 CertID support; dual-CertID handling
- `unauthorized` on unknown rather than a signed `good`
- Never `good` for a non-issued serial
- Nonce boundary behavior at 0, 1, 15, 16, 32, 33, 128, 129 octets
- HTTP header set, and absence of `no-cache` / `no-store` on authoritative responses
- GET accepted at ≤255 bytes; correct base64 and URL encoding handling

**Adversarial tests for the format.** Rollback, fork, truncation, duplicate
keys, unsorted index, oversized manifest, and a bundle whose seal chains to an
untrusted anchor. Each must produce a clean rejection with a distinct reason
code, never a partial load.

**Lab.** cert-revocation-lab already has Dogtag, SoftHSM2, akamu, and kipuka.
Adding `hoike` completes the loop: kipuka enrolls over EST, akamu over ACME,
Dogtag issues and revokes, `hoike` testifies — with an ML-DSA scope alongside a
classical one to demonstrate both.

---

## 12. Milestones

| | Scope |
|---|---|
| **M0** | `ahu` crate: read, write, verify, `ahu inspect`. Spec §8 test vectors. No server. |
| **M1** | Single-CA edge: load a bundle, serve GET and POST, correct headers, `unauthorized` on miss. Interop against OpenSSL and Go. |
| **M2** | Signer tier: Dogtag adapter, batch production, PKCS#11 delegated signing, full and delta generations. |
| **M3** | Multi-CA routing with the issuerKeyHash multimap; nonce policy all three modes; combined mode. |
| **M4** | Gossip membership and generation propagation; enclave import path; anti-rollback persistence hardening. |
| **M5** | ML-DSA scopes end to end; publish the batching-vs-size curve; Infrared conformance module. |

---

## 13. Open questions

1. **Nonce scope.** If `live` and `forward` are dropped, edges are keyless by
   construction and that is a much stronger story to sell. If any target
   customer contractually requires nonce binding, they cannot be. This decision
   shapes the trust boundary and should be settled before M1.
   **Resolved:** `live` and `forward` are implemented as per-CA configuration options.
2. **CA-direct signing as a supported mode**, given how much it saves under
   post-quantum signatures, against the operational cost of the CA key living in
   the signing tier.
3. **Response batching bucket size** — needs measurement, not a guess.
4. **Whether `hoike` should also serve CRLs.** Same revocation data, same
   distribution problem, and the Web PKI has moved that direction. It is scope
   creep now, but designing the source adapters so it stays possible costs
   nothing today.
5. **Seal encoding** — CMS as specified, or COSE. Carried over from the format
   spec. **Resolved:** CMS `SignedData` is the implemented seal format, supporting both ECDSA P-256 and ML-DSA.
