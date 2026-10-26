# ahu 0.1 golden wire-profile vectors

Immutable golden vectors pinning the **as-implemented ahu 0.1 wire profile**
(F12). The specification is `ahu-format-spec.md` at the repository root; the
tests that consume these files are `crates/ahu/tests/wire_profile.rs`.

## Profile summary

| Layer | Value |
|---|---|
| File header `format_major`.`format_minor` | **0.1** |
| CBOR manifest `format_version` | **1** |
| Companion implementation package | 0.2 (independent of both) |

- 64-byte big-endian file header, magic `AHU1`; sections contiguous in the
  order manifest, seal, index, data.
- Manifest is deterministic CBOR (RFC 8949 §4.2).
- Seal is a detached CMS `SignedData` (RFC 5652) over `id-data`
  (1.2.840.113549.1.7.1), `eContent` absent, one SignerInfo, SHA-256 digest,
  exactly one `content-type` signed attribute (value `id-data`) and one
  `message-digest` signed attribute (SHA-256 of the manifest octets).
- Index records are 48 bytes: `entry_key[32] data_offset u64 data_length u32
  flags u16 discriminator u16`, all big-endian, sorted ascending by
  `(entry_key, discriminator)`; duplicate pairs are invalid. The
  discriminator sits at record bytes **46–47**.

## Files

| File | SHA-256 |
|---|---|
| `minimal-full.ahu` | `3233a3e72fe2b2fe340c4d0b6a6c795e77bb6fb09f2e67ff3b7a339c3f57b93c` |
| `dual-algorithm.ahu` | `9803d3feffa6bdbaef12cdd1d0f5e41402bad7866f669e519242158e2a58ea23` |
| `seal-cert.der` | `64ed217c144a554dd25c7ba0ee86c8968aee3426ba72c90c7b76df5b73d4ea32` |

`gen/` is the standalone generator (see below). Payloads in the `.ahu` files
are documented opaque placeholder octets — the container serves bytes
verbatim and never parses them. Entry keys are SHA-256 over documented
preimages standing in for SHA-256(DER of CertID).

## Fixed test verification time

`1_800_000_000` (2027-01-15T08:00:00Z), inside the recorded
seal-certificate validity window below. These are immutable vectors, so a
fixed time is acceptable **only** here; production clocks stay real.

## Seal certificate (recorded)

| Field | Value |
|---|---|
| Subject / issuer | `CN=hoike-wire-profile-0.1` (self-signed) |
| Serial | 1 |
| Public key | ECDSA P-256 (SEC1 uncompressed, see below) |
| notBefore | 1700000000 — 2023-11-14T22:13:20Z (`231114221320Z`) |
| notAfter | 2200000000 — 2039-09-18T23:06:40Z (`390918230640Z`) |
| Extensions | none |

Seal public key (SEC1, hex):
`04e45054eb5b1abd976650f7f395bf51d0d8dd193e0174e7a14a1c8c127fbdf2dbaefe3293b0445f3f92bf8e108202e009415c899499620c71b7f6df9021132c9c`

The seal key is the P-256 key with secret scalar `0x77` repeated 32 times —
a synthetic test key, not a secret. Signatures use deterministic RFC 6979
nonces, so generation is byte-reproducible.

## minimal-full.ahu — decoded field values

One CA scope, one entry, classical (discriminator 0) payload, full bundle,
no compression, shard, or extensions.

| Field | Value |
|---|---|
| Size | 1007 bytes |
| bundle_id | `01939f6e-b000-7000-8000-000000000001` |
| producer_id | `wire-profile-0.1` |
| created_at | 1800000000 |
| bundle_type | 0 (full) |
| format_version | 1 (header 0.1) |
| Manifest section | offset 64, length 275 |
| Manifest SHA-256 | `24117fd43fd011f0c11372999782e38a552bfa2b7bd7f10267d75711045c1450` |
| Seal section | offset 339, length 587 |
| Seal SHA-256 | `a1c9171e8db65a7a0b870097f9cdd6c62b5bb92c3e37899497bb2962c53054f9` |
| Index section | offset 926, length 48 (1 record) |
| Data section | offset 974, length 33 |
| entry_count | 1 |

CA scope:

| Field | Value |
|---|---|
| hash_algorithm | `60 86 48 01 65 03 04 02 01` (SHA-256 OID content octets) |
| issuer_name_hash | `0f855f353e3f5f659b80ed460bcb790be3b8292cd80a294d9daedcf6d6a12a5f` |
| issuer_key_hash | `659822b1182b16b4c74928593eecba48b45561f64638380dc05db5c48a2f3dc2` |
| epoch | 1 |
| responder_id | byKey, `aca810ed940d82d6abcd6e9102eb0f287c887ebe` (first 20 bytes of the responder-key hash below) |
| signature_algorithm | `2A 86 48 CE 3D 04 03 02` (ECDSA-with-SHA256 OID content octets) |
| completeness | 1 (authoritative-complete) |

Hash preimages (SHA-256):

- `issuer_name_hash` = SHA-256(`wire-profile-0.1/issuer-name`)
- `issuer_key_hash` = SHA-256(`wire-profile-0.1/issuer-key`)
- responder_id value = SHA-256(`wire-profile-0.1/responder-key`)[0..20]

Window: produced_at 1800000000, this_update_min 1800000000,
next_update_min 1800086400, next_update_max 1800093600.
Continuity: no prev/base digest, chain_length 0.

Index record 0:

| Field | Value |
|---|---|
| entry_key | `2fe209d00a9083c1d1970e9342b45da16a54dd1a311192d0b17d909a07a78597` = SHA-256(`wire-profile-0.1/minimal/certid`) |
| data_offset / length | 0 / 33 |
| flags | 0x0000 |
| discriminator | 0x0000 |

Payload: ASCII `wire-profile-0.1/minimal/response`.

## dual-algorithm.ahu — decoded field values

Same shape and CA scope as `minimal-full.ahu`, except:

| Field | Value |
|---|---|
| Size | 1096 bytes |
| bundle_id | `01939f6e-b000-7000-8000-000000000002` |
| Manifest SHA-256 | `d3bc5967d7e5c19b0bd853bf94cc7afd4d2772f2a3c7ef14d468a2e80a4e9088` |
| Seal SHA-256 | `1912f7ec3f559a36c4d74a82342af82314a514d3e3161b65eefdd16fc34f0969` |
| Index section | offset 926, length 96 (2 records) |
| Data section | offset 1022, length 74 |
| entry_count | 2 |

One entry key with two records, demonstrating the documented
`(entry_key, discriminator)` order — discriminator 0 (default) first, then 4
(ML-DSA-87):

| # | entry_key | data_offset / length | flags | discriminator | payload |
|---|---|---|---|---|---|
| 0 | `86034854a403b858b5c11d2b16d2680b93bd40fddb5cc710eacb950b51c88296` | 0 / 36 | 0x0000 | 0x0000 | `wire-profile-0.1/dual/response/ecdsa` |
| 1 | (same) | 36 / 38 | 0x0000 | 0x0004 | `wire-profile-0.1/dual/response/mldsa87` |

entry_key = SHA-256(`wire-profile-0.1/dual/certid`). The discriminator-4
payload is a placeholder — the container does not inspect or verify payload
signatures, and the presence of a defined discriminator value does not imply
the serving profile advertises that algorithm.

## Generation instructions

The vectors are produced by `gen/`, a standalone Cargo package that is
deliberately **not** a member of the hoike workspace and shares no code with
the `ahu` crate (no `BundleBuilder`, no `Manifest::to_cbor`): every byte —
header, CBOR manifest, index, data, X.509 seal certificate, and the CMS
`SignedData` seal — is hand-assembled from the layout documented in
`ahu-format-spec.md` and RFC 5652. Its only dependencies are SHA-256, P-256
signing, and hex.

Regenerate from the repository root:

```sh
cargo run --manifest-path testdata/wire-profile-0.1/gen/Cargo.toml
```

All inputs are fixed constants in `gen/src/main.rs` (seal key seed, cert
validity window, UUIDs, hash preimages, payloads), and ECDSA signing is
deterministic (RFC 6979), so regeneration reproduces the committed bytes
exactly. If any constant changes, regenerate and update this README, the
checksums in `crates/ahu/tests/wire_profile.rs`, and the tests' expected
decoded values together.
