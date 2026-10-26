//! Golden wire-profile vectors for the frozen ahu 0.1 profile (F12).
//!
//! The fixtures under `testdata/wire-profile-0.1/` were hand-assembled
//! independently of `BundleBuilder` — see the fixture README for the layout,
//! decoded field values, checksums, and generation instructions. These tests
//! pin the profile the way the reference reader actually enforces it:
//!
//! * file header `FORMAT_MAJOR = 0`, `FORMAT_MINOR = 1` — distinct from the
//!   CBOR manifest `format_version = 1` and the package version 0.2;
//! * index records sorted lexicographically by `(entry_key, discriminator)`
//!   with duplicate-pair rejection, discriminator at bytes 46–47;
//! * detached CMS `SignedData` over `id-data` with the `content-type` and
//!   `message-digest` signed attributes required.
//!
//! Verification of these immutable vectors uses a fixed test time inside the
//! recorded seal-certificate window; production clocks stay real.

/// Fixed verification time (2027-01-15T08:00:00Z) inside the recorded
/// seal-certificate validity window 2023-11-14 .. 2039-09-18. Immutable
/// vectors only.
const FIXED_TEST_TIME: u64 = 1_800_000_000;

/// README-recorded SHA-256 checksums (`testdata/wire-profile-0.1/README.md`).
const MINIMAL_FULL_SHA256: &str =
    "3233a3e72fe2b2fe340c4d0b6a6c795e77bb6fb09f2e67ff3b7a339c3f57b93c";
const DUAL_ALGORITHM_SHA256: &str =
    "9803d3feffa6bdbaef12cdd1d0f5e41402bad7866f669e519242158e2a58ea23";
const SEAL_CERT_SHA256: &str = "64ed217c144a554dd25c7ba0ee86c8968aee3426ba72c90c7b76df5b73d4ea32";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../testdata/wire-profile-0.1/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

/// SHA-256 over the documented preimage standing in for SHA-256(DER of
/// CertID); the container treats the key as opaque.
fn minimal_entry_key() -> [u8; 32] {
    sha256_of(b"wire-profile-0.1/minimal/certid")
}

fn dual_entry_key() -> [u8; 32] {
    sha256_of(b"wire-profile-0.1/dual/certid")
}

#[test]
fn dual_algorithm_pairs_follow_documented_order() {
    use ahu::{ALG_DISC_DEFAULT, ALG_DISC_ML_DSA_87};

    let bytes = fixture("dual-algorithm.ahu");
    assert_eq!(hex_sha256(&bytes), DUAL_ALGORITHM_SHA256);

    let bundle = ahu::Bundle::from_bytes(&bytes).unwrap();
    assert_eq!(
        (bundle.header.format_major, bundle.header.format_minor),
        (0, 1)
    );
    assert_eq!(bundle.manifest.format_version, 1);
    assert_eq!(bundle.index.len(), 2);
    assert_eq!(bundle.manifest.entry_count, 2);

    // Same entry key, one record per algorithm variant, in the documented
    // ascending (entry_key, discriminator) order: 0 (default) then 4
    // (ML-DSA-87).
    let key = dual_entry_key();
    assert_eq!(bundle.index[0].entry_key, key);
    assert_eq!(bundle.index[1].entry_key, key);
    assert_eq!(bundle.index[0].discriminator, ALG_DISC_DEFAULT);
    assert_eq!(bundle.index[1].discriminator, ALG_DISC_ML_DSA_87);
    ahu::index::validate_sort_order(&bundle.index).unwrap();

    // Each discriminator serves its own payload.
    assert_eq!(
        bundle.lookup(&key).unwrap(),
        b"wire-profile-0.1/dual/response/ecdsa".as_slice()
    );
    assert_eq!(
        bundle
            .lookup_preferred(&key, &[ALG_DISC_ML_DSA_87])
            .unwrap(),
        b"wire-profile-0.1/dual/response/mldsa87".as_slice()
    );

    // Independent byte inspection of the index section: the header carries
    // index_offset at bytes 32..40 (big-endian); within each 48-byte record
    // the entry key is at +0..32, data_offset +32..40, data_length +40..44,
    // flags +44..46, discriminator +46..48.
    let index_offset = u64::from_be_bytes(bytes[32..40].try_into().unwrap()) as usize;
    assert_eq!(index_offset, bundle.header.index_offset as usize);
    let data_offset = u64::from_be_bytes(bytes[48..56].try_into().unwrap()) as usize;
    let payloads = [
        (0u16, "wire-profile-0.1/dual/response/ecdsa".as_bytes()),
        (4u16, "wire-profile-0.1/dual/response/mldsa87".as_bytes()),
    ];
    for (i, (disc, payload)) in payloads.iter().enumerate() {
        let record = &bytes[index_offset + i * 48..index_offset + (i + 1) * 48];
        assert_eq!(&record[0..32], &key[..], "record {i} entry key");
        assert_eq!(
            u16::from_be_bytes(record[44..46].try_into().unwrap()),
            0,
            "record {i} flags"
        );
        assert_eq!(
            u16::from_be_bytes(record[46..48].try_into().unwrap()),
            *disc,
            "record {i} discriminator at index offset +46"
        );
        let entry_offset = u64::from_be_bytes(record[32..40].try_into().unwrap()) as usize;
        let entry_length = u32::from_be_bytes(record[40..44].try_into().unwrap()) as usize;
        assert_eq!(
            &bytes[data_offset + entry_offset..data_offset + entry_offset + entry_length],
            *payload,
            "record {i} payload"
        );
    }
}

#[cfg(feature = "seal-verify")]
mod seal_verified {
    use super::*;

    #[test]
    fn independent_0_1_vectors_decode() {
        use ahu::{BundleType, Completeness, ResponderIdType};
        use uuid::Uuid;

        let seal_cert = fixture("seal-cert.der");
        assert_eq!(hex_sha256(&seal_cert), SEAL_CERT_SHA256);

        // ── minimal-full.ahu ────────────────────────────────────────────
        let bytes = fixture("minimal-full.ahu");
        assert_eq!(hex_sha256(&bytes), MINIMAL_FULL_SHA256);

        let bundle = ahu::Bundle::from_bytes(&bytes).unwrap();
        assert_eq!(
            (bundle.header.format_major, bundle.header.format_minor),
            (0, 1)
        );
        assert_eq!(bundle.manifest.format_version, 1);

        // Decoded fields per the fixture README.
        assert_eq!(
            bundle.manifest.bundle_id,
            Uuid::parse_str("01939f6e-b000-7000-8000-000000000001").unwrap()
        );
        assert_eq!(bundle.manifest.producer_id, "wire-profile-0.1");
        assert_eq!(bundle.manifest.created_at, 1_800_000_000);
        assert_eq!(bundle.manifest.bundle_type, BundleType::Full);
        assert_eq!(bundle.manifest.entry_count, 1);
        assert_eq!(bundle.manifest.window.produced_at, 1_800_000_000);
        assert_eq!(bundle.manifest.window.this_update_min, 1_800_000_000);
        assert_eq!(bundle.manifest.window.next_update_min, 1_800_086_400);
        assert_eq!(bundle.manifest.window.next_update_max, 1_800_093_600);
        assert!(bundle.manifest.continuity.prev_manifest_digest.is_none());
        assert!(bundle.manifest.continuity.base_manifest_digest.is_none());
        assert_eq!(bundle.manifest.continuity.chain_length, 0);
        assert!(bundle.manifest.shard.is_none());
        assert!(bundle.manifest.compression.is_none());
        assert!(bundle.manifest.extensions.is_none());

        let scope = &bundle.manifest.ca_scopes[0];
        assert_eq!(
            scope.hash_algorithm,
            vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01] // SHA-256 OID
        );
        assert_eq!(
            scope.issuer_name_hash,
            sha256_of(b"wire-profile-0.1/issuer-name").to_vec()
        );
        assert_eq!(
            scope.issuer_key_hash,
            sha256_of(b"wire-profile-0.1/issuer-key").to_vec()
        );
        assert_eq!(scope.epoch, 1);
        assert_eq!(scope.responder_id.id_type, ResponderIdType::ByKey);
        assert_eq!(
            scope.responder_id.value,
            sha256_of(b"wire-profile-0.1/responder-key")[..20].to_vec()
        );
        assert_eq!(
            scope.signature_algorithm,
            vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02] // ECDSA-with-SHA256 OID
        );
        assert_eq!(scope.completeness, Completeness::AuthoritativeComplete);

        let result = ahu::verify_structure(&bundle).unwrap();
        assert!(result.index_digest_ok);
        assert!(result.data_digest_ok);
        assert!(result.sort_order_ok);
        assert!(result.entry_bounds_ok);
        assert!(result.entry_count_matches);
        assert!(result.seal_present);

        let key = minimal_entry_key();
        assert_eq!(
            bundle.lookup(&key).unwrap(),
            b"wire-profile-0.1/minimal/response".as_slice()
        );

        // The hand encoding is the canonical deterministic CBOR encoding.
        assert_eq!(bundle.manifest_bytes, bundle.manifest.to_cbor());

        // The seal authenticates the manifest under the recorded certificate
        // at the fixed test time inside its window.
        ahu::verify_seal(&bundle.manifest_bytes, &bundle.seal_bytes).unwrap();
        ahu::verify_seal_with_pins(
            &bundle.manifest_bytes,
            &bundle.seal_bytes,
            std::slice::from_ref(&seal_cert),
            FIXED_TEST_TIME,
        )
        .unwrap();

        // ── dual-algorithm.ahu ──────────────────────────────────────────
        let bytes = fixture("dual-algorithm.ahu");
        assert_eq!(hex_sha256(&bytes), DUAL_ALGORITHM_SHA256);

        let bundle = ahu::Bundle::from_bytes(&bytes).unwrap();
        assert_eq!(
            (bundle.header.format_major, bundle.header.format_minor),
            (0, 1)
        );
        assert_eq!(bundle.manifest.format_version, 1);
        assert_eq!(
            bundle.manifest.bundle_id,
            Uuid::parse_str("01939f6e-b000-7000-8000-000000000002").unwrap()
        );
        assert_eq!(bundle.manifest.entry_count, 2);
        assert_eq!(bundle.index.len(), 2);
        ahu::verify_structure(&bundle).unwrap();
        ahu::verify_seal_with_pins(
            &bundle.manifest_bytes,
            &bundle.seal_bytes,
            &[seal_cert],
            FIXED_TEST_TIME,
        )
        .unwrap();
    }

    #[test]
    fn cms_profile_attributes_are_required() {
        use ahu::IndexRecord;
        use der::{Decode, Encode};

        fn rec(key_byte: u8, discriminator: u16) -> IndexRecord {
            let mut entry_key = [0u8; 32];
            entry_key[0] = key_byte;
            IndexRecord {
                entry_key,
                data_offset: 0,
                data_length: 1,
                flags: ahu::IndexFlags::empty(),
                discriminator,
            }
        }

        // A duplicate (entry_key, discriminator) pair is rejected.
        let duplicate_pair = [rec(0x01, 0), rec(0x01, 0)];
        assert!(ahu::index::validate_sort_order(&duplicate_pair).is_err());

        // Equal keys with descending discriminators are not in sorted order.
        let reversed_pair = [rec(0x01, 4), rec(0x01, 0)];
        assert!(ahu::index::validate_sort_order(&reversed_pair).is_err());

        // Distinct discriminators for one key decode in the documented
        // order, including a value this profile does not assign: preserved
        // and included in ordering, without implying algorithm support.
        let distinct = [rec(0x01, 0), rec(0x01, 4), rec(0x02, 0x7bc4)];
        assert!(ahu::index::validate_sort_order(&distinct).is_ok());
        assert_eq!(distinct[2].discriminator, 0x7bc4);

        // Independently inspect the fixture's CMS content type, then prove
        // the reader requires id-data: rebuild the same seal with a
        // different eContentType and the verifier must reject it.
        let bytes = fixture("minimal-full.ahu");
        let bundle = ahu::Bundle::from_bytes(&bytes).unwrap();

        let content_info = cms::content_info::ContentInfo::from_der(&bundle.seal_bytes).unwrap();
        assert_eq!(
            content_info.content_type.to_string(),
            "1.2.840.113549.1.7.2"
        );
        let mut signed_data = content_info
            .content
            .decode_as::<cms::signed_data::SignedData>()
            .unwrap();
        assert_eq!(
            signed_data.encap_content_info.econtent_type.to_string(),
            "1.2.840.113549.1.7.1" // id-data
        );
        assert!(signed_data.encap_content_info.econtent.is_none()); // detached
        assert_eq!(signed_data.signer_infos.0.len(), 1);
        assert_eq!(signed_data.digest_algorithms.len(), 1);

        // Everything else unchanged, a non-id-data eContentType must fail
        // verification.
        signed_data.encap_content_info.econtent_type =
            der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
        let signed_data_der = der::Encode::to_der(&signed_data).unwrap();
        let mismatched_content_type_seal = cms::content_info::ContentInfo {
            content_type: der::asn1::ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2"),
            content: der::Any::from_der(&signed_data_der).unwrap(),
        }
        .to_der()
        .unwrap();
        // Only the eContentType differs; the signed attributes (including
        // the content-type attribute value id-data) are untouched.
        assert_ne!(&mismatched_content_type_seal[..], &bundle.seal_bytes[..]);
        assert!(ahu::verify_seal(&bundle.manifest_bytes, &mismatched_content_type_seal).is_err());
    }
}
