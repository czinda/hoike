use ahu::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn build_test_bundle(entry_count: usize) -> Vec<u8> {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "integration-test".into(),
        created_at: 1700000000,
        bundle_type: BundleType::Full,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            issuer_name_hash: vec![0xAA; 32],
            issuer_key_hash: vec![0xBB; 32],
            epoch: 1,
            responder_id: ResponderId {
                id_type: ResponderIdType::ByKey,
                value: vec![0xCC; 20],
            },
            responder_chain: None,
            signature_algorithm: vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02],
            completeness: Completeness::AuthoritativeComplete,
        }],
        window: Window {
            produced_at: 1700000000,
            this_update_min: 1700000000,
            next_update_min: 1700086400,
            next_update_max: 1700093600,
        },
        integrity: Integrity {
            index_digest: [0; 32],
            data_digest: [0; 32],
        },
        entry_count: 0,
        continuity: Continuity {
            prev_manifest_digest: None,
            base_manifest_digest: None,
            chain_length: 0,
        },
        shard: None,
        compression: None,
        extensions: None,
    };

    let mut builder = BundleBuilder::new(manifest);

    for i in 0..entry_count {
        let certid = format!("test-certid-{i:08}");
        let entry_key = compute_entry_key(certid.as_bytes());
        let response = format!("mock-ocsp-response-for-serial-{i:08}").into_bytes();
        builder.add_entry(entry_key, response);
    }

    builder
        .build(|m| Ok(Sha256::digest(m).to_vec()))
        .expect("bundle build failed")
}

#[test]
fn full_bundle_round_trip_100_entries() {
    let bytes = build_test_bundle(100);
    let bundle = Bundle::from_bytes(&bytes).unwrap();

    assert_eq!(bundle.manifest.entry_count, 100);
    assert_eq!(bundle.index.len(), 100);
    assert_eq!(bundle.manifest.producer_id, "integration-test");
    assert_eq!(bundle.manifest.bundle_type, BundleType::Full);
    assert_eq!(
        bundle.manifest.ca_scopes[0].completeness,
        Completeness::AuthoritativeComplete
    );

    let result = verify_structure(&bundle).unwrap();
    assert!(result.index_digest_ok);
    assert!(result.data_digest_ok);
    assert!(result.sort_order_ok);
    assert!(result.entry_bounds_ok);
    assert!(result.entry_count_matches);
}

#[test]
fn lookup_every_entry() {
    let bytes = build_test_bundle(50);
    let bundle = Bundle::from_bytes(&bytes).unwrap();

    for i in 0..50 {
        let certid = format!("test-certid-{i:08}");
        let entry_key = compute_entry_key(certid.as_bytes());
        let expected = format!("mock-ocsp-response-for-serial-{i:08}");

        let found = bundle
            .lookup(&entry_key)
            .unwrap_or_else(|| panic!("entry {i} not found"));
        assert_eq!(found, expected.as_bytes());
    }
}

#[test]
fn missing_entry_returns_none() {
    let bytes = build_test_bundle(10);
    let bundle = Bundle::from_bytes(&bytes).unwrap();

    let missing_key = compute_entry_key(b"nonexistent-certid");
    assert!(bundle.lookup(&missing_key).is_none());
}

#[test]
fn delta_bundle_with_tombstone() {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "delta-test".into(),
        created_at: 1700003600,
        bundle_type: BundleType::Delta,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x01],
            issuer_name_hash: vec![0xAA; 32],
            issuer_key_hash: vec![0xBB; 32],
            epoch: 2,
            responder_id: ResponderId {
                id_type: ResponderIdType::ByKey,
                value: vec![0xCC; 20],
            },
            responder_chain: None,
            signature_algorithm: vec![0x02],
            completeness: Completeness::AuthoritativeComplete,
        }],
        window: Window {
            produced_at: 1700003600,
            this_update_min: 1700003600,
            next_update_min: 1700090000,
            next_update_max: 1700097200,
        },
        integrity: Integrity {
            index_digest: [0; 32],
            data_digest: [0; 32],
        },
        entry_count: 0,
        continuity: Continuity {
            prev_manifest_digest: Some([0x11; 32]),
            base_manifest_digest: Some([0x22; 32]),
            chain_length: 1,
        },
        shard: None,
        compression: None,
        extensions: None,
    };

    let mut builder = BundleBuilder::new(manifest);

    let added_key = compute_entry_key(b"new-cert");
    builder.add_entry(added_key, b"new-response".to_vec());

    let removed_key = compute_entry_key(b"revoked-cert");
    builder.add_tombstone(removed_key, 0);

    let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();

    let bundle = Bundle::from_bytes(&bytes).unwrap();
    assert_eq!(bundle.manifest.bundle_type, BundleType::Delta);
    assert_eq!(bundle.manifest.continuity.chain_length, 1);
    assert!(bundle.manifest.continuity.base_manifest_digest.is_some());

    assert!(bundle.lookup(&added_key).is_some());
    assert!(bundle.lookup(&removed_key).is_none()); // tombstone

    let result = verify_structure(&bundle).unwrap();
    assert!(result.index_digest_ok);
    assert!(result.data_digest_ok);
}

#[test]
fn manifest_cbor_stability() {
    let bytes = build_test_bundle(5);
    let bundle = Bundle::from_bytes(&bytes).unwrap();

    let re_encoded = bundle.manifest.to_cbor();
    let re_decoded = Manifest::from_cbor(&re_encoded).unwrap();

    assert_eq!(bundle.manifest.format_version, re_decoded.format_version);
    assert_eq!(bundle.manifest.bundle_id, re_decoded.bundle_id);
    assert_eq!(bundle.manifest.entry_count, re_decoded.entry_count);
    assert_eq!(bundle.manifest.window, re_decoded.window);
    assert_eq!(bundle.manifest.integrity, re_decoded.integrity);
}

#[test]
fn write_and_read_from_file() {
    let bytes = build_test_bundle(10);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.ahu");
    std::fs::write(&path, &bytes).unwrap();

    let bundle = Bundle::from_file(&path).unwrap();
    assert_eq!(bundle.manifest.entry_count, 10);
    let result = verify_structure(&bundle).unwrap();
    assert!(result.sort_order_ok);
}

#[test]
fn dual_certid_alias_survives_sort() {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "alias-test".into(),
        created_at: 1700000000,
        bundle_type: BundleType::Full,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x01],
            issuer_name_hash: vec![0xAA; 32],
            issuer_key_hash: vec![0xBB; 32],
            epoch: 1,
            responder_id: ResponderId {
                id_type: ResponderIdType::ByKey,
                value: vec![0xCC; 20],
            },
            responder_chain: None,
            signature_algorithm: vec![0x02],
            completeness: Completeness::AuthoritativeComplete,
        }],
        window: Window {
            produced_at: 1700000000,
            this_update_min: 1700000000,
            next_update_min: 1700086400,
            next_update_max: 1700093600,
        },
        integrity: Integrity {
            index_digest: [0; 32],
            data_digest: [0; 32],
        },
        entry_count: 0,
        continuity: Continuity {
            prev_manifest_digest: None,
            base_manifest_digest: None,
            chain_length: 0,
        },
        shard: None,
        compression: None,
        extensions: None,
    };

    let mut builder = BundleBuilder::new(manifest);

    // Keys chosen so that after sorting, the alias pair is separated
    // by the non-alias entry.
    let key_sha1 = [0x11; 32];
    let key_sha256 = [0xFF; 32];
    let key_between = [0x88; 32];
    let shared_response = b"dual-certid-response".to_vec();

    builder.add_dual_entry(key_sha1, key_sha256, shared_response.clone());
    builder.add_entry(key_between, b"other-response".to_vec());

    let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();

    let bundle = Bundle::from_bytes(&bytes).unwrap();
    let result = verify_structure(&bundle).unwrap();
    assert!(result.sort_order_ok);
    // 3 entries: 2 alias + 1 normal
    assert_eq!(bundle.index.len(), 3);

    // Both alias keys must find the same response.
    let r1 = bundle.lookup(&key_sha1).expect("sha1 alias not found");
    let r2 = bundle.lookup(&key_sha256).expect("sha256 alias not found");
    assert_eq!(r1, r2);
    assert_eq!(r1, &shared_response[..]);

    // The non-alias entry should also work.
    let r3 = bundle.lookup(&key_between).expect("normal entry not found");
    assert_eq!(r3, b"other-response");
}

#[test]
fn overflowing_entry_offsets_never_panic_in_heap_or_mmap() {
    let original = build_test_bundle(1);
    for (offset, length) in [(u64::MAX, 2), (u64::MAX - 2, u32::MAX), (100_000, 0)] {
        let mut bundle = ahu::Bundle::from_bytes(&original).unwrap();
        bundle.index[0].data_offset = offset;
        bundle.index[0].data_length = length;
        let key = bundle.index[0].entry_key;
        assert!(bundle.entry_at(0).is_none());
        assert!(bundle.entry_bytes(&bundle.index[0]).is_none());
        let mut index = Vec::new();
        bundle.index[0].write_to(&mut index).unwrap();
        use sha2::{Digest, Sha256};
        bundle.manifest.integrity.index_digest = Sha256::digest(&index).into();
        bundle.manifest_bytes = bundle.manifest.to_cbor();
        assert!(ahu::verify_structure(&bundle).is_err());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.ahu");
        std::fs::write(&path, bundle.to_bytes().unwrap()).unwrap();
        let mapped = ahu::MmapBundle::open(&path).unwrap();
        assert!(mapped.lookup(&key).is_none());
    }
}
