use ahu::*;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

fn make_manifest(bundle_type: BundleType, epoch: u64, chain_length: u64) -> Manifest {
    Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "apply-test".into(),
        created_at: 1700000000,
        bundle_type,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x01],
            issuer_name_hash: vec![0xAA; 32],
            issuer_key_hash: vec![0xBB; 32],
            epoch,
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
            chain_length,
        },
        shard: None,
        compression: None,
        extensions: None,
    }
}

fn build_full_bundle(entries: &[([u8; 32], &[u8])], epoch: u64) -> (Vec<u8>, [u8; 32]) {
    let manifest = make_manifest(BundleType::Full, epoch, 0);
    let mut builder = BundleBuilder::new(manifest);
    for (key, data) in entries {
        builder.add_entry(*key, data.to_vec());
    }
    let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();
    let bundle = Bundle::from_bytes(&bytes).unwrap();
    let digest = manifest_digest(&bundle.manifest_bytes);
    (bytes, digest)
}

fn build_delta_bundle(
    entries: &[([u8; 32], Option<&[u8]>)], // None = tombstone
    epoch: u64,
    base_digest: [u8; 32],
    prev_digest: [u8; 32],
    chain_length: u64,
) -> (Vec<u8>, [u8; 32]) {
    let mut manifest = make_manifest(BundleType::Delta, epoch, chain_length);
    manifest.continuity.base_manifest_digest = Some(base_digest);
    manifest.continuity.prev_manifest_digest = Some(prev_digest);

    let mut builder = BundleBuilder::new(manifest);
    for (key, data) in entries {
        match data {
            Some(d) => builder.add_entry(*key, d.to_vec()),
            None => builder.add_tombstone(*key),
        }
    }
    let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();
    let bundle = Bundle::from_bytes(&bytes).unwrap();
    let digest = manifest_digest(&bundle.manifest_bytes);
    (bytes, digest)
}

#[test]
fn apply_base_plus_delta() {
    let key_a = [0x0A; 32];
    let key_b = [0x0B; 32];
    let key_c = [0x0C; 32];
    let key_d = [0x0D; 32];

    let (base_bytes, base_digest) = build_full_bundle(
        &[
            (key_a, b"response-A"),
            (key_b, b"response-B"),
            (key_c, b"response-C"),
        ],
        1,
    );

    // Delta: add D, remove B, replace C
    let (delta_bytes, _delta_digest) = build_delta_bundle(
        &[
            (key_d, Some(b"response-D")),
            (key_b, None),                    // tombstone
            (key_c, Some(b"response-C-new")), // replace
        ],
        2,
        base_digest,
        base_digest,
        1,
    );

    // Now simulate what `ahu apply` does:
    let base = Bundle::from_bytes(&base_bytes).unwrap();
    let delta = Bundle::from_bytes(&delta_bytes).unwrap();

    // Build working set from base
    let mut working_set: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for record in &base.index {
        if let Some(data) = base.entry_bytes(record) {
            working_set.insert(record.entry_key, data.to_vec());
        }
    }
    assert_eq!(working_set.len(), 3);

    // Apply delta
    for record in &delta.index {
        if record.flags.contains(IndexFlags::TOMBSTONE) {
            working_set.remove(&record.entry_key);
        } else if let Some(data) = delta.entry_bytes(record) {
            working_set.insert(record.entry_key, data.to_vec());
        }
    }

    // Verify result
    assert_eq!(working_set.len(), 3); // A, C(new), D
    assert_eq!(working_set.get(&key_a).unwrap().as_slice(), b"response-A");
    assert!(!working_set.contains_key(&key_b));
    assert_eq!(
        working_set.get(&key_c).unwrap().as_slice(),
        b"response-C-new"
    );
    assert_eq!(working_set.get(&key_d).unwrap().as_slice(), b"response-D");

    // Build materialized bundle from working set
    let manifest = make_manifest(BundleType::Full, 3, 0);
    let mut builder = BundleBuilder::new(manifest);
    for (key, data) in &working_set {
        builder.add_entry(*key, data.clone());
    }
    let materialized = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();

    let result = Bundle::from_bytes(&materialized).unwrap();
    verify_structure(&result).unwrap();
    assert_eq!(result.manifest.entry_count, 3);
    assert_eq!(result.manifest.bundle_type, BundleType::Full);

    assert!(result.lookup(&key_a).is_some());
    assert!(result.lookup(&key_b).is_none());
    assert_eq!(result.lookup(&key_c).unwrap(), b"response-C-new");
    assert_eq!(result.lookup(&key_d).unwrap(), b"response-D");
}

#[test]
fn apply_chain_of_deltas() {
    let key_a = [0x0A; 32];
    let key_b = [0x0B; 32];
    let key_c = [0x0C; 32];

    let (base_bytes, base_digest) = build_full_bundle(&[(key_a, b"A-v1")], 1);

    // Delta 1: add B
    let (delta1_bytes, delta1_digest) =
        build_delta_bundle(&[(key_b, Some(b"B-v1"))], 2, base_digest, base_digest, 1);

    // Delta 2: add C, update A
    let (delta2_bytes, _delta2_digest) = build_delta_bundle(
        &[(key_c, Some(b"C-v1")), (key_a, Some(b"A-v2"))],
        3,
        base_digest,
        delta1_digest,
        2,
    );

    // Apply both deltas to base
    let base = Bundle::from_bytes(&base_bytes).unwrap();
    let delta1 = Bundle::from_bytes(&delta1_bytes).unwrap();
    let delta2 = Bundle::from_bytes(&delta2_bytes).unwrap();

    let mut ws: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    for record in &base.index {
        if let Some(data) = base.entry_bytes(record) {
            ws.insert(record.entry_key, data.to_vec());
        }
    }

    for delta in [&delta1, &delta2] {
        for record in &delta.index {
            if record.flags.contains(IndexFlags::TOMBSTONE) {
                ws.remove(&record.entry_key);
            } else if let Some(data) = delta.entry_bytes(record) {
                ws.insert(record.entry_key, data.to_vec());
            }
        }
    }

    assert_eq!(ws.len(), 3);
    assert_eq!(ws[&key_a].as_slice(), b"A-v2");
    assert_eq!(ws[&key_b].as_slice(), b"B-v1");
    assert_eq!(ws[&key_c].as_slice(), b"C-v1");
}
