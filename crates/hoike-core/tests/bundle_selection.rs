use ahu::{
    BundleBuilder, BundleType, CaScope, Completeness, Continuity, Integrity, Manifest, ResponderId,
    ResponderIdType, Window,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn build_bundle_at_epoch(epoch: u64, entries: &[([u8; 32], &[u8])]) -> Vec<u8> {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "test".into(),
        created_at: 4102444800,
        bundle_type: BundleType::Full,
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
            produced_at: 4102444800,
            this_update_min: 4102444800,
            next_update_min: 4102531200,
            next_update_max: 4102538400,
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
    for (key, data) in entries {
        builder.add_entry(*key, data.to_vec());
    }
    builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap()
}

#[test]
fn find_newest_bundle_selects_by_epoch_not_mtime() {
    let dir = tempfile::tempdir().unwrap();

    let old_bundle = build_bundle_at_epoch(5, &[([0x11; 32], b"old-response")]);
    let new_bundle = build_bundle_at_epoch(10, &[([0x22; 32], b"new-response")]);

    // Write old bundle SECOND so its mtime is newer
    let new_path = dir.path().join("new.ahu");
    std::fs::write(&new_path, &new_bundle).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(50));
    let old_path = dir.path().join("old.ahu");
    std::fs::write(&old_path, &old_bundle).unwrap();

    // old.ahu has newer mtime but lower epoch.
    // With epoch-based selection, new.ahu (epoch=10) should be selected.
    let config_toml = format!(
        r#"
[server]
mode = "edge"
listen = "127.0.0.1:0"

[storage]
bundle_dir = "{dir}"
state_db = "{dir}/state"
"#,
        dir = dir.path().display(),
    );

    let config_path = dir.path().join("hoike.toml");
    std::fs::write(&config_path, &config_toml).unwrap();

    let config = hoike_core::Config::from_file(&config_path).unwrap();
    let state = hoike_core::ResponderState::load(config).unwrap();

    // The loaded bundle should be the one with epoch 10 (has key 0x22)
    let mut found_22 = false;
    let key_22 = [0x22u8; 32];
    let key_11 = [0x11u8; 32];

    // Build a ParsedCertId for key_22
    let cert_id_22 = hoike_core::ParsedCertId {
        entry_key: key_22,
        certid_der: vec![],
        issuer_name_hash: vec![0xAA; 32],
        issuer_key_hash: vec![0xBB; 32],
        serial_number: vec![0x22],
    };

    if state.lookup(&cert_id_22, &[]).is_some() {
        found_22 = true;
    }

    let cert_id_11 = hoike_core::ParsedCertId {
        entry_key: key_11,
        certid_der: vec![],
        issuer_name_hash: vec![0xAA; 32],
        issuer_key_hash: vec![0xBB; 32],
        serial_number: vec![0x11],
    };

    // epoch=10 bundle should be loaded, which has key 0x22 but not 0x11
    assert!(
        found_22,
        "expected epoch-10 bundle (key 0x22) to be selected"
    );
    assert!(
        state.lookup(&cert_id_11, &[]).is_none(),
        "epoch-5 bundle (key 0x11) should NOT be loaded"
    );
}
