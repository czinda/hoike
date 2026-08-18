use ahu::{
    Bundle, BundleBuilder, BundleType, CaScope, Completeness, Continuity, Integrity, Manifest,
    ResponderId, ResponderIdType, Window,
};
use hoike_core::state::StateStore;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn make_bundle(producer: &str, epoch: u64, prev_digest: Option<[u8; 32]>) -> (Bundle, Vec<u8>) {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: producer.into(),
        created_at: 1700000000 + epoch * 3600,
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
            produced_at: 1700000000 + epoch * 3600,
            this_update_min: 1700000000 + epoch * 3600,
            next_update_min: 1700086400 + epoch * 3600,
            next_update_max: 1700093600 + epoch * 3600,
        },
        integrity: Integrity {
            index_digest: [0; 32],
            data_digest: [0; 32],
        },
        entry_count: 0,
        continuity: Continuity {
            prev_manifest_digest: prev_digest,
            base_manifest_digest: None,
            chain_length: 0,
        },
        shard: None,
        compression: None,
        extensions: None,
    };

    let mut builder = BundleBuilder::new(manifest);
    builder.add_entry([epoch as u8; 32], format!("response-{epoch}").into_bytes());

    let bytes = builder
        .build(|m| Ok(Sha256::digest(m).to_vec()))
        .unwrap();
    let bundle = Bundle::from_bytes(&bytes).unwrap();
    (bundle, bytes)
}

#[test]
fn state_store_persists_across_instances() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    {
        let mut store = StateStore::open(&path).unwrap();
        store
            .advance("producer-a", "aabbcc", 5, [0x11; 32])
            .unwrap();
        assert_eq!(store.get_high_water("producer-a", "aabbcc"), Some(5));
    }

    {
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.get_high_water("producer-a", "aabbcc"), Some(5));
        assert_eq!(
            store.get_manifest_digest("producer-a", "aabbcc"),
            Some([0x11; 32])
        );
        assert_eq!(store.get_high_water("producer-a", "other"), None);
    }
}

#[test]
fn rollback_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut store = StateStore::open(&path).unwrap();
    let (bundle_5, _) = make_bundle("test-producer", 5, None);
    store.check_rollback(&bundle_5).unwrap();
    store.advance_from_bundle(&bundle_5).unwrap();

    let (bundle_3, _) = make_bundle("test-producer", 3, None);
    let err = store.check_rollback(&bundle_3).unwrap_err();
    assert!(
        format!("{err}").contains("rollback"),
        "expected rollback error, got: {err}"
    );

    let (bundle_5_again, _) = make_bundle("test-producer", 5, None);
    let err = store.check_rollback(&bundle_5_again).unwrap_err();
    assert!(
        format!("{err}").contains("rollback"),
        "equal epoch should also be rejected, got: {err}"
    );

    let (bundle_6, _) = make_bundle("test-producer", 6, None);
    store.check_rollback(&bundle_6).unwrap();
}

#[test]
fn fork_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut store = StateStore::open(&path).unwrap();
    let (bundle_1, _) = make_bundle("test-producer", 1, None);
    store.advance_from_bundle(&bundle_1).unwrap();

    let recorded = store
        .get_manifest_digest("test-producer", &hex::encode([0xBB; 32]))
        .unwrap();

    let (bundle_2_good, _) = make_bundle("test-producer", 2, Some(recorded));
    store.check_continuity(&bundle_2_good).unwrap();

    let (bundle_2_bad, _) = make_bundle("test-producer", 2, Some([0xFF; 32]));
    let err = store.check_continuity(&bundle_2_bad).unwrap_err();
    assert!(
        format!("{err}").contains("fork"),
        "expected fork error, got: {err}"
    );
}

#[test]
fn first_run_accepts_any_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let store = StateStore::open(&path).unwrap();
    assert_eq!(store.get_high_water("any", "any"), None);

    let (bundle_100, _) = make_bundle("test-producer", 100, None);
    store.check_rollback(&bundle_100).unwrap();
}

#[test]
fn advance_is_atomic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    let mut store = StateStore::open(&path).unwrap();
    store.advance("p", "k", 10, [0xAA; 32]).unwrap();

    assert!(path.exists());
    let tmp_path = path.with_extension("tmp");
    assert!(!tmp_path.exists(), ".tmp file should be cleaned up after rename");

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("\"p:k\""));
}
