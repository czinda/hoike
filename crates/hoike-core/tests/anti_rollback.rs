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

    let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();
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

    // Reloading the *identical* bundle at the current high-water epoch is a
    // legitimate restart, not a rollback. (Previously rejected by a `<=` check,
    // which crashed the signer on any same-epoch reload.)
    let (bundle_5_reload, _) = make_bundle("test-producer", 5, None);
    store
        .check_rollback(&bundle_5_reload)
        .expect("reloading the identical bundle at the high-water epoch must be allowed");

    // A *different* bundle at the same epoch (different manifest digest) is a
    // fork/rollback attack and must still be rejected.
    let (bundle_5_fork, _) = make_bundle("test-producer", 5, Some([0x99; 32]));
    let err = store.check_rollback(&bundle_5_fork).unwrap_err();
    assert!(
        format!("{err}").contains("rollback"),
        "a different bundle at the same epoch must be rejected, got: {err}"
    );

    let (bundle_6, _) = make_bundle("test-producer", 6, None);
    store.check_rollback(&bundle_6).unwrap();
}

#[test]
fn same_epoch_identical_bundle_reload_allowed() {
    // Regression test for the anti-rollback same-epoch restart bug: a signer
    // (or edge) that restarts and reloads its own most-recent bundle must not be
    // rejected as a rollback, but a forged different bundle at that epoch must be.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");

    // First boot: accept and record epoch 7.
    {
        let mut store = StateStore::open(&path).unwrap();
        let (bundle_7, _) = make_bundle("test-producer", 7, None);
        store.check_rollback(&bundle_7).unwrap();
        store.advance_from_bundle(&bundle_7).unwrap();
    }

    // Restart: a fresh StateStore loads persisted high-water + digest, then
    // reloads the identical epoch-7 bundle from disk. Must be allowed.
    {
        let store = StateStore::open(&path).unwrap();
        let (bundle_7_reload, _) = make_bundle("test-producer", 7, None);
        store
            .check_rollback(&bundle_7_reload)
            .expect("restart reloading the identical bundle must be allowed");

        // But a different bundle at the same epoch must still be rejected.
        let (bundle_7_fork, _) = make_bundle("test-producer", 7, Some([0xEE; 32]));
        let err = store.check_rollback(&bundle_7_fork).unwrap_err();
        assert!(
            format!("{err}").contains("rollback"),
            "a forged bundle at the same epoch must be rejected, got: {err}"
        );
    }
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
    assert!(
        !tmp_path.exists(),
        ".tmp file should be cleaned up after rename"
    );

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.contains("\"p:k\""));
}

#[test]
fn identical_chained_bundle_passes_continuity_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let (a, _) = make_bundle("test", 1, None);
    let (b, _) = make_bundle("test", 2, Some(ahu::manifest_digest(&a.manifest_bytes)));
    let mut store = StateStore::open(&path).unwrap();
    store.advance_from_bundle(&a).unwrap();
    store.check_continuity(&b).unwrap();
    store.advance_from_bundle(&b).unwrap();
    let store = StateStore::open(&path).unwrap();
    store.check_rollback(&b).unwrap();
    store.check_continuity(&b).unwrap();
}

#[test]
fn failed_persist_does_not_change_in_memory_marks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let mut store = StateStore::open(&path).unwrap();
    store.advance("p", "k", 1, [1; 32]).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(store.advance("p", "k", 2, [2; 32]).is_err());
    assert_eq!(store.get_high_water("p", "k"), Some(1));
    assert_eq!(store.get_manifest_digest("p", "k"), Some([1; 32]));
}

#[test]
fn failed_multi_bundle_reload_keeps_marks_and_recovers_committed_snapshots() {
    use hoike_core::{Config, ResponderState};
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
[server]
mode = "edge"
[storage]
bundle_dir = "{dir}"
state_db = "{dir}/state"
[[ca]]
label = "a"
bundle_file = "{dir}/a.ahu"
[[ca]]
label = "b"
bundle_file = "{dir}/b.ahu"
"#,
            dir = dir.path().display()
        ),
    )
    .unwrap();
    let config = Config::from_file(&config_path).unwrap();
    let (_, a) = make_bundle("a", 1, None);
    let (_, b) = make_bundle("b", 1, None);
    std::fs::write(dir.path().join("a.ahu"), a).unwrap();
    std::fs::write(dir.path().join("b.ahu"), b).unwrap();
    let responder = ResponderState::load(config.clone()).unwrap();
    let state_path = dir.path().join("state/state.json");
    let before = std::fs::read(&state_path).unwrap();
    let (_, newer_a) = make_bundle("a", 2, None);
    std::fs::write(dir.path().join("a.ahu"), newer_a).unwrap();
    std::fs::write(dir.path().join("b.ahu"), b"interrupted write").unwrap();
    assert!(responder.reload().is_err());
    assert_eq!(std::fs::read(&state_path).unwrap(), before);
    assert!(responder.bundle_scopes().iter().all(|s| s.epoch == 1));
    drop(responder);
    let recovered = ResponderState::load(config).unwrap();
    assert_eq!(recovered.bundle_count(), 2);
    assert!(recovered.bundle_scopes().iter().all(|s| s.epoch == 1));
    let marks = StateStore::open(&state_path).unwrap();
    assert_eq!(marks.get_high_water("a", &hex::encode([0xbb; 32])), Some(1));
    assert_eq!(marks.get_high_water("b", &hex::encode([0xbb; 32])), Some(1));
}
