//! F05 / S5 — offline, recoverable authenticated installation.
//!
//! `install_bundle` turns an offline import into a real installation: the
//! input is authenticated under the configured trust policy even when demo
//! serving is allowed, the destination is resolved from the selected CA
//! label (never the uploaded filename), and the commit order is
//! snapshot → descriptor → convenience-path publication, so every failure
//! leaves an identifiable, coherent committed generation.

use ahu::{
    Bundle, BundleBuilder, BundleType, CaScope, Completeness, Continuity, Integrity, Manifest,
    ResponderId, ResponderIdType, Window,
};
use der::{Decode, Encode};
use hoike_core::config::Config;
use hoike_core::{InstallResult, ResponderState, StateDirectoryLock, StateStore, install_bundle};
use p256::ecdsa::SigningKey;
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}

/// Self-signed seal certificate with a validity window around this run,
/// canonical across the der 0.7/0.8 boundary.
fn certificate(subject: &SigningKey, now: u64) -> Vec<u8> {
    let mut cert =
        x509_cert::Certificate::from_der(&hoike_sign::generate_seal_cert(subject).unwrap())
            .unwrap();
    let time = |seconds| {
        x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_unix_duration(std::time::Duration::from_secs(seconds))
                .unwrap(),
        )
    };
    cert.tbs_certificate.validity = x509_cert::time::Validity {
        not_before: time(now - 60),
        not_after: time(now + 3600),
    };
    use p256::ecdsa::signature::Signer;
    let signature: p256::ecdsa::DerSignature =
        subject.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(signature.as_bytes()).unwrap();
    cert.to_der().unwrap()
}

/// Parameters of a synthetic but real CMS-sealed full bundle.
struct Spec<'a> {
    producer: &'a str,
    epoch: u64,
    prev: Option<[u8; 32]>,
    issuer_key_hash: [u8; 32],
    signer: &'a SigningKey,
    cert: &'a [u8],
}

fn sealed_bundle(spec: &Spec, now: u64) -> Vec<u8> {
    let manifest = base_manifest(
        spec.producer,
        spec.epoch,
        spec.prev,
        spec.issuer_key_hash,
        now,
    );
    let mut builder = BundleBuilder::new(manifest);
    builder.add_entry(
        [spec.epoch as u8; 32],
        format!("response-{}", spec.epoch).into_bytes(),
    );
    builder
        .build(|m| {
            hoike_sign::create_cms_seal(
                m,
                &hoike_sign::SealKey::EcdsaP256(spec.signer.clone()),
                spec.cert,
            )
            .map_err(|e| ahu::AhuError::SealInvalid(e.to_string()))
        })
        .unwrap()
}

const IKH_A: [u8; 32] = [0xBB; 32];
const IKH_B: [u8; 32] = [0xDD; 32];

struct Fixture {
    dir: tempfile::TempDir,
    key: SigningKey,
    cert: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let now = now();
        let key = key(7);
        let cert = certificate(&key, now);
        std::fs::write(dir.path().join("signer.der"), &cert).unwrap();
        Self { dir, key, cert }
    }

    fn trusted(
        &self,
        producer: &str,
        epoch: u64,
        prev: Option<[u8; 32]>,
        ikh: [u8; 32],
    ) -> Vec<u8> {
        sealed_bundle(
            &Spec {
                producer,
                epoch,
                prev,
                issuer_key_hash: ikh,
                signer: &self.key,
                cert: &self.cert,
            },
            now(),
        )
    }

    /// Correctly structured and freshly sealed, but by an untrusted signer.
    fn untrusted(&self, producer: &str, epoch: u64, ikh: [u8; 32]) -> Vec<u8> {
        let now = now();
        let wrong = key(8);
        let wrong_cert = certificate(&wrong, now);
        sealed_bundle(
            &Spec {
                producer,
                epoch,
                prev: None,
                issuer_key_hash: ikh,
                signer: &wrong,
                cert: &wrong_cert,
            },
            now,
        )
    }

    fn config(&self, ca_entries: &str) -> Config {
        let path = self.dir.path().join("hoike.toml");
        std::fs::write(
            &path,
            format!(
                "[server]\nmode = 'edge'\n[storage]\nbundle_dir = '{0}/bundles'\nstate_db = \
                 '{0}/state'\nseal_signer_pins = ['{0}/signer.der']\n{1}",
                self.dir.path().display(),
                ca_entries
            ),
        )
        .unwrap();
        Config::from_file(&path).unwrap()
    }

    fn default_config(&self) -> Config {
        self.config("[[ca]]\nlabel = 'a'\n[[ca]]\nlabel = 'b'\n")
    }

    fn init_state(&self, config: &Config) {
        StateStore::initialize(&state_path(config)).unwrap();
    }

    fn install(
        &self,
        config: &Config,
        label: &str,
        bytes: &[u8],
    ) -> hoike_core::error::Result<InstallResult> {
        let guard = StateDirectoryLock::acquire(&config.storage.state_db).unwrap();
        install_bundle(config, label, bytes, &guard)
    }

    /// Reload the full working set under a fresh writer, returning
    /// (label, epoch) per served scope.
    fn served_epochs(&self, config: &Config) -> Vec<(String, u64)> {
        let guard = Arc::new(StateDirectoryLock::acquire(&config.storage.state_db).unwrap());
        let responder = ResponderState::load(config.clone(), guard).unwrap();
        responder
            .bundle_scopes()
            .into_iter()
            .map(|s| (s.ca_label, s.epoch))
            .collect()
    }

    fn high_water(&self, config: &Config, producer: &str, ikh: &[u8]) -> Option<u64> {
        StateStore::open(&state_path(config))
            .unwrap()
            .get_high_water(producer, &hex::encode(ikh))
    }

    fn snapshot_files(&self, config: &Config) -> Vec<PathBuf> {
        let mut files: Vec<PathBuf> =
            std::fs::read_dir(config.storage.state_db.join("generations"))
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .collect();
        files.sort();
        files
    }
}

fn state_path(config: &Config) -> PathBuf {
    config.storage.state_db.join("state.json")
}

fn destination(config: &Config, label: &str) -> PathBuf {
    config.bundle_destination(label).unwrap()
}

fn as_json(config: &Config) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(state_path(config)).unwrap()).unwrap()
}

/// Install a first generation for `a` and return the (config, bytes, digest)
/// of the committed baseline plus snapshots of the durable files.
struct Baseline {
    config: Config,
    bytes: Vec<u8>,
    digest: [u8; 32],
    destination: PathBuf,
    state: Vec<u8>,
    snapshots: Vec<PathBuf>,
}

fn committed_baseline(f: &Fixture) -> Baseline {
    let config = f.default_config();
    f.init_state(&config);
    let bytes = f.trusted("install-test", 1, None, IKH_A);
    f.install(&config, "a", &bytes).unwrap();
    let bundle = Bundle::from_bytes(&bytes).unwrap();
    Baseline {
        digest: ahu::manifest_digest(&bundle.manifest_bytes),
        destination: destination(&config, "a"),
        state: std::fs::read(state_path(&config)).unwrap(),
        snapshots: f.snapshot_files(&config),
        bytes,
        config,
    }
}

#[test]
fn import_rejects_untrusted_input_without_changes() {
    let f = Fixture::new();
    let baseline = committed_baseline(&f);

    // Garbage never reaches the state store.
    let err = f
        .install(&baseline.config, "a", b"not an ahu bundle")
        .unwrap_err();
    assert!(err.to_string().to_lowercase().contains("bundle"), "{err}");

    // Structurally valid, freshly sealed — but by a signer nobody pinned.
    let untrusted = f.untrusted("install-test", 2, IKH_A);
    let err = f.install(&baseline.config, "a", &untrusted).unwrap_err();
    assert!(
        err.to_string().contains("seal verification failed"),
        "{err}"
    );

    // Rejections are total: no destination, state, or snapshot change.
    assert_eq!(
        std::fs::read(&baseline.destination).unwrap(),
        baseline.bytes,
        "rejected import must leave the configured destination untouched"
    );
    assert_eq!(
        std::fs::read(state_path(&baseline.config)).unwrap(),
        baseline.state,
        "rejected import must leave the committed descriptor untouched"
    );
    assert_eq!(
        f.snapshot_files(&baseline.config),
        baseline.snapshots,
        "rejected import must not stage new snapshots"
    );
    assert_eq!(
        f.high_water(&baseline.config, "install-test", &IKH_A),
        Some(1)
    );
}

#[test]
fn import_uses_selected_ca_destination() {
    let f = Fixture::new();
    let selected = f.dir.path().join("custom/active.ahu");
    let config = f.config(&format!(
        "[[ca]]\nlabel = 'a'\nbundle_file = '{}'\n[[ca]]\nlabel = 'b'\n",
        selected.display()
    ));
    f.init_state(&config);

    let bytes_a = f.trusted("install-test", 1, None, IKH_A);
    let committed = f.install(&config, "a", &bytes_a).unwrap();
    assert_eq!(committed.destination, selected);
    assert_eq!(committed.publication_warning, None);
    assert_eq!(std::fs::read(&selected).unwrap(), bytes_a);
    assert!(
        !config.storage.bundle_dir.join("a.ahu").exists(),
        "the default path must not be written when bundle_file is selected"
    );

    let bytes_b = f.trusted("install-test", 1, None, IKH_B);
    let committed = f.install(&config, "b", &bytes_b).unwrap();
    assert_eq!(
        committed.destination,
        config.storage.bundle_dir.join("b.ahu")
    );
    assert_eq!(
        std::fs::read(config.storage.bundle_dir.join("b.ahu")).unwrap(),
        bytes_b
    );
}

#[test]
fn import_recovers_committed_snapshot_when_alias_publish_fails() {
    let f = Fixture::new();
    let selected = f.dir.path().join("custom/active.ahu");
    let config = f.config(&format!(
        "[[ca]]\nlabel = 'a'\nbundle_file = '{}'\n",
        selected.display()
    ));
    f.init_state(&config);
    let first = f.trusted("install-test", 1, None, IKH_A);
    f.install(&config, "a", &first).unwrap();

    // Make the configured path unreplaceable: publication after the commit
    // fails, but the installation is already committed.
    std::fs::remove_file(&selected).unwrap();
    std::fs::create_dir(&selected).unwrap();
    std::fs::write(selected.join("occupied"), b"old").unwrap();

    let second = f.trusted("install-test", 2, None, IKH_A);
    let committed = f.install(&config, "a", &second).unwrap();
    assert_eq!(committed.destination, selected);
    let warning = committed.publication_warning.expect(
        "a post-commit publication failure must be reported as a committed warning, not an error",
    );
    assert!(warning.contains("committed"), "{warning}");
    assert_eq!(
        f.high_water(&config, "install-test", &IKH_A),
        Some(2),
        "the descriptor commit is the installation commit point"
    );

    // Startup recovers the committed snapshot even though the configured
    // path is unusable, and serves the selected (new) generation.
    let restarted_epoch = f
        .served_epochs(&config)
        .into_iter()
        .find(|(label, _)| label == "a")
        .map(|(_, epoch)| epoch)
        .unwrap();
    let new_epoch = Bundle::from_bytes(&second).unwrap().manifest.ca_scopes[0].epoch;
    assert_eq!(restarted_epoch, new_epoch);

    // Retrying the identical import repairs the path.
    std::fs::remove_dir_all(&selected).unwrap();
    let retry = f.install(&config, "a", &second).unwrap();
    assert_eq!(retry.publication_warning, None);
    assert_eq!(std::fs::read(&selected).unwrap(), second);
    assert_eq!(f.high_water(&config, "install-test", &IKH_A), Some(2));
}

#[test]
fn install_rejects_guard_for_a_different_state_directory() {
    let f = Fixture::new();
    let baseline = committed_baseline(&f);
    let guard = StateDirectoryLock::acquire(&f.dir.path().join("elsewhere")).unwrap();
    let err = install_bundle(&baseline.config, "a", &baseline.bytes, &guard).unwrap_err();
    assert!(
        err.to_string().contains("guard"),
        "a mismatched guard must be rejected: {err}"
    );
    assert_eq!(
        std::fs::read(state_path(&baseline.config)).unwrap(),
        baseline.state
    );
}

#[test]
fn single_label_install_preserves_other_labels() {
    let f = Fixture::new();
    let config = f.default_config();
    f.init_state(&config);
    let a1 = f.trusted("install-test", 1, None, IKH_A);
    let b1 = f.trusted("install-test", 1, None, IKH_B);
    f.install(&config, "a", &a1).unwrap();
    f.install(&config, "b", &b1).unwrap();
    let b_snapshot = as_json(&config)["active_bundles"]["b"]
        .as_str()
        .map(PathBuf::from)
        .expect("b must have a committed snapshot");
    assert!(b_snapshot.exists());

    let a2 = f.trusted("install-test", 2, None, IKH_A);
    f.install(&config, "a", &a2).unwrap();

    assert!(b_snapshot.exists(), "another label's snapshot must survive");
    let b_reloaded = Bundle::from_bytes(&std::fs::read(&b_snapshot).unwrap()).unwrap();
    assert_eq!(b_reloaded.manifest.ca_scopes[0].epoch, 1);
    assert_eq!(
        f.high_water(&config, "install-test", &IKH_B),
        Some(1),
        "another label's marks must survive"
    );
    assert_eq!(f.high_water(&config, "install-test", &IKH_A), Some(2));

    let served = f.served_epochs(&config);
    assert!(served.contains(&("a".to_string(), 2)));
    assert!(served.contains(&("b".to_string(), 1)));
}

#[test]
fn unknown_label_and_shared_destination_are_rejected() {
    let f = Fixture::new();
    let config = f.default_config();
    f.init_state(&config);
    let bytes = f.trusted("install-test", 1, None, IKH_A);

    let err = f.install(&config, "missing", &bytes).unwrap_err();
    assert!(err.to_string().contains("unknown CA label"), "{err}");

    // Two configured labels may not share one destination: replacing it
    // would ambiguously serve both labels from one file.
    let shared = f.dir.path().join("shared.ahu");
    let mut config = f.config(&format!(
        "[[ca]]\nlabel = 'a'\nbundle_file = '{}'\n[[ca]]\nlabel = 'b'\nbundle_file = '{}'\n",
        shared.display(),
        shared.display()
    ));
    config.storage.state_db = f.dir.path().join("state-shared");
    f.init_state(&config);
    let err = f.install(&config, "a", &bytes).unwrap_err();
    assert!(
        err.to_string().contains("also configured"),
        "a shared destination must be rejected: {err}"
    );
    assert!(!shared.exists());

    // Legacy unscoped configuration has no per-CA destination to select.
    let unscoped = f.config("");
    let err = unscoped.bundle_destination("a").unwrap_err();
    assert!(err.to_string().contains("unscoped"), "{err}");
}

#[test]
fn install_rejects_rollback_fork_and_missing_predecessor() {
    let f = Fixture::new();
    let baseline = committed_baseline(&f);

    // Older epoch.
    let older = f.trusted("install-test", 0, None, IKH_A);
    let err = f.install(&baseline.config, "a", &older).unwrap_err();
    assert!(err.to_string().contains("rollback"), "{err}");

    // Different bundle at the current high-water epoch (fork).
    let fork = f.untrusted_fork(&baseline.config);
    let err = f.install(&baseline.config, "a", &fork).unwrap_err();
    assert!(err.to_string().contains("rollback"), "{err}");

    // New epoch naming a predecessor that was never recorded.
    let skipped = f.trusted("install-test", 2, Some([0x99; 32]), IKH_A);
    let err = f.install(&baseline.config, "a", &skipped).unwrap_err();
    assert!(err.to_string().contains("fork"), "{err}");

    // Every rejection preserved the committed generation.
    assert_eq!(
        std::fs::read(&baseline.destination).unwrap(),
        baseline.bytes
    );
    assert_eq!(
        std::fs::read(state_path(&baseline.config)).unwrap(),
        baseline.state
    );
    assert_eq!(f.snapshot_files(&baseline.config), baseline.snapshots);

    // The correctly chained successor installs.
    let good = f.trusted("install-test", 2, Some(baseline.digest), IKH_A);
    f.install(&baseline.config, "a", &good).unwrap();
    assert_eq!(
        f.high_water(&baseline.config, "install-test", &IKH_A),
        Some(2)
    );
}

impl Fixture {
    /// A different bundle from the committed one, at the same epoch, sealed
    /// by the trusted signer (so only the fork check can reject it).
    fn untrusted_fork(&self, _config: &Config) -> Vec<u8> {
        let now = now();
        let manifest = base_manifest("install-test", 1, None, IKH_A, now);
        let mut builder = BundleBuilder::new(manifest);
        builder.add_entry([0xFE; 32], b"fork-response".to_vec());
        builder
            .build(|m| {
                hoike_sign::create_cms_seal(
                    m,
                    &hoike_sign::SealKey::EcdsaP256(self.key.clone()),
                    &self.cert,
                )
                .map_err(|e| ahu::AhuError::SealInvalid(e.to_string()))
            })
            .unwrap()
    }
}

fn base_manifest(
    producer: &str,
    epoch: u64,
    prev: Option<[u8; 32]>,
    ikh: [u8; 32],
    now: u64,
) -> Manifest {
    Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: producer.into(),
        created_at: now - 1,
        bundle_type: BundleType::Full,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            issuer_name_hash: vec![0xAA; 32],
            issuer_key_hash: ikh.to_vec(),
            epoch,
            responder_id: ResponderId {
                id_type: ResponderIdType::ByKey,
                value: vec![0xCC; 20],
            },
            responder_chain: None,
            signature_algorithm: vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02],
            completeness: Completeness::Partial,
        }],
        window: Window {
            produced_at: now - 1,
            this_update_min: now - 1,
            next_update_min: now + 3600,
            next_update_max: now + 3600,
        },
        integrity: Integrity {
            index_digest: [0; 32],
            data_digest: [0; 32],
        },
        entry_count: 0,
        continuity: Continuity {
            prev_manifest_digest: prev,
            base_manifest_digest: None,
            chain_length: 0,
        },
        shard: None,
        compression: None,
        extensions: None,
    }
}

#[test]
fn published_bytes_come_from_the_checked_buffer() {
    let f = Fixture::new();
    let config = f.config("[[ca]]\nlabel = 'a'\n");
    f.init_state(&config);
    let bytes = f.trusted("install-test", 1, None, IKH_A);
    let source = f.dir.path().join("incoming.ahu");
    std::fs::write(&source, &bytes).unwrap();

    // The source path is replaced after the input buffer was read. The
    // installation must publish the checked bytes, never re-read the path.
    let checked = std::fs::read(&source).unwrap();
    std::fs::write(&source, b"replaced after the buffer was read").unwrap();
    f.install(&config, "a", &checked).unwrap();

    assert_eq!(std::fs::read(destination(&config, "a")).unwrap(), checked);
    let served = f.served_epochs(&config);
    assert!(served.contains(&("a".to_string(), 1)));
}

#[test]
fn retrying_an_identical_committed_import_is_idempotent() {
    let f = Fixture::new();
    let config = f.default_config();
    f.init_state(&config);
    let first = f.trusted("install-test", 1, None, IKH_A);
    f.install(&config, "a", &first).unwrap();
    let bundle = Bundle::from_bytes(&first).unwrap();
    let second = f.trusted(
        "install-test",
        2,
        Some(ahu::manifest_digest(&bundle.manifest_bytes)),
        IKH_A,
    );
    f.install(&config, "a", &second).unwrap();

    let state_before = as_json(&config);
    let dest = destination(&config, "a");
    let dest_before = std::fs::read(&dest).unwrap();
    let snapshots_before = f.snapshot_files(&config);

    let retry = f.install(&config, "a", &second).unwrap();
    assert_eq!(retry.publication_warning, None);
    assert_eq!(as_json(&config), state_before);
    assert_eq!(std::fs::read(&dest).unwrap(), dest_before);
    assert_eq!(f.snapshot_files(&config), snapshots_before);
    assert_eq!(f.high_water(&config, "install-test", &IKH_A), Some(2));
}

#[test]
fn install_always_authenticates_even_with_demo_serving_flag() {
    let f = Fixture::new();
    let mut config = f.default_config();
    config.storage.allow_unauthenticated_bundles = true;
    f.init_state(&config);

    // Serving may run in demo mode; import still requires authentication.
    let unsigned = {
        let mut builder = BundleBuilder::new(base_manifest("install-test", 1, None, IKH_A, now()));
        builder.add_entry([1; 32], b"unsigned demo response".to_vec());
        builder.build(|_| Ok(Vec::new())).unwrap()
    };
    let err = f.install(&config, "a", &unsigned).unwrap_err();
    assert!(
        err.to_string().contains("seal"),
        "import must authenticate even with the demo serving flag: {err}"
    );
    assert!(!config.storage.state_db.join("generations").exists());
    let trusted = f.trusted("install-test", 1, None, IKH_A);
    f.install(&config, "a", &trusted).unwrap();
    assert_eq!(f.high_water(&config, "install-test", &IKH_A), Some(1));
}

#[test]
fn install_requires_an_initialized_state_directory() {
    let f = Fixture::new();
    let config = f.default_config();
    let bytes = f.trusted("install-test", 1, None, IKH_A);
    // Hold the writer guard (as the CLI does) — but never initialize state.
    let guard = StateDirectoryLock::acquire(&config.storage.state_db).unwrap();
    let err = install_bundle(&config, "a", &bytes, &guard).unwrap_err();
    assert!(
        err.to_string().contains("init-state"),
        "a missing state file must point at init-state: {err}"
    );
    assert!(
        !state_path(&config).exists(),
        "import must not initialize state"
    );
    assert!(
        !config.storage.bundle_dir.join("a.ahu").exists(),
        "nothing may be published without committed state"
    );
}
