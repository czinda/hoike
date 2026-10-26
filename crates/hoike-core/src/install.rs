//! Offline, recoverable authenticated installation (design §S5, audit
//! remediation F05).
//!
//! `install_bundle` turns an offline import into a real installation:
//!
//! 1. The input is authenticated under the configured trust policy — always,
//!    even when the config permits unauthenticated demo *serving* — and
//!    validated against the supported serving profile. The destination is
//!    resolved from the selected CA label, never from a filename.
//! 2. Existing state is opened strictly; rollback and predecessor continuity
//!    are checked; changes are staged while retaining other labels'
//!    committed snapshots.
//! 3. The new immutable snapshot is written and fsynced, then the descriptor
//!    (marks + snapshot references) is committed atomically. **That
//!    descriptor commit is the installation commit point.**
//! 4. The configured bundle path is published atomically *after* the commit.
//!    If this convenience-path update fails, the result is still committed
//!    and carries a `publication_warning` — never an error falsely claiming
//!    no installation happened. Startup recovers from the committed
//!    snapshot; retrying the identical import repairs the path.
//!
//! A failure before the descriptor commit leaves the old marks and the
//! configured files intact. If the descriptor rename succeeds but its
//! directory fsync fails, the outcome is indeterminate and is reported as
//! [`CoreError::DurabilityUncertain`] instructing the operator to stop and
//! reopen state — never as a claimed rollback. There is no two-file
//! pseudo-transaction and no deletion of old recovery material before
//! commitment.

use std::path::PathBuf;

use ahu::Bundle;
use tracing::info;

use crate::admission::{authenticate_bundle, validate_serving_profile};
use crate::config::Config;
use crate::error::{CoreError, Result};
use crate::state::StateStore;
use crate::storage::{StateDirectoryLock, write_atomic};

/// The outcome of a successful [`install_bundle`].
#[derive(Debug, Clone)]
pub struct InstallResult {
    /// The configured destination the bundle was installed for.
    pub destination: PathBuf,
    /// Set when the installation is committed but publishing the configured
    /// bundle path failed afterwards. Startup still recovers the committed
    /// snapshot; retrying the identical import repairs the path.
    pub publication_warning: Option<String>,
}

/// Install an authenticated bundle for `label` into its configured
/// destination, following the §S5 commit order.
///
/// `bytes` is the complete checked input: read the source once before
/// calling this — everything published (snapshot and configured path) comes
/// from these bytes, never from a re-read of the source path. `guard` must
/// be the exclusive writer lock for `config.storage.state_db`; a running
/// server holding that lock makes the caller fail before reaching this
/// function.
pub fn install_bundle(
    config: &Config,
    label: &str,
    bytes: &[u8],
    guard: &StateDirectoryLock,
) -> Result<InstallResult> {
    // The guard must protect the directory this configuration names, so a
    // mismatched guard can never authorize writes elsewhere.
    let state_dir = std::fs::canonicalize(&config.storage.state_db).map_err(|e| {
        CoreError::Config(format!(
            "cannot resolve state directory {}: {e}",
            config.storage.state_db.display()
        ))
    })?;
    if guard.state_dir() != state_dir {
        return Err(CoreError::Config(format!(
            "writer guard protects state directory {} but the configuration uses {}",
            guard.state_dir().display(),
            state_dir.display()
        )));
    }

    // Target resolution (S5): the selected CA destination, nothing else.
    let destination = config.bundle_destination(label)?;

    // Authentication always runs — the demo serving flag never relaxes it.
    let bundle = Bundle::from_bytes(bytes)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CoreError::Config(e.to_string()))?
        .as_secs();
    let verification = authenticate_bundle(&bundle, &config.storage, now)?;
    validate_serving_profile(&bundle)?;

    // Strict state open: a missing or incomplete state directory is an
    // operator error (init-state / restore), never a fresh timeline.
    let state_path = config.storage.state_db.join("state.json");
    let mut store = StateStore::open(&state_path)?;
    store.check_rollback(&bundle)?;
    store.check_continuity(&bundle)?;

    info!(
        target: "audit",
        event = "bundle_install",
        ca = label,
        producer = %bundle.manifest.producer_id,
        epoch = bundle.manifest.ca_scopes.first().map(|s| s.epoch).unwrap_or(0),
        signer = %verification.signer_sha256,
        destination = %destination.display(),
        "authenticated bundle installation starting"
    );

    // Stage: single-label installation preserves other labels' committed
    // snapshots; only this label's reference is replaced.
    let mut candidate = store.transaction();
    candidate.advance_from_bundle(&bundle)?;
    candidate.snapshot(label, &bundle)?;

    // The descriptor commit is the installation commit point. A
    // DurabilityUncertain error here is indeterminate by contract: the
    // operator must stop and reopen state.
    store.commit(candidate)?;

    // Post-commit publication of the configured convenience path. Failure
    // here must not be reported as an uncommitted rejection.
    let publication_warning = match write_atomic(&destination, bytes) {
        Ok(()) => None,
        Err(error) => {
            let warning = format!(
                "installation for CA '{label}' is committed, but publishing the configured \
                 bundle path {} failed: {error}. Startup recovers the committed snapshot; \
                 retry this import to repair the path.",
                destination.display()
            );
            info!(
                target: "audit",
                event = "bundle_install_publication_warning",
                ca = label,
                "committed installation with unpublished convenience path"
            );
            Some(warning)
        }
    };

    info!(
        target: "audit",
        event = "bundle_install_committed",
        ca = label,
        epoch = bundle.manifest.ca_scopes.first().map(|s| s.epoch).unwrap_or(0),
        "authenticated bundle installation committed"
    );

    Ok(InstallResult {
        destination,
        publication_warning,
    })
}

#[cfg(test)]
mod fault_tests {
    //! State-owned fault injection at the four §S5 commit-order points.
    //!
    //! These unit tests run in-crate so the thread-local injection in
    //! `storage::fault_injection` is compiled in; the integration suite in
    //! `tests/installation.rs` covers the same order with natural
    //! filesystem faults. Call indices within one `install_bundle` of a
    //! fresh bundle: 0 = snapshot write, 1 = descriptor commit,
    //! 2 = alias publication.

    use super::*;
    use crate::storage::fault_injection::{self, FaultMode};
    use ahu::{
        BundleBuilder, BundleType, CaScope, Completeness, Continuity, Integrity, Manifest,
        ResponderId, ResponderIdType, Window,
    };
    use der::{Decode, Encode};
    use p256::ecdsa::SigningKey;
    use uuid::Uuid;

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn manifest(producer: &str, epoch: u64, ikh: [u8; 32]) -> Manifest {
        Manifest {
            format_version: 1,
            bundle_id: Uuid::nil(),
            producer_id: producer.into(),
            created_at: now() - 1,
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
                produced_at: now() - 1,
                this_update_min: now() - 1,
                next_update_min: now() + 3600,
                next_update_max: now() + 3600,
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
        }
    }

    struct Fixture {
        /// Kept alive for the fixture's lifetime; never read directly.
        _dir: tempfile::TempDir,
        seal_key: SigningKey,
        seal_cert: Vec<u8>,
        config: Config,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let now = now();
            let seal_key = SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
            let mut cert = x509_cert::Certificate::from_der(
                &hoike_sign::generate_seal_cert(&seal_key).unwrap(),
            )
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
            let sig: p256::ecdsa::DerSignature =
                seal_key.sign(&cert.tbs_certificate.to_der().unwrap());
            cert.signature = der::asn1::BitString::from_bytes(sig.as_bytes()).unwrap();
            let seal_cert = cert.to_der().unwrap();
            std::fs::write(dir.path().join("signer.der"), &seal_cert).unwrap();

            let config_path = dir.path().join("hoike.toml");
            std::fs::write(
                &config_path,
                format!(
                    "[server]\nmode = 'edge'\n[storage]\nbundle_dir = '{0}/bundles'\nstate_db = \
                     '{0}/state'\nseal_signer_pins = ['{0}/signer.der']\n[[ca]]\nlabel = 'a'\n",
                    dir.path().display()
                ),
            )
            .unwrap();
            let config = Config::from_file(&config_path).unwrap();
            StateStore::initialize(&config.storage.state_db.join("state.json")).unwrap();
            Self {
                _dir: dir,
                seal_key,
                seal_cert,
                config,
            }
        }

        fn bundle(&self, epoch: u64) -> Vec<u8> {
            let seal_key = hoike_sign::SealKey::EcdsaP256(self.seal_key.clone());
            let seal_cert = self.seal_cert.clone();
            let mut builder = BundleBuilder::new(manifest("fault-test", epoch, [0xBB; 32]));
            builder.add_entry([epoch as u8; 32], format!("response-{epoch}").into_bytes());
            builder
                .build(move |m| {
                    hoike_sign::create_cms_seal(m, &seal_key, &seal_cert)
                        .map_err(|e| ahu::AhuError::SealInvalid(e.to_string()))
                })
                .unwrap()
        }

        fn install(&self, bytes: &[u8]) -> Result<InstallResult> {
            let guard = StateDirectoryLock::acquire(&self.config.storage.state_db).unwrap();
            install_bundle(&self.config, "a", bytes, &guard)
        }

        fn state_bytes(&self) -> Vec<u8> {
            std::fs::read(self.config.storage.state_db.join("state.json")).unwrap()
        }

        fn destination_bytes(&self) -> Vec<u8> {
            std::fs::read(self.config.storage.bundle_dir.join("a.ahu")).unwrap()
        }

        fn high_water(&self) -> Option<u64> {
            StateStore::open(&self.config.storage.state_db.join("state.json"))
                .unwrap()
                .get_high_water("fault-test", &hex::encode([0xBB; 32]))
        }
    }

    #[test]
    fn snapshot_write_failure_preserves_committed_generation() {
        let f = Fixture::new();
        let first = f.bundle(1);
        f.install(&first).unwrap();
        let (old_state, old_destination) = (f.state_bytes(), f.destination_bytes());

        fault_injection::set(0, FaultMode::BeforeRename);
        let err = f.install(&f.bundle(2)).unwrap_err();
        fault_injection::clear();
        assert!(!err.to_string().contains("durability uncertain"), "{err}");
        assert_eq!(f.state_bytes(), old_state);
        assert_eq!(f.destination_bytes(), old_destination);
        assert_eq!(f.high_water(), Some(1));
    }

    #[test]
    fn descriptor_pre_rename_failure_preserves_committed_generation() {
        let f = Fixture::new();
        let first = f.bundle(1);
        f.install(&first).unwrap();
        let (old_state, old_destination) = (f.state_bytes(), f.destination_bytes());

        // Call 1 is the descriptor commit; fail it after the temporary
        // descriptor is written but before the rename.
        fault_injection::set(1, FaultMode::BeforeRename);
        let err = f.install(&f.bundle(2)).unwrap_err();
        fault_injection::clear();
        assert!(
            !matches!(err, CoreError::DurabilityUncertain { .. }),
            "a pre-rename failure is a plain failure: {err}"
        );
        assert_eq!(f.state_bytes(), old_state, "old marks must survive");
        assert_eq!(f.destination_bytes(), old_destination);
        assert_eq!(f.high_water(), Some(1));
    }

    #[test]
    fn descriptor_post_rename_fsync_failure_is_indeterminate_not_rollback() {
        let f = Fixture::new();
        let first = f.bundle(1);
        f.install(&first).unwrap();
        let old_destination = f.destination_bytes();
        let second = f.bundle(2);

        fault_injection::set(1, FaultMode::DirFsyncAfterRename);
        let err = f.install(&second).unwrap_err();
        fault_injection::clear();

        // The typed error, instructing the operator to stop and reopen —
        // never a claim that nothing changed.
        assert!(
            matches!(err, CoreError::DurabilityUncertain { .. }),
            "post-rename directory-fsync failure must be DurabilityUncertain: {err}"
        );
        assert!(err.to_string().contains("reopen"), "{err}");

        // After reopen, state and snapshots are coherent: the rename did
        // happen, so the new generation is committed, and nothing claimed a
        // rollback or undid marks.
        assert_eq!(f.high_water(), Some(2));
        let reopened = StateStore::open(&f.config.storage.state_db.join("state.json")).unwrap();
        assert!(
            reopened
                .active_bundles()
                .get("a")
                .is_some_and(|p| p.exists()),
            "the committed snapshot must be present and referenced"
        );
        // The convenience path was never reached: it still holds the old
        // generation, which startup recovers from (see the integration
        // suite for the full recovery reload).
        assert_eq!(f.destination_bytes(), old_destination);
    }

    #[test]
    fn alias_publication_failure_returns_committed_warning() {
        let f = Fixture::new();
        let first = f.bundle(1);
        f.install(&first).unwrap();

        // Call 2 is the post-commit alias publication.
        fault_injection::set(2, FaultMode::BeforeRename);
        let committed = f.install(&f.bundle(2)).unwrap();
        fault_injection::clear();

        assert!(
            committed.publication_warning.is_some(),
            "a post-commit publication failure is a committed warning"
        );
        assert_eq!(f.high_water(), Some(2), "the installation is committed");
        assert_eq!(
            f.destination_bytes(),
            first,
            "the unpublished path keeps the previous generation"
        );
    }
}
