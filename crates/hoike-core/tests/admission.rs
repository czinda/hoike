use ahu::{
    Bundle, BundleBuilder, BundleType, CaScope, Completeness, Continuity, Integrity, Manifest,
    ResponderId, ResponderIdType, Window,
};
use der::{Decode, Encode, EncodePem};
use hoike_core::admission::{AdmissionTrust, admit_bundle, authenticate_bundle};
use hoike_core::config::{SealAuthorization, StorageConfig};
use hoike_core::{Config, CoreError, ResponderState};
use hoike_sign::{CertIdCompat, SealKey};
use p256::ecdsa::{DerSignature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};
use std::time::Duration;
use uuid::Uuid;

fn current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn storage(dir: &std::path::Path) -> StorageConfig {
    toml::from_str(&format!(
        "bundle_dir = '{0}'\nstate_db = '{0}/state'\n",
        dir.display()
    ))
    .unwrap()
}

fn unsigned_bundle(now: u64) -> Bundle {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::nil(),
        producer_id: "admission-test".into(),
        created_at: now - 1,
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
            prev_manifest_digest: None,
            base_manifest_digest: None,
            chain_length: 0,
        },
        shard: None,
        compression: None,
        extensions: None,
    };
    let mut builder = BundleBuilder::new(manifest);
    builder.add_entry([1; 32], b"demo-response".to_vec());
    Bundle::from_bytes(&builder.build(|_| Ok(Vec::new())).unwrap()).unwrap()
}

#[test]
fn missing_trust_rejects_normal_admission() {
    let dir = tempfile::tempdir().unwrap();
    let mut storage = storage(dir.path());
    let now = current_time();
    let unsigned = unsigned_bundle(now);
    ahu::verify_structure(&unsigned).unwrap();

    assert!(admit_bundle(&unsigned, &storage, now).is_err());
    storage.allow_unauthenticated_bundles = true;
    assert!(matches!(
        admit_bundle(&unsigned, &storage, now),
        Ok(AdmissionTrust::UnauthenticatedDemo)
    ));
    assert!(authenticate_bundle(&unsigned, &storage, now).is_err());
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
}

// Keep the certificate's time encoding canonical across the der 0.7/0.8
// boundary, and its validity window relative to this test run.
fn issued_certificate(subject: &SigningKey, issuer: &SigningKey, ca: bool, now: u64) -> Vec<u8> {
    let mut cert =
        x509_cert::Certificate::from_der(&hoike_sign::generate_seal_cert(subject).unwrap())
            .unwrap();
    let time = |seconds| {
        x509_cert::time::Time::UtcTime(
            der::asn1::UtcTime::from_unix_duration(Duration::from_secs(seconds)).unwrap(),
        )
    };
    cert.tbs_certificate.validity = x509_cert::time::Validity {
        not_before: time(now - 60),
        not_after: time(now + 3600),
    };
    if ca {
        cert.tbs_certificate.extensions = Some(vec![x509_cert::ext::Extension {
            extn_id: const_oid::ObjectIdentifier::new_unwrap("2.5.29.19"),
            critical: true,
            extn_value: der::asn1::OctetString::new(vec![0x30, 0x03, 0x01, 0x01, 0xff]).unwrap(),
        }]);
    }
    // The synthetic subject/issuer names are both CN=hoike-seal; issuer key
    // verification, rather than name matching alone, must establish trust.
    let signature: DerSignature = issuer.sign(&cert.tbs_certificate.to_der().unwrap());
    cert.signature = der::asn1::BitString::from_bytes(signature.as_bytes()).unwrap();
    cert.to_der().unwrap()
}

fn signed_bundle(seal_key: &SigningKey, cert: &[u8], now: u64, compat: CertIdCompat) -> Bundle {
    // Real OCSP responses, using a key distinct from all synthetic seal keys.
    let mut ocsp_key = signing_key(1);
    let ca = hoike_sign::CaIdentity {
        label: "admission-ca".into(),
        issuer_name_der: "CN=Admission CA"
            .parse::<x509_cert::name::Name>()
            .unwrap()
            .to_der()
            .unwrap(),
        issuer_key_bytes: ocsp_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec(),
    };
    let snapshot = hoike_sign::StatusSnapshot {
        entries: [(vec![42], hoike_sign::CertificateStatus::Good)].into(),
        this_update: now - 1,
        next_update: Some(now + 3600),
        ..Default::default()
    };
    let config = hoike_sign::GenerationConfig {
        producer_id: "admission-test".into(),
        certid_compat: compat,
        validity_secs: 3600,
        jitter_secs: 0,
        ..Default::default()
    };
    let bytes = hoike_sign::produce_bundle::<_, DerSignature>(
        &ca,
        &snapshot,
        &config,
        &mut ocsp_key,
        |manifest| {
            hoike_sign::create_cms_seal(manifest, &SealKey::EcdsaP256(seal_key.clone()), cert)
        },
        None,
    )
    .unwrap();
    Bundle::from_bytes(&bytes).unwrap()
}

fn pinned_storage(dir: &std::path::Path, cert: &[u8]) -> StorageConfig {
    let mut storage = storage(dir);
    let pin = dir.join("seal-signer.der");
    std::fs::write(&pin, cert).unwrap();
    storage.seal_signer_pins = vec![pin];
    storage
}

fn authorization(bundle: &Bundle, cert: &[u8], scope: usize) -> SealAuthorization {
    SealAuthorization {
        producer_id: bundle.manifest.producer_id.clone(),
        issuer_key_hash: hex::encode(&bundle.manifest.ca_scopes[scope].issuer_key_hash),
        signer_sha256: hex::encode(Sha256::digest(cert)),
    }
}

#[test]
fn configured_trust_never_downgrades_to_demo() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let key = signing_key(7);
    let cert = issued_certificate(&key, &key, false, now);
    let valid = signed_bundle(&key, &cert, now, CertIdCompat::Sha256Only);
    let mut storage = pinned_storage(dir.path(), &cert);
    storage.allow_unauthenticated_bundles = true;

    assert_eq!(
        admit_bundle(&valid, &storage, now).unwrap(),
        AdmissionTrust::Authenticated {
            signer_sha256: hex::encode(Sha256::digest(&cert)),
        }
    );
    let verification = authenticate_bundle(&valid, &storage, now).unwrap();
    assert!(verification.signature_valid && verification.digest_matches);
    assert!(
        !storage.state_db.exists(),
        "authentication must be read-only"
    );
    assert!(admit_bundle(&unsigned_bundle(now), &storage, now).is_err());

    let mut corrupt = Bundle::from_bytes(&valid.to_bytes().unwrap()).unwrap();
    *corrupt.seal_bytes.last_mut().unwrap() ^= 1;
    let err = admit_bundle(&corrupt, &storage, now).unwrap_err();
    assert!(
        err.to_string().contains("seal verification failed"),
        "{err}"
    );

    let wrong_key = signing_key(8);
    let wrong_cert = issued_certificate(&wrong_key, &wrong_key, false, now);
    for (signer, certificate) in [(&wrong_key, &cert), (&wrong_key, &wrong_cert)] {
        let wrong = signed_bundle(signer, certificate, now, CertIdCompat::Sha256Only);
        let err = admit_bundle(&wrong, &storage, now).unwrap_err();
        assert!(
            err.to_string().contains("seal verification failed"),
            "{err}"
        );
    }

    // Each restriction is meaningful, and uses the verified signer's identity.
    let correct = authorization(&valid, &cert, 0);
    storage.seal_authorizations = vec![correct.clone()];
    authenticate_bundle(&valid, &storage, now).unwrap();
    for field in ["producer", "issuer", "signer"] {
        let mut wrong = correct.clone();
        match field {
            "producer" => wrong.producer_id = "other-producer".into(),
            "issuer" => wrong.issuer_key_hash = "00".repeat(32),
            "signer" => wrong.signer_sha256 = "00".repeat(32),
            _ => unreachable!(),
        }
        storage.seal_authorizations = vec![wrong];
        let err = admit_bundle(&valid, &storage, now).unwrap_err();
        assert!(err.to_string().contains("not authorized"), "{field}: {err}");
    }
}

#[test]
fn embedded_signer_is_not_trust_without_configuration() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let key = signing_key(7);
    let cert = issued_certificate(&key, &key, false, now);
    let bundle = signed_bundle(&key, &cert, now, CertIdCompat::Sha256Only);
    let mut storage = storage(dir.path());
    assert!(admit_bundle(&bundle, &storage, now).is_err());
    storage.allow_unauthenticated_bundles = true;
    assert_eq!(
        admit_bundle(&bundle, &storage, now).unwrap(),
        AdmissionTrust::UnauthenticatedDemo
    );
    assert!(authenticate_bundle(&bundle, &storage, now).is_err());
}

#[test]
fn authorizations_alone_never_enable_demo_admission() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let unsigned = unsigned_bundle(now);
    let mut storage = storage(dir.path());
    storage.allow_unauthenticated_bundles = true;
    storage.seal_authorizations = vec![authorization(&unsigned, b"not-a-certificate", 0)];
    let err = admit_bundle(&unsigned, &storage, now).unwrap_err();
    assert!(
        err.to_string()
            .contains("requires trust anchors or explicit signer pins"),
        "{err}"
    );
}

#[test]
fn directly_issued_anchor_and_alternative_pin_policies_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let root = signing_key(9);
    let leaf = signing_key(7);
    let anchor = issued_certificate(&root, &root, true, now);
    let cert = issued_certificate(&leaf, &root, false, now);
    let bundle = signed_bundle(&leaf, &cert, now, CertIdCompat::Sha256Only);
    let anchor_path = dir.path().join("anchor.pem");
    std::fs::write(
        &anchor_path,
        x509_cert::Certificate::from_der(&anchor)
            .unwrap()
            .to_pem(der::pem::LineEnding::LF)
            .unwrap(),
    )
    .unwrap();
    let mut storage = storage(dir.path());
    storage.seal_trust_anchors = Some(vec![anchor_path.clone()]);
    storage.allow_unauthenticated_bundles = true;
    let expected_signer = hex::encode(Sha256::digest(&cert));
    assert_eq!(
        authenticate_bundle(&bundle, &storage, now)
            .unwrap()
            .signer_sha256,
        expected_signer
    );

    // A nonmatching pin still permits a signer authenticated by a configured
    // anchor. Pins and anchors remain alternative trust sources.
    let wrong = signing_key(8);
    let wrong_cert = issued_certificate(&wrong, &wrong, false, now);
    let pin = dir.path().join("other-signer.der");
    std::fs::write(&pin, &wrong_cert).unwrap();
    storage.seal_signer_pins = vec![pin];
    assert_eq!(
        admit_bundle(&bundle, &storage, now).unwrap(),
        AdmissionTrust::Authenticated {
            signer_sha256: expected_signer
        }
    );
    let untrusted = signed_bundle(&wrong, &wrong_cert, now, CertIdCompat::Sha256Only);
    storage.seal_signer_pins.clear();
    assert!(admit_bundle(&untrusted, &storage, now).is_err());

    // An end-entity pin is not a CA anchor. An unreadable policy is also fatal.
    std::fs::write(&anchor_path, &cert).unwrap();
    assert!(admit_bundle(&bundle, &storage, now).is_err());
    std::fs::remove_file(anchor_path).unwrap();
    assert!(admit_bundle(&bundle, &storage, now).is_err());
}

#[test]
fn dual_scope_authorization_requires_every_scope() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let key = signing_key(7);
    let cert = issued_certificate(&key, &key, false, now);
    let bundle = signed_bundle(&key, &cert, now, CertIdCompat::Dual);
    assert_eq!(bundle.manifest.ca_scopes.len(), 2);
    let mut storage = pinned_storage(dir.path(), &cert);
    storage.allow_unauthenticated_bundles = true;
    storage.seal_authorizations = vec![authorization(&bundle, &cert, 0)];
    assert!(admit_bundle(&bundle, &storage, now).is_err());
    storage
        .seal_authorizations
        .push(authorization(&bundle, &cert, 1));
    for auth in &mut storage.seal_authorizations {
        auth.issuer_key_hash.make_ascii_uppercase();
        auth.signer_sha256.make_ascii_uppercase();
    }
    assert!(matches!(
        admit_bundle(&bundle, &storage, now),
        Ok(AdmissionTrust::Authenticated { .. })
    ));
    storage.seal_authorizations.remove(0);
    assert!(authenticate_bundle(&bundle, &storage, now).is_err());
}

#[test]
fn supplied_time_controls_certificate_validity() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let key = signing_key(7);
    let cert = issued_certificate(&key, &key, false, now);
    let bundle = signed_bundle(&key, &cert, now, CertIdCompat::Sha256Only);
    let mut storage = pinned_storage(dir.path(), &cert);
    storage.allow_unauthenticated_bundles = true;
    authenticate_bundle(&bundle, &storage, now).unwrap();
    for outside in [now - 61, now + 3600] {
        let err = admit_bundle(&bundle, &storage, outside).unwrap_err();
        assert!(err.to_string().contains("outside validity period"), "{err}");
    }
}

#[test]
fn authenticated_and_demo_admission_both_verify_digests() {
    let dir = tempfile::tempdir().unwrap();
    let now = current_time();
    let key = signing_key(7);
    let cert = issued_certificate(&key, &key, false, now);
    let valid = signed_bundle(&key, &cert, now, CertIdCompat::Sha256Only);
    let trusted = pinned_storage(dir.path(), &cert);
    let mut demo = storage(dir.path());
    demo.allow_unauthenticated_bundles = true;
    for section in ["index", "data", "manifest"] {
        let mut bundle = Bundle::from_bytes(&valid.to_bytes().unwrap()).unwrap();
        match section {
            "index" => bundle.index[0].entry_key[0] ^= 1,
            "data" => bundle.data[0] ^= 1,
            "manifest" => {
                bundle.manifest.producer_id = "tampered".into();
                bundle.manifest_bytes = bundle.manifest.to_cbor();
            }
            _ => unreachable!(),
        }
        assert!(
            authenticate_bundle(&bundle, &trusted, now).is_err(),
            "{section}"
        );
        assert!(admit_bundle(&bundle, &trusted, now).is_err(), "{section}");
        if section != "manifest" {
            assert!(
                matches!(admit_bundle(&bundle, &demo, now), Err(CoreError::Bundle(_))),
                "{section}"
            );
        }
    }
}

fn responder_config(dir: &std::path::Path, explicit_ca: bool) -> Config {
    let mut config: Config = toml::from_str(&format!(
        "[server]\n[storage]\nbundle_dir='{0}'\nstate_db='{0}/state'\n",
        dir.display()
    ))
    .unwrap();
    if explicit_ca {
        config.ca.push(toml::from_str("label='test'").unwrap());
    }
    config
}

#[test]
fn normal_and_recovery_loads_require_trust() {
    for explicit_ca in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("test.ahu");
        std::fs::write(
            &bundle_path,
            unsigned_bundle(current_time()).to_bytes().unwrap(),
        )
        .unwrap();
        let mut config = responder_config(dir.path(), explicit_ca);
        assert!(ResponderState::load(config.clone()).is_err());

        config.storage.allow_unauthenticated_bundles = true;
        let responder = ResponderState::load(config.clone()).unwrap();
        assert_eq!(responder.total_entries(), 1);
        drop(responder);
        let state_path = config.storage.state_db.join("state.json");
        let committed = std::fs::read(&state_path).unwrap();
        std::fs::write(&bundle_path, b"interrupted write").unwrap();
        config.storage.allow_unauthenticated_bundles = false;
        assert!(ResponderState::load(config.clone()).is_err());
        assert_eq!(std::fs::read(&state_path).unwrap(), committed);

        config.storage.allow_unauthenticated_bundles = true;
        assert_eq!(ResponderState::load(config).unwrap().total_entries(), 1);
    }
}

#[test]
fn failed_authentication_keeps_committed_state_and_recovery_rechecks_trust() {
    for explicit_ca in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let now = current_time();
        let key = signing_key(7);
        let cert = issued_certificate(&key, &key, false, now);
        let bundle = signed_bundle(&key, &cert, now, CertIdCompat::Sha256Only);
        let path = dir.path().join("test.ahu");
        std::fs::write(&path, bundle.to_bytes().unwrap()).unwrap();
        let mut config = responder_config(dir.path(), explicit_ca);
        config.storage = pinned_storage(dir.path(), &cert);
        config.storage.allow_unauthenticated_bundles = true;
        let responder = ResponderState::load(config.clone()).unwrap();
        let state_path = config.storage.state_db.join("state.json");
        let committed = std::fs::read(&state_path).unwrap();

        std::fs::write(&path, unsigned_bundle(now).to_bytes().unwrap()).unwrap();
        assert!(responder.reload().is_err());
        assert_eq!(std::fs::read(&state_path).unwrap(), committed);
        assert_eq!(responder.total_entries(), 1);
        drop(responder);
        // The bad configured bundle cannot replace the authenticated snapshot.
        let recovered = ResponderState::load(config.clone()).unwrap();
        assert_eq!(recovered.total_entries(), 1);
        assert_eq!(std::fs::read(&state_path).unwrap(), committed);
        drop(recovered);

        // A persisted snapshot is not exempt from the current trust policy.
        let wrong = signing_key(8);
        let wrong_cert = issued_certificate(&wrong, &wrong, false, now);
        std::fs::write(&config.storage.seal_signer_pins[0], wrong_cert).unwrap();
        assert!(ResponderState::load(config).is_err());
        assert_eq!(std::fs::read(&state_path).unwrap(), committed);
    }
}
