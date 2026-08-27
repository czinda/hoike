#[cfg(feature = "seal-verify")]
mod tests {
    use ahu::*;
    use uuid::Uuid;

    fn build_test_manifest() -> Manifest {
        Manifest {
            format_version: 1,
            bundle_id: Uuid::nil(),
            producer_id: "seal-test".into(),
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
        }
    }

    #[test]
    fn seal_created_by_hoike_sign_verifies_in_ahu() {
        // Create a seal using hoike-sign
        let secret = [7u8; 32];
        let signing_key = p256_v013::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
        let seal_cert_der = hoike_sign::generate_seal_cert_for_key(
            &hoike_sign::SealKey::EcdsaP256(signing_key.clone()),
        )
        .unwrap();

        // Build a bundle with a real CMS seal
        let manifest = build_test_manifest();
        let mut builder = BundleBuilder::new(manifest);
        builder.add_entry([0xAA; 32], b"response".to_vec());

        let seal_key = hoike_sign::SealKey::EcdsaP256(signing_key.clone());
        let cert_der = seal_cert_der.clone();
        let bytes = builder
            .build(move |manifest_bytes| {
                hoike_sign::create_cms_seal(manifest_bytes, &seal_key, &cert_der)
                    .map_err(|e| ahu::AhuError::Write(e.to_string()))
            })
            .unwrap();

        // Load and verify the bundle
        let bundle = Bundle::from_bytes(&bytes).unwrap();
        let result = verify_structure(&bundle).unwrap();
        assert!(result.seal_present);

        // Verify the CMS seal
        let seal_result = verify_seal(&bundle.manifest_bytes, &bundle.seal_bytes).unwrap();
        assert!(seal_result.signature_valid);
        assert!(seal_result.digest_matches);
    }

    #[test]
    fn tampered_manifest_fails_seal_verification() {
        let secret = [7u8; 32];
        let signing_key = p256_v013::ecdsa::SigningKey::from_bytes((&secret).into()).unwrap();
        let seal_cert_der = hoike_sign::generate_seal_cert_for_key(
            &hoike_sign::SealKey::EcdsaP256(signing_key.clone()),
        )
        .unwrap();

        let manifest = build_test_manifest();
        let mut builder = BundleBuilder::new(manifest);
        builder.add_entry([0xAA; 32], b"response".to_vec());

        let seal_key = hoike_sign::SealKey::EcdsaP256(signing_key.clone());
        let cert_der = seal_cert_der.clone();
        let bytes = builder
            .build(move |manifest_bytes| {
                hoike_sign::create_cms_seal(manifest_bytes, &seal_key, &cert_der)
                    .map_err(|e| ahu::AhuError::Write(e.to_string()))
            })
            .unwrap();

        let bundle = Bundle::from_bytes(&bytes).unwrap();

        // Tamper with the manifest bytes
        let mut tampered = bundle.manifest_bytes.clone();
        if let Some(b) = tampered.last_mut() {
            *b ^= 0xFF;
        }

        // Seal verification should fail
        let result = verify_seal(&tampered, &bundle.seal_bytes);
        assert!(result.is_err() || !result.unwrap().digest_matches);
    }
}
