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
    fn wrap(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if bytes.len() < 128 {
            out.push(bytes.len() as u8);
        } else if bytes.len() < 256 {
            out.extend_from_slice(&[0x81, bytes.len() as u8]);
        } else {
            out.extend_from_slice(&[0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]);
        }
        out.extend_from_slice(bytes);
        out
    }

    // Synthetic certificates: root and leaf share a test DN, but distinct keys.
    // Re-signing explicitly exercises issuer signature validation rather than DN matching.
    fn issued_cert(
        subject_key: &p256_v013::ecdsa::SigningKey,
        issuer_key: &p256_v013::ecdsa::SigningKey,
        ca: bool,
    ) -> Vec<u8> {
        use der::{Decode, Encode};
        use p256_v013::ecdsa::signature::Signer;
        let original = hoike_sign::generate_seal_cert(subject_key).unwrap();
        let cert = x509_cert::Certificate::from_der(&original).unwrap();
        let tbs_der = cert.tbs_certificate().to_der().unwrap();
        let tbs_any = der::Any::from_der(&tbs_der).unwrap();
        let mut tbs = tbs_any.value().to_vec();
        if ca {
            let basic = wrap(0x30, &[0x01, 0x01, 0xff]);
            let mut extension = vec![0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff];
            extension.extend(wrap(0x04, &basic));
            tbs.extend(wrap(0xa3, &wrap(0x30, &wrap(0x30, &extension))));
        }
        let tbs = wrap(0x30, &tbs);
        let signature: p256_v013::ecdsa::Signature = issuer_key.sign(&tbs);
        let mut output = tbs;
        output.extend(cert.signature_algorithm().to_der().unwrap());
        let mut bits = vec![0];
        bits.extend(signature.to_der().as_bytes());
        output.extend(wrap(0x03, &bits));
        wrap(0x30, &output)
    }

    #[test]
    fn authenticates_direct_issuer_and_rejects_wrong_anchor_and_expiry() {
        let root = p256_v013::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
        let leaf = p256_v013::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let other = p256_v013::ecdsa::SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
        let anchor = issued_cert(&root, &root, true);
        let cert = issued_cert(&leaf, &root, false);
        let seal =
            hoike_sign::create_cms_seal(b"manifest", &hoike_sign::SealKey::EcdsaP256(leaf), &cert)
                .unwrap();
        let now = 1_800_000_000;
        assert!(
            verify_seal_with_anchors(b"manifest", &seal, std::slice::from_ref(&anchor), now)
                .is_ok()
        );
        let wrong = issued_cert(&other, &other, true);
        assert!(verify_seal_with_anchors(b"manifest", &seal, &[wrong], now).is_err());
        assert!(verify_seal_with_anchors(b"manifest", &seal, &[], now).is_err());
        assert!(verify_seal_with_anchors(b"manifest", &seal, &[cert], now).is_err());
        assert!(
            verify_seal_with_anchors(b"manifest", &seal, std::slice::from_ref(&anchor), 0).is_err()
        );
        assert!(verify_seal_with_anchors(b"manifest", &seal, &[anchor], u64::MAX).is_err());
    }

    #[test]
    fn mismatched_embedded_key_is_an_error_not_false_success() {
        let key = p256_v013::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let wrong = p256_v013::ecdsa::SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
        let cert = hoike_sign::generate_seal_cert(&wrong).unwrap();
        let seal =
            hoike_sign::create_cms_seal(b"manifest", &hoike_sign::SealKey::EcdsaP256(key), &cert)
                .unwrap();
        assert!(verify_seal(b"manifest", &seal).is_err());
    }
    #[test]
    fn explicit_pin_accepts_demo_cert_but_does_not_trust_another_key() {
        let key = p256_v013::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let other = p256_v013::ecdsa::SigningKey::from_bytes((&[8u8; 32]).into()).unwrap();
        let cert = hoike_sign::generate_seal_cert(&key).unwrap();
        let wrong = hoike_sign::generate_seal_cert(&other).unwrap();
        let seal =
            hoike_sign::create_cms_seal(b"manifest", &hoike_sign::SealKey::EcdsaP256(key), &cert)
                .unwrap();
        assert!(verify_seal_with_pins(b"manifest", &seal, &[cert], 1_800_000_000).is_ok());
        assert!(verify_seal_with_pins(b"manifest", &seal, &[wrong], 1_800_000_000).is_err());
    }

    #[test]
    fn delta_materialization_supports_a_real_cms_sealing_callback() {
        let key = p256_v013::ecdsa::SigningKey::from_bytes((&[7u8; 32]).into()).unwrap();
        let cert = hoike_sign::generate_seal_cert(&key).unwrap();
        let seal_key = hoike_sign::SealKey::EcdsaP256(key);
        let mut builder = BundleBuilder::new(build_test_manifest());
        builder.add_entry([1; 32], b"fixture".to_vec());
        let base = Bundle::from_bytes(&builder.build(|_| Ok(Vec::new())).unwrap()).unwrap();
        let applied = ahu::ops::apply_sealed(&base, &[], |manifest| {
            hoike_sign::create_cms_seal(manifest, &seal_key, &cert)
                .map_err(|e| ahu::AhuError::Write(e.to_string()))
        })
        .unwrap();
        let result = Bundle::from_bytes(&applied.bytes).unwrap();
        assert!(
            verify_seal_with_pins(
                &result.manifest_bytes,
                &result.seal_bytes,
                &[cert],
                1_800_000_000
            )
            .is_ok()
        );
    }
}
