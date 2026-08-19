use ahu::*;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn main() {
    let manifest = Manifest {
        format_version: 1,
        bundle_id: Uuid::from_bytes([
            0x01, 0x92, 0xf3, 0xc8, 0x00, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ]),
        producer_id: "signer-a.pki.example".into(),
        created_at: 1700000000,
        bundle_type: BundleType::Full,
        ca_scopes: vec![CaScope {
            hash_algorithm: vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
            issuer_name_hash: Sha256::digest(b"CN=Enterprise Issuing CA 01,O=Example Corp")
                .to_vec(),
            issuer_key_hash: Sha256::digest(b"fake-issuer-public-key").to_vec(),
            epoch: 4417,
            responder_id: ResponderId {
                id_type: ResponderIdType::ByKey,
                value: Sha256::digest(b"fake-responder-public-key")[..20].to_vec(),
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

    for serial in 0u64..25 {
        let certid = format!("serial:{serial:032x}");
        let entry_key = compute_entry_key(certid.as_bytes());
        let response = format!("MOCK-OCSP-RESPONSE-serial-{serial:08}").into_bytes();
        builder.add_entry(entry_key, response);
    }

    let bytes = builder
        .build(|m| Ok(Sha256::digest(m).to_vec()))
        .expect("build failed");

    let path = std::env::args().nth(1).unwrap_or_else(|| "test.ahu".into());
    std::fs::write(&path, &bytes).expect("write failed");
    eprintln!("Wrote {} bytes to {path}", bytes.len());
}
