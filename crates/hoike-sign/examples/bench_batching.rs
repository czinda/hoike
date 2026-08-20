use hoike_sign::{CaIdentity, CertIdCompat, CertificateStatus, GenerationConfig, StatusSnapshot};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::time::Instant;
use x509_cert::ext::pkix::CrlReason;

fn build_snapshot(n: usize) -> StatusSnapshot {
    let mut entries = BTreeMap::new();
    for i in 0..n {
        let serial = (i as u64 + 1).to_be_bytes().to_vec();
        if i % 10 == 0 {
            entries.insert(
                serial,
                CertificateStatus::Revoked {
                    revocation_time: 1700000000,
                    reason: Some(CrlReason::Unspecified),
                },
            );
        } else {
            entries.insert(serial, CertificateStatus::Good);
        }
    }
    StatusSnapshot {
        entries,
        this_update: 1700000000,
        next_update: Some(1700086400),
    }
}

fn main() {
    let cert_count: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    let ca = CaIdentity {
        label: "bench-ca".into(),
        issuer_name_der: b"CN=Benchmark CA,O=Hoike Bench".to_vec(),
        issuer_key_bytes: b"bench-ca-public-key-bytes-1234".to_vec(),
    };

    let snapshot = build_snapshot(cert_count);
    let secret = [7u8; 32];
    let mut signing_key = SigningKey::from_bytes((&secret).into()).expect("key");

    let bucket_sizes = [1, 2, 5, 10, 25, 50, 100];

    println!("Batching Benchmark ({cert_count} certificates, ECDSA P-256)");
    println!("═══════════════════════════════════════════════════════════════════════════");
    println!(
        "{:<8} {:>14} {:>12} {:>14} {:>10} {:>10}",
        "Bucket", "Bundle Size", "Per-Entry", "Data Section", "Savings", "Time"
    );
    println!(
        "{:<8} {:>14} {:>12} {:>14} {:>10} {:>10}",
        "------", "-----------", "---------", "------------", "-------", "------"
    );

    let mut baseline_size: Option<usize> = None;

    // Also collect CSV
    let mut csv_lines = Vec::new();
    csv_lines.push(
        "bucket_size,bundle_bytes,per_entry_bytes,data_section_bytes,savings_pct,time_ms"
            .to_string(),
    );

    for &bucket_size in &bucket_sizes {
        if bucket_size > cert_count {
            continue;
        }

        let config = GenerationConfig {
            producer_id: "bench".into(),
            certid_compat: CertIdCompat::Sha256Only,
            bucket_size,
            ..Default::default()
        };

        let start = Instant::now();
        let bundle_bytes = hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca,
            &snapshot,
            &config,
            &mut signing_key,
            |m| Ok(Sha256::digest(m).to_vec()),
            None,
        )
        .expect("bundle production failed");
        let elapsed = start.elapsed();

        let bundle = ahu::Bundle::from_bytes(&bundle_bytes).expect("bundle parse failed");
        let data_size = bundle.header.data_length as usize;
        let entry_count = bundle.index.len();
        let per_entry = data_size.checked_div(entry_count).unwrap_or(0);

        let total_size = bundle_bytes.len();
        if baseline_size.is_none() {
            baseline_size = Some(total_size);
        }
        let savings = baseline_size
            .map(|b| {
                if b > 0 {
                    ((b as f64 - total_size as f64) / b as f64 * 100.0) as i32
                } else {
                    0
                }
            })
            .unwrap_or(0);

        let time_ms = elapsed.as_millis();

        println!(
            "{:<8} {:>14} {:>12} {:>14} {:>9}% {:>8}ms",
            bucket_size,
            format_bytes(total_size),
            format_bytes(per_entry),
            format_bytes(data_size),
            savings,
            time_ms
        );

        csv_lines.push(format!(
            "{},{},{},{},{},{}",
            bucket_size, total_size, per_entry, data_size, savings, time_ms
        ));
    }

    println!();
    println!("CSV output:");
    for line in &csv_lines {
        println!("{line}");
    }
}

fn format_bytes(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1} MB", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1} KB", n as f64 / 1_000.0)
    } else {
        format!("{n} B")
    }
}
