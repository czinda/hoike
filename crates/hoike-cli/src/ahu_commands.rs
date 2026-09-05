use ahu::{Bundle, BundleType, Completeness, ResponderIdType};
use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn inspect(path: &Path) -> Result<()> {
    let bundle = Bundle::from_file(path)?;
    let m = &bundle.manifest;

    println!("═══ ahu bundle ═══");
    println!("  File:           {}", path.display());
    println!(
        "  Format:         {}.{}",
        bundle.header.format_major, bundle.header.format_minor
    );
    println!("  Bundle ID:      {}", m.bundle_id);
    println!("  Producer:       {}", m.producer_id);
    println!("  Created:        {} (epoch)", m.created_at);
    println!(
        "  Type:           {}",
        match m.bundle_type {
            BundleType::Full => "full",
            BundleType::Delta => "delta",
        }
    );
    println!("  Entry count:    {}", m.entry_count);
    println!("  Index records:  {}", bundle.index.len());

    println!("\n── Window ──");
    println!("  produced_at:      {}", m.window.produced_at);
    println!("  this_update_min:  {}", m.window.this_update_min);
    println!("  next_update_min:  {}", m.window.next_update_min);
    println!("  next_update_max:  {}", m.window.next_update_max);

    println!("\n── Integrity ──");
    println!("  index_digest: {}", hex::encode(m.integrity.index_digest));
    println!("  data_digest:  {}", hex::encode(m.integrity.data_digest));

    println!("\n── Continuity ──");
    println!("  chain_length: {}", m.continuity.chain_length);
    if let Some(prev) = &m.continuity.prev_manifest_digest {
        println!("  prev_manifest_digest: {}", hex::encode(prev));
    }
    if let Some(base) = &m.continuity.base_manifest_digest {
        println!("  base_manifest_digest: {}", hex::encode(base));
    }

    println!("\n── CA Scopes ({}) ──", m.ca_scopes.len());
    for (i, scope) in m.ca_scopes.iter().enumerate() {
        println!("  [{}]", i);
        println!(
            "    hash_algorithm:     {}",
            hex::encode(&scope.hash_algorithm)
        );
        println!(
            "    issuer_name_hash:   {}",
            hex::encode(&scope.issuer_name_hash)
        );
        println!(
            "    issuer_key_hash:    {}",
            hex::encode(&scope.issuer_key_hash)
        );
        println!("    epoch:              {}", scope.epoch);
        println!(
            "    responder_id:       {} ({})",
            hex::encode(&scope.responder_id.value),
            match scope.responder_id.id_type {
                ResponderIdType::ByName => "byName",
                ResponderIdType::ByKey => "byKey",
            }
        );
        println!(
            "    signature_alg:      {}",
            hex::encode(&scope.signature_algorithm)
        );
        println!(
            "    completeness:       {}",
            match scope.completeness {
                Completeness::Partial => "partial",
                Completeness::AuthoritativeComplete => "authoritative-complete",
            }
        );
        if let Some(chain) = &scope.responder_chain {
            println!("    responder_chain:    {} cert(s)", chain.len());
        }
    }

    if let Some(shard) = &m.shard {
        println!("\n── Shard ──");
        println!("  index: {} of {}", shard.shard_index, shard.shard_count);
        println!("  function: {}", shard.shard_fn);
    }

    if let Some(comp) = &m.compression {
        println!("\n── Compression ──");
        println!(
            "  algorithm: {}",
            match comp.algorithm {
                ahu::CompressionAlgorithm::None => "none",
                ahu::CompressionAlgorithm::Zstd => "zstd",
            }
        );
        if let Some(dict) = &comp.dictionary_digest {
            println!("  dictionary: {}", hex::encode(dict));
        }
    }

    println!("\n── Layout ──");
    println!("  header:   0..{}", ahu::header::HEADER_SIZE);
    println!(
        "  manifest: {}..{} ({} bytes)",
        bundle.header.manifest_offset,
        bundle.header.manifest_offset + bundle.header.manifest_length as u64,
        bundle.header.manifest_length
    );
    println!(
        "  seal:     {}..{} ({} bytes)",
        bundle.header.seal_offset,
        bundle.header.seal_offset + bundle.header.seal_length as u64,
        bundle.header.seal_length
    );
    println!(
        "  index:    {}..{} ({} bytes, {} records)",
        bundle.header.index_offset,
        bundle.header.index_offset + bundle.header.index_length,
        bundle.header.index_length,
        bundle.index.len()
    );
    println!(
        "  data:     {}..{} ({} bytes)",
        bundle.header.data_offset,
        bundle.header.data_offset + bundle.header.data_length,
        bundle.header.data_length
    );

    let mut disc_counts: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
    for record in &bundle.index {
        *disc_counts.entry(record.discriminator).or_default() += 1;
    }
    if disc_counts.len() > 1 || disc_counts.keys().any(|&k| k != 0) {
        println!("\n── Discriminators ──");
        for (disc, count) in &disc_counts {
            let name = match *disc {
                0 => "default/classical",
                2 => "ML-DSA-44",
                3 => "ML-DSA-65",
                4 => "ML-DSA-87",
                _ => "unknown",
            };
            println!("  disc={disc}: {count} entries ({name})");
        }
    }

    Ok(())
}

pub fn verify(path: &Path, verify_entries: bool) -> Result<()> {
    let bundle = Bundle::from_file(path)?;

    println!("Verifying {}...", path.display());

    let result = ahu::verify_structure(&bundle)?;

    println!("  Header:           OK");
    println!("  Manifest parse:   OK");
    println!(
        "  Index digest:     {}",
        if result.index_digest_ok { "OK" } else { "FAIL" }
    );
    println!(
        "  Data digest:      {}",
        if result.data_digest_ok { "OK" } else { "FAIL" }
    );
    println!(
        "  Sort order:       {}",
        if result.sort_order_ok { "OK" } else { "FAIL" }
    );
    println!(
        "  Entry bounds:     {}",
        if result.entry_bounds_ok { "OK" } else { "FAIL" }
    );
    println!(
        "  Entry count:      {}",
        if result.entry_count_matches {
            "OK".to_string()
        } else {
            format!(
                "MISMATCH (manifest says {}, index has {})",
                bundle.manifest.entry_count,
                bundle.index.len()
            )
        }
    );
    println!(
        "  Seal present:     {}",
        if result.seal_present { "yes" } else { "NO" }
    );

    for warning in &result.warnings {
        println!("  WARNING: {warning}");
    }

    let manifest_hash = ahu::manifest_digest(&bundle.manifest_bytes);
    println!("\n  Manifest digest: {}", hex::encode(manifest_hash));

    if verify_entries {
        println!("\n── Entry signature verification ──");
        let mut verified = 0usize;
        let mut failed = 0usize;
        let mut skipped = 0usize;
        let mut missing = 0usize;
        for record in &bundle.index {
            if record.is_tombstone() {
                continue;
            }
            if let Some(entry_bytes) = bundle.entry_bytes(record) {
                match hoike_sign::verify_ocsp_response_signature(entry_bytes) {
                    Ok(()) => verified += 1,
                    Err(hoike_sign::SignError::NoCert) => {
                        skipped += 1;
                    }
                    Err(e) => {
                        eprintln!("  FAIL: {} — {e}", hex::encode(&record.entry_key[..8]));
                        failed += 1;
                    }
                }
            } else {
                eprintln!("  MISSING DATA: {}", hex::encode(&record.entry_key[..8]));
                missing += 1;
            }
        }
        let total = verified + failed + skipped + missing;
        println!("  Total entries:    {total}");
        println!("  Verified:         {verified}");
        if skipped > 0 {
            println!("  Skipped:          {skipped} (no embedded responder cert)");
        }
        if missing > 0 {
            println!("  Missing data:     {missing}");
        }
        if failed > 0 || missing > 0 {
            println!("  FAILED:           {failed}");
            return Err("entry signature verification failed".into());
        }
        if verified == 0 && total > 0 {
            println!("\n  WARNING: no entries had embedded certs — zero signatures verified");
        }
    }

    // Discriminator distribution (show before final verdict)
    let mut disc_counts: std::collections::BTreeMap<u16, usize> = std::collections::BTreeMap::new();
    for record in &bundle.index {
        *disc_counts.entry(record.discriminator).or_default() += 1;
    }
    if disc_counts.len() > 1 || disc_counts.keys().any(|&k| k != 0) {
        println!("\n── Discriminators ──");
        for (disc, count) in &disc_counts {
            let name = match *disc {
                0 => "default/classical",
                2 => "ML-DSA-44",
                3 => "ML-DSA-65",
                4 => "ML-DSA-87",
                _ => "unknown",
            };
            println!("  disc={disc}: {count} entries ({name})");
        }
    }

    println!("\nVerification passed.");
    Ok(())
}

pub fn extract(path: &Path, certid_hex: &str, output: Option<&Path>) -> Result<()> {
    let bundle = Bundle::from_file(path)?;

    let key_bytes = hex::decode(certid_hex)?;
    if key_bytes.len() != 32 {
        return Err(format!(
            "entry key must be 32 bytes (64 hex chars), got {} bytes",
            key_bytes.len()
        )
        .into());
    }
    let mut entry_key = [0u8; 32];
    entry_key.copy_from_slice(&key_bytes);

    match bundle.lookup(&entry_key) {
        Some(response_bytes) => {
            if let Some(out_path) = output {
                std::fs::write(out_path, response_bytes)?;
                println!(
                    "Extracted {} bytes to {}",
                    response_bytes.len(),
                    out_path.display()
                );
            } else {
                println!("{}", hex::encode(response_bytes));
            }
            Ok(())
        }
        None => {
            eprintln!("No entry found for key {certid_hex}");
            std::process::exit(1);
        }
    }
}

pub fn diff(a_path: &Path, b_path: &Path) -> Result<()> {
    let a = Bundle::from_file(a_path)?;
    let b = Bundle::from_file(b_path)?;

    let d = ahu::diff(&a, &b);

    println!("═══ ahu diff ═══");
    println!("  A: {} (epoch {:?})", a_path.display(), d.a_epochs);
    println!("  B: {} (epoch {:?})", b_path.display(), d.b_epochs);
    println!();
    println!("  Entries in A:    {}", d.a_entry_count);
    println!("  Entries in B:    {}", d.b_entry_count);
    println!("  Added:           {}", d.added.len());
    println!("  Removed:         {}", d.removed.len());
    println!("  Changed:         {}", d.changed.len());
    println!("  Unchanged:       {}", d.unchanged);

    let print_refs = |label: &str, sign: char, refs: &[ahu::EntryRef]| {
        if !refs.is_empty() && refs.len() <= 20 {
            println!("\n── {label} ──");
            for r in refs {
                if r.discriminator == 0 {
                    println!("  {sign} {}", hex::encode(r.entry_key));
                } else {
                    println!(
                        "  {sign} {} (disc={})",
                        hex::encode(r.entry_key),
                        r.discriminator
                    );
                }
            }
        }
    };
    print_refs("Added", '+', &d.added);
    print_refs("Removed", '-', &d.removed);

    Ok(())
}

pub fn apply(
    base_path: &Path,
    delta_paths: &[std::path::PathBuf],
    output_path: &Path,
    seal_key_path: Option<&Path>,
    seal_cert_path: Option<&Path>,
    input_signer_pins: &[std::path::PathBuf],
) -> Result<()> {
    if seal_key_path.is_some() != seal_cert_path.is_some() {
        return Err("--seal-key and --seal-cert must be supplied together".into());
    }
    if seal_key_path.is_some() && input_signer_pins.is_empty() {
        return Err(
            "signed output requires --input-signer-pin to authenticate every input bundle".into(),
        );
    }
    println!("Loading base bundle: {}", base_path.display());
    let base = Bundle::from_file(base_path)?;
    ahu::verify_structure(&base)?;

    let mut deltas = Vec::with_capacity(delta_paths.len());
    for (i, delta_path) in delta_paths.iter().enumerate() {
        println!("Loading delta {}: {}", i + 1, delta_path.display());
        let delta = Bundle::from_file(delta_path)?;
        ahu::verify_structure(&delta)?;
        deltas.push(delta);
    }

    let result = if let (Some(key_path), Some(cert_path)) = (seal_key_path, seal_cert_path) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let pins = input_signer_pins
            .iter()
            .map(|path| read_certificate(path))
            .collect::<Result<Vec<_>>>()?;
        for bundle in std::iter::once(&base).chain(deltas.iter()) {
            ahu::verify_seal_with_pins(&bundle.manifest_bytes, &bundle.seal_bytes, &pins, now)?;
        }
        let key = hoike_sign::SealKey::EcdsaP256(hoike_sign::load_ecdsa_p256_key(key_path)?);
        let cert = read_certificate(cert_path)?;
        let applied = ahu::ops::apply_sealed(&base, &deltas, |manifest| {
            hoike_sign::create_cms_seal(manifest, &key, &cert)
                .map_err(|e| ahu::AhuError::SealInvalid(e.to_string()))
        })?;
        let output = Bundle::from_bytes(&applied.bytes)?;
        // Reject mismatched keys, expired certificates and disallowed key usage
        // before publishing any bytes to the destination.
        ahu::verify_seal_with_pins(&output.manifest_bytes, &output.seal_bytes, &[cert], now)?;
        println!(
            "Output status: CMS sealed; configure the signer in the destination trust policy."
        );
        applied
    } else {
        eprintln!(
            "WARNING: output is an UNSIGNED INTERMEDIATE. Seal with an authorized key before trusted installation."
        );
        ahu::apply(&base, &deltas)?
    };

    for (i, stat) in result.deltas.iter().enumerate() {
        if stat.chain_length_warning {
            eprintln!(
                "  WARNING: delta {} chain_length exceeds recommended max ({})",
                i + 1,
                ahu::ops::MAX_CHAIN_LENGTH
            );
        }
        println!(
            "  Delta {}: +{} ~{} -{}",
            i + 1,
            stat.added,
            stat.replaced,
            stat.removed
        );
    }

    hoike_sign::orchestrate::write_bundle_atomic(output_path, &result.bytes)
        .map_err(std::io::Error::other)?;
    println!(
        "\nWrote materialized bundle: {} ({} bytes, {} entries, epoch {})",
        output_path.display(),
        result.bytes.len(),
        result.entry_count,
        result.final_epoch,
    );

    Ok(())
}

fn read_certificate(path: &Path) -> Result<Vec<u8>> {
    use der::{Decode, DecodePem, Encode};
    let bytes = std::fs::read(path)?;
    let cert = if bytes.starts_with(b"-----BEGIN") {
        x509_cert::Certificate::from_pem(&bytes)?
    } else {
        x509_cert::Certificate::from_der(&bytes)?
    };
    Ok(cert.to_der()?)
}
