use ahu::{Bundle, BundleBuilder, BundleType, Completeness, IndexFlags, ResponderIdType};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
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

    // Use (entry_key, discriminator) pairs to correctly handle dual-algorithm bundles
    // where the same entry_key appears with different discriminators.
    let a_keys: HashSet<([u8; 32], u16)> = a
        .index
        .iter()
        .map(|r| (r.entry_key, r.discriminator))
        .collect();
    let b_keys: HashSet<([u8; 32], u16)> = b
        .index
        .iter()
        .map(|r| (r.entry_key, r.discriminator))
        .collect();

    let added: Vec<_> = b_keys.difference(&a_keys).collect();
    let removed: Vec<_> = a_keys.difference(&b_keys).collect();
    let common: Vec<_> = a_keys.intersection(&b_keys).collect();

    let mut changed = 0usize;
    for (key, disc) in &common {
        let a_data = ahu::index::binary_search_with_discriminator(&a.index, key, *disc)
            .and_then(|idx| a.entry_at(idx));
        let b_data = ahu::index::binary_search_with_discriminator(&b.index, key, *disc)
            .and_then(|idx| b.entry_at(idx));
        if a_data != b_data {
            changed += 1;
        }
    }

    println!("═══ ahu diff ═══");
    println!(
        "  A: {} (epoch {:?})",
        a_path.display(),
        a.manifest
            .ca_scopes
            .iter()
            .map(|s| s.epoch)
            .collect::<Vec<_>>()
    );
    println!(
        "  B: {} (epoch {:?})",
        b_path.display(),
        b.manifest
            .ca_scopes
            .iter()
            .map(|s| s.epoch)
            .collect::<Vec<_>>()
    );
    println!();
    println!("  Entries in A:    {}", a.index.len());
    println!("  Entries in B:    {}", b.index.len());
    println!("  Added:           {}", added.len());
    println!("  Removed:         {}", removed.len());
    println!("  Changed:         {changed}");
    println!("  Unchanged:       {}", common.len() - changed);

    if !added.is_empty() && added.len() <= 20 {
        println!("\n── Added ──");
        for (key, disc) in &added {
            if *disc == 0 {
                println!("  + {}", hex::encode(key));
            } else {
                println!("  + {} (disc={})", hex::encode(key), disc);
            }
        }
    }
    if !removed.is_empty() && removed.len() <= 20 {
        println!("\n── Removed ──");
        for (key, disc) in &removed {
            if *disc == 0 {
                println!("  - {}", hex::encode(key));
            } else {
                println!("  - {} (disc={})", hex::encode(key), disc);
            }
        }
    }

    Ok(())
}

pub fn apply(
    base_path: &Path,
    delta_paths: &[std::path::PathBuf],
    output_path: &Path,
) -> Result<()> {
    println!("Loading base bundle: {}", base_path.display());
    let base = Bundle::from_file(base_path)?;
    ahu::verify_structure(&base)?;

    if base.manifest.bundle_type != BundleType::Full {
        return Err("base bundle must be a full bundle, not a delta".into());
    }

    // Build the working set from the base: (entry_key, discriminator) -> response bytes.
    // Using the (key, disc) pair ensures dual-algorithm entries are tracked separately.
    let mut working_set: BTreeMap<([u8; 32], u16), (Vec<u8>, IndexFlags)> = BTreeMap::new();
    for record in &base.index {
        if let Some(data) = base.entry_bytes(record) {
            working_set.insert(
                (record.entry_key, record.discriminator),
                (data.to_vec(), record.flags),
            );
        }
    }

    println!("  Base entries: {}", working_set.len());

    let base_manifest_digest = ahu::manifest_digest(&base.manifest_bytes);
    let mut prev_manifest_digest = base_manifest_digest;
    let mut max_epoch = base
        .manifest
        .ca_scopes
        .iter()
        .map(|s| s.epoch)
        .max()
        .unwrap_or(0);

    // Apply each delta in order
    for (i, delta_path) in delta_paths.iter().enumerate() {
        println!("Applying delta {}: {}", i + 1, delta_path.display());
        let delta = Bundle::from_file(delta_path)?;
        ahu::verify_structure(&delta)?;

        if delta.manifest.bundle_type != BundleType::Delta {
            return Err(format!(
                "expected delta bundle, got full bundle: {}",
                delta_path.display()
            )
            .into());
        }

        // Verify continuity chain
        if i == 0 {
            if let Some(ref base_digest) = delta.manifest.continuity.base_manifest_digest {
                if *base_digest != base_manifest_digest {
                    return Err(format!(
                        "delta {} base_manifest_digest does not match base bundle",
                        delta_path.display()
                    )
                    .into());
                }
            }
        }

        if let Some(ref prev_digest) = delta.manifest.continuity.prev_manifest_digest {
            if *prev_digest != prev_manifest_digest {
                return Err(format!(
                    "delta {} prev_manifest_digest chain broken (expected {}, got {})",
                    delta_path.display(),
                    hex::encode(prev_manifest_digest),
                    hex::encode(prev_digest),
                )
                .into());
            }
        }

        let chain_len = delta.manifest.continuity.chain_length;
        if chain_len > 24 {
            eprintln!(
                "  WARNING: chain_length {} exceeds recommended max (24)",
                chain_len
            );
        }

        let mut added = 0usize;
        let mut replaced = 0usize;
        let mut removed = 0usize;

        for record in &delta.index {
            let key = (record.entry_key, record.discriminator);
            if record.flags.contains(IndexFlags::TOMBSTONE) {
                if working_set.remove(&key).is_some() {
                    removed += 1;
                }
            } else if let Some(data) = delta.entry_bytes(record) {
                if working_set
                    .insert(key, (data.to_vec(), record.flags))
                    .is_some()
                {
                    replaced += 1;
                } else {
                    added += 1;
                }
            }
        }

        println!(
            "  Applied: +{added} ~{replaced} -{removed} → {} entries",
            working_set.len()
        );

        // Advance epoch tracking
        for scope in &delta.manifest.ca_scopes {
            max_epoch = max_epoch.max(scope.epoch);
        }

        prev_manifest_digest = ahu::manifest_digest(&delta.manifest_bytes);
    }

    // Build the materialized full bundle
    let mut manifest = base.manifest.clone();
    manifest.bundle_type = BundleType::Full;
    manifest.continuity.chain_length = 0;
    manifest.continuity.prev_manifest_digest = Some(prev_manifest_digest);
    manifest.continuity.base_manifest_digest = None;

    // Advance epochs to the max seen
    for scope in &mut manifest.ca_scopes {
        scope.epoch = max_epoch + 1;
    }

    let mut builder = BundleBuilder::new(manifest);

    for ((entry_key, disc), (data, _flags)) in &working_set {
        builder.add_entry_with_discriminator(*entry_key, *disc, data.clone());
    }

    let output_bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec()))?;

    std::fs::write(output_path, &output_bytes)?;
    println!(
        "\nWrote materialized bundle: {} ({} bytes, {} entries)",
        output_path.display(),
        output_bytes.len(),
        working_set.len()
    );

    Ok(())
}
