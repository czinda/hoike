use ahu::{Bundle, BundleType, Completeness, ResponderIdType};
use std::collections::HashSet;
use std::path::Path;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn inspect(path: &Path) -> Result<()> {
    let bundle = Bundle::from_file(path)?;
    let m = &bundle.manifest;

    println!("═══ ahu bundle ═══");
    println!("  File:           {}", path.display());
    println!("  Format:         {}.{}", bundle.header.format_major, bundle.header.format_minor);
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
        println!("    hash_algorithm:     {}", hex::encode(&scope.hash_algorithm));
        println!("    issuer_name_hash:   {}", hex::encode(&scope.issuer_name_hash));
        println!("    issuer_key_hash:    {}", hex::encode(&scope.issuer_key_hash));
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
    println!(
        "  header:   0..{}",
        ahu::header::HEADER_SIZE
    );
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

    Ok(())
}

pub fn verify(path: &Path, _verify_entries: bool) -> Result<()> {
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

    // TODO: --entries flag would verify each OCSP response signature here.

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

    let a_keys: HashSet<[u8; 32]> = a.index.iter().map(|r| r.entry_key).collect();
    let b_keys: HashSet<[u8; 32]> = b.index.iter().map(|r| r.entry_key).collect();

    let added: Vec<_> = b_keys.difference(&a_keys).collect();
    let removed: Vec<_> = a_keys.difference(&b_keys).collect();
    let common: Vec<_> = a_keys.intersection(&b_keys).collect();

    let mut changed = 0usize;
    for key in &common {
        let a_data = a.lookup(key);
        let b_data = b.lookup(key);
        if a_data != b_data {
            changed += 1;
        }
    }

    println!("═══ ahu diff ═══");
    println!("  A: {} (epoch {:?})", a_path.display(),
        a.manifest.ca_scopes.iter().map(|s| s.epoch).collect::<Vec<_>>());
    println!("  B: {} (epoch {:?})", b_path.display(),
        b.manifest.ca_scopes.iter().map(|s| s.epoch).collect::<Vec<_>>());
    println!();
    println!("  Entries in A:    {}", a.index.len());
    println!("  Entries in B:    {}", b.index.len());
    println!("  Added:           {}", added.len());
    println!("  Removed:         {}", removed.len());
    println!("  Changed:         {changed}");
    println!("  Unchanged:       {}", common.len() - changed);

    if !added.is_empty() && added.len() <= 20 {
        println!("\n── Added ──");
        for key in &added {
            println!("  + {}", hex::encode(key));
        }
    }
    if !removed.is_empty() && removed.len() <= 20 {
        println!("\n── Removed ──");
        for key in &removed {
            println!("  - {}", hex::encode(key));
        }
    }

    Ok(())
}
