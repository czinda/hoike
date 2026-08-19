use clap::Parser;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(
    name = "hoike",
    about = "hoike — OCSP responder for pre-signed ahu bundles"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Start the OCSP responder
    Serve {
        /// Config file path
        #[arg(long, default_value = "hoike.toml")]
        config: PathBuf,
    },
    /// Validate configuration, bundle, and connectivity
    Check {
        /// Config file path
        #[arg(long, default_value = "hoike.toml")]
        config: PathBuf,
    },
    /// Produce a signed ahu bundle from a revocation source
    Sign {
        /// CA label
        #[arg(long)]
        ca: String,
        /// CRL file to ingest (DER or PEM)
        #[arg(long)]
        crl: PathBuf,
        /// Output bundle path
        #[arg(short, long, default_value = "output.ahu")]
        output: PathBuf,
        /// Issuer certificate (DER) for CertID computation
        #[arg(long)]
        issuer: Option<PathBuf>,
        /// Epoch number for this generation
        #[arg(long, default_value = "1")]
        epoch: u64,
        /// CertID compatibility mode
        #[arg(long, default_value = "dual")]
        certid_compat: String,
        /// Include known-good serials from a file (one hex serial per line)
        #[arg(long)]
        good_serials: Option<PathBuf>,
        /// Signing algorithm: ecdsa-p256 (default), ml-dsa-44, ml-dsa-65, ml-dsa-87
        #[arg(long, default_value = "ecdsa-p256")]
        sig_alg: String,
        /// Base64-encoded DER issuer name (for correct CertID hashes)
        #[arg(long)]
        issuer_name_b64: Option<String>,
        /// Base64-encoded issuer public key bytes (for correct CertID hashes)
        #[arg(long)]
        issuer_key_b64: Option<String>,
    },
    /// Import a bundle into the responder's bundle directory (for enclave/air-gap deployments)
    Import {
        /// Path to the .ahu bundle to import
        #[arg(long)]
        bundle: PathBuf,
        /// Config file (to determine bundle_dir)
        #[arg(long, default_value = "hoike.toml")]
        config: PathBuf,
        /// Skip anti-rollback check (for first import into a fresh enclave)
        #[arg(long)]
        force: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,tower_http=debug".parse().unwrap()),
        )
        .init();

    match cli.command {
        Commands::Serve { config } => {
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(run_server(config));
        }
        Commands::Check { config } => {
            run_check(config);
        }
        Commands::Sign {
            ca,
            crl,
            output,
            issuer: _,
            epoch,
            certid_compat,
            good_serials,
            sig_alg,
            issuer_name_b64,
            issuer_key_b64,
        } => {
            run_sign(
                ca,
                crl,
                output,
                epoch,
                certid_compat,
                good_serials,
                sig_alg,
                issuer_name_b64,
                issuer_key_b64,
            );
        }
        Commands::Import {
            bundle,
            config,
            force,
        } => {
            run_import(bundle, config, force);
        }
    }
}

async fn run_server(config_path: PathBuf) {
    let config = hoike_core::Config::from_file(&config_path).unwrap_or_else(|e| {
        eprintln!("Failed to load config from {}: {e}", config_path.display());
        std::process::exit(1);
    });

    if let Err(e) = config.validate_for_mode() {
        eprintln!("Configuration error: {e}");
        std::process::exit(1);
    }

    let listen = config.server.listen.clone();
    let is_combined = config.is_combined();

    // In combined mode, run an initial signing pass before loading bundles
    // so there's something to serve immediately.
    if is_combined {
        info!("combined mode: running initial bundle production");
        if let Err(e) = run_signer_pass(&config) {
            eprintln!("Initial signer pass failed: {e}");
            std::process::exit(1);
        }
    }

    let state = hoike_core::ResponderState::load(config.clone()).unwrap_or_else(|e| {
        eprintln!("Failed to initialize responder: {e}");
        std::process::exit(1);
    });

    let app_state = hoike_server::AppState::new(state);

    // In combined mode, start the background signer loop
    if is_combined {
        let signer_state = app_state.responder.clone();
        let signer_config = config.clone();
        tokio::spawn(async move {
            run_signer_loop(signer_state, signer_config).await;
        });
    }

    // Start gossip if enabled
    if let Some(gossip_cfg) = &config.gossip {
        if gossip_cfg.enabled {
            let (msg_tx, mut msg_rx) =
                tokio::sync::mpsc::channel::<hoike_gossip::GossipMessage>(256);

            let gc = hoike_gossip::GossipConfig {
                enabled: true,
                bind: gossip_cfg.bind.clone(),
                seeds: gossip_cfg.seeds.clone(),
                node_name: gossip_cfg.node_name.clone(),
            };

            match hoike_gossip::GossipNode::start(gc, msg_tx).await {
                Ok(_gossip_node) => {
                    info!("gossip node started");
                    let _responder = app_state.responder.clone();
                    tokio::spawn(async move {
                        while let Some(msg) = msg_rx.recv().await {
                            match &msg {
                                hoike_gossip::GossipMessage::GenerationAnnouncement {
                                    producer_id,
                                    epoch,
                                    bundle_url,
                                    ..
                                } => {
                                    info!(
                                        producer = %producer_id,
                                        epoch,
                                        url = bundle_url.as_deref().unwrap_or("none"),
                                        "received generation announcement — would pull bundle from peer"
                                    );
                                    // In a full implementation: fetch bundle from bundle_url,
                                    // verify anti-rollback, swap into router via responder.reload()
                                }
                                hoike_gossip::GossipMessage::UrgentRevocation {
                                    producer_id,
                                    epoch,
                                    ..
                                } => {
                                    info!(
                                        producer = %producer_id,
                                        epoch,
                                        "received urgent revocation notice — would pull delta"
                                    );
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!(error = %e, "gossip startup failed, continuing without gossip");
                }
            }
        }
    }

    let app = hoike_server::build_router(app_state);

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to bind to {listen}: {e}");
            std::process::exit(1);
        });

    info!(listen = %listen, mode = config.server.mode, "hoike OCSP responder starting");
    axum::serve(listener, app).await.unwrap();
}

fn run_signer_pass(config: &hoike_core::Config) -> std::result::Result<(), String> {
    use hoike_sign::{CaIdentity, CrlSource, GenerationConfig, RevocationSource};
    use p256::ecdsa::SigningKey;
    use sha2_v010::{Digest, Sha256};

    for ca_config in &config.ca {
        let source_config = match &ca_config.source {
            Some(s) => s,
            None => continue,
        };

        let source: Box<dyn RevocationSource> = match source_config {
            hoike_core::config::SourceConfig::Crl { path } => {
                let crl_data = std::fs::read(path)
                    .map_err(|e| format!("failed to read CRL {}: {e}", path.display()))?;
                if crl_data.starts_with(b"-----BEGIN") {
                    let pem = String::from_utf8(crl_data)
                        .map_err(|e| format!("CRL not valid UTF-8: {e}"))?;
                    Box::new(CrlSource::from_pem(&pem).map_err(|e| format!("CRL parse: {e}"))?)
                } else {
                    Box::new(CrlSource::from_der(crl_data).map_err(|e| format!("CRL parse: {e}"))?)
                }
            }
        };

        let ca = CaIdentity {
            label: ca_config.label.clone(),
            issuer_name_der: decode_issuer_name(ca_config)?,
            issuer_key_bytes: decode_issuer_key(ca_config)?,
        };

        let snapshot = source
            .snapshot(&ca)
            .map_err(|e| format!("snapshot failed for {}: {e}", ca_config.label))?;

        // Derive epoch from persisted high-water mark — never from wall-clock
        // time, which can step backward (NTP correction, VM restore) and
        // permanently lock out mirrors.
        let epoch = {
            let state_db_path = config.storage.state_db.join("state.json");
            let store = hoike_core::StateStore::open(&state_db_path)
                .map_err(|e| format!("state store: {e}"))?;
            let issuer_key_hash_hex = hex::encode(sha2_v010::Sha256::digest(&ca.issuer_key_bytes));
            store
                .get_high_water("hoike-combined", &issuer_key_hash_hex)
                .unwrap_or(0)
                .saturating_add(1)
        };

        let gen_config = GenerationConfig {
            producer_id: "hoike-combined".into(),
            epoch,
            validity_secs: ca_config.validity_secs,
            certid_compat: hoike_sign::CertIdCompat::Dual,
            ..Default::default()
        };

        // Ephemeral signing key — production would load from config
        let secret = [42u8; 32];
        let mut signing_key =
            SigningKey::from_bytes((&secret).into()).expect("invalid signing key");

        warn!(
            ca = ca_config.label,
            "using ephemeral signing key — not for production"
        );

        let bundle_bytes = hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
            &ca,
            &snapshot,
            &gen_config,
            &mut signing_key,
            |m| Ok(Sha256::digest(m).to_vec()),
        )
        .map_err(|e| format!("bundle production failed for {}: {e}", ca_config.label))?;

        let bundle_path = config
            .storage
            .bundle_dir
            .join(format!("{}.ahu", ca_config.label));

        std::fs::create_dir_all(&config.storage.bundle_dir)
            .map_err(|e| format!("create bundle_dir: {e}"))?;

        std::fs::write(&bundle_path, &bundle_bytes).map_err(|e| format!("write bundle: {e}"))?;

        info!(
            ca = ca_config.label,
            size = bundle_bytes.len(),
            path = %bundle_path.display(),
            entries = snapshot.entries.len(),
            "bundle produced"
        );
    }

    Ok(())
}

async fn run_signer_loop(state: Arc<hoike_core::ResponderState>, config: hoike_core::Config) {
    let min_interval = config
        .ca
        .iter()
        .map(|c| c.batch_interval)
        .min()
        .unwrap_or(3600);

    info!(
        interval_secs = min_interval,
        "combined mode: signer loop starting"
    );

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(min_interval)).await;

        info!("signer loop: starting production cycle");
        match run_signer_pass(&config) {
            Ok(()) => {
                if let Err(e) = state.reload() {
                    error!(error = %e, "signer loop: reload failed after production");
                } else {
                    info!("signer loop: bundles produced and reloaded");
                }
            }
            Err(e) => {
                error!(error = %e, "signer loop: production failed");
            }
        }
    }
}

fn decode_b64_field(
    b64: &Option<String>,
    field_name: &str,
    ca_label: &str,
    fallback: &str,
) -> std::result::Result<Vec<u8>, String> {
    match b64 {
        Some(val) => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(val)
                .map_err(|e| format!("CA '{}': invalid base64 in {}: {e}", ca_label, field_name))
        }
        None => Ok(fallback.as_bytes().to_vec()),
    }
}

fn decode_issuer_name(ca: &hoike_core::config::CaConfig) -> std::result::Result<Vec<u8>, String> {
    decode_b64_field(
        &ca.issuer_name_der_b64,
        "issuer_name_der_b64",
        &ca.label,
        &format!("CN={}", ca.label),
    )
}

fn decode_issuer_key(ca: &hoike_core::config::CaConfig) -> std::result::Result<Vec<u8>, String> {
    decode_b64_field(
        &ca.issuer_key_bytes_b64,
        "issuer_key_bytes_b64",
        &ca.label,
        &format!("{}-key", ca.label),
    )
}

fn run_import(bundle_path: PathBuf, config_path: PathBuf, force: bool) {
    let config = match hoike_core::Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to load config from {}: {e}", config_path.display());
            std::process::exit(1);
        }
    };

    println!("Loading bundle: {}", bundle_path.display());
    let bundle = match ahu::Bundle::from_file(&bundle_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to load bundle: {e}");
            std::process::exit(1);
        }
    };

    println!("Verifying structure...");
    match ahu::verify_structure(&bundle) {
        Ok(result) => {
            if !result.warnings.is_empty() {
                for w in &result.warnings {
                    eprintln!("  WARNING: {w}");
                }
            }
            println!("  Structure:  OK");
        }
        Err(e) => {
            eprintln!("  Structure:  FAIL — {e}");
            std::process::exit(1);
        }
    }

    if !force {
        let state_store =
            match hoike_core::StateStore::open(&config.storage.state_db.join("state.json")) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("  Anti-rollback: FAIL — cannot open state store: {e}");
                    std::process::exit(1);
                }
            };
        if let Err(e) = state_store.check_rollback(&bundle) {
            eprintln!("  Anti-rollback: REJECTED — {e}");
            eprintln!("  Use --force to skip this check (e.g., first import into an enclave)");
            std::process::exit(1);
        }
        println!("  Anti-rollback: OK");
    } else {
        println!("  Anti-rollback: SKIPPED (--force)");
    }

    let bundle_dir = &config.storage.bundle_dir;
    if let Err(e) = std::fs::create_dir_all(bundle_dir) {
        eprintln!(
            "Failed to create bundle directory {}: {e}",
            bundle_dir.display()
        );
        std::process::exit(1);
    }

    let dest_filename = bundle_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("imported.ahu"));
    let dest_path = bundle_dir.join(dest_filename);

    if let Err(e) = std::fs::copy(&bundle_path, &dest_path) {
        eprintln!("Failed to copy bundle to {}: {e}", dest_path.display());
        std::process::exit(1);
    }

    println!(
        "\n  Imported {} → {}",
        bundle_path.display(),
        dest_path.display()
    );
    println!("  Producer:  {}", bundle.manifest.producer_id);
    println!("  Entries:   {}", bundle.manifest.entry_count);
    println!("  Scopes:    {}", bundle.manifest.ca_scopes.len());
    for (i, scope) in bundle.manifest.ca_scopes.iter().enumerate() {
        println!("    [{}] epoch={}", i, scope.epoch);
    }
    println!(
        "\n  To serve: hoike serve --config {}",
        config_path.display()
    );
    println!("  To reload a running server: send SIGHUP (not yet implemented)");
}

fn run_check(config_path: PathBuf) {
    let config = match hoike_core::Config::from_file(&config_path) {
        Ok(c) => {
            println!("  Config:    OK ({})", config_path.display());
            c
        }
        Err(e) => {
            eprintln!("  Config:    FAIL — {e}");
            std::process::exit(1);
        }
    };

    println!("  Mode:      {}", config.server.mode);
    println!("  Listen:    {}", config.server.listen);
    println!("  Bundle:    {}", config.storage.bundle_dir.display());

    if let Err(e) = config.validate_for_mode() {
        eprintln!("  Mode:      FAIL — {e}");
        std::process::exit(1);
    }

    match hoike_core::ResponderState::load(config) {
        Ok(state) => {
            println!("  Bundles:   {}", state.bundle_count());
            println!("  Scopes:    {}", state.scope_count());
            println!("  Entries:   {}", state.total_entries());
            for (label, epoch, completeness) in state.scope_info() {
                println!("    [{label}] epoch={epoch} completeness={completeness}");
            }
            println!("\n  All checks passed.");
        }
        Err(e) => {
            eprintln!("  Bundle:    FAIL — {e}");
            std::process::exit(1);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_sign(
    ca_label: String,
    crl_path: PathBuf,
    output: PathBuf,
    epoch: u64,
    certid_compat: String,
    good_serials: Option<PathBuf>,
    sig_alg: String,
    issuer_name_b64: Option<String>,
    issuer_key_b64: Option<String>,
) {
    use hoike_sign::{
        CaIdentity, CertIdCompat, CertificateStatus, CrlSource, GenerationConfig, RevocationSource,
    };
    use sha2_v010::{Digest, Sha256};

    let compat = match certid_compat.as_str() {
        "dual" => CertIdCompat::Dual,
        "sha256" => CertIdCompat::Sha256Only,
        "sha1" => CertIdCompat::Sha1Only,
        other => {
            eprintln!("Unknown certid_compat: {other} (expected: dual, sha256, sha1)");
            std::process::exit(1);
        }
    };

    let crl_data = std::fs::read(&crl_path).unwrap_or_else(|e| {
        eprintln!("Failed to read CRL from {}: {e}", crl_path.display());
        std::process::exit(1);
    });

    let source = if crl_data.starts_with(b"-----BEGIN") {
        let pem = String::from_utf8(crl_data).unwrap_or_else(|e| {
            eprintln!("CRL file is not valid UTF-8: {e}");
            std::process::exit(1);
        });
        CrlSource::from_pem(&pem).unwrap_or_else(|e| {
            eprintln!("Failed to parse PEM CRL: {e}");
            std::process::exit(1);
        })
    } else {
        CrlSource::from_der(crl_data).unwrap_or_else(|e| {
            eprintln!("Failed to parse DER CRL: {e}");
            std::process::exit(1);
        })
    };

    let issuer_name_der = decode_b64_field(
        &issuer_name_b64,
        "issuer_name_b64",
        &ca_label,
        &format!("CN={ca_label}"),
    )
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    if issuer_name_b64.is_none() {
        warn!(
            ca = ca_label,
            "no --issuer-name-b64 provided — using synthetic placeholder. \
             CertID hashes will not match real client requests."
        );
    }

    let issuer_key_bytes = decode_b64_field(
        &issuer_key_b64,
        "issuer_key_b64",
        &ca_label,
        &format!("{ca_label}-key"),
    )
    .unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });

    let ca = CaIdentity {
        label: ca_label.clone(),
        issuer_name_der,
        issuer_key_bytes,
    };

    let mut snapshot = source.snapshot(&ca).unwrap_or_else(|e| {
        eprintln!("Failed to snapshot CRL: {e}");
        std::process::exit(1);
    });

    if let Some(good_path) = good_serials {
        let content = std::fs::read_to_string(&good_path).unwrap_or_else(|e| {
            eprintln!(
                "Failed to read good serials from {}: {e}",
                good_path.display()
            );
            std::process::exit(1);
        });
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match hex::decode(line) {
                Ok(serial) => {
                    snapshot
                        .entries
                        .entry(serial)
                        .or_insert(CertificateStatus::Good);
                }
                Err(e) => {
                    eprintln!("Warning: invalid hex serial '{line}': {e}");
                }
            }
        }
    }

    info!(
        ca = ca_label,
        revoked = snapshot.entries.values().filter(|s| matches!(s, CertificateStatus::Revoked { .. })).count(),
        good = snapshot.entries.values().filter(|s| matches!(s, CertificateStatus::Good)).count(),
        sig_alg = %sig_alg,
        "snapshot loaded"
    );

    let config = GenerationConfig {
        producer_id: "hoike-cli".into(),
        epoch,
        certid_compat: compat,
        ..Default::default()
    };

    let seed = [42u8; 32];
    let seal_fn = |m: &[u8]| -> hoike_sign::Result<Vec<u8>> { Ok(Sha256::digest(m).to_vec()) };

    let bundle_bytes = match sig_alg.as_str() {
        "ecdsa-p256" => {
            let mut signer =
                p256::ecdsa::SigningKey::from_bytes((&seed).into()).expect("invalid ECDSA key");
            hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
                &ca,
                &snapshot,
                &config,
                &mut signer,
                seal_fn,
            )
        }
        "ml-dsa-44" => {
            let mut signer = hoike_sign::ml_dsa_44_signer(&seed);
            hoike_sign::produce_bundle::<_, hoike_sign::MlDsaSignatureBytes>(
                &ca,
                &snapshot,
                &config,
                &mut signer,
                seal_fn,
            )
        }
        "ml-dsa-65" => {
            let mut signer = hoike_sign::ml_dsa_65_signer(&seed);
            hoike_sign::produce_bundle::<_, hoike_sign::MlDsaSignatureBytes>(
                &ca,
                &snapshot,
                &config,
                &mut signer,
                seal_fn,
            )
        }
        "ml-dsa-87" => {
            let mut signer = hoike_sign::ml_dsa_87_signer(&seed);
            hoike_sign::produce_bundle::<_, hoike_sign::MlDsaSignatureBytes>(
                &ca,
                &snapshot,
                &config,
                &mut signer,
                seal_fn,
            )
        }
        other => {
            eprintln!(
                "Unknown sig_alg: {other} (expected: ecdsa-p256, ml-dsa-44, ml-dsa-65, ml-dsa-87)"
            );
            std::process::exit(1);
        }
    }
    .unwrap_or_else(|e| {
        eprintln!("Failed to produce bundle: {e}");
        std::process::exit(1);
    });

    std::fs::write(&output, &bundle_bytes).unwrap_or_else(|e| {
        eprintln!("Failed to write bundle to {}: {e}", output.display());
        std::process::exit(1);
    });

    let entry_count = ahu::Bundle::from_bytes(&bundle_bytes)
        .map(|b| b.manifest.entry_count)
        .unwrap_or(0);
    let avg_size = if entry_count > 0 {
        bundle_bytes.len() / entry_count as usize
    } else {
        0
    };
    let sig_overhead = hoike_sign::ml_dsa_signature_size(&sig_alg);

    println!("Bundle size: {} bytes", bundle_bytes.len());
    println!("  Entries:           {entry_count}");
    println!("  Avg response size: {avg_size} bytes");
    if sig_overhead > 0 {
        println!("  Signature overhead: ~{sig_overhead} bytes ({sig_alg})");
    }
    println!("  Output:            {}", output.display());
}
