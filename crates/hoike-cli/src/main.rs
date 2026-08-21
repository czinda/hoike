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
        /// Path to PKCS#8 PEM or DER signing key file
        #[arg(long, conflicts_with = "demo_key")]
        signing_key: Option<PathBuf>,
        /// Use an ephemeral demo key (NOT FOR PRODUCTION)
        #[arg(long)]
        demo_key: bool,
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
            signing_key,
            demo_key,
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
                signing_key,
                demo_key,
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

    // Create persistent revocation sources — stateful sources like DogtagSync
    // must survive across signer loop iterations to retain their in-memory
    // snapshot and sync cookie.
    let persistent_sources = if is_combined {
        Some(create_persistent_sources(&config).unwrap_or_else(|e| {
            eprintln!("Failed to create revocation sources: {e}");
            std::process::exit(1);
        }))
    } else {
        None
    };

    // In combined mode, run an initial signing pass before loading bundles
    // so there's something to serve immediately.
    if is_combined {
        info!("combined mode: running initial bundle production");
        if let Err(e) = run_signer_pass_with_sources(&config, persistent_sources.as_ref().unwrap()) {
            eprintln!("Initial signer pass failed: {e}");
            std::process::exit(1);
        }
    }

    let state = hoike_core::ResponderState::load(config.clone()).unwrap_or_else(|e| {
        eprintln!("Failed to initialize responder: {e}");
        std::process::exit(1);
    });

    let mut app_state = hoike_server::AppState::new(state);

    // If any CA has nonce_policy=live, load a signing key for live responses
    let has_live_nonce = config.ca.iter().any(|ca| ca.nonce_policy == "live");
    if has_live_nonce && config.needs_signing() {
        if let Some(ca) = config.ca.iter().find(|ca| ca.nonce_policy == "live") {
            match load_live_signer(ca) {
                Ok(live) => {
                    info!("live nonce signing enabled");
                    app_state = app_state.with_live_signer(live);
                }
                Err(e) => {
                    eprintln!("Failed to load live signer: {e}");
                    std::process::exit(1);
                }
            }
        }
    }

    // In combined mode, start the background signer loop
    if is_combined {
        let signer_state = app_state.responder.clone();
        let signer_config = config.clone();
        let sources = persistent_sources.unwrap();
        tokio::spawn(async move {
            run_signer_loop(signer_state, signer_config, sources).await;
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

/// Map of CA label → persistent revocation source. Stateful sources (DogtagSync)
/// retain their in-memory snapshot and sync cookie across signer loop iterations.
type PersistentSources = std::collections::HashMap<String, Box<dyn hoike_sign::RevocationSource>>;

fn create_persistent_sources(config: &hoike_core::Config) -> std::result::Result<PersistentSources, String> {
    let mut sources = PersistentSources::new();
    for ca_config in &config.ca {
        let source_config = match &ca_config.source {
            Some(s) => s,
            None => continue,
        };
        let source: Box<dyn hoike_sign::RevocationSource> = match source_config {
            #[cfg(feature = "dogtag-sync")]
            hoike_core::config::SourceConfig::DogtagSync {
                ldap_url, base_dn, bind_dn, bind_password,
                bind_password_env, cookie_path, filter,
            } => {
                let password = resolve_ldap_password(bind_password.as_deref(), bind_password_env.as_deref())?;
                let cookie = cookie_path.clone()
                    .unwrap_or_else(|| config.storage.state_db.join("sync-cookie.dat"));
                let sync_config = hoike_sign::DogtagSyncConfig {
                    ldap_url: ldap_url.clone(),
                    base_dn: base_dn.clone(),
                    bind_dn: bind_dn.clone(),
                    bind_password: password,
                    cookie_path: cookie,
                    filter: filter.clone().unwrap_or_else(|| "(objectClass=certificateRecord)".into()),
                };
                Box::new(hoike_sign::DogtagSyncSource::new(sync_config))
            }
            // CRL and other stateless sources are created fresh each pass
            _ => continue,
        };
        sources.insert(ca_config.label.clone(), source);
    }
    Ok(sources)
}

fn run_signer_pass_with_sources(
    config: &hoike_core::Config,
    persistent_sources: &PersistentSources,
) -> std::result::Result<(), String> {
    use hoike_sign::{CaIdentity, CrlSource, GenerationConfig, RevocationSource};
    use sha2_v010::{Digest, Sha256};

    for ca_config in &config.ca {
        let source_config = match &ca_config.source {
            Some(s) => s,
            None => continue,
        };

        // Use persistent source if available, otherwise create a fresh one
        let fresh_source: Option<Box<dyn RevocationSource>>;
        let source: &dyn RevocationSource = if let Some(ps) = persistent_sources.get(&ca_config.label) {
            ps.as_ref()
        } else {
            fresh_source = Some(match source_config {
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
                #[cfg(feature = "dogtag-sync")]
                hoike_core::config::SourceConfig::DogtagSync { .. } => {
                    // Should never hit this — DogtagSync sources are always persistent
                    return Err("DogtagSync source not found in persistent sources".into());
                }
                #[cfg(not(feature = "dogtag-sync"))]
                hoike_core::config::SourceConfig::DogtagSync { .. } => {
                    return Err("dogtag-sync requires the 'dogtag-sync' feature flag".into());
                }
            });
            fresh_source.as_ref().unwrap().as_ref()
        };

        let ca = CaIdentity {
            label: ca_config.label.clone(),
            issuer_name_der: decode_issuer_name(ca_config)?,
            issuer_key_bytes: decode_issuer_key(ca_config)?,
        };

        let snapshot = source
            .snapshot(&ca)
            .map_err(|e| format!("snapshot failed for {}: {e}", ca_config.label))?;

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

        // Continue with signing (rest of the function follows the same pattern)
        // Get the signing key and produce the bundle
        let bundle_path = config.storage.bundle_dir.join(format!("{}.ahu", ca_config.label));

        match &ca_config.signing_key {
            Some(hoike_core::config::SigningKeyConfig::File { path }) => {
                let mut signing_key = hoike_sign::load_ecdsa_p256_key(path)
                    .map_err(|e| format!("signing key: {e}"))?;
                let bundle_bytes = hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
                    &ca, &snapshot, &gen_config, &mut signing_key,
                    |m| Ok(sha2_v010::Sha256::digest(m).to_vec()),
                ).map_err(|e| format!("bundle production failed for {}: {e}", ca_config.label))?;
                std::fs::write(&bundle_path, &bundle_bytes)
                    .map_err(|e| format!("write bundle: {e}"))?;
                info!(ca = ca_config.label, size = bundle_bytes.len(),
                      path = %bundle_path.display(), entries = snapshot.entries.len(),
                      "bundle produced");
            }
            #[cfg(feature = "pkcs11")]
            Some(hoike_core::config::SigningKeyConfig::Pkcs11 {
                module, token_label, key_label, pin, pin_env, slot_id, key_id,
            }) => {
                let pin_val = pin.clone().or_else(|| {
                    pin_env.as_ref().and_then(|e| std::env::var(e).ok())
                }).unwrap_or_default();
                let pkcs11_config = hoike_sign::Pkcs11Config {
                    module_path: module.clone(),
                    slot_id: *slot_id,
                    token_label: token_label.clone(),
                    pin: pin_val,
                    key_label: key_label.clone(),
                    key_id: key_id.as_ref().and_then(|h| hex::decode(h).ok()),
                };
                let signer = hoike_sign::Pkcs11Signer::new(&pkcs11_config)
                    .map_err(|e| format!("PKCS#11 init: {e}"))?;
                let mut signer = hoike_sign::Pkcs11SignerBridge::new(signer);
                let bundle_bytes = hoike_sign::produce_bundle::<_, hoike_sign::Pkcs11EcdsaSignature>(
                    &ca, &snapshot, &gen_config, &mut signer,
                    |m| Ok(sha2_v010::Sha256::digest(m).to_vec()),
                ).map_err(|e| format!("bundle production failed for {}: {e}", ca_config.label))?;
                std::fs::write(&bundle_path, &bundle_bytes)
                    .map_err(|e| format!("write bundle: {e}"))?;
                info!(ca = ca_config.label, size = bundle_bytes.len(),
                      path = %bundle_path.display(), entries = snapshot.entries.len(),
                      "bundle produced");
            }
            Some(hoike_core::config::SigningKeyConfig::Demo) => {
                let mut signing_key = hoike_sign::demo_ecdsa_p256_key();
                let bundle_bytes = hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
                    &ca, &snapshot, &gen_config, &mut signing_key,
                    |m| Ok(sha2_v010::Sha256::digest(m).to_vec()),
                ).map_err(|e| format!("bundle production failed for {}: {e}", ca_config.label))?;
                std::fs::write(&bundle_path, &bundle_bytes)
                    .map_err(|e| format!("write bundle: {e}"))?;
                warn!(ca = ca_config.label, "using demo signing key — NOT FOR PRODUCTION");
                info!(ca = ca_config.label, size = bundle_bytes.len(),
                      path = %bundle_path.display(), entries = snapshot.entries.len(),
                      "bundle produced");
            }
            _ => {
                return Err(format!("CA '{}': no signing_key configured", ca_config.label));
            }
        }
    }
    Ok(())
}

// Keep old function for non-combined modes that don't need persistent sources
fn run_signer_pass(config: &hoike_core::Config) -> std::result::Result<(), String> {
    use hoike_sign::{CaIdentity, CrlSource, GenerationConfig, RevocationSource};
    use sha2_v010::Digest as _;

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

            #[cfg(feature = "dogtag-sync")]
            hoike_core::config::SourceConfig::DogtagSync {
                ldap_url,
                base_dn,
                bind_dn,
                bind_password,
                bind_password_env,
                cookie_path,
                filter,
            } => {
                let password =
                    resolve_ldap_password(bind_password.as_deref(), bind_password_env.as_deref())?;
                let cookie = cookie_path
                    .clone()
                    .unwrap_or_else(|| config.storage.state_db.join("sync-cookie.dat"));
                let sync_config = hoike_sign::DogtagSyncConfig {
                    ldap_url: ldap_url.clone(),
                    base_dn: base_dn.clone(),
                    bind_dn: bind_dn.clone(),
                    bind_password: password,
                    cookie_path: cookie,
                    filter: filter
                        .clone()
                        .unwrap_or_else(|| "(objectClass=certificateRecord)".into()),
                };
                Box::new(hoike_sign::DogtagSyncSource::new(sync_config))
            }

            #[cfg(not(feature = "dogtag-sync"))]
            hoike_core::config::SourceConfig::DogtagSync { .. } => {
                return Err("dogtag-sync source requires the 'dogtag-sync' feature flag".into());
            }
        };

        let ca = CaIdentity {
            label: ca_config.label.clone(),
            issuer_name_der: decode_issuer_name(ca_config)?,
            issuer_key_bytes: decode_issuer_key(ca_config)?,
        };

        let responder_cert_der = ca_config
            .responder_cert
            .as_ref()
            .map(std::fs::read)
            .transpose()
            .map_err(|e| format!("read responder cert: {e}"))?;

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

        // Load seal key and cert for CMS sealing
        let (seal_key, seal_cert_der) = load_seal_materials(ca_config)?;

        let bundle_bytes = match &ca_config.signing_key {
            Some(hoike_core::config::SigningKeyConfig::File { path }) => {
                let mut signer = hoike_sign::load_ecdsa_p256_key(path)
                    .map_err(|e| format!("load signing key: {e}"))?;
                info!(ca = ca_config.label, key = %path.display(), "using file-based signing key");
                let sk = seal_key.clone();
                let sc = seal_cert_der.clone();
                hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
                    &ca,
                    &snapshot,
                    &gen_config,
                    &mut signer,
                    move |m| {
                        hoike_sign::create_cms_seal(m, &sk, &sc)
                    },
                    responder_cert_der.as_deref(),
                )
            }
            Some(hoike_core::config::SigningKeyConfig::Pkcs11 { .. }) => {
                // PKCS#11 signing requires the `pkcs11` feature at compile time
                #[cfg(feature = "pkcs11")]
                {
                    let pkcs11_config = resolve_pkcs11_config(ca_config)?;
                    let inner = hoike_sign::Pkcs11Signer::new(&pkcs11_config)
                        .map_err(|e| format!("PKCS#11 init: {e}"))?;
                    let mut bridge = hoike_sign::Pkcs11SignerBridge::new(inner);
                    let sk = seal_key.clone();
                    let sc = seal_cert_der.clone();
                    hoike_sign::produce_bundle::<_, hoike_sign::Pkcs11EcdsaSignature>(
                        &ca,
                        &snapshot,
                        &gen_config,
                        &mut bridge,
                        move |m| {
                            hoike_sign::create_cms_seal(m, &sk, &sc)
                                .map_err(|e| hoike_sign::SignError::Seal(e.to_string()))
                        },
                        responder_cert_der.as_deref(),
                    )
                }
                #[cfg(not(feature = "pkcs11"))]
                {
                    return Err(format!(
                        "CA '{}' requires PKCS#11 signing but hoike was built without the 'pkcs11' feature. \
                         Rebuild with: cargo build --features pkcs11",
                        ca_config.label
                    ));
                }
            }
            Some(hoike_core::config::SigningKeyConfig::Demo) => {
                warn!(
                    ca = ca_config.label,
                    "using ephemeral demo signing key — NOT FOR PRODUCTION"
                );
                let mut signer = hoike_sign::demo_ecdsa_p256_key();
                let sk = seal_key.clone();
                let sc = seal_cert_der.clone();
                hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
                    &ca,
                    &snapshot,
                    &gen_config,
                    &mut signer,
                    move |m| {
                        hoike_sign::create_cms_seal(m, &sk, &sc)
                    },
                    responder_cert_der.as_deref(),
                )
            }
            None => {
                return Err(format!(
                    "CA '{}' has no signing_key configured. Add [ca.signing_key] to config.",
                    ca_config.label
                ));
            }
        }
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

async fn run_signer_loop(
    state: Arc<hoike_core::ResponderState>,
    config: hoike_core::Config,
    sources: PersistentSources,
) {
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

        // Check certificate rotation before production
        for ca_config in &config.ca {
            if let Some(cert_path) = &ca_config.responder_cert {
                if let Ok(cert_der) = std::fs::read(cert_path) {
                    let renew_before = ca_config
                        .key_rotation
                        .as_ref()
                        .map(|kr| kr.renew_before_days * 86400)
                        .unwrap_or(7 * 86400);

                    match hoike_sign::check_and_log_rotation(
                        &ca_config.label,
                        &cert_der,
                        renew_before,
                    ) {
                        Ok(hoike_sign::RotationStatus::RenewSoon { .. }) => {
                            if let Some(kr) = &ca_config.key_rotation {
                                if let Some(cmd) = &kr.rotation_command {
                                    if let Err(e) =
                                        hoike_sign::run_rotation_command(&ca_config.label, cmd)
                                    {
                                        error!(ca = ca_config.label, error = %e, "rotation command failed");
                                    }
                                }
                            }
                        }
                        Ok(hoike_sign::RotationStatus::Expired) => {
                            error!(
                                ca = ca_config.label,
                                "OCSP signing cert EXPIRED — bundles will be rejected by clients"
                            );
                        }
                        _ => {}
                    }
                }
            }
        }

        info!("signer loop: starting production cycle");
        match run_signer_pass_with_sources(&config, &sources) {
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

/// Resolve LDAP bind password from config value or environment variable.
#[cfg(feature = "dogtag-sync")]
fn resolve_ldap_password(
    password: Option<&str>,
    env_var: Option<&str>,
) -> std::result::Result<String, String> {
    if let Some(pw) = password {
        return Ok(pw.to_string());
    }
    if let Some(var) = env_var {
        return std::env::var(var).map_err(|_| {
            format!(
                "LDAP bind password env var '{var}' not set. \
                 Set it or use bind_password in config."
            )
        });
    }
    Err("no LDAP bind password: set bind_password or bind_password_env in config".into())
}

fn load_responder_cert(
    ca: &hoike_core::config::CaConfig,
) -> std::result::Result<Option<Vec<u8>>, String> {
    match &ca.responder_cert {
        Some(path) => {
            let data = std::fs::read(path)
                .map_err(|e| format!("failed to read responder cert '{}': {e}", path.display()))?;
            if data.starts_with(b"-----BEGIN") {
                let pem_str = String::from_utf8(data)
                    .map_err(|e| format!("responder cert PEM is not valid UTF-8: {e}"))?;
                use base64::Engine;
                let mut b64 = String::new();
                for line in pem_str.lines() {
                    if line.starts_with("-----") {
                        continue;
                    }
                    b64.push_str(line.trim());
                }
                let der = base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .map_err(|e| format!("responder cert PEM base64 decode: {e}"))?;
                Ok(Some(der))
            } else {
                Ok(Some(data))
            }
        }
        None => Ok(None),
    }
}

/// Load seal key and certificate for CMS bundle sealing.
/// Falls back to the OCSP signing key if no seal_key is configured.
fn load_seal_materials(
    ca_config: &hoike_core::config::CaConfig,
) -> std::result::Result<(p256::ecdsa::SigningKey, Vec<u8>), String> {
    let seal_key = if let Some(path) = &ca_config.seal_key {
        hoike_sign::load_ecdsa_p256_key(path)
            .map_err(|e| format!("load seal key: {e}"))?
    } else if let Some(hoike_core::config::SigningKeyConfig::File { path }) = &ca_config.signing_key
    {
        warn!(
            ca = ca_config.label,
            "using OCSP signing key as seal key — configure seal_key for production"
        );
        hoike_sign::load_ecdsa_p256_key(path)
            .map_err(|e| format!("load signing key for seal: {e}"))?
    } else {
        warn!(
            ca = ca_config.label,
            "no seal_key configured — generating ephemeral seal key"
        );
        hoike_sign::demo_ecdsa_p256_key()
    };

    let seal_cert_der = if let Some(path) = &ca_config.seal_cert {
        std::fs::read(path).map_err(|e| format!("read seal cert: {e}"))?
    } else {
        hoike_sign::generate_seal_cert(&seal_key)
            .map_err(|e| format!("generate seal cert: {e}"))?
    };

    Ok((seal_key, seal_cert_der))
}

fn load_live_signer(
    ca: &hoike_core::config::CaConfig,
) -> std::result::Result<hoike_server::LiveSignerState, String> {
    let signing_key = match &ca.signing_key {
        Some(hoike_core::config::SigningKeyConfig::File { path }) => {
            hoike_sign::load_ecdsa_p256_key(path)
                .map_err(|e| format!("failed to load live signing key: {e}"))?
        }
        Some(hoike_core::config::SigningKeyConfig::Demo) => {
            warn!("live nonce signer using demo key — NOT FOR PRODUCTION");
            hoike_sign::demo_ecdsa_p256_key()
        }
        Some(hoike_core::config::SigningKeyConfig::Pkcs11 { .. }) => {
            return Err(
                "PKCS#11 live nonce signing not yet supported — use file key or demo".into(),
            );
        }
        None => {
            return Err(format!(
                "CA '{}': nonce_policy=live requires a signing_key",
                ca.label
            ));
        }
    };

    let responder_cert_der = load_responder_cert(ca)?;

    // RFC 6960: KeyHash = SHA-1(responder's subjectPublicKey).
    // When delegated (cert provided), hash the cert's SPKI.
    // When CA-direct, hash the CA's key bytes.
    let responder_key_bytes = if let Some(cert_der) = &responder_cert_der {
        use sha1::Digest;
        let cert = <x509_cert::Certificate as der::Decode>::from_der(cert_der)
            .map_err(|e| format!("parse responder cert for SPKI: {e}"))?;
        let key_bytes = cert
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes();
        sha1::Sha1::digest(key_bytes).to_vec()
    } else {
        decode_issuer_key(ca)?
    };

    Ok(hoike_server::LiveSignerState {
        signer: tokio::sync::Mutex::new(signing_key),
        responder_key_bytes,
        validity_secs: ca.validity_secs,
        responder_cert_der,
    })
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

    // Check responder certificate expiry for each CA
    for ca in &config.ca {
        if let Some(cert_path) = &ca.responder_cert {
            match std::fs::read(cert_path) {
                Ok(cert_der) => match hoike_sign::format_cert_info(&cert_der) {
                    Ok(info) => {
                        println!("\n  ── Responder Cert ({}) ──", ca.label);
                        println!("    Subject:  {}", info.subject);
                        println!("    Issuer:   {}", info.issuer);
                        println!("    Days remaining: {}", info.days_remaining);
                        println!(
                            "    OCSP Signing EKU: {}",
                            if info.has_ocsp_signing_eku {
                                "yes"
                            } else {
                                "NOT FOUND — clients may reject"
                            }
                        );
                        if info.is_expired {
                            eprintln!("    STATUS: EXPIRED");
                        } else if info.days_remaining <= 30 {
                            eprintln!("    WARNING: expires in {} days", info.days_remaining);
                        } else {
                            println!("    Status:   OK");
                        }
                    }
                    Err(e) => {
                        eprintln!("    Cert parse: FAIL — {e}");
                    }
                },
                Err(e) => {
                    eprintln!("    Cert read ({})): FAIL — {e}", cert_path.display());
                }
            }
        }
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
    signing_key_path: Option<PathBuf>,
    demo_key: bool,
) {
    use hoike_sign::{
        CaIdentity, CertIdCompat, CertificateStatus, CrlSource, GenerationConfig, RevocationSource,
    };

    // Resolve signing key — require explicit --signing-key or --demo-key
    if signing_key_path.is_none() && !demo_key {
        eprintln!(
            "Error: no signing key specified.\n\n\
             Provide one of:\n  \
             --signing-key PATH   PKCS#8 PEM or DER key file\n  \
             --demo-key           Ephemeral key for testing only (NOT FOR PRODUCTION)\n"
        );
        std::process::exit(1);
    }

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

    // For CLI signing, use the OCSP signing key as the seal key too.
    // In production, the seal key should be separate (per ahu spec §2.3).
    let cli_seal_key = if let Some(key_path) = &signing_key_path {
        hoike_sign::load_ecdsa_p256_key(key_path).unwrap_or_else(|e| {
            eprintln!("Failed to load seal key: {e}");
            std::process::exit(1);
        })
    } else {
        hoike_sign::demo_ecdsa_p256_key()
    };
    let cli_seal_cert = hoike_sign::generate_seal_cert(&cli_seal_key).unwrap_or_else(|e| {
        eprintln!("Failed to generate seal cert: {e}");
        std::process::exit(1);
    });
    let seal_fn = move |m: &[u8]| -> hoike_sign::Result<Vec<u8>> {
        hoike_sign::create_cms_seal(m, &cli_seal_key, &cli_seal_cert)
    };

    let bundle_bytes = match sig_alg.as_str() {
        "ecdsa-p256" => {
            let mut signer = if let Some(key_path) = &signing_key_path {
                hoike_sign::load_ecdsa_p256_key(key_path).unwrap_or_else(|e| {
                    eprintln!("Failed to load signing key: {e}");
                    std::process::exit(1);
                })
            } else if demo_key {
                warn!("using ephemeral ECDSA demo key — NOT FOR PRODUCTION");
                hoike_sign::demo_ecdsa_p256_key()
            } else {
                eprintln!("No signing key provided. Use --signing-key <path> for a PKCS#8 key file, or --demo-key for testing.");
                std::process::exit(1);
            };
            hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
                &ca,
                &snapshot,
                &config,
                &mut signer,
                seal_fn,
                None,
            )
        }
        "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" => {
            if !demo_key {
                eprintln!("ML-DSA key loading from file is not yet supported.");
                eprintln!("Use --demo-key for testing, or use --sig-alg ecdsa-p256 with --signing-key for production.");
                std::process::exit(1);
            }
            warn!("using ephemeral ML-DSA demo key — NOT FOR PRODUCTION");
            let mut seed = [0u8; 32];
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut seed);
            match sig_alg.as_str() {
                "ml-dsa-44" => {
                    let mut signer = hoike_sign::ml_dsa_44_signer(&seed);
                    hoike_sign::produce_bundle::<_, hoike_sign::MlDsaSignatureBytes>(
                        &ca, &snapshot, &config, &mut signer, seal_fn, None,
                    )
                }
                "ml-dsa-65" => {
                    let mut signer = hoike_sign::ml_dsa_65_signer(&seed);
                    hoike_sign::produce_bundle::<_, hoike_sign::MlDsaSignatureBytes>(
                        &ca, &snapshot, &config, &mut signer, seal_fn, None,
                    )
                }
                "ml-dsa-87" => {
                    let mut signer = hoike_sign::ml_dsa_87_signer(&seed);
                    hoike_sign::produce_bundle::<_, hoike_sign::MlDsaSignatureBytes>(
                        &ca, &snapshot, &config, &mut signer, seal_fn, None,
                    )
                }
                _ => unreachable!(),
            }
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

#[cfg(feature = "pkcs11")]
/// Resolve a PKCS#11 PIN through the precedence chain:
///   1. `pin` in config (least secure — plaintext on disk)
///   2. `pin_env` — read from the named environment variable
///   3. Interactive terminal prompt (most secure — never stored)
///
/// For production deployments, omit both `pin` and `pin_env` from the
/// config file. hoike will prompt at startup:
///
/// ```text
/// Enter PKCS#11 PIN for CA 'enterprise-issuing-01' (Luna: hoike-partition):
/// ```
///
/// For automated/headless environments (containers, systemd), use `pin_env`
/// and inject the PIN via a secrets manager (Vault, Kubernetes secrets, etc.).
fn resolve_pkcs11_pin(
    ca_label: &str,
    token_label: Option<&str>,
    pin: &Option<String>,
    pin_env: &Option<String>,
) -> std::result::Result<String, String> {
    if let Some(p) = pin {
        warn!(
            ca = ca_label,
            "PKCS#11 PIN is in config file — use pin_env or interactive prompt for production"
        );
        return Ok(p.clone());
    }

    if let Some(env_var) = pin_env {
        return std::env::var(env_var).map_err(|_| {
            format!(
                "CA '{}': PKCS#11 pin_env '{}' is not set in environment",
                ca_label, env_var
            )
        });
    }

    // Interactive prompt — the production path
    let prompt = if let Some(tl) = token_label {
        format!("Enter PKCS#11 PIN for CA '{}' (token: {}): ", ca_label, tl)
    } else {
        format!("Enter PKCS#11 PIN for CA '{}': ", ca_label)
    };

    eprint!("{}", prompt);
    rpassword::read_password()
        .map_err(|e| format!("CA '{}': failed to read PIN from terminal: {e}", ca_label))
}

/// Resolve PKCS#11 config from CaConfig.
#[cfg(feature = "pkcs11")]
fn resolve_pkcs11_config(
    ca_config: &hoike_core::config::CaConfig,
) -> std::result::Result<hoike_sign::Pkcs11Config, String> {
    match &ca_config.signing_key {
        Some(hoike_core::config::SigningKeyConfig::Pkcs11 {
            module,
            token_label,
            slot_id,
            pin,
            pin_env,
            key_label,
            key_id,
        }) => {
            let resolved_pin =
                resolve_pkcs11_pin(&ca_config.label, token_label.as_deref(), pin, pin_env)?;

            Ok(hoike_sign::Pkcs11Config {
                module_path: module.clone(),
                slot_id: *slot_id,
                token_label: token_label.clone(),
                pin: resolved_pin,
                key_label: key_label.clone(),
                key_id: key_id
                    .as_ref()
                    .map(|h| {
                        hex::decode(h).map_err(|e| {
                            format!(
                                "CA '{}': invalid hex in key_id '{}': {e}",
                                ca_config.label, h
                            )
                        })
                    })
                    .transpose()?,
            })
        }
        _ => Err(format!(
            "CA '{}': not a PKCS#11 signing key config",
            ca_config.label
        )),
    }
}
