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
#[allow(clippy::large_enum_variant)]
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
        /// Path to PKCS#8 PEM or DER P-256 seal key file (separate from signing key)
        #[arg(long)]
        seal_key: Option<PathBuf>,
        /// Produce a dual-algorithm bundle: --sig-alg is the classical algorithm,
        /// --dual-alg is the post-quantum algorithm (e.g. ml-dsa-87)
        #[arg(long)]
        dual_alg: Option<String>,
        /// Path to PKCS#8 PEM or DER PQ signing key file (for --dual-alg)
        #[arg(long)]
        pq_signing_key: Option<PathBuf>,
        /// Use an ephemeral demo key (NOT FOR PRODUCTION)
        #[arg(long)]
        demo_key: bool,
    },
    /// Query a running OCSP responder with optional algorithm preference
    Query {
        /// Responder URL (e.g. http://localhost:2560)
        #[arg(long)]
        url: String,
        /// Hex-encoded serial number
        #[arg(long)]
        serial: String,
        /// Base64-encoded DER issuer name
        #[arg(long)]
        issuer_name_b64: String,
        /// Base64-encoded issuer public key bytes
        #[arg(long)]
        issuer_key_b64: String,
        /// Preferred signature algorithms (comma-separated, e.g. "ml-dsa-87,ecdsa-p256")
        #[arg(long)]
        prefer: Option<String>,
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
            seal_key,
            dual_alg,
            pq_signing_key,
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
                seal_key,
                dual_alg,
                pq_signing_key,
                demo_key,
            );
        }
        Commands::Query {
            url,
            serial,
            issuer_name_b64,
            issuer_key_b64,
            prefer,
        } => {
            run_query(url, serial, issuer_name_b64, issuer_key_b64, prefer);
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
    let needs_signing = config.needs_signing();

    // Create persistent revocation sources — stateful sources like DogtagSync
    // must survive across signer loop iterations to retain their in-memory
    // snapshot and sync cookie. Needed for both combined and signer modes.
    let persistent_sources = if needs_signing {
        Some(
            hoike_sign::create_persistent_sources(&config).unwrap_or_else(|e| {
                eprintln!("Failed to create revocation sources: {e}");
                std::process::exit(1);
            }),
        )
    } else {
        None
    };

    // In signing modes, run an initial signing pass before loading bundles so
    // there's something to serve immediately (combined) or a fresh generation
    // on disk (signer).
    if let Some(sources) = persistent_sources.as_ref() {
        info!(
            mode = config.server.mode,
            "running initial bundle production"
        );
        if let Err(e) = hoike_sign::sign_and_write_all(&config, sources) {
            eprintln!("Initial signer pass failed: {e}");
            std::process::exit(1);
        }
    }

    // Install the Prometheus recorder (no-op unless built with --features
    // metrics) before the first bundle load so an initial-load failure is
    // captured in `hoike_bundle_load_failures_total` too, not just later reloads.
    if hoike_server::install_metrics() {
        info!("Prometheus metrics recorder installed");
    }

    let state = hoike_core::ResponderState::load(config.clone()).unwrap_or_else(|e| {
        hoike_server::obs::record_bundle_load_failure(
            "all",
            hoike_server::obs::load_failure_reason(&e),
        );
        hoike_server::obs::audit!(
            event = "bundle_load_failed",
            trigger = "initial_load",
            reason = hoike_server::obs::load_failure_reason(&e),
            error = %e,
            "initial bundle load failed"
        );
        eprintln!("Failed to initialize responder: {e}");
        std::process::exit(1);
    });

    let mut app_state = hoike_server::AppState::new(state, config.clone());

    // Attach the shared signing context (holds the persistent sources behind a
    // mutex) so the admin API and the background loop serialize on one lock.
    if let Some(sources) = persistent_sources {
        let ctx = hoike_server::SignerContext {
            sources: tokio::sync::Mutex::new(sources),
        };
        app_state = app_state.with_signer_context(ctx);
    }

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

    // Start gossip BEFORE the signer loop so the loop can announce generations
    // through the live node. The handle is kept (wrapped in `Arc`, attached to
    // `AppState`) rather than dropped, so admin fleet endpoints and the signer
    // path can reach membership, the generation table, and `announce_generation`.
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
                Ok(gossip_node) => {
                    info!("gossip node started");
                    let gossip_node = std::sync::Arc::new(gossip_node);
                    app_state = app_state.with_gossip(gossip_node.clone());

                    // Consumer: fold received announcements into the generation
                    // table so the fleet view can attribute epochs to nodes and
                    // compute per-node staleness.
                    let consumer_node = gossip_node.clone();
                    tokio::spawn(async move {
                        while let Some(msg) = msg_rx.recv().await {
                            match &msg {
                                hoike_gossip::GossipMessage::GenerationAnnouncement {
                                    producer_id,
                                    epoch,
                                    origin_node,
                                    bundle_url,
                                    ..
                                } => {
                                    info!(
                                        origin = %origin_node,
                                        producer = %producer_id,
                                        epoch,
                                        url = bundle_url.as_deref().unwrap_or("none"),
                                        "received generation announcement"
                                    );
                                    consumer_node.record_generation(&msg).await;
                                    // Bundle pull-on-announce is future work: fetch
                                    // from bundle_url, verify anti-rollback, then
                                    // swap into the router via responder.reload().
                                }
                                hoike_gossip::GossipMessage::UrgentRevocation {
                                    producer_id,
                                    epoch,
                                    origin_node,
                                    ..
                                } => {
                                    info!(
                                        origin = %origin_node,
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

    // In signing modes, start the background signer loop. It shares the same
    // `SignerContext` mutex as the admin API so on-demand and periodic signing
    // never race on epoch/cookie/write. It also gets the gossip handle so each
    // successful pass announces the new generation to the mesh.
    if needs_signing {
        if let Some(ctx) = app_state.signer.clone() {
            let signer_state = app_state.responder.clone();
            let signer_config = config.clone();
            let signer_gossip = app_state.gossip.clone();
            tokio::spawn(async move {
                run_signer_loop(signer_state, signer_config, ctx, signer_gossip).await;
            });
        }
    }

    // The recorder was installed earlier (before the initial load). If
    // configured, expose it on a dedicated private listener — never the public
    // OCSP port.
    if let Some(metrics_listen) = config.server.metrics_listen.clone() {
        let metrics_state = app_state.clone();
        tokio::spawn(async move {
            let router = hoike_server::build_metrics_router(metrics_state);
            match tokio::net::TcpListener::bind(&metrics_listen).await {
                Ok(l) => {
                    info!(listen = %metrics_listen, "metrics listener starting");
                    if let Err(e) = axum::serve(l, router).await {
                        warn!(error = %e, "metrics listener exited");
                    }
                }
                Err(e) => {
                    warn!(error = %e, listen = %metrics_listen, "failed to bind metrics listener")
                }
            }
        });
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

async fn run_signer_loop(
    state: Arc<hoike_core::ResponderState>,
    config: hoike_core::Config,
    ctx: Arc<hoike_server::SignerContext>,
    gossip: Option<Arc<hoike_gossip::GossipNode>>,
) {
    let min_interval = config
        .ca
        .iter()
        .map(|c| c.batch_interval)
        .min()
        .unwrap_or(3600);

    info!(
        interval_secs = min_interval,
        mode = config.server.mode,
        "signer loop starting"
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
        // Serialize against on-demand admin signing via the shared mutex.
        let sources = ctx.sources.lock().await;
        let gen_start = std::time::Instant::now();
        match hoike_sign::sign_and_write_all(&config, &sources) {
            Ok(signed) => {
                let gen_secs = gen_start.elapsed().as_secs_f64();
                for s in &signed {
                    hoike_server::obs::record_signer_generation(&s.label, gen_secs);
                    hoike_server::obs::audit!(
                        event = "signer_generation",
                        ca = %s.label,
                        trigger = "scheduled",
                        epoch = s.epoch,
                        entry_count = s.entry_count,
                        "produced bundle on schedule"
                    );
                }
                if let Err(e) = state.reload() {
                    hoike_server::obs::record_bundle_load_failure(
                        "all",
                        hoike_server::obs::load_failure_reason(&e),
                    );
                    hoike_server::obs::audit!(
                        event = "bundle_load_failed",
                        trigger = "scheduled_reload",
                        reason = hoike_server::obs::load_failure_reason(&e),
                        error = %e,
                        "reload failed after scheduled production"
                    );
                    error!(error = %e, "signer loop: reload failed after production");
                } else {
                    info!(
                        scopes = signed.len(),
                        "signer loop: bundles produced and reloaded"
                    );
                    // Announce each new generation to the mesh (best-effort).
                    if let Some(g) = gossip.as_ref() {
                        for s in &signed {
                            hoike_server::announce_bundle_scopes(g, &s.bytes).await;
                        }
                    }
                }
            }
            Err(e) => {
                hoike_server::obs::audit!(
                    event = "signer_generation_failed",
                    trigger = "scheduled",
                    error = %e,
                    "scheduled production failed"
                );
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

    let responder_cert_der = hoike_sign::orchestrate::load_responder_cert(ca)?;

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
        hoike_sign::orchestrate::decode_issuer_key(ca)?
    };

    Ok(hoike_server::LiveSignerState {
        signer: tokio::sync::Mutex::new(signing_key),
        responder_key_bytes,
        validity_secs: ca.validity_secs,
        responder_cert_der,
    })
}

fn run_query(
    url: String,
    serial_hex: String,
    issuer_name_b64: String,
    issuer_key_b64: String,
    prefer: Option<String>,
) {
    use base64::Engine;
    use der::{Decode, Encode, asn1::OctetString};
    use sha2::{Digest, Sha256};

    let issuer_name_der = base64::engine::general_purpose::STANDARD
        .decode(&issuer_name_b64)
        .unwrap_or_else(|e| {
            eprintln!("Invalid issuer_name_b64: {e}");
            std::process::exit(1);
        });
    let issuer_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&issuer_key_b64)
        .unwrap_or_else(|e| {
            eprintln!("Invalid issuer_key_b64: {e}");
            std::process::exit(1);
        });
    let serial_bytes = hex::decode(&serial_hex).unwrap_or_else(|e| {
        eprintln!("Invalid serial hex: {e}");
        std::process::exit(1);
    });

    let sha256_oid = const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    let name_hash = Sha256::digest(&issuer_name_der);
    let key_hash = Sha256::digest(&issuer_key_bytes);

    let cert_id = x509_ocsp::CertId {
        hash_algorithm: spki::AlgorithmIdentifierOwned {
            oid: sha256_oid,
            parameters: Some(der::asn1::Any::from(der::asn1::Null)),
        },
        issuer_name_hash: OctetString::new(name_hash.to_vec()).unwrap(),
        issuer_key_hash: OctetString::new(key_hash.to_vec()).unwrap(),
        serial_number: x509_cert::serial_number::SerialNumber::new(&serial_bytes).unwrap_or_else(
            |e| {
                eprintln!("Invalid serial: {e}");
                std::process::exit(1);
            },
        ),
    };

    let request_item = x509_ocsp::Request {
        req_cert: cert_id,
        single_request_extensions: None,
    };

    let mut request_extensions = Vec::new();

    if let Some(prefer_str) = &prefer {
        let pref_ext_der = build_preferred_sig_algs_extension(prefer_str);
        let pref_oid = const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.8");
        request_extensions.push(x509_cert::ext::Extension {
            extn_id: pref_oid,
            critical: false,
            extn_value: OctetString::new(pref_ext_der).unwrap(),
        });
    }

    let tbs = x509_ocsp::TbsRequest {
        version: Default::default(),
        requestor_name: None,
        request_list: vec![request_item],
        request_extensions: if request_extensions.is_empty() {
            None
        } else {
            Some(request_extensions)
        },
    };
    let ocsp_request = x509_ocsp::OcspRequest {
        tbs_request: tbs,
        optional_signature: None,
    };

    let request_der = ocsp_request.to_der().unwrap_or_else(|e| {
        eprintln!("Failed to encode OcspRequest: {e}");
        std::process::exit(1);
    });

    println!("Sending OCSP request to {url}");
    println!("  Serial:    {serial_hex}");
    println!("  Request:   {} bytes", request_der.len());
    if let Some(p) = &prefer {
        println!("  Prefer:    {p}");
    }

    let response = ureq::post(&url)
        .header("Content-Type", "application/ocsp-request")
        .send(&request_der);

    match response {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.into_body().read_to_vec().unwrap_or_else(|e| {
                eprintln!("Failed to read response body: {e}");
                std::process::exit(1);
            });

            println!("\n── Response ──");
            println!("  HTTP status: {status}");
            println!("  Body size:   {} bytes", body.len());

            match x509_ocsp::OcspResponse::from_der(&body) {
                Ok(ocsp_resp) => {
                    println!("  OCSP status: {:?}", ocsp_resp.response_status);
                    if let Some(resp_bytes) = &ocsp_resp.response_bytes {
                        match x509_ocsp::BasicOcspResponse::from_der(resp_bytes.response.as_bytes())
                        {
                            Ok(basic) => {
                                let alg_oid = basic.signature_algorithm.oid.to_string();
                                let sig_len = basic.signature.raw_bytes().len();
                                let alg_name = match alg_oid.as_str() {
                                    "1.2.840.10045.4.3.2" => "ecdsa-p256-sha256",
                                    "2.16.840.1.101.3.4.3.17" => "ml-dsa-44",
                                    "2.16.840.1.101.3.4.3.18" => "ml-dsa-65",
                                    "2.16.840.1.101.3.4.3.19" => "ml-dsa-87",
                                    other => other,
                                };
                                println!("  Algorithm:   {alg_name}");
                                println!("  Signature:   {sig_len} bytes");
                                let resp_count = basic.tbs_response_data.responses.len();
                                println!("  Responses:   {resp_count}");
                            }
                            Err(e) => {
                                eprintln!("  Failed to parse BasicOcspResponse: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  Failed to parse OcspResponse: {e}");
                    eprintln!("  Raw (hex): {}", hex::encode(&body));
                }
            }
        }
        Err(e) => {
            eprintln!("HTTP request failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Build the DER-encoded PreferredSignatureAlgorithms extension value.
///
/// Uses the same `#[derive(der::Sequence)]` struct used for parsing in
/// hoike-core, ensuring encode/decode symmetry. RFC 6960 §4.4.7.1.
fn build_preferred_sig_algs_extension(prefer_str: &str) -> Vec<u8> {
    use der::Encode;

    #[derive(der::Sequence)]
    struct PreferredSignatureAlgorithm {
        sig_identifier: spki::AlgorithmIdentifierOwned,
    }

    let alg_ids: Vec<PreferredSignatureAlgorithm> = prefer_str
        .split(',')
        .map(|alg| {
            let (oid_str, params) = match alg.trim() {
                // ECDSA-with-SHA256 requires parameters = NULL per RFC 5754 §3.2
                "ecdsa-p256" => (
                    "1.2.840.10045.4.3.2",
                    Some(der::asn1::Any::from(der::asn1::Null)),
                ),
                // ML-DSA algorithms: parameters absent per RFC 9881 §9
                "ml-dsa-44" => ("2.16.840.1.101.3.4.3.17", None),
                "ml-dsa-65" => ("2.16.840.1.101.3.4.3.18", None),
                "ml-dsa-87" => ("2.16.840.1.101.3.4.3.19", None),
                other => {
                    eprintln!("Unknown algorithm for --prefer: {other}");
                    std::process::exit(1);
                }
            };
            PreferredSignatureAlgorithm {
                sig_identifier: spki::AlgorithmIdentifierOwned {
                    oid: const_oid::ObjectIdentifier::new_unwrap(oid_str),
                    parameters: params,
                },
            }
        })
        .collect();

    alg_ids.to_der().unwrap_or_else(|e| {
        eprintln!("Failed to encode PreferredSignatureAlgorithms: {e}");
        std::process::exit(1);
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
    seal_key_path: Option<PathBuf>,
    dual_alg: Option<String>,
    pq_signing_key_path: Option<PathBuf>,
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

    // Seal key resolution: --seal-key > ECDSA signing key fallback > demo key.
    // In production, the seal key should be separate (per ahu spec §2.3).
    let is_ml_dsa = matches!(sig_alg.as_str(), "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87");
    let cli_seal_key: hoike_sign::SealKey = if let Some(seal_path) = &seal_key_path {
        let ecdsa_key = hoike_sign::load_ecdsa_p256_key(seal_path).unwrap_or_else(|e| {
            eprintln!("Failed to load seal key from {}: {e}", seal_path.display());
            std::process::exit(1);
        });
        hoike_sign::SealKey::EcdsaP256(ecdsa_key)
    } else if !is_ml_dsa {
        if let Some(key_path) = &signing_key_path {
            warn!("using OCSP signing key as seal key — provide --seal-key for production");
            let ecdsa_key = hoike_sign::load_ecdsa_p256_key(key_path).unwrap_or_else(|e| {
                eprintln!("Failed to load seal key: {e}");
                std::process::exit(1);
            });
            hoike_sign::SealKey::EcdsaP256(ecdsa_key)
        } else {
            hoike_sign::SealKey::EcdsaP256(hoike_sign::demo_ecdsa_p256_key())
        }
    } else if signing_key_path.is_some() {
        warn!(
            "ML-DSA signing key cannot be used as P-256 seal key — \
             provide --seal-key for production use"
        );
        hoike_sign::SealKey::EcdsaP256(hoike_sign::demo_ecdsa_p256_key())
    } else {
        hoike_sign::SealKey::EcdsaP256(hoike_sign::demo_ecdsa_p256_key())
    };
    let cli_seal_cert = hoike_sign::generate_seal_cert_for_key(&cli_seal_key).unwrap_or_else(|e| {
        eprintln!("Failed to generate seal cert: {e}");
        std::process::exit(1);
    });
    let seal_fn = move |m: &[u8]| -> hoike_sign::Result<Vec<u8>> {
        hoike_sign::create_cms_seal(m, &cli_seal_key, &cli_seal_cert)
    };

    let bundle_bytes = if let Some(pq_alg) = &dual_alg {
        let disc_pq = match pq_alg.as_str() {
            "ml-dsa-44" => ahu::ALG_DISC_ML_DSA_44,
            "ml-dsa-65" => ahu::ALG_DISC_ML_DSA_65,
            "ml-dsa-87" => ahu::ALG_DISC_ML_DSA_87,
            other => {
                eprintln!("Unknown --dual-alg: {other}");
                std::process::exit(1);
            }
        };
        let mut ecdsa_signer = if let Some(key_path) = &signing_key_path {
            hoike_sign::load_ecdsa_p256_key(key_path).unwrap_or_else(|e| {
                eprintln!("Failed to load classical signing key: {e}");
                std::process::exit(1);
            })
        } else if demo_key {
            warn!("using ephemeral ECDSA demo key — NOT FOR PRODUCTION");
            hoike_sign::demo_ecdsa_p256_key()
        } else {
            eprintln!("--dual-alg requires --signing-key (classical) or --demo-key");
            std::process::exit(1);
        };
        let mut pq_signer = if let Some(pq_path) = &pq_signing_key_path {
            let v = hoike_sign::load_ml_dsa_key(pq_path).unwrap_or_else(|e| {
                eprintln!("Failed to load PQ signing key: {e}");
                std::process::exit(1);
            });
            if v.algorithm_name() != pq_alg.as_str() {
                eprintln!(
                    "PQ key is {} but --dual-alg is {}",
                    v.algorithm_name(), pq_alg
                );
                std::process::exit(1);
            }
            v
        } else if demo_key {
            warn!("using ephemeral ML-DSA demo key — NOT FOR PRODUCTION");
            hoike_sign::MlDsaSignerVariant::demo(pq_alg).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            })
        } else {
            eprintln!("--dual-alg requires --pq-signing-key or --demo-key");
            std::process::exit(1);
        };
        match &mut pq_signer {
            hoike_sign::MlDsaSignerVariant::MlDsa44(s) => {
                hoike_sign::produce_dual_bundle::<_, p256::ecdsa::DerSignature, _, hoike_sign::MlDsaSignatureBytes>(
                    &ca, &snapshot, &config, &mut ecdsa_signer, s, disc_pq, seal_fn, None, None,
                )
            }
            hoike_sign::MlDsaSignerVariant::MlDsa65(s) => {
                hoike_sign::produce_dual_bundle::<_, p256::ecdsa::DerSignature, _, hoike_sign::MlDsaSignatureBytes>(
                    &ca, &snapshot, &config, &mut ecdsa_signer, s, disc_pq, seal_fn, None, None,
                )
            }
            hoike_sign::MlDsaSignerVariant::MlDsa87(s) => {
                hoike_sign::produce_dual_bundle::<_, p256::ecdsa::DerSignature, _, hoike_sign::MlDsaSignatureBytes>(
                    &ca, &snapshot, &config, &mut ecdsa_signer, s, disc_pq, seal_fn, None, None,
                )
            }
        }
    } else { match sig_alg.as_str() {
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
            let mut variant = if let Some(key_path) = &signing_key_path {
                let v = hoike_sign::load_ml_dsa_key(key_path).unwrap_or_else(|e| {
                    eprintln!("Failed to load ML-DSA signing key: {e}");
                    std::process::exit(1);
                });
                if v.algorithm_name() != sig_alg {
                    eprintln!(
                        "Key algorithm mismatch: key is {} but --sig-alg is {}",
                        v.algorithm_name(),
                        sig_alg
                    );
                    std::process::exit(1);
                }
                info!(
                    ca = ca_label,
                    key = %key_path.display(),
                    alg = v.algorithm_name(),
                    "using file-based ML-DSA signing key"
                );
                v
            } else if demo_key {
                warn!("using ephemeral ML-DSA demo key — NOT FOR PRODUCTION");
                hoike_sign::MlDsaSignerVariant::demo(&sig_alg).unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(1);
                })
            } else {
                eprintln!(
                    "No signing key provided. Use --signing-key <path> for a PKCS#8 key file, \
                     or --demo-key for testing."
                );
                std::process::exit(1);
            };
            variant.sign_bundle(&ca, &snapshot, &config, seal_fn, None)
        }
        other => {
            eprintln!(
                "Unknown sig_alg: {other} (expected: ecdsa-p256, ml-dsa-44, ml-dsa-65, ml-dsa-87)"
            );
            std::process::exit(1);
        }
    } }
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
