use clap::Parser;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser)]
#[command(name = "hoike", about = "hoike — OCSP responder for pre-signed ahu bundles")]
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
        } => {
            run_sign(ca, crl, output, epoch, certid_compat, good_serials);
        }
    }
}

async fn run_server(config_path: PathBuf) {
    let config = hoike_core::Config::from_file(&config_path).unwrap_or_else(|e| {
        eprintln!("Failed to load config from {}: {e}", config_path.display());
        std::process::exit(1);
    });

    let listen = config.server.listen.clone();

    let state = hoike_core::ResponderState::load(config).unwrap_or_else(|e| {
        eprintln!("Failed to initialize responder: {e}");
        std::process::exit(1);
    });

    let app_state = hoike_server::AppState::new(state);
    let app = hoike_server::build_router(app_state);

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to bind to {listen}: {e}");
            std::process::exit(1);
        });

    info!(listen = %listen, "hoike OCSP responder starting");
    axum::serve(listener, app).await.unwrap();
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

    match hoike_core::ResponderState::load(config) {
        Ok(state) => {
            let bundle = state.bundle();
            println!("  Entries:   {}", bundle.manifest.entry_count);
            println!("  Producer:  {}", bundle.manifest.producer_id);
            println!("  Scopes:    {}", bundle.manifest.ca_scopes.len());
            for (i, scope) in bundle.manifest.ca_scopes.iter().enumerate() {
                println!(
                    "    [{}] epoch={} completeness={}",
                    i,
                    scope.epoch,
                    match scope.completeness {
                        ahu::Completeness::AuthoritativeComplete => "authoritative-complete",
                        ahu::Completeness::Partial => "partial",
                    }
                );
            }
            println!("\n  All checks passed.");
        }
        Err(e) => {
            eprintln!("  Bundle:    FAIL — {e}");
            std::process::exit(1);
        }
    }
}

fn run_sign(
    ca_label: String,
    crl_path: PathBuf,
    output: PathBuf,
    epoch: u64,
    certid_compat: String,
    good_serials: Option<PathBuf>,
) {
    use hoike_sign::{CaIdentity, CertIdCompat, CertificateStatus, CrlSource, GenerationConfig, RevocationSource};
    use p256::ecdsa::SigningKey;
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

    let ca = CaIdentity {
        label: ca_label.clone(),
        issuer_name_der: format!("CN={ca_label}").into_bytes(),
        issuer_key_bytes: format!("{ca_label}-key").into_bytes(),
    };

    let mut snapshot = source.snapshot(&ca).unwrap_or_else(|e| {
        eprintln!("Failed to snapshot CRL: {e}");
        std::process::exit(1);
    });

    if let Some(good_path) = good_serials {
        let content = std::fs::read_to_string(&good_path).unwrap_or_else(|e| {
            eprintln!("Failed to read good serials from {}: {e}", good_path.display());
            std::process::exit(1);
        });
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match hex::decode(line) {
                Ok(serial) => {
                    snapshot.entries.entry(serial).or_insert(CertificateStatus::Good);
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
        "snapshot loaded"
    );

    let config = GenerationConfig {
        producer_id: "hoike-cli".into(),
        epoch,
        certid_compat: compat,
        ..Default::default()
    };

    // For CLI use, generate an ephemeral ECDSA key
    let secret = [42u8; 32];
    let mut signing_key = SigningKey::from_bytes((&secret).into()).expect("invalid signing key");

    let bundle_bytes = hoike_sign::produce_bundle::<_, p256::ecdsa::DerSignature>(
        &ca,
        &snapshot,
        &config,
        &mut signing_key,
        |m| Ok(Sha256::digest(m).to_vec()),
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to produce bundle: {e}");
        std::process::exit(1);
    });

    std::fs::write(&output, &bundle_bytes).unwrap_or_else(|e| {
        eprintln!("Failed to write bundle to {}: {e}", output.display());
        std::process::exit(1);
    });

    println!(
        "Wrote {} bytes to {}",
        bundle_bytes.len(),
        output.display()
    );
}
