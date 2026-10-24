use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod ahu_commands;

#[derive(Parser)]
#[command(name = "ahu", about = "ahu bundle tools — inspect, verify, extract")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Display manifest, scopes, epochs, and counts
    Inspect {
        /// Path to the .ahu bundle file
        file: PathBuf,
    },
    /// Authenticate a bundle against explicit trust, or check structure only
    #[command(group(clap::ArgGroup::new("mode").required(true).args(["config", "structure_only"])))]
    Verify {
        /// Path to the .ahu bundle file
        file: PathBuf,
        /// Config containing seal trust and scope authorizations (no implicit discovery)
        #[arg(long, value_name = "PATH")]
        config: Option<PathBuf>,
        /// Check structure and digests only; authenticity is not checked
        #[arg(long, conflicts_with_all = ["config", "entries"])]
        structure_only: bool,
        /// Also check OCSP signatures with embedded keys, not responder-chain trust
        #[arg(long, requires = "config")]
        entries: bool,
    },
    /// Extract a single response by CertID hex
    Extract {
        /// Path to the .ahu bundle file
        file: PathBuf,
        /// Hex-encoded entry key (SHA-256 of DER CertID)
        #[arg(long)]
        certid: String,
        /// Output file (default: stdout as hex)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Show differences between two generations
    Diff {
        /// First bundle
        a: PathBuf,
        /// Second bundle
        b: PathBuf,
    },
    /// Apply delta bundles to a base, producing a materialized full bundle
    Apply {
        /// Base full bundle
        base: PathBuf,
        /// Delta bundles to apply in order
        #[arg(required = true)]
        deltas: Vec<PathBuf>,
        /// Output path for the materialized bundle
        #[arg(short, long)]
        output: PathBuf,
        /// P-256 PKCS#8 seal key; omit to produce an unsigned intermediate
        #[arg(long, requires_all = ["seal_cert", "input_signer_pin"])]
        seal_key: Option<PathBuf>,
        /// PEM or DER certificate matching --seal-key
        #[arg(long, requires = "seal_key")]
        seal_cert: Option<PathBuf>,
        /// Trusted input signer certificate (repeat for multiple signers)
        #[arg(long, requires = "seal_key")]
        input_signer_pin: Vec<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Inspect { file } => ahu_commands::inspect(&file),
        Commands::Verify {
            file,
            config,
            structure_only,
            entries,
        } => ahu_commands::verify(&file, config.as_deref(), structure_only, entries),
        Commands::Extract {
            file,
            certid,
            output,
        } => ahu_commands::extract(&file, &certid, output.as_deref()),
        Commands::Diff { a, b } => ahu_commands::diff(&a, &b),
        Commands::Apply {
            base,
            deltas,
            output,
            seal_key,
            seal_cert,
            input_signer_pin,
        } => ahu_commands::apply(
            &base,
            &deltas,
            &output,
            seal_key.as_deref(),
            seal_cert.as_deref(),
            &input_signer_pin,
        ),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_requires_certificate_and_input_trust_for_signing() {
        let unsigned = ["ahu", "apply", "base.ahu", "delta.ahu", "-o", "out.ahu"];
        assert!(Cli::try_parse_from(unsigned).is_ok());
        let mut args = unsigned.to_vec();
        args.extend(["--seal-key", "key.pem"]);
        assert!(Cli::try_parse_from(&args).is_err());
        args.extend(["--seal-cert", "cert.pem"]);
        assert!(Cli::try_parse_from(&args).is_err());
        args.extend(["--input-signer-pin", "trusted.pem"]);
        assert!(Cli::try_parse_from(&args).is_ok());
    }
}
