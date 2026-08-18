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
    /// Verify seal, digests, sort order; optionally verify individual entries
    Verify {
        /// Path to the .ahu bundle file
        file: PathBuf,
        /// Also verify each stored OCSP response signature
        #[arg(long)]
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
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Inspect { file } => ahu_commands::inspect(&file),
        Commands::Verify { file, entries } => ahu_commands::verify(&file, entries),
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
        } => ahu_commands::apply(&base, &deltas, &output),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
