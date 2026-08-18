use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::{info, warn};

use ahu::Bundle;
use crate::config::Config;
use crate::error::{CoreError, Result};
use crate::request::ParsedCertId;

/// The responder's loaded state: one or more bundles serving CA scopes.
///
/// For M1 this is a single bundle. Multi-CA routing (M3) will index
/// bundles by (hashAlg, issuerNameHash, issuerKeyHash).
pub struct ResponderState {
    bundle: ArcSwap<Bundle>,
    pub config: Config,
}

impl ResponderState {
    pub fn load(config: Config) -> Result<Self> {
        let bundle = load_bundle(&config)?;
        Ok(ResponderState {
            bundle: ArcSwap::from_pointee(bundle),
            config,
        })
    }

    /// Look up a CertID in the loaded bundle.
    ///
    /// Returns the raw DER bytes of the pre-signed OCSPResponse,
    /// or None if the entry is not in the working set.
    pub fn lookup(&self, cert_id: &ParsedCertId) -> Option<Vec<u8>> {
        let bundle = self.bundle.load();
        bundle
            .lookup(&cert_id.entry_key)
            .map(|bytes| bytes.to_vec())
    }

    /// Get a snapshot of the current bundle for header computation.
    pub fn bundle(&self) -> arc_swap::Guard<Arc<Bundle>> {
        self.bundle.load()
    }

    /// Hot-reload the bundle from disk.
    pub fn reload(&self) -> Result<()> {
        let bundle = load_bundle(&self.config)?;
        let entry_count = bundle.manifest.entry_count;
        self.bundle.store(Arc::new(bundle));
        info!(entry_count, "bundle reloaded");
        Ok(())
    }
}

fn load_bundle(config: &Config) -> Result<Bundle> {
    let bundle_dir = &config.storage.bundle_dir;

    // If a specific bundle_file is configured for the first CA, use it.
    // Otherwise, find the newest .ahu file in the bundle directory.
    let bundle_path = if let Some(ca) = config.ca.first() {
        if let Some(bf) = &ca.bundle_file {
            bf.clone()
        } else {
            find_newest_bundle(bundle_dir)?
        }
    } else {
        find_newest_bundle(bundle_dir)?
    };

    info!(path = %bundle_path.display(), "loading bundle");
    let bundle = Bundle::from_file(&bundle_path)?;

    let result = ahu::verify_structure(&bundle)?;
    if !result.warnings.is_empty() {
        for w in &result.warnings {
            warn!(warning = w, "bundle verification warning");
        }
    }

    info!(
        entry_count = bundle.manifest.entry_count,
        producer = %bundle.manifest.producer_id,
        "bundle loaded and verified"
    );

    Ok(bundle)
}

fn find_newest_bundle(dir: &Path) -> Result<std::path::PathBuf> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .is_some_and(|ext| ext == "ahu")
        })
        .collect();

    entries.sort_by_key(|e| {
        e.metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });

    entries
        .last()
        .map(|e| e.path())
        .ok_or_else(|| CoreError::Config(format!("no .ahu files in {}", dir.display())))
}
