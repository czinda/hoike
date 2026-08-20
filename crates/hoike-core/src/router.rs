use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use tracing::{info, warn};

use crate::config::Config;
use crate::error::{CoreError, Result};
use crate::request::ParsedCertId;
use crate::state::StateStore;
use ahu::Bundle;

/// Routing key: (issuerNameHash, issuerKeyHash).
/// Both SHA-1 and SHA-256 hash algorithms produce different CertIDs for the
/// same CA, so both the SHA-1 and SHA-256 hashes from the bundle manifest
/// are registered as separate scope keys pointing to the same bundle.
type ScopeKey = (Vec<u8>, Vec<u8>);

/// Metadata about a CA scope within a loaded bundle.
#[derive(Debug, Clone)]
pub struct ScopeEntry {
    pub bundle_idx: usize,
    pub ca_label: String,
    pub nonce_policy: String,
    pub completeness: String,
    pub forward_to: Option<String>,
}

/// The loaded working set: bundles indexed by CA scope for routing.
pub struct ScopeMap {
    entries: HashMap<ScopeKey, Vec<ScopeEntry>>,
    bundles: Vec<Arc<Bundle>>,
}

/// Result of a successful lookup — the response bytes plus the window
/// from the serving bundle for HTTP header generation.
pub struct LookupResult {
    pub response_bytes: Vec<u8>,
    pub window: ahu::Window,
    pub ca_label: String,
    pub nonce_policy: String,
    pub forward_to: Option<String>,
}

/// The responder's loaded state: bundles indexed by CA scope,
/// with persistent anti-rollback state.
pub struct ResponderState {
    scope_map: ArcSwap<ScopeMap>,
    pub config: Config,
    state_store: Mutex<StateStore>,
}

impl ResponderState {
    pub fn load(config: Config) -> Result<Self> {
        let state_db_path = config.storage.state_db.join("state.json");
        let mut state_store = StateStore::open(&state_db_path)?;
        let scope_map = load_scope_map(&config, &mut state_store)?;
        Ok(ResponderState {
            scope_map: ArcSwap::from_pointee(scope_map),
            config,
            state_store: Mutex::new(state_store),
        })
    }

    /// Look up a CertID across all loaded CA scopes.
    ///
    /// Routes by (issuerNameHash, issuerKeyHash) to find candidate bundles,
    /// then searches each by entry_key. On collision (multiple bundles hold
    /// an entry for the same serial), logs a warning and returns the first
    /// by configuration order.
    pub fn lookup(&self, cert_id: &ParsedCertId) -> Option<LookupResult> {
        let map = self.scope_map.load();
        let key = (
            cert_id.issuer_name_hash.clone(),
            cert_id.issuer_key_hash.clone(),
        );

        let scope_entries = map.entries.get(&key)?;

        let mut hits: Vec<(&ScopeEntry, Vec<u8>, ahu::Window)> = Vec::new();

        for entry in scope_entries {
            let bundle = &map.bundles[entry.bundle_idx];
            if let Some(response_bytes) = bundle.lookup(&cert_id.entry_key) {
                hits.push((
                    entry,
                    response_bytes.to_vec(),
                    bundle.manifest.window.clone(),
                ));
            }
        }

        let make_result =
            |entry: &ScopeEntry, response_bytes: Vec<u8>, window: ahu::Window| LookupResult {
                response_bytes,
                window,
                ca_label: entry.ca_label.clone(),
                nonce_policy: entry.nonce_policy.clone(),
                forward_to: entry.forward_to.clone(),
            };

        match hits.len() {
            0 => None,
            1 => {
                let (entry, response_bytes, window) = hits.into_iter().next().unwrap();
                Some(make_result(entry, response_bytes, window))
            }
            n => {
                warn!(
                    count = n,
                    serial = hex::encode(&cert_id.serial_number),
                    issuer_key_hash = hex::encode(&cert_id.issuer_key_hash),
                    "multiple scopes hold entry for same serial — answering from first by config order"
                );
                let (entry, response_bytes, window) = hits.into_iter().next().unwrap();
                Some(make_result(entry, response_bytes, window))
            }
        }
    }

    /// Get the first loaded bundle's window (for backward compatibility
    /// with single-CA deployments). Prefer `LookupResult.window` when
    /// a specific lookup succeeded.
    pub fn default_window(&self) -> Option<ahu::Window> {
        let map = self.scope_map.load();
        map.bundles.first().map(|b| b.manifest.window.clone())
    }

    /// Total entry count across all loaded bundles.
    pub fn total_entries(&self) -> u64 {
        let map = self.scope_map.load();
        map.bundles.iter().map(|b| b.manifest.entry_count).sum()
    }

    /// Number of loaded bundles.
    pub fn bundle_count(&self) -> usize {
        let map = self.scope_map.load();
        map.bundles.len()
    }

    /// Scope count (number of distinct routing keys).
    pub fn scope_count(&self) -> usize {
        let map = self.scope_map.load();
        map.entries.len()
    }

    /// Get info about all loaded scopes for diagnostics.
    pub fn scope_info(&self) -> Vec<(String, u64, String)> {
        let map = self.scope_map.load();
        let mut info = Vec::new();
        for entries in map.entries.values() {
            for entry in entries {
                let bundle = &map.bundles[entry.bundle_idx];
                info.push((
                    entry.ca_label.clone(),
                    bundle
                        .manifest
                        .ca_scopes
                        .first()
                        .map(|s| s.epoch)
                        .unwrap_or(0),
                    entry.completeness.clone(),
                ));
            }
        }
        info
    }

    /// Hot-reload all bundles from disk with anti-rollback checks.
    pub fn reload(&self) -> Result<()> {
        let mut store = self
            .state_store
            .lock()
            .map_err(|e| CoreError::StateStore(format!("state store lock poisoned: {e}")))?;
        let scope_map = load_scope_map(&self.config, &mut store)?;
        let total: u64 = scope_map
            .bundles
            .iter()
            .map(|b| b.manifest.entry_count)
            .sum();
        self.scope_map.store(Arc::new(scope_map));
        info!(total_entries = total, "all bundles reloaded");
        Ok(())
    }
}

fn validate_nonce_config(config: &Config) -> Result<()> {
    for ca in &config.ca {
        match ca.nonce_policy.as_str() {
            "ignore" => {}
            "live" => {
                if config.server.mode == "edge" {
                    return Err(CoreError::Config(format!(
                        "CA '{}': nonce_policy \"live\" requires signer or combined mode \
                         (edge nodes have no signing key)",
                        ca.label
                    )));
                }
                if ca.signing_key.is_none() {
                    return Err(CoreError::Config(format!(
                        "CA '{}': nonce_policy \"live\" requires a signing_key",
                        ca.label
                    )));
                }
            }
            "forward" => {
                if ca.forward_to.is_none() {
                    return Err(CoreError::Config(format!(
                        "CA '{}': nonce_policy \"forward\" requires a forward_to URL",
                        ca.label
                    )));
                }
            }
            other => {
                return Err(CoreError::Config(format!(
                    "CA '{}': unknown nonce_policy \"{other}\" (expected: ignore, live, forward)",
                    ca.label
                )));
            }
        }
    }
    Ok(())
}

fn load_scope_map(config: &Config, state_store: &mut StateStore) -> Result<ScopeMap> {
    validate_nonce_config(config)?;

    let mut bundles: Vec<Arc<Bundle>> = Vec::new();
    let mut entries: HashMap<ScopeKey, Vec<ScopeEntry>> = HashMap::new();
    let mut loaded_paths: HashMap<std::path::PathBuf, usize> = HashMap::new();

    if config.ca.is_empty() {
        let bundle = load_single_bundle(&config.storage.bundle_dir, None)?;
        state_store.check_rollback(&bundle)?;
        state_store.check_continuity(&bundle)?;
        state_store.advance_from_bundle(&bundle)?;
        let bundle_idx = 0;
        register_bundle_scopes(
            &bundle,
            bundle_idx,
            "default",
            "ignore",
            "authoritative-complete",
            None,
            &mut entries,
        );
        bundles.push(Arc::new(bundle));
    } else {
        for ca_config in &config.ca {
            let bundle_path = if let Some(bf) = &ca_config.bundle_file {
                bf.clone()
            } else {
                find_newest_bundle(&config.storage.bundle_dir)?
            };

            let canonical = bundle_path.canonicalize().unwrap_or(bundle_path.clone());

            let bundle_idx = if let Some(&idx) = loaded_paths.get(&canonical) {
                idx
            } else {
                let bundle = load_and_verify_bundle(&bundle_path)?;
                state_store.check_rollback(&bundle)?;
                state_store.check_continuity(&bundle)?;
                state_store.advance_from_bundle(&bundle)?;
                let idx = bundles.len();
                bundles.push(Arc::new(bundle));
                loaded_paths.insert(canonical, idx);
                idx
            };

            register_bundle_scopes(
                &bundles[bundle_idx],
                bundle_idx,
                &ca_config.label,
                &ca_config.nonce_policy,
                &ca_config.completeness,
                ca_config.forward_to.as_deref(),
                &mut entries,
            );
        }
    }

    let scope_count = entries.len();
    let bundle_count = bundles.len();
    info!(
        bundles = bundle_count,
        scopes = scope_count,
        "scope map loaded"
    );

    Ok(ScopeMap { entries, bundles })
}

fn register_bundle_scopes(
    bundle: &Bundle,
    bundle_idx: usize,
    ca_label: &str,
    nonce_policy: &str,
    completeness: &str,
    forward_to: Option<&str>,
    entries: &mut HashMap<ScopeKey, Vec<ScopeEntry>>,
) {
    for scope in &bundle.manifest.ca_scopes {
        let key = (
            scope.issuer_name_hash.clone(),
            scope.issuer_key_hash.clone(),
        );

        let entry = ScopeEntry {
            bundle_idx,
            ca_label: ca_label.to_string(),
            nonce_policy: nonce_policy.to_string(),
            completeness: completeness.to_string(),
            forward_to: forward_to.map(|s| s.to_string()),
        };

        entries.entry(key).or_default().push(entry);

        info!(
            ca = ca_label,
            epoch = scope.epoch,
            issuer_key_hash =
                hex::encode(&scope.issuer_key_hash[..8.min(scope.issuer_key_hash.len())]),
            "registered CA scope"
        );
    }
}

fn load_single_bundle(bundle_dir: &Path, bundle_file: Option<&Path>) -> Result<Bundle> {
    let path = if let Some(bf) = bundle_file {
        bf.to_path_buf()
    } else {
        find_newest_bundle(bundle_dir)?
    };
    load_and_verify_bundle(&path)
}

fn load_and_verify_bundle(path: &Path) -> Result<Bundle> {
    info!(path = %path.display(), "loading bundle");
    let bundle = Bundle::from_file(path)?;

    let result = ahu::verify_structure(&bundle)?;
    if !result.warnings.is_empty() {
        for w in &result.warnings {
            warn!(warning = w, "bundle verification warning");
        }
    }

    info!(
        entry_count = bundle.manifest.entry_count,
        producer = %bundle.manifest.producer_id,
        scopes = bundle.manifest.ca_scopes.len(),
        "bundle loaded and verified"
    );

    Ok(bundle)
}

fn find_newest_bundle(dir: &Path) -> Result<std::path::PathBuf> {
    let ahu_files: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "ahu"))
        .map(|e| e.path())
        .collect();

    if ahu_files.is_empty() {
        return Err(CoreError::Config(format!(
            "no .ahu files in {}",
            dir.display()
        )));
    }

    // Select the bundle with the highest max epoch across its CA scopes.
    // Bundles that fail to parse are skipped with a warning.
    let mut best: Option<(std::path::PathBuf, u64)> = None;
    for path in &ahu_files {
        let max_epoch = match ahu::Bundle::from_file(path) {
            Ok(bundle) => bundle
                .manifest
                .ca_scopes
                .iter()
                .map(|s| s.epoch)
                .max()
                .unwrap_or(0),
            Err(e) => {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to parse bundle for epoch selection, skipping"
                );
                continue;
            }
        };
        if best.as_ref().is_none_or(|(_, e)| max_epoch > *e) {
            best = Some((path.clone(), max_epoch));
        }
    }

    best.map(|(p, _)| p)
        .ok_or_else(|| CoreError::Config(format!("no valid .ahu files in {}", dir.display())))
}
