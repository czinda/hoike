use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::error::{CoreError, Result};
use ahu::Bundle;

/// Maximum allowed epoch jump from the current high-water mark.
/// Prevents a poisoned bundle with epoch = u64::MAX from permanently
/// locking out a CA. Kept as defense-in-depth even with CMS seal
/// verification, since seal trust-anchor enforcement is optional.
pub const MAX_EPOCH_JUMP: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedState {
    high_water_marks: HashMap<String, u64>,
    manifest_digests: HashMap<String, String>,
    /// Immutable bundle snapshots committed with the rollback marks.
    #[serde(default)]
    active_bundles: HashMap<String, PathBuf>,
}

impl PersistedState {
    fn make_key(producer_id: &str, issuer_key_hash_hex: &str) -> String {
        format!("{producer_id}:{issuer_key_hash_hex}")
    }
}

#[derive(Clone)]
pub struct StateStore {
    path: PathBuf,
    state: PersistedState,
    staged: bool,
}

impl StateStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    CoreError::StateStore(format!(
                        "failed to create state directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }

        let state = if path.exists() {
            let contents = std::fs::read_to_string(path).map_err(|e| {
                CoreError::StateStore(format!("failed to read state file {}: {e}", path.display()))
            })?;
            serde_json::from_str(&contents).map_err(|e| {
                CoreError::StateStore(format!(
                    "failed to parse state file {}: {e}",
                    path.display()
                ))
            })?
        } else {
            info!(path = %path.display(), "no existing state file — initializing fresh state");
            PersistedState::default()
        };

        Ok(StateStore {
            path: path.to_path_buf(),
            state,
            staged: false,
        })
    }

    pub fn get_high_water(&self, producer_id: &str, issuer_key_hash_hex: &str) -> Option<u64> {
        let key = PersistedState::make_key(producer_id, issuer_key_hash_hex);
        self.state.high_water_marks.get(&key).copied()
    }

    pub fn get_manifest_digest(
        &self,
        producer_id: &str,
        issuer_key_hash_hex: &str,
    ) -> Option<[u8; 32]> {
        let key = PersistedState::make_key(producer_id, issuer_key_hash_hex);
        self.state.manifest_digests.get(&key).and_then(|hex_str| {
            let bytes = hex::decode(hex_str).ok()?;
            <[u8; 32]>::try_from(bytes.as_slice()).ok()
        })
    }

    pub fn advance(
        &mut self,
        producer_id: &str,
        issuer_key_hash_hex: &str,
        epoch: u64,
        manifest_digest: [u8; 32],
    ) -> Result<()> {
        let mut next = self.clone();
        let key = PersistedState::make_key(producer_id, issuer_key_hash_hex);
        let current = next.state.high_water_marks.get(&key).copied();
        if current.is_none_or(|current| epoch > current) {
            next.state.high_water_marks.insert(key.clone(), epoch);
            next.state
                .manifest_digests
                .insert(key, hex::encode(manifest_digest));
            if !self.staged {
                next.persist()?;
            }
            self.state = next.state;
        }
        Ok(())
    }

    pub(crate) fn transaction(&self) -> Self {
        let mut candidate = self.clone();
        candidate.staged = true;
        candidate.state.active_bundles.clear();
        candidate
    }

    pub(crate) fn commit(&mut self, candidate: Self) -> Result<()> {
        candidate.persist()?;
        self.state = candidate.state;
        // Only collect after the new descriptor is durable. In-flight requests
        // hold heap bundles; an unlinked prior snapshot cannot change their data.
        let dir = self
            .path
            .parent()
            .unwrap_or(Path::new("."))
            .join("generations");
        if let Ok(files) = std::fs::read_dir(&dir) {
            for file in files.flatten() {
                let path = file.path();
                let generated = path.extension().is_some_and(|ext| ext == "ahu")
                    && path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .is_some_and(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()));
                if generated
                    && !self
                        .state
                        .active_bundles
                        .values()
                        .any(|active| active == &path)
                {
                    if let Err(error) = std::fs::remove_file(&path) {
                        tracing::warn!(%error, "could not remove obsolete generation snapshot");
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn active_bundles(&self) -> &HashMap<String, PathBuf> {
        &self.state.active_bundles
    }

    /// Persist immutable content before the descriptor that references it.
    pub(crate) fn snapshot(&mut self, label: &str, bundle: &Bundle) -> Result<()> {
        let bytes = bundle.to_bytes()?;
        let digest = hex::encode(Sha256::digest(&bytes));
        let dir = self
            .path
            .parent()
            .unwrap_or(Path::new("."))
            .join("generations");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{digest}.ahu"));
        // Existing blobs are verified, never trusted solely by their filename.
        if !path.exists() || std::fs::read(&path)? != bytes {
            Self::write_atomic(&path, &bytes)?;
        }
        self.state.active_bundles.insert(label.to_owned(), path);
        Ok(())
    }

    pub fn check_rollback(&self, bundle: &Bundle) -> Result<()> {
        let producer_id = &bundle.manifest.producer_id;
        let manifest_digest: [u8; 32] = Sha256::digest(&bundle.manifest_bytes).into();
        for scope in &bundle.manifest.ca_scopes {
            let ikh = hex::encode(&scope.issuer_key_hash);
            if let Some(hw) = self.get_high_water(producer_id, &ikh) {
                // A strictly older epoch is always a rollback.
                if scope.epoch < hw {
                    return Err(CoreError::EpochRollback {
                        scope: format!("{}:{}", producer_id, &ikh[..16.min(ikh.len())]),
                        epoch: scope.epoch,
                        high_water: hw,
                    });
                }
                // Re-loading at the current high-water epoch is legitimate only
                // when it is the *same* bundle (identical manifest digest) — e.g.
                // a process restart reloading its own state. A *different* bundle
                // at the same epoch is a fork/rollback attack and is rejected.
                if scope.epoch == hw
                    && self.get_manifest_digest(producer_id, &ikh) != Some(manifest_digest)
                {
                    return Err(CoreError::EpochRollback {
                        scope: format!("{}:{}", producer_id, &ikh[..16.min(ikh.len())]),
                        epoch: scope.epoch,
                        high_water: hw,
                    });
                }
                let jump = scope.epoch - hw;
                if jump > MAX_EPOCH_JUMP {
                    return Err(CoreError::EpochJumpTooLarge {
                        scope: format!("{}:{}", producer_id, &ikh[..16.min(ikh.len())]),
                        epoch: scope.epoch,
                        high_water: hw,
                        jump,
                        max_jump: MAX_EPOCH_JUMP,
                    });
                }
            }
        }
        Ok(())
    }

    pub fn check_continuity(&self, bundle: &Bundle) -> Result<()> {
        if let Some(prev_digest) = &bundle.manifest.continuity.prev_manifest_digest {
            let producer_id = &bundle.manifest.producer_id;
            for scope in &bundle.manifest.ca_scopes {
                let ikh = hex::encode(&scope.issuer_key_hash);
                if let Some(recorded) = self.get_manifest_digest(producer_id, &ikh) {
                    let digest: [u8; 32] = Sha256::digest(&bundle.manifest_bytes).into();
                    let identical = self.get_high_water(producer_id, &ikh) == Some(scope.epoch)
                        && digest == recorded;
                    if !identical && *prev_digest != recorded {
                        return Err(CoreError::ForkDetected {
                            scope: format!("{}:{}", producer_id, &ikh[..16.min(ikh.len())]),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    pub fn advance_from_bundle(&mut self, bundle: &Bundle) -> Result<()> {
        let mut candidate = self.clone();
        candidate.staged = true;
        let digest: [u8; 32] = Sha256::digest(&bundle.manifest_bytes).into();
        for scope in &bundle.manifest.ca_scopes {
            candidate.advance(
                &bundle.manifest.producer_id,
                &hex::encode(&scope.issuer_key_hash),
                scope.epoch,
                digest,
            )?;
        }
        if !self.staged {
            candidate.persist()?;
        }
        self.state = candidate.state;
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        let json = serde_json::to_vec_pretty(&self.state)
            .map_err(|e| CoreError::StateStore(format!("failed to serialize state: {e}")))?;
        Self::write_atomic(&self.path, &json)
    }

    fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let tmp = path.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| -> Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            std::fs::rename(&tmp, path)?;
            std::fs::File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }
}
