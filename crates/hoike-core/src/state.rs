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
    /// Open existing state, strictly (F04).
    ///
    /// Missing or malformed state is an error, never a silently fresh
    /// timeline: forgetting recorded high-water marks would let an older
    /// bundle be served again. Valid legacy JSON is preserved. Committed
    /// snapshots must exist, match their content digest, and carry rollback
    /// marks — incomplete committed state is a recovery failure.
    pub fn open(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| {
            CoreError::StateStore(format!(
                "cannot open state file {}: {e}. State is never created implicitly; \
                 run `hoike init-state` to initialize a new state directory, or restore \
                 the state file together with its committed snapshots",
                path.display()
            ))
        })?;
        let state: PersistedState = serde_json::from_str(&contents).map_err(|e| {
            CoreError::StateStore(format!(
                "failed to parse state file {}: {e}. Restore the state directory from \
                 backup; this release has no automatic recovery and no reset escape hatch",
                path.display()
            ))
        })?;
        validate_persisted(&state, path)?;
        Ok(StateStore {
            path: path.to_path_buf(),
            state,
            staged: false,
        })
    }

    /// Explicitly initialize a fresh state directory (F04).
    ///
    /// Initialization is the operator's acknowledgment that this directory is
    /// new. It refuses an existing state file and refuses a directory holding
    /// any recovery material (snapshots, cookies, unknown files) so a partial
    /// restore can never be silently reset. Only the writer lock file is
    /// ignored when checking emptiness. Creating the directory does not by
    /// itself authorize resetting it.
    pub fn initialize(path: &Path) -> Result<Self> {
        if path.exists() {
            return Err(CoreError::StateStore(format!(
                "refusing to initialize {}: state file already exists — existing state is \
                 never reset; restore marks and snapshots together to recover",
                path.display()
            )));
        }
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if dir.exists() {
            // Any content besides the writer lock file is recovery material:
            // a partial restore must never be silently reset.
            let entries = std::fs::read_dir(dir).map_err(|e| {
                CoreError::StateStore(format!(
                    "failed to inspect state directory {}: {e}",
                    dir.display()
                ))
            })?;
            for entry in entries {
                let entry = entry.map_err(|e| {
                    CoreError::StateStore(format!(
                        "failed to inspect state directory {}: {e}",
                        dir.display()
                    ))
                })?;
                if entry.file_name() != crate::storage::WRITER_LOCK_FILE {
                    return Err(CoreError::StateStore(format!(
                        "refusing to initialize state in {}: directory already contains \
                         '{}' — restore state and recovery material together instead of \
                         re-initializing",
                        dir.display(),
                        entry.file_name().to_string_lossy()
                    )));
                }
            }
        } else {
            std::fs::create_dir_all(dir).map_err(|e| {
                CoreError::StateStore(format!(
                    "failed to create state directory {}: {e}",
                    dir.display()
                ))
            })?;
        }
        let store = StateStore {
            path: path.to_path_buf(),
            state: PersistedState::default(),
            staged: false,
        };
        store.persist()?;
        info!(path = %path.display(), "initialized fresh state directory");
        Ok(store)
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

    /// Stage a transaction candidate against this store (design §S5).
    ///
    /// A single-label installation stages into the candidate while
    /// **preserving** other labels' committed snapshots. Callers performing
    /// a full working-set reload must call [`Self::clear_active_bundles`]
    /// explicitly, so the reload builds a replacement working set instead of
    /// merging into whatever was committed before.
    pub(crate) fn transaction(&self) -> Self {
        let mut candidate = self.clone();
        candidate.staged = true;
        candidate
    }

    /// Drop all committed snapshot references: a full reload replaces the
    /// whole working set rather than merging into it.
    pub(crate) fn clear_active_bundles(&mut self) {
        self.state.active_bundles.clear();
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
            crate::storage::write_atomic(&path, &bytes)?;
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
        crate::storage::write_atomic(&self.path, &json)
    }
}

/// Validate persisted state before it is trusted (F04).
///
/// High-water marks and manifest digests are written as pairs, so a record on
/// one side without its counterpart is a torn write. Every committed snapshot
/// must exist, hash to the digest in its filename, and have its scopes covered
/// by a high-water mark at or above the snapshot's epoch — a missing record
/// referenced by a committed snapshot is recovery failure, not a new scope.
fn validate_persisted(state: &PersistedState, path: &Path) -> Result<()> {
    for (key, digest_hex) in &state.manifest_digests {
        let decoded = hex::decode(digest_hex).map_err(|e| {
            CoreError::StateStore(format!(
                "state file {}: manifest digest for '{key}' is not valid hex: {e}",
                path.display()
            ))
        })?;
        if decoded.len() != 32 {
            return Err(CoreError::StateStore(format!(
                "state file {}: manifest digest for '{key}' has {} bytes, expected 32",
                path.display(),
                decoded.len()
            )));
        }
        if !state.high_water_marks.contains_key(key) {
            return Err(CoreError::StateStore(format!(
                "state file {}: manifest digest for '{key}' has no high-water record — \
                 restore marks and snapshots together",
                path.display()
            )));
        }
    }
    for key in state.high_water_marks.keys() {
        if !state.manifest_digests.contains_key(key) {
            return Err(CoreError::StateStore(format!(
                "state file {}: high-water mark for '{key}' has no manifest digest record — \
                 restore marks and snapshots together",
                path.display()
            )));
        }
    }
    for (label, snapshot) in &state.active_bundles {
        let bytes = std::fs::read(snapshot).map_err(|e| {
            CoreError::StateStore(format!(
                "committed snapshot for '{label}' is missing: {} ({e}) — restore marks and \
                 snapshots together; do not re-initialize",
                snapshot.display()
            ))
        })?;
        let digest_hex = snapshot
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| {
                CoreError::StateStore(format!(
                    "committed snapshot for '{label}' has a malformed name: {}",
                    snapshot.display()
                ))
            })?;
        let expected = hex::decode(digest_hex).map_err(|e| {
            CoreError::StateStore(format!(
                "committed snapshot for '{label}' has a non-digest name: {e}"
            ))
        })?;
        let actual: [u8; 32] = Sha256::digest(&bytes).into();
        if actual.as_slice() != expected.as_slice() {
            return Err(CoreError::StateStore(format!(
                "committed snapshot for '{label}' does not match its digest name: {}",
                snapshot.display()
            )));
        }
        let bundle = Bundle::from_bytes(&bytes).map_err(|e| {
            CoreError::StateStore(format!(
                "committed snapshot for '{label}' is unreadable: {e}",
            ))
        })?;
        for scope in &bundle.manifest.ca_scopes {
            let key = PersistedState::make_key(
                &bundle.manifest.producer_id,
                &hex::encode(&scope.issuer_key_hash),
            );
            match state.high_water_marks.get(&key) {
                Some(hw) if *hw >= scope.epoch => {}
                other => {
                    return Err(CoreError::StateStore(format!(
                        "committed snapshot '{label}' records scope at epoch {} with \
                         high-water {:?} — incomplete committed state requires recovery",
                        scope.epoch, other
                    )));
                }
            }
        }
    }
    Ok(())
}
