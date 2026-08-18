use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

use ahu::Bundle;
use crate::error::{CoreError, Result};

#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedState {
    high_water_marks: HashMap<String, u64>,
    manifest_digests: HashMap<String, String>,
}

impl PersistedState {
    fn make_key(producer_id: &str, issuer_key_hash_hex: &str) -> String {
        format!("{producer_id}:{issuer_key_hash_hex}")
    }
}

pub struct StateStore {
    path: PathBuf,
    state: PersistedState,
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
        })
    }

    pub fn get_high_water(
        &self,
        producer_id: &str,
        issuer_key_hash_hex: &str,
    ) -> Option<u64> {
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
        let key = PersistedState::make_key(producer_id, issuer_key_hash_hex);
        self.state.high_water_marks.insert(key.clone(), epoch);
        self.state
            .manifest_digests
            .insert(key, hex::encode(manifest_digest));
        self.persist()
    }

    pub fn check_rollback(&self, bundle: &Bundle) -> Result<()> {
        let producer_id = &bundle.manifest.producer_id;
        for scope in &bundle.manifest.ca_scopes {
            let ikh = hex::encode(&scope.issuer_key_hash);
            if let Some(hw) = self.get_high_water(producer_id, &ikh) {
                if scope.epoch <= hw {
                    return Err(CoreError::EpochRollback {
                        scope: format!("{}:{}", producer_id, &ikh[..16.min(ikh.len())]),
                        epoch: scope.epoch,
                        high_water: hw,
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
                    if *prev_digest != recorded {
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
        let producer_id = bundle.manifest.producer_id.clone();
        let manifest_digest: [u8; 32] = Sha256::digest(&bundle.manifest_bytes).into();

        for scope in &bundle.manifest.ca_scopes {
            let ikh = hex::encode(&scope.issuer_key_hash);
            self.advance(&producer_id, &ikh, scope.epoch, manifest_digest)?;
        }
        Ok(())
    }

    fn persist(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.state).map_err(|e| {
            CoreError::StateStore(format!("failed to serialize state: {e}"))
        })?;

        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, &json).map_err(|e| {
            CoreError::StateStore(format!(
                "failed to write temp state file {}: {e}",
                tmp_path.display()
            ))
        })?;
        std::fs::rename(&tmp_path, &self.path).map_err(|e| {
            CoreError::StateStore(format!(
                "failed to rename {} → {}: {e}",
                tmp_path.display(),
                self.path.display()
            ))
        })?;
        Ok(())
    }
}
