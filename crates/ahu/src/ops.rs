//! Pure bundle operations shared by the CLI and admin API: structural diff and
//! delta-chain application. These functions take parsed `Bundle`s and return
//! data structures — no printing, no filesystem, no `std::process::exit`. The
//! CLI formats the result for a terminal; the server serializes it to JSON.

use std::collections::{BTreeMap, HashSet};

use sha2::{Digest, Sha256};

use crate::bundle::{Bundle, BundleBuilder};
use crate::error::{AhuError, Result};
use crate::index::{self, IndexFlags};
use crate::manifest::BundleType;

/// A single entry identified by its key plus algorithm discriminator. Dual-algorithm
/// bundles hold the same `entry_key` under different discriminators, so both fields
/// are needed to name an entry uniquely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryRef {
    pub entry_key: [u8; 32],
    pub discriminator: u16,
}

/// Structural difference between two bundles (A → B), computed over
/// `(entry_key, discriminator)` pairs. "Changed" means the key exists in both
/// but the response bytes differ.
#[derive(Debug, Clone)]
pub struct DiffResult {
    pub a_entry_count: usize,
    pub b_entry_count: usize,
    pub a_epochs: Vec<u64>,
    pub b_epochs: Vec<u64>,
    pub added: Vec<EntryRef>,
    pub removed: Vec<EntryRef>,
    pub changed: Vec<EntryRef>,
    pub unchanged: usize,
}

/// Compute the structural diff of two bundles. Never fails: it only reads the
/// already-parsed index and data sections.
pub fn diff(a: &Bundle, b: &Bundle) -> DiffResult {
    let a_keys: HashSet<([u8; 32], u16)> = a
        .index
        .iter()
        .map(|r| (r.entry_key, r.discriminator))
        .collect();
    let b_keys: HashSet<([u8; 32], u16)> = b
        .index
        .iter()
        .map(|r| (r.entry_key, r.discriminator))
        .collect();

    let to_ref = |(entry_key, discriminator): &([u8; 32], u16)| EntryRef {
        entry_key: *entry_key,
        discriminator: *discriminator,
    };

    let added: Vec<EntryRef> = b_keys.difference(&a_keys).map(to_ref).collect();
    let removed: Vec<EntryRef> = a_keys.difference(&b_keys).map(to_ref).collect();

    let mut changed = Vec::new();
    let mut unchanged = 0usize;
    for pair @ (key, disc) in a_keys.intersection(&b_keys) {
        let a_data = index::binary_search_with_discriminator(&a.index, key, *disc)
            .and_then(|idx| a.entry_at(idx));
        let b_data = index::binary_search_with_discriminator(&b.index, key, *disc)
            .and_then(|idx| b.entry_at(idx));
        if a_data != b_data {
            changed.push(to_ref(pair));
        } else {
            unchanged += 1;
        }
    }

    DiffResult {
        a_entry_count: a.index.len(),
        b_entry_count: b.index.len(),
        a_epochs: a.manifest.ca_scopes.iter().map(|s| s.epoch).collect(),
        b_epochs: b.manifest.ca_scopes.iter().map(|s| s.epoch).collect(),
        added,
        removed,
        changed,
        unchanged,
    }
}

/// Per-delta application statistics.
#[derive(Debug, Clone)]
pub struct DeltaStat {
    pub added: usize,
    pub replaced: usize,
    pub removed: usize,
    /// The delta's `chain_length` exceeded the recommended maximum (24).
    pub chain_length_warning: bool,
}

/// Result of materializing a base bundle plus an ordered chain of deltas.
#[derive(Debug, Clone)]
pub struct ApplyResult {
    /// Serialized full bundle bytes.
    pub bytes: Vec<u8>,
    pub entry_count: usize,
    /// Epoch assigned to the materialized bundle's scopes (max seen + 1).
    pub final_epoch: u64,
    pub deltas: Vec<DeltaStat>,
}

/// Recommended maximum delta-chain length before a full re-base is advised.
pub const MAX_CHAIN_LENGTH: u64 = 24;

/// Apply an ordered chain of delta bundles onto a full base bundle, producing a
/// materialized full bundle. Verifies the continuity chain (base digest, then
/// `prev_manifest_digest` links) and rejects type mismatches. Callers are
/// responsible for having verified each bundle's structure beforehand if desired.
pub fn apply(base: &Bundle, deltas: &[Bundle]) -> Result<ApplyResult> {
    if base.manifest.bundle_type != BundleType::Full {
        return Err(AhuError::InvalidOperation(
            "base bundle must be a full bundle, not a delta".into(),
        ));
    }

    // Working set keyed by (entry_key, discriminator) so dual-algorithm entries
    // are tracked independently.
    let mut working_set: BTreeMap<([u8; 32], u16), (Vec<u8>, IndexFlags)> = BTreeMap::new();
    for record in &base.index {
        if let Some(data) = base.entry_bytes(record) {
            working_set.insert(
                (record.entry_key, record.discriminator),
                (data.to_vec(), record.flags),
            );
        }
    }

    let base_manifest_digest = crate::manifest_digest(&base.manifest_bytes);
    let mut prev_manifest_digest = base_manifest_digest;
    let mut max_epoch = base
        .manifest
        .ca_scopes
        .iter()
        .map(|s| s.epoch)
        .max()
        .unwrap_or(0);

    let mut stats = Vec::with_capacity(deltas.len());

    for (i, delta) in deltas.iter().enumerate() {
        if delta.manifest.bundle_type != BundleType::Delta {
            return Err(AhuError::InvalidOperation(format!(
                "delta {} is a full bundle, expected a delta",
                i + 1
            )));
        }

        // First delta must chain from the base.
        if i == 0 {
            if let Some(ref base_digest) = delta.manifest.continuity.base_manifest_digest {
                if *base_digest != base_manifest_digest {
                    return Err(AhuError::InvalidOperation(format!(
                        "delta {} base_manifest_digest does not match base bundle",
                        i + 1
                    )));
                }
            }
        }

        // Every delta must chain from its predecessor.
        if let Some(ref prev_digest) = delta.manifest.continuity.prev_manifest_digest {
            if *prev_digest != prev_manifest_digest {
                return Err(AhuError::InvalidOperation(format!(
                    "delta {} prev_manifest_digest chain broken (expected {}, got {})",
                    i + 1,
                    hex::encode(prev_manifest_digest),
                    hex::encode(prev_digest),
                )));
            }
        }

        let chain_length_warning = delta.manifest.continuity.chain_length > MAX_CHAIN_LENGTH;

        let mut added = 0usize;
        let mut replaced = 0usize;
        let mut removed = 0usize;

        for record in &delta.index {
            let key = (record.entry_key, record.discriminator);
            if record.flags.contains(IndexFlags::TOMBSTONE) {
                if working_set.remove(&key).is_some() {
                    removed += 1;
                }
            } else if let Some(data) = delta.entry_bytes(record) {
                if working_set
                    .insert(key, (data.to_vec(), record.flags))
                    .is_some()
                {
                    replaced += 1;
                } else {
                    added += 1;
                }
            }
        }

        for scope in &delta.manifest.ca_scopes {
            max_epoch = max_epoch.max(scope.epoch);
        }
        prev_manifest_digest = crate::manifest_digest(&delta.manifest_bytes);

        stats.push(DeltaStat {
            added,
            replaced,
            removed,
            chain_length_warning,
        });
    }

    // Build the materialized full bundle from the base manifest.
    let mut manifest = base.manifest.clone();
    manifest.bundle_type = BundleType::Full;
    manifest.continuity.chain_length = 0;
    manifest.continuity.prev_manifest_digest = Some(prev_manifest_digest);
    manifest.continuity.base_manifest_digest = None;

    let final_epoch = max_epoch + 1;
    for scope in &mut manifest.ca_scopes {
        scope.epoch = final_epoch;
    }

    let mut builder = BundleBuilder::new(manifest);
    for ((entry_key, disc), (data, _flags)) in &working_set {
        builder.add_entry_with_discriminator(*entry_key, *disc, data.clone());
    }

    let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec()))?;
    let entry_count = working_set.len();

    Ok(ApplyResult {
        bytes,
        entry_count,
        final_epoch,
        deltas: stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        CaScope, Completeness, Continuity, Integrity, Manifest, ResponderId, ResponderIdType,
        Window,
    };
    use uuid::Uuid;

    /// Build a bare manifest of the given type/epoch. Continuity is filled in by
    /// the caller for delta cases.
    fn manifest(bundle_type: BundleType, epoch: u64) -> Manifest {
        Manifest {
            format_version: 1,
            bundle_id: Uuid::nil(),
            producer_id: "test".into(),
            created_at: 1700000000,
            bundle_type,
            ca_scopes: vec![CaScope {
                hash_algorithm: vec![0x01],
                issuer_name_hash: vec![0xAA; 32],
                issuer_key_hash: vec![0xBB; 32],
                epoch,
                responder_id: ResponderId {
                    id_type: ResponderIdType::ByKey,
                    value: vec![0xCC; 20],
                },
                responder_chain: None,
                signature_algorithm: vec![0x02],
                completeness: Completeness::AuthoritativeComplete,
            }],
            window: Window {
                produced_at: 1700000000,
                this_update_min: 1700000000,
                next_update_min: 1700086400,
                next_update_max: 1700093600,
            },
            integrity: Integrity {
                index_digest: [0; 32],
                data_digest: [0; 32],
            },
            entry_count: 0,
            continuity: Continuity {
                prev_manifest_digest: None,
                base_manifest_digest: None,
                chain_length: 0,
            },
            shard: None,
            compression: None,
            extensions: None,
        }
    }

    fn seal(m: &[u8]) -> Result<Vec<u8>> {
        Ok(Sha256::digest(m).to_vec())
    }

    fn key(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// Build a full base bundle with the given (key_byte, response) entries.
    fn full_bundle(epoch: u64, entries: &[(u8, &[u8])]) -> Bundle {
        let mut builder = BundleBuilder::new(manifest(BundleType::Full, epoch));
        for (k, resp) in entries {
            builder.add_entry(key(*k), resp.to_vec());
        }
        let bytes = builder.build(seal).unwrap();
        Bundle::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn diff_detects_added_removed_changed() {
        // A: {1 => "old", 2 => "same"}   B: {2 => "same", 3 => "new"} with 1 changed dropped.
        let a = full_bundle(1, &[(1, b"one"), (2, b"same")]);
        // B replaces key 2's payload, drops key 1, adds key 3.
        let b = full_bundle(2, &[(2, b"CHANGED"), (3, b"three")]);

        let d = diff(&a, &b);
        assert_eq!(d.a_entry_count, 2);
        assert_eq!(d.b_entry_count, 2);
        assert_eq!(d.a_epochs, vec![1]);
        assert_eq!(d.b_epochs, vec![2]);

        assert_eq!(d.added.len(), 1, "key 3 added");
        assert_eq!(d.added[0].entry_key, key(3));
        assert_eq!(d.removed.len(), 1, "key 1 removed");
        assert_eq!(d.removed[0].entry_key, key(1));
        assert_eq!(d.changed.len(), 1, "key 2 payload changed");
        assert_eq!(d.changed[0].entry_key, key(2));
        assert_eq!(d.unchanged, 0);
    }

    #[test]
    fn diff_identical_bundles_all_unchanged() {
        let a = full_bundle(1, &[(1, b"one"), (2, b"two")]);
        let b = full_bundle(1, &[(1, b"one"), (2, b"two")]);
        let d = diff(&a, &b);
        assert!(d.added.is_empty());
        assert!(d.removed.is_empty());
        assert!(d.changed.is_empty());
        assert_eq!(d.unchanged, 2);
    }

    /// Build a delta that chains from `prev` (which may be the base or a prior
    /// delta), setting continuity digests correctly.
    fn delta_from(
        prev: &Bundle,
        base: &Bundle,
        epoch: u64,
        chain_length: u64,
        adds: &[(u8, &[u8])],
        tombstones: &[u8],
    ) -> Bundle {
        let mut m = manifest(BundleType::Delta, epoch);
        m.continuity.base_manifest_digest = Some(crate::manifest_digest(&base.manifest_bytes));
        m.continuity.prev_manifest_digest = Some(crate::manifest_digest(&prev.manifest_bytes));
        m.continuity.chain_length = chain_length;
        let mut builder = BundleBuilder::new(m);
        for (k, resp) in adds {
            builder.add_entry(key(*k), resp.to_vec());
        }
        for k in tombstones {
            builder.add_tombstone(key(*k), 0);
        }
        let bytes = builder.build(seal).unwrap();
        Bundle::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn apply_single_delta_add_replace_remove() {
        let base = full_bundle(5, &[(1, b"one"), (2, b"two")]);
        // Delta: replace 1, remove 2, add 3.
        let delta = delta_from(&base, &base, 6, 1, &[(1, b"ONE"), (3, b"three")], &[2]);

        let result = apply(&base, &[delta]).unwrap();
        assert_eq!(result.entry_count, 2, "one + three remain (two tombstoned)");
        assert_eq!(result.final_epoch, 7, "max epoch (6) + 1");
        assert_eq!(result.deltas.len(), 1);
        assert_eq!(result.deltas[0].added, 1, "key 3");
        assert_eq!(result.deltas[0].replaced, 1, "key 1");
        assert_eq!(result.deltas[0].removed, 1, "key 2");
        assert!(!result.deltas[0].chain_length_warning);

        // The materialized bundle must parse and reflect the applied changes.
        let materialized = Bundle::from_bytes(&result.bytes).unwrap();
        assert_eq!(materialized.manifest.bundle_type, BundleType::Full);
        assert_eq!(materialized.index.len(), 2);
        let idx1 =
            index::binary_search_with_discriminator(&materialized.index, &key(1), 0).unwrap();
        assert_eq!(materialized.entry_at(idx1), Some(&b"ONE"[..]));
        assert!(index::binary_search_with_discriminator(&materialized.index, &key(2), 0).is_none());
    }

    #[test]
    fn apply_two_delta_chain() {
        let base = full_bundle(5, &[(1, b"one")]);
        let d1 = delta_from(&base, &base, 6, 1, &[(2, b"two")], &[]);
        let d2 = delta_from(&d1, &base, 7, 2, &[(3, b"three")], &[]);

        let result = apply(&base, &[d1, d2]).unwrap();
        assert_eq!(result.entry_count, 3);
        assert_eq!(result.final_epoch, 8);
        assert_eq!(result.deltas.len(), 2);
    }

    #[test]
    fn apply_rejects_full_bundle_as_delta() {
        let base = full_bundle(5, &[(1, b"one")]);
        let not_a_delta = full_bundle(6, &[(2, b"two")]);
        let err = apply(&base, &[not_a_delta]).unwrap_err();
        assert!(matches!(err, AhuError::InvalidOperation(_)));
    }

    #[test]
    fn apply_rejects_delta_as_base() {
        let base = full_bundle(5, &[(1, b"one")]);
        let delta = delta_from(&base, &base, 6, 1, &[(2, b"two")], &[]);
        // Passing the delta as the base must be rejected.
        let err = apply(&delta, &[]).unwrap_err();
        assert!(matches!(err, AhuError::InvalidOperation(_)));
    }

    #[test]
    fn apply_rejects_broken_chain() {
        let base = full_bundle(5, &[(1, b"one")]);
        let d1 = delta_from(&base, &base, 6, 1, &[(2, b"two")], &[]);
        // d2 chains from d1, but we apply [d2] directly onto base — prev digest mismatch.
        let d2 = delta_from(&d1, &base, 7, 2, &[(3, b"three")], &[]);
        let err = apply(&base, &[d2]).unwrap_err();
        assert!(matches!(err, AhuError::InvalidOperation(_)));
    }

    #[test]
    fn apply_flags_chain_length_warning() {
        let base = full_bundle(5, &[(1, b"one")]);
        let delta = delta_from(&base, &base, 6, MAX_CHAIN_LENGTH + 1, &[(2, b"two")], &[]);
        let result = apply(&base, &[delta]).unwrap();
        assert!(result.deltas[0].chain_length_warning);
    }
}
