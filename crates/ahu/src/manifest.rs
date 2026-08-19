use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bundle type discriminator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BundleType {
    Full = 0,
    Delta = 1,
}

/// Completeness assertion for a CA scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Completeness {
    Partial = 0,
    AuthoritativeComplete = 1,
}

/// ResponderID type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ResponderIdType {
    ByName = 0,
    ByKey = 1,
}

/// ResponderID — type plus DER-encoded value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderId {
    pub id_type: ResponderIdType,
    pub value: Vec<u8>,
}

/// One CA scope within a bundle manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaScope {
    pub hash_algorithm: Vec<u8>,
    pub issuer_name_hash: Vec<u8>,
    pub issuer_key_hash: Vec<u8>,
    pub epoch: u64,
    pub responder_id: ResponderId,
    pub responder_chain: Option<Vec<Vec<u8>>>,
    pub signature_algorithm: Vec<u8>,
    pub completeness: Completeness,
}

/// Time window for the bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    pub produced_at: u64,
    pub this_update_min: u64,
    pub next_update_min: u64,
    pub next_update_max: u64,
}

/// Integrity digests covering the index and data sections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    pub index_digest: [u8; 32],
    pub data_digest: [u8; 32],
}

/// Continuity chain for rollback and fork detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Continuity {
    pub prev_manifest_digest: Option<[u8; 32]>,
    pub base_manifest_digest: Option<[u8; 32]>,
    pub chain_length: u64,
}

/// Shard descriptor for partitioned bundles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    pub shard_index: u64,
    pub shard_count: u64,
    pub shard_fn: u64,
}

/// Compression settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compression {
    pub algorithm: CompressionAlgorithm,
    pub dictionary_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionAlgorithm {
    None = 0,
    Zstd = 1,
}

/// The full manifest, as specified in §2.2 of the ahu format spec.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub format_version: u64,
    pub bundle_id: Uuid,
    pub producer_id: String,
    pub created_at: u64,
    pub bundle_type: BundleType,
    pub ca_scopes: Vec<CaScope>,
    pub window: Window,
    pub integrity: Integrity,
    pub entry_count: u64,
    pub continuity: Continuity,
    pub shard: Option<Shard>,
    pub compression: Option<Compression>,
    pub extensions: Option<Vec<(String, ciborium::Value)>>,
}

// ── Deterministic CBOR encoding ────────────────────────────────────
//
// We encode manually rather than deriving serde for CBOR because
// RFC 8949 §4.2 requires deterministic encoding: definite lengths,
// canonical integer key ordering, shortest-form integers.
// ciborium's serde path doesn't guarantee this.

impl Manifest {
    pub fn to_cbor(&self) -> Vec<u8> {
        use ciborium::Value;

        let responder_id_to_val = |rid: &ResponderId| -> Value {
            Value::Map(vec![
                (
                    Value::Integer(1.into()),
                    Value::Integer((rid.id_type as u8).into()),
                ),
                (Value::Integer(2.into()), Value::Bytes(rid.value.clone())),
            ])
        };

        let ca_scopes: Vec<Value> = self
            .ca_scopes
            .iter()
            .map(|s| {
                let mut entries = vec![
                    (
                        Value::Integer(1.into()),
                        Value::Bytes(s.hash_algorithm.clone()),
                    ),
                    (
                        Value::Integer(2.into()),
                        Value::Bytes(s.issuer_name_hash.clone()),
                    ),
                    (
                        Value::Integer(3.into()),
                        Value::Bytes(s.issuer_key_hash.clone()),
                    ),
                    (Value::Integer(4.into()), Value::Integer((s.epoch).into())),
                    (
                        Value::Integer(5.into()),
                        responder_id_to_val(&s.responder_id),
                    ),
                ];
                if let Some(chain) = &s.responder_chain {
                    entries.push((
                        Value::Integer(6.into()),
                        Value::Array(chain.iter().map(|c| Value::Bytes(c.clone())).collect()),
                    ));
                }
                entries.push((
                    Value::Integer(7.into()),
                    Value::Bytes(s.signature_algorithm.clone()),
                ));
                entries.push((
                    Value::Integer(8.into()),
                    Value::Integer((s.completeness as u8).into()),
                ));
                Value::Map(entries)
            })
            .collect();

        let window = Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Integer((self.window.produced_at).into()),
            ),
            (
                Value::Integer(2.into()),
                Value::Integer((self.window.this_update_min).into()),
            ),
            (
                Value::Integer(3.into()),
                Value::Integer((self.window.next_update_min).into()),
            ),
            (
                Value::Integer(4.into()),
                Value::Integer((self.window.next_update_max).into()),
            ),
        ]);

        let integrity = Value::Map(vec![
            (
                Value::Integer(1.into()),
                Value::Bytes(self.integrity.index_digest.to_vec()),
            ),
            (
                Value::Integer(2.into()),
                Value::Bytes(self.integrity.data_digest.to_vec()),
            ),
        ]);

        let mut continuity_entries = Vec::new();
        if let Some(prev) = &self.continuity.prev_manifest_digest {
            continuity_entries.push((Value::Integer(1.into()), Value::Bytes(prev.to_vec())));
        }
        if let Some(base) = &self.continuity.base_manifest_digest {
            continuity_entries.push((Value::Integer(2.into()), Value::Bytes(base.to_vec())));
        }
        continuity_entries.push((
            Value::Integer(3.into()),
            Value::Integer((self.continuity.chain_length).into()),
        ));
        let continuity = Value::Map(continuity_entries);

        let mut root = vec![
            (
                Value::Integer(1.into()),
                Value::Integer((self.format_version).into()),
            ),
            (
                Value::Integer(2.into()),
                Value::Bytes(self.bundle_id.as_bytes().to_vec()),
            ),
            (
                Value::Integer(3.into()),
                Value::Text(self.producer_id.clone()),
            ),
            (
                Value::Integer(4.into()),
                Value::Integer((self.created_at).into()),
            ),
            (
                Value::Integer(5.into()),
                Value::Integer((self.bundle_type as u8).into()),
            ),
            (Value::Integer(6.into()), Value::Array(ca_scopes)),
            (Value::Integer(7.into()), window),
            (Value::Integer(8.into()), integrity),
            (
                Value::Integer(9.into()),
                Value::Integer((self.entry_count).into()),
            ),
            (Value::Integer(10.into()), continuity),
        ];

        if let Some(shard) = &self.shard {
            root.push((
                Value::Integer(11.into()),
                Value::Map(vec![
                    (
                        Value::Integer(1.into()),
                        Value::Integer((shard.shard_index).into()),
                    ),
                    (
                        Value::Integer(2.into()),
                        Value::Integer((shard.shard_count).into()),
                    ),
                    (
                        Value::Integer(3.into()),
                        Value::Integer((shard.shard_fn).into()),
                    ),
                ]),
            ));
        }

        if let Some(comp) = &self.compression {
            let mut comp_entries = vec![(
                Value::Integer(1.into()),
                Value::Integer((comp.algorithm as u8).into()),
            )];
            if let Some(dict) = &comp.dictionary_digest {
                comp_entries.push((Value::Integer(2.into()), Value::Bytes(dict.to_vec())));
            }
            root.push((Value::Integer(12.into()), Value::Map(comp_entries)));
        }

        if let Some(exts) = &self.extensions {
            let ext_map: Vec<(Value, Value)> = exts
                .iter()
                .map(|(k, v)| (Value::Text(k.clone()), v.clone()))
                .collect();
            root.push((Value::Integer(13.into()), Value::Map(ext_map)));
        }

        let root_val = Value::Map(root);
        let mut buf = Vec::new();
        ciborium::into_writer(&root_val, &mut buf).expect("CBOR encoding cannot fail for Value");
        buf
    }

    pub fn from_cbor(data: &[u8]) -> crate::error::Result<Self> {
        let val: ciborium::Value = ciborium::from_reader(data)
            .map_err(|e| crate::error::AhuError::ManifestDecode(e.to_string()))?;

        let map = val
            .as_map()
            .ok_or_else(|| crate::error::AhuError::ManifestDecode("root is not a map".into()))?;

        fn get_uint(
            map: &[(ciborium::Value, ciborium::Value)],
            key: i128,
        ) -> crate::error::Result<u64> {
            for (k, v) in map {
                if let Some(ki) = k.as_integer() {
                    if i128::from(ki) == key {
                        if let Some(vi) = v.as_integer() {
                            let n: i128 = vi.into();
                            return u64::try_from(n).map_err(|_| {
                                crate::error::AhuError::ManifestField(format!(
                                    "key {key}: integer out of u64 range"
                                ))
                            });
                        }
                        return Err(crate::error::AhuError::ManifestField(format!(
                            "key {key}: expected integer"
                        )));
                    }
                }
            }
            Err(crate::error::AhuError::ManifestField(format!(
                "key {key}: missing"
            )))
        }

        fn get_bytes(
            map: &[(ciborium::Value, ciborium::Value)],
            key: i128,
        ) -> crate::error::Result<Vec<u8>> {
            for (k, v) in map {
                if let Some(ki) = k.as_integer() {
                    if i128::from(ki) == key {
                        if let Some(b) = v.as_bytes() {
                            return Ok(b.to_vec());
                        }
                        return Err(crate::error::AhuError::ManifestField(format!(
                            "key {key}: expected bytes"
                        )));
                    }
                }
            }
            Err(crate::error::AhuError::ManifestField(format!(
                "key {key}: missing"
            )))
        }

        fn get_text(
            map: &[(ciborium::Value, ciborium::Value)],
            key: i128,
        ) -> crate::error::Result<String> {
            for (k, v) in map {
                if let Some(ki) = k.as_integer() {
                    if i128::from(ki) == key {
                        if let Some(s) = v.as_text() {
                            return Ok(s.to_string());
                        }
                        return Err(crate::error::AhuError::ManifestField(format!(
                            "key {key}: expected text"
                        )));
                    }
                }
            }
            Err(crate::error::AhuError::ManifestField(format!(
                "key {key}: missing"
            )))
        }

        fn get_map(
            map: &[(ciborium::Value, ciborium::Value)],
            key: i128,
        ) -> crate::error::Result<&[(ciborium::Value, ciborium::Value)]> {
            for (k, v) in map {
                if let Some(ki) = k.as_integer() {
                    if i128::from(ki) == key {
                        if let Some(m) = v.as_map() {
                            return Ok(m);
                        }
                        return Err(crate::error::AhuError::ManifestField(format!(
                            "key {key}: expected map"
                        )));
                    }
                }
            }
            Err(crate::error::AhuError::ManifestField(format!(
                "key {key}: missing"
            )))
        }

        fn get_array(
            map: &[(ciborium::Value, ciborium::Value)],
            key: i128,
        ) -> crate::error::Result<&[ciborium::Value]> {
            for (k, v) in map {
                if let Some(ki) = k.as_integer() {
                    if i128::from(ki) == key {
                        if let Some(a) = v.as_array() {
                            return Ok(a);
                        }
                        return Err(crate::error::AhuError::ManifestField(format!(
                            "key {key}: expected array"
                        )));
                    }
                }
            }
            Err(crate::error::AhuError::ManifestField(format!(
                "key {key}: missing"
            )))
        }

        fn get_optional_bytes(
            map: &[(ciborium::Value, ciborium::Value)],
            key: i128,
        ) -> crate::error::Result<Option<Vec<u8>>> {
            for (k, v) in map {
                if let Some(ki) = k.as_integer() {
                    if i128::from(ki) == key {
                        if let Some(b) = v.as_bytes() {
                            return Ok(Some(b.to_vec()));
                        }
                        return Err(crate::error::AhuError::ManifestField(format!(
                            "key {key}: expected bytes"
                        )));
                    }
                }
            }
            Ok(None)
        }

        fn get_optional_map(
            map: &[(ciborium::Value, ciborium::Value)],
            key: i128,
        ) -> Option<&[(ciborium::Value, ciborium::Value)]> {
            for (k, v) in map {
                if let Some(ki) = k.as_integer() {
                    if i128::from(ki) == key {
                        return v.as_map().map(|v| v.as_slice());
                    }
                }
            }
            None
        }

        fn to_fixed_32(v: &[u8]) -> crate::error::Result<[u8; 32]> {
            v.try_into().map_err(|_| {
                crate::error::AhuError::ManifestField("expected 32-byte digest".into())
            })
        }

        let format_version = get_uint(map, 1)?;
        let bundle_id_bytes = get_bytes(map, 2)?;
        let bundle_id = Uuid::from_slice(&bundle_id_bytes)
            .map_err(|e| crate::error::AhuError::ManifestField(format!("bundle_id: {e}")))?;
        let producer_id = get_text(map, 3)?;
        let created_at = get_uint(map, 4)?;
        let bundle_type_raw = get_uint(map, 5)?;
        let bundle_type = match bundle_type_raw {
            0 => BundleType::Full,
            1 => BundleType::Delta,
            _ => {
                return Err(crate::error::AhuError::ManifestField(format!(
                    "unknown bundle_type: {bundle_type_raw}"
                )));
            }
        };

        let ca_scope_arr = get_array(map, 6)?;
        let mut ca_scopes = Vec::with_capacity(ca_scope_arr.len());
        for scope_val in ca_scope_arr {
            let scope_map = scope_val.as_map().ok_or_else(|| {
                crate::error::AhuError::ManifestField("ca_scope entry is not a map".into())
            })?;

            let rid_map = get_map(scope_map, 5)?;
            let responder_id = ResponderId {
                id_type: match get_uint(rid_map, 1)? {
                    0 => ResponderIdType::ByName,
                    1 => ResponderIdType::ByKey,
                    n => {
                        return Err(crate::error::AhuError::ManifestField(format!(
                            "unknown responder_id type: {n}"
                        )));
                    }
                },
                value: get_bytes(rid_map, 2)?,
            };

            let responder_chain = {
                let mut chain = None;
                for (k, v) in scope_map {
                    if let Some(ki) = k.as_integer() {
                        if i128::from(ki) == 6 {
                            if let Some(arr) = v.as_array() {
                                let certs: crate::error::Result<Vec<Vec<u8>>> = arr
                                    .iter()
                                    .map(|c| {
                                        c.as_bytes().map(|b| b.to_vec()).ok_or_else(|| {
                                            crate::error::AhuError::ManifestField(
                                                "responder chain entry is not bytes".into(),
                                            )
                                        })
                                    })
                                    .collect();
                                chain = Some(certs?);
                            }
                        }
                    }
                }
                chain
            };

            ca_scopes.push(CaScope {
                hash_algorithm: get_bytes(scope_map, 1)?,
                issuer_name_hash: get_bytes(scope_map, 2)?,
                issuer_key_hash: get_bytes(scope_map, 3)?,
                epoch: get_uint(scope_map, 4)?,
                responder_id,
                responder_chain,
                signature_algorithm: get_bytes(scope_map, 7)?,
                completeness: match get_uint(scope_map, 8)? {
                    0 => Completeness::Partial,
                    1 => Completeness::AuthoritativeComplete,
                    n => {
                        return Err(crate::error::AhuError::ManifestField(format!(
                            "unknown completeness: {n}"
                        )));
                    }
                },
            });
        }

        let window_map = get_map(map, 7)?;
        let window = Window {
            produced_at: get_uint(window_map, 1)?,
            this_update_min: get_uint(window_map, 2)?,
            next_update_min: get_uint(window_map, 3)?,
            next_update_max: get_uint(window_map, 4)?,
        };

        let integrity_map = get_map(map, 8)?;
        let integrity = Integrity {
            index_digest: to_fixed_32(&get_bytes(integrity_map, 1)?)?,
            data_digest: to_fixed_32(&get_bytes(integrity_map, 2)?)?,
        };

        let entry_count = get_uint(map, 9)?;

        let continuity_map = get_map(map, 10)?;
        let continuity = Continuity {
            prev_manifest_digest: get_optional_bytes(continuity_map, 1)?
                .map(|b| to_fixed_32(&b))
                .transpose()?,
            base_manifest_digest: get_optional_bytes(continuity_map, 2)?
                .map(|b| to_fixed_32(&b))
                .transpose()?,
            chain_length: get_uint(continuity_map, 3)?,
        };

        let shard = get_optional_map(map, 11)
            .map(|sm| -> crate::error::Result<Shard> {
                Ok(Shard {
                    shard_index: get_uint(sm, 1)?,
                    shard_count: get_uint(sm, 2)?,
                    shard_fn: get_uint(sm, 3)?,
                })
            })
            .transpose()?;

        let compression = get_optional_map(map, 12)
            .map(|cm| -> crate::error::Result<Compression> {
                let algo = match get_uint(cm, 1)? {
                    0 => CompressionAlgorithm::None,
                    1 => CompressionAlgorithm::Zstd,
                    n => {
                        return Err(crate::error::AhuError::ManifestField(format!(
                            "unknown compression algorithm: {n}"
                        )));
                    }
                };
                let dict = get_optional_bytes(cm, 2)?
                    .map(|b| to_fixed_32(&b))
                    .transpose()?;
                Ok(Compression {
                    algorithm: algo,
                    dictionary_digest: dict,
                })
            })
            .transpose()?;

        let extensions = get_optional_map(map, 13).map(|ext_map| {
            ext_map
                .iter()
                .filter_map(|(k, v)| k.as_text().map(|key| (key.to_string(), v.clone())))
                .collect::<Vec<_>>()
        });

        Ok(Manifest {
            format_version,
            bundle_id,
            producer_id,
            created_at,
            bundle_type,
            ca_scopes,
            window,
            integrity,
            entry_count,
            continuity,
            shard,
            compression,
            extensions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> Manifest {
        Manifest {
            format_version: 1,
            bundle_id: Uuid::nil(),
            producer_id: "test-producer".into(),
            created_at: 1700000000,
            bundle_type: BundleType::Full,
            ca_scopes: vec![CaScope {
                hash_algorithm: vec![0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01], // SHA-256 OID DER
                issuer_name_hash: vec![0xAA; 32],
                issuer_key_hash: vec![0xBB; 32],
                epoch: 1,
                responder_id: ResponderId {
                    id_type: ResponderIdType::ByKey,
                    value: vec![0xCC; 20],
                },
                responder_chain: None,
                signature_algorithm: vec![0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02], // ECDSA-SHA256
                completeness: Completeness::AuthoritativeComplete,
            }],
            window: Window {
                produced_at: 1700000000,
                this_update_min: 1700000000,
                next_update_min: 1700086400,
                next_update_max: 1700093600,
            },
            integrity: Integrity {
                index_digest: [0x11; 32],
                data_digest: [0x22; 32],
            },
            entry_count: 100,
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

    #[test]
    fn cbor_round_trip() {
        let manifest = sample_manifest();
        let cbor = manifest.to_cbor();
        let decoded = Manifest::from_cbor(&cbor).unwrap();

        assert_eq!(manifest.format_version, decoded.format_version);
        assert_eq!(manifest.bundle_id, decoded.bundle_id);
        assert_eq!(manifest.producer_id, decoded.producer_id);
        assert_eq!(manifest.bundle_type, decoded.bundle_type);
        assert_eq!(manifest.entry_count, decoded.entry_count);
        assert_eq!(manifest.ca_scopes.len(), decoded.ca_scopes.len());
        assert_eq!(manifest.window, decoded.window);
        assert_eq!(manifest.integrity, decoded.integrity);
        assert_eq!(manifest.continuity, decoded.continuity);
    }

    #[test]
    fn deterministic_encoding() {
        let manifest = sample_manifest();
        let cbor1 = manifest.to_cbor();
        let cbor2 = manifest.to_cbor();
        assert_eq!(cbor1, cbor2, "CBOR encoding must be deterministic");
    }
}
