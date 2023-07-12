use std::{marker::PhantomData, sync::Arc};

use async_std::task::spawn_blocking;
use rocksdb::{Direction, IteratorMode, ReadOptions};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq, Clone, Debug)]
pub struct VersionId<T>(pub T);

/// Logical serial number, used for ordering Undo operations.
#[derive(Serialize, Deserialize, Debug)]
pub struct LSN(u32);

const UNDO_PREFIX: &str = "p:undo";
const DB_PREFIX: &str = "p:db";
/// This key is associated with `Vec<VersionIdBoundaries>`, where elements are ordered from oldest
/// to newest.
const VERSION_ID_BOUNDARIES_PREFIX: &str = "p:bound";

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Undo<T, E> {
    version_id: VersionId<T>,
    key: Vec<u8>,
    value: Vec<u8>,
    /// E is the error type associated with the trait bound
    /// T: TryFrom<Vec<u8>, Error = E>
    error_phantom: PhantomData<E>,
}

impl<T, E> From<Vec<u8>> for Undo<T, E>
where
    T: TryFrom<Vec<u8>, Error = E>,
    E: std::fmt::Debug,
{
    fn from(bytes: Vec<u8>) -> Self {
        let version_size = bytes[0] as usize;
        let key_size = bytes[1] as usize;
        let value_size = bytes.len() - version_size - key_size - 2;
        assert!(value_size > 0);
        let version_id_bytes = bytes[2..2 + version_size].to_vec();
        let version_id = VersionId(T::try_from(version_id_bytes).unwrap());

        let key = bytes[2 + version_size..2 + version_size + key_size].to_vec();
        let value = bytes[2 + version_size + key_size..bytes.len()].to_vec();
        Self {
            version_id,
            key,
            value,
            error_phantom: PhantomData::default(),
        }
    }
}

impl<T, E> From<Undo<T, E>> for Vec<u8>
where
    T: Into<Vec<u8>>,
{
    fn from(undo: Undo<T, E>) -> Self {
        let version_bytes: Vec<u8> = undo.version_id.0.into();
        let version_size = version_bytes.len();
        assert!(version_size <= 255);
        let key_size = undo.key.len();
        assert!(key_size <= 255);
        let value_size = undo.value.len();
        assert!(value_size > 0);
        let mut bytes = Vec::with_capacity(version_size + key_size + value_size + 2);
        bytes.push(version_size as u8);
        bytes.push(key_size as u8);
        bytes.extend_from_slice(&version_bytes);
        bytes.extend_from_slice(&undo.key);
        bytes.extend_from_slice(&undo.value);
        bytes
    }
}

pub struct VersionedStore<K, V, T, E> {
    /// Storage for main data
    db: Arc<rocksdb::OptimisticTransactionDB>,
    key_phantom: PhantomData<K>,
    value_phantom: PhantomData<V>,
    version_phantom: PhantomData<T>,
    error_conversion_phantom: PhantomData<E>,
    num_versions_to_store: usize,
}

impl<K, V, T, E> VersionedStore<K, V, T, E>
where
    T: Serialize,
{
    pub async fn new(db_path: &str, num_versions_to_store: usize) -> Self {
        let db = Arc::new(rocksdb::OptimisticTransactionDB::open_default(db_path).unwrap());
        let db_cloned = db.clone();
        spawn_blocking(move || {
            let boundaries_key_bytes = VERSION_ID_BOUNDARIES_PREFIX.as_bytes();
            let boundaries: Vec<VersionIdBoundaries<T>> = vec![];
            db_cloned
                .put(boundaries_key_bytes, bincode::serialize(&boundaries).unwrap())
                .unwrap();
        })
        .await;
        Self {
            db,
            key_phantom: PhantomData::default(),
            value_phantom: PhantomData::default(),
            version_phantom: PhantomData::default(),
            error_conversion_phantom: PhantomData::default(),
            num_versions_to_store,
        }
    }
}

impl<K, V, T, E> VersionedStore<K, V, T, E>
where
    K: std::fmt::Debug + Serialize + Send + 'static,
    V: Serialize + DeserializeOwned + Send + 'static,
    E: std::fmt::Debug,
    T: Clone
        + Into<Vec<u8>>
        + Serialize
        + DeserializeOwned
        + Send
        + 'static
        + std::fmt::Debug
        + PartialEq
        + TryFrom<Vec<u8>, Error = E>,
{
    pub async fn update(&mut self, version_id: VersionId<T>, to_remove: Vec<K>, to_update: Vec<(K, V)>) {
        if to_remove.is_empty() && to_update.is_empty() {
            return;
        }
        let db = self.db.clone();
        let old_last_lsn = self.get_last_lsn().await;
        let num_versions_to_store = self.num_versions_to_store;

        spawn_blocking(move || {
            let mut last_lsn = old_last_lsn;
            let db_tx = db.transaction();
            // Delete keys
            for key in to_remove {
                let key_bytes = prefixed_key(DB_PREFIX, &bincode::serialize(&key).unwrap());
                if let Some(old_value_bytes) = db.get(&key_bytes).unwrap() {
                    db_tx.delete(&key_bytes).unwrap();
                    last_lsn += 1;
                    let undo: Undo<T, E> = Undo {
                        version_id: version_id.clone(),
                        key: key_bytes,
                        value: old_value_bytes,
                        error_phantom: PhantomData::default(),
                    };
                    let undo_key_bytes = prefixed_key(UNDO_PREFIX, &last_lsn.to_be_bytes());
                    let undo_bytes = Vec::<u8>::from(undo);
                    db_tx.put(undo_key_bytes, undo_bytes).unwrap();
                }
            }

            // Update keys
            for (key, value) in to_update {
                let key_bytes = prefixed_key(DB_PREFIX, &bincode::serialize(&key).unwrap());
                assert!(!key_bytes.is_empty());
                if let Some(old_value_bytes) = db.get(&key_bytes).unwrap() {
                    last_lsn += 1;
                    let undo: Undo<T, E> = Undo {
                        version_id: version_id.clone(),
                        key: key_bytes.clone(),
                        value: old_value_bytes,
                        error_phantom: PhantomData::default(),
                    };
                    let undo_key_bytes = prefixed_key(UNDO_PREFIX, &last_lsn.to_be_bytes());
                    let undo_bytes = Vec::<u8>::from(undo);
                    db_tx.put(undo_key_bytes, undo_bytes).unwrap();
                }
                let value_bytes = bincode::serialize(&value).unwrap();

                db_tx.put(&key_bytes, value_bytes).unwrap();
            }

            // Delete old versions if necessary
            let boundaries_key_bytes = VERSION_ID_BOUNDARIES_PREFIX.as_bytes();
            let mut boundaries: Vec<VersionIdBoundaries<T>> =
                bincode::deserialize(&db.get(boundaries_key_bytes).unwrap().unwrap()).unwrap();
            if boundaries.len() == num_versions_to_store + 1 {
                // Since we're currently storing at least 2 versions here, there are no entries
                // associated with the old version under the DB_PREFIX.
                let VersionIdBoundaries {
                    first_lsn, last_lsn, ..
                } = boundaries.remove(0);
                for lsn in first_lsn.0..=last_lsn.0 {
                    let undo_key_bytes = prefixed_key(UNDO_PREFIX, &lsn.to_be_bytes());
                    db_tx.delete(&undo_key_bytes).unwrap();
                }
            }

            let first_lsn = if last_lsn == old_last_lsn {
                last_lsn
            } else {
                old_last_lsn + 1
            };

            let boundary = VersionIdBoundaries {
                version_id,
                first_lsn: LSN(first_lsn),
                last_lsn: LSN(last_lsn),
            };
            boundaries.push(boundary);

            // Persist latest boundary info to DB
            db_tx
                .put(boundaries_key_bytes, bincode::serialize(&boundaries).unwrap())
                .unwrap();

            db_tx.commit().unwrap();
        })
        .await;
    }

    pub async fn get(&self, keys: Vec<K>) -> Vec<(K, Option<V>)> {
        let db = self.db.clone();
        spawn_blocking(move || {
            let mut res = vec![];
            for key in keys {
                let key_bytes = prefixed_key(DB_PREFIX, &bincode::serialize(&key).unwrap());
                let value = db
                    .get(&key_bytes)
                    .unwrap()
                    .map(|value_bytes| bincode::deserialize(&value_bytes).unwrap());
                res.push((key, value));
            }
            res
        })
        .await
    }

    pub async fn rollback_to(&mut self, version_id: VersionId<T>) {
        let db = self.db.clone();
        spawn_blocking(move || {
            let boundaries_key_bytes = VERSION_ID_BOUNDARIES_PREFIX.as_bytes();
            let mut boundaries: Vec<VersionIdBoundaries<T>> =
                bincode::deserialize(&db.get(boundaries_key_bytes).unwrap().unwrap()).unwrap();
            let db_tx = db.transaction();

            let version_id_ix = boundaries
                .iter()
                .position(|b| b.version_id == version_id)
                .unwrap();
            let last_lsn = boundaries.last().unwrap().last_lsn.0;
            let first_lsn = boundaries[version_id_ix].last_lsn.0 + 1;
            // Iterating backwards from `last_lsn` to `first_lsn`
            let mut iter = db.raw_iterator();
            let undo_last_key_bytes = prefixed_key(UNDO_PREFIX, &last_lsn.to_be_bytes());
            iter.seek(&undo_last_key_bytes);

            let undo_prefix = bincode::serialize(UNDO_PREFIX).unwrap();
            loop {
                if iter.valid() {
                    let undo_key_bytes = iter.key().unwrap();
                    let lsn = u32::from_be_bytes(
                        undo_key_bytes[undo_prefix.len()..undo_key_bytes.len()]
                            .try_into()
                            .unwrap(),
                    );

                    let undo: Undo<T, E> = Undo::from(iter.value().unwrap().to_vec());
                    db_tx.put(&undo.key, &undo.value).unwrap();
                    db_tx.delete(undo_key_bytes).unwrap();
                    if lsn == first_lsn {
                        break;
                    }
                } else {
                    unreachable!("expected undo LSN");
                }
                iter.prev();
            }

            boundaries.truncate(version_id_ix + 1);
            db_tx
                .put(boundaries_key_bytes, bincode::serialize(&boundaries).unwrap())
                .unwrap();

            db_tx.commit().unwrap();
        })
        .await
    }

    async fn get_last_lsn(&self) -> u32 {
        let db = self.db.clone();
        spawn_blocking(move || {
            let undo_prefix = bincode::serialize(UNDO_PREFIX).unwrap();
            let mut readopts = ReadOptions::default();
            readopts.set_iterate_range(rocksdb::PrefixRange(undo_prefix.clone()));
            let mut last_read = None;
            let mappings = db.iterator_opt(IteratorMode::From(&undo_prefix, Direction::Forward), readopts);

            for (key_bytes, _) in mappings.flatten() {
                let lsn =
                    u32::from_be_bytes(key_bytes[undo_prefix.len()..key_bytes.len()].try_into().unwrap());
                last_read = Some(lsn);
            }
            last_read.unwrap_or(0)
        })
        .await
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct VersionIdBoundaries<T> {
    version_id: VersionId<T>,
    first_lsn: LSN,
    last_lsn: LSN,
}

pub fn prefixed_key<T: Serialize>(prefix: &str, id: &T) -> Vec<u8> {
    let mut key_bytes = bincode::serialize(prefix).unwrap();
    let id_bytes = bincode::serialize(&id).unwrap();
    key_bytes.extend_from_slice(&id_bytes);
    key_bytes
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use rand::RngCore;

    use super::{Undo, VersionId, VersionedStore};

    type TestVersionedStore = VersionedStore<usize, usize, Vec<u8>, Infallible>;

    #[test]
    fn undo_roundtrip() {
        let value: Vec<u8> = (0_u8..255).collect();
        let key: Vec<u8> = (0_u8..150).collect();
        let version_id_vec: Vec<u8> = (0_u8..50).collect();
        let version_id = VersionId(version_id_vec);
        let undo = Undo {
            version_id,
            key,
            value,
            error_phantom: std::marker::PhantomData::default(),
        };

        let bytes = Vec::<u8>::from(undo.clone());
        let undo_cloned = Undo::from(bytes);
        assert_eq!(undo, undo_cloned);
    }

    #[tokio::test]
    async fn test_update() {
        let rnd = rand::thread_rng().next_u32();

        let mut store: TestVersionedStore = VersionedStore::new(&format!("./tmp/{}", rnd), 1).await;

        let v0 = VersionId(vec![0]);
        let v1 = VersionId(vec![1]);
        store.update(v0, vec![], vec![(0, 0), (1, 1)]).await;
        store.update(v1, vec![0], vec![(1, 2)]).await;

        assert_eq!(store.get_last_lsn().await, 2);
        let mut results = store.get(vec![0, 1, 2]).await;
        results.sort();
        println!("{:?}", results);
    }

    #[tokio::test]
    async fn test_rollback_1_version() {
        let rnd = rand::thread_rng().next_u32();

        let mut store: TestVersionedStore = VersionedStore::new(&format!("./tmp/{}", rnd), 1).await;

        let v0 = VersionId(vec![0]);
        let v1 = VersionId(vec![1]);

        let n = 100_usize;
        // Change all keys from v0
        let v0_updates: Vec<_> = (0..n).map(|i| (i, i)).collect();
        let v1_updates: Vec<_> = v0_updates.iter().map(|&(k, v)| (k, v + 100)).collect();

        store.update(v0.clone(), vec![], v0_updates.clone()).await;
        store.update(v1.clone(), vec![], v1_updates).await;
        store.rollback_to(v0.clone()).await;

        let keys: Vec<_> = (0..n).collect();
        let expected: Vec<_> = keys.iter().map(|&k| (k, Some(k))).collect();
        let mut results = store.get(keys.clone()).await;
        results.sort();
        assert_eq!(results, expected);

        // Change even-valued keys from v0
        let v1_updates: Vec<_> = v0_updates.iter().step_by(2).map(|&(k, v)| (k, v + 100)).collect();
        store.update(v1.clone(), vec![], v1_updates).await;
        store.rollback_to(v0.clone()).await;

        let mut results = store.get(keys.clone()).await;
        results.sort();
        assert_eq!(results, expected);

        // Delete all odd-valued keys from v0
        let v1_deletes: Vec<_> = (0..n).skip(1).step_by(2).collect();
        store.update(v1, v1_deletes, vec![]).await;
        store.rollback_to(v0).await;
        let mut results = store.get(keys.clone()).await;
        results.sort();
        assert_eq!(results, expected);
    }

    #[tokio::test]
    async fn test_rollback_multiple_versions() {
        let rnd = rand::thread_rng().next_u32();

        let mut store: TestVersionedStore = VersionedStore::new(&format!("./tmp/{}", rnd), 10).await;

        let num_versions = 10;
        let n = 100;
        let versions: Vec<_> = (0..num_versions).map(|v| VersionId(vec![v])).collect();
        let v0_updates: Vec<_> = (0..n).map(|i| (i, i)).collect();
        store
            .update(versions[0].clone(), vec![], v0_updates.clone())
            .await;

        let mut shift = 10;
        for (i, version) in versions.iter().enumerate().skip(1) {
            if i % 2 == 0 {
                let to_update: Vec<_> = v0_updates
                    .iter()
                    .step_by(2)
                    .map(|&(k, v)| (k, v + shift))
                    .collect();
                store.update(version.clone(), vec![], to_update).await;
            } else {
                let to_update: Vec<_> = v0_updates
                    .iter()
                    .skip(1)
                    .step_by(2)
                    .map(|&(k, v)| (k, v + shift))
                    .collect();
                store.update(version.clone(), vec![], to_update).await;
            }
            shift += 10;
        }

        store.rollback_to(versions[0].clone()).await;
        let keys: Vec<_> = (0..n).collect();
        let expected: Vec<_> = keys.iter().map(|&k| (k, Some(k))).collect();
        let mut results = store.get(keys.clone()).await;
        results.sort();
        assert_eq!(results, expected);
    }
}
