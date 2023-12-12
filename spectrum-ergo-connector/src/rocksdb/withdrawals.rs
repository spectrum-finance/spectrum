use std::sync::Arc;

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use ergo_lib::ergotree_ir::chain::ergo_box::{BoxId, ErgoBox};
use serde::Serialize;
use spectrum_offchain::{
    binary::prefixed_key,
    data::unique_entity::{Confirmed, Predicted},
};

/// Tracks withdrawals to user addresses in export TXs.
#[async_trait(?Send)]
pub trait WithdrawalRepo {
    async fn get_confirmation_height(&self, box_id: BoxId) -> Option<u32>;
    async fn put_confirmed(&mut self, df: Confirmed<ErgoBox>);
    async fn put_predicted(&mut self, df: Predicted<ErgoBox>);
    async fn may_exist(&self, box_id: BoxId) -> bool;
    async fn remove(&mut self, fid: BoxId);
}

pub struct WithdrawalRepoRocksDB(RepoRocksDB);

impl WithdrawalRepoRocksDB {
    pub fn new(db_path: &str) -> Self {
        Self(RepoRocksDB::new(db_path))
    }
}

#[async_trait(?Send)]
impl WithdrawalRepo for WithdrawalRepoRocksDB {
    async fn put_confirmed(&mut self, bx: Confirmed<ErgoBox>) {
        self.0.put_confirmed(bx).await
    }

    async fn put_predicted(&mut self, bx: Predicted<ErgoBox>) {
        self.0.put_predicted(bx).await
    }

    async fn may_exist(&self, box_id: BoxId) -> bool {
        self.0.may_exist(box_id).await
    }

    async fn remove(&mut self, box_id: BoxId) {
        self.0.remove(box_id).await
    }

    async fn get_confirmation_height(&self, box_id: BoxId) -> Option<u32> {
        self.0.get_confirmation_height(box_id).await
    }
}

pub struct RepoRocksDB {
    pub(crate) db: Arc<rocksdb::OptimisticTransactionDB>,
}

impl RepoRocksDB {
    pub fn new(db_path: &str) -> Self {
        Self {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(db_path).unwrap()),
        }
    }

    pub(crate) async fn put_confirmed(&mut self, Confirmed(bx): Confirmed<ErgoBox>) {
        let db = Arc::clone(&self.db);
        spawn_blocking(move || {
            let key = box_key(KEY_PREFIX, CONFIRMED_PRIORITY, &bx.box_id());
            let index_key = prefixed_key(KEY_INDEX_PREFIX, &bx.box_id());
            let value = bincode::serialize(&bx).unwrap();
            let tx = db.transaction();
            tx.put(key.clone(), value).unwrap();
            tx.put(index_key, key).unwrap();
            tx.commit().unwrap()
        })
        .await
    }

    pub(crate) async fn put_predicted(&mut self, Predicted(bx): Predicted<ErgoBox>) {
        let db = Arc::clone(&self.db);
        spawn_blocking(move || {
            let key = box_key(KEY_PREFIX, PREDICTED_PRIORITY, &bx.box_id());
            let index_key = prefixed_key(KEY_INDEX_PREFIX, &bx.box_id());
            let value = bincode::serialize(&bx).unwrap();
            let tx = db.transaction();
            tx.put(key.clone(), value).unwrap();
            tx.put(index_key, key).unwrap();
            tx.commit().unwrap()
        })
        .await
    }

    pub(crate) async fn remove(&mut self, box_id: BoxId) {
        let db = Arc::clone(&self.db);
        let index_key = prefixed_key(KEY_INDEX_PREFIX, &box_id);
        spawn_blocking(move || {
            if let Some(key) = db.get(index_key.clone()).unwrap() {
                let tx = db.transaction();
                tx.delete(index_key).unwrap();
                tx.delete(key).unwrap();
                tx.commit().unwrap()
            }
        })
        .await
    }

    pub(crate) async fn may_exist(&self, box_id: BoxId) -> bool {
        let db = Arc::clone(&self.db);
        let index_key = prefixed_key(KEY_INDEX_PREFIX, &box_id);
        spawn_blocking(move || db.key_may_exist(index_key)).await
    }

    pub(crate) async fn get_confirmation_height(&self, box_id: BoxId) -> Option<u32> {
        let db = self.db.clone();
        let key = box_key(KEY_PREFIX, CONFIRMED_PRIORITY, &box_id);
        spawn_blocking(move || {
            db.get(key)
                .unwrap()
                .and_then(|bytes| bincode::deserialize::<Confirmed<ErgoBox>>(&bytes).ok())
                .map(|c| c.0.creation_height)
        })
        .await
    }
}

pub(crate) enum ErgoBoxType {
    Confirmed,
    Predicted,
}

const KEY_PREFIX: &str = "key";
const KEY_INDEX_PREFIX: &str = "key_index";
const CONFIRMED_PRIORITY: usize = 0;
const PREDICTED_PRIORITY: usize = 5;

fn box_key<T: Serialize>(prefix: &str, seq_num: usize, id: &T) -> Vec<u8> {
    let mut key_bytes = bincode::serialize(prefix).unwrap();
    let seq_num_bytes = bincode::serialize(&seq_num).unwrap();
    let id_bytes = bincode::serialize(&id).unwrap();
    key_bytes.extend_from_slice(&seq_num_bytes);
    key_bytes.extend_from_slice(&id_bytes);
    key_bytes
}
