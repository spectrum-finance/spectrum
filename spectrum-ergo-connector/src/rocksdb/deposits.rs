use std::sync::Arc;

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use ergo_lib::ergotree_ir::chain::ergo_box::BoxId;
use serde::{Deserialize, Serialize};
use spectrum_offchain::binary::prefixed_key;
use spectrum_offchain_lm::data::AsBox;

use crate::script::ErgoInboundCell;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessedDeposit(pub AsBox<ErgoInboundCell>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnprocessedDeposit(pub AsBox<ErgoInboundCell>);

#[async_trait(?Send)]
pub trait DepositRepo {
    async fn put(&mut self, d: UnprocessedDeposit);
    async fn process(&mut self, id: BoxId);
    async fn unprocess(&mut self, id: BoxId);
    async fn get_processed(&self, id: BoxId) -> Option<ProcessedDeposit>;
    async fn get_unprocessed(&self, id: BoxId) -> Option<UnprocessedDeposit>;
    async fn remove_unprocessed(&mut self, id: BoxId);
}

pub struct DepositRepoRocksDB {
    db: Arc<rocksdb::OptimisticTransactionDB>,
}

impl DepositRepoRocksDB {
    pub fn new(db_path: &str) -> Self {
        Self {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(db_path).unwrap()),
        }
    }
}

#[async_trait(?Send)]
impl DepositRepo for DepositRepoRocksDB {
    async fn put(&mut self, UnprocessedDeposit(bx): UnprocessedDeposit) {
        let db = Arc::clone(&self.db);
        spawn_blocking(move || {
            let key = prefixed_key(KEY_PREFIX, &bx.box_id());
            let value = rmp_serde::to_vec_named(&bx).unwrap();
            let tx = db.transaction();
            tx.put(key.clone(), value).unwrap();
            tx.commit().unwrap()
        })
        .await
    }
    async fn process(&mut self, id: BoxId) {
        let db = Arc::clone(&self.db);
        let processed_key = prefixed_key(PROCESSED_PREFIX, &id);
        let deposit_key = prefixed_key(KEY_PREFIX, &id);
        spawn_blocking(move || {
            assert!(db.get(&deposit_key).unwrap().is_some());
            db.put(processed_key, []).unwrap()
        })
        .await
    }
    async fn unprocess(&mut self, id: BoxId) {
        let db = Arc::clone(&self.db);
        let processed_key = prefixed_key(PROCESSED_PREFIX, &id);
        let deposit_key = prefixed_key(KEY_PREFIX, &id);
        spawn_blocking(move || {
            assert!(db.get(&deposit_key).unwrap().is_some());
            db.delete(processed_key).unwrap()
        })
        .await
    }

    async fn get_processed(&self, id: BoxId) -> Option<ProcessedDeposit> {
        let db = Arc::clone(&self.db);
        let status_key = prefixed_key(PROCESSED_PREFIX, &id);
        spawn_blocking(move || {
            if db.get(status_key).unwrap().is_some() {
                let deposit_key = prefixed_key(KEY_PREFIX, &id);
                let value_bytes = db.get(deposit_key).unwrap().unwrap();
                let deposit: ProcessedDeposit = rmp_serde::from_slice(&value_bytes).unwrap();
                Some(deposit)
            } else {
                None
            }
        })
        .await
    }
    async fn get_unprocessed(&self, id: BoxId) -> Option<UnprocessedDeposit> {
        let db = Arc::clone(&self.db);
        let status_key = prefixed_key(PROCESSED_PREFIX, &id);
        spawn_blocking(move || {
            if db.get(status_key).unwrap().is_none() {
                let deposit_key = prefixed_key(KEY_PREFIX, &id);
                let value_bytes = db.get(deposit_key).unwrap().unwrap();
                let deposit: UnprocessedDeposit = rmp_serde::from_slice(&value_bytes).unwrap();
                Some(deposit)
            } else {
                None
            }
        })
        .await
    }

    async fn remove_unprocessed(&mut self, id: BoxId) {
        let db = Arc::clone(&self.db);
        let processed_key = prefixed_key(PROCESSED_PREFIX, &id);
        let deposit_key = prefixed_key(KEY_PREFIX, &id);
        spawn_blocking(move || {
            assert!(db.get(&deposit_key).unwrap().is_some());
            assert!(db.get(&processed_key).unwrap().is_none());
            db.delete(deposit_key).unwrap();
        })
        .await
    }
}

const PROCESSED_PREFIX: &str = "processed";
const KEY_PREFIX: &str = "key";
