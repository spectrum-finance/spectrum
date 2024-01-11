use std::sync::Arc;

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use ergo_lib::ergotree_ir::chain::ergo_box::BoxId;
use rocksdb::{Direction, IteratorMode, ReadOptions};
use serde::{Deserialize, Serialize};
use spectrum_offchain_lm::data::AsBox;

use crate::script::ErgoInboundCell;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ProcessedDeposit(pub AsBox<ErgoInboundCell>);

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct UnprocessedDeposit(pub AsBox<ErgoInboundCell>);

#[async_trait(?Send)]
pub trait DepositRepo {
    async fn put(&mut self, d: UnprocessedDeposit);
    async fn process(&mut self, id: BoxId);
    async fn unprocess(&mut self, id: BoxId);
    async fn get_processed(&self, id: BoxId) -> Option<ProcessedDeposit>;
    async fn get_unprocessed(&self, id: BoxId) -> Option<UnprocessedDeposit>;
    async fn remove_unprocessed(&mut self, id: BoxId);
    async fn get_all_unprocessed_deposits(&self) -> Vec<UnprocessedDeposit>;
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
            let key = prefixed_key(UNPROCESSED_PREFIX, &bx.box_id());
            let value = rmp_serde::to_vec_named(&UnprocessedDeposit(bx)).unwrap();
            let tx = db.transaction();
            tx.put(key, value).unwrap();
            tx.commit().unwrap()
        })
        .await
    }
    async fn process(&mut self, id: BoxId) {
        let db = Arc::clone(&self.db);
        let unprocessed_key = prefixed_key(UNPROCESSED_PREFIX, &id);
        let processed_key = prefixed_key(PROCESSED_PREFIX, &id);
        spawn_blocking(move || {
            let unprocessed_bytes = db.get(&unprocessed_key).unwrap().unwrap();
            let UnprocessedDeposit(d) = rmp_serde::from_slice(&unprocessed_bytes).unwrap();
            let processed_bytes = rmp_serde::to_vec_named(&ProcessedDeposit(d)).unwrap();
            let tx = db.transaction();
            tx.delete(&unprocessed_key).unwrap();
            tx.put(processed_key, processed_bytes).unwrap();
            tx.commit().unwrap();
        })
        .await
    }
    async fn unprocess(&mut self, id: BoxId) {
        let db = Arc::clone(&self.db);
        let unprocessed_key = prefixed_key(UNPROCESSED_PREFIX, &id);
        let processed_key = prefixed_key(PROCESSED_PREFIX, &id);
        spawn_blocking(move || {
            let processed_bytes = db.get(&processed_key).unwrap().unwrap();
            let ProcessedDeposit(d) = rmp_serde::from_slice(&processed_bytes).unwrap();
            let unprocessed_bytes = rmp_serde::to_vec_named(&UnprocessedDeposit(d)).unwrap();
            let tx = db.transaction();
            tx.delete(&processed_key).unwrap();
            tx.put(unprocessed_key, unprocessed_bytes).unwrap();
            tx.commit().unwrap();
        })
        .await
    }

    async fn get_processed(&self, id: BoxId) -> Option<ProcessedDeposit> {
        let db = Arc::clone(&self.db);
        let key = prefixed_key(PROCESSED_PREFIX, &id);
        spawn_blocking(move || {
            db.get(key).unwrap().map(|bytes| {
                let deposit: ProcessedDeposit = rmp_serde::from_slice(&bytes).unwrap();
                deposit
            })
        })
        .await
    }

    async fn get_unprocessed(&self, id: BoxId) -> Option<UnprocessedDeposit> {
        let db = Arc::clone(&self.db);
        let key = prefixed_key(UNPROCESSED_PREFIX, &id);
        spawn_blocking(move || {
            db.get(key).unwrap().map(|bytes| {
                let deposit: UnprocessedDeposit = rmp_serde::from_slice(&bytes).unwrap();
                deposit
            })
        })
        .await
    }

    async fn remove_unprocessed(&mut self, id: BoxId) {
        let db = Arc::clone(&self.db);
        let processed_key = prefixed_key(PROCESSED_PREFIX, &id);
        let unprocessed_key = prefixed_key(UNPROCESSED_PREFIX, &id);
        spawn_blocking(move || {
            assert!(db.get(&unprocessed_key).unwrap().is_some());
            assert!(db.get(&processed_key).unwrap().is_none());
            db.delete(unprocessed_key).unwrap();
        })
        .await
    }

    async fn get_all_unprocessed_deposits(&self) -> Vec<UnprocessedDeposit> {
        let db = self.db.clone();
        spawn_blocking(move || {
            let mut res = vec![];
            let key_prefix = UNPROCESSED_PREFIX.as_bytes();
            let mut readopts = ReadOptions::default();
            readopts.set_iterate_range(rocksdb::PrefixRange(key_prefix.clone()));
            let mappings = db.iterator_opt(IteratorMode::From(&key_prefix, Direction::Forward), readopts);

            for (_, value_bytes) in mappings.flatten() {
                let d: UnprocessedDeposit = rmp_serde::from_slice(&value_bytes).unwrap();
                res.push(d);
            }
            res
        })
        .await
    }
}

const PROCESSED_PREFIX: &str = "p:";
const UNPROCESSED_PREFIX: &str = "k:";

fn prefixed_key(prefix: &str, box_id: &BoxId) -> Vec<u8> {
    let mut bytes = prefix.as_bytes().to_vec();
    bytes.extend(box_id.as_ref());
    bytes
}

#[cfg(test)]
mod tests {
    use crate::rocksdb::deposits::{DepositRepo, DepositRepoRocksDB, ProcessedDeposit, UnprocessedDeposit};
    use crate::rocksdb::moved_value_history::MovedValueHistoryRocksDB;
    use crate::script::tests::gen_random_token;
    use crate::script::{ErgoCell, ErgoInboundCell};
    use blake2::digest::crypto_common::rand_core::RngCore;
    use ergo_lib::chain::transaction::TxId;
    use ergo_lib::ergotree_ir::chain::address::Address;
    use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
    use ergo_lib::ergotree_ir::chain::ergo_box::{BoxId, ErgoBox};
    use ergo_lib::ergotree_ir::sigma_protocol::sigma_boolean::ProveDlog;
    use rand::prelude::SliceRandom;
    use rand::Rng;
    use sigma_test_util::force_any_val;
    use spectrum_offchain_lm::data::AsBox;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_put_get() {
        let mut repo = rocks_db_client();
        let dep = UnprocessedDeposit(AsBox(force_any_val::<ErgoBox>(), gen_ergo_cell()));
        repo.put(dep.clone()).await;
        assert_eq!(dep, repo.get_unprocessed(dep.0.box_id()).await.unwrap());
    }

    #[tokio::test]
    async fn test_processing_deposit() {
        let mut repo = rocks_db_client();
        let dep = UnprocessedDeposit(AsBox(force_any_val::<ErgoBox>(), gen_ergo_cell()));
        let box_id = dep.0.box_id();
        repo.put(dep.clone()).await;
        repo.process(box_id).await;
        assert!(repo.get_unprocessed(box_id).await.is_none());
        assert_eq!(ProcessedDeposit(dep.0), repo.get_processed(box_id).await.unwrap());
    }

    #[tokio::test]
    async fn test_get_all_unprocessed() {
        let mut repo = rocks_db_client();

        let num_deposits = 30;

        let mut rng = rand::thread_rng();
        let mut indices: Vec<usize> = (0..num_deposits).into_iter().collect();
        indices.shuffle(&mut rng);

        let to_process = &indices[..10];

        let mut deposits = vec![];
        let mut expected = vec![];
        for i in 0..num_deposits {
            let dep = UnprocessedDeposit(AsBox(force_any_val::<ErgoBox>(), gen_ergo_cell()));
            let box_id = dep.0.box_id();
            repo.put(dep.clone()).await;

            if !to_process.contains(&i) {
                expected.push(dep.clone());
            }
            deposits.push(dep);
        }

        for i in to_process {
            let box_id = deposits[*i].0.box_id();
            repo.process(box_id).await;
        }
        let unprocessed = repo.get_all_unprocessed_deposits().await;
        assert_eq!(unprocessed.len(), expected.len());
        for d in unprocessed {
            assert!(expected.contains(&d));
        }

        // Now unprocess all deposits again
        for i in to_process {
            let box_id = deposits[*i].0.box_id();
            repo.unprocess(box_id).await;
        }

        let unprocessed = repo.get_all_unprocessed_deposits().await;
        assert_eq!(unprocessed.len(), deposits.len());
        for d in &unprocessed {
            assert!(deposits.contains(d));
        }

        // Finally remove all unprocessed orders
        for d in unprocessed {
            repo.remove_unprocessed(d.0.box_id()).await;
        }

        assert!(repo.get_all_unprocessed_deposits().await.is_empty());
    }

    fn gen_ergo_cell() -> ErgoInboundCell {
        let ergs: BoxValue = force_any_val();
        let prove_dlog: ProveDlog = force_any_val();
        let address = Address::P2Pk(prove_dlog);
        let tokens = std::iter::repeat_with(|| gen_random_token(10)).take(10).collect();
        ErgoInboundCell(ErgoCell {
            ergs,
            address,
            tokens,
        })
    }

    pub fn gen_box_id() -> BoxId {
        let mut digest = ergo_lib::ergo_chain_types::Digest32::zero();

        let mut rng = rand::thread_rng();
        rng.fill(&mut digest.0);
        BoxId::from(digest)
    }

    fn rocks_db_client() -> DepositRepoRocksDB {
        let rnd = rand::thread_rng().next_u32();
        DepositRepoRocksDB {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(format!("./tmp/{}", rnd)).unwrap()),
        }
    }
}
