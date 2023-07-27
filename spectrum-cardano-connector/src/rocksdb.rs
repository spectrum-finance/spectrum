use std::sync::Arc;

use async_std::task::spawn_blocking;
use pallas_crypto::hash::Hash;
use pallas_traverse::{Era, MultiEraTx};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RocksConfig {
    pub db_path: String,
    pub max_rollback_depth: u32,
}

static BEST_BLOCK: &str = "BEST_BLOCK";
static OLDEST_BLOCK: &str = "OLDEST_BLOCK";
const PARENT_POSTFIX: &str = ":p";
const CHILD_POSTFIX: &str = ":c";
const SLOT_POSTFIX: &str = ":s";
const BLOCK_NUMBER_POSTFIX: &str = ":b";
const TRANSACTION_POSTFIX: &str = ":t";

fn postfixed_key(block_id: &Hash<32>, s: &str) -> Vec<u8> {
    let mut bytes = block_id.to_vec();
    let p_bytes = bincode::serialize(s).unwrap();
    bytes.extend_from_slice(&p_bytes);
    bytes
}

/// Given a block `B`, let `HB` denote the (lowercase) hex-representation of block's ID. Then
///  - {HB}:p is the key which maps to the hex-representation of B's parent block ID.
///  - {HB}:c is the key which maps to the hex-representation of B's child block ID, if it currently
///    exists.
///  - {HB}:s is the key which maps to the slot of `B`.
///  - {HB}:t is the key which maps to a binary-encoding of a Vec containing the hex-representation
///    `HT` of the transaction ID of every transaction of `B`.
///    - Every {HT} is a key which maps to the Ergo-binary-encoded representation of its
///      transaction.
///  - {BEST_BLOCK} is a key which maps to a `BlockRecord` instance associated with the most
///    recently-stored block.
///  - {OLDEST_BLOCK} is a key which maps to a `BlockRecord` instance associated with the oldest
///    block in the persistent store.
pub struct ChainCacheRocksDB {
    pub db: Arc<rocksdb::OptimisticTransactionDB>,
    /// Represents the maximum number of blocks in the persistent store.
    pub max_rollback_depth: u32,
}

impl ChainCacheRocksDB {
    pub fn new(conf: RocksConfig) -> Self {
        Self {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(conf.db_path).unwrap()),
            max_rollback_depth: conf.max_rollback_depth,
        }
    }

    pub async fn append_block(&mut self, block: Block) {
        let db = self.db.clone();
        let max_rollback_depth = self.max_rollback_depth;
        spawn_blocking(move || {
            let db_tx = db.transaction();
            db_tx
                .put(
                    &postfixed_key(&block.id, PARENT_POSTFIX),
                    bincode::serialize(&block.parent_id).unwrap(),
                )
                .unwrap();
            db_tx
                .put(
                    &postfixed_key(&block.parent_id, CHILD_POSTFIX),
                    bincode::serialize(&block.id).unwrap(),
                )
                .unwrap();
            db_tx
                .put(
                    &postfixed_key(&block.id, SLOT_POSTFIX),
                    bincode::serialize(&block.slot).unwrap(),
                )
                .unwrap();

            db_tx
                .put(
                    &postfixed_key(&block.id, BLOCK_NUMBER_POSTFIX),
                    bincode::serialize(&block.block_number).unwrap(),
                )
                .unwrap();

            let tx_ids: Vec<Hash<32>> = block
                .transactions
                .iter()
                .map(|tx_bytes| {
                    let tx = deserialize_tx(tx_bytes);
                    tx.hash()
                })
                .collect();
            // We package together all transactions ids into a Vec.
            db_tx
                .put(
                    &postfixed_key(&block.id, TRANSACTION_POSTFIX),
                    bincode::serialize(&tx_ids).unwrap(),
                )
                .unwrap();

            // Map each transaction id to an encoded representation of its transaction.
            for (tx_id, tx_bytes) in tx_ids.iter().zip(&block.transactions) {
                db_tx.put(tx_id, tx_bytes).unwrap();
            }

            db_tx
                .put(
                    bincode::serialize(BEST_BLOCK).unwrap(),
                    bincode::serialize(&BlockRecord {
                        id: block.id,
                        slot: block.slot,
                        block_number: block.block_number,
                    })
                    .unwrap(),
                )
                .unwrap();

            let oldest_block_key = bincode::serialize(OLDEST_BLOCK).unwrap();
            if let Some(bytes) = db_tx.get(&oldest_block_key).unwrap() {
                let BlockRecord {
                    id: oldest_id,
                    block_number: oldest_block_number,
                    ..
                } = bincode::deserialize(&bytes).unwrap();

                // Replace OLDEST_BLOCK if the persistent store is at capacity.
                if block.block_number - oldest_block_number == max_rollback_depth as u64 {
                    let new_oldest_hash = bincode::deserialize(
                        &db_tx
                            .get(&postfixed_key(&oldest_id, CHILD_POSTFIX))
                            .unwrap()
                            .unwrap(),
                    )
                    .unwrap();
                    let new_oldest_slot: u64 = bincode::deserialize(
                        &db_tx
                            .get(&postfixed_key(&new_oldest_hash, SLOT_POSTFIX))
                            .unwrap()
                            .unwrap(),
                    )
                    .unwrap();

                    let new_oldest_block_number: u64 = bincode::deserialize(
                        &db_tx
                            .get(&postfixed_key(&new_oldest_hash, BLOCK_NUMBER_POSTFIX))
                            .unwrap()
                            .unwrap(),
                    )
                    .unwrap();

                    let new_oldest_block = BlockRecord {
                        id: new_oldest_hash,
                        slot: new_oldest_slot,
                        block_number: new_oldest_block_number,
                    };
                    db_tx
                        .put(
                            bincode::serialize(OLDEST_BLOCK).unwrap(),
                            bincode::serialize(&new_oldest_block).unwrap(),
                        )
                        .unwrap();

                    // Delete all data relating to the 'old' oldest block
                    let tx_ids_bytes = db_tx
                        .get(&postfixed_key(&oldest_id, TRANSACTION_POSTFIX))
                        .unwrap()
                        .unwrap();
                    let tx_ids: Vec<Hash<32>> = bincode::deserialize(&tx_ids_bytes).unwrap();
                    for tx_id in tx_ids {
                        db_tx.delete(tx_id).unwrap();
                    }

                    db_tx
                        .delete(postfixed_key(&oldest_id, TRANSACTION_POSTFIX))
                        .unwrap();
                    db_tx.delete(postfixed_key(&oldest_id, SLOT_POSTFIX)).unwrap();
                    db_tx
                        .delete(postfixed_key(&oldest_id, BLOCK_NUMBER_POSTFIX))
                        .unwrap();
                    db_tx.delete(postfixed_key(&oldest_id, PARENT_POSTFIX)).unwrap();
                    db_tx.delete(postfixed_key(&oldest_id, CHILD_POSTFIX)).unwrap();
                }
            } else {
                // This is the very first block to add to the store
                db_tx
                    .put(
                        bincode::serialize(OLDEST_BLOCK).unwrap(),
                        bincode::serialize(&BlockRecord {
                            id: block.id,
                            slot: block.slot,
                            block_number: block.block_number,
                        })
                        .unwrap(),
                    )
                    .unwrap();
            }

            db_tx.commit().unwrap();
        })
        .await
    }

    pub async fn exists(&mut self, block_id: Hash<32>) -> bool {
        let db = self.db.clone();
        spawn_blocking(move || db.get(postfixed_key(&block_id, SLOT_POSTFIX)).unwrap().is_some()).await
    }

    pub async fn get_best_block(&self) -> Option<BlockRecord> {
        let db = self.db.clone();
        spawn_blocking(move || {
            if let Ok(Some(bytes)) = db.get(bincode::serialize(BEST_BLOCK).unwrap()) {
                bincode::deserialize(&bytes).ok()
            } else {
                None
            }
        })
        .await
    }

    pub async fn take_best_block(&mut self) -> Option<Block> {
        let db = self.db.clone();
        spawn_blocking::<_, Option<Block>>(move || {
            let best_block_key = bincode::serialize(BEST_BLOCK).unwrap();

            loop {
                let db_tx = db.transaction();
                // The call to `get_for_update` is crucial; it plays an identical role as the WATCH
                // command in redis (refer to docs of `take_best_block` in impl of [`RedisClient`].
                if let Some(best_block_bytes) = db_tx.get_for_update(&best_block_key, true).unwrap() {
                    let BlockRecord {
                        id,
                        slot,
                        block_number,
                    } = bincode::deserialize(&best_block_bytes).unwrap();

                    if let Some(tx_ids_bytes) = db_tx.get(&postfixed_key(&id, TRANSACTION_POSTFIX)).unwrap() {
                        let mut transactions = vec![];
                        let tx_ids: Vec<Hash<32>> = bincode::deserialize(&tx_ids_bytes).unwrap();
                        for tx_id in tx_ids {
                            //let tx_key = bincode::serialize(&tx_id).unwrap();
                            let tx_bytes = db_tx.get(tx_id.as_slice()).unwrap().unwrap();

                            // Don't need transaction anymore, delete
                            db_tx.delete(tx_id.as_slice()).unwrap();

                            transactions.push(tx_bytes);
                        }

                        let parent_id_bytes =
                            db_tx.get(&postfixed_key(&id, PARENT_POSTFIX)).unwrap().unwrap();
                        let parent_id: Hash<32> = bincode::deserialize(&parent_id_bytes).unwrap();

                        db_tx.delete(&best_block_key).unwrap();

                        // The new best block will now be the parent of the old best block, if the parent
                        // exists in the cache.
                        if db_tx
                            .get(&postfixed_key(&parent_id, PARENT_POSTFIX))
                            .unwrap()
                            .is_some()
                        {
                            let parent_id_slot_bytes = db_tx
                                .get(&postfixed_key(&parent_id, SLOT_POSTFIX))
                                .unwrap()
                                .unwrap();
                            let parent_id_slot = bincode::deserialize(&parent_id_slot_bytes).unwrap();
                            let parent_block_number_bytes = db_tx
                                .get(&postfixed_key(&parent_id, BLOCK_NUMBER_POSTFIX))
                                .unwrap()
                                .unwrap();
                            let parent_block_number =
                                bincode::deserialize(&parent_block_number_bytes).unwrap();

                            db_tx
                                .put(
                                    &best_block_key,
                                    bincode::serialize(&BlockRecord {
                                        id: parent_id,
                                        slot: parent_id_slot,
                                        block_number: parent_block_number,
                                    })
                                    .unwrap(),
                                )
                                .unwrap();
                        }
                        match db_tx.commit() {
                            Ok(_) => {
                                return Some(Block {
                                    id,
                                    parent_id,
                                    slot,
                                    block_number,
                                    transactions,
                                });
                            }
                            Err(e) => {
                                if e.kind() == rocksdb::ErrorKind::Busy {
                                    continue;
                                } else {
                                    panic!("Unexpected error: {}", e);
                                }
                            }
                        }
                    } else {
                        return None;
                    }
                } else {
                    println!("NO BEST BLOCK!");
                    return None;
                }
            }
        })
        .await
    }
}

#[derive(Clone)]
pub struct Block {
    pub id: Hash<32>,
    pub parent_id: Hash<32>,
    pub slot: u64,
    pub block_number: u64,
    pub transactions: Vec<Vec<u8>>,
}

pub fn serialize_tx(tx: &MultiEraTx<'_>) -> Vec<u8> {
    let tx_bytes = tx.encode();
    let mut result = u16::from(tx.era()).to_be_bytes().to_vec();
    result.extend_from_slice(&tx_bytes);
    result
}

pub fn deserialize_tx(bytes: &'_ [u8]) -> MultiEraTx<'_> {
    let era_u16 = u16::from_be_bytes(bytes[..2].try_into().unwrap());
    let era = Era::try_from(era_u16).unwrap();
    MultiEraTx::decode(era, &bytes[2..]).unwrap()
}

#[derive(Serialize, Deserialize)]
pub struct BlockRecord {
    pub id: Hash<32>,
    pub slot: u64,
    pub block_number: u64,
}

#[cfg(test)]
mod tests {
    use std::{path::PathBuf, sync::Arc};

    use async_std::task::spawn_blocking;
    use pallas_crypto::hash::Hash;
    use pallas_traverse::MultiEraBlock;
    use rand::RngCore;

    use crate::rocksdb::{
        postfixed_key, serialize_tx, Block, BlockRecord, ChainCacheRocksDB, OLDEST_BLOCK, PARENT_POSTFIX,
        SLOT_POSTFIX, TRANSACTION_POSTFIX,
    };

    #[tokio::test]
    async fn test_max_rollback_length() {
        let serialized_blocks = load_cardano_blocks().await;
        let mut blocks = vec![];
        for ser_block in &serialized_blocks {
            let block = MultiEraBlock::decode(ser_block).unwrap();
            println!(
                "{:?}, slot: {:?}, block #: {}",
                block.hash(),
                block.slot(),
                block.number()
            );
            blocks.push(block);
        }

        let max_rollback_depth = 7;

        let rnd = rand::thread_rng().next_u32();
        let mut client = ChainCacheRocksDB {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(format!("./tmp/{}", rnd)).unwrap()),
            max_rollback_depth,
        };

        for i in 1..blocks.len() {
            let transactions: Vec<_> = blocks[i].txs().iter().map(serialize_tx).collect();
            let id = blocks[i].hash();
            let parent_id = blocks[i].header().previous_hash().unwrap();
            let slot = blocks[i].slot();
            let block_number = blocks[i].number();

            let block = Block {
                id,
                parent_id,
                slot,
                block_number,
                transactions,
            };

            client.append_block(block).await;
            assert!(client.exists(id).await);
            if i <= (max_rollback_depth as usize) {
                verify_oldest_block(blocks[1].hash(), blocks[1].number(), client.db.clone()).await;
            } else {
                let ix = i + 1 - (max_rollback_depth as usize);
                verify_oldest_block(blocks[ix].hash(), blocks[ix].number(), client.db.clone()).await;
            }
        }

        // Now test taking blocks out
        for i in (1..blocks.len()).rev().take(max_rollback_depth as usize) {
            println!("------{}", i);
            let Block {
                id,
                slot,
                block_number,
                ..
            } = client.take_best_block().await.unwrap();
            assert_eq!(blocks[i].hash(), id);
            assert_eq!(blocks[i].slot(), slot);
            assert_eq!(blocks[i].number(), block_number);
        }

        // We've rolled back all stored blocks
        assert!(client.get_best_block().await.is_none());
    }

    async fn verify_oldest_block(
        expected_block_id: Hash<32>,
        expected_block_number: u64,
        db: Arc<rocksdb::OptimisticTransactionDB>,
    ) {
        spawn_blocking::<_, ()>(move || {
            let oldest_block_key = bincode::serialize(OLDEST_BLOCK).unwrap();
            let bytes = db.get(oldest_block_key).unwrap().unwrap();
            let BlockRecord {
                id: oldest_id,
                block_number: oldest_block_number,
                ..
            } = bincode::deserialize(&bytes).unwrap();

            assert_eq!(oldest_block_number, expected_block_number);
            assert_eq!(oldest_id, expected_block_id);
            let parent_block_id_bytes = db
                .get(postfixed_key(&oldest_id, PARENT_POSTFIX))
                .unwrap()
                .unwrap();
            let parent_block_id: Hash<32> = bincode::deserialize(&parent_block_id_bytes).unwrap();
            assert!(db
                .get(postfixed_key(&parent_block_id, PARENT_POSTFIX))
                .unwrap()
                .is_none());
            assert!(db
                .get(postfixed_key(&parent_block_id, SLOT_POSTFIX))
                .unwrap()
                .is_none());
            assert!(db
                .get(postfixed_key(&parent_block_id, TRANSACTION_POSTFIX))
                .unwrap()
                .is_none());
        })
        .await;
    }

    /// Loads 30 cardano testnet blocks from file.
    async fn load_cardano_blocks() -> Vec<Vec<u8>> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("resources/serialized_cardano_blocks");
        let base16_bytes = tokio::fs::read(path).await.unwrap();
        let bytes = base16::decode(&base16_bytes).unwrap();
        let serialized_blocks: Vec<Vec<u8>> = bincode::deserialize(&bytes).unwrap();
        serialized_blocks
    }
}
