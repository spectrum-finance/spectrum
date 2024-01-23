use std::sync::Arc;

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use log::info;
use rocksdb::{Direction, IteratorMode};

use crate::tx_event::ErgoTxEvent;

/// Store the entire history of `ErgoTxEvents`, allowing a new consensus-driver to sync with
/// the ergo-connector.
#[async_trait(?Send)]
pub trait ErgoTxEventHistory {
    async fn append(&mut self, moved_value: ErgoTxEvent);
    /// Returns `ErgoTxEvent` that is closest and >= `height`.
    async fn get(&self, height: u32) -> Option<(ErgoTxEvent, u32)>;
}

pub struct ErgoTxEventHistoryRocksDB {
    db: Arc<rocksdb::OptimisticTransactionDB>,
}

impl ErgoTxEventHistoryRocksDB {
    pub fn new(db_path: &str) -> Self {
        Self {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(db_path).unwrap()),
        }
    }
}

#[async_trait(?Send)]
impl ErgoTxEventHistory for ErgoTxEventHistoryRocksDB {
    async fn append(&mut self, moved_value: ErgoTxEvent) {
        let db = Arc::clone(&self.db);
        spawn_blocking(move || {
            let key = moved_value.get_height().to_be_bytes();

            // `bincode` cannot handle arbitrary structs since it is a non-self-describing serialization
            // format. We can use messagepack (via `rmp_serde`), which is a binary format that is also
            // self-describing.
            let value = rmp_serde::to_vec_named(&moved_value).unwrap();
            db.put(key, value).unwrap();
        })
        .await
    }

    async fn get(&self, height: u32) -> Option<(ErgoTxEvent, u32)> {
        let db = Arc::clone(&self.db);
        spawn_blocking(move || {
            let key = height.to_be_bytes();
            let mut vault_iter = db.iterator(IteratorMode::From(&key, Direction::Forward));

            let mut prev = None;
            while let Some(Ok((key_bytes, value_bytes))) = vault_iter.next() {
                let bb: [u8; 4] = key_bytes.as_ref().try_into().unwrap();
                let next_height = u32::from_be_bytes(bb);
                let moved_value: ErgoTxEvent = rmp_serde::from_slice(&value_bytes).unwrap();
                info!(
                    target: "vault",
                    "moved_value_hist: HEIGHT: {}, NEXT HEIGHT: {}, value: {:?}",
                    height, next_height, moved_value
                );
                if prev.is_none() {
                    if height <= next_height {
                        return Some((moved_value, next_height));
                    } else {
                        prev = Some(moved_value);
                        continue;
                    }
                }
                if height > prev.unwrap().get_height() && height <= next_height {
                    return Some((moved_value.clone(), moved_value.get_height()));
                } else {
                    prev = Some(moved_value);
                }
            }
            None
        })
        .await
    }
}

#[derive(Default)]
pub struct InMemoryMovedValueHistory {
    history: Vec<ErgoTxEvent>,
}

#[async_trait(?Send)]
impl ErgoTxEventHistory for InMemoryMovedValueHistory {
    async fn append(&mut self, moved_value: ErgoTxEvent) {
        self.history.push(moved_value);
    }

    async fn get(&self, height: u32) -> Option<(ErgoTxEvent, u32)> {
        let mut prev = None;
        for moved_value in &self.history {
            let next_height = moved_value.get_height();
            if prev.is_none() {
                if height <= next_height {
                    return Some((moved_value.clone(), next_height));
                } else {
                    prev = Some(moved_value);
                    continue;
                }
            }
            if height > prev.unwrap().get_height() && height <= next_height {
                return Some((moved_value.clone(), moved_value.get_height()));
            } else {
                prev = Some(moved_value);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ergo_lib::{
        chain::transaction::TxId,
        ergotree_ir::chain::{
            address::{AddressEncoder, NetworkPrefix},
            ergo_box::box_value::BoxValue,
        },
    };
    use rand::RngCore;
    use sigma_test_util::force_any_val;

    use crate::{
        rocksdb::ergo_tx_event_history::{ErgoTxEventHistory, InMemoryMovedValueHistory},
        script::{ErgoCell, ErgoTermCell},
        tx_event::{ErgoTxEvent, ErgoTxType, SpectrumErgoTx},
        vault_utxo::VaultUtxo,
        AncillaryVaultInfo,
    };

    use super::ErgoTxEventHistoryRocksDB;

    #[tokio::test]
    async fn test_rocksdb_single_insertion() {
        let history_rocksdb = rocks_db_client();
        single_insertion(history_rocksdb).await;
    }

    #[tokio::test]
    async fn test_in_memory_single_insertion() {
        let history = InMemoryMovedValueHistory::default();
        single_insertion(history).await;
    }

    async fn single_insertion<M: ErgoTxEventHistory>(mut history: M) {
        let height = 1234;
        let mv = gen_moved_value(height);
        history.append(mv.clone()).await;
        // Test exact height
        assert_eq!(history.get(height).await, Some((mv.clone(), height)));

        // Test lesser height
        assert_eq!(history.get(height - 10).await, Some((mv.clone(), height)));

        // Test greater height
        assert_eq!(history.get(height + 10).await, None);
    }

    #[tokio::test]
    async fn test_in_memory_2_insertions() {
        let history = InMemoryMovedValueHistory::default();
        two_insertions(history).await;
    }

    #[tokio::test]
    async fn test_rocksdb_2_insertions() {
        let history = rocks_db_client();
        two_insertions(history).await;
    }

    async fn two_insertions<M: ErgoTxEventHistory>(mut history: M) {
        let height = 1234;
        let mv_0 = gen_moved_value(height);
        let mv_1 = gen_moved_value(height + 10);
        history.append(mv_0.clone()).await;
        history.append(mv_1.clone()).await;

        // Test exact height
        assert_eq!(history.get(height).await, Some((mv_0.clone(), height)));

        // Test lesser height
        assert_eq!(history.get(height - 10).await, Some((mv_0.clone(), height)));

        // Test greater height
        assert_eq!(history.get(height + 1).await, Some((mv_1.clone(), height + 10)));
    }

    fn gen_moved_value(height: u32) -> ErgoTxEvent {
        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder
            .parse_address_from_str("9hVmDmyrLoNAupFVoobZRCfbwDWnAvCmjT1KCS4yGy3XziaCyMg")
            .unwrap();

        let ergo_cell = ErgoCell {
            ergs: BoxValue::try_from(100000_u64).unwrap(),
            address,
            tokens: vec![],
        };

        ErgoTxEvent::Applied(SpectrumErgoTx {
            tx_type: ErgoTxType::Withdrawal {
                exported_value: vec![ErgoTermCell(ergo_cell)],
                vault_info: (
                    VaultUtxo {
                        value: force_any_val(),
                        tokens: vec![],
                    },
                    AncillaryVaultInfo {
                        box_id: force_any_val(),
                        height: 1000,
                        tx_id: force_any_val(),
                    },
                ),
            },
            progress_point: height,
            tx_id: TxId::zero(),
        })
    }

    fn rocks_db_client() -> ErgoTxEventHistoryRocksDB {
        let rnd = rand::thread_rng().next_u32();
        ErgoTxEventHistoryRocksDB {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(format!("./tmp/{}", rnd)).unwrap()),
        }
    }
}
