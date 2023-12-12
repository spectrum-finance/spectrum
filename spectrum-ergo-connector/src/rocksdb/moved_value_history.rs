use std::sync::Arc;

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use ergo_lib::chain::transaction::TxId;
use rocksdb::{Direction, IteratorMode};
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::{InboundValue, MovedValue, UserValue};
use spectrum_crypto::digest::Blake2bDigest256;
use spectrum_ledger::{
    cell::{BoxDestination, ProgressPoint, SValue, TermCell},
    interop::Point,
    ChainId,
};
use spectrum_move::SerializedValue;

use crate::script::{ErgoInboundCell, ErgoTermCell};

/// Store the entire history of `ErgoMovedValue`, allowing a new consensus-driver to sync with
/// the ergo-connector.
#[async_trait(?Send)]
pub trait MovedValueHistory {
    async fn append(&mut self, moved_value: ErgoMovedValue);
    /// Returns ErgoMovedValue that is closest and >= `height`.
    async fn get(&self, height: u32) -> Option<(ErgoMovedValue, u32)>;
}

/// Ergo-version of [spectrum_chain_connector::`UserValue`]
#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct ErgoUserValue {
    /// Value that is inbound to Spectrum-network
    pub imported_value: Vec<ErgoInboundCell>,
    /// Value that was successfully exported from Spectrum-network to some recipient on-chain.
    pub exported_value: Vec<ErgoTermCell>,
    pub progress_point: u32,
    pub tx_id: TxId,
}

impl From<ErgoUserValue> for UserValue {
    fn from(value: ErgoUserValue) -> Self {
        let imported_value: Vec<_> = value.imported_value.into_iter().map(InboundValue::from).collect();
        let exported_value = value
            .exported_value
            .into_iter()
            .enumerate()
            .map(|(index, ErgoTermCell(ec))| {
                let digest_bytes = value.tx_id.0 .0.to_vec();
                let tx_id = spectrum_ledger::transaction::TxId::from(
                    Blake2bDigest256::try_from(digest_bytes).unwrap(),
                );
                let dst = BoxDestination {
                    target: ChainId::from(0),
                    address: SerializedValue::from(ec.address.content_bytes()),
                    inputs: None,
                };
                TermCell {
                    value: SValue::from(&ec),
                    tx_id,
                    index: index as u32,
                    dst,
                }
            })
            .collect();
        Self {
            imported_value,
            exported_value,
            progress_point: ProgressPoint {
                chain_id: ChainId::from(0),
                point: Point::from(value.progress_point as u64),
            },
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum ErgoMovedValue {
    /// A new set of TXs are made on-chain for a given progress point.
    Applied(ErgoUserValue),
    /// When the chain experiences a rollback, movements of value must be unapplied.
    Unapplied(ErgoUserValue),
}

impl ErgoMovedValue {
    pub fn get_height(&self) -> u32 {
        match self {
            ErgoMovedValue::Applied(user_value) | ErgoMovedValue::Unapplied(user_value) => {
                user_value.progress_point
            }
        }
    }

    pub fn get_user_value(&self) -> ErgoUserValue {
        match self {
            ErgoMovedValue::Applied(mv) | ErgoMovedValue::Unapplied(mv) => mv.clone(),
        }
    }
}

impl From<ErgoMovedValue> for MovedValue {
    fn from(value: ErgoMovedValue) -> Self {
        let user_value = UserValue::from(value.get_user_value());
        match value {
            ErgoMovedValue::Applied(_) => MovedValue::Applied(user_value),
            ErgoMovedValue::Unapplied(_) => MovedValue::Unapplied(user_value),
        }
    }
}

pub struct MovedValueHistoryRocksDB {
    db: Arc<rocksdb::OptimisticTransactionDB>,
}

impl MovedValueHistoryRocksDB {
    pub fn new(db_path: &str) -> Self {
        Self {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(db_path).unwrap()),
        }
    }
}

#[async_trait(?Send)]
impl MovedValueHistory for MovedValueHistoryRocksDB {
    async fn append(&mut self, moved_value: ErgoMovedValue) {
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

    async fn get(&self, height: u32) -> Option<(ErgoMovedValue, u32)> {
        let db = Arc::clone(&self.db);
        spawn_blocking(move || {
            let key = height.to_be_bytes();
            let mut vault_iter = db.iterator(IteratorMode::From(&key, Direction::Forward));

            let mut prev = None;
            while let Some(Ok((key_bytes, value_bytes))) = vault_iter.next() {
                let bb: [u8; 4] = key_bytes.as_ref().try_into().unwrap();
                let next_height = u32::from_be_bytes(bb);
                println!("HEIGHT: {}, NEXT HEIGHT: {}", height, next_height);
                let moved_value: ErgoMovedValue = rmp_serde::from_slice(&value_bytes).unwrap();
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

pub struct InMemoryMovedValueHistory {
    history: Vec<ErgoMovedValue>,
}

impl InMemoryMovedValueHistory {
    pub fn new() -> Self {
        Self { history: vec![] }
    }
}

#[async_trait(?Send)]
impl MovedValueHistory for InMemoryMovedValueHistory {
    async fn append(&mut self, moved_value: ErgoMovedValue) {
        self.history.push(moved_value);
    }

    async fn get(&self, height: u32) -> Option<(ErgoMovedValue, u32)> {
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

    use crate::{
        rocksdb::moved_value_history::{InMemoryMovedValueHistory, MovedValueHistory},
        script::{ErgoCell, ErgoTermCell},
    };

    use super::{ErgoMovedValue, MovedValueHistoryRocksDB};

    #[tokio::test]
    async fn test_rocksdb_single_insertion() {
        let history_rocksdb = rocks_db_client();
        single_insertion(history_rocksdb).await;
    }

    #[tokio::test]
    async fn test_in_memory_single_insertion() {
        let history = InMemoryMovedValueHistory::new();
        single_insertion(history).await;
    }

    async fn single_insertion<M: MovedValueHistory>(mut history: M) {
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
        let history = InMemoryMovedValueHistory::new();
        two_insertions(history).await;
    }

    #[tokio::test]
    async fn test_rocksdb_2_insertions() {
        let history = rocks_db_client();
        two_insertions(history).await;
    }

    async fn two_insertions<M: MovedValueHistory>(mut history: M) {
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

    fn gen_moved_value(height: u32) -> ErgoMovedValue {
        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder
            .parse_address_from_str("9hVmDmyrLoNAupFVoobZRCfbwDWnAvCmjT1KCS4yGy3XziaCyMg")
            .unwrap();

        let ergo_cell = ErgoCell {
            ergs: BoxValue::try_from(100000_u64).unwrap(),
            address,
            tokens: vec![],
        };

        ErgoMovedValue::Applied(super::ErgoUserValue {
            imported_value: vec![],
            exported_value: vec![ErgoTermCell(ergo_cell)],
            progress_point: height,
            tx_id: TxId::zero(),
        })
    }

    fn rocks_db_client() -> MovedValueHistoryRocksDB {
        let rnd = rand::thread_rng().next_u32();
        MovedValueHistoryRocksDB {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(format!("./tmp/{}", rnd)).unwrap()),
        }
    }
}
