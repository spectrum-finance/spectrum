use std::sync::Arc;

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use elliptic_curve::PublicKey;
use ergo_lib::chain::transaction::TxId;
use ergo_lib::ergotree_ir::chain::address::Address;
use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
use ergo_lib::ergotree_ir::chain::token::Token;
use k256::ProjectivePoint;
use log::info;
use rocksdb::{Direction, IteratorMode};
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::{ChainTxEvent, InboundValue, SpectrumTx, SpectrumTxType};
use spectrum_crypto::digest::Blake2bDigest256;
use spectrum_ledger::cell::AnyCell::Term;
use spectrum_ledger::cell::Owner;
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
    async fn append(&mut self, moved_value: ErgoTxEvent);
    /// Returns ErgoMovedValue that is closest and >= `height`.
    async fn get(&self, height: u32) -> Option<(ErgoTxEvent, u32)>;
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct SpectrumErgoTx {
    pub progress_point: u32,
    pub tx_id: TxId,
    pub tx_type: ErgoTxType,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum ErgoTxType {
    /// Spectrum Network deposit transaction
    Deposit {
        /// Value that is inbound to Spectrum-network
        imported_value: Vec<ErgoInboundCell>,
    },

    /// Spectrum Network withdrawal transaction
    Withdrawal {
        /// Value that was successfully exported from Spectrum-network to some recipient on-chain.
        exported_value: Vec<ErgoTermCell>,
    },

    NewUnprocessedDeposit(ErgoInboundCell),
}

impl From<SpectrumErgoTx> for SpectrumTx {
    fn from(value: SpectrumErgoTx) -> Self {
        let SpectrumErgoTx {
            progress_point,
            tx_type,
            ..
        } = value;
        let progress_point = ProgressPoint {
            chain_id: ChainId::from(0),
            point: Point::from(progress_point as u64),
        };
        match tx_type {
            ErgoTxType::Deposit { imported_value } => {
                let imported_value = imported_value
                    .into_iter()
                    .map(|c| {
                        let value = SValue::from(&c.0);
                        let Address::P2Pk(prove_dlog) = c.0.address else {
                            panic!("Only P2Pk addresses supported");
                        };
                        let affine_point = ProjectivePoint::from(prove_dlog.h.as_ref().clone()).to_affine();
                        let pk = k256::PublicKey::from_affine(affine_point).unwrap();
                        let owner = Owner::ProveDlog(pk);
                        InboundValue { value, owner }
                    })
                    .collect();

                SpectrumTx {
                    progress_point,
                    tx_type: SpectrumTxType::Deposit { imported_value },
                }
            }
            ErgoTxType::Withdrawal { exported_value } => {
                let exported_value = exported_value.into_iter().map(|c| TermCell::from(c)).collect();
                SpectrumTx {
                    progress_point,
                    tx_type: SpectrumTxType::Withdrawal { exported_value },
                }
            }
            ErgoTxType::NewUnprocessedDeposit(inbound_cell) => {
                let inbound_value = InboundValue::from(inbound_cell);
                SpectrumTx {
                    progress_point,
                    tx_type: SpectrumTxType::NewUnprocessedDeposit(inbound_value),
                }
            }
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum ErgoTxEvent {
    /// A new set of TXs are made on-chain for a given progress point.
    Applied(SpectrumErgoTx),
    /// When the chain experiences a rollback, movements of value must be unapplied.
    Unapplied(SpectrumErgoTx),
}

impl ErgoTxEvent {
    pub fn get_height(&self) -> u32 {
        match self {
            ErgoTxEvent::Applied(tx) | ErgoTxEvent::Unapplied(tx) => tx.progress_point,
        }
    }
}

impl From<ErgoTxEvent> for ChainTxEvent {
    fn from(value: ErgoTxEvent) -> Self {
        match value {
            ErgoTxEvent::Applied(tx) => ChainTxEvent::Applied(SpectrumTx::from(tx)),
            ErgoTxEvent::Unapplied(tx) => ChainTxEvent::Unapplied(SpectrumTx::from(tx)),
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

pub struct InMemoryMovedValueHistory {
    history: Vec<ErgoTxEvent>,
}

impl InMemoryMovedValueHistory {
    pub fn new() -> Self {
        Self { history: vec![] }
    }
}

#[async_trait(?Send)]
impl MovedValueHistory for InMemoryMovedValueHistory {
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

    use crate::{
        rocksdb::moved_value_history::{InMemoryMovedValueHistory, MovedValueHistory},
        script::{ErgoCell, ErgoTermCell},
    };

    use super::{ErgoTxEvent, MovedValueHistoryRocksDB};

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

        ErgoTxEvent::Applied(super::ErgoUserValue {
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
