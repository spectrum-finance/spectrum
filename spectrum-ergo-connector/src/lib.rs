use ergo_lib::{chain::transaction::TxId, ergotree_ir::chain::ergo_box::BoxId};
use serde::{Deserialize, Serialize};

pub mod committee;
pub mod deposit;
pub mod ergo_connector;
pub mod rocksdb;
pub mod script;
pub mod tx_event;
pub mod tx_in_progress;
pub mod vault_utxo;

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
/// Ergo-specific information to send to the consensus-driver.
pub struct AncillaryVaultInfo {
    pub tx_id: TxId,
    pub box_id: BoxId,
    pub height: u32,
}
