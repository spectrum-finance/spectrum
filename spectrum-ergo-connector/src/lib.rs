use ergo_lib::ergotree_ir::chain::ergo_box::BoxId;
use serde::{Deserialize, Serialize};

pub mod committee;
pub mod deposit;
pub mod rocksdb;
pub mod script;
pub mod vault;

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct AncillaryVaultInfo {
    pub box_id: BoxId,
    pub height: u32,
}
