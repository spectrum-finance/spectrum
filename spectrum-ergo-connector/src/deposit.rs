use ergo_lib::ergotree_ir::chain::ergo_box::BoxId;
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::InboundValue;
use spectrum_offchain_lm::data::AsBox;

use crate::script::ErgoInboundCell;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct ProcessedDeposit(pub AsBox<ErgoInboundCell>);

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct UnprocessedDeposit(pub AsBox<ErgoInboundCell>);

impl From<UnprocessedDeposit> for InboundValue<BoxId> {
    fn from(value: UnprocessedDeposit) -> Self {
        InboundValue::from(value.0 .1)
    }
}
