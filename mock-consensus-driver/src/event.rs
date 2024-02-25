use crate::tui;
use ergo_lib::ergotree_ir::chain::ergo_box::BoxId;
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::ConnectorResponse;
use spectrum_ergo_connector::rocksdb::vault_boxes::ErgoNotarizationBounds;
use spectrum_ergo_connector::script::ExtraErgoData;
use spectrum_ergo_connector::AncillaryVaultInfo;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    Tui(tui::Event),
    Connector(ConnectorResponse<ExtraErgoData, ErgoNotarizationBounds, BoxId, AncillaryVaultInfo>),
}
