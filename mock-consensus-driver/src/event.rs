use crate::tui;
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::VaultResponse;
use spectrum_ergo_connector::rocksdb::vault_boxes::ErgoNotarizationBounds;
use spectrum_ergo_connector::script::ExtraErgoData;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Event {
    Tui(tui::Event),
    VaultManager(VaultResponse<ExtraErgoData, ErgoNotarizationBounds>),
}
