use crossterm::event::KeyEvent;
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::ProtoTermCell;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Tick,
    Render,
    Resize(u16, u16),
    Suspend,
    Resume,
    Quit,
    Refresh,
    Error(String),
    Help,
    NextBlock,
    EnterKey(KeyEvent),
    RequestDepositProcessing,
    RequestWithdrawal(Vec<ProtoTermCell>),
}
