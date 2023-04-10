use serde::{Deserialize, Serialize};

use crate::protocol_handler::versioning::Versioned;
use crate::types::ProtocolVer;

const HANDEL_V1: ProtocolVer = ProtocolVer(1);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HandelMessage<C> {
    HandelMessageV1(HandelMessageV1<C>),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HandelMessageV1<C> {
    pub level: u32,
    pub individual_contribution: Option<C>,
    pub aggregate_contribution: C,
    /// If true, then receiver needs to contact sender
    pub contact_sender: bool,
}

impl<C> Versioned for HandelMessage<C> {
    fn version(&self) -> ProtocolVer {
        match self {
            HandelMessage::HandelMessageV1(_) => HANDEL_V1,
        }
    }
}
