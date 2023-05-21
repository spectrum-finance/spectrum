use serde::{Deserialize, Serialize};

use spectrum_ledger::{ModifierId, ModifierType};

use crate::protocol_handler::diffusion::types::SerializedModifier;
use crate::protocol_handler::versioning::Versioned;
use crate::protocol_handler::ProtocolSpec;
use crate::types::ProtocolVer;

/// Sync handshake provides initial node status.
#[derive(Serialize, Deserialize, Debug)]
pub enum DiffusionHandshake {
    HandshakeV1(HandshakeV1),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeV1(pub SyncStatus);

impl Versioned for DiffusionHandshake {
    fn version(&self) -> ProtocolVer {
        match self {
            DiffusionHandshake::HandshakeV1(_) => DiffusionSpec::v1(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DiffusionMessage {
    DiffusionMessageV1(DiffusionMessageV1),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Modifiers<T> {
    pub mod_type: ModifierType,
    pub modifiers: Vec<T>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub height: u64,
    pub last_blocks: Vec<ModifierId>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DiffusionMessageV1 {
    Inv(Modifiers<ModifierId>),
    RequestModifiers(Modifiers<ModifierId>),
    Modifiers(Modifiers<SerializedModifier>),
    SyncStatus(SyncStatus),
}

impl Versioned for DiffusionMessage {
    fn version(&self) -> ProtocolVer {
        match self {
            DiffusionMessage::DiffusionMessageV1(_) => DiffusionSpec::v1(),
        }
    }
}

pub struct DiffusionSpec;

impl DiffusionSpec {
    pub fn v1() -> ProtocolVer {
        ProtocolVer::from(1)
    }
}

impl<'de> ProtocolSpec<'de> for DiffusionSpec {
    type THandshake = DiffusionHandshake;
    type TMessage = DiffusionMessage;
}
