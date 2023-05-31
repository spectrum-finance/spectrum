use serde::{Deserialize, Serialize};

use spectrum_ledger::block::BlockId;
use spectrum_ledger::{ModifierId, ModifierType, SerializedModifier, SlotNo};

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

impl DiffusionMessage {
    pub fn inv_v1(mod_type: ModifierType, modifiers: Vec<ModifierId>) -> DiffusionMessage {
        DiffusionMessage::DiffusionMessageV1(DiffusionMessageV1::Inv(Modifiers { mod_type, modifiers }))
    }

    pub fn request_modifiers_v1(mod_type: ModifierType, modifiers: Vec<ModifierId>) -> DiffusionMessage {
        DiffusionMessage::DiffusionMessageV1(DiffusionMessageV1::RequestModifiers(Modifiers {
            mod_type,
            modifiers,
        }))
    }

    pub fn modifiers_v1(mod_type: ModifierType, modifiers: Vec<SerializedModifier>) -> DiffusionMessage {
        DiffusionMessage::DiffusionMessageV1(DiffusionMessageV1::Modifiers(Modifiers { mod_type, modifiers }))
    }

    pub fn sync_status_v1(status: SyncStatus) -> DiffusionMessage {
        DiffusionMessage::DiffusionMessageV1(DiffusionMessageV1::SyncStatus(status))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Modifiers<T> {
    pub mod_type: ModifierType,
    pub modifiers: Vec<T>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    /// Slot number of best available block.
    pub height: SlotNo,
    /// Tail of the peer's chain (in reverse order, newer blocks first).
    pub last_blocks: Vec<BlockId>,
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
