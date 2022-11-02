use crate::protocol_handler::codec::BinCodec;
use crate::protocol_handler::versioning::Versioned;
use crate::protocol_handler::ProtocolSpec;
use crate::types::{ProtocolId, ProtocolVer, RawMessage};

/// Sync handshake provides initial node status.
pub enum SyncHandshake {
    HandshakeV1(HandshakeV1),
}

impl SyncHandshake {
    pub const fn v1() -> ProtocolVer {
        ProtocolVer::from(1)
    }
}

pub struct HandshakeV1 {
    pub supported_protocols: Vec<ProtocolId>,
    pub height: usize,
}

impl Versioned for SyncHandshake {
    fn version(&self) -> ProtocolVer {
        match self {
            SyncHandshake::HandshakeV1(_) => SyncHandshake::v1()
        }
    }
}

impl BinCodec for SyncHandshake {
    fn encode(self) -> RawMessage {
        todo!()
    }

    fn decode(msg: RawMessage) -> Result<Self, String> {
        todo!()
    }
}

pub enum SyncMessage {}

impl Versioned for SyncMessage {
    fn version(&self) -> ProtocolVer {
        todo!()
    }
}

impl BinCodec for SyncMessage {
    fn encode(self) -> RawMessage {
        todo!()
    }

    fn decode(msg: RawMessage) -> Result<Self, String> {
        todo!()
    }
}

pub struct SyncSpec;

impl ProtocolSpec for SyncSpec {
    type THandshake = SyncHandshake;
    type TMessage = SyncMessage;
}
