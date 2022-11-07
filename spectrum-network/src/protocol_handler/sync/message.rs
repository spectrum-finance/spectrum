use crate::protocol_handler::codec::BinCodec;
use crate::protocol_handler::versioning::Versioned;
use crate::protocol_handler::ProtocolSpec;
use crate::types::{ProtocolId, ProtocolVer, RawMessage};
use ciborium::de::Error;
use serde::{Deserialize, Serialize};

/// Sync handshake provides initial node status.
#[derive(Serialize, Deserialize, Debug)]
pub enum SyncHandshake {
    HandshakeV1(HandshakeV1),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeV1 {
    pub supported_protocols: Vec<ProtocolId>,
    pub height: usize,
}

impl Versioned for SyncHandshake {
    fn version(&self) -> ProtocolVer {
        match self {
            SyncHandshake::HandshakeV1(_) => SyncSpec::v1(),
        }
    }
}

impl BinCodec for SyncHandshake {
    fn encode(self) -> RawMessage {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&self, &mut encoded).unwrap();
        RawMessage::from(encoded)
    }

    fn decode(msg: RawMessage) -> Result<Self, Error<std::io::Error>> {
        let bf: Vec<u8> = msg.into();
        ciborium::de::from_reader(&bf[..])
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

    fn decode(msg: RawMessage) -> Result<Self, Error<std::io::Error>> {
        todo!()
    }
}

pub struct SyncSpec;

impl SyncSpec {
    pub fn v1() -> ProtocolVer {
        ProtocolVer::from(1)
    }
}

impl ProtocolSpec for SyncSpec {
    type THandshake = SyncHandshake;
    type TMessage = SyncMessage;
}
