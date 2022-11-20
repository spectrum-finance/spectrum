use crate::peer_manager::data::PeerDestination;
use crate::protocol_handler::versioning::Versioned;
use crate::protocol_handler::ProtocolSpec;
use crate::types::{ProtocolId, ProtocolVer};
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
    fn encode(self) -> Result<RawMessage, ciborium::ser::Error<std::io::Error>> {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&self, &mut encoded)?;
        Ok(RawMessage::from(encoded))
    }

    fn decode(msg: RawMessage) -> Result<Self, Error<std::io::Error>> {
        let bf: Vec<u8> = msg.into();
        ciborium::de::from_reader(&bf[..])
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SyncMessage {
    SyncMessageV1(SyncMessageV1),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SyncMessageV1 {
    GetPeers,
    Peers(Vec<PeerDestination>),
}

impl Versioned for SyncMessage {
    fn version(&self) -> ProtocolVer {
        match self {
            SyncMessage::SyncMessageV1(_) => SyncSpec::v1(),
        }
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
