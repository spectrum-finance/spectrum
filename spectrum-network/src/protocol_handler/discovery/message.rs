use serde::{Deserialize, Serialize};

use crate::peer_manager::data::PeerDestination;
use crate::protocol_handler::versioning::Versioned;
use crate::protocol_handler::ProtocolSpec;
use crate::types::{ProtocolId, ProtocolVer};

/// Sync handshake provides initial node status.
#[derive(Serialize, Deserialize, Debug)]
pub enum DiscoveryHandshake {
    HandshakeV1(HandshakeV1),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeV1 {
    pub supported_protocols: Vec<ProtocolId>,
    pub height: usize,
}

impl Versioned for DiscoveryHandshake {
    fn version(&self) -> ProtocolVer {
        match self {
            DiscoveryHandshake::HandshakeV1(_) => DiscoverySpec::v1(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryMessage {
    DiscoveryMessageV1(DiscoveryMessageV1),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryMessageV1 {
    GetPeers,
    Peers(Vec<PeerDestination>),
}

impl Versioned for DiscoveryMessage {
    fn version(&self) -> ProtocolVer {
        match self {
            DiscoveryMessage::DiscoveryMessageV1(_) => DiscoverySpec::v1(),
        }
    }
}

pub struct DiscoverySpec;

impl DiscoverySpec {
    pub fn v1() -> ProtocolVer {
        ProtocolVer::from(1)
    }
}

impl<'de> ProtocolSpec<'de> for DiscoverySpec {
    type THandshake = DiscoveryHandshake;
    type TMessage = DiscoveryMessage;
}
