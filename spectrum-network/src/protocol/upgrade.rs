use crate::types::{ProtocolId, ProtocolVer, RawMessage};
use libp2p::core::{upgrade, UpgradeInfo};
use std::collections::HashMap;
use std::ops::Deref;
use std::vec;

/// Tag of a protocol. Consists of ProtocolId + ProtocolVer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolTag(Vec<u8>);

impl ProtocolTag {
    fn new(
        protocol_id: ProtocolId,
        protocol_ver: ProtocolVer
    ) -> Self {
        todo!()
    }
}

impl upgrade::ProtocolName for ProtocolTag {
    fn protocol_name(&self) -> &[u8] {
        &*self.0
    }
}

#[derive(Debug, Clone)]
pub struct InboundProtocolSpec {
    /// Maximum allowed size for a single notification.
    max_message_size: u64,
}

/// Upgrade that accepts a substream, sends back a status message, then becomes a unidirectional
/// stream of messages.
#[derive(Debug, Clone)]
pub struct ProtocolUpgradeIn {
    /// All supported protocols.
    protocols: HashMap<ProtocolTag, InboundProtocolSpec>,
}

impl UpgradeInfo for ProtocolUpgradeIn {
    type Info = ProtocolTag;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocols
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
    }
}

#[derive(Debug, Clone)]
pub struct OutboundProtocolSpec {
    /// Maximum allowed size for a single notification.
    max_message_size: u64,
    /// Initial message to send when we start communicating.
    handshake: Option<RawMessage>,
}

/// Upgrade that opens a substream, waits for the remote to accept by sending back a status
/// message, then becomes a unidirectional sink of data.
#[derive(Debug, Clone)]
pub struct ProtocolUpgradeOut {
    /// Protocol to negotiate.
    protocol_id: ProtocolId,
    /// Protocol versions to negotiate.
    /// The first one is the main name, while the other ones are fall backs.
    supported_versions: HashMap<ProtocolVer, OutboundProtocolSpec>,
}

impl UpgradeInfo for ProtocolUpgradeOut {
    type Info = ProtocolTag;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.supported_versions
            .keys()
            .cloned()
            .map(|v| ProtocolTag::new(self.protocol_id, v))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

pub struct ProtocolUpgraded {
    negotiated_ver: ProtocolVer,
    handshake: Option<RawMessage>,
}
