use crate::types::{ProtocolId, ProtocolVer};

pub mod sync;

pub const SYNC_PROTOCOL_ID: ProtocolId = ProtocolId::from_u8(0);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolSpec {
    /// Maximum allowed size for a single message.
    pub max_message_size: usize,
    /// An initial message to send when we start communicating.
    pub handshake_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolConfig {
    pub supported_versions: Vec<(ProtocolVer, ProtocolSpec)>,
}
