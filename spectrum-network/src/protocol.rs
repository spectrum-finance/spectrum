use crate::types::{ProtocolId, ProtocolVer};

pub const SYNC_PROTOCOL_ID: ProtocolId = ProtocolId::from_u8(0);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolSpec {
    /// Maximum allowed size for a single message.
    pub max_message_size: usize,
    /// Is explicit protocol approve is required.
    pub approve_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolConfig {
    pub supported_versions: Vec<(ProtocolVer, ProtocolSpec)>,
}
