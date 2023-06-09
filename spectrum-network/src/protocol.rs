use either::Either;

use crate::types::{ProtocolId, ProtocolVer};

pub const DISCOVERY_PROTOCOL_ID: ProtocolId = ProtocolId::from_u8(0);

pub const DIFFUSION_PROTOCOL_ID: ProtocolId = ProtocolId::from_u8(1);

pub const SIGMA_AGGR_PROTOCOL_ID: ProtocolId = ProtocolId::from_u8(2);

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct StatefulProtocolSpec {
    /// Maximum allowed size for a single message.
    pub max_message_size: usize,
    /// Is explicit protocol approve is required.
    pub approve_required: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct OneShotProtocolSpec {
    /// Maximum allowed size for a single message.
    pub max_message_size: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StatefulProtocolConfig {
    pub supported_versions: Vec<(ProtocolVer, StatefulProtocolSpec)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OneShotProtocolConfig {
    pub version: ProtocolVer,
    pub spec: OneShotProtocolSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolConfig {
    Stateful(StatefulProtocolConfig),
    OneShot(OneShotProtocolConfig),
}
