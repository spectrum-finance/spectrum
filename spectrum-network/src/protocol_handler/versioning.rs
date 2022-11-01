use crate::types::ProtocolVer;

/// An entity that is bound to a concrete protocol version.
pub trait Versioned {
    fn version(&self) -> ProtocolVer;
}