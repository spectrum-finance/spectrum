use crate::peer_manager::data::ReputationChange;

/// Opaque identifier for an incoming connection. Allocated by the network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct IncomingIndex(u64);

impl From<u64> for IncomingIndex {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

/// Reputation value of the node, between `i32::MIN` (we hate that node) and
/// `i32::MAX` (we love that node).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reputation(i32);

impl Reputation {
    pub fn initial() -> Self {
        Self(0)
    }
    pub fn apply(&self, change: ReputationChange) -> Self {
        Reputation(self.0 + change.value)
    }
}

impl From<i32> for Reputation {
    fn from(val: i32) -> Self {
        Self(val)
    }
}

/// Identifier of a protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolId(u8);

impl Into<u8> for ProtocolId {
    fn into(self) -> u8 {
        self.0
    }
}

/// Version of a protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolVer(u8);

impl Into<u8> for ProtocolVer {
    fn into(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawMessage(Vec<u8>);
