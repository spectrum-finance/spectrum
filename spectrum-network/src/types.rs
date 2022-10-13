use crate::peer_manager::data::ReputationChange;
use libp2p::bytes::BytesMut;
use std::cmp::Ordering;

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
        Reputation(self.0 + change as i32)
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

impl From<u8> for ProtocolId {
    fn from(val: u8) -> Self {
        Self(val)
    }
}

/// Version of a protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolVer(u8);

impl Ord for ProtocolVer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0).reverse()
    }
}

impl PartialOrd for ProtocolVer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Into<u8> for ProtocolVer {
    fn into(self) -> u8 {
        self.0
    }
}

impl From<u8> for ProtocolVer {
    fn from(v: u8) -> Self {
        ProtocolVer(v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawMessage(Vec<u8>);

impl From<Vec<u8>> for RawMessage {
    fn from(xs: Vec<u8>) -> Self {
        RawMessage(xs)
    }
}

impl From<BytesMut> for RawMessage {
    fn from(xs: BytesMut) -> Self {
        RawMessage(xs.freeze().to_vec())
    }
}

impl Into<Vec<u8>> for RawMessage {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl AsRef<[u8]> for RawMessage {
    fn as_ref(&self) -> &[u8] {
        &*self.0
    }
}
