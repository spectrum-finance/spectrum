use crate::peer::data::ReputationChange;

/// Opaque identifier for an incoming connection. Allocated by the network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct IncomingIndex(pub u64);

impl From<u64> for IncomingIndex {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

/// Reputation value of the node, between `i32::MIN` (we hate that node) and
/// `i32::MAX` (we love that node).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Reputation(pub i32);

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
