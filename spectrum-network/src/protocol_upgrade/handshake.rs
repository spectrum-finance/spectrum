use std::collections::BTreeMap;

use crate::types::{ProtocolVer, RawMessage};

/// A handshake encoded in formats of all supported versions.
/// Note, versions must be listed in descending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolyVerHandshakeSpec(BTreeMap<ProtocolVer, Option<RawMessage>>);

impl PolyVerHandshakeSpec {
    pub fn empty() -> PolyVerHandshakeSpec {
        PolyVerHandshakeSpec(BTreeMap::new())
    }

    pub fn handshake_for(&self, ver: ProtocolVer) -> Option<RawMessage> {
        self.0.get(&ver).cloned().flatten()
    }
}

impl Into<Vec<(ProtocolVer, Option<RawMessage>)>> for PolyVerHandshakeSpec {
    fn into(self) -> Vec<(ProtocolVer, Option<RawMessage>)> {
        self.0.into_iter().collect()
    }
}
