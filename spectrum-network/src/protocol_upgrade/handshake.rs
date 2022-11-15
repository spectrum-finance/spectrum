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

impl From<PolyVerHandshakeSpec> for Vec<(ProtocolVer, Option<RawMessage>)> {
    fn from(p: PolyVerHandshakeSpec) -> Self {
        p.0.into_iter().collect()
    }
}

impl From<Vec<(ProtocolVer, Option<RawMessage>)>> for PolyVerHandshakeSpec {
    fn from(xs: Vec<(ProtocolVer, Option<RawMessage>)>) -> Self {
        Self(BTreeMap::from_iter(xs))
    }
}

impl From<BTreeMap<ProtocolVer, Option<RawMessage>>> for PolyVerHandshakeSpec {
    fn from(xs: BTreeMap<ProtocolVer, Option<RawMessage>>) -> Self {
        Self(xs)
    }
}
