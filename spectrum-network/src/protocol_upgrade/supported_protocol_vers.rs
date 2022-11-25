//! Wrapper types around `ProtocolId` and `ProtocolVer` and collections of them. Using them ensures
//! at the type-level that the collections of supported `ProtocolId`s and `ProtocolVer`s are
//! determined at peer-startup and that they cannot change. Furthermore the existence of a
//! `SupportProtocol[Id|Ver]` instance is a guarantee that the peer supports that protocol [id|ver].

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
};

use libp2p::core::upgrade;

#[cfg(feature = "integration_tests")]
use crate::protocol_handler::fake_sync_behaviour::FakeSyncSpec;
use crate::{
    protocol::SYNC_PROTOCOL_ID,
    protocol_handler::sync::message::SyncSpec,
    types::{ProtocolId, ProtocolTag, ProtocolVer},
};

/// Ensures that a supported protocol can return `SupportedProtocolId`.
pub trait GetSupportedProtocolId {
    fn get_supported_id() -> SupportedProtocolId;
}

/// Ensures that a supported protocol can return a supported protocol version.
pub trait GetSupportedProtocolVer {
    fn get_supported_ver() -> SupportedProtocolVer;
}

impl GetSupportedProtocolVer for SyncSpec {
    fn get_supported_ver() -> SupportedProtocolVer {
        SupportedProtocolVer(Self::v1())
    }
}

impl GetSupportedProtocolId for SyncSpec {
    fn get_supported_id() -> SupportedProtocolId {
        SupportedProtocolId(SYNC_PROTOCOL_ID)
    }
}

#[cfg(feature = "integration_tests")]
impl GetSupportedProtocolId for FakeSyncSpec {
    fn get_supported_id() -> SupportedProtocolId {
        SupportedProtocolId(SYNC_PROTOCOL_ID)
    }
}

/// A B-tree mapping from `SupportedProtocolVer` to `T`. Keys are ordered from highest to lowest.
/// Once created, the mapping itself cannot be altered, but the mapped values can be mutated.
#[derive(Debug, Clone)]
pub struct SupportedProtocolVerBTreeMap<T>(BTreeMap<ProtocolVer, T>);

impl<T> SupportedProtocolVerBTreeMap<T> {
    pub fn get(&self, ver: SupportedProtocolVer) -> &T {
        #[allow(clippy::unwrap_used)]
        self.0.get(&ver.0).unwrap()
    }

    pub fn keys(&self) -> impl Iterator<Item = SupportedProtocolVer> + '_ {
        self.0.keys().cloned().map(SupportedProtocolVer)
    }
}

impl<T> From<Vec<(SupportedProtocolVer, T)>> for SupportedProtocolVerBTreeMap<T> {
    fn from(v: Vec<(SupportedProtocolVer, T)>) -> Self {
        Self(v.into_iter().map(|(ver, t)| (ver.get_inner(), t)).collect())
    }
}

/// A wrapper over `ProtocolId`.
///
/// **INVARIANT:** any `SupportedProtocolId` instance points to a valid
/// mapping in ANY instance of [`SupportedProtocolIdMap`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SupportedProtocolId(ProtocolId);

impl SupportedProtocolId {
    /// It's safe to expose the underlying [`ProtocolId`].
    pub fn get_inner(&self) -> ProtocolId {
        self.0
    }
}

/// A wrapper over `ProtocolVer`.
///
/// **INVARIANT:** any `SupportedProtocolVer` instance points to a valid
/// mapping in ANY instance of [`SupportedProtocolVerBTreeMap`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SupportedProtocolVer(ProtocolVer);

impl SupportedProtocolVer {
    /// It's safe to expose the underlying [`ProtocolVer`].
    pub fn get_inner(&self) -> ProtocolVer {
        self.0
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SupportedProtocolTag(ProtocolTag);

impl SupportedProtocolTag {
    pub fn protocol_ver(&self) -> SupportedProtocolVer {
        SupportedProtocolVer::from(*self)
    }

    pub fn protocol_id(&self) -> SupportedProtocolId {
        SupportedProtocolId::from(*self)
    }
}

impl SupportedProtocolTag {
    pub fn new(protocol_id: SupportedProtocolId, protocol_ver: SupportedProtocolVer) -> Self {
        Self(ProtocolTag::new(protocol_id.0, protocol_ver.0))
    }
}

impl From<SupportedProtocolTag> for SupportedProtocolVer {
    fn from(p: SupportedProtocolTag) -> Self {
        Self(ProtocolVer::from(p.0))
    }
}

impl From<SupportedProtocolTag> for SupportedProtocolId {
    fn from(p: SupportedProtocolTag) -> Self {
        Self(ProtocolId::from(p.0))
    }
}

impl upgrade::ProtocolName for SupportedProtocolTag {
    fn protocol_name(&self) -> &[u8] {
        self.0.protocol_name()
    }
}

impl Display for SupportedProtocolTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A mapping from `SupportedProtocolId` to `T`. Once created, the mapping itself cannot be altered,
/// but the mapped values can be mutated.
pub struct SupportedProtocolIdMap<T>(HashMap<ProtocolId, T>);

impl<T> From<HashMap<ProtocolId, T>> for SupportedProtocolIdMap<T> {
    fn from(h: HashMap<ProtocolId, T>) -> Self {
        Self(h)
    }
}

impl<T> From<Vec<(SupportedProtocolId, T)>> for SupportedProtocolIdMap<T> {
    fn from(v: Vec<(SupportedProtocolId, T)>) -> Self {
        Self(v.into_iter().map(|(id, t)| (id.get_inner(), t)).collect())
    }
}

impl<T> SupportedProtocolIdMap<T> {
    pub fn get(&self, id: ProtocolId) -> Option<&T> {
        self.0.get(&id)
    }

    pub fn get_mut(&mut self, id: ProtocolId) -> Option<(SupportedProtocolId, &mut T)> {
        self.0.get_mut(&id).map(|t| (SupportedProtocolId(id), t))
    }

    pub fn get_supported(&self, id: SupportedProtocolId) -> &T {
        #[allow(clippy::unwrap_used)]
        self.0.get(&id.0).unwrap()
    }

    pub fn get_supported_mut(&mut self, id: SupportedProtocolId) -> &mut T {
        #[allow(clippy::unwrap_used)]
        self.0.get_mut(&id.0).unwrap()
    }

    pub fn iter(&self) -> impl Iterator<Item = (SupportedProtocolId, &T)> {
        self.0.iter().map(|(id, v)| (SupportedProtocolId(*id), v))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SupportedProtocolId, &mut T)> {
        self.0.iter_mut().map(|(id, v)| (SupportedProtocolId(*id), v))
    }

    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.0.values()
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.0.values_mut()
    }
}
