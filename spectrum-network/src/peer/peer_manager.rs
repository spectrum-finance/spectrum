use libp2p::PeerId;
use crate::peer::types::{IncomingIndex, Reputation};
use std::borrow::Cow;
use std::collections::HashMap;
use crate::peer::data::{PeerConnState, PeerInfo};

#[derive(Debug, PartialEq)]
pub enum Message {
    /// Request to open a connection to the given peer. From the point of view of the PSM, we are
    /// immediately connected.
    Connect(PeerId),

    /// Drop the connection to the given peer, or cancel the connection attempt after a `Connect`.
    Drop(PeerId),

    /// Equivalent to `Connect` for the peer corresponding to this incoming index.
    Accept(IncomingIndex),

    /// Equivalent to `Drop` for the peer corresponding to this incoming index.
    Reject(IncomingIndex),
}

/// Async API to PeerManager.
pub trait Peers {
    fn add_reserved_peer(&self, peer_id: PeerId);
}
