use std::time::Instant;
use crate::peer::types::Reputation;
use libp2p::Multiaddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReputationChange {
    /// Reputation delta.
    pub value: i32,
    /// Reason for reputation change.
    pub reason: &'static str,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionLossReason {
    ResetByPeer,
    Unknown,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connected(ConnectionDirection),
    NotConnected,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionDirection {
    Incoming,
    Outgoing(bool), // confirmed or not
}

#[derive(PartialEq, Debug)]
pub struct Peer {
    pub addr: Multiaddr,
    pub info: PeerInfo,
}

#[derive(PartialEq, Debug, Clone)]
pub struct PeerInfo {
    /// Is the node a reserved peer or not.
    /// We should do our best to remain connected to reserved peers.
    pub is_reserved: bool,
    /// Reputation value of the node, between `i32::MIN` (we hate that node) and
    /// `i32::MAX` (we love that node).
    pub reputation: Reputation,
    pub state: ConnectionState,
    /// How many successful connections with this node do we have.
    pub num_connections: u32,
    pub last_conn_attempt: Option<Instant>
}

impl PeerInfo {
    pub fn new(is_reserved: bool) -> Self {
        Self {
            is_reserved,
            reputation: Reputation::initial(),
            state: ConnectionState::NotConnected,
            num_connections: 0,
            last_conn_attempt: None
        }
    }
}
