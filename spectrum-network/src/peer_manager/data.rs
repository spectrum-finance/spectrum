use crate::types::{ProtocolId, Reputation};
use libp2p::Multiaddr;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationChange {
    MalformedMessage = 10,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionLossReason {
    /// Connection has been explicitly reset by peer.
    ResetByPeer,
    /// Connection has been closed for an unknown reason.
    Unknown,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connected(ConnectionDirection),
    NotConnected,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound(bool), // confirmed or not
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
    /// Time last successful connection attempt was made.
    pub last_handshake: Option<Instant>,
    /// Backoff of the next outbound connection attempt.
    pub outbound_backoff_until: Option<Instant>,
    /// Protocols supported by the peer. `None` if unknown.
    pub supported_protocols: Option<Vec<ProtocolId>>,
}

impl PeerInfo {
    pub fn new(is_reserved: bool) -> Self {
        Self {
            is_reserved,
            reputation: Reputation::initial(),
            state: ConnectionState::NotConnected,
            num_connections: 0,
            last_handshake: None,
            outbound_backoff_until: None,
            supported_protocols: None,
        }
    }

    pub fn supports(&self, protocol: &ProtocolId) -> Option<bool> {
        self.supported_protocols
            .as_ref()
            .map(|ps| ps.contains(protocol))
    }

    pub fn confirm_new_conn(&mut self) {
        let _ = self.num_connections.saturating_add(1);
    }
}

/// Policy of protocols allocation defines the way we should
/// actively allocate connections for a particular protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolAllocationPolicy {
    /// Allocate up to the specified % of all connectons.
    Bounded(usize),
    /// Allocate as many as possible connections.
    Max,
    /// Do not allocate any connections.
    Zero,
}
