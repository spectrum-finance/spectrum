use crate::peer_conn_handler::ConnHandlerError;
use crate::types::{ProtocolId, Reputation};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerDestination {
    PeerId(PeerId),
    PeerIdWithAddr(PeerId, Multiaddr),
}

impl PeerDestination {
    pub fn peer_id(&self) -> PeerId {
        match self {
            PeerDestination::PeerId(pid) => *pid,
            PeerDestination::PeerIdWithAddr(pid, _) => *pid,
        }
    }

    pub fn into_addr(self) -> Option<Multiaddr> {
        match self {
            PeerDestination::PeerIdWithAddr(_, addr) => Some(addr),
            PeerDestination::PeerId(_) => None,
        }
    }
}

impl Serialize for PeerDestination {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        todo!()
    }
}

impl<'de> Deserialize<'de> for PeerDestination {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        todo!()
    }
}

impl Into<DialOpts> for PeerDestination {
    fn into(self) -> DialOpts {
        match self {
            PeerDestination::PeerId(pid) => DialOpts::peer_id(pid)
                .condition(PeerCondition::NotDialing)
                .build(),
            PeerDestination::PeerIdWithAddr(pid, addr) => DialOpts::peer_id(pid)
                .condition(PeerCondition::NotDialing)
                .addresses(vec![addr])
                .build(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationChange {
    MalformedMessage,
    NoResponse,
    TooSlow,
}

impl From<ReputationChange> for i32 {
    fn from(c: ReputationChange) -> Self {
        match c {
            ReputationChange::MalformedMessage => -10,
            ReputationChange::NoResponse => -10,
            ReputationChange::TooSlow => -10,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionLossReason {
    /// Connection has been explicitly reset by peer.
    ResetByPeer,
    /// Connection has been closed by us because of the err.
    Reset(ConnHandlerError),
    /// Connection has been closed for an unknown reason.
    Unknown,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connected(ConnectionDirection),
    NotConnected,
}

impl ConnectionState {
    pub fn is_connected(self) -> bool {
        match self {
            ConnectionState::Connected(_) => true,
            ConnectionState::NotConnected => false,
        }
    }
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
    /// Is this peer a reserved one.
    /// We should do our best to remain connected to reserved peers.
    pub is_reserved: bool,
    /// Is this peer a bootstrapping one.
    pub is_boot: bool,
    /// An address this peer can be reached at.
    pub addr: Option<Multiaddr>,
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
    pub fn new(addr: Option<Multiaddr>, is_reserved: bool, is_boot: bool) -> Self {
        Self {
            is_reserved,
            is_boot,
            addr,
            reputation: Reputation::initial(),
            state: ConnectionState::NotConnected,
            num_connections: 0,
            last_handshake: None,
            outbound_backoff_until: None,
            supported_protocols: None,
        }
    }

    pub fn supports(&self, protocol: &ProtocolId) -> Option<bool> {
        self.supported_protocols.as_ref().map(|ps| ps.contains(protocol))
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
