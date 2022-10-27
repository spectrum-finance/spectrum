use crate::peer_manager::data::{ConnectionDirection, ConnectionState, PeerInfo, ReputationChange};
use crate::peer_manager::peer_index::{PeerIndex, PeerIndexConfig};
use crate::types::{ProtocolId, Reputation};
use libp2p::PeerId;
use std::borrow::{Borrow, Cow};
use std::collections::hash_map::{Entry, OccupiedEntry};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Instant;

#[derive(Debug)]
pub struct ConnectedPeer<'a> {
    peer_id: Cow<'a, PeerId>,
    peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
    peer_sets: &'a mut PeerIndex,
    best_peers: &'a mut BTreeSet<(PeerId, Reputation)>,
}

impl<'a> ConnectedPeer<'a> {
    fn new(
        peer_id: Cow<'a, PeerId>,
        peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
        peer_sets: &'a mut PeerIndex,
        best_peers: &'a mut BTreeSet<(PeerId, Reputation)>,
    ) -> Self {
        Self {
            peer_id,
            peer_info,
            peer_sets,
            best_peers,
        }
    }

    fn from_peer(not_connected_peer: NotConnectedPeer<'a>) -> Self {
        Self {
            peer_id: not_connected_peer.peer_id,
            peer_info: not_connected_peer.peer_info,
            peer_sets: not_connected_peer.peer_sets,
            best_peers: not_connected_peer.sorted_peers,
        }
    }

    pub fn disconnect(mut self) -> NotConnectedPeer<'a> {
        let peer_info = self.peer_info.get_mut();
        match peer_info.state {
            ConnectionState::Connected(ConnectionDirection::Inbound) => {
                self.peer_sets.drop_incoming(self.peer_id.borrow())
            }
            ConnectionState::Connected(ConnectionDirection::Outbound(_)) => {
                self.peer_sets.drop_outgoing(self.peer_id.borrow())
            }
            _ => panic!("impossible"),
        };
        peer_info.state = ConnectionState::NotConnected;
        NotConnectedPeer {
            peer_id: self.peer_id,
            peer_info: self.peer_info,
            peer_sets: self.peer_sets,
            sorted_peers: self.best_peers,
        }
    }

    pub fn confirm_connection(&mut self) -> bool {
        let peer_info = self.peer_info.get_mut();
        match peer_info.state {
            ConnectionState::Connected(ConnectionDirection::Outbound(false)) => {
                peer_info.state = ConnectionState::Connected(ConnectionDirection::Outbound(true));
                true
            }
            _ => false,
        }
    }

    pub fn is_confirmed(&self) -> bool {
        let st = self.peer_info.get().state;
        matches!(
            st,
            ConnectionState::Connected(ConnectionDirection::Outbound(true))
        ) || matches!(st, ConnectionState::Connected(ConnectionDirection::Inbound))
    }

    pub fn get_reputation(&self) -> Reputation {
        self.peer_info.get().reputation
    }

    pub fn get_conn_direction(&self) -> ConnectionDirection {
        match self.peer_info.get().state {
            ConnectionState::Connected(dir) => dir,
            _ => panic!("impossible"),
        }
    }

    pub fn handshaked(&mut self) {
        self.peer_info.get_mut().last_handshake = Some(Instant::now());
    }
    
    pub fn is_protocol_enabled(&self, protocol_id: &ProtocolId) -> bool {
        self.peer_sets
            .is_protocol_enabled(protocol_id, self.peer_id.borrow())
    }

    pub fn enable_protocol(&mut self, protocol_id: ProtocolId) {
        self.peer_sets
            .protocols
            .entry(protocol_id)
            .or_insert(HashSet::new())
            .insert(self.peer_id.clone().into_owned());
    }
}

#[derive(Debug)]
pub struct NotConnectedPeer<'a> {
    peer_id: Cow<'a, PeerId>,
    peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
    peer_sets: &'a mut PeerIndex,
    sorted_peers: &'a mut BTreeSet<(PeerId, Reputation)>,
}

impl<'a> NotConnectedPeer<'a> {
    fn new(
        peer_id: Cow<'a, PeerId>,
        peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
        peer_sets: &'a mut PeerIndex,
        sorted_peers: &'a mut BTreeSet<(PeerId, Reputation)>,
    ) -> Self {
        Self {
            peer_id,
            peer_info,
            peer_sets,
            sorted_peers,
        }
    }

    pub fn try_connect(self) -> Result<ConnectedPeer<'a>, Self> {
        let added = self.peer_sets.try_add_outgoing(self.peer_id.clone().into_owned());
        if added {
            Ok(self.connect(ConnectionDirection::Outbound(false)))
        } else {
            Err(self)
        }
    }

    pub fn try_accept_connection(self) -> Result<ConnectedPeer<'a>, Self> {
        let added = self.peer_sets.try_add_incoming(self.peer_id.clone().into_owned());
        if added {
            Ok(self.connect(ConnectionDirection::Inbound))
        } else {
            Err(self)
        }
    }

    pub fn forget_peer(self) -> PeerInfo {
        self.sorted_peers
            .remove(&(*self.peer_id, self.peer_info.get().reputation));
        self.peer_info.remove()
    }

    pub fn get_reputation(&self) -> Reputation {
        self.peer_info.get().reputation
    }

    pub fn is_reserved(&self) -> bool {
        self.peer_info.get().is_reserved
    }

    pub fn set_backoff_until(&mut self, ts: Instant) {
        self.peer_info.get_mut().outbound_backoff_until = Some(ts);
    }

    pub fn backoff_until(&self) -> Option<Instant> {
        self.peer_info.get().outbound_backoff_until
    }

    fn connect(mut self, direction: ConnectionDirection) -> ConnectedPeer<'a> {
        let peer_info = self.peer_info.get_mut();
        let _ = peer_info.num_connections.saturating_add(1);
        peer_info.state = ConnectionState::Connected(direction);

        ConnectedPeer::from_peer(self)
    }
}

#[derive(Debug)]
pub enum PeerInState<'a> {
    /// We are connected to this peer.
    Connected(ConnectedPeer<'a>),
    /// We are not connected to this peer.
    NotConnected(NotConnectedPeer<'a>),
}

impl<'a> PeerInState<'a> {
    pub fn set_protocols(&mut self, protocols: Vec<ProtocolId>) {
        match self {
            PeerInState::Connected(ref mut cp) => {
                cp.peer_info.get_mut().supported_protocols = Some(protocols);
            }
            PeerInState::NotConnected(ref mut ncp) => {
                ncp.peer_info.get_mut().supported_protocols = Some(protocols);
            }
        }
    }

    pub fn adjust_reputation(self, adjustment: ReputationChange) -> Self {
        match self {
            PeerInState::Connected(mut cp) => {
                let old_rep = cp.peer_info.get().reputation;
                let new_rep = old_rep.apply(adjustment);
                cp.peer_info.get_mut().reputation = new_rep;
                cp.best_peers.remove(&(*cp.peer_id, old_rep));
                cp.best_peers.insert((*cp.peer_id, new_rep));
                PeerInState::Connected(cp)
            }
            PeerInState::NotConnected(mut ncp) => {
                let old_rep = ncp.peer_info.get().reputation;
                let new_rep = old_rep.apply(adjustment);
                ncp.peer_info.get_mut().reputation = new_rep;
                ncp.sorted_peers.remove(&(*ncp.peer_id, old_rep));
                ncp.sorted_peers.insert((*ncp.peer_id, new_rep));
                PeerInState::NotConnected(ncp)
            }
        }
    }

    pub fn get_reputation(&self) -> Reputation {
        match self {
            PeerInState::Connected(cp) => cp.peer_info.get().reputation,
            PeerInState::NotConnected(ncp) => ncp.peer_info.get().reputation,
        }
    }

    pub fn set_reserved(&mut self, is_reserved: bool) {
        match self {
            PeerInState::Connected(ref mut cp) => {
                if is_reserved {
                    cp.peer_sets.reserve_peer(cp.peer_id.clone().into_owned());
                } else {
                    cp.peer_sets.drop_reserved_peer(cp.peer_id.borrow());
                }
                cp.peer_info.get_mut().is_reserved = is_reserved;
            }
            PeerInState::NotConnected(ref mut ncp) => {
                if is_reserved {
                    ncp.peer_sets.reserve_peer(ncp.peer_id.clone().into_owned());
                } else {
                    ncp.peer_sets.drop_reserved_peer(ncp.peer_id.borrow());
                }
                ncp.peer_info.get_mut().is_reserved = is_reserved;
            }
        }
    }
}

pub enum PeerStateFilter {
    Connected,
    NotConnected,
}

/// Peer state transitions.
pub trait PeersState {
    /// Grants access to a peer with the given peer_id if such peer is known.
    fn peer<'a>(&'a mut self, peer_id: &'a PeerId) -> Option<PeerInState<'a>>;

    /// Get reputation of a peer with the given peer_id if such peer is known.
    fn get_peer_reputation(&self, peer_id: &PeerId) -> Option<Reputation>;

    /// Add a peer to PeersState.
    /// Returns a NotConnectedPeer if succeeded.
    fn try_add_peer(&mut self, peer_id: PeerId, is_reserved: bool) -> Option<NotConnectedPeer>;

    /// Update set of reserved peers in the PeersState.
    /// Returns a set of unknown peers which can't be marked as reserved at the moment.
    fn set_reserved_peers(&mut self, peers: HashSet<PeerId>) -> HashSet<PeerId>;

    /// Get reserved peers.
    fn get_reserved_peers(&mut self, filter: Option<PeerStateFilter>) -> HashSet<PeerId>;

    /// Peek best peer.
    fn peek_best<F>(&self, filter: Option<F>) -> Option<PeerId>
    where
        F: Fn(&PeerId, &PeerInfo) -> bool;

    /// Get a set of peers we keep the given protocol enabled with.
    fn get_enabled_peers(&self, protocol_id: &ProtocolId) -> Option<&HashSet<PeerId>>;

    /// Get a number of connected peers.
    fn num_connected_peers(&self) -> usize;
}

pub struct PeersStateDef {
    peers: HashMap<PeerId, PeerInfo>,
    sorted_peers: BTreeSet<(PeerId, Reputation)>,
    index: PeerIndex,
}

impl PeersStateDef {
    pub fn new(peer_index_conf: PeerIndexConfig) -> Self {
        PeersStateDef {
            peers: HashMap::new(),
            sorted_peers: BTreeSet::new(),
            index: PeerIndex::new(peer_index_conf),
        }
    }
}

impl PeersState for PeersStateDef {
    fn peer<'a>(&'a mut self, peer_id: &'a PeerId) -> Option<PeerInState<'a>> {
        match self.peers.entry(peer_id.clone()) {
            Entry::Occupied(peer_info) => match peer_info.get().state {
                ConnectionState::Connected(_) => Some(PeerInState::Connected(ConnectedPeer::new(
                    Cow::Borrowed(peer_id),
                    peer_info,
                    &mut self.index,
                    &mut self.sorted_peers,
                ))),
                ConnectionState::NotConnected => Some(PeerInState::NotConnected(NotConnectedPeer::new(
                    Cow::Borrowed(peer_id),
                    peer_info,
                    &mut self.index,
                    &mut self.sorted_peers,
                ))),
            },
            Entry::Vacant(_) => None,
        }
    }

    fn get_peer_reputation(&self, peer_id: &PeerId) -> Option<Reputation> {
        self.peers.get(peer_id).map(|p| p.reputation)
    }

    fn try_add_peer(&mut self, peer_id: PeerId, is_reserved: bool) -> Option<NotConnectedPeer> {
        if !self.peers.contains_key(&peer_id) {
            let peer_info = PeerInfo::new(is_reserved);
            self.peers.insert(peer_id, peer_info);
            if is_reserved {
                self.index.reserve_peer(peer_id)
            }
            match self.peers.entry(peer_id) {
                Entry::Occupied(peer_info) => Some(NotConnectedPeer::new(
                    Cow::Owned(peer_id),
                    peer_info,
                    &mut self.index,
                    &mut self.sorted_peers,
                )),
                Entry::Vacant(_) => panic!("impossible"),
            }
        } else {
            None
        }
    }

    fn set_reserved_peers(&mut self, peers: HashSet<PeerId>) -> HashSet<PeerId> {
        let mut unknown_peers = HashSet::<PeerId>::new();
        let mut known_reserved_peers = HashSet::<PeerId>::new();
        for pid in peers {
            if let Some(mut pstate) = self.peer(&pid) {
                pstate.set_reserved(true);
                known_reserved_peers.insert(pid);
            } else {
                unknown_peers.insert(pid);
            }
        }
        self.index.update_reserved_set(known_reserved_peers);
        unknown_peers
    }

    fn get_reserved_peers(&mut self, filter: Option<PeerStateFilter>) -> HashSet<PeerId> {
        let mut result = HashSet::<PeerId>::new();
        for pid in &self.index.reserved_peers {
            match self.peers.get(pid) {
                Some(peer) => {
                    if peer.is_reserved {
                        match (peer.state, &filter) {
                            (ConnectionState::Connected(_), Some(PeerStateFilter::Connected)) => {
                                result.insert(*pid);
                            }
                            (ConnectionState::NotConnected, Some(PeerStateFilter::NotConnected)) => {
                                result.insert(*pid);
                            }
                            (_, None) => {
                                result.insert(*pid);
                            }
                            _ => {}
                        }
                    }
                }
                None => {}
            }
        }
        result
    }

    fn peek_best<F>(&self, filter: Option<F>) -> Option<PeerId>
    where
        F: Fn(&PeerId, &PeerInfo) -> bool,
    {
        for (pid, _) in &self.sorted_peers {
            match self.peers.get(pid) {
                Some(pi) if filter.as_ref().map(|f| f(pid, pi)).unwrap_or(true) => {
                    return Some(*pid);
                }
                _ => continue,
            }
        }
        None
    }

    fn get_enabled_peers(&self, protocol_id: &ProtocolId) -> Option<&HashSet<PeerId>> {
        self.index.protocols.get(protocol_id)
    }

    fn num_connected_peers(&self) -> usize {
        self.index.enabled_connections.len()
    }
}
