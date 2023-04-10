use crate::peer_manager::data::{
    ConnectionDirection, ConnectionState, PeerDestination, PeerInfo, ReputationChange,
};
use crate::peer_manager::peer_index::PeerIndex;
use crate::peer_manager::NetworkingConfig;
use crate::types::{ProtocolId, Reputation};
use libp2p::PeerId;
use smallvec::SmallVec;
use std::borrow::{Borrow, Cow};
use std::collections::hash_map::{Entry, OccupiedEntry};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::Instant;

#[derive(Debug)]
pub struct ConnectedPeer<'a> {
    peer_id: Cow<'a, PeerId>,
    peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
    index: &'a mut PeerIndex,
    best_peers: &'a mut BTreeSet<(PeerId, Reputation)>,
    netw_conf: NetworkingConfig,
}

impl<'a> ConnectedPeer<'a> {
    fn new(
        peer_id: Cow<'a, PeerId>,
        peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
        index: &'a mut PeerIndex,
        best_peers: &'a mut BTreeSet<(PeerId, Reputation)>,
        netw_conf: NetworkingConfig,
    ) -> Self {
        Self {
            peer_id,
            peer_info,
            index,
            best_peers,
            netw_conf,
        }
    }

    fn from_peer(ncp: NotConnectedPeer<'a>) -> Self {
        Self {
            peer_id: ncp.peer_id,
            peer_info: ncp.peer_info,
            index: ncp.index,
            best_peers: ncp.sorted_peers,
            netw_conf: ncp.netw_conf,
        }
    }

    pub fn disconnect(mut self) -> NotConnectedPeer<'a> {
        let peer_info = self.peer_info.get_mut();
        match peer_info.state {
            ConnectionState::Connected(ConnectionDirection::Inbound) => {
                self.index.drop_incoming(self.peer_id.borrow());
            }
            ConnectionState::Connected(ConnectionDirection::Outbound(_)) => {
                self.index.drop_outgoing(self.peer_id.borrow(), peer_info.is_boot);
            }
            _ => {}
        };
        peer_info.state = ConnectionState::NotConnected;
        NotConnectedPeer {
            peer_id: self.peer_id,
            peer_info: self.peer_info,
            index: self.index,
            sorted_peers: self.best_peers,
            netw_conf: self.netw_conf,
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

    pub fn adjust_reputation(&mut self, change: ReputationChange) {
        self.peer_info.get_mut().reputation.apply(change);
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
        self.index.is_protocol_enabled(protocol_id, self.peer_id.borrow())
    }

    pub fn enable_protocol(&mut self, protocol_id: ProtocolId) {
        self.index
            .protocols
            .entry(protocol_id)
            .or_insert_with(HashSet::new)
            .insert(self.peer_id.clone().into_owned());
    }

    pub fn destination(&self) -> PeerDestination {
        let pid = self.peer_id.clone().into_owned();
        if let Some(addr) = &self.peer_info.get().addr {
            PeerDestination::PeerIdWithAddr(pid, addr.clone())
        } else {
            PeerDestination::PeerId(pid)
        }
    }
}

#[derive(Debug)]
pub struct NotConnectedPeer<'a> {
    peer_id: Cow<'a, PeerId>,
    peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
    index: &'a mut PeerIndex,
    sorted_peers: &'a mut BTreeSet<(PeerId, Reputation)>,
    netw_conf: NetworkingConfig,
}

impl<'a> NotConnectedPeer<'a> {
    fn new(
        peer_id: Cow<'a, PeerId>,
        peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
        peer_sets: &'a mut PeerIndex,
        sorted_peers: &'a mut BTreeSet<(PeerId, Reputation)>,
        netw_conf: NetworkingConfig,
    ) -> Self {
        Self {
            peer_id,
            peer_info,
            index: peer_sets,
            sorted_peers,
            netw_conf,
        }
    }

    pub fn connect(self) -> ConnectedPeer<'a> {
        self.index.add_outgoing(self.peer_id.clone().into_owned());
        self.force_connect(ConnectionDirection::Outbound(false))
    }

    pub fn try_accept_connection(self) -> Result<ConnectedPeer<'a>, Self> {
        if self.index.num_inbound < self.netw_conf.max_inbound {
            Ok(self.force_connect(ConnectionDirection::Inbound))
        } else {
            Err(self)
        }
    }

    pub fn forget(self) -> PeerInfo {
        self.sorted_peers
            .remove(&(*self.peer_id, self.peer_info.get().reputation));
        self.peer_info.remove()
    }

    pub fn adjust_reputation(&mut self, change: ReputationChange) {
        self.peer_info.get_mut().reputation.apply(change);
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

    fn force_connect(mut self, direction: ConnectionDirection) -> ConnectedPeer<'a> {
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

    pub fn is_reputation_acceptable(&self, min_acceptable_reputation: Reputation) -> bool {
        match self {
            PeerInState::Connected(cp) => cp.get_reputation() >= min_acceptable_reputation,
            PeerInState::NotConnected(ncp) => ncp.get_reputation() >= min_acceptable_reputation,
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
                    cp.index.reserve_peer(cp.peer_id.clone().into_owned());
                } else {
                    cp.index.drop_reserved_peer(cp.peer_id.borrow());
                }
                cp.peer_info.get_mut().is_reserved = is_reserved;
            }
            PeerInState::NotConnected(ref mut ncp) => {
                if is_reserved {
                    ncp.index.reserve_peer(ncp.peer_id.clone().into_owned());
                } else {
                    ncp.index.drop_reserved_peer(ncp.peer_id.borrow());
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

const MAX_BOOT_PEERS: usize = 8;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkingState {
    /// The node has few known peers.
    NotBootstrapped(SmallVec<[PeerDestination; MAX_BOOT_PEERS]>),
    /// The node has few outbound connections.
    BootInProgress,
    /// The node has enough outbound connects, but still can allocate more.
    Bootstrapped,
    /// The node doesn't need more outbound connections.
    Saturated,
}

/// Peer state transitions.
pub trait PeersState {
    /// Grants access to a peer with the given peer_id if such peer is known.
    fn peer<'a>(&'a mut self, peer_id: &'a PeerId) -> Option<PeerInState<'a>>;

    /// Get known peer destinations.
    fn get_peers(&self, limit: usize) -> Vec<PeerDestination>;

    /// Get reputation of a peer with the given peer_id if such peer is known.
    fn get_peer_reputation(&self, peer_id: &PeerId) -> Option<Reputation>;

    /// Add a peer to PeersState.
    /// Returns a NotConnectedPeer if succeeded.
    fn try_add_peer(
        &mut self,
        peer_id: PeerDestination,
        is_reserved: bool,
        is_boot: bool,
    ) -> Option<NotConnectedPeer>;

    /// Update set of reserved peers in the PeersState.
    /// Returns a set of unknown peers which can't be marked as reserved at the moment.
    fn set_reserved_peers(&mut self, peers: HashSet<PeerId>) -> HashSet<PeerId>;

    /// Get reserved peers.
    fn get_reserved_peers(&self, filter: Option<PeerStateFilter>) -> HashSet<PeerId>;

    /// Get a set of peers we keep the given protocol enabled with.
    fn get_enabled_peers(&self, protocol_id: &ProtocolId) -> Option<&HashSet<PeerId>>;

    /// Get number of connected peers.
    fn num_connected_peers(&self) -> usize;

    /// Get actual networking state.
    fn networking_state(&self) -> NetworkingState;

    /// Get peers satisfying the given predicate.
    fn filter_peers<F>(&mut self, predicate: F) -> Vec<PeerId>
    where
        F: Fn(&PeerId, &PeerInfo) -> bool;

    /// Peek best peer.
    fn pick_best<F>(&self, filter: Option<F>) -> Option<PeerId>
    where
        F: Fn(&PeerId, &PeerInfo) -> bool;
}

pub struct PeerRepo {
    // known peers and what we known about them.
    peers: HashMap<PeerId, PeerInfo>,
    sorted_peers: BTreeSet<(PeerId, Reputation)>,
    index: PeerIndex,
    netw_conf: NetworkingConfig,
    boot_peers: Vec<PeerDestination>,
}

impl PeerRepo {
    pub fn new(netw_conf: NetworkingConfig, boot_peers: Vec<PeerDestination>) -> Self {
        PeerRepo {
            peers: HashMap::new(),
            sorted_peers: BTreeSet::new(),
            index: PeerIndex::new(),
            netw_conf,
            boot_peers,
        }
    }
}

impl PeersState for PeerRepo {
    fn peer<'a>(&'a mut self, peer_id: &'a PeerId) -> Option<PeerInState<'a>> {
        match self.peers.entry(*peer_id) {
            Entry::Occupied(peer_info) => match peer_info.get().state {
                ConnectionState::Connected(_) => Some(PeerInState::Connected(ConnectedPeer::new(
                    Cow::Borrowed(peer_id),
                    peer_info,
                    &mut self.index,
                    &mut self.sorted_peers,
                    self.netw_conf,
                ))),
                ConnectionState::NotConnected => Some(PeerInState::NotConnected(NotConnectedPeer::new(
                    Cow::Borrowed(peer_id),
                    peer_info,
                    &mut self.index,
                    &mut self.sorted_peers,
                    self.netw_conf,
                ))),
            },
            Entry::Vacant(_) => None,
        }
    }

    fn get_peers(&self, limit: usize) -> Vec<PeerDestination> {
        let mut peers = Vec::new();
        for (pid, _) in self.sorted_peers.iter().take(limit) {
            if let Some(pif) = self.peers.get(pid) {
                if let Some(addr) = &pif.addr {
                    peers.push(PeerDestination::PeerIdWithAddr(*pid, addr.clone()))
                } else {
                    peers.push(PeerDestination::PeerId(*pid))
                }
            }
        }
        peers
    }

    fn get_peer_reputation(&self, peer_id: &PeerId) -> Option<Reputation> {
        self.peers.get(peer_id).map(|p| p.reputation)
    }

    fn try_add_peer(
        &mut self,
        peer_dest: PeerDestination,
        is_reserved: bool,
        is_boot: bool,
    ) -> Option<NotConnectedPeer> {
        let pid = peer_dest.peer_id();
        if let std::collections::hash_map::Entry::Vacant(e) = self.peers.entry(pid) {
            self.sorted_peers.insert((pid, Reputation::initial()));
            let peer_info = PeerInfo::new(peer_dest.into_addr(), is_reserved, is_boot);
            e.insert(peer_info);
            if is_reserved {
                self.index.reserve_peer(pid)
            }
            // DEV-399: use Entry::insert_entry() when the feature is stable.
            match self.peers.entry(pid) {
                Entry::Occupied(peer_info) => Some(NotConnectedPeer::new(
                    Cow::Owned(pid),
                    peer_info,
                    &mut self.index,
                    &mut self.sorted_peers,
                    self.netw_conf,
                )),
                Entry::Vacant(_) => None,
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

    fn get_reserved_peers(&self, filter: Option<PeerStateFilter>) -> HashSet<PeerId> {
        let mut result = HashSet::new();
        for pid in &self.index.reserved_peers {
            if let Some(peer) = self.peers.get(pid) {
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
        }
        result
    }

    fn get_enabled_peers(&self, protocol_id: &ProtocolId) -> Option<&HashSet<PeerId>> {
        self.index.protocols.get(protocol_id)
    }

    fn num_connected_peers(&self) -> usize {
        self.index.enabled_connections.len()
    }

    fn networking_state(&self) -> NetworkingState {
        if self.peers.len() < self.netw_conf.min_known_peers {
            NetworkingState::NotBootstrapped(SmallVec::from_vec(self.boot_peers.clone()))
        } else if self.index.num_outbound - self.index.boot_peers.len() < self.netw_conf.min_outbound {
            NetworkingState::BootInProgress
        } else if self.index.num_outbound < self.netw_conf.max_outbound {
            NetworkingState::Bootstrapped
        } else {
            NetworkingState::Saturated
        }
    }

    fn filter_peers<F>(&mut self, predicate: F) -> Vec<PeerId>
    where
        F: Fn(&PeerId, &PeerInfo) -> bool,
    {
        let mut res = Vec::new();
        for (pid, pif) in self.peers.iter() {
            if predicate(pid, pif) {
                res.push(*pid)
            }
        }
        res
    }

    fn pick_best<F>(&self, filter: Option<F>) -> Option<PeerId>
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
}
