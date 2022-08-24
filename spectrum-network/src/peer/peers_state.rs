use crate::peer::data::{ConnectionDirection, ConnectionState, PeerInfo, ReputationChange};
use crate::peer::peer_manager::Peers;
use crate::peer::peer_store::{PeerSets, PeerSetsConfig};
use crate::peer::types::Reputation;
use libp2p::PeerId;
use std::borrow::{Borrow, Cow};
use std::collections::hash_map::{Entry, OccupiedEntry};
use std::collections::{HashMap, HashSet};

#[derive(Debug)]
pub struct ConnectedPeer<'a> {
    peer_id: Cow<'a, PeerId>,
    peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
    peer_set: &'a mut PeerSets,
}

impl<'a> ConnectedPeer<'a> {
    fn new(
        peer_id: Cow<'a, PeerId>,
        peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
        peer_set: &'a mut PeerSets,
    ) -> Self {
        Self {
            peer_id,
            peer_info,
            peer_set,
        }
    }

    fn from_peer(not_connected_peer: NotConnectedPeer<'a>) -> Self {
        Self {
            peer_id: not_connected_peer.peer_id,
            peer_info: not_connected_peer.peer_info,
            peer_set: not_connected_peer.peer_set,
        }
    }

    pub fn disconnect_peer(mut self) -> NotConnectedPeer<'a> {
        let peer_info = self.peer_info.get_mut();
        match peer_info.state {
            ConnectionState::Connected(ConnectionDirection::Incoming) => {
                self.peer_set.drop_incoming(self.peer_id.borrow())
            }
            ConnectionState::Connected(ConnectionDirection::Outgoing) => {
                self.peer_set.drop_outgoing(self.peer_id.borrow())
            }
            _ => panic!("impossible"),
        };
        peer_info.state = ConnectionState::NotConnected;
        NotConnectedPeer {
            peer_id: self.peer_id,
            peer_info: self.peer_info,
            peer_set: self.peer_set,
        }
    }
}

#[derive(Debug)]
pub struct NotConnectedPeer<'a> {
    peer_id: Cow<'a, PeerId>,
    peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
    peer_set: &'a mut PeerSets,
}

impl<'a> NotConnectedPeer<'a> {
    fn new(
        peer_id: Cow<'a, PeerId>,
        peer_info: OccupiedEntry<'a, PeerId, PeerInfo>,
        store: &'a mut PeerSets,
    ) -> Self {
        Self {
            peer_id,
            peer_info,
            peer_set: store,
        }
    }

    pub fn try_connect(self) -> Result<ConnectedPeer<'a>, Self> {
        let added = self
            .peer_set
            .try_add_outgoing(self.peer_id.clone().into_owned());
        if added {
            Ok(self.connect(ConnectionDirection::Outgoing))
        } else {
            Err(self)
        }
    }

    pub fn try_accept_connection(self) -> Result<ConnectedPeer<'a>, Self> {
        let added = self
            .peer_set
            .try_add_incoming(self.peer_id.clone().into_owned());
        if added {
            Ok(self.connect(ConnectionDirection::Incoming))
        } else {
            Err(self)
        }
    }

    pub fn forget_peer(self) -> PeerInfo {
        self.peer_info.remove()
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
    pub fn adjust_peer_reputation(self, adjustment: ReputationChange) -> Self {
        match self {
            PeerInState::Connected(mut cp) => {
                cp.peer_info.get_mut().reputation.apply(adjustment);
                PeerInState::Connected(cp)
            }
            PeerInState::NotConnected(mut ncp) => {
                ncp.peer_info.get_mut().reputation.apply(adjustment);
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

    pub fn set_reserved(self, is_reserved: bool) -> Self {
        match self {
            PeerInState::Connected(mut cp) => {
                if is_reserved {
                    cp.peer_set.reserve_peer(cp.peer_id.clone().into_owned());
                } else {
                    cp.peer_set.drop_reserved_peer(cp.peer_id.borrow());
                }
                cp.peer_info.get_mut().is_reserved = is_reserved;
                PeerInState::Connected(cp)
            }
            PeerInState::NotConnected(mut ncp) => {
                if is_reserved {
                    ncp.peer_set.reserve_peer(ncp.peer_id.clone().into_owned());
                } else {
                    ncp.peer_set.drop_reserved_peer(ncp.peer_id.borrow());
                }
                ncp.peer_info.get_mut().is_reserved = is_reserved;
                PeerInState::NotConnected(ncp)
            }
        }
    }
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
}

pub struct DefaultPeersState {
    peers: HashMap<PeerId, PeerInfo>,
    // todo: replace with BTreeMap
    connections: PeerSets,
}

impl DefaultPeersState {
    pub fn new(peer_set_conf: PeerSetsConfig) -> Self {
        DefaultPeersState {
            peers: HashMap::new(),
            connections: PeerSets::new(peer_set_conf),
        }
    }
}

impl PeersState for DefaultPeersState {
    fn peer<'a>(&'a mut self, peer_id: &'a PeerId) -> Option<PeerInState<'a>> {
        match self.peers.entry(peer_id.clone()) {
            Entry::Occupied(peer_info) => match peer_info.get().state {
                ConnectionState::Connected(_) => Some(PeerInState::Connected(ConnectedPeer::new(
                    Cow::Borrowed(peer_id),
                    peer_info,
                    &mut self.connections,
                ))),
                ConnectionState::NotConnected => Some(PeerInState::NotConnected(
                    NotConnectedPeer::new(Cow::Borrowed(peer_id), peer_info, &mut self.connections),
                )),
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
                self.connections.reserve_peer(peer_id)
            };
            match self.peers.entry(peer_id) {
                Entry::Occupied(peer_info) => Some(NotConnectedPeer::new(
                    Cow::Owned(peer_id),
                    peer_info,
                    &mut self.connections,
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
            if let Some(pstate) = self.peer(&pid) {
                pstate.set_reserved(true);
                known_reserved_peers.insert(pid);
            } else {
                unknown_peers.insert(pid);
            }
        }
        self.connections.update_reserved_set(known_reserved_peers);
        unknown_peers
    }
}
