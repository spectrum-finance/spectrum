use crate::peer_connection::data::{PeerConnState, PeerInfo, ReputationChange};
use crate::peer_connection::peer_store::{PeerStore, PeerStoreRejection};
use crate::peer_connection::types::Reputation;
use libp2p::PeerId;

pub struct ConnectedPeer<'a> {
    peer_id: PeerId,
    peer_info: &'a mut PeerInfo,
}

pub struct NotConnectedPeer<'a> {
    peer_id: PeerId,
    peer_info: &'a mut PeerInfo,
}

pub enum PeerInState<'a> {
    /// We are connected to this peer.
    Connected(ConnectedPeer<'a>),
    /// We are connected to this peer.
    NotConnected(NotConnectedPeer<'a>),
}

pub enum PeersStateException {
    PeerStoreRejection(PeerStoreRejection),
}

/// Peer state transitions.
pub trait PeersState {
    fn peer(&mut self, peer_id: PeerId) -> Option<PeerInState>;
    fn peer_reputation(&self, peer_id: PeerId) -> Option<Reputation>;
    fn adjust_peer_reputation<'a>(
        &self,
        adjustment: ReputationChange,
        peer: PeerInState<'a>,
    ) -> PeerInState<'a>;
    fn add_peer(
        &mut self,
        peer_id: PeerId,
        is_reserved: bool,
    ) -> Result<NotConnectedPeer, PeerStoreRejection>;
    fn connect_to_peer<'a>(&self, peer: NotConnectedPeer<'a>) -> ConnectedPeer<'a>;
    fn disconnect_peer<'a>(&self, peer: ConnectedPeer<'a>) -> NotConnectedPeer<'a>;
    fn forget_peer(&mut self, peer: NotConnectedPeer);
}

pub struct DefaultPeersState<S: PeerStore> {
    store: S,
}

impl<S: PeerStore> DefaultPeersState<S> {
    pub fn new(store: S) -> Self {
        DefaultPeersState { store }
    }
}

impl<S: PeerStore> PeersState for DefaultPeersState<S> {
    fn peer(&mut self, peer_id: PeerId) -> Option<PeerInState> {
        self.store.get_mut(&peer_id).map(|p| match p.state {
            PeerConnState::Connected => PeerInState::Connected(ConnectedPeer {
                peer_id,
                peer_info: p,
            }),
            PeerConnState::NotConnected => PeerInState::NotConnected(NotConnectedPeer {
                peer_id,
                peer_info: p,
            }),
        })
    }

    fn peer_reputation(&self, peer_id: PeerId) -> Option<Reputation> {
        self.store.get(&peer_id).map(|p| p.reputation)
    }

    fn adjust_peer_reputation<'a>(
        &self,
        adjustment: ReputationChange,
        peer: PeerInState<'a>,
    ) -> PeerInState<'a> {
        match peer {
            PeerInState::Connected(cp) => {
                cp.peer_info.reputation.apply(adjustment);
                PeerInState::Connected(cp)
            }
            PeerInState::NotConnected(ncp) => {
                ncp.peer_info.reputation.apply(adjustment);
                PeerInState::NotConnected(ncp)
            }
        }
    }

    fn add_peer(
        &mut self,
        peer_id: PeerId,
        is_reserved: bool,
    ) -> Result<NotConnectedPeer, PeerStoreRejection> {
        self.store
            .add(&peer_id, PeerInfo::new(is_reserved))
            .map(|p| NotConnectedPeer {
                peer_id,
                peer_info: p,
            })
    }

    fn connect_to_peer<'a>(&self, peer: NotConnectedPeer<'a>) -> ConnectedPeer<'a> {
        peer.peer_info.num_connections += 1;
        peer.peer_info.state = PeerConnState::Connected;
        ConnectedPeer {
            peer_id: peer.peer_id,
            peer_info: peer.peer_info,
        }
    }

    fn disconnect_peer<'a>(&self, peer: ConnectedPeer<'a>) -> NotConnectedPeer<'a> {
        peer.peer_info.state = PeerConnState::NotConnected;
        NotConnectedPeer {
            peer_id: peer.peer_id,
            peer_info: peer.peer_info,
        }
    }

    fn forget_peer(&mut self, peer: NotConnectedPeer) {
        self.store.drop(&peer.peer_id);
    }
}
