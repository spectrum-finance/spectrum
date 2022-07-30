use crate::peer::data::{PeerConnState, PeerInfo, ReputationChange};
use crate::peer::peer_in_state::{ConnectedPeer, NotConnectedPeer, PeerInState};
use crate::peer::peer_store::{PeerStore, PeerStoreRejection};
use crate::peer::types::Reputation;
use libp2p::PeerId;

/// Peer state transitions.
pub trait PeersState {
    fn get_peer(&mut self, peer_id: &PeerId) -> Option<PeerInState>;
    fn get_peer_reputation(&self, peer_id: &PeerId) -> Option<Reputation>;
    fn add_peer(
        &mut self,
        peer_id: &PeerId,
        is_reserved: bool,
    ) -> Result<NotConnectedPeer, PeerStoreRejection>;
    fn forget_peer(&mut self, peer_id: &PeerId) -> bool;
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
    fn get_peer(&mut self, peer_id: &PeerId) -> Option<PeerInState> {
        self.store.get_mut(peer_id).map(|p| match p.state {
            PeerConnState::Connected => PeerInState::Connected(ConnectedPeer::new(*peer_id, p)),
            PeerConnState::NotConnected => {
                PeerInState::NotConnected(NotConnectedPeer::new(*peer_id, p))
            }
        })
    }

    fn get_peer_reputation(&self, peer_id: &PeerId) -> Option<Reputation> {
        self.store.get(peer_id).map(|p| p.reputation)
    }

    fn add_peer(
        &mut self,
        peer_id: &PeerId,
        is_reserved: bool,
    ) -> Result<NotConnectedPeer, PeerStoreRejection> {
        self.store
            .add(&peer_id, PeerInfo::new(is_reserved))
            .map(|p| NotConnectedPeer::new(*peer_id, p))
    }

    fn forget_peer(&mut self, peer_id: &PeerId) -> bool {
        self.store.drop(peer_id)
    }
}

pub enum PeersStateException {
    PeerStoreRejection(PeerStoreRejection),
}
