use std::borrow::{Borrow, Cow};
use libp2p::PeerId;
use crate::peer::data::{PeerConnState, PeerInfo};
use crate::peer::peer_store::{PeerStore, PeerStoreRejection};
use crate::peer::types::Reputation;

pub struct ConnectedPeer<'a> {
    peer_id: Cow<'a, PeerId>,
    peer_info: &'a mut PeerInfo,
}

pub struct NotConnectedPeer<'a> {
    peer_id: Cow<'a, PeerId>,
    peer_info: &'a mut PeerInfo,
}

impl<'a> NotConnectedPeer<'a> {
    fn to_peer_id(self) -> PeerId {
        self.peer_id.into_owned()
    }
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
    fn peer<'a>(&'a mut self, peer_id: &'a PeerId) -> Option<PeerInState<'a>>;
    fn peer_reputation(&self, peer_id: &PeerId) -> Option<Reputation>;
    fn add_peer(&mut self, peer_id: PeerId, is_reserved: bool) -> Result<NotConnectedPeer, PeerStoreRejection>;
    fn connect_to_peer<'a>(&mut self, peer: NotConnectedPeer<'a>) -> ConnectedPeer<'a>;
    fn disconnect_peer<'a>(&mut self, peer: ConnectedPeer<'a>) -> NotConnectedPeer<'a>;
    fn forget_peer(&mut self, peer: NotConnectedPeer);
}

pub struct DefaultPeersState<S: PeerStore> {
    store: S,
}

impl<S: PeerStore> DefaultPeersState<S> {
    fn new(store: S) -> Self {
        DefaultPeersState { store }
    }
}

impl<S: PeerStore> PeersState for DefaultPeersState<S> {
    fn peer<'a>(&'a mut self, peer_id: &'a PeerId) -> Option<PeerInState<'a>> {
        self.store.get_mut(peer_id).map(|p| match p.state {
            PeerConnState::Connected =>
                PeerInState::Connected(ConnectedPeer { peer_id: Cow::Borrowed(peer_id), peer_info: p }),
            PeerConnState::NotConnected =>
                PeerInState::NotConnected(NotConnectedPeer { peer_id: Cow::Borrowed(peer_id), peer_info: p })
        })
    }

    fn peer_reputation(&self, peer_id: &PeerId) -> Option<Reputation> {
        self.store.get(peer_id).map(|p| p.reputation)
    }

    fn add_peer(&mut self, peer_id: PeerId, is_reserved: bool) -> Result<NotConnectedPeer, PeerStoreRejection> {
        self.store
            .add(&peer_id, PeerInfo::new(is_reserved))
            .map(|p| NotConnectedPeer { peer_id: Cow::Owned(peer_id), peer_info: p })
    }

    fn connect_to_peer<'a>(&mut self, peer: NotConnectedPeer<'a>) -> ConnectedPeer<'a> {
        peer.peer_info.num_connections += 1;
        peer.peer_info.state = PeerConnState::Connected;
        ConnectedPeer { peer_id: peer.peer_id, peer_info: peer.peer_info }
    }

    fn disconnect_peer<'a>(&mut self, peer: ConnectedPeer<'a>) -> NotConnectedPeer<'a> {
        peer.peer_info.state = PeerConnState::NotConnected;
        NotConnectedPeer { peer_id: peer.peer_id, peer_info: peer.peer_info }
    }

    fn forget_peer(&mut self, peer: NotConnectedPeer) {
        self.store.drop(peer.peer_id.borrow());
        ()
    }
}
