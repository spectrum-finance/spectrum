use crate::peer::data::{PeerConnState, PeerInfo, ReputationChange};
use crate::peer::peer_store::PeerStoreRejection;
use libp2p::PeerId;

pub struct ConnectedPeer<'a> {
    peer_id: PeerId,
    peer_info: &'a mut PeerInfo,
}

impl<'a> ConnectedPeer<'a> {
    pub fn new(peer_id: PeerId, peer_info: &'a mut PeerInfo) -> ConnectedPeer<'a> {
        ConnectedPeer { peer_id, peer_info }
    }

    fn disconnect_peer(&'a mut self) -> NotConnectedPeer<'a> {
        self.peer_info.state = PeerConnState::NotConnected;
        NotConnectedPeer {
            peer_id: self.peer_id,
            peer_info: self.peer_info,
        }
    }
}

pub struct NotConnectedPeer<'a> {
    peer_id: PeerId,
    peer_info: &'a mut PeerInfo,
}

impl<'a> NotConnectedPeer<'a> {
    pub fn new(peer_id: PeerId, peer_info: &'a mut PeerInfo) -> NotConnectedPeer<'a> {
        NotConnectedPeer { peer_id, peer_info }
    }

    fn connect_to_peer(&'a mut self) -> ConnectedPeer<'a> {
        self.peer_info.num_connections += 1;
        self.peer_info.state = PeerConnState::Connected;
        ConnectedPeer {
            peer_id: self.peer_id,
            peer_info: self.peer_info,
        }
    }
}

pub enum PeerInState<'a> {
    /// We are connected to this peer.
    Connected(ConnectedPeer<'a>),
    /// We are connected to this peer.
    NotConnected(NotConnectedPeer<'a>),
}

impl<'a> PeerInState<'a> {
    fn adjust_peer_reputation(&self, adjustment: ReputationChange) -> () {
        match self {
            PeerInState::Connected(cp) => {
                cp.peer_info.reputation.apply(adjustment);
            }
            PeerInState::NotConnected(ncp) => {
                ncp.peer_info.reputation.apply(adjustment);
            }
        }
    }
}
