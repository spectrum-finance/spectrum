use std::task::{Context, Poll};
use libp2p::core::connection::ConnectionId;
use libp2p::PeerId;
use libp2p::swarm::{ConnectionHandler, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction, PollParameters};
use crate::peer_connection::peer_store::{InMemoryPeerStore};

struct Notifications {
    peer_store: InMemoryPeerStore
}

impl NetworkBehaviour for Notifications {

    type ConnectionHandler = ();
    type OutEvent = ();

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        todo!()
    }

    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent) {
        todo!()
    }

    fn poll(&mut self, cx: &mut Context<'_>, params: &mut impl PollParameters) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        todo!()
    }
}