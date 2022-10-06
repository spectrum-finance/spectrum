use crate::peer_conn_handler::{ConnHandlerOut, PartialPeerConnHandler};
use crate::peer_manager::Peers;
use crate::protocol::upgrade::ProtocolTag;
use crate::protocol::ProtocolConfig;
use crate::types::RawMessage;
use libp2p::core::connection::ConnectionId;
use libp2p::swarm::{
    ConnectionHandler, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
    PollParameters,
};
use libp2p::PeerId;
use std::collections::VecDeque;
use std::task::{Context, Poll};

#[derive(Debug)]
pub enum NetworkControllerOut {
    Message {
        peer_id: PeerId,
        protocol_tag: ProtocolTag,
        content: RawMessage,
    },
}

pub struct NetworkController<TPeers> {
    supported_protocols: Vec<ProtocolConfig>,
    peers: TPeers,
    pending_actions: VecDeque<NetworkBehaviourAction<NetworkControllerOut, PartialPeerConnHandler>>,
}

impl<TPeers: 'static> NetworkBehaviour for NetworkController<TPeers> {
    type ConnectionHandler = PartialPeerConnHandler;
    type OutEvent = NetworkControllerOut;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        todo!()
    }

    fn inject_event(&mut self, peer_id: PeerId, connection: ConnectionId, event: ConnHandlerOut) {
        todo!()
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        // 1. Try to return a pending action.
        // 2. Poll for instructions from the PM.
        todo!()
    }
}
