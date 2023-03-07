use std::{
    collections::{HashMap, VecDeque},
    marker::PhantomData,
    pin::Pin,
};

use derive_more::Display;
use futures::{stream::FuturesOrdered, Future};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::{peer_manager::Peers, protocol::HANDEL_PROTOCOL_ID, types::ProtocolId};

use self::{
    message::{HandelHandshake, HandelMessage, HandelSpec},
    protocol::{Aggregable, HandelNodeState, Verifiable, Weighable},
};

use super::{ProtocolBehaviour, ProtocolBehaviourOut};

mod message;
mod protocol;

#[derive(Clone)]
pub struct NodeStatus {
    pub supported_protocols: Vec<ProtocolId>,
    pub height: usize,
}

type HandelBehaviourOut<C> = ProtocolBehaviourOut<HandelHandshake<C>, HandelMessage<C>>;

#[derive(Debug, Display)]
pub enum HandelBehaviorError {
    EmptyPeers,
}

type HandelTask<C> = Pin<Box<dyn Future<Output = Result<HandelBehaviourOut<C>, HandelBehaviorError>> + Send>>;

pub struct HandelBehaviour<'de, TPeers, C, R: 'de> {
    node_state: HandelNodeState<C>,
    local_status: NodeStatus,
    outbox: VecDeque<HandelBehaviourOut<C>>,
    tracked_peers: HashMap<PeerId, NodeStatus>,
    // ideally tasks should be ordered in the scope of one peer.
    tasks: FuturesOrdered<HandelTask<C>>,
    peers: TPeers,
    phantom: PhantomData<&'de R>,
}

impl<'de, TPeers, C, R> HandelBehaviour<'de, TPeers, C, R>
where
    TPeers: Peers,
    C: Aggregable
        + Weighable
        + Verifiable
        + Clone
        + Serialize
        + Deserialize<'de>
        + Send
        + core::fmt::Debug
        + 'static,
{
}

impl<'de, TPeers, C, R> ProtocolBehaviour for HandelBehaviour<'de, TPeers, C, R>
where
    TPeers: Peers,
    C: Aggregable
        + Weighable
        + Verifiable
        + Clone
        + Serialize
        + Deserialize<'de>
        + Send
        + core::fmt::Debug
        + 'static,
{
    type TProto = HandelSpec<'de, C>;

    fn get_protocol_id(&self) -> ProtocolId {
        HANDEL_PROTOCOL_ID
    }

    fn inject_peer_connected(&mut self, peer_id: PeerId) {
        todo!()
    }

    fn inject_message(&mut self, peer_id: PeerId, content: <Self::TProto as super::ProtocolSpec>::TMessage) {
        todo!()
    }

    fn inject_malformed_mesage(&mut self, peer_id: PeerId, details: super::MalformedMessage) {
        todo!()
    }

    fn inject_protocol_requested(
        &mut self,
        peer_id: PeerId,
        handshake: Option<<Self::TProto as super::ProtocolSpec>::THandshake>,
    ) {
        todo!()
    }

    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {
        todo!()
    }

    fn inject_protocol_enabled(
        &mut self,
        peer_id: PeerId,
        handshake: Option<<Self::TProto as super::ProtocolSpec>::THandshake>,
    ) {
        todo!()
    }

    fn inject_protocol_disabled(&mut self, peer_id: PeerId) {
        todo!()
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<
        ProtocolBehaviourOut<
            <Self::TProto as super::ProtocolSpec>::THandshake,
            <Self::TProto as super::ProtocolSpec>::TMessage,
        >,
    > {
        todo!()
    }
}
