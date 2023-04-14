use std::collections::VecDeque;
use std::task::{Context, Poll};

use libp2p::PeerId;

use crate::protocol_handler::sigma_aggregation::message::{SigmaAggrMessage, SigmaAggrSpec};
use crate::protocol_handler::{MalformedMessage, ProtocolBehaviour, ProtocolBehaviourOut, ProtocolSpec};
use crate::types::ProtocolId;

mod message;
mod types;

pub struct SigmaAggregation<PP> {
    commettee: Vec<PeerId>,
    host_peer_id: PeerId,
    peer_partitions: PP,
    outbox: VecDeque<ProtocolBehaviourOut<SigmaAggrMessage, SigmaAggrMessage>>,
}

impl<PP> ProtocolBehaviour for SigmaAggregation<PP> {
    type TProto = SigmaAggrSpec;

    fn get_protocol_id(&self) -> ProtocolId {
        todo!()
    }

    fn inject_peer_connected(&mut self, peer_id: PeerId) {
        todo!()
    }

    fn inject_message(&mut self, peer_id: PeerId, content: SigmaAggrMessage) {
        todo!()
    }

    fn inject_malformed_mesage(&mut self, peer_id: PeerId, details: MalformedMessage) {
        todo!()
    }

    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<SigmaAggrMessage>) {
        todo!()
    }

    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {}

    fn inject_protocol_enabled(&mut self, peer_id: PeerId, handshake: Option<SigmaAggrMessage>) {
        todo!()
    }

    fn inject_protocol_disabled(&mut self, peer_id: PeerId) {
        todo!()
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<ProtocolBehaviourOut<SigmaAggrMessage, SigmaAggrMessage>>> {
        todo!()
    }
}
