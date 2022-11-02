use crate::protocol::{ProtocolSpec, SYNC_PROTOCOL_ID};
use crate::protocol_handler::sync::message::{HandshakeV1, SyncHandshake, SyncMessage, SyncSpec};
use crate::protocol_handler::{MalformedMessage, NetworkAction, ProtocolBehaviour, ProtocolBehaviourOut};
use crate::types::{ProtocolId, ProtocolVer};
use libp2p::PeerId;
use std::collections::{HashMap, VecDeque};
use std::task::{Context, Poll};

pub mod data;
pub mod message;

pub struct NodeStatus {
    pub supported_protocols: Vec<ProtocolId>,
    pub height: usize,
}

pub struct SyncBehaviour {
    local_status: NodeStatus,
    outbox: VecDeque<ProtocolBehaviourOut<SyncHandshake, SyncMessage>>,
    peers: HashMap<PeerId, NodeStatus>,
}

impl SyncBehaviour {
    pub fn new(local_status: NodeStatus) -> Self {
        Self {
            local_status,
            outbox: VecDeque::new(),
            peers: HashMap::new(),
        }
    }
}

impl ProtocolBehaviour for SyncBehaviour {
    type TProto = SyncSpec;

    fn get_protocol_id(&self) -> ProtocolId {
        SYNC_PROTOCOL_ID
    }

    fn inject_message(&mut self, peer_id: PeerId, content: SyncMessage) {}

    fn inject_malformed_mesage(&mut self, peer_id: PeerId, details: MalformedMessage) {}

    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<SyncHandshake>) {
        if let Some(SyncHandshake::HandshakeV1(hs)) = handshake {
            self.peers.insert(
                peer_id,
                NodeStatus {
                    supported_protocols: hs.supported_protocols,
                    height: hs.height,
                },
            );
        }
        // todo: DEV-384: Maybe no need for PolyVerHandshake here (bc version should already be defined)?
        self.inject_protocol_requested_locally(peer_id)
    }

    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {
        let status = &self.local_status;
        self.outbox
            .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::EnablePeer {
                peer_id,
                handshakes: vec![(
                    SyncSpec::v1(),
                    Some(SyncHandshake::HandshakeV1(HandshakeV1 {
                        supported_protocols: status.supported_protocols.clone(),
                        height: status.height,
                    })),
                )],
            }))
    }

    fn inject_protocol_enabled(&mut self, peer_id: PeerId, handshake: Option<SyncHandshake>) {}

    fn inject_protocol_disabled(&mut self, peer_id: PeerId) {}

    fn poll(&mut self, cx: &mut Context) -> Poll<ProtocolBehaviourOut<SyncHandshake, SyncMessage>> {
        if let Some(out) = self.outbox.pop_front() {
            return Poll::Ready(out);
        }
        return Poll::Pending;
    }
}
