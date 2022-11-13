use crate::peer_manager::Peers;
use crate::protocol::SYNC_PROTOCOL_ID;
use crate::protocol_handler::sync::message::{
    HandshakeV1, SyncHandshake, SyncMessage, SyncMessageV1, SyncSpec,
};
use crate::protocol_handler::{MalformedMessage, NetworkAction, ProtocolBehaviour, ProtocolBehaviourOut};
use crate::types::{ProtocolId, ProtocolVer};
use derive_more::Display;
use futures::stream::FuturesOrdered;
use futures::Stream;
use libp2p::PeerId;
use log::{error, info};
use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub mod data;
pub mod message;

const MAX_SHARED_PEERS: usize = 128;

pub struct NodeStatus {
    pub supported_protocols: Vec<ProtocolId>,
    pub height: usize,
}

type SyncBehaviourOut = ProtocolBehaviourOut<SyncHandshake, SyncMessage>;

#[derive(Debug, Display)]
pub enum SyncBehaviorError {
    EmptyPeers,
    OperationCancelled,
}

type SyncTask = Pin<Box<dyn Future<Output = Result<SyncBehaviourOut, SyncBehaviorError>> + Send>>;

pub struct SyncBehaviour<TPeers> {
    local_status: NodeStatus,
    outbox: VecDeque<SyncBehaviourOut>,
    tracked_peers: HashMap<PeerId, NodeStatus>,
    // ideally tasks should be ordered in the scope of one peer.
    tasks: FuturesOrdered<SyncTask>,
    peers: TPeers,
}

impl<TPeers> SyncBehaviour<TPeers> {
    pub fn new(peers: TPeers, local_status: NodeStatus) -> Self {
        Self {
            local_status,
            outbox: VecDeque::new(),
            tracked_peers: HashMap::new(),
            tasks: FuturesOrdered::new(),
            peers,
        }
    }

    fn make_poly_handshake(&self) -> Vec<(ProtocolVer, Option<SyncHandshake>)> {
        let status = &self.local_status;
        vec![(
            SyncSpec::v1(),
            Some(SyncHandshake::HandshakeV1(HandshakeV1 {
                supported_protocols: status.supported_protocols.clone(),
                height: status.height,
            })),
        )]
    }
}

impl<TPeers> ProtocolBehaviour for SyncBehaviour<TPeers>
where
    TPeers: Peers,
{
    type TProto = SyncSpec;

    fn get_protocol_id(&self) -> ProtocolId {
        SYNC_PROTOCOL_ID
    }

    fn inject_peer_connected(&mut self, peer_id: PeerId) {
        // Immediately enable sync with the peer.
        self.outbox
            .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::EnablePeer {
                peer_id,
                handshakes: self.make_poly_handshake(),
            }))
    }

    fn inject_message(&mut self, peer_id: PeerId, msg: SyncMessage) {
        match msg {
            SyncMessage::SyncMessageV1(SyncMessageV1::GetPeers) => {
                let get_peers_fut = self.peers.get_peers(MAX_SHARED_PEERS);
                self.tasks.push(Box::pin({
                    async move {
                        if let Ok(peers) = get_peers_fut.await {
                            Ok(ProtocolBehaviourOut::Send {
                                peer_id,
                                message: SyncMessage::SyncMessageV1(SyncMessageV1::Peers(peers.into())),
                            })
                        } else {
                            Err(SyncBehaviorError::OperationCancelled)
                        }
                    }
                }));
            }
            SyncMessage::SyncMessageV1(SyncMessageV1::Peers(peers)) => {
                info!("Peer {} sent {} peers", peer_id, peers.len());
                self.peers.add_peers(peers);
            }
        }
    }

    fn inject_malformed_mesage(&mut self, peer_id: PeerId, details: MalformedMessage) {}

    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<SyncHandshake>) {
        if let Some(SyncHandshake::HandshakeV1(hs)) = handshake {
            self.tracked_peers.insert(
                peer_id,
                NodeStatus {
                    supported_protocols: hs.supported_protocols,
                    height: hs.height,
                },
            );
        }
        // todo: DEV-384: Maybe no need for PolyVerHandshake here (bc version should already be defined)?
        self.outbox
            .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::EnablePeer {
                peer_id,
                handshakes: self.make_poly_handshake(),
            }))
    }

    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {
        self.outbox
            .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::EnablePeer {
                peer_id,
                handshakes: self.make_poly_handshake(),
            }))
    }

    fn inject_protocol_enabled(&mut self, peer_id: PeerId) {
        info!("Sync protocol enabled with peer {}", peer_id)
    }

    fn inject_protocol_disabled(&mut self, peer_id: PeerId) {
        self.tracked_peers.remove(&peer_id);
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<ProtocolBehaviourOut<SyncHandshake, SyncMessage>> {
        loop {
            match Stream::poll_next(Pin::new(&mut self.tasks), cx) {
                Poll::Ready(Some(Ok(out))) => {
                    self.outbox.push_back(out);
                    continue;
                }
                Poll::Ready(Some(Err(err))) => {
                    error!("An error occured: {}", err);
                    continue;
                }
                Poll::Pending | Poll::Ready(None) => break,
            }
        }
        if let Some(out) = self.outbox.pop_front() {
            return Poll::Ready(out);
        }
        Poll::Pending
    }
}
