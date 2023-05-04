use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use derive_more::Display;
use futures::stream::FuturesOrdered;
use futures::Stream;
use libp2p::PeerId;
use log::{error, info, trace};

use crate::peer_manager::data::ReputationChange;
use crate::peer_manager::Peers;
use crate::protocol::SYNC_PROTOCOL_ID;
use crate::protocol_handler::discovery::message::{
    HandshakeV1, DiscoveryHandshake, DiscoveryMessage, DiscoveryMessageV1, DiscoverySpec,
};
use crate::protocol_handler::{
    MalformedMessage, NetworkAction, ProtocolBehaviour, ProtocolBehaviourOut, ProtocolSpec,
};
use crate::types::{ProtocolId, ProtocolVer};

pub mod message;

const MAX_SHARED_PEERS: usize = 128;

#[derive(Clone)]
pub struct NodeStatus {
    pub supported_protocols: Vec<ProtocolId>,
    pub height: usize,
}

type SyncBehaviourOut = ProtocolBehaviourOut<DiscoveryHandshake, DiscoveryMessage>;

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

impl<TPeers> SyncBehaviour<TPeers>
where
    TPeers: Peers,
{
    pub fn new(peers: TPeers, local_status: NodeStatus) -> Self {
        Self {
            local_status,
            outbox: VecDeque::new(),
            tracked_peers: HashMap::new(),
            tasks: FuturesOrdered::new(),
            peers,
        }
    }

    fn make_poly_handshake(&self) -> Vec<(ProtocolVer, Option<DiscoveryHandshake>)> {
        let status = &self.local_status;
        vec![(
            DiscoverySpec::v1(),
            Some(DiscoveryHandshake::HandshakeV1(HandshakeV1 {
                supported_protocols: status.supported_protocols.clone(),
                height: status.height,
            })),
        )]
    }

    fn send_get_peers(&mut self, peer_id: PeerId) {
        trace!("Requesting peers from {}", peer_id);
        self.outbox.push_back(SyncBehaviourOut::Send {
            peer_id,
            message: DiscoveryMessage::DiscoveryMessageV1(DiscoveryMessageV1::GetPeers),
        });
    }

    fn send_peers(&mut self, peer_id: PeerId) {
        trace!("Sharing known peers with {}", peer_id);
        let get_peers_fut = self.peers.get_peers(MAX_SHARED_PEERS);
        self.tasks.push(Box::pin({
            async move {
                trace!("Waiting for peers");
                if let Ok(peers) = get_peers_fut.await {
                    trace!("My peers num {}", peers.len());
                    Ok(ProtocolBehaviourOut::Send {
                        peer_id,
                        message: DiscoveryMessage::DiscoveryMessageV1(DiscoveryMessageV1::Peers(
                            peers.into_iter().filter(|p| p.peer_id() != peer_id).collect(),
                        )),
                    })
                } else {
                    Err(SyncBehaviorError::OperationCancelled)
                }
            }
        }));
    }
}

impl<TPeers> ProtocolBehaviour for SyncBehaviour<TPeers>
where
    TPeers: Peers,
{
    type TProto = DiscoverySpec;

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

    fn inject_message(&mut self, peer_id: PeerId, msg: DiscoveryMessage) {
        match msg {
            DiscoveryMessage::DiscoveryMessageV1(DiscoveryMessageV1::GetPeers) => {
                self.send_peers(peer_id);
            }
            DiscoveryMessage::DiscoveryMessageV1(DiscoveryMessageV1::Peers(peers)) => {
                info!("Peer {} sent {} peers", peer_id, peers.len());
                self.peers.add_peers(peers);
            }
        }
    }

    fn inject_malformed_mesage(&mut self, peer_id: PeerId, details: MalformedMessage) {
        self.peers
            .report_peer(peer_id, ReputationChange::MalformedMessage(details));
    }

    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<DiscoveryHandshake>) {
        if let Some(DiscoveryHandshake::HandshakeV1(hs)) = handshake {
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

    fn inject_protocol_enabled(
        &mut self,
        peer_id: PeerId,
        _handshake: Option<<Self::TProto as ProtocolSpec>::THandshake>,
    ) {
        info!("Sync protocol enabled with peer {}", peer_id);
        self.send_get_peers(peer_id);
    }

    fn inject_protocol_disabled(&mut self, peer_id: PeerId) {
        self.tracked_peers.remove(&peer_id);
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<Option<ProtocolBehaviourOut<DiscoveryHandshake, DiscoveryMessage>>> {
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
            return Poll::Ready(Some(out));
        }
        Poll::Pending
    }
}
