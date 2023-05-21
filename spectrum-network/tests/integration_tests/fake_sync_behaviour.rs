//! This fake Sync protocol is adapted from the Sync protocol. Used to test for malformed-messages.

use std::{
    collections::{HashMap, VecDeque},
    pin::Pin,
    task::{Context, Poll},
};

use derive_more::Display;
use futures::{stream::FuturesOrdered, Future, Stream};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use spectrum_network::{
    peer_manager::Peers,
    protocol::DISCOVERY_PROTOCOL_ID,
    protocol_handler::{
        discovery::{
            message::{DiscoveryHandshake, DiscoverySpec, HandshakeV1},
            NodeStatus,
        },
        versioning::Versioned,
        NetworkAction, ProtocolBehaviour, ProtocolBehaviourOut,
    },
    types::{ProtocolId, ProtocolVer},
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum FakeSyncMessage {
    SyncMessageV1(FakeSyncMessageV1),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum FakeSyncMessageV1 {
    /// This is the message which will be regarded as malformed by the receiving peer.
    FakeMsg,
}

impl Versioned for FakeSyncMessage {
    fn version(&self) -> ProtocolVer {
        match self {
            FakeSyncMessage::SyncMessageV1(_) => FakeSyncSpec::v1(),
        }
    }
}

pub struct FakeSyncSpec;

impl FakeSyncSpec {
    pub fn v1() -> ProtocolVer {
        ProtocolVer::from(1)
    }
}

impl<'de> spectrum_network::protocol_handler::ProtocolSpec<'de> for FakeSyncSpec {
    type THandshake = DiscoveryHandshake;
    type TMessage = FakeSyncMessage;
}

type SyncBehaviourOut = ProtocolBehaviourOut<DiscoveryHandshake, FakeSyncMessage>;

#[derive(Debug, Display)]
pub enum SyncBehaviorError {
    EmptyPeers,
    OperationCancelled,
}

type SyncTask = Pin<Box<dyn Future<Output = Result<SyncBehaviourOut, SyncBehaviorError>> + Send>>;

pub struct FakeSyncBehaviour<TPeers> {
    local_status: NodeStatus,
    outbox: VecDeque<SyncBehaviourOut>,
    tracked_peers: HashMap<PeerId, NodeStatus>,
    // ideally tasks should be ordered in the scope of one peer.
    tasks: FuturesOrdered<SyncTask>,
    _peers: TPeers,
}

impl<TPeers> FakeSyncBehaviour<TPeers>
where
    TPeers: Peers,
{
    pub fn new(peers: TPeers, local_status: NodeStatus) -> Self {
        Self {
            local_status,
            outbox: VecDeque::new(),
            tracked_peers: HashMap::new(),
            tasks: FuturesOrdered::new(),
            _peers: peers,
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

    fn send_fake_msg(&mut self, peer_id: PeerId) {
        self.outbox.push_back(SyncBehaviourOut::Send {
            peer_id,
            message: FakeSyncMessage::SyncMessageV1(FakeSyncMessageV1::FakeMsg),
        });
        #[cfg(feature = "test_peer_punish_too_slow")]
        {
            self.outbox.push_back(SyncBehaviourOut::Send {
                peer_id,
                message: FakeSyncMessage::SyncMessageV1(FakeSyncMessageV1::FakeMsg),
            });
            self.outbox.push_back(SyncBehaviourOut::Send {
                peer_id,
                message: FakeSyncMessage::SyncMessageV1(FakeSyncMessageV1::FakeMsg),
            });
            self.outbox.push_back(SyncBehaviourOut::Send {
                peer_id,
                message: FakeSyncMessage::SyncMessageV1(FakeSyncMessageV1::FakeMsg),
            });
            self.outbox.push_back(SyncBehaviourOut::Send {
                peer_id,
                message: FakeSyncMessage::SyncMessageV1(FakeSyncMessageV1::FakeMsg),
            });
        }
    }
}

impl<'de, TPeers> ProtocolBehaviour<'de> for FakeSyncBehaviour<TPeers>
where
    TPeers: Peers,
{
    type TProto = FakeSyncSpec;

    fn inject_peer_connected(&mut self, peer_id: PeerId) {
        // Immediately enable sync with the peer.
        self.outbox
            .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::EnablePeer {
                peer_id,
                handshakes: self.make_poly_handshake(),
            }))
    }

    fn inject_message(&mut self, peer_id: PeerId, msg: FakeSyncMessage) {
        self.send_fake_msg(peer_id);
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
        _handshake: Option<
            <Self::TProto as spectrum_network::protocol_handler::ProtocolSpec<'de>>::THandshake,
        >,
    ) {
        self.send_fake_msg(peer_id);
    }

    fn inject_protocol_disabled(&mut self, peer_id: PeerId) {
        self.tracked_peers.remove(&peer_id);
    }

    fn poll(
        &mut self,
        cx: &mut Context,
    ) -> Poll<Option<ProtocolBehaviourOut<DiscoveryHandshake, FakeSyncMessage>>> {
        loop {
            match Stream::poll_next(Pin::new(&mut self.tasks), cx) {
                Poll::Ready(Some(Ok(out))) => {
                    self.outbox.push_back(out);
                    continue;
                }
                Poll::Ready(Some(Err(_))) => {
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
