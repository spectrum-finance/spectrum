use std::collections::{BTreeMap, HashMap};
use std::fmt::Debug;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use either::Either;
use futures::channel::mpsc;
use futures::channel::mpsc::Receiver;
use futures::Stream;
pub use libp2p::swarm::NetworkBehaviour;
use libp2p::PeerId;
use log::{error, trace};
use void::Void;

use crate::network_controller::NetworkAPI;
use crate::peer_conn_handler::message_sink::MessageSink;
use crate::peer_conn_handler::stream::FusedStream;
use crate::protocol_api::{ProtocolEvent, ProtocolMailbox};
use crate::protocol_handler::versioning::Versioned;
use crate::protocol_upgrade::handshake::PolyVerHandshakeSpec;
use crate::types::{ProtocolId, ProtocolTag, ProtocolVer, RawMessage};

pub mod aggregation;
pub mod codec;
pub mod cosi;
pub mod diffusion;
pub mod discovery;
pub mod handel;
pub mod sigma_aggregation;
pub mod versioning;
mod pool;

#[derive(Debug)]
pub enum NetworkAction<THandshake, TMessage> {
    /// A directive to enable the specified protocol with the specified peer.
    EnablePeer {
        /// A specific peer we should start the protocol with.
        peer_id: PeerId,
        /// A set of all possible handshakes (of all versions, as long as concrete version
        /// not yet negotiated) to send to the peer upon negotiation of protocol substream.
        handshakes: Vec<(ProtocolVer, Option<THandshake>)>,
    },
    /// A directive to update the set of protocols supported by the specified peer.
    UpdatePeerProtocols {
        peer: PeerId,
        protocols: Vec<ProtocolId>,
    },
    /// Send the given message to the specified peer without
    /// establishing a persistent two-way communication channel.
    SendOneShotMessage {
        peer: PeerId,
        use_version: ProtocolVer,
        message: TMessage,
    },
    /// Ban peer.
    BanPeer(PeerId),
}

#[derive(Debug)]
pub enum ProtocolBehaviourOut<THandshake, TMessage> {
    Send { peer_id: PeerId, message: TMessage },
    NetworkAction(NetworkAction<THandshake, TMessage>),
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolHandlerError {
    #[error("Message deserialization failed.")]
    MalformedMessage(RawMessage),
}

pub trait ProtocolSpec<'de> {
    type THandshake: serde::Serialize + serde::Deserialize<'de> + Versioned + Send;
    type TMessage: serde::Serialize + serde::Deserialize<'de> + Versioned + Debug + Send + Clone;
}

impl<'de, L, R> ProtocolSpec<'de> for Either<L, R>
where
    L: ProtocolSpec<'de>,
    R: ProtocolSpec<'de>,
{
    type THandshake = Either<L::THandshake, R::THandshake>;
    type TMessage = Either<L::TMessage, R::TMessage>;
}

/// Defines behaviour of particular stages of a protocol that terminates with `TOut`,
/// e.g. a single cycle of a protocol consisting of repeating rounds.
pub trait TemporalProtocolStage<THandshake, TMessage, TOut> {
    /// Inject an event that we have established a conn with a peer.
    fn inject_peer_connected(&mut self, peer_id: PeerId) {}

    /// Inject a new message coming from a peer.
    fn inject_message(&mut self, peer_id: PeerId, content: TMessage) {}

    /// Inject protocol request coming from a peer.
    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<THandshake>) {}

    /// Inject local protocol request coming from a peer.
    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {}

    /// Inject an event of protocol being enabled with a peer.
    fn inject_protocol_enabled(&mut self, peer_id: PeerId, handshake: Option<THandshake>) {}

    /// Inject an event of protocol being disabled with a peer.
    fn inject_protocol_disabled(&mut self, peer_id: PeerId) {}

    /// Poll for output actions.
    /// `Either::Right(TOut)` when behaviour has terminated.
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Either<ProtocolBehaviourOut<THandshake, TMessage>, TOut>>;
}

pub trait ProtocolBehaviour<'de> {
    /// Protocol specification.
    type TProto: ProtocolSpec<'de>;

    /// Inject an event that we have established a conn with a peer.
    fn inject_peer_connected(&mut self, peer_id: PeerId) {}

    /// Inject a new message coming from a peer.
    fn inject_message(&mut self, peer_id: PeerId, content: <Self::TProto as ProtocolSpec<'de>>::TMessage) {}

    /// Inject protocol request coming from a peer.
    fn inject_protocol_requested(
        &mut self,
        peer_id: PeerId,
        handshake: Option<<Self::TProto as ProtocolSpec<'de>>::THandshake>,
    ) {
    }

    /// Inject local protocol request coming from a peer.
    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {}

    /// Inject an event of protocol being enabled with a peer.
    fn inject_protocol_enabled(
        &mut self,
        peer_id: PeerId,
        handshake: Option<<Self::TProto as ProtocolSpec<'de>>::THandshake>,
    ) {
    }

    /// Inject an event of protocol being disabled with a peer.
    fn inject_protocol_disabled(&mut self, peer_id: PeerId) {}

    /// Poll for output actions.
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        Option<
            ProtocolBehaviourOut<
                <Self::TProto as ProtocolSpec<'de>>::THandshake,
                <Self::TProto as ProtocolSpec<'de>>::TMessage,
            >,
        >,
    >;
}

/// A layer that facilitate massage transmission from protocol handlers to peers.
pub struct ProtocolHandler<'de, TBehaviour, TNetwork> {
    peers: HashMap<PeerId, MessageSink>,
    inbox: Receiver<ProtocolEvent>,
    pub protocol: ProtocolId,
    behaviour: TBehaviour,
    network: TNetwork,
    pd: PhantomData<&'de Void>,
}

impl<'de, TBehaviour, TNetwork> ProtocolHandler<'de, TBehaviour, TNetwork> {
    pub fn new(
        behaviour: TBehaviour,
        network: TNetwork,
        protocol: ProtocolId,
        msg_buffer_size: usize,
    ) -> (Self, ProtocolMailbox) {
        let (snd, recv) = mpsc::channel::<ProtocolEvent>(msg_buffer_size);
        let prot_mailbox = ProtocolMailbox::new(snd);
        let prot_handler = Self {
            peers: HashMap::new(),
            inbox: recv,
            protocol,
            behaviour,
            network,
            pd: PhantomData::default(),
        };
        (prot_handler, prot_mailbox)
    }
}

impl<'de, TBehaviour, TNetwork> Stream for ProtocolHandler<'de, TBehaviour, TNetwork>
where
    TBehaviour: ProtocolBehaviour<'de> + Unpin,
    TNetwork: NetworkAPI + Unpin,
{
    #[cfg(feature = "integration_tests")]
    type Item = <TBehaviour::TProto as ProtocolSpec<'de>>::TMessage;
    #[cfg(not(feature = "integration_tests"))]
    type Item = ();

    /// Polls the behaviour and the network, forwarding events from the former to the latter and
    /// vice versa.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            // 1. Poll behaviour for commands
            // (1) is polled before (2) to prioritize local work over incoming requests/events.
            match self.behaviour.poll(cx) {
                Poll::Ready(Some(out)) => {
                    match out {
                        ProtocolBehaviourOut::Send { peer_id, message } => {
                            trace!("Sending message {:?} to peer {}", message, peer_id);
                            if let Some(sink) = self.peers.get(&peer_id) {
                                trace!("Sink is available");
                                if let Err(_) = sink.send_message(codec::encode(message.clone())) {
                                    trace!("Failed to submit a message to {:?}. Channel is closed.", peer_id)
                                }
                                trace!("Sent");
                                #[cfg(feature = "integration_tests")]
                                return Poll::Ready(Some(message));
                            } else {
                                error!("Cannot find sink for peer {}", peer_id);
                            }
                        }
                        ProtocolBehaviourOut::NetworkAction(action) => match action {
                            NetworkAction::EnablePeer {
                                peer_id: peer,
                                handshakes,
                            } => {
                                let poly_spec = PolyVerHandshakeSpec::from(
                                    handshakes
                                        .into_iter()
                                        .map(|(v, m)| (v, m.map(codec::encode)))
                                        .collect::<BTreeMap<_, _>>(),
                                );
                                self.network.enable_protocol(self.protocol, peer, poly_spec);
                            }
                            NetworkAction::UpdatePeerProtocols { peer, protocols } => {
                                self.network.update_peer_protocols(peer, protocols);
                            }
                            NetworkAction::SendOneShotMessage {
                                peer,
                                use_version,
                                message,
                            } => {
                                let message_bytes = codec::encode(message.clone());
                                let protocol = ProtocolTag::new(self.protocol, use_version);
                                self.network.send_one_shot_message(peer, protocol, message_bytes);
                            }
                            NetworkAction::BanPeer(pid) => self.network.ban_peer(pid),
                        },
                    }
                    continue;
                }
                Poll::Ready(None) => return Poll::Ready(None), // terminate, behaviour is exhausted
                Poll::Pending => {}
            }

            // 2. Poll incoming events.
            if let Poll::Ready(Some(notif)) = Stream::poll_next(Pin::new(&mut self.inbox), cx) {
                match notif {
                    ProtocolEvent::Connected(peer_id) => {
                        trace!("Connected {:?}", peer_id);
                        self.behaviour.inject_peer_connected(peer_id);
                    }
                    ProtocolEvent::Message {
                        peer_id,
                        protocol_ver: negotiated_ver,
                        content,
                    } => {
                        if let Ok(msg) = codec::decode::<
                            <<TBehaviour as ProtocolBehaviour>::TProto as ProtocolSpec>::TMessage,
                        >(content)
                        {
                            let actual_ver = msg.version();
                            if actual_ver == negotiated_ver {
                                self.behaviour.inject_message(peer_id, msg);
                            } else {
                                self.network.ban_peer(peer_id);
                            }
                        } else {
                            self.network.ban_peer(peer_id);
                        }
                    }
                    ProtocolEvent::Requested {
                        peer_id,
                        protocol_ver: negotiated_ver,
                        handshake,
                    } => {
                        match handshake.map(
                            codec::decode::<
                                <<TBehaviour as ProtocolBehaviour>::TProto as ProtocolSpec>::THandshake,
                            >,
                        ) {
                            Some(Ok(hs)) => {
                                let actual_ver = hs.version();
                                if actual_ver == negotiated_ver {
                                    self.behaviour.inject_protocol_requested(peer_id, Some(hs));
                                } else {
                                    self.network.ban_peer(peer_id);
                                }
                            }
                            Some(Err(_)) => self.network.ban_peer(peer_id),
                            None => self.behaviour.inject_protocol_requested(peer_id, None),
                        }
                    }
                    ProtocolEvent::RequestedLocal(peer_id) => {
                        self.behaviour.inject_protocol_requested_locally(peer_id);
                    }
                    ProtocolEvent::Enabled {
                        peer_id,
                        protocol_ver: negotiated_ver,
                        sink,
                        handshake,
                    } => {
                        self.peers.insert(peer_id, sink);
                        match handshake.map(
                            codec::decode::<
                                <<TBehaviour as ProtocolBehaviour>::TProto as ProtocolSpec>::THandshake,
                            >,
                        ) {
                            Some(Ok(hs)) => {
                                let actual_ver = hs.version();
                                if actual_ver == negotiated_ver {
                                    self.behaviour.inject_protocol_enabled(peer_id, Some(hs));
                                } else {
                                    self.network.ban_peer(peer_id);
                                }
                            }
                            Some(Err(_)) => self.network.ban_peer(peer_id),
                            None => self.behaviour.inject_protocol_enabled(peer_id, None),
                        }
                    }
                    ProtocolEvent::Disabled(peer_id) => {
                        self.behaviour.inject_protocol_disabled(peer_id);
                    }
                }
                continue;
            }

            return Poll::Pending;
        }
    }
}

/// The stream of protocol events never terminates, so we can implement fused for it.
impl<'de, TBehaviour, TNetwork> FusedStream for ProtocolHandler<'de, TBehaviour, TNetwork>
where
    Self: Stream,
{
    fn is_terminated(&self) -> bool {
        false
    }
}
