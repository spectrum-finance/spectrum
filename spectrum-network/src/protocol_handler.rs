use crate::network_controller::{NetworkAPI, NetworkControllerIn};
use crate::peer_conn_handler::message_sink::MessageSink;
use crate::protocol_api::{ProtocolEvent, ProtocolMailbox};
use crate::protocol_handler::versioning::Versioned;
use crate::protocol_upgrade::handshake::PolyVerHandshakeSpec;
use crate::types::{ProtocolId, ProtocolVer, RawMessage};
use futures::channel::mpsc;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::FutureExt;
use futures::Stream;
use libp2p::PeerId;
use log::trace;
use std::collections::{BTreeMap, HashMap};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;

pub mod codec;
pub mod sync;
pub mod versioning;

pub enum ProtocolBehaviourIn<THandshake, TMessage> {
    Message {
        peer_id: PeerId,
        content: TMessage,
    },
    Requested {
        peer_id: PeerId,
        handshake: Option<THandshake>,
    },
    Enabled {
        peer_id: PeerId,
        handshake: Option<THandshake>,
        sink: MessageSink,
    },
    Disabled(PeerId),
}

pub enum NetworkAction<THandshake> {
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
    // todo: Add banning API
}

pub enum ProtocolBehaviourOut<THandshake, TMessage> {
    Send { peer_id: PeerId, message: TMessage },
    NetworkAction(NetworkAction<THandshake>),
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolHandlerError {
    #[error("Message deserialization failed.")]
    MalformedMessage(RawMessage),
}

pub trait ProtocolSpec {
    type THandshake: codec::BinCodec + Versioned + Send;
    type TMessage: codec::BinCodec + Versioned + Send;
}

pub enum MalformedMessage {
    VersionMismatch {
        negotiated_ver: ProtocolVer,
        actual_ver: ProtocolVer,
    },
    UnknownFormat,
}

pub trait ProtocolBehaviour {
    /// Protocol specification.
    type TProto: ProtocolSpec;

    /// Returns ID of the protocol this behaviour implements.
    fn get_protocol_id(&self) -> ProtocolId;

    /// Inject an event that we have established a conn with a peer.
    fn inject_peer_connected(&mut self, peer_id: PeerId);

    /// Inject a new message coming from a peer.
    fn inject_message(&mut self, peer_id: PeerId, content: <Self::TProto as ProtocolSpec>::TMessage);

    /// Inject an event when the peer sent a malformed message.
    fn inject_malformed_mesage(&mut self, peer_id: PeerId, details: MalformedMessage);

    /// Inject protocol request coming from a peer.
    fn inject_protocol_requested(
        &mut self,
        peer_id: PeerId,
        handshake: Option<<Self::TProto as ProtocolSpec>::THandshake>,
    );

    /// Inject local protocol request coming from a peer.
    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId);

    /// Inject an event of protocol being enabled with a peer.
    fn inject_protocol_enabled(
        &mut self,
        peer_id: PeerId,
        handshake: Option<<Self::TProto as ProtocolSpec>::THandshake>,
    );

    /// Inject an event of protocol being disabled with a peer.
    fn inject_protocol_disabled(&mut self, peer_id: PeerId);

    /// Poll for output actions.
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ProtocolBehaviourOut<
            <Self::TProto as ProtocolSpec>::THandshake,
            <Self::TProto as ProtocolSpec>::TMessage,
        >,
    >;
}

/// A layer that facilitate massage transmission from protocol handlers to peers.
pub struct ProtocolHandler<TBehaviour, TNetwork> {
    peers: HashMap<PeerId, MessageSink>,
    inbox: UnboundedReceiver<ProtocolEvent>,
    behaviour: TBehaviour,
    network: TNetwork,
}

impl<TBehaviour, TNetwork> ProtocolHandler<TBehaviour, TNetwork> {
    pub fn new(behaviour: TBehaviour, network: TNetwork) -> (Self, ProtocolMailbox) {
        let (snd, recv) = mpsc::unbounded::<ProtocolEvent>();
        let prot_mailbox = ProtocolMailbox::new(snd);
        let prot_handler = Self {
            peers: HashMap::new(),
            inbox: recv,
            behaviour,
            network,
        };
        (prot_handler, prot_mailbox)
    }
}

impl<TBehaviour, TNetwork> Stream for ProtocolHandler<TBehaviour, TNetwork>
where
    TBehaviour: ProtocolBehaviour + Unpin,
    TNetwork: NetworkAPI + Unpin,
{
    type Item = ();

    /// Polls the behaviour and the network, forwarding events from the former to the latter and
    /// vice versa.
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            if let Poll::Ready(Some(notif)) = Stream::poll_next(Pin::new(&mut self.inbox), cx) {
                match notif {
                    ProtocolEvent::Connected(peer_id) => {}
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
                                self.behaviour.inject_malformed_mesage(
                                    peer_id,
                                    MalformedMessage::VersionMismatch {
                                        negotiated_ver,
                                        actual_ver,
                                    },
                                )
                            }
                        } else {
                            self.behaviour
                                .inject_malformed_mesage(peer_id, MalformedMessage::UnknownFormat);
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
                                    self.behaviour.inject_malformed_mesage(
                                        peer_id,
                                        MalformedMessage::VersionMismatch {
                                            negotiated_ver,
                                            actual_ver,
                                        },
                                    )
                                }
                            }
                            Some(Err(_)) => self
                                .behaviour
                                .inject_malformed_mesage(peer_id, MalformedMessage::UnknownFormat),
                            None => self.behaviour.inject_protocol_requested(peer_id, None),
                        }
                    }
                    ProtocolEvent::RequestedLocal(peer_id) => {
                        self.behaviour.inject_protocol_requested_locally(peer_id);
                    }
                    ProtocolEvent::Enabled {
                        peer_id,
                        protocol_ver: negotiated_ver,
                        handshake,
                        sink,
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
                                    self.behaviour.inject_malformed_mesage(
                                        peer_id,
                                        MalformedMessage::VersionMismatch {
                                            negotiated_ver,
                                            actual_ver,
                                        },
                                    )
                                }
                            }
                            Some(Err(_)) => self
                                .behaviour
                                .inject_malformed_mesage(peer_id, MalformedMessage::UnknownFormat),
                            None => self.behaviour.inject_protocol_enabled(peer_id, None),
                        }
                    }
                    ProtocolEvent::Disabled(peer_id) => {
                        self.behaviour.inject_protocol_disabled(peer_id);
                    }
                }
            }
            if let Poll::Ready(out) = self.behaviour.poll(cx) {
                match out {
                    ProtocolBehaviourOut::Send { peer_id, message } => {
                        if let Some(sink) = self.peers.get(&peer_id) {
                            if let Err(_) = sink.send_message(codec::BinCodec::encode(message)) {
                                trace!("Failed to submit a message to {:?}. Channel is closed.", peer_id)
                            }
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
                                    .map(|(v, m)| (v, m.map(codec::BinCodec::encode)))
                                    .collect::<BTreeMap<_, _>>(),
                            );
                            self.network
                                .enable_protocol(self.behaviour.get_protocol_id(), peer, poly_spec);
                        }
                        NetworkAction::UpdatePeerProtocols { peer, protocols } => {
                            self.network.update_peer_protocols(peer, protocols);
                        }
                    },
                }
            }
        }
    }
}
