mod message_sink;

use crate::peer_conn_handler::message_sink::MessageSink;
use crate::protocol::combinators::AnyUpgradeOf;
use crate::protocol::upgrade::{ProtocolTag, ProtocolUpgradeIn, ProtocolUpgradeOut};
use crate::protocol::{Protocol, ProtocolConfig, ProtocolState};
use crate::types::{ProtocolId, RawMessage};
use futures::channel::mpsc;
pub use futures::prelude::*;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::handler::OutboundUpgradeSend;
use libp2p::swarm::{
    ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, IntoConnectionHandler,
    KeepAlive, NegotiatedSubstream, SubstreamProtocol,
};
use libp2p::{InboundUpgrade, OutboundUpgrade, PeerId};

use std::collections::{HashMap, VecDeque};

use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct PeerConnHandlerConf {
    async_msg_buffer_size: usize,
    open_timeout: Duration,
}

#[derive(Debug, Clone)]
pub enum ConnHandlerIn {
    /// Instruct the handler to open the notification substreams.
    ///
    /// Must always be answered by a [`ConnHandlerOut::Opened`] or a
    /// [`ConnHandlerOut::RefusedToOpen`] event.
    ///
    /// Importantly, it is forbidden to send a [`ConnHandlerIn::Open`] while a previous one is
    /// already in the fly. It is however possible if a `Close` is still in the fly.
    Open(ProtocolId),
    /// Instruct the handler to close the notification substreams, or reject any pending incoming
    /// substream request.
    ///
    /// Must always be answered by a [`ConnHandlerOut::Closed`] event.
    Close(ProtocolId),
}

#[derive(Debug, Clone)]
pub enum ConnHandlerOut {
    // Input commands outcomes:
    /// Ack [`ConnHandlerIn::Open`]. Substream was negotiated.
    Opened {
        protocol_tag: ProtocolTag,
        out_channel: MessageSink,
        handshake: Option<RawMessage>,
    },
    /// Ack [`ConnHandlerIn::Open`]. Peer refused to open a substream.
    RefusedToOpen(ProtocolId),
    /// Ack [`ConnHandlerIn::Close`]
    Closed(ProtocolId),

    // Events:
    /// The remote would like the substreams to be open. Send a [`ConnHandlerIn::Open`] or a
    /// [`ConnHandlerIn::Close`] in order to either accept or deny this request. If a
    /// [`ConnHandlerIn::Open`] or [`ConnHandlerIn::Close`] has been sent before and has not
    /// yet been acknowledged by a matching [`ConnHandlerOut`], then you don't need to a send
    /// another [`ConnHandlerIn`].
    OpenedByPeer(ProtocolTag),
    /// The remote would like the substreams to be closed. Send a [`ConnHandlerIn::Close`] in
    /// order to close them. If a [`ConnHandlerIn::Close`] has been sent before and has not yet
    /// been acknowledged by a [`ConnHandlerOut::CloseResult`], then you don't need to a send
    /// another one.
    ClosedByPeer(ProtocolTag),
    /// Received a message on a custom protocol substream.
    /// Can only happen when the handler is in the open state.
    Message {
        protocol_tag: ProtocolTag,
        content: RawMessage,
    },
}

pub trait PeerConnHandlerActions {
    fn open_protocol(&self, protocol_id: ProtocolId);
    fn close_protocol(&self, protocol_id: ProtocolId);
}

pub struct PartialPeerConnHandler {
    conf: PeerConnHandlerConf,
    protocols: Vec<ProtocolConfig>,
}

impl IntoConnectionHandler for PartialPeerConnHandler {
    type Handler = PeerConnHandler;

    fn into_handler(
        self,
        remote_peer_id: &PeerId,
        connected_point: &ConnectedPoint,
    ) -> Self::Handler {
        let protocols = HashMap::from_iter(self.protocols.iter().flat_map(|p| {
            p.supported_versions.iter().map(|(ver, spec)| {
                (
                    p.protocol_id,
                    Protocol {
                        ver: *ver,
                        spec: spec.clone(),
                        state: Some(ProtocolState::Closed),
                        all_versions_specs: p.supported_versions.clone(),
                    },
                )
            })
        }));
        PeerConnHandler {
            conf: self.conf,
            protocols,
            created_at: Instant::now(),
            endpoint: connected_point.clone(),
            peer_id: *remote_peer_id,
            pending_events: VecDeque::new(),
        }
    }

    fn inbound_protocol(&self) -> AnyUpgradeOf<ProtocolUpgradeIn> {
        self.protocols
            .iter()
            .map(|p| ProtocolUpgradeIn::new(p.protocol_id, p.supported_versions.clone()))
            .collect::<AnyUpgradeOf<_>>()
    }
}

/// Error specific to the collection of protocols.
#[derive(Debug, thiserror::Error)]
pub enum PeerConnHandlerError {
    #[error("Channel of synchronous notifications is full.")]
    SyncNotificationsClogged,
}

pub struct PeerConnHandler {
    conf: PeerConnHandlerConf,
    protocols: HashMap<ProtocolId, Protocol>,
    /// When the connection with the remote has been successfully established.
    created_at: Instant,
    /// Whether we are the connection dialer or listener.
    endpoint: ConnectedPoint,
    /// Remote we are connected to.
    peer_id: PeerId,
    /// Events to return in priority from `poll`.
    pending_events: VecDeque<
        ConnectionHandlerEvent<
            ProtocolUpgradeOut,
            ProtocolTag,
            ConnHandlerOut,
            PeerConnHandlerError,
        >,
    >,
}

impl ConnectionHandler for PeerConnHandler {
    type InEvent = ConnHandlerIn;
    type OutEvent = ConnHandlerOut;
    type Error = PeerConnHandlerError;
    type InboundProtocol = AnyUpgradeOf<ProtocolUpgradeIn>;
    type OutboundProtocol = ProtocolUpgradeOut;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ProtocolTag;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, ()> {
        let protocols = self
            .protocols
            .iter()
            .map(|(pid, prot)| ProtocolUpgradeIn::new(*pid, prot.all_versions_specs.clone()))
            .collect::<AnyUpgradeOf<_>>();
        SubstreamProtocol::new(protocols, ())
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        (upgrade, _): <Self::InboundProtocol as InboundUpgrade<NegotiatedSubstream>>::Output,
        _: Self::InboundOpenInfo,
    ) {
        let negotiated_tag = upgrade.negotiated_tag;
        let protocol_id = negotiated_tag.protocol_id();
        if let Some(protocol) = self.protocols.get_mut(&protocol_id) {
            let state = protocol.state.take();
            if let Some(state) = state {
                let state_next = match state {
                    ProtocolState::Closed => {
                        let event = ConnectionHandlerEvent::Custom(ConnHandlerOut::OpenedByPeer(
                            negotiated_tag,
                        ));
                        self.pending_events.push_back(event);
                        ProtocolState::PartiallyOpenedByPeer {
                            substream_in: upgrade.substream,
                        }
                    }
                    // Should not happen in normal network conditions.
                    ProtocolState::Opening => ProtocolState::PartiallyOpenedByPeer {
                        substream_in: upgrade.substream,
                    },
                    // If a substream already exists, silently drop the new one.
                    // Note that we drop the substream, which will send an equivalent to a
                    // TCP "RST" to the remote and force-close the substream. It might
                    // seem like an unclean way to get rid of a substream. However, keep
                    // in mind that it is invalid for the remote to open multiple such
                    // substreams, and therefore sending a "RST" is the most correct thing
                    // to do.
                    ProtocolState::PartiallyOpened { substream_out } => {
                        let (out_chan, in_chan) =
                            mpsc::channel::<RawMessage>(self.conf.async_msg_buffer_size);
                        let sink = MessageSink::new(self.peer_id, out_chan);
                        self.pending_events
                            .push_back(ConnectionHandlerEvent::Custom(ConnHandlerOut::Opened {
                                protocol_tag: negotiated_tag,
                                out_channel: sink,
                                handshake: upgrade.handshake,
                            }));
                        ProtocolState::Opened {
                            substream_out,
                            substream_in: upgrade.substream,
                            pending_messages: in_chan,
                        }
                    }
                    ProtocolState::PartiallyOpenedByPeer { .. }
                    | ProtocolState::Accepting { .. }
                    | ProtocolState::Opened { .. } => state,
                };
                protocol.state = Some(state_next);
            };
        }
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        upgrade: <Self::OutboundProtocol as OutboundUpgrade<NegotiatedSubstream>>::Output,
        negotiated_tag: Self::OutboundOpenInfo,
    ) {
        let protocol_id = negotiated_tag.protocol_id();
        if let Some(protocol) = self.protocols.get_mut(&protocol_id) {
            let state = protocol.state.take();
            if let Some(state) = state {
                let state_next = match state {
                    ProtocolState::Opening => ProtocolState::PartiallyOpened {
                        substream_out: upgrade.substream,
                    },
                    ProtocolState::Accepting { substream_in } => {
                        let (out_chan, in_chan) =
                            mpsc::channel::<RawMessage>(self.conf.async_msg_buffer_size);
                        let sink = MessageSink::new(self.peer_id, out_chan);
                        self.pending_events
                            .push_back(ConnectionHandlerEvent::Custom(ConnHandlerOut::Opened {
                                protocol_tag: negotiated_tag,
                                out_channel: sink,
                                handshake: upgrade.handshake,
                            }));
                        ProtocolState::Opened {
                            substream_in,
                            substream_out: upgrade.substream,
                            pending_messages: in_chan,
                        }
                    }
                    _ => state, // todo: warn, inconsistent state
                };
                protocol.state = Some(state_next);
            };
        }
    }

    fn inject_event(&mut self, cmd: ConnHandlerIn) {
        match cmd {
            ConnHandlerIn::Open(protocol_id) => {
                if let Some(protocol) = self.protocols.get_mut(&protocol_id) {
                    let state = protocol.state.take();
                    if let Some(state) = state {
                        let state_next = match state {
                            ProtocolState::Closed => {
                                let upgrade = ProtocolUpgradeOut::new(
                                    protocol_id,
                                    protocol.all_versions_specs.clone(),
                                );
                                self.pending_events.push_back(
                                    ConnectionHandlerEvent::OutboundSubstreamRequest {
                                        protocol: SubstreamProtocol::new(
                                            upgrade,
                                            ProtocolTag::new(protocol_id, protocol.ver),
                                        )
                                        .with_timeout(self.conf.open_timeout),
                                    },
                                );
                                ProtocolState::Opening
                            }
                            ProtocolState::PartiallyOpenedByPeer { mut substream_in } => {
                                let upgrade = ProtocolUpgradeOut::new(
                                    protocol_id,
                                    protocol.all_versions_specs.clone(),
                                );
                                self.pending_events.push_back(
                                    ConnectionHandlerEvent::OutboundSubstreamRequest {
                                        protocol: SubstreamProtocol::new(
                                            upgrade,
                                            ProtocolTag::new(protocol_id, protocol.ver),
                                        )
                                        .with_timeout(self.conf.open_timeout),
                                    },
                                );
                                if let Some(hs) = protocol.spec.handshake.clone() {
                                    // Peer is waiting for handshake, so we send it.
                                    substream_in.send_handshake(hs)
                                }
                                ProtocolState::Accepting { substream_in }
                            }
                            _ => state, // todo: warn, incosistent view
                        };
                        protocol.state = Some(state_next);
                    };
                }
            }
            ConnHandlerIn::Close(protocol_id) => {
                if let Some(protocol) = self.protocols.get_mut(&protocol_id) {
                    match protocol.state {
                        Some(ProtocolState::Opening) => {
                            self.pending_events
                                .push_back(ConnectionHandlerEvent::Custom(
                                    ConnHandlerOut::RefusedToOpen(protocol_id),
                                ))
                        }
                        _ => {}
                    }
                    self.pending_events
                        .push_back(ConnectionHandlerEvent::Custom(ConnHandlerOut::Closed(
                            protocol_id,
                        )));
                    protocol.state = Some(ProtocolState::Closed);
                }
            }
        }
    }

    fn inject_dial_upgrade_error(
        &mut self,
        info: Self::OutboundOpenInfo,
        error: ConnectionHandlerUpgrErr<<Self::OutboundProtocol as OutboundUpgradeSend>::Error>,
    ) {
        todo!()
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        todo!()
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::OutEvent,
            Self::Error,
        >,
    > {
        todo!()
    }
}
