mod message_sink;

use crate::peer_conn_handler::message_sink::MessageSink;
use crate::protocol::combinators::AnyUpgradeOf;
use crate::protocol::substream::{ProtocolSubstreamIn};
use crate::protocol::upgrade::{
    ProtocolTag, ProtocolUpgradeErr, ProtocolUpgradeIn, ProtocolUpgradeOut,
};
use crate::protocol::{Protocol, ProtocolConfig, ProtocolState};
use crate::types::{ProtocolId, RawMessage};
use futures::channel::mpsc;
pub use futures::prelude::*;
use libp2p::core::ConnectedPoint;
use libp2p::swarm::{
    ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, IntoConnectionHandler,
    KeepAlive, NegotiatedSubstream, SubstreamProtocol,
};
use libp2p::{InboundUpgrade, OutboundUpgrade, PeerId};

use std::collections::{HashMap, VecDeque};
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct PeerConnHandlerConf {
    async_msg_buffer_size: usize,
    open_timeout: Duration,
    initial_keep_alive: Duration,
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
    OpenedByPeer(ProtocolId),
    /// The remote would like the substreams to be closed. Send a [`ConnHandlerIn::Close`] in
    /// order to close them. If a [`ConnHandlerIn::Close`] has been sent before and has not yet
    /// been acknowledged by a [`ConnHandlerOut::CloseResult`], then you don't need to a send
    /// another one.
    ClosedByPeer(ProtocolId),
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
                            protocol_id,
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
                        let (msg_snd, msg_recv) =
                            mpsc::channel::<RawMessage>(self.conf.async_msg_buffer_size);
                        let sink = MessageSink::new(self.peer_id, msg_snd);
                        self.pending_events
                            .push_back(ConnectionHandlerEvent::Custom(ConnHandlerOut::Opened {
                                protocol_tag: negotiated_tag,
                                out_channel: sink,
                                handshake: upgrade.handshake,
                            }));
                        ProtocolState::Opened {
                            substream_out,
                            substream_in: upgrade.substream,
                            pending_messages_recv: msg_recv.fuse().peekable(),
                        }
                    }
                    _ => state,
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
                    ProtocolState::Accepting {
                        substream_in: Some(substream_in),
                    } => {
                        let (msg_snd, msg_recv) =
                            mpsc::channel::<RawMessage>(self.conf.async_msg_buffer_size);
                        let sink = MessageSink::new(self.peer_id, msg_snd);
                        self.pending_events
                            .push_back(ConnectionHandlerEvent::Custom(ConnHandlerOut::Opened {
                                protocol_tag: negotiated_tag,
                                out_channel: sink,
                                handshake: upgrade.handshake,
                            }));
                        ProtocolState::Opened {
                            substream_in,
                            substream_out: upgrade.substream,
                            pending_messages_recv: msg_recv.fuse().peekable(),
                        }
                    }
                    // todo: handle this in the case we decide to re-open out substream.
                    ProtocolState::OutboundClosedByPeer { .. } => state,
                    // todo: warn, inconsistent state; discard other options explicitly.
                    _ => state,
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
                                ProtocolState::Accepting {
                                    substream_in: Some(substream_in),
                                }
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
        protocol_tag: Self::OutboundOpenInfo,
        _: ConnectionHandlerUpgrErr<ProtocolUpgradeErr>,
    ) {
        let protocol_id = protocol_tag.protocol_id();
        if let Some(protocol) = self.protocols.get_mut(&protocol_id) {
            if let Some(state) = &protocol.state {
                match state {
                    ProtocolState::Opening | ProtocolState::Accepting { .. } => self
                        .pending_events
                        .push_back(ConnectionHandlerEvent::Custom(
                            ConnHandlerOut::RefusedToOpen(protocol_id),
                        )),
                    _ => {}
                }
            }
            protocol.state = Some(ProtocolState::Closed)
        }
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        // Keep alive unless all protocols are inactive.
        // Otherwise close connection once initial_keep_alive interval passed.
        if self
            .protocols
            .values()
            .any(|p| !matches!(p.state, Some(ProtocolState::Closed)))
        {
            KeepAlive::Yes
        } else {
            KeepAlive::Until(self.created_at + self.conf.initial_keep_alive)
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context,
    ) -> Poll<
        ConnectionHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::OutEvent,
            Self::Error,
        >,
    > {
        if let Some(out) = self.pending_events.pop_front() {
            Poll::Ready(out)
        } else {
            // For each open substream, try send messages from `pending_messages_recv`.
            for (_, protocol) in &mut self.protocols {
                if let Some(
                    ProtocolState::Opened {
                        substream_out,
                        pending_messages_recv,
                        ..
                    }
                    | ProtocolState::InboundClosedByPeer {
                        substream_out,
                        pending_messages_recv,
                    },
                ) = &mut protocol.state
                {
                    loop {
                        // Only proceed with `out_substream.poll_ready_unpin` if there is an element
                        // available in `notifications_sink_rx`. This avoids waking up the task when
                        // a substream is ready to send if there isn't actually something to send.
                        match Pin::new(&mut *pending_messages_recv).as_mut().poll_peek(cx) {
                            Poll::Ready(Some(_)) => {}
                            Poll::Ready(None) | Poll::Pending => break,
                        }
                        // Before we extract the element from `pending_messages`, check that the
                        // substream is ready to accept a message.
                        match substream_out.poll_ready_unpin(cx) {
                            Poll::Ready(_) => {}
                            Poll::Pending => break,
                        }

                        // Now that the substream is ready for a message, grab what to send.
                        let message = match pending_messages_recv.poll_next_unpin(cx) {
                            Poll::Ready(Some(message)) => message,
                            _ => panic!(), // Should never be reached, as per `poll_peek` above.
                        };

                        let _ = substream_out.start_send_unpin(message);
                        // Note that flushing is performed later down this function.
                    }
                }
            }

            // Flush all outbound substreams.
            // When `poll` returns `Poll::Ready`, the libp2p `Swarm` may decide to no longer call
            // `poll` again before it is ready to accept more events.
            // In order to make sure that substreams are flushed as soon as possible, the flush is
            // performed before the code paths that can produce `Ready` (with some rare exceptions).
            // Importantly, however, the flush is performed *after* notifications are queued with
            // `Sink::start_send`.
            for (protocol_id, protocol) in &mut self.protocols {
                if let Some(state) = &mut protocol.state {
                    if let ProtocolState::Opened { substream_out, .. }
                    | ProtocolState::PartiallyOpened { substream_out, .. }
                    | ProtocolState::InboundClosedByPeer { substream_out, .. } = state
                    {
                        match Sink::poll_flush(Pin::new(substream_out), cx) {
                            Poll::Pending | Poll::Ready(Ok(())) => {}
                            Poll::Ready(Err(_)) => {
                                if let Some(ProtocolState::Opened { substream_in, .. }) =
                                    mem::replace(&mut protocol.state, None)
                                {
                                    protocol.state =
                                        Some(ProtocolState::OutboundClosedByPeer { substream_in });
                                    let event = ConnHandlerOut::ClosedByPeer(*protocol_id);
                                    return Poll::Ready(ConnectionHandlerEvent::Custom(event));
                                }
                            }
                        }
                    }
                }
            }

            // Poll inbound substreams.
            for (protocol_id, protocol) in &mut self.protocols {
                if let Some(state) = &mut protocol.state {
                    match state {
                        ProtocolState::Opened { substream_in, .. }
                        | ProtocolState::OutboundClosedByPeer { substream_in } => {
                            match Stream::poll_next(Pin::new(substream_in), cx) {
                                Poll::Pending => {}
                                Poll::Ready(Some(Ok(msg))) => {
                                    let event = ConnHandlerOut::Message {
                                        protocol_tag: ProtocolTag::new(*protocol_id, protocol.ver),
                                        content: msg,
                                    };
                                    return Poll::Ready(ConnectionHandlerEvent::Custom(event));
                                }
                                Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                                    if let Some(ProtocolState::Opened {
                                        substream_out,
                                        pending_messages_recv,
                                        ..
                                    }) = mem::replace(&mut protocol.state, None)
                                    {
                                        protocol.state = Some(ProtocolState::InboundClosedByPeer {
                                            substream_out,
                                            pending_messages_recv,
                                        });
                                    } else {
                                        protocol.state = Some(ProtocolState::Closed);
                                        return Poll::Ready(ConnectionHandlerEvent::Custom(
                                            ConnHandlerOut::ClosedByPeer(*protocol_id),
                                        ));
                                    }
                                }
                            }
                        }
                        ProtocolState::PartiallyOpenedByPeer { substream_in } => {
                            match ProtocolSubstreamIn::poll_process_handshake(
                                Pin::new(substream_in),
                                cx,
                            ) {
                                Poll::Pending => {}
                                Poll::Ready(Ok(void)) => match void {},
                                Poll::Ready(Err(_)) => {
                                    protocol.state = Some(ProtocolState::Closed);
                                    return Poll::Ready(ConnectionHandlerEvent::Custom(
                                        ConnHandlerOut::ClosedByPeer(*protocol_id),
                                    ));
                                }
                            }
                        }
                        ProtocolState::Accepting {
                            substream_in: Some(substream_in),
                        } => {
                            match ProtocolSubstreamIn::poll_process_handshake(
                                Pin::new(substream_in),
                                cx,
                            ) {
                                Poll::Pending => {}
                                Poll::Ready(Ok(void)) => match void {},
                                Poll::Ready(Err(_)) => {
                                    protocol.state =
                                        Some(ProtocolState::Accepting { substream_in: None })
                                }
                            }
                        }
                        ProtocolState::Closed
                        | ProtocolState::Opening
                        | ProtocolState::PartiallyOpened { .. }
                        | ProtocolState::InboundClosedByPeer { .. }
                        | ProtocolState::Accepting { .. } => {}
                    }
                }
            }

            Poll::Pending
        }
    }
}
