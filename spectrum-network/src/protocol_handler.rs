use crate::peer_conn_handler::message_sink::MessageSink;
use crate::protocol_handler::codec::BinCodec;
use crate::types::{ProtocolVer, RawMessage};
use futures::channel::mpsc::UnboundedSender;
use futures::FutureExt;
use futures::Stream;
use libp2p::PeerId;
use log::trace;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread;

pub mod codec;
pub mod sync;

pub enum ProtocolHandlerIn {
    Message {
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        content: RawMessage,
    },
    Requested {
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        handshake: Option<RawMessage>,
    },
    RequestedLocal {
        peer_id: PeerId,
    },
    Enabled {
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        handshake: Option<RawMessage>,
        sink: MessageSink,
    },
    Disabled(PeerId),
}

pub enum ProtocolHandlerOut<TMessage> {
    Send { peer_id: PeerId, message: TMessage },
    SetSink { peer_id: PeerId, sink: MessageSink },
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolHandlerError {
    #[error("Message deserialization failed.")]
    MalformedMessage(RawMessage),
}

pub trait ProtocolEvents {
    /// Send message to the protocol handler.
    fn incoming_msg(&self, peer_id: PeerId, protocol_ver: ProtocolVer, msg: RawMessage);

    /// Notify protocol handler that the protocol was requested by the given peer.
    fn protocol_requested(&self, peer_id: PeerId, protocol_ver: ProtocolVer, handshake: Option<RawMessage>);

    /// Notify protocol handler that the protocol with the given peer was requested by us.
    fn protocol_requested_local(&self, peer_id: PeerId);

    /// Notify protocol handler that the protocol was enabled with the given peer.
    fn protocol_enabled(
        &self,
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        handshake: Option<RawMessage>,
        sink: MessageSink,
    );

    /// Notify protocol handler that the given protocol was enabled with the given peer.
    fn protocol_disabled(&self, peer_id: PeerId);
}

#[derive(Clone)]
pub struct ProtocolMailbox {
    notifications_snd: UnboundedSender<ProtocolHandlerIn>,
}

impl ProtocolEvents for ProtocolMailbox {
    fn incoming_msg(&self, peer_id: PeerId, protocol_ver: ProtocolVer, content: RawMessage) {
        let _ = self.notifications_snd.unbounded_send(ProtocolHandlerIn::Message {
            peer_id,
            protocol_ver,
            content,
        });
    }

    fn protocol_requested(&self, peer_id: PeerId, protocol_ver: ProtocolVer, handshake: Option<RawMessage>) {
        let _ = self
            .notifications_snd
            .unbounded_send(ProtocolHandlerIn::Requested {
                peer_id,
                protocol_ver,
                handshake,
            });
    }

    fn protocol_requested_local(&self, peer_id: PeerId) {
        let _ = self
            .notifications_snd
            .unbounded_send(ProtocolHandlerIn::RequestedLocal { peer_id });
    }

    fn protocol_enabled(
        &self,
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        handshake: Option<RawMessage>,
        sink: MessageSink,
    ) {
        let _ = self.notifications_snd.unbounded_send(ProtocolHandlerIn::Enabled {
            peer_id,
            protocol_ver,
            handshake,
            sink,
        });
    }

    fn protocol_disabled(&self, peer_id: PeerId) {
        let _ = self
            .notifications_snd
            .unbounded_send(ProtocolHandlerIn::Disabled(peer_id));
    }
}

/// A layer that facilitate massage transmission from protocol handlers to peers.
pub struct ProtocolRouter<THandler> {
    peers: HashMap<PeerId, MessageSink>,
    handler: THandler,
}

impl<THandler, TMessage> Stream for ProtocolRouter<THandler>
where
    THandler: Stream<Item = ProtocolHandlerOut<TMessage>> + Unpin,
    TMessage: BinCodec + Send,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            if let Poll::Ready(Some(out)) = Stream::poll_next(Pin::new(&mut self.handler), cx) {
                match out {
                    ProtocolHandlerOut::Send { peer_id, message } => {
                        if let Some(sink) = self.peers.get(&peer_id) {
                            if let Err(_) = sink.send_message(BinCodec::encode(message)) {
                                trace!("Failed to submit a message to {:?}. Channel is closed.", peer_id)
                            }
                        }
                    }
                    ProtocolHandlerOut::SetSink { peer_id, sink } => {
                        self.peers.insert(peer_id, sink);
                    }
                }
            }
        }
    }
}
