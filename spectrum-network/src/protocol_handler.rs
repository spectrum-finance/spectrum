use crate::peer_conn_handler::message_sink::MessageSink;
use crate::types::{ProtocolVer, RawMessage};
use futures::channel::mpsc::UnboundedSender;
use libp2p::PeerId;

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

#[derive(Debug, thiserror::Error)]
pub enum ProtocolHandlerError {
    #[error("Message deserialization failed.")]
    MalformedMessage(RawMessage),
}

pub trait ProtocolHandlerEvents {
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
pub struct ProtocolHandler {
    notifications_snd: UnboundedSender<ProtocolHandlerIn>,
}

impl ProtocolHandlerEvents for ProtocolHandler {
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
