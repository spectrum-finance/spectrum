use crate::peer_conn_handler::message_sink::MessageSink;
use crate::types::{ProtocolVer, RawMessage};
use futures::channel::mpsc::UnboundedSender;
use libp2p::PeerId;

pub enum ProtocolEvent {
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
    RequestedLocal(PeerId),
    Enabled {
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        handshake: Option<RawMessage>,
        sink: MessageSink,
    },
    Disabled(PeerId),
}

/// API to protocol handler without information about particular message/codec types.
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
    notifications_snd: UnboundedSender<ProtocolEvent>,
}

impl ProtocolEvents for ProtocolMailbox {
    fn incoming_msg(&self, peer_id: PeerId, protocol_ver: ProtocolVer, content: RawMessage) {
        let _ = self.notifications_snd.unbounded_send(ProtocolEvent::Message {
            peer_id,
            protocol_ver,
            content,
        });
    }

    fn protocol_requested(&self, peer_id: PeerId, protocol_ver: ProtocolVer, handshake: Option<RawMessage>) {
        let _ = self.notifications_snd.unbounded_send(ProtocolEvent::Requested {
            peer_id,
            protocol_ver,
            handshake,
        });
    }

    fn protocol_requested_local(&self, peer_id: PeerId) {
        let _ = self
            .notifications_snd
            .unbounded_send(ProtocolEvent::RequestedLocal(peer_id));
    }

    fn protocol_enabled(
        &self,
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        handshake: Option<RawMessage>,
        sink: MessageSink,
    ) {
        let _ = self.notifications_snd.unbounded_send(ProtocolEvent::Enabled {
            peer_id,
            protocol_ver,
            handshake,
            sink,
        });
    }

    fn protocol_disabled(&self, peer_id: PeerId) {
        let _ = self
            .notifications_snd
            .unbounded_send(ProtocolEvent::Disabled(peer_id));
    }
}
