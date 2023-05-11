use futures::channel::mpsc::Sender;
use futures::SinkExt;
use libp2p::PeerId;

use crate::peer_conn_handler::message_sink::MessageSink;
use crate::types::{ProtocolVer, RawMessage};

#[derive(Debug, Clone)]
pub enum ProtocolEvent {
    Connected(PeerId),
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
        sink: MessageSink,
        handshake: Option<RawMessage>,
    },
    Disabled(PeerId),
}

/// API to protocol handler without information about particular message/codec types.
pub trait ProtocolEvents {
    /// Notify protocol handler that we have established conn with a peer.
    fn connected(&self, peer_id: PeerId);

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
        sink: MessageSink,
        handshake: Option<RawMessage>,
    );

    /// Notify protocol handler that the given protocol was enabled with the given peer.
    fn protocol_disabled(&self, peer_id: PeerId);
}

#[derive(Clone)]
pub struct ProtocolMailbox {
    events_snd: Sender<ProtocolEvent>,
}

impl ProtocolMailbox {
    pub fn new(events_snd: Sender<ProtocolEvent>) -> Self {
        Self { events_snd }
    }
}

impl ProtocolEvents for ProtocolMailbox {
    fn connected(&self, peer_id: PeerId) {
        let _ = futures::executor::block_on(self.events_snd.clone().send(ProtocolEvent::Connected(peer_id)));
    }

    fn incoming_msg(&self, peer_id: PeerId, protocol_ver: ProtocolVer, content: RawMessage) {
        let _ = futures::executor::block_on(self.events_snd.clone().send(ProtocolEvent::Message {
            peer_id,
            protocol_ver,
            content,
        }));
        println!("[PE] Message sent");
    }

    fn protocol_requested(&self, peer_id: PeerId, protocol_ver: ProtocolVer, handshake: Option<RawMessage>) {
        let _ = futures::executor::block_on(self.events_snd.clone().send(ProtocolEvent::Requested {
            peer_id,
            protocol_ver,
            handshake,
        }));
    }

    fn protocol_requested_local(&self, peer_id: PeerId) {
        let _ = futures::executor::block_on(
            self.events_snd
                .clone()
                .send(ProtocolEvent::RequestedLocal(peer_id)),
        );
    }

    fn protocol_enabled(
        &self,
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        sink: MessageSink,
        handshake: Option<RawMessage>,
    ) {
        let _ = futures::executor::block_on(self.events_snd.clone().send(ProtocolEvent::Enabled {
            peer_id,
            protocol_ver,
            sink,
            handshake,
        }));
    }

    fn protocol_disabled(&self, peer_id: PeerId) {
        let _ = futures::executor::block_on(self.events_snd.clone().send(ProtocolEvent::Disabled(peer_id)));
    }
}
