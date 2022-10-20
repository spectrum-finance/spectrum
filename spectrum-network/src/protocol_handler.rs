use crate::peer_conn_handler::message_sink::MessageSink;
use crate::types::{ProtocolVer, RawMessage};
use libp2p::PeerId;
use void::Void;

// Message Handling Pipeline:
// Choose recv -> Put to recv inbox |async| Choose codec -> Deserialize -> Handle (Custom logic)

pub enum ProtocolHandlerIn {
    Message {
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        content: RawMessage,
    },
    Enabled {
        peer_id: PeerId,
        handshake: Option<RawMessage>,
        sink: MessageSink,
    },
    Disabled(PeerId),
    Requested {

    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolHandlerError {
    #[error("Message deserialization failed.")]
    MalformedMessage(RawMessage),
}

pub trait ProtocolHandler {
    /// Send message to the protocol handler.
    fn incoming_msg(
        &self,
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        msg: RawMessage,
    ) -> Result<(), ProtocolHandlerError>;

    /// Notify protocol handler that the protocol was requested by the given peer.
    fn protocol_requested(
        &self,
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        handshake: Option<RawMessage>,
    ) -> Result<(), ProtocolHandlerError>;

    /// Notify protocol handler that the protocol with the given peer was requested by us.
    fn protocol_requested_local(&self, peer_id: PeerId) -> Result<(), Void>;

    /// Notify protocol handler that the protocol was enabled with the given peer.
    fn protocol_enabled(
        &self,
        peer_id: PeerId,
        protocol_ver: ProtocolVer,
        handshake: Option<RawMessage>,
        sink: MessageSink,
    ) -> Result<(), ProtocolHandlerError>;

    /// Notify protocol handler that the given protocol was enabled with the given peer.
    fn protocol_disabled(&self, peer_id: PeerId) -> Result<(), Void>;
}
