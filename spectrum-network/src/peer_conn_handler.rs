use crate::protocol::Protocol;
use crate::types::{ProtocolId, RawMessage};
use libp2p::core::ConnectedPoint;
use libp2p::PeerId;
use std::collections::HashMap;
use std::time::Instant;

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

pub enum ConnHandlerOut {
    // Input commands outcomes:
    /// Ack [`ConnHandlerIn::Open`]. Substream was negotiated.
    Opened(ProtocolId),
    /// Ack [`ConnHandlerIn::Open`]. Peer refused to open a substream.
    RefusedToOpen(ProtocolId),
    /// Ack [`ConnHandlerIn::Close`]
    Closed(ProtocolId),

    // Input commands outcomes:
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
        protocol_id: ProtocolId,
        content: RawMessage,
    },
}

pub trait PeerConnHandlerActions {
    fn open_protocol(&self, protocol_id: ProtocolId);
    fn close_protocol(&self, protocol_id: ProtocolId);
}

pub struct PeerConnHandler {
    protocols: HashMap<ProtocolId, Protocol>,
    /// When the connection with the remote has been successfully established.
    created_at: Instant,
    /// Whether we are the connection dialer or listener.
    endpoint: ConnectedPoint,
    /// Remote we are connected to.
    peer_id: PeerId,
}
