use crate::protocol::substream::{ProtocolSubstreamIn, ProtocolSubstreamOut};
use crate::types::{ProtocolId, ProtocolVer, RawMessage};
use futures::channel::mpsc;
use futures::stream;
use libp2p::swarm::NegotiatedSubstream;

pub mod combinators;
pub(crate) mod substream;
pub mod sync;
pub(crate) mod upgrade;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolSpec {
    /// Maximum allowed size for a single notification.
    pub max_message_size: usize,
    /// Initial message to send when we start communicating.
    pub handshake: Option<RawMessage>,
}

pub struct ProtocolConfig {
    pub protocol_id: ProtocolId,
    pub supported_versions: Vec<(ProtocolVer, ProtocolSpec)>,
}

pub struct Protocol {
    /// Negotiated protocol version
    pub ver: ProtocolVer,
    /// Spec for negotiated protocol version
    pub spec: ProtocolSpec,
    /// Protocol state
    /// Always `Some`. `None` only during update (state transition).
    pub state: Option<ProtocolState>,
    /// Specs for all supported versions of this protocol
    pub all_versions_specs: Vec<(ProtocolVer, ProtocolSpec)>,
}

pub enum ProtocolState {
    /// Protocol is closed.
    Closed,
    /// Outbound protocol negotiation is requsted.
    Opening,
    /// Inbound stream is negotiated by peer. The stream hasn't been approved yet.
    PartiallyOpenedByPeer {
        substream_in: ProtocolSubstreamIn<NegotiatedSubstream>,
    },
    /// Inbound stream is accepted, negotiating outbound upgrade.
    Accepting {
        /// None in the case when peer closed inbound substream.
        substream_in: Option<ProtocolSubstreamIn<NegotiatedSubstream>>,
    },
    /// Outbound stream is negotiated with peer.
    PartiallyOpened {
        substream_out: ProtocolSubstreamOut<NegotiatedSubstream>,
    },
    /// Protocol is negotiated
    Opened {
        substream_in: ProtocolSubstreamIn<NegotiatedSubstream>,
        substream_out: ProtocolSubstreamOut<NegotiatedSubstream>,
        pending_messages_recv: stream::Peekable<stream::Fuse<mpsc::Receiver<RawMessage>>>,
    },
    /// Inbound substream is closed by peer.
    InboundClosedByPeer {
        /// None in the case when the peer closed inbound substream while outbound one
        /// hasn't been negotiated yet.
        substream_out: ProtocolSubstreamOut<NegotiatedSubstream>,
        pending_messages_recv: stream::Peekable<stream::Fuse<mpsc::Receiver<RawMessage>>>,
    },
    /// Outbound substream is closed by peer.
    OutboundClosedByPeer {
        substream_in: ProtocolSubstreamIn<NegotiatedSubstream>,
    },
}
