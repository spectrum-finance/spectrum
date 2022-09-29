use crate::protocol::substream::{ProtocolSubstreamIn, ProtocolSubstreamOut};
use crate::protocol::upgrade::ProtocolUpgradeIn;
use crate::types::{ProtocolId, ProtocolVer, RawMessage};
use futures::channel::mpsc;
use futures::stream;
use libp2p::swarm::NegotiatedSubstream;

pub mod combinators;
mod substream;
pub mod sync;
pub(crate) mod upgrade;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolSpec {
    /// Maximum allowed size for a single notification.
    max_message_size: usize,
    /// Initial message to send when we start communicating.
    handshake: Option<RawMessage>,
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
    /// Inbound stream is negotiated by peer.
    PartiallyOpenedByPeer {
        substream_in: ProtocolSubstreamIn<NegotiatedSubstream>,
    },
    /// Inbound stream is accepted, negotiating outbound upgrade.
    Accepting {
        substream_in: ProtocolSubstreamIn<NegotiatedSubstream>,
    },
    /// Outbound stream is negotiated with peer.
    PartiallyOpened {
        substream_out: ProtocolSubstreamOut<NegotiatedSubstream>,
    },
    /// Protocol is negotiated
    Opened {
        substream_in: ProtocolSubstreamIn<NegotiatedSubstream>,
        substream_out: ProtocolSubstreamOut<NegotiatedSubstream>,
        pending_messages: mpsc::Receiver<RawMessage>,
    },
}
