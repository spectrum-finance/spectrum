use crate::protocol::substream::{ProtocolSubstreamIn, ProtocolSubstreamOut};
use crate::types::RawMessage;
use futures::channel::mpsc;
use futures::stream;
use libp2p::swarm::NegotiatedSubstream;

mod substream;
pub mod sync;
mod upgrade;

pub struct Protocol {
    state: ProtocolState,
}

pub trait ProtocolSpec {
    type Message;
}

pub enum ProtocolState {
    /// Protocol is closed.
    Closed,
    /// Protocol negotiation is requsted.
    Opening,
    /// Inbound stream is negotiated by peer.
    PartiallyOpenedByPeer {
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
        pending_messages: stream::Peekable<
            stream::Select<
                stream::Fuse<mpsc::Receiver<RawMessage>>,
                stream::Fuse<mpsc::Receiver<RawMessage>>,
            >,
        >,
    },
}
