use crate::protocol::upgrade::ProtocolTag;
use crate::types::RawMessage;
use libp2p::PeerId;

// Message Handling Pipeline:
// Choose recv -> Put to recv inbox |async| Choose codec -> Deserialize -> Handle (Custom logic)

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Message {
    peer_id: PeerId,
    protocol_tag: ProtocolTag,
    content: RawMessage,
}

impl Message {
    pub fn new(peer_id: PeerId, protocol_tag: ProtocolTag, content: RawMessage) -> Self {
        Self {
            peer_id,
            protocol_tag,
            content,
        }
    }
}

pub trait OutboxRouter {
    /// Route message to inbox(es) of interested hadnlers.
    fn route(&self, msg: Message) -> Result<(), Message>;
}
