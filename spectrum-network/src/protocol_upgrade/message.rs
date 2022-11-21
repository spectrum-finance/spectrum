use crate::types::RawMessage;

pub const APPROVE_SIZE: usize = 1;

/// Fixed message used as a response to an inbound upgrade request.
pub struct Approve();

impl Approve {
    pub fn bytes() -> [u8; APPROVE_SIZE] {
        [1u8]
    }
}

impl Into<RawMessage> for Approve {
    fn into(self) -> RawMessage {
        RawMessage::from(Vec::from(Approve::bytes()))
    }
}
