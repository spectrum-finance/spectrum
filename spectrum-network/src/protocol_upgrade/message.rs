use crate::types::RawMessage;

pub const APPROVE_SIZE: usize = 1;

/// Fixed message used as a response to an inbound upgrade request.
pub struct Approve();

impl Approve {
    pub fn bytes() -> [u8; APPROVE_SIZE] {
        [1u8]
    }
}

impl From<Approve> for RawMessage {
    fn from(_: Approve) -> Self {
        RawMessage::from(Vec::from(Approve::bytes()))
    }
}
