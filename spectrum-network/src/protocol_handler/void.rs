use ciborium::de::Error;

use crate::protocol_handler::codec::BinCodec;
use crate::protocol_handler::versioning::Versioned;
use crate::types::{ProtocolVer, RawMessage};

#[derive(Debug)]
pub enum VoidMessage {}

impl BinCodec for VoidMessage {
    fn encode(self) -> RawMessage {
        panic!()
    }

    fn decode(msg: RawMessage) -> Result<Self, Error<std::io::Error>> {
        panic!()
    }
}

impl Versioned for VoidMessage {
    fn version(&self) -> ProtocolVer {
        panic!()
    }
}
