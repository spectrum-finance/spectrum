use ciborium::de::Error;
use crate::types::RawMessage;

pub trait BinCodec: Sized {
    fn encode(self) -> RawMessage;
    fn decode(msg: RawMessage) -> Result<Self, Error<std::io::Error>>;
}

pub fn decode<T: BinCodec>(msg: RawMessage) -> Result<T, Error<std::io::Error>> {
    BinCodec::decode(msg)
}
