use crate::types::RawMessage;

pub trait BinCodec: Sized {
    fn encode(self) -> RawMessage;
    fn decode(msg: RawMessage) -> Result<Self, String>;
}

pub fn decode<T: BinCodec>(msg: RawMessage) -> Result<T, String> {
    BinCodec::decode(msg)
}
