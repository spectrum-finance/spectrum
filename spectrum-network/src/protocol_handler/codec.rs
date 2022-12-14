use crate::types::RawMessage;
use ciborium::de::Error;
use serde::{Deserialize, Serialize};

pub trait BinCodec: Sized {
    fn encode(self) -> RawMessage;
    fn decode(msg: RawMessage) -> Result<Self, Error<std::io::Error>>;
}

impl<'de, T> BinCodec for T
where
    T: Serialize + Deserialize<'de>,
{
    fn encode(self) -> RawMessage {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&self, &mut encoded).unwrap();
        RawMessage::from(encoded)
    }

    fn decode(msg: RawMessage) -> Result<Self, Error<std::io::Error>> {
        let bf: Vec<u8> = msg.into();
        ciborium::de::from_reader(&bf[..])
    }
}

pub fn decode<T: BinCodec>(msg: RawMessage) -> Result<T, Error<std::io::Error>> {
    BinCodec::decode(msg)
}
