use ciborium::de::Error;
use serde::{Deserialize, Serialize};

use crate::types::RawMessage;

pub fn encode<T: Serialize>(obj: T) -> RawMessage {
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&obj, &mut encoded).unwrap();
    RawMessage::from(encoded)
}

pub fn decode<'de, T: Deserialize<'de>>(msg: RawMessage) -> Result<T, Error<std::io::Error>> {
    let bf: Vec<u8> = msg.into();
    ciborium::de::from_reader(&bf[..])
}
