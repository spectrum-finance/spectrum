use crate::protocol_handler::versioning::Versioned;
use crate::types::ProtocolVer;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum VoidMessage {}

impl Versioned for VoidMessage {
    fn version(&self) -> ProtocolVer {
        panic!()
    }
}
