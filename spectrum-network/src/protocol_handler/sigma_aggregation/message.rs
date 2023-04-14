use serde::{Deserialize, Serialize};

use crate::protocol_handler::handel::message::HandelMessage;
use crate::protocol_handler::sigma_aggregation::types::{DlogProofs, Responses, SchnorrCommitments};
use crate::protocol_handler::versioning::Versioned;
use crate::protocol_handler::ProtocolSpec;
use crate::types::ProtocolVer;

pub const SIGMA_AGGR_V1: ProtocolVer = ProtocolVer(1);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SigmaAggrMessage {
    SigmaAggrMessageV1(SigmaAggrMessageV1),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SigmaAggrMessageV1 {
    SchnorrCommitments(HandelMessage<SchnorrCommitments>),
    //DlogProofs(HandelMessage<DlogProofs>),
    Responses(HandelMessage<Responses>),
}

impl Versioned for SigmaAggrMessage {
    fn version(&self) -> ProtocolVer {
        match self {
            SigmaAggrMessage::SigmaAggrMessageV1(_) => SIGMA_AGGR_V1,
        }
    }
}

pub struct SigmaAggrSpec;

impl ProtocolSpec for SigmaAggrSpec {
    type THandshake = SigmaAggrMessage;
    type TMessage = SigmaAggrMessage;
}
