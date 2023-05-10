use ciborium::de::Error;
use serde::{Deserialize, Serialize};
use crate::protocol_handler::codec::BinCodec;

use crate::protocol_handler::handel::message::HandelMessage;
use crate::protocol_handler::sigma_aggregation::types::{CommitmentsWithProofs, Responses, PreCommitments};
use crate::protocol_handler::versioning::Versioned;
use crate::protocol_handler::ProtocolSpec;
use crate::protocol_handler::void::VoidMessage;
use crate::types::{ProtocolVer, RawMessage};

pub const SIGMA_AGGR_V1: ProtocolVer = ProtocolVer(1);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SigmaAggrMessage {
    SigmaAggrMessageV1(SigmaAggrMessageV1),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SigmaAggrMessageV1 {
    PreCommitments(HandelMessage<PreCommitments>),
    Commitments(HandelMessage<CommitmentsWithProofs>),
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
    type THandshake = VoidMessage;
    type TMessage = SigmaAggrMessage;
}
