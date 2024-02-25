use serde::{Deserialize, Serialize};

use spectrum_handel::message::HandelMessage;
use spectrum_network::protocol_handler::versioning::Versioned;
use spectrum_network::protocol_handler::void::VoidMessage;
use spectrum_network::protocol_handler::ProtocolSpec;
use spectrum_network::types::ProtocolVer;

use crate::{CommitmentsWithProofs, PreCommitments, Responses};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SigmaAggrMessage {
    SigmaAggrMessageV1(SigmaAggrMessageV1),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum SigmaAggrMessageV1 {
    PreCommitments(HandelMessage<PreCommitments>),
    Commitments(HandelMessage<CommitmentsWithProofs>),
    BroadcastPreCommitments(PreCommitments),
    BroadcastCommitments(CommitmentsWithProofs),
    Responses(HandelMessage<Responses>),
}

impl Versioned for SigmaAggrMessage {
    fn version(&self) -> ProtocolVer {
        match self {
            SigmaAggrMessage::SigmaAggrMessageV1(_) => ProtocolVer::default(),
        }
    }
}

pub struct SigmaAggrSpec;

impl ProtocolSpec for SigmaAggrSpec {
    type THandshake = VoidMessage;
    type TMessage = SigmaAggrMessage;
}
