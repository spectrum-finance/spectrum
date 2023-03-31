use std::fmt::Debug;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::protocol_handler::versioning::Versioned;
use crate::protocol_handler::ProtocolSpec;
use crate::types::ProtocolVer;

const COSI_V1: ProtocolVer = ProtocolVer(1);

#[derive(Serialize, Deserialize, Debug)]
pub enum CoSiHandshake {
    CoSiV1(),
}

impl Versioned for CoSiHandshake {
    fn version(&self) -> ProtocolVer {
        match self {
            CoSiHandshake::CoSiV1() => COSI_V1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CoSiMessage<S, R> {
    CoSiMessageV1(CoSiMessageV1<S, R>),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CoSiMessageV1<S, R> {
    Announcement { statement: S },
    Response { response: R },
}

impl<S, R> Versioned for CoSiMessage<S, R> {
    fn version(&self) -> ProtocolVer {
        match self {
            CoSiMessage::CoSiMessageV1(_) => COSI_V1,
        }
    }
}
