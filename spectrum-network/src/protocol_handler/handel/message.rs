use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use crate::{
    protocol_handler::{versioning::Versioned, ProtocolSpec},
    types::{ProtocolId, ProtocolVer},
};

use super::protocol::{Aggregable, Verifiable, Weighable};

/// Sync handshake provides initial node status.
#[derive(Serialize, Deserialize, Debug)]
pub enum HandelHandshake<C> {
    HandshakeV1(HandshakeV1<C>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HandshakeV1<C> {
    pub supported_protocols: Vec<ProtocolId>,
    pub height: usize,
    phantom: PhantomData<C>,
}

impl<C> Versioned for HandelHandshake<C> {
    fn version(&self) -> ProtocolVer {
        match self {
            HandelHandshake::HandshakeV1(_) => HandelSpec::<C>::v1(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum HandelMessage<C> {
    HandelMessageV1(HandelMessageV1<C>),
}

impl<C> Versioned for HandelMessage<C> {
    fn version(&self) -> ProtocolVer {
        HandelSpec::<C>::v1()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct HandelMessageV1<C> {
    msg: super::protocol::HandelMsg<C>,
}

pub struct HandelSpec<'de, C>(PhantomData<&'de C>);

impl<'de, C> HandelSpec<'de, C> {
    pub fn v1() -> ProtocolVer {
        ProtocolVer::from(1)
    }
}

impl<'de, C> ProtocolSpec for HandelSpec<'de, C>
where
    C: Aggregable
        + Weighable
        + Verifiable
        + Clone
        + Serialize
        + Deserialize<'de>
        + Send
        + core::fmt::Debug
        + 'static,
{
    type THandshake = HandelHandshake<C>;
    type TMessage = HandelMessage<C>;
}
