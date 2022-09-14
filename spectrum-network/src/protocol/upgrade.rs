use crate::protocol::substream::{ProtocolSubstreamHandshakeState, ProtocolSubstreamIn};
use crate::types::{ProtocolId, ProtocolVer, RawMessage};
use asynchronous_codec::Framed;
use futures::prelude::*;
use futures::{AsyncRead, AsyncWrite};
use libp2p::core::{upgrade, UpgradeInfo};
use libp2p::InboundUpgrade;
use std::collections::HashMap;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::{future, io, vec};
use unsigned_varint::codec::UviBytes;
use void::Void;

/// Tag of a protocol. Consists of ProtocolId + ProtocolVer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProtocolTag(Vec<u8>);

impl ProtocolTag {
    fn new(protocol_id: ProtocolId, protocol_ver: ProtocolVer) -> Self {
        Self(vec![protocol_id.into(), protocol_ver.into()])
    }
}

impl Into<ProtocolVer> for ProtocolTag {
    fn into(self) -> ProtocolVer {
        ProtocolVer::from(self.0[1])
    }
}

impl upgrade::ProtocolName for ProtocolTag {
    fn protocol_name(&self) -> &[u8] {
        &*self.0
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolHandshakeErr {
    #[error(transparent)]
    IoErr(#[from] io::Error),
    #[error(transparent)]
    PrefixReadErr(#[from] unsigned_varint::io::ReadError),
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolUpgradeErr {
    #[error(transparent)]
    HandshakeErr(#[from] ProtocolHandshakeErr),
}

#[derive(Debug, Clone)]
pub struct InboundProtocolSpec {
    /// Maximum allowed size for a single message.
    max_message_size: u64,
    /// Does the protocol negotiation require a special handshake or not.
    handshake_required: bool,
}

/// Upgrade that accepts a substream, sends back a status message, then becomes a unidirectional
/// stream of messages.
#[derive(Debug, Clone)]
pub struct ProtocolUpgradeIn {
    /// All supported protocols.
    protocols: HashMap<ProtocolTag, InboundProtocolSpec>,
}

impl UpgradeInfo for ProtocolUpgradeIn {
    type Info = ProtocolTag;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.protocols
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
    }
}

impl<Substream> InboundUpgrade<Substream> for ProtocolUpgradeIn
where
    Substream: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Output = ProtocolUpgraded<ProtocolSubstreamIn<Substream>>;
    type Error = ProtocolUpgradeErr;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>>>>;

    fn upgrade_inbound(self, mut socket: Substream, info: Self::Info) -> Self::Future {
        Box::pin(async move {
            let pspec = self.protocols.get(&info).unwrap();
            let mut codec = UviBytes::default();
            codec.set_max_len(usize::try_from(pspec.max_message_size).unwrap_or(usize::MAX));
            let handshake = if pspec.handshake_required {
                Some(read_handshake(&mut socket).await?)
            } else {
                None
            };
            let handshake_state = if pspec.handshake_required {
                ProtocolSubstreamHandshakeState::NotSent
            } else {
                ProtocolSubstreamHandshakeState::NotRequired
            };
            let substream = ProtocolSubstreamIn {
                socket: Framed::new(socket, codec),
                handshake: handshake_state,
            };
            Ok(ProtocolUpgraded {
                negotiated_ver: info.into(),
                handshake,
                substream,
            })
        })
    }
}

async fn read_handshake<Substream: AsyncRead + Unpin>(
    mut socket: &mut Substream,
) -> Result<RawMessage, ProtocolHandshakeErr> {
    let handshake_len = unsigned_varint::aio::read_usize(&mut socket).await?;
    let mut handshake = vec![0u8; handshake_len];
    socket.read_exact(&mut handshake).await?;
    Ok(RawMessage::from(handshake))
}

#[derive(Debug, Clone)]
pub struct OutboundProtocolSpec {
    /// Maximum allowed size for a single notification.
    max_message_size: u64,
    /// Initial message to send when we start communicating.
    handshake: Option<RawMessage>,
}

/// Upgrade that opens a substream, waits for the remote to accept by sending back a status
/// message, then becomes a unidirectional sink of data.
#[derive(Debug, Clone)]
pub struct ProtocolUpgradeOut {
    /// Protocol to negotiate.
    protocol_id: ProtocolId,
    /// Protocol versions to negotiate.
    /// The first one is the main name, while the other ones are fall backs.
    supported_versions: HashMap<ProtocolVer, OutboundProtocolSpec>,
}

impl UpgradeInfo for ProtocolUpgradeOut {
    type Info = ProtocolTag;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        self.supported_versions
            .keys()
            .cloned()
            .map(|v| ProtocolTag::new(self.protocol_id, v))
            .collect::<Vec<_>>()
            .into_iter()
    }
}

pub struct ProtocolUpgraded<Substream> {
    negotiated_ver: ProtocolVer,
    handshake: Option<RawMessage>,
    substream: Substream,
}
