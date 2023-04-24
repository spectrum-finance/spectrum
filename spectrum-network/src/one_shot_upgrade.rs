use std::future::Future;
use std::pin::Pin;
use std::{io, vec};

use futures::{AsyncRead, AsyncWrite};
use libp2p::core::{upgrade, UpgradeInfo};
use libp2p::{InboundUpgrade, OutboundUpgrade};

use crate::types::{ProtocolTag, RawMessage};

/// Upgrade that opens a connection and immediately sends a single message.
#[derive(Debug, Clone)]
pub struct AtomicUpgradeOut {
    protocol: ProtocolTag,
    message: RawMessage,
}

impl UpgradeInfo for AtomicUpgradeOut {
    type Info = ProtocolTag;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        vec![self.protocol].into_iter()
    }
}

impl<TSubstream> OutboundUpgrade<TSubstream> for AtomicUpgradeOut
where
    TSubstream: AsyncWrite + Unpin + Send + 'static,
{
    type Output = ();
    type Error = AtomicUpgradeErr;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, mut socket: TSubstream, _: Self::Info) -> Self::Future {
        Box::pin(async move {
            upgrade::write_length_prefixed(&mut socket, self.message).await?;
            Ok(())
        })
    }
}

/// Upgrade that expects a single message upon establishing a connection.
#[derive(Debug, Clone)]
pub struct AtomicUpgradeIn {
    protocol: ProtocolTag,
    max_message_size: usize,
}

impl UpgradeInfo for AtomicUpgradeIn {
    type Info = ProtocolTag;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        vec![self.protocol].into_iter()
    }
}

impl<TSubstream> InboundUpgrade<TSubstream> for AtomicUpgradeIn
where
    TSubstream: AsyncRead + Unpin + Send + 'static,
{
    type Output = OneShotMessage;
    type Error = AtomicUpgradeErr;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, mut socket: TSubstream, protocol: Self::Info) -> Self::Future {
        Box::pin(async move {
            let msg = upgrade::read_length_prefixed(&mut socket, self.max_message_size).await?;
            Ok(OneShotMessage {
                protocol,
                content: RawMessage::from(msg),
            })
        })
    }
}

#[derive(Debug)]
pub struct OneShotMessage {
    pub protocol: ProtocolTag,
    pub content: RawMessage,
}

#[derive(Debug, thiserror::Error)]
pub enum AtomicUpgradeErr {
    #[error(transparent)]
    IoErr(#[from] io::Error),
}