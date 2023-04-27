use std::future::Future;
use std::pin::Pin;
use std::{io, vec};

use futures::{AsyncRead, AsyncWrite};
use libp2p::core::{upgrade, UpgradeInfo};
use libp2p::{InboundUpgrade, OutboundUpgrade};

use crate::peer_conn_handler::OneShotRequestId;
use crate::types::{ProtocolTag, RawMessage};

/// Upgrade that opens a connection and immediately sends a single message.
#[derive(Debug, Clone)]
pub struct OneShotUpgradeOut {
    pub(crate) protocol: ProtocolTag,
    pub(crate) id: OneShotRequestId,
    pub(crate) message: RawMessage,
}

impl UpgradeInfo for OneShotUpgradeOut {
    type Info = ProtocolTag;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        vec![self.protocol].into_iter()
    }
}

impl<TSubstream> OutboundUpgrade<TSubstream> for OneShotUpgradeOut
where
    TSubstream: AsyncWrite + Unpin + Send + 'static,
{
    type Output = OneShotRequestId;
    type Error = AtomicUpgradeErr;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, mut socket: TSubstream, _: Self::Info) -> Self::Future {
        Box::pin(async move {
            upgrade::write_length_prefixed(&mut socket, self.message).await?;
            Ok(self.id)
        })
    }
}

/// Upgrade that expects a single message upon establishing a connection.
#[derive(Debug, Clone)]
pub struct OneShotUpgradeIn {
    pub protocol: ProtocolTag,
    pub max_message_size: usize,
}

impl UpgradeInfo for OneShotUpgradeIn {
    type Info = ProtocolTag;
    type InfoIter = vec::IntoIter<Self::Info>;

    fn protocol_info(&self) -> Self::InfoIter {
        vec![self.protocol].into_iter()
    }
}

impl<TSubstream> InboundUpgrade<TSubstream> for OneShotUpgradeIn
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

#[derive(Clone, Debug)]
pub struct OneShotMessage {
    pub protocol: ProtocolTag,
    pub content: RawMessage,
}

#[derive(Debug, thiserror::Error)]
pub enum AtomicUpgradeErr {
    #[error(transparent)]
    IoErr(#[from] io::Error),
}
