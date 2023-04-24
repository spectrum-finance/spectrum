use std::future::Future;
use std::pin::Pin;
use std::{io, vec};

use futures::AsyncRead;
use libp2p::core::{upgrade, UpgradeInfo};
use libp2p::{InboundUpgrade, OutboundUpgrade};
use void::Void;

use crate::peer_conn_handler::Message;
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

impl<Substream> OutboundUpgrade<Substream> for AtomicUpgradeOut {
    type Output = ();
    type Error = AtomicUpgradeErr;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_outbound(self, mut socket: Substream, protocol_tag: Self::Info) -> Self::Future {
        Box::pin(async move {
            upgrade::write_length_prefixed(socket, self.message).await?;
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

impl<Substream> InboundUpgrade<Substream> for AtomicUpgradeIn
where
    Substream: AsyncRead + Unpin + Send + 'static,
{
    type Output = Message;
    type Error = AtomicUpgradeErr;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Output, Self::Error>> + Send>>;

    fn upgrade_inbound(self, mut socket: Substream, protocol_tag: Self::Info) -> Self::Future {
        Box::pin(async move {
            let msg = upgrade::read_length_prefixed(socket, self.max_message_size).await?;
            Ok(Message {
                protocol_tag,
                content: RawMessage::from(msg),
            })
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AtomicUpgradeErr {
    #[error(transparent)]
    IoErr(#[from] io::Error),
}
