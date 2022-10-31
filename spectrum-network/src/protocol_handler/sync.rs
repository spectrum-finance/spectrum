use crate::protocol::ProtocolSpec;
use crate::protocol_handler::{ProtocolHandlerIn, ProtocolMailbox};
use crate::types::ProtocolVer;
use futures::channel::mpsc;
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::Stream;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};

pub mod data;

pub struct SyncHandler<TNetwork> {
    versions: HashMap<ProtocolVer, ProtocolSpec>,
    mailbox: UnboundedReceiver<ProtocolHandlerIn>,
    network: TNetwork,
}

pub fn make<TNetwork>(
    versions: HashMap<ProtocolVer, ProtocolSpec>,
    network: TNetwork,
) -> (SyncHandler<TNetwork>, ProtocolMailbox) {
    let (snd, recv) = mpsc::unbounded::<ProtocolHandlerIn>();
    (
        SyncHandler {
            versions,
            mailbox: recv,
            network,
        },
        ProtocolMailbox {
            notifications_snd: snd,
        },
    )
}

impl<TNetwork> Stream for SyncHandler<TNetwork>
where
    TNetwork: Unpin,
{
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            if let Poll::Ready(Some(event)) = Stream::poll_next(Pin::new(&mut self.mailbox), cx) {
                match event {
                    ProtocolHandlerIn::RequestedLocal { peer_id } => {}
                    ProtocolHandlerIn::Requested {
                        peer_id,
                        protocol_ver,
                        handshake,
                    } => {}
                    ProtocolHandlerIn::Enabled {
                        peer_id,
                        protocol_ver,
                        handshake,
                        sink,
                    } => {}
                    ProtocolHandlerIn::Disabled(peer_id) => {}
                    ProtocolHandlerIn::Message {
                        peer_id,
                        protocol_ver,
                        content,
                    } => {}
                }
            }
        }
    }
}
