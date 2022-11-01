use crate::network_controller::NetworkAPI;
use crate::protocol::{ProtocolSpec, SYNC_PROTOCOL_ID};
use crate::protocol_handler::sync::message::{SyncHandshake, SyncMessage};
use crate::protocol_handler::{ProtocolBehaviourIn, ProtocolBehaviourOut};
use crate::types::ProtocolVer;
use futures::channel::mpsc::{UnboundedReceiver};
use futures::Stream;
use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};

pub mod data;
pub(crate) mod message;

pub struct SyncHandler<TNetwork> {
    versions: HashMap<ProtocolVer, ProtocolSpec>,
    mailbox: UnboundedReceiver<ProtocolBehaviourIn<SyncHandshake, SyncMessage>>,
    network: TNetwork,
}

// pub fn make<TNetwork>(
//     versions: HashMap<ProtocolVer, ProtocolSpec>,
//     network: TNetwork,
// ) -> (SyncHandler<TNetwork>, ProtocolMailbox<SyncHandshake, SyncMessage>) {
//     let (snd, recv) = mpsc::unbounded::<ProtocolHandlerInRaw<SyncHandshake, SyncMessage>>();
//     (
//         SyncHandler {
//             versions,
//             mailbox: recv,
//             network,
//         },
//         ProtocolMailbox {
//             notifications_snd: snd,
//         },
//     )
// }

impl<TNetwork> Stream for SyncHandler<TNetwork>
where
    TNetwork: NetworkAPI + Unpin,
{
    type Item = ProtocolBehaviourOut<SyncHandshake, SyncMessage>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        loop {
            if let Poll::Ready(Some(event)) = Stream::poll_next(Pin::new(&mut self.mailbox), cx) {
                todo!()
            }
        }
    }
}
