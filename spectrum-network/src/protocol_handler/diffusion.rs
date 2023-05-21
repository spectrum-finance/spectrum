use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::FuturesOrdered;
use futures::Stream;
use libp2p_identity::PeerId;
use log::error;

use spectrum_ledger::ledger_view::history::HistoryAsync;

use crate::protocol_handler::diffusion::message::{
    DiffusionHandshake, DiffusionMessage, DiffusionSpec, HandshakeV1, SyncStatus,
};
use crate::protocol_handler::{NetworkAction, ProtocolBehaviour, ProtocolBehaviourOut};
use crate::types::ProtocolVer;

pub mod message;
pub(super) mod types;

type DiffusionBehaviourOut = ProtocolBehaviourOut<DiffusionHandshake, DiffusionMessage>;

#[derive(Debug, derive_more::Display)]
pub enum DiffusionBehaviorError {
    ModifierNotFound,
    OperationCancelled,
}

type DiffusionTask =
    Pin<Box<dyn Future<Output = Result<DiffusionBehaviourOut, DiffusionBehaviorError>> + Send>>;

pub struct DiffusionBehaviour<THistory> {
    outbox: VecDeque<DiffusionBehaviourOut>,
    tasks: FuturesOrdered<DiffusionTask>,
    history: THistory,
}

impl<THistory> DiffusionBehaviour<THistory> {
    fn local_status(&self) -> SyncStatus {
        todo!()
    }

    fn make_poly_handshake(&self) -> Vec<(ProtocolVer, Option<DiffusionHandshake>)> {
        vec![(
            DiffusionSpec::v1(),
            Some(DiffusionHandshake::HandshakeV1(HandshakeV1(self.local_status()))),
        )]
    }
}

impl<'de, THistory> ProtocolBehaviour<'de> for DiffusionBehaviour<THistory>
where
    THistory: HistoryAsync,
{
    type TProto = DiffusionSpec;

    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<DiffusionHandshake>) {
        if let Some(DiffusionHandshake::HandshakeV1(hs)) = handshake {
            self.outbox
                .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::EnablePeer {
                    peer_id,
                    handshakes: self.make_poly_handshake(),
                }))
        }
    }

    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {
        self.outbox
            .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::EnablePeer {
                peer_id,
                handshakes: self.make_poly_handshake(),
            }))
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<ProtocolBehaviourOut<DiffusionHandshake, DiffusionMessage>>> {
        loop {
            match Stream::poll_next(Pin::new(&mut self.tasks), cx) {
                Poll::Ready(Some(Ok(out))) => {
                    self.outbox.push_back(out);
                    continue;
                }
                Poll::Ready(Some(Err(err))) => {
                    error!("An error occured: {}", err);
                    continue;
                }
                Poll::Pending | Poll::Ready(None) => break,
            }
        }
        if let Some(out) = self.outbox.pop_front() {
            return Poll::Ready(Some(out));
        }
        Poll::Pending
    }
}
