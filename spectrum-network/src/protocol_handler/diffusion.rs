use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_std::channel::Receiver;
use futures::Stream;
use libp2p_identity::PeerId;

use spectrum_ledger::ledger_view::history::HistoryReadAsync;

use crate::protocol_handler::diffusion::message::{
    DiffusionHandshake, DiffusionMessage, DiffusionSpec, HandshakeV1,
};
use crate::protocol_handler::diffusion::service::{DiffusionService, SyncState};
use crate::protocol_handler::pool::{FromTask, TaskPool};
use crate::protocol_handler::{NetworkAction, ProtocolBehaviour, ProtocolBehaviourOut};

pub mod message;
mod service;
pub(super) mod types;

enum DiffusionBehaviourIn {
    UpdatePeer { peer_id: PeerId, peer_state: SyncState },
}

type DiffusionBehaviourOut = ProtocolBehaviourOut<DiffusionHandshake, DiffusionMessage>;

pub struct DiffusionBehaviour<THistory> {
    from_tasks: Receiver<FromTask<DiffusionBehaviourIn, DiffusionBehaviourOut>>,
    outbox: VecDeque<DiffusionBehaviourOut>,
    tasks: TaskPool<DiffusionBehaviourIn, DiffusionBehaviourOut, ()>,
    peers: HashMap<PeerId, SyncState>,
    service: Arc<DiffusionService<THistory>>,
}

impl<THistory> DiffusionBehaviour<THistory> {
    fn on_event(&mut self, event: DiffusionBehaviourIn) {
        match event {
            DiffusionBehaviourIn::UpdatePeer { peer_id, peer_state } => {
                self.peers.insert(peer_id, peer_state);
            }
        }
    }
}

impl<'de, THistory> ProtocolBehaviour<'de> for DiffusionBehaviour<THistory>
where
    THistory: HistoryReadAsync + 'static,
{
    type TProto = DiffusionSpec;

    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<DiffusionHandshake>) {
        if let Some(DiffusionHandshake::HandshakeV1(HandshakeV1(status))) = handshake {
            let service = self.service.clone();
            self.tasks.spawn(|to_behaviour| async move {
                let peer_state = service.remote_state(status).await;
                to_behaviour
                    .send(FromTask::ToBehaviour(DiffusionBehaviourIn::UpdatePeer {
                        peer_id,
                        peer_state,
                    }))
                    .await
                    .unwrap();
                to_behaviour
                    .send(FromTask::ToHandler(DiffusionBehaviourOut::NetworkAction(
                        NetworkAction::EnablePeer {
                            peer_id,
                            handshakes: service.make_poly_handshake().await,
                        },
                    )))
                    .await
                    .unwrap();
            })
        }
    }

    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {
        let service = self.service.clone();
        self.tasks.spawn(|to_behaviour| async move {
            to_behaviour
                .send(FromTask::ToHandler(DiffusionBehaviourOut::NetworkAction(
                    NetworkAction::EnablePeer {
                        peer_id,
                        handshakes: service.make_poly_handshake().await,
                    },
                )))
                .await
                .unwrap();
        })
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<ProtocolBehaviourOut<DiffusionHandshake, DiffusionMessage>>> {
        loop {
            // First, let the tasks progress
            match Stream::poll_next(Pin::new(&mut self.tasks), cx) {
                Poll::Ready(Some(_)) => {}
                Poll::Pending | Poll::Ready(None) => {}
            }
            // Then, process their outputs
            match Stream::poll_next(Pin::new(&mut self.from_tasks), cx) {
                Poll::Ready(Some(out)) => match out {
                    FromTask::ToBehaviour(input) => self.on_event(input),
                    FromTask::ToHandler(out) => {
                        self.outbox.push_back(out);
                        break;
                    }
                },
                Poll::Pending | Poll::Ready(None) => break,
            }
        }
        if let Some(out) = self.outbox.pop_front() {
            return Poll::Ready(Some(out));
        }
        Poll::Pending
    }
}
