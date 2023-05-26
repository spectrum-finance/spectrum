use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_std::channel::{Receiver, Sender};
use futures::Stream;
use libp2p_identity::PeerId;

use spectrum_ledger::ledger_view::history::HistoryReadAsync;
use spectrum_ledger::{ModifierId, ModifierType};

use crate::protocol_handler::diffusion::delivery::{DeliveryStore, ModifierStatus};
use crate::protocol_handler::diffusion::message::{
    DiffusionHandshake, DiffusionMessage, DiffusionMessageV1, DiffusionSpec, HandshakeV1, Modifiers,
    SyncStatus,
};
use crate::protocol_handler::diffusion::service::{DiffusionService, RemoteChainCmp, SyncState};
use crate::protocol_handler::pool::{FromTask, TaskPool};
use crate::protocol_handler::{NetworkAction, ProtocolBehaviour, ProtocolBehaviourOut, ProtocolSpec};

mod delivery;
pub mod message;
mod service;
pub(super) mod types;

enum DiffusionBehaviourIn {
    UpdatePeer { peer_id: PeerId, peer_state: SyncState },
}

type DiffusionBehaviourOut = ProtocolBehaviourOut<DiffusionHandshake, DiffusionMessage>;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct DiffusionConfig {
    max_inv_size: usize,
}

pub struct DiffusionBehaviour<THistory> {
    conf: DiffusionConfig,
    from_tasks: Receiver<FromTask<DiffusionBehaviourIn, DiffusionBehaviourOut>>,
    outbox: VecDeque<DiffusionBehaviourOut>,
    tasks: TaskPool<DiffusionBehaviourIn, DiffusionBehaviourOut, ()>,
    peers: HashMap<PeerId, SyncState>,
    service: Arc<DiffusionService<THistory>>,
}

impl<THistory> DiffusionBehaviour<THistory>
where
    THistory: HistoryReadAsync + 'static,
{
    fn on_event(&mut self, event: DiffusionBehaviourIn) {
        match event {
            DiffusionBehaviourIn::UpdatePeer { peer_id, peer_state } => {
                self.peers.insert(peer_id, peer_state);
            }
        }
    }

    fn on_sync(&mut self, peer_id: PeerId, peer_status: SyncStatus, initial: bool) {
        let service = self.service.clone();
        let conf = self.conf;
        self.tasks.spawn(|to_behaviour| async move {
            let peer_state = service.remote_state(peer_status).await;
            to_behaviour
                .send(FromTask::ToBehaviour(DiffusionBehaviourIn::UpdatePeer {
                    peer_id,
                    peer_state: peer_state.clone(),
                }))
                .await
                .unwrap();
            if initial {
                to_behaviour
                    .send(FromTask::ToHandler(DiffusionBehaviourOut::NetworkAction(
                        NetworkAction::EnablePeer {
                            peer_id,
                            handshakes: service.make_poly_handshake().await,
                        },
                    )))
                    .await
                    .unwrap();
            }
            match peer_state.cmp {
                RemoteChainCmp::Equal | RemoteChainCmp::Nonsense => {}
                RemoteChainCmp::Longer(None) | RemoteChainCmp::Fork(None) => {
                    if !initial {
                        // sync is alerady included into handshake if initial
                        to_behaviour
                            .send(FromTask::ToHandler(DiffusionBehaviourOut::Send {
                                peer_id,
                                message: DiffusionMessage::sync_status_v1(service.local_status().await),
                            }))
                            .await
                            .unwrap();
                    }
                }
                RemoteChainCmp::Longer(Some(wanted_suffix)) => {
                    to_behaviour
                        .send(FromTask::ToHandler(DiffusionBehaviourOut::Send {
                            peer_id,
                            message: DiffusionMessage::request_modifiers_v1(
                                ModifierType::BlockHeader,
                                wanted_suffix.into_iter().map(ModifierId::from).collect(),
                            ),
                        }))
                        .await
                        .unwrap();
                }
                RemoteChainCmp::Shorter(remote_tip) | RemoteChainCmp::Fork(Some(remote_tip)) => {
                    let ext = service.extension(remote_tip, conf.max_inv_size).await;
                    to_behaviour
                        .send(FromTask::ToHandler(DiffusionBehaviourOut::Send {
                            peer_id,
                            message: DiffusionMessage::inv_v1(
                                ModifierType::BlockHeader,
                                ext.into_iter().map(ModifierId::from).collect(),
                            ),
                        }))
                        .await
                        .unwrap();
                }
            }
        })
    }
}

impl<'de, THistory> ProtocolBehaviour<'de> for DiffusionBehaviour<THistory>
where
    THistory: HistoryReadAsync + 'static,
{
    type TProto = DiffusionSpec;

    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<DiffusionHandshake>) {
        if let Some(DiffusionHandshake::HandshakeV1(HandshakeV1(status))) = handshake {
            self.on_sync(peer_id, status, true)
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

    fn inject_message(
        &mut self,
        peer_id: PeerId,
        DiffusionMessage::DiffusionMessageV1(msg): DiffusionMessage,
    ) {
        match msg {
            DiffusionMessageV1::Inv(Modifiers { mod_type, modifiers }) => {
                let service = self.service.clone();
                self.tasks.spawn(|to_behaviour| async move {
                    let wanted = service.select_wanted(modifiers).await;
                    to_behaviour
                        .send(FromTask::ToHandler(DiffusionBehaviourOut::Send {
                            peer_id,
                            message: DiffusionMessage::request_modifiers_v1(mod_type, wanted),
                        }))
                        .await
                        .unwrap();
                })
            }
            DiffusionMessageV1::RequestModifiers(_) => {}
            DiffusionMessageV1::Modifiers(_) => {}
            DiffusionMessageV1::SyncStatus(_) => {}
        }
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
