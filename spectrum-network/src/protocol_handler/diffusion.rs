use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_std::sync::RwLock;
use futures::Stream;
use libp2p_identity::PeerId;
use log::error;

use spectrum_ledger::ledger_view::history::HistoryReadAsync;

use crate::protocol_handler::diffusion::message::{
    DiffusionHandshake, DiffusionMessage, DiffusionSpec, HandshakeV1,
};
use crate::protocol_handler::diffusion::service::{DiffusionService, SyncState};
use crate::protocol_handler::pool::TaskPool;
use crate::protocol_handler::{NetworkAction, ProtocolBehaviour, ProtocolBehaviourOut};

pub mod message;
mod service;
pub(super) mod types;

type DiffusionBehaviourOut = ProtocolBehaviourOut<DiffusionHandshake, DiffusionMessage>;

#[derive(Debug, derive_more::Display)]
pub enum DiffusionBehaviorError {
    ModifierNotFound,
    OperationCancelled,
}

pub struct DiffusionBehaviour<THistory> {
    outbox: VecDeque<DiffusionBehaviourOut>,
    tasks: TaskPool<DiffusionBehaviourOut, DiffusionBehaviorError>,
    peers: Arc<RwLock<HashMap<PeerId, SyncState>>>, // todo: maybe it's better to mutate via messaging rather than locks?
    service: Arc<DiffusionService<THistory>>,
}

impl<'de, THistory> ProtocolBehaviour<'de> for DiffusionBehaviour<THistory>
where
    THistory: HistoryReadAsync + 'static,
{
    type TProto = DiffusionSpec;

    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<DiffusionHandshake>) {
        if let Some(DiffusionHandshake::HandshakeV1(HandshakeV1(status))) = handshake {
            let service = self.service.clone();
            let peers = self.peers.clone();
            self.tasks.spawn(async move {
                let peer_state = service.remote_state(status).await;
                peers.write().await.insert(peer_id, peer_state);
                Ok(DiffusionBehaviourOut::NetworkAction(NetworkAction::EnablePeer {
                    peer_id,
                    handshakes: service.make_poly_handshake().await,
                }))
            })
        }
    }

    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {
        let service = self.service.clone();
        self.tasks.spawn(async move {
            Ok(DiffusionBehaviourOut::NetworkAction(NetworkAction::EnablePeer {
                peer_id,
                handshakes: service.make_poly_handshake().await,
            }))
        })
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
