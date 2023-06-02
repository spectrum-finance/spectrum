use std::collections::{HashMap, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_std::channel::{Receiver, Sender};
use futures::channel::oneshot;
use futures::{stream, Stream, StreamExt};
use libp2p_identity::PeerId;

use spectrum_ledger::block::BlockHeader;
use spectrum_ledger::{Modifier, ModifierId, ModifierType, SerializedModifier};
use spectrum_view::history::LedgerHistoryReadAsync;
use spectrum_view::node_view::NodeViewWriteAsync;

use crate::protocol_handler::diffusion::message::{
    DiffusionHandshake, DiffusionMessage, DiffusionMessageV1, DiffusionSpec, HandshakeV1, Modifiers,
    SyncStatus,
};
use crate::protocol_handler::diffusion::service::{RemoteChainCmp, RemoteSync, SyncState};
use crate::protocol_handler::pool::{FromTask, TaskPool};
use crate::protocol_handler::{NetworkAction, ProtocolBehaviour, ProtocolBehaviourOut, ProtocolSpec};

pub mod message;
mod service;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum ModifierStatus {
    Wanted,
    Requested(Instant),
    Received,
    Unknown,
}

trait ModifierTracker {
    fn status(&self, mid: &ModifierId) -> ModifierStatus;
    fn set_status(&mut self, mid: ModifierId, status: ModifierStatus);
}

impl ModifierTracker for HashMap<ModifierId, ModifierStatus> {
    fn status(&self, mid: &ModifierId) -> ModifierStatus {
        self.get(mid).copied().unwrap_or(ModifierStatus::Unknown)
    }
    fn set_status(&mut self, mid: ModifierId, status: ModifierStatus) {
        if let ModifierStatus::Unknown = status {
            self.remove(&mid);
        } else {
            self.insert(mid, status);
        }
    }
}

#[derive(Debug)]
enum DiffusionBehaviourIn {
    UpdatePeer {
        peer_id: PeerId,
        peer_state: SyncState,
    },
    UpdateModifier {
        modifier_id: ModifierId,
        status: ModifierStatus,
    },
    GetModifierStatus {
        modifier: ModifierId,
        status_future: oneshot::Sender<ModifierStatus>,
    },
}

#[async_trait::async_trait]
trait DiffusionStateWrite {
    async fn update_peer(&self, peer_id: PeerId, peer_state: SyncState);
    async fn update_modifier(&self, modifier_id: ModifierId, status: ModifierStatus);
}

#[async_trait::async_trait]
impl DiffusionStateWrite for Sender<FromTask<DiffusionBehaviourIn, DiffusionBehaviourOut>> {
    async fn update_peer(&self, peer_id: PeerId, peer_state: SyncState) {
        self.send(FromTask::ToBehaviour(DiffusionBehaviourIn::UpdatePeer {
            peer_id,
            peer_state,
        }))
        .await
        .unwrap();
    }

    async fn update_modifier(&self, modifier_id: ModifierId, status: ModifierStatus) {
        self.send(FromTask::ToBehaviour(DiffusionBehaviourIn::UpdateModifier {
            modifier_id,
            status,
        }))
        .await
        .unwrap();
    }
}

#[async_trait::async_trait]
trait DiffusionStateRead {
    async fn modifier_status(&self, mid: ModifierId) -> ModifierStatus;
}

#[async_trait::async_trait]
impl DiffusionStateRead for Sender<FromTask<DiffusionBehaviourIn, DiffusionBehaviourOut>> {
    async fn modifier_status(&self, modifier: ModifierId) -> ModifierStatus {
        let (snd, recv) = oneshot::channel();
        self.send(FromTask::ToBehaviour(DiffusionBehaviourIn::GetModifierStatus {
            modifier,
            status_future: snd,
        }))
        .await
        .unwrap();
        recv.await.unwrap()
    }
}

type DiffusionBehaviourOut = ProtocolBehaviourOut<DiffusionHandshake, DiffusionMessage>;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct DiffusionConfig {
    max_inv_size: usize,
    task_timeout: Duration,
}

pub struct DiffusionBehaviour<'a, THistory, TLedgerView> {
    conf: DiffusionConfig,
    from_tasks: Receiver<FromTask<DiffusionBehaviourIn, DiffusionBehaviourOut>>,
    outbox: VecDeque<DiffusionBehaviourOut>,
    tasks: TaskPool<'a, DiffusionBehaviourIn, DiffusionBehaviourOut, ()>,
    peers: HashMap<PeerId, SyncState>,
    delivery: HashMap<ModifierId, ModifierStatus>,
    remote_sync: RemoteSync<THistory>,
    history: Arc<THistory>,
    ledger_view: TLedgerView,
}

const FROM_TASK_BUFFER_SIZE: usize = 1000;

impl<'a, THistory, TLedgerView> DiffusionBehaviour<'a, THistory, TLedgerView>
where
    THistory: LedgerHistoryReadAsync + 'a,
    TLedgerView: NodeViewWriteAsync + 'a,
{
    pub fn new(conf: DiffusionConfig, history: Arc<THistory>, ledger_view: TLedgerView) -> Self {
        let (snd, recv) = async_std::channel::bounded(FROM_TASK_BUFFER_SIZE);
        Self {
            conf,
            from_tasks: recv,
            outbox: VecDeque::new(),
            tasks: TaskPool::new(String::from("Diffusion"), conf.task_timeout, snd),
            peers: HashMap::new(),
            delivery: HashMap::new(),
            remote_sync: RemoteSync::new(Arc::clone(&history)),
            history,
            ledger_view,
        }
    }

    fn on_event(&mut self, event: DiffusionBehaviourIn) {
        match event {
            DiffusionBehaviourIn::UpdatePeer { peer_id, peer_state } => {
                self.peers.insert(peer_id, peer_state);
            }
            DiffusionBehaviourIn::UpdateModifier {
                modifier_id: modifier,
                status,
            } => {
                self.delivery.set_status(modifier, status);
            }

            DiffusionBehaviourIn::GetModifierStatus {
                modifier,
                status_future,
            } => {
                status_future.send(self.delivery.status(&modifier)).unwrap();
            }
        }
    }

    fn on_sync(&mut self, peer_id: PeerId, peer_status: SyncStatus, initial: bool) {
        let service = self.remote_sync.clone();
        let conf = self.conf;
        self.tasks.spawn(|to_behaviour| async move {
            let peer_state = service.remote_state(peer_status).await;
            to_behaviour.update_peer(peer_id, peer_state.clone()).await;
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

    fn on_modifiers_request(&mut self, peer_id: PeerId, mod_type: ModifierType, modifiers: Vec<ModifierId>) {
        let service = self.remote_sync.clone();
        self.tasks.spawn(|to_behaviour| async move {
            let raw_modifiers = service.get_modifiers(mod_type, modifiers).await;
            to_behaviour
                .send(FromTask::ToHandler(ProtocolBehaviourOut::Send {
                    peer_id,
                    message: DiffusionMessage::modifiers_v1(mod_type, raw_modifiers),
                }))
                .await
                .unwrap();
        })
    }

    fn on_modifiers(
        &mut self,
        peer_id: PeerId,
        mod_type: ModifierType,
        raw_modifiers: Vec<SerializedModifier>,
    ) {
        let ledger_view = self.ledger_view.clone();
        self.tasks.spawn(|to_behaviour| async move {
            let mut modifiers = vec![];
            for m in raw_modifiers {
                if let Ok(md) = decode_modifier(mod_type, &m) {
                    to_behaviour
                        .update_modifier(md.id(), ModifierStatus::Received)
                        .await;
                    modifiers.push(md)
                } else {
                    to_behaviour
                        .send(FromTask::ToHandler(ProtocolBehaviourOut::NetworkAction(
                            NetworkAction::BanPeer(peer_id),
                        )))
                        .await
                        .unwrap();
                    break;
                }
            }
            stream::iter(modifiers)
                .then(|md| {
                    let mut ledger = ledger_view.clone();
                    async move { ledger.apply_modifier(md).await }
                })
                .collect::<Vec<_>>()
                .await;
        })
    }
}

/// Select desired modifiers from the given list of proposed modifiers.
async fn select_wanted<THistory: LedgerHistoryReadAsync, TDiffusion: DiffusionStateRead>(
    history: &Arc<THistory>,
    diffusion: &TDiffusion,
    proposed_modifiers: Vec<ModifierId>,
) -> Vec<ModifierId> {
    stream::iter(proposed_modifiers)
        .filter(|&mid| async move {
            (matches!(diffusion.modifier_status(mid).await, ModifierStatus::Wanted)
                || matches!(diffusion.modifier_status(mid).await, ModifierStatus::Unknown))
                && !history.contains(&mid).await
        })
        .collect::<Vec<_>>()
        .await
}

fn decode_modifier(
    mod_type: ModifierType,
    SerializedModifier(bf): &SerializedModifier,
) -> Result<Modifier, ()> {
    let res = match mod_type {
        ModifierType::BlockHeader => {
            ciborium::de::from_reader::<BlockHeader, _>(&bf[..]).map(|h| Modifier::from(h))
        }
    };
    res.map_err(|_| ())
}

impl<'a, 'de, THistory, TLedgerView> ProtocolBehaviour<'de> for DiffusionBehaviour<'a, THistory, TLedgerView>
where
    THistory: LedgerHistoryReadAsync + 'a,
    TLedgerView: NodeViewWriteAsync + 'a,
{
    type TProto = DiffusionSpec;

    fn inject_message(
        &mut self,
        peer_id: PeerId,
        DiffusionMessage::DiffusionMessageV1(msg): DiffusionMessage,
    ) {
        match msg {
            DiffusionMessageV1::Inv(Modifiers { mod_type, modifiers }) => {
                let history = self.history.clone();
                self.tasks.spawn(|to_behaviour| async move {
                    let wanted = select_wanted(&history, &to_behaviour, modifiers).await;
                    if !wanted.is_empty() {
                        to_behaviour
                            .send(FromTask::ToHandler(DiffusionBehaviourOut::Send {
                                peer_id,
                                message: DiffusionMessage::request_modifiers_v1(mod_type, wanted),
                            }))
                            .await
                            .unwrap();
                    }
                })
            }
            DiffusionMessageV1::RequestModifiers(Modifiers { mod_type, modifiers }) => {
                self.on_modifiers_request(peer_id, mod_type, modifiers)
            }
            DiffusionMessageV1::Modifiers(Modifiers { mod_type, modifiers }) => {
                self.on_modifiers(peer_id, mod_type, modifiers)
            }
            DiffusionMessageV1::SyncStatus(status) => self.on_sync(peer_id, status, false),
        }
    }

    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<DiffusionHandshake>) {
        if let Some(DiffusionHandshake::HandshakeV1(HandshakeV1(status))) = handshake {
            self.on_sync(peer_id, status, true)
        }
    }

    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {
        let service = self.remote_sync.clone();
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use async_std::{future, task};
    use futures::channel::mpsc;
    use futures::StreamExt;
    use libp2p_identity::PeerId;

    use spectrum_ledger::block::{BlockHeader, BlockId, BlockSection, BlockVer};
    use spectrum_ledger::{ModifierId, ModifierType, SlotNo};
    use spectrum_view::node_view::NodeViewMailbox;

    use crate::protocol_handler::diffusion::message::{
        DiffusionHandshake, DiffusionMessage, HandshakeV1, SyncStatus,
    };
    use crate::protocol_handler::diffusion::service::tests::EphemeralHistory;
    use crate::protocol_handler::diffusion::{DiffusionBehaviour, DiffusionConfig};
    use crate::protocol_handler::{BehaviourStream, ProtocolBehaviour, ProtocolBehaviourOut};

    #[async_std::test]
    async fn process_inv() {
        let local_chain = make_chain(16);
        let mut beh = make_behaviour(local_chain.clone());
        let unknown_modifiers = (0..4)
            .map(|_| ModifierId::from(BlockId::random()))
            .collect::<Vec<_>>();
        let inv_modifiers = unknown_modifiers
            .clone()
            .into_iter()
            .chain(vec![ModifierId::from(local_chain[0].id)])
            .collect();
        let inv = DiffusionMessage::inv_v1(ModifierType::BlockHeader, inv_modifiers);
        let remote_pid = PeerId::random();
        beh.inject_message(remote_pid, inv);
        let handle = task::spawn(async move {
            let mut stream = BehaviourStream::new(beh);
            loop {
                match stream.select_next_some().await {
                    ProtocolBehaviourOut::Send { peer_id, message } => {
                        return (peer_id, message);
                    }
                    ProtocolBehaviourOut::NetworkAction(_) => {}
                }
            }
        });
        let (peer, msg) = future::timeout(Duration::from_secs(5), handle).await.unwrap();
        assert_eq!(peer, remote_pid);
        let expected_msg =
            DiffusionMessage::request_modifiers_v1(ModifierType::BlockHeader, unknown_modifiers);
        assert_eq!(msg, expected_msg);
    }

    #[async_std::test]
    async fn handsake_with_younger_peer() {
        let local_chain = make_chain(16);
        let mut remote_chain = local_chain.clone()[..14]
            .into_iter()
            .map(|blk| blk.id)
            .collect::<Vec<_>>();
        remote_chain.reverse();
        let remote_ss = SyncStatus {
            height: SlotNo::from(13),
            last_blocks: remote_chain.clone(),
        };
        let mut beh = make_behaviour(local_chain.clone());

        let remote_pid = PeerId::random();
        let remote_hs = DiffusionHandshake::HandshakeV1(HandshakeV1(remote_ss));

        beh.inject_protocol_requested(remote_pid, Some(remote_hs));

        let handle = task::spawn(async move {
            let mut stream = BehaviourStream::new(beh);
            loop {
                match stream.select_next_some().await {
                    ProtocolBehaviourOut::Send { peer_id, message } => {
                        return (peer_id, message);
                    }
                    ProtocolBehaviourOut::NetworkAction(_) => {}
                }
            }
        });

        let (peer, msg) = future::timeout(Duration::from_secs(5), handle).await.unwrap();
        assert_eq!(peer, remote_pid);

        let expected_msg = DiffusionMessage::inv_v1(
            ModifierType::BlockHeader,
            local_chain[14..]
                .into_iter()
                .map(|blk| ModifierId::from(blk.id))
                .collect(),
        );
        assert_eq!(msg, expected_msg);
    }

    fn make_behaviour(
        chain: Vec<BlockHeader>,
    ) -> DiffusionBehaviour<'static, EphemeralHistory, NodeViewMailbox> {
        let history = Arc::new(EphemeralHistory {
            db: chain
                .into_iter()
                .map(|hdr| (hdr.id, BlockSection::Header(hdr)))
                .collect(),
        });

        let conf = DiffusionConfig {
            max_inv_size: 9182,
            task_timeout: Duration::from_secs(5),
        };
        let (snd, recv) = mpsc::channel(100);
        let lv = NodeViewMailbox::new(snd);
        DiffusionBehaviour::new(conf, history, lv)
    }

    fn make_chain(n: usize) -> Vec<BlockHeader> {
        (0..n)
            .map(|i| BlockHeader {
                id: BlockId::random(),
                slot: SlotNo::from(i as u64),
                version: BlockVer::INITIAL,
            })
            .collect::<Vec<_>>()
    }
}
