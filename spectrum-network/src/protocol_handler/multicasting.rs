use std::collections::{HashSet, VecDeque};
use std::ops::Sub;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_std::channel::Receiver;
use either::{Either, Left, Right};
use futures::{FutureExt, Stream};
use libp2p_identity::PeerId;

use algebra_core::{CommutativePartialSemigroup, CommutativeSemigroup};
use spectrum_crypto::{AsyncVerifiable, VerifiableAgainst, Verified};
use tracing::trace;

use crate::protocol_handler::multicasting::overlay::DagOverlay;
use crate::protocol_handler::pool::{FromTask, TaskPool};
use crate::protocol_handler::void::VoidMessage;
use crate::protocol_handler::{NetworkAction, ProtocolBehaviourOut, TemporalProtocolStage};

use super::handel::partitioning::{PeerIx, PeerPartitions};
use super::handel::Weighted;

pub mod overlay;

/// DAG based multicasting that accumulates received statements along the way.
pub struct DagMulticasting<S, P, PP> {
    pub statement: Option<S>,
    pub public_data: P,
    pub overlay: DagOverlay,
    pub contacted_peers: HashSet<PeerId>,
    pub outbox: VecDeque<ProtocolBehaviourOut<VoidMessage, S>>,
    partitions: PP,
    creation_time: std::time::Instant,
    processing_delay: Duration,
    next_processing: Option<Pin<Box<tokio::time::Sleep>>>,
    multicasting_duration: Duration,
}

impl<S, P, PP> DagMulticasting<S, P, PP>
where
    PP: PeerPartitions + Send + Clone,
{
    pub fn new(
        statement: Option<S>,
        public_data: P,
        overlay: DagOverlay,
        config: DagMulticastingConfig,
        partitions: PP,
    ) -> Self {
        let parent_nodes: Vec<_> = overlay
            .parent_nodes
            .iter()
            .map(|id| partitions.try_index_peer(*id).unwrap())
            .collect();
        let children_nodes: Vec<_> = overlay
            .child_nodes
            .iter()
            .map(|(id, _)| partitions.try_index_peer(*id).unwrap())
            .collect();
        trace!(
            "Overlay info: parent_nodes: {:?}, children_nodes: {:?}",
            parent_nodes,
            children_nodes
        );
        Self {
            statement,
            public_data,
            overlay,
            contacted_peers: HashSet::new(),
            outbox: VecDeque::new(),
            partitions,
            creation_time: std::time::Instant::now(),
            processing_delay: config.processing_delay,
            multicasting_duration: config.multicasting_duration,
            next_processing: Some(Box::pin(tokio::time::sleep(config.processing_delay))),
        }
    }
}

impl<S, P, PP> TemporalProtocolStage<VoidMessage, S, S> for DagMulticasting<S, P, PP>
where
    S: CommutativePartialSemigroup + Weighted + VerifiableAgainst<P> + Clone,
    PP: PeerPartitions + Send + Clone,
{
    fn inject_message(&mut self, peer_id: PeerId, content: S) {
        if self.overlay.parent_nodes.contains(&peer_id) {
            if content.verify(&self.public_data) {
                if let Some(stmt) = self.statement.take() {
                    if let Some(combined) = stmt.try_combine(&content) {
                        if combined.weight() > stmt.weight() {
                            let previously_contacted_peers: Vec<_> = self
                                .contacted_peers
                                .iter()
                                .map(|id| self.partitions.try_index_peer(*id).unwrap())
                                .collect();
                            trace!(
                                "Got new broadcast contribution from {:?}. Previously contacted peers: {:?}",
                                self.partitions.try_index_peer(peer_id).unwrap(),
                                previously_contacted_peers,
                            );
                            // Since we have a new contribution, let's broadcast again through
                            // all nodes in the overlay.
                            self.contacted_peers.clear();
                        } else {
                            trace!(
                                "Got broadcast contribution from {:?} (nothing new)",
                                self.partitions.try_index_peer(peer_id).unwrap(),
                            );
                        }
                        let _ = self.statement.insert(combined);
                    }
                } else {
                    let _ = self.statement.insert(content);
                }
            } else {
                self.outbox
                    .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::BanPeer(
                        peer_id,
                    )));
            }
        }
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<Either<ProtocolBehaviourOut<VoidMessage, S>, S>> {
        if let Some(mut delay) = self.next_processing.take() {
            match delay.poll_unpin(cx) {
                Poll::Ready(_) => {}
                Poll::Pending => {
                    self.next_processing = Some(delay);
                    return Poll::Pending;
                }
            }
        }

        let finished_at = std::time::Instant::now();
        let elapsed = finished_at.sub(self.creation_time);
        if elapsed > self.multicasting_duration {
            if let Some(stmt) = self.statement.take() {
                return Poll::Ready(Right(stmt));
            }
        }

        if let Some(stmt) = &self.statement {
            for (peer, addr) in &self.overlay.child_nodes {
                if !self.contacted_peers.contains(peer) {
                    self.contacted_peers.insert(*peer);
                    self.outbox.push_back(ProtocolBehaviourOut::NetworkAction(
                        NetworkAction::SendOneShotMessage {
                            peer: *peer,
                            addr_hint: addr.clone(),
                            use_version: Default::default(),
                            message: stmt.clone(),
                        },
                    ));
                }
            }
        }
        if let Some(out) = self.outbox.pop_front() {
            self.next_processing = Some(Box::pin(tokio::time::sleep(self.processing_delay)));
            return Poll::Ready(Left(out));
        }

        self.next_processing = Some(Box::pin(tokio::time::sleep(self.processing_delay)));
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

#[derive(Copy, Clone)]
pub struct DagMulticastingConfig {
    pub processing_delay: Duration,
    pub multicasting_duration: Duration,
    pub redundancy_factor: usize,
    pub seed: u64,
}

struct ApplyStatement<S>(Verified<S>);

/// This type of multicasting supports async verification of statements.
pub struct DagMulticastingAsync<'a, S, P> {
    statement: Option<S>,
    public_data: Arc<P>,
    overlay: DagOverlay,
    contacted_peers: HashSet<PeerId>,
    outbox: VecDeque<ProtocolBehaviourOut<VoidMessage, S>>,
    from_tasks: Receiver<FromTask<ApplyStatement<S>, ProtocolBehaviourOut<VoidMessage, S>>>,
    tasks: TaskPool<'a, ApplyStatement<S>, ProtocolBehaviourOut<VoidMessage, S>, ()>,
}

const FROM_TASK_BUFFER_SIZE: usize = 1000;

impl<'a, S, P> DagMulticastingAsync<'a, S, P> {
    pub fn new(statement: Option<S>, public_data: P, overlay: DagOverlay, task_timeout: Duration) -> Self {
        let (snd, recv) = async_std::channel::bounded(FROM_TASK_BUFFER_SIZE);
        let tasks = TaskPool::new(String::from("MCast"), task_timeout, snd);
        Self {
            statement,
            public_data: Arc::new(public_data),
            overlay,
            contacted_peers: HashSet::new(),
            outbox: VecDeque::new(),
            from_tasks: recv,
            tasks,
        }
    }

    /// Apply verified statement
    fn on_apply_statement(&mut self, ApplyStatement(Verified(stmt)): ApplyStatement<S>) {
        if self.statement.is_none() {
            let _ = self.statement.insert(stmt);
        }
    }
}

impl<'a, S, P> TemporalProtocolStage<VoidMessage, S, S> for DagMulticastingAsync<'a, S, P>
where
    S: CommutativeSemigroup + AsyncVerifiable<P> + Clone + 'a,
    P: Send + Sync + 'a,
{
    fn inject_message(&mut self, peer_id: PeerId, content: S) {
        if self.overlay.parent_nodes.contains(&peer_id) {
            let pd = Arc::clone(&self.public_data);
            self.tasks.spawn(|to_behaviour| async move {
                if let Ok(ver) = content.verify(&pd).await {
                    to_behaviour
                        .send(FromTask::ToBehaviour(ApplyStatement(ver)))
                        .await
                        .unwrap();
                } else {
                    to_behaviour
                        .send(FromTask::ToHandler(ProtocolBehaviourOut::NetworkAction(
                            NetworkAction::BanPeer(peer_id),
                        )))
                        .await
                        .unwrap();
                }
            });
        }
    }

    fn poll(&mut self, cx: &mut Context) -> Poll<Either<ProtocolBehaviourOut<VoidMessage, S>, S>> {
        // First, let the tasks progress
        match Stream::poll_next(Pin::new(&mut self.tasks), cx) {
            Poll::Ready(Some(_)) => {}
            Poll::Pending | Poll::Ready(None) => {}
        }
        // Then, process their outputs
        match Stream::poll_next(Pin::new(&mut self.from_tasks), cx) {
            Poll::Ready(Some(out)) => match out {
                FromTask::ToBehaviour(input) => {
                    self.on_apply_statement(input);
                }
                FromTask::ToHandler(out) => {
                    self.outbox.push_back(out);
                }
            },
            Poll::Pending | Poll::Ready(None) => {}
        }
        if let Some(stmt) = &self.statement {
            for (peer, addr) in &self.overlay.child_nodes {
                if !self.contacted_peers.contains(peer) {
                    self.contacted_peers.insert(*peer);
                    self.outbox.push_back(ProtocolBehaviourOut::NetworkAction(
                        NetworkAction::SendOneShotMessage {
                            peer: *peer,
                            addr_hint: addr.clone(),
                            use_version: Default::default(),
                            message: stmt.clone(),
                        },
                    ))
                }
            }
        }
        if let Some(out) = self.outbox.pop_front() {
            return Poll::Ready(Left(out));
        }
        if let Some(stmt) = self.statement.take() {
            return Poll::Ready(Right(stmt));
        }
        return Poll::Pending;
    }
}

pub trait Multicasting<S>: TemporalProtocolStage<VoidMessage, S, S> {}

impl<S, P, PP> Multicasting<S> for DagMulticasting<S, P, PP>
where
    S: CommutativePartialSemigroup + Weighted + VerifiableAgainst<P> + Clone,
    PP: PeerPartitions + Send + Clone,
{
}
