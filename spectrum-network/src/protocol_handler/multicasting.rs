use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_std::channel::Receiver;
use either::{Either, Left, Right};
use futures::Stream;
use libp2p_identity::PeerId;

use algebra_core::{CommutativePartialSemigroup, CommutativeSemigroup};
use spectrum_crypto::{AsyncVerifiable, VerifiableAgainst, Verified};

use crate::protocol_handler::multicasting::overlay::DagOverlay;
use crate::protocol_handler::pool::{FromTask, TaskPool};
use crate::protocol_handler::void::VoidMessage;
use crate::protocol_handler::{NetworkAction, ProtocolBehaviourOut, TemporalProtocolStage};

pub mod overlay;

/// DAG based multicasting that accumulates received statements along the way.
pub struct DagMulticasting<S, P> {
    statement: Option<S>,
    public_data: P,
    overlay: DagOverlay,
    outbox: VecDeque<ProtocolBehaviourOut<VoidMessage, S>>,
}

impl<S, P> DagMulticasting<S, P> {
    pub fn new(statement: Option<S>, public_data: P, overlay: DagOverlay) -> Self {
        Self {
            statement,
            public_data,
            overlay,
            outbox: VecDeque::new(),
        }
    }
}

impl<S, P> TemporalProtocolStage<VoidMessage, S, S> for DagMulticasting<S, P>
where
    S: CommutativePartialSemigroup + VerifiableAgainst<P> + Clone,
{
    fn inject_message(&mut self, peer_id: PeerId, content: S) {
        if self.overlay.parent_nodes.contains(&peer_id) {
            if content.verify(&self.public_data) {
                if let Some(stmt) = self.statement.take() {
                    if let Some(combined) = stmt.try_combine(&content) {
                        let _ = self.statement.insert(combined);
                    }
                } else {
                    let _ = self.statement.insert(content);
                }
            } else {
                self.outbox
                    .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::BanPeer(
                        peer_id,
                    )))
            }
        }
    }

    fn poll(&mut self, _: &mut Context) -> Poll<Either<ProtocolBehaviourOut<VoidMessage, S>, S>> {
        if let Some(stmt) = &self.statement {
            for (peer, addr) in &self.overlay.child_nodes {
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
        if let Some(out) = self.outbox.pop_front() {
            return Poll::Ready(Left(out));
        }
        if let Some(stmt) = self.statement.take() {
            return Poll::Ready(Right(stmt));
        }
        return Poll::Pending;
    }
}

struct ApplyStatement<S>(Verified<S>);

/// This type of multicating supports async verification of statements.
pub struct DagMulticastingAsync<'a, S, P> {
    task_timeout: Duration,
    statement: Option<S>,
    public_data: Arc<P>,
    overlay: DagOverlay,
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
            task_timeout,
            statement,
            public_data: Arc::new(public_data),
            overlay,
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
        if let Some(out) = self.outbox.pop_front() {
            return Poll::Ready(Left(out));
        }
        if let Some(stmt) = self.statement.take() {
            return Poll::Ready(Right(stmt));
        }
        return Poll::Pending;
    }
}

pub trait Multicasting<'a, S>: TemporalProtocolStage<VoidMessage, S, S> + 'a {}

impl<'a, S, P> Multicasting<'a, S> for DagMulticasting<S, P>
where
    S: CommutativePartialSemigroup + VerifiableAgainst<P> + Clone + 'a,
    P: 'a,
{
}
