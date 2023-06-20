use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_std::channel::Receiver;
use either::{Either, Left, Right};
use futures::Stream;
use libp2p_identity::PeerId;

use algebra_core::CommutativeSemigroup;
use spectrum_crypto::{AsyncVerifiable, VerifiableAgainst, Verified};

use crate::protocol_handler::multicasting::overlay::TreeOverlay;
use crate::protocol_handler::pool::{FromTask, TaskPool};
use crate::protocol_handler::void::VoidMessage;
use crate::protocol_handler::{NetworkAction, ProtocolBehaviourOut, TemporalProtocolStage};

mod overlay;

struct ApplyStatement<S>(Verified<S>);

type MCastOut<S> = ProtocolBehaviourOut<VoidMessage, S>;

pub struct MCastConfig {
    /// Try to collect more stements from different peers.
    /// Finish when any statement is received if `false`.
    collect_more: bool,
    task_timeout: Duration,
}

pub struct TreeBasedMulticasting<'a, S, P> {
    conf: MCastConfig,
    statement: Option<S>,
    public_data: Arc<P>,
    overlay: TreeOverlay,
    notified_nodes: HashSet<PeerId>,
    outbox: VecDeque<ProtocolBehaviourOut<VoidMessage, S>>,
    from_tasks: Receiver<FromTask<ApplyStatement<S>, MCastOut<S>>>,
    tasks: TaskPool<'a, ApplyStatement<S>, MCastOut<S>, ()>,
}

const FROM_TASK_BUFFER_SIZE: usize = 1000;

impl<'a, S, P> TreeBasedMulticasting<'a, S, P>
where
    S: CommutativeSemigroup,
{
    pub fn new(statement: Option<S>, public_data: P, overlay: TreeOverlay, conf: MCastConfig) -> Self {
        let (snd, recv) = async_std::channel::bounded(FROM_TASK_BUFFER_SIZE);
        let tasks = TaskPool::new(String::from("MCast"), conf.task_timeout, snd);
        Self {
            conf,
            statement,
            public_data: Arc::new(public_data),
            overlay,
            notified_nodes: HashSet::new(),
            outbox: VecDeque::new(),
            from_tasks: recv,
            tasks,
        }
    }

    /// Apply verified statement
    fn on_apply_statement(&mut self, ApplyStatement(Verified(extension)): ApplyStatement<S>) {
        if let Some(stmt) = &self.statement {
            let _ = self.statement.insert(stmt.combine(&extension));
        }
    }
}

impl<'a, S, P> TemporalProtocolStage<VoidMessage, S, S> for TreeBasedMulticasting<'a, S, P>
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
        loop {
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
                        if self.conf.collect_more {
                            continue;
                        }
                    }
                    FromTask::ToHandler(out) => {
                        self.outbox.push_back(out);
                    }
                },
                Poll::Pending | Poll::Ready(None) => {}
            }
            if let Some(stmt) = self.statement.take() {
                for (peer, addr) in &self.overlay.child_nodes {
                    if !self.notified_nodes.contains(peer) {
                        self.notified_nodes.insert(*peer);
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
}
