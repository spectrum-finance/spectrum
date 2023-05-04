use std::collections::VecDeque;
use std::fmt::Debug;
use std::task::{Context, Poll};

use either::{Either, Right};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use algebra_core::CommutativeSemigroup;

use crate::protocol_handler::cosi::message::{CoSiHandshake, CoSiMessage, CoSiMessageV1};
use crate::protocol_handler::ProtocolBehaviourOut;
use crate::protocol_handler::TemporalProtocolStage;

pub mod message;

/// A behaviour that drives a single round of announcement.
/// Statement `S` is multicasted down the B-ary tree of nodes.
/// todo: make multicating more resilient by forwarding announcements via alternative nodes?
pub struct CoSiAnnouncementStage<S, R> {
    state: AnnouncementState<S>,
    outbox: VecDeque<ProtocolBehaviourOut<CoSiHandshake, CoSiMessage<S, R>>>,
}

pub enum IsNotified {
    Notified,
    NotNotified,
}

pub struct AnnouncementState<S> {
    statement: Option<S>,
    parent: Option<PeerId>,
    left_subtree: (PeerId, IsNotified),
    right_subtree: (PeerId, IsNotified),
}

/// It basically waits for an announcement and then forwards it to it's subtrees.
impl<'d, S, R> TemporalProtocolStage<CoSiHandshake, CoSiMessage<S, R>, S> for CoSiAnnouncementStage<S, R>
where
    S: Eq + Clone + Send + Serialize + Deserialize<'d> + Debug,
{
    fn inject_message(&mut self, peer_id: PeerId, msg: CoSiMessage<S, R>) {
        match msg {
            CoSiMessage::CoSiMessageV1(CoSiMessageV1::Announcement { statement }) => {
                if self.state.parent == Some(peer_id) && self.state.statement.is_none() {
                    self.state.statement = Some(statement);
                }
            }
            CoSiMessage::CoSiMessageV1(_) => {
                // todo: punish peer?
            }
        }
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Either<ProtocolBehaviourOut<CoSiHandshake, CoSiMessage<S, R>>, S>> {
        if let Some(statement) = self.state.statement.clone() {
            if let (peer_id, IsNotified::NotNotified) = self.state.left_subtree {
                self.outbox.push_back(ProtocolBehaviourOut::Send {
                    peer_id,
                    message: CoSiMessage::CoSiMessageV1(CoSiMessageV1::Announcement {
                        statement: statement.clone(),
                    }),
                });
                self.state.left_subtree.1 = IsNotified::Notified;
            }
            if let (peer_id, IsNotified::NotNotified) = self.state.right_subtree {
                self.outbox.push_back(ProtocolBehaviourOut::Send {
                    peer_id,
                    message: CoSiMessage::CoSiMessageV1(CoSiMessageV1::Announcement {
                        statement: statement.clone(),
                    }),
                });
                self.state.right_subtree.1 = IsNotified::Notified;
            }
            return Poll::Ready(Right(statement));
        }
        Poll::Pending
    }
}

/// A behaviour that drives response stage of signature aggregation.
pub struct CoSiResponseStage<S, R> {
    state: ResponseState<R>,
    outbox: VecDeque<ProtocolBehaviourOut<CoSiHandshake, CoSiMessage<S, R>>>,
}

pub struct ResponseState<R> {
    own_share: R,
    parent: Option<PeerId>,
    left_subtree: (PeerId, Option<R>),
    right_subtree: (PeerId, Option<R>),
    aggregate: Option<R>,
}

impl<'d, S, R> TemporalProtocolStage<CoSiHandshake, CoSiMessage<S, R>, R> for CoSiResponseStage<S, R>
where
    S: Eq + Clone + Send + Serialize + Deserialize<'d> + Debug,
    R: CommutativeSemigroup + Eq + Clone + Send + Serialize + Deserialize<'d> + Debug,
{
    fn inject_message(&mut self, peer_id: PeerId, content: CoSiMessage<S, R>) {
        match content {
            CoSiMessage::CoSiMessageV1(CoSiMessageV1::Response { response }) => {
                if self.state.left_subtree == (peer_id, None) {
                    self.state.left_subtree = (peer_id, Some(response));
                } else if self.state.right_subtree == (peer_id, None) {
                    self.state.right_subtree = (peer_id, Some(response));
                };
                if let (Some(left), Some(right)) = (&self.state.left_subtree.1, &self.state.right_subtree.1) {
                    self.state.aggregate = Some(self.state.own_share.clone().combine(&left.combine(&right)));
                }
            }
            CoSiMessage::CoSiMessageV1(CoSiMessageV1::Announcement { .. }) => {}
        }
    }

    fn poll(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Either<ProtocolBehaviourOut<CoSiHandshake, CoSiMessage<S, R>>, R>> {
        if let Some(aggr) = &self.state.aggregate {
            if let Some(peer_id) = &self.state.parent {
                self.outbox.push_back(ProtocolBehaviourOut::Send {
                    peer_id: peer_id.clone(),
                    message: CoSiMessage::CoSiMessageV1(CoSiMessageV1::Response {
                        response: aggr.clone(),
                    }),
                })
            }
            return Poll::Ready(Right(aggr.clone()));
        }
        Poll::Pending
    }
}
