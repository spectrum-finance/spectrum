use std::ops::Index;
use std::task::{Context, Poll};

use either::Either;
use libp2p::PeerId;
use void::Void;

use algebra_core::{CommutativePartialSemigroup, CommutativeSemigroup};
use spectrum_crypto::VerifiableAgainst;

use crate::protocol_handler::handel::message::HandelMessage;
use crate::protocol_handler::{ProtocolBehaviourOut, TemporalProtocolStage};

mod message;

/// A round of Handel protocol that drives aggregation of contribution `C`.
pub struct Handel<C, P> {
    state: HandelState<C>,
    individual_contribution: C,
    verification_prop: P,
    peers: Vec<PeerId>,
}

type PeerIx = u32;

pub trait Weighted {
    fn weight(&self) -> u32;
}

pub struct HandelState<C> {
    window_size: u32,
    contribution_prioritization_vector: Vec<Vec<PeerIx>>,
    best_incoming_aggregate_contribution: Vec<Option<ScoredContribution<C>>>,
    best_outgoing_aggregate_contribution: Vec<Option<ScoredContribution<C>>>,
    /// `individual_verified_contributions[l]` denotes all verified individual contributions received by other nodes at level `l`.
    individual_verified_contributions: Vec<Vec<(PeerIx, C)>>,
    /// `verification_priorities[l][j]` represents the Handel node id with `j'th` priority rank, at level `l`.
    verification_priorities: Vec<Vec<PeerIx>>,
    unverified_contributions: Vec<Vec<UnverifiedContribution<C>>>,
    incoming_level_status: Vec<LevelStatus>,
    byzantine_nodes: Vec<PeerIx>,
}

impl<C, P> Handel<C, P>
where
    C: CommutativePartialSemigroup + Weighted + VerifiableAgainst<P> + Clone,
{
    pub fn try_verify(&mut self, level: usize) {
        let mut ranked_contributions = vec![];
        for &node_ix in &self.state.verification_priorities[level] {
            if let Some(pos) = self.state.unverified_contributions[level]
                .iter()
                .position(|uc| uc.sender_ix == node_ix)
            {
                let uc = self.state.unverified_contributions[level].swap_remove(pos);
                ranked_contributions.push(uc);
            }
            if ranked_contributions.len() as u32 == self.state.window_size {
                break;
            }
        }

        // Now find the highest scored contribution
        if !ranked_contributions.is_empty() {
            let mut best_contribution = ranked_contributions.pop().unwrap();
            let mut best_score = self.score_contribution(&best_contribution.aggregate_contribution, level);
            for rc in ranked_contributions {
                let score = self.score_contribution(&rc.aggregate_contribution, level);
                if score > best_score {
                    best_score = score;
                    best_contribution = rc;
                }
            }

            // If both aggregate and individual contributions are verified
            if best_contribution
                .aggregate_contribution
                .verify(&self.verification_prop)
                && best_contribution
                    .individual_contribution
                    .verify(&self.verification_prop)
            {
                // Update best incoming aggregate contribution, if needed
                if let Some(ref b) = self.state.best_incoming_aggregate_contribution[level] {
                    if b.score < best_score {
                        self.state.best_incoming_aggregate_contribution[level] = Some(ScoredContribution {
                            score: best_score,
                            contribution: best_contribution.aggregate_contribution,
                        });
                    }
                } else {
                    self.state.best_incoming_aggregate_contribution[level] = Some(ScoredContribution {
                        score: best_score,
                        contribution: best_contribution.aggregate_contribution,
                    });
                }

                // Update incoming individual contribution,
                if let Some(pos) = self.state.individual_verified_contributions[level]
                    .iter()
                    .position(|&(node_id, _)| node_id == best_contribution.sender_ix)
                {
                    self.state.individual_verified_contributions[level][pos] = (
                        best_contribution.sender_ix,
                        best_contribution.individual_contribution,
                    );
                } else {
                    self.state.individual_verified_contributions[level].push((
                        best_contribution.sender_ix,
                        best_contribution.individual_contribution,
                    ));
                }

                // Update incoming level status
                match self.state.incoming_level_status[level] {
                    LevelStatus::Complete => {
                        unreachable!()
                    }
                    LevelStatus::Incomplete(ref node_ids) => {
                        if !node_ids.contains(&best_contribution.sender_ix) {
                            let mut new_node_ids = node_ids.clone();
                            new_node_ids.push(best_contribution.sender_ix);
                            if (new_node_ids.len() as u32)
                                < self.state.verification_priorities[level].len() as u32
                            {
                                self.state.incoming_level_status[level] =
                                    LevelStatus::Incomplete(new_node_ids);
                            } else {
                                self.state.incoming_level_status[level] = LevelStatus::Complete;

                                // Have new outgoing aggregate contribution
                            }
                        }
                    }
                }
            } else {
                // Otherwise sender is flagged as Byzantine, prune contributions
                self.state.byzantine_nodes.push(best_contribution.sender_ix);
                while let Some(pos) = self.state.individual_verified_contributions[level]
                    .iter()
                    .position(|&(node_id, _)| node_id == best_contribution.sender_ix)
                {
                    self.state.individual_verified_contributions[level].swap_remove(pos);
                }
            }
        }
    }

    pub fn score_contribution(&self, aggregate_contribution: &C, level: usize) -> u32 {
        if let Some(ref c) = self.state.best_incoming_aggregate_contribution[level] {
            if let Some(agg) = c.contribution.try_combine(aggregate_contribution) {
                return agg.weight();
            } else if level > 0 {
                let mut acc: Option<C> = None;
                for (_, c) in self.state.individual_verified_contributions[level]
                    .iter()
                    .cloned()
                {
                    if let Some(a) = &acc {
                        if let Some(combined) = a.try_combine(&c) {
                            acc = Some(combined.clone());
                        }
                    } else {
                        acc = Some(c);
                    }
                }
            }
        }
        0
    }
}

struct UnverifiedContribution<C> {
    sender_ix: PeerIx,
    aggregate_contribution: C,
    individual_contribution: C,
}

struct ScoredContribution<C> {
    score: u32,
    contribution: C,
}

#[derive(PartialEq, Eq)]
enum LevelStatus {
    Complete,
    // The node ids who've contributed to the level
    Incomplete(Vec<u32>),
}

impl<C, P> TemporalProtocolStage<Void, HandelMessage<C>, C> for Handel<C, P>
where
    C: CommutativePartialSemigroup + Weighted + VerifiableAgainst<P> + Clone,
{
    fn inject_message(&mut self, peer_id: PeerId, HandelMessage::HandelMessageV1(msg): HandelMessage<C>) {
        let peer_ix = self.peers.iter().position(|p| p == &peer_id).unwrap() as u32; // todo
        if self.state.incoming_level_status[msg.level as usize] == LevelStatus::Complete
            || self.state.byzantine_nodes.contains(&peer_ix)
        {
            return;
        }

        if let Some(pos) = self.state.unverified_contributions[msg.level as usize]
            .iter()
            .position(|UnverifiedContribution { sender_ix, .. }| *sender_ix == peer_ix)
        {
            self.state.unverified_contributions[msg.level as usize][pos] = UnverifiedContribution {
                sender_ix: peer_ix,
                aggregate_contribution: msg.aggregate_contribution,
                individual_contribution: msg.individual_contribution,
            };
        } else {
            self.state.unverified_contributions[msg.level as usize].push(UnverifiedContribution {
                sender_ix: peer_ix,
                aggregate_contribution: msg.aggregate_contribution,
                individual_contribution: msg.individual_contribution,
            });
        }

        self.try_verify(msg.level as usize);
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Either<ProtocolBehaviourOut<Void, HandelMessage<C>>, C>> {
        todo!()
    }
}
