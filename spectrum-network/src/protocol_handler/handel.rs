use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::task::{Context, Poll};

use either::Either;
use libp2p::PeerId;
use void::Void;

use algebra_core::CommutativePartialSemigroup;
use spectrum_crypto::VerifiableAgainst;

use crate::protocol_handler::handel::message::{HandelMessage, HandelMessageV1};
use crate::protocol_handler::handel::partitioning::{PeerIx, PeerPartitions};
use crate::protocol_handler::{NetworkAction, ProtocolBehaviourOut, TemporalProtocolStage};

mod message;
mod partitioning;

pub trait Weighted {
    fn weight(&self) -> usize;
}

#[derive(Copy, Clone)]
pub struct Threshold {
    pub num: usize,
    pub denom: usize,
}

impl Threshold {
    pub fn min(&self, n: usize) -> usize {
        n * self.num / self.denom
    }
}

#[derive(Clone)]
struct ActiveLevel<C> {
    prioritized_contributions: Vec<PendingContribution<C>>,
    individual_contributions: Vec<Verified<C>>,
    best_contribution: Option<Verified<ScoredContribution<C>>>,
    /// Index of the peer we contacted last at the level.
    last_contacted_peer: Option<usize>,
}

impl<C> ActiveLevel<C> {
    fn new(best_contribution: Option<Verified<ScoredContribution<C>>>) -> Self {
        Self {
            prioritized_contributions: vec![],
            individual_contributions: vec![],
            last_contacted_peer: None,
            best_contribution,
        }
    }
    fn unit(contribution: C) -> Self {
        Self {
            prioritized_contributions: vec![],
            individual_contributions: vec![],
            last_contacted_peer: None,
            best_contribution: Some(Verified(ScoredContribution {
                score: 1,
                contribution,
            })),
        }
    }
}

#[derive(Copy, Clone)]
pub struct HandelConfig {
    pub threshold: Threshold,
    pub window_shrinking_factor: usize,
    pub initial_scoring_window: usize,
}

/// A round of Handel protocol that drives aggregation of contribution `C`.
pub struct Handel<C, P, PP> {
    conf: HandelConfig,
    public_data: P,
    scoring_window: usize,
    unverified_contributions: Vec<HashMap<PeerIx, PendingContribution<C>>>,
    peer_partitions: PP,
    levels: Vec<Option<ActiveLevel<C>>>,
    /// Keeps track of byzantine peers.
    byzantine_nodes: HashSet<PeerIx>,
    /// Keeps track of the peers to whom we've sent our own contribution already.
    own_contribution_recvs: HashSet<PeerIx>,
}

impl<C, P, PP> Handel<C, P, PP>
where
    C: CommutativePartialSemigroup + Weighted + VerifiableAgainst<P> + Eq + Clone,
    PP: PeerPartitions,
{
    pub fn new(conf: HandelConfig, own_contribution: C, public_data: P, peer_partitions: PP) -> Self {
        let num_levels = peer_partitions.num_levels();
        let mut levels = vec![None; num_levels];
        levels[0] = Some(ActiveLevel::unit(own_contribution));
        Handel {
            conf,
            public_data,
            scoring_window: conf.initial_scoring_window,
            unverified_contributions: vec![HashMap::new(); num_levels],
            peer_partitions,
            levels,
            byzantine_nodes: HashSet::new(),
            own_contribution_recvs: HashSet::new(),
        }
    }

    /// Run aggregation on the specified level.
    pub fn run_aggregation(&mut self, level: usize) {
        if let Some(lvl) = &mut self.levels[level] {
            // Prioritize contributions
            if !self.unverified_contributions[level].is_empty() {
                for pix in &self.peer_partitions.peers_at_level(level) {
                    if let Some(uc) = self.unverified_contributions[level].remove(pix) {
                        lvl.prioritized_contributions.push(uc);
                    }
                    if lvl.prioritized_contributions.len() >= self.scoring_window {
                        break;
                    }
                }
            }
            let best_contribution = lvl.best_contribution.clone().map(|Verified(vc)| vc.contribution);
            let mut scored_contributions: BTreeSet<ScoredContributionTraced<C>> = BTreeSet::new();
            while let Some(c) = lvl.prioritized_contributions.pop() {
                // Verify individual contribution first
                if let Some(ic) = c.individual_contribution {
                    if ic.verify(&self.public_data) {
                        lvl.individual_contributions.push(Verified(ic))
                    } else {
                        // Ban peer, shrink scoring window, skip scoring and
                        // verification of aggregate contribution from this peer.
                        self.byzantine_nodes.insert(c.sender_id);
                        self.scoring_window /= self.conf.window_shrinking_factor;
                        continue;
                    }
                }
                // Score aggregate contribution
                match best_contribution
                    .as_ref()
                    .map(|bc| bc.try_combine(&c.aggregate_contribution))
                {
                    Some(Some(aggr)) => {
                        let score = aggr.weight();
                        scored_contributions.insert(ScoredContributionTraced {
                            score,
                            sender_id: c.sender_id,
                            contribution: aggr,
                        });
                    }
                    Some(_) | None => {
                        let mut acc_aggr = c.aggregate_contribution.clone();
                        for Verified(ic) in &lvl.individual_contributions {
                            if let Some(aggr) = acc_aggr.try_combine(&ic) {
                                acc_aggr = aggr;
                            }
                        }
                        let score = acc_aggr.weight();
                        scored_contributions.insert(ScoredContributionTraced {
                            score,
                            sender_id: c.sender_id,
                            contribution: acc_aggr,
                        });
                    }
                }
            }
            // Verify aggregate contributions
            for sc in scored_contributions.into_iter() {
                if sc.contribution.verify(&self.public_data) {
                    if let Some(Verified(best_contrib)) = &lvl.best_contribution {
                        if sc.score > best_contrib.score {
                            lvl.best_contribution = Some(Verified(sc.into()))
                        }
                    } else {
                        lvl.best_contribution = Some(Verified(sc.into()))
                    }
                } else {
                    // Ban peer, shrink scoring window.
                    self.byzantine_nodes.insert(sc.sender_id);
                    self.scoring_window /= self.conf.window_shrinking_factor
                }
            }
        }
    }

    pub fn inject_contribution(
        &mut self,
        peer_id: PeerId,
        level: u32,
        aggregate_contribution: C,
        individual_contribution: Option<C>,
    ) -> Result<(), ()> {
        if let Some(peer_ix) = self.peer_partitions.try_index_peer(peer_id) {
            if !self.byzantine_nodes.contains(&peer_ix) {
                let contrib = PendingContribution {
                    sender_id: peer_ix,
                    aggregate_contribution,
                    individual_contribution,
                };
                self.unverified_contributions[level as usize].insert(peer_ix, contrib);
                return Ok(());
            }
        }
        Err(())
    }

    pub fn next_dissimination(&mut self) -> Vec<(PeerId, HandelMessage<C>)> {
        let own_contrib = self.levels[0]
            .as_ref()
            .and_then(|l| l.best_contribution.as_ref().map(|c| c.0.contribution.clone()));
        let mut messages = vec![];
        for (lix, lvl) in &mut self.levels.iter_mut().enumerate() {
            if let Some(active_lvl) = lvl {
                let peers_at_level = self.peer_partitions.peers_at_level(lix);
                let maybe_next_peer = active_lvl
                    .last_contacted_peer
                    .and_then(|i| peers_at_level.get(i + 1));
                let next_peer_ix = if let Some(next_peer) = maybe_next_peer {
                    active_lvl.last_contacted_peer = active_lvl.last_contacted_peer.map(|i| i + 1);
                    *next_peer
                } else {
                    active_lvl.last_contacted_peer = Some(0);
                    self.peer_partitions.peers_at_level(lix)[0]
                };
                let next_peer = self.peer_partitions.identify_peer(next_peer_ix);
                let maybe_own_contrib = if !self.own_contribution_recvs.contains(&next_peer_ix) {
                    own_contrib.clone()
                } else {
                    None
                };
                if let Some(Verified(best_contrib)) = active_lvl.best_contribution.clone() {
                    messages.push((
                        next_peer,
                        HandelMessage::HandelMessageV1(HandelMessageV1 {
                            level: lix as u32,
                            individual_contribution: maybe_own_contrib,
                            aggregate_contribution: best_contrib.contribution,
                            contact_sender: false,
                        }),
                    ));
                }
            }
        }
        messages
    }

    fn is_complete(&self, contribution: &C, level: usize) -> bool {
        let weight = contribution.weight();
        let num_nodes_at_level = (2 as usize).pow(level as u32);
        let threshold = self.conf.threshold.min(num_nodes_at_level);
        weight >= threshold
    }
}

#[derive(Clone, Debug)]
struct PendingContribution<C> {
    sender_id: PeerIx,
    aggregate_contribution: C,
    individual_contribution: Option<C>,
}

#[derive(Eq, PartialEq, Clone)]
struct ScoredContributionTraced<C> {
    score: usize,
    sender_id: PeerIx,
    contribution: C,
}

#[derive(Eq, PartialEq, Clone)]
struct ScoredContribution<C> {
    score: usize,
    contribution: C,
}

impl<C> From<ScoredContributionTraced<C>> for ScoredContribution<C> {
    fn from(sct: ScoredContributionTraced<C>) -> Self {
        Self {
            score: sct.score,
            contribution: sct.contribution,
        }
    }
}

impl<C: PartialEq> PartialOrd for ScoredContributionTraced<C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.score.partial_cmp(&other.score)
    }
}

impl<C: Eq> Ord for ScoredContributionTraced<C> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score.cmp(&other.score)
    }
}

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone)]
struct Verified<C>(C);

pub struct HandelProtocol<C, P, PP> {
    handel: Handel<C, P, PP>,
    outbox: VecDeque<ProtocolBehaviourOut<Void, HandelMessage<C>>>,
}

impl<C, P, PP> TemporalProtocolStage<Void, HandelMessage<C>, C> for HandelProtocol<C, P, PP>
where
    C: CommutativePartialSemigroup + Weighted + VerifiableAgainst<P> + Clone + Eq,
    PP: PeerPartitions,
{
    fn inject_message(&mut self, peer_id: PeerId, HandelMessage::HandelMessageV1(msg): HandelMessage<C>) {
        if self
            .handel
            .inject_contribution(
                peer_id,
                msg.level,
                msg.aggregate_contribution,
                msg.individual_contribution,
            )
            .is_err()
        {
            self.outbox
                .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::BanPeer(
                    peer_id,
                )));
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Either<ProtocolBehaviourOut<Void, HandelMessage<C>>, C>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::protocol_handler::handel::Weighted;

    struct Contrib(HashSet<u32>);

    impl Weighted for Contrib {
        fn weight(&self) -> usize {
            self.0.len()
        }
    }
}
