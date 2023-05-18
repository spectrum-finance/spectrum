use std::cmp::{max, Ordering};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::ops::{Add, Mul};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use either::{Either, Left, Right};
use libp2p::PeerId;

use algebra_core::CommutativePartialSemigroup;
use spectrum_crypto::VerifiableAgainst;

use crate::protocol_handler::handel::message::HandelMessage;
use crate::protocol_handler::handel::partitioning::{PeerIx, PeerOrd, PeerPartitions};
use crate::protocol_handler::void::VoidMessage;
use crate::protocol_handler::{NetworkAction, ProtocolBehaviourOut, TemporalProtocolStage};
use crate::types::ProtocolVer;

pub mod message;
pub mod partitioning;

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

#[derive(Clone, Debug)]
struct ActiveLevel<C> {
    prioritized_contributions: Vec<PendingContribution<C>>,
    individual_contributions: Vec<Verified<C>>,
    best_contribution: Verified<ScoredContribution<C>>,
    /// Index of the peer we contacted last at the level.
    last_contacted_peer_ix: Option<usize>,
    /// Scores of contributions we shared with peers at this level.
    sent_contribution_scores: Vec<usize>,
    is_completed: bool,
}

impl<C> ActiveLevel<C> {
    fn new(best_contribution: Verified<ScoredContribution<C>>, num_nodes_at_level: usize) -> Self {
        Self {
            prioritized_contributions: vec![],
            individual_contributions: vec![],
            best_contribution,
            last_contacted_peer_ix: None,
            sent_contribution_scores: vec![0; num_nodes_at_level],
            is_completed: false,
        }
    }

    fn unit(contribution: Verified<ScoredContribution<C>>) -> Self {
        Self {
            prioritized_contributions: vec![],
            individual_contributions: vec![],
            best_contribution: contribution,
            last_contacted_peer_ix: None,
            sent_contribution_scores: vec![0],
            is_completed: true,
        }
    }

    fn completed(&mut self) {
        self.is_completed = true;
    }
}

#[derive(Copy, Clone)]
pub struct HandelConfig {
    pub threshold: Threshold,
    pub window_shrinking_factor: usize,
    pub initial_scoring_window: usize,
    pub fast_path_window: usize,
    pub dissemination_interval: Duration,
    pub level_activation_delay: Duration,
}

#[derive(Copy, Clone, Debug)]
pub struct HandelProgress {
    num_verified: u32,
    num_failed: u32,
}

impl HandelProgress {
    pub fn new() -> Self {
        Self {
            num_verified: 0,
            num_failed: 0,
        }
    }
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
    outbox: VecDeque<ProtocolBehaviourOut<VoidMessage, HandelMessage<C>>>,
    next_dissemination_at: Instant,
    level_activation_schedule: Vec<Option<Instant>>,
    progress: HandelProgress,
}

impl<C, P, PP> Handel<C, P, PP>
where
    C: CommutativePartialSemigroup + Weighted + VerifiableAgainst<P> + Eq + Clone + Debug,
    PP: PeerPartitions,
{
    pub fn new(conf: HandelConfig, own_contribution: C, public_data: P, peer_partitions: PP) -> Self {
        let num_levels = peer_partitions.num_levels();
        let mut levels = vec![None; num_levels];
        let own_contribution_scored = Verified(ScoredContribution {
            score: 1,
            contribution: own_contribution,
        });
        levels[0] = Some(ActiveLevel::unit(own_contribution_scored.clone()));
        levels[1] = Some(ActiveLevel::new(own_contribution_scored, 1));
        let now = Instant::now();
        Handel {
            conf,
            public_data,
            scoring_window: conf.initial_scoring_window,
            unverified_contributions: vec![HashMap::new(); num_levels],
            peer_partitions,
            levels,
            byzantine_nodes: HashSet::new(),
            own_contribution_recvs: HashSet::new(),
            outbox: VecDeque::new(),
            next_dissemination_at: now,
            level_activation_schedule: vec![(); num_levels]
                .into_iter()
                .enumerate()
                .map(|(i, _)| {
                    if i > 1 {
                        Some(now.add(conf.level_activation_delay.mul(i as u32)))
                    } else {
                        // 0'th and 1'st levels are already activated.
                        None
                    }
                })
                .collect(),
            progress: HandelProgress::new(),
        }
    }

    fn try_disseminatate(&mut self) {
        let now = Instant::now();
        if now >= self.next_dissemination_at {
            self.run_dissemination();
            self.next_dissemination_at = now.add(self.conf.dissemination_interval);
        }
    }

    fn try_activate_levels(&mut self) {
        let now = Instant::now();
        for (lvl, schedule) in self.level_activation_schedule.clone().into_iter().enumerate() {
            if let Some(ts) = schedule {
                if ts <= now {
                    self.try_activate_level(lvl);
                    self.level_activation_schedule[lvl] = None;
                } else {
                    break;
                }
            }
        }
    }

    /// Run aggregation on the specified level.
    fn run_aggregation(&mut self, level: usize) {
        if let Some(lvl) = &mut self.levels[level] {
            // Prioritize contributions
            if !self.unverified_contributions[level].is_empty() {
                for pix in &self.peer_partitions.peers_at_level(level, PeerOrd::VP) {
                    if let Some(uc) = self.unverified_contributions[level].remove(pix) {
                        lvl.prioritized_contributions.push(uc);
                    }
                    if lvl.prioritized_contributions.len() >= self.scoring_window {
                        break;
                    }
                }
            } else {
                return;
            }
            let Verified(best_contribution) = lvl.best_contribution.clone();
            let mut scored_contributions: BTreeSet<ScoredContributionTraced<C>> = BTreeSet::new();
            while let Some(c) = lvl.prioritized_contributions.pop() {
                // Verify individual contribution first
                if let Some(ic) = c.individual_contribution {
                    if ic.verify(&self.public_data) {
                        self.progress.num_verified += 1;
                        lvl.individual_contributions.push(Verified(ic));
                    } else {
                        // Ban peer, shrink scoring window, skip scoring and
                        // verification of aggregate contribution from this peer.
                        self.progress.num_failed += 1;
                        self.byzantine_nodes.insert(c.sender_id);
                        let shrinked_window = self
                            .scoring_window
                            .saturating_div(self.conf.window_shrinking_factor);
                        self.scoring_window = max(shrinked_window, 1);
                        continue;
                    }
                }
                // Score aggregate contribution
                match best_contribution
                    .contribution
                    .try_combine(&c.aggregate_contribution)
                {
                    Some(aggr) => {
                        let score = aggr.weight();
                        scored_contributions.insert(ScoredContributionTraced {
                            score,
                            sender_id: c.sender_id,
                            contribution: aggr,
                        });
                    }
                    None => {
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
                    self.progress.num_verified += 1;
                    let Verified(best_contrib) = &lvl.best_contribution;
                    if sc.score > best_contrib.score {
                        lvl.best_contribution = Verified(sc.into());
                    }
                    self.scoring_window = self
                        .scoring_window
                        .saturating_mul(self.conf.window_shrinking_factor);
                } else {
                    // Ban peer, shrink scoring window.
                    self.progress.num_failed += 1;
                    self.byzantine_nodes.insert(sc.sender_id);
                    let shrinked_window = self
                        .scoring_window
                        .saturating_div(self.conf.window_shrinking_factor);
                    self.scoring_window = max(shrinked_window, 1);
                }
            }
            let Verified(best_contrib) = &lvl.best_contribution;
            if is_complete(&best_contrib.contribution, level, self.conf.threshold) {
                lvl.completed();
                self.run_fast_path(level);
                self.try_activate_level(level + 1);
            }
        }
    }

    /// Activates the given level (if possible).
    fn try_activate_level(&mut self, level: usize) {
        if self.levels.get(level).is_some() {
            if !self.is_active(level) {
                if let Some(prev_level) = self.levels[level - 1].as_ref() {
                    let peers_at_level = self.peer_partitions.peers_at_level(level, PeerOrd::VP);
                    if peers_at_level.is_empty() {
                        // This level is empty, skip it
                        self.levels[level] = Some(ActiveLevel::unit(prev_level.best_contribution.clone()));
                        self.try_activate_level(level + 1);
                    } else {
                        self.levels[level] = Some(ActiveLevel::new(
                            prev_level.best_contribution.clone(),
                            peers_at_level.len(),
                        ))
                    }
                }
            }
        }
    }

    fn handle_contribution(
        &mut self,
        peer_id: PeerId,
        level: u32,
        aggregate_contribution: C,
        individual_contribution: Option<C>,
    ) -> Result<(), ()> {
        if let Some(peer_ix) = self.peer_partitions.try_index_peer(peer_id) {
            let is_byzantine = self.byzantine_nodes.contains(&peer_ix);
            let level_uncompleted = !self.levels[level as usize]
                .as_ref()
                .map(|lvl| lvl.is_completed)
                .unwrap_or(false);
            if !is_byzantine && level_uncompleted {
                let contrib = PendingContribution {
                    sender_id: peer_ix,
                    aggregate_contribution,
                    individual_contribution,
                };
                self.unverified_contributions[level as usize].insert(peer_ix, contrib);
                Ok(())
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }

    fn run_fast_path(&mut self, level: usize) {
        let own_contrib = self.levels[0]
            .as_ref()
            .map(|l| l.best_contribution.0.contribution.clone());
        if let Some(lvl) = &mut self.levels[level] {
            assert!(lvl.is_completed);
            let offset = lvl.last_contacted_peer_ix.map(|x| x + 1).unwrap_or(0);
            let nodes_at_level = self.peer_partitions.peers_at_level(level, PeerOrd::CVP);
            let indexes = (0..self.conf.fast_path_window)
                .map(|ix| (ix + offset) % nodes_at_level.len())
                .collect::<Vec<_>>();
            let nodes = indexes
                .into_iter()
                .map(|ix| nodes_at_level[ix])
                .collect::<Vec<_>>();
            for pix in nodes {
                let pid = self.peer_partitions.identify_peer(pix);
                let maybe_own_contrib = if !self.own_contribution_recvs.contains(&pix) {
                    own_contrib.clone()
                } else {
                    None
                };
                let Verified(best_contrib) = lvl.best_contribution.clone();
                self.outbox.push_back(ProtocolBehaviourOut::NetworkAction(
                    NetworkAction::SendOneShotMessage {
                        peer: pid,
                        addr_hint: self.peer_partitions.addr_hint(pid),
                        use_version: ProtocolVer::default(),
                        message: HandelMessage {
                            level: level as u32,
                            individual_contribution: maybe_own_contrib,
                            aggregate_contribution: best_contrib.contribution,
                            contact_sender: false,
                        },
                    },
                ));
            }
        }
    }

    /// Sends messages for one node from each active level.
    fn run_dissemination(&mut self) {
        let own_contrib = self.get_own_contribution();
        for (lix, lvl) in &mut self.levels.iter_mut().enumerate().skip(1) {
            if let Some(active_lvl) = lvl {
                let peers_at_level = self.peer_partitions.peers_at_level(lix, PeerOrd::CVP);
                let maybe_next_peer = active_lvl
                    .last_contacted_peer_ix
                    .and_then(|i| peers_at_level.get(i + 1));
                let next_peer_ix_within_level = active_lvl.last_contacted_peer_ix.unwrap_or(0);
                let next_peer_ix = if let Some(next_peer) = maybe_next_peer {
                    active_lvl.last_contacted_peer_ix = active_lvl.last_contacted_peer_ix.map(|i| i + 1);
                    *next_peer
                } else {
                    active_lvl.last_contacted_peer_ix = Some(0);
                    peers_at_level[0]
                };
                let next_peer = self.peer_partitions.identify_peer(next_peer_ix);
                let maybe_own_contrib = if !self.own_contribution_recvs.contains(&next_peer_ix) {
                    Some(own_contrib.clone())
                } else {
                    None
                };
                let Verified(best_contrib) = active_lvl.best_contribution.clone();
                if active_lvl.sent_contribution_scores[next_peer_ix_within_level] < best_contrib.score {
                    active_lvl.sent_contribution_scores[next_peer_ix_within_level] = best_contrib.score;
                    self.outbox.push_back(ProtocolBehaviourOut::NetworkAction(
                        NetworkAction::SendOneShotMessage {
                            peer: next_peer,
                            addr_hint: self.peer_partitions.addr_hint(next_peer),
                            use_version: ProtocolVer::default(),
                            message: HandelMessage {
                                level: lix as u32,
                                individual_contribution: maybe_own_contrib,
                                aggregate_contribution: best_contrib.contribution,
                                contact_sender: false,
                            },
                        },
                    ));
                }
            }
        }
    }

    fn best_contribution(&self) -> C {
        let mut levels = self.levels.iter();
        let mut best_contrib = self.get_own_contribution();
        while let Some(Some(ActiveLevel {
            best_contribution: Verified(best_contrib_at_level),
            ..
        })) = levels.next()
        {
            best_contrib = best_contrib_at_level.clone().contribution;
        }
        best_contrib
    }

    /// Get complete aggregate (if available) containing at least `threshold` total contributions.
    fn get_complete_aggregate(&self) -> Option<C> {
        if let Some(last_level) = &self.levels[self.levels.len() - 1] {
            if last_level.is_completed {
                return Some(last_level.clone().best_contribution.0.contribution);
            }
        }
        None
    }

    fn is_active(&self, level: usize) -> bool {
        self.levels.get(level).map(|l| l.is_some()).unwrap_or(false)
    }

    fn get_own_contribution(&self) -> C {
        self.levels[0]
            .as_ref()
            .map(|l| l.best_contribution.0.contribution.clone())
            .unwrap()
    }
}

fn is_complete<C: Weighted>(contribution: &C, level: usize, threshold: Threshold) -> bool {
    let weight = contribution.weight();
    let max_score_at_level = (2 as usize).pow(level as u32);
    let threshold = threshold.min(max_score_at_level);
    weight >= threshold
}

#[derive(Clone, Debug)]
struct PendingContribution<C> {
    sender_id: PeerIx,
    aggregate_contribution: C,
    individual_contribution: Option<C>,
}

#[derive(Eq, PartialEq, Clone, Debug)]
struct ScoredContributionTraced<C> {
    score: usize,
    sender_id: PeerIx,
    contribution: C,
}

#[derive(Eq, PartialEq, Clone, Debug)]
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

#[derive(Ord, PartialOrd, Eq, PartialEq, Clone, Debug)]
struct Verified<C>(C);

impl<C, P, PP> TemporalProtocolStage<VoidMessage, HandelMessage<C>, C> for Handel<C, P, PP>
where
    C: CommutativePartialSemigroup + Weighted + VerifiableAgainst<P> + Clone + Eq + Debug,
    PP: PeerPartitions,
{
    fn inject_message(&mut self, peer_id: PeerId, msg: HandelMessage<C>) {
        if self
            .handle_contribution(
                peer_id,
                msg.level,
                msg.aggregate_contribution,
                msg.individual_contribution,
            )
            .is_ok()
        {
            //println!("[Handel] run_aggregation @ level {}", msg.level);
            self.run_aggregation(msg.level as usize);
        } else {
            self.outbox
                .push_back(ProtocolBehaviourOut::NetworkAction(NetworkAction::BanPeer(
                    peer_id,
                )));
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Either<ProtocolBehaviourOut<VoidMessage, HandelMessage<C>>, C>> {
        self.try_disseminatate();
        self.try_activate_levels();
        if let Some(ca) = self.get_complete_aggregate() {
            return Poll::Ready(Right(ca));
        }
        if let Some(out) = self.outbox.pop_front() {
            return Poll::Ready(Left(out));
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

pub trait NarrowTo<T> {
    fn narrow(self: Box<Self>) -> T;
}

impl<C, P, PP> NarrowTo<PP> for Handel<C, P, PP> {
    fn narrow(self: Box<Self>) -> PP {
        self.peer_partitions
    }
}

pub trait HandelRound<'a, C, PP>:
    TemporalProtocolStage<VoidMessage, HandelMessage<C>, C> + NarrowTo<PP> + 'a
{
}

impl<'a, C, P, PP> HandelRound<'a, C, PP> for Handel<C, P, PP>
where
    C: CommutativePartialSemigroup + Weighted + VerifiableAgainst<P> + Clone + Eq + Debug + 'a,
    PP: PeerPartitions + 'a,
    P: 'a,
{
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use libp2p::{Multiaddr, PeerId};

    use algebra_core::CommutativePartialSemigroup;
    use spectrum_crypto::VerifiableAgainst;

    use crate::protocol_handler::handel::partitioning::tests::FakePartitions;
    use crate::protocol_handler::handel::partitioning::{
        BinomialPeerPartitions, PeerOrd, PeerPartitions, PseudoRandomGenPerm,
    };
    use crate::protocol_handler::handel::{Handel, HandelConfig, Threshold, Weighted};

    #[derive(Clone, Eq, PartialEq, Debug)]
    struct Contrib(HashSet<u32>);

    impl Weighted for Contrib {
        fn weight(&self) -> usize {
            self.0.len()
        }
    }

    impl CommutativePartialSemigroup for Contrib {
        fn try_combine(&self, that: &Self) -> Option<Self> {
            Some(Self(self.0.union(&that.0).copied().collect()))
        }
    }

    impl VerifiableAgainst<()> for Contrib {
        fn verify(&self, proposition: &()) -> bool {
            true
        }
    }

    const CONF: HandelConfig = HandelConfig {
        threshold: Threshold { num: 2, denom: 3 },
        window_shrinking_factor: 2,
        initial_scoring_window: 4,
        fast_path_window: 4,
        dissemination_interval: Duration::from_millis(2000),
        level_activation_delay: Duration::from_millis(400),
    };

    fn make_handel(
        own_peer: PeerId,
        peers: Vec<(PeerId, Option<Multiaddr>)>,
        contrib: Contrib,
    ) -> Handel<Contrib, (), BinomialPeerPartitions<PseudoRandomGenPerm>> {
        let rng = PseudoRandomGenPerm::new([0u8; 32]);
        let pp = BinomialPeerPartitions::new(own_peer, peers, rng);
        Handel::new(CONF, contrib, (), pp)
    }

    #[test]
    fn best_contrib_is_own_contrib_when_no_interactions() {
        let my_contrib = Contrib(HashSet::from([0]));
        let peers = (0..10).map(|_| (PeerId::random(), None)).collect::<Vec<_>>();
        let own_peer = peers[0].0;
        let handel = make_handel(own_peer, peers, my_contrib.clone());
        assert_eq!(handel.best_contribution(), my_contrib);
    }

    #[test]
    fn zeroth_and_first_levels_are_active_on_start() {
        let my_contrib = Contrib(HashSet::from([0]));
        let peers = (0..10).map(|_| (PeerId::random(), None)).collect::<Vec<_>>();
        let own_peer = peers[0].0;
        let handel = make_handel(own_peer, peers, my_contrib.clone());
        assert!(handel.is_active(0));
        assert!(handel.is_active(1));
        assert!(!handel.is_active(2));
    }

    #[test]
    fn aggregate_contribution() {
        let my_contrib = Contrib(HashSet::from([0]));
        let their_contrib = Contrib(HashSet::from([1]));
        let their_aggregate_contrib = Contrib(HashSet::from([1, 4, 9]));
        let peers = (0..16).map(|_| (PeerId::random(), None)).collect::<Vec<_>>();
        let own_peer = peers[0].0;
        let mut handel = make_handel(own_peer, peers.clone(), my_contrib.clone());
        let peer = handel.peer_partitions.peers_at_level(1, PeerOrd::VP)[0];
        let res = handel.handle_contribution(
            handel.peer_partitions.identify_peer(peer),
            1,
            their_aggregate_contrib,
            Some(their_contrib),
        );
        assert!(res.is_ok());
        handel.run_aggregation(1);
        assert_eq!(handel.best_contribution(), Contrib(HashSet::from([0, 1, 4, 9])));
    }

    #[test]
    fn ingnore_contributions_from_unknown_peers() {
        let my_contrib = Contrib(HashSet::from([0]));
        let their_contrib = Contrib(HashSet::from([1]));
        let their_aggregate_contrib = Contrib(HashSet::from([1, 4, 9]));
        let peers = (0..10).map(|_| (PeerId::random(), None)).collect::<Vec<_>>();
        let own_peer = peers[0].0;
        let mut handel = make_handel(own_peer, peers.clone(), my_contrib.clone());
        let res =
            handel.handle_contribution(PeerId::random(), 1, their_aggregate_contrib, Some(their_contrib));
        if handel.peer_partitions.peers_at_level(1, PeerOrd::VP).is_empty() {
            return;
        }
        assert!(res.is_err());
        handel.run_aggregation(1);
        assert_eq!(handel.best_contribution(), my_contrib);
    }

    #[test]
    fn empty_levels_are_skipped() {
        let my_contrib = Contrib(HashSet::from([0]));
        let level_1_peer_contrib = Contrib(HashSet::from([1]));
        let level_1_peer_aggregate_contrib = Contrib(HashSet::from([1, 4, 9]));
        let peers = vec![
            vec![],
            vec![PeerId::random()],
            vec![],
            vec![
                PeerId::random(),
                PeerId::random(),
                PeerId::random(),
                PeerId::random(),
            ],
            vec![
                PeerId::random(),
                PeerId::random(),
                PeerId::random(),
                PeerId::random(),
                PeerId::random(),
                PeerId::random(),
                PeerId::random(),
                PeerId::random(),
            ],
        ];
        let pp = FakePartitions::new(peers.clone());
        let mut handel = Handel::new(CONF, my_contrib, (), pp);
        let res = handel.handle_contribution(
            peers[1][0],
            1,
            level_1_peer_aggregate_contrib,
            Some(level_1_peer_contrib),
        );
        assert!(res.is_ok());
        handel.run_aggregation(1);
        assert!(handel.levels[2].is_some());
        assert!(handel.levels[2].as_ref().unwrap().is_completed);
        assert!(handel.levels[3].is_some());
    }
}
