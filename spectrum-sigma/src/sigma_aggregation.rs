use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};

use either::Either;
use futures::channel::mpsc::Receiver;
use futures::channel::oneshot::Sender;
use futures::Stream;
use higher::Bifunctor;
use k256::{Scalar, SecretKey};
use libp2p::{Multiaddr, PeerId};
use tracing::{info, trace, trace_span};

use spectrum_crypto::digest::Digest256;
use spectrum_crypto::pubkey::PublicKey;
use spectrum_handel::partitioning::{MakePeerPartitions, PeerIx, PeerPartitions};
use spectrum_handel::{Handel, HandelConfig, HandelRound};
use spectrum_mcast::behaviour::DagMulticastingConfig;
use spectrum_mcast::behaviour::{DagMulticasting, Multicasting};
use spectrum_mcast::overlay::{DagOverlay, MakeDagOverlay};
use spectrum_network::protocol_handler::void::VoidMessage;
use spectrum_network::protocol_handler::ProtocolBehaviourOut;
use spectrum_network::protocol_handler::{ProtocolBehaviour, TemporalProtocolStage};

use crate::crypto::{
    aggregate_commitment, aggregate_pk, aggregate_response, challenge, exclusion_proof, individual_input,
    pre_commitment, response, schnorr_commitment_pair,
};
use crate::message::{SigmaAggrMessage, SigmaAggrMessageV1, SigmaAggrSpec};
use crate::{
    AggregateCommitment, Commitment, CommitmentSecret, CommitmentsVerifInput, CommitmentsWithProofs,
    Contributions, PreCommitments, Responses, ResponsesVerifInput, Signature,
};

pub enum AggregationAction<H> {
    /// Restart aggregation with new committee.
    Reset {
        new_committee: HashMap<PublicKey, Option<Multiaddr>>,
        new_message: Digest256<H>,
        channel: Sender<Result<AggregateCertificate<H>, ()>>,
    },
}

struct AggregatePreCommitments<'a, H, PP> {
    /// `x_i`
    host_sk: SecretKey,
    /// Host's index in the Handel overlay.
    host_ix: PeerIx,
    /// `{X_1, X_2, ..., X_n}`. Set of public keys of committee members.
    committee: HashMap<PeerIx, PublicKey>,
    /// `a_i = H(X_1, X_2, ..., X_n; X_i)`, `{a_1, a_2, ..., a_n}`
    individual_inputs: HashMap<PeerIx, Scalar>,
    /// Message that we aggregate signatures for.
    message_digest: Digest256<H>,
    /// `y_i`
    host_secret: CommitmentSecret,
    /// `Y_i = g^{y_i}`
    host_commitment: Commitment,
    /// `σ_i`. Dlog proof of knowledge for `Y_i`.
    host_explusion_proof: Signature,
    mcast_overlay: DagOverlay,
    multicasting_conf: DagMulticastingConfig,
    partitions: PP,
    handel: Box<dyn HandelRound<'a, PreCommitments, PP> + Send>,
}

impl<'a, H, PP> AggregatePreCommitments<'a, H, PP>
where
    PP: PeerPartitions + Clone + Send + 'static,
{
    fn init<MPP: MakePeerPartitions<PP = PP>, OB: MakeDagOverlay>(
        host_sk: SecretKey,
        committee: HashMap<PublicKey, Option<Multiaddr>>,
        message_digest: Digest256<H>,
        partitioner: MPP,
        mcast_overlay_builder: OB,
        handel_conf: HandelConfig,
        multicasting_conf: DagMulticastingConfig,
    ) -> AggregatePreCommitments<'a, H, PP> {
        let host_pk = PublicKey::from(host_sk.clone());
        let host_pid = PeerId::from(host_pk);
        let peers = committee
            .iter()
            .map(|(pk, maddr)| (PeerId::from(pk), maddr.clone()))
            .collect::<Vec<_>>();
        let mcast_overlay = mcast_overlay_builder.make(None, host_pid, peers.clone());
        let partitions = partitioner.make(host_pid, peers);
        let committee_indexed = committee
            .into_iter()
            .map(|(pk, _)| {
                let pid = PeerId::from(&pk);
                let pix = partitions.try_index_peer(pid).unwrap();
                (pix, pk)
            })
            .collect::<HashMap<_, _>>();

        // Sort keys by their PeerIx.
        let mut committee_keys = committee_indexed.clone().into_iter().collect::<Vec<_>>();
        committee_keys.sort_by_key(|k| k.0);
        let committee_keys = committee_keys.into_iter().map(|(_, key)| key).collect::<Vec<_>>();
        let ais = committee_indexed
            .iter()
            .map(|(pix, pk)| (*pix, individual_input(committee_keys.clone(), pk.clone())))
            .collect();
        let (host_secret, host_commitment) = schnorr_commitment_pair();
        let host_pre_commitment = pre_commitment(host_commitment.clone());
        let host_ix = partitions.try_index_peer(host_pid).unwrap();
        trace!("[SA] {:?} <-> {:?}", host_pid, host_ix);
        AggregatePreCommitments {
            host_sk,
            host_ix,
            committee: committee_indexed,
            individual_inputs: ais,
            message_digest: message_digest.clone(),
            host_secret: host_secret.clone(),
            host_commitment,
            host_explusion_proof: exclusion_proof(host_secret, message_digest),
            mcast_overlay,
            multicasting_conf,
            partitions: partitions.clone(),
            handel: Box::new(Handel::new(
                handel_conf,
                Contributions::unit(host_ix, host_pre_commitment),
                (),
                partitions,
                host_ix,
            )),
        }
    }

    fn complete(
        self,
        pre_commitments: PreCommitments,
        handel_conf: HandelConfig,
    ) -> BroadcastPreCommitments<H, PP> {
        let handel_partitions = self.handel.narrow();
        BroadcastPreCommitments {
            host_sk: self.host_sk,
            host_ix: self.host_ix,
            committee: self.committee,
            individual_inputs: self.individual_inputs,
            message_digest: self.message_digest,
            host_secret: self.host_secret,
            host_commitment: self.host_commitment.clone(),
            host_explusion_proof: self.host_explusion_proof.clone(),
            handel_partitions: handel_partitions.clone(),
            mcast_overlay: self.mcast_overlay.clone(),
            multicasting_conf: self.multicasting_conf,
            mcast: Box::new(DagMulticasting::new(
                Some(pre_commitments),
                (),
                self.mcast_overlay,
                self.multicasting_conf,
                handel_partitions,
            )),
        }
    }
}

struct BroadcastPreCommitments<H, PP> {
    /// `x_i`
    host_sk: SecretKey,
    /// Host's index in the Handel overlay.
    host_ix: PeerIx,
    /// `{X_1, X_2, ..., X_n}`. Set of public keys of committee members.
    committee: HashMap<PeerIx, PublicKey>,
    /// `a_i = H(X_1, X_2, ..., X_n; X_i)`, `{a_1, a_2, ..., a_n}`
    individual_inputs: HashMap<PeerIx, Scalar>,
    /// Message that we aggregate signatures for.
    message_digest: Digest256<H>,
    /// `y_i`
    host_secret: CommitmentSecret,
    /// `Y_i = g^{y_i}`
    host_commitment: Commitment,
    /// `σ_i`. Dlog proof of knowledge for `Y_i`.
    host_explusion_proof: Signature,
    handel_partitions: PP,
    mcast_overlay: DagOverlay,
    multicasting_conf: DagMulticastingConfig,
    mcast: Box<dyn Multicasting<PreCommitments> + Send>,
}

impl<'a, H, PP> BroadcastPreCommitments<H, PP>
where
    PP: PeerPartitions + Send + Clone + 'a,
{
    fn complete(
        self,
        pre_commitments: PreCommitments,
        handel_conf: HandelConfig,
    ) -> AggregateCommitments<'a, H, PP> {
        let verif_input = CommitmentsVerifInput {
            pre_commitments,
            message_digest_bytes: self.message_digest.as_ref().to_vec(),
        };
        AggregateCommitments {
            host_sk: self.host_sk,
            host_ix: self.host_ix,
            committee: self.committee,
            individual_inputs: self.individual_inputs,
            message_digest: self.message_digest,
            host_secret: self.host_secret,
            host_commitment: self.host_commitment.clone(),
            host_explusion_proof: self.host_explusion_proof.clone(),
            mcast_overlay: self.mcast_overlay,
            multicasting_conf: self.multicasting_conf,
            partitions: self.handel_partitions.clone(),
            handel: Box::new(Handel::new(
                handel_conf,
                Contributions::unit(self.host_ix, (self.host_commitment, self.host_explusion_proof)),
                verif_input,
                self.handel_partitions,
                self.host_ix,
            )),
        }
    }
}

struct AggregateCommitments<'a, H, PP> {
    /// `x_i`
    host_sk: SecretKey,
    /// Host's index in the Handel overlay.
    host_ix: PeerIx,
    /// `{X_1, X_2, ..., X_n}`. Set of public keys of committee members.
    committee: HashMap<PeerIx, PublicKey>,
    /// `a_i = H(X_1, X_2, ..., X_n; X_i)`, `{a_1, a_2, ..., a_n}`
    individual_inputs: HashMap<PeerIx, Scalar>,
    /// Message that we aggregate signatures for.
    message_digest: Digest256<H>,
    /// `y_i`
    host_secret: CommitmentSecret,
    /// `Y_i = g^{y_i}`
    host_commitment: Commitment,
    /// `σ_i`. Dlog proof of knowledge for `Y_i`.
    host_explusion_proof: Signature,
    mcast_overlay: DagOverlay,
    multicasting_conf: DagMulticastingConfig,
    partitions: PP,
    handel: Box<dyn HandelRound<'a, CommitmentsWithProofs, PP> + Send>,
}

impl<'a, H, PP> AggregateCommitments<'a, H, PP>
where
    PP: PeerPartitions + Send + Clone + 'static,
{
    fn complete(self, commitments_with_proofs: CommitmentsWithProofs) -> BroadcastCommitments<H, PP> {
        let handel_partitions = self.handel.narrow();
        BroadcastCommitments {
            host_sk: self.host_sk,
            host_ix: self.host_ix,
            committee: self.committee,
            individual_inputs: self.individual_inputs,
            message_digest: self.message_digest,
            host_secret: self.host_secret,
            host_commitment: self.host_commitment.clone(),
            host_explusion_proof: self.host_explusion_proof.clone(),
            handel_partitions: handel_partitions.clone(),
            mcast: Box::new(DagMulticasting::new(
                Some(commitments_with_proofs),
                (),
                self.mcast_overlay,
                self.multicasting_conf,
                handel_partitions,
            )),
        }
    }
}

struct BroadcastCommitments<H, PP> {
    /// `x_i`
    host_sk: SecretKey,
    /// Host's index in the Handel overlay.
    host_ix: PeerIx,
    /// `{X_1, X_2, ..., X_n}`. Set of public keys of committee members.
    committee: HashMap<PeerIx, PublicKey>,
    /// `a_i = H(X_1, X_2, ..., X_n; X_i)`, `{a_1, a_2, ..., a_n}`
    individual_inputs: HashMap<PeerIx, Scalar>,
    /// Message that we aggregate signatures for.
    message_digest: Digest256<H>,
    /// `y_i`
    host_secret: CommitmentSecret,
    /// `Y_i = g^{y_i}`
    host_commitment: Commitment,
    /// `σ_i`. Dlog proof of knowledge for `Y_i`.
    host_explusion_proof: Signature,
    handel_partitions: PP,
    mcast: Box<dyn Multicasting<CommitmentsWithProofs> + Send>,
}

impl<'a, H, PP> BroadcastCommitments<H, PP>
where
    PP: PeerPartitions + Send + Clone + 'a,
{
    fn complete(
        self,
        commitments_with_proofs_intersect: CommitmentsWithProofs,
        handel_conf: HandelConfig,
    ) -> AggregateResponses<'a, H, PP> {
        // Need to ensure stable ordering for committee and individual inputs. Just sort by PeerIx.
        let mut committee = self.committee.clone().into_iter().collect::<Vec<_>>();
        committee.sort_by_key(|k| k.0);
        let committee = committee.into_iter().map(|(_, key)| key).collect();

        let mut individual_inputs = self.individual_inputs.clone().into_iter().collect::<Vec<_>>();
        individual_inputs.sort_by_key(|k| k.0);
        let individual_inputs = individual_inputs.into_iter().map(|(_, scalar)| scalar).collect();

        let aggr_pk = aggregate_pk(committee, individual_inputs);
        let aggr_commitment = aggregate_commitment(
            commitments_with_proofs_intersect
                .values()
                .into_iter()
                .map(|(xi, _)| xi)
                .collect(),
        );
        let challenge = challenge(aggr_pk, aggr_commitment.clone(), self.message_digest);
        let individual_input = *self.individual_inputs.get(&self.host_ix).unwrap();
        let host_response = response(
            self.host_secret.clone(),
            self.host_sk.clone(),
            challenge,
            individual_input,
        );
        let verif_inputs = ResponsesVerifInput::new(
            commitments_with_proofs_intersect.clone(),
            self.committee.clone(),
            self.individual_inputs.clone(),
            challenge,
        );
        AggregateResponses {
            message_digest: self.message_digest,
            aggr_commitment,
            commitments_with_proofs: commitments_with_proofs_intersect,
            host_ix: self.host_ix,
            partitions: self.handel_partitions.clone(),
            handel: Box::new(Handel::new(
                handel_conf,
                Contributions::unit(self.host_ix, host_response),
                verif_inputs,
                self.handel_partitions,
                self.host_ix,
            )),
        }
    }
}

struct AggregateResponses<'a, H, PP> {
    message_digest: Digest256<H>,
    aggr_commitment: AggregateCommitment,
    commitments_with_proofs: CommitmentsWithProofs,
    host_ix: PeerIx,
    partitions: PP,
    handel: Box<dyn HandelRound<'a, Responses, PP> + Send>,
}

impl<'a, H, PP> AggregateResponses<'a, H, PP> {
    fn complete(self, responses: Responses) -> AggregateCertificate<H> {
        let mut exclusion_set = HashMap::new();
        for (pix, (yi, sig)) in self.commitments_with_proofs.entries() {
            if responses.get(&pix).is_none() {
                exclusion_set.insert(yi, sig);
            }
        }
        let aggr_resp = aggregate_response(responses.values().into_iter().collect());
        AggregateCertificate {
            message_digest: self.message_digest,
            aggregate_commitment: self.aggr_commitment,
            aggregate_response: aggr_resp,
            exclusion_set,
        }
    }
}

/// Result of an aggregation.
#[derive(Debug, Eq, PartialEq, Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound = "H: Debug")]
pub struct AggregateCertificate<H> {
    pub message_digest: Digest256<H>,
    pub aggregate_commitment: AggregateCommitment,
    pub aggregate_response: Scalar,
    pub exclusion_set: HashMap<Commitment, Signature>,
}

enum AggregationState<'a, H, PP> {
    AggregatePreCommitments(AggregatePreCommitments<'a, H, PP>),
    BroadcastPreCommitments(BroadcastPreCommitments<H, PP>),
    AggregateCommitments(AggregateCommitments<'a, H, PP>),
    BroadcastCommitments(BroadcastCommitments<H, PP>),
    AggregateResponses(AggregateResponses<'a, H, PP>),
}

struct AggregationTask<'a, H, PP> {
    state: AggregationState<'a, H, PP>,
    channel: Sender<Result<AggregateCertificate<H>, ()>>,
}

#[repr(usize)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum StageTag {
    PreCommit = 0,
    Commit = 1,
    BroadcastPreCommitments = 2,
    BroadcastCommitments = 3,
    Response = 4,
}

impl From<&SigmaAggrMessageV1> for StageTag {
    fn from(m: &SigmaAggrMessageV1) -> Self {
        match m {
            SigmaAggrMessageV1::PreCommitments(_) => StageTag::PreCommit,
            SigmaAggrMessageV1::Commitments(_) => StageTag::Commit,
            SigmaAggrMessageV1::BroadcastPreCommitments(_) => StageTag::BroadcastPreCommitments,
            SigmaAggrMessageV1::BroadcastCommitments(_) => StageTag::BroadcastCommitments,
            SigmaAggrMessageV1::Responses(_) => StageTag::Response,
        }
    }
}

/// Stash of messages received during improper stage. Messages are groupped by stage.
struct MessageStash([HashMap<PeerId, SigmaAggrMessageV1>; 5]);

impl MessageStash {
    fn new() -> Self {
        Self([
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        ])
    }

    fn stash(&mut self, peer: PeerId, m: SigmaAggrMessageV1) {
        let stage = StageTag::from(&m);
        self.0[stage as usize].insert(peer, m);
    }

    fn unstash(&mut self, stage: StageTag) -> HashMap<PeerId, SigmaAggrMessageV1> {
        mem::replace(&mut self.0[stage as usize], HashMap::new())
    }

    fn flush(&mut self) {
        self.0 = [
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        ];
    }
}

pub struct SigmaAggregation<'a, H, MPP, OB>
where
    MPP: MakePeerPartitions,
{
    host_sk: SecretKey,
    handel_conf: HandelConfig,
    multicasting_conf: DagMulticastingConfig,
    task: Option<AggregationTask<'a, H, MPP::PP>>,
    stash: MessageStash,
    partitioner: MPP,
    mcast_overlay_builder: OB,
    inbox: Receiver<AggregationAction<H>>,
    outbox: VecDeque<ProtocolBehaviourOut<VoidMessage, SigmaAggrMessage>>,
}

trait AssertKinds: Unpin {}
impl<'a, H, MPP, OB> AssertKinds for SigmaAggregation<'a, H, MPP, OB>
where
    MPP: MakePeerPartitions + Unpin,
    <MPP as MakePeerPartitions>::PP: Unpin,
    OB: Unpin,
    H: Unpin,
{
}

impl<'a, H, MPP, OB> SigmaAggregation<'a, H, MPP, OB>
where
    MPP: MakePeerPartitions + Clone,
    MPP::PP: Clone + 'static,
{
    pub fn new(
        host_sk: SecretKey,
        handel_conf: HandelConfig,
        multicasting_conf: DagMulticastingConfig,
        partitioner: MPP,
        mcast_overlay_builder: OB,
        inbox: Receiver<AggregationAction<H>>,
    ) -> Self {
        Self {
            host_sk,
            handel_conf,
            multicasting_conf,
            task: None,
            stash: MessageStash::new(),
            partitioner,
            mcast_overlay_builder,
            inbox,
            outbox: VecDeque::new(),
        }
    }

    fn unstash_stage(&mut self, stage: StageTag)
    where
        H: Debug,
        MPP: MakePeerPartitions + Clone + Send,
        MPP::PP: Send + 'a,
        OB: MakeDagOverlay + Clone,
    {
        for (p, m) in self.stash.unstash(stage) {
            self.inject_message(p, SigmaAggrMessage::SigmaAggrMessageV1(m))
        }
    }
}

impl<'a, H, MPP, OB> ProtocolBehaviour for SigmaAggregation<'a, H, MPP, OB>
where
    H: Debug,
    MPP: MakePeerPartitions + Clone + Send,
    MPP::PP: Send + Clone + 'static,
    OB: MakeDagOverlay + Clone,
{
    type TProto = SigmaAggrSpec;

    #[tracing::instrument(skip(self, msg, peer_id), level = "trace")]
    fn inject_message(
        &mut self,
        peer_id: PeerId,
        SigmaAggrMessage::SigmaAggrMessageV1(msg): SigmaAggrMessage,
    ) {
        match &mut self.task {
            Some(AggregationTask {
                state: AggregationState::AggregatePreCommitments(ref mut pre_commitment),
                ..
            }) => {
                let span = trace_span!("", host_ix = ?pre_commitment.host_ix, stage = ?StageTag::PreCommit);
                let _enter = span.enter();
                if let SigmaAggrMessageV1::PreCommitments(pre_commits) = msg {
                    pre_commitment.handel.inject_message(peer_id, pre_commits);
                } else {
                    trace!(
                        "SigmaAggrMessageV1 from {:?}: expected PreCommitments, got {}",
                        pre_commitment.partitions.try_index_peer(peer_id).unwrap(),
                        msg_variant_as_str(&msg)
                    );
                    self.stash.stash(peer_id, msg);
                }
            }
            Some(AggregationTask {
                state: AggregationState::BroadcastPreCommitments(ref mut bcast),
                ..
            }) => {
                let span =
                    trace_span!("", host_ix = ?bcast.host_ix, stage = ?StageTag::BroadcastPreCommitments);
                let _enter = span.enter();
                if let SigmaAggrMessageV1::BroadcastPreCommitments(commits) = msg {
                    bcast.mcast.inject_message(peer_id, commits);
                } else {
                    trace!(
                        "SigmaAggrMessageV1 from {:?}: expected BroadcastPreCommitments, got {}",
                        bcast.handel_partitions.try_index_peer(peer_id).unwrap(),
                        msg_variant_as_str(&msg)
                    );
                    self.stash.stash(peer_id, msg);
                }
            }
            Some(AggregationTask {
                state: AggregationState::AggregateCommitments(ref mut commitment),
                ..
            }) => {
                let span = trace_span!("", host_ix = ?commitment.host_ix, stage = ?StageTag::Commit);
                let _enter = span.enter();
                if let SigmaAggrMessageV1::Commitments(commits) = msg {
                    commitment.handel.inject_message(peer_id, commits);
                } else {
                    trace!(
                        "SigmaAggrMessageV1 from {:?}: expected Commitments, got {}",
                        commitment.partitions.try_index_peer(peer_id).unwrap(),
                        msg_variant_as_str(&msg)
                    );
                    self.stash.stash(peer_id, msg);
                }
            }
            Some(AggregationTask {
                state: AggregationState::BroadcastCommitments(ref mut bcast),
                ..
            }) => {
                let span = trace_span!("", host_ix = ?bcast.host_ix, stage = ?StageTag::BroadcastCommitments);
                let _enter = span.enter();
                if let SigmaAggrMessageV1::BroadcastCommitments(commits) = msg {
                    bcast.mcast.inject_message(peer_id, commits);
                } else {
                    trace!(
                        "SigmaAggrMessageV1 from {:?}: expected BroadcastCommitments, got {}",
                        bcast.handel_partitions.try_index_peer(peer_id).unwrap(),
                        msg_variant_as_str(&msg)
                    );
                    self.stash.stash(peer_id, msg);
                }
            }
            Some(AggregationTask {
                state: AggregationState::AggregateResponses(ref mut response),
                ..
            }) => {
                let span = trace_span!("", host_ix = ?response.host_ix, stage = ?StageTag::Response);
                let _enter = span.enter();
                if let SigmaAggrMessageV1::Responses(resps) = msg {
                    response.handel.inject_message(peer_id, resps);
                } else {
                    trace!(
                        "SigmaAggrMessageV1 from {:?}: expected Responses, got {}",
                        response.partitions.try_index_peer(peer_id).unwrap(),
                        msg_variant_as_str(&msg)
                    );
                    self.stash.stash(peer_id, msg);
                }
            }
            None => {}
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<ProtocolBehaviourOut<VoidMessage, SigmaAggrMessage>>> {
        loop {
            if let Some(out) = self.outbox.pop_front() {
                return Poll::Ready(Some(out));
            }

            if let Poll::Ready(Some(notif)) = Stream::poll_next(Pin::new(&mut self.inbox), cx) {
                match notif {
                    AggregationAction::Reset {
                        new_committee,
                        new_message,
                        channel,
                    } => {
                        self.stash.flush();
                        self.task = Some(AggregationTask {
                            state: AggregationState::AggregatePreCommitments(AggregatePreCommitments::init(
                                self.host_sk.clone(),
                                new_committee,
                                new_message,
                                self.partitioner.clone(),
                                self.mcast_overlay_builder.clone(),
                                self.handel_conf.clone(),
                                self.multicasting_conf,
                            )),
                            channel,
                        });
                    }
                }
            }

            if let Some(task) = self.task.take() {
                match task {
                    AggregationTask {
                        state: AggregationState::AggregatePreCommitments(mut st),
                        channel,
                    } => {
                        let span = trace_span!("poll: self.task.take()", host_ix = ?st.host_ix, stage = ?StageTag::PreCommit);
                        let _enter = span.enter();
                        match st.handel.poll(cx) {
                            Poll::Ready(out) => match out {
                                Either::Left(cmd) => {
                                    self.outbox.push_back(cmd.rmap(|m| {
                                        SigmaAggrMessage::SigmaAggrMessageV1(
                                            SigmaAggrMessageV1::PreCommitments(m),
                                        )
                                    }));
                                    self.task = Some(AggregationTask {
                                        state: AggregationState::AggregatePreCommitments(st),
                                        channel,
                                    });
                                    continue;
                                }
                                Either::Right(pre_commitments) => {
                                    let mut missing_peers: Vec<_> = (0_usize..st.committee.len()).collect();
                                    let peers = pre_commitments
                                        .entries()
                                        .into_iter()
                                        .map(|(key, _)| key.unwrap())
                                        .collect::<Vec<_>>();
                                    for i in peers {
                                        if let Some(ix) = missing_peers.iter().position(|j| *j == i) {
                                            missing_peers.remove(ix);
                                        }
                                    }
                                    missing_peers.sort();
                                    info!("Precommitment stage complete, PreCommitments missing from PeerIx(_): {:?}", missing_peers);
                                    self.unstash_stage(StageTag::Commit);
                                    self.task = Some(AggregationTask {
                                        state: AggregationState::BroadcastPreCommitments(
                                            st.complete(pre_commitments, self.handel_conf),
                                        ),
                                        channel,
                                    });
                                    continue;
                                }
                            },
                            Poll::Pending => {
                                self.task = Some(AggregationTask {
                                    state: AggregationState::AggregatePreCommitments(st),
                                    channel,
                                });
                            }
                        }
                    }
                    AggregationTask {
                        state: AggregationState::BroadcastPreCommitments(mut st),
                        channel,
                    } => {
                        let span = trace_span!("poll: self.task.take()", host_ix = ?st.host_ix, stage = ?StageTag::BroadcastPreCommitments);
                        let _enter = span.enter();
                        match st.mcast.poll(cx) {
                            Poll::Ready(out) => match out {
                                Either::Left(cmd) => {
                                    self.outbox.push_back(cmd.rmap(|m| {
                                        SigmaAggrMessage::SigmaAggrMessageV1(
                                            SigmaAggrMessageV1::BroadcastPreCommitments(m),
                                        )
                                    }));
                                    self.task = Some(AggregationTask {
                                        state: AggregationState::BroadcastPreCommitments(st),
                                        channel,
                                    });
                                    continue;
                                }
                                Either::Right(pre_commitments) => {
                                    let mut missing_peers: Vec<_> = (0_usize..st.committee.len()).collect();
                                    let peers = pre_commitments
                                        .entries()
                                        .into_iter()
                                        .map(|(key, _)| key.unwrap())
                                        .collect::<Vec<_>>();
                                    for i in peers {
                                        if let Some(ix) = missing_peers.iter().position(|j| *j == i) {
                                            missing_peers.remove(ix);
                                        }
                                    }
                                    missing_peers.sort();
                                    info!(
                                        "Finish broadcasting precommitments, missing from: {:?}",
                                        missing_peers
                                    );
                                    self.unstash_stage(StageTag::Response);
                                    self.task = Some(AggregationTask {
                                        state: AggregationState::AggregateCommitments(
                                            st.complete(pre_commitments, self.handel_conf),
                                        ),
                                        channel,
                                    });
                                    continue;
                                }
                            },
                            Poll::Pending => {
                                self.task = Some(AggregationTask {
                                    state: AggregationState::BroadcastPreCommitments(st),
                                    channel,
                                });
                            }
                        }
                    }
                    AggregationTask {
                        state: AggregationState::AggregateCommitments(mut st),
                        channel,
                    } => {
                        let span = trace_span!("poll: self.task.take()", host_ix = ?st.host_ix, stage = ?StageTag::Commit);
                        let _enter = span.enter();
                        match st.handel.poll(cx) {
                            Poll::Ready(out) => match out {
                                Either::Left(cmd) => {
                                    self.outbox.push_back(cmd.rmap(|m| {
                                        SigmaAggrMessage::SigmaAggrMessageV1(SigmaAggrMessageV1::Commitments(
                                            m,
                                        ))
                                    }));
                                    self.task = Some(AggregationTask {
                                        state: AggregationState::AggregateCommitments(st),
                                        channel,
                                    });
                                    continue;
                                }

                                Either::Right(commitments) => {
                                    let mut missing_peers: Vec<_> = (0_usize..st.committee.len()).collect();
                                    let peers = commitments
                                        .entries()
                                        .into_iter()
                                        .map(|(key, _)| key.unwrap())
                                        .collect::<Vec<_>>();
                                    for i in peers {
                                        if let Some(ix) = missing_peers.iter().position(|j| *j == i) {
                                            missing_peers.remove(ix);
                                        }
                                    }
                                    missing_peers.sort();
                                    info!("Finished commitments stage: missing from {:?}", missing_peers);
                                    self.unstash_stage(StageTag::BroadcastCommitments);
                                    self.task = Some(AggregationTask {
                                        state: AggregationState::BroadcastCommitments(
                                            st.complete(commitments),
                                        ),
                                        channel,
                                    });
                                    continue;
                                }
                            },
                            Poll::Pending => {
                                self.task = Some(AggregationTask {
                                    state: AggregationState::AggregateCommitments(st),
                                    channel,
                                });
                            }
                        }
                    }
                    AggregationTask {
                        state: AggregationState::BroadcastCommitments(mut st),
                        channel,
                    } => {
                        let span = trace_span!("poll: self.task.take()", host_ix = ?st.host_ix, stage = ?StageTag::BroadcastCommitments);
                        let _enter = span.enter();
                        match st.mcast.poll(cx) {
                            Poll::Ready(out) => match out {
                                Either::Left(cmd) => {
                                    self.outbox.push_back(cmd.rmap(|m| {
                                        SigmaAggrMessage::SigmaAggrMessageV1(
                                            SigmaAggrMessageV1::BroadcastCommitments(m),
                                        )
                                    }));
                                    self.task = Some(AggregationTask {
                                        state: AggregationState::BroadcastCommitments(st),
                                        channel,
                                    });
                                    continue;
                                }
                                Either::Right(commitments) => {
                                    let mut missing_peers: Vec<_> = (0_usize..st.committee.len()).collect();
                                    let peers = commitments
                                        .entries()
                                        .into_iter()
                                        .map(|(key, _)| key.unwrap())
                                        .collect::<Vec<_>>();
                                    for i in peers {
                                        if let Some(ix) = missing_peers.iter().position(|j| *j == i) {
                                            missing_peers.remove(ix);
                                        }
                                    }
                                    missing_peers.sort();
                                    info!(
                                        "Finished broadcasting commitments, missing from: {:?}",
                                        missing_peers
                                    );
                                    self.unstash_stage(StageTag::Response);
                                    self.task = Some(AggregationTask {
                                        state: AggregationState::AggregateResponses(
                                            st.complete(commitments, self.handel_conf),
                                        ),
                                        channel,
                                    });
                                    continue;
                                }
                            },
                            Poll::Pending => {
                                self.task = Some(AggregationTask {
                                    state: AggregationState::BroadcastCommitments(st),
                                    channel,
                                });
                            }
                        }
                    }
                    AggregationTask {
                        state: AggregationState::AggregateResponses(mut st),
                        channel,
                    } => {
                        let span = trace_span!("poll: self.task.take()", host_ix = ?st.host_ix, stage = ?StageTag::Response);
                        let _enter = span.enter();
                        match st.handel.poll(cx) {
                            Poll::Ready(out) => match out {
                                Either::Left(cmd) => {
                                    self.outbox.push_back(cmd.rmap(|m| {
                                        SigmaAggrMessage::SigmaAggrMessageV1(SigmaAggrMessageV1::Responses(m))
                                    }));
                                    self.task = Some(AggregationTask {
                                        state: AggregationState::AggregateResponses(st),
                                        channel,
                                    });
                                    continue;
                                }
                                Either::Right(responses) => {
                                    self.task = None;
                                    self.stash.flush();
                                    let res = st.complete(responses);
                                    // todo: support error case.
                                    info!("Got responses");
                                    if channel.send(Ok(res)).is_err() {
                                        // warn here.
                                    }
                                    continue;
                                }
                            },
                            Poll::Pending => {
                                self.task = Some(AggregationTask {
                                    state: AggregationState::AggregateResponses(st),
                                    channel,
                                });
                            }
                        }
                    }
                }
            }

            return Poll::Pending;
        }
    }
}

fn msg_variant_as_str(msg: &SigmaAggrMessageV1) -> &str {
    match msg {
        SigmaAggrMessageV1::PreCommitments(_) => "SigmaAggrMessageV1::PreCommitments",
        SigmaAggrMessageV1::Commitments(_) => "SigmaAggrMessageV1::Commitments",
        SigmaAggrMessageV1::BroadcastPreCommitments(_) => "SigmaAggrMessageV1::BroadcastPreCommitments",
        SigmaAggrMessageV1::BroadcastCommitments(_) => "SigmaAggrMessageV1::BroadcastCommitments",
        SigmaAggrMessageV1::Responses(_) => "SigmaAggrMessageV1::Responses",
    }
}
