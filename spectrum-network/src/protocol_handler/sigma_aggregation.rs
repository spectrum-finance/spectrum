use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::pin::Pin;
use std::task::{Context, Poll};

use either::Either;
use futures::channel::mpsc::Receiver;
use futures::channel::oneshot::Sender;
use futures::Stream;
use higher::Bifunctor;
use k256::{Scalar, SecretKey};
use libp2p::{Multiaddr, PeerId};
use log::trace;

use spectrum_crypto::digest::Digest256;
use spectrum_crypto::pubkey::PublicKey;

use crate::protocol_handler::aggregation::AggregationAction;
use crate::protocol_handler::handel::partitioning::{MakePeerPartitions, PeerIx, PeerPartitions};
use crate::protocol_handler::handel::{Handel, HandelConfig, HandelRound};
use crate::protocol_handler::multicasting::overlay::{DagOverlay, MakeDagOverlay};
use crate::protocol_handler::multicasting::{DagMulticasting, Multicasting};
use crate::protocol_handler::sigma_aggregation::crypto::{
    aggregate_commitment, aggregate_pk, aggregate_response, challenge, exclusion_proof, individual_input,
    pre_commitment, response, schnorr_commitment_pair,
};
use crate::protocol_handler::sigma_aggregation::message::{
    SigmaAggrMessage, SigmaAggrMessageV1, SigmaAggrSpec,
};
use crate::protocol_handler::sigma_aggregation::types::{
    AggregateCommitment, Commitment, CommitmentSecret, CommitmentsVerifInput, CommitmentsWithProofs,
    Contributions, PreCommitments, Responses, ResponsesVerifInput, Signature,
};
use crate::protocol_handler::void::VoidMessage;
use crate::protocol_handler::ProtocolBehaviourOut;
use crate::protocol_handler::{ProtocolBehaviour, TemporalProtocolStage};

mod crypto;
mod message;
pub mod types;

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
    handel: Box<dyn HandelRound<'a, PreCommitments, PP> + Send>,
}

impl<'a, H, PP> AggregatePreCommitments<'a, H, PP>
where
    PP: PeerPartitions + Send + 'a,
{
    fn init<MPP: MakePeerPartitions<PP = PP>, OB: MakeDagOverlay>(
        host_sk: SecretKey,
        committee: HashMap<PublicKey, Option<Multiaddr>>,
        message_digest: Digest256<H>,
        partitioner: MPP,
        mcast_overlay_builder: OB,
        handel_conf: HandelConfig,
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
            handel: Box::new(Handel::new(
                handel_conf,
                Contributions::unit(self.host_ix, (self.host_commitment, self.host_explusion_proof)),
                verif_input,
                self.handel.narrow(),
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
    handel: Box<dyn HandelRound<'a, CommitmentsWithProofs, PP> + Send>,
}

impl<'a, H, PP> AggregateCommitments<'a, H, PP>
where
    PP: PeerPartitions + Send + 'a,
{
    fn complete(self, commitments_with_proofs: CommitmentsWithProofs) -> BroadcastCommitments<'a, H, PP> {
        BroadcastCommitments {
            host_sk: self.host_sk,
            host_ix: self.host_ix,
            committee: self.committee,
            individual_inputs: self.individual_inputs,
            message_digest: self.message_digest,
            host_secret: self.host_secret,
            host_commitment: self.host_commitment.clone(),
            host_explusion_proof: self.host_explusion_proof.clone(),
            handel_partitions: self.handel.narrow(),
            mcast: Box::new(DagMulticasting::new(
                Some(commitments_with_proofs),
                (),
                self.mcast_overlay,
            )),
        }
    }
}

struct BroadcastCommitments<'a, H, PP> {
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
    mcast: Box<dyn Multicasting<'a, CommitmentsWithProofs> + Send>,
}

impl<'a, H, PP> BroadcastCommitments<'a, H, PP>
where
    PP: PeerPartitions + Send + 'a,
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
    handel: Box<dyn HandelRound<'a, Responses, PP> + Send>,
}

impl<'a, H, PP> AggregateResponses<'a, H, PP> {
    fn complete(self, responses: Responses) -> Aggregated<H> {
        let mut exclusion_set = HashMap::new();
        for (pix, (yi, sig)) in self.commitments_with_proofs.entries() {
            if responses.get(&pix).is_none() {
                exclusion_set.insert(yi, sig);
            }
        }
        let aggr_resp = aggregate_response(responses.values().into_iter().collect());
        Aggregated {
            message_digest: self.message_digest,
            aggregate_commitment: self.aggr_commitment,
            aggregate_response: aggr_resp,
            exclusion_set,
        }
    }
}

/// Result of an aggregation.
#[derive(Debug)]
pub struct Aggregated<H> {
    pub message_digest: Digest256<H>,
    pub aggregate_commitment: AggregateCommitment,
    pub aggregate_response: Scalar,
    pub exclusion_set: HashMap<Commitment, Signature>,
}

enum AggregationState<'a, H, PP> {
    AggregatePreCommitments(AggregatePreCommitments<'a, H, PP>),
    AggregateCommitments(AggregateCommitments<'a, H, PP>),
    BroadcastCommitments(BroadcastCommitments<'a, H, PP>),
    AggregateResponses(AggregateResponses<'a, H, PP>),
}

struct AggregationTask<'a, H, PP> {
    state: AggregationState<'a, H, PP>,
    channel: Sender<Result<Aggregated<H>, ()>>,
}

pub struct SigmaAggregation<'a, H, MPP, OB>
where
    MPP: MakePeerPartitions,
{
    host_sk: SecretKey,
    handel_conf: HandelConfig,
    task: Option<AggregationTask<'a, H, MPP::PP>>,
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
{
    pub fn new(
        host_sk: SecretKey,
        handel_conf: HandelConfig,
        partitioner: MPP,
        mcast_overlay_builder: OB,
        inbox: Receiver<AggregationAction<H>>,
    ) -> Self {
        Self {
            host_sk,
            handel_conf,
            task: None,
            partitioner,
            mcast_overlay_builder,
            inbox,
            outbox: VecDeque::new(),
        }
    }
}

impl<'a, H, MPP, OB> ProtocolBehaviour for SigmaAggregation<'a, H, MPP, OB>
where
    H: Debug,
    MPP: MakePeerPartitions + Clone + Send,
    MPP::PP: Send + 'a,
    OB: MakeDagOverlay + Clone,
{
    type TProto = SigmaAggrSpec;

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
                if let SigmaAggrMessageV1::PreCommitments(pre_commits) = msg {
                    trace!(
                        "SigmaAggrMessageV1::PreCommitments (host_ix: {:?})",
                        pre_commitment.host_ix,
                    );
                    pre_commitment.handel.inject_message(peer_id, pre_commits);
                }
            }
            Some(AggregationTask {
                state: AggregationState::AggregateCommitments(ref mut commitment),
                ..
            }) => {
                if let SigmaAggrMessageV1::Commitments(commits) = msg {
                    trace!("SigmaAggrMessageV1::Commitments: {:?}", commits);
                    commitment.handel.inject_message(peer_id, commits);
                } else {
                    trace!("SigmaAggrMessageV1 expected Commitments, got {:?}", msg);
                }
            }
            Some(AggregationTask {
                state: AggregationState::BroadcastCommitments(ref mut bcast),
                ..
            }) => {}
            Some(AggregationTask {
                state: AggregationState::AggregateResponses(ref mut response),
                ..
            }) => {
                if let SigmaAggrMessageV1::Responses(resps) = msg {
                    trace!("SigmaAggrMessageV1::Responses {:?}", resps);
                    response.handel.inject_message(peer_id, resps);
                } else {
                    trace!("SigmaAggrMessageV1 expected Responses, got {:?}", msg);
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
                        self.task = Some(AggregationTask {
                            state: AggregationState::AggregatePreCommitments(AggregatePreCommitments::init(
                                self.host_sk.clone(),
                                new_committee,
                                new_message,
                                self.partitioner.clone(),
                                self.mcast_overlay_builder.clone(),
                                self.handel_conf.clone(),
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
                    } => match st.handel.poll(cx) {
                        Poll::Ready(out) => match out {
                            Either::Left(cmd) => {
                                self.outbox.push_back(cmd.rmap(|m| {
                                    SigmaAggrMessage::SigmaAggrMessageV1(SigmaAggrMessageV1::PreCommitments(
                                        m,
                                    ))
                                }));
                                self.task = Some(AggregationTask {
                                    state: AggregationState::AggregatePreCommitments(st),
                                    channel,
                                });
                                continue;
                            }
                            Either::Right(pre_commitments) => {
                                let host_ix = st.host_ix;
                                self.task = Some(AggregationTask {
                                    state: AggregationState::AggregateCommitments(
                                        st.complete(pre_commitments, self.handel_conf),
                                    ),
                                    channel,
                                });
                                trace!("[SA] host_ix: {:?} Got precommitment", host_ix);
                                continue;
                            }
                        },
                        Poll::Pending => {
                            self.task = Some(AggregationTask {
                                state: AggregationState::AggregatePreCommitments(st),
                                channel,
                            });
                        }
                    },
                    AggregationTask {
                        state: AggregationState::AggregateCommitments(mut st),
                        channel,
                    } => match st.handel.poll(cx) {
                        Poll::Ready(out) => match out {
                            Either::Left(cmd) => {
                                self.outbox.push_back(cmd.rmap(|m| {
                                    SigmaAggrMessage::SigmaAggrMessageV1(SigmaAggrMessageV1::Commitments(m))
                                }));
                                self.task = Some(AggregationTask {
                                    state: AggregationState::AggregateCommitments(st),
                                    channel,
                                });
                                continue;
                            }

                            Either::Right(commitments) => {
                                trace!("[SA] Got commitments");
                                self.task = Some(AggregationTask {
                                    state: AggregationState::BroadcastCommitments(st.complete(commitments)),
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
                    },
                    AggregationTask {
                        state: AggregationState::BroadcastCommitments(mut st),
                        channel,
                    } => match st.mcast.poll(cx) {
                        Poll::Ready(out) => match out {
                            Either::Left(cmd) => {
                                self.outbox.push_back(cmd.rmap(|m| {
                                    SigmaAggrMessage::SigmaAggrMessageV1(SigmaAggrMessageV1::Broadcast(m))
                                }));
                                self.task = Some(AggregationTask {
                                    state: AggregationState::BroadcastCommitments(st),
                                    channel,
                                });
                                continue;
                            }
                            Either::Right(commitments) => {
                                trace!("[SA] Got commitments");
                                self.task = Some(AggregationTask {
                                    state: AggregationState::AggregateResponses(
                                        st.complete(commitments, self.handel_conf),
                                    ),
                                    channel,
                                });
                                continue;
                            }
                        },
                        Poll::Pending => {}
                    },
                    AggregationTask {
                        state: AggregationState::AggregateResponses(mut st),
                        channel,
                    } => {
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
                                    let res = st.complete(responses);
                                    // todo: support error case.
                                    trace!("[SA] Got responses: {:?}", res);
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
