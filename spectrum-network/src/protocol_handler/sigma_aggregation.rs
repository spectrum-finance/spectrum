use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::pin::Pin;
use std::task::{Context, Poll};

use either::Either;
use futures::channel::mpsc::Receiver;
use futures::channel::oneshot::Sender;
use futures::Stream;
use k256::{Scalar, SecretKey};
use libp2p::PeerId;

use spectrum_crypto::digest::Digest256;

use crate::protocol::SIGMA_AGGR_PROTOCOL_ID;
use crate::protocol_handler::aggregation::AggregationAction;
use crate::protocol_handler::handel::partitioning::{MakePeerPartitions, PeerIx, PeerPartitions};
use crate::protocol_handler::handel::{Handel, HandelConfig, HandelRound, NarrowTo};
use crate::protocol_handler::sigma_aggregation::crypto::{
    aggregate_commitment, aggregate_pk, aggregate_response, challenge, exclusion_proof, individual_input,
    pre_commitment, response, schnorr_commitment_pair,
};
use crate::protocol_handler::sigma_aggregation::message::{
    SigmaAggrMessage, SigmaAggrMessageV1, SigmaAggrSpec,
};
use crate::protocol_handler::sigma_aggregation::types::{
    AggregateCommitment, Commitment, CommitmentSecret, CommitmentsVerifInput, CommitmentsWithProofs,
    Contributions, PreCommitments, PublicKey, Responses, ResponsesVerifInput, Signature,
};
use crate::protocol_handler::NetworkAction;
use crate::protocol_handler::ProtocolBehaviour;
use crate::protocol_handler::ProtocolBehaviourOut;
use crate::types::ProtocolId;

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
    /// `σ_i`. Dlog proof of knowledge of `Y_i`.
    host_explusion_proof: Signature,
    handel: Box<dyn HandelRound<'a, PreCommitments, PP>>,
}

impl<'a, H, PP> AggregatePreCommitments<'a, H, PP>
where
    PP: PeerPartitions + 'a,
{
    fn init<MPP: MakePeerPartitions<PP = PP>>(
        host_sk: SecretKey,
        committee: HashSet<PublicKey>,
        message_digest: Digest256<H>,
        partitioner: MPP,
        handel_conf: HandelConfig,
    ) -> AggregatePreCommitments<'a, H, PP> {
        let host_pk = PublicKey::from(host_sk.clone());
        let host_pid = PeerId::from(host_pk);
        let peers = committee.iter().map(PeerId::from).collect();
        let partitions = partitioner.make(host_pid, peers);
        let committee_indexed = committee
            .iter()
            .map(|pk| {
                let pid = PeerId::from(pk);
                let pix = partitions.try_index_peer(pid).unwrap();
                (pix, pk.clone())
            })
            .collect::<HashMap<_, _>>();
        let ais = committee_indexed
            .iter()
            .map(|(pix, pk)| {
                (
                    *pix,
                    individual_input(committee.clone().into_iter().collect(), pk.clone()),
                )
            })
            .collect();
        let (host_secret, host_commitment) = schnorr_commitment_pair();
        let host_pre_commitment = pre_commitment(host_commitment.clone());
        let host_ix = partitions.try_index_peer(host_pid).unwrap();
        AggregatePreCommitments {
            host_sk,
            host_ix,
            committee: committee_indexed,
            individual_inputs: ais,
            message_digest: message_digest.clone(),
            host_secret: host_secret.clone(),
            host_commitment,
            host_explusion_proof: exclusion_proof(host_secret, message_digest),
            handel: Box::new(Handel::new(
                handel_conf,
                Contributions::unit(host_ix, host_pre_commitment),
                (),
                partitions,
            )),
        }
    }

    fn complete(
        self,
        pre_commitments: PreCommitments,
        handel_conf: HandelConfig,
    ) -> AggregateSchnorrCommitments<'a, H, PP> {
        let verif_input = CommitmentsVerifInput {
            pre_commitments,
            message_digest_bytes: self.message_digest.as_ref().to_vec(),
        };
        AggregateSchnorrCommitments {
            host_sk: self.host_sk,
            host_ix: self.host_ix,
            committee: self.committee,
            individual_inputs: self.individual_inputs,
            message_digest: self.message_digest,
            host_secret: self.host_secret,
            host_commitment: self.host_commitment.clone(),
            host_explusion_proof: self.host_explusion_proof.clone(),
            handel: Box::new(Handel::new(
                handel_conf,
                Contributions::unit(self.host_ix, (self.host_commitment, self.host_explusion_proof)),
                verif_input,
                self.handel.narrow(),
            )),
        }
    }
}

struct AggregateSchnorrCommitments<'a, H, PP> {
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
    /// `σ_i`. Dlog proof of knowledge of `Y_i`.
    host_explusion_proof: Signature,
    handel: Box<dyn HandelRound<'a, CommitmentsWithProofs, PP>>,
}

impl<'a, H, PP> AggregateSchnorrCommitments<'a, H, PP>
where
    PP: PeerPartitions + 'a,
{
    fn complete(
        self,
        commitments_with_proofs: CommitmentsWithProofs,
        handel_conf: HandelConfig,
    ) -> AggregateResponses<'a, H, PP> {
        let aggr_pk = aggregate_pk(
            self.committee.values().cloned().collect(),
            self.individual_inputs.values().cloned().collect(),
        );
        let aggr_commitment = aggregate_commitment(
            commitments_with_proofs
                .values()
                .into_iter()
                .map(|(xi, _)| xi)
                .collect(),
        );
        let challenge = challenge(aggr_pk, aggr_commitment.clone(), self.message_digest);
        let individual_input = self.individual_inputs.get(&self.host_ix).unwrap().clone();
        let host_response = response(
            self.host_secret.clone(),
            self.host_sk.clone(),
            challenge,
            individual_input,
        );
        let verif_inputs = ResponsesVerifInput::new(
            commitments_with_proofs.clone(),
            self.committee.clone(),
            self.individual_inputs.clone(),
            challenge,
        );
        AggregateResponses {
            host_sk: self.host_sk,
            host_ix: self.host_ix,
            committee: self.committee,
            individual_inputs: self.individual_inputs,
            message_digest: self.message_digest,
            host_secret: self.host_secret,
            host_commitment: self.host_commitment,
            aggr_commitment,
            host_explusion_proof: self.host_explusion_proof,
            commitments_with_proofs,
            handel: Box::new(Handel::new(
                handel_conf,
                Contributions::unit(self.host_ix, host_response),
                verif_inputs,
                self.handel.narrow(),
            )),
        }
    }
}

struct AggregateResponses<'a, H, PP> {
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
    aggr_commitment: AggregateCommitment,
    /// `σ_i`. Dlog proof of knowledge of `Y_i`.
    host_explusion_proof: Signature,
    commitments_with_proofs: CommitmentsWithProofs,
    handel: Box<dyn HandelRound<'a, Responses, PP>>,
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
    AggregateSchnorrCommitments(AggregateSchnorrCommitments<'a, H, PP>),
    AggregateResponses(AggregateResponses<'a, H, PP>),
}

struct AggregationTask<'a, H, PP> {
    state: AggregationState<'a, H, PP>,
    channel: Sender<Result<Aggregated<H>, ()>>,
}

pub struct SigmaAggregation<'a, H, MPP>
where
    MPP: MakePeerPartitions + Clone,
{
    host_sk: SecretKey,
    handel_conf: HandelConfig,
    task: Option<AggregationTask<'a, H, MPP::PP>>,
    partitioner: MPP,
    inbox: Receiver<AggregationAction<H>>,
    outbox: VecDeque<ProtocolBehaviourOut<SigmaAggrMessage, SigmaAggrMessage>>,
}

impl<'a, H, MPP> ProtocolBehaviour for SigmaAggregation<'a, H, MPP>
where
    H: Debug,
    MPP: MakePeerPartitions + Clone,
    MPP::PP: 'a,
{
    type TProto = SigmaAggrSpec;

    fn get_protocol_id(&self) -> ProtocolId {
        SIGMA_AGGR_PROTOCOL_ID
    }

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
                    pre_commitment.handel.inject_message(peer_id, pre_commits);
                }
            }
            Some(AggregationTask {
                state: AggregationState::AggregateSchnorrCommitments(ref mut commitment),
                ..
            }) => {
                if let SigmaAggrMessageV1::Commitments(commits) = msg {
                    commitment.handel.inject_message(peer_id, commits);
                }
            }
            Some(AggregationTask {
                state: AggregationState::AggregateResponses(ref mut response),
                ..
            }) => {
                if let SigmaAggrMessageV1::Responses(resps) = msg {
                    response.handel.inject_message(peer_id, resps);
                }
            }
            None => {}
        }
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<ProtocolBehaviourOut<SigmaAggrMessage, SigmaAggrMessage>>> {
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
                    } => {
                        match st.handel.poll(cx) {
                            Poll::Ready(out) => match out {
                                Either::Left(cmd) => match cmd {
                                    ProtocolBehaviourOut::Send { peer_id, message } => {
                                        self.outbox.push_back(ProtocolBehaviourOut::Send {
                                            peer_id,
                                            message: SigmaAggrMessage::SigmaAggrMessageV1(
                                                SigmaAggrMessageV1::PreCommitments(message),
                                            ),
                                        });
                                    }
                                    ProtocolBehaviourOut::NetworkAction(NetworkAction::BanPeer(pid)) => {
                                        self.outbox.push_back(ProtocolBehaviourOut::NetworkAction(
                                            NetworkAction::BanPeer(pid),
                                        ));
                                    }
                                    ProtocolBehaviourOut::NetworkAction(_) => {}
                                },
                                Either::Right(pre_commitments) => {
                                    self.task = Some(AggregationTask {
                                        state: AggregationState::AggregateSchnorrCommitments(
                                            st.complete(pre_commitments, self.handel_conf),
                                        ),
                                        channel,
                                    });
                                    continue;
                                }
                            },
                            Poll::Pending => {}
                        }
                        self.task = Some(AggregationTask {
                            state: AggregationState::AggregatePreCommitments(st),
                            channel,
                        });
                    }
                    AggregationTask {
                        state: AggregationState::AggregateSchnorrCommitments(mut st),
                        channel,
                    } => {
                        match st.handel.poll(cx) {
                            Poll::Ready(out) => match out {
                                Either::Left(cmd) => match cmd {
                                    ProtocolBehaviourOut::Send { peer_id, message } => {
                                        self.outbox.push_back(ProtocolBehaviourOut::Send {
                                            peer_id,
                                            message: SigmaAggrMessage::SigmaAggrMessageV1(
                                                SigmaAggrMessageV1::Commitments(message),
                                            ),
                                        });
                                    }
                                    ProtocolBehaviourOut::NetworkAction(NetworkAction::BanPeer(pid)) => {
                                        self.outbox.push_back(ProtocolBehaviourOut::NetworkAction(
                                            NetworkAction::BanPeer(pid),
                                        ));
                                    }
                                    ProtocolBehaviourOut::NetworkAction(_) => {}
                                },

                                Either::Right(commitments) => {
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
                        }
                        self.task = Some(AggregationTask {
                            state: AggregationState::AggregateSchnorrCommitments(st),
                            channel,
                        });
                    }
                    AggregationTask {
                        state: AggregationState::AggregateResponses(mut st),
                        channel,
                    } => {
                        match st.handel.poll(cx) {
                            Poll::Ready(out) => match out {
                                Either::Left(cmd) => match cmd {
                                    ProtocolBehaviourOut::Send { peer_id, message } => {
                                        self.outbox.push_back(ProtocolBehaviourOut::Send {
                                            peer_id,
                                            message: SigmaAggrMessage::SigmaAggrMessageV1(
                                                SigmaAggrMessageV1::Responses(message),
                                            ),
                                        });
                                    }
                                    ProtocolBehaviourOut::NetworkAction(NetworkAction::BanPeer(pid)) => {
                                        self.outbox.push_back(ProtocolBehaviourOut::NetworkAction(
                                            NetworkAction::BanPeer(pid),
                                        ));
                                    }
                                    ProtocolBehaviourOut::NetworkAction(_) => {}
                                },
                                Either::Right(responses) => {
                                    self.task = None;
                                    let res = st.complete(responses);
                                    // todo: support error case.
                                    if channel.send(Ok(res)).is_err() {
                                        // warn here.
                                    }
                                    continue;
                                }
                            },
                            Poll::Pending => {}
                        }
                        self.task = Some(AggregationTask {
                            state: AggregationState::AggregateResponses(st),
                            channel,
                        });
                    }
                }
            }
            return Poll::Pending;
        }
    }
}
