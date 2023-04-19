use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use elliptic_curve::rand_core::OsRng;
use futures::channel::mpsc::Receiver;
use futures::Stream;
use k256::{Scalar, SecretKey};
use libp2p::PeerId;
use nonempty::NonEmpty;

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256, Digest256};

use crate::protocol::SIGMA_AGGR_PROTOCOL_ID;
use crate::protocol_handler::aggregation::AggregationAction;
use crate::protocol_handler::handel::partitioning::{MakePeerPartitions, PeerIx, PeerPartitions};
use crate::protocol_handler::handel::{Handel, HandelConfig};
use crate::protocol_handler::sigma_aggregation::crypto::{
    aggregate, challenge, exclusion_proof, individual_input, pre_commitment, response, schnorr_commitment,
};
use crate::protocol_handler::sigma_aggregation::message::{SigmaAggrMessage, SigmaAggrSpec};
use crate::protocol_handler::sigma_aggregation::types::{
    CommitmentsVerifInput, CommitmentsWithProofs, Contributions, PreCommitments, PublicKey, Responses,
    ResponsesVerifInput, Signature,
};
use crate::protocol_handler::{MalformedMessage, ProtocolBehaviour, ProtocolBehaviourOut};
use crate::types::ProtocolId;

mod crypto;
mod message;
pub mod types;

struct AggregatePreCommitments<H, PP> {
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
    host_secret: SecretKey,
    /// `Y_i = g^{y_i}`
    host_commitment: PublicKey,
    /// `σ_i`. Dlog proof of knowledge of `Y_i`.
    host_explusion_proof: Signature,
    /// `t_i = H(Y_i)`. Hash type of host pre-commitment is fixed.
    host_pre_commitment: Blake2bDigest256,
    process: Handel<PreCommitments, (), PP>,
}

impl<H, PP> AggregatePreCommitments<H, PP>
where
    PP: PeerPartitions,
{
    fn init<MPP: MakePeerPartitions<PP = PP>>(
        host_sk: SecretKey,
        committee: HashSet<PublicKey>,
        message_digest: Digest256<H>,
        partitioner: MPP,
        handel_conf: HandelConfig,
    ) -> AggregatePreCommitments<H, PP> {
        let host_pk = PublicKey::from(host_sk.clone());
        let host_pid = PeerId::from(host_pk);
        let peers = committee.iter().map(PeerId::from).collect();
        let partitions = partitioner.make(host_pid, peers);
        let commitee_indexed = committee
            .iter()
            .map(|pk| {
                let pid = PeerId::from(pk);
                let pix = partitions.try_index_peer(pid).unwrap();
                (pix, pk.clone())
            })
            .collect::<HashMap<_, _>>();
        let ais = commitee_indexed
            .iter()
            .map(|(pix, pk)| {
                (
                    *pix,
                    individual_input(committee.clone().into_iter().collect(), pk.clone()),
                )
            })
            .collect();
        let host_secret = SecretKey::random(&mut OsRng);
        let host_commitment = schnorr_commitment(host_secret.clone());
        let host_pre_commitment = pre_commitment(host_commitment.clone());
        let host_ix = partitions.try_index_peer(host_pid).unwrap();
        AggregatePreCommitments {
            host_sk,
            host_ix,
            committee: commitee_indexed,
            individual_inputs: ais,
            message_digest: message_digest.clone(),
            host_secret: host_secret.clone(),
            host_commitment,
            host_explusion_proof: exclusion_proof(host_secret, message_digest),
            host_pre_commitment,
            process: Handel::new(
                handel_conf,
                Contributions::unit(host_ix, host_pre_commitment),
                (),
                partitions,
            ),
        }
    }

    fn complete(
        self,
        pre_commitments: PreCommitments,
        handel_conf: HandelConfig,
        partitions: PP,
    ) -> AggregateSchnorrCommitments<H, PP> {
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
            host_pre_commitment: self.host_pre_commitment,
            process: Handel::new(
                handel_conf,
                Contributions::unit(self.host_ix, (self.host_commitment, self.host_explusion_proof)),
                verif_input,
                partitions,
            ),
        }
    }
}

struct AggregateSchnorrCommitments<H, PP> {
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
    host_secret: SecretKey,
    /// `Y_i = g^{y_i}`
    host_commitment: PublicKey,
    /// `σ_i`. Dlog proof of knowledge of `Y_i`.
    host_explusion_proof: Signature,
    /// `t_i = H(Y_i)`. Hash type of host pre-commitment is fixed.
    host_pre_commitment: Blake2bDigest256,
    process: Handel<CommitmentsWithProofs, CommitmentsVerifInput, PP>,
}

impl<H, PP> AggregateSchnorrCommitments<H, PP>
where
    PP: PeerPartitions,
{
    fn complete(
        self,
        commitments_with_proofs: CommitmentsWithProofs,
        handel_conf: HandelConfig,
        partitions: PP,
    ) -> AggregateResponses<H, PP> {
        let aggr_pk = aggregate(NonEmpty::from_vec(self.committee.values().cloned().collect()).unwrap());
        let aggr_commitment = aggregate(
            NonEmpty::from_vec(
                commitments_with_proofs
                    .values()
                    .into_iter()
                    .map(|(xi, _)| xi.clone())
                    .collect(),
            )
            .unwrap(),
        );
        let challenge = challenge(aggr_pk, aggr_commitment, self.message_digest);
        let individual_input = self.individual_inputs.get(&self.host_ix).unwrap().clone();
        let host_response = response(
            self.host_secret.clone(),
            self.host_sk.clone(),
            challenge,
            individual_input,
        );
        let verif_inputs = ResponsesVerifInput::new(
            commitments_with_proofs,
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
            host_explusion_proof: self.host_explusion_proof,
            host_pre_commitment: self.host_pre_commitment,
            process: Handel::new(
                handel_conf,
                Contributions::unit(self.host_ix, host_response),
                verif_inputs,
                partitions,
            ),
        }
    }
}

struct AggregateResponses<H, PP> {
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
    host_secret: SecretKey,
    /// `Y_i = g^{y_i}`
    host_commitment: PublicKey,
    /// `σ_i`. Dlog proof of knowledge of `Y_i`.
    host_explusion_proof: Signature,
    /// `t_i = H(Y_i)`. Hash type of host pre-commitment is fixed.
    host_pre_commitment: Blake2bDigest256,
    process: Handel<Responses, ResponsesVerifInput, PP>,
}

struct Aggregated<H> {
    message_digest: Digest256<H>,
    aggregate_commitment: PublicKey,
    aggregate_response: Scalar,
    exclusion_proof: HashMap<PublicKey, Signature>,
}

enum AggregationState<H, PP> {
    AggregatePreCommitments(AggregatePreCommitments<H, PP>),
    AggregateSchnorrCommitments(AggregateSchnorrCommitments<H, PP>),
    AggregateResponses(AggregateResponses<H, PP>),
    Aggregated(Aggregated<H>),
}

pub struct SigmaAggregation<H, MPP>
where
    MPP: MakePeerPartitions + Clone,
{
    host_sk: SecretKey,
    handel_conf: HandelConfig,
    state: AggregationState<H, MPP::PP>,
    partitioner: MPP,
    inbox: Receiver<AggregationAction<H>>,
    outbox: VecDeque<ProtocolBehaviourOut<SigmaAggrMessage, SigmaAggrMessage>>,
}

impl<H, MPP> ProtocolBehaviour for SigmaAggregation<H, MPP>
where
    MPP: MakePeerPartitions + Clone,
{
    type TProto = SigmaAggrSpec;

    fn get_protocol_id(&self) -> ProtocolId {
        SIGMA_AGGR_PROTOCOL_ID
    }

    fn inject_peer_connected(&mut self, peer_id: PeerId) {
        todo!()
    }

    fn inject_message(&mut self, peer_id: PeerId, content: SigmaAggrMessage) {
        todo!()
    }

    fn inject_malformed_mesage(&mut self, peer_id: PeerId, details: MalformedMessage) {
        todo!()
    }

    fn inject_protocol_requested(&mut self, peer_id: PeerId, handshake: Option<SigmaAggrMessage>) {
        todo!()
    }

    fn inject_protocol_requested_locally(&mut self, peer_id: PeerId) {}

    fn inject_protocol_enabled(&mut self, peer_id: PeerId, handshake: Option<SigmaAggrMessage>) {
        todo!()
    }

    fn inject_protocol_disabled(&mut self, peer_id: PeerId) {
        todo!()
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
                    } => {
                        self.state =
                            AggregationState::AggregatePreCommitments(AggregatePreCommitments::init(
                                self.host_sk.clone(),
                                new_committee,
                                new_message,
                                self.partitioner.clone(),
                                self.handel_conf.clone(),
                            ));
                    }
                }
            }
        }
    }
}
