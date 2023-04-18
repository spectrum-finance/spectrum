use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};

use elliptic_curve::rand_core::OsRng;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::ScalarPrimitive;
use futures::channel::mpsc::Receiver;
use futures::Stream;
use k256::{Scalar, Secp256k1, SecretKey};
use libp2p::PeerId;

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256, Digest256};

use crate::protocol::SIGMA_AGGR_PROTOCOL_ID;
use crate::protocol_handler::aggregation::AggregationAction;
use crate::protocol_handler::handel::partitioning::{MakePeerPartitions, PeerIx, PeerPartitions};
use crate::protocol_handler::handel::{Handel, HandelConfig};
use crate::protocol_handler::sigma_aggregation::crypto::{
    gen_exclusion_proof, gen_pre_commitment, gen_schnorr_commitment,
};
use crate::protocol_handler::sigma_aggregation::message::{SigmaAggrMessage, SigmaAggrSpec};
use crate::protocol_handler::sigma_aggregation::types::{
    CommitmentsWithProofs, Contributions, PreCommitments, PublicKey, Responses, Signature,
};
use crate::protocol_handler::{MalformedMessage, ProtocolBehaviour, ProtocolBehaviourOut};
use crate::types::ProtocolId;

mod crypto;
mod message;
pub mod types;

struct AggregatePreCommitments<H, PP> {
    /// `x_i`
    host_sk: SecretKey,
    /// `{X_1, X_2, ..., X_n}`. Set of public keys of committee members.
    committee: HashSet<PublicKey>,
    /// `a_i = H(X_1, X_2, ..., X_n; X_i)`
    ai_set: HashMap<PeerIx, ScalarPrimitive<Secp256k1>>,
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

struct AggregateSchnorrCommitments<H, PP> {
    committee: HashSet<PublicKey>,
    partitions: PP,
    ai_set: HashMap<PeerIx, ScalarPrimitive<Secp256k1>>,
    message_digest: Digest256<H>,
    commitment: PublicKey,
    explusion_proof: Signature,
    pre_commitments: PreCommitments,
}

struct AggregateResponses<H, PP> {
    committee: HashSet<PublicKey>,
    partitions: PP,
    ai_set: HashMap<PeerIx, ScalarPrimitive<Secp256k1>>,
    message_digest: Digest256<H>,
    commitment: PublicKey,
    explusion_proof: Signature,
    pre_commitments: PreCommitments,
    commitments_with_proofs: CommitmentsWithProofs,
    aggregate_commitment: PublicKey,
    challenge: ScalarPrimitive<Secp256k1>,
    contributions: Responses,
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

impl<H, PP> AggregationState<H, PP>
where
    PP: PeerPartitions,
{
    fn init<MPP: MakePeerPartitions<PP = PP>>(
        host_sk: SecretKey,
        committee: HashSet<PublicKey>,
        message_digest: Digest256<H>,
        partitioner: MPP,
        handel_conf: HandelConfig,
    ) -> AggregationState<H, PP> {
        let host_pk = PublicKey::from(host_sk.clone());
        let host_pid = PeerId::from(host_pk);
        let peers = committee.iter().map(PeerId::from).collect();
        let partitions = partitioner.make(host_pid, peers);
        let host_secret = SecretKey::random(&mut OsRng);
        let host_commitment = gen_schnorr_commitment(host_secret.clone());
        let host_pre_commitment = gen_pre_commitment(host_commitment.clone());
        let host_ix = partitions.try_index_peer(host_pid).unwrap();
        AggregationState::AggregatePreCommitments(AggregatePreCommitments {
            host_sk,
            committee,
            ai_set: Default::default(),
            message_digest: message_digest.clone(),
            host_secret: host_secret.clone(),
            host_commitment,
            host_explusion_proof: gen_exclusion_proof(host_secret, message_digest),
            host_pre_commitment,
            process: Handel::new(
                handel_conf,
                Contributions::unit(host_ix, host_pre_commitment),
                (),
                partitions,
            ),
        })
    }
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
                        self.state = AggregationState::init(
                            self.host_sk.clone(),
                            new_committee,
                            new_message,
                            self.partitioner.clone(),
                            self.handel_conf.clone(),
                        );
                    }
                }
            }
        }
    }
}
