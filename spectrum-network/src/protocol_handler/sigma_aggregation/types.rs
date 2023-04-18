use std::collections::HashMap;

use derive_more::Into;
use elliptic_curve::ScalarPrimitive;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::signature::*;
use k256::schnorr::VerifyingKey;
use k256::{ProjectivePoint, Scalar, Secp256k1, SecretKey};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use algebra_core::CommutativePartialSemigroup;
use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_crypto::VerifiableAgainst;

use crate::protocol_handler::handel::partitioning::PeerIx;
use crate::protocol_handler::handel::Weighted;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(k256::PublicKey);

impl From<SecretKey> for PublicKey {
    fn from(sk: SecretKey) -> Self {
        Self(sk.public_key())
    }
}

impl From<PublicKey> for k256::PublicKey {
    fn from(pk: PublicKey) -> Self {
        pk.0
    }
}

impl From<k256::PublicKey> for PublicKey {
    fn from(pk: k256::PublicKey) -> Self {
        Self(pk)
    }
}

impl From<PublicKey> for PeerId {
    fn from(pk: PublicKey) -> Self {
        let k256point = pk.0.to_encoded_point(true);
        let encoded_pk = k256point.as_bytes();
        PeerId::from_public_key(&libp2p_identity::PublicKey::Secp256k1(
            libp2p_identity::secp256k1::PublicKey::decode(encoded_pk).unwrap(),
        ))
    }
}

impl From<&PublicKey> for PeerId {
    fn from(pk: &PublicKey) -> Self {
        pk.clone().into()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Contributions<C>(HashMap<PeerIx, C>);

impl<C> Contributions<C> {
    pub fn unit(peer: PeerIx, c: C) -> Self {
        Self(HashMap::from([(peer, c)]))
    }
}

impl<C> CommutativePartialSemigroup for Contributions<C>
where
    C: Eq + Clone,
{
    fn try_combine(&self, that: &Self) -> Option<Self> {
        let mut bf = self.0.clone();
        for (k, v) in &that.0 {
            if let Some(v0) = bf.get(&k) {
                if v != v0 {
                    return None;
                }
            } else {
                bf.insert(*k, v.clone());
            }
        }
        Some(Self(bf))
    }
}

impl<C> Weighted for Contributions<C> {
    fn weight(&self) -> usize {
        self.0.len()
    }
}

pub type PreCommitments = Contributions<Blake2bDigest256>;

impl VerifiableAgainst<()> for PreCommitments {
    fn verify(&self, _: &()) -> bool {
        true
    }
}

pub struct CommitmentsVerifInput {
    commitments: PreCommitments,
    message: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Into)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct Signature(k256::schnorr::Signature);

impl From<k256::schnorr::Signature> for Signature {
    fn from(sig: k256::schnorr::Signature) -> Self {
        Self(sig)
    }
}

impl TryFrom<Vec<u8>> for Signature {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        k256::schnorr::Signature::try_from(&*value).map(Signature)
    }
}

impl From<Signature> for Vec<u8> {
    fn from(Signature(sig): Signature) -> Self {
        <Vec<u8>>::from(sig.to_bytes())
    }
}

pub type CommitmentsWithProofs = Contributions<(PublicKey, Signature)>;

impl VerifiableAgainst<CommitmentsVerifInput> for CommitmentsWithProofs {
    fn verify(&self, public_data: &CommitmentsVerifInput) -> bool {
        self.0.iter().all(|(i, (point, sig))| {
            if let Some(commitment) = public_data.commitments.0.get(&i) {
                *commitment == blake2b256_hash(&point.0.to_encoded_point(false).to_bytes())
                    && VerifyingKey::try_from(point.0)
                        .map(|vk| vk.verify(&public_data.message, &sig.0).is_ok())
                        .unwrap_or(false)
            } else {
                false
            }
        })
    }
}

pub type Responses = Contributions<Scalar>;

pub struct Committee(HashMap<PeerIx, PublicKey>);

pub struct ResponsesVerifInput {
    individual_inputs: HashMap<PeerIx, ResponseVerifInput>,
    challenge: ScalarPrimitive<Secp256k1>,
}

struct ResponseVerifInput {
    dlog_proof: (PublicKey, Signature),
    pk: PublicKey,
    ai: ScalarPrimitive<Secp256k1>,
}

impl VerifiableAgainst<ResponsesVerifInput> for Responses {
    fn verify(&self, public_data: &ResponsesVerifInput) -> bool {
        let c = &public_data.challenge.into();
        self.0.iter().all(|(k, zi)| {
            public_data
                .individual_inputs
                .get(&k)
                .map(|input| {
                    let xi = input.pk.0.to_projective();
                    let yi = input.dlog_proof.0 .0.to_projective();
                    let ai = &input.ai.into();
                    ProjectivePoint::GENERATOR * zi == yi + xi * ai * c
                })
                .unwrap_or(false)
        })
    }
}
