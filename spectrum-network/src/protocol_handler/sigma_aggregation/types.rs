use std::collections::HashMap;

use derive_more::Into;
use elliptic_curve::ScalarPrimitive;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::signature::*;
use k256::schnorr::{Signature, VerifyingKey};
use k256::{ProjectivePoint, PublicKey, Scalar, Secp256k1};
use serde::{Deserialize, Serialize};

use algebra_core::CommutativePartialSemigroup;
use spectrum_crypto::digest::{blake2b256_hash, Blake2b256Digest};
use spectrum_crypto::VerifiableAgainst;

use crate::protocol_handler::handel::partitioning::PeerIx;
use crate::protocol_handler::handel::Weighted;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Contributions<C>(HashMap<PeerIx, C>);

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

pub type SchnorrCommitments = Contributions<Blake2b256Digest>;

impl VerifiableAgainst<()> for SchnorrCommitments {
    fn verify(&self, _: &()) -> bool {
        true
    }
}

pub struct CommitmentsVerifInput {
    commitments: SchnorrCommitments,
    message: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, Into)]
#[serde(try_from = "Vec<u8>", into = "Vec<u8>")]
pub struct DlogProof(Signature);

impl TryFrom<Vec<u8>> for DlogProof {
    type Error = Error;
    fn try_from(value: Vec<u8>) -> std::result::Result<Self, Self::Error> {
        Signature::try_from(&*value).map(DlogProof)
    }
}

impl From<DlogProof> for Vec<u8> {
    fn from(DlogProof(sig): DlogProof) -> Self {
        <Vec<u8>>::from(sig.to_bytes())
    }
}

pub type DlogProofs = Contributions<(PublicKey, DlogProof)>;

impl VerifiableAgainst<CommitmentsVerifInput> for DlogProofs {
    fn verify(&self, public_data: &CommitmentsVerifInput) -> bool {
        self.0.iter().all(|(i, (point, sig))| {
            if let Some(commitment) = public_data.commitments.0.get(&i) {
                *commitment == blake2b256_hash(&point.to_encoded_point(false).to_bytes())
                    && VerifyingKey::try_from(point)
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
    dlog_proof: (PublicKey, DlogProof),
    pk: PublicKey,
    ai: ScalarPrimitive<Secp256k1>,
}

impl VerifiableAgainst<ResponsesVerifInput> for Responses {
    fn verify(&self, public_data: &ResponsesVerifInput) -> bool {
        self.0.iter().all(|(k, zi)| {
            public_data
                .individual_inputs
                .get(&k)
                .map(|input| {
                    let xi = input.pk.to_projective();
                    let yi = input.dlog_proof.0.to_projective();
                    let ai = &input.ai.into();
                    let c = &public_data.challenge.into();
                    ProjectivePoint::GENERATOR * zi == yi + xi * ai * c
                })
                .unwrap_or(false)
        })
    }
}
