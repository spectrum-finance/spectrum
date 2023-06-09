use std::collections::HashMap;
use std::hash::{Hash, Hasher};

use derive_more::Into;
use elliptic_curve::rand_core::OsRng;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::signature::*;
use k256::schnorr::VerifyingKey;
use k256::{ProjectivePoint, Scalar, SecretKey};
use serde::{Deserialize, Serialize};

use algebra_core::CommutativePartialSemigroup;
use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_crypto::pubkey::PublicKey;
use spectrum_crypto::{PVResult, VerifiableAgainst};

use crate::protocol_handler::handel::partitioning::PeerIx;
use crate::protocol_handler::handel::Weighted;
use crate::protocol_handler::sigma_aggregation::crypto::verify_response;

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, derive_more::From, derive_more::Into)]
pub struct AggregateCommitment(PublicKey);

impl AggregateCommitment {
    pub fn to_bytes(self) -> Vec<u8> {
        let point = k256::PublicKey::from(self.0).to_encoded_point(true);
        point.as_bytes().to_vec()
    }
}

impl From<ProjectivePoint> for AggregateCommitment {
    fn from(p: ProjectivePoint) -> Self {
        Self(PublicKey::from(k256::PublicKey::try_from(p).unwrap()))
    }
}

impl From<AggregateCommitment> for ProjectivePoint {
    fn from(AggregateCommitment(pk): AggregateCommitment) -> Self {
        k256::PublicKey::from(pk).to_projective()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, derive_more::From, derive_more::Into)]
pub struct Commitment(VerifyingKey);

impl Commitment {
    pub fn as_bytes(&self) -> Vec<u8> {
        let point = k256::PublicKey::from(self.0).to_encoded_point(true);
        point.as_bytes().to_vec()
    }
}

impl Hash for Commitment {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&*self.as_bytes())
    }
}

impl TryFrom<ProjectivePoint> for Commitment {
    type Error = Error;
    fn try_from(point: ProjectivePoint) -> std::result::Result<Self, Self::Error> {
        k256::PublicKey::try_from(point)
            .map_err(|_| Error::new())
            .and_then(VerifyingKey::try_from)
            .map(Self)
    }
}

impl From<Commitment> for ProjectivePoint {
    fn from(Commitment(vk): Commitment) -> Self {
        ProjectivePoint::from(k256::PublicKey::from(vk))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, derive_more::From, derive_more::Into)]
pub struct CommitmentSecret(SecretKey);

impl CommitmentSecret {
    pub fn random() -> Self {
        Self(SecretKey::random(&mut OsRng))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Contributions<C>(HashMap<PeerIx, C>);

impl<C> Contributions<C> {
    pub fn unit(peer: PeerIx, c: C) -> Self {
        Self(HashMap::from([(peer, c)]))
    }

    pub fn entries(&self) -> Vec<(PeerIx, C)>
    where
        C: Clone,
    {
        self.0.iter().map(|(k, v)| (*k, v.clone())).collect()
    }

    pub fn values(&self) -> Vec<C>
    where
        C: Clone,
    {
        self.0.values().map(|v| v.clone()).collect()
    }

    pub fn get(&self, peer: &PeerIx) -> Option<&C> {
        self.0.get(peer)
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
    fn verify(self, _: &()) -> PVResult<Self> {
        PVResult::Valid {
            contribution: self,
            partially: false,
        }
    }
}

pub struct CommitmentsVerifInput {
    pub pre_commitments: PreCommitments,
    pub message_digest_bytes: Vec<u8>,
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

pub type CommitmentsWithProofs = Contributions<(Commitment, Signature)>;

impl VerifiableAgainst<CommitmentsVerifInput> for CommitmentsWithProofs {
    fn verify(self, public_data: &CommitmentsVerifInput) -> PVResult<Self> {
        let contrib_len = self.0.len();
        let mut aggr = HashMap::new();
        let mut missing_parts = 0;
        for (i, (commitment, sig)) in self.0 {
            if let Some(pre_commitment) = public_data.pre_commitments.0.get(&i) {
                let vk = VerifyingKey::from(commitment.clone());
                let verified = *pre_commitment == blake2b256_hash(&*commitment.as_bytes())
                    && vk.verify(&public_data.message_digest_bytes, &sig.0).is_ok();
                if !verified {
                    return PVResult::Invalid;
                }
                aggr.insert(i, (commitment, sig));
            } else {
                missing_parts += 1;
            }
            if contrib_len > 1 && missing_parts * 2 > contrib_len {
                // More than 50% of aggregate is invalid.
                return PVResult::Invalid;
            }
        }
        PVResult::Valid {
            contribution: Contributions(aggr),
            partially: missing_parts > 0,
        }
    }
}

pub type Responses = Contributions<Scalar>;

pub struct ResponsesVerifInput {
    inputs: HashMap<PeerIx, ResponseVerifInput>,
    challenge: Scalar,
}

impl ResponsesVerifInput {
    pub fn new(
        commitments: CommitmentsWithProofs,
        committee: HashMap<PeerIx, PublicKey>,
        individual_inputs: HashMap<PeerIx, Scalar>,
        challenge: Scalar,
    ) -> Self {
        let mut inputs = HashMap::new();
        for (pix, (yi, _)) in commitments.0 {
            if let Some(xi) = committee.get(&pix) {
                if let Some(ii) = individual_inputs.get(&pix) {
                    inputs.insert(
                        pix,
                        ResponseVerifInput {
                            commitment: yi,
                            pk: xi.clone(),
                            individual_input: *ii,
                        },
                    );
                }
            }
        }
        Self { inputs, challenge }
    }
}

struct ResponseVerifInput {
    commitment: Commitment,
    pk: PublicKey,
    individual_input: Scalar,
}

impl VerifiableAgainst<ResponsesVerifInput> for Responses {
    fn verify(self, public_data: &ResponsesVerifInput) -> PVResult<Self> {
        let c = &public_data.challenge;
        let contrib_len = self.0.len();
        let mut aggr = HashMap::new();
        let mut missing_parts = 0;
        for (k, zi) in self.0 {
            if let Some(input) = public_data.inputs.get(&k) {
                let ai = &input.individual_input.into();
                let verified = verify_response(&zi, ai, c, input.commitment.clone(), input.pk.clone());
                if verified {
                    aggr.insert(k, zi);
                }
            } else {
                missing_parts += 1;
            }
            if contrib_len > 1 && missing_parts * 2 > contrib_len {
                // More than 50% of aggregate is invalid.
                return PVResult::Invalid;
            }
        }
        PVResult::Valid {
            contribution: Contributions(aggr),
            partially: missing_parts > 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use elliptic_curve::rand_core::OsRng;
    use elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn libp2p_pk_is_compatible() {
        let host_secret = k256::SecretKey::random(&mut OsRng);
        let k256_pk = host_secret.public_key();
        let k256_point = k256_pk.to_encoded_point(true);
        let k256_encoded = k256_point.as_bytes();
        let libp2p_pk = libp2p_identity::secp256k1::PublicKey::decode(k256_encoded).unwrap();
        assert_eq!(libp2p_pk.encode(), k256_encoded)
    }
}
