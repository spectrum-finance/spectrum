use digest::{FixedOutput, HashMarker};
use elliptic_curve::{Curve, ScalarPrimitive};
use elliptic_curve::rand_core::OsRng;
use k256::{ProjectivePoint, Scalar, Secp256k1, SecretKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::{SigningKey, VerifyingKey};
use k256::schnorr::signature::{Signer, Verifier};

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256, Digest};
use spectrum_crypto::pubkey::PublicKey;
use spectrum_handel::Threshold;

use crate::{AggregateCommitment, Commitment, CommitmentSecret, Signature};

/// `a_i = H(X_1, X_2, ..., X_n; X_i)`
pub fn individual_input<H>(committee: Vec<PublicKey>, pki: PublicKey) -> Scalar where
    H: HashMarker + FixedOutput<OutputSize = <Secp256k1 as Curve>::FieldBytesSize> + Default,{
    use digest::Digest;
    let mut hasher = H::new();
    for pk in committee {
        let bytes = k256::PublicKey::from(pk).to_encoded_point(true).to_bytes();
        hasher.update(&*bytes);
    }
    let pki_bytes = k256::PublicKey::from(pki).to_encoded_point(true).to_bytes();
    hasher.update(&*pki_bytes);
    ScalarPrimitive::from_bytes(&hasher.finalize_fixed())
        .unwrap()
        .into()
}

/// `˜X = Π_iX_i^{a_i}`
pub fn aggregate_pk(committee: Vec<PublicKey>, individual_inputs: Vec<Scalar>) -> PublicKey {
    PublicKey::from(
        k256::PublicKey::try_from(
            committee
                .into_iter()
                .enumerate()
                .map(|(i, xi)| k256::PublicKey::from(xi.clone()).to_projective() * individual_inputs[i])
                .sum::<ProjectivePoint>(),
        )
            .unwrap(),
    )
}

/// `Y = Π_iY_i`
pub fn aggregate_commitment(individual_commitments: Vec<Commitment>) -> AggregateCommitment {
    AggregateCommitment::try_from(
        individual_commitments
            .into_iter()
            .map(|yi| ProjectivePoint::from(yi))
            .sum::<ProjectivePoint>(),
    )
        .unwrap()
}

/// `r = Σ_ir_i`
pub fn aggregate_response(individual_responses: Vec<Scalar>) -> Scalar {
    individual_responses.into_iter().sum()
}

/// `c = H(˜X, Y, m)`
pub fn challenge<H>(aggr_pk: PublicKey, aggr_commitment: AggregateCommitment, md: Digest<H>) -> Scalar
    where
        H: HashMarker + FixedOutput<OutputSize = <Secp256k1 as Curve>::FieldBytesSize> + Default,
{
    use digest::Digest;
    let mut hasher = H::new();
    hasher.update(&*k256::PublicKey::from(aggr_pk).to_encoded_point(true).to_bytes());
    hasher.update(&*aggr_commitment.to_bytes());
    hasher.update(md.as_ref());
    ScalarPrimitive::from_bytes(&hasher.finalize_fixed())
        .unwrap()
        .into()
}

/// `y_i, Y_i`
pub fn schnorr_commitment_pair() -> (CommitmentSecret, Commitment) {
    let mut rng = OsRng;
    loop {
        let commitment_sk = CommitmentSecret::from(SecretKey::random(&mut rng));
        let commitment = schnorr_commitment(commitment_sk.clone());
        if let Some(r) = commitment.map(|c| (commitment_sk, c)) {
            return r;
        }
    }
}

/// `Y_i = g^{y_i}`
fn schnorr_commitment(sk: CommitmentSecret) -> Option<Commitment> {
    let point = ProjectivePoint::GENERATOR * Scalar::from(k256::SecretKey::from(sk).as_scalar_primitive());
    point.try_into().ok()
}

/// `σ_i`
pub fn exclusion_proof<H: HashMarker + FixedOutput>(sk: CommitmentSecret, md: Digest<H>) -> Signature {
    SigningKey::from(&k256::SecretKey::from(sk))
        .sign(&md.as_ref())
        .into()
}

/// `t_i = H(Y_i)`
pub fn pre_commitment(pk: Commitment) -> Blake2bDigest256 {
    blake2b256_hash(&*pk.as_bytes())
}

/// `z_i = y_i + c * a_i * x_i`
pub fn response(
    host_commitment_sk: CommitmentSecret,
    host_sk: SecretKey,
    challenge: Scalar,
    individual_input: Scalar,
) -> Scalar {
    let yi = Scalar::from(k256::SecretKey::from(host_commitment_sk).as_scalar_primitive());
    let xi = Scalar::from(host_sk.as_scalar_primitive());
    let ai = individual_input;
    let c = challenge;
    yi + c * ai * xi
}

/// `g^{z_i} = Y_i * X^{a_i * c}`
pub fn verify_response(
    z: &Scalar,
    a: &Scalar,
    challenge: &Scalar,
    commitment: Commitment,
    pk: PublicKey,
) -> bool {
    let x = k256::PublicKey::from(pk).to_projective();
    let y = ProjectivePoint::from(commitment);
    ProjectivePoint::GENERATOR * z == y + x * a * challenge
}

pub fn verify<H>(
    aggregate_commitment: AggregateCommitment,
    aggregate_response: Scalar,
    exclusion_set: Vec<(usize, Option<(Commitment, Signature)>)>,
    committee: Vec<PublicKey>,
    md: Digest<H>,
    threshold: Threshold,
) -> bool where H: HashMarker + FixedOutput<OutputSize = <Secp256k1 as Curve>::FieldBytesSize> + Default {
    let individual_inputs = committee
        .iter()
        .map(|x| individual_input::<H>(committee.clone(), x.clone()))
        .collect::<Vec<_>>();
    let aggregate_x = aggregate_pk(committee.clone(), individual_inputs.clone());
    let partial_x: ProjectivePoint = committee
        .iter()
        .enumerate()
        .filter_map(|(i, x)| {
            if exclusion_set.iter().find(|(ex_i, _)| *ex_i == i).is_none() {
                Some(k256::PublicKey::from(x.clone()).to_projective() * individual_inputs[i])
            } else {
                None
            }
        })
        .sum();
    let excluded_y: ProjectivePoint = exclusion_set
        .iter()
        .filter_map(|(_, maybe_yi)| maybe_yi.as_ref().map(|(yi, _)| ProjectivePoint::from(yi.clone())))
        .sum();
    let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
    let aggregate_commitment_point = ProjectivePoint::from(aggregate_commitment);
    if ProjectivePoint::GENERATOR * aggregate_response
        != partial_x * challenge + aggregate_commitment_point - excluded_y
    {
        return false;
    }
    for (_, maybe_pair) in exclusion_set.clone() {
        if !maybe_pair
            .map(|(yi, proof)| {
                VerifyingKey::from(yi)
                    .verify(&md.as_ref(), &k256::schnorr::Signature::from(proof))
                    .is_ok()
            })
            .unwrap_or(true)
        {
            return false;
        }
    }
    let num_succeeded_committees = committee.len() - exclusion_set.len();
    num_succeeded_committees >= threshold.min(committee.len())
}

#[cfg(test)]
mod tests {
    use blake2::Blake2b;
    use digest::consts::U32;
    use elliptic_curve::rand_core::OsRng;
    use k256::SecretKey;
    use rand::Rng;

    use spectrum_crypto::digest::blake2b256_hash;
    use spectrum_crypto::pubkey::PublicKey;

    use crate::protocol_handler::handel::Threshold;
    use crate::protocol_handler::sigma_aggregation::crypto::{
        aggregate_commitment, aggregate_pk, aggregate_response, challenge, exclusion_proof, individual_input,
        response, schnorr_commitment_pair, verify, verify_response,
    };

    #[test]
    fn uniqie_individual_inputs() {
        let num_participants = 16;
        let mut rng = OsRng;
        let committee = (0..num_participants)
            .into_iter()
            .map(|_| {
                let sk = SecretKey::random(&mut rng);
                PublicKey::from(sk.public_key())
            })
            .collect::<Vec<_>>();
        let ii0 = individual_input::<Blake2b<U32>>(committee.clone(), committee[0].clone());
        let ii1 = individual_input::<Blake2b<U32>>(committee[1..].to_vec(), committee[0].clone());
        assert_ne!(ii0, ii1)
    }

    #[test]
    fn aggregation_with_byzantine_nodes_before_commit() {
        let num_participants = 16;
        let num_byzantine_before_commit = 2;
        let num_byzantine_on_response = 2;
        let mut rng = OsRng;
        let mut byz_indexes = vec![];
        loop {
            let rng = rng.gen_range(0usize..num_participants);
            if !byz_indexes.contains(&rng) {
                byz_indexes.push(rng);
            }
            if byz_indexes.len() == num_byzantine_before_commit + num_byzantine_on_response {
                break;
            }
        }
        let (byz_peers_commit, byz_peer_response) = (
            byz_indexes[..num_byzantine_before_commit].to_vec(),
            byz_indexes[num_byzantine_before_commit..].to_vec(),
        );
        let md = blake2b256_hash(b"foo");
        let committee_keys = (0..num_participants)
            .into_iter()
            .map(|_| {
                let sk = SecretKey::random(&mut rng);
                let pk = PublicKey::from(sk.public_key());
                (sk, pk)
            })
            .collect::<Vec<_>>();
        let committee = committee_keys
            .iter()
            .map(|(_, pk)| pk.clone())
            .collect::<Vec<_>>();
        let individual_inputs = committee
            .iter()
            .map(|pk| individual_input::<Blake2b<U32>>(committee.clone(), pk.clone()))
            .collect::<Vec<_>>();
        let aggregate_x = aggregate_pk(
            committee.iter().map(|pk| pk.clone()).collect(),
            individual_inputs.clone(),
        );
        let commitment_keys = committee
            .iter()
            .enumerate()
            .map(|(i, _)| {
                if byz_peers_commit.contains(&i) {
                    None
                } else {
                    Some(schnorr_commitment_pair())
                }
            })
            .collect::<Vec<_>>();
        let individual_commitments = commitment_keys
            .iter()
            .filter_map(|pair| pair.as_ref().map(|(_, c)| c.clone()))
            .collect::<Vec<_>>();
        let aggregate_commitment = aggregate_commitment(individual_commitments);
        let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
        let individual_responses_subset = committee_keys
            .iter()
            .zip(commitment_keys.clone())
            .enumerate()
            .map(|(i, ((sk, _), maybe_commitment_pair))| {
                maybe_commitment_pair.and_then(|(commitment_sk, _)| {
                    if byz_peer_response.contains(&i) {
                        None
                    } else {
                        Some((
                            i,
                            response(commitment_sk.clone(), sk.clone(), challenge, individual_inputs[i]),
                        ))
                    }
                })
            })
            .collect::<Vec<_>>();
        for (i, maybe_response) in individual_responses_subset.iter().enumerate() {
            if let Some((_, zi)) = maybe_response {
                if let Some((_, commitment)) = commitment_keys[i].clone() {
                    assert!(verify_response(
                        zi,
                        &individual_inputs[i],
                        &challenge,
                        commitment.clone(),
                        committee[i].clone()
                    ))
                }
            }
        }
        let aggregate_response = aggregate_response(
            individual_responses_subset
                .into_iter()
                .filter_map(|pair| pair.map(|(_, z)| z))
                .collect(),
        );
        let exclusion_set = committee
            .iter()
            .enumerate()
            .filter_map(|(i, _)| {
                if byz_peers_commit.contains(&i) {
                    Some((i, None))
                } else if byz_peer_response.contains(&i) {
                    let (sk, c) = commitment_keys[i].clone().unwrap();
                    Some((i, Some((c, exclusion_proof(sk, md)))))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert!(verify(
            aggregate_commitment,
            aggregate_response,
            exclusion_set,
            committee,
            md,
            Threshold { num: 2, denom: 3 }
        ))
    }

    #[test]
    fn aggregation_with_byzantine_nodes_on_response() {
        let num_participants = 16;
        let num_byzantine = 2;
        let mut rng = OsRng;
        let mut byz_indexes = vec![];
        loop {
            let rng = rng.gen_range(0usize..num_participants);
            if !byz_indexes.contains(&rng) {
                byz_indexes.push(rng);
            }
            if byz_indexes.len() == num_byzantine {
                break;
            }
        }
        let md = blake2b256_hash(b"foo");
        let individual_keys = (0..num_participants)
            .into_iter()
            .map(|_| {
                let sk = SecretKey::random(&mut rng);
                let pk = PublicKey::from(sk.public_key());
                let (commitment_sk, commitment) = schnorr_commitment_pair();
                (sk, pk, commitment_sk, commitment)
            })
            .collect::<Vec<_>>();
        let committee = individual_keys
            .iter()
            .map(|(_, pk, _, _)| pk.clone())
            .collect::<Vec<_>>();
        let individual_inputs = individual_keys
            .iter()
            .map(|(_, pki, _, _)| individual_input::<Blake2b<U32>>(committee.clone(), pki.clone()))
            .collect::<Vec<_>>();
        let aggregate_x = aggregate_pk(
            individual_keys.iter().map(|(_, pk, _, _)| pk.clone()).collect(),
            individual_inputs.clone(),
        );
        let aggregate_commitment = aggregate_commitment(
            individual_keys
                .iter()
                .map(|(_, _, _, commitment)| commitment.clone())
                .collect(),
        );
        let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
        let (byz_keys, active_keys): (Vec<_>, Vec<_>) = individual_keys
            .clone()
            .into_iter()
            .enumerate()
            .partition(|(i, _)| byz_indexes.contains(i));
        let individual_responses_subset = active_keys
            .iter()
            .map(|(i, (sk, _, commitment_sk, _))| {
                (
                    *i,
                    response(
                        commitment_sk.clone(),
                        sk.clone(),
                        challenge,
                        individual_inputs[*i],
                    ),
                )
            })
            .collect::<Vec<_>>();
        for (i, zi) in individual_responses_subset.iter() {
            let (_, pk, _, commitment) = &individual_keys[*i];
            assert!(verify_response(
                zi,
                &individual_inputs[*i],
                &challenge,
                commitment.clone(),
                pk.clone()
            ))
        }
        let aggregate_response =
            aggregate_response(individual_responses_subset.into_iter().map(|(_, x)| x).collect());
        let exclusion_set = byz_keys
            .iter()
            .map(|(i, (_, _, sk, commitment))| {
                (*i, Some((commitment.clone(), exclusion_proof(sk.clone(), md))))
            })
            .collect::<Vec<_>>();
        assert!(verify(
            aggregate_commitment,
            aggregate_response,
            exclusion_set,
            committee,
            md,
            Threshold { num: 2, denom: 3 }
        ))
    }

    #[test]
    fn aggregation_ideal() {
        let num_participants = 16;
        let mut rng = OsRng;
        let md = blake2b256_hash(b"foo");
        let individual_keys = (0..num_participants)
            .into_iter()
            .map(|_| {
                let sk = SecretKey::random(&mut rng);
                let pk = PublicKey::from(sk.public_key());
                let (commitment_sk, commitment) = schnorr_commitment_pair();
                (sk, pk, commitment_sk, commitment)
            })
            .collect::<Vec<_>>();
        let committee = individual_keys
            .iter()
            .map(|(_, pk, _, _)| pk.clone())
            .collect::<Vec<_>>();
        let individual_inputs = individual_keys
            .iter()
            .map(|(_, pki, _, _)| individual_input::<Blake2b<U32>>(committee.clone(), pki.clone()))
            .collect::<Vec<_>>();
        let aggregate_x = aggregate_pk(
            individual_keys.iter().map(|(_, pk, _, _)| pk.clone()).collect(),
            individual_inputs.clone(),
        );
        let aggregate_commitment = aggregate_commitment(
            individual_keys
                .iter()
                .map(|(_, _, _, commitment)| commitment.clone())
                .collect(),
        );
        let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
        let individual_responses = individual_keys
            .iter()
            .enumerate()
            .map(|(i, (sk, pk, commitment_sk, _))| {
                response(commitment_sk.clone(), sk.clone(), challenge, individual_inputs[i])
            })
            .collect::<Vec<_>>();

        for (i, zi) in individual_responses.iter().enumerate() {
            let (_, pk, _, commitment) = &individual_keys[i];
            assert!(verify_response(
                zi,
                &individual_inputs[i],
                &challenge,
                commitment.clone(),
                pk.clone()
            ))
        }

        let aggregate_response = aggregate_response(individual_responses);
        assert!(verify(
            aggregate_commitment,
            aggregate_response,
            Vec::new(),
            committee,
            md,
            Threshold { num: 1, denom: 1 }
        ))
    }
}
