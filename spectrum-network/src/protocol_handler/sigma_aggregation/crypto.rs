use blake2::digest::typenum::U32;
use blake2::Blake2b;
use blake2::Digest;
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::ScalarPrimitive;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::signature::{Signer, Verifier};
use k256::schnorr::{SigningKey, VerifyingKey};
use k256::{ProjectivePoint, Scalar, SecretKey};
use nonempty::NonEmpty;

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256, Digest256};

use crate::protocol_handler::handel::Threshold;
use crate::protocol_handler::sigma_aggregation::types::{PublicKey, Signature};

type Blake2b256 = Blake2b<U32>;

/// `a_i = H(X_1, X_2, ..., X_n; X_i)`
pub fn individual_input(committee: Vec<PublicKey>, pki: PublicKey) -> Scalar {
    let mut hasher = Blake2b256::new();
    for pk in committee {
        let bytes = k256::PublicKey::from(pk).to_encoded_point(true).to_bytes();
        hasher.update(bytes);
    }
    let pki_bytes = k256::PublicKey::from(pki).to_encoded_point(true).to_bytes();
    hasher.update(pki_bytes);
    let hash: [u8; 32] = hasher.finalize().into();
    ScalarPrimitive::from_bytes(GenericArray::from_slice(&hash))
        .unwrap()
        .into()
}

/// `X = Π_iX_i^{a_i}`
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

/// `X = Π_iY_i`
pub fn aggregate_commitment(individual_commitments: Vec<PublicKey>) -> PublicKey {
    PublicKey::from(
        k256::PublicKey::try_from(
            individual_commitments
                .into_iter()
                .enumerate()
                .map(|(i, yi)| k256::PublicKey::from(yi.clone()).to_projective())
                .sum::<ProjectivePoint>(),
        )
        .unwrap(),
    )
}

pub fn aggregate_response(individual_responses: Vec<Scalar>) -> Scalar {
    individual_responses.into_iter().sum()
}

/// c = H(˜X, Y, m)
pub fn challenge<H>(aggr_pk: PublicKey, aggr_commitment: PublicKey, md: Digest256<H>) -> Scalar {
    let mut hasher = Blake2b256::new();
    hasher.update(k256::PublicKey::from(aggr_pk).to_encoded_point(true).to_bytes());
    hasher.update(
        k256::PublicKey::from(aggr_commitment)
            .to_encoded_point(true)
            .to_bytes(),
    );
    hasher.update(md.as_ref());
    let hash: [u8; 32] = hasher.finalize().into();
    ScalarPrimitive::from_bytes(GenericArray::from_slice(&hash))
        .unwrap()
        .into()
}

/// `Y_i = g^{y_i}`
pub fn schnorr_commitment(sk: SecretKey) -> PublicKey {
    let point = ProjectivePoint::GENERATOR * Scalar::from(sk.as_scalar_primitive());
    PublicKey::from(k256::PublicKey::try_from(point).unwrap())
}

/// `σ_i`
pub fn exclusion_proof<H>(sk: SecretKey, md: Digest256<H>) -> Signature {
    SigningKey::from(&sk).sign(&md.as_ref()).into()
}

/// `t_i`
pub fn pre_commitment(pk: PublicKey) -> Blake2bDigest256 {
    blake2b256_hash(&*k256::PublicKey::from(pk).to_encoded_point(true).to_bytes())
}

/// `z_i = y_i + c * a_i * x_i`
pub fn response(
    host_commit_secret: SecretKey,
    host_sk: SecretKey,
    challenge: Scalar,
    individual_input: Scalar,
) -> Scalar {
    let yi = Scalar::from(host_commit_secret.as_scalar_primitive());
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
    commitment: PublicKey,
    pk: PublicKey,
) -> bool {
    let x = k256::PublicKey::from(pk).to_projective();
    let y = k256::PublicKey::from(commitment).to_projective();
    ProjectivePoint::GENERATOR * z == y + x * a * challenge
}

fn verify<H>(
    aggregate_commitment: PublicKey,
    aggregate_response: Scalar,
    exclusion_set: Vec<(usize, PublicKey, Signature)>,
    failed_committees: Vec<usize>,
    committee: Vec<PublicKey>,
    md: Digest256<H>,
    threshold: Threshold,
) -> bool {
    let individual_inputs = committee
        .iter()
        .map(|x| individual_input(committee.clone(), x.clone()))
        .collect::<Vec<_>>();
    let aggregate_x = aggregate_pk(committee.clone(), individual_inputs.clone());
    let partial_x: ProjectivePoint = committee
        .iter()
        .enumerate()
        .filter_map(|(i, x)| {
            if exclusion_set.iter().find(|(ex_i, _, _)| *ex_i == i).is_none()
                && !failed_committees.contains(&i)
            {
                Some(k256::PublicKey::from(x.clone()).to_projective() * individual_inputs[i])
            } else {
                None
            }
        })
        .sum();
    let excluded_y: ProjectivePoint = exclusion_set
        .iter()
        .map(|(_, yi, _)| k256::PublicKey::from(yi.clone()).to_projective())
        .sum();
    let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
    let aggregate_commitment_point = k256::PublicKey::from(aggregate_commitment).to_projective();
    if ProjectivePoint::GENERATOR * aggregate_response
        != partial_x * challenge + aggregate_commitment_point + excluded_y
    {
        return false;
    }
    for (_, yi, sigi) in exclusion_set.clone() {
        if !VerifyingKey::try_from(k256::PublicKey::from(yi))
            .map(|vk| {
                vk.verify(&md.as_ref(), &k256::schnorr::Signature::from(sigi))
                    .is_ok()
            })
            .unwrap_or(false)
        {
            return false;
        }
    }
    let num_succeeded_committees = committee.len() - failed_committees.len() - exclusion_set.len();
    num_succeeded_committees >= threshold.min(committee.len())
}

#[cfg(test)]
mod tests {
    use elliptic_curve::rand_core::OsRng;
    use k256::SecretKey;
    use nonempty::NonEmpty;

    use spectrum_crypto::digest::blake2b256_hash;

    use crate::protocol_handler::handel::Threshold;
    use crate::protocol_handler::sigma_aggregation::crypto::{
        aggregate_commitment, aggregate_pk, aggregate_response, challenge, individual_input, pre_commitment,
        response, schnorr_commitment, verify, verify_response,
    };
    use crate::protocol_handler::sigma_aggregation::types::PublicKey;

    struct TXi(PublicKey);
    struct Txi(SecretKey);
    struct TYi(PublicKey);
    struct Tyi(SecretKey);

    #[test]
    fn uniqie_individual_inputs() {
        let num_participants = 16;
        let mut rng = OsRng;
        let committee = (0..num_participants)
            .into_iter()
            .map(|_| {
                let sk = SecretKey::random(&mut rng);
                let pk = PublicKey::from(sk.public_key());
                pk
            })
            .collect::<Vec<_>>();
        let ii0 = individual_input(committee.clone(), committee[0].clone());
        let ii1 = individual_input(committee[1..].to_vec(), committee[0].clone());
        assert_ne!(ii0, ii1)
    }

    #[test]
    fn aggregation_no_corrupted_parties() {
        let num_participants = 16;
        let mut rng = OsRng;
        let md = blake2b256_hash(b"foo");
        let individual_keys = (0..num_participants)
            .into_iter()
            .map(|_| {
                let sk = SecretKey::random(&mut rng);
                let pk = PublicKey::from(sk.public_key());
                let sk_tmp = SecretKey::random(&mut rng);
                let commitment = schnorr_commitment(sk_tmp.clone());
                (Txi(sk), TXi(pk), Tyi(sk_tmp), TYi(commitment))
            })
            .collect::<Vec<_>>();
        let committee = individual_keys
            .iter()
            .map(|(_, TXi(pk), _, _)| pk.clone())
            .collect::<Vec<_>>();
        let individual_inputs = individual_keys
            .iter()
            .map(|(_, TXi(pki), _, _)| individual_input(committee.clone(), pki.clone()))
            .collect::<Vec<_>>();
        let aggregate_x = aggregate_pk(
            individual_keys
                .iter()
                .map(|(_, TXi(pk), _, _)| pk.clone())
                .collect(),
            individual_inputs.clone(),
        );
        let aggregate_commitment = aggregate_commitment(
            individual_keys
                .iter()
                .map(|(_, _, _, TYi(pk))| pk.clone())
                .collect(),
        );
        let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
        let individual_responses = individual_keys
            .iter()
            .enumerate()
            .map(|(i, (Txi(sk), TXi(pk), Tyi(sk_tmp), TYi(commitment)))| {
                response(sk_tmp.clone(), sk.clone(), challenge, individual_inputs[i])
            })
            .collect::<Vec<_>>();

        for (i, zi) in individual_responses.iter().enumerate() {
            let (_, TXi(pk), _, TYi(commitment)) = &individual_keys[i];
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
            Vec::new(),
            committee,
            md,
            Threshold { num: 1, denom: 1 }
        ))
    }
}
