use std::collections::HashSet;

use blake2::digest::typenum::U32;
use blake2::Blake2b;
use blake2::Digest;
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::ScalarPrimitive;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::signature::Signer;
use k256::schnorr::SigningKey;
use k256::{ProjectivePoint, Scalar, Secp256k1, SecretKey};
use nonempty::NonEmpty;

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256, Digest256};

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
    ScalarPrimitive::from_bytes(GenericArray::from_slice(&hash)).unwrap().into()
}

/// `X = Π_iX_i`
pub fn aggregate(NonEmpty { head, tail }: NonEmpty<PublicKey>) -> PublicKey {
    tail.into_iter().fold(head, |apk, pk| {
        k256::PublicKey::try_from(
            k256::PublicKey::from(apk).to_projective() + k256::PublicKey::from(pk).to_projective(),
        )
        .unwrap()
        .into()
    })
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
    PublicKey::from(k256::PublicKey::try_from(point.to_affine()).unwrap())
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
    host_secret: SecretKey,
    host_sk: SecretKey,
    challenge: Scalar,
    individual_input: Scalar,
) -> Scalar {
    let yi = Scalar::from(host_secret.as_scalar_primitive());
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
