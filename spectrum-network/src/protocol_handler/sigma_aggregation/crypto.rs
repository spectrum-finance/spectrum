use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::signature::Signer;
use k256::schnorr::SigningKey;
use k256::{ProjectivePoint, Scalar, SecretKey};

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256, Digest256};

use crate::protocol_handler::sigma_aggregation::types::{PublicKey, Signature};

/// `Y_i = g^{y_i}`
pub fn gen_schnorr_commitment(sk: SecretKey) -> PublicKey {
    let point = ProjectivePoint::GENERATOR * Scalar::from(sk.as_scalar_primitive());
    PublicKey::from(k256::PublicKey::try_from(point.to_affine()).unwrap())
}

/// `σ_i`
pub fn gen_exclusion_proof<H>(sk: SecretKey, md: Digest256<H>) -> Signature {
    SigningKey::from(&sk).sign(&md.as_ref()).into()
}

/// `t_i`
pub fn gen_pre_commitment(pk: PublicKey) -> Blake2bDigest256 {
    blake2b256_hash(&*<k256::PublicKey>::from(pk).to_encoded_point(true).to_bytes())
}
