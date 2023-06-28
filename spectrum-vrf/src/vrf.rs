//! # Elliptic Curve Verifiable Random Function (ECVRF)
//!
//! The Elliptic Curve Verifiable Random Function is a Verifiable Random Function (VRF) that
//!  satisfies the trusted uniqueness, trusted collision resistance, and
//!  full pseudorandomness properties. The security
//!  of this ECVRF follows from the decisional Diffie-Hellman (DDH)
//!  assumption in the random oracle model.
//! * [905.pdf](https://eprint.iacr.org/2014/905.pdf)
//!

use blake2::Blake2b;
use blake2::Digest;
use blake2::digest::typenum::U32;
use elliptic_curve::{CurveArithmetic, Group, NonZeroScalar, ProjectivePoint, PublicKey,
                     Scalar, ScalarPrimitive, SecretKey};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::point::PointCompression;
use elliptic_curve::rand_core::OsRng;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use spectrum_crypto::digest::Sha2Digest256;

use crate::utils::{hash_to_projective_point, projective_point_to_bytes};

pub type Blake2b256 = Blake2b<U32>;

pub struct ECVRFProof<TCurve: CurveArithmetic> {
    pub(crate) gamma: ProjectivePoint<TCurve>,
    pub(crate) c: Scalar<TCurve>,
    pub(crate) s: Scalar<TCurve>,
}

#[derive(Debug)]
pub struct Error;


pub fn vrf_gen<TCurve: CurveArithmetic>() -> Result<(SecretKey<TCurve>, PublicKey<TCurve>), Error>
{
    let spectrum_vrf_sk = SecretKey::<TCurve>::random(&mut OsRng);
    let spectrum_vrf_pk = PublicKey::<TCurve>::from_secret_scalar(
        &spectrum_vrf_sk.to_nonzero_scalar());
    Ok((spectrum_vrf_sk, spectrum_vrf_pk))
}

pub fn vrf_prove<TCurve: CurveArithmetic + PointCompression>(sk: SecretKey<TCurve>,
                                                             message_hash: Sha2Digest256)
                                                             -> Result<ECVRFProof<TCurve>,
                                                                 Error> where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve> {
    let base_point = ProjectivePoint::<TCurve>::generator();

    let message_point: ProjectivePoint<TCurve> =
        hash_to_projective_point::<TCurve>(message_hash);

    let sk_scalar: Scalar<TCurve> = (*sk.as_scalar_primitive()).into();
    let gamma_point: ProjectivePoint<TCurve> = message_point * sk_scalar;
    let random_scalar: Scalar<TCurve> = *NonZeroScalar::<TCurve>::random(&mut OsRng);

    let mut hasher = Blake2b256::default();
    hasher.update(projective_point_to_bytes::<TCurve>(base_point));
    hasher.update(projective_point_to_bytes::<TCurve>(message_point));
    hasher.update(projective_point_to_bytes::<TCurve>(base_point * sk_scalar));
    hasher.update(projective_point_to_bytes::<TCurve>(message_point * sk_scalar));
    hasher.update(projective_point_to_bytes::<TCurve>(base_point * random_scalar));
    hasher.update(projective_point_to_bytes::<TCurve>(message_point * random_scalar));

    let mut c = [0 as u8; 32];
    let h_res = hasher.finalize();
    for i in 0..h_res.len() {
        c[i] = h_res[i];
    }
    let c_scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(
        GenericArray::from_slice(&c)).unwrap().into();
    let s_scalar: Scalar<TCurve> = random_scalar - c_scalar * sk_scalar;
    Ok(ECVRFProof::<TCurve> { gamma: gamma_point, c: c_scalar, s: s_scalar })
}

pub fn vrf_verify<TCurve: CurveArithmetic + PointCompression>(
    pk: PublicKey<TCurve>,
    message_hash: Sha2Digest256,
    proof: ECVRFProof<TCurve>,
) -> Result<bool, Error> where
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>
{
    let base_point = ProjectivePoint::<TCurve>::generator();

    let pk_point = pk.to_projective();

    let message_point: ProjectivePoint<TCurve> =
        hash_to_projective_point::<TCurve>(message_hash);
    let u_point = pk_point * proof.c + base_point * proof.s;
    let v_point = proof.gamma * proof.c + message_point * proof.s;

    let mut hasher = Blake2b256::default();
    hasher.update(projective_point_to_bytes::<TCurve>(base_point));
    hasher.update(projective_point_to_bytes::<TCurve>(message_point));
    hasher.update(projective_point_to_bytes::<TCurve>(pk_point));
    hasher.update(projective_point_to_bytes::<TCurve>(proof.gamma));
    hasher.update(projective_point_to_bytes::<TCurve>(u_point));
    hasher.update(projective_point_to_bytes::<TCurve>(v_point));

    let mut local_c = [0 as u8; 32];
    let hres = hasher.finalize();
    for i in 0..hres.len() {
        local_c[i] = hres[i];
    }
    let local_c_scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(
        GenericArray::from_slice(&local_c)).unwrap().into();
    Ok(local_c_scalar == proof.c)
}