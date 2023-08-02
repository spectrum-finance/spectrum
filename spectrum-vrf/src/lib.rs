extern crate core;

use ecdsa::signature::digest::{Digest as DigestHash, FixedOutput, HashMarker, Update};
use elliptic_curve::{
    CurveArithmetic, Group, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, ScalarPrimitive, SecretKey,
};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::point::PointCompression;
use elliptic_curve::rand_core::OsRng;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use type_equals::TypeEquals;

use spectrum_crypto::digest::Digest;

use crate::utils::{hash_to_projective_point, projective_point_to_bytes};

mod example;
mod lottery;
mod tests;
pub mod utils;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECVRFProof<TCurve: CurveArithmetic> {
    pub gamma: ProjectivePoint<TCurve>,
    pub c: Scalar<TCurve>,
    pub s: Scalar<TCurve>,
}

#[derive(Debug)]
pub struct Error;

pub fn vrf_gen<TCurve: CurveArithmetic>() -> Result<(SecretKey<TCurve>, PublicKey<TCurve>), Error> {
    let spectrum_vrf_sk = SecretKey::<TCurve>::random(&mut OsRng);
    let spectrum_vrf_pk = PublicKey::<TCurve>::from_secret_scalar(&spectrum_vrf_sk.to_nonzero_scalar());
    Ok((spectrum_vrf_sk, spectrum_vrf_pk))
}

pub fn vrf_prove<HF, TCurve>(
    sk: SecretKey<TCurve>,
    message_hash: Digest<HF>,
) -> Result<ECVRFProof<TCurve>, Error>
    where
        TCurve: CurveArithmetic + PointCompression,
        <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
        <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize + TypeEquals<Other=HF::OutputSize>,
        <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
        HF: Default + FixedOutput + HashMarker + Update
{
    let base_point = ProjectivePoint::<TCurve>::generator();

    let message_point: ProjectivePoint<TCurve> = hash_to_projective_point::<HF, TCurve>(&message_hash);

    let sk_scalar: Scalar<TCurve> = (*sk.as_scalar_primitive()).into();
    let gamma_point: ProjectivePoint<TCurve> = message_point * sk_scalar;
    let random_scalar: Scalar<TCurve> = *NonZeroScalar::<TCurve>::random(&mut OsRng);

    let mut hasher = HF::new();
    hasher.update(&projective_point_to_bytes::<TCurve>(&base_point).as_slice());
    hasher.update(&projective_point_to_bytes::<TCurve>(&message_point).as_slice());
    hasher.update(&projective_point_to_bytes::<TCurve>(&(base_point * sk_scalar)).as_slice());
    hasher.update(&projective_point_to_bytes::<TCurve>(&(message_point * sk_scalar)).as_slice());
    hasher.update(&projective_point_to_bytes::<TCurve>(&(base_point * random_scalar)).as_slice());
    hasher.update(&projective_point_to_bytes::<TCurve>(&(message_point * random_scalar)).as_slice());
    let arr = hasher.finalize_fixed();
    let c_scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_slice(arr.as_ref())
        .unwrap()
        .into();
    let s_scalar: Scalar<TCurve> = random_scalar - c_scalar * sk_scalar;
    Ok(ECVRFProof {
        gamma: gamma_point,
        c: c_scalar,
        s: s_scalar,
    })
}

pub fn vrf_verify<HF, TCurve: CurveArithmetic + PointCompression>
(
    pk: PublicKey<TCurve>,
    message_hash: Digest<HF>,
    proof: ECVRFProof<TCurve>,
) -> Result<bool, Error>
    where
        <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
        <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
        HF: Default + FixedOutput + HashMarker + Update {
    {
        let base_point = ProjectivePoint::<TCurve>::generator();

        let pk_point = pk.to_projective();

        let message_point: ProjectivePoint<TCurve> = hash_to_projective_point::<HF, TCurve>(&message_hash);
        let u_point = pk_point * proof.c + base_point * proof.s;
        let v_point = proof.gamma * proof.c + message_point * proof.s;

        let mut hasher = HF::new();
        hasher.update(&projective_point_to_bytes::<TCurve>(&base_point).as_slice());
        hasher.update(&projective_point_to_bytes::<TCurve>(&message_point).as_slice());
        hasher.update(&projective_point_to_bytes::<TCurve>(&pk_point).as_slice());
        hasher.update(&projective_point_to_bytes::<TCurve>(&proof.gamma).as_slice());
        hasher.update(&projective_point_to_bytes::<TCurve>(&u_point).as_slice());
        hasher.update(&projective_point_to_bytes::<TCurve>(&v_point).as_slice());

        let h_res = hasher.finalize_fixed();
        let local_c_scalar: Scalar<TCurve> =
            ScalarPrimitive::<TCurve>::from_bytes(GenericArray::from_slice(&h_res))
                .unwrap()
                .into();
        Ok(local_c_scalar == proof.c)
    }
}

