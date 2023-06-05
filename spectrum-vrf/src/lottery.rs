use std::{u128, u32};

use elliptic_curve::{CurveArithmetic, FieldBytes};
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use spectrum_crypto::digest::blake2b256_hash;

use crate::utils::projective_point_to_bytes;
use crate::vrf::ECVRFProof;

pub fn proof_to_random_number<TCurve: CurveArithmetic + PointCompression>(
    proof: &ECVRFProof<TCurve>, vrf_range: u32) -> u64
    where <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
          <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
          <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>
{
    let c_fb: FieldBytes<TCurve> = proof.c.into();
    let s_fb: FieldBytes<TCurve> = proof.s.into();

    let proof_bytes = [projective_point_to_bytes::<TCurve>(proof.gamma),
        c_fb.to_vec(), s_fb.to_vec()].concat();
    let proof_hash = blake2b256_hash(&proof_bytes);
    let proof_hash_bytes: [u8; 32] = proof_hash.into();
    let proof_hash_bytes_vec = proof_hash_bytes.to_vec();

    let proof_num = u64::from_ne_bytes(proof_hash_bytes_vec[0..8].try_into().unwrap());
    let mult = u64::try_from(2_i32.pow(vrf_range) as u32).unwrap();

    ((proof_num as u128 * mult as u128) / (u64::MAX as u128)) as u64
}

pub fn get_lottery_threshold(
    vrf_range: u32,
    stake: u64,
    total_stake: u64,
    selection_fraction_num: u32,
    selection_fraction_denom: u32,
) -> u64
{
    let selection_fraction = selection_fraction_num as f32 / selection_fraction_denom as f32;
    let relative_stake = (stake as f64 / total_stake as f64) as f32;
    let phi_value = 1_f32 - (1_f32 - selection_fraction).powf(relative_stake);
    let mult = u32::try_from(2_i32.pow(vrf_range) as u64).unwrap();

    (phi_value * mult as f32) as u64
}
