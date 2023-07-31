use bigint::{U256, U512};
use ecdsa::signature::digest::{FixedOutput, HashMarker, Update};
use elliptic_curve::{CurveArithmetic, FieldBytes};
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use crate::ECVRFProof;
use crate::utils::{hash_bytes, projective_point_to_bytes};

pub fn proof_to_random_number<const N: usize, H, Hs, TCurve: CurveArithmetic + PointCompression>(
    proof: &ECVRFProof<TCurve>,
    constant_bytes: Vec<u8>,
    vrf_range: u32,
) -> U256
    where
        <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
        <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
        Hs: Default, Hs: FixedOutput, Hs: HashMarker, Hs: Update

{
    let c_fb: FieldBytes<TCurve> = proof.c.into();
    let s_fb: FieldBytes<TCurve> = proof.s.into();

    let random_bytes = [
        constant_bytes,
        projective_point_to_bytes::<TCurve>(&proof.gamma),
        c_fb.to_vec(),
        s_fb.to_vec(),
    ]
        .concat();
    let random_hash = hash_bytes::<N, H, Hs>(&random_bytes);
    let random_hash_bytes: [u8; N] = random_hash.into();

    let random_num = U512::from(U256::from(random_hash_bytes.as_slice()));
    let mult = U512::from(U256::from(2).pow(U256::from(vrf_range)));

    U256::from(random_num * mult / U512::from(U256::MAX))
}

pub fn get_lottery_threshold(
    vrf_range: u32,
    stake: u64,
    total_stake: u64,
    selection_fraction_num: u32,
    selection_fraction_denom: u32,
) -> U256 {
    let selection_fraction = selection_fraction_num as f64 / selection_fraction_denom as f64;
    let relative_stake = stake as f64 / total_stake as f64;

    let phi_value = 1_f64 - (1_f64 - selection_fraction).powf(relative_stake);
    let (phi_num, phi_denom) = to_rational(phi_value);

    let mult = U512::from(U256::from(2).pow(U256::from(vrf_range)));

    U256::from((U512::from(phi_num) * mult) / U512::from(phi_denom))
}

fn gcd(mut x: u64, mut y: u64) -> u64 {
    while y > 0 {
        let rem = x % y;
        x = y;
        y = rem;
    }
    x
}

fn to_rational(x: f64) -> (u64, u64) {
    let log = x.log2().floor();
    if log >= 0.0 {
        (x as u64, 1)
    } else {
        let num: u64 = (x / f64::EPSILON) as _;
        let denom: u64 = (1.0 / f64::EPSILON) as _;
        let gcd = gcd(num as u64, denom);
        (num / gcd as u64, denom / gcd)
    }
}
