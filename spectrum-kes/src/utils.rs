use ecdsa::signature::digest::{Digest as DigestHasher, FixedOutput, HashMarker, Update};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, NonZeroScalar, PublicKey, Scalar, ScalarPrimitive};

use spectrum_crypto::digest::{hash, Digest};
use spectrum_vrf::utils::projective_point_to_bytes;

pub fn hash_to_public_key<H: HashMarker + FixedOutput, TCurve: CurveArithmetic>(
    hash: Digest<H>,
) -> PublicKey<TCurve> {
    let scalar: Scalar<TCurve> =
        ScalarPrimitive::<TCurve>::from_bytes(GenericArray::from_slice(hash.as_ref()))
            .unwrap()
            .into();
    let non_zero_scalar = NonZeroScalar::<TCurve>::new(scalar).unwrap();

    PublicKey::<TCurve>::from_secret_scalar(&non_zero_scalar)
}

pub fn merge_public_keys<HF, TCurve: CurveArithmetic + PointCompression>(
    pk1: &PublicKey<TCurve>,
    pk2: &PublicKey<TCurve>,
) -> PublicKey<TCurve>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
    HF: Default + FixedOutput + HashMarker + Update,
{
    let mut h = HF::new();
    h.update(&projective_point_to_bytes::<TCurve>(&pk1.to_projective()).as_slice());
    h.update(&projective_point_to_bytes::<TCurve>(&pk2.to_projective()).as_slice());
    let b = h.finalize();
    let res = hash::<HF>(&b);

    hash_to_public_key::<HF, TCurve>(res)
}

pub fn concat<H: HashMarker + FixedOutput>(current_slot: &u32, message: &Digest<H>) -> Vec<u8> {
    [message.as_ref(), &current_slot.to_be_bytes()].concat()
}

pub fn partial_seed<HF>(seed: &Digest<HF>, if_left: bool) -> Digest<HF>
where
    HF: Default + FixedOutput + HashMarker + Update,
{
    let mut partial_seed = HF::new();
    partial_seed.update(&[if if_left { 1 } else { 2 }]);
    partial_seed.update(&seed.as_ref());
    let res = partial_seed.finalize();
    hash::<HF>(&res)
}

pub fn double_the_seed<HF>(seed: &Digest<HF>) -> (Digest<HF>, Digest<HF>)
where
    HF: Default + FixedOutput + HashMarker + Update,
{
    let seed_left = partial_seed::<HF>(&seed, true);
    let seed_right = partial_seed::<HF>(&seed, false);
    (seed_left, seed_right)
}

#[cfg(test)]
mod test {
    use elliptic_curve::rand_core::{OsRng, RngCore};

    use spectrum_crypto::digest::sha256_hash;

    use crate::utils::double_the_seed;

    #[test]
    fn test_seed_split() {
        let r = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let (r_l, r_r) = double_the_seed(&r);
        assert_ne!(r_r, r_l);
        assert_ne!(r_l, r);
        assert_eq!(r.as_ref().len(), 32);
        assert_eq!(r_l.as_ref().len(), 32);
        assert_eq!(r_l.as_ref().len(), r_r.as_ref().len());
    }
}
