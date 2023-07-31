use ecdsa::signature::digest::{Digest as DigestHasher, FixedOutput, HashMarker, Update};
use elliptic_curve::{
    CurveArithmetic, NonZeroScalar, PublicKey, Scalar, ScalarPrimitive
};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use spectrum_crypto::digest::Digest;
use spectrum_vrf::utils::{hash_bytes, projective_point_to_bytes};

pub fn hash_to_public_key<const N: usize, H, TCurve: CurveArithmetic>(hash: Digest<N, H>) -> PublicKey<TCurve> {
    let scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(GenericArray::from_slice(hash.as_ref()))
        .unwrap()
        .into();
    let non_zero_scalar = NonZeroScalar::<TCurve>::new(scalar).unwrap();

    PublicKey::<TCurve>::from_secret_scalar(&non_zero_scalar)
}

pub fn merge_public_keys<const N: usize, H, Hs, TCurve: CurveArithmetic + PointCompression>(
    pk1: &PublicKey<TCurve>,
    pk2: &PublicKey<TCurve>,
) -> PublicKey<TCurve>
    where
        <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
        <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
        Hs: Default, Hs: FixedOutput, Hs: HashMarker, Hs: Update
{
    let mut h = Hs::new();
    h.update(&projective_point_to_bytes::<TCurve>(&pk1.to_projective()).as_slice());
    h.update(&projective_point_to_bytes::<TCurve>(&pk2.to_projective()).as_slice());
    let b = h.finalize();
    let res = hash_bytes::<N, H, Hs>(&b);

    hash_to_public_key::<N, H, TCurve>(res)
}

pub fn concat<const N: usize, H>(
    current_slot: &u32,
    message: &spectrum_crypto::digest::Digest<N, H>,
) -> Vec<u8> {
    [message.as_ref(), &current_slot.to_be_bytes()].concat()
}


pub fn partial_seed<const N: usize, H, Hs>(seed: &Digest<N, H>, if_left: bool) -> Digest<N, H>
    where Hs: Default, Hs: FixedOutput, Hs: HashMarker, Hs: Update {
    let mut partial_seed = Hs::new();
    partial_seed.update(&[if if_left { 1 } else { 2 }]);
    partial_seed.update(&seed.as_ref());
    let res = partial_seed.finalize();
    hash_bytes::<N, H, Hs>(&res)
}

pub fn double_the_seed<const N: usize, H, Hs>(seed: &Digest<N, H>) -> (Digest<N, H>, Digest<N, H>)
    where Hs: Default, Hs: FixedOutput, Hs: HashMarker, Hs: Update {
    let seed_left = partial_seed::<N, H, Hs>(&seed, true);
    let seed_right = partial_seed::<N, H, Hs>(&seed, false);
    (seed_left, seed_right)
}

#[cfg(test)]
mod test {
    use elliptic_curve::rand_core::{OsRng, RngCore};
    use sha2::Sha256;

    use spectrum_crypto::digest::{Sha2, sha256_hash};

    use crate::utils::double_the_seed;

    #[test]
    fn test_seed_split() {
        let r = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let (r_l, r_r) = double_the_seed::<32, Sha2, Sha256>(&r);
        assert_ne!(r_r, r_l);
        assert_ne!(r_l, r);
        assert_eq!(r.as_ref().len(), 32);
        assert_eq!(r_l.as_ref().len(), 32);
        assert_eq!(r_l.as_ref().len(), r_r.as_ref().len());
    }
}
