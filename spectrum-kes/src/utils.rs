use blake2::{Blake2b, Digest};
use blake2::digest::typenum::U32;
use elliptic_curve::{CurveArithmetic, NonZeroScalar, PublicKey, Scalar, ScalarPrimitive};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use spectrum_crypto::digest::{sha256_hash, Sha2Digest256};
use spectrum_vrf::utils::projective_point_to_bytes;

pub type Blake2b256 = Blake2b<U32>;

pub fn hash_to_public_key<TCurve: CurveArithmetic>(hash: Sha2Digest256)
                                                   -> PublicKey<TCurve>
{
    let hash_bytes: [u8; 32] = hash.into();
    let scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(
        GenericArray::from_slice(&hash_bytes)).unwrap().into();
    let non_zero_scalar = NonZeroScalar::<TCurve>::new(
        scalar).unwrap();

    PublicKey::<TCurve>::from_secret_scalar(&non_zero_scalar)
}

pub fn merge_public_keys<TCurve: CurveArithmetic + PointCompression>(pk_0: &PublicKey<TCurve>,
                                                                     pk_1: &PublicKey<TCurve>)
                                                                     -> PublicKey<TCurve>
    where <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
          <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
          <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>
{
    let pk_0_bytes = projective_point_to_bytes::<TCurve>(
        (*pk_0).clone().to_projective());
    let pk_1_bytes = projective_point_to_bytes::<TCurve>(
        (*pk_1).clone().to_projective());

    let pk_concatenated = [pk_0_bytes, pk_1_bytes].concat();
    let pk_sum_hash = sha256_hash(&pk_concatenated);

    hash_to_public_key::<TCurve>(pk_sum_hash)
}

pub fn partial_seed(seed: &Sha2Digest256, if_left: bool) -> Sha2Digest256 {
    let mut partial_seed = Blake2b256::default();
    partial_seed.update(&[if if_left { 1 } else { 2 }]);
    partial_seed.update(&seed.0);
    let res = partial_seed.finalize();
    sha256_hash(&res)
}

pub fn double_the_seed(seed: &Sha2Digest256) -> (Sha2Digest256, Sha2Digest256) {
    let seed_left = partial_seed(&seed, true);
    let seed_right = partial_seed(&seed, false);
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
        assert_eq!(r.0.len(), 32);
        assert_eq!(r_l.0.len(), 32);
        assert_eq!(r_l.0.len(), r_r.0.len());
    }
}
