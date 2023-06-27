use blake2::digest::typenum::U32;
use blake2::{Blake2b, Digest};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, NonZeroScalar, PublicKey, Scalar, ScalarPrimitive, SecretKey};

use spectrum_crypto::digest::{sha256_hash, Sha2Digest256};
use spectrum_vrf::utils::projective_point_to_bytes;

#[derive(Debug)]
pub struct Error;

pub type Blake2b256 = Blake2b<U32>;

pub fn kes_key_gen<TCurve: CurveArithmetic>(
    seed: &Sha2Digest256,
) -> Result<(SecretKey<TCurve>, PublicKey<TCurve>), Error> {
    let seed_bytes: [u8; 32] = (*seed).into();
    let sk: SecretKey<TCurve> = SecretKey::<TCurve>::from_slice(&seed_bytes).unwrap();
    let pk = PublicKey::<TCurve>::from_secret_scalar(&sk.to_nonzero_scalar());
    Ok((sk, pk))
}

pub fn kes_sk_key_gen<TCurve: CurveArithmetic>(seed: &Sha2Digest256) -> Result<SecretKey<TCurve>, Error> {
    let seed_bytes: [u8; 32] = (*seed).into();
    let sk = SecretKey::<TCurve>::from_slice(&seed_bytes).unwrap();
    Ok(sk)
}

pub fn hash_to_public_key<TCurve: CurveArithmetic>(hash: Sha2Digest256) -> PublicKey<TCurve> {
    let hash_bytes: [u8; 32] = hash.into();
    let scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(GenericArray::from_slice(&hash_bytes))
        .unwrap()
        .into();
    let non_zero_scalar = NonZeroScalar::<TCurve>::new(scalar).unwrap();

    PublicKey::<TCurve>::from_secret_scalar(&non_zero_scalar)
}

pub fn merge_public_keys<TCurve: CurveArithmetic + PointCompression>(
    pk_0: &PublicKey<TCurve>,
    pk_1: &PublicKey<TCurve>,
) -> PublicKey<TCurve>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
{
    let pk_0_bytes = projective_point_to_bytes::<TCurve>((*pk_0).clone().to_projective());
    let pk_1_bytes = projective_point_to_bytes::<TCurve>((*pk_1).clone().to_projective());

    let pk_concatenated = [pk_0_bytes, pk_1_bytes].concat();
    let pk_sum_hash = sha256_hash(&pk_concatenated);

    hash_to_public_key::<TCurve>(pk_sum_hash)
}

pub fn partial_seed(seed: &Sha2Digest256, if_left: bool) -> Sha2Digest256 {
    let mut partial_seed = Blake2b256::default();
    partial_seed.update(&[if if_left { 1 } else { 2 }]);
    partial_seed.update(&seed.as_ref());
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
    use k256::Secp256k1;

    use spectrum_crypto::digest::sha256_hash;

    use crate::utils::{double_the_seed, kes_key_gen};

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

    #[test]
    fn test_kes_key_gen() {
        let seed_0 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let seed_1 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let (sk_0, pk_0) = kes_key_gen::<Secp256k1>(&seed_0).unwrap();
        let (sk_1, pk_1) = kes_key_gen::<Secp256k1>(&seed_1).unwrap();
        assert_ne!(sk_0, sk_1);
        assert_ne!(pk_0, pk_1);
    }
}
