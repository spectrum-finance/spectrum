use blake2::digest::typenum::U32;
use blake2::{Blake2b, Digest};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::group::Curve;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{
    CurveArithmetic, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, ScalarPrimitive, SecretKey,
};

use spectrum_crypto::digest::{sha256_hash, Sha2Digest256};

pub type Blake2b256 = Blake2b<U32>;

pub fn partial_seed(seed: &Sha2Digest256, if_left: bool) -> Sha2Digest256 {
    let mut partial_seed = Blake2b256::default();
    partial_seed.update(&[if if_left { 1 } else { 2 }]);
    partial_seed.update(&seed.as_ref());
    let res = partial_seed.finalize();
    sha256_hash(&res)
}

pub fn double_seed(seed: &Sha2Digest256) -> (Sha2Digest256, Sha2Digest256) {
    let seed_left = partial_seed(&seed, true);
    let seed_right = partial_seed(&seed, false);
    (seed_left, seed_right)
}

pub fn projective_point_to_bytes<TCurve: CurveArithmetic + PointCompression>(
    point: &ProjectivePoint<TCurve>,
) -> Vec<u8>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
{
    PublicKey::<TCurve>::from_affine((*point).to_affine())
        .unwrap()
        .to_sec1_bytes()
        .to_vec()
}

pub fn hash_to_projective_point<TCurve: CurveArithmetic>(hash: &Sha2Digest256) -> ProjectivePoint<TCurve> {
    let hash_bytes: [u8; 32] = (*hash).into();
    let scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(GenericArray::from_slice(&hash_bytes))
        .unwrap()
        .into();
    let non_zero_scalar = NonZeroScalar::<TCurve>::new(scalar).unwrap();

    PublicKey::<TCurve>::from_secret_scalar(&non_zero_scalar).to_projective()
}

pub fn key_pair_gen<TCurve: CurveArithmetic>(seed: &Sha2Digest256) -> (SecretKey<TCurve>, PublicKey<TCurve>) {
    let seed_bytes: [u8; 32] = (*seed).into();
    let sk: SecretKey<TCurve> = SecretKey::<TCurve>::from_slice(&seed_bytes).unwrap();
    let pk = PublicKey::<TCurve>::from_secret_scalar(&sk.to_nonzero_scalar());
    (sk, pk)
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
    pk1: &PublicKey<TCurve>,
    pk2: &PublicKey<TCurve>,
) -> PublicKey<TCurve>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
{
    let mut h = Blake2b256::default();
    h.update(&projective_point_to_bytes::<TCurve>(&pk1.to_projective()).as_slice());
    h.update(&projective_point_to_bytes::<TCurve>(&pk2.to_projective()).as_slice());
    let b = h.finalize();
    let res = sha256_hash(&b);

    hash_to_public_key::<TCurve>(res)
}

pub fn associate_message_with_slot(current_slot: &u32, message: &Sha2Digest256) -> Vec<u8> {
    [message.as_ref(), (*current_slot).to_string().as_bytes()].concat()
}
#[cfg(test)]
mod test {
    use elliptic_curve::generic_array::GenericArray;
    use elliptic_curve::group::GroupEncoding;
    use elliptic_curve::rand_core::{OsRng, RngCore};
    use elliptic_curve::ProjectivePoint;
    use k256::Secp256k1;

    use spectrum_crypto::digest::{sha256_hash, Sha2Digest256};

    use crate::utils::{double_seed, key_pair_gen};

    #[test]
    fn test_seed_split() {
        let r = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let (r_l, r_r) = double_seed(&r);
        assert_ne!(r_r, r_l);
        assert_ne!(r_l, r);
        assert_eq!(r.as_ref().len(), 32);
        assert_eq!(r_l.as_ref().len(), 32);
        assert_eq!(r_l.as_ref().len(), r_r.as_ref().len());
    }

    #[test]
    fn test_key_gen() {
        let seed_0 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let seed_1 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let (sk_0, pk_0) = key_pair_gen::<Secp256k1>(&seed_0);
        let (sk_1, pk_1) = key_pair_gen::<Secp256k1>(&seed_1);
        assert_ne!(sk_0, sk_1);
        assert_ne!(pk_0, pk_1);
    }

    #[test]
    fn point_compression_test() {
        let m_hash: Sha2Digest256 = sha256_hash("Hi".as_bytes());
        let point = super::hash_to_projective_point::<Secp256k1>(&m_hash);

        let point_hash = sha256_hash(point.to_bytes().as_slice());

        let bytes = super::projective_point_to_bytes::<Secp256k1>(&point);
        let point_decompressed =
            ProjectivePoint::<Secp256k1>::from_bytes(GenericArray::from_slice(&bytes)).unwrap();

        assert_eq!(point, point_decompressed);
        assert_ne!(m_hash, point_hash);
    }
}
