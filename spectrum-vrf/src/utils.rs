use std::convert::TryInto;

use ecdsa::signature::digest::{Digest as DigestHasher, FixedOutput, HashMarker, Update};
use elliptic_curve::{
    CurveArithmetic, NonZeroScalar, ProjectivePoint, PublicKey, Scalar, ScalarPrimitive, SecretKey,
};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::group::Curve;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use spectrum_crypto::digest::Digest;

pub fn key_pair_gen<const N: usize, H, TCurve: CurveArithmetic>(seed: &Digest<N, H>) -> (SecretKey<TCurve>, PublicKey<TCurve>) {
    let sk: SecretKey<TCurve> = SecretKey::<TCurve>::from_slice(seed.as_ref()).unwrap();
    let pk = PublicKey::<TCurve>::from_secret_scalar(&sk.to_nonzero_scalar());
    (sk, pk)
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

pub fn hash_to_projective_point<const N: usize, H, TCurve: CurveArithmetic>(hash: &Digest<N, H>) -> ProjectivePoint<TCurve> {
    let scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(GenericArray::from_slice(hash.as_ref()))
        .unwrap()
        .into();
    let non_zero_scalar = NonZeroScalar::<TCurve>::new(scalar).unwrap();

    PublicKey::<TCurve>::from_secret_scalar(&non_zero_scalar).to_projective()
}

pub fn hash_to_public_key<const N: usize, H, TCurve: CurveArithmetic>(hash: Digest<N, H>) -> PublicKey<TCurve> {
    let scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(GenericArray::from_slice(hash.as_ref()))
        .unwrap()
        .into();
    let non_zero_scalar = NonZeroScalar::<TCurve>::new(scalar).unwrap();

    PublicKey::<TCurve>::from_secret_scalar(&non_zero_scalar)
}

fn vec_to_arr<T, const N: usize, H>(v: Vec<T>) -> [T; N] {
    let boxed_slice = v.into_boxed_slice();
    let boxed_array: Box<[T; N]> = match boxed_slice.try_into() {
        Ok(ba) => ba,
        Err(o) => panic!("Expected a Vec of length {} but it was {}", N, o.len()),
    };
    *boxed_array
}

pub fn hash_bytes<const N: usize, H, Hs>(bytes: &[u8]) -> Digest<N, H>
    where Hs: Default, Hs: FixedOutput, Hs: HashMarker, Hs: Update,
{
    let mut hasher = Hs::new();
    hasher.update(bytes);
    let arr: [u8; N] = vec_to_arr::<u8, N, H>(hasher.finalize().to_vec());
    Digest::from(arr)
}

#[cfg(test)]
mod test {
    use elliptic_curve::generic_array::GenericArray;
    use elliptic_curve::group::GroupEncoding;
    use elliptic_curve::ProjectivePoint;
    use elliptic_curve::rand_core::{OsRng, RngCore};
    use k256::Secp256k1;
    use sha2::Sha256;

    use spectrum_crypto::digest::{Digest, Sha2, sha256_hash};

    use crate::utils::{hash_bytes, key_pair_gen};

    #[test]
    fn test_key_gen() {
        let seed_0 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let seed_1 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let (sk_0, pk_0) = key_pair_gen::<32, Sha2, Secp256k1>(&seed_0);
        let (sk_1, pk_1) = key_pair_gen::<32, Sha2, Secp256k1>(&seed_1);
        assert_ne!(sk_0, sk_1);
        assert_ne!(pk_0, pk_1);
    }

    #[test]
    fn point_compression_test() {
        let m_hash: Digest<32, Sha2> = sha256_hash("Hi".as_bytes());
        let point = super::hash_to_projective_point::<32, Sha2, Secp256k1>(&m_hash);

        let point_hash = sha256_hash(point.to_bytes().as_slice());

        let bytes = super::projective_point_to_bytes::<Secp256k1>(&point);
        let point_decompressed =
            ProjectivePoint::<Secp256k1>::from_bytes(GenericArray::from_slice(&bytes)).unwrap();

        assert_eq!(point, point_decompressed);
        assert_ne!(m_hash, point_hash);
    }

    #[test]
    fn hasher_test() {
        let m_hash_sha: Digest<32, Sha2> = sha256_hash("Hi".as_bytes());
        let m_hash_sha_0: Digest<32, Sha2> = hash_bytes::<32, Sha2, Sha256>("Hi".as_bytes());

        let point_sha = super::hash_to_projective_point::<32, Sha2, Secp256k1>(&m_hash_sha);

        let point_hash_sha = sha256_hash(point_sha.to_bytes().as_slice());
        let point_hash_sha_0 = hash_bytes::<32, Sha2, Sha256>(point_sha.to_bytes().as_slice());

        assert_eq!(point_hash_sha, point_hash_sha_0);
        assert_eq!(m_hash_sha, m_hash_sha_0);
    }
}
