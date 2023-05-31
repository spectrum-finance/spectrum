use elliptic_curve::{CurveArithmetic, NonZeroScalar, ProjectivePoint, PublicKey, Scalar,
                     ScalarPrimitive};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::group::Curve;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use spectrum_crypto::digest::Sha2Digest256;

pub fn hash_to_projective_point<TCurve: CurveArithmetic>(hash: Sha2Digest256)
                                                         -> ProjectivePoint<TCurve>
{
    let hash_bytes: [u8; 32] = hash.into();
    let scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(
        GenericArray::from_slice(&hash_bytes)).unwrap().into();
    let non_zero_scalar = NonZeroScalar::<TCurve>::new(
        scalar).unwrap();

    PublicKey::<TCurve>::from_secret_scalar(&non_zero_scalar).to_projective()
}

pub fn projective_point_to_bytes<TCurve: CurveArithmetic + PointCompression>
(point: ProjectivePoint<TCurve>) -> Vec<u8> where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>
{
    PublicKey::<TCurve>::from_affine(
        (point).to_affine()).unwrap().to_sec1_bytes().to_vec()
}

#[cfg(test)]
mod test {
    use elliptic_curve::group::GroupEncoding;
    use k256::Secp256k1;

    use spectrum_crypto::digest::sha256_hash;
    use spectrum_crypto::digest::Sha2Digest256;

    #[test]
    fn hash_to_projective_point_test() {
        let m_hash_0: Sha2Digest256 = sha256_hash("fair".as_bytes());
        let point_0 = super::hash_to_projective_point::<Secp256k1>(m_hash_0);

        let m_hash_1: Sha2Digest256 = sha256_hash("malicious".as_bytes());
        let point_1 = super::hash_to_projective_point::<Secp256k1>(m_hash_1);

        assert_ne!(point_0.to_bytes(), point_1.to_bytes());
    }

    #[test]
    fn projective_point_to_bytes_test() {
        let m_hash_0: Sha2Digest256 = sha256_hash("Alice_tx".as_bytes());
        let point_0 = super::hash_to_projective_point::<Secp256k1>(m_hash_0);

        let m_hash_1: Sha2Digest256 = sha256_hash("Bob_tx".as_bytes());
        let point_1 = super::hash_to_projective_point::<Secp256k1>(m_hash_1);

        let point_0_hash = sha256_hash(point_0.to_bytes().as_slice());
        let point_1_hash = sha256_hash(point_1.to_bytes().as_slice());

        let bytes_0 = super::projective_point_to_bytes::<Secp256k1>(point_0);
        let bytes_1 = super::projective_point_to_bytes::<Secp256k1>(point_1);

        assert_eq!(point_0_hash, sha256_hash(bytes_0.as_slice()));
        assert_eq!(point_1_hash, sha256_hash(bytes_1.as_slice()));
        assert_ne!(bytes_0, bytes_1)
    }
}
