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