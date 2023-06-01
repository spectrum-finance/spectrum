use elliptic_curve::{CurveArithmetic, FieldBytes, NonZeroScalar, ProjectivePoint, PublicKey,
                     Scalar, ScalarPrimitive};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::group::Curve;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use spectrum_crypto::digest::{blake2b256_hash, Sha2Digest256};

use crate::vrf::ECVRFProof;

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

pub fn proof_to_random_scalar<TCurve: CurveArithmetic + PointCompression>(proof: &ECVRFProof<TCurve>,
                                                                          vrf_range: u32)
                                                                          -> Scalar<TCurve>
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

    let proof_scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(
        GenericArray::from_slice(&proof_hash_bytes)).unwrap().into();
    let mult_scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from(
        2 * 2_i32.pow(vrf_range) as u64).into();

    proof_scalar * mult_scalar
}

#[cfg(test)]
mod test {
    use elliptic_curve::{Scalar, ScalarPrimitive};
    use elliptic_curve::generic_array::GenericArray;
    use elliptic_curve::group::GroupEncoding;
    use k256::{ProjectivePoint, Secp256k1};

    use spectrum_crypto::digest::sha256_hash;
    use spectrum_crypto::digest::Sha2Digest256;

    use crate::vrf::{vrf_gen, vrf_prove};

    #[test]
    fn hash_to_projective_point_test() {
        let m_hash_0: Sha2Digest256 = sha256_hash("Alice_tx".as_bytes());
        let point_0 = super::hash_to_projective_point::<Secp256k1>(m_hash_0);

        let m_hash_1: Sha2Digest256 = sha256_hash("Bob_tx".as_bytes());
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

    #[test]
    fn vice_versa_test() {
        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());
        let point = super::hash_to_projective_point::<Secp256k1>(m_hash);

        let point_hash = sha256_hash(point.to_bytes().as_slice());

        let bytes = super::projective_point_to_bytes::<Secp256k1>(point);
        let point_decompressed = ProjectivePoint::from_bytes(
            GenericArray::from_slice(&bytes)).unwrap();

        assert_eq!(point, point_decompressed);
        assert_ne!(m_hash, point_hash);
    }

    #[test]
    fn vice_versa_hash_to_projective_point_projective_point_to_bytes_test() {
        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());
        let point = super::hash_to_projective_point::<Secp256k1>(m_hash);

        let point_hash = sha256_hash(point.to_bytes().as_slice());

        let bytes = super::projective_point_to_bytes::<Secp256k1>(point);
        let point_decompressed = ProjectivePoint::from_bytes(
            GenericArray::from_slice(&bytes)).unwrap();

        assert_eq!(point, point_decompressed);
        assert_ne!(m_hash, point_hash);
    }


    #[test]
    fn proof_to_random_number_test() {
        let base_vrf_range = 5;
        let option_vrf_range = 8;

        let (vrf_sk, _) =
            vrf_gen::<Secp256k1>().unwrap();

        let m_hash: Sha2Digest256 = sha256_hash("Test_tx".as_bytes());

        let proof =
            vrf_prove::<Secp256k1>(vrf_sk, m_hash).unwrap();

        let r_0 = super::proof_to_random_scalar(&proof, base_vrf_range);
        let r_1 = super::proof_to_random_scalar(&proof, base_vrf_range.clone());
        let r_2 = super::proof_to_random_scalar(&proof, option_vrf_range.clone());

        let mult_scalar_0: Scalar<Secp256k1> = ScalarPrimitive::<Secp256k1>::from(
            2 * 2_i32.pow(base_vrf_range.clone()) as u64).into();
        let mult_scalar_2: Scalar<Secp256k1> = ScalarPrimitive::<Secp256k1>::from(
            2 * 2_i32.pow(option_vrf_range.clone()) as u64).into();

        let valid_relation = mult_scalar_0 * r_2 == mult_scalar_2 * r_0;
        let valid_order = r_1 < r_2;

        assert_eq!(r_0, r_1);
        assert!(valid_relation);
        assert!(valid_order); //todo!() valid_order sometime fails.
    }
}
