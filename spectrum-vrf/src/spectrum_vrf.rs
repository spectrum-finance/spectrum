use blake2::Blake2b;
use blake2::Digest;
use blake2::digest::KeyInit;
use blake2::digest::typenum::U32;
use elliptic_curve::{CurveArithmetic, NonZeroScalar, ProjectivePoint, ScalarPrimitive};
use elliptic_curve::generic_array::GenericArray;
use elliptic_curve::group::Curve;
use elliptic_curve::point::PointCompression;
use elliptic_curve::rand_core::OsRng;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use crate::{AffinePoint, ECVRF, ECVRFProof, PublicKey, Scalar, SecretKey, Sha2Digest256};

type Blake2b256 = Blake2b<U32>;
// use k256::ProjectivePoint;

pub struct SpectrumVRF<TCurve>(TCurve);

impl<TCurve> ECVRF<TCurve> for SpectrumVRF<TCurve>
    where TCurve: CurveArithmetic + PointCompression {
    type Error = ();

    fn gen(&self)
           -> Result<(SecretKey<TCurve>, PublicKey<TCurve>), Self::Error> {
        let spectrum_vrf_sk = SecretKey::<TCurve>::random(&mut OsRng);
        let spectrum_vrf_pk = PublicKey::<TCurve>::from_secret_scalar(
            &spectrum_vrf_sk.to_nonzero_scalar());
        Ok((spectrum_vrf_sk, spectrum_vrf_pk))
    }

    fn prove(&self, sk: SecretKey<TCurve>, message_hash: Sha2Digest256)
             -> Result<ECVRFProof<TCurve>, Self::Error> where
        <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
        <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve> {
        /// Message hash to Scalar:
        let message_hash_bytes: [u8; 32] = message_hash.into();

        let message_scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(
            GenericArray::from_slice(&message_hash_bytes)).unwrap().into();
        let message_non_zero_scalar = NonZeroScalar::<TCurve>::new(
            message_scalar).unwrap();

        let message_point: ProjectivePoint<TCurve> = PublicKey::<TCurve>::from_secret_scalar(
            &message_non_zero_scalar).to_projective();

        /// Base point of the curve:
        let base_point = ProjectivePoint::<TCurve>::default();
        // let k256_base = k256::ProjectivePoint::GENERATOR;

        /// Create proof:
        let sk_scalar: Scalar<TCurve> = (*sk.as_scalar_primitive()).into();
        let gamma_point: ProjectivePoint<TCurve> = message_point * sk_scalar;
        let random_scalar: Scalar<TCurve> = *NonZeroScalar::<TCurve>::random(&mut OsRng);

        let mut hasher = Blake2b256::new();
        hasher.update(PublicKey::<TCurve>::from_affine(
            base_point.to_affine()).unwrap().to_sec1_bytes().as_ref());
        hasher.update(PublicKey::<TCurve>::from_affine(
            message_point.to_affine()).unwrap().to_sec1_bytes().as_ref());
        hasher.update(PublicKey::<TCurve>::from_affine(
            (base_point * sk_scalar).to_affine()).unwrap().to_sec1_bytes().as_ref());
        hasher.update(PublicKey::<TCurve>::from_affine(
            (message_point * sk_scalar).to_affine()).unwrap().to_sec1_bytes().as_ref());
        hasher.update(PublicKey::<TCurve>::from_affine(
            (base_point * random_scalar).to_affine()).unwrap().to_sec1_bytes().as_ref());
        hasher.update(PublicKey::<TCurve>::from_affine(
            (message_point * random_scalar).to_affine()).unwrap().to_sec1_bytes().as_ref());

        let mut c = [0 as u8; 32];
        let h_res = hasher.finalize();
        for i in 0..h_res.len() {
            c[i] = h_res[i];
        }
        let c_scalar: Scalar<TCurve> = ScalarPrimitive::<TCurve>::from_bytes(
            GenericArray::from_slice(&c)).unwrap().into();
        let s_scalar: Scalar<TCurve> = random_scalar - c_scalar * sk_scalar;
        Ok(ECVRFProof::<TCurve> { gamma: gamma_point.into(), c: c_scalar, s: s_scalar })
    }

    fn verify(
        &self,
        pk: PublicKey<TCurve>,
        message_hash: Sha2Digest256,
        proof: ECVRFProof<TCurve>,
    ) -> Result<AffinePoint<TCurve>, Self::Error> {
        todo!()
    }
}