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
use crate::utils::{hash_to_projective_point, projective_point_to_bytes};

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
        let message_point: ProjectivePoint<TCurve> = hash_to_projective_point::<TCurve>(message_hash);

        /// Base point of the curve:
        let base_point = ProjectivePoint::<TCurve>::default();
        // let k256_base = k256::ProjectivePoint::GENERATOR;

        /// Create proof:
        let sk_scalar: Scalar<TCurve> = (*sk.as_scalar_primitive()).into();
        let gamma_point: ProjectivePoint<TCurve> = message_point * sk_scalar;
        let random_scalar: Scalar<TCurve> = *NonZeroScalar::<TCurve>::random(&mut OsRng);

        let mut hasher = Blake2b256::new();
        hasher.update(projective_point_to_bytes::<TCurve>(base_point));
        hasher.update(projective_point_to_bytes::<TCurve>(message_point));
        hasher.update(projective_point_to_bytes::<TCurve>(base_point * sk_scalar));
        hasher.update(projective_point_to_bytes::<TCurve>(message_point * sk_scalar));
        hasher.update(projective_point_to_bytes::<TCurve>(base_point * random_scalar));
        hasher.update(projective_point_to_bytes::<TCurve>(message_point * random_scalar));

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