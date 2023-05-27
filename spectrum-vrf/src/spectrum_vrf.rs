use elliptic_curve::CurveArithmetic;
use elliptic_curve::rand_core::OsRng;

use crate::{AffinePoint, ECVRF, ECVRFProof, PublicKey, Secp256k1,
            SecretKey, Sha2Digest256};

pub struct SpectrumVRF<TCurve>(TCurve);

impl<TCurve> ECVRF<TCurve> for SpectrumVRF<TCurve>
    where TCurve: CurveArithmetic {
    type Error = ();

    fn gen(&self)
           -> Result<(SecretKey<TCurve>, PublicKey<TCurve>), Self::Error> {
        let spectrum_vrf_sk = SecretKey::<TCurve>::random(&mut OsRng);
        let spectrum_vrf_pk = PublicKey::from_secret_scalar(
            &spectrum_vrf_sk.to_nonzero_scalar());
        Ok((spectrum_vrf_sk, spectrum_vrf_pk))
    }

    fn prove(&self, sk: SecretKey<TCurve>, message_hash: Sha2Digest256)
             -> Result<ECVRFProof<TCurve>, Self::Error> {
        todo!()
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