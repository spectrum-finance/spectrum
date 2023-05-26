use crate::{AffinePoint, PublicKey, Scalar, Secp256k1, SecretKey, Sha2Digest256, ECVRFProof, ECVRF};


pub struct SpectrumVRF;

impl ECVRF<TCurve> for SpectrumVRF {
    type Error = ();

    fn gen(&self)
           -> Result<(SecretKey<TCurve>, PublicKey<TCurve>), Self::Error> {
        // todo!()
    }

    fn prove(&self, sk: SecretKey<TCurve>, message_hash: Sha2Digest256)
             -> Result<VRFProof<TCurve>, Self::Error> {
        // todo!()
    }

    fn verify(
        &self,
        pk: PublicKey<TCurve>,
        message_hash: &[u8],
        proof: VRFProof<TCurve>,
    ) -> Result<AffinePoint<TCurve>, Self::Error> {
        // todo!()
    }
}