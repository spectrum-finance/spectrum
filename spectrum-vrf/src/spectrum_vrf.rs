use crate::{AffinePoint, PublicKey, Scalar, Secp256k1, SecretKey, Sha2Digest256, ECVRFProof, ECVRF};


pub struct SpectrumVRF;

impl ECVRF<Secp256k1> for SpectrumVRF {
    type Error = ();

    fn gen(&self)
           -> Result<(SecretKey<Secp256k1>, PublicKey<Secp256k1>), Self::Error> {
        todo!()
    }

    fn prove(&self, sk: SecretKey<Secp256k1>, message_hash: Sha2Digest256)
             -> Result<ECVRFProof<Secp256k1>, Self::Error> {
        todo!()
    }

    fn verify(
        &self,
        pk: PublicKey<Secp256k1>,
        message_hash: Sha2Digest256,
        proof: ECVRFProof<Secp256k1>,
    ) -> Result<AffinePoint<Secp256k1>, Self::Error> {
        todo!()
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//
//     #[test]
//     fn test_key_gen() {
//         let s = "769a48bdb72d0f7bade76a120982b6d479fda6084c84d40957ae9f935f3b99ac";
//     }
// }