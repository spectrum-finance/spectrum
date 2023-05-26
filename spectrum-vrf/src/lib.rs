use elliptic_curve::{AffinePoint, CurveArithmetic, PublicKey, Scalar, SecretKey};
use k256::Secp256k1;

pub struct VRFProof<TCurve: CurveArithmetic>(pub AffinePoint<TCurve>, pub Scalar<TCurve>, pub Scalar<TCurve>);

pub trait VRF<TCurve>
where
    TCurve: CurveArithmetic,
{
    type Error;

    /// Generates random value and it's VRF proof from a secret key `sk` and a message `m`.
    fn eval_prove(&self, sk: SecretKey<TCurve>, m: &[u8]) -> Result<VRFProof<TCurve>, Self::Error>;

    /// Verifies the provided random value `y` and it's VRF proof `pi`.
    fn verify(
        &self,
        pk: PublicKey<TCurve>,
        m: &[u8],
        proof: VRFProof<TCurve>,
    ) -> Result<Scalar<TCurve>, Self::Error>;
}

pub struct SpectrumVRF;

impl VRF<Secp256k1> for SpectrumVRF {
    type Error = ();

    fn eval_prove(&self, sk: SecretKey<Secp256k1>, m: &[u8]) -> Result<VRFProof<Secp256k1>, Self::Error> {
        todo!()
    }

    fn verify(
        &self,
        pk: PublicKey<Secp256k1>,
        m: &[u8],
        proof: VRFProof<Secp256k1>,
    ) -> Result<Scalar<Secp256k1>, Self::Error> {
        todo!()
    }
}
