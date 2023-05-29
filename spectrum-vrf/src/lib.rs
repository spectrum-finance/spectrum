//! # Elliptic Curve Verifiable Random Function (ECVRF)
//!
//! The Elliptic Curve Verifiable Random Function is a Verifiable Random Function (VRF) that
//!  satisfies the trusted uniqueness, trusted collision resistance, and
//!  full pseudorandomness properties. The security
//!  of this ECVRF follows from the decisional Diffie-Hellman (DDH)
//!  assumption in the random oracle model.
//!
//! This crate defines the generic contract that must be followed by ECVRF\
//! implementations ([`ECVRF`](trait.ECVRF.html) trait).
//!
//! It follows the algorithms described in:
//!
//! * [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
//! * [RFC6979](https://tools.ietf.org/html/rfc6979)
//!
//! Current implementation is based on the secp256k1 (K-256) curve.

use elliptic_curve::{AffinePoint, CurveArithmetic, PublicKey, Scalar, SecretKey};
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::weierstrass::ProjectivePoint;

use spectrum_crypto::digest::Sha2Digest256;

pub mod spectrum_vrf;

pub struct ECVRFProof<TCurve: CurveArithmetic> {
    gamma: AffinePoint<TCurve>,
    c: Scalar<TCurve>,
    s: Scalar<TCurve>,
}

pub trait ECVRF<TCurve>
    where
        TCurve: CurveArithmetic + PointCompression,
{
    type Error;
    /// Generates an ECVRF key-pair `(ec_vrf_secret_key, ec_vrf_public_key)`
    fn gen(&self) -> Result<(SecretKey<TCurve>, PublicKey<TCurve>), Self::Error>;

    /// Generates random value and it's ECVRF proof from a secret key `sk` and a message `m`.
    fn prove(&self, sk: SecretKey<TCurve>, message_hash: Sha2Digest256)
             -> Result<ECVRFProof<TCurve>, Self::Error> where
        <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
        <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>;

    /// Verifies the provided random value `y` and it's VRF proof `pi`.
    fn verify(
        &self,
        pk: PublicKey<TCurve>,
        message_hash: Sha2Digest256,
        proof: ECVRFProof<TCurve>,
    ) -> Result<AffinePoint<TCurve>, Self::Error>;
}
