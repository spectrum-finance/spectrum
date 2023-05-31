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
//! It uses the algorithms described in:
//!
//! * [VRF-draft-05](https://tools.ietf.org/pdf/draft-irtf-cfrg-vrf-05)
//! * [RFC6979](https://tools.ietf.org/html/rfc6979)
//! * [905.pdf](https://eprint.iacr.org/2014/905.pdf)
//!

use elliptic_curve::{CurveArithmetic, ProjectivePoint, PublicKey, Scalar, SecretKey};
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use spectrum_crypto::digest::Sha2Digest256;

pub mod vrf;
pub mod utils;
mod tests;

pub struct ECVRFProof<TCurve: CurveArithmetic> {
    gamma: ProjectivePoint<TCurve>,
    c: Scalar<TCurve>,
    s: Scalar<TCurve>,
}

pub trait ECVRF<TCurve>
    where
        TCurve: CurveArithmetic + PointCompression,
{
    type Error;
    /// Generates an ECVRF key-pair `(ec_vrf_secret_key, ec_vrf_public_key)`
    fn gen() -> Result<(SecretKey<TCurve>, PublicKey<TCurve>), Self::Error>;

    /// Generates random value and it's ECVRF proof from a secret key `sk` and a message `m`.
    fn prove(sk: SecretKey<TCurve>, message_hash: Sha2Digest256)
             -> Result<ECVRFProof<TCurve>, Self::Error> where
        <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
        <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>;

    /// Verifies the provided random value `y` and it's VRF proof `pi`.
    fn verify(
        pk: PublicKey<TCurve>,
        message_hash: Sha2Digest256,
        proof: ECVRFProof<TCurve>,
    ) -> Result<bool, Self::Error> where
        <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
        <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>;
}
