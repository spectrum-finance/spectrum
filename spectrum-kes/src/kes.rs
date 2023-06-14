use elliptic_curve::{CurveArithmetic, PublicKey, Scalar, SecretKey};
use elliptic_curve::rand_core::OsRng;

use spectrum_crypto::digest::Sha2Digest256;

//! # Key Evolving Signature (KES)
//!
//!
//! The Key Evolving Signature mechanism prevents an attacker from generating signatures for
//! messages that were created in the past (not valid time slot). It also allows any protocol
//! participant  to verify that a given signature was generated at a particular slot.
//! The security guarantees are achieved by evolving the secret key after each signature
//! is created in the way that the actual secret key used to sign the previous message
//! cannot be recovered.
//! * [2001/034](https://eprint.iacr.org/2001/034)
//! * [2017/573]( https://eprint.iacr.org/2017/573.pdf)

#[derive(Debug)]
pub struct Error;

pub struct Counter {
    k: i32,
}

pub struct KesSignature<TCurve: CurveArithmetic>
{
    s: Scalar<TCurve>,
}

pub fn kes_gen<TCurve: CurveArithmetic>() -> Result<(SecretKey<TCurve>, PublicKey<TCurve>, Counter),
    Error>
{
    todo!()
}

pub fn kes_sign<TCurve: CurveArithmetic>(kes_sk: SecretKey<TCurve>,
                                         message: Sha2Digest256,
                                         signing_num: i32)
                                         -> Result<(KesSignature<TCurve>, Counter), Error>
{
    todo!()
}

pub fn kes_verify<TCurve: CurveArithmetic>(signature: KesSignature<TCurve>,
                                           kes_pk: PublicKey<TCurve>,
                                           message: Sha2Digest256,
                                           signing_num: i32)
                                           -> Result<bool, Error>
{
    todo!()
}

fn kes_update<TCurve: CurveArithmetic>(kes_sk: SecretKey<TCurve>) -> Result<(SecretKey<TCurve>),
    Error>
{
    todo!()
}
