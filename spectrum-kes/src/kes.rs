//! # Key Evolving Signature (KES)
//!
//! The Key Evolving Signature mechanism prevents an attacker from generating signatures for
//! messages that were created in the past (not valid time slot). It also allows any protocol
//! participant  to verify that a given signature was generated at a particular slot.
//! The security guarantees are achieved by evolving the secret key after each signature
//! is created in the way that the actual secret key used to sign the previous message
//! cannot be recovered.
//! * [2001/034](https://eprint.iacr.org/2001/034)
//! * [2017/573]( https://eprint.iacr.org/2017/573.pdf)
