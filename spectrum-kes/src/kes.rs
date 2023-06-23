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

use std::ops::Add;

use ecdsa::hazmat::SignPrimitive;
use ecdsa::signature::{Signer, SignerMut};
use ecdsa::{Signature, SigningKey, VerifyingKey};
use elliptic_curve::generic_array::ArrayLength;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, PublicKey, SecretKey};
use k256::ecdsa::signature::Verifier;
use k256::Secp256k1;

use spectrum_crypto::digest::Sha2Digest256;

use crate::utils::{double_the_seed, merge_public_keys};

#[derive(Debug)]
pub struct Error;

#[derive(Debug)]
pub struct KesSumSecretKey<TCurve: CurveArithmetic> {
    sk_0: SecretKey<TCurve>,
    seed_1: Sha2Digest256,
    pk_0: PublicKey<TCurve>,
    pk_1: PublicKey<TCurve>,
}

pub struct KesSignature<TCurve: CurveArithmetic + ecdsa::PrimeCurve> {
    sig: Signature<TCurve>,
    pk_0: PublicKey<TCurve>,
    pk_1: PublicKey<TCurve>,
}

pub fn kes_key_gen<TCurve: CurveArithmetic>(
    seed: &Sha2Digest256,
) -> Result<(SecretKey<TCurve>, PublicKey<TCurve>), Error> {
    let seed_bytes: [u8; 32] = (*seed).into();
    let sk: SecretKey<TCurve> = SecretKey::<TCurve>::from_slice(&seed_bytes).unwrap();
    let pk = PublicKey::<TCurve>::from_secret_scalar(&sk.to_nonzero_scalar());
    Ok((sk, pk))
}

pub fn kes_sk_key_gen<TCurve: CurveArithmetic>(seed: &Sha2Digest256) -> Result<SecretKey<TCurve>, Error> {
    let seed_bytes: [u8; 32] = (*seed).into();
    let sk = SecretKey::<TCurve>::from_slice(&seed_bytes).unwrap();
    Ok(sk)
}

pub fn kes_sum_key_gen<TCurve: CurveArithmetic + PointCompression>(
    seed: &Sha2Digest256,
) -> Result<(KesSumSecretKey<TCurve>, PublicKey<TCurve>), Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
{
    let (seed_0, seed_1) = double_the_seed(&seed);
    let (sk_0, pk_0) = kes_key_gen::<TCurve>(&seed_0).unwrap();
    let (_, pk_1) = kes_key_gen::<TCurve>(&seed_1).unwrap();
    let pk_sum = merge_public_keys(&pk_0, &pk_1);
    let sk_sum = KesSumSecretKey {
        sk_0,
        seed_1,
        pk_0,
        pk_1,
    };
    Ok((sk_sum, pk_sum))
}

fn kes_sum_update<TCurve: CurveArithmetic>(
    kes_sk: &KesSumSecretKey<TCurve>,
    current_slot: &i32,
    bound_slot: &i32,
) -> Result<KesSumSecretKey<TCurve>, Error> {
    let sk_new = {
        if *current_slot + 1 >= *bound_slot {
            kes_sk_key_gen::<TCurve>(&kes_sk.seed_1).unwrap()
        } else {
            kes_sk.sk_0.clone()
        }
    };

    Ok(KesSumSecretKey {
        sk_0: sk_new,
        seed_1: kes_sk.seed_1.clone(),
        pk_0: kes_sk.pk_0.clone(),
        pk_1: kes_sk.pk_1.clone(),
    })
}

pub fn kes_sum_sign(
    kes_sk: &KesSumSecretKey<Secp256k1>,
    message: &Sha2Digest256,
) -> Result<KesSignature<Secp256k1>, Error> {
    {
        let signing_key: SigningKey<Secp256k1> = SigningKey::from(kes_sk.sk_0.clone());
        let signature: Signature<Secp256k1> = signing_key.sign(message.as_ref());
        Ok(KesSignature {
            sig: signature,
            pk_0: kes_sk.pk_0,
            pk_1: kes_sk.pk_1,
        })
    }
}

pub fn kes_sum_generic_sign<TCurve>(
    kes_sk: &KesSumSecretKey<TCurve>,
    message: &Sha2Digest256,
) -> Result<KesSignature<TCurve>, Error>
where
    TCurve: CurveArithmetic + elliptic_curve::PrimeCurve,
    <TCurve as CurveArithmetic>::Scalar: SignPrimitive<TCurve>,
    <<TCurve as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    SigningKey<TCurve>: Signer<Signature<TCurve>>,
    SigningKey<TCurve>: SignerMut<Signature<TCurve>>,
{
    {
        let signing_key = SigningKey::from(&kes_sk.sk_0);
        let signature = signing_key.sign(message.as_ref());
        Ok(KesSignature {
            sig: signature,
            pk_0: kes_sk.pk_0.clone(),
            pk_1: kes_sk.pk_1.clone(),
        })
    }
}

pub fn kes_sum_verify(
    signature: &KesSignature<Secp256k1>,
    kes_pk: &PublicKey<Secp256k1>,
    message: &Sha2Digest256,
    bound_slot: &i32,
    signing_slot: &i32,
) -> Result<bool, Error> {
    let actual_pk = merge_public_keys(&signature.pk_0, &signature.pk_1);

    let result = {
        if actual_pk == *kes_pk {
            let ver_key: VerifyingKey<Secp256k1> = {
                if *signing_slot < *bound_slot {
                    VerifyingKey::from(signature.pk_0.clone())
                } else {
                    VerifyingKey::from(signature.pk_1.clone())
                }
            };
            match ver_key.verify(&message.as_ref(), &signature.sig) {
                Ok(_) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    };
    Ok(result)
}

#[cfg(test)]
mod test {
    use elliptic_curve::rand_core::{OsRng, RngCore};
    use k256::Secp256k1;

    use spectrum_crypto::digest::{sha256_hash, Sha2Digest256};

    use crate::kes::{kes_sum_key_gen, kes_sum_sign, kes_sum_update, kes_sum_verify};

    #[test]
    fn key_gen_sum_test() {
        let seed_00 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let seed_01 = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (sk_sum_0, pk_sum_0) = kes_sum_key_gen::<Secp256k1>(&seed_00).unwrap();
        let (_, pk_sum_1) = kes_sum_key_gen::<Secp256k1>(&seed_01).unwrap();

        assert_ne!(sk_sum_0.pk_0, sk_sum_0.pk_1);
        assert_ne!(seed_00, sk_sum_0.seed_1);
        assert_ne!(pk_sum_0, sk_sum_0.pk_0);
        assert_ne!(pk_sum_0, sk_sum_0.pk_1);

        assert_ne!(seed_01, seed_00);
        assert_ne!(pk_sum_0, pk_sum_1);
    }

    #[test]
    fn kes_sum_update_test() {
        let bound_slot = 6;
        let current_slot_0 = 0;
        let current_slot_1 = bound_slot.clone() / 2;
        let current_slot_2 = bound_slot.clone() - 1;
        let current_slot_3 = bound_slot.clone() + 1;

        let seed = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (sk_sum, _) = kes_sum_key_gen::<Secp256k1>(&seed).unwrap();

        let sk_new_0 = kes_sum_update::<Secp256k1>(&sk_sum, &current_slot_0, &bound_slot).unwrap();

        let sk_new_1 = kes_sum_update::<Secp256k1>(&sk_new_0, &current_slot_1, &bound_slot).unwrap();

        let sk_new_2 = kes_sum_update::<Secp256k1>(&sk_new_1, &current_slot_2, &bound_slot).unwrap();

        let sk_new_3 = kes_sum_update::<Secp256k1>(&sk_new_2, &current_slot_3, &bound_slot).unwrap();

        assert_eq!(sk_sum.sk_0, sk_new_0.sk_0);
        assert_eq!(sk_sum.sk_0, sk_new_1.sk_0);
        assert_ne!(sk_sum.sk_0, sk_new_2.sk_0);
        assert_eq!(sk_new_2.sk_0, sk_new_3.sk_0);
    }

    #[test]
    fn kes_sum_sign_test() {
        let bound_slot = 6;
        let current_slot_0 = 1;
        let current_slot_1 = bound_slot - 1;

        let seed = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (sk_sum, _) = kes_sum_key_gen::<Secp256k1>(&seed).unwrap();

        let sk_new_0 = kes_sum_update::<Secp256k1>(&sk_sum, &current_slot_0, &bound_slot).unwrap();

        let sk_new_1 = kes_sum_update::<Secp256k1>(&sk_new_0, &current_slot_1, &bound_slot).unwrap();

        let m_0_hash: Sha2Digest256 = sha256_hash("Hi".as_bytes());
        let m_1_hash: Sha2Digest256 = sha256_hash("Buy".as_bytes());

        let sign_0 = kes_sum_sign(&sk_new_0, &m_0_hash).unwrap();
        let sign_01 = kes_sum_sign(&sk_new_0, &m_1_hash).unwrap();
        let sign_1 = kes_sum_sign(&sk_new_1, &m_0_hash).unwrap();
        let sign_10 = kes_sum_sign(&sk_new_1, &m_0_hash).unwrap();

        assert_eq!(sk_sum.sk_0, sk_new_0.sk_0);
        assert_ne!(sk_new_0.sk_0, sk_new_1.sk_0);
        assert_ne!(sign_0.sig.to_bytes(), sign_1.sig.to_bytes());
        assert_ne!(sign_0.sig.to_bytes(), sign_01.sig.to_bytes());
        assert_eq!(sign_1.sig.to_bytes(), sign_10.sig.to_bytes());
    }

    #[test]
    fn kes_sum_verify_test() {
        let bound_slot = 6;
        let current_slot_0 = 1;
        let current_slot_1 = bound_slot;

        let seed = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (sk_sum, pk_sum) = kes_sum_key_gen::<Secp256k1>(&seed).unwrap();

        let sk_new_0 = kes_sum_update::<Secp256k1>(&sk_sum, &current_slot_0, &bound_slot).unwrap();

        let sk_new_1 = kes_sum_update::<Secp256k1>(&sk_new_0, &current_slot_1, &bound_slot).unwrap();

        let m_0_hash: Sha2Digest256 = sha256_hash("Hi".as_bytes());
        let m_1_hash: Sha2Digest256 = sha256_hash("Buy".as_bytes());

        let sign_00 = kes_sum_sign(&sk_new_0, &m_0_hash).unwrap();
        let sign_10 = kes_sum_sign(&sk_new_1, &m_0_hash).unwrap();

        let ver_00_fair = kes_sum_verify(&sign_00, &pk_sum, &m_0_hash, &bound_slot, &current_slot_0).unwrap();
        let ver_00_mal_message =
            kes_sum_verify(&sign_00, &pk_sum, &m_1_hash, &bound_slot, &current_slot_0).unwrap();
        let ver_00_mal_slot =
            kes_sum_verify(&sign_00, &pk_sum, &m_1_hash, &bound_slot, &current_slot_1).unwrap();
        let ver_10_fair = kes_sum_verify(&sign_10, &pk_sum, &m_0_hash, &bound_slot, &current_slot_1).unwrap();

        let seed_0 = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (_, pk_sum_mal) = kes_sum_key_gen::<Secp256k1>(&seed_0).unwrap();

        let ver_10_mal_pk =
            kes_sum_verify(&sign_10, &pk_sum_mal, &m_0_hash, &bound_slot, &current_slot_1).unwrap();

        assert!(ver_00_fair);
        assert!(!!!ver_00_mal_message);
        assert!(!!!ver_00_mal_slot);
        assert!(ver_10_fair);
        assert!(!!!ver_10_mal_pk);
    }
}
