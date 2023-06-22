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

use elliptic_curve::{CurveArithmetic, PublicKey, Scalar, SecretKey};
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use spectrum_crypto::digest::{sha256_hash, Sha2Digest256};
use spectrum_vrf::utils::projective_point_to_bytes;

use crate::utils::{double_the_seed, hash_to_public_key};

#[derive(Debug)]
pub struct Error;

#[derive(Debug)]
pub struct KesSumSecretKey<TCurve: CurveArithmetic>
{
    sk_0: SecretKey<TCurve>,
    seed_1: Sha2Digest256,
    pk_0: PublicKey<TCurve>,
    pk_1: PublicKey<TCurve>,

}

pub struct KesSignature<TCurve: CurveArithmetic>
{
    sig: Sha2Digest256,
    pk_0: PublicKey<TCurve>,
    pk_1: PublicKey<TCurve>,
}

pub fn kes_key_gen<TCurve: CurveArithmetic>(seed: &Sha2Digest256) -> Result<(SecretKey<TCurve>,
                                                                             PublicKey<TCurve>),
    Error>
{
    let seed_bytes: [u8; 32] = (*seed).into();
    let sk: SecretKey::<TCurve> = SecretKey::<TCurve>::from_slice(&seed_bytes).unwrap();
    let pk = PublicKey::<TCurve>::from_secret_scalar(
        &sk.to_nonzero_scalar());
    Ok((sk, pk))
}

pub fn kes_sk_key_gen<TCurve: CurveArithmetic>(seed: &Sha2Digest256) -> Result<SecretKey<TCurve>,
    Error>
{
    let seed_bytes: [u8; 32] = (*seed).into();
    let sk = SecretKey::<TCurve>::from_slice(&seed_bytes).unwrap();
    Ok(sk)
}

pub fn kes_sum_key_gen<TCurve: CurveArithmetic + PointCompression>(seed: &Sha2Digest256) ->
Result<(KesSumSecretKey<TCurve>, PublicKey<TCurve>), Error>
    where <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
          <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
          <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>
{
    let (seed_0, seed_1) = double_the_seed(&seed);
    let (sk_0, pk_0) = kes_key_gen::<TCurve>(
        &seed_0).unwrap();
    let (_, pk_1) = kes_key_gen::<TCurve>(&seed_1).unwrap();
    let pk_0_bytes = projective_point_to_bytes::<TCurve>(pk_0.to_projective());
    let pk_1_bytes = projective_point_to_bytes::<TCurve>(pk_1.to_projective());

    let pk_concatenated = [pk_0_bytes, pk_1_bytes].concat();
    let pk_sum_hash = sha256_hash(&pk_concatenated);

    let pk_sum = hash_to_public_key::<TCurve>(pk_sum_hash);
    let sk_sum = KesSumSecretKey { sk_0, seed_1, pk_0, pk_1 };
    Ok((sk_sum, pk_sum))
}

fn kes_sum_update<TCurve: CurveArithmetic>(kes_sk: &KesSumSecretKey<TCurve>,
                                           current_slot: &i32,
                                           total_slots: &i32)
                                           -> Result<KesSumSecretKey<TCurve>, Error>
{
    let sk_new = {
        if *current_slot + 1 == *total_slots {
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

pub fn kes_sum_sign<TCurve: CurveArithmetic>(kes_sk: KesSumSecretKey<TCurve>,
                                             message: Sha2Digest256,
                                             total_slots: i32,
                                             current_slot: i32)
                                             -> Result<KesSignature<TCurve>, Error>
{
    let sigma_new = if current_slot < total_slots {
        kes_sum_sign::<TCurve>(kes_sk, message, total_slots, current_slot)
    } else {
        return kes_sum_sign::<TCurve>(kes_sk, message, total_slots, current_slot);
    };
    todo!()
}

pub fn kes_verify<TCurve: CurveArithmetic>(signature: KesSignature<TCurve>,
                                           kes_pk: PublicKey<TCurve>,
                                           message: Sha2Digest256,
                                           total_slots: i32,
                                           signing_slot: i32)
                                           -> Result<bool, Error>
{
    todo!()
}

#[cfg(test)]
mod test {
    use elliptic_curve::rand_core::{OsRng, RngCore};
    use k256::Secp256k1;

    use spectrum_crypto::digest::sha256_hash;

    use crate::kes::{kes_sum_key_gen, kes_sum_update};

    #[test]
    fn key_gen_sum_test() {
        let seed_00 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let seed_01 = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (sk_sum_0, pk_sum_0)
            = kes_sum_key_gen::<Secp256k1>(&seed_00).unwrap();
        let (_, pk_sum_1)
            = kes_sum_key_gen::<Secp256k1>(&seed_01).unwrap();

        assert_ne!(sk_sum_0.pk_0, sk_sum_0.pk_1);
        assert_ne!(seed_00, sk_sum_0.seed_1);
        assert_ne!(pk_sum_0, sk_sum_0.pk_0);
        assert_ne!(pk_sum_0, sk_sum_0.pk_1);

        assert_ne!(seed_01, seed_00);
        assert_ne!(pk_sum_0, pk_sum_1);
    }

    #[test]
    fn kes_sum_update_test() {
        let total_slots = 6;
        let current_slot_0 = 0;
        let current_slot_1 = total_slots / 2;
        let current_slot_2 = total_slots - 1;
        let current_slot_3 = total_slots + 1;

        let seed = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (sk_sum, _)
            = kes_sum_key_gen::<Secp256k1>(&seed).unwrap();

        let sk_new_0 = kes_sum_update::<Secp256k1>(&sk_sum,
                                                   &current_slot_0,
                                                   &total_slots).unwrap();

        let sk_new_1 = kes_sum_update::<Secp256k1>(&sk_new_0,
                                                   &current_slot_1,
                                                   &total_slots).unwrap();

        let sk_new_2 = kes_sum_update::<Secp256k1>(&sk_new_1,
                                                   &current_slot_2,
                                                   &total_slots).unwrap();

        let sk_new_3 = kes_sum_update::<Secp256k1>(&sk_new_2,
                                                   &current_slot_3,
                                                   &total_slots).unwrap();

        assert_eq!(sk_sum.sk_0, sk_new_0.sk_0);
        assert_eq!(sk_sum.sk_0, sk_new_1.sk_0);
        assert_ne!(sk_sum.sk_0, sk_new_2.sk_0);
        assert_eq!(sk_new_2.sk_0, sk_new_3.sk_0);
    }
}

