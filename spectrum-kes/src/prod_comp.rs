use std::ops::Add;

use ecdsa::hazmat::SignPrimitive;
use ecdsa::signature::{Signer, SignerMut, Verifier};
use ecdsa::{Signature, SigningKey, VerifyingKey};
use elliptic_curve::generic_array::ArrayLength;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, PublicKey, SecretKey};

use spectrum_crypto::digest::Sha2Digest256;
use spectrum_vrf::utils::projective_point_to_bytes;

use crate::utils::{associate_message_with_slot, associate_pk_with_slot, double_the_seed, kes_key_gen};

#[derive(Debug)]
pub struct Error;

pub struct KesProdSecretKey<TCurve: CurveArithmetic + ecdsa::PrimeCurve> {
    sk_0: SecretKey<TCurve>,
    sk_1: SecretKey<TCurve>,
    sig: Signature<TCurve>,
    pk_1: PublicKey<TCurve>,
    seed_11: Sha2Digest256,
}

pub struct KesProdSignature<TCurve: CurveArithmetic + ecdsa::PrimeCurve> {
    pk_1: PublicKey<TCurve>,
    sig_0: Signature<TCurve>,
    sig_1: Signature<TCurve>,
}

pub fn kes_prod_key_gen<TCurve: CurveArithmetic + ecdsa::PrimeCurve + PointCompression>(
    seed: &Sha2Digest256,
) -> Result<(KesProdSecretKey<TCurve>, PublicKey<TCurve>), Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
    <TCurve as CurveArithmetic>::Scalar: SignPrimitive<TCurve>,
    <<TCurve as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    SigningKey<TCurve>: Signer<Signature<TCurve>>,
    SigningKey<TCurve>: SignerMut<Signature<TCurve>>,
{
    let (seed_0, seed_01) = double_the_seed(&seed);
    let (seed_10, seed_11) = double_the_seed(&seed_01);

    let (sk_0, pk) = kes_key_gen::<TCurve>(&seed_0).unwrap();
    let (sk_1, pk_1) = kes_key_gen::<TCurve>(&seed_10).unwrap();

    let signing_key = SigningKey::from(&sk_0);
    let sig = signing_key.sign(&projective_point_to_bytes::<TCurve>(pk_1.to_projective()));

    Ok((
        KesProdSecretKey {
            sk_0,
            sk_1,
            sig,
            pk_1,
            seed_11,
        },
        pk,
    ))
}

fn kes_prod_update<TCurve: CurveArithmetic + ecdsa::PrimeCurve + PointCompression>(
    kes_sk: &KesProdSecretKey<TCurve>,
    current_slot: &i32,
    bound_slot: &i32,
) -> Result<KesProdSecretKey<TCurve>, Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
    <TCurve as CurveArithmetic>::Scalar: SignPrimitive<TCurve>,
    <<TCurve as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    SigningKey<TCurve>: Signer<Signature<TCurve>>,
    SigningKey<TCurve>: SignerMut<Signature<TCurve>>,
{
    //TODO: make recursive
    let (sk_new, pk_new, sig) = {
        if ((*current_slot).clone() + 1).rem_euclid((*bound_slot).clone()) == 0 {
            let (seed_0, _) = double_the_seed(&kes_sk.seed_11);
            let (sk_new_, pk_new_) = kes_key_gen::<TCurve>(&seed_0).unwrap();

            let m = associate_pk_with_slot::<TCurve>(&current_slot, &bound_slot, &pk_new_);

            let signing_key = SigningKey::from(&kes_sk.sk_0);
            let sig_ = signing_key.sign(&m);
            (sk_new_, pk_new_, sig_)
        } else {
            (kes_sk.sk_1.clone(), kes_sk.pk_1.clone(), kes_sk.sig.clone())
        }
    };

    Ok(KesProdSecretKey {
        sk_0: kes_sk.sk_0.clone(),
        sk_1: sk_new,
        pk_1: pk_new,
        sig,
        seed_11: kes_sk.seed_11.clone(),
    })
}

pub fn kes_prod_sign<TCurve>(
    kes_sk: &KesProdSecretKey<TCurve>,
    message: &Sha2Digest256,
    bound_slot: &i32,
    current_slot: &i32,
) -> Result<KesProdSignature<TCurve>, Error>
where
    TCurve: CurveArithmetic + elliptic_curve::PrimeCurve,
    <TCurve as CurveArithmetic>::Scalar: SignPrimitive<TCurve>,
    <<TCurve as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    SigningKey<TCurve>: Signer<Signature<TCurve>>,
    SigningKey<TCurve>: SignerMut<Signature<TCurve>>,
{
    //TODO: make recursive
    {
        let m = associate_message_with_slot(&current_slot, &bound_slot, &message);
        let signing_key = SigningKey::from(&kes_sk.sk_1);
        let sig_1 = signing_key.sign(&m);
        Ok(KesProdSignature {
            sig_0: kes_sk.sig.clone(),
            sig_1,
            pk_1: kes_sk.pk_1.clone(),
        })
    }
}

pub fn kes_prod_verify<TCurve: CurveArithmetic + ecdsa::PrimeCurve + PointCompression>(
    signature: &KesProdSignature<TCurve>,
    kes_pk: &PublicKey<TCurve>,
    message: &Sha2Digest256,
    bound_slot: &i32,
    signing_slot: &i32,
) -> Result<bool, Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
    VerifyingKey<TCurve>: Verifier<Signature<TCurve>>,
{
    let ver_key_0: VerifyingKey<TCurve> = VerifyingKey::from(kes_pk.clone());
    let ver_key_1: VerifyingKey<TCurve> = VerifyingKey::from(signature.pk_1);

    let m_0 = if (*signing_slot).clone() + 1 >= (*bound_slot).clone() {
        associate_pk_with_slot::<TCurve>(&signing_slot, &bound_slot, &signature.pk_1)
    } else {
        projective_point_to_bytes::<TCurve>(signature.pk_1.to_projective())
    };

    let m_1 = associate_message_with_slot(&signing_slot, &bound_slot, &message);

    let ver_0 = match ver_key_0.verify(m_0.as_ref(), &signature.sig_0.clone()) {
        Ok(_) => true,
        Err(_) => false,
    };

    let ver_1 = match ver_key_1.verify(&m_1, &signature.sig_1.clone()) {
        Ok(_) => true,
        Err(_) => false,
    };

    Ok(ver_0 & ver_1)
}

#[cfg(test)]
mod test {
    use elliptic_curve::rand_core::{OsRng, RngCore};
    use k256::Secp256k1;

    use spectrum_crypto::digest::{sha256_hash, Sha2Digest256};

    use crate::prod_comp::{kes_prod_key_gen, kes_prod_sign, kes_prod_update, kes_prod_verify};

    #[test]
    fn key_gen_prod_test() {
        let seed_00 = sha256_hash(OsRng.next_u64().to_string().as_bytes());
        let seed_01 = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (sk_prod_0, pk_prod_0) = kes_prod_key_gen::<Secp256k1>(&seed_00).unwrap();
        let (_, pk_prod_1) = kes_prod_key_gen::<Secp256k1>(&seed_01).unwrap();

        assert_ne!(sk_prod_0.sk_0, sk_prod_0.sk_1);
        assert_ne!(seed_00, sk_prod_0.seed_11);
        assert_ne!(seed_01, seed_00);
        assert_ne!(pk_prod_0, sk_prod_0.pk_1);
        assert_ne!(pk_prod_1, pk_prod_0);
    }

    #[test]
    fn kes_prod_update_test() {
        let bound_slot = 6;
        let current_slot_0 = 0;
        let current_slot_1 = bound_slot.clone() / 2;
        let current_slot_2 = bound_slot.clone() - 1;
        let current_slot_3 = bound_slot.clone() + 1;

        let seed = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (sk_prod, _) = kes_prod_key_gen::<Secp256k1>(&seed).unwrap();

        let sk_new_0 = kes_prod_update::<Secp256k1>(&sk_prod, &current_slot_0, &bound_slot).unwrap();

        let sk_new_1 = kes_prod_update::<Secp256k1>(&sk_new_0, &current_slot_1, &bound_slot).unwrap();

        let sk_new_2 = kes_prod_update::<Secp256k1>(&sk_new_1, &current_slot_2, &bound_slot).unwrap();

        let sk_new_3 = kes_prod_update::<Secp256k1>(&sk_new_2, &current_slot_3, &bound_slot).unwrap();

        assert_eq!(sk_prod.sk_1, sk_new_0.sk_1);
        assert_eq!(sk_prod.sk_1, sk_new_1.sk_1);
        assert_ne!(sk_prod.sk_1, sk_new_2.sk_1);
        assert_eq!(sk_new_2.sk_1, sk_new_3.sk_1);
        assert_eq!(sk_prod.pk_1, sk_new_0.pk_1);
        assert_ne!(sk_new_0.pk_1, sk_new_2.pk_1);
    }

    #[test]
    fn kes_prod_sign_test() {
        let bound_slot = 6;
        let current_slot_0 = 1;
        let current_slot_1 = bound_slot - 1;

        let seed = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (sk_prod, _) = kes_prod_key_gen::<Secp256k1>(&seed).unwrap();

        let sk_new_0 = kes_prod_update::<Secp256k1>(&sk_prod, &current_slot_0, &bound_slot).unwrap();

        let sk_new_1 = kes_prod_update::<Secp256k1>(&sk_new_0, &current_slot_1, &bound_slot).unwrap();

        let m_0_hash: Sha2Digest256 = sha256_hash("Hi".as_bytes());
        let m_1_hash: Sha2Digest256 = sha256_hash("Buy".as_bytes());

        let sign_0 = kes_prod_sign::<Secp256k1>(&sk_new_0, &m_0_hash, &bound_slot, &current_slot_0).unwrap();
        let sign_01 = kes_prod_sign::<Secp256k1>(&sk_new_0, &m_1_hash, &bound_slot, &current_slot_0).unwrap();
        let sign_1 = kes_prod_sign::<Secp256k1>(&sk_new_1, &m_0_hash, &bound_slot, &current_slot_1).unwrap();
        let sign_10 = kes_prod_sign::<Secp256k1>(&sk_new_1, &m_1_hash, &bound_slot, &current_slot_1).unwrap();

        assert_eq!(sk_prod.sk_1, sk_new_0.sk_1);
        assert_ne!(sk_new_0.sk_1, sk_new_1.sk_1);
        assert_ne!(sign_0.sig_1.to_bytes(), sign_1.sig_1.to_bytes());
        assert_ne!(sign_0.sig_1.to_bytes(), sign_01.sig_1.to_bytes());
        assert_ne!(sign_1.sig_1.to_bytes(), sign_10.sig_1.to_bytes());
    }

    #[test]
    fn kes_prod_verify_test() {
        let bound_slot = 6;
        let current_slot_0 = 1;
        let current_slot_1 = bound_slot - 1;

        let seed = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (sk_prod, pk_prod) = kes_prod_key_gen::<Secp256k1>(&seed).unwrap();

        let sk_new_0 = kes_prod_update::<Secp256k1>(&sk_prod, &current_slot_0, &bound_slot).unwrap();

        let sk_new_1 = kes_prod_update::<Secp256k1>(&sk_new_0, &current_slot_1, &bound_slot).unwrap();

        let m_0_hash: Sha2Digest256 = sha256_hash("Hi".as_bytes());
        let m_1_hash: Sha2Digest256 = sha256_hash("Buy".as_bytes());

        let sign_00 = kes_prod_sign::<Secp256k1>(&sk_new_0, &m_0_hash, &bound_slot, &current_slot_0).unwrap();
        let sign_10 = kes_prod_sign::<Secp256k1>(&sk_new_1, &m_0_hash, &bound_slot, &current_slot_1).unwrap();

        let ver_00_fair =
            kes_prod_verify::<Secp256k1>(&sign_00, &pk_prod, &m_0_hash, &bound_slot, &current_slot_0)
                .unwrap();
        let ver_00_mal_message =
            kes_prod_verify::<Secp256k1>(&sign_00, &pk_prod, &m_1_hash, &bound_slot, &current_slot_0)
                .unwrap();
        let ver_00_mal_slot =
            kes_prod_verify::<Secp256k1>(&sign_00, &pk_prod, &m_1_hash, &bound_slot, &current_slot_1)
                .unwrap();
        let ver_10_fair =
            kes_prod_verify::<Secp256k1>(&sign_10, &pk_prod, &m_0_hash, &bound_slot, &current_slot_1)
                .unwrap();

        let seed_0 = sha256_hash(OsRng.next_u64().to_string().as_bytes());

        let (_, pk_prod_mal) = kes_prod_key_gen::<Secp256k1>(&seed_0).unwrap();

        let ver_10_mal_pk =
            kes_prod_verify::<Secp256k1>(&sign_10, &pk_prod_mal, &m_0_hash, &bound_slot, &current_slot_1)
                .unwrap();

        assert!(ver_00_fair);
        assert!(!!!ver_00_mal_message);
        assert!(!!!ver_00_mal_slot);
        assert!(ver_10_fair);
        assert!(!!!ver_10_mal_pk);
    }
}
