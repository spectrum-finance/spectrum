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

use crate::utils::{double_the_seed, kes_key_gen};

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
    let (seed_0, _) = double_the_seed(&seed);
    let (seed_10, seed_11) = double_the_seed(&seed);

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
    let (sk_1, pk_1, sig) = {
        if ((*current_slot).clone() + 1).rem_euclid((*bound_slot).clone()) == 0 {
            let (seed_0, _) = double_the_seed(&kes_sk.seed_11);
            let (sk_1_, pk_1_) = kes_key_gen::<TCurve>(&seed_0).unwrap();

            let m = [
                current_slot
                    .rem_euclid((*bound_slot).clone())
                    .to_string()
                    .as_bytes(),
                &projective_point_to_bytes::<TCurve>(pk_1_.to_projective()),
            ]
            .concat();

            let signing_key = SigningKey::from(&kes_sk.sk_0);
            let sig_ = signing_key.sign(&m);
            (sk_1_, pk_1_, sig_)
        } else {
            (kes_sk.sk_1.clone(), kes_sk.pk_1.clone(), kes_sk.sig.clone())
        }
    };

    Ok(KesProdSecretKey {
        sk_0: kes_sk.sk_0.clone(),
        sk_1,
        pk_1,
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
        let m = [
            message.as_ref(),
            current_slot
                .rem_euclid((*bound_slot).clone())
                .to_string()
                .as_bytes(),
        ]
        .concat();
        let signing_key = SigningKey::from(&kes_sk.sk_0);
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
    let ver_key_1: VerifyingKey<TCurve> = VerifyingKey::from(signature.pk_1.clone());

    let m_0 = [
        &projective_point_to_bytes::<TCurve>(signature.pk_1.to_projective()),
        (signing_slot / bound_slot).to_string().as_bytes(),
    ]
    .concat();

    let m_1 = [
        message.as_ref(),
        signing_slot
            .rem_euclid((*bound_slot).clone())
            .to_string()
            .as_bytes(),
    ]
    .concat();

    let ver_0 = match ver_key_0.verify(&m_0, &signature.sig_0.clone()) {
        Ok(_) => true,
        Err(_) => false,
    };

    let ver_1 = match ver_key_1.verify(&m_1, &signature.sig_1.clone()) {
        Ok(_) => true,
        Err(_) => false,
    };

    Ok(ver_0 | ver_1)
}
