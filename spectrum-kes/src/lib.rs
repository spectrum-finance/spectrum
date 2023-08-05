use std::ops::Add;

use const_oid::AssociatedOid;
use ecdsa::hazmat::SignPrimitive;
use ecdsa::signature::digest::{FixedOutput, HashMarker, Update};
use ecdsa::signature::{Signer, SignerMut, Verifier};
use ecdsa::{Signature, SignatureSize, SigningKey, VerifyingKey};
use elliptic_curve::generic_array::ArrayLength;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey, SecretKey};

use spectrum_crypto::digest::{hash, Digest};
use spectrum_vrf::utils::{key_pair_gen, projective_point_to_bytes};

use crate::composition_utils::{
    calculate_scheme_pk_from_signature, get_left_merkle_tree_branch, insert_in_vec, sum_composition_pk_gen,
};
use crate::utils::{concat, merge_public_keys};

mod composition_utils;
mod tests;
mod utils;

#[derive(Debug)]
pub struct Error;

#[derive(Debug)]
pub struct KESSecret<HF: HashMarker + FixedOutput, TCurve: CurveArithmetic> {
    initial_merkle_tree_high: u32,
    n_hot_sk_updates: u32,
    hot_sk: SecretKey<TCurve>,
    hot_pk: PublicKey<TCurve>,
    merkle_seeds: Vec<Digest<HF>>,
    merkle_public_keys: Vec<(PublicKey<TCurve>, PublicKey<TCurve>)>,
}

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(
    bound = "TCurve: CurveArithmetic + ecdsa::PrimeCurve + AssociatedOid, SignatureSize<TCurve>: ArrayLength<u8>, AffinePoint<TCurve>: FromEncodedPoint<TCurve> + ToEncodedPoint<TCurve>, FieldBytesSize<TCurve>: ModulusSize"
)]
pub struct KESSignature<TCurve: CurveArithmetic + ecdsa::PrimeCurve> {
    pub sig: Signature<TCurve>,
    pub hot_pk: PublicKey<TCurve>,
    pub other_pks: Vec<PublicKey<TCurve>>,
}

pub fn kes_gen<HF, TCurve: CurveArithmetic + PointCompression>(
    merkle_tree_high: &u32,
    seed: &Digest<HF>,
) -> Result<(KESSecret<HF, TCurve>, PublicKey<TCurve>), Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
    HF: Default + FixedOutput + HashMarker + Update,
{
    let (sk_actual, pk_actual, pk_all_scheme, merkle_seeds, merkle_public_keys) = {
        if *merkle_tree_high == 0 {
            let (sk_, pk_) = key_pair_gen::<HF, TCurve>(seed);
            (sk_, pk_, pk_.clone(), vec![], vec![])
        } else {
            // Generate all keys for the left branch and save seeds from the right branch
            let (sk_0, pk_0, merkle_seeds_) =
                get_left_merkle_tree_branch::<HF, TCurve>(merkle_tree_high, seed).unwrap();

            // Aggregate main Merkle tree Public Key and Public Keys of the related leafs
            let mut pk_all_scheme_ = pk_0.clone();
            let mut merkle_public_keys_ = Vec::new();

            let mut high = 0;
            for i in (0..merkle_seeds_.len()).rev() {
                let seed = merkle_seeds_[i].clone();
                let pk_right = if *merkle_tree_high == 0 {
                    key_pair_gen::<HF, TCurve>(&seed).1
                } else {
                    sum_composition_pk_gen::<HF, TCurve>(&high, &seed).unwrap()
                };
                high += 1;
                merkle_public_keys_.push((pk_all_scheme_, pk_right));
                pk_all_scheme_ = merge_public_keys::<HF, TCurve>(&pk_all_scheme_, &pk_right);
            }
            merkle_public_keys_.reverse();
            (sk_0, pk_0, pk_all_scheme_, merkle_seeds_, merkle_public_keys_)
        }
    };

    assert_eq!(merkle_public_keys.len(), *merkle_tree_high as usize);
    assert_eq!(merkle_seeds.len(), *merkle_tree_high as usize);

    let sk_sum = KESSecret {
        initial_merkle_tree_high: *merkle_tree_high,
        n_hot_sk_updates: 0,
        hot_pk: pk_actual,
        hot_sk: sk_actual,
        merkle_seeds,
        merkle_public_keys,
    };
    Ok((sk_sum, pk_all_scheme))
}

pub fn kes_update<HF, TCurve: CurveArithmetic + PointCompression>(
    secret: KESSecret<HF, TCurve>,
) -> Result<KESSecret<HF, TCurve>, Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
    HF: Default + FixedOutput + HashMarker + Update + 'static,
{
    let last_seed_ind = secret.merkle_seeds.len() - 1;

    let mut merkle_public_keys_new = Vec::new();
    let mut merkle_seeds_new = Vec::new();

    let (sk_new, pk_new) = {
        // Count number of anchors between the consequent leafs
        let anc_num = usize::count_ones(
            secret.n_hot_sk_updates as usize ^ (secret.n_hot_sk_updates.clone() as usize + 1),
        );
        // Repair next Secret Key
        if anc_num == 1 {
            if secret.merkle_seeds.len() >= 1 {
                // Remove last Seed
                merkle_seeds_new =
                    insert_in_vec(merkle_seeds_new, secret.merkle_seeds.clone(), 0..last_seed_ind);
                merkle_public_keys_new = insert_in_vec(
                    merkle_public_keys_new,
                    secret.merkle_public_keys.clone(),
                    0..secret.initial_merkle_tree_high as usize,
                );
            }
            key_pair_gen::<HF, TCurve>(&secret.merkle_seeds[last_seed_ind])
        } else {
            let seed = secret.merkle_seeds[last_seed_ind].clone();

            // Get the child branch
            let (secret_child, pk_child) = kes_gen::<HF, TCurve>(&(anc_num - 1), &seed).unwrap();

            if secret.merkle_public_keys.len() > 1 {
                let ind = (secret.initial_merkle_tree_high as i32 - anc_num as i32) as usize;

                assert_eq!(secret.merkle_public_keys[ind].1, pk_child);

                merkle_seeds_new = insert_in_vec(
                    merkle_seeds_new,
                    secret.merkle_seeds.clone(),
                    0..secret.merkle_seeds.len() - 1,
                );
            }

            // Remove (High - anc_num) Public Keys and insert from the child
            merkle_public_keys_new = insert_in_vec(
                merkle_public_keys_new,
                secret.merkle_public_keys.clone(),
                0..(secret.merkle_public_keys.len() - secret_child.merkle_public_keys.len()),
            );
            merkle_public_keys_new = insert_in_vec(
                merkle_public_keys_new,
                secret_child.merkle_public_keys.clone(),
                0..secret_child.merkle_public_keys.len(),
            );
            merkle_seeds_new = insert_in_vec(
                merkle_seeds_new,
                secret_child.merkle_seeds.clone(),
                0..secret_child.merkle_public_keys.len(),
            );

            assert_eq!(
                merkle_public_keys_new.len() as u32,
                secret.initial_merkle_tree_high
            );

            (secret_child.hot_sk, secret_child.hot_pk)
        }
    };

    Ok(KESSecret {
        initial_merkle_tree_high: secret.initial_merkle_tree_high.clone(),
        n_hot_sk_updates: secret.n_hot_sk_updates.clone() + 1,
        hot_sk: sk_new,
        hot_pk: pk_new,
        merkle_seeds: merkle_seeds_new,
        merkle_public_keys: merkle_public_keys_new,
    })
}

pub fn kes_sign<HF, TCurve>(
    message: &Digest<HF>,
    secret: &KESSecret<HF, TCurve>,
    current_slot: &u32,
) -> Result<KESSignature<TCurve>, Error>
where
    HF: HashMarker + FixedOutput,
    TCurve: CurveArithmetic + elliptic_curve::PrimeCurve,
    <TCurve as CurveArithmetic>::Scalar: SignPrimitive<TCurve>,
    <<TCurve as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    SigningKey<TCurve>: Signer<Signature<TCurve>>,
    SigningKey<TCurve>: SignerMut<Signature<TCurve>>,
{
    // Sign the message with an actual Secret Key (message is associated with slot)
    let signing_key = SigningKey::from(&secret.hot_sk);
    let sig = signing_key.sign(&concat(&current_slot, &message));

    let mut leaf_related_public_keys = Vec::new();
    let mut h = current_slot.clone();

    // Aggregate the corresponding leafs' Public Key
    for i in 0..secret.merkle_public_keys.len() {
        let leaf_high = secret.initial_merkle_tree_high.clone() - i as u32;
        let actual_high = (2u32).pow(leaf_high - 1);
        if h >= actual_high {
            h -= actual_high;
            leaf_related_public_keys.push(secret.merkle_public_keys[i].0.clone());
        } else {
            leaf_related_public_keys.push(secret.merkle_public_keys[i].1.clone());
        }
    }

    Ok(KESSignature {
        sig,
        hot_pk: secret.hot_pk.clone(),
        other_pks: leaf_related_public_keys,
    })
}

pub fn kes_verify<HF, TCurve: CurveArithmetic + ecdsa::PrimeCurve + PointCompression>(
    signature: &KESSignature<TCurve>,
    message: &Digest<HF>,
    all_scheme_pk: &PublicKey<TCurve>,
    signing_slot: &u32,
) -> Result<bool, Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
    VerifyingKey<TCurve>: Verifier<Signature<TCurve>>,
    HF: Default,
    HF: FixedOutput,
    HF: HashMarker,
    HF: Update,
{
    // Verify message
    let ver_key: VerifyingKey<TCurve> = VerifyingKey::from(signature.hot_pk.clone());
    let message_is_verified = ver_key
        .verify(&concat(&signing_slot, &message), &signature.sig)
        .is_ok();

    // Verify scheme Public Key
    let sig_scheme_pk = calculate_scheme_pk_from_signature::<HF, TCurve>(signature, signing_slot);
    let pk_is_verified =
        hash::<HF>(&projective_point_to_bytes::<TCurve>(&sig_scheme_pk.to_projective()).as_slice()).as_ref()
            == hash::<HF>(&projective_point_to_bytes::<TCurve>(&all_scheme_pk.to_projective()).as_slice())
                .as_ref();

    Ok(message_is_verified && pk_is_verified)
}
