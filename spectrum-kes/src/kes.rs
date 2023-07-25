use std::ops::Add;

use ecdsa::hazmat::SignPrimitive;
use ecdsa::signature::{Signer, SignerMut, Verifier};
use ecdsa::{Signature, SigningKey, VerifyingKey};
use elliptic_curve::generic_array::ArrayLength;
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, PublicKey, SecretKey};

use spectrum_crypto::digest::{sha256_hash, Sha2Digest256};

use crate::composition_utils::{
    calculate_scheme_pk_from_signature, get_left_merkle_tree_branch, insert_in_vec, sum_composition_pk_gen,
};
use crate::utils::{associate_message_with_slot, key_pair_gen, merge_public_keys, projective_point_to_bytes};

#[derive(Debug)]
pub struct Error;

#[derive(Debug)]
pub struct KesSecret<TCurve: CurveArithmetic> {
    initial_merkle_tree_high: u32,
    n_sk_actual_updates: u32,
    sk_actual: SecretKey<TCurve>,
    pk_actual: PublicKey<TCurve>,
    merkle_seeds: Vec<Sha2Digest256>,
    merkle_public_keys: Vec<(PublicKey<TCurve>, PublicKey<TCurve>)>,
}

pub struct KeSignature<TCurve: CurveArithmetic + ecdsa::PrimeCurve> {
    pub(crate) sig: Signature<TCurve>,
    pub(crate) pk_actual: PublicKey<TCurve>,
    pub(crate) scheme_public_keys: Vec<PublicKey<TCurve>>,
}

pub fn kes_gen<TCurve: CurveArithmetic + PointCompression>(
    merkle_tree_high: &u32,
    seed: &Sha2Digest256,
) -> Result<(KesSecret<TCurve>, PublicKey<TCurve>), Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
{
    let (sk_actual, pk_actual, pk_all_scheme, merkle_seeds, merkle_public_keys) = {
        if *merkle_tree_high == 0 {
            let (sk_, pk_) = key_pair_gen::<TCurve>(seed);
            (sk_, pk_, pk_.clone(), vec![], vec![])
        } else {
            // Generate all keys for the left branch and save seeds from the right branch
            let (sk_0, pk_0, merkle_seeds_) =
                get_left_merkle_tree_branch::<TCurve>(merkle_tree_high, seed).unwrap();

            // Aggregate main Merkle tree Public Key and Public Keys of the related leafs
            let mut pk_all_scheme_ = pk_0.clone();
            let mut merkle_public_keys_ = Vec::new();

            let mut high = 0;
            for i in (0..merkle_seeds_.len()).rev() {
                let seed = merkle_seeds_[i].clone();
                let pk_right = if *merkle_tree_high == 0 {
                    key_pair_gen::<TCurve>(&seed).1
                } else {
                    sum_composition_pk_gen::<TCurve>(&high, &seed).unwrap()
                };
                high += 1;
                merkle_public_keys_.push((pk_all_scheme_, pk_right));
                pk_all_scheme_ = merge_public_keys::<TCurve>(&pk_all_scheme_, &pk_right);
            }
            merkle_public_keys_.reverse();
            (sk_0, pk_0, pk_all_scheme_, merkle_seeds_, merkle_public_keys_)
        }
    };

    assert_eq!(merkle_public_keys.len(), *merkle_tree_high as usize);
    assert_eq!(merkle_seeds.len(), *merkle_tree_high as usize);

    let sk_sum = KesSecret {
        initial_merkle_tree_high: *merkle_tree_high,
        n_sk_actual_updates: 0,
        pk_actual,
        sk_actual,
        merkle_seeds,
        merkle_public_keys,
    };
    Ok((sk_sum, pk_all_scheme))
}

pub fn kes_update<TCurve: CurveArithmetic + PointCompression>(
    secret: KesSecret<TCurve>,
) -> Result<KesSecret<TCurve>, Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
{
    let last_seed_ind = secret.merkle_seeds.len() - 1;

    let mut merkle_public_keys_new = Vec::new();
    let mut merkle_seeds_new = Vec::new();

    let (sk_new, pk_new) = {
        // Count number of anchors between the consequent leafs
        let anc_num = usize::count_ones(
            secret.n_sk_actual_updates as usize ^ (secret.n_sk_actual_updates.clone() as usize + 1),
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
            key_pair_gen::<TCurve>(&secret.merkle_seeds[last_seed_ind])
        } else {
            let seed = secret.merkle_seeds[last_seed_ind].clone();

            // Get the child branch
            let (secret_child, pk_child) = kes_gen::<TCurve>(&(anc_num - 1), &seed).unwrap();

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

            (secret_child.sk_actual, secret_child.pk_actual)
        }
    };

    Ok(KesSecret::<TCurve> {
        initial_merkle_tree_high: secret.initial_merkle_tree_high.clone(),
        n_sk_actual_updates: secret.n_sk_actual_updates.clone() + 1,
        sk_actual: sk_new,
        pk_actual: pk_new,
        merkle_seeds: merkle_seeds_new,
        merkle_public_keys: merkle_public_keys_new,
    })
}

pub fn kes_sign<TCurve>(
    message: &Sha2Digest256,
    secret: &KesSecret<TCurve>,
    current_slot: &u32,
) -> Result<KeSignature<TCurve>, Error>
where
    TCurve: CurveArithmetic + elliptic_curve::PrimeCurve,
    <TCurve as CurveArithmetic>::Scalar: SignPrimitive<TCurve>,
    <<TCurve as elliptic_curve::Curve>::FieldBytesSize as Add>::Output: ArrayLength<u8>,
    SigningKey<TCurve>: Signer<Signature<TCurve>>,
    SigningKey<TCurve>: SignerMut<Signature<TCurve>>,
{
    // Sign the message with an actual Secret Key (message is associated with slot)
    let signing_key = SigningKey::from(&secret.sk_actual);
    let sig = signing_key.sign(&associate_message_with_slot(&current_slot, &message));

    let mut leaf_related_public_keys = Vec::new();
    let mut h = current_slot.clone();

    // Aggregate the corresponding leafs' Public Key
    for i in 0..secret.merkle_public_keys.len() {
        let leaf_high = secret.initial_merkle_tree_high.clone() - i as u32;
        let actual_high = (2 as u32).pow((leaf_high as u32 - 1) as u32);
        if h >= actual_high {
            h -= actual_high;
            leaf_related_public_keys.push(secret.merkle_public_keys[i].0.clone());
        } else {
            leaf_related_public_keys.push(secret.merkle_public_keys[i].1.clone());
        }
    }

    Ok(KeSignature {
        sig,
        pk_actual: secret.pk_actual.clone(),
        scheme_public_keys: leaf_related_public_keys,
    })
}

pub fn kes_verify<TCurve: CurveArithmetic + ecdsa::PrimeCurve + PointCompression>(
    signature: &KeSignature<TCurve>,
    message: &Sha2Digest256,
    all_scheme_pk: &PublicKey<TCurve>,
    signing_slot: &u32,
) -> Result<bool, Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
    VerifyingKey<TCurve>: Verifier<Signature<TCurve>>,
{
    // Verify message
    let ver_key: VerifyingKey<TCurve> = VerifyingKey::from(signature.pk_actual.clone());
    let message_is_verified = match ver_key.verify(
        &associate_message_with_slot(&signing_slot, &message),
        &signature.sig,
    ) {
        Ok(_) => true,
        Err(_) => false,
    };

    // Verify scheme Public Key
    let sig_scheme_pk = calculate_scheme_pk_from_signature(signature, signing_slot);
    let pk_is_verified =
        sha256_hash(&projective_point_to_bytes::<TCurve>(&sig_scheme_pk.to_projective()).as_slice())
            == sha256_hash(&projective_point_to_bytes::<TCurve>(&all_scheme_pk.to_projective()).as_slice());

    Ok(message_is_verified && pk_is_verified)
}
