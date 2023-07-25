use std::any::Any;
use std::fmt::Debug;
use std::ops::Range;

use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{CurveArithmetic, PrimeCurve, PublicKey, SecretKey};

use spectrum_crypto::digest::Sha2Digest256;

use crate::kes::KeSignature;
use crate::utils::{double_seed, key_pair_gen, merge_public_keys};

#[derive(Debug)]
pub struct Error;

pub fn get_left_merkle_tree_branch<TCurve: CurveArithmetic>(
    merkle_tree_high: &u32,
    seed: &Sha2Digest256,
) -> Result<(SecretKey<TCurve>, PublicKey<TCurve>, Vec<Sha2Digest256>), Error> {
    let mut branch_seeds = Vec::new();
    let mut actual_seed = (*seed).clone();
    let mut h = (*merkle_tree_high).clone();

    loop {
        let (seed_0, seed_1) = double_seed(&actual_seed);
        branch_seeds.push(seed_1.clone());
        if h == 1 {
            let (sk, pk) = key_pair_gen::<TCurve>(&seed_0);
            return Ok((sk, pk, branch_seeds));
        } else {
            actual_seed = seed_0;
        }
        h -= 1;
    }
}

pub fn sum_composition_pk_gen<TCurve: CurveArithmetic + PointCompression>(
    merkle_tree_high: &u32,
    seed: &Sha2Digest256,
) -> Result<PublicKey<TCurve>, Error>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
{
    if *merkle_tree_high == 0 {
        return Ok(key_pair_gen::<TCurve>(seed).1);
    }

    let (_, pk0, branch_seeds) = get_left_merkle_tree_branch::<TCurve>(merkle_tree_high, seed).unwrap();

    let mut pk = pk0.clone();
    let mut high = 0;

    for seed in branch_seeds.iter().rev() {
        let pk_right = if high == 0 {
            key_pair_gen::<TCurve>(&seed).1
        } else {
            sum_composition_pk_gen::<TCurve>(&high, &seed).unwrap()
        };
        high += 1;
        pk = merge_public_keys::<TCurve>(&pk, &pk_right);
    }
    Ok(pk)
}

pub fn calculate_scheme_pk_from_signature<TCurve: CurveArithmetic + PrimeCurve + PointCompression>(
    signature: &KeSignature<TCurve>,
    signing_period: &u32,
) -> PublicKey<TCurve>
where
    <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
    <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
    <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
{
    let mut scheme_pk = (*signature).pk_actual;
    for i in (0..(*signature).scheme_public_keys.len()).rev() {
        let pk_ = (*signature).scheme_public_keys[i].clone();
        let right = (*signing_period & (1 << (*signature).scheme_public_keys.len() - i - 1)) != 0;
        if right {
            scheme_pk = merge_public_keys::<TCurve>(&pk_, &scheme_pk);
        } else {
            scheme_pk = merge_public_keys::<TCurve>(&scheme_pk, &pk_);
        }
    }
    scheme_pk
}

pub fn insert_in_vec<T: Any + Clone>(
    mut source_vec: Vec<T>,
    cloned_vec: Vec<T>,
    inds: Range<usize>,
) -> Vec<T> {
    for i in inds {
        source_vec.push(cloned_vec[i].clone());
    }
    source_vec
}
