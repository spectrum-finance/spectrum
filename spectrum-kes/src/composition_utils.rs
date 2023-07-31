use std::any::Any;
use std::fmt::Debug;
use std::ops::Range;

use ecdsa::signature::digest::{FixedOutput, HashMarker, Update};
use elliptic_curve::{CurveArithmetic, PrimeCurve, PublicKey, SecretKey};
use elliptic_curve::point::PointCompression;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};

use spectrum_crypto::digest::Digest;

use crate::KESSignature;
use crate::utils::{double_the_seed, key_pair_gen, merge_public_keys};

#[derive(Debug)]
pub struct Error;

pub fn get_left_merkle_tree_branch<const N: usize, H, Hs, TCurve: CurveArithmetic>(
    merkle_tree_high: &u32,
    seed: &Digest<N, H>,
) -> Result<(SecretKey<TCurve>, PublicKey<TCurve>, Vec<Digest<N, H>>), Error>
    where Hs: Default, Hs: FixedOutput, Hs: HashMarker, Hs: Update {
    let mut branch_seeds = Vec::new();
    let mut actual_seed = (*seed).clone();
    let mut h = (*merkle_tree_high).clone();

    loop {
        let (seed_0, seed_1) = double_the_seed::<N, H, Hs>(&actual_seed);
        branch_seeds.push(seed_1.clone());
        if h == 1 {
            let (sk, pk) = key_pair_gen(&seed_0);
            return Ok((sk, pk, branch_seeds));
        } else {
            actual_seed = seed_0;
        }
        h -= 1;
    }
}

pub fn sum_composition_pk_gen<const N: usize, H, Hs, TCurve: CurveArithmetic + PointCompression>(
    merkle_tree_high: &u32,
    seed: &Digest<N, H>,
) -> Result<PublicKey<TCurve>, Error>
    where
        <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
        <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
        Hs: Default, Hs: FixedOutput, Hs: HashMarker, Hs: Update
{
    if *merkle_tree_high == 0 {
        return Ok(key_pair_gen::<N, H, TCurve>(seed).1);
    }

    let (_, pk0, branch_seeds) = get_left_merkle_tree_branch::<N, H, Hs, TCurve>(merkle_tree_high, seed).unwrap();

    let mut pk = pk0.clone();
    let mut high = 0;

    for seed in branch_seeds.iter().rev() {
        let pk_right = if high == 0 {
            key_pair_gen(&seed).1
        } else {
            sum_composition_pk_gen::<N, H, Hs, TCurve>(&high, &seed).unwrap()
        };
        high += 1;
        pk = merge_public_keys::<N, H, Hs, TCurve>(&pk, &pk_right);
    }
    Ok(pk)
}

pub fn calculate_scheme_pk_from_signature<const N: usize, H, Hs, TCurve: CurveArithmetic + PrimeCurve + PointCompression>(
    signature: &KESSignature<TCurve>,
    signing_period: &u32,
) -> PublicKey<TCurve>
    where
        <TCurve as CurveArithmetic>::AffinePoint: FromEncodedPoint<TCurve>,
        <TCurve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
        <TCurve as CurveArithmetic>::AffinePoint: ToEncodedPoint<TCurve>,
        Hs: Default, Hs: FixedOutput, Hs: HashMarker, Hs: Update

{
    let mut scheme_pk = (*signature).hot_pk;
    for i in (0..(*signature).other_pks.len()).rev() {
        let pk_ = (*signature).other_pks[i].clone();
        let right = (*signing_period & (1 << (*signature).other_pks.len() - i - 1)) != 0;
        if right {
            scheme_pk = merge_public_keys::<N, H, Hs, TCurve>(&pk_, &scheme_pk);
        } else {
            scheme_pk = merge_public_keys::<N, H, Hs, TCurve>(&scheme_pk, &pk_);
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
