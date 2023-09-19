use elliptic_curve::ops::{LinearCombination, Reduce};
use ergo_lib::{
    ergo_chain_types::EcPoint,
    ergotree_ir::{
        bigint256::BigInt256,
        mir::{
            constant::{Constant, Literal},
            value::CollKind,
        },
        types::{
            stuple::{STuple, TupleItems},
            stype::SType,
        },
    },
};
use k256::{schnorr::Signature, FieldElement, NonZeroScalar, ProjectivePoint, Scalar, U256};
use num_bigint::{BigUint, Sign, ToBigUint};
use scorex_crypto_avltree::{
    batch_node::{Node, NodeHeader},
    operation::Digest32,
};
use sha2::Digest as OtherDigest;
use sha2::Sha256;
use spectrum_sigma::Commitment;

fn tagged_hash(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest
}

fn serialize_exclusion_set(
    exclusion_set: Vec<(usize, Option<(Commitment, Signature)>)>,
    md: &[u8],
) -> Constant {
    let mut elem_tpe = None;
    let mut items = vec![];
    let filtered_exclusion_set = exclusion_set.into_iter().filter_map(|(ix, pair)| {
        if let Some((Commitment(verifying_key), sig)) = pair {
            Some((ix, verifying_key, sig))
        } else {
            None
        }
    });
    for (ix, verifying_key, signature) in filtered_exclusion_set {
        let signature_bytes = signature.to_bytes();

        // The components (r,s) of the taproot `Signature` struct are not public, but we can
        // extract it through its byte representation.
        let (r_bytes, s_bytes) = signature_bytes.split_at(32);
        let r: FieldElement = Option::from(FieldElement::from_bytes(r_bytes.into())).unwrap();

        const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";
        //  int(sha256(sha256(CHALLENGE_TAG) || sha256(CHALLENGE_TAG) || bytes(r) || bytes(P) || m)) mod n
        let e = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r.to_bytes())
                .chain_update(verifying_key.to_bytes())
                .chain_update(md)
                .finalize(),
        );
        let s = NonZeroScalar::try_from(s_bytes).unwrap();

        // R
        let r_point = ProjectivePoint::lincomb(
            &ProjectivePoint::GENERATOR,
            &s,
            &ProjectivePoint::from(verifying_key.as_affine()),
            &-e,
        );

        // The taproot signature satisfies:
        //     g ^ s == R * P^e
        // Note: `k256` uses additive notation for elliptic-curves, so we can compute the right
        // hand side with:
        //   r_point + ProjectivePoint::from(verifying_key.as_affine()) * e;
        //
        // Note in the above equation that the values `s` and `e` have a 256bit UNSIGNED integer
        // representation. This is a problem for Ergoscript since the largest integer values it
        // allows for is 256bit signed. We can work around the problem by splitting the value
        // into 2 signed ints.
        //
        // Let `B` denote the big-endian unsigned byte representation of `s`. Let `U` and `L`
        // denote the first 16 and last 16 bytes of `B`, respectively. Then `U` and `L` are
        // themselves unsigned integers. Moreover,
        //    B == U*p + L, where p == 340282366920938463463374607431768211456
        //
        // We want to use this decomposition on the ergo side, but we need to convert `U` and `L`
        // into signed integers, `U_S` and `L_S`. We need to be careful as `U_S` and/or `L_S` could
        // each require 17 bytes if the most-significant-bit of `U`/`L` is 1 (and so we need to
        // prepend a zero byte to accomodate the sign-bit).
        //
        // So we can transport `s` across the boundary with the bytes of [U_S | L_S], and decoding
        // `U_S` and `L_S` within Ergoscript.
        let s_biguint = scalar_to_biguint(*s.as_ref());
        let biguint_bytes = s_biguint.to_bytes_be();
        let split = biguint_bytes.len() - 16;
        //println!("# bytes: {}", s_biguint.to_bytes_be().len());
        let upper = BigUint::from_bytes_be(&biguint_bytes[..split]);
        let upper_256 = BigInt256::try_from(upper).unwrap();
        assert_eq!(upper_256.sign(), Sign::Plus);
        let lower = BigUint::from_bytes_be(&s_biguint.to_bytes_be()[split..]);
        let lower_256 = BigInt256::try_from(lower).unwrap();
        assert_eq!(lower_256.sign(), Sign::Plus);

        let mut s_bytes = upper_256.to_signed_bytes_be();
        // Need this variable because we could add an extra byte to the encoding for signed-representation.
        let first_len = s_bytes.len() as i32;
        s_bytes.extend(lower_256.to_signed_bytes_be());

        //println!("first_len: {}, S_BYTES_LEN: {}", first_len, s_bytes.len());
        //let p = BigInt256::from_str_radix("340282366920938463463374607431768211456", 10).unwrap();

        //println!(
        //    "PP_base64: {}",
        //    base64::engine::general_purpose::STANDARD_NO_PAD.encode(p.to_signed_bytes_be())
        //);

        // P from BIP-0340
        let pubkey_point = EcPoint::from(ProjectivePoint::from(verifying_key.as_affine()));
        // The x-coordinate of P
        let pubkey_x_coords = verifying_key.to_bytes().to_vec();

        let pubkey_tuple: Constant = (Constant::from(pubkey_point), Constant::from(pubkey_x_coords)).into();
        let with_ix: Constant = (Constant::from(ix as i32), pubkey_tuple).into();
        let s_tuple: Constant = (Constant::from(s_bytes), Constant::from(first_len)).into();
        let r_tuple: Constant = (
            Constant::from(EcPoint::from(r_point)),
            Constant::from(r.to_bytes().to_vec()),
        )
            .into();
        let s_r_tuple: Constant = (s_tuple, r_tuple).into();
        let elem: Constant = (with_ix, s_r_tuple).into();

        items.push(elem.v);

        if elem_tpe.is_none() {
            elem_tpe = Some(elem.tpe.clone());
        }
    }
    if let Some(elem_tpe) = elem_tpe {
        Constant {
            tpe: SType::SColl(Box::new(elem_tpe.clone())),
            v: Literal::Coll(CollKind::WrappedColl { elem_tpe, items }),
        }
    } else {
        let schnorr_sig_elem_type = schnorr_signature_verification_ergoscript_type();
        Constant {
            tpe: SType::SColl(Box::new(schnorr_sig_elem_type.clone())),
            v: Literal::Coll(CollKind::WrappedColl {
                elem_tpe: schnorr_sig_elem_type,
                items: vec![],
            }),
        }
    }
}

fn scalar_to_biguint(scalar: Scalar) -> BigUint {
    scalar
        .to_bytes()
        .iter()
        .enumerate()
        .map(|(i, w)| w.to_biguint().unwrap() << ((31 - i) * 8))
        .sum()
}

fn dummy_resolver(digest: &Digest32) -> Node {
    Node::LabelOnly(NodeHeader::new(Some(digest.clone()), None))
}

fn schnorr_signature_verification_ergoscript_type() -> SType {
    //   ( ( Int, (GroupElement, Coll[Byte]) ),
    //     ( (Coll[Byte], Int), (GroupElement, Coll[Byte]) )
    //   )

    let bytes_type = SType::SColl(Box::new(SType::SByte));
    let group_element_and_bytes = SType::STuple(STuple {
        items: TupleItems::from_vec(vec![SType::SGroupElement, bytes_type.clone()]).unwrap(),
    });

    // ( Int, (GroupElement, Coll[Byte]) )
    let left = SType::STuple(STuple {
        items: TupleItems::from_vec(vec![SType::SInt, group_element_and_bytes.clone()]).unwrap(),
    });

    let right = SType::STuple(STuple {
        items: TupleItems::from_vec(vec![
            SType::STuple(STuple {
                items: TupleItems::from_vec(vec![bytes_type, SType::SInt]).unwrap(),
            }),
            group_element_and_bytes,
        ])
        .unwrap(),
    });

    SType::STuple(STuple {
        items: TupleItems::from_vec(vec![left, right]).unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use blake2::Blake2b;
    use bytes::Bytes;
    use elliptic_curve::consts::U32;
    use elliptic_curve::group::GroupEncoding;
    use ergo_lib::chain::ergo_state_context::ErgoStateContext;
    use ergo_lib::chain::transaction::unsigned::UnsignedTransaction;
    use ergo_lib::chain::transaction::DataInput;
    use ergo_lib::chain::transaction::TxId;
    use ergo_lib::chain::transaction::TxIoVec;
    use ergo_lib::chain::transaction::UnsignedInput;
    use ergo_lib::ergo_chain_types::ec_point::generator;
    use ergo_lib::ergo_chain_types::BlockId;
    use ergo_lib::ergo_chain_types::Digest;
    use ergo_lib::ergo_chain_types::EcPoint;
    use ergo_lib::ergo_chain_types::Header;
    use ergo_lib::ergo_chain_types::PreHeader;
    use ergo_lib::ergo_chain_types::Votes;
    use ergo_lib::ergotree_interpreter::sigma_protocol::prover::ContextExtension;
    use ergo_lib::ergotree_ir::base16_str::Base16Str;
    use ergo_lib::ergotree_ir::bigint256::BigInt256;
    use ergo_lib::ergotree_ir::chain::address::AddressEncoder;
    use ergo_lib::ergotree_ir::chain::address::NetworkPrefix;
    use ergo_lib::ergotree_ir::chain::ergo_box::box_value::BoxValue;
    use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBox;
    use ergo_lib::ergotree_ir::chain::ergo_box::ErgoBoxCandidate;
    use ergo_lib::ergotree_ir::chain::ergo_box::NonMandatoryRegisterId;
    use ergo_lib::ergotree_ir::chain::ergo_box::NonMandatoryRegisters;
    use ergo_lib::ergotree_ir::ergo_tree::ErgoTree;
    use ergo_lib::ergotree_ir::mir::avl_tree_data::AvlTreeData;
    use ergo_lib::ergotree_ir::mir::avl_tree_data::AvlTreeFlags;
    use ergo_lib::ergotree_ir::mir::constant::Constant;
    use ergo_lib::ergotree_ir::mir::constant::Literal;
    use ergo_lib::ergotree_ir::mir::value::CollKind;
    use ergo_lib::ergotree_ir::serialization::SigmaSerializable;
    use ergo_lib::ergotree_ir::types::stuple::STuple;
    use ergo_lib::ergotree_ir::types::stuple::TupleItems;
    use ergo_lib::ergotree_ir::types::stype::SType;
    use ergo_lib::wallet::miner_fee::MINERS_FEE_ADDRESS;
    use ergo_lib::wallet::tx_context::TransactionContext;
    use ergo_lib::wallet::Wallet;
    use indexmap::IndexMap;
    use k256::schnorr::signature::Signer;
    use k256::schnorr::Signature;
    use k256::schnorr::SigningKey;
    use k256::ProjectivePoint;
    use k256::Scalar;
    use k256::SecretKey;
    use num_bigint::BigUint;
    use num_bigint::Sign;
    use rand::rngs::OsRng;
    use rand::Rng;
    use scorex_crypto_avltree::authenticated_tree_ops::*;
    use scorex_crypto_avltree::batch_avl_prover::BatchAVLProver;
    use scorex_crypto_avltree::batch_node::*;
    use scorex_crypto_avltree::operation::*;
    use serde::Deserialize;
    use serde::Serialize;
    use spectrum_crypto::digest::blake2b256_hash;
    use spectrum_crypto::digest::Blake2bDigest256;
    use spectrum_crypto::pubkey::PublicKey;
    use spectrum_handel::Threshold;
    use spectrum_sigma::crypto::aggregate_commitment;
    use spectrum_sigma::crypto::aggregate_pk;
    use spectrum_sigma::crypto::aggregate_response;
    use spectrum_sigma::crypto::challenge;
    use spectrum_sigma::crypto::exclusion_proof;
    use spectrum_sigma::crypto::individual_input;
    use spectrum_sigma::crypto::response;
    use spectrum_sigma::crypto::schnorr_commitment_pair;
    use spectrum_sigma::crypto::verify;
    use spectrum_sigma::crypto::verify_response;
    use spectrum_sigma::AggregateCommitment;
    use spectrum_sigma::Commitment;
    use std::collections::HashMap;
    use std::time::Instant;

    use crate::script::scalar_to_biguint;
    use crate::script::serialize_exclusion_set;

    use super::dummy_resolver;

    // Script URL: https://wallet.plutomonkey.com/p2s/?source=ewogIHZhbCBtZXNzYWdlICAgICAgICAgICAgICA9IElOUFVUUygwKS5SNFtDb2xsW0J5dGVdXS5nZXQKICB2YWwgZ3JvdXBHZW5lcmF0b3IgICAgICAgPSBJTlBVVFMoMCkuUjVbR3JvdXBFbGVtZW50XS5nZXQKICB2YWwgZ3JvdXBFbGVtZW50SWRlbnRpdHkgPSBJTlBVVFMoMCkuUjZbR3JvdXBFbGVtZW50XS5nZXQKICB2YWwgdGhyZXNob2xkICAgICAgICAgICAgPSBJTlBVVFMoMCkuUjdbSW50XS5nZXQKCiAgLy8gQnl0ZSByZXByZXNlbnRhdGlvbiBvZiBIKFhfMSwgLi4uLCBYX24pCiAgdmFsIGlubmVyQnl0ZXMgICAgICAgICAgID0gSU5QVVRTKDApLlI4W0NvbGxbQnl0ZV1dLmdldAoKCiAgLy8gUmVwcmVzZW50cyB0aGUgbnVtYmVyIG9mIGRhdGEgaW5wdXRzIHRoYXQgY29udGFpbiB0aGUgR3JvdXBFbGVtZW50IG9mIGNvbW1pdHRlZSBtZW1iZXJzLgogIHZhbCBudW1iZXJDb21taXR0ZWVEYXRhSW5wdXRCb3hlcyA9IENPTlRFWFQuZGF0YUlucHV0cygwKS5SNVtTaG9ydF0uZ2V0CiAgCiAgLy8gVGhlIEdyb3VwRWxlbWVudHMgb2YgZWFjaCBjb21taXR0ZWUgbWVtYmVyIGFyZSBhcnJhbmdlZCB3aXRoaW4gYSBDb2xsW0dyb3VwRWxlbWVudF0KICAvLyByZXNpZGluZyB3aXRoaW4gdGhlIFI0IHJlZ2lzdGVyIG9mIHRoZSBmaXJzdCAnbiA9PSBudW1iZXJDb21taXR0ZWVEYXRhSW5wdXRCb3hlcycKICAvLyBkYXRhIGlucHV0cy4KICB2YWwgY29tbWl0dGVlID0gQ09OVEVYVC5kYXRhSW5wdXRzLnNsaWNlKDAsIG51bWJlckNvbW1pdHRlZURhdGFJbnB1dEJveGVzLnRvSW50KS5mb2xkKAogICAgQ29sbFtHcm91cEVsZW1lbnRdKCksCiAgICB7IChhY2M6IENvbGxbR3JvdXBFbGVtZW50XSwgeDogQm94KSA9PgogICAgICAgIGFjYy5hcHBlbmQoeC5SNFtDb2xsW0dyb3VwRWxlbWVudF1dLmdldCkKICAgIH0KICApCgogIHZhbCB2ZXJpZmljYXRpb25EYXRhID0gZ2V0VmFyW0NvbGxbKChJbnQsIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSwgKChDb2xsW0J5dGVdLCBJbnQpLCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSkgKV1dKDApLmdldAogIHZhbCBhZ2dyZWdhdGVSZXNwb25zZVJhdyA9IGdldFZhclsoQ29sbFtCeXRlXSwgSW50KV0oMSkuZ2V0IC8vIHoKICB2YWwgYWdncmVnYXRlQ29tbWl0bWVudCA9IGdldFZhcltHcm91cEVsZW1lbnRdKDIpLmdldCAvLyBZCiAKICAvLyBQZXJmb3JtcyBleHBvbmVudGlhdGlvbiBvZiBhIEdyb3VwRWxlbWVudCBieSBhbiB1bnNpZ25lZCAyNTZiaXQKICAvLyBpbnRlZ2VyIEkgdXNpbmcgdGhlIGZvbGxvd2luZyBkZWNvbXBvc2l0aW9uIG9mIEk6CiAgLy8gTGV0IGUgPSAoZywgKGIsIG4pKS4gVGhlbiB0aGlzIGZ1bmN0aW9uIGNvbXB1dGVzOgogIC8vCiAgLy8gICBnXkkgPT0gKGdeYigwLG4pKV5wICogZ14oYihuLi4pKQogIC8vIHdoZXJlCiAgLy8gIC0gYigwLG4pIGlzIHRoZSBmaXJzdCBuIGJ5dGVzIG9mIGEgcG9zaXRpdmUgQmlnSW50IGBVYAogIC8vICAtIGIobi4uKSBhcmUgdGhlIHJlbWFpbmluZyBieXRlcyBzdGFydGluZyBmcm9tIGluZGV4IG4uIFRoZXNlIGJ5dGVzCiAgLy8gICAgYWxzbyByZXByZXNlbnQgYSBwb3NpdGl2ZSBCaWdJbnQgYExgLgogIC8vICAtIHAgaXMgMzQwMjgyMzY2OTIwOTM4NDYzNDYzMzc0NjA3NDMxNzY4MjExNDU2IGJhc2UgMTAuCiAgLy8gIC0gSSA9PSBVICogcCArIEwKICBkZWYgbXlFeHAoZTogKEdyb3VwRWxlbWVudCwgKENvbGxbQnl0ZV0sIEludCkpKSA6IEdyb3VwRWxlbWVudCA9IHsKICAgIHZhbCB4ID0gZS5fMQogICAgdmFsIHkgPSBlLl8yLl8xCiAgICB2YWwgbGVuID0gZS5fMi5fMgogICAgdmFsIHVwcGVyID0gYnl0ZUFycmF5VG9CaWdJbnQoeS5zbGljZSgwLCBsZW4pKQogICAgdmFsIGxvd2VyID0gYnl0ZUFycmF5VG9CaWdJbnQoeS5zbGljZShsZW4sIHkuc2l6ZSkpCgogICAgLy8gVGhlIGZvbGxvd2luZyB2YWx1ZSBpcyAzNDAyODIzNjY5MjA5Mzg0NjM0NjMzNzQ2MDc0MzE3NjgyMTE0NTYgYmFzZS0xMC4KICAgIHZhbCBwID0gYnl0ZUFycmF5VG9CaWdJbnQoZnJvbUJhc2U2NCgiQVFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiKSkKICAgCiAgICB4LmV4cCh1cHBlcikuZXhwKHApLm11bHRpcGx5KHguZXhwKGxvd2VyKSkKICB9CgogIC8vIENvbnZlcnRzIGEgYmlnLWVuZGlhbiBieXRlIHJlcHJlc2VudGF0aW9uIG9mIGFuIHVuc2lnbmVkIGludGVnZXIgaW50byBpdHMKICAvLyBlcXVpdmFsZW50IHNpZ25lZCByZXByZXNlbnRhdGlvbgogIGRlZiB0b1NpZ25lZEJ5dGVzKGI6IENvbGxbQnl0ZV0pIDogQ29sbFtCeXRlXSA9IHsKICAgIC8vIE5vdGUgdGhhdCBhbGwgaW50ZWdlcnMgKGluY2x1ZGluZyBCeXRlKSBpbiBFcmdvc2NyaXB0IGFyZSBzaWduZWQuIEluIHN1Y2gKICAgIC8vIGEgcmVwcmVzZW50YXRpb24sIHRoZSBtb3N0LXNpZ25pZmljYW50IGJpdCAoTVNCKSBpcyB1c2VkIHRvIHJlcHJlc2VudCB0aGUKICAgIC8vIHNpZ247IDAgZm9yIGEgcG9zaXRpdmUgaW50ZWdlciBhbmQgMSBmb3IgbmVnYXRpdmUuIE5vdyBzaW5jZSBgYmAgaXMgYmlnLQogICAgLy8gZW5kaWFuLCB0aGUgTVNCIHJlc2lkZXMgaW4gdGhlIGZpcnN0IGJ5dGUgYW5kIE1TQiA9PSAxIGluZGljYXRlcyB0aGF0IGV2ZXJ5CiAgICAvLyBiaXQgaXMgdXNlZCB0byBzcGVjaWZ5IHRoZSBtYWduaXR1ZGUgb2YgdGhlIGludGVnZXIuIFRoaXMgbWVhbnMgdGhhdCBhbgogICAgLy8gZXh0cmEgMC1iaXQgbXVzdCBiZSBwcmVwZW5kZWQgdG8gYGJgIHRvIHJlbmRlciBpdCBhIHZhbGlkIHBvc2l0aXZlIHNpZ25lZAogICAgLy8gaW50ZWdlci4KICAgIC8vCiAgICAvLyBOb3cgc2lnbmVkIGludGVnZXJzIGFyZSBuZWdhdGl2ZSBpZmYgTVNCID09IDEsIGhlbmNlIHRoZSBjb25kaXRpb24gYmVsb3cuCiAgICBpZiAoYigwKSA8IDAgKSB7CiAgICAgICAgQ29sbCgwLnRvQnl0ZSkuYXBwZW5kKGIpCiAgICB9IGVsc2UgewogICAgICAgIGIKICAgIH0KICB9CgogIC8vIENvbXB1dGVzIGFfaSA9IEgoWF8xLCBYXzIsLi4sIFhfbjsgWF9pKQogIGRlZiBjYWxjQShlOiAoQ29sbFtHcm91cEVsZW1lbnRdLCBJbnQpKSA6IChDb2xsW0J5dGVdLCBJbnQpID0gewogICAgdmFsIGNvbW1pdHRlZU1lbWJlcnMgPSBlLl8xCiAgICB2YWwgaSA9IGUuXzIKICAgIHZhbCByYXcgPSBibGFrZTJiMjU2KGlubmVyQnl0ZXMuYXBwZW5kKGNvbW1pdHRlZU1lbWJlcnMoaSkuZ2V0RW5jb2RlZCkpCiAgICB2YWwgc3BsaXQgPSByYXcuc2l6ZSAtIDE2CiAgICB2YWwgZmlyc3RJbnQgPSB0b1NpZ25lZEJ5dGVzKHJhdy5zbGljZSgwLCBzcGxpdCkpCiAgICB2YWwgY29uY2F0Qnl0ZXMgPSBmaXJzdEludC5hcHBlbmQodG9TaWduZWRCeXRlcyhyYXcuc2xpY2Uoc3BsaXQsIHJhdy5zaXplKSkpCiAgICB2YWwgZmlyc3RJbnROdW1CeXRlcyA9IGZpcnN0SW50LnNpemUKICAgIChjb25jYXRCeXRlcywgZmlyc3RJbnROdW1CeXRlcykKICB9CiAgCiAgLy8gQ29tcHV0ZXMgWH4gPSBYXzBee2FfMH0gKiBYXzFee2FfMX0gKiAuLi4gKiBYX3tuLTF9XnthX3tuLTF9fQogIGRlZiBjYWxjRnVsbEFnZ3JlZ2F0ZUtleShlOiAoQ29sbFtHcm91cEVsZW1lbnRdLCBDb2xsWyhDb2xsW0J5dGVdLCBJbnQpXSApKSA6IEdyb3VwRWxlbWVudCA9IHsKICAgIHZhbCBjb21taXR0ZWVNZW1iZXJzID0gZS5fMQogICAgdmFsIGFpVmFsdWVzID0gZS5fMgogICAgY29tbWl0dGVlTWVtYmVycy5mb2xkKAogICAgICAoZ3JvdXBFbGVtZW50SWRlbnRpdHksIDApLAogICAgICB7IChhY2M6IChHcm91cEVsZW1lbnQsIEludCApLCB4OiBHcm91cEVsZW1lbnQpID0+CiAgICAgICAgICB2YWwgeF9hY2MgPSBhY2MuXzEKICAgICAgICAgIHZhbCBpID0gYWNjLl8yCiAgICAgICAgICAoeF9hY2MubXVsdGlwbHkobXlFeHAoKHgsIGFpVmFsdWVzKGkpKSkpLCBpICsgMSkKICAgICAgfQogICAgKS5fMQogIH0KCiAgLy8gQ29tcHV0ZXMgWCcKICBkZWYgY2FsY1BhcnRpYWxBZ2dyZWdhdGVLZXkoZTogKChDb2xsW0dyb3VwRWxlbWVudF0sIENvbGxbSW50XSksIENvbGxbKENvbGxbQnl0ZV0sIEludCldKSkgOiBHcm91cEVsZW1lbnQgPSB7CiAgICB2YWwgY29tbWl0dGVlTWVtYmVycyA9IGUuXzEuXzEKICAgIHZhbCBleGNsdWRlZEluZGljZXMgPSBlLl8xLl8yCiAgICB2YWwgYWlWYWx1ZXMgPSBlLl8yCiAgICBjb21taXR0ZWVNZW1iZXJzLmZvbGQoCiAgICAgIChncm91cEVsZW1lbnRJZGVudGl0eSwgMCksCiAgICAgIHsgKGFjYzogKEdyb3VwRWxlbWVudCwgSW50KSwgeDogR3JvdXBFbGVtZW50KSA9PgogICAgICAgICAgdmFsIHhBY2MgPSBhY2MuXzEKICAgICAgICAgIHZhbCBpID0gYWNjLl8yCiAgICAgICAgICBpZiAoZXhjbHVkZWRJbmRpY2VzLmV4aXN0cyB7IChpeDogSW50KSA9PiBpeCA9PSBpIH0pIHsKICAgICAgICAgICAgICh4QWNjLCBpICsgMSkKICAgICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgICh4QWNjLm11bHRpcGx5KG15RXhwKCh4LCBhaVZhbHVlcyhpKSkpKSwgaSArIDEpCiAgICAgICAgICB9CiAgICAgICAgICAKICAgICAgfQogICAgKS5fMQogIH0KCiAgLy8gQ2FsY3VsYXRlcyBhZ2dyZWdhdGUgY29tbWl0bWVudCBZJwogIGRlZiBjYWxjQWdncmVnYXRlQ29tbWl0bWVudChjb21taXRtZW50czogQ29sbFtHcm91cEVsZW1lbnRdKSA6IEdyb3VwRWxlbWVudCA9IHsKICAgIGNvbW1pdG1lbnRzLmZvbGQoCiAgICAgIGdyb3VwRWxlbWVudElkZW50aXR5LAogICAgICB7IChhY2M6IEdyb3VwRWxlbWVudCwgeTogR3JvdXBFbGVtZW50KSA9PgogICAgICAgICAgYWNjLm11bHRpcGx5KHkpCiAgICAgIH0KICAgICkgIAogIH0KCiAgZGVmIGVuY29kZVVuc2lnbmVkMjU2Qml0SW50KGJ5dGVzOiBDb2xsW0J5dGVdKSA6IChDb2xsW0J5dGVdLCBJbnQpID0gewogICAgdmFsIHNwbGl0ID0gYnl0ZXMuc2l6ZSAtIDE2CiAgICB2YWwgZmlyc3RJbnQgPSB0b1NpZ25lZEJ5dGVzKGJ5dGVzLnNsaWNlKDAsIHNwbGl0KSkKICAgIHZhbCBjb25jYXRCeXRlcyA9IGZpcnN0SW50LmFwcGVuZCh0b1NpZ25lZEJ5dGVzKGJ5dGVzLnNsaWNlKHNwbGl0LCBieXRlcy5zaXplKSkpCiAgICB2YWwgZmlyc3RJbnROdW1CeXRlcyA9IGZpcnN0SW50LnNpemUKICAgIChjb25jYXRCeXRlcywgZmlyc3RJbnROdW1CeXRlcykKICB9CiAgICAKICAvLyBCSVAtMDM0MCB1c2VzIHNvLWNhbGxlZCB0YWdnZWQgaGFzaGVzCiAgdmFsIGNoYWxsZW5nZVRhZyA9IHNoYTI1NihDb2xsKDY2LCA3MywgODAsIDQ4LCA1MSwgNTIsIDQ4LCA0NywgOTksIDEwNCwgOTcsIDEwOCwgMTA4LCAxMDEsIDExMCwgMTAzLCAxMDEpLm1hcCB7ICh4OkludCkgPT4geC50b0J5dGUgfSkKICAKICAvLyBQcmVjb21wdXRlIGFfaSB2YWx1ZXMKICB2YWwgYWlWYWx1ZXMgPSBjb21taXR0ZWUuaW5kaWNlcy5tYXAgeyAoaXg6IEludCkgPT4KICAgIGNhbGNBKChjb21taXR0ZWUsIGl4KSkKICB9CgogIC8vIGMKICB2YWwgY2hhbGxlbmdlUmF3ID0gYmxha2UyYjI1NihjYWxjRnVsbEFnZ3JlZ2F0ZUtleSgoY29tbWl0dGVlLCBhaVZhbHVlcykpLmdldEVuY29kZWQgKysgYWdncmVnYXRlQ29tbWl0bWVudC5nZXRFbmNvZGVkICsrIG1lc3NhZ2UgKQogIHZhbCBjaGFsbGVuZ2UgICAgPSBlbmNvZGVVbnNpZ25lZDI1NkJpdEludChjaGFsbGVuZ2VSYXcpCgogIHZhbCBleGNsdWRlZEluZGljZXMgPSB2ZXJpZmljYXRpb25EYXRhLm1hcCB7IChlOiAoKEludCwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpLCAoKENvbGxbQnl0ZV0sIEludCksIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSkpID0+CiAgICBlLl8xLl8xIAogIH0KCiAgdmFsIGV4Y2x1ZGVkQ29tbWl0bWVudHMgPSB2ZXJpZmljYXRpb25EYXRhLm1hcCB7IChlOiAoKEludCwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpLCAoKENvbGxbQnl0ZV0sIEludCksIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSkpID0+CiAgICBlLl8xLl8yLl8xIAogIH0KCiAgdmFsIFlEYXNoID0gY2FsY0FnZ3JlZ2F0ZUNvbW1pdG1lbnQoZXhjbHVkZWRDb21taXRtZW50cykKCiAgdmFsIHBhcnRpYWxBZ2dyZWdhdGVLZXkgPSBjYWxjUGFydGlhbEFnZ3JlZ2F0ZUtleSgoKGNvbW1pdHRlZSwgZXhjbHVkZWRJbmRpY2VzKSwgYWlWYWx1ZXMpKQoKICAvLyBWZXJpZmllcyB0aGF0IFknKmdeeiA9PSAoWCcpXmMgKiBZCiAgdmFsIHZlcmlmeUFnZ3JlZ2F0ZVJlc3BvbnNlID0gKCBteUV4cCgoZ3JvdXBHZW5lcmF0b3IsIGFnZ3JlZ2F0ZVJlc3BvbnNlUmF3KSkubXVsdGlwbHkoWURhc2gpIAogICAgICA9PSBteUV4cCgocGFydGlhbEFnZ3JlZ2F0ZUtleSwgY2hhbGxlbmdlKSkubXVsdGlwbHkoYWdncmVnYXRlQ29tbWl0bWVudCkgKQoKICB2YWwgdmVyaWZ5U2lnbmF0dXJlc0luRXhjbHVzaW9uU2V0ID0KICAgIHZlcmlmaWNhdGlvbkRhdGEuZm9yYWxsIHsgKGU6ICgoSW50LCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSksICgoQ29sbFtCeXRlXSwgSW50KSwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpKSkgPT4KICAgICAgdmFsIHB1YktleVR1cGxlID0gZS5fMS5fMgogICAgICB2YWwgcyAgPSBlLl8yLl8xCiAgICAgIHZhbCByZXNwb25zZVR1cGxlID0gZS5fMi5fMgoKICAgICAgdmFsIHB1YktleSAgICAgICAgID0gcHViS2V5VHVwbGUuXzEgLy8gWV9pCiAgICAgIHZhbCBwa0J5dGVzICAgICAgICA9IHB1YktleVR1cGxlLl8yIC8vIGVuY29kZWQgeC1jb29yZGluYXRlIG9mIFlfaQogICAgICB2YWwgcmVzcG9uc2UgICAgICAgPSByZXNwb25zZVR1cGxlLl8xIC8vIFIgaW4gQklQLTAzNDAKICAgICAgdmFsIHJCeXRlcyAgICAgICAgID0gcmVzcG9uc2VUdXBsZS5fMiAvLyBCeXRlIHJlcHJlc2VudGF0aW9uIG9mICdyJwoKCiAgICAgIHZhbCByYXcgPSBzaGEyNTYoY2hhbGxlbmdlVGFnICsrIGNoYWxsZW5nZVRhZyArKyByQnl0ZXMgKysgcGtCeXRlcyArKyBtZXNzYWdlKQogCiAgICAgIC8vIE5vdGUgdGhhdCB0aGUgb3V0cHV0IG9mIFNIQTI1NiBpcyBhIGNvbGxlY3Rpb24gb2YgYnl0ZXMgdGhhdCByZXByZXNlbnRzIGFuIHVuc2lnbmVkIDI1NmJpdCBpbnRlZ2VyLgogICAgICB2YWwgc3BsaXQgPSByYXcuc2l6ZSAtIDE2CiAgICAgIHZhbCBmaXJzdCA9IHRvU2lnbmVkQnl0ZXMocmF3LnNsaWNlKDAsIHNwbGl0KSkKICAgICAgdmFsIGNvbmNhdEJ5dGVzID0gZmlyc3QuYXBwZW5kKHRvU2lnbmVkQnl0ZXMocmF3LnNsaWNlKHNwbGl0LCByYXcuc2l6ZSkpKQogICAgICB2YWwgZmlyc3RJbnROdW1CeXRlcyA9IGZpcnN0LnNpemUKICAgICAgbXlFeHAoKGdyb3VwR2VuZXJhdG9yLCBzKSkgPT0gIG15RXhwKChwdWJLZXksIChjb25jYXRCeXRlcywgZmlyc3RJbnROdW1CeXRlcykpKS5tdWx0aXBseShyZXNwb25zZSkKICAgIH0KCiAgdmFsIHZlcmlmeVRocmVzaG9sZCA9IChjb21taXR0ZWUuc2l6ZSAtIHZlcmlmaWNhdGlvbkRhdGEuc2l6ZSkgPj0gdGhyZXNob2xkCgogIHNpZ21hUHJvcCAoCiAgICB2ZXJpZnlBZ2dyZWdhdGVSZXNwb25zZSAmJgogICAgdmVyaWZ5U2lnbmF0dXJlc0luRXhjbHVzaW9uU2V0ICYmCiAgICB2ZXJpZnlUaHJlc2hvbGQKICApCn0=
    const SIGNATURE_AGGREGATE_SCRIPT_BYTES: &str = "L3f7CYfrFdi8dDWURXX1g4mj2YqQ9u5thnPg2NRxehg49bhLs1FxZVRiJcAC76ZrrbBowRSwy3YnoJoBY1fVeyYVwv6qJ41Yibp7HLvNCEC1GtdbfSTf2U2tBxv7mgz5jxvX4XA5AHstZoiawk4ekCjqkk6ugYDkVF54Chx673jmZ7HSZ8V8sQhCBAfqMtBLpcgfMJg9T7eSMEx3cUAsEUZa7Yw9Z93eKDvi1bpy3CH8KarTjw5hMEP457hcpMVQpZNiS56UPCFZMCoxZYSpmnNq5DymSxxqtvg7AeXckturg5zzxoMTBRSaD5uhTWdfSjGvWBDAwZbZS5HdwYeaL6mdAafskwFSQYZsUhwmvN9m1YZ4KDXQVHe8Hc5E56T3kUubi25uELdHcRhbon8A8F3b44jamz7bffdrkSrHZYccz2BD7JShVfgkmRdCoKP5VxKMLXQspnhnw6jktKgE1n5tw9LQxXaxfxwzBG7A6NTbTFpjw2ZPscpSEgrADPp6Vi2CP8xYL6N8Yevjnpnd1qWs8ACWm8TEZsk4NoP9bXh49779QxjjVUwzWWzn45BQdJ3gpAJqVFFvpu1eSMwmu78nNneWK7Lsr9r5Lm69afjzvHbW62qQvVZbBazMjrkMC5iuYneJ8wAAaWqfTe1AP4fWsWmHu7W3WjPEFBUioWnA1rb5AkDskxLQzf43zJdp6qLH2DFCh3zyQ7xrh5nZSSy81tzesotRuyWGyjbLpbqoytqaAmxLDgA3RLUbmkUFCUAZPJjJQjbiYof4AWLrY9F3FFCgrqhvutP73ssuAycm7BMkM9M9M6Sh5gk8xhLjnef3VFvA9oFuWhu6irrbkJ8PKfsXgrBL2L1jNCe17AHq6fRv5ujs3G7TStggvBhmYcnaqedqfAUmK9orENBZnWGQdyEYoh5gQS2zyog6xatGdzXUx8CShQTS7x7faKM3VCQ3Nan5ALmxZkqQDmAWU1mXLFBgufQ2sMFcDCcSyZSxo6vPRvKH9XvREpPQ9eNbGasKec7YeSzdTESW99DTrv2csDBH1WuxCSDSYL8wfRpMLbZdfYUpLpTY1YaHHNw1uHGVgwGWnywn2ob9T9GnWAFcrEGUJtbUaMpDMacJvaEWiQyMNcYbUiQZEFNgVXTYT9ns73kHiL3UBTKy37a12XPDFSzoX2BXhv1Vqj65DxLXDKxXAe8D4wgkNtyeHecuc2C76XFhbkxi9tGb8FCK2KLojw9Q4ursuKDhCHwXEQWJJxe1DMimHN5V1VyWVPKbRfabkSy";

    const KEY_LENGTH: usize = 32;
    const VALUE_LENGTH: usize = 8;
    const MIN_KEY: [u8; KEY_LENGTH] = [0u8; KEY_LENGTH];
    const MAX_KEY: [u8; KEY_LENGTH] = [0xFFu8; KEY_LENGTH];

    fn random_key() -> ADKey {
        Bytes::copy_from_slice(&rand::random::<[u8; KEY_LENGTH]>())
    }

    fn random_value() -> ADValue {
        Bytes::copy_from_slice(&rand::random::<[u8; VALUE_LENGTH]>())
    }

    fn random_kv() -> KeyValue {
        loop {
            let key = random_key();
            if key != Bytes::copy_from_slice(&MIN_KEY) && key != Bytes::copy_from_slice(&MAX_KEY) {
                let value = random_value();
                return KeyValue { key, value };
            }
        }
    }
    #[test]
    fn test_avl_tree_verification() {
        let empty_tree = AVLTree::new(dummy_resolver, KEY_LENGTH, Some(VALUE_LENGTH));
        let mut prover = BatchAVLProver::new(empty_tree.clone(), true);
        let initial_digest = prover.digest().unwrap().to_vec();
        let pairs: Vec<_> = (0..3).map(|_| random_kv()).collect();
        for kv in &pairs {
            let m = Operation::Insert(kv.clone());
            prover.perform_one_operation(&m).unwrap();
        }
        let operations_vec: Vec<_> = pairs
            .into_iter()
            .map(|kv| {
                let key_const = Literal::from(kv.key.to_vec());
                let value_const = Literal::from(kv.value.to_vec());
                Literal::Tup(TupleItems::try_from(vec![key_const, value_const]).unwrap())
            })
            .collect();

        let operations_tpe = SType::SColl(Box::new(SType::STuple(STuple::pair(
            SType::SColl(Box::new(SType::SByte)),
            SType::SColl(Box::new(SType::SByte)),
        ))));
        let operations_lit = Literal::Coll(CollKind::WrappedColl {
            elem_tpe: SType::STuple(STuple::pair(
                SType::SColl(Box::new(SType::SByte)),
                SType::SColl(Box::new(SType::SByte)),
            )),
            items: operations_vec,
        });
        let operations_const = Constant {
            tpe: operations_tpe,
            v: operations_lit,
        };

        let proof = Constant::from(prover.generate_proof().to_vec());
        let resulting_digest = prover.digest().unwrap().to_vec();
        let avl_tree_data = AvlTreeData {
            digest: Digest::<33>::try_from(initial_digest).unwrap(),
            tree_flags: AvlTreeFlags::new(true, false, false),
            key_length: KEY_LENGTH as u32,
            value_length_opt: Some(Box::new(VALUE_LENGTH as u32)),
        };
        let avl_const = Constant::from(avl_tree_data);

        // Script: https://wallet.plutomonkey.com/p2s/?source=eyAvLyA9PT09PSBDb250cmFjdCBJbmZvcm1hdGlvbiA9PT09PSAvLwogIC8vIE5hbWU6IFZlcmlmeSBBVkwgdHJlZSB0ZXN0CiAgLy8KICAvLyBDb250ZXh0RXh0ZW5zaW9uIGNvbnN0YW50czoKICAvLyAwOiBBdmxUcmVlIC0gaW5pdGlhbCBzdGF0ZSBvZiB0aGUgQVZMIHRyZWUKICAvLyAxOiBDb2xsW0NvbGxbKEludCwgQ29sbFtCeXRlXSldXSAtIGluc2VydCBvcGVyYXRpb25zIGZvciBBVkwgdHJlZQogIC8vIDI6IENvbGxbQnl0ZV0gLSBBVkwgdHJlZSBwcm9vZgogIC8vIDM6IENvbGxbQnl0ZV0gLSBFeHBlY3RlZCBkaWdlc3QgYWZ0ZXIgaW5zZXJ0IG9wZXJhdGlvbnMgaGF2ZSBiZWVuIHBlcmZvcm1lZAogCgogIHZhbCB0cmVlICAgICAgICA9IGdldFZhcltBdmxUcmVlXSgwKS5nZXQKICB2YWwgb3BlcmF0aW9ucyAgPSBnZXRWYXJbQ29sbFsoQ29sbFtCeXRlXSwgQ29sbFtCeXRlXSldXSgxKS5nZXQKICB2YWwgcHJvb2YgICAgICAgPSBnZXRWYXJbQ29sbFtCeXRlXV0oMikuZ2V0CiAgdmFsIGRpZ2VzdCAgICAgID0gZ2V0VmFyW0NvbGxbQnl0ZV1dKDMpLmdldAoKICB2YWwgZW5kVHJlZSA9IHRyZWUuaW5zZXJ0KG9wZXJhdGlvbnMsIHByb29mKS5nZXQKICAKICBzaWdtYVByb3AgKGVuZFRyZWUuZGlnZXN0ID09IGRpZ2VzdCkKfQ==
        const SCRIPT_BYTES: &str = "2MEDDujrWqP7AmJZKvCPfe9bzoWQgmaLB9ykrQ9rvtEoKBpTd";
        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder.parse_address_from_str(SCRIPT_BYTES).unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();
        let input_box = ErgoBox::new(
            erg_value,
            ergo_tree,
            None,
            NonMandatoryRegisters::empty(),
            900000,
            TxId::zero(),
            0,
        )
        .unwrap();

        // Send all Ergs to miner fee
        let miner_output = ErgoBoxCandidate {
            value: erg_value,
            ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: 900001,
        };
        let mut constants = IndexMap::new();
        constants.insert(0_u8, avl_const);
        constants.insert(1_u8, operations_const);
        constants.insert(2_u8, proof);
        constants.insert(3_u8, Constant::from(resulting_digest));

        let outputs = TxIoVec::from_vec(vec![miner_output]).unwrap();
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values: constants });
        let unsigned_tx =
            UnsignedTransaction::new(TxIoVec::from_vec(vec![unsigned_input]).unwrap(), None, outputs)
                .unwrap();
        let tx_context = TransactionContext::new(unsigned_tx, vec![input_box], vec![]).unwrap();
        let wallet = get_wallet();
        let ergo_state_context: ErgoStateContext = dummy_ergo_state_context();
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    #[test]
    fn test_verify_schnorr_signature() {
        // Script: https://wallet.plutomonkey.com/p2s/?source=ewogIHZhbCBtZXNzYWdlICAgICAgICA9IElOUFVUUygwKS5SNFtDb2xsW0J5dGVdXS5nZXQKICB2YWwgZ3JvdXBHZW5lcmF0b3IgPSBJTlBVVFMoMCkuUjVbR3JvdXBFbGVtZW50XS5nZXQKCiAgdmFsIHZlcmlmaWNhdGlvbkRhdGEgPSBnZXRWYXJbQ29sbFsoKEludCwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpLCAoKENvbGxbQnl0ZV0sIEludCksIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSApXV0oMCkuZ2V0CiAKICAvLyBQZXJmb3JtcyBleHBvbmVudGlhdGlvbiBvZiBhIEdyb3VwRWxlbWVudCBieSBhbiB1bnNpZ25lZCAyNTZiaXQKICAvLyBpbnRlZ2VyIEkgdXNpbmcgdGhlIGZvbGxvd2luZyBkZWNvbXBvc2l0aW9uIG9mIEk6CiAgLy8gTGV0IGUgPSAoZywgKGIsIG4pKS4gVGhlbiB0aGlzIGZ1bmN0aW9uIGNvbXB1dGVzOgogIC8vCiAgLy8gICBnXkkgPT0gKGdeYigwLG4pKV5wICogZ14oYihuLi4pKQogIC8vIHdoZXJlCiAgLy8gIC0gYigwLG4pIGlzIHRoZSBmaXJzdCBuIGJ5dGVzIG9mIGEgcG9zaXRpdmUgQmlnSW50IGBVYAogIC8vICAtIGIobi4uKSBhcmUgdGhlIHJlbWFpbmluZyBieXRlcyBzdGFydGluZyBmcm9tIGluZGV4IG4uIFRoZXNlIGJ5dGVzCiAgLy8gICAgYWxzbyByZXByZXNlbnQgYSBwb3NpdGl2ZSBCaWdJbnQgYExgLgogIC8vICAtIHAgaXMgMzQwMjgyMzY2OTIwOTM4NDYzNDYzMzc0NjA3NDMxNzY4MjExNDU2IGJhc2UgMTAuCiAgLy8gIC0gSSA9PSBVICogcCArIEwKICBkZWYgbXlFeHAoZTogKEdyb3VwRWxlbWVudCwgKENvbGxbQnl0ZV0sIEludCkpKSA6IEdyb3VwRWxlbWVudCA9IHsKICAgIHZhbCB4ID0gZS5fMQogICAgdmFsIHkgPSBlLl8yLl8xCiAgICB2YWwgbGVuID0gZS5fMi5fMgogICAgdmFsIHVwcGVyID0gYnl0ZUFycmF5VG9CaWdJbnQoeS5zbGljZSgwLCBsZW4pKQogICAgdmFsIGxvd2VyID0gYnl0ZUFycmF5VG9CaWdJbnQoeS5zbGljZShsZW4sIHkuc2l6ZSkpCgogICAgLy8gVGhlIGZvbGxvd2luZyB2YWx1ZSBpcyAzNDAyODIzNjY5MjA5Mzg0NjM0NjMzNzQ2MDc0MzE3NjgyMTE0NTYgYmFzZS0xMC4KICAgIHZhbCBwID0gYnl0ZUFycmF5VG9CaWdJbnQoZnJvbUJhc2U2NCgiQVFBQUFBQUFBQUFBQUFBQUFBQUFBQUEiKSkKICAgCiAgICB4LmV4cCh1cHBlcikuZXhwKHApLm11bHRpcGx5KHguZXhwKGxvd2VyKSkKICB9CgogIC8vIENvbnZlcnRzIGEgYmlnLWVuZGlhbiBieXRlIHJlcHJlc2VudGF0aW9uIG9mIGFuIHVuc2lnbmVkIGludGVnZXIgaW50byBpdHMKICAvLyBlcXVpdmFsZW50IHNpZ25lZCByZXByZXNlbnRhdGlvbgogIGRlZiB0b1NpZ25lZEJ5dGVzKGI6IENvbGxbQnl0ZV0pIDogQ29sbFtCeXRlXSA9IHsKICAgIC8vIE5vdGUgdGhhdCBhbGwgaW50ZWdlcnMgKGluY2x1ZGluZyBCeXRlKSBpbiBFcmdvc2NyaXB0IGFyZSBzaWduZWQuIEluIHN1Y2gKICAgIC8vIGEgcmVwcmVzZW50YXRpb24sIHRoZSBtb3N0LXNpZ25pZmljYW50IGJpdCAoTVNCKSBpcyB1c2VkIHRvIHJlcHJlc2VudCB0aGUKICAgIC8vIHNpZ247IDAgZm9yIGEgcG9zaXRpdmUgaW50ZWdlciBhbmQgMSBmb3IgbmVnYXRpdmUuIE5vdyBzaW5jZSBgYmAgaXMgYmlnLQogICAgLy8gZW5kaWFuLCB0aGUgTVNCIHJlc2lkZXMgaW4gdGhlIGZpcnN0IGJ5dGUgYW5kIE1TQiA9PSAxIGluZGljYXRlcyB0aGF0IGV2ZXJ5CiAgICAvLyBiaXQgaXMgdXNlZCB0byBzcGVjaWZ5IHRoZSBtYWduaXR1ZGUgb2YgdGhlIGludGVnZXIuIFRoaXMgbWVhbnMgdGhhdCBhbgogICAgLy8gZXh0cmEgMC1iaXQgbXVzdCBiZSBwcmVwZW5kZWQgdG8gYGJgIHRvIHJlbmRlciBpdCBhIHZhbGlkIHBvc2l0aXZlIHNpZ25lZAogICAgLy8gaW50ZWdlci4KICAgIC8vCiAgICAvLyBOb3cgc2lnbmVkIGludGVnZXJzIGFyZSBuZWdhdGl2ZSBpZmYgTVNCID09IDEsIGhlbmNlIHRoZSBjb25kaXRpb24gYmVsb3cuCiAgICBpZiAoYigwKSA8IDAgKSB7CiAgICAgICAgQ29sbCgwLnRvQnl0ZSkuYXBwZW5kKGIpCiAgICB9IGVsc2UgewogICAgICAgIGIKICAgIH0KICB9CiAgICAKICAvLyBCSVAtMDM0MCB1c2VzIHNvLWNhbGxlZCB0YWdnZWQgaGFzaGVzCiAgdmFsIGNoYWxsZW5nZVRhZyA9IHNoYTI1NihDb2xsKDY2LCA3MywgODAsIDQ4LCA1MSwgNTIsIDQ4LCA0NywgOTksIDEwNCwgOTcsIDEwOCwgMTA4LCAxMDEsIDExMCwgMTAzLCAxMDEpLm1hcCB7ICh4OkludCkgPT4geC50b0J5dGUgfSkKCgogIHNpZ21hUHJvcCAoCiAgICB2ZXJpZmljYXRpb25EYXRhLmZvcmFsbCB7IChlOiAoKEludCwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpLCAoKENvbGxbQnl0ZV0sIEludCksIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSkpID0+CiAgICAgIHZhbCBwdWJLZXlUdXBsZSA9IGUuXzEuXzIKICAgICAgdmFsIHMgID0gZS5fMi5fMQogICAgICB2YWwgcmVzcG9uc2VUdXBsZSA9IGUuXzIuXzIKCiAgICAgIHZhbCBwdWJLZXkgICAgICAgICA9IHB1YktleVR1cGxlLl8xIC8vIFAKICAgICAgdmFsIHBrQnl0ZXMgICAgICAgID0gcHViS2V5VHVwbGUuXzIgLy8gZW5jb2RlZCB4LWNvb3JkaW5hdGUgb2YgUAogICAgICB2YWwgcmVzcG9uc2UgICAgICAgPSByZXNwb25zZVR1cGxlLl8xIC8vIFIgaW4gQklQLTAzNDAKICAgICAgdmFsIHJCeXRlcyAgICAgICAgID0gcmVzcG9uc2VUdXBsZS5fMiAvLyBCeXRlIHJlcHJlc2VudGF0aW9uIG9mICdyJwoKCiAgICAgIHZhbCByYXcgPSBzaGEyNTYoY2hhbGxlbmdlVGFnICsrIGNoYWxsZW5nZVRhZyArKyByQnl0ZXMgKysgcGtCeXRlcyArKyBtZXNzYWdlKQogCiAgICAgIC8vIE5vdGUgdGhhdCB0aGUgb3V0cHV0IG9mIFNIQTI1NiBpcyBhIGNvbGxlY3Rpb24gb2YgYnl0ZXMgdGhhdCByZXByZXNlbnRzIGFuIHVuc2lnbmVkIDI1NmJpdCBpbnRlZ2VyLiAKICAgICAgdmFsIGZpcnN0ID0gdG9TaWduZWRCeXRlcyhyYXcuc2xpY2UoMCwxNikpCiAgICAgIHZhbCBjb25jYXRCeXRlcyA9IGZpcnN0LmFwcGVuZCh0b1NpZ25lZEJ5dGVzKHJhdy5zbGljZSgxNixyYXcuc2l6ZSkpKQogICAgICB2YWwgZmlyc3RJbnROdW1CeXRlcyA9IGZpcnN0LnNpemUKICAgICAgbXlFeHAoKGdyb3VwR2VuZXJhdG9yLCBzKSkgPT0gIG15RXhwKChwdWJLZXksIChjb25jYXRCeXRlcywgZmlyc3RJbnROdW1CeXRlcykpKS5tdWx0aXBseShyZXNwb25zZSkKICAgIH0KICAgICAgCiAgKQp9
        const SCRIPT_BYTES: &str = "291X3UroKTCRC8KCGxEMLgq35xFL9Hng8iuN1CWPjV8cYBzBr49FQ6KYioEMd6nfB7Vw7rt2m3pfU7sgCbzKv67pFj5iRVgxGvp5XzYSR43GJEjqkNL8HGoU7EDyqTDir9Bj6UJMKyACzzBr4ui7dqkKAwTrY4rYsvvgUp1GZYEKun6ZqSCYSRTyd4PztGUXVGmWykSajpjB9ddp5kwn15qNYT9HJ9rpENofSaeoroooLaAs3d9Z1idarto3zY2YnHN31fa67L3xDtRsCZ2wC3yp2RV9VroiWggAD98ddViYuHXD6eFhu9ifFuRPbR1k96CMo9U2Mup9kiJUcx6TPhKPBn8gWqqRemGAs4EVuz75d52wgqfQxgc6hEDQwUh7BedjusfXeSTneVCcZevRJFmgFnpo2dnNk5PotVXQGqHSJBbe48mU4S7eZ6px5ZtyjPsAdjMffHX3p33f9eCdJkzkQYhRDEzRYM29faVRemnDz3PfgrSUiMioFc68K54B";

        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder.parse_address_from_str(SCRIPT_BYTES).unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();

        let msg = b"foo".as_slice();
        let mut rng = OsRng;
        let mut sigs = vec![];

        for i in 0..100 {
            let secret_key = SecretKey::random(&mut rng);
            let signing_key = SigningKey::from(secret_key);
            let signature = signing_key.sign(msg);
            sigs.push((
                i as usize,
                Some((Commitment::from(*signing_key.verifying_key()), signature)),
            ));
        }

        let schnorr_sig_data = serialize_exclusion_set(sigs, msg);

        let mut registers = HashMap::new();

        registers.insert(NonMandatoryRegisterId::R4, Constant::from(msg.to_vec()));
        registers.insert(NonMandatoryRegisterId::R5, Constant::from(generator()));
        let mut values = IndexMap::new();
        values.insert(0, schnorr_sig_data);
        let input_box = ErgoBox::new(
            erg_value,
            ergo_tree,
            None,
            NonMandatoryRegisters::new(registers).unwrap(),
            900000,
            TxId::zero(),
            0,
        )
        .unwrap();

        // Send all Ergs to miner fee
        let miner_output = ErgoBoxCandidate {
            value: erg_value,
            ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: 900001,
        };
        let outputs = TxIoVec::from_vec(vec![miner_output]).unwrap();
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values });
        let unsigned_tx =
            UnsignedTransaction::new(TxIoVec::from_vec(vec![unsigned_input]).unwrap(), None, outputs)
                .unwrap();
        let tx_context = TransactionContext::new(unsigned_tx, vec![input_box], vec![]).unwrap();
        let wallet = get_wallet();
        let ergo_state_context: ErgoStateContext = dummy_ergo_state_context();
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    fn get_wallet() -> Wallet {
        const SEED_PHRASE: &str = "gather gather gather gather gather gather gather gather gather gather gather gather gather gather gather";
        Wallet::from_mnemonic(SEED_PHRASE, "").expect("Invalid seed")
    }

    fn dummy_ergo_state_context() -> ErgoStateContext {
        let mut rng = OsRng;
        let pre_header = PreHeader {
            version: 1,
            parent_id: BlockId(Digest::zero()),
            timestamp: 1234,
            n_bits: 1234,
            height: 900000,
            miner_pk: Box::new(EcPoint::from(
                SecretKey::random(&mut rng).public_key().to_projective(),
            )),
            votes: Votes([0, 0, 0]),
        };

        let header = Header {
            version: 1,
            id: BlockId(Digest::zero()),
            parent_id: BlockId(Digest::zero()),
            ad_proofs_root: Digest::zero(),
            state_root: Digest::zero(),
            transaction_root: Digest::zero(),
            timestamp: 1234,
            n_bits: 1234,
            height: 900000,
            extension_root: Digest::zero(),
            autolykos_solution: ergo_lib::ergo_chain_types::AutolykosSolution {
                miner_pk: Box::new(EcPoint::from(
                    SecretKey::random(&mut rng).public_key().to_projective(),
                )),
                pow_onetime_pk: None,
                nonce: vec![0, 1, 2, 3],
                pow_distance: None,
            },
            votes: Votes([0, 0, 0]),
        };
        let headers = [
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
            header.clone(),
        ];
        ErgoStateContext { pre_header, headers }
    }

    #[test]
    fn verify_non_byzantine_ergoscript() {
        let committee_sizes = vec![4, 8, 16, 32, 64, 128, 256, 512];
        for committee_size in committee_sizes {
            println!("Committee size: {}", committee_size);
            let num_participants = 16;
            let mut rng = OsRng;
            let md = blake2b256_hash(b"foo");
            let individual_keys = (0..num_participants)
                .map(|_| {
                    let sk = SecretKey::random(&mut rng);
                    let pk = PublicKey::from(sk.public_key());
                    let (commitment_sk, commitment) = schnorr_commitment_pair();
                    (sk, pk, commitment_sk, commitment)
                })
                .collect::<Vec<_>>();
            let committee = individual_keys
                .iter()
                .map(|(_, pk, _, _)| pk.clone())
                .collect::<Vec<_>>();
            let individual_inputs = individual_keys
                .iter()
                .map(|(_, pki, _, _)| individual_input::<Blake2b<U32>>(committee.clone(), pki.clone()))
                .collect::<Vec<_>>();
            let aggregate_x = aggregate_pk(
                individual_keys.iter().map(|(_, pk, _, _)| pk.clone()).collect(),
                individual_inputs.clone(),
            );
            let aggregate_commitment = aggregate_commitment(
                individual_keys
                    .iter()
                    .map(|(_, _, _, commitment)| commitment.clone())
                    .collect(),
            );
            let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
            let individual_responses = individual_keys
                .iter()
                .enumerate()
                .map(|(i, (sk, pk, commitment_sk, _))| {
                    response(commitment_sk.clone(), sk.clone(), challenge, individual_inputs[i])
                })
                .collect::<Vec<_>>();

            for (i, zi) in individual_responses.iter().enumerate() {
                let (_, pk, _, commitment) = &individual_keys[i];
                assert!(verify_response(
                    zi,
                    &individual_inputs[i],
                    &challenge,
                    commitment.clone(),
                    pk.clone()
                ))
            }

            let aggregate_response = aggregate_response(individual_responses);
            assert!(verify(
                aggregate_commitment.clone(),
                aggregate_response,
                Vec::new(),
                committee.clone(),
                md,
                Threshold { num: 1, denom: 1 }
            ));

            verify_ergoscript_with_sigma_rust(
                committee,
                num_participants,
                aggregate_commitment,
                aggregate_response,
                vec![],
                md,
            );
        }
    }

    #[test]
    fn verify_byzantine_ergoscript() {
        let num_byzantine_nodes = vec![34];

        for num_byzantine in num_byzantine_nodes {
            println!("# byzantine nodes: {}", num_byzantine);
            let num_participants = 128;
            let mut rng = OsRng;
            let mut byz_indexes = vec![];
            loop {
                let rng = rng.gen_range(0usize..num_participants);
                if !byz_indexes.contains(&rng) {
                    byz_indexes.push(rng);
                }
                if byz_indexes.len() == num_byzantine {
                    break;
                }
            }
            let md = blake2b256_hash(b"foo");
            let individual_keys = (0..num_participants)
                .map(|_| {
                    let sk = SecretKey::random(&mut rng);
                    let pk = PublicKey::from(sk.public_key());
                    let (commitment_sk, commitment) = schnorr_commitment_pair();
                    (sk, pk, commitment_sk, commitment)
                })
                .collect::<Vec<_>>();
            let committee = individual_keys
                .iter()
                .map(|(_, pk, _, _)| pk.clone())
                .collect::<Vec<_>>();
            let individual_inputs = individual_keys
                .iter()
                .map(|(_, pki, _, _)| individual_input::<Blake2b<U32>>(committee.clone(), pki.clone()))
                .collect::<Vec<_>>();
            let aggregate_x = aggregate_pk(
                individual_keys.iter().map(|(_, pk, _, _)| pk.clone()).collect(),
                individual_inputs.clone(),
            );
            let aggregate_commitment = aggregate_commitment(
                individual_keys
                    .iter()
                    .map(|(_, _, _, commitment)| commitment.clone())
                    .collect(),
            );
            let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
            let (byz_keys, active_keys): (Vec<_>, Vec<_>) = individual_keys
                .clone()
                .into_iter()
                .enumerate()
                .partition(|(i, _)| byz_indexes.contains(i));
            let individual_responses_subset = active_keys
                .iter()
                .map(|(i, (sk, _, commitment_sk, _))| {
                    (
                        *i,
                        response(
                            commitment_sk.clone(),
                            sk.clone(),
                            challenge,
                            individual_inputs[*i],
                        ),
                    )
                })
                .collect::<Vec<_>>();
            for (i, zi) in individual_responses_subset.iter() {
                let (_, pk, _, commitment) = &individual_keys[*i];
                assert!(verify_response(
                    zi,
                    &individual_inputs[*i],
                    &challenge,
                    commitment.clone(),
                    pk.clone()
                ))
            }
            let aggregate_response =
                aggregate_response(individual_responses_subset.into_iter().map(|(_, x)| x).collect());
            let exclusion_set = byz_keys
                .iter()
                .map(|(i, (_, _, sk, commitment))| {
                    (*i, Some((commitment.clone(), exclusion_proof(sk.clone(), md))))
                })
                .collect::<Vec<_>>();
            let threshold = Threshold { num: 2, denom: 4 };
            assert!(verify(
                aggregate_commitment.clone(),
                aggregate_response,
                exclusion_set.clone(),
                committee.clone(),
                md,
                threshold,
            ));
            let exclusion_set: Vec<_> = exclusion_set
                .into_iter()
                .map(|(ix, pair)| (ix, pair.map(|(c, s)| (c, k256::schnorr::Signature::from(s)))))
                .collect();
            verify_ergoscript_with_sigma_rust(
                committee,
                (num_participants * threshold.num / threshold.denom) as i32,
                aggregate_commitment,
                aggregate_response,
                exclusion_set,
                md,
            );
        }
    }

    #[tokio::test]
    async fn verify_byzantine_ergoscript_sigmastate() {
        let num_byzantine_nodes = vec![40];

        for num_byzantine in num_byzantine_nodes {
            println!("# byzantine nodes: {}", num_byzantine);
            let num_participants = 512;
            let mut rng = OsRng;
            let mut byz_indexes = vec![];
            loop {
                let rng = rng.gen_range(0usize..num_participants);
                if !byz_indexes.contains(&rng) {
                    byz_indexes.push(rng);
                }
                if byz_indexes.len() == num_byzantine {
                    break;
                }
            }
            let md = blake2b256_hash(b"foo");
            let individual_keys = (0..num_participants)
                .map(|_| {
                    let sk = SecretKey::random(&mut rng);
                    let pk = PublicKey::from(sk.public_key());
                    let (commitment_sk, commitment) = schnorr_commitment_pair();
                    (sk, pk, commitment_sk, commitment)
                })
                .collect::<Vec<_>>();
            let committee = individual_keys
                .iter()
                .map(|(_, pk, _, _)| pk.clone())
                .collect::<Vec<_>>();
            let individual_inputs = individual_keys
                .iter()
                .map(|(_, pki, _, _)| individual_input::<Blake2b<U32>>(committee.clone(), pki.clone()))
                .collect::<Vec<_>>();
            let aggregate_x = aggregate_pk(
                individual_keys.iter().map(|(_, pk, _, _)| pk.clone()).collect(),
                individual_inputs.clone(),
            );
            let aggregate_commitment = aggregate_commitment(
                individual_keys
                    .iter()
                    .map(|(_, _, _, commitment)| commitment.clone())
                    .collect(),
            );
            let challenge = challenge(aggregate_x, aggregate_commitment.clone(), md);
            let (byz_keys, active_keys): (Vec<_>, Vec<_>) = individual_keys
                .clone()
                .into_iter()
                .enumerate()
                .partition(|(i, _)| byz_indexes.contains(i));
            let individual_responses_subset = active_keys
                .iter()
                .map(|(i, (sk, _, commitment_sk, _))| {
                    (
                        *i,
                        response(
                            commitment_sk.clone(),
                            sk.clone(),
                            challenge,
                            individual_inputs[*i],
                        ),
                    )
                })
                .collect::<Vec<_>>();
            for (i, zi) in individual_responses_subset.iter() {
                let (_, pk, _, commitment) = &individual_keys[*i];
                assert!(verify_response(
                    zi,
                    &individual_inputs[*i],
                    &challenge,
                    commitment.clone(),
                    pk.clone()
                ))
            }
            let aggregate_response =
                aggregate_response(individual_responses_subset.into_iter().map(|(_, x)| x).collect());
            let exclusion_set = byz_keys
                .iter()
                .map(|(i, (_, _, sk, commitment))| {
                    (*i, Some((commitment.clone(), exclusion_proof(sk.clone(), md))))
                })
                .collect::<Vec<_>>();
            let threshold = Threshold { num: 2, denom: 4 };
            assert!(verify(
                aggregate_commitment.clone(),
                aggregate_response,
                exclusion_set.clone(),
                committee.clone(),
                md,
                threshold,
            ));
            let exclusion_set: Vec<_> = exclusion_set
                .into_iter()
                .map(|(ix, pair)| (ix, pair.map(|(c, s)| (c, k256::schnorr::Signature::from(s)))))
                .collect();
            verify_ergoscript_with_sigmastate(
                committee,
                (num_participants * threshold.num / threshold.denom) as i32,
                aggregate_commitment,
                aggregate_response,
                exclusion_set,
                md,
            )
            .await;
        }
    }

    async fn verify_ergoscript_with_sigmastate(
        committee: Vec<PublicKey>,
        threshold: i32,
        aggregate_commitment: AggregateCommitment,
        aggregate_response: Scalar,
        exclusion_set: Vec<(usize, Option<(Commitment, Signature)>)>,
        md: Blake2bDigest256,
    ) {
        let c_bytes = committee.iter().fold(Vec::<u8>::new(), |mut b, p| {
            b.extend_from_slice(
                k256::PublicKey::from(p.clone())
                    .to_projective()
                    .to_bytes()
                    .as_slice(),
            );
            b
        });
        let committee_bytes = blake2b256_hash(&c_bytes).as_ref().to_vec();
        let committee_lit = Literal::from(
            committee
                .into_iter()
                .map(|p| EcPoint::from(k256::PublicKey::from(p).to_projective()))
                .collect::<Vec<_>>(),
        );

        let serialized_committee = Constant {
            tpe: SType::SColl(Box::new(SType::SGroupElement)),
            v: committee_lit,
        };

        let serialized_aggregate_commitment =
            Constant::from(EcPoint::from(ProjectivePoint::from(aggregate_commitment)));

        let s_biguint = scalar_to_biguint(aggregate_response);
        let biguint_bytes = s_biguint.to_bytes_be();
        if biguint_bytes.len() < 32 {
            println!("# bytes: {}", biguint_bytes.len());
        }
        let split = biguint_bytes.len() - 16;
        let upper = BigUint::from_bytes_be(&biguint_bytes[..split]);
        let upper_256 = BigInt256::try_from(upper).unwrap();
        assert_eq!(upper_256.sign(), Sign::Plus);
        let lower = BigUint::from_bytes_be(&biguint_bytes[split..]);
        let lower_256 = BigInt256::try_from(lower).unwrap();
        assert_eq!(lower_256.sign(), Sign::Plus);

        let mut aggregate_response_bytes = upper_256.to_signed_bytes_be();
        // Need this variable because we could add an extra byte to the encoding for signed-representation.
        let first_len = aggregate_response_bytes.len() as i32;
        aggregate_response_bytes.extend(lower_256.to_signed_bytes_be());

        let exclusion_set_data = serialize_exclusion_set(exclusion_set, md.as_ref());
        let aggregate_response: Constant = (
            Constant::from(aggregate_response_bytes),
            Constant::from(first_len),
        )
            .into();

        let input = SignatureValidationInput {
            contract: SIGNATURE_AGGREGATE_SCRIPT_BYTES.to_string(),
            exclusion_set: exclusion_set_data.base16_str().unwrap(),
            aggregate_response: aggregate_response.base16_str().unwrap(),
            aggregate_commitment: serialized_aggregate_commitment.base16_str().unwrap(),
            generator: Constant::from(generator()).base16_str().unwrap(),
            identity: Constant::from(EcPoint::from(ProjectivePoint::IDENTITY))
                .base16_str()
                .unwrap(),
            committee: serialized_committee.base16_str().unwrap(),
            md: Constant::from(md.as_ref().to_vec()).base16_str().unwrap(),
            threshold: Constant::from(threshold).base16_str().unwrap(),
            hash_bytes: Constant::from(committee_bytes.clone()).base16_str().unwrap(),
        };

        let raw = reqwest::Client::new()
            .put("http://localhost:8080/validate")
            .json(&input)
            .send()
            .await
            .unwrap();
        println!("{:?}", raw);
        let details = raw.json::<ValidationResponse>().await.unwrap();

        println!("{}", serde_json::to_string(&details).unwrap());
    }

    #[test]
    fn test_committee_box_size() {
        let num_participants = 118;
        let mut rng = OsRng;
        let individual_keys = (0..num_participants)
            .map(|_| {
                let sk = SecretKey::random(&mut rng);
                let pk = PublicKey::from(sk.public_key());
                let (commitment_sk, commitment) = schnorr_commitment_pair();
                (sk, pk, commitment_sk, commitment)
            })
            .collect::<Vec<_>>();
        let vault_sk = ergo_lib::wallet::secret_key::SecretKey::random_dlog();
        let ergo_tree = vault_sk.get_address_from_public_image().script().unwrap();
        let committee = individual_keys
            .iter()
            .map(|(_, pk, _, _)| pk.clone())
            .collect::<Vec<_>>();
        create_committee_input_box(&committee, ergo_tree, Some(9));
    }

    fn verify_ergoscript_with_sigma_rust(
        committee: Vec<PublicKey>,
        threshold: i32,
        aggregate_commitment: AggregateCommitment,
        aggregate_response: Scalar,
        exclusion_set: Vec<(usize, Option<(Commitment, Signature)>)>,
        md: Blake2bDigest256,
    ) {
        let c_bytes = committee.iter().fold(Vec::<u8>::new(), |mut b, p| {
            b.extend_from_slice(
                k256::PublicKey::from(p.clone())
                    .to_projective()
                    .to_bytes()
                    .as_slice(),
            );
            b
        });
        let committee_bytes = blake2b256_hash(&c_bytes).as_ref().to_vec();

        let serialized_aggregate_commitment =
            Constant::from(EcPoint::from(ProjectivePoint::from(aggregate_commitment)));

        let s_biguint = scalar_to_biguint(aggregate_response);
        let biguint_bytes = s_biguint.to_bytes_be();
        if biguint_bytes.len() < 32 {
            println!("# bytes: {}", biguint_bytes.len());
        }
        let split = biguint_bytes.len() - 16;
        let upper = BigUint::from_bytes_be(&biguint_bytes[..split]);
        let upper_256 = BigInt256::try_from(upper).unwrap();
        assert_eq!(upper_256.sign(), Sign::Plus);
        let lower = BigUint::from_bytes_be(&biguint_bytes[split..]);
        let lower_256 = BigInt256::try_from(lower).unwrap();
        assert_eq!(lower_256.sign(), Sign::Plus);

        let mut aggregate_response_bytes = upper_256.to_signed_bytes_be();
        // Need this variable because we could add an extra byte to the encoding for signed-representation.
        let first_len = aggregate_response_bytes.len() as i32;
        aggregate_response_bytes.extend(lower_256.to_signed_bytes_be());

        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder
            .parse_address_from_str(SIGNATURE_AGGREGATE_SCRIPT_BYTES)
            .unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();

        let mut registers = HashMap::new();

        let exclusion_set_data = serialize_exclusion_set(exclusion_set, md.as_ref());
        let aggregate_response: Constant = (
            Constant::from(aggregate_response_bytes),
            Constant::from(first_len),
        )
            .into();

        let num_bytes_needed: usize = vec![
            address.content_bytes().len(),
            exclusion_set_data.sigma_serialize_bytes().unwrap().len(),
            aggregate_response.sigma_serialize_bytes().unwrap().len(),
            serialized_aggregate_commitment
                .sigma_serialize_bytes()
                .unwrap()
                .len(),
            //Constant::from(generator()).sigma_serialize_bytes().unwrap().len(),
            //Constant::from(EcPoint::from(ProjectivePoint::IDENTITY))
            //    .sigma_serialize_bytes()
            //    .unwrap()
            //    .len(),
            //serialized_committee.sigma_serialize_bytes().unwrap().len(),
            Constant::from(md.as_ref().to_vec())
                .sigma_serialize_bytes()
                .unwrap()
                .len(),
            Constant::from(threshold).sigma_serialize_bytes().unwrap().len(),
            Constant::from(committee_bytes.clone())
                .sigma_serialize_bytes()
                .unwrap()
                .len(),
        ]
        .into_iter()
        .sum();

        println!(
            "# bytes in exclusion set: {}",
            exclusion_set_data.sigma_serialize_bytes().unwrap().len()
        );

        registers.insert(NonMandatoryRegisterId::R4, Constant::from(md.as_ref().to_vec()));
        registers.insert(NonMandatoryRegisterId::R5, Constant::from(generator()));
        registers.insert(
            NonMandatoryRegisterId::R6,
            Constant::from(EcPoint::from(ProjectivePoint::IDENTITY)),
        );
        registers.insert(NonMandatoryRegisterId::R7, threshold.into());
        registers.insert(NonMandatoryRegisterId::R8, committee_bytes.into());
        let mut values = IndexMap::new();
        values.insert(0, exclusion_set_data);
        values.insert(1, aggregate_response);
        values.insert(2, serialized_aggregate_commitment);
        let input_box = ErgoBox::new(
            erg_value,
            ergo_tree,
            None,
            NonMandatoryRegisters::new(registers).unwrap(),
            900000,
            TxId::zero(),
            0,
        )
        .unwrap();

        // Send all Ergs to miner fee
        let miner_output = ErgoBoxCandidate {
            value: erg_value,
            ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: 900001,
        };
        let outputs = TxIoVec::from_vec(vec![miner_output]).unwrap();
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values });

        // We've determined empirically that we can fit at most 118 public keys into a single box.
        const MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX: usize = 118;

        let vault_sk = ergo_lib::wallet::secret_key::SecretKey::random_dlog();
        let ergo_tree = vault_sk.get_address_from_public_image().script().unwrap();
        let num_data_inputs = committee.len() / MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX + 1;
        let data_boxes: Vec<_> = committee
            .chunks(MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX)
            .map(|chunk| create_committee_input_box(chunk, ergo_tree.clone(), Some(num_data_inputs as i16)))
            .collect();

        let data_inputs: Vec<_> = data_boxes
            .iter()
            .map(|d| DataInput { box_id: d.box_id() })
            .collect();
        let data_inputs = Some(TxIoVec::from_vec(data_inputs).unwrap());

        let unsigned_tx = UnsignedTransaction::new(
            TxIoVec::from_vec(vec![unsigned_input]).unwrap(),
            data_inputs,
            outputs,
        )
        .unwrap();
        let tx_context = TransactionContext::new(unsigned_tx, vec![input_box], data_boxes).unwrap();
        let wallet = get_wallet();
        let ergo_state_context: ErgoStateContext = dummy_ergo_state_context();
        let now = Instant::now();
        println!("Signing TX...");
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        if res.is_err() {
            panic!("{:?}", res);
        }
        println!("Time to validate and sign: {} ms", now.elapsed().as_millis());
    }

    fn create_committee_input_box(
        committee_members: &[PublicKey],
        ergo_tree: ErgoTree,
        number_of_boxes: Option<i16>,
    ) -> ErgoBox {
        let committee_lit = Literal::from(
            committee_members
                .iter()
                .map(|p| EcPoint::from(k256::PublicKey::from(p.clone()).to_projective()))
                .collect::<Vec<_>>(),
        );

        let serialized_committee = Constant {
            tpe: SType::SColl(Box::new(SType::SGroupElement)),
            v: committee_lit,
        };

        let mut registers = HashMap::new();
        registers.insert(NonMandatoryRegisterId::R4, serialized_committee);
        if let Some(num_boxes) = number_of_boxes {
            registers.insert(NonMandatoryRegisterId::R5, num_boxes.into());
        }
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();
        let input_box = ErgoBox::new(
            erg_value,
            ergo_tree,
            None,
            NonMandatoryRegisters::new(registers).unwrap(),
            900000,
            TxId::zero(),
            0,
        )
        .unwrap();

        println!(
            "box is {} bytes",
            input_box.sigma_serialize_bytes().unwrap().len()
        );

        input_box
    }

    #[derive(Serialize)]
    struct SignatureValidationInput {
        contract: String,
        #[serde(rename = "exclusionSet")]
        exclusion_set: String,
        #[serde(rename = "aggregateResponse")]
        aggregate_response: String,
        #[serde(rename = "aggregateCommitment")]
        aggregate_commitment: String,
        generator: String,
        identity: String,
        committee: String,
        md: String,
        threshold: String,
        #[serde(rename = "hashBytes")]
        hash_bytes: String,
    }

    #[derive(Deserialize, Serialize)]
    struct ValidationResponse {
        #[serde(rename = "Right")]
        right: Value,
    }

    #[derive(Deserialize, Serialize)]
    struct Value {
        value: ValidationDetails,
    }
    #[derive(Deserialize, Serialize)]
    //#[serde(from = "ValidationResponse")]   // Would be nice to have this, but it fails in practice.
    struct ValidationDetails {
        result: bool,
        #[serde(rename = "txCost")]
        tx_cost: usize,
        #[serde(rename = "validationTimeMillis")]
        validation_time_millis: usize,
    }

    impl From<ValidationResponse> for ValidationDetails {
        fn from(value: ValidationResponse) -> Self {
            value.right.value
        }
    }
}
