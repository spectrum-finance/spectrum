use std::hash::Hash;

use derive_more::From;
use elliptic_curve::ops::{LinearCombination, Reduce};
use ergo_lib::{
    ergo_chain_types::{Digest32 as ELDigest32, DigestNError, EcPoint},
    ergotree_ir::{
        bigint256::BigInt256,
        chain::{
            address::Address,
            ergo_box::box_value::{BoxValue, BoxValueError},
            token::{Token, TokenAmount, TokenAmountError, TokenId},
        },
        mir::{
            constant::{Constant, Literal},
            value::CollKind,
        },
        serialization::{SigmaParsingError, SigmaSerializable},
        types::{
            stuple::{STuple, TupleItems},
            stype::SType,
        },
    },
};
use k256::{schnorr::Signature, FieldElement, NonZeroScalar, ProjectivePoint, Scalar, U256};
use num_bigint::{BigUint, Sign, ToBigUint};
use scorex_crypto_avltree::batch_node::{Node, NodeHeader};
use sha2::Digest as OtherDigest;
use sha2::Sha256;
use spectrum_ledger::{cell::TermCell, ERGO_CHAIN_ID};
use spectrum_sigma::Commitment;

pub struct ErgoTermCell {
    ergs: BoxValue,
    address: Address,
    tokens: Vec<Token>,
}

impl ErgoTermCell {
    fn to_bytes(&self) -> Vec<u8> {
        let mut res = vec![];
        res.extend_from_slice(&self.ergs.as_i64().to_be_bytes());
        let prop_bytes = self.address.script().unwrap().sigma_serialize_bytes().unwrap();
        res.extend(prop_bytes);
        for Token { token_id, amount } in &self.tokens {
            let digest = ergo_lib::ergo_chain_types::Digest32::from(*token_id);
            res.extend(digest.0);
            res.extend(&(*amount.as_u64()).to_be_bytes());
        }
        res
    }
}

impl Hash for ErgoTermCell {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ergs.as_i64().hash(state);
        let prop_bytes = self.address.script().unwrap().sigma_serialize_bytes().unwrap();
        prop_bytes.hash(state);
        for Token { token_id, amount } in &self.tokens {
            let digest = ergo_lib::ergo_chain_types::Digest32::from(*token_id);
            digest.0.hash(state);
            (*amount.as_u64() as i64).hash(state);
        }
    }
}

pub struct ErgoTermCells(Vec<ErgoTermCell>);

impl ErgoTermCell {
    fn get_stype() -> SType {
        SType::STuple(STuple {
            items: TupleItems::from_vec(vec![
                SType::SLong,
                SType::STuple(STuple {
                    items: TupleItems::from_vec(vec![
                        SType::SColl(Box::new(SType::SByte)),
                        SType::SColl(Box::new(SType::STuple(STuple {
                            items: TupleItems::from_vec(vec![
                                SType::SColl(Box::new(SType::SByte)),
                                SType::SLong,
                            ])
                            .unwrap(),
                        }))),
                    ])
                    .unwrap(),
                }),
            ])
            .unwrap(),
        })
    }
}

#[derive(From)]
pub enum ErgoTermCellError {
    BoxValue(BoxValueError),
    SigmaParsing(SigmaParsingError),
    DigestN(DigestNError),
    TokenAmount(TokenAmountError),
    WrongChainId,
}

impl TryFrom<TermCell> for ErgoTermCell {
    type Error = ErgoTermCellError;

    fn try_from(value: TermCell) -> Result<Self, Self::Error> {
        if value.dst.target == ERGO_CHAIN_ID {
            let ergs = BoxValue::try_from(value.value.native.0)?;
            let address_bytes: Vec<u8> = value.dst.address.into();
            let address = Address::p2pk_from_pk_bytes(&address_bytes)?;
            let mut token_details = vec![];
            for (_, assets) in value.value.assets {
                for (id, a) in assets {
                    let digest = ELDigest32::try_from(id.0.as_ref())?;
                    let amount = TokenAmount::try_from(a.0)?;
                    token_details.push((digest, amount));
                }
            }

            token_details.sort_by(|a, b| a.0.cmp(&b.0));

            let tokens = token_details
                .into_iter()
                .map(|(digest, amount)| Token {
                    token_id: TokenId::from(digest),
                    amount,
                })
                .collect();

            Ok(ErgoTermCell {
                ergs,
                address,
                tokens,
            })
        } else {
            Err(ErgoTermCellError::WrongChainId)
        }
    }
}

impl From<ErgoTermCell> for Constant {
    fn from(cell: ErgoTermCell) -> Self {
        // The Constant is of the form (nanoErg, (propositionBytes, tokens)), with type
        //    (Long, (Coll[Byte], Coll[(Coll[Byte], Long)]))
        //
        let nano_ergs: Constant = cell.ergs.into();
        let prop_bytes: Constant = cell
            .address
            .script()
            .unwrap()
            .sigma_serialize_bytes()
            .unwrap()
            .into();
        let elem_tpe = ErgoTermCell::get_stype();
        let tokens: Vec<Literal> = cell
            .tokens
            .into_iter()
            .map(|t| {
                let tup: Constant = (
                    Constant::from(t.token_id),
                    Constant::from(*t.amount.as_u64() as i64),
                )
                    .into();
                tup.v
            })
            .collect();
        let tokens = Constant {
            tpe: SType::SColl(Box::new(elem_tpe.clone())),
            v: Literal::Coll(CollKind::WrappedColl {
                elem_tpe,
                items: tokens,
            }),
        };
        let inner_tuple: Constant = (prop_bytes, tokens).into();
        (nano_ergs, inner_tuple).into()
    }
}

impl From<ErgoTermCells> for Constant {
    fn from(value: ErgoTermCells) -> Self {
        let lits: Vec<_> = value
            .0
            .into_iter()
            .map(|e| {
                let c = Constant::from(e);
                c.v
            })
            .collect();
        Constant {
            tpe: SType::SColl(Box::new(ErgoTermCell::get_stype())),
            v: Literal::Coll(CollKind::WrappedColl {
                elem_tpe: ErgoTermCell::get_stype(),
                items: lits,
            }),
        }
    }
}

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

fn dummy_resolver(digest: &scorex_crypto_avltree::operation::Digest32) -> Node {
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
    use ergo_lib::ergo_chain_types::{
        ec_point::generator, BlockId, Digest, EcPoint, Header, PreHeader, Votes,
    };
    use ergo_lib::ergotree_interpreter::sigma_protocol::prover::ContextExtension;
    use ergo_lib::ergotree_ir::chain::address::{Address, NetworkAddress};
    use ergo_lib::ergotree_ir::chain::ergo_box::BoxTokens;
    use ergo_lib::ergotree_ir::chain::token::{Token, TokenAmount};
    use ergo_lib::ergotree_ir::{
        base16_str::Base16Str,
        bigint256::BigInt256,
        chain::{
            address::{AddressEncoder, NetworkPrefix},
            ergo_box::{
                box_value::BoxValue, ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId, NonMandatoryRegisters,
            },
        },
        ergo_tree::ErgoTree,
        mir::{
            avl_tree_data::{AvlTreeData, AvlTreeFlags},
            constant::{Constant, Literal},
        },
        types::stype::SType,
    };
    use ergo_lib::ergotree_ir::{
        mir::value::CollKind,
        serialization::SigmaSerializable,
        types::stuple::{STuple, TupleItems},
    };
    use ergo_lib::wallet::{miner_fee::MINERS_FEE_ADDRESS, tx_context::TransactionContext, Wallet};
    use ergo_lib::{
        chain::{
            ergo_state_context::ErgoStateContext,
            transaction::{unsigned::UnsignedTransaction, DataInput, TxId, TxIoVec, UnsignedInput},
        },
        ergotree_ir::chain::token::TokenId,
    };
    use indexmap::IndexMap;
    use itertools::Itertools;
    use k256::{
        schnorr::{signature::Signer, Signature, SigningKey},
        ProjectivePoint, Scalar, SecretKey,
    };
    use num_bigint::BigUint;
    use num_bigint::Sign;
    use rand::rngs::OsRng;
    use rand::Rng;
    use scorex_crypto_avltree::{
        authenticated_tree_ops::*, batch_avl_prover::BatchAVLProver, batch_node::*, operation::*,
    };
    use serde::Deserialize;
    use serde::Serialize;
    use sigma_test_util::force_any_val;
    use spectrum_crypto::{
        digest::{blake2b256_hash, Blake2bDigest256},
        pubkey::PublicKey,
    };
    use spectrum_handel::Threshold;
    use spectrum_sigma::{
        crypto::{
            aggregate_commitment, aggregate_pk, aggregate_response, challenge, exclusion_proof,
            individual_input, response, schnorr_commitment_pair, verify, verify_response,
        },
        AggregateCommitment, Commitment,
    };
    use std::collections::HashMap;
    use std::time::Instant;

    use crate::script::{scalar_to_biguint, serialize_exclusion_set, ErgoTermCell, ErgoTermCells};

    use super::dummy_resolver;

    // Script URL: ewoKICAvLyBSZXByZXNlbnRzIHRoZSBudW1iZXIgb2YgZGF0YSBpbnB1dHMgdGhhdCBjb250YWluIHRoZSBHcm91cEVsZW1lbnQgb2YgY29tbWl0dGVlIG1lbWJlcnMuCiAgdmFsIG51bWJlckNvbW1pdHRlZURhdGFJbnB1dEJveGVzID0gQ09OVEVYVC5kYXRhSW5wdXRzKDApLlI1W1Nob3J0XS5nZXQKICB2YWwgZ3JvdXBHZW5lcmF0b3IgICAgICAgPSBDT05URVhULmRhdGFJbnB1dHMoMCkuUjZbR3JvdXBFbGVtZW50XS5nZXQKICB2YWwgZ3JvdXBFbGVtZW50SWRlbnRpdHkgPSBDT05URVhULmRhdGFJbnB1dHMoMCkuUjdbR3JvdXBFbGVtZW50XS5nZXQKICAvLyBCeXRlIHJlcHJlc2VudGF0aW9uIG9mIEgoWF8xLCAuLi4sIFhfbikKICB2YWwgaW5uZXJCeXRlcyAgICAgICAgICAgPSBDT05URVhULmRhdGFJbnB1dHMoMCkuUjhbQ29sbFtCeXRlXV0uZ2V0IAoKICAvLyBUaGUgR3JvdXBFbGVtZW50cyBvZiBlYWNoIGNvbW1pdHRlZSBtZW1iZXIgYXJlIGFycmFuZ2VkIHdpdGhpbiBhIENvbGxbR3JvdXBFbGVtZW50XQogIC8vIHJlc2lkaW5nIHdpdGhpbiB0aGUgUjQgcmVnaXN0ZXIgb2YgdGhlIGZpcnN0ICduID09IG51bWJlckNvbW1pdHRlZURhdGFJbnB1dEJveGVzJwogIC8vIGRhdGEgaW5wdXRzLgogIHZhbCBjb21taXR0ZWUgPSBDT05URVhULmRhdGFJbnB1dHMuc2xpY2UoMCwgbnVtYmVyQ29tbWl0dGVlRGF0YUlucHV0Qm94ZXMudG9JbnQpLmZvbGQoCiAgICBDb2xsW0dyb3VwRWxlbWVudF0oKSwKICAgIHsgKGFjYzogQ29sbFtHcm91cEVsZW1lbnRdLCB4OiBCb3gpID0
    const SIGNATURE_AGGREGATION_SCRIPT_BYTES: &str = "6r15oRzuDZbNeMDGSXfSMJhyD7fu95LkC8wR2YekrBEGoSJnEC4BncB8WDVWAMNmWYrLUTdQdNZnwJJXyQjyUnjLDAnqHtPBgq8QvHvEux3YsibhqCMRi1aAcjcdFAbuwXpfbRVt4MkSfHYyovvTHGVAL3JgMpvdjYXwB7DoirYAYZgLSZCRZW2uAN5ZGNL9tzeDPS1BR2cc8ZmYEEFMQdq59s2AXKF4CPkTh2gNxFpeNyJsRNVG3phUJc2nAN1kbYakVZVojwRXkZ6qeGspnG8NaRcKj2KXuvQ4S7dhEeDaEW1qNm2JNNxWhS2hLrkBh6CgpSjVyRhEyvQ4vQxUaPtigfjKVo7jZZETc5uYaRrA4h3tCDZJNcNTaaezpAbmyyak3EjQRGmCziTgwk6g4D9beLobiZQp8Ex3XjMGybr7BSm26idk6yRV5kegj3s835WZvFi6XVXVNwtCTjCVNopZDF6qyvssK1ZKR3sYmLkXSJ4tyi2C94xNbkALrjHcmv2iVZ384dfkAqgsYVyCs1P3tPza1ho5oLcZMbto3YKZD9tDDkawJZH2eA5Grr2cjp2Xbhx61D96d7i1a7uMU95MKEmbVRmRzie2f3RRgn5dPu19wtHrPSHnTXXbWnEvnjbRPtJGGZEUZUawNNNEapU3TK8T83nYDmfVkbRB7VipqPxm7sAFm9LYhch8evmy9YQWurYhvGwTmdmPbmA5PUEpeVmA59cekaK6piN6dXrXx7aX9u6QR3PCtbZqfpSXEk1gmeZ218NK5DXgQZ6jcdVFcQnh62m1RGacuxAoFLeRPh5A2GCb39iguyAnsYDD8sAME2i88AArHfUN3Wor5V6KuJcpeorzdFd5SZPc3ezUckqcXNs3fSXBKK5Yy3SUKQoYGeAsUPucQ3Mha4p3CduGWVbfrrmr8pXARFGU8eHJq9aPHQSYrwEg1WY9mDvDhSC1eXEU3hEfTHEyjRLQzCfTMDNcK2GXYbTfomnKEsSVq3uowXYGKwbMKuuArEkC8cfMFZq4XenvNBW91jkJkZvpG688q5Nk1WqCxBYF8tyo7Y7nLhWC7pQY7nZJgWtgTH1ubzu1TBWmP72YxfFwqua2iLFrwreDg9tNtFFhP9j5fwASM6GBheUPrkDbjoBXDdvYVZrmLyfkcEhgKpaGUkh5UYg85RDRkntqpgrctRAgG6B1Ahq2UNCVLq2V5WWj9pAUmV7SQaCfmb8N3dXCcTF4KgnZ3AdPF8UnWNsvjwfagqEV3x1EyfnhhDs";

    // Script URL: https://wallet.plutomonkey.com/p2s/?source=eyAvLyA9PT09PSBDb250cmFjdCBJbmZvcm1hdGlvbiA9PT09PSAvLwogIC8vIE5hbWU6IFZhdWx0U2lnbmF0dXJlVmVyaWZpY2F0aW9uCiAgLy8gRGVzY3JpcHRpb246IENvbnRyYWN0IHRoYXQgdmFsaWRhdGVzIHRoZSBhZ2dyZWdhdGVkIHNpZ25hdHVyZSBvZiBhIG1lc3NhZ2UgZGlnZXN0ICdtJyBhbmQKICAvLyBhbHNvIHZlcmlmaWVzIHRoYXQgYWxsIHRyYW5zYWN0aW9ucyBpbiBhIGdpdmVuIHJlcG9ydCB3ZXJlIG5vdGFyaXplZCBieSB0aGUgY3VycmVudCBjb21taXR0ZWUKICAvLyAodmFsaWRhdG9yIHNldCkuCiAgLy8KICAvLyBUaGlzIGlzIGhvdyB0aGUgb3ZlcmFsbCBwcm9jZXNzIHdvcmtzOgogIC8vICAxLiBUaGUgJ3JlcG9ydCcgY29uc2lzdHMgb2YgYSBjb2xsZWN0aW9uIG9mICd0ZXJtaW5hbCBjZWxscycsIHdoaWNoIGRlc2NyaWJlcyB0aGUgdmFsdWUKICAvLyAgICAgKEVSR3MgYW5kIHRva2VucykgdGhhdCB3aWxsIGJlIHRyYW5zZmVycmVkIHRvIGEgcGFydGljdWxhciBhZGRyZXNzLgogIC8vICAyLiBFYWNoIHRlcm1pbmFsIGNlbGwgaXMgZW5jb2RlZCBhcyBieXRlcyB3aGljaCBhcmUgdXNlZCBpbiBhbiBpbnNlcnRpb24gb3BlcmF0aW9uIG9mIGFuIEFWTAogIC8vICAgICB0cmVlLgogIC8vICAzLiBUaGUgaW5zZXJ0aW9ucyBhcmUgcGVyZm9ybWVkIG9mZi1jaGFpbiBhbmQgdGhlIHJlc3VsdGluZyBBVkwgdHJlZSBkaWdlc3QgaXMgaGFzaGVkIGJ5CiAgLy8gICAgIGJsYWtlMmIyNTY7IHRoaXMgdmFsdWUgaXMgdGhlIG1lc3NhZ2UgZGlnZXN0ICdtJy4KICAvLyAgNC4gVGhlIGNvbW1pdHRlZSBwZXJmb3JtcyB0aGUgc2lnbmF0dXJlIGFnZ3JlZ2F0aW9uIHByb2Nlc3MgdG8gc2lnbiAnbScuCiAgLy8gIDUuIFRoaXMgY29udHJhY3QgdmVyaWZpZXMgdGhhdCB0aGUgY29tbWl0dGVlIHNpZ25lZCAnbScsIGVuY29kZXMgdGhlIHRlcm1pbmFsIGNlbGxzIGFuZAogIC8vICAgICByZWNyZWF0ZXMgdGhlIEFWTCB0cmVlIHByb29mLCBhbmQgY2hlY2tzIHRoYXQgdGhlIGhhc2ggb2YgdGhlIHJlc3VsdGluZyBBVkwgZGlnZXN0IGlzIGVxdWFsCiAgLy8gICAgIHRvICdtJy4KICAvLwogIC8vID09PT09IERhdGEgaW5wdXRzID09PT09CiAgLy8gUmVnaXN0ZXJzIG9mIGRhdGFJbnB1dCgwKToKICAvLyAgIFI0W0NvbGxbR3JvdXBFbGVtZW50XV06IFB1YmxpYyBrZXlzIG9mIGNvbW1pdHRlZSBtZW1iZXJzCiAgLy8gICBSNVtTaG9ydF06IFRoZSBudW1iZXIgJ0QnIG9mIGRhdGEgaW5wdXQgYm94ZXMgdGhhdCBuZWVkZWQgdG8gc3RvcmUgY29tbWl0dGVlIGluZm9ybWF0aW9uLgogIC8vICAgUjZbR3JvdXBFbGVtZW50XTogR2VuZXJhdG9yIG9mIHRoZSBzZWNwMjU2azEgY3VydmUuCiAgLy8gICBSN1tHcm91cEVsZW1lbnRdOiBJZGVudGl0eSBlbGVtZW50IG9mIHNlY3AyNTZrMS4KICAvLyAgIFI4W0NvbGxbQnl0ZV1dOiBCeXRlIHJlcHJlc2VudGF0aW9uIG9mIEgoWF8xLCAuLi4sIFhfbikKICAvLwogIC8vIFJlZ2lzdGVycyBvZiBkYXRhSW5wdXQoMSksIC4uLiwgZGF0YUlucHV0KEQpOgogIC8vICAgUjRbQ29sbFtHcm91cEVsZW1lbnRdXTogUHVibGljIGtleXMgb2YgY29tbWl0dGVlIG1lbWJlcnMKCiAgdmFsIG51bWJlckNvbW1pdHRlZURhdGFJbnB1dEJveGVzID0gQ09OVEVYVC5kYXRhSW5wdXRzKDApLlI1W1Nob3J0XS5nZXQKICB2YWwgZ3JvdXBHZW5lcmF0b3IgICAgICAgPSBDT05URVhULmRhdGFJbnB1dHMoMCkuUjZbR3JvdXBFbGVtZW50XS5nZXQKICB2YWwgZ3JvdXBFbGVtZW50SWRlbnRpdHkgPSBDT05URVhULmRhdGFJbnB1dHMoMCkuUjdbR3JvdXBFbGVtZW50XS5nZXQKICB2YWwgaW5uZXJCeXRlcyAgICAgICAgICAgPSBDT05URVhULmRhdGFJbnB1dHMoMCkuUjhbQ29sbFtCeXRlXV0uZ2V0IAoKICAvLyBUaGUgR3JvdXBFbGVtZW50cyBvZiBlYWNoIGNvbW1pdHRlZSBtZW1iZXIgYXJlIGFycmFuZ2VkIHdpdGhpbiBhIENvbGxbR3JvdXBFbGVtZW50XQogIC8vIHJlc2lkaW5nIHdpdGhpbiB0aGUgUjQgcmVnaXN0ZXIgb2YgdGhlIGZpcnN0ICdEID09IG51bWJlckNvbW1pdHRlZURhdGFJbnB1dEJveGVzJwogIC8vIGRhdGEgaW5wdXRzLgogIHZhbCBjb21taXR0ZWUgPSBDT05URVhULmRhdGFJbnB1dHMuc2xpY2UoMCwgbnVtYmVyQ29tbWl0dGVlRGF0YUlucHV0Qm94ZXMudG9JbnQpLmZvbGQoCiAgICBDb2xsW0dyb3VwRWxlbWVudF0oKSwKICAgIHsgKGFjYzogQ29sbFtHcm91cEVsZW1lbnRdLCB4OiBCb3gpID0+CiAgICAgICAgYWNjLmFwcGVuZCh4LlI0W0NvbGxbR3JvdXBFbGVtZW50XV0uZ2V0KQogICAgfQogICkKCiAgLy8gQ29udGV4dEV4dGVuc2lvbiBjb25zdGFudHM6CiAgLy8gIDA6IERhdGEgdG8gdmVyaWZ5IHRoZSBzaWduYXR1cmVzIHdpdGhpbiB0aGUgZXhjbHVzaW9uIHNldAogIC8vICAxOiBBZ2dyZWdhdGUgcmVzcG9uc2UgJ3onIGZyb20gV1AuCiAgLy8gIDI6IEFnZ3JlZ2F0ZSBjb21taXRtZW50ICdZJyBmcm9tIFdQLgogIC8vICAzOiBNZXNzYWdlIGRpZ2VzdCAnbScgZnJvbSBXUC4KICAvLyAgNDogVmVyaWZpY2F0aW9uIHRocmVzaG9sZAogIC8vICA1OiBUZXJtaW5hbCBjZWxscyBkZXNjcmliaW5nIHdpdGhkcmF3YWxzIGZyb20gc3BlY3RydW0tbmV0d29yawogIC8vICA2OiBTdGFydGluZyBBVkwgdHJlZSB0aGF0IGlzIHVzZWQgaW4gcmVwb3J0IG5vdGFyaXphdGlvbgogIC8vICA3OiBJbnNlcnRpb24gb3BlcmF0aW9ucyBmb3IgQVZMIHRyZWUKICAvLyAgODogQVZMIHRyZWUgcHJvb2YsIHVzZWQgdG8gcmVjb25zdHJ1Y3QgcGFydCBvZiB0aGUgdHJlZQogIHZhbCB2ZXJpZmljYXRpb25EYXRhICAgICA9IGdldFZhcltDb2xsWygoSW50LCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSksICgoQ29sbFtCeXRlXSwgSW50KSwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpICldXSgwKS5nZXQKICB2YWwgYWdncmVnYXRlUmVzcG9uc2VSYXcgPSBnZXRWYXJbKENvbGxbQnl0ZV0sIEludCldKDEpLmdldAogIHZhbCBhZ2dyZWdhdGVDb21taXRtZW50ICA9IGdldFZhcltHcm91cEVsZW1lbnRdKDIpLmdldAogIHZhbCBtZXNzYWdlICAgICAgICAgICAgICA9IGdldFZhcltDb2xsW0J5dGVdXSgzKS5nZXQKICB2YWwgdGhyZXNob2xkICAgICAgICAgICAgPSBnZXRWYXJbSW50XSg0KS5nZXQKICB2YWwgdGVybWluYWxDZWxscyAgICAgICAgPSBnZXRWYXJbQ29sbFsoTG9uZywgKENvbGxbQnl0ZV0sIENvbGxbKENvbGxbQnl0ZV0sIExvbmcpXSkpXV0oNSkuZ2V0CgogIHZhbCB0cmVlICAgICAgICA9IGdldFZhcltBdmxUcmVlXSg2KS5nZXQKICB2YWwgb3BlcmF0aW9ucyAgPSBnZXRWYXJbQ29sbFsoQ29sbFtCeXRlXSwgQ29sbFtCeXRlXSldXSg3KS5nZXQKICB2YWwgcHJvb2YgICAgICAgPSBnZXRWYXJbQ29sbFtCeXRlXV0oOCkuZ2V0CgogIC8vIFBlcmZvcm1zIGV4cG9uZW50aWF0aW9uIG9mIGEgR3JvdXBFbGVtZW50IGJ5IGFuIHVuc2lnbmVkIDI1NmJpdAogIC8vIGludGVnZXIgSSB1c2luZyB0aGUgZm9sbG93aW5nIGRlY29tcG9zaXRpb24gb2YgSToKICAvLyBMZXQgZSA9IChnLCAoYiwgbikpLiBUaGVuIHRoaXMgZnVuY3Rpb24gY29tcHV0ZXM6CiAgLy8KICAvLyAgIGdeSSA9PSAoZ15iKDAsbikpXnAgKiBnXihiKG4uLikpCiAgLy8gd2hlcmUKICAvLyAgLSBiKDAsbikgaXMgdGhlIGZpcnN0IG4gYnl0ZXMgb2YgYSBwb3NpdGl2ZSBCaWdJbnQgYFVgCiAgLy8gIC0gYihuLi4pIGFyZSB0aGUgcmVtYWluaW5nIGJ5dGVzIHN0YXJ0aW5nIGZyb20gaW5kZXggbi4gVGhlc2UgYnl0ZXMKICAvLyAgICBhbHNvIHJlcHJlc2VudCBhIHBvc2l0aXZlIEJpZ0ludCBgTGAuCiAgLy8gIC0gcCBpcyAzNDAyODIzNjY5MjA5Mzg0NjM0NjMzNzQ2MDc0MzE3NjgyMTE0NTYgYmFzZSAxMC4KICAvLyAgLSBJID09IFUgKiBwICsgTAogIGRlZiBteUV4cChlOiAoR3JvdXBFbGVtZW50LCAoQ29sbFtCeXRlXSwgSW50KSkpIDogR3JvdXBFbGVtZW50ID0gewogICAgdmFsIHggPSBlLl8xCiAgICB2YWwgeSA9IGUuXzIuXzEKICAgIHZhbCBsZW4gPSBlLl8yLl8yCiAgICB2YWwgdXBwZXIgPSBieXRlQXJyYXlUb0JpZ0ludCh5LnNsaWNlKDAsIGxlbikpCiAgICB2YWwgbG93ZXIgPSBieXRlQXJyYXlUb0JpZ0ludCh5LnNsaWNlKGxlbiwgeS5zaXplKSkKCiAgICAvLyBUaGUgZm9sbG93aW5nIHZhbHVlIGlzIDM0MDI4MjM2NjkyMDkzODQ2MzQ2MzM3NDYwNzQzMTc2ODIxMTQ1NiBiYXNlLTEwLgogICAgdmFsIHAgPSBieXRlQXJyYXlUb0JpZ0ludChmcm9tQmFzZTY0KCJBUUFBQUFBQUFBQUFBQUFBQUFBQUFBQSIpKQogICAKICAgIHguZXhwKHVwcGVyKS5leHAocCkubXVsdGlwbHkoeC5leHAobG93ZXIpKQogIH0KCiAgLy8gQ29udmVydHMgYSBiaWctZW5kaWFuIGJ5dGUgcmVwcmVzZW50YXRpb24gb2YgYW4gdW5zaWduZWQgaW50ZWdlciBpbnRvIGl0cwogIC8vIGVxdWl2YWxlbnQgc2lnbmVkIHJlcHJlc2VudGF0aW9uCiAgZGVmIHRvU2lnbmVkQnl0ZXMoYjogQ29sbFtCeXRlXSkgOiBDb2xsW0J5dGVdID0gewogICAgLy8gTm90ZSB0aGF0IGFsbCBpbnRlZ2VycyAoaW5jbHVkaW5nIEJ5dGUpIGluIEVyZ29zY3JpcHQgYXJlIHNpZ25lZC4gSW4gc3VjaAogICAgLy8gYSByZXByZXNlbnRhdGlvbiwgdGhlIG1vc3Qtc2lnbmlmaWNhbnQgYml0IChNU0IpIGlzIHVzZWQgdG8gcmVwcmVzZW50IHRoZQogICAgLy8gc2lnbjsgMCBmb3IgYSBwb3NpdGl2ZSBpbnRlZ2VyIGFuZCAxIGZvciBuZWdhdGl2ZS4gTm93IHNpbmNlIGBiYCBpcyBiaWctCiAgICAvLyBlbmRpYW4sIHRoZSBNU0IgcmVzaWRlcyBpbiB0aGUgZmlyc3QgYnl0ZSBhbmQgTVNCID09IDEgaW5kaWNhdGVzIHRoYXQgZXZlcnkKICAgIC8vIGJpdCBpcyB1c2VkIHRvIHNwZWNpZnkgdGhlIG1hZ25pdHVkZSBvZiB0aGUgaW50ZWdlci4gVGhpcyBtZWFucyB0aGF0IGFuCiAgICAvLyBleHRyYSAwLWJpdCBtdXN0IGJlIHByZXBlbmRlZCB0byBgYmAgdG8gcmVuZGVyIGl0IGEgdmFsaWQgcG9zaXRpdmUgc2lnbmVkCiAgICAvLyBpbnRlZ2VyLgogICAgLy8KICAgIC8vIE5vdyBzaWduZWQgaW50ZWdlcnMgYXJlIG5lZ2F0aXZlIGlmZiBNU0IgPT0gMSwgaGVuY2UgdGhlIGNvbmRpdGlvbiBiZWxvdy4KICAgIGlmIChiKDApIDwgMCApIHsKICAgICAgICBDb2xsKDAudG9CeXRlKS5hcHBlbmQoYikKICAgIH0gZWxzZSB7CiAgICAgICAgYgogICAgfQogIH0KCiAgLy8gQ29tcHV0ZXMgYV9pID0gSChIKFhfMSwgWF8yLC4uLCBYX24pOyBYX2kpCiAgZGVmIGNhbGNBKGU6IChDb2xsW0dyb3VwRWxlbWVudF0sIEludCkpIDogKENvbGxbQnl0ZV0sIEludCkgPSB7CiAgICB2YWwgY29tbWl0dGVlTWVtYmVycyA9IGUuXzEKICAgIHZhbCBpID0gZS5fMgogICAgdmFsIHJhdyA9IGJsYWtlMmIyNTYoaW5uZXJCeXRlcy5hcHBlbmQoY29tbWl0dGVlTWVtYmVycyhpKS5nZXRFbmNvZGVkKSkKICAgIHZhbCBzcGxpdCA9IHJhdy5zaXplIC0gMTYKICAgIHZhbCBmaXJzdEludCA9IHRvU2lnbmVkQnl0ZXMocmF3LnNsaWNlKDAsIHNwbGl0KSkKICAgIHZhbCBjb25jYXRCeXRlcyA9IGZpcnN0SW50LmFwcGVuZCh0b1NpZ25lZEJ5dGVzKHJhdy5zbGljZShzcGxpdCwgcmF3LnNpemUpKSkKICAgIHZhbCBmaXJzdEludE51bUJ5dGVzID0gZmlyc3RJbnQuc2l6ZQogICAgKGNvbmNhdEJ5dGVzLCBmaXJzdEludE51bUJ5dGVzKQogIH0KICAKICAvLyBDb21wdXRlcyBYfiA9IFhfMF57YV8wfSAqIFhfMV57YV8xfSAqIC4uLiAqIFhfe24tMX1ee2Ffe24tMX19CiAgZGVmIGNhbGNGdWxsQWdncmVnYXRlS2V5KGU6IChDb2xsW0dyb3VwRWxlbWVudF0sIENvbGxbKENvbGxbQnl0ZV0sIEludCldICkpIDogR3JvdXBFbGVtZW50ID0gewogICAgdmFsIGNvbW1pdHRlZU1lbWJlcnMgPSBlLl8xCiAgICB2YWwgYWlWYWx1ZXMgPSBlLl8yCiAgICBjb21taXR0ZWVNZW1iZXJzLmZvbGQoCiAgICAgIChncm91cEVsZW1lbnRJZGVudGl0eSwgMCksCiAgICAgIHsgKGFjYzogKEdyb3VwRWxlbWVudCwgSW50ICksIHg6IEdyb3VwRWxlbWVudCkgPT4KICAgICAgICAgIHZhbCB4X2FjYyA9IGFjYy5fMQogICAgICAgICAgdmFsIGkgPSBhY2MuXzIKICAgICAgICAgICh4X2FjYy5tdWx0aXBseShteUV4cCgoeCwgYWlWYWx1ZXMoaSkpKSksIGkgKyAxKQogICAgICB9CiAgICApLl8xCiAgfQoKICAvLyBDb21wdXRlcyBYJwogIGRlZiBjYWxjUGFydGlhbEFnZ3JlZ2F0ZUtleShlOiAoKENvbGxbR3JvdXBFbGVtZW50XSwgQ29sbFtJbnRdKSwgQ29sbFsoQ29sbFtCeXRlXSwgSW50KV0pKSA6IEdyb3VwRWxlbWVudCA9IHsKICAgIHZhbCBjb21taXR0ZWVNZW1iZXJzID0gZS5fMS5fMQogICAgdmFsIGV4Y2x1ZGVkSW5kaWNlcyA9IGUuXzEuXzIKICAgIHZhbCBhaVZhbHVlcyA9IGUuXzIKICAgIGNvbW1pdHRlZU1lbWJlcnMuZm9sZCgKICAgICAgKGdyb3VwRWxlbWVudElkZW50aXR5LCAwKSwKICAgICAgeyAoYWNjOiAoR3JvdXBFbGVtZW50LCBJbnQpLCB4OiBHcm91cEVsZW1lbnQpID0+CiAgICAgICAgICB2YWwgeEFjYyA9IGFjYy5fMQogICAgICAgICAgdmFsIGkgPSBhY2MuXzIKICAgICAgICAgIGlmIChleGNsdWRlZEluZGljZXMuZXhpc3RzIHsgKGl4OiBJbnQpID0+IGl4ID09IGkgfSkgewogICAgICAgICAgICAgKHhBY2MsIGkgKyAxKQogICAgICAgICAgfSBlbHNlIHsKICAgICAgICAgICAgKHhBY2MubXVsdGlwbHkobXlFeHAoKHgsIGFpVmFsdWVzKGkpKSkpLCBpICsgMSkKICAgICAgICAgIH0KICAgICAgICAgIAogICAgICB9CiAgICApLl8xCiAgfQoKICAvLyBDYWxjdWxhdGVzIGFnZ3JlZ2F0ZSBjb21taXRtZW50IFknCiAgZGVmIGNhbGNBZ2dyZWdhdGVDb21taXRtZW50KGNvbW1pdG1lbnRzOiBDb2xsW0dyb3VwRWxlbWVudF0pIDogR3JvdXBFbGVtZW50ID0gewogICAgY29tbWl0bWVudHMuZm9sZCgKICAgICAgZ3JvdXBFbGVtZW50SWRlbnRpdHksCiAgICAgIHsgKGFjYzogR3JvdXBFbGVtZW50LCB5OiBHcm91cEVsZW1lbnQpID0+CiAgICAgICAgICBhY2MubXVsdGlwbHkoeSkKICAgICAgfQogICAgKSAgCiAgfQoKICBkZWYgZW5jb2RlVW5zaWduZWQyNTZCaXRJbnQoYnl0ZXM6IENvbGxbQnl0ZV0pIDogKENvbGxbQnl0ZV0sIEludCkgPSB7CiAgICB2YWwgc3BsaXQgPSBieXRlcy5zaXplIC0gMTYKICAgIHZhbCBmaXJzdEludCA9IHRvU2lnbmVkQnl0ZXMoYnl0ZXMuc2xpY2UoMCwgc3BsaXQpKQogICAgdmFsIGNvbmNhdEJ5dGVzID0gZmlyc3RJbnQuYXBwZW5kKHRvU2lnbmVkQnl0ZXMoYnl0ZXMuc2xpY2Uoc3BsaXQsIGJ5dGVzLnNpemUpKSkKICAgIHZhbCBmaXJzdEludE51bUJ5dGVzID0gZmlyc3RJbnQuc2l6ZQogICAgKGNvbmNhdEJ5dGVzLCBmaXJzdEludE51bUJ5dGVzKQogIH0KICAgIAogIC8vIEJJUC0wMzQwIHVzZXMgc28tY2FsbGVkIHRhZ2dlZCBoYXNoZXMKICB2YWwgY2hhbGxlbmdlVGFnID0gc2hhMjU2KENvbGwoNjYsIDczLCA4MCwgNDgsIDUxLCA1MiwgNDgsIDQ3LCA5OSwgMTA0LCA5NywgMTA4LCAxMDgsIDEwMSwgMTEwLCAxMDMsIDEwMSkubWFwIHsgKHg6SW50KSA9PiB4LnRvQnl0ZSB9KQogIAogIC8vIFByZWNvbXB1dGUgYV9pIHZhbHVlcwogIHZhbCBhaVZhbHVlcyA9IGNvbW1pdHRlZS5pbmRpY2VzLm1hcCB7IChpeDogSW50KSA9PgogICAgY2FsY0EoKGNvbW1pdHRlZSwgaXgpKQogIH0KCiAgLy8gYwogIHZhbCBjaGFsbGVuZ2VSYXcgPSBibGFrZTJiMjU2KGNhbGNGdWxsQWdncmVnYXRlS2V5KChjb21taXR0ZWUsIGFpVmFsdWVzKSkuZ2V0RW5jb2RlZCArKyBhZ2dyZWdhdGVDb21taXRtZW50LmdldEVuY29kZWQgKysgbWVzc2FnZSApCiAgdmFsIGNoYWxsZW5nZSAgICA9IGVuY29kZVVuc2lnbmVkMjU2Qml0SW50KGNoYWxsZW5nZVJhdykKCiAgdmFsIGV4Y2x1ZGVkSW5kaWNlcyA9IHZlcmlmaWNhdGlvbkRhdGEubWFwIHsgKGU6ICgoSW50LCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSksICgoQ29sbFtCeXRlXSwgSW50KSwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpKSkgPT4KICAgIGUuXzEuXzEgCiAgfQoKICB2YWwgZXhjbHVkZWRDb21taXRtZW50cyA9IHZlcmlmaWNhdGlvbkRhdGEubWFwIHsgKGU6ICgoSW50LCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSksICgoQ29sbFtCeXRlXSwgSW50KSwgKEdyb3VwRWxlbWVudCwgQ29sbFtCeXRlXSkpKSkgPT4KICAgIGUuXzEuXzIuXzEgCiAgfQoKICAvLyBZJyBmcm9tIFdQCiAgdmFsIFlEYXNoID0gY2FsY0FnZ3JlZ2F0ZUNvbW1pdG1lbnQoZXhjbHVkZWRDb21taXRtZW50cykKCiAgLy8gWCcgZnJvbSBXUAogIHZhbCBwYXJ0aWFsQWdncmVnYXRlS2V5ID0gY2FsY1BhcnRpYWxBZ2dyZWdhdGVLZXkoKChjb21taXR0ZWUsIGV4Y2x1ZGVkSW5kaWNlcyksIGFpVmFsdWVzKSkKCiAgLy8gVmVyaWZpZXMgdGhhdCBZJypnXnogPT0gKFgnKV5jICogWQogIHZhbCB2ZXJpZnlBZ2dyZWdhdGVSZXNwb25zZSA9ICggbXlFeHAoKGdyb3VwR2VuZXJhdG9yLCBhZ2dyZWdhdGVSZXNwb25zZVJhdykpLm11bHRpcGx5KFlEYXNoKSAKICAgICAgPT0gbXlFeHAoKHBhcnRpYWxBZ2dyZWdhdGVLZXksIGNoYWxsZW5nZSkpLm11bHRpcGx5KGFnZ3JlZ2F0ZUNvbW1pdG1lbnQpICkKCiAgLy8gVmVyaWZpZXMgZWFjaCB0YXByb290IHNpZ25hdHVyZSBpbiB0aGUgZXhjbHVzaW9uIHNldAogIHZhbCB2ZXJpZnlTaWduYXR1cmVzSW5FeGNsdXNpb25TZXQgPQogICAgdmVyaWZpY2F0aW9uRGF0YS5mb3JhbGwgeyAoZTogKChJbnQsIChHcm91cEVsZW1lbnQsIENvbGxbQnl0ZV0pKSwgKChDb2xsW0J5dGVdLCBJbnQpLCAoR3JvdXBFbGVtZW50LCBDb2xsW0J5dGVdKSkpKSA9PgogICAgICB2YWwgcHViS2V5VHVwbGUgPSBlLl8xLl8yCiAgICAgIHZhbCBzICA9IGUuXzIuXzEKICAgICAgdmFsIHJlc3BvbnNlVHVwbGUgPSBlLl8yLl8yCgogICAgICB2YWwgcHViS2V5ICAgICAgICAgPSBwdWJLZXlUdXBsZS5fMSAvLyBZX2kKICAgICAgdmFsIHBrQnl0ZXMgICAgICAgID0gcHViS2V5VHVwbGUuXzIgLy8gZW5jb2RlZCB4LWNvb3JkaW5hdGUgb2YgWV9pCiAgICAgIHZhbCByZXNwb25zZSAgICAgICA9IHJlc3BvbnNlVHVwbGUuXzEgLy8gUiBpbiBCSVAtMDM0MAogICAgICB2YWwgckJ5dGVzICAgICAgICAgPSByZXNwb25zZVR1cGxlLl8yIC8vIEJ5dGUgcmVwcmVzZW50YXRpb24gb2YgJ3InCgoKICAgICAgdmFsIHJhdyA9IHNoYTI1NihjaGFsbGVuZ2VUYWcgKysgY2hhbGxlbmdlVGFnICsrIHJCeXRlcyArKyBwa0J5dGVzICsrIG1lc3NhZ2UpCiAKICAgICAgLy8gTm90ZSB0aGF0IHRoZSBvdXRwdXQgb2YgU0hBMjU2IGlzIGEgY29sbGVjdGlvbiBvZiBieXRlcyB0aGF0IHJlcHJlc2VudHMgYW4gdW5zaWduZWQgMjU2Yml0IGludGVnZXIuCiAgICAgIHZhbCBzcGxpdCA9IHJhdy5zaXplIC0gMTYKICAgICAgdmFsIGZpcnN0ID0gdG9TaWduZWRCeXRlcyhyYXcuc2xpY2UoMCwgc3BsaXQpKQogICAgICB2YWwgY29uY2F0Qnl0ZXMgPSBmaXJzdC5hcHBlbmQodG9TaWduZWRCeXRlcyhyYXcuc2xpY2Uoc3BsaXQsIHJhdy5zaXplKSkpCiAgICAgIHZhbCBmaXJzdEludE51bUJ5dGVzID0gZmlyc3Quc2l6ZQogICAgICBteUV4cCgoZ3JvdXBHZW5lcmF0b3IsIHMpKSA9PSAgbXlFeHAoKHB1YktleSwgKGNvbmNhdEJ5dGVzLCBmaXJzdEludE51bUJ5dGVzKSkpLm11bHRpcGx5KHJlc3BvbnNlKQogICAgfQoKICAvLyBDaGVjayB0aHJlc2hvbGQgY29uZGl0aW9uIGZyb20gV1AKICB2YWwgdmVyaWZ5VGhyZXNob2xkID0gKGNvbW1pdHRlZS5zaXplIC0gdmVyaWZpY2F0aW9uRGF0YS5zaXplKSA+PSB0aHJlc2hvbGQKCiAgLy8gQ2hlY2sgdGhhdCB0aGUgYWRkcmVzcywgbmFuby1FcmcgdmFsdWUgYW5kIHRva2VucyAoaWYgdGhleSBleGlzdCkgc3BlY2lmaWVkIGluIGVhY2ggdGVybWluYWwgY2VsbCBUX2kKICAvLyBhcmUgcHJvcGVybHkgc3BlY2lmaWVkIGluIHRoZSBpJ3RoIG91dHB1dCBib3ggCiAgdmFsIHZlcmlmeVR4T3V0cHV0cyA9IHRlcm1pbmFsQ2VsbHMuemlwKE9VVFBVVFMpLmZvcmFsbCB7IChlOiAoKExvbmcsIChDb2xsW0J5dGVdLCBDb2xsWyhDb2xsW0J5dGVdLCBMb25nKV0pKSwgQm94KSkgPT4gCiAgICB2YWwgdGVybUNlbGwgPSBlLl8xCiAgICB2YWwgb3V0cHV0Qm94ID0gZS5fMgogICAgdmFsIHRlcm1DZWxsVG9rZW5zOiBDb2xsWyhDb2xsW0J5dGVdLCBMb25nKV0gPSB0ZXJtQ2VsbC5fMi5fMgogICAgb3V0cHV0Qm94LnZhbHVlID09IHRlcm1DZWxsLl8xICYmCiAgICBvdXRwdXRCb3gucHJvcG9zaXRpb25CeXRlcyA9PSB0ZXJtQ2VsbC5fMi5fMSAmJgogICAgb3V0cHV0Qm94LnRva2Vucy5zaXplID09IHRlcm1DZWxsLl8yLl8yLnNpemUgJiYKICAgIG91dHB1dEJveC50b2tlbnMuemlwKHRlcm1DZWxsVG9rZW5zKS5mb3JhbGwgeyAoZTogKChDb2xsW0J5dGVdLCBMb25nKSwgKENvbGxbQnl0ZV0sIExvbmcpKSkgPT4KICAgICAgZS5fMSA9PSBlLl8yICAgICAgCiAgICB9CiAgfQoKICBkZWYgaGFzaFRlcm1pbmFsQ2VsbChjZWxsOiAoTG9uZywgKENvbGxbQnl0ZV0sIENvbGxbKENvbGxbQnl0ZV0sIExvbmcpXSkpKSA6IENvbGxbQnl0ZV0gPSB7CiAgICB2YWwgbmFub0VyZ3MgPSBjZWxsLl8xCiAgICB2YWwgcHJvcEJ5dGVzID0gY2VsbC5fMi5fMQogICAgdmFsIHRva2VucyA9IGNlbGwuXzIuXzIKICAgIHZhbCB0b2tlbkJ5dGVzID0gdG9rZW5zLmZvbGQoCiAgICAgIENvbGxbQnl0ZV0oKSwKICAgICAgeyAoYWNjOiBDb2xsW0J5dGVdLCB0OiAoQ29sbFtCeXRlXSwgTG9uZykpID0+CiAgICAgICAgICBhY2MgKysgdC5fMSArKyBsb25nVG9CeXRlQXJyYXkodC5fMikKICAgICAgfSAgICAgIAogICAgKQogICAgdmFsIGJ5dGVzID0gbG9uZ1RvQnl0ZUFycmF5KG5hbm9FcmdzKSArKyBwcm9wQnl0ZXMgKysgdG9rZW5CeXRlcwogICAgYmxha2UyYjI1NihieXRlcykKICB9CgogIHZhbCBlbmRUcmVlID0gdHJlZS5pbnNlcnQob3BlcmF0aW9ucywgcHJvb2YpLmdldAogIHZhbCB2ZXJpZnlEaWdlc3QgPSBibGFrZTJiMjU2KGVuZFRyZWUuZGlnZXN0KSA9PSBtZXNzYWdlCgogIC8vIFZlcmlmaWVzIHRoYXQgZWFjaCBBVkwgaW5zZXJ0aW9uIG9wZXJhdGlvbiBjb3JyZXNwb25kcyB0byB0aGUgYXNzb2NpYXRlZCB0ZXJtaW5hbCBjZWxsICAKICB2YWwgdmVyaWZ5T3BlcmF0aW9ucyA9IG9wZXJhdGlvbnMuc2l6ZSA+IDAgJiYgb3BlcmF0aW9ucy56aXAodGVybWluYWxDZWxscy56aXAodGVybWluYWxDZWxscy5pbmRpY2VzKSkuZm9yYWxsIHsKICAgIChlOiAoKENvbGxbQnl0ZV0sIENvbGxbQnl0ZV0pLCAoKExvbmcsIChDb2xsW0J5dGVdLCBDb2xsWyhDb2xsW0J5dGVdLCBMb25nKV0pKSwgSW50KSkgKSA9PgogICAgICB2YWwga2V5ID0gZS5fMS5fMQogICAgICB2YWwgdmFsdWUgPSBlLl8xLl8yCiAgICAgIHZhbCB0ZXJtaW5hbENlbGwgPSBlLl8yLl8xCiAgICAgIHZhbCBpeCA9IGUuXzIuXzIgKyAxCiAgICAgIGtleSA9PSBsb25nVG9CeXRlQXJyYXkoaXgudG9Mb25nKSAmJgogICAgICAgIHZhbHVlID09IGhhc2hUZXJtaW5hbENlbGwodGVybWluYWxDZWxsKQogIH0KCiAgc2lnbWFQcm9wICgKICAgIHZlcmlmeURpZ2VzdCAmJgogICAgdmVyaWZ5T3BlcmF0aW9ucyAmJgogICAgdmVyaWZ5QWdncmVnYXRlUmVzcG9uc2UgJiYKICAgIHZlcmlmeVNpZ25hdHVyZXNJbkV4Y2x1c2lvblNldCAmJgogICAgdmVyaWZ5VGhyZXNob2xkICYmCiAgICB2ZXJpZnlUeE91dHB1dHMKICApCn0=
    const VAULT_CONTRACT_SCRIPT_BYTES: &str = "2iFLSnxiTdtJm4vUr6UomUryb8XNczMCvfdX9jfDsfqR1rQyswmdAxu2g61yFUCjAWA7ruN3wy5rW7tvGiT7ApnagXvbcWbSgJTeUqQsUy41cyDZXYhrnPm19x4LvDeLTrZBxjLfSfGEcQoJyLwnktVs1sAh93gzDwcXWUVZcx3rLzDH4MkhpGitvjFetu432Jjs4dDUjFL7etQkrCwUDJAq9QodPNeN4eEWvoEAJPy3tM16wa6vGMeqtUVmVEMbTkfcpsGLUe8j2QYEyAMb1a9T8kbpVLCeV4Xgp6e1mcxc8JRAJDo6FncciuvDvKV3GcPCbUjyFBRbTKZzCKYHJbb8QppZ7Nc1f7vj17ghHmWfEeFHi7bkwJ4Y7a4sGKFnSKRA6d2ad1iwbmBGGLXXAy3KN6MBPH8cFrrV5SYMAexmFTM1EqWyvtbCWxNM2z7xf96YJZ777acJU5NJxwc9YjLns1CwadGceQEJ1cfmnpt4MWn3TmLGL1LC5Qk3hh4Yy9f5fVhw7fFUqUxvbSYMREz4sZjQcLDNjhgMZLu3PcyTAz8iv8sUT6eP4SYM3bX3D1VFBXiZtzg2rokrX4P6xacNEo9g5E4qe9kYzP2ZvX9oD6Svcqf2bEFowdk9kzUNdy7i6vxkixdNfgywbsAzHghMpKjfrxhQX5KjD84fyWHVCavpTPnCn9RVXjGpo3FzEYWM8UALrMeNzpH7UBHH1oUFgFUHzfKahbhjrJ4npPtkVT7c5wVhLJdwi7e2vpcFXrqQdFqQfHA4SEHEMq4fVisZFw9QrVgLfTF3hq6RsfJy6SySRyLsJaCWdLsAL7bPS3fcX6D2Tmobge7jWSURg26HjA1s2HsvfxL7jrxTPyb9Sr2Y9Dg2vHy8ZrJEqnuEHo5Sa8ssiw3V8HNYD8i4nDVErxAMud4DxJavutpyT3FFazuAM2ipkMfzvsdWhtBYYfQjFjgfs3T2nK7H9kQMEJrjVy7UzK5SjXLb16wX7a67w3vRMpJTV2jTnyM9vc6nF8VsmsjyBtV8ps6RJURdsaeBDmLGUvPvDf3uznsmRyU3JCRpqZ4zeuviXC6E1g7GxN6vFAudwZKrcXDCMxZdRT3h5DZve2wMCzhXwZaniq1imHQNTgi6eKdpcQTiYqtWQEUA56r4tEmurk4qy9rXLdN6u2UwDbutBcf94dTNMsfxkrFcMQ9ysVc97iN8rfi34T6Q39W9RudrajPgToRgz9zTGVE3FLehY43oXEzf5YBY9szQw1BQHSjwf8TBHThStU2KBP9ke3gv9V8vCGMLegUWXsqxPhNXbFd8f1wj9pAAt6kvfpUUvC2eX6yceiRbJ6vE5WgoqZjLxGbNrMJQEub2nb7yq4CJ5U1itFWQv4WxauTZRSKKKcbfzzRhvxE475xFwppY5RZ7hCXWjxUihb79Dw1gt1hXUxN3HCG5KVyQSZpzTq5f5xkAsRxbFwcbUeZ8KhU5eDc3rhTEh53eBAxP46eqogN89Ceto8xTurAxgcYrtSifctd3iLNiVEp1Hnc2igDQwN2S2ymGm4WJbnnse3W7oQehPDAo3yppLe3Qjh5JEoKEKyU58ypcPYwkNacyjhNn2Q28rPcAD8ssASoHDCq7qfKbSeA6LKUJNFFnVskGbDrgfu24u4533JFa9bMWgdL9QpUNPbbrYVKro";

    const KEY_LENGTH: usize = 8;
    const VALUE_LENGTH: usize = 32;
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
        let ergo_state_context = force_any_val::<ErgoStateContext>();
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
        let ergo_state_context = force_any_val::<ErgoStateContext>();
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        println!("{:?}", res);
        assert!(res.is_ok());
    }

    fn get_wallet() -> Wallet {
        const SEED_PHRASE: &str = "gather gather gather gather gather gather gather gather gather gather gather gather gather gather gather";
        Wallet::from_mnemonic(SEED_PHRASE, "").expect("Invalid seed")
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

            verify_sig_aggr_ergoscript_with_sigma_rust(
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

        let num_participants = 128;
        let md = blake2b256_hash(b"foo");
        for num_byzantine in num_byzantine_nodes {
            let SignatureAggregationElements {
                aggregate_commitment,
                aggregate_response,
                exclusion_set,
                committee,
                threshold,
            } = simulate_signature_aggregation_with_predefined_digest(num_participants, num_byzantine, md);
            let exclusion_set: Vec<_> = exclusion_set
                .into_iter()
                .map(|(ix, pair)| (ix, pair.map(|(c, s)| (c, k256::schnorr::Signature::from(s)))))
                .collect();
            verify_sig_aggr_ergoscript_with_sigma_rust(
                committee,
                (num_participants * threshold.num / threshold.denom) as i32,
                aggregate_commitment,
                aggregate_response,
                exclusion_set,
                md,
            );
        }
    }

    #[test]
    fn verify_vault_contract_sigma_rust() {
        let num_byzantine_nodes = vec![34];

        let num_participants = 128;
        let md = blake2b256_hash(b"foo");
        for num_byzantine in num_byzantine_nodes {
            let SignatureAggregationElements {
                aggregate_commitment,
                aggregate_response,
                exclusion_set,
                committee,
                threshold,
            } = simulate_signature_aggregation_with_predefined_digest(num_participants, num_byzantine, md);
            let exclusion_set: Vec<_> = exclusion_set
                .into_iter()
                .map(|(ix, pair)| (ix, pair.map(|(c, s)| (c, k256::schnorr::Signature::from(s)))))
                .collect();
            verify_vault_contract_ergoscript_with_sigma_rust(
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

        let md = blake2b256_hash(b"foo");
        let num_participants = 512;
        for num_byzantine in num_byzantine_nodes {
            let SignatureAggregationElements {
                aggregate_commitment,
                aggregate_response,
                exclusion_set,
                committee,
                threshold,
            } = simulate_signature_aggregation_with_predefined_digest(num_participants, num_byzantine, md);
            let exclusion_set: Vec<_> = exclusion_set
                .into_iter()
                .map(|(ix, pair)| (ix, pair.map(|(c, s)| (c, k256::schnorr::Signature::from(s)))))
                .collect();
            verify_sig_aggr_ergoscript_with_sigmastate(
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

    async fn verify_sig_aggr_ergoscript_with_sigmastate(
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
            contract: SIGNATURE_AGGREGATION_SCRIPT_BYTES.to_string(),
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

    #[tokio::test]
    async fn verify_vault_ergoscript_sigmastate() {
        let num_byzantine_nodes = vec![140];

        let num_participants = 1024;
        for num_byzantine in num_byzantine_nodes {
            let SignatureAggregationWithNotarizationElements {
                aggregate_commitment,
                aggregate_response,
                exclusion_set,
                committee,
                threshold,
                starting_avl_tree,
                avl_operations,
                proof,
                resulting_digest,
                terminal_cells,
            } = simulate_signature_aggregation_notarized_proofs(num_participants, num_byzantine);
            let exclusion_set: Vec<_> = exclusion_set
                .into_iter()
                .map(|(ix, pair)| (ix, pair.map(|(c, s)| (c, k256::schnorr::Signature::from(s)))))
                .collect();
            verify_vault_ergoscript_with_sigmastate(
                committee,
                (num_participants * threshold.num / threshold.denom) as i32,
                aggregate_commitment,
                aggregate_response,
                exclusion_set,
                starting_avl_tree,
                avl_operations,
                proof,
                resulting_digest,
                terminal_cells,
            )
            .await;
        }
    }

    async fn verify_vault_ergoscript_with_sigmastate(
        committee: Vec<PublicKey>,
        threshold: i32,
        aggregate_commitment: AggregateCommitment,
        aggregate_response: Scalar,
        exclusion_set: Vec<(usize, Option<(Commitment, Signature)>)>,
        starting_avl_tree: AvlTreeData,
        avl_operations: Vec<KeyValue>,
        proof: Vec<u8>,
        resulting_digest: Vec<u8>,
        terminal_cells: Vec<ErgoTermCell>,
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

        let md = blake2b256_hash(&resulting_digest);
        let exclusion_set_data = serialize_exclusion_set(exclusion_set, md.as_ref());
        let aggregate_response: Constant = (
            Constant::from(aggregate_response_bytes),
            Constant::from(first_len),
        )
            .into();

        let signature_input = SignatureValidationInput {
            contract: VAULT_CONTRACT_SCRIPT_BYTES.to_string(),
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

        let operations_lit: Vec<_> = avl_operations
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
            items: operations_lit,
        });
        let operations_const = Constant {
            tpe: operations_tpe,
            v: operations_lit,
        };

        let proof = Constant::from(proof);
        let avl_const = Constant::from(starting_avl_tree);
        let input = VaultValidationInput {
            signature_input,
            terminal_cells: Constant::from(ErgoTermCells(terminal_cells))
                .base16_str()
                .unwrap(),
            starting_avl_tree: avl_const.base16_str().unwrap(),
            avl_operations: operations_const.base16_str().unwrap(),
            avl_proof: proof.base16_str().unwrap(),
        };

        let raw = reqwest::Client::new()
            .put("http://localhost:8080/validateVault")
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
        let num_participants = 115;
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
        let committee = individual_keys.iter().map(|(_, pk, _, _)| pk);
        create_committee_input_box(
            committee,
            ergo_tree,
            Some((9, blake2b256_hash(b"blah").as_ref().to_vec())),
        );
    }

    fn simulate_signature_aggregation_with_predefined_digest(
        num_participants: usize,
        num_byzantine_nodes: usize,
        md: Blake2bDigest256,
    ) -> SignatureAggregationElements {
        let mut rng = OsRng;
        let mut byz_indexes = vec![];
        loop {
            let rng = rng.gen_range(0usize..num_participants);
            if !byz_indexes.contains(&rng) {
                byz_indexes.push(rng);
            }
            if byz_indexes.len() == num_byzantine_nodes {
                break;
            }
        }
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
        SignatureAggregationElements {
            aggregate_commitment,
            aggregate_response,
            exclusion_set,
            committee,
            threshold,
        }
    }

    fn simulate_signature_aggregation_notarized_proofs(
        num_participants: usize,
        num_byzantine_nodes: usize,
    ) -> SignatureAggregationWithNotarizationElements {
        let mut rng = OsRng;
        let mut byz_indexes = vec![];
        loop {
            let rng = rng.gen_range(0usize..num_participants);
            if !byz_indexes.contains(&rng) {
                byz_indexes.push(rng);
            }
            if byz_indexes.len() == num_byzantine_nodes {
                break;
            }
        }
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
        let mut total_num_tokens = 0;
        let max_tokens_per_box = 122;

        let terminal_cells: Vec<_> = (0..100)
            .map(|_| {
                let address = generate_address();
                let ergs = BoxValue::try_from(rng.gen_range(1_u64..=9000000000)).unwrap();
                let contains_tokens = rng.gen_bool(0.5);
                let tokens = if contains_tokens {
                    let num_tokens = rng.gen_range(0_usize..=10);
                    if total_num_tokens + num_tokens <= max_tokens_per_box {
                        total_num_tokens += num_tokens;
                        (0..num_tokens).map(|_| gen_random_token()).collect()
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                };
                ErgoTermCell {
                    ergs,
                    address,
                    tokens,
                }
            })
            .collect();

        println!("{} tokens generated", total_num_tokens);

        let empty_tree = AVLTree::new(dummy_resolver, KEY_LENGTH, Some(VALUE_LENGTH));
        let mut prover = BatchAVLProver::new(empty_tree.clone(), true);
        let initial_digest = prover.digest().unwrap().to_vec();

        let mut avl_operations = vec![];
        for (i, cell) in terminal_cells.iter().enumerate() {
            let value = Bytes::copy_from_slice(blake2b256_hash(&cell.to_bytes()).as_ref());
            let key_bytes = ((i + 1) as i64).to_be_bytes();
            let key = Bytes::copy_from_slice(&key_bytes);
            let kv = KeyValue { key, value };
            let insert = Operation::Insert(kv.clone());
            prover.perform_one_operation(&insert).unwrap();
            avl_operations.push(kv);
        }

        let proof = prover.generate_proof().to_vec();
        let resulting_digest = prover.digest().unwrap().to_vec();
        let avl_tree_data = AvlTreeData {
            digest: Digest::<33>::try_from(initial_digest).unwrap(),
            tree_flags: AvlTreeFlags::new(true, false, false),
            key_length: KEY_LENGTH as u32,
            value_length_opt: Some(Box::new(VALUE_LENGTH as u32)),
        };

        let md = blake2b256_hash(&resulting_digest);

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
        SignatureAggregationWithNotarizationElements {
            aggregate_commitment,
            aggregate_response,
            exclusion_set,
            committee,
            threshold,
            starting_avl_tree: avl_tree_data,
            avl_operations,
            proof,
            resulting_digest,
            terminal_cells,
        }
    }

    struct SignatureAggregationElements {
        aggregate_commitment: AggregateCommitment,
        aggregate_response: Scalar,
        exclusion_set: Vec<(usize, Option<(Commitment, spectrum_sigma::Signature)>)>,
        committee: Vec<PublicKey>,
        threshold: Threshold,
    }

    struct SignatureAggregationWithNotarizationElements {
        aggregate_commitment: AggregateCommitment,
        aggregate_response: Scalar,
        exclusion_set: Vec<(usize, Option<(Commitment, spectrum_sigma::Signature)>)>,
        committee: Vec<PublicKey>,
        threshold: Threshold,
        starting_avl_tree: AvlTreeData,
        avl_operations: Vec<KeyValue>,
        proof: Vec<u8>,
        resulting_digest: Vec<u8>,
        terminal_cells: Vec<ErgoTermCell>,
    }

    fn verify_sig_aggr_ergoscript_with_sigma_rust(
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
            .parse_address_from_str(SIGNATURE_AGGREGATION_SCRIPT_BYTES)
            .unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();

        //let mut registers = HashMap::new();

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

        let mut values = IndexMap::new();
        values.insert(0, exclusion_set_data);
        values.insert(1, aggregate_response);
        values.insert(2, serialized_aggregate_commitment);
        values.insert(3, Constant::from(md.as_ref().to_vec()));
        values.insert(4, threshold.into());
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
        let outputs = TxIoVec::from_vec(vec![miner_output]).unwrap();
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values });

        // The first committee box can hold 115 public keys together with other data necessary to
        // verify signatures.
        const NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX: usize = 115;

        // We've determined empirically that we can fit at most 118 public keys into a single box.
        const MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX: usize = 118;

        let vault_sk = ergo_lib::wallet::secret_key::SecretKey::random_dlog();
        let ergo_tree = vault_sk.get_address_from_public_image().script().unwrap();
        let num_data_inputs = committee.len() / MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX + 1;

        let mut data_boxes = vec![create_committee_input_box(
            committee.iter().take(NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX),
            ergo_tree.clone(),
            Some((num_data_inputs as i16, committee_bytes)),
        )];

        let chunks = committee
            .iter()
            .skip(NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX)
            .chunks(MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX);
        let remaining_data_boxes = chunks
            .into_iter()
            .map(|chunk| create_committee_input_box(chunk, ergo_tree.clone(), None));

        data_boxes.extend(remaining_data_boxes);

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
        let ergo_state_context = force_any_val::<ErgoStateContext>();
        let now = Instant::now();
        println!("Signing TX...");
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        if res.is_err() {
            panic!("{:?}", res);
        }
        println!("Time to validate and sign: {} ms", now.elapsed().as_millis());
    }

    fn verify_vault_contract_ergoscript_with_sigma_rust(
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
            .parse_address_from_str(VAULT_CONTRACT_SCRIPT_BYTES)
            .unwrap();
        let ergo_tree = address.script().unwrap();
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();

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

        let mut values = IndexMap::new();
        values.insert(0, exclusion_set_data);
        values.insert(1, aggregate_response);
        values.insert(2, serialized_aggregate_commitment);
        values.insert(3, Constant::from(md.as_ref().to_vec()));
        values.insert(4, threshold.into());

        let token_id = TokenId::from(ergo_lib::ergo_chain_types::Digest32::zero());
        let amount = TokenAmount::try_from(100_u64).unwrap();
        let token = Token { token_id, amount };

        let term_cell = ErgoTermCell {
            ergs: BoxValue::try_from(3000000_u64).unwrap(),
            address,
            tokens: vec![], //token.clone()],
        };
        let output_0 = ErgoBoxCandidate {
            value: term_cell.ergs,
            ergo_tree: term_cell.address.script().unwrap(),
            tokens: None, //Some(BoxTokens::from_vec(vec![token]).unwrap()),
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: 900001,
        };

        values.insert(5, ErgoTermCells(vec![term_cell]).into());

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
        let outputs = TxIoVec::from_vec(vec![output_0, miner_output]).unwrap();
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values });

        // The first committee box can hold 115 public keys together with other data necessary to
        // verify signatures.
        const NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX: usize = 115;

        // We've determined empirically that we can fit at most 118 public keys into a single box.
        const MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX: usize = 118;

        let vault_sk = ergo_lib::wallet::secret_key::SecretKey::random_dlog();
        let ergo_tree = vault_sk.get_address_from_public_image().script().unwrap();
        let num_data_inputs = committee.len() / MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX + 1;

        let mut data_boxes = vec![create_committee_input_box(
            committee.iter().take(NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX),
            ergo_tree.clone(),
            Some((num_data_inputs as i16, committee_bytes)),
        )];

        let chunks = committee
            .iter()
            .skip(NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX)
            .chunks(MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX);
        let remaining_data_boxes = chunks
            .into_iter()
            .map(|chunk| create_committee_input_box(chunk, ergo_tree.clone(), None));

        data_boxes.extend(remaining_data_boxes);

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
        let ergo_state_context = force_any_val::<ErgoStateContext>();
        let now = Instant::now();
        println!("Signing TX...");
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        if res.is_err() {
            panic!("{:?}", res);
        }
        println!("Time to validate and sign: {} ms", now.elapsed().as_millis());
    }
    fn create_committee_input_box<'a>(
        committee_members: impl Iterator<Item = &'a PublicKey>,
        ergo_tree: ErgoTree,
        first_box_register_data: Option<(i16, Vec<u8>)>,
    ) -> ErgoBox {
        let committee_lit = Literal::from(
            committee_members
                .map(|p| EcPoint::from(k256::PublicKey::from(p.clone()).to_projective()))
                .collect::<Vec<_>>(),
        );

        let serialized_committee = Constant {
            tpe: SType::SColl(Box::new(SType::SGroupElement)),
            v: committee_lit,
        };

        let mut registers = HashMap::new();
        registers.insert(NonMandatoryRegisterId::R4, serialized_committee);
        if let Some((num_boxes, committee_hash)) = first_box_register_data {
            registers.insert(NonMandatoryRegisterId::R5, num_boxes.into());
            registers.insert(NonMandatoryRegisterId::R6, Constant::from(generator()));
            registers.insert(
                NonMandatoryRegisterId::R7,
                Constant::from(EcPoint::from(ProjectivePoint::IDENTITY)),
            );
            registers.insert(NonMandatoryRegisterId::R8, Constant::from(committee_hash));
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

    #[derive(Serialize)]
    struct VaultValidationInput {
        #[serde(rename = "signatureInput")]
        signature_input: SignatureValidationInput,
        #[serde(rename = "terminalCells")]
        terminal_cells: String,
        #[serde(rename = "startingAvlTree")]
        starting_avl_tree: String,
        #[serde(rename = "avlOperations")]
        avl_operations: String,
        #[serde(rename = "avlProof")]
        avl_proof: String,
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

    fn gen_random_token() -> Token {
        let mut token = force_any_val::<Token>();
        let mut digest = ergo_lib::ergo_chain_types::Digest32::zero();

        let mut rng = rand::thread_rng();
        rng.fill(&mut digest.0);
        token.token_id = TokenId::from(digest);
        token
    }

    fn generate_address() -> Address {
        let mut rng = OsRng;
        let sk = SecretKey::random(&mut rng);
        let pk = PublicKey::from(sk.public_key());
        let proj = k256::PublicKey::from(pk.clone()).to_projective();
        Address::P2Pk(
            ergo_lib::ergotree_ir::sigma_protocol::sigma_boolean::ProveDlog::from(EcPoint::from(proj)),
        )
    }
}
