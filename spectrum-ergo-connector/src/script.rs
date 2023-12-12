use std::{collections::HashMap, hash::Hash, iter::repeat};

use blake2::Blake2b;
use bytes::Bytes;
use derive_more::From;
use elliptic_curve::{
    consts::U32,
    ops::{LinearCombination, Reduce},
};
use ergo_lib::{
    ergo_chain_types::{Digest, Digest32 as ELDigest32, DigestNError, EcPoint},
    ergotree_ir::{
        bigint256::BigInt256,
        chain::{
            address::{Address, AddressEncoder, NetworkPrefix},
            ergo_box::{
                box_value::{BoxValue, BoxValueError},
                BoxId, ErgoBox,
            },
            token::{Token, TokenAmount, TokenAmountError, TokenId},
        },
        ergo_tree::ErgoTree,
        mir::{
            avl_tree_data::{AvlTreeData, AvlTreeFlags},
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
use k256::{FieldElement, NonZeroScalar, ProjectivePoint, Scalar, SecretKey, U256};
use lazy_static::lazy_static;
use num_bigint::{BigUint, Sign, ToBigUint};
use rand::{rngs::OsRng, Rng};
use scorex_crypto_avltree::{
    authenticated_tree_ops::AuthenticatedTreeOps,
    batch_avl_prover::BatchAVLProver,
    batch_node::{AVLTree, Node, NodeHeader},
    operation::{KeyValue, Operation},
};
use serde::{Deserialize, Serialize};
use sha2::Digest as OtherDigest;
use sha2::Sha256;
use spectrum_chain_connector::{InboundValue, NotarizedReport, ProtoTermCell};
use spectrum_crypto::{
    digest::{blake2b256_hash, Blake2bDigest256},
    pubkey::PublicKey,
};
use spectrum_handel::Threshold;
use spectrum_ledger::{
    cell::{AssetId, BoxDestination, CustomAsset, NativeCoin, Owner, PolicyId, SValue, TermCell},
    interop::ReportCertificate,
    transaction::TxId,
    ChainId, ERGO_CHAIN_ID,
};
use spectrum_move::SerializedValue;
use spectrum_sigma::{
    crypto::{
        aggregate_commitment, aggregate_pk, aggregate_response, challenge, exclusion_proof, individual_input,
        response, schnorr_commitment_pair, verify, verify_response,
    },
    sigma_aggregation::AggregateCertificate,
    AggregateCommitment, Commitment, Signature,
};

const VAULT_CONTRACT_SCRIPT_BYTES: &str = "9jeXrT5JjR8aUSjfdePh7uuooaC8zj7xEJuUFH5FBqJnkkkJkxiUmKjdgWNipwup5NpCFdLbMpDZHw3771FN62kLii5BvwAUGSmPoD5g2GgZnL7ScRDBzLc49647yEh7y9fvruaGF2aKP85RUAc48GbqqvvT6NZfCdr88jTWNdy6fPGHopeid5iYmM2CiY24XpA5Kt9FTQ6N4RQBmyDYQ9VnCp3JveGw9hCZtvN92GfRm3dqvLXMn9rrps4jbqfCzjFnN8jmBAf2p6Q8WES4fmmpkemVWp2ym5gEkm671ALULqEjuYSJ6AVvMV4q6Z9ksGLs4w8itxTFoDB83xPshp2DdjCkoxeSydq9DpAUcGiPo7z372VpxsKNSobd6UnDJqBBZg6wUEfYpxrDbNZ8iuSi64bx95AQ3T5gE2eYrGQxaZDHoyFs4bU5K4SUxeDhMZMG1RooLRBhHwLHKorJ4VkkUP6WgayG7CcXocnMQ8CuSrKV7vsMHhnDF3BQ7yxzxJh3ZgYpaYxTr2WHc4HKf7ctKoXCt13NNirX4NYCDgWkH5Pg2CkL2DmhBpyiCgZuHdTFUo22fUupmLqGqpA6jahAx8uL3NAS4dKHc3Doj1F6fvSWsGTykSZ3rdnjKSWsLvVwF34K3R8FqbtcfYZggkLDWySbdTCjEZRJATJmHYKjUHyjZ7gD9erBdVAg4HKRHaJnriGqqu4yAHdWTVepzTXuJRsw7XjkocsJ6YidofjTXerR3PWT43eLcLbmxboYttG2aK7WxyLFapq2JQL2P4U1hLUebCu7AhRZwCLieYA1MzHHM1NKXQ3LrCZ4pdFRLdGDvyVBznmhs22vGaWSaY743q2DZm3rZL6W2MSvxPd9d85eXHH3gqW7dHb1q7ZhARvov8RZ1DT19BGRLXggwXRspNTRXbWGpk38sRq4r5T4mjBB7ccMLFjAWr2RfZyNNnyFfqqzVnvDA3GVSQKLbE7LRbQ3wEDTrh5cCb7wGsn8XBmQc6xemkUBi1WFs19sbGNchwbCwL4u3qacWU76eV4iVtWE8381sGVD6eyxydBmeCMnwepAQkoJCAxcViPEnX5qTnjokyv1zwPo1ZDcwEbsLDRsy1k5gpykotuS7wk2EUCun4C2QFtVTnKXRLfEkXkmQRUFmCCASwLWGDQP9FukDVsVaNRxWiVnW3ouM2JyS1yy7Yr5bBLZXRKFm2cjyt3xkM4po6tu3khpwRkQNtLtH72Zsc8vxAcei4tN2ptAVKQUKiK2G7UuwLB64nF6zXPSJJDQVYvJiGanW3Hvwe96Xr7sQckEuYPFFJSDftmUyNkVxrCQGjULtww5WfYxSB78caij6xsYjuJK2LfexB7dGkWfqYjTpmc1vb3czy6yJ2iYAUGE37KxaLQjZtN6Rrgi4nRKJC5msRorLpueD2wfC7v2b3QgsExRQ6377AedojoowNF3TwwEaeHhtGNQmgH9h1uXcqutoSoeCZmEZ5iiNM1BSEF6Y2yfPdSFEYyoXzaf5fjF9Ws5Jus5EGgkv7yhL8L4rP24Uosq3diqJUrqi6Wub6LShSTmgfWPF2WppJmn5oMY5o4yt2PBFRePb2SD3XkXcY1RVqRiYPtQv7eBLvgQCgpyETAJYhaY4WQv29MXMxgPuLmBbJGsUBpDYCxV3Ze338D5fdJEbFDsqaAAzi1iiWVWTUxQwBuFro4cHHSfD11rrwXyEJzdEDLkYG4EdsrhmJcjaMd8xkt27GEDxST6kpBykEN5ok7KPvJE2e7PJXcaevqsnvYfZsXxLKAkTzrdXb3vetWzavbqbqngiHTR9kxUxts3jwuaKc1vHStDj2PLuWFYP1hFNkQXwBoRjM8j7WqYYtvtXejzGqg8jQDJfBEtpYs31ABtB7Y7g1z1Hju4uTbVCcCdEpQGDth9y9JJLwV8TRdGh8T7WJHUea4nQwSqXR6SLKTgWjrLFWkpXojBZmiKjsE5bbyQLvsAAwHgJZRqwR4SN7bGXj1VWpwvcuFv8FFWvcEeK6ZvjfpCGPCJMAdcHmRVwf3bdEQBeD1zseNmfbsk6nPSecAXnqY7asUor7vrxjrvTLikQVVaJKEEWbAwDpP2VztyhsTxg4EeGwGTxYzwH8WjGcceAZ";

lazy_static! {
    pub static ref VAULT_CONTRACT: ErgoTree = AddressEncoder::new(NetworkPrefix::Mainnet)
        .parse_address_from_str(VAULT_CONTRACT_SCRIPT_BYTES)
        .unwrap()
        .script()
        .unwrap();
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ErgoTermCell(pub ErgoCell);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ErgoInboundCell(pub ErgoCell);

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(from = "ErgoCellProto", into = "ErgoCellProto")]
pub struct ErgoCell {
    pub ergs: BoxValue,
    pub address: Address,
    pub tokens: Vec<Token>,
}

impl From<&ErgoCell> for SValue {
    fn from(value: &ErgoCell) -> Self {
        let mut assets = HashMap::new();
        let asset_map: HashMap<AssetId, CustomAsset> = value
            .tokens
            .iter()
            .map(|t| {
                let asset_id =
                    AssetId::from(Blake2bDigest256::try_from(<Vec<u8>>::from(t.token_id)).unwrap());
                let custom_asset = CustomAsset::from(*t.amount.as_u64());
                (asset_id, custom_asset)
            })
            .collect();
        assets.insert(PolicyId::from(Blake2bDigest256::zero()), asset_map);
        SValue {
            native: NativeCoin::from(*value.ergs.as_u64()),
            assets,
        }
    }
}

impl From<ErgoInboundCell> for InboundValue {
    fn from(ErgoInboundCell(value): ErgoInboundCell) -> Self {
        let s_value = SValue::from(&value);
        let owner = match value.address {
            Address::P2Pk(pdl) => {
                let affine_point = ProjectivePoint::from(pdl.h.as_ref().clone()).to_affine();
                let pk = k256::PublicKey::from_affine(affine_point).unwrap();
                Owner::ProveDlog(pk)
            }

            Address::P2S(_) => {
                unimplemented!()
            }
            Address::P2SH(_) => {
                unimplemented!()
            }
        };

        Self {
            value: s_value,
            owner,
        }
    }
}

impl From<&ErgoBox> for ErgoCell {
    fn from(value: &ErgoBox) -> Self {
        let address = Address::recreate_from_ergo_tree(&value.ergo_tree).unwrap();
        let tokens = value
            .tokens
            .clone()
            .map(|tokens| tokens.as_vec().clone())
            .unwrap_or_default();
        let ergs = value.value;
        Self {
            ergs,
            address,
            tokens,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ErgoCellProto {
    pub ergs: BoxValue,
    pub address_base58_string: String,
    pub tokens: Vec<Token>,
}

impl From<ErgoCellProto> for ErgoCell {
    fn from(value: ErgoCellProto) -> Self {
        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder
            .parse_address_from_str(&value.address_base58_string)
            .unwrap();
        Self {
            ergs: value.ergs,
            address,
            tokens: value.tokens,
        }
    }
}

impl From<ErgoCell> for ErgoCellProto {
    fn from(value: ErgoCell) -> Self {
        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        Self {
            ergs: value.ergs,
            address_base58_string: encoder.address_to_str(&value.address),
            tokens: value.tokens,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(from = "ExtraErgoDataProto", into = "ExtraErgoDataProto")]
pub struct ExtraErgoData {
    pub starting_avl_tree: AvlTreeData,
    pub proof: Vec<u8>,
    pub max_miner_fee: i64,
    pub threshold: Threshold,
    pub vault_utxos: Vec<BoxId>,
}

#[derive(Serialize, Deserialize)]
pub struct ExtraErgoDataProto {
    /// Base16-encoded byte representation of the starting AVL tree.
    starting_avl_tree: String,
    /// Base 16 encoded byte representation of the AVL tree proof.
    proof: String,
    max_miner_fee: i64,
    threshold: Threshold,
    vault_utxos: Vec<BoxId>,
}

impl From<ExtraErgoDataProto> for ExtraErgoData {
    fn from(value: ExtraErgoDataProto) -> Self {
        let avl_tree_bytes = base16::decode(&value.starting_avl_tree).unwrap();
        let starting_avl_tree = AvlTreeData::sigma_parse_bytes(&avl_tree_bytes).unwrap();
        let proof_bytes = base16::decode(&value.proof).unwrap();
        Self {
            starting_avl_tree,
            proof: proof_bytes,
            max_miner_fee: value.max_miner_fee,
            threshold: value.threshold,
            vault_utxos: value.vault_utxos,
        }
    }
}

impl From<ExtraErgoData> for ExtraErgoDataProto {
    fn from(value: ExtraErgoData) -> Self {
        let starting_avl_tree_bytes = value.starting_avl_tree.sigma_serialize_bytes().unwrap();
        let starting_avl_tree = base16::encode_lower(&starting_avl_tree_bytes);
        let proof = base16::encode_lower(&value.proof);
        Self {
            starting_avl_tree,
            proof,
            max_miner_fee: value.max_miner_fee,
            threshold: value.threshold,
            vault_utxos: value.vault_utxos,
        }
    }
}

impl ErgoTermCell {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res = vec![];
        res.extend_from_slice(&self.0.ergs.as_i64().to_be_bytes());
        let prop_bytes = self.0.address.script().unwrap().sigma_serialize_bytes().unwrap();
        res.extend(prop_bytes);
        for Token { token_id, amount } in &self.0.tokens {
            let digest = ergo_lib::ergo_chain_types::Digest32::from(*token_id);
            res.extend(digest.0);
            res.extend(&(*amount.as_u64()).to_be_bytes());
        }
        res
    }
}

impl Hash for ErgoTermCell {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.ergs.as_i64().hash(state);
        let prop_bytes = self.0.address.script().unwrap().sigma_serialize_bytes().unwrap();
        prop_bytes.hash(state);
        for Token { token_id, amount } in &self.0.tokens {
            let digest = ergo_lib::ergo_chain_types::Digest32::from(*token_id);
            digest.0.hash(state);
            (*amount.as_u64() as i64).hash(state);
        }
    }
}

pub struct SignatureAggregationWithNotarizationElements {
    pub aggregate_commitment: AggregateCommitment,
    pub aggregate_response: Scalar,
    pub exclusion_set: Vec<(usize, Option<(Commitment, Signature)>)>,
    pub threshold: Threshold,
    pub starting_avl_tree: AvlTreeData,
    pub proof: Vec<u8>,
    pub resulting_digest: Vec<u8>,
    pub terminal_cells: Vec<ErgoTermCell>,
    pub max_miner_fee: i64,
}

impl From<NotarizedReport<ExtraErgoData>> for SignatureAggregationWithNotarizationElements {
    fn from(value: NotarizedReport<ExtraErgoData>) -> Self {
        let ReportCertificate::SchnorrK256(AggregateCertificate {
            message_digest,
            aggregate_commitment,
            aggregate_response,
            exclusion_set,
        }): ReportCertificate = value.certificate;
        let ExtraErgoData {
            starting_avl_tree,
            proof,
            max_miner_fee,
            threshold,
            ..
        } = value.additional_chain_data;

        let terminal_cells = value
            .value_to_export
            .into_iter()
            .map(|tc| ErgoTermCell::try_from(tc).unwrap())
            .collect();
        Self {
            aggregate_commitment,
            aggregate_response,
            exclusion_set,
            threshold,
            starting_avl_tree,
            proof,
            max_miner_fee,
            resulting_digest: value.authenticated_digest, //message_digest.as_ref().to_vec(),
            terminal_cells,
        }
    }
}

pub struct ErgoTermCells(pub Vec<ErgoTermCell>);

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

#[derive(Debug, From)]
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
            let ergs = BoxValue::try_from(u64::from(value.value.native))?;
            let address_bytes: Vec<u8> = value.dst.address.into();
            let address = Address::p2pk_from_pk_bytes(&address_bytes)?;
            let mut token_details = vec![];
            for (_, assets) in value.value.assets {
                for (id, a) in assets {
                    let digest = ELDigest32::try_from(Blake2bDigest256::from(id).as_ref())?;
                    let amount = TokenAmount::try_from(u64::from(a))?;
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

            Ok(ErgoTermCell(ErgoCell {
                ergs,
                address,
                tokens,
            }))
        } else {
            Err(ErgoTermCellError::WrongChainId)
        }
    }
}

impl From<ErgoTermCell> for TermCell {
    fn from(value: ErgoTermCell) -> Self {
        let s_value = SValue::from(&value.0);
        let dst = BoxDestination {
            target: ChainId::from(0),
            address: SerializedValue::from(value.0.address.content_bytes()),
            inputs: None,
        };

        Self {
            value: s_value,
            tx_id: TxId::from(Blake2bDigest256::random()), // TODO: set by spectrum-network?
            index: 0,
            dst,
        }
    }
}

impl From<ErgoTermCell> for ProtoTermCell {
    fn from(value: ErgoTermCell) -> Self {
        let s_value = SValue::from(&value.0);
        let dst = BoxDestination {
            target: ChainId::from(0),
            address: SerializedValue::from(value.0.address.content_bytes()),
            inputs: None,
        };
        Self { value: s_value, dst }
    }
}

impl TryFrom<ProtoTermCell> for ErgoTermCell {
    type Error = ErgoTermCellError;

    fn try_from(value: ProtoTermCell) -> Result<Self, Self::Error> {
        let ergs = BoxValue::try_from(u64::from(value.value.native))?;
        let address_bytes: Vec<u8> = value.dst.address.into();
        let address = Address::p2pk_from_pk_bytes(&address_bytes)?;
        let mut token_details = vec![];
        for (_, assets) in value.value.assets {
            for (id, a) in assets {
                let digest = ELDigest32::try_from(Blake2bDigest256::from(id).as_ref())?;
                let amount = TokenAmount::try_from(u64::from(a))?;
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

        Ok(ErgoTermCell(ErgoCell {
            ergs,
            address,
            tokens,
        }))
    }
}

impl From<ErgoTermCell> for Constant {
    fn from(cell: ErgoTermCell) -> Self {
        // The Constant is of the form (nanoErg, (propositionBytes, tokens)), with type
        //    (Long, (Coll[Byte], Coll[(Coll[Byte], Long)]))
        //
        let cell = cell.0;
        let nano_ergs: Constant = cell.ergs.into();
        let prop_bytes: Constant = cell
            .address
            .script()
            .unwrap()
            .sigma_serialize_bytes()
            .unwrap()
            .into();
        let elem_tpe = SType::STuple(STuple {
            items: TupleItems::from_vec(vec![SType::SColl(Box::new(SType::SByte)), SType::SLong]).unwrap(),
        });
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
        let tokens_tpe = SType::SColl(Box::new(SType::STuple(STuple {
            items: TupleItems::from_vec(vec![SType::SColl(Box::new(SType::SByte)), SType::SLong]).unwrap(),
        })));
        let tokens = Constant {
            tpe: tokens_tpe,
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

pub fn serialize_exclusion_set(
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
        let signature_bytes = k256::schnorr::Signature::from(signature).to_bytes();

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

pub fn scalar_to_biguint(scalar: Scalar) -> BigUint {
    scalar
        .to_bytes()
        .iter()
        .enumerate()
        .map(|(i, w)| w.to_biguint().unwrap() << ((31 - i) * 8))
        .sum()
}

pub fn dummy_resolver(digest: &scorex_crypto_avltree::operation::Digest32) -> Node {
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

pub fn estimate_tx_size_in_kb(
    num_withdrawals: usize,
    num_byzantine_nodes: usize,
    num_token_occurrences: usize,
) -> f32 {
    0.67 + 0.086 * (num_withdrawals as f32)
        + (num_byzantine_nodes as f32) * 0.165
        + (num_token_occurrences as f32) * 0.039
}

pub fn simulate_signature_aggregation_notarized_proofs(
    participant_secret_keys: Vec<SecretKey>,
    terminal_cells: Vec<ErgoTermCell>,
    num_byzantine_nodes: usize,
    threshold: Threshold,
    max_miner_fee: i64,
) -> SignatureAggregationWithNotarizationElements {
    let mut rng = OsRng;
    let mut byz_indexes = vec![];
    if num_byzantine_nodes > 0 {
        loop {
            let rng = rng.gen_range(0usize..participant_secret_keys.len());
            if !byz_indexes.contains(&rng) {
                byz_indexes.push(rng);
            }
            if byz_indexes.len() == num_byzantine_nodes {
                break;
            }
        }
    }
    let individual_keys = participant_secret_keys
        .into_iter()
        .map(|sk| {
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

    let empty_tree = AVLTree::new(dummy_resolver, KEY_LENGTH, Some(VALUE_LENGTH));
    let mut prover = BatchAVLProver::new(empty_tree.clone(), true);
    let initial_digest = prover.digest().unwrap().to_vec();

    for (i, cell) in terminal_cells.iter().enumerate() {
        let value = Bytes::copy_from_slice(blake2b256_hash(&cell.to_bytes()).as_ref());
        let key_bytes = ((i + 1) as i64).to_be_bytes();
        let key = Bytes::copy_from_slice(&key_bytes);
        let kv = KeyValue { key, value };
        let insert = Operation::Insert(kv.clone());
        prover.perform_one_operation(&insert).unwrap();
    }

    // Perform insertion for max_miner_fee
    {
        let key_bytes = ((terminal_cells.len() + 1) as i64).to_be_bytes();
        let key = Bytes::copy_from_slice(&key_bytes);
        let mut value_bytes = max_miner_fee.to_be_bytes().to_vec();
        // Need to pad to 32 bytes
        value_bytes.extend(repeat(0).take(24));
        let value = Bytes::copy_from_slice(&value_bytes);
        let kv = KeyValue { key, value };
        let insert = Operation::Insert(kv.clone());
        prover.perform_one_operation(&insert).unwrap();
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
        .map(|(i, (_, _, sk, commitment))| (*i, Some((commitment.clone(), exclusion_proof(sk.clone(), md)))))
        .collect::<Vec<_>>();
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
        threshold,
        starting_avl_tree: avl_tree_data,
        proof,
        resulting_digest,
        terminal_cells,
        max_miner_fee,
    }
}

const KEY_LENGTH: usize = 8;
const VALUE_LENGTH: usize = 32;
const MIN_KEY: [u8; KEY_LENGTH] = [0u8; KEY_LENGTH];
const MAX_KEY: [u8; KEY_LENGTH] = [0xFFu8; KEY_LENGTH];
#[cfg(test)]
pub mod tests {
    use bytes::Bytes;
    use elliptic_curve::group::GroupEncoding;
    use ergo_lib::ergo_chain_types::{ec_point::generator, Digest, EcPoint};
    use ergo_lib::ergotree_interpreter::sigma_protocol::prover::ContextExtension;
    use ergo_lib::ergotree_ir::chain::address::Address;
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
        schnorr::{signature::Signer, SigningKey},
        ProjectivePoint, SecretKey,
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
    use spectrum_crypto::{digest::blake2b256_hash, pubkey::PublicKey};
    use spectrum_handel::Threshold;
    use spectrum_sigma::{crypto::schnorr_commitment_pair, Commitment, Signature};
    use std::collections::HashMap;
    use std::time::Instant;

    use crate::script::{
        estimate_tx_size_in_kb, scalar_to_biguint, serialize_exclusion_set, ErgoCell, ErgoTermCell,
        ErgoTermCells, VAULT_CONTRACT, VAULT_CONTRACT_SCRIPT_BYTES,
    };

    use super::{
        dummy_resolver, simulate_signature_aggregation_notarized_proofs,
        SignatureAggregationWithNotarizationElements, KEY_LENGTH, MAX_KEY, MIN_KEY, VALUE_LENGTH,
    };

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
    fn verify_vault_contract_sigma_rust() {
        let mut rng = OsRng;
        let num_byzantine_nodes = vec![17];

        let num_participants = 64;
        let epoch_len = 720;
        let current_epoch = 3;
        let threshold = Threshold { num: 2, denom: 4 };
        let max_num_tokens = 122;
        let max_miner_fee = 1000000;
        for num_byzantine in num_byzantine_nodes {
            let mut total_num_tokens = 0;
            let terminal_cells: Vec<_> = (0..100)
                .map(|_| {
                    let address = generate_address();
                    let ergs = BoxValue::try_from(rng.gen_range(1_u64..=9000000000)).unwrap();
                    let contains_tokens = rng.gen_bool(0.5);
                    let tokens = if contains_tokens {
                        let num_tokens = rng.gen_range(0_usize..=10);
                        if total_num_tokens + num_tokens <= max_num_tokens {
                            total_num_tokens += num_tokens;
                            (0..num_tokens).map(|_| gen_random_token(10000)).collect()
                        } else {
                            vec![]
                        }
                    } else {
                        vec![]
                    };
                    ErgoTermCell(ErgoCell {
                        ergs,
                        address,
                        tokens,
                    })
                })
                .collect();
            let participant_secret_keys: Vec<_> = (0..num_participants)
                .map(|_| SecretKey::random(&mut rng))
                .collect();
            let public_keys = participant_secret_keys
                .iter()
                .map(|sk| PublicKey::from(sk.public_key()))
                .collect();
            let inputs = simulate_signature_aggregation_notarized_proofs(
                participant_secret_keys,
                terminal_cells,
                num_byzantine,
                threshold,
                max_miner_fee,
            );
            verify_vault_contract_ergoscript_with_sigma_rust(
                (inputs, public_keys),
                num_participants,
                epoch_len,
                current_epoch,
            );
        }
    }

    #[tokio::test]
    async fn verify_vault_ergoscript_sigmastate() {
        let mut rng = OsRng;
        let num_byzantine_nodes = vec![0]; //, 100, 150, 200, 250, 300, 340];

        let num_participants = 4;
        let epoch_len = 720;
        let current_epoch = 3;
        let threshold = Threshold { num: 2, denom: 4 };
        //let num_notarized_txs = 1;
        let max_num_tokens = 0;
        let num_byzantine = 0;
        let max_miner_fee = 1000000;
        for num_notarized_txs in vec![3] {
            let mut total_num_tokens = 0;
            let terminal_cells: Vec<_> = (0..num_notarized_txs)
                .map(|_| {
                    let address = generate_address();
                    let ergs = BoxValue::try_from(rng.gen_range(1_u64..=9000000000)).unwrap();
                    let contains_tokens = rng.gen_bool(0.5);
                    let tokens = if contains_tokens {
                        let num_tokens = rng.gen_range(0_usize..=10);
                        if total_num_tokens + num_tokens <= max_num_tokens {
                            total_num_tokens += num_tokens;
                            (0..num_tokens).map(|_| gen_random_token(10000)).collect()
                        } else {
                            vec![]
                        }
                    } else {
                        vec![]
                    };
                    ErgoTermCell(ErgoCell {
                        ergs,
                        address,
                        tokens,
                    })
                })
                .collect();
            let participant_secret_keys: Vec<_> = (0..num_participants)
                .map(|_| SecretKey::random(&mut rng))
                .collect();
            let public_keys = participant_secret_keys
                .iter()
                .map(|sk| PublicKey::from(sk.public_key()))
                .collect();
            //vec![10, 20, 30, 40, 50, 100] {
            let inputs = simulate_signature_aggregation_notarized_proofs(
                participant_secret_keys,
                terminal_cells,
                num_byzantine,
                threshold,
                max_miner_fee,
            );
            verify_vault_ergoscript_with_sigmastate(
                (inputs, public_keys),
                num_participants,
                epoch_len,
                current_epoch,
            )
            .await;
        }
    }

    async fn verify_vault_ergoscript_with_sigmastate(
        (inputs, committee): (SignatureAggregationWithNotarizationElements, Vec<PublicKey>),
        num_participants: usize,
        epoch_len: i32,
        current_epoch: i32,
    ) {
        let SignatureAggregationWithNotarizationElements {
            aggregate_commitment,
            aggregate_response,
            exclusion_set,
            threshold,
            starting_avl_tree,
            proof,
            resulting_digest,
            terminal_cells,
            max_miner_fee,
        } = inputs;
        let threshold = (num_participants * threshold.num / threshold.denom) as i32;
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
        // VERY IMPORTANT: Need this variable because we could add an extra byte to the encoding
        // for signed-representation.
        let first_len = aggregate_response_bytes.len() as i32;
        aggregate_response_bytes.extend(lower_256.to_signed_bytes_be());

        let md = blake2b256_hash(&resulting_digest);
        let num_byzantine_nodes = exclusion_set.len();
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

        let proof = Constant::from(proof);
        let avl_const = Constant::from(starting_avl_tree);
        let num_withdrawals = terminal_cells.len();
        let num_token_occurrences = terminal_cells.iter().fold(0, |acc, tc| tc.0.tokens.len() + acc);
        let input = VaultValidationInput {
            signature_input,
            terminal_cells: Constant::from(ErgoTermCells(terminal_cells))
                .base16_str()
                .unwrap(),
            starting_avl_tree: avl_const.base16_str().unwrap(),
            avl_proof: proof.base16_str().unwrap(),
            epoch_len,
            current_epoch,
        };

        println!("\n\n\n{}\n\n\n", serde_json::to_string_pretty(&input).unwrap());

        let raw = reqwest::Client::new()
            .put("http://localhost:8080/validateVault")
            .json(&input)
            .send()
            .await
            .unwrap();
        println!("{:?}", raw);
        let details = raw.json::<ValidationResponse>().await.unwrap();

        let actual_size = details.right.value.tx_size_in_kb;
        let estiamted_size =
            estimate_tx_size_in_kb(num_withdrawals, num_byzantine_nodes, 2 * num_token_occurrences);
        println!(
            "{} byzantine nodes, estimate tx size(kb): {}, actual size: {}, error: {}%",
            num_byzantine_nodes,
            estiamted_size,
            actual_size,
            (actual_size - estiamted_size) / actual_size * 100.0
        );
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
            Some(blake2b256_hash(b"blah").as_ref().to_vec()),
            vec![1, 1, 1, 1],
            900000,
            0,
        );
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
                Some((
                    Commitment::from(*signing_key.verifying_key()),
                    Signature::from(signature),
                )),
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

    #[test]
    fn serialize_keys() {
        // SecretKey
        let mut rng = OsRng;
        let mut pub_keys = vec![];
        for _ in 0..4 {
            let sk = SecretKey::random(&mut rng);
            let sk_enc = base16::encode_lower(sk.to_bytes().as_slice());
            let bytes = base16::decode(&sk_enc).unwrap();
            assert_eq!(bytes, sk.to_bytes().as_slice());

            // PublicKey
            let pk = sk.public_key();
            let bytes = pk.to_sec1_bytes().as_ref().to_vec();
            let pk_enc = base16::encode_lower(&bytes);
            println!("Secret key(base16): {}, public key: {}", sk_enc, pk_enc);

            let bytes = base16::decode(&pk_enc).unwrap();
            pub_keys.push(pk_enc);
            assert_eq!(pk, k256::PublicKey::from_sec1_bytes(&bytes).unwrap());
        }

        println!("{}", serde_yaml::to_string(&pub_keys).unwrap());
    }

    fn get_wallet() -> Wallet {
        const SEED_PHRASE: &str = "gather gather gather gather gather gather gather gather gather gather gather gather gather gather gather";
        Wallet::from_mnemonic(SEED_PHRASE, "").expect("Invalid seed")
    }

    fn verify_vault_contract_ergoscript_with_sigma_rust(
        (inputs, committee): (SignatureAggregationWithNotarizationElements, Vec<PublicKey>),
        num_participants: usize,
        epoch_len: i32,
        current_epoch: i32,
    ) {
        let SignatureAggregationWithNotarizationElements {
            aggregate_commitment,
            aggregate_response,
            exclusion_set,
            threshold,
            starting_avl_tree,
            proof,
            resulting_digest,
            terminal_cells,
            max_miner_fee,
        } = inputs;
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
        // VERY IMPORTANT: Need this variable because we could add an extra byte to the encoding
        // for signed-representation.
        let first_len = aggregate_response_bytes.len() as i32;
        aggregate_response_bytes.extend(lower_256.to_signed_bytes_be());

        let encoder = AddressEncoder::new(NetworkPrefix::Mainnet);
        let address = encoder
            .parse_address_from_str(VAULT_CONTRACT_SCRIPT_BYTES)
            .unwrap();
        let ergo_tree = address.script().unwrap();
        let change_for_miner = BoxValue::try_from(1000000_u64).unwrap();

        let md = blake2b256_hash(&resulting_digest);
        let exclusion_set_data = serialize_exclusion_set(exclusion_set, md.as_ref());
        let aggregate_response: Constant = (
            Constant::from(aggregate_response_bytes),
            Constant::from(first_len),
        )
            .into();
        let threshold = (num_participants * threshold.num / threshold.denom) as i32;
        let proof = Constant::from(proof);
        let avl_const = Constant::from(starting_avl_tree);
        let num_withdrawals = terminal_cells.len();
        let num_token_occurrences = terminal_cells.iter().fold(0, |acc, tc| tc.0.tokens.len() + acc);

        let current_height = 900000_i32;

        // Create outboxes for terminal cells
        let mut term_cell_outputs: Vec<_> = terminal_cells
            .iter()
            .map(
                |ErgoTermCell(ErgoCell {
                     ergs,
                     address,
                     tokens,
                 })| {
                    let tokens = if tokens.is_empty() {
                        None
                    } else {
                        Some(BoxTokens::from_vec(tokens.clone()).unwrap())
                    };
                    ErgoBoxCandidate {
                        value: *ergs,
                        ergo_tree: address.script().unwrap(),
                        tokens,
                        additional_registers: NonMandatoryRegisters::empty(),
                        creation_height: current_height as u32,
                    }
                },
            )
            .collect();

        let initial_vault_balance = 2000000000_i64;
        let ergs_to_distribute: i64 = terminal_cells.iter().map(|t| t.0.ergs.as_i64()).sum();

        let mut values = IndexMap::new();
        values.insert(0, exclusion_set_data);
        values.insert(5, aggregate_response);
        values.insert(1, serialized_aggregate_commitment);
        values.insert(6, Constant::from(md.as_ref().to_vec()));
        values.insert(9, threshold.into());
        values.insert(2, ErgoTermCells(terminal_cells).into());
        values.insert(7, avl_const);
        values.insert(3, proof);
        values.insert(8, change_for_miner.as_i64().into());

        let input_box = ErgoBox::new(
            BoxValue::try_from(initial_vault_balance + ergs_to_distribute).unwrap(),
            ergo_tree,
            None,
            NonMandatoryRegisters::empty(),
            (current_height as u32) - 10,
            TxId::zero(),
            0,
        )
        .unwrap();

        let vault_output_box = ErgoBoxCandidate {
            value: BoxValue::try_from(initial_vault_balance - change_for_miner.as_i64()).unwrap(),
            ergo_tree: VAULT_CONTRACT.clone(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: current_height as u32,
        };

        let miner_output = ErgoBoxCandidate {
            value: change_for_miner,
            ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: current_height as u32,
        };
        term_cell_outputs.push(vault_output_box);
        term_cell_outputs.push(miner_output);
        let outputs = TxIoVec::from_vec(term_cell_outputs).unwrap();
        let unsigned_input = UnsignedInput::new(input_box.box_id(), ContextExtension { values });

        // The first committee box can hold 115 public keys together with other data necessary to
        // verify signatures.
        const NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX: usize = 115;

        // We've determined empirically that we can fit at most 118 public keys into a single box.
        const MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX: usize = 118;

        let vault_sk = ergo_lib::wallet::secret_key::SecretKey::random_dlog();
        let ergo_tree = vault_sk.get_address_from_public_image().script().unwrap();
        let num_data_inputs = committee.len() / MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX + 1;
        let vault_start: i32 = current_height - epoch_len * current_epoch + 1;
        let vault_parameters = vec![num_data_inputs as i32, current_epoch, epoch_len, vault_start];

        let mut data_boxes = vec![create_committee_input_box(
            committee.iter().take(NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX),
            ergo_tree.clone(),
            Some(committee_bytes),
            vault_parameters.clone(),
            current_height as u32,
            0,
        )];

        let chunks = committee
            .iter()
            .skip(NUM_COMMITTEE_ELEMENTS_IN_FIRST_BOX)
            .chunks(MAX_NUM_COMMITTEE_ELEMENTS_PER_BOX);
        let remaining_data_boxes = chunks.into_iter().enumerate().map(|(ix, chunk)| {
            create_committee_input_box(
                chunk,
                ergo_tree.clone(),
                None,
                vault_parameters.clone(),
                current_height as u32,
                (ix + 1) as i32,
            )
        });

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
        let mut ergo_state_context = force_any_val::<ErgoStateContext>();
        // Set height in ergo context
        ergo_state_context.pre_header.height = current_height as u32;
        for c in &mut ergo_state_context.headers {
            c.height = current_height as u32;
        }
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
        first_box_committee_hash: Option<Vec<u8>>,
        vault_parameters: Vec<i32>,
        current_height: u32,
        ix: i32,
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
        registers.insert(NonMandatoryRegisterId::R5, ix.into());
        if let Some(committee_hash) = first_box_committee_hash {
            registers.insert(NonMandatoryRegisterId::R6, vault_parameters.into());
            registers.insert(NonMandatoryRegisterId::R7, Constant::from(generator()));
            registers.insert(
                NonMandatoryRegisterId::R8,
                Constant::from(EcPoint::from(ProjectivePoint::IDENTITY)),
            );
            registers.insert(NonMandatoryRegisterId::R9, Constant::from(committee_hash));
        }
        let erg_value = BoxValue::try_from(1000000_u64).unwrap();
        let input_box = ErgoBox::new(
            erg_value,
            ergo_tree,
            None,
            NonMandatoryRegisters::new(registers).unwrap(),
            current_height - 10,
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
        #[serde(rename = "avlProof")]
        avl_proof: String,
        #[serde(rename = "epochLength")]
        epoch_len: i32,
        #[serde(rename = "currentEpoch")]
        current_epoch: i32,
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
        #[serde(rename = "txSizeInKb")]
        tx_size_in_kb: f32,
    }

    impl From<ValidationResponse> for ValidationDetails {
        fn from(value: ValidationResponse) -> Self {
            value.right.value
        }
    }

    pub fn gen_random_token(min_quantity: usize) -> Token {
        let mut token = force_any_val::<Token>();

        let mut digest = ergo_lib::ergo_chain_types::Digest32::zero();
        let mut rng = rand::thread_rng();
        rng.fill(&mut digest.0);

        let amount = TokenAmount::try_from(rng.gen_range((min_quantity as i64)..=i64::MAX) as u64).unwrap();

        token.token_id = TokenId::from(digest);
        token.amount = amount;
        token
    }

    pub fn gen_tx_id() -> TxId {
        let mut digest = ergo_lib::ergo_chain_types::Digest32::zero();

        let mut rng = rand::thread_rng();
        rng.fill(&mut digest.0);
        TxId::from(digest)
    }

    pub fn generate_address() -> Address {
        let mut rng = OsRng;
        let sk = SecretKey::random(&mut rng);
        let pk = PublicKey::from(sk.public_key());
        let proj = k256::PublicKey::from(pk.clone()).to_projective();
        Address::P2Pk(
            ergo_lib::ergotree_ir::sigma_protocol::sigma_boolean::ProveDlog::from(EcPoint::from(proj)),
        )
    }
}
