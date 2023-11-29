use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use ergo_lib::{
    ergo_chain_types::Digest32,
    ergotree_ir::{
        chain::{
            address::Address,
            ergo_box::{BoxId, ErgoBox, NonMandatoryRegisterId, RegisterValue},
            token::{Token, TokenAmount, TokenAmountError, TokenId},
        },
        mir::{
            constant::Literal,
            value::{CollKind, NativeColl},
        },
    },
};
use nonempty::NonEmpty;
use num_bigint::BigUint;
use rocksdb::{Direction, IteratorMode, ReadOptions};
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::{Kilobytes, NotarizedReportConstraints, ProtoTermCell};
use spectrum_crypto::digest::Blake2bDigest256;
use spectrum_ledger::cell::{AssetId, CustomAsset};
use spectrum_offchain::{
    binary::prefixed_key,
    data::unique_entity::{Confirmed, Predicted},
    event_sink::handlers::types::TryFromBox,
};
use spectrum_offchain_lm::data::AsBox;

use crate::script::{estimate_tx_size_in_kb, VAULT_CONTRACT};

#[async_trait(?Send)]
pub trait VaultDepositRepo {
    async fn put_confirmed(&mut self, df: Confirmed<AsBox<VaultDeposit>>);
    async fn put_predicted(&mut self, df: Predicted<AsBox<VaultDeposit>>);
    async fn spend_box(&mut self, box_id: BoxId);
    async fn unspend_box(&mut self, box_id: BoxId);
    /// False positive version of `exists()`.
    async fn may_exist(&self, box_id: BoxId) -> bool;
    async fn remove(&mut self, fid: BoxId);
}

pub struct VaultDepositRepoRocksDB {
    db: Arc<rocksdb::OptimisticTransactionDB>,
}

impl VaultDepositRepoRocksDB {
    pub fn new(db_path: &str) -> Self {
        Self {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(db_path).unwrap()),
        }
    }
}

#[async_trait(?Send)]
impl VaultDepositRepo for VaultDepositRepoRocksDB {
    async fn put_confirmed(&mut self, Confirmed(bx): Confirmed<AsBox<VaultDeposit>>) {
        let db = Arc::clone(&self.db);
        spawn_blocking(move || {
            let key = box_key(KEY_PREFIX, CONFIRMED_PRIORITY, &bx.box_id());
            let index_key = prefixed_key(KEY_INDEX_PREFIX, &bx.box_id());
            let value = bincode::serialize(&bx).unwrap();
            let tx = db.transaction();
            tx.put(key.clone(), value).unwrap();
            tx.put(index_key, key).unwrap();
            tx.commit().unwrap()
        })
        .await
    }

    async fn put_predicted(&mut self, Predicted(bx): Predicted<AsBox<VaultDeposit>>) {
        let db = Arc::clone(&self.db);
        spawn_blocking(move || {
            let key = box_key(KEY_PREFIX, PREDICTED_PRIORITY, &bx.box_id());
            let index_key = prefixed_key(KEY_INDEX_PREFIX, &bx.box_id());
            let value = bincode::serialize(&bx).unwrap();
            let tx = db.transaction();
            tx.put(key.clone(), value).unwrap();
            tx.put(index_key, key).unwrap();
            tx.commit().unwrap()
        })
        .await
    }

    async fn spend_box(&mut self, box_id: BoxId) {
        let db = Arc::clone(&self.db);
        let key = prefixed_key(SPENT_PREFIX, &box_id);
        spawn_blocking(move || db.put(key, []).unwrap()).await
    }

    async fn unspend_box(&mut self, box_id: BoxId) {
        let db = Arc::clone(&self.db);
        let key = prefixed_key(SPENT_PREFIX, &box_id);
        spawn_blocking(move || db.delete(key).unwrap()).await
    }

    async fn may_exist(&self, box_id: BoxId) -> bool {
        let db = Arc::clone(&self.db);
        let index_key = prefixed_key(KEY_INDEX_PREFIX, &box_id);
        spawn_blocking(move || db.key_may_exist(index_key)).await
    }

    async fn remove(&mut self, box_id: BoxId) {
        let db = Arc::clone(&self.db);
        let index_key = prefixed_key(KEY_INDEX_PREFIX, &box_id);
        spawn_blocking(move || {
            if let Some(key) = db.get(index_key.clone()).unwrap() {
                let tx = db.transaction();
                tx.delete(index_key).unwrap();
                tx.delete(key).unwrap();
                tx.commit().unwrap()
            }
        })
        .await
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultDeposit {
    #[serde(
        serialize_with = "serialize_option_address",
        deserialize_with = "deserialize_option_address"
    )]
    from_user_address: Option<Address>,
}

impl TryFromBox for VaultDeposit {
    fn try_from_box(bx: ErgoBox) -> Option<Self> {
        if bx.ergo_tree == *VAULT_CONTRACT {
            let from_user_address = if let Some(r4) = bx.additional_registers.get(NonMandatoryRegisterId::R4)
            {
                let RegisterValue::Parsed(c) = r4 else {
                    return None;
                };
                let Literal::Coll(CollKind::NativeColl(NativeColl::CollByte(bytes_i8))) = &c.v else {
                    return None;
                };
                let bytes: Vec<u8> = bytes_i8.iter().map(|b| *b as u8).collect();
                let address = Address::p2pk_from_pk_bytes(&bytes).unwrap();
                Some(address)
            } else {
                None
            };
            Some(VaultDeposit { from_user_address })
        } else {
            None
        }
    }
}

fn serialize_option_address<S>(address: &Option<Address>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match address {
        Some(addr) => serializer.serialize_some(&addr.content_bytes()),
        None => serializer.serialize_none(),
    }
}

// Custom deserialization for Option<Address>
fn deserialize_option_address<'de, D>(deserializer: D) -> Result<Option<Address>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    // Custom visitor to handle an Option<Address>
    struct OptionAddressVisitor;

    impl<'de> serde::de::Visitor<'de> for OptionAddressVisitor {
        type Value = Option<Address>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("an Option<Address>")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let s = <Vec<u8>>::deserialize(deserializer)?;
            Address::p2pk_from_pk_bytes(&s)
                .map(Some)
                .map_err(serde::de::Error::custom)
        }
    }

    deserializer.deserialize_option(OptionAddressVisitor)
}

fn compute_token_amounts(term_cells: &[ProtoTermCell]) -> HashMap<TokenId, BigUint> {
    let mut res = HashMap::new();

    for proto_term_cell in term_cells {
        for map in proto_term_cell.value.assets.values() {
            for (asset_id, asset) in map {
                let digest_raw: [u8; 32] = *Blake2bDigest256::from(*asset_id).raw();
                let token_id = TokenId::from(Digest32::from(digest_raw));
                *res.entry(token_id).or_insert(BigUint::from(0_u64)) += BigUint::from(u64::from(*asset));
                let token_amount = TokenAmount::try_from(u64::from(*asset)).unwrap();
            }
        }
    }

    res
}

const SPENT_PREFIX: &str = "spent";
const KEY_PREFIX: &str = "key";
const KEY_INDEX_PREFIX: &str = "key_index";
const CONFIRMED_PRIORITY: usize = 0;
const PREDICTED_PRIORITY: usize = 5;

fn box_key<T: Serialize>(prefix: &str, seq_num: usize, id: &T) -> Vec<u8> {
    let mut key_bytes = bincode::serialize(prefix).unwrap();
    let seq_num_bytes = bincode::serialize(&seq_num).unwrap();
    let id_bytes = bincode::serialize(&id).unwrap();
    key_bytes.extend_from_slice(&seq_num_bytes);
    key_bytes.extend_from_slice(&id_bytes);
    key_bytes
}

fn box_key_prefix(prefix: &str, seq_num: usize) -> Vec<u8> {
    let mut key_bytes = bincode::serialize(prefix).unwrap();
    let seq_num_bytes = bincode::serialize(&seq_num).unwrap();
    key_bytes.extend_from_slice(&seq_num_bytes);
    key_bytes
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Arc};

    use ergo_lib::{
        chain::transaction::TxId,
        ergo_chain_types::Digest32,
        ergotree_ir::{
            chain::{
                ergo_box::{box_value::BoxValue, BoxTokens, ErgoBox, NonMandatoryRegisters},
                token::{Token, TokenAmount, TokenId},
            },
            ergo_tree::ErgoTree,
            mir::{constant::Constant, expr::Expr},
        },
    };
    use itertools::Itertools;
    use num_bigint::BigUint;
    use rand::{Rng, RngCore};
    use spectrum_chain_connector::{Kilobytes, NotarizedReportConstraints, ProtoTermCell};
    use spectrum_crypto::digest::Blake2bDigest256;
    use spectrum_ledger::{
        cell::{AssetId, BoxDestination, CustomAsset, NativeCoin, PolicyId, ProgressPoint, SValue},
        interop::Point,
        ChainId,
    };
    use spectrum_move::SerializedValue;
    use spectrum_offchain::{data::unique_entity::Confirmed, event_sink::handlers::types::TryFromBox};
    use spectrum_offchain_lm::data::AsBox;

    use crate::{
        rocksdb::deposits::VaultDepositRepo,
        script::{
            estimate_tx_size_in_kb,
            tests::{gen_random_token, gen_tx_id, generate_address},
            VAULT_CONTRACT,
        },
    };

    use super::{VaultDeposit, VaultDepositRepoRocksDB};

    #[test]
    fn deposit_serialization_roundtrip() {
        let v = VaultDeposit {
            from_user_address: None,
        };
        let bytes = bincode::serialize(&v).unwrap();
        let deserialized_v: VaultDeposit = bincode::deserialize(&bytes).unwrap();
        assert_eq!(v, deserialized_v);

        let v = VaultDeposit {
            from_user_address: Some(generate_address()),
        };
        let bytes = bincode::serialize(&v).unwrap();
        let deserialized_v: VaultDeposit = bincode::deserialize(&bytes).unwrap();
        assert_eq!(v, deserialized_v);
    }

    fn rocks_db_client() -> VaultDepositRepoRocksDB {
        let rnd = rand::thread_rng().next_u32();
        VaultDepositRepoRocksDB {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(format!("./tmp/{}", rnd)).unwrap()),
        }
    }

    fn trivial_prop() -> ErgoTree {
        ErgoTree::try_from(Expr::Const(Constant::from(true))).unwrap()
    }

    fn generate_tokenless_vault_utxos(erg_per_box: u64, num_boxes: u16) -> Vec<AsBox<VaultDeposit>> {
        let tx_id = gen_tx_id();
        (0..num_boxes)
            .map(|index| {
                let bx = ErgoBox::new(
                    BoxValue::try_from(erg_per_box).unwrap(),
                    VAULT_CONTRACT.clone(),
                    None,
                    NonMandatoryRegisters::empty(),
                    500,
                    tx_id,
                    index,
                )
                .unwrap();
                AsBox(bx.clone(), VaultDeposit::try_from_box(bx).unwrap())
            })
            .collect()
    }

    fn generate_deposits_with_tokens(
        erg_per_box: u64,
        num_boxes: u16,
        tokens: Vec<Token>,
        strategy: TokenDistributionStrategy,
    ) -> Vec<AsBox<VaultDeposit>> {
        let tx_id = gen_tx_id();

        let mut rng = rand::thread_rng();
        (0..num_boxes)
            .map(|index| {
                let tokens = match strategy {
                    TokenDistributionStrategy::AllTokens => {
                        let mut tokens = tokens.clone();
                        for t in &mut tokens {
                            t.amount =
                                TokenAmount::try_from(*t.amount.as_u64() / (num_boxes as u64)).unwrap();
                        }
                        Some(BoxTokens::try_from(tokens).unwrap())
                    }
                    TokenDistributionStrategy::RandomSubset(n) => {
                        let mut selected = vec![];
                        loop {
                            let choice = rng.gen_range(0..tokens.len());
                            if !selected.contains(&choice) {
                                selected.push(choice);
                                if selected.len() == n {
                                    break;
                                }
                            }
                        }
                        let selected_tokens: Vec<_> = selected
                            .into_iter()
                            .map(|ix| {
                                let mut token = tokens[ix].clone();
                                token.amount =
                                    TokenAmount::try_from(*token.amount.as_u64() / (num_boxes as u64))
                                        .unwrap();
                                token
                            })
                            .collect();
                        Some(BoxTokens::try_from(selected_tokens).unwrap())
                    }
                };

                let bx = ErgoBox::new(
                    BoxValue::try_from(erg_per_box).unwrap(),
                    VAULT_CONTRACT.clone(),
                    tokens,
                    NonMandatoryRegisters::empty(),
                    500,
                    tx_id,
                    index,
                )
                .unwrap();
                AsBox(bx.clone(), VaultDeposit::try_from_box(bx).unwrap())
            })
            .collect()
    }

    enum TokenDistributionStrategy {
        /// Each box will contain some quantity of all available tokens
        AllTokens,
        /// Each box will contain a random number of different tokens bounded by the given field
        /// value.
        RandomSubset(usize),
    }

    fn trivial_box(nano_ergs: u64) -> ErgoBox {
        ErgoBox::new(
            BoxValue::try_from(nano_ergs).unwrap(),
            trivial_prop(),
            None,
            NonMandatoryRegisters::empty(),
            0,
            TxId::zero(),
            0,
        )
        .unwrap()
    }
}
