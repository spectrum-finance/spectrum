use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_std::task::spawn_blocking;
use async_trait::async_trait;
use ergo_lib::{
    ergo_chain_types::Digest32,
    ergotree_ir::chain::{
        ergo_box::{box_value::BoxValue, BoxId, ErgoBox},
        token::{Token, TokenAmount, TokenAmountError, TokenId},
    },
};
use nonempty::NonEmpty;
use num_bigint::BigUint;
use num_traits::FromPrimitive;
use rocksdb::{Direction, IteratorMode, ReadOptions};
use serde::Serialize;
use spectrum_chain_connector::{Kilobytes, NotarizedReportConstraints, ProtoTermCell};
use spectrum_crypto::digest::{self, Blake2bDigest256};
use spectrum_ledger::cell::{AssetId, CustomAsset};
use spectrum_offchain::{
    binary::prefixed_key,
    data::unique_entity::{Confirmed, Predicted},
};

use crate::script::estimate_tx_size_in_kb;

use super::withdrawals::RepoRocksDB;

#[async_trait(?Send)]
pub trait VaultBoxRepo {
    /// Collect vault boxes that meet the specified `constraints`.
    async fn collect(
        &mut self,
        contraints: NotarizedReportConstraints,
    ) -> Result<(NonEmpty<ErgoBox>, usize), ()>;
    async fn put_confirmed(&mut self, df: Confirmed<ErgoBox>);
    async fn put_predicted(&mut self, df: Predicted<ErgoBox>);
    async fn spend_box(&mut self, box_id: BoxId);
    async fn unspend_box(&mut self, box_id: BoxId);
    /// False positive version of `exists()`.
    async fn may_exist(&self, box_id: BoxId) -> bool;
    async fn remove(&mut self, fid: BoxId);
}

pub struct VaultBoxRepoRocksDB {
    db: Arc<rocksdb::OptimisticTransactionDB>,
}

impl VaultBoxRepoRocksDB {
    pub fn new(db_path: &str) -> Self {
        Self {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(db_path).unwrap()),
        }
    }
}

#[async_trait(?Send)]
impl VaultBoxRepo for VaultBoxRepoRocksDB {
    async fn collect(
        &mut self,
        constraints: NotarizedReportConstraints,
    ) -> Result<(NonEmpty<ErgoBox>, usize), ()> {
        let db = self.db.clone();
        spawn_blocking(move || {
            let NotarizedReportConstraints {
                txs,
                last_progress_point,
                max_tx_size: Kilobytes(max_tx_size),
                estimated_number_of_byzantine_nodes,
            } = constraints;
            let mut num_withdrawals = 0_usize;
            let mut num_token_occurrences = 0_usize;
            let mut included_tokens = HashSet::new();

            // For now just consider confirmed boxes
            let prefix = box_key_prefix(KEY_PREFIX, CONFIRMED_PRIORITY);
            let mut readopts = ReadOptions::default();
            readopts.set_iterate_range(rocksdb::PrefixRange(prefix.clone()));

            let mut term_cell_iter = txs.iter();

            let mut included_vault_utxos = Vec::new();
            let mut vault_iter = db.iterator_opt(IteratorMode::From(&prefix, Direction::Forward), readopts);

            let mut asset_diff = AssetDifference {
                nano_erg_diff: NanoErgDifference::Balanced,
                token_shortfall: vec![],
                token_surplus: vec![],
            };

            let mut add_term_cells = true;

            let mut term_cell_index = 0;

            'vault_iter: while let Some(Ok((_, value_bytes))) = vault_iter.next() {
                if !add_term_cells {
                    match asset_diff.nano_erg_diff {
                        NanoErgDifference::Balanced | NanoErgDifference::Surplus(_) => break,
                        NanoErgDifference::Shortfall(_) => (),
                    }
                }

                let vault_utxo: ErgoBox = bincode::deserialize(&value_bytes).unwrap();
                let current_utxo_value = *vault_utxo.value.as_u64();
                let new_token_ids = if let Some(tokens) = &vault_utxo.tokens {
                    tokens
                        .iter()
                        .filter_map(|t| {
                            if !included_tokens.contains(&t.token_id) {
                                Some(t.token_id)
                            } else {
                                None
                            }
                        })
                        .collect()
                } else {
                    vec![]
                };
                let num_new_token_occurrences = new_token_ids.len();

                let estimated_tx_size = estimate_tx_size_in_kb(
                    num_withdrawals + 1,
                    estimated_number_of_byzantine_nodes as usize,
                    num_token_occurrences + num_new_token_occurrences,
                );

                if estimated_tx_size > max_tx_size as f32 {
                    return Ok((NonEmpty::try_from(included_vault_utxos).unwrap(), term_cell_index));
                } else {
                    num_withdrawals += 1;
                    num_token_occurrences += num_new_token_occurrences;
                    included_vault_utxos.push(vault_utxo.clone());
                }

                if let Some(tokens) = &vault_utxo.tokens {
                    for token in tokens {
                        included_tokens.insert(token.token_id);
                        let utxo_amount = *token.amount.as_u64();
                        if let Some(ix) = asset_diff
                            .token_shortfall
                            .iter()
                            .position(|(token_id, _)| *token_id == token.token_id)
                        {
                            let existing_shortfall = asset_diff.token_shortfall[ix].1;
                            if existing_shortfall < utxo_amount {
                                // Now have surplus
                                asset_diff.token_shortfall.remove(ix);
                                asset_diff
                                    .token_surplus
                                    .push((token.token_id, utxo_amount - existing_shortfall));
                            } else if existing_shortfall > utxo_amount {
                                asset_diff.token_shortfall[ix].1 -= utxo_amount;
                            } else {
                                asset_diff.token_shortfall.remove(ix);
                            }
                        } else if let Some(ix) = asset_diff
                            .token_surplus
                            .iter()
                            .position(|(token_id, _)| *token_id == token.token_id)
                        {
                            asset_diff.token_shortfall[ix].1 += utxo_amount;
                        } else {
                            // Newly created surplus token
                            asset_diff.token_surplus.push((token.token_id, utxo_amount));
                        }
                    }
                }

                if add_term_cells {
                    while let Some(term_cell) = term_cell_iter.next() {
                        let estimated_tx_size = estimate_tx_size_in_kb(
                            num_withdrawals + 1,
                            estimated_number_of_byzantine_nodes as usize,
                            num_token_occurrences + number_new_token_ids(term_cell, &included_tokens),
                        );
                        if estimated_tx_size > max_tx_size as f32 {
                            // Don't add anymore terminal cells
                            add_term_cells = false;
                            continue 'vault_iter;
                        } else {
                            term_cell_index += 1;
                        }

                        let cell_erg_value = u64::from(term_cell.value.native);
                        let nano_erg_diff = match asset_diff.nano_erg_diff {
                            NanoErgDifference::Balanced => match current_utxo_value.cmp(&cell_erg_value) {
                                Ordering::Less => {
                                    NanoErgDifference::Shortfall(cell_erg_value - current_utxo_value)
                                }
                                Ordering::Greater => {
                                    NanoErgDifference::Surplus(current_utxo_value - cell_erg_value)
                                }
                                Ordering::Equal => NanoErgDifference::Balanced,
                            },
                            NanoErgDifference::Shortfall(shortfall) => {
                                if current_utxo_value > shortfall {
                                    let diff = current_utxo_value - shortfall;
                                    if diff > cell_erg_value {
                                        NanoErgDifference::Surplus(diff - cell_erg_value)
                                    } else if diff < cell_erg_value {
                                        NanoErgDifference::Shortfall(cell_erg_value - diff)
                                    } else {
                                        NanoErgDifference::Balanced
                                    }
                                } else {
                                    NanoErgDifference::Shortfall(shortfall - current_utxo_value)
                                }
                            }
                            NanoErgDifference::Surplus(surplus) => {
                                let new_surplus = surplus + current_utxo_value;
                                if new_surplus < cell_erg_value {
                                    NanoErgDifference::Shortfall(cell_erg_value - new_surplus)
                                } else if new_surplus > cell_erg_value {
                                    NanoErgDifference::Surplus(new_surplus - cell_erg_value)
                                } else {
                                    NanoErgDifference::Balanced
                                }
                            }
                        };

                        asset_diff.nano_erg_diff = nano_erg_diff;

                        // Update token surpluses and shortfalls
                        for map in term_cell.value.assets.values() {
                            for (asset_id, asset) in map {
                                let digest_raw: [u8; 32] = *Blake2bDigest256::from(*asset_id).raw();
                                let term_cell_token_id = TokenId::from(Digest32::from(digest_raw));
                                let term_cell_token_amount = u64::from(*asset);

                                if let Some(ix) = asset_diff
                                    .token_shortfall
                                    .iter()
                                    .position(|(token_id, _)| *token_id == term_cell_token_id)
                                {
                                    asset_diff.token_shortfall[ix].1 += term_cell_token_amount;
                                } else if let Some(ix) = asset_diff
                                    .token_surplus
                                    .iter()
                                    .position(|(token_id, _)| *token_id == term_cell_token_id)
                                {
                                    let existing_surplus = asset_diff.token_surplus[ix].1;
                                    if existing_surplus < term_cell_token_amount {
                                        // Now have shortfall
                                        asset_diff.token_surplus.remove(ix);
                                        asset_diff.token_shortfall.push((
                                            term_cell_token_id,
                                            term_cell_token_amount - existing_surplus,
                                        ));
                                    } else if existing_surplus > term_cell_token_amount {
                                        asset_diff.token_surplus[ix].1 -= term_cell_token_amount;
                                    } else {
                                        asset_diff.token_surplus.remove(ix);
                                    }
                                } else {
                                    // Newly created token shortfall
                                    asset_diff
                                        .token_shortfall
                                        .push((term_cell_token_id, term_cell_token_amount));
                                }
                            }
                        }
                    }
                }
            }
            Err(())
        })
        .await
    }

    async fn put_confirmed(&mut self, Confirmed(bx): Confirmed<ErgoBox>) {
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

    async fn put_predicted(&mut self, Predicted(bx): Predicted<ErgoBox>) {
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

/// Note: due to orphan rule, we cannot impl From<(AssertId, CustomAsset)>
fn create_token(asset_id: AssetId, asset: CustomAsset) -> Result<Token, TokenAmountError> {
    let digest_raw: [u8; 32] = *Blake2bDigest256::from(asset_id).raw();
    let token_id = TokenId::from(Digest32::from(digest_raw));
    let amount = TokenAmount::try_from(u64::from(asset))?;
    Ok(Token { token_id, amount })
}

fn number_new_token_ids(term_cell: &ProtoTermCell, included_token_ids: &HashSet<TokenId>) -> usize {
    let mut count = 0;
    for map in term_cell.value.assets.values() {
        for asset_id in map.keys() {
            let digest_raw: [u8; 32] = *Blake2bDigest256::from(*asset_id).raw();
            let token_id = TokenId::from(Digest32::from(digest_raw));
            if !included_token_ids.contains(&token_id) {
                count += 1;
            }
        }
    }

    count
}

enum NanoErgDifference {
    /// The selected UTXOs currently are not sufficient to cover a selection of terminal cells.
    Shortfall(u64),
    /// The total nano-Erg value of the selected UTXOs exceeds the total value of the selected
    /// terminal cells.
    Surplus(u64),
    /// No shortfall nor surplus.
    Balanced,
}

struct AssetDifference {
    nano_erg_diff: NanoErgDifference,
    token_shortfall: Vec<(TokenId, u64)>,
    token_surplus: Vec<(TokenId, u64)>,
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
