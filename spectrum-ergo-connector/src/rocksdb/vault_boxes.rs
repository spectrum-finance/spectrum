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
        ergo_box::{BoxId, ErgoBox},
        token::{Token, TokenAmount, TokenAmountError, TokenId},
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

/// Track changing state of Vault UTxOs.
#[async_trait(?Send)]
pub trait VaultBoxRepo {
    /// Collect vault boxes that meet the specified `constraints`.
    async fn collect(
        &self,
        constraints: NotarizedReportConstraints,
    ) -> Result<ErgoNotarizationBoundsWithBoxes, ()>;
    async fn put_confirmed(&mut self, df: Confirmed<AsBox<VaultUtxo>>);
    async fn put_predicted(&mut self, df: Predicted<AsBox<VaultUtxo>>);
    async fn get_confirmed(&self, box_id: &BoxId) -> Option<Confirmed<AsBox<VaultUtxo>>>;
    async fn spend_box(&mut self, box_id: BoxId);
    async fn unspend_box(&mut self, box_id: BoxId);
    /// False positive version of `exists()`.
    async fn may_exist(&self, box_id: BoxId) -> bool;
    async fn remove(&mut self, fid: BoxId);
}

#[derive(Serialize, Deserialize, Debug)]
/// Sent in response to a request for notarization of terminal cell withdrawals.
pub struct ErgoNotarizationBounds {
    pub vault_utxos: NonEmpty<BoxId>,
    /// Represents an index i within the terminal cells in NotarizedReportConstraints such that all
    /// terminal cells up to and NOT including the i'th one will be included in the notarized report.
    pub terminal_cell_bound: usize,
}

/// The same as `ErgoNotarizationBounds` above, but we retain boxes for testing/debugging purposes.
pub struct ErgoNotarizationBoundsWithBoxes {
    pub vault_utxos: NonEmpty<ErgoBox>,
    pub terminal_cell_bound: usize,
}

impl From<ErgoNotarizationBoundsWithBoxes> for ErgoNotarizationBounds {
    fn from(value: ErgoNotarizationBoundsWithBoxes) -> Self {
        let vault_utxos = value.vault_utxos.map(|bx| bx.box_id());
        Self {
            vault_utxos,
            terminal_cell_bound: value.terminal_cell_bound,
        }
    }
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
        &self,
        constraints: NotarizedReportConstraints,
    ) -> Result<ErgoNotarizationBoundsWithBoxes, ()> {
        let db = self.db.clone();
        spawn_blocking(move || {
            let NotarizedReportConstraints {
                term_cells,
                max_tx_size: Kilobytes(max_tx_size),
                estimated_number_of_byzantine_nodes,
                ..
            } = constraints;
            let mut num_withdrawals = 0_usize;
            let mut num_token_occurrences = 0_usize;
            let mut included_tokens = HashSet::new();

            // For now just consider confirmed boxes
            let prefix = box_key_prefix(KEY_PREFIX, CONFIRMED_PRIORITY);
            let mut readopts = ReadOptions::default();
            readopts.set_iterate_range(rocksdb::PrefixRange(prefix.clone()));

            let mut term_cell_iter = term_cells.iter();

            let mut included_vault_utxos = Vec::new();
            let mut vault_iter = db.iterator_opt(IteratorMode::From(&prefix, Direction::Forward), readopts);

            let mut asset_diff = AssetDifference {
                nano_erg_diff: NanoErgDifference::Balanced,
                token_shortfall: vec![],
                token_surplus: vec![],
            };

            let mut add_term_cells = true;

            let mut terminal_cell_bound = 0;

            'vault_iter: while let Some(Ok((_, value_bytes))) = vault_iter.next() {
                if !add_term_cells {
                    match asset_diff.nano_erg_diff {
                        NanoErgDifference::Balanced | NanoErgDifference::Surplus(_) => break,
                        NanoErgDifference::Shortfall(_) => (),
                    }
                }

                let AsBox(bx, vault_utxo): AsBox<VaultUtxo> = bincode::deserialize(&value_bytes).unwrap();
                let spent_key = prefixed_key(SPENT_PREFIX, &bx.box_id());
                if db.get(&spent_key).unwrap().is_some() {
                    continue 'vault_iter;
                }
                let current_utxo_value = *bx.value.as_u64();
                let new_token_ids = if let Some(tokens) = &bx.tokens {
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

                // TODO: even if we're over the limit, if we have shortfall we need to add more
                // UTXOs till we're covered.
                if !asset_diff.in_shortfall()
                    && !included_vault_utxos.is_empty()
                    && estimated_tx_size > max_tx_size
                {
                    return Ok(ErgoNotarizationBoundsWithBoxes {
                        vault_utxos: NonEmpty::try_from(included_vault_utxos).unwrap(),
                        terminal_cell_bound,
                    });
                } else {
                    println!("Added vault UTXO. TX size: {}", estimated_tx_size);
                    num_withdrawals += 1;
                    num_token_occurrences += num_new_token_occurrences;
                    included_vault_utxos.push(bx.clone());
                }

                let nano_erg_diff = match asset_diff.nano_erg_diff {
                    NanoErgDifference::Balanced => NanoErgDifference::Surplus(current_utxo_value),
                    NanoErgDifference::Shortfall(shortfall) => match current_utxo_value.cmp(&shortfall) {
                        Ordering::Greater => NanoErgDifference::Surplus(current_utxo_value - shortfall),

                        Ordering::Less => NanoErgDifference::Shortfall(shortfall - current_utxo_value),
                        Ordering::Equal => NanoErgDifference::Balanced,
                    },
                    NanoErgDifference::Surplus(surplus) => {
                        NanoErgDifference::Surplus(surplus + current_utxo_value)
                    }
                };
                asset_diff.nano_erg_diff = nano_erg_diff;

                if let Some(tokens) = &bx.tokens {
                    for token in tokens {
                        included_tokens.insert(token.token_id);
                        let utxo_amount = *token.amount.as_u64();
                        if let Some(ix) = asset_diff
                            .token_shortfall
                            .iter()
                            .position(|(token_id, _)| *token_id == token.token_id)
                        {
                            let existing_shortfall = asset_diff.token_shortfall[ix].1;
                            match existing_shortfall.cmp(&utxo_amount) {
                                Ordering::Less => {
                                    // Now have surplus
                                    asset_diff.token_shortfall.remove(ix);
                                    asset_diff
                                        .token_surplus
                                        .push((token.token_id, utxo_amount - existing_shortfall));
                                }
                                Ordering::Greater => {
                                    asset_diff.token_shortfall[ix].1 -= utxo_amount;
                                }
                                Ordering::Equal => {
                                    asset_diff.token_shortfall.remove(ix);
                                }
                            }
                        } else if let Some(ix) = asset_diff
                            .token_surplus
                            .iter()
                            .position(|(token_id, _)| *token_id == token.token_id)
                        {
                            asset_diff.token_surplus[ix].1 += utxo_amount;
                        } else {
                            // Newly created surplus token
                            asset_diff.token_surplus.push((token.token_id, utxo_amount));
                        }
                    }
                }

                if add_term_cells {
                    while let Some(term_cell) = term_cell_iter.next() {
                        let num_new_tokens = number_new_token_ids(term_cell, &included_tokens);
                        let estimated_tx_size = estimate_tx_size_in_kb(
                            num_withdrawals + 1,
                            estimated_number_of_byzantine_nodes as usize,
                            num_token_occurrences + num_new_tokens,
                        );
                        if estimated_tx_size > max_tx_size && terminal_cell_bound > 0 {
                            // Don't add anymore terminal cells.
                            println!("Term cell -> {} kb > limit", estimated_tx_size);
                            add_term_cells = false;
                            continue 'vault_iter;
                        } else {
                            terminal_cell_bound += 1;
                            num_withdrawals += 1;
                            num_token_occurrences += num_new_tokens;
                        }

                        let cell_erg_value = u64::from(term_cell.value.native);
                        let nano_erg_diff = match asset_diff.nano_erg_diff {
                            NanoErgDifference::Balanced => NanoErgDifference::Shortfall(cell_erg_value),
                            NanoErgDifference::Shortfall(shortfall) => {
                                NanoErgDifference::Shortfall(cell_erg_value + shortfall)
                            }
                            NanoErgDifference::Surplus(surplus) => match surplus.cmp(&cell_erg_value) {
                                Ordering::Less => NanoErgDifference::Shortfall(cell_erg_value - surplus),
                                Ordering::Greater => NanoErgDifference::Surplus(surplus - cell_erg_value),
                                Ordering::Equal => NanoErgDifference::Balanced,
                            },
                        };

                        println!(
                            "Cell value: {}, status: {:?}, TX size(kb): {}",
                            cell_erg_value, nano_erg_diff, estimated_tx_size
                        );
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
                                    match existing_surplus.cmp(&term_cell_token_amount) {
                                        Ordering::Less => {
                                            // Now have shortfall
                                            asset_diff.token_surplus.remove(ix);
                                            asset_diff.token_shortfall.push((
                                                term_cell_token_id,
                                                term_cell_token_amount - existing_surplus,
                                            ));
                                        }
                                        Ordering::Greater => {
                                            asset_diff.token_surplus[ix].1 -= term_cell_token_amount;
                                        }
                                        Ordering::Equal => {
                                            asset_diff.token_surplus.remove(ix);
                                        }
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

                    // Here we've included all terminal cells
                    match asset_diff.nano_erg_diff {
                        NanoErgDifference::Balanced | NanoErgDifference::Surplus(_)
                            if asset_diff.token_shortfall.is_empty() =>
                        {
                            break 'vault_iter;
                        }
                        _ => {
                            println!("Passing through...");
                        }
                    }
                }
            }
            let vault_utxos = NonEmpty::try_from(included_vault_utxos).unwrap();
            Ok(ErgoNotarizationBoundsWithBoxes {
                vault_utxos,
                terminal_cell_bound,
            })
        })
        .await
    }

    async fn put_confirmed(&mut self, Confirmed(bx): Confirmed<AsBox<VaultUtxo>>) {
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

    async fn put_predicted(&mut self, Predicted(bx): Predicted<AsBox<VaultUtxo>>) {
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

    async fn get_confirmed(&self, box_id: &BoxId) -> Option<Confirmed<AsBox<VaultUtxo>>> {
        let db = Arc::clone(&self.db);
        let box_id = *box_id;
        spawn_blocking(move || {
            let key = box_key(KEY_PREFIX, CONFIRMED_PRIORITY, &box_id);
            if let Ok(Some(bytes)) = db.get(key) {
                let value: AsBox<VaultUtxo> = bincode::deserialize(&bytes).unwrap();
                return Some(Confirmed(value));
            }
            None
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
pub struct VaultUtxo {}

impl TryFromBox for VaultUtxo {
    fn try_from_box(bx: ErgoBox) -> Option<Self> {
        if bx.ergo_tree == *VAULT_CONTRACT {
            Some(VaultUtxo {})
        } else {
            None
        }
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

#[derive(Debug)]
enum NanoErgDifference {
    /// The selected UTXOs currently are not sufficient to cover a selection of terminal cells.
    Shortfall(u64),
    /// The total nano-Erg value of the selected UTXOs exceeds the total value of the selected
    /// terminal cells.
    Surplus(u64),
    /// No shortfall nor surplus.
    Balanced,
}

#[derive(Debug)]
struct AssetDifference {
    nano_erg_diff: NanoErgDifference,
    token_shortfall: Vec<(TokenId, u64)>,
    token_surplus: Vec<(TokenId, u64)>,
}

impl AssetDifference {
    fn in_shortfall(&self) -> bool {
        matches!(self.nano_erg_diff, NanoErgDifference::Shortfall(_)) || !self.token_shortfall.is_empty()
    }
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
pub mod tests {
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
        rocksdb::vault_boxes::{ErgoNotarizationBoundsWithBoxes, VaultBoxRepo},
        script::{
            estimate_tx_size_in_kb,
            tests::{gen_random_token, gen_tx_id, generate_address},
            VAULT_CONTRACT,
        },
    };

    use super::{VaultBoxRepoRocksDB, VaultUtxo};

    #[tokio::test]
    async fn collect_simple() {
        let mut client = rocks_db_client();
        for f in generate_tokenless_vault_utxos(500_000, 3) {
            client.put_confirmed(Confirmed(f)).await
        }
        let constraints = NotarizedReportConstraints {
            term_cells: vec![proto_term_cell(
                1_000_000,
                vec![],
                generate_address().content_bytes(),
            )],
            last_progress_point: ProgressPoint {
                chain_id: ChainId::from(0),
                point: Point::from(100),
            },
            max_tx_size: Kilobytes(5.0),
            estimated_number_of_byzantine_nodes: 10,
        };
        let term_cells = constraints.term_cells.clone();
        let ErgoNotarizationBoundsWithBoxes {
            vault_utxos,
            terminal_cell_bound,
        } = client.collect(constraints).await.unwrap();
        let vault_utxos_vec: Vec<_> = vault_utxos.into_iter().collect_vec();
        check_sufficient_utxos(&vault_utxos_vec, &term_cells[..terminal_cell_bound]);
        assert_eq!(terminal_cell_bound, 1);
        assert_eq!(vault_utxos_vec.len(), 2);
    }

    #[tokio::test]
    async fn collect_cell_shortfall() {
        // In this test, adding the terminal cell results in exceeding the Kb threshold. But we
        // should add in the extra vault UTXO to achieve surplus.
        let mut client = rocks_db_client();
        for f in generate_tokenless_vault_utxos(500_000, 3) {
            client.put_confirmed(Confirmed(f)).await
        }
        let constraints = NotarizedReportConstraints {
            term_cells: vec![proto_term_cell(
                1_000_000,
                vec![],
                generate_address().content_bytes(),
            )],
            last_progress_point: ProgressPoint {
                chain_id: ChainId::from(0),
                point: Point::from(100),
            },
            max_tx_size: Kilobytes(4.06),
            estimated_number_of_byzantine_nodes: 20,
        };
        let term_cells = constraints.term_cells.clone();
        let ErgoNotarizationBoundsWithBoxes {
            vault_utxos,
            terminal_cell_bound,
        } = client.collect(constraints).await.unwrap();
        let vault_utxos_vec: Vec<_> = vault_utxos.into_iter().collect_vec();
        check_sufficient_utxos(&vault_utxos_vec, &term_cells[..terminal_cell_bound]);
        assert_eq!(terminal_cell_bound, 1);
        assert_eq!(vault_utxos_vec.len(), 2);
    }

    #[tokio::test]
    async fn collect_single_cell_single_token() {
        // In this test, the vault contains 3 UTXOs containing identical value. The Kb threshold is
        // set to the cost of one of these UTXOs. Now we have 2 terminal cells, each with identical
        // value of a vault UTXO. Adding just 1 terminal cell exceeds the threshold, but its nErg
        // value and token amount is exactly covered by one of the vault UTXOs.
        let mut client = rocks_db_client();
        let num_boxes = 3;
        let token = gen_random_token(num_boxes as usize);
        for f in generate_vault_utxos_with_tokens(
            500_000,
            num_boxes,
            vec![token.clone()],
            TokenDistributionStrategy::AllTokens,
        ) {
            client.put_confirmed(Confirmed(f)).await
        }
        let mut term_token = token.clone();
        term_token.amount = TokenAmount::try_from(*term_token.amount.as_u64() / 3).unwrap();

        let estimated_number_of_byzantine_nodes = 20;
        let max_tx_size = estimate_tx_size_in_kb(1, estimated_number_of_byzantine_nodes, 1);
        let constraints = NotarizedReportConstraints {
            term_cells: vec![
                proto_term_cell(
                    500_000,
                    vec![term_token.clone()],
                    generate_address().content_bytes(),
                ),
                proto_term_cell(500_000, vec![term_token], generate_address().content_bytes()),
            ],
            last_progress_point: ProgressPoint {
                chain_id: ChainId::from(0),
                point: Point::from(100),
            },
            max_tx_size: Kilobytes(max_tx_size), // So even the first vault UTXO will be over limit
            estimated_number_of_byzantine_nodes: estimated_number_of_byzantine_nodes as u32,
        };
        let term_cells = constraints.term_cells.clone();
        let ErgoNotarizationBoundsWithBoxes {
            vault_utxos,
            terminal_cell_bound,
        } = client.collect(constraints).await.unwrap();
        let vault_utxos_vec: Vec<_> = vault_utxos.into_iter().collect_vec();
        check_sufficient_utxos(&vault_utxos_vec, &term_cells[..terminal_cell_bound]);
        assert_eq!(terminal_cell_bound, 1);
        assert_eq!(vault_utxos_vec.len(), 1);
    }

    #[tokio::test]
    async fn collect_multiple_tokens() {
        // In this test, the vault contains 3 UTXOs containing identical value. The Kb threshold is
        // set to the cost of one of these UTXOs. Now we have 2 terminal cells, each with identical
        // value of a vault UTXO. Adding just 1 terminal cell exceeds the threshold, but its nErg
        // value and token amount is exactly covered by one of the vault UTXOs.
        let mut client = rocks_db_client();
        let num_boxes = 50;
        let erg_per_box = 5_000_000;
        let tokens_pool: Vec<_> = (0..num_boxes)
            .map(|_| gen_random_token(num_boxes as usize))
            .collect();

        let mut selected_tokens: Vec<Token> = vec![];

        for AsBox(ergo_box, vault_utxo) in generate_vault_utxos_with_tokens(
            erg_per_box,
            num_boxes,
            tokens_pool.clone(),
            TokenDistributionStrategy::RandomSubset(2),
        ) {
            if let Some(tokens) = &ergo_box.tokens {
                for token in tokens {
                    if let Some(existing_token) =
                        selected_tokens.iter_mut().find(|t| t.token_id == token.token_id)
                    {
                        if let Ok(new_amount) = existing_token.amount.checked_add(&token.amount) {
                            existing_token.amount = new_amount;
                        }
                    } else {
                        selected_tokens.push(token.clone());
                    }
                }
            }
            client.put_confirmed(Confirmed(AsBox(ergo_box, vault_utxo))).await
        }

        let estimated_number_of_byzantine_nodes = 20;
        let max_tx_size = 6.0; //estimate_tx_size_in_kb(1, estimated_number_of_byzantine_nodes, 1);

        let term_cells = generate_term_cells(
            (num_boxes as u64) * erg_per_box,
            selected_tokens,
            80,
            TokenDistributionStrategy::RandomSubset(1),
        );
        let constraints = NotarizedReportConstraints {
            term_cells,
            last_progress_point: ProgressPoint {
                chain_id: ChainId::from(0),
                point: Point::from(100),
            },
            max_tx_size: Kilobytes(max_tx_size), // So even the first vault UTXO will be over limit
            estimated_number_of_byzantine_nodes: estimated_number_of_byzantine_nodes as u32,
        };
        let term_cells = constraints.term_cells.clone();
        let ErgoNotarizationBoundsWithBoxes {
            vault_utxos,
            terminal_cell_bound,
        } = client.collect(constraints).await.unwrap();
        let vault_utxos_vec: Vec<_> = vault_utxos.into_iter().collect_vec();
        println!(
            "# vault UTXOs: {}, # term cells: {}",
            vault_utxos_vec.len(),
            terminal_cell_bound
        );
        check_sufficient_utxos(&vault_utxos_vec, &term_cells[..terminal_cell_bound]);
    }

    #[test]
    fn vault_utxo_serialization_roundtrip() {
        let v = VaultUtxo {};
        let bytes = bincode::serialize(&v).unwrap();
        let deserialized_v: VaultUtxo = bincode::deserialize(&bytes).unwrap();
        assert_eq!(v, deserialized_v);

        let v = VaultUtxo {};
        let bytes = bincode::serialize(&v).unwrap();
        let deserialized_v: VaultUtxo = bincode::deserialize(&bytes).unwrap();
        assert_eq!(v, deserialized_v);
    }

    fn rocks_db_client() -> VaultBoxRepoRocksDB {
        let rnd = rand::thread_rng().next_u32();
        VaultBoxRepoRocksDB {
            db: Arc::new(rocksdb::OptimisticTransactionDB::open_default(format!("./tmp/{}", rnd)).unwrap()),
        }
    }

    pub fn proto_term_cell(nano_ergs: u64, tokens: Vec<Token>, address_bytes: Vec<u8>) -> ProtoTermCell {
        let dst = BoxDestination {
            target: ChainId::from(0),
            address: SerializedValue::from(address_bytes),
            inputs: None,
        };
        let mut assets = HashMap::new();
        let asset_map: HashMap<AssetId, CustomAsset> = tokens
            .into_iter()
            .map(|t| {
                let asset_id =
                    AssetId::from(Blake2bDigest256::try_from(<Vec<u8>>::from(t.token_id)).unwrap());
                let custom_asset = CustomAsset::from(*t.amount.as_u64());
                (asset_id, custom_asset)
            })
            .collect();
        assets.insert(PolicyId::from(Blake2bDigest256::zero()), asset_map);
        ProtoTermCell {
            value: SValue {
                native: NativeCoin::from(nano_ergs),
                assets,
            },
            dst,
        }
    }

    fn check_sufficient_utxos(vault_utxos: &[ErgoBox], selected_term_cells: &[ProtoTermCell]) {
        let mut term_cell_tokens = HashMap::new();
        let mut vault_tokens = HashMap::new();

        let mut total_vault_nano_ergs = BigUint::from(0_u64);
        let mut total_term_cell_nano_ergs = BigUint::from(0_u64);

        for ergo_box in vault_utxos {
            total_vault_nano_ergs += *ergo_box.value.as_u64();
            if let Some(tokens) = &ergo_box.tokens {
                for token in tokens {
                    *vault_tokens.entry(token.token_id).or_insert(0_u64) += *token.amount.as_u64();
                }
            }
        }

        for term_cell in selected_term_cells {
            total_term_cell_nano_ergs += u64::from(term_cell.value.native);
            for map in term_cell.value.assets.values() {
                for (asset_id, asset) in map {
                    let digest_raw: [u8; 32] = *Blake2bDigest256::from(*asset_id).raw();
                    let term_cell_token_id = TokenId::from(Digest32::from(digest_raw));
                    let term_cell_token_amount = u64::from(*asset);
                    *term_cell_tokens.entry(term_cell_token_id).or_insert(0_u64) += term_cell_token_amount;
                }
            }
        }

        let sufficient_erg = total_term_cell_nano_ergs <= total_vault_nano_ergs;
        assert!(sufficient_erg);
        let enough_tokens = if term_cell_tokens.is_empty() {
            true
        } else {
            term_cell_tokens.into_iter().any(|(key, value)| {
                if let Some(vault_value) = vault_tokens.get(&key) {
                    *vault_value >= value
                } else {
                    false
                }
            })
        };

        assert!(enough_tokens);
    }

    fn trivial_prop() -> ErgoTree {
        ErgoTree::try_from(Expr::Const(Constant::from(true))).unwrap()
    }

    fn generate_tokenless_vault_utxos(erg_per_box: u64, num_boxes: u16) -> Vec<AsBox<VaultUtxo>> {
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
                AsBox(bx.clone(), VaultUtxo::try_from_box(bx).unwrap())
            })
            .collect()
    }

    fn generate_vault_utxos_with_tokens(
        erg_per_box: u64,
        num_boxes: u16,
        tokens: Vec<Token>,
        strategy: TokenDistributionStrategy,
    ) -> Vec<AsBox<VaultUtxo>> {
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
                AsBox(bx.clone(), VaultUtxo::try_from_box(bx).unwrap())
            })
            .collect()
    }

    fn generate_term_cells(
        total_nano_ergs: u64,
        mut tokens: Vec<Token>,
        max_number_term_cells: u16,
        strategy: TokenDistributionStrategy,
    ) -> Vec<ProtoTermCell> {
        let mut res = vec![];
        let mut rng = rand::thread_rng();
        let mut remaining_nergs = total_nano_ergs;
        let mut num_cells = 0;
        const MIN_NERG_PER_BOX: u64 = 1_000_000_u64;

        while remaining_nergs > MIN_NERG_PER_BOX && num_cells < max_number_term_cells {
            let tokens = match strategy {
                TokenDistributionStrategy::AllTokens => {
                    let mut tokens_to_take = vec![];
                    for token in &mut tokens {
                        if *token.amount.as_u64() / 10 > 0 {
                            let amount =
                                TokenAmount::try_from(rng.gen_range(1..=*token.amount.as_u64() / 10))
                                    .unwrap();
                            tokens_to_take.push(Token {
                                token_id: token.token_id,
                                amount,
                            });
                            let new_amount_left = token.amount.checked_sub(&amount).unwrap();
                            token.amount = new_amount_left;
                        }
                    }
                    tokens_to_take
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
                    selected
                        .into_iter()
                        .map(|ix| {
                            let mut token = tokens[ix].clone();
                            let amount = TokenAmount::try_from(*token.amount.as_u64() / 10).unwrap();
                            let num_tokens_left = tokens[ix].amount.checked_sub(&amount).unwrap();
                            tokens[ix].amount = num_tokens_left;
                            token.amount = amount;
                            token
                        })
                        .collect()
                }
            };
            let nano_ergs = rng.gen_range(MIN_NERG_PER_BOX..=remaining_nergs.min(10 * MIN_NERG_PER_BOX));
            res.push(proto_term_cell(
                nano_ergs,
                tokens,
                generate_address().content_bytes(),
            ));
            num_cells += 1;
            remaining_nergs -= nano_ergs;
        }

        res
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
