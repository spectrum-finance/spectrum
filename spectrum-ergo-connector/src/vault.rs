use std::{
    collections::{HashMap, VecDeque},
    time::Instant,
};

use ergo_chain_sync::client::node::ErgoNodeHttpClient;
use ergo_lib::{
    chain::{
        ergo_state_context::ErgoStateContext,
        transaction::{unsigned::UnsignedTransaction, DataInput, Transaction, TxIoVec, UnsignedInput},
    },
    ergo_chain_types::EcPoint,
    ergotree_interpreter::sigma_protocol::prover::ContextExtension,
    ergotree_ir::{
        bigint256::BigInt256,
        chain::{
            ergo_box::{
                box_value::BoxValue, BoxId, BoxTokens, ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId,
                NonMandatoryRegisters, RegisterValue,
            },
            token::Token,
        },
        ergo_tree::ErgoTree,
        mir::constant::{Constant, Literal},
    },
    wallet::{miner_fee::MINERS_FEE_ADDRESS, tx_context::TransactionContext},
};
use indexmap::IndexMap;
use k256::ProjectivePoint;
use nonempty::NonEmpty;
use num_bigint::{BigUint, Sign};
use spectrum_chain_connector::{MovedValue, NotarizedReportConstraints, ProtoTermCell, TxEvent, VaultStatus};
use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_ledger::{
    cell::{AssetId, BoxDestination, CustomAsset, NativeCoin, PolicyId, ProgressPoint, SValue},
    interop::Point,
    ChainId,
};
use spectrum_move::SerializedValue;
use spectrum_offchain::{
    data::unique_entity::{Confirmed, Predicted},
    event_sink::handlers::types::{TryFromBox, TryFromBoxCtx},
    network::ErgoNetwork,
};
use spectrum_offchain_lm::{
    data::AsBox,
    ergo::{NanoErg, MIN_SAFE_BOX_VALUE},
};

use crate::{
    committee::{CommitteeData, FirstCommitteeBox, SubsequentCommitteeBox},
    rocksdb::{
        moved_value_history::{self, ErgoMovedValue, ErgoUserValue, MovedValueHistory},
        vault_boxes::{VaultBoxRepo, VaultBoxRepoRocksDB, VaultUtxo},
        withdrawals::{WithdrawalRepo, WithdrawalRepoRocksDB},
    },
    script::{
        scalar_to_biguint, serialize_exclusion_set, ErgoCell, ErgoTermCell, ErgoTermCells,
        SignatureAggregationWithNotarizationElements, VAULT_CONTRACT,
    },
};

const MAX_SYNCED_BLOCK_HEIGHTS: usize = 100;
const MAX_MOVED_VALUES_PER_RESPONSE: usize = 100;

pub struct VaultHandler<MVH> {
    vault_box_repo: VaultBoxRepoRocksDB,
    withdrawal_repo: WithdrawalRepoRocksDB,
    vault_contract: ErgoTree,
    committee_data: CommitteeData,
    chain_tip_reached: bool,
    synced_block_heights: VecDeque<u32>,
    sync_starting_height: u32,
    moved_value_history: MVH,
}

impl<MVH> VaultHandler<MVH>
where
    MVH: MovedValueHistory,
{
    pub fn new(
        vault_box_repo: VaultBoxRepoRocksDB,
        withdrawal_repo: WithdrawalRepoRocksDB,
        committee_guarding_script: ErgoTree,
        committee_public_keys: Vec<EcPoint>,
        data_inputs: TxIoVec<ErgoBox>,
        sync_starting_height: u32,
        moved_value_history: MVH,
    ) -> Option<Self> {
        let mut slice_ix = 0_usize;

        let first_box = AsBox(
            data_inputs.first().clone(),
            FirstCommitteeBox::try_from_box(
                data_inputs.first().clone(),
                (committee_guarding_script.clone(), &committee_public_keys),
            )?,
        );
        slice_ix += first_box.1.public_keys.len();

        let mut subsequent_data_inputs = vec![];
        for (index, ergo_box) in data_inputs.iter().enumerate().skip(1) {
            let subsequent = SubsequentCommitteeBox::try_from_box(
                ergo_box.clone(),
                (
                    ergo_box.value,
                    committee_guarding_script.clone(),
                    index as u32,
                    &committee_public_keys[slice_ix..],
                ),
            )?;
            slice_ix += subsequent.public_keys.len();
            subsequent_data_inputs.push(AsBox(ergo_box.clone(), subsequent));
        }

        let subsequent_boxes = TxIoVec::try_from(subsequent_data_inputs).ok();
        let committee_data = CommitteeData {
            first_box,
            subsequent_boxes,
        };
        Some(Self {
            vault_box_repo,
            withdrawal_repo,
            committee_data,
            vault_contract: VAULT_CONTRACT.clone(),
            chain_tip_reached: false,
            synced_block_heights: VecDeque::with_capacity(MAX_SYNCED_BLOCK_HEIGHTS),
            sync_starting_height,
            moved_value_history,
        })
    }

    pub async fn handle(&mut self, event: TxEvent<(Transaction, bool, u32)>) {
        match event {
            TxEvent::AppliedTx((tx, tip_reached, height)) => {
                self.chain_tip_reached = tip_reached;
                if self.is_vault_withdrawal_tx(&tx).await {
                    println!(
                        "VAULT TX {:?} FOUND. Tip reached: {}",
                        tx.id(),
                        self.chain_tip_reached
                    );
                    // Spend input vault box
                    self.vault_box_repo.spend_box(tx.inputs.first().box_id).await;

                    let num_outputs = tx.outputs.len();
                    let vault_output = tx.outputs.get(num_outputs - 2).unwrap().clone();
                    let as_box = AsBox(
                        vault_output.clone(),
                        VaultUtxo::try_from_box(vault_output).unwrap(),
                    );
                    self.vault_box_repo.put_confirmed(Confirmed(as_box)).await;

                    let mut exported_value = vec![];
                    // Add withdrawals
                    for output in tx.outputs.iter().take(num_outputs - 2) {
                        self.withdrawal_repo
                            .put_confirmed(Confirmed(output.clone()))
                            .await;
                        assert!(self.withdrawal_repo.may_exist(output.box_id()).await);
                        exported_value.push(ErgoTermCell(ErgoCell::from(output)));
                    }

                    let user_value = ErgoUserValue {
                        imported_value: vec![],
                        exported_value,
                        progress_point: height,
                    };

                    self.moved_value_history
                        .append(moved_value_history::ErgoMovedValue::Applied(user_value))
                        .await;

                    if height > self.synced_block_heights.back().copied().unwrap_or(0) {
                        if self.synced_block_heights.len() == MAX_SYNCED_BLOCK_HEIGHTS {
                            let _ = self.synced_block_heights.pop_front();
                        }
                        self.synced_block_heights.push_back(height);
                    }
                }
                //else {
                //    // println!("tx@ height {}", tx.outputs.first().creation_height);
                //    // Vault deposit TX (TODO)
                //    for output in tx.outputs {
                //        if output.ergo_tree == VAULT_CONTRACT.clone() {
                //            println!("Box_id {} is  a vault UTxO", output.box_id());
                //            let as_box = AsBox(output.clone(), VaultUtxo::try_from_box(output).unwrap());
                //            self.vault_box_repo.put_confirmed(Confirmed(as_box)).await;

                //            // let constraints = NotarizedReportConstraints {
                //            //     term_cells: vec![
                //            //         proto_term_cell(u64::from(MIN_SAFE_BOX_VALUE), vec![], vec![0]),
                //            //         proto_term_cell(500_000, vec![], vec![0]),
                //            //     ],
                //            //     last_progress_point: ProgressPoint {
                //            //         chain_id: ChainId::from(0),
                //            //         point: Point::from(1138759),
                //            //     },
                //            //     max_tx_size: spectrum_chain_connector::Kilobytes(3.0),
                //            //     estimated_number_of_byzantine_nodes: 0,
                //            // };
                //            // let utxos = self.vault_box_repo.collect(constraints).await.unwrap();
                //            // println!("Collected: {:?}", utxos);
                //        }
                //    }
                //}
            }
            TxEvent::UnappliedTx((tx, _, height)) => {
                if self.is_vault_withdrawal_tx(&tx).await {
                    let num_outputs = tx.outputs.len();
                    let vault_box_id = tx.inputs.first().box_id;

                    // Add back previous vault box
                    self.vault_box_repo.unspend_box(vault_box_id).await;

                    self.vault_box_repo
                        .remove(tx.outputs.get(num_outputs - 2).unwrap().box_id())
                        .await;

                    let mut exported_value = vec![];

                    // Remove withdrawals
                    for output in tx.outputs.iter().take(num_outputs - 2) {
                        self.withdrawal_repo.remove(output.box_id()).await;
                        exported_value.push(ErgoTermCell(ErgoCell::from(output)));
                    }

                    let user_value = ErgoUserValue {
                        imported_value: vec![],
                        exported_value,
                        progress_point: height,
                    };

                    self.moved_value_history
                        .append(moved_value_history::ErgoMovedValue::Unapplied(user_value))
                        .await;

                    if let Some(last_synced_height) = self.synced_block_heights.back() {
                        if *last_synced_height == height {
                            let _ = self.synced_block_heights.pop_back();
                        }
                    }
                }
            }
        }
    }

    async fn is_vault_withdrawal_tx(&self, tx: &Transaction) -> bool {
        // If the first output is for the miner's fee and the second output is guarded by
        // the vault contract, we can be sure that this TX is for report notarization.
        // This is necessary but insufficient:
        // For real TX:
        //  - OUTPUTs 0...n: withdrawals
        //  - OUTPUT(n + 1): vault UTXO
        //  - OUTPUT(n + 2): miner fee
        //  - INPUTS: every input UTXO should be Guarded by contract and have address in R4.
        //            Don't need to check this since it should be in vault_box_repo
        //  - Check data-inputs for current committee.
        //
        let num_outputs = tx.outputs.len();
        if num_outputs <= 2
            || tx.inputs.len() != 1
            || tx.outputs.last().ergo_tree != MINERS_FEE_ADDRESS.script().unwrap()
            || tx.outputs.get(num_outputs - 2).unwrap().ergo_tree != self.vault_contract
            || tx.data_inputs.is_none()
        {
            return false;
        }

        if !self.valid_data_inputs(&tx.data_inputs) {
            return false;
        }

        true
    }

    fn valid_data_inputs(&self, data_inputs: &Option<TxIoVec<DataInput>>) -> bool {
        // Check data inputs
        let Some(data_inputs) = data_inputs else {
            return false;
        };
        // Check first data input
        if data_inputs.first().box_id != self.committee_data.first_box.0.box_id() {
            return false;
        }

        if let Some(subsequent_boxes) = &self.committee_data.subsequent_boxes {
            if subsequent_boxes.len() != data_inputs.len() - 1 {
                return false;
            }
            for (ix, input) in data_inputs.iter().enumerate().skip(1) {
                let Some(sb) = subsequent_boxes.get(ix - 1) else {
                    return false;
                };
                if input.box_id != sb.0.box_id() {
                    return false;
                }
            }
        } else if data_inputs.len() > 1 {
            return false;
        }
        true
    }

    pub async fn select_txs_to_notarize(
        &self,
        constraints: NotarizedReportConstraints,
    ) -> Result<(NonEmpty<ErgoBox>, usize), ()> {
        self.vault_box_repo.collect(constraints).await
    }

    pub fn get_vault_status(&self, current_height: u32) -> VaultStatus {
        let current_sync_height = self
            .synced_block_heights
            .back()
            .copied()
            .unwrap_or(self.sync_starting_height);
        let current_progress_point = ProgressPoint {
            chain_id: ChainId::from(0),
            point: Point::from(current_sync_height as u64),
        };
        if current_height > current_sync_height {
            VaultStatus::Syncing {
                current_progress_point,
                num_points_remaining: current_height - current_sync_height,
            }
        } else {
            VaultStatus::Synced(current_progress_point)
        }
    }

    pub async fn sync_consensus_driver(&self, from_height: Option<u32>) -> Vec<ErgoMovedValue> {
        let mut res = vec![];
        let mut height = from_height.map(|h| h + 1).unwrap_or(self.sync_starting_height);
        while res.len() < MAX_MOVED_VALUES_PER_RESPONSE {
            if let Some((mv, next_height)) = self.moved_value_history.get(height).await {
                res.push(mv);
                height = next_height + 1;
            }
        }
        res
    }

    pub async fn export_value(
        &mut self,
        inputs: SignatureAggregationWithNotarizationElements,
        ergo_state_context: ErgoStateContext,
        current_height: u32,
        vault_utxo: ErgoBox,
        ergo_node: &ErgoNodeHttpClient,
        wallet: &ergo_lib::wallet::Wallet,
    ) -> bool {
        if !self.chain_tip_reached {
            return false;
        }

        let mut data_boxes = vec![self.committee_data.first_box.0.clone()];
        if let Some(subsequent) = &self.committee_data.subsequent_boxes {
            data_boxes.extend(subsequent.iter().map(|AsBox(bx, _)| bx.clone()));
        }
        let signed_tx = self.verify_vault_contract_ergoscript_with_sigma_rust(
            inputs,
            ergo_state_context,
            vault_utxo,
            data_boxes,
            wallet,
            current_height,
        );

        let tx_id = signed_tx.id();

        let num_outputs = signed_tx.outputs.len();
        let vault_output_utxo = signed_tx.outputs.get(num_outputs - 2).unwrap().clone();
        let withdrawals = signed_tx.outputs.clone().into_iter().take(num_outputs - 2);
        if let Err(e) = ergo_node.submit_tx(signed_tx).await {
            println!("ERGO NODE ERROR: {:?}", e);
            false
        } else {
            println!("TX {:?} successfully submitted!", tx_id);

            // Update persistent stores
            self.vault_box_repo
                .put_predicted(Predicted(AsBox(vault_output_utxo, VaultUtxo {})))
                .await;

            for w in withdrawals {
                self.withdrawal_repo.put_predicted(Predicted(w)).await;
            }

            true
        }
    }

    pub fn verify_vault_contract_ergoscript_with_sigma_rust(
        &self,
        inputs: SignatureAggregationWithNotarizationElements,
        ergo_state_context: ErgoStateContext,
        vault_utxo: ErgoBox,
        data_boxes: Vec<ErgoBox>,
        wallet: &ergo_lib::wallet::Wallet,
        current_height: u32,
    ) -> Transaction {
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

        let change_for_miner = BoxValue::try_from(max_miner_fee).unwrap();

        let md = blake2b256_hash(&resulting_digest);
        let exclusion_set_data = serialize_exclusion_set(exclusion_set, md.as_ref());
        let aggregate_response: Constant = (
            Constant::from(aggregate_response_bytes),
            Constant::from(first_len),
        )
            .into();
        let num_participants = 1 + self
            .committee_data
            .subsequent_boxes
            .as_ref()
            .map(|boxes| boxes.len())
            .unwrap_or(0);
        let threshold = (num_participants * threshold.num / threshold.denom) as i32;
        let proof = Constant::from(proof);
        let avl_const = Constant::from(starting_avl_tree);

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
                        creation_height: current_height,
                    }
                },
            )
            .collect();

        let initial_vault_balance = vault_utxo.value.as_i64();
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

        let vault_output_box = ErgoBoxCandidate {
            value: BoxValue::try_from(initial_vault_balance - change_for_miner.as_i64() - ergs_to_distribute)
                .unwrap(),
            ergo_tree: VAULT_CONTRACT.clone(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: current_height,
        };

        let miner_output = ErgoBoxCandidate {
            value: change_for_miner,
            ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: current_height,
        };
        term_cell_outputs.push(vault_output_box);
        term_cell_outputs.push(miner_output);
        let outputs = TxIoVec::from_vec(term_cell_outputs).unwrap();
        let unsigned_input = UnsignedInput::new(vault_utxo.box_id(), ContextExtension { values });

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
        let tx_context = TransactionContext::new(unsigned_tx, vec![vault_utxo], data_boxes).unwrap();
        let now = Instant::now();
        println!("Signing TX...");
        let res = wallet.sign_transaction(tx_context, &ergo_state_context, None);
        if res.is_err() {
            panic!("{:?}", res);
        }
        println!("Time to validate and sign: {} ms", now.elapsed().as_millis());
        res.unwrap()
    }
}