use std::{collections::VecDeque, time::Instant};

use chrono::Utc;
use ergo_chain_sync::client::node::{ErgoNetwork, ErgoNodeHttpClient};
use ergo_lib::ergotree_ir::chain::address::{AddressEncoder, NetworkPrefix};
use ergo_lib::{
    chain::{
        ergo_state_context::ErgoStateContext,
        transaction::{unsigned::UnsignedTransaction, DataInput, Transaction, TxIoVec, UnsignedInput},
    },
    ergo_chain_types::{Digest32, EcPoint},
    ergotree_interpreter::sigma_protocol::prover::ContextExtension,
    ergotree_ir::{
        bigint256::BigInt256,
        chain::{
            address::Address,
            ergo_box::{
                box_value::BoxValue, BoxId, BoxTokens, ErgoBox, ErgoBoxCandidate, NonMandatoryRegisterId,
                NonMandatoryRegisters,
            },
            token::TokenId,
        },
        ergo_tree::ErgoTree,
        mir::{
            constant::{Constant, Literal},
            value::{CollKind, NativeColl},
        },
        sigma_protocol::sigma_boolean::ProveDlog,
    },
    wallet::{miner_fee::MINERS_FEE_ADDRESS, tx_context::TransactionContext, Wallet},
};
use indexmap::IndexMap;
use k256::ProjectivePoint;
use log::info;
use num_bigint::{BigUint, Sign};
use spectrum_chain_connector::{
    NotarizedReport, NotarizedReportConstraints, PendingExportStatus, PendingTxIdentifier, PendingTxStatus,
    TxEvent, VaultStatus,
};
use spectrum_crypto::digest::blake2b256_hash;
use spectrum_ledger::cell::SValue;
use spectrum_ledger::{cell::ProgressPoint, interop::Point, ChainId};
use spectrum_offchain::{
    data::unique_entity::{Confirmed, Predicted},
    event_sink::handlers::types::{TryFromBox, TryFromBoxCtx},
    network::ErgoNetwork as EN,
};
use spectrum_offchain_lm::data::AsBox;
use spectrum_offchain_lm::prover::SeedPhrase;

use crate::rocksdb::moved_value_history::{ErgoTxType, SpectrumErgoTx};
use crate::rocksdb::tx_retry_scheduler::{DepositInProgress, TxInProgress};
use crate::AncillaryVaultInfo;
use crate::{
    committee::{CommitteeData, FirstCommitteeBox, SubsequentCommitteeBox},
    rocksdb::{
        deposits::{DepositRepo, DepositRepoRocksDB, UnprocessedDeposit},
        moved_value_history::{self, ErgoTxEvent, MovedValueHistory},
        tx_retry_scheduler::{Command, ExportInProgress, TxRetryScheduler},
        vault_boxes::{ErgoNotarizationBounds, VaultBoxRepo, VaultBoxRepoRocksDB, VaultUtxo},
        withdrawals::{WithdrawalRepo, WithdrawalRepoRocksDB},
    },
    script::{
        scalar_to_biguint, serialize_exclusion_set, ErgoCell, ErgoInboundCell, ErgoTermCell, ErgoTermCells,
        ExtraErgoData, SignatureAggregationWithNotarizationElements, DEPOSIT_CONTRACT, VAULT_CONTRACT,
    },
};

const MAX_SYNCED_BLOCK_HEIGHTS: usize = 100;
const MAX_MOVED_VALUES_PER_RESPONSE: usize = 100;

pub struct VaultHandler<MVH, E> {
    vault_box_repo: VaultBoxRepoRocksDB,
    withdrawal_repo: WithdrawalRepoRocksDB,
    deposit_repo: DepositRepoRocksDB,
    vault_contract: ErgoTree,
    committee_data: CommitteeData,
    synced_block_heights: VecDeque<u32>,
    sync_starting_height: u32,
    moved_value_history: MVH,
    tx_retry_scheduler: E,
    dummy_wallet: Wallet,
    vault_utxo_token_id: TokenId,
    genesis_vault_utxo_box_id: Option<VaultUtxo>,
}

impl<M, E> VaultHandler<M, E>
where
    M: MovedValueHistory,
    E: TxRetryScheduler<TxInProgress, PendingTxIdentifier<ExtraErgoData, BoxId>>,
{
    pub fn new(
        vault_box_repo: VaultBoxRepoRocksDB,
        withdrawal_repo: WithdrawalRepoRocksDB,
        deposit_repo: DepositRepoRocksDB,
        committee_guarding_script: ErgoTree,
        committee_public_keys: Vec<EcPoint>,
        vault_utxo_token_id: TokenId,
        data_inputs: TxIoVec<ErgoBox>,
        sync_starting_height: u32,
        moved_value_history: M,
        tx_retry_scheduler: E,
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
        const SEED_PHRASE: &str = "gather gather gather gather gather gather gather gather gather gather gather gather gather gather gather";
        let dummy_wallet = Wallet::from_mnemonic(SEED_PHRASE, "").expect("Invalid seed");
        Some(Self {
            vault_box_repo,
            withdrawal_repo,
            deposit_repo,
            committee_data,
            vault_contract: VAULT_CONTRACT.clone(),
            synced_block_heights: VecDeque::with_capacity(MAX_SYNCED_BLOCK_HEIGHTS),
            sync_starting_height,
            moved_value_history,
            tx_retry_scheduler,
            dummy_wallet,
            vault_utxo_token_id,
            genesis_vault_utxo_box_id: None,
        })
    }

    pub async fn handle(&mut self, event: TxEvent<(Transaction, u32)>) {
        match event {
            TxEvent::AppliedTx((tx, height)) => {
                match self.try_extract_vault_tx(&tx).await {
                    Some(VaultTx::Withdrawals { terminal_cells }) => {
                        info!(target: "vault", "VAULT WITHDRAWAL TX {:?} FOUND", tx.id());
                        // Spend input vault box
                        self.vault_box_repo.spend_box(tx.inputs.first().box_id).await;

                        let vault_output = tx.outputs.first().clone();
                        let vault_utxo =
                            VaultUtxo::try_from_box(vault_output.clone(), self.vault_utxo_token_id).unwrap();
                        let as_box = AsBox(vault_output.clone(), vault_utxo.clone());
                        self.vault_box_repo.put_confirmed(Confirmed(as_box)).await;

                        let mut exported_value = vec![];
                        // Add withdrawals
                        for (term_cell, bx) in terminal_cells {
                            let box_id = bx.box_id();
                            self.withdrawal_repo.put_confirmed(Confirmed(bx)).await;
                            assert!(self.withdrawal_repo.may_exist(box_id).await);
                            exported_value.push(term_cell);
                        }

                        // If this Tx was in the mempool and tracked, we can confirm it now.
                        match self.tx_retry_scheduler.next_command().await {
                            Command::ResubmitTx(tx_in_progress) | Command::Wait(_, tx_in_progress) => {
                                // If the signed-input of the vault UTXO coincides with the input tracked
                                // by `export_tx_retry_scheduler`, we can be sure it is our Tx that has been
                                // confirmed.
                                if let TxInProgress::Export(ref tracked_export) = tx_in_progress {
                                    if tracked_export.vault_utxo_signed_input == *tx.inputs.first() {
                                        info!(target: "vault", "VAULT WITHDRAWAL TX {:?} CONFIRMED", tx.id());
                                        self.tx_retry_scheduler.notify_confirmed(&tx_in_progress).await;
                                    }
                                } else {
                                    panic!("Expecting export TX in progress, not deposits!");
                                }
                            }
                            _ => (),
                        }

                        let vault_info = (
                            vault_utxo,
                            AncillaryVaultInfo {
                                box_id: vault_output.box_id(),
                                height,
                            },
                        );

                        let tx = SpectrumErgoTx {
                            progress_point: height,
                            tx_id: tx.id(),
                            tx_type: ErgoTxType::Withdrawal {
                                exported_value,
                                vault_info,
                            },
                        };
                        let ergo_moved_value = moved_value_history::ErgoTxEvent::Applied(tx);
                        self.moved_value_history.append(ergo_moved_value).await;
                    }

                    Some(VaultTx::Deposits { deposits }) => {
                        info!(target: "vault", "VAULT DEPOSIT TX {:?} FOUND ({} deposits)", tx.id(), deposits.len());
                        // Spend input vault box
                        self.vault_box_repo.spend_box(tx.inputs.first().box_id).await;

                        let vault_output = tx.outputs.first().clone();
                        let vault_utxo =
                            VaultUtxo::try_from_box(vault_output.clone(), self.vault_utxo_token_id).unwrap();
                        let as_box = AsBox(vault_output.clone(), vault_utxo.clone());
                        self.vault_box_repo.put_confirmed(Confirmed(as_box)).await;

                        let mut imported_value = vec![];
                        // Process deposits
                        for (inbound_cell, box_id) in deposits {
                            self.deposit_repo.process(box_id).await;
                            imported_value.push(inbound_cell);
                        }

                        // If this Tx was in the mempool and tracked, we can confirm it now.
                        match self.tx_retry_scheduler.next_command().await {
                            Command::ResubmitTx(tx_in_progress) | Command::Wait(_, tx_in_progress) => {
                                // If the signed-input of the vault UTXO coincides with the input tracked
                                // by `deposit_tx_retry_scheduler`, we can be sure it is our Tx that has been
                                // confirmed.
                                if let TxInProgress::Deposit(ref tracked_deposit) = tx_in_progress {
                                    if tracked_deposit.vault_utxo_signed_input == *tx.inputs.first() {
                                        info!(target: "vault", "VAULT DEPOSIT TX {:?} CONFIRMED", tx.id());
                                        self.tx_retry_scheduler.notify_confirmed(&tx_in_progress).await;
                                    }
                                } else {
                                    panic!("Expecting deposit TX in progress, not export!");
                                }
                            }
                            _ => (),
                        }

                        let vault_info = (
                            vault_utxo,
                            AncillaryVaultInfo {
                                box_id: vault_output.box_id(),
                                height,
                            },
                        );

                        let tx = SpectrumErgoTx {
                            progress_point: height,
                            tx_id: tx.id(),
                            tx_type: ErgoTxType::Deposit {
                                imported_value,
                                vault_info,
                            },
                        };
                        let ergo_moved_value = moved_value_history::ErgoTxEvent::Applied(tx);
                        self.moved_value_history.append(ergo_moved_value).await;
                    }
                    None => {
                        // Scan for refunded deposits
                        for input in &tx.inputs {
                            if let Some(unprocessed_deposit) =
                                self.deposit_repo.get_unprocessed(input.box_id).await
                            {
                                let addr_str = AddressEncoder::encode_address_as_string(
                                    NetworkPrefix::Mainnet,
                                    &unprocessed_deposit.0 .1 .0.address,
                                );
                                info!("REFUNDING DEPOSIT FROM {:?} ", addr_str);
                                self.moved_value_history
                                    .append(ErgoTxEvent::Applied(SpectrumErgoTx {
                                        progress_point: height,
                                        tx_id: tx.id(),
                                        tx_type: ErgoTxType::RefundedDeposit(unprocessed_deposit.0 .1),
                                    }))
                                    .await;
                            }
                        }

                        // Scan for genesis Vault UTxO and created deposit boxes
                        for output in &tx.outputs {
                            if let Some(unprocessed_deposit) = self.try_extract_unprocessed_deposit(output) {
                                info!(
                                    target: "vault",
                                    "DEPOSIT FOUND (value: {:?} nErgs), height: {}",
                                    unprocessed_deposit.0 .1 .0.ergs, height
                                );
                                self.deposit_repo.put(unprocessed_deposit.clone()).await;
                                self.moved_value_history
                                    .append(ErgoTxEvent::Applied(SpectrumErgoTx {
                                        progress_point: height,
                                        tx_id: tx.id(),
                                        tx_type: ErgoTxType::NewUnprocessedDeposit(unprocessed_deposit.0 .1),
                                    }))
                                    .await;
                            } else if let Some(vault_utxo) =
                                VaultUtxo::try_from_box(output.clone(), self.vault_utxo_token_id)
                            {
                                info!("GENESIS VAULT UTXO {:?} FOUND", output.box_id());
                                // A Vault UTxO that appears in an output outside the context of a withdrawal or
                                // deposit TX means that this is a genesis UTxO of Spectrum Network.
                                assert!(self.genesis_vault_utxo_box_id.is_none());
                                self.genesis_vault_utxo_box_id = Some(vault_utxo.clone());
                                let as_box = AsBox(output.clone(), vault_utxo);
                                self.vault_box_repo.put_confirmed(Confirmed(as_box)).await;
                            }
                        }
                    }
                }

                if height > self.synced_block_heights.back().copied().unwrap_or(0) {
                    if self.synced_block_heights.len() == MAX_SYNCED_BLOCK_HEIGHTS {
                        let _ = self.synced_block_heights.pop_front();
                    }
                    self.synced_block_heights.push_back(height);
                }
            }
            TxEvent::UnappliedTx((tx, height)) => {
                match self.try_extract_vault_tx(&tx).await {
                    Some(VaultTx::Withdrawals { terminal_cells }) => {
                        // Add back previous vault box
                        let prev_vault_box_id = tx.inputs.first().box_id;
                        self.vault_box_repo.unspend_box(prev_vault_box_id).await;
                        self.vault_box_repo.remove(tx.outputs.first().box_id()).await;

                        let mut exported_value = vec![];
                        // Remove withdrawals
                        for (term_cell, bx) in terminal_cells {
                            self.withdrawal_repo.remove(bx.box_id()).await;
                            exported_value.push(term_cell);
                        }

                        let vault_output = tx.outputs.first().clone();
                        let vault_box_id = vault_output.box_id();
                        let vault_utxo =
                            VaultUtxo::try_from_box(vault_output, self.vault_utxo_token_id).unwrap();
                        let vault_info = (
                            vault_utxo,
                            AncillaryVaultInfo {
                                box_id: vault_box_id,
                                height,
                            },
                        );

                        let tx = SpectrumErgoTx {
                            progress_point: height,
                            tx_id: tx.id(),
                            tx_type: ErgoTxType::Withdrawal {
                                exported_value,
                                vault_info,
                            },
                        };
                        let ergo_moved_value = moved_value_history::ErgoTxEvent::Unapplied(tx);
                        self.moved_value_history.append(ergo_moved_value).await;
                    }
                    Some(VaultTx::Deposits { deposits }) => {
                        // Add back previous vault box
                        let prev_vault_box_id = tx.inputs.first().box_id;
                        self.vault_box_repo.unspend_box(prev_vault_box_id).await;
                        self.vault_box_repo.remove(tx.outputs.first().box_id()).await;

                        let mut imported_value = vec![];
                        // Unprocess deposits
                        for (inbound_cell, box_id) in deposits {
                            self.deposit_repo.unprocess(box_id).await;
                            imported_value.push(inbound_cell);
                        }

                        let vault_output = tx.outputs.first().clone();
                        let vault_box_id = vault_output.box_id();
                        let vault_utxo =
                            VaultUtxo::try_from_box(vault_output, self.vault_utxo_token_id).unwrap();
                        let vault_info = (
                            vault_utxo,
                            AncillaryVaultInfo {
                                box_id: vault_box_id,
                                height,
                            },
                        );

                        let tx = SpectrumErgoTx {
                            progress_point: height,
                            tx_id: tx.id(),
                            tx_type: ErgoTxType::Deposit {
                                imported_value,
                                vault_info,
                            },
                        };
                        let ergo_moved_value = moved_value_history::ErgoTxEvent::Unapplied(tx);
                        self.moved_value_history.append(ergo_moved_value).await;
                    }
                    None => {
                        // Check for unprocessed deposits and remove them
                        for output in &tx.outputs {
                            if let Some(unprocessed_deposit) = self.try_extract_unprocessed_deposit(output) {
                                self.deposit_repo
                                    .remove_unprocessed(unprocessed_deposit.0.box_id())
                                    .await;
                            }
                        }
                    }
                }
                if let Some(last_synced_height) = self.synced_block_heights.back() {
                    if *last_synced_height == height {
                        let _ = self.synced_block_heights.pop_back();
                    }
                }
            }
        }
    }

    pub fn get_genesis_vault_utxo(&self) -> Option<VaultUtxo> {
        self.genesis_vault_utxo_box_id.clone()
    }

    pub async fn handle_tx_resubmission(&mut self, ergo_node: &ErgoNodeHttpClient) {
        let export_command = self.tx_retry_scheduler.next_command().await;
        if let Command::ResubmitTx(tx) = export_command {
            match tx {
                TxInProgress::Export(e) => {
                    info!(target: "vault", "Resubmitting export tx");
                    self.export_value(e.report, true, e.vault_utxo, ergo_node).await;
                }
                TxInProgress::Deposit(d) => {
                    info!(target: "vault", "Resubmitting deposit tx");
                    self.process_deposits(true, ergo_node).await;
                }
            }
        }
    }

    pub async fn select_txs_to_notarize(
        &self,
        constraints: NotarizedReportConstraints,
    ) -> Result<ErgoNotarizationBounds, ()> {
        self.vault_box_repo
            .collect(constraints)
            .await
            .map(ErgoNotarizationBounds::from)
    }

    pub async fn get_vault_status(&self, current_height: u32) -> VaultStatus<ExtraErgoData, BoxId> {
        let current_sync_height = self
            .synced_block_heights
            .back()
            .copied()
            .unwrap_or(self.sync_starting_height);
        let current_progress_point = ProgressPoint {
            chain_id: ChainId::from(0),
            point: Point::from(current_sync_height as u64),
        };

        let pending_tx_status = Option::<PendingTxStatus<ExtraErgoData, BoxId>>::from(
            self.tx_retry_scheduler.next_command().await,
        );

        if current_height > current_sync_height {
            VaultStatus::Syncing {
                current_progress_point,
                num_points_remaining: current_height - current_sync_height,
                pending_tx_status,
            }
        } else {
            VaultStatus::Synced {
                current_progress_point,
                pending_tx_status,
            }
        }
    }

    pub async fn sync_consensus_driver(&self, from_height: Option<u32>) -> Vec<ErgoTxEvent> {
        let mut res = vec![];
        let mut height = from_height.map(|h| h + 1).unwrap_or(self.sync_starting_height);
        while res.len() < MAX_MOVED_VALUES_PER_RESPONSE {
            if let Some((mv, next_height)) = self.moved_value_history.get(height).await {
                res.push(mv);
                height = next_height + 1;
            } else {
                break;
            }
        }
        res
    }

    pub async fn process_deposits(&mut self, is_resubmission: bool, ergo_node: &ErgoNodeHttpClient) -> bool {
        let current_height = ergo_node.get_height().await;
        if let VaultStatus::Syncing { .. } = self.get_vault_status(current_height).await {
            info!(target: "vault", "CHAIN TIP NOT REACHED");
            return false;
        }

        let max_miner_fee = 1000000_i64;
        let max_miner_fee_constant = Constant::from(max_miner_fee);

        let mut values = IndexMap::new();
        values.insert(8_u8, max_miner_fee_constant.clone());
        values.insert(4_u8, Constant::from(self.vault_utxo_token_id));
        let context_extension = ContextExtension { values };

        // For now we assume only 1 vault UTxO
        let Confirmed(AsBox(vault_utxo, _)) = self
            .vault_box_repo
            .get_all_confirmed()
            .await
            .first()
            .unwrap()
            .clone();

        let vault_input_box_registers = vault_utxo.additional_registers.clone();
        let mut output_vault_tokens = vault_utxo.tokens.clone().map(|t| t.to_vec()).unwrap_or_default();
        let unsigned_vault_input = UnsignedInput::new(vault_utxo.box_id(), context_extension);
        let initial_vault_balance = vault_utxo.value.as_i64();
        let mut unsigned_inputs = vec![unsigned_vault_input];
        let mut boxes_to_spend = vec![vault_utxo.clone()];

        let mut total_deposit_value = 0_i64;
        let unprocessed_deposits = self.deposit_repo.get_all_unprocessed_deposits().await;
        for UnprocessedDeposit(AsBox(bx, cell)) in &unprocessed_deposits {
            for t in &cell.0.tokens {
                if let Some(i) = output_vault_tokens
                    .iter()
                    .position(|tok| tok.token_id == t.token_id)
                {
                    let new_amount = output_vault_tokens[i].amount.checked_add(&t.amount).unwrap();
                    output_vault_tokens[i].amount = new_amount;
                } else {
                    output_vault_tokens.push(t.clone());
                }
            }

            let mut constants = IndexMap::new();
            constants.insert(8_u8, max_miner_fee_constant.clone());
            let unsigned_deposit_input =
                UnsignedInput::new(bx.box_id(), ContextExtension { values: constants });
            unsigned_inputs.push(unsigned_deposit_input);
            total_deposit_value += bx.value.as_i64();
            boxes_to_spend.push(bx.clone());
        }

        let vault_output_tokens = if output_vault_tokens.is_empty() {
            None
        } else {
            Some(BoxTokens::try_from(output_vault_tokens).unwrap())
        };

        let change_for_miner = BoxValue::try_from(max_miner_fee).unwrap();
        let vault_output_box = ErgoBoxCandidate {
            value: BoxValue::try_from(
                initial_vault_balance + total_deposit_value - change_for_miner.as_i64(),
            )
            .unwrap(),
            ergo_tree: VAULT_CONTRACT.clone(),
            tokens: vault_output_tokens,
            additional_registers: vault_input_box_registers,
            creation_height: current_height,
        };
        let miner_output = ErgoBoxCandidate {
            value: change_for_miner,
            ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
            tokens: None,
            additional_registers: NonMandatoryRegisters::empty(),
            creation_height: current_height,
        };
        let outputs = TxIoVec::from_vec(vec![vault_output_box, miner_output]).unwrap();
        let mut data_boxes = vec![self.committee_data.first_box.0.clone()];
        if let Some(subsequent) = &self.committee_data.subsequent_boxes {
            data_boxes.extend(subsequent.iter().map(|AsBox(bx, _)| bx.clone()));
        }
        let data_inputs: Vec<_> = data_boxes
            .iter()
            .map(|d| DataInput { box_id: d.box_id() })
            .collect();
        let data_inputs = Some(TxIoVec::from_vec(data_inputs).unwrap());
        let unsigned_tx =
            UnsignedTransaction::new(TxIoVec::from_vec(unsigned_inputs).unwrap(), data_inputs, outputs)
                .unwrap();
        let tx_context = TransactionContext::new(unsigned_tx, boxes_to_spend, data_boxes).unwrap();
        let ergo_state_context = ergo_node.get_ergo_state_context().await.unwrap();
        let res = self
            .dummy_wallet
            .sign_transaction(tx_context, &ergo_state_context, None);
        if res.is_err() {
            panic!("{:?}", res);
        }
        let signed_tx = res.unwrap();
        let tx_id = signed_tx.id();

        let vault_output_utxo = signed_tx.outputs.get(0).unwrap().clone();
        let deposit = TxInProgress::Deposit(DepositInProgress {
            unprocessed_deposits: unprocessed_deposits.clone(),
            vault_utxo_signed_input: signed_tx.inputs.first().clone(),
            vault_utxo,
            timestamp: Utc::now().timestamp(),
        });

        if let Err(e) = ergo_node.submit_tx(signed_tx).await {
            println!("ERGO NODE ERROR: {:?}", e);
            if is_resubmission {
                self.tx_retry_scheduler.notify_failed(&deposit).await;
            }
            false
        } else {
            println!("Deposit TX {:?} successfully submitted!", tx_id);

            // Update persistent stores
            self.vault_box_repo
                .put_predicted(Predicted(AsBox(
                    vault_output_utxo.clone(),
                    VaultUtxo::try_from_box(vault_output_utxo, self.vault_utxo_token_id).unwrap(),
                )))
                .await;

            for unprocessed_deposits in unprocessed_deposits {
                self.deposit_repo.put(unprocessed_deposits).await;
            }

            if !is_resubmission {
                self.tx_retry_scheduler.add(deposit).await;
            }

            true
        }
    }

    pub async fn export_value(
        &mut self,
        report: NotarizedReport<ExtraErgoData>,
        is_resubmission: bool,
        vault_utxo: ErgoBox,
        ergo_node: &ErgoNodeHttpClient,
    ) -> bool {
        let current_height = ergo_node.get_height().await;
        if let VaultStatus::Syncing { .. } = self.get_vault_status(current_height).await {
            info!(target: "vault", "CHAIN TIP NOT REACHED");
            return false;
        }

        let inputs = SignatureAggregationWithNotarizationElements::from(report.clone());
        let ergo_state_context = ergo_node.get_ergo_state_context().await.unwrap();
        let mut data_boxes = vec![self.committee_data.first_box.0.clone()];
        if let Some(subsequent) = &self.committee_data.subsequent_boxes {
            data_boxes.extend(subsequent.iter().map(|AsBox(bx, _)| bx.clone()));
        }
        let signed_tx = verify_vault_contract_ergoscript_with_sigma_rust(
            inputs,
            self.committee_data.committee_size(),
            ergo_state_context,
            vault_utxo.clone(),
            self.vault_utxo_token_id,
            data_boxes,
            &self.dummy_wallet,
            current_height,
        );

        let tx_id = signed_tx.id();

        let num_outputs = signed_tx.outputs.len();
        let vault_output_utxo = signed_tx.outputs.get(0).unwrap().clone();
        let withdrawals = signed_tx
            .outputs
            .clone()
            .into_iter()
            .skip(1)
            .take(num_outputs - 2);
        let export = TxInProgress::Export(ExportInProgress {
            report,
            vault_utxo_signed_input: signed_tx.inputs.first().clone(),
            vault_utxo,
            timestamp: Utc::now().timestamp(),
        });
        if let Err(e) = ergo_node.submit_tx(signed_tx).await {
            println!("ERGO NODE ERROR: {:?}", e);
            if is_resubmission {
                self.tx_retry_scheduler.notify_failed(&export).await;
            }
            false
        } else {
            println!("TX {:?} successfully submitted!", tx_id);

            // Update persistent stores
            self.vault_box_repo
                .put_predicted(Predicted(AsBox(
                    vault_output_utxo.clone(),
                    VaultUtxo::try_from_box(vault_output_utxo, self.vault_utxo_token_id).unwrap(),
                )))
                .await;

            for w in withdrawals {
                self.withdrawal_repo.put_predicted(Predicted(w)).await;
            }

            if !is_resubmission {
                self.tx_retry_scheduler.add(export).await;
            }

            true
        }
    }

    pub async fn acknowledge_confirmed_tx(&mut self, data: &PendingTxIdentifier<ExtraErgoData, BoxId>) {
        self.tx_retry_scheduler.clear_confirmed(data).await;
    }

    pub async fn acknowledge_aborted_tx(&mut self, data: &PendingTxIdentifier<ExtraErgoData, BoxId>) {
        self.tx_retry_scheduler.clear_aborted(data).await;
    }

    async fn try_extract_vault_tx(&self, tx: &Transaction) -> Option<VaultTx> {
        if let Some(vault_utxo) =
            VaultUtxo::try_from_box(tx.outputs.first().clone(), self.vault_utxo_token_id)
        {
            if let Some(Confirmed(bx)) = self.vault_box_repo.get_confirmed(&tx.inputs.first().box_id).await {
                if bx.0.value > vault_utxo.value {
                    // withdrawal
                    let mut withdrawals = vec![];
                    for withdrawal_bx in tx.outputs.iter().skip(1).take(tx.outputs.len() - 2) {
                        withdrawals
                            .push((ErgoTermCell(ErgoCell::from(withdrawal_bx)), withdrawal_bx.clone()));
                    }
                    return Some(VaultTx::Withdrawals {
                        terminal_cells: withdrawals,
                    });
                } else if bx.0.value < vault_utxo.value {
                    // deposit
                    let mut deposits = vec![];
                    for deposit_input in tx.inputs.iter().skip(1) {
                        let UnprocessedDeposit(AsBox(_bx, d)) = self
                            .deposit_repo
                            .get_unprocessed(deposit_input.box_id)
                            .await
                            .unwrap();
                        deposits.push((d, deposit_input.box_id));
                    }
                    return Some(VaultTx::Deposits { deposits });
                }
            }
        }
        None
    }

    fn try_extract_unprocessed_deposit(&self, bx: &ErgoBox) -> Option<UnprocessedDeposit> {
        if bx.ergo_tree == *DEPOSIT_CONTRACT {
            let valid_vault_token = if let Ok(Some(r4)) = bx.get_register(NonMandatoryRegisterId::R4.into()) {
                if let Literal::Coll(CollKind::NativeColl(NativeColl::CollByte(bytes))) = r4.v {
                    let bytes_u8: Vec<u8> = bytes.into_iter().map(|b| b as u8).collect();
                    let t = TokenId::from(Digest32::try_from(bytes_u8).unwrap());
                    t == self.vault_utxo_token_id
                } else {
                    false
                }
            } else {
                false
            };

            if valid_vault_token {
                if let Ok(Some(r5)) = bx.get_register(NonMandatoryRegisterId::R5.into()) {
                    if let Ok(prove_dlog) = ProveDlog::try_from(r5.v) {
                        let address = Address::P2Pk(prove_dlog);
                        let tokens = bx.tokens.clone().map(|toks| toks.to_vec()).unwrap_or_default();
                        let cell = ErgoInboundCell(
                            ErgoCell {
                                ergs: bx.value,
                                address,
                                tokens,
                            },
                            bx.box_id(),
                        );
                        return Some(UnprocessedDeposit(AsBox(bx.clone(), cell)));
                    }
                }
            }
        }
        None
    }
}

pub fn verify_vault_contract_ergoscript_with_sigma_rust(
    inputs: SignatureAggregationWithNotarizationElements,
    committee_size: u32,
    ergo_state_context: ErgoStateContext,
    vault_utxo: ErgoBox,
    expected_vault_utxo_token_id: TokenId,
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
    let threshold = ((committee_size as usize) * threshold.num / threshold.denom) as i32;
    let proof = Constant::from(proof);
    let avl_const = Constant::from(starting_avl_tree);

    // Create outboxes for terminal cells
    let term_cell_outputs: Vec<_> = terminal_cells
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
    values.insert(4, expected_vault_utxo_token_id.into());

    let vault_output_box = ErgoBoxCandidate {
        value: BoxValue::try_from(initial_vault_balance - change_for_miner.as_i64() - ergs_to_distribute)
            .unwrap(),
        ergo_tree: VAULT_CONTRACT.clone(),
        tokens: vault_utxo.tokens.clone(),
        additional_registers: vault_utxo.additional_registers.clone(),
        creation_height: current_height,
    };

    let miner_output = ErgoBoxCandidate {
        value: change_for_miner,
        ergo_tree: MINERS_FEE_ADDRESS.script().unwrap(),
        tokens: None,
        additional_registers: NonMandatoryRegisters::empty(),
        creation_height: current_height,
    };
    let mut outputs_vec = vec![vault_output_box];
    outputs_vec.extend(term_cell_outputs);
    outputs_vec.push(miner_output);
    let outputs = TxIoVec::from_vec(outputs_vec).unwrap();
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

pub enum VaultTx {
    Withdrawals {
        terminal_cells: Vec<(ErgoTermCell, ErgoBox)>,
    },

    Deposits {
        deposits: Vec<(ErgoInboundCell, BoxId)>,
    },
}
