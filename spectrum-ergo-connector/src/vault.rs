use std::collections::HashMap;

use ergo_lib::{
    chain::transaction::{Transaction, TxIoVec},
    ergo_chain_types::EcPoint,
    ergotree_ir::{
        chain::{
            ergo_box::{ErgoBox, NonMandatoryRegisterId, RegisterValue},
            token::Token,
        },
        ergo_tree::ErgoTree,
        mir::constant::Literal,
    },
    wallet::miner_fee::MINERS_FEE_ADDRESS,
};
use spectrum_chain_connector::{NotarizedReportConstraints, ProtoTermCell, TxEvent};
use spectrum_crypto::digest::Blake2bDigest256;
use spectrum_ledger::{
    cell::{AssetId, BoxDestination, CustomAsset, NativeCoin, PolicyId, ProgressPoint, SValue},
    interop::Point,
    ChainId,
};
use spectrum_move::SerializedValue;
use spectrum_offchain::{
    data::unique_entity::Confirmed,
    event_sink::handlers::types::{TryFromBox, TryFromBoxCtx},
};
use spectrum_offchain_lm::{
    data::AsBox,
    ergo::{NanoErg, MIN_SAFE_BOX_VALUE},
};

use crate::{
    committee::{CommitteeData, FirstCommitteeBox, SubsequentCommitteeBox},
    rocksdb::{
        vault_boxes::{VaultBoxRepo, VaultBoxRepoRocksDB, VaultUtxo},
        withdrawals::{WithdrawalRepo, WithdrawalRepoRocksDB},
    },
    script::VAULT_CONTRACT,
};

pub struct VaultHandler {
    vault_box_repo: VaultBoxRepoRocksDB,
    withdrawal_repo: WithdrawalRepoRocksDB,
    vault_contract: ErgoTree,
    committee_data: CommitteeData,
}

impl VaultHandler {
    pub fn new(
        vault_box_repo: VaultBoxRepoRocksDB,
        withdrawal_repo: WithdrawalRepoRocksDB,
        committee_guarding_script: ErgoTree,
        committee_public_keys: Vec<EcPoint>,
        data_inputs: TxIoVec<ErgoBox>,
    ) -> Option<Self> {
        let mut slice_ix = 0_usize;

        println!("box_id first data_input: {}", data_inputs.first().box_id());
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
        })
    }

    pub async fn handle(&mut self, event: TxEvent<Transaction>) {
        match event {
            TxEvent::AppliedTx(tx) => {
                if self.is_vault_withdrawal_tx(&tx).await {
                    // Spend input vault box
                    self.vault_box_repo.spend_box(tx.inputs.first().box_id).await;

                    let first_vault_output = tx.outputs.get(1).unwrap().clone();
                    let as_box = AsBox(
                        first_vault_output.clone(),
                        VaultUtxo::try_from_box(first_vault_output).unwrap(),
                    );
                    self.vault_box_repo.put_confirmed(Confirmed(as_box)).await;

                    // Add withdrawals
                    for output in tx.outputs.iter().skip(2) {
                        self.withdrawal_repo
                            .put_confirmed(Confirmed(output.clone()))
                            .await;
                    }
                } else {
                    // println!("tx@ height {}", tx.outputs.first().creation_height);
                    // Vault deposit TX (TODO)
                    for output in tx.outputs {
                        if output.ergo_tree == VAULT_CONTRACT.clone() {
                            println!("Box_id {} is  a vault UTxO", output.box_id());
                            let as_box = AsBox(output.clone(), VaultUtxo::try_from_box(output).unwrap());
                            self.vault_box_repo.put_confirmed(Confirmed(as_box)).await;

                            // let constraints = NotarizedReportConstraints {
                            //     term_cells: vec![
                            //         proto_term_cell(u64::from(MIN_SAFE_BOX_VALUE), vec![], vec![0]),
                            //         proto_term_cell(500_000, vec![], vec![0]),
                            //     ],
                            //     last_progress_point: ProgressPoint {
                            //         chain_id: ChainId::from(0),
                            //         point: Point::from(1138759),
                            //     },
                            //     max_tx_size: spectrum_chain_connector::Kilobytes(3.0),
                            //     estimated_number_of_byzantine_nodes: 0,
                            // };
                            // let utxos = self.vault_box_repo.collect(constraints).await.unwrap();
                            // println!("Collected: {:?}", utxos);
                        }
                    }
                }
            }
            TxEvent::UnappliedTx(tx) => {
                // If the first output is for the miner's fee and the second output is guarded by
                // the vault contract, we can be sure that this TX is for report notarization.
                if tx.outputs.first().ergo_tree != MINERS_FEE_ADDRESS.script().unwrap() {
                    return;
                }
                if let Some(first_vault_output) = tx.outputs.get(1) {
                    if let Some(num_vault_outputs) = self.get_num_new_vault_utxos(first_vault_output) {
                        for input in tx.inputs {
                            let box_id = input.box_id;

                            // Add back previous vault boxes
                            self.vault_box_repo.unspend_box(box_id).await;
                        }

                        for output in tx.outputs.iter().skip(1).take(num_vault_outputs) {
                            self.vault_box_repo.remove(output.box_id()).await;
                        }

                        // Remove withdrawals
                        for output in tx.outputs.iter().skip(1 + num_vault_outputs) {
                            self.withdrawal_repo.remove(output.box_id()).await;
                        }
                    }
                }
            }
        }
    }

    /// Returns `Some(num_new_vault_utxos)` is the TX was initiated by a spectrum-network
    /// vault-manager, `None` otherwise.
    fn get_num_new_vault_utxos(&self, ergo_box: &ErgoBox) -> Option<usize> {
        if ergo_box.ergo_tree == self.vault_contract {
            let r4 = ergo_box
                .additional_registers
                .get(NonMandatoryRegisterId::R4)
                .unwrap();

            let RegisterValue::Parsed(c) = r4 else {
                return None;
            };
            let Literal::Int(num_vault_outputs) = c.v else {
                return None;
            };
            Some(num_vault_outputs as usize)
        } else {
            None
        }
    }

    async fn is_vault_withdrawal_tx(&self, tx: &Transaction) -> bool {
        // If the first output is for the miner's fee and the second output is guarded by
        // the vault contract, we can be sure that this TX is for report notarization.
        // This is necessary but insufficient:
        // For real TX:
        //  - OUTPUT(0): miner fee
        //  - OUTPUT(1): SN funding UTXO
        //  - OUTPUTs 2...n: withdrawals
        //  - INPUTS: every input UTXO should be Guarded by contract and have address in R4.
        //            Don't need to check this since it should be in vault_box_repo
        //  - Check data-inputs for current committee.
        //
        if tx.outputs.len() <= 2
            || tx.inputs.len() != 1
            || tx.outputs.first().ergo_tree != MINERS_FEE_ADDRESS.script().unwrap()
            || tx.outputs.get(1).unwrap().ergo_tree != self.vault_contract
            || tx.data_inputs.is_none()
        {
            return false;
        }

        // Check that input box is a known vault-UTxO
        if !self.vault_box_repo.may_exist(tx.inputs.first().box_id).await {
            return false;
        }

        // Check data inputs
        let Some(data_inputs) = &tx.data_inputs else {
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
}
