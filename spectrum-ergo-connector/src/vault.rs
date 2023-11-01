use ergo_lib::{
    chain::transaction::Transaction,
    ergotree_ir::{
        chain::ergo_box::{ErgoBox, NonMandatoryRegisterId, RegisterValue},
        ergo_tree::ErgoTree,
        mir::constant::Literal,
    },
    wallet::miner_fee::MINERS_FEE_ADDRESS,
};
use spectrum_chain_connector::TxEvent;
use spectrum_offchain::data::unique_entity::Confirmed;

use crate::rocksdb::{
    vault_boxes::{VaultBoxRepo, VaultBoxRepoRocksDB},
    withdrawals::{WithdrawalRepo, WithdrawalRepoRocksDB},
};

pub struct VaultHandler {
    vault_box_repo: VaultBoxRepoRocksDB,
    withdrawal_repo: WithdrawalRepoRocksDB,
    vault_contract: ErgoTree,
}

impl VaultHandler {
    async fn handle(&mut self, event: TxEvent<Transaction>) {
        match event {
            TxEvent::AppliedTx(tx) => {
                // If the first output is for the miner's fee and the second output is guarded by
                // the vault contract, we can be sure that this TX is for report notarization.
                if tx.outputs.first().ergo_tree != MINERS_FEE_ADDRESS.script().unwrap() {
                    return;
                }
                if let Some(first_vault_output) = tx.outputs.get(1) {
                    if let Some(num_vault_outputs) = self.get_num_new_vault_utxos(first_vault_output) {
                        for input in tx.inputs {
                            let box_id = input.box_id;

                            // Spend input vault boxes
                            self.vault_box_repo.spend_box(box_id).await;
                        }

                        // Add new vault outputs
                        for output in tx.outputs.iter().skip(1).take(num_vault_outputs) {
                            self.vault_box_repo.put_confirmed(Confirmed(output.clone())).await;
                        }

                        // Add withdrawals
                        for output in tx.outputs.iter().skip(1 + num_vault_outputs) {
                            self.withdrawal_repo
                                .put_confirmed(Confirmed(output.clone()))
                                .await;
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

                            // Add back previous vault boxes (TODO)
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
                panic!("");
            };
            let Literal::Int(num_vault_outputs) = c.v else {
                panic!("");
            };
            Some(num_vault_outputs as usize)
        } else {
            None
        }
    }
}
