use ergo_lib::{chain::transaction::TxId, ergotree_ir::chain::ergo_box::BoxId};
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::{ChainTxEvent, InboundValue, SpectrumTx, SpectrumTxType, VaultBalance};
use spectrum_ledger::{
    cell::{ProgressPoint, SValue, TermCell},
    interop::Point,
    ChainId,
};

use crate::{
    script::{ErgoInboundCell, ErgoTermCell},
    vault_utxo::VaultUtxo,
    AncillaryVaultInfo,
};

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum ErgoTxEvent {
    /// A new set of TXs are made on-chain for a given progress point.
    Applied(SpectrumErgoTx),
    /// When the chain experiences a rollback, movements of value must be unapplied.
    Unapplied(SpectrumErgoTx),
}

impl ErgoTxEvent {
    pub fn get_height(&self) -> u32 {
        match self {
            ErgoTxEvent::Applied(tx) | ErgoTxEvent::Unapplied(tx) => tx.progress_point,
        }
    }
}

impl From<ErgoTxEvent> for ChainTxEvent<BoxId, AncillaryVaultInfo> {
    fn from(value: ErgoTxEvent) -> Self {
        match value {
            ErgoTxEvent::Applied(tx) => ChainTxEvent::Applied(SpectrumTx::from(tx)),
            ErgoTxEvent::Unapplied(tx) => ChainTxEvent::Unapplied(SpectrumTx::from(tx)),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub struct SpectrumErgoTx {
    pub progress_point: u32,
    pub tx_id: TxId,
    pub tx_type: ErgoTxType,
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq, Clone)]
pub enum ErgoTxType {
    /// Spectrum Network deposit transaction
    Deposit {
        /// Value that is inbound to Spectrum-network
        imported_value: Vec<ErgoInboundCell>,
        vault_info: (VaultUtxo, AncillaryVaultInfo),
    },

    /// Spectrum Network withdrawal transaction
    Withdrawal {
        /// Value that was successfully exported from Spectrum-network to some recipient on-chain.
        exported_value: Vec<ErgoTermCell>,
        vault_info: (VaultUtxo, AncillaryVaultInfo),
    },

    NewUnprocessedDeposit(ErgoInboundCell),
    RefundedDeposit(ErgoInboundCell),
}

impl From<SpectrumErgoTx> for SpectrumTx<BoxId, AncillaryVaultInfo> {
    fn from(value: SpectrumErgoTx) -> Self {
        let SpectrumErgoTx {
            progress_point,
            tx_type,
            ..
        } = value;
        let progress_point = ProgressPoint {
            chain_id: ChainId::from(0),
            point: Point::from(progress_point as u64),
        };
        match tx_type {
            ErgoTxType::Deposit {
                imported_value,
                vault_info: (vault_utxo, ancillary_info),
            } => {
                let imported_value = imported_value.into_iter().map(InboundValue::from).collect();

                let vault_balance = VaultBalance {
                    value: SValue::from(&vault_utxo),
                    on_chain_characteristics: ancillary_info,
                };
                SpectrumTx {
                    progress_point,
                    tx_type: SpectrumTxType::Deposit {
                        imported_value,
                        vault_balance,
                    },
                }
            }
            ErgoTxType::Withdrawal {
                exported_value,
                vault_info: (vault_utxo, ancillary_info),
            } => {
                let exported_value = exported_value.into_iter().map(TermCell::from).collect();
                let vault_balance = VaultBalance {
                    value: SValue::from(&vault_utxo),
                    on_chain_characteristics: ancillary_info,
                };
                SpectrumTx {
                    progress_point,
                    tx_type: SpectrumTxType::Withdrawal {
                        exported_value,
                        vault_balance,
                    },
                }
            }
            ErgoTxType::NewUnprocessedDeposit(inbound_cell) => {
                let inbound_value = InboundValue::from(inbound_cell);
                SpectrumTx {
                    progress_point,
                    tx_type: SpectrumTxType::NewUnprocessedDeposit(inbound_value),
                }
            }

            ErgoTxType::RefundedDeposit(inbound_cell) => {
                let inbound_value = InboundValue::from(inbound_cell);
                SpectrumTx {
                    progress_point,
                    tx_type: SpectrumTxType::RefundedDeposit(inbound_value),
                }
            }
        }
    }
}
