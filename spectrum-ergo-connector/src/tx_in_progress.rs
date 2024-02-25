use derivative::Derivative;
use ergo_lib::{
    chain::transaction::Input,
    ergotree_ir::chain::ergo_box::{BoxId, ErgoBox},
};
use serde::{Deserialize, Serialize};
use spectrum_chain_connector::{InboundValue, NotarizedReport, PendingTxIdentifier};

use crate::{deposit::UnprocessedDeposit, script::ExtraErgoData};

pub trait IdentifyBy<T> {
    fn is_identified_by(&self, t: &T) -> bool;
}

pub trait Timestamped {
    fn get_timestamp(&self) -> i64;
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub enum TxInProgress {
    Withdrawal(WithdrawalInProgress),
    Deposit(DepositInProgress),
}

#[derive(Serialize, Deserialize, Clone, Debug, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct WithdrawalInProgress {
    pub report: NotarizedReport<ExtraErgoData>,
    pub vault_utxo_signed_input: Input,
    pub vault_utxo: ErgoBox,
    #[derivative(PartialEq = "ignore")]
    pub timestamp: i64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Derivative)]
#[derivative(PartialEq, Eq)]
pub struct DepositInProgress {
    pub unprocessed_deposits: Vec<UnprocessedDeposit>,
    pub vault_utxo_signed_input: Input,
    pub vault_utxo: ErgoBox,
    #[derivative(PartialEq = "ignore")]
    pub timestamp: i64,
}

impl IdentifyBy<PendingTxIdentifier<ExtraErgoData, BoxId>> for TxInProgress {
    fn is_identified_by(&self, t: &PendingTxIdentifier<ExtraErgoData, BoxId>) -> bool {
        match (self, t) {
            (TxInProgress::Withdrawal(e), PendingTxIdentifier::Withdrawal(notarized_report)) => {
                e.report == *notarized_report.as_ref()
            }
            (TxInProgress::Deposit(d), PendingTxIdentifier::Deposit(unprocessed_deposits)) => {
                let inbound_values: Vec<InboundValue<BoxId>> = d
                    .unprocessed_deposits
                    .clone()
                    .into_iter()
                    .map(InboundValue::from)
                    .collect();
                inbound_values == *unprocessed_deposits
            }
            _ => false,
        }
    }
}

impl Timestamped for TxInProgress {
    fn get_timestamp(&self) -> i64 {
        match self {
            TxInProgress::Deposit(d) => d.timestamp,
            TxInProgress::Withdrawal(report) => report.timestamp,
        }
    }
}
