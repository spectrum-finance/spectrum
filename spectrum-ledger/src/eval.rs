use spectrum_move::GasUnits;

use crate::transaction::{EvaluatedTransaction, LinkedTransaction};

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct EvaluationError {
    pub at_input: usize,
    pub gas_consumed: GasUnits,
}

pub trait TxEvaluator {
    /// Evaluate scripts and check signatures within the given linked transaction.
    fn evaluate_transaction(&self, tx: LinkedTransaction) -> Result<EvaluatedTransaction, EvaluationError>;
}
