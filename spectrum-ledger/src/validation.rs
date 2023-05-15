use crate::sbox::BoxRef;
use crate::transaction::EvaluatedTransaction;

pub enum TransactionEffect {
    Drop(BoxRef),
    //todo ...
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct TxRuleId(u16);

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum ConsensusRuleViolation {
    //todo
}

pub trait TxValidator {
    /// Validate evaluated transaction and produce final effects to be applied to the ledger state.
    fn validate_transaction(
        &self,
        tx: EvaluatedTransaction,
    ) -> Result<Vec<TransactionEffect>, ConsensusRuleViolation>;
}
