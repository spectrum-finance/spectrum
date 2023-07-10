use spectrum_ledger::cell::{AnyCell, CellRef, ActiveCell};
use spectrum_ledger::transaction::EvaluatedTransaction;

pub enum TransactionEffect {
    Drop(CellRef),
    Create(AnyCell),
    // todo: Mutation, CoinMinting ..
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct TxRuleId(u16);

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum ConsensusRuleViolation {}

pub trait TxValidator {
    /// Validate evaluated transaction and produce final effects to be applied to the ledger state.
    fn validate_transaction(
        &self,
        tx: EvaluatedTransaction,
    ) -> Result<Vec<TransactionEffect>, ConsensusRuleViolation>;
}

pub struct ConsensusTxValidator {}

impl TxValidator for ConsensusTxValidator {
    fn validate_transaction(
        &self,
        EvaluatedTransaction { inputs, outputs }: EvaluatedTransaction,
    ) -> Result<Vec<TransactionEffect>, ConsensusRuleViolation> {
        // todo: support input mutation, coin minting
        let mut effects = vec![];
        for i in inputs {
            effects.push(TransactionEffect::Drop(i.cref()))
        }
        for o in outputs {
            effects.push(TransactionEffect::Create(o.cell))
        }
        Ok(effects)
    }
}
