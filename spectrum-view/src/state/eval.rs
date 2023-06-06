use std::collections::HashMap;

use k256::schnorr::signature::Verifier;
use k256::schnorr::VerifyingKey;

use spectrum_ledger::sbox::{Owner, SBox, ScriptHash};
use spectrum_ledger::transaction::{EvaluatedTransaction, LinkedTransaction};
use spectrum_move::{GasUnits, SerializedModule};

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct EvaluationError {
    pub at_input: usize,
    pub gas_consumed: GasUnits,
}

pub trait TxEvaluator {
    /// Evaluate scripts and check signatures within the given linked transaction.
    fn evaluate_transaction(&self, tx: LinkedTransaction) -> Result<EvaluatedTransaction, EvaluationError>;
}

pub struct InvokationScope {
    pub script: SerializedModule,
    pub owned_inputs: Vec<SBox>,
}

impl InvokationScope {
    pub fn new(script: SerializedModule) -> Self {
        Self {
            script,
            owned_inputs: Vec::new(),
        }
    }
    pub fn add_owned_input(&mut self, bx: SBox) {
        self.owned_inputs.push(bx);
    }
}

pub struct ProgrammableTxEvaluator {}

impl TxEvaluator for ProgrammableTxEvaluator {
    fn evaluate_transaction(
        &self,
        LinkedTransaction {
            inputs,
            reference_inputs,
            invokations,
            mut evaluated_outputs,
            hash,
        }: LinkedTransaction,
    ) -> Result<EvaluatedTransaction, EvaluationError> {
        let mut verified_inputs = vec![];
        let mut invokation_scopes: HashMap<ScriptHash, InvokationScope> = invokations
            .iter()
            .map(|i| {
                (
                    ScriptHash::from(i.script.clone()),
                    InvokationScope::new(i.script.clone()),
                )
            })
            .collect();
        for (ix, (i, maybe_sig)) in inputs.into_iter().enumerate() {
            if let Some(sig) = maybe_sig {
                match i.owner {
                    Owner::ProveDlog(pk) => {
                        let vk = VerifyingKey::try_from(pk).unwrap();
                        if vk.verify(hash.as_ref(), &sig.into()).is_ok() {
                            verified_inputs.push(i);
                        } else {
                            return Err(EvaluationError {
                                at_input: ix,
                                gas_consumed: GasUnits::ZERO,
                            });
                        }
                    }
                    Owner::ScriptHash(sh) => {
                        if let Some(iscope) = invokation_scopes.get_mut(&sh) {
                            iscope.add_owned_input(i);
                        }
                    }
                }
            }
        }
        // todo: perform invokations, add computed outputs to `evaluated_outputs`;
        Ok(EvaluatedTransaction {
            inputs: verified_inputs,
            outputs: evaluated_outputs,
        })
    }
}
