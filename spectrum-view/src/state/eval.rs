use std::collections::HashMap;

use k256::schnorr::signature::Verifier;
use k256::schnorr::VerifyingKey;

use spectrum_ledger::cell::{ActiveCell, CellMeta, Owner, ProgressPoint, ScriptHash};
use spectrum_ledger::interop::Point;
use spectrum_ledger::transaction::{EvaluatedTransaction, LinkedTransaction};
use spectrum_ledger::ChainId;
use spectrum_move::{GasUnits, SerializedModule};

use crate::state::CellPool;

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
    pub owned_inputs: Vec<ActiveCell>,
}

impl InvokationScope {
    pub fn new(script: SerializedModule) -> Self {
        Self {
            script,
            owned_inputs: Vec::new(),
        }
    }
    pub fn add_owned_input(&mut self, cell: ActiveCell) {
        self.owned_inputs.push(cell);
    }
}

pub struct ProgrammableTxEvaluator<P> {
    pub pool: P,
}

impl<P> TxEvaluator for ProgrammableTxEvaluator<P>
where
    P: CellPool,
{
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
        let mut converged_ancors: HashMap<ChainId, Point> = HashMap::new();
        for (ix, (CellMeta { cell: i, ancors }, maybe_sig)) in inputs.into_iter().enumerate() {
            for ProgressPoint { chain_id, point } in ancors {
                if let Some(max_point) = converged_ancors.get(&chain_id) {
                    if *max_point >= point {
                        continue;
                    }
                }
                converged_ancors.insert(chain_id, point);
            }
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
        let converged_ancors = converged_ancors
            .into_iter()
            .filter(|(chain_id, point)| self.pool.progress_of(*chain_id) < *point) // remove reached ancors.
            .map(|(chain_id, point)| ProgressPoint { chain_id, point })
            .collect::<Vec<_>>();
        let outputs = evaluated_outputs
            .into_iter()
            .map(|cell| CellMeta {
                cell,
                ancors: converged_ancors.clone(),
            })
            .collect();
        // todo: perform invokations, add computed outputs to `evaluated_outputs`;
        Ok(EvaluatedTransaction {
            inputs: verified_inputs,
            outputs,
        })
    }
}
