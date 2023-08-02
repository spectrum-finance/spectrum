use spectrum_ledger::cell::{AnyCell, CellMeta, CellPtr, DatumRef, Owner, ScriptRef};
use spectrum_ledger::transaction::{
    DatumWitness, LinkedScriptInv, LinkedTransaction, ScriptInv, ScriptWitness, Transaction, TransactionBody,
};
use spectrum_ledger::SystemDigest;

use crate::state::Cells;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum LinkingError {
    MissingInput(CellPtr),
    NonConsumableInput(CellPtr),
    MissingRefInput(CellPtr),
    MissingScript(),
    MissingDatum(DatumRef),
    MissingSignature(/*input_index*/ usize),
    MalformedInput(/*input_index*/ usize),
    UnresolvedScriptRef(ScriptRef),
}

pub trait TxLinker {
    /// Resolve all references within the given transaction.
    fn link_transaction(&self, tx: Transaction) -> Result<LinkedTransaction, LinkingError>;
}

pub struct LedgerTxLinker<P> {
    pub pool: P,
}

impl<P> TxLinker for LedgerTxLinker<P>
where
    P: Cells,
{
    fn link_transaction(&self, tx: Transaction) -> Result<LinkedTransaction, LinkingError> {
        let digest = tx.digest();
        let Transaction {
            body:
                TransactionBody {
                    inputs,
                    reference_inputs,
                    invokations,
                    evaluated_outputs,
                },
            witness,
        } = tx;
        let mut linked_inputs = vec![];
        for (ix, (pt, maybe_sig_ix)) in inputs.into_iter().enumerate() {
            if let Some(cell) = self.pool.get(pt) {
                if let CellMeta {
                    cell: AnyCell::Mut(active_cell),
                    ancors,
                } = cell
                {
                    match (&active_cell.owner, maybe_sig_ix) {
                        (Owner::ProveDlog(_), Some(sig_ix)) => {
                            if let Some(sig) = witness.signatures.get(sig_ix as usize) {
                                linked_inputs.push((
                                    CellMeta {
                                        cell: active_cell,
                                        ancors,
                                    },
                                    Some(sig.clone()),
                                ));
                            } else {
                                return Err(LinkingError::MissingSignature(ix));
                            }
                        }
                        (Owner::ScriptHash(_), None) => linked_inputs.push((
                            CellMeta {
                                cell: active_cell,
                                ancors,
                            },
                            None,
                        )),
                        _ => return Err(LinkingError::MalformedInput(ix)),
                    }
                } else {
                    return Err(LinkingError::NonConsumableInput(pt));
                }
            } else {
                return Err(LinkingError::MissingInput(pt));
            }
        }
        let mut linked_ref_inputs = vec![];
        for pt in reference_inputs {
            if let Some(mcell) = self.pool.get(pt) {
                linked_ref_inputs.push(mcell.cell);
            } else {
                return Err(LinkingError::MissingRefInput(pt));
            }
        }
        let mut linked_invokations = vec![];
        for ScriptInv {
            script: script_ix,
            datum: maybe_datum_ix,
            function,
            args,
            targs,
        } in invokations
        {
            if let Some(script_wit) = witness.scripts.get(script_ix as usize) {
                let mut maybe_datum = None;
                if let Some(datum_ix) = maybe_datum_ix {
                    if let Some(datum_wit) = witness.data.get(datum_ix as usize) {
                        match datum_wit {
                            DatumWitness::DatumRef(datum_ref) => {
                                if let Some(datum) = self.pool.get_ref_datum(*datum_ref) {
                                    maybe_datum = Some(datum);
                                }
                            }
                            DatumWitness::Datum(datum) => {}
                        }
                    }
                }
                let script = match script_wit {
                    ScriptWitness::ScriptRef(sc_ref) => {
                        if let Some(script) = self.pool.get_ref_script(*sc_ref) {
                            script
                        } else {
                            return Err(LinkingError::UnresolvedScriptRef(*sc_ref));
                        }
                    }
                    ScriptWitness::Script(script) => script.clone(),
                };
                linked_invokations.push(LinkedScriptInv {
                    script,
                    datum: maybe_datum,
                    function,
                    args,
                    targs,
                });
            } else {
                return Err(LinkingError::MissingScript());
            }
        }
        Ok(LinkedTransaction {
            inputs: linked_inputs,
            reference_inputs: linked_ref_inputs,
            invokations: linked_invokations,
            evaluated_outputs,
            hash: digest,
        })
    }
}
