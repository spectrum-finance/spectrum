use spectrum_ledger::cell::{CellPtr, DatumRef, Owner, ScriptRef};
use spectrum_ledger::transaction::{
    DatumWitness, LinkedScriptInv, LinkedTransaction, ScriptInv, ScriptWitness, Transaction,
};
use spectrum_ledger::SystemDigest;

use crate::state::LedgerState;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum LinkingError {
    MissingInput(CellPtr),
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

pub struct LedgerTxLinker<L> {
    pub ledger: L,
}

impl<L> TxLinker for LedgerTxLinker<L>
where
    L: LedgerState,
{
    fn link_transaction(&self, tx: Transaction) -> Result<LinkedTransaction, LinkingError> {
        let digest = tx.digest();
        let Transaction {
            inputs,
            reference_inputs,
            invokations,
            evaluated_outputs,
            witness,
        } = tx;
        let mut linked_inputs = vec![];
        for (ix, (pt, maybe_sig_ix)) in inputs.into_iter().enumerate() {
            if let Some(bx) = self.ledger.get(pt) {
                match (&bx.owner(), maybe_sig_ix) {
                    (Owner::ProveDlog(_), Some(sig_ix)) => {
                        if let Some(sig) = witness.signatures.get(sig_ix as usize) {
                            linked_inputs.push((bx, Some(sig.clone())));
                        } else {
                            return Err(LinkingError::MissingSignature(ix));
                        }
                    }
                    (Owner::ScriptHash(_), None) => linked_inputs.push((bx, None)),
                    _ => return Err(LinkingError::MalformedInput(ix)),
                }
            } else {
                return Err(LinkingError::MissingInput(pt));
            }
        }
        let mut linked_ref_inputs = vec![];
        for pt in reference_inputs {
            if let Some(bx) = self.ledger.get(pt) {
                linked_ref_inputs.push(bx);
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
                                if let Some(datum) = self.ledger.get_ref_datum(*datum_ref) {
                                    maybe_datum = Some(datum);
                                }
                            }
                            DatumWitness::Datum(datum) => {}
                        }
                    }
                }
                let script = match script_wit {
                    ScriptWitness::ScriptRef(sc_ref) => {
                        if let Some(script) = self.ledger.get_ref_script(*sc_ref) {
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
