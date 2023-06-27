use nonempty::NonEmpty;

use spectrum_ledger::cell::{CellPtr, DatumRef, CellCore, ScriptRef, AnyCell};
use spectrum_ledger::transaction::Transaction;
use spectrum_move::{SerializedModule, SerializedValue};

pub mod validation;
pub mod eval;
pub mod linking;

#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum LedgerStateError {
    #[error("Invalid transaction")]
    InvalidTransaction,
}

/// Sync API to ledger state.
pub trait LedgerState {
    /// Get box by pointer from ledger state.
    fn get(&self, ptr: CellPtr) -> Option<AnyCell>;
    /// Get reference script.
    fn get_ref_script(&self, script_ref: ScriptRef) -> Option<SerializedModule>;
    /// Get reference datum.
    fn get_ref_datum(&self, datum_ref: DatumRef) -> Option<SerializedValue>;
    /// Apply transaction batch.
    fn apply_transactions(&self, txs: &NonEmpty<Transaction>) -> Result<(), LedgerStateError>;
}
