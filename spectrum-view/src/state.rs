use nonempty::NonEmpty;

use spectrum_ledger::sbox::{BoxPtr, DatumRef, SBox, ScriptRef};
use spectrum_ledger::transaction::Transaction;
use spectrum_move::{SerializedModule, SerializedValue};

#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum LedgerStateError {
    #[error("Invalid transaction")]
    InvalidTransaction,
}

/// Sync API to ledger state.
pub trait LedgerState {
    /// Get box by pointer from ledger state.
    fn get(&self, ptr: BoxPtr) -> Option<SBox>;
    /// Get reference script.
    fn get_ref_script(&self, script_ref: ScriptRef) -> Option<SerializedModule>;
    /// Get reference datum.
    fn get_ref_datum(&self, datum_ref: DatumRef) -> Option<SerializedValue>;
    /// Apply transaction batch.
    fn apply_transactions(&self, txs: NonEmpty<Transaction>) -> Result<(), LedgerStateError>;
}
