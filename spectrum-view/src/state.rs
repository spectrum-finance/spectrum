use nonempty::NonEmpty;
use spectrum_ledger::block::BlockBody;

use spectrum_ledger::cell::{CellPtr, DatumRef, Cell, ScriptRef, OutputCell, InputCell};
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

pub trait LedgerStateWrite {
    /// Apply transaction batch.
    fn apply_block(&self, blk: &BlockBody) -> Result<(), LedgerStateError>;
}

/// Sync API to cell pool.
pub trait CellPool {
    /// Get cell by pointer.
    fn get(&self, ptr: CellPtr) -> Option<InputCell>;
    /// Get reference script.
    fn get_ref_script(&self, script_ref: ScriptRef) -> Option<SerializedModule>;
    /// Get reference datum.
    fn get_ref_datum(&self, datum_ref: DatumRef) -> Option<SerializedValue>;
}
