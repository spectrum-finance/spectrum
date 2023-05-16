use spectrum_move::{SerializedModule, SerializedValue};

use crate::sbox::{BoxPointer, DatumRef, SBox, ScriptRef};

pub trait Ledger {
    /// Get box by pointer from ledger state.
    fn get(&self, pt: BoxPointer) -> Option<SBox>;
    /// Get reference script.
    fn get_ref_script(&self, script_ref: ScriptRef) -> Option<SerializedModule>;
    /// Get reference datum.
    fn get_ref_datum(&self, datum_ref: DatumRef) -> Option<SerializedValue>;
}
