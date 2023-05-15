use crate::sbox::{DatumRef, ScriptHash};
use crate::transaction::{LinkedTransaction, Transaction};

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum LinkingError {
    MissingScript(ScriptHash),
    MissingDatum(DatumRef),
    MissingSignature(/*input_index*/ u16),
}

pub trait TxLinker {
    /// Resolve all references within the given transaction.
    fn link_transaction(&self, tx: Transaction) -> Result<LinkedTransaction, LinkingError>;
}
