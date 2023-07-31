use spectrum_ledger::block::BlockBody;
use spectrum_ledger::cell::{AnyCell, CellMeta, CellPtr, DatumRef, NativeCoin, ScriptRef};
use spectrum_ledger::ChainId;
use spectrum_ledger::consensus::{DomainVKey, KESVKey, StakePoolId};
use spectrum_ledger::interop::Point;
use spectrum_move::{SerializedModule, SerializedValue};

pub mod eval;
pub mod linking;
pub mod validation;

#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum LedgerStateError {
    #[error("Invalid transaction")]
    InvalidTransaction,
}

pub trait LedgerStateWrite {
    /// Apply transaction batch.
    fn apply_block(&self, blk: &BlockBody) -> Result<(), LedgerStateError>;
}

/// Pool of cells.
pub trait Cells {
    /// Get cell by pointer.
    fn get(&self, ptr: CellPtr) -> Option<CellMeta<AnyCell>>;
    /// Get progress of the given chain.
    fn progress_of(&self, chain_id: ChainId) -> Point;
    /// Get reference script.
    fn get_ref_script(&self, script_ref: ScriptRef) -> Option<SerializedModule>;
    /// Get reference datum.
    fn get_ref_datum(&self, datum_ref: DatumRef) -> Option<SerializedValue>;
}

/// Registered validator credentials.
pub trait ValidatorCredentials {
    /// Query validator credentials by his public VRF key.
    fn get(&self, pool_id: StakePoolId) -> Option<(KESVKey, Vec<(ChainId, DomainVKey)>)>;
}

/// Stake distribution.
pub trait StakeDistribution {
    /// Query current stake managed by the given pool.
    fn get(&self, pool_id: StakePoolId) -> NativeCoin;
}
