use spectrum_crypto::digest::Blake2bDigest256;
use spectrum_ledger::cell::{AnyCell, CellMeta, CellPtr, DatumRef, NativeCoin, ScriptRef};
use spectrum_ledger::consensus::AnyRuleId;
use spectrum_ledger::interop::{Effect, Point};
use spectrum_ledger::transaction::{EvaluatedTransaction, ValidTx};
use spectrum_ledger::{ChainId, EpochNo, VRFProof};
use spectrum_ledger::{DomainVKey, KESVKey, StakePoolId};
use spectrum_move::{SerializedModule, SerializedValue};

pub mod eval;
pub mod linking;

#[derive(Eq, PartialEq, Debug, thiserror::Error)]
pub enum LedgerStateError {
    #[error("Invalid transaction")]
    InvalidTransaction,
}

pub trait LedgerStateWrite {
    /// Apply valid transaction.
    fn apply_tx(&self, tx: ValidTx<EvaluatedTransaction>) -> Result<(), LedgerStateError>;
    /// Apply valid effect.
    fn apply_eff(&self, tx: ValidTx<Effect>) -> Result<(), LedgerStateError>;
    /// Rollback state to previous version.
    fn rollback(&self, tag: Blake2bDigest256);
}

/// Pool of cells.
pub trait Cells {
    /// Get cell by pointer.
    fn get_cell(&self, ptr: CellPtr) -> Option<CellMeta<AnyCell>>;
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
    fn get_pool_creds(&self, pool_id: StakePoolId) -> Option<(KESVKey, Vec<(ChainId, DomainVKey)>)>;
}

/// Stake distribution.
pub trait StakeDistribution {
    /// Query current stake managed by the given pool.
    fn get_stake(&self, pool_id: StakePoolId) -> NativeCoin;
}

/// Disabled consensus rules.
pub trait ConsensusRules {
    fn get_disabled_rules(&self) -> Vec<AnyRuleId>;
}

/// Hot stuff for consensus.
pub trait ConsensusIndexes {
    fn get_epoch_rand_proof(&self, epoch: EpochNo) -> Option<VRFProof>;
}
