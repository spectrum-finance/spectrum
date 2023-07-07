use nonempty::NonEmpty;

use spectrum_crypto::digest::Blake2bDigest256;

use crate::block::BlockId;
use crate::cell::{AnyCell, CellId};
use crate::transaction::TxId;
use crate::ChainId;

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct Point(u64);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct Source(ChainId, Point);

/// Identifier derived from external value carrying unit.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeriferalId(Blake2bDigest256);

// Bundled outbound transactions
pub struct CertBundle(NonEmpty<[u8; 32]>);

pub struct IBlockCert();

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct EffectId(Blake2bDigest256);

/// Events observed in external system affecting the state of Spectrum.
#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Effect {
    /// Value incoming from external system.
    Imported(AnyCell),
    /// Elimination of a terminal cell in result of outbound transaction.
    Exported(CellId),
    /// Revokation of an initial cell due to rollback on external system.
    Revoked(CellId),
    /// External system reached new point.
    Progressed(Point),
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ApplyEffects {
    pub id: TxId,
    pub source: Source,
    pub effects: Vec<EffectId>,
}
