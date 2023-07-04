use nonempty::NonEmpty;

use spectrum_crypto::digest::Blake2bDigest256;

use crate::block::BlockId;
use crate::cell::{CellId, InitCell};

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct Point(u64);

/// Identifier derived from external value carrying unit.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeriferalId(Blake2bDigest256);

// Bundled outbound transactions
pub struct CertBundle(NonEmpty<[u8; 32]>);

pub struct IBlockCert();

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct ExtEffId(Blake2bDigest256);

/// Events observed in external system affecting the state of Spectrum.
pub enum ExtEff {
    /// Value incoming from external system.
    Imported(InitCell),
    /// Elimination of a terminal cell in result of outbound transaction.
    Exported(CellId),
    /// Revokation of an initial cell due to rollback on external system.
    Revoked(CellId),
    /// External system reached new point.
    Progressed(Point),
}

pub struct EffBlockCandidate {
    pub id: EffBlockId,
    pub height: u64,
    pub effects: Vec<ExtEffId>,
}

pub struct EffBlock {
    pub id: EffBlockId,
    pub height: u64,
    pub cert: IBlockCert,
    pub effects: Vec<ExtEff>,
}

pub struct EffBlockPtr {
    pub id: EffBlockId,
    pub block_id: BlockId,
}

#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Hash,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    derive_more::From,
    derive_more::Into,
)]
pub struct EffBlockId(Blake2bDigest256);
