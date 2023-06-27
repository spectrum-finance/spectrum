use nonempty::NonEmpty;

use spectrum_crypto::digest::Blake2bDigest256;

use crate::block::BlockId;
use crate::cell::{CellId, ImportedCell};

/// Identifier derived from external value carrying unit.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeriferalId(Blake2bDigest256);

// Bundled outbound transactions
pub struct CertBundle(NonEmpty<[u8; 32]>);

pub struct IBlockCert();

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct IEffectId(Blake2bDigest256);

/// State transitions coming from external system.
pub enum IEffect {
    /// Value incoming from external system.
    InboundCreated(ImportedCell),
    /// Certification of outbound value transfer.
    OutboundCertified(CertBundle),
    /// Elimination of local box in result of outbound transaction.
    Eliminated(CellId),
}

pub struct IBlockCandidate {
    pub id: IBlockId,
    pub height: u64,
    pub effects: Vec<IEffectId>,
}

pub struct IBlock {
    pub id: IBlockId,
    pub height: u64,
    pub cert: IBlockCert,
    pub effects: Vec<IEffect>,
}

pub struct IBlockPtr {
    pub id: IBlockId,
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
pub struct IBlockId(Blake2bDigest256);

/// A cell which can either contain `IBlock` itself ot a ppointer to it.
pub enum IBlockCell {
    Fresh(IBlock),
    Moved(IBlockPtr),
}
