use spectrum_crypto::digest::Blake2bDigest256;

use crate::block::{BlockHeader, BlockId};

pub mod block;
pub mod sbox;
pub mod transaction;

#[derive(
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Copy,
    Clone,
    Hash,
    derive_more::Add,
    derive_more::Sub,
    derive_more::From,
    derive_more::Into,
    serde::Serialize,
    serde::Deserialize,
    Debug,
)]
pub struct SlotNo(u64);

impl SlotNo {
    pub const ORIGIN: SlotNo = SlotNo(0);
}

#[derive(
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Copy,
    Clone,
    Hash,
    derive_more::Add,
    derive_more::Sub,
    derive_more::From,
    derive_more::Into,
    serde::Serialize,
    serde::Deserialize,
    Debug,
)]
pub struct EpochNo(u64);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct ChainId(u16);

#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    derive_more::From,
    derive_more::Into,
)]
pub struct ModifierId(Blake2bDigest256);

impl From<BlockId> for ModifierId {
    fn from(blk: BlockId) -> Self {
        Self(Blake2bDigest256::from(blk))
    }
}

impl Into<BlockId> for ModifierId {
    fn into(self) -> BlockId {
        BlockId::from(self.0)
    }
}

#[derive(Clone, Eq, PartialEq, Debug, derive_more::From)]
pub enum Modifier {
    BlockHeader(BlockHeader),
    // BlockBody(BlockPayload),
    // Transaction(Transaction),
}

impl Modifier {
    pub fn id(&self) -> ModifierId {
        match self {
            Modifier::BlockHeader(bh) => ModifierId::from(bh.id),
            // Modifier::BlockBody(bb) => ModifierId::from(bb.id),
            // Modifier::Transaction(tx) => tx.id(),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum ModifierType {
    BlockHeader,
    // BlockBody,
    // Transaction,
}

/// Provides digest used across the system for authentication.
pub trait SystemDigest {
    fn digest(&self) -> Blake2bDigest256;
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into,
)]
pub struct SerializedModifier(pub Vec<u8>);
