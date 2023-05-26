use spectrum_crypto::digest::{Blake2b, Blake2bDigest256, Digest256};

use crate::block::BlockId;

pub mod block;
pub mod eval;
pub mod ledger_view;
pub mod linking;
pub mod sbox;
pub mod transaction;
pub mod validation;

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

#[derive(Copy, Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum ModifierType {
    BlockHeader,
    BlockBody,
    Transaction,
}

/// Provides digest used across the system for authentication.
pub trait SystemDigest {
    fn digest(&self) -> Blake2bDigest256;
}