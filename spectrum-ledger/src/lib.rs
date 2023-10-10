use std::fmt::Debug;

use serde::Serialize;

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};

use crate::block::{BlockBody, BlockHeader, BlockId};
use crate::transaction::{Transaction, TxId};

pub mod block;
pub mod cell;
pub mod consensus;
pub mod interop;
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
pub struct BlockNo(u64);

impl BlockNo {
    pub const ORIGIN: BlockNo = BlockNo(0);
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

pub const ERGO_CHAIN_ID: ChainId = ChainId(0);

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

impl From<TxId> for ModifierId {
    fn from(id: TxId) -> Self {
        Self(Blake2bDigest256::from(id))
    }
}

impl Into<BlockId> for ModifierId {
    fn into(self) -> BlockId {
        BlockId::from(self.0)
    }
}

/// Modifier with precomputed identifier.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ModifierRecord<M> {
    pub id: ModifierId,
    pub modifier: M,
}

#[derive(Clone, Eq, PartialEq, Debug, derive_more::From)]
pub enum Modifier {
    BlockHeader(BlockHeader),
    BlockBody(BlockBody),
    Transaction(Transaction),
}

impl Modifier {
    /// Compute ID of a modifier.
    /// Prefer to use this method only on new/unverified modifiers to avoid redundant computations.
    pub fn id(&self) -> ModifierId {
        match self {
            Modifier::BlockHeader(bh) => ModifierId::from(bh.body.digest()),
            Modifier::BlockBody(bb) => ModifierId::from(bb.digest()),
            Modifier::Transaction(tx) => ModifierId::from(tx.id()),
        }
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

/// Marker trait for stucts whose hashes can be derived from serialised repr.
trait DigestViaEncoder: Serialize {}

impl<T: DigestViaEncoder> SystemDigest for T {
    fn digest(&self) -> Blake2bDigest256 {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(self, &mut encoded).unwrap();
        blake2b256_hash(&*encoded)
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into,
)]
pub struct SerializedModifier(pub Vec<u8>);
