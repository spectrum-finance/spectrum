use nonempty::NonEmpty;

use spectrum_crypto::digest::{Blake2bDigest256, Digest};

use crate::interop::Effect;
use crate::transaction::Transaction;
use crate::SlotNo;

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
pub struct BlockId(Blake2bDigest256);

impl BlockId {
    pub const ORIGIN: BlockId = BlockId(Digest::zero());
    pub fn random() -> BlockId {
        BlockId(Digest::random())
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockVer(u16);

impl BlockVer {
    pub const INITIAL: BlockVer = BlockVer(1);
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum BlockSectionId {
    Header(BlockId),
    Payload(BlockId),
}

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub id: BlockId,
    pub slot: SlotNo,
    pub version: BlockVer,
}

impl BlockHeader {
    pub const ORIGIN: BlockHeader = BlockHeader {
        id: BlockId::ORIGIN,
        slot: SlotNo::ORIGIN,
        version: BlockVer::INITIAL,
    };
}

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockBody {
    pub id: BlockId,
    pub effects: Vec<Effect>,
    pub txs: Vec<Transaction>,
}

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize, derive_more::From)]
pub enum BlockSection {
    Header(BlockHeader),
    Body(BlockBody),
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum BlockSectionType {
    Header,
    Body,
}
