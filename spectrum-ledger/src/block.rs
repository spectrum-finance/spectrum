use spectrum_crypto::digest::Blake2bDigest256;

use crate::transaction::Transaction;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockId(Blake2bDigest256);

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum BlockSectionId {
    Header(BlockId),
    Payload(BlockId),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockHeaderV1 {
    pub id: BlockId
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum BlockHeader {
    HeaderV1(BlockHeaderV1)
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockPayload(Vec<Transaction>);

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum BlockSection {
    Header(BlockHeader),
    Payload(Vec<Transaction>),
}
