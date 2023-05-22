use spectrum_crypto::digest::Blake2bDigest256;

use crate::transaction::Transaction;
use crate::Height;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockId(Blake2bDigest256);

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum BlockSectionId {
    Header(BlockId),
    Payload(BlockId),
}

// #[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
// pub struct BlockHeaderV1 {
//     pub id: BlockId,
//     pub height: Height,
// }

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub id: BlockId,
    pub height: Height,
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct BlockPayload(Vec<Transaction>);

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum BlockSection {
    Header(BlockHeader),
    //Payload(Vec<Transaction>),
}
