use spectrum_crypto::digest::{Blake2bDigest256, Digest};
use spectrum_crypto::pubkey::PublicKey;

use crate::interop::Effect;
use crate::transaction::Transaction;
use crate::{BlockNo, SlotNo, VRFProof};

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
pub struct ProtocolVer(u16);

impl ProtocolVer {
    pub const INITIAL: ProtocolVer = ProtocolVer(1);
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum BlockSectionId {
    Header(BlockId),
    Payload(BlockId),
}

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct HeaderBody {
    pub prev_id: BlockId,
    pub block_num: BlockNo,
    pub slot_num: SlotNo,
    pub vrf_pk: PublicKey,
    pub leader_proof: VRFProof,
    pub seed_proof: VRFProof,
    pub block_body_hash: Blake2bDigest256,
    pub protocol_version: ProtocolVer,
}

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub id: BlockId,
    pub body: HeaderBody,
    pub body_signature: Vec<u8>,
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
