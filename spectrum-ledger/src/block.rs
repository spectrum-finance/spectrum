use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256, Digest};
use spectrum_crypto::pubkey::PublicKey;

use crate::interop::{ReportBody, ReportCertificate};
use crate::transaction::{TransactionBody, Witness};
use crate::{BlockNo, KESSignature, ModifierId, ModifierType, SlotNo, SystemDigest, VRFProof, VRFVKey};

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
    derive_more::Display,
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

pub trait Modifier {
    fn id(&self) -> ModifierId;
    fn tpe() -> ModifierType;
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum BlockSectionId {
    Header(BlockId),
    Body(BlockId),
}

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct HeaderBody {
    pub prev_id: BlockId,
    pub block_num: BlockNo,
    pub slot_num: SlotNo,
    pub vrf_vk: VRFVKey,
    /// VRF proof for seed and leadership.
    pub vrf_proof: VRFProof,
    /// Merkle Tree root hash of the block body.
    pub block_body_root: Blake2bDigest256,
    pub protocol_version: ProtocolVer,
}

impl SystemDigest for HeaderBody {
    fn digest(&self) -> Blake2bDigest256 {
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&self, &mut encoded).unwrap();
        blake2b256_hash(&*encoded)
    }
}

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub body: HeaderBody,
    pub body_signature: KESSignature,
}

impl Modifier for BlockHeader {
    fn id(&self) -> ModifierId {
        self.body.digest().into()
    }
    fn tpe() -> ModifierType {
        ModifierType::BlockHeader
    }
}

#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockBody {
    pub reports: Vec<ReportBody>,
    pub certificates: Vec<ReportCertificate>,
    pub txs: Vec<TransactionBody>,
    pub witnesses: Vec<Witness>,
}

impl SystemDigest for BlockBody {
    fn digest(&self) -> Blake2bDigest256 {
        todo!("Use root hash of the Merkle Tree here")
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum BlockSectionType {
    Header,
    Body,
}
