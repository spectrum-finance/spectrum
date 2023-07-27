use std::fmt::{Debug, Formatter};

use elliptic_curve::ScalarPrimitive;
use k256::elliptic_curve::group::GroupEncoding;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::elliptic_curve::Error;
use k256::{elliptic_curve, EncodedPoint, ProjectivePoint, Secp256k1};
use serde::Serialize;

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_vrf::vrf::ECVRFProof;

use crate::block::{BlockBody, BlockHeader, BlockId};
use crate::transaction::{Transaction, TxId};

pub mod block;
pub mod cell;
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

#[derive(
    Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into,
)]
pub struct KESSignature(spectrum_kes::KESSignature<Secp256k1>);

impl Debug for KESSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("sig")
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, derive_more::From, derive_more::Into,
)]
#[serde(try_from = "VRFProofRaw", into = "VRFProofRaw")]
pub struct VRFProof(ECVRFProof<Secp256k1>);

#[derive(serde::Serialize, serde::Deserialize)]
struct VRFProofRaw {
    gamma: Vec<u8>,
    c: ScalarPrimitive<Secp256k1>,
    s: ScalarPrimitive<Secp256k1>,
}

impl Into<VRFProofRaw> for VRFProof {
    fn into(self) -> VRFProofRaw {
        VRFProofRaw {
            gamma: self.0.gamma.to_bytes().to_vec(),
            c: self.0.c.into(),
            s: self.0.s.into(),
        }
    }
}

impl TryFrom<VRFProofRaw> for VRFProof {
    type Error = Error;
    fn try_from(value: VRFProofRaw) -> Result<Self, Self::Error> {
        let gamma = EncodedPoint::from_bytes(&*value.gamma)
            .map(|r| ProjectivePoint::from_encoded_point(&r).unwrap())?;
        Ok(VRFProof(ECVRFProof {
            gamma,
            c: value.c.into(),
            s: value.s.into(),
        }))
    }
}
