use std::collections::HashMap;

use k256::PublicKey;

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_move::{SerializedModule, SerializedValue};

use crate::interop::IEffectId;
use crate::transaction::TxId;
use crate::{ChainId, SystemDigest};

/// Stable cell identifier.
#[derive(
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Copy,
    Clone,
    Hash,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    derive_more::From,
)]
pub struct CellId(Blake2bDigest256);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct CellVer(u32);

impl CellVer {
    pub const INITIAL: CellVer = CellVer(0);
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct CellRef(pub CellId, pub CellVer);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum CellPtr {
    Id(CellId),
    Ref(CellRef),
}

#[derive(Eq, PartialEq, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct NativeCoin(u64);

#[derive(Eq, PartialEq, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct CustomAsset(u64);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct PolicyId(Blake2bDigest256);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct AssetId(Blake2bDigest256);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AssetRef(PolicyId, AssetId);

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SValue {
    pub native: NativeCoin,
    pub assets: HashMap<PolicyId, HashMap<AssetId, CustomAsset>>,
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct ScriptHash(Blake2bDigest256);

impl From<SerializedModule> for ScriptHash {
    fn from(sm: SerializedModule) -> Self {
        Self(blake2b256_hash(&*<Vec<u8>>::from(sm)))
    }
}

/// Where the script source can be found.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct ScriptRef(CellRef);

/// Where the datum source can be found.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct DatumRef(CellRef);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum Owner {
    ProveDlog(PublicKey),
    ScriptHash(ScriptHash),
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct DatumHash(Blake2bDigest256);

/// Additional data for bridge (e.g. validator to be used on the dst chain).
#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BridgeInputs();

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BoxDestination {
    target: ChainId,
    inputs: Option<BridgeInputs>,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CellCore {
    /// Monetary value attached to the box.
    pub value: SValue,
    /// Owner who can mutate the box.
    pub owner: Owner,
    /// Data attached to the box.
    pub datum: Option<DatumHash>,
    /// Destination chain of the box (where the value of the box is supposed to settle in the end).
    /// `None` if the box is supposed to remain on the multichain.
    pub dst: Option<BoxDestination>,
    /// Script that can be referenced by other transactions.
    pub reference_script: Option<SerializedModule>,
    /// Datum that can be referenced by other transactions.
    pub reference_datum: Option<SerializedValue>,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MutCell {
    /// Core cell
    pub core: CellCore,
    /// Monotonically increasing version of the box.
    pub ver: CellVer,
    /// ID of a transaction which created this cell.
    pub tx_id: TxId,
    pub index: u32,
}

impl MutCell {
    pub fn id(&self) -> CellId {
        todo!()
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ImportedCell {
    /// Core cell
    pub core: CellCore,
    /// ID of an inbound effect which created this cell.
    pub eff_id: IEffectId,
}

impl ImportedCell {
    pub fn id(&self) -> CellId {
        todo!()
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum AnyCell {
    Mut(MutCell),
    Imported(ImportedCell),
}

impl AnyCell {
    pub fn id(&self) -> CellId {
        match self {
            AnyCell::Mut(mc) => mc.id(),
            AnyCell::Imported(ic) => ic.id(),
        }
    }

    pub fn ver(&self) -> CellVer {
        match self {
            AnyCell::Mut(mc) => mc.ver,
            AnyCell::Imported(_) => CellVer::INITIAL,
        }
    }

    pub fn cell_ref(&self) -> CellRef {
        CellRef(self.id(), self.ver())
    }

    pub fn owner(&self) -> Owner {
        match self {
            AnyCell::Mut(mc) => mc.core.owner,
            AnyCell::Imported(ic) => ic.core.owner,
        }
    }
}

impl SystemDigest for AnyCell {
    fn digest(&self) -> Blake2bDigest256 {
        todo!()
    }
}
