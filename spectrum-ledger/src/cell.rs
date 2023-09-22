use std::collections::HashMap;

use k256::PublicKey;

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_move::{SerializedModule, SerializedValue};

use crate::interop::Point;
use crate::transaction::{TxId, Witness};
use crate::{ChainId, DigestViaEncoder, SystemDigest};

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
pub struct Serial(u32);

impl Serial {
    pub const INITIAL: Serial = Serial(0);
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct CellRef(pub CellId, pub Serial);

/// Pointer to a cell.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub enum CellPtr {
    /// Pointer by stable identifier.
    /// Concrete version of the cell is to be resolved in runtime.
    Id(CellId),
    /// Fully qualified pointer.
    Ref(CellRef),
}

#[derive(Eq, PartialEq, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct NativeCoin(pub u64);

#[derive(Eq, PartialEq, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct CustomAsset(pub u64);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct PolicyId(Blake2bDigest256);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct AssetId(pub Blake2bDigest256);

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
pub struct BridgeInputs(Witness);

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct BoxDestination {
    pub target: ChainId,
    pub address: SerializedValue,
    pub inputs: Option<BridgeInputs>,
}

/// Progress point on external chain.
#[derive(Eq, PartialEq, Clone, Debug, Hash, serde::Serialize, serde::Deserialize)]
pub struct ProgressPoint {
    pub chain_id: ChainId,
    pub point: Point,
}

/// Main and the only value carrying unit in the system.
#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Cell {
    /// Monetary value attached to the cell.
    pub value: SValue,
    /// Owner that can mutate/consume the cell.
    pub owner: Owner,
    /// Data attached to the cell.
    pub datum: Option<DatumHash>,
    /// Script that can be referenced by other transactions.
    pub reference_script: Option<SerializedModule>,
    /// Datum that can be referenced by other transactions.
    pub reference_datum: Option<SerializedValue>,
    /// ID of a transaction which created the cell.
    pub tx_id: TxId,
    /// Index of the cell inside the TX which created it.
    pub index: u32,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ActiveCell {
    /// Monetary value attached to the cell.
    pub value: SValue,
    /// Owner that can mutate/consume the cell.
    pub owner: Owner,
    /// Data attached to the cell.
    pub datum: Option<DatumHash>,
    /// Script that can be referenced by other transactions.
    pub reference_script: Option<SerializedModule>,
    /// Datum that can be referenced by other transactions.
    pub reference_datum: Option<SerializedValue>,
    /// ID of a transaction which created the cell.
    pub tx_id: TxId,
    /// Index of the cell inside the TX which created it.
    pub index: u32,
    /// Monotonically increasing version of the box.
    pub ver: Serial,
}

impl ActiveCell {
    pub fn id(&self) -> CellId {
        CellId::from(self.digest())
    }

    pub fn cref(&self) -> CellRef {
        CellRef(self.id(), self.ver)
    }
}

impl DigestViaEncoder for ActiveCell {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TermCell {
    /// Monetary value attached to the cell.
    pub value: SValue,
    /// ID of a transaction which created the cell.
    pub tx_id: TxId,
    /// Index of the cell inside the TX which created it.
    pub index: u32,
    /// Destination chain of the cell (where the value of the cell is supposed to settle in the end).
    pub dst: BoxDestination,
}

impl TermCell {
    pub fn id(&self) -> CellId {
        CellId::from(self.digest())
    }
}

impl DigestViaEncoder for TermCell {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum AnyCell {
    Mut(ActiveCell),
    Term(TermCell),
}

impl AnyCell {
    pub fn id(&self) -> CellId {
        match self {
            AnyCell::Mut(mc) => mc.id(),
            AnyCell::Term(tc) => tc.id(),
        }
    }

    pub fn ver(&self) -> Serial {
        match self {
            AnyCell::Term(_) => Serial::INITIAL,
            AnyCell::Mut(mc) => mc.ver,
        }
    }

    pub fn cref(&self) -> CellRef {
        CellRef(self.id(), self.ver())
    }
}

/// Representation of a cell with associated metadata attached to it.
#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize, higher::Functor)]
pub struct CellMeta<C> {
    pub cell: C,
    /// Until external systems which this cell depends on reach those progress points
    /// the cell is not confirmed.
    pub ancors: Vec<ProgressPoint>,
}
