use std::collections::HashMap;

use k256::PublicKey;

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_move::{SerializedModule, SerializedValue};

use crate::interop::{ExtEffId, Point};
use crate::transaction::TxId;
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

/// Main and the only value carrying unit in the system.
#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Cell {
    /// Monetary value attached to the cell.
    pub value: SValue,
    /// Owner who can mutate the cell.
    pub owner: Owner,
    /// Data attached to the cell.
    pub datum: Option<DatumHash>,
    /// Destination chain of the cell (where the value of the cell is supposed to settle in the end).
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
    pub core: Cell,
    /// Monotonically increasing version of the box.
    pub ver: Serial,
    /// ID of a transaction which created this cell.
    pub tx_id: TxId,
    /// Index of the cell inside the TX which created it.
    pub index: u32,
}

impl MutCell {
    pub fn id(&self) -> CellId {
        CellId::from(self.digest())
    }
}

impl DigestViaEncoder for MutCell {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InitCell {
    /// Core cell
    pub core: Cell,
    /// ID of an inbound effect which created this cell.
    pub eff_id: ExtEffId,
}

impl InitCell {
    pub fn id(&self) -> CellId {
        CellId::from(self.digest())
    }
}

impl DigestViaEncoder for InitCell {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TermCell {
    /// Core cell
    pub core: Cell,
    /// ID of a transaction which created the cell.
    pub tx_id: TxId,
    /// Index of the cell inside the TX which created it.
    pub index: u32,
}

impl TermCell {
    pub fn id(&self) -> CellId {
        CellId::from(self.digest())
    }
}

impl DigestViaEncoder for TermCell {}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum AnyCell {
    Init(InitCell),
    Mut(MutCell),
    Term(TermCell),
}

impl From<OutputCell> for AnyCell {
    fn from(out: OutputCell) -> Self {
        match out {
            OutputCell::Mut(mc) => Self::Mut(mc),
            OutputCell::Term(tc) => Self::Term(tc),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum OutputCell {
    Mut(MutCell),
    Term(TermCell),
}

impl OutputCell {
    pub fn id(&self) -> CellId {
        match self {
            OutputCell::Mut(mc) => mc.id(),
            OutputCell::Term(tc) => tc.id(),
        }
    }

    pub fn ver(&self) -> Serial {
        match self {
            OutputCell::Term(_) => Serial::INITIAL,
            OutputCell::Mut(mc) => mc.ver,
        }
    }

    pub fn cell_ref(&self) -> CellRef {
        CellRef(self.id(), self.ver())
    }

    pub fn owner(&self) -> Owner {
        match self {
            OutputCell::Mut(mc) => mc.core.owner,
            OutputCell::Term(tc) => tc.core.owner,
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum InputCell {
    Init { cell: InitCell, settled: bool },
    Mut(MutCell),
}

impl InputCell {
    pub fn id(&self) -> CellId {
        match self {
            InputCell::Init { cell, .. } => cell.id(),
            InputCell::Mut(mc) => mc.id(),
        }
    }

    pub fn ver(&self) -> Serial {
        match self {
            InputCell::Init { .. } => Serial::INITIAL,
            InputCell::Mut(mc) => mc.ver,
        }
    }

    pub fn cell_ref(&self) -> CellRef {
        CellRef(self.id(), self.ver())
    }

    pub fn owner(&self) -> Owner {
        match self {
            InputCell::Init { cell, .. } => cell.core.owner,
            InputCell::Mut(mc) => mc.core.owner,
        }
    }
}
