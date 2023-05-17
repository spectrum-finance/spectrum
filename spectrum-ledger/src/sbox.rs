use std::collections::HashMap;

use k256::PublicKey;

use spectrum_crypto::digest::{blake2b256_hash, Blake2bDigest256};
use spectrum_move::{SerializedModule, SerializedValue};

use crate::ChainId;

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug)]
pub struct BoxId(Blake2bDigest256);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug)]
pub struct BoxVer(u32);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug)]
pub struct BoxRef(pub BoxId, pub BoxVer);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug)]
pub enum BoxPointer {
    Id(BoxId),
    Ref(BoxRef),
}

#[derive(Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct NativeCoin(u64);

#[derive(Eq, PartialEq, Copy, Clone, Hash, Debug)]
pub struct CustomAsset(u64);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug)]
pub struct PolicyId(Blake2bDigest256);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug)]
pub struct AssetId(Blake2bDigest256);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub struct AssetRef(PolicyId, AssetId);

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct SValue {
    pub native: NativeCoin,
    pub assets: HashMap<PolicyId, HashMap<AssetId, CustomAsset>>,
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug)]
pub struct ScriptHash(Blake2bDigest256);

impl From<SerializedModule> for ScriptHash {
    fn from(sm: SerializedModule) -> Self {
        Self(blake2b256_hash(&*<Vec<u8>>::from(sm)))
    }
}

/// Where the script source can be found.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug)]
pub struct ScriptRef(BoxRef);

/// Where the datum source can be found.
#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug)]
pub struct DatumRef(BoxRef);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Debug)]
pub enum Owner {
    ProveDlog(PublicKey),
    ScriptHash(ScriptHash),
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug)]
pub struct DatumHash(Blake2bDigest256);

/// Additional data for bridge (e.g. validator to be used on the dst chain).
#[derive(Eq, PartialEq, Clone, Debug)]
pub struct BridgeInputs();

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct BoxDestination {
    target: ChainId,
    inputs: Option<BridgeInputs>,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct SBox {
    /// Unique identifier of the box.
    pub id: BoxId,
    /// Monotonically increasing version of the box.
    pub ver: BoxVer,
    /// Monetary value attached to the box.
    pub value: SValue,
    /// Owner who can mutate the box.
    pub owner: Owner,
    /// Data attached to the box.
    pub datum: Option<DatumHash>,
    /// Source chain of the box. `None` if the box is local.
    pub src: Option<ChainId>,
    /// Destination chain of the box (where the value of the box is supposed to settle in the end).
    /// `None` if the box is supposed to remain on the multichain.
    pub dst: Option<BoxDestination>,
    /// Script that can be referenced by other transactions.
    pub reference_script: Option<SerializedModule>,
    /// Datum that can be referenced by other transactions.
    pub reference_datum: Option<SerializedValue>,
}

impl SBox {
    pub fn get_ref(&self) -> BoxRef {
        BoxRef(self.id, self.ver)
    }
}
