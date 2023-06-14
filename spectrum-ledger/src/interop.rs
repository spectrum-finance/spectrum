use nonempty::NonEmpty;

use spectrum_crypto::digest::{Blake2bDigest256, Digest256};
use spectrum_move::{SerializedModule, SerializedValue};

use crate::block::BlockId;
use crate::sbox::{BoxDestination, BoxId, DatumHash, Owner, SValue};
use crate::ChainId;

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct PeriferalId(Blake2bDigest256);

/// Value coming from external system.
pub struct InboundBox {
    /// ID of the periferal value carrying unit (e.g an output in an external UTxO system).
    pub id: PeriferalId,
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

// Bundled outbound transactions
pub struct CertBundle(NonEmpty<[u8; 32]>);

pub struct IBlockCert();

pub struct IEffDigest(Blake2bDigest256);

/// State transitions coming from external system.
pub enum IEffect {
    /// Value incoming from external system.
    InboundCreated(InboundBox),
    /// Certification of outbound value transfer.
    OutboundCertified(CertBundle),
    /// Elimination of local box in result of outbound transaction.
    Eliminated(BoxId),
}

pub struct IBlockCandidate {
    pub id: IBlockId,
    pub height: u64,
    pub effects: Vec<IEffDigest>,
}

pub struct IBlock {
    pub id: IBlockId,
    pub height: u64,
    pub cert: IBlockCert,
    pub effects: Vec<IEffect>,
}

pub struct IBlockPtr {
    pub id: IBlockId,
    pub block_id: BlockId,
}

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
pub struct IBlockId(Blake2bDigest256);

/// A cell which can either contain `IBlock` itself ot a ppointer to it.
pub enum IBlockCell {
    Fresh(IBlock),
    Moved(IBlockPtr),
}
