use spectrum_crypto::digest::Blake2bDigest256;
use spectrum_move::{SerializedModule, SerializedValue};

use crate::sbox::{BoxDestination, BoxId, DatumHash, Owner, SValue};
use crate::ChainId;

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct InteropHeight(u64);

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

// Proof that local interop committee approved outbound value transfer.
pub struct OutboundCert();

/// Events coming from external system.
pub enum InteropEvent {
    /// Value incoming from external system.
    InboundCreated(InboundBox),
    /// Certification of outbound value transfer.
    OutboundCertified(OutboundCert),
    /// Elimination of local box in result of outbound transaction.
    Eliminated(BoxId),
}

pub struct InteropBlock {
    pub height: InteropHeight,
    pub events: Vec<InteropEvent>,
}
