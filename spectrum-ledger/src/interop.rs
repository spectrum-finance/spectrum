use spectrum_crypto::digest::{Blake2b, Blake2bDigest256};
use spectrum_sigma::sigma_aggregation::MultiCertificate;

use crate::cell::{AnyCell, CellId};
use crate::ChainId;

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct Point(u64);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct Source(ChainId, Point);

#[derive(Eq, PartialEq, Ord, PartialOrd, Copy, Clone, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct EffectId(Blake2bDigest256);

/// Events observed in external system affecting the state of Spectrum.
#[derive(Clone, Eq, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Effect {
    /// Value incoming from external system.
    Imported(AnyCell),
    /// Elimination of a terminal cell in result of outbound transaction.
    Exported(CellId),
    /// Revokation of an initial cell due to rollback on external system.
    Revoked(CellId),
    /// External system reached new point.
    Progressed(Point),
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ReportCertificate {
    SchnorrK256(MultiCertificate<Blake2b>),
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Report {
    pub body: ReportBody,
    pub body_certificate: ReportCertificate,
}

#[derive(Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReportBody {
    pub source: Source,
    pub effects: Vec<Effect>,
}
