use either::Either;

use crate::types::ProtocolVer;

/// An entity that is bound to a concrete protocol version.
pub trait Versioned {
    fn version(&self) -> ProtocolVer;
}

impl<L: Versioned, R: Versioned> Versioned for Either<L, R> {
    fn version(&self) -> ProtocolVer {
        match self {
            Either::Left(l) => l.version(),
            Either::Right(r) => r.version(),
        }
    }
}
