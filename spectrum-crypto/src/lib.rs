pub mod digest;
mod hash;
pub mod pubkey;

/// Result of partial verification.
#[derive(Debug)]
pub enum PVResult<T> {
    Invalid,
    Valid {
        contribution: T,
        /// `true` if contribution is only partially valid.
        partially: bool,
    },
}

/// Some statement which can be verified against public data `P`.
pub trait VerifiableAgainst<P>: Sized {
    /// Verifies the statement.
    fn verify(&self, public_data: &P) -> bool;
    /// Verifies the statement and returns valid part in case partial verification succeded.
    /// Returns `PVResult::Invalid` otherwise.
    fn verify_part(self, public_data: &P) -> PVResult<Self>;
}
