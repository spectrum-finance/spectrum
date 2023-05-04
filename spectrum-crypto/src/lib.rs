pub mod digest;
mod hash;

/// Some statement which can be verified against public data `P`.
pub trait VerifiableAgainst<P> {
    fn verify(&self, public_data: &P) -> bool;
}
