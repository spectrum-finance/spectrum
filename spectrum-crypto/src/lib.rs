/// Some statement which can be verified against proposition `P`.
pub trait VerifiableAgainst<P> {
    fn verify(&self, proposition: &P) -> bool;
}