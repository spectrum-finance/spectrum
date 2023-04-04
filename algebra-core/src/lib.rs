/// https://ncatlab.org/nlab/show/commutative+semigroup
pub trait CommutativeSemigroup {
    fn combine(&self, that: &Self) -> Self;
}

/// Commutative Partial Semigroup is like Commutative Semigroup but the operator is partial.
pub trait CommutativePartialSemigroup: Sized {
    fn try_combine(&self, that: &Self) -> Option<Self>;
}
