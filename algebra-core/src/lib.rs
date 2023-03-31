/// https://ncatlab.org/nlab/show/commutative+semigroup
pub trait CommutativeSemigroup {
    fn combine(self, that: Self) -> Self;
}
