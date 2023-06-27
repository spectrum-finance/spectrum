use crate::iso::Iso;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum EitherOrBoth<A, B> {
    Left(A),
    Right(B),
    Both(A, B),
}

impl<A, B> EitherOrBoth<A, B> {
    pub fn swap(self) -> EitherOrBoth<B, A> {
        match self {
            EitherOrBoth::Left(o1) => EitherOrBoth::Right(o1),
            EitherOrBoth::Right(o2) => EitherOrBoth::Left(o2),
            EitherOrBoth::Both(o1, o2) => EitherOrBoth::Both(o2, o1),
        }
    }

    /// If `Left`, or `Both`, return `Some` with the left value, otherwise, return `None`.
    pub fn left(self) -> Option<A> {
        match self {
            EitherOrBoth::Left(left) | EitherOrBoth::Both(left, _) => Some(left),
            _ => None,
        }
    }

    /// If `Right`, or `Both`, return `Some` with the right value, otherwise, return `None`.
    pub fn right(self) -> Option<B> {
        match self {
            EitherOrBoth::Right(right) | EitherOrBoth::Both(_, right) => Some(right),
            _ => None,
        }
    }

    /// If Both, return `Some` tuple containing left and right.
    pub fn both(self) -> Option<(A, B)> {
        match self {
            EitherOrBoth::Both(a, b) => Some((a, b)),
            _ => None,
        }
    }

    pub fn collect(self) -> Vec<B>
    where
        A: Iso<B>,
    {
        match self {
            EitherOrBoth::Left(a) => vec![a.iso_into()],
            EitherOrBoth::Right(b) => vec![b],
            EitherOrBoth::Both(a, b) => vec![a.iso_into(), b],
        }
    }
}

impl<A, B> TryFrom<(Option<A>, Option<B>)> for EitherOrBoth<A, B> {
    type Error = ();
    fn try_from(pair: (Option<A>, Option<B>)) -> Result<Self, Self::Error> {
        match pair {
            (Some(l), Some(r)) => Ok(Self::Both(l, r)),
            (Some(l), None) => Ok(Self::Left(l)),
            (None, Some(r)) => Ok(Self::Right(r)),
            _ => Err(()),
        }
    }
}
