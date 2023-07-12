pub trait Iso<T> {
    fn iso_into(self) -> T;
    fn iso_from(that: T) -> Self;
}

impl<A> Iso<A> for A {
    fn iso_into(self) -> A {
        self
    }
    fn iso_from(that: A) -> Self {
        that
    }
}
