use nonempty::NonEmpty;

pub trait CanValidate<M, FE, NFE> {
    fn try_validate(&self, md: &M) -> ValidationResult<&M, FE, NFE>;
}

#[derive(Clone, Debug)]
pub struct ValidModifier<T>(T);

impl<T> ValidModifier<T> {
    pub(crate) fn unsafe_make(md: T) -> Self {
        Self(md)
    }
}

#[derive(Clone, Debug)]
pub struct RecoverableModifier<T>(T);

impl<T> RecoverableModifier<T> {
    pub(crate) fn unsafe_make(md: T) -> Self {
        Self(md)
    }
}

pub struct ModifierValidation<T, FE, NFE> {
    pub fail_fast: bool,
    pub result: ValidationResult<T, FE, NFE>,
}

pub struct NonFatal<E> {
    erros: NonEmpty<E>,
}

pub enum ValidationResult<T, FE, NFE> {
    Fatal(FE),
    NonFatal(RecoverableModifier<T>, NonFatal<NFE>),
    Valid(ValidModifier<T>),
}

impl<T, FE, NFE> ValidationResult<T, FE, NFE> {
    pub fn is_valid(&self) -> bool {
        match self {
            ValidationResult::Fatal(_) | ValidationResult::NonFatal(_, _) => false,
            ValidationResult::Valid(_) => true,
        }
    }
}

pub trait ValidationError {
    fn is_fatal(&self) -> bool;
    fn message(&self) -> &str;
}
