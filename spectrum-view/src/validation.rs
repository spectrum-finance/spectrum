use nonempty::NonEmpty;

pub trait CanValidate<M, E> {
    fn try_validate(&self, md: M) -> ValidationResult<ValidModifier<M>, E>;
}

#[derive(Clone, Debug)]
pub struct ValidModifier<T>(T);

impl<T> ValidModifier<T> {
    pub(crate) fn unsafe_make(md: T) -> Self {
        Self(md)
    }
}

pub struct ModifierValidation<T, E> {
    pub fail_fast: bool,
    pub result: ValidationResult<T, E>,
}

pub struct ValidationResultValid<T> {
    payload: T,
}

pub struct ValidationResultInvalid<E> {
    erros: NonEmpty<E>,
}

impl<E> ValidationResultInvalid<E>
where
    E: ValidationError,
{
    pub fn is_fatal(&self) -> bool {
        self.erros.iter().find(|e| e.is_fatal()).is_some()
    }

    pub fn accumulate_err<T>(mut self, next: ValidationResult<T, E>) -> ValidationResultInvalid<E> {
        match next {
            ValidationResult::Valid(_) => self,
            ValidationResult::Invalid(r) => {
                for err in r.erros {
                    self.erros.push(err)
                }
                self
            }
        }
    }
}

pub enum ValidationResult<T, E> {
    Valid(ValidationResultValid<T>),
    Invalid(ValidationResultInvalid<E>),
}

impl<T, E> ValidationResult<T, E>
where
    E: ValidationError,
{
    pub fn is_valid(&self) -> bool {
        match self {
            ValidationResult::Valid(_) => true,
            ValidationResult::Invalid(_) => false,
        }
    }
}

pub trait ValidationError {
    fn is_fatal(&self) -> bool;
    fn message(&self) -> &str;
}
