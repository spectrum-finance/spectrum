#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Into, derive_more::From)]
pub struct RuleId(u16);
