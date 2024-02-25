/// Variant of rule ID regardless of rule's fatality.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Into, derive_more::From)]
pub struct AnyRuleId(u16);
