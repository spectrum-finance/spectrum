#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Into, derive_more::From)]
pub struct RuleId<const F: bool>(u16);

/// Consensus rule which results in a fatal error when violated.
pub type FatalRuleId = RuleId<true>;
/// Consensus rule which results in a non-fatal error when violated.
pub type NonFatalRuleId = RuleId<false>;

impl<const F: bool> From<RuleId<F>> for AnyRuleId {
    fn from(RuleId(id): RuleId<F>) -> Self {
        Self(id)
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Into, derive_more::From)]
pub struct AnyRuleId(u16);
