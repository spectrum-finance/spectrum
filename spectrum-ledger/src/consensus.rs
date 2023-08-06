#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Into, derive_more::From)]
pub struct RuleId<const F: bool>(u16);

impl RuleId<true> {
    pub fn fatal(id: u16) -> Self {
        Self(id)
    }
}

impl RuleId<false> {
    pub fn non_fatal(id: u16) -> Self {
        Self(id)
    }
}

pub type FatalRuleId = RuleId<true>;
pub type NonFatalRuleId = RuleId<false>;

impl<const F: bool> From<RuleId<F>> for AnyRuleId {
    fn from(RuleId(id): RuleId<F>) -> Self {
        Self(id)
    }
}

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Into, derive_more::From)]
pub struct AnyRuleId(u16);
