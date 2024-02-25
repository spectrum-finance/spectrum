use spectrum_ledger::consensus::AnyRuleId;

/// An identifier of a consensus rule with "terminality" status encoded on type-level.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Into, derive_more::From)]
pub struct RuleId<const IsTerm: bool>(u16);

impl<const IsTerm: bool> RuleId<IsTerm> {
    pub const fn from_u16(id: u16) -> Self {
        Self(id)
    }
}

impl<const F: bool> From<RuleId<F>> for AnyRuleId {
    fn from(RuleId(id): RuleId<F>) -> AnyRuleId {
        AnyRuleId::from(id)
    }
}

/// Terminal consensus rule. Halts validation if violated, cannot be disabled.
/// Can be fatal or non-fatal.
pub type TermRuleId = RuleId<true>;
/// Consensus rule which does not halt validation when violated, always non-fatal.
pub type NonTermRuleId = RuleId<false>;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct NonTermRuleSpec {
    /// Is rule active
    pub active: bool,
    pub description: *const str,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct TermRuleSpec {
    pub fatal: bool,
    pub description: *const str,
}

/// Consensus rules table.
pub trait ConsensusRuleSet {
    fn get_rule(&self, rule_id: NonTermRuleId) -> NonTermRuleSpec;
    fn get_term_rule(&self, rule_id: TermRuleId) -> TermRuleSpec;
}
