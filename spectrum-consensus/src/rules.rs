use spectrum_ledger::consensus::AnyRuleId;

/// An identifier of a consensus rule with "terminality" status encoded on type-level.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, derive_more::Into, derive_more::From)]
pub struct RuleId<const IsTerm: bool>(u16);

/// Terminal consensus rule. Halts validation if violated, cannot be disabled.
/// Can be fatal or non-fatal.
pub type TermRuleId = RuleId<true>;
/// Consensus rule which does not halt validation when violated, always non-fatal.
pub type NonTermRuleId = RuleId<false>;

impl<const F: bool> From<RuleId<F>> for AnyRuleId {
    fn from(RuleId(id): RuleId<F>) -> AnyRuleId {
        AnyRuleId::from(id)
    }
}

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

/// Header occupies valid slot.
pub const HEADER_SLOT: TermRuleId = RuleId(0);
/// Header links to a valid parent.
pub const HEADER_PARENT_LINK: TermRuleId = RuleId(1);
/// SPO's credentials are verified.
pub const HEADER_SPO_VERIFIED: TermRuleId = RuleId(2);
/// Header's VRF is valid against SPO key.
pub const HEADER_VRF: TermRuleId = RuleId(3);
