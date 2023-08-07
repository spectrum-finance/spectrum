use spectrum_ledger::consensus::AnyRuleId;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct RuleSpec {
    /// Essential rules cannot be disabled.
    pub essential: bool,
    /// Is rule active
    pub active: bool,
    pub description: *const str,
}

/// Consensus rules table.
pub trait ConsensusRuleSet {
    fn get_rule(&self, rule_id: AnyRuleId) -> RuleSpec;
}
