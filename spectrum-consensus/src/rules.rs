use spectrum_validation::rules::{RuleId, TermRuleId};

/// Header links to a valid parent.
pub const HEADER_PARENT_LINK: TermRuleId = RuleId::from_u16(0);
pub const HEADER_NON_DESC_SLOT: TermRuleId = RuleId::from_u16(1);
pub const HEADER_PARENT_SLOT_DELTA: TermRuleId = RuleId::from_u16(2);
pub const HEADER_VALIDATOR_CREDS: TermRuleId = RuleId::from_u16(2);
pub const HEADER_VALIDATOR_MEMBER: TermRuleId = RuleId::from_u16(2);
pub const HEADER_VALIDATOR_LEADER: TermRuleId = RuleId::from_u16(2);
pub const HEADER_EPOCH_SEED: TermRuleId = RuleId::from_u16(3);
/// SPO's credentials are verified.
pub const HEADER_SPO_VERIFIED: TermRuleId = RuleId::from_u16(1);
/// Header's VRF is valid against SPO key.
pub const HEADER_VRF: TermRuleId = RuleId::from_u16(2);
