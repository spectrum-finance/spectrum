use spectrum_ledger::consensus::RuleId;
use spectrum_ledger::{ModifierId, ModifierType};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InvalidModifier {
    pub id: ModifierId,
    pub tpe: ModifierType,
    pub details: String,
}

#[derive(Debug, Copy, Clone)]
pub struct RuleSpec {
    /// Essential rules cannot be disabled.
    pub essential: bool,
    /// Is rule violation fatal
    pub fatal: bool,
    /// Is rule active
    pub active: bool,
    pub description: *const str,
}

pub trait ConsensusRules {
    fn get_rule(&self, rule_id: RuleId) -> RuleSpec;
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ValidationResult<A> {
    Ok(A),
    NonFatal(Vec<InvalidModifier>),
    Error(InvalidModifier),
}

impl<A> ValidationResult<A> {
    pub fn is_failed(&self) -> bool {
        matches!(self, ValidationResult::Error(_))
    }
}

pub struct Validation<A, R> {
    rules: R,
    result: ValidationResult<A>,
}

impl<A, R> Validation<A, R>
where
    R: ConsensusRules,
{
    pub fn new(payload: A, rules: R) -> Self {
        Self {
            rules,
            result: ValidationResult::Ok(payload),
        }
    }

    pub fn validate<F1, F2>(self, id: RuleId, condition: F1, if_invalid: F2) -> Self
    where
        F1: FnOnce() -> bool,
        F2: FnOnce() -> InvalidModifier,
    {
        let rule = self.rules.get_rule(id);
        if self.result.is_failed() || !rule.active || condition() {
            self
        } else {
            self.apply(|| {
                if rule.fatal {
                    ValidationResult::Error(if_invalid())
                } else {
                    ValidationResult::NonFatal(vec![if_invalid()])
                }
            })
        }
    }

    pub fn result(self) -> ValidationResult<A> {
        self.result
    }

    fn apply<B, F>(self, op: F) -> Validation<B, R>
    where
        F: FnOnce() -> ValidationResult<B>,
    {
        match self.result {
            ValidationResult::Ok(_) => Validation {
                rules: self.rules,
                result: op(),
            },
            ValidationResult::NonFatal(mut errs) => Validation {
                rules: self.rules,
                result: match op() {
                    ValidationResult::Ok(_) => ValidationResult::NonFatal(errs),
                    ValidationResult::NonFatal(ref mut errs2) => {
                        errs.append(errs2);
                        ValidationResult::NonFatal(errs)
                    }
                    err => err,
                },
            },
            ValidationResult::Error(err) => Validation {
                rules: self.rules,
                result: ValidationResult::Error(err),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use spectrum_ledger::consensus::RuleId;
    use spectrum_ledger::{ModifierId, ModifierType};

    use crate::validation::{ConsensusRules, InvalidModifier, RuleSpec, Validation, ValidationResult};

    struct RuleRepo<const N: usize>([RuleSpec; N]);

    impl<const N: usize> ConsensusRules for RuleRepo<N> {
        fn get_rule(&self, rule_id: RuleId) -> RuleSpec {
            self.0[<u16>::from(rule_id) as usize]
        }
    }

    #[test]
    fn fail_fast_on_fatal_error() {
        let rules = RuleRepo([
            RuleSpec {
                essential: true,
                fatal: true,
                active: true,
                description: "Rule 0",
            },
            RuleSpec {
                essential: true,
                fatal: false,
                active: true,
                description: "Rule 1",
            },
        ]);
        let validation = Validation::new((), rules);
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let res = validation
            .validate(
                RuleId::from(0),
                || false,
                || InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_1_descr.clone(),
                },
            )
            .validate(
                RuleId::from(1),
                || panic!("boom"),
                || InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: "Rule 2 failed".to_string(),
                },
            )
            .result();
        assert_eq!(
            res,
            ValidationResult::Error(InvalidModifier {
                id: modifier,
                tpe: ModifierType::BlockHeader,
                details: rule_1_descr,
            })
        );
    }

    #[test]
    fn accumulate_on_non_fatal_error() {
        let rules = RuleRepo([
            RuleSpec {
                essential: true,
                fatal: false,
                active: true,
                description: "Rule 0",
            },
            RuleSpec {
                essential: true,
                fatal: false,
                active: true,
                description: "Rule 1",
            },
        ]);
        let validation = Validation::new((), rules);
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let rule_2_descr = "Rule 2 failed".to_string();
        let res = validation
            .validate(
                RuleId::from(0),
                || false,
                || InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_1_descr.clone(),
                },
            )
            .validate(
                RuleId::from(1),
                || false,
                || InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_2_descr.clone(),
                },
            )
            .result();
        assert_eq!(
            res,
            ValidationResult::NonFatal(vec![
                InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_1_descr,
                },
                InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_2_descr,
                }
            ])
        );
    }

    #[test]
    fn skip_disabled_rules() {
        let rules = RuleRepo([
            RuleSpec {
                essential: true,
                fatal: false,
                active: true,
                description: "Rule 0",
            },
            RuleSpec {
                essential: true,
                fatal: false,
                active: false,
                description: "Rule 1",
            },
        ]);
        let validation = Validation::new((), rules);
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let rule_2_descr = "Rule 2 failed".to_string();
        let res = validation
            .validate(
                RuleId::from(0),
                || false,
                || InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_1_descr.clone(),
                },
            )
            .validate(
                RuleId::from(1),
                || panic!("boom"),
                || InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_2_descr.clone(),
                },
            )
            .result();
        assert_eq!(
            res,
            ValidationResult::NonFatal(vec![InvalidModifier {
                id: modifier,
                tpe: ModifierType::BlockHeader,
                details: rule_1_descr,
            },])
        );
    }
}
