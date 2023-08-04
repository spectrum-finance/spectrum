use spectrum_ledger::{ModifierId, ModifierType};
use spectrum_ledger::consensus::RuleId;

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
enum ValidationResult<A> {
    Ok(A),
    NonFatal(Vec<InvalidModifier>),
    Error(InvalidModifier),
}

pub struct Validation<A, R> {
    rules: R,
    result: ValidationResult<A>,
}

impl<A, R> Validation<A, R> where A: Clone, R: ConsensusRules {
    fn apply<B, F>(self, op: F) -> Validation<B, R> where F: FnOnce() -> ValidationResult<B> {
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
            }
        }
    }

    pub fn validate<F1, F2>(self, id: RuleId, condition: F1, if_invalid: F2) -> Self
        where
            F1: FnOnce() -> bool,
            F2: FnOnce() -> InvalidModifier {
        let rule = self.rules.get_rule(id);
        if !rule.active || condition() {
            let res = self.result.clone();
            self.apply(|| res)
        } else {
            self.apply(|| if rule.fatal {
                ValidationResult::Error(if_invalid())
            } else {
                ValidationResult::NonFatal(vec![if_invalid()])
            })
        }
    }
}
