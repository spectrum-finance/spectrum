use spectrum_ledger::block::Modifier;
use spectrum_ledger::consensus::AnyRuleId;
use spectrum_ledger::{ModifierId, ModifierType};

use crate::rules::{ConsensusRuleSet, NonTermRuleId, TermRuleId};

/// A valid modifier.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValidModifier<T>(T);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InvalidModifier {
    pub modifier_id: ModifierId,
    pub modifier_type: ModifierType,
    pub fatal: bool,
    pub violations: Vec<RuleViolation>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ModifierErr {
    pub modifier_id: ModifierId,
    pub modifier_type: ModifierType,
    pub details: String,
}

pub trait AsInvalidModifier {
    fn as_invalid(&self, details: String) -> ModifierErr;
}

impl<T> AsInvalidModifier for T
where
    T: Modifier,
{
    fn as_invalid(&self, details: String) -> ModifierErr {
        ModifierErr {
            modifier_id: self.id(),
            modifier_type: T::tpe(),
            details,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuleViolation {
    pub rule: AnyRuleId,
    pub modifier_id: ModifierId,
    pub modifier_type: ModifierType,
    pub details: String,
}

trait IntoViolation {
    fn into_violation(self, rule: AnyRuleId) -> RuleViolation;
}

impl IntoViolation for ModifierErr {
    fn into_violation(self, rule: AnyRuleId) -> RuleViolation {
        RuleViolation {
            rule,
            modifier_id: self.modifier_id,
            modifier_type: self.modifier_type,
            details: self.details,
        }
    }
}

/// An effect allowing to compose multiple steps of validation.
/// Captures modifier `A` in its context.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Validation<A, T, E> {
    modifier: A,
    state: ValidationState<T, E>,
}

impl<A> Validation<A, (), ()>
where
    A: Modifier,
{
    pub fn result(self) -> Result<ValidModifier<A>, InvalidModifier> {
        let Validation { modifier, state } = self;
        match state {
            ValidationState::Ok(_) => Ok(ValidModifier(modifier)),
            ValidationState::NonTermError(_, errs) => Err(InvalidModifier {
                modifier_id: modifier.id(),
                modifier_type: A::tpe(),
                fatal: false,
                violations: errs,
            }),
            ValidationState::TermError(_, fatal, err) => Err(InvalidModifier {
                modifier_id: modifier.id(),
                modifier_type: A::tpe(),
                fatal,
                violations: vec![err],
            }),
        }
    }
}

impl<A, E> Validation<A, (), E> {
    pub fn new(modifier: A) -> Self {
        Self {
            modifier,
            state: ValidationState::Ok(()),
        }
    }
}

impl<A, T, E> Validation<A, T, E> {
    pub fn and_then<T1, F>(self, func: F) -> Validation<A, T1, E>
    where
        F: FnOnce(&A, T) -> ValidationState<T1, E>,
    {
        let Validation {
            modifier,
            state: result,
        } = self;
        let next_result = match result {
            ValidationState::Ok(t) => func(&modifier, t),
            ValidationState::NonTermError(t, mut err_acc) => match func(&modifier, t) {
                ValidationState::Ok(t1) => ValidationState::NonTermError(t1, err_acc),
                ValidationState::NonTermError(t1, mut errs) => {
                    err_acc.append(&mut errs);
                    ValidationState::NonTermError(t1, err_acc)
                }
                fatal => fatal,
            },
            ValidationState::TermError(e, f, err) => ValidationState::TermError(e, f, err),
        };
        Validation {
            modifier,
            state: next_result,
        }
    }
}
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValidationError<E> {
    output: E,
    fatal: bool,
    errors: Vec<RuleViolation>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ValidationState<T, E> {
    /// Successful case.
    Ok(T),
    /// Caught N non-terminal errors in the pipeline.
    NonTermError(T, Vec<RuleViolation>),
    /// Caught a terminal error.
    TermError(E, /*is_fatal*/ bool, RuleViolation),
}

impl<E> ValidationState<(), E> {
    pub fn ok() -> Self {
        Self::Ok(())
    }
}

impl<A> ValidationState<A, ()> {
    pub fn fail<RS: ConsensusRuleSet>(rule_id: TermRuleId, rules: &RS, err: ModifierErr) -> Self {
        let rule = rules.get_term_rule(rule_id);
        Self::TermError((), rule.fatal, err.into_violation(rule_id.into()))
    }

    pub fn unwrap<F1, F2, RS: ConsensusRuleSet>(
        rule_id: TermRuleId,
        rules: &RS,
        extractor: F1,
        err: F2,
    ) -> ValidationState<A, ()>
    where
        F1: FnOnce() -> Option<A>,
        F2: FnOnce() -> ModifierErr,
    {
        let rule = rules.get_term_rule(rule_id);
        if let Some(t1) = extractor() {
            ValidationState::Ok(t1)
        } else {
            ValidationState::TermError((), rule.fatal, err().into_violation(rule_id.into()))
        }
    }

    pub fn assert_defined<A1, F1, F2, RS: ConsensusRuleSet>(
        self,
        rule_id: TermRuleId,
        rules: &RS,
        cond: F1,
        err: F2,
    ) -> ValidationState<A1, ()>
    where
        F1: FnOnce(&A) -> Option<A1>,
        F2: FnOnce(&A) -> ModifierErr,
    {
        let rule = rules.get_term_rule(rule_id);
        self.and_then(|t| {
            if let Some(t1) = cond(&t) {
                ValidationState::Ok(t1)
            } else {
                ValidationState::TermError((), rule.fatal, err(&t).into_violation(rule_id.into()))
            }
        })
    }

    pub fn asset_term<F1, F2, RS: ConsensusRuleSet>(
        self,
        rule_id: TermRuleId,
        rules: &RS,
        cond: F1,
        err: F2,
    ) -> Self
    where
        F1: FnOnce(&A) -> bool,
        F2: FnOnce(&A) -> ModifierErr,
    {
        let rule = rules.get_term_rule(rule_id);
        self.and_then(|t| {
            if cond(&t) {
                ValidationState::Ok(t)
            } else {
                ValidationState::TermError((), rule.fatal, err(&t).into_violation(rule_id.into()))
            }
        })
    }
}

impl<T, E> ValidationState<T, E> {
    pub fn new(payload: T) -> Self {
        Self::Ok(payload)
    }

    pub fn fail_out<RS: ConsensusRuleSet>(rule_id: TermRuleId, rules: &RS, out: E, err: ModifierErr) -> Self {
        let rule = rules.get_term_rule(rule_id);
        Self::TermError(out, rule.fatal, err.into_violation(rule_id.into()))
    }

    pub fn assert<F1, F2, RS: ConsensusRuleSet>(
        self,
        rule_id: NonTermRuleId,
        rules: &RS,
        cond: F1,
        if_failed: F2,
    ) -> Self
    where
        F1: FnOnce(&T) -> bool,
        F2: FnOnce(&T) -> ModifierErr,
    {
        let rule = rules.get_rule(rule_id);
        self.and_then(|t| {
            if !rule.active || cond(&t) {
                ValidationState::Ok(t)
            } else {
                let err = if_failed(&t).into_violation(rule_id.into());
                ValidationState::NonTermError(t, vec![err])
            }
        })
    }

    pub fn asset_term_out<F1, F2, RS: ConsensusRuleSet>(
        self,
        rule_id: TermRuleId,
        rules: &RS,
        cond: F1,
        if_failed: F2,
    ) -> Self
    where
        F1: FnOnce(&T) -> bool,
        F2: FnOnce(&T) -> (E, ModifierErr),
    {
        let rule = rules.get_term_rule(rule_id);
        self.and_then(|t| {
            if cond(&t) {
                ValidationState::Ok(t)
            } else {
                let (out, err) = if_failed(&t);
                ValidationState::TermError(out, rule.fatal, err.into_violation(rule_id.into()))
            }
        })
    }

    pub fn and_then<T1, F>(self, func: F) -> ValidationState<T1, E>
    where
        F: FnOnce(T) -> ValidationState<T1, E>,
    {
        match self {
            ValidationState::Ok(t) => func(t),
            ValidationState::NonTermError(s, mut err_acc) => match func(s) {
                ValidationState::Ok(t1) => ValidationState::NonTermError(t1, err_acc),
                ValidationState::NonTermError(t1, mut errs) => {
                    err_acc.append(&mut errs);
                    ValidationState::NonTermError(t1, err_acc)
                }
                fatal => fatal,
            },
            ValidationState::TermError(e, f, err) => ValidationState::TermError(e, f, err),
        }
    }

    /// Does not alter the output type.
    pub fn flat_tap<T1, F>(self, func: F) -> ValidationState<T, E>
    where
        F: FnOnce(&T) -> ValidationState<T1, E>,
    {
        match self {
            ValidationState::Ok(t) => func(&t).map(|_| t),
            ValidationState::NonTermError(t, mut err_acc) => match func(&t).map(|_| t) {
                ValidationState::Ok(t1) => ValidationState::NonTermError(t1, err_acc),
                ValidationState::NonTermError(t1, mut errs) => {
                    err_acc.append(&mut errs);
                    ValidationState::NonTermError(t1, err_acc)
                }
                fatal => fatal,
            },
            ValidationState::TermError(e, f, err) => ValidationState::TermError(e, f, err),
        }
    }

    pub fn map<T1, F>(self, func: F) -> ValidationState<T1, E>
    where
        F: FnOnce(T) -> T1,
    {
        match self {
            ValidationState::Ok(s) => ValidationState::Ok(func(s)),
            ValidationState::NonTermError(s, errs) => ValidationState::NonTermError(func(s), errs),
            ValidationState::TermError(e, f, err) => ValidationState::TermError(e, f, err),
        }
    }

    pub fn discard(self) -> ValidationState<(), E> {
        self.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use spectrum_ledger::{ModifierId, ModifierType};

    use crate::rules::{NonTermRuleId, NonTermRuleSpec, RuleId, TermRuleId, TermRuleSpec};
    use crate::validation::{ConsensusRuleSet, ModifierErr, RuleViolation, ValidationState};

    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    struct RuleSpec {
        pub active: bool,
        pub fatal: bool,
        pub description: *const str,
    }

    #[derive(Debug, Eq, PartialEq, Clone)]
    struct RuleRepo<const N: usize>([RuleSpec; N]);

    impl<const N: usize> ConsensusRuleSet for RuleRepo<N> {
        fn get_rule(&self, rule_id: NonTermRuleId) -> NonTermRuleSpec {
            let RuleSpec {
                active, description, ..
            } = self.0[<u16>::from(rule_id) as usize];
            NonTermRuleSpec { active, description }
        }
        fn get_term_rule(&self, rule_id: TermRuleId) -> TermRuleSpec {
            let RuleSpec {
                fatal, description, ..
            } = self.0[<u16>::from(rule_id) as usize];
            TermRuleSpec { fatal, description }
        }
    }

    #[test]
    fn fail_fast_on_fatal_error() {
        let rules = RuleRepo([
            RuleSpec {
                active: true,
                fatal: true,
                description: "Rule 0",
            },
            RuleSpec {
                active: true,
                fatal: true,
                description: "Rule 1",
            },
        ]);
        let modifier = ModifierId::random();
        let rule_1: TermRuleId = RuleId::from(0);
        let rule_2: NonTermRuleId = RuleId::from(1);
        let rule_1_descr = "Rule 1 failed".to_string();
        let res = ValidationState::ok()
            .asset_term(
                rule_1,
                &rules,
                |_| false,
                |_| ModifierErr {
                    modifier_id: modifier,
                    modifier_type: ModifierType::BlockHeader,
                    details: rule_1_descr.clone(),
                },
            )
            .assert(
                rule_2,
                &rules,
                |_| panic!("boom"),
                |_| ModifierErr {
                    modifier_id: modifier,
                    modifier_type: ModifierType::BlockHeader,
                    details: "Rule 2 failed".to_string(),
                },
            );
        assert_eq!(
            res,
            ValidationState::TermError(
                (),
                true,
                RuleViolation {
                    rule: rule_1.into(),
                    modifier_id: modifier,
                    modifier_type: ModifierType::BlockHeader,
                    details: rule_1_descr,
                }
            )
        );
    }

    #[test]
    fn accumulate_on_non_fatal_error() {
        let rules = RuleRepo([
            RuleSpec {
                active: true,
                fatal: false,
                description: "Rule 0",
            },
            RuleSpec {
                active: true,
                fatal: false,
                description: "Rule 1",
            },
        ]);
        let modifier = ModifierId::random();
        let rule_1: NonTermRuleId = RuleId::from(0);
        let rule_2: NonTermRuleId = RuleId::from(1);
        let rule_1_descr = "Rule 1 failed".to_string();
        let rule_2_descr = "Rule 2 failed".to_string();
        let res = ValidationState::<(), ()>::ok()
            .assert(
                rule_1,
                &rules,
                |_| false,
                |_| ModifierErr {
                    modifier_id: modifier,
                    modifier_type: ModifierType::BlockHeader,
                    details: rule_1_descr.clone(),
                },
            )
            .assert(
                rule_2,
                &rules,
                |_| false,
                |_| ModifierErr {
                    modifier_id: modifier,
                    modifier_type: ModifierType::BlockHeader,
                    details: rule_2_descr.clone(),
                },
            );
        assert_eq!(
            res,
            ValidationState::NonTermError(
                (),
                vec![
                    RuleViolation {
                        rule: rule_1.into(),
                        modifier_id: modifier,
                        modifier_type: ModifierType::BlockHeader,
                        details: rule_1_descr,
                    },
                    RuleViolation {
                        rule: rule_2.into(),
                        modifier_id: modifier,
                        modifier_type: ModifierType::BlockHeader,
                        details: rule_2_descr,
                    }
                ]
            )
        );
    }

    #[test]
    fn skip_disabled_rules() {
        let rules = RuleRepo([
            RuleSpec {
                active: true,
                fatal: false,
                description: "Rule 0",
            },
            RuleSpec {
                active: false,
                fatal: false,
                description: "Rule 1",
            },
        ]);
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let rule_2_descr = "Rule 2 failed".to_string();
        let res = ValidationState::<(), ()>::ok()
            .assert(
                RuleId::from(0),
                &rules,
                |_| true,
                |_| ModifierErr {
                    modifier_id: modifier,
                    modifier_type: ModifierType::BlockHeader,
                    details: rule_1_descr.clone(),
                },
            )
            .assert(
                RuleId::from(1),
                &rules,
                |_| panic!("boom"),
                |_| ModifierErr {
                    modifier_id: modifier,
                    modifier_type: ModifierType::BlockHeader,
                    details: rule_2_descr.clone(),
                },
            );
        assert_eq!(res, ValidationState::ok());
    }

    #[test]
    fn map_after_disabled_rules() {
        let rules = RuleRepo([
            RuleSpec {
                active: true,
                fatal: false,
                description: "Rule 0",
            },
            RuleSpec {
                active: false,
                fatal: false,
                description: "Rule 1",
            },
        ]);
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let rule_2_descr = "Rule 2 failed".to_string();
        let payload = 0u8;
        let res = ValidationState::<_, ()>::ok()
            .assert(
                RuleId::from(0),
                &rules,
                |_| true,
                |_| ModifierErr {
                    modifier_id: modifier,
                    modifier_type: ModifierType::BlockHeader,
                    details: rule_1_descr.clone(),
                },
            )
            .assert(
                RuleId::from(1),
                &rules,
                |_| panic!("boom"),
                |_| ModifierErr {
                    modifier_id: modifier,
                    modifier_type: ModifierType::BlockHeader,
                    details: rule_2_descr.clone(),
                },
            )
            .map(|_| payload);
        assert_eq!(res, ValidationState::new(payload));
    }
}
