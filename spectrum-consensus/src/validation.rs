use spectrum_ledger::{ModifierId, ModifierType};

use crate::rules::{ConsensusRuleSet, NonTermRuleId, TermRuleId};

/// A valid modifier.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Valid<T>(T);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InvalidModifier {
    pub id: ModifierId,
    pub tpe: ModifierType,
    pub details: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Validation<A, T, E> {
    modifier: A,
    state: ValidationState<T, E>,
}

impl<A, E> Validation<A, (), E> {
    pub fn new(modifier: A) -> Self {
        Self {
            modifier,
            state: ValidationState::Ok(())
        }
    }
}

impl<A, T> Validation<A, T, T> {
    pub fn finalize(self) -> Result<ValidationOk<A, T>, ValidationError<A, T>> {
        let Validation { modifier, state } = self;
        match state {
            ValidationState::Ok(a) => Ok(ValidationOk { modifier: Valid(modifier), payload: a }),
            ValidationState::NonTermError(a, errs) => Err(ValidationError { modifier, output: a, fatal: false, errors: errs }),
            ValidationState::TermError(e, f, err) => Err(ValidationError { modifier, output: e, fatal: f, errors: vec![err] }),
        }
    }
}

impl<A, T, E> Validation<A, T, E> {
    pub fn and_then<T1, F>(self, func: F) -> Validation<A, T1, E>
    where
        F: FnOnce(&A, T) -> ValidationState<T1, E>,
    {
        let Validation { modifier, state: result } = self;
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
pub struct ValidationOk<M, A> {
    modifier: Valid<M>,
    payload: A,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ValidationError<M, E> {
    modifier: M,
    output: E,
    fatal: bool,
    errors: Vec<InvalidModifier>
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ValidationState<T, E> {
    /// Successful case.
    Ok(T),
    /// Caught N non-terminal errors in the pipeline.
    NonTermError(T, Vec<InvalidModifier>),
    /// Caught a terminal error.
    TermError(E, /*is_fatal*/ bool, InvalidModifier),
}

impl<E> ValidationState<(), E> {
    pub fn init() -> Self {
        Self::Ok(())
    }
}

impl<T, E> ValidationState<T, E> {
    pub fn new(payload: T) -> Self {
        Self::Ok(payload)
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
        F2: FnOnce(&T) -> InvalidModifier,
    {
        let rule = rules.get_rule(rule_id);
        self.and_then(|t| {
            if !rule.active || cond(&t) {
                ValidationState::Ok(t)
            } else {
                let err = if_failed(&t);
                ValidationState::NonTermError(t, vec![err])
            }
        })
    }

    pub fn asset_term<F1, F2, RS: ConsensusRuleSet>(
        self,
        rule_id: TermRuleId,
        rules: &RS,
        cond: F1,
        if_failed: F2,
    ) -> Self
    where
        F1: FnOnce(&T) -> bool,
        F2: FnOnce(&T) -> (E, InvalidModifier),
    {
        let rule = rules.get_term_rule(rule_id);
        self.and_then(|t| {
            if cond(&t) {
                ValidationState::Ok(t)
            } else {
                let (out, err) = if_failed(&t);
                ValidationState::TermError(out, rule.fatal, err)
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
}

#[cfg(test)]
mod tests {
    use spectrum_ledger::{ModifierId, ModifierType};

    use crate::rules::{NonTermRuleId, NonTermRuleSpec, RuleId, TermRuleId, TermRuleSpec};
    use crate::validation::{ConsensusRuleSet, InvalidModifier, Valid, Validation, ValidationError, ValidationOk, ValidationState};

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
            let RuleSpec { active, description, .. } = self.0[<u16>::from(rule_id) as usize];
            NonTermRuleSpec {
                active,
                description,
            }
        }
        fn get_term_rule(&self, rule_id: TermRuleId) -> TermRuleSpec {
            let RuleSpec { fatal, description, .. } = self.0[<u16>::from(rule_id) as usize];
            TermRuleSpec {
                fatal,
                description,
            }
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
        let validation = Validation::new(());
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let res = validation.and_then(|_, _| {
            ValidationState::init()
                .asset_term(
                    RuleId::from(0),
                    &rules,
                    |_| false,
                    |_| {
                        (
                            (),
                            InvalidModifier {
                                id: modifier,
                                tpe: ModifierType::BlockHeader,
                                details: rule_1_descr.clone(),
                            },
                        )
                    },
                )
                .assert(
                    RuleId::from(1),
                    &rules,
                    |_| panic!("boom"),
                    |_| InvalidModifier {
                        id: modifier,
                        tpe: ModifierType::BlockHeader,
                        details: "Rule 2 failed".to_string(),
                    },
                )
        }).finalize();
        assert_eq!(
            res,
            Err(ValidationError {
                modifier: (),
                output: (),
                fatal: true,
                errors: vec![InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_1_descr,
                }],
            })
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
        let validation = Validation::new(());
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let rule_2_descr = "Rule 2 failed".to_string();
        let res = validation.and_then(|_, _| {
            ValidationState::init()
                .assert(
                    RuleId::from(0),
                    &rules,
                    |_| false,
                    |_| InvalidModifier {
                        id: modifier,
                        tpe: ModifierType::BlockHeader,
                        details: rule_1_descr.clone(),
                    },
                )
                .assert(
                    RuleId::from(1),
                    &rules,
                    |_| false,
                    |_| InvalidModifier {
                        id: modifier,
                        tpe: ModifierType::BlockHeader,
                        details: rule_2_descr.clone(),
                    },
                )
        }).finalize();
        assert_eq!(
            res,
            Err(ValidationError {
                modifier: (),
                output: (),
                fatal: false,
                errors: vec![
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
                ],
            })
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
        let validation = Validation::new(());
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let rule_2_descr = "Rule 2 failed".to_string();
        let res = validation.and_then(|_, _| {
            ValidationState::init()
                .assert(
                    RuleId::from(0),
                    &rules,
                    |_| true,
                    |_| InvalidModifier {
                        id: modifier,
                        tpe: ModifierType::BlockHeader,
                        details: rule_1_descr.clone(),
                    },
                )
                .assert(
                    RuleId::from(1),
                    &rules,
                    |_| panic!("boom"),
                    |_| InvalidModifier {
                        id: modifier,
                        tpe: ModifierType::BlockHeader,
                        details: rule_2_descr.clone(),
                    },
                )
        }).finalize();
        assert_eq!(res, Ok(ValidationOk { modifier: Valid(()), payload: () }));
    }
}
