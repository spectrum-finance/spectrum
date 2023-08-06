use spectrum_ledger::{ModifierId, ModifierType};
use spectrum_ledger::consensus::{AnyRuleId, FatalRuleId, NonFatalRuleId};

/// A valid modifier.
#[derive(Debug)]
pub struct Valid<T>(T);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InvalidModifier {
    pub id: ModifierId,
    pub tpe: ModifierType,
    pub details: String,
}

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

/// An effect for consensus validations of modifier `A` against the rule set `R`.
/// Validations may rely on intermediate state `S`.
/// In worst case the chain of validations terminate with output `E`.
#[derive(Debug, Clone, Eq, PartialEq)]
enum Validation<A, S, E, R> {
    /// Successful case.
    Ok(A, S, R),
    /// Caught N non-fatal errors in the pipeline.
    NonFatal(A, S, R, Vec<InvalidModifier>),
    /// Caught a fatal error. Terminal state.
    Error(E, InvalidModifier),
}

impl<A, S, E, R> Validation<A, S, E, R> {
    pub fn new(modifier: A, state: S, rules: R) -> Self {
        Validation::Ok(modifier, state, rules)
    }

    pub fn verify_fatal<F1, F2>(self, rule: FatalRuleId, cond: F1, if_invalid: F2) -> Self
    where
        R: ConsensusRuleSet,
        F1: FnOnce() -> bool,
        F2: FnOnce() -> (E, InvalidModifier),
    {
        if let Some(rules) = self.rules() {
            let rule_spec = rules.get_rule(rule.into());
            if !rule_spec.active || cond() {
                self
            } else {
                let (e, err) = if_invalid();
                Validation::Error(e, err)
            }
        } else {
            self
        }
    }

    pub fn verify_non_fatal<F1, F2>(self, rule: NonFatalRuleId, cond: F1, if_invalid: F2) -> Self
    where
        R: ConsensusRuleSet,
        F1: FnOnce() -> bool,
        F2: FnOnce() -> InvalidModifier,
    {
        if let Some(rules) = self.rules() {
            let rule_spec = rules.get_rule(rule.into());
            if !rule_spec.active || cond() {
                self
            } else {
                match self {
                    Validation::Ok(a, s, r) => Validation::NonFatal(a, s, r, vec![if_invalid()]),
                    Validation::NonFatal(a, s, r, mut errs) => {
                        errs.push(if_invalid());
                        Validation::NonFatal(a, s, r, errs)
                    }
                    fatal => fatal,
                }
            }
        } else {
            self
        }
    }

    pub fn and_then<S1, F>(self, func: F) -> Validation<A, S1, E, R>
    where
        F: FnOnce(A, S, R) -> Validation<A, S1, E, R>,
    {
        match self {
            Validation::Ok(a, s, r) => func(a, s, r),
            Validation::NonFatal(a, s, r, mut err_acc) => match func(a, s, r) {
                Validation::Ok(a, s1, r) => Validation::NonFatal(a, s1, r, err_acc),
                Validation::NonFatal(a, s1, r, mut errs) => {
                    err_acc.append(&mut errs);
                    Validation::NonFatal(a, s1, r, err_acc)
                }
                fatal => fatal,
            },
            Validation::Error(e, err) => Validation::Error(e, err),
        }
    }

    pub fn map_state<S1, F>(self, func: F) -> Validation<A, S1, E, R> where F: FnOnce(S) -> S1 {
        match self {
            Validation::Ok(a, s, r) => Validation::Ok(a, func(s), r),
            Validation::NonFatal(a, s, r, errs) => Validation::NonFatal(a, func(s), r, errs),
            Validation::Error(e, err) => Validation::Error(e, err),
        }
    }

    fn rules(&self) -> Option<&R> {
        match self {
            Validation::Ok(_, _, r) | Validation::NonFatal(_, _, r, _) => Some(r),
            Validation::Error(_, _) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use spectrum_ledger::{ModifierId, ModifierType};
    use spectrum_ledger::consensus::{AnyRuleId, RuleId};

    use crate::validation::{ConsensusRuleSet, InvalidModifier, RuleSpec, Validation};

    #[derive(Debug, Eq, PartialEq, Clone)]
    struct RuleRepo<const N: usize>([RuleSpec; N]);

    impl<const N: usize> ConsensusRuleSet for RuleRepo<N> {
        fn get_rule(&self, rule_id: AnyRuleId) -> RuleSpec {
            self.0[<u16>::from(rule_id) as usize]
        }
    }

    #[test]
    fn fail_fast_on_fatal_error() {
        let rules = RuleRepo([
            RuleSpec {
                essential: true,
                active: true,
                description: "Rule 0",
            },
            RuleSpec {
                essential: true,
                active: true,
                description: "Rule 1",
            },
        ]);
        let validation = Validation::new((), (), rules);
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let res = validation
            .verify_fatal(
                RuleId::from(0),
                || false,
                || {
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
            .verify_non_fatal(
                RuleId::from(1),
                || panic!("boom"),
                || InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: "Rule 2 failed".to_string(),
                },
            );
        assert_eq!(
            res,
            Validation::Error(
                (),
                InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_1_descr,
                }
            )
        );
    }

    #[test]
    fn accumulate_on_non_fatal_error() {
        let rules = RuleRepo([
            RuleSpec {
                essential: true,
                active: true,
                description: "Rule 0",
            },
            RuleSpec {
                essential: true,
                active: true,
                description: "Rule 1",
            },
        ]);
        let validation = Validation::<_, _, (), _>::new((), (), rules.clone());
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let rule_2_descr = "Rule 2 failed".to_string();
        let res = validation
            .verify_non_fatal(
                RuleId::from(0),
                || false,
                || InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_1_descr.clone(),
                },
            )
            .verify_non_fatal(
                RuleId::from(1),
                || false,
                || InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_2_descr.clone(),
                },
            );
        assert_eq!(
            res,
            Validation::NonFatal(
                (),
                (),
                rules,
                vec![
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
                ]
            )
        );
    }

    #[test]
    fn skip_disabled_rules() {
        let rules = RuleRepo([
            RuleSpec {
                essential: true,
                active: true,
                description: "Rule 0",
            },
            RuleSpec {
                essential: true,
                active: false,
                description: "Rule 1",
            },
        ]);
        let validation = Validation::new((), (), rules.clone());
        let modifier = ModifierId::random();
        let rule_1_descr = "Rule 1 failed".to_string();
        let rule_2_descr = "Rule 2 failed".to_string();
        let res = validation
            .verify_fatal(
                RuleId::from(0),
                || true,
                || {
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
            .verify_non_fatal(
                RuleId::from(1),
                || panic!("boom"),
                || InvalidModifier {
                    id: modifier,
                    tpe: ModifierType::BlockHeader,
                    details: rule_2_descr.clone(),
                },
            );
        assert_eq!(res, Validation::Ok((), (), rules));
    }
}
