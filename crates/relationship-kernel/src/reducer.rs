use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::{
    AssertionHead, EffectiveOutcome, ReductionError, ReductionFacts, RelationshipProposition,
};

pub(super) fn validate_reducer(id: &str, version: u64) -> Result<(), ReductionError> {
    reducer(id, version).map(drop)
}

pub(super) fn reduce_effective_relationship(
    facts: ReductionFacts<'_>,
) -> Result<EffectiveOutcome, ReductionError> {
    let mut outcome =
        reducer(facts.reducer_id, facts.reducer_version)?.reduce(facts.proposition, facts.heads);
    if !facts.relationship_active {
        outcome.effective_state = "retired";
    } else if !facts.endpoints_resolved {
        outcome.effective_state = "unresolved";
        outcome.epistemic_state = "incomplete";
    }
    Ok(outcome)
}

impl AssertionHead {
    fn coordinate(&self) -> (&str, &str) {
        (&self.issuer_origin_db_id, &self.assertion_id)
    }

    fn admitted_active(&self) -> bool {
        self.state == "active" && self.local_admission_state == "admitted"
    }

    fn unresolved_active(&self) -> bool {
        self.state == "active" && self.local_admission_state != "admitted"
    }
}

trait RelationshipReducer {
    fn reduce(
        &self,
        proposition: RelationshipProposition<'_>,
        heads: &[AssertionHead],
    ) -> EffectiveOutcome;
}

fn reducer(id: &str, version: u64) -> Result<Box<dyn RelationshipReducer>, ReductionError> {
    if version != 1 {
        return Err(ReductionError::UnknownVersion);
    }
    match id {
        "default" => Ok(Box::new(DefaultReducer)),
        "answerable_by" => Ok(Box::new(AnswerableByReducer)),
        "assigned_to" => Ok(Box::new(AssignedToReducer)),
        "bilateral" => Ok(Box::new(BilateralReducer {
            required_admission_classes: Vec::new(),
        })),
        "legacy_link" => Ok(Box::new(LegacyLinkReducer)),
        _ => Err(ReductionError::UnknownReducer),
    }
}

/// Compatibility add/remove is an assertion frontier, not destructive
/// mutation of another issuer's evidence. A causally-later contest deactivates
/// support; incomparable heads remain unresolved and therefore fail closed.
struct LegacyLinkReducer;

impl RelationshipReducer for LegacyLinkReducer {
    fn reduce(
        &self,
        _proposition: RelationshipProposition<'_>,
        heads: &[AssertionHead],
    ) -> EffectiveOutcome {
        reduce_frontier(heads)
    }
}

fn counts(heads: &[&AssertionHead]) -> (usize, usize, BTreeMap<String, usize>) {
    let support = heads.iter().filter(|head| head.stance == "support").count();
    let contest = heads.iter().filter(|head| head.stance == "contest").count();
    let mut classes = BTreeMap::new();
    for head in heads {
        if let Some(class) = &head.local_admission_class {
            *classes.entry(class.clone()).or_insert(0) += 1;
        }
    }
    (support, contest, classes)
}

fn incomplete(heads: &[AssertionHead]) -> bool {
    let known = heads
        .iter()
        .map(|head| {
            (
                head.issuer_origin_db_id.as_str(),
                head.assertion_id.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let by_coordinate = heads
        .iter()
        .map(|head| {
            (
                (head.issuer_origin_db_id.clone(), head.assertion_id.clone()),
                head,
            )
        })
        .collect::<HashMap<_, _>>();
    heads.iter().any(AssertionHead::unresolved_active)
        || heads
            .iter()
            .filter(|head| head.admitted_active())
            .any(|head| {
                !head.causal_parents_resolved
                    || head.causal_parents.iter().any(|parent| {
                        !known.contains(&(
                            parent.assertion_issuer_origin_db_id.as_str(),
                            parent.assertion_id.as_str(),
                        ))
                    })
            })
        || heads
            .iter()
            .any(|head| descends_from(head, head.coordinate(), &by_coordinate))
}

struct DefaultReducer;

impl RelationshipReducer for DefaultReducer {
    fn reduce(
        &self,
        _proposition: RelationshipProposition<'_>,
        heads: &[AssertionHead],
    ) -> EffectiveOutcome {
        let admitted = heads
            .iter()
            .filter(|head| head.admitted_active())
            .collect::<Vec<_>>();
        let (support, contest, admission_counts) = counts(&admitted);
        EffectiveOutcome {
            effective_state: if support > 0 { "active" } else { "inactive" },
            epistemic_state: if incomplete(heads) {
                "incomplete"
            } else if contest > 0 {
                "contested"
            } else if support > 0 {
                "supported"
            } else {
                "unsupported"
            },
            support_count: support,
            contest_count: contest,
            admission_counts,
        }
    }
}

struct AnswerableByReducer;

impl RelationshipReducer for AnswerableByReducer {
    fn reduce(
        &self,
        proposition: RelationshipProposition<'_>,
        heads: &[AssertionHead],
    ) -> EffectiveOutcome {
        let _definition = (
            proposition.relationship_type,
            proposition.type_definition_id,
        );
        let admitted = heads
            .iter()
            .filter(|head| head.admitted_active())
            .collect::<Vec<_>>();
        let (support, contest, admission_counts) = counts(&admitted);
        let task_support = admitted.iter().any(|head| {
            head.stance == "support"
                && head.local_admission_class.as_deref() == Some("task_authorised_support")
        });
        EffectiveOutcome {
            effective_state: if task_support { "active" } else { "inactive" },
            epistemic_state: if incomplete(heads) {
                "incomplete"
            } else if contest > 0 {
                "contested"
            } else if task_support {
                "supported"
            } else {
                "unsupported"
            },
            support_count: support,
            contest_count: contest,
            admission_counts,
        }
    }
}

struct AssignedToReducer;

impl RelationshipReducer for AssignedToReducer {
    fn reduce(
        &self,
        proposition: RelationshipProposition<'_>,
        heads: &[AssertionHead],
    ) -> EffectiveOutcome {
        let _definition = (
            proposition.relationship_type,
            proposition.type_definition_id,
        );
        reduce_frontier(heads)
    }
}

fn reduce_frontier(heads: &[AssertionHead]) -> EffectiveOutcome {
    let admitted = heads
        .iter()
        .filter(|head| head.admitted_active())
        .collect::<Vec<_>>();
    let (support, contest, admission_counts) = counts(&admitted);
    let frontier = maximal_causal_frontier(heads, &admitted);
    let frontier_support = frontier.iter().any(|head| head.stance == "support");
    let frontier_contest = frontier.iter().any(|head| head.stance == "contest");
    let (effective_state, epistemic_state) = if incomplete(heads) {
        ("unresolved", "incomplete")
    } else if frontier_support && frontier_contest {
        ("unresolved", "contested")
    } else if frontier_support {
        ("active", "supported")
    } else if frontier_contest {
        ("inactive", "contested")
    } else {
        ("inactive", "unsupported")
    };
    EffectiveOutcome {
        effective_state,
        epistemic_state,
        support_count: support,
        contest_count: contest,
        admission_counts,
    }
}

fn maximal_causal_frontier<'a>(
    all: &'a [AssertionHead],
    admitted: &[&'a AssertionHead],
) -> Vec<&'a AssertionHead> {
    let by_coordinate = all
        .iter()
        .map(|head| {
            (
                (head.issuer_origin_db_id.clone(), head.assertion_id.clone()),
                head,
            )
        })
        .collect::<HashMap<_, _>>();
    admitted
        .iter()
        .copied()
        .filter(|candidate| {
            !admitted.iter().any(|other| {
                other.coordinate() != candidate.coordinate()
                    && descends_from(other, candidate.coordinate(), &by_coordinate)
            })
        })
        .collect()
}

fn descends_from(
    child: &AssertionHead,
    ancestor: (&str, &str),
    by_coordinate: &HashMap<(String, String), &AssertionHead>,
) -> bool {
    if !child.causal_parents_resolved {
        return false;
    }
    let mut pending = child
        .causal_parents
        .iter()
        .map(|parent| {
            (
                parent.assertion_issuer_origin_db_id.clone(),
                parent.assertion_id.clone(),
            )
        })
        .collect::<Vec<_>>();
    let mut seen = HashSet::new();
    while let Some(coordinate) = pending.pop() {
        if coordinate.0 == ancestor.0 && coordinate.1 == ancestor.1 {
            return true;
        }
        if !seen.insert(coordinate.clone()) {
            continue;
        }
        if let Some(parent) = by_coordinate.get(&coordinate) {
            if parent.causal_parents_resolved {
                pending.extend(parent.causal_parents.iter().map(|parent| {
                    (
                        parent.assertion_issuer_origin_db_id.clone(),
                        parent.assertion_id.clone(),
                    )
                }));
            }
        }
    }
    false
}

struct BilateralReducer {
    required_admission_classes: Vec<String>,
}

impl RelationshipReducer for BilateralReducer {
    fn reduce(
        &self,
        _proposition: RelationshipProposition<'_>,
        heads: &[AssertionHead],
    ) -> EffectiveOutcome {
        reduce_bilateral(heads, &self.required_admission_classes)
    }
}

fn reduce_bilateral(
    heads: &[AssertionHead],
    required_admission_classes: &[String],
) -> EffectiveOutcome {
    let admitted = heads
        .iter()
        .filter(|head| head.admitted_active())
        .collect::<Vec<_>>();
    let (support, contest, admission_counts) = counts(&admitted);
    let supported_classes = admitted
        .iter()
        .filter(|head| head.stance == "support")
        .filter_map(|head| head.local_admission_class.as_deref())
        .collect::<BTreeSet<_>>();
    let complete = !required_admission_classes.is_empty()
        && required_admission_classes
            .iter()
            .all(|class| supported_classes.contains(class.as_str()));
    EffectiveOutcome {
        effective_state: if complete { "active" } else { "inactive" },
        epistemic_state: if incomplete(heads) || !complete {
            "incomplete"
        } else if contest > 0 {
            "contested"
        } else {
            "supported"
        },
        support_count: support,
        contest_count: contest,
        admission_counts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CausalAssertionParent;

    const ORIGIN: &str = "ndb_0123456789abcdef0123456789abcdef";

    fn parent(id: &str) -> CausalAssertionParent {
        CausalAssertionParent {
            assertion_issuer_origin_db_id: ORIGIN.into(),
            assertion_id: id.into(),
            head_event_issuer_origin_db_id: ORIGIN.into(),
            head_event_id: "00000000-0000-4000-8000-000000000000".into(),
            head_stream_version: 1,
        }
    }

    fn head(id: &str, stance: &str, class: &str, parents: &[&str]) -> AssertionHead {
        AssertionHead {
            issuer_origin_db_id: ORIGIN.into(),
            assertion_id: id.into(),
            stream_version: 1,
            stance: stance.into(),
            state: "active".into(),
            causal_parents: parents.iter().map(|id| parent(id)).collect(),
            causal_parents_resolved: true,
            last_event_issuer_origin_db_id: ORIGIN.into(),
            last_event_id: "00000000-0000-4000-8000-000000000001".into(),
            local_admission_state: "admitted".into(),
            local_admission_class: Some(class.into()),
            local_policy_version: 1,
            local_evidence_digest: Some("a".repeat(64)),
        }
    }

    fn proposition(kind: &str) -> RelationshipProposition<'_> {
        RelationshipProposition {
            relationship_type: kind,
            type_definition_id: match kind {
                "assigned_to" => "assigned_to.v1",
                "answerable_by" => "answerable_by.v1",
                _ => "relates_to.v1",
            },
        }
    }

    fn reduce(id: &str, heads: &[AssertionHead]) -> EffectiveOutcome {
        reduce_effective_relationship(ReductionFacts {
            reducer_id: id,
            reducer_version: 1,
            relationship_active: true,
            endpoints_resolved: true,
            proposition: proposition(id),
            heads,
        })
        .unwrap()
    }

    #[test]
    fn reducer_registry_and_relationship_precedence_fail_closed() {
        assert_eq!(validate_reducer("default", 1), Ok(()));
        assert_eq!(
            validate_reducer("unknown", 1),
            Err(ReductionError::UnknownReducer)
        );
        assert_eq!(
            validate_reducer("default", 2),
            Err(ReductionError::UnknownVersion)
        );
        assert_eq!(
            reduce_effective_relationship(ReductionFacts {
                reducer_id: "unknown",
                reducer_version: 1,
                relationship_active: true,
                endpoints_resolved: true,
                proposition: proposition("relates_to"),
                heads: &[],
            }),
            Err(ReductionError::UnknownReducer)
        );
        assert_eq!(
            reduce_effective_relationship(ReductionFacts {
                reducer_id: "default",
                reducer_version: 2,
                relationship_active: true,
                endpoints_resolved: true,
                proposition: proposition("relates_to"),
                heads: &[],
            }),
            Err(ReductionError::UnknownVersion)
        );

        let support = [head("support", "support", "anchor", &[])];
        let retired = reduce_effective_relationship(ReductionFacts {
            reducer_id: "default",
            reducer_version: 1,
            relationship_active: false,
            endpoints_resolved: false,
            proposition: proposition("relates_to"),
            heads: &support,
        })
        .unwrap();
        assert_eq!(
            (retired.effective_state, retired.epistemic_state),
            ("retired", "supported")
        );
        let unresolved = reduce_effective_relationship(ReductionFacts {
            reducer_id: "default",
            reducer_version: 1,
            relationship_active: true,
            endpoints_resolved: false,
            proposition: proposition("relates_to"),
            heads: &support,
        })
        .unwrap();
        assert_eq!(
            (unresolved.effective_state, unresolved.epistemic_state),
            ("unresolved", "incomplete")
        );
        assert_eq!(unresolved.support_count, 1);
    }

    #[test]
    fn default_reducer_matrix_counts_only_admitted_active_heads() {
        let empty = reduce("default", &[]);
        assert_eq!(
            (empty.effective_state, empty.epistemic_state),
            ("inactive", "unsupported")
        );

        let support = head("support", "support", "left", &[]);
        let contest = head("contest", "contest", "right", &[]);
        let both = reduce("default", &[support.clone(), contest.clone()]);
        assert_eq!(
            (both.effective_state, both.epistemic_state),
            ("active", "contested")
        );
        assert_eq!((both.support_count, both.contest_count), (1, 1));
        assert_eq!(
            both.admission_counts,
            BTreeMap::from([("left".into(), 1), ("right".into(), 1)])
        );

        let mut unresolved = support.clone();
        unresolved.local_admission_state = "unresolved".into();
        let outcome = reduce("default", &[unresolved]);
        assert_eq!(
            (outcome.effective_state, outcome.epistemic_state),
            ("inactive", "incomplete")
        );
        assert_eq!(outcome.support_count, 0);

        let mut retracted = contest;
        retracted.state = "retracted".into();
        assert_eq!(reduce("default", &[retracted]), empty);
    }

    #[test]
    fn answerable_contest_does_not_erase_task_authorised_support() {
        let wrong = reduce("answerable_by", &[head("wrong", "support", "anchor", &[])]);
        assert_eq!(
            (wrong.effective_state, wrong.epistemic_state),
            ("inactive", "unsupported")
        );
        let outcome = reduce(
            "answerable_by",
            &[
                head("support", "support", "task_authorised_support", &[]),
                head("contest", "contest", "accountable_bound_contest", &[]),
            ],
        );
        assert_eq!(
            (outcome.effective_state, outcome.epistemic_state),
            ("active", "contested")
        );
    }

    #[test]
    fn assigned_to_and_legacy_link_use_the_causal_frontier() {
        for reducer_id in ["assigned_to", "legacy_link"] {
            let support = head("support", "support", "task_authorised_support", &[]);
            let contest = head("contest", "contest", "assignee_bound_contest", &["support"]);
            let later = reduce(reducer_id, &[contest.clone(), support.clone()]);
            assert_eq!(
                (later.effective_state, later.epistemic_state),
                ("inactive", "contested")
            );
            assert_eq!(
                later,
                reduce(reducer_id, &[support.clone(), contest.clone()])
            );

            let concurrent = head("concurrent", "contest", "assignee_bound_contest", &[]);
            let outcome = reduce(reducer_id, &[support.clone(), concurrent]);
            assert_eq!(
                (outcome.effective_state, outcome.epistemic_state),
                ("unresolved", "contested")
            );

            let replacement = head(
                "replacement",
                "support",
                "task_authorised_support",
                &["contest"],
            );
            let outcome = reduce(reducer_id, &[support.clone(), contest, replacement]);
            assert_eq!(
                (outcome.effective_state, outcome.epistemic_state),
                ("active", "supported")
            );

            let mut invalidated = support;
            invalidated.state = "invalidated".into();
            assert_eq!(
                reduce(reducer_id, &[invalidated.clone()]).effective_state,
                "inactive"
            );
            invalidated.state = "active".into();
            assert_eq!(
                reduce(reducer_id, &[invalidated]).effective_state,
                "active",
                "restoration reactivates the preserved assertion head"
            );
        }
    }

    #[test]
    fn unresolved_missing_and_cyclic_causality_is_incomplete() {
        let support = head("support", "support", "task_authorised_support", &[]);
        let mut unresolved = head("contest", "contest", "contest", &["support"]);
        unresolved.causal_parents_resolved = false;
        assert_eq!(
            reduce("assigned_to", &[support.clone(), unresolved]).epistemic_state,
            "incomplete"
        );

        let missing = head("missing", "contest", "contest", &["absent"]);
        assert_eq!(
            reduce("assigned_to", &[support.clone(), missing]).epistemic_state,
            "incomplete"
        );

        let self_cycle = head("cycle", "support", "support", &["cycle"]);
        assert_eq!(
            reduce("assigned_to", &[self_cycle]).epistemic_state,
            "incomplete"
        );

        let left = head("left", "support", "support", &["right"]);
        let right = head("right", "contest", "contest", &["left"]);
        assert_eq!(
            reduce("assigned_to", &[left, right]).epistemic_state,
            "incomplete"
        );
    }

    #[test]
    fn bilateral_requires_each_declared_admission_class() {
        let required = vec!["left_support".into(), "right_support".into()];
        assert_eq!(reduce_bilateral(&[], &[]).epistemic_state, "incomplete");
        let one = vec![head("left", "support", "left_support", &[])];
        assert_eq!(
            reduce_bilateral(&one, &required).effective_state,
            "inactive"
        );
        let both = vec![
            head("left", "support", "left_support", &[]),
            head("right", "support", "right_support", &[]),
        ];
        assert_eq!(reduce_bilateral(&both, &required).effective_state, "active");
        assert_eq!(
            reduce_bilateral(&both, &required),
            reduce_bilateral(&[both[1].clone(), both[0].clone()], &required)
        );

        let mut retracted = both.clone();
        retracted[1].state = "retracted".into();
        assert_eq!(
            (
                reduce_bilateral(&retracted, &required).effective_state,
                reduce_bilateral(&retracted, &required).support_count
            ),
            ("inactive", 1)
        );
        let mut contested = both;
        contested.push(head("contest", "contest", "right_support", &[]));
        let outcome = reduce_bilateral(&contested, &required);
        assert_eq!(
            (
                outcome.effective_state,
                outcome.epistemic_state,
                outcome.contest_count
            ),
            ("active", "contested", 1)
        );
    }
}
