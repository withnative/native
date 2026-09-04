use super::{Classification, ClassificationInput, Eligibility, MechanicalReason};

pub(super) fn classify(mut input: ClassificationInput) -> Classification {
    if input.current == input.target {
        input.blockers.push(MechanicalReason {
            code: "identical_shape".into(),
            detail: "current and target type/kind are identical".into(),
        });
    }
    if !input.target_active {
        input.blockers.push(MechanicalReason {
            code: "target_identity_not_active".into(),
            detail: "target type/kind is not active governed identity".into(),
        });
    }
    input
        .blockers
        .sort_by(|a, b| (&a.code, &a.detail).cmp(&(&b.code, &b.detail)));
    input.blockers.dedup();

    let (eligibility, reasons) = if !input.blockers.is_empty() {
        (Eligibility::Ineligible, input.blockers)
    } else if input.unique_wrong_type_match && input.same_run_provenance && !input.shared_use {
        (
            Eligibility::Autonomous,
            vec![MechanicalReason {
                code: "unique_same_run_wrong_type".into(),
                detail: "the quarantined stored kind has one active cross-spine match and every relevant contribution belongs to the creating run".into(),
            }],
        )
    } else {
        let mut reasons = Vec::new();
        if !input.unique_wrong_type_match {
            reasons.push(MechanicalReason {
                code: "autonomous_identity_not_proven".into(),
                detail: "the first-slice unique registry-provable wrong-type rule is not satisfied"
                    .into(),
            });
        }
        if !input.same_run_provenance {
            reasons.push(MechanicalReason {
                code: "autonomous_provenance_not_proven".into(),
                detail: "all relevant state cannot be attributed to the creating caller/run".into(),
            });
        }
        if input.shared_use {
            reasons.push(MechanicalReason {
                code: "record_in_shared_use".into(),
                detail: "independent or dependent state has entered shared use".into(),
            });
        }
        (Eligibility::ConfirmationRequired, reasons)
    };
    Classification {
        eligibility,
        reasons,
        current: input.current,
        target: input.target,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;
    use serde_json::json;

    fn identity(record_type: &str, kind: &str) -> Identity {
        Identity {
            record_type: record_type.into(),
            kind: kind.into(),
        }
    }

    fn input(
        unique_wrong_type_match: bool,
        same_run_provenance: bool,
        shared_use: bool,
    ) -> ClassificationInput {
        ClassificationInput {
            current: identity("Document", "decision"),
            target: identity("Resolution", "decision"),
            target_active: true,
            unique_wrong_type_match,
            same_run_provenance,
            shared_use,
            blockers: vec![],
        }
    }

    fn reason_codes(classification: &Classification) -> Vec<&str> {
        classification
            .reasons
            .iter()
            .map(|reason| reason.code.as_str())
            .collect()
    }

    #[test]
    fn autonomous_eligibility_requires_every_positive_fact_and_no_shared_use() {
        for unique_wrong_type_match in [false, true] {
            for same_run_provenance in [false, true] {
                for shared_use in [false, true] {
                    let classified = classify(input(
                        unique_wrong_type_match,
                        same_run_provenance,
                        shared_use,
                    ));
                    let autonomous = unique_wrong_type_match && same_run_provenance && !shared_use;
                    assert_eq!(
                        classified.eligibility,
                        if autonomous {
                            Eligibility::Autonomous
                        } else {
                            Eligibility::ConfirmationRequired
                        },
                        "unique={unique_wrong_type_match}, same_run={same_run_provenance}, shared={shared_use}"
                    );
                    let mut expected = Vec::new();
                    if autonomous {
                        expected.push("unique_same_run_wrong_type");
                    } else {
                        if !unique_wrong_type_match {
                            expected.push("autonomous_identity_not_proven");
                        }
                        if !same_run_provenance {
                            expected.push("autonomous_provenance_not_proven");
                        }
                        if shared_use {
                            expected.push("record_in_shared_use");
                        }
                    }
                    assert_eq!(reason_codes(&classified), expected);
                }
            }
        }
    }

    #[test]
    fn blockers_dominate_autonomous_facts_and_are_sorted_and_deduplicated() {
        let duplicate = MechanicalReason {
            code: "semantic_unit".into(),
            detail: "immutable".into(),
        };
        let mut facts = input(true, true, false);
        facts.blockers = vec![
            duplicate.clone(),
            MechanicalReason {
                code: "another_blocker".into(),
                detail: "comes first".into(),
            },
            duplicate,
        ];

        let classified = classify(facts);

        assert_eq!(classified.eligibility, Eligibility::Ineligible);
        assert_eq!(
            reason_codes(&classified),
            ["another_blocker", "semantic_unit"]
        );
    }

    #[test]
    fn identical_or_inactive_targets_fail_closed_independently() {
        for identical in [false, true] {
            for target_active in [false, true] {
                let current = identity("Document", "decision");
                let target = if identical {
                    current.clone()
                } else {
                    identity("Resolution", "decision")
                };
                let classified = classify(ClassificationInput {
                    current,
                    target,
                    target_active,
                    unique_wrong_type_match: true,
                    same_run_provenance: true,
                    shared_use: false,
                    blockers: vec![],
                });

                let expected = match (identical, target_active) {
                    (false, true) => vec!["unique_same_run_wrong_type"],
                    (false, false) => vec!["target_identity_not_active"],
                    (true, true) => vec!["identical_shape"],
                    (true, false) => {
                        vec!["identical_shape", "target_identity_not_active"]
                    }
                };
                assert_eq!(
                    classified.eligibility,
                    if identical || !target_active {
                        Eligibility::Ineligible
                    } else {
                        Eligibility::Autonomous
                    }
                );
                assert_eq!(reason_codes(&classified), expected);
            }
        }
    }

    #[test]
    fn classification_preserves_current_and_target_identities() {
        let current = identity("Document", "decision");
        let target = identity("Resolution", "resolution");
        let classified = classify(ClassificationInput {
            current: current.clone(),
            target: target.clone(),
            target_active: true,
            unique_wrong_type_match: false,
            same_run_provenance: true,
            shared_use: false,
            blockers: vec![],
        });

        assert_eq!(classified.current, current);
        assert_eq!(classified.target, target);
    }

    #[test]
    fn serialized_classification_preserves_the_signed_effect_shape() {
        let autonomous = classify(input(true, true, false));

        assert_eq!(
            serde_json::to_value(autonomous).unwrap(),
            json!({
                "eligibility": "autonomous",
                "reasons": [{
                    "code": "unique_same_run_wrong_type",
                    "detail": "the quarantined stored kind has one active cross-spine match and every relevant contribution belongs to the creating run"
                }],
                "current": {"type": "Document", "kind": "decision"},
                "target": {"type": "Resolution", "kind": "decision"}
            })
        );

        let confirmed = classify(input(false, true, false));
        assert_eq!(
            serde_json::to_value(confirmed).unwrap(),
            json!({
                "eligibility": "confirmation_required",
                "reasons": [{
                    "code": "autonomous_identity_not_proven",
                    "detail": "the first-slice unique registry-provable wrong-type rule is not satisfied"
                }],
                "current": {"type": "Document", "kind": "decision"},
                "target": {"type": "Resolution", "kind": "decision"}
            })
        );

        let mut blocked_input = input(true, true, false);
        blocked_input.target_active = false;
        let blocked = classify(blocked_input);
        assert_eq!(
            serde_json::to_value(blocked).unwrap(),
            json!({
                "eligibility": "ineligible",
                "reasons": [{
                    "code": "target_identity_not_active",
                    "detail": "target type/kind is not active governed identity"
                }],
                "current": {"type": "Document", "kind": "decision"},
                "target": {"type": "Resolution", "kind": "decision"}
            })
        );

        assert_eq!(
            serde_json::to_value(Eligibility::ConfirmationRequired).unwrap(),
            json!("confirmation_required")
        );
        assert_eq!(
            serde_json::to_value(Eligibility::Ineligible).unwrap(),
            json!("ineligible")
        );
    }

    #[test]
    fn eligibility_owns_the_exact_executor_mode_and_confirmation_contract() {
        let cases = [
            (Eligibility::Autonomous, "autonomous", false),
            (Eligibility::ConfirmationRequired, "confirmed", true),
            (Eligibility::Ineligible, "ineligible", false),
        ];

        for (eligibility, mode, confirmation_required) in cases {
            assert_eq!(eligibility.execution_mode(), mode);
            assert_eq!(eligibility.confirmation_required(), confirmation_required);
        }
    }
}
