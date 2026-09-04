use super::{
    normalize_entries, AllowEntry, Capability, PlanError, PolicyMode, PolicyMutation,
    PolicySnapshot, PolicySubject, PolicyTransition, MEMBERS_SUBJECT_ID,
};

fn subject_key(subject: &PolicySubject) -> (&'static str, &str) {
    match subject {
        PolicySubject::Members => ("members", MEMBERS_SUBJECT_ID),
        PolicySubject::Account(id) => ("account", id),
    }
}

fn validate_members_capabilities(entries: &[AllowEntry]) -> Result<(), PlanError> {
    if entries.iter().any(|entry| {
        matches!(entry.subject, PolicySubject::Members) && entry.capability == Capability::Manage
    }) {
        return Err(PlanError::MembersManageMutation);
    }
    Ok(())
}

fn effective_members_baseline(entries: &[AllowEntry]) -> Option<Capability> {
    entries
        .iter()
        .filter_map(|entry| {
            matches!(entry.subject, PolicySubject::Members)
                .then_some(entry.capability)
                .filter(|capability| *capability != Capability::None)
        })
        .max()
}

pub(super) fn validate_inheritance_restoration(
    record_id: &str,
    is_canonical_root: bool,
    before: &PolicySnapshot,
) -> Result<(), PlanError> {
    if is_canonical_root {
        return Err(PlanError::CanonicalRootCannotInherit);
    }
    if before.mode != PolicyMode::Explicit {
        return Err(PlanError::ExplicitPolicyRequired {
            record_id: record_id.to_owned(),
        });
    }
    Ok(())
}

pub(super) fn plan_policy_transition(
    record_id: &str,
    is_canonical_root: bool,
    before: &PolicySnapshot,
    mutation: PolicyMutation,
) -> Result<PolicyTransition, PlanError> {
    let before_normalized = normalize_entries(before.entries.clone())?;
    let no_change = || PolicyTransition::NoChange {
        after_mode: before.mode,
        after_anchor_id: before.anchor_id.clone(),
        after_normalized: before_normalized.clone(),
    };
    let replace = |entries: Vec<AllowEntry>| -> Result<PolicyTransition, PlanError> {
        let after_normalized = normalize_entries(entries.clone())?;
        Ok(PolicyTransition::ReplaceExplicit {
            after_anchor_id: record_id.to_owned(),
            entries,
            after_normalized,
            boundary_created: before.mode == PolicyMode::Inherit,
        })
    };

    match mutation {
        PolicyMutation::Set {
            subject,
            capability,
        } => {
            if matches!(subject, PolicySubject::Members) && capability == Some(Capability::Manage) {
                return Err(PlanError::MembersManageMutation);
            }
            let requested = capability.filter(|capability| *capability != Capability::None);
            let key = subject_key(&subject);
            let current = before
                .entries
                .iter()
                .filter(|entry| subject_key(&entry.subject) == key)
                .map(|entry| entry.capability)
                .max();
            if current == requested {
                Ok(no_change())
            } else {
                let mut entries = before.entries.clone();
                entries.retain(|entry| subject_key(&entry.subject) != key);
                if let Some(capability) = requested {
                    entries.push(AllowEntry {
                        subject,
                        capability,
                    });
                }
                replace(entries)
            }
        }
        PolicyMutation::Grant {
            subject,
            capability,
        } => {
            validate_members_capabilities(&[AllowEntry {
                subject: subject.clone(),
                capability,
            }])?;
            if capability == Capability::None {
                return Ok(no_change());
            }
            let key = subject_key(&subject);
            if before.entries.iter().any(|entry| {
                subject_key(&entry.subject) == key && entry.capability.allows(capability)
            }) {
                Ok(no_change())
            } else {
                let mut entries = before.entries.clone();
                entries.retain(|entry| subject_key(&entry.subject) != key);
                entries.push(AllowEntry {
                    subject,
                    capability,
                });
                replace(entries)
            }
        }
        PolicyMutation::Revoke { subject } => {
            let key = subject_key(&subject);
            if !before
                .entries
                .iter()
                .any(|entry| subject_key(&entry.subject) == key)
            {
                Ok(no_change())
            } else {
                let mut entries = before.entries.clone();
                entries.retain(|entry| subject_key(&entry.subject) != key);
                replace(entries)
            }
        }
        PolicyMutation::SetMembersBaseline { capability } => {
            if capability == Some(Capability::Manage) {
                return Err(PlanError::MembersManageMutation);
            }
            let requested = capability.filter(|capability| *capability != Capability::None);
            if effective_members_baseline(&before.entries) == requested {
                Ok(no_change())
            } else {
                let mut entries = before.entries.clone();
                entries.retain(|entry| !matches!(entry.subject, PolicySubject::Members));
                if let Some(capability) = requested {
                    entries.push(AllowEntry::members(capability));
                }
                replace(entries)
            }
        }
        PolicyMutation::Replace { entries } => {
            validate_members_capabilities(&entries)?;
            let normalized = normalize_entries(entries.clone())?;
            let changed = before.mode != PolicyMode::Explicit || normalized != before_normalized;
            if changed {
                replace(entries)
            } else {
                Ok(no_change())
            }
        }
        PolicyMutation::RestoreInheritance { inherited } => {
            validate_inheritance_restoration(record_id, is_canonical_root, before)?;
            let after_normalized = normalize_entries(inherited.entries)?;
            Ok(PolicyTransition::RestoreInheritance {
                after_anchor_id: inherited.anchor_id,
                after_normalized,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RECORD_ID: &str = "01920b7a-6f2b-7c3d-8e4f-5a6b7c8d9e0f";

    fn account(id: &str, capability: Capability) -> AllowEntry {
        AllowEntry::account(id, capability)
    }

    fn snapshot(mode: PolicyMode, anchor_id: &str, entries: Vec<AllowEntry>) -> PolicySnapshot {
        PolicySnapshot {
            mode,
            anchor_id: anchor_id.into(),
            entries,
            revision: "prv1:test".into(),
        }
    }

    fn plan(
        before: &PolicySnapshot,
        mutation: PolicyMutation,
    ) -> Result<PolicyTransition, PlanError> {
        plan_policy_transition(RECORD_ID, false, before, mutation)
    }

    fn replacement_entries(plan: &PolicyTransition) -> &[AllowEntry] {
        match plan {
            PolicyTransition::ReplaceExplicit { entries, .. } => entries,
            other => panic!("expected explicit replacement, got {other:?}"),
        }
    }

    #[test]
    fn set_converges_one_subject_exactly_without_disturbing_other_entries() {
        let before = snapshot(
            PolicyMode::Explicit,
            RECORD_ID,
            vec![
                AllowEntry::members(Capability::View),
                account("acct:a", Capability::Manage),
                account("acct:b", Capability::Edit),
            ],
        );

        let downgraded = plan(
            &before,
            PolicyMutation::Set {
                subject: PolicySubject::Account("acct:a".into()),
                capability: Some(Capability::View),
            },
        )
        .unwrap();
        assert!(downgraded.changed());
        assert_eq!(
            normalize_entries(replacement_entries(&downgraded).to_vec()).unwrap(),
            normalize_entries(vec![
                AllowEntry::members(Capability::View),
                account("acct:a", Capability::View),
                account("acct:b", Capability::Edit),
            ])
            .unwrap()
        );

        let removed = plan(
            &before,
            PolicyMutation::Set {
                subject: PolicySubject::Account("acct:a".into()),
                capability: None,
            },
        )
        .unwrap();
        assert!(removed.changed());
        assert_eq!(
            normalize_entries(replacement_entries(&removed).to_vec()).unwrap(),
            normalize_entries(vec![
                AllowEntry::members(Capability::View),
                account("acct:b", Capability::Edit),
            ])
            .unwrap()
        );

        let same = plan(
            &before,
            PolicyMutation::Set {
                subject: PolicySubject::Account("acct:a".into()),
                capability: Some(Capability::Manage),
            },
        )
        .unwrap();
        assert!(!same.changed());

        let members_manage = plan(
            &before,
            PolicyMutation::Set {
                subject: PolicySubject::Members,
                capability: Some(Capability::Manage),
            },
        )
        .unwrap_err();
        assert_eq!(members_manage, PlanError::MembersManageMutation);
    }

    #[test]
    fn grants_compare_capability_before_creating_or_replacing_a_boundary() {
        let inherited = snapshot(
            PolicyMode::Inherit,
            "native:root",
            vec![account("acct:a", Capability::Edit)],
        );
        for capability in [Capability::View, Capability::Edit] {
            let transition = plan(
                &inherited,
                PolicyMutation::Grant {
                    subject: PolicySubject::Account("acct:a".into()),
                    capability,
                },
            )
            .unwrap();
            assert!(!transition.changed(), "{capability:?} is already allowed");
            assert_eq!(transition.after_mode(), PolicyMode::Inherit);
            assert_eq!(transition.after_anchor_id(), "native:root");
        }

        let absent_none = plan(
            &inherited,
            PolicyMutation::Grant {
                subject: PolicySubject::Account("acct:missing".into()),
                capability: Capability::None,
            },
        )
        .unwrap();
        assert!(!absent_none.changed());
        assert!(!absent_none.boundary_created());
        assert_eq!(absent_none.after_mode(), PolicyMode::Inherit);
        assert_eq!(absent_none.after_anchor_id(), "native:root");
        assert_eq!(
            absent_none.after_normalized(),
            normalize_entries(inherited.entries.clone()).unwrap()
        );

        let stronger = plan(
            &inherited,
            PolicyMutation::Grant {
                subject: PolicySubject::Account("acct:a".into()),
                capability: Capability::Manage,
            },
        )
        .unwrap();
        assert!(stronger.changed());
        assert!(stronger.boundary_created());
        assert_eq!(stronger.after_mode(), PolicyMode::Explicit);
        assert_eq!(stronger.after_anchor_id(), RECORD_ID);
        assert_eq!(
            replacement_entries(&stronger),
            &[account("acct:a", Capability::Manage)]
        );

        let explicit = snapshot(
            PolicyMode::Explicit,
            RECORD_ID,
            vec![account("acct:a", Capability::Manage)],
        );
        let explicit_weaker = plan(
            &explicit,
            PolicyMutation::Grant {
                subject: PolicySubject::Account("acct:a".into()),
                capability: Capability::View,
            },
        )
        .unwrap();
        assert!(!explicit_weaker.changed());
        assert_eq!(explicit_weaker.after_mode(), PolicyMode::Explicit);
        assert_eq!(explicit_weaker.after_anchor_id(), RECORD_ID);
    }

    #[test]
    fn revoke_and_members_baseline_distinguish_noops_from_exact_replacements() {
        let before = snapshot(
            PolicyMode::Explicit,
            RECORD_ID,
            vec![
                AllowEntry::members(Capability::View),
                account("acct:a", Capability::Edit),
            ],
        );
        let absent = plan(
            &before,
            PolicyMutation::Revoke {
                subject: PolicySubject::Account("acct:missing".into()),
            },
        )
        .unwrap();
        assert!(!absent.changed());

        let revoked = plan(
            &before,
            PolicyMutation::Revoke {
                subject: PolicySubject::Account("acct:a".into()),
            },
        )
        .unwrap();
        assert!(revoked.changed());
        assert_eq!(
            replacement_entries(&revoked),
            &[AllowEntry::members(Capability::View)]
        );

        let same = plan(
            &before,
            PolicyMutation::SetMembersBaseline {
                capability: Some(Capability::View),
            },
        )
        .unwrap();
        assert!(!same.changed());

        let removed = plan(
            &before,
            PolicyMutation::SetMembersBaseline { capability: None },
        )
        .unwrap();
        assert_eq!(
            replacement_entries(&removed),
            &[account("acct:a", Capability::Edit)]
        );

        let removed_with_none_capability = plan(
            &before,
            PolicyMutation::SetMembersBaseline {
                capability: Some(Capability::None),
            },
        )
        .unwrap();
        assert_eq!(
            replacement_entries(&removed_with_none_capability),
            &[account("acct:a", Capability::Edit)]
        );
        assert_eq!(
            removed_with_none_capability.after_normalized(),
            removed.after_normalized()
        );

        let without_baseline = snapshot(
            PolicyMode::Explicit,
            RECORD_ID,
            vec![account("acct:a", Capability::Edit)],
        );
        let absent_none_capability = plan(
            &without_baseline,
            PolicyMutation::SetMembersBaseline {
                capability: Some(Capability::None),
            },
        )
        .unwrap();
        assert!(!absent_none_capability.changed());

        for members in [
            vec![
                AllowEntry::members(Capability::View),
                AllowEntry::members(Capability::Edit),
            ],
            vec![
                AllowEntry::members(Capability::Edit),
                AllowEntry::members(Capability::View),
            ],
        ] {
            let mut entries = members;
            entries.push(account("acct:a", Capability::Edit));
            let duplicate_baseline = snapshot(PolicyMode::Explicit, RECORD_ID, entries);
            let narrowed = plan(
                &duplicate_baseline,
                PolicyMutation::SetMembersBaseline {
                    capability: Some(Capability::View),
                },
            )
            .unwrap();
            assert_eq!(
                replacement_entries(&narrowed),
                &[
                    account("acct:a", Capability::Edit),
                    AllowEntry::members(Capability::View),
                ]
            );
        }
    }

    #[test]
    fn mutation_mode_cross_product_creates_only_the_required_boundaries() {
        let explicit = snapshot(
            PolicyMode::Explicit,
            RECORD_ID,
            vec![account("acct:a", Capability::Edit)],
        );
        let new_grant = plan(
            &explicit,
            PolicyMutation::Grant {
                subject: PolicySubject::Account("acct:b".into()),
                capability: Capability::View,
            },
        )
        .unwrap();
        assert!(new_grant.changed());
        assert!(!new_grant.boundary_created());
        assert_eq!(
            replacement_entries(&new_grant),
            &[
                account("acct:a", Capability::Edit),
                account("acct:b", Capability::View),
            ]
        );

        let added_baseline = plan(
            &explicit,
            PolicyMutation::SetMembersBaseline {
                capability: Some(Capability::View),
            },
        )
        .unwrap();
        assert!(added_baseline.changed());
        assert!(!added_baseline.boundary_created());
        assert_eq!(
            replacement_entries(&added_baseline),
            &[
                account("acct:a", Capability::Edit),
                AllowEntry::members(Capability::View),
            ]
        );

        let inherited = snapshot(
            PolicyMode::Inherit,
            "native:root",
            vec![
                AllowEntry::members(Capability::View),
                account("acct:a", Capability::Edit),
            ],
        );
        let revoked = plan(
            &inherited,
            PolicyMutation::Revoke {
                subject: PolicySubject::Account("acct:a".into()),
            },
        )
        .unwrap();
        assert!(revoked.boundary_created());

        let inherited_new_grant = plan(
            &inherited,
            PolicyMutation::Grant {
                subject: PolicySubject::Account("acct:b".into()),
                capability: Capability::View,
            },
        )
        .unwrap();
        assert!(inherited_new_grant.changed());
        assert!(inherited_new_grant.boundary_created());
        assert_eq!(
            replacement_entries(&inherited_new_grant),
            &[
                AllowEntry::members(Capability::View),
                account("acct:a", Capability::Edit),
                account("acct:b", Capability::View),
            ]
        );

        let baseline = plan(
            &inherited,
            PolicyMutation::SetMembersBaseline {
                capability: Some(Capability::Edit),
            },
        )
        .unwrap();
        assert!(baseline.boundary_created());
        assert_eq!(
            replacement_entries(&baseline),
            &[
                account("acct:a", Capability::Edit),
                AllowEntry::members(Capability::Edit),
            ]
        );

        let equal_but_inherited = plan(
            &inherited,
            PolicyMutation::Replace {
                entries: inherited.entries.clone(),
            },
        )
        .unwrap();
        assert!(equal_but_inherited.boundary_created());

        let canonical_before = snapshot(
            PolicyMode::Explicit,
            RECORD_ID,
            vec![
                account("acct:a", Capability::Manage),
                account("acct:b", Capability::View),
            ],
        );
        let duplicate_and_reordered = plan(
            &canonical_before,
            PolicyMutation::Replace {
                entries: vec![
                    account("acct:b", Capability::View),
                    account("acct:a", Capability::View),
                    account("acct:a", Capability::Manage),
                ],
            },
        )
        .unwrap();
        assert!(!duplicate_and_reordered.changed());
    }

    #[test]
    fn replacements_and_grants_reject_a_members_manage_grant() {
        let before = snapshot(
            PolicyMode::Explicit,
            RECORD_ID,
            vec![account("acct:a", Capability::Edit)],
        );
        let same = plan(
            &before,
            PolicyMutation::Replace {
                entries: vec![account("acct:a", Capability::Edit)],
            },
        )
        .unwrap();
        assert!(!same.changed());

        for mutation in [
            PolicyMutation::Replace {
                entries: vec![AllowEntry::members(Capability::Manage)],
            },
            PolicyMutation::Grant {
                subject: PolicySubject::Members,
                capability: Capability::Manage,
            },
        ] {
            assert_eq!(
                plan(&before, mutation).unwrap_err(),
                PlanError::MembersManageMutation
            );
        }
    }

    #[test]
    fn inheritance_restoration_requires_a_non_root_explicit_boundary() {
        let inherited = snapshot(
            PolicyMode::Inherit,
            "native:root",
            vec![AllowEntry::members(Capability::View)],
        );
        let explicit = snapshot(
            PolicyMode::Explicit,
            RECORD_ID,
            vec![account("acct:a", Capability::Manage)],
        );
        let transition = plan(
            &explicit,
            PolicyMutation::RestoreInheritance {
                inherited: inherited.clone(),
            },
        )
        .unwrap();
        assert!(transition.changed());
        assert!(matches!(
            transition,
            PolicyTransition::RestoreInheritance { .. }
        ));
        assert!(!transition.boundary_created());
        assert_eq!(transition.after_mode(), PolicyMode::Inherit);
        assert_eq!(transition.after_anchor_id(), "native:root");

        assert_eq!(
            plan(
                &inherited,
                PolicyMutation::RestoreInheritance {
                    inherited: inherited.clone(),
                },
            )
            .unwrap_err(),
            PlanError::ExplicitPolicyRequired {
                record_id: RECORD_ID.into()
            }
        );
        assert_eq!(
            plan_policy_transition(
                RECORD_ID,
                true,
                &explicit,
                PolicyMutation::RestoreInheritance { inherited },
            )
            .unwrap_err(),
            PlanError::CanonicalRootCannotInherit
        );
    }
}
