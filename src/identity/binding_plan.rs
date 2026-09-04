//! Storage-free transition decisions for governed binding mutations.
//!
//! Each adapter owns normalization, authorization, policy lookup and
//! transactional fact collection. These types are the single production
//! interpretation consumed by SQLite preparation/execution and the portable
//! Postgres/Turso domain transaction.

use std::fmt;

use super::BindingClaim;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExistingBinding {
    pub record_id: String,
    pub canonical: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddBindingPlan {
    pub claim: BindingClaim,
    pub record_id: String,
    pub requested_canonical: bool,
    pub present: bool,
    pub was_canonical: bool,
    pub previous_canonical: Option<String>,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CanonicalizeBindingPlan {
    pub claim: BindingClaim,
    pub record_id: String,
    pub was_canonical: bool,
    pub previous_canonical: Option<String>,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoveBindingPlan {
    pub claim: BindingClaim,
    pub record_id: String,
    pub was_canonical: Option<bool>,
    pub required_durable: bool,
    pub system_binding_count: i64,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReconcileBindingFact {
    pub claim: BindingClaim,
    pub owner_record_id: Option<String>,
    pub canonical: bool,
    pub target_canonical_identifier: Option<String>,
    pub transfer_policy: String,
    pub reconciliation_rule: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReconcileBindingPlan {
    pub target_record_id: String,
    pub source_record_id: String,
    pub bindings: Vec<ReconcileBindingFact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BindingPlanError {
    Collision,
    MissingCanonicalTarget,
    RequiredDurable(String),
    StaleOwner(BindingClaim),
    CanonicalTransferCollision(String),
}

impl fmt::Display for BindingPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collision => formatter.write_str(
                "binding collision: external identity already belongs to another visible record",
            ),
            Self::MissingCanonicalTarget => {
                formatter.write_str("binding to canonicalize does not exist on record")
            }
            Self::RequiredDurable(system) => write!(
                formatter,
                "cannot remove the only required durable '{system}' identity"
            ),
            Self::StaleOwner(claim) => write!(
                formatter,
                "stale expected owner for {}:{}",
                claim.system, claim.identifier
            ),
            Self::CanonicalTransferCollision(system) => write!(
                formatter,
                "canonical binding collision while transferring system '{system}'"
            ),
        }
    }
}

pub(crate) fn plan_add(
    record_id: &str,
    claim: BindingClaim,
    requested_canonical: bool,
    existing: Option<ExistingBinding>,
    previous_canonical: Option<String>,
) -> Result<AddBindingPlan, BindingPlanError> {
    validate_add_owner(record_id, existing.as_ref())?;
    let present = existing.is_some();
    let was_canonical = existing.is_some_and(|binding| binding.canonical);
    Ok(AddBindingPlan {
        claim,
        record_id: record_id.into(),
        requested_canonical,
        present,
        was_canonical,
        previous_canonical,
        changed: !present || (requested_canonical && !was_canonical),
    })
}

pub(crate) fn validate_add_owner(
    record_id: &str,
    existing: Option<&ExistingBinding>,
) -> Result<(), BindingPlanError> {
    if existing.is_some_and(|binding| binding.record_id != record_id) {
        Err(BindingPlanError::Collision)
    } else {
        Ok(())
    }
}

pub(crate) fn plan_canonicalize(
    record_id: &str,
    claim: BindingClaim,
    target_canonical: Option<bool>,
    previous_canonical: Option<String>,
) -> Result<CanonicalizeBindingPlan, BindingPlanError> {
    let was_canonical = target_canonical.ok_or(BindingPlanError::MissingCanonicalTarget)?;
    Ok(CanonicalizeBindingPlan {
        claim,
        record_id: record_id.into(),
        was_canonical,
        previous_canonical,
        changed: !was_canonical,
    })
}

pub(crate) fn plan_remove(
    record_id: &str,
    claim: BindingClaim,
    target_canonical: Option<bool>,
    required_durable: bool,
    system_binding_count: i64,
) -> Result<RemoveBindingPlan, BindingPlanError> {
    if target_canonical.is_some() && required_durable && system_binding_count == 1 {
        return Err(BindingPlanError::RequiredDurable(claim.system.clone()));
    }
    Ok(RemoveBindingPlan {
        claim,
        record_id: record_id.into(),
        was_canonical: target_canonical,
        required_durable,
        system_binding_count,
        changed: target_canonical.is_some(),
    })
}

pub(crate) fn plan_reconcile(
    target_record_id: &str,
    source_record_id: &str,
    bindings: Vec<ReconcileBindingFact>,
) -> Result<ReconcileBindingPlan, BindingPlanError> {
    validate_reconcile_owners(source_record_id, &bindings)?;
    for binding in &bindings {
        if binding.canonical && binding.target_canonical_identifier.is_some() {
            return Err(BindingPlanError::CanonicalTransferCollision(
                binding.claim.system.clone(),
            ));
        }
    }
    Ok(ReconcileBindingPlan {
        target_record_id: target_record_id.into(),
        source_record_id: source_record_id.into(),
        bindings,
    })
}

pub(crate) fn validate_reconcile_owners(
    source_record_id: &str,
    bindings: &[ReconcileBindingFact],
) -> Result<(), BindingPlanError> {
    for binding in bindings {
        if binding.owner_record_id.as_deref() != Some(source_record_id) {
            return Err(BindingPlanError::StaleOwner(binding.claim.clone()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(identifier: &str) -> BindingClaim {
        BindingClaim {
            system: "native-principal".into(),
            identifier: identifier.into(),
        }
    }

    #[test]
    fn add_matrix_distinguishes_insert_promotion_noop_and_collision() {
        let insert = plan_add("target", claim("new"), true, None, Some("old".into())).unwrap();
        assert!(insert.changed);
        assert!(!insert.present);
        assert_eq!(insert.previous_canonical.as_deref(), Some("old"));

        let noop = plan_add(
            "target",
            claim("same"),
            false,
            Some(ExistingBinding {
                record_id: "target".into(),
                canonical: true,
            }),
            None,
        )
        .unwrap();
        assert!(!noop.changed);

        let promoted = plan_add(
            "target",
            claim("same"),
            true,
            Some(ExistingBinding {
                record_id: "target".into(),
                canonical: false,
            }),
            Some("old".into()),
        )
        .unwrap();
        assert!(promoted.changed);

        assert_eq!(
            plan_add(
                "target",
                claim("foreign"),
                false,
                Some(ExistingBinding {
                    record_id: "other".into(),
                    canonical: false,
                }),
                None,
            ),
            Err(BindingPlanError::Collision)
        );
    }

    #[test]
    fn canonicalize_and_remove_matrix_preserves_noops_and_guards() {
        assert_eq!(
            plan_canonicalize("target", claim("missing"), None, None),
            Err(BindingPlanError::MissingCanonicalTarget)
        );
        assert!(
            !plan_canonicalize("target", claim("same"), Some(true), Some("same".into()))
                .unwrap()
                .changed
        );
        assert!(
            plan_canonicalize("target", claim("next"), Some(false), Some("old".into()))
                .unwrap()
                .changed
        );

        assert!(
            !plan_remove("target", claim("absent"), None, false, 0)
                .unwrap()
                .changed
        );
        assert_eq!(
            plan_remove("target", claim("last"), Some(true), true, 1),
            Err(BindingPlanError::RequiredDurable("native-principal".into()))
        );
        assert!(
            plan_remove("target", claim("one-of-two"), Some(false), true, 2)
                .unwrap()
                .changed
        );
    }

    #[test]
    fn reconcile_matrix_checks_owner_and_canonical_collision() {
        let fact = |owner: Option<&str>, canonical, target: Option<&str>| ReconcileBindingFact {
            claim: claim("selected"),
            owner_record_id: owner.map(str::to_owned),
            canonical,
            target_canonical_identifier: target.map(str::to_owned),
            transfer_policy: "record_manage".into(),
            reconciliation_rule: "binding_only".into(),
        };
        assert!(
            plan_reconcile("target", "source", vec![fact(Some("source"), false, None)]).is_ok()
        );
        assert!(matches!(
            plan_reconcile("target", "source", vec![fact(Some("other"), false, None)]),
            Err(BindingPlanError::StaleOwner(_))
        ));
        assert_eq!(
            plan_reconcile(
                "target",
                "source",
                vec![fact(Some("source"), true, Some("occupied"))]
            ),
            Err(BindingPlanError::CanonicalTransferCollision(
                "native-principal".into()
            ))
        );
    }
}
