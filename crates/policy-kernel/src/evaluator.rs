use std::fmt;

use crate::{Capability, MEMBERS_SUBJECT_ID};

/// Host-verified identity and live membership facts used by policy evaluation.
///
/// Identity lookup remains an adapter responsibility. An absent account keeps
/// stored account grants dormant and cannot match the members baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyEvaluationPrincipal<'a> {
    pub account_id: Option<&'a str>,
    pub is_member: bool,
}

impl<'a> PolicyEvaluationPrincipal<'a> {
    pub fn new(account_id: Option<&'a str>, is_member: bool) -> Self {
        Self {
            account_id,
            is_member,
        }
    }
}

/// One raw row from an explicit policy boundary.
///
/// The evaluator deliberately accepts the persisted strings rather than a
/// pre-normalized policy. This keeps malformed-state validation in the same
/// fold for scalar and preloaded adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyEvaluationEntry<'a> {
    pub subject_kind: &'a str,
    pub subject_id: &'a str,
    pub effect: &'a str,
    pub capability: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyEvaluationError {
    UnsupportedEffect(String),
    UnsupportedSubjectKind(String),
    UnsupportedCapability(String),
}

impl fmt::Display for PolicyEvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedEffect(effect) => {
                write!(formatter, "unsupported policy effect '{effect}'")
            }
            Self::UnsupportedSubjectKind(subject_kind) => {
                write!(
                    formatter,
                    "unsupported policy subject kind '{subject_kind}'"
                )
            }
            Self::UnsupportedCapability(capability) => {
                write!(formatter, "unsupported policy capability '{capability}'")
            }
        }
    }
}

impl std::error::Error for PolicyEvaluationError {}

/// Fold the matching grants at one explicit policy boundary.
///
/// Owner binding is intentionally applied separately with
/// [`resolve_effective_capability`]. Adapters historically validate every
/// policy entry before reading the owner binding, and keeping these phases
/// separate preserves that fail-closed precedence.
pub fn evaluate_policy_grants(
    principal: PolicyEvaluationPrincipal<'_>,
    entries: &[PolicyEvaluationEntry<'_>],
) -> Result<Capability, PolicyEvaluationError> {
    let mut strongest = Capability::None;
    for entry in entries {
        if entry.effect != "allow" {
            return Err(PolicyEvaluationError::UnsupportedEffect(
                entry.effect.to_string(),
            ));
        }
        let matches = match entry.subject_kind {
            "members" => {
                principal.account_id.is_some()
                    && principal.is_member
                    && entry.subject_id == MEMBERS_SUBJECT_ID
            }
            "account" => principal.account_id == Some(entry.subject_id),
            other => {
                return Err(PolicyEvaluationError::UnsupportedSubjectKind(
                    other.to_string(),
                ));
            }
        };
        if matches {
            let capability = Capability::from_policy_str(entry.capability).ok_or_else(|| {
                PolicyEvaluationError::UnsupportedCapability(entry.capability.to_string())
            })?;
            strongest = strongest.max(capability);
        }
    }
    Ok(strongest)
}

/// Apply the non-removable owner floor after policy entries have been
/// validated and folded.
pub fn resolve_effective_capability(
    policy_capability: Capability,
    owner_matches: bool,
) -> Capability {
    if owner_matches {
        Capability::Manage
    } else {
        policy_capability
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry<'a>(
        subject_kind: &'a str,
        subject_id: &'a str,
        effect: &'a str,
        capability: &'a str,
    ) -> PolicyEvaluationEntry<'a> {
        PolicyEvaluationEntry {
            subject_kind,
            subject_id,
            effect,
            capability,
        }
    }

    #[test]
    fn live_membership_requires_a_verified_account_and_the_canonical_subject() {
        let members = [entry("members", MEMBERS_SUBJECT_ID, "allow", "edit")];
        let wrong_subject = [entry("members", "members", "allow", "edit")];

        for (principal, expected) in [
            (
                PolicyEvaluationPrincipal::new(Some("acct:bea"), true),
                Capability::Edit,
            ),
            (
                PolicyEvaluationPrincipal::new(Some("acct:bea"), false),
                Capability::None,
            ),
            (PolicyEvaluationPrincipal::new(None, true), Capability::None),
        ] {
            assert_eq!(evaluate_policy_grants(principal, &members), Ok(expected));
        }
        assert_eq!(
            evaluate_policy_grants(
                PolicyEvaluationPrincipal::new(Some("acct:bea"), true),
                &wrong_subject,
            ),
            Ok(Capability::None)
        );
    }

    #[test]
    fn direct_account_grants_are_membership_independent_and_strongest_wins() {
        let entries = [
            entry("account", "acct:bea", "allow", "view"),
            entry("members", MEMBERS_SUBJECT_ID, "allow", "view"),
            entry("account", "acct:bea", "allow", "edit"),
            entry("account", "acct:other", "allow", "manage"),
        ];

        assert_eq!(
            evaluate_policy_grants(
                PolicyEvaluationPrincipal::new(Some("acct:bea"), false),
                &entries,
            ),
            Ok(Capability::Edit)
        );
    }

    #[test]
    fn malformed_rows_fail_in_input_order_before_the_owner_floor() {
        let principal = PolicyEvaluationPrincipal::new(Some("acct:owner"), true);
        let entries = [
            entry("account", "acct:other", "allow", "future"),
            entry("group", "team:one", "allow", "view"),
            entry("account", "acct:owner", "limit", "manage"),
        ];

        assert_eq!(
            evaluate_policy_grants(principal, &entries),
            Err(PolicyEvaluationError::UnsupportedSubjectKind(
                "group".into()
            )),
            "a malformed capability on a non-matching valid subject stays dormant"
        );
        assert_eq!(
            evaluate_policy_grants(
                principal,
                &[entry("account", "acct:owner", "limit", "manage")],
            ),
            Err(PolicyEvaluationError::UnsupportedEffect("limit".into())),
            "owner status cannot bypass malformed policy state"
        );
    }

    #[test]
    fn malformed_capability_fails_only_when_its_subject_matches() {
        let malformed = [entry("account", "acct:bea", "allow", "future")];
        assert_eq!(
            evaluate_policy_grants(
                PolicyEvaluationPrincipal::new(Some("acct:other"), false),
                &malformed,
            ),
            Ok(Capability::None)
        );
        assert_eq!(
            evaluate_policy_grants(
                PolicyEvaluationPrincipal::new(Some("acct:bea"), false),
                &malformed,
            ),
            Err(PolicyEvaluationError::UnsupportedCapability(
                "future".into()
            ))
        );
    }

    #[test]
    fn owner_floor_is_applied_after_the_policy_fold() {
        assert_eq!(
            resolve_effective_capability(Capability::None, true),
            Capability::Manage
        );
        assert_eq!(
            resolve_effective_capability(Capability::Edit, false),
            Capability::Edit
        );
    }
}
