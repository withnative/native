//! Storage-free record-policy types, evaluation, normalization, and mutation
//! planning.
//!
//! Physical adapters resolve identities and load snapshots. This crate owns
//! the deterministic transition from those facts to a persistence plan, so
//! preparation and execution cannot develop separate policy interpretations.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// Fast-lane eligibility is deliberately structural: changes to this shared
// public API file are ineligible, while private planner/evaluator implementation
// changes are candidates only after their public contracts have already landed.
mod evaluator;
mod planner;

pub use evaluator::{
    evaluate_policy_grants, resolve_effective_capability, PolicyEvaluationEntry,
    PolicyEvaluationError, PolicyEvaluationPrincipal,
};

pub const MEMBERS_SUBJECT_ID: &str = "native:members";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    None,
    View,
    Edit,
    Manage,
}

impl Capability {
    pub fn as_policy_str(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::View => Some("view"),
            Self::Edit => Some("edit"),
            Self::Manage => Some("manage"),
        }
    }

    pub fn allows(self, required: Self) -> bool {
        self >= required
    }

    pub fn from_policy_str(value: &str) -> Option<Self> {
        match value {
            "view" => Some(Self::View),
            "edit" => Some(Self::Edit),
            "manage" => Some(Self::Manage),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyMode {
    Inherit,
    Explicit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicySubject {
    Members,
    Account(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowEntry {
    pub subject: PolicySubject,
    pub capability: Capability,
}

impl AllowEntry {
    pub fn members(capability: Capability) -> Self {
        Self {
            subject: PolicySubject::Members,
            capability,
        }
    }

    pub fn account(account_id: impl Into<String>, capability: Capability) -> Self {
        Self {
            subject: PolicySubject::Account(account_id.into()),
            capability,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedPolicyEntry {
    pub subject_kind: String,
    pub subject_id: String,
    pub effect: String,
    pub capability: String,
}

impl NormalizedPolicyEntry {
    pub fn new(subject_kind: String, subject_id: String, capability: Capability) -> Self {
        Self {
            subject_kind,
            subject_id,
            effect: "allow".into(),
            capability: capability
                .as_policy_str()
                .expect("none policy entries are omitted")
                .into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    MembersManage,
    EmptyAccount,
}

impl fmt::Display for NormalizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MembersManage => formatter.write_str("the members baseline cannot grant manage"),
            Self::EmptyAccount => formatter.write_str("account policy subject cannot be empty"),
        }
    }
}

impl std::error::Error for NormalizeError {}

pub fn normalize_entries(
    entries: Vec<AllowEntry>,
) -> Result<Vec<NormalizedPolicyEntry>, NormalizeError> {
    let mut strongest: HashMap<(String, String), Capability> = HashMap::new();
    for entry in entries {
        if entry.capability == Capability::None {
            continue;
        }
        let (kind, id) = match entry.subject {
            PolicySubject::Members => {
                if entry.capability == Capability::Manage {
                    return Err(NormalizeError::MembersManage);
                }
                ("members".to_string(), MEMBERS_SUBJECT_ID.to_string())
            }
            PolicySubject::Account(id) => {
                if id.is_empty() {
                    return Err(NormalizeError::EmptyAccount);
                }
                ("account".to_string(), id)
            }
        };
        strongest
            .entry((kind, id))
            .and_modify(|current| *current = (*current).max(entry.capability))
            .or_insert(entry.capability);
    }
    let mut normalized = strongest
        .into_iter()
        .map(|((kind, id), capability)| NormalizedPolicyEntry::new(kind, id, capability))
        .collect::<Vec<_>>();
    normalized.sort();
    Ok(normalized)
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub mode: PolicyMode,
    pub anchor_id: String,
    pub entries: Vec<AllowEntry>,
    pub revision: String,
}

#[derive(Debug)]
pub enum PolicyMutation {
    Set {
        subject: PolicySubject,
        capability: Option<Capability>,
    },
    Grant {
        subject: PolicySubject,
        capability: Capability,
    },
    Revoke {
        subject: PolicySubject,
    },
    SetMembersBaseline {
        capability: Option<Capability>,
    },
    Replace {
        entries: Vec<AllowEntry>,
    },
    RestoreInheritance {
        inherited: PolicySnapshot,
    },
}

#[derive(Debug)]
pub enum PolicyTransition {
    NoChange {
        after_mode: PolicyMode,
        after_anchor_id: String,
        after_normalized: Vec<NormalizedPolicyEntry>,
    },
    ReplaceExplicit {
        after_anchor_id: String,
        entries: Vec<AllowEntry>,
        after_normalized: Vec<NormalizedPolicyEntry>,
        boundary_created: bool,
    },
    RestoreInheritance {
        after_anchor_id: String,
        after_normalized: Vec<NormalizedPolicyEntry>,
    },
}

impl PolicyTransition {
    pub fn after_mode(&self) -> PolicyMode {
        match self {
            Self::NoChange { after_mode, .. } => *after_mode,
            Self::ReplaceExplicit { .. } => PolicyMode::Explicit,
            Self::RestoreInheritance { .. } => PolicyMode::Inherit,
        }
    }

    pub fn after_anchor_id(&self) -> &str {
        match self {
            Self::NoChange {
                after_anchor_id, ..
            }
            | Self::ReplaceExplicit {
                after_anchor_id, ..
            }
            | Self::RestoreInheritance {
                after_anchor_id, ..
            } => after_anchor_id,
        }
    }

    pub fn after_normalized(&self) -> &[NormalizedPolicyEntry] {
        match self {
            Self::NoChange {
                after_normalized, ..
            }
            | Self::ReplaceExplicit {
                after_normalized, ..
            }
            | Self::RestoreInheritance {
                after_normalized, ..
            } => after_normalized,
        }
    }

    pub fn changed(&self) -> bool {
        !matches!(self, Self::NoChange { .. })
    }

    pub fn boundary_created(&self) -> bool {
        matches!(
            self,
            Self::ReplaceExplicit {
                boundary_created: true,
                ..
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    Normalize(NormalizeError),
    MembersManageMutation,
    CanonicalRootCannotInherit,
    ExplicitPolicyRequired { record_id: String },
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Normalize(error) => error.fmt(formatter),
            Self::MembersManageMutation => {
                formatter.write_str("the members baseline cannot grant manage")
            }
            Self::CanonicalRootCannotInherit => {
                formatter.write_str("the canonical root policy cannot inherit")
            }
            Self::ExplicitPolicyRequired { record_id } => {
                write!(
                    formatter,
                    "record '{record_id}' does not have an explicit policy"
                )
            }
        }
    }
}

impl std::error::Error for PlanError {}

impl From<NormalizeError> for PlanError {
    fn from(error: NormalizeError) -> Self {
        Self::Normalize(error)
    }
}

pub fn validate_inheritance_restoration(
    record_id: &str,
    is_canonical_root: bool,
    before: &PolicySnapshot,
) -> Result<(), PlanError> {
    planner::validate_inheritance_restoration(record_id, is_canonical_root, before)
}

pub fn plan_policy_transition(
    record_id: &str,
    is_canonical_root: bool,
    before: &PolicySnapshot,
    mutation: PolicyMutation,
) -> Result<PolicyTransition, PlanError> {
    planner::plan_policy_transition(record_id, is_canonical_root, before, mutation)
}
