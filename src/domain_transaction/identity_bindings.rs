//! Shared governed external-binding fold for non-SQLite adapters.
//!
//! Normalization, system policy, authorization, collision concealment and
//! transactional fact collection live here; the identity binding planner owns
//! transition interpretation. Drivers retain only transaction admission, lock
//! acquisition, event/projector execution and the small physical mutations
//! which differ between Postgres and Turso.

use std::collections::HashSet;

use futures::future::BoxFuture;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::authorization::{self, Capability, Principal};
use crate::domain_transaction::AttachmentPhysicalPort;
use crate::identity::binding_plan::{
    self, AddBindingPlan, BindingPlanError, CanonicalizeBindingPlan, ExistingBinding,
    ReconcileBindingFact, ReconcileBindingPlan, RemoveBindingPlan,
};
use crate::identity::{BindingClaim, Resolution, StubHints};
use crate::portable_sql::DomainStatementExecutor;
use crate::schema::UNFILED_RECORD_ID;
use crate::store::AppendSpec;
use crate::{Error, Result};

#[derive(Clone, Debug)]
pub(crate) struct BindingSystemRule {
    pub system: String,
    pub compatible_type: Option<String>,
    pub compatible_kind: Option<String>,
    pub visibility: String,
    pub add_policy: String,
    pub remove_policy: String,
    pub canonicalize_policy: String,
    pub transfer_policy: String,
    pub reconciliation_rule: String,
    pub stub_allowed: bool,
    pub required_durable: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct BindingRow {
    pub record_id: String,
    pub system: String,
    pub identifier: String,
    pub canonical: bool,
    pub url: Option<String>,
    pub etag: Option<String>,
    pub last_seen_at: Option<String>,
}

pub(crate) type BindingRecordShape = (String, Option<String>, bool);

#[derive(Clone, Debug)]
pub(crate) struct BindingAudit<'a> {
    pub action: &'a str,
    pub claim: &'a BindingClaim,
    pub old_record_id: Option<&'a str>,
    pub new_record_id: Option<&'a str>,
    pub old_canonical: Option<bool>,
    pub new_canonical: Option<bool>,
    pub actor: &'a str,
    pub reason: &'a str,
    pub run_key: Option<&'a str>,
    pub parent_key: Option<&'a str>,
    pub intent: Option<&'a str>,
}

pub(crate) trait BindingPhysicalPort:
    DomainStatementExecutor + AttachmentPhysicalPort
{
    fn lock_bindings<'a>(&'a mut self, claims: &'a [BindingClaim]) -> BoxFuture<'a, Result<()>>;
    fn system_rule<'a>(
        &'a mut self,
        system: &'a str,
    ) -> BoxFuture<'a, Result<Option<BindingSystemRule>>>;
    fn binding<'a>(
        &'a mut self,
        system: &'a str,
        identifier: &'a str,
    ) -> BoxFuture<'a, Result<Option<BindingRow>>>;
    fn record_shape<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<BindingRecordShape>>>;
    fn canonical_binding<'a>(
        &'a mut self,
        record_id: &'a str,
        system: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>>>;
    fn binding_count<'a>(
        &'a mut self,
        record_id: &'a str,
        system: &'a str,
    ) -> BoxFuture<'a, Result<i64>>;
    fn account_owner<'a>(&'a mut self, actor: &'a str) -> BoxFuture<'a, Result<Option<String>>>;
    fn public_bindings<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<BindingRow>>>;
    fn set_canonical<'a>(
        &'a mut self,
        record_id: &'a str,
        system: &'a str,
        identifier: &'a str,
        canonical: bool,
    ) -> BoxFuture<'a, Result<()>>;
    fn insert_binding<'a>(
        &'a mut self,
        record_id: &'a str,
        claim: &'a BindingClaim,
        canonical: bool,
    ) -> BoxFuture<'a, Result<()>>;
    fn delete_binding<'a>(
        &'a mut self,
        record_id: &'a str,
        claim: &'a BindingClaim,
    ) -> BoxFuture<'a, Result<()>>;
    fn transfer_binding<'a>(
        &'a mut self,
        source_record_id: &'a str,
        target_record_id: &'a str,
        claim: &'a BindingClaim,
    ) -> BoxFuture<'a, Result<()>>;
    fn append_binding_audit<'a>(&'a mut self, audit: BindingAudit<'a>)
        -> BoxFuture<'a, Result<()>>;
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResolveExternalRequest {
    pub bindings: Vec<BindingClaim>,
    #[serde(default)]
    pub hints: StubHints,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
pub(crate) enum ManageBindingsRequest {
    List {
        record_id: String,
    },
    Observations {
        record_id: String,
        #[serde(default = "default_limit")]
        limit: i64,
    },
    Add {
        record_id: String,
        binding: BindingClaim,
        #[serde(default)]
        canonical: bool,
        reason: String,
        #[serde(default)]
        if_binding_state_revision: Option<String>,
    },
    Remove {
        record_id: String,
        binding: BindingClaim,
        reason: String,
        #[serde(default)]
        if_binding_state_revision: Option<String>,
    },
    Canonicalize {
        record_id: String,
        binding: BindingClaim,
        reason: String,
        #[serde(default)]
        if_binding_state_revision: Option<String>,
    },
    Reconcile {
        target_record_id: String,
        expected_source_record_id: String,
        bindings: Vec<BindingClaim>,
        #[serde(default)]
        apply: bool,
        reason: Option<String>,
        #[serde(default)]
        if_binding_state_revision: Option<String>,
    },
}

impl ManageBindingsRequest {
    pub(crate) fn mutates(&self) -> bool {
        matches!(
            self,
            Self::Add { .. }
                | Self::Remove { .. }
                | Self::Canonicalize { .. }
                | Self::Reconcile { apply: true, .. }
        )
    }
}

pub(crate) struct ManageBindingsOutcome {
    pub response: Value,
    pub changed: bool,
}

fn binding_outcome(response: Value, changed: bool) -> Result<ManageBindingsOutcome> {
    Ok(ManageBindingsOutcome { response, changed })
}

fn default_limit() -> i64 {
    20
}

pub(crate) fn parse_resolve_external(arguments: Value) -> Result<ResolveExternalRequest> {
    serde_json::from_value(arguments)
        .map_err(|error| Error::engine(format!("invalid arguments for resolve_external: {error}")))
}

pub(crate) fn parse_manage_bindings(arguments: Value) -> Result<ManageBindingsRequest> {
    serde_json::from_value(arguments)
        .map_err(|error| Error::engine(format!("invalid arguments for manage_bindings: {error}")))
}

fn require_reason(tool: &str, reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        Err(Error::engine(format!(
            "{tool}: 'reason' must contain non-whitespace reasoning"
        )))
    } else {
        Ok(())
    }
}

fn operation_policy(rule: &BindingSystemRule, policy: &str) -> Result<()> {
    if policy == "internal" {
        return Err(Error::engine(format!(
            "forbidden binding-system operation: '{}' requires an internal writer",
            rule.system
        )));
    }
    if policy == "forbidden" {
        return Err(Error::engine(format!(
            "binding system '{}' forbids this operation",
            rule.system
        )));
    }
    if policy != "record_manage" {
        return Err(Error::engine(format!(
            "binding system '{}' has an unsupported operation policy",
            rule.system
        )));
    }
    Ok(())
}

async fn normalized_rule<P: BindingPhysicalPort>(
    port: &mut P,
    claim: &BindingClaim,
) -> Result<(BindingClaim, BindingSystemRule)> {
    let rule = port
        .system_rule(&claim.system)
        .await?
        .ok_or_else(|| Error::engine(format!("unknown binding system '{}'", claim.system)))?;
    if rule.visibility != "public" {
        return Err(Error::engine(format!(
            "forbidden binding-system operation: '{}' is {}",
            claim.system, rule.visibility
        )));
    }
    Ok((
        BindingClaim {
            system: claim.system.clone(),
            identifier: crate::identity::normalize_identifier(&claim.system, &claim.identifier)?,
        },
        rule,
    ))
}

async fn require_capability<P: BindingPhysicalPort>(
    port: &mut P,
    principal: Principal<'_>,
    record_id: &str,
    capability: Capability,
) -> Result<()> {
    if authorization::allows_record_with(port, principal, record_id, capability).await? {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "record '{record_id}' requires {capability:?}; caller has insufficient authority"
        )))
    }
}

async fn require_visible<P: BindingPhysicalPort>(
    port: &mut P,
    principal: Principal<'_>,
    record_id: &str,
) -> Result<()> {
    if authorization::allows_record_with(port, principal, record_id, Capability::View).await? {
        Ok(())
    } else {
        Err(Error::engine(
            "binding_not_visible: the external identity is not visible to this caller",
        ))
    }
}

async fn require_shape<P: BindingPhysicalPort>(
    port: &mut P,
    record_id: &str,
    rule: &BindingSystemRule,
) -> Result<()> {
    let Some((record_type, kind, deleted)) = port.record_shape(record_id).await? else {
        return Err(Error::engine(format!("record '{record_id}' not found")));
    };
    if deleted
        || rule
            .compatible_type
            .as_deref()
            .is_some_and(|value| value != record_type)
        || rule
            .compatible_kind
            .as_deref()
            .is_some_and(|value| Some(value) != kind.as_deref())
    {
        return Err(Error::engine(format!(
            "incompatible record kind for binding system '{}' on record '{record_id}'",
            rule.system
        )));
    }
    Ok(())
}

async fn audit<P: BindingPhysicalPort>(port: &mut P, entry: BindingAudit<'_>) -> Result<()> {
    port.append_binding_audit(entry).await
}

fn planner_error(error: BindingPlanError) -> Error {
    Error::engine(error.to_string())
}

#[allow(clippy::too_many_arguments)]
async fn apply_canonicalize_plan<P: BindingPhysicalPort>(
    port: &mut P,
    plan: &CanonicalizeBindingPlan,
    actor: &str,
    reason: &str,
    run_key: Option<&str>,
    parent_key: Option<&str>,
    intent: Option<&str>,
) -> Result<()> {
    if !plan.changed {
        return Ok(());
    }
    if let Some(previous) = plan.previous_canonical.as_deref() {
        if previous != plan.claim.identifier.as_str() {
            port.set_canonical(&plan.record_id, &plan.claim.system, previous, false)
                .await?;
            let previous_claim = BindingClaim {
                system: plan.claim.system.clone(),
                identifier: previous.into(),
            };
            audit(
                port,
                BindingAudit {
                    action: "canonicalize",
                    claim: &previous_claim,
                    old_record_id: Some(&plan.record_id),
                    new_record_id: Some(&plan.record_id),
                    old_canonical: Some(true),
                    new_canonical: Some(false),
                    actor,
                    reason,
                    run_key,
                    parent_key,
                    intent,
                },
            )
            .await?;
        }
    }
    port.set_canonical(
        &plan.record_id,
        &plan.claim.system,
        &plan.claim.identifier,
        true,
    )
    .await?;
    audit(
        port,
        BindingAudit {
            action: "canonicalize",
            claim: &plan.claim,
            old_record_id: Some(&plan.record_id),
            new_record_id: Some(&plan.record_id),
            old_canonical: Some(false),
            new_canonical: Some(true),
            actor,
            reason,
            run_key,
            parent_key,
            intent,
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn canonicalize<P: BindingPhysicalPort>(
    port: &mut P,
    record_id: &str,
    claim: &BindingClaim,
    actor: &str,
    reason: &str,
    run_key: Option<&str>,
    parent_key: Option<&str>,
    intent: Option<&str>,
) -> Result<bool> {
    let target_canonical = port
        .binding(&claim.system, &claim.identifier)
        .await?
        .filter(|row| row.record_id == record_id)
        .map(|row| row.canonical);
    if target_canonical.is_none() {
        return binding_plan::plan_canonicalize(record_id, claim.clone(), None, None)
            .map(|plan| plan.changed)
            .map_err(planner_error);
    }
    let previous_canonical = if target_canonical == Some(false) {
        port.canonical_binding(record_id, &claim.system).await?
    } else {
        None
    };
    let plan = binding_plan::plan_canonicalize(
        record_id,
        claim.clone(),
        target_canonical,
        previous_canonical,
    )
    .map_err(planner_error)?;
    apply_canonicalize_plan(port, &plan, actor, reason, run_key, parent_key, intent).await?;
    Ok(plan.changed)
}

#[allow(clippy::too_many_arguments)]
async fn apply_add_plan<P: BindingPhysicalPort>(
    port: &mut P,
    plan: &AddBindingPlan,
    actor: &str,
    reason: &str,
    run_key: Option<&str>,
    parent_key: Option<&str>,
    intent: Option<&str>,
) -> Result<()> {
    if !plan.changed {
        return Ok(());
    }
    if let Some(previous) = plan.previous_canonical.as_deref() {
        if previous != plan.claim.identifier.as_str() {
            port.set_canonical(&plan.record_id, &plan.claim.system, previous, false)
                .await?;
            let previous_claim = BindingClaim {
                system: plan.claim.system.clone(),
                identifier: previous.into(),
            };
            audit(
                port,
                BindingAudit {
                    action: "canonicalize",
                    claim: &previous_claim,
                    old_record_id: Some(&plan.record_id),
                    new_record_id: Some(&plan.record_id),
                    old_canonical: Some(true),
                    new_canonical: Some(false),
                    actor,
                    reason,
                    run_key,
                    parent_key,
                    intent,
                },
            )
            .await?;
        }
    }
    if plan.present {
        port.set_canonical(
            &plan.record_id,
            &plan.claim.system,
            &plan.claim.identifier,
            true,
        )
        .await?;
        audit(
            port,
            BindingAudit {
                action: "canonicalize",
                claim: &plan.claim,
                old_record_id: Some(&plan.record_id),
                new_record_id: Some(&plan.record_id),
                old_canonical: Some(false),
                new_canonical: Some(true),
                actor,
                reason,
                run_key,
                parent_key,
                intent,
            },
        )
        .await?;
    } else {
        port.insert_binding(&plan.record_id, &plan.claim, plan.requested_canonical)
            .await?;
        audit(
            port,
            BindingAudit {
                action: "add",
                claim: &plan.claim,
                old_record_id: None,
                new_record_id: Some(&plan.record_id),
                old_canonical: None,
                new_canonical: Some(plan.requested_canonical),
                actor,
                reason,
                run_key,
                parent_key,
                intent,
            },
        )
        .await?;
    }
    Ok(())
}

async fn apply_remove_plan<P: BindingPhysicalPort>(
    port: &mut P,
    plan: &RemoveBindingPlan,
    actor: &str,
    reason: &str,
    run_key: Option<&str>,
    parent_key: Option<&str>,
    intent: Option<&str>,
) -> Result<()> {
    if !plan.changed {
        return Ok(());
    }
    port.delete_binding(&plan.record_id, &plan.claim).await?;
    audit(
        port,
        BindingAudit {
            action: "remove",
            claim: &plan.claim,
            old_record_id: Some(&plan.record_id),
            new_record_id: None,
            old_canonical: plan.was_canonical,
            new_canonical: None,
            actor,
            reason,
            run_key,
            parent_key,
            intent,
        },
    )
    .await
}

async fn apply_reconcile_plan<P: BindingPhysicalPort>(
    port: &mut P,
    plan: &ReconcileBindingPlan,
    actor: &str,
    reason: &str,
    run_key: Option<&str>,
    parent_key: Option<&str>,
    intent: Option<&str>,
) -> Result<()> {
    for binding in &plan.bindings {
        port.transfer_binding(
            &plan.source_record_id,
            &plan.target_record_id,
            &binding.claim,
        )
        .await?;
        audit(
            port,
            BindingAudit {
                action: "transfer",
                claim: &binding.claim,
                old_record_id: Some(&plan.source_record_id),
                new_record_id: Some(&plan.target_record_id),
                old_canonical: Some(binding.canonical),
                new_canonical: Some(binding.canonical),
                actor,
                reason,
                run_key,
                parent_key,
                intent,
            },
        )
        .await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn add_binding<P: BindingPhysicalPort>(
    port: &mut P,
    principal: Principal<'_>,
    record_id: &str,
    claim: &BindingClaim,
    canonical: bool,
    actor: &str,
    reason: &str,
    run_key: Option<&str>,
    parent_key: Option<&str>,
    intent: Option<&str>,
) -> Result<bool> {
    let existing = port
        .binding(&claim.system, &claim.identifier)
        .await?
        .map(|row| ExistingBinding {
            record_id: row.record_id,
            canonical: row.canonical,
        });
    if let Some(existing) = existing
        .as_ref()
        .filter(|existing| existing.record_id != record_id)
    {
        require_visible(port, principal, &existing.record_id).await?;
    }
    binding_plan::validate_add_owner(record_id, existing.as_ref()).map_err(planner_error)?;
    let was_canonical = existing.as_ref().is_some_and(|binding| binding.canonical);
    let previous_canonical = if canonical && !was_canonical {
        port.canonical_binding(record_id, &claim.system).await?
    } else {
        None
    };
    let plan = binding_plan::plan_add(
        record_id,
        claim.clone(),
        canonical,
        existing,
        previous_canonical,
    )
    .map_err(planner_error)?;
    apply_add_plan(port, &plan, actor, reason, run_key, parent_key, intent).await?;
    Ok(plan.changed)
}

pub(crate) async fn resolve_external<P: BindingPhysicalPort>(
    port: &mut P,
    principal: Principal<'_>,
    actor: &str,
    run_key: Option<&str>,
    parent_key: Option<&str>,
    intent: Option<&str>,
    request: ResolveExternalRequest,
) -> Result<Resolution> {
    require_reason("resolve_external", &request.reason)?;
    if request.bindings.is_empty() {
        return Err(Error::engine(
            "resolve_external requires at least one binding claim",
        ));
    }
    let mut resolved = Vec::with_capacity(request.bindings.len());
    for claim in &request.bindings {
        resolved.push(normalized_rule(port, claim).await?);
    }
    let normalized = resolved
        .iter()
        .map(|(claim, _)| claim.clone())
        .collect::<Vec<_>>();
    port.lock_bindings(&normalized).await?;
    let mut owners = Vec::new();
    let mut states = Vec::with_capacity(resolved.len());
    for (claim, rule) in resolved {
        let owner = port
            .binding(&claim.system, &claim.identifier)
            .await?
            .map(|row| row.record_id);
        if let Some(owner) = owner.as_ref() {
            if !owners.contains(owner) {
                owners.push(owner.clone());
            }
        }
        states.push((claim, rule, owner));
    }
    for owner in &owners {
        require_visible(port, principal, owner).await?;
    }
    if owners.len() > 1 {
        return Err(Error::engine(
            "reconciliation conflict: supplied bindings resolve to different visible records",
        ));
    }
    let missing = states.iter().any(|(_, _, owner)| owner.is_none());
    let (record_id, created) = if let Some(owner) = owners.first() {
        (owner.clone(), false)
    } else {
        let rule = &states[0].1;
        if !rule.stub_allowed {
            return Err(Error::engine(format!(
                "binding system '{}' cannot create an identity-only stub",
                rule.system
            )));
        }
        require_capability(port, principal, UNFILED_RECORD_ID, Capability::Edit).await?;
        let record_type = rule
            .compatible_type
            .clone()
            .or(request.hints.record_type.clone())
            .ok_or_else(|| {
                Error::engine("record_type hint is required to resolve this native-record miss")
            })?;
        let kind = rule
            .compatible_kind
            .clone()
            .or(request.hints.kind.clone())
            .ok_or_else(|| {
                Error::engine("kind hint is required to resolve this native-record miss")
            })?;
        let record_id = Uuid::new_v4().to_string();
        let owner_id = port.account_owner(actor).await?;
        AttachmentPhysicalPort::append_content(port, AppendSpec {
            record_id: record_id.clone(),
            event_type: "record.created".into(),
            payload: json!({
                "type":record_type,
                "kind":kind,
                "name":request.hints.name.clone().unwrap_or_else(|| format!("External {}", &record_id[..8])),
                "home_id":UNFILED_RECORD_ID,
                "owner_id":owner_id,
                "persistence":"enduring"
            }),
            actor: Some(actor.into()),
        }).await?;
        (record_id, true)
    };
    if missing {
        require_capability(port, principal, &record_id, Capability::Manage).await?;
    }
    let mut added = Vec::new();
    for (claim, rule, owner) in states {
        require_shape(port, &record_id, &rule).await?;
        if owner.is_some() {
            continue;
        }
        operation_policy(&rule, &rule.add_policy)?;
        if add_binding(
            port,
            principal,
            &record_id,
            &claim,
            true,
            actor,
            &request.reason,
            run_key,
            parent_key,
            intent,
        )
        .await?
        {
            added.push(claim);
        }
    }
    Ok(Resolution {
        record_id,
        created,
        bindings_added: added,
    })
}

fn reject_revision(revision: &Option<String>) -> Result<()> {
    if revision.is_some() {
        Err(Error::engine(
            "manage_bindings: if_binding_state_revision is not yet qualified on this backend",
        ))
    } else {
        Ok(())
    }
}

pub(crate) async fn manage_bindings<P: BindingPhysicalPort>(
    port: &mut P,
    principal: Principal<'_>,
    actor: &str,
    run_key: Option<&str>,
    parent_key: Option<&str>,
    intent: Option<&str>,
    request: ManageBindingsRequest,
) -> Result<ManageBindingsOutcome> {
    match request {
        ManageBindingsRequest::List { record_id } => {
            require_capability(port, principal, &record_id, Capability::View).await?;
            let bindings = port.public_bindings(&record_id).await?.into_iter().map(|row| json!({
                "system":row.system,"identifier":row.identifier,"is_canonical":row.canonical,
                "url":row.url,"etag":row.etag,"last_seen_at":row.last_seen_at,
            })).collect::<Vec<_>>();
            binding_outcome(
                json!({"status":"listed","record_id":record_id,"bindings":bindings}),
                false,
            )
        }
        ManageBindingsRequest::Observations { record_id, limit } => {
            let _unsupported_but_validated_shape = (record_id, limit);
            Err(Error::engine(
                "manage_bindings operation 'observations' is unsupported by the qualified domain boundary",
            ))
        }
        ManageBindingsRequest::Add {
            record_id,
            binding,
            canonical,
            reason,
            if_binding_state_revision,
        } => {
            require_reason("manage_bindings", &reason)?;
            reject_revision(&if_binding_state_revision)?;
            require_capability(port, principal, &record_id, Capability::Manage).await?;
            let (binding, rule) = normalized_rule(port, &binding).await?;
            operation_policy(&rule, &rule.add_policy)?;
            require_shape(port, &record_id, &rule).await?;
            port.lock_bindings(std::slice::from_ref(&binding)).await?;
            let changed = add_binding(
                port, principal, &record_id, &binding, canonical, actor, &reason, run_key,
                parent_key, intent,
            )
            .await?;
            binding_outcome(
                json!({"status":if changed{"added"}else{"unchanged"},"record_id":record_id,"changed":changed}),
                changed,
            )
        }
        ManageBindingsRequest::Remove {
            record_id,
            binding,
            reason,
            if_binding_state_revision,
        } => {
            require_reason("manage_bindings", &reason)?;
            reject_revision(&if_binding_state_revision)?;
            require_capability(port, principal, &record_id, Capability::Manage).await?;
            let (binding, rule) = normalized_rule(port, &binding).await?;
            operation_policy(&rule, &rule.remove_policy)?;
            port.lock_bindings(std::slice::from_ref(&binding)).await?;
            let target_canonical = port
                .binding(&binding.system, &binding.identifier)
                .await?
                .filter(|row| row.record_id == record_id)
                .map(|row| row.canonical);
            let system_binding_count = if target_canonical.is_some() && rule.required_durable {
                port.binding_count(&record_id, &binding.system).await?
            } else {
                0
            };
            let plan = binding_plan::plan_remove(
                &record_id,
                binding,
                target_canonical,
                rule.required_durable,
                system_binding_count,
            )
            .map_err(planner_error)?;
            apply_remove_plan(port, &plan, actor, &reason, run_key, parent_key, intent).await?;
            binding_outcome(
                json!({"status":if plan.changed{"removed"}else{"unchanged"},"record_id":record_id,"changed":plan.changed}),
                plan.changed,
            )
        }
        ManageBindingsRequest::Canonicalize {
            record_id,
            binding,
            reason,
            if_binding_state_revision,
        } => {
            require_reason("manage_bindings", &reason)?;
            reject_revision(&if_binding_state_revision)?;
            require_capability(port, principal, &record_id, Capability::Manage).await?;
            let (binding, rule) = normalized_rule(port, &binding).await?;
            operation_policy(&rule, &rule.canonicalize_policy)?;
            port.lock_bindings(std::slice::from_ref(&binding)).await?;
            let changed = canonicalize(
                port, &record_id, &binding, actor, &reason, run_key, parent_key, intent,
            )
            .await?;
            binding_outcome(
                json!({"status":if changed{"canonicalized"}else{"unchanged"},"record_id":record_id,"changed":changed}),
                changed,
            )
        }
        ManageBindingsRequest::Reconcile {
            target_record_id,
            expected_source_record_id,
            bindings,
            apply,
            reason,
            if_binding_state_revision,
        } => {
            if bindings.is_empty() {
                return Err(Error::engine(
                    "reconcile requires at least one selected binding",
                ));
            }
            if target_record_id == expected_source_record_id {
                return Err(Error::engine(
                    "reconcile target and expected source records must be different",
                ));
            }
            let reason = reason.unwrap_or_default();
            if apply {
                require_reason("manage_bindings", &reason)?;
                reject_revision(&if_binding_state_revision)?;
            }
            require_capability(port, principal, &target_record_id, Capability::Manage).await?;
            require_capability(
                port,
                principal,
                &expected_source_record_id,
                Capability::Manage,
            )
            .await?;
            let mut selected = Vec::with_capacity(bindings.len());
            let mut seen = HashSet::new();
            for binding in bindings {
                let (binding, rule) = normalized_rule(port, &binding).await?;
                operation_policy(&rule, &rule.transfer_policy)?;
                if rule.reconciliation_rule != "binding_only" {
                    return Err(Error::engine(format!(
                        "binding system '{}' does not permit binding-only reconciliation",
                        rule.system
                    )));
                }
                if !seen.insert((binding.system.clone(), binding.identifier.clone())) {
                    return Err(Error::engine(format!(
                        "reconcile selected duplicate binding {}:{}",
                        binding.system, binding.identifier
                    )));
                }
                require_shape(port, &target_record_id, &rule).await?;
                selected.push(ReconcileBindingFact {
                    claim: binding,
                    owner_record_id: None,
                    canonical: false,
                    target_canonical_identifier: None,
                    transfer_policy: rule.transfer_policy,
                    reconciliation_rule: rule.reconciliation_rule,
                });
            }
            let normalized = selected
                .iter()
                .map(|binding| binding.claim.clone())
                .collect::<Vec<_>>();
            port.lock_bindings(&normalized).await?;
            for binding in &mut selected {
                let owner = port
                    .binding(&binding.claim.system, &binding.claim.identifier)
                    .await?;
                if let Some(owner) = owner
                    .as_ref()
                    .filter(|owner| owner.record_id != expected_source_record_id)
                {
                    require_visible(port, principal, &owner.record_id).await?;
                }
                binding.owner_record_id = owner.map(|row| row.record_id);
                binding_plan::validate_reconcile_owners(
                    &expected_source_record_id,
                    std::slice::from_ref(binding),
                )
                .map_err(planner_error)?;
            }
            if apply {
                for binding in &selected {
                    let row = port
                        .binding(&binding.claim.system, &binding.claim.identifier)
                        .await?
                        .expect("owner checked");
                    let mut binding = binding.clone();
                    binding.canonical = row.canonical;
                    if binding.canonical {
                        binding.target_canonical_identifier = port
                            .canonical_binding(&target_record_id, &binding.claim.system)
                            .await?;
                    }
                    let plan = binding_plan::plan_reconcile(
                        &target_record_id,
                        &expected_source_record_id,
                        vec![binding],
                    )
                    .map_err(planner_error)?;
                    apply_reconcile_plan(port, &plan, actor, &reason, run_key, parent_key, intent)
                        .await?;
                }
            }
            binding_outcome(
                json!({"status":if apply{"reconciled"}else{"preview"},"record_id":target_record_id,"from_record_id":expected_source_record_id,"to_record_id":target_record_id,"bindings":normalized,"changed":apply}),
                apply,
            )
        }
    }
}
