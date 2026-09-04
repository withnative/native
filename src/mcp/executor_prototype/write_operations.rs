//! Consequential-write routes for the test-only executor facade.
//!
//! A raw call to a supported high-risk operation is preparation only. Mutation
//! is reachable exclusively with the opaque plan id and the visible
//! target/effect fields returned by preparation. Plans and their execution
//! fences are persisted in a versioned SQLite sidecar before dispatch.

use std::sync::Arc;

use chrono::{SecondsFormat, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{Error, Result};

use super::*;

const ACCESS_EXECUTOR: &str = "access_admin";
const POLICY_GRANT_OPERATION: &str = "manage_record_policy.grant";
const POLICY_REPLACE_OPERATION: &str = "manage_record_policy.replace";
const POLICY_RESTORE_OPERATION: &str = "manage_record_policy.restore_inheritance";
const POLICY_REVOKE_OPERATION: &str = "manage_record_policy.revoke";
const POLICY_BASELINE_OPERATION: &str = "manage_record_policy.set_members_baseline";
const POLICY_SET_MANY_OPERATION: &str = "manage_record_policy.set_many";
const ARTIFACT_GRANT_OPERATION: &str = "manage_artifact_module_grants.grant";
const ARTIFACT_REVOKE_OPERATION: &str = "manage_artifact_module_grants.revoke";
const MEMBERSHIP_EXECUTOR: &str = "membership_admin";
const MEMBERSHIP_REMOVE_EXECUTOR: &str = "membership_remove";
const CANVAS_WRITE_EXECUTOR: &str = "canvas_write";
const CANVAS_PROMOTE_OPERATION: &str = "manage_canvas.promote";
const MEMBERSHIP_SET_ROLE_OPERATION: &str = "manage_memberships.set_role";
const MEMBERSHIP_REMOVE_OPERATION: &str = "manage_memberships.remove";
const MEMBERSHIP_CREATE_INVITATION_OPERATION: &str = "manage_memberships.invitations_create";
const MEMBERSHIP_COPY_INVITATION_LINK_OPERATION: &str = "manage_memberships.invitations_copy_link";
const MEMBERSHIP_SEND_INVITATION_OPERATION: &str = "manage_memberships.invitations_send";
const MEMBERSHIP_REVOKE_INVITATION_OPERATION: &str = "manage_memberships.invitations_revoke";
const IDENTITY_EXECUTOR: &str = "identity_admin";
const IDENTITY_ADD_OPERATION: &str = "manage_bindings.add";
const IDENTITY_CANONICALIZE_OPERATION: &str = "manage_bindings.canonicalize";
const IDENTITY_RECONCILE_OPERATION: &str = "manage_bindings.reconcile";
const IDENTITY_REMOVE_OPERATION: &str = "manage_bindings.remove";
const RECORDS_DELETE_EXECUTOR: &str = "records_delete";
const RECORDS_WRITE_EXECUTOR: &str = "records_write";
const CORRECT_RECORD_TYPE_OPERATION: &str = "correct_record_type";
const DELETE_RECORD_OPERATION: &str = "delete_record";
const DETACH_ATTACHMENT_OPERATION: &str = "manage_attachments.detach";
const REMOVE_CITATION_OPERATION: &str = "manage_citations.remove";
const SCHEMA_ADMIN_EXECUTOR: &str = "schema_admin";
const SCHEMA_DELETE_EXECUTOR: &str = "schema_delete";
const VOCABULARY_ALIAS_OPERATION: &str = "manage_vocabularies.alias_value";
const VOCABULARY_CREATE_OPERATION: &str = "manage_vocabularies.create_vocabulary";
const VOCABULARY_DELETE_VALUE_OPERATION: &str = "manage_vocabularies.delete_value";
const VOCABULARY_DELETE_OPERATION: &str = "manage_vocabularies.delete_vocabulary";
const VOCABULARY_DEPRECATE_OPERATION: &str = "manage_vocabularies.deprecate_value";
const VOCABULARY_PROMOTE_OPERATION: &str = "manage_vocabularies.promote_value";
const VOCABULARY_PROPOSE_OPERATION: &str = "manage_vocabularies.propose_value";
const VOCABULARY_REORDER_OPERATION: &str = "manage_vocabularies.reorder_value";
const VOCABULARY_SET_GLOSS_OPERATION: &str = "manage_vocabularies.set_gloss";
const VOCABULARY_METADATA_OPERATION: &str = "manage_vocabularies.set_metadata";
const SCHEMA_CONFIG_WRITE_OPERATION: &str = "manage_schema_config.write";
const DEFAULT_TTL_MS: i64 = 120_000;
use super::plan_store::{ClaimOutcome, PlanStore, StoredPlan, StoredState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PlanPolicy {
    Direct,
    RequiredSupported,
    RequiredUnavailable,
}

/// The ratified first dogfood boundary, as one table.
///
/// Classification is deliberately exact: a tool being complicated,
/// write-shaped, or merely labelled administrative is not enough to require a
/// plan. Every plan-requiring executor/operation pair appears here exactly
/// once, with the policy that pair carries; anything absent is
/// [`PlanPolicy::Direct`]. `RequiredUnavailable` rows are classified but have
/// no truthful non-mutating preparer yet, so they are withheld rather than
/// advertised.
///
/// The table is the single source: `plan_policy`, and through it
/// `requires_plan`, `supports`, and `advertisable`, derive from nothing else.
/// Duplicate and conflicting rows are rejected by
/// `plan_policy_table_rows_are_unique_and_disjoint`, and the whole mapping is
/// frozen by `plan_policy_table_is_frozen`.
pub(super) const PLAN_POLICY_TABLE: &[(&str, &str, PlanPolicy)] = &[
    (
        ACCESS_EXECUTOR,
        POLICY_GRANT_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        ACCESS_EXECUTOR,
        POLICY_REPLACE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        ACCESS_EXECUTOR,
        POLICY_RESTORE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        ACCESS_EXECUTOR,
        POLICY_REVOKE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        ACCESS_EXECUTOR,
        POLICY_BASELINE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        ACCESS_EXECUTOR,
        POLICY_SET_MANY_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        ACCESS_EXECUTOR,
        ARTIFACT_GRANT_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        ACCESS_EXECUTOR,
        ARTIFACT_REVOKE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        IDENTITY_EXECUTOR,
        IDENTITY_ADD_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        IDENTITY_EXECUTOR,
        IDENTITY_CANONICALIZE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        IDENTITY_EXECUTOR,
        IDENTITY_RECONCILE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        IDENTITY_EXECUTOR,
        IDENTITY_REMOVE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        RECORDS_WRITE_EXECUTOR,
        CORRECT_RECORD_TYPE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        RECORDS_DELETE_EXECUTOR,
        DELETE_RECORD_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        RECORDS_DELETE_EXECUTOR,
        DETACH_ATTACHMENT_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        RECORDS_DELETE_EXECUTOR,
        REMOVE_CITATION_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_ADMIN_EXECUTOR,
        VOCABULARY_ALIAS_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_ADMIN_EXECUTOR,
        VOCABULARY_CREATE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_ADMIN_EXECUTOR,
        VOCABULARY_DEPRECATE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_ADMIN_EXECUTOR,
        VOCABULARY_PROMOTE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_ADMIN_EXECUTOR,
        VOCABULARY_PROPOSE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_ADMIN_EXECUTOR,
        VOCABULARY_REORDER_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_ADMIN_EXECUTOR,
        VOCABULARY_SET_GLOSS_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_ADMIN_EXECUTOR,
        VOCABULARY_METADATA_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_ADMIN_EXECUTOR,
        SCHEMA_CONFIG_WRITE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_DELETE_EXECUTOR,
        VOCABULARY_DELETE_VALUE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        SCHEMA_DELETE_EXECUTOR,
        VOCABULARY_DELETE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        MEMBERSHIP_EXECUTOR,
        MEMBERSHIP_CREATE_INVITATION_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        MEMBERSHIP_EXECUTOR,
        MEMBERSHIP_COPY_INVITATION_LINK_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        MEMBERSHIP_EXECUTOR,
        MEMBERSHIP_SEND_INVITATION_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        MEMBERSHIP_EXECUTOR,
        MEMBERSHIP_REVOKE_INVITATION_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    // Classified, but withheld: the hosted atomic membership writes have no
    // truthful non-mutating preparer in this facade.
    (
        MEMBERSHIP_EXECUTOR,
        MEMBERSHIP_SET_ROLE_OPERATION,
        PlanPolicy::RequiredUnavailable,
    ),
    (
        MEMBERSHIP_REMOVE_EXECUTOR,
        MEMBERSHIP_REMOVE_OPERATION,
        PlanPolicy::RequiredUnavailable,
    ),
    // Promotion mints records and writes provenance from a canvas sketch, so
    // the preview must bind the execution. Its preparer is the promotion dry
    // run itself, which rolls back before returning, so preparation provably
    // does not mutate.
    (
        CANVAS_WRITE_EXECUTOR,
        CANVAS_PROMOTE_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
];

/// Exact lookup in [`PLAN_POLICY_TABLE`]; unclassified pairs are
/// [`PlanPolicy::Direct`].
pub(super) fn plan_policy(executor: &str, operation: &str) -> PlanPolicy {
    PLAN_POLICY_TABLE
        .iter()
        .find(|(table_executor, table_operation, _)| {
            *table_executor == executor && *table_operation == operation
        })
        .map(|(_, _, policy)| *policy)
        .unwrap_or(PlanPolicy::Direct)
}

pub(super) fn requires_plan(executor: &str, operation: &str) -> bool {
    plan_policy(executor, operation) != PlanPolicy::Direct
}

/// True only when a classified operation has a truthful, non-mutating
/// production-adjacent preparer. Catalogue construction must withhold the
/// other classified rows until their source modules expose equivalent seams.
pub(super) fn supports(executor: &str, operation: &str) -> bool {
    plan_policy(executor, operation) == PlanPolicy::RequiredSupported
}

pub(super) fn is_membership_operation(executor: &str, operation: &str) -> bool {
    matches!(
        (executor, operation),
        (MEMBERSHIP_EXECUTOR, MEMBERSHIP_SET_ROLE_OPERATION)
            | (MEMBERSHIP_REMOVE_EXECUTOR, MEMBERSHIP_REMOVE_OPERATION)
            | (MEMBERSHIP_EXECUTOR, MEMBERSHIP_CREATE_INVITATION_OPERATION)
            | (
                MEMBERSHIP_EXECUTOR,
                MEMBERSHIP_COPY_INVITATION_LINK_OPERATION
            )
            | (MEMBERSHIP_EXECUTOR, MEMBERSHIP_SEND_INVITATION_OPERATION)
            | (MEMBERSHIP_EXECUTOR, MEMBERSHIP_REVOKE_INVITATION_OPERATION)
    )
}

fn is_hosted_atomic_membership_operation(executor: &str, operation: &str) -> bool {
    matches!(
        (executor, operation),
        (MEMBERSHIP_EXECUTOR, MEMBERSHIP_SET_ROLE_OPERATION)
            | (MEMBERSHIP_REMOVE_EXECUTOR, MEMBERSHIP_REMOVE_OPERATION)
    )
}

pub(super) fn advertisable(executor: &str, operation: &str) -> bool {
    plan_policy(executor, operation) != PlanPolicy::RequiredUnavailable
}

pub(super) fn validate(
    executor: &str,
    operation: &str,
    arguments: Value,
    hosted_authority: Option<&dyn HostedExecutorAuthority>,
) -> Result<()> {
    if !supports(executor, operation) && !is_membership_operation(executor, operation) {
        return Err(Error::engine(format!(
            "{executor}.{operation} has no write prototype implementation"
        )));
    }
    if (executor, operation) == (SCHEMA_ADMIN_EXECUTOR, SCHEMA_CONFIG_WRITE_OPERATION) {
        return super::super::tools::meta::validate_schema_config_mutation(arguments);
    }
    if matches!(executor, SCHEMA_ADMIN_EXECUTOR | SCHEMA_DELETE_EXECUTOR) {
        return super::super::tools::meta::validate_vocabulary_mutation(
            vocabulary_action(executor, operation)?,
            arguments,
        );
    }
    let source = canonical_source_arguments(executor, operation, arguments)?;
    match (executor, operation) {
        (ACCESS_EXECUTOR, operation) if policy_action(operation).is_ok() => {
            super::super::tools::policy::validate_record_policy_mutation(
                policy_action(operation)?,
                source,
            )
        }
        (ACCESS_EXECUTOR, operation) if artifact_grant_action(operation).is_ok() => {
            super::super::tools::artifacts::validate_artifact_module_grant_mutation(
                artifact_grant_action(operation)?,
                source,
            )
        }
        (IDENTITY_EXECUTOR, operation) => super::super::tools::identity::validate_binding_mutation(
            identity_action(operation)?,
            source,
        ),
        (RECORDS_WRITE_EXECUTOR, CORRECT_RECORD_TYPE_OPERATION) => Ok(()),
        (RECORDS_DELETE_EXECUTOR, DELETE_RECORD_OPERATION)
        | (RECORDS_DELETE_EXECUTOR, DETACH_ATTACHMENT_OPERATION)
        | (RECORDS_DELETE_EXECUTOR, REMOVE_CITATION_OPERATION) => Ok(()),
        // Promotion's shape is validated by the handler's own argument
        // parsing during preparation, which is the dry run.
        (CANVAS_WRITE_EXECUTOR, CANVAS_PROMOTE_OPERATION) => Ok(()),
        (executor, operation) if is_membership_operation(executor, operation) => hosted_authority
            .ok_or_else(|| {
                Error::engine("hosted membership plans require an authoritative catalogue context")
            })?
            .validate_membership_write(source),
        _ => Err(Error::engine(format!(
            "{executor}.{operation} has no exact write preparation route"
        ))),
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
struct CallerBinding {
    actor: String,
    principal: String,
    workspace: String,
    database: String,
}

#[derive(Clone, Debug)]
pub(super) struct PreparedWrite {
    pub revalidation_arguments: Value,
    pub canonical_source_arguments: Value,
    pub target_id: String,
    pub target: String,
    pub state_revision: String,
    pub target_state_digest: String,
    pub effect: Value,
    pub effect_summary: String,
    pub operation_evidence: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WritePlan {
    id: String,
    binding: CallerBinding,
    executor: String,
    operation: String,
    source_tool: String,
    operation_arguments: Value,
    arguments_digest: String,
    revalidation_arguments: Value,
    revalidation_arguments_digest: String,
    canonical_source_arguments: Value,
    source_arguments_digest: String,
    target_id: String,
    target: String,
    target_state_digest: String,
    state_revision: String,
    effect: Value,
    effect_summary: String,
    operation_evidence: Value,
    effect_digest: String,
    contract_digest: String,
    catalogue_digest: String,
    server_version: String,
    expires_at_ms: i64,
    nonce: String,
    signing_key_id: String,
    integrity: String,
}

pub(super) struct WriteRuntime {
    store: Arc<PlanStore>,
    ttl_ms: i64,
    #[cfg(test)]
    dispatch_gate: Option<Arc<DispatchGate>>,
    #[cfg(test)]
    revalidation_gate: Option<Arc<DispatchGate>>,
}

#[cfg(test)]
struct DispatchGate {
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
impl DispatchGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Arc::new(tokio::sync::Semaphore::new(0)),
            release: Arc::new(tokio::sync::Semaphore::new(0)),
        })
    }
}

impl WriteRuntime {
    pub(super) fn new(store: PlanStore) -> Self {
        Self {
            store: Arc::new(store),
            ttl_ms: DEFAULT_TTL_MS,
            #[cfg(test)]
            dispatch_gate: None,
            #[cfg(test)]
            revalidation_gate: None,
        }
    }

    #[cfg(test)]
    fn with_ttl_ms(store: Arc<PlanStore>, ttl_ms: i64) -> Self {
        Self {
            store,
            ttl_ms,
            dispatch_gate: None,
            revalidation_gate: None,
        }
    }

    async fn verify(&self, plan: &WritePlan) -> Result<()> {
        if digest(&plan.operation_arguments)? != plan.arguments_digest {
            return Err(Error::engine(
                "write plan operation arguments digest mismatch",
            ));
        }
        if digest(&plan.revalidation_arguments)? != plan.revalidation_arguments_digest {
            return Err(Error::engine(
                "write plan revalidation arguments digest mismatch",
            ));
        }
        if digest(&plan.canonical_source_arguments)? != plan.source_arguments_digest {
            return Err(Error::engine(
                "write plan canonical source arguments digest mismatch",
            ));
        }
        if digest(&plan.effect)? != plan.effect_digest {
            return Err(Error::engine("write plan effect digest mismatch"));
        }
        self.store
            .verify(
                &plan.signing_key_id,
                &integrity_payload(plan),
                &plan.integrity,
            )
            .await
    }
}

fn now_ms() -> i64 {
    Utc::now().timestamp_millis()
}

fn server_version() -> String {
    crate::engine_version_string()
}

fn rfc3339_millis(timestamp_ms: i64) -> String {
    Utc.timestamp_millis_opt(timestamp_ms)
        .single()
        .expect("prototype plan timestamp is representable")
        .to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn digest(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(value)?)))
}

async fn engine_binding(engine: &EngineHandle, caller: &Caller) -> Result<CallerBinding> {
    let principal = caller.hosting_principal().unwrap_or(caller.credential());
    let workspace = caller
        .hosting_database()
        .unwrap_or(crate::schema::ROOT_RECORD_ID);
    let database = match engine {
        EngineHandle::Sqlite(db) => format!("sqlite:{}", crate::identity::database_id(db).await?),
        #[cfg(feature = "postgres")]
        EngineHandle::Postgres(_) => format!("postgres:{workspace}"),
        #[cfg(feature = "turso-local")]
        EngineHandle::TursoLocal(_) => format!("turso-local:{workspace}"),
    };
    Ok(CallerBinding {
        actor: caller.actor().into(),
        principal: principal.into(),
        workspace: workspace.into(),
        database,
    })
}

fn integrity_payload(plan: &WritePlan) -> Value {
    json!({
        "version":"native.write-plan.v1",
        "plan_id":plan.id,
        "actor":plan.binding.actor,
        "principal":plan.binding.principal,
        "workspace":plan.binding.workspace,
        "database":plan.binding.database,
        "executor":plan.executor,
        "operation":plan.operation,
        "source_tool":plan.source_tool,
        "arguments_digest":plan.arguments_digest,
        "revalidation_arguments_digest":plan.revalidation_arguments_digest,
        "source_arguments_digest":plan.source_arguments_digest,
        "target_id":plan.target_id,
        "target":plan.target,
        "target_state_digest":plan.target_state_digest,
        "state_revision":plan.state_revision,
        "effect_summary":plan.effect_summary,
        "effect_digest":plan.effect_digest,
        "operation_evidence":plan.operation_evidence,
        "contract_digest":plan.contract_digest,
        "catalogue_digest":plan.catalogue_digest,
        "server_version":plan.server_version,
        "expires_at_ms":plan.expires_at_ms,
        "nonce":plan.nonce,
        "signing_key_id":plan.signing_key_id,
    })
}

fn canonical_source_arguments(executor: &str, operation: &str, arguments: Value) -> Result<Value> {
    let mut object = arguments.as_object().cloned().ok_or_else(|| {
        Error::engine(format!(
            "{executor}.{operation} arguments must be an object"
        ))
    })?;
    if executor == RECORDS_DELETE_EXECUTOR && object.contains_key("if_content_seq") {
        return Err(Error::engine(
            "content revision is source-owned and cannot be supplied by the caller",
        ));
    }
    if (executor, operation) == (RECORDS_WRITE_EXECUTOR, CORRECT_RECORD_TYPE_OPERATION)
        && [
            "if_content_seq",
            "if_schema_state_revision",
            "if_dependency_digest",
            "mode",
            "confirmation_required",
            "plan_id",
            "effect_digest",
        ]
        .iter()
        .any(|field| object.contains_key(*field))
    {
        return Err(Error::engine(
            "record type correction plan evidence is executor-owned and cannot be supplied by the caller",
        ));
    }
    let action = match (executor, operation) {
        (ACCESS_EXECUTOR, operation) if policy_action(operation).is_ok() => {
            Some(policy_action(operation)?)
        }
        (ACCESS_EXECUTOR, operation) if artifact_grant_action(operation).is_ok() => {
            Some(artifact_grant_action(operation)?)
        }
        (IDENTITY_EXECUTOR, operation) => Some(identity_action(operation)?),
        (RECORDS_WRITE_EXECUTOR, CORRECT_RECORD_TYPE_OPERATION) => None,
        (RECORDS_DELETE_EXECUTOR, DELETE_RECORD_OPERATION) => None,
        (RECORDS_DELETE_EXECUTOR, DETACH_ATTACHMENT_OPERATION) => Some("detach"),
        (RECORDS_DELETE_EXECUTOR, REMOVE_CITATION_OPERATION) => Some("remove"),
        (MEMBERSHIP_EXECUTOR, MEMBERSHIP_SET_ROLE_OPERATION) => Some("set_role"),
        (MEMBERSHIP_REMOVE_EXECUTOR, MEMBERSHIP_REMOVE_OPERATION) => Some("remove"),
        (MEMBERSHIP_EXECUTOR, MEMBERSHIP_CREATE_INVITATION_OPERATION) => Some("invitations_create"),
        (MEMBERSHIP_EXECUTOR, MEMBERSHIP_COPY_INVITATION_LINK_OPERATION) => {
            Some("invitations_copy_link")
        }
        (MEMBERSHIP_EXECUTOR, MEMBERSHIP_SEND_INVITATION_OPERATION) => Some("invitations_send"),
        (MEMBERSHIP_EXECUTOR, MEMBERSHIP_REVOKE_INVITATION_OPERATION) => Some("invitations_revoke"),
        (CANVAS_WRITE_EXECUTOR, CANVAS_PROMOTE_OPERATION) => Some("promote"),
        _ => {
            return Err(Error::engine(format!(
                "{executor}.{operation} has no exact source-argument route"
            )))
        }
    };
    if (executor, operation) == (CANVAS_WRITE_EXECUTOR, CANVAS_PROMOTE_OPERATION)
        && (object.contains_key("plan_digest") || object.contains_key("dry_run"))
    {
        return Err(Error::engine(
            "promotion plan evidence is executor-owned and cannot be supplied by the caller",
        ));
    }
    if executor == IDENTITY_EXECUTOR && object.contains_key("if_binding_state_revision") {
        return Err(Error::engine(
            "identity binding state revision is source-owned and cannot be supplied by the caller",
        ));
    }
    if executor == ACCESS_EXECUTOR
        && policy_action(operation).is_ok()
        && (object.contains_key("if_content_seq")
            || object.contains_key("if_inherited_policy_revision")
            || contains_field(&object, "if_account_id"))
    {
        return Err(Error::engine(
            "access policy preparation state is source-owned and cannot be supplied by the caller",
        ));
    }
    if (executor, operation) == (ACCESS_EXECUTOR, POLICY_SET_MANY_OPERATION)
        && ["if_policy_revision", "if_content_seq", "if_account_id"]
            .iter()
            .any(|field| contains_field(&object, field))
    {
        return Err(Error::engine(
            "access policy preparation state is source-owned and cannot be supplied by the caller",
        ));
    }
    if executor == ACCESS_EXECUTOR
        && artifact_grant_action(operation).is_ok()
        && object.contains_key("if_previous_seq")
    {
        return Err(Error::engine(
            "artifact grant revision is source-owned and cannot be supplied by the caller",
        ));
    }
    if let Some(action) = action {
        object.insert("action".into(), json!(action));
    }
    if executor == IDENTITY_EXECUTOR && operation == IDENTITY_RECONCILE_OPERATION {
        if object
            .get("apply")
            .is_some_and(|value| value.as_bool() != Some(true))
        {
            return Err(Error::engine(
                "identity_admin.manage_bindings.reconcile apply must be true when supplied; preparation itself is the preview",
            ));
        }
        object.insert("apply".into(), json!(true));
    }
    Ok(Value::Object(object))
}

fn contains_field(object: &serde_json::Map<String, Value>, field: &str) -> bool {
    object.iter().any(|(key, value)| {
        key == field
            || value
                .as_object()
                .is_some_and(|object| contains_field(object, field))
            || value.as_array().is_some_and(|items| {
                items.iter().any(|item| {
                    item.as_object()
                        .is_some_and(|object| contains_field(object, field))
                })
            })
    })
}

fn identity_action(operation: &str) -> Result<&'static str> {
    match operation {
        IDENTITY_ADD_OPERATION => Ok("add"),
        IDENTITY_CANONICALIZE_OPERATION => Ok("canonicalize"),
        IDENTITY_RECONCILE_OPERATION => Ok("reconcile"),
        IDENTITY_REMOVE_OPERATION => Ok("remove"),
        _ => Err(Error::engine(format!(
            "identity_admin.{operation} has no exact binding action"
        ))),
    }
}

fn sqlite_engine<'a>(engine: &'a EngineHandle, operation: &str) -> Result<&'a crate::Db> {
    match engine {
        EngineHandle::Sqlite(db) => Ok(db),
        #[allow(unreachable_patterns)]
        _ => Err(Error::engine(format!(
            "{operation} preparation is unavailable on this backend"
        ))),
    }
}

fn policy_action(operation: &str) -> Result<&'static str> {
    match operation {
        POLICY_GRANT_OPERATION => Ok("grant"),
        POLICY_REPLACE_OPERATION => Ok("replace"),
        POLICY_RESTORE_OPERATION => Ok("restore_inheritance"),
        POLICY_REVOKE_OPERATION => Ok("revoke"),
        POLICY_BASELINE_OPERATION => Ok("set_members_baseline"),
        POLICY_SET_MANY_OPERATION => Ok("set_many"),
        _ => Err(Error::engine(format!(
            "access_admin.{operation} has no exact policy action"
        ))),
    }
}

fn artifact_grant_action(operation: &str) -> Result<&'static str> {
    match operation {
        ARTIFACT_GRANT_OPERATION => Ok("grant"),
        ARTIFACT_REVOKE_OPERATION => Ok("revoke"),
        _ => Err(Error::engine(format!(
            "access_admin.{operation} has no exact artifact grant action"
        ))),
    }
}

fn vocabulary_action(executor: &str, operation: &str) -> Result<&'static str> {
    match (executor, operation) {
        (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_ALIAS_OPERATION) => Ok("alias_value"),
        (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_CREATE_OPERATION) => Ok("create_vocabulary"),
        (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_DEPRECATE_OPERATION) => Ok("deprecate_value"),
        (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_PROMOTE_OPERATION) => Ok("promote_value"),
        (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_PROPOSE_OPERATION) => Ok("propose_value"),
        (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_REORDER_OPERATION) => Ok("reorder_value"),
        (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_SET_GLOSS_OPERATION) => Ok("set_gloss"),
        (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_METADATA_OPERATION) => Ok("set_metadata"),
        (SCHEMA_DELETE_EXECUTOR, VOCABULARY_DELETE_VALUE_OPERATION) => Ok("delete_value"),
        (SCHEMA_DELETE_EXECUTOR, VOCABULARY_DELETE_OPERATION) => Ok("delete_vocabulary"),
        _ => Err(Error::engine(format!(
            "{executor}.{operation} has no exact vocabulary action"
        ))),
    }
}

fn policy_effect_summary(
    action: &str,
    prepared: &super::super::tools::policy::RecordPolicyPreparation,
) -> String {
    if action == "set_many" {
        let item_count = prepared.effect["item_count"].as_u64().unwrap_or_default();
        let changed_count = prepared.effect["changed_count"]
            .as_u64()
            .unwrap_or_default();
        return format!(
            "set exact subject grants on {item_count} record policies ({changed_count} changing)"
        );
    }
    let before_mode = prepared.effect["before"]["mode"]
        .as_str()
        .unwrap_or("unknown");
    let after_entries = prepared.effect["after"]["entries"]
        .as_array()
        .map(Vec::len)
        .unwrap_or_default();
    let change = if prepared.effect["changed"] == true {
        action.replace('_', " ")
    } else {
        "leave unchanged".into()
    };
    format!(
        "{change} access policy on '{}' ({}) from {before_mode} to {} with {after_entries} entr{}",
        prepared.target_name,
        prepared.target_id,
        prepared.effect["after"]["mode"]
            .as_str()
            .unwrap_or("unknown"),
        if after_entries == 1 { "y" } else { "ies" }
    )
}

fn artifact_grant_effect_summary(
    action: &str,
    prepared: &super::super::tools::artifacts::ArtifactModuleGrantPreparation,
) -> String {
    let capability = prepared.effect["grant"]["capability"]
        .as_str()
        .unwrap_or("unknown capability");
    let subject = prepared.effect["grant"]["subject_event_id"]
        .as_str()
        .unwrap_or("unknown subject");
    format!(
        "{action} {capability} for {subject} on '{}' ({})",
        prepared.target_name, prepared.target_id
    )
}

async fn prepare_operation(
    engine: &EngineHandle,
    caller: &Caller,
    hosted_authority: Option<&dyn HostedExecutorAuthority>,
    executor: &str,
    operation: &str,
    operation_arguments: Value,
) -> Result<PreparedWrite> {
    if (executor, operation) == (SCHEMA_ADMIN_EXECUTOR, SCHEMA_CONFIG_WRITE_OPERATION) {
        let db = sqlite_engine(engine, "schema configuration mutation")?;
        let prepared = super::super::tools::meta::prepare_schema_config_mutation(
            db,
            caller,
            operation_arguments,
        )
        .await?;
        return Ok(PreparedWrite {
            revalidation_arguments: prepared.revalidation_arguments,
            canonical_source_arguments: prepared.canonical_source_arguments,
            target_id: prepared.target_id,
            target: prepared.target,
            state_revision: prepared.state_revision,
            target_state_digest: prepared.target_state_digest,
            effect: prepared.effect,
            effect_summary: prepared.effect_summary,
            operation_evidence: prepared.operation_evidence,
        });
    }
    if matches!(executor, SCHEMA_ADMIN_EXECUTOR | SCHEMA_DELETE_EXECUTOR) {
        let db = sqlite_engine(engine, "vocabulary mutation")?;
        let prepared = super::super::tools::meta::prepare_vocabulary_mutation(
            db,
            caller,
            vocabulary_action(executor, operation)?,
            operation_arguments,
        )
        .await?;
        return Ok(PreparedWrite {
            revalidation_arguments: prepared.revalidation_arguments,
            canonical_source_arguments: prepared.canonical_source_arguments,
            target_id: prepared.target_id,
            target: prepared.target,
            state_revision: prepared.state_revision,
            target_state_digest: prepared.target_state_digest,
            effect: prepared.effect,
            effect_summary: prepared.effect_summary,
            operation_evidence: prepared.operation_evidence,
        });
    }
    let revalidation_arguments = operation_arguments.clone();
    let canonical_source_arguments =
        canonical_source_arguments(executor, operation, operation_arguments)?;
    match (executor, operation) {
        (executor, operation) if is_membership_operation(executor, operation) => {
            let hosted_authority = hosted_authority.ok_or_else(|| {
                Error::engine("hosted membership plans require an authoritative catalogue context")
            })?;
            let db = sqlite_engine(engine, "hosted membership mutation")?;
            let prepared = hosted_authority
                .prepare_membership_write(db, caller, canonical_source_arguments)
                .await?;
            // Invitation creation resolves its default expiry during
            // preparation. Revalidate the resolved canonical request, not
            // the caller's `expires_at: null`, which would drift on every
            // execution attempt as the clock advances.
            let revalidation_arguments = if operation == MEMBERSHIP_CREATE_INVITATION_OPERATION {
                prepared.canonical_source_arguments.clone()
            } else {
                revalidation_arguments
            };
            Ok(PreparedWrite {
                revalidation_arguments,
                canonical_source_arguments: prepared.canonical_source_arguments,
                target_id: prepared.target_id,
                target: prepared.target,
                state_revision: prepared.state_revision,
                target_state_digest: prepared.target_state_digest,
                effect: prepared.effect,
                effect_summary: prepared.effect_summary,
                operation_evidence: json!({
                    "kind": match operation {
                        MEMBERSHIP_SET_ROLE_OPERATION => "membership_role_change",
                        MEMBERSHIP_REMOVE_OPERATION => "membership_offboarding",
                        MEMBERSHIP_CREATE_INVITATION_OPERATION => "membership_invitation_create",
                        MEMBERSHIP_COPY_INVITATION_LINK_OPERATION => "membership_invitation_copy_link",
                        MEMBERSHIP_SEND_INVITATION_OPERATION => "membership_invitation_send",
                        MEMBERSHIP_REVOKE_INVITATION_OPERATION => "membership_invitation_revoke",
                        _ => unreachable!("membership operation classification is exact"),
                    },
                    "catalogue_snapshot":prepared.catalogue_snapshot,
                    "source_evidence":prepared.operation_evidence,
                }),
            })
        }
        (ACCESS_EXECUTOR, operation) if policy_action(operation).is_ok() => {
            let db = sqlite_engine(engine, "access policy mutation")?;
            let action = policy_action(operation)?;
            let prepared = super::super::tools::policy::prepare_record_policy_mutation(
                db,
                caller,
                action,
                canonical_source_arguments.clone(),
            )
            .await?;
            let target = format!("{} ({})", prepared.target_name, prepared.target_id);
            let effect_summary = policy_effect_summary(action, &prepared);
            Ok(PreparedWrite {
                revalidation_arguments,
                canonical_source_arguments: prepared.canonical_source_arguments,
                target_id: prepared.target_id.clone(),
                target,
                state_revision: prepared.policy_revision.clone(),
                target_state_digest: prepared.target_state_digest.clone(),
                effect_summary,
                effect: prepared.effect,
                operation_evidence: json!({
                    "kind":"record_policy_mutation",
                    "action":action,
                    "policy_revision":prepared.policy_revision,
                }),
            })
        }
        (ACCESS_EXECUTOR, operation) if artifact_grant_action(operation).is_ok() => {
            let db = sqlite_engine(engine, "artifact module grant mutation")?;
            let action = artifact_grant_action(operation)?;
            let prepared = super::super::tools::artifacts::prepare_artifact_module_grant_mutation(
                db,
                caller,
                action,
                canonical_source_arguments,
            )
            .await?;
            let target = format!("{} ({})", prepared.target_name, prepared.target_id);
            let effect_summary = artifact_grant_effect_summary(action, &prepared);
            Ok(PreparedWrite {
                revalidation_arguments,
                canonical_source_arguments: prepared.canonical_source_arguments,
                target_id: prepared.target_id.clone(),
                target,
                state_revision: prepared.state_revision.clone(),
                target_state_digest: prepared.target_state_digest,
                effect_summary,
                effect: prepared.effect,
                operation_evidence: json!({
                    "kind":"artifact_module_grant_mutation",
                    "action":action,
                    "artifact_content_revision":prepared.state_revision,
                }),
            })
        }
        (IDENTITY_EXECUTOR, operation) => {
            let db = sqlite_engine(engine, "identity binding")?;
            let prepared = super::super::tools::identity::prepare_binding_mutation(
                db,
                caller,
                identity_action(operation)?,
                canonical_source_arguments.clone(),
            )
            .await?;
            Ok(PreparedWrite {
                revalidation_arguments,
                canonical_source_arguments: prepared.canonical_source_arguments,
                target_id: prepared.target_id,
                target: prepared.target,
                state_revision: prepared.state_revision.clone(),
                target_state_digest: prepared.target_state_digest,
                effect: prepared.effect,
                effect_summary: prepared.effect_summary,
                operation_evidence: json!({
                    "kind":"identity_binding_mutation",
                    "binding_state_revision":prepared.state_revision,
                }),
            })
        }
        (RECORDS_WRITE_EXECUTOR, CORRECT_RECORD_TYPE_OPERATION) => {
            let prepared = match engine {
                EngineHandle::Sqlite(db) => {
                    super::super::tools::lifecycle::prepare_correct_record_type(
                        db,
                        caller,
                        canonical_source_arguments,
                    )
                    .await?
                }
                #[cfg(feature = "postgres")]
                EngineHandle::Postgres(db) => {
                    crate::postgres::prepare_correct_record_type(
                        db,
                        caller,
                        canonical_source_arguments,
                    )
                    .await?
                }
                #[cfg(feature = "turso-local")]
                EngineHandle::TursoLocal(db) => {
                    crate::turso_local::prepare_correct_record_type(
                        db,
                        caller,
                        canonical_source_arguments,
                    )
                    .await?
                }
            };
            Ok(PreparedWrite {
                revalidation_arguments,
                canonical_source_arguments: prepared.canonical_source_arguments,
                target_id: prepared.target_id,
                target: prepared.target,
                state_revision: prepared.state_revision,
                target_state_digest: prepared.target_state_digest,
                effect: prepared.effect,
                effect_summary: prepared.effect_summary,
                operation_evidence: prepared.operation_evidence,
            })
        }
        (CANVAS_WRITE_EXECUTOR, CANVAS_PROMOTE_OPERATION) => {
            let db = sqlite_engine(engine, "canvas promotion")?;
            let prepared = super::super::tools::canvas::prepare_promote(
                db,
                caller,
                canonical_source_arguments,
            )
            .await?;
            Ok(PreparedWrite {
                revalidation_arguments,
                canonical_source_arguments: prepared.canonical_source_arguments,
                target_id: prepared.target_id,
                target: prepared.target,
                state_revision: prepared.state_revision,
                target_state_digest: prepared.target_state_digest,
                effect: prepared.effect,
                effect_summary: prepared.effect_summary,
                operation_evidence: prepared.operation_evidence,
            })
        }
        (RECORDS_DELETE_EXECUTOR, DELETE_RECORD_OPERATION) => {
            let db = sqlite_engine(engine, "record deletion")?;
            let prepared = super::super::tools::lifecycle::prepare_delete_record(
                db,
                caller,
                canonical_source_arguments,
            )
            .await?;
            Ok(PreparedWrite {
                revalidation_arguments,
                canonical_source_arguments: prepared.canonical_source_arguments,
                target_id: prepared.target_id,
                target: prepared.target,
                state_revision: prepared.state_revision,
                target_state_digest: prepared.target_state_digest,
                effect: prepared.effect,
                effect_summary: prepared.effect_summary,
                operation_evidence: prepared.operation_evidence,
            })
        }
        (RECORDS_DELETE_EXECUTOR, REMOVE_CITATION_OPERATION) => {
            let db = sqlite_engine(engine, "citation removal")?;
            let prepared = super::super::tools::citations::prepare_manage_citations_remove(
                db,
                caller,
                canonical_source_arguments,
            )
            .await?;
            Ok(PreparedWrite {
                revalidation_arguments,
                canonical_source_arguments: prepared.canonical_source_arguments,
                target_id: prepared.target_id,
                target: prepared.target,
                state_revision: prepared.state_revision,
                target_state_digest: prepared.target_state_digest,
                effect: prepared.effect,
                effect_summary: prepared.effect_summary,
                operation_evidence: prepared.operation_evidence,
            })
        }
        (RECORDS_DELETE_EXECUTOR, DETACH_ATTACHMENT_OPERATION) => {
            let prepared = match engine {
                EngineHandle::Sqlite(db) => {
                    super::super::tools::attachments::prepare_manage_attachments_detach(
                        db,
                        caller,
                        canonical_source_arguments,
                    )
                    .await?
                }
                #[cfg(feature = "postgres")]
                EngineHandle::Postgres(db) => {
                    crate::postgres::prepare_manage_attachments_detach(
                        db,
                        caller,
                        canonical_source_arguments,
                    )
                    .await?
                }
                #[cfg(feature = "turso-local")]
                EngineHandle::TursoLocal(db) => {
                    crate::turso_local::prepare_manage_attachments_detach(
                        db,
                        caller,
                        canonical_source_arguments,
                    )
                    .await?
                }
            };
            Ok(PreparedWrite {
                revalidation_arguments,
                canonical_source_arguments: prepared.canonical_source_arguments,
                target_id: prepared.target_id,
                target: prepared.target,
                state_revision: prepared.state_revision,
                target_state_digest: prepared.target_state_digest,
                effect: prepared.effect,
                effect_summary: prepared.effect_summary,
                operation_evidence: prepared.operation_evidence,
            })
        }
        _ => Err(Error::engine(format!(
            "{executor}.{operation} has no exact write preparation route"
        ))),
    }
}

fn allowed_fields(arguments: &Value, allowed: &[&str]) -> Result<()> {
    let object = arguments
        .as_object()
        .ok_or_else(|| Error::engine("executor arguments must be an object"))?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(Error::engine(format!(
            "unexpected executor field '{field}'; allowed fields: {}",
            allowed.join(", ")
        )));
    }
    Ok(())
}

fn with_plan_error(mut body: Value, code: &str, continuation: Value) -> Value {
    body["result"]["structuredContent"]["plan_error"] = json!({
        "code":code,
        "continuation":continuation,
    });
    body
}

fn describe_then_prepare_continuation(contract: &OperationContract) -> Value {
    json!({
        "action":"describe_operation_then_prepare",
        "retry_ready":false,
        "describe":{
            "tool":"describe_operation",
            "arguments":{
                "executor":contract.executor,
                "operation":contract.operation,
            },
        },
        "operation_input_schema_pointer":"/result/structuredContent/input_schema",
        "prepare_arguments_pointer":"/arguments",
    })
}

struct PlanError<'a> {
    code: &'a str,
    diagnostic: &'a str,
    include_contract_repair: bool,
    continuation: Option<Value>,
    source_dispatch_count: u64,
}

struct RevalidationContext<'a> {
    id: Value,
    modern: bool,
    contract: &'a OperationContract,
    envelope: &'a Value,
    plan_id: &'a str,
    initially_loaded: &'a StoredPlan,
    plan: &'a WritePlan,
    telemetry_request: Option<&'a super::telemetry::TelemetryRequest>,
    started: Instant,
}

impl<'a> PlanError<'a> {
    fn new(code: &'a str, diagnostic: &'a str, include_contract_repair: bool) -> Self {
        Self {
            code,
            diagnostic,
            include_contract_repair,
            continuation: None,
            source_dispatch_count: 0,
        }
    }

    fn unavailable(diagnostic: &'a str) -> Self {
        Self {
            code: "plan_preparation_unavailable",
            diagnostic,
            include_contract_repair: false,
            continuation: Some(json!({
                "action":"operation_withheld",
                "retryable":false,
                "retry_ready":false,
            })),
            source_dispatch_count: 0,
        }
    }

    fn indeterminate(diagnostic: &'a str) -> Self {
        Self {
            code: "plan_execution_indeterminate",
            diagnostic,
            include_contract_repair: false,
            continuation: Some(json!({
                "action":"verify_target_state_before_any_new_plan",
                "retryable":false,
                "retry_ready":false,
            })),
            source_dispatch_count: 1,
        }
    }
}

impl ExecutorPrototypeStdioServer {
    pub(super) async fn handle_plan_backed_write(
        &self,
        id: Value,
        modern: bool,
        message: Value,
        contract: OperationContract,
        arguments: Value,
        persistence_lease: Option<DeploymentPersistenceLease>,
    ) -> Value {
        let telemetry_request = self.telemetry.as_ref().map(|telemetry| {
            telemetry.request(
                Some(&contract.executor),
                Some(&contract.operation),
                arguments.get("plan_id").and_then(Value::as_str),
            )
        });
        if !(supports(&contract.executor, &contract.operation)
            || self.hosted_membership_plans
                && is_membership_operation(&contract.executor, &contract.operation))
        {
            if let (Some(telemetry), Some(request)) = (&self.telemetry, &telemetry_request) {
                telemetry.emit(super::telemetry::EventSpec {
                    request: Some(request.clone()),
                    phase: super::telemetry::TelemetryPhase::OperationUnavailable,
                    outcome: super::telemetry::TelemetryOutcome::Unavailable,
                    error_class: Some(super::telemetry::TelemetryErrorClass::ContractUnavailable),
                    flags: super::telemetry::TelemetryFlags {
                        unreachable_advertised: true,
                        ..super::telemetry::TelemetryFlags::default()
                    },
                    ..super::telemetry::EventSpec::default()
                });
            }
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &arguments,
                    telemetry_request.as_ref(),
                    PlanError::unavailable(
                        "this high-risk operation is withheld until its source module exposes a truthful non-mutating preparation seam",
                    ),
                )
                .await;
        }
        if let (Some(telemetry), Some(request)) = (&self.telemetry, &telemetry_request) {
            let sizes = super::telemetry::TelemetrySizes {
                request_bytes: super::telemetry::size_bucket(
                    serde_json::to_vec(&arguments)
                        .map(|bytes| bytes.len())
                        .unwrap_or(0),
                ),
                contract_bytes: super::telemetry::size_bucket(contract.bytes),
                ..super::telemetry::TelemetrySizes::default()
            };
            telemetry.emit(super::telemetry::EventSpec {
                request: Some(request.clone()),
                phase: super::telemetry::TelemetryPhase::OperationSelected,
                outcome: super::telemetry::TelemetryOutcome::Succeeded,
                sizes,
                ..super::telemetry::EventSpec::default()
            });
            telemetry.emit(super::telemetry::EventSpec {
                request: Some(request.clone()),
                phase: super::telemetry::TelemetryPhase::ContractLoaded,
                outcome: super::telemetry::TelemetryOutcome::Succeeded,
                sizes,
                ..super::telemetry::EventSpec::default()
            });
        }
        if arguments.get("plan_id").is_some() {
            return self
                .execute_write_plan(
                    id,
                    modern,
                    message,
                    contract,
                    arguments,
                    telemetry_request,
                    persistence_lease,
                )
                .await;
        }
        if arguments.get("arguments").is_some() {
            return self
                .prepare_write_plan(id, modern, contract, arguments, telemetry_request)
                .await;
        }
        let body = self
            .fixture_error_response(
                id,
                modern,
                &contract.executor,
                &contract.operation,
                "raw execution is forbidden; prepare with operation-specific arguments first",
                None,
                &arguments,
                "prepare_required",
                None,
                false,
            )
            .await;
        with_plan_error(
            body,
            "prepare_required",
            describe_then_prepare_continuation(&contract),
        )
    }

    async fn prepare_write_plan(
        &self,
        id: Value,
        modern: bool,
        contract: OperationContract,
        envelope: Value,
        telemetry_request: Option<super::telemetry::TelemetryRequest>,
    ) -> Value {
        let started = Instant::now();
        let mut format_arguments = envelope.clone();
        if let Err(error) = render::take_format("executor_write_plan", &mut format_arguments) {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new("preparation_validation_failed", &error, true),
                )
                .await;
        }
        if let Err(error) = allowed_fields(
            &envelope,
            &["operation", "arguments", "run_key", "parent_key", "format"],
        ) {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new("preparation_validation_failed", &error.to_string(), true),
                )
                .await;
        }
        let operation_arguments = envelope
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let schema_valid = jsonschema::validator_for(&contract.input_schema)
            .map(|validator| validator.is_valid(&operation_arguments))
            .unwrap_or(false);
        if let Err(error) = validate(
            &contract.executor,
            &contract.operation,
            operation_arguments.clone(),
            self.hosted_authority.as_deref(),
        ) {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new("preparation_validation_failed", &error.to_string(), true),
                )
                .await;
        }
        if !schema_valid {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new(
                        "contract_drift",
                        "production parser accepted arguments rejected by the disclosed schema",
                        true,
                    ),
                )
                .await;
        }
        let prepared = match prepare_operation(
            &self.engine,
            &self.caller,
            self.hosted_authority.as_deref(),
            &contract.executor,
            &contract.operation,
            operation_arguments.clone(),
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("preparation_rejected", &error.to_string(), true),
                    )
                    .await
            }
        };
        if let (Some(telemetry), Some(request)) = (&self.telemetry, &telemetry_request) {
            telemetry.emit(super::telemetry::EventSpec {
                request: Some(request.clone()),
                phase: super::telemetry::TelemetryPhase::ValidationCompleted,
                outcome: super::telemetry::TelemetryOutcome::Succeeded,
                counts: super::telemetry::TelemetryCounts {
                    attempt_bucket: super::telemetry::attempt_bucket(1),
                    ..super::telemetry::TelemetryCounts::default()
                },
                ..super::telemetry::EventSpec::default()
            });
        }
        let created_at_ms = now_ms();
        let binding = match engine_binding(&self.engine, &self.caller).await {
            Ok(binding) => binding,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("preparation_failed", &error.to_string(), false),
                    )
                    .await
            }
        };
        let mut plan = WritePlan {
            id: format!("wpl1:{}", Uuid::new_v4()),
            binding,
            executor: contract.executor.clone(),
            operation: contract.operation.clone(),
            source_tool: contract.source_tool.clone(),
            operation_arguments,
            arguments_digest: String::new(),
            revalidation_arguments: prepared.revalidation_arguments,
            revalidation_arguments_digest: String::new(),
            canonical_source_arguments: prepared.canonical_source_arguments,
            source_arguments_digest: String::new(),
            target_id: prepared.target_id,
            target: prepared.target,
            target_state_digest: prepared.target_state_digest,
            state_revision: prepared.state_revision,
            effect: prepared.effect,
            effect_summary: prepared.effect_summary,
            operation_evidence: prepared.operation_evidence,
            effect_digest: String::new(),
            contract_digest: contract.digest.clone(),
            catalogue_digest: self.manifest_digest.clone(),
            server_version: server_version(),
            expires_at_ms: created_at_ms.saturating_add(self.write_runtime.ttl_ms),
            nonce: Uuid::new_v4().to_string(),
            signing_key_id: String::new(),
            integrity: String::new(),
        };
        plan.arguments_digest = match digest(&plan.operation_arguments) {
            Ok(digest) => digest,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("preparation_failed", &error.to_string(), false),
                    )
                    .await
            }
        };
        plan.source_arguments_digest = match digest(&plan.canonical_source_arguments) {
            Ok(digest) => digest,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("preparation_failed", &error.to_string(), false),
                    )
                    .await
            }
        };
        plan.revalidation_arguments_digest = match digest(&plan.revalidation_arguments) {
            Ok(digest) => digest,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("preparation_failed", &error.to_string(), false),
                    )
                    .await
            }
        };
        plan.effect_digest = match digest(&plan.effect) {
            Ok(digest) => digest,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("preparation_failed", &error.to_string(), false),
                    )
                    .await
            }
        };
        plan.signing_key_id = match self.write_runtime.store.active_key_id().await {
            Ok(key_id) => key_id,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("preparation_failed", &error.to_string(), false),
                    )
                    .await
            }
        };
        plan.integrity = match self
            .write_runtime
            .store
            .seal(&plan.signing_key_id, &integrity_payload(&plan))
            .await
        {
            Ok(integrity) => integrity,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("preparation_failed", &error.to_string(), false),
                    )
                    .await
            }
        };
        let plan_id = plan.id.clone();
        let response = json!({
            "plan_id":plan.id,
            "executor":plan.executor,
            "operation":plan.operation,
            "target":plan.target,
            "effect_summary":plan.effect_summary,
            "effect":plan.effect,
            "expires_at":rfc3339_millis(plan.expires_at_ms),
            "contract_digest":plan.contract_digest,
            "catalogue_digest":plan.catalogue_digest,
            "server_version":plan.server_version,
            "arguments_digest":plan.arguments_digest,
            "revalidation_arguments_digest":plan.revalidation_arguments_digest,
            "source_arguments_digest":plan.source_arguments_digest,
            "effect_digest":plan.effect_digest,
            "state_revision":plan.state_revision,
            "target_state_digest":plan.target_state_digest,
            "operation_evidence":plan.operation_evidence,
            "preparation_mutated":false,
            "plan_policy_evidence":[
                {"policy":"high_risk_only","would_require_plan":true,"reason":"classified consequential operation"},
                {"policy":"all_complex_writes","would_require_plan":true,"reason":"state-bound concurrency-guarded write"}
            ],
            "next_call":{
                "tool":plan.executor,
                "arguments":{
                    "operation":plan.operation,
                    "plan_id":plan.id,
                    "target":plan.target,
                    "effect_summary":plan.effect_summary
                }
            }
        });
        let payload = match serde_json::to_value(&plan) {
            Ok(payload) => payload,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("preparation_failed", &error.to_string(), false),
                    )
                    .await
            }
        };
        let expires_at_ms = plan.expires_at_ms;
        let signing_key_id = plan.signing_key_id.clone();
        if let Err(error) = self
            .write_runtime
            .store
            .insert_prepared(
                &plan_id,
                &payload,
                &signing_key_id,
                expires_at_ms,
                created_at_ms,
            )
            .await
        {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new("preparation_failed", &error.to_string(), false),
                )
                .await;
        }
        if let (Some(telemetry), Some(request)) = (&self.telemetry, telemetry_request) {
            let request = telemetry.with_plan_correlation(request, &plan_id);
            let response_bytes = serde_json::to_vec(&response)
                .map(|bytes| bytes.len())
                .unwrap_or(0);
            telemetry.emit(super::telemetry::EventSpec {
                request: Some(request),
                phase: super::telemetry::TelemetryPhase::PlanPrepared,
                outcome: super::telemetry::TelemetryOutcome::Succeeded,
                counts: super::telemetry::TelemetryCounts {
                    attempt_bucket: super::telemetry::attempt_bucket(1),
                    ..super::telemetry::TelemetryCounts::default()
                },
                latency_bucket: super::telemetry::latency_bucket(elapsed_ms(started)),
                sizes: super::telemetry::TelemetrySizes {
                    request_bytes: super::telemetry::size_bucket(
                        serde_json::to_vec(&envelope)
                            .map(|bytes| bytes.len())
                            .unwrap_or(0),
                    ),
                    result_bytes: super::telemetry::size_bucket(response_bytes),
                    contract_bytes: super::telemetry::size_bucket(contract.bytes),
                },
                ..super::telemetry::EventSpec::default()
            });
        }
        let run_context = run_context_for_engine(
            &self.engine,
            self.caller.clone(),
            &envelope,
            self.registry.public_origin(),
        )
        .await;
        let structured = attach_run_context(response, run_context);
        let mut result = protocol::call_result_content(
            &contract.executor,
            render::Format::Json,
            ToolResult::from(structured),
            None,
        );
        if modern {
            protocol::add_modern_result_fields(&mut result);
        }
        result["_meta"]["nativeExecutor"] = self.executor_meta();
        let body = json!({"jsonrpc":"2.0","id":id,"result":result});
        self.trace.record(json!({
            "schema":TRACE_SCHEMA,
            "request_id":self.trace.next_request_id(),
            "kind":"write_plan_prepared",
            "mode":"prepare",
            "executor":contract.executor,
            "operation":contract.operation,
            "plan_id":plan_id,
            "contract_digest":contract.digest,
            "manifest_sha256":self.manifest_digest,
            "server_version":server_version(),
            "preparation_mutated":false,
            "source_dispatch_count":0,
            "completed":true,
            "elapsed_ms":elapsed_ms(started),
        }));
        body
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_write_plan(
        &self,
        id: Value,
        modern: bool,
        mut message: Value,
        contract: OperationContract,
        envelope: Value,
        telemetry_request: Option<super::telemetry::TelemetryRequest>,
        persistence_lease: Option<DeploymentPersistenceLease>,
    ) -> Value {
        let started = Instant::now();
        let mut format_arguments = envelope.clone();
        if let Err(error) = render::take_format("executor_write_plan", &mut format_arguments) {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new("execution_shape_rejected", &error, false),
                )
                .await;
        }
        if envelope.get("arguments").is_some() {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new(
                        "raw_arguments_forbidden",
                        "plan-backed execution accepts no raw operation arguments",
                        false,
                    ),
                )
                .await;
        }
        if let Err(error) = allowed_fields(
            &envelope,
            &[
                "operation",
                "plan_id",
                "target",
                "effect_summary",
                "run_key",
                "parent_key",
                "format",
            ],
        ) {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new("execution_shape_rejected", &error.to_string(), false),
                )
                .await;
        }
        let Some(plan_id) = envelope.get("plan_id").and_then(Value::as_str) else {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new("plan_id_required", "plan_id must be a string", false),
                )
                .await;
        };
        let plan_id = plan_id.to_string();
        let binding = match engine_binding(&self.engine, &self.caller).await {
            Ok(binding) => binding,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("plan_identity_unavailable", &error.to_string(), false),
                    )
                    .await
            }
        };
        let stored = match self.write_runtime.store.load(&plan_id, now_ms()).await {
            Ok(Some(plan)) => plan,
            Ok(None) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new(
                            "plan_not_found",
                            "write plan is unknown to the durable store",
                            false,
                        ),
                    )
                    .await
            }
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("plan_store_unavailable", &error.to_string(), false),
                    )
                    .await
            }
        };
        let plan: WritePlan = match serde_json::from_value(stored.payload.clone()) {
            Ok(plan) => plan,
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("plan_integrity_failed", &error.to_string(), false),
                    )
                    .await
            }
        };
        if stored.key_id != plan.signing_key_id {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new(
                        "plan_integrity_failed",
                        "write plan signing key binding does not match its durable row",
                        false,
                    ),
                )
                .await;
        }
        if plan.id != plan_id || stored.expires_at_ms != plan.expires_at_ms {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new(
                        "plan_integrity_failed",
                        "write plan row identity or expiry does not match its signed payload",
                        false,
                    ),
                )
                .await;
        }
        if plan.binding != binding {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new(
                        "plan_identity_mismatch",
                        "write plan belongs to another actor, principal, workspace, or database",
                        false,
                    ),
                )
                .await;
        }
        if plan.executor != contract.executor
            || plan.operation != contract.operation
            || plan.source_tool != contract.source_tool
            || plan.contract_digest != contract.digest
            || plan.catalogue_digest != self.manifest_digest
            || plan.server_version != server_version()
        {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new(
                        "plan_contract_mismatch",
                        "write plan no longer matches the live operation contract, catalogue, or server version",
                        false,
                    ),
                )
                .await;
        }
        if let Err(error) = self.write_runtime.verify(&plan).await {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new("plan_integrity_failed", &error.to_string(), false),
                )
                .await;
        }
        let visible_target = envelope.get("target").and_then(Value::as_str);
        let visible_effect = envelope.get("effect_summary").and_then(Value::as_str);
        if visible_target != Some(plan.target.as_str())
            || visible_effect != Some(plan.effect_summary.as_str())
        {
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::new(
                        "visible_effect_mismatch",
                        "target and effect_summary must exactly match the prepared approval effect",
                        false,
                    ),
                )
                .await;
        }
        match &stored.state {
            StoredState::Completed {
                result,
                source_dispatch_count,
            } => {
                return self.replay_write_plan(
                    id,
                    &plan,
                    result.clone(),
                    *source_dispatch_count,
                    telemetry_request.as_ref(),
                    started,
                )
            }
            StoredState::Executing { started_at_ms, .. }
            | StoredState::Indeterminate { started_at_ms, .. } => {
                let started_at = rfc3339_millis(*started_at_ms);
                let diagnostic = format!(
                    "write plan entered source execution at {started_at} but no terminal result was durably cached; verify target state before preparing any replacement plan"
                );
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::indeterminate(&diagnostic),
                    )
                    .await;
            }
            StoredState::Expired => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new(
                            "plan_expired",
                            "write plan has expired; prepare the current effect again",
                            false,
                        ),
                    )
                    .await;
            }
            StoredState::Prepared => {}
        }
        #[cfg(test)]
        if let Some(gate) = &self.write_runtime.revalidation_gate {
            gate.entered.add_permits(1);
            let permit = gate
                .release
                .acquire()
                .await
                .expect("revalidation gate open");
            permit.forget();
        }
        let current = prepare_operation(
            &self.engine,
            &self.caller,
            self.hosted_authority.as_deref(),
            &plan.executor,
            &plan.operation,
            plan.revalidation_arguments.clone(),
        )
        .await;
        let current = match current {
            Ok(current) => current,
            Err(error) => {
                let diagnostic = error.to_string();
                let identity_state_drift = plan.executor == IDENTITY_EXECUTOR
                    && (diagnostic.contains("stale expected owner")
                        || diagnostic.contains("collision"));
                let code = if diagnostic.contains("revision conflict") || identity_state_drift {
                    "plan_stale"
                } else {
                    "plan_revalidation_failed"
                };
                return self
                    .write_revalidation_error_or_advanced(
                        RevalidationContext {
                            id,
                            modern,
                            contract: &contract,
                            envelope: &envelope,
                            plan_id: &plan_id,
                            initially_loaded: &stored,
                            plan: &plan,
                            telemetry_request: telemetry_request.as_ref(),
                            started,
                        },
                        PlanError::new(code, &diagnostic, false),
                    )
                    .await;
            }
        };
        let current_effect_digest = match digest(&current.effect) {
            Ok(digest) => digest,
            Err(error) => {
                return self
                    .write_revalidation_error_or_advanced(
                        RevalidationContext {
                            id,
                            modern,
                            contract: &contract,
                            envelope: &envelope,
                            plan_id: &plan_id,
                            initially_loaded: &stored,
                            plan: &plan,
                            telemetry_request: telemetry_request.as_ref(),
                            started,
                        },
                        PlanError::new("plan_revalidation_failed", &error.to_string(), false),
                    )
                    .await;
            }
        };
        let current_source_arguments_digest = match digest(&current.canonical_source_arguments) {
            Ok(digest) => digest,
            Err(error) => {
                return self
                    .write_revalidation_error_or_advanced(
                        RevalidationContext {
                            id,
                            modern,
                            contract: &contract,
                            envelope: &envelope,
                            plan_id: &plan_id,
                            initially_loaded: &stored,
                            plan: &plan,
                            telemetry_request: telemetry_request.as_ref(),
                            started,
                        },
                        PlanError::new("plan_revalidation_failed", &error.to_string(), false),
                    )
                    .await;
            }
        };
        let current_revalidation_arguments_digest = match digest(&current.revalidation_arguments) {
            Ok(digest) => digest,
            Err(error) => {
                return self
                    .write_revalidation_error_or_advanced(
                        RevalidationContext {
                            id,
                            modern,
                            contract: &contract,
                            envelope: &envelope,
                            plan_id: &plan_id,
                            initially_loaded: &stored,
                            plan: &plan,
                            telemetry_request: telemetry_request.as_ref(),
                            started,
                        },
                        PlanError::new("plan_revalidation_failed", &error.to_string(), false),
                    )
                    .await;
            }
        };
        if current.target_id != plan.target_id
            || current.target != plan.target
            || current.state_revision != plan.state_revision
            || current.target_state_digest != plan.target_state_digest
            || current_source_arguments_digest != plan.source_arguments_digest
            || current.canonical_source_arguments != plan.canonical_source_arguments
            || current_revalidation_arguments_digest != plan.revalidation_arguments_digest
            || current.revalidation_arguments != plan.revalidation_arguments
            || current.effect_summary != plan.effect_summary
            || current.operation_evidence != plan.operation_evidence
            || current_effect_digest != plan.effect_digest
        {
            return self
                .write_revalidation_error_or_advanced(
                    RevalidationContext {
                        id,
                        modern,
                        contract: &contract,
                        envelope: &envelope,
                        plan_id: &plan_id,
                        initially_loaded: &stored,
                        plan: &plan,
                        telemetry_request: telemetry_request.as_ref(),
                        started,
                    },
                    PlanError::new(
                        "plan_stale",
                        "source arguments, state revision, target, or prepared effect changed; prepare again",
                        false,
                    ),
                )
                .await;
        }
        if let (Some(telemetry), Some(request)) = (&self.telemetry, &telemetry_request) {
            telemetry.emit(super::telemetry::EventSpec {
                request: Some(request.clone()),
                phase: super::telemetry::TelemetryPhase::PlanRevalidated,
                outcome: super::telemetry::TelemetryOutcome::Succeeded,
                counts: super::telemetry::TelemetryCounts {
                    attempt_bucket: super::telemetry::attempt_bucket(1),
                    ..super::telemetry::TelemetryCounts::default()
                },
                ..super::telemetry::EventSpec::default()
            });
        }
        let hosted_atomic_membership = self.hosted_membership_plans
            && is_hosted_atomic_membership_operation(&contract.executor, &contract.operation);
        let attempt_id = if hosted_atomic_membership {
            Uuid::new_v4().to_string()
        } else {
            match self.write_runtime.store.claim(&plan_id, now_ms()).await {
                Ok(ClaimOutcome::Claimed {
                    attempt_id,
                    plan: claimed,
                }) => {
                    if claimed.payload != stored.payload
                        || claimed.key_id != stored.key_id
                        || claimed.catalogue_payload_sha256 != stored.catalogue_payload_sha256
                    {
                        let _ = self
                            .write_runtime
                            .store
                            .mark_indeterminate(
                                &plan_id,
                                &attempt_id,
                                "durable plan payload changed while acquiring execution fence",
                                now_ms(),
                            )
                            .await;
                        return self
                            .write_plan_error(
                                id,
                                modern,
                                &contract,
                                &envelope,
                                telemetry_request.as_ref(),
                                PlanError::indeterminate(
                                    "durable plan payload changed while acquiring execution fence",
                                ),
                            )
                            .await;
                    }
                    attempt_id
                }
                Ok(ClaimOutcome::Existing(existing)) => match existing.state {
                    StoredState::Completed {
                        result,
                        source_dispatch_count,
                    } => {
                        return self.replay_write_plan(
                            id,
                            &plan,
                            result,
                            source_dispatch_count,
                            telemetry_request.as_ref(),
                            started,
                        )
                    }
                    StoredState::Executing { started_at_ms, .. }
                    | StoredState::Indeterminate { started_at_ms, .. } => {
                        let diagnostic = format!(
                        "write plan entered source execution at {} but no terminal result was durably cached; verify target state before preparing any replacement plan",
                        rfc3339_millis(started_at_ms)
                    );
                        return self
                            .write_plan_error(
                                id,
                                modern,
                                &contract,
                                &envelope,
                                telemetry_request.as_ref(),
                                PlanError::indeterminate(&diagnostic),
                            )
                            .await;
                    }
                    StoredState::Expired => {
                        return self
                            .write_plan_error(
                                id,
                                modern,
                                &contract,
                                &envelope,
                                telemetry_request.as_ref(),
                                PlanError::new(
                                    "plan_expired",
                                    "write plan expired before its durable execution claim",
                                    false,
                                ),
                            )
                            .await;
                    }
                    StoredState::Prepared => {
                        return self
                            .write_plan_error(
                                id,
                                modern,
                                &contract,
                                &envelope,
                                telemetry_request.as_ref(),
                                PlanError::new(
                                    "plan_store_conflict",
                                    "write plan could not acquire its durable execution fence",
                                    false,
                                ),
                            )
                            .await;
                    }
                },
                Ok(ClaimOutcome::NotFound) => {
                    return self
                        .write_plan_error(
                            id,
                            modern,
                            &contract,
                            &envelope,
                            telemetry_request.as_ref(),
                            PlanError::new(
                                "plan_not_found",
                                "write plan disappeared before claim",
                                false,
                            ),
                        )
                        .await;
                }
                Err(error) => {
                    return self
                        .write_plan_error(
                            id,
                            modern,
                            &contract,
                            &envelope,
                            telemetry_request.as_ref(),
                            PlanError::new("plan_store_unavailable", &error.to_string(), false),
                        )
                        .await;
                }
            }
        };
        if !hosted_atomic_membership {
            if let (Some(telemetry), Some(request)) = (&self.telemetry, &telemetry_request) {
                let counts = super::telemetry::TelemetryCounts {
                    attempt_bucket: super::telemetry::attempt_bucket(1),
                    dispatch_count_bucket: super::telemetry::dispatch_bucket(1),
                    ..super::telemetry::TelemetryCounts::default()
                };
                telemetry.emit(super::telemetry::EventSpec {
                    request: Some(request.clone()),
                    phase: super::telemetry::TelemetryPhase::PlanClaimed,
                    outcome: super::telemetry::TelemetryOutcome::Succeeded,
                    counts,
                    ..super::telemetry::EventSpec::default()
                });
                telemetry.emit(super::telemetry::EventSpec {
                    request: Some(request.clone()),
                    phase: super::telemetry::TelemetryPhase::DispatchBegun,
                    outcome: super::telemetry::TelemetryOutcome::Started,
                    counts,
                    ..super::telemetry::EventSpec::default()
                });
            }
        }
        let mut legacy_arguments = plan.canonical_source_arguments.clone();
        if let Some(object) = legacy_arguments.as_object_mut() {
            if (plan.executor.as_str(), plan.operation.as_str())
                == (RECORDS_WRITE_EXECUTOR, CORRECT_RECORD_TYPE_OPERATION)
            {
                object.insert("plan_id".into(), json!(&plan.id));
                object.insert("effect_digest".into(), json!(&plan.effect_digest));
            }
            for field in ["run_key", "parent_key"] {
                if let Some(value) = envelope.get(field) {
                    object.insert(field.into(), value.clone());
                }
            }
            object.insert("format".into(), json!("json"));
        }
        if let Some(params) = message.get_mut("params").and_then(Value::as_object_mut) {
            params.insert("name".into(), Value::String(plan.source_tool.clone()));
            params.insert("arguments".into(), legacy_arguments);
        }
        #[cfg(test)]
        if let Some(gate) = &self.write_runtime.dispatch_gate {
            gate.entered.add_permits(1);
            let permit = gate
                .release
                .acquire()
                .await
                .expect("test dispatch gate remains open");
            permit.forget();
        }
        let caller = if hosted_atomic_membership {
            match stored.catalogue_payload_sha256.clone() {
                Some(payload_sha256) => self.caller.clone().with_hosted_plan_execution(
                    crate::mcp::registry::HostedMembershipPlanExecution::detached(
                        plan_id.clone(),
                        attempt_id.clone(),
                        payload_sha256,
                        plan.operation_evidence.clone(),
                        now_ms(),
                    ),
                ),
                None => {
                    return self
                        .write_plan_error(
                            id,
                            modern,
                            &contract,
                            &envelope,
                            telemetry_request.as_ref(),
                            PlanError::new(
                                "plan_integrity_failed",
                                "hosted write plan is missing its catalogue payload fence",
                                false,
                            ),
                        )
                        .await
                }
            }
        } else {
            self.caller.clone()
        };
        let caller = caller.with_write_plan_execution(crate::mcp::registry::WritePlanExecution {
            plan_id: plan.id.clone(),
            effect_digest: plan.effect_digest.clone(),
            executor: plan.executor.clone(),
            operation: plan.operation.clone(),
        });
        let outcome = self
            .delegate_with_caller_and_persistence(message, caller, persistence_lease)
            .await;
        let mut body = outcome_body(outcome).unwrap_or_else(|| {
            protocol::error_response(
                id.clone(),
                protocol::INTERNAL_ERROR,
                "missing source response",
            )
        });
        add_executor_meta(&mut body, self.executor_meta());
        if !hosted_atomic_membership {
            if let (Some(telemetry), Some(request)) = (&self.telemetry, &telemetry_request) {
                telemetry.emit(super::telemetry::EventSpec {
                    request: Some(request.clone()),
                    phase: super::telemetry::TelemetryPhase::DispatchCompleted,
                    outcome: if response_succeeded(&body) {
                        super::telemetry::TelemetryOutcome::Succeeded
                    } else {
                        super::telemetry::TelemetryOutcome::Rejected
                    },
                    error_class: (!response_succeeded(&body))
                        .then_some(super::telemetry::TelemetryErrorClass::ExecutionError),
                    counts: super::telemetry::TelemetryCounts {
                        attempt_bucket: super::telemetry::attempt_bucket(1),
                        dispatch_count_bucket: super::telemetry::dispatch_bucket(1),
                        ..super::telemetry::TelemetryCounts::default()
                    },
                    latency_bucket: super::telemetry::latency_bucket(elapsed_ms(started)),
                    sizes: super::telemetry::TelemetrySizes {
                        result_bytes: super::telemetry::size_bucket(
                            serde_json::to_vec(&body)
                                .map(|bytes| bytes.len())
                                .unwrap_or(0),
                        ),
                        ..super::telemetry::TelemetrySizes::default()
                    },
                    ..super::telemetry::EventSpec::default()
                });
            }
        }
        if hosted_atomic_membership {
            match self.write_runtime.store.load(&plan_id, now_ms()).await {
                Ok(Some(StoredPlan {
                    state: StoredState::Executing { attempt_id: owner, .. },
                    ..
                })) if owner == attempt_id => {
                    if let (Some(telemetry), Some(request)) =
                        (&self.telemetry, &telemetry_request)
                    {
                        let counts = super::telemetry::TelemetryCounts {
                            attempt_bucket: super::telemetry::attempt_bucket(1),
                            dispatch_count_bucket: super::telemetry::dispatch_bucket(1),
                            ..super::telemetry::TelemetryCounts::default()
                        };
                        // The hosted source handler atomically committed the
                        // plan claim and membership/source fence before it
                        // returned. Only this authoritative read makes both
                        // lifecycle facts safe to emit.
                        telemetry.emit(super::telemetry::EventSpec {
                            request: Some(request.clone()),
                            phase: super::telemetry::TelemetryPhase::PlanClaimed,
                            outcome: super::telemetry::TelemetryOutcome::Succeeded,
                            counts,
                            ..super::telemetry::EventSpec::default()
                        });
                        telemetry.emit(super::telemetry::EventSpec {
                            request: Some(request.clone()),
                            phase: super::telemetry::TelemetryPhase::DispatchBegun,
                            outcome: super::telemetry::TelemetryOutcome::Started,
                            counts,
                            ..super::telemetry::EventSpec::default()
                        });
                        telemetry.emit(super::telemetry::EventSpec {
                            request: Some(request.clone()),
                            phase: super::telemetry::TelemetryPhase::DispatchCompleted,
                            outcome: if response_succeeded(&body) {
                                super::telemetry::TelemetryOutcome::Succeeded
                            } else {
                                super::telemetry::TelemetryOutcome::Rejected
                            },
                            error_class: (!response_succeeded(&body)).then_some(
                                super::telemetry::TelemetryErrorClass::ExecutionError,
                            ),
                            counts,
                            latency_bucket: super::telemetry::latency_bucket(elapsed_ms(started)),
                            sizes: super::telemetry::TelemetrySizes {
                                result_bytes: super::telemetry::size_bucket(
                                    serde_json::to_vec(&body)
                                        .map(|bytes| bytes.len())
                                        .unwrap_or(0),
                                ),
                                ..super::telemetry::TelemetrySizes::default()
                            },
                            ..super::telemetry::EventSpec::default()
                        });
                    }
                }
                Ok(Some(StoredPlan {
                    state: StoredState::Prepared,
                    ..
                })) => {
                    // Authorization or source-state rejection happened before
                    // the catalogue claim. Preserve the authoritative source
                    // error and leave the plan unmutated.
                    return body;
                }
                Ok(Some(StoredPlan {
                    state:
                        StoredState::Completed {
                            result,
                            source_dispatch_count,
                        },
                    ..
                })) => {
                    return self.replay_write_plan(
                        id,
                        &plan,
                        result,
                        source_dispatch_count,
                        telemetry_request.as_ref(),
                        started,
                    )
                }
                Ok(Some(StoredPlan {
                    state: StoredState::Executing { started_at_ms, .. }
                        | StoredState::Indeterminate { started_at_ms, .. },
                    ..
                })) => {
                    return self
                        .write_plan_error(
                            id,
                            modern,
                            &contract,
                            &envelope,
                            telemetry_request.as_ref(),
                            PlanError::indeterminate(&format!(
                                "write plan was claimed at {} by another hosted executor; replay after it reaches a durable terminal state",
                                rfc3339_millis(started_at_ms)
                            )),
                        )
                        .await
                }
                Ok(Some(StoredPlan {
                    state: StoredState::Expired,
                    ..
                })) => {
                    return self
                        .write_plan_error(
                            id,
                            modern,
                            &contract,
                            &envelope,
                            telemetry_request.as_ref(),
                            PlanError::new(
                                "plan_expired",
                                "write plan expired before its catalogue execution claim",
                                false,
                            ),
                        )
                        .await
                }
                Ok(None) => {
                    return self
                        .write_plan_error(
                            id,
                            modern,
                            &contract,
                            &envelope,
                            telemetry_request.as_ref(),
                            PlanError::new(
                                "plan_not_found",
                                "write plan disappeared during catalogue execution",
                                false,
                            ),
                        )
                        .await
                }
                Err(error) => {
                    return self
                        .write_plan_error(
                            id,
                            modern,
                            &contract,
                            &envelope,
                            telemetry_request.as_ref(),
                            PlanError::indeterminate(&format!(
                                "source returned but its catalogue execution fence could not be read: {error}"
                            )),
                        )
                        .await
                }
            }
        }
        let stored_result = body.get("result").cloned().unwrap_or_else(|| {
            json!({
                "isError":true,
                "content":[{"type":"text","text":"source dispatch returned no result"}]
            })
        });
        // Copy-link is the one invitation mutation whose successful result is
        // itself a bearer credential. Keep the first post-consent response
        // intact for the caller, but persist only a replay-safe terminal
        // result. A later retry must never recover the join URL from the plan
        // store, even after restart.
        let persisted_result = if contract.operation == MEMBERSHIP_COPY_INVITATION_LINK_OPERATION {
            json!({
                "isError": true,
                "content": [{"type":"text", "text":"invitation link was already disclosed; use a new idempotency key to rotate a fresh link"}],
                "structuredContent": {
                    "status": "already_disclosed",
                    "bearer_credential_persisted": false
                }
            })
        } else {
            stored_result.clone()
        };
        if let Err(error) = self
            .write_runtime
            .store
            .complete(&plan_id, &attempt_id, &persisted_result, now_ms())
            .await
        {
            let _ = self
                .write_runtime
                .store
                .mark_indeterminate(
                    &plan_id,
                    &attempt_id,
                    "source returned but terminal result could not be persisted",
                    now_ms(),
                )
                .await;
            return self
                .write_plan_error(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    telemetry_request.as_ref(),
                    PlanError::indeterminate(&format!(
                        "source execution returned but its result was not durably cached: {error}"
                    )),
                )
                .await;
        }
        if let (Some(telemetry), Some(request)) = (&self.telemetry, telemetry_request) {
            telemetry.emit(super::telemetry::EventSpec {
                request: Some(request),
                phase: super::telemetry::TelemetryPhase::PlanCompleted,
                outcome: if response_succeeded(&body) {
                    super::telemetry::TelemetryOutcome::Succeeded
                } else {
                    super::telemetry::TelemetryOutcome::Rejected
                },
                error_class: (!response_succeeded(&body))
                    .then_some(super::telemetry::TelemetryErrorClass::ExecutionError),
                counts: super::telemetry::TelemetryCounts {
                    attempt_bucket: super::telemetry::attempt_bucket(1),
                    dispatch_count_bucket: super::telemetry::dispatch_bucket(1),
                    ..super::telemetry::TelemetryCounts::default()
                },
                latency_bucket: super::telemetry::latency_bucket(elapsed_ms(started)),
                sizes: super::telemetry::TelemetrySizes {
                    result_bytes: super::telemetry::size_bucket(
                        serde_json::to_vec(&body)
                            .map(|bytes| bytes.len())
                            .unwrap_or(0),
                    ),
                    ..super::telemetry::TelemetrySizes::default()
                },
                ..super::telemetry::EventSpec::default()
            });
        }
        let completed = response_succeeded(&body);
        let source_dispatch_count = 1;
        self.trace.record(json!({
            "schema":TRACE_SCHEMA,
            "request_id":self.trace.next_request_id(),
            "kind":"write_plan_executed",
            "mode":"execute",
            "executor":contract.executor,
            "operation":contract.operation,
            "plan_id":plan_id,
            "source_tool":contract.source_tool,
            "contract_digest":contract.digest,
            "manifest_sha256":self.manifest_digest,
            "server_version":server_version(),
            "source_dispatch_count":source_dispatch_count,
            "completed":completed,
            "elapsed_ms":elapsed_ms(started),
        }));
        body
    }

    fn replay_write_plan(
        &self,
        id: Value,
        plan: &WritePlan,
        mut result: Value,
        source_dispatch_count: u64,
        telemetry_request: Option<&super::telemetry::TelemetryRequest>,
        started: Instant,
    ) -> Value {
        result["_meta"]["nativeWritePlanReplay"] = json!({
            "planId":plan.id,
            "idempotentReplay":true,
            "sourceDispatchCount":source_dispatch_count,
        });
        let body = json!({"jsonrpc":"2.0","id":id,"result":result});
        if let (Some(telemetry), Some(request)) = (&self.telemetry, telemetry_request) {
            telemetry.emit(super::telemetry::EventSpec {
                request: Some(request.clone()),
                phase: super::telemetry::TelemetryPhase::ReplayReturned,
                outcome: super::telemetry::TelemetryOutcome::Replayed,
                flags: super::telemetry::TelemetryFlags {
                    replayed: true,
                    duplicate_effect_attempt: true,
                    ..super::telemetry::TelemetryFlags::default()
                },
                counts: super::telemetry::TelemetryCounts {
                    attempt_bucket: super::telemetry::attempt_bucket(1),
                    dispatch_count_bucket: super::telemetry::dispatch_bucket(source_dispatch_count),
                    ..super::telemetry::TelemetryCounts::default()
                },
                latency_bucket: super::telemetry::latency_bucket(elapsed_ms(started)),
                sizes: super::telemetry::TelemetrySizes {
                    result_bytes: super::telemetry::size_bucket(
                        serde_json::to_vec(&body)
                            .map(|bytes| bytes.len())
                            .unwrap_or(0),
                    ),
                    ..super::telemetry::TelemetrySizes::default()
                },
                ..super::telemetry::EventSpec::default()
            });
        }
        self.trace.record(json!({
            "schema":TRACE_SCHEMA,
            "request_id":self.trace.next_request_id(),
            "kind":"write_plan_replayed",
            "mode":"execute",
            "executor":plan.executor,
            "operation":plan.operation,
            "plan_id":plan.id,
            "source_dispatch_count":source_dispatch_count,
            "completed":true,
            "elapsed_ms":elapsed_ms(started),
        }));
        body
    }

    async fn write_revalidation_error_or_advanced(
        &self,
        context: RevalidationContext<'_>,
        revalidation_error: PlanError<'_>,
    ) -> Value {
        let RevalidationContext {
            id,
            modern,
            contract,
            envelope,
            plan_id,
            initially_loaded,
            plan,
            telemetry_request,
            started,
        } = context;
        let reloaded = match self.write_runtime.store.load(plan_id, now_ms()).await {
            Ok(Some(reloaded)) => reloaded,
            Ok(None) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        contract,
                        envelope,
                        telemetry_request,
                        PlanError::new(
                            "plan_not_found",
                            "write plan disappeared during source revalidation",
                            false,
                        ),
                    )
                    .await;
            }
            Err(error) => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        contract,
                        envelope,
                        telemetry_request,
                        PlanError::new("plan_store_unavailable", &error.to_string(), false),
                    )
                    .await;
            }
        };
        if reloaded.payload != initially_loaded.payload
            || reloaded.key_id != initially_loaded.key_id
            || reloaded.expires_at_ms != initially_loaded.expires_at_ms
        {
            return self
                .write_plan_error(
                    id,
                    modern,
                    contract,
                    envelope,
                    telemetry_request,
                    PlanError::new(
                        "plan_integrity_failed",
                        "durable plan row changed during source revalidation",
                        false,
                    ),
                )
                .await;
        }
        match reloaded.state {
            StoredState::Completed {
                result,
                source_dispatch_count,
            } => self.replay_write_plan(
                id,
                plan,
                result,
                source_dispatch_count,
                telemetry_request,
                started,
            ),
            StoredState::Executing { started_at_ms, .. }
            | StoredState::Indeterminate { started_at_ms, .. } => {
                let diagnostic = format!(
                    "write plan entered source execution at {} but no terminal result was durably cached; verify target state before preparing any replacement plan",
                    rfc3339_millis(started_at_ms)
                );
                self.write_plan_error(
                    id,
                    modern,
                    contract,
                    envelope,
                    telemetry_request,
                    PlanError::indeterminate(&diagnostic),
                )
                .await
            }
            StoredState::Expired => {
                self.write_plan_error(
                    id,
                    modern,
                    contract,
                    envelope,
                    telemetry_request,
                    PlanError::new(
                        "plan_expired",
                        "write plan expired during source revalidation; prepare the current effect again",
                        false,
                    ),
                )
                .await
            }
            StoredState::Prepared => {
                self.write_plan_error(
                    id,
                    modern,
                    contract,
                    envelope,
                    telemetry_request,
                    revalidation_error,
                )
                .await
            }
        }
    }

    async fn write_plan_error(
        &self,
        id: Value,
        modern: bool,
        contract: &OperationContract,
        arguments: &Value,
        telemetry_request: Option<&super::telemetry::TelemetryRequest>,
        error: PlanError<'_>,
    ) -> Value {
        let PlanError {
            code,
            diagnostic,
            include_contract_repair,
            continuation,
            source_dispatch_count,
        } = error;
        let body = self
            .fixture_error_response(
                id,
                modern,
                &contract.executor,
                &contract.operation,
                diagnostic,
                include_contract_repair.then_some(contract),
                arguments,
                code,
                None,
                false,
            )
            .await;
        let body = with_plan_error(
            body,
            code,
            continuation.unwrap_or_else(|| {
                if include_contract_repair {
                    describe_then_prepare_continuation(contract)
                } else {
                    json!({
                        "action":"prepare_again_if_still_authorized",
                        "retry_ready":false,
                    })
                }
            }),
        );
        if code != "plan_preparation_unavailable" {
            if let (Some(telemetry), Some(request)) = (&self.telemetry, telemetry_request) {
                let (phase, outcome, error_class, stale_plan) = match code {
                    "plan_expired" => (
                        super::telemetry::TelemetryPhase::PlanRevalidated,
                        super::telemetry::TelemetryOutcome::Rejected,
                        super::telemetry::TelemetryErrorClass::PlanExpired,
                        false,
                    ),
                    "plan_stale" => (
                        super::telemetry::TelemetryPhase::PlanRevalidated,
                        super::telemetry::TelemetryOutcome::Rejected,
                        super::telemetry::TelemetryErrorClass::PlanStale,
                        true,
                    ),
                    "plan_store_conflict" | "visible_effect_mismatch" => (
                        super::telemetry::TelemetryPhase::PlanRevalidated,
                        super::telemetry::TelemetryOutcome::Rejected,
                        super::telemetry::TelemetryErrorClass::PlanConflict,
                        false,
                    ),
                    "plan_execution_indeterminate" => (
                        super::telemetry::TelemetryPhase::DispatchCompleted,
                        super::telemetry::TelemetryOutcome::Indeterminate,
                        super::telemetry::TelemetryErrorClass::PlanIndeterminate,
                        false,
                    ),
                    "preparation_validation_failed" | "contract_drift" => (
                        super::telemetry::TelemetryPhase::ValidationCompleted,
                        super::telemetry::TelemetryOutcome::Rejected,
                        super::telemetry::TelemetryErrorClass::SchemaValidation,
                        false,
                    ),
                    "preparation_rejected" => (
                        super::telemetry::TelemetryPhase::ValidationCompleted,
                        super::telemetry::TelemetryOutcome::Rejected,
                        super::telemetry::TelemetryErrorClass::RuntimeValidation,
                        false,
                    ),
                    _ => (
                        super::telemetry::TelemetryPhase::ValidationCompleted,
                        super::telemetry::TelemetryOutcome::Rejected,
                        super::telemetry::TelemetryErrorClass::Internal,
                        false,
                    ),
                };
                let flags = super::telemetry::TelemetryFlags {
                    repair_returned: include_contract_repair,
                    stale_plan,
                    duplicate_effect_attempt: false,
                    ..super::telemetry::TelemetryFlags::default()
                };
                let counts = super::telemetry::TelemetryCounts {
                    attempt_bucket: super::telemetry::attempt_bucket(1),
                    dispatch_count_bucket: super::telemetry::dispatch_bucket(source_dispatch_count),
                    repair_count_bucket: super::telemetry::repair_bucket(u64::from(
                        include_contract_repair,
                    )),
                    ..super::telemetry::TelemetryCounts::default()
                };
                let sizes = super::telemetry::TelemetrySizes {
                    request_bytes: super::telemetry::size_bucket(
                        serde_json::to_vec(arguments)
                            .map(|bytes| bytes.len())
                            .unwrap_or(0),
                    ),
                    result_bytes: super::telemetry::size_bucket(
                        serde_json::to_vec(&body)
                            .map(|bytes| bytes.len())
                            .unwrap_or(0),
                    ),
                    contract_bytes: super::telemetry::size_bucket(contract.bytes),
                };
                telemetry.emit(super::telemetry::EventSpec {
                    request: Some(request.clone()),
                    phase,
                    outcome,
                    error_class: Some(error_class),
                    flags,
                    counts,
                    sizes,
                    ..super::telemetry::EventSpec::default()
                });
                if include_contract_repair {
                    telemetry.emit(super::telemetry::EventSpec {
                        request: Some(request.clone()),
                        phase: super::telemetry::TelemetryPhase::RepairReturned,
                        outcome: super::telemetry::TelemetryOutcome::Repaired,
                        error_class: Some(error_class),
                        flags,
                        counts,
                        sizes,
                        ..super::telemetry::EventSpec::default()
                    });
                }
            }
        }
        body
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    use crate::db::{create_database, open_database_at};
    use crate::mcp::{register_builtin_tools, register_surface_tools, DEPLOYMENT_READ_ONLY_ERROR};
    use crate::store::{create_record, update_record};
    use sqlx::Row;
    use std::sync::Mutex;

    const EXECUTOR: &str = ACCESS_EXECUTOR;
    const OPERATION: &str = POLICY_REPLACE_OPERATION;

    /// Pinned fixture record ids whose *text* an assertion reads back.
    ///
    /// `PLAN_ONCE_ID` is asserted absent from serialized telemetry, and the
    /// other two are the expected `record_id` of an emitted event, so each
    /// must be one literal used in both the fixture and its assertion.
    const PLAN_ONCE_ID: &str = "ec00b000-0000-4000-8000-000000000024";
    const PLAN_DELETE_ID: &str = "ec00b000-0000-4000-8000-000000000025";
    const PLAN_CITATION_ID: &str = "ec00b000-0000-4000-8000-000000000026";

    struct FakeHostedExecutorAuthority {
        pool: sqlx::SqlitePool,
        validated: Mutex<Vec<Value>>,
        prepared: Mutex<Vec<Value>>,
    }

    impl HostedPlanCatalogue for FakeHostedExecutorAuthority {
        fn executor_plan_pool(&self) -> &sqlx::SqlitePool {
            &self.pool
        }
    }

    impl HostedExecutorAuthority for FakeHostedExecutorAuthority {
        fn validate_membership_write(&self, arguments: Value) -> Result<()> {
            self.validated.lock().unwrap().push(arguments);
            Ok(())
        }

        fn prepare_membership_write<'a>(
            &'a self,
            _db: &'a crate::db::Db,
            _caller: &'a Caller,
            arguments: Value,
        ) -> BoxFuture<'a, Result<HostedMembershipPreparation>> {
            self.prepared.lock().unwrap().push(arguments.clone());
            Box::pin(async move {
                Ok(HostedMembershipPreparation {
                    canonical_source_arguments: arguments,
                    target_id: "invitation-target".into(),
                    target: "Invitation target".into(),
                    state_revision: "catalogue-revision".into(),
                    target_state_digest: "target-digest".into(),
                    effect_summary: "Create one invitation".into(),
                    effect: json!({"changed":true}),
                    operation_evidence: json!({"source":"fake-authority"}),
                    catalogue_snapshot: json!({"generation":7}),
                })
            })
        }
    }

    fn registry() -> Arc<ToolRegistry> {
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        Arc::new(registry)
    }

    fn call_message(id: u64, arguments: Value) -> Value {
        executor_call_message(id, EXECUTOR, arguments)
    }

    fn executor_call_message(id: u64, executor: &str, arguments: Value) -> Value {
        json!({
            "jsonrpc":"2.0",
            "id":id,
            "method":"tools/call",
            "params":{"name":executor,"arguments":arguments}
        })
    }

    async fn policy_revision(
        registry: &ToolRegistry,
        db: &crate::Db,
        caller: Caller,
        target: &str,
    ) -> String {
        registry
            .call(
                db.clone(),
                caller,
                "manage_record_policy",
                json!({"action":"list","record_id":target}),
            )
            .await
            .unwrap()["policy_revision"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn preparation_arguments(target: &str, revision: &str) -> Value {
        json!({
            "operation":OPERATION,
            "arguments":{
                "record_id":target,
                "entries":[{"subject":{"kind":"members"},"capability":"view"}],
                "if_policy_revision":revision,
                "reason":"Exercise the plan-backed policy replacement fixture"
            }
        })
    }

    fn execution_arguments(prepared: &Value) -> Value {
        execution_arguments_for(OPERATION, prepared)
    }

    fn execution_arguments_for(operation: &str, prepared: &Value) -> Value {
        let plan = &prepared["result"]["structuredContent"];
        json!({
            "operation":operation,
            "plan_id":plan["plan_id"],
            "target":plan["target"],
            "effect_summary":plan["effect_summary"],
        })
    }

    async fn policy_event_count(db: &crate::Db) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn type_correction_event_count(db: &crate::Db, record_id: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='record.type_corrected.v1'",
        )
        .bind(record_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
    }

    async fn binding_audit_count(db: &crate::Db) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM binding_audit")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn meta_event_count(db: &crate::Db) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    async fn prepare_and_execute_schema_plan(
        server: &ExecutorPrototypeStdioServer,
        db: &crate::Db,
        id: u64,
        executor: &str,
        operation: &str,
        arguments: Value,
    ) -> Value {
        let events_before = meta_event_count(db).await;
        let prepared = server
            .handle_message(executor_call_message(
                id,
                executor,
                json!({"operation":operation,"arguments":arguments}),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        assert_eq!(
            prepared["result"]["structuredContent"]["preparation_mutated"],
            false
        );
        assert_eq!(
            prepared["result"]["structuredContent"]["effect"]["changed"], true,
            "{prepared}"
        );
        assert_eq!(meta_event_count(db).await, events_before);

        let execute = execution_arguments_for(operation, &prepared);
        let first = server
            .handle_message(executor_call_message(id + 1, executor, execute.clone()))
            .await
            .unwrap();
        assert!(response_succeeded(&first), "{first}");
        assert_eq!(meta_event_count(db).await, events_before + 1);
        let replay = server
            .handle_message(executor_call_message(id + 2, executor, execute))
            .await
            .unwrap();
        assert!(response_succeeded(&replay), "{replay}");
        assert_eq!(meta_event_count(db).await, events_before + 1);
        prepared
    }

    async fn binding_owner(db: &crate::Db, identifier: &str) -> Option<(String, bool)> {
        sqlx::query_as::<_, (String, i64)>(
            "SELECT record_id,is_canonical FROM bindings WHERE system='native-principal' AND identifier=?",
        )
        .bind(identifier)
        .fetch_optional(db.pool())
        .await
        .unwrap()
        .map(|(record_id, canonical)| (record_id, canonical != 0))
    }

    async fn grant_local_binding_manage(db: &crate::Db, record_ids: &[&str]) {
        for record_id in record_ids {
            replace_explicit_policy(
                db,
                &format!("test:grant-local-binding-manage:{record_id}"),
                record_id,
                vec![AllowEntry::account("local", Capability::Manage)],
            )
            .await
            .unwrap();
        }
    }

    #[test]
    fn access_source_owned_fences_cannot_be_supplied_by_executor_callers() {
        for (field, value) in [
            ("if_content_seq", json!(7)),
            ("if_schema_state_revision", json!("forged-schema")),
            ("if_dependency_digest", json!("forged-dependencies")),
            ("mode", json!("autonomous")),
            ("confirmation_required", json!(false)),
            ("plan_id", json!("forged-plan")),
            ("effect_digest", json!("0".repeat(64))),
        ] {
            let mut arguments = json!({
                "record_id":"r",
                "target_type":"Resolution",
                "target_kind":"decision",
                "reason":"crafted hidden field",
            });
            arguments[field] = value;
            let correction = canonical_source_arguments(
                RECORDS_WRITE_EXECUTOR,
                CORRECT_RECORD_TYPE_OPERATION,
                arguments,
            )
            .expect_err("record correction plan evidence is executor-owned")
            .to_string();
            assert!(correction.contains("executor-owned"), "{correction}");
        }

        let policy = canonical_source_arguments(
            ACCESS_EXECUTOR,
            POLICY_GRANT_OPERATION,
            json!({
                "record_id":"r",
                "subject":{"kind":"person","person_record_id":"p","if_account_id":"acct"},
                "capability":"view",
                "reason":"crafted hidden field",
            }),
        )
        .expect_err("person binding fence is source-owned")
        .to_string();
        assert!(policy.contains("source-owned"), "{policy}");

        for (field, value) in [
            ("if_policy_revision", json!("forged-policy-revision")),
            ("if_content_seq", json!(7)),
            ("if_account_id", json!("acct:forged-binding")),
        ] {
            let mut item = json!({
                "record_id":"r",
                "subject":{"kind":"account","account_id":"acct"},
                "capability":"view",
            });
            if field == "if_account_id" {
                item["subject"][field] = value;
            } else {
                item[field] = value;
            }
            let policy = canonical_source_arguments(
                ACCESS_EXECUTOR,
                POLICY_SET_MANY_OPERATION,
                json!({
                    "items":[item],
                    "reason":"crafted hidden batch field",
                }),
            )
            .expect_err("set_many preparation fences are source-owned")
            .to_string();
            assert!(policy.contains("source-owned"), "{policy}");
        }

        let policy = canonical_source_arguments(
            ACCESS_EXECUTOR,
            POLICY_GRANT_OPERATION,
            json!({
                "record_id":"r",
                "subject":{"kind":"account","account_id":"acct"},
                "capability":"view",
                "if_content_seq":7,
                "reason":"crafted hidden field",
            }),
        )
        .expect_err("content fence is source-owned")
        .to_string();
        assert!(policy.contains("source-owned"), "{policy}");

        let policy = canonical_source_arguments(
            ACCESS_EXECUTOR,
            POLICY_RESTORE_OPERATION,
            json!({
                "record_id":"r",
                "if_policy_revision":"visible-caller-cas",
                "if_inherited_policy_revision":"crafted-hidden-parent-cas",
                "reason":"crafted hidden field",
            }),
        )
        .expect_err("inherited policy fence is source-owned")
        .to_string();
        assert!(policy.contains("source-owned"), "{policy}");

        let artifact = canonical_source_arguments(
            ACCESS_EXECUTOR,
            ARTIFACT_GRANT_OPERATION,
            json!({"artifact_id":"a","if_previous_seq":7}),
        )
        .expect_err("artifact revision is source-owned")
        .to_string();
        assert!(artifact.contains("source-owned"), "{artifact}");
    }

    /// The complete classification table, written out independently of the
    /// constants it is built from. A future edit to `PLAN_POLICY_TABLE` has to
    /// update this list, in the same order, with the literal executor and
    /// operation names the wire actually carries.
    /// Every classified operation must actually be routable.
    ///
    /// `canonical_source_arguments` and `validate` are exhaustive matches with
    /// fail-closed default arms, and they run *before* the arm that dispatches
    /// to a preparer. An operation classified plan-required but missing from
    /// either one is not merely unprepared: because `requires_plan` sends it
    /// down the plan path, it becomes unreachable in both modes, so adding the
    /// classification silently removes the operation from the facade. This
    /// pins the whole table rather than one row, because the next operation
    /// added will meet the same three-place requirement.
    #[test]
    fn every_supported_plan_operation_has_a_source_argument_and_preparation_route() {
        for (executor, operation, policy) in PLAN_POLICY_TABLE {
            if *policy != PlanPolicy::RequiredSupported {
                continue;
            }
            // Schema executors return from `prepare_operation` before the
            // generic routing, so they legitimately have no row in either
            // match. Everything else flows through both.
            if matches!(*executor, SCHEMA_ADMIN_EXECUTOR | SCHEMA_DELETE_EXECUTOR) {
                continue;
            }
            let routed = canonical_source_arguments(executor, operation, json!({}));
            if let Err(error) = &routed {
                assert!(
                    !error.to_string().contains("no exact source-argument route"),
                    "{executor}.{operation} is classified plan-required but has no source-argument route, so the facade cannot reach it at all"
                );
            }
            let prepared = validate(executor, operation, json!({}), None);
            if let Err(error) = &prepared {
                assert!(
                    !error.to_string().contains("no exact write preparation route"),
                    "{executor}.{operation} is classified plan-required but has no preparation route"
                );
            }
        }
    }

    #[test]
    fn plan_policy_table_is_frozen() {
        let expected: &[(&str, &str, PlanPolicy)] = &[
            (
                "access_admin",
                "manage_record_policy.grant",
                PlanPolicy::RequiredSupported,
            ),
            (
                "access_admin",
                "manage_record_policy.replace",
                PlanPolicy::RequiredSupported,
            ),
            (
                "access_admin",
                "manage_record_policy.restore_inheritance",
                PlanPolicy::RequiredSupported,
            ),
            (
                "access_admin",
                "manage_record_policy.revoke",
                PlanPolicy::RequiredSupported,
            ),
            (
                "access_admin",
                "manage_record_policy.set_members_baseline",
                PlanPolicy::RequiredSupported,
            ),
            (
                "access_admin",
                "manage_record_policy.set_many",
                PlanPolicy::RequiredSupported,
            ),
            (
                "access_admin",
                "manage_artifact_module_grants.grant",
                PlanPolicy::RequiredSupported,
            ),
            (
                "access_admin",
                "manage_artifact_module_grants.revoke",
                PlanPolicy::RequiredSupported,
            ),
            (
                "identity_admin",
                "manage_bindings.add",
                PlanPolicy::RequiredSupported,
            ),
            (
                "identity_admin",
                "manage_bindings.canonicalize",
                PlanPolicy::RequiredSupported,
            ),
            (
                "identity_admin",
                "manage_bindings.reconcile",
                PlanPolicy::RequiredSupported,
            ),
            (
                "identity_admin",
                "manage_bindings.remove",
                PlanPolicy::RequiredSupported,
            ),
            (
                "records_write",
                "correct_record_type",
                PlanPolicy::RequiredSupported,
            ),
            (
                "records_delete",
                "delete_record",
                PlanPolicy::RequiredSupported,
            ),
            (
                "records_delete",
                "manage_attachments.detach",
                PlanPolicy::RequiredSupported,
            ),
            (
                "records_delete",
                "manage_citations.remove",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_admin",
                "manage_vocabularies.alias_value",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_admin",
                "manage_vocabularies.create_vocabulary",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_admin",
                "manage_vocabularies.deprecate_value",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_admin",
                "manage_vocabularies.promote_value",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_admin",
                "manage_vocabularies.propose_value",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_admin",
                "manage_vocabularies.reorder_value",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_admin",
                "manage_vocabularies.set_gloss",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_admin",
                "manage_vocabularies.set_metadata",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_admin",
                "manage_schema_config.write",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_delete",
                "manage_vocabularies.delete_value",
                PlanPolicy::RequiredSupported,
            ),
            (
                "schema_delete",
                "manage_vocabularies.delete_vocabulary",
                PlanPolicy::RequiredSupported,
            ),
            (
                "membership_admin",
                "manage_memberships.invitations_create",
                PlanPolicy::RequiredSupported,
            ),
            (
                "membership_admin",
                "manage_memberships.invitations_copy_link",
                PlanPolicy::RequiredSupported,
            ),
            (
                "membership_admin",
                "manage_memberships.invitations_send",
                PlanPolicy::RequiredSupported,
            ),
            (
                "membership_admin",
                "manage_memberships.invitations_revoke",
                PlanPolicy::RequiredSupported,
            ),
            (
                "membership_admin",
                "manage_memberships.set_role",
                PlanPolicy::RequiredUnavailable,
            ),
            (
                "membership_remove",
                "manage_memberships.remove",
                PlanPolicy::RequiredUnavailable,
            ),
            (
                "canvas_write",
                "manage_canvas.promote",
                PlanPolicy::RequiredSupported,
            ),
        ];
        assert_eq!(PLAN_POLICY_TABLE, expected);
        assert_eq!(PLAN_POLICY_TABLE.len(), 34);
        assert_eq!(
            PLAN_POLICY_TABLE
                .iter()
                .filter(|(_, _, policy)| *policy == PlanPolicy::RequiredSupported)
                .count(),
            32
        );
        assert_eq!(
            PLAN_POLICY_TABLE
                .iter()
                .filter(|(_, _, policy)| *policy == PlanPolicy::RequiredUnavailable)
                .count(),
            2
        );
        for (executor, operation, policy) in PLAN_POLICY_TABLE {
            assert_eq!(plan_policy(executor, operation), *policy);
            assert!(requires_plan(executor, operation));
            assert_eq!(
                supports(executor, operation),
                *policy == PlanPolicy::RequiredSupported
            );
            assert_eq!(
                advertisable(executor, operation),
                *policy != PlanPolicy::RequiredUnavailable
            );
        }
    }

    /// A pair may be classified once and only once, so the supported and
    /// unavailable sets cannot overlap and no row can be shadowed by an
    /// earlier one.
    #[test]
    fn plan_policy_table_rows_are_unique_and_disjoint() {
        let mut seen = std::collections::BTreeMap::new();
        for (executor, operation, policy) in PLAN_POLICY_TABLE {
            if let Some(previous) = seen.insert((*executor, *operation), *policy) {
                panic!("{executor}.{operation} is classified twice: {previous:?} then {policy:?}");
            }
        }
        assert_eq!(seen.len(), PLAN_POLICY_TABLE.len());
        let supported = PLAN_POLICY_TABLE
            .iter()
            .filter(|(_, _, policy)| *policy == PlanPolicy::RequiredSupported)
            .map(|(executor, operation, _)| (*executor, *operation))
            .collect::<std::collections::BTreeSet<_>>();
        let unavailable = PLAN_POLICY_TABLE
            .iter()
            .filter(|(_, _, policy)| *policy == PlanPolicy::RequiredUnavailable)
            .map(|(executor, operation, _)| (*executor, *operation))
            .collect::<std::collections::BTreeSet<_>>();
        assert!(
            supported.is_disjoint(&unavailable),
            "overlap: {:?}",
            supported.intersection(&unavailable).collect::<Vec<_>>()
        );
        assert!(
            !PLAN_POLICY_TABLE
                .iter()
                .any(|(_, _, policy)| *policy == PlanPolicy::Direct),
            "Direct is the absence of a row, never a row"
        );
    }

    /// Nothing outside the table requires a plan, including near misses that
    /// share an executor or an operation name with a classified row.
    #[test]
    fn unclassified_pairs_are_direct() {
        for (executor, operation) in [
            ("records_write", "update_record"),
            ("records_write", "delete_record"),
            ("records_lifecycle", "archive_record"),
            ("records_delete", "correct_record_type"),
            ("schema_admin", "manage_vocabularies.delete_value"),
            ("schema_delete", "manage_vocabularies.alias_value"),
            ("membership_admin", "manage_memberships.remove"),
            ("membership_remove", "manage_memberships.set_role"),
            ("access_admin", "manage_bindings.add"),
            ("identity_admin", "manage_record_policy.grant"),
            ("", ""),
        ] {
            assert_eq!(
                plan_policy(executor, operation),
                PlanPolicy::Direct,
                "{executor}.{operation}"
            );
            assert!(!requires_plan(executor, operation));
            assert!(!supports(executor, operation));
            assert!(advertisable(executor, operation));
        }
    }

    #[test]
    fn initial_high_risk_classification_is_exact_and_fail_closed() {
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let classified = audit
            .audit_rows
            .iter()
            .filter(|row| {
                row.stability == "stable"
                    && requires_plan(&row.candidate_executor, &row.candidate_operation)
            })
            .map(|row| {
                (
                    row.candidate_executor.as_str(),
                    row.candidate_operation.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(classified.len(), 34);
        assert_eq!(
            classified
                .iter()
                .filter(|(executor, operation)| supports(executor, operation))
                .count(),
            32
        );
        assert!(supports(EXECUTOR, OPERATION));
        for operation in [
            POLICY_GRANT_OPERATION,
            POLICY_SET_MANY_OPERATION,
            POLICY_REPLACE_OPERATION,
            POLICY_RESTORE_OPERATION,
            POLICY_REVOKE_OPERATION,
            POLICY_BASELINE_OPERATION,
            ARTIFACT_GRANT_OPERATION,
            ARTIFACT_REVOKE_OPERATION,
        ] {
            assert!(supports(ACCESS_EXECUTOR, operation));
            assert!(advertisable(ACCESS_EXECUTOR, operation));
        }
        for operation in [
            IDENTITY_ADD_OPERATION,
            IDENTITY_CANONICALIZE_OPERATION,
            IDENTITY_RECONCILE_OPERATION,
            IDENTITY_REMOVE_OPERATION,
        ] {
            assert!(supports(IDENTITY_EXECUTOR, operation));
            assert!(advertisable(IDENTITY_EXECUTOR, operation));
        }
        for operation in [
            DELETE_RECORD_OPERATION,
            DETACH_ATTACHMENT_OPERATION,
            REMOVE_CITATION_OPERATION,
        ] {
            assert!(supports(RECORDS_DELETE_EXECUTOR, operation));
            assert!(advertisable(RECORDS_DELETE_EXECUTOR, operation));
        }
        for (executor, operation) in [
            (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_ALIAS_OPERATION),
            (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_CREATE_OPERATION),
            (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_DEPRECATE_OPERATION),
            (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_PROMOTE_OPERATION),
            (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_PROPOSE_OPERATION),
            (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_REORDER_OPERATION),
            (SCHEMA_ADMIN_EXECUTOR, VOCABULARY_METADATA_OPERATION),
            (SCHEMA_ADMIN_EXECUTOR, SCHEMA_CONFIG_WRITE_OPERATION),
            (SCHEMA_DELETE_EXECUTOR, VOCABULARY_DELETE_VALUE_OPERATION),
            (SCHEMA_DELETE_EXECUTOR, VOCABULARY_DELETE_OPERATION),
        ] {
            assert!(supports(executor, operation));
            assert!(advertisable(executor, operation));
        }
        for operation in [
            MEMBERSHIP_CREATE_INVITATION_OPERATION,
            MEMBERSHIP_COPY_INVITATION_LINK_OPERATION,
            MEMBERSHIP_SEND_INVITATION_OPERATION,
            MEMBERSHIP_REVOKE_INVITATION_OPERATION,
        ] {
            assert_eq!(
                plan_policy(MEMBERSHIP_EXECUTOR, operation),
                PlanPolicy::RequiredSupported
            );
            assert!(supports(MEMBERSHIP_EXECUTOR, operation));
            assert!(advertisable(MEMBERSHIP_EXECUTOR, operation));
        }
        assert!(!advertisable(
            "membership_remove",
            "manage_memberships.remove"
        ));
        assert_eq!(
            plan_policy("records_write", "update_record"),
            PlanPolicy::Direct
        );
        assert_eq!(
            plan_policy(RECORDS_WRITE_EXECUTOR, CORRECT_RECORD_TYPE_OPERATION),
            PlanPolicy::RequiredSupported
        );
        assert!(supports(
            RECORDS_WRITE_EXECUTOR,
            CORRECT_RECORD_TYPE_OPERATION
        ));
        assert!(advertisable(
            RECORDS_WRITE_EXECUTOR,
            CORRECT_RECORD_TYPE_OPERATION
        ));
        assert_eq!(
            plan_policy("records_lifecycle", "archive_record"),
            PlanPolicy::Direct
        );
        assert!(advertisable("records_write", "update_record"));
    }

    #[tokio::test]
    async fn classified_operations_without_truthful_preparers_are_withheld() {
        let db = create_database(":memory:").await.unwrap();
        let server = ExecutorPrototypeStdioServer::new(registry(), db, Caller::local(), None)
            .await
            .unwrap();
        assert!(!server.contracts.contains_key(&(
            "membership_remove".into(),
            "manage_memberships.remove".into()
        )));
        assert!(!server
            .operations_by_executor
            .contains_key("membership_remove"));
        let rejected = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/call",
                "params":{
                    "name":"membership_remove",
                    "arguments":{
                        "operation":"manage_memberships.remove",
                        "arguments":{"account_id":"never-dispatched","reason":"prove fail-closed classification"}
                    }
                }
            }))
            .await
            .unwrap();
        assert!(rejected["result"]["structuredContent"]["plan_error"].is_null());
        assert!(rejected["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("selection_error"));
        assert!(!server.trace_events().iter().any(|event| matches!(
            event["kind"].as_str(),
            Some("write_plan_prepared" | "write_plan_executed")
        )));
    }

    #[tokio::test]
    async fn membership_preparation_uses_only_the_composite_hosted_authority() {
        let db = create_database(":memory:").await.unwrap();
        let authority = FakeHostedExecutorAuthority {
            pool: db.pool().clone(),
            validated: Mutex::new(Vec::new()),
            prepared: Mutex::new(Vec::new()),
        };
        let arguments = json!({
            "email":"member@example.test",
            "role":"member",
            "expires_at":null,
            "idempotency_key":"authority-seam",
            "reason":"prove package-safe delegation",
        });
        let canonical = canonical_source_arguments(
            MEMBERSHIP_EXECUTOR,
            MEMBERSHIP_CREATE_INVITATION_OPERATION,
            arguments.clone(),
        )
        .unwrap();

        let absent = validate(
            MEMBERSHIP_EXECUTOR,
            MEMBERSHIP_CREATE_INVITATION_OPERATION,
            arguments.clone(),
            None,
        )
        .unwrap_err();
        assert!(absent
            .to_string()
            .contains("authoritative catalogue context"));
        validate(
            MEMBERSHIP_EXECUTOR,
            MEMBERSHIP_CREATE_INVITATION_OPERATION,
            arguments.clone(),
            Some(&authority),
        )
        .unwrap();
        let prepared = prepare_operation(
            &EngineHandle::Sqlite(db),
            &Caller::authenticated("actor").with_hosting_context("user-1", "database-1"),
            Some(&authority),
            MEMBERSHIP_EXECUTOR,
            MEMBERSHIP_CREATE_INVITATION_OPERATION,
            arguments,
        )
        .await
        .unwrap();

        assert_eq!(
            *authority.validated.lock().unwrap(),
            vec![canonical.clone()]
        );
        assert_eq!(*authority.prepared.lock().unwrap(), vec![canonical.clone()]);
        assert_eq!(prepared.canonical_source_arguments, canonical);
        assert_eq!(
            prepared.revalidation_arguments,
            prepared.canonical_source_arguments
        );
        assert_eq!(prepared.state_revision, "catalogue-revision");
        assert_eq!(prepared.target_state_digest, "target-digest");
        assert_eq!(
            prepared.operation_evidence,
            json!({
                "kind":"membership_invitation_create",
                "catalogue_snapshot":{"generation":7},
                "source_evidence":{"source":"fake-authority"},
            })
        );
    }

    #[tokio::test]
    async fn integrity_and_identity_bind_every_security_dimension() {
        let db = create_database(":memory:").await.unwrap();
        let store = PlanStore::open_for_database(db.path()).await.unwrap();
        let runtime = WriteRuntime::new(store);
        let mut base = WritePlan {
            id: "wpl1:test".into(),
            binding: CallerBinding {
                actor: "actor-a".into(),
                principal: "principal-a".into(),
                workspace: "workspace-a".into(),
                database: "database-a".into(),
            },
            executor: EXECUTOR.into(),
            operation: OPERATION.into(),
            source_tool: "manage_record_policy".into(),
            operation_arguments: json!({"record_id":"r"}),
            arguments_digest: digest(&json!({"record_id":"r"})).unwrap(),
            revalidation_arguments: json!({"record_id":"r"}),
            revalidation_arguments_digest: digest(&json!({"record_id":"r"})).unwrap(),
            canonical_source_arguments: json!({"action":"replace","record_id":"r"}),
            source_arguments_digest: digest(&json!({"action":"replace","record_id":"r"})).unwrap(),
            target_id: "r".into(),
            target: "Record (r)".into(),
            target_state_digest: "state".into(),
            state_revision: "revision".into(),
            effect: json!({"changed":true}),
            effect_summary: "replace policy".into(),
            operation_evidence: json!({"kind":"test"}),
            effect_digest: digest(&json!({"changed":true})).unwrap(),
            contract_digest: "contract".into(),
            catalogue_digest: "catalogue".into(),
            server_version: server_version(),
            expires_at_ms: now_ms() + 1_000,
            nonce: "server-nonce".into(),
            signing_key_id: String::new(),
            integrity: String::new(),
        };
        base.signing_key_id = runtime.store.active_key_id().await.unwrap();
        let mut signed = base.clone();
        signed.integrity = runtime
            .store
            .seal(&signed.signing_key_id, &integrity_payload(&signed))
            .await
            .unwrap();
        runtime.verify(&signed).await.unwrap();

        for mutate in [
            |plan: &mut WritePlan| plan.id = "wpl1:other".into(),
            |plan: &mut WritePlan| plan.binding.actor = "actor-b".into(),
            |plan: &mut WritePlan| plan.binding.principal = "principal-b".into(),
            |plan: &mut WritePlan| plan.binding.workspace = "workspace-b".into(),
            |plan: &mut WritePlan| plan.binding.database = "database-b".into(),
            |plan: &mut WritePlan| plan.executor = "schema_admin".into(),
            |plan: &mut WritePlan| plan.operation = "other".into(),
            |plan: &mut WritePlan| plan.source_tool = "other".into(),
            |plan: &mut WritePlan| plan.arguments_digest = "tampered".into(),
            |plan: &mut WritePlan| plan.target_id = "other".into(),
            |plan: &mut WritePlan| plan.target = "Other (other)".into(),
            |plan: &mut WritePlan| plan.effect_digest = "tampered".into(),
            |plan: &mut WritePlan| plan.target_state_digest = "tampered".into(),
            |plan: &mut WritePlan| plan.state_revision = "tampered".into(),
            |plan: &mut WritePlan| plan.contract_digest = "tampered".into(),
            |plan: &mut WritePlan| plan.catalogue_digest = "tampered".into(),
            |plan: &mut WritePlan| plan.server_version = "tampered".into(),
            |plan: &mut WritePlan| plan.effect_summary = "tampered".into(),
            |plan: &mut WritePlan| plan.expires_at_ms += 1,
            |plan: &mut WritePlan| plan.nonce = "tampered".into(),
            |plan: &mut WritePlan| plan.operation_arguments["record_id"] = json!("other"),
            |plan: &mut WritePlan| plan.revalidation_arguments["record_id"] = json!("other"),
            |plan: &mut WritePlan| plan.revalidation_arguments_digest = "tampered".into(),
            |plan: &mut WritePlan| plan.canonical_source_arguments["record_id"] = json!("other"),
            |plan: &mut WritePlan| plan.source_arguments_digest = "tampered".into(),
            |plan: &mut WritePlan| plan.operation_evidence["kind"] = json!("tampered"),
            |plan: &mut WritePlan| plan.signing_key_id = "tampered".into(),
            |plan: &mut WritePlan| plan.effect["changed"] = json!(false),
        ] {
            let mut tampered = signed.clone();
            mutate(&mut tampered);
            assert!(runtime.verify(&tampered).await.is_err());
        }
    }

    #[tokio::test]
    async fn preparation_is_non_mutating_repairs_exactly_and_execution_dispatches_once() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":PLAN_ONCE_ID,"type":"Document","kind":"note","name":"Once"}),
        )
        .await
        .unwrap();
        let registry = registry();
        let caller = Caller::local();
        let revision = policy_revision(&registry, &db, caller.clone(), &target).await;
        let telemetry_sink = Arc::new(super::telemetry::TestTelemetrySink::default());
        let telemetry = ExecutorTelemetryContext::new(
            telemetry_sink.clone(),
            super::telemetry::DEFAULT_RETENTION_DAYS,
        )
        .unwrap();
        let server = ExecutorPrototypeStdioServer::new_with_telemetry(
            registry,
            db.clone(),
            caller,
            None,
            telemetry.clone(),
        )
        .await
        .unwrap();
        let events_before = policy_event_count(&db).await;

        let invalid = server
            .handle_message(call_message(
                1,
                json!({
                    "operation":OPERATION,
                    "arguments":{"record_id":target,"entries":[],"if_policy_revision":revision}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(invalid["result"]["isError"], true);
        assert_eq!(
            invalid["result"]["structuredContent"]["plan_error"]["code"],
            "preparation_validation_failed"
        );
        let invalid_repair = &invalid["result"]["structuredContent"]["repair"];
        let contract_schema = &server
            .contracts
            .get(&(EXECUTOR.into(), OPERATION.into()))
            .unwrap()
            .input_schema;
        // Localised failures cite `describe_operation` rather than echoing the
        // contract; only a failure the validator could not localise keeps it.
        if invalid_repair["expected_shape"]["keyword"]
            .as_str()
            .is_some()
        {
            assert!(
                invalid_repair.get("input_schema").is_none(),
                "a localised repair must not echo the full contract: {invalid_repair}"
            );
            assert_eq!(
                invalid_repair["contract_reference"]["arguments"],
                json!({"executor":EXECUTOR,"operation":OPERATION})
            );
            assert_eq!(
                invalid_repair["contract_reference"]["input_schema_pointer"],
                "/result/structuredContent/input_schema"
            );
        } else {
            assert!(invalid_repair.get("contract_reference").is_none());
            assert_eq!(invalid_repair["input_schema"], *contract_schema);
        }
        let invalid_continuation =
            &invalid["result"]["structuredContent"]["plan_error"]["continuation"];
        assert_eq!(invalid_continuation["retry_ready"], false);
        assert_eq!(
            invalid_continuation["describe"]["arguments"],
            json!({"executor":EXECUTOR,"operation":OPERATION})
        );
        assert_eq!(
            invalid_continuation["operation_input_schema_pointer"],
            "/result/structuredContent/input_schema"
        );
        assert!(!invalid.to_string().contains("<object matching"));

        let prepare_required = server
            .handle_message(call_message(100, json!({"operation":OPERATION})))
            .await
            .unwrap();
        let continuation =
            &prepare_required["result"]["structuredContent"]["plan_error"]["continuation"];
        assert_eq!(
            prepare_required["result"]["structuredContent"]["plan_error"]["code"],
            "prepare_required"
        );
        assert_eq!(continuation["retry_ready"], false);
        assert_eq!(continuation["prepare_arguments_pointer"], "/arguments");
        assert!(!prepare_required.to_string().contains("<object matching"));
        assert_eq!(policy_event_count(&db).await, events_before);

        let prepared = server
            .handle_message(call_message(2, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        assert_eq!(prepared["result"]["isError"], false);
        let plan = &prepared["result"]["structuredContent"];
        assert_eq!(plan["preparation_mutated"], false);
        assert_eq!(plan["effect"]["target"]["record_id"], target);
        assert_eq!(plan["effect"]["before"]["mode"], "inherit");
        assert_eq!(plan["effect"]["after"]["mode"], "explicit");
        assert!(plan["effect_summary"].as_str().unwrap().contains("Once"));
        assert_eq!(plan["plan_policy_evidence"].as_array().unwrap().len(), 2);
        assert_eq!(policy_event_count(&db).await, events_before);

        let mut forbidden = execution_arguments(&prepared);
        forbidden["arguments"] = json!({"record_id":target});
        let rejected_raw = server
            .handle_message(call_message(3, forbidden))
            .await
            .unwrap();
        assert_eq!(
            rejected_raw["result"]["structuredContent"]["plan_error"]["code"],
            "raw_arguments_forbidden"
        );
        let mut tampered = execution_arguments(&prepared);
        tampered["effect_summary"] = json!("approve a different effect");
        let rejected_tamper = server
            .handle_message(call_message(4, tampered))
            .await
            .unwrap();
        assert_eq!(
            rejected_tamper["result"]["structuredContent"]["plan_error"]["code"],
            "visible_effect_mismatch"
        );
        let mut unknown_plan = execution_arguments(&prepared);
        unknown_plan["plan_id"] = json!(format!("wpl1:{}", Uuid::new_v4()));
        let rejected_plan = server
            .handle_message(call_message(5, unknown_plan))
            .await
            .unwrap();
        assert_eq!(
            rejected_plan["result"]["structuredContent"]["plan_error"]["code"],
            "plan_not_found"
        );
        assert_eq!(policy_event_count(&db).await, events_before);

        let execute = execution_arguments(&prepared);
        let (first, duplicate) = tokio::join!(
            server.handle_message(call_message(6, execute.clone())),
            server.handle_message(call_message(7, execute))
        );
        let first = first.unwrap();
        let duplicate = duplicate.unwrap();
        assert!(response_succeeded(&first) || response_succeeded(&duplicate));
        if !response_succeeded(&first) {
            assert_eq!(
                first["result"]["structuredContent"]["plan_error"]["code"],
                "plan_execution_indeterminate"
            );
        }
        if !response_succeeded(&duplicate) {
            assert_eq!(
                duplicate["result"]["structuredContent"]["plan_error"]["code"],
                "plan_execution_indeterminate"
            );
        }
        assert_eq!(policy_event_count(&db).await, events_before + 1);
        let listed = server
            .registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_record_policy",
                json!({"action":"list","record_id":target}),
            )
            .await
            .unwrap();
        assert_eq!(listed["mode"], "explicit");
        assert_eq!(listed["entries"].as_array().unwrap().len(), 1);
        assert_eq!(listed["entries"][0]["subject"]["kind"], "members");
        assert_eq!(listed["entries"][0]["capability"], "view");
        assert!(
            !(first["result"]["_meta"]
                .get("nativeWritePlanReplay")
                .is_some()
                && duplicate["result"]["_meta"]
                    .get("nativeWritePlanReplay")
                    .is_some())
        );
        let terminal_replay = server
            .handle_message(call_message(8, execution_arguments(&prepared)))
            .await
            .unwrap();
        assert!(response_succeeded(&terminal_replay));
        assert_eq!(
            terminal_replay["result"]["_meta"]["nativeWritePlanReplay"]["idempotentReplay"],
            true
        );
        assert_eq!(policy_event_count(&db).await, events_before + 1);
        let trace = server.trace_events();
        assert_eq!(
            trace
                .iter()
                .filter(|event| event["kind"] == "write_plan_executed")
                .count(),
            1
        );
        assert!((1..=2).contains(
            &trace
                .iter()
                .filter(|event| event["kind"] == "write_plan_replayed")
                .count()
        ));
        assert_eq!(
            trace
                .iter()
                .find(|event| event["kind"] == "write_plan_executed")
                .unwrap()["source_dispatch_count"],
            1
        );
        telemetry.flush().unwrap();
        let emitted = telemetry_sink
            .events()
            .into_iter()
            .map(|event| serde_json::from_slice::<Value>(&event).unwrap())
            .collect::<Vec<_>>();
        let plan_correlation = emitted
            .iter()
            .find(|event| event["phase"] == "plan_prepared")
            .and_then(|event| event["request"]["plan_correlation"].as_str())
            .expect("the durably prepared plan has a correlation")
            .to_string();
        for phase in [
            "plan_prepared",
            "plan_revalidated",
            "plan_claimed",
            "dispatch_begun",
            "dispatch_completed",
            "plan_completed",
            "replay_returned",
        ] {
            assert!(
                emitted.iter().any(|event| {
                    event["phase"] == phase
                        && event["request"]["plan_correlation"] == plan_correlation
                }),
                "missing authoritative plan telemetry phase {phase}: {emitted:?}"
            );
        }
        assert!(emitted.iter().all(|event| {
            event["schema"] == "native.mcp-executor-telemetry.v1"
                && event["session"]["correlation"]
                    .as_str()
                    .is_some_and(|value| value.starts_with("h1_") && value.len() == 35)
        }));
        assert!(emitted.iter().any(|event| {
            event["phase"] == "replay_returned"
                && event["flags"]["replayed"] == true
                && event["flags"]["duplicate_effect_attempt"] == true
                && event["counts"]["dispatch_count_bucket"] == "1"
        }));
        let rejected_plan_events = emitted
            .iter()
            .filter(|event| {
                event["outcome"] == "rejected"
                    && matches!(
                        event["error_class"].as_str(),
                        Some("plan_conflict" | "internal")
                    )
                    && event["request"]["plan_correlation"] == plan_correlation
            })
            .collect::<Vec<_>>();
        assert!(!rejected_plan_events.is_empty(), "{emitted:?}");
        assert!(rejected_plan_events.iter().all(|event| {
            event["flags"]["duplicate_effect_attempt"] == false
                && emitted.iter().any(|selected| {
                    selected["phase"] == "operation_selected"
                        && selected["request"]["correlation"] == event["request"]["correlation"]
                })
        }));
        let cached_replay = emitted
            .iter()
            .rev()
            .find(|event| event["phase"] == "replay_returned")
            .unwrap();
        assert!(emitted.iter().any(|selected| {
            selected["phase"] == "operation_selected"
                && selected["request"]["correlation"] == cached_replay["request"]["correlation"]
        }));
        let serialized = serde_json::to_string(&emitted).unwrap();
        for raw in [target.as_str(), PLAN_ONCE_ID] {
            assert!(!serialized.contains(raw), "telemetry leaked {raw}");
        }
        assert!(!serialized.contains(
            prepared["result"]["structuredContent"]["plan_id"]
                .as_str()
                .unwrap()
        ));
    }

    #[tokio::test]
    async fn deployment_freeze_refuses_plan_prepare_and_execute_without_lifecycle_writes() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"type":"Document","kind":"note","name":"Frozen plan target"}),
        )
        .await
        .unwrap();
        let barrier = DeploymentMutationBarrier::default();
        let mut registry = ToolRegistry::new();
        registry.set_deployment_mutation_barrier(barrier.clone());
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let revision = policy_revision(&registry, &db, Caller::local(), &target).await;
        let policy_events_before = policy_event_count(&db).await;
        let server = ExecutorPrototypeStdioServer::new(registry, db.clone(), Caller::local(), None)
            .await
            .unwrap();
        let plan_count = || async {
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM write_plans")
                .fetch_one(server.write_runtime.store.local_pool())
                .await
                .unwrap()
        };

        let frozen = barrier.freeze().await;
        let refused_prepare = server
            .handle_message(call_message(201, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        let prepare_error = &refused_prepare["result"]["structuredContent"];
        assert_eq!(prepare_error["error_code"], DEPLOYMENT_READ_ONLY_ERROR);
        assert_eq!(prepare_error["retryable"], true);
        assert_eq!(prepare_error["applied"], false);
        assert_eq!(
            prepare_error["operation"],
            "access_admin.manage_record_policy.replace"
        );
        assert_eq!(plan_count().await, 0);
        drop(frozen);

        let prepared = server
            .handle_message(call_message(202, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        let plan_id = prepared["result"]["structuredContent"]["plan_id"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(plan_count().await, 1);

        let frozen = barrier.freeze().await;
        let refused_execute = server
            .handle_message(call_message(203, execution_arguments(&prepared)))
            .await
            .unwrap();
        let execute_error = &refused_execute["result"]["structuredContent"];
        assert_eq!(execute_error["error_code"], DEPLOYMENT_READ_ONLY_ERROR);
        assert_eq!(execute_error["retryable"], true);
        assert_eq!(execute_error["applied"], false);
        assert_eq!(
            execute_error["operation"],
            "access_admin.manage_record_policy.replace"
        );
        let state: String = sqlx::query_scalar("SELECT state FROM write_plans WHERE plan_id = ?")
            .bind(&plan_id)
            .fetch_one(server.write_runtime.store.local_pool())
            .await
            .unwrap();
        assert_eq!(state, "prepared");
        assert_eq!(policy_event_count(&db).await, policy_events_before);
        drop(frozen);

        let executed = server
            .handle_message(call_message(204, execution_arguments(&prepared)))
            .await
            .unwrap();
        assert!(response_succeeded(&executed), "{executed}");
        let state: String = sqlx::query_scalar("SELECT state FROM write_plans WHERE plan_id = ?")
            .bind(plan_id)
            .fetch_one(server.write_runtime.store.local_pool())
            .await
            .unwrap();
        assert_eq!(state, "completed");
        assert_eq!(policy_event_count(&db).await, policy_events_before + 1);
    }

    #[tokio::test]
    async fn freeze_drains_admitted_executor_dispatch_without_nested_readmission() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"type":"Document","kind":"note","name":"Drain executor target"}),
        )
        .await
        .unwrap();
        let barrier = DeploymentMutationBarrier::default();
        let mut registry = ToolRegistry::new();
        registry.set_deployment_mutation_barrier(barrier.clone());
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        let registry = Arc::new(registry);
        let revision = policy_revision(&registry, &db, Caller::local(), &target).await;
        let policy_events_before = policy_event_count(&db).await;
        let mut server =
            ExecutorPrototypeStdioServer::new(registry, db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let prepared = server
            .handle_message(call_message(211, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        let gate = DispatchGate::new();
        server.write_runtime.dispatch_gate = Some(Arc::clone(&gate));
        let server = Arc::new(server);

        let running = {
            let server = Arc::clone(&server);
            let arguments = execution_arguments(&prepared);
            tokio::spawn(async move { server.handle_message(call_message(212, arguments)).await })
        };
        let entered = gate.entered.acquire().await.unwrap();
        entered.forget();
        let freeze = {
            let barrier = barrier.clone();
            tokio::spawn(async move { barrier.freeze().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !barrier.is_read_only() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("freeze intent was not registered");

        let late = server
            .handle_message(call_message(213, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        assert_eq!(
            late["result"]["structuredContent"]["error_code"],
            DEPLOYMENT_READ_ONLY_ERROR
        );
        assert!(!freeze.is_finished());

        gate.release.add_permits(1);
        let completed = running.await.unwrap().unwrap();
        assert!(response_succeeded(&completed), "{completed}");
        assert_eq!(policy_event_count(&db).await, policy_events_before + 1);
        let frozen = tokio::time::timeout(std::time::Duration::from_secs(2), freeze)
            .await
            .expect("freeze did not complete after admitted executor dispatch")
            .unwrap();
        let still_late = server
            .handle_message(call_message(214, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        assert_eq!(
            still_late["result"]["structuredContent"]["error_code"],
            DEPLOYMENT_READ_ONLY_ERROR
        );
        drop(frozen);
    }

    #[tokio::test]
    async fn record_type_correction_requires_the_claimed_executor_dispatch_boundary() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({
                "id":"ec00b000-0000-4000-8000-000000000027",
                "type":"Document",
                "kind":"note",
                "name":"Misfiled executor fixture",
                "body":"The bearer and its body must survive correction.",
            }),
        )
        .await
        .unwrap();
        let registry = registry();
        let caller = Caller::local();
        let server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), caller.clone(), None)
                .await
                .unwrap();

        let prepared = server
            .handle_message(executor_call_message(
                1,
                RECORDS_WRITE_EXECUTOR,
                json!({
                    "operation":CORRECT_RECORD_TYPE_OPERATION,
                    "arguments":{
                        "record_id":target,
                        "target_type":"Resolution",
                        "target_kind":"decision",
                        "reason":"Correct the registry-proven wrong spine type."
                    }
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        assert_eq!(
            prepared["result"]["structuredContent"]["preparation_mutated"],
            false
        );
        assert_eq!(type_correction_event_count(&db, &target).await, 0);
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT type FROM records WHERE id=?")
                .bind(&target)
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            "Document"
        );

        let plan_id = prepared["result"]["structuredContent"]["plan_id"]
            .as_str()
            .unwrap();
        let stored = server
            .write_runtime
            .store
            .load(plan_id, now_ms())
            .await
            .unwrap()
            .unwrap();
        let plan: WritePlan = serde_json::from_value(stored.payload).unwrap();
        let mut forged_source_arguments = plan.canonical_source_arguments.clone();
        forged_source_arguments["plan_id"] = json!(plan.id);
        forged_source_arguments["effect_digest"] = json!(plan.effect_digest);
        let direct = registry
            .call(
                db.clone(),
                caller,
                "correct_record_type",
                forged_source_arguments,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            direct.contains("claimed records_write.correct_record_type plan"),
            "{direct}"
        );
        assert_eq!(type_correction_event_count(&db, &target).await, 0);

        let execute = execution_arguments_for(CORRECT_RECORD_TYPE_OPERATION, &prepared);
        let first = server
            .handle_message(executor_call_message(
                2,
                RECORDS_WRITE_EXECUTOR,
                execute.clone(),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&first), "{first}");
        assert_eq!(type_correction_event_count(&db, &target).await, 1);
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT type FROM records WHERE id=?")
                .bind(&target)
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            "Resolution"
        );

        let replay = server
            .handle_message(executor_call_message(3, RECORDS_WRITE_EXECUTOR, execute))
            .await
            .unwrap();
        assert!(response_succeeded(&replay), "{replay}");
        assert_eq!(
            replay["result"]["_meta"]["nativeWritePlanReplay"]["sourceDispatchCount"],
            1
        );
        assert_eq!(type_correction_event_count(&db, &target).await, 1);
        assert_eq!(
            server
                .trace_events()
                .iter()
                .filter(|event| {
                    event["kind"] == "write_plan_executed"
                        && event["operation"] == CORRECT_RECORD_TYPE_OPERATION
                })
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn policy_delta_and_inheritance_plans_prepare_without_mutation_then_dispatch_once() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000001","type":"Document","kind":"note","name":"Policy Deltas"}),
        )
        .await
        .unwrap();
        let registry = registry();
        let server = ExecutorPrototypeStdioServer::new(registry, db.clone(), Caller::local(), None)
            .await
            .unwrap();
        for operation in [
            POLICY_GRANT_OPERATION,
            POLICY_REVOKE_OPERATION,
            POLICY_BASELINE_OPERATION,
            POLICY_RESTORE_OPERATION,
            ARTIFACT_GRANT_OPERATION,
            ARTIFACT_REVOKE_OPERATION,
        ] {
            assert!(server
                .contracts
                .contains_key(&(ACCESS_EXECUTOR.into(), operation.into())));
        }

        let cases = [
            (
                POLICY_GRANT_OPERATION,
                json!({
                    "record_id":target,
                    "subject":{"kind":"account","account_id":"acct:planned-policy-grant"},
                    "capability":"view",
                    "reason":"Approve the exact account view grant"
                }),
                "grant",
            ),
            (
                POLICY_BASELINE_OPERATION,
                json!({
                    "record_id":target,
                    "capability":"edit",
                    "reason":"Approve the exact members baseline change"
                }),
                "set_members_baseline",
            ),
            (
                POLICY_REVOKE_OPERATION,
                json!({
                    "record_id":target,
                    "subject":{"kind":"account","account_id":"acct:planned-policy-grant"},
                    "reason":"Approve removal of the exact account entry"
                }),
                "revoke",
            ),
        ];
        let mut next_id = 300;
        for (operation, arguments, action) in cases {
            let before = policy_event_count(&db).await;
            let prepared = server
                .handle_message(executor_call_message(
                    next_id,
                    ACCESS_EXECUTOR,
                    json!({"operation":operation,"arguments":arguments}),
                ))
                .await
                .unwrap();
            next_id += 1;
            assert!(response_succeeded(&prepared), "{prepared}");
            assert_eq!(
                prepared["result"]["structuredContent"]["preparation_mutated"],
                false
            );
            assert_eq!(
                prepared["result"]["structuredContent"]["effect"]["action"],
                action
            );
            assert_eq!(policy_event_count(&db).await, before);
            let changed = prepared["result"]["structuredContent"]["effect"]["changed"] == true;
            let executed = server
                .handle_message(executor_call_message(
                    next_id,
                    ACCESS_EXECUTOR,
                    execution_arguments_for(operation, &prepared),
                ))
                .await
                .unwrap();
            next_id += 1;
            assert!(response_succeeded(&executed), "{executed}");
            assert_eq!(policy_event_count(&db).await, before + i64::from(changed));
        }
        let restore_revision =
            policy_revision(&server.registry, &db, Caller::local(), &target).await;
        let before = policy_event_count(&db).await;
        let prepared = server
            .handle_message(executor_call_message(
                next_id,
                ACCESS_EXECUTOR,
                json!({
                    "operation":POLICY_RESTORE_OPERATION,
                    "arguments":{
                        "record_id":target,
                        "if_policy_revision":restore_revision,
                        "reason":"Approve restoration of inherited access"
                    }
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        assert_eq!(
            prepared["result"]["structuredContent"]["effect"]["action"],
            "restore_inheritance"
        );
        assert_eq!(policy_event_count(&db).await, before);
        let executed = server
            .handle_message(executor_call_message(
                next_id + 1,
                ACCESS_EXECUTOR,
                execution_arguments_for(POLICY_RESTORE_OPERATION, &prepared),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&executed), "{executed}");
        assert_eq!(policy_event_count(&db).await, before + 1);
    }

    #[tokio::test]
    async fn policy_set_many_plan_executes_once_replays_and_fences_a_later_target() {
        let db = create_database(":memory:").await.unwrap();
        let first = create_record(
            &db,
            json!({
                "id":"ec00b000-0000-4000-8000-000000000021",
                "type":"Document",
                "kind":"note",
                "name":"Policy set first"
            }),
        )
        .await
        .unwrap();
        let second = create_record(
            &db,
            json!({
                "id":"ec00b000-0000-4000-8000-000000000022",
                "type":"Document",
                "kind":"note",
                "name":"Policy set second"
            }),
        )
        .await
        .unwrap();
        let registry = registry();
        let server = ExecutorPrototypeStdioServer::new(registry, db.clone(), Caller::local(), None)
            .await
            .unwrap();
        let events_before = policy_event_count(&db).await;
        let prepared = server
            .handle_message(executor_call_message(
                340,
                ACCESS_EXECUTOR,
                json!({
                    "operation":POLICY_SET_MANY_OPERATION,
                    "arguments":{
                        "items":[
                            {
                                "record_id":first,
                                "subject":{"kind":"account","account_id":"acct:set-first"},
                                "capability":"view"
                            },
                            {
                                "record_id":second,
                                "subject":{"kind":"account","account_id":"acct:set-second"},
                                "capability":"edit"
                            }
                        ],
                        "reason":"Approve both exact policy grants as one set"
                    }
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        let plan = &prepared["result"]["structuredContent"];
        assert_eq!(plan["preparation_mutated"], false);
        assert_eq!(plan["effect"]["action"], "set_many");
        assert_eq!(plan["effect"]["item_count"], 2);
        assert_eq!(plan["effect"]["changed_count"], 2);
        assert_eq!(plan["effect"]["items"][0]["index"], 0);
        assert_eq!(plan["effect"]["items"][1]["index"], 1);
        assert_eq!(policy_event_count(&db).await, events_before);

        let execute = execution_arguments_for(POLICY_SET_MANY_OPERATION, &prepared);
        let executed = server
            .handle_message(executor_call_message(341, ACCESS_EXECUTOR, execute.clone()))
            .await
            .unwrap();
        assert!(response_succeeded(&executed), "{executed}");
        assert_eq!(policy_event_count(&db).await, events_before + 2);
        for (record_id, account_id, capability) in [
            (&first, "acct:set-first", "view"),
            (&second, "acct:set-second", "edit"),
        ] {
            let listed = server
                .registry
                .call(
                    db.clone(),
                    Caller::local(),
                    "manage_record_policy",
                    json!({"action":"list","record_id":record_id}),
                )
                .await
                .unwrap();
            assert!(listed["entries"].as_array().unwrap().iter().any(|entry| {
                entry["subject"]["account_id"] == account_id && entry["capability"] == capability
            }));
        }

        let replayed = server
            .handle_message(executor_call_message(342, ACCESS_EXECUTOR, execute))
            .await
            .unwrap();
        assert!(response_succeeded(&replayed), "{replayed}");
        assert_eq!(executed["result"]["content"], replayed["result"]["content"]);
        assert_eq!(
            replayed["result"]["_meta"]["nativeWritePlanReplay"]["idempotentReplay"],
            true
        );
        assert_eq!(
            replayed["result"]["_meta"]["nativeWritePlanReplay"]["sourceDispatchCount"],
            1
        );
        assert_eq!(policy_event_count(&db).await, events_before + 2);

        let stale_prepared = server
            .handle_message(executor_call_message(
                343,
                ACCESS_EXECUTOR,
                json!({
                    "operation":POLICY_SET_MANY_OPERATION,
                    "arguments":{
                        "items":[
                            {
                                "record_id":first,
                                "subject":{"kind":"account","account_id":"acct:set-first"},
                                "capability":"edit"
                            },
                            {
                                "record_id":second,
                                "subject":{"kind":"account","account_id":"acct:set-second"},
                                "capability":"view"
                            }
                        ],
                        "reason":"Prepare a second exact policy set"
                    }
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&stale_prepared), "{stale_prepared}");
        update_record(&db, &second, json!({"name":"Policy set second changed"}))
            .await
            .unwrap();
        let events_before_stale_execute = policy_event_count(&db).await;
        let stale = server
            .handle_message(executor_call_message(
                344,
                ACCESS_EXECUTOR,
                execution_arguments_for(POLICY_SET_MANY_OPERATION, &stale_prepared),
            ))
            .await
            .unwrap();
        assert_eq!(
            stale["result"]["structuredContent"]["plan_error"]["code"],
            "plan_stale"
        );
        assert_eq!(policy_event_count(&db).await, events_before_stale_execute);
    }

    #[tokio::test]
    async fn inherited_policy_revision_fences_mid_dispatch_parent_changes() {
        let db = create_database(":memory:").await.unwrap();
        let parent = create_record(
            &db,
            json!({
                "id":"ec00b000-0000-4000-8000-000000000002",
                "type":"Collection",
                "kind":"folder",
                "name":"Policy parent"
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:seed-policy-parent",
            &parent,
            vec![AllowEntry::members(Capability::View)],
        )
        .await
        .unwrap();
        let target = create_record(
            &db,
            json!({
                "id":"ec00b000-0000-4000-8000-000000000003",
                "type":"Document",
                "kind":"note",
                "name":"Policy child",
                "home_id":parent
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:seed-policy-child",
            &target,
            vec![AllowEntry::account("acct:child", Capability::Manage)],
        )
        .await
        .unwrap();

        let registry = registry();
        let target_revision = policy_revision(&registry, &db, Caller::local(), &target).await;
        let mut server =
            ExecutorPrototypeStdioServer::new(registry, db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let gate = DispatchGate::new();
        server.write_runtime.dispatch_gate = Some(Arc::clone(&gate));
        let server = Arc::new(server);
        let events_before = policy_event_count(&db).await;
        let prepared = server
            .handle_message(executor_call_message(
                320,
                ACCESS_EXECUTOR,
                json!({
                    "operation":POLICY_RESTORE_OPERATION,
                    "arguments":{
                        "record_id":target,
                        "if_policy_revision":target_revision,
                        "reason":"Restore the exact approved inherited policy"
                    }
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        assert_eq!(
            prepared["result"]["structuredContent"]["preparation_mutated"],
            false
        );
        assert_eq!(policy_event_count(&db).await, events_before);

        let running = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                server
                    .handle_message(executor_call_message(
                        321,
                        ACCESS_EXECUTOR,
                        execution_arguments_for(POLICY_RESTORE_OPERATION, &prepared),
                    ))
                    .await
            })
        };
        let entered = gate.entered.acquire().await.unwrap();
        entered.forget();
        replace_explicit_policy(
            &db,
            "test:change-policy-parent-after-revalidation",
            &parent,
            vec![AllowEntry::members(Capability::Edit)],
        )
        .await
        .unwrap();
        gate.release.add_permits(1);
        let rejected = running.await.unwrap().unwrap();
        assert_eq!(rejected["result"]["isError"], true);
        assert!(rejected["result"]["structuredContent"]["plan_error"].is_null());
        assert!(rejected["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("inherited policy revision conflict"));
        assert_eq!(policy_event_count(&db).await, events_before + 1);
        assert_eq!(
            policy_revision(&server.registry, &db, Caller::local(), &target).await,
            target_revision
        );
        let target_mode: String = server
            .registry
            .call(
                db,
                Caller::local(),
                "manage_record_policy",
                json!({"action":"list","record_id":target}),
            )
            .await
            .unwrap()["mode"]
            .as_str()
            .unwrap()
            .to_string();
        assert_eq!(target_mode, "explicit");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn artifact_grant_plans_prepare_truthfully_then_grant_and_revoke_exactly() {
        let _guard = native_artifact_runtime::mdx::test_guard();
        let db = create_database(":memory:").await.unwrap();
        let registry = registry();
        let artifact_id = "99999999-9999-4999-8999-999999999999";
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id":artifact_id,
                    "type":"Document",
                    "kind":"artifact",
                    "name":"Planned grant artifact",
                    "body":"export const nativeArtifact = { schema: \"native.mdx.artifact.v2\", inputs: {}, module_inputs: {}, capability_requests: [{ capability: \"navigation.external.user_gesture\", scope: {} }] }\n\n<Metric label=\"Ready\" value=\"yes\" />",
                    "facets":{"runtime":native_artifact_runtime::mdx_v2::RUNTIME_ID},
                    "reason":"Create the artifact grant plan fixture"
                }),
            )
            .await
            .unwrap();
        let source = sqlx::query(
            "SELECT id,json_extract(payload,'$.body') AS body FROM content_events
              WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
        )
        .bind(artifact_id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        let source_event_id: String = source.get("id");
        let source_body: String = source.get("body");
        let operation_arguments = json!({
            "artifact_id":artifact_id,
            "subject_kind":"artifact_source",
            "subject_record_id":artifact_id,
            "subject_event_id":source_event_id,
            "source_sha256":native_artifact_runtime::mdx::sha256_hex(source_body.as_bytes()),
            "capability":"navigation.external.user_gesture",
            "scope":{},
        });
        let server = ExecutorPrototypeStdioServer::new(registry, db.clone(), Caller::local(), None)
            .await
            .unwrap();
        let prepared = server
            .handle_message(executor_call_message(
                400,
                ACCESS_EXECUTOR,
                json!({"operation":ARTIFACT_GRANT_OPERATION,"arguments":operation_arguments}),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        assert_eq!(
            prepared["result"]["structuredContent"]["effect"]["action"],
            "grant"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM artifact_module_grants")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            0
        );
        let granted = server
            .handle_message(executor_call_message(
                401,
                ACCESS_EXECUTOR,
                execution_arguments_for(ARTIFACT_GRANT_OPERATION, &prepared),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&granted), "{granted}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM artifact_module_grants")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            1
        );

        let revoke_arguments = prepared["result"]["structuredContent"]["effect"]["grant"].clone();
        let revoke_arguments = json!({
            "artifact_id":artifact_id,
            "subject_kind":revoke_arguments["subject_kind"],
            "subject_record_id":revoke_arguments["subject_record_id"],
            "subject_event_id":revoke_arguments["subject_event_id"],
            "source_sha256":revoke_arguments["source_sha256"],
            "capability":revoke_arguments["capability"],
            "scope":revoke_arguments["scope"],
        });
        let revoke = server
            .handle_message(executor_call_message(
                402,
                ACCESS_EXECUTOR,
                json!({"operation":ARTIFACT_REVOKE_OPERATION,"arguments":revoke_arguments}),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&revoke), "{revoke}");
        assert_eq!(
            revoke["result"]["structuredContent"]["effect"]["action"],
            "revoke"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM artifact_module_grants")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            1
        );
        let revoked = server
            .handle_message(executor_call_message(
                403,
                ACCESS_EXECUTOR,
                execution_arguments_for(ARTIFACT_REVOKE_OPERATION, &revoke),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&revoked), "{revoked}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM artifact_module_grants")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            0
        );
    }

    #[test]
    fn identity_binding_plans_are_truthful_non_mutating_stale_safe_and_exactly_once() {
        std::thread::Builder::new()
            .name("identity-write-plan-test".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(identity_binding_plan_truthfulness_body());
            })
            .unwrap()
            .join()
            .expect("identity write-plan test thread must not panic");
    }

    async fn identity_binding_plan_truthfulness_body() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000004","type":"Entity","kind":"person","name":"Target Person"}),
        )
        .await
        .unwrap();
        let source = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000005","type":"Entity","kind":"person","name":"Source Person"}),
        )
        .await
        .unwrap();
        let other = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000006","type":"Entity","kind":"person","name":"Other Person"}),
        )
        .await
        .unwrap();
        grant_local_binding_manage(&db, &[&target, &source, &other]).await;
        let registry = registry();
        let caller = Caller::local();
        let server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), caller.clone(), None)
                .await
                .unwrap();
        let mut revalidation_server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), caller.clone(), None)
                .await
                .unwrap();
        let revalidation_gate = DispatchGate::new();
        revalidation_server.write_runtime.revalidation_gate = Some(Arc::clone(&revalidation_gate));
        let revalidation_server = Arc::new(revalidation_server);
        for operation in [
            IDENTITY_ADD_OPERATION,
            IDENTITY_CANONICALIZE_OPERATION,
            IDENTITY_RECONCILE_OPERATION,
            IDENTITY_REMOVE_OPERATION,
        ] {
            assert!(server
                .contracts
                .contains_key(&(IDENTITY_EXECUTOR.into(), operation.into())));
        }

        let caller_owned_state = server
            .handle_message(executor_call_message(
                197,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_ADD_OPERATION,
                    "arguments":{
                        "record_id":target,
                        "binding":{"system":"native-principal","identifier":"dns:fixture.test/forged"},
                        "reason":"Reject a forged source state token",
                        "if_binding_state_revision":"caller-token",
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            caller_owned_state["result"]["structuredContent"]["plan_error"]["code"],
            "preparation_validation_failed"
        );
        assert!(caller_owned_state["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("identity binding state revision is source-owned"));
        assert!(!caller_owned_state.to_string().contains("contract_drift"));

        let preview_bypass = server
            .handle_message(executor_call_message(
                198,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_RECONCILE_OPERATION,
                    "arguments":{
                        "target_record_id":target,
                        "expected_source_record_id":source,
                        "bindings":[{"system":"native-principal","identifier":"dns:fixture.test/missing"}],
                        "apply":false,
                        "reason":"Do not turn a preview into an approved mutation"
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(preview_bypass["result"]["isError"], true);
        assert!(preview_bypass["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("apply must be true"));
        let same_record = server
            .handle_message(executor_call_message(
                199,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_RECONCILE_OPERATION,
                    "arguments":{
                        "target_record_id":target,
                        "expected_source_record_id":target,
                        "bindings":[{"system":"native-principal","identifier":"dns:fixture.test/missing"}],
                        "reason":"Reject a transfer to the same record"
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(same_record["result"]["isError"], true);
        assert!(same_record["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("must be different"));

        let audit_before = binding_audit_count(&db).await;
        let add = server
            .handle_message(executor_call_message(
                200,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_ADD_OPERATION,
                    "arguments":{
                        "record_id":target,
                        "binding":{"system":"native-principal","identifier":"dns:fixture.test/primary"},
                        "canonical":true,
                        "reason":"Add the exact governed identity"
                    }
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&add));
        assert_eq!(
            add["result"]["structuredContent"]["preparation_mutated"],
            false
        );
        assert_eq!(
            add["result"]["structuredContent"]["effect"]["binding"]["identifier"],
            "dns:fixture.test/primary"
        );
        assert_eq!(binding_owner(&db, "dns:fixture.test/primary").await, None);
        assert_eq!(binding_audit_count(&db).await, audit_before);
        let add_execute = execution_arguments_for(IDENTITY_ADD_OPERATION, &add);
        {
            let duplicate = {
                let revalidation_server = Arc::clone(&revalidation_server);
                let add_execute = add_execute.clone();
                tokio::spawn(async move {
                    revalidation_server
                        .handle_message(executor_call_message(202, IDENTITY_EXECUTOR, add_execute))
                        .await
                })
            };
            let entered = revalidation_gate.entered.acquire().await.unwrap();
            entered.forget();
            let first = server
                .handle_message(executor_call_message(201, IDENTITY_EXECUTOR, add_execute))
                .await
                .unwrap();
            assert!(response_succeeded(&first), "{first}");
            revalidation_gate.release.add_permits(1);
            let duplicate = duplicate.await.unwrap().unwrap();
            assert!(response_succeeded(&duplicate), "{duplicate}");
            assert_eq!(
                duplicate["result"]["_meta"]["nativeWritePlanReplay"]["sourceDispatchCount"],
                1
            );
        }
        assert_eq!(
            binding_owner(&db, "dns:fixture.test/primary").await,
            Some((target.clone(), true))
        );
        assert_eq!(binding_audit_count(&db).await, audit_before + 1);

        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_bindings",
                json!({
                    "action":"add",
                    "record_id":target,
                    "binding":{"system":"native-principal","identifier":"dns:fixture.test/secondary"},
                    "reason":"Seed a second governed identity"
                }),
            )
            .await
            .unwrap();
        let canonicalize = server
            .handle_message(executor_call_message(
                203,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_CANONICALIZE_OPERATION,
                    "arguments":{
                        "record_id":target,
                        "binding":{"system":"native-principal","identifier":"dns:fixture.test/secondary"},
                        "reason":"Select the exact canonical identity"
                    }
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&canonicalize));
        assert_eq!(
            binding_owner(&db, "dns:fixture.test/secondary").await,
            Some((target.clone(), false))
        );
        let canonicalized = server
            .handle_message(executor_call_message(
                204,
                IDENTITY_EXECUTOR,
                execution_arguments_for(IDENTITY_CANONICALIZE_OPERATION, &canonicalize),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&canonicalized));
        assert_eq!(
            binding_owner(&db, "dns:fixture.test/secondary").await,
            Some((target.clone(), true))
        );
        assert_eq!(
            binding_owner(&db, "dns:fixture.test/primary").await,
            Some((target.clone(), false))
        );

        let remove = server
            .handle_message(executor_call_message(
                205,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_REMOVE_OPERATION,
                    "arguments":{
                        "record_id":target,
                        "binding":{"system":"native-principal","identifier":"dns:fixture.test/primary"},
                        "reason":"Remove the exact noncanonical identity"
                    }
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&remove));
        assert_eq!(
            binding_owner(&db, "dns:fixture.test/primary")
                .await
                .unwrap()
                .0,
            target
        );
        let removed = server
            .handle_message(executor_call_message(
                206,
                IDENTITY_EXECUTOR,
                execution_arguments_for(IDENTITY_REMOVE_OPERATION, &remove),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&removed));
        assert_eq!(binding_owner(&db, "dns:fixture.test/primary").await, None);

        for (identifier, canonical) in [
            ("dns:fixture.test/transfer", false),
            ("dns:fixture.test/canonical-transfer", true),
            ("dns:fixture.test/stale", false),
        ] {
            registry
                .call(
                    db.clone(),
                    caller.clone(),
                    "manage_bindings",
                    json!({
                        "action":"add",
                        "record_id":source,
                        "binding":{"system":"native-principal","identifier":identifier},
                        "canonical":canonical,
                        "reason":"Seed an exact reconciliation identity"
                    }),
                )
                .await
                .unwrap();
        }
        let duplicate_selection = server
            .handle_message(executor_call_message(
                207,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_RECONCILE_OPERATION,
                    "arguments":{
                        "target_record_id":target,
                        "expected_source_record_id":source,
                        "bindings":[
                            {"system":"native-principal","identifier":"dns:fixture.test/transfer"},
                            {"system":"native-principal","identifier":"dns:fixture.test/transfer"}
                        ],
                        "reason":"Reject a duplicated normalized selection"
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(duplicate_selection["result"]["isError"], true);
        assert!(duplicate_selection["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("duplicate binding"));
        let reconcile = server
            .handle_message(executor_call_message(
                208,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_RECONCILE_OPERATION,
                    "arguments":{
                        "target_record_id":target,
                        "expected_source_record_id":source,
                        "bindings":[{"system":"native-principal","identifier":"dns:fixture.test/transfer"}],
                        "reason":"Transfer only the selected governed identity"
                    }
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&reconcile));
        assert_eq!(
            reconcile["result"]["structuredContent"]["effect"]["scope"],
            "bindings_only"
        );
        assert_eq!(
            binding_owner(&db, "dns:fixture.test/transfer")
                .await
                .unwrap()
                .0,
            source
        );
        let reconciled = server
            .handle_message(executor_call_message(
                209,
                IDENTITY_EXECUTOR,
                execution_arguments_for(IDENTITY_RECONCILE_OPERATION, &reconcile),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&reconciled));
        assert_eq!(
            binding_owner(&db, "dns:fixture.test/transfer")
                .await
                .unwrap()
                .0,
            target
        );

        let canonical_collision = server
            .handle_message(executor_call_message(
                210,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_RECONCILE_OPERATION,
                    "arguments":{
                        "target_record_id":target,
                        "expected_source_record_id":source,
                        "bindings":[{"system":"native-principal","identifier":"dns:fixture.test/canonical-transfer"}],
                        "reason":"Reject an exact canonical collision"
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(canonical_collision["result"]["isError"], true);
        assert!(canonical_collision["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("canonical binding collision"));

        let stale = server
            .handle_message(executor_call_message(
                211,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_RECONCILE_OPERATION,
                    "arguments":{
                        "target_record_id":target,
                        "expected_source_record_id":source,
                        "bindings":[{"system":"native-principal","identifier":"dns:fixture.test/stale"}],
                        "reason":"Bind execution to the exact current owner"
                    }
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&stale));
        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_bindings",
                json!({
                    "action":"remove",
                    "record_id":source,
                    "binding":{"system":"native-principal","identifier":"dns:fixture.test/stale"},
                    "reason":"Change the prepared binding state"
                }),
            )
            .await
            .unwrap();
        let stale_execution = server
            .handle_message(executor_call_message(
                212,
                IDENTITY_EXECUTOR,
                execution_arguments_for(IDENTITY_RECONCILE_OPERATION, &stale),
            ))
            .await
            .unwrap();
        assert_eq!(
            stale_execution["result"]["structuredContent"]["plan_error"]["code"],
            "plan_stale"
        );

        registry
            .call(
                db.clone(),
                caller,
                "manage_bindings",
                json!({
                    "action":"add",
                    "record_id":other,
                    "binding":{"system":"native-principal","identifier":"dns:fixture.test/collision"},
                    "reason":"Seed an exact visible collision"
                }),
            )
            .await
            .unwrap();
        let collision = server
            .handle_message(executor_call_message(
                213,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_ADD_OPERATION,
                    "arguments":{
                        "record_id":target,
                        "binding":{"system":"native-principal","identifier":"dns:fixture.test/collision"},
                        "reason":"Never invent a collision outcome"
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(collision["result"]["isError"], true);
        assert!(collision["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("binding collision"));
        assert_eq!(
            binding_owner(&db, "dns:fixture.test/collision")
                .await
                .unwrap()
                .0,
            other
        );

        replace_explicit_policy(
            &db,
            "test:grant-identity-operator",
            &target,
            vec![AllowEntry::account("identity-operator", Capability::Manage)],
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "test:conceal-binding-owner", &other, vec![])
            .await
            .unwrap();
        let concealed_server = ExecutorPrototypeStdioServer::new(
            registry,
            db.clone(),
            Caller::authenticated("identity-operator"),
            None,
        )
        .await
        .unwrap();
        let concealed_collision = concealed_server
            .handle_message(executor_call_message(
                214,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_ADD_OPERATION,
                    "arguments":{
                        "record_id":target,
                        "binding":{"system":"native-principal","identifier":"dns:fixture.test/collision"},
                        "reason":"Do not expose an inaccessible binding owner"
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(concealed_collision["result"]["isError"], true);
        let concealed_text = concealed_collision["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(concealed_text.contains("binding_not_visible"));
        assert!(!concealed_text.contains("another visible record"));
    }

    #[test]
    fn schema_and_vocabulary_plans_prepare_truthful_effects_and_dispatch_once() {
        std::thread::Builder::new()
            .name("schema-vocabulary-write-plans-test".into())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(
                        schema_and_vocabulary_plans_prepare_truthful_effects_and_dispatch_once_body(
                        ),
                    );
            })
            .unwrap()
            .join()
            .expect("schema and vocabulary plan test thread must not panic");
    }

    async fn schema_and_vocabulary_plans_prepare_truthful_effects_and_dispatch_once_body() {
        let db = create_database(":memory:").await.unwrap();
        let registry = registry();
        let caller = Caller::local();

        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_vocabularies",
                json!({"action":"create_vocabulary","name":"executor-plan-work"}),
            )
            .await
            .unwrap();
        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_vocabularies",
                json!({"action":"create_vocabulary","name":"executor-plan-empty"}),
            )
            .await
            .unwrap();
        for value in ["red", "blue", "delete-me"] {
            registry
                .call(
                    db.clone(),
                    caller.clone(),
                    "manage_vocabularies",
                    json!({
                        "action":"propose_value",
                        "vocabulary":"executor-plan-work",
                        "value":value,
                    }),
                )
                .await
                .unwrap();
        }
        let mut kind_metadata = crate::meta::KindMetadataV1::legacy("Document", "executor-plan");
        let kind_value_id = crate::meta::propose_value_with_kind_metadata_as(
            &db,
            "kind:Document",
            "executor-plan",
            None,
            0.0,
            crate::meta::VocabularyValueTerminality::Open,
            Some(kind_metadata.clone()),
            Some("test:schema-plan"),
        )
        .await
        .unwrap();
        kind_metadata.definition = "Updated through one approved schema plan.".into();

        let server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), caller.clone(), None)
                .await
                .unwrap();
        for operation in [
            VOCABULARY_ALIAS_OPERATION,
            VOCABULARY_CREATE_OPERATION,
            VOCABULARY_DEPRECATE_OPERATION,
            VOCABULARY_PROMOTE_OPERATION,
            VOCABULARY_PROPOSE_OPERATION,
            VOCABULARY_REORDER_OPERATION,
            VOCABULARY_METADATA_OPERATION,
            SCHEMA_CONFIG_WRITE_OPERATION,
        ] {
            assert!(server
                .contracts
                .contains_key(&(SCHEMA_ADMIN_EXECUTOR.into(), operation.into())));
        }
        for operation in [
            VOCABULARY_DELETE_VALUE_OPERATION,
            VOCABULARY_DELETE_OPERATION,
        ] {
            assert!(server
                .contracts
                .contains_key(&(SCHEMA_DELETE_EXECUTOR.into(), operation.into())));
        }

        prepare_and_execute_schema_plan(
            &server,
            &db,
            300,
            SCHEMA_ADMIN_EXECUTOR,
            VOCABULARY_CREATE_OPERATION,
            json!({"name":"executor-plan-created"}),
        )
        .await;
        prepare_and_execute_schema_plan(
            &server,
            &db,
            310,
            SCHEMA_ADMIN_EXECUTOR,
            VOCABULARY_PROPOSE_OPERATION,
            json!({"vocabulary":"executor-plan-created","value":"planned"}),
        )
        .await;
        prepare_and_execute_schema_plan(
            &server,
            &db,
            320,
            SCHEMA_ADMIN_EXECUTOR,
            VOCABULARY_REORDER_OPERATION,
            json!({"value_id":"vv:voc:executor-plan-work:red","ordinal":125.5}),
        )
        .await;
        prepare_and_execute_schema_plan(
            &server,
            &db,
            330,
            SCHEMA_ADMIN_EXECUTOR,
            VOCABULARY_PROMOTE_OPERATION,
            json!({"value_id":"vv:voc:executor-plan-work:red"}),
        )
        .await;
        prepare_and_execute_schema_plan(
            &server,
            &db,
            340,
            SCHEMA_ADMIN_EXECUTOR,
            VOCABULARY_DEPRECATE_OPERATION,
            json!({"value_id":"vv:voc:executor-plan-work:red"}),
        )
        .await;
        prepare_and_execute_schema_plan(
            &server,
            &db,
            350,
            SCHEMA_ADMIN_EXECUTOR,
            VOCABULARY_ALIAS_OPERATION,
            json!({
                "value_id":"vv:voc:executor-plan-work:red",
                "canonical_id":"vv:voc:executor-plan-work:blue",
            }),
        )
        .await;
        prepare_and_execute_schema_plan(
            &server,
            &db,
            360,
            SCHEMA_ADMIN_EXECUTOR,
            VOCABULARY_METADATA_OPERATION,
            json!({
                "value_id":kind_value_id,
                "metadata":serde_json::to_value(kind_metadata).unwrap(),
            }),
        )
        .await;
        prepare_and_execute_schema_plan(
            &server,
            &db,
            370,
            SCHEMA_DELETE_EXECUTOR,
            VOCABULARY_DELETE_VALUE_OPERATION,
            json!({"value_id":"vv:voc:executor-plan-work:delete-me"}),
        )
        .await;
        prepare_and_execute_schema_plan(
            &server,
            &db,
            380,
            SCHEMA_DELETE_EXECUTOR,
            VOCABULARY_DELETE_OPERATION,
            json!({"vocabulary":"executor-plan-empty"}),
        )
        .await;
        let schema = prepare_and_execute_schema_plan(
            &server,
            &db,
            390,
            SCHEMA_ADMIN_EXECUTOR,
            SCHEMA_CONFIG_WRITE_OPERATION,
            json!({
                "data":{"shapes":{"Document":{"facets":{"executor_plan":{}}}}}
            }),
        )
        .await;
        let schema_target = schema["result"]["structuredContent"]["target"]
            .as_str()
            .unwrap();
        assert!(schema_target.contains("global schema config row"));
        assert!(!schema_target.contains("null"));
        let schema_plan_id = schema["result"]["structuredContent"]["plan_id"]
            .as_str()
            .unwrap();
        let stored_row = server
            .write_runtime
            .store
            .load(schema_plan_id, now_ms())
            .await
            .unwrap()
            .unwrap();
        let stored: WritePlan = serde_json::from_value(stored_row.payload).unwrap();
        assert!(stored.operation_arguments.get("id").is_none());
        assert_eq!(
            stored.revalidation_arguments["id"].as_str(),
            Some(stored.target_id.as_str())
        );
        assert_eq!(
            stored.canonical_source_arguments["id"],
            stored.revalidation_arguments["id"]
        );
        assert_eq!(
            digest(&stored.revalidation_arguments).unwrap(),
            stored.revalidation_arguments_digest
        );
    }

    #[tokio::test]
    async fn schema_preparation_preserves_noop_rejections_and_authorization() {
        let db = create_database(":memory:").await.unwrap();
        let registry = registry();
        let owner = Caller::local();
        for vocabulary in ["executor-guard-a", "executor-guard-b"] {
            registry
                .call(
                    db.clone(),
                    owner.clone(),
                    "manage_vocabularies",
                    json!({"action":"create_vocabulary","name":vocabulary}),
                )
                .await
                .unwrap();
        }
        for (vocabulary, value) in [
            ("executor-guard-a", "deprecated"),
            ("executor-guard-a", "alias-source"),
            ("executor-guard-b", "alias-target"),
        ] {
            registry
                .call(
                    db.clone(),
                    owner.clone(),
                    "manage_vocabularies",
                    json!({
                        "action":"propose_value",
                        "vocabulary":vocabulary,
                        "value":value,
                    }),
                )
                .await
                .unwrap();
        }
        registry
            .call(
                db.clone(),
                owner.clone(),
                "manage_vocabularies",
                json!({
                    "action":"deprecate_value",
                    "value_id":"vv:voc:executor-guard-a:deprecated",
                }),
            )
            .await
            .unwrap();
        let referenced_kind = crate::meta::propose_value_with_kind_metadata_as(
            &db,
            "kind:Document",
            "executor-delete-guard",
            None,
            0.0,
            crate::meta::VocabularyValueTerminality::Open,
            Some(crate::meta::KindMetadataV1::legacy(
                "Document",
                "executor-delete-guard",
            )),
            Some("test:schema-delete-guard"),
        )
        .await
        .unwrap();
        registry
            .call(
                db.clone(),
                owner.clone(),
                "manage_vocabularies",
                json!({"action":"promote_value","value_id":referenced_kind}),
            )
            .await
            .unwrap();
        create_record(
            &db,
            json!({
                "id":"ec00b000-0000-4000-8000-000000000007",
                "type":"Document",
                "kind":"executor-delete-guard",
                "name":"Referenced kind value",
            }),
        )
        .await
        .unwrap();

        let owner_server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), owner.clone(), None)
                .await
                .unwrap();
        let events_before = meta_event_count(&db).await;
        let no_op = owner_server
            .handle_message(executor_call_message(
                420,
                SCHEMA_ADMIN_EXECUTOR,
                json!({
                    "operation":VOCABULARY_DEPRECATE_OPERATION,
                    "arguments":{"value_id":"vv:voc:executor-guard-a:deprecated"},
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&no_op), "{no_op}");
        assert_eq!(
            no_op["result"]["structuredContent"]["effect"]["changed"],
            false
        );
        assert_eq!(
            no_op["result"]["structuredContent"]["effect"]["result"]["records_quarantined"],
            0
        );
        assert_eq!(meta_event_count(&db).await, events_before);
        let no_op_execution = execution_arguments_for(VOCABULARY_DEPRECATE_OPERATION, &no_op);
        let no_op_first = owner_server
            .handle_message(executor_call_message(
                421,
                SCHEMA_ADMIN_EXECUTOR,
                no_op_execution.clone(),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&no_op_first), "{no_op_first}");
        let no_op_replay = owner_server
            .handle_message(executor_call_message(
                422,
                SCHEMA_ADMIN_EXECUTOR,
                no_op_execution,
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&no_op_replay), "{no_op_replay}");
        assert_eq!(
            no_op_first["result"]["content"], no_op_replay["result"]["content"],
            "the replay must return the exact same model-visible receipt"
        );
        assert!(no_op_first["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("records_quarantined"));
        assert_eq!(
            no_op_replay["result"]["_meta"]["nativeWritePlanReplay"]["sourceDispatchCount"],
            1
        );
        assert_eq!(meta_event_count(&db).await, events_before);

        for (id, executor, operation, arguments, diagnostic) in [
            (
                423,
                SCHEMA_ADMIN_EXECUTOR,
                VOCABULARY_ALIAS_OPERATION,
                json!({
                    "value_id":"vv:voc:executor-guard-a:alias-source",
                    "canonical_id":"vv:voc:executor-guard-b:alias-target",
                }),
                "cannot alias across vocabularies",
            ),
            (
                424,
                SCHEMA_DELETE_EXECUTOR,
                VOCABULARY_DELETE_VALUE_OPERATION,
                json!({"value_id":"vv:voc:maturity:exploratory"}),
                "cannot delete seeded vocabulary value",
            ),
            (
                425,
                SCHEMA_DELETE_EXECUTOR,
                VOCABULARY_DELETE_VALUE_OPERATION,
                json!({"value_id":"vv:voc:kind:Document:executor-delete-guard"}),
                "record(s) of type 'Document' store that token",
            ),
        ] {
            let rejected = owner_server
                .handle_message(executor_call_message(
                    id,
                    executor,
                    json!({"operation":operation,"arguments":arguments}),
                ))
                .await
                .unwrap();
            assert_eq!(rejected["result"]["isError"], true, "{rejected}");
            assert!(
                rejected["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains(diagnostic),
                "{rejected}"
            );
            assert_eq!(meta_event_count(&db).await, events_before);
        }

        let collection = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000008","type":"Collection","kind":"folder","name":"Schema scope"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:grant-schema-manager",
            &collection,
            vec![AllowEntry::account("schema-manager", Capability::Manage)],
        )
        .await
        .unwrap();
        let manager_server = ExecutorPrototypeStdioServer::new(
            registry,
            db.clone(),
            Caller::authenticated("schema-manager")
                .with_hosting_context("schema-manager", "executor-schema-db"),
            None,
        )
        .await
        .unwrap();
        let vocabulary_denied = manager_server
            .handle_message(executor_call_message(
                423,
                SCHEMA_ADMIN_EXECUTOR,
                json!({
                    "operation":VOCABULARY_CREATE_OPERATION,
                    "arguments":{"name":"owner-only"},
                }),
            ))
            .await
            .unwrap();
        assert_eq!(vocabulary_denied["result"]["isError"], true);
        assert!(vocabulary_denied["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("database owner host role required"));
        let global_denied = manager_server
            .handle_message(executor_call_message(
                424,
                SCHEMA_ADMIN_EXECUTOR,
                json!({
                    "operation":SCHEMA_CONFIG_WRITE_OPERATION,
                    "arguments":{"id":"global-denied","data":{"shapes":{}}},
                }),
            ))
            .await
            .unwrap();
        assert_eq!(global_denied["result"]["isError"], true);
        assert!(global_denied["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("database owner host role required for global rows"));
        let scoped_events = meta_event_count(&db).await;
        let scoped = manager_server
            .handle_message(executor_call_message(
                425,
                SCHEMA_ADMIN_EXECUTOR,
                json!({
                    "operation":SCHEMA_CONFIG_WRITE_OPERATION,
                    "arguments":{
                        "id":"scoped-authorized",
                        "applies_to_collection_id":collection,
                        "data":{"shapes":{}},
                    },
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&scoped), "{scoped}");
        assert_eq!(meta_event_count(&db).await, scoped_events);
    }

    #[tokio::test]
    async fn schema_state_token_fences_independent_and_mid_dispatch_changes() {
        let db = create_database(":memory:").await.unwrap();
        let registry = registry();
        let caller = Caller::local();
        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_vocabularies",
                json!({"action":"create_vocabulary","name":"executor-schema-cas"}),
            )
            .await
            .unwrap();
        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_vocabularies",
                json!({
                    "action":"propose_value",
                    "vocabulary":"executor-schema-cas",
                    "value":"one",
                }),
            )
            .await
            .unwrap();
        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_schema_config",
                json!({
                    "action":"write",
                    "id":"executor-schema-gated",
                    "data":{"shapes":{"WorkItem":{"facets":{"planned":{}}}}},
                }),
            )
            .await
            .unwrap();
        let counted_record = "ec00b000-0000-4000-8000-000000000009";
        registry
            .call(
                db.clone(),
                caller.clone(),
                "create_record",
                json!({
                    "id":counted_record,
                    "type":"WorkItem",
                    "kind":"task",
                    "name":"Counted schema value",
                    "facets":{"planned":"not-a-number"},
                    "reason":"Seed one historical value for schema count fencing",
                }),
            )
            .await
            .unwrap();
        let value_id = "vv:voc:executor-schema-cas:one";
        let mut server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), caller.clone(), None)
                .await
                .unwrap();
        let independent_gate = DispatchGate::new();
        server.write_runtime.dispatch_gate = Some(Arc::clone(&independent_gate));
        let server = Arc::new(server);
        let preparation = json!({
            "operation":VOCABULARY_REORDER_OPERATION,
            "arguments":{"value_id":value_id,"ordinal":10.0},
        });
        let first_plan = server
            .handle_message(executor_call_message(
                400,
                SCHEMA_ADMIN_EXECUTOR,
                preparation.clone(),
            ))
            .await
            .unwrap();
        let second_plan = server
            .handle_message(executor_call_message(
                401,
                SCHEMA_ADMIN_EXECUTOR,
                preparation,
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&first_plan));
        assert!(response_succeeded(&second_plan));
        let concurrent_events_before = meta_event_count(&db).await;
        let first_execution = execution_arguments_for(VOCABULARY_REORDER_OPERATION, &first_plan);
        let second_execution = execution_arguments_for(VOCABULARY_REORDER_OPERATION, &second_plan);
        let first_running = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                server
                    .handle_message(executor_call_message(
                        402,
                        SCHEMA_ADMIN_EXECUTOR,
                        first_execution,
                    ))
                    .await
            })
        };
        let second_running = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                server
                    .handle_message(executor_call_message(
                        403,
                        SCHEMA_ADMIN_EXECUTOR,
                        second_execution,
                    ))
                    .await
            })
        };
        for _ in 0..2 {
            let entered = independent_gate.entered.acquire().await.unwrap();
            entered.forget();
        }
        independent_gate.release.add_permits(2);
        let (first, second) = tokio::join!(first_running, second_running);
        let first = first.unwrap().unwrap();
        let second = second.unwrap().unwrap();
        assert_eq!(
            [response_succeeded(&first), response_succeeded(&second)]
                .into_iter()
                .filter(|succeeded| *succeeded)
                .count(),
            1
        );
        let stale = [&first, &second]
            .into_iter()
            .find(|response| !response_succeeded(response))
            .unwrap();
        assert!(stale["result"]["structuredContent"]["plan_error"].is_null());
        assert!(stale["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("schema state revision conflict"));
        assert_eq!(meta_event_count(&db).await, concurrent_events_before + 1);
        let failed_plan = if response_succeeded(&first) {
            &second_plan
        } else {
            &first_plan
        };
        let failed_plan_id = failed_plan["result"]["structuredContent"]["plan_id"]
            .as_str()
            .unwrap();
        let failed_stored = server
            .write_runtime
            .store
            .load(failed_plan_id, now_ms())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            failed_stored.state,
            StoredState::Completed {
                source_dispatch_count: 1,
                ..
            }
        ));

        let forged = server
            .handle_message(executor_call_message(
                404,
                SCHEMA_ADMIN_EXECUTOR,
                json!({
                    "operation":VOCABULARY_REORDER_OPERATION,
                    "arguments":{
                        "value_id":value_id,
                        "ordinal":20.0,
                        "if_schema_state_revision":"caller-token",
                    }
                }),
            ))
            .await
            .unwrap();
        assert_eq!(
            forged["result"]["structuredContent"]["plan_error"]["code"],
            "preparation_validation_failed"
        );
        assert!(forged["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("schema state revision is source-owned"));

        let mut gated_server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), caller.clone(), None)
                .await
                .unwrap();
        let gate = DispatchGate::new();
        gated_server.write_runtime.dispatch_gate = Some(Arc::clone(&gate));
        let gated_server = Arc::new(gated_server);
        let guarded_plan = gated_server
            .handle_message(executor_call_message(
                405,
                SCHEMA_ADMIN_EXECUTOR,
                json!({
                    "operation":VOCABULARY_REORDER_OPERATION,
                    "arguments":{"value_id":value_id,"ordinal":30.0},
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&guarded_plan));
        let running = {
            let gated_server = Arc::clone(&gated_server);
            tokio::spawn(async move {
                gated_server
                    .handle_message(executor_call_message(
                        406,
                        SCHEMA_ADMIN_EXECUTOR,
                        execution_arguments_for(VOCABULARY_REORDER_OPERATION, &guarded_plan),
                    ))
                    .await
            })
        };
        let entered = gate.entered.acquire().await.unwrap();
        entered.forget();
        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_vocabularies",
                json!({"action":"reorder_value","value_id":value_id,"ordinal":25.0}),
            )
            .await
            .unwrap();
        gate.release.add_permits(1);
        let guarded = running.await.unwrap().unwrap();
        assert_eq!(guarded["result"]["isError"], true);
        assert!(guarded["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("schema state revision conflict"));
        let ordinal: f64 = sqlx::query_scalar("SELECT ordinal FROM vocabulary_values WHERE id = ?")
            .bind(value_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(ordinal, 25.0);

        let schema_plan = gated_server
            .handle_message(executor_call_message(
                407,
                SCHEMA_ADMIN_EXECUTOR,
                json!({
                    "operation":SCHEMA_CONFIG_WRITE_OPERATION,
                    "arguments":{
                        "id":"executor-schema-gated",
                        "data":{"shapes":{"WorkItem":{"facets":{"planned":{"type":"number"}}}}},
                    },
                }),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&schema_plan), "{schema_plan}");
        assert_eq!(
            schema_plan["result"]["structuredContent"]["effect"]["result"]
                ["nonconforming_stored_values"],
            1
        );
        let running = {
            let gated_server = Arc::clone(&gated_server);
            tokio::spawn(async move {
                gated_server
                    .handle_message(executor_call_message(
                        408,
                        SCHEMA_ADMIN_EXECUTOR,
                        execution_arguments_for(SCHEMA_CONFIG_WRITE_OPERATION, &schema_plan),
                    ))
                    .await
            })
        };
        let entered = gate.entered.acquire().await.unwrap();
        entered.forget();
        registry
            .call(
                db.clone(),
                caller,
                "update_record",
                json!({
                    "id":counted_record,
                    "facets":{"planned":1.0},
                    "reason":"Change the prepared nonconformance count before dispatch",
                }),
            )
            .await
            .unwrap();
        gate.release.add_permits(1);
        let guarded = running.await.unwrap().unwrap();
        assert_eq!(guarded["result"]["isError"], true);
        assert!(guarded["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("schema state revision conflict"));
        let stored_schema: String =
            sqlx::query_scalar("SELECT data FROM schema_config WHERE id = ?")
                .bind("executor-schema-gated")
                .fetch_one(db.pool())
                .await
                .unwrap();
        let stored_schema: Value = serde_json::from_str(&stored_schema).unwrap();
        assert!(stored_schema["shapes"]["WorkItem"]["facets"]["planned"]
            .get("type")
            .is_none());
    }

    #[tokio::test]
    async fn identity_state_token_fences_independent_and_mid_dispatch_changes() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000010","type":"Entity","kind":"person","name":"CAS Target"}),
        )
        .await
        .unwrap();
        let other = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000011","type":"Entity","kind":"person","name":"CAS Other"}),
        )
        .await
        .unwrap();
        grant_local_binding_manage(&db, &[&target, &other]).await;
        let registry = registry();
        let mut server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let independent_gate = DispatchGate::new();
        server.write_runtime.dispatch_gate = Some(Arc::clone(&independent_gate));
        let server = Arc::new(server);
        let independent_args = json!({
            "operation":IDENTITY_ADD_OPERATION,
            "arguments":{
                "record_id":target,
                "binding":{"system":"native-principal","identifier":"dns:fixture.test/independent"},
                "reason":"Approve one exact independent add"
            }
        });
        let first_plan = server
            .handle_message(executor_call_message(
                220,
                IDENTITY_EXECUTOR,
                independent_args.clone(),
            ))
            .await
            .unwrap();
        let second_plan = server
            .handle_message(executor_call_message(
                221,
                IDENTITY_EXECUTOR,
                independent_args,
            ))
            .await
            .unwrap();
        let audit_before = binding_audit_count(&db).await;
        let first_running = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                server
                    .handle_message(executor_call_message(
                        222,
                        IDENTITY_EXECUTOR,
                        execution_arguments_for(IDENTITY_ADD_OPERATION, &first_plan),
                    ))
                    .await
            })
        };
        let second_running = {
            let server = Arc::clone(&server);
            tokio::spawn(async move {
                server
                    .handle_message(executor_call_message(
                        223,
                        IDENTITY_EXECUTOR,
                        execution_arguments_for(IDENTITY_ADD_OPERATION, &second_plan),
                    ))
                    .await
            })
        };
        for _ in 0..2 {
            let entered = independent_gate.entered.acquire().await.unwrap();
            entered.forget();
        }
        independent_gate.release.add_permits(2);
        let (first, second) = tokio::join!(first_running, second_running);
        let first = first.unwrap().unwrap();
        let second = second.unwrap().unwrap();
        assert_eq!(
            [response_succeeded(&first), response_succeeded(&second)]
                .into_iter()
                .filter(|succeeded| *succeeded)
                .count(),
            1
        );
        let source_rejected = [&first, &second]
            .into_iter()
            .find(|response| !response_succeeded(response))
            .unwrap();
        assert_eq!(source_rejected["result"]["isError"], true);
        assert!(source_rejected["result"]["structuredContent"]["plan_error"].is_null());
        assert!(source_rejected["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("binding state revision conflict"));
        assert_ne!(
            source_rejected.pointer("/result/structuredContent/repair/retry_ready"),
            Some(&Value::Bool(true))
        );
        assert_ne!(
            source_rejected.pointer("/result/structuredContent/repair/guidance/automatic_retry"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            binding_owner(&db, "dns:fixture.test/independent").await,
            Some((target.clone(), false))
        );
        assert_eq!(binding_audit_count(&db).await, audit_before + 1);

        let mut gated_server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let gate = DispatchGate::new();
        gated_server.write_runtime.dispatch_gate = Some(Arc::clone(&gate));
        let gated_server = Arc::new(gated_server);
        let guarded_plan = gated_server
            .handle_message(executor_call_message(
                224,
                IDENTITY_EXECUTOR,
                json!({
                    "operation":IDENTITY_ADD_OPERATION,
                    "arguments":{
                        "record_id":target,
                        "binding":{"system":"native-principal","identifier":"dns:fixture.test/guarded"},
                        "reason":"Fence the state through source dispatch"
                    }
                }),
            ))
            .await
            .unwrap();
        let running = {
            let gated_server = Arc::clone(&gated_server);
            tokio::spawn(async move {
                gated_server
                    .handle_message(executor_call_message(
                        225,
                        IDENTITY_EXECUTOR,
                        execution_arguments_for(IDENTITY_ADD_OPERATION, &guarded_plan),
                    ))
                    .await
            })
        };
        let entered = gate.entered.acquire().await.unwrap();
        entered.forget();
        registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_bindings",
                json!({
                    "action":"add",
                    "record_id":other,
                    "binding":{"system":"native-principal","identifier":"dns:fixture.test/concurrent-change"},
                    "reason":"Change identity state after plan revalidation"
                }),
            )
            .await
            .unwrap();
        gate.release.add_permits(1);
        let guarded = running.await.unwrap().unwrap();
        assert_eq!(guarded["result"]["isError"], true);
        assert!(guarded["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("binding state revision conflict"));
        assert_eq!(binding_owner(&db, "dns:fixture.test/guarded").await, None);
    }

    #[tokio::test]
    async fn cancelled_source_dispatch_is_fenced_as_indeterminate_and_never_retried() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000012","type":"Document","kind":"note","name":"Cancel"}),
        )
        .await
        .unwrap();
        let registry = registry();
        let caller = Caller::local();
        let revision = policy_revision(&registry, &db, caller.clone(), &target).await;
        let mut server = ExecutorPrototypeStdioServer::new(registry, db.clone(), caller, None)
            .await
            .unwrap();
        let gate = DispatchGate::new();
        server.write_runtime.dispatch_gate = Some(Arc::clone(&gate));
        let server = Arc::new(server);
        let events_before = policy_event_count(&db).await;
        let prepared = server
            .handle_message(call_message(30, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        let execute = execution_arguments(&prepared);
        let running = {
            let server = Arc::clone(&server);
            let execute = execute.clone();
            tokio::spawn(async move { server.handle_message(call_message(31, execute)).await })
        };
        let entered = gate.entered.acquire().await.unwrap();
        entered.forget();
        running.abort();
        assert!(running.await.unwrap_err().is_cancelled());

        let telemetry_sink = Arc::new(super::telemetry::TestTelemetrySink::default());
        let telemetry = ExecutorTelemetryContext::new(
            telemetry_sink.clone(),
            super::telemetry::DEFAULT_RETENTION_DAYS,
        )
        .unwrap();
        let restarted = ExecutorPrototypeStdioServer::new_with_telemetry(
            Arc::clone(&server.registry),
            db.clone(),
            server.caller.clone(),
            None,
            telemetry.clone(),
        )
        .await
        .unwrap();
        let retry = restarted
            .handle_message(call_message(32, execute))
            .await
            .unwrap();
        assert_eq!(
            retry["result"]["structuredContent"]["plan_error"]["code"],
            "plan_execution_indeterminate"
        );
        assert_eq!(
            retry["result"]["structuredContent"]["plan_error"]["continuation"],
            json!({
                "action":"verify_target_state_before_any_new_plan",
                "retryable":false,
                "retry_ready":false,
            })
        );
        assert_eq!(policy_event_count(&db).await, events_before);
        telemetry.flush().unwrap();
        let emitted = telemetry_sink
            .events()
            .into_iter()
            .map(|event| serde_json::from_slice::<Value>(&event).unwrap())
            .collect::<Vec<_>>();
        let indeterminate = emitted
            .iter()
            .find(|event| event["error_class"] == "plan_indeterminate")
            .expect("retry observes the authoritative post-claim indeterminate state");
        assert_eq!(indeterminate["counts"]["dispatch_count_bucket"], "1");
        assert_eq!(indeterminate["flags"]["duplicate_effect_attempt"], false);
        assert!(emitted.iter().any(|selected| {
            selected["phase"] == "operation_selected"
                && selected["request"]["correlation"] == indeterminate["request"]["correlation"]
        }));
    }

    #[tokio::test]
    async fn prepared_plan_survives_restart_and_executes_once() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000013","type":"Document","kind":"note","name":"Restart"}),
        )
        .await
        .unwrap();
        let registry = registry();
        let caller = Caller::local();
        let revision = policy_revision(&registry, &db, caller.clone(), &target).await;
        let events_before = policy_event_count(&db).await;
        let before_restart = ExecutorPrototypeStdioServer::new(
            Arc::clone(&registry),
            db.clone(),
            caller.clone(),
            None,
        )
        .await
        .unwrap();
        let prepared = before_restart
            .handle_message(call_message(40, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        let reopened = open_database_at(db.path()).await.unwrap();
        assert_ne!(db.handle_id(), reopened.handle_id());
        let after_restart = ExecutorPrototypeStdioServer::new(registry, reopened, caller, None)
            .await
            .unwrap();
        let executed = after_restart
            .handle_message(call_message(41, execution_arguments(&prepared)))
            .await
            .unwrap();
        assert!(response_succeeded(&executed), "{executed}");
        let replayed = before_restart
            .handle_message(call_message(42, execution_arguments(&prepared)))
            .await
            .unwrap();
        assert_eq!(
            replayed["result"]["_meta"]["nativeWritePlanReplay"]["idempotentReplay"],
            true
        );
        assert_eq!(policy_event_count(&db).await, events_before + 1);
    }

    #[tokio::test]
    async fn two_executor_instances_share_one_durable_dispatch_fence() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000014","type":"Document","kind":"note","name":"Multi instance"}),
        )
        .await
        .unwrap();
        let registry = registry();
        let caller = Caller::local();
        let revision = policy_revision(&registry, &db, caller.clone(), &target).await;
        let mut first = ExecutorPrototypeStdioServer::new(
            Arc::clone(&registry),
            db.clone(),
            caller.clone(),
            None,
        )
        .await
        .unwrap();
        let gate = DispatchGate::new();
        first.write_runtime.dispatch_gate = Some(Arc::clone(&gate));
        let first = Arc::new(first);
        let reopened = open_database_at(db.path()).await.unwrap();
        let second = ExecutorPrototypeStdioServer::new(registry, reopened, caller, None)
            .await
            .unwrap();
        let prepared = first
            .handle_message(call_message(50, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        let execute = execution_arguments(&prepared);
        let events_before = policy_event_count(&db).await;

        let running = {
            let first = Arc::clone(&first);
            let execute = execute.clone();
            tokio::spawn(async move { first.handle_message(call_message(51, execute)).await })
        };
        let entered = gate.entered.acquire().await.unwrap();
        entered.forget();
        let in_flight = second
            .handle_message(call_message(52, execute.clone()))
            .await
            .unwrap();
        assert_eq!(
            in_flight["result"]["structuredContent"]["plan_error"]["code"],
            "plan_execution_indeterminate"
        );
        gate.release.add_permits(1);
        let executed = running.await.unwrap().unwrap();
        assert!(response_succeeded(&executed), "{executed}");
        let replay = second
            .handle_message(call_message(53, execute))
            .await
            .unwrap();
        assert!(response_succeeded(&replay), "{replay}");
        assert_eq!(
            replay["result"]["_meta"]["nativeWritePlanReplay"]["sourceDispatchCount"],
            1
        );
        assert_eq!(policy_event_count(&db).await, events_before + 1);
    }

    #[tokio::test]
    async fn catalogue_and_server_version_changes_invalidate_a_signed_plan() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000015","type":"Document","kind":"note","name":"Version"}),
        )
        .await
        .unwrap();
        let registry = registry();
        let caller = Caller::local();
        let revision = policy_revision(&registry, &db, caller.clone(), &target).await;
        let mut server = ExecutorPrototypeStdioServer::new(registry, db.clone(), caller, None)
            .await
            .unwrap();
        let events_before = policy_event_count(&db).await;
        let prepared = server
            .handle_message(call_message(42, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        let execute = execution_arguments(&prepared);

        let original_manifest = server.manifest_digest.clone();
        server.manifest_digest = "next-catalogue".into();
        let wrong_catalogue = server
            .handle_message(call_message(43, execute.clone()))
            .await
            .unwrap();
        assert_eq!(
            wrong_catalogue["result"]["structuredContent"]["plan_error"]["code"],
            "plan_contract_mismatch"
        );
        server.manifest_digest = original_manifest;

        let plan_id = prepared["result"]["structuredContent"]["plan_id"]
            .as_str()
            .unwrap();
        let stored = server
            .write_runtime
            .store
            .load(plan_id, now_ms())
            .await
            .unwrap()
            .unwrap();
        let mut plan: WritePlan = serde_json::from_value(stored.payload).unwrap();
        plan.server_version = "older-server".into();
        plan.integrity = server
            .write_runtime
            .store
            .seal(&plan.signing_key_id, &integrity_payload(&plan))
            .await
            .unwrap();
        server
            .write_runtime
            .store
            .replace_payload(
                plan_id,
                &serde_json::to_value(&plan).unwrap(),
                &plan.signing_key_id,
            )
            .await
            .unwrap();
        let wrong_server = server
            .handle_message(call_message(44, execute))
            .await
            .unwrap();
        assert_eq!(
            wrong_server["result"]["structuredContent"]["plan_error"]["code"],
            "plan_contract_mismatch"
        );
        assert_eq!(policy_event_count(&db).await, events_before);
    }

    #[tokio::test]
    async fn plans_reject_wrong_binding_stale_state_and_expiry_without_mutation() {
        let db = create_database(":memory:").await.unwrap();
        let registry = registry();
        let caller = Caller::local();

        let binding_target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000016","type":"Document","kind":"note","name":"Binding"}),
        )
        .await
        .unwrap();
        let binding_revision =
            policy_revision(&registry, &db, caller.clone(), &binding_target).await;
        let mut binding_server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), caller.clone(), None)
                .await
                .unwrap();
        let binding_plan = binding_server
            .handle_message(call_message(
                10,
                preparation_arguments(&binding_target, &binding_revision),
            ))
            .await
            .unwrap();
        let binding_execute = execution_arguments(&binding_plan);
        let events_before = policy_event_count(&db).await;
        binding_server.caller = Caller::authenticated("different-actor");
        let wrong_actor = binding_server
            .handle_message(call_message(11, binding_execute.clone()))
            .await
            .unwrap();
        assert_eq!(
            wrong_actor["result"]["structuredContent"]["plan_error"]["code"],
            "plan_identity_mismatch"
        );
        binding_server.caller = caller
            .clone()
            .with_hosting_context("local", "different-workspace");
        let wrong_workspace = binding_server
            .handle_message(call_message(12, binding_execute))
            .await
            .unwrap();
        assert_eq!(
            wrong_workspace["result"]["structuredContent"]["plan_error"]["code"],
            "plan_identity_mismatch"
        );
        let other_db = create_database(":memory:").await.unwrap();
        binding_server.caller = caller.clone();
        binding_server.engine = EngineHandle::Sqlite(other_db);
        let wrong_database = binding_server
            .handle_message(call_message(13, execution_arguments(&binding_plan)))
            .await
            .unwrap();
        assert_eq!(
            wrong_database["result"]["structuredContent"]["plan_error"]["code"],
            "plan_identity_mismatch"
        );
        assert_eq!(policy_event_count(&db).await, events_before);

        let stale_target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000017","type":"Document","kind":"note","name":"Before rename"}),
        )
        .await
        .unwrap();
        let stale_revision = policy_revision(&registry, &db, caller.clone(), &stale_target).await;
        let stale_server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), caller.clone(), None)
                .await
                .unwrap();
        let stale_plan = stale_server
            .handle_message(call_message(
                14,
                preparation_arguments(&stale_target, &stale_revision),
            ))
            .await
            .unwrap();
        update_record(&db, &stale_target, json!({"name":"After rename"}))
            .await
            .unwrap();
        let stale = stale_server
            .handle_message(call_message(15, execution_arguments(&stale_plan)))
            .await
            .unwrap();
        assert_eq!(
            stale["result"]["structuredContent"]["plan_error"]["code"],
            "plan_stale"
        );
        assert_eq!(policy_event_count(&db).await, events_before);

        let revision_target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000018","type":"Document","kind":"note","name":"Revision"}),
        )
        .await
        .unwrap();
        let expected_revision =
            policy_revision(&registry, &db, caller.clone(), &revision_target).await;
        let revision_server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), caller.clone(), None)
                .await
                .unwrap();
        let revision_plan = revision_server
            .handle_message(call_message(
                16,
                preparation_arguments(&revision_target, &expected_revision),
            ))
            .await
            .unwrap();
        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_record_policy",
                json!({
                    "action":"grant",
                    "record_id":revision_target,
                    "subject":{"kind":"account","account_id":"revision-observer"},
                    "capability":"view",
                    "if_policy_revision":expected_revision,
                    "reason":"Change the policy revision after plan preparation"
                }),
            )
            .await
            .unwrap();
        let events_after_revision_change = policy_event_count(&db).await;
        let stale_revision = revision_server
            .handle_message(call_message(17, execution_arguments(&revision_plan)))
            .await
            .unwrap();
        assert_eq!(
            stale_revision["result"]["structuredContent"]["plan_error"]["code"],
            "plan_stale"
        );
        assert_eq!(policy_event_count(&db).await, events_after_revision_change);

        let expiry_target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000019","type":"Document","kind":"note","name":"Expiry"}),
        )
        .await
        .unwrap();
        let expiry_revision = policy_revision(&registry, &db, caller.clone(), &expiry_target).await;
        let mut expiry_server =
            ExecutorPrototypeStdioServer::new(registry, db.clone(), caller, None)
                .await
                .unwrap();
        expiry_server.write_runtime =
            WriteRuntime::with_ttl_ms(Arc::clone(&expiry_server.write_runtime.store), 0);
        let expired_plan = expiry_server
            .handle_message(call_message(
                18,
                preparation_arguments(&expiry_target, &expiry_revision),
            ))
            .await
            .unwrap();
        let expired = expiry_server
            .handle_message(call_message(19, execution_arguments(&expired_plan)))
            .await
            .unwrap();
        assert_eq!(
            expired["result"]["structuredContent"]["plan_error"]["code"],
            "plan_expired"
        );
        assert_eq!(policy_event_count(&db).await, events_after_revision_change);
    }

    #[tokio::test]
    async fn authorization_and_policy_revision_are_rechecked_before_dispatch() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000020","type":"Document","kind":"note","name":"Authorization"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:grant-plan-author",
            &target,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        let registry = registry();
        let caller = Caller::authenticated("plan-author");
        let revision = policy_revision(&registry, &db, caller.clone(), &target).await;
        let server = ExecutorPrototypeStdioServer::new(registry, db.clone(), caller, None)
            .await
            .unwrap();
        let prepared = server
            .handle_message(call_message(20, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        replace_explicit_policy(&db, "test:revoke-plan-author", &target, vec![])
            .await
            .unwrap();
        let events_before_execute = policy_event_count(&db).await;
        let denied = server
            .handle_message(call_message(21, execution_arguments(&prepared)))
            .await
            .unwrap();
        assert_eq!(
            denied["result"]["structuredContent"]["plan_error"]["code"],
            "plan_revalidation_failed"
        );
        assert_eq!(policy_event_count(&db).await, events_before_execute);
        assert_eq!(
            server
                .trace_events()
                .iter()
                .filter(|event| event["kind"] == "write_plan_executed")
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn destructive_routes_prepare_without_mutation_and_dispatch_exactly_once() {
        let db = create_database(":memory:").await.unwrap();
        let registry = registry();
        let caller = Caller::local();

        let delete_id = create_record(
            &db,
            json!({"id":PLAN_DELETE_ID,"type":"Document","kind":"note","name":"Delete"}),
        )
        .await
        .unwrap();
        let parent_id = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000021","type":"Document","kind":"note","name":"Parent"}),
        )
        .await
        .unwrap();
        let attachment_id = registry
            .call(
                db.clone(),
                caller.clone(),
                "attach_text",
                json!({
                    "record_id":parent_id,
                    "text":"signed attachment",
                    "filename":"signed.txt"
                }),
            )
            .await
            .unwrap()["attachment_id"]
            .as_str()
            .unwrap()
            .to_string();
        for record in [
            json!({"id":"ec00b000-0000-4000-8000-000000000022","type":"WorkItem","kind":"task","name":"Bearer"}),
            json!({"id":"ec00b000-0000-4000-8000-000000000023","type":"Document","kind":"note","name":"Source","body":"alpha beta"}),
            json!({"id":PLAN_CITATION_ID,"type":"Annotation","kind":"citation","name":"Citation"}),
        ] {
            create_record(&db, record).await.unwrap();
        }
        crate::store::add_link(
            &db,
            crate::events::LinkAddedPayload {
                id: None,
                source_id: PLAN_CITATION_ID.into(),
                target_id: "ec00b000-0000-4000-8000-000000000022".into(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();
        registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_citations",
                json!({
                    "action":"reanchor",
                    "citation_id":PLAN_CITATION_ID,
                    "target":{
                        "target_record_id":"ec00b000-0000-4000-8000-000000000023",
                        "source_slot":"body",
                        "selectors":[{"type":"text_quote","exact":"alpha"}]
                    },
                    "reason":"Anchor before destructive-plan coverage"
                }),
            )
            .await
            .unwrap();
        let mut connection = db.write_pool().acquire().await.unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = ON")
            .execute(&mut *connection)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE annotation_targets SET selectors='legacy:not-json' WHERE annotation_id='plan-citation'",
        )
        .execute(&mut *connection)
        .await
        .unwrap();
        sqlx::query("PRAGMA ignore_check_constraints = OFF")
            .execute(&mut *connection)
            .await
            .unwrap();
        drop(connection);
        let server = ExecutorPrototypeStdioServer::new(
            Arc::clone(&registry),
            db.clone(),
            caller.clone(),
            None,
        )
        .await
        .unwrap();
        let mut revalidation_server =
            ExecutorPrototypeStdioServer::new(registry, db.clone(), caller, None)
                .await
                .unwrap();
        let revalidation_gate = DispatchGate::new();
        revalidation_server.write_runtime.revalidation_gate = Some(Arc::clone(&revalidation_gate));
        let revalidation_server = Arc::new(revalidation_server);

        let cases = [
            (
                DELETE_RECORD_OPERATION,
                json!({"id":delete_id,"reason":"Delete through the signed plan route"}),
                "record.deleted",
                PLAN_DELETE_ID,
            ),
            (
                DETACH_ATTACHMENT_OPERATION,
                json!({"attachment_id":attachment_id}),
                "record.deleted",
                attachment_id.as_str(),
            ),
            (
                REMOVE_CITATION_OPERATION,
                json!({"citation_id":PLAN_CITATION_ID,"reason":"Remove through the signed plan route"}),
                "annotation.target.removed",
                PLAN_CITATION_ID,
            ),
        ];
        for (index, (operation, arguments, _, _)) in cases.iter().enumerate() {
            let mut forged = arguments.as_object().unwrap().clone();
            forged.insert("if_content_seq".into(), json!(1));
            let rejected = server
                .handle_message(executor_call_message(
                    280 + index as u64,
                    RECORDS_DELETE_EXECUTOR,
                    json!({"operation":operation,"arguments":forged}),
                ))
                .await
                .unwrap();
            assert_eq!(
                rejected["result"]["structuredContent"]["plan_error"]["code"],
                "preparation_validation_failed"
            );
            assert!(rejected["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("content revision is source-owned"));
            assert!(!rejected.to_string().contains("contract_drift"));
        }
        for (index, (operation, arguments, event_type, record_id)) in cases.into_iter().enumerate()
        {
            let before: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type=?",
            )
            .bind(record_id)
            .bind(event_type)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
            let prepared = server
                .handle_message(executor_call_message(
                    300 + index as u64 * 4,
                    RECORDS_DELETE_EXECUTOR,
                    json!({"operation":operation,"arguments":arguments}),
                ))
                .await
                .unwrap();
            assert!(response_succeeded(&prepared), "{prepared}");
            assert_eq!(
                prepared["result"]["structuredContent"]["preparation_mutated"],
                false
            );
            let after_prepare: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type=?",
            )
            .bind(record_id)
            .bind(event_type)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
            assert_eq!(after_prepare, before);

            let execute = execution_arguments_for(operation, &prepared);
            let advancing = {
                let revalidation_server = Arc::clone(&revalidation_server);
                let execute = execute.clone();
                tokio::spawn(async move {
                    revalidation_server
                        .handle_message(executor_call_message(
                            302 + index as u64 * 4,
                            RECORDS_DELETE_EXECUTOR,
                            execute,
                        ))
                        .await
                })
            };
            let entered = revalidation_gate.entered.acquire().await.unwrap();
            entered.forget();
            let executed = server
                .handle_message(executor_call_message(
                    301 + index as u64 * 4,
                    RECORDS_DELETE_EXECUTOR,
                    execute.clone(),
                ))
                .await
                .unwrap();
            assert!(response_succeeded(&executed), "{executed}");
            revalidation_gate.release.add_permits(1);
            let replay = advancing.await.unwrap().unwrap();
            assert!(response_succeeded(&replay), "{replay}");
            assert_eq!(
                replay["result"]["_meta"]["nativeWritePlanReplay"]["sourceDispatchCount"],
                1
            );
            let terminal_replay = server
                .handle_message(executor_call_message(
                    303 + index as u64 * 4,
                    RECORDS_DELETE_EXECUTOR,
                    execute,
                ))
                .await
                .unwrap();
            assert!(response_succeeded(&terminal_replay), "{terminal_replay}");
            assert_eq!(
                terminal_replay["result"]["_meta"]["nativeWritePlanReplay"]["sourceDispatchCount"],
                1
            );
            let after_execute: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type=?",
            )
            .bind(record_id)
            .bind(event_type)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
            assert_eq!(after_execute, before + 1);
        }
    }
}
