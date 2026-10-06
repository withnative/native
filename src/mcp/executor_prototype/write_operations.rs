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

#[path = "sql_selected_write/mod.rs"]
mod selected;

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
const MEMBERSHIP_CREATE_GUEST_LINK_OPERATION: &str = "manage_memberships.create_guest_link";
const MEMBERSHIP_REVOKE_GUEST_LINK_OPERATION: &str = "manage_memberships.revoke_guest_link";
const WORKSPACE_EXECUTOR: &str = "workspace_read";
const WORKSPACE_LIST_OPERATION: &str = "workspace_read.list";
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
const SQL_WRITE_TTL_MS: i64 = 600_000;
/// Preview-only SQL write pair. Its plan-required source and executor are
/// advertised only when the deployment allowlists `sql_write`.
const SQL_WRITE_EXECUTOR: &str = "sql_write";
const SQL_WRITE_OPERATION: &str = "sql_write";

/// Operation-specific plan TTL selection.
///
/// `sql_write` preview plans get ten minutes; every other operation keeps
/// the two-minute default. Classification and admission are handled separately.
pub(super) fn plan_ttl_ms(executor: &str, operation: &str) -> i64 {
    if executor == SQL_WRITE_EXECUTOR && operation == SQL_WRITE_OPERATION {
        SQL_WRITE_TTL_MS
    } else {
        DEFAULT_TTL_MS
    }
}
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
    (
        MEMBERSHIP_EXECUTOR,
        MEMBERSHIP_CREATE_GUEST_LINK_OPERATION,
        PlanPolicy::RequiredSupported,
    ),
    (
        MEMBERSHIP_EXECUTOR,
        MEMBERSHIP_REVOKE_GUEST_LINK_OPERATION,
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
    // Preview-only SQL-selected edits (E4 M1). The preparer runs the caller
    // SELECT through the governed read path and checks versions and Edit
    // authorization in the same transaction before rolling back; preparation
    // provably does not mutate. Admitted only under the experimental
    // allowlist; there is no commit route in this milestone.
    (
        SQL_WRITE_EXECUTOR,
        SQL_WRITE_OPERATION,
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
            | (MEMBERSHIP_EXECUTOR, MEMBERSHIP_CREATE_GUEST_LINK_OPERATION)
            | (MEMBERSHIP_EXECUTOR, MEMBERSHIP_REVOKE_GUEST_LINK_OPERATION)
    )
}

fn is_hosted_atomic_membership_operation(executor: &str, operation: &str) -> bool {
    matches!(
        (executor, operation),
        (MEMBERSHIP_EXECUTOR, MEMBERSHIP_SET_ROLE_OPERATION)
            | (MEMBERSHIP_REMOVE_EXECUTOR, MEMBERSHIP_REMOVE_OPERATION)
    )
}

/// The hosted workspace directory. It is `Direct` — a read needs no plan —
/// yet it must never be advertised without hosted authority: the source tool
/// is absent from every non-hosted registry, and this gate keeps that true
/// even for a registry that registered it.
pub(super) fn is_workspace_operation(executor: &str, operation: &str) -> bool {
    matches!(
        (executor, operation),
        (WORKSPACE_EXECUTOR, WORKSPACE_LIST_OPERATION)
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
        // Preview-only SQL writes: the shape is validated by the preview
        // preparer's own argument parsing during preparation, which is the
        // dry run. The preparer stays authoritative for bounds and parity.
        (SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION) => {
            if source.get("selection_contract").is_some() {
                selected::validate(source)
            } else if source.get("folder_id").is_some() || source.get("write").is_some() {
                Err(Error::conflict("sql_write: folder_id/write require selection_contract native.sql-write-selection.v1"))
            } else {
                Ok(())
            }
        }
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
    #[cfg(test)]
    claim_attempts: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    dispatch_attempts: std::sync::atomic::AtomicUsize,
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
            #[cfg(test)]
            claim_attempts: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            dispatch_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    fn with_ttl_ms(store: Arc<PlanStore>, ttl_ms: i64) -> Self {
        Self {
            store,
            ttl_ms,
            dispatch_gate: None,
            revalidation_gate: None,
            claim_attempts: std::sync::atomic::AtomicUsize::new(0),
            dispatch_attempts: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn ttl_for(&self, executor: &str, operation: &str) -> i64 {
        if executor == SQL_WRITE_EXECUTOR && operation == SQL_WRITE_OPERATION {
            plan_ttl_ms(executor, operation)
        } else {
            self.ttl_ms
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

#[cfg(test)]
tokio::task_local! {
    static SQL_RELOAD_GATE: Arc<DispatchGate>;
    static SQL_TEST_CLOCK: Arc<std::sync::atomic::AtomicI64>;
}
#[cfg(test)]
async fn wait_sql_reload_gate(executor: &str) {
    if executor == SQL_WRITE_EXECUTOR {
        if let Ok(gate) = SQL_RELOAD_GATE.try_with(Arc::clone) {
            gate.entered.add_permits(1);
            gate.release
                .acquire()
                .await
                .expect("SQL reload gate open")
                .forget();
        }
    }
}

fn now_ms() -> i64 {
    #[cfg(test)]
    if let Ok(clock) = SQL_TEST_CLOCK.try_with(Arc::clone) {
        return clock.load(std::sync::atomic::Ordering::Relaxed);
    }
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
        (MEMBERSHIP_EXECUTOR, MEMBERSHIP_CREATE_GUEST_LINK_OPERATION) => Some("create_guest_link"),
        (MEMBERSHIP_EXECUTOR, MEMBERSHIP_REVOKE_GUEST_LINK_OPERATION) => Some("revoke_guest_link"),
        (CANVAS_WRITE_EXECUTOR, CANVAS_PROMOTE_OPERATION) => Some("promote"),
        // Preview-only SQL writes carry no source action selector: the single
        // `sql_write` source tool is the whole contract.
        (SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION) => None,
        _ => {
            return Err(Error::engine(format!(
                "{executor}.{operation} has no exact source-argument route"
            )))
        }
    };
    if (executor, operation) == (SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION) {
        for field in object.keys() {
            if ![
                "statement",
                "parameters",
                "reason",
                "expected_version",
                "link_note",
                "selection_contract",
                "folder_id",
                "write",
            ]
            .contains(&field.as_str())
            {
                return Err(Error::engine(format!(
                    "sql_write.sql_write has no field '{field}'; known fields are statement, parameters, reason, expected_version, link_note, selection_contract, folder_id, write"
                )));
            }
        }
    }
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

/// Request shape for the preview-only `sql_write` preparer (E4 M1).
///
/// One portable read SELECT yielding typed operation rows
/// (`set_field`/`set_facet`/`unset_facet`/`archive`/`add_link`) over the
/// caller-visible logical catalog, plus the caller-visible `reason` and an
/// optional expected content sequence. Unknown fields are rejected; submitted
/// SQL is never authority for physical writes.
///
/// `link_note` is an optional directed note carried with an `add_link`
/// candidate. It is admitted only when non-blank and within
/// [`SQL_WRITE_MAX_LINK_NOTE_CHARS`] Unicode scalar values, and only when the
/// selection actually contains an `add_link` row; a note without a link
/// refuses rather than silently signing into nothing. The note is effective
/// only when the preview would create a new directed proposition; re-adding an
/// existing one appends support and ignores it. A `remove_link` selection
/// never carries a note: the singular remove passes `None` unconditionally,
/// so a note alongside a removal refuses.
///
/// `expected_version` pins exactly one record. A multi-target selection has no
/// single revision, so supplying it alongside more than one distinct target is
/// refused rather than interpreted: multi-target version integrity comes from
/// the signed per-target `previous_seq` set instead, and any concurrent edit
/// changes that set and revalidates as `plan_stale`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SqlWritePreviewArgs {
    statement: String,
    // Coupling note (Native b0b7419): this shares `QuerySqlParameter`'s
    // deserializer, so the parse layer accepts bare scalars here too — but
    // the sql_write source schema stays typed-only by design, and the
    // executor validates arguments against that schema before parsing. Net
    // behaviour is unchanged: bare scalars are still rejected at the schema
    // layer with the typed-only repair. Widening sql_write is out of scope.
    #[serde(default)]
    parameters: Vec<crate::query::sql_contract::QuerySqlParameter>,
    reason: String,
    #[serde(default)]
    expected_version: Option<i64>,
    #[serde(default)]
    link_note: Option<String>,
}

#[derive(Debug)]
struct SqlWritePreparation {
    canonical_source_arguments: Value,
    target_id: String,
    target: String,
    state_revision: String,
    target_state_digest: String,
    effect: Value,
    effect_summary: String,
    operation_evidence: Value,
}

/// The admitted typed-operation kinds. `set_field` edits `name`/`summary`;
/// `set_facet` sets one open facet's current value, matching
/// `update_record.facets` and never an observation-only write; `unset_facet`
/// clears one open facet (SQL NULL value), matching `update_record.facets`
/// with an explicit null (absent facet has `changed:false` projected state);
/// `archive` is the whole-record lifecycle transition matching
/// `archive_record`/`batch_write`, never a `set_facet` of the
/// engine-reserved `archived` key; `add_link` is the directed
/// `legacy_link.v1` compatibility proposition over `relates_to`, matching
/// `manage_links.add`'s relationship-owned route (never the content/Message
/// content/Message `link.added` fallback); `remove_link` contests that same
/// directed proposition, matching `manage_links.remove`'s relationship-owned
/// route (never the content-owned `link.removed` fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlWriteOpKind {
    SetField,
    SetFacet,
    UnsetFacet,
    Archive,
    AddLink,
    RemoveLink,
}

impl SqlWriteOpKind {
    fn as_str(self) -> &'static str {
        match self {
            SqlWriteOpKind::SetField => "set_field",
            SqlWriteOpKind::SetFacet => "set_facet",
            SqlWriteOpKind::UnsetFacet => "unset_facet",
            SqlWriteOpKind::Archive => "archive",
            SqlWriteOpKind::AddLink => "add_link",
            SqlWriteOpKind::RemoveLink => "remove_link",
        }
    }
}

/// One parsed typed operation row before per-record resolution. Row order is
/// canonicalized after parsing, so this is also the sort unit.
#[derive(Debug)]
struct ParsedSqlWriteOp {
    record_id: String,
    kind: SqlWriteOpKind,
    key: String,
    value: String,
}

/// One resolved governed operation. `before`/`after` are the exact signed
/// values; neither is ever clipped, and the target's `previous_seq` pins the
/// revision it was read at. Facet operations additionally sign the exact
/// before/after vocabulary references, so a value-equal but reference-different
/// write is not mistaken for a no-op. Archive operations sign the exact archived
/// before/after booleans and carry no vocabulary reference. Field operations
/// leave both `None` and are emitted without those keys, preserving the existing
/// field effect shape.
#[derive(Debug)]
struct SqlWriteResolvedOp {
    kind: SqlWriteOpKind,
    key: String,
    value: String,
    before: Value,
    after: Value,
    before_vocab_ref: Option<String>,
    after_vocab_ref: Option<String>,
    changed: bool,
    /// Present only for `add_link`. Field/facet/archive operations leave this
    /// `None` and emit exactly their existing effect shape.
    link: Option<SqlWriteResolvedLink>,
}

/// One observed directed `legacy_link.v1` proposition and the guaranteed
/// mutation intent, read in the same governed snapshot as the endpoints.
///
/// It signs the *observed* relationship state (identity, status, effective and
/// epistemic state, the assertion-set digest and support/contest counts) plus
/// the guaranteed intent. It deliberately does **not** sign a projected
/// post-append `effective_state`: appending support to an existing active
/// proposition can leave effective/epistemic state unchanged and does not
/// bump an endpoint content seq, so only the assertion-set digest (and counts)
/// make that drift observable on revalidation.
#[derive(Debug)]
struct SqlWriteResolvedLink {
    route: &'static str,
    source_id: String,
    source_previous_seq: i64,
    target_id: String,
    target_previous_seq: i64,
    proposition_key: String,
    existing: Option<SqlWriteObservedRelationship>,
    intent: &'static str,
    note: Option<String>,
    note_applied: bool,
}

#[derive(Debug)]
struct SqlWriteObservedRelationship {
    relationship_id: String,
    status: String,
    effective_state: Option<String>,
    epistemic_state: Option<String>,
    assertion_set_digest: Option<String>,
    support_count: Option<i64>,
    contest_count: Option<i64>,
}

#[derive(Debug)]
struct SqlWriteTarget {
    record_id: String,
    previous_seq: i64,
    name: String,
    ops: Vec<SqlWriteResolvedOp>,
}

/// Caller-controlled proposal bounds, refused rather than clipped: the
/// signed effect must stay predictably small, and silent clipping would
/// corrupt the proposal a future commit path must execute exactly. No
/// singular-tool per-field cap exists for `name`/`summary`/`reason`, so
/// these are preview policy, not reused limits; the statement and
/// parameters are already capped by the governed request validator.
const SQL_WRITE_MAX_VALUE_CHARS: usize = 1024;
/// Facet-key bound. Keys are caller-controlled text and enter the signed effect
/// and summary; a query cell can be far larger than any value bound, so a 50-op
/// plan is only bounded once the key itself is bounded too. This is preview
/// policy, not a singular-tool limit.
const SQL_WRITE_MAX_FACET_KEY_CHARS: usize = 120;
/// Vocabulary references are engine-resident text (`rec:<vocabulary_id>`), so
/// they are bounded before signing exactly like a facet value; an oversized
/// stored or derived reference refuses rather than inflating the effect.
const SQL_WRITE_MAX_VOCAB_REF_CHARS: usize = 1024;
const SQL_WRITE_MAX_REASON_CHARS: usize = 1024;
/// Directed-note bound for an `add_link` candidate. The note enters the signed
/// envelope, so it is refused rather than clipped past this bound, exactly like
/// a proposed value. Like the other bounds here it is preview policy, not a
/// singular-tool limit.
const SQL_WRITE_MAX_LINK_NOTE_CHARS: usize = 1024;
/// Display bound for target/effect text built from engine-resident record
/// text (unbounded physical TEXT). Clipping is explicit (`...`) and
/// char-boundary safe; semantic `effect` values are never clipped.
const SQL_WRITE_MAX_DISPLAY_CHARS: usize = 120;
/// Distinct record cap. The total typed-operation set is independently capped
/// at [`SQL_WRITE_MAX_OPS`], and the distinct-target count is derived from that
/// complete set, so this is exact regardless of how many rows one record
/// contributes.
const SQL_WRITE_MAX_TARGETS: usize = 25;
/// Fixed policy cap on the complete typed-operation set. This is deliberately
/// not `SQL_WRITE_MAX_TARGETS * 2`: `set_field` alone admitted two keys per
/// record, but `set_facet` admits any open facet key, so one record can carry
/// more than two operations. Completeness is still proved by the single
/// `LIMIT SQL_WRITE_OP_ROW_LIMIT` probe, and the distinct-target cap is derived
/// from the complete ≤50-row result rather than a rows-per-record ratio.
const SQL_WRITE_MAX_OPS: usize = 50;
/// Overflow probe: request one row beyond the complete-operation bound so a
/// truncated selection is refused, never digested. A complete 50-row result
/// fixes the distinct ID set, so counting its distinct IDs is exact and needs
/// no second, volatile run of the caller's SELECT.
const SQL_WRITE_OP_ROW_LIMIT: i64 = SQL_WRITE_MAX_OPS as i64 + 1;
/// Domain separator mixed into the sorted target-set digest so an equivalent
/// digest computed for another payload cannot be confused with this one.
const SQL_WRITE_TARGET_DOMAIN: &str = "native.sql-write.target-set.v1";
/// Effect-summary sample bound: the signed effect carries every operation, but
/// the human-readable summary samples at most this many and then says how many
/// it omitted, explicitly.
const SQL_WRITE_SUMMARY_SAMPLE_OPS: usize = 3;
/// Internal identity for an `archive` row. Archive carries SQL NULL `key` and
/// `value` (there is no caller facet), so this sentinel participates only in
/// duplicate detection and canonical ordering and is never signed into the
/// effect or the summary.
const SQL_WRITE_ARCHIVE_KEY: &str = "\u{0}archive";
/// The only admitted `add_link` operation and relation key. W2's note-carrying
/// `manage_links.add` relationship is the directed `legacy_link.v1`
/// compatibility proposition, not the symmetric core `relates_to.v1` assertion
/// path. [`resolve_sql_write_add_link`] admits and resolves the op through that
/// same relationship-owned route; the content/Message `link.added` fallback is
/// refused.
const SQL_WRITE_ADD_LINK_OP: &str = "add_link";
const SQL_WRITE_REMOVE_LINK_OP: &str = "remove_link";
const SQL_WRITE_ADD_LINK_KEY: &str = "relates_to";
/// Signed route marker for the directed compatibility proposition. The
/// content/Message `link.added` fallback is refused, so this is the only route.
const SQL_WRITE_LINK_ROUTE: &str = "directed_legacy_link";
/// Guaranteed intent: a new proposition is created, or an existing active one
/// gains another support assertion. Neither is ever a no-op.
const SQL_WRITE_LINK_INTENT_CREATE: &str = "would_create_relationship";
const SQL_WRITE_LINK_INTENT_APPEND: &str = "would_append_support";
/// Guaranteed intent for a directed removal: the existing active proposition
/// gains another contest assertion. Absent or inactive propositions refuse
/// rather than previewing a no-op, exactly as the singular route does.
const SQL_WRITE_LINK_INTENT_CONTEST: &str = "would_contest";

fn sql_write_display(text: &str) -> String {
    if text.chars().count() > SQL_WRITE_MAX_DISPLAY_CHARS {
        format!(
            "{}...",
            text.chars()
                .take(SQL_WRITE_MAX_DISPLAY_CHARS)
                .collect::<String>()
        )
    } else {
        text.to_string()
    }
}

/// Bounded, order-independent human-readable effect summary. Samples at most
/// [`SQL_WRITE_SUMMARY_SAMPLE_OPS`] operations and then states the omitted
/// count explicitly; display text is clipped, semantic `effect` values are not.
fn sql_write_effect_summary(targets: &[SqlWriteTarget], op_count: usize) -> String {
    let plural = |count: usize| if count == 1 { "" } else { "s" };
    let mut summary = format!(
        "set {op_count} operation{} on {} record{}",
        plural(op_count),
        targets.len(),
        plural(targets.len())
    );
    let mut sampled = 0usize;
    let mut omitted = 0usize;
    let mut parts = Vec::new();
    for target in targets {
        for op in &target.ops {
            if sampled < SQL_WRITE_SUMMARY_SAMPLE_OPS {
                sampled += 1;
                // Field rendering is kept byte-identical to the pre-facet
                // summary so existing field-only plans do not move.
                match op.kind {
                    SqlWriteOpKind::SetField => parts.push(format!(
                        "{} of {} ({}) -> {}",
                        op.key,
                        sql_write_display(&target.name),
                        target.record_id,
                        sql_write_display(&op.value),
                    )),
                    SqlWriteOpKind::SetFacet => parts.push(format!(
                        "set_facet '{}' of {} ({}) -> {}",
                        op.key,
                        sql_write_display(&target.name),
                        target.record_id,
                        sql_write_display(&op.value),
                    )),
                    // An unset names the cleared facet; the signed effect
                    // carries the before/after absence, so the summary stays
                    // identical for changed and already-absent projected-state unsets.
                    SqlWriteOpKind::UnsetFacet => parts.push(format!(
                        "unset_facet '{}' of {} ({})",
                        op.key,
                        sql_write_display(&target.name),
                        target.record_id,
                    )),
                    // Archive is lifecycle, not a facet assertion, so it has
                    // no key or value to render; the target name and ID carry
                    // the identity, and the signed effect carries the
                    // before/after archived state.
                    SqlWriteOpKind::Archive => parts.push(format!(
                        "archive of {} ({})",
                        sql_write_display(&target.name),
                        target.record_id,
                    )),
                    // A directed link is a pair, so the summary names the
                    // source and the (bounded) target id, and states the
                    // guaranteed intent. An existing proposition appends
                    // support and ignores the passed note; that is stated
                    // rather than presented as a no-op.
                    SqlWriteOpKind::AddLink => {
                        let link = op
                            .link
                            .as_ref()
                            .expect("add_link op carries its resolved link detail");
                        let target_display = sql_write_display(&link.target_id);
                        let suffix = if link.intent == SQL_WRITE_LINK_INTENT_APPEND {
                            if link.note.is_some() {
                                "appends support; note ignored"
                            } else {
                                "appends support"
                            }
                        } else if link.note_applied {
                            "new relationship with note"
                        } else {
                            "new relationship"
                        };
                        parts.push(format!(
                            "add_link {} {} ({}) -> {} ({suffix})",
                            op.key,
                            sql_write_display(&target.name),
                            target.record_id,
                            target_display,
                        ))
                    }
                    // A directed removal is a pair like an add, so the summary
                    // names the source and the bounded target id and states the
                    // guaranteed contest intent. It is never a no-op: absent or
                    // inactive propositions refuse rather than previewing one.
                    SqlWriteOpKind::RemoveLink => {
                        let link = op
                            .link
                            .as_ref()
                            .expect("remove_link op carries its resolved link detail");
                        parts.push(format!(
                            "remove_link {} {} ({}) -> {} (would contest relationship)",
                            op.key,
                            sql_write_display(&target.name),
                            target.record_id,
                            sql_write_display(&link.target_id),
                        ))
                    }
                }
            } else {
                omitted += 1;
            }
        }
    }
    if !parts.is_empty() {
        summary.push_str(": ");
        summary.push_str(&parts.join("; "));
    }
    if omitted > 0 {
        summary.push_str(&format!("; (+{omitted} more operation{})", plural(omitted)));
    }
    summary
}

/// Truthful non-mutating preparation for a bounded typed-operation set.
///
/// Runs the caller's SELECT through the governed in-transaction read path
/// (portable validator plus caller-relative catalog relations), then checks
/// every target's version and Edit authorization in that same transaction
/// before rolling it back. Appends no event and calls no mutation handler.
///
/// M1 admits `set_field` on `name` or `summary`, string-valued `set_facet`
/// on any open facet key (a current assertion matching `update_record.facets`,
/// never an observation-only write), `unset_facet` on any open facet key with
/// a SQL NULL `value` (matching `update_record.facets` with an explicit null;
/// absent facet prepares `changed:false` projected state), whole-record `archive`
/// (its `key` and `value` are SQL NULL; it requires Manage), and directed
/// `add_link` (`key` is `relates_to`, `value` is a non-blank target id, with
/// an optional top-level `link_note`), and directed `remove_link` (`key` is
/// `relates_to`, `value` is a non-blank target id, never with a `link_note`)
/// over at most 25
/// distinct visible records, at most one operation per `(record_id, key)`, and
/// no extra columns. Archive never mixes with another operation on the same
/// record, and a link never mixes with a content edit on the same source. Each
/// `add_link` mirrors the singular `manage_links.add` relationship-owned route
/// in the same transaction: Edit source, View target, bearer immutability, the
/// directed proposition probe, and the same retired refusal. Each `remove_link`
/// mirrors the singular `manage_links.remove` relationship-owned route the
/// same way: Edit source, View target, bearer immutability, the directed
/// proposition probe, and the same absent, inactive, retired, and
/// content-owned refusals. Facet values are governed through the shared
/// schema/vocabulary fold in the same transaction; the exact governed
/// `vocab_ref` is signed. A complete result is proved by requesting one row
/// beyond the 50-operation policy cap: either that row arrives or the engine
/// reports truncation. Rows are canonically sorted so caller row order cannot
/// change the signed target, effect, or digest.
async fn prepare_sql_write_preview(
    db: &crate::Db,
    caller: &Caller,
    arguments: Value,
) -> Result<SqlWritePreparation> {
    if arguments.get("selection_contract").is_some() {
        return selected::prepare(db, caller, arguments).await;
    }
    const TOOL: &str = "sql_write";
    let args: SqlWritePreviewArgs = super::super::tools::parse_args(TOOL, arguments)?;
    super::super::tools::require_nonblank_reason(TOOL, &args.reason)?;
    if args.reason.chars().count() > SQL_WRITE_MAX_REASON_CHARS {
        return Err(Error::engine(format!(
            "{TOOL}: 'reason' exceeds {SQL_WRITE_MAX_REASON_CHARS} characters"
        )));
    }
    if args.statement.trim().is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: 'statement' must be a portable read SELECT"
        )));
    }
    // A supplied note is bounded before the selection runs: it can only matter
    // with an `add_link` row, but the bound is unconditional so a malformed
    // note never depends on what the caller's SQL happens to return.
    if let Some(note) = args.link_note.as_deref() {
        if note.trim().is_empty() {
            return Err(Error::engine(format!(
                "{TOOL}: 'link_note' must be non-blank when supplied"
            )));
        }
        if note.chars().count() > SQL_WRITE_MAX_LINK_NOTE_CHARS {
            return Err(Error::engine(format!(
                "{TOOL}: 'link_note' exceeds {SQL_WRITE_MAX_LINK_NOTE_CHARS} characters"
            )));
        }
    }
    let mut tx = db.write_pool().begin().await?;
    let request = crate::query::sql_contract::QuerySqlRequest {
        sql: args.statement.clone(),
        parameters: args.parameters.clone(),
    };
    let principal: crate::query::QueryPrincipal = caller.into();
    let (result, _) = crate::query::sql::query_sql_request_in_with_row_limit(
        &mut tx,
        principal,
        request,
        SQL_WRITE_OP_ROW_LIMIT,
        crate::query::sql_contract::FunctionAllowance::Portable,
    )
    .await
    .map_err(|error| Error::engine(format!("{TOOL}: selection rejected: {error}")))?;
    // The probe row beyond the operation cap is how completeness is proved:
    // 50 typed rows is the fixed policy cap over any mix of admitted
    // operations, so anything past the cap refuses instead of digesting a
    // truncation. The distinct-ID cap below is then exact over a complete set.
    if result.truncated || result.rows.len() > SQL_WRITE_MAX_OPS {
        return Err(Error::conflict(format!(
            "{TOOL}: selection exceeds the {SQL_WRITE_MAX_OPS}-operation preview bound; narrow the statement"
        )));
    }
    if result.rows.is_empty() {
        return Err(Error::conflict(format!(
            "{TOOL}: selection returned no visible operation row"
        )));
    }
    // Parse and canonicalize the typed rows before any per-record check, so a
    // malformed or duplicate row refuses even when another target is fine.
    let mut seen = std::collections::HashSet::new();
    let mut parsed: Vec<ParsedSqlWriteOp> = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        let object = row
            .as_object()
            .ok_or_else(|| Error::conflict(format!("{TOOL}: operation row must be an object")))?;
        for key in object.keys() {
            if !matches!(key.as_str(), "record_id" | "op" | "key" | "value") {
                return Err(Error::conflict(format!(
                    "{TOOL}: unknown operation field '{key}'"
                )));
            }
        }
        let missing =
            |field: &str| Error::conflict(format!("{TOOL}: operation row is missing '{field}'"));
        let record_id = object
            .get("record_id")
            .and_then(Value::as_str)
            .ok_or_else(|| missing("record_id"))?;
        // Every row field is validated, including rows the previous contract
        // increment skipped: a blank source id is malformed shape, and must not
        // reach the not-found path as if it were a missing record.
        if record_id.trim().is_empty() {
            return Err(Error::conflict(format!(
                "{TOOL}: operation row 'record_id' must be non-blank"
            )));
        }
        let op = object
            .get("op")
            .and_then(Value::as_str)
            .ok_or_else(|| missing("op"))?;
        let kind = match op {
            "set_field" => SqlWriteOpKind::SetField,
            "set_facet" => SqlWriteOpKind::SetFacet,
            "unset_facet" => SqlWriteOpKind::UnsetFacet,
            "archive" => SqlWriteOpKind::Archive,
            SQL_WRITE_ADD_LINK_OP => SqlWriteOpKind::AddLink,
            SQL_WRITE_REMOVE_LINK_OP => SqlWriteOpKind::RemoveLink,
            other => {
                return Err(Error::conflict(format!(
                    "{TOOL}: unsupported operation '{other}'; M1 admits only set_field, set_facet, unset_facet, archive, add_link, and remove_link"
                )));
            }
        };
        // `value` must be present on every admitted row. Extra columns already
        // refused above, so `key` and `value` are the only payload columns.
        let value_cell = object.get("value").ok_or_else(|| missing("value"))?;
        let (key, value) = if kind == SqlWriteOpKind::Archive {
            // Archive is the whole-record lifecycle transition matching
            // `archive_record`/`batch_write`, never a `set_facet` of the
            // engine-reserved `archived` key. It carries no payload, so both
            // `key` and `value` must be present SQL NULL; a non-null cell
            // refuses rather than being reinterpreted as a facet write.
            let key_cell = object.get("key").ok_or_else(|| missing("key"))?;
            if !key_cell.is_null() {
                return Err(Error::conflict(format!(
                    "{TOOL}: archive row requires a SQL NULL 'key'; got {key_cell}"
                )));
            }
            if !value_cell.is_null() {
                return Err(Error::conflict(format!(
                    "{TOOL}: archive row requires a SQL NULL 'value'; got {value_cell}"
                )));
            }
            (SQL_WRITE_ARCHIVE_KEY.to_string(), "true".to_string())
        } else if kind == SqlWriteOpKind::UnsetFacet {
            // `unset_facet` clears one open facet, matching
            // `update_record.facets` with an explicit null. It carries no
            // value, so `value` must be present SQL NULL; a non-null cell
            // refuses rather than being reinterpreted as a set.
            if !value_cell.is_null() {
                return Err(Error::conflict(format!(
                    "{TOOL}: unset_facet row requires a SQL NULL 'value'; got {value_cell}"
                )));
            }
            let key_cell = object.get("key").ok_or_else(|| missing("key"))?;
            let raw_key = key_cell.as_str().ok_or_else(|| {
                Error::conflict(format!(
                    "{TOOL}: unset_facet row requires a string 'key'; got {key_cell}"
                ))
            })?;
            crate::domain_transaction::assert_open_facet_key(TOOL, raw_key)
                .map_err(|error| Error::conflict(error.to_string()))?;
            if raw_key.chars().count() > SQL_WRITE_MAX_FACET_KEY_CHARS {
                return Err(Error::conflict(format!(
                    "{TOOL}: facet key exceeds {SQL_WRITE_MAX_FACET_KEY_CHARS} characters"
                )));
            }
            (raw_key.to_string(), String::new())
        } else {
            // `value` must be a present JSON string for every field/set-facet
            // and link M1 op. A SQL NULL (or any non-string) refuses rather
            // than silently folding.
            let value = value_cell.as_str().ok_or_else(|| {
                Error::conflict(format!(
                    "{TOOL}: operation row 'value' must be a JSON string; got {value_cell}"
                ))
            })?;
            let raw_key = object
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| missing("key"))?;
            let key = match kind {
                SqlWriteOpKind::SetField => match raw_key {
                    "name" => "name".to_string(),
                    "summary" => "summary".to_string(),
                    other => {
                        return Err(Error::conflict(format!(
                            "{TOOL}: unsupported set_field key '{other}'; the compiler admits only name and summary"
                        )));
                    }
                },
                SqlWriteOpKind::SetFacet => {
                    // Reuse the singular-tool open-key guard so engine-reserved,
                    // spine, and exact governed-relationship names refuse here
                    // exactly as they do in `update_record.facets`.
                    crate::domain_transaction::assert_open_facet_key(TOOL, raw_key)
                        .map_err(|error| Error::conflict(error.to_string()))?;
                    // The key is caller-controlled and is signed into the effect
                    // and summary; bound it before admission.
                    if raw_key.chars().count() > SQL_WRITE_MAX_FACET_KEY_CHARS {
                        return Err(Error::conflict(format!(
                            "{TOOL}: facet key exceeds {SQL_WRITE_MAX_FACET_KEY_CHARS} characters"
                        )));
                    }
                    raw_key.to_string()
                }
                SqlWriteOpKind::AddLink => {
                    // The only admitted directed relationship token. Self-links
                    // are allowed by the singular tool, so none is refused here.
                    if raw_key != SQL_WRITE_ADD_LINK_KEY {
                        return Err(Error::conflict(format!(
                            "{TOOL}: unsupported add_link key '{raw_key}'; the directed compiler admits only {SQL_WRITE_ADD_LINK_KEY}"
                        )));
                    }
                    raw_key.to_string()
                }
                SqlWriteOpKind::RemoveLink => {
                    // The only admitted directed relationship token, shared
                    // with `add_link`. Self-links are allowed by the singular
                    // remove route, so none is refused here either.
                    if raw_key != SQL_WRITE_ADD_LINK_KEY {
                        return Err(Error::conflict(format!(
                            "{TOOL}: unsupported remove_link key '{raw_key}'; the directed compiler admits only {SQL_WRITE_ADD_LINK_KEY}"
                        )));
                    }
                    raw_key.to_string()
                }
                // Handled by the archive/unset branches above.
                SqlWriteOpKind::Archive | SqlWriteOpKind::UnsetFacet => {
                    unreachable!("archive/unset parse their NULL value shape above")
                }
            };
            (key, value.to_string())
        };
        if kind == SqlWriteOpKind::SetField && key == "name" && value.trim().is_empty() {
            return Err(Error::conflict(format!(
                "{TOOL}: set_field name must be non-blank"
            )));
        }
        if kind == SqlWriteOpKind::AddLink && value.trim().is_empty() {
            return Err(Error::conflict(format!(
                "{TOOL}: add_link value must be a non-blank target id"
            )));
        }
        if kind == SqlWriteOpKind::RemoveLink && value.trim().is_empty() {
            return Err(Error::conflict(format!(
                "{TOOL}: remove_link value must be a non-blank target id"
            )));
        }
        if value.chars().count() > SQL_WRITE_MAX_VALUE_CHARS {
            return Err(Error::conflict(format!(
                "{TOOL}: {op} value exceeds {SQL_WRITE_MAX_VALUE_CHARS} characters"
            )));
        }
        if !seen.insert((record_id.to_string(), key.clone())) {
            return Err(Error::conflict(format!(
                "{TOOL}: duplicate '{key}' for record {record_id}; each record admits at most one operation per key"
            )));
        }
        parsed.push(ParsedSqlWriteOp {
            record_id: record_id.to_string(),
            kind,
            key,
            value,
        });
    }
    let has_add_link = parsed.iter().any(|op| op.kind == SqlWriteOpKind::AddLink);
    let has_remove_link = parsed
        .iter()
        .any(|op| op.kind == SqlWriteOpKind::RemoveLink);
    // A removal carries no note: the singular `manage_links.remove` passes
    // `None` unconditionally, so a note alongside a `remove_link` row refuses
    // with its own message rather than the generic orphan-note one below.
    if args.link_note.is_some() && has_remove_link {
        return Err(Error::conflict(format!(
            "{TOOL}: 'link_note' is only valid with an add_link selection; remove_link carries no note"
        )));
    }
    // A note has no meaning without a link to carry it, so it refuses rather
    // than being silently dropped from an ordinary preparation.
    if args.link_note.is_some() && !has_add_link {
        return Err(Error::conflict(format!(
            "{TOOL}: 'link_note' is only valid when the selection includes an add_link operation"
        )));
    }
    // A directed link assertion and a content edit on the same source are not
    // proved atomic against the singular tools, so the combination refuses.
    // Both link kinds share the source set; the message names the link op on
    // that source so an `add_link` mix keeps its existing wording.
    let link_records: std::collections::HashSet<&str> = parsed
        .iter()
        .filter(|op| {
            matches!(
                op.kind,
                SqlWriteOpKind::AddLink | SqlWriteOpKind::RemoveLink
            )
        })
        .map(|op| op.record_id.as_str())
        .collect();
    if let Some(mixed) = parsed.iter().find(|op| {
        !matches!(
            op.kind,
            SqlWriteOpKind::AddLink | SqlWriteOpKind::RemoveLink
        ) && link_records.contains(op.record_id.as_str())
    }) {
        let record_id = mixed.record_id.as_str();
        let link_op = if parsed
            .iter()
            .any(|op| op.record_id.as_str() == record_id && op.kind == SqlWriteOpKind::RemoveLink)
        {
            "remove_link"
        } else {
            "add_link"
        };
        return Err(Error::conflict(format!(
            "{TOOL}: record {record_id} mixes '{link_op}' with another operation; M1 does not prove that combination atomic against the singular tools"
        )));
    }
    // Archive is a whole-record lifecycle transition. M1 has not proved that
    // mixing it with a field or facet operation on the same record is atomic
    // against the singular tools, so the combination refuses. A duplicate
    // archive row for one record is already refused by the `(record_id, key)`
    // uniqueness check above, since both rows share the archive sentinel key.
    let archive_records: std::collections::HashSet<&str> = parsed
        .iter()
        .filter(|op| op.kind == SqlWriteOpKind::Archive)
        .map(|op| op.record_id.as_str())
        .collect();
    if let Some(record_id) = parsed
        .iter()
        .find(|op| {
            op.kind != SqlWriteOpKind::Archive && archive_records.contains(op.record_id.as_str())
        })
        .map(|op| op.record_id.as_str())
    {
        return Err(Error::conflict(format!(
            "{TOOL}: record {record_id} mixes 'archive' with another operation; M1 does not prove that combination atomic against the singular tools"
        )));
    }
    // Canonical sort makes caller row order irrelevant to every signed field.
    // `(record_id, key)` is unique after the duplicate refusal above, so the
    // sort is total and deterministic.
    parsed.sort_by(|left, right| (&left.record_id, &left.key).cmp(&(&right.record_id, &right.key)));
    let mut distinct_targets: Vec<String> = parsed.iter().map(|op| op.record_id.clone()).collect();
    distinct_targets.dedup();
    if distinct_targets.len() > SQL_WRITE_MAX_TARGETS {
        return Err(Error::conflict(format!(
            "{TOOL}: selection targets {} distinct records; the preview admits at most {SQL_WRITE_MAX_TARGETS}",
            distinct_targets.len()
        )));
    }
    if args.expected_version.is_some() && distinct_targets.len() > 1 {
        return Err(Error::conflict(format!(
            "{TOOL}: 'expected_version' pins one record but the selection targets {} distinct records; omit it and rely on the signed per-target versions",
            distinct_targets.len()
        )));
    }
    // Facet rows resolve through the shared schema/vocabulary fold, which reads
    // the declaration cascade; read it once inside this same transaction.
    // Field-only selections never pay for it.
    let schema_rows = if parsed.iter().any(|op| {
        matches!(
            op.kind,
            SqlWriteOpKind::SetFacet | SqlWriteOpKind::UnsetFacet
        )
    }) {
        Some(crate::query::cascade::schema_config_rows_in(&mut tx).await?)
    } else {
        None
    };
    let mut targets: Vec<SqlWriteTarget> = Vec::with_capacity(distinct_targets.len());
    for record_id in &distinct_targets {
        // Archive is a lifecycle transition and requires Manage, exactly as
        // `archive_record` and `batch_write`'s archive item do. Field and facet
        // edits keep the weaker Edit requirement.
        let target_has_archive = parsed
            .iter()
            .any(|op| &op.record_id == record_id && op.kind == SqlWriteOpKind::Archive);
        // Both link kinds skip the archived-source refusal below: neither
        // singular link route has one, so this preview mirrors those routes
        // rather than inventing a narrower one.
        let target_has_link = parsed.iter().any(|op| {
            &op.record_id == record_id
                && matches!(
                    op.kind,
                    SqlWriteOpKind::AddLink | SqlWriteOpKind::RemoveLink
                )
        });
        let required = if target_has_archive {
            crate::authorization::Capability::Manage
        } else {
            crate::authorization::Capability::Edit
        };
        super::super::tools::require_record_in(&mut tx, caller, TOOL, record_id, required)
            .await
            .map_err(|error| match error {
                // Infrastructure failures stay non-stale; lost visibility,
                // Edit, or Manage is selection drift. The message is preserved
                // verbatim, so hidden and missing targets keep refusing
                // identically.
                Error::Sqlx(_) => error,
                other => Error::conflict(other.to_string()),
            })?;
        // Temporary ambiguity guard (E4 M1; E3 M1 stays open): a live
        // incoming `supersedes` link means the preview cannot establish the
        // target as current. This refuses rather than proving whole-record
        // supersession. It runs after authorization so hidden and missing
        // targets keep refusing identically above, and it never names the
        // successor (id, name, or count), so a visible target with a hidden
        // successor refuses with the same stable string as one with a
        // visible successor. A tombstoned successor discloses nothing, and
        // the same probe re-runs on revalidation, where this `Conflict`
        // maps to `plan_stale`.
        let superseded: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM links l JOIN records s ON s.id = l.source_id WHERE l.relationship = 'supersedes' AND l.target_id = ? AND s.deleted_at IS NULL)",
        )
        .bind(record_id)
        .fetch_one(&mut *tx)
        .await?;
        if superseded != 0 {
            return Err(Error::conflict(format!(
                "{TOOL}: selected record {record_id} has an incoming supersedes link; SQL write preview cannot establish current target"
            )));
        }
        // Link sources deliberately skip the archived-source refusal: neither
        // singular link route has one, so this preview mirrors those routes
        // rather than inventing a narrower one. A tombstoned or missing
        // source still refuses through `require_record_in` above and
        // `previous_record_seq_in` below.
        let was_archived = if target_has_link {
            false
        } else {
            let archived: i64 = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM facet_values WHERE record_id = ? AND key = ?)",
            )
            .bind(record_id)
            .bind(crate::schema::ARCHIVED_FACET_KEY)
            .fetch_one(&mut *tx)
            .await?;
            // An already-archived target refuses every edit/facet operation,
            // but an archive op is the transition itself: it prepares as a
            // `changed:false` no-op rather than refusing, matching
            // `archive_record` and the batch archive item.
            if archived != 0 && !target_has_archive {
                return Err(Error::conflict(format!(
                    "{TOOL}: selected record {record_id} is archived; restore it before preparing an edit"
                )));
            }
            archived != 0
        };
        let previous_seq = super::super::tools::previous_record_seq_in(&mut tx, record_id)
            .await?
            .ok_or_else(|| Error::conflict(format!("{TOOL}: record {record_id} does not exist")))?;
        if args
            .expected_version
            .is_some_and(|expected| expected != previous_seq)
        {
            return Err(Error::conflict(format!(
                "{TOOL}: content revision conflict; get the record and prepare again"
            )));
        }
        let current: (String, Option<String>, String, Option<String>) =
            sqlx::query_as::<_, (String, Option<String>, String, Option<String>)>(
                "SELECT name, summary, type, kind FROM records WHERE id = ? AND deleted_at IS NULL",
            )
            .bind(record_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| Error::conflict(format!("{TOOL}: record {record_id} does not exist")))?;
        let (current_name, current_summary, record_type, record_kind) = current;
        let mut ops = Vec::new();
        for parsed_op in parsed.iter().filter(|op| &op.record_id == record_id) {
            match parsed_op.kind {
                SqlWriteOpKind::SetField => {
                    let before = if parsed_op.key == "name" {
                        json!(current_name.clone())
                    } else {
                        json!(current_summary.clone())
                    };
                    let existing = if parsed_op.key == "name" {
                        current_name.as_str()
                    } else {
                        current_summary.as_deref().unwrap_or("")
                    };
                    // The signed `before` carries the exact stored value, so an
                    // oversized stored field is refused like an oversized
                    // proposal: no clipping of semantic fields, ever.
                    if existing.chars().count() > SQL_WRITE_MAX_VALUE_CHARS {
                        return Err(Error::conflict(format!(
                            "{TOOL}: existing {} exceeds {SQL_WRITE_MAX_VALUE_CHARS} characters; the preview bound covers the replaced value too",
                            parsed_op.key
                        )));
                    }
                    let after = json!(parsed_op.value);
                    ops.push(SqlWriteResolvedOp {
                        kind: SqlWriteOpKind::SetField,
                        key: parsed_op.key.clone(),
                        value: parsed_op.value.clone(),
                        before: before.clone(),
                        after: after.clone(),
                        before_vocab_ref: None,
                        after_vocab_ref: None,
                        changed: before != after,
                        link: None,
                    });
                }
                SqlWriteOpKind::SetFacet => {
                    // Exact parity with `update_record.facets`: a Message's
                    // sender-authored expectation facet is immutable in place.
                    if parsed_op.key == crate::message_expectation::EXPECTATION_FACET_KEY
                        && record_type == "Message"
                    {
                        return Err(Error::conflict(format!(
                            "{TOOL}: Message expectation is immutable sender-authored content; create a superseding Message to correct it"
                        )));
                    }
                    let op = resolve_sql_write_facet(
                        &mut tx,
                        schema_rows
                            .as_ref()
                            .expect("a facet row implies schema rows were read"),
                        record_id,
                        &record_type,
                        record_kind.as_deref(),
                        &parsed_op.key,
                        &parsed_op.value,
                    )
                    .await?;
                    ops.push(op);
                }
                SqlWriteOpKind::UnsetFacet => {
                    // Exact parity with `update_record.facets` explicit-null
                    // unset: a Message's expectation facet is immutable in
                    // place, whether set or cleared.
                    if parsed_op.key == crate::message_expectation::EXPECTATION_FACET_KEY
                        && record_type == "Message"
                    {
                        return Err(Error::conflict(format!(
                            "{TOOL}: Message expectation is immutable sender-authored content; create a superseding Message to correct it"
                        )));
                    }
                    let op = resolve_sql_write_facet_unset(
                        &mut tx,
                        schema_rows
                            .as_ref()
                            .expect("a facet row implies schema rows were read"),
                        record_id,
                        &record_type,
                        record_kind.as_deref(),
                        &parsed_op.key,
                    )
                    .await?;
                    ops.push(op);
                }
                SqlWriteOpKind::Archive => {
                    // Lifecycle transition, never a facet assertion: the signed
                    // before/after are the exact archived state read in this
                    // snapshot, and the proposed event matches `archive_record`
                    // (`facet.set` on the engine-reserved `archived` key). An
                    // already-archived target signs `changed:false`.
                    ops.push(SqlWriteResolvedOp {
                        kind: SqlWriteOpKind::Archive,
                        key: SQL_WRITE_ARCHIVE_KEY.to_string(),
                        value: "true".to_string(),
                        before: json!(was_archived),
                        after: json!(true),
                        before_vocab_ref: None,
                        after_vocab_ref: None,
                        changed: !was_archived,
                        link: None,
                    });
                }
                SqlWriteOpKind::AddLink => {
                    // Directed `legacy_link.v1` compatibility proposition,
                    // resolved in this same transaction. A re-add is never a
                    // no-op: it appends another support assertion, and the
                    // passed note is ignored by the singular route.
                    ops.push(
                        resolve_sql_write_add_link(
                            &mut tx,
                            caller,
                            record_id,
                            previous_seq,
                            &parsed_op.value,
                            args.link_note.as_deref(),
                        )
                        .await?,
                    );
                }
                SqlWriteOpKind::RemoveLink => {
                    // Directed `legacy_link.v1` compatibility contest, resolved
                    // in this same transaction. Absent or inactive propositions
                    // refuse rather than previewing a no-op, exactly as the
                    // singular remove route does.
                    ops.push(
                        resolve_sql_write_remove_link(
                            &mut tx,
                            caller,
                            record_id,
                            previous_seq,
                            &parsed_op.value,
                        )
                        .await?,
                    );
                }
            }
        }
        targets.push(SqlWriteTarget {
            record_id: record_id.clone(),
            previous_seq,
            name: current_name,
            ops,
        });
    }
    let target_evidence: Vec<Value> = targets
        .iter()
        .map(|target| {
            json!({
                "record_id": &target.record_id,
                "previous_seq": target.previous_seq,
            })
        })
        .collect();
    // Domain-separated digest of the sorted IDs plus their pinned versions:
    // stable under row order and sensitive to any set or version change.
    let target_state_digest = digest(&json!({
        "domain": SQL_WRITE_TARGET_DOMAIN,
        "targets": target_evidence,
    }))?;
    let target_count = targets.len();
    let op_count: usize = targets.iter().map(|target| target.ops.len()).sum();
    let changed = targets
        .iter()
        .any(|target| target.ops.iter().any(|op| op.changed));
    let operation_evidence = json!({
        "kind": "sql_write_preview",
        "target_count": target_count,
        "op_count": op_count,
        "targets": target_evidence,
    });
    let mut effect_targets = Vec::with_capacity(target_count);
    for target in &targets {
        let ops: Vec<Value> = target
            .ops
            .iter()
            .map(|op| {
                // Field operations keep exactly their pre-facet keys; facet
                // operations add the two exact vocabulary references. Archive is
                // deliberately its own shape: the typed row's `key`/`value` were
                // SQL NULL, so the effect signs the exact archived before/after
                // rather than inventing a facet payload.
                match op.kind {
                    SqlWriteOpKind::SetField => json!({
                        "op": op.kind.as_str(),
                        "key": &op.key,
                        "value": &op.value,
                        "before": &op.before,
                        "after": &op.after,
                        "changed": op.changed,
                    }),
                    SqlWriteOpKind::SetFacet => json!({
                        "op": op.kind.as_str(),
                        "key": &op.key,
                        "value": &op.value,
                        "before": &op.before,
                        "after": &op.after,
                        "before_vocab_ref": &op.before_vocab_ref,
                        "after_vocab_ref": &op.after_vocab_ref,
                        "changed": op.changed,
                    }),
                    // An unset carries a SQL NULL value by construction, so
                    // the effect signs an explicit null `value`/`after`/
                    // `after_vocab_ref`; `before`/`before_vocab_ref` sign the
                    // exact current absence or stored pair.
                    SqlWriteOpKind::UnsetFacet => json!({
                        "op": op.kind.as_str(),
                        "key": &op.key,
                        "value": Value::Null,
                        "before": &op.before,
                        "after": Value::Null,
                        "before_vocab_ref": &op.before_vocab_ref,
                        "after_vocab_ref": Value::Null,
                        "changed": op.changed,
                    }),
                    SqlWriteOpKind::Archive => json!({
                        "op": op.kind.as_str(),
                        "before": &op.before,
                        "after": &op.after,
                        "changed": op.changed,
                    }),
                    SqlWriteOpKind::AddLink => {
                        let link = op
                            .link
                            .as_ref()
                            .expect("add_link op carries its resolved link detail");
                        json!({
                            "op": op.kind.as_str(),
                            "relationship": &op.key,
                            "route": link.route,
                            "source_id": &link.source_id,
                            "source_previous_seq": link.source_previous_seq,
                            "target_id": &link.target_id,
                            "target_previous_seq": link.target_previous_seq,
                            "proposition_key": &link.proposition_key,
                            "existing": link.existing.as_ref().map(|existing| json!({
                                "relationship_id": &existing.relationship_id,
                                "status": &existing.status,
                                "effective_state": &existing.effective_state,
                                "epistemic_state": &existing.epistemic_state,
                                "assertion_set_digest": &existing.assertion_set_digest,
                                "support_count": existing.support_count,
                                "contest_count": existing.contest_count,
                            })),
                            "intent": link.intent,
                            "note": &link.note,
                            "note_applied": link.note_applied,
                            "changed": op.changed,
                        })
                    }
                    SqlWriteOpKind::RemoveLink => {
                        // Same signed shape as an add: the observed before
                        // state plus the guaranteed contest intent. A removal
                        // carries no note, so both note fields sign their
                        // absent values rather than being omitted.
                        let link = op
                            .link
                            .as_ref()
                            .expect("remove_link op carries its resolved link detail");
                        json!({
                            "op": op.kind.as_str(),
                            "relationship": &op.key,
                            "route": link.route,
                            "source_id": &link.source_id,
                            "source_previous_seq": link.source_previous_seq,
                            "target_id": &link.target_id,
                            "target_previous_seq": link.target_previous_seq,
                            "proposition_key": &link.proposition_key,
                            "existing": link.existing.as_ref().map(|existing| json!({
                                "relationship_id": &existing.relationship_id,
                                "status": &existing.status,
                                "effective_state": &existing.effective_state,
                                "epistemic_state": &existing.epistemic_state,
                                "assertion_set_digest": &existing.assertion_set_digest,
                                "support_count": existing.support_count,
                                "contest_count": existing.contest_count,
                            })),
                            "intent": link.intent,
                            "note": &link.note,
                            "note_applied": link.note_applied,
                            "changed": op.changed,
                        })
                    }
                }
            })
            .collect();
        effect_targets.push(json!({
            "record_id": &target.record_id,
            "previous_seq": target.previous_seq,
            "ops": ops,
        }));
    }
    let effect = json!({
        "kind": "sql_write_preview",
        "targets": effect_targets,
        "target_count": target_count,
        "op_count": op_count,
        "changed": changed,
        "reason": &args.reason,
    });
    // A single target keeps the stricter resolved-version pin; a multi-target
    // selection carries no scalar pin and relies on the signed version set.
    let canonical_expected_version = if target_count == 1 {
        Some(targets[0].previous_seq)
    } else {
        None
    };
    let mut canonical_arguments = json!({
        "statement": &args.statement,
        "parameters": &args.parameters,
        "reason": &args.reason,
        "expected_version": canonical_expected_version,
    });
    // Only present when supplied, so a link-free envelope canonicalizes to the
    // exact four-field object it always did. A link selection carries its note
    // here and into the signed revalidation arguments, so re-adding with a
    // different note is a different plan even though the singular route ignores
    // that note when the proposition already exists.
    if let Some(note) = args.link_note.as_deref() {
        canonical_arguments["link_note"] = json!(note);
    }
    let preparation = SqlWritePreparation {
        canonical_source_arguments: canonical_arguments,
        // A single target keeps its real record ID (unchanged from the
        // one-row contract). A multi-target plan has no single record ID, so
        // it uses a deterministic namespaced digest of the sorted set rather
        // than silently choosing the first record.
        target_id: if target_count == 1 {
            targets[0].record_id.clone()
        } else {
            format!("sql-write-target-set:{target_state_digest}")
        },
        target: format!(
            "{target_count} record{} [{target_state_digest}]",
            if target_count == 1 { "" } else { "s" }
        ),
        state_revision: format!("content-seq-set:{target_state_digest}"),
        target_state_digest,
        effect_summary: sql_write_effect_summary(&targets, op_count),
        effect,
        operation_evidence,
    };
    tx.rollback().await?;
    Ok(preparation)
}

/// Resolve one `set_facet` operation against one target's current state in the
/// same governed transaction.
///
/// Reuses the singular `update_record.facets` semantics: the open-key guard is
/// applied at parse time, the shared schema/vocabulary fold derives the exact
/// post-governance `vocab_ref`, and the signed `(value, vocab_ref)` pair is
/// compared for `changed`, so a value-equal but reference-different write is
/// not mistaken for a no-op. Stored and derived text is bounded before it is
/// signed. Appends no event.
async fn resolve_sql_write_facet(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    schema_rows: &[crate::query::cascade::SchemaConfigRow],
    record_id: &str,
    record_type: &str,
    record_kind: Option<&str>,
    key: &str,
    value: &str,
) -> Result<SqlWriteResolvedOp> {
    const TOOL: &str = "sql_write";
    // Current-state read in the same snapshot; mirrors `facet_state_in`.
    let current: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT value, vocab_ref FROM facet_values WHERE record_id = ? AND key = ?")
            .bind(record_id)
            .bind(key)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some((stored, _)) = &current {
        if stored.chars().count() > SQL_WRITE_MAX_VALUE_CHARS {
            return Err(Error::conflict(format!(
                "{TOOL}: existing facet '{key}' exceeds {SQL_WRITE_MAX_VALUE_CHARS} characters; the preview bound covers the replaced value too"
            )));
        }
    }
    if let Some(vocab_ref) = current
        .as_ref()
        .and_then(|(_, vocab_ref)| vocab_ref.as_ref())
    {
        if vocab_ref.chars().count() > SQL_WRITE_MAX_VOCAB_REF_CHARS {
            return Err(Error::conflict(format!(
                "{TOOL}: existing facet '{key}' vocabulary reference exceeds {SQL_WRITE_MAX_VOCAB_REF_CHARS} characters"
            )));
        }
    }
    // A string-only typed row never supplies a vocab_ref; the shared fold
    // derives the canonical one from the facet's governing vocabulary, exactly
    // as `update_record.facets` does.
    let mut facet = crate::domain_transaction::FacetWrite {
        key: key.to_string(),
        value: Value::String(value.to_string()),
        vocab_ref: None,
        time_type: None,
    };
    {
        let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(&mut *tx);
        crate::domain_transaction::govern_facet_writes(
            &mut executor,
            schema_rows,
            TOOL,
            record_type,
            record_kind,
            std::slice::from_mut(&mut facet),
        )
        .await
        .map_err(|error| match error {
            // The shared governance fold reports rejected shape and vocabulary
            // rules as Engine. During revalidation those are changed plan facts.
            // Preserve transport and storage failures as infrastructure errors.
            Error::Engine(message) => Error::conflict(message),
            other => other,
        })?;
    }
    if let Some(vocab_ref) = &facet.vocab_ref {
        if vocab_ref.chars().count() > SQL_WRITE_MAX_VOCAB_REF_CHARS {
            return Err(Error::conflict(format!(
                "{TOOL}: facet '{key}' governing vocabulary reference exceeds {SQL_WRITE_MAX_VOCAB_REF_CHARS} characters"
            )));
        }
    }
    let before = current.as_ref().map(|(stored, _)| stored.clone());
    let before_vocab_ref = current
        .as_ref()
        .and_then(|(_, vocab_ref)| vocab_ref.clone());
    let changed = (before.as_deref(), before_vocab_ref.as_deref())
        != (Some(value), facet.vocab_ref.as_deref());
    Ok(SqlWriteResolvedOp {
        kind: SqlWriteOpKind::SetFacet,
        key: key.to_string(),
        value: value.to_string(),
        before: match before {
            Some(stored) => json!(stored),
            None => Value::Null,
        },
        after: json!(value),
        before_vocab_ref,
        after_vocab_ref: facet.vocab_ref.clone(),
        changed,
        link: None,
    })
}

/// Resolve one `unset_facet` operation against one target's current state in
/// the same governed transaction.
///
/// Mirrors the singular `update_record.facets` explicit-null unset: the
/// open-key guard is applied at parse time, the current `(value, vocab_ref)`
/// pair is read in this snapshot, and `changed` is whether a facet row
/// exists. A present facet prepares `changed:true` with the exact stored
/// before pair; an absent facet prepares `changed:false` because the projected
/// facet state would stay absent. The singular route still appends an unset
/// event for that case. A present required open facet refuses rather
/// than signing a new required violation, matching `required_violations_in`
/// before/after plus `assert_required_not_worsened` without mutating to
/// simulate: presence implies no current violation for this key, so clearing
/// it would introduce one. No vocabulary governance runs (there is no
/// desired value to govern). Appends no event.
async fn resolve_sql_write_facet_unset(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    schema_rows: &[crate::query::cascade::SchemaConfigRow],
    record_id: &str,
    record_type: &str,
    record_kind: Option<&str>,
    key: &str,
) -> Result<SqlWriteResolvedOp> {
    const TOOL: &str = "sql_write";
    let current: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT value, vocab_ref FROM facet_values WHERE record_id = ? AND key = ?")
            .bind(record_id)
            .bind(key)
            .fetch_optional(&mut **tx)
            .await?;
    if let Some((stored, _)) = &current {
        if stored.chars().count() > SQL_WRITE_MAX_VALUE_CHARS {
            return Err(Error::conflict(format!(
                "{TOOL}: existing facet '{key}' exceeds {SQL_WRITE_MAX_VALUE_CHARS} characters; the preview bound covers the replaced value too"
            )));
        }
    }
    if let Some(vocab_ref) = current
        .as_ref()
        .and_then(|(_, vocab_ref)| vocab_ref.as_ref())
    {
        if vocab_ref.chars().count() > SQL_WRITE_MAX_VOCAB_REF_CHARS {
            return Err(Error::conflict(format!(
                "{TOOL}: existing facet '{key}' vocabulary reference exceeds {SQL_WRITE_MAX_VOCAB_REF_CHARS} characters"
            )));
        }
    }
    let changed = current.is_some();
    if changed {
        let shapes = crate::query::cascade::facets_for_record_context(
            schema_rows,
            record_type,
            record_kind,
            None,
        );
        if shapes
            .get(key)
            .is_some_and(|shape| shape.get("required") == Some(&Value::Bool(true)))
        {
            let kind_suffix = record_kind
                .map(|kind| format!(":{kind}"))
                .unwrap_or_default();
            return Err(Error::conflict(format!(
                "{TOOL}: batch would worsen required-facet conformance: record {record_id} missing required facet '{key}' for {record_type}{kind_suffix}"
            )));
        }
    }
    let (before, before_vocab_ref) = match current {
        Some((stored, vocab_ref)) => (json!(stored), vocab_ref),
        None => (Value::Null, None),
    };
    Ok(SqlWriteResolvedOp {
        kind: SqlWriteOpKind::UnsetFacet,
        key: key.to_string(),
        value: String::new(),
        before,
        after: Value::Null,
        before_vocab_ref,
        after_vocab_ref: None,
        changed,
        link: None,
    })
}

/// Resolve one `add_link` row into the guaranteed directed `legacy_link.v1`
/// mutation intent, read entirely inside the governed preparation
/// transaction.
///
/// Mirrors `manage_links.add`'s relationship-owned route in this same
/// snapshot: `assert_bearer_immutable_on`, the relationship/content classifier
/// (`relationship_owned_in`), `View(target)`, both endpoint content seqs, the
/// canonical proposition key, and the `relationships`/`effective_relationships`
/// probe. A retired proposition refuses exactly as the singular route does.
///
/// The signed evidence is the *observed before state* plus the guaranteed
/// intent: a new proposition would be created (the note is effective), or an
/// existing active proposition would gain another support assertion (the note
/// is ignored). It never invents a projected post-append `effective_state`:
/// appending support can leave effective/epistemic state and both endpoint seqs
/// unchanged, so the assertion-set digest and support/contest counts are signed
/// to make that drift revalidate as `plan_stale`.
async fn resolve_sql_write_add_link(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    source_id: &str,
    source_previous_seq: i64,
    target_id: &str,
    note: Option<&str>,
) -> Result<SqlWriteResolvedOp> {
    const TOOL: &str = "sql_write";
    super::super::tools::require_record_in(
        tx,
        caller,
        TOOL,
        target_id,
        crate::authorization::Capability::View,
    )
    .await
    .map_err(|error| match error {
        Error::Sqlx(_) => error,
        other => Error::conflict(other.to_string()),
    })?;
    // `manage_links.add` checks `assert_bearer_immutable_on(source)` before the
    // route classifier; the relationship-owned path never reaches the
    // content-owned `link.added` fallback, which `relationship_owned_in`
    // rejects below. Storage failures stay non-stale (`Sqlx` is preserved);
    // only a semantic bearer refusal is drift.
    crate::comments::assert_bearer_immutable_on(tx, TOOL, source_id, SQL_WRITE_ADD_LINK_KEY)
        .await
        .map_err(|error| match error {
            Error::Sqlx(_) => error,
            other => Error::conflict(other.to_string()),
        })?;
    let relationship_owned = crate::mcp::tools::links::relationship_owned_in(
        tx,
        source_id,
        target_id,
        SQL_WRITE_ADD_LINK_KEY,
    )
    .await?;
    if !relationship_owned {
        // A Message endpoint or a content-owned token takes the singular
        // `link.added` fallback, whose event semantics differ; this preview
        // refuses that route rather than signing a link event it cannot mirror.
        return Err(Error::conflict(format!(
            "{TOOL}: add_link {SQL_WRITE_ADD_LINK_KEY} from {source_id} to {target_id} is content-owned; the directed compatibility relationship route is required"
        )));
    }
    let target_previous_seq = super::super::tools::previous_record_seq_in(tx, target_id)
        .await?
        .ok_or_else(|| {
            Error::conflict(format!("{TOOL}: link target {target_id} does not exist"))
        })?;
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    let source_ref = crate::identity::encode_native_record(&origin, source_id)?;
    let target_ref = crate::identity::encode_native_record(&origin, target_id)?;
    let proposition = crate::relationship::legacy::proposition_key(
        &source_ref,
        &target_ref,
        SQL_WRITE_ADD_LINK_KEY,
    );
    // The same probe `mutate_with_reserved_attestation_in` runs
    // (`legacy.rs`): look up the proposition by origin, definition, and
    // canonical key, then read its receiver-local reduction. `assertion_set_digest`
    // and the counts are what move when another support assertion is appended.
    type ExistingRelationshipRow = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<i64>,
    );
    let existing: Option<ExistingRelationshipRow> = sqlx::query_as(
        "SELECT r.relationship_id,r.status,e.effective_state,e.epistemic_state,
                    e.assertion_set_digest,e.support_count,e.contest_count
               FROM relationships r LEFT JOIN effective_relationships e
                 ON e.relationship_origin_db_id=r.relationship_origin_db_id
                AND e.relationship_id=r.relationship_id
              WHERE r.relationship_origin_db_id=? AND r.type_definition_id=?
                AND r.canonical_proposition_key=?",
    )
    .bind(&origin)
    .bind(crate::relationship::legacy::LEGACY_LINK_DEFINITION_ID)
    .bind(&proposition)
    .fetch_optional(&mut **tx)
    .await?;
    let existing = match existing {
        None => None,
        Some((
            relationship_id,
            status,
            effective_state,
            epistemic_state,
            assertion_set_digest,
            support_count,
            contest_count,
        )) => {
            // Exactly the singular refusal: a retired proposition is not
            // re-addable through the compatibility route.
            if status != "active" {
                return Err(Error::conflict(format!(
                    "{TOOL}: compatibility relationship is retired; use manage_relationships"
                )));
            }
            Some(SqlWriteObservedRelationship {
                relationship_id,
                status,
                effective_state,
                epistemic_state,
                assertion_set_digest,
                support_count,
                contest_count,
            })
        }
    };
    let intent = if existing.is_some() {
        SQL_WRITE_LINK_INTENT_APPEND
    } else {
        SQL_WRITE_LINK_INTENT_CREATE
    };
    // The note is written only when a relationship is created (create-time /
    // first-wins). Appending support ignores it, exactly as the singular path.
    let note_applied = existing.is_none() && note.is_some();
    Ok(SqlWriteResolvedOp {
        kind: SqlWriteOpKind::AddLink,
        key: SQL_WRITE_ADD_LINK_KEY.to_string(),
        value: target_id.to_string(),
        before: Value::Null,
        after: Value::Null,
        before_vocab_ref: None,
        after_vocab_ref: None,
        // A link add is never a no-op: it creates a proposition or appends a
        // support assertion.
        changed: true,
        link: Some(SqlWriteResolvedLink {
            route: SQL_WRITE_LINK_ROUTE,
            source_id: source_id.to_string(),
            source_previous_seq,
            target_id: target_id.to_string(),
            target_previous_seq,
            proposition_key: proposition,
            existing,
            intent,
            note: note.map(str::to_string),
            note_applied,
        }),
    })
}

/// Resolve one `remove_link` row into the guaranteed directed `legacy_link.v1`
/// contest intent, read entirely inside the governed preparation transaction.
///
/// Mirrors `manage_links.remove`'s relationship-owned route in this same
/// snapshot, in the singular order: `View(target)`,
/// `assert_bearer_immutable_on(source)`, the relationship/content classifier
/// (`relationship_owned_in`), both endpoint content seqs, the canonical
/// proposition key, and the `relationships`/`effective_relationships` probe.
/// Absent, inactive, retired, and content-owned propositions refuse exactly as
/// the singular route does, so each of those drifts revalidates as
/// `plan_stale`.
///
/// The signed evidence is the *observed before state* plus the guaranteed
/// `would_contest` intent. It never invents a projected post-contest
/// `effective_state`: contesting can leave effective/epistemic state and both
/// endpoint seqs unchanged, so the assertion-set digest and support/contest
/// counts are signed to make that drift observable on revalidation. A removal
/// carries no note: the singular route passes `None` unconditionally.
async fn resolve_sql_write_remove_link(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    source_id: &str,
    source_previous_seq: i64,
    target_id: &str,
) -> Result<SqlWriteResolvedOp> {
    const TOOL: &str = "sql_write";
    super::super::tools::require_record_in(
        tx,
        caller,
        TOOL,
        target_id,
        crate::authorization::Capability::View,
    )
    .await
    .map_err(|error| match error {
        Error::Sqlx(_) => error,
        other => Error::conflict(other.to_string()),
    })?;
    // `manage_links.remove` checks `assert_bearer_immutable_on(source)` before
    // the route classifier; the relationship-owned path never reaches the
    // content-owned `link.removed` fallback, which `relationship_owned_in`
    // rejects below. Storage failures stay non-stale (`Sqlx` is preserved);
    // only a semantic bearer refusal is drift.
    crate::comments::assert_bearer_immutable_on(tx, TOOL, source_id, SQL_WRITE_ADD_LINK_KEY)
        .await
        .map_err(|error| match error {
            Error::Sqlx(_) => error,
            other => Error::conflict(other.to_string()),
        })?;
    let relationship_owned = crate::mcp::tools::links::relationship_owned_in(
        tx,
        source_id,
        target_id,
        SQL_WRITE_ADD_LINK_KEY,
    )
    .await?;
    if !relationship_owned {
        // A Message endpoint or a content-owned token takes the singular
        // `link.removed` content-event fallback, whose event semantics differ;
        // this preview refuses that route rather than signing a relationship
        // contest it cannot mirror.
        return Err(Error::conflict(format!(
            "{TOOL}: remove_link {SQL_WRITE_ADD_LINK_KEY} from {source_id} to {target_id} is content-owned; the directed compatibility relationship route is required"
        )));
    }
    let target_previous_seq = super::super::tools::previous_record_seq_in(tx, target_id)
        .await?
        .ok_or_else(|| {
            Error::conflict(format!("{TOOL}: link target {target_id} does not exist"))
        })?;
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    let source_ref = crate::identity::encode_native_record(&origin, source_id)?;
    let target_ref = crate::identity::encode_native_record(&origin, target_id)?;
    let proposition = crate::relationship::legacy::proposition_key(
        &source_ref,
        &target_ref,
        SQL_WRITE_ADD_LINK_KEY,
    );
    // The same probe `mutate_with_reserved_attestation_in` runs for a removal
    // (`legacy.rs`): look up the proposition by origin, definition, and
    // canonical key, then read its receiver-local reduction. `assertion_set_digest`
    // and the counts are what move when another contest assertion is appended.
    type ExistingRelationshipRow = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<i64>,
    );
    let existing: Option<ExistingRelationshipRow> = sqlx::query_as(
        "SELECT r.relationship_id,r.status,e.effective_state,e.epistemic_state,
                    e.assertion_set_digest,e.support_count,e.contest_count
               FROM relationships r LEFT JOIN effective_relationships e
                 ON e.relationship_origin_db_id=r.relationship_origin_db_id
                AND e.relationship_id=r.relationship_id
              WHERE r.relationship_origin_db_id=? AND r.type_definition_id=?
                AND r.canonical_proposition_key=?",
    )
    .bind(&origin)
    .bind(crate::relationship::legacy::LEGACY_LINK_DEFINITION_ID)
    .bind(&proposition)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((
        relationship_id,
        status,
        effective_state,
        epistemic_state,
        assertion_set_digest,
        support_count,
        contest_count,
    )) = existing
    else {
        // Exactly the singular refusal: nothing to contest.
        return Err(Error::conflict(format!(
            "{TOOL}: cannot remove link: no '{SQL_WRITE_ADD_LINK_KEY}' link from {source_id} to {target_id}"
        )));
    };
    // Exactly the singular refusal: only an active proposition can be
    // contested through the compatibility route.
    if effective_state.as_deref() != Some("active") {
        return Err(Error::conflict(format!(
            "{TOOL}: compatibility state is inactive or causally unresolved; use manage_relationships to inspect the assertion frontier"
        )));
    }
    if status != "active" {
        return Err(Error::conflict(format!(
            "{TOOL}: compatibility relationship is retired; use manage_relationships"
        )));
    }
    Ok(SqlWriteResolvedOp {
        kind: SqlWriteOpKind::RemoveLink,
        key: SQL_WRITE_ADD_LINK_KEY.to_string(),
        value: target_id.to_string(),
        before: Value::Null,
        after: Value::Null,
        before_vocab_ref: None,
        after_vocab_ref: None,
        // A link removal is never a no-op: absent or inactive propositions
        // refuse above, so reaching here always appends a contest assertion.
        changed: true,
        link: Some(SqlWriteResolvedLink {
            route: SQL_WRITE_LINK_ROUTE,
            source_id: source_id.to_string(),
            source_previous_seq,
            target_id: target_id.to_string(),
            target_previous_seq,
            proposition_key: proposition,
            existing: Some(SqlWriteObservedRelationship {
                relationship_id,
                status,
                effective_state,
                epistemic_state,
                assertion_set_digest,
                support_count,
                contest_count,
            }),
            intent: SQL_WRITE_LINK_INTENT_CONTEST,
            note: None,
            note_applied: false,
        }),
    })
}

async fn prepare_operation(
    engine: &EngineHandle,
    caller: &Caller,
    hosted_authority: Option<&dyn HostedExecutorAuthority>,
    executor: &str,
    operation: &str,
    operation_arguments: Value,
) -> Result<PreparedWrite> {
    // Preview-only `sql_write` (E4 M1): classified `RequiredSupported`, so the
    // facade admits it once the executor is allowlisted. This arm serves
    // preparation calls and the future revalidation path only; it never
    // dispatches a mutation.
    if (executor, operation) == (SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION) {
        let db = sqlite_engine(engine, "sql write preview")?;
        let prepared = prepare_sql_write_preview(db, caller, operation_arguments).await?;
        return Ok(PreparedWrite {
            revalidation_arguments: prepared.canonical_source_arguments.clone(),
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
            let revalidation_arguments = if operation == MEMBERSHIP_CREATE_INVITATION_OPERATION
                || operation == MEMBERSHIP_CREATE_GUEST_LINK_OPERATION
            {
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
                        MEMBERSHIP_CREATE_GUEST_LINK_OPERATION => "membership_guest_link_create",
                        MEMBERSHIP_REVOKE_GUEST_LINK_OPERATION => "membership_guest_link_revoke",
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
        // Dispatch refuses standby mutations before plan access; this fails
        // the same closed refusal if a plan path is ever reached without one.
        let Some(write_runtime) = self.write_runtime.as_ref() else {
            return self.standby_read_only_response(id, modern, &envelope).await;
        };
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
        // Record-selector aliases normalise to the canonical field before
        // schema validation and preparation, exactly as on the direct
        // paths — so `record_id`/`id`/`ids` spellings prepare the same plan.
        // A malformed selector rejects here with the value-free shape
        // diagnostic; it must not become a state/authorization failure.
        let operation_arguments = match crate::mcp::record_ref::normalize_operation_record_selector(
            &contract.operation,
            operation_arguments.clone(),
        ) {
            Ok(normalized) => normalized,
            Err(error) => {
                let diagnostic =
                    crate::mcp::record_ref::invalid_operation_record_selector_diagnostic(
                        &contract.operation,
                        &operation_arguments,
                    )
                    .map(|diagnostic| diagnostic.to_string())
                    .unwrap_or_else(|| error.to_string());
                return self
                    .write_plan_error(
                        id,
                        modern,
                        &contract,
                        &envelope,
                        telemetry_request.as_ref(),
                        PlanError::new("preparation_validation_failed", &diagnostic, true),
                    )
                    .await;
            }
        };
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
            expires_at_ms: created_at_ms
                .saturating_add(write_runtime.ttl_for(&contract.executor, &contract.operation)),
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
        plan.signing_key_id = match write_runtime.store.active_key_id().await {
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
        plan.integrity = match write_runtime
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
        if let Err(error) = write_runtime
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

    /// Revalidate-only confirmation for a preview-only `sql_write` plan.
    ///
    /// Runs after every signed comparison succeeds and before any claim or
    /// dispatch exists. It reloads the signed row, fails closed on any race
    /// (missing row, payload drift, expiry, or non-Prepared state), then
    /// returns an explicit preview-current success. No `store.claim`, no
    /// source dispatch, no content event: repeated confirmations leave the
    /// plan Prepared.
    #[allow(clippy::too_many_arguments)]
    async fn confirm_sql_write_preview_current(
        &self,
        id: Value,
        modern: bool,
        contract: &OperationContract,
        envelope: &Value,
        plan_id: &str,
        initially_loaded: &StoredPlan,
        plan: &WritePlan,
        telemetry_request: Option<&super::telemetry::TelemetryRequest>,
        started: Instant,
    ) -> Value {
        let Some(write_runtime) = self.write_runtime.as_ref() else {
            return self.standby_read_only_response(id, modern, envelope).await;
        };
        #[cfg(test)]
        wait_sql_reload_gate(&plan.executor).await;
        let reloaded = match write_runtime.store.load(plan_id, now_ms()).await {
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
                            "write plan disappeared before preview confirmation",
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
                        "durable plan row changed before preview confirmation",
                        false,
                    ),
                )
                .await;
        }
        if reloaded.expires_at_ms <= now_ms() {
            return self
                .write_plan_error(
                    id,
                    modern,
                    contract,
                    envelope,
                    telemetry_request,
                    PlanError::new(
                        "plan_expired",
                        "write plan expired before preview confirmation; prepare the current effect again",
                        false,
                    ),
                )
                .await;
        }
        match reloaded.state {
            StoredState::Prepared => {}
            StoredState::Expired => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        contract,
                        envelope,
                        telemetry_request,
                        PlanError::new(
                            "plan_expired",
                            "write plan expired before preview confirmation; prepare the current effect again",
                            false,
                        ),
                    )
                    .await;
            }
            _ => {
                return self
                    .write_plan_error(
                        id,
                        modern,
                        contract,
                        envelope,
                        telemetry_request,
                        PlanError::new(
                            "plan_store_conflict",
                            "write plan left Prepared before preview confirmation; prepare again",
                            false,
                        ),
                    )
                    .await;
            }
        }
        if let (Some(telemetry), Some(request)) = (&self.telemetry, telemetry_request) {
            let request = telemetry.with_plan_correlation(request.clone(), plan_id);
            telemetry.emit(super::telemetry::EventSpec {
                request: Some(request),
                phase: super::telemetry::TelemetryPhase::PlanRevalidated,
                outcome: super::telemetry::TelemetryOutcome::Succeeded,
                counts: super::telemetry::TelemetryCounts {
                    attempt_bucket: super::telemetry::attempt_bucket(1),
                    ..super::telemetry::TelemetryCounts::default()
                },
                latency_bucket: super::telemetry::latency_bucket(elapsed_ms(started)),
                ..super::telemetry::EventSpec::default()
            });
        }
        let response = json!({
            "plan_id":plan.id,
            "executor":plan.executor,
            "operation":plan.operation,
            "preview_current":true,
            "target":plan.target,
            "effect_summary":plan.effect_summary,
            "effect":plan.effect,
            "expires_at":rfc3339_millis(plan.expires_at_ms),
            "state_revision":plan.state_revision,
            "target_state_digest":plan.target_state_digest,
            "operation_evidence":plan.operation_evidence,
            "contract_digest":plan.contract_digest,
            "catalogue_digest":plan.catalogue_digest,
            "server_version":plan.server_version,
            "committed":false,
            "preparation_mutated":false,
            "source_dispatch_count":0,
        });
        let run_context = run_context_for_engine(
            &self.engine,
            self.caller.clone(),
            envelope,
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
            "kind":"write_plan_preview_current",
            "mode":"execute",
            "executor":contract.executor,
            "operation":contract.operation,
            "plan_id":plan.id,
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
        let Some(write_runtime) = self.write_runtime.as_ref() else {
            return self.standby_read_only_response(id, modern, &envelope).await;
        };
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
        let stored = match write_runtime.store.load(&plan_id, now_ms()).await {
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
        if let Err(error) = write_runtime.verify(&plan).await {
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
        if let Some(gate) = &write_runtime.revalidation_gate {
            gate.entered.add_permits(1);
            let permit = gate
                .release
                .acquire()
                .await
                .expect("revalidation gate open");
            permit.forget();
        }
        if plan.executor == SQL_WRITE_EXECUTOR
            && plan.operation == SQL_WRITE_OPERATION
            && plan
                .revalidation_arguments
                .get("selection_contract")
                .is_some()
            && !selected::supported_evidence(&plan.operation_evidence)
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
                        "plan_contract_mismatch",
                        "unsupported or missing selection evidence version; prepare again",
                        false,
                    ),
                )
                .await;
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
                // Preview-only SQL writes classify drift by error type, never
                // by message: the preparer raises `Conflict` for selection,
                // shape, visibility, authorization, version, bound, and facet
                // governance drift, while validator, storage, and digest
                // failures stay non-stale. Every other pair keeps its existing
                // diagnostic-substring classification untouched.
                let code = if (plan.executor.as_str(), plan.operation.as_str())
                    == (SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION)
                {
                    if matches!(error, Error::Conflict(_)) {
                        "plan_stale"
                    } else {
                        "plan_revalidation_failed"
                    }
                } else {
                    let diagnostic = error.to_string();
                    let identity_state_drift = plan.executor == IDENTITY_EXECUTOR
                        && (diagnostic.contains("stale expected owner")
                            || diagnostic.contains("collision"));
                    if diagnostic.contains("revision conflict") || identity_state_drift {
                        "plan_stale"
                    } else {
                        "plan_revalidation_failed"
                    }
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
                        PlanError::new(code, &error.to_string(), false),
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
        // Preview-only `sql_write` (E4 M1): an execute-shaped call is a
        // revalidate-only confirmation. It returns after every signed
        // comparison succeeds and before any claim or dispatch exists, so no
        // commit path is reachable from this pair.
        if (plan.executor.as_str(), plan.operation.as_str())
            == (SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION)
        {
            return self
                .confirm_sql_write_preview_current(
                    id,
                    modern,
                    &contract,
                    &envelope,
                    &plan_id,
                    &stored,
                    &plan,
                    telemetry_request.as_ref(),
                    started,
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
            #[cfg(test)]
            write_runtime
                .claim_attempts
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            match write_runtime.store.claim(&plan_id, now_ms()).await {
                Ok(ClaimOutcome::Claimed {
                    attempt_id,
                    plan: claimed,
                }) => {
                    if claimed.payload != stored.payload
                        || claimed.key_id != stored.key_id
                        || claimed.catalogue_payload_sha256 != stored.catalogue_payload_sha256
                    {
                        let _ = write_runtime
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
        if let Some(gate) = &write_runtime.dispatch_gate {
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
        #[cfg(test)]
        write_runtime
            .dispatch_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            match write_runtime.store.load(&plan_id, now_ms()).await {
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
        if let Err(error) = write_runtime
            .store
            .complete(&plan_id, &attempt_id, &persisted_result, now_ms())
            .await
        {
            let _ = write_runtime
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
        let Some(write_runtime) = self.write_runtime.as_ref() else {
            return self.standby_read_only_response(id, modern, envelope).await;
        };
        #[cfg(test)]
        wait_sql_reload_gate(&plan.executor).await;
        let reloaded = match write_runtime.store.load(plan_id, now_ms()).await {
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

    /// Preview-only SQL writes route through the facade with strict known
    /// fields; unknown fields refuse in canonicalization, and validation
    /// defers shape checks to the authoritative preparer.
    #[test]
    fn sql_write_canonical_arguments_enforce_strict_known_fields() {
        let canonical = canonical_source_arguments(
            SQL_WRITE_EXECUTOR,
            SQL_WRITE_OPERATION,
            json!({"statement": "SELECT 1", "reason": "probe"}),
        )
        .expect("known fields must canonicalize");
        assert_eq!(canonical["statement"], json!("SELECT 1"));
        assert!(
            canonical.get("action").is_none(),
            "sql_write carries no source action selector"
        );
        let unknown = canonical_source_arguments(
            SQL_WRITE_EXECUTOR,
            SQL_WRITE_OPERATION,
            json!({"statement": "SELECT 1", "reason": "probe", "plan_id": "p"}),
        )
        .expect_err("unknown fields must refuse");
        assert!(
            unknown.to_string().contains("known fields are"),
            "{unknown}"
        );
        validate(
            SQL_WRITE_EXECUTOR,
            SQL_WRITE_OPERATION,
            json!({"statement": "SELECT 1", "reason": "probe"}),
            None,
        )
        .expect("validate defers shape checks to the preparer");
        validate(
            SQL_WRITE_EXECUTOR,
            SQL_WRITE_OPERATION,
            json!({"statement": "SELECT 1", "reason": "probe", "bogus": true}),
            None,
        )
        .expect_err("validate must surface the strict-field refusal");
        // The directed note is a known field and survives canonicalization, but
        // it never changes an unrelated field/facet/archive canonical shape.
        let with_note = canonical_source_arguments(
            SQL_WRITE_EXECUTOR,
            SQL_WRITE_OPERATION,
            json!({"statement": "SELECT 1", "reason": "probe", "link_note": "e0-harness"}),
        )
        .expect("link_note is a known field");
        assert_eq!(with_note["link_note"], json!("e0-harness"));
        validate(
            SQL_WRITE_EXECUTOR,
            SQL_WRITE_OPERATION,
            json!({"statement": "SELECT 1", "reason": "probe", "link_note": "e0-harness"}),
            None,
        )
        .expect("validate accepts the known link_note field");
        let selected = json!({"selection_contract":"native.sql-write-selection.v1","folder_id":"c0510000-0000-4000-8000-000000000001","statement":"SELECT id FROM children WHERE archived=false","write":{"op":"archive"},"reason":"Canonical selected facade route."});
        assert_eq!(
            canonical_source_arguments(SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION, selected.clone())
                .unwrap(),
            selected
        );
        validate(SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION, selected, None).unwrap();
    }

    #[tokio::test]
    async fn sql_selected_write_never_attempts_claim_or_dispatch_with_live_control() {
        use std::sync::atomic::Ordering;
        let db = create_database(":memory:").await.unwrap();
        let folder = "ec00b000-0000-4000-8000-000000000bd1";
        let target = "ec00b000-0000-4000-8000-000000000bd2";
        // Independently fixed protocol probe manifest, public setup BEFORE compiler.
        let mut r = ToolRegistry::new();
        register_builtin_tools(&mut r).unwrap();
        register_surface_tools(&mut r).unwrap();
        let experimental =
            crate::mcp::ExperimentalExecutors::from_env_value(Some("sql_write".into())).unwrap();
        crate::mcp::register_allowlisted_experimental_tools(&mut r, &experimental).unwrap();
        for record in [
            json!({"id":folder,"type":"Collection","kind":"folder","name":"Counter scope","persistence":"enduring","reason":"Public protocol scope setup."}),
            json!({"id":target,"type":"Document","kind":"note","name":"Counter target","home_id":folder,"reason":"Public protocol target setup."}),
        ] {
            r.call(db.clone(), Caller::local(), "create_record", record)
                .await
                .unwrap();
        }
        let server = ExecutorPrototypeStdioServer::new_with_telemetry_and_experimental(
            Arc::new(r),
            db.clone(),
            Caller::local(),
            None,
            ExecutorTelemetryContext::new(
                Arc::new(super::telemetry::TestTelemetrySink::default()),
                7,
            )
            .unwrap(),
            experimental,
        )
        .await
        .unwrap();
        let runtime = server.write_runtime.as_ref().unwrap();
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let prepared=server.handle_message(executor_call_message(1,SQL_WRITE_EXECUTOR,json!({"operation":"sql_write","arguments":{"selection_contract":selected::CONTRACT,"folder_id":folder,"statement":"SELECT id FROM children","write":{"op":"archive"},"reason":"Observe counters on preview only."}}))).await.unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        for id in 2..5 {
            let confirmed = server
                .handle_message(executor_call_message(
                    id,
                    SQL_WRITE_EXECUTOR,
                    execution_arguments_for(SQL_WRITE_OPERATION, &prepared),
                ))
                .await
                .unwrap();
            assert!(response_succeeded(&confirmed), "{confirmed}");
            assert_eq!(runtime.claim_attempts.load(Ordering::Relaxed), 0);
            assert_eq!(runtime.dispatch_attempts.load(Ordering::Relaxed), 0);
        }
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(before, after);
        let refused=server.handle_message(executor_call_message(10,SQL_WRITE_EXECUTOR,json!({"operation":"sql_write","arguments":{"selection_contract":selected::CONTRACT,"folder_id":folder,"statement":"SELECT id FROM children WHERE name='absent'","write":{"op":"archive"},"reason":"Refused prepare counter probe."}}))).await.unwrap();
        assert_eq!(
            refused["result"]["structuredContent"]["plan_error"]["code"],
            "preparation_rejected"
        );
        let mut misuse = execution_arguments_for(SQL_WRITE_OPERATION, &prepared);
        misuse["arguments"] = json!({"statement":"SELECT id FROM children"});
        let misuse = server
            .handle_message(executor_call_message(11, SQL_WRITE_EXECUTOR, misuse))
            .await
            .unwrap();
        assert!(!response_succeeded(&misuse));
        assert_eq!(
            before,
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
        // Deliberate public delta is outside the before/after refusal audit.
        server.registry.call(db.clone(),Caller::local(),"update_record",json!({"id":target,"name":"Changed counter target","reason":"Public scoped drift counter probe."})).await.unwrap();
        let drift_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let stale = server
            .handle_message(executor_call_message(
                12,
                SQL_WRITE_EXECUTOR,
                execution_arguments_for(SQL_WRITE_OPERATION, &prepared),
            ))
            .await
            .unwrap();
        assert_eq!(
            stale["result"]["structuredContent"]["plan_error"]["code"],
            "plan_stale"
        );
        let fresh=server.handle_message(executor_call_message(13,SQL_WRITE_EXECUTOR,json!({"operation":"sql_write","arguments":{"selection_contract":selected::CONTRACT,"folder_id":folder,"statement":"SELECT id FROM children","write":{"op":"archive"},"reason":"Expired confirmation counter probe."}}))).await.unwrap();
        assert!(response_succeeded(&fresh), "{fresh}");
        use sqlx::Connection;
        let path = db.path().canonicalize().unwrap();
        let file = path.file_name().unwrap().to_str().unwrap();
        let mut plan_db = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path.with_file_name(format!("{file}.write-plans.sqlite3"))),
        )
        .await
        .unwrap();
        sqlx::query("UPDATE write_plans SET state='expired' WHERE plan_id=?")
            .bind(
                fresh["result"]["structuredContent"]["plan_id"]
                    .as_str()
                    .unwrap(),
            )
            .execute(&mut plan_db)
            .await
            .unwrap();
        plan_db.close().await.unwrap();
        let expired = server
            .handle_message(executor_call_message(
                14,
                SQL_WRITE_EXECUTOR,
                execution_arguments_for(SQL_WRITE_OPERATION, &fresh),
            ))
            .await
            .unwrap();
        assert_eq!(
            expired["result"]["structuredContent"]["plan_error"]["code"],
            "plan_expired"
        );
        assert_eq!(
            drift_before,
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
        assert_eq!(runtime.claim_attempts.load(Ordering::Relaxed), 0);
        assert_eq!(runtime.dispatch_attempts.load(Ordering::Relaxed), 0);
        // Positive control proves these are executed boundary counters, not
        // response constants: a separate ordinary policy plan claims/dispatches.
        let revision = policy_revision(&server.registry, &db, Caller::local(), target).await;
        let control = server
            .handle_message(call_message(5, preparation_arguments(target, &revision)))
            .await
            .unwrap();
        assert!(response_succeeded(&control), "{control}");
        let executed = server
            .handle_message(call_message(6, execution_arguments(&control)))
            .await
            .unwrap();
        assert!(response_succeeded(&executed), "{executed}");
        assert_eq!(runtime.claim_attempts.load(Ordering::Relaxed), 1);
        assert_eq!(runtime.dispatch_attempts.load(Ordering::Relaxed), 1);
    }

    /// Grant `plan-author` Edit (which implies View) on each id, so the link
    /// preview's `require_record_in` checks pass.
    async fn grant_link_edit(db: &crate::Db, ids: &[&str]) {
        for id in ids {
            replace_explicit_policy(
                db,
                "test:sql-write-link",
                id,
                vec![AllowEntry::account("plan-author", Capability::Edit)],
            )
            .await
            .unwrap();
        }
    }

    /// Run the singular relationship-owned `manage_links.add`, so the preview
    /// is compared against the real route rather than a stand-in.
    async fn singular_add_link(
        db: &crate::Db,
        caller: &Caller,
        source: &str,
        target: &str,
        note: Option<&str>,
    ) {
        let mut arguments = json!({
            "action":"add","source_id":source,"target_id":target,"relationship":"relates_to"
        });
        if let Some(note) = note {
            arguments["note"] = json!(note);
        }
        let receipt = registry()
            .call(db.clone(), caller.clone(), "manage_links", arguments)
            .await
            .unwrap();
        assert_eq!(receipt["action"], json!("add"));
    }

    async fn preview_link(
        db: &crate::Db,
        caller: &Caller,
        statement: String,
        note: Option<&str>,
    ) -> Result<SqlWritePreparation> {
        let mut arguments = json!({"statement": statement, "reason": "link probe"});
        if let Some(note) = note {
            arguments["link_note"] = json!(note);
        }
        prepare_sql_write_preview(db, caller, arguments).await
    }

    fn link_row(source: &str, key: &str, value_expr: &str) -> String {
        format!(
            "SELECT id AS record_id, 'add_link' AS op, '{key}' AS key, {value_expr} AS value FROM records WHERE id = '{source}'"
        )
    }

    /// A directed `add_link` previews the singular relationship-owned route: a
    /// first add signs a would-create intent with a note that is effective, and
    /// re-adding signs a would-append-support intent that ignores the passed
    /// note. `e0-harness` is a W2 test fixture value only; production never
    /// names it.
    #[tokio::test]
    async fn sql_write_link_preview_signs_create_then_append_support() {
        let db = create_database(":memory:").await.unwrap();
        let source = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e0","type":"Document","kind":"note","name":"Link source"}),
        )
        .await
        .unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e2","type":"Document","kind":"note","name":"Link target"}),
        )
        .await
        .unwrap();
        grant_link_edit(&db, &[&source, &target]).await;
        let caller = Caller::authenticated("plan-author");
        let statement = link_row(&source, "relates_to", &format!("'{target}'"));
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();

        let created = preview_link(&db, &caller, statement.clone(), Some("e0-harness"))
            .await
            .expect("a fresh directed link must prepare");
        let created_op = &created.effect["targets"][0]["ops"][0];
        assert_eq!(created_op["op"], json!("add_link"));
        assert_eq!(created_op["relationship"], json!("relates_to"));
        assert_eq!(created_op["route"], json!("directed_legacy_link"));
        assert_eq!(created_op["intent"], json!("would_create_relationship"));
        assert_eq!(created_op["note"], json!("e0-harness"));
        assert_eq!(created_op["note_applied"], json!(true));
        assert_eq!(created_op["existing"], Value::Null);
        assert_eq!(created_op["changed"], json!(true));
        assert_eq!(created_op["source_id"], json!(source));
        assert_eq!(created_op["target_id"], json!(target));
        assert!(created_op["source_previous_seq"].is_i64());
        assert!(created_op["target_previous_seq"].is_i64());
        assert!(created_op["proposition_key"].is_string());
        assert!(
            created
                .effect_summary
                .contains("new relationship with note"),
            "{}",
            created.effect_summary
        );

        // The singular tool asserts the same relationship-owned route.
        singular_add_link(&db, &caller, &source, &target, Some("first-wins")).await;

        // Re-add is never a no-op: it appends another support assertion, and
        // the passed note is ignored by the singular route.
        let appended = preview_link(&db, &caller, statement, Some("second-note"))
            .await
            .expect("a re-add must prepare, never a no-op");
        let appended_op = &appended.effect["targets"][0]["ops"][0];
        assert_eq!(appended_op["intent"], json!("would_append_support"));
        assert_eq!(appended_op["note"], json!("second-note"));
        assert_eq!(appended_op["note_applied"], json!(false));
        assert_eq!(appended_op["changed"], json!(true));
        assert_eq!(appended_op["existing"]["status"], json!("active"));
        assert!(
            appended_op["existing"]["relationship_id"].is_string(),
            "{appended_op}"
        );
        assert!(
            appended_op["existing"]["assertion_set_digest"].is_string(),
            "the assertion-set digest is the drift signal: {appended_op}"
        );
        assert!(
            appended.effect_summary.contains("note ignored"),
            "{}",
            appended.effect_summary
        );
        // Appending support does not move an endpoint content seq, so the two
        // target-state digests agree; only the signed effect (assertion-set
        // digest) distinguishes them. That is exactly why the effect is signed.
        assert_eq!(created.target_state_digest, appended.target_state_digest);
        assert_ne!(created.effect, appended.effect);

        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_before, events_after,
            "preparation must append no content event"
        );
    }

    /// A self-link is allowed by the singular tool, so the preview must not
    /// invent a self-link refusal.
    #[tokio::test]
    async fn sql_write_link_preview_allows_self_link() {
        let db = create_database(":memory:").await.unwrap();
        let record = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e8","type":"Document","kind":"note","name":"Self"}),
        )
        .await
        .unwrap();
        grant_link_edit(&db, &[&record]).await;
        let caller = Caller::authenticated("plan-author");
        let prepared = preview_link(
            &db,
            &caller,
            link_row(&record, "relates_to", &format!("'{record}'")),
            Some("self"),
        )
        .await
        .expect("a self-link must prepare");
        let op = &prepared.effect["targets"][0]["ops"][0];
        assert_eq!(op["intent"], json!("would_create_relationship"));
        assert_eq!(op["source_id"], json!(record));
        assert_eq!(op["target_id"], json!(record));
        assert_eq!(op["note_applied"], json!(true));
    }

    /// Strict four-column shape refusals, including the fields B1 skipped:
    /// blank record ids, mixing a link with a content edit, duplicates, and the
    /// shared distinct-target overflow bound.
    #[tokio::test]
    async fn sql_write_link_preview_shape_refusals() {
        let db = create_database(":memory:").await.unwrap();
        let source = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e4","type":"Document","kind":"note","name":"Shape source"}),
        )
        .await
        .unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e5","type":"Document","kind":"note","name":"Shape target"}),
        )
        .await
        .unwrap();
        grant_link_edit(&db, &[&source, &target]).await;
        let caller = Caller::authenticated("plan-author");
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let probe = |statement: String, note: Option<&str>| {
            let db = db.clone();
            let caller = caller.clone();
            let note = note.map(str::to_string);
            async move { preview_link(&db, &caller, statement, note.as_deref()).await }
        };

        let bad_key = probe(
            link_row(&source, "target", &format!("'{target}'")),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(bad_key.contains("unsupported add_link key"), "{bad_key}");

        let null_value = probe(link_row(&source, "relates_to", "NULL"), Some("n"))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            null_value.contains("must be a JSON string"),
            "a SQL NULL value must refuse: {null_value}"
        );

        let blank_value = probe(link_row(&source, "relates_to", "''"), Some("n"))
            .await
            .unwrap_err()
            .to_string();
        assert!(blank_value.contains("non-blank target id"), "{blank_value}");

        let fifth_column = probe(
            format!(
                "SELECT id AS record_id, 'add_link' AS op, 'relates_to' AS key, '{target}' AS value, 1 AS extra FROM records WHERE id = '{source}'"
            ),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            fifth_column.contains("unknown operation field 'extra'"),
            "{fifth_column}"
        );

        let blank_record = probe(
            format!(
                "SELECT '' AS record_id, 'add_link' AS op, 'relates_to' AS key, '{target}' AS value FROM records WHERE id = '{source}'"
            ),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            blank_record.contains("'record_id' must be non-blank"),
            "{blank_record}"
        );

        let orphan_note = probe(
            format!(
                "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{source}'"
            ),
            Some("orphan"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            orphan_note.contains("only valid when the selection includes an add_link"),
            "{orphan_note}"
        );

        let blank_note = probe(
            link_row(&source, "relates_to", &format!("'{target}'")),
            Some("   "),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            blank_note.contains("'link_note' must be non-blank"),
            "{blank_note}"
        );

        let oversize_note = probe(
            link_row(&source, "relates_to", &format!("'{target}'")),
            Some(&"e".repeat(1025)),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            oversize_note.contains("exceeds 1024 characters"),
            "{oversize_note}"
        );

        let mixed = probe(
            format!(
                "SELECT id AS record_id, 'add_link' AS op, 'relates_to' AS key, '{target}' AS value FROM records WHERE id = '{source}' \
                 UNION ALL \
                 SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{source}'"
            ),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            mixed.contains("mixes 'add_link' with another operation"),
            "{mixed}"
        );

        let duplicate = probe(
            format!(
                "SELECT id AS record_id, 'add_link' AS op, 'relates_to' AS key, '{target}' AS value FROM records WHERE id = '{source}' \
                 UNION ALL \
                 SELECT id AS record_id, 'add_link' AS op, 'relates_to' AS key, '{target}' AS value FROM records WHERE id = '{source}'"
            ),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(duplicate.contains("duplicate 'relates_to'"), "{duplicate}");

        let events_after_refusals: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_before, events_after_refusals,
            "shape refusals must append no content event"
        );

        // The distinct-source cap is shared with the other operations: 26 links
        // exceed the 25-target bound and refuse before any per-source check.
        for index in 0..26 {
            let id = format!("ec00b000-0000-4000-8000-0000000001{index:02}");
            create_record(
                &db,
                json!({
                    "id": id,
                    "type":"Document","kind":"note","name":"Link overflow"
                }),
            )
            .await
            .unwrap();
            grant_link_edit(&db, &[id.as_str()]).await;
        }
        let events_before_overflow: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let overflow = probe(
            format!(
                "SELECT id AS record_id, 'add_link' AS op, 'relates_to' AS key, '{target}' AS value FROM records WHERE name = 'Link overflow'"
            ),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(overflow.contains("distinct records"), "{overflow}");
        let events_after_overflow: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_before_overflow, events_after_overflow,
            "the overflow refusal must append no content event"
        );
    }

    /// The preview mirrors the singular route and endpoint guard: a Message
    /// endpoint is content-owned and refuses, a hidden target is
    /// indistinguishable from a missing one, and a visible View-only source
    /// keeps its capability error.
    #[tokio::test]
    async fn sql_write_link_preview_route_and_endpoint_denials() {
        let db = create_database(":memory:").await.unwrap();
        let source = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e6","type":"Document","kind":"note","name":"Denial source"}),
        )
        .await
        .unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e7","type":"Document","kind":"note","name":"Denial target"}),
        )
        .await
        .unwrap();
        let message = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e9","type":"Message","kind":"text","body":"fallback","addressed_to":[],"facets":{"expectation":"none"}}),
        )
        .await
        .unwrap();
        let hidden = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000ea","type":"Document","kind":"note","name":"Hidden target"}),
        )
        .await
        .unwrap();
        let view_only = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000eb","type":"Document","kind":"note","name":"View only"}),
        )
        .await
        .unwrap();
        grant_link_edit(&db, &[&source, &target, &message]).await;
        // A View-only source cannot be linked from; a hidden target is not
        // visible; a View-only target still satisfies the link's View check.
        replace_explicit_policy(
            &db,
            "test:sql-write-link-view",
            &view_only,
            vec![AllowEntry::account("plan-author", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "test:sql-write-link-hidden", &hidden, vec![])
            .await
            .unwrap();
        let caller = Caller::authenticated("plan-author");

        let content_owned = preview_link(
            &db,
            &caller,
            link_row(&source, "relates_to", &format!("'{message}'")),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            content_owned.contains("content-owned"),
            "a Message endpoint must take the refused content route: {content_owned}"
        );

        let hidden_error = preview_link(
            &db,
            &caller,
            link_row(&source, "relates_to", &format!("'{hidden}'")),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        let missing = "ec00b000-0000-4000-8000-00000000dead";
        let missing_error = preview_link(
            &db,
            &caller,
            link_row(&source, "relates_to", &format!("'{missing}'")),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(hidden_error.contains("does not exist"), "{hidden_error}");
        assert!(missing_error.contains("does not exist"), "{missing_error}");
        assert!(
            !hidden_error.contains("capability"),
            "a hidden target must not leak a capability distinction: {hidden_error}"
        );

        let view_only_error = preview_link(
            &db,
            &caller,
            link_row(&view_only, "relates_to", &format!("'{target}'")),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            view_only_error.contains("requires edit capability"),
            "a visible View-only source keeps its capability error: {view_only_error}"
        );

        // A View-only target satisfies the link's View requirement.
        preview_link(
            &db,
            &caller,
            link_row(&source, "relates_to", &format!("'{view_only}'")),
            Some("n"),
        )
        .await
        .expect("a View-only target is linkable");
    }

    /// Archived-source parity: the preview deliberately adds no archived-source
    /// refusal the singular `manage_links.add` lacks. Archive the source through
    /// the public `archive_record` tool, then both the singular add and the
    /// preview must succeed from that source.
    #[tokio::test]
    async fn sql_write_link_preview_archived_source_matches_singular_route() {
        let db = create_database(":memory:").await.unwrap();
        let source = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000ec","type":"Document","kind":"note","name":"Archived source"}),
        )
        .await
        .unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000ed","type":"Document","kind":"note","name":"Archived target"}),
        )
        .await
        .unwrap();
        // Manage on the source so the public archive tool is allowed; Edit on
        // the target (Manage implies Edit/View).
        replace_explicit_policy(
            &db,
            "test:sql-write-link-archived",
            &source,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        grant_link_edit(&db, &[&target]).await;
        let caller = Caller::authenticated("plan-author");
        let archived = registry()
            .call(
                db.clone(),
                caller.clone(),
                "archive_record",
                json!({"id": source, "reason": "archived-source link parity fixture"}),
            )
            .await
            .unwrap();
        assert_eq!(archived["archived"], json!(true));
        // The singular route still adds a link from the archived source.
        singular_add_link(&db, &caller, &source, &target, Some("archived")).await;
        // The preview does the same and signs the append intent rather than
        // inventing an archived-source refusal.
        let prepared = preview_link(
            &db,
            &caller,
            link_row(&source, "relates_to", &format!("'{target}'")),
            Some("archived"),
        )
        .await
        .expect("an archived source is linkable, matching the singular route");
        let op = &prepared.effect["targets"][0]["ops"][0];
        assert_eq!(op["intent"], json!("would_append_support"));
        assert_eq!(op["existing"]["status"], json!("active"));
    }

    /// Run the singular relationship-owned `manage_links.remove`, so the
    /// preview is compared against the real route rather than a stand-in.
    async fn singular_remove_link(db: &crate::Db, caller: &Caller, source: &str, target: &str) {
        let receipt = registry()
            .call(
                db.clone(),
                caller.clone(),
                "manage_links",
                json!({
                    "action":"remove","source_id":source,"target_id":target,
                    "relationship":"relates_to"
                }),
            )
            .await
            .unwrap();
        assert_eq!(receipt["action"], json!("remove"));
    }

    fn remove_row(source: &str, key: &str, value_expr: &str) -> String {
        format!(
            "SELECT id AS record_id, 'remove_link' AS op, '{key}' AS key, {value_expr} AS value FROM records WHERE id = '{source}'"
        )
    }

    /// A directed `remove_link` previews the singular relationship-owned
    /// removal route: an existing active proposition signs the observed
    /// before state plus a guaranteed `would_contest` intent, with no note
    /// and no projected post-contest state. Preparation appends no event.
    #[tokio::test]
    async fn sql_write_remove_link_preview_signs_contest() {
        let db = create_database(":memory:").await.unwrap();
        let source = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000f0","type":"Document","kind":"note","name":"Remove source"}),
        )
        .await
        .unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000f2","type":"Document","kind":"note","name":"Remove target"}),
        )
        .await
        .unwrap();
        grant_link_edit(&db, &[&source, &target]).await;
        let caller = Caller::authenticated("plan-author");
        // The proposition must exist before it can be contested.
        singular_add_link(&db, &caller, &source, &target, Some("first-wins")).await;
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let relationship_events_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap();

        let prepared = preview_link(
            &db,
            &caller,
            remove_row(&source, "relates_to", &format!("'{target}'")),
            None,
        )
        .await
        .expect("an existing directed link must prepare a removal");
        let op = &prepared.effect["targets"][0]["ops"][0];
        assert_eq!(op["op"], json!("remove_link"));
        assert_eq!(op["relationship"], json!("relates_to"));
        assert_eq!(op["route"], json!("directed_legacy_link"));
        assert_eq!(op["intent"], json!("would_contest"));
        assert_eq!(op["changed"], json!(true));
        assert_eq!(op["note"], Value::Null);
        assert_eq!(op["note_applied"], json!(false));
        assert_eq!(op["source_id"], json!(source));
        assert_eq!(op["target_id"], json!(target));
        assert!(op["source_previous_seq"].is_i64());
        assert!(op["target_previous_seq"].is_i64());
        assert!(op["proposition_key"].is_string());
        assert_eq!(op["existing"]["status"], json!("active"));
        assert_eq!(op["existing"]["effective_state"], json!("active"));
        assert!(op["existing"]["relationship_id"].is_string());
        assert!(
            prepared
                .effect_summary
                .contains("would contest relationship"),
            "{}",
            prepared.effect_summary
        );
        // The canonical envelope carries no note key for a removal.
        assert!(
            prepared
                .canonical_source_arguments
                .get("link_note")
                .is_none(),
            "{}",
            prepared.canonical_source_arguments
        );

        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_before, events_after,
            "preparation must append no event"
        );
        let relationship_events_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(
            relationship_events_before, relationship_events_after,
            "preparation must append no relationship event"
        );
    }

    /// Strict shape refusals for `remove_link`: absent propositions, bad keys,
    /// blank or NULL target ids, a note alongside a removal, mixing a removal
    /// with a content edit, and duplicates. Every refusal appends no event.
    #[tokio::test]
    async fn sql_write_remove_link_preview_shape_refusals() {
        let db = create_database(":memory:").await.unwrap();
        let source = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000f4","type":"Document","kind":"note","name":"Remove shape source"}),
        )
        .await
        .unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000f5","type":"Document","kind":"note","name":"Remove shape target"}),
        )
        .await
        .unwrap();
        grant_link_edit(&db, &[&source, &target]).await;
        let caller = Caller::authenticated("plan-author");
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let probe = |statement: String, note: Option<&str>| {
            let db = db.clone();
            let caller = caller.clone();
            let note = note.map(str::to_string);
            async move { preview_link(&db, &caller, statement, note.as_deref()).await }
        };

        // No proposition exists yet: removal refuses, it never previews a
        // no-op.
        let absent = probe(
            remove_row(&source, "relates_to", &format!("'{target}'")),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            absent.contains("cannot remove link"),
            "an absent proposition must refuse: {absent}"
        );

        let bad_key = probe(remove_row(&source, "target", &format!("'{target}'")), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(bad_key.contains("unsupported remove_link key"), "{bad_key}");

        let null_value = probe(remove_row(&source, "relates_to", "NULL"), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            null_value.contains("must be a JSON string"),
            "a SQL NULL value must refuse: {null_value}"
        );

        let blank_value = probe(remove_row(&source, "relates_to", "''"), None)
            .await
            .unwrap_err()
            .to_string();
        assert!(blank_value.contains("non-blank target id"), "{blank_value}");

        // Establish the proposition for the remaining shape probes.
        singular_add_link(&db, &caller, &source, &target, Some("first-wins")).await;

        // A removal carries no note: the singular remove passes `None`.
        let noted = probe(
            remove_row(&source, "relates_to", &format!("'{target}'")),
            Some("n"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(noted.contains("remove_link carries no note"), "{noted}");

        let mixed = probe(
            format!(
                "SELECT id AS record_id, 'remove_link' AS op, 'relates_to' AS key, '{target}' AS value FROM records WHERE id = '{source}' \
                 UNION ALL \
                 SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{source}'"
            ),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            mixed.contains("mixes 'remove_link' with another operation"),
            "{mixed}"
        );

        let duplicate = probe(
            format!(
                "SELECT id AS record_id, 'remove_link' AS op, 'relates_to' AS key, '{target}' AS value FROM records WHERE id = '{source}' \
                 UNION ALL \
                 SELECT id AS record_id, 'remove_link' AS op, 'relates_to' AS key, '{target}' AS value FROM records WHERE id = '{source}'"
            ),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(duplicate.contains("duplicate 'relates_to'"), "{duplicate}");

        let events_after_refusals: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        // The mid-test fixture add is relationship-only and moves no endpoint
        // content seq, so the count still equals the pre-probe baseline: every
        // refusal appended no content event.
        assert_eq!(
            events_before, events_after_refusals,
            "shape refusals must append no content event"
        );
    }

    /// The removal preview mirrors the singular route and endpoint guard: a
    /// Message endpoint is content-owned and refuses, a hidden target is
    /// indistinguishable from a missing one, and a visible View-only source
    /// keeps its capability error.
    #[tokio::test]
    async fn sql_write_remove_link_preview_route_and_endpoint_denials() {
        let db = create_database(":memory:").await.unwrap();
        let source = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000f6","type":"Document","kind":"note","name":"Remove denial source"}),
        )
        .await
        .unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000f7","type":"Document","kind":"note","name":"Remove denial target"}),
        )
        .await
        .unwrap();
        let message = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000f9","type":"Message","kind":"text","body":"fallback","addressed_to":[],"facets":{"expectation":"none"}}),
        )
        .await
        .unwrap();
        let hidden = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000fa","type":"Document","kind":"note","name":"Hidden remove target"}),
        )
        .await
        .unwrap();
        let view_only = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000fb","type":"Document","kind":"note","name":"Remove view only"}),
        )
        .await
        .unwrap();
        grant_link_edit(&db, &[&source, &target, &message]).await;
        replace_explicit_policy(
            &db,
            "test:sql-write-remove-link-view",
            &view_only,
            vec![AllowEntry::account("plan-author", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "test:sql-write-remove-link-hidden", &hidden, vec![])
            .await
            .unwrap();
        let caller = Caller::authenticated("plan-author");

        let content_owned = preview_link(
            &db,
            &caller,
            remove_row(&source, "relates_to", &format!("'{message}'")),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            content_owned.contains("content-owned"),
            "a Message endpoint must take the refused content route: {content_owned}"
        );

        let hidden_error = preview_link(
            &db,
            &caller,
            remove_row(&source, "relates_to", &format!("'{hidden}'")),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        let missing = "ec00b000-0000-4000-8000-00000000dead";
        let missing_error = preview_link(
            &db,
            &caller,
            remove_row(&source, "relates_to", &format!("'{missing}'")),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(hidden_error.contains("does not exist"), "{hidden_error}");
        assert!(missing_error.contains("does not exist"), "{missing_error}");
        assert!(
            !hidden_error.contains("capability"),
            "a hidden target must not leak a capability distinction: {hidden_error}"
        );

        let view_only_error = preview_link(
            &db,
            &caller,
            remove_row(&view_only, "relates_to", &format!("'{target}'")),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            view_only_error.contains("requires edit capability"),
            "a visible View-only source keeps its capability error: {view_only_error}"
        );

        // A View-only target satisfies the removal's View requirement, once a
        // link to it exists through an authorized route.
        singular_add_link(&db, &caller, &source, &target, Some("first-wins")).await;
        let view_target_error = preview_link(
            &db,
            &caller,
            remove_row(&source, "relates_to", &format!("'{view_only}'")),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            view_target_error.contains("cannot remove link"),
            "a View-only target with no proposition still refuses as absent: {view_target_error}"
        );
    }

    /// Contesting the proposition through the public singular route flips its
    /// effective state, and the removal preview then refuses exactly as the
    /// singular second removal does. The retired-proposition fixture stays
    /// deferred: `retired` is set only by a federation-origin event with no
    /// public setter, so it is exercised by inspection, not manufacture.
    #[tokio::test]
    async fn sql_write_remove_link_preview_inactive_after_contest_refuses() {
        let db = create_database(":memory:").await.unwrap();
        let source = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000fc","type":"Document","kind":"note","name":"Inactive source"}),
        )
        .await
        .unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000fd","type":"Document","kind":"note","name":"Inactive target"}),
        )
        .await
        .unwrap();
        grant_link_edit(&db, &[&source, &target]).await;
        let caller = Caller::authenticated("plan-author");
        singular_add_link(&db, &caller, &source, &target, Some("first-wins")).await;
        // Contest through the real singular route: the reducer deactivates the
        // support, so the proposition is no longer effectively active.
        singular_remove_link(&db, &caller, &source, &target).await;
        let singular_second = registry()
            .call(
                db.clone(),
                caller.clone(),
                "manage_links",
                json!({
                    "action":"remove","source_id":source,"target_id":target,
                    "relationship":"relates_to"
                }),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            singular_second.contains("inactive or causally unresolved"),
            "the singular second removal proves the inactive state: {singular_second}"
        );

        let preview_second = preview_link(
            &db,
            &caller,
            remove_row(&source, "relates_to", &format!("'{target}'")),
            None,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            preview_second.contains("inactive or causally unresolved"),
            "the preview must refuse the same inactive state: {preview_second}"
        );
    }

    /// Archived-source parity: the preview deliberately adds no
    /// archived-source refusal the singular `manage_links.remove` lacks.
    /// Archive the source through the public `archive_record` tool, then both
    /// the singular removal and the preview must succeed from that source.
    #[tokio::test]
    async fn sql_write_remove_link_preview_archived_source_matches_singular_route() {
        let db = create_database(":memory:").await.unwrap();
        let source = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000fe","type":"Document","kind":"note","name":"Archived remove source"}),
        )
        .await
        .unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000ff","type":"Document","kind":"note","name":"Archived remove target"}),
        )
        .await
        .unwrap();
        // Manage on the source so the public archive tool is allowed; Edit on
        // the target (Manage implies Edit/View).
        replace_explicit_policy(
            &db,
            "test:sql-write-remove-link-archived",
            &source,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        grant_link_edit(&db, &[&target]).await;
        let caller = Caller::authenticated("plan-author");
        singular_add_link(&db, &caller, &source, &target, Some("archived")).await;
        let archived = registry()
            .call(
                db.clone(),
                caller.clone(),
                "archive_record",
                json!({"id": source, "reason": "archived-source remove parity fixture"}),
            )
            .await
            .unwrap();
        assert_eq!(archived["archived"], json!(true));
        // The singular route still removes a link from the archived source.
        singular_remove_link(&db, &caller, &source, &target).await;
        // Re-establish so the preview has an active proposition to contest:
        // the point is that the archived source itself never refuses.
        singular_add_link(&db, &caller, &source, &target, Some("archived-again")).await;
        let prepared = preview_link(
            &db,
            &caller,
            remove_row(&source, "relates_to", &format!("'{target}'")),
            None,
        )
        .await
        .expect("an archived source is removable, matching the singular route");
        let op = &prepared.effect["targets"][0]["ops"][0];
        assert_eq!(op["intent"], json!("would_contest"));
        assert_eq!(op["existing"]["status"], json!("active"));
    }

    /// A link-free envelope keeps the exact pre-link canonical contract: the
    /// optional note is absent, no `link_note` key is synthesized, and an
    /// ordinary field selection still prepares.
    #[tokio::test]
    async fn sql_write_preview_without_link_note_keeps_canonical_shape() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e1","type":"Document","kind":"note","name":"No note"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-no-link-note",
            &target,
            vec![AllowEntry::account("plan-author", Capability::Edit)],
        )
        .await
        .unwrap();
        let caller = Caller::authenticated("plan-author");
        let prepared = prepare_sql_write_preview(
            &db,
            &caller,
            json!({
                "statement": format!("SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{target}'"),
                "reason": "link-free probe",
            }),
        )
        .await
        .expect("a link-free field selection still prepares");
        let canonical = prepared.canonical_source_arguments;
        assert!(
            canonical.get("link_note").is_none(),
            "an absent note must not appear in the canonical object: {canonical}"
        );
        assert_eq!(
            canonical.as_object().expect("canonical object").len(),
            4,
            "a link-free canonical envelope keeps exactly its four fields: {canonical}"
        );
    }

    /// Governed validator rejections are infrastructure failures, not drift:
    /// they stay non-stale so the execute path reports
    /// `plan_revalidation_failed` rather than `plan_stale`.
    #[tokio::test]
    async fn sql_write_validator_failure_stays_non_stale() {
        let db = create_database(":memory:").await.unwrap();
        let caller = Caller::authenticated("plan-author");
        let error = prepare_sql_write_preview(
            &db,
            &caller,
            json!({"statement": "DELETE FROM records", "reason": "probe"}),
        )
        .await
        .expect_err("write statements must be rejected");
        assert!(
            !matches!(error, Error::Conflict(_)),
            "validator failure must stay non-stale: {error}"
        );
    }

    #[tokio::test]
    async fn sql_write_preview_refuses_unordered_limit_without_default() {
        // E2 scope: the server default ORDER BY is ad-hoc-`query_sql`-only.
        // A sql_write selection with an unordered top-level LIMIT is refused
        // with today's repair — a mutation's target set must be stated by
        // the author, never assumed, and nothing is disclosed.
        let db = create_database(":memory:").await.unwrap();
        let caller = Caller::authenticated("plan-author");
        let error = prepare_sql_write_preview(
            &db,
            &caller,
            json!({"statement": "SELECT id FROM records LIMIT 2", "reason": "probe"}),
        )
        .await
        .expect_err("unordered LIMIT selection must be rejected");
        let message = error.to_string();
        assert!(message.contains("selection rejected"), "{message}");
        assert!(message.contains("LIMIT without ORDER BY"), "{message}");
        assert!(!message.contains("ad-hoc default"), "{message}");
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
                "manage_memberships.create_guest_link",
                PlanPolicy::RequiredSupported,
            ),
            (
                "membership_admin",
                "manage_memberships.revoke_guest_link",
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
            ("sql_write", "sql_write", PlanPolicy::RequiredSupported),
        ];
        assert_eq!(PLAN_POLICY_TABLE, expected);
        assert_eq!(PLAN_POLICY_TABLE.len(), 37);
        assert_eq!(
            PLAN_POLICY_TABLE
                .iter()
                .filter(|(_, _, policy)| *policy == PlanPolicy::RequiredSupported)
                .count(),
            35
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

    /// E4 M1 slices: the `sql_write` plan reserves ten minutes while every
    /// other classified plan-required pair keeps exactly two minutes.
    /// `sql_write` is classified `RequiredSupported` and admitted only under
    /// the experimental allowlist; the TTL reservation never advertises it.
    #[tokio::test]
    async fn sql_write_ttl_is_ten_minutes_while_existing_plans_keep_two() {
        assert_eq!(
            plan_ttl_ms(SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION),
            SQL_WRITE_TTL_MS
        );
        assert_eq!(SQL_WRITE_TTL_MS, 600_000);
        for (executor, operation, _) in PLAN_POLICY_TABLE {
            if (*executor, *operation) == (SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION) {
                continue;
            }
            assert_eq!(
                plan_ttl_ms(executor, operation),
                DEFAULT_TTL_MS,
                "{executor}.{operation}"
            );
            assert_eq!(plan_ttl_ms(executor, operation), 120_000);
        }
        assert!(PLAN_POLICY_TABLE
            .iter()
            .any(|(executor, operation, policy)| {
                *executor == SQL_WRITE_EXECUTOR
                    && *operation == SQL_WRITE_OPERATION
                    && *policy == PlanPolicy::RequiredSupported
            }));
        assert_eq!(
            plan_policy(SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION),
            PlanPolicy::RequiredSupported
        );
        assert!(requires_plan(SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION));
        assert!(supports(SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION));

        let db = create_database(":memory:").await.unwrap();
        let store = PlanStore::open_for_database(db.path()).await.unwrap();
        let runtime = WriteRuntime::new(store);
        assert_eq!(
            runtime.ttl_for(SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION),
            600_000
        );
        for (executor, operation, _) in PLAN_POLICY_TABLE {
            if (*executor, *operation) == (SQL_WRITE_EXECUTOR, SQL_WRITE_OPERATION) {
                continue;
            }
            assert_eq!(
                runtime.ttl_for(executor, operation),
                120_000,
                "{executor}.{operation}"
            );
        }
    }

    /// E4 M1 multirow preparer: one portable SELECT producing at most one
    /// `set_field` per `(record, name|summary)` across a bounded visible target
    /// set, with every target's version and Edit authorization checked in the
    /// same governed snapshot. The E0 W4 rename task proves both field
    /// operations on one record survive in the signed effect. Hidden and
    /// missing targets refuse identically; archived, view-only, duplicate,
    /// oversized, and unknown operations refuse; and no preparation appends a
    /// content event.
    #[tokio::test]
    async fn sql_write_preview_prepares_bounded_multirow_set_field_without_mutation() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000031","type":"Document","kind":"note","name":"Perturb me"}),
        )
        .await
        .unwrap();
        let hidden = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000032","type":"Document","kind":"note","name":"Hidden"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-preview",
            &target,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "test:sql-write-preview-hide", &hidden, vec![])
            .await
            .unwrap();
        let viewonly = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000033","type":"Document","kind":"note","name":"Look only"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-preview-view",
            &viewonly,
            vec![AllowEntry::account("plan-author", Capability::View)],
        )
        .await
        .unwrap();
        let big_summary: String = std::iter::repeat_n('s', 1025).collect();
        let big_record = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000035","type":"Document","kind":"note","name":"Big summary","summary":big_summary}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-preview-big",
            &big_record,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        let archived = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000037","type":"Document","kind":"note","name":"Archived"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-preview-archived",
            &archived,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        crate::store::archive_record(&db, &archived).await.unwrap();
        let caller = Caller::authenticated("plan-author");
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let args_for = |id: &str| {
            json!({
                "statement": format!("SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{id}'"),
                "reason": "Preview a rename through the sql_write preparer",
            })
        };
        // Predicate probe: matches the target and would also match a
        // same-prefixed hidden record, which the governed layer filters.
        let like_args = || {
            json!({
                "statement": "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE name LIKE 'Perturb%'",
                "reason": "Preview a rename through the sql_write preparer",
            })
        };
        // E0 W4: rename `name` and rewrite `summary` on the same single record
        // in one edit. Both operations must survive in the signed effect.
        let w4_args = || {
            json!({
                "statement": format!(
                    "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{target}' \
                     UNION ALL \
                     SELECT id AS record_id, 'set_field' AS op, 'summary' AS key, 'Rewritten summary' AS value FROM records WHERE id = '{target}'"
                ),
                "reason": "Preview the W4 rename and summary rewrite",
            })
        };
        let prepared = prepare_sql_write_preview(&db, &caller, w4_args())
            .await
            .unwrap();
        assert_eq!(prepared.target_id, target, "one target keeps its record id");
        assert_eq!(prepared.effect["target_count"], json!(1));
        assert_eq!(prepared.effect["op_count"], json!(2));
        assert_eq!(prepared.effect["changed"], json!(true));
        assert_eq!(prepared.effect["targets"][0]["record_id"], json!(target));
        let ops = prepared.effect["targets"][0]["ops"]
            .as_array()
            .expect("target ops array");
        assert_eq!(ops.len(), 2, "both W4 field operations must survive");
        // Ops are canonically sorted by field key, independent of row order.
        assert_eq!(ops[0]["key"], json!("name"));
        assert_eq!(ops[1]["key"], json!("summary"));
        assert_eq!(ops[0]["after"], json!("Renamed"));
        assert_eq!(ops[0]["before"], json!("Perturb me"));
        assert_eq!(ops[0]["changed"], json!(true));
        assert_eq!(ops[1]["after"], json!("Rewritten summary"));
        assert_eq!(ops[1]["before"], json!(null));
        assert!(prepared.target.starts_with("1 record ["));
        assert!(prepared.state_revision.starts_with("content-seq-set:"));
        assert_eq!(prepared.target_state_digest.len(), 64);
        assert!(prepared.effect_summary.contains("Renamed"));
        assert!(prepared.effect_summary.contains("Rewritten summary"));
        assert!(prepared.canonical_source_arguments["expected_version"]
            .as_i64()
            .is_some());
        // Hidden and missing targets refuse identically: neither yields a
        // visible operation row, so neither refusal names a difference.
        let hidden_error = prepare_sql_write_preview(&db, &caller, args_for(&hidden))
            .await
            .unwrap_err()
            .to_string();
        let missing_error = prepare_sql_write_preview(
            &db,
            &caller,
            args_for("ec00b000-0000-4000-8000-00000000ffff"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(hidden_error, missing_error);
        // Visible but View-only: the row is selected, then Edit
        // authorization refuses without preparing.
        let view_error = prepare_sql_write_preview(&db, &caller, args_for(&viewonly))
            .await
            .unwrap_err()
            .to_string();
        assert!(view_error.contains("capability"), "{view_error}");
        assert_ne!(view_error, missing_error);
        // Stale expected version: the pinned sequence moved on.
        let stale_version = prepared.canonical_source_arguments["expected_version"]
            .as_i64()
            .unwrap()
            + 1;
        let mut stale_args = args_for(&target);
        stale_args["expected_version"] = json!(stale_version);
        let stale_error = prepare_sql_write_preview(&db, &caller, stale_args)
            .await
            .unwrap_err()
            .to_string();
        assert!(stale_error.contains("revision conflict"), "{stale_error}");
        // `expected_version` pins one record; a two-target selection refuses it
        // explicitly instead of guessing which record it means.
        let two_targets = json!({
            "statement": format!(
                "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id IN ('{target}','{big_record}')"
            ),
            "reason": "Preview a two-record rename",
            "expected_version": 1,
        });
        let multi_version_error = prepare_sql_write_preview(&db, &caller, two_targets)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            multi_version_error.contains("'expected_version' pins one record"),
            "{multi_version_error}"
        );
        // An oversized stored value is refused like an oversized proposal:
        // the signed `before` stays exact, never clipped.
        let big_existing_error = prepare_sql_write_preview(
            &db,
            &caller,
            json!({
                "statement": format!("SELECT id AS record_id, 'set_field' AS op, 'summary' AS key, 'Small' AS value FROM records WHERE id = '{big_record}'"),
                "reason": "Oversized-existing probe",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            big_existing_error.contains("existing summary exceeds 1024"),
            "{big_existing_error}"
        );
        // A readable archived record is explicitly refused by the compiler;
        // the governed `records` view still contains it.
        let archived_error = prepare_sql_write_preview(&db, &caller, args_for(&archived))
            .await
            .unwrap_err()
            .to_string();
        assert!(archived_error.contains("is archived"), "{archived_error}");
        // Hidden rows do not perturb a successful preview: insert a record
        // the predicate would also match, hide it, and re-prepare. The
        // governed layer filters it, so the visible result is identical.
        let predicate_before = prepare_sql_write_preview(&db, &caller, like_args())
            .await
            .unwrap();
        // Every preparation above appended nothing; assert it immediately
        // before the one deliberate perturbative fixture write.
        let events_pre_insert: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(events_pre_insert, events_before);
        let perturbative = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000036","type":"Document","kind":"note","name":"Perturb me too"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-preview-hide-perturbative",
            &perturbative,
            vec![],
        )
        .await
        .unwrap();
        let events_mid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let predicate_after = prepare_sql_write_preview(&db, &caller, like_args())
            .await
            .unwrap();
        assert_eq!(predicate_after.effect, predicate_before.effect);
        assert_eq!(
            predicate_after.effect_summary,
            predicate_before.effect_summary
        );
        assert_eq!(predicate_after.target, predicate_before.target);
        assert_eq!(
            predicate_after.state_revision,
            predicate_before.state_revision
        );
        assert_eq!(
            predicate_after.target_state_digest,
            predicate_before.target_state_digest
        );
        // Unknown op rows are refused, never interpreted. `set_facet` and
        // `unset_facet` are now admitted, so the probe uses an op the
        // compiler still refuses.
        let op_error = prepare_sql_write_preview(
            &db,
            &caller,
            json!({
                "statement": format!("SELECT id AS record_id, 'bogus_op' AS op, 'triage' AS key, 'done' AS value FROM records WHERE id = '{target}'"),
                "reason": "Unknown-op probe",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            op_error.contains(
                "M1 admits only set_field, set_facet, unset_facet, archive, add_link, and remove_link"
            ),
            "{op_error}"
        );
        // Unknown field keys refuse the same way.
        let field_error = prepare_sql_write_preview(
            &db,
            &caller,
            json!({
                "statement": format!("SELECT id AS record_id, 'set_field' AS op, 'body' AS key, 'x' AS value FROM records WHERE id = '{target}'"),
                "reason": "Unknown-field probe",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            field_error.contains("only name and summary"),
            "{field_error}"
        );
        // Oversized caller text is refused with a precise bound, never
        // signed into a plan.
        let big_value: String = std::iter::repeat_n('v', 1025).collect();
        let big_error = prepare_sql_write_preview(
            &db,
            &caller,
            json!({
                "statement": format!("SELECT id AS record_id, 'set_field' AS op, 'name' AS key, '{big_value}' AS value FROM records WHERE id = '{target}'"),
                "reason": "Oversized-value probe",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(big_error.contains("exceeds 1024"), "{big_error}");
        let big_reason: String = std::iter::repeat_n('r', 1025).collect();
        let reason_error = prepare_sql_write_preview(
            &db,
            &caller,
            json!({ "statement": format!("SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Ok' AS value FROM records WHERE id = '{target}'"),
                "reason": big_reason }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(reason_error.contains("exceeds 1024"), "{reason_error}");
        // No preparation appended anything: fixture writes sit strictly
        // between the baselines, preparations add nothing after them.
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert!(
            events_mid > events_pre_insert,
            "the hidden perturbative fixture write must append, so the baselines bracket it"
        );
        assert_eq!(events_mid, events_after);
    }

    /// The signed result is canonically sorted, so the same complete operation
    /// set selected in a different row order yields an identical target,
    /// effect, summary, and version-sensitive digests. Only the statement text
    /// (hence canonical source arguments) differs.
    #[tokio::test]
    async fn sql_write_preview_row_order_is_canonically_irrelevant() {
        let db = create_database(":memory:").await.unwrap();
        let alpha = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000041","type":"Document","kind":"note","name":"Alpha"}),
        )
        .await
        .unwrap();
        let beta = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000042","type":"Document","kind":"note","name":"Beta"}),
        )
        .await
        .unwrap();
        let caller = Caller::local();
        let forward = json!({
            "statement": "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'X' AS value FROM records WHERE name IN ('Alpha','Beta') \
                 UNION ALL \
                 SELECT id AS record_id, 'set_field' AS op, 'summary' AS key, 'S' AS value FROM records WHERE name = 'Alpha'",
            "reason": "Row-order probe",
        });
        let reverse = json!({
            "statement": "SELECT id AS record_id, 'set_field' AS op, 'summary' AS key, 'S' AS value FROM records WHERE name = 'Alpha' \
                 UNION ALL \
                 SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'X' AS value FROM records WHERE name IN ('Beta','Alpha')",
            "reason": "Row-order probe",
        });
        let first = prepare_sql_write_preview(&db, &caller, forward)
            .await
            .unwrap();
        let second = prepare_sql_write_preview(&db, &caller, reverse)
            .await
            .unwrap();
        assert_eq!(first.effect, second.effect);
        assert_eq!(first.effect_summary, second.effect_summary);
        assert_eq!(first.target, second.target);
        assert_eq!(first.target_id, second.target_id);
        assert_eq!(first.state_revision, second.state_revision);
        assert_eq!(first.target_state_digest, second.target_state_digest);
        assert_eq!(first.operation_evidence, second.operation_evidence);
        // The two-target set is canonically ordered regardless of row order.
        assert_eq!(first.effect["targets"][0]["record_id"], json!(alpha));
        assert_eq!(first.effect["targets"][1]["record_id"], json!(beta));
        assert_eq!(
            first.target_id,
            format!("sql-write-target-set:{}", first.target_state_digest)
        );
        assert!(first.target.starts_with("2 records ["));
    }

    /// The compiler proves completeness with a one-row overflow probe: more
    /// than 50 operation rows refuse, more than 25 distinct targets refuse, and
    /// a duplicate `(record_id, key)` refuses rather than collapsing silently.
    #[tokio::test]
    async fn sql_write_preview_enforces_target_operation_and_uniqueness_bounds() {
        let db = create_database(":memory:").await.unwrap();
        let mut ids = Vec::new();
        for index in 0..26u32 {
            let id = format!("ec00b000-0000-4000-8000-{:012}", 0x100 + index);
            create_record(
                &db,
                json!({"id": id, "type":"Document","kind":"note","name": format!("Bound {index}")}),
            )
            .await
            .unwrap();
            ids.push(id);
        }
        let caller = Caller::local();
        // 26 distinct targets, one operation each: the distinct-target cap
        // refuses. Rows (26) are within the 50-operation bound.
        let many_targets = json!({
            "statement": "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'X' AS value FROM records WHERE name LIKE 'Bound %'",
            "reason": "Target overflow probe",
        });
        let target_error = prepare_sql_write_preview(&db, &caller, many_targets)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            target_error.contains("26 distinct records") && target_error.contains("at most 25"),
            "{target_error}"
        );
        // 26 targets x two keys = 52 operation rows: the 51-row probe refuses
        // overflow instead of digesting a truncated selection.
        let many_ops = json!({
            "statement": "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'X' AS value FROM records WHERE name LIKE 'Bound %' \
                          UNION ALL \
                          SELECT id AS record_id, 'set_field' AS op, 'summary' AS key, 'Y' AS value FROM records WHERE name LIKE 'Bound %'",
            "reason": "Operation overflow probe",
        });
        let op_error = prepare_sql_write_preview(&db, &caller, many_ops)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            op_error.contains("50-operation preview bound"),
            "{op_error}"
        );
        // The caps are inclusive: exactly 25 targets and exactly 50 operations
        // (25 records x two keys) prepare, and the bounded summary truncates
        // its sample explicitly.
        let boundary = json!({
            "statement": "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'X' AS value FROM records WHERE name LIKE 'Bound %' AND name != 'Bound 25' \
                          UNION ALL \
                          SELECT id AS record_id, 'set_field' AS op, 'summary' AS key, 'Y' AS value FROM records WHERE name LIKE 'Bound %' AND name != 'Bound 25'",
            "reason": "Boundary probe",
        });
        let accepted = prepare_sql_write_preview(&db, &caller, boundary)
            .await
            .unwrap();
        assert_eq!(accepted.effect["target_count"], json!(25));
        assert_eq!(accepted.effect["op_count"], json!(50));
        assert!(
            accepted.effect_summary.contains("(+47 more operations)"),
            "bounded summary must state its omitted count: {}",
            accepted.effect_summary
        );
        assert_eq!(
            accepted.target_id,
            format!("sql-write-target-set:{}", accepted.target_state_digest)
        );
        let first = ids[0].clone();
        let duplicate = json!({
            "statement": format!(
                "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'A' AS value FROM records WHERE id = '{first}' \
                 UNION ALL \
                 SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'B' AS value FROM records WHERE id = '{first}'"
            ),
            "reason": "Duplicate probe",
        });
        let duplicate_error = prepare_sql_write_preview(&db, &caller, duplicate)
            .await
            .unwrap_err()
            .to_string();
        assert!(duplicate_error.contains("duplicate"), "{duplicate_error}");
    }

    /// E0 W1 shape: a folder-containment selection prepares a `set_facet`
    /// `e0probe=done` row on every visible child and only the visible child
    /// set. This establishes the prepared target set, not an executed landing
    /// (M1 has no commit path). A hidden child in the same folder does not
    /// perturb the signed target, effect, or digest, and no preparation
    /// appends an event.
    #[tokio::test]
    async fn sql_write_preview_prepares_string_set_facet_over_folder_target_set() {
        let db = create_database(":memory:").await.unwrap();
        let folder = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000a1","type":"Collection","kind":"folder","name":"W1 folder"}),
        )
        .await
        .unwrap();
        // The children's `home_id` is disclosed only while the folder is
        // visible to the caller, so the folder needs View.
        replace_explicit_policy(
            &db,
            "test:sql-write-w1-folder",
            &folder,
            vec![AllowEntry::account("plan-author", Capability::View)],
        )
        .await
        .unwrap();
        let first = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000a2","type":"Document","kind":"note","name":"W1 child one","home_id":&folder}),
        )
        .await
        .unwrap();
        let second = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000a3","type":"Document","kind":"note","name":"W1 child two","home_id":&folder}),
        )
        .await
        .unwrap();
        let hidden = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000a4","type":"Document","kind":"note","name":"W1 hidden child","home_id":&folder}),
        )
        .await
        .unwrap();
        let outside = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000a5","type":"Document","kind":"note","name":"W1 outside"}),
        )
        .await
        .unwrap();
        for id in [first.as_str(), second.as_str(), outside.as_str()] {
            replace_explicit_policy(
                &db,
                "test:sql-write-w1-visible",
                id,
                vec![AllowEntry::account("plan-author", Capability::Manage)],
            )
            .await
            .unwrap();
        }
        replace_explicit_policy(&db, "test:sql-write-w1-hidden", &hidden, vec![])
            .await
            .unwrap();
        let caller = Caller::authenticated("plan-author");
        let statement = format!(
            "SELECT id AS record_id, 'set_facet' AS op, 'e0probe' AS key, 'done' AS value FROM records WHERE home_id = '{folder}'"
        );
        let args = || json!({ "statement": statement, "reason": "Preview the W1 bulk facet set" });
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_sql_write_preview(&db, &caller, args())
            .await
            .unwrap();
        assert_eq!(prepared.effect["target_count"], json!(2));
        assert_eq!(prepared.effect["op_count"], json!(2));
        assert_eq!(prepared.effect["changed"], json!(true));
        let mut target_ids: Vec<&str> = prepared.effect["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|target| target["record_id"].as_str().unwrap())
            .collect();
        target_ids.sort();
        let mut expected = vec![first.as_str(), second.as_str()];
        expected.sort();
        assert_eq!(
            target_ids, expected,
            "the W1 target set is exactly the visible children"
        );
        for target in prepared.effect["targets"].as_array().unwrap() {
            let ops = target["ops"].as_array().unwrap();
            assert_eq!(ops.len(), 1);
            assert_eq!(ops[0]["op"], json!("set_facet"));
            assert_eq!(ops[0]["key"], json!("e0probe"));
            assert_eq!(ops[0]["value"], json!("done"));
            assert_eq!(ops[0]["before"], json!(null));
            assert_eq!(ops[0]["after"], json!("done"));
            assert_eq!(ops[0]["before_vocab_ref"], json!(null));
            assert_eq!(ops[0]["after_vocab_ref"], json!(null));
            assert_eq!(ops[0]["changed"], json!(true));
        }
        assert!(
            prepared.target.starts_with("2 records ["),
            "{}",
            prepared.target
        );
        assert!(prepared.effect_summary.contains("set_facet 'e0probe'"));
        // Hidden-member nonperturbation: a further hidden child in the same
        // folder changes nothing signed.
        let perturbative = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000a6","type":"Document","kind":"note","name":"W1 hidden two","home_id":&folder}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-w1-hidden-perturbative",
            &perturbative,
            vec![],
        )
        .await
        .unwrap();
        let after = prepare_sql_write_preview(&db, &caller, args())
            .await
            .unwrap();
        assert_eq!(after.effect, prepared.effect);
        assert_eq!(after.effect_summary, prepared.effect_summary);
        assert_eq!(after.target, prepared.target);
        assert_eq!(after.target_state_digest, prepared.target_state_digest);
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        // Only the deliberate hidden fixture write appended; both preparations
        // appended nothing.
        assert_eq!(events_after, events_before + 1);
    }

    /// E0 W2 shape: an open-standby source selection prepares one `add_link`
    /// `relates_to` row per visible open work item mentioning standby, all
    /// pointing at the deciding record with note `e0-harness`. In-progress,
    /// closed, non-matching, hidden, and non-WorkItem rows are excluded.
    #[tokio::test]
    async fn sql_write_preview_prepares_w2_open_standby_link_target_set() {
        let db = create_database(":memory:").await.unwrap();
        let deciding = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000c0","type":"Document","kind":"note","name":"W2 deciding record"}),
        )
        .await
        .unwrap();
        let open_body = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000c1","type":"WorkItem","kind":"task","lifecycle":"open","name":"W2 open one","body":"covers standby rotation"}),
        )
        .await
        .unwrap();
        let open_summary = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000c2","type":"WorkItem","kind":"task","lifecycle":"open","name":"W2 open two","body":"routine","summary":"standby follow-up"}),
        )
        .await
        .unwrap();
        let in_progress = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000c3","type":"WorkItem","kind":"task","lifecycle":"in_progress","name":"W2 underway","body":"standby escalation"}),
        )
        .await
        .unwrap();
        let open_plain = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000c4","type":"WorkItem","kind":"task","lifecycle":"open","name":"W2 plain","body":"routine rotation"}),
        )
        .await
        .unwrap();
        let closed = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000c5","type":"WorkItem","kind":"task","lifecycle":"closed","name":"W2 closed","body":"standby handoff"}),
        )
        .await
        .unwrap();
        let hidden = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000c6","type":"WorkItem","kind":"task","lifecycle":"open","name":"W2 hidden","body":"standby hidden"}),
        )
        .await
        .unwrap();
        grant_link_edit(
            &db,
            &[
                &open_body,
                &open_summary,
                &in_progress,
                &open_plain,
                &closed,
                &deciding,
            ],
        )
        .await;
        replace_explicit_policy(&db, "test:sql-write-w2-hidden", &hidden, vec![])
            .await
            .unwrap();
        let caller = Caller::authenticated("plan-author");
        let statement = format!(
            "SELECT id AS record_id, 'add_link' AS op, 'relates_to' AS key, '{deciding}' AS value FROM records WHERE type = 'WorkItem' AND lifecycle = 'open' AND (name LIKE '%standby%' OR body LIKE '%standby%' OR summary LIKE '%standby%')"
        );
        let args = json!({"statement": statement, "reason": "Preview the W2 bulk link", "link_note": "e0-harness"});
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_sql_write_preview(&db, &caller, args).await.unwrap();
        assert_eq!(prepared.effect["target_count"], json!(2));
        assert_eq!(prepared.effect["op_count"], json!(2));
        let mut target_ids: Vec<&str> = prepared.effect["targets"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["record_id"].as_str().unwrap())
            .collect();
        target_ids.sort();
        let mut expected = vec![open_body.as_str(), open_summary.as_str()];
        expected.sort();
        assert_eq!(
            target_ids, expected,
            "W2 sources are exactly the open standby set"
        );
        for target in prepared.effect["targets"].as_array().unwrap() {
            let ops = target["ops"].as_array().unwrap();
            assert_eq!(ops.len(), 1);
            assert_eq!(ops[0]["op"], json!("add_link"));
            assert_eq!(ops[0]["relationship"], json!("relates_to"));
            assert_eq!(ops[0]["route"], json!("directed_legacy_link"));
            assert_eq!(ops[0]["intent"], json!("would_create_relationship"));
            assert_eq!(ops[0]["note"], json!("e0-harness"));
            assert_eq!(ops[0]["note_applied"], json!(true));
            assert_eq!(ops[0]["target_id"], json!(deciding));
            assert_eq!(ops[0]["changed"], json!(true));
        }
        assert!(
            prepared.target.starts_with("2 records ["),
            "{}",
            prepared.target
        );
        assert!(
            prepared
                .effect_summary
                .contains("new relationship with note"),
            "{}",
            prepared.effect_summary
        );
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_before, events_after,
            "preparation must append no content event"
        );
    }

    /// E4 M1 strict W3 exact-set fixture over the E3 task relation
    /// (Native records dbb9bc1, c26f553, 194fef5, d519925) with the E3
    /// currency guard (Native #1713 exposes caller-visible
    /// `records.is_current`).
    ///
    /// Strict rule pinned here, never relaxed: real unchecked `- [ ]`,
    /// `* [ ]`, `+ [ ]` items with text are INCLUDED; quotes, fences,
    /// checked, ordered, bare checkbox-only, inline-only, non-draft,
    /// superseded, and hidden/soft-deleted rows are EXCLUDED; an archived
    /// draft with a real task stays INCLUDED with archive preview
    /// `changed:false`.
    const W3_STRICT_ARCHIVE_STATEMENT: &str = "SELECT id AS record_id, 'archive' AS op, NULL AS key, NULL AS value FROM records WHERE maturity = 'draft' AND records.is_current = 1 AND EXISTS (SELECT 1 FROM body_task_items WHERE body_task_items.record_id = records.id AND checked = 0 AND in_quote = 0 AND marker IN ('-', '*', '+')) ORDER BY id";

    #[tokio::test]
    async fn sql_write_preview_w3_strict_selection_uses_visible_task_items() {
        let db = create_database(":memory:").await.unwrap();
        let body_for: std::collections::HashMap<&str, &str> = [
            ("ec00b000-0000-4000-8000-0000000000f0", "- [ ] real dash\n"),
            ("ec00b000-0000-4000-8000-0000000000f1", "* [ ] real star\n"),
            ("ec00b000-0000-4000-8000-0000000000f2", "+ [ ] real plus\n"),
            (
                "ec00b000-0000-4000-8000-0000000000f3",
                "- [ ] real\n```\n- [ ] fake\n```\n> - [ ] quoted\n",
            ),
            (
                "ec00b000-0000-4000-8000-0000000000f4",
                "```\n- [ ] fake\n```\n",
            ),
            (
                "ec00b000-0000-4000-8000-0000000000f5",
                "> - [ ] quoted only\n",
            ),
            ("ec00b000-0000-4000-8000-0000000000f6", "see `- [ ]` here\n"),
            ("ec00b000-0000-4000-8000-0000000000f7", "1. [ ] o-task\n"),
            ("ec00b000-0000-4000-8000-0000000000f8", "- [ ]\n"),
            ("ec00b000-0000-4000-8000-0000000000f9", "- [x] done\n"),
            (
                "ec00b000-0000-4000-8000-0000000000fa",
                "- [ ] real but decided\n",
            ),
            (
                "ec00b000-0000-4000-8000-0000000000fb",
                "- [ ] hidden real\n",
            ),
            (
                "ec00b000-0000-4000-8000-0000000000fc",
                "- [ ] deleted real\n",
            ),
            (
                "ec00b000-0000-4000-8000-0000000000fd",
                "- [ ] archived real\n",
            ),
            (
                "ec00b000-0000-4000-8000-0000000000fe",
                "- [ ] superseded real\n",
            ),
            (
                "ec00b000-0000-4000-8000-0000000000ff",
                "W3 successor has no task\n",
            ),
        ]
        .into_iter()
        .collect();
        let mut visible: Vec<String> = Vec::new();
        for (id, body) in &body_for {
            let maturity = if *id == "ec00b000-0000-4000-8000-0000000000fa" {
                "decided"
            } else {
                "draft"
            };
            let created = create_record(
                &db,
                json!({"id": id, "type": "Document", "kind": "note", "name": format!("W3 {id}"), "body": body, "maturity": maturity}),
            )
            .await
            .unwrap();
            if *id != "ec00b000-0000-4000-8000-0000000000fb" {
                visible.push(created);
            }
        }
        for id in &visible {
            replace_explicit_policy(
                &db,
                "test:sql-write-w3-strict",
                id,
                vec![AllowEntry::account("plan-author", Capability::Manage)],
            )
            .await
            .unwrap();
        }
        replace_explicit_policy(
            &db,
            "test:sql-write-w3-hidden",
            "ec00b000-0000-4000-8000-0000000000fb",
            vec![],
        )
        .await
        .unwrap();
        crate::store::delete_record(&db, "ec00b000-0000-4000-8000-0000000000fc")
            .await
            .unwrap();
        crate::store::archive_record(&db, "ec00b000-0000-4000-8000-0000000000fd")
            .await
            .unwrap();
        // Supersede the fe draft through the supported domain event path, so
        // the E3 currency projector nulls `records.is_current` (never a raw
        // projection forgery). The successor carries no task, so the shape
        // set below grows by exactly the superseded draft.
        crate::store::add_link(
            &db,
            crate::events::LinkAddedPayload {
                id: None,
                source_id: "ec00b000-0000-4000-8000-0000000000ff".to_string(),
                target_id: "ec00b000-0000-4000-8000-0000000000fe".to_string(),
                relationship: "supersedes".to_string(),
                note: None,
            },
        )
        .await
        .unwrap();
        let mut parser_hits: Vec<&str> = body_for
            .iter()
            .filter(|(id, body)| {
                let maturity = if **id == "ec00b000-0000-4000-8000-0000000000fa" {
                    "decided"
                } else {
                    "draft"
                };
                if maturity != "draft" {
                    return false;
                }
                if **id == "ec00b000-0000-4000-8000-0000000000fb"
                    || **id == "ec00b000-0000-4000-8000-0000000000fc"
                {
                    return false;
                }
                crate::body_task_items::extract_task_items(body)
                    .expect("fixture body must parse")
                    .iter()
                    .any(|item| item.is_w3_candidate())
            })
            .map(|(id, _)| *id)
            .collect();
        parser_hits.sort_unstable();
        assert_eq!(
            parser_hits,
            vec![
                "ec00b000-0000-4000-8000-0000000000f0",
                "ec00b000-0000-4000-8000-0000000000f1",
                "ec00b000-0000-4000-8000-0000000000f2",
                "ec00b000-0000-4000-8000-0000000000f3",
                "ec00b000-0000-4000-8000-0000000000fd",
                "ec00b000-0000-4000-8000-0000000000fe",
            ],
            "parser shape set: dash/star/plus + mixed + archived-draft real + superseded-draft real"
        );
        let caller = Caller::authenticated("plan-author");
        // Currency proof through the caller-visible lens, before preview: the
        // superseded draft must read non-current while the exact-five stay
        // current, so the preview exclusion below is not vacuous.
        let currency_probe = crate::query::sql::query_sql_request_owned(
            db.clone(),
            (&caller).into(),
            crate::query::sql_contract::QuerySqlRequest {
                sql: "SELECT id, is_current, successor_count FROM records WHERE id IN ('ec00b000-0000-4000-8000-0000000000f0', 'ec00b000-0000-4000-8000-0000000000f1', 'ec00b000-0000-4000-8000-0000000000f2', 'ec00b000-0000-4000-8000-0000000000f3', 'ec00b000-0000-4000-8000-0000000000fd', 'ec00b000-0000-4000-8000-0000000000fe', 'ec00b000-0000-4000-8000-0000000000ff') ORDER BY id"
                    .to_string(),
                parameters: vec![],
            },
        )
        .await
        .expect("caller-visible currency probe must serve");
        let row_by_id = |id: &str| {
            currency_probe
                .rows
                .iter()
                .find(|row| row["id"] == json!(id))
                .unwrap_or_else(|| panic!("currency probe must return {id}"))
                .clone()
        };
        let superseded_row = row_by_id("ec00b000-0000-4000-8000-0000000000fe");
        assert_eq!(superseded_row["is_current"], json!(null));
        assert_eq!(superseded_row["successor_count"], json!(1));
        for id in [
            "ec00b000-0000-4000-8000-0000000000f0",
            "ec00b000-0000-4000-8000-0000000000f1",
            "ec00b000-0000-4000-8000-0000000000f2",
            "ec00b000-0000-4000-8000-0000000000f3",
            "ec00b000-0000-4000-8000-0000000000fd",
        ] {
            let row = row_by_id(id);
            assert_eq!(row["is_current"], json!(1), "{id} must stay current");
            assert_eq!(
                row["successor_count"],
                json!(0),
                "{id} must have no successor"
            );
        }
        let successor_row = row_by_id("ec00b000-0000-4000-8000-0000000000ff");
        assert_eq!(successor_row["is_current"], json!(1));
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_sql_write_preview(
            &db,
            &caller,
            json!({"statement": W3_STRICT_ARCHIVE_STATEMENT, "reason": "W3 strict target-set probe"}),
        )
        .await
        .expect("W3 task relation must serve the strict selection");
        let expected_selected = vec![
            "ec00b000-0000-4000-8000-0000000000f0",
            "ec00b000-0000-4000-8000-0000000000f1",
            "ec00b000-0000-4000-8000-0000000000f2",
            "ec00b000-0000-4000-8000-0000000000f3",
            "ec00b000-0000-4000-8000-0000000000fd",
        ];
        assert_eq!(
            prepared.effect["target_count"],
            json!(expected_selected.len())
        );
        assert_eq!(prepared.effect["op_count"], json!(expected_selected.len()));
        let targets = prepared.effect["targets"].as_array().unwrap();
        let selected: Vec<&str> = targets
            .iter()
            .map(|target| target["record_id"].as_str().unwrap())
            .collect();
        assert_eq!(
            selected, expected_selected,
            "preview must preserve the exact currency-aware W3 set"
        );
        assert!(
            !selected.contains(&"ec00b000-0000-4000-8000-0000000000fe"),
            "superseded draft must be excluded by the currency guard"
        );
        for target in targets {
            let op = &target["ops"][0];
            assert_eq!(op["op"], json!("archive"));
            assert_eq!(target["ops"].as_array().unwrap().len(), 1);
            let already_archived = target["record_id"] == "ec00b000-0000-4000-8000-0000000000fd";
            assert_eq!(op["before"], json!(already_archived));
            assert_eq!(op["after"], json!(true));
            assert_eq!(op["changed"], json!(!already_archived));
        }
        let unavailable =
            W3_STRICT_ARCHIVE_STATEMENT.replace("body_task_items", "body_task_items_unavailable");
        let error = prepare_sql_write_preview(
            &db,
            &caller,
            json!({"statement": unavailable, "reason": "W3 unavailable-relation probe"}),
        )
        .await
        .expect_err("an unavailable task relation must fail closed");
        let detail = error.to_string();
        assert!(detail.contains("selection rejected"), "{detail}");
        assert!(detail.contains("body_task_items_unavailable"), "{detail}");
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_before, events_after,
            "preview preparation and refused selection append nothing"
        );
    }

    /// `set_facet` compares the full `(value, vocab_ref)` pair: a value-equal
    /// but reference-different write is `changed: true`, and a same-pair write
    /// is a true no-op. The governed reference is derived by the shared fold,
    /// never supplied by the string-only row.
    #[tokio::test]
    async fn sql_write_preview_facet_vocab_ref_drift_is_changed_and_same_pair_is_noop() {
        let db = create_database(":memory:").await.unwrap();
        crate::meta::seed_pack_schema_config(
            &db,
            "@test/sql-write-facet",
            json!({ "shapes": { "Document": { "facets": { "e4mw1": { "vocab": "e4mw1" } } } } }),
            crate::meta::SchemaConfigOptions::default(),
        )
        .await
        .unwrap();
        crate::meta::create_vocabulary(&db, "e4mw1", None)
            .await
            .unwrap();
        let active = crate::meta::propose_value(&db, "e4mw1", "done", None)
            .await
            .unwrap();
        crate::meta::promote_value(&db, &active).await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000b1","type":"Document","kind":"note","name":"Facet drift"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-facet-drift",
            &target,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        let facet = |value: &str, vocab_ref: Option<String>| crate::events::FacetSetPayload {
            key: "e4mw1".into(),
            value: Some(value.into()),
            vocab_ref,
            as_of: None,
            observation_only: false,
        };
        // Current value equal to the proposal, stored without the governed
        // reference (the pre-governance / legacy state).
        crate::store::set_facet(&db, &target, facet("done", None))
            .await
            .unwrap();
        let caller = Caller::authenticated("plan-author");
        let args = || {
            json!({
                "statement": format!("SELECT id AS record_id, 'set_facet' AS op, 'e4mw1' AS key, 'done' AS value FROM records WHERE id = '{target}'"),
                "reason": "Preview a governed facet assertion",
            })
        };
        let drifted = prepare_sql_write_preview(&db, &caller, args())
            .await
            .unwrap();
        let op = &drifted.effect["targets"][0]["ops"][0];
        assert_eq!(op["value"], json!("done"));
        assert_eq!(op["before"], json!("done"));
        assert_eq!(op["after"], json!("done"));
        assert_eq!(op["before_vocab_ref"], json!(null));
        let derived = op["after_vocab_ref"]
            .as_str()
            .expect("governance must derive a vocab_ref");
        assert!(derived.starts_with("rec:"), "{derived}");
        assert_eq!(
            op["changed"],
            json!(true),
            "value-equal but reference-different must be changed"
        );
        // Persist the governed reference, then re-prepare: an exact same-pair
        // write is a true no-op.
        crate::store::set_facet(&db, &target, facet("done", Some(derived.to_string())))
            .await
            .unwrap();
        let noop = prepare_sql_write_preview(&db, &caller, args())
            .await
            .unwrap();
        let op = &noop.effect["targets"][0]["ops"][0];
        assert_eq!(op["before_vocab_ref"], json!(derived));
        assert_eq!(op["after_vocab_ref"], json!(derived));
        assert_eq!(
            op["changed"],
            json!(false),
            "same (value, vocab_ref) pair is a no-op"
        );
        assert_eq!(noop.effect["changed"], json!(false));
    }

    /// Facet keys the singular writer refuses are refused here too: spine
    /// facets, engine-reserved facets, and non-string values never sign.
    #[tokio::test]
    async fn sql_write_preview_refuses_reserved_spine_and_non_string_facet_rows() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000c1","type":"Document","kind":"note","name":"Key guard"}),
        )
        .await
        .unwrap();
        let caller = Caller::local();
        let facet_stmt = |key: &str| {
            json!({
                "statement": format!("SELECT id AS record_id, 'set_facet' AS op, '{key}' AS key, 'x' AS value FROM records WHERE id = '{target}'"),
                "reason": "Facet key guard probe",
            })
        };
        for (key, expected) in [
            ("lifecycle", "spine facet"),
            ("persistence", "spine facet"),
            ("archived", "engine-reserved"),
        ] {
            let error = prepare_sql_write_preview(&db, &caller, facet_stmt(key))
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{key}: {error}");
        }
        // A non-string value cell (SQL INTEGER) refuses rather than folding.
        let typed = prepare_sql_write_preview(
            &db,
            &caller,
            json!({
                "statement": format!("SELECT id AS record_id, 'set_facet' AS op, 'e0probe' AS key, 7 AS value FROM records WHERE id = '{target}'"),
                "reason": "Non-string facet value probe",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(typed.contains("must be a JSON string"), "{typed}");
        // A caller-supplied key is bounded before it enters the signed effect
        // and summary; a query cell can be far larger than any value bound.
        let oversized_key: String = std::iter::repeat_n('k', 121).collect();
        let oversized = prepare_sql_write_preview(&db, &caller, facet_stmt(&oversized_key))
            .await
            .unwrap_err()
            .to_string();
        assert!(oversized.contains("facet key exceeds 120"), "{oversized}");
    }

    /// `unset_facet` clears an existing open facet (`changed:true`) and signs
    /// an absent facet as `changed:false` projected state with the same effect keys,
    /// matching `update_record.facets` explicit-null parity. The typed row
    /// requires a SQL NULL value; preparation appends no event.
    #[tokio::test]
    async fn sql_write_preview_unset_facet_existing_and_missing_sign_noop_parity() {
        let db = create_database(":memory:").await.unwrap();
        let existing = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e1","type":"Document","kind":"note","name":"Unset existing"}),
        )
        .await
        .unwrap();
        let absent = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e2","type":"Document","kind":"note","name":"Unset absent"}),
        )
        .await
        .unwrap();
        for id in [&existing, &absent] {
            replace_explicit_policy(
                &db,
                "test:sql-write-unset-visible",
                id,
                vec![AllowEntry::account("plan-author", Capability::Manage)],
            )
            .await
            .unwrap();
        }
        crate::store::set_facet(
            &db,
            &existing,
            crate::events::FacetSetPayload {
                key: "e0probe".into(),
                value: Some("done".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        let caller = Caller::authenticated("plan-author");
        let unset_args = |id: &str| {
            json!({
                "statement": format!("SELECT id AS record_id, 'unset_facet' AS op, 'e0probe' AS key, NULL AS value FROM records WHERE id = '{id}'"),
                "reason": "Preview the facet clear",
            })
        };
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_sql_write_preview(&db, &caller, unset_args(&existing))
            .await
            .unwrap();
        assert_eq!(prepared.effect["target_count"], json!(1));
        assert_eq!(prepared.effect["op_count"], json!(1));
        assert_eq!(prepared.effect["changed"], json!(true));
        let ops = prepared.effect["targets"][0]["ops"].as_array().unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0]["op"], json!("unset_facet"));
        assert_eq!(ops[0]["key"], json!("e0probe"));
        assert_eq!(ops[0]["value"], json!(null));
        assert_eq!(ops[0]["before"], json!("done"));
        assert_eq!(ops[0]["after"], json!(null));
        assert_eq!(ops[0]["before_vocab_ref"], json!(null));
        assert_eq!(ops[0]["after_vocab_ref"], json!(null));
        assert_eq!(ops[0]["changed"], json!(true));
        assert!(prepared.effect_summary.contains("unset_facet 'e0probe'"));
        assert!(prepared.target.starts_with("1 record ["));
        assert_eq!(prepared.target_state_digest.len(), 64);
        let missing = prepare_sql_write_preview(&db, &caller, unset_args(&absent))
            .await
            .unwrap();
        let missing_ops = missing.effect["targets"][0]["ops"].as_array().unwrap();
        assert_eq!(missing.effect["changed"], json!(false));
        assert_eq!(missing_ops[0]["op"], json!("unset_facet"));
        assert_eq!(missing_ops[0]["before"], json!(null));
        assert_eq!(missing_ops[0]["after"], json!(null));
        assert_eq!(missing_ops[0]["changed"], json!(false));
        assert!(missing.effect_summary.contains("unset_facet 'e0probe'"));
        let repeat = prepare_sql_write_preview(&db, &caller, unset_args(&existing))
            .await
            .unwrap();
        assert_eq!(repeat.effect, prepared.effect);
        assert_eq!(repeat.target_state_digest, prepared.target_state_digest);
        let non_null = prepare_sql_write_preview(
            &db,
            &caller,
            json!({
                "statement": format!("SELECT id AS record_id, 'unset_facet' AS op, 'e0probe' AS key, 'done' AS value FROM records WHERE id = '{existing}'"),
                "reason": "Non-null unset value probe",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            non_null.contains("requires a SQL NULL 'value'"),
            "{non_null}"
        );
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(events_after, events_before);
    }

    /// `unset_facet` uses the same snapshot for visibility, Edit, and version
    /// pinning: hidden and missing refuse identically, View-only refuses Edit,
    /// and a concurrent clear changes the signed effect so revalidation sees
    /// drift. Preparations append no event.
    #[tokio::test]
    async fn sql_write_preview_unset_facet_hidden_edit_and_stale_drift() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e3","type":"Document","kind":"note","name":"Unset drift"}),
        )
        .await
        .unwrap();
        let hidden = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e4","type":"Document","kind":"note","name":"Unset hidden"}),
        )
        .await
        .unwrap();
        let view_only = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e5","type":"Document","kind":"note","name":"Unset view"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-unset-manage",
            &target,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "test:sql-write-unset-hidden", &hidden, vec![])
            .await
            .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-unset-view",
            &view_only,
            vec![AllowEntry::account("plan-author", Capability::View)],
        )
        .await
        .unwrap();
        crate::store::set_facet(
            &db,
            &target,
            crate::events::FacetSetPayload {
                key: "e0probe".into(),
                value: Some("done".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        let caller = Caller::authenticated("plan-author");
        let unset_args = |id: &str| {
            json!({
                "statement": format!("SELECT id AS record_id, 'unset_facet' AS op, 'e0probe' AS key, NULL AS value FROM records WHERE id = '{id}'"),
                "reason": "Preview the facet clear",
            })
        };
        let hidden_error = prepare_sql_write_preview(&db, &caller, unset_args(&hidden))
            .await
            .unwrap_err()
            .to_string();
        let missing_error = prepare_sql_write_preview(
            &db,
            &caller,
            unset_args("ec00b000-0000-4000-8000-00000000ffff"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(hidden_error, missing_error);
        let view_error = prepare_sql_write_preview(&db, &caller, unset_args(&view_only))
            .await
            .unwrap_err()
            .to_string();
        assert!(view_error.contains("capability"), "{view_error}");
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_sql_write_preview(&db, &caller, unset_args(&target))
            .await
            .unwrap();
        assert_eq!(prepared.effect["changed"], json!(true));
        let previous_seq = prepared.effect["targets"][0]["previous_seq"]
            .as_i64()
            .unwrap();
        crate::store::unset_facet(&db, &target, "e0probe")
            .await
            .unwrap();
        let drifted = prepare_sql_write_preview(&db, &caller, unset_args(&target))
            .await
            .unwrap();
        assert_eq!(drifted.effect["changed"], json!(false));
        assert_ne!(drifted.effect, prepared.effect);
        assert_ne!(drifted.target_state_digest, prepared.target_state_digest);
        let stale = prepare_sql_write_preview(
            &db,
            &caller,
            json!({
                "statement": format!("SELECT id AS record_id, 'unset_facet' AS op, 'e0probe' AS key, NULL AS value FROM records WHERE id = '{target}'"),
                "reason": "Stale version probe",
                "expected_version": previous_seq,
            }),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(stale.contains("content revision conflict"), "{stale}");
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(events_after, events_before + 1);
    }

    /// `unset_facet` refuses a present required open facet read-only, matching
    /// the singular `update_record` before/after `required_violations_in` plus
    /// `assert_required_not_worsened` without mutating to simulate. A
    /// nonrequired present facet still prepares, and an absent required facet
    /// (already-violating state) still prepares a no-op.
    #[tokio::test]
    async fn sql_write_preview_unset_facet_required_refuses_while_nonrequired_and_absent_prepare() {
        let db = create_database(":memory:").await.unwrap();
        let required_target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e6","type":"Document","kind":"note","name":"Unset required"}),
        )
        .await
        .unwrap();
        let plain_target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000e7","type":"Document","kind":"note","name":"Unset plain"}),
        )
        .await
        .unwrap();
        let req_facet = || crate::events::FacetSetPayload {
            key: "e4req".into(),
            value: Some("done".into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        };
        crate::store::set_facet(&db, &required_target, req_facet())
            .await
            .unwrap();
        crate::store::set_facet(
            &db,
            &required_target,
            crate::events::FacetSetPayload {
                key: "e0probe".into(),
                value: Some("done".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        crate::meta::seed_pack_schema_config(
            &db,
            "@test/sql-write-unset-required",
            json!({ "shapes": { "Document": { "facets": { "e4req": { "required": true } } } } }),
            crate::meta::SchemaConfigOptions::default(),
        )
        .await
        .unwrap();
        let caller = Caller::local();
        let unset_args = |id: &str, key: &str| {
            json!({
                "statement": format!("SELECT id AS record_id, 'unset_facet' AS op, '{key}' AS key, NULL AS value FROM records WHERE id = '{id}'"),
                "reason": "Preview the required facet clear",
            })
        };
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let preview_error =
            prepare_sql_write_preview(&db, &caller, unset_args(&required_target, "e4req"))
                .await
                .unwrap_err()
                .to_string();
        assert!(
            preview_error.contains("would worsen required-facet conformance"),
            "{preview_error}"
        );
        assert!(
            preview_error.contains("missing required facet 'e4req'"),
            "{preview_error}"
        );
        let singular_error = registry()
            .call(
                db.clone(),
                caller.clone(),
                "update_record",
                json!({"id": required_target, "facets": {"e4req": null}, "reason": "Clear the required facet"}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            singular_error.contains("would worsen required-facet conformance"),
            "{singular_error}"
        );
        assert!(
            singular_error.contains("missing required facet 'e4req'"),
            "{singular_error}"
        );
        let nonrequired =
            prepare_sql_write_preview(&db, &caller, unset_args(&required_target, "e0probe"))
                .await
                .unwrap();
        assert_eq!(nonrequired.effect["changed"], json!(true));
        let absent = prepare_sql_write_preview(&db, &caller, unset_args(&plain_target, "e4req"))
            .await
            .unwrap();
        assert_eq!(absent.effect["changed"], json!(false));
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(events_after, events_before);
    }

    /// `set_field` and `set_facet` rows share one total operation cap: 25
    /// targets × (one field + one facet) prepares 50 rows, and a 51st row
    /// refuses overflow. Duplicate facet keys refuse per `(record_id, key)`.
    #[tokio::test]
    async fn sql_write_preview_mixed_field_and_facet_share_one_operation_bound() {
        let db = create_database(":memory:").await.unwrap();
        let mut ids = Vec::new();
        for index in 0..25u32 {
            let id = format!("ec00b000-0000-4000-8000-{:012}", 0x300 + index);
            create_record(
                &db,
                json!({"id": id, "type":"Document","kind":"note","name": format!("Mix {index}")}),
            )
            .await
            .unwrap();
            ids.push(id);
        }
        let caller = Caller::local();
        let at_bound = json!({
            "statement": "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Mixed' AS value FROM records WHERE name LIKE 'Mix %' \
                          UNION ALL \
                          SELECT id AS record_id, 'set_facet' AS op, 'e0probe' AS key, 'done' AS value FROM records WHERE name LIKE 'Mix %'",
            "reason": "Mixed boundary probe",
        });
        let accepted = prepare_sql_write_preview(&db, &caller, at_bound)
            .await
            .unwrap();
        assert_eq!(accepted.effect["target_count"], json!(25));
        assert_eq!(accepted.effect["op_count"], json!(50));
        let overflow = json!({
            "statement": "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Mixed' AS value FROM records WHERE name LIKE 'Mix %' \
                          UNION ALL \
                          SELECT id AS record_id, 'set_field' AS op, 'summary' AS key, 'Mixed summary' AS value FROM records WHERE name LIKE 'Mix %' \
                          UNION ALL \
                          SELECT id AS record_id, 'set_facet' AS op, 'e0probe' AS key, 'done' AS value FROM records WHERE name LIKE 'Mix %'",
            "reason": "Mixed overflow probe",
        });
        let overflow_error = prepare_sql_write_preview(&db, &caller, overflow)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            overflow_error.contains("50-operation preview bound"),
            "{overflow_error}"
        );
        let first = ids[0].clone();
        let duplicate = json!({
            "statement": format!(
                "SELECT id AS record_id, 'set_facet' AS op, 'e0probe' AS key, 'a' AS value FROM records WHERE id = '{first}' \
                 UNION ALL \
                 SELECT id AS record_id, 'set_facet' AS op, 'e0probe' AS key, 'b' AS value FROM records WHERE id = '{first}'"
            ),
            "reason": "Duplicate facet probe",
        });
        let duplicate_error = prepare_sql_write_preview(&db, &caller, duplicate)
            .await
            .unwrap_err()
            .to_string();
        assert!(duplicate_error.contains("duplicate"), "{duplicate_error}");
    }

    /// E4 M1 archive slice: an `archive` typed row requires Manage (unlike
    /// field/facet Edit), signs the exact archived before/after as
    /// `changed:true` on an unarchived target, and never writes the facet during
    /// preparation. Edit-only callers keep field/facet access but cannot
    /// archive.
    #[tokio::test]
    async fn sql_write_preview_archive_requires_manage_and_signs_archived_transition() {
        let db = create_database(":memory:").await.unwrap();
        let managed = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000d1","type":"Document","kind":"note","name":"Managed archive"}),
        )
        .await
        .unwrap();
        let edit_only = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000d2","type":"Document","kind":"note","name":"Edit only"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-archive-manage",
            &managed,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-archive-edit",
            &edit_only,
            vec![AllowEntry::account("plan-author", Capability::Edit)],
        )
        .await
        .unwrap();
        let caller = Caller::authenticated("plan-author");
        let archive_args = |id: &str| {
            json!({
                "statement": format!("SELECT id AS record_id, 'archive' AS op, NULL AS key, NULL AS value FROM records WHERE id = '{id}'"),
                "reason": "Preview the archive lifecycle transition",
            })
        };
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_sql_write_preview(&db, &caller, archive_args(&managed))
            .await
            .unwrap();
        assert_eq!(
            prepared.target_id, managed,
            "one target keeps its record id"
        );
        assert_eq!(prepared.effect["target_count"], json!(1));
        assert_eq!(prepared.effect["op_count"], json!(1));
        assert_eq!(prepared.effect["changed"], json!(true));
        let ops = prepared.effect["targets"][0]["ops"]
            .as_array()
            .expect("target ops array");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0]["op"], json!("archive"));
        assert_eq!(ops[0]["before"], json!(false));
        assert_eq!(ops[0]["after"], json!(true));
        assert_eq!(ops[0]["changed"], json!(true));
        assert!(
            ops[0].get("key").is_none() && ops[0].get("value").is_none(),
            "archive must not invent a facet key/value payload: {}",
            ops[0]
        );
        assert!(
            prepared.effect_summary.contains("archive of"),
            "{}",
            prepared.effect_summary
        );
        // Preparation never writes the archived facet: the preview is not the
        // transition.
        let archived_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM facet_values WHERE record_id = ? AND key = 'archived'",
        )
        .bind(&managed)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(archived_rows, 0, "preparation must not archive");
        // Archive requires Manage: the Edit-only record refuses archive.
        let edit_error = prepare_sql_write_preview(&db, &caller, archive_args(&edit_only))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            edit_error.contains("requires manage capability"),
            "{edit_error}"
        );
        // Edit still admits a field edit on that same Edit-only record.
        let field = prepare_sql_write_preview(
            &db,
            &caller,
            json!({
                "statement": format!("SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{edit_only}'"),
                "reason": "Edit-only field probe",
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            field.effect["targets"][0]["ops"][0]["op"],
            json!("set_field")
        );
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(events_after, events_before, "preparation appends no event");
    }

    /// An already-archived target prepares as a `changed:false` no-op, matching
    /// `archive_record` and the batch archive item, rather than refusing like a
    /// field/facet edit on an archived record.
    #[tokio::test]
    async fn sql_write_preview_archive_on_archived_target_is_changed_false_noop() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000d3","type":"Document","kind":"note","name":"Already archived"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-archive-already",
            &target,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        crate::store::archive_record(&db, &target).await.unwrap();
        let caller = Caller::authenticated("plan-author");
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let prepared = prepare_sql_write_preview(
            &db,
            &caller,
            json!({
                "statement": format!("SELECT id AS record_id, 'archive' AS op, NULL AS key, NULL AS value FROM records WHERE id = '{target}'"),
                "reason": "Preview an archive no-op",
            }),
        )
        .await
        .unwrap();
        let op = &prepared.effect["targets"][0]["ops"][0];
        assert_eq!(op["op"], json!("archive"));
        assert_eq!(op["before"], json!(true));
        assert_eq!(op["after"], json!(true));
        assert_eq!(op["changed"], json!(false));
        assert_eq!(prepared.effect["changed"], json!(false));
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_after, events_before,
            "no-op preparation appends nothing"
        );
    }

    /// Archive shape and composition refusals: a non-null key or value, an
    /// extra column, a duplicate archive row, archive mixed with another op on
    /// the same record, and a tombstoned target all refuse with nothing
    /// written.
    #[tokio::test]
    async fn sql_write_preview_archive_refuses_bad_shape_tombstone_duplicate_and_mixed() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000d4","type":"Document","kind":"note","name":"Archive shape"}),
        )
        .await
        .unwrap();
        let tombstoned = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000d5","type":"Document","kind":"note","name":"Tombstoned"}),
        )
        .await
        .unwrap();
        for id in [target.as_str(), tombstoned.as_str()] {
            replace_explicit_policy(
                &db,
                "test:sql-write-archive-shape",
                id,
                vec![AllowEntry::account("plan-author", Capability::Manage)],
            )
            .await
            .unwrap();
        }
        crate::store::delete_record(&db, &tombstoned).await.unwrap();
        let caller = Caller::authenticated("plan-author");
        let probe = |statement: String| {
            let db = db.clone();
            let caller = caller.clone();
            async move {
                prepare_sql_write_preview(
                    &db,
                    &caller,
                    json!({
                        "statement": statement,
                        "reason": "Archive shape probe",
                    }),
                )
                .await
            }
        };
        let nonnull_key = probe(format!(
            "SELECT id AS record_id, 'archive' AS op, 'archived' AS key, NULL AS value FROM records WHERE id = '{target}'"
        ))
        .await
        .unwrap_err()
        .to_string();
        assert!(nonnull_key.contains("SQL NULL 'key'"), "{nonnull_key}");
        let nonnull_value = probe(format!(
            "SELECT id AS record_id, 'archive' AS op, NULL AS key, 'true' AS value FROM records WHERE id = '{target}'"
        ))
        .await
        .unwrap_err()
        .to_string();
        assert!(
            nonnull_value.contains("SQL NULL 'value'"),
            "{nonnull_value}"
        );
        let extra_column = probe(format!(
            "SELECT id AS record_id, 'archive' AS op, NULL AS key, NULL AS value, 1 AS extra FROM records WHERE id = '{target}'"
        ))
        .await
        .unwrap_err()
        .to_string();
        assert!(
            extra_column.contains("unknown operation field 'extra'"),
            "{extra_column}"
        );
        let duplicate = probe(format!(
            "SELECT id AS record_id, 'archive' AS op, NULL AS key, NULL AS value FROM records WHERE id = '{target}' \
             UNION ALL \
             SELECT id AS record_id, 'archive' AS op, NULL AS key, NULL AS value FROM records WHERE id = '{target}'"
        ))
        .await
        .unwrap_err()
        .to_string();
        assert!(duplicate.contains("duplicate"), "{duplicate}");
        let mixed = probe(format!(
            "SELECT id AS record_id, 'archive' AS op, NULL AS key, NULL AS value FROM records WHERE id = '{target}' \
             UNION ALL \
             SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{target}'"
        ))
        .await
        .unwrap_err()
        .to_string();
        assert!(
            mixed.contains("mixes 'archive' with another operation"),
            "{mixed}"
        );
        // A tombstoned target refuses; the refusal is drift-shaped (Conflict),
        // never a successful preview.
        let tombstone_error = probe(format!(
            "SELECT id AS record_id, 'archive' AS op, NULL AS key, NULL AS value FROM records WHERE id = '{tombstoned}'"
        ))
        .await
        .unwrap_err();
        assert!(
            matches!(&tombstone_error, Error::Conflict(_)),
            "tombstone refusal must be drift-shaped: {tombstone_error}"
        );
        // The target is still live and unarchived: every refusal above appended
        // no event and did not archive.
        let archived_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM facet_values WHERE record_id = ? AND key = 'archived'",
        )
        .bind(&target)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(archived_rows, 0);
    }

    /// A hidden record that a predicate also matches does not perturb the
    /// archive target set, signed effect, summary, or digest, and preparation
    /// appends no event.
    #[tokio::test]
    async fn sql_write_preview_archive_hidden_match_does_not_perturb() {
        let db = create_database(":memory:").await.unwrap();
        let visible = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000d6","type":"Document","kind":"note","name":"Archivable visible"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-archive-visible",
            &visible,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        let hidden = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000d7","type":"Document","kind":"note","name":"Archivable hidden"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(&db, "test:sql-write-archive-hidden", &hidden, vec![])
            .await
            .unwrap();
        let caller = Caller::authenticated("plan-author");
        let args = || {
            json!({
                "statement": "SELECT id AS record_id, 'archive' AS op, NULL AS key, NULL AS value FROM records WHERE name LIKE 'Archivable %'",
                "reason": "Archive hidden-match probe",
            })
        };
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let before = prepare_sql_write_preview(&db, &caller, args())
            .await
            .unwrap();
        assert_eq!(before.effect["target_count"], json!(1));
        assert_eq!(
            before.effect["targets"][0]["record_id"],
            json!(visible),
            "the hidden match must not enter the target set"
        );
        // A further hidden match changes nothing signed.
        let perturbative = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-0000000000d8","type":"Document","kind":"note","name":"Archivable hidden two"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-archive-hidden-two",
            &perturbative,
            vec![],
        )
        .await
        .unwrap();
        let after = prepare_sql_write_preview(&db, &caller, args())
            .await
            .unwrap();
        assert_eq!(after.effect, before.effect);
        assert_eq!(after.effect_summary, before.effect_summary);
        assert_eq!(after.target, before.target);
        assert_eq!(after.target_state_digest, before.target_state_digest);
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_after,
            events_before + 1,
            "only the deliberate hidden fixture write appends; preparations add nothing"
        );
    }

    /// Temporary ambiguity guard (E4 M1; E3 M1 stays open): a live incoming
    /// `supersedes` link refuses the preview before any signed effect exists.
    /// Visible and hidden successors refuse with the same stable string and
    /// never leak the successor; a tombstoned successor discloses nothing.
    #[tokio::test]
    async fn sql_write_preview_refuses_superseded_target() {
        let db = create_database(":memory:").await.unwrap();
        let mk = |id: &str, name: &str| {
            let db = db.clone();
            let body = json!({"id":id,"type":"Document","kind":"note","name":name});
            async move { create_record(&db, body).await.unwrap() }
        };
        let target_v = mk("ec00b000-0000-4000-8000-000000000aa1", "Superseded visible").await;
        let succ_visible = mk("ec00b000-0000-4000-8000-000000000aa2", "Visible successor").await;
        let target_h = mk("ec00b000-0000-4000-8000-000000000aa3", "Superseded hidden").await;
        let succ_hidden = mk("ec00b000-0000-4000-8000-000000000aa4", "Hidden successor").await;
        let target_t = mk(
            "ec00b000-0000-4000-8000-000000000aa5",
            "Tombstoned successor target",
        )
        .await;
        let succ_tomb = mk(
            "ec00b000-0000-4000-8000-000000000aa6",
            "Tombstoned successor",
        )
        .await;
        for (id, cap) in [
            (target_v.as_str(), Capability::Edit),
            (succ_visible.as_str(), Capability::View),
            (target_h.as_str(), Capability::Edit),
            (target_t.as_str(), Capability::Edit),
            (succ_tomb.as_str(), Capability::View),
        ] {
            replace_explicit_policy(
                &db,
                "test:sql-write-superseded",
                id,
                vec![AllowEntry::account("plan-author", cap)],
            )
            .await
            .unwrap();
        }
        // succ_hidden gets an explicitly empty policy: hidden by decision,
        // not by the absence of a fixture grant.
        replace_explicit_policy(
            &db,
            "test:sql-write-superseded-hidden",
            &succ_hidden,
            vec![],
        )
        .await
        .unwrap();
        for (n, source, target) in [
            (
                "supersede-visible",
                succ_visible.as_str(),
                target_v.as_str(),
            ),
            ("supersede-hidden", succ_hidden.as_str(), target_h.as_str()),
            ("supersede-tomb", succ_tomb.as_str(), target_t.as_str()),
        ] {
            sqlx::query("INSERT INTO links(id,source_id,target_id,relationship) VALUES (?,?,?,'supersedes')")
                .bind(n)
                .bind(source)
                .bind(target)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        crate::store::delete_record(&db, &succ_tomb).await.unwrap();
        let caller = Caller::authenticated("plan-author");
        let args = |id: &str| {
            json!({
                "statement": format!("SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{id}'"),
                "reason": "Superseded-target probe",
            })
        };
        // Hiddenness proof through the same governed lens the probe runs
        // under: selecting the hidden successor itself refuses
        // byte-identically to a missing record, so the refusal comparison
        // below is genuinely visible-vs-hidden, not visible-vs-unasserted.
        let hidden_direct = prepare_sql_write_preview(&db, &caller, args(&succ_hidden))
            .await
            .unwrap_err()
            .to_string();
        let missing_direct =
            prepare_sql_write_preview(&db, &caller, args("ec00b000-0000-4000-8000-00000000ffff"))
                .await
                .unwrap_err()
                .to_string();
        assert_eq!(
            hidden_direct, missing_direct,
            "succ_hidden must be hidden to plan-author"
        );
        // The tombstoned-successor case is vacuous unless the link row
        // survives the successor's deletion (links cascade only on hard
        // delete) while the successor itself reads tombstoned.
        let tomb_link: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE id = 'supersede-tomb'")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(
            tomb_link, 1,
            "delete_record must tombstone, not remove the link row"
        );
        let tomb_deleted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM records WHERE id = ? AND deleted_at IS NOT NULL",
        )
        .bind(succ_tomb.as_str())
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            tomb_deleted, 1,
            "the tombstoned successor must read tombstoned"
        );
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let err_v = prepare_sql_write_preview(&db, &caller, args(&target_v))
            .await
            .unwrap_err()
            .to_string();
        assert!(err_v.contains("has an incoming supersedes link"), "{err_v}");
        assert!(err_v.contains(&target_v), "{err_v}");
        assert!(!err_v.contains(&succ_visible), "{err_v}");
        assert!(!err_v.contains("Visible successor"), "{err_v}");
        let err_h = prepare_sql_write_preview(&db, &caller, args(&target_h))
            .await
            .unwrap_err()
            .to_string();
        assert!(err_h.contains("has an incoming supersedes link"), "{err_h}");
        assert!(!err_h.contains(&succ_hidden), "{err_h}");
        assert!(!err_h.contains("Hidden successor"), "{err_h}");
        assert_eq!(
            err_h.replace(target_h.as_str(), "ID"),
            err_v.replace(target_v.as_str(), "ID"),
            "visible and hidden successors must refuse identically"
        );
        prepare_sql_write_preview(&db, &caller, args(&target_t))
            .await
            .expect("a tombstoned successor discloses nothing and must prepare");
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_after, events_before,
            "refusals and preparations append nothing"
        );
    }

    /// A `supersedes` link added after prepare makes the execute-shaped
    /// call revalidate as `plan_stale` (never `plan_revalidation_failed`)
    /// with no dispatch: the full plan prepare + execute path, not just a
    /// second preparer call.
    #[tokio::test]
    async fn sql_write_preview_supersede_after_prepare_is_stale() {
        use crate::mcp::{
            register_allowlisted_experimental_tools, ExperimentalExecutors,
            EXPERIMENTAL_SQL_WRITE_EXECUTOR,
        };

        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000ab1","type":"Document","kind":"note","name":"Drift target"}),
        )
        .await
        .unwrap();
        let telemetry = ExecutorTelemetryContext::new(
            Arc::new(super::telemetry::TestTelemetrySink::default()),
            super::telemetry::DEFAULT_RETENTION_DAYS,
        )
        .unwrap();
        let experimental = ExperimentalExecutors::from_env_value(Some(
            EXPERIMENTAL_SQL_WRITE_EXECUTOR.to_string(),
        ))
        .unwrap();
        // The executor contract requires the allowlisted source tool in the
        // registry, exactly as production registers it: without the source
        // there is no contract and the execute-shaped call cannot route.
        let mut allowlisted = ToolRegistry::new();
        register_builtin_tools(&mut allowlisted).unwrap();
        register_surface_tools(&mut allowlisted).unwrap();
        register_allowlisted_experimental_tools(&mut allowlisted, &experimental).unwrap();
        let server = ExecutorPrototypeStdioServer::new_with_telemetry_and_experimental(
            Arc::new(allowlisted),
            db.clone(),
            Caller::local(),
            None,
            telemetry,
            experimental,
        )
        .await
        .unwrap();
        assert!(server
            .contracts
            .contains_key(&(SQL_WRITE_EXECUTOR.into(), SQL_WRITE_OPERATION.into())));
        let statement = format!("SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{target}'");
        let prepared = server
            .handle_message(executor_call_message(
                1,
                SQL_WRITE_EXECUTOR,
                json!({"operation":SQL_WRITE_OPERATION,"arguments":{"statement":statement,"reason":"Supersede-drift probe"}}),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        let successor = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000ab2","type":"Document","kind":"note","name":"Late successor"}),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO links(id,source_id,target_id,relationship) VALUES (?,?,?,'supersedes')",
        )
        .bind("supersede-drift")
        .bind(successor.as_str())
        .bind(target.as_str())
        .execute(db.write_pool())
        .await
        .unwrap();
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let executed = server
            .handle_message(executor_call_message(
                2,
                SQL_WRITE_EXECUTOR,
                execution_arguments_for(SQL_WRITE_OPERATION, &prepared),
            ))
            .await
            .unwrap();
        assert_eq!(
            executed["result"]["structuredContent"]["plan_error"]["code"],
            json!("plan_stale"),
            "{executed}"
        );
        assert!(
            executed["result"]["structuredContent"]["preview_current"].is_null(),
            "a stale plan must not confirm current: {executed}"
        );
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_after, events_before,
            "the stale execution dispatches nothing"
        );
    }

    /// The positive counterpart to the stale test: an execute-shaped call on a
    /// preview whose signed target has not drifted is a revalidate-only
    /// confirmation. It reports `preview_current`, claims no execution fence,
    /// dispatches nothing, and leaves the plan `Prepared` — on the first call
    /// and identically on a repeated call. Only once the target changes
    /// through an ordinary domain write does the same call go `plan_stale`.
    #[tokio::test]
    async fn sql_write_preview_execute_confirms_current_without_claim_or_dispatch() {
        use crate::mcp::{
            register_allowlisted_experimental_tools, ExperimentalExecutors,
            EXPERIMENTAL_SQL_WRITE_EXECUTOR,
        };

        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id":"ec00b000-0000-4000-8000-000000000ac1","type":"Document","kind":"note","name":"Confirm target"}),
        )
        .await
        .unwrap();
        let telemetry = ExecutorTelemetryContext::new(
            Arc::new(super::telemetry::TestTelemetrySink::default()),
            super::telemetry::DEFAULT_RETENTION_DAYS,
        )
        .unwrap();
        let experimental = ExperimentalExecutors::from_env_value(Some(
            EXPERIMENTAL_SQL_WRITE_EXECUTOR.to_string(),
        ))
        .unwrap();
        // Production registers the allowlisted source tool alongside the
        // ordinary surface; without it there is no contract and the
        // execute-shaped call cannot route.
        let mut allowlisted = ToolRegistry::new();
        register_builtin_tools(&mut allowlisted).unwrap();
        register_surface_tools(&mut allowlisted).unwrap();
        register_allowlisted_experimental_tools(&mut allowlisted, &experimental).unwrap();
        let server = ExecutorPrototypeStdioServer::new_with_telemetry_and_experimental(
            Arc::new(allowlisted),
            db.clone(),
            Caller::local(),
            None,
            telemetry,
            experimental,
        )
        .await
        .unwrap();
        assert!(server
            .contracts
            .contains_key(&(SQL_WRITE_EXECUTOR.into(), SQL_WRITE_OPERATION.into())));

        let name_before: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
            .bind(target.as_str())
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let events_before_prepare: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();

        let statement = format!(
            "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Renamed' AS value FROM records WHERE id = '{target}'"
        );
        let prepared = server
            .handle_message(executor_call_message(
                1,
                SQL_WRITE_EXECUTOR,
                json!({"operation":SQL_WRITE_OPERATION,"arguments":{"statement":statement,"reason":"Confirmation proof"}}),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        let signed = prepared["result"]["structuredContent"].clone();
        assert!(signed["plan_error"].is_null(), "{prepared}");
        let plan_id = signed["plan_id"].as_str().unwrap().to_string();
        let signed_target = signed["target"].clone();
        let signed_effect_summary = signed["effect_summary"].clone();
        let signed_effect = signed["effect"].clone();
        assert_eq!(signed["preparation_mutated"], false, "{prepared}");
        // Preserve the returned effect as a whole value; confirmation must
        // echo it without assuming an object shape at the protocol boundary.
        assert!(!signed_effect.is_null(), "{prepared}");
        let events_after_prepare: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_after_prepare, events_before_prepare,
            "signing a preview plan appends no domain event"
        );
        let name_after_prepare: String =
            sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
                .bind(target.as_str())
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(name_after_prepare, name_before);

        let execute = execution_arguments_for(SQL_WRITE_OPERATION, &prepared);
        let write_runtime = server
            .write_runtime
            .as_ref()
            .expect("the local executor server holds a write runtime");
        let stored_prepared = write_runtime
            .store
            .load(&plan_id, now_ms())
            .await
            .unwrap()
            .expect("preparation persists the signed preview plan");
        // The local store's Prepared constraint also requires attempt_id,
        // execution_owner and started_at_ms to be NULL. Operational plan and
        // telemetry bookkeeping is separate from the domain assertions above.
        assert!(matches!(stored_prepared.state, StoredState::Prepared));

        // The same execute-shaped arguments, twice: each call re-confirms
        // rather than replaying a claim or a committed result.
        for round in 0..2u64 {
            let confirmed = server
                .handle_message(executor_call_message(
                    10 + round,
                    SQL_WRITE_EXECUTOR,
                    execute.clone(),
                ))
                .await
                .unwrap();
            assert!(response_succeeded(&confirmed), "{confirmed}");
            let content = &confirmed["result"]["structuredContent"];
            assert!(content["plan_error"].is_null(), "{confirmed}");
            assert_eq!(content["plan_id"], plan_id, "{confirmed}");
            assert_eq!(content["preview_current"], json!(true), "{confirmed}");
            assert_eq!(content["committed"], json!(false), "{confirmed}");
            assert_eq!(content["preparation_mutated"], json!(false), "{confirmed}");
            assert_eq!(content["source_dispatch_count"], json!(0), "{confirmed}");
            assert_eq!(content["target"], signed_target, "{confirmed}");
            assert_eq!(
                content["effect_summary"], signed_effect_summary,
                "{confirmed}"
            );
            assert_eq!(content["effect"], signed_effect, "{confirmed}");
            let stored = write_runtime
                .store
                .load(&plan_id, now_ms())
                .await
                .unwrap()
                .expect("a confirmed preview plan stays persisted");
            assert!(
                matches!(stored.state, StoredState::Prepared),
                "confirmation round {round} must leave the plan Prepared, never Executing: {stored:?}"
            );
            assert_eq!(stored.payload, stored_prepared.payload);
            let events_after_confirmation: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
                    .fetch_one(db.write_pool())
                    .await
                    .unwrap();
            assert_eq!(
                events_after_confirmation, events_before_prepare,
                "confirmation round {round} appends no domain event"
            );
            let name_now: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
                .bind(target.as_str())
                .fetch_one(db.write_pool())
                .await
                .unwrap();
            assert_eq!(
                name_now, name_before,
                "confirmation round {round} must not mutate the target"
            );
        }

        // An ordinary domain write changes the signed target's state, so the
        // same execute-shaped call must now refuse as stale and dispatch
        // nothing.
        update_record(&db, &target, json!({"name":"Drifted after signing"}))
            .await
            .unwrap();
        let events_after_domain_edit: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert!(events_after_domain_edit > events_before_prepare);
        let stale = server
            .handle_message(executor_call_message(20, SQL_WRITE_EXECUTOR, execute))
            .await
            .unwrap();
        assert_eq!(
            stale["result"]["structuredContent"]["plan_error"]["code"],
            json!("plan_stale"),
            "{stale}"
        );
        assert!(
            stale["result"]["structuredContent"]["preview_current"].is_null(),
            "a stale plan must not confirm current: {stale}"
        );
        let events_after_stale: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            events_after_stale, events_after_domain_edit,
            "the stale execute dispatches no domain event"
        );
        let name_after_stale: String = sqlx::query_scalar("SELECT name FROM records WHERE id = ?")
            .bind(target.as_str())
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(name_after_stale, "Drifted after signing");
        let stored_stale = write_runtime
            .store
            .load(&plan_id, now_ms())
            .await
            .unwrap()
            .expect("a stale confirmation leaves the signed preview persisted");
        assert!(matches!(stored_stale.state, StoredState::Prepared));
        assert_eq!(stored_stale.payload, stored_prepared.payload);
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
        assert_eq!(classified.len(), 36);
        assert_eq!(
            classified
                .iter()
                .filter(|(executor, operation)| supports(executor, operation))
                .count(),
            34
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
            MEMBERSHIP_CREATE_GUEST_LINK_OPERATION,
            MEMBERSHIP_REVOKE_GUEST_LINK_OPERATION,
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
                .fetch_one(server.write_runtime.as_ref().unwrap().store.local_pool())
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
            .fetch_one(server.write_runtime.as_ref().unwrap().store.local_pool())
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
            .fetch_one(server.write_runtime.as_ref().unwrap().store.local_pool())
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
        server.write_runtime.as_mut().unwrap().dispatch_gate = Some(Arc::clone(&gate));
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
            .as_ref()
            .unwrap()
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
        server.write_runtime.as_mut().unwrap().dispatch_gate = Some(Arc::clone(&gate));
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
        revalidation_server
            .write_runtime
            .as_mut()
            .unwrap()
            .revalidation_gate = Some(Arc::clone(&revalidation_gate));
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
            .as_ref()
            .unwrap()
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
        server.write_runtime.as_mut().unwrap().dispatch_gate = Some(Arc::clone(&independent_gate));
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
            .as_ref()
            .unwrap()
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
        gated_server.write_runtime.as_mut().unwrap().dispatch_gate = Some(Arc::clone(&gate));
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
        server.write_runtime.as_mut().unwrap().dispatch_gate = Some(Arc::clone(&independent_gate));
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
        gated_server.write_runtime.as_mut().unwrap().dispatch_gate = Some(Arc::clone(&gate));
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
        server.write_runtime.as_mut().unwrap().dispatch_gate = Some(Arc::clone(&gate));
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
        first.write_runtime.as_mut().unwrap().dispatch_gate = Some(Arc::clone(&gate));
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
            .as_ref()
            .unwrap()
            .store
            .load(plan_id, now_ms())
            .await
            .unwrap()
            .unwrap();
        let mut plan: WritePlan = serde_json::from_value(stored.payload).unwrap();
        plan.server_version = "older-server".into();
        plan.integrity = server
            .write_runtime
            .as_ref()
            .unwrap()
            .store
            .seal(&plan.signing_key_id, &integrity_payload(&plan))
            .await
            .unwrap();
        server
            .write_runtime
            .as_ref()
            .unwrap()
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
        expiry_server.write_runtime = Some(WriteRuntime::with_ttl_ms(
            Arc::clone(&expiry_server.write_runtime.as_ref().unwrap().store),
            0,
        ));
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
        revalidation_server
            .write_runtime
            .as_mut()
            .unwrap()
            .revalidation_gate = Some(Arc::clone(&revalidation_gate));
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

    /// Record-selector aliases on the plan-backed writes (e674559): every
    /// spelling prepares the same canonical plan without mutating, while a
    /// conflicting selector rejects value-free before preparation runs.
    #[tokio::test]
    async fn record_selector_aliases_prepare_canonical_write_plans() {
        let db = create_database(":memory:").await.unwrap();
        let correction_target = create_record(
            &db,
            json!({
                "id":"ec00b000-0000-4000-8000-000000000031",
                "type":"Document",
                "kind":"note",
                "name":"Alias correction fixture",
            }),
        )
        .await
        .unwrap();
        let delete_target = create_record(
            &db,
            json!({
                "id":"ec00b000-0000-4000-8000-000000000032",
                "type":"Document",
                "kind":"note",
                "name":"Alias delete fixture",
            }),
        )
        .await
        .unwrap();
        let registry = registry();
        let server = ExecutorPrototypeStdioServer::new(registry, db.clone(), Caller::local(), None)
            .await
            .unwrap();

        // Each alias prepares the same plan as the canonical spelling: same
        // target, no mutation, and the stored plan carries only the canonical
        // selector field.
        for (executor, operation, canonical, target, companions) in [
            (
                RECORDS_WRITE_EXECUTOR,
                CORRECT_RECORD_TYPE_OPERATION,
                "record_id",
                correction_target.as_str(),
                json!({"target_type":"Resolution","target_kind":"decision"}),
            ),
            (
                RECORDS_DELETE_EXECUTOR,
                DELETE_RECORD_OPERATION,
                "id",
                delete_target.as_str(),
                json!({}),
            ),
        ] {
            let expected_target = if operation == CORRECT_RECORD_TYPE_OPERATION {
                format!("Alias correction fixture ({target})")
            } else {
                format!("Alias delete fixture ({target})")
            };
            for (field, reference) in [
                ("id", target.to_string()),
                ("record_id", target.to_string()),
                ("ids", target.to_string()),
            ] {
                let mut arguments = companions.clone();
                arguments["reason"] = json!("Prepare through a selector alias");
                if field == "ids" {
                    arguments[field] = json!([reference]);
                } else {
                    arguments[field] = json!(reference);
                }
                let prepared = server
                    .handle_message(executor_call_message(
                        500,
                        executor,
                        json!({"operation":operation,"arguments":arguments}),
                    ))
                    .await
                    .unwrap();
                assert!(
                    response_succeeded(&prepared),
                    "{executor}.{operation}.{field}: {prepared}"
                );
                let structured = &prepared["result"]["structuredContent"];
                assert_eq!(structured["preparation_mutated"], false);
                assert_eq!(structured["target"], expected_target);
                let plan_id = structured["plan_id"].as_str().unwrap();
                let stored = server
                    .write_runtime
                    .as_ref()
                    .unwrap()
                    .store
                    .load(plan_id, now_ms())
                    .await
                    .unwrap()
                    .unwrap();
                let plan: WritePlan = serde_json::from_value(stored.payload).unwrap();
                assert_eq!(plan.operation_arguments[canonical], json!(target));
                for alias in ["id", "record_id", "ids"] {
                    if alias != canonical {
                        assert!(
                            plan.operation_arguments.get(alias).is_none(),
                            "{executor}.{operation}.{field}: {plan:?}"
                        );
                    }
                }
            }
        }
        // Nothing above mutated: the correction target keeps its type and the
        // delete target is still live.
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT type FROM records WHERE id=?")
                .bind(&correction_target)
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            "Document"
        );
        assert_eq!(
            type_correction_event_count(&db, &correction_target).await,
            0
        );
        let deleted_at: Option<String> =
            sqlx::query_scalar("SELECT deleted_at FROM records WHERE id=?")
                .bind(&delete_target)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert!(deleted_at.is_none());

        // A conflicting selector rejects before preparation with the
        // value-free shape diagnostic and stores no plan.
        for (executor, operation, target) in [
            (
                RECORDS_WRITE_EXECUTOR,
                CORRECT_RECORD_TYPE_OPERATION,
                correction_target.as_str(),
            ),
            (
                RECORDS_DELETE_EXECUTOR,
                DELETE_RECORD_OPERATION,
                delete_target.as_str(),
            ),
        ] {
            let rejected = server
                .handle_message(executor_call_message(
                    501,
                    executor,
                    json!({
                        "operation":operation,
                        "arguments":{
                            "id":target,
                            "record_id":target,
                            "target_type":"Resolution",
                            "target_kind":"decision",
                            "reason":"Conflicting selectors must reject"
                        }
                    }),
                ))
                .await
                .unwrap();
            assert!(!response_succeeded(&rejected), "{rejected}");
            let serialized = serde_json::to_string(&rejected).unwrap();
            assert!(serialized.contains("exactly one selector"), "{serialized}");
            assert!(
                !serialized.contains(target),
                "the rejection must not reflect the selector value: {serialized}"
            );
        }
        assert_eq!(
            type_correction_event_count(&db, &correction_target).await,
            0
        );
    }

    const STANDBY_RECORD_ID: &str = "ec00b000-0000-4000-8000-000000000031";
    const STANDBY_RUN_KEY: &str = "scout-chair-a748b2";

    fn standby_registry() -> Arc<ToolRegistry> {
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        registry.set_standby_read_only(true);
        Arc::new(registry)
    }

    fn directory_entry_names(path: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    async fn standby_server_with_record() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        crate::Db,
        ExecutorPrototypeStdioServer,
    ) {
        standby_server_with_registry(standby_registry()).await
    }

    async fn standby_server_with_registry(
        registry: Arc<ToolRegistry>,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        crate::Db,
        ExecutorPrototypeStdioServer,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("standby.db");
        let url = path.to_str().unwrap().to_string();
        let source = create_database(&url).await.unwrap();
        let created = create_record(
            &source,
            json!({"id": STANDBY_RECORD_ID, "type": "Document", "kind": "note", "name": "Standby fixture"}),
        )
        .await
        .unwrap();
        assert_eq!(created, STANDBY_RECORD_ID);
        crate::db::checkpoint_and_close_hosted_adoption_database(source)
            .await
            .unwrap();
        let db = crate::db::open_existing_database_standby_read_only(&url)
            .await
            .unwrap();
        assert_eq!(db.open_mode(), crate::db::DatabaseOpenMode::StandbyReadOnly);
        let server = ExecutorPrototypeStdioServer::new_standby_read_only(
            registry,
            EngineHandle::Sqlite(db.clone()),
            Caller::local(),
        )
        .await
        .unwrap();
        (directory, path, db, server)
    }

    #[tokio::test]
    async fn standby_constructor_rejects_writable_registry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("standby.db");
        let url = path.to_str().unwrap();
        let source = create_database(url).await.unwrap();
        crate::db::checkpoint_and_close_hosted_adoption_database(source)
            .await
            .unwrap();
        let db = crate::db::open_existing_database_standby_read_only(url)
            .await
            .unwrap();
        let error = match ExecutorPrototypeStdioServer::new_standby_read_only(
            registry(),
            EngineHandle::Sqlite(db),
            Caller::local(),
        )
        .await
        {
            Ok(_) => panic!("standby constructor admitted a writable registry"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("standby read-only registry"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn standby_constructor_rejects_physically_writable_engine() {
        // :memory: is never a standby open.
        let memory = create_database(":memory:").await.unwrap();
        let error = match ExecutorPrototypeStdioServer::new_standby_read_only(
            standby_registry(),
            EngineHandle::Sqlite(memory),
            Caller::local(),
        )
        .await
        {
            Ok(_) => panic!("standby constructor admitted a writable :memory: engine"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("physically read-only standby engine"),
            "{error}"
        );
        // A file-backed database that was never checkpointed into an
        // immutable standby open is rejected before any catalogue, runtime,
        // or sidecar construction.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("writable.db");
        let writable = create_database(path.to_str().unwrap()).await.unwrap();
        let error = match ExecutorPrototypeStdioServer::new_standby_read_only(
            standby_registry(),
            EngineHandle::Sqlite(writable),
            Caller::local(),
        )
        .await
        {
            Ok(_) => panic!("standby constructor admitted a writable file engine"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("physically read-only standby engine"),
            "{error}"
        );
        assert!(
            !path
                .with_file_name("writable.db.write-plans.sqlite3")
                .exists(),
            "rejected construction must not create a plan sidecar"
        );
    }

    #[tokio::test]
    async fn standby_server_holds_no_write_state() {
        let (_directory, path, _db, server) = standby_server_with_record().await;
        assert!(server.write_runtime.is_none());
        assert!(server.telemetry.is_none());
        assert!(server.trace.file.is_none());
        assert!(
            !path
                .with_file_name("standby.db.write-plans.sqlite3")
                .exists(),
            "standby construction must not create a plan sidecar"
        );
    }

    #[tokio::test]
    async fn standby_discovery_advertises_only_admitted_reads() {
        let (_directory, _path, _db, server) = standby_server_with_record().await;
        let listed = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list",
                "params": {}
            }))
            .await
            .unwrap();
        let tools = listed["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .collect();
        assert!(names.contains(&"bootstrap"), "{names:?}");
        assert!(names.contains(&"describe_operation"), "{names:?}");
        assert_eq!(
            listed["result"]["_meta"]["nativeExecutor"]["surface"],
            json!("standby-read-only")
        );
        // Catalogue honesty: dispatch refuses every mutation and every
        // plan-backed operation before plan access, so discovery must not
        // advertise any of them as callable reads.
        for (executor, operations) in &server.operations_by_executor {
            assert!(!operations.is_empty(), "{executor}");
            for operation in operations {
                let contract = server
                    .contracts
                    .get(&(executor.clone(), operation.clone()))
                    .unwrap_or_else(|| {
                        panic!("advertised {executor}.{operation} lacks a contract")
                    });
                assert_eq!(
                    contract.access,
                    OperationAccess::Read,
                    "{executor}.{operation}"
                );
                assert!(
                    !requires_plan(executor, operation),
                    "advertised {executor}.{operation} requires a plan yet standby dispatch refuses plan-backed calls"
                );
            }
        }
        let advertised = server
            .operations_by_executor
            .get(EXECUTOR)
            .cloned()
            .unwrap_or_default();
        assert!(
            !advertised.contains(&OPERATION.to_string()),
            "plan-backed {EXECUTOR}.{OPERATION} must not be advertised"
        );
        assert!(
            !server
                .operations_by_executor
                .contains_key(WORKSPACE_EXECUTOR),
            "hosted workspace reads must not leak without hosted authority"
        );
    }

    #[tokio::test]
    async fn standby_bootstrap_reports_truthful_surface_in_both_eras() {
        let (_directory, _path, _db, server) = standby_server_with_record().await;
        let legacy = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "bootstrap", "arguments": {}}
            }))
            .await
            .unwrap();
        assert!(response_succeeded(&legacy), "{legacy}");
        assert_eq!(
            legacy["result"]["_meta"]["nativeExecutor"]["surface"],
            json!("standby-read-only")
        );
        assert_eq!(
            legacy["result"]["_meta"]["nativeExecutor"]["manifestSha256"],
            json!(server.manifest_digest)
        );
        let modern = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "bootstrap",
                    "arguments": {"format": "json"},
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": protocol::PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"}
                    }
                }
            }))
            .await
            .unwrap();
        assert!(response_succeeded(&modern), "{modern}");
        assert_eq!(
            modern["result"]["structuredContent"]["tool_exposure"]["scope"],
            json!("standby-read-only")
        );
        assert_eq!(
            modern["result"]["structuredContent"]["tool_exposure"]["advertised_count"],
            json!(server.descriptors.len())
        );
        assert_eq!(
            modern["result"]["_meta"]["nativeExecutor"]["surface"],
            json!("standby-read-only")
        );
    }

    fn standby_status_provider_fixture(
    ) -> (tempfile::TempDir, crate::standby::StandbyStatusProvider) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("provider");
        std::fs::create_dir_all(&root).unwrap();
        let origin = "ndb_00000000000000000000000000000000";
        let config = crate::standby::StandbyRuntimeConfig::from_json(
            json!({
                "replica_root": root.to_str().unwrap(),
                "hosted_route_database_id": "standby-fixture-route",
                "origin_database_id": origin,
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
        let store = crate::standby::GenerationStore::open(
            root.join("store"),
            "standby-fixture-route",
            Some(origin.to_string()),
        )
        .unwrap();
        let provider = crate::standby::StandbyStatusProvider::for_status_only_reason(
            config,
            store,
            None,
            crate::standby::StandbyStatusOnly {
                reason: "fixture-no-candidate".into(),
                candidate_count: 0,
                unusable_candidate_count: 0,
            },
            false,
            false,
        );
        (directory, provider)
    }

    #[tokio::test]
    async fn standby_bootstrap_preserves_provider_runtime_status() {
        let (_provider_dir, provider) = standby_status_provider_fixture();
        let mut inner = ToolRegistry::new();
        register_builtin_tools(&mut inner).unwrap();
        register_surface_tools(&mut inner).unwrap();
        inner.set_standby_status_provider(provider);
        let (_directory, _path, _db, server) = standby_server_with_registry(Arc::new(inner)).await;
        // Modern JSON keeps the authentic provider-generated runtime block.
        let modern = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "bootstrap",
                    "arguments": {"format": "json"},
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": protocol::PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"}
                    }
                }
            }))
            .await
            .unwrap();
        assert!(response_succeeded(&modern), "{modern}");
        let runtime = &modern["result"]["structuredContent"]["tool_exposure"]["runtime"];
        assert_eq!(runtime["read_only"], json!(true));
        assert_eq!(runtime["writes_supported"], json!(false));
        // The status-only provider reports its own authentic mutation
        // error, not the generic standby one: assert what it generates.
        assert_eq!(runtime["mutation_error"], json!("STANDBY_STATUS_ONLY"));
        assert_eq!(
            runtime["status_only"]["reason"],
            json!("fixture-no-candidate")
        );
        // Legacy text renders the same authentic status block.
        let legacy = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "bootstrap", "arguments": {}}
            }))
            .await
            .unwrap();
        assert!(response_succeeded(&legacy), "{legacy}");
        // Legacy text renders the same authentic status block through
        // `/tool_exposure/runtime`: the renderer prints mode and serving
        // state, not the status-only reason string.
        let text = legacy["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("# Local standby status"), "{text}");
        assert!(text.contains("Serving generation: none"), "{text}");
    }

    #[tokio::test]
    async fn standby_read_contract_matches_authoritative_schema() {
        let (_directory, _path, _db, server) = standby_server_with_record().await;
        let memory = create_database(":memory:").await.unwrap();
        let writable = ExecutorPrototypeStdioServer::new(registry(), memory, Caller::local(), None)
            .await
            .unwrap();
        // Sampled reads only: full-descriptor equality is not claimed. The
        // hosted/ordinary source flag must not disturb the cached read contract.
        for (executor, operation) in [
            ("records_read", "get_record"),
            ("records_read", "query_record"),
        ] {
            assert!(
                server
                    .contracts
                    .contains_key(&(executor.to_string(), operation.to_string())),
                "{executor}.{operation}"
            );
            let arguments = json!({"executor": executor, "operation": operation});
            let standby_described = server
                .handle_message(executor_call_message(
                    1,
                    "describe_operation",
                    arguments.clone(),
                ))
                .await
                .unwrap();
            let writable_described = writable
                .handle_message(executor_call_message(1, "describe_operation", arguments))
                .await
                .unwrap();
            assert!(
                response_succeeded(&standby_described),
                "{standby_described}"
            );
            assert_eq!(
                standby_described["result"]["structuredContent"],
                writable_described["result"]["structuredContent"]
            );
        }
    }

    #[tokio::test]
    async fn standby_describe_withholds_unavailable_contracts_but_dispatch_refuses() {
        let (_directory, _path, _db, server) = standby_server_with_record().await;
        // describe follows the advertised index: the retained plan-backed
        // mutation contract is withheld, with no plan_required writable
        // guidance leaked for the unavailable operation.
        let withheld = server
            .handle_message(executor_call_message(
                1,
                "describe_operation",
                json!({"executor": EXECUTOR, "operation": OPERATION}),
            ))
            .await
            .unwrap();
        assert!(!response_succeeded(&withheld), "{withheld}");
        let serialized = serde_json::to_string(&withheld).unwrap();
        assert!(
            serialized.contains("unknown (executor, operation)"),
            "{serialized}"
        );
        assert!(!serialized.contains("plan_required"), "{serialized}");
        // Dispatch of the same retained pair still refuses with the stable
        // read-only error rather than a selection error.
        let refused = server
            .handle_message(executor_call_message(
                2,
                EXECUTOR,
                json!({"operation": OPERATION, "arguments": {}}),
            ))
            .await
            .unwrap();
        assert!(!response_succeeded(&refused), "{refused}");
        assert_eq!(
            refused["result"]["structuredContent"]["error_code"],
            crate::mcp::registry::STANDBY_READ_ONLY_ERROR
        );
        // The advertised bootstrap self-description still resolves.
        let bootstrap_described = server
            .handle_message(executor_call_message(
                3,
                "describe_operation",
                json!({"executor": "bootstrap", "operation": "bootstrap"}),
            ))
            .await
            .unwrap();
        assert!(
            response_succeeded(&bootstrap_described),
            "{bootstrap_described}"
        );
    }

    #[tokio::test]
    async fn standby_refuses_mutations_with_stable_error_and_echoes_run_key() {
        let (_directory, _path, _db, server) = standby_server_with_record().await;
        // One directly-dispatched mutation from the retained full contract
        // map: lookup succeeds, then dispatch refuses before plan access.
        let (direct_executor, direct_operation) = server
            .contracts
            .iter()
            .find(|((executor, operation), contract)| {
                contract.access == OperationAccess::Mutation && !requires_plan(executor, operation)
            })
            .map(|((executor, operation), _)| (executor.clone(), operation.clone()))
            .expect("catalogue must retain a direct mutation for refusal");
        let keyed = |arguments: Value| {
            let mut envelope = arguments.as_object().cloned().unwrap();
            envelope.insert("run_key".into(), json!(STANDBY_RUN_KEY));
            Value::Object(envelope)
        };
        let envelopes = [
            // Cached prepare envelope for the plan-backed fixture.
            executor_call_message(
                1,
                EXECUTOR,
                keyed(
                    json!({"operation": OPERATION, "arguments": {"record_id": "probe", "reason": "standby refusal probe"}}),
                ),
            ),
            // Forged execute envelope: refused before any plan load.
            executor_call_message(
                2,
                EXECUTOR,
                keyed(
                    json!({"operation": OPERATION, "plan_id": "forged", "target": "probe", "effect_summary": "probe"}),
                ),
            ),
            // Direct mutation from the retained contract map.
            executor_call_message(
                3,
                &direct_executor,
                keyed(json!({"operation": direct_operation, "arguments": {}})),
            ),
        ];
        for envelope in envelopes {
            let refused = server.handle_message(envelope).await.unwrap();
            assert!(!response_succeeded(&refused), "{refused}");
            let structured = &refused["result"]["structuredContent"];
            assert_eq!(
                structured["error_code"],
                crate::mcp::registry::STANDBY_READ_ONLY_ERROR
            );
            assert_eq!(structured["run_context"]["run_key"], json!(STANDBY_RUN_KEY));
            let serialized = serde_json::to_string(&refused).unwrap();
            assert!(!serialized.contains("selection_error"), "{serialized}");
            assert!(!serialized.contains("unknown executor"), "{serialized}");
        }
        // Same closed refusal in the modern era.
        let modern = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": EXECUTOR,
                    "arguments": {"operation": OPERATION, "arguments": {}, "run_key": STANDBY_RUN_KEY},
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": protocol::PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"}
                    }
                }
            }))
            .await
            .unwrap();
        assert!(!response_succeeded(&modern), "{modern}");
        assert_eq!(
            modern["result"]["structuredContent"]["error_code"],
            crate::mcp::registry::STANDBY_READ_ONLY_ERROR
        );
        // The closed refusal echoes the supplied key in the modern era too.
        assert_eq!(
            modern["result"]["structuredContent"]["run_context"]["run_key"],
            json!(STANDBY_RUN_KEY)
        );
    }

    #[tokio::test]
    async fn standby_calls_leave_database_and_directory_unchanged() {
        let (directory, path, db, server) = standby_server_with_record().await;
        db.drain_captures().await;
        let runs_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_runs")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let read_log_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let interactions_before: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM provenance_interaction_receipts")
                .fetch_one(db.pool())
                .await
                .unwrap();
        let bytes_before = std::fs::read(&path).unwrap();
        let entries_before = directory_entry_names(directory.path());
        // A real delegated read, bootstrap, describe, and a keyed refusal.
        let read = server
            .handle_message(executor_call_message(
                1,
                "records_read",
                json!({"operation": "get_record", "arguments": {"ids": [STANDBY_RECORD_ID]}, "run_key": STANDBY_RUN_KEY, "format": "json"}),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&read), "{read}");
        // The envelope `run_key` is hoisted and forwarded into the source-tool
        // arguments by `translate_arguments`; the registry validates it,
        // attaches `run_context`, and `attach_run_context` lands the echo in
        // `structuredContent.run_context`. The record body proves real
        // delegation over the immutable open.
        assert_eq!(
            read["result"]["structuredContent"]["run_context"]["run_key"],
            json!(STANDBY_RUN_KEY),
            "{read}"
        );
        let serialized_read = serde_json::to_string(&read).unwrap();
        assert!(
            serialized_read.contains(STANDBY_RECORD_ID),
            "{serialized_read}"
        );
        // The same read twice: a cached read contract is unaffected by source flags.
        let reread = server
            .handle_message(executor_call_message(
                2,
                "records_read",
                json!({"operation": "get_record", "arguments": {"ids": [STANDBY_RECORD_ID]}}),
            ))
            .await
            .unwrap();
        assert!(response_succeeded(&reread), "{reread}");
        // The same read in the modern era: success, engine data, and the
        // standby surface marker, still with no persistent writes below.
        let modern_read = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "records_read",
                    "arguments": {"operation": "get_record", "arguments": {"ids": [STANDBY_RECORD_ID]}, "run_key": STANDBY_RUN_KEY, "format": "json"},
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": protocol::PROTOCOL_VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                        "io.modelcontextprotocol/clientInfo": {"name": "test", "version": "1"}
                    }
                }
            }))
            .await
            .unwrap();
        assert!(response_succeeded(&modern_read), "{modern_read}");
        assert_eq!(
            modern_read["result"]["structuredContent"]["run_context"]["run_key"],
            json!(STANDBY_RUN_KEY)
        );
        let serialized_modern = serde_json::to_string(&modern_read).unwrap();
        assert!(
            serialized_modern.contains(STANDBY_RECORD_ID),
            "{serialized_modern}"
        );
        assert_eq!(
            modern_read["result"]["_meta"]["nativeExecutor"]["surface"],
            json!("standby-read-only")
        );
        let refused = server
            .handle_message(executor_call_message(
                3,
                EXECUTOR,
                json!({"operation": OPERATION, "arguments": {}, "run_key": STANDBY_RUN_KEY}),
            ))
            .await
            .unwrap();
        assert!(!response_succeeded(&refused), "{refused}");
        db.drain_captures().await;
        let runs_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_runs")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let read_log_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let interactions_after: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM provenance_interaction_receipts")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(runs_after, runs_before);
        assert_eq!(read_log_after, read_log_before);
        assert_eq!(interactions_after, interactions_before);
        assert_eq!(std::fs::read(&path).unwrap(), bytes_before);
        assert_eq!(directory_entry_names(directory.path()), entries_before);
    }

    #[tokio::test]
    async fn writable_prepare_execute_lifecycle_still_binds_some_runtime() {
        let db = create_database(":memory:").await.unwrap();
        let target = create_record(
            &db,
            json!({"id": PLAN_ONCE_ID, "type": "Document", "kind": "note", "name": "Once"}),
        )
        .await
        .unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        assert!(server.write_runtime.is_some());
        let revision = policy_revision(&server.registry, &db, Caller::local(), &target).await;
        let prepared = server
            .handle_message(call_message(1, preparation_arguments(&target, &revision)))
            .await
            .unwrap();
        assert!(response_succeeded(&prepared), "{prepared}");
        let executed = server
            .handle_message(call_message(2, execution_arguments(&prepared)))
            .await
            .unwrap();
        assert!(response_succeeded(&executed), "{executed}");
    }
}

#[cfg(test)]
#[path = "sql_selected_write/qualification.rs"]
mod selected_qualification;
