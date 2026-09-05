//! Permission-shaped executor facade.
//!
//! This module advertises the audited executor descriptors, but delegates an
//! enabled operation to the original [`ToolRegistry`] exact-name call. The
//! production registration, handler, validation, authorization, request
//! lifecycle, provenance, and interaction extraction paths are therefore not
//! replaced by synthetic aliases.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use futures::future::BoxFuture;
use futures::TryStreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::DeploymentReadOnlyOperation;

use super::evidence::ToolResult;
use super::lens_dispatch::LensDispatch;
use super::lens_surface::lens_descriptor_projection_for_policy;
use super::protocol::{self, RpcOutcome};
use super::registry::{
    attach_run_context, run_context_for_engine, Caller, EngineHandle, ToolRegistry,
};
use super::render;
use super::{
    DeploymentAdmission, DeploymentMutationBarrier, DeploymentPersistenceLease, OperationAccess,
};

#[path = "executor_prototype/plan_store.rs"]
mod plan_store;
pub use plan_store::{DeploymentPlanKeyring, HostedPlanCatalogue, HostedPlanKeyProvider};
#[path = "executor_prototype/hosted_runtime.rs"]
mod hosted_runtime;
#[path = "executor_prototype/telemetry.rs"]
mod telemetry;
#[doc(hidden)]
pub use hosted_runtime::HostedExecutorRuntime;
pub use telemetry::{
    ExecutorTelemetryContext, ExecutorTelemetryHealth, ExecutorTelemetrySink,
    StructuredLogTelemetrySink, DEFAULT_RETENTION_DAYS,
};

/// Source-owned result of a non-mutating hosted membership preparation.
///
/// This executor-owned transfer type keeps the executor independent of the
/// concrete hosting package while retaining every value bound into plan
/// signing and exact pre-execution revalidation.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq)]
pub struct HostedMembershipPreparation {
    pub canonical_source_arguments: Value,
    pub target_id: String,
    pub target: String,
    pub state_revision: String,
    pub target_state_digest: String,
    pub effect_summary: String,
    pub effect: Value,
    pub operation_evidence: Value,
    pub catalogue_snapshot: Value,
}

/// One authoritative hosted executor composition.
///
/// The same implementation supplies the plan catalogue and membership
/// preparation reads so callers cannot accidentally compose lifecycle rows
/// from one hosted authority with membership snapshots from another. The
/// registered membership source handler must be built from this same
/// authority: role and removal execution atomically couple its source fence
/// to the plan claim.
#[doc(hidden)]
pub trait HostedExecutorAuthority: HostedPlanCatalogue + Send + Sync {
    fn validate_membership_write(&self, arguments: Value) -> Result<()>;

    fn prepare_membership_write<'a>(
        &'a self,
        db: &'a crate::db::Db,
        caller: &'a Caller,
        arguments: Value,
    ) -> BoxFuture<'a, Result<HostedMembershipPreparation>>;
}

/// Avoid relying on trait-object upcasting when the plan store needs the
/// catalogue portion of the composite hosted authority.
#[derive(Clone)]
struct HostedAuthorityCatalogue(Arc<dyn HostedExecutorAuthority>);

impl HostedPlanCatalogue for HostedAuthorityCatalogue {
    fn executor_plan_pool(&self) -> &sqlx::SqlitePool {
        self.0.executor_plan_pool()
    }
}

pub(super) async fn validate_hosted_plan_key_provider(
    keys: &Arc<dyn HostedPlanKeyProvider>,
) -> Result<()> {
    plan_store::validate_hosted_key_provider(keys).await
}

pub(super) async fn validate_hosted_plan_keys_for_catalogue(
    keys: &Arc<dyn HostedPlanKeyProvider>,
    catalog: &dyn HostedPlanCatalogue,
) -> Result<()> {
    validate_hosted_plan_key_provider(keys).await?;
    let retained_key_ids: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT key_id FROM executor_write_plans ORDER BY key_id")
            .fetch_all(catalog.executor_plan_pool())
            .await?;
    if retained_key_ids.len() > plan_store::HOSTED_MAX_RETAINED_KEYS {
        return Err(Error::engine(
            "hosted write plan catalogue references more retained keys than the bounded deployment keyring supports",
        ));
    }
    for key_id in retained_key_ids {
        let mut candidates = sqlx::query_as::<_, (String, String)>(
            "SELECT payload, payload_sha256 FROM executor_write_plans
             WHERE key_id = ? ORDER BY plan_id LIMIT 1024",
        )
        .bind(&key_id)
        .fetch(catalog.executor_plan_pool());
        let mut verified = false;
        while let Some((payload, payload_sha256)) = candidates.try_next().await? {
            if plan_store::verify_hosted_retained_key(keys, &key_id, &payload, &payload_sha256)
                .await
                .is_ok()
            {
                verified = true;
                break;
            }
        }
        if !verified {
            return Err(Error::engine(
                "retained hosted write plan verification key is unavailable or incorrect",
            ));
        }
    }
    Ok(())
}
#[path = "executor_prototype/read_operations.rs"]
mod read_operations;
#[path = "executor_prototype/write_operations.rs"]
mod write_operations;

const CONTRACT_VERSION: &str = "native.operation-contract.v1";
const TRACE_SCHEMA: &str = "native.mcp-executor-fixture-event.v1";
/// Committed public projection of the held candidate audit, restricted to the
/// fields the structs below deserialize. Regenerate with
/// `node scripts/mcp-executor-audit-projection.mjs`; a held CI lane asserts it
/// has not drifted from `docs/evals/mcp-executors/candidate-audit.generated.json`.
const AUDIT: &str = include_str!("executor_prototype/candidate-audit.public.generated.json");

#[derive(Deserialize)]
struct Audit {
    candidate_surfaces: CandidateSurfaces,
    audit_rows: Vec<AuditRow>,
}

#[derive(Deserialize)]
struct CandidateSurfaces {
    stable: StableSurfaces,
}

#[derive(Deserialize)]
struct StableSurfaces {
    ordinary: CandidateSurface,
    lens: CandidateSurface,
}

#[derive(Deserialize)]
struct CandidateSurface {
    descriptor_bytes: usize,
    descriptors: Vec<Value>,
}

#[derive(Deserialize)]
struct AuditRow {
    legacy_tool: String,
    legacy_action: String,
    stability: String,
    availability: Vec<String>,
    candidate_executor: String,
    candidate_operation: String,
    candidate_plan_policy: String,
}

#[derive(Clone, Debug)]
struct Selector {
    field: String,
    value: String,
}

#[derive(Clone, Debug)]
struct OperationContract {
    surface: ExecutorSurface,
    executor: String,
    operation: String,
    source_tool: String,
    /// The registered ToolSpec description, verbatim. It covers the whole
    /// source tool; `selector` records which action of it this operation is.
    /// Emitted as `source.tool_description` rather than a bare `description`
    /// so a caller is not misled into reading whole-tool prose as
    /// action-specific.
    tool_description: String,
    selector: Option<Selector>,
    input_schema: Value,
    selector_specific_schema: bool,
    /// Server-derived access classification for deployment persistence
    /// admission. Missing/custom source kinds and ambiguous selectors remain
    /// mutations until a registered exhaustive classification proves read.
    access: OperationAccess,
    digest: String,
    bytes: usize,
}

type OperationContracts = BTreeMap<(String, String), OperationContract>;
type OperationsByExecutor = BTreeMap<String, Vec<String>>;

struct BuiltContracts {
    contracts: OperationContracts,
    operations_by_executor: OperationsByExecutor,
}

/// Principal-neutral ordinary executor catalogue fixed at process startup.
pub(crate) struct PinnedExecutorCatalogue {
    descriptors: Vec<Value>,
    descriptor_bytes: usize,
    manifest_digest: String,
    contracts: OperationContracts,
    operations_by_executor: OperationsByExecutor,
}

impl PinnedExecutorCatalogue {
    pub(crate) fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub(crate) fn descriptor_bytes(&self) -> usize {
        self.descriptor_bytes
    }
}

/// Principal-neutral lens executor catalogue fixed on first authoritative
/// resolution of one lens revision.
pub(crate) struct PinnedLensExecutorCatalogue {
    descriptors: Vec<Value>,
    descriptor_bytes: usize,
    manifest_digest: String,
    contracts: OperationContracts,
    operations_by_executor: OperationsByExecutor,
}

impl PinnedLensExecutorCatalogue {
    pub(crate) fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub(crate) fn descriptor_bytes(&self) -> usize {
        self.descriptor_bytes
    }
}

fn build_ordinary_catalogue(
    registry: &ToolRegistry,
    engine_kind: super::registry::EngineKind,
    hosted: bool,
) -> Result<PinnedExecutorCatalogue> {
    let audit: Audit = serde_json::from_str(AUDIT)?;
    let BuiltContracts {
        contracts,
        operations_by_executor,
    } = build_contracts_for_hosting(
        registry,
        engine_kind,
        &audit.audit_rows,
        ExecutorSurface::Ordinary,
        hosted,
    )?;
    let source_surface = audit.candidate_surfaces.stable.ordinary;
    if serde_json::to_vec(&source_surface.descriptors)?.len() != source_surface.descriptor_bytes {
        return Err(Error::engine(
            "audited ordinary executor descriptor byte count drifted",
        ));
    }
    let mut descriptors =
        executable_descriptors(source_surface.descriptors, &operations_by_executor)?;
    add_ordinary_executor_format_contracts(&mut descriptors, &contracts)?;
    let descriptor_bytes = serde_json::to_vec(&descriptors)?.len();
    let manifest_digest = jcs_sha256(&Value::Array(descriptors.clone()))?;
    Ok(PinnedExecutorCatalogue {
        descriptors,
        descriptor_bytes,
        manifest_digest,
        contracts,
        operations_by_executor,
    })
}

impl OperationContract {
    fn with_registered_access(mut self, registry: &ToolRegistry) -> Self {
        if self.source_tool == "materialize_record" {
            // Federation materialization is a synthetic lens source rather
            // than a registered ToolKind and must stay fail-closed.
            self.access = OperationAccess::Mutation;
            return self;
        }
        let mut source_arguments = serde_json::Map::new();
        if let Some(selector) = &self.selector {
            source_arguments.insert(
                selector.field.clone(),
                Value::String(selector.value.clone()),
            );
        }
        self.access = registry
            .registered_operation_access(&self.source_tool, &Value::Object(source_arguments))
            .unwrap_or(OperationAccess::Mutation);
        self
    }

    fn payload(&self) -> Value {
        let plan_required = write_operations::requires_plan(&self.executor, &self.operation);
        let direct_execution_enabled = !plan_required;
        let schema_authority = if self.selector_specific_schema {
            "the registered selector-specific operation schema and exact-name production runtime handler"
        } else {
            "the registered production ToolSpec schema and exact-name runtime handler"
        };
        json!({
            "contract_version": CONTRACT_VERSION,
            "contract_digest": self.digest,
            "executor": self.executor,
            "operation": self.operation,
            "surface": self.surface.as_str(),
            "input_schema": self.input_schema,
            "source": {
                "tool": self.source_tool,
                "tool_description": self.tool_description,
                "selector": self.selector.as_ref().map(|selector| json!({
                    "field": selector.field,
                    "value": selector.value,
                })),
                "authority": schema_authority,
            },
            "prototype": {
                "direct_execution_enabled": direct_execution_enabled,
                "fast_path": direct_execution_enabled,
                "plan_required": plan_required,
                "guided_path": true,
                "repair_path": true,
            },
        })
    }
}

#[derive(Clone, Debug)]
struct CallContext {
    request_id: String,
    executor: String,
    operation: String,
    contract: OperationContract,
    request_bytes: usize,
    schema_valid: bool,
    started: Instant,
    repair_of: Option<String>,
    described_before: bool,
}

struct TraceSink {
    next_id: AtomicU64,
    file: Option<Mutex<File>>,
    events: Mutex<Vec<Value>>,
    pending_repairs: Mutex<HashMap<String, String>>,
    pending_descriptions: Mutex<HashSet<String>>,
}

impl TraceSink {
    fn new(path: Option<&Path>) -> Result<Self> {
        let file = path
            .map(|path| OpenOptions::new().create(true).append(true).open(path))
            .transpose()?;
        Ok(Self {
            next_id: AtomicU64::new(1),
            file: file.map(Mutex::new),
            events: Mutex::new(Vec::new()),
            pending_repairs: Mutex::new(HashMap::new()),
            pending_descriptions: Mutex::new(HashSet::new()),
        })
    }

    fn next_request_id(&self) -> String {
        format!(
            "fixture-{:08}",
            self.next_id.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn repair_key(run_key: Option<&str>, executor: &str, operation: &str) -> String {
        format!("{}\u{1f}{executor}\u{1f}{operation}", run_key.unwrap_or(""))
    }

    fn take_repair(
        &self,
        run_key: Option<&str>,
        executor: &str,
        operation: &str,
    ) -> Option<String> {
        self.pending_repairs
            .lock()
            .expect("prototype repair lock")
            .remove(&Self::repair_key(run_key, executor, operation))
    }

    fn remember_failure(
        &self,
        run_key: Option<&str>,
        executor: &str,
        operation: &str,
        request_id: &str,
    ) {
        self.pending_repairs
            .lock()
            .expect("prototype repair lock")
            .insert(
                Self::repair_key(run_key, executor, operation),
                request_id.to_string(),
            );
    }

    fn remember_description(&self, run_key: Option<&str>, executor: &str, operation: &str) {
        self.pending_descriptions
            .lock()
            .expect("prototype description lock")
            .insert(Self::repair_key(run_key, executor, operation));
    }

    fn take_description(&self, run_key: Option<&str>, executor: &str, operation: &str) -> bool {
        self.pending_descriptions
            .lock()
            .expect("prototype description lock")
            .remove(&Self::repair_key(run_key, executor, operation))
    }

    fn record(&self, event: Value) {
        self.events
            .lock()
            .expect("prototype event lock")
            .push(event.clone());
        if let Some(file) = &self.file {
            let mut file = file.lock().expect("prototype trace file lock");
            // A trace sink is evidence-only. Failure to append must not change
            // the operation result; the event remains inspectable in memory.
            if let Ok(mut bytes) = serde_json::to_vec(&event) {
                bytes.push(b'\n');
                let _ = file.write_all(&bytes);
                let _ = file.flush();
            }
        }
    }
}

/// The production executor transport over one normal registry.
pub struct ExecutorPrototypeStdioServer {
    registry: Arc<ToolRegistry>,
    engine: EngineHandle,
    caller: Caller,
    descriptors: Vec<Value>,
    descriptor_bytes: usize,
    manifest_digest: String,
    contracts: OperationContracts,
    operations_by_executor: OperationsByExecutor,
    trace: Arc<TraceSink>,
    telemetry: Option<telemetry::BoundExecutorTelemetry>,
    write_runtime: write_operations::WriteRuntime,
    hosted_authority: Option<Arc<dyn HostedExecutorAuthority>>,
    hosted_membership_plans: bool,
    deployment_mutation_barrier: Option<DeploymentMutationBarrier>,
}

pub(super) struct HostedExecutorConstruction {
    pub(super) authority: Arc<dyn HostedExecutorAuthority>,
    pub(super) database_id: String,
    pub(super) keys: Arc<dyn HostedPlanKeyProvider>,
    pub(super) catalogue: Arc<PinnedExecutorCatalogue>,
    pub(super) telemetry: Option<telemetry::BoundExecutorTelemetry>,
}

enum TelemetryConstruction {
    Disabled,
    Local(Arc<ExecutorTelemetryContext>),
    Hosted(telemetry::BoundExecutorTelemetry),
}

struct ExecutorConstruction {
    plan_store: plan_store::PlanStore,
    hosted_authority: Option<Arc<dyn HostedExecutorAuthority>>,
    pinned_catalogue: Option<Arc<PinnedExecutorCatalogue>>,
    telemetry: TelemetryConstruction,
    transport: telemetry::TelemetryTransport,
    deployment_mutation_barrier: Option<DeploymentMutationBarrier>,
}

impl ExecutorPrototypeStdioServer {
    pub(crate) fn pin_hosted_catalogue(
        registry: &ToolRegistry,
    ) -> Result<Arc<PinnedExecutorCatalogue>> {
        Ok(Arc::new(build_ordinary_catalogue(
            registry,
            super::registry::EngineKind::Sqlite,
            true,
        )?))
    }

    pub async fn new(
        registry: Arc<ToolRegistry>,
        engine: impl Into<EngineHandle>,
        caller: Caller,
        trace_path: Option<&Path>,
    ) -> Result<Self> {
        let engine = engine.into();
        let plan_store = match &engine {
            EngineHandle::Sqlite(db) => plan_store::PlanStore::open_for_database(db.path()).await?,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(Error::engine(
                    "executor write plans require a qualified shared durable store; this backend is disabled",
                ))
            }
        };
        let deployment_mutation_barrier = registry.deployment_mutation_barrier().cloned();
        Self::new_with_plan_store(
            registry,
            engine,
            caller,
            trace_path,
            ExecutorConstruction {
                plan_store,
                hosted_authority: None,
                pinned_catalogue: None,
                telemetry: TelemetryConstruction::Disabled,
                transport: telemetry::TelemetryTransport::Stdio,
                deployment_mutation_barrier,
            },
        )
        .await
    }

    /// Build the local executor with the privacy-safe dogfood sink enabled.
    pub async fn new_with_telemetry(
        registry: Arc<ToolRegistry>,
        engine: impl Into<EngineHandle>,
        caller: Caller,
        trace_path: Option<&Path>,
        telemetry: Arc<ExecutorTelemetryContext>,
    ) -> Result<Self> {
        let engine = engine.into();
        let plan_store = match &engine {
            EngineHandle::Sqlite(db) => plan_store::PlanStore::open_for_database(db.path()).await?,
            #[allow(unreachable_patterns)]
            _ => {
                return Err(Error::engine(
                    "executor write plans require a qualified shared durable store; this backend is disabled",
                ))
            }
        };
        let deployment_mutation_barrier = registry.deployment_mutation_barrier().cloned();
        Self::new_with_plan_store(
            registry,
            engine,
            caller,
            trace_path,
            ExecutorConstruction {
                plan_store,
                hosted_authority: None,
                pinned_catalogue: None,
                telemetry: TelemetryConstruction::Local(telemetry),
                transport: telemetry::TelemetryTransport::Stdio,
                deployment_mutation_barrier,
            },
        )
        .await
    }

    /// Build the executor over the authenticated hosted route and the shared
    /// catalogue lifecycle store. Callers cannot request this mode through MCP
    /// arguments; the hosting ingress supplies the authoritative catalogue,
    /// database id, and shared signing provider.
    pub async fn new_hosted(
        registry: Arc<ToolRegistry>,
        engine: impl Into<EngineHandle>,
        caller: Caller,
        authority: Arc<dyn HostedExecutorAuthority>,
        database_id: impl Into<String>,
        keys: Arc<dyn HostedPlanKeyProvider>,
    ) -> Result<Self> {
        let database_id = database_id.into();
        if caller.hosting_database() != Some(database_id.as_str()) {
            return Err(Error::engine(
                "hosted executor database does not match authenticated route",
            ));
        }
        let catalogue = HostedAuthorityCatalogue(Arc::clone(&authority));
        validate_hosted_plan_keys_for_catalogue(&keys, &catalogue).await?;
        Self::new_hosted_with_ready_keys(
            registry,
            engine,
            caller,
            authority,
            database_id,
            keys,
            None,
        )
        .await
    }

    /// Per-request constructor for an HTTP router that validated its shared
    /// key provider before it began serving. Direct callers use `new_hosted`,
    /// which owns that readiness probe itself.
    pub(super) async fn new_hosted_with_ready_keys(
        registry: Arc<ToolRegistry>,
        engine: impl Into<EngineHandle>,
        caller: Caller,
        authority: Arc<dyn HostedExecutorAuthority>,
        database_id: impl Into<String>,
        keys: Arc<dyn HostedPlanKeyProvider>,
        telemetry: Option<Arc<ExecutorTelemetryContext>>,
    ) -> Result<Self> {
        let catalogue = Self::pin_hosted_catalogue(&registry)?;
        let telemetry = telemetry.map(|context| {
            context.bind_hosted_manifest(&catalogue.manifest_digest, catalogue.descriptor_bytes)
        });
        Self::new_hosted_with_pinned_catalogue(
            registry,
            engine,
            caller,
            HostedExecutorConstruction {
                authority,
                database_id: database_id.into(),
                keys,
                catalogue,
                telemetry,
            },
        )
        .await
    }

    pub(super) async fn new_hosted_with_pinned_catalogue(
        registry: Arc<ToolRegistry>,
        engine: impl Into<EngineHandle>,
        caller: Caller,
        construction: HostedExecutorConstruction,
    ) -> Result<Self> {
        let engine = engine.into();
        let HostedExecutorConstruction {
            authority,
            database_id,
            keys,
            catalogue,
            telemetry,
        } = construction;
        if caller.hosting_database() != Some(database_id.as_str()) {
            return Err(Error::engine(
                "hosted executor database does not match authenticated route",
            ));
        }
        let plan_store = plan_store::PlanStore::open_for_catalogue_with_ready_keys(
            HostedAuthorityCatalogue(Arc::clone(&authority)),
            database_id,
            keys,
        )
        .await?;
        let deployment_mutation_barrier = registry.deployment_mutation_barrier().cloned();
        Self::new_with_plan_store(
            registry,
            engine,
            caller,
            None,
            ExecutorConstruction {
                plan_store,
                hosted_authority: Some(authority),
                pinned_catalogue: Some(catalogue),
                telemetry: telemetry
                    .map(TelemetryConstruction::Hosted)
                    .unwrap_or(TelemetryConstruction::Disabled),
                transport: telemetry::TelemetryTransport::Http,
                deployment_mutation_barrier,
            },
        )
        .await
    }

    async fn new_with_plan_store(
        registry: Arc<ToolRegistry>,
        engine: EngineHandle,
        caller: Caller,
        trace_path: Option<&Path>,
        construction: ExecutorConstruction,
    ) -> Result<Self> {
        let ExecutorConstruction {
            plan_store,
            hosted_authority,
            pinned_catalogue,
            telemetry: telemetry_construction,
            transport,
            deployment_mutation_barrier,
        } = construction;
        let started = Instant::now();
        let catalogue = match pinned_catalogue {
            Some(catalogue) => catalogue,
            None => Arc::new(build_ordinary_catalogue(
                &registry,
                engine.kind(),
                hosted_authority.is_some(),
            )?),
        };
        // Local stdio construction is a process-start boundary. Hosted
        // construction is per request and must remain observational; hosted
        // catalogue maintenance is performed once by HostedExecutorRuntime.
        if hosted_authority.is_none() {
            plan_store
                .expire_all(chrono::Utc::now().timestamp_millis())
                .await?;
            plan_store
                .cleanup_expired(
                    chrono::Utc::now().timestamp_millis(),
                    plan_store::EXPIRED_PLAN_RETENTION_MS,
                )
                .await?;
        }
        let telemetry = match telemetry_construction {
            TelemetryConstruction::Disabled => None,
            TelemetryConstruction::Hosted(telemetry) => Some(telemetry),
            TelemetryConstruction::Local(context) => {
                let raw_session_binding = Zeroizing::new(format!(
                    "{}\u{1f}{}\u{1f}{}",
                    caller.actor(),
                    caller.hosting_principal().unwrap_or(caller.credential()),
                    caller.hosting_database().unwrap_or("")
                ));
                let engine = if hosted_authority.is_some() {
                    telemetry::TelemetryEngine::Hosted
                } else {
                    match engine.kind() {
                        super::registry::EngineKind::Sqlite => telemetry::TelemetryEngine::Sqlite,
                        #[cfg(feature = "postgres")]
                        super::registry::EngineKind::Postgres => {
                            telemetry::TelemetryEngine::Postgres
                        }
                        #[cfg(feature = "turso-local")]
                        super::registry::EngineKind::TursoLocal => {
                            telemetry::TelemetryEngine::TursoLocal
                        }
                    }
                };
                Some(context.bind(
                    &raw_session_binding,
                    &catalogue.manifest_digest,
                    crate::FULL_GIT_SHA,
                    engine,
                    transport,
                ))
            }
        };
        if let Some(telemetry) = &telemetry {
            if transport == telemetry::TelemetryTransport::Stdio {
                telemetry.session_started();
                telemetry.manifest_loaded(catalogue.descriptor_bytes, elapsed_ms(started));
            }
        }
        Ok(Self {
            registry,
            engine,
            caller,
            descriptors: catalogue.descriptors.clone(),
            descriptor_bytes: catalogue.descriptor_bytes,
            manifest_digest: catalogue.manifest_digest.clone(),
            contracts: catalogue.contracts.clone(),
            operations_by_executor: catalogue.operations_by_executor.clone(),
            trace: Arc::new(TraceSink::new(trace_path)?),
            telemetry,
            write_runtime: write_operations::WriteRuntime::new(plan_store),
            hosted_membership_plans: hosted_authority.is_some(),
            hosted_authority,
            deployment_mutation_barrier,
        })
    }

    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    pub fn descriptor_bytes(&self) -> usize {
        self.descriptor_bytes
    }

    fn admit_deployment_operation(
        &self,
        contract: &OperationContract,
    ) -> Result<Option<DeploymentAdmission>> {
        let Some(barrier) = &self.deployment_mutation_barrier else {
            return Ok(None);
        };
        let operation = DeploymentReadOnlyOperation::registered(format!(
            "{}.{}",
            contract.executor, contract.operation
        ));
        barrier.admit(&operation, contract.access).map(Some)
    }

    fn deployment_read_only_response(&self, id: Value, modern: bool, error: Error) -> Value {
        let mut result = protocol::call_error_content(&error, Value::Null, None);
        if modern {
            protocol::add_modern_result_fields(&mut result);
        }
        result["_meta"]["nativeExecutor"] = self.executor_meta();
        json!({"jsonrpc":"2.0","id":id,"result":result})
    }

    #[cfg(test)]
    fn trace_events(&self) -> Vec<Value> {
        self.trace
            .events
            .lock()
            .expect("prototype event lock")
            .clone()
    }

    pub async fn serve_stdio(&self) -> Result<()> {
        self.serve(BufReader::new(tokio::io::stdin()), tokio::io::stdout())
            .await
    }

    pub async fn serve<R, W>(&self, mut reader: R, mut writer: W) -> Result<()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await? == 0 {
                return Ok(());
            }
            if line.trim().is_empty() {
                continue;
            }
            let response = match serde_json::from_str::<Value>(&line) {
                Ok(message) => self.handle_message(message).await,
                Err(error) => Some(protocol::error_response(
                    Value::Null,
                    protocol::PARSE_ERROR,
                    &format!("parse error: {error}"),
                )),
            };
            if let Some(response) = response {
                let mut bytes = serde_json::to_vec(&response)?;
                bytes.push(b'\n');
                writer.write_all(&bytes).await?;
                writer.flush().await?;
            }
        }
    }

    pub async fn handle_message(&self, mut message: Value) -> Option<Value> {
        let modern = protocol::is_modern_request(&message);
        let (method, name) = protocol::method_and_name(&message);
        if method == Some("initialize") {
            if let Some(telemetry) = &self.telemetry {
                telemetry.authenticated_initialize();
            }
            return outcome_body(self.delegate(message).await);
        }
        if method == Some("tools/list") {
            let outcome = self.delegate(message).await;
            return outcome_body(outcome).map(|mut body| {
                if body.get("result").is_some() {
                    body["result"]["tools"] = Value::Array(self.descriptors.clone());
                    body["result"]["_meta"]["nativeExecutor"] = self.executor_meta();
                }
                body
            });
        }
        if method != Some("tools/call") {
            return outcome_body(self.delegate(message).await);
        }
        let id = protocol::request_id(&message);
        if id.is_null() {
            return None;
        }
        let params = match message.get("params").and_then(Value::as_object) {
            Some(params) => params,
            None => {
                return Some(protocol::error_response(
                    id,
                    protocol::INVALID_PARAMS,
                    "invalid params: tools/call params must be an object",
                ))
            }
        };
        let Some(executor) = name.map(String::from) else {
            return Some(protocol::error_response(
                id,
                protocol::INVALID_PARAMS,
                "invalid params: missing tool name",
            ));
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if executor == "describe_operation" {
            return Some(self.describe_response(id, arguments, modern).await);
        }
        if executor == "bootstrap" {
            if let Err(error) =
                validate_envelope_fields(&arguments, &["run_key", "parent_key", "format"])
            {
                return Some(
                    self.fixture_error_response(
                        id,
                        modern,
                        "bootstrap",
                        "bootstrap",
                        &error.to_string(),
                        None,
                        &arguments,
                        "validation_failure",
                        Some(false),
                        true,
                    )
                    .await,
                );
            }
            let requested_format = match force_json_bootstrap_format(&mut message) {
                Ok(format) => format,
                Err(error) => {
                    return Some(
                        self.fixture_error_response(
                            id,
                            modern,
                            "bootstrap",
                            "bootstrap",
                            &error,
                            None,
                            &arguments,
                            "validation_failure",
                            Some(false),
                            true,
                        )
                        .await,
                    )
                }
            };
            let request_id = self.trace.next_request_id();
            let started = Instant::now();
            let outcome = self.delegate(message).await;
            let mut body = outcome_body(outcome)?;
            rewrite_executor_bootstrap(
                &mut body,
                requested_format,
                "ordinary",
                self.descriptors.len(),
                self.descriptor_bytes,
            );
            let success = response_succeeded(&body);
            add_executor_meta(&mut body, self.executor_meta());
            self.trace.record(json!({
                "schema": TRACE_SCHEMA,
                "request_id": request_id,
                "kind": "operation_selection",
                "mode": "direct",
                "executor": "bootstrap",
                "operation": "bootstrap",
                "manifest_sha256": self.manifest_digest,
                "request_bytes": serde_json::to_vec(&arguments).map(|bytes| bytes.len()).unwrap_or(0),
                "response_bytes": serde_json::to_vec(&body).map(|bytes| bytes.len()).unwrap_or(0),
                "completed": success,
                "elapsed_ms": elapsed_ms(started),
            }));
            return Some(body);
        }
        let Some(operation) = arguments.get("operation").and_then(Value::as_str) else {
            return Some(
                self.fixture_error_response(
                    id,
                    modern,
                    &executor,
                    "",
                    "missing required string field 'operation'",
                    None,
                    &arguments,
                    "selection_error",
                    None,
                    true,
                )
                .await,
            );
        };
        let operation = operation.to_string();
        let Some(contract) = self
            .contracts
            .get(&(executor.clone(), operation.clone()))
            .cloned()
        else {
            let expected = self
                .operations_by_executor
                .get(&executor)
                .cloned()
                .unwrap_or_default();
            let diagnostic = if expected.is_empty() {
                format!("unknown executor '{executor}'")
            } else {
                format!(
                    "unknown operation '{operation}' for {executor}; select one of: {}. Keep operation as routing metadata and nest operation-specific fields under arguments",
                    expected.join(", "),
                )
            };
            return Some(
                self.fixture_error_response(
                    id,
                    modern,
                    &executor,
                    &operation,
                    &diagnostic,
                    None,
                    &arguments,
                    "selection_error",
                    None,
                    true,
                )
                .await,
            );
        };
        let _deployment_admission = match self.admit_deployment_operation(&contract) {
            Ok(admission) => admission,
            Err(error) => {
                return Some(self.deployment_read_only_response(id, modern, error));
            }
        };
        let deployment_persistence_lease = match &_deployment_admission {
            Some(DeploymentAdmission::Writable(lease)) => Some(lease.clone()),
            Some(DeploymentAdmission::FrozenRead) | None => None,
        };
        if write_operations::requires_plan(&executor, &operation) {
            return Some(
                Box::pin(self.handle_plan_backed_write(
                    id,
                    modern,
                    message,
                    contract,
                    arguments,
                    deployment_persistence_lease,
                ))
                .await,
            );
        }
        if let Err(error) = validate_envelope_fields(
            &arguments,
            &["operation", "arguments", "run_key", "parent_key", "format"],
        ) {
            return Some(
                self.fixture_error_response(
                    id,
                    modern,
                    &executor,
                    &operation,
                    &error.to_string(),
                    Some(&contract),
                    &arguments,
                    "validation_failure",
                    Some(false),
                    true,
                )
                .await,
            );
        }
        let operation_arguments = arguments
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let schema_errors = match jsonschema::validator_for(&contract.input_schema) {
            Ok(validator) => validator
                .iter_errors(&operation_arguments)
                .map(|error| error.to_string())
                .collect::<Vec<_>>(),
            Err(error) => vec![format!("invalid authoritative contract: {error}")],
        };
        let schema_valid = schema_errors.is_empty();
        if !schema_valid {
            return Some(
                self.fixture_error_response(
                    id,
                    modern,
                    &executor,
                    &operation,
                    &format!(
                        "arguments do not match the authoritative operation contract: {}",
                        schema_errors.join("; ")
                    ),
                    Some(&contract),
                    &arguments,
                    "validation_failure",
                    Some(false),
                    true,
                )
                .await,
            );
        }
        let runtime_validation = validate_enabled_operation(
            &contract,
            operation_arguments.clone(),
            self.hosted_authority.as_deref(),
        );
        if let Err(error) = runtime_validation {
            return Some(
                self.fixture_error_response(
                    id,
                    modern,
                    &executor,
                    &operation,
                    &error.to_string(),
                    Some(&contract),
                    &arguments,
                    "validation_failure",
                    Some(true),
                    true,
                )
                .await,
            );
        }
        let run_key = arguments.get("run_key").and_then(Value::as_str);
        let request_id = self.trace.next_request_id();
        let repair_of = self.trace.take_repair(run_key, &executor, &operation);
        let described_before = self.trace.take_description(run_key, &executor, &operation);
        let call_context = CallContext {
            request_id,
            executor: executor.clone(),
            operation: operation.clone(),
            contract: contract.clone(),
            request_bytes: serde_json::to_vec(&arguments)
                .map(|bytes| bytes.len())
                .unwrap_or(0),
            schema_valid,
            started: Instant::now(),
            repair_of,
            described_before,
        };
        let mut legacy_arguments = match translate_arguments(&contract, &arguments) {
            Ok(arguments) => arguments,
            Err(error) => {
                return Some(
                    self.fixture_error_response(
                        id,
                        modern,
                        &executor,
                        &operation,
                        &error.to_string(),
                        Some(&contract),
                        &arguments,
                        "validation_failure",
                        Some(true),
                        true,
                    )
                    .await,
                )
            }
        };
        // Empty-query guidance is attached to the authoritative structured
        // result below. Always obtain that result from the delegated source,
        // then restore the representation the executor caller selected after
        // the guidance mutation. This also keeps default Text calls working
        // when the shared protocol no longer duplicates structuredContent.
        let query_record_format = force_json_query_record_format(&contract, &mut legacy_arguments);
        let telemetry_request = self
            .telemetry
            .as_ref()
            .map(|telemetry| telemetry.request(Some(&executor), Some(&operation), None));
        if let (Some(telemetry), Some(request)) = (&self.telemetry, &telemetry_request) {
            let sizes = telemetry::TelemetrySizes {
                request_bytes: telemetry::size_bucket(call_context.request_bytes),
                contract_bytes: telemetry::size_bucket(call_context.contract.bytes),
                ..telemetry::TelemetrySizes::default()
            };
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::OperationSelected,
                outcome: telemetry::TelemetryOutcome::Succeeded,
                sizes,
                ..telemetry::EventSpec::default()
            });
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::ContractLoaded,
                outcome: telemetry::TelemetryOutcome::Succeeded,
                flags: telemetry::TelemetryFlags {
                    described_before: call_context.described_before,
                    ..telemetry::TelemetryFlags::default()
                },
                sizes,
                ..telemetry::EventSpec::default()
            });
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::ValidationCompleted,
                outcome: telemetry::TelemetryOutcome::Succeeded,
                flags: telemetry::TelemetryFlags {
                    repair_retry: call_context.repair_of.is_some(),
                    described_before: call_context.described_before,
                    ..telemetry::TelemetryFlags::default()
                },
                counts: telemetry::TelemetryCounts {
                    attempt_bucket: telemetry::attempt_bucket(
                        1 + u64::from(call_context.repair_of.is_some()),
                    ),
                    repair_count_bucket: telemetry::repair_bucket(u64::from(
                        call_context.repair_of.is_some(),
                    )),
                    ..telemetry::TelemetryCounts::default()
                },
                sizes,
                ..telemetry::EventSpec::default()
            });
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::DispatchBegun,
                outcome: telemetry::TelemetryOutcome::Started,
                counts: telemetry::TelemetryCounts {
                    dispatch_count_bucket: telemetry::dispatch_bucket(1),
                    ..telemetry::TelemetryCounts::default()
                },
                sizes,
                ..telemetry::EventSpec::default()
            });
        }
        if let Some(params) = message.get_mut("params").and_then(Value::as_object_mut) {
            params.insert("name".into(), Value::String(contract.source_tool.clone()));
            params.insert("arguments".into(), legacy_arguments);
        }
        let outcome = self
            .delegate_with_caller_and_persistence(
                message,
                self.caller.clone(),
                deployment_persistence_lease,
            )
            .await;
        let mut body = outcome_body(outcome)?;
        let success = response_succeeded(&body);
        let error_class = if success {
            Value::Null
        } else {
            json!("execution_error")
        };
        if !success {
            attach_repair(
                &mut body,
                &contract,
                "execution_error",
                None,
                &arguments,
                self.hosted_authority.as_deref(),
            );
            self.trace.remember_failure(
                run_key,
                &call_context.executor,
                &call_context.operation,
                &call_context.request_id,
            );
        } else {
            attach_empty_query_guidance(&mut body, &contract, &operation_arguments, &arguments);
            if let Some(format) = query_record_format {
                rewrite_executor_query_record(&mut body, format, &contract.source_tool);
            }
        }
        add_executor_meta(&mut body, self.executor_meta());
        let mode = if call_context.repair_of.is_some() {
            "repair_retry"
        } else if call_context.described_before {
            "guided"
        } else {
            "direct"
        };
        let response_bytes = serde_json::to_vec(&body)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        let latency_ms = elapsed_ms(call_context.started);
        if let (Some(telemetry), Some(request)) = (&self.telemetry, telemetry_request) {
            let flags = telemetry::TelemetryFlags {
                repair_returned: !success,
                repair_retry: call_context.repair_of.is_some(),
                described_before: call_context.described_before,
                ..telemetry::TelemetryFlags::default()
            };
            let counts = telemetry::TelemetryCounts {
                attempt_bucket: telemetry::attempt_bucket(
                    1 + u64::from(call_context.repair_of.is_some()),
                ),
                dispatch_count_bucket: telemetry::dispatch_bucket(1),
                repair_count_bucket: telemetry::repair_bucket(
                    u64::from(call_context.repair_of.is_some()) + u64::from(!success),
                ),
                ..telemetry::TelemetryCounts::default()
            };
            let sizes = telemetry::TelemetrySizes {
                request_bytes: telemetry::size_bucket(call_context.request_bytes),
                result_bytes: telemetry::size_bucket(response_bytes),
                contract_bytes: telemetry::size_bucket(call_context.contract.bytes),
            };
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::DispatchCompleted,
                outcome: if success {
                    telemetry::TelemetryOutcome::Succeeded
                } else {
                    telemetry::TelemetryOutcome::Rejected
                },
                error_class: (!success).then_some(telemetry::TelemetryErrorClass::ExecutionError),
                flags,
                counts,
                latency_bucket: telemetry::latency_bucket(latency_ms),
                sizes,
            });
            if !success {
                telemetry.emit(telemetry::EventSpec {
                    request: Some(request),
                    phase: telemetry::TelemetryPhase::RepairReturned,
                    outcome: telemetry::TelemetryOutcome::Repaired,
                    error_class: Some(telemetry::TelemetryErrorClass::ExecutionError),
                    flags,
                    counts,
                    latency_bucket: telemetry::latency_bucket(latency_ms),
                    sizes,
                });
            }
        }
        self.trace.record(json!({
            "schema": TRACE_SCHEMA,
            "request_id": call_context.request_id,
            "kind": "operation_selection",
            "mode": mode,
            "executor": call_context.executor,
            "operation": call_context.operation,
            "source_tool": call_context.contract.source_tool,
            "contract_digest": call_context.contract.digest,
            "contract_bytes": call_context.contract.bytes,
            "manifest_sha256": self.manifest_digest,
            "schema_valid": call_context.schema_valid,
            "runtime_valid": true,
            "completed": success,
            "error_class": error_class,
            "repair_of": call_context.repair_of,
            "run_key": run_key,
            "request_bytes": call_context.request_bytes,
            "response_bytes": response_bytes,
            "elapsed_ms": latency_ms,
            "selection": {
                "executor": call_context.executor,
                "operation": call_context.operation,
                "source_tool": call_context.contract.source_tool,
            },
            "validation": {
                "schema_valid": call_context.schema_valid,
                "runtime_valid": true,
            },
            "repair": {
                "returned": false,
                "repair_of": call_context.repair_of,
            },
            "counts": {"tool_calls": 1, "turns": Value::Null},
            "latency_ms": latency_ms,
            "sizes": {
                "request_bytes": call_context.request_bytes,
                "result_bytes": response_bytes,
                "contract_bytes": call_context.contract.bytes,
                "manifest_bytes": self.descriptor_bytes,
            },
        }));
        Some(body)
    }

    async fn delegate(&self, message: Value) -> RpcOutcome {
        self.delegate_with_caller(message, self.caller.clone())
            .await
    }

    async fn delegate_with_caller(&self, message: Value, caller: Caller) -> RpcOutcome {
        self.delegate_with_caller_and_persistence(message, caller, None)
            .await
    }

    async fn delegate_with_caller_and_persistence(
        &self,
        message: Value,
        caller: Caller,
        persistence_lease: Option<DeploymentPersistenceLease>,
    ) -> RpcOutcome {
        if protocol::is_modern_request(&message) {
            Box::pin(protocol::handle_modern_engine_message_with_persistence(
                self.registry.clone(),
                self.engine.clone(),
                caller,
                message,
                persistence_lease,
            ))
            .await
        } else {
            Box::pin(protocol::handle_legacy_engine_message_with_persistence(
                self.registry.clone(),
                self.engine.clone(),
                caller,
                message,
                persistence_lease,
            ))
            .await
        }
    }

    async fn describe_response(&self, id: Value, arguments: Value, modern: bool) -> Value {
        let started = Instant::now();
        let request_id = self.trace.next_request_id();
        let run_context = self
            .registry
            .run_context_for_engine(&self.engine, self.caller.clone(), &arguments)
            .await;
        if let Err(error) = validate_envelope_fields(
            &arguments,
            &["executor", "operation", "run_key", "parent_key", "format"],
        ) {
            return self
                .fixture_error_response(
                    id,
                    modern,
                    "describe_operation",
                    "describe_operation",
                    &error.to_string(),
                    None,
                    &arguments,
                    "validation_failure",
                    Some(false),
                    true,
                )
                .await;
        }
        let mut format_arguments = arguments.clone();
        if let Err(error) = render::take_format("describe_operation", &mut format_arguments) {
            return self
                .fixture_error_response(
                    id,
                    modern,
                    "describe_operation",
                    "describe_operation",
                    &error,
                    None,
                    &arguments,
                    "validation_failure",
                    Some(false),
                    true,
                )
                .await;
        }
        let executor = arguments
            .get("executor")
            .and_then(Value::as_str)
            .unwrap_or("");
        let operation = arguments
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("");
        let Some(contract) = self
            .contracts
            .get(&(executor.to_string(), operation.to_string()))
        else {
            let expected = self
                .operations_by_executor
                .get(executor)
                .cloned()
                .unwrap_or_default();
            return self
                .fixture_error_response(
                    id,
                    modern,
                    executor,
                    operation,
                    &format!(
                        "unknown (executor, operation). Select one operation for this executor: {}. To load its contract call describe_operation with {{executor, operation}}; to execute it keep operation as routing metadata and nest operation-specific fields under arguments",
                        expected.join(", ")
                    ),
                    None,
                    &arguments,
                    "selection_error",
                    None,
                    true,
                )
                .await;
        };
        let structured = attach_run_context(contract.payload(), run_context);
        let run_key = arguments.get("run_key").and_then(Value::as_str);
        self.trace
            .remember_description(run_key, executor, operation);
        let mut result = protocol::call_result_content(
            "describe_operation",
            render::Format::Json,
            ToolResult::from(structured),
            None,
        );
        if modern {
            protocol::add_modern_result_fields(&mut result);
        }
        result["_meta"]["nativeExecutor"] = self.executor_meta();
        let body = json!({"jsonrpc":"2.0","id":id,"result":result});
        let response_bytes = serde_json::to_vec(&body)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        let latency_ms = elapsed_ms(started);
        if let Some(telemetry) = &self.telemetry {
            let request = telemetry.request(Some(executor), Some(operation), None);
            let sizes = telemetry::TelemetrySizes {
                request_bytes: telemetry::size_bucket(
                    serde_json::to_vec(&arguments)
                        .map(|bytes| bytes.len())
                        .unwrap_or(0),
                ),
                result_bytes: telemetry::size_bucket(response_bytes),
                contract_bytes: telemetry::size_bucket(contract.bytes),
            };
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::OperationSelected,
                outcome: telemetry::TelemetryOutcome::Succeeded,
                sizes,
                ..telemetry::EventSpec::default()
            });
            telemetry.emit(telemetry::EventSpec {
                request: Some(request),
                phase: telemetry::TelemetryPhase::ContractLoaded,
                outcome: telemetry::TelemetryOutcome::Succeeded,
                flags: telemetry::TelemetryFlags {
                    described_before: true,
                    ..telemetry::TelemetryFlags::default()
                },
                latency_bucket: telemetry::latency_bucket(latency_ms),
                sizes,
                ..telemetry::EventSpec::default()
            });
        }
        self.trace.record(json!({
            "schema": TRACE_SCHEMA,
            "request_id": request_id,
            "kind": "contract_load",
            "mode": "describe",
            "executor": executor,
            "operation": operation,
            "contract_digest": contract.digest,
            "contract_bytes": contract.bytes,
            "manifest_sha256": self.manifest_digest,
            "run_key": run_key,
            "request_bytes": serde_json::to_vec(&arguments).map(|bytes| bytes.len()).unwrap_or(0),
            "response_bytes": response_bytes,
            "completed": true,
            "elapsed_ms": latency_ms,
            "selection": {"executor": executor, "operation": operation},
            "validation": {"schema_valid": Value::Null, "runtime_valid": Value::Null},
            "repair": {"returned": false, "repair_of": Value::Null},
            "counts": {"tool_calls": 1, "turns": Value::Null},
            "latency_ms": latency_ms,
            "sizes": {
                "request_bytes": serde_json::to_vec(&arguments).map(|bytes| bytes.len()).unwrap_or(0),
                "result_bytes": response_bytes,
                "contract_bytes": contract.bytes,
                "manifest_bytes": self.descriptor_bytes,
            },
        }));
        body
    }

    #[allow(clippy::too_many_arguments)]
    async fn fixture_error_response(
        &self,
        id: Value,
        modern: bool,
        executor: &str,
        operation: &str,
        diagnostic: &str,
        contract: Option<&OperationContract>,
        arguments: &Value,
        error_class: &str,
        schema_valid: Option<bool>,
        emit_telemetry: bool,
    ) -> Value {
        let started = Instant::now();
        let request_id = self.trace.next_request_id();
        let run_key = arguments.get("run_key").and_then(Value::as_str);
        let run_context = self
            .registry
            .run_context_for_engine(&self.engine, self.caller.clone(), arguments)
            .await;
        let error = Error::engine(format!("executor prototype {error_class}: {diagnostic}"));
        let mut result = protocol::call_error_content(&error, run_context, None);
        if let Some(contract) = contract {
            attach_repair_result(
                &mut result,
                contract,
                error_class,
                Some(diagnostic),
                arguments,
                self.hosted_authority.as_deref(),
            );
        }
        if modern {
            protocol::add_modern_result_fields(&mut result);
        }
        result["_meta"]["nativeExecutor"] = self.executor_meta();
        let body = json!({"jsonrpc":"2.0","id":id,"result":result});
        if !executor.is_empty() && !operation.is_empty() {
            self.trace
                .remember_failure(run_key, executor, operation, &request_id);
        }
        let response_bytes = serde_json::to_vec(&body)
            .map(|bytes| bytes.len())
            .unwrap_or(0);
        let latency_ms = elapsed_ms(started);
        if emit_telemetry {
            if let Some(telemetry) = &self.telemetry {
                let resolved = contract.is_some();
                let request = telemetry.request(
                    resolved.then_some(executor),
                    resolved.then_some(operation),
                    arguments.get("plan_id").and_then(Value::as_str),
                );
                let sizes = telemetry::TelemetrySizes {
                    request_bytes: telemetry::size_bucket(
                        serde_json::to_vec(arguments)
                            .map(|bytes| bytes.len())
                            .unwrap_or(0),
                    ),
                    result_bytes: telemetry::size_bucket(response_bytes),
                    contract_bytes: contract
                        .map(|contract| telemetry::size_bucket(contract.bytes))
                        .unwrap_or("not_measured"),
                };
                telemetry.emit(telemetry::EventSpec {
                    request: Some(request.clone()),
                    phase: telemetry::TelemetryPhase::OperationSelected,
                    outcome: if resolved {
                        telemetry::TelemetryOutcome::Succeeded
                    } else {
                        telemetry::TelemetryOutcome::Rejected
                    },
                    error_class: (!resolved)
                        .then_some(telemetry::TelemetryErrorClass::SelectionError),
                    sizes,
                    ..telemetry::EventSpec::default()
                });
                if resolved {
                    telemetry.emit(telemetry::EventSpec {
                        request: Some(request.clone()),
                        phase: telemetry::TelemetryPhase::ContractLoaded,
                        outcome: telemetry::TelemetryOutcome::Succeeded,
                        sizes,
                        ..telemetry::EventSpec::default()
                    });
                    let schema_error = schema_valid != Some(true);
                    let normalized_error = if schema_error {
                        telemetry::TelemetryErrorClass::SchemaValidation
                    } else {
                        telemetry::TelemetryErrorClass::RuntimeValidation
                    };
                    let flags = telemetry::TelemetryFlags {
                        repair_returned: true,
                        ..telemetry::TelemetryFlags::default()
                    };
                    let counts = telemetry::TelemetryCounts {
                        attempt_bucket: telemetry::attempt_bucket(1),
                        repair_count_bucket: telemetry::repair_bucket(1),
                        ..telemetry::TelemetryCounts::default()
                    };
                    telemetry.emit(telemetry::EventSpec {
                        request: Some(request.clone()),
                        phase: telemetry::TelemetryPhase::ValidationCompleted,
                        outcome: telemetry::TelemetryOutcome::Rejected,
                        error_class: Some(normalized_error),
                        flags,
                        counts,
                        latency_bucket: telemetry::latency_bucket(latency_ms),
                        sizes,
                    });
                    telemetry.emit(telemetry::EventSpec {
                        request: Some(request),
                        phase: telemetry::TelemetryPhase::RepairReturned,
                        outcome: telemetry::TelemetryOutcome::Repaired,
                        error_class: Some(normalized_error),
                        flags,
                        counts,
                        latency_bucket: telemetry::latency_bucket(latency_ms),
                        sizes,
                    });
                }
            }
        }
        self.trace.record(json!({
            "schema": TRACE_SCHEMA,
            "request_id": request_id,
            "kind": if error_class == "validation_failure" { "validation_failure" } else { "operation_selection" },
            "mode": if contract.is_some() { "repair" } else { "direct" },
            "executor": executor,
            "operation": operation,
            "contract_digest": contract.map(|contract| contract.digest.as_str()),
            "contract_bytes": contract.map(|contract| contract.bytes),
            "manifest_sha256": self.manifest_digest,
            "run_key": run_key,
            "schema_valid": schema_valid,
            "runtime_valid": if schema_valid == Some(true) { Some(false) } else { None },
            "completed": false,
            "error_class": error_class,
            "repair_contract_returned": contract.is_some(),
            "request_bytes": serde_json::to_vec(arguments).map(|bytes| bytes.len()).unwrap_or(0),
            "response_bytes": response_bytes,
            "elapsed_ms": latency_ms,
            "selection": {"executor": executor, "operation": operation},
            "validation": {
                "schema_valid": schema_valid,
                "runtime_valid": if schema_valid == Some(true) { Some(false) } else { None },
            },
            "repair": {
                "returned": contract.is_some(),
                "repair_of": Value::Null,
            },
            "counts": {"tool_calls": 1, "turns": Value::Null},
            "latency_ms": latency_ms,
            "sizes": {
                "request_bytes": serde_json::to_vec(arguments).map(|bytes| bytes.len()).unwrap_or(0),
                "result_bytes": response_bytes,
                "contract_bytes": contract.map(|contract| contract.bytes),
                "manifest_bytes": self.descriptor_bytes,
            },
        }));
        body
    }

    fn executor_meta(&self) -> Value {
        production_executor_meta("ordinary", &self.manifest_digest, self.descriptor_bytes)
    }
}

/// Permission-shaped facade over the existing hosted lens dispatcher.
///
/// The facade owns no federation, authorization, pagination, destination, or
/// materialization semantics. Accepted calls are translated back to the exact
/// legacy tool/action and delegated once to [`LensDispatch`], which remains
/// authoritative for all of those behaviours.
pub(crate) struct ExecutorPrototypeLensServer {
    registry: Arc<ToolRegistry>,
    dispatcher: Arc<dyn LensDispatch>,
    descriptors: Vec<Value>,
    descriptor_bytes: usize,
    manifest_digest: String,
    contracts: OperationContracts,
    operations_by_executor: OperationsByExecutor,
    telemetry: Option<telemetry::BoundExecutorTelemetry>,
}

impl ExecutorPrototypeLensServer {
    pub(crate) fn pin_catalogue(
        registry: &ToolRegistry,
    ) -> Result<Arc<PinnedLensExecutorCatalogue>> {
        let audit: Audit = serde_json::from_str(AUDIT)?;
        let policy = super::ResolvedToolExposure::new(super::ExposureProfile::Complete);
        let sources = lens_descriptor_projection_for_policy(registry, &policy)?;
        let BuiltContracts {
            contracts,
            operations_by_executor,
        } = build_lens_contracts(registry, &sources, &audit.audit_rows)?;
        let source_surface = audit.candidate_surfaces.stable.lens;
        if serde_json::to_vec(&source_surface.descriptors)?.len() != source_surface.descriptor_bytes
        {
            return Err(Error::engine(
                "audited lens executor descriptor byte count drifted",
            ));
        }
        let descriptors =
            executable_descriptors(source_surface.descriptors, &operations_by_executor)?;
        let descriptor_bytes = serde_json::to_vec(&descriptors)?.len();
        let manifest_digest = jcs_sha256(&Value::Array(descriptors.clone()))?;
        Ok(Arc::new(PinnedLensExecutorCatalogue {
            descriptors,
            descriptor_bytes,
            manifest_digest,
            contracts,
            operations_by_executor,
        }))
    }

    pub(crate) fn new_with_pinned_catalogue(
        registry: Arc<ToolRegistry>,
        dispatcher: Arc<dyn LensDispatch>,
        catalogue: Arc<PinnedLensExecutorCatalogue>,
        telemetry: Option<telemetry::BoundExecutorTelemetry>,
    ) -> Result<Self> {
        Ok(Self {
            registry,
            dispatcher,
            descriptors: catalogue.descriptors.clone(),
            descriptor_bytes: catalogue.descriptor_bytes,
            manifest_digest: catalogue.manifest_digest.clone(),
            contracts: catalogue.contracts.clone(),
            operations_by_executor: catalogue.operations_by_executor.clone(),
            telemetry,
        })
    }

    pub(crate) async fn handle_message(&self, mut message: Value) -> Option<Value> {
        let modern = protocol::is_modern_request(&message);
        let (method, name) = protocol::method_and_name(&message);
        if method == Some("initialize") {
            if let Some(telemetry) = &self.telemetry {
                telemetry.authenticated_initialize();
            }
            return outcome_body(self.delegate(message).await);
        }
        if method == Some("tools/list") {
            return outcome_body(self.delegate(message).await).map(|mut body| {
                if body.get("result").is_some() {
                    body["result"]["tools"] = Value::Array(self.descriptors.clone());
                    body["result"]["_meta"]["nativeExecutor"] = self.executor_meta();
                }
                body
            });
        }
        if method != Some("tools/call") {
            return outcome_body(self.delegate(message).await);
        }
        let id = protocol::request_id(&message);
        if id.is_null() {
            return None;
        }
        let Some(params) = message.get("params").and_then(Value::as_object) else {
            return Some(protocol::error_response(
                id,
                protocol::INVALID_PARAMS,
                "invalid params: tools/call params must be an object",
            ));
        };
        let Some(executor) = name.map(str::to_string) else {
            return Some(protocol::error_response(
                id,
                protocol::INVALID_PARAMS,
                "invalid params: missing tool name",
            ));
        };
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if let Err(error) = render::reject_format(&arguments, "lens executor") {
            return Some(
                self.error_response(id, modern, &error, None, &arguments)
                    .await,
            );
        }
        if executor == "describe_operation" {
            if let Err(error) = validate_envelope_fields(
                &arguments,
                &["executor", "operation", "run_key", "parent_key"],
            ) {
                return Some(
                    self.error_response(id, modern, &error.to_string(), None, &arguments)
                        .await,
                );
            }
            return Some(self.describe_response(id, arguments, modern).await);
        }
        if executor == "bootstrap" {
            if let Err(error) = validate_envelope_fields(&arguments, &["run_key", "parent_key"]) {
                return Some(
                    self.error_response(id, modern, &error.to_string(), None, &arguments)
                        .await,
                );
            }
            message["params"]["arguments"]["format"] = json!("json");
            let mut body = outcome_body(self.delegate(message).await)?;
            rewrite_executor_bootstrap(
                &mut body,
                render::Format::Json,
                "lens",
                self.descriptors.len(),
                self.descriptor_bytes,
            );
            add_executor_meta(&mut body, self.executor_meta());
            return Some(body);
        }
        let resolved_executor = self
            .operations_by_executor
            .contains_key(&executor)
            .then_some(executor.as_str());
        let Some(operation) = arguments.get("operation").and_then(Value::as_str) else {
            self.emit_selection_failure(resolved_executor, None, &arguments, false);
            return Some(
                self.error_response(
                    id,
                    modern,
                    "missing required string field 'operation'",
                    None,
                    &arguments,
                )
                .await,
            );
        };
        let operation = operation.to_string();
        let Some(contract) = self
            .contracts
            .get(&(executor.clone(), operation.clone()))
            .cloned()
        else {
            let expected = self
                .operations_by_executor
                .get(&executor)
                .cloned()
                .unwrap_or_default();
            let diagnostic = if expected.is_empty() {
                format!("unknown executor '{executor}'")
            } else {
                format!(
                    "unknown operation '{operation}' for {executor}; expected one of: {}",
                    expected.join(", ")
                )
            };
            let resolved_operation = expected
                .iter()
                .any(|candidate| candidate == &operation)
                .then_some(operation.as_str());
            self.emit_selection_failure(resolved_executor, resolved_operation, &arguments, false);
            return Some(
                self.error_response(id, modern, &diagnostic, None, &arguments)
                    .await,
            );
        };
        if let Err(error) = validate_envelope_fields(
            &arguments,
            &[
                "operation",
                "arguments",
                "run_key",
                "parent_key",
                "destination_db_id",
                "cursor",
                "page_size",
            ],
        ) {
            return Some(
                self.error_response(id, modern, &error.to_string(), Some(&contract), &arguments)
                    .await,
            );
        }
        let telemetry_request = self
            .telemetry
            .as_ref()
            .map(|telemetry| telemetry.request(Some(&executor), Some(&operation), None));
        if let (Some(telemetry), Some(request)) = (&self.telemetry, &telemetry_request) {
            let sizes = telemetry::TelemetrySizes {
                request_bytes: telemetry::size_bucket(
                    serde_json::to_vec(&arguments)
                        .map(|bytes| bytes.len())
                        .unwrap_or(0),
                ),
                contract_bytes: telemetry::size_bucket(contract.bytes),
                ..telemetry::TelemetrySizes::default()
            };
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::OperationSelected,
                outcome: telemetry::TelemetryOutcome::Succeeded,
                sizes,
                ..telemetry::EventSpec::default()
            });
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::ContractLoaded,
                outcome: telemetry::TelemetryOutcome::Succeeded,
                sizes,
                ..telemetry::EventSpec::default()
            });
        }
        let operation_arguments = arguments
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let schema_errors = match jsonschema::validator_for(&contract.input_schema) {
            Ok(validator) => validator
                .iter_errors(&operation_arguments)
                .map(|error| error.to_string())
                .collect::<Vec<_>>(),
            Err(error) => vec![format!("invalid authoritative contract: {error}")],
        };
        if !schema_errors.is_empty() {
            self.emit_validation_failure(
                telemetry_request.as_ref(),
                &contract,
                &arguments,
                telemetry::TelemetryErrorClass::SchemaValidation,
            );
            return Some(
                self.error_response(
                    id,
                    modern,
                    &format!(
                        "arguments do not match the authoritative lens operation contract: {}",
                        schema_errors.join("; ")
                    ),
                    Some(&contract),
                    &arguments,
                )
                .await,
            );
        }
        let legacy_arguments = match translate_arguments(&contract, &arguments) {
            Ok(arguments) => arguments,
            Err(error) => {
                self.emit_validation_failure(
                    telemetry_request.as_ref(),
                    &contract,
                    &arguments,
                    telemetry::TelemetryErrorClass::RuntimeValidation,
                );
                return Some(
                    self.error_response(
                        id,
                        modern,
                        &error.to_string(),
                        Some(&contract),
                        &arguments,
                    )
                    .await,
                );
            }
        };
        if let Some(params) = message.get_mut("params").and_then(Value::as_object_mut) {
            params.insert("name".into(), Value::String(contract.source_tool.clone()));
            params.insert("arguments".into(), legacy_arguments);
        }
        if let (Some(telemetry), Some(request)) = (&self.telemetry, &telemetry_request) {
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::ValidationCompleted,
                outcome: telemetry::TelemetryOutcome::Succeeded,
                counts: telemetry::TelemetryCounts {
                    attempt_bucket: telemetry::attempt_bucket(1),
                    ..telemetry::TelemetryCounts::default()
                },
                ..telemetry::EventSpec::default()
            });
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::DispatchBegun,
                outcome: telemetry::TelemetryOutcome::Started,
                counts: telemetry::TelemetryCounts {
                    dispatch_count_bucket: telemetry::dispatch_bucket(1),
                    ..telemetry::TelemetryCounts::default()
                },
                ..telemetry::EventSpec::default()
            });
        }
        let started = Instant::now();
        let mut body = outcome_body(self.delegate(message).await)?;
        let success = response_succeeded(&body);
        if !success {
            attach_repair(
                &mut body,
                &contract,
                "execution_error",
                None,
                &arguments,
                None,
            );
        }
        add_executor_meta(&mut body, self.executor_meta());
        if let (Some(telemetry), Some(request)) = (&self.telemetry, telemetry_request) {
            let flags = telemetry::TelemetryFlags {
                repair_returned: !success,
                ..telemetry::TelemetryFlags::default()
            };
            let counts = telemetry::TelemetryCounts {
                attempt_bucket: telemetry::attempt_bucket(1),
                dispatch_count_bucket: telemetry::dispatch_bucket(1),
                repair_count_bucket: telemetry::repair_bucket(u64::from(!success)),
                ..telemetry::TelemetryCounts::default()
            };
            let sizes = telemetry::TelemetrySizes {
                request_bytes: telemetry::size_bucket(
                    serde_json::to_vec(&arguments)
                        .map(|bytes| bytes.len())
                        .unwrap_or(0),
                ),
                result_bytes: telemetry::size_bucket(
                    serde_json::to_vec(&body)
                        .map(|bytes| bytes.len())
                        .unwrap_or(0),
                ),
                contract_bytes: telemetry::size_bucket(contract.bytes),
            };
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::DispatchCompleted,
                outcome: if success {
                    telemetry::TelemetryOutcome::Succeeded
                } else {
                    telemetry::TelemetryOutcome::Rejected
                },
                error_class: (!success).then_some(telemetry::TelemetryErrorClass::ExecutionError),
                flags,
                counts,
                latency_bucket: telemetry::latency_bucket(elapsed_ms(started)),
                sizes,
            });
            if !success {
                telemetry.emit(telemetry::EventSpec {
                    request: Some(request),
                    phase: telemetry::TelemetryPhase::RepairReturned,
                    outcome: telemetry::TelemetryOutcome::Repaired,
                    error_class: Some(telemetry::TelemetryErrorClass::ExecutionError),
                    flags,
                    counts,
                    latency_bucket: telemetry::latency_bucket(elapsed_ms(started)),
                    sizes,
                });
            }
        }
        Some(body)
    }

    fn emit_selection_failure(
        &self,
        executor: Option<&str>,
        operation: Option<&str>,
        arguments: &Value,
        repair_returned: bool,
    ) {
        let Some(telemetry) = &self.telemetry else {
            return;
        };
        let request = telemetry.request(executor, operation, None);
        telemetry.emit(telemetry::EventSpec {
            request: Some(request),
            phase: telemetry::TelemetryPhase::OperationSelected,
            outcome: telemetry::TelemetryOutcome::Rejected,
            error_class: Some(telemetry::TelemetryErrorClass::SelectionError),
            flags: telemetry::TelemetryFlags {
                repair_returned,
                ..telemetry::TelemetryFlags::default()
            },
            sizes: telemetry::TelemetrySizes {
                request_bytes: telemetry::size_bucket(
                    serde_json::to_vec(arguments)
                        .map(|bytes| bytes.len())
                        .unwrap_or(0),
                ),
                ..telemetry::TelemetrySizes::default()
            },
            ..telemetry::EventSpec::default()
        });
    }

    fn emit_validation_failure(
        &self,
        request: Option<&telemetry::TelemetryRequest>,
        contract: &OperationContract,
        arguments: &Value,
        error_class: telemetry::TelemetryErrorClass,
    ) {
        let (Some(telemetry), Some(request)) = (&self.telemetry, request) else {
            return;
        };
        let flags = telemetry::TelemetryFlags {
            repair_returned: true,
            ..telemetry::TelemetryFlags::default()
        };
        let counts = telemetry::TelemetryCounts {
            attempt_bucket: telemetry::attempt_bucket(1),
            repair_count_bucket: telemetry::repair_bucket(1),
            ..telemetry::TelemetryCounts::default()
        };
        let sizes = telemetry::TelemetrySizes {
            request_bytes: telemetry::size_bucket(
                serde_json::to_vec(arguments)
                    .map(|bytes| bytes.len())
                    .unwrap_or(0),
            ),
            contract_bytes: telemetry::size_bucket(contract.bytes),
            ..telemetry::TelemetrySizes::default()
        };
        telemetry.emit(telemetry::EventSpec {
            request: Some(request.clone()),
            phase: telemetry::TelemetryPhase::ValidationCompleted,
            outcome: telemetry::TelemetryOutcome::Rejected,
            error_class: Some(error_class),
            flags,
            counts,
            sizes,
            ..telemetry::EventSpec::default()
        });
        telemetry.emit(telemetry::EventSpec {
            request: Some(request.clone()),
            phase: telemetry::TelemetryPhase::RepairReturned,
            outcome: telemetry::TelemetryOutcome::Repaired,
            error_class: Some(error_class),
            flags,
            counts,
            sizes,
            ..telemetry::EventSpec::default()
        });
    }

    async fn describe_response(&self, id: Value, arguments: Value, modern: bool) -> Value {
        let started = Instant::now();
        let executor = arguments
            .get("executor")
            .and_then(Value::as_str)
            .unwrap_or("");
        let operation = arguments
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("");
        let Some(contract) = self
            .contracts
            .get(&(executor.to_string(), operation.to_string()))
        else {
            return self
                .error_response(
                    id,
                    modern,
                    "unknown (executor, operation)",
                    None,
                    &arguments,
                )
                .await;
        };
        let run_context = self
            .dispatcher
            .run_context(&self.registry, &arguments)
            .await;
        let structured = attach_run_context(contract.payload(), run_context);
        let mut result = protocol::call_result_content(
            "describe_operation",
            render::Format::Json,
            ToolResult::from(structured),
            None,
        );
        if modern {
            protocol::add_modern_result_fields(&mut result);
        }
        result["_meta"]["nativeExecutor"] = self.executor_meta();
        let body = json!({"jsonrpc":"2.0","id":id,"result":result});
        if let Some(telemetry) = &self.telemetry {
            let request = telemetry.request(Some(executor), Some(operation), None);
            let sizes = telemetry::TelemetrySizes {
                request_bytes: telemetry::size_bucket(
                    serde_json::to_vec(&arguments)
                        .map(|bytes| bytes.len())
                        .unwrap_or(0),
                ),
                result_bytes: telemetry::size_bucket(
                    serde_json::to_vec(&body)
                        .map(|bytes| bytes.len())
                        .unwrap_or(0),
                ),
                contract_bytes: telemetry::size_bucket(contract.bytes),
            };
            telemetry.emit(telemetry::EventSpec {
                request: Some(request.clone()),
                phase: telemetry::TelemetryPhase::OperationSelected,
                outcome: telemetry::TelemetryOutcome::Succeeded,
                sizes,
                ..telemetry::EventSpec::default()
            });
            telemetry.emit(telemetry::EventSpec {
                request: Some(request),
                phase: telemetry::TelemetryPhase::ContractLoaded,
                outcome: telemetry::TelemetryOutcome::Succeeded,
                flags: telemetry::TelemetryFlags {
                    described_before: true,
                    ..telemetry::TelemetryFlags::default()
                },
                latency_bucket: telemetry::latency_bucket(elapsed_ms(started)),
                sizes,
                ..telemetry::EventSpec::default()
            });
        }
        body
    }

    async fn error_response(
        &self,
        id: Value,
        modern: bool,
        diagnostic: &str,
        contract: Option<&OperationContract>,
        arguments: &Value,
    ) -> Value {
        let run_context = self.dispatcher.run_context(&self.registry, arguments).await;
        let error = Error::engine(format!("executor prototype: {diagnostic}"));
        let mut result = protocol::call_error_content(&error, run_context, None);
        if let Some(contract) = contract {
            attach_repair_result(
                &mut result,
                contract,
                "validation_failure",
                Some(diagnostic),
                arguments,
                None,
            );
        }
        if modern {
            protocol::add_modern_result_fields(&mut result);
        }
        result["_meta"]["nativeExecutor"] = self.executor_meta();
        json!({"jsonrpc":"2.0","id":id,"result":result})
    }

    async fn delegate(&self, message: Value) -> RpcOutcome {
        if protocol::is_modern_request(&message) {
            protocol::handle_modern_lens_message(
                self.registry.clone(),
                self.dispatcher.clone(),
                message,
            )
            .await
        } else {
            protocol::handle_legacy_lens_message(
                self.registry.clone(),
                self.dispatcher.clone(),
                message,
            )
            .await
        }
    }

    fn executor_meta(&self) -> Value {
        production_executor_meta("lens", &self.manifest_digest, self.descriptor_bytes)
    }
}

#[cfg(test)]
fn build_contracts(
    registry: &ToolRegistry,
    engine_kind: super::registry::EngineKind,
    rows: &[AuditRow],
    surface: ExecutorSurface,
) -> Result<BuiltContracts> {
    build_contracts_for_hosting(registry, engine_kind, rows, surface, false)
}

fn build_contracts_for_hosting(
    registry: &ToolRegistry,
    engine_kind: super::registry::EngineKind,
    rows: &[AuditRow],
    surface: ExecutorSurface,
    hosted_membership_plans: bool,
) -> Result<BuiltContracts> {
    let mut contracts = BTreeMap::new();
    let mut operations_by_executor = OperationsByExecutor::new();
    for row in rows.iter().filter(|row| {
        row.stability == "stable"
            && row
                .availability
                .iter()
                .any(|available| available == surface.as_str())
    }) {
        validate_candidate_plan_policy(row)?;
        let Some(source) = registry.get(&row.legacy_tool) else {
            // An environment-gated source capability is unavailable before
            // selection. It receives neither a contract nor an advertised
            // operation enum value; no substitute schema is invented.
            continue;
        };
        // Validate the audited selector and registered operation contract even when
        // this environment cannot advertise the operation. Availability is a
        // runtime concern; a broken compatibility mapping is always a build
        // error.
        let contract = operation_contract(
            &source.input_schema,
            &source.description,
            row,
            surface,
            source.operation_schema(&row.legacy_action),
        )?
        .with_registered_access(registry);
        if !registry.has_engine_operation(
            &row.legacy_tool,
            engine_kind,
            contract
                .selector
                .as_ref()
                .map(|selector| (selector.field.as_str(), selector.value.as_str())),
        ) {
            // A schema-only or backend-unimplemented source is not executable
            // in this environment and therefore must not be advertised.
            continue;
        }
        if engine_kind != super::registry::EngineKind::Sqlite
            && write_operations::requires_plan(&row.candidate_executor, &row.candidate_operation)
        {
            // The signed plan store is currently SQLite-qualified. A source
            // handler or preparer on another backend is not by itself an
            // executable plan route, so withhold every plan-required contract
            // before tools/list and selection.
            continue;
        }
        if !operation_has_execution_path_for_hosting(
            surface,
            &row.candidate_executor,
            &row.candidate_operation,
            hosted_membership_plans,
        ) {
            // The dogfood policy forbids raw execution for these high-risk
            // operations. Until a truthful non-mutating preparer exists, the
            // production handler alone is not an executable executor route.
            continue;
        }
        operations_by_executor
            .entry(row.candidate_executor.clone())
            .or_default()
            .push(row.candidate_operation.clone());
        contracts.insert(
            (
                row.candidate_executor.clone(),
                row.candidate_operation.clone(),
            ),
            contract,
        );
    }
    for operations in operations_by_executor.values_mut() {
        operations.sort();
        operations.dedup();
    }
    Ok(BuiltContracts {
        contracts,
        operations_by_executor,
    })
}

fn build_lens_contracts(
    registry: &ToolRegistry,
    source_descriptors: &[super::registry::AdvertisedTool],
    rows: &[AuditRow],
) -> Result<BuiltContracts> {
    let schemas = source_descriptors
        .iter()
        .filter_map(|tool| {
            tool.descriptor
                .get("inputSchema")
                .map(|schema| (tool.name.as_str(), schema))
        })
        .collect::<HashMap<_, _>>();
    // Read the description off the same projected descriptor the schema came
    // from, so the lens surface discloses what it actually advertises rather
    // than what the unprojected registry holds.
    let descriptions = source_descriptors
        .iter()
        .filter_map(|tool| {
            tool.descriptor
                .get("description")
                .and_then(Value::as_str)
                .map(|description| (tool.name.as_str(), description))
        })
        .collect::<HashMap<_, _>>();
    let mut contracts = BTreeMap::new();
    let mut operations_by_executor = OperationsByExecutor::new();
    for row in rows.iter().filter(|row| {
        row.stability == "stable" && row.availability.iter().any(|value| value == "lens")
    }) {
        validate_candidate_plan_policy(row)?;
        let Some(source_schema) = schemas.get(row.legacy_tool.as_str()) else {
            continue;
        };
        let contract = operation_contract(
            source_schema,
            descriptions
                .get(row.legacy_tool.as_str())
                .copied()
                .unwrap_or_default(),
            row,
            ExecutorSurface::Lens,
            registry
                .get(&row.legacy_tool)
                .and_then(|source| source.operation_schema(&row.legacy_action)),
        )?
        .with_registered_access(registry);
        let source_executable = row.legacy_tool == "materialize_record"
            || registry.has_engine_operation(
                &row.legacy_tool,
                super::registry::EngineKind::Sqlite,
                contract
                    .selector
                    .as_ref()
                    .map(|selector| (selector.field.as_str(), selector.value.as_str())),
            );
        if !source_executable
            || !operation_has_execution_path(
                ExecutorSurface::Lens,
                &row.candidate_executor,
                &row.candidate_operation,
            )
        {
            continue;
        }
        operations_by_executor
            .entry(row.candidate_executor.clone())
            .or_default()
            .push(row.candidate_operation.clone());
        contracts.insert(
            (
                row.candidate_executor.clone(),
                row.candidate_operation.clone(),
            ),
            contract,
        );
    }
    for operations in operations_by_executor.values_mut() {
        operations.sort();
        operations.dedup();
    }
    Ok(BuiltContracts {
        contracts,
        operations_by_executor,
    })
}

fn validate_candidate_plan_policy(row: &AuditRow) -> Result<()> {
    let expected =
        if write_operations::requires_plan(&row.candidate_executor, &row.candidate_operation) {
            "plan_required"
        } else {
            "direct"
        };
    if row.candidate_plan_policy != expected {
        return Err(Error::engine(format!(
            "candidate plan classification drift for {}.{}: audit={}, runtime={expected}",
            row.candidate_executor, row.candidate_operation, row.candidate_plan_policy
        )));
    }
    Ok(())
}

fn operation_contract(
    source_schema: &Value,
    source_description: &str,
    row: &AuditRow,
    surface: ExecutorSurface,
    selector_specific_schema: Option<&Value>,
) -> Result<OperationContract> {
    // A registered tool with no description is a build error for the same
    // reason a missing schema is: the contract is the only place a caller can
    // learn what an operation does, and an empty string discloses nothing
    // while looking like disclosure.
    if source_description.trim().is_empty() {
        return Err(Error::engine(format!(
            "source tool {} has no registered description, so the contract for {}.{} would disclose nothing",
            row.legacy_tool, row.candidate_executor, row.candidate_operation
        )));
    }
    let selector = if row.legacy_action == "call" {
        None
    } else {
        find_selector(source_schema, &row.legacy_action)
    };
    if row.legacy_action != "call" && selector.is_none() {
        return Err(Error::engine(format!(
            "candidate mapping {}.{} cannot find source selector value '{}' on {}",
            row.candidate_executor, row.candidate_operation, row.legacy_action, row.legacy_tool
        )));
    }
    let mut input_schema = match selector_specific_schema {
        Some(schema) => schema.clone(),
        None => project_operation_schema(source_schema, selector.as_ref(), surface)?,
    };
    strip_routing_fields(&mut input_schema, None, surface);
    if surface == ExecutorSurface::Ordinary
        && row.candidate_executor == "records_read"
        && row.candidate_operation == "query_record"
    {
        let mut authoritative = super::tools::querying::query_record_operation_schema();
        strip_routing_fields(&mut authoritative, None, surface);
        if input_schema != authoritative {
            return Err(Error::engine(
                "records_read.query_record contract drifted from its authoritative typed schema",
            ));
        }
    }
    let digest_input = json!({
        "contract_version": CONTRACT_VERSION,
        "executor": row.candidate_executor,
        "operation": row.candidate_operation,
        "surface": surface.as_str(),
        "source_tool": row.legacy_tool,
        // The digest certifies everything the contract discloses. Exempting
        // the only human-readable part would invert the point of having one:
        // a silent wording change would be undetectable, which is the exact
        // failure this field exists to fix.
        "tool_description": source_description,
        "selector": selector.as_ref().map(|selector| json!({
            "field": selector.field,
            "value": selector.value,
        })),
        "selector_specific_schema": selector_specific_schema.is_some(),
        "input_schema": input_schema,
    });
    let digest = jcs_sha256(&digest_input)?;
    let bytes = serde_json::to_vec(&input_schema)?.len();
    Ok(OperationContract {
        surface,
        executor: row.candidate_executor.clone(),
        operation: row.candidate_operation.clone(),
        source_tool: row.legacy_tool.clone(),
        tool_description: source_description.to_owned(),
        selector,
        input_schema,
        selector_specific_schema: selector_specific_schema.is_some(),
        access: OperationAccess::Mutation,
        digest,
        bytes,
    })
}

fn operation_has_execution_path(surface: ExecutorSurface, executor: &str, operation: &str) -> bool {
    operation_has_execution_path_for_hosting(surface, executor, operation, false)
}

fn operation_has_execution_path_for_hosting(
    surface: ExecutorSurface,
    executor: &str,
    operation: &str,
    hosted_membership_plans: bool,
) -> bool {
    match surface {
        ExecutorSurface::Ordinary => {
            write_operations::advertisable(executor, operation)
                || (hosted_membership_plans
                    && write_operations::is_membership_operation(executor, operation))
        }
        ExecutorSurface::Lens => !write_operations::requires_plan(executor, operation),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExecutorSurface {
    Ordinary,
    Lens,
}

impl ExecutorSurface {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Lens => "lens",
        }
    }
}

fn executable_descriptors(
    descriptors: Vec<Value>,
    operations_by_executor: &BTreeMap<String, Vec<String>>,
) -> Result<Vec<Value>> {
    let mut available = descriptors
        .into_iter()
        .filter_map(|mut descriptor| {
            let name = descriptor.get("name")?.as_str()?.to_string();
            if name == "describe_operation" {
                return Some(descriptor);
            }
            let operations = operations_by_executor.get(&name)?;
            if name != "bootstrap" {
                descriptor["inputSchema"]["properties"]["operation"]["enum"] = json!(operations);
                let operations = operations
                    .iter()
                    .map(String::as_str)
                    .collect::<HashSet<_>>();
                filter_operation_constraints(&mut descriptor["inputSchema"], &operations);
            }
            Some(descriptor)
        })
        .collect::<Vec<_>>();

    let executor_names = available
        .iter()
        .filter_map(|descriptor| descriptor.get("name").and_then(Value::as_str))
        .filter(|name| *name != "describe_operation")
        .map(str::to_string)
        .collect::<Vec<_>>();
    let describe = available
        .iter_mut()
        .find(|descriptor| descriptor["name"] == "describe_operation")
        .ok_or_else(|| Error::engine("executor catalogue is missing describe_operation"))?;
    describe["inputSchema"]["properties"]["executor"]["enum"] = json!(executor_names);
    Ok(available)
}

/// Advertise the response selector on the ordinary callable envelope. Direct
/// operations inherit their source renderer truth; plan-backed operations and
/// executor-authored contract receipts are JSON-only until they gain audited
/// compact renderers. Conditional schemas keep grouped executors honest.
fn add_ordinary_executor_format_contracts(
    descriptors: &mut [Value],
    contracts: &OperationContracts,
) -> Result<()> {
    let text_json = json!({
        "type":"string",
        "enum":["text","json"],
        "default":"text",
        "description":"Response representation on this callable envelope. Availability may depend on operation; keep this field outside nested arguments."
    });
    let json_only = json!({
        "type":"string",
        "enum":["json"],
        "default":"json",
        "description":"Exact serialized JSON in content plus the exact object in structuredContent. Keep this field outside nested arguments."
    });
    for descriptor in descriptors {
        let name = descriptor
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("executor descriptor has no name"))?
            .to_string();
        let schema = descriptor.get_mut("inputSchema").ok_or_else(|| {
            Error::engine(format!("executor descriptor {name} has no inputSchema"))
        })?;
        if name == "bootstrap" {
            render::add_format_schema(schema, &text_json);
            continue;
        }
        if name == "describe_operation" {
            render::add_format_schema(schema, &json_only);
            continue;
        }
        let mut text_operations = Vec::new();
        let mut json_operations = Vec::new();
        for ((executor, operation), contract) in contracts {
            if executor != &name {
                continue;
            }
            if !write_operations::requires_plan(executor, operation)
                && render::has_renderer(&contract.source_tool)
            {
                text_operations.push(operation.clone());
            } else {
                json_operations.push(operation.clone());
            }
        }
        text_operations.sort();
        json_operations.sort();
        let broad = if text_operations.is_empty() {
            json_only.clone()
        } else {
            let mut schema = text_json.clone();
            schema.as_object_mut().unwrap().remove("default");
            schema
        };
        render::add_format_schema(schema, &broad);
        if !text_operations.is_empty() && !json_operations.is_empty() {
            let conditions = schema
                .as_object_mut()
                .expect("executor input schema object")
                .entry("allOf")
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .expect("executor allOf array");
            conditions.push(json!({
                "if":{"properties":{"operation":{"enum":text_operations}},"required":["operation"]},
                "then":{"properties":{"format":text_json}}
            }));
            conditions.push(json!({
                "if":{"properties":{"operation":{"enum":json_operations}},"required":["operation"]},
                "then":{"properties":{"format":json_only}}
            }));
        }
        update_executor_argument_descriptions(schema);
    }
    Ok(())
}

fn update_executor_argument_descriptions(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(description) = object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("arguments"))
        .and_then(Value::as_object_mut)
        .and_then(|arguments| arguments.get_mut("description"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
    {
        let updated = description.replace(
            "operation, run_key and parent_key",
            "operation, run_key, parent_key and format",
        );
        object["properties"]["arguments"]["description"] = json!(updated);
    }
    for keyword in ["oneOf", "anyOf", "allOf"] {
        if let Some(branches) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            for branch in branches {
                update_executor_argument_descriptions(branch);
            }
        }
    }
}

/// Intersect every executor-operation discriminator with the operations that
/// have a live contract. Plan envelopes repeat this discriminator inside
/// `oneOf`; filtering only the top-level enum leaves withheld operations
/// model-visible even though JSON Schema intersection makes them unreachable.
fn filter_operation_constraints(schema: &mut Value, operations: &HashSet<&str>) {
    match schema {
        Value::Object(object) => {
            if let Some(operation) = object
                .get_mut("properties")
                .and_then(Value::as_object_mut)
                .and_then(|properties| properties.get_mut("operation"))
                .and_then(Value::as_object_mut)
            {
                if let Some(values) = operation.get_mut("enum").and_then(Value::as_array_mut) {
                    values.retain(|value| {
                        value
                            .as_str()
                            .is_some_and(|value| operations.contains(value))
                    });
                }
                if operation
                    .get("const")
                    .and_then(Value::as_str)
                    .is_some_and(|value| !operations.contains(value))
                {
                    operation.remove("const");
                    operation.insert("enum".into(), json!([]));
                }
            }
            for value in object.values_mut() {
                filter_operation_constraints(value, operations);
            }
        }
        Value::Array(values) => {
            for value in values {
                filter_operation_constraints(value, operations);
            }
        }
        _ => {}
    }
}

fn find_selector(schema: &Value, action: &str) -> Option<Selector> {
    let candidates = schema
        .get("oneOf")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_else(|| std::slice::from_ref(schema));
    for candidate in candidates {
        let Some(properties) = candidate.get("properties").and_then(Value::as_object) else {
            continue;
        };
        for (field, property) in properties {
            let matches_const = property.get("const").and_then(Value::as_str) == Some(action);
            let matches_enum = property
                .get("enum")
                .and_then(Value::as_array)
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(action)));
            if matches_const || matches_enum {
                return Some(Selector {
                    field: field.clone(),
                    value: action.to_string(),
                });
            }
        }
    }
    None
}

fn project_operation_schema(
    schema: &Value,
    selector: Option<&Selector>,
    surface: ExecutorSurface,
) -> Result<Value> {
    let mut projected = match selector {
        None => schema.clone(),
        Some(selector) => {
            let candidates = schema
                .get("oneOf")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_else(|| std::slice::from_ref(schema));
            candidates
                .iter()
                .find(|candidate| {
                    candidate
                        .get("properties")
                        .and_then(|properties| properties.get(&selector.field))
                        .is_some_and(|property| {
                            property.get("const").and_then(Value::as_str)
                                == Some(selector.value.as_str())
                                || property.get("enum").and_then(Value::as_array).is_some_and(
                                    |values| {
                                        values.iter().any(|value| {
                                            value.as_str() == Some(selector.value.as_str())
                                        })
                                    },
                                )
                        })
                })
                .cloned()
                .ok_or_else(|| {
                    Error::engine(format!(
                        "candidate selector {}={} is absent from source schema",
                        selector.field, selector.value
                    ))
                })?
        }
    };
    strip_routing_fields(
        &mut projected,
        selector.map(|selector| selector.field.as_str()),
        surface,
    );
    Ok(projected)
}

fn strip_routing_fields(
    schema: &mut Value,
    selector_field: Option<&str>,
    surface: ExecutorSurface,
) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(properties) = object.get_mut("properties").and_then(Value::as_object_mut) {
        properties.remove("run_key");
        properties.remove("parent_key");
        properties.remove("format");
        if surface == ExecutorSurface::Lens {
            properties.remove("destination_db_id");
            properties.remove("cursor");
            properties.remove("page_size");
        }
        if let Some(selector_field) = selector_field {
            properties.remove(selector_field);
        }
    }
    if let Some(required) = object.get_mut("required").and_then(Value::as_array_mut) {
        required.retain(|field| {
            let field = field.as_str();
            field != Some("run_key")
                && field != Some("parent_key")
                && field != selector_field
                && !(surface == ExecutorSurface::Lens
                    && matches!(field, Some("destination_db_id" | "cursor" | "page_size")))
        });
    }
    for keyword in ["oneOf", "anyOf", "allOf"] {
        if let Some(branches) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            for branch in branches {
                strip_routing_fields(branch, selector_field, surface);
            }
        }
    }
}

fn validate_envelope_fields(arguments: &Value, allowed: &[&str]) -> Result<()> {
    let object = arguments
        .as_object()
        .ok_or_else(|| Error::engine("executor arguments must be an object"))?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(Error::engine(format!(
            "unknown executor-envelope property '{field}'; accepted properties: {}",
            allowed.join(", ")
        )));
    }
    Ok(())
}

fn translate_arguments(contract: &OperationContract, envelope: &Value) -> Result<Value> {
    let mut arguments = envelope
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let object = arguments.as_object_mut().ok_or_else(|| {
        Error::engine(format!(
            "{}.{} arguments must be an object",
            contract.executor, contract.operation
        ))
    })?;
    if let Some(selector) = &contract.selector {
        object.insert(
            selector.field.clone(),
            Value::String(selector.value.clone()),
        );
    }
    // `format` rides the envelope, not the operation arguments: it selects a
    // representation rather than saying anything about the operation, and the
    // operation schemas are projections of source ToolSpecs that have no such
    // field. The delegate's `render::take_format` reads it and strips it before
    // any handler parses, exactly as it does for a direct caller.
    //
    // Ordinary only. The lens surface forces JSON downstream
    // (`federation.rs`), so forwarding `format` there would accept an argument
    // and then discard it — the failure this whole seam exists to avoid.
    let routing_fields: &[&str] = match contract.surface {
        ExecutorSurface::Ordinary => &["run_key", "parent_key", "format"],
        ExecutorSurface::Lens => &[
            "run_key",
            "parent_key",
            "destination_db_id",
            "cursor",
            "page_size",
        ],
    };
    for field in routing_fields {
        if let Some(value) = envelope.get(field) {
            object.insert((*field).into(), value.clone());
        }
    }
    Ok(arguments)
}

fn validate_enabled_operation(
    contract: &OperationContract,
    arguments: Value,
    hosted_authority: Option<&dyn HostedExecutorAuthority>,
) -> Result<()> {
    if read_operations::supports(&contract.executor, &contract.operation) {
        return read_operations::validate(&contract.executor, &contract.operation, arguments);
    }
    if write_operations::supports(&contract.executor, &contract.operation) {
        return write_operations::validate(
            &contract.executor,
            &contract.operation,
            arguments,
            hosted_authority,
        );
    }
    // The registered operation contract and unchanged production handler are
    // authoritative for static shape and stateful admission respectively.
    // Only the operations above have a stronger side-effect-free parser
    // available for eager repair; every other accepted call proceeds through
    // the exact production dispatch seam once.
    Ok(())
}

fn attach_repair(
    body: &mut Value,
    contract: &OperationContract,
    error_class: &str,
    diagnostic: Option<&str>,
    envelope: &Value,
    hosted_authority: Option<&dyn HostedExecutorAuthority>,
) {
    if let Some(result) = body.get_mut("result") {
        let source_diagnostic = diagnostic.map(str::to_owned).or_else(|| {
            result
                .pointer("/structuredContent/error")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        attach_repair_result(
            result,
            contract,
            error_class,
            source_diagnostic.as_deref(),
            envelope,
            hosted_authority,
        );
    }
}

fn attach_repair_result(
    result: &mut Value,
    contract: &OperationContract,
    error_class: &str,
    diagnostic: Option<&str>,
    envelope: &Value,
    hosted_authority: Option<&dyn HostedExecutorAuthority>,
) {
    let cue = repair_cue(contract, envelope, diagnostic, hosted_authority);
    let is_execution_error = error_class == "execution_error";
    let is_validation_error = matches!(
        error_class,
        "validation_failure" | "preparation_validation_failed"
    );
    let corrected_envelope = cue
        .corrected_envelope
        .filter(|corrected| is_validation_error && corrected != envelope);
    let retry = corrected_envelope.as_ref().map(|corrected| {
        json!({
            "tool": contract.executor,
            "arguments": corrected,
        })
    });
    let code = if is_execution_error {
        "operation_execution_diagnostic"
    } else {
        "operation_contract_repair"
    };
    let reason_code = if is_execution_error {
        "authoritative_source_rejected"
    } else {
        cue.reason_code
    };
    let failing_pointer = if is_execution_error {
        Value::Null
    } else {
        json!(cue.failing_pointer)
    };
    let expected_shape = if is_execution_error {
        json!({
            "description":"The envelope matched the disclosed contract; the authoritative source rejected current state, authorization, or runtime semantics."
        })
    } else {
        cue.expected_shape
    };
    let guidance = is_execution_error.then(|| {
        json!({
            "action":"inspect_authoritative_source_error",
            "retry_ready":false,
            "automatic_retry":false,
            "message":"Resolve or re-read the state, authorization, or concurrency condition reported by the source before constructing another call."
        })
    });
    // A localised failure already carries everything the caller needs to
    // correct the call in `expected_shape`, so echoing the whole `input_schema`
    // beside it is redundant bulk. Point at `describe_operation` instead; the
    // caller can fetch the document on demand and check it against
    // `contract_digest`. When the failure is not localised the caller has not
    // been told how to fix it, so the full document still travels with the
    // repair.
    let localised = !is_execution_error && cue.localised;
    let mut repair = json!({
        "code": code,
        "reason_code": reason_code,
        "error_class": error_class,
        "diagnostic": diagnostic,
        "failing_pointer": failing_pointer,
        "expected_shape": expected_shape,
        "executor": contract.executor,
        "operation": contract.operation,
        "contract_version": CONTRACT_VERSION,
        "contract_digest": contract.digest,
    });
    if localised {
        repair["contract_reference"] = json!({
            "reason":"expected_shape names the failing constraint and the correction it admits; the full operation contract is omitted here",
            "tool":"describe_operation",
            "arguments":{
                "executor": contract.executor,
                "operation": contract.operation,
            },
            "input_schema_pointer":"/result/structuredContent/input_schema",
        });
    } else {
        repair["input_schema"] = contract.input_schema.clone();
    }
    repair["preserved_intent"] = envelope.clone();
    repair["retry_ready"] = json!(corrected_envelope.is_some());
    repair["corrected_envelope"] = json!(corrected_envelope);
    repair["retry"] = json!(retry);
    repair["guidance"] = json!(guidance);
    result["structuredContent"]["repair"] = repair;
    let repair_text = result["structuredContent"]["repair"].to_string();
    if let Some(content) = result.get_mut("content").and_then(Value::as_array_mut) {
        if let Some(text) = content
            .first_mut()
            .and_then(Value::as_object_mut)
            .and_then(|block| block.get_mut("text"))
        {
            let label = if is_execution_error {
                "Execution diagnostic"
            } else {
                "Repair contract"
            };
            let suffix = format!("\n{label}: {repair_text}");
            if let Some(text) = text.as_str() {
                *content.first_mut().expect("first content block") = json!({
                    "type": "text",
                    "text": format!("{text}{suffix}"),
                });
            }
        }
    }
}

struct RepairCue {
    reason_code: &'static str,
    failing_pointer: String,
    expected_shape: Value,
    /// True when `expected_shape` has actually told the caller what to do: the
    /// validator compiled, produced an error, and the error resolved to a
    /// constraint that names a correction — for a rejected property name that
    /// means the accepted names, since `additionalProperties: false` alone
    /// names none. False falls back to prose, and keeps the whole contract.
    localised: bool,
    corrected_envelope: Option<Value>,
}

fn repair_cue(
    contract: &OperationContract,
    envelope: &Value,
    diagnostic: Option<&str>,
    hosted_authority: Option<&dyn HostedExecutorAuthority>,
) -> RepairCue {
    let operation_arguments = envelope
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut reason_code = "operation_arguments_invalid";
    let mut failing_pointer = runtime_failure_pointer(contract, diagnostic);
    let mut expected_shape = json!({
        "description": runtime_expected_shape(contract, diagnostic),
    });
    let mut localised = false;
    if let Ok(validator) = jsonschema::validator_for(&contract.input_schema) {
        if let Some(error) = validator.iter_errors(&operation_arguments).next() {
            use jsonschema::error::ValidationErrorKind;
            let path = error.instance_path().as_str();
            failing_pointer = format!("/arguments{path}");
            reason_code = match error.kind() {
                ValidationErrorKind::Required { property } => {
                    if let Some(property) = property.as_str() {
                        failing_pointer.push('/');
                        failing_pointer.push_str(&escape_json_pointer(property));
                    }
                    "required_field_missing"
                }
                ValidationErrorKind::AdditionalProperties { unexpected }
                | ValidationErrorKind::UnevaluatedProperties { unexpected } => {
                    if let Some(property) = unexpected.first() {
                        failing_pointer.push('/');
                        failing_pointer.push_str(&escape_json_pointer(property));
                    }
                    "unexpected_field"
                }
                ValidationErrorKind::Type { .. } => "wrong_type",
                ValidationErrorKind::Enum { .. } | ValidationErrorKind::Constant { .. } => {
                    "unsupported_value"
                }
                ValidationErrorKind::MinItems { .. } => "array_too_short",
                ValidationErrorKind::Minimum { .. }
                | ValidationErrorKind::ExclusiveMinimum { .. } => "value_too_small",
                ValidationErrorKind::Maximum { .. }
                | ValidationErrorKind::ExclusiveMaximum { .. } => "value_too_large",
                _ => "schema_constraint_failed",
            };
            let schema_pointer = error.schema_path().as_str();
            let constraint = contract.input_schema.pointer(schema_pointer);
            let keyword = error.kind().keyword();
            let mut shape = json!({
                "keyword": keyword,
                "constraint": constraint,
                "contract_pointer": schema_pointer,
            });
            // A rejected property name resolves to the literal
            // `additionalProperties: false`, which tells a caller that
            // misspelled a field nothing about the spelling it wanted. Name the
            // accepted properties of the enclosing object schema — names only,
            // not their subschemas — so the correction is recoverable from the
            // repair without a second round trip.
            let mut names_disclosed = true;
            if matches!(keyword, "additionalProperties" | "unevaluatedProperties") {
                names_disclosed = false;
                let enclosing = schema_pointer
                    .rfind('/')
                    .map_or("", |index| &schema_pointer[..index]);
                if let Some(object) = contract.input_schema.pointer(enclosing) {
                    let accepted = object
                        .get("properties")
                        .and_then(Value::as_object)
                        .map(|properties| properties.keys().cloned().collect::<Vec<_>>())
                        .unwrap_or_default();
                    if !accepted.is_empty() {
                        shape["accepted_properties"] = json!(accepted);
                        shape["required_properties"] =
                            object.get("required").cloned().unwrap_or_else(|| json!([]));
                        names_disclosed = true;
                    }
                }
            }
            expected_shape = shape;
            // Localised means the caller has been told what to do, not merely
            // that a pointer resolved. A constraint that does not resolve, or a
            // rejected property name with no accepted-name list beside it,
            // leaves the caller stranded once the full contract is omitted.
            localised = constraint.is_some() && names_disclosed;
        }
    }
    RepairCue {
        reason_code,
        failing_pointer,
        expected_shape,
        localised,
        corrected_envelope: minimal_corrected_envelope(contract, envelope, hosted_authority),
    }
}

fn escape_json_pointer(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn runtime_failure_pointer(contract: &OperationContract, diagnostic: Option<&str>) -> String {
    if contract.operation != "query_record" {
        return "/arguments".into();
    }
    let diagnostic = diagnostic.unwrap_or_default();
    for field in [
        "steps",
        "activity",
        "count_by",
        "aggregate",
        "facet_key",
        "facet_order",
        "limit",
        "offset",
    ] {
        if diagnostic.contains(field) {
            return format!("/arguments/{field}");
        }
    }
    "/arguments/steps".into()
}

fn runtime_expected_shape(contract: &OperationContract, diagnostic: Option<&str>) -> String {
    if contract.operation == "query_record" {
        return "a non-empty steps array beginning with a filter step; each step is an object with a step discriminator".into();
    }
    diagnostic
        .unwrap_or("an object matching the disclosed operation contract")
        .to_string()
}

fn minimal_corrected_envelope(
    contract: &OperationContract,
    envelope: &Value,
    hosted_authority: Option<&dyn HostedExecutorAuthority>,
) -> Option<Value> {
    let mut corrected = envelope.as_object().cloned().unwrap_or_default();
    corrected.insert("operation".into(), json!(contract.operation));
    let mut operation_arguments = corrected
        .remove("arguments")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();

    const ORDINARY_ROUTING_FIELDS: [&str; 4] = [
        "operation",
        "run_key",
        "parent_key",
        // Putting `format` in the operation arguments is the natural mistake,
        // and the inner schema rejects it. Repair moves it to the envelope
        // rather than dropping the caller's stated intent.
        "format",
    ];
    const LENS_ROUTING_FIELDS: [&str; 6] = [
        "operation",
        "run_key",
        "parent_key",
        "destination_db_id",
        "cursor",
        "page_size",
    ];
    let routing_fields: &[&str] = match contract.surface {
        ExecutorSurface::Ordinary => &ORDINARY_ROUTING_FIELDS,
        ExecutorSurface::Lens => &LENS_ROUTING_FIELDS,
    };
    let misplaced = corrected
        .keys()
        .filter(|field| !routing_fields.contains(&field.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    for field in misplaced {
        if let Some(value) = corrected.remove(&field) {
            operation_arguments.entry(field).or_insert(value);
        }
    }
    for field in routing_fields {
        if *field != "operation" {
            if let Some(value) = operation_arguments.remove(*field) {
                corrected.entry(*field).or_insert(value);
            }
        }
    }
    operation_arguments.remove("operation");

    if contract.operation == "query_record" {
        normalize_query_record_arguments(&mut operation_arguments);
    }
    corrected.insert("arguments".into(), Value::Object(operation_arguments));
    let corrected = Value::Object(corrected);
    let operation_arguments = corrected.get("arguments")?.clone();
    let validator = jsonschema::validator_for(&contract.input_schema).ok()?;
    if !validator.is_valid(&operation_arguments)
        || validate_enabled_operation(contract, operation_arguments, hosted_authority).is_err()
    {
        return None;
    }
    Some(corrected)
}

fn normalize_query_record_arguments(arguments: &mut serde_json::Map<String, Value>) {
    if let Some(steps) = arguments.get_mut("steps") {
        if steps.is_object() {
            *steps = Value::Array(vec![steps.take()]);
        }
        return;
    }
    if arguments.contains_key("step") {
        let outer_fields = [
            "activity",
            "count_by",
            "aggregate",
            "facet_key",
            "order",
            "facet_order",
            "limit",
            "offset",
            "as_of",
            "include_interpretation",
        ];
        let step_fields = arguments
            .keys()
            .filter(|field| !outer_fields.contains(&field.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        let mut step = serde_json::Map::new();
        for field in step_fields {
            if let Some(value) = arguments.remove(&field) {
                step.insert(field, value);
            }
        }
        arguments.insert("steps".into(), Value::Array(vec![Value::Object(step)]));
    }
}

fn attach_empty_query_guidance(
    body: &mut Value,
    contract: &OperationContract,
    operation_arguments: &Value,
    envelope: &Value,
) {
    if contract.executor != "records_read" || contract.operation != "query_record" {
        return;
    }
    let structured = &body["result"]["structuredContent"];
    let empty_records = structured.get("total").and_then(Value::as_i64) == Some(0)
        && structured
            .get("records")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
    if !empty_records {
        return;
    }
    let constraint_pointers = query_constraint_pointers(operation_arguments);
    if constraint_pointers.len() < 2 {
        return;
    }
    let guidance = json!({
        "code":"empty_overconstrained_query",
        "action_required":true,
        "diagnostic":"No records matched this combination of structured constraints. This is evidence about the query, not proof that no relevant record exists.",
        "constraint_pointers":constraint_pointers,
        "next_steps":[
            "Broaden one constraint at a time and retry the same executor operation.",
            "If the intent is discovery rather than exact filtering, use records_read.search or scan before concluding absence."
        ],
        "original_envelope":envelope,
    });
    body["result"]["structuredContent"]["result_guidance"] = guidance.clone();
    append_content_text(&mut body["result"], &format!("Result guidance: {guidance}"));
}

fn query_constraint_pointers(arguments: &Value) -> Vec<String> {
    let Some(steps) = arguments.get("steps").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut pointers = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        let Some(object) = step.as_object() else {
            continue;
        };
        if index > 0 {
            pointers.push(format!("/arguments/steps/{index}"));
        }
        if object.get("step").and_then(Value::as_str) == Some("filter") {
            pointers.extend(
                object
                    .keys()
                    .filter(|field| field.as_str() != "step")
                    .map(|field| {
                        format!("/arguments/steps/{index}/{}", escape_json_pointer(field))
                    }),
            );
        }
    }
    pointers.sort();
    pointers.dedup();
    pointers
}

fn append_content_text(result: &mut Value, suffix: &str) {
    let Some(content) = result.get_mut("content").and_then(Value::as_array_mut) else {
        return;
    };
    let Some(text) = content
        .first_mut()
        .and_then(Value::as_object_mut)
        .and_then(|block| block.get_mut("text"))
        .and_then(|value| value.as_str())
    else {
        return;
    };
    let updated = format!("{text}\n{suffix}");
    content[0]["text"] = Value::String(updated);
}

/// Preserve an ordinary executor caller's representation choice while making
/// the delegated query return the structured payload needed by executor-only
/// result post-processing.
fn force_json_query_record_format(
    contract: &OperationContract,
    arguments: &mut Value,
) -> Option<render::Format> {
    if contract.surface != ExecutorSurface::Ordinary
        || contract.executor != "records_read"
        || contract.operation != "query_record"
    {
        return None;
    }
    let object = arguments.as_object_mut()?;
    let mut clone = Value::Object(object.clone());
    let requested = render::take_format(&contract.source_tool, &mut clone).ok()?;
    object.insert("format".into(), json!("json"));
    Some(requested)
}

/// Reframe a successfully post-processed query without disturbing any
/// additional content/evidence blocks or transport metadata.
fn rewrite_executor_query_record(body: &mut Value, format: render::Format, source_tool: &str) {
    if !response_succeeded(body) {
        return;
    }
    let Some(structured) = body.pointer("/result/structuredContent").cloned() else {
        return;
    };
    let (text, retain_structured) = match format {
        render::Format::Text => {
            let Some(outcome) = render::render_outcome(source_tool, &structured) else {
                return;
            };
            let mut text = outcome.text;
            if let Some(guidance) = structured.get("result_guidance") {
                text.push_str(&format!("\nResult guidance: {guidance}"));
            }
            (text, outcome.requires_structured_fallback)
        }
        render::Format::Json => (structured.to_string(), true),
        render::Format::App => return,
    };
    let Some(first) = body
        .pointer_mut("/result/content")
        .and_then(Value::as_array_mut)
        .and_then(|content| content.first_mut())
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    first.insert("text".into(), Value::String(text));
    if format == render::Format::Text && !retain_structured {
        body["result"]
            .as_object_mut()
            .expect("successful MCP result is an object")
            .remove("structuredContent");
    }
}

/// Make the delegated legacy bootstrap return its structured payload so the
/// executor can replace the legacy registry projection before rendering it.
/// The caller's requested format is validated before the delegated request is
/// rewritten, so the internal JSON forcing cannot hide an invalid value.
fn force_json_bootstrap_format(message: &mut Value) -> std::result::Result<render::Format, String> {
    if message.pointer("/params/arguments").is_none() {
        message["params"]["arguments"] = json!({"format":"json"});
        return Ok(render::Format::Text);
    }
    let arguments = message
        .pointer_mut("/params/arguments")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "arguments must be an object".to_string())?;
    let mut clone = Value::Object(arguments.clone());
    let requested = render::take_format("bootstrap", &mut clone)?;
    arguments.insert("format".into(), json!("json"));
    Ok(requested)
}

fn executor_exposure_summary(
    surface: &str,
    descriptor_count: usize,
    descriptor_bytes: usize,
) -> Value {
    json!({
        "surface": "executor",
        "scope": surface,
        "discovery_semantics": "contract-derived: the catalogue contains only executor descriptors backed by executable operation contracts",
        "authorization_semantics": "independent: every selected executor operation retains its ordinary authorization and validation",
        "advertised_count": descriptor_count,
        "advertised_bytes": descriptor_bytes,
        "configurable": false,
    })
}

fn rewrite_executor_bootstrap(
    body: &mut Value,
    format: render::Format,
    surface: &str,
    descriptor_count: usize,
    descriptor_bytes: usize,
) {
    if !response_succeeded(body) {
        return;
    }
    let Some(structured) = body
        .pointer_mut("/result/structuredContent")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    structured.insert(
        "tool_exposure".into(),
        executor_exposure_summary(surface, descriptor_count, descriptor_bytes),
    );
    let structured = Value::Object(structured.clone());
    let text = match format {
        render::Format::Text => {
            render::render("bootstrap", &structured).unwrap_or_else(|| structured.to_string())
        }
        render::Format::Json => structured.to_string(),
        render::Format::App => unreachable!("bootstrap is not an App tool"),
    };
    body["result"]["content"] = json!([{"type":"text", "text":text}]);
    if format == render::Format::Text {
        body["result"]
            .as_object_mut()
            .expect("successful MCP result is an object")
            .remove("structuredContent");
    } else {
        body["result"]["structuredContent"] = structured;
    }
}

fn add_executor_meta(body: &mut Value, meta: Value) {
    if body.get("result").is_some() {
        body["result"]["_meta"]["nativeExecutor"] = meta;
    }
}

fn production_executor_meta(
    surface: &str,
    manifest_digest: &str,
    descriptor_bytes: usize,
) -> Value {
    json!({
        "schema": "native.mcp-executor.v1",
        "surface": surface,
        "contractVersion": CONTRACT_VERSION,
        "manifestSha256": manifest_digest,
        "descriptorBytes": descriptor_bytes,
        "handlerAuthority": "registered production ToolRegistry",
    })
}

fn response_succeeded(body: &Value) -> bool {
    body.get("result")
        .and_then(|result| result.get("isError"))
        .and_then(Value::as_bool)
        == Some(false)
}

fn outcome_body(outcome: RpcOutcome) -> Option<Value> {
    match outcome {
        RpcOutcome::Notification => None,
        RpcOutcome::Response { body, .. } => Some(body),
    }
}

fn elapsed_ms(started: Instant) -> u64 {
    started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
}

fn jcs_sha256(value: &Value) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(value)?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::create_database;
    use crate::mcp::{register_builtin_tools, register_surface_tools};
    use futures::future::BoxFuture;
    use sqlx::Row;

    fn registry() -> Arc<ToolRegistry> {
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        Arc::new(registry)
    }

    struct BootstrapLensDispatch;

    impl LensDispatch for BootstrapLensDispatch {
        fn exposure_policy(&self, _registry: &ToolRegistry) -> super::super::ResolvedToolExposure {
            super::super::ResolvedToolExposure::new(super::super::ExposureProfile::Complete)
        }

        fn tools_list(&self, _registry: &ToolRegistry, _modern: bool) -> Result<Value> {
            Ok(json!({"tools":[]}))
        }

        fn run_context<'a>(
            &'a self,
            _registry: &'a ToolRegistry,
            _arguments: &'a Value,
        ) -> BoxFuture<'a, Value> {
            Box::pin(async { Value::Null })
        }

        fn tools_call<'a>(
            &'a self,
            _registry: &'a ToolRegistry,
            params: &'a serde_json::Map<String, Value>,
            _modern: bool,
        ) -> BoxFuture<'a, std::result::Result<Value, (i64, String)>> {
            Box::pin(async move {
                if params
                    .get("arguments")
                    .and_then(|arguments| arguments.get("format"))
                    .and_then(Value::as_str)
                    != Some("json")
                {
                    return Err((
                        protocol::INVALID_PARAMS,
                        "lens bootstrap delegate was not forced to JSON".into(),
                    ));
                }
                let structured = json!({"schema":"bootstrap.fixture", "tools":[]});
                Ok(json!({
                    "content":[{"type":"text", "text":structured.to_string()}],
                    "structuredContent":structured,
                    "isError":false
                }))
            })
        }

        fn revision(&self) -> i64 {
            1
        }
    }

    #[test]
    fn production_executor_metadata_is_truthful_and_byte_pinned() {
        let ordinary = production_executor_meta("ordinary", &"a".repeat(64), 30_067);
        let lens = production_executor_meta("lens", &"b".repeat(64), 34_725);
        for (meta, surface, bytes) in [
            (&ordinary, "ordinary", 269_usize),
            (&lens, "lens", 265_usize),
        ] {
            assert_eq!(meta["schema"], "native.mcp-executor.v1");
            assert_eq!(meta["surface"], surface);
            assert_eq!(
                meta["handlerAuthority"],
                "registered production ToolRegistry"
            );
            assert!(meta.get("testOnly").is_none());
            assert!(meta.get("productionRegistrationChanged").is_none());
            assert_eq!(serde_json::to_vec(meta).unwrap().len(), bytes);
        }
    }

    #[test]
    fn lens_executor_bootstrap_exposure_is_fixed_to_its_descriptor_catalogue() {
        let registry = registry();
        let catalogue = ExecutorPrototypeLensServer::pin_catalogue(&registry).unwrap();
        let summary = executor_exposure_summary(
            "lens",
            catalogue.descriptors.len(),
            catalogue.descriptor_bytes,
        );
        assert_eq!(summary["surface"], "executor");
        assert_eq!(summary["scope"], "lens");
        assert_eq!(summary["advertised_count"], catalogue.descriptors.len());
        assert_eq!(summary["advertised_bytes"], catalogue.descriptor_bytes);
        assert_eq!(summary["configurable"], false);
        assert!(summary.get("profile").is_none());
        assert!(summary.get("configure_with").is_none());
    }

    #[tokio::test]
    async fn lens_executor_bootstrap_omission_returns_exact_json() {
        let registry = registry();
        let catalogue = ExecutorPrototypeLensServer::pin_catalogue(&registry).unwrap();
        let server = ExecutorPrototypeLensServer::new_with_pinned_catalogue(
            registry,
            Arc::new(BootstrapLensDispatch),
            catalogue,
            None,
        )
        .unwrap();
        let response = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/call",
                "params":{"name":"bootstrap","arguments":{}}
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], false, "{response}");
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(text).unwrap(),
            response["result"]["structuredContent"],
            "fixed-format lens bootstrap must return exact JSON"
        );
    }

    #[tokio::test]
    async fn executor_bootstrap_reports_its_pinned_catalogue_not_legacy_preferences() {
        let db = create_database(":memory:").await.unwrap();
        let server = ExecutorPrototypeStdioServer::new(
            registry(),
            db.clone(),
            Caller::local().with_exposure_profile(super::super::ExposureProfile::Focused),
            None,
        )
        .await
        .unwrap();

        let json_response = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/call",
                "params":{"name":"bootstrap", "arguments":{"format":"json"}}
            }))
            .await
            .unwrap();
        let exposure = &json_response["result"]["structuredContent"]["tool_exposure"];
        assert_eq!(exposure["surface"], "executor");
        assert_eq!(exposure["scope"], "ordinary");
        assert_eq!(exposure["advertised_count"], server.descriptors.len());
        assert_eq!(exposure["advertised_bytes"], server.descriptor_bytes);
        assert_eq!(exposure["configurable"], false);
        assert!(exposure.get("profile").is_none());
        assert!(exposure.get("configure_with").is_none());
        assert!(exposure["discovery_semantics"]
            .as_str()
            .unwrap()
            .contains("executable operation contracts"));
        let rendered_json: Value = serde_json::from_str(
            json_response["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(rendered_json, json_response["result"]["structuredContent"]);

        let text_request = json!({
            "jsonrpc":"2.0",
            "id":2,
            "method":"tools/call",
            "params":{"name":"bootstrap", "arguments":{"format":"text"}}
        });
        let delegated_text = outcome_body(server.delegate(text_request.clone()).await).unwrap()
            ["result"]["content"][0]["text"]
            .clone();
        let text_response = server.handle_message(text_request).await.unwrap();
        assert!(text_response["result"].get("structuredContent").is_none());
        let normalize_dynamic_bootstrap = |value: &Value| {
            value
                .as_str()
                .unwrap()
                .lines()
                .map(|line| {
                    if line.trim_start().starts_with("run_key: &run_key ") {
                        "  run_key: &run_key \"<dynamic>\""
                    } else if line.starts_with("UTC observed at: ") {
                        "UTC observed at: <dynamic>"
                    } else if line.starts_with("Observed: ") {
                        "Observed: <dynamic>"
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(
            normalize_dynamic_bootstrap(&text_response["result"]["content"][0]["text"]),
            normalize_dynamic_bootstrap(&delegated_text)
        );
        assert!(!text_response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("/workbench/settings/tools"));

        let invalid_format = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":3,
                "method":"tools/call",
                "params":{"name":"bootstrap", "arguments":{"format":"yaml"}}
            }))
            .await
            .unwrap();
        assert!(!response_succeeded(&invalid_format));
        db.close().await;
    }

    #[tokio::test]
    async fn schema_read_advertises_and_dispatches_record_shape_preview() {
        let db = create_database(":memory:").await.unwrap();
        let server = ExecutorPrototypeStdioServer::new(registry(), db, Caller::local(), None)
            .await
            .unwrap();

        let listed = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/list",
                "params":{}
            }))
            .await
            .unwrap();
        let schema_read = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "schema_read")
            .expect("schema_read executor must be advertised");
        assert!(
            schema_read["inputSchema"]["properties"]["operation"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .any(|operation| operation == "preview_record_shape")
        );

        let preview = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                "params":{
                    "name":"schema_read",
                    "arguments":{
                        "operation":"preview_record_shape",
                        "arguments":{
                            "type":"Document",
                            "facets":{"area":"platform"}
                        },
                        "format":"json",
                        "run_key":"record-shape-preview-contract-test"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(preview["result"]["isError"], false, "{preview}");
        assert_eq!(
            preview["result"]["structuredContent"]["schema"],
            "native.record_shape_preview.v1"
        );
        assert_eq!(
            preview["result"]["structuredContent"]["advisory_only"],
            true
        );
        assert_eq!(
            preview["result"]["structuredContent"]["proposed_facets"]["status"],
            "accepted"
        );
    }

    #[test]
    fn candidate_manifest_and_read_contracts_are_stable_and_source_derived() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        assert_eq!(
            audit.candidate_surfaces.stable.ordinary.descriptors.len(),
            32
        );
        assert_eq!(
            audit.candidate_surfaces.stable.ordinary.descriptor_bytes,
            39_871
        );
        assert_eq!(
            serde_json::to_vec(&audit.candidate_surfaces.stable.ordinary.descriptors)
                .unwrap()
                .len(),
            audit.candidate_surfaces.stable.ordinary.descriptor_bytes
        );
        let BuiltContracts { contracts, .. } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        assert_eq!(
            audit.candidate_surfaces.stable.lens.descriptor_bytes,
            47_272
        );
        assert_eq!(
            serde_json::to_vec(&audit.candidate_surfaces.stable.lens.descriptors)
                .unwrap()
                .len(),
            audit.candidate_surfaces.stable.lens.descriptor_bytes
        );
        assert!(audit.candidate_surfaces.stable.ordinary.descriptor_bytes < 55_902);
        assert!(audit.candidate_surfaces.stable.lens.descriptor_bytes < 61_727);
        for operation in [
            "query_record",
            "get_record",
            "resolve_many",
            "search",
            "get_structure",
        ] {
            let contract = contracts
                .get(&("records_read".into(), operation.into()))
                .unwrap_or_else(|| panic!("missing records_read.{operation}"));
            let source = registry.get(&contract.source_tool).unwrap();
            let mut projected = source.input_schema.clone();
            strip_routing_fields(&mut projected, None, ExecutorSurface::Ordinary);
            assert_eq!(
                contract.input_schema, projected,
                "{operation} must disclose its live production ToolSpec"
            );
            assert_eq!(contract.digest.len(), 64);
        }
        let contract = contracts
            .get(&("records_read".into(), "query_record".into()))
            .unwrap();
        let mut source = super::super::tools::querying::query_record_operation_schema();
        strip_routing_fields(&mut source, None, ExecutorSurface::Ordinary);
        assert_eq!(contract.input_schema, source);
        let direct = contract.payload();
        assert_eq!(direct["prototype"]["direct_execution_enabled"], true);
        assert_eq!(direct["prototype"]["fast_path"], true);
        assert_eq!(direct["prototype"]["plan_required"], false);

        let planned = contracts
            .get(&("access_admin".into(), "manage_record_policy.replace".into()))
            .unwrap()
            .payload();
        assert_eq!(planned["prototype"]["direct_execution_enabled"], false);
        assert_eq!(planned["prototype"]["fast_path"], false);
        assert_eq!(planned["prototype"]["plan_required"], true);
    }

    #[test]
    fn create_record_contract_glosses_the_exact_closed_spine_enum() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let BuiltContracts { contracts, .. } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        let contract = contracts
            .get(&("records_write".into(), "create_record".into()))
            .expect("the authoritative create_record operation contract must exist");
        let type_schema = &contract.input_schema["properties"]["type"];

        assert_eq!(type_schema["enum"], json!(crate::schema::SPINE_TYPES));
        assert_eq!(
            crate::schema::SPINE_TYPE_GLOSSES.map(|(record_type, _)| record_type),
            crate::schema::SPINE_TYPES,
            "the gloss table must cover the exact ordered spine enum"
        );
        let description = type_schema["description"]
            .as_str()
            .expect("create_record type guidance must be visible schema prose");
        let record_types_guide = crate::mcp::GUIDE_SPECS
            .iter()
            .find(|guide| guide.topic == "record-types")
            .expect("the record-types guide must remain registered")
            .markdown;

        for (record_type, gloss) in crate::schema::SPINE_TYPE_GLOSSES {
            assert!(
                description.contains(&format!("{record_type}={gloss}")),
                "create_record must visibly gloss {record_type}: {description}"
            );
            assert!(
                record_types_guide.contains(gloss),
                "the create_record gloss for {record_type} must stay synchronized with the record-types guide"
            );
        }
    }

    #[test]
    fn manage_messages_send_contract_preserves_addressed_and_channel_branches() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let BuiltContracts { contracts, .. } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        let send = contracts
            .get(&("messaging_write".into(), "manage_messages.send".into()))
            .expect("manage_messages.send contract");
        let source = registry.get("manage_messages").unwrap();
        assert!(source.operation_schema("send").is_some());
        assert_eq!(
            source.input_schema["required"],
            json!(["action", "run_key"])
        );
        assert!(source.input_schema.get("allOf").is_none());
        let common = send.input_schema["allOf"][0]["properties"]
            .as_object()
            .expect("send common properties");
        assert_eq!(
            common.keys().map(String::as_str).collect::<HashSet<_>>(),
            HashSet::from([
                "id",
                "body",
                "preview",
                "name",
                "addressed_to",
                "origin",
                "expectation",
                "home_id",
                "owner_id",
                "links",
                "mentions",
                "idempotency_key",
                "reason",
            ])
        );
        for unrelated in [
            "message_id",
            "conversation_id",
            "view",
            "executor_route",
            "preference",
        ] {
            assert!(
                !common.contains_key(unrelated),
                "send must not disclose unrelated field {unrelated}"
            );
        }
        assert!(!common.contains_key("action"));
        assert!(send.payload()["source"]["authority"]
            .as_str()
            .unwrap()
            .contains("selector-specific operation schema"));
        let branches = send.input_schema["allOf"][1]["oneOf"]
            .as_array()
            .expect("send must disclose both delivery modes");
        assert_eq!(branches.len(), 2);

        let validator = jsonschema::validator_for(&send.input_schema).unwrap();
        assert!(validator.is_valid(&json!({
            "body":"Please decide",
            "origin":{"type":"direct","participant_ids":["person-0","person-1"]},
            "addressed_to":["person-1"],
            "expectation":"decision",
            "idempotency_key":"addressed-1",
            "reason":"Ask the responsible person"
        })));
        assert!(validator.is_valid(&json!({
            "body":"Status update",
            "origin":{"type":"collection","collection_id":"collection-1"},
            "addressed_to":[],
            "expectation":"none",
            "home_id":"collection-1",
            "idempotency_key":"channel-1",
            "reason":"Post to the project channel"
        })));
        assert!(!validator.is_valid(&json!({
            "body":"Unfiled broadcast",
            "addressed_to":[],
            "expectation":"none",
            "idempotency_key":"invalid-1",
            "reason":"Missing its channel"
        })));
        assert!(!validator.is_valid(&json!({
            "body":"Unaddressed obligation",
            "origin":{"type":"collection","collection_id":"collection-1"},
            "addressed_to":[],
            "expectation":"reply",
            "home_id":"collection-1",
            "idempotency_key":"invalid-2",
            "reason":"Nobody carries the obligation"
        })));
        for blank_field in ["body", "preview", "idempotency_key", "reason"] {
            let mut arguments = json!({
                "body":"Please decide",
                "origin":{"type":"direct","participant_ids":["person-0","person-1"]},
                "addressed_to":["person-1"],
                "expectation":"decision",
                "idempotency_key":"addressed-1",
                "reason":"Ask the responsible person"
            });
            arguments[blank_field] = json!("   ");
            assert!(
                !validator.is_valid(&arguments),
                "send must reject whitespace-only {blank_field} before dispatch"
            );
        }

        let list_inbox = contracts
            .get(&("messaging_read".into(), "manage_messages.list_inbox".into()))
            .expect("manage_messages.list_inbox contract");
        assert!(list_inbox.input_schema["properties"].get("view").is_some());
        assert!(list_inbox.input_schema.get("oneOf").is_none());
    }

    #[test]
    fn messaging_write_advertises_replies_thinly_and_send_discloses_reply_and_mention_semantics() {
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        // Disclosure boundary: the always-loaded executor description must
        // make reply-capability selection possible without hydrating reply
        // syntax, mention-offset rules, or the messaging model.
        for surface in [
            &audit.candidate_surfaces.stable.ordinary.descriptors,
            &audit.candidate_surfaces.stable.lens.descriptors,
        ] {
            let messaging = surface
                .iter()
                .find(|descriptor| descriptor["name"] == "messaging_write")
                .expect("messaging_write descriptor");
            let description = messaging["description"].as_str().unwrap();
            assert!(
                description.contains("replies"),
                "messaging_write must advertise replies: {description}"
            );
            for hydrated in [
                "reply_to",
                "span_start",
                "span_end",
                "UTF-8",
                "authored_label",
            ] {
                assert!(
                    !description.contains(hydrated),
                    "messaging_write must not inline detailed send schema ({hydrated}): {description}"
                );
            }
        }
        let registry = registry();
        let BuiltContracts { contracts, .. } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        let send = contracts
            .get(&("messaging_write".into(), "manage_messages.send".into()))
            .expect("manage_messages.send contract");
        let common = send.input_schema["allOf"][0]["properties"]
            .as_object()
            .expect("send common properties");
        // Creation-time reply_to shape and its same-origin, single-target,
        // immutability constraints must be visible on first load.
        let links = common["links"].as_object().expect("send links schema");
        let links_description = links["description"].as_str().unwrap();
        for phrase in [
            "creation-time",
            "At most one reply_to",
            "retain its target's communication origin",
            "cannot be added after creation",
            "stays unthreaded",
        ] {
            assert!(
                links_description.contains(phrase),
                "send links must disclose {phrase:?}: {links_description}"
            );
        }
        let reply_example = links["examples"][0][0].as_object().unwrap();
        assert_eq!(
            reply_example["relationship"], "reply_to",
            "send must exemplify the reply_to shape"
        );
        // Mention span units and interval semantics, same contract.
        let mentions = common["mentions"]
            .as_object()
            .expect("send mentions schema");
        let mentions_description = mentions["description"].as_str().unwrap();
        for phrase in [
            "zero-based half-open UTF-8 byte offsets",
            "character boundaries",
            "must equal authored_label",
            "must already be addressed",
        ] {
            assert!(
                mentions_description.contains(phrase),
                "send mentions must disclose {phrase:?}: {mentions_description}"
            );
        }
        // "Héllo recipient": é is two UTF-8 bytes, so "recipient" spans
        // bytes 7..16. A reply carrying that mention must validate.
        let validator = jsonschema::validator_for(&send.input_schema).unwrap();
        assert!(validator.is_valid(&json!({
            "body": "Héllo recipient",
            "origin": {"type": "direct", "participant_ids": ["person-0", "person-1"]},
            "addressed_to": ["person-1"],
            "expectation": "reply",
            "links": [{"target_id": "message-1", "relationship": "reply_to"}],
            "mentions": [{"mention_id": "mention-1", "target_kind": "principal", "target_id": "person-1", "span_start": 7, "span_end": 16, "authored_label": "recipient"}],
            "idempotency_key": "multibyte-reply-1",
            "reason": "Reply with a mention after multibyte prose"
        })));
    }

    #[test]
    fn discovery_cues_match_the_live_query_contract_and_separate_plan_phases() {
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let descriptors = &audit.candidate_surfaces.stable.ordinary.descriptors;
        let records = descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "records_read")
            .unwrap();
        assert!(records["description"]
            .as_str()
            .unwrap()
            .contains("arguments:{steps:[{step:'filter'"));
        let records_description = records["description"].as_str().unwrap();
        assert!(records_description.contains("short record reference"));
        assert!(
            records_description.contains("{operation:'get_record', arguments:{ids:[reference]}}")
        );
        assert!(records_description.contains("{operation:'search', arguments:{query:'...'}}"));
        assert!(
            records["inputSchema"]["properties"]["arguments"]["description"]
                .as_str()
                .unwrap()
                .contains("Nested operation arguments only")
        );

        let access = descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "access_admin")
            .unwrap();
        assert!(access["description"].as_str().unwrap().starts_with(
            "For plan-required operations, prepare first; preparation does not mutate"
        ));
        let validator = jsonschema::validator_for(&access["inputSchema"]).unwrap();
        let prepare = json!({
            "operation":"manage_record_policy.replace",
            "arguments":{}
        });
        let execute = json!({
            "operation":"manage_record_policy.replace",
            "plan_id":"wpl1:test",
            "target":"Record (r)",
            "effect_summary":"replace policy"
        });
        assert!(validator.is_valid(&prepare));
        assert!(validator.is_valid(&execute));
        let mut mixed = execute;
        mixed["arguments"] = json!({});
        assert!(!validator.is_valid(&mixed));

        let mut filtered_access = access.clone();
        filtered_access["inputSchema"]["properties"]["operation"]["enum"] =
            json!(["manage_record_policy.replace"]);
        let filtered = jsonschema::validator_for(&filtered_access["inputSchema"]).unwrap();
        assert!(filtered.is_valid(&json!({
            "operation":"manage_record_policy.replace",
            "plan_id":"wpl1:test",
            "target":"Record (r)",
            "effect_summary":"replace policy"
        })));
        assert!(!filtered.is_valid(&json!({
            "operation":"manage_record_policy.grant",
            "plan_id":"wpl1:test",
            "target":"Record (r)",
            "effect_summary":"grant policy"
        })));

        let records_write = descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "records_write")
            .unwrap();
        assert!(records_write["description"]
            .as_str()
            .unwrap()
            .contains("prepare first"));
        let records_write_validator =
            jsonschema::validator_for(&records_write["inputSchema"]).unwrap();
        assert!(records_write_validator.is_valid(&json!({
            "operation":"create_record",
            "arguments":{}
        })));
        assert!(records_write_validator.is_valid(&json!({
            "operation":"correct_record_type",
            "plan_id":"wpl1:test",
            "target":"Record (r)",
            "effect_summary":"correct type"
        })));
        assert!(!records_write_validator.is_valid(&json!({
            "operation":"create_record",
            "plan_id":"wpl1:test",
            "target":"Record (r)",
            "effect_summary":"create record"
        })));

        for direct_only in [
            "external_import",
            "identity_resolve",
            "artifacts_execute",
            "guidance_admin",
        ] {
            let descriptor = descriptors
                .iter()
                .find(|descriptor| descriptor["name"] == direct_only)
                .unwrap();
            assert!(descriptor["inputSchema"].get("oneOf").is_none());
            for field in ["plan_id", "target", "effect_summary"] {
                assert!(descriptor["inputSchema"]["properties"].get(field).is_none());
            }
            assert!(!descriptor["description"]
                .as_str()
                .unwrap()
                .contains("prepare first"));
        }

        for row in &audit.audit_rows {
            assert_eq!(
                row.candidate_plan_policy == "plan_required",
                write_operations::requires_plan(&row.candidate_executor, &row.candidate_operation),
                "plan classification drift for {}.{}",
                row.candidate_executor,
                row.candidate_operation
            );
        }
        assert_eq!(
            audit
                .audit_rows
                .iter()
                .filter(|row| row.candidate_plan_policy == "plan_required")
                .count(),
            34
        );
    }

    #[test]
    fn ordinary_executor_formats_are_conditional_and_inner_contracts_reject_them() {
        let registry = registry();
        let catalogue =
            build_ordinary_catalogue(&registry, super::super::registry::EngineKind::Sqlite, false)
                .unwrap();
        let descriptor = |name: &str| {
            catalogue
                .descriptors
                .iter()
                .find(|descriptor| descriptor["name"] == name)
                .unwrap()
        };

        assert_eq!(
            descriptor("bootstrap")["inputSchema"]["properties"]["format"]["enum"],
            json!(["text", "json"])
        );
        assert_eq!(
            descriptor("describe_operation")["inputSchema"]["properties"]["format"]["enum"],
            json!(["json"])
        );

        let records_write = descriptor("records_write");
        let validator = jsonschema::validator_for(&records_write["inputSchema"]).unwrap();
        assert!(validator.is_valid(&json!({
            "operation":"create_record",
            "arguments":{},
            "format":"text"
        })));
        assert!(validator.is_valid(&json!({
            "operation":"correct_record_type",
            "arguments":{},
            "format":"json"
        })));
        assert!(!validator.is_valid(&json!({
            "operation":"correct_record_type",
            "arguments":{},
            "format":"text"
        })));
        assert!(!validator.is_valid(&json!({
            "operation":"create_record",
            "arguments":{},
            "response_format":"json"
        })));

        for branch in records_write["inputSchema"]["oneOf"].as_array().unwrap() {
            assert!(
                branch["properties"].get("format").is_some(),
                "closed callable branch omitted format: {branch}"
            );
            if let Some(description) = branch
                .pointer("/properties/arguments/description")
                .and_then(Value::as_str)
            {
                assert!(description.contains("and format"), "{description}");
            }
        }

        fn assert_inner_omits_format(schema: &Value) {
            assert!(schema["properties"].get("format").is_none(), "{schema}");
            for keyword in ["oneOf", "anyOf", "allOf"] {
                if let Some(branches) = schema[keyword].as_array() {
                    for branch in branches {
                        assert_inner_omits_format(branch);
                    }
                }
            }
        }
        for contract in catalogue.contracts.values() {
            assert_inner_omits_format(&contract.input_schema);
        }

        let system = descriptor("system_read");
        let validator = jsonschema::validator_for(&system["inputSchema"]).unwrap();
        for operation in ["ping", "engine_info"] {
            assert!(validator.is_valid(&json!({
                "operation":operation,
                "arguments":{},
                "format":"json"
            })));
            assert!(!validator.is_valid(&json!({
                "operation":operation,
                "arguments":{},
                "format":"text"
            })));
        }
    }

    #[test]
    fn every_operation_contract_discloses_its_source_tool_description() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let BuiltContracts { contracts, .. } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        assert!(!contracts.is_empty());
        for ((executor, operation), contract) in &contracts {
            let payload = contract.payload();
            let disclosed = payload["source"]["tool_description"]
                .as_str()
                .unwrap_or_else(|| panic!("{executor}.{operation} discloses no tool description"));
            assert!(
                !disclosed.trim().is_empty(),
                "{executor}.{operation} discloses an empty tool description"
            );
            assert_eq!(
                disclosed,
                registry.get(&contract.source_tool).unwrap().description,
                "{executor}.{operation} must disclose the registered description verbatim"
            );
        }
    }

    #[test]
    fn executor_access_is_derived_from_registered_source_operations_and_fails_closed() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let BuiltContracts { contracts, .. } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        for (executor, operation, expected) in [
            ("guidance_read", "quickstart", OperationAccess::Mutation),
            ("records_read", "get_record", OperationAccess::Read),
            ("records_write", "create_record", OperationAccess::Mutation),
            ("records_read", "manage_links.list", OperationAccess::Read),
            (
                "records_write",
                "manage_links.add",
                OperationAccess::Mutation,
            ),
            (
                "identity_resolve",
                "resolve_external",
                OperationAccess::Mutation,
            ),
            (
                "identity_resolve",
                "observe_external",
                OperationAccess::Mutation,
            ),
            (
                "artifacts_execute",
                "render_artifact",
                OperationAccess::Read,
            ),
            (
                "artifacts_execute",
                "invoke_artifact_interaction",
                OperationAccess::Mutation,
            ),
        ] {
            let contract = contracts
                .get(&(executor.to_string(), operation.to_string()))
                .unwrap_or_else(|| panic!("missing contract for {executor}.{operation}"));
            assert_eq!(contract.access, expected, "{executor}.{operation}");
        }
        let mut unknown = contracts[&("records_read".into(), "get_record".into())].clone();
        unknown.source_tool = "future_custom_source".into();
        unknown.access = OperationAccess::Read;
        assert_eq!(
            unknown.with_registered_access(&registry).access,
            OperationAccess::Mutation
        );

        let mut materialize = contracts[&("records_read".into(), "get_record".into())].clone();
        materialize.source_tool = "materialize_record".into();
        materialize.access = OperationAccess::Read;
        assert_eq!(
            materialize.with_registered_access(&registry).access,
            OperationAccess::Mutation
        );
    }

    #[test]
    fn the_observation_contract_carries_the_warning_its_tool_registers() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let BuiltContracts { contracts, .. } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        // The regression this whole field exists for: the sentence was
        // registered, stored, and dropped one layer before the caller.
        let payload = contracts
            .get(&(
                "records_write".into(),
                "manage_facet_observations.set".into(),
            ))
            .expect("the observation set contract must exist")
            .payload();
        assert!(
            payload["source"]["tool_description"]
                .as_str()
                .unwrap()
                .contains("without changing the record's current facet value"),
            "the registered warning must reach the caller: {}",
            payload["source"]["tool_description"]
        );
        // A multi-action tool discloses whole-tool prose, so the selector must
        // stay alongside it to say which action this contract addresses.
        assert_eq!(payload["source"]["selector"]["value"], "set");
    }

    #[test]
    fn a_source_tool_without_a_description_fails_the_build() {
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let row = audit
            .audit_rows
            .iter()
            .find(|row| row.candidate_operation == "manage_facet_observations.set")
            .unwrap();
        let registry = registry();
        let schema = &registry.get(&row.legacy_tool).unwrap().input_schema;
        let err = operation_contract(schema, "   ", row, ExecutorSurface::Ordinary, None)
            .expect_err("an empty description must not silently produce a contract");
        assert!(
            err.to_string().contains("no registered description"),
            "{err}"
        );
    }

    #[test]
    fn rewording_a_description_moves_only_that_operations_digest() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let BuiltContracts { contracts, .. } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        let key = (
            "records_write".to_string(),
            "manage_facet_observations.set".to_string(),
        );
        let contract = contracts.get(&key).unwrap();
        let row = audit
            .audit_rows
            .iter()
            .find(|row| row.candidate_operation == "manage_facet_observations.set")
            .unwrap();
        let schema = &registry.get(&row.legacy_tool).unwrap().input_schema;
        let reworded = operation_contract(
            schema,
            "Set or unset one valid-time open-facet observation. Reworded.",
            row,
            ExecutorSurface::Ordinary,
            None,
        )
        .unwrap();
        // Prose drift is caught like schema drift: the digest certifies
        // everything the contract discloses, including the only part a human
        // reads.
        assert_ne!(contract.digest, reworded.digest);
        assert_eq!(contract.input_schema, reworded.input_schema);
        // And the rewording is confined to the operation whose tool was
        // reworded. Feeding another operation the reworded description proves
        // isolation rather than mere determinism: if the digest mixed in
        // anything shared across the catalogue, this would move `get_record`
        // too.
        let unrelated_row = audit
            .audit_rows
            .iter()
            .find(|row| row.candidate_operation == "get_record")
            .unwrap();
        let unrelated = contracts
            .get(&("records_read".into(), "get_record".into()))
            .unwrap();
        let unrelated_source = registry.get(&unrelated.source_tool).unwrap();
        assert_ne!(
            unrelated.source_tool, contract.source_tool,
            "the isolation check needs two genuinely different source tools"
        );
        let rebuilt = operation_contract(
            &unrelated_source.input_schema,
            &unrelated_source.description,
            unrelated_row,
            ExecutorSurface::Ordinary,
            unrelated_source.operation_schema(&unrelated_row.legacy_action),
        )
        .unwrap();
        assert_eq!(unrelated.digest, rebuilt.digest);
        let unrelated_reworded = operation_contract(
            &unrelated_source.input_schema,
            "Reworded.",
            unrelated_row,
            ExecutorSurface::Ordinary,
            unrelated_source.operation_schema(&unrelated_row.legacy_action),
        )
        .unwrap();
        assert_ne!(
            unrelated.digest, unrelated_reworded.digest,
            "every operation's digest must track its own description"
        );
    }

    #[test]
    fn selector_projection_and_translation_are_inverse_at_the_routing_boundary() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let BuiltContracts { contracts, .. } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        let contract = contracts
            .get(&("access_admin".into(), "manage_record_policy.replace".into()))
            .unwrap();
        assert!(contract.input_schema["properties"].get("action").is_none());
        assert!(contract.input_schema["properties"].get("run_key").is_none());
        assert_eq!(
            contract.input_schema["required"],
            json!(["record_id", "entries", "if_policy_revision", "reason"])
        );
        let translated = translate_arguments(
            contract,
            &json!({
                "operation":"manage_record_policy.replace",
                "arguments": {
                    "record_id":"abc",
                    "entries":[],
                    "if_policy_revision":"rev",
                    "reason":"fixture"
                },
                "run_key":"contract-test-a748b2"
            }),
        )
        .unwrap();
        assert_eq!(translated["action"], "replace");
        assert_eq!(translated["run_key"], "contract-test-a748b2");
    }

    #[test]
    fn every_registered_stable_selector_round_trips_on_the_ordinary_surface() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        for surface in [ExecutorSurface::Ordinary] {
            let BuiltContracts {
                contracts,
                operations_by_executor: operations,
            } = build_contracts(
                &registry,
                super::super::registry::EngineKind::Sqlite,
                &audit.audit_rows,
                surface,
            )
            .unwrap();
            for row in audit.audit_rows.iter().filter(|row| {
                row.stability == "stable"
                    && row
                        .availability
                        .iter()
                        .any(|available| available == surface.as_str())
                    && registry.get(&row.legacy_tool).is_some()
            }) {
                let key = (
                    row.candidate_executor.clone(),
                    row.candidate_operation.clone(),
                );
                let source = registry.get(&row.legacy_tool).unwrap();
                let contract = operation_contract(
                    &source.input_schema,
                    &source.description,
                    row,
                    surface,
                    source.operation_schema(&row.legacy_action),
                )
                .unwrap();
                assert_eq!(contract.source_tool, row.legacy_tool);
                let translated = translate_arguments(
                    &contract,
                    &json!({
                        "operation":row.candidate_operation,
                        "arguments":{},
                        "run_key":"selector-round-trip-a748b2",
                        "parent_key":"selector-parent-a748b2",
                    }),
                )
                .unwrap();
                if row.legacy_action == "call" {
                    assert!(contract.selector.is_none());
                } else {
                    let selector = contract.selector.as_ref().unwrap();
                    assert_eq!(selector.value, row.legacy_action);
                    assert_eq!(translated[&selector.field], row.legacy_action);
                    assert!(contract.input_schema["properties"]
                        .get(&selector.field)
                        .is_none());
                }
                assert_eq!(translated["run_key"], "selector-round-trip-a748b2");
                assert_eq!(translated["parent_key"], "selector-parent-a748b2");
                if operation_has_execution_path(
                    surface,
                    &row.candidate_executor,
                    &row.candidate_operation,
                ) {
                    assert_eq!(contracts.get(&key).unwrap().digest, contract.digest);
                    assert!(operations[&row.candidate_executor].contains(&row.candidate_operation));
                } else {
                    assert!(!contracts.contains_key(&key));
                    assert!(!operations
                        .get(&row.candidate_executor)
                        .is_some_and(|available| available.contains(&row.candidate_operation)));
                }
            }
        }
    }

    #[test]
    fn advertised_operations_equal_executable_contracts_and_omit_absent_capabilities() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let BuiltContracts {
            contracts,
            operations_by_executor: operations,
        } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        let descriptors = executable_descriptors(
            audit.candidate_surfaces.stable.ordinary.descriptors,
            &operations,
        )
        .unwrap();

        let advertised = descriptors
            .iter()
            .filter(|descriptor| {
                !matches!(
                    descriptor["name"].as_str(),
                    Some("bootstrap" | "describe_operation")
                )
            })
            .flat_map(|descriptor| {
                let executor = descriptor["name"].as_str().unwrap();
                descriptor["inputSchema"]["properties"]["operation"]["enum"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(move |operation| {
                        (
                            executor.to_string(),
                            operation.as_str().unwrap().to_string(),
                        )
                    })
            })
            .collect::<HashSet<_>>();
        let executable = contracts
            .keys()
            .filter(|(executor, _)| executor != "bootstrap")
            .cloned()
            .collect::<HashSet<_>>();
        assert_eq!(advertised, executable);
        assert!(!descriptors.iter().any(|descriptor| matches!(
            descriptor["name"].as_str(),
            Some("membership_read" | "membership_admin" | "membership_remove" | "export")
        )));
        assert!(descriptors
            .iter()
            .any(|descriptor| descriptor["name"] == "records_delete"));
        for executor in ["schema_admin", "schema_delete"] {
            assert!(descriptors
                .iter()
                .any(|descriptor| descriptor["name"] == executor));
        }
        let access_operations = descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "access_admin")
            .unwrap()["inputSchema"]["properties"]["operation"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(
            access_operations,
            &[
                json!("manage_artifact_module_grants.grant"),
                json!("manage_artifact_module_grants.revoke"),
                json!("manage_record_policy.grant"),
                json!("manage_record_policy.replace"),
                json!("manage_record_policy.restore_inheritance"),
                json!("manage_record_policy.revoke"),
                json!("manage_record_policy.set_many"),
                json!("manage_record_policy.set_members_baseline"),
            ],
            "only access mutations with truthful preparers may be selected"
        );
        let identity_operations = descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "identity_admin")
            .unwrap()["inputSchema"]["properties"]["operation"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(
            identity_operations,
            &[
                json!("manage_bindings.add"),
                json!("manage_bindings.canonicalize"),
                json!("manage_bindings.reconcile"),
                json!("manage_bindings.remove"),
            ],
            "only identity mutations with truthful preparers may be selected"
        );
        let schema_admin_operations = descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "schema_admin")
            .unwrap()["inputSchema"]["properties"]["operation"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(
            schema_admin_operations,
            &[
                json!("manage_schema_config.write"),
                json!("manage_vocabularies.alias_value"),
                json!("manage_vocabularies.create_vocabulary"),
                json!("manage_vocabularies.deprecate_value"),
                json!("manage_vocabularies.promote_value"),
                json!("manage_vocabularies.propose_value"),
                json!("manage_vocabularies.reorder_value"),
                json!("manage_vocabularies.set_gloss"),
                json!("manage_vocabularies.set_metadata"),
            ],
        );
        let schema_delete_operations = descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "schema_delete")
            .unwrap()["inputSchema"]["properties"]["operation"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(
            schema_delete_operations,
            &[
                json!("manage_vocabularies.delete_value"),
                json!("manage_vocabularies.delete_vocabulary"),
            ],
        );

        let records_write = descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "records_write")
            .unwrap();
        let records_write_branches = records_write["inputSchema"]["oneOf"].as_array().unwrap();
        let prepare = records_write_branches
            .iter()
            .find(|branch| branch["title"] == "Prepare or direct")
            .unwrap();
        let prepare_operations = prepare["properties"]["operation"]["enum"]
            .as_array()
            .unwrap();
        assert!(prepare_operations.contains(&json!("create_record")));
        assert!(prepare["properties"].get("arguments").is_some());
        assert!(prepare["required"]
            .as_array()
            .unwrap()
            .contains(&json!("operation")));
        let execute = records_write_branches
            .iter()
            .find(|branch| branch["title"] == "Execute prepared plan")
            .unwrap();
        assert_eq!(
            execute["properties"]["operation"]["enum"],
            json!(["correct_record_type"])
        );
        for property in ["plan_id", "target", "effect_summary"] {
            assert!(execute["properties"].get(property).is_some());
        }

        fn operation_occurrences(schema: &Value, occurrences: &mut Vec<Vec<String>>) {
            match schema {
                Value::Object(object) => {
                    if let Some(operation) = object
                        .get("properties")
                        .and_then(Value::as_object)
                        .and_then(|properties| properties.get("operation"))
                    {
                        if let Some(values) = operation.get("enum").and_then(Value::as_array) {
                            occurrences.push(
                                values
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .map(str::to_string)
                                    .collect(),
                            );
                        }
                        if let Some(value) = operation.get("const").and_then(Value::as_str) {
                            occurrences.push(vec![value.to_string()]);
                        }
                    }
                    for value in object.values() {
                        operation_occurrences(value, occurrences);
                    }
                }
                Value::Array(values) => {
                    for value in values {
                        operation_occurrences(value, occurrences);
                    }
                }
                _ => {}
            }
        }

        for descriptor in descriptors.iter().filter(|descriptor| {
            !matches!(
                descriptor["name"].as_str(),
                Some("bootstrap" | "describe_operation")
            )
        }) {
            let executor = descriptor["name"].as_str().unwrap();
            let executable = operations[executor]
                .iter()
                .map(String::as_str)
                .collect::<HashSet<_>>();
            let mut occurrences = Vec::new();
            operation_occurrences(&descriptor["inputSchema"], &mut occurrences);
            assert!(
                !occurrences.is_empty(),
                "{executor} has no operation constraint"
            );
            for occurrence in &occurrences {
                assert!(
                    !occurrence.is_empty(),
                    "{executor} has an empty operation enum"
                );
                assert!(
                    occurrence
                        .iter()
                        .all(|operation| executable.contains(operation.as_str())),
                    "{executor} descriptor exposes a non-executable operation: {occurrence:?}"
                );
            }
            if executor == "access_admin" || executor == "identity_admin" {
                assert!(
                    occurrences.len() >= 2,
                    "{executor} must constrain both the envelope and execute-plan branch"
                );
                assert!(occurrences.iter().all(|occurrence| {
                    occurrence
                        .iter()
                        .all(|operation| executable.contains(operation.as_str()))
                }));
            }
        }
    }

    #[test]
    fn nested_operation_constraints_are_filtered_without_flattening_one_of() {
        let mut schema = json!({
            "type":"object",
            "properties":{"operation":{"enum":["available","withheld"]}},
            "oneOf":[
                {"properties":{"operation":{"const":"available"}}},
                {"properties":{"operation":{"const":"withheld"}}},
                {"properties":{"operation":{"enum":["available","withheld"]}}}
            ]
        });
        filter_operation_constraints(&mut schema, &HashSet::from(["available"]));

        assert_eq!(schema["oneOf"].as_array().unwrap().len(), 3);
        assert_eq!(
            schema["properties"]["operation"]["enum"],
            json!(["available"])
        );
        assert_eq!(
            schema["oneOf"][0]["properties"]["operation"]["const"],
            json!("available")
        );
        assert_eq!(
            schema["oneOf"][1]["properties"]["operation"]["enum"],
            json!([])
        );
        assert_eq!(
            schema["oneOf"][2]["properties"]["operation"]["enum"],
            json!(["available"])
        );
        assert!(!schema.to_string().contains("withheld"));
    }

    #[test]
    fn backend_operation_evidence_filters_sqlite_postgres_and_schema_only_routes() {
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();

        let sqlite = registry();
        let BuiltContracts {
            contracts: sqlite_contracts,
            ..
        } = build_contracts(
            &sqlite,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        assert!(sqlite_contracts.contains_key(&("records_write".into(), "manage_links.add".into())));
        assert!(
            sqlite_contracts.contains_key(&("records_write".into(), "manage_links.remove".into()))
        );
        assert!(
            sqlite_contracts.contains_key(&("records_write".into(), "correct_record_type".into()))
        );
        assert!(sqlite_contracts.contains_key(&("records_read".into(), "manage_links.list".into())));
        for operation in [
            "delete_record",
            "manage_attachments.detach",
            "manage_citations.remove",
        ] {
            assert!(sqlite_contracts.contains_key(&("records_delete".into(), operation.into())));
        }

        let mut schema_only = ToolRegistry::new();
        register_builtin_tools(&mut schema_only).unwrap();
        register_surface_tools(&mut schema_only).unwrap();
        schema_only
            .register(
                super::super::ToolKind::ManageMemberships,
                "schema-only hosted membership fixture",
                json!({
                    "type":"object",
                    "required":["action"],
                    "properties":{
                        "action":{"enum":[
                            "list",
                            "invitations_list",
                            "invitations_inspect",
                            "invitations_create",
                            "invitations_copy_link",
                            "invitations_send",
                            "invitations_revoke",
                            "set_role",
                            "remove"
                        ]}
                    },
                    "additionalProperties":true
                }),
                |_db, _caller, _arguments| async {
                    Err::<Value, _>(Error::engine(
                        "schema-only membership fixture cannot be dispatched",
                    ))
                },
            )
            .unwrap();
        schema_only
            .mark_engine_operations_unavailable(
                super::super::ToolKind::ManageMemberships.name(),
                super::super::registry::EngineKind::Sqlite,
            )
            .unwrap();
        let BuiltContracts {
            contracts: schema_contracts,
            ..
        } = build_contracts(
            &schema_only,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        assert!(!schema_contracts
            .contains_key(&("membership_read".into(), "manage_memberships.list".into())));

        #[cfg(feature = "postgres")]
        {
            let mut postgres = ToolRegistry::new();
            register_builtin_tools(&mut postgres).unwrap();
            register_surface_tools(&mut postgres).unwrap();
            crate::postgres::register_postgres_tools(&mut postgres).unwrap();
            let BuiltContracts {
                contracts: postgres_contracts,
                ..
            } = build_contracts(
                &postgres,
                super::super::registry::EngineKind::Postgres,
                &audit.audit_rows,
                ExecutorSurface::Ordinary,
            )
            .unwrap();
            assert!(postgres_contracts
                .contains_key(&("records_write".into(), "manage_links.add".into())));
            assert!(postgres_contracts
                .contains_key(&("records_read".into(), "manage_links.list".into())));
            assert!(!postgres_contracts
                .contains_key(&("records_write".into(), "manage_links.remove".into())));
            assert!(!postgres_contracts
                .contains_key(&("records_delete".into(), "manage_attachments.detach".into())));
            assert!(!postgres_contracts
                .contains_key(&("records_delete".into(), "delete_record".into())));
            assert!(!postgres_contracts
                .contains_key(&("records_delete".into(), "manage_citations.remove".into())));
        }

        #[cfg(feature = "turso-local")]
        {
            let mut turso = ToolRegistry::new();
            register_builtin_tools(&mut turso).unwrap();
            register_surface_tools(&mut turso).unwrap();
            crate::turso_local::register_turso_local_tools(&mut turso).unwrap();
            let BuiltContracts {
                contracts: turso_contracts,
                ..
            } = build_contracts(
                &turso,
                super::super::registry::EngineKind::TursoLocal,
                &audit.audit_rows,
                ExecutorSurface::Ordinary,
            )
            .unwrap();
            assert!(!turso_contracts
                .contains_key(&("records_delete".into(), "manage_attachments.detach".into())));
            assert!(
                !turso_contracts.contains_key(&("records_delete".into(), "delete_record".into()))
            );
            assert!(!turso_contracts
                .contains_key(&("records_delete".into(), "manage_citations.remove".into())));
        }
    }

    #[test]
    fn lens_catalogue_uses_lens_schemas_and_routes_materialization() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let policy =
            super::super::ResolvedToolExposure::new(super::super::ExposureProfile::Complete);
        let sources = lens_descriptor_projection_for_policy(&registry, &policy).unwrap();
        let BuiltContracts {
            contracts,
            operations_by_executor: operations,
        } = build_lens_contracts(&registry, &sources, &audit.audit_rows).unwrap();
        let lens_send = contracts
            .get(&("messaging_write".into(), "manage_messages.send".into()))
            .expect("lens manage_messages.send contract");
        assert!(lens_send.selector_specific_schema);
        assert_eq!(
            lens_send.input_schema["allOf"][1]["oneOf"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let schemas = sources
            .iter()
            .map(|tool| {
                (
                    tool.name.as_str(),
                    tool.descriptor.get("inputSchema").unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();
        let descriptions = sources
            .iter()
            .map(|tool| {
                (
                    tool.name.as_str(),
                    tool.descriptor
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap(),
                )
            })
            .collect::<HashMap<_, _>>();
        for row in audit.audit_rows.iter().filter(|row| {
            row.stability == "stable"
                && row.availability.iter().any(|available| available == "lens")
                && schemas.contains_key(row.legacy_tool.as_str())
        }) {
            let contract = operation_contract(
                schemas[row.legacy_tool.as_str()],
                descriptions[row.legacy_tool.as_str()],
                row,
                ExecutorSurface::Lens,
                registry
                    .get(&row.legacy_tool)
                    .and_then(|source| source.operation_schema(&row.legacy_action)),
            )
            .unwrap();
            let translated = translate_arguments(
                &contract,
                &json!({
                    "operation":row.candidate_operation,
                    "arguments":{},
                    "destination_db_id":"destination",
                    "cursor":"cursor",
                    "page_size":7,
                }),
            )
            .unwrap();
            if row.legacy_action == "call" {
                assert!(contract.selector.is_none());
            } else {
                let selector = contract.selector.as_ref().unwrap();
                assert_eq!(translated[&selector.field], row.legacy_action);
            }
            assert_eq!(translated["destination_db_id"], "destination");
            assert_eq!(translated["cursor"], "cursor");
            assert_eq!(translated["page_size"], 7);
        }

        let materialize = contracts
            .get(&("identity_resolve".into(), "materialize_record".into()))
            .expect("lens-local materialization must remain executable");
        assert_eq!(materialize.surface, ExecutorSurface::Lens);
        assert!(materialize.input_schema["properties"]
            .get("destination_db_id")
            .is_none());
        let translated = translate_arguments(
            materialize,
            &json!({
                "operation":"materialize_record",
                "arguments":{
                    "source_ref":{"db_id":"source","record_id":"record"},
                    "reason":"Capture a governed shadow."
                },
                "destination_db_id":"destination",
                "run_key":"lens-materialize-a748b2"
            }),
        )
        .unwrap();
        assert_eq!(translated["destination_db_id"], "destination");
        assert_eq!(translated["run_key"], "lens-materialize-a748b2");

        let descriptors = executable_descriptors(
            audit.candidate_surfaces.stable.lens.descriptors,
            &operations,
        )
        .unwrap();
        let identity_resolve = descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "identity_resolve")
            .unwrap();
        assert!(
            identity_resolve["inputSchema"]["properties"]["operation"]["enum"]
                .as_array()
                .unwrap()
                .contains(&json!("materialize_record"))
        );

        let mut restricted =
            super::super::ResolvedToolExposure::new(super::super::ExposureProfile::Complete);
        restricted.tool_overrides.insert(
            "materialize_record".into(),
            super::super::VisibilityOverride::Hide,
        );
        let restricted_sources =
            lens_descriptor_projection_for_policy(&registry, &restricted).unwrap();
        let BuiltContracts {
            contracts: restricted_contracts,
            ..
        } = build_lens_contracts(&registry, &restricted_sources, &audit.audit_rows).unwrap();
        assert!(!restricted_contracts
            .contains_key(&("identity_resolve".into(), "materialize_record".into())));
    }

    #[test]
    fn query_parser_and_disclosed_schema_reject_the_same_basic_drift_cases() {
        let schema = super::super::tools::querying::query_record_operation_schema();
        let validator = jsonschema::validator_for(&schema).unwrap();
        let valid = json!({"steps":[{"step":"filter","types":["task"]}],"limit":10});
        assert!(validator.is_valid(&valid));
        super::super::tools::querying::validate_query_record_operation(valid).unwrap();
        for invalid in [
            json!({}),
            json!({"steps":"not-an-array"}),
            json!({"steps":[{"step":"filter"}],"hallucinated":true}),
            json!({"steps":[{"step":"filter"}],"limit":0}),
        ] {
            assert!(!validator.is_valid(&invalid));
            assert!(
                super::super::tools::querying::validate_query_record_operation(invalid).is_err()
            );
        }
        let grammar_invalid = json!({"steps":[{"step":"traverse","target":"children"}]});
        assert!(
            validator.is_valid(&grammar_invalid),
            "the grammar seam, rather than structural JSON Schema, owns the non-empty pipeline rule"
        );
        assert!(
            super::super::tools::querying::validate_query_record_operation(grammar_invalid)
                .is_err()
        );
    }

    #[tokio::test]
    async fn fixture_exposes_direct_describe_and_exact_repair_paths() {
        let db = create_database(":memory:").await.unwrap();
        let telemetry_sink = Arc::new(telemetry::TestTelemetrySink::default());
        let telemetry = ExecutorTelemetryContext::new(
            telemetry_sink.clone(),
            telemetry::DEFAULT_RETENTION_DAYS,
        )
        .unwrap();
        let server = ExecutorPrototypeStdioServer::new_with_telemetry(
            registry(),
            db.clone(),
            Caller::local(),
            None,
            telemetry.clone(),
        )
        .await
        .unwrap();
        // The delivery worker is asynchronous. Establish the startup events
        // before arming the injected sink failure so coverage instrumentation
        // cannot race that failure against session_started/manifest_loaded.
        telemetry.flush().unwrap();
        telemetry_sink.fail_next(1);
        let list = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/list",
                "params":{}
            }))
            .await
            .unwrap();
        let tools = list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), server.operations_by_executor.len() + 1);
        assert!(tools.len() < 30, "unavailable executors must be omitted");
        assert!(tools.iter().any(|tool| tool["name"] == "records_read"));
        assert!(!tools.iter().any(|tool| tool["name"] == "query_record"));

        let describe = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                "params":{
                    "name":"describe_operation",
                    "arguments":{
                        "executor":"records_read",
                        "operation":"query_record",
                        "run_key":"contract-fixture-a748b2"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(describe["result"]["isError"], false);
        let described_digest = describe["result"]["structuredContent"]["contract_digest"]
            .as_str()
            .unwrap()
            .to_string();

        let guided = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":3,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":"query_record",
                        "arguments":{"steps":[{"step":"filter"}],"limit":1},
                        "run_key":"contract-fixture-a748b2"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(guided["result"]["isError"], false, "{guided}");

        let mut localised_seen = 0_u32;
        let mut fallback_seen = 0_u32;
        for (id, run_key, invalid_arguments) in [
            (4, "read-missing-a748b2", json!({})),
            (
                5,
                "read-hallucinated-a748b2",
                json!({"steps":[{"step":"filter"}],"hallucinated":true}),
            ),
            (6, "read-wrong-type-a748b2", json!({"steps":"not-an-array"})),
            (
                7,
                "read-grammar-a748b2",
                json!({"steps":[{"step":"traverse","target":"children"}]}),
            ),
            (
                72,
                "read-array-wrapper-a748b2",
                json!({"steps":{"step":"filter","types":["task"]}}),
            ),
        ] {
            let invalid = server
                .handle_message(json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "method":"tools/call",
                    "params":{
                        "name":"records_read",
                        "arguments":{
                            "operation":"query_record",
                            "arguments":invalid_arguments,
                            "run_key":run_key
                        }
                    }
                }))
                .await
                .unwrap();
            assert_eq!(invalid["result"]["isError"], true, "{invalid}");
            let repair = &invalid["result"]["structuredContent"]["repair"];
            assert_eq!(repair["code"], "operation_contract_repair");
            assert!(repair["reason_code"].as_str().is_some());
            assert!(repair["failing_pointer"]
                .as_str()
                .is_some_and(|pointer| pointer.starts_with("/arguments")));
            assert!(repair["expected_shape"].is_object());
            assert_eq!(repair["contract_digest"], described_digest);
            assert!(repair["diagnostic"]
                .as_str()
                .is_some_and(|text| !text.is_empty()));
            // A localised failure names the failing keyword and carries the
            // exact failing subschema, so the repair cites `describe_operation`
            // instead of echoing the whole contract. A failure the validator
            // could not localise still travels with the full document.
            if repair["expected_shape"]["keyword"].as_str().is_some() {
                localised_seen += 1;
                assert!(
                    !repair["expected_shape"]["constraint"].is_null(),
                    "a localised repair must carry the failing subschema: {repair}"
                );
                assert!(
                    repair.get("input_schema").is_none(),
                    "a localised repair must not echo the full contract: {repair}"
                );
                if repair["expected_shape"]["keyword"] == "additionalProperties" {
                    assert!(
                        repair["expected_shape"]["accepted_properties"]
                            .as_array()
                            .is_some_and(|names| !names.is_empty()),
                        "a rejected property name must be answered with the names that would have been accepted: {repair}"
                    );
                }
                let reference = &repair["contract_reference"];
                assert_eq!(reference["tool"], "describe_operation");
                assert_eq!(
                    reference["arguments"],
                    json!({"executor":"records_read","operation":"query_record"})
                );
                assert_eq!(
                    reference["input_schema_pointer"],
                    "/result/structuredContent/input_schema"
                );
                assert_eq!(
                    describe.pointer(reference["input_schema_pointer"].as_str().unwrap()),
                    Some(&describe["result"]["structuredContent"]["input_schema"]),
                    "the cited pointer must resolve against a describe_operation response"
                );
            } else {
                fallback_seen += 1;
                assert!(
                    repair.get("contract_reference").is_none(),
                    "a non-localised repair keeps the contract inline: {repair}"
                );
                assert_eq!(
                    repair["input_schema"],
                    describe["result"]["structuredContent"]["input_schema"]
                );
            }
            assert_eq!(repair["preserved_intent"]["run_key"], run_key);
            let retry_ready = id == 72;
            assert_eq!(repair["retry_ready"], retry_ready, "{repair}");
            if retry_ready {
                assert_eq!(repair["retry"]["tool"], "records_read");
                assert_eq!(repair["retry"]["arguments"], repair["corrected_envelope"]);
                assert_ne!(repair["corrected_envelope"], repair["preserved_intent"]);
                let callable_schema = tools
                    .iter()
                    .find(|tool| tool["name"] == "records_read")
                    .unwrap()["inputSchema"]
                    .clone();
                let callable_validator = jsonschema::validator_for(&callable_schema).unwrap();
                assert!(
                    callable_validator.is_valid(&repair["corrected_envelope"]),
                    "repair must emit an envelope accepted by tools/list: {repair}"
                );
                let corrected = repair["corrected_envelope"]["arguments"].clone();
                let validator = jsonschema::validator_for(
                    &describe["result"]["structuredContent"]["input_schema"],
                )
                .unwrap();
                assert!(validator.is_valid(&corrected), "{repair}");
                super::super::tools::querying::validate_query_record_operation(corrected).unwrap();
            } else {
                assert!(repair["corrected_envelope"].is_null());
                assert!(repair["retry"].is_null());
            }
        }
        assert!(
            localised_seen > 0 && fallback_seen > 0,
            "both repair shapes must stay covered: localised={localised_seen} fallback={fallback_seen}"
        );

        // A misspelled field has to be correctable from the repair alone. The
        // observed failure is `get_record` carrying `record_id` where the
        // contract wants `ids`. The repair omits the contract for this class,
        // so its accepted-name list is the caller's only route to the right
        // spelling; `additionalProperties: false` on its own would not be one.
        let misspelled = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":73,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":"get_record",
                        "arguments":{"record_id":"read-fixture-a748b2"},
                        "run_key":"read-misspelled-a748b2"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(misspelled["result"]["isError"], true, "{misspelled}");
        let misspelled = &misspelled["result"]["structuredContent"]["repair"];
        assert_eq!(
            misspelled["reason_code"], "unexpected_field",
            "{misspelled}"
        );
        assert_eq!(
            misspelled["failing_pointer"], "/arguments/record_id",
            "{misspelled}"
        );
        assert_eq!(
            misspelled["expected_shape"]["keyword"], "additionalProperties",
            "{misspelled}"
        );
        assert!(misspelled.get("input_schema").is_none(), "{misspelled}");
        let accepted = misspelled["expected_shape"]["accepted_properties"]
            .as_array()
            .expect("the rejected name must be answered with the accepted names")
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>();
        assert!(
            accepted.contains(&"ids"),
            "the caller must be able to recover the correct spelling without describe_operation: {misspelled}"
        );
        assert!(!accepted.contains(&"record_id"), "{misspelled}");
        assert!(
            misspelled["expected_shape"]["required_properties"].is_array(),
            "{misspelled}"
        );
        // The disclosure stays cheap: names only, never their subschemas.
        assert!(
            misspelled["expected_shape"]["accepted_properties"]
                .as_array()
                .unwrap()
                .iter()
                .all(Value::is_string),
            "{misspelled}"
        );

        let routing_confusion = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":71,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":"query_record",
                        "steps":[{"step":"filter","types":["task"]}],
                        "limit":10,
                        "run_key":"read-routing-a748b2"
                    }
                }
            }))
            .await
            .unwrap();
        let repair = &routing_confusion["result"]["structuredContent"]["repair"];
        assert_eq!(repair["failing_pointer"], "/arguments/steps");
        assert_eq!(repair["retry_ready"], true);
        assert_ne!(repair["corrected_envelope"], repair["preserved_intent"]);
        assert_eq!(
            repair["corrected_envelope"]["arguments"]["steps"][0]["types"],
            json!(["task"])
        );
        assert_eq!(repair["corrected_envelope"]["arguments"]["limit"], 10);
        assert!(repair["corrected_envelope"].get("steps").is_none());

        let valid = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":8,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":"query_record",
                        "arguments":{
                            "steps":[{"step":"filter"}],
                            "limit":1
                        },
                        "run_key":"read-grammar-a748b2"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(valid["result"]["isError"], false, "{valid}");
        let source_calls: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls WHERE tool='query_record'")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(
            source_calls, 2,
            "each of the two successful facade calls must dispatch the source tool once"
        );
        let events = server.trace_events();
        assert!(events.iter().any(|event| event["kind"] == "contract_load"));
        assert!(events
            .iter()
            .any(|event| event["kind"] == "validation_failure"));
        assert!(events.iter().any(|event| {
            event["kind"] == "operation_selection"
                && event["mode"] == "repair_retry"
                && event["repair_of"].is_string()
        }));
        assert!(events.iter().any(|event| {
            event["kind"] == "operation_selection"
                && event["mode"] == "guided"
                && event["run_key"] == "contract-fixture-a748b2"
        }));
        telemetry.flush().unwrap();
        let emitted = telemetry_sink
            .events()
            .into_iter()
            .map(|event| serde_json::from_slice::<Value>(&event).unwrap())
            .collect::<Vec<_>>();
        for phase in [
            "session_started",
            "manifest_loaded",
            "operation_selected",
            "contract_loaded",
            "validation_completed",
            "repair_returned",
            "dispatch_begun",
            "dispatch_completed",
            "telemetry_dropped",
        ] {
            assert!(
                emitted.iter().any(|event| event["phase"] == phase),
                "missing normalized telemetry phase {phase}: {emitted:?}"
            );
        }
        assert!(emitted.iter().any(|event| {
            event["phase"] == "validation_completed"
                && event["outcome"] == "rejected"
                && event["error_class"] == "schema_validation"
        }));
        assert!(emitted.iter().any(|event| {
            event["phase"] == "dispatch_completed"
                && event["flags"]["repair_retry"] == true
                && event["counts"]["dispatch_count_bucket"] == "1"
        }));
        assert_eq!(telemetry.health().dropped_event_count, 1);
        let serialized = serde_json::to_string(&emitted).unwrap();
        for raw in [
            "contract-fixture-a748b2",
            "read-grammar-a748b2",
            "read-routing-a748b2",
        ] {
            assert!(!serialized.contains(raw), "telemetry leaked {raw}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn ordinary_stateful_source_failure_is_diagnostic_and_never_retry_ready() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let envelope = json!({
            "operation":"update_record",
            "arguments":{
                "id":"missing-stateful-record",
                "reason":"Exercise authoritative missing-state rejection",
                "name":"Never applied"
            },
            "run_key":"stateful-source-failure-a748b2"
        });
        let response = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":80,
                "method":"tools/call",
                "params":{"name":"records_write","arguments":envelope}
            }))
            .await
            .unwrap();

        assert_eq!(response["result"]["isError"], true, "{response}");
        let source_error = response["result"]["structuredContent"]["error"]
            .as_str()
            .unwrap();
        assert!(source_error.contains("missing-stateful-record"));
        assert!(response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with(source_error));
        let diagnostic = &response["result"]["structuredContent"]["repair"];
        assert_eq!(diagnostic["code"], "operation_execution_diagnostic");
        assert_eq!(diagnostic["reason_code"], "authoritative_source_rejected");
        assert_eq!(diagnostic["diagnostic"], source_error);
        assert_eq!(diagnostic["retry_ready"], false);
        assert!(diagnostic["corrected_envelope"].is_null());
        assert!(diagnostic["retry"].is_null());
        assert_eq!(
            diagnostic["guidance"]["action"],
            "inspect_authoritative_source_error"
        );
        assert_eq!(diagnostic["guidance"]["automatic_retry"], false);
        db.close().await;
    }

    /// The guard refusals must never travel as contract repairs. Synthesising
    /// `if_body_digest` from current state would hand the caller a token it
    /// never read and silently reproduce the lost update the guard exists to
    /// prevent, so both codes stay ordinary execution diagnostics with a null
    /// `corrected_envelope`.
    #[tokio::test]
    async fn guarded_body_refusals_are_diagnostic_and_never_synthesise_a_token() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let call = |arguments: Value, id: i64| {
            let server = &server;
            async move {
                server
                    .handle_message(json!({
                        "jsonrpc":"2.0",
                        "id":id,
                        "method":"tools/call",
                        "params":{"name":"records_write","arguments":arguments}
                    }))
                    .await
                    .unwrap()
            }
        };
        call(
            json!({
                "operation":"create_record",
                "arguments":{
                    "id":"guarded:refusal",
                    "type":"Document",
                    "kind":"note",
                    "name":"Guarded refusal",
                    "body":"the body a concurrent editor is holding",
                    "reason":"Establish guarded body state"
                },
                "run_key":"guarded-refusal-3f81aa"
            }),
            90,
        )
        .await;

        for (id, arguments) in [
            (
                91,
                json!({
                    "id":"guarded:refusal",
                    "body":"must not land",
                    "reason":"Attempt an unguarded whole-body replacement"
                }),
            ),
            (
                92,
                json!({
                    "id":"guarded:refusal",
                    "body":"must not land",
                    "if_body_digest":"0".repeat(64),
                    "reason":"Attempt a stale guarded replacement"
                }),
            ),
        ] {
            let envelope = json!({
                "operation":"update_record",
                "arguments":arguments,
                "run_key":"guarded-refusal-3f81aa"
            });
            let response = call(envelope.clone(), id).await;
            assert_eq!(response["result"]["isError"], true, "{response}");
            let repair = &response["result"]["structuredContent"]["repair"];
            assert_eq!(repair["code"], "operation_execution_diagnostic", "{repair}");
            assert_eq!(repair["reason_code"], "authoritative_source_rejected");
            assert_eq!(repair["retry_ready"], false, "{repair}");
            assert!(repair["corrected_envelope"].is_null(), "{repair}");
            assert!(repair["retry"].is_null(), "{repair}");
            assert_eq!(repair["preserved_intent"], envelope);
            let error = response["result"]["structuredContent"]["error"]
                .as_str()
                .unwrap();
            assert!(
                !error.contains(&hex::encode(Sha256::digest(b"must not land"))),
                "the refusal never echoes a token for a body the caller did not read: {error}"
            );
        }
        db.close().await;
    }

    #[test]
    fn lens_stateful_source_failure_keeps_authoritative_error_and_no_retry() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let policy =
            super::super::ResolvedToolExposure::new(super::super::ExposureProfile::Complete);
        let sources = lens_descriptor_projection_for_policy(&registry, &policy).unwrap();
        let BuiltContracts { contracts, .. } =
            build_lens_contracts(&registry, &sources, &audit.audit_rows).unwrap();
        let contract = contracts
            .get(&("records_write".into(), "update_record".into()))
            .unwrap();
        assert_eq!(contract.surface, ExecutorSurface::Lens);
        let envelope = json!({
            "operation":"update_record",
            "arguments":{
                "id":"missing-lens-stateful-record",
                "reason":"Exercise lens source rejection",
                "name":"Never applied"
            },
            "destination_db_id":"destination"
        });
        let source_error = "update_record: record missing-lens-stateful-record does not exist";
        let mut body = json!({
            "result":{
                "isError":true,
                "content":[{"type":"text","text":source_error}],
                "structuredContent":{"error":source_error}
            }
        });

        attach_repair(
            &mut body,
            contract,
            "execution_error",
            None,
            &envelope,
            None,
        );

        assert_eq!(body["result"]["structuredContent"]["error"], source_error);
        assert!(body["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with(source_error));
        let diagnostic = &body["result"]["structuredContent"]["repair"];
        assert_eq!(diagnostic["diagnostic"], source_error);
        assert_eq!(diagnostic["error_class"], "execution_error");
        assert_eq!(diagnostic["retry_ready"], false);
        assert!(diagnostic["corrected_envelope"].is_null());
        assert!(diagnostic["retry"].is_null());
        assert_eq!(diagnostic["preserved_intent"], envelope);
    }

    #[test]
    fn lens_repair_never_lifts_a_fixed_surface_format_into_the_envelope() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let policy =
            super::super::ResolvedToolExposure::new(super::super::ExposureProfile::Complete);
        let sources = lens_descriptor_projection_for_policy(&registry, &policy).unwrap();
        let BuiltContracts { contracts, .. } =
            build_lens_contracts(&registry, &sources, &audit.audit_rows).unwrap();
        let contract = contracts
            .get(&("records_read".into(), "get_record".into()))
            .unwrap();
        assert_eq!(contract.surface, ExecutorSurface::Lens);

        let envelope = json!({
            "operation":"get_record",
            "arguments":{"ids":["native:root"], "format":"json"}
        });
        assert!(
            minimal_corrected_envelope(contract, &envelope, None).is_none(),
            "a fixed-format lens repair must not turn nested format into an invalid retry envelope"
        );
        let descriptor = sources
            .iter()
            .find(|tool| tool.name == "get_record")
            .unwrap();
        assert!(
            descriptor.descriptor["inputSchema"]["properties"]
                .get("format")
                .is_none(),
            "lens source descriptor must remain fixed-format"
        );
    }

    #[tokio::test]
    async fn ordinary_repair_never_preserves_lens_only_routing_fields() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let contract = server
            .contracts
            .get(&("records_read".into(), "get_record".into()))
            .unwrap();
        assert_eq!(contract.surface, ExecutorSurface::Ordinary);

        let envelope = json!({
            "operation":"get_record",
            "arguments":{"ids":["native:root"]},
            "destination_db_id":"lens-only"
        });
        assert!(
            minimal_corrected_envelope(contract, &envelope, None).is_none(),
            "an ordinary repair must not preserve a lens-only field outside the validated operation arguments"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn overconstrained_empty_query_is_success_with_actionable_result_guidance() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let call = |id: i64, format: Option<&'static str>| {
            let server = &server;
            async move {
                let mut envelope = json!({
                    "operation":"query_record",
                    "arguments":{
                        "steps":[{
                            "step":"filter",
                            "types":["task"],
                            "name_contains":"definitely-no-such-record-a748b2"
                        }],
                        "limit":10
                    },
                    "run_key":"empty-guidance-a748b2"
                });
                if let Some(format) = format {
                    envelope["format"] = json!(format);
                }
                server
                    .handle_message(json!({
                        "jsonrpc":"2.0",
                        "id":id,
                        "method":"tools/call",
                        "params":{"name":"records_read", "arguments":envelope}
                    }))
                    .await
                    .unwrap()
            }
        };

        for (id, format) in [(1, None), (2, Some("text"))] {
            let response = call(id, format).await;
            assert_eq!(response["result"]["isError"], false, "{response}");
            assert!(
                response["result"].get("structuredContent").is_none(),
                "Text executor results must not retain the delegated JSON duplicate: {response}"
            );
            let text = response["result"]["content"][0]["text"].as_str().unwrap();
            assert!(text.contains("Result guidance:"), "{text}");
            assert!(
                text.contains("not proof that no relevant record exists"),
                "{text}"
            );
            assert!(response["result"]["_meta"]["nativeExecutor"].is_object());
        }

        let response = call(3, Some("json")).await;
        assert_eq!(response["result"]["isError"], false, "{response}");
        let guidance = &response["result"]["structuredContent"]["result_guidance"];
        assert_eq!(guidance["code"], "empty_overconstrained_query");
        assert_eq!(guidance["action_required"], true);
        assert_eq!(guidance["constraint_pointers"].as_array().unwrap().len(), 2);
        let json_text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(json_text).unwrap(),
            response["result"]["structuredContent"],
            "the JSON text must be resynchronised after executor guidance mutation"
        );
        assert!(response["result"]["_meta"]["nativeExecutor"].is_object());
        db.close().await;
    }

    #[tokio::test]
    async fn neighbouring_record_reads_select_and_dispatch_the_exact_source_once() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        for (id, operation, arguments) in [
            (
                1,
                "query_record",
                json!({"steps":[{"step":"filter"}],"limit":1}),
            ),
            (2, "get_record", json!({"ids":["native:root"]})),
            (3, "search", json!({"query":"Native","limit":1})),
            (
                4,
                "get_structure",
                json!({"root_id":"native:root","max_depth":1,"max_children_per_node":1}),
            ),
            (5, "resolve_many", json!({"names":["Definitely missing"]})),
        ] {
            let response = server
                .handle_message(json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "method":"tools/call",
                    "params":{
                        "name":"records_read",
                        "arguments":{
                            "operation":operation,
                            "arguments":arguments,
                            "run_key":format!("read-select-{id}-a748b2")
                        }
                    }
                }))
                .await
                .unwrap();
            assert_eq!(
                response["result"]["isError"], false,
                "{operation}: {response}"
            );
        }
        for tool in [
            "query_record",
            "get_record",
            "resolve_many",
            "search",
            "get_structure",
        ] {
            let source_calls: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls WHERE tool = ?")
                    .bind(tool)
                    .fetch_one(db.write_pool())
                    .await
                    .unwrap();
            assert_eq!(source_calls, 1, "{tool} must dispatch exactly once");
        }
        let events = server.trace_events();
        for operation in [
            "query_record",
            "get_record",
            "resolve_many",
            "search",
            "get_structure",
        ] {
            assert!(events.iter().any(|event| {
                event["selection"]["executor"] == "records_read"
                    && event["selection"]["operation"] == operation
                    && event["validation"]["schema_valid"] == true
                    && event["validation"]["runtime_valid"] == true
                    && event["counts"]["tool_calls"] == 1
            }));
        }
        db.close().await;
    }

    /// `format` on the envelope selects the representation, and is honoured
    /// rather than accepted and discarded.
    ///
    /// It rides the envelope because it describes the answer, not the
    /// operation; the operation schemas are projections of source ToolSpecs and
    /// have no such field, so an inner `format` is a schema error by design.
    /// Without this, a rendered tool's own prose can tell an agent to "call
    /// again with format json" and be wrong on the one surface agents use.
    #[tokio::test]
    async fn envelope_format_selects_the_representation_on_the_executor_surface() {
        let db = create_database(":memory:").await.unwrap();
        sqlx::query(
            "INSERT INTO content_events
                (id, record_id, type, payload, actor, run_key, created_at, causal_envelope_version, causal_status)
             VALUES
                ('event:executor-format-context', 'native:root', 'record.updated',
                 '{\"summary\":\"executor transport format context\"}', 'engine:seed',
                 'scout-chair-a748b2', '2026-08-28T00:00:00.000Z', 1, 'legacy_unknown')",
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let records_descriptor = server
            .descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "records_read")
            .unwrap();
        let callable_validator =
            jsonschema::validator_for(&records_descriptor["inputSchema"]).unwrap();
        let advertised_formats = records_descriptor["inputSchema"]["properties"]["format"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(advertised_formats, ["text", "json"]);

        let call = |format: Option<&'static str>| {
            let server = &server;
            async move {
                let mut envelope = json!({
                    "operation":"get_record",
                    "arguments":{"ids":["native:root"]},
                    "run_key":"cobra-echo-jnbkt3"
                });
                if let Some(format) = format {
                    envelope["format"] = json!(format);
                }
                server
                    .handle_message(json!({
                        "jsonrpc":"2.0",
                        "id":1,
                        "method":"tools/call",
                        "params":{"name":"records_read","arguments":envelope}
                    }))
                    .await
                    .unwrap()
            }
        };

        for format in &advertised_formats {
            assert!(callable_validator.is_valid(&json!({
                "operation":"get_record",
                "arguments":{"ids":["native:root"]},
                "run_key":"cobra-echo-jnbkt3",
                "format":format,
            })));
        }

        // Default is unchanged: `get_record` has a renderer, so it renders.
        let default = call(None).await;
        assert_eq!(default["result"]["isError"], false, "{default}");
        let default_text = default["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            !default_text.trim_start().starts_with('{'),
            "default must stay the prose rendering: {default_text}"
        );
        assert!(
            default["result"].get("structuredContent").is_none(),
            "safe default Text must not duplicate the handler payload: {default}"
        );
        for key in [
            "version",
            "body_digest",
            "created_at",
            "updated_at",
            "custody_boundary",
            "containment_path_visible",
            "kind_governance",
            "lifecycle_interpretation",
        ] {
            let expected = format!("\"{key}\":");
            assert!(
                default_text.contains(&expected),
                "default prose lost {key}: {default_text}"
            );
        }
        assert!(default_text.contains("Read scope:"), "{default_text}");

        // `json` returns the serialized payload instead, and is not merely
        // accepted and ignored — the text must actually change shape.
        let explicit = call(Some("json")).await;
        assert_eq!(explicit["result"]["isError"], false, "{explicit}");
        let explicit_text = explicit["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            explicit_text.trim_start().starts_with('{'),
            "format json must return the payload, not prose: {explicit_text}"
        );
        assert_eq!(
            serde_json::from_str::<Value>(explicit_text).unwrap(),
            explicit["result"]["structuredContent"]
        );
        assert!(
            explicit["result"]["structuredContent"]["records"][0]["id"] == "native:root",
            "{explicit}"
        );

        // `text` is selectable explicitly and agrees with the default.
        let text = call(Some("text")).await;
        assert_eq!(
            text["result"]["content"][0]["text"], default["result"]["content"][0]["text"],
            "explicit text must match the rendered default"
        );

        let unknown_outer = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":99,
                "method":"tools/call",
                "params":{"name":"records_read","arguments":{
                    "operation":"get_record",
                    "arguments":{"ids":["native:root"]},
                    "response_format":"json"
                }}
            }))
            .await
            .unwrap();
        assert_eq!(unknown_outer["result"]["isError"], true, "{unknown_outer}");
        assert!(unknown_outer["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown executor-envelope property 'response_format'"));

        let invalid_bootstrap = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":100,
                "method":"tools/call",
                "params":{"name":"bootstrap","arguments":{"format":"yaml"}}
            }))
            .await
            .unwrap();
        assert_eq!(
            invalid_bootstrap["result"]["isError"], true,
            "{invalid_bootstrap}"
        );
        assert!(invalid_bootstrap["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("must be \"text\" or \"json\""));

        let describe_extra = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":101,
                "method":"tools/call",
                "params":{"name":"describe_operation","arguments":{
                    "executor":"records_read",
                    "operation":"get_record",
                    "response_format":"json"
                }}
            }))
            .await
            .unwrap();
        assert_eq!(
            describe_extra["result"]["isError"], true,
            "{describe_extra}"
        );
        assert!(describe_extra["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("unknown executor-envelope property 'response_format'"));

        // Derive the executable JSON-only matrix from the emitted grouped
        // descriptor, then prove each advertised value reaches runtime with
        // exact JSON framing while the non-advertised text value is rejected.
        let system_descriptor = server
            .descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "system_read")
            .unwrap();
        let system_validator =
            jsonschema::validator_for(&system_descriptor["inputSchema"]).unwrap();
        let format_candidates = system_descriptor["inputSchema"]["properties"]["format"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(format_candidates, vec!["json"]);
        for operation in ["ping", "engine_info"] {
            let advertised_formats = format_candidates
                .iter()
                .copied()
                .filter(|format| {
                    system_validator.is_valid(&json!({
                        "operation":operation,
                        "arguments":{},
                        "format":format
                    }))
                })
                .collect::<Vec<_>>();
            assert_eq!(advertised_formats, vec!["json"], "{operation}");
            for &format in &advertised_formats {
                let envelope = json!({
                    "operation":operation,
                    "arguments":{},
                    "format":format
                });
                assert!(system_validator.is_valid(&envelope), "{operation}.{format}");
                let response = server
                    .handle_message(json!({
                        "jsonrpc":"2.0",
                        "id":102,
                        "method":"tools/call",
                        "params":{"name":"system_read","arguments":envelope}
                    }))
                    .await
                    .unwrap();
                assert_eq!(response["result"]["isError"], false, "{response}");
                let text = response["result"]["content"][0]["text"].as_str().unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(text).unwrap(),
                    response["result"]["structuredContent"],
                    "{operation}.{format} did not use exact JSON framing"
                );
            }
            if !advertised_formats.contains(&"text") {
                let envelope = json!({
                    "operation":operation,
                    "arguments":{},
                    "format":"text"
                });
                assert!(!system_validator.is_valid(&envelope), "{operation}.text");
                let response = server
                    .handle_message(json!({
                        "jsonrpc":"2.0",
                        "id":103,
                        "method":"tools/call",
                        "params":{"name":"system_read","arguments":envelope}
                    }))
                    .await
                    .unwrap();
                assert_eq!(response["result"]["isError"], true, "{response}");
                assert!(response["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("no registered text renderer"));
            }
        }

        let query_call = |format: Option<&'static str>| {
            let server = &server;
            async move {
                let mut envelope = json!({
                    "operation":"query_record",
                    "arguments":{
                        "steps":[{"step":"filter","ids":["native:root"]}],
                        "limit":1
                    },
                    "run_key":"cobra-echo-jnbkt3"
                });
                if let Some(format) = format {
                    envelope["format"] = json!(format);
                }
                server
                    .handle_message(json!({
                        "jsonrpc":"2.0",
                        "id":2,
                        "method":"tools/call",
                        "params":{"name":"records_read","arguments":envelope}
                    }))
                    .await
                    .unwrap()
            }
        };
        let query_default = query_call(None).await;
        assert_eq!(query_default["result"]["isError"], false, "{query_default}");
        assert!(query_default["result"].get("structuredContent").is_none());
        let query_text = query_default["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(query_text.contains("Query page:"), "{query_text}");
        assert!(query_text.contains("native:root"), "{query_text}");
        assert!(
            serde_json::from_str::<Value>(query_text).is_err(),
            "{query_text}"
        );

        let query_json = query_call(Some("json")).await;
        assert_eq!(query_json["result"]["isError"], false, "{query_json}");
        let query_json_text = query_json["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(query_json_text).unwrap(),
            query_json["result"]["structuredContent"]
        );

        let intent_call = |format: Option<&'static str>, run_key: &'static str| {
            let server = &server;
            async move {
                let mut envelope = json!({
                    "operation":"set_intent",
                    "arguments":{"intent":"Render the coordination briefing."},
                    "run_key":run_key
                });
                if let Some(format) = format {
                    envelope["format"] = json!(format);
                }
                server
                    .handle_message(json!({
                        "jsonrpc":"2.0",
                        "id":3,
                        "method":"tools/call",
                        "params":{"name":"coordination_write","arguments":envelope}
                    }))
                    .await
                    .unwrap()
            }
        };
        let intent_default = intent_call(None, "scout-chair-e748b2").await;
        assert_eq!(
            intent_default["result"]["isError"], false,
            "{intent_default}"
        );
        let intent_text = intent_default["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(
            intent_text.starts_with("Intent accepted: Render the coordination briefing."),
            "{intent_text}"
        );
        assert!(
            intent_text.contains("Briefing availability: available")
                || intent_text.contains("Briefing unavailable:"),
            "the executor text must preserve the producer availability discriminator: {intent_text}"
        );
        assert!(serde_json::from_str::<Value>(intent_text).is_err());
        assert_eq!(
            intent_default["result"]["structuredContent"]["accepted_intent"],
            "Render the coordination briefing.",
            "non-idempotent set_intent retains its exact recovery receipt"
        );

        let intent_json = intent_call(Some("json"), "scout-chair-f748b2").await;
        assert_eq!(intent_json["result"]["isError"], false, "{intent_json}");
        assert_eq!(
            serde_json::from_str::<Value>(
                intent_json["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            intent_json["result"]["structuredContent"]
        );

        let change_summaries_call = |format: Option<&'static str>| {
            let server = &server;
            async move {
                let mut envelope = json!({
                    "operation":"query_change_summaries.list",
                    "arguments":{},
                    "run_key":"cobra-echo-jnbkt3"
                });
                if let Some(format) = format {
                    envelope["format"] = json!(format);
                }
                server
                    .handle_message(json!({
                        "jsonrpc":"2.0",
                        "id":4,
                        "method":"tools/call",
                        "params":{"name":"artifacts_read","arguments":envelope}
                    }))
                    .await
                    .unwrap()
            }
        };
        let change_summaries_default = change_summaries_call(None).await;
        assert_eq!(
            change_summaries_default["result"]["isError"], false,
            "{change_summaries_default}"
        );
        let change_summaries_text = change_summaries_default["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(
            change_summaries_text.starts_with("Confirmed change-summary page:"),
            "{change_summaries_text}"
        );
        assert!(
            serde_json::from_str::<Value>(change_summaries_text).is_err(),
            "{change_summaries_text}"
        );
        assert!(change_summaries_default["result"]
            .get("structuredContent")
            .is_none());

        let change_summaries_json = change_summaries_call(Some("json")).await;
        assert_eq!(
            change_summaries_json["result"]["isError"], false,
            "{change_summaries_json}"
        );
        assert_eq!(
            serde_json::from_str::<Value>(
                change_summaries_json["result"]["content"][0]["text"]
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
            change_summaries_json["result"]["structuredContent"]
        );

        let guidance_call = |id: i64, operation: &'static str, format: Option<&'static str>| {
            let server = &server;
            async move {
                let mut envelope = json!({
                    "operation":operation,
                    "arguments":{},
                    "run_key":"cobra-echo-jnbkt3"
                });
                if let Some(format) = format {
                    envelope["format"] = json!(format);
                }
                server
                    .handle_message(json!({
                        "jsonrpc":"2.0",
                        "id":id,
                        "method":"tools/call",
                        "params":{"name":"guidance_read","arguments":envelope}
                    }))
                    .await
                    .unwrap()
            }
        };
        for (id, operation, heading) in [
            (
                40,
                "manage_instructions.list",
                "Instruction binding list (read-only):",
            ),
            (
                41,
                "manage_onboarding.list_programmes",
                "Onboarding programme list (read-only):",
            ),
        ] {
            let default = guidance_call(id, operation, None).await;
            assert_eq!(default["result"]["isError"], false, "{default}");
            let text = default["result"]["content"][0]["text"].as_str().unwrap();
            assert!(text.starts_with(heading), "{text}");
            assert!(!text.contains("updated"), "{text}");
            assert!(serde_json::from_str::<Value>(text).is_err(), "{text}");
            assert!(default["result"].get("structuredContent").is_none());

            let exact = guidance_call(id + 10, operation, Some("json")).await;
            assert_eq!(exact["result"]["isError"], false, "{exact}");
            assert_eq!(
                serde_json::from_str::<Value>(
                    exact["result"]["content"][0]["text"].as_str().unwrap()
                )
                .unwrap(),
                exact["result"]["structuredContent"]
            );
        }

        let coordination_call =
            |id: i64, operation: &'static str, arguments: Value, format: Option<&'static str>| {
                let server = &server;
                async move {
                    let mut envelope = json!({
                        "operation":operation,
                        "arguments":arguments,
                        "run_key":"cobra-echo-jnbkt3"
                    });
                    if let Some(format) = format {
                        envelope["format"] = json!(format);
                    }
                    server
                        .handle_message(json!({
                            "jsonrpc":"2.0",
                            "id":id,
                            "method":"tools/call",
                            "params":{"name":"coordination_read","arguments":envelope}
                        }))
                        .await
                        .unwrap()
                }
            };

        let activity_default = coordination_call(
            5,
            "get_run_activity",
            json!({"for_run":"scout-chair-a748b2"}),
            None,
        )
        .await;
        assert_eq!(
            activity_default["result"]["isError"], false,
            "{activity_default}"
        );
        let activity_text = activity_default["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(
            activity_text.contains("for_run=\"scout-chair-a748b2\""),
            "{activity_text}"
        );
        assert!(
            activity_text.contains("No visible aggregate read-activity rows were returned"),
            "{activity_text}"
        );
        assert!(serde_json::from_str::<Value>(activity_text).is_err());
        assert!(activity_default["result"]
            .get("structuredContent")
            .is_none());

        let activity_json = coordination_call(
            6,
            "get_run_activity",
            json!({"for_run":"scout-chair-a748b2"}),
            Some("json"),
        )
        .await;
        assert_eq!(activity_json["result"]["isError"], false, "{activity_json}");
        assert_eq!(
            activity_json["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
            activity_json["result"]["structuredContent"].to_string(),
            "explicit JSON content must be the exact structured payload serialization"
        );

        let event_context_default = coordination_call(
            7,
            "get_event_context",
            json!({"event_id":"event:executor-format-context"}),
            None,
        )
        .await;
        assert_eq!(
            event_context_default["result"]["isError"], false,
            "{event_context_default}"
        );
        let event_context_text = event_context_default["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(
            event_context_text.contains("event:executor-format-context"),
            "{event_context_text}"
        );
        assert!(
            event_context_text.contains("Selected event:"),
            "{event_context_text}"
        );
        assert!(serde_json::from_str::<Value>(event_context_text).is_err());
        assert!(event_context_default["result"]
            .get("structuredContent")
            .is_none());

        let event_context_json = coordination_call(
            8,
            "get_event_context",
            json!({"event_id":"event:executor-format-context"}),
            Some("json"),
        )
        .await;
        assert_eq!(
            event_context_json["result"]["isError"], false,
            "{event_context_json}"
        );
        assert_eq!(
            event_context_json["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
            event_context_json["result"]["structuredContent"].to_string(),
            "explicit JSON content must be the exact structured payload serialization"
        );

        let relationships_default = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":9,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":"manage_relationships.find",
                        "arguments":{
                            "endpoint_record_id":"native:root"
                        }
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(
            relationships_default["result"]["isError"], false,
            "{relationships_default}"
        );
        let relationships_text = relationships_default["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(
            relationships_text.starts_with("Relationship find."),
            "{relationships_text}"
        );
        assert!(relationships_text.contains("native:root"));
        assert!(relationships_text.contains("Page: 0 result(s) returned"));
        assert_eq!(
            relationships_default["result"]["structuredContent"]["action"], "find",
            "the mixed relationship family conservatively retains its recovery payload"
        );

        let relationships_json = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":10,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":"manage_relationships.find",
                        "arguments":{
                            "endpoint_record_id":"native:root"
                        },
                        "format":"json"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(
            relationships_json["result"]["isError"], false,
            "{relationships_json}"
        );
        assert_eq!(
            relationships_json["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
            relationships_json["result"]["structuredContent"].to_string(),
            "explicit JSON content must be the exact structured payload serialization"
        );

        let interventions_default = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":11,
                "method":"tools/call",
                "params":{
                    "name":"messaging_read",
                    "arguments":{
                        "operation":"manage_interventions.query",
                        "arguments":{}
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(
            interventions_default["result"]["isError"], false,
            "{interventions_default}"
        );
        let interventions_text = interventions_default["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(
            !interventions_text.trim_start().starts_with('{'),
            "default intervention response must be rendered text: {interventions_text}"
        );
        assert!(
            interventions_text
                .starts_with("Intervention query returned 0 live viewer-relative item(s)."),
            "{interventions_text}"
        );
        assert!(
            interventions_text.contains("Page controls:"),
            "{interventions_text}"
        );
        assert!(
            interventions_text.contains(
                "No continuation cursor was issued; raised candidates below this page boundary were exhausted at this live read."
            ),
            "{interventions_text}"
        );
        assert!(
            interventions_text
                .contains("Pages are evaluated live; this is not a frozen cross-page snapshot."),
            "{interventions_text}"
        );
        assert_eq!(
            interventions_default["result"]["structuredContent"]["action"],
            "query"
        );
        assert_eq!(
            interventions_default["result"]["structuredContent"]["count"],
            0
        );
        assert_eq!(
            interventions_default["result"]["structuredContent"]["has_more"],
            false
        );
        assert!(interventions_default["result"]["structuredContent"]["next_cursor"].is_null());
        assert_eq!(
            interventions_default["result"]["structuredContent"]["query_basis"],
            "live_at_each_page_read"
        );

        let interventions_json = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":12,
                "method":"tools/call",
                "params":{
                    "name":"messaging_read",
                    "arguments":{
                        "operation":"manage_interventions.query",
                        "arguments":{},
                        "format":"json"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(
            interventions_json["result"]["isError"], false,
            "{interventions_json}"
        );
        assert_eq!(
            interventions_json["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
            interventions_json["result"]["structuredContent"].to_string(),
            "explicit JSON content must be the exact structured intervention payload serialization"
        );

        let links_default = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":13,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":"manage_links.list",
                        "arguments":{"record_id":"native:root"}
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(links_default["result"]["isError"], false, "{links_default}");
        let links_text = links_default["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(
            !links_text.trim_start().starts_with('{'),
            "default manage_links response must be rendered text: {links_text}"
        );
        assert!(
            links_text.starts_with(
                "Link list returned 0 caller-visible row(s) for \"native:root\" in this live page."
            ),
            "{links_text}"
        );
        assert!(links_text.contains("Live page controls:"), "{links_text}");
        assert!(
            links_text.contains(
                "Rows are authorization-filtered by opposite-endpoint visibility at this read; this is not a claim about inaccessible links or a frozen cross-page snapshot."
            ),
            "{links_text}"
        );
        assert!(
            links_text.contains(
                "No continuation cursor was issued; this live candidate scan is exhausted."
            ),
            "{links_text}"
        );
        assert_eq!(
            links_default["result"]["structuredContent"]["action"],
            "list"
        );
        assert_eq!(
            links_default["result"]["structuredContent"]["record_id"],
            "native:root"
        );
        assert_eq!(links_default["result"]["structuredContent"]["returned"], 0);

        let links_json = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":14,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":"manage_links.list",
                        "arguments":{"record_id":"native:root"},
                        "format":"json"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(links_json["result"]["isError"], false, "{links_json}");
        assert_eq!(
            links_json["result"]["content"][0]["text"].as_str().unwrap(),
            links_json["result"]["structuredContent"].to_string(),
            "explicit JSON content must be the exact structured manage_links payload serialization"
        );

        // `format` never reaches the handler, which parses with
        // `deny_unknown_fields` and would reject it.
        assert!(!explicit_text.contains("unknown field"), "{explicit_text}");

        db.close().await;
    }

    #[tokio::test]
    async fn attribution_responses_render_truthfully_on_the_executor_surface() {
        const BEARER: &str = "700cac00-0000-4000-8000-000000000017";

        let db = create_database(":memory:").await.unwrap();
        let fixture_registry = registry();
        fixture_registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id":BEARER,
                    "type":"Document",
                    "kind":"note",
                    "name":"Executor attribution bearer",
                    "body":"The executor preserves this exact attributed view.",
                    "reason":"create executor attribution bearer"
                }),
            )
            .await
            .unwrap();
        let target_row = sqlx::query(
            "SELECT e.id,r.body FROM records r JOIN content_events e ON e.record_id=r.id
             WHERE r.id=? AND (e.type='record.created' OR (e.type='record.updated' AND json_type(e.payload,'$.body') IS NOT NULL))
             ORDER BY e.seq DESC LIMIT 1",
        )
        .bind(BEARER)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let source_event_id = target_row.try_get::<String, _>("id").unwrap();
        let body = target_row
            .try_get::<Option<String>, _>("body")
            .unwrap()
            .unwrap_or_default();
        let source_body_sha256 = hex::encode(Sha256::digest(body.as_bytes()));

        let issuer = crate::awareness::HumanInteractionTokenIssuer::random("test-ui");
        let surfaced_records = vec![BEARER.to_string()];
        let token = issuer
            .issue(
                "local",
                "agent-executor:test-agent:test-delegation",
                &surfaced_records,
                60,
            )
            .unwrap();
        let caller = Caller::local()
            .with_agent_executor_token(
                &issuer,
                &token,
                "test-agent",
                "test-delegation",
                &surfaced_records,
            )
            .unwrap();
        let server = ExecutorPrototypeStdioServer::new(registry(), db.clone(), caller, None)
            .await
            .unwrap();

        let created = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/call",
                "params":{
                    "name":"records_write",
                    "arguments":{
                        "operation":"create_attribution",
                        "arguments":{
                            "idempotency_key":"executor-attribution-create",
                            "bearer_id":BEARER,
                            "target":{
                                "source_event_id":source_event_id,
                                "source_body_sha256":source_body_sha256,
                                "scope":"whole_revision",
                                "selectors":[]
                            },
                            "subject":{"kind":"self_agent_execution"},
                            "relation":"expresses_view",
                            "polarity":"affirmed",
                            "confidence":"likely",
                            "transformation":"summary",
                            "rationale":"The executor test agent assesses this exact revision."
                        }
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(created["result"]["isError"], false, "{created}");
        let create_text = created["result"]["content"][0]["text"].as_str().unwrap();
        for expected in [BEARER, "created", "assessment", "Action attestation:"] {
            assert!(
                create_text.contains(expected),
                "missing {expected}: {create_text}"
            );
        }
        let annotation_id = created["result"]["structuredContent"]["annotation_id"]
            .as_str()
            .expect("non-idempotent attribution creation retains its recovery receipt")
            .to_string();

        let read_arguments = json!({
            "operation":"read_attributions",
            "arguments":{
                "bearer_id":BEARER,
                "explain_annotation_id":annotation_id
            }
        });
        let read = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                "params":{"name":"records_read","arguments":read_arguments.clone()}
            }))
            .await
            .unwrap();
        assert_eq!(read["result"]["isError"], false, "{read}");
        let read_text = read["result"]["content"][0]["text"].as_str().unwrap();
        for expected in [
            BEARER,
            annotation_id.as_str(),
            "source_event_id",
            "The executor test agent assesses this exact revision.",
            "Interpretation projection:",
            "Claim-specific explanation:",
        ] {
            assert!(
                read_text.contains(expected),
                "missing {expected}: {read_text}"
            );
        }
        assert!(
            serde_json::from_str::<Value>(read_text).is_err(),
            "{read_text}"
        );
        assert!(read["result"].get("structuredContent").is_none());

        let mut exact_arguments = read_arguments;
        exact_arguments["format"] = json!("json");
        let exact = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":3,
                "method":"tools/call",
                "params":{"name":"records_read","arguments":exact_arguments}
            }))
            .await
            .unwrap();
        assert_eq!(exact["result"]["isError"], false, "{exact}");
        assert_eq!(
            exact["result"]["content"][0]["text"].as_str().unwrap(),
            exact["result"]["structuredContent"].to_string()
        );

        let retracted = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":4,
                "method":"tools/call",
                "params":{
                    "name":"records_write",
                    "arguments":{
                        "operation":"manage_attributions.retract",
                        "arguments":{
                            "annotation_id":annotation_id,
                            "reason":"The executor fixture has completed its purpose."
                        }
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(retracted["result"]["isError"], false, "{retracted}");
        let retract_text = retracted["result"]["content"][0]["text"].as_str().unwrap();
        assert!(retract_text.contains("retracted"), "{retract_text}");
        assert_eq!(
            retracted["result"]["structuredContent"]["action"],
            "retracted"
        );

        db.close().await;
    }

    #[tokio::test]
    async fn citation_responses_render_truthfully_on_the_executor_surface() {
        const SOURCE: &str = "700cac00-0000-4000-8000-000000000014";
        const BEARER: &str = "700cac00-0000-4000-8000-000000000015";
        const CITATION: &str = "700cac00-0000-4000-8000-000000000016";

        let db = create_database(":memory:").await.unwrap();
        let fixture_registry = registry();
        for arguments in [
            json!({
                "id":SOURCE,
                "type":"Document",
                "kind":"note",
                "name":"Executor citation source",
                "body":"Intro. The executor preserves this evidence. End.",
                "reason":"create executor citation source"
            }),
            json!({
                "id":BEARER,
                "type":"WorkItem",
                "kind":"task",
                "name":"Executor citation bearer",
                "reason":"create executor citation bearer"
            }),
            json!({
                "id":CITATION,
                "type":"Annotation",
                "kind":"citation",
                "name":"Executor citation fixture",
                "body":"Why this evidence matters",
                "links":[{"target_id":BEARER,"relationship":"part_of"}],
                "target":{
                    "target_record_id":SOURCE,
                    "source_slot":"body",
                    "purpose":"extracted_from",
                    "selectors":[{"type":"text_quote","exact":"The executor preserves this evidence."}]
                },
                "reason":"create executor citation fixture"
            }),
        ] {
            fixture_registry
                .call(db.clone(), Caller::local(), "create_record", arguments)
                .await
                .unwrap();
        }

        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let resolve = |id: i64, format: Option<&'static str>| {
            let server = &server;
            async move {
                let mut envelope = json!({
                    "operation":"resolve_citation",
                    "arguments":{"citation_id":CITATION}
                });
                if let Some(format) = format {
                    envelope["format"] = json!(format);
                }
                server
                    .handle_message(json!({
                        "jsonrpc":"2.0",
                        "id":id,
                        "method":"tools/call",
                        "params":{"name":"records_read","arguments":envelope}
                    }))
                    .await
                    .unwrap()
            }
        };

        let default = resolve(1, None).await;
        assert_eq!(default["result"]["isError"], false, "{default}");
        let text = default["result"]["content"][0]["text"].as_str().unwrap();
        for expected in [
            CITATION,
            SOURCE,
            "The executor preserves this evidence.",
            "Validation:",
            "Anchored source:",
            "Current source:",
            "Selectors:",
            "Read only: true",
        ] {
            assert!(text.contains(expected), "missing {expected}: {text}");
        }
        assert!(serde_json::from_str::<Value>(text).is_err(), "{text}");
        assert!(default["result"].get("structuredContent").is_none());

        let exact = resolve(2, Some("json")).await;
        assert_eq!(exact["result"]["isError"], false, "{exact}");
        assert_eq!(
            exact["result"]["content"][0]["text"].as_str().unwrap(),
            exact["result"]["structuredContent"].to_string()
        );

        let reanchored = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":3,
                "method":"tools/call",
                "params":{
                    "name":"records_write",
                    "arguments":{
                        "operation":"manage_citations.reanchor",
                        "arguments":{
                            "citation_id":CITATION,
                            "target":{
                                "target_record_id":SOURCE,
                                "source_slot":"body",
                                "selectors":[{"type":"text_quote","exact":"executor preserves"}]
                            },
                            "reason":"Narrow to the operative words."
                        }
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(reanchored["result"]["isError"], false, "{reanchored}");
        let write_text = reanchored["result"]["content"][0]["text"].as_str().unwrap();
        for expected in [
            CITATION,
            "reanchored",
            "Event sequence:",
            "Narrow to the operative words.",
        ] {
            assert!(
                write_text.contains(expected),
                "missing {expected}: {write_text}"
            );
        }
        assert_eq!(
            reanchored["result"]["structuredContent"]["action"],
            "reanchored"
        );

        let exact_write = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":4,
                "method":"tools/call",
                "params":{
                    "name":"records_write",
                    "arguments":{
                        "operation":"manage_citations.reanchor",
                        "arguments":{
                            "citation_id":CITATION,
                            "target":{
                                "target_record_id":SOURCE,
                                "source_slot":"body",
                                "selectors":[{"type":"text_quote","exact":"The executor preserves this evidence."}]
                            },
                            "reason":"Restore the complete assertion.",
                        },
                        "format":"json"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(exact_write["result"]["isError"], false, "{exact_write}");
        assert_eq!(
            exact_write["result"]["content"][0]["text"]
                .as_str()
                .unwrap(),
            exact_write["result"]["structuredContent"].to_string(),
            "explicit JSON content must be the exact structured citation write receipt"
        );

        db.close().await;
    }

    #[tokio::test]
    async fn records_write_executor_renders_write_receipts_and_honours_json() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let id = "0189d4c6-1f2a-7b3c-9d4e-5f60718293a5";

        let created = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/call",
                "params":{
                    "name":"records_write",
                    "arguments":{
                        "operation":"create_record",
                        "arguments":{
                            "id":id,
                            "type":"Document",
                            "kind":"note",
                            "name":"Executor write rendering",
                            "body":"first body",
                            "reason":"Exercise the executor write renderer."
                        },
                        "run_key":"write-render-a748b2"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(created["result"]["isError"], false, "{created}");
        let created_text = created["result"]["content"][0]["text"].as_str().unwrap();
        // The verb line names the record it wrote. The confirmation no longer
        // echoes the post-write record, so this line plus the receipt is the
        // whole answer the caller gets without a second read.
        assert!(
            created_text.starts_with(&format!("Created {id}\n")),
            "{created_text}"
        );
        assert!(created_text.contains("Write receipt:"), "{created_text}");
        assert!(
            !created_text.contains("first body"),
            "the confirmation must not echo the body it was handed: {created_text}"
        );
        assert!(created_text.contains("body_digest: \""), "{created_text}");
        assert!(created["result"].get("structuredContent").is_none());

        let updated = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                "params":{
                    "name":"records_write",
                    "arguments":{
                        "operation":"update_record",
                        "arguments":{
                            "id":id,
                            "summary":"Rendered through the executor",
                            "reason":"Exercise the default executor text response."
                        },
                        "run_key":"write-render-a748b2"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(updated["result"]["isError"], false, "{updated}");
        let updated_text = updated["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            updated_text.starts_with(&format!("Updated {id}\n")),
            "{updated_text}"
        );
        assert!(updated_text.contains("Write receipt:"), "{updated_text}");
        assert!(updated["result"].get("structuredContent").is_none());

        let explicit = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":3,
                "method":"tools/call",
                "params":{
                    "name":"records_write",
                    "arguments":{
                        "operation":"update_record",
                        "arguments":{
                            "id":id,
                            "name":"JSON executor write rendering",
                            "reason":"Exercise the explicit executor JSON response."
                        },
                        "format":"json",
                        "run_key":"write-render-a748b2"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(explicit["result"]["isError"], false, "{explicit}");
        let explicit_text = explicit["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(explicit_text).unwrap(),
            explicit["result"]["structuredContent"],
        );

        db.close().await;
    }

    /// An unusable `format` fails loudly rather than falling back to a default.
    #[tokio::test]
    async fn envelope_format_rejects_a_representation_it_cannot_produce() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let response = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":"get_record",
                        "arguments":{"ids":["native:root"]},
                        "run_key":"cobra-echo-jnbkt3",
                        "format":"yaml"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], true, "{response}");
        let text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("format"), "{text}");
        db.close().await;
    }
}
