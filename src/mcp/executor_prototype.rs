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
use super::{
    ExperimentalExecutors, EXPERIMENTAL_FRESHNESS_EXECUTOR, EXPERIMENTAL_SQL_WRITE_EXECUTOR,
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
    build_enabled_experimental: BuildEnabledExperimentalSurfaces,
}

#[derive(Deserialize)]
struct StableSurfaces {
    ordinary: CandidateSurface,
    lens: CandidateSurface,
}

#[derive(Deserialize)]
struct BuildEnabledExperimentalSurfaces {
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
    /// Whether `input_schema` describes this action alone, decided where the
    /// projection happens rather than inferred from the result.
    action_specific_projection: bool,
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

/// Whether an audit row may enter a catalogue. Stable rows always may.
/// Experimental rows may only when the deployment allowlisted their executor;
/// anything else is never advertised. Together with the allowlisted
/// descriptor push in the catalogue builders, this filter is why the audited
/// `experimental_freshness` executor is not advertised by default.
fn row_is_admitted(row: &AuditRow, experimental: &ExperimentalExecutors) -> bool {
    if row.stability == "stable" {
        return true;
    }
    row.stability == "experimental" && experimental.contains(&row.candidate_executor)
}

/// One audited experimental executor descriptor, loaded verbatim from the
/// `build_enabled_experimental` surface of the committed public projection
/// (itself a verbatim copy of the held candidate audit's surface). Nothing
/// about the stable inventory changes: the descriptor only enters a catalogue
/// when its executor is allowlisted.
fn experimental_executor_descriptor(
    surface: &CandidateSurface,
    surface_name: &str,
    executor: &str,
) -> Result<Value> {
    if serde_json::to_vec(&surface.descriptors)?.len() != surface.descriptor_bytes {
        return Err(Error::engine(format!(
            "audited build-enabled-experimental {surface_name} executor descriptor byte count drifted"
        )));
    }
    surface
        .descriptors
        .iter()
        .find(|descriptor| descriptor.get("name").and_then(Value::as_str) == Some(executor))
        .cloned()
        .ok_or_else(|| {
            Error::engine(format!(
                "audited build-enabled-experimental {surface_name} surface is missing {executor}"
            ))
        })
}

/// The audited `experimental_freshness` executor descriptor, loaded verbatim
/// from the `build_enabled_experimental` surface of the committed public
/// projection (itself a verbatim copy of the held candidate audit's surface).
/// Nothing about the stable inventory changes: the descriptor only enters a
/// catalogue when its executor is allowlisted.
fn experimental_freshness_descriptor(
    surface: &CandidateSurface,
    surface_name: &str,
) -> Result<Value> {
    experimental_executor_descriptor(surface, surface_name, EXPERIMENTAL_FRESHNESS_EXECUTOR)
}

/// The audited `sql_write` executor descriptor. Like freshness, it only
/// enters a catalogue when its executor is allowlisted.
fn experimental_sql_write_descriptor(
    surface: &CandidateSurface,
    surface_name: &str,
) -> Result<Value> {
    experimental_executor_descriptor(surface, surface_name, EXPERIMENTAL_SQL_WRITE_EXECUTOR)
}

fn build_ordinary_catalogue(
    registry: &ToolRegistry,
    engine_kind: super::registry::EngineKind,
    hosted: bool,
    experimental: &ExperimentalExecutors,
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
        experimental,
    )?;
    let source_surface = audit.candidate_surfaces.stable.ordinary;
    if serde_json::to_vec(&source_surface.descriptors)?.len() != source_surface.descriptor_bytes {
        return Err(Error::engine(
            "audited ordinary executor descriptor byte count drifted",
        ));
    }
    let mut source_descriptors = source_surface.descriptors;
    if experimental.contains(EXPERIMENTAL_FRESHNESS_EXECUTOR) {
        source_descriptors.push(experimental_freshness_descriptor(
            &audit.candidate_surfaces.build_enabled_experimental.ordinary,
            "ordinary",
        )?);
    }
    if experimental.contains(EXPERIMENTAL_SQL_WRITE_EXECUTOR) {
        source_descriptors.push(experimental_sql_write_descriptor(
            &audit.candidate_surfaces.build_enabled_experimental.ordinary,
            "ordinary",
        )?);
    }
    let mut descriptors = executable_descriptors(source_descriptors, &operations_by_executor)?;
    add_ordinary_executor_format_contracts(&mut descriptors, &contracts)?;
    add_operation_field_listings(&mut descriptors, &contracts)?;
    add_sql_read_catalog_card(&mut descriptors);
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
    experimental: ExperimentalExecutors,
    telemetry: TelemetryConstruction,
    transport: telemetry::TelemetryTransport,
    deployment_mutation_barrier: Option<DeploymentMutationBarrier>,
}

impl ExecutorPrototypeStdioServer {
    pub(crate) fn pin_hosted_catalogue(
        registry: &ToolRegistry,
    ) -> Result<Arc<PinnedExecutorCatalogue>> {
        Self::pin_hosted_catalogue_with_experimental(registry, &ExperimentalExecutors::empty())
    }

    pub(crate) fn pin_hosted_catalogue_with_experimental(
        registry: &ToolRegistry,
        experimental: &ExperimentalExecutors,
    ) -> Result<Arc<PinnedExecutorCatalogue>> {
        Ok(Arc::new(build_ordinary_catalogue(
            registry,
            super::registry::EngineKind::Sqlite,
            true,
            experimental,
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
                experimental: ExperimentalExecutors::empty(),
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
        Self::new_with_telemetry_and_experimental(
            registry,
            engine,
            caller,
            trace_path,
            telemetry,
            ExperimentalExecutors::empty(),
        )
        .await
    }

    /// Build the local executor with the privacy-safe dogfood sink enabled
    /// and an explicit experimental-executor allowlist.
    pub async fn new_with_telemetry_and_experimental(
        registry: Arc<ToolRegistry>,
        engine: impl Into<EngineHandle>,
        caller: Caller,
        trace_path: Option<&Path>,
        telemetry: Arc<ExecutorTelemetryContext>,
        experimental: ExperimentalExecutors,
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
                experimental,
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
                experimental: ExperimentalExecutors::empty(),
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
            experimental,
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
                &experimental,
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
        let mut arguments = params
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
        // Hoist `arguments.run_key`/`arguments.parent_key` to the envelope
        // before any run-keyed bookkeeping, so a hoisted key attaches exactly
        // as an envelope key would. Conflicts and non-strings reject here
        // rather than silently dropping either value.
        if let Err(diagnostic) = hoist_nested_routing_keys(&mut arguments) {
            return Some(
                self.fixture_error_response(
                    id,
                    modern,
                    &executor,
                    &operation,
                    &diagnostic,
                    Some(&contract),
                    &arguments,
                    "validation_failure",
                    Some(false),
                    true,
                )
                .await,
            );
        }
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
        // The selector is part of the callable input contract. Validate it
        // before dispatch so its rejection cannot become a state/auth failure.
        // Plan-backed operations returned above; fixed-format surfaces have
        // their own handler and never enter this ordinary direct path.
        let mut format_arguments = arguments.clone();
        if let Err(error) = render::take_format(&contract.source_tool, &mut format_arguments) {
            return Some(
                self.fixture_error_response(
                    id,
                    modern,
                    &executor,
                    &operation,
                    &error,
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
        let normalized_arguments = match normalized_executor_arguments(&operation, &arguments) {
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
                        Some(false),
                        true,
                    )
                    .await,
                )
            }
        };
        let schema_errors = match jsonschema::validator_for(&contract.input_schema) {
            Ok(validator) => validator
                .iter_errors(&operation_arguments)
                .map(|error| schema_error_text(&error))
                .collect::<Vec<_>>(),
            Err(error) => vec![format!("invalid authoritative contract: {error}")],
        };
        let schema_valid = schema_errors.is_empty();
        if !schema_valid {
            let diagnostic = crate::mcp::record_ref::invalid_operation_record_selector_diagnostic(
                &operation,
                &operation_arguments,
            )
            .map(|error| error.to_string())
            .unwrap_or_else(|| {
                format!(
                    "arguments do not match the authoritative operation contract: {}",
                    schema_errors.join("; ")
                )
            });
            return Some(
                self.fixture_error_response(
                    id,
                    modern,
                    &executor,
                    &operation,
                    &diagnostic,
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
            normalized_arguments
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({})),
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
        let mut legacy_arguments = match translate_arguments(&contract, &normalized_arguments) {
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
    pub(crate) fn pin_catalogue_with_experimental(
        registry: &ToolRegistry,
        experimental: &ExperimentalExecutors,
    ) -> Result<Arc<PinnedLensExecutorCatalogue>> {
        let audit: Audit = serde_json::from_str(AUDIT)?;
        let policy = super::ResolvedToolExposure::new(super::ExposureProfile::Complete);
        let sources = lens_descriptor_projection_for_policy(registry, &policy)?;
        let BuiltContracts {
            contracts,
            operations_by_executor,
        } = build_lens_contracts(registry, &sources, &audit.audit_rows, experimental)?;
        let source_surface = audit.candidate_surfaces.stable.lens;
        if serde_json::to_vec(&source_surface.descriptors)?.len() != source_surface.descriptor_bytes
        {
            return Err(Error::engine(
                "audited lens executor descriptor byte count drifted",
            ));
        }
        let mut source_descriptors = source_surface.descriptors;
        if experimental.contains(EXPERIMENTAL_FRESHNESS_EXECUTOR) {
            source_descriptors.push(experimental_freshness_descriptor(
                &audit.candidate_surfaces.build_enabled_experimental.lens,
                "lens",
            )?);
        }
        if experimental.contains(EXPERIMENTAL_SQL_WRITE_EXECUTOR) {
            source_descriptors.push(experimental_sql_write_descriptor(
                &audit.candidate_surfaces.build_enabled_experimental.lens,
                "lens",
            )?);
        }
        let mut descriptors = executable_descriptors(source_descriptors, &operations_by_executor)?;
        add_operation_field_listings(&mut descriptors, &contracts)?;
        add_sql_read_catalog_card(&mut descriptors);
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
        let mut arguments = params
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
        // Hoist nested routing keys before validation so the delegated
        // legacy call carries them; conflicts and non-strings reject here.
        if let Err(diagnostic) = hoist_nested_routing_keys(&mut arguments) {
            return Some(
                self.error_response(id, modern, &diagnostic, Some(&contract), &arguments)
                    .await,
            );
        }
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
        let normalized_arguments = match normalized_executor_arguments(&operation, &arguments) {
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
        let schema_errors = match jsonschema::validator_for(&contract.input_schema) {
            Ok(validator) => validator
                .iter_errors(&operation_arguments)
                .map(|error| schema_error_text(&error))
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
            let diagnostic = crate::mcp::record_ref::invalid_operation_record_selector_diagnostic(
                &operation,
                &operation_arguments,
            )
            .map(|error| error.to_string())
            .unwrap_or_else(|| {
                format!(
                    "arguments do not match the authoritative lens operation contract: {}",
                    schema_errors.join("; ")
                )
            });
            return Some(
                self.error_response(id, modern, &diagnostic, Some(&contract), &arguments)
                    .await,
            );
        }
        let legacy_arguments = match translate_arguments(&contract, &normalized_arguments) {
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
    build_contracts_for_hosting(
        registry,
        engine_kind,
        rows,
        surface,
        false,
        &ExperimentalExecutors::empty(),
    )
}

fn build_contracts_for_hosting(
    registry: &ToolRegistry,
    engine_kind: super::registry::EngineKind,
    rows: &[AuditRow],
    surface: ExecutorSurface,
    hosted_membership_plans: bool,
    experimental: &ExperimentalExecutors,
) -> Result<BuiltContracts> {
    let mut contracts = BTreeMap::new();
    let mut operations_by_executor = OperationsByExecutor::new();
    for row in rows.iter().filter(|row| {
        row_is_admitted(row, experimental)
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
    experimental: &ExperimentalExecutors,
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
        row_is_admitted(row, experimental) && row.availability.iter().any(|value| value == "lens")
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
        action_specific_projection: projection_is_action_specific(
            source_schema,
            selector.as_ref(),
            selector_specific_schema.is_some(),
        ),
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
            // The workspace directory is Direct yet hosted-only: without
            // hosted authority it is withheld exactly like the plan-gated
            // membership operations below.
            (write_operations::advertisable(executor, operation)
                && !write_operations::is_workspace_operation(executor, operation))
                || (hosted_membership_plans
                    && (write_operations::is_membership_operation(executor, operation)
                        || write_operations::is_workspace_operation(executor, operation)))
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

/// Advertise each operation's accepted field names on its executor descriptor,
/// with unconditionally required fields starred, so a caller can construct a
/// first call to an unfamiliar operation without a preparatory
/// `describe_operation`.
///
/// Decision `e9ecb98` (5 Sep 2026): names travel in the descriptor, types and
/// prose stay behind `describe_operation`. Projecting the full per-operation
/// schemas instead was measured at ~300 KB against a ~197 KB legacy Complete
/// profile — more than the surface this facade replaced — so the facade pays a
/// bounded price in bytes for the common question (which fields does this
/// operation take, and which must I supply) and keeps the round trip for the
/// uncommon one.
///
/// The contracts are already projected at boot, so this derives nothing at
/// request time.
fn add_sql_read_catalog_card(descriptors: &mut [Value]) {
    // E2 I-4: the served `sql_read` descriptor carries the catalog card so
    // first contact already names every relation, the value model, the
    // placeholder rule and worked statements. Budget enforced below.
    let card = crate::query::sql_contract::sql_read_catalog_card();
    debug_assert!(
        card.len() <= crate::query::sql_contract::SQL_READ_CARD_MAX_BYTES,
        "catalog card exceeded its byte budget"
    );
    for descriptor in descriptors {
        if descriptor.get("name").and_then(Value::as_str) != Some("sql_read") {
            continue;
        }
        let description = descriptor
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default();
        descriptor["description"] = json!(format!("{description} {card}"));
    }
}

fn add_operation_field_listings(
    descriptors: &mut [Value],
    contracts: &OperationContracts,
) -> Result<()> {
    for descriptor in descriptors {
        let name = descriptor
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("executor descriptor has no name"))?
            .to_string();
        if name == "bootstrap" || name == "describe_operation" {
            continue;
        }
        // Advertise only what this environment actually routes: the enum was
        // already narrowed by `executable_descriptors`, so an environment-gated
        // operation that received no advertised value receives no listing.
        let Some(operations) = descriptor
            .pointer("/inputSchema/properties/operation/enum")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
        else {
            continue;
        };
        let routed = operations
            .iter()
            .filter_map(|operation| contracts.get(&(name.clone(), operation.clone())))
            .collect::<Vec<_>>();
        if routed.is_empty() {
            continue;
        }
        // Body writes need their semantics at first contact: a caller that
        // mistakes replacement for append can lose content despite a valid
        // concurrency token. Disclose this bounded exception only when the
        // routed contract actually carries the explicit body operations.
        if let Some(contract) = routed
            .iter()
            .find(|contract| contract.operation == "update_record")
        {
            let mut fields = Vec::new();
            collect_property_names(&contract.input_schema, &mut fields);
            if ["body_set", "body_append", "body_replace"]
                .iter()
                .all(|field| fields.iter().any(|name| name == *field))
            {
                let description = descriptor["description"].as_str().unwrap_or_default();
                descriptor["description"] = json!(format!(
                    "{description} update_record body operations (choose one): body_set replaces the whole body; body_append appends literal text; body_replace applies surgical edits; body is a deprecated full-replacement alias."
                ));
            }
        }
        // An operation whose projection is not action-specific shares one
        // projected contract with its sibling actions, so naming its accepted
        // fields would name theirs too. It still gets its required ones: see
        // `required_field_listing` for why that half is sound when the whole is
        // not.
        let (specific, shared): (Vec<_>, Vec<_>) = routed
            .iter()
            .copied()
            .partition(|contract| contract.action_specific_projection);
        let listings = specific
            .iter()
            .map(|contract| operation_field_listing(&contract.operation, &contract.input_schema))
            .collect::<Vec<_>>();
        let shared_listings = shared
            .iter()
            .filter_map(|contract| {
                required_field_listing(&contract.operation, &contract.input_schema)
            })
            .collect::<Vec<_>>();
        let mut clause = String::new();
        if !listings.is_empty() {
            clause.push_str(&format!(
                "Fields by operation, * = required (describe_operation carries \
                 types, prose and conditional requirements): {}.",
                listings.join("; ")
            ));
        }
        // The two sentences below are independent, not alternatives. An
        // executor can route several flat-bag source tools, one demanding a
        // field of every action and another demanding nothing beyond the
        // selector — and then some shared operations are named here while
        // others can only be covered by the catch-all. Choosing between the
        // sentences would leave that second group described by neither, which
        // is less disclosure than before this listing existed.
        if !shared_listings.is_empty() {
            // Carries its own `* = required` legend: an executor whose source
            // tools are all flat bags — `canvas_read` — has no listing above to
            // establish the convention.
            if !clause.is_empty() {
                clause.push(' ');
            }
            clause.push_str(&format!(
                "An operation shown next shares one contract with its sibling \
                 actions, so only the fields required of every action are named \
                 for it (* = required) and its remaining fields are available \
                 from describe_operation: {}.",
                shared_listings.join("; ")
            ));
        }
        if shared.len() > shared_listings.len() {
            // Said even when nothing could be listed, so an executor that
            // discloses no fields says so rather than saying nothing.
            if !clause.is_empty() {
                clause.push(' ');
            }
            clause.push_str(
                "An operation not listed here shares one contract with its \
                 sibling actions, so its own fields are only available from \
                 describe_operation.",
            );
        }
        if clause.is_empty() {
            continue;
        }
        // Plan-carrying descriptors redeclare `arguments` inside their `oneOf`
        // branches as a byte-identical copy of the top-level description, and
        // the branch that actually requires `arguments` is one of those. Writing
        // only the top level would leave that branch advertising a contract
        // without its fields, so every copy carries the listing. It costs about
        // 3.3 KB to keep one field from describing itself two ways.
        append_to_argument_descriptions(&mut descriptor["inputSchema"], &clause);
    }
    Ok(())
}

/// Add `addition` to every `arguments` description in this schema, including
/// the byte-identical copies inside conditional branches.
fn append_to_argument_descriptions(schema: &mut Value, addition: &str) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(arguments) = object
        .get_mut("properties")
        .and_then(Value::as_object_mut)
        .and_then(|properties| properties.get_mut("arguments"))
        .and_then(Value::as_object_mut)
    {
        let existing = arguments
            .get("description")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .trim_end()
            .to_string();
        let separator = if existing.is_empty() { "" } else { " " };
        arguments.insert(
            "description".into(),
            json!(format!("{existing}{separator}{addition}")),
        );
    }
    for keyword in ["oneOf", "anyOf", "allOf"] {
        if let Some(branches) = object.get_mut(keyword).and_then(Value::as_array_mut) {
            for branch in branches {
                append_to_argument_descriptions(branch, addition);
            }
        }
    }
}

/// `operation: field*, field` — every accepted property name for one operation,
/// with required ones starred.
fn operation_field_listing(operation: &str, schema: &Value) -> String {
    let mut required = Vec::new();
    collect_required_names(schema, &mut required);
    let required = required.into_iter().collect::<HashSet<_>>();
    let mut names = Vec::new();
    collect_property_names(schema, &mut names);
    names.sort();
    names.dedup();
    if names.is_empty() {
        return format!("{operation}: (no arguments)");
    }
    let rendered = names
        .into_iter()
        .map(|name| {
            if required.contains(&name) {
                format!("{name}*")
            } else {
                name
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("{operation}: {rendered}")
}

/// `operation: field*, field*` — only the fields required of every action a
/// shared contract routes, for an operation whose projection is not
/// action-specific.
///
/// Naming a shared projection's *accepted* fields as one action's own is the
/// defect `projection_is_action_specific` exists to prevent: a flat-bag source
/// tool's `properties` map is the union of actions whose contracts differ, so
/// `manage_attachments.detach` would be advertised as accepting `record_id`,
/// which its handler rejects. The required half carries no such risk. That
/// array sits above the action selector in the same flat bag, and
/// `collect_required_names` walks only the top level and `allOf`, never a
/// branch — so every name it returns is required of every action the tool
/// routes, and starring it states what the server already enforces.
///
/// This is the whole disclosure for an executor whose source tools are all flat
/// bags. `read_canvas` is one: before this, none of its four operations named a
/// field, and a caller learned `canvas_id` by being rejected.
fn required_field_listing(operation: &str, schema: &Value) -> Option<String> {
    let mut required = Vec::new();
    collect_required_names(schema, &mut required);
    required.sort();
    required.dedup();
    if required.is_empty() {
        return None;
    }
    let rendered = required
        .into_iter()
        .map(|name| format!("{name}*"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(format!("{operation}: {rendered}"))
}

/// Every property name an operation accepts, including those reachable only
/// through a conditional branch. A caller needs the whole vocabulary; which
/// combination is legal is what `describe_operation` is for.
fn collect_property_names(schema: &Value, into: &mut Vec<String>) {
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        into.extend(properties.keys().cloned());
    }
    for keyword in ["allOf", "anyOf", "oneOf"] {
        if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
            for branch in branches {
                collect_property_names(branch, into);
            }
        }
    }
    if let Some(then) = schema.get("then") {
        collect_property_names(then, into);
    }
}

/// Only *unconditionally* required names: the top level and `allOf`, which
/// every valid envelope must satisfy. A field required inside one `oneOf`
/// branch is not required of the operation, and starring it would trade one
/// misleading contract for another.
fn collect_required_names(schema: &Value, into: &mut Vec<String>) {
    if let Some(required) = schema.get("required").and_then(Value::as_array) {
        into.extend(
            required
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string),
        );
    }
    if let Some(branches) = schema.get("allOf").and_then(Value::as_array) {
        for branch in branches {
            collect_required_names(branch, into);
        }
    }
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

/// Whether projecting this action yields a schema describing that action alone.
///
/// `project_operation_schema` narrows to a `oneOf` branch when the source tool
/// declares one. A tool that hand-declares a flat properties bag with an action
/// enum declares no branches, so its "projection" is the whole union of every
/// action's fields — `manage_attachments` is the specimen, see `a193c01` — and
/// a branch whose selector enum lists several actions is shared by all of them.
///
/// Naming a shared schema's fields as one action's own would advertise
/// `manage_attachments.detach` as accepting `record_id`, which its
/// `deny_unknown_fields` handler rejects, and would star nothing on an action
/// that has required fields. Deciding it here, from the source schema, rather
/// than by comparing projected results, keeps the answer independent of which
/// operations a given surface happens to route.
fn projection_is_action_specific(
    schema: &Value,
    selector: Option<&Selector>,
    selector_specific_schema: bool,
) -> bool {
    // A registered per-operation schema is action-specific by construction, and
    // a single-operation source tool has no siblings to be confused with.
    if selector_specific_schema {
        return true;
    }
    let Some(selector) = selector else {
        return true;
    };
    let Some(branches) = schema.get("oneOf").and_then(Value::as_array) else {
        return false;
    };
    branches.iter().any(|branch| {
        let Some(property) = branch
            .get("properties")
            .and_then(|properties| properties.get(&selector.field))
        else {
            return false;
        };
        if property.get("const").and_then(Value::as_str) == Some(selector.value.as_str()) {
            return true;
        }
        // A branch whose selector enum names several actions is a declaration
        // that those actions share one contract — `manage_relationships` groups
        // `read` and `why` this way, and the branch is exactly each one's
        // fields. That is not the flat-bag case: there the tool declares no
        // branches at all, so the projection is the union of actions whose
        // contracts genuinely differ.
        property
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.as_str() == Some(selector.value.as_str()))
            })
    })
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

/// Hoist a `run_key`/`parent_key` nested under `arguments` to the executor
/// envelope, preserving run correlation.
///
/// Transactional: normalization runs on a clone and the caller's envelope is
/// assigned only on full success, so a rejection/repair is always built from
/// the envelope the caller actually sent — never from a partially hoisted
/// one (e.g. `run_key` moved before a later `parent_key` error is found).
///
/// Returns `Ok(true)` when the envelope was mutated (hoisted or deduped),
/// `Ok(false)` when there was nothing nested to do, and `Err(diagnostic)`
/// when the call must be rejected rather than silently reinterpreted:
/// a non-string nested key, or any envelope key (including null) beside a
/// nested key that is not the identical string. Only a missing envelope key
/// hoists; only an identical string dedupes.
fn hoist_nested_routing_keys(envelope: &mut Value) -> std::result::Result<bool, String> {
    // Preflight before the transactional clone: the common case carries no
    // nested routing keys, and must not pay for an envelope-wide clone.
    let needs_hoist = envelope
        .get("arguments")
        .and_then(Value::as_object)
        .is_some_and(|arguments| {
            arguments.contains_key("run_key") || arguments.contains_key("parent_key")
        });
    if !needs_hoist {
        return Ok(false);
    }
    let mut candidate = envelope.clone();
    let mut hoisted = false;
    for field in ["run_key", "parent_key"] {
        let nested = candidate
            .get("arguments")
            .and_then(Value::as_object)
            .and_then(|arguments| arguments.get(field))
            .cloned();
        let Some(nested_value) = nested else {
            continue;
        };
        let outer = candidate.get(field).cloned();
        match (outer, nested_value) {
            (None, Value::String(nested_key)) => {
                if let Some(envelope_object) = candidate.as_object_mut() {
                    envelope_object.insert(field.into(), Value::String(nested_key));
                }
                if let Some(arguments_object) = candidate
                    .get_mut("arguments")
                    .and_then(Value::as_object_mut)
                {
                    arguments_object.remove(field);
                }
                hoisted = true;
            }
            (None, nested_value) => {
                let _ = nested_value;
                return Err(misplaced_routing_key_diagnostic(field, false));
            }
            (Some(outer_value), Value::String(nested_key))
                if outer_value == Value::String(nested_key.clone()) =>
            {
                if let Some(arguments_object) = candidate
                    .get_mut("arguments")
                    .and_then(Value::as_object_mut)
                {
                    arguments_object.remove(field);
                }
                hoisted = true;
            }
            (Some(_), _) => {
                return Err(misplaced_routing_key_diagnostic(field, true));
            }
        }
    }
    if hoisted {
        *envelope = candidate;
    }
    Ok(hoisted)
}

fn misplaced_routing_key_diagnostic(field: &str, conflict: bool) -> String {
    if conflict {
        format!(
            "arguments.{field} conflicts with envelope {field}: remove the nested key and keep the envelope {field}; hoisting must not silently drop a conflicting key."
        )
    } else {
        format!(
            "arguments.{field} is misplaced: put {field} on the executor envelope alongside operation and arguments; the nested value must be a string {field}."
        )
    }
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

fn normalized_executor_arguments(operation: &str, envelope: &Value) -> Result<Value> {
    let operation_arguments = envelope
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let normalized = crate::mcp::record_ref::normalize_operation_record_selector(
        operation,
        operation_arguments,
    )?;
    let mut envelope = envelope.clone();
    envelope
        .as_object_mut()
        .ok_or_else(|| Error::engine("executor arguments must be an object"))?
        .insert("arguments".into(), normalized);
    Ok(envelope)
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

/// Bound on any caller-supplied value echoed in a repair block, in
/// characters. Rejections stay proportional to the mistake, never to the
/// payload that carried it.
const REPAIR_VALUE_CHAR_LIMIT: usize = 200;

/// The offending value at `failing_pointer` within `envelope`, bounded to
/// [`REPAIR_VALUE_CHAR_LIMIT`] characters. Strings truncate to that many
/// chars (char boundaries, never mid-codepoint); non-strings serialise
/// compactly and either travel as-is when the serialisation already fits or
/// travel as the truncated serialisation string. Returns `None` when the
/// pointer does not resolve — the expected case for a required-field-missing
/// failure, which names a field that is absent.
fn repair_failing_value(failing_pointer: &str, envelope: &Value) -> Option<Value> {
    let value = envelope.pointer(failing_pointer)?;
    let (value, length, truncated) = match value {
        Value::String(text) => {
            let length = text.chars().count();
            if length <= REPAIR_VALUE_CHAR_LIMIT {
                (json!(text), length, false)
            } else {
                let truncated_text: String = text.chars().take(REPAIR_VALUE_CHAR_LIMIT).collect();
                (json!(truncated_text), length, true)
            }
        }
        _ => {
            let serialised = serde_json::to_string(value).unwrap_or_default();
            let length = serialised.chars().count();
            if length <= REPAIR_VALUE_CHAR_LIMIT {
                (value.clone(), length, false)
            } else {
                let truncated_text: String =
                    serialised.chars().take(REPAIR_VALUE_CHAR_LIMIT).collect();
                (json!(truncated_text), length, true)
            }
        }
    };
    Some(json!({
        "pointer": failing_pointer,
        "value": value,
        "length": length,
        "truncated": truncated,
    }))
}

fn escape_repair_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

fn unescape_repair_pointer_segment(segment: &str) -> String {
    segment.replace("~1", "/").replace("~0", "~")
}

fn split_repair_pointer(pointer: &str) -> Vec<String> {
    pointer
        .split('/')
        .skip(1)
        .map(unescape_repair_pointer_segment)
        .collect()
}

/// Cap on correction entries in one repair block; overflow states its total
/// beside the list instead of growing it.
const REPAIR_MAX_CORRECTIONS: usize = 20;

/// One raw diff output: a leaf to set, or a pointer to delete.
enum RawCorrection {
    Set { pointer: String, value: Value },
    Remove { pointer: String },
}

/// One leaf of `corrected` that is new or changed becomes one raw `Set`;
/// objects and arrays always expand to their scalar leaves, so no entry ever
/// carries a subtree — including across a type change, where the old and new
/// shapes share no structure to diff.
fn push_repair_correction_leaf(pointer: String, value: &Value, out: &mut Vec<RawCorrection>) {
    match value {
        Value::Object(map) => {
            if map.is_empty() {
                out.push(RawCorrection::Set {
                    pointer,
                    value: value.clone(),
                });
            } else {
                for (key, child) in map {
                    push_repair_correction_leaf(
                        format!("{pointer}/{}", escape_repair_pointer_segment(key)),
                        child,
                        out,
                    );
                }
            }
        }
        Value::Array(items) => {
            if items.is_empty() {
                out.push(RawCorrection::Set {
                    pointer,
                    value: value.clone(),
                });
            } else {
                for (index, child) in items.iter().enumerate() {
                    push_repair_correction_leaf(format!("{pointer}/{index}"), child, out);
                }
            }
        }
        _ => out.push(RawCorrection::Set {
            pointer,
            value: value.clone(),
        }),
    }
}

/// Diff `corrected` against the caller's `envelope`: one raw entry per leaf
/// that differs or is newly present in the corrected version, plus one
/// removal per deleted pointer.
fn diff_repair_envelopes(
    envelope: &Value,
    corrected: &Value,
    pointer: String,
    out: &mut Vec<RawCorrection>,
) {
    match (envelope, corrected) {
        (Value::Object(previous), Value::Object(next)) => {
            for (key, next_value) in next {
                let child = format!("{pointer}/{}", escape_repair_pointer_segment(key));
                match previous.get(key) {
                    Some(previous_value) => {
                        diff_repair_envelopes(previous_value, next_value, child, out);
                    }
                    None => push_repair_correction_leaf(child, next_value, out),
                }
            }
            for key in previous.keys() {
                if !next.contains_key(key) {
                    out.push(RawCorrection::Remove {
                        pointer: format!("{pointer}/{}", escape_repair_pointer_segment(key)),
                    });
                }
            }
        }
        (Value::Array(previous), Value::Array(next)) => {
            let shared = previous.len().min(next.len());
            for (index, (previous_item, next_item)) in
                previous.iter().zip(next.iter()).enumerate().take(shared)
            {
                diff_repair_envelopes(previous_item, next_item, format!("{pointer}/{index}"), out);
            }
            for (index, next_item) in next.iter().enumerate().skip(shared) {
                push_repair_correction_leaf(format!("{pointer}/{index}"), next_item, out);
            }
            for index in next.len()..previous.len() {
                out.push(RawCorrection::Remove {
                    pointer: format!("{pointer}/{index}"),
                });
            }
        }
        _ => {
            if envelope != corrected {
                push_repair_correction_leaf(pointer, corrected, out);
            }
        }
    }
}

/// Index every value the caller's own envelope carries (compact
/// serialisation to pointer, first wins) so a correction whose value already
/// exists in the envelope can be emitted as a move by reference instead of an
/// echo. Deterministic: object keys iterate sorted, arrays in order.
fn index_envelope_values(envelope: &Value) -> std::collections::BTreeMap<String, String> {
    fn walk(node: &Value, pointer: String, out: &mut std::collections::BTreeMap<String, String>) {
        if !pointer.is_empty() {
            out.entry(serde_json::to_string(node).unwrap_or_default())
                .or_insert(pointer.clone());
        }
        match node {
            Value::Object(map) => {
                for (key, child) in map {
                    walk(
                        child,
                        format!("{pointer}/{}", escape_repair_pointer_segment(key)),
                        out,
                    );
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    walk(child, format!("{pointer}/{index}"), out);
                }
            }
            _ => {}
        }
    }
    let mut index = std::collections::BTreeMap::new();
    walk(envelope, String::new(), &mut index);
    index
}

/// Order correction entries for a stable shape and safe application.
/// Segments compare numerically when both sides parse as indices
/// (`/arr/10` sorts after `/arr/2`); removals off the same array sort
/// descending by index so applying them in order never shifts a later
/// target.
fn compare_correction_entries(left: &Value, right: &Value) -> std::cmp::Ordering {
    let left_pointer = left.get("pointer").and_then(Value::as_str).unwrap_or("");
    let right_pointer = right.get("pointer").and_then(Value::as_str).unwrap_or("");
    let left_segments = split_repair_pointer(left_pointer);
    let right_segments = split_repair_pointer(right_pointer);
    let shared = left_segments.len().min(right_segments.len());
    for (index, (left_segment, right_segment)) in left_segments
        .iter()
        .zip(right_segments.iter())
        .enumerate()
        .take(shared)
    {
        let last = index + 1 == left_segments.len() && index + 1 == right_segments.len();
        if last {
            let both_remove = left.get("remove").and_then(Value::as_bool) == Some(true)
                && right.get("remove").and_then(Value::as_bool) == Some(true);
            if let (Ok(left_index), Ok(right_index)) = (
                left_segment.parse::<usize>(),
                right_segment.parse::<usize>(),
            ) {
                if both_remove && left_index != right_index {
                    return right_index.cmp(&left_index);
                }
                if left_index != right_index {
                    return left_index.cmp(&right_index);
                }
                continue;
            }
        } else if let (Ok(left_index), Ok(right_index)) = (
            left_segment.parse::<usize>(),
            right_segment.parse::<usize>(),
        ) {
            if left_index != right_index {
                return left_index.cmp(&right_index);
            }
            continue;
        }
        if left_segment != right_segment {
            return left_segment.cmp(right_segment);
        }
    }
    left_segments.len().cmp(&right_segments.len())
}

/// A built correction list: the entries, whether any value had to be
/// truncated to the bound (which demotes `retry_ready`), and the pre-cap
/// entry count.
struct BuiltCorrections {
    entries: Vec<Value>,
    truncated: bool,
    total: usize,
}

/// The minimal patch list that turns the caller's own envelope into the
/// corrected one. Moves — values the caller already sent at another pointer —
/// travel as `{"pointer", "from"}` with no value at all; `from` always resolves
/// against the envelope the caller submitted, never against the partially
/// patched result, so a move whose source is also removed still resolves; genuinely new values
/// travel literally up to [`REPAIR_VALUE_CHAR_LIMIT`] serialised chars and as
/// a disclosed truncation beyond it; removals travel as
/// `{"pointer", "value": null, "remove": true}`. Capped at
/// [`REPAIR_MAX_CORRECTIONS`] entries.
fn repair_corrections(envelope: &Value, corrected: &Value) -> BuiltCorrections {
    let mut raw = Vec::new();
    diff_repair_envelopes(envelope, corrected, String::new(), &mut raw);
    let sources = index_envelope_values(envelope);
    let mut truncated = false;
    let mut entries = Vec::with_capacity(raw.len());
    for correction in raw {
        match correction {
            RawCorrection::Remove { pointer } => {
                entries.push(json!({"pointer": pointer, "value": Value::Null, "remove": true}));
            }
            RawCorrection::Set { pointer, value } => {
                let serialised = serde_json::to_string(&value).unwrap_or_default();
                let moved = sources
                    .get(&serialised)
                    .filter(|source| *source != &pointer);
                if let Some(source) = moved {
                    entries.push(json!({"pointer": pointer, "from": source}));
                } else if serialised.chars().count() <= REPAIR_VALUE_CHAR_LIMIT {
                    entries.push(json!({"pointer": pointer, "value": value}));
                } else {
                    truncated = true;
                    entries.push(json!({
                        "pointer": pointer,
                        "value": serialised.chars().take(REPAIR_VALUE_CHAR_LIMIT).collect::<String>(),
                        "length": serialised.chars().count(),
                        "truncated": true,
                    }));
                }
            }
        }
    }
    entries.sort_by(compare_correction_entries);
    let total = entries.len();
    entries.truncate(REPAIR_MAX_CORRECTIONS);
    BuiltCorrections {
        entries,
        truncated,
        total,
    }
}

/// Whether a built patch list can be applied mechanically to reproduce the
/// corrected envelope, and so whether the repair may advertise `retry_ready`.
/// A truncated value cannot be written back, and a capped list omits entries
/// the caller would need; in both cases the corrections still describe the
/// fault but no longer constitute an automatic fix.
fn corrections_are_applicable(built: &BuiltCorrections) -> bool {
    !built.truncated && built.total <= REPAIR_MAX_CORRECTIONS
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
    let selector_shape_invalid = envelope
        .get("arguments")
        .and_then(|arguments| {
            crate::mcp::record_ref::invalid_operation_record_selector_diagnostic(
                &contract.operation,
                arguments,
            )
        })
        .is_some();
    let is_execution_error = error_class == "execution_error";
    let is_validation_error = matches!(
        error_class,
        "validation_failure" | "preparation_validation_failed"
    );
    let corrected_envelope = cue
        .corrected_envelope
        .filter(|corrected| is_validation_error && corrected != envelope);
    // A patch list that was truncated or capped still describes the fault, but
    // it is no longer mechanically applicable — a truncated value cannot be
    // written back, and a capped list omits entries the caller would need — so
    // it must not advertise an automatic fix in either case.
    let mut retry_ready = false;
    let mut built_corrections: Option<BuiltCorrections> = None;
    if let Some(corrected) = corrected_envelope.as_ref() {
        let built = repair_corrections(envelope, corrected);
        retry_ready = corrections_are_applicable(&built);
        built_corrections = Some(built);
    }
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
    //
    // An execution error is never one of those cases. Its `expected_shape`
    // says in as many words that the envelope matched the disclosed contract,
    // and the source rejected state, authorization or runtime semantics
    // instead — so the caller cannot repair it by reshaping the envelope, and
    // the schema it already satisfied tells it nothing. Sending the full
    // document there contradicts the sentence beside it and, on a stale-write
    // conflict, made the rejection several times the size of the request that
    // provoked it. Point at `describe_operation` like any other localised
    // failure.
    let localised = is_execution_error || cue.localised;
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
        let reason = if is_execution_error {
            "the envelope matched the disclosed contract, so the contract cannot explain this failure; the full operation contract is omitted here"
        } else {
            "expected_shape names the failing constraint and the correction it admits; the full operation contract is omitted here"
        };
        repair["contract_reference"] = json!({
            "reason": reason,
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
    repair["retry_ready"] = json!(retry_ready);
    // The caller holds the request it just sent, so the repair never echoes
    // the payload back: no `preserved_intent`, no `corrected_envelope`, no
    // `retry`. What travels instead is bounded by the mistake, not the
    // payload: the offending value at `failing_pointer` (capped at
    // `REPAIR_VALUE_CHAR_LIMIT` chars) and the minimal patch list that turns
    // the caller's own envelope into the corrected one. Moves travel by
    // reference (`from`); genuinely new values travel literally up to the
    // same bound, disclosed when truncated.
    // Descended composite cues stay value-free end to end (the diagnostic
    // above is masked for composites, and no offending value travels here),
    // mirroring the read-side selector redaction. Direct cues keep their
    // existing bounded `failing_value` behavior.
    if !is_execution_error && !selector_shape_invalid && !cue.suppress_failing_value {
        if let Some(failing_value) = repair_failing_value(&cue.failing_pointer, envelope) {
            repair["failing_value"] = failing_value;
        }
    }
    if let Some(built) = built_corrections {
        if built.total > REPAIR_MAX_CORRECTIONS {
            repair["corrections_total"] = json!(built.total);
        }
        repair["corrections"] = Value::Array(built.entries);
    }
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
    /// True when the cue was produced by descending into a `oneOf`/`anyOf`
    /// composite to name the best branch's leaf failure. Descended cues stay
    /// value-free (no `failing_value`): the read-side selector diagnostic
    /// already sets that precedent, and the offending value on a write path
    /// can carry record content. Direct (non-composite) cues keep their
    /// existing bounded `failing_value` behavior.
    suppress_failing_value: bool,
}

/// One leaf failure, owned so that top-level borrow lifetimes and the
/// `'static` nested `context` errors can share one selection without lifetime
/// plumbing. A single conversion (`leaf_from_error`) and a single
/// reason-mapping block serve both the direct and the descended paths.
#[derive(Clone)]
struct SelectedLeaf {
    instance_path: String,
    schema_path: String,
    keyword: String,
    rank: u8,
    unexpected_sorted: Vec<String>,
    required_property: Option<String>,
}

/// Specificity rank for leaf failures: a rejected property name is the most
/// actionable (it pairs with the accepted-name list), a missing required
/// field next, typed/valued constraints after that, and everything else
/// (not/falseSchema/composite leftovers) last.
fn selected_leaf_rank(keyword: &str) -> u8 {
    match keyword {
        "additionalProperties" | "unevaluatedProperties" => 0,
        "required" => 1,
        "type" | "enum" | "const" | "minItems" | "minimum" | "exclusiveMinimum" | "maximum"
        | "exclusiveMaximum" | "minLength" | "maxLength" | "pattern" | "format" => 2,
        _ => 3,
    }
}

/// Single conversion from a borrowed validator error to an owned leaf.
/// `sort_unexpected` sorts the rejected-name list for deterministic reporting
/// inside composite selection only; the direct (non-composite) path passes
/// `false` to preserve the validator's existing `unexpected.first()`
/// ordering exactly.
fn leaf_from_error(error: &jsonschema::ValidationError<'_>, sort_unexpected: bool) -> SelectedLeaf {
    use jsonschema::error::ValidationErrorKind;
    let keyword = error.kind().keyword().to_string();
    let (unexpected_sorted, required_property) = match error.kind() {
        ValidationErrorKind::AdditionalProperties { unexpected }
        | ValidationErrorKind::UnevaluatedProperties { unexpected } => {
            if sort_unexpected {
                let mut sorted = unexpected.clone();
                sorted.sort();
                (sorted, None)
            } else {
                (unexpected.first().cloned().into_iter().collect(), None)
            }
        }
        ValidationErrorKind::Required { property } => {
            (Vec::new(), property.as_str().map(str::to_string))
        }
        _ => (Vec::new(), None),
    };
    SelectedLeaf {
        instance_path: error.instance_path().as_str().to_string(),
        schema_path: error.schema_path().as_str().to_string(),
        rank: selected_leaf_rank(&keyword),
        keyword,
        unexpected_sorted,
        required_property,
    }
}

/// Actual violation count for a branch: each rejected property name counts
/// separately (one `additionalProperties` aggregate can reject several
/// names), every other leaf counts once.
fn branch_violation_count(leaves: &[SelectedLeaf]) -> usize {
    leaves
        .iter()
        .map(|leaf| match leaf.keyword.as_str() {
            "additionalProperties" | "unevaluatedProperties" => leaf.unexpected_sorted.len().max(1),
            _ => 1,
        })
        .sum()
}

/// Resolve one validator error to the leaves it contributes to its parent
/// branch: a nested `oneOf`/`anyOf` contributes its own best branch's
/// leaves (selected recursively), any other error contributes itself.
/// `oneOf` with several valid branches is deliberately left generic.
fn resolve_error_leaves(error: &jsonschema::ValidationError<'_>) -> Vec<SelectedLeaf> {
    use jsonschema::error::ValidationErrorKind;
    match error.kind() {
        ValidationErrorKind::OneOfNotValid { context } | ValidationErrorKind::AnyOf { context } => {
            select_composite_best(context).unwrap_or_default()
        }
        _ => vec![leaf_from_error(error, true)],
    }
}

/// Select the best branch of a `oneOf`/`anyOf` context and return its
/// resolved leaves. Branch order: fewest actual violations first, then most
/// specific (an unexpected-property branch beats a missing-key branch at
/// equal counts), then lowest branch index. The deterministic tie-break is
/// part of the contract: ambiguous branches report the first branch.
fn select_composite_best(
    context: &[Vec<jsonschema::ValidationError<'static>>],
) -> Option<Vec<SelectedLeaf>> {
    let mut best_key: Option<(usize, u8, usize)> = None;
    let mut best_leaves: Vec<SelectedLeaf> = Vec::new();
    let mut found = false;
    for (index, branch_errors) in context.iter().enumerate() {
        let mut leaves = Vec::new();
        for branch_error in branch_errors {
            leaves.extend(resolve_error_leaves(branch_error));
        }
        if leaves.is_empty() {
            continue;
        }
        let count = branch_violation_count(&leaves);
        let specificity = leaves.iter().map(|leaf| leaf.rank).min().unwrap_or(3);
        let key = (count, specificity, index);
        if !found || key < best_key.unwrap_or((usize::MAX, u8::MAX, usize::MAX)) {
            best_key = Some(key);
            best_leaves = leaves;
            found = true;
        }
    }
    if found {
        Some(best_leaves)
    } else {
        None
    }
}

/// Best single leaf within a winning branch: unexpected field, missing
/// required field, typed/valued constraints, then anything else; ties break
/// by instance path, then schema path.
fn best_leaf_in_branch(mut leaves: Vec<SelectedLeaf>) -> Option<SelectedLeaf> {
    leaves.sort_by(|a, b| {
        (a.rank, &a.instance_path, &a.schema_path).cmp(&(b.rank, &b.instance_path, &b.schema_path))
    });
    leaves.into_iter().next()
}

fn repair_cue(
    contract: &OperationContract,
    envelope: &Value,
    diagnostic: Option<&str>,
    hosted_authority: Option<&dyn HostedExecutorAuthority>,
) -> RepairCue {
    // A nested routing-key rejection from the hoist helper names its own
    // field in the diagnostic (`arguments.run_key ...` / `arguments.parent_key
    // ...`). Honor it ahead of every other derivation: the schema
    // `unexpected.first()` below follows caller key order and can name the
    // other nested key when both are present, and the format pre-check would
    // otherwise override the actual rejection entirely.
    let routing_rejected = ["run_key", "parent_key"].iter().copied().find(|field| {
        diagnostic.is_some_and(|diagnostic| diagnostic.starts_with(&format!("arguments.{field}")))
    });
    if routing_rejected.is_none()
        && contract.surface == ExecutorSurface::Ordinary
        && !write_operations::requires_plan(&contract.executor, &contract.operation)
    {
        let mut format_arguments = envelope.clone();
        if render::take_format(&contract.source_tool, &mut format_arguments).is_err() {
            let mut expected_shape = render::format_schema(&contract.source_tool);
            expected_shape["supported_values"] = expected_shape["enum"].clone();
            expected_shape["description"] = json!(
                "Select a supported format at the executor envelope /format, or omit the field to preserve this operation's default representation."
            );
            return RepairCue {
                reason_code: if envelope["format"].is_string() {
                    "unsupported_value"
                } else {
                    "wrong_type"
                },
                failing_pointer: "/format".into(),
                expected_shape,
                localised: true,
                corrected_envelope: None,
                suppress_failing_value: false,
            };
        }
    }
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
    let mut descended = false;
    if let Ok(validator) = jsonschema::validator_for(&contract.input_schema) {
        if let Some(error) = validator.iter_errors(&operation_arguments).next() {
            use jsonschema::error::ValidationErrorKind;
            // Best-branch descent for `oneOf`/`anyOf`: the validator's first
            // error for a branch combinator is the whole combinator at
            // `/arguments`, which names no field. Use the nested `context`
            // errors (one entry per branch, full pointers retained) to pick
            // the branch the caller most likely meant, then report that
            // branch's best leaf failure with its pointer and accepted names.
            //
            // Branch order: fewest actual violations first (each rejected
            // property name counts separately, not one per aggregate), then
            // most specific (an unexpected-property branch beats a
            // missing-key branch at equal counts), then lowest branch index.
            // The index tie-break is part of the contract: ambiguous branches
            // report the first branch deterministically. Leaf order within
            // the winner: unexpected field, missing required field,
            // typed/valued constraints, then anything else; ties break by
            // instance path, then schema path. Inside composite selection a
            // multi-element unexpected list reports its lexicographically
            // smallest name so the choice does not depend on caller key
            // order; the direct path keeps validator ordering. `oneOf` with
            // several valid branches stays generic (but value-free) rather
            // than naming one match. Nested `oneOf`/`anyOf` select their own
            // best branch recursively; branches are never flattened across
            // mutually exclusive alternatives.
            let descended_leaf: Option<SelectedLeaf> =
                if let ValidationErrorKind::OneOfNotValid { context }
                | ValidationErrorKind::AnyOf { context } = error.kind()
                {
                    select_composite_best(context).and_then(best_leaf_in_branch)
                } else {
                    None
                };
            // Single reason mapping for both paths: the direct path converts
            // the top error preserving validator ordering, the descended
            // path uses the winning branch's leaf (sorted inside composite
            // selection only). A multiply-valid `oneOf` stays generic but
            // suppresses values like any composite cue: its diagnostic is
            // masked and its whole-object value must not travel.
            let multiple_valid =
                matches!(error.kind(), ValidationErrorKind::OneOfMultipleValid { .. });
            let leaf: SelectedLeaf = match descended_leaf {
                Some(leaf) => {
                    descended = true;
                    leaf
                }
                None => leaf_from_error(&error, false),
            };
            if multiple_valid {
                descended = true;
            }
            failing_pointer = format!("/arguments{}", leaf.instance_path);
            reason_code = match leaf.keyword.as_str() {
                "required" => {
                    if let Some(property) = leaf.required_property.as_deref() {
                        failing_pointer.push('/');
                        failing_pointer.push_str(&escape_json_pointer(property));
                    }
                    "required_field_missing"
                }
                "additionalProperties" | "unevaluatedProperties" => {
                    if let Some(property) = leaf.unexpected_sorted.first() {
                        failing_pointer.push('/');
                        failing_pointer.push_str(&escape_json_pointer(property));
                    }
                    "unexpected_field"
                }
                "type" => "wrong_type",
                "enum" | "const" => "unsupported_value",
                "minItems" => "array_too_short",
                "minimum" | "exclusiveMinimum" => "value_too_small",
                "maximum" | "exclusiveMaximum" => "value_too_large",
                _ => "schema_constraint_failed",
            };
            let schema_pointer = leaf.schema_path.clone();
            let constraint = contract.input_schema.pointer(&schema_pointer);
            let keyword = leaf.keyword.clone();
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
            if matches!(
                keyword.as_str(),
                "additionalProperties" | "unevaluatedProperties"
            ) {
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
    if let Some(field) = routing_rejected {
        // The helper rejected this exact field; the schema derivation above
        // may have named the other nested key instead.
        failing_pointer = format!("/arguments/{field}");
        reason_code = "unexpected_field";
    }
    if contract.surface == ExecutorSurface::Ordinary
        && !write_operations::requires_plan(&contract.executor, &contract.operation)
        && failing_pointer == "/arguments/format"
    {
        expected_shape["description"] = json!(
            "arguments.format is misplaced: put format on the executor envelope alongside operation, arguments and run_key. Omission preserves the operation's default representation."
        );
        expected_shape["supported_values"] =
            render::format_schema(&contract.source_tool)["enum"].clone();
        if contract.executor == "records_read" && contract.operation == "get_record" {
            // Show placement without echoing a potentially large caller payload.
            // The existing correction patches preserve the actual ids/run key.
            expected_shape["request_example"] = json!({
                "operation":"get_record",
                "arguments":{"ids":["<record-reference>"]},
                "format":"json",
                "run_key":"<bootstrap-run-key>"
            });
        }
    }
    // `run_key`/`parent_key` ride the envelope, not the operation arguments:
    // the inner schemas strip them (`strip_routing_fields`), so a nested key
    // fails as a generic unknown property. Name the envelope placement
    // directly, mirroring the `format` misplacement repair. This covers any
    // path that reaches validation with the keys still nested (conflicts,
    // non-strings, or callers that bypassed the hoist); the hoisted path
    // itself proceeds without failing.
    if failing_pointer == "/arguments/run_key" {
        expected_shape["description"] = json!(
            "arguments.run_key is misplaced: put run_key on the executor envelope alongside operation and arguments."
        );
    } else if failing_pointer == "/arguments/parent_key" {
        expected_shape["description"] = json!(
            "arguments.parent_key is misplaced: put parent_key on the executor envelope alongside operation, arguments and run_key."
        );
    }
    RepairCue {
        reason_code,
        failing_pointer,
        expected_shape,
        localised,
        corrected_envelope: minimal_corrected_envelope(contract, envelope, hosted_authority),
        suppress_failing_value: descended,
    }
}

/// Value-free rendering of a schema validation failure for the diagnostic
/// string. Composite `oneOf`/`anyOf` failures echo the whole instance in
/// their `Display` (the entire arguments object, record content included),
/// which then feeds `structuredContent.error`, the text block, and
/// `repair.diagnostic`. Mask those to the `value` placeholder so a descended
/// composite cue stays value-free end to end; direct leaf failures keep
/// their existing rendering.
fn schema_error_text(error: &jsonschema::ValidationError<'_>) -> String {
    use jsonschema::error::ValidationErrorKind;
    match error.kind() {
        ValidationErrorKind::OneOfNotValid { .. }
        | ValidationErrorKind::AnyOf { .. }
        | ValidationErrorKind::OneOfMultipleValid { .. } => error.masked().to_string(),
        _ => error.to_string(),
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
    // A non-string routing key must never be advertised as an automatic
    // correction: moving a number/bool to the envelope would read as
    // retry_ready, and the retry would then succeed with correlation
    // silently absent (envelope keys only attach as strings). This covers
    // both a nested non-string lifted here and a pre-existing non-string
    // envelope key the correction would otherwise preserve.
    for field in ["run_key", "parent_key"] {
        if let Some(value) = corrected.get(field) {
            if !value.is_string() {
                return None;
            }
        }
    }

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
    if contract.surface == ExecutorSurface::Ordinary
        && !write_operations::requires_plan(&contract.executor, &contract.operation)
    {
        // A moved selector must be executable, not merely absent from the
        // operation arguments. Do not advertise an invalid format as retry-ready.
        let mut translated = translate_arguments(contract, &corrected).ok()?;
        render::take_format(&contract.source_tool, &mut translated).ok()?;
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

    struct SelectorHostedAuthority {
        pool: sqlx::SqlitePool,
    }

    impl HostedPlanCatalogue for SelectorHostedAuthority {
        fn executor_plan_pool(&self) -> &sqlx::SqlitePool {
            &self.pool
        }
    }

    impl HostedExecutorAuthority for SelectorHostedAuthority {
        fn validate_membership_write(&self, _arguments: Value) -> Result<()> {
            Ok(())
        }

        fn prepare_membership_write<'a>(
            &'a self,
            _db: &'a crate::Db,
            _caller: &'a Caller,
            _arguments: Value,
        ) -> BoxFuture<'a, Result<HostedMembershipPreparation>> {
            Box::pin(async { Err(Error::engine("selector fixture never prepares a write")) })
        }
    }

    struct SelectorHostedKeys;

    impl HostedPlanKeyProvider for SelectorHostedKeys {
        fn active_key_id(&self) -> BoxFuture<'static, Result<String>> {
            Box::pin(async { Ok("selector-fixture-key".into()) })
        }

        fn seal(&self, key_id: String, _payload: Value) -> BoxFuture<'static, Result<String>> {
            Box::pin(async move { Ok(format!("{key_id}:fixture-signature")) })
        }

        fn verify(
            &self,
            key_id: String,
            _payload: Value,
            signature: String,
        ) -> BoxFuture<'static, Result<()>> {
            Box::pin(async move {
                if signature == format!("{key_id}:fixture-signature") {
                    Ok(())
                } else {
                    Err(Error::engine("selector fixture signature mismatch"))
                }
            })
        }
    }

    fn registry() -> Arc<ToolRegistry> {
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        Arc::new(registry)
    }

    async fn call_records_read(
        server: &ExecutorPrototypeStdioServer,
        id: i64,
        operation: &str,
        arguments: Value,
    ) -> Value {
        server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":id,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":operation,
                        "arguments":arguments,
                        "run_key":"recordselector-alias-0537ed7"
                    }
                }
            }))
            .await
            .unwrap()
    }

    /// The registry the hosted deployment actually serves, mirrored from the
    /// composition in `held/runtime/src/serve.rs`: builtin and surface tools,
    /// build-enabled experimental tools, allowlisted experimental sources,
    /// snapshot, membership, workspace, and reach when its sidecar is configured.
    /// The snapshot source
    /// is the in-crate `LocalSnapshotSource` and the membership delegate is
    /// non-dispatchable; neither substitution matters here because the
    /// executor catalogue is built from descriptors, never by dispatching.
    /// What must match the shipped shape is engine-availability, so the
    /// membership tool is registered with `register_membership_tool_with`
    /// (which leaves the Sqlite operations executable) and NOT with the
    /// generator-only `register_membership_tool_schema` (whose Sqlite
    /// unavailable marking filters the membership executors out of the
    /// catalogue before the hosted flag is consulted).
    /// The `sql_write` source is registered explicitly here to mirror a
    /// deployment that allowlisted its executor.
    fn hosted_registry() -> Arc<ToolRegistry> {
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        crate::mcp::register_build_enabled_experimental_tools(&mut registry).unwrap();
        crate::mcp::tools::sql_write::register_sql_write_tool(&mut registry).unwrap();
        crate::mcp::register_snapshot_tool(
            &mut registry,
            Arc::new(crate::export::LocalSnapshotSource::new()),
        )
        .unwrap();
        crate::mcp::register_membership_tool_with(
            &mut registry,
            |_db, _caller, _arguments| async {
                Err(Error::engine(
                    "manage_memberships fixture delegate cannot be dispatched",
                ))
            },
        )
        .unwrap();
        // Hosted-only workspace directory, registered executable (not
        // schema-only) so the audit drift guard sees the same action serve
        // exposes.
        crate::mcp::register_workspace_tool_with(&mut registry, |_db, _caller, _arguments| async {
            Err(Error::engine(
                "workspace_read fixture delegate cannot be dispatched",
            ))
        })
        .unwrap();
        // Hosted-only reach tools, registered executable (not schema-only) so
        // the audit drift guard sees the same actions serve exposes once the
        // reach sidecar is configured.
        crate::mcp::register_reach_read_tool_with(
            &mut registry,
            |_db, _caller, _arguments| async {
                Err(Error::engine(
                    "reach_read fixture delegate cannot be dispatched",
                ))
            },
        )
        .unwrap();
        crate::mcp::register_reach_connect_tool_with(
            &mut registry,
            |_db, _caller, _arguments| async {
                Err(Error::engine(
                    "reach_connect fixture delegate cannot be dispatched",
                ))
            },
        )
        .unwrap();
        // Hosted-only authority act transport uses an executable fixture so
        // the audit drift guard sees the operations served by hosting.
        crate::mcp::register_authority_act_tools(
            &mut registry,
            Arc::new(AuthorityActFixtureSource),
        )
        .unwrap();
        Arc::new(registry)
    }

    struct AuthorityActFixtureSource;

    impl crate::mcp::authority_act::AuthorityActSource for AuthorityActFixtureSource {
        fn head(
            &self,
            _db: crate::Db,
            _caller: Caller,
        ) -> BoxFuture<'static, Result<crate::standby::delta_transport::AuthorityActHeadResponseV1>>
        {
            Box::pin(async {
                Err(Error::engine(
                    "authority_act fixture delegate cannot be dispatched",
                ))
            })
        }

        fn delta(
            &self,
            _db: crate::Db,
            _caller: Caller,
            _request: crate::mcp::AuthorityActDeltaRequest,
        ) -> BoxFuture<'static, Result<crate::standby::delta_transport::AuthorityActDeltaResponseV1>>
        {
            Box::pin(async {
                Err(Error::engine(
                    "authority_act fixture delegate cannot be dispatched",
                ))
            })
        }
    }

    /// Drift guard for the executor operation catalogue.
    ///
    /// `build_contracts_for_hosting` can only select operations with a row in
    /// the committed audit projection (`AUDIT`), while dispatch serves
    /// whatever the live `ToolRegistry` registers. Before this guard, any
    /// direct tool or action added after the baseline freeze — e.g.
    /// `read_canvas.export`, registered 5 Sep 2026 but unfrozen until the
    /// re-freeze that landed alongside this guard — was silently unreachable
    /// over the executor facade: no generation step failed and no test
    /// noticed.
    ///
    /// The check is one-directional on purpose: audit rows with no registered
    /// tool (notably the synthetic lens-only `materialize_record` the
    /// candidate generator injects) are allowed, because an unregistered row
    /// advertises nothing. A registered direct call or action with no audit
    /// row is the exact condition that makes an implemented capability
    /// unselectable, so it fails, naming the missing `tool.action` and the
    /// regeneration commands.
    fn selector_action_values(schema: &Value, into: &mut Vec<String>) {
        // The frozen inventory evidences exactly two selector fields across
        // every registered tool (`action` everywhere, plus `intention` on the
        // experimental agent-intent tool). Anything else shaped like a string
        // enum — a value enum such as messaging `expectation`, or a type enum
        // such as `SPINE_TYPES` — is an argument of one operation, not a
        // sub-operation address, and must not be collected here.
        if let Some(object) = schema.as_object() {
            if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                for field in ["action", "intention"] {
                    if let Some(property) = properties.get(field) {
                        if let Some(values) = property.get("enum").and_then(Value::as_array) {
                            into.extend(
                                values.iter().filter_map(Value::as_str).map(str::to_string),
                            );
                        }
                        if let Some(value) = property.get("const").and_then(Value::as_str) {
                            into.push(value.to_string());
                        }
                    }
                }
            }
            for keyword in ["oneOf", "anyOf", "allOf"] {
                if let Some(branches) = object.get(keyword).and_then(Value::as_array) {
                    for branch in branches {
                        selector_action_values(branch, into);
                    }
                }
            }
        } else if let Some(branches) = schema.as_array() {
            for branch in branches {
                selector_action_values(branch, into);
            }
        }
    }

    fn registered_selector_actions(registry: &ToolRegistry) -> Vec<(String, Vec<String>)> {
        let mut tools = Vec::new();
        for spec in registry.specs() {
            let mut actions = Vec::new();
            selector_action_values(&spec.input_schema, &mut actions);
            if actions.is_empty() {
                actions.push("call".to_string());
            }
            actions.sort();
            actions.dedup();
            tools.push((spec.name.clone(), actions));
        }
        tools
    }

    fn missing_audit_rows(
        tools: &[(String, Vec<String>)],
        audited: &std::collections::BTreeSet<(String, String)>,
    ) -> Vec<String> {
        let mut missing = Vec::new();
        for (tool, actions) in tools {
            for action in actions {
                if !audited.contains(&(tool.clone(), action.clone())) {
                    missing.push(format!("{tool}.{action}"));
                }
            }
        }
        missing.sort();
        missing
    }

    fn audit_projection_rows() -> std::collections::BTreeSet<(String, String)> {
        let audit: Audit =
            serde_json::from_str(AUDIT).expect("committed audit projection must parse");
        audit
            .audit_rows
            .into_iter()
            .map(|row| (row.legacy_tool, row.legacy_action))
            .collect()
    }

    #[test]
    fn every_registered_toolspec_action_has_an_audit_row() {
        // The hosted composition is the fullest registry the facade serves:
        // builtin + surface + build-enabled experimental + snapshot +
        // membership. A selector action missing from the committed projection
        // is implemented but unselectable over every hosted MCP client.
        let tools = registered_selector_actions(&hosted_registry());
        assert!(
            !tools.is_empty(),
            "the hosted registry must contain selector tools"
        );
        let missing = missing_audit_rows(&tools, &audit_projection_rows());
        assert!(
            missing.is_empty(),
            "registered ToolSpec action(s) with no row in the committed executor audit \
             — implemented but unreachable over the facade: {}. \
             Re-freeze with `cargo run --manifest-path held/Cargo.toml -p native-evidence \
             --features dev-tools --bin mcp-executor-evidence -- --revision <40-hex> \
             --output docs/evals/mcp-executors/frozen-baseline-inventory.generated.json`, \
             map the new action in scripts/mcp-executor-candidate.mjs `byAction`, \
             then `node scripts/mcp-executor-candidate.mjs <baseline> <audit>` and \
             `node scripts/mcp-executor-audit-projection.mjs`",
            missing.join(", ")
        );
    }

    #[test]
    fn audit_drift_guard_names_a_seeded_gap() {
        // Reproduces the 5 Sep 2026 condition against the live tree: the
        // registry knows `read_canvas.export` but the audit does not. The
        // guard must name the missing action rather than fail opaquely.
        let tools = registered_selector_actions(&hosted_registry());
        assert!(
            tools.iter().any(|(tool, actions)| tool == "read_canvas"
                && actions.iter().any(|action| action == "export")),
            "seed assumption: the live registry must advertise read_canvas.export"
        );
        let mut audited = audit_projection_rows();
        assert!(
            audited.remove(&("read_canvas".to_string(), "export".to_string())),
            "seed assumption: the committed audit must contain read_canvas|export to remove"
        );
        let missing = missing_audit_rows(&tools, &audited);
        assert_eq!(missing, vec!["read_canvas.export".to_string()]);
    }

    #[test]
    fn audit_only_synthetic_tools_need_no_registry_tool() {
        // The candidate generator injects lens-only `materialize_record` rows
        // with no registered ToolKind; the guard direction (registry ->
        // audit) tolerates that by construction. This pins the tolerance so a
        // future refactor cannot silently flip it.
        let registry = hosted_registry();
        assert!(
            audit_projection_rows()
                .contains(&("materialize_record".to_string(), "call".to_string())),
            "the committed audit must retain the synthetic materialize_record row"
        );
        assert!(
            registry.get("materialize_record").is_none(),
            "materialize_record must stay a synthetic audit row, not a registered tool"
        );
    }

    #[test]
    fn read_canvas_export_is_selectable_on_the_ordinary_facade() {
        // End-to-end selectability, not just row presence: the ordinary
        // catalogue the facade serves must route `canvas_read` /
        // `read_canvas.export` to a contract.
        let registry = hosted_registry();
        let catalogue = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            true,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let operations_by_executor = &catalogue.operations_by_executor;
        let contracts = &catalogue.contracts;
        let operations = operations_by_executor
            .get("canvas_read")
            .expect("the ordinary facade must advertise canvas_read");
        assert!(
            operations
                .iter()
                .any(|operation| operation == "read_canvas.export"),
            "canvas_read must select read_canvas.export, selecting only: {}",
            operations.join(", ")
        );
        assert!(
            contracts.contains_key(&("canvas_read".to_string(), "read_canvas.export".to_string())),
            "read_canvas.export must have an ordinary operation contract"
        );
    }

    #[test]
    fn workspace_read_list_is_selectable_on_the_hosted_facade() {
        // End-to-end selectability, not just row presence: the ordinary
        // catalogue the facade serves must route `workspace_read` /
        // `workspace_read.list` to a read contract, and the lens catalogue
        // must carry it too, exactly like `membership_read`.
        let registry = hosted_registry();
        let catalogue = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            true,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let operations = catalogue
            .operations_by_executor
            .get("workspace_read")
            .expect("the ordinary facade must advertise workspace_read");
        assert_eq!(operations, &["workspace_read.list".to_string()]);
        assert_eq!(
            catalogue
                .contracts
                .get(&(
                    "workspace_read".to_string(),
                    "workspace_read.list".to_string()
                ))
                .expect("workspace_read.list must have an ordinary operation contract")
                .access,
            OperationAccess::Read
        );
    }

    #[test]
    fn reach_operations_are_selectable_only_on_the_ordinary_facade() {
        let registry = hosted_registry();
        let catalogue = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            true,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let reads = catalogue
            .operations_by_executor
            .get("reach_read")
            .expect("configured hosted reach must advertise reach_read");
        assert_eq!(
            reads,
            &[
                "reach_read.list_linear_projects".to_string(),
                "reach_read.recent_activity".to_string(),
                "reach_read.search_notion".to_string(),
                "reach_read.search_slack".to_string(),
                "reach_read.source_status".to_string(),
            ]
        );
        assert_eq!(
            catalogue.operations_by_executor.get("reach_connect"),
            Some(&vec!["connect_source".to_string()])
        );
        assert_eq!(
            catalogue
                .contracts
                .get(&("reach_connect".to_string(), "connect_source".to_string()))
                .expect("reach connect contract")
                .access,
            OperationAccess::Mutation
        );

        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        assert!(audit
            .audit_rows
            .iter()
            .filter(|row| row.legacy_tool.starts_with("reach_"))
            .all(|row| row.availability == ["ordinary"] && row.candidate_plan_policy == "direct"));
        assert!(audit.candidate_surfaces.stable.lens.descriptors.iter().all(
            |descriptor| !matches!(
                descriptor["name"].as_str(),
                Some("reach_read" | "reach_connect")
            )
        ));
    }

    /// Applies a repair `corrections` list to the caller's own envelope, the
    /// way a caller patches its payload locally. Entries with `"remove": true`
    /// delete the pointer; entries with `"from"` copy the value the caller
    /// already sent at that source pointer; every other entry sets its value.
    /// `from` sources resolve against the submitted envelope, not the
    /// half-patched one, so a move followed by its source removal still copies
    /// the original bytes. Test-only mirror of the documented patch semantics.
    fn apply_test_corrections(envelope: &Value, corrections: &[Value]) -> Value {
        fn unescape(segment: &str) -> String {
            segment.replace("~1", "/").replace("~0", "~")
        }
        fn resolve<'a>(root: &'a Value, pointer: &str) -> &'a Value {
            let mut target = root;
            for segment in pointer.split('/').skip(1).map(unescape) {
                target = match segment.parse::<usize>() {
                    Ok(index) => &target.as_array().unwrap()[index],
                    Err(_) => &target.as_object().unwrap()[&segment],
                };
            }
            target
        }
        fn descend<'a>(target: &'a mut Value, segment: &'a str) -> &'a mut Value {
            if let Ok(index) = segment.parse::<usize>() {
                if !target.is_array() {
                    *target = Value::Array(Vec::new());
                }
                let items = target.as_array_mut().unwrap();
                while items.len() <= index {
                    items.push(Value::Null);
                }
                return &mut items[index];
            }
            if !target.is_object() {
                *target = Value::Object(serde_json::Map::new());
            }
            target
                .as_object_mut()
                .unwrap()
                .entry(segment.to_string())
                .or_insert(Value::Null)
        }
        let original = envelope.clone();
        let mut patched = envelope.clone();
        for correction in corrections {
            let pointer = correction["pointer"].as_str().unwrap();
            let mut segments = pointer.split('/').skip(1).map(unescape).collect::<Vec<_>>();
            let leaf = segments.pop().unwrap();
            let mut target = &mut patched;
            for segment in &segments {
                target = descend(target, segment);
            }
            // The final segment lands on the same upsert-or-delete semantics:
            // descend creates it, then a removal deletes what was created.
            target = descend(target, &leaf);
            if correction.get("remove").and_then(Value::as_bool) == Some(true) {
                let mut target = &mut patched;
                for segment in &segments {
                    target = match segment.parse::<usize>() {
                        Ok(index) => &mut target.as_array_mut().unwrap()[index],
                        Err(_) => &mut target.as_object_mut().unwrap()[segment],
                    };
                }
                match target {
                    Value::Object(map) => {
                        map.remove(&leaf);
                    }
                    Value::Array(items) => {
                        items.remove(leaf.parse::<usize>().unwrap());
                    }
                    _ => panic!("correction pointer escapes the envelope: {pointer}"),
                }
            } else if let Some(source) = correction.get("from").and_then(Value::as_str) {
                *target = resolve(&original, source).clone();
            } else {
                *target = correction["value"].clone();
            }
        }
        patched
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
        let catalogue = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
            &registry,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
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
        let catalogue = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
            &registry,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
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

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // Serialize MDX admission across the complete test.
    async fn artifact_authoring_discovery_routes_to_callable_creation_and_guide() {
        let _guard = native_artifact_runtime::mdx::test_guard();
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let listed = server
            .handle_message(json!({"jsonrpc":"2.0", "id":1, "method":"tools/list"}))
            .await
            .unwrap();
        let descriptor = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == "artifacts_write")
            .unwrap();
        let cue = descriptor["description"].as_str().unwrap();
        for route in [
            "records_write.create_record",
            "facets.runtime",
            "compositions",
        ] {
            assert!(
                cue.contains(route),
                "missing authoring route {route}: {cue}"
            );
        }

        async fn call(server: &ExecutorPrototypeStdioServer, name: &str, args: Value) -> Value {
            let response = server
                .handle_message(json!({
                    "jsonrpc":"2.0", "id":2, "method":"tools/call",
                    "params":{"name":name, "arguments":args}
                }))
                .await
                .unwrap();
            assert!(response_succeeded(&response), "{response:#}");
            response["result"]["structuredContent"].clone()
        }

        let copy = call(
            &server,
            "describe_operation",
            json!({
                "executor":"artifacts_write", "operation":"instantiate_artifact", "format":"json"
            }),
        )
        .await;
        assert!(copy["source"]["tool_description"]
            .as_str()
            .unwrap()
            .contains("records_write.create_record"));
        assert_eq!(copy["input_schema"]["required"], json!(["source_id"]));

        let guide = call(
            &server,
            "guidance_read",
            json!({
                "operation":"read_guide", "arguments":{"topic":"compositions"}, "format":"json"
            }),
        )
        .await;
        assert!(guide["markdown"]
            .as_str()
            .unwrap()
            .contains("manage_artifact_module_grants.grant"));

        // Exercise the advertised route with an authored source, without a
        // template or source_id. Live-input behavior has its own operated fixture.
        let id = "66eb2aa1-2ec6-4c6b-9434-afecf550ea76";
        call(&server, "records_write", json!({
            "operation":"create_record", "format":"json", "arguments":{
                "id":id, "type":"Document", "kind":"artifact", "name":"Authored from scratch",
                "body":"export const nativeArtifact = { schema: \"native.mdx.artifact.v2\", inputs: {}, module_inputs: {}, capability_requests: [] }\n\n# Authored from scratch",
                "facets":{"runtime":"native.mdx.v2"},
                "reason":"Prove the advertised creation route accepts new artifact source."
            }
        })).await;
        let rendered = call(
            &server,
            "artifacts_execute",
            json!({
                "operation":"render_artifact", "arguments":{"id":id}, "format":"json"
            }),
        )
        .await;
        assert_eq!(rendered["status"], "rendered", "{rendered:#}");
        assert!(rendered["plan"]["tree"]
            .to_string()
            .contains("Authored from scratch"));
        db.close().await;
    }

    #[test]
    fn candidate_manifest_and_read_contracts_are_stable_and_source_derived() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        assert_eq!(
            audit.candidate_surfaces.stable.ordinary.descriptors.len(),
            35
        );
        assert_eq!(
            audit.candidate_surfaces.stable.ordinary.descriptor_bytes,
            43_163
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
            49_410
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
            "get_reuse_context",
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

    /// Decision `e9ecb98`: a caller must be able to name an operation's fields
    /// without a preparatory `describe_operation`.
    #[test]
    fn executor_descriptors_advertise_each_operations_field_names() {
        let registry = registry();
        let catalogue = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            false,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let descriptor = catalogue
            .descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "records_write")
            .expect("records_write descriptor");
        let description = descriptor["inputSchema"]["properties"]["arguments"]["description"]
            .as_str()
            .expect("arguments description");

        let body_guidance = descriptor["description"].as_str().unwrap();
        for expected in [
            "body_set replaces the whole body",
            "body_append appends literal text",
            "body_replace applies surgical edits",
            "body is a deprecated full-replacement alias",
        ] {
            assert!(body_guidance.contains(expected), "{body_guidance}");
        }

        // The incident that opened the investigation: `create_record` rejected
        // for a `reason` the advertised contract never mentioned.
        assert!(
            description.contains("create_record: "),
            "operation listing missing: {description}"
        );
        assert!(
            description.contains("reason*"),
            "required field must be starred: {description}"
        );
        // The prose stays behind describe_operation, and the caller is told so.
        assert!(
            description.contains("describe_operation"),
            "listing must name the depth call: {description}"
        );
        assert!(
            !description.contains("Why this change: reasoning and alternatives"),
            "field prose must not travel in the descriptor: {description}"
        );

        // An absence is explained rather than silent: the deferral sentence
        // tells the caller that anything unlisted shares a contract, so
        // "not there" cannot be misread as "takes no arguments".
        assert!(
            description.contains("An operation not listed here")
                || description.contains("An operation shown next")
                || descriptor["inputSchema"]["properties"]["operation"]["enum"]
                    .as_array()
                    .expect("operation enum")
                    .iter()
                    .all(|operation| description
                        .contains(&format!("{}: ", operation.as_str().unwrap()))),
            "unlisted operations must be explained: {description}"
        );

        // Routing executors carry no operation vocabulary of their own.
        for name in ["bootstrap", "describe_operation"] {
            let descriptor = catalogue
                .descriptors
                .iter()
                .find(|descriptor| descriptor["name"] == name)
                .expect("descriptor");
            let carried = serde_json::to_string(descriptor).unwrap();
            assert!(
                !carried.contains("Fields by operation"),
                "{name} must not carry an operation listing"
            );
        }
    }

    /// `437b0e9` review finding 1. An executor can route two flat-bag source
    /// tools where one demands a field of every action and the other demands
    /// nothing beyond the selector. No shipped executor does today, so nothing
    /// above would have caught treating the two disclosure sentences as
    /// alternatives — and an operation in the second group would then be
    /// described by neither, which is less than it got before the required-only
    /// listing existed.
    #[test]
    fn a_shared_operation_requiring_nothing_is_still_explained_beside_one_that_does() {
        let mut descriptors = vec![json!({
            "name": "mixed_executor",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "operation": { "enum": ["demanding.act", "lax.act"] },
                    "arguments": { "type": "object", "description": "" }
                }
            }
        })];
        let mut contracts = OperationContracts::new();
        for (operation, schema) in [
            (
                "demanding.act",
                json!({"properties": {"canvas_id": {}, "limit": {}}, "required": ["canvas_id"]}),
            ),
            ("lax.act", json!({"properties": {"vocabulary": {}}})),
        ] {
            let mut contract = test_contract(operation, schema);
            contract.executor = "mixed_executor".into();
            contract.action_specific_projection = false;
            contracts.insert(("mixed_executor".into(), operation.into()), contract);
        }
        add_operation_field_listings(&mut descriptors, &contracts).unwrap();
        let description = descriptors[0]["inputSchema"]["properties"]["arguments"]["description"]
            .as_str()
            .expect("arguments description");

        assert!(
            description.contains("demanding.act: canvas_id*"),
            "the demanding operation must name what every action requires: {description}"
        );
        assert!(
            !description.contains("limit"),
            "a shared contract must not advertise its optional half: {description}"
        );
        assert!(
            description.contains("An operation not listed here"),
            "the operation requiring nothing must still be explained rather than \
             silently dropped: {description}"
        );
    }

    /// `437b0e9`, option 1: an executor whose source tools are flat bags
    /// disclosed nothing at all — every operation deferred, so the contract was
    /// silent about fields the server unconditionally demands. It now names the
    /// fields required of every action, and only those.
    ///
    /// `canvas_read` is the specimen. Its four operations come from one flat
    /// `read_canvas` schema requiring `action` and `canvas_id`, so `canvas_id`
    /// is required of all four; the optionals (`after`, `limit`,
    /// `include_deleted`, `include_history`) belong to one action each and must
    /// not travel, which is what deferral is for.
    #[test]
    fn flat_bag_operations_name_the_fields_required_of_every_action() {
        let registry = registry();
        let catalogue = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            false,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let description = |executor: &str| {
            catalogue
                .descriptors
                .iter()
                .find(|descriptor| descriptor["name"] == executor)
                .unwrap_or_else(|| panic!("{executor} descriptor"))["inputSchema"]["properties"]
                ["arguments"]["description"]
                .as_str()
                .expect("arguments description")
                .to_string()
        };

        let canvas = description("canvas_read");
        for operation in [
            "read_canvas.changes",
            "read_canvas.describe",
            "read_canvas.export",
            "read_canvas.get_scene",
        ] {
            assert!(
                canvas.contains(&format!("{operation}: canvas_id*")),
                "{operation} must name the field required of every action: {canvas}"
            );
        }
        for optional in [
            "after",
            "limit",
            "include_deleted",
            "include_history",
            "as_of",
        ] {
            assert!(
                !canvas.contains(optional),
                "{optional} belongs to one action and must stay behind \
                 describe_operation: {canvas}"
            );
        }
        assert!(
            canvas.contains("available from describe_operation"),
            "the required-only listing must say where the rest is: {canvas}"
        );

        // The honest limit of this variant, pinned so it is not mistaken for a
        // regression. `manage_vocabularies` and `manage_schema_config` require
        // only `action`, which is the selector and never appears in
        // `arguments` — so there is no unconditional field to name and
        // `schema_admin` still discloses none. Closing that gap means giving
        // those tools per-action branches, which `437b0e9` scopes out.
        let schema_admin = description("schema_admin");
        assert!(
            schema_admin.contains("An operation not listed here"),
            "schema_admin must still explain its silence: {schema_admin}"
        );
        assert!(
            !schema_admin.contains('*'),
            "schema_admin has no unconditionally required field to star: {schema_admin}"
        );
    }

    /// Only unconditionally required fields are starred. `update_record` needs
    /// `id` in its singular branch and `ids` in its batch branch, and neither
    /// is required of the operation, so starring either would trade one
    /// misleading contract for another.
    #[test]
    fn only_unconditionally_required_fields_are_starred() {
        let schema = json!({
            "type": "object",
            "properties": {"reason": {}},
            "required": ["reason"],
            "oneOf": [
                {"properties": {"id": {}}, "required": ["id", "reason"]},
                {"properties": {"ids": {}}, "required": ["ids", "reason"]}
            ]
        });
        assert_eq!(
            operation_field_listing("update_record", &schema),
            "update_record: id, ids, reason*"
        );
    }

    /// `cc34ddc`: the descriptor surface is a real constraint on a real
    /// resource, and without a legible guard it is enforced by a server that
    /// will not boot, several CI jobs away from the cause. This asserts the
    /// budget where the failure names itself.
    ///
    /// The ceiling is deliberately not tight. `e9ecb98` decided to spend ~30 KB
    /// here; this exists to catch the *next* unbudgeted spend, not to relitigate
    /// that one.
    ///
    /// This measures the shipped registry, not the test registry: the hosted
    /// fixture mirrors the composition in `held/runtime/src/serve.rs`
    /// (builtin + surface + build-enabled experimental + snapshot +
    /// membership + workspace), built here as the hosted catalogue plus the lens surface.
    /// The membership delegate is non-dispatchable on purpose. This test
    /// measures descriptor bytes and never dispatches, so what it must
    /// reproduce is the shipped descriptor shape, not execution semantics —
    /// and the generator-only schema registrar would be the wrong fixture
    /// precisely because its Sqlite unavailable marking filters the
    /// membership executors out before the hosted flag is consulted, leaving
    /// a hosted-looking assertion with nothing hosted inside. The
    /// executor-name assertions below are the guard against that
    /// going-blind-again failure. Drift risk runs the other way too: if
    /// `serve.rs` gains a registrar, this fixture must gain it as well, or
    /// the gate measures a surface smaller than what ships.
    #[test]
    fn executor_catalogue_stays_within_its_descriptor_budget() {
        const EXECUTOR_DESCRIPTOR_MAX_BYTES: usize = 96 * 1024;
        let registry = hosted_registry();
        let ordinary = ExecutorPrototypeStdioServer::pin_hosted_catalogue(&registry).unwrap();
        let lens = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
            &registry,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let ordinary_names: Vec<&str> = ordinary
            .descriptors
            .iter()
            .filter_map(|descriptor| descriptor.get("name").and_then(Value::as_str))
            .collect();
        for executor in [
            "membership_read",
            "membership_admin",
            "membership_remove",
            "workspace_read",
            "export",
        ] {
            assert!(
                ordinary_names.contains(&executor),
                "hosted ordinary catalogue is missing {executor}; the budget \
                 measurement is blind to the shipped surface it claims to guard: \
                 {ordinary_names:?}"
            );
        }
        let lens_names: Vec<&str> = lens
            .descriptors
            .iter()
            .filter_map(|descriptor| descriptor.get("name").and_then(Value::as_str))
            .collect();
        for executor in ["membership_read", "workspace_read", "export"] {
            assert!(
                lens_names.contains(&executor),
                "hosted lens catalogue is missing {executor}; the budget \
                 measurement is blind to the shipped surface it claims to guard: \
                 {lens_names:?}"
            );
        }
        for (surface, bytes) in [
            ("ordinary", ordinary.descriptor_bytes()),
            ("lens", lens.descriptor_bytes()),
        ] {
            assert!(
                bytes <= EXECUTOR_DESCRIPTOR_MAX_BYTES,
                "{surface} executor descriptors are {bytes} bytes against a \
                 {EXECUTOR_DESCRIPTOR_MAX_BYTES} ceiling. Raising the ceiling \
                 is a decision, not a fix: see cc34ddc, where a 657-byte \
                 documentation change took production offline because the \
                 margin had already been spent."
            );
        }
    }

    /// The opted-in `experimental_freshness` descriptor is data, not code: it
    /// is loaded verbatim from the `build_enabled_experimental` surface of
    /// the committed public projection. This asserts the loaded descriptor
    /// exists on both surfaces with the audited name. Opting in must keep the
    /// catalogue within the descriptor ceiling.
    ///
    /// Needs the experimental legacy tool registered, so it is unavailable
    /// in `--no-default-features` builds.
    #[cfg(feature = "experimental-agent-intents")]
    #[test]
    fn experimental_descriptors_come_from_the_audited_projection() {
        const EXECUTOR_DESCRIPTOR_MAX_BYTES: usize = 96 * 1024;
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        for (surface, source_surface) in [
            (
                "ordinary",
                &audit.candidate_surfaces.build_enabled_experimental.ordinary,
            ),
            (
                "lens",
                &audit.candidate_surfaces.build_enabled_experimental.lens,
            ),
        ] {
            let descriptor = source_surface
                .descriptors
                .iter()
                .find(|descriptor| {
                    descriptor.get("name").and_then(Value::as_str)
                        == Some(EXPERIMENTAL_FRESHNESS_EXECUTOR)
                })
                .unwrap_or_else(|| {
                    panic!("audited build-enabled-experimental {surface} surface is missing {EXPERIMENTAL_FRESHNESS_EXECUTOR}")
                });
            assert_eq!(
                descriptor.get("name").and_then(Value::as_str),
                Some(EXPERIMENTAL_FRESHNESS_EXECUTOR),
            );
        }
        let registry = hosted_registry();
        let experimental = ExperimentalExecutors::from_env_value(Some(
            EXPERIMENTAL_FRESHNESS_EXECUTOR.to_string(),
        ))
        .unwrap();
        let ordinary = ExecutorPrototypeStdioServer::pin_hosted_catalogue_with_experimental(
            &registry,
            &experimental,
        )
        .unwrap();
        let lens =
            ExecutorPrototypeLensServer::pin_catalogue_with_experimental(&registry, &experimental)
                .unwrap();
        // Exact byte pins relaxed to ceilings (Richard, 24 Sep 2026); a generated descriptor snapshot is tracked in Native 5af0a10.
        // Opting in must never spend the ceiling's margin: experimental stays
        // under the same ceiling, with actuals printed.
        for (surface, bytes) in [
            ("ordinary+experimental", ordinary.descriptor_bytes()),
            ("lens+experimental", lens.descriptor_bytes()),
        ] {
            assert!(
                bytes <= EXECUTOR_DESCRIPTOR_MAX_BYTES,
                "{surface} executor descriptors are {bytes} bytes against a \
                 {EXECUTOR_DESCRIPTOR_MAX_BYTES} ceiling."
            );
        }
    }

    /// The audited `experimental_freshness` operations, verbatim from the
    /// candidate audit rows. Executor operation names follow the audit's
    /// dotted `tool.action` convention (as every stable executor does), so
    /// these are the exact enum values the opted-in descriptor advertises.
    #[cfg(feature = "experimental-agent-intents")]
    const EXPERIMENTAL_FRESHNESS_OPERATIONS: [&str; 6] = [
        "experimental_freshness_agent_intent.assess_exact_change",
        "experimental_freshness_agent_intent.bind_exact_expression",
        "experimental_freshness_agent_intent.declare_sources",
        "experimental_freshness_agent_intent.promote_exact_expression",
        "experimental_freshness_agent_intent.reconcile_affected_output",
        "experimental_freshness_agent_intent.revise_exact_expression",
    ];

    fn pinned_descriptor_names(descriptors: &[Value]) -> Vec<&str> {
        descriptors
            .iter()
            .filter_map(|descriptor| descriptor.get("name").and_then(Value::as_str))
            .collect()
    }

    #[cfg(feature = "experimental-agent-intents")]
    fn operation_enum(descriptors: &[Value], executor: &str) -> Vec<String> {
        descriptors
            .iter()
            .find(|descriptor| descriptor.get("name").and_then(Value::as_str) == Some(executor))
            .expect("executor descriptor")
            .pointer("/inputSchema/properties/operation/enum")
            .expect("operation enum")
            .as_array()
            .expect("operation enum array")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    }

    /// The executor enum of the `describe_operation` descriptor, which names
    /// executors rather than operations.
    fn describe_executor_enum(descriptors: &[Value]) -> Vec<String> {
        descriptors
            .iter()
            .find(|descriptor| {
                descriptor.get("name").and_then(Value::as_str) == Some("describe_operation")
            })
            .expect("describe_operation descriptor")
            .pointer("/inputSchema/properties/executor/enum")
            .expect("executor enum")
            .as_array()
            .expect("executor enum array")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    }

    /// Without the allowlist the catalogues are the stable-only surface. This
    /// proves it with the exact descriptor name lists and the per-surface
    /// descriptor ceilings (exact byte pins relaxed per Native 5af0a10),
    /// plus the absence of `experimental_freshness` — including in
    /// `describe_operation`'s executor enum — on both surfaces.
    #[test]
    fn stable_catalogues_stay_within_budget_without_the_opt_in() {
        let registry = hosted_registry();
        let ordinary = ExecutorPrototypeStdioServer::pin_hosted_catalogue(&registry).unwrap();
        let lens = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
            &registry,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let ordinary_names = pinned_descriptor_names(&ordinary.descriptors);
        let lens_names = pinned_descriptor_names(&lens.descriptors);
        assert_eq!(
            ordinary_names,
            [
                "bootstrap",
                "describe_operation",
                "system_read",
                "guidance_read",
                "guidance_admin",
                "records_read",
                "records_write",
                "records_lifecycle",
                "records_delete",
                "coordination_read",
                "coordination_write",
                "sql_read",
                "external_import",
                "identity_read",
                "identity_resolve",
                "identity_admin",
                "access_read",
                "access_admin",
                "schema_read",
                "schema_admin",
                "schema_delete",
                "messaging_read",
                "messaging_write",
                "artifacts_read",
                "artifacts_execute",
                "artifacts_write",
                "membership_read",
                "membership_admin",
                "membership_remove",
                "export",
                "canvas_read",
                "canvas_write",
                "reach_read",
                "reach_connect",
                "workspace_read",
            ],
        );
        // The lens surface withholds plan-required executors (its execution
        // path is direct-only), so the stable lens catalogue is the audit
        // lens list minus records_delete, identity_admin, access_admin,
        // schema_admin, and schema_delete. That withholding predates this
        // opt-in and is unchanged by it.
        assert_eq!(
            lens_names,
            [
                "bootstrap",
                "describe_operation",
                "system_read",
                "guidance_read",
                "guidance_admin",
                "records_read",
                "records_write",
                "records_lifecycle",
                "coordination_read",
                "coordination_write",
                "sql_read",
                "external_import",
                "identity_read",
                "identity_resolve",
                "access_read",
                "schema_read",
                "messaging_read",
                "messaging_write",
                "artifacts_read",
                "artifacts_execute",
                "artifacts_write",
                "membership_read",
                "export",
                "canvas_read",
                "canvas_write",
                "workspace_read",
            ],
        );
        // Exact byte pins relaxed to ceilings (Richard, 24 Sep 2026); a generated descriptor snapshot is tracked in Native 5af0a10.
        const EXECUTOR_DESCRIPTOR_MAX_BYTES: usize = 96 * 1024;
        for (surface, bytes) in [
            ("ordinary", ordinary.descriptor_bytes()),
            ("lens", lens.descriptor_bytes()),
        ] {
            assert!(
                bytes <= EXECUTOR_DESCRIPTOR_MAX_BYTES,
                "{surface} executor descriptors are {bytes} bytes against a \
                 {EXECUTOR_DESCRIPTOR_MAX_BYTES} ceiling."
            );
        }
        // E2 I-4: the served `sql_read` descriptor carries the catalog card
        // within its byte budget on both surfaces.
        for descriptors in [&ordinary.descriptors, &lens.descriptors] {
            let sql = descriptors
                .iter()
                .find(|descriptor| descriptor["name"] == "sql_read")
                .expect("sql_read descriptor");
            let bytes = serde_json::to_vec(sql).unwrap().len();
            assert!(
                bytes <= crate::query::sql_contract::SQL_READ_DESCRIPTOR_MAX_BYTES,
                "sql_read descriptor is {bytes} bytes over budget"
            );
            let description = sql["description"].as_str().unwrap_or_default();
            assert!(description.contains("Queryable relations"), "{description}");
            assert!(description.contains("catalog_columns"), "{description}");
        }
        // `describe_operation` must not name an executor that has no
        // descriptor, in either direction, on either surface.
        for descriptors in [&ordinary.descriptors, &lens.descriptors] {
            assert!(
                !describe_executor_enum(descriptors)
                    .contains(&EXPERIMENTAL_FRESHNESS_EXECUTOR.to_string()),
                "stable describe_operation must not advertise {EXPERIMENTAL_FRESHNESS_EXECUTOR}"
            );
        }
        assert!(!ordinary_names.contains(&EXPERIMENTAL_FRESHNESS_EXECUTOR));
        assert!(!lens_names.contains(&EXPERIMENTAL_FRESHNESS_EXECUTOR));
    }

    /// E4 M1 source contract: without the `sql_write` allowlist no executor
    /// catalogue may name it, on either surface. With the allowlist, the
    /// ordinary SQLite catalogue carries the full source contract while the
    /// lens surface keeps withholding plan-required operations, which the
    /// existing lens engine does not support.
    #[test]
    fn sql_write_catalogue_admission_follows_its_allowlist() {
        let registry = hosted_registry();
        assert!(
            registry.get("sql_write").is_some(),
            "seed assumption: the allowlisted-shape registry holds the sql_write source"
        );
        // Default and freshness-only catalogues withhold on both surfaces.
        let empty = ExperimentalExecutors::empty();
        let freshness = ExperimentalExecutors::from_env_value(Some(
            EXPERIMENTAL_FRESHNESS_EXECUTOR.to_string(),
        ))
        .unwrap();
        for experimental in [&empty, &freshness] {
            let ordinary = ExecutorPrototypeStdioServer::pin_hosted_catalogue_with_experimental(
                &registry,
                experimental,
            )
            .unwrap();
            let lens = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
                &registry,
                experimental,
            )
            .unwrap();
            for descriptors in [&ordinary.descriptors, &lens.descriptors] {
                assert!(
                    !pinned_descriptor_names(descriptors).contains(&"sql_write"),
                    "unopted catalogue must not advertise sql_write"
                );
                assert!(
                    !describe_executor_enum(descriptors).contains(&"sql_write".to_string()),
                    "unopted describe_operation must not name sql_write"
                );
            }
            for contracts in [&ordinary.contracts, &lens.contracts] {
                assert!(
                    !contracts.contains_key(&("sql_write".to_string(), "sql_write".to_string())),
                    "unopted catalogue must hold no sql_write contract"
                );
            }
        }
        // The sql_write allowlist admits the full source contract on the
        // ordinary SQLite catalogue: descriptor, operation enum,
        // describe_operation entry, and contract bound to the source tool.
        let allowlisted = ExperimentalExecutors::from_env_value(Some(
            EXPERIMENTAL_SQL_WRITE_EXECUTOR.to_string(),
        ))
        .unwrap();
        let ordinary = ExecutorPrototypeStdioServer::pin_hosted_catalogue_with_experimental(
            &registry,
            &allowlisted,
        )
        .unwrap();
        assert!(
            pinned_descriptor_names(&ordinary.descriptors).contains(&"sql_write"),
            "opted-in ordinary catalogue must advertise sql_write"
        );
        assert_eq!(
            operation_names(&ordinary.descriptors, "sql_write"),
            vec!["sql_write".to_string()],
            "opted-in sql_write descriptor carries exactly its audited operation"
        );
        assert!(
            describe_executor_enum(&ordinary.descriptors).contains(&"sql_write".to_string()),
            "opted-in describe_operation must name sql_write"
        );
        let contract = ordinary
            .contracts
            .get(&("sql_write".to_string(), "sql_write".to_string()))
            .expect("opted-in ordinary catalogue must hold the sql_write contract");
        assert_eq!(contract.source_tool, "sql_write");
        assert!(
            contract.selector.is_none(),
            "the single sql_write source tool needs no action selector"
        );
        // The lens engine supports no plan-required operations, so the lens
        // catalogue keeps withholding the admitted pair there.
        let lens =
            ExecutorPrototypeLensServer::pin_catalogue_with_experimental(&registry, &allowlisted)
                .unwrap();
        assert!(
            !pinned_descriptor_names(&lens.descriptors).contains(&"sql_write"),
            "lens catalogue must withhold plan-required sql_write"
        );
        assert!(
            !lens
                .contracts
                .contains_key(&("sql_write".to_string(), "sql_write".to_string())),
            "lens catalogue must hold no sql_write contract"
        );
    }

    /// Operation enum reader without the experimental-agent-intents feature
    /// gate, so allowlist admission stays covered in every feature set.
    fn operation_names(descriptors: &[Value], executor: &str) -> Vec<String> {
        descriptors
            .iter()
            .find(|descriptor| descriptor.get("name").and_then(Value::as_str) == Some(executor))
            .expect("executor descriptor")
            .pointer("/inputSchema/properties/operation/enum")
            .expect("operation enum")
            .as_array()
            .expect("operation enum array")
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    }

    /// Facade harness for the revalidate-only `sql_write` route: an opted-in
    /// executor server with a `plan-author` caller holding Manage on the
    /// fixture record.
    async fn sql_write_opted_in_server(
        db: &crate::Db,
        caller: Caller,
    ) -> ExecutorPrototypeStdioServer {
        use crate::mcp::EXPERIMENTAL_SQL_WRITE_EXECUTOR;
        let experimental = ExperimentalExecutors::from_env_value(Some(
            EXPERIMENTAL_SQL_WRITE_EXECUTOR.to_string(),
        ))
        .unwrap();
        let telemetry_sink = Arc::new(telemetry::TestTelemetrySink::default());
        let telemetry =
            ExecutorTelemetryContext::new(telemetry_sink, telemetry::DEFAULT_RETENTION_DAYS)
                .unwrap();
        ExecutorPrototypeStdioServer::new_with_telemetry_and_experimental(
            hosted_registry(),
            db.clone(),
            caller,
            None,
            telemetry,
            experimental,
        )
        .await
        .unwrap()
    }

    async fn sql_write_fixture(db: &crate::Db) -> (String, Caller) {
        use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
        let target = crate::store::create_record(
            db,
            json!({"id":"ec00b000-0000-4000-8000-00000000b201","type":"Document","kind":"note","name":"Confirm me"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            db,
            "test:sql-write-facade",
            &target,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        (target, Caller::authenticated("plan-author"))
    }

    fn sql_write_statement(target: &str) -> String {
        format!(
            "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Confirmed' AS value FROM records WHERE id = '{target}'"
        )
    }

    async fn sql_write_prepare(server: &ExecutorPrototypeStdioServer, statement: &str) -> Value {
        server
            .handle_message(json!({
                "jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"sql_write","arguments":{
                    "operation":"sql_write",
                    "arguments":{"statement":statement,"reason":"facade probe"},
                    "run_key":"sql-write-b2","parent_key":"sql-write-b2"
                }}
            }))
            .await
            .unwrap()
    }

    async fn sql_write_execute(
        server: &ExecutorPrototypeStdioServer,
        plan_id: &str,
        target: &str,
        effect_summary: &str,
    ) -> Value {
        server
            .handle_message(json!({
                "jsonrpc":"2.0","id":2,"method":"tools/call",
                "params":{"name":"sql_write","arguments":{
                    "operation":"sql_write",
                    "plan_id":plan_id,"target":target,"effect_summary":effect_summary,
                    "run_key":"sql-write-b2","parent_key":"sql-write-b2"
                }}
            }))
            .await
            .unwrap()
    }

    /// Plan-path responses carry the plan object directly under
    /// `structuredContent` (unlike direct tool calls, which nest it under
    /// `result`).
    fn structured_result(body: &Value) -> &Value {
        &body["result"]["structuredContent"]
    }

    fn plan_error_code(body: &Value) -> &str {
        body["result"]["structuredContent"]["plan_error"]["code"]
            .as_str()
            .unwrap_or_else(|| panic!("expected a plan_error envelope: {body}"))
    }

    async fn content_event_count(db: &crate::Db) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    }

    async fn assert_sql_write_plan_prepared(db: &crate::Db, plan_id: &str) {
        let store = plan_store::PlanStore::open_for_database(db.path())
            .await
            .unwrap();
        let stored = store
            .load(plan_id, chrono::Utc::now().timestamp_millis())
            .await
            .unwrap()
            .expect("signed sql_write plan must remain in the store");
        assert!(
            matches!(stored.state, plan_store::StoredState::Prepared),
            "sql_write confirmation must not claim its plan: {:?}",
            stored.state
        );
    }

    /// Prepare then execute-shaped call returns preview-current with no claim,
    /// no dispatch, and no event; a repeated confirmation agrees, the raw
    /// arguments shape stays refused, and the plan keeps its ten-minute TTL.
    #[tokio::test]
    async fn sql_write_execute_confirms_preview_current_without_mutation() {
        let db = create_database(":memory:").await.unwrap();
        let (target, caller) = sql_write_fixture(&db).await;
        let server = sql_write_opted_in_server(&db, caller).await;
        let prepared = sql_write_prepare(&server, &sql_write_statement(&target)).await;
        assert_eq!(prepared["result"]["isError"], false, "{prepared}");
        let plan = structured_result(&prepared);
        assert_eq!(plan["preparation_mutated"], false);
        let plan_id = plan["plan_id"].as_str().unwrap();
        let target_text = plan["target"].as_str().unwrap();
        let effect_summary = plan["effect_summary"].as_str().unwrap();
        let events_before = content_event_count(&db).await;
        let confirmed = sql_write_execute(&server, plan_id, target_text, effect_summary).await;
        assert_eq!(confirmed["result"]["isError"], false, "{confirmed}");
        let current = structured_result(&confirmed);
        assert_eq!(current["preview_current"], true);
        assert_eq!(current["committed"], false);
        assert_eq!(current["plan_id"], json!(plan_id));
        assert_eq!(current["target"], json!(target_text));
        assert_eq!(current["effect_summary"], json!(effect_summary));
        assert_eq!(current["source_dispatch_count"], 0);
        assert_eq!(current["preparation_mutated"], false);
        assert_sql_write_plan_prepared(&db, plan_id).await;
        // Ten-minute TTL on the confirmed preview.
        let expires_at = current["expires_at"].as_str().unwrap();
        let expiry_ms = chrono::DateTime::parse_from_rfc3339(expires_at)
            .unwrap()
            .timestamp_millis();
        let ttl_ms = expiry_ms - chrono::Utc::now().timestamp_millis();
        assert!(
            (540_000..=600_000).contains(&ttl_ms),
            "preview TTL must be ten minutes, got {ttl_ms}ms"
        );
        assert_eq!(content_event_count(&db).await, events_before);
        // A repeated confirmation agrees: the plan is still Prepared, never
        // claimed or consumed.
        let repeated = sql_write_execute(&server, plan_id, target_text, effect_summary).await;
        assert_eq!(repeated["result"]["isError"], false, "{repeated}");
        assert_eq!(structured_result(&repeated)["preview_current"], true);
        assert_sql_write_plan_prepared(&db, plan_id).await;
        assert_eq!(content_event_count(&db).await, events_before);
        // Raw operation arguments on an execute-shaped call stay refused.
        let raw = server
            .handle_message(json!({
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":"sql_write","arguments":{
                    "operation":"sql_write",
                    "plan_id":plan_id,"target":target_text,"effect_summary":effect_summary,
                    "arguments":{"statement":"SELECT 1"},
                    "run_key":"sql-write-b2","parent_key":"sql-write-b2"
                }}
            }))
            .await
            .unwrap();
        assert_eq!(plan_error_code(&raw), "raw_arguments_forbidden");
        assert_sql_write_plan_prepared(&db, plan_id).await;
        assert_eq!(content_event_count(&db).await, events_before);
    }

    /// A grown selection between prepare and execute is drift: the
    /// one-operation bound trips on revalidation, so the execute-shaped call
    /// reports `plan_stale` with no claim and no dispatch.
    #[tokio::test]
    async fn sql_write_grown_selection_reports_plan_stale() {
        use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
        let db = create_database(":memory:").await.unwrap();
        let (_target, caller) = sql_write_fixture(&db).await;
        let server = sql_write_opted_in_server(&db, caller).await;
        let statement = "SELECT id AS record_id, 'set_field' AS op, 'name' AS key, 'Confirmed' AS value FROM records WHERE name LIKE 'Confirm%'";
        let prepared = sql_write_prepare(&server, statement).await;
        assert_eq!(prepared["result"]["isError"], false, "{prepared}");
        let plan = structured_result(&prepared);
        let (plan_id, target_text, effect_summary) = (
            plan["plan_id"].as_str().unwrap().to_string(),
            plan["target"].as_str().unwrap().to_string(),
            plan["effect_summary"].as_str().unwrap().to_string(),
        );
        let grown = crate::store::create_record(
            &db,
            json!({"type":"Document","kind":"note","name":"Confirm me too"}),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:sql-write-facade-grown",
            &grown,
            vec![AllowEntry::account("plan-author", Capability::Manage)],
        )
        .await
        .unwrap();
        let events_before = content_event_count(&db).await;
        let stale = sql_write_execute(&server, &plan_id, &target_text, &effect_summary).await;
        assert_eq!(plan_error_code(&stale), "plan_stale", "{stale}");
        assert_sql_write_plan_prepared(&db, &plan_id).await;
        assert_eq!(content_event_count(&db).await, events_before);
        // Still stale on repeat: nothing was claimed or dispatched.
        let repeated = sql_write_execute(&server, &plan_id, &target_text, &effect_summary).await;
        assert_eq!(plan_error_code(&repeated), "plan_stale");
        assert_sql_write_plan_prepared(&db, &plan_id).await;
        assert_eq!(content_event_count(&db).await, events_before);
    }

    /// A hidden selection between prepare and execute is drift with
    /// hidden/missing parity: the execute-shaped call reports `plan_stale`
    /// with no claim and no dispatch.
    #[tokio::test]
    async fn sql_write_hidden_selection_reports_plan_stale() {
        use crate::authorization::replace_explicit_policy;
        let db = create_database(":memory:").await.unwrap();
        let (target, caller) = sql_write_fixture(&db).await;
        let server = sql_write_opted_in_server(&db, caller).await;
        let prepared = sql_write_prepare(&server, &sql_write_statement(&target)).await;
        assert_eq!(prepared["result"]["isError"], false, "{prepared}");
        let plan = structured_result(&prepared);
        let (plan_id, target_text, effect_summary) = (
            plan["plan_id"].as_str().unwrap().to_string(),
            plan["target"].as_str().unwrap().to_string(),
            plan["effect_summary"].as_str().unwrap().to_string(),
        );
        replace_explicit_policy(&db, "test:sql-write-facade-hide", &target, vec![])
            .await
            .unwrap();
        let events_before = content_event_count(&db).await;
        let stale = sql_write_execute(&server, &plan_id, &target_text, &effect_summary).await;
        assert_eq!(plan_error_code(&stale), "plan_stale", "{stale}");
        assert_sql_write_plan_prepared(&db, &plan_id).await;
        assert_eq!(content_event_count(&db).await, events_before);
    }

    /// A content version change between prepare and execute is drift: the
    /// pinned expected version conflicts on revalidation, so the
    /// execute-shaped call reports `plan_stale` with no claim and no dispatch.
    #[tokio::test]
    async fn sql_write_version_drift_reports_plan_stale() {
        let db = create_database(":memory:").await.unwrap();
        let (target, caller) = sql_write_fixture(&db).await;
        let server = sql_write_opted_in_server(&db, caller).await;
        let prepared = sql_write_prepare(&server, &sql_write_statement(&target)).await;
        assert_eq!(prepared["result"]["isError"], false, "{prepared}");
        let plan = structured_result(&prepared);
        let (plan_id, target_text, effect_summary) = (
            plan["plan_id"].as_str().unwrap().to_string(),
            plan["target"].as_str().unwrap().to_string(),
            plan["effect_summary"].as_str().unwrap().to_string(),
        );
        crate::store::update_record(&db, &target, json!({"name": "Bumped"}))
            .await
            .unwrap();
        let events_before = content_event_count(&db).await;
        let stale = sql_write_execute(&server, &plan_id, &target_text, &effect_summary).await;
        assert_eq!(plan_error_code(&stale), "plan_stale", "{stale}");
        assert_sql_write_plan_prepared(&db, &plan_id).await;
        assert_eq!(content_event_count(&db).await, events_before);
    }

    /// Lost Edit between prepare and execute is drift: the capability check
    /// fails on revalidation, so the execute-shaped call reports `plan_stale`
    /// with no claim and no dispatch.
    #[tokio::test]
    async fn sql_write_lost_edit_reports_plan_stale() {
        use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
        let db = create_database(":memory:").await.unwrap();
        let (target, caller) = sql_write_fixture(&db).await;
        let server = sql_write_opted_in_server(&db, caller).await;
        let prepared = sql_write_prepare(&server, &sql_write_statement(&target)).await;
        assert_eq!(prepared["result"]["isError"], false, "{prepared}");
        let plan = structured_result(&prepared);
        let (plan_id, target_text, effect_summary) = (
            plan["plan_id"].as_str().unwrap().to_string(),
            plan["target"].as_str().unwrap().to_string(),
            plan["effect_summary"].as_str().unwrap().to_string(),
        );
        replace_explicit_policy(
            &db,
            "test:sql-write-facade-demote",
            &target,
            vec![AllowEntry::account("plan-author", Capability::View)],
        )
        .await
        .unwrap();
        let events_before = content_event_count(&db).await;
        let stale = sql_write_execute(&server, &plan_id, &target_text, &effect_summary).await;
        assert_eq!(plan_error_code(&stale), "plan_stale", "{stale}");
        assert_sql_write_plan_prepared(&db, &plan_id).await;
        assert_eq!(content_event_count(&db).await, events_before);
    }

    /// With `experimental_freshness` allowlisted, both surfaces advertise the
    /// executor with exactly the six audited operations, `describe_operation`
    /// reflects it, and `describe_operation` resolves one of its contracts.
    ///
    /// Needs the experimental legacy tool registered, so it is unavailable
    /// in `--no-default-features` builds.
    #[cfg(feature = "experimental-agent-intents")]
    #[test]
    fn experimental_opt_in_advertises_freshness_on_both_surfaces() {
        let registry = hosted_registry();
        let experimental = ExperimentalExecutors::from_env_value(Some(
            EXPERIMENTAL_FRESHNESS_EXECUTOR.to_string(),
        ))
        .unwrap();
        let ordinary = ExecutorPrototypeStdioServer::pin_hosted_catalogue_with_experimental(
            &registry,
            &experimental,
        )
        .unwrap();
        let lens =
            ExecutorPrototypeLensServer::pin_catalogue_with_experimental(&registry, &experimental)
                .unwrap();
        for descriptors in [&ordinary.descriptors, &lens.descriptors] {
            let names = pinned_descriptor_names(descriptors);
            assert!(
                names.contains(&EXPERIMENTAL_FRESHNESS_EXECUTOR),
                "opted-in catalogue is missing {EXPERIMENTAL_FRESHNESS_EXECUTOR}: {names:?}"
            );
            assert_eq!(
                operation_enum(descriptors, EXPERIMENTAL_FRESHNESS_EXECUTOR),
                EXPERIMENTAL_FRESHNESS_OPERATIONS,
            );
            let executor_enum = describe_executor_enum(descriptors);
            assert!(
                executor_enum.contains(&EXPERIMENTAL_FRESHNESS_EXECUTOR.to_string()),
                "describe_operation must reflect the opted-in executor: {executor_enum:?}"
            );
        }
        // The opted-in executor carries per-operation contracts on both
        // surfaces, resolved through the registered legacy tool.
        for contracts in [&ordinary.contracts, &lens.contracts] {
            for operation in EXPERIMENTAL_FRESHNESS_OPERATIONS {
                let contract = contracts
                    .get(&(
                        EXPERIMENTAL_FRESHNESS_EXECUTOR.to_string(),
                        operation.to_string(),
                    ))
                    .unwrap_or_else(|| panic!("missing contract for {operation}"));
                assert_eq!(contract.source_tool, "experimental_freshness_agent_intent");
                assert!(contract.selector.is_some(), "{operation} has no selector");
            }
        }
        // Opting in advertises exactly one more descriptor per surface.
        let stable_ordinary =
            ExecutorPrototypeStdioServer::pin_hosted_catalogue(&registry).unwrap();
        let stable_lens = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
            &registry,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        assert_eq!(
            ordinary.descriptors.len(),
            stable_ordinary.descriptors.len() + 1
        );
        assert_eq!(lens.descriptors.len(), stable_lens.descriptors.len() + 1);
    }

    /// End to end on SQLite: through an executor-prototype stdio server built
    /// with the allowlist, `experimental_freshness /
    /// experimental_freshness_agent_intent.promote_exact_expression` promotes
    /// an exact expression and returns a Unit, revision, and Occurrence. The
    /// executor performs no freshness logic itself; it translates the envelope
    /// back to the exact legacy tool/action and delegates once.
    #[cfg(feature = "experimental-agent-intents")]
    #[tokio::test]
    async fn experimental_opt_in_dispatches_promote_exact_expression_end_to_end() {
        let db = create_database(":memory:").await.unwrap();
        let source_text = "Audience: technical founders.";
        let source = crate::store::create_record(
            &db,
            json!({"type":"Document","kind":"note","name":"Audience source","body":source_text}),
        )
        .await
        .unwrap();
        let source_revision = crate::freshness::current_record_body_revision(&db, &source)
            .await
            .unwrap();
        let experimental = ExperimentalExecutors::from_env_value(Some(
            EXPERIMENTAL_FRESHNESS_EXECUTOR.to_string(),
        ))
        .unwrap();
        let telemetry_sink = Arc::new(telemetry::TestTelemetrySink::default());
        let telemetry =
            ExecutorTelemetryContext::new(telemetry_sink, telemetry::DEFAULT_RETENTION_DAYS)
                .unwrap();
        let server = ExecutorPrototypeStdioServer::new_with_telemetry_and_experimental(
            hosted_registry(),
            db.clone(),
            Caller::local(),
            None,
            telemetry,
            experimental,
        )
        .await
        .unwrap();
        // With the allowlist the executor is advertised and selectable.
        let list = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":1,
                "method":"tools/list",
                "params":{}
            }))
            .await
            .unwrap();
        let tools = list["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("tools/list did not return tools: {list}"));
        let freshness = tools
            .iter()
            .find(|tool| tool["name"] == EXPERIMENTAL_FRESHNESS_EXECUTOR)
            .expect("opted-in tools/list advertises experimental_freshness");
        assert_eq!(
            freshness["inputSchema"]["properties"]["operation"]["enum"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>(),
            EXPERIMENTAL_FRESHNESS_OPERATIONS,
        );
        let promoted = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":2,
                "method":"tools/call",
                    "params":{
                    "name": EXPERIMENTAL_FRESHNESS_EXECUTOR,
                    "arguments":{
                        "operation": "experimental_freshness_agent_intent.promote_exact_expression",
                        "arguments":{
                            "input": {
                                "source_revision": serde_json::to_value(&source_revision).unwrap(),
                                "selectors": [{"type":"text_quote","exact": source_text}],
                                "first_content": {
                                    "content": "Primary audience: technical founders.",
                                    "content_media_type": "text/plain",
                                    "encoding_version": 1
                                },
                                "expression_role": "canonical",
                                "idempotency_key": "executor-e2e-promote-a748b2"
                            }
                        },
                        "run_key": "executor-e2e-a748b2"
                    }
                }
            }))
            .await
            .unwrap();
        assert_eq!(promoted["result"]["isError"], false, "{promoted}");
        let evidence = &promoted["result"]["structuredContent"]["result"];
        let unit_id = evidence["promoted"]["unit_id"].as_str().unwrap();
        assert!(!unit_id.is_empty(), "{evidence}");
        assert_eq!(evidence["unit"]["unit_id"].as_str().unwrap(), unit_id);
        assert_eq!(
            evidence["occurrence"]["occurrence"]["occurrence_id"]
                .as_str()
                .unwrap(),
            evidence["promoted"]["occurrence_id"].as_str().unwrap(),
        );
        assert!(
            evidence["promoted"]["first_revision"]["sha256"]
                .as_str()
                .is_some_and(|sha| sha.len() == 64),
            "{evidence}"
        );
        db.close().await;
    }

    /// Once a shared source publishes action-discriminated branches, each
    /// executor operation must advertise its own fields rather than the old
    /// shared-contract deferral.
    #[test]
    fn action_discriminated_attachment_operations_advertise_their_own_fields() {
        let registry = registry();
        let catalogue = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            false,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let description = catalogue
            .descriptors
            .iter()
            .find(|descriptor| descriptor["name"] == "records_delete")
            .expect("records_delete descriptor")["inputSchema"]["properties"]["arguments"]
            ["description"]
            .as_str()
            .expect("arguments description")
            .to_string();

        assert!(
            description.contains("manage_attachments.detach"),
            "the action branch must be listed with its own fields: {description}"
        );
        assert!(
            !description.contains("manage_attachments shares one contract with its sibling actions"),
            "an action-discriminated source no longer needs the shared-contract deferral: {description}"
        );

        // A single-operation source tool has no siblings, so it still lists.
        assert!(
            description.contains("delete_record: "),
            "an unshared contract must still list: {description}"
        );
    }

    /// Every `arguments` copy in one descriptor carries the same listing.
    /// Plan-carrying descriptors duplicate the description into their `oneOf`
    /// branches, and the branch that requires `arguments` is one of them, so a
    /// top-level-only write would leave the operative branch without fields.
    #[test]
    fn every_arguments_copy_carries_the_same_listing() {
        let registry = registry();
        let catalogue = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            false,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        fn argument_descriptions(schema: &Value, into: &mut Vec<String>) {
            if let Some(description) = schema
                .pointer("/properties/arguments/description")
                .and_then(Value::as_str)
            {
                into.push(description.to_string());
            }
            for keyword in ["oneOf", "anyOf", "allOf"] {
                let Some(branches) = schema.get(keyword).and_then(Value::as_array) else {
                    continue;
                };
                for branch in branches {
                    argument_descriptions(branch, into);
                }
            }
        }
        let mut branched = 0;
        for descriptor in &catalogue.descriptors {
            let name = descriptor["name"].as_str().unwrap();
            let mut descriptions = Vec::new();
            argument_descriptions(&descriptor["inputSchema"], &mut descriptions);
            if descriptions.len() < 2 {
                continue;
            }
            branched += 1;
            let (first, rest) = descriptions.split_first().expect("checked above");
            for other in rest {
                assert_eq!(
                    first, other,
                    "{name} advertises two different argument contracts"
                );
            }
        }
        assert!(
            branched > 0,
            "no descriptor carried a branched arguments copy, so this proves nothing"
        );
    }

    /// An operation whose source tool declares real per-action branches must be
    /// named, not deferred. Checked on both surfaces: the lens routes a
    /// different subset, and a rule that depends on what a surface happens to
    /// route is the defect this test exists to catch.
    #[test]
    fn operations_with_action_specific_schemas_are_named_not_deferred() {
        let registry = registry();
        let ordinary = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            false,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let lens = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
            &registry,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let mut named = 0;
        let mut deferred = 0;
        for (surface, descriptors, contracts) in [
            ("ordinary", &ordinary.descriptors, &ordinary.contracts),
            ("lens", &lens.descriptors, &lens.contracts),
        ] {
            for descriptor in descriptors {
                let name = descriptor["name"].as_str().unwrap();
                if name == "bootstrap" || name == "describe_operation" {
                    continue;
                }
                let operations = descriptor["inputSchema"]["properties"]["operation"]["enum"]
                    .as_array()
                    .expect("operation enum");
                if operations.is_empty() {
                    continue;
                }
                let description = descriptor
                    .pointer("/inputSchema/properties/arguments/description")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| {
                        panic!(
                            "{surface} {name} routes operations but carries no arguments \
                                description"
                        )
                    });
                for operation in operations {
                    let operation = operation.as_str().unwrap();
                    let contract = contracts
                        .get(&(name.to_string(), operation.to_string()))
                        .expect("contract");
                    if contract.action_specific_projection {
                        named += 1;
                        assert!(
                            description.contains(&format!("{operation}: ")),
                            "{surface} {name}.{operation} has a schema of its own but was \
                             not named"
                        );
                    } else {
                        deferred += 1;
                        // A shared contract may name the fields required of
                        // every action it routes, and nothing else. An
                        // unstarred name here would be an optional field of one
                        // sibling advertised as this operation's own, which is
                        // the defect the discriminator exists to prevent.
                        let prefix = format!("{operation}: ");
                        match required_field_listing(operation, &contract.input_schema) {
                            None => {
                                assert!(
                                    !description.contains(&prefix),
                                    "{surface} {name}.{operation} shares a contract and \
                                     requires nothing unconditionally, so it must name no \
                                     fields"
                                );
                                // Naming nothing is not the same as saying
                                // nothing: the catch-all must still cover it,
                                // whether or not a sibling tool on this same
                                // executor produced a required-only listing.
                                assert!(
                                    description.contains("An operation not listed here"),
                                    "{surface} {name}.{operation} names no fields and is not \
                                     covered by the deferral sentence either: {description}"
                                );
                            }
                            Some(expected) => {
                                assert!(
                                    description.contains(&expected),
                                    "{surface} {name}.{operation} shares a contract but does \
                                     not name the fields required of every action: expected \
                                     {expected:?}"
                                );
                                let start = description.find(&prefix).expect("listed operation")
                                    + prefix.len();
                                let segment = &description[start..];
                                let end = segment
                                    .find(';')
                                    .unwrap_or(segment.len())
                                    .min(segment.find('.').unwrap_or(segment.len()));
                                for field in segment[..end].split(", ") {
                                    assert!(
                                        field.ends_with('*'),
                                        "{surface} {name}.{operation} shares a contract but \
                                         advertised the optional field {field:?} as its own"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(named > 20, "expected many named operations, got {named}");
        assert!(deferred > 0, "expected some deferrals, got {deferred}");
    }

    /// The specimens the reviews found, pinned by name so a future change to the
    /// discriminator cannot quietly reintroduce either direction of the bug.
    #[test]
    fn shared_and_branched_contracts_are_each_classified_correctly() {
        let registry = registry();
        let catalogue = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            false,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let classified = |executor: &str, operation: &str| {
            catalogue
                .contracts
                .get(&(executor.to_string(), operation.to_string()))
                .unwrap_or_else(|| panic!("{executor}.{operation} contract"))
                .action_specific_projection
        };

        // Attachments now declare one branch per action so the list branch can
        // carry selector aliases without leaking them to inspect or detach.
        assert!(classified("records_delete", "manage_attachments.detach"));
        assert!(classified("records_read", "manage_attachments.list"));

        // Declared branches whose projected schemas are byte-identical to a
        // sibling's. Comparing projected results deferred these; the source
        // schema does not. `read` and `why` share one branch by declaration,
        // and that branch is exactly each one's contract.
        assert!(classified("records_read", "manage_relationships.read"));
        assert!(classified("records_read", "manage_relationships.why"));
        assert!(classified("records_write", "manage_relationships.assert"));

        // Single-operation source tools have no siblings at all.
        assert!(classified("records_write", "create_record"));
        assert!(classified("records_read", "search"));
    }

    /// `manage_links` declares one `oneOf` branch per action, so each
    /// operation advertises its own fields and rejects its siblings'. The
    /// flat-bag declaration accepted `note` on `remove` at discovery while the
    /// `deny_unknown_fields` handler rejected it at dispatch; the branch
    /// structure carries that meaning now.
    #[test]
    fn manage_links_operations_advertise_only_their_own_fields() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let BuiltContracts { contracts, .. } = build_contracts(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            &audit.audit_rows,
            ExecutorSurface::Ordinary,
        )
        .unwrap();
        let add = contracts
            .get(&("records_write".into(), "manage_links.add".into()))
            .expect("manage_links.add contract");
        let remove = contracts
            .get(&("records_write".into(), "manage_links.remove".into()))
            .expect("manage_links.remove contract");
        let list = contracts
            .get(&("records_read".into(), "manage_links.list".into()))
            .expect("manage_links.list contract");
        for contract in [add, remove, list] {
            assert!(
                contract.action_specific_projection,
                "{}.{} must project to its own branch",
                contract.executor, contract.operation
            );
        }
        fn properties_of(contract: &OperationContract) -> HashSet<String> {
            let mut properties = Vec::new();
            collect_property_names(&contract.input_schema, &mut properties);
            properties.into_iter().collect()
        }
        assert_eq!(
            properties_of(add),
            HashSet::from([
                "source_id".into(),
                "target_id".into(),
                "relationship".into(),
                "note".into(),
            ])
        );
        assert_eq!(
            properties_of(remove),
            HashSet::from([
                "source_id".into(),
                "target_id".into(),
                "relationship".into(),
            ])
        );
        assert_eq!(
            properties_of(list),
            HashSet::from([
                "id".into(),
                "record_id".into(),
                "ids".into(),
                "limit".into(),
                "cursor".into(),
            ])
        );
        // The exact sets above already exclude every sibling field. This one
        // is named anyway because it is the defect: the flat bag disclosed
        // `note` to `remove`, and the handler rejected the caller who sent it.
        assert!(
            !properties_of(remove).contains("note"),
            "remove must not disclose note"
        );

        let add_validator = jsonschema::validator_for(&add.input_schema).unwrap();
        let remove_validator = jsonschema::validator_for(&remove.input_schema).unwrap();
        let list_validator = jsonschema::validator_for(&list.input_schema).unwrap();
        assert!(add_validator.is_valid(&json!({
            "source_id": "rec-a", "target_id": "rec-b",
            "relationship": "relates_to", "note": "why"
        })));
        assert!(!add_validator.is_valid(&json!({
            "source_id": "rec-a", "target_id": "rec-b",
            "relationship": "relates_to", "record_id": "rec-a"
        })));
        assert!(remove_validator.is_valid(&json!({
            "source_id": "rec-a", "target_id": "rec-b",
            "relationship": "relates_to"
        })));
        assert!(!remove_validator.is_valid(&json!({
            "source_id": "rec-a", "target_id": "rec-b",
            "relationship": "relates_to", "note": "why"
        })));
        assert!(list_validator.is_valid(&json!({
            "record_id": "rec-a"
        })));
        assert!(!list_validator.is_valid(&json!({
            "record_id": "rec-a", "note": "why"
        })));
        assert!(!list_validator.is_valid(&json!({
            "record_id": "rec-a", "source_id": "rec-a"
        })));
    }

    /// Task 667c083 — source-derived argument-naming audit: traversal helpers.
    ///
    /// These walk the **runtime contract map** (the per-operation
    /// `input_schema` that `describe_operation` serves), not the committed
    /// JSON projection, which carries only envelope fields. Keeping the
    /// traversal here puts it in the same place as a future cross-executor
    /// naming build test: the snapshot test below consumes exactly these
    /// helpers, so one traversal yields both the report input and the gate.
    #[derive(Debug, Default)]
    struct AuditArgEntry {
        types: std::collections::BTreeSet<String>,
        required_always: bool,
        required_sometimes: bool,
        nested: bool,
    }

    /// One-line type summary for a property subschema. Deterministic and
    /// compact: it captures the scalar-vs-array distinction the shape-drift
    /// class needs, while full prose stays behind `describe_operation`.
    fn audit_branch_kind(schema: &Value) -> String {
        if schema.get("const").is_some() {
            return "const".into();
        }
        match schema.get("type") {
            Some(Value::String(t)) => t.clone(),
            Some(Value::Array(ts)) => ts
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join("|"),
            _ => {
                if schema.get("enum").is_some() {
                    "enum".into()
                } else if schema.get("properties").is_some() {
                    "object".into()
                } else if schema.get("items").is_some() {
                    "array".into()
                } else {
                    "untyped".into()
                }
            }
        }
    }

    fn audit_type_summary(schema: &Value) -> String {
        if let Some(c) = schema.get("const") {
            return format!("const:{c}");
        }
        let mut base = audit_branch_kind(schema);
        if base == "untyped" {
            for keyword in ["anyOf", "oneOf", "allOf"] {
                if let Some(branches) = schema.get(keyword).and_then(Value::as_array) {
                    let inner = branches
                        .iter()
                        .map(audit_branch_kind)
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join("|");
                    base = format!("{keyword}[{inner}]");
                    break;
                }
            }
        }
        if base == "array" {
            if let Some(items) = schema.get("items") {
                let items_vec: Vec<&Value> = match items {
                    Value::Array(tuple) => tuple.iter().collect(),
                    single => vec![single],
                };
                let inner = items_vec
                    .iter()
                    .map(|item| audit_branch_kind(item))
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join("|");
                if !inner.is_empty() && inner != "untyped" {
                    base = format!("array<{inner}>");
                }
            }
        }
        if let Some(values) = schema.get("enum").and_then(Value::as_array) {
            let shown = values
                .iter()
                .take(12)
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| value.to_string())
                })
                .collect::<Vec<_>>()
                .join("|");
            let suffix = if values.len() > 12 {
                format!("|+{}", values.len() - 12)
            } else {
                String::new()
            };
            base = format!("{base}={shown}{suffix}");
        }
        base
    }

    /// Recursive walk of one operation `input_schema`. `unconditional` is
    /// true at the top level and inside `allOf` (which every valid envelope
    /// must satisfy), false inside `anyOf`/`oneOf`/`then` and below the first
    /// nesting level. `if` subschemas are skipped deliberately: they restate
    /// names for condition matching, not for acceptance. `not` subschemas
    /// are skipped for the same reason in reverse: they forbid combinations,
    /// they do not accept names.
    fn audit_walk_node(
        node: &Value,
        unconditional: bool,
        prefix: &str,
        nested: bool,
        out: &mut BTreeMap<String, AuditArgEntry>,
    ) {
        let required = node
            .get("required")
            .and_then(Value::as_array)
            .map(|required| {
                required
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<HashSet<&str>>()
            })
            .unwrap_or_default();
        // Requiredness is applied to every name in this node's `required`
        // set, whether or not the node declares it in `properties`. Branches
        // of the form `{"required": ["id"]}` with no `properties` — exactly
        // what `with_record_selector_aliases` emits when it replaces the
        // `id`/`record_id`/`ids` required entries with a `oneOf` — still
        // constrain the operation; the sibling branch carrying the
        // declaration merges through the shared entry. A name required on a
        // branch but declared in no `properties` anywhere surfaces with an
        // empty `types` set, which is itself a finding (see the report).
        for name in &required {
            let full = if prefix.is_empty() {
                (*name).to_string()
            } else {
                format!("{prefix}.{name}")
            };
            let entry = out.entry(full).or_default();
            entry.nested = entry.nested || nested;
            if unconditional {
                entry.required_always = true;
            } else {
                entry.required_sometimes = true;
            }
        }
        if let Some(properties) = node.get("properties").and_then(Value::as_object) {
            for (name, subschema) in properties {
                let full = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                let entry = out.entry(full.clone()).or_default();
                entry.types.insert(audit_type_summary(subschema));
                entry.nested = entry.nested || nested;
                // Requiredness was already applied above for every name in
                // this node's `required` set, so there is exactly one
                // application point regardless of schema layout.
                // One nesting level for object properties and array items
                // keeps the enumeration bounded; deeper structure stays
                // recoverable via describe_operation.
                if !nested {
                    if subschema.get("properties").is_some() {
                        audit_walk_node(subschema, false, &full, true, out);
                    }
                    if let Some(items) = subschema.get("items") {
                        let items_vec: Vec<&Value> = match items {
                            Value::Array(tuple) => tuple.iter().collect(),
                            single => vec![single],
                        };
                        for item in items_vec {
                            if item.get("properties").is_some() {
                                audit_walk_node(item, false, &format!("{full}[]"), true, out);
                            }
                        }
                    }
                }
            }
        }
        if let Some(branches) = node.get("allOf").and_then(Value::as_array) {
            for branch in branches {
                audit_walk_node(branch, unconditional, prefix, nested, out);
            }
        }
        for keyword in ["anyOf", "oneOf"] {
            if let Some(branches) = node.get(keyword).and_then(Value::as_array) {
                for branch in branches {
                    audit_walk_node(branch, false, prefix, nested, out);
                }
            }
        }
        if let Some(then) = node.get("then") {
            audit_walk_node(then, false, prefix, nested, out);
        }
    }

    /// Task 667c083: enumerate every property name on every operation
    /// contract in the runtime contract map, per surface. The ordinary
    /// catalogue is the hosted one serve exposes (membership, workspace and
    /// reach included); the lens catalogue is pinned from the same registry.
    /// Rows are keyed `surface.executor.operation` so a same-named operation
    /// whose schema differs per surface shows up twice rather than merging.
    fn audit_enumeration() -> Value {
        let registry = hosted_registry();
        let ordinary = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            true,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let lens = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
            &registry,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let mut rows = Vec::new();
        for (surface, catalogue) in [("ordinary", &ordinary.contracts), ("lens", &lens.contracts)] {
            for ((executor, operation), contract) in catalogue {
                let mut args = BTreeMap::new();
                audit_walk_node(&contract.input_schema, true, "", false, &mut args);
                let arguments = args
                    .into_iter()
                    .map(|(name, entry)| {
                        let required = if entry.required_always {
                            "always"
                        } else if entry.required_sometimes {
                            "sometimes"
                        } else {
                            "never"
                        };
                        (
                            name,
                            json!({
                                "types": entry.types.into_iter().collect::<Vec<_>>(),
                                "required": required,
                                "nested": entry.nested,
                            }),
                        )
                    })
                    .collect::<serde_json::Map<_, _>>();
                rows.push(json!({
                    "surface": surface,
                    "executor": executor,
                    "operation": operation,
                    "source_tool": contract.source_tool,
                    "action_specific_projection": contract.action_specific_projection,
                    "additional_properties": contract.input_schema.get("additionalProperties"),
                    "arguments": arguments,
                }));
            }
        }
        rows.sort_by(|left, right| {
            let key = |row: &Value| {
                (
                    row["surface"].as_str().unwrap_or_default().to_string(),
                    row["executor"].as_str().unwrap_or_default().to_string(),
                    row["operation"].as_str().unwrap_or_default().to_string(),
                )
            };
            key(left).cmp(&key(right))
        });
        let operation_count = rows.len();
        let executor_count = rows
            .iter()
            .map(|row| (row["surface"].clone(), row["executor"].clone()))
            .collect::<HashSet<_>>()
            .len();
        json!({
            "producer": "argument_naming_audit_enumeration_matches_snapshot (task 667c083)",
            "note": "Source-derived from the runtime contract map (input_schema per operation). Top-level argument names carry full type+requiredness; one nesting level (parent.child, array items as parent[]) is enumerated with nested=true and requiredness relative to the parent. `if` subschemas are skipped (condition matching, not acceptance). Deeper structure is recoverable via describe_operation.",
            "operation_count": operation_count,
            "surface_executor_count": executor_count,
            "rows": rows,
        })
    }

    /// Task 667c083: cross-executor naming gate (seed).
    ///
    /// Fails on any new operation, removed operation, or argument change
    /// until the audit snapshot is deliberately refreshed with
    /// `NAMING_AUDIT_UPDATE=1`, which rewrites
    /// `docs/mcp-argument-naming-audit.raw.json` — the raw input of
    /// `docs/mcp-argument-naming-audit.md`. A red run therefore means
    /// either surface drift to triage into the report, or a stale
    /// snapshot to refresh; it never means "update the snapshot blindly".
    fn audit_index_rows(value: &Value) -> BTreeMap<String, &Value> {
        value["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                (
                    format!(
                        "{}.{}.{}",
                        row["surface"].as_str().unwrap(),
                        row["executor"].as_str().unwrap(),
                        row["operation"].as_str().unwrap()
                    ),
                    row,
                )
            })
            .collect::<BTreeMap<_, _>>()
    }

    #[test]
    fn argument_naming_audit_enumeration_matches_snapshot() {
        let enumeration = audit_enumeration();
        let path = format!(
            "{}/docs/mcp-argument-naming-audit.raw.json",
            env!("CARGO_MANIFEST_DIR")
        );
        if std::env::var("NAMING_AUDIT_UPDATE").is_ok_and(|value| value == "1") {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&enumeration).unwrap() + "\n",
            )
            .unwrap();
            println!(
                "naming audit snapshot refreshed: {} rows",
                enumeration["operation_count"]
            );
            return;
        }
        let raw = std::fs::read_to_string(&path).expect(
            "naming audit snapshot missing: run with NAMING_AUDIT_UPDATE=1 to generate docs/mcp-argument-naming-audit.raw.json",
        );
        let expected: Value = serde_json::from_str(&raw).unwrap();
        if expected == enumeration {
            return;
        }
        let mut detail = String::new();
        let before = audit_index_rows(&expected);
        let after = audit_index_rows(&enumeration);
        for key in before.keys().filter(|key| !after.contains_key(*key)) {
            detail.push_str(&format!("removed operation: {key}\n"));
        }
        for key in after.keys().filter(|key| !before.contains_key(*key)) {
            detail.push_str(&format!("added operation: {key}\n"));
        }
        for key in before.keys().filter(|key| after.contains_key(*key)) {
            let old_args = before[key]["arguments"].as_object().unwrap();
            let new_args = after[key]["arguments"].as_object().unwrap();
            for name in old_args.keys().filter(|name| !new_args.contains_key(*name)) {
                detail.push_str(&format!("{key}: removed argument {name}\n"));
            }
            for name in new_args.keys().filter(|name| !old_args.contains_key(*name)) {
                detail.push_str(&format!("{key}: added argument {name}\n"));
            }
            for name in old_args.keys().filter(|name| new_args.contains_key(*name)) {
                if old_args.get(name.as_str()) != new_args.get(name.as_str()) {
                    detail.push_str(&format!(
                        "{key}: changed argument {name}: {} -> {}\n",
                        old_args.get(name.as_str()).unwrap(),
                        new_args.get(name.as_str()).unwrap()
                    ));
                }
            }
            if before[key]["additional_properties"] != after[key]["additional_properties"] {
                detail.push_str(&format!(
                    "{key}: additionalProperties {} -> {}\n",
                    before[key]["additional_properties"], after[key]["additional_properties"]
                ));
            }
        }
        panic!(
            "naming audit snapshot drifted ({} -> {} operations). Refresh only after triaging into docs/mcp-argument-naming-audit.md; regenerate with NAMING_AUDIT_UPDATE=1.\n{detail}",
            expected["operation_count"], enumeration["operation_count"]
        );
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
            37
        );
    }

    #[test]
    fn ordinary_executor_formats_are_conditional_and_inner_contracts_reject_them() {
        let registry = registry();
        let catalogue = build_ordinary_catalogue(
            &registry,
            super::super::registry::EngineKind::Sqlite,
            false,
            &ExperimentalExecutors::empty(),
        )
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
            Some(
                "membership_read"
                    | "membership_admin"
                    | "membership_remove"
                    | "workspace_read"
                    | "export"
            )
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
                            "create_guest_link",
                            "revoke_guest_link",
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
        } = build_lens_contracts(
            &registry,
            &sources,
            &audit.audit_rows,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
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
        } = build_lens_contracts(
            &registry,
            &restricted_sources,
            &audit.audit_rows,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
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
            // The repair never echoes the payload: no `preserved_intent`, no
            // `corrected_envelope`, no `retry`. The caller holds the request
            // it just sent; the repair carries the bounded offending value
            // and the minimal patch list instead.
            assert!(repair.get("preserved_intent").is_none(), "{repair}");
            assert!(repair.get("corrected_envelope").is_none(), "{repair}");
            assert!(repair.get("retry").is_none(), "{repair}");
            let envelope = json!({
                "operation": "query_record",
                "arguments": invalid_arguments,
                "run_key": run_key,
            });
            let failing_pointer = repair["failing_pointer"].as_str().unwrap();
            match envelope.pointer(failing_pointer) {
                Some(offending) => {
                    let failing_value = &repair["failing_value"];
                    assert_eq!(failing_value["pointer"], failing_pointer, "{repair}");
                    let length = failing_value["length"].as_u64().unwrap() as usize;
                    let truncated = failing_value["truncated"].as_bool().unwrap();
                    match offending {
                        Value::String(text) => {
                            assert_eq!(length, text.chars().count(), "{repair}");
                            let echoed = failing_value["value"].as_str().unwrap();
                            assert!(echoed.chars().count() <= 200, "{repair}");
                            assert_eq!(truncated, length > 200, "{repair}");
                            if truncated {
                                assert_eq!(
                                    echoed,
                                    text.chars().take(200).collect::<String>(),
                                    "{repair}"
                                );
                            } else {
                                assert_eq!(echoed, text, "{repair}");
                            }
                        }
                        _ => {
                            let serialised = serde_json::to_string(offending).unwrap();
                            assert_eq!(length, serialised.chars().count(), "{repair}");
                            assert_eq!(truncated, length > 200, "{repair}");
                            if truncated {
                                assert_eq!(
                                    failing_value["value"].as_str().unwrap(),
                                    serialised.chars().take(200).collect::<String>(),
                                    "{repair}"
                                );
                            } else {
                                assert_eq!(failing_value["value"], *offending, "{repair}");
                            }
                        }
                    }
                }
                // A required-field-missing failure names a field that is
                // absent, so the pointer cannot resolve — omitting the field
                // is the expected case.
                None => assert!(repair.get("failing_value").is_none(), "{repair}"),
            }
            let retry_ready = id == 72;
            assert_eq!(repair["retry_ready"], retry_ready, "{repair}");
            if retry_ready {
                let corrections = repair["corrections"].as_array().unwrap();
                assert!(!corrections.is_empty(), "{repair}");
                for correction in corrections {
                    assert!(correction["pointer"].as_str().is_some(), "{repair}");
                    // A set carries either a literal `value` or a `from`
                    // reference into the caller's own envelope — never both,
                    // and a removal carries neither of the two.
                    let is_remove = correction.get("remove").and_then(Value::as_bool) == Some(true);
                    assert_eq!(
                        correction.get("value").is_some(),
                        !is_remove && correction.get("from").is_none(),
                        "{repair}"
                    );
                    assert_eq!(
                        correction.get("from").and_then(Value::as_str).is_some(),
                        !is_remove && correction.get("value").is_none(),
                        "{repair}"
                    );
                }
                let corrected = apply_test_corrections(&envelope, corrections);
                let callable_schema = tools
                    .iter()
                    .find(|tool| tool["name"] == "records_read")
                    .unwrap()["inputSchema"]
                    .clone();
                let callable_validator = jsonschema::validator_for(&callable_schema).unwrap();
                assert!(
                    callable_validator.is_valid(&corrected),
                    "applying the corrections must yield an envelope accepted by tools/list: {repair}"
                );
                let corrected_arguments = corrected["arguments"].clone();
                let validator = jsonschema::validator_for(
                    &describe["result"]["structuredContent"]["input_schema"],
                )
                .unwrap();
                assert!(validator.is_valid(&corrected_arguments), "{repair}");
                super::super::tools::querying::validate_query_record_operation(corrected_arguments)
                    .unwrap();
            } else {
                assert!(repair.get("corrections").is_none(), "{repair}");
            }
        }
        assert!(
            localised_seen > 0 && fallback_seen > 0,
            "both repair shapes must stay covered: localised={localised_seen} fallback={fallback_seen}"
        );

        // A genuinely misspelled field has to be correctable from the repair
        // alone. All three singular/batch selector spellings are intentional
        // now, so use `record_ids` as the negative specimen. The repair omits
        // the contract for this class, making its accepted-name list the
        // caller's only route to a supported spelling.
        let misspelled = server
            .handle_message(json!({
                "jsonrpc":"2.0",
                "id":73,
                "method":"tools/call",
                "params":{
                    "name":"records_read",
                    "arguments":{
                        "operation":"get_record",
                        "arguments":{"record_ids":"read-fixture-a748b2"},
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
            misspelled["failing_pointer"], "/arguments/record_ids",
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
        assert!(accepted.contains(&"id"), "{misspelled}");
        assert!(accepted.contains(&"record_id"), "{misspelled}");
        assert!(!accepted.contains(&"record_ids"), "{misspelled}");
        assert!(
            misspelled["expected_shape"]["required_properties"].is_array(),
            "{misspelled}"
        );
        // The offending value travels bounded: the misspelled field resolves
        // in the caller's own envelope, so it is echoed at most at 200 chars.
        assert_eq!(
            misspelled["failing_value"],
            json!({
                "pointer": "/arguments/record_ids",
                "value": "read-fixture-a748b2",
                "length": 19,
                "truncated": false,
            }),
            "{misspelled}"
        );
        assert!(misspelled.get("preserved_intent").is_none(), "{misspelled}");
        assert!(
            misspelled.get("corrected_envelope").is_none(),
            "{misspelled}"
        );
        assert!(misspelled.get("retry").is_none(), "{misspelled}");
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
        assert!(repair.get("preserved_intent").is_none(), "{repair}");
        assert!(repair.get("corrected_envelope").is_none(), "{repair}");
        assert!(repair.get("retry").is_none(), "{repair}");
        // `/arguments/steps` names a field the envelope never had — the steps
        // sat at the top level — so the pointer cannot resolve and the field
        // is omitted rather than nulled.
        assert!(repair.get("failing_value").is_none(), "{repair}");
        let envelope = json!({
            "operation": "query_record",
            "steps": [{"step": "filter", "types": ["task"]}],
            "limit": 10,
            "run_key": "read-routing-a748b2",
        });
        let corrections = repair["corrections"].as_array().unwrap();
        assert!(!corrections.is_empty(), "{repair}");
        // A removal must be distinguishable from an explicit null.
        assert!(
            corrections
                .iter()
                .any(|correction| correction.get("remove") == Some(&json!(true))),
            "moved fields must leave explicit removals behind: {repair}"
        );
        let corrected = apply_test_corrections(&envelope, corrections);
        assert_eq!(corrected["arguments"]["steps"][0]["types"], json!(["task"]));
        assert_eq!(corrected["arguments"]["limit"], 10);
        assert!(corrected.get("steps").is_none());
        assert!(corrected.get("limit").is_none());

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
        // Captures run on the handle's background queue; drain before
        // asserting per-tool dispatch counts.
        db.drain_captures().await;
        let source_calls: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls WHERE tool='query_record'")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(source_calls, 0, "ordinary reads leave no raw capture rows");
        let events = server.trace_events();
        let dispatched = events
            .iter()
            .filter(|event| {
                event["selection"]["executor"] == "records_read"
                    && event["selection"]["operation"] == "query_record"
                    && event["validation"]["schema_valid"] == true
                    && event["validation"]["runtime_valid"] == true
                    && event["counts"]["tool_calls"] == 1
            })
            .count();
        assert_eq!(dispatched, 2, "each successful facade call dispatches once");
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
        assert!(diagnostic.get("corrected_envelope").is_none());
        assert!(diagnostic.get("retry").is_none());
        assert!(diagnostic.get("preserved_intent").is_none());
        assert!(diagnostic.get("corrections").is_none());
        // Execution diagnostics never name a failing envelope field, so
        // there is no offending value to bound.
        assert!(diagnostic.get("failing_value").is_none());
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
    /// prevent, so both codes stay ordinary execution diagnostics with no
    /// `corrections`.
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
            assert!(repair.get("corrected_envelope").is_none(), "{repair}");
            assert!(repair.get("retry").is_none(), "{repair}");
            assert!(repair.get("preserved_intent").is_none(), "{repair}");
            assert!(repair.get("corrections").is_none(), "{repair}");
            assert!(repair.get("failing_value").is_none(), "{repair}");
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
        let BuiltContracts { contracts, .. } = build_lens_contracts(
            &registry,
            &sources,
            &audit.audit_rows,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
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
        assert!(diagnostic.get("corrected_envelope").is_none());
        assert!(diagnostic.get("retry").is_none());
        assert!(diagnostic.get("preserved_intent").is_none());
        assert!(diagnostic.get("corrections").is_none());
        assert!(diagnostic.get("failing_value").is_none());
        // The envelope matched the contract, so the contract cannot explain
        // this failure and must not be shipped alongside a message saying so.
        assert!(diagnostic.get("input_schema").is_none(), "{diagnostic}");
        assert!(diagnostic["contract_reference"].is_object(), "{diagnostic}");
    }

    /// A digest conflict must not cost more than the write it refused. It is
    /// an execution error, so it carries no echo of the payload and no
    /// correction — and, because the envelope matched the contract, no
    /// `input_schema` either. What remains is fixed scaffolding: the source's
    /// own message, the guidance, the digest, and the pointer to
    /// `describe_operation`.
    ///
    /// So the property is constancy, not a bare byte comparison. A rejection
    /// that is 1.1KB whatever you send is cheap on the four-anchor patch this
    /// task was written about — where the payload is roughly double the edited
    /// text — and cannot be made arbitrarily expensive by making the request
    /// bigger. Before the `input_schema` came off this path it was 3,179 bytes,
    /// 2,352 of which were the schema the caller had already satisfied.
    #[tokio::test]
    async fn digest_conflict_repair_does_not_scale_with_the_patch() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let contract = server
            .contracts
            .get(&("records_write".into(), "update_record".into()))
            .unwrap()
            .clone();
        // Anchors the length of real prose, which is what a four-anchor patch
        // on a real record looks like.
        let envelope_for = |anchor_chars: usize| {
            let anchor = |seed: char| "x".repeat(anchor_chars).replace('x', &seed.to_string());
            json!({
                "operation": "update_record",
                "arguments": {
                    "id": "digest-conflict-record",
                    "reason": "Exercise a four-anchor stale write",
                    "if_body_digest": "a-digest-the-caller-read-earlier",
                    "body_replace": [
                        {"old": anchor('a'), "new": anchor('b')},
                        {"old": anchor('c'), "new": anchor('d')},
                        {"old": anchor('e'), "new": anchor('f')},
                        {"old": anchor('g'), "new": anchor('h')},
                    ],
                },
                "run_key": "digest-conflict-4f21ab",
            })
        };
        let repair_for = |envelope: &Value| {
            let mut result = json!({"structuredContent": {}});
            attach_repair_result(
                &mut result,
                &contract,
                "execution_error",
                Some(
                    "update_record: stale write conflict — the body changed since the caller read it",
                ),
                envelope,
                None,
            );
            result["structuredContent"]["repair"].take()
        };

        let modest = envelope_for(80);
        let large = envelope_for(4_000);
        let modest_repair = repair_for(&modest);
        let large_repair = repair_for(&large);
        assert!(
            modest_repair.get("input_schema").is_none(),
            "the schema the caller already satisfied must not travel: {modest_repair}"
        );
        let modest_bytes = serde_json::to_string(&modest_repair).unwrap().len();
        let large_bytes = serde_json::to_string(&large_repair).unwrap().len();

        // Constant: a bigger patch does not buy a bigger rejection.
        assert_eq!(
            modest_bytes, large_bytes,
            "a digest conflict must cost the same whatever the patch: \
             {modest_bytes} vs {large_bytes}"
        );
        // Bounded by a small absolute ceiling, so the constancy above is
        // constancy at a cheap value rather than at an expensive one. The
        // remainder is the source's message, the guidance, the digest and the
        // `describe_operation` pointer — all worth their bytes. It crosses
        // below the size of the request itself once the patch exceeds ~1.2KB,
        // which a four-anchor patch on real prose does.
        assert!(
            modest_bytes < 1_536,
            "a digest conflict must stay near its fixed scaffolding, \
             was {modest_bytes}: {modest_repair}"
        );
    }

    /// A rejection's size must not scale with the size of the submitted body.
    /// Two envelopes failing the same way — one with a small body, one with a
    /// ~20KB body — must produce repair blocks within a small constant of
    /// each other. The old shape echoed the whole payload three times over
    /// (`preserved_intent`, `corrected_envelope`, `retry.arguments`); the
    /// descended composite shape names the rejected field and carries no
    /// offending value at all.
    #[tokio::test]
    async fn repair_size_does_not_scale_with_submitted_body() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let contract = server
            .contracts
            .get(&("records_write".into(), "update_record".into()))
            .unwrap()
            .clone();
        let envelope_for = |body: String| {
            json!({
                "operation": "update_record",
                "arguments": {
                    "id": "repair-size-record",
                    "reason": "Exercise bounded rejection size",
                    "body": body,
                    "bogus_field": true,
                },
                "run_key": "repair-size-a748b2",
            })
        };
        let repair_for = |envelope: &Value| {
            let mut result = json!({"structuredContent": {}});
            attach_repair_result(
                &mut result,
                &contract,
                "validation_failure",
                Some("test diagnostic"),
                envelope,
                None,
            );
            result["structuredContent"]["repair"].take()
        };
        let small = envelope_for("small body".into());
        // The marker sits past the truncation bound: if any part of the large
        // body leaks into the repair beyond the 200-char window, it shows up.
        let large_body = format!("{}TAIL-MARKER", "y".repeat(20_000));
        let large = envelope_for(large_body);
        assert!(
            serde_json::to_string(&large).unwrap().len()
                - serde_json::to_string(&small).unwrap().len()
                > 19_000,
            "the test is vacuous unless the envelopes differ hugely"
        );
        let small_repair = repair_for(&small);
        let large_repair = repair_for(&large);
        // The `update_record` contract wraps its variants in `oneOf`; descent
        // names the rejected field in the closest branch instead of the whole
        // combinator. The cue is value-free, so neither body size travels.
        for repair in [&small_repair, &large_repair] {
            assert_eq!(repair["reason_code"], "unexpected_field", "{repair}");
            assert_eq!(
                repair["failing_pointer"], "/arguments/bogus_field",
                "{repair}"
            );
            assert_eq!(
                repair["expected_shape"]["keyword"], "additionalProperties",
                "{repair}"
            );
            let accepted = repair["expected_shape"]["accepted_properties"]
                .as_array()
                .expect("rejected name must be answered with accepted names");
            assert!(
                accepted.iter().any(|name| name == "id"),
                "caller must recover without describe_operation: {repair}"
            );
            assert!(repair.get("failing_value").is_none(), "{repair}");
            assert_eq!(repair["retry_ready"], false, "{repair}");
            assert!(repair.get("preserved_intent").is_none(), "{repair}");
            assert!(repair.get("corrected_envelope").is_none(), "{repair}");
            assert!(repair.get("retry").is_none(), "{repair}");
            assert!(repair.get("corrections").is_none(), "{repair}");
        }
        let small_text = serde_json::to_string(&small_repair).unwrap();
        let large_text = serde_json::to_string(&large_repair).unwrap();
        assert!(
            !large_text.contains("TAIL-MARKER"),
            "the large body leaked into the repair"
        );
        let gap = (large_text.len() as i64 - small_text.len() as i64).abs();
        // The window itself is 200 chars, so the two repairs may differ by up
        // to ~that plus serialisation slack — and by never more, however large
        // the payload grows.
        assert!(
            gap <= 256,
            "same failure, ~20KB apart in payload, {gap} bytes apart in repair"
        );
        db.close().await;
    }

    fn test_contract(operation: &str, input_schema: Value) -> OperationContract {
        OperationContract {
            surface: ExecutorSurface::Ordinary,
            executor: "test".into(),
            operation: operation.into(),
            source_tool: "test".into(),
            tool_description: String::new(),
            selector: None,
            input_schema,
            selector_specific_schema: false,
            action_specific_projection: true,
            access: OperationAccess::Mutation,
            digest: "test-digest".into(),
            bytes: 0,
        }
    }

    /// bff6395 regression: `update_record` with a definitely-unknown property
    /// (`recordd_id` survives the e674559 alias work; `record_id` itself may
    /// become valid) must name the rejected field and the accepted names,
    /// value-free end to end. Exercised on stdio and hosted alike: the
    /// schema-error diagnostic is masked for composites, `failing_value` is
    /// suppressed for descended cues, and the text block carries the field
    /// name via the JSON repair it appends.
    #[tokio::test]
    async fn oneof_descent_names_unknown_property_value_free() {
        const UNKNOWN_SENTINEL: &str = "SENTINEL_UNKNOWN_BFF6395";
        const BODY_SENTINEL: &str = "SENTINEL_BODY_BFF6395_APPEND";

        async fn exercise(server: &ExecutorPrototypeStdioServer) {
            // Default, explicit `json`, and explicit `text` envelopes share
            // one contract cue; the text block carries the field name in all
            // three because the renderer appends the JSON repair.
            for (offset, format) in [None, Some("json"), Some("text")].into_iter().enumerate() {
                let mut envelope = json!({
                    "operation": "update_record",
                    "arguments": {
                        "recordd_id": UNKNOWN_SENTINEL,
                        "reason": "bff6395 descent probe",
                        "body_append": BODY_SENTINEL,
                    },
                    "run_key": "bff6395-descent-a748b2",
                });
                if let Some(format) = format {
                    envelope["format"] = json!(format);
                }
                let response = server
                    .handle_message(json!({
                        "jsonrpc": "2.0",
                        "id": 63950 + offset as i64,
                        "method": "tools/call",
                        "params": {
                            "name": "records_write",
                            "arguments": envelope,
                        },
                    }))
                    .await
                    .unwrap();
                assert_eq!(response["result"]["isError"], true, "{response}");
                // No input value anywhere in the serialized response.
                let serialized = serde_json::to_string(&response).unwrap();
                for sentinel in [UNKNOWN_SENTINEL, BODY_SENTINEL] {
                    assert!(
                        !serialized.contains(sentinel),
                        "descended cue reflected input value {sentinel}: {serialized}"
                    );
                }
                let repair = &response["result"]["structuredContent"]["repair"];
                assert_eq!(repair["code"], "operation_contract_repair", "{repair}");
                assert_eq!(repair["reason_code"], "unexpected_field", "{repair}");
                assert_eq!(
                    repair["failing_pointer"], "/arguments/recordd_id",
                    "{repair}"
                );
                assert_eq!(
                    repair["expected_shape"]["keyword"], "additionalProperties",
                    "{repair}"
                );
                let accepted = repair["expected_shape"]["accepted_properties"]
                    .as_array()
                    .expect("rejected name must be answered with accepted names");
                assert!(
                    accepted.iter().any(|name| name == "id"),
                    "caller must recover `id` without describe_operation: {repair}"
                );
                assert!(
                    repair["expected_shape"]["required_properties"].is_array(),
                    "{repair}"
                );
                assert!(repair.get("input_schema").is_none(), "{repair}");
                assert!(repair.get("failing_value").is_none(), "{repair}");
                assert!(repair.get("preserved_intent").is_none(), "{repair}");
                assert!(repair.get("corrected_envelope").is_none(), "{repair}");
                assert!(repair.get("retry").is_none(), "{repair}");
                assert_eq!(repair["retry_ready"], false, "{repair}");
                assert!(repair.get("corrections").is_none(), "{repair}");
                // No valid selector was supplied, so the alias diagnostic takes
                // precedence while the repair still names the unknown field.
                let diagnostic = repair["diagnostic"].as_str().unwrap_or_default();
                assert!(
                    diagnostic.contains("update_record accepts exactly one selector"),
                    "missing selector must explain the accepted aliases: {repair}"
                );
                // Text renderer appends the JSON repair, so the field name and
                // accepted-shape keys travel to `format: text` callers too.
                let text = response["result"]["content"][0]["text"].as_str().unwrap();
                assert!(text.contains("Repair contract:"), "{text}");
                assert!(text.contains("recordd_id"), "{text}");
                assert!(text.contains("accepted_properties"), "{text}");
            }
        }

        let db = create_database(":memory:").await.unwrap();
        let stdio =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        exercise(&stdio).await;

        let catalogue = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        for statement in [
            "CREATE TABLE databases (id TEXT PRIMARY KEY, status TEXT NOT NULL, activity_epoch INTEGER NOT NULL)",
            "CREATE TABLE executor_write_plans (key_id TEXT)",
            "INSERT INTO databases (id, status, activity_epoch) VALUES ('bff6395-hosted-db', 'ready', 0)",
        ] {
            sqlx::query(statement).execute(&catalogue).await.unwrap();
        }
        let hosted = ExecutorPrototypeStdioServer::new_hosted(
            registry(),
            db.clone(),
            Caller::authenticated("bff6395-hosted-account")
                .with_hosting_context("bff6395-hosted-user", "bff6395-hosted-db"),
            Arc::new(SelectorHostedAuthority { pool: catalogue }),
            "bff6395-hosted-db",
            Arc::new(SelectorHostedKeys),
        )
        .await
        .unwrap();
        exercise(&hosted).await;
        db.close().await;
    }

    /// A wrong-typed `id` must stay in the singular branch (`wrong_type` at
    /// `/arguments/id`): the batch branch rejects more names and misses more
    /// keys, so fewest-violations-first keeps the cue where the caller meant.
    #[tokio::test]
    async fn oneof_descent_keeps_wrong_type_in_closest_branch() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 6396,
                "method": "tools/call",
                "params": {
                    "name": "records_write",
                    "arguments": {
                        "operation": "update_record",
                        "arguments": {
                            "id": 42,
                            "reason": "bff6395 wrong-type probe",
                            "body_append": "literal",
                        },
                        "run_key": "bff6395-wrongtype-a748b2",
                    },
                },
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], true, "{response}");
        let repair = &response["result"]["structuredContent"]["repair"];
        assert_eq!(repair["reason_code"], "wrong_type", "{repair}");
        assert_eq!(repair["failing_pointer"], "/arguments/id", "{repair}");
        assert!(repair.get("failing_value").is_none(), "{repair}");
        db.close().await;
    }

    /// A missing `reason` still reports `required_field_missing` at
    /// `/arguments/reason`: top-level required failures never enter descent.
    #[tokio::test]
    async fn oneof_descent_missing_reason_stays_required() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 6397,
                "method": "tools/call",
                "params": {
                    "name": "records_write",
                    "arguments": {
                        "operation": "update_record",
                        "arguments": {
                            "id": "bff6395-missing-reason",
                            "body_append": "literal",
                        },
                        "run_key": "bff6395-required-a748b2",
                    },
                },
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], true, "{response}");
        let repair = &response["result"]["structuredContent"]["repair"];
        assert_eq!(repair["reason_code"], "required_field_missing", "{repair}");
        assert_eq!(repair["failing_pointer"], "/arguments/reason", "{repair}");
        db.close().await;
    }

    /// Frozen pre-alias `update_record` shape: the original `record_id`
    /// report, kept as a unit test on a pinned contract so it survives the
    /// e674559 alias work making `record_id` valid on the live contract.
    #[test]
    fn oneof_descent_original_record_id_on_frozen_contract() {
        let input_schema = json!({
            "type": "object",
            "properties": {"reason": {"type": "string"}},
            "required": ["reason"],
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "reason": {"type": "string"},
                        "body_append": {"type": "string"}
                    },
                    "required": ["id", "reason"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "ids": {"type": "array", "items": {"type": "string"}},
                        "reason": {"type": "string"}
                    },
                    "required": ["ids", "reason"],
                    "additionalProperties": false
                }
            ]
        });
        let contract = test_contract("update_record", input_schema);
        let envelope = json!({
            "operation": "update_record",
            "arguments": {
                "record_id": "frozen-sentinel",
                "reason": "bff6395 frozen probe",
                "body_append": "literal"
            },
            "run_key": "bff6395-frozen-a748b2"
        });
        let cue = repair_cue(&contract, &envelope, None, None);
        assert_eq!(cue.reason_code, "unexpected_field");
        assert_eq!(cue.failing_pointer, "/arguments/record_id");
        assert!(cue.suppress_failing_value);
        let accepted = cue.expected_shape["accepted_properties"]
            .as_array()
            .expect("accepted names must travel");
        assert!(accepted.iter().any(|name| name == "id"));
    }

    /// Each rejected name counts separately, not one per aggregate: branch A
    /// accepts anything with no required keys, so `{b, x, y}` fails it with a
    /// single aggregate rejecting three names; branch B requires `b`, which
    /// the caller supplied, so it fails with a single aggregate rejecting two
    /// names. Aggregate counting ties 1-1 and falls back to index 0 (the
    /// wrong branch); per-name counting picks B 3-2 (the branch the caller
    /// meant) and reports its deterministic smallest name.
    #[test]
    fn composite_descent_counts_each_rejected_name() {
        let input_schema = json!({
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"a": {"type": "string"}},
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {"b": {"type": "string"}},
                    "required": ["b"],
                    "additionalProperties": false
                }
            ]
        });
        let contract = test_contract("probe", input_schema);
        let envelope = json!({
            "operation": "probe",
            "arguments": {"b": "ok", "x": "1", "y": "2"},
            "run_key": "bff6395-count-a748b2"
        });
        let cue = repair_cue(&contract, &envelope, None, None);
        assert_eq!(cue.reason_code, "unexpected_field");
        assert_eq!(cue.failing_pointer, "/arguments/x");
        let accepted = cue.expected_shape["accepted_properties"]
            .as_array()
            .expect("accepted names must travel");
        assert!(accepted.iter().any(|name| name == "b"));
        assert!(!accepted.iter().any(|name| name == "a"));
    }

    /// Nested combinators select their own best branch recursively: the inner
    /// combinator prefers its unexpected-property variant (f2 rejects one
    /// name) over its missing-key variant (f1 misses its key and rejects two
    /// names), so the outer slow branch contributes one violation against the
    /// fast branch's three and the cue names the nested rejected field.
    /// Flattening across the mutually exclusive nested variants would pool
    /// both variants' failures and could not select f2. Covered for both
    /// nested `oneOf` and nested `anyOf` under a top-level `oneOf`.
    #[test]
    fn composite_descent_selects_nested_best_branch_recursively() {
        for nested in ["oneOf", "anyOf"] {
            let input_schema = json!({
                "type": "object",
                "oneOf": [
                    {
                        "type": "object",
                        "properties": {
                            "mode": {"const": "fast"},
                            "speed": {"type": "integer"}
                        },
                        "required": ["mode", "speed"],
                        "additionalProperties": false
                    },
                    {
                        "type": "object",
                        "properties": {
                            "mode": {"const": "slow"},
                            "payload": {
                                "type": "object",
                                nested: [
                                    {
                                        "type": "object",
                                        "properties": {"f1": {"type": "string"}},
                                        "required": ["f1"],
                                        "additionalProperties": false
                                    },
                                    {
                                        "type": "object",
                                        "properties": {"f2": {"type": "string"}},
                                        "required": ["f2"],
                                        "additionalProperties": false
                                    }
                                ]
                            }
                        },
                        "required": ["mode", "payload"],
                        "additionalProperties": false
                    }
                ]
            });
            let contract = test_contract("probe", input_schema);
            let envelope = json!({
                "operation": "probe",
                "arguments": {
                    "mode": "slow",
                    "payload": {"f2": "ok", "deep": "nope"}
                },
                "run_key": "bff6395-nested-a748b2"
            });
            let cue = repair_cue(&contract, &envelope, None, None);
            assert_eq!(cue.reason_code, "unexpected_field", "nested={nested}");
            assert_eq!(
                cue.failing_pointer, "/arguments/payload/deep",
                "nested={nested}"
            );
            assert_eq!(
                cue.expected_shape["keyword"], "additionalProperties",
                "nested={nested}"
            );
            let accepted = cue.expected_shape["accepted_properties"]
                .as_array()
                .expect("nested accepted names must travel");
            assert!(
                accepted.iter().any(|name| name == "f2"),
                "nested={nested}: {accepted:?}"
            );
            let pointer = cue.expected_shape["contract_pointer"]
                .as_str()
                .expect("nested contract pointer must travel");
            assert_eq!(
                pointer,
                &format!("/oneOf/1/properties/payload/{nested}/1/additionalProperties"),
                "nested={nested}"
            );
            assert!(cue.suppress_failing_value, "nested={nested}");
        }
    }

    /// Overlapping branches that both accept the instance stay generic but
    /// value-free: no branch leaf is named, and neither the whole-object
    /// value nor the diagnostic echoes input.
    #[test]
    fn composite_multiple_valid_stays_generic_but_value_free() {
        const SECRET: &str = "OVERLAP_SECRET_BFF6395";
        let input_schema = json!({
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {"a": {"type": "string"}},
                    "required": ["a"]
                },
                {
                    "type": "object",
                    "properties": {"a": {"type": "string"}},
                    "required": ["a"]
                }
            ]
        });
        let contract = test_contract("probe", input_schema);
        let envelope = json!({
            "operation": "probe",
            "arguments": {"a": SECRET},
            "run_key": "bff6395-overlap-a748b2"
        });
        let cue = repair_cue(&contract, &envelope, None, None);
        assert_eq!(cue.reason_code, "schema_constraint_failed");
        assert_eq!(cue.failing_pointer, "/arguments");
        assert!(cue.suppress_failing_value);
        let mut result = json!({"structuredContent": {}});
        attach_repair_result(
            &mut result,
            &contract,
            "validation_failure",
            Some("value is not valid under more than one of the schemas listed in the 'oneOf' keyword"),
            &envelope,
            None,
        );
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(
            !serialized.contains(SECRET),
            "multiply-valid cue leaked its value: {serialized}"
        );
    }

    /// The boundedness guarantee on the path that actually moves bytes: the
    /// probe envelope carries a ~20KB body at the top level (misplaced routing
    /// the repair corrects by moving it under `arguments`), so the old shape
    /// echoed 21KB and `corrections` naively would too. Moves must travel by
    /// reference, keeping the repair small while `retry_ready` stays true.
    #[tokio::test]
    async fn repair_with_retry_ready_does_not_scale_with_submitted_body() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let contract = server
            .contracts
            .get(&("records_write".into(), "update_record".into()))
            .unwrap()
            .clone();
        let envelope = json!({
            "operation": "update_record",
            "id": "probe-record",
            "reason": "Exercise move-by-reference corrections",
            "body": format!("{}TAIL-MARKER", "y".repeat(20_000)),
            "run_key": "repair-probe-a748b2",
        });
        let mut result = json!({"structuredContent": {}});
        attach_repair_result(
            &mut result,
            &contract,
            "validation_failure",
            Some("test diagnostic"),
            &envelope,
            None,
        );
        let repair = &result["structuredContent"]["repair"];
        // With no `arguments` key the validator reports the missing required
        // field of the singular variant first; it names an absent field, so
        // there is no offending value to bound.
        assert_eq!(repair["reason_code"], "required_field_missing", "{repair}");
        assert_eq!(repair["failing_pointer"], "/arguments/reason", "{repair}");
        assert_eq!(repair["retry_ready"], true, "{repair}");
        assert!(repair.get("failing_value").is_none(), "{repair}");
        let corrections = repair["corrections"].as_array().unwrap();
        assert!(!corrections.is_empty(), "{repair}");
        // Every set is a move by reference: no `value`, so no body bytes.
        for correction in corrections {
            if correction.get("remove").and_then(Value::as_bool) == Some(true) {
                assert!(correction.get("value").is_some(), "{repair}");
            } else {
                assert!(
                    correction.get("from").and_then(Value::as_str).is_some(),
                    "{repair}"
                );
                assert!(correction.get("value").is_none(), "{repair}");
            }
        }
        assert!(
            corrections
                .iter()
                .any(|correction| correction["from"] == "/body"),
            "the 20KB body must move by reference: {repair}"
        );
        assert!(repair.get("corrections_total").is_none(), "{repair}");
        let text = serde_json::to_string(repair).unwrap();
        assert!(
            !text.contains("TAIL-MARKER"),
            "the large body leaked into the repair"
        );
        assert!(
            text.len() < 4096,
            "repair with retry_ready=true must stay small, was {} bytes",
            text.len()
        );
        // The reference patch list still applies: resolving `from` against the
        // submitted envelope reproduces the corrected shape.
        let corrected = apply_test_corrections(&envelope, corrections);
        assert_eq!(
            corrected,
            json!({
                "operation": "update_record",
                "arguments": {
                    "id": "probe-record",
                    "reason": "Exercise move-by-reference corrections",
                    "body": envelope["body"],
                },
                "run_key": "repair-probe-a748b2",
            })
        );
        db.close().await;
    }

    #[test]
    fn repair_failing_value_truncates_at_char_boundaries() {
        // Multi-byte content: 300 `é` chars must truncate to exactly 200
        // chars without slicing a codepoint.
        let text = "é".repeat(300);
        let envelope = json!({"arguments": {"body": text}});
        let failing = repair_failing_value("/arguments/body", &envelope).unwrap();
        assert_eq!(failing["pointer"], "/arguments/body");
        assert_eq!(failing["length"], 300);
        assert_eq!(failing["truncated"], true);
        let echoed = failing["value"].as_str().unwrap();
        assert_eq!(echoed.chars().count(), 200);
        assert_eq!(echoed, "é".repeat(200));
        // Short strings travel whole.
        let envelope = json!({"arguments": {"body": "small"}});
        let failing = repair_failing_value("/arguments/body", &envelope).unwrap();
        assert_eq!(
            failing,
            json!({
                "pointer": "/arguments/body",
                "value": "small",
                "length": 5,
                "truncated": false,
            })
        );
        // Non-strings serialise compactly; over the bound they travel as the
        // truncated serialisation string, under it as the value itself.
        let big = json!({"arguments": {"ids": vec!["x".repeat(300)]}});
        let failing = repair_failing_value("/arguments/ids", &big).unwrap();
        assert_eq!(failing["truncated"], true);
        assert_eq!(failing["value"].as_str().unwrap().chars().count(), 200);
        assert_eq!(
            failing["length"],
            serde_json::to_string(&big["arguments"]["ids"])
                .unwrap()
                .chars()
                .count()
        );
        let small = json!({"arguments": {"limit": 10}});
        let failing = repair_failing_value("/arguments/limit", &small).unwrap();
        assert_eq!(
            failing,
            json!({
                "pointer": "/arguments/limit",
                "value": 10,
                "length": 2,
                "truncated": false,
            })
        );
        // A required-field-missing pointer names an absent field.
        let envelope = json!({"arguments": {}});
        assert!(repair_failing_value("/arguments/id", &envelope).is_none());
    }

    #[test]
    fn repair_corrections_diff_leaves_and_marks_removals() {
        let envelope = json!({
            "operation": "query_record",
            "arguments": {"steps": [{"step": "filter"}], "limit": 1},
            "stale": "drop me",
            "run_key": "k",
        });
        let corrected = json!({
            "operation": "query_record",
            "arguments": {"steps": [{"step": "filter", "types": ["task"]}], "limit": 2},
            "run_key": "k",
        });
        let built = repair_corrections(&envelope, &corrected);
        assert!(!built.truncated);
        assert_eq!(built.total, 3);
        let corrections = built.entries;
        // Changed leaves only: the untouched `step` and `run_key` appear
        // nowhere; the dropped top-level field is an explicit removal. A
        // newly present array expands to its scalar leaves. Both new values
        // are small and genuinely new, so they travel literally.
        assert_eq!(
            corrections,
            vec![
                json!({"pointer": "/arguments/limit", "value": 2}),
                json!({
                    "pointer": "/arguments/steps/0/types/0",
                    "value": "task",
                }),
                json!({"pointer": "/stale", "value": null, "remove": true}),
            ]
        );
        // The documented round trip: patching the caller's own envelope with
        // the corrections reproduces the corrected one.
        assert_eq!(apply_test_corrections(&envelope, &corrections), corrected);
        // Identical envelopes diff to nothing.
        let built = repair_corrections(&envelope, &envelope);
        assert!(!built.truncated);
        assert_eq!(built.total, 0);
        assert_eq!(built.entries, Vec::<Value>::new());
    }

    #[test]
    fn repair_corrections_type_change_expands_and_stays_bounded() {
        // A scalar-to-object change shares no structure to diff: the fallback
        // must expand to leaves, and the genuinely new 20KB leaf must travel
        // truncated — never whole.
        let big = format!("{}TAIL-MARKER", "x".repeat(20_000));
        let envelope = json!({"a": 1});
        let corrected = json!({"a": {"x": big}});
        let built = repair_corrections(&envelope, &corrected);
        assert!(built.truncated);
        assert_eq!(built.total, 1);
        let entry = &built.entries[0];
        assert_eq!(entry["pointer"], "/a/x");
        assert_eq!(entry["truncated"], true);
        assert_eq!(
            entry["value"].as_str().unwrap().chars().count(),
            REPAIR_VALUE_CHAR_LIMIT
        );
        let text = serde_json::to_string(&built.entries).unwrap();
        assert!(!text.contains("TAIL-MARKER"));
        assert!(text.len() < 1024);
    }

    #[test]
    fn repair_corrections_array_shrink_removes_descending() {
        // Twelve elements down to two: removals must come out numerically
        // descending (`/arr/11` … `/arr/2`), or applying them in order shifts
        // every later index — and lexicographic sorting would put `/arr/10`
        // before `/arr/2`.
        let envelope = json!({"arr": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]});
        let corrected = json!({"arr": [0, 1]});
        let built = repair_corrections(&envelope, &corrected);
        assert!(!built.truncated);
        let pointers = built
            .entries
            .iter()
            .map(|entry| entry["pointer"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            pointers,
            vec![
                "/arr/11", "/arr/10", "/arr/9", "/arr/8", "/arr/7", "/arr/6", "/arr/5", "/arr/4",
                "/arr/3", "/arr/2",
            ]
        );
        assert!(
            built.entries.iter().all(|entry| entry["remove"] == true),
            "shrinks are removals only: {:?}",
            built.entries
        );
        assert_eq!(apply_test_corrections(&envelope, &built.entries), corrected);
    }

    #[test]
    fn repair_corrections_cap_states_total() {
        // Twenty-five new leaves: only the first 20 travel, with the total
        // stated so the caller knows entries were withheld.
        let mut corrected_map = serde_json::Map::new();
        for index in 0..25 {
            corrected_map.insert(format!("k{index:02}"), json!(index));
        }
        let built = repair_corrections(&json!({}), &Value::Object(corrected_map));
        assert!(!built.truncated);
        assert_eq!(built.total, 25);
        assert_eq!(built.entries.len(), REPAIR_MAX_CORRECTIONS);
        // A capped list is incomplete, so applying it would not reproduce the
        // corrected envelope. It must not advertise an automatic fix, for the
        // same reason a truncated value must not.
        assert!(
            !corrections_are_applicable(&built),
            "a capped patch list is not mechanically applicable"
        );
    }

    #[test]
    fn repair_corrections_under_the_cap_stay_applicable() {
        let mut corrected_map = serde_json::Map::new();
        for index in 0..REPAIR_MAX_CORRECTIONS {
            corrected_map.insert(format!("k{index:02}"), json!(index));
        }
        let built = repair_corrections(&json!({}), &Value::Object(corrected_map));
        assert_eq!(built.total, REPAIR_MAX_CORRECTIONS);
        assert!(corrections_are_applicable(&built));
    }

    #[test]
    fn lens_repair_never_lifts_a_fixed_surface_format_into_the_envelope() {
        let registry = registry();
        let audit: Audit = serde_json::from_str(AUDIT).unwrap();
        let policy =
            super::super::ResolvedToolExposure::new(super::super::ExposureProfile::Complete);
        let sources = lens_descriptor_projection_for_policy(&registry, &policy).unwrap();
        let BuiltContracts { contracts, .. } = build_lens_contracts(
            &registry,
            &sources,
            &audit.audit_rows,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
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
        // Source-tool captures run on the handle's background queue; drain
        // before asserting per-tool dispatch counts.
        db.drain_captures().await;
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
            assert_eq!(source_calls, 0, "{tool} is an uncaptured ordinary read");
        }
        let events = server.trace_events();
        for operation in [
            "query_record",
            "get_record",
            "resolve_many",
            "search",
            "get_structure",
        ] {
            let dispatched = events
                .iter()
                .filter(|event| {
                    event["selection"]["executor"] == "records_read"
                        && event["selection"]["operation"] == operation
                        && event["validation"]["schema_valid"] == true
                        && event["validation"]["runtime_valid"] == true
                        && event["counts"]["tool_calls"] == 1
                })
                .count();
            assert_eq!(dispatched, 1, "{operation} must dispatch exactly once");
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
            "lifecycle_interpretation",
        ] {
            let expected = format!("\"{key}\":");
            assert!(
                default_text.contains(&expected),
                "default prose lost {key}: {default_text}"
            );
        }
        assert!(!default_text.contains("Read scope:"), "{default_text}");
        let omissions = default_text
            .lines()
            .find(|line| line.contains("Additional record fields omitted from text:"))
            .unwrap();
        for key in ["kind_governance", "contribution"] {
            assert!(omissions.contains(key), "{default_text}");
            assert!(!default_text.contains(&format!("\"{key}\":")));
        }

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
        for key in ["kind_governance", "contribution"] {
            assert!(explicit["result"]["structuredContent"]["records"][0][key].is_object());
        }
        assert_eq!(explicit["result"]["structuredContent"]["resolve"], true);

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
            activity_text
                .contains("No visible aggregate activity rows were retained in this scope"),
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

    #[tokio::test]
    async fn record_selector_aliases_have_schema_runtime_and_sqlite_replay_parity() {
        const RECORD_ID: &str = "0537ed75-466f-457c-ad04-bcdf48c4fdbe";
        const SHORT_ID: &str = "0537ed7";

        fn companions(operation: &str, before_seq: i64) -> Value {
            match operation {
                "render_record_version_diff" => json!({"before_seq":before_seq}),
                "manage_attachments.list" => json!({}),
                "manage_links.list" => json!({"limit":1}),
                "manage_facet_observations.list" => json!({"key":"amount", "limit":1}),
                "resolve_rollup" => json!({"rollup_name":"count"}),
                _ => json!({}),
            }
        }

        fn with_selector(mut companions: Value, field: &str, reference: &str) -> Value {
            companions.as_object_mut().unwrap().insert(
                field.into(),
                if field == "ids" {
                    json!([reference])
                } else {
                    json!(reference)
                },
            );
            companions
        }

        fn stable_payload(operation: &str, mut payload: Value) -> Value {
            if operation == "resolve_rollup" {
                let text = payload.as_str().unwrap().replace(" [cache hit]", "");
                payload = json!(text);
            }
            payload
        }

        fn legacy_call(operation: &str, mut arguments: Value) -> (&str, Value) {
            let tool = match operation {
                "manage_attachments.list" => "manage_attachments",
                "manage_links.list" => "manage_links",
                "manage_facet_observations.list" => "manage_facet_observations",
                other => other,
            };
            if operation.contains(".list") {
                arguments["action"] = json!("list");
            }
            (tool, arguments)
        }

        fn stable_structured(operation: &str, mut payload: Value) -> Value {
            if operation == "resolve_rollup" {
                payload.as_object_mut().unwrap().remove("cache_hit");
            }
            payload
        }

        fn schema_has_property(schema: &Value, property: &str) -> bool {
            schema["properties"].get(property).is_some()
                || ["oneOf", "anyOf", "allOf"].into_iter().any(|keyword| {
                    schema[keyword].as_array().is_some_and(|branches| {
                        branches
                            .iter()
                            .any(|branch| schema_has_property(branch, property))
                    })
                })
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("record-selector-aliases.sqlite3");
        let db = create_database(path.to_str().unwrap()).await.unwrap();
        let registry = registry();
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id":RECORD_ID,
                    "type":"Document",
                    "kind":"note",
                    "name":"Record selector alias fixture",
                    "body":"before",
                    "facets":{"rollup":json!({
                        "v":"0.1",
                        "outputs":{"count":{
                            "query":{"steps":[{"step":"filter","home_id":"native:root"}]},
                            "fold":{"op":"count"}
                        }}
                    }).to_string()},
                    "reason":"record selector alias fixture"
                }),
            )
            .await
            .unwrap();
        let before_seq: i64 =
            sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
                .bind(RECORD_ID)
                .fetch_one(db.pool())
                .await
                .unwrap();
        registry
            .call(
                db.clone(),
                Caller::local(),
                "update_record",
                json!({
                    "id":RECORD_ID,
                    "body":"after",
                    "if_body_digest":hex::encode(Sha256::digest(b"before")),
                    "reason":"make a version diff"
                }),
            )
            .await
            .unwrap();
        sqlx::query("DELETE FROM read_log_calls")
            .execute(db.write_pool())
            .await
            .unwrap();

        let server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let operations = [
            ("get_record", "ids"),
            ("render_record", "id"),
            ("render_record_version_diff", "record_id"),
            ("render_suggestion_review", "record_id"),
            ("manage_attachments.list", "record_id"),
            ("manage_links.list", "record_id"),
            ("manage_facet_observations.list", "record_id"),
            ("resolve_rollup", "record_id"),
        ];

        // Discovery and describe_operation expose precisely the same alias
        // contract that runtime accepts.
        for (index, (operation, canonical)) in operations.iter().enumerate() {
            let contract = server
                .contracts
                .get(&("records_read".into(), (*operation).into()))
                .unwrap_or_else(|| panic!("missing records_read.{operation}"));
            let validator = jsonschema::validator_for(&contract.input_schema).unwrap();
            for field in ["id", "record_id", "ids"] {
                let arguments = with_selector(companions(operation, before_seq), field, RECORD_ID);
                assert!(
                    validator.is_valid(&arguments),
                    "{operation}.{field}: {arguments}; {}",
                    contract.input_schema
                );
            }
            let mut invalid_arguments = vec![
                companions(operation, before_seq),
                {
                    let mut value = companions(operation, before_seq);
                    value["ids"] = json!([]);
                    value
                },
                {
                    let mut value = companions(operation, before_seq);
                    value["id"] = json!(RECORD_ID);
                    value["record_id"] = json!(RECORD_ID);
                    value
                },
            ];
            if *operation == "get_record" {
                invalid_arguments.push(with_selector(companions(operation, before_seq), "id", ""));
            } else {
                invalid_arguments.push(with_selector(companions(operation, before_seq), "ids", ""));
                let mut multiple = companions(operation, before_seq);
                multiple["ids"] = json!([RECORD_ID, RECORD_ID]);
                invalid_arguments.push(multiple);
            }
            for arguments in invalid_arguments {
                assert!(!validator.is_valid(&arguments), "{operation}: {arguments}");
            }

            let described = server
                .handle_message(json!({
                    "jsonrpc":"2.0", "id":10_000 + index, "method":"tools/call",
                    "params":{"name":"describe_operation","arguments":{
                        "executor":"records_read", "operation":operation, "format":"json"
                    }}
                }))
                .await
                .unwrap();
            assert_eq!(described["result"]["isError"], false, "{described}");
            assert_eq!(
                described["result"]["structuredContent"]["input_schema"], contract.input_schema,
                "describe drift for {operation}"
            );
            assert!(schema_has_property(&contract.input_schema, canonical));
        }

        // Every operation produces the same semantic payload for every
        // spelling, with both the full id and its unique short reference.
        let mut request_id = 20_000_i64;
        for (operation, canonical) in operations {
            let baseline_arguments =
                with_selector(companions(operation, before_seq), canonical, RECORD_ID);
            let baseline =
                call_records_read(&server, request_id, operation, baseline_arguments).await;
            request_id += 1;
            assert_eq!(baseline["result"]["isError"], false, "{baseline}");
            let expected =
                stable_payload(operation, baseline["result"]["content"][0]["text"].clone());
            for reference in [RECORD_ID, SHORT_ID] {
                for field in ["id", "record_id", "ids"] {
                    let response = call_records_read(
                        &server,
                        request_id,
                        operation,
                        with_selector(companions(operation, before_seq), field, reference),
                    )
                    .await;
                    request_id += 1;
                    assert_eq!(
                        response["result"]["isError"], false,
                        "{operation}.{field}({reference}): {response}"
                    );
                    assert_eq!(
                        stable_payload(operation, response["result"]["content"][0]["text"].clone()),
                        expected,
                        "semantic drift for {operation}.{field}({reference})"
                    );
                }
            }
        }

        // The legacy exact-name surface runs its own operation-aware boundary,
        // rather than relying on the grouped executor's translation.
        for (operation, canonical) in operations {
            let (tool, baseline_arguments) = legacy_call(
                operation,
                with_selector(companions(operation, before_seq), canonical, RECORD_ID),
            );
            let expected = stable_structured(
                operation,
                registry
                    .call(db.clone(), Caller::local(), tool, baseline_arguments)
                    .await
                    .unwrap(),
            );
            for reference in [RECORD_ID, SHORT_ID] {
                for field in ["id", "record_id", "ids"] {
                    let (tool, arguments) = legacy_call(
                        operation,
                        with_selector(companions(operation, before_seq), field, reference),
                    );
                    let actual = registry
                        .call(db.clone(), Caller::local(), tool, arguments)
                        .await
                        .unwrap_or_else(|error| {
                            panic!("legacy {operation}.{field}({reference}): {error}")
                        });
                    assert_eq!(
                        stable_structured(operation, actual),
                        expected,
                        "legacy semantic drift for {operation}.{field}({reference})"
                    );
                }
            }
        }

        // Explicit MCP replay: three differently shaped legacy handlers all
        // consume the same singleton `ids` spelling against disposable SQLite.
        for (operation, arguments) in [
            ("get_record", json!({"ids":[SHORT_ID]})),
            (
                "render_record",
                json!({"ids":[SHORT_ID], "include_interpretation":false}),
            ),
            ("manage_attachments.list", json!({"ids":[SHORT_ID]})),
        ] {
            let response = call_records_read(&server, request_id, operation, arguments).await;
            request_id += 1;
            assert_eq!(response["result"]["isError"], false, "{response}");
        }

        // Runtime selector failures are rejected before the source handler can
        // append a read-log call, and carry one actionable operation-aware cue.
        // Drain first: prior valid calls' captures must have landed, or they
        // race the after-count below.
        db.drain_captures().await;
        let calls_before_invalid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
            .fetch_one(db.pool())
            .await
            .unwrap();
        for (operation, _) in operations {
            let mut invalid_arguments = vec![
                companions(operation, before_seq),
                {
                    let mut value = companions(operation, before_seq);
                    value["ids"] = json!([]);
                    value
                },
                {
                    let mut value = companions(operation, before_seq);
                    value["id"] = json!(RECORD_ID);
                    value["record_id"] = json!(RECORD_ID);
                    value
                },
            ];
            if operation == "get_record" {
                invalid_arguments.push(with_selector(
                    companions(operation, before_seq),
                    "record_id",
                    "",
                ));
            } else {
                let mut multiple = companions(operation, before_seq);
                multiple["ids"] = json!([RECORD_ID, RECORD_ID]);
                invalid_arguments.push(multiple);
            }
            for arguments in invalid_arguments {
                let response = call_records_read(&server, request_id, operation, arguments).await;
                request_id += 1;
                assert_eq!(response["result"]["isError"], true, "{response}");
                let text = response["result"]["content"][0]["text"].as_str().unwrap();
                for needle in [operation, "operation_contract_repair", "retry_ready"] {
                    assert!(text.contains(needle), "missing {needle:?}: {text}");
                }
            }
        }
        let calls_after_invalid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(calls_after_invalid, calls_before_invalid);

        // Equal-value conflicts are rejected, but an exact creation id keeps
        // its existing write meaning and excluded attachment actions do not
        // acquire the alias.
        let creation_id = "1537ed75-466f-457c-ad04-bcdf48c4fdbe";
        let created = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id":creation_id,
                    "type":"Document",
                    "kind":"note",
                    "name":"Boundary fixture",
                    "reason":"prove create_record id semantics are unchanged"
                }),
            )
            .await
            .unwrap();
        assert_eq!(created["id"], creation_id);
        let excluded = registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_attachments",
                json!({"action":"inspect", "ids":[RECORD_ID], "attachment_id":"missing"}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(excluded.contains("ids"), "{excluded}");

        db.close().await;
    }

    /// Write-selector aliases on the direct executor paths (e674559): every
    /// spelling executes the same single-record write the canonical field
    /// would, while conflicts and singleton-batch misuse reject without
    /// writing and without reflecting the selector value.
    #[tokio::test]
    async fn write_selector_aliases_execute_direct_writes_and_reject_conflicts() {
        async fn call_executor(
            server: &ExecutorPrototypeStdioServer,
            id: i64,
            executor: &str,
            operation: &str,
            arguments: Value,
        ) -> Value {
            server
                .handle_message(json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "method":"tools/call",
                    "params":{
                        "name":executor,
                        "arguments":{
                            "operation":operation,
                            "arguments":arguments,
                            "run_key":"write-selector-alias-3f71aa",
                            "format":"json"
                        }
                    }
                }))
                .await
                .unwrap()
        }

        const RECORD_ID: &str = "0537ed75-466f-457c-ad04-bcdf48c4fdbe";
        let db = create_database(":memory:").await.unwrap();
        let registry = registry();
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "id":RECORD_ID,
                    "type":"Document",
                    "kind":"note",
                    "name":"Write selector alias fixture",
                    "body":"before",
                    "reason":"write selector alias fixture"
                }),
            )
            .await
            .unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry.clone(), db.clone(), Caller::local(), None)
                .await
                .unwrap();

        // update_record through record_id writes exactly as id would.
        let updated = call_executor(
            &server,
            1,
            "records_write",
            "update_record",
            json!({"record_id":RECORD_ID, "body_append":" plus alias", "reason":"alias single write"}),
        )
        .await;
        assert_eq!(updated["result"]["isError"], false, "{updated}");
        let fetched = registry
            .call(
                db.clone(),
                Caller::local(),
                "get_record",
                json!({"ids":[RECORD_ID]}),
            )
            .await
            .unwrap();
        assert_eq!(fetched["records"][0]["body"], "before plus alias");

        // attach_text through id attaches under the same record.
        let attached = call_executor(
            &server,
            2,
            "records_write",
            "attach_text",
            json!({"id":RECORD_ID, "text":"aliased bytes", "filename":"alias.txt"}),
        )
        .await;
        assert_eq!(attached["result"]["isError"], false, "{attached}");
        assert_eq!(
            attached["result"]["structuredContent"]["record_id"],
            RECORD_ID
        );

        // archive_record through a singleton ids list archives the record.
        let archived = call_executor(
            &server,
            3,
            "records_lifecycle",
            "archive_record",
            json!({"ids":[RECORD_ID], "reason":"alias archive"}),
        )
        .await;
        assert_eq!(archived["result"]["isError"], false, "{archived}");
        assert_eq!(archived["result"]["structuredContent"]["changed"], true);

        // manage_facet_observations.set through record_id observes on it.
        let observed = call_executor(
            &server,
            4,
            "records_write",
            "manage_facet_observations.set",
            json!({
                "record_id":RECORD_ID,
                "key":"alias_probe",
                "value":"v",
                "as_of":"2026-08-01T00:00:00Z",
                "reason":"alias observation write"
            }),
        )
        .await;
        assert_eq!(observed["result"]["isError"], false, "{observed}");
        assert_eq!(observed["result"]["structuredContent"]["status"], "set");

        // A conflicting selector rejects value-free and writes nothing.
        let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let conflicted = call_executor(
            &server,
            5,
            "records_write",
            "update_record",
            json!({"id":RECORD_ID, "record_id":RECORD_ID, "name":"must not land", "reason":"conflict probe"}),
        )
        .await;
        assert_eq!(conflicted["result"]["isError"], true, "{conflicted}");
        let serialized = serde_json::to_string(&conflicted).unwrap();
        assert!(serialized.contains("exactly one selector"), "{serialized}");
        assert!(
            !serialized.contains(RECORD_ID),
            "the rejection must not reflect the selector value: {serialized}"
        );
        let events_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(events_after, events_before);

        // A singleton ids list on update_record stays a batch call: the
        // single-only field rejects through the batch parser.
        let singleton = call_executor(
            &server,
            6,
            "records_write",
            "update_record",
            json!({"ids":[RECORD_ID], "body_append":"must not land", "reason":"batch probe"}),
        )
        .await;
        assert_eq!(singleton["result"]["isError"], true, "{singleton}");
        let fetched = registry
            .call(
                db.clone(),
                Caller::local(),
                "get_record",
                json!({"ids":[RECORD_ID]}),
            )
            .await
            .unwrap();
        assert_eq!(fetched["records"][0]["body"], "before plus alias");
        db.close().await;
    }

    /// Operation-specific selector constraints stay value-free on the direct
    /// executor path (e674559): a claim alias carrying a non-UUID and a
    /// batch carrying a non-UUID or a duplicate reject with the shape
    /// diagnostic rather than a schema-library message echoing the value.
    /// Normalisation still passes these through untouched, so legacy parser
    /// wording and authority order are unchanged — this is repair-surface
    /// behaviour only.
    #[tokio::test]
    async fn write_selector_constraint_repairs_never_reflect_selector_values() {
        const PRIVATE_A: &str = "PRIVATE_WRITE_SELECTOR_SENTINEL_A";
        const DUPLICATE: &str = "1537ed75-466f-457c-ad04-bcdf48c4fdbe";
        let db = create_database(":memory:").await.unwrap();
        let registry = registry();
        let server = ExecutorPrototypeStdioServer::new(registry, db.clone(), Caller::local(), None)
            .await
            .unwrap();
        for (id, (executor, operation, arguments)) in (40_000_i64..).zip([
            (
                "records_write",
                "claim_unowned_record",
                json!({"id":PRIVATE_A, "reason":"Sentinel claim probe"}),
            ),
            (
                "records_write",
                "claim_unowned_record",
                json!({"record_id":PRIVATE_A, "reason":"Sentinel claim probe"}),
            ),
            (
                "records_write",
                "claim_unowned_record",
                json!({"ids":[PRIVATE_A], "reason":"Sentinel claim probe"}),
            ),
            (
                "records_write",
                "update_record",
                json!({"ids":[PRIVATE_A], "facets":{"probe":"v"}, "reason":"Sentinel batch probe"}),
            ),
            (
                "records_write",
                "update_record",
                json!({"ids":[DUPLICATE, DUPLICATE], "facets":{"probe":"v"}, "reason":"Duplicate batch probe"}),
            ),
        ]) {
            let response = server
                .handle_message(json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "method":"tools/call",
                    "params":{
                        "name":executor,
                        "arguments":{
                            "operation":operation,
                            "arguments":arguments,
                            "run_key":"write-selector-redaction-9c44bd"
                        }
                    }
                }))
                .await
                .unwrap();
            assert_eq!(response["result"]["isError"], true, "{response}");
            let serialized = serde_json::to_string(&response).unwrap();
            assert!(
                serialized.contains("exactly one selector"),
                "{operation}: {serialized}"
            );
            for sentinel in [PRIVATE_A, DUPLICATE] {
                assert!(
                    !serialized.contains(sentinel),
                    "{operation} reflected selector value {sentinel}: {serialized}"
                );
            }
            let repair = &response["result"]["structuredContent"]["repair"];
            assert_eq!(repair["code"], "operation_contract_repair", "{repair}");
            assert!(repair.get("failing_value").is_none(), "{repair}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn selector_shape_repairs_never_reflect_selector_values_on_stdio_or_hosted() {
        const PRIVATE_A: &str = "PRIVATE_SELECTOR_SENTINEL_A_0537ED7";
        const PRIVATE_B: &str = "PRIVATE_SELECTOR_SENTINEL_B_0537ED7";

        fn assert_redacted(operation: &str, response: &Value) {
            assert_eq!(response["result"]["isError"], true, "{response}");
            let serialized = serde_json::to_string(response).unwrap();
            for sentinel in [PRIVATE_A, PRIVATE_B] {
                assert!(
                    !serialized.contains(sentinel),
                    "{operation} reflected selector value {sentinel}: {serialized}"
                );
            }
            let repair = &response["result"]["structuredContent"]["repair"];
            assert_eq!(repair["code"], "operation_contract_repair", "{repair}");
            assert_eq!(repair["operation"], operation, "{repair}");
            assert!(
                repair["failing_pointer"]
                    .as_str()
                    .is_some_and(|pointer| pointer.starts_with("/arguments")),
                "{repair}"
            );
            assert!(repair["expected_shape"].is_object(), "{repair}");
            assert!(repair.get("contract_reference").is_some(), "{repair}");
            assert!(repair.get("failing_value").is_none(), "{repair}");
            let text = response["result"]["content"][0]["text"].as_str().unwrap();
            assert!(text.contains("Repair contract:"), "{text}");
        }

        async fn exercise(server: &ExecutorPrototypeStdioServer) {
            let operations = [
                "get_record",
                "render_record",
                "render_record_version_diff",
                "render_suggestion_review",
                "manage_attachments.list",
                "manage_links.list",
                "manage_facet_observations.list",
                "resolve_rollup",
            ];
            for (index, operation) in operations.into_iter().enumerate() {
                let response = call_records_read(
                    server,
                    30_000 + index as i64,
                    operation,
                    json!({"id":PRIVATE_A, "record_id":PRIVATE_B}),
                )
                .await;
                assert_redacted(operation, &response);
            }
            for (offset, (operation, arguments)) in [
                ("render_record", json!({"ids":[PRIVATE_A, PRIVATE_B]})),
                ("render_record", json!({"id":{"private":PRIVATE_A}})),
                ("get_record", json!({"ids":[{"private":PRIVATE_A}]})),
            ]
            .into_iter()
            .enumerate()
            {
                let response =
                    call_records_read(server, 31_000 + offset as i64, operation, arguments).await;
                assert_redacted(operation, &response);
            }

            let boundary = call_records_read(
                server,
                32_000,
                "get_record",
                json!({"ids":vec!["native:root"; crate::mcp::tools::lifecycle::MAX_BATCH_GET]}),
            )
            .await;
            assert_eq!(boundary["result"]["isError"], false, "{boundary}");

            let over_limit = call_records_read(
                server,
                32_001,
                "get_record",
                json!({
                    "ids":vec![
                        PRIVATE_A;
                        crate::mcp::tools::lifecycle::MAX_BATCH_GET + 1
                    ]
                }),
            )
            .await;
            assert_redacted("get_record", &over_limit);
            let serialized = serde_json::to_string(&over_limit).unwrap();
            assert!(
                serialized.contains(&format!(
                    "maximum {}",
                    crate::mcp::tools::lifecycle::MAX_BATCH_GET
                )),
                "over-limit repair must state the authoritative cap: {serialized}"
            );
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("selector-redaction.sqlite3");
        let db = create_database(path.to_str().unwrap()).await.unwrap();
        let stdio =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        exercise(&stdio).await;

        let catalogue = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        for statement in [
            "CREATE TABLE databases (id TEXT PRIMARY KEY, status TEXT NOT NULL, activity_epoch INTEGER NOT NULL)",
            "CREATE TABLE executor_write_plans (key_id TEXT)",
            "INSERT INTO databases (id, status, activity_epoch) VALUES ('selector-hosted-db', 'ready', 0)",
        ] {
            sqlx::query(statement).execute(&catalogue).await.unwrap();
        }
        let hosted = ExecutorPrototypeStdioServer::new_hosted(
            registry(),
            db.clone(),
            Caller::authenticated("selector-hosted-account")
                .with_hosting_context("selector-hosted-user", "selector-hosted-db"),
            Arc::new(SelectorHostedAuthority { pool: catalogue }),
            "selector-hosted-db",
            Arc::new(SelectorHostedKeys),
        )
        .await
        .unwrap();
        exercise(&hosted).await;
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

    /// Helper boundaries: hoist only a missing envelope key, dedupe only an
    /// identical string, and never partially normalize. A rejection leaves
    /// the caller's envelope untouched so the repair describes what was sent.
    #[test]
    fn nested_run_key_helper_hoists_transactionally_and_rejects_conflicts() {
        // Missing outer + string nested hoists both keys.
        let mut envelope = json!({
            "operation": "get_record",
            "arguments": {"ids": ["native:root"], "run_key": "hoist-a748b2", "parent_key": "parent-a748b2"},
        });
        assert_eq!(hoist_nested_routing_keys(&mut envelope), Ok(true));
        assert_eq!(envelope["run_key"], "hoist-a748b2");
        assert_eq!(envelope["parent_key"], "parent-a748b2");
        assert!(envelope["arguments"].get("run_key").is_none());
        assert!(envelope["arguments"].get("parent_key").is_none());

        // Identical strings dedupe to the envelope value.
        let mut envelope = json!({
            "operation": "get_record",
            "arguments": {"ids": ["native:root"], "run_key": "same-a748b2"},
            "run_key": "same-a748b2",
        });
        assert_eq!(hoist_nested_routing_keys(&mut envelope), Ok(true));
        assert_eq!(envelope["run_key"], "same-a748b2");
        assert!(envelope["arguments"].get("run_key").is_none());

        // Differing keys conflict rather than silently dropping either.
        let mut envelope = json!({
            "operation": "get_record",
            "arguments": {"ids": ["native:root"], "run_key": "nested-a748b2"},
            "run_key": "envelope-a748b2",
        });
        let diagnostic = hoist_nested_routing_keys(&mut envelope).unwrap_err();
        assert!(diagnostic.contains("conflicts"), "{diagnostic}");
        assert_eq!(envelope["run_key"], "envelope-a748b2");
        assert_eq!(envelope["arguments"]["run_key"], "nested-a748b2");

        // An explicit null envelope key counts as present: no hoist.
        let mut envelope = json!({
            "operation": "get_record",
            "arguments": {"ids": ["native:root"], "run_key": "nested-a748b2"},
            "run_key": Value::Null,
        });
        let diagnostic = hoist_nested_routing_keys(&mut envelope).unwrap_err();
        assert!(diagnostic.contains("conflicts"), "{diagnostic}");
        assert!(envelope["run_key"].is_null());
        assert_eq!(envelope["arguments"]["run_key"], "nested-a748b2");

        // Equal non-strings never dedupe.
        let mut envelope = json!({
            "operation": "get_record",
            "arguments": {"run_key": 17},
            "run_key": 17,
        });
        let diagnostic = hoist_nested_routing_keys(&mut envelope).unwrap_err();
        assert!(diagnostic.contains("conflicts"), "{diagnostic}");

        // A non-string nested key with no outer key is misplaced, not hoisted.
        let mut envelope = json!({
            "operation": "get_record",
            "arguments": {"ids": ["native:root"], "run_key": 17},
        });
        let diagnostic = hoist_nested_routing_keys(&mut envelope).unwrap_err();
        assert!(diagnostic.contains("misplaced"), "{diagnostic}");
        assert!(envelope["arguments"].get("run_key").is_some());

        // Transactional: a valid `run_key` hoist is rolled back when a later
        // `parent_key` fails, so the repair sees the envelope as sent.
        let mut envelope = json!({
            "operation": "get_record",
            "arguments": {"ids": ["native:root"], "run_key": "hoist-a748b2", "parent_key": 17},
        });
        let before = envelope.clone();
        let diagnostic = hoist_nested_routing_keys(&mut envelope).unwrap_err();
        assert!(diagnostic.contains("parent_key"), "{diagnostic}");
        assert_eq!(envelope, before);
    }

    /// A nested `run_key`/`parent_key` attaches exactly as an envelope key
    /// would; conflicts and non-strings fail with a targeted repair beside
    /// the existing `format` misplacement message.
    #[tokio::test]
    async fn nested_run_keys_hoist_and_correlate_on_the_ordinary_surface() {
        let db = create_database(":memory:").await.unwrap();
        let server =
            ExecutorPrototypeStdioServer::new(registry(), db.clone(), Caller::local(), None)
                .await
                .unwrap();
        let call = |id: i64, envelope: Value| {
            let server = &server;
            async move {
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

        // Nested `run_key` succeeds and correlates like an envelope key.
        let nested = call(
            1,
            json!({
                "operation": "get_record",
                "arguments": {"ids": ["native:root"], "run_key": "nested-hoist-a748b2"},
            }),
        )
        .await;
        assert_eq!(nested["result"]["isError"], false, "{nested}");
        let envelope_call = call(
            2,
            json!({
                "operation": "get_record",
                "arguments": {"ids": ["native:root"]},
                "run_key": "nested-hoist-a748b2",
            }),
        )
        .await;
        assert_eq!(envelope_call["result"]["isError"], false, "{envelope_call}");
        assert_eq!(
            nested["result"]["content"][0]["text"], envelope_call["result"]["content"][0]["text"],
            "a hoisted key must render exactly as an envelope key would"
        );
        assert!(
            server
                .trace_events()
                .iter()
                .any(|event| event["kind"] == "operation_selection"
                    && event["run_key"] == "nested-hoist-a748b2"),
            "a hoisted key must attach the call to the run exactly as an envelope key would"
        );

        // Nested `parent_key` hoists alongside an envelope `run_key`.
        let parented = call(
            3,
            json!({
                "operation": "get_record",
                "arguments": {"ids": ["native:root"], "parent_key": "nested-parent-a748b2"},
                "run_key": "parent-probe-a748b2",
            }),
        )
        .await;
        assert_eq!(parented["result"]["isError"], false, "{parented}");

        // An identical duplicate dedupes harmlessly.
        let duplicate = call(
            4,
            json!({
                "operation": "get_record",
                "arguments": {"ids": ["native:root"], "run_key": "same-a748b2"},
                "run_key": "same-a748b2",
            }),
        )
        .await;
        assert_eq!(duplicate["result"]["isError"], false, "{duplicate}");

        // Differing keys reject without silently dropping either value.
        let conflict = call(
            5,
            json!({
                "operation": "get_record",
                "arguments": {"ids": ["native:root"], "run_key": "nested-a748b2"},
                "run_key": "envelope-a748b2",
            }),
        )
        .await;
        assert_eq!(conflict["result"]["isError"], true, "{conflict}");
        let conflict_text = conflict["result"]["content"][0]["text"].as_str().unwrap();
        assert!(conflict_text.contains("conflicts"), "{conflict_text}");
        let conflict_repair = &conflict["result"]["structuredContent"]["repair"];
        assert_eq!(
            conflict_repair["failing_pointer"], "/arguments/run_key",
            "{conflict_repair}"
        );
        assert!(
            conflict_repair["expected_shape"]["description"]
                .as_str()
                .unwrap()
                .contains("arguments.run_key is misplaced"),
            "{conflict_repair}"
        );

        // A non-string nested key is a targeted misplacement, not a hoist.
        let non_string = call(
            6,
            json!({
                "operation": "get_record",
                "arguments": {"ids": ["native:root"], "run_key": 17},
            }),
        )
        .await;
        assert_eq!(non_string["result"]["isError"], true, "{non_string}");
        let non_string_text = non_string["result"]["content"][0]["text"].as_str().unwrap();
        assert!(non_string_text.contains("misplaced"), "{non_string_text}");
        assert!(
            non_string_text.contains("must be a string"),
            "{non_string_text}"
        );
        let non_string_repair = &non_string["result"]["structuredContent"]["repair"];
        assert_eq!(
            non_string_repair["failing_pointer"], "/arguments/run_key",
            "{non_string_repair}"
        );
        assert!(
            non_string_repair["expected_shape"]["description"]
                .as_str()
                .unwrap()
                .contains("arguments.run_key is misplaced"),
            "{non_string_repair}"
        );
        // No automatic correction: lifting the number to the envelope would
        // read as retry_ready, and the retry would succeed with correlation
        // silently absent.
        assert_eq!(
            non_string_repair["retry_ready"], false,
            "{non_string_repair}"
        );
        assert!(
            non_string_repair.get("corrections").is_none(),
            "{non_string_repair}"
        );

        // Both keys nested with the helper rejecting the later-processed
        // field: the repair still names the helper's field, not whichever
        // key the schema iterator yields first.
        let both_nested = call(
            7,
            json!({
                "operation": "get_record",
                "arguments": {"ids": ["native:root"], "parent_key": 17, "run_key": 18},
            }),
        )
        .await;
        assert_eq!(both_nested["result"]["isError"], true, "{both_nested}");
        let both_text = both_nested["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(both_text.contains("arguments.run_key"), "{both_text}");
        let both_repair = &both_nested["result"]["structuredContent"]["repair"];
        assert_eq!(
            both_repair["failing_pointer"], "/arguments/run_key",
            "{both_repair}"
        );
        assert!(
            both_repair["expected_shape"]["description"]
                .as_str()
                .unwrap()
                .contains("arguments.run_key is misplaced"),
            "{both_repair}"
        );
        assert_eq!(both_repair["retry_ready"], false, "{both_repair}");

        // A helper rejection wins over an invalid envelope format: the
        // repair names the routing key, not /format.
        let format_override = call(
            8,
            json!({
                "operation": "get_record",
                "arguments": {"ids": ["native:root"], "run_key": "nested-a748b2"},
                "run_key": "envelope-a748b2",
                "format": "yaml",
            }),
        )
        .await;
        assert_eq!(
            format_override["result"]["isError"], true,
            "{format_override}"
        );
        let override_repair = &format_override["result"]["structuredContent"]["repair"];
        assert_eq!(
            override_repair["failing_pointer"], "/arguments/run_key",
            "{override_repair}"
        );
        db.close().await;
    }

    /// The lens path hoists before validation and forwards the hoisted key
    /// in the delegated legacy call.
    #[tokio::test]
    async fn lens_nested_run_key_hoists_into_the_delegated_call() {
        use std::sync::{Arc, Mutex};
        struct RecordingLensDispatch {
            seen: Arc<Mutex<Option<Value>>>,
        }
        impl LensDispatch for RecordingLensDispatch {
            fn exposure_policy(
                &self,
                _registry: &ToolRegistry,
            ) -> super::super::ResolvedToolExposure {
                super::super::ResolvedToolExposure::new(super::super::ExposureProfile::Complete)
            }
            fn tools_list(&self, _registry: &ToolRegistry, _modern: bool) -> Result<Value> {
                Ok(json!({"tools": []}))
            }
            fn run_context<'a>(
                &'a self,
                _registry: &'a ToolRegistry,
                _arguments: &'a Value,
            ) -> futures::future::BoxFuture<'a, Value> {
                Box::pin(async { Value::Null })
            }
            fn tools_call<'a>(
                &'a self,
                _registry: &'a ToolRegistry,
                params: &'a serde_json::Map<String, Value>,
                _modern: bool,
            ) -> futures::future::BoxFuture<'a, std::result::Result<Value, (i64, String)>>
            {
                let seen = self.seen.clone();
                let captured = params.get("arguments").cloned().unwrap_or(Value::Null);
                Box::pin(async move {
                    *seen.lock().unwrap() = Some(captured);
                    Ok(json!({
                        "content": [{"type": "text", "text": "{}"}],
                        "structuredContent": {},
                        "isError": false,
                    }))
                })
            }
            fn revision(&self) -> i64 {
                1
            }
        }

        let seen = Arc::new(Mutex::new(None));
        let registry = registry();
        let catalogue = ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
            &registry,
            &ExperimentalExecutors::empty(),
        )
        .unwrap();
        let server = ExecutorPrototypeLensServer::new_with_pinned_catalogue(
            registry,
            Arc::new(RecordingLensDispatch { seen: seen.clone() }),
            catalogue,
            None,
        )
        .unwrap();
        let response = server
            .handle_message(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "records_read",
                    "arguments": {
                        "operation": "get_record",
                        "arguments": {"ids": ["native:root"], "run_key": "lens-hoist-a748b2"},
                    },
                },
            }))
            .await
            .unwrap();
        assert_eq!(response["result"]["isError"], false, "{response}");
        let delegated = seen
            .lock()
            .unwrap()
            .clone()
            .expect("lens delegate must run");
        assert_eq!(
            delegated.get("run_key"),
            Some(&json!("lens-hoist-a748b2")),
            "the delegated legacy call must carry the hoisted run key: {delegated}"
        );
        assert!(
            delegated.get("ids").is_some(),
            "the delegated call must preserve the operation arguments: {delegated}"
        );
    }
}
