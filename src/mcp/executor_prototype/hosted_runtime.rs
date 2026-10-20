//! Opaque process-scoped runtime for the hosted executor transport.
//!
//! HTTP owns authentication and response mapping. This runtime owns the
//! principal-neutral executor catalogue, shared hosted authority, keyring,
//! telemetry binding, and bounded per-lens catalogue pins. None of those
//! implementation types cross the hosted transport boundary.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::{Db, Error, Result};

use super::telemetry::BoundExecutorTelemetry;
use super::{
    ExecutorPrototypeLensServer, ExecutorPrototypeStdioServer, ExecutorTelemetryContext,
    ExecutorTelemetryHealth, HostedAuthorityCatalogue, HostedExecutorAuthority,
    HostedExecutorConstruction, HostedPlanKeyProvider, PinnedExecutorCatalogue,
    PinnedLensExecutorCatalogue,
};
use crate::mcp::protocol::{add_modern_result_fields, call_error_content};
use crate::mcp::registry::{EngineHandle, EngineKind};
use crate::mcp::OperationAccess;
use crate::mcp::{
    Caller, DeploymentPersistenceLease, ExperimentalExecutors, LensDispatch, McpSurfaceMode,
    ToolRegistry,
};
use crate::DeploymentReadOnlyOperation;

const MAX_PINNED_LENS_CATALOGUES: usize = 128;

/// Storage-free classification for the maintenance proxy. It uses the same
/// pinned source contracts as hosted dispatch, without keys or plan cleanup.
#[doc(hidden)]
pub struct HostedExecutorAdmission {
    ordinary: Arc<PinnedExecutorCatalogue>,
    lens: Arc<PinnedLensExecutorCatalogue>,
}

impl HostedExecutorAdmission {
    pub fn new(registry: &ToolRegistry, experimental: &ExperimentalExecutors) -> Result<Self> {
        Self::new_for_surface(registry, experimental, McpSurfaceMode::Executor)
    }

    /// Classification for the ordinary catalogue the upstream serves: the
    /// full executor catalogue or its lean projection. Lens classification
    /// is unchanged by the surface.
    pub fn new_for_surface(
        registry: &ToolRegistry,
        experimental: &ExperimentalExecutors,
        surface: McpSurfaceMode,
    ) -> Result<Self> {
        Ok(Self {
            ordinary: ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_surface(
                registry,
                experimental,
                surface,
            )?,
            lens: ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
                registry,
                experimental,
            )?,
        })
    }

    /// Exact contract identity for dark outbox acceptance/replay. The caller
    /// must pass this release's pinned catalogue, not a journal-supplied one.
    #[doc(hidden)]
    pub fn deferred_contract_identity(
        &self,
        executor: &str,
        operation: &str,
    ) -> Option<(&str, &str)> {
        self.ordinary
            .contracts
            .get(&(executor.into(), operation.into()))
            .map(|contract| (super::CONTRACT_VERSION, contract.digest.as_str()))
    }

    pub fn classify_call(
        &self,
        executor: &str,
        operation: Option<&str>,
        lens: bool,
    ) -> Option<OperationAccess> {
        if lens {
            self.lens.classify_call(executor, operation)
        } else {
            self.ordinary
                .classify_call(executor, operation)
                .map(|(_, access)| access)
        }
    }

    /// Classify one `tools/call` by tool name and raw envelope. On a lean
    /// ordinary catalogue a `call_executor` envelope classifies as its
    /// target; lens routes never unwrap (lean is ordinary-only).
    pub fn classify_tools_call(
        &self,
        name: &str,
        arguments: Option<&Value>,
        lens: bool,
    ) -> Option<OperationAccess> {
        if lens {
            let operation = arguments
                .and_then(|arguments| arguments.get("operation"))
                .and_then(Value::as_str)
                .or_else(|| (name == "bootstrap").then_some("bootstrap"));
            return self.lens.classify_call(name, operation);
        }
        let (executor, operation) = self.ordinary.call_target(name, arguments)?;
        let operation = operation.or_else(|| (executor == "bootstrap").then_some("bootstrap"));
        self.ordinary
            .classify_call(executor, operation)
            .map(|(_, access)| access)
    }

    /// The lean direct-call refusal for an ordinary route, rendered by the
    /// proxy itself instead of forwarding. Lens routes never project lean.
    pub fn lean_direct_refusal(
        &self,
        id: Value,
        modern: bool,
        name: &str,
        arguments: Option<&Value>,
        lens: bool,
    ) -> Option<Value> {
        if lens {
            return None;
        }
        self.ordinary
            .lean_direct_refusal(id, modern, name, arguments)
    }
}

/// Fully initialized hosted executor state shared by one HTTP router.
///
/// The type is intentionally opaque: transports may submit already-authorized
/// requests, report authorization refusals, and inspect delivery health, but
/// cannot access or recombine keys, catalogues, authorities, or telemetry.
#[doc(hidden)]
pub struct HostedExecutorRuntime {
    registry: Arc<ToolRegistry>,
    authority: Arc<dyn HostedExecutorAuthority>,
    keys: Arc<dyn HostedPlanKeyProvider>,
    ordinary: Arc<PinnedExecutorCatalogue>,
    #[cfg(feature = "v2-kernel-probe")]
    v2_ordinary: Arc<PinnedExecutorCatalogue>,
    #[cfg(feature = "v2-kernel-probe")]
    v2_telemetry: std::sync::OnceLock<BoundExecutorTelemetry>,
    lens_admission: Arc<PinnedLensExecutorCatalogue>,
    ordinary_telemetry: BoundExecutorTelemetry,
    lenses: PinnedLensCatalogueCache,
    telemetry: Arc<ExecutorTelemetryContext>,
    experimental: ExperimentalExecutors,
    sql_commit: bool,
}

#[derive(Clone)]
struct PinnedLensCatalogue {
    revision: i64,
    catalogue: Arc<PinnedLensExecutorCatalogue>,
    telemetry: Option<BoundExecutorTelemetry>,
}

#[derive(Default)]
struct PinnedLensCatalogueCache {
    entries: Mutex<HashMap<String, PinnedLensCatalogue>>,
}

impl HostedExecutorRuntime {
    /// Deployment consent for qualified ordinary SQLite commit plans. Each
    /// preparation still needs signed commit consent. Lens writes are excluded.
    pub fn with_sql_commit(mut self) -> Result<Self> {
        if !self.experimental.contains("sql_write") {
            return Err(Error::engine(
                "hosted SQL commit requires the sql_write experimental allowlist",
            ));
        }
        self.sql_commit = true;
        Ok(self)
    }
    /// Initialize the production structured-log runtime. Retained-key
    /// validation completes before telemetry construction or catalogue pinning
    /// so a bad deployment cannot begin serving or emit a loaded manifest.
    pub async fn new(
        registry: Arc<ToolRegistry>,
        authority: Arc<dyn HostedExecutorAuthority>,
        keys: Arc<dyn HostedPlanKeyProvider>,
    ) -> Result<Self> {
        Self::new_with_experimental(registry, authority, keys, ExperimentalExecutors::empty()).await
    }

    /// Initialize with an explicit experimental-executor allowlist. Without
    /// the allowlist the pinned catalogues are the stable-only surface.
    pub async fn new_with_experimental(
        registry: Arc<ToolRegistry>,
        authority: Arc<dyn HostedExecutorAuthority>,
        keys: Arc<dyn HostedPlanKeyProvider>,
        experimental: ExperimentalExecutors,
    ) -> Result<Self> {
        Self::validate_keys(&authority, &keys).await?;
        let telemetry = ExecutorTelemetryContext::structured_log()?;
        Self::from_validated(registry, authority, keys, telemetry, experimental).await
    }

    /// Initialize with an injected process-scoped telemetry context. Key
    /// validation still precedes every catalogue pin and telemetry binding.
    pub async fn new_with_telemetry(
        registry: Arc<ToolRegistry>,
        authority: Arc<dyn HostedExecutorAuthority>,
        keys: Arc<dyn HostedPlanKeyProvider>,
        telemetry: Arc<ExecutorTelemetryContext>,
    ) -> Result<Self> {
        Self::new_with_telemetry_and_experimental(
            registry,
            authority,
            keys,
            telemetry,
            ExperimentalExecutors::empty(),
        )
        .await
    }

    /// Initialize with an injected process-scoped telemetry context and an
    /// explicit experimental-executor allowlist.
    pub async fn new_with_telemetry_and_experimental(
        registry: Arc<ToolRegistry>,
        authority: Arc<dyn HostedExecutorAuthority>,
        keys: Arc<dyn HostedPlanKeyProvider>,
        telemetry: Arc<ExecutorTelemetryContext>,
        experimental: ExperimentalExecutors,
    ) -> Result<Self> {
        Self::validate_keys(&authority, &keys).await?;
        Self::from_validated(registry, authority, keys, telemetry, experimental).await
    }

    async fn validate_keys(
        authority: &Arc<dyn HostedExecutorAuthority>,
        keys: &Arc<dyn HostedPlanKeyProvider>,
    ) -> Result<()> {
        let catalogue = HostedAuthorityCatalogue(Arc::clone(authority));
        super::validate_hosted_plan_keys_for_catalogue(keys, &catalogue).await
    }

    /// Initialize for one executor-serving surface, with an optional
    /// injected telemetry context (the production structured log when
    /// `None`). `Executor` is exactly the historical constructors; `Lean`
    /// pins the lean projection of the same ordinary catalogue. Key
    /// validation still precedes every catalogue pin and telemetry binding.
    pub async fn new_for_surface(
        registry: Arc<ToolRegistry>,
        authority: Arc<dyn HostedExecutorAuthority>,
        keys: Arc<dyn HostedPlanKeyProvider>,
        telemetry: Option<Arc<ExecutorTelemetryContext>>,
        experimental: ExperimentalExecutors,
        surface: McpSurfaceMode,
    ) -> Result<Self> {
        if !surface.serves_executors() {
            return Err(Error::engine(format!(
                "the {surface} MCP surface has no hosted executor runtime"
            )));
        }
        Self::validate_keys(&authority, &keys).await?;
        let telemetry = match telemetry {
            Some(telemetry) => telemetry,
            None => ExecutorTelemetryContext::structured_log()?,
        };
        Self::from_validated_for_surface(
            registry,
            authority,
            keys,
            telemetry,
            experimental,
            surface,
        )
        .await
    }

    async fn from_validated(
        registry: Arc<ToolRegistry>,
        authority: Arc<dyn HostedExecutorAuthority>,
        keys: Arc<dyn HostedPlanKeyProvider>,
        telemetry: Arc<ExecutorTelemetryContext>,
        experimental: ExperimentalExecutors,
    ) -> Result<Self> {
        Self::from_validated_for_surface(
            registry,
            authority,
            keys,
            telemetry,
            experimental,
            McpSurfaceMode::Executor,
        )
        .await
    }

    async fn from_validated_for_surface(
        registry: Arc<ToolRegistry>,
        authority: Arc<dyn HostedExecutorAuthority>,
        keys: Arc<dyn HostedPlanKeyProvider>,
        telemetry: Arc<ExecutorTelemetryContext>,
        experimental: ExperimentalExecutors,
        surface: McpSurfaceMode,
    ) -> Result<Self> {
        let maintenance_admission = match registry.deployment_mutation_barrier() {
            Some(barrier) => match barrier.admit(
                &DeploymentReadOnlyOperation::server("executor_plan_maintenance"),
                OperationAccess::Mutation,
            ) {
                Ok(admission) => Some(admission),
                Err(crate::Error::DeploymentReadOnly(_)) => None,
                Err(error) => return Err(error),
            },
            None => None,
        };
        // A server that boots frozen still needs the executor read catalogue.
        // Expiry and cleanup are catalog writes, so skip them without admission.
        if registry.deployment_mutation_barrier().is_none() || maintenance_admission.is_some() {
            let now_ms = chrono::Utc::now().timestamp_millis();
            super::plan_store::maintain_hosted_catalogue(
                &HostedAuthorityCatalogue(Arc::clone(&authority)),
                now_ms,
                super::plan_store::EXPIRED_PLAN_RETENTION_MS,
            )
            .await?;
        }
        let ordinary = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_surface(
            &registry,
            &experimental,
            surface,
        )?;
        let ordinary_telemetry = telemetry.bind_hosted_manifest_for_surface(
            super::telemetry::TelemetrySurface::for_ordinary_catalogue(ordinary.is_lean()),
            ordinary.manifest_digest(),
            ordinary.descriptor_bytes(),
        );
        #[cfg(feature = "v2-kernel-probe")]
        let v2_ordinary = ExecutorPrototypeStdioServer::pin_hosted_catalogue_for_engine(
            &registry,
            &experimental,
            surface,
            EngineKind::KernelV2,
        )?;
        // Principal-neutral contracts use the same immutable registry and
        // allowlist as each authoritative lens-revision pin. Classification
        // does not allocate a lens pin or claim an authorization decision.
        let lens_admission =
            ExecutorPrototypeLensServer::pin_catalogue_with_experimental(&registry, &experimental)?;
        Ok(Self {
            registry,
            authority,
            keys,
            ordinary,
            #[cfg(feature = "v2-kernel-probe")]
            v2_ordinary,
            #[cfg(feature = "v2-kernel-probe")]
            v2_telemetry: std::sync::OnceLock::new(),
            lens_admission,
            ordinary_telemetry,
            lenses: PinnedLensCatalogueCache::default(),
            telemetry,
            experimental,
            sql_commit: false,
        })
    }

    /// Execute one already-authorized ordinary hosted request.
    pub async fn handle_ordinary(
        &self,
        db: Db,
        caller: Caller,
        database_id: String,
        message: Value,
    ) -> Result<Option<Value>> {
        self.handle_ordinary_inner(db.into(), caller, database_id, message, None)
            .await
    }

    /// Execute one already-authorized ordinary hosted request under the
    /// transport's persistence lease. The lease is re-validated for the
    /// contract dispatch instead of fresh-admitting, so a freeze registered
    /// after the transport's admission drains instead of refusing an
    /// already-admitted mutation. `None` preserves the historical
    /// per-message admission exactly.
    pub async fn handle_ordinary_with_persistence(
        &self,
        db: Db,
        caller: Caller,
        database_id: String,
        message: Value,
        persistence_lease: Option<DeploymentPersistenceLease>,
    ) -> Result<Option<Value>> {
        self.handle_ordinary_inner(db.into(), caller, database_id, message, persistence_lease)
            .await
    }

    /// Authoritative pre-auth classification for one executor-routed
    /// `tools/call`: resolve `(executor, operation)` against the pinned
    /// catalogue. `None` keeps the transport's legacy deferred path.
    pub fn classify_call(
        &self,
        executor: &str,
        operation: Option<&str>,
    ) -> Option<(DeploymentReadOnlyOperation, OperationAccess)> {
        self.ordinary.classify_call(executor, operation)
    }

    /// Pre-auth classification by tool name and raw envelope: on a lean
    /// runtime a `call_executor` envelope is unwrapped to the target it will
    /// dispatch, so admission (and a freeze) apply to that operation. Other
    /// calls classify exactly as [`Self::classify_call`].
    pub fn classify_tools_call(
        &self,
        name: &str,
        arguments: Option<&Value>,
    ) -> Option<(DeploymentReadOnlyOperation, OperationAccess)> {
        self.ordinary.classify_tools_call(name, arguments)
    }

    /// Lean only: refuse a direct call to an operation the lean catalogue
    /// does not advertise directly, before the transport admits it or
    /// authenticates the caller. Returns the rendered `tools/call` error
    /// result (the same diagnostic and `call_executor` repair dispatch
    /// renders, without run context), or `None` when the call is not such a
    /// call. The refused target is recorded as a rejected selection with
    /// its resolved executor and operation; no request is dispatched.
    pub fn lean_direct_refusal(
        &self,
        id: Value,
        modern: bool,
        name: &str,
        arguments: Option<&Value>,
    ) -> Option<Value> {
        let (executor, operation) = self.ordinary.lean_hidden_direct_target(name, arguments)?;
        let body = self
            .ordinary
            .lean_direct_refusal(id, modern, name, arguments)?;
        let request = self
            .ordinary_telemetry
            .request(Some(&executor), Some(&operation), None);
        self.ordinary_telemetry.emit(super::telemetry::EventSpec {
            request: Some(request),
            phase: super::telemetry::TelemetryPhase::OperationSelected,
            outcome: super::telemetry::TelemetryOutcome::Rejected,
            error_class: Some(super::telemetry::TelemetryErrorClass::SelectionError),
            ..super::telemetry::EventSpec::default()
        });
        Some(body)
    }

    /// Classify against the lens contracts, which differ from the ordinary
    /// executor surface. Unknown selectors remain fail-closed at transport.
    pub fn classify_lens_call(
        &self,
        executor: &str,
        operation: Option<&str>,
    ) -> Option<OperationAccess> {
        self.lens_admission.classify_call(executor, operation)
    }

    /// Render a frozen-contract refusal with the exact dispatch-time shape:
    /// a `tools/call` error result carrying `DEPLOYMENT_READ_ONLY`,
    /// `applied=false`, and the executor meta the dispatch-time refusal
    /// attaches. Transports return it before authentication.
    pub fn frozen_call_refusal(&self, id: Value, modern: bool, error: &Error) -> Value {
        let mut result = call_error_content(error, Value::Null, None);
        if modern {
            add_modern_result_fields(&mut result);
        }
        result["_meta"]["nativeExecutor"] = super::production_executor_meta(
            "ordinary",
            self.ordinary.manifest_digest(),
            self.ordinary.descriptor_bytes(),
        );
        json!({"jsonrpc": "2.0", "id": id, "result": result})
    }

    /// Dispatch the engine paired with the router handle, using an immutable
    /// catalogue pinned for that physical implementation.
    pub async fn handle_engine_with_persistence(
        &self,
        engine: EngineHandle,
        caller: Caller,
        database_id: String,
        message: Value,
        persistence_lease: Option<DeploymentPersistenceLease>,
    ) -> Result<Option<Value>> {
        self.handle_ordinary_inner(engine, caller, database_id, message, persistence_lease)
            .await
    }

    async fn handle_ordinary_inner(
        &self,
        engine: EngineHandle,
        caller: Caller,
        database_id: String,
        message: Value,
        persistence_lease: Option<DeploymentPersistenceLease>,
    ) -> Result<Option<Value>> {
        crate::mcp::scope_database_persistence(
            database_id.clone(),
            self.handle_ordinary_scoped_inner(
                engine,
                caller,
                database_id,
                message,
                persistence_lease,
            ),
        )
        .await
    }

    async fn handle_ordinary_scoped_inner(
        &self,
        engine: EngineHandle,
        caller: Caller,
        database_id: String,
        message: Value,
        persistence_lease: Option<DeploymentPersistenceLease>,
    ) -> Result<Option<Value>> {
        let (catalogue, telemetry) = match engine.kind() {
            EngineKind::Sqlite => (&self.ordinary, &self.ordinary_telemetry),
            #[cfg(feature = "v2-kernel-probe")]
            EngineKind::KernelV2 => (
                &self.v2_ordinary,
                self.v2_telemetry.get_or_init(|| {
                    self.telemetry.bind_hosted_manifest_for_surface(
                        super::telemetry::TelemetrySurface::for_ordinary_catalogue(
                            self.v2_ordinary.is_lean(),
                        ),
                        self.v2_ordinary.manifest_digest(),
                        self.v2_ordinary.descriptor_bytes(),
                    )
                }),
            ),
            #[allow(unreachable_patterns)]
            _ => {
                return Err(Error::engine(
                    "hosted executor does not support this engine",
                ))
            }
        };
        #[cfg(feature = "v2-kernel-probe")]
        if matches!(&engine, EngineHandle::KernelV2(db) if db.has_enrolled_execution())
            && message["method"] == "tools/call"
            && self
                .ordinary
                .classify_tools_call(
                    message["params"]["name"].as_str().unwrap_or(""),
                    message.pointer("/params/arguments"),
                )
                .is_some_and(|(_, access)| access == super::OperationAccess::Mutation)
        {
            return Err(Error::engine("managed-custody v2 writes not yet supported"));
        }
        if engine.kind() != EngineKind::Sqlite && message["method"] == "tools/call" {
            let name = message
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("");
            let arguments = message.pointer("/params/arguments");
            if let Some((executor, Some(operation))) = self.ordinary.call_target(name, arguments) {
                if super::write_operations::requires_plan(executor, operation) {
                    let Some(id) = message.get("id").cloned() else {
                        return Ok(None);
                    };
                    let error = Error::engine("this is a v2 database; plan-required operations are unavailable until v2 write plans are qualified");
                    let mut result = call_error_content(&error, Value::Null, None);
                    if crate::mcp::protocol::is_modern_request(&message) {
                        add_modern_result_fields(&mut result);
                    }
                    return Ok(Some(json!({"jsonrpc":"2.0", "id":id, "result":result})));
                }
            }
        }
        // Preserve the transport contract: successful authorization is
        // observed before plan-store/server construction, including when that
        // later construction fails.
        telemetry.authorization_accepted();
        let mut server = ExecutorPrototypeStdioServer::new_hosted_with_pinned_catalogue(
            Arc::clone(&self.registry),
            engine,
            caller,
            HostedExecutorConstruction {
                authority: Arc::clone(&self.authority),
                database_id,
                keys: Arc::clone(&self.keys),
                catalogue: Arc::clone(catalogue),
                telemetry: Some(telemetry.clone()),
            },
        )
        .await?;
        if self.sql_commit && server.engine.kind() == EngineKind::Sqlite {
            server = server.with_hosted_sql_commit()?;
        }
        if let Some(lease) = persistence_lease {
            server = server.with_persistence_lease(lease);
        }
        Ok(server.handle_message(message).await)
    }

    /// Execute one already-authorized federated-lens request. The authoritative
    /// dispatcher supplies its own revision; callers cannot pair a lens id with
    /// a separately supplied revision or cache a principal-bound dispatcher.
    pub async fn handle_lens(
        &self,
        lens_id: &str,
        dispatcher: Arc<dyn LensDispatch>,
        message: Value,
    ) -> Result<Option<Value>> {
        let pinned = self.lenses.pin_runtime(
            lens_id,
            dispatcher.revision(),
            &self.registry,
            Some(&self.telemetry),
            &self.experimental,
        )?;
        if let Some(telemetry) = &pinned.telemetry {
            telemetry.authorization_accepted();
        }
        let server = ExecutorPrototypeLensServer::new_with_pinned_catalogue(
            Arc::clone(&self.registry),
            dispatcher,
            pinned.catalogue,
            pinned.telemetry,
        )?;
        Ok(server.handle_message(message).await)
    }

    /// Record an ordinary-route authorization refusal. The ordinary manifest
    /// is known even though no request server is constructed.
    pub fn observe_ordinary_authorization_denied(&self) {
        self.telemetry.observe_hosted_authorization_denied(
            super::telemetry::TelemetrySurface::for_ordinary_catalogue(self.ordinary.is_lean()),
            Some(self.ordinary.manifest_digest()),
            crate::FULL_GIT_SHA,
        );
    }

    /// Record a lens refusal that occurred before authoritative resolution.
    /// No lens manifest is pinned or claimed for this event.
    pub fn observe_lens_authorization_denied(&self) {
        self.telemetry.observe_hosted_authorization_denied(
            super::telemetry::TelemetrySurface::Executor,
            None,
            crate::FULL_GIT_SHA,
        );
    }

    pub fn telemetry_health(&self) -> ExecutorTelemetryHealth {
        self.telemetry.health()
    }
}

impl PinnedLensCatalogueCache {
    #[cfg(test)]
    fn pin(
        &self,
        lens_id: &str,
        revision: i64,
        registry: &ToolRegistry,
    ) -> Result<Arc<PinnedLensExecutorCatalogue>> {
        Ok(self
            .pin_runtime(
                lens_id,
                revision,
                registry,
                None,
                &ExperimentalExecutors::empty(),
            )?
            .catalogue)
    }

    fn pin_runtime(
        &self,
        lens_id: &str,
        revision: i64,
        registry: &ToolRegistry,
        telemetry: Option<&Arc<ExecutorTelemetryContext>>,
        experimental: &ExperimentalExecutors,
    ) -> Result<PinnedLensCatalogue> {
        let mut lenses = self
            .entries
            .lock()
            .map_err(|_| Error::engine("executor lens catalogue cache lock is unavailable"))?;
        if let Some(pinned) = lenses.get(lens_id) {
            if pinned.revision != revision {
                return Err(Error::engine(
                    "lens executor catalogue revision changed; restart is required",
                ));
            }
            return Ok(pinned.clone());
        }
        if lenses.len() >= MAX_PINNED_LENS_CATALOGUES {
            return Err(Error::engine(
                "executor lens catalogue capacity is exhausted; restart is required",
            ));
        }
        // Build while holding the bounded cache lock so two first requests can
        // never race different authoritative revisions into the same process.
        let catalogue =
            ExecutorPrototypeLensServer::pin_catalogue_with_experimental(registry, experimental)?;
        let telemetry = telemetry.map(|context| {
            context.bind_hosted_manifest(catalogue.manifest_digest(), catalogue.descriptor_bytes())
        });
        let pinned = PinnedLensCatalogue {
            revision,
            catalogue,
            telemetry,
        };
        lenses.insert(lens_id.to_owned(), pinned.clone());
        Ok(pinned)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use super::*;
    use crate::mcp::{register_builtin_tools, register_surface_tools};

    fn registry() -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).unwrap();
        register_surface_tools(&mut registry).unwrap();
        registry
    }

    #[test]
    fn lens_catalogue_first_pin_is_stable_drift_fails_and_capacity_never_evicts() {
        let registry = registry();
        let cache = PinnedLensCatalogueCache::default();
        let first = cache.pin("lens-first", 7, &registry).unwrap();
        let same = cache.pin("lens-first", 7, &registry).unwrap();
        assert!(Arc::ptr_eq(&first, &same));
        let drift = match cache.pin("lens-first", 8, &registry) {
            Ok(_) => panic!("a changed lens revision must not replace its process pin"),
            Err(error) => error,
        };
        assert!(drift.to_string().contains("revision changed"), "{drift}");

        for index in 1..MAX_PINNED_LENS_CATALOGUES {
            cache.pin(&format!("lens-{index}"), 1, &registry).unwrap();
        }
        let capacity = match cache.pin("lens-overflow", 1, &registry) {
            Ok(_) => panic!("a full lens catalogue cache must not evict a process pin"),
            Err(error) => error,
        };
        assert!(capacity.to_string().contains("capacity"), "{capacity}");
        assert!(Arc::ptr_eq(
            &first,
            &cache.pin("lens-first", 7, &registry).unwrap()
        ));
    }

    #[test]
    fn concurrent_lens_first_pin_accepts_exactly_one_authoritative_revision() {
        let registry = Arc::new(registry());
        let cache = Arc::new(PinnedLensCatalogueCache::default());
        let start = Arc::new(Barrier::new(2));

        let outcomes = std::thread::scope(|scope| {
            let handles = [41_i64, 42_i64].map(|revision| {
                let registry = Arc::clone(&registry);
                let cache = Arc::clone(&cache);
                let start = Arc::clone(&start);
                scope.spawn(move || {
                    start.wait();
                    cache
                        .pin("concurrent-lens", revision, &registry)
                        .map(|_| revision)
                })
            });
            handles.map(|handle| handle.join().unwrap())
        });

        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_err()).count(),
            1
        );
        assert!(outcomes
            .iter()
            .filter_map(|outcome| outcome.as_ref().err())
            .all(|error| error.to_string().contains("revision changed")));
    }
}
