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
use crate::mcp::OperationAccess;
use crate::mcp::{
    Caller, DeploymentPersistenceLease, ExperimentalExecutors, LensDispatch, ToolRegistry,
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
        Ok(Self {
            ordinary: ExecutorPrototypeStdioServer::pin_hosted_catalogue_with_experimental(
                registry,
                experimental,
            )?,
            lens: ExecutorPrototypeLensServer::pin_catalogue_with_experimental(
                registry,
                experimental,
            )?,
        })
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
    lens_admission: Arc<PinnedLensExecutorCatalogue>,
    ordinary_telemetry: BoundExecutorTelemetry,
    lenses: PinnedLensCatalogueCache,
    telemetry: Arc<ExecutorTelemetryContext>,
    experimental: ExperimentalExecutors,
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

    async fn from_validated(
        registry: Arc<ToolRegistry>,
        authority: Arc<dyn HostedExecutorAuthority>,
        keys: Arc<dyn HostedPlanKeyProvider>,
        telemetry: Arc<ExecutorTelemetryContext>,
        experimental: ExperimentalExecutors,
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
        let ordinary = ExecutorPrototypeStdioServer::pin_hosted_catalogue_with_experimental(
            &registry,
            &experimental,
        )?;
        let ordinary_telemetry =
            telemetry.bind_hosted_manifest(ordinary.manifest_digest(), ordinary.descriptor_bytes());
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
            lens_admission,
            ordinary_telemetry,
            lenses: PinnedLensCatalogueCache::default(),
            telemetry,
            experimental,
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
        self.handle_ordinary_inner(db, caller, database_id, message, None)
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
        self.handle_ordinary_inner(db, caller, database_id, message, persistence_lease)
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

    async fn handle_ordinary_inner(
        &self,
        db: Db,
        caller: Caller,
        database_id: String,
        message: Value,
        persistence_lease: Option<DeploymentPersistenceLease>,
    ) -> Result<Option<Value>> {
        // Preserve the transport contract: successful authorization is
        // observed before plan-store/server construction, including when that
        // later construction fails.
        self.ordinary_telemetry.authorization_accepted();
        let mut server = ExecutorPrototypeStdioServer::new_hosted_with_pinned_catalogue(
            Arc::clone(&self.registry),
            db,
            caller,
            HostedExecutorConstruction {
                authority: Arc::clone(&self.authority),
                database_id,
                keys: Arc::clone(&self.keys),
                catalogue: Arc::clone(&self.ordinary),
                telemetry: Some(self.ordinary_telemetry.clone()),
            },
        )
        .await?;
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
            Some(self.ordinary.manifest_digest()),
            crate::FULL_GIT_SHA,
        );
    }

    /// Record a lens refusal that occurred before authoritative resolution.
    /// No lens manifest is pinned or claimed for this event.
    pub fn observe_lens_authorization_denied(&self) {
        self.telemetry
            .observe_hosted_authorization_denied(None, crate::FULL_GIT_SHA);
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
