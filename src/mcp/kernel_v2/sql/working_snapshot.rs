//! Private, bounded native-Get publication snapshots. A worker owns its SQLite
//! session through receiver cancellation. This is not a general read router.
// Private off-default support is deliberately unwired until the actual
// manager caller lands, matching the fork/journal/replay support modules.
#![allow(dead_code)]
use super::*;
use crate::fork::working_v2::{BindingGuard, WorkingPublication, WorkingReadBinding};
use crate::mcp::Caller;
use tokio::sync::{mpsc, oneshot};

pub(crate) const MAX_DECLARED_NOTES: usize = 16;
struct GetRequest {
    caller: Caller,
    arguments: Option<Value>,
    reply: oneshot::Sender<Result<Value>>,
}
#[derive(Clone)]
pub(crate) struct PinnedWorkingRead {
    sender: mpsc::Sender<GetRequest>,
    guard: BindingGuard,
    publication: WorkingPublication,
    notes: std::sync::Arc<Vec<String>>,
    workspace: bool,
    // Both handles and the worker retain the private generation owner. A
    // dropped response cannot release files while native hydration still runs.
    _generation: std::sync::Arc<dyn Send + Sync>,
}
pub(crate) struct WorkingReadResult {
    pub publication: WorkingPublication,
    pub value: Value,
}
impl PinnedWorkingRead {
    /// Staging is bounded to explicitly declared notes, using precisely the
    /// native Get columns and PartOf relation scope. No whole-workspace stage.
    pub(crate) async fn pin(
        db: Db,
        caller: Caller,
        notes: Vec<String>,
        guard: BindingGuard,
        owner_binding: WorkingReadBinding,
    ) -> Result<Self> {
        Self::pin_owned(
            db,
            caller,
            notes,
            guard,
            owner_binding,
            std::sync::Arc::new(()),
        )
        .await
    }
    pub(crate) async fn pin_owned(
        db: Db,
        caller: Caller,
        notes: Vec<String>,
        guard: BindingGuard,
        owner_binding: WorkingReadBinding,
        generation: std::sync::Arc<dyn Send + Sync>,
    ) -> Result<Self> {
        Self::pin_scope_owned(db, caller, Some(notes), guard, owner_binding, generation).await
    }
    /// One publication snapshot, with native Get's bounded request candidates
    /// staged on demand. No pending-ID union or workspace-wide TEMP stage.
    pub(crate) async fn pin_workspace_owned(
        db: Db,
        caller: Caller,
        guard: BindingGuard,
        owner_binding: WorkingReadBinding,
        generation: std::sync::Arc<dyn Send + Sync>,
    ) -> Result<Self> {
        Self::pin_scope_owned(db, caller, None, guard, owner_binding, generation).await
    }
    async fn pin_scope_owned(
        db: Db,
        caller: Caller,
        notes: Option<Vec<String>>,
        guard: BindingGuard,
        owner_binding: WorkingReadBinding,
        generation: std::sync::Arc<dyn Send + Sync>,
    ) -> Result<Self> {
        guard.check()?;
        let workspace = notes.is_none();
        let notes = notes.unwrap_or_default();
        if (!workspace
            && (notes.is_empty()
                || notes.len() > MAX_DECLARED_NOTES
                || notes.iter().any(|id| uuid::Uuid::parse_str(id).is_err())))
            || caller.host_asserted_app().is_some()
        {
            return Err(Error::engine(
                "working Get requires a bounded first-party note declaration",
            ));
        }
        let session = open_scoped_session(
            &db,
            "",
            super::super::GET_RECORD_READS,
            LinkScope::PartOf,
            Some(ReadCandidates::Anchors(&notes)),
            None,
            Some(&caller),
        )
        .await?;
        let publication = {
            let mut state = session.lock().await;
            let encoded: String = sqlx::query_scalar(
                "SELECT state FROM main._native_working_publication WHERE singleton=1",
            )
            .fetch_one(&mut *state.connection)
            .await?;
            let publication: WorkingPublication = serde_json::from_str(&encoded)?;
            publication.validate()?;
            let actual_principal = state.actor.clone();
            owner_binding
                .validate_on(&mut state.connection, &publication, &actual_principal)
                .await?;
            state
                .connection
                .lock_handle()
                .await?
                .remove_progress_handler();
            publication
        };
        // Native Get first establishes visibility on THIS existing snapshot.
        // Kind checks use only its authorized public rows, never raw metadata.
        let actor = session.lock().await.actor.clone();
        if !workspace {
            let declared = READ_SESSION
                .scope(session.clone(), async {
                    let plan = super::super::get_plan(json!({"ids":notes}))?;
                    tokio::time::timeout(
                        super::super::get_batch_deadline(),
                        kernel::read_cache::with_capabilities(super::super::get_record_from_plan(
                            &db, &actor, plan,
                        )),
                    )
                    .await
                    .map_err(|_| {
                        Error::engine("working native Get declaration deadline exceeded")
                    })?
                })
                .await?;
            let records = declared
                .get("records")
                .and_then(Value::as_array)
                .ok_or_else(|| Error::engine("working native Get declaration incomplete"))?;
            if records.len() != notes.len()
                || records.iter().any(|record| record["status"] != "found")
            {
                return Err(Error::engine(kernel::HIDDEN_OR_MISSING));
            }
            if records
                .iter()
                .any(|record| record["type"] != "Document" || record["kind"] != "note")
            {
                return Err(Error::engine(
                    "working Get requires plain Document/note targets",
                ));
            }
        }
        session
            .lock()
            .await
            .connection
            .lock_handle()
            .await?
            .remove_progress_handler();
        guard.check()?;
        let (sender, mut receive) = mpsc::channel::<GetRequest>(32);
        let worker_guard = guard.clone();
        let worker_generation = generation.clone();
        tokio::spawn(async move {
            let _generation = worker_generation;
            loop {
                let request = tokio::select! {
                    _ = worker_guard.closed() => break,
                    request = receive.recv() => match request { Some(request) => request, None => break },
                };
                let authorized = async {
                    worker_guard.check()?;
                    if request.caller.host_asserted_app().is_some() {
                        return Err(Error::engine("working Get is first-party only"));
                    }
                    let mut state = session.lock().await;
                    let pinned = {
                        let mut handle = state.connection.lock_handle().await?;
                        handle.remove_progress_handler();
                        // SAFETY: the owned physical handle is exclusively locked.
                        unsafe {
                            libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr())
                                == 0
                        }
                    };
                    if !pinned {
                        return Err(Error::engine("working snapshot lost its read transaction"));
                    }
                    let actor =
                        super::super::principal_on(&mut state.connection, &request.caller).await?;
                    if actor != state.actor {
                        return Err(Error::engine("working read principal changed"));
                    }
                    Ok(actor)
                }
                .await;
                let actor = match authorized {
                    Ok(actor) => actor,
                    Err(error) => {
                        let _ = request.reply.send(Err(error));
                        continue;
                    }
                };
                if request.arguments.is_none() {
                    let _delivery = worker_guard.while_open(|| request.reply.send(Ok(Value::Null)));
                    continue;
                }
                // Use native Get hydration/enrichment inside this existing
                // session, not get_record_read (which opens another snapshot).
                let result = READ_SESSION
                    .scope(session.clone(), async {
                        let plan =
                            super::super::get_plan(request.arguments.expect("Get arguments"))?;
                        if workspace {
                            restage_working_get(&session, &plan.args.ids).await?;
                        }
                        tokio::time::timeout(
                            super::super::get_batch_deadline(),
                            kernel::read_cache::with_capabilities(
                                super::super::get_record_from_plan(&db, &actor, plan),
                            ),
                        )
                        .await
                        .map_err(|_| Error::engine("working native Get deadline exceeded"))?
                    })
                    .await;
                // TEMP candidates belong to this request, even if its receiver
                // was cancelled. The worker owns cleanup before any next caller.
                let result = if workspace {
                    match clear_working_get(&session).await {
                        Ok(()) => result,
                        Err(error) => Err(error),
                    }
                } else {
                    result
                };
                let failed = result.is_err();
                // Confirmed close and response delivery share the short
                // owner fence; native work itself never holds this mutex.
                let _delivery = worker_guard.while_open(|| request.reply.send(result));
                // A failed/interrupted VM may have unpinned the transaction.
                // Never reuse it or silently reopen at another publication.
                if failed {
                    break;
                }
            }
            // Cancellation of a receiver never cancels the owner above. A
            // binding close or last-handle drop eventually closes its session.
        });
        Ok(Self {
            sender,
            guard,
            publication,
            notes: std::sync::Arc::new(notes),
            workspace,
            _generation: generation,
        })
    }
    pub(crate) fn ensure_open(&self) -> Result<()> {
        self.guard.check()?;
        if self.sender.is_closed() {
            return Err(Error::engine("working snapshot owner stopped"));
        }
        Ok(())
    }
    pub(crate) fn publication(&self) -> &WorkingPublication {
        &self.publication
    }
    pub(crate) async fn get(&self, caller: Caller, id: &str) -> Result<WorkingReadResult> {
        self.get_arguments(caller, json!({"ids":[id]})).await
    }
    pub(crate) async fn get_arguments(
        &self,
        caller: Caller,
        arguments: Value,
    ) -> Result<WorkingReadResult> {
        self.guard.check()?;
        if arguments.as_object().is_none_or(|args| {
            args.keys()
                .any(|key| !matches!(key.as_str(), "ids" | "links_limit" | "links_offset"))
        }) {
            return Err(Error::engine(
                "working Get supports bounded current ids and native link windows",
            ));
        }
        let plan = super::super::get_plan(arguments.clone())?;
        if !self.workspace
            && plan
                .args
                .ids
                .iter()
                .any(|id| !self.notes.iter().any(|note| note == id))
        {
            return Err(Error::engine(
                "note is outside the declared working read set",
            ));
        }
        let value = self.request(caller, Some(arguments)).await?;
        Ok(WorkingReadResult {
            publication: self.publication.clone(),
            value,
        })
    }
    /// Authenticate before handing a new caller this publication's header.
    /// This uses the SAME retained native session, with no hydration/polling.
    pub(crate) async fn authorize(&self, caller: Caller) -> Result<()> {
        self.request(caller, None).await?;
        Ok(())
    }
    async fn request(&self, caller: Caller, arguments: Option<Value>) -> Result<Value> {
        self.guard.check()?;
        if caller.host_asserted_app().is_some() || crate::provenance::current_app_claim().is_some()
        {
            return Err(Error::engine("working Get is first-party only"));
        }
        let (reply, result) = oneshot::channel();
        self.sender
            .send(GetRequest {
                caller,
                arguments,
                reply,
            })
            .await
            .map_err(|_| Error::engine("working snapshot unavailable"))?;
        let value = result
            .await
            .map_err(|_| Error::engine("working snapshot owner stopped"))??;
        self.guard.check()?;
        Ok(value)
    }
}

async fn clear_working_get(
    session: &std::sync::Arc<tokio::sync::Mutex<ReadSession>>,
) -> Result<()> {
    let mut state = session.lock().await;
    state.staging_failure = Some("working Get cleanup interrupted".into());
    state
        .connection
        .lock_handle()
        .await?
        .remove_progress_handler();
    sqlx::query("PRAGMA query_only=OFF; ROLLBACK TO demand_stage; PRAGMA query_only=ON")
        .execute(&mut *state.connection)
        .await?;
    state.staging.anchors = Some(Vec::new());
    state.staging_failure = None;
    Ok(())
}

async fn restage_working_get(
    session: &std::sync::Arc<tokio::sync::Mutex<ReadSession>>,
    ids: &[String],
) -> Result<()> {
    let mut state = session.lock().await;
    state.staging_failure = Some("working Get restaging interrupted".into());
    state
        .connection
        .lock_handle()
        .await?
        .remove_progress_handler();
    // This is the ordinary composed-read savepoint, inside the SAME retained
    // outer native read transaction. Main is physically read-only; only TEMP
    // request candidates are rebuilt, never accumulated across callers.
    sqlx::query("PRAGMA query_only=OFF; ROLLBACK TO demand_stage")
        .execute(&mut *state.connection)
        .await?;
    state.staging.anchors = Some(ids.to_vec());
    state.staging.names = None;
    state.staging.exact = None;
    state.demand_enabled = false;
    let started = Instant::now();
    let budget = Duration::from_millis(contract::QUERY_DEADLINE_MS);
    let mut deadline = guard_diagnostics::VmDeadline::new(
        started,
        budget,
        guard_diagnostics::Stage::ComposedStaging,
    );
    state
        .connection
        .lock_handle()
        .await?
        .set_progress_handler(guard::PROGRESS_OPS, move || deadline.evaluate().0);
    let ReadSession {
        connection,
        db,
        actor,
        reads,
        cache_identity,
        admission_cache,
        staging,
        ..
    } = &mut *state;
    demand::with_legacy(kernel::read_cache::in_pinned_snapshot_with_admissions(
        cache_identity.clone(),
        kernel::read_cache::connection_id(connection),
        admission_cache.clone(),
        async {
            visible_cache::scoped(db, staging.install(connection, db, actor, reads)).await?;
            Box::pin(materialize_composed_records(connection, reads)).await?;
            Ok::<_, Error>(())
        },
    ))
    .await?;
    if started.elapsed() >= budget {
        return Err(Error::engine(
            "working Get request staging deadline exceeded",
        ));
    }
    state.staging_failure = None;
    state
        .connection
        .lock_handle()
        .await?
        .remove_progress_handler();
    Ok(())
}

/// Native collection queries use a separate raw read transaction. Get's TEMP
/// request relations cannot represent full accepted-plus-pending discovery.
#[derive(Clone)]
pub(crate) struct PinnedWorkingCollection {
    sender: mpsc::Sender<CollectionRequest>,
    guard: BindingGuard,
    publication: WorkingPublication,
    _generation: std::sync::Arc<dyn Send + Sync>,
}
struct CollectionRequest {
    caller: Caller,
    query: CollectionQuery,
    reply: oneshot::Sender<Result<Value>>,
}
enum CollectionQuery {
    Search(super::super::SearchArgs),
    List(super::super::QueryArgs, super::super::Filter),
}
impl CollectionQuery {
    fn parse(operation: &str, args: Value) -> Result<Self> {
        match operation {
            "search" => {
                let args: super::super::SearchArgs = super::super::parse(operation, args)?;
                if args.query.trim().is_empty()
                    || args.scope.is_some()
                    || args.limit.is_some_and(|n| !(1..=200).contains(&n))
                {
                    return Err(Error::engine("working search requires a nonempty query, limit 1..200 and no scope; scoped search is not yet qualified"));
                }
                Ok(Self::Search(args))
            }
            "query_record" => {
                let args: super::super::QueryArgs = super::super::parse(operation, args)?;
                if args.steps.len() != 1
                    || args.limit.is_some_and(|n| !(1..=500).contains(&n))
                    || args.projection.as_ref().is_some_and(|p| {
                        *p != crate::mcp::tools::querying::RecordProjection::Metadata
                    })
                {
                    return Err(Error::engine("working list supports one bounded record filter, limit 1..500, offset and optional metadata projection"));
                }
                let filter: super::super::Filter =
                    super::super::parse(operation, args.steps[0].clone())?;
                if filter.step != "filter"
                    || filter.types.as_ref().is_none_or(|types| {
                        types.is_empty()
                            || types.len() > 2
                            || types
                                .iter()
                                .any(|ty| !matches!(ty.as_str(), "Document" | "WorkItem"))
                    })
                    || filter.kinds.as_ref().is_some_and(|kinds| {
                        kinds.is_empty()
                            || kinds.len() > 2
                            || kinds
                                .iter()
                                .any(|kind| !matches!(kind.as_str(), "note" | "task"))
                    })
                    || filter
                        .ids
                        .as_ref()
                        .is_some_and(|ids| ids.len() > 500 || ids.iter().any(|id| id.len() > 200))
                {
                    return Err(Error::engine("working list requires bounded Document/WorkItem types and optional note/task kinds; broader pipelines are not yet qualified"));
                }
                Ok(Self::List(args, filter))
            }
            _ => Err(Error::engine("unsupported working collection operation")),
        }
    }
    async fn execute(self, conn: &mut sqlx::SqliteConnection, actor: &str) -> Result<Value> {
        match self {
            Self::Search(args) => {
                let limit = args.limit.unwrap_or(20);
                let (hits, truncated) = kernel::search_v2::search_scoped_on(
                    conn,
                    actor,
                    &args.query,
                    limit,
                    args.include_archived.unwrap_or(false),
                    None,
                )
                .await?;
                let mut rendered = Vec::with_capacity(hits.len());
                for hit in &hits {
                    let home = crate::v1_import::placement_on(conn, actor, &hit.id)
                        .await?
                        .filter(|p| p.kernel_home_id == hit.home_id)
                        .and_then(|p| p.home_id);
                    rendered.push(json!({"id":hit.id,"type":hit.record_type,"kind":hit.kind,"name":hit.name,"home_id":home,"score":hit.score,"snippet":hit.snippet}));
                }
                let limit_reached = truncated || hits.len() as i64 == limit;
                let mut value = json!({"query":args.query,"scope":args.scope,"hits":rendered,"total":hits.len(),"returned":hits.len(),"limit":limit,"limit_reached":limit_reached,"thin":false});
                if limit_reached {
                    value["guidance"] = json!("This list may be incomplete. Use query_record with a filter step for a narrow, exhaustive answer.");
                }
                Ok(value)
            }
            Self::List(args, filter) => {
                let groups = kernel::search_v2::distinct_groups_on(conn).await?;
                let limit = args.limit.unwrap_or(50);
                let offset = args.offset.unwrap_or(0);
                let page = kernel::search_v2::bounded_query_on(
                    conn,
                    actor,
                    &groups,
                    filter.ids.as_deref(),
                    filter.types.as_deref(),
                    filter.kinds.as_deref(),
                    None,
                    limit,
                    offset,
                    &kernel::search_v2::S7aCounters::default(),
                )
                .await?;
                let metadata = args.projection.is_some();
                let records = super::super::bounded_page_on(conn, actor, &page, metadata).await?;
                let returned = records.len();
                let mut value = json!({"shape":"records","records":records,"total":page.total,"returned":returned,"offset":offset,"has_more":offset.saturating_add(returned)<page.total});
                if metadata {
                    crate::mcp::tools::querying::project_record_metadata(&mut value);
                }
                Ok(value)
            }
        }
    }
}
impl PinnedWorkingCollection {
    pub(crate) async fn pin_owned(
        db: Db,
        caller: Caller,
        guard: BindingGuard,
        owner_binding: WorkingReadBinding,
        generation: std::sync::Arc<dyn Send + Sync>,
    ) -> Result<Self> {
        guard.check()?;
        if caller.host_asserted_app().is_some() || crate::provenance::current_app_claim().is_some()
        {
            return Err(Error::engine("working discovery is first-party only"));
        }
        // Db is the physically read-only handle opened before collector DDL.
        // BEGIN and the header read pin accepted and pending native projections.
        let mut tx = db.pool().begin().await?;
        let actor = super::super::principal_on(&mut tx, &caller).await?;
        let encoded: String = sqlx::query_scalar(
            "SELECT state FROM main._native_working_publication WHERE singleton=1",
        )
        .fetch_one(&mut *tx)
        .await?;
        let publication: WorkingPublication = serde_json::from_str(&encoded)?;
        publication.validate()?;
        owner_binding
            .validate_on(&mut tx, &publication, &actor)
            .await?;
        guard.check()?;
        let (sender, mut receive) = mpsc::channel::<CollectionRequest>(32);
        let worker_guard = guard.clone();
        let worker_generation = generation.clone();
        tokio::spawn(async move {
            let _generation = worker_generation;
            loop {
                let request = tokio::select! { _ = worker_guard.closed() => break,
                r = receive.recv() => match r { Some(r) => r, None => break }, };
                let authorized = async {
                    worker_guard.check()?;
                    if request.caller.host_asserted_app().is_some() {
                        return Err(Error::engine("working discovery is first-party only"));
                    }
                    let pinned = {
                        let mut handle = tx.lock_handle().await?;
                        handle.remove_progress_handler();
                        // SAFETY: this worker exclusively owns the physical RO handle.
                        unsafe {
                            libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr())
                                == 0
                        }
                    };
                    if !pinned {
                        return Err(Error::engine("working discovery lost its read transaction"));
                    }
                    if super::super::principal_on(&mut tx, &request.caller).await? != actor {
                        return Err(Error::engine("working discovery principal changed"));
                    }
                    Ok(())
                }
                .await;
                if let Err(error) = authorized {
                    let _ = request.reply.send(Err(error));
                    continue;
                }
                let result = async {
                    let budget = Duration::from_millis(contract::QUERY_DEADLINE_MS);
                    let mut deadline = guard_diagnostics::VmDeadline::new(
                        Instant::now(),
                        budget,
                        guard_diagnostics::Stage::SnapshotHydration,
                    );
                    tx.lock_handle()
                        .await?
                        .set_progress_handler(guard::PROGRESS_OPS, move || deadline.evaluate().0);
                    tokio::time::timeout(
                        budget,
                        kernel::read_cache::with_capabilities(
                            request.query.execute(&mut tx, &actor),
                        ),
                    )
                    .await
                    .map_err(|_| Error::engine("working discovery deadline exceeded"))?
                }
                .await;
                let failed = result.is_err();
                let _delivery = worker_guard.while_open(|| request.reply.send(result));
                if failed {
                    break;
                }
            }
            // Ordinary settled RO transaction ownership, independent of a
            // dropped response receiver; no writes or lease reuse here.
            let _ = tx.rollback().await;
        });
        Ok(Self {
            sender,
            guard,
            publication,
            _generation: generation,
        })
    }
    pub(crate) fn publication(&self) -> &WorkingPublication {
        &self.publication
    }
    pub(crate) async fn query(
        &self,
        caller: Caller,
        operation: &str,
        args: Value,
    ) -> Result<WorkingReadResult> {
        self.guard.check()?;
        if caller.host_asserted_app().is_some() || crate::provenance::current_app_claim().is_some()
        {
            return Err(Error::engine("working discovery is first-party only"));
        }
        let query = CollectionQuery::parse(operation, args)?;
        let (reply, result) = oneshot::channel();
        self.sender
            .send(CollectionRequest {
                caller,
                query,
                reply,
            })
            .await
            .map_err(|_| Error::engine("working discovery unavailable"))?;
        let value = result
            .await
            .map_err(|_| Error::engine("working discovery owner stopped"))??;
        self.guard.check()?;
        Ok(WorkingReadResult {
            publication: self.publication.clone(),
            value,
        })
    }
}
