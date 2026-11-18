//! Probe-only public SQL over a single kernel authority snapshot.
//!
//! Only TEMP state is written. The physical connection is discarded even on
//! cancellation, so neither scoped rows nor VM guards can reach another caller.
#[cfg(feature = "v2-kernel-probe")]
pub(super) mod working_snapshot;

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

// Semantic selector inputs shared with the disposable projector.
pub(crate) const SELECTOR_EXCLUSION_GLOBS_SQL: &str =
    "e.type NOT GLOB 'kernel.hcp_*' AND e.type NOT GLOB 'kernel.webhook_*'";
pub(crate) const IMPORT_EVENT_PATTERN: &str = "kernel.import_*";
pub(crate) fn native_event_globs_sql() -> String {
    format!("{SELECTOR_EXCLUSION_GLOBS_SQL} AND e.type NOT GLOB '{IMPORT_EVENT_PATTERN}'")
}
pub(crate) const RECORD_EVENT_EXCLUSIONS_SQL: &str = "'kernel.identity_binding_added.v1','kernel.identity_binding_removed.v1','kernel.identity_bindings_reconciled.v1','kernel.account_config_bound.v1','kernel.app_state_imported.v1','kernel.import_receipt.v1','kernel.v1_state_imported.v1','kernel.message_state.v1','kernel.notification_preference_set.v1','kernel.message_command_committed.v1','kernel.mcp_write_receipt_recorded.v1','kernel.mcp_write_fenced.v1','kernel.message_destination_imported.v1','kernel.message_destination_set.v1','kernel.provider_outcome.v1','kernel.link_added.v2','kernel.link_added.v1','kernel.link_removed.v1'";
pub(crate) const PROJECTED_EVENT_EXCLUSIONS_SQL: &str = "'kernel.identity_binding_added.v1','kernel.identity_binding_removed.v1','kernel.identity_bindings_reconciled.v1','kernel.account_config_bound.v1','kernel.app_state_imported.v1','kernel.v1_state_imported.v1','kernel.message_state.v1','kernel.notification_preference_set.v1','kernel.message_command_committed.v1','kernel.mcp_write_receipt_recorded.v1','kernel.mcp_write_fenced.v1','kernel.message_destination_imported.v1','kernel.message_destination_set.v1'";
pub(crate) const V1_LINK_TYPES_SQL: &str = "'kernel.link_added.v1','kernel.link_removed.v1'";
pub(crate) const GENERIC_LINK_PATTERN: &str = "kernel.generic_link_%";
pub(crate) const LINK4_TYPE: &str = "kernel.link_added.v2";
pub(crate) const PROVIDER_TYPE: &str = "kernel.provider_outcome.v1";

mod activity;
mod connection;
pub(crate) mod demand;
#[cfg(test)]
pub(crate) mod event_equivalence;
#[cfg(test)]
pub(crate) mod event_profile;
mod event_projection;
mod event_scope;
#[cfg(test)]
mod event_staging_baseline;
#[cfg(test)]
pub(crate) use event_scope::with_full_staging as with_full_event_staging;
mod facet_times;
mod facets;
mod guard_diagnostics;
mod lifecycle;
mod named_views;
mod observation_scope;
mod predicates;
#[cfg(all(test, feature = "v2-kernel-probe"))]
mod read_diagnostics;
mod record_classes;
mod record_projection;
#[cfg(test)]
pub(crate) use record_projection::with_oracle as with_record_projection_oracle;
#[cfg(test)]
#[path = "sql_read_cost.rs"]
pub(crate) mod read_cost;
mod record_scope;
mod union_sections;
pub(crate) mod visible_cache;

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) use read_diagnostics::{with_candidate_diagnostics, with_session_lifecycle};

#[cfg(test)]
pub(crate) async fn with_full_union_staging<F: std::future::Future>(work: F) -> F::Output {
    union_sections::with_full_staging(work).await
}

#[cfg(test)]
tokio::task_local! { static ALL_MOVED_CANDIDATES: (); }

/// Same-fixture baseline for Get/render before logical move narrowing.
#[cfg(test)]
pub(crate) async fn with_all_moved_candidates<F: std::future::Future>(work: F) -> F::Output {
    ALL_MOVED_CANDIDATES.scope((), work).await
}

#[cfg(test)]
pub(crate) async fn with_full_record_scope_staging<F: std::future::Future>(work: F) -> F::Output {
    record_scope::with_full_staging(work).await
}

#[cfg(test)]
pub(crate) async fn with_full_facet_staging<F: std::future::Future>(work: F) -> F::Output {
    facets::with_full_staging(work).await
}

#[cfg(test)]
pub(crate) async fn with_full_lifecycle_staging<F: std::future::Future>(work: F) -> F::Output {
    lifecycle::with_full_staging(work).await
}

#[cfg(test)]
pub(crate) async fn with_full_record_class_staging<F: std::future::Future>(work: F) -> F::Output {
    predicates::with_full_staging(work).await
}

/// Today's full-staging read: every finite-scope narrowing off, permanent
/// oracle cells. The reference that demand-scoped staging must equal.
#[cfg(test)]
pub(crate) async fn with_full_read_oracle<F: std::future::Future>(work: F) -> F::Output {
    record_projection::with_oracle(record_scope::with_full_staging(
        predicates::with_full_staging(event_scope::with_full_staging(
            union_sections::with_full_staging(work),
        )),
    ))
    .await
}

use futures::TryStreamExt;

use serde_json::{json, Map, Value};
use sqlx::{Column, Row};

use super::parse;
use crate::authorization::Capability;
use crate::query::{sql as guard, sql_contract as contract};
use crate::{db::Db, kernel, Error, Result};

#[cfg(test)]
pub(super) fn columns_for_test(relation: &str) -> bool {
    columns(relation).is_some()
}

pub(crate) fn columns(relation: &str) -> Option<&'static [&'static str]> {
    if relation == "bindings" {
        return Some(&["record_id", "system", "identifier", "is_canonical"]);
    }
    if [
        "records",
        "blobs",
        "links",
        "runs",
        "run_intents",
        "actors",
        "viewer",
        "comment_anchors",
        "vocabularies",
        "vocabulary_values",
        "record_lifecycle_interpretations",
        "agent_activity",
        "agent_activity_claims",
        "facet_values",
        "facet_observations",
        "facet_times",
        "bindings",
        "message_reactions",
        "my_mentions",
        "my_message_state",
        "messages_awaiting_reply",
        "catalog_relations",
        "catalog_columns",
        "catalog_operations",
        "catalog_view_definitions",
    ]
    .contains(&relation)
    {
        return contract::LOGICAL_RELATIONS
            .iter()
            .find(|r| r.name == relation)
            .map(|r| r.columns);
    }
    if relation == "content_events" {
        return Some(&[
            "local_seq",
            "id",
            "record_id",
            "type",
            "actor",
            "run_key",
            "parent_key",
            "channel_kind",
            "created_at",
            "created_at_ms",
        ]);
    }
    None
}
fn unsupported(relation: &str, column: &str) -> Error {
    contract::categorized_error(
        contract::QuerySqlErrorCategory::UnauthorizedRelation,
        format!(
            "{} not yet supported on v2. Supported columns: {}. See catalog_columns.",
            if column.is_empty() {
                format!("relation '{relation}'")
            } else {
                format!("column '{relation}.{column}'")
            },
            columns(relation)
                .map(|cols| cols.join(", "))
                .unwrap_or_else(|| "none for this relation".into())
        ),
    )
}

// Internal composed reads may share one scoped authority snapshot. The session
// is task-local, handle/caller-bound, never cached across requests, and its
// physical connection is discarded on cancellation just like ordinary SQL.
struct ReadSession {
    #[cfg(test)]
    cost_probe: Option<usize>,
    db: Db,
    actor: String,
    connection: connection::ReadConnection,
    reads: BTreeSet<(String, String)>,
    as_of_seq: i64,
    cache_identity: Option<kernel::read_cache::Key>,
    admission_cache: std::sync::Arc<kernel::app_installs::ReadAdmissions>,
    demand_enabled: bool,
    staging: SessionStaging,
    staging_failure: Option<String>,
}
tokio::task_local! {
    static READ_SESSION: std::sync::Arc<tokio::sync::Mutex<ReadSession>>;
    static SNAPSHOT_VM_DEADLINE: Instant;
}

/// The external fixture owns release. Cancelling the scoped reader drops only
/// its task-local clone; panic/cancellation of the fixture releases the worker.
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(super) struct CurrentCloseProbe {
    inner: std::sync::Arc<connection::CloseProbe>,
}
#[cfg(all(test, feature = "v2-kernel-probe"))]
impl CurrentCloseProbe {
    pub(super) fn new() -> Self {
        Self {
            inner: connection::CloseProbe::new(),
        }
    }
    pub(super) fn scope<F>(
        &self,
        work: F,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = F::Output> + Send + 'static>>
    where
        F: std::future::Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let inner = self.inner.clone();
        Box::pin(async move { connection::with_close_probe(inner, work).await })
    }
    pub(super) async fn pending(&self) {
        self.inner.pending().await;
    }
    pub(super) fn acknowledged(&self) -> bool {
        self.inner.acknowledged()
    }
    pub(super) fn handle(&self) -> usize {
        self.inner.handle()
    }
    pub(super) fn release_worker(&self) {
        self.inner.release_worker();
    }
}
#[cfg(all(test, feature = "v2-kernel-probe"))]
impl Drop for CurrentCloseProbe {
    fn drop(&mut self) {
        self.inner.release_worker();
    }
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(super) async fn with_failed_current_close_ack<F: std::future::Future>(work: F) -> F::Output {
    connection::with_failed_close_ack(work).await
}

#[cfg(feature = "v2-kernel-probe")]
tokio::task_local! { static CURRENT_OWNED_SQL: (); }
#[cfg(feature = "v2-kernel-probe")]
pub(super) fn require_no_read_session() -> Result<()> {
    if READ_SESSION.try_with(|_| ()).is_ok() || CURRENT_OWNED_SQL.try_with(|_| ()).is_ok() {
        return Err(Error::engine(
            "current body read rejects an ambient or nested SQL session",
        ));
    }
    Ok(())
}

#[cfg(feature = "v2-kernel-probe")]
pub(super) struct ClosedCurrentGet<T>(T);
#[cfg(feature = "v2-kernel-probe")]
impl<T> ClosedCurrentGet<T> {
    pub(super) fn into_owned(self) -> T {
        self.0
    }
}

#[cfg(feature = "v2-kernel-probe")]
pub(super) async fn with_current_materialization<T, F, Fut>(
    db: &Db,
    caller: &super::Caller,
    reads: &[(&str, &str)],
    ids: &[String],
    work: F,
) -> Result<ClosedCurrentGet<T>>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    require_no_read_session()?;
    let session = open_scoped_session(
        db,
        "",
        reads,
        LinkScope::PartOf,
        Some(ReadCandidates::Anchors(ids)),
        None,
        Some(caller),
    )
    .await?;
    let actor = {
        let mut owned = session.lock().await;
        // Reject obvious oversize visible body/metadata before native hydration
        // can copy them into a response Value. No text is fetched by this guard.
        // Counts are deliberately conservative and apply only to this lane.
        let bytes: i64 = sqlx::query_scalar(
            "WITH requested(id) AS (SELECT value FROM json_each(?1)), visible(id) AS (SELECT r.id FROM temp.records r JOIN requested q ON q.id=r.id) SELECT coalesce(sum(bytes),0) FROM (SELECT length(CAST(b.body AS BLOB)) AS bytes FROM main.kernel_record_bodies b JOIN visible v ON v.id=b.record_id UNION ALL SELECT length(CAST(f.name AS BLOB))+length(CAST(f.value_json AS BLOB)) FROM main.kernel_record_fields f JOIN visible v ON v.id=f.record_id UNION ALL SELECT length(CAST(f.key AS BLOB))+length(CAST(f.value AS BLOB))+coalesce(length(CAST(f.vocab_ref AS BLOB)),0) FROM main.kernel_facets f JOIN visible v ON v.id=f.record_id WHERE f.value IS NOT NULL AND f.key!='archived')"
        ).bind(serde_json::to_string(ids)?).fetch_one(&mut *owned.connection).await?;
        if bytes < 0 || bytes as u64 > contract::MAX_RESULT_ENCODED_BYTES as u64 {
            return Err(Error::engine(
                "current get_record exceeds staging byte limit; no partial result",
            ));
        }
        owned.actor.clone()
    };
    let result = CURRENT_OWNED_SQL
        .scope((), READ_SESSION.scope(session.clone(), work(actor)))
        .await;
    let session = std::sync::Arc::try_unwrap(session).map_err(|_| {
        Error::engine("current body SQL session ownership escaped; no validation permitted")
    })?;
    let ReadSession { mut connection, .. } = session.into_inner();
    let rollback = sqlx::query("ROLLBACK").execute(&mut *connection).await;
    #[cfg(test)]
    let boundary =
        super::current_body_read::checkpoint(db, super::current_body_read::Stage::SqlRolledBack)
            .await;
    let closed = connection.close_owned().await;
    rollback?;
    #[cfg(test)]
    boundary?;
    closed?;
    result.map(ClosedCurrentGet)
}

pub(super) async fn with_read_session<T>(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    with_scoped_read_session(db, actor, reads, LinkScope::All, None, None, work).await
}

/// Closed exact-name resolution only. Candidates are a structural superset;
/// the normal record View gate and final logical-name predicate still apply.
pub(super) async fn with_name_read_session<T>(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    names: &[String],
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    with_scoped_read_session(
        db,
        actor,
        reads,
        LinkScope::All,
        Some(ReadCandidates::Names(names)),
        None,
        work,
    )
    .await
}

/// Share staging for a closed count/page pair. Hydration runs after this
/// selection session ends, so it retains its independent live View recheck.
pub(super) async fn with_query_read_session<T>(
    db: &Db,
    actor: &str,
    statements: &[&str],
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if READ_SESSION.try_with(|_| ()).is_ok() {
        return work.await;
    }
    let mut reads = BTreeSet::new();
    for statement in statements {
        reads.extend(guard::public_reads_ad_hoc(statement)?);
    }
    let reads = reads
        .iter()
        .map(|(r, c)| (r.as_str(), c.as_str()))
        .collect::<Vec<_>>();
    event_scope::scope(statements, with_read_session(db, actor, &reads, work)).await
}

/// Declared SQL already has validated bindings. Carry them into demand
/// planning before staging, while retaining the ordinary snapshot and gates.
#[cfg(test)]
pub(crate) async fn with_bound_query_read_session_for_test<T>(
    db: &Db,
    actor: &str,
    queries: &[Value],
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    with_bound_query_read_session(db, actor, queries, work).await
}

pub(super) async fn with_bound_query_read_session<T>(
    db: &Db,
    actor: &str,
    queries: &[Value],
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if READ_SESSION.try_with(|_| ()).is_ok() {
        return work.await;
    }
    let mut reads = BTreeSet::new();
    let mut prepared = Vec::new();
    let mut finite = Some(BTreeSet::new());
    let mut plan = demand::plan_for(db);
    let mut home_chain = false;
    for args in queries {
        // Invalid batch items retain their ordinary per-item refusal when
        // executed; they cannot contribute a staging dependency or demand.
        let Ok((query, dependencies)) = prepare_read(actor, args.clone(), false) else {
            continue;
        };
        if let Some(ids) = &mut finite {
            if let Some((bound, chain)) = record_scope::ids_with(
                &query.statement,
                &query.parameters,
                &dependencies,
                plan.docs_page,
            ) {
                home_chain |= chain;
                ids.extend(bound);
                if ids.len() > 1000 {
                    finite = None;
                }
            } else {
                finite = None;
            }
        }
        reads.extend(dependencies);
        prepared.push(query);
    }
    let reads = reads
        .iter()
        .map(|(r, c)| (r.as_str(), c.as_str()))
        .collect::<Vec<_>>();
    // An empty declaration can still use closed non-SQL snapshot helpers.
    let ids = if prepared.is_empty() { None } else { finite };
    let ids_json = ids.as_ref().map(serde_json::to_string).transpose()?;
    let candidates = ids_json.as_deref().map(|arg| ReadCandidates::ExactFrom {
        sql: "SELECT value FROM json_each(?1)",
        arg,
    });
    plan.home_chain = home_chain && ids.is_some();
    demand::scoped_for_db(
        db,
        plan,
        event_scope::bound_scope(
            &prepared,
            with_scoped_read_session(db, actor, &reads, LinkScope::All, candidates, None, work),
        ),
    )
    .await
}

/// `with_query_read_session` staging only the ids `candidate_sql` yields on
/// the session's own snapshot (see `ReadCandidates::ExactFrom`). The compiled
/// statements, visibility gate and guards are unchanged; a NULL candidate row
/// falls back to full staging in the same session.
pub(super) async fn with_query_read_session_exact<T>(
    db: &Db,
    actor: &str,
    statements: &[&str],
    candidate_sql: &str,
    candidate_arg: &str,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    if READ_SESSION.try_with(|_| ()).is_ok() {
        return work.await;
    }
    let mut reads = BTreeSet::new();
    for statement in statements {
        reads.extend(guard::public_reads_ad_hoc(statement)?);
    }
    let reads = reads
        .iter()
        .map(|(r, c)| (r.as_str(), c.as_str()))
        .collect::<Vec<_>>();
    with_scoped_read_session(
        db,
        actor,
        &reads,
        LinkScope::All,
        Some(ReadCandidates::ExactFrom {
            sql: candidate_sql,
            arg: candidate_arg,
        }),
        None,
        work,
    )
    .await
}

/// Get's composed SQL only consumes part_of edges for annotation windows.
/// Its complete link envelope still uses the kernel's subject-scoped reader.
pub(super) async fn with_part_of_read_session<T>(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    ids: &[String],
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    with_scoped_read_session(
        db,
        actor,
        reads,
        LinkScope::PartOf,
        Some(ReadCandidates::Anchors(ids)),
        None,
        work,
    )
    .await
}

/// Only the closed renderer lookup may use this narrowed relation.
pub(super) async fn with_renderer_read_session<T>(
    db: &Db,
    actor: &str,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    with_scoped_read_session(
        db,
        actor,
        &[
            ("records", "id"),
            ("records", "name"),
            ("links", "source_id"),
            ("links", "target_id"),
            ("links", "relationship"),
        ],
        LinkScope::Renderers,
        None,
        None,
        work,
    )
    .await
}

#[derive(Clone, Copy)]
pub(super) struct HistoryWindow {
    pub after: Option<i64>,
    pub newest: bool,
    pub limit: usize,
}

pub(super) async fn with_history_read_session<T>(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    window: HistoryWindow,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    with_scoped_read_session(db, actor, reads, LinkScope::All, None, Some(window), work).await
}

/// Label only the extended query_record composition; never accept caller text
/// as a diagnostic tool or phase. The label is captured before SQLite's worker.
pub(super) async fn with_query_record_guard_diagnostics<F: std::future::Future>(
    work: F,
) -> F::Output {
    guard_diagnostics::query_record(work).await
}

/// Label the current query_record's computed shape for deadline diagnostics.
pub(super) fn set_query_record_shape(shape: &'static str) {
    guard_diagnostics::set_query_record_shape(shape);
}

/// Hydration and SQL enrichment borrow the same caller-bound read snapshot.
/// The closure must only use connection-scoped kernel helpers.
pub(super) async fn in_snapshot<T>(
    db: &Db,
    actor: &str,
    work: impl for<'a> FnOnce(
        &'a mut sqlx::SqliteConnection,
    ) -> futures::future::BoxFuture<'a, Result<T>>,
) -> Result<T> {
    if let Ok(session) = READ_SESSION.try_with(Clone::clone) {
        let mut session = session.lock().await;
        if !session.db.same_handle(db) || session.actor != actor {
            return Err(Error::engine("read snapshot caller/database mismatch"));
        }
        if let Some(error) = &session.staging_failure {
            return Err(Error::engine(error.clone()));
        }
        // Hydration is bounded per subject, not by time already spent on
        // other ids. Keep the transaction and staging, reset only the VM
        // work budget; composed SQL independently applies the same deadline.
        let started = Instant::now();
        let budget = snapshot_budget();
        let deadline = started + budget;
        let mut vm_deadline = guard_diagnostics::VmDeadline::new(
            started,
            budget,
            guard_diagnostics::Stage::SnapshotHydration,
        );
        session
            .connection
            .lock_handle()
            .await?
            .set_progress_handler(guard::PROGRESS_OPS, move || vm_deadline.evaluate().0);
        let identity = session.cache_identity.clone();
        SNAPSHOT_VM_DEADLINE
            .scope(
                deadline,
                kernel::read_cache::in_pinned_snapshot_with_admissions(
                    identity,
                    kernel::read_cache::connection_id(&mut session.connection),
                    session.admission_cache.clone(),
                    work(&mut session.connection),
                ),
            )
            .await
    } else {
        #[cfg(feature = "v2-kernel-probe")]
        if CURRENT_OWNED_SQL.try_with(|_| ()).is_ok() {
            return Err(Error::engine(
                "current body read lost its owned SQL session",
            ));
        }
        let mut tx = db.pool().begin().await?;
        kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
        let identity = kernel::read_cache::key_on(&mut tx, actor, "read_snapshot").await?;
        let result = kernel::read_cache::in_pinned_snapshot(
            identity,
            kernel::read_cache::connection_id(&mut tx),
            work(&mut tx),
        )
        .await;
        tx.rollback().await?;
        result
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LinkScope {
    All,
    PartOf,
    Renderers,
}

#[derive(Clone, Copy)]
enum ReadCandidates<'a> {
    Anchors(&'a [String]),
    Names(&'a [String]),
    /// Stage exactly the ids this query yields (still behind the ordinary
    /// visibility gate, plus direct placement dependencies), computed on the
    /// session's own connection after BEGIN so candidates and staging share
    /// one snapshot. A NULL row means "not narrowable here": full staging.
    ExactFrom {
        sql: &'a str,
        arg: &'a str,
    },
}

struct SessionStaging {
    link_scope: LinkScope,
    names: Option<Vec<String>>,
    anchors: Option<Vec<String>>,
    exact: Option<Vec<String>>,
    history: Option<HistoryWindow>,
    home_chain: bool,
}
impl SessionStaging {
    fn new(
        link_scope: LinkScope,
        candidates: Option<ReadCandidates<'_>>,
        exact: Option<Vec<String>>,
        history: Option<HistoryWindow>,
        home_chain: bool,
    ) -> Self {
        Self {
            link_scope,
            names: match candidates {
                Some(ReadCandidates::Names(ids)) => Some(ids.to_vec()),
                _ => None,
            },
            anchors: match candidates {
                Some(ReadCandidates::Anchors(ids)) => Some(ids.to_vec()),
                _ => None,
            },
            exact,
            history,
            home_chain,
        }
    }
    async fn install(
        &self,
        conn: &mut sqlx::SqliteConnection,
        db: &Db,
        actor: &str,
        reads: &BTreeSet<(String, String)>,
    ) -> Result<()> {
        let candidates = self
            .names
            .as_deref()
            .map(ReadCandidates::Names)
            .or_else(|| self.anchors.as_deref().map(ReadCandidates::Anchors));
        // Closure is structural candidate scope, retained even when the
        // independent demand evaluator is disabled for the retry.
        let mut plan = demand::current();
        plan.home_chain = self.home_chain;
        demand::scoped(
            plan,
            Box::pin(install_relations(
                conn,
                actor,
                reads,
                self.link_scope,
                candidates,
                self.history,
                None,
                self.exact.as_deref(),
                None,
                chrono::Utc::now().timestamp_millis(),
                false,
                None,
                db.sql_event_projection_generation(),
                db.sql_record_projection_generation().as_deref(),
            )),
        )
        .await
    }
}

async fn with_scoped_read_session<T>(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    link_scope: LinkScope,
    candidates: Option<ReadCandidates<'_>>,
    history_window: Option<HistoryWindow>,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    #[cfg(feature = "v2-kernel-probe")]
    if CURRENT_OWNED_SQL.try_with(|_| ()).is_ok() {
        return Err(Error::engine(
            "current body read refuses nested SQL materialization",
        ));
    }
    let session = open_scoped_session(
        db,
        actor,
        reads,
        link_scope,
        candidates,
        history_window,
        None,
    )
    .await?;
    let result = READ_SESSION.scope(session.clone(), work).await;
    // Roll back TEMP state explicitly on success/error; cancellation closes the
    // owned physical connection, so no TEMP state or VM guard can be borrowed.
    let mut session = session.lock().await;
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    read_diagnostics::observe_session(&mut session.connection, "before_rollback", None).await;
    #[cfg(test)]
    {
        let probe = session.cost_probe.take();
        read_cost::detach(&mut session.connection, probe).await?;
    }
    rollback_read_session(&mut session.connection).await?;
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    read_diagnostics::observe_session(&mut session.connection, "after_rollback", None).await;
    session.connection.finish().await;
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    {
        let reusable = session.connection.reusable_for_diagnostic();
        read_diagnostics::observe_session(&mut session.connection, "after_finish", Some(reusable))
            .await;
    }
    result
}

/// SQLITE_INTERRUPT during a TEMP write can roll back the whole transaction.
/// Consult SQLite itself before cleanup; the original interrupted read must
/// not be replaced by a second rollback's "no transaction is active" error.
async fn rollback_read_session(conn: &mut sqlx::SqliteConnection) -> Result<()> {
    let active = {
        let mut handle = conn.lock_handle().await?;
        handle.remove_progress_handler();
        // SAFETY: this locked handle is exclusively borrowed and live.
        unsafe { libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()) == 0 }
    };
    if active {
        sqlx::query("ROLLBACK").execute(conn).await?;
    }
    Ok(())
}

async fn open_scoped_session(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    link_scope: LinkScope,
    candidates: Option<ReadCandidates<'_>>,
    history_window: Option<HistoryWindow>,
    current_caller: Option<&super::Caller>,
) -> Result<std::sync::Arc<tokio::sync::Mutex<ReadSession>>> {
    let home_chain = demand::current().home_chain;
    let (result, attempted, _) = demand::attempt(Box::pin(open_scoped_session_once(
        db,
        actor,
        reads,
        link_scope,
        candidates,
        history_window,
        current_caller,
        home_chain,
    )))
    .await;
    if attempted && result.is_err() {
        #[cfg(test)]
        let _ = STATS.try_with(|s| s.borrow_mut().demand_fallbacks += 1);
        return demand::with_legacy(Box::pin(open_scoped_session_once(
            db,
            actor,
            reads,
            link_scope,
            candidates,
            history_window,
            current_caller,
            home_chain,
        )))
        .await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn open_scoped_session_once(
    db: &Db,
    actor: &str,
    reads: &[(&str, &str)],
    link_scope: LinkScope,
    candidates: Option<ReadCandidates<'_>>,
    history_window: Option<HistoryWindow>,
    current_caller: Option<&super::Caller>,
    home_chain: bool,
) -> Result<std::sync::Arc<tokio::sync::Mutex<ReadSession>>> {
    // Retain the governed slot, not an ordinary write-pool slot: enrichment
    // borrows ordinary connections too. Concurrent batches must not each hold
    // one ordinary slot while all wait for a second one.
    let queued = Instant::now();
    let mut connection = connection::ReadConnection::new(db.governed_pool().acquire().await?);
    tracing::debug!(target: "native_ce::read_staging", phase = "composed_pool_wait", elapsed_us = queued.elapsed().as_micros() as u64);
    #[cfg(test)]
    let _ = STATS.try_with(|s| s.borrow_mut().pool_wait_us += queued.elapsed().as_micros() as u64);
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    read_diagnostics::observe_session(&mut connection, "acquire_before_begin", None).await;
    #[cfg(test)]
    let cost_probe = read_cost::attach(&mut connection).await?;
    sqlx::query("BEGIN").execute(&mut *connection).await?;
    let actual_actor;
    let actor = if let Some(caller) = current_caller {
        actual_actor = super::principal_on(&mut connection, caller).await?;
        &actual_actor
    } else {
        actor
    };
    kernel::app_installs::admit_dispatched_on(&mut connection, actor).await?;
    if current_caller.is_some_and(|caller| caller.host_asserted_app().is_some())
        || (current_caller.is_some() && crate::provenance::current_app_claim().is_some())
    {
        return Err(Error::engine("current body read: installed-app same-snapshot data-needs qualification is not supported"));
    }
    let as_of_seq = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events")
        .fetch_one(&mut *connection)
        .await?;
    let reads: BTreeSet<_> = reads
        .iter()
        .map(|(r, c)| (r.to_string(), c.to_string()))
        .collect();
    let started = Instant::now();
    let budget = Duration::from_millis(contract::QUERY_DEADLINE_MS);
    #[cfg(test)]
    let budget = read_cost::budget(budget);
    #[cfg(test)]
    let staging_progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    read_diagnostics::register_progress(&staging_progress);
    #[cfg(test)]
    let _measurement = ComposedStagingMeasurement {
        started,
        progress: staging_progress.clone(),
    };
    {
        let mut handle = connection.lock_handle().await?;
        // SQLite executes this callback on its worker, outside the async
        // task's tracing context. Carry only the bounded bootstrap attempt
        // span, so an actual guard expiry can be distinguished from another
        // interruption source when bootstrap's phase subsequently fails.
        let bootstrap_span = tracing::Span::current();
        let bootstrap_attempt = bootstrap_span
            .metadata()
            .is_some_and(|m| m.target() == "native_ce::bootstrap");
        #[cfg(test)]
        let staging_progress = staging_progress.clone();
        let mut vm_deadline = guard_diagnostics::VmDeadline::new(
            started,
            budget,
            guard_diagnostics::Stage::ComposedStaging,
        );
        handle.set_progress_handler(guard::PROGRESS_OPS, move || {
            #[cfg(test)]
            staging_progress.fetch_add(
                guard::PROGRESS_OPS as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            let (permit, elapsed) = vm_deadline.evaluate();
            if !permit && bootstrap_attempt {
                bootstrap_span.in_scope(|| {
                    tracing::warn!(target: "native_ce::bootstrap", stage = "composed_staging", pool = "governed", interrupt_source = "vm_deadline", elapsed_ms = elapsed.as_millis() as u64, budget_ms = contract::QUERY_DEADLINE_MS, "bootstrap staging guard expired");
                });
            }
            permit
        });
    }
    sqlx::query("SAVEPOINT demand_stage")
        .execute(&mut *connection)
        .await?;
    let cache_identity =
        kernel::read_cache::key_on(&mut connection, actor, "pinned_snapshot").await?;
    let admission_cache = std::sync::Arc::<kernel::app_installs::ReadAdmissions>::default();
    let (candidates, exact): (Option<ReadCandidates<'_>>, Option<Vec<String>>) = match candidates {
        Some(ReadCandidates::ExactFrom { sql, arg }) => {
            let rows: Vec<Option<String>> = sqlx::query_scalar(sql)
                .bind(arg)
                .fetch_all(&mut *connection)
                .await?;
            if rows.iter().any(Option::is_none) {
                guard_diagnostics::mark_selected_plan_staged_in_full();
                (None, None)
            } else {
                (None, Some(rows.into_iter().flatten().collect()))
            }
        }
        other => (other, None),
    };
    let staging = SessionStaging::new(link_scope, candidates, exact, history_window, home_chain);
    kernel::read_cache::in_pinned_snapshot_with_admissions(
        cache_identity.clone(),
        kernel::read_cache::connection_id(&mut connection),
        admission_cache.clone(),
        visible_cache::scoped(db, staging.install(&mut connection, db, actor, &reads)),
    )
    .await?;
    Box::pin(materialize_composed_records(&mut connection, &reads)).await?;
    if started.elapsed() >= budget {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "SQL relation staging exceeded query deadline",
        ));
    }
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    read_diagnostics::observe_session(&mut connection, "after_staging", None).await;
    #[cfg(test)]
    {
        drop(_measurement);
        read_cost::staged(&mut connection, &cost_probe).await?;
    }
    Ok(std::sync::Arc::new(tokio::sync::Mutex::new(ReadSession {
        #[cfg(test)]
        cost_probe,
        db: db.clone(),
        actor: actor.into(),
        connection,
        reads,
        as_of_seq,
        cache_identity,
        admission_cache,
        demand_enabled: demand::served(),
        staging,
        staging_failure: None,
    })))
}

async fn materialize_composed_records(
    connection: &mut sqlx::SqliteConnection,
    reads: &BTreeSet<(String, String)>,
) -> Result<()> {
    let materialization_started = Instant::now();
    // Composed enrichment consumes a closed metadata column set many times.
    // Materialize it once and index filing; otherwise each child count would
    // reevaluate lazy placement for every visible record, despite shared ACLs.
    let record_columns = reads
        .iter()
        .filter(|(r, c)| r == "records" && !c.is_empty())
        .map(|(_, c)| c.as_str())
        .collect::<Vec<_>>();
    if !record_columns.is_empty() {
        if record_columns
            .iter()
            .any(|c| !columns("records").unwrap().contains(c))
        {
            return Err(Error::engine("invalid composed record column"));
        }
        // Display values may be needed only for a bounded returned page.
        // Keep them lazy instead of decoding them for every visible record;
        // predicates still evaluate them through the same snapshot's view.
        let lazy_pages = record_columns.contains(&"id");
        let lazy = |column: &&str| {
            lazy_pages && ["name", "body", "created_at", "created_at_ms"].contains(column)
        };
        let eager_columns = record_columns
            .iter()
            .copied()
            .filter(|c| !lazy(c))
            .collect::<Vec<_>>();
        sqlx::query(&format!(
            "CREATE TEMP TABLE _v2_composed_records AS SELECT {} FROM temp.records",
            eager_columns.join(",")
        ))
        .persistent(false)
        .execute(&mut *connection)
        .await?;
        let projection = record_columns
            .iter()
            .map(|column| {
                if lazy(column) {
                    // Bodies are never cached. Looking through the cache UNION
                    // lets SQLite build an automatic covering index of every
                    // visible body before applying this id, under the caller's
                    // SQL cell ceiling. Use the same visible-id oracle directly.
                    let source = if *column == "body" {
                        "_v2_record_oracle"
                    } else {
                        "_v2_record_values"
                    };
                    format!("(SELECT v.{column} FROM temp.{source} v WHERE v.id=c.id) AS {column}")
                } else {
                    format!("c.{column}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query(&format!("DROP VIEW temp.records; CREATE TEMP VIEW records AS SELECT {projection} FROM temp._v2_composed_records c"))
            .persistent(false).execute(&mut *connection).await?;
        if record_columns.contains(&"type") && record_columns.contains(&"kind") {
            sqlx::query("CREATE INDEX _v2_composed_kind ON _v2_composed_records(type,kind)")
                .execute(&mut *connection)
                .await?;
        }
        for column in ["id", "home_id"] {
            if record_columns.contains(&column) {
                sqlx::query(&format!(
                    "CREATE INDEX _v2_composed_{column} ON _v2_composed_records({column})"
                ))
                .persistent(false)
                .execute(&mut *connection)
                .await?;
            }
        }
    }

    tracing::debug!(target: "native_ce::read_staging", phase = "composed_records", elapsed_us = materialization_started.elapsed().as_micros() as u64);
    Ok(())
}

#[derive(Clone)]
struct PreparedRead {
    statement: String,
    persistent: bool,
    parameters: Vec<contract::QuerySqlParameter>,
    output_columns: Vec<String>,
    now_ms_ms: Option<i64>,
    time_dependent: bool,
    assumed_order: Option<contract::AssumedOrder>,
}

/// A conservative closed prefix: no caller predicate, expression, alias,
/// join, offset or alternate ordering may move through the visibility barrier.
/// Narrow only the admitted ID prefix; caller SQL still reads a materialized
/// visible relation and retains its own LIMIT and SQL value/error guards.
fn id_ordered_record_limit(statement: &str) -> Option<i64> {
    static PREFIX: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let captures = PREFIX.get_or_init(|| regex::Regex::new(r"(?i)\A\s*SELECT\s+(?:id|name)(?:\s*,\s*(?:id|name))*\s+FROM\s+records\s+ORDER\s+BY\s+id(?:\s+ASC)?\s+LIMIT\s+([0-9]+)\s*;?\s*\z").expect("closed record prefix")).captures(statement)?;
    captures[1]
        .parse::<i64>()
        .ok()
        .filter(|n| (1..=1000).contains(n))
}

/// Only the shell's closed revision/metadata pulses can push its ID set through staging.
/// The caller statement still runs unchanged over the same live visibility gate.
/// Every other expression, relation, alias or predicate falls back to full staging.
fn metadata_pulse_ids(
    statement: &str,
    parameters: &[contract::QuerySqlParameter],
) -> Option<Vec<String>> {
    static PULSE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let captures = PULSE.get_or_init(|| regex::Regex::new(
        r"(?i-u)\A\s*SELECT\s+(?:id\s*,\s*updated_at|id\s*,\s*type\s*,\s*kind\s*,\s*name\s*,\s*summary\s*,\s*home_id\s*,\s*lifecycle\s*,\s*maturity\s*,\s*updated_at\s*,\s*last_activity_at)\s+FROM\s+records\s+WHERE\s+(?:deleted_at\s+IS\s+NULL\s+AND\s+)?id\s+IN\s*\(\s*(\?[1-9][0-9]*(?:\s*,\s*\?[1-9][0-9]*)*)\s*\)\s*;?\s*\z"
    ).expect("closed metadata pulse")).captures(statement)?;
    let mut ids = BTreeSet::new();
    for placeholder in captures[1].split(',') {
        let index = placeholder
            .trim()
            .strip_prefix('?')?
            .parse::<usize>()
            .ok()?;
        match parameters.get(index.checked_sub(1)?)? {
            contract::QuerySqlParameter::Text { value: Some(id) } => {
                ids.insert(id.clone());
            }
            contract::QuerySqlParameter::Text { value: None } => {}
            _ => return None,
        }
    }
    Some(ids.into_iter().collect())
}

pub(crate) async fn query_sql(db: &Db, actor: &str, args: Value) -> Result<Value> {
    execute(db, actor, args, false)
        .await
        .map_err(contract::ensure_categorized)
}

/// Only executor ad-hoc dispatch carries a trusted serving catalogue. Internal
/// composed reads and saved definitions keep the ordinary entry point above.
pub(super) async fn query_sql_for_caller(
    db: &Db,
    actor: &str,
    caller: &super::Caller,
    args: Value,
) -> Result<Value> {
    execute_with_catalog(db, actor, args, false, caller.catalog_operations())
        .await
        .map_err(contract::ensure_categorized)
}
/// Called only after inspection of an existing governed definition and its
/// artifact port pins. Ordinary callers cannot select the stored SQL allowance.
pub(super) async fn query_stored_saved_sql(db: &Db, actor: &str, args: Value) -> Result<Value> {
    // Trusted saved definitions may race transient VM/staging contention. Retry
    // once, with the original per-attempt budget and a new authority snapshot.
    // Ad hoc SQL and every non-timeout refusal retain their existing behavior.
    match stored_attempt(db, actor, args.clone()).await {
        Err(error) if is_timeout(&error) => stored_attempt(db, actor, args).await,
        result => result,
    }
}

fn is_timeout(error: &Error) -> bool {
    error.to_string().starts_with("query_sql [timeout]")
}

// Only a pinned saved definition or a freshly admitted installed-app dispatch
// can use this preparation allowance. Visibility/provenance staging is adapter work;
// it must not consume the v1 caller SQL VM budget. Both phases remain bounded.
const NATIVE_INPUT_STAGING_MS: u64 = 4 * contract::QUERY_DEADLINE_MS;

#[cfg(test)]
tokio::task_local! {
    static TEST_ELAPSED: (Duration, Duration);
}

#[cfg(test)]
pub(crate) async fn with_elapsed<T>(
    staging: Duration,
    caller_vm: Duration,
    work: impl std::future::Future<Output = T>,
) -> T {
    TEST_ELAPSED.scope((staging, caller_vm), work).await
}

async fn stored_attempt(db: &Db, actor: &str, args: Value) -> Result<Value> {
    #[cfg(test)]
    if STORED_TIMEOUT_TEST
        .try_with(|state| {
            let mut state = state.borrow_mut();
            state.attempts += 1;
            let timeout = state.remaining > 0;
            state.remaining = state.remaining.saturating_sub(1);
            timeout
        })
        .unwrap_or(false)
    {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "injected stored query deadline",
        ));
    }
    execute(db, actor, args, true)
        .await
        .map_err(contract::ensure_categorized)
}

#[cfg(test)]
struct StoredTimeoutTest {
    remaining: usize,
    attempts: usize,
}
#[cfg(test)]
tokio::task_local! { static STORED_TIMEOUT_TEST: std::cell::RefCell<StoredTimeoutTest>; }
#[cfg(test)]
pub(crate) async fn with_stored_timeouts<T>(
    remaining: usize,
    work: impl std::future::Future<Output = T>,
) -> (T, usize) {
    STORED_TIMEOUT_TEST
        .scope(
            std::cell::RefCell::new(StoredTimeoutTest {
                remaining,
                attempts: 0,
            }),
            async {
                let result = work.await;
                (
                    result,
                    STORED_TIMEOUT_TEST.with(|state| state.borrow().attempts),
                )
            },
        )
        .await
}

// Shared parser, statement guard, parameter binding and clock rewriting for
// ordinary reads and effect membership on the caller's writer snapshot.
fn prepare_read(
    actor: &str,
    args: Value,
    stored: bool,
) -> Result<(PreparedRead, BTreeSet<(String, String)>)> {
    prepare_read_with_views(actor, args, stored, None)
}

fn prepare_read_with_views(
    actor: &str,
    args: Value,
    stored: bool,
    registry: Option<&named_views::Registry>,
) -> Result<(PreparedRead, BTreeSet<(String, String)>)> {
    let validators = registry.and_then(|r| r.validators.as_ref());
    let request: contract::QuerySqlRequest = parse("query_sql", args).map_err(|error| {
        contract::categorized_error(
            contract::QuerySqlErrorCategory::InvalidArguments,
            error.to_string(),
        )
    })?;
    request.validate()?;
    if crate::query::turso_ast_rules::named_view_references(&request.sql)
        .is_ok_and(|r| r.iter().any(|n| n.starts_with("_native_view_")))
    {
        return Err(Error::engine(
            "internal named-view aliases are not caller relations",
        ));
    }

    let profile = contract::QuerySqlProfile::SqliteLocal;
    let (statement, assumed_order, reads, output_columns) = if stored {
        let statement = contract::classify_stored_saved_sql(profile, &request.sql)?;
        let (reads, labels) = match validators {
            Some(v) => v.inspect_saved(&statement)?,
            None => guard::inspect_kernel_v2_stored_saved_sql(&statement)?,
        };
        (statement, None, reads, labels)
    } else {
        let statement = contract::classify_sqlite_ad_hoc_statement(&request.sql)?;
        let (statement, assumed_order) = match validators {
            Some(v) => v.default_order(&statement)?,
            None => guard::apply_kernel_v2_default_order(&statement)?,
        };
        let (reads, labels) = match validators {
            Some(v) => v.inspect(&statement)?,
            None => {
                let reads = guard::public_reads_ad_hoc(&statement)?;
                guard::validate_kernel_v2_ad_hoc(&statement)?;
                (
                    reads,
                    guard::validated_kernel_v2_output_columns(&statement)?,
                )
            }
        };
        (statement, assumed_order, reads, labels)
    };
    let activity_clock = reads
        .iter()
        .any(|(relation, _)| relation == "agent_activity");
    for (relation, column) in &reads {
        if let Some(view) = registry.and_then(|r| r.views.get(relation)) {
            if !column.is_empty()
                && !view
                    .definition
                    .output
                    .columns
                    .iter()
                    .any(|c| c.name == *column)
            {
                return Err(unsupported(relation, column));
            }
            continue;
        }
        if let Some(node) = registry
            .and_then(|r| r.retained.as_ref())
            .and_then(|p| p.nodes.iter().find(|n| &n.alias == relation))
        {
            if !column.is_empty()
                && !node
                    .definition
                    .query
                    .output
                    .columns
                    .iter()
                    .any(|c| &c.name == column)
            {
                return Err(unsupported(relation, column));
            }
            continue;
        }
        let Some(supported) = columns(relation) else {
            return Err(unsupported(relation, ""));
        };
        if !column.is_empty() && !supported.contains(&column.as_str()) {
            return Err(unsupported(relation, column));
        }
    }
    if output_columns.len() > contract::MAX_COLUMNS {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::ResultTooLarge,
            "result exceeds column limit",
        ));
    }
    let mut unique = BTreeSet::new();
    if let Some(duplicate) = output_columns
        .iter()
        .find(|label| !unique.insert(label.as_str()))
    {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::DuplicateColumns,
            format!("duplicate output column label '{duplicate}'"),
        ));
    }
    contract::check_positional_arguments(profile, &statement, request.parameters.len())?;
    contract::validate_regexp_bound_patterns(profile, &statement, &request.parameters)?;
    if !stored {
        contract::validate_ad_hoc_clock_bound_args(profile, &statement, &request.parameters)?;
    }
    contract::validate_utc_date_label_bound_args(profile, &statement, &request.parameters)?;
    let (statement, clock_uses) = contract::rewrite_now_ms_calls(
        profile,
        &statement,
        &format!("?{}", request.parameters.len() + 1),
    )?;
    let now_ms_ms =
        (clock_uses > 0 || activity_clock).then(|| chrono::Utc::now().timestamp_millis());
    let (statement, principal_uses) = contract::rewrite_current_principal_calls(
        profile,
        &statement,
        &format!(
            "?{}",
            request.parameters.len() + 1 + usize::from(clock_uses > 0)
        ),
    )?;
    let (statement, _) = contract::rewrite_utc_date_label_calls(
        profile,
        &statement,
        contract::UtcDateLabelEngine::Sqlite,
    )?;
    let mut parameters = request.parameters;
    if let Some(now) = now_ms_ms.filter(|_| clock_uses > 0) {
        parameters.push(contract::QuerySqlParameter::Integer {
            value: Some(now.to_string()),
        });
    }
    if principal_uses > 0 {
        parameters.push(contract::QuerySqlParameter::Text {
            value: Some(actor.into()),
        });
    }
    contract::check_positional_arguments(profile, &statement, parameters.len())?;

    let prepared = PreparedRead {
        statement,
        persistent: registry.is_none(),
        parameters,
        output_columns,
        now_ms_ms,
        time_dependent: clock_uses > 0 || activity_clock,
        assumed_order,
    };
    Ok((prepared, reads))
}

/// Guarded SQL on the already admitted writer snapshot. TEMP staging is scoped
/// to a savepoint and discarded before any kernel mutation; invocation SQL is
/// never accepted by the caller of this seam.
/// Cancellation drops the enclosing write transaction. The write pool's
/// sanitize_released_write_connection removes progress handlers and closes
/// connections with unrolled-back transactions before reuse.
/// Relations a folder-scoped app may read through `query_sql`: every row
/// is staged from the folder-filtered visible set, plus the two pure
/// schema catalogues (names/types only, no record data). Anything else
/// — runs, intents, activity, messaging state, vocabularies, bindings,
/// named views — refuses `outside_app_scope` rather than silently
/// staging person-level rows.
const SCOPED_SQL_RELATIONS: [&str; 11] = [
    "records",
    "links",
    "blobs",
    "facet_values",
    "facet_observations",
    "facet_times",
    "record_lifecycle_interpretations",
    "comment_anchors",
    "content_events",
    "catalog_relations",
    "catalog_columns",
];

/// Whether this dispatch is a folder-scoped app for `actor`, resolved on
/// the caller's own snapshot.
#[inline(never)]
fn scoped_app_folders_on<'a>(
    conn: &'a mut sqlx::SqliteConnection,
    actor: &'a str,
) -> futures::future::BoxFuture<'a, Result<bool>> {
    Box::pin(async move {
        Ok(
            match kernel::app_installs::scope::active_scope_cached(actor) {
                kernel::app_installs::scope::ActiveScope::None => false,
                kernel::app_installs::scope::ActiveScope::Known(scope) => scope.is_scoped(),
                kernel::app_installs::scope::ActiveScope::Unresolved(_) => {
                    kernel::app_installs::scope::active_scope_on(conn, actor)
                        .await?
                        .is_some_and(|scope| scope.is_scoped())
                }
            },
        )
    })
}

/// Refuse user SQL that reaches any relation outside the scoped allowlist.
async fn refuse_out_of_scope_relations(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    reads: &BTreeSet<(String, String)>,
) -> Result<()> {
    if !scoped_app_folders_on(conn, actor).await? {
        return Ok(());
    }
    if reads
        .iter()
        .any(|(relation, _)| !SCOPED_SQL_RELATIONS.contains(&relation.as_str()))
    {
        return Err(Error::engine(kernel::OUTSIDE_APP_SCOPE));
    }
    Ok(())
}

pub(super) async fn query_sql_on(
    connection: &mut sqlx::SqliteConnection,
    actor: &str,
    args: Value,
    row_limit: usize,
) -> Result<Value> {
    let (prepared, reads) = prepare_read(actor, args, false)?;
    refuse_out_of_scope_relations(connection, actor, &reads).await?;
    let was_query_only: bool = sqlx::query_scalar("PRAGMA query_only")
        .fetch_one(&mut *connection)
        .await?;
    sqlx::query("SAVEPOINT v2_effect_read")
        .execute(&mut *connection)
        .await?;
    let started = Instant::now();
    connection
        .lock_handle()
        .await?
        .set_progress_handler(guard::PROGRESS_OPS, move || {
            started.elapsed() < Duration::from_millis(contract::QUERY_DEADLINE_MS)
        });
    let outcome = async {
        install(connection, actor, &reads).await?;
        let seq = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events")
            .fetch_one(&mut *connection)
            .await?;
        execute_prepared_mode(
            connection,
            prepared,
            seq,
            Instant::now(),
            true,
            row_limit.clamp(1, contract::MAX_ROWS),
        )
        .await
    }
    .await;
    connection.lock_handle().await?.remove_progress_handler();
    // Restore even on a statement error, before the enclosing native effect
    // writes. Cancellation drops its transaction; pool release sanitizes the
    // connection (or discards it) before another request can use it.
    let reset = sqlx::query(if was_query_only {
        "PRAGMA query_only=ON"
    } else {
        "PRAGMA query_only=OFF"
    })
    .execute(&mut *connection)
    .await;
    let cleanup = sqlx::query("ROLLBACK TO v2_effect_read; RELEASE v2_effect_read")
        .execute(connection)
        .await;
    reset?;
    cleanup?;
    outcome
}

async fn execute(db: &Db, actor: &str, args: Value, stored: bool) -> Result<Value> {
    execute_with_catalog(db, actor, args, stored, None).await
}

async fn execute_with_catalog(
    db: &Db,
    actor: &str,
    args: Value,
    stored: bool,
    catalogue: Option<&crate::query::principal::CatalogOperationsSnapshot>,
) -> Result<Value> {
    let (result, attempted, caller_started) = demand::attempt(Box::pin(execute_with_catalog_once(
        db,
        actor,
        args.clone(),
        stored,
        catalogue,
    )))
    .await;
    if attempted
        && result
            .as_ref()
            .is_err_and(|error| !caller_started || demand::retry_caller(error))
    {
        #[cfg(test)]
        let _ = STATS.try_with(|s| s.borrow_mut().demand_fallbacks += 1);
        return demand::with_legacy(Box::pin(execute_with_catalog_once(
            db, actor, args, stored, catalogue,
        )))
        .await;
    }
    result
}

async fn execute_with_catalog_once(
    db: &Db,
    actor: &str,
    args: Value,
    stored: bool,
    catalogue: Option<&crate::query::principal::CatalogOperationsSnapshot>,
) -> Result<Value> {
    let pinned = if stored {
        args.get("_named_view_pins").cloned().map(serde_json::from_value::<std::collections::BTreeMap<String,crate::named_views::Pin>>).transpose()?
    } else {
        None
    };
    let mut args = args;
    if stored {
        args.as_object_mut()
            .ok_or_else(|| Error::engine("query arguments must be an object"))?
            .remove("_named_view_pins");
    }
    if pinned.is_some()
        && (db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite
            || READ_SESSION.try_with(|_| ()).is_ok())
    {
        return Err(Error::engine(
            "view_profile_unsupported: exact views require standalone hosted writer reads",
        ));
    }
    let request_started = Instant::now();
    let preflight = prepare_read(actor, args.clone(), stored);
    if preflight
        .as_ref()
        .is_ok_and(|(_, reads)| reads.iter().any(|(r, _)| r == "catalog_operations"))
        && (catalogue.is_none() || stored || READ_SESSION.try_with(|_| ()).is_ok())
    {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::UnauthorizedRelation,
            "catalog_operations requires this server's serving executor catalogue in standalone executor ad-hoc query_sql; saved SQL, internal reads and member/offline copies cannot supply it",
        ));
    }
    if preflight
        .as_ref()
        .is_ok_and(|(_, reads)| reads.iter().any(|(r, _)| r == "catalog_view_definitions"))
        && (db.open_mode() != crate::db::DatabaseOpenMode::ReadWrite
            || READ_SESSION.try_with(|_| ()).is_ok())
    {
        return Err(Error::engine("view_profile_unsupported: catalog_view_definitions requires standalone hosted writer reads"));
    }
    if stored
        && preflight
            .as_ref()
            .is_ok_and(|(_, reads)| reads.iter().any(|(r, _)| r == "catalog_view_definitions"))
    {
        return Err(Error::engine("saved governed SQL cannot read 'catalog_view_definitions': caller-relative detail rows require standalone hosted ad-hoc query_sql"));
    }
    let registry_needed = (!stored || pinned.is_some())
        && db.open_mode() == crate::db::DatabaseOpenMode::ReadWrite
        && (pinned.as_ref().is_some_and(|pins| !pins.is_empty())
            || named_views::needed(&preflight, &args));
    // Preserve the original early refusal and all narrowing on static reads.
    let preflight = match preflight {
        Err(error) if !registry_needed => return Err(error),
        other => other,
    };
    if let Ok(session) = READ_SESSION.try_with(Clone::clone) {
        let (prepared, reads) = preflight?;
        let mut session = session.lock().await;
        if !session.db.same_handle(db) || session.actor != actor {
            return Err(Error::engine("composed SQL read caller/database differs"));
        }
        if let Some(error) = &session.staging_failure {
            return Err(Error::engine(error.clone()));
        }
        if reads.iter().any(|(r, c)| {
            !session.reads.contains(&(r.clone(), c.clone()))
                && !(c.is_empty() && session.reads.iter().any(|(sr, _)| sr == r))
        }) {
            return Err(Error::engine(
                "composed SQL read exceeds declared relations/columns",
            ));
        }
        // Composed SQL (declared app-data reads, subscriptions) returns
        // early, before the standalone path's allowlist check. A folder-
        // scoped app must meet the same relation allowlist here, or a
        // declaration naming e.g. `run_intents` would bypass it.
        refuse_out_of_scope_relations(&mut session.connection, actor, &reads).await?;
        let as_of_seq = session.as_of_seq;
        let started = Instant::now();
        let result = execute_prepared(
            &mut session.connection,
            prepared.clone(),
            as_of_seq,
            started,
        )
        .await;
        #[cfg(test)]
        let result = if session.demand_enabled && demand::fail_caller() {
            demand::injected_caller_error(&mut session.connection).await
        } else {
            result
        };
        let result = if session.demand_enabled && result.as_ref().is_err_and(demand::retry_caller) {
            #[cfg(test)]
            let _ = STATS.try_with(|s| s.borrow_mut().demand_fallbacks += 1);
            // Poison BEFORE the first destructive/fallible step. This also
            // fences later uses if the retry future is cancelled mid-restage.
            session.staging_failure =
                Some("query_sql [engine]: composed SQL restaging was interrupted".into());
            session.demand_enabled = false;
            let restaged = Box::pin(async {
                // Caller SELECT errors cannot commit or mutate main. Restaging
                // TEMP data from before installation preserves the pinned snapshot.
                session
                    .connection
                    .lock_handle()
                    .await?
                    .remove_progress_handler();
                sqlx::query("PRAGMA query_only=OFF; ROLLBACK TO demand_stage")
                    .execute(&mut *session.connection)
                    .await?;
                let started = Instant::now();
                let budget = Duration::from_millis(contract::QUERY_DEADLINE_MS);
                #[cfg(test)]
                let budget = read_cost::budget(budget);
                let mut deadline = guard_diagnostics::VmDeadline::new(
                    started,
                    budget,
                    guard_diagnostics::Stage::ComposedStaging,
                );
                session
                    .connection
                    .lock_handle()
                    .await?
                    .set_progress_handler(guard::PROGRESS_OPS, move || deadline.evaluate().0);
                let ReadSession {
                    connection,
                    db,
                    reads,
                    cache_identity,
                    admission_cache,
                    staging,
                    ..
                } = &mut *session;
                demand::with_legacy(kernel::read_cache::in_pinned_snapshot_with_admissions(
                    cache_identity.clone(),
                    kernel::read_cache::connection_id(connection),
                    admission_cache.clone(),
                    async {
                        visible_cache::scoped(db, staging.install(connection, db, actor, reads))
                            .await?;
                        #[cfg(test)]
                        if demand::fail_restage() {
                            sqlx::query("DELETE FROM temp._v2_visible")
                                .execute(&mut **connection)
                                .await?;
                            let error =
                                demand::injected_caller_error(connection).await.unwrap_err();
                            return Err(match error {
                                Error::Sqlx(error) => guard::map_stream_error(error),
                                other => other,
                            });
                        }
                        Box::pin(materialize_composed_records(connection, reads)).await?;
                        if started.elapsed() >= budget {
                            return Err(contract::categorized_error(
                                contract::QuerySqlErrorCategory::Timeout,
                                "SQL relation staging exceeded query deadline",
                            ));
                        }
                        Ok::<_, Error>(())
                    },
                ))
                .await?;
                Ok::<_, Error>(())
            })
            .await;
            if let Err(error) = restaged {
                let error = contract::ensure_categorized(error);
                session.staging_failure = Some(error.to_string());
                return Err(error);
            }
            session.staging_failure = None;
            execute_prepared(&mut session.connection, prepared, as_of_seq, Instant::now()).await
        } else {
            result
        };
        tracing::debug!(target: "native_ce::read_staging", phase = "composed_caller", elapsed_us = started.elapsed().as_micros() as u64);
        return result;
    }

    // An ordinary pool slot, exclusively held and armed for physical close.
    // Only a verified clean rollback allows reuse; cancellation still closes.
    // A render may already hold a snapshot on the shared read pool. Use the
    // dedicated SQL tier so concurrent renders cannot exhaust that pool while
    // each waits for a second slot, and never borrow an ordinary writer slot.
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_validation", elapsed_us = request_started.elapsed().as_micros() as u64);
    let acquire_started = Instant::now();
    #[cfg(feature = "v2-kernel-probe")]
    if CURRENT_OWNED_SQL.try_with(|_| ()).is_ok() {
        return Err(Error::engine(
            "current body read lost its staged SQL session",
        ));
    }
    let mut connection = connection::ReadConnection::new(db.governed_pool().acquire().await?);
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_pool_wait", elapsed_us = acquire_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    let _ = STATS
        .try_with(|s| s.borrow_mut().pool_wait_us += acquire_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    let cost_probe = read_cost::attach(&mut connection).await?;
    let admission_started = Instant::now();
    let mut tx = sqlx::Connection::begin(&mut *connection).await?;
    let admitted_app = crate::kernel::app_installs::admit_dispatched_on(&mut tx, actor)
        .await?
        .is_some();
    let as_of_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM main.content_events")
        .fetch_one(&mut *tx)
        .await?;
    let registry_started = Instant::now();
    if registry_needed {
        tx.lock_handle()
            .await?
            .set_progress_handler(guard::PROGRESS_OPS, move || {
                admission_started.elapsed() < Duration::from_millis(contract::QUERY_DEADLINE_MS)
            });
    }
    let mut registry = if registry_needed {
        named_views::Registry::load_retained(
            &mut tx,
            actor,
            &args,
            pinned,
            admission_started + Duration::from_millis(contract::QUERY_DEADLINE_MS),
        )
        .await
        .map_err(named_views::map_setup_error)?
    } else {
        named_views::Registry::default()
    };
    #[cfg(test)]
    if registry_needed && !registry.views.is_empty() {
        if let Ok((arrived, resume)) = NAMED_READ_PAUSE.try_with(Clone::clone) {
            arrived.wait().await;
            resume.wait().await;
        }
    }
    if registry_needed && preflight.is_err() {
        registry.unavailable(&args)?;
    }
    let deadline = admission_started + Duration::from_millis(contract::QUERY_DEADLINE_MS);
    let (mut registry, mut prepared, reads) = if registry.retained.is_some() && preflight.is_err() {
        let worker_actor = actor.to_owned();
        crate::query::sql::view_validation::run(deadline, move || {
            registry.validators = Some(guard::NamedViewValidators::from_closure(
                registry.retained.as_ref().unwrap(),
            )?);
            let (prepared, mut reads) =
                prepare_read_with_views(&worker_actor, args, stored, Some(&registry))?;
            registry.expand(&mut reads)?;
            registry.validators = None;
            Ok((registry, prepared, reads))
        })
        .await?
    } else {
        let (prepared, mut reads) = if registry_needed
            && registry.retained.is_none()
            && (!registry.views.is_empty() || !registry.invalid.is_empty())
        {
            prepare_read_with_views(actor, args, stored, Some(&registry))?
        } else {
            preflight?
        };
        registry.expand(&mut reads)?;
        registry.validators = None;
        (registry, prepared, reads)
    };
    // Same snapshot as staging: refuse relations the folder scope does
    // not filter before any rows are staged for this statement.
    refuse_out_of_scope_relations(&mut tx, actor, &reads).await?;
    if reads.iter().any(|(r, _)| r == "agent_activity") {
        prepared
            .now_ms_ms
            .get_or_insert_with(|| chrono::Utc::now().timestamp_millis());
        prepared.time_dependent = true;
    }
    let view_bearing = !registry.selected.is_empty();
    if view_bearing {
        prepared.persistent = false;
    }
    let registry_elapsed = registry_started.elapsed();
    if registry_needed && registry_elapsed >= Duration::from_millis(contract::QUERY_DEADLINE_MS) {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "named view registry exceeded query deadline",
        ));
    }
    // Exclude pool queue delay. Ad hoc callers retain their shared deadline;
    // verified saved inputs and installed-app dispatches get separately bounded
    // native preparation. The app claim alone grants nothing: the receipt above
    // rechecks current account membership, source pins and consent on this read
    // snapshot. JSON arguments cannot create that internal dispatch context.
    let separate_staging = !view_bearing && (stored || admitted_app);
    let started = if registry_needed {
        admission_started
    } else {
        Instant::now() - registry_elapsed
    };
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_admission", elapsed_us = admission_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    let _ = STATS.try_with(|s| {
        s.borrow_mut().sql_admission_us += admission_started.elapsed().as_micros() as u64
    });
    #[cfg(test)]
    let started = started
        - TEST_ELAPSED
            .try_with(|elapsed| elapsed.0)
            .unwrap_or_default();
    let staging_budget = Duration::from_millis(if separate_staging {
        NATIVE_INPUT_STAGING_MS
    } else {
        contract::QUERY_DEADLINE_MS
    });
    #[cfg(test)]
    let staging_budget = read_cost::budget(staging_budget);
    #[cfg(test)]
    let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    {
        let mut handle = tx.lock_handle().await?;
        #[cfg(test)]
        let progress = progress.clone();
        handle.set_progress_handler(guard::PROGRESS_OPS, move || {
            #[cfg(test)]
            progress.fetch_add(
                guard::PROGRESS_OPS as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            started.elapsed() < staging_budget
        });
    }
    let mut plan = demand::plan_for(db);
    let pulse_ids = if view_bearing || record_scope::full_staging() {
        None
    } else {
        record_scope::ids_with(
            &prepared.statement,
            &prepared.parameters,
            &reads,
            plan.docs_page,
        )
        .map(|(ids, chain)| {
            plan.home_chain = chain;
            ids
        })
        .or_else(|| metadata_pulse_ids(&prepared.statement, &prepared.parameters))
    };
    let class_scope = if view_bearing || record_scope::full_staging() {
        None
    } else {
        record_classes::plan(&prepared.statement, &prepared.parameters, &reads)
    };
    // Keep original reads authoritative for validation, scope planning and
    // execution. Only population is reduced, in this admitted snapshot; the
    // unconditional TEMP schema still supports every original UNION arm.
    let section_reads = if admitted_app && !stored && !registry_needed && !view_bearing {
        union_sections::staging_reads(&prepared.statement, &prepared.parameters, &reads)
    } else {
        None
    };
    let staging_started = Instant::now();
    // Preserve benchmark diagnostics even if relation installation times out.
    #[cfg(test)]
    let staging_measurement = ComposedStagingMeasurement {
        started: staging_started,
        progress: progress.clone(),
    };
    demand::scoped_for_db(
        db,
        plan,
        event_scope::bound_scope(
            std::slice::from_ref(&prepared),
            visible_cache::scoped(
                db,
                install_relations(
                    &mut tx,
                    actor,
                    section_reads.as_ref().unwrap_or(&reads),
                    LinkScope::All,
                    None,
                    None,
                    if view_bearing || record_scope::full_staging() {
                        None
                    } else {
                        id_ordered_record_limit(&prepared.statement)
                    },
                    pulse_ids.as_deref(),
                    class_scope.as_ref(),
                    prepared
                        .now_ms_ms
                        .unwrap_or_else(|| chrono::Utc::now().timestamp_millis()),
                    !view_bearing,
                    catalogue,
                    db.sql_event_projection_generation(),
                    db.sql_record_projection_generation().as_deref(),
                ),
            ),
        ),
    )
    .await
    .map_err(|error| {
        let error = match error {
            crate::Error::Sqlx(error) => guard::map_stream_error(error),
            error => error,
        };
        if is_timeout(&error) {
            contract::categorized_error(
                contract::QuerySqlErrorCategory::Timeout,
                "SQL relation staging exceeded query deadline",
            )
        } else {
            error
        }
    })?;
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_staging", elapsed_us = staging_started.elapsed().as_micros() as u64);
    // A link join revisits record identity metadata once per edge. Decode the
    // caller's closed scalar column set once per visible record instead. Bodies
    // and other potentially large values retain their existing lazy path.
    let metadata_started = Instant::now();
    let joined_columns: Vec<_> = reads
        .iter()
        .filter(|(relation, column)| relation == "records" && !column.is_empty())
        .map(|(_, column)| column.as_str())
        .collect();
    if !view_bearing
        && reads.iter().any(|(relation, _)| relation == "links")
        && !joined_columns.is_empty()
        && joined_columns
            .iter()
            .all(|c| ["id", "type", "kind", "name"].contains(c))
    {
        sqlx::query(&format!(
            "CREATE TEMP TABLE _v2_joined_records AS SELECT {} FROM temp.records",
            joined_columns.join(",")
        ))
        .persistent(false)
        .execute(&mut *tx)
        .await?;
        if joined_columns.contains(&"id") {
            sqlx::query("CREATE INDEX temp._v2_joined_id ON _v2_joined_records(id)")
                .execute(&mut *tx)
                .await?;
        }
        let projection = columns("records")
            .expect("records contract")
            .iter()
            .map(|c| {
                if joined_columns.contains(c) {
                    format!("r.{c}")
                } else {
                    format!("NULL AS {c}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query(&format!("DROP VIEW temp.records; CREATE TEMP VIEW records AS SELECT {projection} FROM temp._v2_joined_records r"))
            .persistent(false).execute(&mut *tx).await?;
    }
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_join_metadata", elapsed_us = metadata_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    drop(staging_measurement);
    // Many individually small SQL statements (or provider decoding in Rust)
    // may never invoke the VM callback. They still consume the same budget.
    if started.elapsed() >= staging_budget {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "SQL relation staging exceeded query deadline",
        ));
    }
    let caller_started = if separate_staging {
        Instant::now()
    } else {
        started
    };
    registry
        .append_catalog(&mut tx, &reads)
        .await
        .map_err(named_views::map_setup_error)?;
    registry
        .register(&mut tx)
        .await
        .map_err(named_views::map_setup_error)?;
    #[cfg(test)]
    if !registry.views.is_empty() {
        if let Ok((arrived, resume)) = NAMED_REGISTER_PAUSE.try_with(Clone::clone) {
            arrived.wait().await;
            resume.wait().await;
        }
    }
    if started.elapsed() >= staging_budget {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::Timeout,
            "named view compilation exceeded query deadline",
        ));
    }
    #[cfg(test)]
    read_cost::staged(&mut tx, &cost_probe).await?;
    let execution_started = Instant::now();
    demand::caller_started();
    #[cfg(test)]
    if demand::served() && demand::fail_caller() {
        return demand::injected_caller_error(&mut tx).await;
    }
    let mut result = execute_prepared(&mut tx, prepared, as_of_seq, caller_started).await?;
    if !registry.generated_drift.is_empty() {
        result["view_provenance"] = json!({"generated_source_drift":registry.generated_drift,"generated_unknown_reason":registry.generated_unknown_reason});
    }
    if let Some(message) = registry.omission {
        result["notices"] = json!([{"code":"view_catalog_incomplete","message":message}]);
    }
    if let Some(plan) = &registry.retained {
        let static_relations: std::collections::BTreeMap<_, _> = reads
            .iter()
            .filter_map(|(name, _)| {
                contract::LOGICAL_RELATIONS
                    .iter()
                    .find(|r| r.name == name)
                    .map(|r| {
                        (
                            name.clone(),
                            json!({"identity":r.identity,"semantic_version":r.semantic_version}),
                        )
                    })
            })
            .collect();
        // Catalog candidates are discovery metadata, never dependencies of the
        // executed statement. Version/diagnostics come only from this closure.
        let drift: std::collections::BTreeMap<_, _> = plan
            .generated_drift
            .iter()
            .map(|(p, d)| (p.revision_id.clone(), *d))
            .collect();
        let reasons: std::collections::BTreeMap<_, _> = plan
            .generated_unknown_reason
            .iter()
            .map(|(p, r)| (p.revision_id.clone(), *r))
            .collect();
        let generated = plan.retained.values().any(|revision| revision.v == 2);
        let summaries = crate::named_views::receipt::generated_summaries(plan)?;
        result["view_provenance"] = json!({"roots":registry.pins,"closure_digest":plan.digest,"static_relations":static_relations,"has_generated_nodes":generated,"generated_diagnostics":summaries,"generated_source_drift":drift,"generated_unknown_reason":reasons});
    }
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_caller", elapsed_us = execution_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    read_cost::detach(&mut tx, cost_probe).await?;
    let cleanup_started = Instant::now();
    tx.rollback().await?;
    connection.finish().await;
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_cleanup", elapsed_us = cleanup_started.elapsed().as_micros() as u64);
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_total", elapsed_us = request_started.elapsed().as_micros() as u64);
    Ok(result)
}

async fn execute_prepared(
    connection: &mut sqlx::SqliteConnection,
    prepared: PreparedRead,
    as_of_seq: i64,
    started: Instant,
) -> Result<Value> {
    execute_prepared_mode(
        connection,
        prepared,
        as_of_seq,
        started,
        true,
        contract::MAX_ROWS,
    )
    .await
}

async fn execute_prepared_mode(
    connection: &mut sqlx::SqliteConnection,
    prepared: PreparedRead,
    as_of_seq: i64,
    started: Instant,
    query_only: bool,
    row_limit: usize,
) -> Result<Value> {
    #[cfg(test)]
    let _ = STATS.try_with(|s| s.borrow_mut().caller_executions += 1);
    let PreparedRead {
        statement,
        persistent,
        parameters,
        output_columns,
        now_ms_ms,
        time_dependent,
        assumed_order,
    } = prepared;
    #[cfg(test)]
    let started = started
        - TEST_ELAPSED
            .try_with(|elapsed| elapsed.1)
            .unwrap_or_default();
    let budget = Duration::from_millis(contract::QUERY_DEADLINE_MS);
    #[cfg(test)]
    let budget = read_cost::budget(budget);
    {
        let mut handle = connection.lock_handle().await?;
        handle.set_progress_handler(guard::PROGRESS_OPS, move || started.elapsed() < budget);
    }
    if query_only {
        sqlx::query("PRAGMA query_only=ON")
            .execute(&mut *connection)
            .await?;
    }
    let previous_value_limit = {
        let mut handle = connection.lock_handle().await?;
        // SAFETY: exclusive SQLite handle lock, connection never returns to pool.
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                guard::MAX_SQLITE_VALUE_BYTES,
            )
        }
    };
    let result = async {
        let capped = guard::cap_statement(&statement, row_limit as i64);
        #[cfg(test)]
        if !persistent {
            let _ = STATS.try_with(|s| s.borrow_mut().uncached_caller_statements += 1);
        }
        let query =
            guard::bind_parameters(sqlx::query(&capped).persistent(persistent), &parameters)?;
        #[cfg(test)]
        let prepare_started = Instant::now();
        #[cfg(test)]
        if read_cost::active() {
            use sqlx::Executor;
            (&mut *connection).prepare(&capped).await?;
            let _ = STATS.try_with(|s| {
                s.borrow_mut().caller_prepare_us += prepare_started.elapsed().as_micros() as u64
            });
        }
        #[cfg(test)]
        let execute_started = Instant::now();
        let mut stream = query.fetch(&mut *connection);
        let mut rows = Vec::new();
        let mut bytes = serde_json::to_vec(&output_columns)?.len() + 2;
        let mut truncated = false;
        while let Some(row) = stream.try_next().await.map_err(guard::map_stream_error)? {
            if rows.len() == row_limit {
                truncated = true;
                break;
            }
            let mut object = Map::new();
            for (index, column) in row.columns().iter().enumerate() {
                object.insert(column.name().into(), guard::json_cell(&row, index)?);
            }
            let value = Value::Object(object);
            bytes += serde_json::to_vec(&value)?.len() + 1;
            if bytes > contract::MAX_RESULT_ENCODED_BYTES {
                return Err(contract::categorized_error(
                    contract::QuerySqlErrorCategory::ResultTooLarge,
                    "encoded result exceeds byte limit",
                ));
            }
            rows.push(value);
        }
        drop(stream);
        #[cfg(test)]
        let _ = STATS.try_with(|s| {
            s.borrow_mut().caller_execute_us += execute_started.elapsed().as_micros() as u64
        });
        Ok(json!(contract::QuerySqlResult {
            columns: output_columns,
            row_count: rows.len(),
            rows,
            truncated,
            truncation_hint: contract::truncation_hint_for(truncated),
            as_of_seq,
            now_ms_ms,
            time_dependent,
            assumed_order,
        }))
    }
    .await;
    // SQL's cell ceiling must not persist into closed kernel hydration: an
    // ordinary Get may legitimately return a body larger than a SQL cell.
    // Cancellation discards this session's owned physical connection.
    {
        let mut handle = connection.lock_handle().await?;
        // SAFETY: the exclusive handle lock owns this connection.
        unsafe {
            libsqlite3_sys::sqlite3_limit(
                handle.as_raw_handle().as_ptr(),
                libsqlite3_sys::SQLITE_LIMIT_LENGTH,
                previous_value_limit,
            );
        }
    }
    result
}

#[cfg(test)]
#[derive(Default, Debug, serde::Serialize)]
pub(crate) struct Stats {
    pub demand_rechecked: u64,
    pub demand_recheck_rejections: u64,
    pub demand_fallbacks: u64,
    pub visibility_us: u64,
    pub caller_prepare_us: u64,
    pub caller_execute_us: u64,
    pub pool_wait_us: u64,
    pub sql_admission_us: u64,
    pub staging_vm_ops: u64,
    pub named_registry_loads: usize,
    pub uncached_caller_statements: usize,
    pub caller_executions: usize,
    pub staging_us: u64,
    pub installations: usize,
    pub record_projection_installations: usize,
    pub home_checks: usize,
    pub failed_homes: usize,
    pub staged_records: u64,
    pub staged_currency_records: u64,
    pub native_event_rows: u64,
    pub legacy_event_rows: u64,
    pub staged_metadata_records: u64,
    pub staged_relations: usize,
    pub provider_states_decoded: usize,
    pub invalid_facet_time_rows: usize,
    /// Shape served by demand-scoped visibility, or the fallback reason.
    pub demand: Option<&'static str>,
}
#[cfg(test)]
tokio::task_local! { static STATS: std::cell::RefCell<Stats>; }
// Record failed and successful staging alike. In particular a deadline error
// must not look like a request that performed no work.
#[cfg(test)]
struct ComposedStagingMeasurement {
    started: Instant,
    progress: std::sync::Arc<std::sync::atomic::AtomicU64>,
}
#[cfg(test)]
impl Drop for ComposedStagingMeasurement {
    fn drop(&mut self) {
        let _ = STATS.try_with(|s| {
            let mut stats = s.borrow_mut();
            stats.staging_us += self.started.elapsed().as_micros() as u64;
            stats.staging_vm_ops += self.progress.load(std::sync::atomic::Ordering::Relaxed);
        });
    }
}
#[cfg(test)]
pub(crate) async fn measured<T>(work: impl std::future::Future<Output = T>) -> (T, Stats) {
    STATS
        .scope(std::cell::RefCell::new(Stats::default()), async {
            let result = work.await;
            (result, STATS.with(|s| s.take()))
        })
        .await
}

// Values are scalar lookups driven ONLY by staged visible IDs. User predicates
// cannot reach a hidden value, even when SQLite pushes them through the view.
fn field(name: &str) -> String {
    format!("(SELECT json_extract(value_json,'$') FROM main.kernel_record_fields f WHERE f.record_id=r.id AND f.name='{name}')")
}
fn millis(expression: &str) -> String {
    format!("(CAST(strftime('%s',{expression}) AS INTEGER)*1000 + CAST(substr(strftime('%f',{expression}),4,3) AS INTEGER))")
}
fn records_ddl() -> String {
    let activity =
        "(SELECT last_activity_at FROM main.kernel_record_metadata m WHERE m.record_id=r.id)";
    let updated = kernel::record_metadata::updated_clock_sql("r.id");
    let created = "coalesce((SELECT m.created_at FROM main.kernel_legacy_sql_events m WHERE m.record_id=r.id AND m.source_stream='snapshot_provenance' ORDER BY m.seq DESC LIMIT 1),r.created_at)";
    // Same immutable carrier binding as v1_type_and_kind; column values remain lazy.
    let carrier = format!(
        "r.pin_family='{}' AND r.pin_version=1",
        crate::v2_standard::v1_compat::FAMILY
    );
    let values = format!(
        r#"CREATE TEMP VIEW _v2_record_oracle AS SELECT r.id,
 CASE WHEN {carrier} THEN {v1_type} ELSE r.primary_type END AS type,
 CASE WHEN {carrier} THEN {v1_kind} ELSE r.kind END AS kind,
 -- V1 records.name is NOT NULL DEFAULT ''. Import carriers intentionally
 -- omit empty titles. This fallback is inside the visible-record relation:
 -- an unmatched caller LEFT JOIN still has SQL NULLs for the absent row.
 coalesce({title},{name},'') AS name,
 coalesce((SELECT body FROM main.kernel_record_bodies b WHERE b.record_id=r.id),{body}) AS body,
 {summary} AS summary,
 (SELECT home_id FROM temp._v2_record_homes h WHERE h.id=r.id) AS home_id,
 CASE WHEN (SELECT count(*) FROM main.kernel_generic_links l WHERE l.active=1 AND l.target_id=r.id AND l.relationship='supersedes' AND EXISTS(SELECT 1 FROM temp._v2_visible s WHERE s.id=l.source_id))=0 THEN 1 ELSE NULL END AS is_current,
 (SELECT count(*) FROM main.kernel_generic_links l WHERE l.active=1 AND l.target_id=r.id AND l.relationship='supersedes' AND EXISTS(SELECT 1 FROM temp._v2_visible s WHERE s.id=l.source_id)) AS successor_count,
 coalesce((SELECT value FROM main.kernel_facets f WHERE f.record_id=r.id AND f.key='lifecycle'),{lifecycle}) AS lifecycle,
 {persistence} AS persistence, {maturity} AS maturity,
 coalesce((SELECT archived FROM main.kernel_lifecycle l WHERE l.record_id=r.id),0) AS archived,
 strftime('%Y-%m-%dT%H:%M:%fZ',{created}) AS created_at, {created_ms} AS created_at_ms,
 strftime('%Y-%m-%dT%H:%M:%fZ',{updated}) AS updated_at, {updated_ms} AS updated_at_ms,
 {activity} AS last_activity_at, {activity_ms} AS last_activity_at_ms,
 (SELECT json_extract(e.payload,'$.evidence.deleted_at') FROM main.content_events e WHERE e.record_id=r.id AND e.type='kernel.import_removed.v1' AND json_extract(e.payload,'$.kind')='record' ORDER BY e.seq DESC LIMIT 1) AS deleted_at,
 (SELECT CAST(unixepoch(json_extract(e.payload,'$.evidence.deleted_at'),'subsec')*1000 AS INTEGER) FROM main.content_events e WHERE e.record_id=r.id AND e.type='kernel.import_removed.v1' AND json_extract(e.payload,'$.kind')='record' ORDER BY e.seq DESC LIMIT 1) AS deleted_at_ms FROM temp._v2_visible r"#,
        v1_type = field("v1_type"),
        v1_kind = field("v1_kind"),
        title = field("title"),
        name = field("name"),
        body = field("body"),
        summary = field("summary"),
        lifecycle = field("lifecycle"),
        persistence =
            "(SELECT persistence FROM main.kernel_record_metadata m WHERE m.record_id=r.id)",
        maturity = "(SELECT maturity FROM main.kernel_record_metadata m WHERE m.record_id=r.id)",
        activity_ms = millis(activity),
        created_ms = millis(created),
        updated_ms = millis(&updated)
    );
    format!(
        "{values}; CREATE TEMP VIEW _v2_record_values AS SELECT * FROM temp._v2_record_oracle; CREATE TEMP VIEW records AS SELECT {} FROM temp._v2_record_values",
        columns("records").expect("records contract").join(",")
    )
}
const DDL: &str = r#"
CREATE TEMP TABLE _v2_scopes(home_id TEXT PRIMARY KEY, valid INTEGER, policy_view INTEGER, home_view INTEGER);
CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY, home_id TEXT, primary_type TEXT, kind TEXT, pin_family TEXT, pin_version INTEGER, created_at TEXT);
CREATE TEMP TABLE _v2_home_map(home_id TEXT PRIMARY KEY,record_id TEXT);
-- Only populated when the statement reads home_id. No caller expression can
-- force a retained body through the metadata/provenance lookup.
CREATE TEMP TABLE _v2_record_homes(id TEXT PRIMARY KEY,home_id TEXT);
-- Folder-scoped calls only: granted folder ids the person can View. They
-- authorise a logical home cell by id; they admit no row and no values.
CREATE TEMP TABLE _v2_authorized_homes(id TEXT PRIMARY KEY);
CREATE TEMP TABLE catalog_relations(relation_name TEXT, identity TEXT, semantic_version INTEGER, caller_relative INTEGER, completeness TEXT, profiles TEXT, comment TEXT);
CREATE TEMP TABLE catalog_columns(relation_name TEXT,column_name TEXT,column_position INTEGER);
CREATE TEMP TABLE catalog_operations(executor TEXT, operation TEXT, surface TEXT, access TEXT, plan_required INTEGER, direct_execution_enabled INTEGER, contract_version TEXT, contract_digest TEXT, source_tool TEXT, selector_field TEXT, selector_value TEXT, advertised_directly INTEGER, requires_acceptance INTEGER);
CREATE TEMP TABLE catalog_view_definitions(relation_name TEXT,view_id TEXT,revision_id TEXT,definition_sha256 TEXT,schema_sha256 TEXT,origin TEXT,description TEXT,scope_json TEXT,source_pins_json TEXT,dependencies_json TEXT,columns_json TEXT);
CREATE TEMP TABLE _v2_facet_rows(id TEXT,record_id TEXT,key TEXT,value TEXT,value_num REAL,vocab_ref TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE INDEX _v2_facet_record_key ON _v2_facet_rows(record_id,key);
CREATE INDEX _v2_facet_key_value ON _v2_facet_rows(key,value);
CREATE INDEX _v2_facet_key_num ON _v2_facet_rows(key,value_num) WHERE value_num IS NOT NULL;
CREATE TEMP VIEW facet_values AS SELECT * FROM temp._v2_facet_rows;
CREATE TEMP TABLE facet_observations(id TEXT,record_id TEXT,key TEXT,value TEXT,op TEXT,vocab_ref TEXT,as_of TEXT,observed_at TEXT,observed_at_ms INTEGER,event_seq INTEGER);
CREATE INDEX _v2_observation_series ON facet_observations(record_id,key,as_of);
CREATE INDEX _v2_observation_key ON facet_observations(key,as_of);
CREATE TEMP TABLE _v2_provider_links(source_id TEXT,target_id TEXT);
CREATE TEMP TABLE _v2_visible_providers(id TEXT PRIMARY KEY);
-- All edge sources pass the same endpoint fence. New sources belong here.
CREATE TEMP VIEW _v2_link_sources AS
 SELECT printf('v2:link:%s:%s:%s',l.source_id,l.target_id,l.relationship) AS id,l.source_id,l.target_id,l.relationship,NULL AS note,e.created_at FROM main.kernel_links l LEFT JOIN main.content_events e INDEXED BY idx_kernel_event_birth ON e.seq=l.created_seq
 UNION ALL SELECT l.edge_id,l.source_id,l.target_id,l.predicate,NULL,e.created_at FROM main.kernel_link4_edges l LEFT JOIN main.content_events e INDEXED BY idx_kernel_event_birth ON e.seq=l.created_seq
 UNION ALL SELECT link_id,source_id,target_id,relationship,note,created_at FROM main.kernel_generic_links WHERE active=1
;
CREATE TEMP VIEW _v2_link_endpoints AS
 SELECT printf('v2:link:%s:%s:%s',source_id,target_id,relationship) AS id,source_id,target_id,relationship,NULL AS note FROM main.kernel_links
 UNION ALL SELECT edge_id,source_id,target_id,predicate,NULL FROM main.kernel_link4_edges
 UNION ALL SELECT link_id,source_id,target_id,relationship,note FROM main.kernel_generic_links WHERE active=1
;
CREATE TEMP TABLE _v2_link_rows(id TEXT,source_id TEXT,target_id TEXT,relationship TEXT,note TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE INDEX _v2_link_target ON _v2_link_rows(target_id,relationship);
CREATE INDEX _v2_link_source ON _v2_link_rows(source_id,relationship,target_id);
CREATE TEMP VIEW links AS SELECT * FROM temp._v2_link_rows;
CREATE TEMP TABLE _v2_event_disclosure(actor TEXT,root_visible INTEGER);
CREATE TEMP TABLE _v2_disclosed_legacy_actors(actor TEXT PRIMARY KEY);
CREATE TEMP TABLE _v2_event_ids(seq INTEGER PRIMARY KEY);
CREATE TEMP TABLE runs(run_key TEXT PRIMARY KEY,principal_person_id TEXT,started_at_ms INTEGER,ended_at_ms INTEGER,reported_model TEXT,reported_client TEXT,model_assurance TEXT);
CREATE TEMP TABLE run_intents(run_key TEXT,ordinal INTEGER,intent TEXT,declared_at_ms INTEGER);
CREATE TEMP TABLE vocabularies(id TEXT,name TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE TEMP TABLE vocabulary_values(id TEXT,vocabulary_id TEXT,value TEXT,gloss TEXT,status TEXT,ordinal REAL,terminality TEXT,metadata TEXT,alias_of TEXT);
CREATE TEMP TABLE record_lifecycle_interpretations(record_id TEXT,status TEXT,raw TEXT,axis_key TEXT,axis_label TEXT,vocabulary_id TEXT,vocabulary_name TEXT,value_id TEXT,canonical TEXT,terminality TEXT,reason TEXT);
CREATE TEMP TABLE agent_activity(activity_id TEXT,run_key TEXT,principal_ref TEXT,principal_display_name TEXT,started_at TEXT,started_at_ms INTEGER,ended_at TEXT,ended_at_ms INTEGER,last_observed_activity_at TEXT,last_observed_activity_at_ms INTEGER,active_until TEXT,active_until_ms INTEGER,appears_active INTEGER,declared_intent TEXT,declared_intent_state TEXT);
CREATE TEMP TABLE agent_activity_claims(claim_id TEXT,activity_id TEXT,record_id TEXT,claimed_at TEXT,claimed_at_ms INTEGER,released_at TEXT,released_at_ms INTEGER,is_current INTEGER);

CREATE TEMP TABLE _v2_runs(id TEXT PRIMARY KEY,run_key TEXT,owner TEXT);
CREATE TEMP TABLE _v2_imported_accounts(principal_id TEXT PRIMARY KEY);
CREATE TEMP TABLE my_message_state(message_id TEXT PRIMARY KEY,stage TEXT,unread INTEGER,is_own INTEGER,mentioned INTEGER,flagged INTEGER,muted INTEGER,archived INTEGER,snoozed_until TEXT,snoozed_until_ms INTEGER,reactable INTEGER);
CREATE TEMP TABLE messages_awaiting_reply(message_id TEXT PRIMARY KEY);
CREATE TEMP TABLE bindings(record_id TEXT,system TEXT,identifier TEXT,is_canonical INTEGER);
CREATE TEMP TABLE message_reactions(reaction_id TEXT PRIMARY KEY,message_id TEXT,emoji TEXT,actor_record_id TEXT,actor_name TEXT,executor_kind TEXT,reacted_at TEXT,reacted_at_ms INTEGER,viewer INTEGER);
CREATE TEMP TABLE my_mentions(source_id TEXT,source_kind TEXT,via TEXT,own_source INTEGER,mentioned_at TEXT,mentioned_at_ms INTEGER,seen INTEGER);

"#;

// Trusted snapshot preparation extracts only the authorized logical home.
// The thin legacy header finds provenance without searching body envelopes;
// caller VM value limits apply after this metadata has been materialized.
fn logical_home_placement_sql() -> String {
    format!(
        r#" SELECT r.id,m.record_id,{direct_home} AS direct_home,
 coalesce(json_extract(move.payload,'$.logical_home_id'), {direct_home}, CASE WHEN m.record_id=r.id AND json_extract(e.payload,'$.legacy.payload.policy_anchor')=r.id
 THEN json_extract(e.payload,'$.legacy.payload.original_home') ELSE coalesce(m.record_id,r.home_id) END) AS candidate
 FROM temp._v2_visible r LEFT JOIN temp._v2_home_map m ON m.home_id=r.home_id
 LEFT JOIN main.kernel_messages message ON message.message_id=r.id
 LEFT JOIN main.content_events move ON move.seq=(SELECT max(seq) FROM (SELECT max(p.seq) AS seq FROM main.content_events p WHERE p.record_id=r.id AND p.type='kernel.record_rehomed.v1' UNION ALL SELECT max(p.seq) AS seq FROM main.content_events p WHERE p.record_id=r.id AND p.type='kernel.record_rehomed.v2'))
 LEFT JOIN main.content_events e ON e.seq=CASE WHEN m.record_id=r.id THEN (SELECT seq FROM main.kernel_legacy_sql_events p WHERE p.record_id=r.id AND p.source_stream='snapshot_provenance' ORDER BY seq DESC LIMIT 1) END"#,
        direct_home = kernel::messaging::LOGICAL_DIRECT_HOME_SQL
    )
}

pub(super) fn logical_home_rows_sql() -> String {
    format!(
        r#"INSERT INTO temp._v2_record_homes WITH placement AS ({placement})
 SELECT p.id,CASE WHEN (p.candidate='native:unfiled' AND p.direct_home='native:unfiled')
 OR EXISTS(SELECT 1 FROM temp._v2_visible v WHERE v.id=p.candidate)
 OR EXISTS(SELECT 1 FROM temp._v2_authorized_homes a WHERE a.id=p.candidate)
 OR (p.candidate='native:root' AND NOT EXISTS(SELECT 1 FROM main.kernel_records WHERE id='native:root') AND EXISTS(SELECT 1 FROM temp._v2_home_map m JOIN temp._v2_scopes h ON h.home_id=m.home_id WHERE m.record_id='native:root' AND h.home_view))
 OR (NOT EXISTS(SELECT 1 FROM main.kernel_records hidden WHERE hidden.id=p.candidate) AND EXISTS(SELECT 1 FROM temp._v2_scopes h WHERE h.home_id=p.candidate AND h.home_view)) THEN p.candidate ELSE NULL END AS home_id FROM placement p"#,
        placement = logical_home_placement_sql()
    )
}

const FACET_ROWS: &str = r#"INSERT INTO temp._v2_facet_rows SELECT printf('v2:facet:%s:%s',f.record_id,f.key),
 f.record_id,f.key,f.value,f.value_num,f.vocab_ref,strftime('%Y-%m-%dT%H:%M:%fZ',f.as_of),
 CAST(strftime('%s',f.as_of) AS INTEGER)*1000+CAST(substr(strftime('%f',f.as_of),4,3) AS INTEGER)
 FROM main.kernel_facets f JOIN temp._v2_visible v ON v.id=f.record_id WHERE f.value IS NOT NULL"#;
// v1's projector stores one observation per (record,key,as_of), replacing
// equal-time observations in source order. Only the public cell is projected;
// actor, app origin, and the rest of the retained envelope never enter SQL.
// Legacy event_seq follows the public v2 content_events namespace, so joins
// remain exact. IDs and all other fields retain their v1 representation.
fn facet_observation_rows(scoped: bool) -> String {
    let legacy = if scoped {
        "FROM json_each(?1) requested CROSS JOIN temp._v2_visible v ON v.id=requested.value CROSS JOIN main.kernel_legacy_sql_events h ON h.record_id=v.id CROSS JOIN main.content_events e ON e.seq=h.seq"
    } else {
        "FROM main.kernel_legacy_sql_events h JOIN main.content_events e ON e.seq=h.seq JOIN temp._v2_visible v ON v.id=h.record_id"
    };
    let native = if scoped {
        "FROM json_each(?1) requested CROSS JOIN temp._v2_visible v ON v.id=requested.value CROSS JOIN main.content_events e ON e.record_id=v.id"
    } else {
        "FROM main.content_events e JOIN temp._v2_visible v ON v.id=e.record_id"
    };
    format!(
        r#"INSERT INTO temp.facet_observations
WITH candidates AS (
 SELECT h.record_id,json_extract(e.payload,'$.legacy.payload.key') AS key,
 CASE h.event_type WHEN 'facet.set' THEN json_extract(e.payload,'$.legacy.payload.value') END AS value,
 CASE h.event_type WHEN 'facet.set' THEN 'set' ELSE 'unset' END AS op,
 CASE h.event_type WHEN 'facet.set' THEN json_extract(e.payload,'$.legacy.payload.vocab_ref') END AS vocab_ref,
 coalesce(json_extract(e.payload,'$.legacy.payload.as_of'),h.created_at) AS as_of,
 h.created_at AS observed_at,h.seq AS event_seq,0 AS native,
 json_extract(e.payload,'$.legacy.source.metadata.seq') AS ordering
 {legacy}
 WHERE h.source_stream='content_events' AND h.event_type IN ('facet.set','facet.unset')
 AND json_type(e.payload,'$.legacy.payload.key')='text'
 AND json_type(e.payload,'$.legacy.source.metadata.seq')='integer'
 UNION ALL
 SELECT e.record_id,json_extract(e.payload,'$.key'),json_extract(e.payload,'$.value'),
 CASE WHEN json_extract(e.payload,'$.value') IS NULL THEN 'unset' ELSE 'set' END,
 json_extract(e.payload,'$.vocab_ref'),json_extract(e.payload,'$.as_of'),e.created_at,e.seq,1,e.seq
 {native}
 WHERE e.type='kernel.facet_observed.v1'
 UNION ALL
 SELECT e.record_id,'archived',CASE WHEN json_extract(e.payload,'$.archived') THEN 'true' END,
 CASE WHEN json_extract(e.payload,'$.archived') THEN 'set' ELSE 'unset' END,
 NULL,e.created_at,e.created_at,e.seq,1,e.seq
 {native}
 WHERE e.type='kernel.archive_changed.v1'
), latest AS (
 SELECT *,row_number() OVER(PARTITION BY record_id,key,as_of ORDER BY native DESC,ordering DESC,event_seq DESC) AS rank
 FROM candidates WHERE key NOT IN ('lifecycle','owner','persistence','maturity') AND as_of IS NOT NULL
)
SELECT 'fo:'||record_id||':'||key||':'||as_of,record_id,key,value,op,vocab_ref,as_of,
 strftime('%Y-%m-%dT%H:%M:%fZ',observed_at),(CAST(strftime('%s',observed_at) AS INTEGER)*1000+CAST(substr(strftime('%f',observed_at),4,3) AS INTEGER)),event_seq
 FROM latest WHERE rank=1"#
    )
}

fn events_ddl() -> String {
    format!(
        r#"
CREATE TEMP TABLE _v2_event_rows(local_seq INTEGER PRIMARY KEY,id TEXT,record_id TEXT,type TEXT,actor TEXT,run_key TEXT,parent_key TEXT,channel_kind TEXT,created_at TEXT,created_at_ms INTEGER);
CREATE TEMP VIEW content_events AS
 SELECT local_seq,id,record_id,type,actor,run_key,parent_key,channel_kind,
 strftime('%Y-%m-%dT%H:%M:%fZ',created_at) AS created_at,
 CAST(strftime('%s',created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',created_at),4,3) AS INTEGER) AS created_at_ms
 FROM temp._v2_event_rows;
CREATE TEMP VIEW actors AS SELECT DISTINCT e.actor,r.id AS person_id,coalesce(json_extract(n.value_json,'$'),p.display_label) AS display_name
 FROM temp.content_events e LEFT JOIN main.kernel_principals p ON p.principal_id=e.actor OR 'v1:'||p.auth_binding=e.actor
 LEFT JOIN main.kernel_v1_state d ON d.section='account_directory' AND d.account_principal=p.principal_id
 LEFT JOIN main.kernel_message_people mp ON mp.principal_id=p.principal_id
 LEFT JOIN temp._v2_visible v ON v.id=coalesce(d.record_id,mp.person_id)
 LEFT JOIN main.kernel_records r ON r.id=v.id
 LEFT JOIN main.kernel_record_fields n ON n.record_id=r.id AND n.name='title'
 WHERE e.actor IS NOT NULL;
CREATE TEMP TABLE _v2_viewer_principal(principal_id TEXT);
CREATE TEMP VIEW viewer AS SELECT r.id AS person_id,coalesce(json_extract(n.value_json,'$'),p.display_label) AS display_name
 FROM temp._v2_viewer_principal own
 LEFT JOIN main.kernel_principals p ON p.principal_id=own.principal_id
 LEFT JOIN main.kernel_v1_state d ON d.section='account_directory' AND d.account_principal=p.principal_id
 LEFT JOIN main.kernel_message_people mp ON mp.principal_id=p.principal_id
 LEFT JOIN temp._v2_visible v ON v.id=coalesce(d.record_id,mp.person_id)
 LEFT JOIN main.kernel_records r ON r.id=v.id
 LEFT JOIN main.kernel_record_fields n ON n.record_id=r.id AND n.name='title'
 ORDER BY r.id IS NULL,d.source_id,r.id LIMIT 1;
CREATE TEMP VIEW comment_anchors AS SELECT a.annotation_id,a.target_record_id,a.purpose,a.selectors,a.body_revision AS source_event_seq,a.body_sha256 AS source_sha256
 FROM main.kernel_comment_anchors a JOIN temp._v2_visible c ON c.id=a.annotation_id JOIN temp._v2_visible t ON t.id=a.target_record_id JOIN main.kernel_records r ON r.id=a.annotation_id
 WHERE a.source_slot='body' AND {};
"#,
        kernel::comments_v2::sql_is_comment("r")
    )
}

// Keep every retained-header join after the tiny selected-position set.
// Fencing only a/m lets SQLite move the JSON subject scan ahead of both.
pub(super) const LEGACY_ADMISSION_SQL: &str = "INSERT INTO temp._v2_legacy_admitted SELECT m.seq FROM temp._v2_event_ids a CROSS JOIN main.kernel_legacy_sql_events m ON m.seq=a.seq CROSS JOIN main.kernel_legacy_history h ON h.seq=m.seq CROSS JOIN temp._v2_visible r ON r.id=m.record_id WHERE m.source_stream='content_events' AND NOT h.hidden AND (?1 OR NOT h.restricted OR h.owner=?2) AND EXISTS(SELECT 1 FROM temp._v2_legacy_subject_sets subjects WHERE subjects.subjects=h.subjects AND subjects.admitted)";

/// Share W5 disclosure checks. Only replayed header facts are read here;
/// source bodies and immutable retained envelopes stay outside ordinary SQL.
async fn install_events(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    root_visible: bool,
    bounded: bool,
) -> Result<()> {
    #[cfg(test)]
    if event_equivalence::baseline_enabled() {
        return event_staging_baseline::install_events(tx, actor, root_visible, bounded).await;
    }
    install_events_after(tx, actor, root_visible, bounded, 0, false).await
}

async fn install_events_after(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    root_visible: bool,
    bounded: bool,
    after: i64,
    oracle_only: bool,
) -> Result<()> {
    let event_started = Instant::now();
    let logical_types = super::LOGICAL_EVENT_TYPES
        .iter()
        .map(|(native, logical)| format!("WHEN '{native}' THEN '{logical}'"))
        .collect::<Vec<_>>()
        .join(" ");
    let imported = super::IMPORTED_EVENTS
        .iter()
        .map(|event| format!("'{event}'"))
        .collect::<Vec<_>>()
        .join(",");
    let native_globs = native_event_globs_sql();
    let native_sql = format!(
        r#"INSERT INTO temp._v2_event_rows
 SELECT e.seq,e.id,e.record_id,
 CASE e.type {logical_types} ELSE e.type END,
 CASE WHEN ?1 OR e.actor=?2 OR EXISTS(SELECT 1 FROM main.kernel_message_people mp JOIN temp._v2_visible v ON v.id=mp.person_id WHERE mp.principal_id=e.actor) THEN e.actor END,
 CASE WHEN ?1 THEN e.run_key END,CASE WHEN ?1 THEN e.parent_key END,
 CASE WHEN ?1 OR e.actor=?2 THEN 'unknown' END,
 e.created_at,NULL
 FROM temp._v2_event_ids a CROSS JOIN main.content_events e ON e.seq=a.seq
 WHERE e.type!='kernel.legacy_recorded.v1' AND {native_globs} AND e.type NOT IN ({imported})"#
    );
    #[cfg(test)]
    let native_phase = event_profile::Phase::new("native_insert");
    let native_rows = sqlx::query(&native_sql)
        .bind(root_visible)
        .bind(actor)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    #[cfg(test)]
    let _ = STATS.try_with(|s| s.borrow_mut().native_event_rows += native_rows);
    #[cfg(not(test))]
    let _ = native_rows;
    tracing::debug!(target: "native_ce::read_staging", phase = "events_native", elapsed_us = event_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    drop(native_phase);
    #[cfg(test)]
    let reaction_phase = event_profile::Phase::new("reaction_synthesis");
    install_reaction_headers(tx, actor, root_visible, bounded, after, oracle_only).await?;
    tracing::debug!(target: "native_ce::read_staging", phase = "events_reactions", elapsed_us = event_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    drop(reaction_phase);
    #[cfg(test)]
    let subject_phase = event_profile::Phase::new("legacy_subject_sets_and_visibility");
    let headers: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.sqlite_master WHERE type='table' AND name='kernel_legacy_sql_events')").fetch_one(&mut *tx).await?;
    if !headers {
        let retained: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_legacy_history)")
                .fetch_one(&mut *tx)
                .await?;
        if retained {
            return Err(Error::engine(
                "kernel-v2 logical history needs import projection upgrade",
            ));
        }
        return Ok(());
    }
    let binding: String =
        sqlx::query_scalar("SELECT auth_binding FROM main.kernel_principals WHERE principal_id=?")
            .bind(actor)
            .fetch_one(&mut *tx)
            .await?;
    let admin =
        kernel::kernel_effective_capability_on(&mut *tx, actor, crate::events::KERNEL_ROOT_ID)
            .await?
            .allows(Capability::Manage);
    let subject_sets: Vec<String> = sqlx::query_scalar("SELECT DISTINCT h.subjects FROM temp._v2_event_ids a CROSS JOIN main.kernel_legacy_sql_events m ON m.seq=a.seq CROSS JOIN main.kernel_legacy_history h ON h.seq=m.seq CROSS JOIN temp._v2_visible r ON r.id=m.record_id WHERE m.source_stream='content_events' AND NOT h.hidden AND (?1 OR NOT h.restricted OR h.owner=?2)")
        .bind(admin).bind(&binding).fetch_all(&mut *tx).await?;
    let mut visibility = std::collections::BTreeMap::new();
    // Reuse current record visibility already established by S7, including
    // terminal-bearer authorization for derived records. Comments retain W5's
    // additional anchor check; homes and other subjects use its shared helper.
    let mut subjects = BTreeSet::<String>::new();
    for row in &subject_sets {
        subjects.extend(serde_json::from_str::<Vec<String>>(row)?);
    }
    let ordinary = format!(
        "SELECT v.id FROM temp._v2_visible v JOIN main.kernel_records r ON r.id=v.id WHERE v.id IN (SELECT value FROM json_each(?1)) AND NOT {}",
        kernel::comments_v2::sql_is_comment("r")
    );
    for id in sqlx::query_scalar::<_, String>(&ordinary)
        .bind(serde_json::to_string(&subjects)?)
        .fetch_all(&mut *tx)
        .await?
    {
        visibility.insert(id, true);
    }
    // Resolve each subject once, with the same W5 helper as before. Admission
    // of the many historical rows is then a set operation inside this exact
    // authority snapshot, rather than decoding/inserting each row in Rust.
    for subjects in &subject_sets {
        for subject in serde_json::from_str::<Vec<String>>(subjects)? {
            kernel::legacy_history_visible(&mut *tx, actor, &subject, &mut visibility).await?;
        }
    }
    sqlx::query("CREATE TEMP TABLE IF NOT EXISTS _v2_legacy_visible_subjects(id TEXT PRIMARY KEY); DELETE FROM temp._v2_legacy_visible_subjects; CREATE TEMP TABLE IF NOT EXISTS _v2_legacy_admitted(seq INTEGER PRIMARY KEY); DELETE FROM temp._v2_legacy_admitted")
        .execute(&mut *tx).await?;
    let visible: Vec<&str> = visibility
        .iter()
        .filter_map(|(id, allowed)| allowed.then_some(id.as_str()))
        .collect();
    for chunk in visible.chunks(500) {
        let mut insert = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT INTO temp._v2_legacy_visible_subjects(id) ",
        );
        insert.push_values(chunk, |mut row, id| {
            row.push_bind(*id);
        });
        insert.build().execute(&mut *tx).await?;
    }
    #[cfg(test)]
    drop(subject_phase);
    tracing::debug!(target: "native_ce::read_staging", phase = "events_subjects", elapsed_us = event_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    let admission_phase = event_profile::Phase::new("legacy_admission");
    // Preserve the exact SQLite json_each/value comparison, but evaluate it
    // once per distinct raw subject set. Clear on every history window: its
    // visible subject set can grow within the same authority snapshot.
    sqlx::query("CREATE TEMP TABLE IF NOT EXISTS _v2_legacy_subject_sets(subjects TEXT PRIMARY KEY,admitted INTEGER NOT NULL DEFAULT 0); DELETE FROM temp._v2_legacy_subject_sets").execute(&mut *tx).await?;
    for chunk in subject_sets.chunks(500) {
        let mut insert = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT INTO temp._v2_legacy_subject_sets(subjects) ",
        );
        insert.push_values(chunk, |mut row, subjects| {
            row.push_bind(subjects);
        });
        insert.build().execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE temp._v2_legacy_subject_sets SET admitted=NOT EXISTS(SELECT 1 FROM json_each(_v2_legacy_subject_sets.subjects) subject WHERE NOT EXISTS(SELECT 1 FROM temp._v2_legacy_visible_subjects visible WHERE visible.id=subject.value))").execute(&mut *tx).await?;
    sqlx::query(LEGACY_ADMISSION_SQL)
        .bind(admin)
        .bind(&binding)
        .execute(&mut *tx)
        .await?;
    #[cfg(test)]
    drop(admission_phase);
    tracing::debug!(target: "native_ce::read_staging", phase = "events_admission", elapsed_us = event_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    let disclosure_phase = event_profile::Phase::new("legacy_actor_disclosure");
    // Same v1 rule as get_history: self, or an actor's verified Person
    // visible under current policy. Root visibility is not a substitute.
    for principal in kernel::v1_state::disclosed_accounts_on(tx, actor).await? {
        sqlx::query("INSERT OR IGNORE INTO temp._v2_disclosed_legacy_actors SELECT 'v1:'||auth_binding FROM main.kernel_principals WHERE principal_id=?")
            .bind(principal).execute(&mut *tx).await?;
    }
    // Resolve each disclosed source alias once. auth_binding is UNIQUE, so
    // this preserves the old per-event LEFT JOIN's row cardinality and NULL
    // fallback. Undisclosed aliases never acquire a public principal here.
    sqlx::query("CREATE TEMP TABLE IF NOT EXISTS _v2_disclosed_legacy_principals(actor TEXT PRIMARY KEY,principal_id TEXT); DELETE FROM temp._v2_disclosed_legacy_principals; INSERT INTO temp._v2_disclosed_legacy_principals SELECT d.actor,p.principal_id FROM temp._v2_disclosed_legacy_actors d LEFT JOIN main.kernel_principals p ON p.auth_binding=substr(d.actor,4) AND d.actor LIKE 'v1:%' AND p.kind='account'").execute(&mut *tx).await?;
    // SQL uses one verified principal identity across imported and native
    // activity. Otherwise apps mistake a source alias and that principal's
    // first native event for two different accounts bound to the same Person.
    // Disclosure still gates the source actor first; retained headers and raw
    // history keep the exact v1 actor. Never coalesce accounts by Person/name.
    // Copy admitted headers in one set operation, never one round trip per
    // historical event. No source payload enters the ordinary SQL surface.
    #[cfg(test)]
    drop(disclosure_phase);
    tracing::debug!(target: "native_ce::read_staging", phase = "events_disclosure", elapsed_us = event_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    let legacy_phase = event_profile::Phase::new("legacy_insert");
    let (legacy_native, legacy_logical) = super::LEGACY_RECEIPT_MAPPING;
    let legacy_rows = sqlx::query(&format!(r#"INSERT INTO temp._v2_event_rows
      SELECT m.seq,m.source_id,m.record_id,
       CASE WHEN m.event_type='{legacy_native}' THEN '{legacy_logical}' ELSE m.event_type END,
       CASE WHEN d.actor IS NOT NULL THEN coalesce(d.principal_id,m.actor) END,
       CASE WHEN d.actor IS NOT NULL AND (NOT h.claim_sensitive OR m.actor='v1:'||?1) THEN m.run_key END,
       CASE WHEN d.actor IS NOT NULL AND (NOT h.claim_sensitive OR m.actor='v1:'||?1) THEN m.parent_key END,
       CASE WHEN d.actor IS NOT NULL THEN 'unknown' END,
       m.created_at,NULL
      FROM temp._v2_legacy_admitted a CROSS JOIN main.kernel_legacy_sql_events m ON m.seq=a.seq
      CROSS JOIN main.kernel_legacy_history h ON h.seq=m.seq
      LEFT JOIN temp._v2_disclosed_legacy_principals d ON d.actor=m.actor"#))
        .bind(&binding).execute(&mut *tx).await?.rows_affected();
    #[cfg(test)]
    let _ = STATS.try_with(|s| s.borrow_mut().legacy_event_rows += legacy_rows);
    #[cfg(not(test))]
    let _ = legacy_rows;
    tracing::debug!(target: "native_ce::read_staging", phase = "events_legacy", elapsed_us = event_started.elapsed().as_micros() as u64);
    #[cfg(test)]
    drop(legacy_phase);
    Ok(())
}

async fn select_event_ids(tx: &mut sqlx::SqliteConnection, bounded: bool) -> Result<()> {
    #[cfg(test)]
    if event_equivalence::baseline_enabled() {
        return event_staging_baseline::select_event_ids(tx, bounded).await;
    }
    select_event_ids_after(tx, bounded, 0, false).await
}

async fn select_event_ids_after(
    tx: &mut sqlx::SqliteConnection,
    bounded: bool,
    after: i64,
    oracle_only: bool,
) -> Result<()> {
    #[cfg(test)]
    let _phase = event_profile::Phase::new("select_event_ids");
    let candidate = if bounded {
        " AND e.seq IN (SELECT seq FROM temp._v2_history_candidates)".to_owned()
    } else if oracle_only {
        " AND e.seq IN (SELECT seq FROM temp._v2_oracle_events)".to_owned()
    } else {
        format!(" AND e.seq>{after}")
    };
    sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN temp._v2_visible v ON v.id=e.record_id WHERE {SELECTOR_EXCLUSION_GLOBS_SQL} AND e.type NOT IN ({RECORD_EVENT_EXCLUSIONS_SQL}) AND e.type NOT LIKE '{GENERIC_LINK_PATTERN}'{candidate}")).execute(&mut *tx).await?;

    sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN main.kernel_link4_edges l ON l.created_seq=e.seq JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id WHERE e.type='{LINK4_TYPE}'{candidate}")).execute(&mut *tx).await?;
    if bounded || oracle_only {
        let source = if oracle_only {
            // Keep payload evaluation after the visible-source gate even for
            // malformed hidden V1 links. Candidates drive point seeks.
            "temp._v2_oracle_events c CROSS JOIN main.content_events e ON e.seq=c.seq CROSS JOIN temp._v2_visible s ON s.id=e.record_id CROSS JOIN temp._v2_visible t ON t.id=json_extract(e.payload,'$.target_id')"
        } else {
            "main.content_events e JOIN temp._v2_visible s ON s.id=e.record_id JOIN temp._v2_visible t ON t.id=json_extract(e.payload,'$.target_id')"
        };
        sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM {source} WHERE e.type IN ({V1_LINK_TYPES_SQL}){candidate}")).execute(&mut *tx).await?;
        let generic_source = if oracle_only {
            // Preserve the permanent generic selector's evaluation order: JSON
            // identity decoding precedes retained endpoint admission.
            "temp._v2_oracle_events c CROSS JOIN main.content_events e ON e.seq=c.seq CROSS JOIN main.kernel_generic_links l ON l.link_id=json_extract(e.payload,'$.link_id') CROSS JOIN temp._v2_visible s ON s.id=l.source_id CROSS JOIN temp._v2_visible t ON t.id=l.target_id"
        } else {
            "main.content_events e JOIN main.kernel_generic_links l ON l.link_id=json_extract(e.payload,'$.link_id') JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id"
        };
        sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM {generic_source} WHERE e.type LIKE '{GENERIC_LINK_PATTERN}'{candidate}")).execute(&mut *tx).await?;
    } else {
        // Seek each authorized source's two V1 event types through the existing
        // (record_id,type,seq) index, then apply the unchanged target fence.
        sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM temp._v2_visible s CROSS JOIN main.content_events e INDEXED BY idx_kernel_hosted_event_lookup ON e.record_id=s.id CROSS JOIN temp._v2_visible t ON t.id=json_extract(e.payload,'$.target_id') WHERE e.type IN ({V1_LINK_TYPES_SQL}){candidate}")).execute(&mut *tx).await?;
        // Generic admission uses the projected endpoints, not e.record_id.
        // Read only positions/types in the covering index before fetching the
        // comparatively few generic payloads. Keep LIKE's exact semantics.
        sqlx::query(&format!("WITH candidates AS MATERIALIZED (SELECT e.seq FROM main.content_events e INDEXED BY idx_kernel_hosted_event_lookup WHERE e.type LIKE '{GENERIC_LINK_PATTERN}'{candidate}) INSERT INTO temp._v2_event_ids SELECT e.seq FROM candidates c CROSS JOIN main.content_events e ON e.seq=c.seq CROSS JOIN main.kernel_generic_links l ON l.link_id=json_extract(e.payload,'$.link_id') CROSS JOIN temp._v2_visible s ON s.id=l.source_id CROSS JOIN temp._v2_visible t ON t.id=l.target_id")).execute(&mut *tx).await?;
    }
    sqlx::query(&format!("INSERT INTO temp._v2_event_ids SELECT e.seq FROM main.content_events e JOIN temp._v2_visible anchor ON anchor.id=e.record_id WHERE e.type='{PROVIDER_TYPE}' AND EXISTS(SELECT 1 FROM main.kernel_provider_subjects s WHERE s.aggregate_id=e.record_id) AND NOT EXISTS(SELECT 1 FROM main.kernel_provider_subjects s WHERE s.aggregate_id=e.record_id AND s.subject_id NOT IN (SELECT id FROM temp._v2_visible)){candidate}")).execute(&mut *tx).await?;
    Ok(())
}

/// Structural subjects for a closed history window, followed by the SAME
/// live record gate as full staging. Accumulate admitted subjects across
/// windows; all event selectors/redactors still run unchanged afterwards.
async fn stage_history_subjects(tx: &mut sqlx::SqliteConnection, actor: &str) -> Result<()> {
    let visibility = kernel::sql_record_visible(
        "r",
        "?1",
        "SELECT home_id AS id,policy_view AS view FROM temp._v2_scopes WHERE valid",
        true,
    );
    let subjects = r#"WITH candidates AS MATERIALIZED (SELECT e.seq,e.record_id,e.type,e.actor,CASE WHEN e.type IN ('kernel.link_added.v1','kernel.link_removed.v1') OR e.type LIKE 'kernel.generic_link_%' THEN e.payload END AS payload FROM temp._v2_history_candidates c CROSS JOIN main.content_events e ON e.seq=c.seq),
    subjects(id) AS (
      SELECT record_id FROM candidates
      UNION SELECT m.record_id FROM candidates c JOIN main.kernel_legacy_sql_events m ON m.seq=c.seq
      UNION SELECT j.value FROM candidates c JOIN main.kernel_legacy_history h ON h.seq=c.seq JOIN json_each(h.subjects) j
      UNION SELECT l.source_id FROM candidates c JOIN main.kernel_generic_links l ON l.link_id=json_extract(c.payload,'$.link_id') WHERE c.type LIKE 'kernel.generic_link_%'
      UNION SELECT l.target_id FROM candidates c JOIN main.kernel_generic_links l ON l.link_id=json_extract(c.payload,'$.link_id') WHERE c.type LIKE 'kernel.generic_link_%'
      UNION SELECT l.source_id FROM candidates c JOIN main.kernel_link4_edges l ON l.created_seq=c.seq WHERE c.type='kernel.link_added.v2'
      UNION SELECT l.target_id FROM candidates c JOIN main.kernel_link4_edges l ON l.created_seq=c.seq WHERE c.type='kernel.link_added.v2'
      UNION SELECT json_extract(payload,'$.target_id') FROM candidates WHERE type IN ('kernel.link_added.v1','kernel.link_removed.v1')
      UNION SELECT s.subject_id FROM candidates c JOIN main.kernel_provider_subjects s ON s.aggregate_id=c.record_id WHERE c.type='kernel.provider_outcome.v1'
      UNION SELECT p.person_id FROM main.kernel_message_people p
    )"#;
    // Payloads only supply native edge ids/endpoints. Retained payloads stay
    // opaque; their already projected subject headers are the authority input.
    sqlx::query(&format!("{subjects} INSERT OR IGNORE INTO temp._v2_visible SELECT r.id,r.home_id,NULL,NULL,NULL,NULL,NULL FROM main.kernel_records r WHERE r.id IN (SELECT id FROM subjects) AND ({visibility})"))
        .bind(actor).execute(tx).await?;
    Ok(())
}

/// Candidate positions carry no authority. Every window still passes the
/// unchanged native/legacy disclosure selectors and retained header gates.
async fn install_history_window(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    root_visible: bool,
    window: HistoryWindow,
) -> Result<()> {
    sqlx::query("CREATE TEMP TABLE _v2_history_candidates(seq INTEGER PRIMARY KEY)")
        .execute(&mut *tx)
        .await?;
    let imported = super::IMPORTED_EVENTS
        .iter()
        .map(|event| format!("'{event}'"))
        .collect::<Vec<_>>()
        .join(",");
    let direction = if window.newest { "DESC" } else { "ASC" };
    let mut cursor = window
        .after
        .unwrap_or(if window.newest { i64::MAX } else { 0 });
    let mut inclusive = window.newest && window.after.is_none();
    let mut admitted_count = 0usize;
    let mut fetch = window.limit.saturating_add(1).clamp(16, 256);
    loop {
        let comparison = if window.newest {
            if inclusive {
                "<="
            } else {
                "<"
            }
        } else {
            ">"
        };
        inclusive = false;
        let positions: Vec<i64> = sqlx::query_scalar(&format!(
            "SELECT e.seq FROM main.content_events e WHERE e.seq{comparison}?1 AND e.type NOT GLOB 'kernel.hcp_*' AND e.type NOT GLOB 'kernel.webhook_*' AND e.type NOT GLOB 'kernel.import_*' AND e.type NOT IN ({imported},'kernel.identity_binding_added.v1','kernel.identity_binding_removed.v1','kernel.identity_bindings_reconciled.v1','kernel.account_config_bound.v1','kernel.app_state_imported.v1','kernel.v1_state_imported.v1','kernel.notification_preference_set.v1','kernel.message_command_committed.v1','kernel.mcp_write_receipt_recorded.v1','kernel.mcp_write_fenced.v1','kernel.message_destination_imported.v1','kernel.message_destination_set.v1') AND (e.type!='kernel.legacy_recorded.v1' OR EXISTS(SELECT 1 FROM main.kernel_legacy_sql_events m WHERE m.seq=e.seq AND m.source_stream='content_events')) ORDER BY e.seq {direction} LIMIT {fetch}"
        )).bind(cursor).fetch_all(&mut *tx).await?;
        if positions.is_empty() {
            break;
        }
        cursor = *positions.last().expect("nonempty candidate window");
        sqlx::query("DELETE FROM temp._v2_history_candidates; DELETE FROM temp._v2_event_ids")
            .execute(&mut *tx)
            .await?;
        let mut insert = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "INSERT INTO temp._v2_history_candidates(seq) ",
        );
        insert.push_values(&positions, |mut row, seq| {
            row.push_bind(*seq);
        });
        insert.build().execute(&mut *tx).await?;
        stage_history_subjects(tx, actor).await?;
        select_event_ids(tx, true).await?;
        install_events(tx, actor, root_visible, true).await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM temp._v2_event_rows")
            .fetch_one(&mut *tx)
            .await?;
        if count > window.limit as i64 || positions.len() < fetch {
            break;
        }
        // Fetch only the remaining page/lookahead when making progress. A
        // hidden or private-only window uses the old full stride next time.
        fetch = if count as usize == admitted_count {
            256
        } else {
            window
                .limit
                .saturating_add(1)
                .saturating_sub(count as usize)
                .clamp(16, 256)
        };
        admitted_count = count as usize;
    }
    Ok(())
}

// Drive immutable home-event lookup from the already evaluated scopes. Letting
// SQLite reorder an ordinary join scans every retained content-event row before
// probing the tiny scope set, even though the existing record/type index can
// answer these exact lookups. No authority predicate or source data changes.
pub(super) const HOME_MAP_SQL: &str = "INSERT INTO temp._v2_home_map SELECT e.record_id,json_extract(e.payload,'$.source_record_id') FROM temp._v2_scopes h CROSS JOIN main.content_events e ON e.record_id=h.home_id AND e.type IN ('kernel.import_home.v1','kernel.home_created.v1') WHERE json_extract(e.payload,'$.source_record_id') IS NOT NULL";

/// Frozen app bundles use the v1-versioned public headers for counts and invalidation.
/// Derive them from adjacent authoritative states, never from private-lane
/// writes. No replacement payload enters TEMP SQL or the ordinary event feed.
async fn install_reaction_headers(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    root_visible: bool,
    bounded: bool,
    after: i64,
    oracle_only: bool,
) -> Result<()> {
    // No messages means no reaction transitions, including on ordinary
    // scans of document-only workspaces. Avoid preparing the state window.
    let messages: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_messages m JOIN temp._v2_visible v ON v.id=m.message_id)")
        .fetch_one(&mut *tx).await?;
    if !messages {
        return Ok(());
    }
    if bounded {
        let transitions: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM temp._v2_history_candidates c CROSS JOIN main.content_events e ON e.seq=c.seq JOIN main.kernel_messages m ON m.message_id=e.record_id JOIN temp._v2_visible v ON v.id=m.message_id WHERE e.type='kernel.message_state.v1')")
            .fetch_one(&mut *tx).await?;
        if !transitions {
            return Ok(());
        }
    }
    // Drive bounded reads from selected positions. An IN over positions
    // inside a message-driven join lets SQLite probe every position for
    // every visible message, even though only a tiny window is requested.
    let scoped: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_temp_master WHERE name='_v2_event_subjects')",
    )
    .fetch_one(&mut *tx)
    .await?;
    let source = if bounded {
        "FROM temp._v2_history_candidates c CROSS JOIN main.content_events e ON e.seq=c.seq CROSS JOIN main.kernel_messages m ON m.message_id=e.record_id CROSS JOIN temp._v2_visible v ON v.id=m.message_id"
    } else {
        "FROM main.kernel_messages m JOIN temp._v2_visible v ON v.id=m.message_id CROSS JOIN main.content_events e"
    };
    let subjects = if scoped {
        " AND m.message_id IN (SELECT id FROM temp._v2_event_subjects)"
    } else {
        ""
    };
    // Only the immediately preceding authoritative state is needed for a
    // closed window. The unbounded path retains its complete LAG window.
    let previous = if bounded {
        // An explicit alias keeps JSON paths intact (notably $.state.message).
        let state = kernel::messaging::PREVIOUS_STATE_JSON_SQL;
        format!("(SELECT json_extract({state},'$.reactions') FROM main.content_events p WHERE p.record_id=states.record_id AND p.seq<states.seq AND p.type IN {} AND json_type({state})='object' ORDER BY p.seq DESC LIMIT 1)",kernel::messaging::STATE_EVENTS_SQL)
    } else {
        "lag(reactions) OVER (PARTITION BY record_id ORDER BY seq)".to_owned()
    };
    // Retain the full LAG window for sparse oracle/tail staging: earlier
    // authoritative states can raise JSON errors even when not predecessors
    // of selected positions. Restricting evaluation would change that behavior.
    let remainder = if oracle_only {
        "seq IN (SELECT seq FROM temp._v2_oracle_events) AND ?3>=0"
    } else {
        "seq>?3"
    };
    sqlx::query(&format!(r#"WITH states AS (
      SELECT e.seq,e.id,e.record_id,e.type,e.actor,e.run_key,e.parent_key,e.created_at,
       json_extract({state_json},'$.reactions') AS reactions
      {source}
      WHERE e.record_id=m.message_id {subjects} AND e.type IN {state_events}
       AND json_type({state_json})='object'
     ), transitions AS (
      SELECT *,{previous} AS previous FROM states
     ), changes AS (
      SELECT *,
       EXISTS(SELECT p.key,emoji.value FROM json_each(reactions) p,json_each(p.value) emoji
        EXCEPT SELECT p.key,emoji.value FROM json_each(previous) p,json_each(p.value) emoji) AS added,
       EXISTS(SELECT p.key,emoji.value FROM json_each(previous) p,json_each(p.value) emoji
        EXCEPT SELECT p.key,emoji.value FROM json_each(reactions) p,json_each(p.value) emoji) AS removed
      FROM transitions WHERE type='kernel.message_state.v1' AND previous IS NOT NULL
     )
     INSERT INTO temp._v2_event_rows
     SELECT seq,id,record_id,
      CASE WHEN added THEN 'message.reaction.added.v1' ELSE 'message.reaction.removed.v1' END,
      CASE WHEN ?1 OR actor=?2 OR EXISTS(SELECT 1 FROM main.kernel_message_people mp JOIN temp._v2_visible v ON v.id=mp.person_id WHERE mp.principal_id=changes.actor) THEN actor END,
      CASE WHEN ?1 THEN run_key END,CASE WHEN ?1 THEN parent_key END,
      CASE WHEN ?1 OR actor=?2 THEN 'unknown' END,
      created_at,NULL
     FROM changes WHERE (added OR removed) AND {remainder}"#, state_json=kernel::messaging::STATE_JSON_SQL, state_events=kernel::messaging::STATE_EVENTS_SQL))
        .bind(root_visible).bind(actor).bind(after).execute(tx).await?;
    Ok(())
}

pub(crate) async fn install(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    reads: &BTreeSet<(String, String)>,
) -> Result<()> {
    install_relations(
        tx,
        actor,
        reads,
        LinkScope::All,
        None,
        None,
        None,
        None,
        None,
        chrono::Utc::now().timestamp_millis(),
        false,
        None,
        None,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn install_relations(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    reads: &BTreeSet<(String, String)>,
    link_scope: LinkScope,
    candidates: Option<ReadCandidates<'_>>,
    history_window: Option<HistoryWindow>,
    record_limit: Option<i64>,
    exact_record_ids: Option<&[String]>,
    class_scope: Option<&record_classes::Plan>,
    observed_ms: i64,
    project_facet_columns: bool,
    catalogue: Option<&crate::query::principal::CatalogOperationsSnapshot>,
    event_cache_generation: Option<i64>,
    record_cache_generation: Option<&str>,
) -> Result<()> {
    #[cfg(test)]
    let _ = STATS.try_with(|s| s.borrow_mut().installations += 1);
    if reads.iter().any(|(r, _)| r == "catalog_operations") && catalogue.is_none() {
        return Err(contract::categorized_error(
            contract::QuerySqlErrorCategory::UnauthorizedRelation,
            "catalog_operations requires the serving executor catalogue",
        ));
    }
    let schema_started = Instant::now();
    sqlx::query(DDL).persistent(false).execute(&mut *tx).await?;
    if reads.iter().any(|(r, _)| r == "catalog_operations") {
        let snapshot = catalogue.ok_or_else(|| {
            contract::categorized_error(
                contract::QuerySqlErrorCategory::UnauthorizedRelation,
                "catalog_operations requires the serving executor catalogue",
            )
        })?;
        sqlx::query("INSERT INTO temp.catalog_operations SELECT value ->> 'executor', value ->> 'operation', value ->> 'surface', value ->> 'access', json_extract(value, '$.plan_required'), json_extract(value, '$.direct_execution_enabled'), value ->> 'contract_version', value ->> 'contract_digest', value ->> 'source_tool', value ->> 'selector_field', value ->> 'selector_value', json_extract(value, '$.advertised_directly'), json_extract(value, '$.requires_acceptance') FROM json_each(?)")
            .bind(serde_json::to_string(snapshot.as_slice())?)
            .execute(&mut *tx).await?;
    }

    sqlx::query(&records_ddl())
        .persistent(false)
        .execute(&mut *tx)
        .await?;
    sqlx::query(&events_ddl())
        .persistent(false)
        .execute(&mut *tx)
        .await?;
    tracing::debug!(target: "native_ce::read_staging", phase = "sql_temp_schema", elapsed_us = schema_started.elapsed().as_micros() as u64);
    sqlx::query("INSERT INTO temp._v2_viewer_principal VALUES(?)")
        .bind(actor)
        .execute(&mut *tx)
        .await?;
    let needs = |relation: &str| reads.iter().any(|(r, _)| r == relation);
    if needs("bindings") {
        // Keep main's caller-scoped portable/catalog aliases. The native
        // principal is also a verified alias for current_principal(), as the
        // typed Messages feed expects; never stage another member's bindings.
        let mut bindings = super::identity_read::sql_bindings_on(tx, actor).await?;
        if let Some((person, _)) = bindings.first() {
            let native = (person.clone(), actor.to_owned());
            if !bindings.contains(&native) {
                bindings.push(native);
            }
        }
        for (person, identifier) in bindings {
            // This caller-relative view has one canonical native identifier.
            // Portable/catalog identifiers remain verified lookup aliases;
            // they are not fabricated canonical native principals.
            let canonical = i64::from(identifier == actor);
            sqlx::query("INSERT INTO temp.bindings VALUES(?,'account',?,?)")
                .bind(person)
                .bind(identifier)
                .bind(canonical)
                .execute(&mut *tx)
                .await?;
        }
    }
    let column = |name: &str| reads.contains(&("records".into(), name.into()));
    let needs_events = needs("content_events") || needs("actors");
    let needs_records = [
        "records",
        "blobs",
        "links",
        "facet_values",
        "facet_observations",
        "facet_times",
        "content_events",
        "actors",
        "viewer",
        "comment_anchors",
        "record_lifecycle_interpretations",
        "agent_activity_claims",
        "bindings",
        "message_reactions",
        "my_mentions",
        "my_message_state",
        "messages_awaiting_reply",
    ]
    .iter()
    .any(|r| needs(r));
    // Viewer-only reads need visibility checks for this principal's possible
    // people, rather than every record in the workspace. Keep the same join
    // precedence as the relation, including its directory/person fallback.
    let viewer_record_ids: Option<Vec<String>> = if !reads.is_empty()
        && reads.iter().all(|(relation, _)| relation == "viewer")
    {
        Some(sqlx::query_scalar("SELECT DISTINCT coalesce(d.record_id,mp.person_id) FROM main.kernel_principals p LEFT JOIN main.kernel_v1_state d ON d.section='account_directory' AND d.account_principal=p.principal_id LEFT JOIN main.kernel_message_people mp ON mp.principal_id=p.principal_id WHERE p.principal_id=? AND coalesce(d.record_id,mp.person_id) IS NOT NULL")
            .bind(actor).fetch_all(&mut *tx).await?)
    } else {
        None
    };
    let exact_record_ids = viewer_record_ids.as_deref().or(exact_record_ids);
    // A finite scope that accepted a closed home-ID self-join chain stages
    // the chain's logical-placement fixpoint; otherwise it stages in full.
    let plan = demand::current();
    if exact_record_ids.is_some() && (plan.exact_body || plan.docs_page) {
        demand::mark_attempt();
    }
    let closed_chain = match exact_record_ids {
        Some(ids) if plan.home_chain && viewer_record_ids.is_none() => {
            Some(Box::pin(demand::placement_closure(tx, ids)).await?)
        }
        _ => None,
    };
    let exact_record_ids = match &closed_chain {
        Some(Some(ids)) => Some(ids.as_slice()),
        Some(None) => None,
        None => exact_record_ids,
    };
    let demand_shape = (exact_record_ids.is_some()
        && viewer_record_ids.is_none()
        && candidates.is_none()
        && history_window.is_none()
        && class_scope.is_none()
        && record_limit.is_none()
        && reads
            .iter()
            .all(|(r, _)| r == "records" || r == "facet_values"))
    .then(|| {
        if column("home_id") {
            demand::Shape::DocsPage
        } else {
            demand::Shape::ExactBody
        }
    })
    .filter(|shape| plan.allows(*shape));
    let mut demand_candidates: Option<Vec<String>> = None;
    let needs_runs = needs("runs") || needs("run_intents") || needs("agent_activity_claims");
    let mut root_visible = false;
    if needs_records {
        // Authorize requested anchors in this same snapshot before their raw
        // structural relations can influence staging (including timing).
        let candidate_names = match candidates {
            Some(ReadCandidates::Names(names)) => Some(names),
            _ => None,
        };
        let candidate_ids = if let Some(ReadCandidates::Anchors(ids)) = candidates {
            let mut allowed = BTreeSet::new();
            for id in ids.iter().collect::<BTreeSet<_>>() {
                let root = [crate::events::KERNEL_ROOT_ID, "native:root"].contains(&id.as_str());
                let visible = kernel::read_record_on(tx, actor, id).await?.is_some()
                    || (root
                        && kernel::kernel_effective_capability_on(
                            tx,
                            actor,
                            crate::events::KERNEL_ROOT_ID,
                        )
                        .await?
                        .allows(Capability::View));
                if visible {
                    allowed.insert(id.clone());
                    if root {
                        allowed.extend([
                            crate::events::KERNEL_ROOT_ID.to_owned(),
                            "native:root".to_owned(),
                        ]);
                    }
                }
            }
            Some(serde_json::to_string(&allowed)?)
        } else {
            None
        };
        // A pre-upgrade importer may append while this handle stays open.
        // Never serve incomplete logical headers or invented birth times.
        let frontier_started = Instant::now();
        kernel::legacy_history::require_sql_frontier_on(&mut *tx).await?;
        tracing::debug!(target: "native_ce::read_staging", phase = "legacy_frontier", elapsed_us = frontier_started.elapsed().as_micros() as u64);

        let scopes_started = Instant::now();
        let scope = match (demand_shape, exact_record_ids) {
            (Some(shape), Some(ids)) => {
                // The logical-home cell admits placement dependencies below
                // with this same decision, joins or not. Their authority
                // homes and Message proof must be loaded with the demand.
                let dependencies = if column("home_id") {
                    Box::pin(demand::placement_dependencies(tx, ids)).await?
                } else {
                    Vec::new()
                };
                match Box::pin(kernel::demand_visibility::demand_home_anchors_as(
                    tx,
                    actor,
                    ids,
                    &dependencies,
                    demand::root_aliases(),
                ))
                .await?
                {
                    kernel::demand_visibility::Demand::Scope(demanded) => {
                        demand::selected(shape);
                        demand_candidates = Some(demanded.staged);
                        #[cfg(test)]
                        let _ = STATS.try_with(|s| {
                            s.borrow_mut().demand = Some(match shape {
                                demand::Shape::ExactBody => "exact_body",
                                demand::Shape::DocsPage => "docs_page",
                            })
                        });
                        let _ = shape;
                        demanded.homes
                    }
                    kernel::demand_visibility::Demand::Fallback(_reason) => {
                        #[cfg(test)]
                        let _ = STATS.try_with(|s| s.borrow_mut().demand = Some(_reason));
                        Box::pin(kernel::visible_home_anchors_as(tx, actor)).await?
                    }
                }
            }
            _ => Box::pin(kernel::visible_home_anchors_as(tx, actor)).await?,
        };
        #[cfg(test)]
        let _ = STATS.try_with(|s| {
            let mut s = s.borrow_mut();
            s.visibility_us += scopes_started.elapsed().as_micros() as u64;
            s.home_checks = scope.homes.len();
            s.failed_homes = scope.failed_homes;
        });
        let mut home_rows = Vec::with_capacity(scope.homes.len());
        for home in scope.homes {
            if home.home_id == crate::events::KERNEL_ROOT_ID {
                root_visible = home.home_view;
            }
            home_rows.push((
                home.home_id,
                home.policy_valid,
                home.policy_view,
                home.home_view,
            ));
        }
        for batch in home_rows.chunks(256) {
            sqlx::query("INSERT INTO temp._v2_scopes SELECT json_extract(value,'$[0]'),json_extract(value,'$[1]'),json_extract(value,'$[2]'),json_extract(value,'$[3]') FROM json_each(?)")
                .bind(serde_json::to_string(batch)?).execute(&mut *tx).await?;
        }
        tracing::debug!(target: "native_ce::read_staging", phase = "scopes", elapsed_us = scopes_started.elapsed().as_micros() as u64);
        let visible_started = Instant::now();
        let map_started = Instant::now();
        if column("home_id")
            || (exact_record_ids.is_some() && needs("record_lifecycle_interpretations"))
        {
            sqlx::query(HOME_MAP_SQL).execute(&mut *tx).await?;
            // The importer does not create a record for the structural v1 root;
            // its sealed root policy import witnesses that logical home mapping.
            sqlx::query("INSERT OR IGNORE INTO temp._v2_home_map SELECT ?1,'native:root' WHERE EXISTS(SELECT 1 FROM main.kernel_records WHERE id='native:root') OR EXISTS(SELECT 1 FROM main.content_events WHERE record_id=?1 AND type='kernel.import_home_policy.v1')").bind(crate::events::KERNEL_ROOT_ID).execute(&mut *tx).await?;
        }
        tracing::debug!(target:"native_ce::read_staging",phase="home_map",elapsed_us=map_started.elapsed().as_micros() as u64);
        // Single set operation; no per-record authority, field reads or inserts.
        let identity = column("type") || column("kind") || needs("my_mentions") || needs("blobs");
        let creation = column("created_at") || column("created_at_ms") || needs("my_mentions");
        let projection = if identity {
            "r.primary_type,r.kind,r.pin_family,r.pin_version"
        } else {
            "NULL,NULL,NULL,NULL"
        };
        let creation = if creation {
            "COALESCE((SELECT json_extract(m.state,'$.created_at') FROM kernel_messages m WHERE m.message_id=r.id),r.created_at)"
        } else {
            "NULL"
        };
        // Omit the recursive per-row Message gate only when this same read
        // snapshot proves there are no sealed OR unsealed Message records.
        // The second probe preserves fail-closed reads of missing audience
        // state; it is intentionally independent of the public type carrier.
        let has_messages: bool = match &demand_candidates {
            Some(candidates) => {
                Box::pin(demand::has_messages_for(
                    tx,
                    actor,
                    candidates,
                    "SELECT home_id AS id,policy_view AS view FROM temp._v2_scopes WHERE valid",
                ))
                .await?
            }
            None => {
                sqlx::query_scalar(demand::HAS_MESSAGES_SQL)
                    .fetch_one(&mut *tx)
                    .await?
            }
        };
        let visibility = kernel::sql_record_visible(
            "r",
            "?1",
            "SELECT home_id AS id,policy_view AS view FROM temp._v2_scopes WHERE valid",
            has_messages,
        );
        // This is a structural superset for Get's closed enrichment queries,
        // not an authorization gate. Annotation windows only consume direct
        // part_of sources of requested subjects, not unrelated annotations.
        // All candidates pass the unchanged kernel
        // visibility predicates below. Include every self-home and any record
        // historically moved into a requested logical parent. A later move
        // away may overselect a candidate; the latest placement below still
        // determines child membership. Physical destinations alone cannot
        // identify these children: private records retain their own ACL home.
        let candidates = if exact_record_ids.is_some() {
            "r.id IN (SELECT value FROM json_each(?2))"
        } else if candidate_names.is_some() {
            // Nonempty logical names are coalesce(title,name,''). Either
            // stored field can nominate a candidate, including a shadowed
            // name; the unchanged caller predicate resolves precedence.
            "r.id IN (SELECT f.record_id FROM main.kernel_record_fields f WHERE f.name IN ('title','name') AND json_extract(f.value_json,'$') COLLATE BINARY IN (SELECT value FROM json_each(?2)))"
        } else if candidate_ids.is_some() {
            "r.id IN (SELECT value FROM json_each(?2) UNION SELECT id FROM main.kernel_records WHERE home_id IN (SELECT value FROM json_each(?2)) UNION SELECT id FROM main.kernel_records WHERE home_id IN (SELECT home_id FROM temp._v2_home_map WHERE record_id IN (SELECT value FROM json_each(?2))) UNION SELECT record_id FROM temp._v2_home_map UNION SELECT root_id FROM main.kernel_roots UNION SELECT id FROM main.kernel_records WHERE primary_type='Collection' UNION SELECT record_id FROM main.kernel_record_fields WHERE name='v1_type' AND value_json IN ('\"Annotation\"','\"Collection\"') AND value_json='\"Collection\"' UNION SELECT source_id FROM main.kernel_generic_links WHERE active=1 AND relationship='part_of' AND target_id IN (SELECT value FROM json_each(?2)) UNION SELECT source_id FROM main.kernel_links WHERE relationship='part_of' AND target_id IN (SELECT value FROM json_each(?2)) UNION SELECT source_id FROM main.kernel_link4_edges WHERE predicate='part_of' AND target_id IN (SELECT value FROM json_each(?2)) UNION SELECT record_id FROM main.content_events INDEXED BY idx_kernel_record_logical_homes WHERE type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2') AND json_extract(payload,'$.logical_home_id') IN (SELECT value FROM json_each(?2)))"
        } else if let Some(scope) = class_scope {
            &scope.predicate
        } else {
            "1"
        };
        #[cfg(test)]
        let candidates = if candidate_ids.is_some()
            && exact_record_ids.is_none()
            && ALL_MOVED_CANDIDATES.try_with(|_| ()).is_ok()
        {
            "r.id IN (SELECT value FROM json_each(?2) UNION SELECT id FROM main.kernel_records WHERE home_id IN (SELECT value FROM json_each(?2)) UNION SELECT id FROM main.kernel_records WHERE home_id IN (SELECT home_id FROM temp._v2_home_map WHERE record_id IN (SELECT value FROM json_each(?2))) UNION SELECT record_id FROM temp._v2_home_map UNION SELECT root_id FROM main.kernel_roots UNION SELECT id FROM main.kernel_records WHERE primary_type='Collection' UNION SELECT record_id FROM main.kernel_record_fields WHERE name='v1_type' AND value_json IN ('\"Annotation\"','\"Collection\"') AND value_json='\"Collection\"' UNION SELECT source_id FROM main.kernel_generic_links WHERE active=1 AND relationship='part_of' AND target_id IN (SELECT value FROM json_each(?2)) UNION SELECT source_id FROM main.kernel_links WHERE relationship='part_of' AND target_id IN (SELECT value FROM json_each(?2)) UNION SELECT source_id FROM main.kernel_link4_edges WHERE predicate='part_of' AND target_id IN (SELECT value FROM json_each(?2)) UNION SELECT record_id FROM main.content_events INDEXED BY idx_kernel_record_moves WHERE type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2'))"
        } else {
            candidates
        };
        let prefix = record_limit
            .map(|n| format!(" ORDER BY r.id LIMIT {n}"))
            .unwrap_or_default();
        #[cfg(test)]
        let visibility = if demand_candidates.is_some() && demand::broken_admission() {
            "1".to_owned()
        } else {
            visibility
        };
        let staging = format!("INSERT INTO temp._v2_visible SELECT r.id,r.home_id,{projection},{creation} FROM main.kernel_records r WHERE ({candidates}) AND ({visibility}){prefix}");
        #[cfg(all(test, feature = "v2-kernel-probe"))]
        let diagnostic_input =
            if read_diagnostics::active() && history_window.is_none() && exact_record_ids.is_none()
            {
                if let Some(names) = candidate_names {
                    Some(("names", serde_json::to_string(names)?))
                } else {
                    candidate_ids.as_ref().map(|ids| ("moves", ids.clone()))
                }
            } else {
                None
            };
        // Scoped entries are keyed by the person's canonical folder grant.
        // A broader known set is narrowed before seeding a new grant entry.
        let scoped_app = scoped_app_folders_on(tx, actor).await?;
        // Full staging only: no candidates, exact ids, names, class scope,
        // record limit or history window.
        let cache = (candidates == "1"
            && record_limit.is_none()
            && history_window.is_none()
            && exact_record_ids.is_none())
        .then(visible_cache::current)
        .flatten();
        let cache_snapshot = match &cache {
            Some(_) => Some(visible_cache::snapshot_on(tx).await?),
            None => None,
        };
        let cache_plan = match (&cache, cache_snapshot) {
            (Some(ctx), Some(snap)) => {
                Some(visible_cache::plan(tx, ctx, actor, has_messages, &visibility, snap).await?)
            }
            _ => None,
        };
        let staging = match &cache_plan {
            Some(visible_cache::Plan::Use(_)) => format!("INSERT INTO temp._v2_visible SELECT r.id,r.home_id,{projection},{creation} FROM main.kernel_records r WHERE ?1 IS NOT NULL AND r.id IN (SELECT value FROM json_each(?2))"),
            _ => staging,
        };
        // Cache cost is timed from here: serialising cached ids, or the full
        // gate plus publishing its result on a miss.
        let cache_stage_started = Instant::now();
        let mut query = sqlx::query(&staging).bind(actor);
        if let Some(visible_cache::Plan::Use(ids)) = &cache_plan {
            query = query.bind(serde_json::to_string(&**ids)?);
        } else if let Some(ids) = exact_record_ids {
            query = query.bind(serde_json::to_string(ids)?);
        } else if let Some(names) = candidate_names {
            query = query.bind(serde_json::to_string(names)?);
        } else if let Some(ids) = candidate_ids {
            query = query.bind(ids);
        } else if let Some(scope) = class_scope {
            for parameter in &scope.parameters {
                query = query.bind(parameter);
            }
        }
        let staging_started = Instant::now();
        // Global history stages only each candidate window's direct subjects
        // below. Its closed callback consumes event headers, never records.
        let count = if history_window.is_some() {
            0
        } else {
            query.execute(&mut *tx).await?.rows_affected()
        };
        if let (Some(ctx), Some(snap), Some(visible_cache::Plan::Miss { publish: true })) =
            (&cache, cache_snapshot, &cache_plan)
        {
            visible_cache::publish_staged(tx, ctx, actor, has_messages, snap).await?;
        }
        if let Some(ctx) = &cache {
            visible_cache::record_stage(
                ctx,
                matches!(cache_plan, Some(visible_cache::Plan::Use(_))),
                cache_stage_started.elapsed(),
            );
        }
        #[cfg(all(test, feature = "v2-kernel-probe"))]
        if let Some((kind, input)) = diagnostic_input {
            read_diagnostics::on_candidates(
                tx,
                actor,
                kind,
                &input,
                candidates,
                &visibility,
                &staging,
                count,
            )
            .await?;
        }
        let currency_dependencies =
            exact_record_ids.is_some() && (column("is_current") || column("successor_count"));
        if currency_dependencies {
            // Freeze the one-hop frontier while _v2_visible contains ONLY
            // admitted requested targets. Neither placement dependencies nor
            // newly admitted successors may expand it. This is the exact
            // active-generic-link definition used by records' currency cells;
            // the candidate table grants no visibility by itself.
            sqlx::query("CREATE TEMP TABLE _v2_currency_candidates AS SELECT DISTINCT l.source_id AS id FROM temp._v2_visible target CROSS JOIN main.kernel_generic_links l ON l.target_id=target.id AND l.relationship='supersedes' AND l.active=1")
                .execute(&mut *tx).await?;
        }
        // The wide pulse also discloses logical placement. Admit only its
        // direct placement dependencies with the SAME kernel endpoint gate.
        // They cannot become caller rows: the original IN predicate remains.
        let dependency_count = if exact_record_ids.is_some()
            && (column("home_id") || needs("record_lifecycle_interpretations"))
        {
            // Lifecycle interpretation also needs the source record bearing
            // the policy home, even when its logical folder differs.
            let policy_bearers = if needs("record_lifecycle_interpretations") {
                " UNION SELECT h.record_id FROM temp._v2_visible v JOIN temp._v2_home_map h ON h.home_id=v.home_id"
            } else {
                ""
            };
            sqlx::query(&format!("CREATE TEMP TABLE _v2_home_candidates AS SELECT DISTINCT candidate AS id FROM ({}){policy_bearers}", logical_home_placement_sql()))
                .execute(&mut *tx).await?;
            sqlx::query(&format!("INSERT OR IGNORE INTO temp._v2_visible SELECT r.id,r.home_id,{projection},{creation} FROM main.kernel_records r WHERE r.id IN (SELECT id FROM temp._v2_home_candidates) AND ({visibility})"))
                .bind(actor).execute(&mut *tx).await?.rows_affected()
        } else {
            0
        };
        let currency_count = if currency_dependencies {
            // A successor contributes only its independently authorized
            // existence. Its own currency and placement are not observed by
            // the closed finite-ID query, so no recursive closure is needed.
            sqlx::query(&format!("INSERT OR IGNORE INTO temp._v2_visible SELECT r.id,r.home_id,{projection},{creation} FROM main.kernel_records r WHERE r.id IN (SELECT id FROM temp._v2_currency_candidates) AND ({visibility})"))
                .bind(actor).execute(&mut *tx).await?.rows_affected()
        } else {
            0
        };
        let count = count + dependency_count + currency_count;
        // A folder-scoped app never sees Message records (audience rules,
        // not folders) nor records deriving authority from one, even when
        // the message is filed inside a granted folder.
        if scoped_app {
            sqlx::query(
                "DELETE FROM temp._v2_visible WHERE id IN (
                   WITH RECURSIVE excluded(id) AS (
                     SELECT id FROM main.kernel_records WHERE primary_type='Message'
                     UNION SELECT message_id FROM main.kernel_messages
                     UNION SELECT record_id FROM main.kernel_record_fields
                            WHERE name='v1_type' AND value_json='\"Message\"'
                     UNION
                     SELECT l.source_id FROM main.kernel_generic_links l
                       JOIN excluded e ON e.id=l.target_id
                      WHERE l.relationship='part_of' AND l.active=1
                   ) SELECT id FROM excluded)",
            )
            .execute(&mut *tx)
            .await?;
        }
        if demand_candidates.is_some() {
            Box::pin(demand::recheck(tx, actor)).await?;
        }
        tracing::debug!(target:"native_ce::read_staging",phase="visibility_gate",elapsed_us=staging_started.elapsed().as_micros() as u64,records=count);
        #[cfg(test)]
        let _ = STATS.try_with(|s| {
            let mut s = s.borrow_mut();
            s.visibility_us += visible_started.elapsed().as_micros() as u64;
            s.staged_records = count;
            s.staged_currency_records = currency_count;
            s.staged_metadata_records = if identity || creation != "NULL" {
                count
            } else {
                0
            };
        });
        #[cfg(not(test))]
        let _ = count;
        tracing::debug!(target: "native_ce::read_staging", phase = "visible_records", elapsed_us = visible_started.elapsed().as_micros() as u64);
    } else if needs_runs {
        root_visible =
            kernel::kernel_effective_capability_on(tx, actor, crate::events::KERNEL_ROOT_ID)
                .await
                .unwrap_or(Capability::None)
                .allows(Capability::View);
    }
    if needs("records") {
        record_projection::install(
            tx,
            reads,
            record_cache_generation,
            demand_candidates.is_some(),
        )
        .await?;
    }
    let relations_started = Instant::now();
    if column("home_id") {
        // A folder-scoped app already holds its grant's folder ids. The
        // folder record itself may sit in a home outside the grant (so it is
        // not staged), yet it is the authorised logical home of the rows the
        // grant admits. Its id, and nothing else about it, passes the mask.
        let authorized = kernel::app_scope_authorized_homes_on(tx, actor).await?;
        if !authorized.is_empty() {
            sqlx::query(
                "INSERT OR IGNORE INTO temp._v2_authorized_homes SELECT value FROM json_each(?)",
            )
            .bind(serde_json::to_string(&authorized)?)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(&logical_home_rows_sql())
            .execute(&mut *tx)
            .await?;
    }
    if (needs("links") && link_scope == LinkScope::All)
        || (needs_events && history_window.is_none())
    {
        stage_visible_providers(tx).await?;
    }
    if needs("facet_values") {
        // Internal readers may declare only relation dependencies. Only SQL
        // admission supplies an authoritative set of consumed columns.
        let rows = if project_facet_columns {
            facets::rows_sql(reads)
        } else {
            FACET_ROWS.to_owned()
        };
        // A finite admitted set drives facet lookups from its own IDs, so
        // SQLite cannot choose a scan of every facet row.
        let rows = if demand_shape.is_some() {
            rows.replace(
                "FROM main.kernel_facets f JOIN temp._v2_visible v ON v.id=f.record_id",
                "FROM temp._v2_visible v CROSS JOIN main.kernel_facets f ON f.record_id=v.id",
            )
        } else {
            rows
        };
        sqlx::query(&rows).execute(&mut *tx).await?;
    }
    if needs("facet_observations") {
        let ids = observation_scope::current();
        let statement = facet_observation_rows(ids.is_some());
        let mut query = sqlx::query(&statement).persistent(false);
        if let Some(ids) = ids {
            query = query.bind(ids);
        }
        query.execute(&mut *tx).await?;
    }
    if needs("facet_times") {
        facet_times::stage(tx).await?;
    }
    if needs("links") {
        install_link_view(tx, reads, link_scope).await?;
    }
    tracing::debug!(target: "native_ce::read_staging", phase = "home_links", elapsed_us = relations_started.elapsed().as_micros() as u64);
    if needs_events {
        sqlx::query("INSERT INTO temp._v2_event_disclosure VALUES(?,?)")
            .bind(actor)
            .bind(root_visible)
            .execute(&mut *tx)
            .await?;
        if let Some(window) = history_window {
            install_history_window(tx, actor, root_visible, window).await?;
        } else if event_scope::stage(tx, actor).await? {
            select_event_ids(tx, true).await?;
            install_events(tx, actor, root_visible, false).await?;
        } else if !event_projection::install(tx, actor, root_visible, event_cache_generation)
            .await?
        {
            select_event_ids(tx, false).await?;
            install_events(tx, actor, root_visible, false).await?;
        }
        #[cfg(test)]
        let _index_phase = event_profile::Phase::new("event_index");
        sqlx::query(
            "CREATE INDEX temp._v2_event_record_type ON _v2_event_rows(record_id,type,local_seq)",
        )
        .execute(&mut *tx)
        .await?;
    }
    if needs("blobs") {
        // A byte handle is public only through a visible, live Document
        // attachment with its exact engine-owned blob_ref. Group references
        // before joining bytes: metadata-only needs never materialize blobs.
        sqlx::query("CREATE TEMP VIEW blobs AS SELECT a.handle AS id,b.bytes,json_extract(a.metadata,'$.mime') AS mime,b.size_bytes,b.sha256,json_extract(a.metadata,'$.original_filename') AS original_filename,json_extract(a.metadata,'$.storage_tier') AS storage_tier,NULL AS external_ref,json_extract(a.metadata,'$.created_at') AS created_at,CAST((julianday(json_extract(a.metadata,'$.created_at'))-2440587.5)*86400000 AS INTEGER) AS created_at_ms FROM (SELECT json_extract(a.metadata,'$.id') AS handle,a.metadata,a.sha256 FROM main.kernel_attachment_blobs a JOIN temp.records r ON r.id=a.record_id JOIN main.kernel_facets f ON f.record_id=a.record_id AND f.key='blob_ref' AND f.value=json_extract(a.metadata,'$.id') WHERE r.type='Document' AND r.kind='attachment' AND r.deleted_at IS NULL GROUP BY json_extract(a.metadata,'$.id')) a JOIN main.kernel_blobs b ON b.sha256=a.sha256")
            .execute(&mut *tx).await?;
    }
    install_imported_catalogue(tx, actor, reads).await?;
    if needs("my_message_state")
        || needs("messages_awaiting_reply")
        || needs("message_reactions")
        || needs("my_mentions")
    {
        install_messaging(
            tx,
            actor,
            needs("my_message_state"),
            needs("messages_awaiting_reply"),
            needs("message_reactions"),
            needs("my_mentions"),
        )
        .await?;
    }

    if needs("agent_activity") {
        activity::install(tx, actor, observed_ms).await?;
    }
    if needs_runs {
        install_runs(tx, actor, root_visible, needs("run_intents")).await?;
        install_imported_runs(
            tx,
            actor,
            root_visible,
            needs("run_intents"),
            needs("agent_activity_claims"),
        )
        .await?;
    }
    #[cfg(test)]
    let _ = STATS.try_with(|s| {
        s.borrow_mut().staged_relations = [
            "records",
            "links",
            "facet_values",
            "facet_observations",
            "facet_times",
            "content_events",
            "agent_activity",
            "runs",
            "run_intents",
            "vocabularies",
            "vocabulary_values",
            "record_lifecycle_interpretations",
            "agent_activity_claims",
        ]
        .iter()
        .filter(|r| needs(r))
        .count()
    });
    if needs("catalog_relations") || needs("catalog_columns") || needs("catalog_view_definitions") {
        for relation in contract::LOGICAL_RELATIONS {
            let Some(supported) = columns(relation.name) else {
                continue;
            };
            sqlx::query("INSERT INTO temp.catalog_relations VALUES(?,?,?,?,?,?,?)")
                .bind(relation.name).bind(relation.identity).bind(relation.semantic_version as i64).bind(relation.caller_relative)
                .bind("best_effort").bind("sqlite-local-v2")
                .bind("v2 probe; catalog_columns lists the supported columns. Bindings expose only the caller's visible verified Person with its portable account and stored H3 catalogue aliases; email, canonical flags and provider timestamps are not represented. Bodies lazy. Home is the visible logical folder, or native home id. Currency counts visible active supersedes sources; is_current is 1 or NULL. Generic links retain ids/notes/times; provider links retain each directed legacy source identity, note and claimed timestamp (or assertion time). Native provider assertions without legacy sources expose the symmetric pair with stable ids and assertion time. Facet value timestamps use as_of; facet_times follows v1 current typed writes and excludes observation-only writes. Native event attribution uses self/root-directory admission; legacy attribution requires self or View on the verified Person and retains v1:. Logical create/update types and retained content headers are exposed; migration receipts are omitted. channel_kind is unknown until provenance admission. Actor names/person IDs use visible verified imported Persons when available, otherwise labels may be placeholders. Anchor positions retain their source namespace without a coedit cut proof. Native runs use self/root-directory admission and NULL person/model/client fields. Imported runs/intents require self or a visible verified imported Person; known principal_person_id is retained; imported runs preserve declarations, use model_assurance imported_historical and ended_at_ms at the source close or snapshot boundary. Imported claims are historical, is_current=0 and released at the source release or snapshot boundary; they never occupy the live claims lane. Imported creation times retain source birth; native creation time stays separate; deletion times NULL.")
                .execute(&mut *tx).await?;
            for (position, column) in supported.iter().enumerate() {
                sqlx::query("INSERT INTO temp.catalog_columns VALUES(?,?,?)")
                    .bind(relation.name)
                    .bind(*column)
                    .bind(position as i64)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    Ok(())
}

// The subject table is keyed by (subject_id,aggregate_id). Group once in
// this authority snapshot; a correlated aggregate_id probe per provider would
// scan the entire subject table repeatedly. A provider with no subjects is
// absent, and one hidden endpoint excludes the whole provider, as before.
async fn stage_visible_providers(tx: &mut sqlx::SqliteConnection) -> Result<()> {
    sqlx::query("INSERT INTO temp._v2_visible_providers SELECT s.aggregate_id FROM main.kernel_provider_subjects s LEFT JOIN temp._v2_visible v ON v.id=s.subject_id GROUP BY s.aggregate_id HAVING count(v.id)=count(*)")
        .execute(tx).await?;
    Ok(())
}

/// Keep the disclosure barrier, but let SQLite build its narrow ephemeral
/// rows once for the caller statement. Eagerly copying every link into another
/// TEMP table plus two indexes dominated joins which only consume endpoints.
/// MATERIALIZED prevents caller expressions from moving below the live gates.
async fn install_link_view(
    tx: &mut sqlx::SqliteConnection,
    reads: &BTreeSet<(String, String)>,
    scope: LinkScope,
) -> Result<()> {
    // Composed Get/render sessions consume the same closed relation repeatedly.
    // Keep their one-time materialization instead of rebuilding a CTE per id.
    if scope != LinkScope::All {
        let predicate = if scope == LinkScope::PartOf {
            "l.relationship='part_of'"
        } else {
            "l.relationship='renders'"
        };
        sqlx::query(&format!("INSERT INTO temp._v2_link_rows SELECT l.id,l.source_id,l.target_id,l.relationship,l.note,strftime('%Y-%m-%dT%H:%M:%fZ',l.created_at),CAST(strftime('%s',l.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',l.created_at),4,3) AS INTEGER) FROM temp._v2_link_sources l JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id WHERE {predicate}")).execute(tx).await?;
        return Ok(());
    }
    let used = |column: &str| reads.contains(&("links".into(), column.into()));
    let native = |column: &str| {
        if used(column) {
            format!("l.{column}")
        } else {
            "NULL".into()
        }
    };
    let native_clock = if used("created_at") {
        "strftime('%Y-%m-%dT%H:%M:%fZ',l.created_at)"
    } else {
        "NULL"
    };
    let native_ms = if used("created_at_ms") {
        "CAST(strftime('%s',l.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',l.created_at),4,3) AS INTEGER)"
    } else {
        "NULL"
    };
    let predicate = match scope {
        LinkScope::PartOf => " WHERE l.relationship='part_of'",
        LinkScope::Renderers => " WHERE l.relationship='renders'",
        LinkScope::All => "",
    };
    // An unused birth clock must not retain joins to the canonical event log.
    let source_view = if used("created_at") || used("created_at_ms") {
        "temp._v2_link_sources"
    } else {
        "temp._v2_link_endpoints"
    };
    let ordinary=format!("SELECT {} id,{} source_id,{} target_id,{} relationship,{} note,{native_clock} created_at,{native_ms} created_at_ms FROM {source_view} l JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id{predicate}",native("id"),native("source_id"),native("target_id"),native("relationship"),native("note"));
    let provider = if scope == LinkScope::All {
        let readiness_started = Instant::now();
        kernel::provider_link_reads::require_ready_on(tx).await?;
        tracing::debug!(target: "native_ce::read_staging", phase = "provider_readiness", elapsed_us = readiness_started.elapsed().as_micros() as u64);
        let duplicates:bool=sqlx::query_scalar("SELECT EXISTS(SELECT id FROM main.kernel_provider_link_rows GROUP BY id HAVING count(*)>1)").fetch_one(&mut *tx).await?;
        let from = if duplicates {
            stage_projected_provider_rows(tx).await?;
            "temp._v2_link_rows l"
        } else {
            "main.kernel_provider_link_rows l JOIN temp._v2_visible_providers p ON p.id=l.aggregate_id"
        };
        let relationship = if used("relationship") {
            "'relates_to'"
        } else {
            "NULL"
        };
        format!("SELECT {} id,{} source_id,{} target_id,{relationship} relationship,{} note,{} created_at,{} created_at_ms FROM {from} JOIN temp._v2_visible s ON s.id=l.source_id JOIN temp._v2_visible t ON t.id=l.target_id UNION ALL ",native("id"),native("source_id"),native("target_id"),native("note"),native("created_at"),native("created_at_ms"))
    } else {
        String::new()
    };
    if reads.iter().any(|(relation, _)| relation == "records") {
        // Joins reuse the same disclosed endpoints. Persist only consumed
        // columns and one driving index rather than rebuilding a CTE and its
        // automatic index inside caller execution. No caller expression can
        // run until this live-gated materialization has finished.
        let selected: Vec<_> = columns("links")
            .expect("links contract")
            .iter()
            .copied()
            .filter(|c| used(c))
            .collect();
        let selected_sql = if selected.is_empty() {
            "1 AS _row".into()
        } else {
            selected.join(",")
        };
        sqlx::query(&format!("CREATE TEMP TABLE _v2_selected_links AS SELECT {selected_sql} FROM ({provider}{ordinary})"))
            .persistent(false).execute(&mut *tx).await?;
        for index in ["source_id", "target_id"].into_iter().filter(|c| used(c)) {
            sqlx::query(&format!(
                "CREATE INDEX temp._v2_selected_link_{index} ON _v2_selected_links({index})"
            ))
            .persistent(false)
            .execute(&mut *tx)
            .await?;
        }
        let projection = columns("links")
            .expect("links contract")
            .iter()
            .map(|c| {
                if used(c) {
                    format!("l.{c}")
                } else {
                    format!("NULL AS {c}")
                }
            })
            .collect::<Vec<_>>()
            .join(",");
        sqlx::query(&format!("DROP VIEW temp.links; CREATE TEMP VIEW links AS SELECT {projection} FROM temp._v2_selected_links l"))
            .persistent(false).execute(tx).await?;
    } else {
        sqlx::query(&format!("DROP VIEW temp.links; CREATE TEMP VIEW links AS WITH disclosed AS MATERIALIZED ({provider}{ordinary}) SELECT * FROM disclosed"))
            .persistent(false).execute(tx).await?;
    }
    Ok(())
}

// Interpretations are projected at commit/preparation time. Ranking retains
// the old BTreeMap semantics: native rows only fill an absent id; retained
// sources must agree with the first row, including the original timestamp.
// Both provider admission and the endpoint gate are evaluated live here.
async fn stage_projected_provider_rows(tx: &mut sqlx::SqliteConnection) -> Result<()> {
    // Most workspaces have globally unique link ids. Prove that fact from the
    // interpreted identity index before choosing the direct path; duplicates
    // retain the complete native/retained conflict and first-row semantics.
    let duplicates: bool = sqlx::query_scalar("SELECT EXISTS(SELECT id FROM main.kernel_provider_link_rows GROUP BY id HAVING count(*)>1)").fetch_one(&mut *tx).await?;
    if !duplicates {
        sqlx::query("INSERT INTO temp._v2_link_rows SELECT r.id,r.source_id,r.target_id,'relates_to',r.note,r.created_at,r.created_at_ms FROM main.kernel_provider_link_rows r JOIN temp._v2_visible_providers p ON p.id=r.aggregate_id JOIN temp._v2_visible s ON s.id=r.source_id JOIN temp._v2_visible t ON t.id=r.target_id").execute(tx).await?;
        return Ok(());
    }
    let cte = "WITH admitted AS MATERIALIZED (SELECT r.* FROM main.kernel_provider_link_rows r JOIN temp._v2_visible_providers p ON p.id=r.aggregate_id), ranked AS (SELECT *,first_value(raw_json) OVER (PARTITION BY id ORDER BY aggregate_id,ordinal) first_json,row_number() OVER (PARTITION BY id ORDER BY aggregate_id,ordinal) position FROM admitted)";
    let conflict: bool = sqlx::query_scalar(&format!(
        "{cte} SELECT EXISTS(SELECT 1 FROM ranked WHERE if_absent=0 AND raw_json<>first_json)"
    ))
    .fetch_one(&mut *tx)
    .await?;
    if conflict {
        return Err(Error::engine(
            "provider source identity has conflicting link metadata",
        ));
    }
    sqlx::query(&format!("{cte} INSERT INTO temp._v2_link_rows SELECT r.id,r.source_id,r.target_id,'relates_to',r.note,r.created_at,r.created_at_ms FROM ranked r JOIN temp._v2_visible s ON s.id=r.source_id JOIN temp._v2_visible t ON t.id=r.target_id WHERE r.position=1"))
        .execute(tx).await?;
    Ok(())
}

// Batch trusted projection rows, retaining both endpoint checks. A workspace
// with thousands of provider links must not pay one async SQL round trip per
// pair before its actual query can start. No source state enters the public tier.
/// Imported assertions retain each original directional link, including its
/// identity, note and birth time. Native assertions without legacy sources
/// expose the symmetric pair at the host-attested assertion time.
#[cfg(test)]
async fn stage_provider_rows(
    tx: &mut sqlx::SqliteConnection,
    states: &[crate::v2_standard::relates_to::State],
) -> Result<()> {
    let mut rows = BTreeMap::new();
    for state in states {
        for assertion in state.assertions.iter().filter(|a| !a.retracted) {
            if assertion.sources.is_empty() {
                for (from, to) in [(&state.left, &state.right), (&state.right, &state.left)] {
                    let id = format!("v2:relates_to:{from}:{to}");
                    rows.entry(id.clone()).or_insert_with(|| {
                        json!([id, from, to, Value::Null, assertion.asserted_at])
                    });
                }
            } else {
                for source in &assertion.sources {
                    let row = json!([
                        source.source_id,
                        source.from,
                        source.to,
                        source.note,
                        source
                            .claimed_timestamp
                            .as_deref()
                            .unwrap_or(&assertion.asserted_at)
                    ]);
                    if rows
                        .insert(source.source_id.clone(), row.clone())
                        .is_some_and(|previous| previous != row)
                    {
                        return Err(Error::engine(
                            "provider source identity has conflicting link metadata",
                        ));
                    }
                }
            }
        }
    }
    let rows: Vec<Value> = rows.into_values().collect();
    for chunk in rows.chunks(500) {
        sqlx::query(r#"WITH rows AS (
 SELECT json_extract(value,'$[0]') id,json_extract(value,'$[1]') source_id,
 json_extract(value,'$[2]') target_id,json_extract(value,'$[3]') note,
 json_extract(value,'$[4]') created_at FROM json_each(?1)
)
INSERT INTO temp._v2_link_rows
 SELECT r.id,r.source_id,r.target_id,'relates_to',r.note,
 strftime('%Y-%m-%dT%H:%M:%fZ',r.created_at),
 CAST(strftime('%s',r.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',r.created_at),4,3) AS INTEGER)
 FROM rows r JOIN temp._v2_visible s ON s.id=r.source_id
 JOIN temp._v2_visible t ON t.id=r.target_id"#)
            .bind(serde_json::to_string(chunk)?).execute(&mut *tx).await?;
    }
    Ok(())
}

#[cfg(test)]
async fn stage_provider_pairs(
    tx: &mut sqlx::SqliteConnection,
    pairs: &[(String, String)],
) -> Result<()> {
    for chunk in pairs.chunks(500) {
        sqlx::query(
            r#"WITH pairs AS (
 SELECT json_extract(p.value,'$[0]') AS source_id,json_extract(p.value,'$[1]') AS target_id
 FROM json_each(?1) p
), admitted AS (
 SELECT p.source_id,p.target_id FROM pairs p
 JOIN temp._v2_visible s ON s.id=p.source_id JOIN temp._v2_visible t ON t.id=p.target_id
)
INSERT INTO temp._v2_provider_links SELECT source_id,target_id FROM admitted
UNION ALL SELECT target_id,source_id FROM admitted"#,
        )
        .bind(serde_json::to_string(chunk)?)
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

async fn install_messaging(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    private: bool,
    awaiting: bool,
    reactions: bool,
    mentions: bool,
) -> Result<()> {
    let rows:Vec<(String,String)>=sqlx::query_as("SELECT m.message_id,m.state FROM kernel_messages m JOIN temp._v2_visible v ON v.id=m.message_id ORDER BY m.message_id LIMIT 10001").fetch_all(&mut *conn).await?;
    if rows.len() > 10_000 {
        return Err(Error::engine(
            "messaging SQL exceeds the bounded 10000 Message selection",
        ));
    }
    let person: Option<String> =
        sqlx::query_scalar("SELECT person_id FROM kernel_message_people WHERE principal_id=?")
            .bind(actor)
            .fetch_optional(&mut *conn)
            .await?;
    for (id, raw) in rows {
        let state: kernel::MessageState = serde_json::from_str(&raw)?;
        if reactions {
            let mut withheld = std::collections::BTreeMap::<String, usize>::new();
            for (principal, emojis) in &state.reactions {
                let face: Option<(String, Option<String>)> = sqlx::query_as("SELECT p.person_id,json_extract(n.value_json,'$') FROM main.kernel_message_people p JOIN temp._v2_visible v ON v.id=p.person_id LEFT JOIN main.kernel_record_fields n ON n.record_id=p.person_id AND n.name='title' WHERE p.principal_id=?")
                    .bind(principal).fetch_optional(&mut *conn).await?;
                for emoji in emojis {
                    // A public digest must never encode a withheld principal:
                    // known account IDs would make that digest an identity oracle.
                    let hidden_slot = if face.is_none() && principal != actor {
                        let n = withheld.entry(emoji.clone()).or_default();
                        *n += 1;
                        Some(*n)
                    } else {
                        None
                    };
                    let key = crate::canonical_json::digest_json(&json!([
                        id,
                        emoji,
                        face.as_ref().map(|f| &f.0),
                        principal == actor,
                        hidden_slot
                    ]));
                    sqlx::query(
                        "INSERT INTO temp.message_reactions VALUES(?,?,?,?,?,NULL,NULL,NULL,?)",
                    )
                    .bind(key)
                    .bind(&id)
                    .bind(emoji)
                    .bind(face.as_ref().map(|f| f.0.as_str()))
                    .bind(face.as_ref().and_then(|f| f.1.as_deref()))
                    .bind(principal == actor)
                    .execute(&mut *conn)
                    .await?;
                }
            }
        }
        if private || mentions {
            let value = super::messaging::private_fields(actor, person.as_deref(), &state);
            if mentions && value["mention"]["principal"] == true {
                let at: Option<String> =
                    sqlx::query_scalar("SELECT created_at FROM temp.records WHERE id=?")
                        .bind(&id)
                        .fetch_one(&mut *conn)
                        .await?;
                let ms = at
                    .as_deref()
                    .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
                    .map(|v| v.timestamp_millis());
                let seen = matches!(
                    value["human"]["stage"].as_str(),
                    Some("opened" | "acknowledged")
                );
                sqlx::query("INSERT INTO temp.my_mentions VALUES(?,'message','principal',?,?,?,?)")
                    .bind(&id)
                    .bind(state.author.as_deref() == Some(actor) && state.speaker.is_none())
                    .bind(at)
                    .bind(ms)
                    .bind(seen)
                    .execute(&mut *conn)
                    .await?;
            }
            if private {
                let pref = state
                    .private
                    .get(actor)
                    .and_then(|p| p.get("preference"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let bool_value = |key: &str| {
                    pref[key]
                        .as_bool()
                        .unwrap_or_else(|| pref[key].as_i64() == Some(1))
                };
                let snoozed = pref["snoozed_until"].as_str();
                let snoozed_ms = snoozed
                    .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
                    .map(|d| d.timestamp_millis());
                sqlx::query("INSERT INTO temp.my_message_state VALUES(?,?,?,?,?,?,?,?,?,?,?)")
                    .bind(&id)
                    .bind(value["human"]["stage"].as_str())
                    .bind(value["attention"]["unread"].as_bool().unwrap_or(false))
                    .bind(state.author.as_deref() == Some(actor) && state.speaker.is_none())
                    .bind(value["mention"]["principal"].as_bool().unwrap_or(false))
                    .bind(bool_value("attention_flag"))
                    .bind(bool_value("muted"))
                    .bind(bool_value("archived"))
                    .bind(snoozed)
                    .bind(snoozed_ms)
                    .bind(true)
                    .execute(&mut *conn)
                    .await?;
            }
        }
        if awaiting
            && state.expectation.as_deref() == Some("reply")
            && person
                .as_ref()
                .is_some_and(|p| state.addressed_to.contains(p))
        {
            let expectation = super::messaging::expectation_value(conn, actor, &id, &state).await?;
            if expectation["state"] == "open" {
                sqlx::query("INSERT INTO temp.messages_awaiting_reply VALUES(?)")
                    .bind(&id)
                    .execute(&mut *conn)
                    .await?;
            }
        }
    }
    if mentions {
        install_reference_mentions(conn, actor, person.as_deref()).await?;
    }
    Ok(())
}

async fn install_runs(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    root_visible: bool,
    intents: bool,
) -> Result<()> {
    // The kernel directory replaces v1's disclosable Person/account binding:
    // ordinary principals see their own runs, directory viewers may see all.
    let admission = if root_visible {
        "1"
    } else {
        "r.owner_principal=?"
    };
    let sql=format!("INSERT INTO temp._v2_runs SELECT r.id,CASE WHEN p.auth_binding LIKE 'mcp-run:%' THEN substr(p.auth_binding,9) ELSE r.id END,r.owner_principal FROM main.kernel_runs r JOIN main.kernel_principals p ON p.principal_id=r.run_principal WHERE {admission}");
    let mut query = sqlx::query(&sql);
    if !root_visible {
        query = query.bind(actor);
    }
    query.execute(&mut *tx).await?;
    sqlx::query("INSERT INTO temp.runs SELECT v.run_key,NULL,CAST(strftime('%s',e.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',e.created_at),4,3) AS INTEGER),(SELECT CAST(strftime('%s',c.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',c.created_at),4,3) AS INTEGER) FROM main.content_events c WHERE c.record_id=r.id AND c.type='kernel.run_closed.v1' ORDER BY seq DESC LIMIT 1),NULL,NULL,'self_declared' FROM temp._v2_runs v JOIN main.kernel_runs r ON r.id=v.id JOIN main.content_events e ON e.seq=r.opened_seq").execute(&mut *tx).await?;
    if intents {
        let sql=format!("INSERT INTO temp.run_intents SELECT v.run_key,row_number() OVER(PARTITION BY v.id ORDER BY e.seq),CASE WHEN octet_length(json_extract(e.payload,'$.intent'))>{} THEN NULL ELSE json_extract(e.payload,'$.intent') END,CAST(strftime('%s',e.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',e.created_at),4,3) AS INTEGER) FROM temp._v2_runs v CROSS JOIN main.content_events e INDEXED BY idx_content_events_record WHERE e.record_id=v.id AND e.type='kernel.run_intent_set.v1' AND e.actor=v.owner",guard::MAX_RUN_INTENT_BYTES);
        sqlx::query(&sql).execute(&mut *tx).await?;
    }
    Ok(())
}

async fn install_imported_catalogue(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    reads: &BTreeSet<(String, String)>,
) -> Result<()> {
    let needs = |name: &str| reads.iter().any(|(r, _)| r == name);
    if needs("vocabularies") {
        sqlx::query("INSERT INTO temp.vocabularies SELECT json_extract(payload,'$.id'),json_extract(payload,'$.name'),strftime('%Y-%m-%dT%H:%M:%fZ',json_extract(payload,'$.created_at')),(CAST(strftime('%s',json_extract(payload,'$.created_at')) AS INTEGER)*1000+CAST(substr(strftime('%f',json_extract(payload,'$.created_at')),4,3) AS INTEGER)) FROM main.kernel_v1_state WHERE section='vocabularies'").execute(&mut *tx).await?;
    }
    if needs("vocabulary_values") {
        sqlx::query("INSERT INTO temp.vocabulary_values SELECT json_extract(payload,'$.id'),json_extract(payload,'$.vocabulary_id'),json_extract(payload,'$.value'),json_extract(payload,'$.gloss'),json_extract(payload,'$.status'),CASE WHEN json_type(payload,'$.ordinal') IN ('integer','real') THEN json_extract(payload,'$.ordinal') END,json_extract(payload,'$.terminality'),json_extract(payload,'$.metadata'),json_extract(payload,'$.alias_of') FROM main.kernel_v1_state WHERE section='vocabulary_values'").execute(&mut *tx).await?;
    }
    if needs("record_lifecycle_interpretations") {
        lifecycle::install(tx, actor).await?;
    }
    Ok(())
}
async fn install_imported_runs(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    _root_visible: bool,
    intents: bool,
    claims: bool,
) -> Result<()> {
    sqlx::query("INSERT INTO temp._v2_imported_accounts VALUES(?)")
        .bind(actor)
        .execute(&mut *tx)
        .await?;
    for account in kernel::v1_state::disclosed_accounts_on(tx, actor).await? {
        sqlx::query("INSERT OR IGNORE INTO temp._v2_imported_accounts VALUES(?)")
            .bind(account)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("INSERT INTO temp.runs SELECT json_extract(s.payload,'$.run_key'),(SELECT d.record_id FROM main.kernel_v1_state d WHERE d.section='account_directory' AND d.account_principal=s.account_principal LIMIT 1),(CAST(strftime('%s',json_extract(s.payload,'$.started_at')) AS INTEGER)*1000+CAST(substr(strftime('%f',json_extract(s.payload,'$.started_at')),4,3) AS INTEGER)),(CAST(strftime('%s',coalesce(json_extract(s.payload,'$.ended_at'),s.observed_at)) AS INTEGER)*1000+CAST(substr(strftime('%f',coalesce(json_extract(s.payload,'$.ended_at'),s.observed_at)),4,3) AS INTEGER)),json_extract(s.payload,'$.reported_model'),CASE WHEN json_extract(s.payload,'$.reported_mcp_client_name') IS NULL THEN NULL WHEN json_extract(s.payload,'$.reported_mcp_client_version') IS NULL THEN json_extract(s.payload,'$.reported_mcp_client_name') ELSE json_extract(s.payload,'$.reported_mcp_client_name')||'/'||json_extract(s.payload,'$.reported_mcp_client_version') END,'imported_historical' FROM main.kernel_v1_state s WHERE s.section='runs' AND s.account_principal IN (SELECT principal_id FROM temp._v2_imported_accounts) AND NOT EXISTS(SELECT 1 FROM temp.runs r WHERE r.run_key=json_extract(s.payload,'$.run_key'))")
        .execute(&mut *tx).await?;
    if intents {
        let sql=format!("WITH numbered AS (SELECT i.source_id,json_extract(i.payload,'$.run_key') AS run_key,row_number() OVER(PARTITION BY json_extract(i.payload,'$.run_key') ORDER BY json_extract(i.payload,'$.source_seq'),i.source_id) AS ordinal FROM main.kernel_v1_state i WHERE i.section='run_intents' AND i.account_principal IN (SELECT principal_id FROM temp._v2_imported_accounts) AND EXISTS(SELECT 1 FROM temp.runs r WHERE r.run_key=json_extract(i.payload,'$.run_key'))) INSERT INTO temp.run_intents SELECT n.run_key,n.ordinal,CASE WHEN octet_length(json_extract(i.payload,'$.intent'))>{} THEN NULL ELSE json_extract(i.payload,'$.intent') END,(CAST(strftime('%s',json_extract(i.payload,'$.declared_at')) AS INTEGER)*1000+CAST(substr(strftime('%f',json_extract(i.payload,'$.declared_at')),4,3) AS INTEGER)) FROM numbered n JOIN main.kernel_v1_state i ON i.section='run_intents' AND i.source_id=n.source_id",guard::MAX_RUN_INTENT_BYTES);

        sqlx::query(&sql).execute(&mut *tx).await?;
    }
    if claims {
        sqlx::query("INSERT INTO temp.agent_activity_claims SELECT json_extract(c.payload,'$.id'),json_extract(r.payload,'$.activity_id'),c.record_id,json_extract(c.payload,'$.claimed_at'),(CAST(strftime('%s',json_extract(c.payload,'$.claimed_at')) AS INTEGER)*1000+CAST(substr(strftime('%f',json_extract(c.payload,'$.claimed_at')),4,3) AS INTEGER)),coalesce(json_extract(c.payload,'$.released_at'),c.observed_at),(CAST(strftime('%s',coalesce(json_extract(c.payload,'$.released_at'),c.observed_at)) AS INTEGER)*1000+CAST(substr(strftime('%f',coalesce(json_extract(c.payload,'$.released_at'),c.observed_at)),4,3) AS INTEGER)),0 FROM main.kernel_v1_state c LEFT JOIN main.kernel_v1_state r ON r.section='runs' AND json_extract(r.payload,'$.run_key')=json_extract(c.payload,'$.run_key') AND +r.account_principal=c.account_principal JOIN temp._v2_visible v ON v.id=c.record_id WHERE c.section='claims' AND c.account_principal IN (SELECT principal_id FROM temp._v2_imported_accounts)")
            .execute(&mut *tx).await?;
    }
    Ok(())
}

/// Rebuild this caller's reference rows from current visible bodies. First
/// narrow by the caller's six-hex prefix in SQLite; never scan hidden bodies
/// or use hidden look-alikes to resolve a reference.
async fn install_reference_mentions(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    person: Option<&str>,
) -> Result<()> {
    let Some(person) =
        person.filter(|id| uuid::Uuid::parse_str(id).is_ok_and(|u| u.to_string() == *id))
    else {
        return Ok(());
    };
    let visible: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM temp._v2_visible WHERE id=?)")
            .bind(person)
            .fetch_one(&mut *conn)
            .await?;
    if !visible {
        return Ok(());
    }
    let canonical = person.to_ascii_lowercase();
    let hex = canonical.replace('-', "");
    let rivals: Vec<String> =
        sqlx::query_scalar("SELECT id FROM temp._v2_visible WHERE id>=? AND id<? AND id!=?")
            .bind(&hex[..6])
            .bind(format!("{}g", &hex[..6]))
            .bind(person)
            .fetch_all(&mut *conn)
            .await?;
    let rivals: Vec<String> = rivals
        .into_iter()
        .filter(|id| uuid::Uuid::parse_str(id).is_ok())
        .map(|id| id.replace('-', "").to_ascii_lowercase())
        .collect();
    type MentionSource = (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<MentionSource> = sqlx::query_as("SELECT r.id,r.body,r.type,k.owner_id,coalesce(e.created_at,r.created_at) FROM temp.records r JOIN main.kernel_records k ON k.id=r.id LEFT JOIN main.kernel_record_bodies b ON b.record_id=r.id LEFT JOIN main.content_events e ON e.seq=b.event_seq WHERE instr(lower(r.body),?)>0 ORDER BY r.id LIMIT 10001")
        .bind(&hex[..6]).fetch_all(&mut *conn).await?;
    if rows.len() > 10000 || rows.iter().map(|r| r.1.len()).sum::<usize>() > 128 * 1024 * 1024 {
        return Err(Error::engine(
            "mention SQL exceeds bounded visible body selection",
        ));
    }
    for (id, body, kind, owner, at) in rows {
        let matched = crate::mentions::scan_body(&body).iter().any(|mention| {
            let key = &mention.lookup_key;
            if key == &canonical {
                return true;
            }
            let prefix = key.replace('-', "");
            (6..32).contains(&prefix.len())
                && (key == &prefix || canonical.starts_with(key))
                && prefix.bytes().all(|b| b.is_ascii_hexdigit())
                && hex.starts_with(&prefix)
                && !rivals.iter().any(|r| r.starts_with(&prefix))
        });
        if !matched {
            continue;
        }
        let ms = at
            .as_deref()
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .map(|v| v.timestamp_millis());
        let own: bool = if kind.as_deref() == Some("Message") {
            sqlx::query_scalar("SELECT coalesce(json_extract(state,'$.author')=? AND json_extract(state,'$.speaker') IS NULL,0) FROM main.kernel_messages WHERE message_id=?").bind(actor).bind(&id).fetch_optional(&mut *conn).await?.unwrap_or(false)
        } else {
            owner.as_deref() == Some(actor)
        };
        sqlx::query("INSERT INTO temp.my_mentions VALUES(?,?,'reference',?,?,?,NULL)")
            .bind(id)
            .bind(if kind.as_deref() == Some("Message") {
                "message"
            } else {
                "record"
            })
            .bind(own)
            .bind(at)
            .bind(ms)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod prefix_tests {
    use super::id_ordered_record_limit;
    #[test]
    fn metadata_pulse_refuses_to_narrow_other_sql_or_parameter_types() {
        use crate::query::sql_contract::QuerySqlParameter;
        let parameters = [QuerySqlParameter::Text {
            value: Some("id".into()),
        }];
        assert_eq!(
            super::metadata_pulse_ids(
                "SELECT id, updated_at FROM records WHERE id IN (?1)",
                &parameters
            ),
            Some(vec!["id".into()])
        );
        for sql in [
            "ſELECT id, updated_at FROM records WHERE id IN (?1)",
            "SELECT\u{a0}id, updated_at FROM records WHERE id IN (?1)",
            "SELECT id, type, Kind, name, summary, home_id, lifecycle, maturity, updated_at, last_activity_at FROM records WHERE deleted_at IS NULL AND id IN (?1)",
            "SELECT id, updated_at FROM records WHERE id IN (?1) OR 1",
            "SELECT id, updated_at FROM records WHERE id IN (?1) UNION SELECT id, updated_at FROM records",
            "SELECT id, updated_at FROM records WHERE id IN (SELECT id FROM records)",
            "SELECT id, updated_at FROM records WHERE id IN (?1 COLLATE NOCASE)",
            "SELECT id, updated_at FROM records WHERE id IN (?2)",
            "SELECT id, updated_at FROM records WHERE id IN (?0)",
            "SELECT id, updated_at FROM records WHERE id IN ('id')",
        ] { assert_eq!(super::metadata_pulse_ids(sql, &parameters), None, "{sql}"); }
        assert_eq!(
            super::metadata_pulse_ids(
                "SELECT id, updated_at FROM records WHERE id IN (?1)",
                &[QuerySqlParameter::Integer {
                    value: Some("1".into())
                }]
            ),
            None
        );
    }
    #[test]
    fn only_closed_id_ordered_prefixes_narrow_staging() {
        for (sql, limit) in [
            ("SELECT id,name FROM records ORDER BY id LIMIT 20", 20),
            ("select name from records order by id asc limit 1;", 1),
        ] {
            assert_eq!(id_ordered_record_limit(sql), Some(limit));
        }
        for sql in [
            "SELECT name AS id FROM records ORDER BY id LIMIT 20",
            "SELECT id,name FROM records WHERE id>'a' ORDER BY id LIMIT 20",
            "SELECT id,name FROM records ORDER BY name LIMIT 20",
            "SELECT id,name FROM records ORDER BY id COLLATE NOCASE LIMIT 20",
            "SELECT id,name FROM records ORDER BY id LIMIT 20 OFFSET 1",
            "SELECT id,name FROM records ORDER BY id LIMIT 1001",
            "SELECT id,name FROM records ORDER BY id LIMIT ?1",
            "SELECT id,name FROM records ORDER BY id LIMIT 20 UNION SELECT id,name FROM records",
            "SELECT (SELECT name FROM records LIMIT 1) AS id FROM records ORDER BY id LIMIT 20",
        ] {
            assert_eq!(id_ordered_record_limit(sql), None, "{sql}");
        }
    }
}

#[cfg(test)]
mod html_input_tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    async fn provider_link_batches_keep_both_endpoint_visibility_and_revocation() {
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY); CREATE TEMP TABLE _v2_provider_links(source_id TEXT,target_id TEXT)")
            .execute(&mut db).await.unwrap();
        sqlx::query("INSERT INTO _v2_visible VALUES('source')")
            .execute(&mut db)
            .await
            .unwrap();
        let mut pairs = Vec::new();
        for i in 0..501 {
            let target = format!("target-{i}");
            sqlx::query("INSERT INTO _v2_visible VALUES(?)")
                .bind(&target)
                .execute(&mut db)
                .await
                .unwrap();
            pairs.push(("source".into(), target));
        }
        sqlx::query("CREATE TABLE kernel_provider_subjects(subject_id TEXT,aggregate_id TEXT,PRIMARY KEY(subject_id,aggregate_id)); CREATE TEMP TABLE _v2_visible_providers(id TEXT PRIMARY KEY); INSERT INTO kernel_provider_subjects VALUES('source','shared'),('target-0','shared'),('source','private'),('hidden','private')")
            .execute(&mut db).await.unwrap();
        stage_visible_providers(&mut db).await.unwrap();
        let admitted: Vec<String> =
            sqlx::query_scalar("SELECT id FROM _v2_visible_providers ORDER BY id")
                .fetch_all(&mut db)
                .await
                .unwrap();
        assert_eq!(admitted, vec!["shared"]);
        pairs.extend([
            ("source".into(), "hidden".into()),
            ("hidden".into(), "target-0".into()),
            ("hidden".into(), "also-hidden".into()),
        ]);
        stage_provider_pairs(&mut db, &pairs).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM _v2_provider_links")
            .fetch_one(&mut db)
            .await
            .unwrap();
        assert_eq!(count, 1002);
        let hidden: i64 = sqlx::query_scalar("SELECT count(*) FROM _v2_provider_links WHERE source_id='hidden' OR target_id='hidden' OR target_id='also-hidden'")
            .fetch_one(&mut db).await.unwrap();
        assert_eq!(hidden, 0);
        sqlx::query("DELETE FROM _v2_visible WHERE id='source'; DELETE FROM _v2_provider_links")
            .execute(&mut db)
            .await
            .unwrap();
        stage_provider_pairs(&mut db, &pairs).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM _v2_provider_links")
            .fetch_one(&mut db)
            .await
            .unwrap();
        assert_eq!(count, 0, "next snapshot must respect the lost endpoint");
        sqlx::query("DELETE FROM _v2_visible_providers")
            .execute(&mut db)
            .await
            .unwrap();
        stage_visible_providers(&mut db).await.unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM _v2_visible_providers")
            .fetch_one(&mut db)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
    #[tokio::test]
    async fn provider_link_projection_matches_each_retained_interpreter_prefix() {
        use crate::kernel::provider_catalogue::{self as catalogue, FoldInput, StoredState};
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE kernel_provider_state(id TEXT PRIMARY KEY,provider_key TEXT,head INTEGER); CREATE TABLE content_events(seq INTEGER PRIMARY KEY,created_at TEXT); CREATE TABLE kernel_record_fields(record_id TEXT,name TEXT,value_json TEXT)").execute(&mut db).await.unwrap();
        kernel::provider_link_reads::ensure_schema_on(&mut db)
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY); CREATE TEMP TABLE _v2_visible_providers(id TEXT PRIMARY KEY); CREATE TEMP TABLE _v2_link_rows(id TEXT,source_id TEXT,target_id TEXT,relationship TEXT,note TEXT,created_at TEXT,created_at_ms INTEGER)").execute(&mut db).await.unwrap();
        for bytes in [
            include_str!("../../kernel/fixtures/relates_to_v1.golden.json"),
            include_str!("../../kernel/fixtures/relates_to_v2.golden.json"),
            include_str!("../../kernel/fixtures/relates_to_v3.golden.json"),
        ] {
            let vector: Value = serde_json::from_str(bytes).unwrap();
            let mut current: Option<StoredState> = None;
            for event in vector["events"].as_array().unwrap() {
                let entry = catalogue::recorded(&event["payload"]).unwrap();
                let decoded = (entry.decode)(&event["payload"]).unwrap();
                let input = FoldInput {
                    decoded: &decoded,
                    principal: event["actor"].as_str().unwrap(),
                    timestamp: event["created_at"].as_str().unwrap(),
                    event_seq: event["seq"].as_i64().unwrap(),
                };
                let folded = (entry.fold)(&input, current.as_ref()).unwrap();
                let stored = StoredState {
                    pins: (entry.pins)(),
                    state: folded.state,
                    attribution: folded.attribution,
                };
                let state: crate::v2_standard::relates_to::State =
                    serde_json::from_value(stored.view().unwrap()).unwrap();
                sqlx::query("DELETE FROM kernel_provider_link_rows; DELETE FROM kernel_provider_link_heads; DELETE FROM _v2_visible; DELETE FROM _v2_visible_providers; DELETE FROM _v2_link_rows").execute(&mut db).await.unwrap();
                sqlx::query("INSERT INTO _v2_visible VALUES(?),(?)")
                    .bind(&state.left)
                    .bind(&state.right)
                    .execute(&mut db)
                    .await
                    .unwrap();
                sqlx::query("INSERT INTO _v2_visible_providers VALUES(?)")
                    .bind(&decoded.facts.aggregate_id)
                    .execute(&mut db)
                    .await
                    .unwrap();
                kernel::provider_link_reads::store_on(
                    &mut db,
                    &decoded.facts.aggregate_id,
                    input.event_seq,
                    &stored.pins,
                    entry.link_read.unwrap()(stored.view().unwrap()).unwrap(),
                )
                .await
                .unwrap();
                stage_provider_rows(&mut db, std::slice::from_ref(&state))
                    .await
                    .unwrap();
                let select = "SELECT json_array(id,source_id,target_id,relationship,note,created_at,created_at_ms) FROM _v2_link_rows ORDER BY id";
                let expected: Vec<String> =
                    sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
                sqlx::query("DELETE FROM _v2_link_rows")
                    .execute(&mut db)
                    .await
                    .unwrap();
                stage_projected_provider_rows(&mut db).await.unwrap();
                let projected: Vec<String> =
                    sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
                assert_eq!(
                    projected, expected,
                    "retained codec prefix {}",
                    input.event_seq
                );
                // Two admitted aggregates can carry the same source/native id.
                // Aggregate order, not insertion order, determines the first row.
                let mut first = state.clone();
                let mut native = first.assertions[0].clone();
                native.sources.clear();
                native.retracted = false;
                first.assertions.push(native);
                kernel::provider_link_reads::store_on(
                    &mut db,
                    &decoded.facts.aggregate_id,
                    input.event_seq,
                    &stored.pins,
                    entry.link_read.unwrap()(serde_json::to_value(&first).unwrap()).unwrap(),
                )
                .await
                .unwrap();
                let later_id = format!("~{}", decoded.facts.aggregate_id);
                sqlx::query("INSERT INTO _v2_visible_providers VALUES(?)")
                    .bind(&later_id)
                    .execute(&mut db)
                    .await
                    .unwrap();
                for variant in 0..3 {
                    let mut later = first.clone();
                    for assertion in &mut later.assertions {
                        if variant == 1 && assertion.sources.is_empty() {
                            assertion.asserted_at = "2030-01-01T00:00:00Z".into();
                        }
                        if variant == 2 {
                            for source in &mut assertion.sources {
                                source.note = Some("conflicting second aggregate".into());
                            }
                        }
                    }
                    kernel::provider_link_reads::store_on(
                        &mut db,
                        &later_id,
                        input.event_seq,
                        &stored.pins,
                        entry.link_read.unwrap()(serde_json::to_value(&later).unwrap()).unwrap(),
                    )
                    .await
                    .unwrap();
                    sqlx::query("DELETE FROM _v2_link_rows")
                        .execute(&mut db)
                        .await
                        .unwrap();
                    let oracle = stage_provider_rows(&mut db, &[first.clone(), later]).await;
                    assert_eq!(
                        oracle.is_err(),
                        variant == 2,
                        "retained conflict versus native first-row ranking"
                    );
                    let expected: Vec<String> =
                        sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
                    sqlx::query("DELETE FROM _v2_link_rows")
                        .execute(&mut db)
                        .await
                        .unwrap();
                    let projected = stage_projected_provider_rows(&mut db).await;
                    assert_eq!(
                        projected.is_ok(),
                        oracle.is_ok(),
                        "two aggregates, prefix {}, variant {variant}",
                        input.event_seq
                    );
                    match (oracle, projected) {
                        (Ok(()), Ok(())) => {
                            let actual: Vec<String> =
                                sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
                            assert_eq!(actual, expected, "first aggregate wins, variant {variant}");
                        }
                        (Err(old), Err(new)) => assert_eq!(old.to_string(), new.to_string()),
                        _ => unreachable!(),
                    }
                }
                sqlx::query("DELETE FROM _v2_link_rows; DELETE FROM _v2_visible")
                    .execute(&mut db)
                    .await
                    .unwrap();
                // Provider admission would drop the aggregate after revocation.
                sqlx::query("DELETE FROM _v2_visible_providers")
                    .execute(&mut db)
                    .await
                    .unwrap();
                stage_projected_provider_rows(&mut db).await.unwrap();
                let hidden: i64 = sqlx::query_scalar("SELECT count(*) FROM _v2_link_rows")
                    .fetch_one(&mut db)
                    .await
                    .unwrap();
                assert_eq!(hidden, 0);
                current = Some(stored);
            }
        }
    }

    #[tokio::test]
    async fn provider_link_projection_preserves_source_shapes_and_conflict_refusals() {
        use crate::v2_standard::relates_to::{Assertion, Source, State};
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE kernel_provider_state(id TEXT PRIMARY KEY,provider_key TEXT,head INTEGER); CREATE TABLE content_events(seq INTEGER PRIMARY KEY,created_at TEXT); CREATE TABLE kernel_record_fields(record_id TEXT,name TEXT,value_json TEXT)").execute(&mut db).await.unwrap();
        kernel::provider_link_reads::ensure_schema_on(&mut db)
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY); INSERT INTO _v2_visible VALUES('a'),('b'); CREATE TEMP TABLE _v2_visible_providers(id TEXT PRIMARY KEY); INSERT INTO _v2_visible_providers VALUES('pair'); CREATE TEMP TABLE _v2_link_rows(id TEXT,source_id TEXT,target_id TEXT,relationship TEXT,note TEXT,created_at TEXT,created_at_ms INTEGER)").execute(&mut db).await.unwrap();
        let native = Assertion {
            id: "native".into(),
            sources: vec![],
            retracted: false,
            asserted_by: Some("member".into()),
            asserted_at: "2026-01-01T00:00:00Z".into(),
            asserted_seq: 1,
            retracted_by: None,
            retracted_at: None,
            retracted_seq: None,
        };
        let source = Source {
            source_id: "retained".into(),
            from: "b".into(),
            to: "a".into(),
            claimed_author: Some("source-author".into()),
            claimed_timestamp: None,
            note: Some("source note".into()),
        };
        let retained = Assertion {
            id: "retained-assertion".into(),
            sources: vec![source.clone()],
            ..native.clone()
        };
        let mut reverse = source.clone();
        reverse.source_id = "reverse".into();
        reverse.from = "a".into();
        reverse.to = "b".into();
        reverse.claimed_timestamp = Some("2025-12-31T23:00:00+01:00".into());
        let mut invalid_time = source.clone();
        invalid_time.source_id = "invalid-time".into();
        invalid_time.claimed_timestamp = Some("unknown".into());
        let mut conflict_source = source.clone();
        conflict_source.note = Some("different".into());
        let cases = vec![
            vec![],
            vec![native.clone()],
            vec![retained.clone()],
            vec![
                retained.clone(),
                Assertion {
                    id: "other".into(),
                    sources: vec![reverse, invalid_time, source.clone()],
                    ..native.clone()
                },
            ],
            vec![
                native.clone(),
                Assertion {
                    id: "native-later".into(),
                    asserted_at: "2026-02-01T00:00:00Z".into(),
                    ..native.clone()
                },
            ],
            vec![
                retained.clone(),
                Assertion {
                    retracted: true,
                    ..native.clone()
                },
            ],
            vec![Assertion {
                retracted: true,
                ..retained.clone()
            }],
            vec![
                retained.clone(),
                Assertion {
                    sources: vec![conflict_source],
                    ..retained
                },
            ],
        ];
        let entry = &crate::v2_standard::relates_to_retained::V3;
        for assertions in cases {
            let state = State {
                left: "a".into(),
                right: "b".into(),
                assertions,
            };
            sqlx::query("DELETE FROM _v2_link_rows")
                .execute(&mut db)
                .await
                .unwrap();
            let old = stage_provider_rows(&mut db, std::slice::from_ref(&state)).await;
            let select="SELECT json_array(id,source_id,target_id,relationship,note,created_at,created_at_ms) FROM _v2_link_rows ORDER BY id";
            let expected: Vec<String> =
                sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
            sqlx::query("DELETE FROM _v2_link_rows")
                .execute(&mut db)
                .await
                .unwrap();
            kernel::provider_link_reads::store_on(
                &mut db,
                "pair",
                1,
                &(entry.pins)(),
                entry.link_read.unwrap()(serde_json::to_value(&state).unwrap()).unwrap(),
            )
            .await
            .unwrap();
            let projected = stage_projected_provider_rows(&mut db).await;
            assert_eq!(old.is_err(), projected.is_err());
            if let (Err(old), Err(projected)) = (old, projected) {
                assert_eq!(old.to_string(), projected.to_string());
            } else {
                let actual: Vec<String> =
                    sqlx::query_scalar(select).fetch_all(&mut db).await.unwrap();
                assert_eq!(actual, expected);
            }
        }
    }

    #[tokio::test]
    async fn provider_sql_retains_imported_link_identity_note_and_birth_time() {
        let mut db = sqlx::SqliteConnection::connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE _v2_visible(id TEXT PRIMARY KEY); INSERT INTO _v2_visible VALUES('a'),('b'); CREATE TEMP TABLE _v2_link_rows(id TEXT,source_id TEXT,target_id TEXT,relationship TEXT,note TEXT,created_at TEXT,created_at_ms INTEGER)")
            .execute(&mut db).await.unwrap();
        let state: crate::v2_standard::relates_to::State =
            serde_json::from_value(json!({"left":"a","right":"b","assertions":[{
                "id":"assertion","sources":[
                    {"source_id":"original","from":"a","to":"b","claimed_author":null,
                     "claimed_timestamp":"2026-01-01T00:00:00Z","note":"retained note"}
                ],"retracted":false,"asserted_by":"importer","asserted_at":"2026-02-01T00:00:00Z",
                "asserted_seq":1,"retracted_by":null,"retracted_at":null,"retracted_seq":null
            }]}))
            .unwrap();
        let mut hidden = state.clone();
        hidden.right = "hidden".into();
        hidden.assertions[0].sources[0].source_id = "hidden-link".into();
        hidden.assertions[0].sources[0].to = "hidden".into();
        stage_provider_rows(&mut db, &[state, hidden])
            .await
            .unwrap();
        let rows: Vec<(String, String, String, String, String, i64)> = sqlx::query_as(
            "SELECT id,source_id,target_id,note,created_at,created_at_ms FROM _v2_link_rows",
        )
        .fetch_all(&mut db)
        .await
        .unwrap();
        assert_eq!(
            rows,
            vec![(
                "original".into(),
                "a".into(),
                "b".into(),
                "retained note".into(),
                "2026-01-01T00:00:00.000Z".into(),
                1767225600000
            )]
        );
    }

    #[test]
    fn provider_batch_decodes_each_row_and_keeps_exact_retained_pins() {
        use crate::kernel::provider_catalogue::StoredState;
        let old = StoredState {
            pins: crate::v2_standard::relates_to_v1::pins(),
            state: json!({"left":"a","right":"b","assertions":[]}),
            attribution: json!({}),
        };
        let active = StoredState {
            pins: crate::v2_standard::relates_to_v3::pins(),
            state: json!({"left":"a","right":"b","assertions":[{
                "id":"assertion","sources":[],"retracted":false,
                "asserted_by":"actor","asserted_at":"2026-01-01T00:00:00Z","asserted_seq":1,
                "retracted_by":null,"retracted_at":null,"retracted_seq":null
            }]}),
            attribution: Value::Null,
        };
        let states = vec![
            serde_json::to_string(&old).unwrap(),
            serde_json::to_string(&active).unwrap(),
        ];
        let expected: Vec<_> = states
            .iter()
            .filter_map(|state| kernel::relates_to_port::active_pair_from_state(state).unwrap())
            .collect();
        assert_eq!(
            kernel::relates_to_port::active_pairs_from_states(&states).unwrap(),
            expected
        );
        assert_eq!(expected, vec![("a".into(), "b".into())]);
        let mut bad_pin = active.clone();
        bad_pin.pins.relationship.digest = "unattested".into();
        assert!(kernel::relates_to_port::active_pairs_from_states(&[
            states[1].clone(),
            serde_json::to_string(&bad_pin).unwrap()
        ])
        .is_err());
        let mut bad_row = active;
        bad_row.state["assertions"] = json!("malformed");
        assert!(
            kernel::relates_to_port::active_pairs_from_states(&[
                states[1].clone(),
                serde_json::to_string(&bad_row).unwrap()
            ])
            .is_err(),
            "a cached interpreter must still decode every row"
        );
    }

    #[test]
    fn stored_sql_keeps_v1_rules_without_allowing_physical_reads() {
        let stored = "SELECT round(1.234,2) AS n FROM records LIMIT 1";
        assert!(guard::inspect_kernel_v2_stored_saved_sql(stored).is_ok());
        assert!(guard::validate_kernel_v2_ad_hoc(stored).is_err());
        for sql in [
            "SELECT * FROM main.records",
            "SELECT * FROM main.kernel_records",
            "SELECT * FROM policy_entries",
            "SELECT load_extension('untrusted')",
        ] {
            assert!(
                guard::inspect_kernel_v2_stored_saved_sql(sql).is_err(),
                "{sql}"
            );
        }
    }
}

#[cfg(test)]
mod effect_read_tests {
    use super::*;

    #[tokio::test]
    async fn declared_effect_read_restores_query_only_on_success_and_statement_error() {
        let dir = tempfile::tempdir().unwrap();
        let (db, actor) = kernel::create_v2_database(
            dir.path().join("query.db").to_str().unwrap(),
            "account",
            "Owner",
            "fixture-owner",
        )
        .await
        .unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        sqlx::query("CREATE TEMP TABLE fence_probe(value INTEGER)")
            .execute(&mut *tx)
            .await
            .unwrap();
        for (sql, ok) in [
            ("SELECT id FROM records ORDER BY id", true),
            ("SELECT json_extract('not-json', '$') AS broken", false),
        ] {
            let result = query_sql_on(&mut tx, &actor, json!({"sql":sql}), 2).await;
            assert_eq!(result.is_ok(), ok, "{result:?}");
            let fenced: bool = sqlx::query_scalar("PRAGMA query_only")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            assert!(!fenced, "the enclosing effect must remain writable");
            sqlx::query("INSERT INTO fence_probe VALUES(1)")
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.rollback().await.unwrap();
        db.close().await;
    }
}

#[cfg(test)]
tokio::task_local! {
    static NAMED_READ_PAUSE: (std::sync::Arc<tokio::sync::Barrier>, std::sync::Arc<tokio::sync::Barrier>);
    static NAMED_REGISTER_PAUSE: (std::sync::Arc<tokio::sync::Barrier>, std::sync::Arc<tokio::sync::Barrier>);
}
#[cfg(test)]
pub(crate) async fn with_named_read_pause<T>(
    arrived: std::sync::Arc<tokio::sync::Barrier>,
    resume: std::sync::Arc<tokio::sync::Barrier>,
    work: impl std::future::Future<Output = T>,
) -> T {
    NAMED_READ_PAUSE.scope((arrived, resume), work).await
}

#[cfg(test)]
pub(crate) async fn with_named_registered_pause<T>(
    arrived: std::sync::Arc<tokio::sync::Barrier>,
    resume: std::sync::Arc<tokio::sync::Barrier>,
    work: impl std::future::Future<Output = T>,
) -> T {
    NAMED_REGISTER_PAUSE.scope((arrived, resume), work).await
}

/// Test-only connection adapter into the real caller-relative installer,
/// registry expansion/registration and result executor. It neither loads nor
/// enables a v2 revision. The fixture owns the snapshot and rolls it back.
#[cfg(test)]
pub(crate) async fn generated_checkpoint_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    name: &str,
    definition: &crate::named_views::contract::Definition,
    outer: &crate::named_views::contract::SavedSqlV12,
    deadline: Instant,
) -> Result<Value> {
    outer.validate_current()?;
    let started = deadline - Duration::from_millis(contract::QUERY_DEADLINE_MS);
    conn.lock_handle()
        .await?
        .set_progress_handler(guard::PROGRESS_OPS, move || Instant::now() < deadline);
    let roots = outer.roots();
    let pin = roots
        .get(name)
        .ok_or_else(|| Error::engine("checkpoint root missing"))?;
    let mut registry = named_views::Registry::generated_checkpoint(name, definition, pin)?;
    let (mut prepared, mut reads) = prepare_read_with_views(
        actor,
        json!({"sql":outer.sql,"parameters":outer.parameters}),
        true,
        Some(&registry),
    )?;
    registry.expand(&mut reads)?;
    prepared.persistent = false;
    install_relations(
        conn,
        actor,
        &reads,
        LinkScope::All,
        None,
        None,
        None,
        None,
        None,
        chrono::Utc::now().timestamp_millis(),
        false,
        None,
        None,
        None,
    )
    .await?;
    registry.register(conn).await?;
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events")
        .fetch_one(&mut *conn)
        .await?;
    execute_prepared(conn, prepared, head, started).await
}

// Scan has no whole-call wall-clock wrapper. Its select/enrichment snapshot
// owns a 2 s VM guard, separate from relation staging and later successors.
// Reserve 500 ms of that actual deadline for axes and sample enrichment; HQ
// owner attribution can take ~695 ms, so a fixed 800 ms cap is too tight.
const SCAN_ATTRIBUTION_RESERVE: Duration = Duration::from_millis(500);
#[cfg(test)]
tokio::task_local! {
    pub(super) static TEST_SCAN_ATTRIBUTION_BUDGET: Duration;
    pub(super) static TEST_SCAN_ATTRIBUTION_EXIT_AT: std::cell::Cell<usize>;
    pub(super) static TEST_SNAPSHOT_BUDGET: Duration;
}
fn snapshot_budget() -> Duration {
    #[cfg(test)]
    if let Ok(budget) = TEST_SNAPSHOT_BUDGET.try_with(|b| *b) {
        return budget;
    }
    Duration::from_millis(contract::QUERY_DEADLINE_MS)
}

/// Stage births and the newest authored positions first. Only unresolved
/// records walk older authored positions, in bounded descending windows.
/// Ordinary event admission/disclosure and the read deadline remain in force.
pub(super) async fn scan_attribution_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    ids: &[String],
    selector: Option<&str>,
) -> Result<Option<Vec<(String, String, Option<i64>, Option<String>)>>> {
    const AUTHORED_WINDOW: i64 = 256;
    let started = Instant::now();
    let deadline = SNAPSHOT_VM_DEADLINE
        .try_with(|deadline| {
            deadline
                .checked_sub(SCAN_ATTRIBUTION_RESERVE)
                .unwrap_or(started)
        })
        .map_err(|_| Error::engine("scan attribution requires a snapshot VM deadline"))?;
    #[cfg(test)]
    let deadline = TEST_SCAN_ATTRIBUTION_BUDGET
        .try_with(|budget| deadline.min(started + *budget))
        .unwrap_or(deadline);
    // Check cooperatively: interrupting a TEMP-table write can roll back the
    // entire shared SQLite transaction. Each statement retains the enclosing
    // VM deadline; never cancel it or reset that deadline for attribution.
    macro_rules! budget_checkpoint {
        () => {
            #[cfg(test)]
            if TEST_SCAN_ATTRIBUTION_EXIT_AT
                .try_with(|remaining| {
                    let count = remaining.get();
                    remaining.set(count.saturating_sub(1));
                    count == 1
                })
                .unwrap_or(false)
            {
                return Ok(None);
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
        };
    }
    kernel::legacy_history::require_sql_frontier_on(conn).await?;
    let binding: String =
        sqlx::query_scalar("SELECT auth_binding FROM main.kernel_principals WHERE principal_id=?")
            .bind(actor)
            .fetch_one(&mut *conn)
            .await?;
    let owner = kernel::kernel_effective_capability_on(conn, actor, crate::events::KERNEL_ROOT_ID)
        .await?
        .allows(Capability::Manage);
    if selector.is_some_and(|s| s != binding) && !owner {
        return Err(Error::engine(
            "scan: authored_by may name only the current caller",
        ));
    }
    let target: String = match selector {
        None => actor.to_owned(),
        Some(value) => sqlx::query_scalar("SELECT principal_id FROM main.kernel_principals WHERE auth_binding=? AND kind='account'")
            .bind(value).fetch_optional(&mut *conn).await?
            .ok_or_else(|| Error::engine("scan: 'authored_by' must be an account token present in this file"))?,
    };
    let legacy_target: String = sqlx::query_scalar(
        "SELECT 'v1:'||auth_binding FROM main.kernel_principals WHERE principal_id=?",
    )
    .bind(&target)
    .fetch_one(&mut *conn)
    .await?;
    budget_checkpoint!();
    sqlx::query(
        "CREATE TEMP TABLE _scan_headers(id TEXT PRIMARY KEY,genesis INTEGER,latest INTEGER,candidate INTEGER)",
    )
    .execute(&mut *conn)
    .await?;
    budget_checkpoint!();
    sqlx::query("CREATE TEMP TABLE _v2_history_candidates(seq INTEGER PRIMARY KEY)")
        .execute(&mut *conn)
        .await?;
    budget_checkpoint!();
    // Correlated lookups use the record/seq indexes. Imported births must
    // prefer the source create even when that header will fail admission.
    // Falling back after admission would credit the host import principal.
    let imported = super::IMPORTED_EVENTS
        .iter()
        .map(|v| format!("'{v}'"))
        .collect::<Vec<_>>()
        .join(",");
    sqlx::query("INSERT INTO temp._scan_headers SELECT r.id,coalesce((SELECT min(m.seq) FROM main.kernel_legacy_sql_events m WHERE m.record_id=r.id AND m.source_stream='content_events' AND m.event_type='record.created'),r.created_seq),NULL,NULL FROM main.kernel_records r WHERE r.id IN (SELECT value FROM json_each(?1))")
        .bind(serde_json::to_string(ids)?).execute(&mut *conn).await?;
    budget_checkpoint!();
    tracing::debug!(target: "native_ce::read_staging", phase="scan_headers", elapsed_us=started.elapsed().as_micros() as u64);
    let root = kernel::kernel_effective_capability_on(conn, actor, crate::events::KERNEL_ROOT_ID)
        .await?
        .allows(Capability::View);
    let native_authored = format!("e.type!='kernel.legacy_recorded.v1' AND e.type NOT GLOB 'kernel.hcp_*' AND e.type NOT GLOB 'kernel.webhook_*' AND e.type NOT GLOB 'kernel.import_*' AND e.type NOT IN ({imported}) AND e.actor=?1");
    let legacy_authored = "m.source_stream='content_events' AND m.actor=?2";
    // Filter excluded types from the existing (record_id,type,seq) index
    // before loading actor from event rows. The record/seq plan fetches every
    // retained envelope when a record has no native authored position.
    // Indexed newest-position lookups do not stage the target's whole
    // history. In the common case admission settles a record immediately.
    sqlx::query(&format!("UPDATE temp._scan_headers AS s SET candidate=max(coalesce((SELECT max(e.seq) FROM main.content_events e INDEXED BY idx_kernel_hosted_event_lookup WHERE e.record_id=s.id AND {native_authored}),0),coalesce((SELECT max(m.seq) FROM main.kernel_legacy_sql_events m WHERE m.record_id=s.id AND {legacy_authored}),0))"))
        .bind(&target).bind(&legacy_target).execute(&mut *conn).await?;
    budget_checkpoint!();
    tracing::debug!(target: "native_ce::read_staging", phase="scan_newest_authored", elapsed_us=started.elapsed().as_micros() as u64);
    let positions = sqlx::query("INSERT INTO temp._v2_history_candidates SELECT genesis FROM temp._scan_headers WHERE genesis IS NOT NULL UNION SELECT candidate FROM temp._scan_headers WHERE candidate>0")
        .execute(&mut *conn).await?.rows_affected();
    tracing::debug!(target: "native_ce::read_staging", phase="scan_candidates", elapsed_us=started.elapsed().as_micros() as u64,positions);
    select_event_ids(conn, true).await?;
    budget_checkpoint!();
    tracing::debug!(target: "native_ce::read_staging", phase="scan_native_ids", elapsed_us=started.elapsed().as_micros() as u64);
    install_events(conn, actor, root, true).await?;
    budget_checkpoint!();
    tracing::debug!(target: "native_ce::read_staging", phase="scan_admitted", elapsed_us=started.elapsed().as_micros() as u64);
    sqlx::query("CREATE INDEX _scan_admitted_author ON _v2_event_rows(record_id,actor,local_seq)")
        .execute(&mut *conn)
        .await?;
    budget_checkpoint!();
    // An admitted birth alone cannot settle authored_latest: an admitted
    // edit may lie between that birth and a newer unadmitted position.
    sqlx::query("UPDATE temp._scan_headers AS s SET latest=(SELECT a.local_seq FROM temp._v2_event_rows a WHERE a.local_seq=s.candidate AND a.actor=?1)")
        .bind(&target).execute(&mut *conn).await?;
    budget_checkpoint!();
    sqlx::query("CREATE INDEX _scan_pending ON _scan_headers(candidate) WHERE latest IS NULL AND candidate>0; CREATE TEMP TABLE _scan_tail(id TEXT,seq INTEGER,PRIMARY KEY(id,seq))")
        .execute(&mut *conn).await?;
    budget_checkpoint!();
    while sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM temp._scan_headers WHERE latest IS NULL AND candidate>0)",
    )
    .fetch_one(&mut *conn)
    .await?
    {
        sqlx::query("DELETE FROM temp._scan_tail; DELETE FROM temp._v2_history_candidates; DELETE FROM temp._v2_event_ids")
            .execute(&mut *conn).await?;
        budget_checkpoint!();
        // Bound each pending record's next window; settled records and birth
        // headers are never restaged. Native and legacy positions are disjoint.
        sqlx::query(&format!("INSERT INTO temp._scan_tail SELECT s.id,j.value FROM temp._scan_headers s CROSS JOIN json_each((SELECT json_group_array(seq) FROM (SELECT seq FROM (SELECT e.seq FROM main.content_events e INDEXED BY idx_kernel_hosted_event_lookup WHERE e.record_id=s.id AND e.seq<s.candidate AND {native_authored} UNION ALL SELECT m.seq FROM main.kernel_legacy_sql_events m WHERE m.record_id=s.id AND m.seq<s.candidate AND {legacy_authored}) ORDER BY seq DESC LIMIT {AUTHORED_WINDOW}))) j WHERE s.latest IS NULL AND s.candidate>0"))
            .bind(&target).bind(&legacy_target).execute(&mut *conn).await?;
        budget_checkpoint!();
        let positions = sqlx::query("INSERT INTO temp._v2_history_candidates SELECT DISTINCT t.seq FROM temp._scan_tail t WHERE NOT EXISTS(SELECT 1 FROM temp._v2_event_rows a WHERE a.local_seq=t.seq)")
            .execute(&mut *conn).await?.rows_affected();
        if positions > 0 {
            select_event_ids(conn, true).await?;
            budget_checkpoint!();
            install_events(conn, actor, root, true).await?;
            budget_checkpoint!();
        }
        // Accept the newest admitted position only if it lies in the visited
        // prefix, or this partial/empty window proves history is exhausted.
        // Otherwise continue older windows under the unchanged deadline;
        // never substitute a birth or zero because an arbitrary K was reached.
        sqlx::query(&format!("UPDATE temp._scan_headers AS s SET latest=(SELECT max(a.local_seq) FROM temp._v2_event_rows a WHERE a.record_id=s.id AND a.actor=?1 AND (a.local_seq>=(SELECT min(t.seq) FROM temp._scan_tail t WHERE t.id=s.id) OR (SELECT count(*) FROM temp._scan_tail t WHERE t.id=s.id)<{AUTHORED_WINDOW})) WHERE s.latest IS NULL AND s.candidate>0"))
            .bind(&target).execute(&mut *conn).await?;
        budget_checkpoint!();
        sqlx::query(&format!("UPDATE temp._scan_headers AS s SET candidate=CASE WHEN (SELECT count(*) FROM temp._scan_tail t WHERE t.id=s.id)<{AUTHORED_WINDOW} THEN 0 ELSE (SELECT min(t.seq) FROM temp._scan_tail t WHERE t.id=s.id) END WHERE s.latest IS NULL AND s.candidate>0"))
            .execute(&mut *conn).await?;
        budget_checkpoint!();
        tracing::debug!(target: "native_ce::read_staging", phase="scan_authored_window",elapsed_us=started.elapsed().as_micros() as u64,positions);
    }
    // A boolean run signal is all scan discloses. Neither native root-only
    // run keys nor admitted legacy run keys leave this internal query.
    // Retained births already carry their run signal in m. Loading their
    // wrapped content row would read a potentially large envelope just to
    // compute unused native-only actor/run fields.
    let rows_started = Instant::now();
    let rows = sqlx::query_as("SELECT s.id,CASE WHEN g.local_seq IS NULL OR (m.seq IS NULL AND birth.auth_binding=?3) THEN 'unknown' WHEN (CASE WHEN m.seq IS NOT NULL THEN m.run_key ELSE e.run_key END) IS NOT NULL THEN 'agent' WHEN g.actor=?1 THEN 'you' WHEN p.kind='account' THEN 'other_account' ELSE 'unknown' END,
      a.local_seq,a.created_at FROM temp._scan_headers s
      LEFT JOIN temp._v2_event_rows g ON g.local_seq=s.genesis
      LEFT JOIN main.kernel_legacy_sql_events m ON m.seq=g.local_seq
      LEFT JOIN main.content_events e ON e.seq=CASE WHEN m.seq IS NULL THEN g.local_seq END
      LEFT JOIN main.kernel_principals birth ON birth.principal_id=e.actor
      LEFT JOIN main.kernel_principals p ON p.principal_id=g.actor
      LEFT JOIN temp._v2_event_rows a ON a.local_seq=s.latest AND a.actor=?2")
      .bind(actor).bind(target).bind(kernel::hq::HOST_IMPORT_BINDING).fetch_all(&mut *conn).await?;
    tracing::debug!(target: "native_ce::read_staging", phase="scan_attribution_join", elapsed_us=rows_started.elapsed().as_micros() as u64);
    // Complete rows are already paid for: preserve them even if the last
    // statement used the remaining attribution allowance.
    Ok(Some(rows))
}
