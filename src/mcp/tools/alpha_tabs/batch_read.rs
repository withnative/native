//! Batched on-request reads: `live_read` with `reads: [{need, params?}]`
//! (task `9be4011`, slice 3).
//!
//! A tab opening a page asks for several declared needs at once. One call
//! answers all of them and pays the install gate once per pool rather than
//! once per need:
//!
//! - The gate runs first, on a read-only-pool transaction. A gate refusal
//!   (missing install, stale token, disabled, lost View, source or digest
//!   drift, a declaration whose SQL needs no longer parse) fails the whole
//!   call, as it fails a single read.
//! - Each item is then checked as a single read checks it (snapshot,
//!   declared SQL key, declaration membership, push-only, parameters), and
//!   anything wrong with one item is reported against that item only.
//! - Search, reference and canvas items read through that same gate
//!   transaction. SQL items share one governed transaction with its own
//!   gate. Record-change, artifact-render and snapshot items each run through
//!   their single read path, which gates on its own (cached) snapshot.
//! - A gate that refuses partway through, because the install changed
//!   after the first gate passed, also fails the whole call: the SQL
//!   group's gate refusal directly, and a record-change, artifact-render or
//!   snapshot item's failure whenever a fresh gate now refuses
//!   (`gate_still_passes`).
//!
//! Items are therefore not one snapshot: host items share one, SQL items
//! share another, and record-change, artifact-render and snapshot items each
//! have their own.
//! Every successful item carries exactly the body its single read returns.
//!
//! Groups run one after another (host, SQL, own-path reads, snapshots), and
//! items within a group in request order. Running the host and SQL groups
//! concurrently on their two pools measured no faster for an eight-need page
//! (`docs/perf/tab-read-baseline.md`): the SQL items dominate, and on one
//! governed transaction they cannot overlap.

use super::*;

/// Most items one batched read may carry.
pub(super) const LIVE_READ_BATCH_MAX: usize = 16;

/// One item of a batched `live_read`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiveReadItem {
    pub need: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// What an item turned out to be once the gate and its own checks passed.
enum Planned {
    Host(DeclaredRead),
    /// A declared read whose single read path gates itself (record changes,
    /// artifact render), so it runs there rather than on the gate's
    /// transaction.
    OwnPath(DeclaredRead),
    Sql,
    Snapshot,
}

fn refused(code: &str) -> Error {
    Error::engine(format!("{TOOL}: live read refused [{code}]"))
}

/// The code inside an error's trailing `[code]`, as the refusals in this
/// module spell it, or `read_failed` for anything without one.
fn error_code(message: &str) -> String {
    message
        .rsplit_once('[')
        .and_then(|(_, tail)| tail.strip_suffix(']'))
        .filter(|code| {
            !code.is_empty()
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
        .unwrap_or("read_failed")
        .to_string()
}

fn item_result(need: &str, result: Result<Value>) -> Value {
    match result {
        Ok(body) => json!({"need": need, "ok": body}),
        Err(error) => {
            let message = error.to_string();
            json!({
                "need": need,
                "error": {"code": error_code(&message), "message": message},
            })
        }
    }
}

/// The checks a single read makes after its gate, in the same order, for
/// one item. `Err` is that item's refusal.
fn plan(
    gate: &LiveReadGate,
    sql_keys: &[String],
    item: &LiveReadItem,
) -> std::result::Result<Planned, Error> {
    let need = item.need.as_str();
    if need == ATTENTION_QUERY_NEED {
        if item.params.is_some() {
            return Err(refused("invalid_params"));
        }
        return Ok(Planned::Snapshot);
    }
    if sql_keys.iter().any(|key| key == need) {
        if HOST_READ_NEEDS.contains(&need) {
            // As in the single read: install refuses a SQL key named like a
            // host need, so this cannot happen. Fail closed.
            return Err(refused("undeclared_need"));
        }
        return Ok(Planned::Sql);
    }
    if !gate.needs.iter().any(|declared| declared == need) {
        return Err(refused("undeclared_need"));
    }
    if PUSH_ONLY_NEEDS.contains(&need) {
        return Err(refused("undeclared_need"));
    }
    match parse_declared_read(need, item.params.as_ref()).map_err(refused)? {
        read @ (DeclaredRead::RecordChanges { .. } | DeclaredRead::ArtifactRender { .. }) => {
            Ok(Planned::OwnPath(read))
        }
        read => Ok(Planned::Host(read)),
    }
}

/// One search, reference or canvas item on the gate's own transaction.
async fn host_item_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    package: &str,
    gate: &LiveReadGate,
    need: &str,
    read: DeclaredRead,
) -> Result<Value> {
    let (echo, result) = match read {
        DeclaredRead::Search { query, limit } => {
            let result =
                super::super::querying::search_in(tx, caller, &query, None, Some(limit), false)
                    .await?;
            (json!({"query": query, "limit": limit}), result)
        }
        DeclaredRead::ResolveReference { reference } => {
            let result = resolve_reference_in(tx, caller, &reference).await?;
            (json!({"reference": reference}), result)
        }
        DeclaredRead::CanvasScene {
            canvas_id,
            limit,
            cursor,
        } => {
            let after = match cursor.as_deref() {
                None => None,
                Some(cursor) => Some(
                    super::super::canvas::SceneCursor::decode(cursor)
                        .ok_or_else(|| refused("invalid_params"))?,
                ),
            };
            let result =
                canvas_scene_in(tx, caller, &gate.row.event_id, &canvas_id, limit, after).await?;
            (
                json!({"canvas_id": canvas_id, "limit": limit, "cursor": cursor}),
                result,
            )
        }
        DeclaredRead::RecordChanges { .. } | DeclaredRead::ArtifactRender { .. } => {
            unreachable!("self-gating reads are planned onto their own path")
        }
    };
    Ok(declared_read_body(
        package,
        &gate.row,
        &gate.source,
        &gate.runtime,
        &gate.bundle_sha256,
        need,
        echo,
        result,
    ))
}

/// One SQL item on the governed transaction its gate passed on.
async fn sql_item_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    package: &str,
    gate: &LiveReadGate,
    item: &LiveReadItem,
) -> Result<Value> {
    let sql_need = gate
        .verified
        .sql_needs()?
        .into_iter()
        .find(|candidate| candidate.key == item.need)
        .ok_or_else(|| refused("undeclared_need"))?;
    let echo = item.params.clone().unwrap_or(json!({}));
    let bound = bind_sql_params(&sql_need, item.params.as_ref()).map_err(refused)?;
    let principal: crate::query::QueryPrincipal = caller.into();
    let executed = execute_sql_need_in(tx, principal, &sql_need, bound, None, None).await?;
    let revision = sql_keyed_revision(&gate.row, &sql_need, &executed.digest);
    let mut body = declared_read_body(
        package,
        &gate.row,
        &gate.source,
        &gate.runtime,
        &gate.bundle_sha256,
        &item.need,
        echo,
        executed.input,
    );
    if let Some(revision) = revision {
        body["revision"] = json!({"revision_digest": revision});
    }
    Ok(body)
}

/// The SQL items, in request order, on one governed transaction gated once.
/// A failed item ends that transaction and the next item opens a fresh one,
/// so an execution error cannot leave later items on a broken snapshot. A
/// gate refusal here fails the whole call.
async fn sql_group(
    db: &Db,
    caller: &Caller,
    account_id: &str,
    package: &str,
    expected_install_event_id: &str,
    items: Vec<(usize, &LiveReadItem)>,
) -> Result<Vec<(usize, Value)>> {
    let mut out = Vec::with_capacity(items.len());
    let mut open: Option<(sqlx::Transaction<'static, sqlx::Sqlite>, LiveReadGate)> = None;
    for (index, item) in items {
        let (tx, gate) = match open.as_mut() {
            Some(open) => open,
            None => {
                let mut tx = db.governed_pool().begin().await?;
                let gate = live_read_gates_in(
                    db,
                    &mut tx,
                    caller,
                    account_id,
                    package,
                    expected_install_event_id,
                )
                .await?;
                open.insert((tx, gate))
            }
        };
        let result = sql_item_in(tx, caller, package, gate, item).await;
        if result.is_err() {
            if let Some((tx, _)) = open.take() {
                let _ = tx.rollback().await;
            }
        }
        out.push((index, item_result(&item.need, result)));
    }
    if let Some((tx, _)) = open {
        tx.rollback().await?;
    }
    Ok(out)
}

/// After a record-change or snapshot item fails: whether the install gate
/// still passes on a fresh snapshot. Those items re-run the gate inside
/// their single read path, so their error may be a gate refusal, which is
/// about the install and fails the whole batch rather than one item.
async fn gate_still_passes(
    db: &Db,
    caller: &Caller,
    account_id: &str,
    package: &str,
    expected_install_event_id: &str,
) -> Result<()> {
    let mut tx = db.pool().begin().await?;
    let gate = live_read_gates_in(
        db,
        &mut tx,
        caller,
        account_id,
        package,
        expected_install_event_id,
    )
    .await;
    tx.rollback().await?;
    gate.map(|_| ())
}

/// `live_read` with `reads`: every item answered in request order, under one
/// gate per pool. See the module documentation for what is shared.
pub(super) async fn do_batch_read(
    db: &Db,
    caller: &Caller,
    package: String,
    expected_install_event_id: String,
    reads: Vec<LiveReadItem>,
) -> Result<Value> {
    if reads.is_empty() || reads.len() > LIVE_READ_BATCH_MAX {
        return Err(Error::engine(format!(
            "{TOOL}: live read refused: reads must hold 1..={LIVE_READ_BATCH_MAX} items, got {} [invalid_params]",
            reads.len()
        )));
    }
    let account_id = live_read_precheck(caller, &package, &expected_install_event_id)?;
    let mut tx = db.pool().begin().await?;
    let gate = live_read_gates_in(
        db,
        &mut tx,
        caller,
        &account_id,
        &package,
        &expected_install_event_id,
    )
    .await?;
    let sql_keys: Vec<String> = gate
        .verified
        .sql_needs()?
        .into_iter()
        .map(|need| need.key)
        .collect();

    let mut results: Vec<Option<Value>> = vec![None; reads.len()];
    let mut host = Vec::new();
    let mut sql = Vec::new();
    let mut own_path = Vec::new();
    let mut snapshots = Vec::new();
    for (index, item) in reads.iter().enumerate() {
        match plan(&gate, &sql_keys, item) {
            Err(error) => results[index] = Some(item_result(&item.need, Err(error))),
            Ok(Planned::Host(read)) => host.push((index, item, read)),
            Ok(Planned::Sql) => sql.push((index, item)),
            Ok(Planned::OwnPath(read)) => own_path.push((index, item, read)),
            Ok(Planned::Snapshot) => snapshots.push((index, item)),
        }
    }

    let mut host_out = Vec::with_capacity(host.len());
    for (index, item, read) in host {
        let result = host_item_in(&mut tx, caller, &package, &gate, &item.need, read).await;
        host_out.push((index, item_result(&item.need, result)));
    }
    tx.rollback().await?;
    let sql_out = sql_group(
        db,
        caller,
        &account_id,
        &package,
        &expected_install_event_id,
        sql,
    )
    .await?;

    let mut other_out = Vec::with_capacity(own_path.len() + snapshots.len());
    for (index, item, read) in own_path {
        let (echo, result) = match read {
            DeclaredRead::RecordChanges {
                record_id,
                limit,
                cursor,
            } => (
                json!({"record_id": record_id, "limit": limit, "cursor": cursor}),
                record_changes_read(
                    db,
                    caller,
                    &package,
                    &expected_install_event_id,
                    &record_id,
                    limit,
                    cursor.as_deref(),
                )
                .await,
            ),
            DeclaredRead::ArtifactRender { artifact_id } => (
                json!({"artifact_id": artifact_id}),
                artifact_render_read(
                    db,
                    caller,
                    &package,
                    &expected_install_event_id,
                    &artifact_id,
                )
                .await,
            ),
            DeclaredRead::Search { .. }
            | DeclaredRead::ResolveReference { .. }
            | DeclaredRead::CanvasScene { .. } => {
                unreachable!("gate-transaction reads are planned onto the host group")
            }
        };
        let result = result.map(|result| {
            declared_read_body(
                &package,
                &gate.row,
                &gate.source,
                &gate.runtime,
                &gate.bundle_sha256,
                &item.need,
                echo,
                result,
            )
        });
        if result.is_err() {
            gate_still_passes(
                db,
                caller,
                &account_id,
                &package,
                &expected_install_event_id,
            )
            .await?;
        }
        other_out.push((index, item_result(&item.need, result)));
    }
    for (index, item) in snapshots {
        let result = Box::pin(do_live_read(
            db,
            caller,
            package.clone(),
            expected_install_event_id.clone(),
            None,
            None,
            LiveReadOptions {
                subscribe: None,
                if_revision: None,
                watch: None,
            },
        ))
        .await;
        if result.is_err() {
            gate_still_passes(
                db,
                caller,
                &account_id,
                &package,
                &expected_install_event_id,
            )
            .await?;
        }
        other_out.push((index, item_result(&item.need, result)));
    }
    for (index, value) in host_out.into_iter().chain(sql_out).chain(other_out) {
        results[index] = Some(value);
    }

    Ok(json!({
        "package": package,
        "install_event_id": gate.row.event_id,
        "pin": {
            "package": gate.row.package,
            "version": gate.row.version,
            "digest": gate.row.digest,
            "artifact_id": gate.row.artifact_id,
            "source_revision": gate.row.consented_source_revision,
            "declaration_digest": gate.row.declaration_digest,
        },
        "source": {
            "event_id": gate.source.event_id,
            "bundle_sha256": gate.bundle_sha256,
            "runtime": gate.runtime,
        },
        "results": results.into_iter().map(|result| result.expect("every item answered")).collect::<Vec<_>>(),
        "live_reads": true,
        "effects_wired": false,
    }))
}

#[cfg(test)]
mod tests {
    use super::error_code;

    #[test]
    fn error_codes_come_from_the_trailing_bracket_only() {
        assert_eq!(
            error_code("manage_alpha_tabs: live read refused [undeclared_need]"),
            "undeclared_need"
        );
        assert_eq!(
            error_code("manage_alpha_tabs: sql need 'a' failed: boom [sql_need_failed]"),
            "sql_need_failed"
        );
        assert_eq!(
            error_code("search: 'query' must be non-empty"),
            "read_failed"
        );
        assert_eq!(error_code("odd [Not A Code]"), "read_failed");
        assert_eq!(error_code("trailing [code] then text"), "read_failed");
    }
}
