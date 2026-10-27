//! Optional physical acceleration; event state remains authoritative.
use super::*;

pub(crate) const INDEX_DDL: &str = "CREATE INDEX IF NOT EXISTS idx_kernel_named_view_lifecycle ON content_events(type,seq,record_id,id) WHERE type IN ('kernel.named_view_revision_recorded.v1','kernel.named_view_binding_changed.v1','kernel.named_view_admitted.v1')";
const PREDICATE: &str = "type IN ('kernel.named_view_revision_recorded.v1','kernel.named_view_binding_changed.v1','kernel.named_view_admitted.v1')";

pub(crate) fn prefix_query() -> String {
    format!("SELECT seq,id,record_id,type FROM content_events WHERE {PREDICATE} AND seq<=? ORDER BY type,seq LIMIT 777")
}

pub(crate) async fn verify_index_on(conn: &mut SqliteConnection) -> Result<bool> {
    let entry: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT type,tbl_name,sql FROM sqlite_schema WHERE name='idx_kernel_named_view_lifecycle'",
    )
    .fetch_optional(conn)
    .await?;
    match entry {
        None => Ok(false),
        Some((kind, table, sql))
            if kind == "index"
                && table == "content_events"
                && sql.as_deref() == Some(INDEX_DDL.replacen(" IF NOT EXISTS", "", 1).as_str()) =>
        {
            Ok(true)
        }
        _ => Err(invalid(
            "optional lifecycle index differs from compiled schema",
        )),
    }
}

/// Optional physical preparation; never a readiness or event-emission condition.
/// Verify an existing object before IF NOT EXISTS can hide incompatible DDL.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) async fn ensure_index_on(conn: &mut SqliteConnection) -> Result<bool> {
    let installed = verify_index_on(conn).await?;
    if !installed {
        sqlx::query(INDEX_DDL).execute(&mut *conn).await?;
    }
    verify_index_on(conn).await?;
    Ok(installed)
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
tokio::task_local! { static FALLBACK_HEADERS: std::cell::Cell<usize>; }
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) async fn measured_fallback<T>(work: impl std::future::Future<Output = T>) -> (T, usize) {
    FALLBACK_HEADERS
        .scope(std::cell::Cell::new(0), async {
            let result = work.await;
            (result, FALLBACK_HEADERS.with(std::cell::Cell::get))
        })
        .await
}

/// The prefix is already canonical/verified. V1 keeps its header-only path;
/// v2 bodies pass bounded closed-format validation before header certification.
/// New events still pass ReplayChecker::apply; serving rejects v2 independently.
pub(crate) async fn load_prefix(
    conn: &mut SqliteConnection,
    head: i64,
    deadline: impl Into<Option<Instant>>,
) -> Result<ReplayChecker> {
    let deadline = deadline.into();
    let check = || deadline.map(check_deadline).transpose().map(|_| ());
    check()?;
    let headers = load_headers(conn, head, deadline).await?;
    let mut checker = ReplayChecker::default();
    for (seq, id, record, kind) in &headers {
        check()?;
        if kind == REVISION {
            if checker.revisions.len() >= MAX_REVISIONS
                || checker
                    .revisions
                    .values()
                    .filter(|r| r.record_id == *record)
                    .count()
                    >= 128
            {
                return Err(invalid("revision history limit"));
            }
            // Count SQL-side JSON parsing as body access as well as read_event.
            #[cfg(test)]
            record_revision_access(id);
            let (version_kind, version, bytes): (Option<String>, Option<i64>, i64) = sqlx::query_as(
                "SELECT json_type(payload,'$.v'),json_extract(payload,'$.v'),length(CAST(payload AS BLOB)) FROM content_events WHERE id=? AND seq<=?")
                .bind(id).bind(head).fetch_one(&mut *conn).await?;
            if version_kind.as_deref() != Some("integer") {
                return Err(invalid("revision identity/version/digest mismatch"));
            }
            let mut generated_name = None;
            let (digest, schema, origin): (String, String, String) = match version {
                Some(1) => sqlx::query_as("SELECT json_extract(payload,'$.definition_sha256'),json_extract(payload,'$.definition.query.output.schema_sha256'),json_extract(payload,'$.definition.origin.kind') FROM content_events WHERE id=? AND seq<=?")
                    .bind(id).bind(head).fetch_one(&mut *conn).await?,
                Some(2) => {
                    if !(0..=MAX_CARRIER_BYTES as i64).contains(&bytes) {
                        return Err(invalid("payload exceeds bound"));
                    }
                    let event = read_event(conn, id, head).await?;
                    let revision: Revision = decode(&event, MAX_CARRIER_BYTES)?;
                    let definition = revision.validate_retained(&event)?;
                    generated_name = revision.generated_name();
                    (revision.definition_sha256, definition.query.output.schema_sha256, "generated".into())
                }
                _ => return Err(invalid("revision identity/version/digest mismatch")),
            };
            if digest.len() != 64 || schema.len() != 64 {
                return Err(invalid("invalid revision header"));
            }
            checker.revisions.insert(
                id.clone(),
                RevisionHeader {
                    record_id: record.clone(),
                    seq: *seq,
                    digest,
                    schema_digest: schema,
                    generated: origin == "generated",
                    generated_name,
                },
            );
        }
    }
    for (_, id, _, kind) in &headers {
        check()?;
        if kind != REVISION {
            checker.apply(&read_event(conn, id, head).await?)?;
        }
    }
    checker.last_seq = head.max(0);
    Ok(checker)
}

// No revision payload/JSON paths are read here. Both consumers share the same
// optional-index and bounded fallback policy; only canonical load_prefix may
// certify the historical bodies.
async fn load_headers(
    conn: &mut SqliteConnection,
    head: i64,
    deadline: Option<Instant>,
) -> Result<Vec<(i64, String, String, String)>> {
    let check = || deadline.map(check_deadline).transpose().map(|_| ());
    let mut headers = Vec::new();
    if verify_index_on(conn).await? {
        let query = prefix_query();
        headers = sqlx::query_as::<_, (i64, String, String, String)>(&query)
            .bind(head)
            .fetch_all(&mut *conn)
            .await?;
        check_history_counts(&headers)?;
    } else {
        let mut after = 0;
        let mut inspected = 0;
        let mut bytes = 0;
        while after < head {
            check()?;
            let rows:Vec<(i64,String,String,String)>=sqlx::query_as("SELECT seq,id,record_id,type FROM content_events WHERE seq>? AND seq<=? ORDER BY seq LIMIT 512").bind(after).bind(head).fetch_all(&mut *conn).await?;
            if rows.is_empty() {
                break;
            }
            for (seq, id, record, kind) in rows {
                #[cfg(all(test, feature = "v2-kernel-probe"))]
                let _ = FALLBACK_HEADERS.try_with(|n| n.set(n.get() + 1));
                inspected += 1;
                bytes += serde_json::to_vec(&(seq, &id, &record, &kind))?.len();
                if inspected > 65_536 || bytes > 8 * 1024 * 1024 {
                    return Err(invalid("view_registry_scan_budget_exceeded; ask a workspace administrator to run records_write.prepare_named_views on an upgraded hosted writer after reader rollout, then refresh read-only copies"));
                }
                check()?;
                after = seq;
                if is_new_event(&kind) || kind == LEGACY {
                    headers.push((seq, id, record, kind));
                }
                check_history_counts(&headers)?;
            }
        }
    }
    check()?;
    headers.sort_by_key(|h| h.0);
    Ok(headers)
}

// Slice 1 admitted at most eight bindings. Its legacy carriers consume their
// own budget and cannot take slots from retained revision/transition history.
fn check_history_counts(headers: &[(i64, String, String, String)]) -> Result<()> {
    let legacy = headers.iter().filter(|h| h.3 == LEGACY).count();
    if legacy > 8 {
        return Err(invalid("legacy admission history limit"));
    }
    if headers.len() - legacy > MAX_REVISIONS + MAX_TRANSITIONS {
        return Err(invalid("lifecycle history limit"));
    }
    Ok(())
}

pub(crate) fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err(invalid("named view deadline exceeded"))
    } else {
        Ok(())
    }
}

/// Called within the append transaction after the closed admission gate. The
/// caller already holds BEGIN IMMEDIATE; replay never invokes this live path.
pub(crate) async fn admit_on(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    admit(&event.event_type)?;
    if !is_new_event(&event.event_type) {
        return Ok(());
    }
    #[cfg(feature = "v2-kernel-probe")]
    let deadline = super::gate::deadline();
    #[cfg(not(feature = "v2-kernel-probe"))]
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut state = load_live(conn, i64::MAX, deadline).await?;
    if state.legacy() {
        return Err(invalid("legacy_named_view_format_unsupported"));
    }
    // Append admission occurs before SQLite assigns seq; use the next prefix
    // coordinate, without mutating the host-assigned event identity.
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *conn)
        .await?;
    let mut proposed = event.clone();
    proposed.local_seq = head + 1;
    state.apply_new_on(conn, &proposed, deadline).await
}

/// Deliberately not a ReplayChecker: indexed historical identities and namespace
/// transitions are trusted only on an already canonically admitted database.
/// These provisional entries must never certify an executable definition.
#[derive(Default)]
pub(crate) struct LiveNamespace {
    state: ReplayChecker,
}
impl LiveNamespace {
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn revision_ids(&self) -> impl Iterator<Item = (&String, &str, i64)> {
        self.state
            .revisions
            .iter()
            .map(|(id, h)| (id, h.record_id.as_str(), h.seq))
    }
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    pub(crate) fn bindings(&self) -> &BTreeMap<String, Binding> {
        &self.state.bindings
    }
    pub(crate) fn legacy(&self) -> bool {
        self.state.legacy
    }
    /// New effects validate their bounded direct/reference closure, never SQL.
    pub(crate) async fn apply_new_on(
        &mut self,
        conn: &mut SqliteConnection,
        event: &EventRow,
        deadline: Instant,
    ) -> Result<()> {
        let mut pending = Vec::new();
        if event.event_type == REVISION {
            let revision: Revision = decode(event, MAX_CARRIER_BYTES)?;
            if revision.v != 1 {
                return Err(invalid("view_revision_unavailable"));
            }
            let definition = revision.validate_retained(event)?;
            pending.extend(definition.query.relations.values().filter_map(|d| match d {
                contract::Dependency::View(p) => Some(p.clone()),
                _ => None,
            }));
        } else if event.event_type == TRANSITION {
            let transition: Transition = decode(event, 2048)?;
            if let Action::Activate { pin, .. } = transition.action {
                pending.push(pin);
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut bytes = if event.event_type == REVISION {
            event.payload.as_ref().map_or(0, String::len)
        } else {
            0
        };
        while let Some(pin) = pending.pop() {
            check_deadline(deadline)?;
            if !seen.insert(pin.clone()) {
                continue;
            }
            if seen.len() + usize::from(event.event_type == REVISION) > 16 {
                return Err(invalid("view_budget_exceeded: nodes"));
            }
            let (seq, record, kind, len): (i64,String,String,i64) = sqlx::query_as("SELECT seq,record_id,type,coalesce(length(CAST(payload AS BLOB)),0) FROM content_events WHERE id=?")
                .bind(&pin.revision_id).fetch_optional(&mut *conn).await?.ok_or_else(|| invalid("revision unavailable"))?;
            let len = usize::try_from(len).map_err(|_| invalid("payload exceeds bound"))?;
            if kind != REVISION
                || len > MAX_CARRIER_BYTES
                || len > (512 * 1024usize).saturating_sub(bytes)
            {
                return Err(invalid("view_budget_exceeded: closure bytes"));
            }
            bytes += len;
            let reference = read_event(conn, &pin.revision_id, event.local_seq - 1).await?;
            let revision: Revision = decode(&reference, MAX_CARRIER_BYTES)?;
            if revision.v != 1 {
                return Err(invalid("view_revision_unavailable"));
            }
            let definition = revision.validate_retained(&reference)?;
            if pin.view_id != revision.view_id
                || pin.definition_sha256 != revision.definition_sha256
                || pin.schema_sha256 != definition.query.output.schema_sha256
            {
                return Err(invalid("revision pin mismatch"));
            }
            pending.extend(definition.query.relations.values().filter_map(|d| match d {
                contract::Dependency::View(p) => Some(p.clone()),
                _ => None,
            }));
            let generated_name = revision.generated_name();
            self.state.revisions.insert(
                pin.revision_id,
                RevisionHeader {
                    record_id: record,
                    seq,
                    digest: revision.definition_sha256,
                    schema_digest: definition.query.output.schema_sha256,
                    generated: matches!(definition.origin, contract::Origin::Generated { .. }),
                    generated_name,
                },
            );
        }
        self.state.apply(event)
    }
}

/// Reconstruct only the live namespace. Never use for FULL/tail replay/import.
pub(crate) async fn load_live(
    conn: &mut SqliteConnection,
    head: i64,
    deadline: Instant,
) -> Result<LiveNamespace> {
    let headers = load_headers(conn, head, Some(deadline)).await?;
    let mut state = ReplayChecker::default();
    for (seq, id, record, kind) in headers {
        check_deadline(deadline)?;
        if kind == REVISION {
            if state.revisions.len() >= MAX_REVISIONS
                || state
                    .revisions
                    .values()
                    .filter(|h| h.record_id == record)
                    .count()
                    >= 128
            {
                return Err(invalid("revision history limit"));
            }
            state.revisions.insert(
                id,
                RevisionHeader {
                    record_id: record,
                    seq,
                    digest: String::new(),
                    schema_digest: String::new(),
                    generated: false,
                    generated_name: None,
                },
            );
            state.last_seq = seq;
        } else if kind == LEGACY {
            state.legacy = true;
            state.last_seq = seq;
        } else {
            let len: i64 = sqlx::query_scalar(
                "SELECT coalesce(length(CAST(payload AS BLOB)),0) FROM content_events WHERE id=?",
            )
            .bind(&id)
            .fetch_one(&mut *conn)
            .await?;
            if !(0..=2048).contains(&len) {
                return Err(invalid("payload exceeds bound"));
            }
            state.apply_with_headers(&read_event(conn, &id, head).await?, false)?;
        }
    }
    // Retain the last actual lifecycle coordinate, including when the caller
    // asks for i64::MAX. It is not an executable-prefix certificate.
    Ok(LiveNamespace { state })
}

/// Ordinary local append only. Generic projector/import and canonical tail
/// replay continue through named_views::project / ReplayChecker::apply.
pub(crate) async fn project_live(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    #[cfg(feature = "v2-kernel-probe")]
    let deadline = super::gate::deadline();
    #[cfg(not(feature = "v2-kernel-probe"))]
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut state = load_live(conn, event.local_seq - 1, deadline).await?;
    state.apply_new_on(conn, event, deadline).await?;
    verify_retained_sources_on(conn, event).await?;
    touch_metadata(conn, event).await
}
