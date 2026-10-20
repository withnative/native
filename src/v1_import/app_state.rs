//! Projection custody only. No executable grants, external I/O or v1 folds.
use super::*;
use k::app_state::RetainedAppState;
use serde_json::Value;
use sqlx::{Column, TypeInfo, ValueRef};

#[derive(Default, Serialize)]
pub struct Report {
    /// Capture coverage only, never a certificate of executable admission.
    pub capture_complete: bool,
    pub bearers_with_evidence_gaps: usize,
    pub largest_capsule_bytes: usize,
    pub missing_tables: Vec<String>,
    pub source_rows: BTreeMap<String, usize>,
    pub source_bearers: BTreeMap<String, usize>,
    pub retained_rows: BTreeMap<String, usize>,
    pub unavailable_bearer_rows: BTreeMap<String, usize>,
    pub referenced_source_events: usize,
    pub missing_source_events: usize,
    pub referenced_control_events: usize,
    pub missing_control_events: usize,
    pub created: usize,
    pub updated: usize,
    pub unchanged: usize,
    pub verified: usize,
    /// Always false until live app admission, reads and commits are adapted.
    pub executable_on_kernel_v2: bool,
}

// Read actual SQLite values. json_object() formats REALs through SQLite's
// decimal printer and can round geometry before verification even begins.
fn row_value(row: &sqlx::sqlite::SqliteRow) -> Result<Value> {
    let mut fields = serde_json::Map::new();
    for column in row.columns() {
        let index = column.ordinal();
        let raw = row.try_get_raw(index)?;
        let value = if raw.is_null() {
            Value::Null
        } else {
            match raw.type_info().name() {
                "INTEGER" | "INT4" | "INT8" | "BOOLEAN" => json!(row.try_get::<i64, _>(index)?),
                "REAL" => {
                    let value: f64 = row.try_get(index)?;
                    if !value.is_finite() {
                        return Err("nonfinite app-state source value".into());
                    }
                    // Keep the SQL cell's exact IEEE-754 bits. The existing
                    // JSON parser is intentionally unchanged: changing its
                    // float semantics could reinterpret retained v1 hashes.
                    json!({"native.v1.sqlite.real_bits": format!("{:016x}", value.to_bits())})
                }
                "TEXT" => Value::String(row.try_get::<String, _>(index)?),
                _ => return Err("unsupported app-state source cell type".into()),
            }
        };
        fields.insert(column.name().into(), value);
    }
    Ok(Value::Object(fields))
}

async fn table_exists(source: &mut SqliteConnection, table: &str) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?)",
    )
    .bind(table)
    .fetch_one(source)
    .await?)
}

pub(super) async fn import(
    source: &mut SqliteConnection,
    db: &Db,
    host: &str,
    origin: &str,
    expected: &BTreeMap<String, (String, String, k::ImportRecordState)>,
    report: &mut Report,
) -> Result<()> {
    // Missing tables cannot establish deletions. Skip the entire custody
    // reconciliation before any capsule writes, preserving prior generations.
    for table in [
        "artifact_source_attestations",
        "artifact_inputs",
        "artifact_module_grants",
        "module_releases",
        "module_release_imports",
        "canvas_objects",
        "canvas_batches",
        "alpha_tab_installs",
        "alpha_tab_orders",
        "content_events",
        "control_events",
    ] {
        if !table_exists(source, table).await? {
            report.missing_tables.push(table.into());
        }
    }
    if !report.missing_tables.is_empty() {
        return Ok(());
    }
    let frontier = k::app_state::CustodyFrontier {
        format: 1,
        source_user_version: sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut *source)
            .await?,
        content_frontier: sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
            .fetch_one(&mut *source)
            .await?,
        control_frontier: sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM control_events")
            .fetch_one(&mut *source)
            .await?,
        missing_source_events: Vec::new(),
        missing_control_events: Vec::new(),
        closure_admission: "not_evaluated".into(),
    };
    k::app_state::ensure_as(db, host).await?;
    let mut states: BTreeMap<String, RetainedAppState> = expected
        .keys()
        .map(|id| (id.clone(), RetainedAppState::default()))
        .collect();
    // Include prior bearers even when the source record disappeared. Marked
    // negative evidence prevents a later adapter activating stale custody.
    let prior: Vec<String> =
        sqlx::query_scalar("SELECT record_id FROM kernel_app_state WHERE origin=?")
            .bind(origin)
            .fetch_all(db.pool())
            .await?;
    for id in prior {
        if !id.starts_with(k::app_state::ACCOUNT_ORDER_PREFIX) && !expected.contains_key(&id) {
            let live: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND deleted_at IS NULL)",
            )
            .bind(&id)
            .fetch_one(&mut *source)
            .await?;
            if live {
                continue;
            }
            states.insert(
                id,
                RetainedAppState {
                    source_deleted: true,
                    ..Default::default()
                },
            );
        }
    }
    let orders = sqlx::query("SELECT * FROM alpha_tab_orders ORDER BY account_id")
        .fetch_all(&mut *source)
        .await?;
    report
        .source_rows
        .insert("alpha_tab_orders".into(), orders.len());
    report
        .source_bearers
        .insert("alpha_tab_orders".into(), orders.len());
    // Empty rows establish deletion of an earlier account arrangement too.
    let accounts: Vec<String> =
        sqlx::query_scalar("SELECT auth_binding FROM kernel_principals WHERE kind='account'")
            .fetch_all(db.pool())
            .await?;
    for account in accounts {
        states
            .entry(k::app_state::account_bearer(&account))
            .or_default();
    }
    for row in orders {
        let account: String = row.try_get("account_id")?;
        let key = k::app_state::account_bearer(&account);
        if let Some(state) = states.get_mut(&key) {
            state.alpha_tab_orders.push(row_value(&row)?);
            *report
                .retained_rows
                .entry("alpha_tab_orders".into())
                .or_default() += 1;
        } else {
            *report
                .unavailable_bearer_rows
                .entry("alpha_tab_orders".into())
                .or_default() += 1;
        }
    }
    for (table, bearer, order) in [
        (
            "artifact_source_attestations",
            "artifact_id",
            "attestation_event_id",
        ),
        ("artifact_inputs", "artifact_id", "port_name"),
        (
            "artifact_module_grants",
            "artifact_id",
            "subject_kind,subject_record_id,subject_event_id,capability,scope_sha256",
        ),
        (
            "module_releases",
            "module_record_id",
            "publication_event_id",
        ),
        ("canvas_objects", "canvas_id", "object_id"),
        ("canvas_batches", "canvas_id", "event_seq"),
        ("alpha_tab_installs", "artifact_id", "account_id,package"),
    ] {
        if !table_exists(source, table).await? {
            continue;
        }
        let rows = sqlx::query(&format!("SELECT * FROM {table} ORDER BY {bearer},{order}"))
            .fetch_all(&mut *source)
            .await?;
        report.source_rows.insert(table.into(), rows.len());
        let bearers: BTreeSet<String> = rows
            .iter()
            .map(|row| row.try_get(bearer))
            .collect::<std::result::Result<_, _>>()?;
        report.source_bearers.insert(table.into(), bearers.len());
        for row in rows {
            let id: String = row.try_get(bearer)?;
            let Some(state) = states.get_mut(&id) else {
                *report
                    .unavailable_bearer_rows
                    .entry(table.into())
                    .or_default() += 1;
                continue;
            };
            let row = row_value(&row)?;
            let target = match table {
                "artifact_source_attestations" => &mut state.artifact_source_attestations,
                "artifact_inputs" => &mut state.artifact_inputs,
                "artifact_module_grants" => &mut state.artifact_module_grants,
                "module_releases" => &mut state.module_releases,
                "canvas_objects" => &mut state.canvas_objects,
                "canvas_batches" => &mut state.canvas_batches,
                "alpha_tab_installs" => &mut state.alpha_tab_installs,
                _ => unreachable!(),
            };
            target.push(row);
            *report.retained_rows.entry(table.into()).or_default() += 1;
        }
    }
    let imports = sqlx::query("SELECT i.*,r.module_record_id AS custody_bearer FROM module_release_imports i JOIN module_releases r ON r.publication_event_id=i.consumer_publication_event_id ORDER BY r.module_record_id,i.consumer_publication_event_id,i.ordinal").fetch_all(&mut *source).await?;
    report
        .source_rows
        .insert("module_release_imports".into(), imports.len());
    for row in imports {
        let bearer: String = row.try_get("custody_bearer")?;
        if let Some(state) = states.get_mut(&bearer) {
            let mut value = row_value(&row)?;
            value.as_object_mut().unwrap().remove("custody_bearer");
            state.module_release_imports.push(value);
            *report
                .retained_rows
                .entry("module_release_imports".into())
                .or_default() += 1;
        } else {
            *report
                .unavailable_bearer_rows
                .entry("module_release_imports".into())
                .or_default() += 1;
        }
    }
    if !table_exists(source, "content_events").await? {
        return Err("source content events missing".into());
    }
    let control_present = table_exists(source, "control_events").await?;
    for (id, state) in &mut states {
        state.custody = Some(frontier.clone());
        // Pin the actual source events used by attestations/releases/installs,
        // plus the canvas ledger's accepted batches. Other history is W5's job.
        let mut events = BTreeSet::new();
        for row in state
            .artifact_source_attestations
            .iter()
            .chain(&state.artifact_inputs)
            .chain(&state.artifact_module_grants)
            .chain(&state.module_releases)
            .chain(&state.module_release_imports)
        {
            for field in [
                "source_event_id",
                "artifact_source_event_id",
                "artifact_source_attestation_event_id",
                "subject_event_id",
                "attestation_event_id",
                "publication_event_id",
                "consumer_publication_event_id",
                "dependency_publication_event_id",
            ] {
                if let Some(value) = row[field].as_str() {
                    events.insert(value.to_owned());
                }
            }
        }
        for row in &state.canvas_batches {
            if let Some(value) = row["event_id"].as_str() {
                events.insert(value.to_owned());
            }
        }
        for row in &state.alpha_tab_installs {
            if let Some(value) = row["consented_source_revision"].as_str() {
                events.insert(value.to_owned());
            }
        }
        for row in state
            .module_releases
            .iter()
            .chain(&state.artifact_source_attestations)
            .chain(&state.artifact_inputs)
            .chain(&state.artifact_module_grants)
        {
            for field in ["event_seq", "local_event_seq", "status_event_seq"] {
                if let Some(seq) = row[field].as_i64() {
                    let event_id: Option<String> =
                        sqlx::query_scalar("SELECT id FROM content_events WHERE seq=?")
                            .bind(seq)
                            .fetch_optional(&mut *source)
                            .await?;
                    if let Some(event_id) = event_id {
                        events.insert(event_id);
                    } else {
                        state
                            .custody
                            .as_mut()
                            .unwrap()
                            .missing_source_events
                            .push(format!("seq:{seq}"));
                        report.missing_source_events += 1;
                    }
                }
            }
        }
        for event_id in events {
            let row = sqlx::query("SELECT * FROM content_events WHERE id=?")
                .bind(&event_id)
                .fetch_optional(&mut *source)
                .await?;
            if let Some(row) = row {
                state.source_events.insert(event_id, row_value(&row)?);
                report.referenced_source_events += 1;
            } else {
                report.missing_source_events += 1;
                state
                    .custody
                    .as_mut()
                    .unwrap()
                    .missing_source_events
                    .push(event_id);
            }
        }
        let mut control_ids = BTreeSet::new();
        for row in state
            .alpha_tab_installs
            .iter()
            .chain(&state.alpha_tab_orders)
        {
            for field in ["event_id", "body_read_admission_event_id"] {
                if let Some(value) = row[field].as_str() {
                    control_ids.insert(value.to_owned());
                }
            }
        }
        for event_id in control_ids {
            let row = if control_present {
                sqlx::query("SELECT * FROM control_events WHERE id=?")
                    .bind(&event_id)
                    .fetch_optional(&mut *source)
                    .await?
            } else {
                None
            };
            if let Some(row) = row {
                state.control_events.insert(event_id, row_value(&row)?);
                report.referenced_control_events += 1;
            } else {
                report.missing_control_events += 1;
                state
                    .custody
                    .as_mut()
                    .unwrap()
                    .missing_control_events
                    .push(event_id);
            }
        }
        let custody = state.custody.as_ref().unwrap();
        if !custody.missing_source_events.is_empty() || !custody.missing_control_events.is_empty() {
            report.bearers_with_evidence_gaps += 1;
        }
        report.largest_capsule_bytes = report
            .largest_capsule_bytes
            .max(serde_json::to_vec(state)?.len());
        match k::app_state::import_as(db, host, id, origin, state)
            .await
            .map_err(|error| format!("sealed app-state import refused: {error}"))?
        {
            k::ImportResult::Created => report.created += 1,
            k::ImportResult::Updated => report.updated += 1,
            k::ImportResult::Unchanged => report.unchanged += 1,
        }
        let actual: Option<String> = sqlx::query_scalar(
            "SELECT payload FROM kernel_app_state WHERE record_id=? AND origin=?",
        )
        .bind(id)
        .bind(origin)
        .fetch_optional(db.pool())
        .await?;
        let actual_state = actual
            .as_deref()
            .map(serde_json::from_str::<RetainedAppState>)
            .transpose()?;
        // An absent initial capsule and an explicit cleared capsule both
        // witness empty source state. Updates keep their predecessor chain.
        if actual_state.as_ref().is_some_and(|actual| actual != state)
            || (actual_state.is_none() && !state.is_empty())
        {
            return Err("retained app-state verification failed".into());
        }
        if actual.is_some() {
            report.verified += 1;
        }
    }
    report.capture_complete = report.bearers_with_evidence_gaps == 0
        && report
            .unavailable_bearer_rows
            .values()
            .all(|count| *count == 0);
    Ok(())
}
