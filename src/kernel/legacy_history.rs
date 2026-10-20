//! Replayable disclosure facts for retained interpretation; never current state.
use super::*;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
pub(super) const DDL: &str = "CREATE TABLE kernel_legacy_history(seq INTEGER PRIMARY KEY, event_type TEXT NOT NULL, subjects TEXT NOT NULL, owner TEXT, hidden INTEGER NOT NULL, restricted INTEGER NOT NULL, claim_sensitive INTEGER NOT NULL, disclosure_version INTEGER NOT NULL DEFAULT 2)";
/// Header facts for ordinary SQL, so metadata reads never parse retained
/// source bodies. Native seq is the local cursor; source identity stays exact.
pub(super) const SQL_EVENTS_DDL: &str = "CREATE TABLE kernel_legacy_sql_events (
 seq INTEGER PRIMARY KEY REFERENCES content_events(seq),
 source_id TEXT NOT NULL, record_id TEXT NOT NULL, event_type TEXT NOT NULL,
 actor TEXT, run_key TEXT, parent_key TEXT, created_at TEXT NOT NULL,
 source_stream TEXT NOT NULL)";
pub(super) const SQL_EVENTS_INDEX_DDL: &str = "CREATE INDEX idx_kernel_legacy_sql_record ON kernel_legacy_sql_events(record_id,source_stream,seq)";
/// A scanned log position, including legacy events with no SQL header. Older
/// import binaries do not advance it; explicit preparation catches up without source.
pub(super) const SQL_PROGRESS_DDL: &str = "CREATE TABLE kernel_legacy_sql_progress (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), scanned_seq INTEGER NOT NULL, gap_free INTEGER NOT NULL DEFAULT 1, provenance_headers INTEGER NOT NULL DEFAULT 1)";
pub(super) const SUBJECTS_DDL: &str = "CREATE TABLE kernel_legacy_subjects(subject_id TEXT NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY(subject_id,seq))";

/// Additive upgrade for imported targets created before retained history.
/// Missing disclosure projections are rebuilt from immutable legacy envelopes.
pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    let present: i64 = sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('kernel_legacy_history','kernel_legacy_subjects','kernel_legacy_sql_events','kernel_legacy_sql_progress')")
        .fetch_one(&mut *conn).await?;
    let upgraded: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_table_info('kernel_legacy_history') WHERE name='disclosure_version')")
        .fetch_one(&mut *conn).await?;
    let rebuild = present != 4 || !upgraded;
    for ddl in [DDL, SUBJECTS_DDL, SQL_EVENTS_DDL, SQL_PROGRESS_DDL] {
        sqlx::query(&ddl.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
            .execute(&mut *conn)
            .await?;
    }
    let gap_free: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_table_info('kernel_legacy_sql_progress') WHERE name='gap_free')")
        .fetch_one(&mut *conn).await?;
    if !gap_free {
        // The old max-only frontier could conceal an older writer's gap.
        // Rescan canonical envelopes once; existing headers are idempotent.
        sqlx::query(
            "ALTER TABLE kernel_legacy_sql_progress ADD COLUMN gap_free INTEGER NOT NULL DEFAULT 0",
        )
        .execute(&mut *conn)
        .await?;
        sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=0,gap_free=1")
            .execute(&mut *conn)
            .await?;
    }
    let provenance_headers: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_table_info('kernel_legacy_sql_progress') WHERE name='provenance_headers')")
        .fetch_one(&mut *conn).await?;
    if !provenance_headers {
        // Earlier complete frontiers omitted sealed provenance envelopes whose
        // payload had no record_id. Their immutable outer subject now supplies
        // the header. Rescan once, even when the old frontier was fully caught up.
        sqlx::query("ALTER TABLE kernel_legacy_sql_progress ADD COLUMN provenance_headers INTEGER NOT NULL DEFAULT 0")
            .execute(&mut *conn).await?;
    }
    sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=0,provenance_headers=1 WHERE provenance_headers=0")
        .execute(&mut *conn).await?;
    let upgraded: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pragma_table_info('kernel_legacy_history') WHERE name='disclosure_version')")
        .fetch_one(&mut *conn).await?;
    if !upgraded {
        sqlx::query("ALTER TABLE kernel_legacy_history ADD COLUMN disclosure_version INTEGER NOT NULL DEFAULT 2")
            .execute(&mut *conn).await?;
    }
    sqlx::query(&SQL_EVENTS_INDEX_DDL.replacen("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1))
        .execute(&mut *conn)
        .await?;
    if rebuild {
        for table in [
            "kernel_legacy_sql_events",
            "kernel_legacy_subjects",
            "kernel_legacy_history",
            "kernel_legacy_sql_progress",
        ] {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(&mut *conn)
                .await?;
        }
    }
    let mut after: i64 =
        sqlx::query_scalar("SELECT scanned_seq FROM kernel_legacy_sql_progress WHERE singleton=1")
            .fetch_optional(&mut *conn)
            .await?
            .unwrap_or(0);
    let head: i64 = sqlx::query_scalar(
        "SELECT coalesce(max(seq),0) FROM content_events WHERE type='kernel.legacy_recorded.v1'",
    )
    .fetch_one(&mut *conn)
    .await?;
    if after > head {
        return Err(Error::engine(
            "legacy SQL projection frontier exceeds canonical history",
        ));
    }
    while after < head {
        let rows: Vec<(i64,String)> = sqlx::query_as("SELECT seq,json_extract(payload,'$.legacy') FROM content_events WHERE seq>? AND seq<=? AND type='kernel.legacy_recorded.v1' ORDER BY seq LIMIT 128")
            .bind(after).bind(head).fetch_all(&mut *conn).await?;
        if rows.is_empty() {
            return Err(Error::engine(
                "legacy SQL projection catchup did not advance",
            ));
        }
        for (seq, raw) in rows {
            let legacy: hq::LegacyEvent = serde_json::from_str(&raw)?;
            if rebuild {
                project_at(conn, seq, &legacy).await?;
            } else {
                // Older importers already folded W5 disclosure; fill only the
                // new SQL projection, without duplicating its history rows.
                project_sql_header(conn, seq, &legacy).await?;
            }
            after = seq;
        }
    }
    Ok(())
}

pub(super) async fn project(
    conn: &mut SqliteConnection,
    event: &EventRow,
    legacy: &hq::LegacyEvent,
) -> Result<()> {
    project_at(conn, event.local_seq, legacy).await
}
async fn project_at(conn: &mut SqliteConnection, seq: i64, legacy: &hq::LegacyEvent) -> Result<()> {
    project_sql_header(conn, seq, legacy).await?;
    let Some(source) = &legacy.source else {
        return Ok(());
    };
    let mut subjects: BTreeSet<String> = source["subjects"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    // Pre-W6 envelopes could map unsupported Message subjects to a policy
    // home. That immutable anchor is historical evidence, not disclosure
    // authority. Retain the original subjects as additional dependencies.
    subjects.extend(
        source["original_subjects"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_owned)),
    );
    if let Some(id) = source["metadata"]["record_id"].as_str() {
        subjects.insert(id.to_owned());
    }
    for key in [
        "source_id",
        "target_id",
        "source_record_id",
        "root_record_id",
        "artifact_id",
        "person_record_id",
    ] {
        if let Some(id) = legacy.payload[key].as_str() {
            subjects.insert(id.to_owned());
        }
    }
    for endpoint in legacy.payload["endpoints"].as_array().into_iter().flatten() {
        if let Some(id) = endpoint["record_id"].as_str() {
            subjects.insert(id.to_owned());
        }
    }
    // Selectors quote independently protected content. Withhold the whole
    // event if its bearer cannot be viewed, including failed comment anchors.
    let mut stack = vec![&legacy.payload];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    if matches!(
                        key.as_str(),
                        "target_record_id" | "artifact_id" | "artefact_id"
                    ) || (legacy.event_type == "occurrence.bound.v1" && key == "subject_id")
                    {
                        if let Some(id) = value.as_str() {
                            subjects.insert(id.to_owned());
                        }
                    }
                    stack.push(value);
                }
            }
            Value::Array(values) => stack.extend(values),
            _ => (),
        }
    }
    // Old relationship removals have neither endpoint payloads nor an original
    // subject list. Their mapped homes cannot prove endpoint visibility. Keep
    // the evidence but fail closed rather than guessing a wider audience.
    let unproven_endpoints = source["stream"] == "relationship_events"
        && source.get("original_subjects").is_none()
        && legacy.payload["endpoints"]
            .as_array()
            .is_none_or(Vec::is_empty);
    let hidden = unproven_endpoints
        || source["hidden_acknowledgement"] == true
        || crate::query::events::HISTORY_HIDDEN_EVENT_TYPES.contains(&legacy.event_type.as_str())
        || (legacy.event_type == "occurrence.bound.v1"
            && serde_json::from_value::<crate::events::OccurrenceBoundPayload>(
                legacy.payload.clone(),
            )
            .is_err());
    let control = source["stream"] == "control_events";
    let account_scope = control && legacy.payload["scope_kind"] == "account";
    let account_declared = control && legacy.payload.get("account_id").is_some();
    let restricted = subjects.is_empty()
        || (control
            && (account_scope
                || account_declared
                || [
                    "account_config.",
                    "member_obligation.",
                    "onboarding_programme.",
                    "agent_run.",
                ]
                .iter()
                .any(|prefix| legacy.event_type.starts_with(prefix))));
    let claim_sensitive = [
        "claimed_by_account",
        "claimed_run_key",
        "released_from_run_key",
    ]
    .iter()
    .any(|key| legacy.payload.get(key).is_some());
    // An actor is attribution, never proof of account ownership: an admin
    // can change someone else's settings. Unproven ownership stays admin-only.
    let owner = if control && source.get("app_custody").is_some() {
        // Versioned custody shares placement's strict declaration rule. Old
        // unmarked envelopes keep their original disclosure interpretation.
        super::app_state::declared_account(&legacy.payload)
    } else if account_scope {
        legacy.payload["scope_id"].as_str()
    } else if control {
        legacy.payload["account_id"].as_str()
    } else {
        None
    };
    sqlx::query("INSERT INTO kernel_legacy_history VALUES(?,?,?,?,?,?,?,2)")
        .bind(seq)
        .bind(&legacy.event_type)
        .bind(serde_json::to_string(&subjects)?)
        .bind(owner)
        .bind(hidden)
        .bind(restricted)
        .bind(claim_sensitive)
        .execute(&mut *conn)
        .await?;
    // Only relationship endpoints add history to another subject. Other
    // references are visibility dependencies, not history ownership.
    if source["stream"] == "relationship_events" {
        for id in source["subjects"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            sqlx::query("INSERT OR IGNORE INTO kernel_legacy_subjects VALUES(?,?)")
                .bind(id)
                .bind(seq)
                .execute(&mut *conn)
                .await?;
        }
    }
    Ok(())
}

async fn project_sql_header(
    conn: &mut SqliteConnection,
    seq: i64,
    legacy: &hq::LegacyEvent,
) -> Result<()> {
    // Early sealed provenance envelopes did not duplicate the subject in
    // their payload. The immutable outer event still supplies its identity.
    let subject: Option<String> = if legacy.source.is_none()
        && legacy.event_type == "v1.snapshot_provenance"
        && legacy.payload["record_id"].as_str().is_none()
    {
        sqlx::query_scalar("SELECT record_id FROM content_events WHERE seq=?")
            .bind(seq)
            .fetch_optional(&mut *conn)
            .await?
            .flatten()
    } else {
        None
    };
    let identity = if let Some(source) = &legacy.source {
        Some((
            source["metadata"]["record_id"].as_str().unwrap_or(""),
            source["stream"].as_str().unwrap_or(""),
            source["metadata"]["parent_key"].as_str(),
        ))
    } else if legacy.event_type == "v1.snapshot_provenance" {
        legacy.payload["record_id"]
            .as_str()
            .or(subject.as_deref())
            .map(|record| (record, "snapshot_provenance", None))
    } else {
        None
    };
    if let Some((record, stream, parent)) = identity {
        sqlx::query("INSERT OR IGNORE INTO kernel_legacy_sql_events VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(seq)
            .bind(&legacy.id)
            .bind(record)
            .bind(&legacy.event_type)
            .bind(legacy.actor.as_deref().map(|actor| format!("v1:{actor}")))
            .bind(&legacy.run_key)
            .bind(parent)
            .bind(&legacy.created_at)
            .bind(stream)
            .execute(&mut *conn)
            .await?;
    }
    // Native event numbers need not be adjacent. Every earlier *legacy*
    // envelope must already be scanned before this position can advance.
    // A newer writer therefore cannot jump over an older writer's gap.
    let prior: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events WHERE type='kernel.legacy_recorded.v1' AND seq<?")
        .bind(seq).fetch_one(&mut *conn).await?;
    sqlx::query("INSERT INTO kernel_legacy_sql_progress(singleton,scanned_seq,gap_free,provenance_headers) VALUES(1,CASE WHEN ?2=0 THEN ?1 ELSE 0 END,1,1) ON CONFLICT(singleton) DO UPDATE SET scanned_seq=CASE WHEN gap_free=1 AND scanned_seq>=?2 THEN max(scanned_seq,?1) ELSE scanned_seq END")
        .bind(seq).bind(prior).execute(conn).await?;
    Ok(())
}

pub(crate) async fn visible(
    conn: &mut SqliteConnection,
    principal: &str,
    subject: &str,
    cache: &mut BTreeMap<String, bool>,
) -> Result<bool> {
    if let Some(v) = cache.get(subject) {
        return Ok(*v);
    }
    let capability = match kernel_effective_capability_on(conn, principal, subject).await {
        Ok(c) => Some(c),
        Err(Error::Engine(message)) if message == HIDDEN_OR_MISSING => None,
        Err(e) => return Err(e),
    };
    let v = if let Some(c) = capability {
        c.allows(Capability::View)
    } else {
        // Original v1 Collection references retain their original spelling;
        // authorize their deterministically imported home instead.
        let mapped = if subject == "native:root" {
            KERNEL_ROOT_ID.to_owned()
        } else {
            hq::v1_import_home_id(subject)
        };
        match kernel_effective_capability_on(conn, principal, &mapped).await {
            Ok(c) => c.allows(Capability::View),
            Err(Error::Engine(message)) if message == HIDDEN_OR_MISSING => false,
            Err(e) => return Err(e),
        }
    };
    let v = v && comment_history_visible(conn, principal, subject).await?;
    cache.insert(subject.into(), v);
    Ok(v)
}

pub(crate) async fn redact(
    conn: &mut SqliteConnection,
    principal: &str,
    legacy: &mut Value,
    claim_holder: bool,
    cache: &mut BTreeMap<String, bool>,
) -> Result<()> {
    // The row digest and source bookkeeping are not public payloads.
    legacy.as_object_mut().unwrap().remove("source");
    let mut stack = vec![&mut legacy["payload"]];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(map) => {
                for (key, value) in map {
                    use crate::mcp::tools::history::{redaction_key_rule, RedactionKeyRule};
                    match redaction_key_rule(key, claim_holder) {
                        RedactionKeyRule::Erase => *value = Value::Null,
                        RedactionKeyRule::CheckReference => {
                            if let Some(id) = value.as_str() {
                                if !visible(conn, principal, id, cache).await? {
                                    *value = Value::Null;
                                }
                            }
                        }
                        RedactionKeyRule::Descend => stack.push(value),
                    }
                }
            }
            Value::Array(values) => stack.extend(values),
            _ => (),
        }
    }
    // Headers are disclosed separately, never from a retained envelope.
    for key in ["actor", "run_key"] {
        legacy.as_object_mut().unwrap().remove(key);
    }
    Ok(())
}

pub(super) fn marker(event_type: &str) -> Value {
    json!({"event_type":event_type})
}

/// v1 acknowledgement identity under either native or retained compat pins.
pub(super) fn sql_acknowledgement(alias: &str) -> String {
    format!("(({alias}.primary_type='Annotation' AND {alias}.kind IN ('acknowledgement','vv:voc:kind:Annotation:acknowledgement')) OR
        ({alias}.pin_family='{family}' AND {alias}.pin_version=1 AND {alias}.kind='{kind}'
         AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id={alias}.id AND f.name='v1_type' AND f.value_json='\"Annotation\"')
         AND EXISTS(SELECT 1 FROM kernel_record_fields f WHERE f.record_id={alias}.id AND f.name='v1_kind' AND f.value_json IN ('\"acknowledgement\"','\"vv:voc:kind:Annotation:acknowledgement\"'))))",
        family=crate::v2_standard::v1_compat::FAMILY,kind=crate::v2_standard::v1_compat::KIND)
}

// Replies inherit the root's anchor. Without an anchor, visibility follows
// the terminal part_of bearer, exactly as comment capability does. Selectors
// remain protected separately by their retained event's subject dependencies.
async fn comment_history_visible(
    conn: &mut SqliteConnection,
    principal: &str,
    subject: &str,
) -> Result<bool> {
    if !comments_v2::is_comment_on(conn, subject).await? {
        return Ok(true);
    }
    let mut current = subject.to_owned();
    for _ in 0..8 {
        let target: Option<String> = sqlx::query_scalar(
            "SELECT target_record_id FROM kernel_comment_anchors WHERE annotation_id=?",
        )
        .bind(&current)
        .fetch_optional(&mut *conn)
        .await?;
        if let Some(target) = target {
            return match kernel_effective_capability_on(conn, principal, &target).await {
                Ok(c) => Ok(c.allows(Capability::View)),
                Err(Error::Engine(message)) if message == HIDDEN_OR_MISSING => Ok(false),
                Err(e) => Err(e),
            };
        }
        let bearers = comments_v2::bearer_on(conn, &current).await?;
        let [bearer] = bearers.as_slice() else {
            return Ok(false);
        };
        if !comments_v2::is_comment_on(conn, bearer).await? {
            return match kernel_effective_capability_on(conn, principal, bearer).await {
                Ok(c) => Ok(c.allows(Capability::View)),
                Err(Error::Engine(message)) if message == HIDDEN_OR_MISSING => Ok(false),
                Err(e) => Err(e),
            };
        }
        current = bearer.clone();
    }
    Ok(false)
}
