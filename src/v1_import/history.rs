//! Offline-only retained v1 interpretation. Never fold history over current state.
use super::*;
use serde_json::Value;

#[derive(Default, Serialize)]
pub struct HistoryReport {
    pub streams: BTreeMap<String, HistoryCounts>,
    pub records_verified: usize,
    pub busy_record_read: Option<HistoryTiming>,
}
#[derive(Serialize)]
pub struct HistoryTiming {
    pub retained_events: i64,
    pub returned_events: usize,
    pub get_history_ms: f64,
}
#[derive(Default, Serialize)]
pub struct HistoryCounts {
    pub source: usize,
    pub created: usize,
    pub unchanged: usize,
    pub verified: usize,
    pub skipped_subject_not_selected: usize,
    pub retained_without_imported_subject: usize,
}

// Extract the entire source row for byte-sensitive hashing, including payload
// text spelling, original act, local sequence and stream-specific metadata.
async fn rows(source: &mut SqliteConnection, table: &str) -> Result<Vec<Value>> {
    let columns = sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(&mut *source)
        .await?;
    if columns.is_empty() {
        return Ok(Vec::new());
    }
    let fields = columns
        .iter()
        .map(|c| {
            let name: String = c.get("name");
            format!(
                "'{}',\"{}\"",
                name.replace('\'', "''"),
                name.replace('"', "\"\"")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let raw: Vec<String> = sqlx::query_scalar(&format!(
        "SELECT json_object({fields}) FROM {table} ORDER BY seq"
    ))
    .fetch_all(source)
    .await?;
    raw.into_iter()
        .map(|r| Ok(serde_json::from_str(&r)?))
        .collect()
}

pub(super) struct Scope<'a> {
    pub imported: BTreeSet<String>,
    pub selected: BTreeSet<String>,
    pub homes: &'a BTreeMap<String, String>,
    pub all: bool,
}

async fn flush(
    db: &Db,
    host: &str,
    pending: &mut Vec<(String, k::LegacyEvent)>,
    report: &mut HistoryReport,
    expected: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    let results = k::import_history_batch_as(db, host, pending)
        .await
        .map_err(|_| "sealed history import refused")?;
    for ((anchor, legacy), result) in pending.drain(..).zip(results) {
        let counts = report
            .streams
            .get_mut(legacy.source.as_ref().unwrap()["stream"].as_str().unwrap())
            .unwrap();
        match result {
            k::ImportResult::Created => counts.created += 1,
            k::ImportResult::Unchanged => counts.unchanged += 1,
            k::ImportResult::Updated => {
                return Err("sealed history unexpectedly updated an event".into())
            }
        }
        expected.entry(anchor).or_default().insert(legacy.id);
    }
    Ok(())
}

pub(super) async fn import(
    source: &mut SqliteConnection,
    db: &Db,
    host: &str,
    origin: &str,
    scope: Scope<'_>,
    report: &mut HistoryReport,
) -> Result<()> {
    // Retry the recorded interpretation, not a freshly inferred mapping.
    // The raw source-row digest must still match; the sealed kernel lane then
    // compares the complete reconstructed legacy envelope byte for byte.
    let retained_rows: Vec<(String,String,String)> = sqlx::query_as("SELECT id,record_id,json_extract(payload,'$.legacy.source') FROM content_events WHERE type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.source.origin')=?")
        .bind(origin).fetch_all(db.pool()).await?;
    let retained: BTreeMap<String, (String, Value)> = retained_rows
        .into_iter()
        .map(|(id, anchor, metadata)| Ok((id, (anchor, serde_json::from_str(&metadata)?))))
        .collect::<Result<_>>()?;
    let map = |id: &str| {
        if scope.imported.contains(id) {
            Some(id.to_owned())
        } else {
            scope.homes.get(id).cloned()
        }
    };
    // Unsupported acknowledgement records may still have imported policy
    // homes. Preserve the v1 hidden-kind fact before mapping those subjects.
    let vocabulary_tables: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('vocabularies','vocabulary_values')").fetch_one(&mut *source).await?;
    let acknowledgement = if vocabulary_tables == 2 {
        crate::query::acknowledgement_predicate("r")
    } else {
        // Older/minimal snapshots carry the closed-spine token directly.
        "r.type='Annotation' AND r.kind IN ('acknowledgement','vv:voc:kind:Annotation:acknowledgement')".into()
    };
    let acknowledgement_ids: BTreeSet<String> = sqlx::query_scalar(&format!(
        "SELECT r.id FROM records r WHERE {acknowledgement}"
    ))
    .fetch_all(&mut *source)
    .await?
    .into_iter()
    .collect();
    let relationships = rows(source, "relationship_events").await?;
    let mut endpoints = BTreeMap::<(String, String), Vec<String>>::new();
    for row in &relationships {
        if row["type"] != "relationship.created.v1" {
            continue;
        }
        let payload: Value = serde_json::from_str(row["payload"].as_str().unwrap_or("{}"))?;
        let subjects = payload["endpoints"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|e| e["record_id"].as_str().map(str::to_owned))
            .collect();
        endpoints.insert(
            (
                row["relationship_origin_db_id"]
                    .as_str()
                    .unwrap_or("")
                    .into(),
                row["relationship_id"].as_str().unwrap_or("").into(),
            ),
            subjects,
        );
    }
    let mut expected = BTreeMap::<String, BTreeSet<String>>::new();
    let mut merged = Vec::new();
    for stream in [
        "content_events",
        "relationship_events",
        "policy_events",
        "control_events",
    ] {
        report.streams.entry(stream.into()).or_default();
        let stream_rows = if stream == "relationship_events" {
            relationships.clone()
        } else {
            rows(source, stream).await?
        };
        merged.extend(stream_rows.into_iter().map(|row| (stream, row)));
    }
    // v1 act is global across streams. Older rows without an act precede
    // allocated acts; time, stream and local sequence break ties deterministically.
    merged.sort_by(|(sa, a), (sb, b)| {
        (
            a["act"].as_i64().unwrap_or(0),
            a["created_at"]
                .as_str()
                .or(a["occurred_at"].as_str())
                .unwrap_or(""),
            sa,
            a["seq"].as_i64().unwrap_or(0),
        )
            .cmp(&(
                b["act"].as_i64().unwrap_or(0),
                b["created_at"]
                    .as_str()
                    .or(b["occurred_at"].as_str())
                    .unwrap_or(""),
                sb,
                b["seq"].as_i64().unwrap_or(0),
            ))
    });
    let mut pending = Vec::new();
    for (stream, row) in merged {
        let counts = report.streams.get_mut(stream).unwrap();
        counts.source += 1;
        let id = row["id"]
            .as_str()
            .ok_or("history source event missing id")?
            .to_owned();
        use sha2::{Digest, Sha256};
        let row_sha256 = format!("{:x}", Sha256::digest(serde_json::to_vec(&row)?));
        let recorded = retained.get(&id);
        if let Some((_, metadata)) = recorded {
            if metadata["stream"] != stream || metadata["row_sha256"] != row_sha256 {
                return Err("retained source history row changed".into());
            }
        }
        let payload: Value = match serde_json::from_str(row["payload"].as_str().unwrap_or("null")) {
            Ok(payload) => payload,
            Err(error) => {
                flush(db, host, &mut pending, report, &mut expected).await?;
                return Err(error.into());
            }
        };
        let mut subjects: Vec<String> = if stream == "relationship_events" {
            endpoints
                .get(&(
                    row["relationship_origin_db_id"]
                        .as_str()
                        .unwrap_or("")
                        .into(),
                    row["relationship_id"].as_str().unwrap_or("").into(),
                ))
                .cloned()
                .unwrap_or_default()
        } else if let Some(id) = row["record_id"].as_str() {
            vec![id.into()]
        } else {
            [
                "source_record_id",
                "root_record_id",
                "artifact_id",
                "person_record_id",
            ]
            .iter()
            .filter_map(|key| payload[key].as_str().map(str::to_owned))
            .collect()
        };
        // Legacy links and revision payloads can mention other records;
        // withhold the whole event when any referenced subject is hidden.
        for key in ["source_id", "target_id"] {
            if let Some(id) = payload[key].as_str() {
                if !subjects.iter().any(|s| s == id) {
                    subjects.push(id.into());
                }
            }
        }
        let anchor = if let Some(id) = row["record_id"].as_str() {
            // Content/policy belong to their original record, never to a
            // referenced link target that happened to import successfully.
            map(id)
        } else {
            subjects.iter().find_map(|id| map(id))
        };
        let selected = row["record_id"].as_str().map_or_else(
            || subjects.iter().any(|id| scope.selected.contains(id)),
            |id| scope.selected.contains(id),
        );
        let anchor = match (recorded, anchor) {
            (Some((anchor, _)), current) => {
                if current.is_none() {
                    counts.retained_without_imported_subject += 1;
                }
                anchor.clone()
            }
            (None, Some(id)) => id,
            (None, None) if scope.all || selected || subjects.is_empty() => {
                // Retain evidence for v1 tombstones/unsupported current-state
                // kinds without resurrecting them as v2 records. Missing
                // visibility subjects keep these envelopes out of reads.
                counts.retained_without_imported_subject += 1;
                KERNEL_ROOT_ID.into()
            }
            (None, None) => {
                counts.skipped_subject_not_selected += 1;
                continue;
            }
        };
        let mapped_subjects: Vec<String> = subjects
            .iter()
            .map(|s| map(s).unwrap_or_else(|| s.clone()))
            .collect();
        let mut metadata = row.as_object().unwrap().clone();
        for key in [
            "id",
            "type",
            "payload",
            "actor",
            "run_key",
            "created_at",
            "occurred_at",
        ] {
            metadata.remove(key);
        }
        let mut source_metadata = recorded.map_or_else(|| json!({"origin":origin,"stream":stream,"metadata":metadata,"row_sha256":row_sha256,"subjects":mapped_subjects,"original_subjects":subjects}), |(_,metadata)| metadata.clone());
        if recorded.is_none() && subjects.iter().any(|id| acknowledgement_ids.contains(id)) {
            source_metadata["hidden_acknowledgement"] = json!(true);
        }
        let mut legacy = k::LegacyEvent {
            source: Some(source_metadata),
            id: id.clone(),
            event_type: row["type"]
                .as_str()
                .ok_or("history source missing type")?
                .into(),
            payload,
            created_at: row["created_at"]
                .as_str()
                .or_else(|| row["occurred_at"].as_str())
                .ok_or("history source missing time")?
                .into(),
            actor: row["actor"].as_str().map(str::to_owned),
            run_key: row["run_key"].as_str().map(str::to_owned),
        };
        let anchor = if let Some(custody) = k::app_state::history_aggregate(&legacy)? {
            if recorded.is_some_and(|(old, metadata)| {
                old != &custody
                    || metadata["app_custody"].as_u64()
                        != Some(k::app_state::HISTORY_CUSTODY_VERSION)
            }) {
                return Err("private app history requires a fresh custody-isolated target".into());
            }
            legacy.source.as_mut().unwrap()["app_custody"] =
                json!(k::app_state::HISTORY_CUSTODY_VERSION);
            custody
        } else {
            anchor
        };
        pending.push((anchor, legacy));
        if pending.len() == k::LEGACY_IMPORT_BATCH_LIMIT {
            flush(db, host, &mut pending, report, &mut expected).await?;
        }
    }
    flush(db, host, &mut pending, report, &mut expected).await?;
    // Include anchors whose last source row disappeared: they are absent from
    // `expected`, but must not leave unnoticed extra retained rows on resume.
    let expected_total: usize = expected.values().map(BTreeSet::len).sum();
    let stored_total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.source.origin')=?",
    ).bind(origin).fetch_one(db.write_pool()).await?;
    if usize::try_from(stored_total)? != expected_total {
        return Err("history total count mismatch, including empty source subjects".into());
    }
    // Exact per-anchor ID sets and counts, independent of import outcomes.
    for (anchor, ids) in expected {
        let stored: Vec<(String, String)> = sqlx::query_as(
            "SELECT id,json_extract(payload,'$.legacy.source.stream') FROM content_events WHERE record_id=? AND type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.source.origin')=?")
            .bind(anchor).bind(origin).fetch_all(db.write_pool()).await?;
        if stored
            .iter()
            .map(|(id, _)| id.clone())
            .collect::<BTreeSet<_>>()
            != ids
            || stored.len() != ids.len()
        {
            return Err("history per-record count or event ID mismatch".into());
        }
        for (_, stream) in stored {
            report
                .streams
                .get_mut(&stream)
                .ok_or("unknown imported history stream")?
                .verified += 1;
        }
        report.records_verified += 1;
    }
    Ok(())
}
