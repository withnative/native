//! Shared W1 projection/storage. Domain decoding and host witnesses belong to
//! the recorded catalogue entry, never to a current provider request or state.
use super::provider_catalogue::{self as catalogue, Decoded, FoldInput, StoredState};
use super::*;

pub(super) const STATE_DDL: &str = "CREATE TABLE kernel_provider_state (id TEXT PRIMARY KEY, provider_key TEXT NOT NULL, subjects_json TEXT NOT NULL, state_json TEXT NOT NULL, head INTEGER NOT NULL)";
pub(super) const RECEIPT_DDL: &str = "CREATE TABLE kernel_provider_receipts (principal_id TEXT NOT NULL, operation TEXT NOT NULL, operation_key TEXT NOT NULL, request_json TEXT NOT NULL, assertion_id TEXT NOT NULL, event_seq INTEGER NOT NULL, PRIMARY KEY(principal_id, operation, operation_key))";
pub(super) const SUBJECT_DDL: &str = "CREATE TABLE kernel_provider_subjects (subject_id TEXT NOT NULL, aggregate_id TEXT NOT NULL, PRIMARY KEY(subject_id,aggregate_id))";
pub const PROVIDER_OUTCOME_EVENT: &str = "kernel.provider_outcome.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpretationPins {
    pub package: PackageSelection,
    pub relationship: RevisionIdentity,
    pub provider: String,
    pub decoder: String,
    pub reducer: String,
    pub payload_version: u32,
}
pub(crate) async fn project(
    conn: &mut SqliteConnection,
    event: &EventRow,
    replay: bool,
) -> Result<()> {
    let payload: serde_json::Value = event_payload(event)?;
    let entry = catalogue::recorded(&payload)?;
    project_with_entry(conn, event, replay, entry, &payload).await
}

pub(super) async fn project_with_entry(
    conn: &mut SqliteConnection,
    event: &EventRow,
    replay: bool,
    entry: &catalogue::Entry,
    payload: &serde_json::Value,
) -> Result<()> {
    let logged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE seq=? AND id=? AND record_id=? AND type=? AND actor IS ? AND payload IS ? AND created_at=?)")
        .bind(event.local_seq).bind(&event.id).bind(&event.record_id).bind(&event.event_type).bind(&event.actor).bind(&event.payload).bind(&event.created_at).fetch_one(&mut *conn).await?;
    if !logged {
        return Err(Error::engine(
            "provider projection requires the kernel-issued logged outcome",
        ));
    }
    let decoded = (entry.decode)(payload)?;
    if decoded.facts.pins != (entry.pins)()
        || event.record_id != decoded.facts.stream_id
        || event.actor.as_deref() != Some(&decoded.facts.principal)
    {
        return Err(Error::engine("provider actor or aggregate mismatch"));
    }
    (entry.validate_recorded)(conn, event, &decoded, replay).await?;
    let current: Option<(String, String, String)> = sqlx::query_as(
        "SELECT provider_key,subjects_json,state_json FROM kernel_provider_state WHERE id=?",
    )
    .bind(&decoded.facts.aggregate_id)
    .fetch_optional(&mut *conn)
    .await?;
    let current: Option<StoredState> = match current {
        Some((provider_key, subjects_json, state_json)) => {
            if provider_key != decoded.facts.provider_key {
                return Err(Error::engine("provider aggregate identity mismatch"));
            }
            let subjects: Vec<String> = serde_json::from_str(&subjects_json)?;
            if subjects != decoded.facts.subjects {
                return Err(Error::engine("provider aggregate subjects mismatch"));
            }
            Some(serde_json::from_str(&state_json)?)
        }
        None => None,
    };
    let folded = (entry.fold)(
        &FoldInput {
            decoded: &decoded,
            principal: &decoded.facts.principal,
            timestamp: &event.created_at,
            event_seq: event.local_seq,
        },
        current.as_ref(),
    )?;
    let stored = StoredState {
        pins: decoded.facts.pins.clone(),
        state: folded.state,
        attribution: folded.attribution,
    };
    // The recorded codec validates its own representation, without a domain cast.
    (entry.state_codec)(&stored)?;
    store_fold(conn, &decoded, &stored, event.local_seq).await
}

async fn store_fold(
    conn: &mut SqliteConnection,
    decoded: &Decoded,
    stored: &StoredState,
    seq: i64,
) -> Result<()> {
    let f = &decoded.facts;
    sqlx::query("INSERT INTO kernel_provider_state(id,provider_key,subjects_json,state_json,head) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state_json=excluded.state_json,head=excluded.head")
        .bind(&f.aggregate_id).bind(&f.provider_key).bind(serde_json::to_string(&f.subjects)?).bind(serde_json::to_string(stored)?).bind(seq).execute(&mut *conn).await?;
    for subject in &f.subjects {
        sqlx::query(
            "INSERT OR IGNORE INTO kernel_provider_subjects(subject_id,aggregate_id) VALUES(?,?)",
        )
        .bind(subject)
        .bind(&f.aggregate_id)
        .execute(&mut *conn)
        .await?;
    }
    // Historical column name retained; the value is an opaque provider receipt ID.
    sqlx::query("INSERT INTO kernel_provider_receipts(principal_id,operation,operation_key,request_json,assertion_id,event_seq) VALUES(?,?,?,?,?,?)")
        .bind(&f.principal).bind(&f.operation).bind(&f.operation_key).bind(serde_json::to_string(&f.receipt_request)?).bind(&f.receipt_id).bind(seq).execute(conn).await?;
    Ok(())
}

/// Generic sealed append admission, selected only by recorded interpretation pins.
pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type != PROVIDER_OUTCOME_EVENT {
        return Ok(());
    }
    let payload: serde_json::Value = event_payload(event)?;
    let entry = catalogue::recorded(&payload)?;
    (entry.admit)(conn, event).await
}
