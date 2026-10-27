//! Dark, connection-scoped imported-source proof helpers. No producer uses these.
//! Preparation owns a read snapshot; recheck requires the same Db's existing
//! BEGIN IMMEDIATE transaction. Neither helper compiles SQL or grants access.
use crate::{db::Db, events::KERNEL_ROOT_ID, kernel, Error, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};
use std::{collections::BTreeSet, time::Instant};

const SECTIONS: [&str; 3] = ["schema_config", "vocabularies", "vocabulary_values"];
const PAGE: i64 = 32;
const PREPARE_ROWS: usize = 65_536;
const PREPARE_BYTES: usize = 8 * 1024 * 1024;
const WINDOW_ROWS: usize = 512;
const WINDOW_BYTES: usize = 1024 * 1024;
const STATE_BYTES: &str = "coalesce(octet_length(section),0)+coalesce(octet_length(source_id),0)+coalesce(octet_length(origin),0)+coalesce(octet_length(payload),0)+coalesce(octet_length(account_principal),0)+coalesce(octet_length(record_id),0)+coalesce(octet_length(observed_at),0)+8";
const EVENT_BYTES: &str = "coalesce(octet_length(id),0)+coalesce(octet_length(record_id),0)+coalesce(octet_length(type),0)+coalesce(octet_length(payload),0)+coalesce(octet_length(actor),0)+coalesce(octet_length(run_key),0)+coalesce(octet_length(parent_key),0)+coalesce(octet_length(intent),0)+coalesce(octet_length(created_at),0)+coalesce(octet_length(causal_status),0)+24";
const EVENT_PAGE: &str =
    "SELECT seq FROM main.content_events NOT INDEXED WHERE seq>? AND seq<=? ORDER BY seq LIMIT ?";

fn state_page_sql(after: bool) -> String {
    format!("SELECT rowid,event_seq,{STATE_BYTES} FROM main.kernel_v1_state WHERE section=? {} ORDER BY source_id LIMIT ?", if after { "AND source_id>?" } else { "" })
}

fn conflict(why: &str) -> Error {
    Error::conflict(format!("view_source_changed: {why}; prepare again"))
}
fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(conflict("source proof deadline exceeded"));
    }
    Ok(())
}
#[derive(Default, Clone, Copy, Debug)]
pub(super) struct Work {
    pub rows: usize,
    pub bytes: usize,
}
impl Work {
    fn charge(&mut self, bytes: i64, rows: usize, limit: usize) -> Result<()> {
        self.rows = self
            .rows
            .checked_add(1)
            .ok_or_else(|| conflict("row bound"))?;
        self.bytes = self
            .bytes
            .checked_add(usize::try_from(bytes).map_err(|_| conflict("invalid byte length"))?)
            .ok_or_else(|| conflict("byte bound"))?;
        if self.rows > rows || self.bytes > limit {
            return Err(conflict("source scan budget exceeded"));
        }
        Ok(())
    }
}
#[derive(Debug)]
pub(super) struct Source {
    pub section: String,
    pub source_id: String,
    pub origin: String,
    pub payload: String,
    pub event_id: String,
    #[allow(dead_code)] // Retained evidence consumed by the future trusted resolver.
    pub event_sha256: String,
    event_seq: i64,
}
#[derive(Clone)]
struct Anchor {
    id: String,
    home: String,
    // Conservatively detects logical rehomes as well as physical placement.
    // Interpreting logical records.home_id belongs to the later resolver.
    moved: i64,
}
#[derive(Clone)]
struct Reference {
    section: String,
    source_id: String,
    origin: String,
    event_seq: i64,
    event_id: String,
}
#[allow(dead_code)] // B is deliberately not wired to a generated producer.
pub(super) struct Snapshot {
    conn: SqliteConnection,
    db: Db,
    head: (i64, String),
    deadline: Instant,
    sources: Vec<Source>,
    work: Work,
}
#[allow(dead_code)] // Only a future trusted resolver may construct/use this proof.
pub(super) struct Proof {
    db: Db,
    actor: String,
    head: (i64, String),
    deadline: Instant,
    refs: Vec<Reference>,
    anchors: Vec<Anchor>,
}

async fn head_on(conn: &mut SqliteConnection) -> Result<(i64, String)> {
    sqlx::query_as("SELECT seq,id FROM main.content_events ORDER BY seq DESC LIMIT 1")
        .fetch_optional(conn)
        .await?
        .ok_or_else(|| conflict("missing source snapshot anchor"))
}
async fn anchor_on(conn: &mut SqliteConnection, actor: &str, id: &str) -> Result<Anchor> {
    let mut seen = BTreeSet::new();
    super::closure::require_accessible_bearer_on(conn, actor, id, &mut seen, true).await?;
    let (home, moved): (String, i64) = sqlx::query_as("SELECT home_id,coalesce((SELECT max(seq) FROM main.content_events INDEXED BY idx_kernel_record_moves WHERE record_id=? AND type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2')),0) FROM main.kernel_records WHERE id=?")
        .bind(id).bind(id).fetch_one(conn).await?;
    Ok(Anchor {
        id: id.into(),
        home,
        moved,
    })
}

#[allow(dead_code)] // Closed proof-only entrypoint, not an admission API.
pub(super) async fn prepare(db: &Db, deadline: Instant) -> Result<Snapshot> {
    check(deadline)?;
    // A detached, owned read-only connection cannot return a progress callback
    // or an open snapshot to a serving borrower, including on cancellation.
    let mut conn = tokio::time::timeout_at(deadline.into(), db.pool().acquire())
        .await
        .map_err(|_| conflict("source snapshot queue deadline"))??
        .detach();
    conn.lock_handle()
        .await?
        .set_progress_handler(100, move || Instant::now() < deadline);
    sqlx::query("BEGIN").execute(&mut conn).await?;
    let head = head_on(&mut conn).await?; // Establish S before any source read.
    let mut sources = Vec::new();
    let mut work = Work::default();
    for section in SECTIONS {
        let mut after = String::new();
        let mut first = true;
        loop {
            check(deadline)?;
            // Direct column octet_length uses SQLite's BYTELEN Column flag:
            // numeric metadata only, no CAST, JSON filter or oversized cells.
            let sql = state_page_sql(!first);
            let mut query = sqlx::query_as::<_, (i64, i64, i64)>(&sql).bind(section);
            if !first {
                query = query.bind(&after);
            }
            // Reserve one sealed-wrapper row for every returned state row.
            // Refuse before another page when completeness cannot fit: do not
            // fetch a sentinel page outside the shared inspected-row cap.
            let limit = ((PREPARE_ROWS - work.rows) / 2).min(PAGE as usize);
            if limit == 0 {
                return Err(conflict("source scan budget exceeded"));
            }
            let rows = query.bind(limit as i64).fetch_all(&mut conn).await?;
            if rows.is_empty() {
                break;
            }
            // Charge the complete inspected metadata page before fetching cells.
            for (_, _, bytes) in &rows {
                work.charge(*bytes, PREPARE_ROWS, PREPARE_BYTES)?;
            }
            for (rowid, seq, _) in rows {
                check(deadline)?;
                trace(Trace::StateFetch);
                let row = sqlx::query("SELECT source_id,origin,payload,account_principal,record_id,observed_at FROM main.kernel_v1_state WHERE rowid=?")
                    .bind(rowid).fetch_one(&mut conn).await?;
                after = row.try_get("source_id")?;
                let event = sealed_on(&mut conn, seq, head.0, &mut work, deadline).await?;
                let wrapper = decode_wrapper(&event.kind, &event.payload)?;
                if event.record != KERNEL_ROOT_ID
                    || wrapper.section != section
                    || wrapper.source_id != after
                    || wrapper.origin != row.try_get::<String, _>("origin")?
                    || wrapper.value_json.as_deref() != Some(row.try_get::<&str, _>("payload")?)
                    || wrapper.account_principal
                        != row.try_get::<Option<String>, _>("account_principal")?
                    || wrapper.record_id != row.try_get::<Option<String>, _>("record_id")?
                    || wrapper.observed_at != row.try_get::<String, _>("observed_at")?
                {
                    return Err(conflict("state differs from sealed import"));
                }
                let value = serde_json::from_str::<crate::record_body::budgeted::UniqueJson>(
                    wrapper.value_json.as_deref().unwrap(),
                )?
                .0;
                if !value.is_object()
                    || value["id"].as_str().is_none()
                    || serde_json::to_string(&[value["id"].as_str().unwrap()])? != after
                {
                    return Err(conflict("source row identity differs"));
                }
                sources.push(Source {
                    section: section.into(),
                    source_id: after.clone(),
                    origin: wrapper.origin,
                    payload: wrapper.value_json.unwrap(),
                    event_id: event.id,
                    event_seq: seq,
                    event_sha256: event.digest,
                });
            }
            first = false;
        }
    }
    check(deadline)?;
    Ok(Snapshot {
        conn,
        db: db.clone(),
        head,
        deadline,
        sources,
        work,
    })
}

struct Sealed {
    id: String,
    record: String,
    kind: String,
    payload: String,
    digest: String,
}
async fn sealed_on(
    conn: &mut SqliteConnection,
    seq: i64,
    head: i64,
    work: &mut Work,
    deadline: Instant,
) -> Result<Sealed> {
    check(deadline)?;
    if seq <= 0 || seq > head {
        return Err(conflict("source event outside snapshot"));
    }
    let size: i64 = sqlx::query_scalar(&format!(
        "SELECT {EVENT_BYTES} FROM main.content_events WHERE seq=?"
    ))
    .bind(seq)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| conflict("source event missing"))?;
    work.charge(size, PREPARE_ROWS, PREPARE_BYTES)?;
    trace(Trace::EventFetch);
    let (id, record, kind, payload): (String, String, String, String) =
        sqlx::query_as("SELECT id,record_id,type,payload FROM main.content_events WHERE seq=?")
            .bind(seq)
            .fetch_one(conn)
            .await?;
    let parsed: crate::record_body::budgeted::UniqueJson = serde_json::from_str(&payload)?;
    let digest = format!(
        "{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &serde_json::json!([kind, record, parsed.0])
        ))
    );
    Ok(Sealed {
        id,
        record,
        kind,
        payload,
        digest,
    })
}
fn decode_wrapper(kind: &str, raw: &str) -> Result<kernel::v1_state::ImportedState> {
    trace(Trace::Parse);
    if kind != kernel::v1_state::EVENT {
        return Err(conflict("unsupported import version"));
    }
    // Reject duplicates before the closed typed envelope erases them. The
    // snapshot value is bounded provenance, never an admission authority.
    let _: crate::record_body::budgeted::UniqueJson = serde_json::from_str(raw)?;
    let row: kernel::v1_state::ImportedState = serde_json::from_str(raw)?;
    if !matches!(
        row.section.as_str(),
        "member_contexts"
            | "member_context_capture"
            | "identity_directory_capture"
            | "surface_bindings"
            | "surface_bindings_capture"
            | "account_config_capture"
            | "account_configs"
            | "record_deletion_guards"
            | "account_directory"
            | "vocabularies"
            | "vocabulary_values"
            | "schema_config"
            | "onboarding_programmes"
            | "onboarding_programme_sources"
            | "member_obligations"
            | "member_obligation_progress"
            | "runs"
            | "run_intents"
            | "claims"
    ) || row.source_id.is_empty()
        || row.origin.is_empty()
        || !row.snapshot.is_object()
        || chrono::DateTime::parse_from_rfc3339(&row.observed_at).is_err()
    {
        return Err(conflict("malformed import wrapper"));
    }
    Ok(row)
}

#[allow(dead_code)] // Future resolver selects evidence only from this owned S snapshot.
impl Snapshot {
    pub(super) fn sources(&self) -> &[Source] {
        &self.sources
    }
    pub(super) fn work(&self) -> Work {
        self.work
    }

    pub(super) async fn seal(
        mut self,
        actor: &str,
        selected: &[usize],
        anchors: &[String],
    ) -> Result<Proof> {
        check(self.deadline)?;
        if selected.len() > 288 || anchors.is_empty() || anchors.len() > 33 {
            return Err(conflict("retained source/anchor bound"));
        }
        let mut refs = Vec::new();
        let mut ids = BTreeSet::new();
        let mut catalog = 0;
        let mut values = std::collections::BTreeMap::<String, usize>::new();
        for index in selected {
            check(self.deadline)?;
            if !ids.insert(index) {
                return Err(conflict("duplicate selected source"));
            }
            let source = self
                .sources
                .get(*index)
                .ok_or_else(|| conflict("unknown selected source"))?;
            if source.section == "vocabulary_values" {
                let value: Value = serde_json::from_str(&source.payload)?;
                let vocab = value["vocabulary_id"]
                    .as_str()
                    .ok_or_else(|| conflict("missing vocabulary identity"))?;
                *values.entry(vocab.into()).or_default() += 1;
            } else {
                catalog += 1;
            }
            refs.push(Reference {
                section: source.section.clone(),
                source_id: source.source_id.clone(),
                origin: source.origin.clone(),
                event_seq: source.event_seq,
                event_id: source.event_id.clone(),
            });
        }
        if catalog > 32
            || values.values().sum::<usize>() > 256
            || values.values().any(|n| *n > 64)
            || refs.iter().filter(|r| r.section == "schema_config").count() > 128
        {
            return Err(conflict("retained source category bound"));
        }
        let mut checked = Vec::new();
        let mut seen = BTreeSet::new();
        for id in anchors {
            check(self.deadline)?;
            if !seen.insert(id) {
                return Err(conflict("duplicate anchor"));
            }
            checked.push(anchor_on(&mut self.conn, actor, id).await?);
        }
        check(self.deadline)?;
        sqlx::query("ROLLBACK").execute(&mut self.conn).await?;
        Ok(Proof {
            db: self.db,
            actor: actor.into(),
            head: self.head,
            deadline: self.deadline,
            refs,
            anchors: checked,
        })
    }
}

#[allow(dead_code)] // No authored write or receipt path calls this helper.
impl Proof {
    pub(super) async fn recheck_on(
        &self,
        db: &Db,
        conn: &mut SqliteConnection,
        actor: &str,
    ) -> Result<Work> {
        check(self.deadline)?;
        if !self.db.same_handle(db) || actor != self.actor {
            return Err(conflict("source proof owner differs"));
        }
        let current = head_on(conn).await?;
        let id: Option<String> =
            sqlx::query_scalar("SELECT id FROM main.content_events WHERE seq=?")
                .bind(self.head.0)
                .fetch_optional(&mut *conn)
                .await?;
        if current.0 < self.head.0 || id.as_deref() != Some(&self.head.1) {
            return Err(conflict("source snapshot anchor changed"));
        }
        // Current authorization is never certified by the interval. Check it
        // before reporting conflicts which might describe hidden source work.
        for expected in &self.anchors {
            check(self.deadline)?;
            let actual = anchor_on(conn, actor, &expected.id).await?;
            if actual.home != expected.home || actual.moved != expected.moved {
                return Err(conflict("anchor placement changed"));
            }
        }
        for r in &self.refs {
            check(self.deadline)?;
            // Do not transport a replacement origin before noticing a stale
            // reference. CASE is lazy and direct octet_length uses metadata;
            // any compared string is at most the already charged S length.
            let actual: Option<(i64,String,bool)> = sqlx::query_as("SELECT s.event_seq,e.id,CASE WHEN octet_length(s.origin)=? THEN s.origin=? ELSE 0 END FROM main.kernel_v1_state s JOIN main.content_events e ON e.seq=s.event_seq WHERE s.section=? AND s.source_id=?")
                .bind(r.origin.len() as i64).bind(&r.origin).bind(&r.section).bind(&r.source_id).fetch_optional(&mut *conn).await?;
            if actual != Some((r.event_seq, r.event_id.clone(), true)) {
                return Err(conflict("source reference changed"));
            }
        }
        let mut work = Work::default();
        let mut after = self.head.0;
        while after < current.0 {
            check(self.deadline)?;
            // Every event in (S,T], never a type-filtered LIMIT.
            let limit = (WINDOW_ROWS - work.rows).min(PAGE as usize);
            if limit == 0 {
                return Err(conflict("source scan budget exceeded"));
            }
            let seqs: Vec<i64> = sqlx::query_scalar(EVENT_PAGE)
                .bind(after)
                .bind(current.0)
                .bind(limit as i64)
                .fetch_all(&mut *conn)
                .await?;
            if seqs.is_empty() {
                return Err(conflict("event interval incomplete"));
            }
            for _ in &seqs {
                trace(Trace::WindowRow);
            }
            let mut metadata = Vec::new();
            for seq in seqs {
                check(self.deadline)?;
                let bytes: i64 = sqlx::query_scalar(&format!(
                    "SELECT {EVENT_BYTES} FROM main.content_events WHERE seq=?"
                ))
                .bind(seq)
                .fetch_one(&mut *conn)
                .await?;
                work.charge(bytes, WINDOW_ROWS, WINDOW_BYTES)?;
                metadata.push(seq);
            }
            for seq in metadata {
                check(self.deadline)?;
                let kind: String =
                    sqlx::query_scalar("SELECT type FROM main.content_events WHERE seq=?")
                        .bind(seq)
                        .fetch_one(&mut *conn)
                        .await?;
                if kind.starts_with("kernel.v1_state_imported.") {
                    trace(Trace::EventFetch);
                    let (record, raw): (String, String) = sqlx::query_as(
                        "SELECT record_id,payload FROM main.content_events WHERE seq=?",
                    )
                    .bind(seq)
                    .fetch_one(&mut *conn)
                    .await?;
                    let wrapper = decode_wrapper(&kind, &raw)?;
                    if record != KERNEL_ROOT_ID {
                        return Err(conflict("malformed import anchor"));
                    }
                    if SECTIONS.contains(&wrapper.section.as_str()) {
                        return Err(conflict("catalog import since preparation"));
                    }
                }
                after = seq;
            }
        }
        check(self.deadline)?;
        Ok(work)
    }
}

#[derive(Clone, Copy)]
enum Trace {
    StateFetch,
    EventFetch,
    Parse,
    WindowRow,
}
fn trace(_event: Trace) {
    #[cfg(test)]
    let _ = TRACE.try_with(|n| {
        let mut v = n.get();
        v[_event as usize] += 1;
        n.set(v);
    });
}
#[cfg(test)]
tokio::task_local! { static TRACE: std::cell::Cell<[usize;4]>; }
#[cfg(test)]
mod tests;
