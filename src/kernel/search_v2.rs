//! HQ cutover slice S7a: text search and bounded record queries on the v2
//! kernel. Probe-only (`v2-kernel-probe`): the FTS index, its projection
//! maintenance, the bounded query scanner and the indexed prefix resolver all
//! live here so the ordinary MCP handlers in `mcp::kernel_v2` stay thin.
//!
//! Visibility rule (load-bearing): hidden records never affect counts or
//! ordering visible to the caller. The FTS index therefore stores every
//! record, and capability filtering happens after the match, over
//! caller-visible rows only. Scores are tier constants (title 0, summary 1,
//! body 2) — corpus-independent by construction, so hidden rows cannot shift
//! a visible row's score the way raw BM25/IDF would.
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

/// Timing-independent read accounting for the bounded-query tests: how many
/// indexed page scans ran, and how many bulk hydration reads (fields,
/// bodies, revisions) a call performed. One instance per call — the registry
/// passes a fresh one, tests pass their own — so parallel tests never share
/// counts.
#[derive(Debug, Default)]
pub(crate) struct S7aCounters {
    pub scan_pages: AtomicUsize,
    pub field_reads: AtomicUsize,
    // Pinned at zero: list paths never read the body lane. Test-only so
    // non-test builds do not carry an unread counter.
    #[cfg(test)]
    pub body_reads: AtomicUsize,
    pub revision_reads: AtomicUsize,
}
impl S7aCounters {
    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> (usize, usize, usize, usize) {
        (
            self.scan_pages.load(Ordering::Relaxed),
            self.field_reads.load(Ordering::Relaxed),
            self.body_reads.load(Ordering::Relaxed),
            self.revision_reads.load(Ordering::Relaxed),
        )
    }
}

/// FTS5 index over title, summary and body. `record_id` is stored unindexed;
/// ranking is tier-based in Rust, never BM25, so hidden rows cannot move a
/// visible hit. Maintained by the kernel projection (see `refresh_search_row`)
/// and rebuilt wholesale by `replay_all_projections`.
pub(crate) const SEARCH_FTS_DDL: &str = "CREATE VIRTUAL TABLE IF NOT EXISTS kernel_search_fts USING fts5(record_id UNINDEXED, title, summary, body, tokenize='unicode61')";
/// Covering index for the bounded group scans: equality on family/kind,
/// ordered range on (accession, id) for stable cursor paging.
pub(crate) const SCAN_INDEX_DDL: &str = "CREATE INDEX IF NOT EXISTS idx_kernel_records_family_kind_accession ON kernel_records(pin_family, kind, accession, id)";
/// Current probe index version. Bump when the indexed content or its schema
/// changes; `ensure_search_index` rebuilds anything older (including
/// databases that only ever saw the lazy per-write creation, which wrote no
/// marker at all).
pub(crate) const SEARCH_INDEX_VERSION: i64 = 1;
pub(crate) const SEARCH_META_DDL: &str =
    "CREATE TABLE IF NOT EXISTS kernel_search_meta(version INTEGER NOT NULL)";

/// Probe schema additions. Idempotent, so replay and older databases converge
/// without a migration. Seeds the version marker: the schema is current and
/// the projection maintains it from here.
pub(crate) async fn apply_search_schema(conn: &mut SqliteConnection) -> Result<()> {
    sqlx::query(SEARCH_FTS_DDL).execute(&mut *conn).await?;
    sqlx::query(SCAN_INDEX_DDL).execute(&mut *conn).await?;
    sqlx::query(SEARCH_META_DDL).execute(&mut *conn).await?;
    sqlx::query("INSERT INTO kernel_search_meta(version) SELECT ? WHERE NOT EXISTS(SELECT 1 FROM kernel_search_meta)")
        .bind(SEARCH_INDEX_VERSION)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Ensure the probe search schema exists and is populated, backfilling
/// pre-existing records. Called on the KernelV2 open path (not lazily per
/// write): a database created before the probe schema — or one given only a
/// partial index by the earlier lazy per-write creation, which wrote no
/// version marker — gains a complete index instead of one covering only
/// post-upgrade writes. No-op when the marker is current.
/// The FTS table stores its own copy of indexed text (title, summary, body):
/// derived data, fully rebuildable from projections via `rebuild_search_index`.
pub async fn ensure_search_index(db: &Db) -> Result<()> {
    let tables: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'kernel_search_fts')
         AND EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'kernel_search_meta')",
    )
    .fetch_one(db.pool())
    .await?;
    // The version read runs only when the table exists: referencing a
    // missing table fails at prepare time, not per row.
    let current = if tables {
        sqlx::query_scalar::<_, i64>("SELECT version FROM kernel_search_meta LIMIT 1")
            .fetch_optional(db.pool())
            .await?
            .is_some_and(|version| version >= SEARCH_INDEX_VERSION)
    } else {
        false
    };
    if current {
        return Ok(());
    }
    let mut tx = begin_write(db.write_pool()).await?;
    rebuild_search_index(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

/// Re-index one record after its fields or body changed. Reads only the
/// title/summary/body(-field) rows and the body lane — never the full field
/// set — and upserts exactly one FTS row. The schema is ensured by the
/// constructors and the open path, never here.
pub(crate) async fn refresh_search_row(conn: &mut SqliteConnection, record_id: &str) -> Result<()> {
    let field_rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, value_json FROM kernel_record_fields WHERE record_id = ? AND name IN ('title', 'summary', 'body')",
    )
    .bind(record_id)
    .fetch_all(&mut *conn)
    .await?;
    let mut title = String::new();
    let mut summary = String::new();
    let mut field_body = String::new();
    for (name, value_json) in field_rows {
        let text: serde_json::Value = serde_json::from_str(&value_json)?;
        let text = text.as_str().unwrap_or("").to_string();
        match name.as_str() {
            "title" => title = text,
            "summary" => summary = text,
            _ => field_body = text,
        }
    }
    let lane_body: Option<String> =
        sqlx::query_scalar("SELECT body FROM kernel_record_bodies WHERE record_id = ?")
            .bind(record_id)
            .fetch_optional(&mut *conn)
            .await?;
    let body = match (field_body.is_empty(), lane_body) {
        (true, Some(lane)) => lane,
        (true, None) => String::new(),
        (false, Some(lane)) if !lane.is_empty() => format!("{field_body}\n{lane}"),
        _ => field_body,
    };
    sqlx::query("DELETE FROM kernel_search_fts WHERE record_id = ?")
        .bind(record_id)
        .execute(&mut *conn)
        .await?;
    if !(title.is_empty() && summary.is_empty() && body.is_empty()) {
        sqlx::query(
            "INSERT INTO kernel_search_fts(record_id, title, summary, body) VALUES(?, ?, ?, ?)",
        )
        .bind(record_id)
        .bind(title)
        .bind(summary)
        .bind(body)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// Rebuild the whole search index from current projections. Called at the end
/// of `replay_all_projections`; per-event refresh during replay already
/// converges, this makes the rebuild explicit and self-healing.
pub(crate) async fn rebuild_search_index(conn: &mut SqliteConnection) -> Result<()> {
    apply_search_schema(conn).await?;
    sqlx::query("DELETE FROM kernel_search_fts")
        .execute(&mut *conn)
        .await?;
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM kernel_records ORDER BY id")
        .fetch_all(&mut *conn)
        .await?;
    for id in ids {
        refresh_search_row(conn, &id).await?;
    }
    // The rebuild is the version's source of truth: anything reaching this
    // point carries a complete index at the current version.
    sqlx::query("DELETE FROM kernel_search_meta")
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO kernel_search_meta(version) VALUES(?)")
        .bind(SEARCH_INDEX_VERSION)
        .execute(&mut *conn)
        .await?;
    Ok(())
}
/// Preloaded authorization inputs for one bounded call, so per-candidate
/// visibility is pure CPU after a constant number of indexed queries.
/// Mirrors `kernel_effective_capability_on` exactly: home anchor walk with the
/// same depth bound, policy-entry evaluation, owner floor. Homes and policies
/// are few; candidates are many.
struct PolicyCache {
    admitted: bool,
    anchors: HashMap<String, String>,
    entries: HashMap<String, Vec<(String, String, String, String)>>,
}

async fn load_policy_cache(conn: &mut SqliteConnection, principal: &str) -> Result<PolicyCache> {
    let admitted = super::hosted_identity::admitted(conn, principal).await?;
    let mut loaded = load_roots_and_entries(conn).await?;
    for home in &loaded.anchored {
        if let Some(rows) = super::hosted_identity::policy_rows(conn, principal, home).await? {
            loaded.entries.insert(home.clone(), rows);
        }
    }
    let mut anchors = HashMap::new();
    for id in loaded.roots.iter() {
        // Unresolvable homes stay out of the cache: records there can never
        // pass the SQL-side scope filter, and the per-row gate below treats
        // an unresolvable home as hidden rather than failing the call.
        if let Ok(anchor) = resolve_anchor_strict(&loaded, id) {
            anchors.insert(id.clone(), anchor);
        }
    }
    Ok(PolicyCache {
        admitted,
        anchors,
        entries: loaded.entries,
    })
}

/// Raw authorization tables for one call: every home's parent, the anchored
/// roots, and every policy entry. Homes and policies are few; loading them
/// once lets per-row visibility become pure CPU (the cache) or a SQL filter
/// (the visible scope below).
struct LoadedAuthz {
    parents: HashMap<String, Option<String>>,
    roots: HashSet<String>,
    anchored: HashSet<String>,
    entries: HashMap<String, Vec<(String, String, String, String)>>,
}

async fn load_roots_and_entries(conn: &mut SqliteConnection) -> Result<LoadedAuthz> {
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT root_id, parent_id FROM kernel_roots")
            .fetch_all(&mut *conn)
            .await?;
    let roots: HashSet<String> = rows.iter().map(|(id, _)| id.clone()).collect();
    let parents: HashMap<String, Option<String>> = rows.into_iter().collect();
    let anchored: HashSet<String> =
        sqlx::query_scalar::<_, String>("SELECT root_id FROM kernel_policies")
            .fetch_all(&mut *conn)
            .await?
            .into_iter()
            .collect();
    let entry_rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT root_id, subject_kind, subject_id, effect, capability FROM kernel_policy_entries",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut entries: HashMap<String, Vec<(String, String, String, String)>> = HashMap::new();
    for (root, kind, subject, effect, capability) in entry_rows {
        entries
            .entry(root)
            .or_default()
            .push((kind, subject, effect, capability));
    }
    Ok(LoadedAuthz {
        parents,
        roots,
        anchored,
        entries,
    })
}

/// Strict anchor walk, mirroring `kernel_effective_capability_on`: the same
/// depth bound, the same fail-closed errors. Used where exact parity with
/// the per-record gate matters.
fn resolve_anchor_strict(loaded: &LoadedAuthz, home_id: &str) -> Result<String> {
    let mut anchor = home_id.to_string();
    let mut depth = 0usize;
    loop {
        if loaded.anchored.contains(&anchor) {
            return Ok(anchor);
        }
        depth += 1;
        if depth > MAX_HOME_DEPTH {
            return Err(Error::engine(HIDDEN_OR_MISSING));
        }
        anchor = loaded
            .parents
            .get(anchor.as_str())
            .and_then(|parent| parent.clone())
            .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
    }
}

fn evaluate_anchor(
    entries: &HashMap<String, Vec<(String, String, String, String)>>,
    anchor: &str,
    principal_id: &str,
) -> Result<Capability> {
    let empty = Vec::new();
    let rows = entries.get(anchor).unwrap_or(&empty);
    let evaluation_entries: Vec<PolicyEvaluationEntry<'_>> = rows
        .iter()
        .map(|row| PolicyEvaluationEntry {
            subject_kind: &row.0,
            subject_id: &row.1,
            effect: &row.2,
            capability: &row.3,
        })
        .collect();
    evaluate_policy_grants(
        PolicyEvaluationPrincipal::new(Some(principal_id), false),
        &evaluation_entries,
    )
    .map_err(|_| Error::engine(HIDDEN_OR_MISSING))
}

/// Cached equivalent of `kernel_effective_capability_on` for a record row the
/// caller already holds. `home_id`/`owner_id` come from the row; nothing is
/// read. Fail-closed exactly like the original.
fn cached_capability(
    cache: &PolicyCache,
    principal_id: &str,
    home_id: &str,
    owner_id: Option<&str>,
) -> Result<Capability> {
    if !cache.admitted {
        return Ok(Capability::None);
    }
    let anchor = cache
        .anchors
        .get(home_id)
        .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
    let policy_capability = evaluate_anchor(&cache.entries, anchor, principal_id)?;
    Ok(resolve_effective_capability(
        policy_capability,
        owner_id == Some(principal_id),
    ))
}

/// Per-row second gate with comment derivation: comment candidates resolve
/// through the kernel capability (terminal bearer policy plus its owner's
/// floor), never the candidate's own home or owner. Every other candidate
/// keeps the cached home-policy check.
async fn candidate_visible(
    conn: &mut SqliteConnection,
    cache: &PolicyCache,
    principal_id: &str,
    meta: &CandidateMeta,
) -> bool {
    if !super::messaging::audience_allows(conn, principal_id, &meta.id)
        .await
        .unwrap_or(false)
    {
        return false;
    }
    if super::hq::tombstoned_on(conn, &meta.id)
        .await
        .unwrap_or(true)
    {
        return false;
    }
    if comments_v2::is_derived_on(conn, &meta.id)
        .await
        .unwrap_or(true)
    {
        return kernel_effective_capability_on(conn, principal_id, &meta.id)
            .await
            .is_ok_and(|capability| capability.allows(Capability::View));
    }
    matches!(
        cached_capability(cache, principal_id, &meta.home_id, meta.owner_id.as_deref()),
        Ok(capability) if capability.allows(Capability::View)
    )
}
/// One candidate row from the covering index: identity plus everything the
/// v1-shaped envelope needs, without fields, bodies or revision lookups.
#[derive(Debug, Clone)]
struct CandidateMeta {
    id: String,
    accession: Option<String>,
    home_id: String,
    owner_id: Option<String>,
    primary_type: Option<String>,
    kind: Option<String>,
    pin_family: Option<String>,
    pin_version: Option<i64>,
    pin_digest: Option<String>,
    interpreter: Option<String>,
    created_at: String,
}

type CandidateRow = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
    String,
);

fn candidate_meta(row: CandidateRow) -> CandidateMeta {
    CandidateMeta {
        id: row.0,
        accession: row.1,
        home_id: row.2,
        owner_id: row.3,
        primary_type: row.4,
        kind: row.5,
        pin_family: row.6,
        pin_version: row.7,
        pin_digest: row.8,
        interpreter: row.9,
        created_at: row.10,
    }
}

/// Caller-facing type/kind for one candidate. Mirrors
/// `mcp::kernel_v2::v1_type_and_kind` (the canonical definition lives there;
/// this copy keeps the query path inside the kernel crate): records carried
/// by `native/v1@1` report their v1 fields, everything else its columns.
fn candidate_type_and_kind<'a>(
    meta: &'a CandidateMeta,
    v1_type: Option<&'a str>,
    v1_kind: Option<&'a str>,
) -> (Option<&'a str>, Option<&'a str>) {
    if meta.pin_family.as_deref() == Some("native.v1.record") && meta.pin_version == Some(1) {
        (v1_type, v1_kind)
    } else {
        (meta.primary_type.as_deref(), meta.kind.as_deref())
    }
}

fn is_carrier(meta: &CandidateMeta) -> bool {
    meta.pin_family.as_deref() == Some("native.v1.record") && meta.pin_version == Some(1)
}

/// A hydrated list hit: everything `record_value` renders, with the body lane
/// deliberately absent — lists never read `kernel_record_bodies`.
#[derive(Debug, Clone)]
pub(crate) struct BoundedRecord {
    pub metadata: RecordMetadata,
    pub id: String,
    pub home_id: String,
    pub owner_id: Option<String>,
    pub primary_type: Option<String>,
    pub kind: Option<String>,
    pub family: Option<String>,
    pub pin: Option<RevisionIdentity>,
    pub interpreter: Option<String>,
    pub created_at: String,
    pub revision: i64,
    pub fields: serde_json::Map<String, serde_json::Value>,
}

pub(crate) struct BoundedQueryPage {
    pub total: usize,
    pub records: Vec<BoundedRecord>,
}

/// Distinct visible-shape groups, cheapest possible: two narrow columns, no
/// fields, no bodies, no per-record work. Replaces the `list_records_as`
/// group discovery that loaded every visible record in full.
pub(crate) async fn distinct_groups(db: &Db) -> Result<Vec<(String, String)>> {
    let mut snapshot = db.pool().begin().await?;
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT pin_family, kind FROM kernel_records WHERE pin_family IS NOT NULL AND kind IS NOT NULL ORDER BY pin_family, kind",
    )
    .fetch_all(&mut *snapshot)
    .await?;
    snapshot.rollback().await?;
    Ok(rows)
}
const SCAN_FETCH: i64 = 500;

/// Linked-to visibility gate, mirroring `query_as`: an unseen or nonexistent
/// anchor behaves exactly like a nonexistent id (empty page, no signal).
async fn linked_anchor_visible(
    conn: &mut SqliteConnection,
    principal_id: &str,
    linked_id: &str,
) -> Result<bool> {
    if sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
        .bind(linked_id)
        .fetch_one(&mut *conn)
        .await?
    {
        Ok(
            kernel_effective_capability_on(conn, principal_id, linked_id)
                .await?
                .allows(Capability::View),
        )
    } else if sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id = ?)",
    )
    .bind(linked_id)
    .fetch_one(&mut *conn)
    .await?
    {
        Ok(
            kernel_effective_capability_on(conn, principal_id, KERNEL_ROOT_ID)
                .await?
                .allows(Capability::View),
        )
    } else {
        Ok(false)
    }
}

// Both link lanes use the same candidate/anchor predicate. The outer record
// scan applies SCOPE_CLAUSE before counting or hydration; the anchor is admitted
// once in the same snapshot by linked_anchor_visible.
fn linked_clause(direction: &str) -> Result<String> {
    let predicate = match direction {
        "out" => "l.source_id = r.id AND l.target_id = ?",
        "in" => "l.target_id = r.id AND l.source_id = ?",
        "either" => {
            "((l.source_id = r.id AND l.target_id = ?) OR (l.target_id = r.id AND l.source_id = ?))"
        }
        _ => {
            return Err(Error::engine(format!(
                "unknown link direction '{direction}'"
            )))
        }
    };
    Ok(format!(" AND EXISTS(SELECT 1 FROM (SELECT source_id,target_id,relationship FROM kernel_links UNION ALL SELECT source_id,target_id,relationship FROM kernel_generic_links WHERE active=1) l WHERE {predicate} AND l.relationship = ?)"))
}

/// Scan one family/kind group through the covering index, evaluating
/// SQL-side visibility terms from S8's shared `visible_home_anchors_as`:
/// homes whose policy grants View, plus homes with a valid policy (whose
/// records the caller may own). The scan predicate is
/// `home IN view OR (home IN valid AND owner = caller)` — exactly record
/// View — so hidden rows are never scanned, counted, or bounded.
struct SqlScope {
    view_json: String,
    valid_json: String,
    terminal_json: String,
}

fn sql_scope(scope: &VisibleHomeAnchors) -> Result<SqlScope> {
    let view: Vec<&str> = scope
        .homes
        .iter()
        .filter(|home| home.policy_view)
        .map(|home| home.home_id.as_str())
        .collect();
    let valid: Vec<&str> = scope
        .homes
        .iter()
        .filter(|home| home.policy_valid)
        .map(|home| home.home_id.as_str())
        .collect();
    Ok(SqlScope {
        view_json: serde_json::to_string(&view)?,
        valid_json: serde_json::to_string(&valid)?,
        terminal_json: serde_json::to_string(
            &scope
                .homes
                .iter()
                .filter(|h| h.policy_valid)
                .map(|h| serde_json::json!({"id":h.home_id,"view":h.policy_view}))
                .collect::<Vec<_>>(),
        )?,
    })
}

/// Derived-artifact scope: annotations and attachments never take the record-owner leg, and the
/// terminal owner's floor reaches them through the bearer chain. The two
/// trailing binds are the valid-homes JSON plus the actor once; every
/// `SCOPE_CLAUSE` call site binds them immediately after the principal.
fn scope_clause() -> String {
    // Five binds: ordinary view/valid/owner, then terminal home scopes/owner.
    // The terminal homes use one JSON object to keep the bound SQL stable.
    format!(
        " AND (((NOT {derived}) AND ((r.home_id IN (SELECT value FROM json_each(?))) OR (r.home_id IN (SELECT value FROM json_each(?)) AND r.owner_id=?))) OR ({derived} AND {derived_visible}))",
        derived = crate::kernel::sql_is_derived_artifact("r"),
        derived_visible = comments_v2::sql_derived_visible("r", "?", "SELECT json_extract(value,'$.id') AS id,json_extract(value,'$.view') AS view FROM json_each(?)"),
    )
}

/// Scan one family/kind group through the covering index. Hidden rows are
/// excluded in SQL by the caller's scope, so the walk, its counts and any
/// bound never observe them; the cached capability stays as an exact
/// per-row second gate. No per-record MAX(seq), no fields, no bodies.
/// Returns matching candidates in (accession, id) order with the cursor for
/// the next page (`None` = group exhausted).
#[allow(clippy::too_many_arguments)]
async fn scan_group(
    conn: &mut SqliteConnection,
    cache: &PolicyCache,
    scope: &SqlScope,
    family: &str,
    kind: &str,
    linked_to: Option<(&str, &str, &str)>,
    cursor: Option<(String, String)>,
    principal_id: &str,
    counters: &S7aCounters,
) -> Result<(Vec<CandidateMeta>, Option<(String, String)>)> {
    let mut sql = String::from(
        "SELECT r.id, r.accession, r.home_id, r.owner_id, r.primary_type, r.kind, r.pin_family, r.pin_version, r.pin_digest, r.interpreter, r.created_at
         FROM kernel_records r WHERE r.pin_family = ? AND r.kind = ?",
    );
    sql.push_str(&scope_clause());
    if let Some((_, _, direction)) = linked_to {
        sql.push_str(&linked_clause(direction)?);
    }
    if cursor.is_some() {
        sql.push_str(" AND (r.accession, r.id) > (?, ?)");
    }
    sql.push_str(" ORDER BY r.accession, r.id LIMIT ?");
    let mut query = sqlx::query_as::<_, CandidateRow>(&sql)
        .bind(family)
        .bind(kind)
        .bind(&scope.view_json)
        .bind(&scope.valid_json)
        .bind(principal_id)
        .bind(&scope.terminal_json)
        .bind(principal_id);
    if let Some((predicate, linked_id, direction)) = linked_to {
        query = query.bind(linked_id);
        if direction == "either" {
            query = query.bind(linked_id);
        }
        query = query.bind(predicate);
    }
    if let Some((accession, id)) = &cursor {
        query = query.bind(accession).bind(id);
    }
    query = query.bind(SCAN_FETCH);
    counters.scan_pages.fetch_add(1, Ordering::Relaxed);
    let rows: Vec<CandidateRow> = query.fetch_all(&mut *conn).await?;
    let window_full = rows.len() as i64 == SCAN_FETCH;
    let mut matched = Vec::new();
    let mut last: Option<(String, String)> = None;
    for row in rows {
        let meta = candidate_meta(row);
        last = Some((meta.accession.clone().unwrap_or_default(), meta.id.clone()));
        // Second gate behind the SQL-side scope filter: unresolvable rows
        // read as hidden, never as a call failure.
        let visible = candidate_visible(conn, cache, principal_id, &meta).await;
        if visible {
            matched.push(meta);
        }
    }
    Ok((matched, last.filter(|_| window_full)))
}
fn types_constrain(filter: Option<&[String]>) -> bool {
    filter.is_some_and(|types| !types.is_empty())
}

/// Bulk carrier type/kind labels for one page: a single indexed read for all
/// `native/v1@1` candidates instead of one field lookup each.
async fn carrier_labels(
    conn: &mut SqliteConnection,
    ids: &[String],
) -> Result<HashMap<String, (Option<String>, Option<String>)>> {
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let encoded = serde_json::to_string(ids)?;
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT record_id, name, value_json FROM kernel_record_fields
         WHERE record_id IN (SELECT value FROM json_each(?)) AND name IN ('v1_type', 'v1_kind')",
    )
    .bind(encoded)
    .fetch_all(&mut *conn)
    .await?;
    let mut labels: HashMap<String, (Option<String>, Option<String>)> = HashMap::new();
    for (id, name, value_json) in rows {
        let value: serde_json::Value = serde_json::from_str(&value_json)?;
        let text = value.as_str().map(str::to_string);
        let entry = labels.entry(id).or_insert((None, None));
        if name == "v1_type" {
            entry.0 = text;
        } else {
            entry.1 = text;
        }
    }
    Ok(labels)
}

fn candidate_matches(
    meta: &CandidateMeta,
    labels: &HashMap<String, (Option<String>, Option<String>)>,
    filter_ids: Option<&[String]>,
    filter_types: Option<&[String]>,
    filter_kinds: Option<&[String]>,
) -> bool {
    if filter_ids.is_some_and(|ids| !ids.is_empty() && !ids.contains(&meta.id)) {
        return false;
    }
    let (v1_type, v1_kind) = match labels.get(&meta.id) {
        Some((t, k)) => (t.as_deref(), k.as_deref()),
        None => (None, None),
    };
    let (record_type, kind) = candidate_type_and_kind(meta, v1_type, v1_kind);
    if types_constrain(filter_types)
        && !filter_types
            .unwrap()
            .iter()
            .any(|t| record_type == Some(t.as_str()))
    {
        return false;
    }
    if types_constrain(filter_kinds)
        && !filter_kinds
            .unwrap()
            .iter()
            .any(|k| kind == Some(k.as_str()))
    {
        return false;
    }
    true
}

/// Bounded list over the v2 kernel: indexed group scans with cached
/// visibility, exact totals, and hydration strictly for the returned window.
/// Bodies are never read; revisions resolve in one bulk query for the window.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn bounded_query_as(
    db: &Db,
    principal_id: &str,
    groups: &[(String, String)],
    filter_ids: Option<&[String]>,
    filter_types: Option<&[String]>,
    filter_kinds: Option<&[String]>,
    linked_to: Option<(&str, &str, &str)>,
    limit: usize,
    offset: usize,
    counters: &S7aCounters,
) -> Result<BoundedQueryPage> {
    let limit = limit.clamp(1, 500);
    // Read-only snapshot: this path never writes.
    let mut tx = db.pool().begin().await?;
    #[cfg(feature = "v2-kernel-probe")]
    super::app_installs::admit_dispatched_on(&mut tx, principal_id).await?;
    if let Some((_, linked_id, _)) = linked_to {
        if !linked_anchor_visible(&mut tx, principal_id, linked_id).await? {
            tx.rollback().await?;
            return Ok(BoundedQueryPage {
                total: 0,
                records: Vec::new(),
            });
        }
    }
    let cache = load_policy_cache(&mut tx, principal_id).await?;
    // SQL-side visibility via S8's shared helper: hidden rows never enter
    // the scans below, so their count cannot change answers or ordering.
    let scope = sql_scope(&visible_home_anchors_as(&mut tx, principal_id).await?)?;
    // A malformed root falls back to no root capability (owner disclosure
    // off), exactly like `list_records_as` — never a call failure.
    let root_visible = kernel_effective_capability_on(&mut tx, principal_id, KERNEL_ROOT_ID)
        .await
        .unwrap_or(Capability::None)
        .allows(Capability::View);
    let mut matched: Vec<CandidateMeta> = Vec::new();
    if let Some(ids) = filter_ids {
        if !ids.is_empty() {
            for id in ids {
                let mut sql = String::from(
                    "SELECT r.id, r.accession, r.home_id, r.owner_id, r.primary_type, r.kind, r.pin_family, r.pin_version, r.pin_digest, r.interpreter, r.created_at FROM kernel_records r WHERE r.id = ?",
                );
                sql.push_str(&scope_clause());
                if let Some((_, _, direction)) = linked_to {
                    sql.push_str(&linked_clause(direction)?);
                }
                let mut query = sqlx::query_as::<_, CandidateRow>(&sql)
                    .bind(id)
                    .bind(&scope.view_json)
                    .bind(&scope.valid_json)
                    .bind(principal_id)
                    .bind(&scope.terminal_json)
                    .bind(principal_id);
                if let Some((predicate, linked_id, direction)) = linked_to {
                    query = query.bind(linked_id);
                    if direction == "either" {
                        query = query.bind(linked_id);
                    }
                    query = query.bind(predicate);
                }
                let row = query.fetch_optional(&mut *tx).await?;
                let Some(row) = row else { continue };
                let meta = candidate_meta(row);
                if meta.pin_family.is_none() || meta.kind.is_none() {
                    // Parity with the untyped-record refusal below: a bare
                    // record an id filter can see is an error, not a skip.
                    let visible = candidate_visible(&mut tx, &cache, principal_id, &meta).await;
                    if visible {
                        return Err(Error::engine(
                            "query_record (kernel-v2): unsupported query that may match untyped records",
                        ));
                    }
                    continue;
                }
                let visible = candidate_visible(&mut tx, &cache, principal_id, &meta).await;
                if !visible {
                    continue;
                }
                matched.push(meta);
            }
            // Carrier labels for the probed set when a type/kind filter needs
            // them; point reads stay proportional to the id list.
            let carriers: Vec<String> = matched
                .iter()
                .filter(|m| is_carrier(m))
                .map(|m| m.id.clone())
                .collect();
            let labels = if (types_constrain(filter_types) || types_constrain(filter_kinds))
                && !carriers.is_empty()
            {
                counters.field_reads.fetch_add(1, Ordering::Relaxed);
                carrier_labels(&mut tx, &carriers).await?
            } else {
                HashMap::new()
            };
            matched
                .retain(|m| candidate_matches(m, &labels, filter_ids, filter_types, filter_kinds));
        }
    }
    let scan_groups = filter_ids.is_none_or(|ids| ids.is_empty());
    if scan_groups {
        // Bare records cannot be expressed by the group scans. Refuse queries
        // that could silently omit them — but only for bare records the
        // caller can see: the same scope clause as the scans, so a hidden
        // bare record can never flip a restricted caller's answer.
        if !types_constrain(filter_types) && !types_constrain(filter_kinds) {
            let bare: bool = sqlx::query_scalar(&format!(
                "SELECT EXISTS(SELECT 1 FROM kernel_records r WHERE (r.pin_family IS NULL OR r.kind IS NULL){})",
                scope_clause()
            ))
            .bind(&scope.view_json)
            .bind(&scope.valid_json)
            .bind(principal_id)
            .bind(&scope.terminal_json)
            .bind(principal_id)
            .fetch_one(&mut *tx)
            .await?;
            if bare {
                return Err(Error::engine(
                    "query_record (kernel-v2): unsupported query that may match untyped records",
                ));
            }
        }
        for (family, kind) in groups {
            let mut cursor: Option<(String, String)> = None;
            // No scan bound: hidden rows are excluded in SQL, so the walk is
            // proportional to visible rows at constant cheap work per row
            // (one amortized page read, CPU-only visibility, no fields).
            loop {
                let (mut page, next) = scan_group(
                    &mut tx,
                    &cache,
                    &scope,
                    family,
                    kind,
                    linked_to,
                    cursor,
                    principal_id,
                    counters,
                )
                .await?;
                if (types_constrain(filter_types) || types_constrain(filter_kinds))
                    && page.iter().any(is_carrier)
                {
                    let carriers: Vec<String> = page
                        .iter()
                        .filter(|m| is_carrier(m))
                        .map(|m| m.id.clone())
                        .collect();
                    counters.field_reads.fetch_add(1, Ordering::Relaxed);
                    let labels = carrier_labels(&mut tx, &carriers).await?;
                    page.retain(|m| {
                        candidate_matches(m, &labels, filter_ids, filter_types, filter_kinds)
                    });
                } else {
                    page.retain(|m| {
                        candidate_matches(
                            m,
                            &HashMap::new(),
                            filter_ids,
                            filter_types,
                            filter_kinds,
                        )
                    });
                }
                matched.extend(page);
                cursor = next;
                if cursor.is_none() {
                    break;
                }
            }
        }
    }
    matched.sort_by(|a, b| a.id.cmp(&b.id));
    let total = matched.len();
    let window: Vec<CandidateMeta> = matched.into_iter().skip(offset).take(limit).collect();
    let window_ids: Vec<String> = window.iter().map(|m| m.id.clone()).collect();
    // Hydration, strictly window-bounded: bulk fields, record metadata and
    // revisions for the whole page, with zero body reads.
    let encoded = serde_json::to_string(&window_ids)?;
    let field_rows: Vec<(String, String, String)> = if window_ids.is_empty() {
        Vec::new()
    } else {
        counters.field_reads.fetch_add(1, Ordering::Relaxed);
        sqlx::query_as(
            "SELECT record_id, name, value_json FROM kernel_record_fields
             WHERE record_id IN (SELECT value FROM json_each(?)) ORDER BY record_id, name",
        )
        .bind(encoded.clone())
        .fetch_all(&mut *tx)
        .await?
    };
    let mut fields_by_id: HashMap<String, serde_json::Map<String, serde_json::Value>> =
        HashMap::new();
    for (id, name, value_json) in field_rows {
        let value: serde_json::Value = serde_json::from_str(&value_json)?;
        fields_by_id.entry(id).or_default().insert(name, value);
    }
    let metadata_rows: Vec<(String,String,Option<String>,String)> = sqlx::query_as("SELECT record_id,persistence,maturity,last_activity_at FROM kernel_record_metadata WHERE record_id IN (SELECT value FROM json_each(?))")
        .bind(&encoded).fetch_all(&mut *tx).await?;
    let mut metadata_by_id: HashMap<String, RecordMetadata> = metadata_rows
        .into_iter()
        .map(|(id, persistence, maturity, last_activity_at)| {
            (
                id,
                RecordMetadata {
                    persistence,
                    maturity,
                    last_activity_at,
                },
            )
        })
        .collect();
    let revision_rows: Vec<(String, i64)> = if window_ids.is_empty() {
        Vec::new()
    } else {
        counters.revision_reads.fetch_add(1, Ordering::Relaxed);
        sqlx::query_as(
            "SELECT record_id, COALESCE(MAX(seq), 0) FROM content_events
             WHERE record_id IN (SELECT value FROM json_each(?)) GROUP BY record_id",
        )
        .bind(encoded)
        .fetch_all(&mut *tx)
        .await?
    };
    let revisions: HashMap<String, i64> = revision_rows.into_iter().collect();
    let mut records = Vec::new();
    for meta in window {
        let fields = fields_by_id.remove(&meta.id).unwrap_or_default();
        let pin = match (&meta.pin_family, meta.pin_version, &meta.pin_digest) {
            (Some(family), Some(version), Some(digest)) => Some(RevisionIdentity {
                family: family.clone(),
                version: u32::try_from(version).unwrap_or(0),
                digest: digest.clone(),
            }),
            _ => None,
        };
        let (record_type, kind) = candidate_type_and_kind(
            &meta,
            fields.get("v1_type").and_then(|v| v.as_str()),
            fields.get("v1_kind").and_then(|v| v.as_str()),
        );
        let owner_id = match &meta.owner_id {
            Some(owner) if owner == principal_id || root_visible => Some(owner.clone()),
            _ => None,
        };
        let revision = revisions.get(&meta.id).copied().unwrap_or(0);
        records.push(BoundedRecord {
            metadata: metadata_by_id
                .remove(&meta.id)
                .ok_or_else(|| Error::engine("record metadata projection missing"))?,
            id: meta.id.clone(),
            home_id: meta.home_id.clone(),
            owner_id,
            primary_type: record_type.map(str::to_string),
            kind: kind.map(str::to_string),
            family: meta.pin_family,
            pin,
            interpreter: meta.interpreter,
            created_at: meta.created_at,
            revision,
            fields,
        });
    }
    tx.rollback().await?;
    Ok(BoundedQueryPage { total, records })
}
/// One search hit: v1-shaped, corpus-independent score, short snippet.
#[derive(Debug, Clone)]
pub(crate) struct SearchHitV2 {
    pub id: String,
    pub record_type: Option<String>,
    pub kind: Option<String>,
    pub name: String,
    pub home_id: String,
    pub score: f64,
    pub snippet: String,
}

/// Split free text into FTS5-safe quoted terms, mirroring `query::fts`:
/// embedded quotes are doubled, so FTS5 syntax in user input cannot error or
/// subvert the search. Returns `None` when no token survives.
fn quoted_terms(input: &str) -> Option<String> {
    let terms: Vec<String> = input
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{}\"", t.replace('"', "\"\"")))
        .collect();
    if terms.is_empty() {
        None
    } else {
        Some(terms.join(" "))
    }
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let kept: String = text.chars().take(max).collect();
    format!("{kept}…")
}

/// Token set of one column under the same splitting the FTS index applies
/// (case folded). Tiering is a ranking heuristic only: inclusion is decided
/// by the FTS match, so tokenizer divergence can only misrank, never
/// misinclude.
fn column_token_set(text: &str) -> HashSet<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect()
}

/// Tier for one visible candidate: every query term in the title (0), else
/// every term in the summary (1), else body or cross-field (2).
fn tier_for(title: &str, summary: &str, tokens: &[String]) -> usize {
    let title_tokens = column_token_set(title);
    if tokens.iter().all(|t| title_tokens.contains(t)) {
        return 0;
    }
    let summary_tokens = column_token_set(summary);
    if tokens.iter().all(|t| summary_tokens.contains(t)) {
        return 1;
    }
    2
}

/// One hit with its tier-column snippet. Body-tier snippets resolve later
/// through FTS for emitted hits only; the placeholder carries the name.
fn search_hit(
    id: &str,
    title: &str,
    summary: &str,
    meta: &CandidateMeta,
    v1: (Option<&str>, Option<&str>),
    tier: usize,
) -> SearchHitV2 {
    let (record_type, kind) = candidate_type_and_kind(meta, v1.0, v1.1);
    let snippet = match tier {
        0 => truncate_chars(title, 200),
        1 => truncate_chars(summary, 200),
        _ => truncate_chars(title, 200),
    };
    SearchHitV2 {
        id: id.to_string(),
        record_type: record_type.map(str::to_string),
        kind: kind.map(str::to_string),
        name: truncate_chars(title, 200),
        home_id: meta.home_id.clone(),
        score: tier as f64,
        snippet,
    }
}
const SEARCH_WINDOW: i64 = 100;
const SEARCH_SCAN_BOUND: usize = 5000;
const SEARCH_MAX_LIMIT: i64 = 200;

/// Tiered full-text search over title, summary and body, with v1's match
/// semantics: every quoted term must occur somewhere in the document (terms
/// ANDed over the whole FTS row, never per column). Ranking is tiered in
/// Rust — every term in the title first, then summary, then body — and never
/// consults BM25/IDF, so hidden rows cannot move a visible hit.
///
/// Hidden rows are excluded in SQL by the shared visible-home scope, so the
/// scan, its backstop and its ordering never observe them. Ordering and
/// scores are computed over visible rows only and cannot leak hidden content.
pub(crate) async fn search_as(
    db: &Db,
    principal_id: &str,
    query: &str,
    limit: i64,
    include_archived: bool,
) -> Result<(Vec<SearchHitV2>, bool)> {
    search_scoped_as(db, principal_id, query, limit, include_archived, None).await
}

pub(crate) async fn search_scoped_as(
    db: &Db,
    principal_id: &str,
    query: &str,
    limit: i64,
    include_archived: bool,
    allowed_ids: Option<&[String]>,
) -> Result<(Vec<SearchHitV2>, bool)> {
    let allowed_ids = allowed_ids.map(serde_json::to_string).transpose()?;
    let limit = limit.clamp(1, SEARCH_MAX_LIMIT);
    // Unscoped, like v1: "alpha beta" matches alpha-in-title plus
    // beta-in-body. Tiering below recovers the ranking.
    let Some(terms) = quoted_terms(query) else {
        return Ok((Vec::new(), false));
    };
    let tokens: Vec<String> = query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect();
    // Read-only snapshot: this path never writes.
    let mut tx = db.pool().begin().await?;
    #[cfg(feature = "v2-kernel-probe")]
    super::app_installs::admit_dispatched_on(&mut tx, principal_id).await?;
    let cache = load_policy_cache(&mut tx, principal_id).await?;
    let scope = sql_scope(&visible_home_anchors_as(&mut tx, principal_id).await?)?;
    let mut buckets: [Vec<SearchHitV2>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    let mut scanned = 0usize;
    let mut truncated = false;
    let mut offset = 0i64;
    loop {
        let mut sql = String::from(
            "SELECT f.record_id, f.title, f.summary FROM kernel_search_fts f
             JOIN kernel_records r ON r.id = f.record_id
             WHERE kernel_search_fts MATCH ?",
        );
        sql.push_str(&scope_clause());
        // Restrict before the scan backstop and ranking/page limits: an
        // out-of-scope hit must never displace an in-scope result.
        sql.push_str(" AND (? IS NULL OR r.id IN (SELECT value FROM json_each(?)))");
        sql.push_str(" ORDER BY f.record_id LIMIT ? OFFSET ?");
        let rows: Vec<(String, String, String)> = sqlx::query_as(&sql)
            .bind(&terms)
            .bind(&scope.view_json)
            .bind(&scope.valid_json)
            .bind(principal_id)
            .bind(&scope.terminal_json)
            .bind(principal_id)
            .bind(&allowed_ids)
            .bind(&allowed_ids)
            .bind(SEARCH_WINDOW)
            .bind(offset)
            .fetch_all(&mut *tx)
            .await?;
        let window_full = rows.len() as i64 == SEARCH_WINDOW;
        // Carrier candidates defer their v1 labels to one bulk read below.
        let mut pending: Vec<(String, String, String, CandidateMeta)> = Vec::new();
        for (id, title, summary) in rows {
            scanned += 1;
            if scanned > SEARCH_SCAN_BOUND {
                // Backstop only: hidden rows never reach it (SQL filter), so
                // truncation cannot leak them; the page reports limit_reached.
                truncated = true;
                break;
            }
            let meta: Option<CandidateRow> = sqlx::query_as(
                "SELECT id, accession, home_id, owner_id, primary_type, kind, pin_family, pin_version, pin_digest, interpreter, created_at
                 FROM kernel_records WHERE id = ?",
            )
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await?;
            let Some(meta) = meta.map(candidate_meta) else {
                continue;
            };
            let visible = candidate_visible(&mut tx, &cache, principal_id, &meta).await;
            if !visible {
                continue;
            }
            if !include_archived {
                let archived: Option<i64> =
                    sqlx::query_scalar("SELECT archived FROM kernel_lifecycle WHERE record_id = ?")
                        .bind(&id)
                        .fetch_optional(&mut *tx)
                        .await?;
                if archived == Some(1) {
                    continue;
                }
            }
            if is_carrier(&meta) {
                pending.push((id, title, summary, meta));
                continue;
            }
            let tier = tier_for(&title, &summary, &tokens);
            buckets[tier].push(search_hit(&id, &title, &summary, &meta, (None, None), tier));
        }
        // One bulk label read for the window's carriers.
        let carrier_ids: Vec<String> = pending.iter().map(|(id, _, _, _)| id.clone()).collect();
        let labels = carrier_labels(&mut tx, &carrier_ids).await?;
        for (id, title, summary, meta) in &pending {
            let (t, k) = match labels.get(id) {
                Some((t, k)) => (t.as_deref(), k.as_deref()),
                None => (None, None),
            };
            let tier = tier_for(title, summary, &tokens);
            buckets[tier].push(search_hit(id, title, summary, meta, (t, k), tier));
        }
        // The best tier fills the page on its own: later rows are
        // same-or-worse tiers at higher ids and cannot displace it.
        if buckets[0].len() as i64 >= limit || truncated || !window_full {
            break;
        }
        offset += SEARCH_WINDOW;
    }
    let mut hits: Vec<SearchHitV2> = buckets.into_iter().flatten().take(limit as usize).collect();
    // Body-tier snippets resolve through FTS for emitted hits only — bodies
    // stay out of the candidate scan entirely.
    if hits.iter().any(|hit| hit.score == 2.0) {
        let body_pattern = format!("{{body}} : {terms}");
        for hit in hits.iter_mut().filter(|hit| hit.score == 2.0) {
            let snippet: Option<String> = sqlx::query_scalar(
                "SELECT snippet(kernel_search_fts, 3, '', '', '', 24) FROM kernel_search_fts
                 WHERE record_id = ? AND kernel_search_fts MATCH ?",
            )
            .bind(&hit.id)
            .bind(&body_pattern)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
            hit.snippet = truncate_chars(
                snippet
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .unwrap_or(&hit.name),
                200,
            );
        }
    }
    tx.rollback().await?;
    Ok((hits, truncated))
}
/// Indexed short-id prefix resolution over kernel records. Exact identity
/// wins (including a hidden exact id, just as on v1 — never redirect it to a
/// visible neighbour); otherwise a bounded primary-key range scan feeds the
/// same View gate the tools apply, and 0/1/many visible candidates resolve
/// exactly like v1's rule 3. Replaces the `list_records_as` load-everything
/// scan this path used before.
pub(crate) async fn resolve_prefix_as(
    db: &Db,
    principal_id: &str,
    tool: &str,
    input: &str,
    prefix: &str,
) -> Result<Option<String>> {
    let exact: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id = ?)")
            .bind(input)
            .fetch_one(db.pool())
            .await?;
    if exact {
        return Ok(None);
    }
    // Half-open range on the TEXT PRIMARY KEY, the same technique as v1's
    // prefix scan: `g` sorts after every character a canonical hex UUID tail
    // can hold (`-`, `0`-`9`, `a`-`f`), so the bound is tight for the
    // UUID-shaped ids prefix matching admits.
    let upper = format!("{prefix}g");
    let mut snapshot = db.pool().begin().await?;
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM kernel_records WHERE id >= ? AND id < ? ORDER BY id LIMIT 33",
    )
    .bind(prefix)
    .bind(&upper)
    .fetch_all(&mut *snapshot)
    .await?;
    let mut visible = Vec::new();
    for id in rows {
        if uuid::Uuid::parse_str(&id).is_err() || !id.starts_with(prefix) {
            continue;
        }
        let capable = kernel_effective_capability_on(&mut snapshot, principal_id, &id)
            .await?
            .allows(Capability::View);
        if capable {
            visible.push(id);
        }
    }
    snapshot.rollback().await?;
    match visible.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some(id.clone())),
        _ => Err(Error::engine(format!(
            "{tool}: ambiguous record reference '{input}'; use a longer prefix"
        ))),
    }
}
