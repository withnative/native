//! Ordinary record reads through the kernel's caller-filtered SQL relations.
use super::*;

// Retain the complete relation as a test oracle for the closed small reads.
#[cfg(test)]
tokio::task_local! { static FULL_SMALL_READ_STAGING: bool; }

#[cfg(test)]
pub(super) async fn with_full_small_read_staging<T>(
    work: impl std::future::Future<Output = T>,
) -> T {
    FULL_SMALL_READ_STAGING.scope(true, work).await
}

fn full_small_read_staging() -> bool {
    #[cfg(test)]
    if let Ok(full) = FULL_SMALL_READ_STAGING.try_with(|full| *full) {
        return full;
    }
    false
}

async fn rows(db: &Db, actor: &str, statement: &str, parameters: Vec<Value>) -> Result<Vec<Value>> {
    let result =
        sql::query_sql(db, actor, json!({"sql":statement,"parameters":parameters})).await?;
    if result["truncated"] == true {
        return Err(Error::engine("record read exceeds the SQL result bound"));
    }
    result["rows"]
        .as_array()
        .cloned()
        .ok_or_else(|| Error::engine("record read: invalid SQL rows"))
}
fn text(value: impl Into<String>) -> Value {
    json!({"type":"text","value":value.into()})
}
fn ordinary() -> String {
    super::native_query_hidden_predicate("r", &[])
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveArgs {
    names: Vec<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    kind: Option<String>,
    include_archived: Option<bool>,
}

pub(super) async fn resolve_many(db: &Db, actor: &str, args: Value) -> Result<Value> {
    kernel::read_cache::with_capabilities(resolve_many_read(db, actor, args)).await
}

async fn resolve_many_read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: ResolveArgs = parse("resolve_many", args)?;
    if args.names.is_empty() || args.names.len() > 100 {
        return Err(Error::engine(
            "resolve_many: requires between 1 and 100 names",
        ));
    }
    if args
        .names
        .iter()
        .any(|name| name.is_empty() || name.chars().count() > 512)
    {
        return Err(Error::engine(
            "resolve_many: names must contain between 1 and 512 characters",
        ));
    }
    if args
        .record_type
        .as_deref()
        .is_some_and(|typ| !crate::schema::SPINE_TYPES.contains(&typ))
    {
        return Err(Error::engine(format!(
            "resolve_many: unknown record type {}",
            args.record_type.as_deref().unwrap_or_default()
        )));
    }
    if args.kind.as_deref() == Some("") {
        return Err(Error::engine("resolve_many: kind must not be empty"));
    }
    // Filtering, ordering and grouping all happen AFTER the kernel View gate.
    // A hidden duplicate cannot turn a visible singleton into ambiguity.
    let statement = "SELECT r.id,r.name,r.type,r.kind FROM records r WHERE NOT (r.type='Annotation' AND r.kind IS 'attribution') AND r.name COLLATE BINARY IN (SELECT value FROM json_each(?1)) AND (?2 IS NULL OR r.type=?2) AND (?3 IS NULL OR r.kind=?3) AND (?4=1 OR r.archived=0) ORDER BY r.name COLLATE BINARY,r.id";
    let names = serde_json::to_string(&args.names)?;
    let typ = args.record_type.clone();
    let kind = args.kind.clone();
    let archived = args.include_archived.unwrap_or(false);
    let reads = &[
        ("records", "id"),
        ("records", "name"),
        ("records", "type"),
        ("records", "kind"),
        ("records", "archived"),
    ];
    let work = sql::in_snapshot(db, actor, move |conn| {
        Box::pin(async move {
            use sqlx::Row;
            sqlx::query(statement).bind(names).bind(typ).bind(kind).bind(archived)
            .fetch_all(conn).await?.into_iter().map(|row| Ok(json!({
                "id":row.try_get::<String,_>("id")?,"name":row.try_get::<String,_>("name")?,
                "type":row.try_get::<String,_>("type")?,"kind":row.try_get::<Option<String>,_>("kind")?,
            }))).collect::<Result<Vec<_>>>()
        })
    });
    let matches = if full_small_read_staging() {
        sql::with_read_session(db, actor, reads, work).await?
    } else {
        sql::with_name_read_session(db, actor, reads, &args.names, work).await?
    };
    let mut counts = [0; 3];
    let results = args.names.iter().enumerate().map(|(index,input)| {
        let found: Vec<_> = matches.iter().filter(|row| row["name"] == *input).map(|row| {
            let mut row = row.clone();
            if row["kind"].is_null() { row.as_object_mut().unwrap().remove("kind"); }
            row
        }).collect();
        match found.len() {
            0 => { counts[0]+=1; json!({"index":index,"input":input,"status":"not_found"}) },
            1 => { counts[1]+=1; json!({"index":index,"input":input,"status":"resolved","match":found[0]}) },
            n => { counts[2]+=1; json!({"index":index,"input":input,"status":"ambiguous","match_count":n,"matches":found}) },
        }
    }).collect::<Vec<_>>();
    Ok(
        json!({"results":results,"counts":{"not_found":counts[0],"resolved":counts[1],"ambiguous":counts[2],"not_held":0},"type":args.record_type,"kind":args.kind,"include_archived":args.include_archived.unwrap_or(false),"match":"exact"}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RenderArgs {
    id: String,
    include_interpretation: Option<bool>,
}
fn string(row: &Value, key: &str) -> String {
    row[key].as_str().unwrap_or_default().to_owned()
}
fn optional(row: &Value, key: &str) -> Option<String> {
    row[key].as_str().map(str::to_owned)
}

pub(super) async fn render_record(db: &Db, actor: &str, args: Value) -> Result<Value> {
    kernel::read_cache::with_capabilities(render_record_read(db, actor, args)).await
}

async fn render_record_read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: RenderArgs = parse("render_record", args)?;
    if args.include_interpretation.unwrap_or(false) {
        return Err(unsupported("render_record", "interpretation projection"));
    }
    let reads = &[
        ("records", "id"),
        ("records", "type"),
        ("records", "kind"),
        ("records", "name"),
        ("records", "archived"),
        ("records", "created_at"),
        ("records", "home_id"),
        ("links", "source_id"),
        ("links", "target_id"),
        ("links", "relationship"),
        ("links", "created_at"),
    ];
    if full_small_read_staging() {
        sql::with_read_session(db, actor, reads, render_in_session(db, actor, args)).await
    } else {
        let ids = [args.id.clone()];
        sql::with_part_of_read_session(db, actor, reads, &ids, render_in_session(db, actor, args))
            .await
    }
}

async fn render_in_session(db: &Db, actor: &str, args: RenderArgs) -> Result<Value> {
    // Reuse Get's complete visibility and enrichment path in the same pinned
    // session as the authorized endpoint metadata and successor count.
    let plan = super::get_plan(json!({"ids":[args.id]}))?;
    let response = super::get_record_from_plan(db, actor, plan).await?;
    let value = &response["records"][0];
    if value["status"] != "found" {
        return Err(Error::engine(format!(
            "render_record: record {} does not exist",
            args.id
        )));
    }
    let mut enriched = render_enrichment(value);
    enriched.superseded_by = if full_small_read_staging() {
        successors(db, actor, std::slice::from_ref(&args.id))
            .await?
            .remove(&args.id)
    } else {
        let actor_owned = actor.to_owned();
        let id = args.id.clone();
        sql::in_snapshot(db, actor, move |conn| {
            Box::pin(async move { render_successors_on(conn, &actor_owned, &id).await })
        })
        .await?
    };
    let ids = enriched
        .links_out
        .iter()
        .map(|link| link.target_id.clone())
        .chain(enriched.links_in.iter().map(|link| link.source_id.clone()))
        .collect::<std::collections::BTreeSet<_>>();
    let names = if full_small_read_staging() {
        rows(
            db,
            actor,
            "SELECT id,name FROM records WHERE id IN (SELECT value FROM json_each(?1))",
            vec![text(serde_json::to_string(&ids)?)],
        )
        .await?
        .into_iter()
        .map(|v| (string(&v, "id"), string(&v, "name")))
        .collect()
    } else {
        let actor_owned = actor.to_owned();
        sql::in_snapshot(db, actor, move |conn| {
            Box::pin(async move {
                let mut names = std::collections::HashMap::new();
                for id in ids {
                    if let Some(name) = visible_name_on(conn, &actor_owned, &id).await? {
                        names.insert(id, name);
                    }
                }
                Ok(names)
            })
        })
        .await?
    };
    let mut markdown =
        crate::mcp::tools::lifecycle::render_enriched_record_markdown(&enriched, &names);
    let speaker = value.get("speaker").filter(|v| !v.is_null());
    if let Some(speaker) = speaker {
        markdown.push_str(&format!(
            "\nSpeaker: {} ({})\n",
            speaker["display_name"].as_str().unwrap_or("Persona"),
            speaker["assurance"].as_str().unwrap_or("client_asserted")
        ));
    }
    let mut output = json!({"id":args.id,"markdown":markdown});
    if let Some(speaker) = speaker {
        output["speaker"] = speaker.clone();
    }
    Ok(output)
}

/// A closed name-only read after the kernel's complete record authority gate.
/// The existence probe also excludes non-record principal link targets. Keep
/// SQL's title/name precedence without hydrating endpoint bodies or metadata.
async fn visible_name_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<Option<String>> {
    kernel::app_installs::admit_dispatched_on(conn, actor).await?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_records WHERE id=?)")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    if !exists
        || !kernel::kernel_effective_capability_on(conn, actor, id)
            .await?
            .allows(crate::authorization::Capability::View)
    {
        return Ok(None);
    }
    // rows() represents non-text names as non-string JSON; string() renders
    // those as empty strings. Preserve that behavior for retained fields too.
    let name = sqlx::query_scalar("SELECT CASE WHEN typeof(name)='text' THEN name ELSE '' END FROM (SELECT coalesce((SELECT json_extract(value_json,'$') FROM main.kernel_record_fields WHERE record_id=?1 AND name='title'),(SELECT json_extract(value_json,'$') FROM main.kernel_record_fields WHERE record_id=?1 AND name='name'),'') AS name)")
        .bind(id).fetch_one(&mut *conn).await?;
    Ok(Some(name))
}

/// Render's SQL session only needs part_of for Get. Read every supersedes
/// source on that same connection so totals do not depend on Get's link page.
/// Preserve the SQL relation's UNION ALL provenance and normalized clock order.
pub(super) async fn render_successors_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<Option<crate::query::read::SupersededBy>> {
    use crate::query::read::{SupersededBy, SupersededByItem};
    if visible_name_on(conn, actor, id).await?.is_none() {
        return Ok(None);
    }
    let sources: Vec<String> = sqlx::query_scalar("SELECT source_id FROM temp._v2_link_sources WHERE relationship='supersedes' AND target_id=? ORDER BY strftime('%Y-%m-%dT%H:%M:%fZ',created_at),source_id")
        .bind(id).fetch_all(&mut *conn).await?;
    let mut result = SupersededBy {
        items: Vec::new(),
        total_count: 0,
    };
    for source in sources {
        if let Some(name) = visible_name_on(conn, actor, &source).await? {
            result.total_count += 1;
            if result.items.len() < 3 {
                let display_reference = writes::short_reference(conn, &source).await?;
                result.items.push(SupersededByItem {
                    id: source,
                    name,
                    display_reference,
                });
            }
        }
    }
    Ok((result.total_count > 0).then_some(result))
}

// Keep the renderer's counts on the same authorized projection as Get.
pub(super) fn render_enrichment(value: &Value) -> crate::query::read::EnrichedRecord {
    use crate::query::{read, tree, FacetValueRow, LinkRow, RecordRow};
    let links = |key: &str| -> Vec<read::EnrichedLink> {
        value[key]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| {
                LinkRow {
                    id: string(v, "id"),
                    source_id: string(v, "source_id"),
                    target_id: string(v, "target_id"),
                    relationship: string(v, "relationship"),
                    note: optional(v, "note"),
                    created_at: string(v, "created_at"),
                }
                .into()
            })
            .collect()
    };
    read::EnrichedRecord {
        record: RecordRow {
            id: string(value, "id"),
            record_type: string(value, "type"),
            kind: optional(value, "kind"),
            name: string(value, "name"),
            body: optional(value, "body"),
            home_id: optional(value, "home_id"),
            lifecycle: optional(value, "lifecycle"),
            // Markdown renders the physical lifecycle token, not this
            // structured projection (which has no Deserialize contract).
            lifecycle_interpretation: crate::query::lifecycle::LifecycleInterpretation::Absent(
                crate::query::lifecycle::AbsentLifecycleInterpretation {
                    axis: None,
                    vocabulary: None,
                },
            ),
            owner_id: optional(value, "owner_id"),
            persistence: string(value, "persistence"),
            maturity: optional(value, "maturity"),
            summary: optional(value, "summary"),
            last_activity_at: optional(value, "last_activity_at"),
            created_at: string(value, "created_at"),
            updated_at: string(value, "updated_at"),
            deleted_at: optional(value, "deleted_at"),
            communication_origin: value.get("communication_origin").cloned(),
            federation_provenance: None,
        },
        archived: value["archived"] == true,
        custody_boundary: value["custody_boundary"] == true,
        containment_path_visible: value["containment_path_visible"] == true,
        bears_shape: value["bears_shape"] == true,
        kind_governance: None,
        facets: value["facets"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| FacetValueRow {
                key: string(v, "key"),
                value: v.get("value").filter(|v| !v.is_null()).cloned(),
                vocab_ref: optional(v, "vocab_ref"),
                version: optional(v, "version"),
            })
            .collect(),
        links_out: links("links_out"),
        links_out_count: value["links_out_count"].as_i64().unwrap_or(0),
        links_in: links("links_in"),
        links_in_count: value["links_in_count"].as_i64().unwrap_or(0),
        mentions_out: None,
        mentions_out_count: None,
        mentions_in: None,
        mentions_in_count: None,
        superseded_by: None,
        children: value["children"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| read::ChildSummary {
                id: string(v, "id"),
                record_type: string(v, "type"),
                kind: optional(v, "kind"),
                name: string(v, "name"),
                archived: v["archived"] == true,
            })
            .collect(),
        child_count: value["child_count"].as_i64().unwrap_or(0),
        suggestions: None,
        suggestion_count: value["suggestion_count"].as_i64().unwrap_or(0),
        citations: None,
        citation_count: value["citation_count"].as_i64().unwrap_or(0),
        comments: None,
        comment_count: value["comment_count"].as_i64().unwrap_or(0),
        target: None,
        contribution: None,
        history_summary: None,
        ancestors: value["ancestors"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| tree::AncestorEntry {
                id: string(v, "id"),
                record_type: string(v, "type"),
                kind: optional(v, "kind"),
                name: string(v, "name"),
            })
            .collect(),
        freshness: None,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DashboardArgs {
    scope: Option<String>,
    stale_after_days: Option<i64>,
    limit: Option<usize>,
}

pub(super) async fn get_dashboard(db: &Db, actor: &str, args: Value) -> Result<Value> {
    kernel::read_cache::with_capabilities(get_dashboard_read(db, actor, args)).await
}

async fn get_dashboard_read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: DashboardArgs = parse("get_dashboard", args)?;
    let days = args.stale_after_days.unwrap_or(14);
    let limit = args.limit.unwrap_or(20);
    if !(1..=36_500).contains(&days) || !(1..=100).contains(&limit) {
        return Err(Error::engine(
            "get_dashboard: stale_after_days must be 1..36500 and limit 1..100",
        ));
    }
    sql::with_read_session(
        db,
        actor,
        &[
            ("records", "id"),
            ("records", "type"),
            ("records", "kind"),
            ("records", "name"),
            ("records", "home_id"),
            ("records", "lifecycle"),
            ("records", "maturity"),
            ("records", "last_activity_at"),
            ("records", "archived"),
            ("links", "source_id"),
            ("links", "target_id"),
            ("links", "relationship"),
            ("links", "created_at"),
        ],
        dashboard_in_session(db, actor, args, days, limit),
    )
    .await
}

const DASHBOARD_CANDIDATE_LIMIT: usize = 10_000;
#[cfg(test)]
tokio::task_local! { pub(super) static TEST_DASHBOARD_CANDIDATE_LIMIT: usize; }
fn dashboard_candidate_limit() -> usize {
    #[cfg(test)]
    if let Ok(limit) = TEST_DASHBOARD_CANDIDATE_LIMIT.try_with(|limit| *limit) {
        return limit;
    }
    DASHBOARD_CANDIDATE_LIMIT
}

async fn dashboard_in_session(
    db: &Db,
    actor: &str,
    args: DashboardArgs,
    days: i64,
    limit: usize,
) -> Result<Value> {
    // Census covers the scoped visible corpus. The refusal bounds only actual
    // attention/blocked candidates, never unrelated or lifecycle-less records.
    let candidate_limit = dashboard_candidate_limit();
    let actor_owned = actor.to_owned();
    let scope = args.scope.clone();
    let (records, edges, buckets) = sql::in_snapshot(db, actor, move |conn| Box::pin(async move {
        use sqlx::Row;
        if let Some(root) = &scope {
            let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM temp.records WHERE id=? AND archived=0)")
                .bind(root).fetch_one(&mut *conn).await?;
            if !exists { return Err(Error::engine("get_dashboard: scope record does not exist")); }
        }
        // Deliberately traverse visible homes only: hidden intermediates cannot
        // disclose the existence of a containment path.
        let scoped = format!("WITH RECURSIVE subtree(id) AS (SELECT id FROM temp.records WHERE id=?1 AND archived=0 UNION SELECT r.id FROM temp.records r JOIN subtree s ON r.home_id=s.id WHERE r.archived=0), scoped AS (SELECT r.id,r.type,r.kind,r.name,r.lifecycle,r.maturity,r.last_activity_at FROM temp.records r WHERE r.archived=0 AND {} AND (?1 IS NULL OR r.id IN (SELECT id FROM subtree)))", ordinary());
        let census_sql = format!("{scoped} SELECT lifecycle,count(*) AS count FROM scoped GROUP BY lifecycle ORDER BY count DESC,lifecycle");
        let buckets = sqlx::query(&census_sql).bind(&scope).fetch_all(&mut *conn).await?
            .into_iter().map(|r| Ok((r.try_get::<Option<String>,_>("lifecycle")?, r.try_get::<i64,_>("count")?))).collect::<Result<Vec<_>>>()?;
        // Both endpoints have already passed View. Blockers need not be in the
        // requested home subtree, but hidden/archived blockers never qualify.
        let visible_edges = format!("SELECT l.source_id,l.target_id,l.relationship,l.created_at FROM temp.links l JOIN temp.records s ON s.id=l.source_id JOIN temp.records t ON t.id=l.target_id WHERE s.archived=0 AND t.archived=0 AND {} AND {} AND l.relationship IN ('blocks','depends_on')",super::native_query_hidden_predicate("s", &[]),super::native_query_hidden_predicate("t", &[]));
        let candidates = format!("{scoped}, edges AS ({visible_edges}) SELECT r.*,k.home_id AS policy_home FROM scoped r JOIN main.kernel_records k ON k.id=r.id WHERE r.lifecycle IS NOT NULL OR EXISTS(SELECT 1 FROM edges e WHERE (e.relationship='blocks' AND e.target_id=r.id) OR (e.relationship='depends_on' AND e.source_id=r.id)) ORDER BY r.last_activity_at DESC,r.id LIMIT ?2");
        let rows = sqlx::query(&candidates).bind(&scope).bind((candidate_limit+1) as i64).fetch_all(&mut *conn).await?;
        if rows.len() > candidate_limit { return Err(Error::engine(format!("get_dashboard: visible candidate set exceeds {candidate_limit} records"))); }
        let ids = rows.iter().map(|r| r.try_get::<String,_>("id")).collect::<std::result::Result<Vec<_>,_>>()?;
        let edge_statement = format!("WITH edges AS ({visible_edges}) SELECT * FROM edges WHERE (relationship='blocks' AND target_id IN (SELECT value FROM json_each(?1))) OR (relationship='depends_on' AND source_id IN (SELECT value FROM json_each(?1))) ORDER BY created_at,source_id,target_id");
        let edges = sqlx::query(&edge_statement).bind(serde_json::to_string(&ids)?)
            .fetch_all(&mut *conn).await?.into_iter().map(|r| Ok((r.try_get::<String,_>("source_id")?,r.try_get::<String,_>("target_id")?,r.try_get::<String,_>("relationship")?))).collect::<Result<Vec<_>>>()?;
        let blocked_ids = edges.iter().map(|(source,target,rel)| if rel == "blocks" { target.as_str() } else { source.as_str() }).collect::<std::collections::HashSet<_>>();
        let mut records = Vec::new();
        let mut blocked_seen = 0;
        // Staging has already admitted these rows through View in this pinned
        // snapshot, including app admission. Repeating kernel_require for each
        // candidate cannot add authority. Keep semantic inputs local to this
        // callback: physical homes (not public logical placement), the same
        // caller-filtered interpreter, and the scalar self-bearer exception.
        let mut interpreter = None;
        let mut bearers = std::collections::BTreeMap::new();
        let mut interpretations = std::collections::BTreeMap::new();
        for row in rows {
            let id: String = row.try_get("id")?;
            let typ: String = row.try_get("type")?;
            let kind: Option<String> = row.try_get("kind")?;
            let lifecycle: Option<String> = row.try_get("lifecycle")?;
            let blocked = blocked_ids.contains(id.as_str());
            if blocked { blocked_seen += 1; }
            // All lifecycle-bearing candidates need classification for exact
            // totals. Lifecycle-less blocked rows need interpretation only if
            // they will be emitted in the limited blocked page.
            let interpretation = if lifecycle.is_some() || (blocked && blocked_seen <= limit) {
                if interpreter.is_none() {
                    interpreter = Some(kernel::v1_state::interpreter_on(conn, &actor_owned).await?);
                }
                let home: String = row.try_get("policy_home")?;
                let entry = match bearers.entry(home) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        let bearer = kernel::v1_state::lifecycle_bearer_on(conn, entry.key(), None).await?;
                        entry.insert(bearer)
                    }
                    std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
                };
                let bearer = if *entry == id {
                    let home: String = row.try_get("policy_home")?;
                    kernel::v1_state::lifecycle_bearer_on(conn, &home, Some(&id)).await?
                } else {
                    entry.clone()
                };
                let key = (typ.clone(), kind.clone(), lifecycle.clone(), bearer);
                if let Some(value) = interpretations.get(&key) {
                    Value::clone(value)
                } else {
                    let value = serde_json::to_value(interpreter.as_ref().unwrap().interpret(
                        &typ, kind.as_deref(), Some(&key.3), lifecycle.as_deref(),
                    ))?;
                    interpretations.insert(key, value.clone());
                    value
                }
            } else { Value::Null };
            records.push(json!({"id":id,"type":typ,"kind":kind,"name":row.try_get::<String,_>("name")?,
                "lifecycle_interpretation":interpretation,"maturity":row.try_get::<Option<String>,_>("maturity")?,
                "last_activity_at":row.try_get::<Option<String>,_>("last_activity_at")?,"raw_lifecycle":lifecycle}));
        }
        Ok((records,edges,buckets))
    })).await?;
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(days))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let mut active = Vec::new();
    let mut stale = Vec::new();
    let mut blocked = Vec::new();
    let mut unclassified = Vec::new();
    let mut blocks = std::collections::BTreeMap::<String, (Vec<Value>, Vec<Value>)>::new();
    for (source, target, relationship) in edges {
        if relationship == "blocks" {
            blocks
                .entry(target)
                .or_default()
                .0
                .push(json!({"id":source,"relationship":"blocks"}));
        } else {
            blocks
                .entry(source)
                .or_default()
                .1
                .push(json!({"id":target,"relationship":"depends_on"}));
        }
    }
    for mut entry in records {
        let raw = entry
            .as_object_mut()
            .unwrap()
            .remove("raw_lifecycle")
            .unwrap();
        let id = string(&entry, "id");
        if let Some((blocked_by, waiting_on)) = blocks.get(&id) {
            let mut blocked_entry = entry.clone();
            blocked_entry["blocked_by"] = json!(blocked_by);
            blocked_entry["waiting_on"] = json!(waiting_on);
            blocked.push(blocked_entry);
        }
        if raw.is_null() {
            continue;
        }
        let interpretation = &entry["lifecycle_interpretation"];
        if interpretation["status"] == "governed" && interpretation["terminality"] != "open" {
            continue;
        }
        if interpretation["status"] == "unclassified" {
            let mut gap = entry.clone();
            gap["reason"] = interpretation["reason"].clone();
            unclassified.push(gap);
        }
        if entry["last_activity_at"]
            .as_str()
            .is_some_and(|at| at >= cutoff.as_str())
        {
            active.push(entry);
        } else {
            stale.push(entry);
        }
    }
    stale.reverse();
    let (active_total, stale_total, blocked_total, gap_total) =
        (active.len(), stale.len(), blocked.len(), unclassified.len());
    for bucket in [&mut active, &mut stale, &mut blocked, &mut unclassified] {
        bucket.truncate(limit);
    }
    let ids = active
        .iter()
        .chain(&stale)
        .chain(&blocked)
        .map(|v| string(v, "id"))
        .collect::<Vec<_>>();
    let successors = successors(db, actor, &ids).await?;
    for bucket in [&mut active, &mut stale, &mut blocked] {
        for entry in bucket {
            if let Some(successor) = successors.get(&string(entry, "id")) {
                entry["superseded_by"] = serde_json::to_value(successor)?;
            }
        }
    }
    Ok(
        json!({"scope":args.scope,"stale_after_days":days,"stale_cutoff":cutoff,"limit":limit,
        "active":active,"active_total":active_total,"stale":stale,"stale_total":stale_total,
        "blocked":blocked,"blocked_total":blocked_total,
        "unclassified_lifecycle":{"note":crate::mcp::tools::orientation::UNCLASSIFIED_LIFECYCLE_NOTE,"items":unclassified,"total_count":gap_total,"truncated":gap_total>limit},
        "lifecycle_census":{"shape":"counts","total":buckets.iter().map(|b| b.1).sum::<i64>(),"buckets":buckets.into_iter().map(|(key,count)| json!({"key":key,"count":count})).collect::<Vec<_>>()}}),
    )
}

/// Scope before counting: even successor totals disclose only Viewable rows.
pub(super) async fn successors(
    db: &Db,
    actor: &str,
    ids: &[String],
) -> Result<std::collections::BTreeMap<String, crate::query::read::SupersededBy>> {
    use crate::query::read::{SupersededBy, SupersededByItem};
    let mut result = std::collections::BTreeMap::<String, SupersededBy>::new();
    let ids = ids
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    for chunk in ids.chunks(200) {
        let page = rows(db, actor, "WITH successors AS (SELECT l.target_id,r.id,r.name,count(*) OVER (PARTITION BY l.target_id) AS total,row_number() OVER (PARTITION BY l.target_id ORDER BY l.created_at,r.id) AS ordinal FROM links l JOIN records r ON r.id=l.source_id WHERE l.relationship='supersedes' AND l.target_id IN (SELECT value FROM json_each(?1))) SELECT target_id,id,name,total FROM successors WHERE ordinal<=3 ORDER BY target_id,ordinal", vec![text(serde_json::to_string(chunk)?)]).await?;
        for row in page {
            let id = string(&row, "id");
            let total_count = row["total"]
                .as_i64()
                .ok_or_else(|| Error::engine("record read: invalid successor total"))?;
            let reference_id = id.clone();
            let display_reference = sql::in_snapshot(db, actor, move |conn| {
                Box::pin(async move { writes::short_reference(conn, &reference_id).await })
            })
            .await?;
            result
                .entry(string(&row, "target_id"))
                .or_insert_with(|| SupersededBy {
                    items: Vec::new(),
                    total_count,
                })
                .items
                .push(SupersededByItem {
                    id,
                    name: string(&row, "name"),
                    display_reference,
                });
        }
    }
    Ok(result)
}
