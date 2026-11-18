//! Cross-axis orientation over one caller-filtered v2 snapshot.
use super::*;
use sqlx::Row;
use std::collections::BTreeMap;

// Honest-absence §5's not_held forms describe missing replica state, and
// unavailable_offline promises an online retry. Here state is held and online;
// a budget-specific unavailable status preserves that distinction.
fn attribution_unavailable() -> Value {
    json!({"status":"unavailable","reason":"attribution_budget_exhausted",
        "interpretation_note":"Attribution exceeded its time budget; provenance and authored_by are unavailable, including authored_by contributions to convergence."})
}

const PROVENANCE_NOTE: &str = "other_account counts only actors the caller may identify; unknown includes the rest. External ingestion is not classified on this engine.";

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    query: Option<String>,
    scope: Option<String>,
    types: Option<Vec<String>>,
    recent_window_days: Option<i64>,
    high_degree_min: Option<i64>,
    include_archived: Option<bool>,
    authored_by: Option<String>,
}

fn facet(mut pool: Vec<Value>, corpus: usize) -> Value {
    let count = pool.len();
    pool.truncate(3);
    json!({"count":count,"samples":pool,"quality":quality(count as i64,corpus)})
}
fn quality(count: i64, corpus: usize) -> &'static str {
    if count == 0 {
        "empty"
    } else if corpus > 0 && count as f64 / corpus as f64 >= 0.10 {
        "saturated"
    } else {
        "focused"
    }
}

pub(super) async fn scan(db: &Db, actor: &str, arguments: Value) -> Result<Value> {
    let args: Args = parse("scan", arguments)?;
    let days = args.recent_window_days.unwrap_or(14);
    let degree = args.high_degree_min.unwrap_or(8);
    if !(1..=36_500).contains(&days) {
        return Err(Error::engine(
            "scan: 'recent_window_days' must be between 1 and 36500",
        ));
    }
    if degree < 1 {
        return Err(Error::engine("scan: 'high_degree_min' must be positive"));
    }
    kernel::read_cache::with_capabilities(sql::with_read_session(
        db,
        actor,
        &[
            ("records", "id"),
            ("records", "name"),
            ("records", "type"),
            ("records", "kind"),
            ("records", "lifecycle"),
            ("records", "last_activity_at"),
            ("records", "home_id"),
            ("records", "archived"),
            ("links", "source_id"),
            ("links", "target_id"),
            ("links", "relationship"),
            ("links", "created_at"),
        ],
        run(db, actor, args, days, degree),
    ))
    .await
}

async fn run(db: &Db, actor: &str, args: Args, days: i64, minimum: i64) -> Result<Value> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(days))
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();
    let actor_owned = actor.to_owned();
    let args_read = args.clone();
    let cutoff_read = cutoff.clone();
    let (corpus_size, census, mut axes) = sql::in_snapshot(db, actor, move |conn| {
        Box::pin(select(conn, actor_owned, args_read, cutoff_read, minimum))
    })
    .await?;
    let ids = axes
        .values()
        .flat_map(|v| v["samples"].as_array().into_iter().flatten())
        .filter_map(|s| s["id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    let successors = record_reads::successors(db, actor, &ids).await?;
    for facet in axes.values_mut() {
        for sample in facet
            .get_mut("samples")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            if let Some(next) = successors.get(sample["id"].as_str().unwrap()) {
                sample["superseded_by"] = serde_json::to_value(next)?;
            }
        }
    }
    let convergence = crate::mcp::tools::querying::build_scan_convergence(&axes);
    let mut output = json!({"corpus_size":corpus_size,"scope":args.scope,"census":census,"axes":axes,"convergence":convergence,"thresholds":{"recent_window_days":days,"recent_cutoff":cutoff,"high_degree_min":minimum,"sample_limit":3,"saturation_threshold":0.10}});
    if output["axes"]["authored_by"]["status"] == "unavailable" {
        output["convergence_basis"] = json!({
            "kind":"served_axes",
            "axes":crate::mcp::tools::querying::served_scan_axes(output["axes"].as_object().unwrap()),
            "excluded_axes":["authored_by"],
        });
    }
    Ok(output)
}

async fn select(
    conn: &mut sqlx::SqliteConnection,
    actor_owned: String,
    args: Args,
    cutoff_read: String,
    minimum: i64,
) -> Result<(
    usize,
    serde_json::Map<String, Value>,
    serde_json::Map<String, Value>,
)> {
    let started = std::time::Instant::now();
    tracing::debug!(target: "native_ce::read_staging", phase="scan_start");
    let scope = args.scope;
    let query = args.query;
    let types = serde_json::to_string(&args.types.unwrap_or_default())?;
    let archived = args.include_archived.unwrap_or(false);
    let selector = args.authored_by;
    // Index the already-authorized home graph before recursive traversal.
    // Looking up a computed home in the records view for every descendant
    // otherwise rescans the corpus once per child on large scoped reads.
    sqlx::query("CREATE TEMP TABLE _scan_records(id TEXT PRIMARY KEY,type TEXT,kind TEXT,name TEXT,home_id TEXT,lifecycle TEXT,last_activity_at TEXT,archived INTEGER); CREATE INDEX _scan_records_home ON _scan_records(home_id); INSERT INTO temp._scan_records SELECT id,type,kind,name,home_id,lifecycle,last_activity_at,archived FROM temp.records")
        .execute(&mut *conn).await?;
    if let Some(root) = &scope {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM temp._scan_records WHERE id=? AND archived=0)",
        )
        .bind(root)
        .fetch_one(&mut *conn)
        .await?;
        if !exists {
            return Err(Error::engine(
                "scan: scope record does not exist or is archived",
            ));
        }
    }
    // As in v1, scoped traversal prunes archived records even when the
    // unscoped corpus would include them. Hidden intermediates also prune.
    let scoped = format!("WITH RECURSIVE subtree(id) AS (SELECT id FROM temp._scan_records WHERE id=?1 AND archived=0 UNION SELECT r.id FROM temp._scan_records r JOIN subtree s ON r.home_id=s.id WHERE r.archived=0) SELECT r.id,r.type,r.kind,r.name,r.lifecycle,r.last_activity_at FROM temp._scan_records r WHERE {} AND (?1 IS NULL OR r.id IN (SELECT id FROM subtree)) AND (?2 OR r.archived=0) AND (?3='[]' OR r.type IN (SELECT value FROM json_each(?3))) ORDER BY r.id",super::native_query_hidden_predicate("r", &[]));
    sqlx::query("CREATE TEMP TABLE _scan_corpus(id TEXT PRIMARY KEY,type TEXT,kind TEXT,name TEXT,lifecycle TEXT,last_activity_at TEXT)").execute(&mut *conn).await?;
    sqlx::query(&format!("INSERT INTO temp._scan_corpus {scoped}"))
        .bind(scope)
        .bind(archived)
        .bind(types)
        .execute(&mut *conn)
        .await?;
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM temp._scan_corpus ORDER BY id")
        .fetch_all(&mut *conn)
        .await?;
    let size = ids.len();
    let mut census = serde_json::Map::new();
    for (label, column) in [
        ("by_type", "type"),
        ("by_kind", "kind"),
        ("by_lifecycle", "lifecycle"),
    ] {
        let buckets: Vec<(Option<String>,i64)> = sqlx::query_as(&format!("SELECT {column},count(*) AS n FROM temp._scan_corpus GROUP BY {column} ORDER BY n DESC,{column}")).fetch_all(&mut *conn).await?;
        census.insert(label.into(),json!({"shape":"counts","total":size,"buckets":buckets.into_iter().map(|(key,count)|json!({"key":key,"count":count})).collect::<Vec<_>>()}));
    }
    let untyped: i64 =
        sqlx::query_scalar("SELECT count(*) FROM temp._scan_corpus WHERE type IS NULL")
            .fetch_one(&mut *conn)
            .await?;
    if untyped > 0 {
        census["by_type"]["untyped_count"] = json!(untyped);
        census["by_type"]["interpretation_note"] = json!(
            "The null type bucket counts untyped records; their sample type label is untyped."
        );
    }
    tracing::debug!(target: "native_ce::read_staging", phase="scan_census", elapsed_us=started.elapsed().as_micros() as u64);
    let attribution =
        sql::scan_attribution_on(conn, &actor_owned, &ids, selector.as_deref()).await?;
    tracing::debug!(target: "native_ce::read_staging", phase="scan_attribution", elapsed_us=started.elapsed().as_micros() as u64);
    let mut counts = BTreeMap::<String, usize>::new();
    let mut authored = Vec::new();
    let attribution_available = attribution.is_some();
    for (id, class, seq, at) in attribution.into_iter().flatten() {
        *counts.entry(class).or_default() += 1;
        if let (Some(seq), Some(at)) = (seq, at) {
            authored.push((seq, id, at));
        }
    }
    census.insert("provenance".into(),json!({"interpretation_note":PROVENANCE_NOTE,"shape":"counts","total":size,"buckets":counts.into_iter().map(|(key,count)|json!({"key":key,"count":count})).collect::<Vec<_>>()}));
    if !attribution_available {
        census.insert("provenance".into(), attribution_unavailable());
    }
    authored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let rows = sqlx::query("SELECT * FROM temp._scan_corpus")
        .fetch_all(&mut *conn)
        .await?;
    let mut records = BTreeMap::new();
    for row in rows {
        let id: String = row.try_get("id")?;
        let record_type = row.try_get::<Option<String>, _>("type")?;
        records.insert(
            id.clone(),
            json!({"id":id,"type":record_type.unwrap_or_else(|| "untyped".into()),"name":row.try_get::<String,_>("name")?}),
        );
    }
    let mut axes = serde_json::Map::new();
    axes.insert(
        "authored_by".into(),
        facet(
            authored
                .into_iter()
                .map(|(_, id, at)| {
                    let mut v = records[&id].clone();
                    v["authored_at"] = json!(at);
                    v
                })
                .collect(),
            size,
        ),
    );
    if !attribution_available {
        axes.insert("authored_by".into(), attribution_unavailable());
    }
    if let Some(query) = query.as_deref().filter(|q| !q.trim().is_empty()) {
        let count = kernel::search_v2::scan_pool_count_on(conn, query, &ids).await?;
        let (hits, bounded) =
            kernel::search_v2::search_scoped_on(conn, &actor_owned, query, 3, true, Some(&ids))
                .await?;
        axes.insert("lexical".into(),json!({"count":count,"quality":quality(count,size),"samples":hits.into_iter().map(|h|json!({"id":h.id,"type":h.record_type,"name":h.name,"score":h.score,"snippet":h.snippet})).collect::<Vec<_>>(),"sample_selection_bounded":bounded}));
    }
    let recent:Vec<(String,String)>=sqlx::query_as("SELECT id,last_activity_at FROM temp._scan_corpus WHERE last_activity_at>=? ORDER BY last_activity_at DESC,id").bind(cutoff_read).fetch_all(&mut *conn).await?;
    axes.insert(
        "recent".into(),
        facet(
            recent
                .into_iter()
                .map(|(id, at)| {
                    let mut v = records[&id].clone();
                    v["last_activity_at"] = json!(at);
                    v
                })
                .collect(),
            size,
        ),
    );
    let children = format!("SELECT r.id,coalesce(c.n,0) AS n FROM temp._scan_corpus r LEFT JOIN (SELECT c.home_id,count(*) AS n FROM temp._scan_records c WHERE {} GROUP BY c.home_id) c ON c.home_id=r.id", super::native_query_hidden_predicate("c", &[]));
    for (axis,metric,statement,min) in [
            ("high_degree","degree","SELECT r.id,coalesce(d.n,0) AS n FROM temp._scan_corpus r LEFT JOIN (SELECT id,count(*) AS n FROM (SELECT source_id AS id FROM temp.links UNION ALL SELECT target_id FROM temp.links WHERE target_id!=source_id) GROUP BY id) d ON d.id=r.id",minimum),
            ("containers","child_count",children.as_str(),1),
        ] {
            let metrics:Vec<(String,i64)>=sqlx::query_as(&format!("SELECT m.id,m.n FROM ({statement}) m JOIN temp._scan_corpus c ON c.id=m.id WHERE m.n>=? ORDER BY m.n DESC,c.name,m.id")).bind(min).fetch_all(&mut *conn).await?;
            axes.insert(axis.into(),facet(metrics.into_iter().map(|(id,n)|{let mut v=records[&id].clone();v[metric]=json!(n);v}).collect(),size));
        }
    tracing::debug!(target: "native_ce::read_staging", phase="scan_axes", elapsed_us=started.elapsed().as_micros() as u64);
    // Enrich only the sample heads, once per distinct record.
    let sample_ids = axes
        .values()
        .flat_map(|v| v["samples"].as_array().into_iter().flatten())
        .filter_map(|s| s["id"].as_str().map(str::to_owned))
        .collect::<std::collections::BTreeSet<_>>();
    let mut enrich = BTreeMap::new();
    for id in sample_ids {
        let row = sqlx::query("SELECT type,kind,lifecycle FROM temp._scan_corpus WHERE id=?")
            .bind(&id)
            .fetch_one(&mut *conn)
            .await?;
        let typ: String = row
            .try_get::<Option<String>, _>("type")?
            .unwrap_or_default();
        let kind: Option<String> = row.try_get("kind")?;
        let lifecycle: Option<String> = row.try_get("lifecycle")?;
        let interpretation = kernel::v1_state::lifecycle_on(
            conn,
            &actor_owned,
            &typ,
            kind.as_deref(),
            &id,
            lifecycle.as_deref(),
        )
        .await?;
        let reference = writes::short_reference(conn, &id).await?;
        enrich.insert(id, (serde_json::to_value(interpretation)?, reference));
    }
    for facet in axes.values_mut() {
        for sample in facet
            .get_mut("samples")
            .and_then(Value::as_array_mut)
            .into_iter()
            .flatten()
        {
            let id = sample["id"].as_str().unwrap().to_owned();
            let (interpretation, reference) = &enrich[&id];
            sample["lifecycle_interpretation"] = interpretation.clone();
            crate::mcp::tools::lifecycle::apply_record_path_with_reference(
                sample,
                &id,
                reference.clone(),
            )?;
        }
    }
    tracing::debug!(target: "native_ce::read_staging", phase="scan_finish", elapsed_us=started.elapsed().as_micros() as u64);
    Ok((size, census, axes))
}
