//! Browser read adapters over the same caller-filtered kernel SQL relations.
//! Optional sections are absent unless requested; counts never use a page's size.
use super::*;

async fn rows(db: &Db, actor: &str, statement: &str, parameters: Vec<Value>) -> Result<Vec<Value>> {
    let answer =
        sql::query_sql(db, actor, json!({"sql":statement,"parameters":parameters})).await?;
    Ok(answer["rows"].as_array().expect("SQL result rows").clone())
}
fn text(value: &str) -> Value {
    json!({"type":"text","value":value})
}
fn integer(value: i64) -> Value {
    json!({"type":"integer","value":value.to_string()})
}
pub(super) async fn section(
    db: &Db,
    actor: &str,
    predicate: &str,
    parameters: Vec<Value>,
    order: &str,
    limit: i64,
    offset: i64,
) -> Result<(Value, Value)> {
    let count = rows(
        db,
        actor,
        &format!(
            "SELECT count(*) AS n FROM (SELECT r.id FROM records r WHERE {predicate}) eligible"
        ),
        parameters.clone(),
    )
    .await?;
    if limit == 0 {
        return Ok((count[0]["n"].clone(), json!([])));
    }
    let mut parameters = parameters;
    let page = parameters.len() + 1;
    parameters.extend([integer(limit), integer(offset)]);
    let mut values = rows(db, actor, &format!("SELECT r.id,r.type,r.kind,r.name,r.archived FROM records r WHERE {predicate} ORDER BY {order} LIMIT ?{page} OFFSET ?{}",page+1), parameters).await?;
    for value in &mut values {
        value["archived"] = json!(value["archived"].as_i64() == Some(1));
    }
    Ok((count[0]["n"].clone(), json!(values)))
}

// These families have dedicated presentation, just as v1's hidden-family
// predicates do. Exact kinds opt query_record into a family, never into others.
fn ordinary(alias: &str) -> String {
    format!("NOT ({alias}.type='Annotation' AND coalesce({alias}.kind,'') IN ('comment','suggestion','citation','attribution','acknowledgement')) AND NOT ({alias}.type='Entity' AND {alias}.kind IS 'semantic-unit')")
}

pub(super) async fn artifact_kinds(db: &Db, actor: &str) -> Result<[Vec<String>; 2]> {
    let actor_owned = actor.to_owned();
    sql::in_snapshot(db, actor, move |conn| {
        Box::pin(async move { artifact_kinds_on(conn, &actor_owned).await })
    })
    .await
}
async fn artifact_kinds_on(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
) -> Result<[Vec<String>; 2]> {
    kernel::app_installs::admit_dispatched_on(tx, actor).await?;
    let vocabularies = kernel::v1_state::rows_on(tx, "vocabularies").await?;
    let values = kernel::v1_state::rows_on(tx, "vocabulary_values").await?;
    Ok(artifact_kind_tokens(&vocabularies, &values))
}

pub(crate) fn artifact_kind_tokens(vocabularies: &[Value], values: &[Value]) -> [Vec<String>; 2] {
    let vocabulary = vocabularies.iter().find(|v| v["name"] == "kind:Annotation");
    let mut result = [Vec::new(), Vec::new()];
    for (index, family) in [
        crate::generated::kinds::CoreKind::AnnotationSuggestion,
        crate::generated::kinds::CoreKind::AnnotationCitation,
    ]
    .into_iter()
    .enumerate()
    {
        // Native-only databases have the built-in identity and no imported v1
        // vocabulary. Imported vocabularies use precisely v1's active canonical
        // identity rule, including stored aliases regardless of alias status.
        let Some(vocabulary) = vocabulary else {
            result[index].push(family.token().to_owned());
            continue;
        };
        let Some(canonical) = values
            .iter()
            .find(|v| v["id"] == family.value_id() && v["vocabulary_id"] == vocabulary["id"])
        else {
            continue;
        };
        if canonical["status"] != "active" || !canonical["alias_of"].is_null() {
            continue;
        }
        result[index] = values
            .iter()
            .filter(|v| {
                v["vocabulary_id"] == canonical["vocabulary_id"]
                    && (v["id"] == canonical["id"] || v["alias_of"] == canonical["id"])
            })
            .filter_map(|v| v["value"].as_str().map(str::to_owned))
            .collect();
    }
    result
}

/// Counts use the same staged visible relations as the individual windows.
/// DISTINCT preserves the old EXISTS semantics when link lanes overlap.
pub(super) async fn artifact_counts(
    db: &Db,
    actor: &str,
    ids: &[String],
    kinds: &[Vec<String>; 2],
) -> Result<std::collections::BTreeMap<String, [i64; 2]>> {
    let mut result = std::collections::BTreeMap::<String, [i64; 2]>::new();
    let ids = serde_json::to_string(ids)?;
    for (index, kinds) in kinds.iter().enumerate() {
        let tokens = serde_json::to_string(kinds)?;
        for row in rows(db,actor,"SELECT l.target_id,count(DISTINCT r.id) AS n FROM links l JOIN records r ON r.id=l.source_id WHERE l.relationship='part_of' AND l.target_id IN (SELECT value FROM json_each(?1)) AND r.type='Annotation' AND r.kind IN (SELECT value FROM json_each(?2)) GROUP BY l.target_id", vec![text(&ids),text(&tokens)]).await? {
            result.entry(row["target_id"].as_str().expect("target id").to_owned()).or_default()[index] = row["n"].as_i64().expect("count");
        }
    }
    Ok(result)
}

/// Child counts and pages for Get's closed batch share its staged relations.
/// Root aliases retain the existing combined-root path in `enrich`.
pub(super) async fn child_sections(
    db: &Db,
    actor: &str,
    ids: &[String],
    opts: &crate::query::read::EnrichOptions,
) -> Result<std::collections::BTreeMap<String, (Value, Value)>> {
    let ids: Vec<_> = ids
        .iter()
        .filter(|id| ![crate::events::KERNEL_ROOT_ID, "native:root"].contains(&id.as_str()))
        .collect();
    let mut sections = std::collections::BTreeMap::new();
    if ids.is_empty() {
        return Ok(sections);
    }
    let parameters = vec![text(&serde_json::to_string(&ids)?)];
    for row in rows(db,actor,&format!("SELECT r.home_id,count(*) AS n FROM records r WHERE r.home_id IN (SELECT value FROM json_each(?1)) AND {} GROUP BY r.home_id",ordinary("r")),parameters.clone()).await? {
        sections.insert(row["home_id"].as_str().expect("parent").to_owned(), (row["n"].clone(), json!([])));
    }
    if opts.children_limit > 0 {
        let mut parameters = parameters;
        parameters.extend([
            integer(opts.children_offset),
            integer(opts.children_offset.saturating_add(opts.children_limit)),
        ]);
        let page = rows(db,actor,&format!("WITH eligible AS (SELECT r.home_id,r.id,r.type,r.kind,r.name,r.archived,row_number() OVER (PARTITION BY r.home_id ORDER BY r.name,r.id) AS ordinal FROM records r WHERE r.home_id IN (SELECT value FROM json_each(?1)) AND {}) SELECT home_id,id,type,kind,name,archived FROM eligible WHERE ordinal>?2 AND ordinal<=?3 ORDER BY home_id,ordinal",ordinary("r")),parameters).await?;
        for mut row in page {
            let home = row
                .as_object_mut()
                .expect("child")
                .remove("home_id")
                .expect("parent");
            row["archived"] = json!(row["archived"].as_i64() == Some(1));
            sections
                .get_mut(home.as_str().expect("parent"))
                .expect("counted child")
                .1
                .as_array_mut()
                .expect("children")
                .push(row);
        }
    }
    for id in ids {
        sections
            .entry(id.to_owned())
            .or_insert_with(|| (json!(0), json!([])));
    }
    Ok(sections)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn enrich(
    db: &Db,
    actor: &str,
    id: &str,
    opts: &crate::query::read::EnrichOptions,
    artifact_kinds: &[Vec<String>; 2],
    history: bool,
    artifact_counts: &[i64; 2],
    child_section: Option<&(Value, Value)>,
    value: &mut Value,
) -> Result<()> {
    let (child_predicate, child_params) =
        if [crate::events::KERNEL_ROOT_ID, "native:root"].contains(&id) {
            (
                format!("r.home_id IN (?1,?2) AND {}", ordinary("r")),
                vec![text(crate::events::KERNEL_ROOT_ID), text("native:root")],
            )
        } else {
            (
                format!("r.home_id=?1 AND {}", ordinary("r")),
                vec![text(id)],
            )
        };
    let (count, children) = if let Some(section) = child_section {
        section.clone()
    } else {
        section(
            db,
            actor,
            &child_predicate,
            child_params,
            "r.name,r.id",
            opts.children_limit,
            opts.children_offset,
        )
        .await?
    };
    value["child_count"] = count;
    value["children"] = children;
    for (index, (kind, enabled, limit, offset)) in [
        (
            "suggestion",
            opts.include_suggestions,
            opts.suggestions_limit,
            opts.suggestions_offset,
        ),
        (
            "citation",
            opts.include_citations,
            opts.citations_limit,
            opts.citations_offset,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        if !enabled {
            value[format!("{kind}_count")] = json!(artifact_counts[index]);
            continue;
        }
        let tokens = serde_json::to_string(&artifact_kinds[index])?;
        let (count, page) = section(db, actor,
            "r.type='Annotation' AND r.kind IN (SELECT value FROM json_each(?1)) AND EXISTS(SELECT 1 FROM links l WHERE l.source_id=r.id AND l.relationship='part_of' AND l.target_id=?2)",
            vec![text(&tokens),text(id)],"r.created_at,r.id",if enabled {limit} else {0},offset).await?;
        value[format!("{kind}_count")] = count;
        if enabled {
            value[format!("{kind}s")] = page;
        }
    }
    let ancestors_started = std::time::Instant::now();
    let (ancestors, path_visible) = ancestors(db, actor, id).await?;
    tracing::debug!(target:"native_ce::read_staging",phase="get_ancestors",elapsed_us=ancestors_started.elapsed().as_micros() as u64);
    value["ancestors"] = json!(ancestors);
    value["containment_path_visible"] = json!(path_visible);
    if history {
        let history_id = if value["kernel_v2"]["virtual_root"] == true {
            crate::events::KERNEL_ROOT_ID
        } else {
            id
        };
        let mut ends = json!({});
        for (key, order) in [("oldest", "oldest_first"), ("latest", "newest_first")] {
            let page = super::get_history(
                db,
                actor,
                json!({"record_id":history_id,"limit":1,"order":order,"detail":"metadata"}),
            )
            .await?;
            ends[key] = page["events"]
                .as_array()
                .and_then(|events| events.first())
                .cloned()
                .unwrap_or(Value::Null);
        }
        value["history_summary"] = ends;
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Query {
    steps: Vec<Step>,
    projection: Option<crate::mcp::tools::querying::RecordProjection>,
    order: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}
#[derive(Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
enum Step {
    Filter {
        ids: Option<Vec<String>>,
        types: Option<Vec<String>>,
        kinds: Option<Vec<String>>,
        home_id: Option<String>,
        lifecycle: Option<Vec<String>>,
        maturity: Option<Vec<String>>,
        persistence: Option<String>,
        name_contains: Option<String>,
        updated_since: Option<String>,
        last_activity_since: Option<String>,
        include_archived: Option<bool>,
        facets: Option<Vec<Value>>,
    },
    Traverse {
        target: String,
        relationship: Option<String>,
        direction: Option<String>,
    },
}
#[cfg(test)]
tokio::task_local! {
    /// Test-only oracle control: force today's full staging so parity tests
    /// can compare it byte-for-byte with the narrowed path. There is no
    /// runtime or production toggle.
    pub(crate) static FORCE_FULL_STAGING: bool;
}
fn anchor_narrowing_enabled() -> bool {
    #[cfg(test)]
    {
        !FORCE_FULL_STAGING.try_with(|full| *full).unwrap_or(false)
    }
    #[cfg(not(test))]
    {
        true
    }
}

/// A fixed diagnostic label for the staging branch this call takes: the
/// narrowing plan actually selected, or the first structural reason it falls
/// back to full staging. Static identifiers only; never caller data.
fn shape_label(query: &Query, anchor: Option<&AnchorPlan>) -> &'static str {
    match anchor {
        Some(AnchorPlan::Home(_)) => return "p1_home",
        Some(AnchorPlan::Ids(_)) => return "p2_ids",
        None => {}
    }
    let mut traverses = 0usize;
    for step in &query.steps {
        match step {
            // Only the filter fields `own_row_filter` still refuses; other
            // own-row fields fall through to the structural reason.
            Step::Filter {
                last_activity_since,
                facets,
                ..
            } if last_activity_since.is_some() || facets.is_some() => {
                return "fallback_row_filter";
            }
            Step::Traverse { target, .. } => {
                if target != "links" {
                    return "fallback_traverse_tree";
                }
                traverses += 1;
            }
            Step::Filter { .. } => {}
        }
    }
    if traverses >= 2 {
        return "fallback_multi_traverse";
    }
    match query.steps.first() {
        Some(Step::Traverse { .. }) => "fallback_traverse_first",
        Some(Step::Filter {
            ids: Some(_),
            home_id: Some(_),
            ..
        }) => "fallback_mixed_anchor",
        Some(Step::Filter {
            ids: None,
            home_id: None,
            ..
        }) => "fallback_unanchored",
        Some(Step::Filter { ids: Some(ids), .. }) => {
            if ids.is_empty() || ids.len() > ANCHOR_ID_LIMIT {
                "fallback_id_count"
            } else if query.steps.len() == 1 {
                "fallback_ids_only"
            } else if query.steps.len() > 3 {
                "fallback_long_pipeline"
            } else if matches!(
                query.steps.get(1),
                Some(Step::Traverse { direction: Some(d), .. })
                    if !matches!(d.as_str(), "in" | "out" | "both")
            ) {
                "fallback_link_direction"
            } else if matches!(
                query.steps.get(2),
                Some(Step::Filter { ids, home_id, .. }) if ids.is_some() || home_id.is_some()
            ) {
                "fallback_trailing_anchor"
            } else {
                "fallback_other"
            }
        }
        Some(Step::Filter {
            home_id: Some(_), ..
        }) => "fallback_home_then_step",
        None => "fallback_other",
    }
}

/// An anchor-first extended query_record pipeline whose every possible result
/// row is derivable from a small candidate set (Native design 3a3eabb). Any
/// other shape is `None` and keeps full staging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum AnchorPlan {
    /// P1: one filter on `home_id` (types/kinds/include_archived allowed).
    Home(String),
    /// P2: filter on `ids`, one `traverse links`, optional own-row filter.
    Ids(Vec<String>),
}

const ANCHOR_ID_LIMIT: usize = 1000;

/// A filter whose every field compiles to a predicate over the candidate's
/// OWN row in the staged `records` relation, so it can only remove rows
/// from a candidate superset, never require one outside it.
///
/// Proved own-row (sql.rs `records_ddl`: each value is a scalar lookup
/// keyed by `r.id` over main tables, with no join through `_v2_visible`,
/// links or other records), and compiled as `r.<column> IN/=/>=` or
/// `instr(lower(r.name), ..)` by `query_record`'s filter step:
/// `ids`, `types`, `kinds`, `home_id`, `include_archived`, and
/// `lifecycle` (`kernel_facets`/`kernel_record_fields` of r.id),
/// `maturity`/`persistence` (`kernel_record_metadata` of r.id),
/// `name_contains` (`kernel_record_fields` title/name of r.id) and
/// `updated_since` (latest `content_events` row for r.id).
///
/// Kept on full staging, conservatively, until separately reviewed:
/// `last_activity_since` (likely own-row via `kernel_record_metadata`) and
/// `facets` (compiled over the staged `_v2_facet_rows` relation).
fn own_row_filter(step: &Step) -> Option<(&Option<Vec<String>>, &Option<String>)> {
    match step {
        // Exhaustive on purpose: a new filter field must be classified here
        // before it can reach a narrowed plan.
        Step::Filter {
            ids,
            types: _,
            kinds: _,
            home_id,
            lifecycle: _,
            maturity: _,
            persistence: _,
            name_contains: _,
            updated_since: _,
            include_archived: _,
            last_activity_since: None,
            facets: None,
        } => Some((ids, home_id)),
        _ => None,
    }
}

fn recognize_anchor(query: &Query) -> Option<AnchorPlan> {
    let (first_ids, first_home) = own_row_filter(query.steps.first()?)?;
    match (query.steps.len(), first_ids, first_home) {
        (1, None, Some(home)) => Some(AnchorPlan::Home(home.clone())),
        (2 | 3, Some(ids), None) if !ids.is_empty() && ids.len() <= ANCHOR_ID_LIMIT => {
            if !matches!(
                &query.steps[1],
                Step::Traverse { target, direction, .. }
                    if target == "links" && direction.as_deref().is_none_or(|d| matches!(d, "in" | "out" | "both"))
            ) {
                return None;
            }
            if let Some(last) = query.steps.get(2) {
                // The trailing filter may only narrow on own-row columns; it
                // never introduces a new anchor or home.
                let (ids, home) = own_row_filter(last)?;
                if ids.is_some() || home.is_some() {
                    return None;
                }
            }
            Some(AnchorPlan::Ids(ids.clone()))
        }
        _ => None,
    }
}

/// Narrowing is sound only on the provider fast path. When any provider link
/// id is duplicated across aggregates, sql.rs `stage_projected_provider_rows`
/// ranks admitted copies and runs a GLOBAL conflict check over every admitted
/// aggregate; a narrowed run admits fewer aggregates, so it could miss a
/// conflict the full run refuses on, or keep a different first copy. That
/// exact global predicate selects the path in both runs, so falling back
/// whenever it holds keeps refusal and copy-choice parity.
#[cfg(test)]
pub(super) async fn narrowing_supported_on(conn: &mut sqlx::SqliteConnection) -> Result<bool> {
    let duplicates: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT id FROM main.kernel_provider_link_rows GROUP BY id HAVING count(*)>1)",
    )
    .fetch_one(&mut *conn)
    .await?;
    Ok(!duplicates)
}

/// Parse and recognise raw query_record arguments; `None` when unparseable or
/// not an anchor-first shape.
#[cfg(test)]
pub(super) fn recognize_args(args: &Value) -> Option<AnchorPlan> {
    recognize_anchor(&serde_json::from_value::<Query>(args.clone()).ok()?)
}

/// The direct candidate superset for a plan, from the canonical tables the
/// `links` view and logical placement are built from (sql.rs link view:
/// kernel_links, kernel_link4_edges, active kernel_generic_links, provider
/// link rows plus their aggregates' subjects). It ignores
/// relationship, direction and visibility on purpose: a superset, which the
/// unchanged visibility gate and compiled SQL then filter. Each candidate's
/// direct placement dependencies (logical home records) are admitted by
/// install_relations' exact-id path behind the same visibility gate.
/// A NULL row means "not narrowable in this snapshot" (duplicated provider
/// link ids, the predicate `narrowing_supported_on` tests), so staging falls
/// back to full. The dup CTE is repeated in each query below.
///
/// P1. A record's LOGICAL home (sql.rs logical_home_placement_sql) is the
/// first of: its latest rehome target, a Message's direct home, a policy
/// anchor's legacy original home, the home map of its physical root
/// (`source_record_id` of import_home/home_created), or the physical root.
/// The superset therefore takes records whose physical root is H or maps to
/// H, records rehomed into H, every Message, and every home-map record.
/// The home map is read only for keys staging can ever map: `_v2_scopes`
/// holds exactly `kernel_roots` plus every physical `home_id`
/// (kernel::visible_home_anchors_as), and HOME_MAP_SQL joins on those keys.
/// Probing `content_events(record_id, seq)` per key avoids two full scans of
/// the event log (about 450ms on HQ; identical sets).
const HOME_CANDIDATES: &str = concat!(
    "WITH h(id) AS (SELECT value FROM json_each(?1)), ",
    "k(home_id) AS (SELECT root_id FROM main.kernel_roots UNION SELECT home_id FROM main.kernel_records), ",
    "hm(home_id,record_id) AS MATERIALIZED (SELECT e.record_id,json_extract(e.payload,'$.source_record_id') ",
    "FROM k CROSS JOIN main.content_events e ON e.record_id=k.home_id ",
    "AND e.type IN ('kernel.import_home.v1','kernel.home_created.v1') ",
    "WHERE json_extract(e.payload,'$.source_record_id') IS NOT NULL), ",
    "roots(id) AS (SELECT id FROM h UNION SELECT home_id FROM hm WHERE record_id IN (SELECT id FROM h)), ",
    "dup(x) AS (SELECT 1 WHERE EXISTS(SELECT id FROM main.kernel_provider_link_rows GROUP BY id HAVING count(*)>1)) ",
    "SELECT NULL FROM dup UNION ALL SELECT id FROM (",
    "SELECT id FROM main.kernel_records WHERE home_id IN (SELECT id FROM roots) ",
    "UNION SELECT record_id FROM main.content_events WHERE type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2') ",
    "AND json_extract(payload,'$.logical_home_id') IN (SELECT id FROM h) ",
    "UNION SELECT message_id FROM main.kernel_messages ",
    "UNION SELECT record_id FROM hm",
    ") WHERE id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM dup)",
);

/// P2. The anchors, every endpoint of every link touching them (all tables
/// behind the links view), and every subject of any provider aggregate with
/// a link touching them (provider links are visible only when their whole
/// aggregate is staged; sql.rs stage_visible_providers).
const LINK_CANDIDATES: &str = concat!(
    "WITH a(id) AS (SELECT value FROM json_each(?1)), ",
    "l(s,t) AS (SELECT source_id,target_id FROM main.kernel_links ",
    "UNION ALL SELECT source_id,target_id FROM main.kernel_link4_edges ",
    "UNION ALL SELECT source_id,target_id FROM main.kernel_generic_links WHERE active=1 ",
    "UNION ALL SELECT source_id,target_id FROM main.kernel_provider_link_rows), ",
    "touched(aggregate_id) AS (SELECT DISTINCT aggregate_id FROM main.kernel_provider_link_rows ",
    "WHERE source_id IN (SELECT id FROM a) OR target_id IN (SELECT id FROM a)), ",
    "dup(x) AS (SELECT 1 WHERE EXISTS(SELECT id FROM main.kernel_provider_link_rows GROUP BY id HAVING count(*)>1)) ",
    "SELECT NULL FROM dup UNION ALL SELECT id FROM (",
    "SELECT id FROM a UNION SELECT s FROM l WHERE t IN (SELECT id FROM a) ",
    "UNION SELECT t FROM l WHERE s IN (SELECT id FROM a) ",
    "UNION SELECT subject_id FROM main.kernel_provider_subjects WHERE aggregate_id IN (SELECT aggregate_id FROM touched)",
    ") WHERE NOT EXISTS(SELECT 1 FROM dup)",
);

/// The in-session candidate query and its JSON argument for a plan.
pub(super) fn candidate_query(plan: &AnchorPlan) -> Result<(&'static str, String)> {
    Ok(match plan {
        AnchorPlan::Home(home) => {
            let homes: Vec<&str> =
                if [crate::events::KERNEL_ROOT_ID, "native:root"].contains(&home.as_str()) {
                    vec![crate::events::KERNEL_ROOT_ID, "native:root"]
                } else {
                    vec![home.as_str()]
                };
            (HOME_CANDIDATES, serde_json::to_string(&homes)?)
        }
        AnchorPlan::Ids(ids) => (LINK_CANDIDATES, serde_json::to_string(ids)?),
    })
}

/// Test helper: the candidate set (empty when the snapshot is not narrowable).
#[cfg(test)]
pub(super) async fn direct_candidates_on(
    conn: &mut sqlx::SqliteConnection,
    plan: &AnchorPlan,
) -> Result<std::collections::BTreeSet<String>> {
    let (sql, arg) = candidate_query(plan)?;
    let rows: Vec<Option<String>> = sqlx::query_scalar(sql)
        .bind(arg)
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows.into_iter().flatten().collect())
}

fn bind(parameters: &mut Vec<Value>, value: Value) -> String {
    parameters.push(value);
    format!("?{}", parameters.len())
}

/// Existing native query family opt-ins. This is a surface rule, not a
/// legacy CoreKind catalogue or a fallback from failed kind resolution.
pub(crate) const ATTRIBUTION_KIND: &str = "attribution";
pub(crate) const QUERY_OPT_IN_FAMILIES: [&str; 3] = ["comment", "suggestion", "citation"];
pub(crate) fn query_hidden_predicate(alias: &str, families: &[&str]) -> String {
    let mut predicate=format!("NOT ({alias}.type='Annotation' AND coalesce({alias}.kind,'') IN ('{ATTRIBUTION_KIND}','acknowledgement')) AND NOT ({alias}.type='Entity' AND {alias}.kind IS 'semantic-unit')");
    for kind in QUERY_OPT_IN_FAMILIES
        .into_iter()
        .filter(|kind| !families.contains(kind))
    {
        // Only the fixed engine-owned constants above become SQL literals.
        predicate.push_str(&format!(
            " AND NOT ({alias}.type='Annotation' AND {alias}.kind IS '{kind}')"
        ));
    }
    predicate
}

pub(super) async fn query_record(db: &Db, actor: &str, args: Value) -> Result<Value> {
    query_record_with_projection(db, actor, args, None).await
}

/// Collection-envelope width over the unchanged selection pipeline: the
/// saved query keeps its validated shape (no public projection override).
/// The width travels as a typed parameter, never inside the argument object,
/// so no caller — trusted direct calls included — can select it by accident.
pub(super) async fn query_record_for_envelope(db: &Db, actor: &str, args: Value) -> Result<Value> {
    query_record_with_projection(db, actor, args, Some(ValueProjection::Envelope)).await
}

async fn query_record_with_projection(
    db: &Db,
    actor: &str,
    args: Value,
    overwrite: Option<ValueProjection>,
) -> Result<Value> {
    let args: Query = parse("query_record", args)?;
    // Anchor narrowing (Native 3a3eabb): only the proven P1/P2 shapes stage
    // a candidate superset; every other shape, and any snapshot with
    // duplicated provider link ids, keeps full staging.
    let anchor = if anchor_narrowing_enabled() {
        recognize_anchor(&args)
    } else {
        None
    };
    sql::set_query_record_shape(shape_label(&args, anchor.as_ref()));
    let projection = match (overwrite, args.projection.is_some()) {
        (Some(width), _) => width,
        (None, true) => ValueProjection::Metadata,
        (None, false) => ValueProjection::Full,
    };
    let limit = args.limit.unwrap_or(50);
    let offset = args.offset.unwrap_or(0);
    if !(1..=500).contains(&limit) || offset < 0 {
        return Err(Error::engine(
            "query_record: limit must be between 1 and 500; offset must be nonnegative",
        ));
    }
    let order = match args.order.as_deref().unwrap_or("updated_desc") {
        "updated_desc" => "r.updated_at DESC,r.id",
        "created_desc" => "r.created_at DESC,r.id",
        "last_activity_desc" => "r.last_activity_at DESC,r.id",
        "name_asc" => "r.name,r.id",
        _ => {
            return Err(unsupported(
                "query_record",
                "order; expected updated_desc, created_desc, last_activity_desc or name_asc",
            ))
        }
    };
    if args.steps.is_empty() || args.steps.len() > 32 {
        return Err(Error::engine(
            "query_record: expected between 1 and 32 steps",
        ));
    }
    let mut parameters = Vec::new();
    let mut previous: Option<String> = None;
    // A kind opt-in applies throughout the pipeline, as in v1. An annotation
    // family never makes other hidden annotation families discoverable.
    let families: Vec<&str> = args
        .steps
        .iter()
        .flat_map(|s| match s {
            Step::Filter { kinds: Some(k), .. } => k.iter().map(String::as_str).collect(),
            _ => Vec::new(),
        })
        .collect();
    let hidden_clause = query_hidden_predicate("r", &families);
    for (step_index, step) in args.steps.into_iter().enumerate() {
        let mut clauses = vec![hidden_clause.clone()];
        match step {
            Step::Filter {
                ids,
                types,
                kinds,
                home_id,
                lifecycle,
                maturity,
                persistence,
                name_contains,
                updated_since,
                last_activity_since,
                include_archived,
                facets,
            } => {
                if let Some(previous) = &previous {
                    clauses.push(format!("r.id IN ({previous})"));
                }
                for (column, values) in [
                    ("id", ids),
                    ("type", types),
                    ("kind", kinds),
                    ("lifecycle", lifecycle),
                    ("maturity", maturity),
                ] {
                    if let Some(values) = values.filter(|v| !v.is_empty()) {
                        let placeholders = values
                            .into_iter()
                            .map(|v| bind(&mut parameters, text(&v)))
                            .collect::<Vec<_>>()
                            .join(",");
                        clauses.push(format!("r.{column} IN ({placeholders})"));
                    }
                }
                for (column, value) in [("home_id", home_id), ("persistence", persistence)] {
                    if let Some(value) = value {
                        if column == "home_id"
                            && [crate::events::KERNEL_ROOT_ID, "native:root"]
                                .contains(&value.as_str())
                        {
                            clauses.push(format!(
                                "r.home_id IN ({},{})",
                                bind(&mut parameters, text(crate::events::KERNEL_ROOT_ID)),
                                bind(&mut parameters, text("native:root"))
                            ));
                        } else {
                            clauses.push(format!(
                                "r.{column}={}",
                                bind(&mut parameters, text(&value))
                            ));
                        }
                    }
                }
                if let Some(value) = name_contains {
                    clauses.push(format!(
                        "instr(lower(r.name),lower({}))>0",
                        bind(&mut parameters, text(&value))
                    ));
                }
                for (column, value) in [
                    ("updated_at", updated_since),
                    ("last_activity_at", last_activity_since),
                ] {
                    if let Some(value) = value {
                        clauses.push(format!(
                            "r.{column}>={}",
                            bind(&mut parameters, text(&value))
                        ));
                    }
                }
                // Reuse v1 validation and predicates, over the SQL lane's
                // caller-filtered facet relation. Unlike v1 member slices,
                // this relation includes its typed value_num projection.
                let facets = facets
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(index, facet)| {
                        crate::mcp::tools::querying::parse_facet_arg(
                            "query_record",
                            step_index,
                            index,
                            facet,
                        )
                    })
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>();
                let (facet_clauses, facet_binds) =
                    crate::query::pipeline::facet_filter_sql(&facets, false)?;
                let mut facet_binds = facet_binds.into_iter();
                for clause in facet_clauses {
                    // Only compiler-generated SQL is renumbered here; authored
                    // strings never enter the fragment and cannot contain SQL.
                    let mut numbered = String::new();
                    for ch in clause.chars() {
                        if ch == '?' {
                            numbered.push_str(&bind(
                                &mut parameters,
                                text(&facet_binds.next().expect("facet SQL binding")),
                            ));
                        } else {
                            numbered.push(ch);
                        }
                    }
                    clauses.push(numbered);
                }
                debug_assert!(facet_binds.next().is_none());
                if !include_archived.unwrap_or(false) {
                    clauses.push("r.archived=0".into());
                }
            }
            Step::Traverse {
                target,
                relationship,
                direction,
            } => {
                let previous = previous.as_ref().ok_or_else(|| {
                    Error::engine("query_record: traversal requires a preceding filter")
                })?;
                if matches!(target.as_str(), "children" | "parents")
                    && (direction.is_some() || relationship.is_some())
                {
                    return Err(Error::engine(
                        "query_record: 'relationship' and 'direction' apply to target 'links' only",
                    ));
                }
                let direction = direction.as_deref().unwrap_or("both");
                let clause = match target.as_str() {
                    "links" => {
                        let endpoints=match direction {"in"=>format!("l.target_id IN ({previous}) AND l.source_id=r.id"),"out"=>format!("l.source_id IN ({previous}) AND l.target_id=r.id"),"both"=>format!("(l.target_id IN ({previous}) AND l.source_id=r.id OR l.source_id IN ({previous}) AND l.target_id=r.id)"),_=>return Err(unsupported("query_record","link direction"))};
                        let relationship = relationship
                            .map(|v| {
                                format!(" AND l.relationship={}", bind(&mut parameters, text(&v)))
                            })
                            .unwrap_or_default();
                        format!("EXISTS(SELECT 1 FROM links l WHERE ({endpoints}){relationship})")
                    }
                    "children" if relationship.is_none() => format!("r.home_id IN ({previous})"),
                    "parents" if relationship.is_none() => format!(
                        "r.id IN (SELECT p.home_id FROM records p WHERE p.id IN ({previous}))"
                    ),
                    _ => return Err(unsupported("query_record", "traverse target")),
                };
                clauses.push(clause);
            }
        }
        previous = Some(format!(
            "SELECT r.id FROM records r WHERE {}",
            clauses.join(" AND ")
        ));
    }
    let selected = previous.expect("nonempty pipeline");
    let count_sql = format!("SELECT count(*) AS n FROM (SELECT r.id FROM records r WHERE r.id IN ({selected})) eligible");
    let page = parameters.len() + 1;
    let page_sql = format!("SELECT r.id FROM records r WHERE r.id IN ({selected}) ORDER BY {order} LIMIT ?{page} OFFSET ?{}",page+1);
    let work = async {
        let total = rows(db, actor, &count_sql, parameters.clone()).await?[0]["n"]
            .as_u64()
            .unwrap_or(0) as usize;
        parameters.extend([integer(limit), integer(offset)]);
        let ids = rows(db, actor, &page_sql, parameters).await?;
        Ok((total, ids))
    };
    let (total, ids) = match &anchor {
        Some(plan) => {
            let (candidate_sql, candidate_arg) = candidate_query(plan)?;
            sql::with_query_read_session_exact(
                db,
                actor,
                &[&count_sql, &page_sql],
                candidate_sql,
                &candidate_arg,
                work,
            )
            .await?
        }
        None => sql::with_query_read_session(db, actor, &[&count_sql, &page_sql], work).await?,
    };
    let ids: Vec<String> = ids
        .iter()
        .filter_map(|row| row["id"].as_str().map(str::to_owned))
        .collect();
    // One pinned hydration snapshot for the returned window. Selection is
    // still separately governed, and every selected id is re-authorized here.
    // The envelope width rides the body-free metadata view; its persistence
    // comes from the same view, never a second snapshot.
    let actor_owned = actor.to_owned();
    let records = sql::in_snapshot(db, actor, move |conn| {
        Box::pin(async move {
            let mut records = Vec::with_capacity(ids.len());
            for id in ids {
                let record = if projection == ValueProjection::Full {
                    kernel::read_record_on(conn, &actor_owned, &id).await?
                } else {
                    kernel::read_record_metadata_on(conn, &actor_owned, &id).await?
                };
                if let Some(record) = record {
                    records.push(
                        record_value_projection_on(conn, &actor_owned, &record, projection).await?,
                    );
                }
            }
            Ok(records)
        })
    })
    .await?;
    let returned = records.len();
    Ok(
        json!({"shape":"records","records":records,"total":total,"returned":returned,"offset":offset,"has_more":(offset as usize).saturating_add(returned)<total}),
    )
}

/// The v2 policy root has a real event stream but is not a domain record.
/// Expose its folder descriptor using imported workspace metadata, never an
/// invented body, creator or history event. View on the root is still required.
pub(super) async fn root(db: &Db, actor: &str, id: &str) -> Result<Option<Value>> {
    if ![crate::events::KERNEL_ROOT_ID, "native:root"].contains(&id) {
        return Ok(None);
    }
    let actor_owned = actor.to_owned();
    let id = id.to_owned();
    sql::in_snapshot(db, actor, move |conn| {
        Box::pin(async move { root_on(conn, &actor_owned, &id).await })
    })
    .await
}
pub(crate) async fn root_on(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<Option<Value>> {
    if !kernel::kernel_effective_capability_on(tx, actor, crate::events::KERNEL_ROOT_ID)
        .await?
        .allows(crate::authorization::Capability::View)
    {
        return Ok(None);
    }
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
            .bind(crate::events::KERNEL_ROOT_ID)
            .fetch_one(&mut *tx)
            .await?;
    let (seq,created,updated):(i64,String,String)=sqlx::query_as("SELECT max(seq),min(created_at),max(created_at) FROM main.content_events WHERE record_id IN (?,?)").bind(crate::events::KERNEL_ROOT_ID).bind(kernel::workspace_metadata::RECORD_ID).fetch_one(&mut *tx).await?;
    let metadata = kernel::workspace_metadata::read_on(tx).await?;
    Ok(Some(
        json!({"id":id,"status":"found","type":"Collection","kind":"folder","name":metadata.as_ref().map(|m|m.name.as_str()).unwrap_or("Native workspace"),"summary":metadata.and_then(|m|m.summary),"body":null,"body_digest":crate::mcp::tools::lifecycle::body_digest(None),"home_id":null,"owner_id":owner,"persistence":"enduring","maturity":null,"archived":false,"created_at":created,"updated_at":updated,"last_activity_at":updated,"record_version":format!("rec:{seq}"),"version":format!("rec:{seq}"),"kernel_v2":{"virtual_root":true},"ancestors":[]}),
    ))
}

async fn descriptor(db: &Db, actor: &str, id: &str) -> Result<Option<Value>> {
    match kernel::read_record_as(db, actor, id).await? {
        Some(record) => Ok(Some(record_value(db, actor, &record).await?)),
        None => root(db, actor, id).await,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Structure {
    root_id: String,
    max_depth: Option<i64>,
    include_archived: Option<bool>,
    max_children_per_node: Option<i64>,
    #[serde(default)]
    exclude_types: Vec<String>,
}

/// Bootstrap needs one root summary and its visible ordinary-child count.
/// Keep the tree's placement and visibility rules, but do not materialize
/// names, persistence or activity for the unrelated workspace corpus.
pub(super) async fn bootstrap_roots(db: &Db, actor: &str) -> Result<Value> {
    let id = "native:root";
    if root(db, actor, id).await?.is_none() {
        return Ok(json!([]));
    }
    sql::with_part_of_read_session(
        db,
        actor,
        &[
            ("records", "id"),
            ("records", "type"),
            ("records", "kind"),
            ("records", "home_id"),
            ("records", "archived"),
        ],
        &[id.to_owned()],
        async {
            let node = descriptor(db, actor, id)
                .await?
                .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
            let path_visible = ancestors(db, actor, id).await?.1;
            let count = rows(
                db,
                actor,
                &format!(
                    "SELECT count(*) AS n FROM records r WHERE {} AND r.home_id IN (?1,?2) AND r.archived=0",
                    ordinary("r")
                ),
                vec![text(crate::events::KERNEL_ROOT_ID), text(id)],
            )
            .await?;
            let boundary = {
                let mut connection = db.pool().acquire().await?;
                custody_boundary_on(&mut connection, id).await?
            };
            let mut summary = json!({"depth":0,"child_count":count[0]["n"],"custody_boundary":boundary,"containment_path_visible":path_visible,"archived":node["archived"]==true || node["archived"]==1});
            for field in [
                "id",
                "type",
                "kind",
                "name",
                "home_id",
                "persistence",
                "last_activity_at",
            ] {
                summary[field] = node[field].clone();
            }
            Ok(json!([summary]))
        },
    )
    .await
}

pub(super) async fn get_structure(db: &Db, actor: &str, args: Value) -> Result<Value> {
    sql::with_read_session(
        db,
        actor,
        &[
            ("records", "id"),
            ("records", "type"),
            ("records", "kind"),
            ("records", "name"),
            ("records", "home_id"),
            ("records", "persistence"),
            ("records", "last_activity_at"),
            ("records", "archived"),
        ],
        get_structure_in_session(db, actor, args),
    )
    .await
}
async fn get_structure_in_session(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: Structure = parse("get_structure", args)?;
    let depth = args.max_depth.unwrap_or(3);
    let width = args
        .max_children_per_node
        .unwrap_or(crate::query::tree::DEFAULT_MAX_CHILDREN_PER_NODE);
    if depth < 0 || !(0..=crate::query::tree::MAX_CHILDREN_PER_NODE).contains(&width) {
        return Err(Error::engine("get_structure: max_depth must be nonnegative; max_children_per_node must be between 0 and 1000"));
    }
    for typ in &args.exclude_types {
        if !crate::schema::SPINE_TYPES.contains(&typ.as_str()) {
            return Err(Error::engine(
                "get_structure: exclude_types entry is not a spine type",
            ));
        }
    }
    let root = descriptor(db, actor, &args.root_id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    let path_visible = ancestors(db, actor, &args.root_id).await?.1;
    let mut level = vec![root];
    let mut seen = std::collections::BTreeSet::new();
    let mut nodes = Vec::new();
    for at in 0..=depth.min(100) {
        if level.is_empty() {
            break;
        }
        let mut totals = std::collections::BTreeMap::<String, i64>::new();
        // Count the entire frontier in bounded parameter chunks. A wide
        // folder at depth 1 must not stage the whole workspace per child.
        let mut parents: Vec<String> = level
            .iter()
            .filter_map(|n| n["id"].as_str().map(str::to_owned))
            .collect();
        if parents
            .iter()
            .any(|id| [crate::events::KERNEL_ROOT_ID, "native:root"].contains(&id.as_str()))
        {
            parents.extend([crate::events::KERNEL_ROOT_ID.into(), "native:root".into()]);
        }
        parents.sort();
        parents.dedup();
        for chunk in parents.chunks(200) {
            let mut params = Vec::new();
            let placeholders = chunk
                .iter()
                .map(|id| bind(&mut params, text(id)))
                .collect::<Vec<_>>()
                .join(",");
            let mut predicate = format!("{} AND r.home_id IN ({placeholders})", ordinary("r"));
            if !args.include_archived.unwrap_or(false) {
                predicate.push_str(" AND r.archived=0");
            }
            for typ in &args.exclude_types {
                predicate.push_str(&format!(" AND r.type!={}", bind(&mut params, text(typ))));
            }
            for row in rows(db,actor,&format!("SELECT r.home_id,count(*) AS n FROM records r WHERE {predicate} GROUP BY r.home_id"),params).await? {
                totals.insert(row["home_id"].as_str().expect("parent id").into(), row["n"].as_i64().expect("child count"));
            }
        }
        let mut next_level = Vec::new();
        for node in level {
            let id = node["id"].as_str().expect("descriptor id").to_owned();
            if !seen.insert(id.clone()) {
                continue;
            }
            let root_alias = [crate::events::KERNEL_ROOT_ID, "native:root"].contains(&id.as_str());
            let count = if root_alias {
                totals
                    .get(crate::events::KERNEL_ROOT_ID)
                    .copied()
                    .unwrap_or(0)
                    + totals.get("native:root").copied().unwrap_or(0)
            } else {
                totals.get(&id).copied().unwrap_or(0)
            };
            let mut params = vec![text(&id)];
            let mut predicate = format!("{} AND r.home_id=?1", ordinary("r"));
            if root_alias {
                predicate = format!("{} AND r.home_id IN (?1,?2)", ordinary("r"));
                params.push(text(if id == "native:root" {
                    crate::events::KERNEL_ROOT_ID
                } else {
                    "native:root"
                }));
            }
            if !args.include_archived.unwrap_or(false) {
                predicate.push_str(" AND r.archived=0");
            }
            for typ in &args.exclude_types {
                predicate.push_str(&format!(" AND r.type!={}", bind(&mut params, text(typ))));
            }
            if at < depth.min(100) && width > 0 && count > 0 {
                let page = params.len() + 1;
                params.push(integer(width));
                let children = rows(db,actor,&format!("SELECT r.id,r.type,r.kind,r.name,r.home_id,r.persistence,r.last_activity_at,r.archived FROM records r WHERE {predicate} ORDER BY r.name,r.id LIMIT ?{page}"),params).await?;
                next_level.extend(children);
            }
            let boundary = {
                let mut connection = db.pool().acquire().await?;
                custody_boundary_on(&mut connection, &id).await?
            };
            let mut summary = json!({"depth":at,"child_count":count,"custody_boundary":boundary,"containment_path_visible":path_visible,"archived":node["archived"]==true || node["archived"]==1});
            for field in [
                "id",
                "type",
                "kind",
                "name",
                "home_id",
                "persistence",
                "last_activity_at",
            ] {
                summary[field] = node[field].clone();
            }
            nodes.push(summary);
        }
        level = next_level;
    }
    Ok(
        json!({"root_id":args.root_id,"max_depth":depth,"max_children_per_node":width,"nodes":nodes}),
    )
}

// Test-only work counters at the actual resolver boundaries; no timing claims.
#[cfg(test)]
#[derive(Default, Debug)]
pub(super) struct ContainmentWork {
    pub initial_placements: usize,
    pub admissions: usize,
    pub descriptor_loads: usize,
}
#[cfg(test)]
tokio::task_local! { static CONTAINMENT_WORK: std::cell::RefCell<ContainmentWork>; }
#[cfg(test)]
pub(super) async fn measured_containment<T>(
    work: impl std::future::Future<Output = T>,
) -> (T, ContainmentWork) {
    CONTAINMENT_WORK
        .scope(std::cell::RefCell::new(ContainmentWork::default()), async {
            let result = work.await;
            (result, CONTAINMENT_WORK.with(|value| value.take()))
        })
        .await
}

// Ancestors expose only labels and placement. Reuse the existing body-free
// metadata projection (label-relevant fields only, no body lane read) so a
// large ancestor body cannot cost label resolution. Unrelated fields are also
// skipped, which deliberately tolerates a malformed unrelated field where the
// old full hydration failed; title/name/v1_type/v1_kind precedence, View
// gating, virtual roots, logical moves and memoization below are unchanged.
async fn ancestor_descriptor_on(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<Option<Value>> {
    type Labels = std::sync::Mutex<std::collections::BTreeMap<String, Option<Value>>>;
    kernel::app_installs::admit_dispatched_on(tx, actor).await?;
    #[cfg(test)]
    let _ = CONTAINMENT_WORK.try_with(|value| value.borrow_mut().admissions += 1);
    let key = kernel::read_cache::key_on(tx, actor, "ancestor_descriptors").await?;
    let labels = kernel::read_cache::get::<Labels>(&key).unwrap_or_default();
    let cached = labels
        .lock()
        .expect("ancestor cache poisoned")
        .get(id)
        .cloned();
    if let Some(cached) = cached {
        return Ok(cached);
    }
    #[cfg(test)]
    let _ = CONTAINMENT_WORK.try_with(|value| value.borrow_mut().descriptor_loads += 1);
    let value = if let Some(record) = kernel::read_record_metadata_on(tx, actor, id).await? {
        let primary: Option<String> =
            sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
        let (typ, kind) = v1_type_and_kind(
            record.family.as_deref(),
            record.pin.as_ref().map(|p| p.version),
            primary.as_deref(),
            record.kind.as_deref(),
            &record.fields,
        );
        let home = crate::v1_import::placement_on(tx, actor, id)
            .await?
            .and_then(|p| p.home_id);
        Some(
            json!({"id":id,"type":typ,"kind":kind,"name":record.fields.get("title").or_else(||record.fields.get("name")),"home_id":home}),
        )
    } else if [crate::events::KERNEL_ROOT_ID, "native:root"].contains(&id)
        && kernel::kernel_effective_capability_on(tx, actor, crate::events::KERNEL_ROOT_ID)
            .await?
            .allows(crate::authorization::Capability::View)
    {
        let metadata = kernel::workspace_metadata::read_on(tx).await?;
        Some(
            json!({"id":id,"type":"Collection","kind":"folder","name":metadata.as_ref().map(|m|m.name.as_str()).unwrap_or("Native workspace"),"home_id":null,"kernel_v2":{"virtual_root":true}}),
        )
    } else {
        None
    };
    labels
        .lock()
        .expect("ancestor cache poisoned")
        .insert(id.to_owned(), value.clone());
    kernel::read_cache::put(key, labels);
    Ok(value)
}

async fn ancestors(db: &Db, actor: &str, id: &str) -> Result<(Vec<Value>, bool)> {
    let actor_owned = actor.to_owned();
    let id = id.to_owned();
    sql::in_snapshot(db, actor, move |conn| {
        Box::pin(async move { ancestors_on(conn, &actor_owned, &id).await })
    })
    .await
}

/// Snapshot-scoped source fact for a selected member record. Reuse the native
/// ancestor resolver's exact visibility, virtual-root and depth/cycle rules;
/// neither a held subset nor a logical root id grants canonical visibility.
pub(crate) async fn containment_path_visible_on(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<bool> {
    Ok(ancestors_on(tx, actor, id).await?.1)
}

async fn ancestors_on(
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<(Vec<Value>, bool)> {
    let mut chain = Vec::new();
    let mut seen = std::collections::BTreeSet::from([id.to_string()]);
    let mut terminal_root = [crate::events::KERNEL_ROOT_ID, "native:root"].contains(&id);
    #[cfg(test)]
    let _ = CONTAINMENT_WORK.try_with(|value| value.borrow_mut().initial_placements += 1);
    let mut next = crate::v1_import::placement_on(tx, actor, id)
        .await?
        .and_then(|p| p.home_id);
    // A hidden/missing ancestor ends disclosure. Never bridge it with a raw id.
    for _ in 0..100 {
        let Some(id) = next.take() else {
            chain.reverse();
            return Ok((chain, terminal_root));
        };
        if !seen.insert(id.clone()) {
            chain.reverse();
            return Ok((chain, false));
        }
        let Some(value) = ancestor_descriptor_on(tx, actor, &id).await? else {
            chain.reverse();
            return Ok((chain, false));
        };
        terminal_root = value["kernel_v2"]["virtual_root"] == true;
        next = value["home_id"].as_str().map(str::to_owned);
        chain.push(json!({"id":id,"type":value["type"],"kind":value["kind"],"name":value["name"]}));
    }
    chain.reverse();
    Ok((chain, false))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Collection {
    id: String,
}
pub(super) async fn open_collection(db: &Db, actor: &str, args: Value) -> Result<Value> {
    kernel::read_cache::with_capabilities(open_collection_read(db, actor, args)).await
}
async fn open_collection_read(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: Collection = parse("open_collection", args)?;
    let record = descriptor(db, actor, &args.id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    let kind = record["kind"].as_str().unwrap_or_default();
    if crate::mcp::tools::artifacts::native_collection_kind(
        record["type"].as_str().unwrap_or_default(),
        Some(kind),
    )
    .is_none()
    {
        return Ok(
            json!({"status":"error","diagnostic":{"format":"native.artifact-diagnostic.v1","code":"invalid_collection_shape","message":"not a live governed Collection kind:query|selection|folder","details":{"collection_id":args.id}}}),
        );
    }
    let resolution = open_collection_input(db, actor, &args.id, kind).await;
    match resolution {
        Ok(value) => Ok(value),
        Err(error) => Ok(crate::mcp::tools::artifacts::diagnostic(
            "input_resolution_failed",
            error.to_string(),
            json!({"collection_id":args.id,"kind":kind}),
        )),
    }
}

/// Test-only envelope work counters. Production paths are unchanged; these
/// task-local tallies let the envelope regression test compare hydrated body
/// bytes and facet transactions between the page-scoped fetch and an
/// old-style full-hydration plus per-record-facet oracle executed for real.
/// Follows the existing task-local precedent (`FORCE_FULL_STAGING`,
/// `sql::measured`); no benchmark framework.
#[cfg(test)]
pub(super) mod envelope_diagnostics {
    #[derive(Clone, Copy, Default, Debug)]
    pub struct Probe {
        pub body_loads: u64,
        pub body_bytes: u64,
        pub facet_transactions: u64,
        pub envelope_pages: u64,
    }

    tokio::task_local! {
        static PROBE: std::cell::RefCell<Probe>;
    }

    pub fn note_body_hydrated(bytes: usize) {
        let _ = PROBE.try_with(|probe| {
            let mut probe = probe.borrow_mut();
            probe.body_loads += 1;
            probe.body_bytes += bytes as u64;
        });
    }

    pub fn note_facet_transaction() {
        let _ = PROBE.try_with(|probe| probe.borrow_mut().facet_transactions += 1);
    }

    pub fn note_envelope_page() {
        let _ = PROBE.try_with(|probe| probe.borrow_mut().envelope_pages += 1);
    }

    pub async fn scoped<T>(work: impl std::future::Future<Output = T>) -> (T, Probe) {
        PROBE
            .scope(std::cell::RefCell::new(Probe::default()), async {
                let result = work.await;
                (result, PROBE.with(|probe| *probe.borrow()))
            })
            .await
    }
}

/// Page-scoped envelope facet fetch for one membership page. One transaction
/// and one admission cover every member; per-record View is still enforced
/// one id at a time so a hidden member refuses exactly as the per-record
/// path did. Rows keep the per-record key ordering the decoder expects.
/// Persistence is not fetched here: it rides the envelope hydration row from
/// the same snapshot, so maturity and persistence can never skew.
async fn envelope_facet_values(
    db: &Db,
    actor: &str,
    ids: &[String],
) -> Result<std::collections::BTreeMap<String, Vec<(String, String, Option<String>, i64)>>> {
    let mut out = std::collections::BTreeMap::new();
    for id in ids {
        out.insert(id.clone(), Vec::new());
    }
    if ids.is_empty() {
        return Ok(out);
    }
    #[cfg(test)]
    envelope_diagnostics::note_envelope_page();
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    for id in ids {
        kernel::kernel_require(&mut tx, actor, id, crate::authorization::Capability::View).await?;
    }
    let ids_json = serde_json::to_string(ids)?;
    let rows: Vec<(String, String, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT record_id,key,value,vocab_ref,event_seq FROM kernel_facets WHERE record_id IN (SELECT value FROM json_each(?)) AND value IS NOT NULL AND key!='archived' ORDER BY record_id,key",
    )
    .bind(ids_json)
    .fetch_all(&mut *tx)
    .await?;
    for (record_id, key, value, vocab_ref, seq) in rows {
        if let Some(entry) = out.get_mut(&record_id) {
            entry.push((key, value, vocab_ref, seq));
        }
    }
    tx.rollback().await?;
    Ok(out)
}

async fn open_collection_input(db: &Db, actor: &str, id: &str, kind: &str) -> Result<Value> {
    let (mut query, exhaustive) = match kind {
        "folder" => (
            json!({"steps":[{"step":"filter","home_id":id}],"order":"name_asc"}),
            true,
        ),
        "selection" => (
            json!({"steps":[{"step":"filter","ids":[id]},{"step":"traverse","target":"links","relationship":"member_of","direction":"in"}],"order":"name_asc"}),
            true,
        ),
        _ => {
            // V1 artifacts.rs:4381: inspect once; preserve the authored/default
            // page unless full membership was explicitly declared and unpaged.
            let facets = metadata_reads::facet_values(db, actor, id).await?;
            let raw = facets
                .iter()
                .find(|(key, _, _, _)| key == "query")
                .map(|(_, value, _, _)| value.as_str());
            use crate::mcp::tools::querying::SavedQueryInspection;
            match crate::mcp::tools::querying::inspect_saved_record_query(raw) {
                SavedQueryInspection::Valid { query, .. } => {
                    let all_matching = facets.iter().any(|(key, value, _, _)| {
                        key == "input_membership" && value == "all_matching"
                    });
                    let unpaged = query.get("limit").is_none() && query.get("offset").is_none();
                    (query, all_matching && unpaged)
                }
                SavedQueryInspection::GovernedSql { .. }
                | SavedQueryInspection::GovernedSqlPinned { .. } => return Err(Error::engine(
                    "saved governed SQL artifact inputs require a native.relation-envelope.v1 port",
                )),
                SavedQueryInspection::Invalid { diagnostic }
                | SavedQueryInspection::UnsupportedVersion { diagnostic, .. } => {
                    return Err(Error::engine(diagnostic))
                }
            }
        }
    };
    let schema = metadata_reads::schema(db, actor).await?;
    // The captured schema is immutable for this resolution. Reuse the pure
    // cascade only for exactly the same type, kind and context argument.
    let mut shape_contexts = std::collections::BTreeMap::new();
    let mut records = Vec::new();
    let mut offset = 0;
    // Envelope hydration is body-free by construction: the private envelope
    // width skips bodies, historical claims and legacy provenance that this
    // resolver discards, while carrying persistence from the same snapshot
    // as maturity. The saved query keeps its validated shape; only the
    // exhaustive/authored-page limit/offset below is adjusted.
    loop {
        if exhaustive {
            query["limit"] = json!(500);
            query["offset"] = json!(offset);
        }
        let page = query_record_for_envelope(db, actor, query.clone()).await?;
        let members = page["records"].as_array().ok_or_else(|| {
            Error::engine("Collection kind:query must resolve to records, not a count or aggregate")
        })?;
        let member_ids: Vec<String> = members
            .iter()
            .map(|record| record["id"].as_str().expect("member id").to_owned())
            .collect();
        let batched = envelope_facet_values(db, actor, &member_ids).await?;
        for record in members {
            let mut value = json!({});
            for field in [
                "id",
                "type",
                "kind",
                "name",
                "summary",
                "lifecycle_interpretation",
                "maturity",
                "persistence",
            ] {
                value[field] = record[field].clone();
            }
            let id = record["id"].as_str().expect("member id");
            let fields = batched.get(id).cloned().unwrap_or_default();
            let context = (
                record["type"].as_str().unwrap_or_default().to_owned(),
                record["kind"].as_str().map(str::to_owned),
                record["home_id"].as_str().map(str::to_owned),
            );
            let shapes = shape_contexts.entry(context.clone()).or_insert_with(|| {
                crate::query::cascade::facets_for_record_context(
                    &schema,
                    &context.0,
                    context.1.as_deref(),
                    context.2.as_deref(),
                )
            });
            let mut facets = serde_json::Map::new();
            for (key, stored, _, _) in fields {
                let declared = shapes.get(&key).and_then(|s| s["type"].as_str());
                let decoded = match declared {
                    Some("number" | "object") => serde_json::from_str::<Value>(&stored)
                        .ok()
                        .filter(|v| {
                            if declared == Some("number") {
                                v.is_number()
                            } else {
                                v.is_object()
                            }
                        })
                        .ok_or_else(|| {
                            Error::engine(
                                "artifact input contains a non-canonical declared facet value",
                            )
                        })?,
                    _ => Value::String(stored),
                };
                facets.insert(key, decoded);
            }
            value["facets"] = json!(facets);
            records.push(value);
        }
        if !exhaustive || page["has_more"] != true {
            break;
        }
        if members.is_empty() {
            return Err(Error::engine(
                "open_collection: membership paging did not advance",
            ));
        }
        offset += members.len();
    }
    records.sort_by(|a, b| {
        a["name"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .cmp(&b["name"].as_str().unwrap_or_default().to_lowercase())
            .then_with(|| a["id"].as_str().cmp(&b["id"].as_str()))
    });
    let renderers=sql::with_renderer_read_session(db,actor,rows(db,actor,"SELECT r.id,r.name FROM records r WHERE EXISTS(SELECT 1 FROM links l WHERE l.source_id=r.id AND l.relationship='renders' AND l.target_id=?1) ORDER BY r.name,r.id",vec![text(id)])).await?;
    Ok(
        json!({"status":"opened","surface":"neutral_table","collection":{"id":id,"kind":kind},"input":{"version":"native.artifact-input.v1","records":records},"renderers":renderers}),
    )
}

pub(super) async fn scope_ids(db: &Db, actor: &str, id: &str) -> Result<Vec<String>> {
    descriptor(db, actor, id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    // As in v1 subtree_ids, this is filing reachability, NOT authorization.
    // Walk hidden intermediate parents internally: an owner-visible child can
    // still belong to a visible scope through one. The kernel search fence
    // intersects every candidate with current capability before rank/count/output.
    // Use the existing imported/native home binding and move receipt, exactly
    // as logical SQL placement does; never use policy ancestry as filing.
    let ids: Vec<String> = sqlx::query_scalar(r#"
      WITH RECURSIVE homes AS (
        SELECT e.record_id AS home_id,json_extract(e.payload,'$.source_record_id') AS record_id
        FROM content_events e JOIN kernel_roots h ON h.root_id=e.record_id
        WHERE e.type IN ('kernel.import_home.v1','kernel.home_created.v1')
          AND json_extract(e.payload,'$.source_record_id') IS NOT NULL
      ), placement AS (
        SELECT r.id,coalesce(json_extract(moved.payload,'$.logical_home_id'),
          CASE WHEN home.record_id=r.id AND json_extract(original.payload,'$.legacy.payload.policy_anchor')=r.id
          THEN json_extract(original.payload,'$.legacy.payload.original_home')
          ELSE coalesce(home.record_id,r.home_id) END) AS home_id
        FROM kernel_records r LEFT JOIN homes home ON home.home_id=r.home_id
        LEFT JOIN content_events moved ON moved.seq=(SELECT max(e.seq) FROM content_events e
          WHERE e.record_id=r.id AND e.type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2'))
        LEFT JOIN content_events original ON original.seq=(SELECT max(h.seq) FROM kernel_legacy_sql_events h
          WHERE h.record_id=r.id AND h.source_stream='snapshot_provenance')
      ), tree(id) AS (
        SELECT ?1 UNION SELECT ?2 UNION SELECT p.id FROM placement p JOIN tree t ON p.home_id=t.id
      ) SELECT DISTINCT id FROM tree ORDER BY id
    "#).bind(id).bind(if [crate::events::KERNEL_ROOT_ID,"native:root"].contains(&id) {
        if id=="native:root" {crate::events::KERNEL_ROOT_ID} else {"native:root"}
    } else {id}).fetch_all(db.pool()).await?;
    Ok(ids)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct History {
    record_id: Option<String>,
    for_run: Option<String>,
    include_child_runs: Option<bool>,
    #[serde(alias = "after_seq")]
    after_local_seq: Option<i64>,
    limit: Option<i64>,
    order: Option<String>,
    detail: Option<String>,
    include_import_receipts: Option<bool>,
}
fn validate_history(args: &History) -> Result<(i64, bool)> {
    let children = args.include_child_runs.unwrap_or(false);
    if children && args.for_run.is_none() {
        return Err(Error::engine(
            "get_history include_child_runs requires for_run",
        ));
    }
    let limit = args.limit.unwrap_or(100);
    if !(1..=1000).contains(&limit) {
        return Err(Error::engine(
            "get_history limit must be between 1 and 1000",
        ));
    }
    let newest = match args.order.as_deref().unwrap_or("oldest_first") {
        "newest_first" => true,
        "oldest_first" => false,
        _ => return Err(unsupported("get_history", "order")),
    };
    if args
        .detail
        .as_deref()
        .is_some_and(|d| !["metadata", "full"].contains(&d))
    {
        return Err(unsupported("get_history", "detail"));
    }
    if args.include_import_receipts == Some(true) {
        return Err(unsupported(
            "get_history",
            "global import receipts; select one record",
        ));
    }
    if args.after_local_seq.is_some_and(|cursor| cursor < 0) {
        return Err(Error::engine("get_history: cursor must be nonnegative"));
    }
    Ok((limit, newest))
}

pub(super) async fn history(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let request: History = parse("get_history", args.clone())?;
    let (limit, newest) = validate_history(&request)?;
    let reads = &[
        ("content_events", "local_seq"),
        ("content_events", "record_id"),
        ("content_events", "run_key"),
        ("content_events", "parent_key"),
    ];
    if request.record_id.is_none() && request.for_run.is_none() {
        sql::with_history_read_session(
            db,
            actor,
            reads,
            sql::HistoryWindow {
                after: request.after_local_seq,
                newest,
                limit: limit as usize,
            },
            history_in_session(db, actor, args),
        )
        .await
    } else {
        sql::with_read_session(db, actor, reads, history_in_session(db, actor, args)).await
    }
}

pub(super) async fn history_in_session(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: History = parse("get_history", args)?;
    let (limit, newest) = validate_history(&args)?;
    let children = args.include_child_runs.unwrap_or(false);
    if let Some(id) = args.record_id.as_deref() {
        descriptor(db, actor, id)
            .await?
            .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    }
    let mut params = Vec::new();
    let mut clauses = Vec::new();
    if let Some(key) = &args.for_run {
        if !matches!(
            crate::runkey::validate_full(Some(key)),
            crate::runkey::KeyOutcome::Valid(_)
        ) {
            return Err(Error::engine("get_history: invalid for_run"));
        }
        if children {
            // Lineage is reachability, not disclosure. As in v1, a hidden
            // intermediate event must not hide an otherwise visible grandchild.
            // Only indexed/scalar event headers enter this private traversal;
            // the public SQL relation still filters every returned event.
            let mut snapshot = db.pool().begin().await?;
            kernel::app_installs::admit_dispatched_on(&mut snapshot, actor).await?;
            let keys: String = sqlx::query_scalar(r#"
              WITH RECURSIVE selected_runs(run_key) AS (
                SELECT ?1
                UNION SELECT e.run_key FROM main.content_events e JOIN selected_runs p
                  ON e.parent_key=p.run_key WHERE e.run_key IS NOT NULL
                UNION SELECT e.run_key FROM main.kernel_legacy_sql_events e JOIN selected_runs p
                  ON e.parent_key=p.run_key WHERE e.source_stream='content_events' AND e.run_key IS NOT NULL
              ) SELECT json_group_array(run_key) FROM selected_runs
            "#).bind(key).fetch_one(&mut *snapshot).await?;
            clauses.push(format!(
                "e.run_key IN (SELECT value FROM json_each({}))",
                bind(&mut params, text(&keys))
            ));
        } else {
            clauses.push(format!("e.run_key={}", bind(&mut params, text(key))));
        }
    }
    if let Some(id) = args.record_id {
        clauses.push(format!("e.record_id={}", bind(&mut params, text(&id))));
    }
    if let Some(after) = args.after_local_seq {
        if after < 0 {
            return Err(Error::engine("get_history: cursor must be nonnegative"));
        }
        clauses.push(format!(
            "e.local_seq{}{}",
            if newest { "<" } else { ">" },
            bind(&mut params, integer(after))
        ));
    }
    if clauses.is_empty() {
        clauses.push("1=1".into());
    }
    let where_sql = clauses.join(" AND ");
    let direction = if newest { "DESC" } else { "ASC" };
    let page=rows(db,actor,&format!("SELECT e.local_seq,e.record_id,e.run_key,e.parent_key FROM content_events e WHERE {where_sql} ORDER BY e.local_seq {direction} LIMIT {limit}"),params.clone()).await?;
    let last_scanned = page.last().and_then(|e| e["local_seq"].as_i64());
    let sequences = page
        .iter()
        .map(|h| h["local_seq"].as_i64().expect("header seq"))
        .collect::<Vec<_>>();
    let selected = kernel::history_headers_as(
        db,
        actor,
        &sequences,
        args.detail.as_deref() == Some("full"),
    )
    .await?
    .into_iter()
    .filter(|e| !super::migration_event(e))
    .collect();
    let hydrated = super::history_values(selected, args.detail.as_deref() == Some("full"), None)
        .into_iter()
        .map(|e| (e["local_seq"].as_i64().expect("event seq"), e))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut events = Vec::new();
    for header in page {
        if let Some(event) = hydrated.get(&header["local_seq"].as_i64().expect("header seq")) {
            let mut event = event.clone();
            // Logical retained headers carry the disclosed run lineage, while
            // their native wrapper may have a NULL run key.
            event["run_key"] = header["run_key"].clone();
            event["parent_key"] = header["parent_key"].clone();
            events.push(event);
        }
    }
    let next = if let Some(last) = last_scanned {
        let after = bind(&mut params, integer(last));
        let more=rows(db,actor,&format!("SELECT e.local_seq FROM content_events e WHERE {where_sql} AND e.local_seq{}{after} ORDER BY e.local_seq {direction} LIMIT 1",if newest {"<"}else{">"}),params).await?;
        (!more.is_empty()).then_some(last)
    } else {
        None
    };
    Ok(
        json!({"local_database_id":null,"events":events,"next_after_local_seq":next,"order":if newest {"newest_first"}else{"oldest_first"},"representation":{"detail":args.detail.as_deref().unwrap_or("metadata"),"payloads":"native unavailable; retained v1 payloads governed by record history"}}),
    )
}

/// The same placement boundary used by ordinary tree reads and member export.
pub(crate) async fn custody_boundary_on(
    connection: &mut sqlx::SqliteConnection,
    id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_records r JOIN main.content_events e ON e.record_id=r.home_id WHERE r.id=? AND e.type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(e.payload,'$.source_record_id')=r.id)").bind(id).fetch_one(connection).await?)
}

#[cfg(test)]
mod shape_label_tests {
    use super::*;
    use serde_json::json;

    fn label(args: Value) -> &'static str {
        let query: Query = serde_json::from_value(args).unwrap();
        let anchor = recognize_anchor(&query);
        shape_label(&query, anchor.as_ref())
    }

    #[test]
    fn query_record_shape_labels_are_static_and_match_the_selected_branch() {
        let cases = [
            (
                json!({"steps":[{"step":"filter","home_id":"h"}],"order":"name_asc"}),
                "p1_home",
            ),
            (
                json!({"steps":[{"step":"filter","ids":["a"]},{"step":"traverse","target":"links"}],"order":"name_asc"}),
                "p2_ids",
            ),
            (
                json!({"steps":[{"step":"filter","home_id":"h","lifecycle":["open"]}],"order":"name_asc"}),
                "p1_home",
            ),
            (
                json!({"steps":[{"step":"filter","ids":["a"]},{"step":"traverse","target":"links","relationship":"part_of","direction":"in"},{"step":"filter","kinds":["suggestion"],"lifecycle":["rejected"],"include_archived":true}],"order":"created_desc"}),
                "p2_ids",
            ),
            (
                json!({"steps":[{"step":"filter","home_id":"h","last_activity_since":"2000-01-01T00:00:00Z"}],"order":"name_asc"}),
                "fallback_row_filter",
            ),
            (
                json!({"steps":[{"step":"filter","home_id":"h","facets":[]}],"order":"name_asc"}),
                "fallback_row_filter",
            ),
            (
                json!({"steps":[{"step":"filter","types":["Resolution"],"maturity":["proposed"]}],"order":"name_asc"}),
                "fallback_unanchored",
            ),
            (
                json!({"steps":[{"step":"filter","home_id":"h","lifecycle":["open"]},{"step":"traverse","target":"links"}],"order":"name_asc"}),
                "fallback_home_then_step",
            ),
            (
                json!({"steps":[{"step":"filter","ids":["a"]},{"step":"traverse","target":"links"},{"step":"traverse","target":"links"}],"order":"name_asc"}),
                "fallback_multi_traverse",
            ),
            (
                json!({"steps":[{"step":"filter","ids":["a"]},{"step":"traverse","target":"children"}],"order":"name_asc"}),
                "fallback_traverse_tree",
            ),
            (
                json!({"steps":[{"step":"filter","ids":["a"],"home_id":"h"}],"order":"name_asc"}),
                "fallback_mixed_anchor",
            ),
            (
                json!({"steps":[{"step":"filter","types":["Document"]}],"order":"name_asc"}),
                "fallback_unanchored",
            ),
            (
                json!({"steps":[{"step":"traverse","target":"links"}],"order":"name_asc"}),
                "fallback_traverse_first",
            ),
            (
                json!({"steps":[{"step":"filter","ids":["a"]}],"order":"name_asc"}),
                "fallback_ids_only",
            ),
            (
                json!({"steps":[{"step":"filter","ids":[]},{"step":"traverse","target":"links"}],"order":"name_asc"}),
                "fallback_id_count",
            ),
            (
                json!({"steps":[{"step":"filter","ids":["a"]},{"step":"traverse","target":"links","direction":"sideways"}],"order":"name_asc"}),
                "fallback_link_direction",
            ),
            (
                json!({"steps":[{"step":"filter","ids":["a"]},{"step":"traverse","target":"links"},{"step":"filter","home_id":"h"}],"order":"name_asc"}),
                "fallback_trailing_anchor",
            ),
            (
                json!({"steps":[{"step":"filter","home_id":"h"},{"step":"traverse","target":"links"}],"order":"name_asc"}),
                "fallback_home_then_step",
            ),
        ];
        for (args, expected) in cases {
            let got = label(args.clone());
            assert_eq!(got, expected, "{args}");
            // Labels are fixed identifiers: never caller text.
            assert!(got
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_' || b.is_ascii_digit()));
        }
    }
}

#[cfg(test)]
mod ancestor_descriptor_tests {
    use super::*;
    use crate::events::KERNEL_ROOT_ID;

    /// Minimal six-note fixture filed in one logical chain under the virtual
    /// root. Unlike the engine-level tests, this harness drives `ancestors_on`
    /// directly so the regression exercise fits ordinary test stacks.
    struct Chain {
        _dir: tempfile::TempDir,
        db: Db,
        admin: String,
        ids: Vec<String>,
    }

    async fn file_insert(conn: &mut sqlx::SqliteConnection, id: &str, home: Option<&str>) {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES(?,?,'kernel.record_rehomed.v2',?,1,'legacy_unknown')")
            .bind(uuid::Uuid::new_v4().to_string()).bind(id)
            .bind(json!({"logical_home_id":home}).to_string()).execute(&mut *conn).await.unwrap();
    }

    async fn chain() -> Chain {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = kernel::create_v2_database(
            dir.path().join("v2.db").to_str().unwrap(),
            "account",
            "Admin",
            "acct:admin",
        )
        .await
        .unwrap();
        let definition = json!({
            "family": "fixture.mcp", "version": 1, "interpreter": "native.defn/2",
            "primary_type": "Document", "kinds": [{"token": "note", "description": "MCP fixture",
                "maturity": "current", "identity": {"field": "title"},
                "fields": [{"name": "title", "type": "text", "required": true}, {"name": "body", "type": "text", "required": false}],
                "links": [{"predicate": "relates_to", "target": {"primary_type": "Document", "kind": "note"}, "direction": "out", "cardinality": "many"}]}]
        });
        let pin = kernel::install_definition_as(
            &db,
            &admin,
            "fixture.mcp",
            1,
            &serde_json::to_vec(&definition).unwrap(),
        )
        .await
        .unwrap();
        kernel::adopt_definition_as(&db, &admin, &pin.family, Some(&pin))
            .await
            .unwrap();
        let mut ids = Vec::new();
        for n in 0..6 {
            ids.push(
                kernel::create_as(
                    &db,
                    &admin,
                    "fixture.mcp",
                    "note",
                    json!({"title": format!("ancestor {n}")})
                        .as_object()
                        .unwrap(),
                    KERNEL_ROOT_ID,
                )
                .await
                .unwrap(),
            );
        }
        let mut conn = db.write_pool().acquire().await.unwrap();
        for pair in ids.windows(2) {
            file_insert(&mut conn, &pair[0], Some(&pair[1])).await;
        }
        file_insert(&mut conn, ids.last().unwrap(), Some(KERNEL_ROOT_ID)).await;
        drop(conn);
        Chain {
            _dir: dir,
            db,
            admin,
            ids,
        }
    }

    /// Six-deep ancestor labels are identical before and after every ancestor
    /// carries a 64 KiB body lane: the descriptor path reads label fields
    /// only, so all 393,216 body bytes sit unread while labels stay small.
    #[tokio::test]
    async fn ancestor_labels_ignore_large_body_lanes() {
        // Box large debug futures at construction so they do not all occupy
        // the outer test's stack frame (precedent: bounded_placement_call).
        let c = Box::pin(chain()).await;
        let leaf = c.ids[0].clone();
        let mut conn = c.db.write_pool().acquire().await.unwrap();
        let (before, visible) = Box::pin(ancestors_on(&mut conn, &c.admin, &leaf))
            .await
            .unwrap();
        assert!(visible);
        assert_eq!(before.len(), 6);
        assert_eq!(before[0]["id"], json!(KERNEL_ROOT_ID));
        assert_eq!(
            before[1],
            json!({"id": c.ids[5], "type": "Document", "kind": "note", "name": "ancestor 5"}),
        );
        drop(conn);

        for id in &c.ids {
            let big = "y".repeat(64 * 1024);
            let revision = Box::pin(kernel::read_record_as(&c.db, &c.admin, id))
                .await
                .unwrap()
                .unwrap()
                .revision;
            Box::pin(kernel::set_body_as(&c.db, &c.admin, id, &big, revision))
                .await
                .unwrap();
        }

        let mut conn = c.db.write_pool().acquire().await.unwrap();
        let body_bytes: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(LENGTH(body)),0) FROM kernel_record_bodies WHERE record_id IN (SELECT value FROM json_each(?))",
        )
        .bind(serde_json::to_string(&c.ids).unwrap())
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        assert_eq!(body_bytes, 6 * 64 * 1024);
        let (after, visible) = Box::pin(ancestors_on(&mut conn, &c.admin, &leaf))
            .await
            .unwrap();
        assert!(visible);
        assert_eq!(after, before);
        let labels = serde_json::to_string(&after).unwrap();
        assert!(labels.len() < 4096, "labels stay small: {labels}");
        drop(conn);
        c.db.close().await;
    }

    /// A malformed unrelated field breaks full hydration but not ancestor
    /// labels: the metadata projection only parses the label-relevant fields.
    /// Deliberate boundary change from the old full-hydration descriptor path.
    #[tokio::test]
    async fn ancestor_labels_skip_unrelated_malformed_fields() {
        let c = Box::pin(chain()).await;
        let parent = c.ids[1].clone();
        let leaf = c.ids[0].clone();
        let mut conn = c.db.write_pool().acquire().await.unwrap();
        let (clean, _) = Box::pin(ancestors_on(&mut conn, &c.admin, &leaf))
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO kernel_record_fields (record_id, name, value_json, created_seq) VALUES (?, 'unrelated', 'not-json', 1)",
        )
        .bind(&parent)
        .execute(&mut *conn)
        .await
        .unwrap();
        assert!(
            Box::pin(kernel::read_record_on(&mut conn, &c.admin, &parent))
                .await
                .is_err(),
            "full hydration parses the unrelated field"
        );
        assert!(
            Box::pin(kernel::read_record_metadata_on(
                &mut conn, &c.admin, &parent
            ))
            .await
            .unwrap()
            .is_some(),
            "metadata projection skips unrelated fields"
        );
        let (poisoned, visible) = Box::pin(ancestors_on(&mut conn, &c.admin, &leaf))
            .await
            .unwrap();
        assert!(visible);
        assert_eq!(poisoned, clean);
        drop(conn);
        c.db.close().await;
    }
}
