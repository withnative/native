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
async fn section(
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
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let vocabularies = kernel::v1_state::rows_on(&mut tx, "vocabularies").await?;
    let vocabulary = vocabularies.iter().find(|v| v["name"] == "kind:Annotation");
    let values = kernel::v1_state::rows_on(&mut tx, "vocabulary_values").await?;
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
    Ok(result)
}

pub(super) async fn enrich(
    db: &Db,
    actor: &str,
    id: &str,
    opts: &crate::query::read::EnrichOptions,
    artifact_kinds: &[Vec<String>; 2],
    history: bool,
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
    let (count, children) = section(
        db,
        actor,
        &child_predicate,
        child_params,
        "r.name,r.id",
        opts.children_limit,
        opts.children_offset,
    )
    .await?;
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
        let tokens = serde_json::to_string(&artifact_kinds[index])?;
        let (count, page) = section(db, actor,
            "r.type='Annotation' AND r.kind IN (SELECT value FROM json_each(?1)) AND EXISTS(SELECT 1 FROM links l WHERE l.source_id=r.id AND l.relationship='part_of' AND l.target_id=?2)",
            vec![text(&tokens),text(id)],"r.created_at,r.id",if enabled {limit} else {0},offset).await?;
        value[format!("{kind}_count")] = count;
        if enabled {
            value[format!("{kind}s")] = page;
        }
    }
    value["ancestors"] = json!(ancestors(db, actor, id).await?.0);
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
    },
    Traverse {
        target: String,
        relationship: Option<String>,
        direction: Option<String>,
    },
}
fn bind(parameters: &mut Vec<Value>, value: Value) -> String {
    parameters.push(value);
    format!("?{}", parameters.len())
}

pub(super) async fn query_record(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: Query = parse("query_record", args)?;
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
    let hidden: Vec<&str> = ["comment", "suggestion", "citation"]
        .into_iter()
        .filter(|kind| !families.contains(kind))
        .collect();
    let mut hidden_clause="NOT (r.type='Annotation' AND coalesce(r.kind,'') IN ('attribution','acknowledgement')) AND NOT (r.type='Entity' AND r.kind IS 'semantic-unit')".to_string();
    for kind in hidden {
        let placeholder = bind(&mut parameters, text(kind));
        hidden_clause.push_str(&format!(
            " AND NOT (r.type='Annotation' AND r.kind IS {placeholder})"
        ));
    }
    for step in args.steps {
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
    let total = rows(
        db,
        actor,
        &format!("SELECT count(*) AS n FROM (SELECT r.id FROM records r WHERE r.id IN ({selected})) eligible"),
        parameters.clone(),
    )
    .await?[0]["n"]
        .as_u64()
        .unwrap_or(0) as usize;
    let page = parameters.len() + 1;
    parameters.extend([integer(limit), integer(offset)]);
    let ids=rows(db,actor,&format!("SELECT r.id FROM records r WHERE r.id IN ({selected}) ORDER BY {order} LIMIT ?{page} OFFSET ?{}",page+1),parameters).await?;
    let ids: Vec<String> = ids
        .iter()
        .filter_map(|row| row["id"].as_str().map(str::to_owned))
        .collect();
    let mut records = Vec::with_capacity(ids.len());
    // Keep body hydration window-bounded, and use get's exact Message origin,
    // lifecycle, owner and logical home rendering. No pre-page record reads.
    for id in ids {
        if let Some(record) = kernel::read_record_as(db, actor, &id).await? {
            records.push(record_value(db, actor, &record).await?);
        }
    }
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
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    if !kernel::kernel_effective_capability_on(&mut tx, actor, crate::events::KERNEL_ROOT_ID)
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
    let (seq,created,updated):(i64,String,String)=sqlx::query_as("SELECT max(seq),min(created_at),max(created_at) FROM content_events WHERE record_id IN (?,?)").bind(crate::events::KERNEL_ROOT_ID).bind(kernel::workspace_metadata::RECORD_ID).fetch_one(&mut *tx).await?;
    tx.rollback().await?;
    let metadata = kernel::workspace_metadata::read(db).await?;
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
pub(super) async fn get_structure(db: &Db, actor: &str, args: Value) -> Result<Value> {
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
            let boundary:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r JOIN content_events e ON e.record_id=r.home_id WHERE r.id=? AND e.type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(e.payload,'$.source_record_id')=r.id)").bind(&id).fetch_one(db.pool()).await?;
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

async fn ancestors(db: &Db, actor: &str, id: &str) -> Result<(Vec<Value>, bool)> {
    let mut chain = Vec::new();
    let mut seen = std::collections::BTreeSet::from([id.to_string()]);
    let mut terminal_root = [crate::events::KERNEL_ROOT_ID, "native:root"].contains(&id);
    let mut next = crate::v1_import::placement_as(db, actor, id)
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
        let Some(value) = descriptor(db, actor, &id).await? else {
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
    let args: Collection = parse("open_collection", args)?;
    let record = descriptor(db, actor, &args.id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    let kind = record["kind"].as_str().unwrap_or_default();
    if record["type"] != "Collection" || !["folder", "selection", "query"].contains(&kind) {
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
                SavedQueryInspection::GovernedSql { .. } => return Err(Error::engine(
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
    let mut records = Vec::new();
    let mut offset = 0;
    loop {
        if exhaustive {
            query["limit"] = json!(500);
            query["offset"] = json!(offset);
        }
        let page = query_record(db, actor, query.clone()).await?;
        let members = page["records"].as_array().ok_or_else(|| {
            Error::engine("Collection kind:query must resolve to records, not a count or aggregate")
        })?;
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
            let fields =
                metadata_reads::facet_values(db, actor, record["id"].as_str().expect("member id"))
                    .await?;
            let shapes = crate::query::cascade::facets_for_record_context(
                &schema,
                record["type"].as_str().unwrap_or_default(),
                record["kind"].as_str(),
                record["home_id"].as_str(),
            );
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
    let renderers=rows(db,actor,"SELECT r.id,r.name FROM records r WHERE EXISTS(SELECT 1 FROM links l WHERE l.source_id=r.id AND l.relationship='renders' AND l.target_id=?1) ORDER BY r.name,r.id",vec![text(id)]).await?;
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
pub(super) async fn history(db: &Db, actor: &str, args: Value) -> Result<Value> {
    sql::with_read_session(
        db,
        actor,
        &[
            ("content_events", "local_seq"),
            ("content_events", "record_id"),
            ("content_events", "run_key"),
            ("content_events", "parent_key"),
        ],
        history_in_session(db, actor, args),
    )
    .await
}
pub(super) async fn history_in_session(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: History = parse("get_history", args)?;
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
