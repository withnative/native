//! V1 apps.rs:35/history.rs:4021: record versions under current authority.
use super::*;
use crate::authorization::Capability;
use kernel::historical::RecordState;
use sqlx::SqliteConnection;
use std::collections::BTreeMap;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    record_id: String,
    before_seq: Option<i64>,
    before_event_id: Option<String>,
}
async fn can(conn: &mut SqliteConnection, actor: &str, id: &str) -> Result<bool> {
    let id = if id == "native:root" {
        crate::events::KERNEL_ROOT_ID
    } else {
        id
    };
    match kernel::kernel_effective_capability_on(conn, actor, id).await {
        Ok(cap) => Ok(cap.allows(Capability::View)),
        Err(Error::Engine(message)) if message == kernel::HIDDEN_OR_MISSING => Ok(false),
        Err(error) => Err(error),
    }
}
async fn home_on(
    conn: &mut SqliteConnection,
    id: &str,
    home: &str,
    seq: i64,
) -> Result<Option<String>> {
    let moved:Option<String>=sqlx::query_scalar("SELECT json_extract(payload,'$.logical_home_id') FROM content_events WHERE record_id=? AND seq<=? AND type IN ('kernel.record_rehomed.v1','kernel.record_rehomed.v2') ORDER BY seq DESC LIMIT 1").bind(id).bind(seq).fetch_optional(&mut *conn).await?.flatten();
    if moved.is_some() {
        return Ok(moved);
    }
    let provenance: Option<(Option<String>,Option<String>)> = sqlx::query_as("SELECT json_extract(e.payload,'$.legacy.payload.policy_anchor'),json_extract(e.payload,'$.legacy.payload.original_home') FROM kernel_legacy_sql_events h JOIN content_events e ON e.seq=h.seq WHERE h.record_id=? AND h.seq<=? AND h.source_stream='snapshot_provenance' ORDER BY h.seq DESC LIMIT 1")
        .bind(id).bind(seq).fetch_optional(&mut *conn).await?;
    if home == crate::v1_import::derived(id) {
        if let Some((anchor, original)) = provenance {
            if anchor.as_deref() == Some(id) {
                return Ok(original);
            }
        }
    }
    let mapped:Option<String>=sqlx::query_scalar("SELECT json_extract(payload,'$.source_record_id') FROM content_events WHERE record_id=? AND seq<=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id') IS NOT NULL ORDER BY seq LIMIT 1").bind(home).bind(seq).fetch_optional(&mut *conn).await?;
    if mapped.is_some() {
        return Ok(mapped);
    }
    if home == crate::events::KERNEL_ROOT_ID {
        let imported:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id='native:root' AND created_seq<=?) OR EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND seq<=? AND type='kernel.import_home_policy.v1')").bind(seq).bind(home).bind(seq).fetch_one(&mut *conn).await?;
        if imported {
            return Ok(Some("native:root".into()));
        }
    }
    Ok(Some(home.into()))
}

/// A bounded, memoized subject reader. Head reads use the live projection;
/// historical reads never open a database or replay another record's state.
struct Projection<'a> {
    live: &'a mut SqliteConnection,
    seq: i64,
    historical: bool,
    records: BTreeMap<String, Option<RecordState>>,
}
impl Projection<'_> {
    async fn record(&mut self, actor: &str, id: &str) -> Result<Option<RecordState>> {
        if !self.records.contains_key(id) {
            let state = if self.historical {
                kernel::historical::record_at_on(self.live, actor, id, self.seq).await?
            } else {
                current_record(self.live, actor, id).await?
            };
            self.records.insert(id.to_owned(), state);
        }
        Ok(self.records[id].clone())
    }
    async fn home(&mut self, id: &str, home: &str) -> Result<Option<String>> {
        home_on(self.live, id, home, self.seq).await
    }
}
async fn current_record(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<Option<RecordState>> {
    let Some(record) = kernel::read_record_on(conn, actor, id).await? else {
        return Ok(None);
    };
    let (primary_type, created_at): (Option<String>, String) =
        sqlx::query_as("SELECT primary_type,created_at FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *conn)
            .await?;
    let created_at=sqlx::query_scalar::<_,String>("SELECT created_at FROM kernel_legacy_sql_events WHERE record_id=? AND source_stream='snapshot_provenance' ORDER BY seq DESC LIMIT 1").bind(id).fetch_optional(&mut *conn).await?.unwrap_or(created_at);
    let updated_at: String =
        sqlx::query_scalar("SELECT created_at FROM content_events WHERE seq=?")
            .bind(record.revision)
            .fetch_one(&mut *conn)
            .await?;
    let facets:Vec<kernel::FacetObservation>=sqlx::query_as("SELECT key,value,value_num,vocab_ref,as_of FROM kernel_facets WHERE record_id=? ORDER BY key").bind(id).fetch_all(&mut *conn).await?;
    let blob: Option<String> =
        sqlx::query_scalar("SELECT metadata FROM kernel_attachment_blobs WHERE record_id=?")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await?;
    Ok(Some(RecordState {
        home_id: record.home_id,
        owner_id: record.owner_id,
        primary_type,
        kind: record.kind,
        pin: record.pin,
        fields: record.fields,
        metadata: record.metadata,
        body: record.body,
        archived: record.archived,
        revision: record.revision,
        created_at,
        updated_at,
        facets: facets.into_iter().map(|f| (f.key.clone(), f)).collect(),
        blob: blob.map(|raw| serde_json::from_str(&raw)).transpose()?,
    }))
}
async fn descriptor(view: &mut Projection<'_>, actor: &str, id: &str) -> Result<Option<Value>> {
    let Some(record) = view.record(actor, id).await? else {
        return Ok(None);
    };
    let (typ, kind) = v1_type_and_kind(
        record.pin.as_ref().map(|p| p.family.as_str()),
        record.pin.as_ref().map(|p| p.version),
        record.primary_type.as_deref(),
        record.kind.as_deref(),
        &record.fields,
    );
    Ok(Some(
        json!({"id":id,"type":typ,"kind":kind,"name":record.fields.get("title").or_else(||record.fields.get("name")),"summary":record.fields.get("summary"),"lifecycle":record.fields.get("lifecycle"),"archived":record.archived,"home_id":view.home(id,&record.home_id).await?,"persistence":record.metadata.persistence,"maturity":record.metadata.maturity}),
    ))
}
async fn safe_descriptor(
    view: &mut Projection<'_>,
    actor: &str,
    id: &str,
) -> Result<Option<Value>> {
    let Some(mut value) = descriptor(view, actor, id).await? else {
        return Ok(None);
    };
    if let Some(home) = value["home_id"].as_str() {
        if !can(view.live, actor, home).await? {
            value["home_id"] = Value::Null;
        }
    }
    Ok(Some(value))
}
async fn links(view: &mut Projection<'_>, actor: &str, id: &str) -> Result<Vec<Value>> {
    if !view.historical {
        return live_links(view.live, actor, id).await;
    }
    let candidates = kernel::historical::links_at_on(view.live, actor, id, view.seq).await?;
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for mut row in candidates {
        let subjects = row.as_object_mut().unwrap().remove("_subjects");
        let mut visible = true;
        if let Some(subjects) = subjects {
            for subject in subjects.as_array().unwrap() {
                if !can(view.live, actor, subject.as_str().unwrap()).await? {
                    visible = false;
                    break;
                }
            }
        }
        let source = row["source_id"].as_str().unwrap();
        let target = row["target_id"].as_str().unwrap();
        if visible
            && can(view.live, actor, source).await?
            && can(view.live, actor, target).await?
            && seen.insert((
                source.to_owned(),
                target.to_owned(),
                row["relationship"].as_str().unwrap().to_owned(),
            ))
        {
            rows.push(row);
        }
    }
    rows.sort_by_key(|r| {
        ["relationship", "created_at", "id", "source_id", "target_id"]
            .map(|key| r[key].as_str().unwrap_or_default().to_owned())
    });
    Ok(rows)
}
async fn live_links(conn: &mut SqliteConnection, actor: &str, id: &str) -> Result<Vec<Value>> {
    let generic:Vec<String>=sqlx::query_scalar("SELECT json_object('id',link_id,'source_id',source_id,'target_id',target_id,'relationship',relationship,'note',note,'created_at',created_at) FROM kernel_generic_links WHERE active=1 AND (source_id=? OR target_id=?) ORDER BY link_id").bind(id).bind(id).fetch_all(&mut *conn).await?;
    let legacy:Vec<String>=sqlx::query_scalar("SELECT json_object('id',NULL,'source_id',l.source_id,'target_id',l.target_id,'relationship',l.relationship,'note',NULL,'created_at',e.created_at) FROM kernel_links l JOIN content_events e ON e.seq=l.created_seq WHERE l.source_id=? OR l.target_id=?").bind(id).bind(id).fetch_all(&mut *conn).await?;
    let mut candidates: Vec<Value> = generic
        .into_iter()
        .chain(legacy)
        .map(|raw| serde_json::from_str(&raw))
        .collect::<std::result::Result<_, _>>()?;
    let states:Vec<(String,String)>=sqlx::query_as("SELECT id,state_json FROM kernel_provider_state WHERE provider_key='relates_to.v1' AND id IN (SELECT aggregate_id FROM kernel_provider_subjects WHERE subject_id=?)").bind(id).fetch_all(&mut *conn).await?;
    for (aggregate, state) in states {
        let subjects: Vec<String> = sqlx::query_scalar(
            "SELECT subject_id FROM kernel_provider_subjects WHERE aggregate_id=?",
        )
        .bind(aggregate)
        .fetch_all(&mut *conn)
        .await?;
        let mut visible = true;
        for subject in subjects {
            if !can(&mut *conn, actor, &subject).await? {
                visible = false;
                break;
            }
        }
        if !visible {
            continue;
        }
        if let Some((left, right)) = kernel::relates_to_port::active_pair_from_state(&state)? {
            for (source, target) in [(&left, &right), (&right, &left)] {
                candidates.push(json!({"id":null,"source_id":source,"target_id":target,"relationship":"relates_to","note":null,"created_at":null}));
            }
        }
    }
    let mut rows = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for row in candidates {
        let source = row["source_id"].as_str().unwrap();
        let target = row["target_id"].as_str().unwrap();
        if can(&mut *conn, actor, source).await?
            && can(&mut *conn, actor, target).await?
            && seen.insert((
                source.to_owned(),
                target.to_owned(),
                row["relationship"].as_str().unwrap().to_owned(),
            ))
        {
            rows.push(row);
        }
    }
    rows.sort_by_key(|r| {
        ["relationship", "created_at", "id", "source_id", "target_id"]
            .map(|key| r[key].as_str().unwrap_or_default().to_owned())
    });
    Ok(rows)
}
async fn record_at(
    live: &mut SqliteConnection,
    actor: &str,
    id: &str,
    seq: i64,
    historical: bool,
) -> Result<Value> {
    let mut view = Projection {
        live,
        seq,
        historical,
        records: BTreeMap::new(),
    };
    let record = view
        .record(actor, id)
        .await?
        .ok_or_else(|| Error::engine(format!("record {id} has no state as of seq {seq}")))?;
    let mut value = descriptor(&mut view, actor, id).await?.unwrap();
    let body = record
        .effective_body()
        .map(|body| json!(body))
        .unwrap_or(Value::Null);
    value["body"] = body.clone();
    value["body_digest"] = json!(crate::mcp::tools::lifecycle::body_digest(body.as_str()));
    value["fields"] = json!(record.fields);
    value["version"] = json!(format!("rec:{}", record.revision));
    value["record_version"] = value["version"].clone();
    value["owner_id"] = if record.owner_id.as_deref() == Some(actor)
        || can(view.live, actor, crate::events::KERNEL_ROOT_ID).await?
    {
        json!(record.owner_id)
    } else {
        Value::Null
    };
    value["created_at"] = json!(record.created_at);
    value["updated_at"] = json!(record.updated_at);
    value["last_activity_at"] = json!(record.metadata.last_activity_at);
    if let Some(home) = value["home_id"].as_str() {
        if !can(view.live, actor, home).await? {
            value["home_id"] = Value::Null;
        }
    }
    let interpreter = kernel::v1_state::interpreter_on(view.live, actor).await?;
    let shapes = crate::query::cascade::facets_for_record_context(
        interpreter.schema_rows(),
        value["type"].as_str().unwrap_or_default(),
        value["kind"].as_str(),
        None,
    );
    value["bears_shape"] = json!(crate::query::cascade::bears_shape_from_rows(
        interpreter.schema_rows(),
        id
    ));
    value["deleted_at"] = Value::Null;
    value["custody_boundary"]=json!(sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND seq<=? AND type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(payload,'$.source_record_id')=?)").bind(&record.home_id).bind(seq).bind(id).fetch_one(&mut *view.live).await?);
    if value["type"] == "Document" && value["kind"] == "attachment" {
        value["blob"] = record.blob.clone().unwrap_or(Value::Null);
    }
    value["facets"] = json!(record
        .facets
        .values()
        .filter(|facet| facet.value.is_some() && facet.key != "archived")
        .map(|facet| {
            let key = facet.key.clone();
            let value = facet.value.clone();
            let vocab_ref = facet.vocab_ref.clone();
            let object_typed = crate::domain_transaction::declared_type_is_json_object(
                shapes.get(&key).and_then(|shape| shape["type"].as_str()),
            );
            crate::query::FacetValueRow {
                key,
                value: value.map(|stored| {
                    if object_typed {
                        serde_json::from_str::<Value>(&stored)
                            .ok()
                            .filter(Value::is_object)
                            .unwrap_or(Value::String(stored))
                    } else {
                        Value::String(stored)
                    }
                }),
                vocab_ref,
                version: None,
            }
        })
        .collect::<Vec<_>>());
    let links = links(&mut view, actor, id).await?;
    for (field, endpoint) in [("links_out", "source_id"), ("links_in", "target_id")] {
        let rows: Vec<_> = links.iter().filter(|row| row[endpoint] == id).collect();
        value[format!("{field}_count")] = json!(rows.len());
        value[field] = json!(rows
            .into_iter()
            .take(crate::query::read::DEFAULT_ENRICH_LIMIT as usize)
            .collect::<Vec<_>>());
    }
    let child_ids = if view.historical {
        kernel::historical::child_candidates_on(view.live, id, seq).await?
    } else {
        sqlx::query_scalar::<_,String>("SELECT r.id FROM kernel_records r WHERE r.id<>?1 AND (r.home_id=?1 OR r.home_id IN (SELECT e.record_id FROM content_events e WHERE e.type IN ('kernel.import_home.v1','kernel.home_created.v1') AND json_extract(e.payload,'$.source_record_id')=?1)) ORDER BY r.id").bind(id).fetch_all(&mut *view.live).await?
    };
    let mut children = Vec::new();
    for child in child_ids {
        if child == id || !can(view.live, actor, &child).await? {
            continue;
        }
        let Some(state) = view.record(actor, &child).await? else {
            continue;
        };
        if view.home(&child, &state.home_id).await?.as_deref() != Some(id) {
            continue;
        }
        if let Some(child) = safe_descriptor(&mut view, actor, &child).await? {
            if child["type"] != "Annotation"
                && !(child["type"] == "Document" && child["kind"] == "attachment")
            {
                children.push(child);
            }
        }
    }
    children.sort_by_key(|r| {
        (
            r["name"].as_str().unwrap_or_default().to_lowercase(),
            r["id"].as_str().unwrap().to_owned(),
        )
    });
    value["child_count"] = json!(children.len());
    value["children"] = json!(children
        .into_iter()
        .take(crate::query::read::DEFAULT_ENRICH_LIMIT as usize)
        .collect::<Vec<_>>());
    for (kind, key) in [
        ("suggestion", "suggestion_count"),
        ("citation", "citation_count"),
        ("comment", "comment_count"),
    ] {
        let ids: Vec<String> = links
            .iter()
            .filter(|link| link["relationship"] == "part_of" && link["target_id"] == id)
            .filter_map(|link| link["source_id"].as_str().map(str::to_owned))
            .collect();
        let mut count = 0;
        for child in ids {
            if !can(view.live, actor, &child).await? {
                continue;
            }
            if let Some(child) = safe_descriptor(&mut view, actor, &child).await? {
                if child["type"] == "Annotation" && child["kind"] == kind {
                    count += 1;
                }
            }
        }
        value[key] = json!(count);
    }
    let mut ancestors = Vec::new();
    let mut next = view.home(id, &record.home_id).await?;
    let mut seen = std::collections::BTreeSet::from([id.to_owned()]);
    let mut path_visible = true;
    for _ in 0..100 {
        let Some(parent) = next.take() else {
            break;
        };
        if !seen.insert(parent.clone()) || !can(view.live, actor, &parent).await? {
            path_visible = false;
            break;
        }
        let Some(parent) = descriptor(&mut view, actor, &parent).await? else {
            if !["native:root", crate::events::KERNEL_ROOT_ID].contains(&parent.as_str()) {
                path_visible = false;
            }
            break;
        };
        next = parent["home_id"].as_str().map(str::to_owned);
        let mut parent = parent;
        if let Some(next_id) = next.as_deref() {
            if !can(view.live, actor, next_id).await? {
                parent["home_id"] = Value::Null;
                path_visible = false;
                next = None;
            }
        }
        ancestors.push(parent);
    }
    ancestors.reverse();
    value["ancestors"] = json!(ancestors);
    value["containment_path_visible"] = json!(path_visible);
    // Kind/lifecycle governance comes from the currently authorized schema,
    // applied to the historical value and historical logical filing home.
    let typ = value["type"].as_str().unwrap_or_default();
    let kind = value["kind"].as_str();
    value["lifecycle_interpretation"] = serde_json::to_value(interpreter.interpret(
        typ,
        kind,
        value["home_id"].as_str(),
        value["lifecycle"].as_str(),
    ))?;
    Ok(json!({"as_of_seq":seq,"record":value}))
}

pub(super) async fn render(db: &Db, actor: &str, args: Value) -> Result<Value> {
    let args: Args = parse("render_record_version_diff", args)?;
    let mut live = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut live, actor).await?;
    kernel::read_record_on(&mut live, actor, &args.record_id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    kernel::legacy_history::require_sql_frontier_on(&mut live).await?;
    let before = match (args.before_seq, args.before_event_id) {
        (Some(seq), None) => seq,
        (None, Some(_)) => {
            return Err(unsupported(
                "render_record_version_diff",
                "event-id historical positions; use before_seq",
            ))
        }
        _ => {
            return Err(Error::engine(
                "render_record_version_diff takes exactly one of before_seq or before_event_id",
            ))
        }
    };
    if before < 1 {
        return Err(Error::engine(
            "render_record_version_diff before_seq must be positive",
        ));
    }
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *live)
        .await?;
    if before > head {
        return Err(Error::engine(format!("render_record_version_diff before_seq {before} is after the current content head {head}")));
    }
    // Classify only an event disclosed on the View-checked record. A global
    // cutoff or an event withheld for hidden dependencies must not reveal its
    // retained/native type through a different refusal.
    let position = kernel::history_page_in_range_on(
        &mut live,
        actor,
        &args.record_id,
        Some(before - 1),
        false,
        1,
        false,
        false,
        (before, before),
    )
    .await?;
    if position
        .iter()
        .any(|event| event.event_type == "kernel.legacy_recorded.v1")
    {
        return Err(Error::engine("render_record_version_diff: source_position_unavailable: retained v1 provenance is not a reconstructable v2 record version"));
    }
    let started = std::time::Instant::now();
    let older = record_at(&mut live, actor, &args.record_id, before, true).await?;
    tracing::debug!(target:"native_ce::read_staging",phase="historical_before",elapsed_us=started.elapsed().as_micros() as u64);
    let started = std::time::Instant::now();
    let after = record_at(&mut live, actor, &args.record_id, head, false).await?;
    tracing::debug!(target:"native_ce::read_staging",phase="historical_after",elapsed_us=started.elapsed().as_micros() as u64);
    let mut events = Vec::new();
    let mut cursor = before;
    loop {
        let page = kernel::history_page_in_range_on(
            &mut live,
            actor,
            &args.record_id,
            Some(cursor),
            false,
            256,
            true,
            false,
            (before + 1, head),
        )
        .await?;
        if page.is_empty() {
            break;
        }
        let last = page.last().unwrap().seq;
        for event in page {
            if !migration_event(&event) {
                events.push(super::event_context::shaped(&mut live, actor, event).await?);
            }
        }
        if last <= cursor {
            return Err(Error::engine("history cursor did not advance"));
        }
        cursor = last;
    }
    live.rollback().await?;
    Ok(
        json!({"view":"record_version_diff","record_id":args.record_id,"before":older,"after":after,"events":events}),
    )
}
