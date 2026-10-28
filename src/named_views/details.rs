//! Bounded retained metadata reads. All payloads follow closure authorization.
use super::*;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use serde_json::{json, Value};
use std::sync::OnceLock;

pub(crate) fn summary(name: &str, pin: &Pin, def: &contract::Definition) -> Value {
    json!({"relation_name":name,"view_id":pin.view_id,"revision_id":pin.revision_id,
        "definition_sha256":pin.definition_sha256,"schema_sha256":pin.schema_sha256,
        "origin":def.origin,"description":def.description,"scope":def.scope,
        "source_pins":def.source_pins,"dependencies":def.query.relations,"columns":def.columns})
}
fn bearer(view: &str) -> Result<&str> {
    view.strip_prefix("native.named-view:")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("view_missing"))
}
async fn pin_on(
    conn: &mut SqliteConnection,
    actor: &str,
    view: &str,
    id: &str,
    head: i64,
    deadline: Instant,
) -> Result<Pin> {
    storage::check_deadline(deadline)?;
    // Metadata stays readable on archived bearers with current View.
    closure::require_accessible_bearer_on(
        conn,
        actor,
        bearer(view)?,
        &mut std::collections::BTreeSet::new(),
        false,
    )
    .await?;
    let header:Option<(String,String,i64)>=sqlx::query_as("SELECT record_id,type,length(CAST(payload AS BLOB)) FROM content_events WHERE id=? AND seq<=?").bind(id).bind(head).fetch_optional(&mut *conn).await?;
    if !header.is_some_and(|(record, kind, bytes)| {
        record == bearer(view).unwrap_or_default()
            && kind == REVISION
            && (0..=MAX_CARRIER_BYTES as i64).contains(&bytes)
    }) {
        return Err(invalid("view_revision_unavailable"));
    }
    let event = read_event(conn, id, head).await?;
    let rev: Revision = decode(&event, MAX_CARRIER_BYTES)?;
    let def = rev.validate_retained(&event)?;
    let pin = Pin {
        view_id: view.into(),
        revision_id: id.into(),
        definition_sha256: rev.definition_sha256,
        schema_sha256: def.query.output.schema_sha256,
    };
    Ok(pin)
}
// Owned by one metadata read and caller snapshot, never a permission cache.
type MetadataContexts = BTreeMap<String, Option<(i64, super::source_proof::Work)>>;

async fn metadata_on(
    conn: &mut SqliteConnection,
    actor: &str,
    view: &str,
    id: &str,
    deadline: Instant,
    advisory: bool,
    contexts: &mut MetadataContexts,
) -> Result<Value> {
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *conn)
        .await?;
    let pin = pin_on(conn, actor, view, id, head, deadline).await?;
    let roots = BTreeMap::from([("view_detail".into(), pin.clone())]);
    let inspected = closure::inspect_metadata_on(conn, actor, &roots, deadline).await?;
    if let Some(revision) = inspected.retained.get(&pin).filter(|r| r.v == 2) {
        let definition: v2::Definition = serde_json::from_value(revision.definition.clone())?;
        let workspace = super::generated::workspace_on(conn).await?;
        if definition.generated.workspace_id != workspace {
            return Err(Error::engine(MISSING));
        }
        super::retained_facets::required_presence_on(conn, &definition, deadline).await?;
        if definition.query.validate_for_preparation().is_err() {
            return Ok(
                json!({"pin":pin,"definition":revision.definition,"diagnostic":"view_source_invalidated"}),
            );
        }
        // Archival prevents execution but does not revoke metadata visibility.
        // A carrier move alone says nothing about retained source context H;
        // normalize that actual context below, as execution does.
        storage::check_deadline(deadline)?;
        if inspected.drifted {
            return Ok(
                json!({"pin":pin,"definition":revision.definition,"diagnostic":"view_context_unavailable"}),
            );
        }
        // View and required presence were checked independently above for this
        // revision. Reuse only context normalization within this read: versions
        // sharing H/anchors must not repeat a historical home-witness scan.
        let anchors: std::collections::BTreeSet<_> = definition
            .generated
            .sources
            .iter()
            .filter_map(|source| source.anchor.as_deref())
            .collect();
        let key =
            serde_json::to_string(&(head, &definition.generated.context.logical_home_id, anchors))?;
        let context = if let Some(context) = contexts.get(&key) {
            *context
        } else {
            let result = super::source_proof::retained_context_on(
                conn,
                actor,
                bearer(view)?,
                &definition.generated,
                deadline,
            )
            .await;
            storage::check_deadline(deadline)?;
            let context = match result {
                Ok(context) => Some(context),
                // These are context failures only after same-snapshot current
                // View and required presence; SQL/IO and deadline still refuse.
                Err(Error::Engine(message))
                    if message == MISSING || message == "named view: view_missing" =>
                {
                    None
                }
                Err(Error::Conflict(_)) => None,
                Err(error) => return Err(error),
            };
            contexts.insert(key, context);
            context
        };
        let Some(context) = context else {
            return Ok(
                json!({"pin":pin,"definition":revision.definition,"diagnostic":"view_context_unavailable"}),
            );
        };
        if !advisory {
            return Ok(
                json!({"pin":pin,"definition":revision.definition,"diagnostic":null,"advisory_comparison":"not_requested"}),
            );
        }
        let checked =
            super::retained_facets::compare_metadata_on(conn, definition, context, deadline)
                .await?;
        return Ok(json!({"pin":pin,"definition":checked.definition,
            "diagnostic":null,"source_drift":checked.drift,"source_drift_unknown_reason":checked.unknown_reason}));
    }
    // No immutable payload leaves this function until every discovered bearer
    // and source is authorized. Drift never prevents retrieving SQL to repair it.
    let plan = inspected.build(&roots);
    let diagnostic = if inspected.drifted {
        Some("view_source_invalidated")
    } else if let Ok(plan) = &plan {
        match crate::query::sql::view_validation::analyze_diagnostic(plan, deadline).await {
            Ok(crate::query::sql::view_validation::Outcome::Valid(_)) => None,
            Ok(crate::query::sql::view_validation::Outcome::Invalid(_)) => {
                Some("view_source_invalidated")
            }
            Err(_) => Some("view_validation_unavailable"),
        }
    } else {
        Some("view_source_invalidated")
    };
    Ok(json!({"pin":pin,"definition":inspected.definitions[&pin],
        "closure_digest":plan.as_ref().ok().map(|p| &p.digest),"diagnostic":diagnostic,"diagnostic_retryable":diagnostic==Some("view_validation_unavailable")}))
}
pub(crate) async fn get_on(
    conn: &mut SqliteConnection,
    actor: &str,
    view: &str,
    id: &str,
    deadline: Instant,
) -> Result<Value> {
    let reply = metadata_on(
        conn,
        actor,
        view,
        id,
        deadline,
        true,
        &mut MetadataContexts::new(),
    )
    .await?;
    if serde_json::to_vec(&reply)?.len() > 256 * 1024 {
        return Err(invalid("view_budget_exceeded: revision response"));
    }
    Ok(reply)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    actor: String,
    view: String,
    snapshot: (String, Option<String>, Option<String>),
    after: (i64, String),
    expires: i64,
}
fn cipher() -> ChaCha20Poly1305 {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    ChaCha20Poly1305::new_from_slice(KEY.get_or_init(rand::random)).expect("cursor key")
}
fn encode(cursor: &Cursor) -> Result<String> {
    let nonce: [u8; 12] = rand::random();
    let mut out = nonce.to_vec();
    out.extend(
        cipher()
            .encrypt(&Nonce::from(nonce), serde_json::to_vec(cursor)?.as_slice())
            .map_err(|_| invalid("revision cursor unavailable"))?,
    );
    Ok(URL_SAFE_NO_PAD.encode(out))
}
fn decode_cursor(raw: &str) -> Result<Cursor> {
    let fail = || invalid("view_revision_cursor_invalid: restart revision listing");
    if raw.len() > 4096 {
        return Err(fail());
    }
    let data = URL_SAFE_NO_PAD.decode(raw).map_err(|_| fail())?;
    if data.len() < 28 {
        return Err(fail());
    }
    let clear = cipher()
        .decrypt(
            &Nonce::from(<[u8; 12]>::try_from(&data[..12]).map_err(|_| fail())?),
            &data[12..],
        )
        .map_err(|_| fail())?;
    serde_json::from_slice(&clear).map_err(|_| fail())
}
pub(crate) async fn list_on(
    conn: &mut SqliteConnection,
    actor: &str,
    view: &str,
    limit: usize,
    cursor: Option<&str>,
    deadline: Instant,
) -> Result<Value> {
    if !(1..=16).contains(&limit) {
        return Err(invalid("revision page limit must be 1..16 (default 8)"));
    }
    closure::require_accessible_bearer_on(
        conn,
        actor,
        bearer(view)?,
        &mut std::collections::BTreeSet::new(),
        false,
    )
    .await?;
    let snapshot:(String,Option<String>,Option<String>)=sqlx::query_as("SELECT (SELECT file FROM pragma_database_list WHERE name='main'),(SELECT id FROM content_events ORDER BY seq DESC LIMIT 1),(SELECT id FROM meta_events ORDER BY seq DESC LIMIT 1)").fetch_one(&mut *conn).await?;
    let after = if let Some(raw) = cursor {
        let c = decode_cursor(raw)?;
        if c.actor != actor
            || c.view != view
            || c.snapshot != snapshot
            || c.expires < chrono::Utc::now().timestamp()
        {
            return Err(invalid("view_revision_cursor_invalid: snapshot or visibility changed; restart revision listing"));
        }
        c.after
    } else {
        (0, String::new())
    };
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *conn)
        .await?;
    let state = storage::load_live(conn, head, deadline).await?;
    if state.legacy() {
        return Err(invalid("view_legacy_format: re-author retained revisions"));
    }
    let mut headers: Vec<_> = state
        .revision_ids()
        .filter(|(id, record, seq)| {
            *record == bearer(view).unwrap_or_default()
                && (*seq, id.as_str()) > (after.0, after.1.as_str())
        })
        .collect();
    headers.sort_by_key(|(id, _, seq)| (*seq, id.as_str()));
    let more = headers.len() > limit;
    let mut items = Vec::new();
    let mut contexts = MetadataContexts::new();
    let mut last = after;
    for (id, _, seq) in headers.into_iter().take(limit) {
        let metadata = metadata_on(conn, actor, view, id, deadline, false, &mut contexts).await;
        match metadata {
            Ok(detail) => {
                let pin: Pin = serde_json::from_value(detail["pin"].clone())?;
                let definition: contract::Definition =
                    if detail["definition"].get("generated").is_some() {
                        serde_json::from_value::<v2::Definition>(detail["definition"].clone())?
                            .common()
                    } else {
                        serde_json::from_value(detail["definition"].clone())?
                    };
                let mut item = summary("", &pin, &definition);
                if let Some(mode) = detail.get("advisory_comparison") {
                    item["advisory_comparison"] = mode.clone();
                }
                if let Some(drift) = detail.get("source_drift") {
                    item["source_drift"] = drift.clone();
                    item["source_drift_unknown_reason"] =
                        detail["source_drift_unknown_reason"].clone();
                }
                item["available"] = json!(detail["diagnostic"].is_null());
                if !detail["diagnostic"].is_null() {
                    item["diagnostic"] = detail["diagnostic"].clone();
                }
                items.push(item);
            }
            Err(error) => {
                let message = error.to_string();
                if Instant::now() >= deadline
                    || message.contains("deadline")
                    || message.contains("cancel")
                {
                    return Err(error);
                }
                let diagnostic = [
                    "view_missing",
                    "view_source_invalidated",
                    "view_profile_unsupported",
                    "view_budget_exceeded",
                ]
                .into_iter()
                .find(|code| message.contains(code))
                .unwrap_or("view_revision_unavailable");
                // Root headers belong to the already-authorized bearer. Do
                // not return SQL, semantics, source pins or dependency IDs
                // for a closure the caller cannot currently read.
                let root_pin = pin_on(conn, actor, view, id, head, deadline).await.ok();
                items.push(json!({"view_id":view,"revision_id":id,"definition_sha256":root_pin.as_ref().map(|p| &p.definition_sha256),"schema_sha256":root_pin.as_ref().map(|p| &p.schema_sha256),"available":false,"diagnostic":diagnostic}));
            }
        }
        last = (seq, id.clone());
    }
    let next = if more {
        Some(encode(&Cursor {
            actor: actor.into(),
            view: view.into(),
            snapshot,
            after: last,
            expires: chrono::Utc::now().timestamp() + 300,
        })?)
    } else {
        None
    };
    let binding = state.bindings().get(view);
    let active = binding.and_then(|b| b.active.as_ref());
    let reply = json!({"revisions":items,"cursor":next,"binding":{"event_id":binding.map(|b|&b.event_id),"active":active.is_some(),"name":active.map(|(name,_)|name),"pin":active.map(|(_,pin)|pin)}});
    if serde_json::to_vec(&reply)?.len() > 256 * 1024 {
        return Err(invalid(
            "view_budget_exceeded: metadata page; request fewer revisions",
        ));
    }
    Ok(reply)
}
