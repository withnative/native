//! Tools 15–16 — the facet pair, the first consumers of stage 1's
//! `query::cascade` resolver (finding 4).
//!
//! `resolve_facets` answers "what facet shape is in effect here": the four
//! spine columns, the resolved pack → user cascade for the type, and (when
//! asked about a record) its current values. Both the pack view and the
//! resolved view are returned — the interop-floor judgement (tool 21,
//! rejection (a)) is a comparison BETWEEN the two, and this tool's output is
//! where a caller sees the same distinction.
//!
//! `suggest_facet_values` is a pure vocabulary lookup in CE (no LLM): facet
//! key → governing vocabulary via the resolved cascade, then the active,
//! alias-resolved value listing from `meta::vocabulary::list_values`.

use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::meta::vocabulary::{get_vocabulary, list_values, resolve_vocab_ref, ListValuesOptions};
use crate::query::{cascade, read};
use crate::schema::{ARCHIVED_FACET_KEY, SPINE_FACET_KEYS};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{can_record, can_record_in_pool, parse_args, require_record};

const SHAPE_GUARANTEE: &str = "Supported record-writing tools enforce global declared type, values, and governing vocabulary membership absolutely for every outgoing open-facet value, using the resulting kind and the same write-transaction snapshot; global required is enforced post-batch and comparatively (new missing facets are refused, unchanged legacy gaps remain editable); multi is rejected at schema authoring. Collection-scoped declarations are discoverability metadata: resolve_facets on the bearing record may display them, but filing home never contributes schema to a child's product facet context and writers do not enforce them in V1. These checks are forward-only, are not re-run during replay, do not retroactively certify stored values, and can be bypassed through store::append* or direct trusted-filesystem mutation of the ejectable SQLite file; Db::pool() is physically read-only. This response is not a standing data-invariant certificate. V1 rejects declared type on string-carried spine facets.";
const MAX_RESOLVED_VALUES: usize = 10_000;
const MAX_VOCABULARY_SUGGESTIONS: usize = 10_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveFacetsArgs {
    record_id: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    kind: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SuggestFacetValuesArgs {
    facet_key: String,
    record_id: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
    kind: Option<String>,
}

async fn visible_schema_rows(
    db: &Db,
    caller: &Caller,
) -> Result<Vec<crate::query::cascade::SchemaConfigRow>> {
    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    cascade::schema_config_rows_for_principal(db, principal).await
}

/// M4 slice 1: index-backed `resolve_facets` record response.
///
/// Clones one record's head plus its facet rows from the per-workspace index
/// (no full-index clone) and shapes the byte-identical response the governed
/// path below would build. The whole hit is read-pool-only: schema rows,
/// anchor/owner visibility, kind resolution, and version tokens all read
/// through `db.pool()`; a write-pool checkout anywhere on this path is a
/// defect, pinned by the differential test's acquisition sink.
///
/// Fallback discipline: `Ok(None)` (take the governed path) is returned for
/// absent/refused index, fence races, unheld records, comment-kind records
/// (whose validity tier stays governed), held tombstones (which the governed
/// read serves rather than denying), and ANY index/read-pool check failure.
/// The governed path then produces the authoritative answer — including the
/// genuine error — so the fast path can never emit a distinct result. The
/// only errors this function itself returns are byte-identical to governed:
/// auth denial and the value-set cap, both issued after the post-read fence
/// is verified current.
async fn indexed_record_response(
    db: &Db,
    caller: &Caller,
    record_id: &str,
) -> Result<Option<Value>> {
    let Ok(Some(extract)) = db.indexed_facets_record(record_id).await else {
        return Ok(None);
    };
    // Read-pool schema rows: the governed entrypoint uses the write pool
    // (`schema_config_rows_for_principal`); the fast path must not.
    let principal = (!super::is_legacy_local(caller)).then(|| super::principal(caller));
    let Ok(rows) = cascade::schema_config_rows_for_principal_in_pool(db.pool(), principal).await
    else {
        return Ok(None);
    };
    // Read-pool anchor gate: same `can_record_in` logic as `can_record`,
    // scoped to a read-pool snapshot instead of the writer. A check failure
    // falls back; the denial itself is issued only after the post-read fence
    // below is verified, so a concurrent grant cannot turn a governed-allow
    // into a fast-deny.
    let anchor_visible =
        match can_record_in_pool(db.pool(), caller, record_id, Capability::View).await {
            Ok(visible) => visible,
            Err(_) => return Ok(None),
        };
    let head = extract.head;
    // A held tombstone falls back: tombstone visibility is decided by the
    // governed eligibility tier, so the fast path never denies (or serves)
    // on its own authority — the governed answer below is authoritative by
    // construction.
    if head.deleted_at.is_some() {
        return Ok(None);
    }
    // Comment validity (`read.rs` `valid_comment_with_lens`) can suppress an
    // otherwise visible comment record. Rather than re-implementing that
    // validity tier, comments always take the governed fallback, which
    // applies it identically. Resolution failure also falls back so the
    // genuine error surfaces from the governed path, never from here.
    // Resolved on the read pool: the governed read uses the meta snapshot
    // (write) pool, which would defeat the fast path.
    {
        let governance = match head.kind.as_deref() {
            Some(kind) => {
                match crate::meta::kind::resolve_in_pool(db.pool(), &head.record_type, kind).await {
                    Ok(resolution) => Some(resolution),
                    Err(_) => return Ok(None),
                }
            }
            None => None,
        };
        if governance.as_ref().is_some_and(|resolution| {
            crate::generated::kinds::CoreKind::AnnotationComment.matches(resolution)
        }) {
            return Ok(None);
        }
    }
    let mut values_src: Vec<&crate::workspace_index::FacetRow> = extract
        .facets
        .iter()
        .filter(|facet| facet.key != ARCHIVED_FACET_KEY)
        .collect();
    values_src.sort_by(|a, b| a.key.cmp(&b.key).then(a.id.cmp(&b.id)));
    // No cap error here: the count comes from the possibly-stale
    // extraction, and a concurrent shrink could bring the live set under
    // cap while this snapshot still exceeds it. The error below is issued
    // only after the post-read fence is verified current.
    let record_type = head.record_type.clone();
    let kind = head.kind.clone();
    // Object-typed detection matches the governed read exactly: shapes with
    // no bearer (`read.rs` value projection), not the display shapes below.
    let value_shapes =
        cascade::facets_for_record_context(&rows, &record_type, kind.as_deref(), None);
    let version_rows = sqlx::query(
        "SELECT key, MAX(event_seq) AS version FROM facet_observations \
         WHERE record_id = ? GROUP BY key",
    )
    .bind(record_id)
    .fetch_all(db.pool())
    .await;
    // Never silently empty: an observations-read failure falls back to the
    // governed path (which surfaces the genuine error identically) rather
    // than emitting version-less tokens.
    let version_rows = match version_rows {
        Ok(rows) => rows,
        Err(_) => return Ok(None),
    };
    let mut versions: std::collections::HashMap<String, i64> =
        std::collections::HashMap::with_capacity(version_rows.len());
    for row in &version_rows {
        let Ok(key): std::result::Result<String, _> = row.try_get("key") else {
            return Ok(None);
        };
        let Ok(version): std::result::Result<Option<i64>, _> = row.try_get("version") else {
            return Ok(None);
        };
        if let Some(version) = version {
            versions.insert(key, version);
        }
    }
    let mut values = Vec::with_capacity(values_src.len());
    for facet in values_src {
        let object_typed = value_shapes
            .get(&facet.key)
            .and_then(|shape| shape.get("type"))
            .and_then(Value::as_str)
            == Some("object");
        let value = facet.value.clone().map(|stored| {
            if object_typed {
                serde_json::from_str::<Value>(&stored)
                    .ok()
                    .filter(Value::is_object)
                    .unwrap_or(Value::String(stored))
            } else {
                Value::String(stored)
            }
        });
        let version = versions.get(&facet.key).map(|event_seq| {
            native_artifact_runtime::artifact_intents::FacetVersion::Observation {
                event_seq: *event_seq,
            }
            .encode()
        });
        values.push(crate::query::FacetValueRow {
            key: facet.key.clone(),
            value,
            vocab_ref: facet.vocab_ref.clone(),
            version,
        });
    }
    let owner = match head.owner_id.as_deref() {
        Some(owner) => {
            match can_record_in_pool(db.pool(), caller, owner, Capability::View).await {
                Ok(true) => Some(owner.to_string()),
                Ok(false) => None,
                // Owner-masking check failure falls back rather than masking:
                // the governed path's answer is authoritative.
                Err(_) => return Ok(None),
            }
        }
        _ => None,
    };
    // Post-read fence: anchor gate, owner masking, schema rows, and version
    // tokens above all read live pools after the index extraction. A
    // concurrent write landing in between must not yield a mixed response —
    // fall back so the governed path serves the new snapshot atomically. A
    // fence-read failure falls back for the same reason. The auth denial
    // below is issued only on a verified-current fence, so a concurrent
    // grant cannot turn a governed-allow into a fast-deny.
    let Ok(live_after): std::result::Result<(i64, i64, i64), _> = sqlx::query_as(
        "SELECT (SELECT COALESCE(MAX(seq), 0) FROM content_events), \
                (SELECT COALESCE(MAX(seq), 0) FROM relationship_events), \
                (SELECT epoch FROM authorization_revision WHERE id = 1)",
    )
    .fetch_one(db.pool())
    .await
    else {
        return Ok(None);
    };
    if (
        extract.content_seq,
        extract.relationship_seq,
        extract.authorization_epoch,
    ) != live_after
    {
        return Ok(None);
    }
    if !anchor_visible {
        return Err(Error::engine(format!("record {record_id} does not exist")));
    }
    // Value-set cap after the fence: the count above comes from the index
    // extraction, and erroring on it before verifying currency would let a
    // concurrent shrink (live set now under cap) diverge into a fast error
    // where the governed read succeeds. Same message as governed, issued
    // only on a verified-current snapshot.
    if values.len() > MAX_RESOLVED_VALUES {
        return Err(Error::engine(format!(
            "resolve_facets: value set exceeds {MAX_RESOLVED_VALUES} rows"
        )));
    }
    Ok(Some(json!({
        "record_id": record_id,
        "type": record_type,
        "kind": kind,
        "bears_shape": cascade::bears_shape_from_rows(&rows, record_id),
        "spine": {
            "lifecycle": head.lifecycle,
            "owner": owner,
            "persistence": head.persistence,
            "maturity": head.maturity,
        },
        "archived": extract.facets.iter().any(|facet| facet.key == ARCHIVED_FACET_KEY),
        "shape": cascade::facets_for_record_context(&rows, &record_type, kind.as_deref(), Some(record_id)),
        "pack_shape": cascade::pack_facets_for_record_context(&rows, &record_type, kind.as_deref(), Some(record_id)),
        "provenance": cascade::provenance_for_record_context(&rows, &record_type, kind.as_deref(), Some(record_id)),
        "values": values,
        "shape_guarantee": SHAPE_GUARANTEE,
    })))
}

/// The unchanged governed `resolve_facets` record path, extracted so the
/// differential oracle can call it directly without process-global mutable
/// state (no kill switch): registry-fast versus direct-governed on the same
/// request and principal.
async fn governed_record_response(
    db: &Db,
    caller: &Caller,
    rows: &[crate::query::cascade::SchemaConfigRow],
    record_id: &str,
) -> Result<Value> {
    if !can_record(db, caller, record_id, Capability::View).await? {
        return Err(Error::engine(format!("record {record_id} does not exist")));
    }
    let Some(record) = read::get_record(db, record_id).await? else {
        return Err(Error::engine(format!("record {record_id} does not exist")));
    };
    if record.facets.len() > MAX_RESOLVED_VALUES {
        return Err(Error::engine(format!(
            "resolve_facets: value set exceeds {MAX_RESOLVED_VALUES} rows"
        )));
    }
    let record_type = record.record.record_type.clone();
    let kind = record.record.kind.clone();
    let owner = match record.record.owner_id.as_deref() {
        Some(owner) if can_record(db, caller, owner, Capability::View).await? => {
            Some(owner.to_string())
        }
        _ => None,
    };
    let response = json!({
        "record_id": record_id,
        "type": record_type,
        "kind": kind,
        "bears_shape": cascade::bears_shape_from_rows(rows, record_id),
        "spine": {
            "lifecycle": record.record.lifecycle,
            "owner": owner,
            "persistence": record.record.persistence,
            "maturity": record.record.maturity,
        },
        "archived": record.archived,
        "shape": cascade::facets_for_record_context(rows, &record_type, kind.as_deref(), Some(record_id)),
        "pack_shape": cascade::pack_facets_for_record_context(rows, &record_type, kind.as_deref(), Some(record_id)),
        "provenance": cascade::provenance_for_record_context(rows, &record_type, kind.as_deref(), Some(record_id)),
        "values": record.facets,
        "shape_guarantee": SHAPE_GUARANTEE,
    });
    Ok(response)
}

async fn resolve_facets(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: ResolveFacetsArgs = parse_args("resolve_facets", arguments)?;
    match (args.record_id, args.record_type) {
        (Some(record_id), None) => {
            // M4 fast path first: read-pool only, byte-identical on hit.
            // Any miss falls through to the governed path below, unchanged.
            if let Some(fast) = indexed_record_response(&db, &caller, &record_id).await? {
                crate::mcp::request_timing::record_m4_index_decision(true);
                return Ok(fast);
            }
            let rows = visible_schema_rows(&db, &caller).await?;
            let response = governed_record_response(&db, &caller, &rows, &record_id).await?;
            crate::mcp::request_timing::record_m4_index_decision(false);
            Ok(response)
        }
        (None, Some(record_type)) => {
            // Type path untouched by M4: schema configuration has no
            // record-index lookup to replace; behavior identical to before.
            let rows = visible_schema_rows(&db, &caller).await?;
            let resolved = cascade::resolve_from_rows(&rows);
            let kind = args.kind;
            let mut response = json!({
                "type": record_type,
                "kind": kind,
                "spine": SPINE_FACET_KEYS,
                "shape": cascade::facets_for_type(&resolved.resolved, &record_type, kind.as_deref()),
                "pack_shape": cascade::facets_for_type(&resolved.pack, &record_type, kind.as_deref()),
                "provenance": cascade::provenance_for_type(&rows, &record_type, kind.as_deref()),
                "shape_guarantee": SHAPE_GUARANTEE,
            });
            if kind.is_none() {
                response["kind_shapes"] =
                    json!(cascade::kind_shapes(&resolved.resolved, &record_type));
            }
            Ok(response)
        }
        _ => Err(Error::engine(
            "resolve_facets takes exactly one of record_id or type",
        )),
    }
}

async fn suggest_facet_values(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: SuggestFacetValuesArgs = parse_args("suggest_facet_values", arguments)?;
    let (record_type, kind, bearer_id) = match (args.record_id, args.record_type) {
        (Some(record_id), None) => {
            require_record(
                &db,
                &caller,
                "suggest_facet_values",
                &record_id,
                Capability::View,
            )
            .await?;
            let Some(record) = read::get_record(&db, &record_id).await? else {
                return Err(Error::engine(format!("record {record_id} does not exist")));
            };
            (
                record.record.record_type,
                record.record.kind,
                Some(record_id),
            )
        }
        (None, Some(record_type)) => (record_type, args.kind, None),
        _ => Err(Error::engine(
            "suggest_facet_values takes exactly one of record_id or type",
        ))?,
    };
    let rows = visible_schema_rows(&db, &caller).await?;
    let shape = cascade::facets_for_record_context(
        &rows,
        &record_type,
        kind.as_deref(),
        bearer_id.as_deref(),
    );
    let declared_type = shape
        .get(&args.facet_key)
        .and_then(|facet| facet.get("type"))
        .cloned()
        .unwrap_or(Value::Null);
    let Some(governing) = shape.get(&args.facet_key).and_then(|shape| {
        shape
            .get("vocab")
            .or_else(|| shape.get("vocab_ref"))
            .and_then(Value::as_str)
            .map(String::from)
    }) else {
        return Ok(json!({
            "facet_key": args.facet_key,
            "type": record_type,
            "kind": kind,
            "declared_type": declared_type,
            "vocabulary": Value::Null,
            "suggestions": [],
            "shape_guarantee": SHAPE_GUARANTEE,
        }));
    };
    let vocabulary = resolve_vocab_ref(&governing);
    let suggestions = list_values(
        &db,
        vocabulary,
        ListValuesOptions {
            status: Some("active".into()),
            resolve_aliases: true,
        },
    )
    .await?;
    if suggestions.len() > MAX_VOCABULARY_SUGGESTIONS {
        return Err(Error::engine(format!(
            "suggest_facet_values: suggestion set exceeds {MAX_VOCABULARY_SUGGESTIONS} rows"
        )));
    }
    // `list_values` errored if the vocabulary were missing, so this is `Some`.
    let vocab = get_vocabulary(&db, vocabulary).await?;
    Ok(json!({
        "facet_key": args.facet_key,
        "type": record_type,
        "kind": kind,
        "declared_type": declared_type,
        "vocabulary": vocab,
        "suggestions": suggestions,
        "shape_guarantee": SHAPE_GUARANTEE,
    }))
}

/// Register tools 14–15.
pub fn register_facet_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ResolveFacets,
        "Resolve the effective facet shape for a record or a type: spine \
         columns, the pack → user schema_config cascade (both the pack view \
         and the resolved view), and — for a record — its current values, \
         derived bears_shape capability. Filing home never contributes schema.",
        json!({
            "type": "object",
            "properties": {
                "record_id": {
                    "type": "string",
                    "description": "Resolve for this record (its type, plus current values)."
                },
                "type": {
                    "type": "string",
                    "description": "Resolve for a type alone (e.g. \"WorkItem\")."
                },
                "kind": {
                    "type": "string",
                    "description": "Optional kind when resolving by type. A record_id uses the record's own kind."
                }
            },
            "additionalProperties": false
        }),
        resolve_facets,
    )?;
    registry.register(
        ToolKind::SuggestFacetValues,
        "Valid values for a facet key from its governing vocabulary (active, \
         alias-resolved). No governing vocabulary is an empty answer, not an \
         error.",
        json!({
            "type": "object",
            "properties": {
                "facet_key": { "type": "string" },
                "record_id": {
                    "type": "string",
                    "description": "Take the type from this record."
                },
                "type": {
                    "type": "string",
                    "description": "Or name the type directly."
                },
                "kind": {
                    "type": "string",
                    "description": "Optional kind when resolving by type. A record_id uses the record's own kind."
                }
            },
            "required": ["facet_key"],
            "additionalProperties": false
        }),
        suggest_facet_values,
    )?;
    Ok(())
}

#[cfg(test)]
mod m4_oracle_tests {
    //! M4 slice 1 differential oracle: the indexed `resolve_facets` record
    //! response must be byte-identical to the governed path for two
    //! principals, across owner masking, archival, comment-kind fallback,
    //! and an authorization narrowing event — and the hit must take no
    //! write-pool checkout.

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use serde_json::{json, Value};

    use crate::authorization::{AllowEntry, Capability};
    use crate::db::Db;
    use crate::events::FacetSetPayload;
    use crate::mcp::registry::{Caller, ToolRegistry};
    use crate::meta::{KindMetadataV1, VocabularyValueTerminality};

    const ALICE: &str = "a1111111-1111-4111-8111-111111111111";
    const TASK: &str = "b2222222-2222-4222-8222-222222222222";
    const REMARK: &str = "c3333333-3333-4333-8333-333333333333";
    const DOOMED: &str = "d4444444-4444-4444-8444-444444444444";

    fn alice() -> Caller {
        Caller::authenticated("acct:alice")
            .with_hosting_context("host:alice", "db:m4")
            .with_hosting_owner(false)
    }

    fn bea() -> Caller {
        Caller::authenticated("acct:bea")
            .with_hosting_context("host:bea", "db:m4")
            .with_hosting_owner(false)
    }

    async fn fixture_db() -> Db {
        let db = crate::open_database(":memory:").await.unwrap();
        crate::apply_schema(&db).await.unwrap();
        crate::seed_content_tier(&db).await.unwrap();
        crate::identity::seed_database_identity(&db).await.unwrap();
        db
    }

    fn registry() -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
    }

    async fn grant(db: &Db, record_id: &str, accounts: &[(&str, Capability)]) {
        crate::authorization::replace_explicit_policy(
            db,
            "test:m4-oracle",
            record_id,
            accounts
                .iter()
                .map(|(account, capability)| AllowEntry::account(account.to_string(), *capability))
                .collect(),
        )
        .await
        .unwrap();
    }

    /// Call `resolve_facets` for one record through the registry, returning
    /// the outcome rendered for byte comparison plus the handler-body
    /// write-pool acquisitions. The dispatch envelope's `run_context` echo
    /// is stripped before rendering: it is added by the transport layer
    /// around every tool identically and is not part of the handler
    /// contract under test.
    async fn resolve_with_write_count(
        registry: &ToolRegistry,
        db: &Db,
        caller: Caller,
        record_id: &str,
    ) -> (String, u64) {
        let sink = Arc::new(AtomicU64::new(0));
        let outcome = crate::db::with_write_pool_acquisition_sink(
            sink.clone(),
            registry.call(
                db.clone(),
                caller,
                "resolve_facets",
                json!({ "record_id": record_id }),
            ),
        )
        .await;
        db.drain_captures_for_tests().await;
        let rendered = match outcome {
            Ok(mut value) => {
                value.as_object_mut().map(|o| o.remove("run_context"));
                serde_json::to_string(&value).unwrap()
            }
            Err(error) => format!("ERR:{error}"),
        };
        (rendered, sink.load(Ordering::SeqCst))
    }

    /// The governed answer for the same request, called directly — no
    /// process-global kill switch, no cross-test state. Returns the rendered
    /// outcome plus the write-pool acquisitions it took, counted by the pool
    /// hooks directly (the publish sink only works through registry
    /// dispatch, so it cannot observe a direct helper call).
    async fn govern_direct(db: &Db, caller: &Caller, record_id: &str) -> (String, u64) {
        let rows = super::visible_schema_rows(db, caller).await.unwrap();
        let (outcome, writes) = crate::db::with_write_pool_acquisition_counter(
            super::governed_record_response(db, caller, &rows, record_id),
        )
        .await;
        let rendered = match outcome {
            Ok(value) => serde_json::to_string(&value).unwrap(),
            Err(error) => format!("ERR:{error}"),
        };
        (rendered, writes)
    }

    fn facet(key: &str, value: &str) -> FacetSetPayload {
        FacetSetPayload {
            key: key.to_string(),
            value: Some(value.to_string()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        }
    }

    #[tokio::test]
    async fn indexed_record_response_matches_governed_for_two_principals() {
        let db = fixture_db().await;
        let registry = registry();
        crate::store::create_record(
            &db,
            json!({
                "id": ALICE,
                "type": "Entity", "kind": "person", "name": "Alice",
            }),
        )
        .await
        .unwrap();
        crate::store::create_record(
            &db,
            json!({
                "id": TASK,
                "type": "WorkItem", "kind": "task", "name": "M4 task",
                "lifecycle": "in_progress", "owner_id": ALICE,
            }),
        )
        .await
        .unwrap();
        crate::store::set_facet(&db, TASK, facet("priority", "high"))
            .await
            .unwrap();
        grant(
            &db,
            TASK,
            &[
                ("acct:alice", Capability::View),
                ("acct:bea", Capability::View),
            ],
        )
        .await;
        grant(
            &db,
            ALICE,
            &[
                ("acct:alice", Capability::View),
                ("acct:bea", Capability::View),
            ],
        )
        .await;

        for caller in [alice(), bea()] {
            let (fast, writes) =
                resolve_with_write_count(&registry, &db, caller.clone(), TASK).await;
            let (governed, governed_writes) = govern_direct(&db, &caller, TASK).await;
            assert_eq!(fast, governed, "indexed != governed");
            assert!(
                governed_writes > 0,
                "governed control took no writer checkout"
            );
            assert_eq!(writes, 0, "indexed hit took a write-pool checkout");
            assert!(fast.contains("\"type\":\"WorkItem\""), "{fast}");
            assert!(fast.contains("\"priority\""), "{fast}");
        }
        db.close().await;
    }

    #[tokio::test]
    async fn indexed_record_response_tracks_owner_masking_archival_and_narrowing() {
        let db = fixture_db().await;
        let registry = registry();
        crate::store::create_record(
            &db,
            json!({
                "id": ALICE,
                "type": "Entity", "kind": "person", "name": "Alice",
            }),
        )
        .await
        .unwrap();
        crate::store::create_record(
            &db,
            json!({
                "id": TASK,
                "type": "WorkItem", "kind": "task", "name": "M4 task",
                "owner_id": ALICE,
            }),
        )
        .await
        .unwrap();
        grant(
            &db,
            TASK,
            &[
                ("acct:alice", Capability::View),
                ("acct:bea", Capability::View),
            ],
        )
        .await;
        grant(
            &db,
            ALICE,
            &[
                ("acct:alice", Capability::View),
                ("acct:bea", Capability::View),
            ],
        )
        .await;

        // Owner visible to both while the person record is shared.
        for caller in [alice(), bea()] {
            let (fast, _) = resolve_with_write_count(&registry, &db, caller.clone(), TASK).await;
            let (governed, _) = govern_direct(&db, &caller, TASK).await;
            assert_eq!(fast, governed, "owner-visible indexed != governed");
            assert!(fast.contains(ALICE), "owner should be disclosed: {fast}");
        }

        // Restrict the owner person to alice: bea's owner masks to null.
        grant(&db, ALICE, &[("acct:alice", Capability::View)]).await;
        let (bea_fast, _) = resolve_with_write_count(&registry, &db, bea(), TASK).await;
        let (bea_governed, _) = govern_direct(&db, &bea(), TASK).await;
        assert_eq!(bea_fast, bea_governed, "owner-masked indexed != governed");
        assert!(!bea_fast.contains(ALICE), "owner leaked to bea: {bea_fast}");
        let (alice_fast, _) = resolve_with_write_count(&registry, &db, alice(), TASK).await;
        assert!(
            alice_fast.contains(ALICE),
            "owner hidden from alice: {alice_fast}"
        );

        // Archival is held facet state: both paths report it identically.
        registry
            .call(
                db.clone(),
                Caller::local(),
                "archive_record",
                json!({ "id": TASK, "reason": "m4 oracle fixture" }),
            )
            .await
            .unwrap();
        db.drain_captures_for_tests().await;
        let (arch_fast, _) = resolve_with_write_count(&registry, &db, alice(), TASK).await;
        let (arch_governed, _) = govern_direct(&db, &alice(), TASK).await;
        assert_eq!(arch_fast, arch_governed, "archived indexed != governed");
        assert!(arch_fast.contains("\"archived\":true"), "{arch_fast}");

        // Narrowing: bea loses the task. The policy write bumps the
        // authorization epoch, so the next indexed read must rebuild (a
        // content fold alone cannot repair it) and still serve byte parity —
        // with no write-pool checkout on the restored hit.
        grant(&db, TASK, &[("acct:alice", Capability::View)]).await;
        let (bea_denied, _) = resolve_with_write_count(&registry, &db, bea(), TASK).await;
        let (bea_denied_governed, _) = govern_direct(&db, &bea(), TASK).await;
        assert_eq!(
            bea_denied, bea_denied_governed,
            "narrowed indexed != governed"
        );
        assert!(bea_denied.contains("does not exist"), "{bea_denied}");
        let (alice_hit, alice_writes) =
            resolve_with_write_count(&registry, &db, alice(), TASK).await;
        let (alice_governed, _) = govern_direct(&db, &alice(), TASK).await;
        assert_eq!(alice_hit, alice_governed, "post-narrow indexed != governed");
        assert_eq!(
            alice_writes, 0,
            "post-rebuild hit took a write-pool checkout"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn indexed_record_response_falls_back_for_comment_kind() {
        let db = fixture_db().await;
        let registry = registry();
        crate::meta::create_vocabulary(&db, "kind:Annotation", Some("voc:kind:Annotation"))
            .await
            .unwrap();
        let value = crate::meta::propose_value_with_kind_metadata_as(
            &db,
            "kind:Annotation",
            "comment",
            None,
            0.0,
            VocabularyValueTerminality::Open,
            Some(KindMetadataV1::legacy("Annotation", "comment")),
            None,
        )
        .await
        .unwrap();
        crate::meta::promote_value(&db, &value).await.unwrap();
        crate::store::create_record(
            &db,
            json!({
                "id": REMARK,
                "type": "Annotation", "kind": "comment", "name": "stray remark",
            }),
        )
        .await
        .unwrap();
        grant(
            &db,
            REMARK,
            &[
                ("acct:alice", Capability::View),
                ("acct:bea", Capability::View),
            ],
        )
        .await;

        // Comment validity stays governed: the fast path must fall back and
        // the served answer must still equal the governed one exactly.
        let (fast, _) = resolve_with_write_count(&registry, &db, alice(), REMARK).await;
        let (governed, _) = govern_direct(&db, &alice(), REMARK).await;
        assert_eq!(fast, governed, "comment-kind indexed != governed");
        db.close().await;
    }

    #[tokio::test]
    async fn indexed_record_response_falls_back_for_tombstones() {
        let db = fixture_db().await;
        let registry = registry();
        crate::store::create_record(
            &db,
            json!({
                "id": DOOMED,
                "type": "WorkItem", "kind": "task", "name": "doomed",
            }),
        )
        .await
        .unwrap();
        grant(
            &db,
            DOOMED,
            &[
                ("acct:alice", Capability::View),
                ("acct:bea", Capability::View),
            ],
        )
        .await;

        let (live_fast, _) = resolve_with_write_count(&registry, &db, alice(), DOOMED).await;
        let (live_governed, _) = govern_direct(&db, &alice(), DOOMED).await;
        assert_eq!(live_fast, live_governed, "live indexed != governed");

        // Tombstoned records are denied through the governed eligibility
        // tier — so the fast path must fall back, never deny (or serve) on
        // its own authority. Both answers must still match exactly.
        registry
            .call(
                db.clone(),
                Caller::local(),
                "delete_record",
                json!({ "id": DOOMED, "reason": "m4 oracle fixture" }),
            )
            .await
            .unwrap();
        db.drain_captures_for_tests().await;
        let (dead_fast, _) = resolve_with_write_count(&registry, &db, alice(), DOOMED).await;
        let (dead_governed, _) = govern_direct(&db, &alice(), DOOMED).await;
        assert_eq!(dead_fast, dead_governed, "tombstoned indexed != governed");
        assert!(
            dead_fast.contains("does not exist"),
            "tombstone should deny identically: {dead_fast}"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn indexed_record_response_rebuilds_after_dropped_index() {
        let db = fixture_db().await;
        let registry = registry();
        crate::store::create_record(
            &db,
            json!({
                "id": TASK,
                "type": "WorkItem", "kind": "task", "name": "M4 task",
            }),
        )
        .await
        .unwrap();
        grant(
            &db,
            TASK,
            &[
                ("acct:alice", Capability::View),
                ("acct:bea", Capability::View),
            ],
        )
        .await;

        let (warm_fast, _) = resolve_with_write_count(&registry, &db, alice(), TASK).await;
        let (warm_governed, _) = govern_direct(&db, &alice(), TASK).await;
        assert_eq!(warm_fast, warm_governed, "warm indexed != governed");

        // Drop the held index: the next read must cold-rebuild under cap
        // and serve the identical answer, still with no writer checkout.
        db.clear_workspace_index_for_tests().await;
        assert!(!db.workspace_index_built_for_tests().await);
        let (cold_fast, cold_writes) =
            resolve_with_write_count(&registry, &db, alice(), TASK).await;
        let (cold_governed, _) = govern_direct(&db, &alice(), TASK).await;
        assert_eq!(cold_fast, cold_governed, "rebuilt indexed != governed");
        assert_eq!(cold_writes, 0, "rebuilt hit took a write-pool checkout");
        db.close().await;
    }

    #[tokio::test]
    async fn indexed_record_response_survives_write_then_read_race() {
        let db = fixture_db().await;
        let registry = registry();
        crate::store::create_record(
            &db,
            json!({
                "id": TASK,
                "type": "WorkItem", "kind": "task", "name": "M4 task",
            }),
        )
        .await
        .unwrap();
        grant(
            &db,
            TASK,
            &[
                ("acct:alice", Capability::View),
                ("acct:bea", Capability::View),
            ],
        )
        .await;

        // Back-to-back write/read races the background commit-wake fold.
        // Whichever path the read takes — stale-content fold, rebuild, or
        // governed fallback — the served answer must equal governed.
        for round in 0..3 {
            crate::store::set_facet(&db, TASK, facet("round", &round.to_string()))
                .await
                .unwrap();
            for caller in [alice(), bea()] {
                let (fast, _) =
                    resolve_with_write_count(&registry, &db, caller.clone(), TASK).await;
                let (governed, _) = govern_direct(&db, &caller, TASK).await;
                assert_eq!(fast, governed, "round {round} indexed != governed");
            }
        }
        db.close().await;
    }

    #[tokio::test]
    async fn resolve_facets_type_path_is_unchanged() {
        let db = fixture_db().await;
        let registry = registry();
        let out: Value = registry
            .call(
                db.clone(),
                alice(),
                "resolve_facets",
                json!({ "type": "WorkItem" }),
            )
            .await
            .unwrap();
        db.drain_captures_for_tests().await;
        assert_eq!(
            out["spine"],
            json!(["lifecycle", "owner", "persistence", "maturity"])
        );
        assert!(out.get("values").is_none());
        db.close().await;
    }
}
