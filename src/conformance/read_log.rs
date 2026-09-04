//! `read-log-disposability` — the check that keeps the user's attention data
//! controlled and non-authoritative (spec fbfaf25 §6, decision e7d9790).
//!
//! ## Why this check exists, and why it is shaped the way it is
//!
//! The read log (`read_log_calls`, `read_log_touches`) contains agent execution
//! traces and potentially sensitive human attention data. Decision e7d9790
//! corrected an over-strong interpretation of disposability: the governing
//! promise is **control**, not total feature independence. A person may delete
//! the log; doing so must never damage authoritative workspace data or break
//! core operations. Explicit attention-derived features may become empty.
//!
//! ## Core independence plus named attention-derived surfaces
//!
//! An earlier draft of this check specified *drop the tables, rebuild, assert the
//! workspace still functions*. That is very close to vacuous, and the reason is
//! the capture point's own fail-open rule: nothing is permitted to crash when
//! read-log machinery fails, so "still functions" is guaranteed by construction
//! and the check would pass on a build that had grown a real dependency.
//!
//! The check remains DIFFERENTIAL for every core response. It runs a fixed
//! corpus against a populated database, drops both read-log tables, replays the
//! identical corpus, and requires equality outside a small named allowlist.
//! Every allowlisted surface is separately required to degrade to empty.
//!
//! `rebuild-and-diff` must also still pass on the dropped database, which is what
//! rules out "independent because nothing works".
//!
//! ## The exemptions, and why they are an allowlist rather than a shrug
//!
//! Attention-derived response keys may legitimately differ across the drop.
//! Collection fields must degrade to EMPTY rather than to an error, while the
//! activity availability receipt must change from available to unavailable:
//!
//!   1. the intent briefing, whose entire content is a read over the dropped
//!      tables;
//!   2. the displaced-key nudge, same reasoning.
//!   3. `read_activity`, the aggregate-only follow-page activity layer.
//!   4. the `get_run_activity.availability` receipt, which makes the named
//!      degradation distinguishable from a genuinely empty available result.
//!
//! The first two ship in [[17a374f]] / spec §3.2a, §6a. The third,
//! `read_activity`, is the aggregate-only follow-page layer ratified by
//! e7d9790. Keeping it named rather than loosening the comparison is the point:
//! every later consumer must arrive as an explicit, reviewable diff.
//!
//! ## Copy-forward is an explicit exemption
//!
//! Durable intent copy-forward stamps the latest exact-run declaration on new
//! content events while the read log exists. Dropping the log correctly changes
//! future event `intent` to NULL, while previously copied annotations remain.
//! The differential removes that named field before comparing core projections
//! and still runs rebuild-and-diff on both databases.

use serde_json::{json, Map, Value};

use crate::db::create_database;
use crate::error::Result;
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::mcp::tools::register_surface_tools;

use super::rebuild::rebuild_and_diff;
use super::spine::CheckResult;

/// Response keys permitted to differ across the drop, each of which must degrade
/// to empty rather than to an error. See the module header for why each key must
/// be explicitly named and tested on both sides of the drop.
pub const EXEMPT_RESPONSE_KEYS: [&str; 3] = ["briefing", "intent", "read_activity"];

/// The corpus's EXPLICIT record ids. Record ids are canonical UUIDs (v4/v7)
/// since the record-id authority stopped admitting slugs, which collides with
/// the UUID redaction in [`normalize`]: a blanket "redact anything UUID-shaped"
/// would now erase record identity, the one thing this differential must
/// compare. These are pinned literals, identical in both runs, so they are
/// exempted from that redaction and compared verbatim.
const CORPUS_RECORD_IDS: [&str; 4] = [CORPUS_DOC_1, CORPUS_DOC_2, CORPUS_TASK_1, CORPUS_MISSING];
const CORPUS_DOC_1: &str = "d0c00001-0000-4000-8000-000000000001";
const CORPUS_DOC_2: &str = "d0c00002-0000-4000-8000-000000000002";
const CORPUS_TASK_1: &str = "7a5c0001-0000-4000-8000-000000000003";
/// Deliberately never created: the corpus's missing-id failure path.
const CORPUS_MISSING: &str = "0b5e0000-0000-4000-8000-00000000dead";

/// The fixed corpus: one call per entry, `(tool, arguments)`, run in order.
///
/// Ids are EXPLICIT throughout. The comparison is between two independent
/// databases, so anything the engine generates freshly (a UUID) would differ for
/// reasons that have nothing to do with the read log — pinning ids keeps the
/// assertion about disposability instead of about determinism. Timestamps are
/// handled the other way, by redaction in [`normalize`], because they cannot be
/// pinned from outside.
///
/// One tool is deliberately ABSENT: `describe_schema`. It reports the physical
/// schema, so after the drop it honestly reports two fewer tables — it is a
/// MIRROR of the drop rather than a consumer of the log, and the difference is
/// the tool working correctly. It is called out here rather than silently
/// omitted, because "it was inconvenient" and "it is categorically different"
/// look identical in a corpus with no note attached.
///
/// The corpus deliberately spans every shape that could hide a dependency:
/// reads, writes, and calls that FAIL (a zero-result search and a missing id) —
/// failed retrieval is exactly the signal the read log is designed to keep, so it
/// is also where a reader of the log is most likely to appear. The write-path
/// break extends it with the `run_key` accept path and a malformed key.
struct CorpusCall {
    tool: &'static str,
    arguments: Value,
    expect_ok: bool,
}

fn ok(tool: &'static str, arguments: Value) -> CorpusCall {
    CorpusCall {
        tool,
        arguments,
        expect_ok: true,
    }
}

fn error(tool: &'static str, arguments: Value) -> CorpusCall {
    CorpusCall {
        tool,
        arguments,
        expect_ok: false,
    }
}

fn corpus() -> Vec<CorpusCall> {
    // A fixed, shape-and-membership-valid key, so the corpus exercises the
    // validated accept, echo, and event-annotation paths rather than only the
    // null path. The declaration below makes copy-forward observable.
    let run = "scout-chair-a748b2";
    let reason = "Fixed corpus for the disposability differential — exercises the \
                  write path so the check compares real events rather than empty \
                  reads.";
    vec![
        ok("bootstrap", json!({ "run_key": run })),
        ok(
            "set_intent",
            json!({
                "intent": "Exercise the named copy-forward exemption.",
                "run_key": run,
            }),
        ),
        ok(
            "create_record",
            json!({
                "type": "Document",
                "kind": "note",
                "id": CORPUS_DOC_2,
                "name": "Disposability corpus companion",
                "reason": reason,
                "run_key": run,
            }),
        ),
        // Keep the scan's bounded recent sample filled with authored corpus
        // records, rather than the engine-created root folders whose read-log
        // touches are intentionally disposable.
        ok(
            "create_record",
            json!({
                "type": "Document",
                "kind": "note",
                "id": CORPUS_DOC_1,
                "name": "Disposability corpus document",
                "body": "A body with searchable words: harbour lantern threshold.",
                "reason": reason,
                "run_key": run,
            }),
        ),
        ok(
            "create_record",
            json!({
                "type": "WorkItem",
                "kind": "task",
                "id": CORPUS_TASK_1,
                "name": "Disposability corpus task",
                "facets": { "stage": "drafting" },
                "links": [{ "target_id": CORPUS_DOC_1, "relationship": "implements" }],
                "reason": reason,
                "run_key": run,
                "parent_key": "pilot-river-b748b2",
            }),
        ),
        ok(
            "get_record",
            json!({ "ids": [CORPUS_DOC_1, CORPUS_TASK_1], "run_key": run }),
        ),
        ok(
            "update_record",
            json!({
                "id": CORPUS_TASK_1,
                "summary": "Updated by the corpus.",
                "reason": reason,
                "run_key": run,
            }),
        ),
        ok(
            "query_record",
            json!({ "steps": [{ "step": "filter", "types": ["WorkItem"] }] , "run_key": run }),
        ),
        ok("search", json!({ "query": "lantern", "run_key": run })),
        // `scan` may read the durable content log for provenance/authorship,
        // but must remain exactly unchanged when the disposable read log goes.
        ok("scan", json!({ "query": "corpus", "run_key": run })),
        // Zero results: failed retrieval is the signal, not the absence of one.
        ok(
            "search",
            json!({ "query": "zzzznotpresent", "run_key": run }),
        ),
        ok(
            "get_history",
            json!({ "record_id": CORPUS_DOC_1, "run_key": run }),
        ),
        ok(
            "get_structure",
            json!({ "root_id": CORPUS_DOC_1, "run_key": run }),
        ),
        ok(
            "archive_record",
            json!({ "id": CORPUS_TASK_1, "reason": reason, "run_key": run }),
        ),
        // An erroring call. The error text must match across the drop too — a
        // read-log dependency that surfaced only in a failure path would be
        // exactly the kind this check exists to catch.
        error(
            "get_structure",
            json!({ "root_id": CORPUS_MISSING, "run_key": run }),
        ),
        ok(
            "delete_record",
            json!({ "id": CORPUS_TASK_1, "reason": reason, "run_key": run }),
        ),
        // A malformed key. It must be recorded as null, keep the raw string in
        // the logged arguments, and NOT fail the call — with and without the log
        // alike. A build that made the read log the reason a tool fails would
        // diverge right here.
        ok(
            "query_record",
            json!({ "steps": [{ "step": "filter", "types": ["Document"] }], "run_key": "scout-chiar-a748b2" }),
        ),
        // No key at all: the honest, common case, and the one the echo turns into
        // a nudge.
        ok(
            "query_record",
            json!({ "steps": [{ "step": "filter", "types": ["Document"] }] }),
        ),
        // The one shipped attention-derived surface. With the log present this
        // must observe the corpus searches/touches; after the drop it must
        // answer successfully with an empty collection.
        ok(
            "get_run_activity",
            json!({ "for_run": run, "include_child_runs": true, "run_key": run }),
        ),
    ]
}

/// Redact values that legitimately differ between two independent runs.
///
/// Exactly three classes, and the list is short on purpose — a looser normalizer
/// is the easy way to make this check pass while meaning nothing:
///
///   - **Timestamps.** Two runs happen at two moments; there is no way to pin
///     them from outside the engine.
///   - **Freshly-minted UUIDs**, which is really one thing: the `id` the engine
///     assigns each event. Record ids in the corpus are EXPLICIT and pinned
///     ([`CORPUS_RECORD_IDS`]) — they are UUID-shaped now that the record-id
///     authority admits only canonical v4/v7, so they are exempted from this
///     redaction by value. That keeps the old guarantee intact: redacting
///     UUID-shaped values cannot hide a record identity difference, it only
///     hides the surrogate keys of rows the two databases created
///     independently.
///   - **Relationship compatibility ids.** Post-v35 projected LinkRow ids embed
///     both a freshly-created database origin and relationship UUID. Only the
///     `id` field of that exact response object is redacted; the same string in
///     record content, notes, or errors remains compared verbatim.
///
/// Everything else is compared verbatim, because everything else is supposed to
/// be identical.
fn normalize(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            // The compatibility id is non-deterministic only on an actual
            // projected LinkRow. Do not redact the same string shape from
            // arbitrary record fields, payloads, notes, or error text: doing
            // so would let this differential hide unrelated response drift.
            let projected_link = map.contains_key("id")
                && map.contains_key("source_id")
                && map.contains_key("target_id")
                && map.contains_key("relationship");
            for (key, child) in map {
                if EXEMPT_RESPONSE_KEYS.contains(&key.as_str()) {
                    continue;
                }
                if key == "local_database_id"
                    && child.as_str().is_some_and(crate::identity::is_database_id)
                {
                    // The differential deliberately uses two independent
                    // databases. Database-scoped replay positions must carry
                    // this context publicly, but the freshly minted identity
                    // itself is not a read-log dependency.
                    out.insert(key.clone(), Value::String("<local-database-id>".into()));
                } else if projected_link
                    && key == "id"
                    && child.as_str().is_some_and(is_relationship_projection_id)
                {
                    out.insert(
                        key.clone(),
                        Value::String("<relationship-projection-id>".into()),
                    );
                } else {
                    out.insert(key.clone(), normalize(child));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(normalize).collect()),
        Value::String(text) if is_timestamp(text) => Value::String("<timestamp>".into()),
        Value::String(text) if is_uuid(text) && !CORPUS_RECORD_IDS.contains(&text.as_str()) => {
            Value::String("<uuid>".into())
        }
        other => other.clone(),
    }
}

fn is_relationship_projection_id(text: &str) -> bool {
    text.strip_prefix("rel:")
        .and_then(|coordinate| coordinate.rsplit_once(':'))
        .is_some_and(|(origin, id)| crate::identity::is_database_id(origin) && is_uuid(id))
}

/// `37229b9e-5575-406c-9b80-d47fb291740d` — the shape `Uuid::new_v4()` renders.
fn is_uuid(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23].iter().all(|&i| bytes[i] == b'-')
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| [8, 13, 18, 23].contains(&i) || b.is_ascii_hexdigit())
}

/// `2026-07-30T18:22:41.123Z` and friends — the DDL's timestamp shape.
fn is_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() >= 20
        && text.ends_with('Z')
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[..4].iter().all(u8::is_ascii_digit)
}

/// Run the corpus against a fresh database, returning one normalized JSON value
/// per call (the handler's payload, or its error rendered as a value — an error
/// is a result too, and one this check compares).
async fn run_corpus(drop_read_log: bool) -> Result<Vec<Value>> {
    let db = create_database(":memory:").await?;
    if drop_read_log {
        // Touches first: the FK points at calls, so the reverse order would
        // depend on whether `PRAGMA foreign_keys` happens to be on.
        for statement in ["DROP TABLE read_log_touches", "DROP TABLE read_log_calls"] {
            sqlx::query(statement).execute(db.write_pool()).await?;
        }
    }

    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry)?;

    let mut results = Vec::new();
    for call in corpus() {
        let outcome = registry
            .call(db.clone(), Caller::local(), call.tool, call.arguments)
            .await;
        if outcome.is_ok() != call.expect_ok {
            return Err(crate::error::Error::engine(format!(
                "disposability corpus call '{}' expected ok={} but got {}",
                call.tool,
                call.expect_ok,
                match &outcome {
                    Ok(_) => "success".to_string(),
                    Err(err) => format!("error: {err}"),
                }
            )));
        }
        if call.tool == "get_run_activity" {
            let value = outcome.as_ref().ok().ok_or_else(|| {
                crate::error::Error::engine("get_run_activity did not return a value")
            })?;
            let activity = value
                .get("read_activity")
                .and_then(Value::as_array)
                .ok_or_else(|| {
                    crate::error::Error::engine(
                        "get_run_activity did not return a read_activity collection",
                    )
                })?;
            if drop_read_log && !activity.is_empty() {
                return Err(crate::error::Error::engine(
                    "get_run_activity did not degrade to empty after the read-log drop",
                ));
            }
            if !drop_read_log && activity.is_empty() {
                return Err(crate::error::Error::engine(
                    "get_run_activity failed to observe the populated read log",
                ));
            }
            let expected_status = if drop_read_log {
                "unavailable"
            } else {
                "available"
            };
            if value
                .pointer("/availability/status")
                .and_then(Value::as_str)
                != Some(expected_status)
            {
                return Err(crate::error::Error::engine(format!(
                    "get_run_activity did not report {expected_status} across the read-log differential"
                )));
            }
            let availability = value
                .get("availability")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    crate::error::Error::engine(
                        "get_run_activity did not return an availability object",
                    )
                })?;
            let expected_shape = availability.len() == 3
                && availability.get("status").and_then(Value::as_str) == Some(expected_status)
                && if drop_read_log {
                    availability.get("reason").and_then(Value::as_str)
                        == Some("read_log_unavailable")
                        && availability
                            .get("visibility_filtered")
                            .is_some_and(Value::is_null)
                } else {
                    availability.get("reason").is_some_and(Value::is_null)
                        && availability
                            .get("visibility_filtered")
                            .and_then(Value::as_bool)
                            .is_some()
                };
            if !expected_shape {
                return Err(crate::error::Error::engine(format!(
                    "get_run_activity returned a malformed {expected_status} availability receipt"
                )));
            }
        }
        let mut response = match outcome {
            Ok(value) => json!({ "tool": call.tool, "ok": true, "value": value }),
            Err(err) => json!({ "tool": call.tool, "ok": false, "error": err.to_string() }),
        };
        if call.tool == "get_run_activity" {
            // The available/unavailable transition is asserted immediately
            // above. Replace only this tool's receipt before the core-response
            // differential; a global `availability` exemption would be far too
            // broad and could hide drift in unrelated tools.
            if let Some(availability) = response.pointer_mut("/value/availability") {
                *availability = Value::String("<attention-derived-availability>".into());
            }
        }
        results.push(normalize(&response));
    }

    // Prove the differential exercised real mutations rather than two identical
    // piles of errors. These are exact consequences of the fixed corpus:
    // root and Unfiled seeds (2), document creates (2), task create+facet (2),
    // update/archive/delete (3). The task link is post-v35 relationship-owned:
    // its proposition and initial assertion are two relationship events, not a
    // content event. Counting both ledgers keeps this guard exact across the
    // deliberate ownership cutover instead of silently weakening it.
    let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await?;
    let relationship_event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM relationship_events")
            .fetch_one(db.write_pool())
            .await?;
    let content_event_types: Vec<(String, i64)> =
        sqlx::query_as("SELECT type,COUNT(*) FROM content_events GROUP BY type ORDER BY type")
            .fetch_all(db.write_pool())
            .await?;
    let relationship_event_types: Vec<(String, i64)> =
        sqlx::query_as("SELECT type,COUNT(*) FROM relationship_events GROUP BY type ORDER BY type")
            .fetch_all(db.write_pool())
            .await?;
    let record_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.write_pool())
        .await?;
    let deleted_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE deleted_at IS NOT NULL")
            .fetch_one(db.write_pool())
            .await?;
    let expected_content_types = vec![
        ("facet.set".into(), 2),
        ("record.created".into(), 5),
        ("record.deleted".into(), 1),
        ("record.updated".into(), 1),
    ];
    let expected_relationship_types = vec![
        ("assertion.created.v1".into(), 1),
        ("relationship.created.v1".into(), 1),
    ];
    if (
        event_count,
        relationship_event_count,
        record_count,
        deleted_count,
    ) != (9, 2, 5, 1)
        || content_event_types != expected_content_types
        || relationship_event_types != expected_relationship_types
    {
        return Err(crate::error::Error::engine(format!(
            "disposability corpus did not populate the expected state: \
             content_events={event_count}, relationship_events={relationship_event_count}, \
             records={record_count}, deleted={deleted_count}, \
             content_event_types={content_event_types:?}, \
             relationship_event_types={relationship_event_types:?}"
        )));
    }

    // Independence must not be bought with a broken fold: the log-is-the-law
    // check has to hold on the database that lost its read log.
    let rebuild = rebuild_and_diff(&db).await?;
    results.push(json!({ "rebuild_and_diff_equal": rebuild.equal }));

    db.close().await;
    Ok(results)
}

/// The differential check itself.
pub async fn check_read_log_disposability() -> CheckResult {
    match differential().await {
        Ok(violations) => CheckResult {
            check: "read-log-disposability".into(),
            ok: violations.is_empty(),
            violations,
        },
        Err(err) => CheckResult {
            check: "read-log-disposability".into(),
            ok: false,
            violations: vec![format!("check could not run: {err}")],
        },
    }
}

async fn differential() -> Result<Vec<String>> {
    // The corpus exercises every registered handler. Keep its future off the
    // conformance caller's stack so expanding one tool cannot make storage
    // migration verification depend on the test thread's stack allowance.
    let with_log = Box::pin(run_corpus(false)).await?;
    let without_log = Box::pin(run_corpus(true)).await?;

    let mut violations: Vec<String> = Vec::new();
    if with_log.len() != without_log.len() {
        violations.push(format!(
            "corpus length differs across the drop ({} vs {}) — the replay did not run the same calls",
            with_log.len(),
            without_log.len()
        ));
        return Ok(violations);
    }
    for (index, (before, after)) in with_log.iter().zip(without_log.iter()).enumerate() {
        if before != after {
            violations.push(format!(
                "call {index} differs across the read-log drop — something outside the named exemptions reads the disposable tier.\n          with log:    {before}\n          without log: {after}"
            ));
        }
    }
    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relationship_projection_id_redaction_is_limited_to_link_rows() {
        let coordinate =
            "rel:ndb_0123456789abcdef0123456789abcdef:11111111-1111-4111-8111-111111111111";
        let value = json!({
            "links_out": [{
                "id": coordinate,
                "source_id": "source",
                "target_id": "target",
                "relationship": "implements",
                "note": coordinate,
                "created_at": "2026-08-12T12:00:00.000Z"
            }],
            "record": {"id": coordinate, "summary": coordinate},
            "error": coordinate
        });

        let normalized = normalize(&value);
        assert_eq!(
            normalized["links_out"][0]["id"],
            "<relationship-projection-id>"
        );
        assert_eq!(normalized["links_out"][0]["note"], coordinate);
        assert_eq!(normalized["record"]["id"], coordinate);
        assert_eq!(normalized["record"]["summary"], coordinate);
        assert_eq!(normalized["error"], coordinate);
    }
}
