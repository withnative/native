//! Release benchmark harness for the `whats_changed` filter pushdown
//! (task c6ee44e): safe actor/account/run/family filtering ahead of
//! authorization, with actor narrowing inside the `content_events` SQL window.
//!
//! Every case runs the same deterministic corpus and arguments through two
//! traversals and reports comparable latency plus authorization/identity
//! counts for both:
//!
//! * `optimized` — the production [`whats_changed_inner`](super::whats_changed_inner)
//!   path with its [`TraversalMetrics`](super::TraversalMetrics).
//! * `legacy` — the test-only [`legacy_reference_traversal`] below, which
//!   preserves the pre-c6ee44e semantics exactly (unfiltered SQL window,
//!   filters after authorization, full [`redact_event`](super::redact_event)
//!   with its embedded-record walk, identity reconstruction before
//!   redaction). It lives here, under `#[cfg(test)]`, and nowhere in the
//!   production path.
//!
//! The wire response deliberately exposes only caller-visible counts, so both
//! metric sets travel on in-crate paths. Each case also asserts the two
//! traversals agree on matched count and `has_more`: the harness is a parity
//! proof as well as a benchmark.
//!
//! These are ordinary (non-ignored) tests so the repository's ignored-test
//! policy stays exact: by default they run a tiny deterministic corpus that
//! is cheap in every CI lane while still asserting legacy/optimized parity.
//! Scale up for evidence runs through the environment (release profile
//! matters: the dev profile compiles workspace code at O0 per AGENTS.md,
//! which buries the per-event authorization cost this harness exists to
//! measure):
//!
//! ```bash
//! WHATS_CHANGED_BENCH_TOTAL=3000 WHATS_CHANGED_BENCH_SPARSE_EVERY=100 \
//!     cargo test --release --lib whats_changed_bench -- --nocapture
//! ```
//!
//! The corpus is deterministic: a scaled run of events on members-viewable
//! records, predominantly one author, with a sparse minority the query
//! selects. Keep the numbers in the output when quoting results so runs stay
//! comparable.

use std::time::Instant;

use serde_json::{json, Value};

use super::{
    is_impact_identity, normalize_accounts, normalize_event_families, redact_event,
    whats_changed_inner, ActorDisclosure, ActorScope, Caller, WhatsChangedArgs,
};
use crate::authorization::Capability;
use crate::db::Db;
use crate::error::Result;
use crate::query::events;

const ALICE: &str = "account:alice";
const BEA: &str = "account:bea";
const ROOT_RUN: &str = "scout-chair-a748b2";

/// Corpus size, scaled by `WHATS_CHANGED_BENCH_TOTAL` (default 120 for CI;
/// 3,000 for evidence runs). Large enough to make the before/after gap
/// unmistakable: the legacy traversal takes a top-level per-record
/// authorization decision for every row its unfiltered window returns, the
/// optimized one only for rows that can survive the filters.
fn bench_total() -> usize {
    std::env::var("WHATS_CHANGED_BENCH_TOTAL")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&total| total > 0)
        .unwrap_or(120)
}
/// Every Nth event belongs to the sparse minority the benchmark queries
/// select (actor `account:bea`, run-less, `record.updated`), via
/// `WHATS_CHANGED_BENCH_SPARSE_EVERY` (default 20, evidence runs 100).
fn bench_sparse_every() -> usize {
    std::env::var("WHATS_CHANGED_BENCH_SPARSE_EVERY")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&every| every >= 2)
        .unwrap_or(20)
}
const ITERATIONS: usize = 5;

/// Counts reported by [`legacy_reference_traversal`], field-for-field
/// comparable with [`TraversalMetrics`](super::TraversalMetrics) and named
/// with the same precision: `window_rows_seen` counts rows the (unfiltered)
/// SQL window returned to the loop — not SQLite's internal scans — and
/// `record_auth_checks` counts top-level per-record `can_record` decisions
/// only, excluding the acknowledgement/artefact checks in `event_is_visible`,
/// the person-policy evaluations in `ActorDisclosure`, and the
/// embedded-record walk inside the full `redact_event`.
#[derive(Clone, Copy, Debug, Default)]
struct ReferenceOutcome {
    window_rows_seen: u64,
    record_auth_checks: u64,
    identity_lookups: u64,
    matched: i64,
    has_more: bool,
    scanned_through_seq: i64,
}

/// Test-only reference traversal preserving the pre-c6ee44e `whats_changed`
/// semantics: the SQL window carries no actor predicate, and every returned
/// row is authorized, visibility-checked, identity-reconstructed, fully
/// redacted (embedded-record walk included, malformed payloads normalized to
/// `None`), and only then filtered by actor, account, run, and family.
///
/// Structurally this is the loop body the optimization replaced, kept
/// line-for-line in gate order so the bench compares the same answers with
/// and without the pushdown. `record_auth_checks` counts the same top-level
/// `can_record` calls the optimized metrics count; the legacy path
/// additionally pays the embedded-record authorization walk inside
/// `redact_event`, which no counter observes on either side — so where the
/// two counts differ, the true legacy cost is strictly higher than reported.
async fn legacy_reference_traversal(
    db: Db,
    caller: Caller,
    arguments: Value,
) -> Result<ReferenceOutcome> {
    let args: WhatsChangedArgs = super::super::parse_args("whats_changed", arguments)?;
    let order = args.order.event_order();
    let mut after_seq = args.after_seq.unwrap_or_else(|| order.initial_cursor());
    let limit = args.limit.unwrap_or(events::DEFAULT_CHANGE_WINDOW_LIMIT);
    let actor_scope = args.actor_scope.unwrap_or_default();
    let accounts = normalize_accounts(args.accounts.clone())?;
    let selected_families = normalize_event_families(args.event_families.clone())?;

    let mut outcome = ReferenceOutcome::default();
    let mut raw_cursor = after_seq;
    let mut high_water_seq = args.through_seq;
    let mut scope_ids = None;
    let mut selected_runs = None;
    let mut membership_initialized = false;
    let mut scanned_through_seq = after_seq;
    let mut has_more = false;
    let mut matched = 0i64;
    let mut actor_disclosure = ActorDisclosure::default();
    'raw_pages: loop {
        let membership = if membership_initialized {
            events::ChangeMembership::default()
        } else {
            events::ChangeMembership {
                scope_record_id: args.scope_record_id.as_deref(),
                for_run: args.for_run.as_deref(),
                include_child_runs: args.include_child_runs,
            }
        };
        // No actor predicate: the legacy window reads every raw row.
        let snapshot = events::change_window_with_membership(
            db.write_pool(),
            raw_cursor,
            high_water_seq,
            events::MAX_CHANGE_WINDOW_LIMIT,
            membership,
            order,
        )
        .await?;
        let raw_page = snapshot.page;
        if !membership_initialized {
            scope_ids = snapshot.scope_ids;
            selected_runs = snapshot.run_keys;
            high_water_seq = Some(raw_page.high_water_seq);
            after_seq = raw_page.after_seq;
            scanned_through_seq = after_seq;
            membership_initialized = true;
        }
        let raw_has_more = raw_page.has_more;
        let raw_scanned_through_seq = raw_page.scanned_through_seq;
        for event in raw_page.events {
            let prior_scanned_through_seq = scanned_through_seq;
            scanned_through_seq = event.local_seq;
            outcome.window_rows_seen += 1;
            // Legacy order: authorize first, filter afterwards.
            outcome.record_auth_checks += 1;
            if !super::super::can_record(&db, &caller, &event.record_id, Capability::View).await? {
                continue;
            }
            if !super::event_is_visible(&db, &caller, &event).await? {
                continue;
            }
            if scope_ids
                .as_ref()
                .is_some_and(|ids| !ids.contains(&event.record_id))
            {
                continue;
            }
            let identity = super::event_time_identity(&db, &event).await?;
            outcome.identity_lookups += 1;
            let is_impact = is_impact_identity(&identity);
            let mut event = event;
            redact_event(&db, &caller, &mut actor_disclosure, &mut event).await?;
            let actor_matches = match actor_scope {
                ActorScope::All => true,
                ActorScope::Self_ => event.actor.as_deref() == Some(caller.actor()),
                ActorScope::Others => event.actor.as_deref() != Some(caller.actor()),
            };
            if !actor_matches {
                continue;
            }
            if accounts.as_ref().is_some_and(|accounts| {
                event
                    .actor
                    .as_ref()
                    .is_none_or(|actor| !accounts.contains(actor))
            }) {
                continue;
            }
            if selected_runs
                .as_ref()
                .is_some_and(|runs| event.run_key.as_ref().is_none_or(|run| !runs.contains(run)))
            {
                continue;
            }
            let families = super::event_families(&event, is_impact)?;
            if selected_families
                .as_ref()
                .is_some_and(|selected| selected.is_disjoint(&families))
            {
                continue;
            }
            if matched == limit {
                scanned_through_seq = prior_scanned_through_seq;
                has_more = true;
                break 'raw_pages;
            }
            matched += 1;
        }
        if !raw_has_more {
            scanned_through_seq = raw_scanned_through_seq;
            break;
        }
        raw_cursor = raw_scanned_through_seq;
    }
    outcome.matched = matched;
    outcome.has_more = has_more;
    outcome.scanned_through_seq = scanned_through_seq;
    Ok(outcome)
}

async fn bench_db() -> Db {
    let db = crate::db::open_database(":memory:").await.unwrap();
    crate::db::apply_schema(&db).await.unwrap();
    crate::identity::seed_database_identity(&db).await.unwrap();
    db
}

async fn insert_viewable_record(db: &Db, id: &str) {
    sqlx::query(
        "INSERT INTO records
            (id, type, kind, name, home_id, policy_anchor_id, persistence, created_at, updated_at)
         VALUES (?, 'Document', 'note', ?, NULL, ?, 'enduring',
                 '2026-08-02T00:00:00.000Z', '2026-08-02T00:00:00.000Z')",
    )
    .bind(id)
    .bind(id)
    .bind(id)
    .execute(db.write_pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO record_policies (record_id) VALUES (?)")
        .bind(id)
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO policy_entries
            (policy_anchor_id, subject_kind, subject_id, effect, capability)
         VALUES (?, 'members', 'native:members', 'allow', 'view')",
    )
    .bind(id)
    .execute(db.write_pool())
    .await
    .unwrap();
}

/// A run of `record.updated` events with no run key: all but every
/// `sparse_every`th by Alice, the rest by Bea. Bea has no person binding, so
/// her actor is undisclosable to Alice — exactly the mixed-visibility shape
/// the sparse queries must preserve.
async fn sparse_actor_corpus(db: &Db) {
    let (total, sparse_every) = (bench_total(), bench_sparse_every());
    for id in ["record:alice-log", "record:bea-log"] {
        insert_viewable_record(db, id).await;
    }
    for n in 0..total {
        let sparse = n % sparse_every == 0;
        sqlx::query(
            "INSERT INTO content_events
                (id, record_id, type, payload, actor, run_key, created_at,
                 causal_envelope_version, causal_status)
             VALUES (?, ?, 'record.updated', ?, ?, NULL,
                     strftime('%Y-%m-%dT%H:%M:%fZ', '2026-08-02T00:00:00Z', '+' || ? || ' seconds'),
                     1, 'legacy_unknown')",
        )
        .bind(format!("event:{n}"))
        .bind(if sparse {
            "record:bea-log"
        } else {
            "record:alice-log"
        })
        .bind(format!("{{\"summary\":\"event {n}\"}}"))
        .bind(if sparse { BEA } else { ALICE })
        .bind(n.to_string())
        .execute(db.write_pool())
        .await
        .unwrap();
    }
}

/// Alice-authored `record.updated` events plus one `facet.set` per
/// `sparse_every` events, all under one run key: the family-sparse corpus.
async fn sparse_family_corpus(db: &Db) {
    let (total, sparse_every) = (bench_total(), bench_sparse_every());
    insert_viewable_record(db, "record:log").await;
    let mut n = 0;
    for _ in 0..(total / sparse_every) {
        for _ in 0..(sparse_every - 1) {
            sqlx::query(
                "INSERT INTO content_events
                    (id, record_id, type, payload, actor, run_key, created_at,
                     causal_envelope_version, causal_status)
                 VALUES (?, 'record:log', 'record.updated', ?, ?, ?,
                         strftime('%Y-%m-%dT%H:%M:%fZ', '2026-08-02T00:00:00Z', '+' || ? || ' seconds'),
                         1, 'legacy_unknown')",
            )
            .bind(format!("event:{n}"))
            .bind(format!("{{\"summary\":\"event {n}\"}}"))
            .bind(ALICE)
            .bind(ROOT_RUN)
            .bind(n.to_string())
            .execute(db.write_pool())
            .await
            .unwrap();
            n += 1;
        }
        sqlx::query(
            "INSERT INTO content_events
                (id, record_id, type, payload, actor, run_key, created_at,
                 causal_envelope_version, causal_status)
             VALUES (?, 'record:log', 'facet.set', ?, ?, ?,
                     strftime('%Y-%m-%dT%H:%M:%fZ', '2026-08-02T00:00:00Z', '+' || ? || ' seconds'),
                     1, 'legacy_unknown')",
        )
        .bind(format!("event:{n}"))
        .bind("{\"key\":\"priority\",\"value\":\"high\"}")
        .bind(ALICE)
        .bind(ROOT_RUN)
        .bind(n.to_string())
        .execute(db.write_pool())
        .await
        .unwrap();
        n += 1;
    }
}

/// One viewable record carrying a valid event plus one Bea-private record
/// carrying a stored payload no JSON parser accepts. Both traversals must
/// match the control and reject the hidden corrupt row at authorization,
/// before anything parses it — and agree with each other. (An authorized
/// corrupt row is deliberately absent: it reaches the post-authorization
/// identity reconstruction, which can fail SQLite JSON exactly as before
/// this change, and would fail both traversals alike.)
async fn malformed_payload_corpus(db: &Db) {
    insert_viewable_record(db, "record:control").await;
    sqlx::query(
        "INSERT INTO content_events
            (id, record_id, type, payload, actor, run_key, created_at,
             causal_envelope_version, causal_status)
         VALUES ('event:control', 'record:control', 'record.updated',
                 '{\"summary\":\"control\"}', ?, NULL,
                 '2026-08-02T00:00:00.000Z', 1, 'legacy_unknown')",
    )
    .bind(ALICE)
    .execute(db.write_pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO records
            (id, type, kind, name, policy_anchor_id, persistence, created_at, updated_at)
         VALUES ('record:hidden-garbage', 'Document', 'note', 'Hidden garbage',
                 'record:hidden-garbage', 'enduring',
                 '2026-08-02T00:00:00.000Z', '2026-08-02T00:00:00.000Z')",
    )
    .execute(db.write_pool())
    .await
    .unwrap();
    sqlx::query("INSERT INTO record_policies (record_id) VALUES ('record:hidden-garbage')")
        .execute(db.write_pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO policy_entries
            (policy_anchor_id, subject_kind, subject_id, effect, capability)
         VALUES ('record:hidden-garbage', 'account', ?, 'allow', 'view')",
    )
    .bind(BEA)
    .execute(db.write_pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO content_events
            (id, record_id, type, payload, actor, run_key, created_at,
             causal_envelope_version, causal_status)
         VALUES ('event:hidden-garbage', 'record:hidden-garbage', 'record.updated',
                 '{not json', ?, NULL,
                 '2026-08-02T00:00:01.000Z', 1, 'legacy_unknown')",
    )
    .bind(BEA)
    .execute(db.write_pool())
    .await
    .unwrap();
}

async fn run_case(db: &Db, name: &str, arguments: Value) {
    let mut optimized_ms = Vec::with_capacity(ITERATIONS);
    let mut legacy_ms = Vec::with_capacity(ITERATIONS);
    let mut first_metrics = None;
    let mut first_reference = None;
    let mut first_matched = 0;
    let mut first_has_more = false;
    let mut first_scanned = 0;
    for _ in 0..ITERATIONS {
        let start = Instant::now();
        let (value, metrics) =
            whats_changed_inner(db.clone(), Caller::authenticated(ALICE), arguments.clone())
                .await
                .unwrap();
        optimized_ms.push(start.elapsed().as_secs_f64() * 1000.0);
        let start = Instant::now();
        let reference =
            legacy_reference_traversal(db.clone(), Caller::authenticated(ALICE), arguments.clone())
                .await
                .unwrap();
        legacy_ms.push(start.elapsed().as_secs_f64() * 1000.0);
        if first_metrics.is_none() {
            first_metrics = Some(metrics);
            first_reference = Some(reference);
            first_matched = value["matched_event_count"].as_i64().unwrap();
            first_has_more = value["has_more"].as_bool().unwrap();
            first_scanned = value["scanned_through_local_seq"].as_i64().unwrap();
        }
    }
    let metrics = first_metrics.unwrap();
    let reference: ReferenceOutcome = first_reference.unwrap();
    // Parity proof: the reorder must not change answers.
    assert_eq!(
        first_matched, reference.matched,
        "case={name}: optimized matched {first_matched} != legacy {}",
        reference.matched
    );
    assert_eq!(
        first_has_more, reference.has_more,
        "case={name}: has_more parity"
    );
    // Cursor parity holds for these cases because each either exhausts its
    // window (both land on the far end) or carries no actor predicate (both
    // walk identical rows). It is not a universal guarantee: on a
    // non-exhausted actor-filtered page the optimized cursor legitimately
    // skips rows the SQL predicate excluded, and continuation stays
    // gap-free from either position.
    assert_eq!(
        first_scanned, reference.scanned_through_seq,
        "case={name}: cursor parity"
    );
    optimized_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    legacy_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = |samples: &[f64]| samples.iter().sum::<f64>() / samples.len() as f64;
    eprintln!(
        "[whats_changed_bench] case={name} iterations={ITERATIONS} \
         optimized_mean_ms={:.1} legacy_mean_ms={:.1} \
         optimized{{window_rows={} record_auth={} identity={}}} \
         legacy{{window_rows={} record_auth={} identity={}}} matched={first_matched} args={arguments}",
        mean(&optimized_ms),
        mean(&legacy_ms),
        metrics.window_rows_seen,
        metrics.record_auth_checks,
        metrics.identity_lookups,
        reference.window_rows_seen,
        reference.record_auth_checks,
        reference.identity_lookups,
    );
}

#[tokio::test]
async fn sparse_others_over_single_author_log() {
    let db = bench_db().await;
    sparse_actor_corpus(&db).await;
    run_case(
        &db,
        "sparse_others",
        json!({"actor_scope": "others", "limit": 200}),
    )
    .await;
    db.close().await;
}

#[tokio::test]
async fn sparse_accounts_over_single_author_log() {
    let db = bench_db().await;
    sparse_actor_corpus(&db).await;
    run_case(
        &db,
        "sparse_accounts",
        json!({"accounts": [BEA], "limit": 200}),
    )
    .await;
    db.close().await;
}

#[tokio::test]
async fn sparse_family_over_uniform_log() {
    let db = bench_db().await;
    sparse_family_corpus(&db).await;
    run_case(
        &db,
        "sparse_family",
        json!({"event_families": ["facets"], "limit": 200}),
    )
    .await;
    db.close().await;
}

#[tokio::test]
async fn dense_unfiltered_control() {
    let db = bench_db().await;
    sparse_actor_corpus(&db).await;
    run_case(&db, "dense_control", json!({"limit": 200})).await;
    db.close().await;
}

#[tokio::test]
async fn malformed_payload_parity() {
    let db = bench_db().await;
    malformed_payload_corpus(&db).await;
    // Unfiltered and family-filtered: both traversals match the valid
    // control, reject the hidden corrupt row at authorization, and agree.
    run_case(&db, "malformed_unfiltered", json!({})).await;
    run_case(
        &db,
        "malformed_created_filter",
        json!({"event_families": ["created"]}),
    )
    .await;
    db.close().await;
}
