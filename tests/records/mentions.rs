//! Slice 1: the lexical mention scanner against the shared fixture corpus.
//!
//! `tests/fixtures/mentions/corpus.json` is the canonical corpus, also
//! readable from JS (see `tests/fixtures/mentions/README.md`; the JS consumer
//! lands in slice 5 on the demo lineage). This test pins
//! `native_ce::mentions::scan_body` to it case by case, and additionally
//! asserts every span lands on a character boundary.
//!
//! The unit tests below specify grammar v1 independently of the corpus:
//! scheme-less and case-insensitive hosts, tilde parity, inline-code scope,
//! and the bounded unmatched-wiki scan.

use native_ce::mentions::{scan_body, MENTION_PARSER_VERSION};
use std::path::PathBuf;

#[test]
fn parser_version_is_one() {
    assert_eq!(MENTION_PARSER_VERSION, 1);
}

#[test]
fn fixture_corpus_matches_scanner() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(root.join("tests/fixtures/mentions/corpus.json"))
        .expect("read mentions corpus");
    let corpus: serde_json::Value = serde_json::from_str(&raw).expect("parse mentions corpus");
    assert_eq!(
        corpus["version"], 1,
        "corpus version tracks MENTION_PARSER_VERSION"
    );
    let cases = corpus["cases"].as_array().expect("cases is an array");
    assert!(!cases.is_empty(), "corpus must not be empty");
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        let body = case["body"].as_str().expect("case body");
        let expected = case["expected"].as_array().expect("case expected");
        let got = scan_body(body);
        assert_eq!(
            got.len(),
            expected.len(),
            "case {name}: expected {} occurrence(s), got {} ({got:?})",
            expected.len(),
            got.len()
        );
        for (occurrence, want) in got.iter().zip(expected.iter()) {
            assert_eq!(
                occurrence.form.as_str(),
                want["form"].as_str().expect("form"),
                "case {name}: form"
            );
            assert_eq!(
                occurrence.authored_reference,
                want["authored_reference"]
                    .as_str()
                    .expect("authored_reference"),
                "case {name}: authored_reference"
            );
            assert_eq!(
                occurrence.lookup_key,
                want["lookup_key"].as_str().expect("lookup_key"),
                "case {name}: lookup_key"
            );
            assert_eq!(
                occurrence.span_start,
                want["span_start"].as_u64().expect("span_start") as usize,
                "case {name}: span_start"
            );
            assert_eq!(
                occurrence.span_end,
                want["span_end"].as_u64().expect("span_end") as usize,
                "case {name}: span_end"
            );
        }
        for occurrence in &got {
            assert!(
                body.is_char_boundary(occurrence.span_start),
                "case {name}: span_start is a char boundary"
            );
            assert!(
                body.is_char_boundary(occurrence.span_end),
                "case {name}: span_end is a char boundary"
            );
        }
    }
}

#[test]
fn scheme_and_host_match_case_insensitively() {
    let body = "Read HTTP://N8V.TO/ABC1234 now.";
    let got = scan_body(body);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].form.as_str(), "url");
    assert_eq!(got[0].authored_reference, "ABC1234");
    assert_eq!(got[0].lookup_key, "abc1234");
    assert_eq!(
        &body[got[0].span_start..got[0].span_end],
        "HTTP://N8V.TO/ABC1234"
    );
}

#[test]
fn tilde_fences_skip_like_backticks() {
    let body = "~~~\nabc1234\n~~~\nReal abc1234 here.";
    let got = scan_body(body);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].authored_reference, "abc1234");
    assert_eq!(&body[got[0].span_start..got[0].span_end], "abc1234");
}

#[test]
fn inline_code_is_not_a_fence() {
    // Grammar v1 skips fenced blocks only; backtick spans still scan.
    let got = scan_body("Use `abc1234` here.");
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].authored_reference, "abc1234");
}

#[test]
fn many_unmatched_wikis_scan_bounded_and_empty() {
    // No wall-clock assertion: boundedness follows from the 512-byte closer
    // window, so these pin correctness on inputs where an unbounded search
    // would be O(n²).
    assert!(scan_body(&"[[".repeat(10_000)).is_empty());
    assert!(scan_body(&format!("[[{}", "a".repeat(1_000))).is_empty());
    assert!(scan_body(&"[[".repeat(500)).is_empty());
}

#[test]
fn multibyte_unmatched_wiki_at_search_edge_does_not_panic() {
    // '𝄞' is 4 bytes in UTF-8 and the leading 'a' places byte 512 of the
    // closer-search window mid-character; the window end must retreat to a
    // boundary rather than panic, and the unmatched opener yields nothing.
    let body = format!("[[a{}", "\u{1D11E}".repeat(200));
    assert!(scan_body(&body).is_empty());
    // Multibyte content inside a closed wiki still resolves with byte spans.
    let body = "See [[caf\u{e9}]] end.";
    let got = scan_body(body);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got[0].form.as_str(), "wiki_name");
    assert_eq!(got[0].authored_reference, "caf\u{e9}");
    assert_eq!(&body[got[0].span_start..got[0].span_end], "[[caf\u{e9}]]");
}

// ---------------------------------------------------------------------------
// Slice 2: the current-state `record_mentions` projection fold.
//
// These tests pin the fold, not the scanner: expected rows are derived from
// `scan_body` (pinned above and by the corpus test), and every assertion is
// about replacement semantics, provenance stamping and rebuild equality.
// Bodies use fixed seven-hex references that the v1 grammar matches
// deterministically.
// ---------------------------------------------------------------------------

use native_ce::conformance::rebuild_and_diff;
use native_ce::store::{create_record, delete_record, update_record};
use native_ce::{create_database, Db};
use serde_json::json;
use sqlx::Row;

const BODY_A: &str = "See abc1234 and [[My Note]] end.";
const BODY_B: &str = "Now https://n8v.to/def5678 only.";

#[derive(Debug, PartialEq, Eq)]
struct MentionRow {
    source_id: String,
    occurrence_ix: i64,
    source_event_seq: i64,
    span_start: i64,
    span_end: i64,
    authored_reference: String,
    lookup_key: String,
    form: String,
    parser_version: i64,
}

async fn mention_rows(db: &Db, source_id: &str) -> Vec<MentionRow> {
    sqlx::query(
        "SELECT source_id, occurrence_ix, source_event_seq, span_start, span_end,
                authored_reference, lookup_key, form, parser_version
           FROM record_mentions WHERE source_id = ? ORDER BY occurrence_ix",
    )
    .bind(source_id)
    .fetch_all(db.pool())
    .await
    .unwrap()
    .iter()
    .map(|row| MentionRow {
        source_id: row.get("source_id"),
        occurrence_ix: row.get("occurrence_ix"),
        source_event_seq: row.get("source_event_seq"),
        span_start: row.get("span_start"),
        span_end: row.get("span_end"),
        authored_reference: row.get("authored_reference"),
        lookup_key: row.get("lookup_key"),
        form: row.get("form"),
        parser_version: row.get("parser_version"),
    })
    .collect()
}

async fn latest_seq(db: &Db, record_id: &str) -> i64 {
    sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id = ?")
        .bind(record_id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

fn expected_rows(source_id: &str, source_event_seq: i64, body: &str) -> Vec<MentionRow> {
    scan_body(body)
        .iter()
        .enumerate()
        .map(|(ix, occurrence)| MentionRow {
            source_id: source_id.to_string(),
            occurrence_ix: ix as i64,
            source_event_seq,
            span_start: occurrence.span_start as i64,
            span_end: occurrence.span_end as i64,
            authored_reference: occurrence.authored_reference.clone(),
            lookup_key: occurrence.lookup_key.clone(),
            form: occurrence.form.as_str().to_string(),
            parser_version: MENTION_PARSER_VERSION,
        })
        .collect()
}

async fn create_noted(db: &Db, body: serde_json::Value) -> String {
    create_record(
        db,
        json!({"type": "Document", "kind": "note", "name": "mention fold", "body": body}),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn create_with_body_folds_current_mentions() {
    let db = create_database(":memory:").await.unwrap();
    let id = create_noted(&db, json!(BODY_A)).await;
    let seq = latest_seq(&db, &id).await;
    let rows = mention_rows(&db, &id).await;
    assert_eq!(rows, expected_rows(&id, seq, BODY_A));
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert!(rows.iter().all(|row| row.parser_version == 1));
    db.close().await;
}

#[tokio::test]
async fn create_without_body_leaves_no_rows() {
    let db = create_database(":memory:").await.unwrap();
    for body in [
        json!(null),
        json!(""),
        json!("plain prose without references"),
    ] {
        let id = create_noted(&db, body).await;
        assert!(mention_rows(&db, &id).await.is_empty());
    }
    db.close().await;
}

#[tokio::test]
async fn update_body_replaces_mentions_with_new_provenance() {
    let db = create_database(":memory:").await.unwrap();
    let id = create_noted(&db, json!(BODY_A)).await;
    update_record(&db, &id, json!({"body": BODY_B}))
        .await
        .unwrap();
    let seq = latest_seq(&db, &id).await;
    let rows = mention_rows(&db, &id).await;
    assert_eq!(rows, expected_rows(&id, seq, BODY_B));
    assert_eq!(rows.len(), 1, "{rows:?}");
    // Old occurrences are absent: replacement, never accumulation.
    assert!(!rows.iter().any(|row| row.authored_reference == "abc1234"));
    assert!(!rows.iter().any(|row| row.authored_reference == "My Note"));
    db.close().await;
}

#[tokio::test]
async fn metadata_only_update_preserves_mentions_and_provenance() {
    let db = create_database(":memory:").await.unwrap();
    let id = create_noted(&db, json!(BODY_A)).await;
    let before_seq = latest_seq(&db, &id).await;
    let before = mention_rows(&db, &id).await;
    assert_eq!(before.len(), 2);
    update_record(&db, &id, json!({"name": "renamed", "summary": "touched"}))
        .await
        .unwrap();
    // A new event exists, but the body it carries is unchanged.
    assert!(latest_seq(&db, &id).await > before_seq);
    assert_eq!(mention_rows(&db, &id).await, before);
    assert_eq!(
        mention_rows(&db, &id).await,
        expected_rows(&id, before_seq, BODY_A)
    );
    db.close().await;
}

#[tokio::test]
async fn null_or_empty_body_update_leaves_no_rows() {
    let db = create_database(":memory:").await.unwrap();
    let id = create_noted(&db, json!(BODY_A)).await;
    assert_eq!(mention_rows(&db, &id).await.len(), 2);
    update_record(&db, &id, json!({"body": null}))
        .await
        .unwrap();
    assert!(mention_rows(&db, &id).await.is_empty());
    // Re-adding a body folds it again under the re-add event's sequence.
    update_record(&db, &id, json!({"body": BODY_B}))
        .await
        .unwrap();
    let seq = latest_seq(&db, &id).await;
    assert_eq!(
        mention_rows(&db, &id).await,
        expected_rows(&id, seq, BODY_B)
    );
    update_record(&db, &id, json!({"body": ""})).await.unwrap();
    assert!(mention_rows(&db, &id).await.is_empty());
    db.close().await;
}

#[tokio::test]
async fn delete_removes_mention_rows() {
    let db = create_database(":memory:").await.unwrap();
    let id = create_noted(&db, json!(BODY_A)).await;
    assert_eq!(mention_rows(&db, &id).await.len(), 2);
    delete_record(&db, &id).await.unwrap();
    assert!(mention_rows(&db, &id).await.is_empty());
    db.close().await;
}

#[tokio::test]
async fn rebuild_and_diff_equal_after_mixed_mention_history() {
    let db = create_database(":memory:").await.unwrap();
    let kept = create_noted(&db, json!(BODY_A)).await;
    let replaced = create_noted(&db, json!(BODY_A)).await;
    update_record(&db, &replaced, json!({"body": BODY_B}))
        .await
        .unwrap();
    let renamed = create_noted(&db, json!(BODY_B)).await;
    update_record(&db, &renamed, json!({"summary": "metadata only"}))
        .await
        .unwrap();
    let emptied = create_noted(&db, json!(BODY_A)).await;
    update_record(&db, &emptied, json!({"body": null}))
        .await
        .unwrap();
    let tombstoned = create_noted(&db, json!(BODY_A)).await;
    delete_record(&db, &tombstoned).await.unwrap();
    let plain = create_noted(&db, json!("no references here")).await;

    assert_eq!(mention_rows(&db, &kept).await.len(), 2);
    assert_eq!(mention_rows(&db, &replaced).await.len(), 1);
    assert_eq!(mention_rows(&db, &renamed).await.len(), 1);
    assert!(mention_rows(&db, &emptied).await.is_empty());
    assert!(mention_rows(&db, &tombstoned).await.is_empty());
    assert!(mention_rows(&db, &plain).await.is_empty());

    let result = rebuild_and_diff(&db).await.unwrap();
    assert!(
        result.equal,
        "rebuild drift: {}",
        serde_json::to_string_pretty(&result.tables).unwrap()
    );
    assert!(result.event_count > 0);
    db.close().await;
}

#[tokio::test]
async fn non_string_body_update_scans_the_stored_json_text() {
    let db = create_database(":memory:").await.unwrap();
    let id = create_noted(&db, json!(BODY_A)).await;
    assert_eq!(mention_rows(&db, &id).await.len(), 2);

    // The public store accepts a non-string JSON body. `records.body` is
    // TEXT, so the projector stores the value's JSON rendering; the mention
    // fold must scan that same text rather than skip the update, or a
    // string->non-string transition would drift between live folding, the
    // migration backfill (which reads the stored column) and replay.
    for (value, stored) in [
        (
            json!({"note": "keep abc1234 in mind"}),
            r#"{"note":"keep abc1234 in mind"}"#,
        ),
        (
            json!(["deadbee and [[Wiki Name]]"]),
            r#"["deadbee and [[Wiki Name]]"]"#,
        ),
    ] {
        update_record(&db, &id, json!({ "body": value }))
            .await
            .unwrap();
        let actual: String = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
            .bind(&id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(actual, stored);
        let seq = latest_seq(&db, &id).await;
        assert_eq!(
            mention_rows(&db, &id).await,
            expected_rows(&id, seq, stored)
        );
    }

    let result = rebuild_and_diff(&db).await.unwrap();
    assert!(
        result.equal,
        "rebuild drift after non-string bodies: {}",
        serde_json::to_string_pretty(&result.tables).unwrap()
    );
    db.close().await;
}

/// The fourth writer of `records.body` is `unit.revision.recorded.v1`, so a
/// Unit revision must fold mentions live, backfill with the revision event's
/// sequence on migration, and rebuild equal.
#[tokio::test]
async fn unit_revision_body_folds_and_backfills_mentions() {
    use native_ce::authorization::Principal;
    use native_ce::freshness::{
        current_record_body_revision, promote_idea, revise_unit, ExpressionRole, IdempotencyKey,
        OccurrenceSelector, PromoteIdeaInput, ReviseUnitInput, UnitContent,
    };
    use native_ce::migrations::EngineMigrationRegistry;
    use sqlx::sqlite::{SqliteConnectOptions, SqliteConnection};
    use sqlx::Connection;
    use std::str::FromStr;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("unit-mentions.db");
    let db = create_database(path.to_str().unwrap()).await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();

    let principal = || Principal::bound("acct:mentions-unit", true);
    let actor = "test:mentions-unit";
    let source = create_record(
        &db,
        json!({
            "type":"Document","kind":"note","name":"Idea source",
            "body":"Audience: technical founders."
        }),
    )
    .await
    .unwrap();
    let promoted = promote_idea(
        &db,
        principal(),
        actor,
        PromoteIdeaInput {
            source_revision: current_record_body_revision(&db, &source).await.unwrap(),
            selectors: vec![OccurrenceSelector::TextQuote {
                exact: "Audience: technical founders.".into(),
                prefix: None,
                suffix: None,
                position_hint: None,
            }],
            first_content: UnitContent::text("Primary audience: technical founders.").unwrap(),
            expression_role: ExpressionRole::Canonical,
            label: None,
            requested_unit_id: None,
            requested_occurrence_id: None,
            idempotency_key: IdempotencyKey::new("mentions-unit-promote").unwrap(),
        },
    )
    .await
    .unwrap();
    let unit_id = promoted.unit_id.as_str().to_owned();
    assert!(mention_rows(&db, &unit_id).await.is_empty());

    let revised = "See abc1234 and [[Wiki Note]] end.";
    revise_unit(
        &db,
        principal(),
        actor,
        ReviseUnitInput {
            unit_id: promoted.unit_id.clone(),
            expected_current: promoted.first_revision.clone(),
            content: UnitContent::text(revised).unwrap(),
            rationale: "Add mention-bearing content.".into(),
            idempotency_key: IdempotencyKey::new("mentions-unit-revise").unwrap(),
        },
    )
    .await
    .unwrap();

    let revision_seq: i64 = sqlx::query_scalar(
        "SELECT seq FROM content_events WHERE record_id = ? AND type = 'unit.revision.recorded.v1'
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(&unit_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    let live = mention_rows(&db, &unit_id).await;
    assert_eq!(live, expected_rows(&unit_id, revision_seq, revised));
    db.close().await;

    // Reconstruct the engine-58 preimage, run the real 58->59 edge, and prove
    // the backfill stamps the revision event and converges with the live fold.
    let options = SqliteConnectOptions::from_str(&format!("sqlite:{}", path.display()))
        .unwrap()
        .foreign_keys(true);
    let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
    // Reconstruct the released engine-58 shape before exercising its real
    // record-mentions backfill edge.
    for statement in [
        "DROP INDEX idx_external_observations_act",
        "ALTER TABLE external_observations DROP COLUMN act",
        "DROP INDEX idx_awareness_command_intents_act",
        "ALTER TABLE awareness_command_intents DROP COLUMN act",
        "DROP INDEX idx_content_events_act",
        "DROP INDEX idx_policy_events_act",
        "DROP INDEX idx_awareness_events_act",
        "DROP INDEX idx_notification_candidate_events_act",
        "DROP INDEX idx_binding_audit_act",
        "DROP INDEX idx_database_identity_audit_act",
        "DROP INDEX idx_meta_events_act",
        "DROP INDEX idx_control_events_act",
        "DROP INDEX idx_derivation_events_act",
        "DROP INDEX idx_relationship_events_act",
        "DROP TRIGGER binding_systems_no_insert",
        "DROP TRIGGER binding_systems_no_update",
        "DROP TRIGGER binding_systems_no_delete",
        "DROP INDEX idx_provenance_validity_act",
        "ALTER TABLE provenance_attestation_validity_events DROP COLUMN act",
    ] {
        sqlx::query(statement).execute(&mut conn).await.unwrap();
    }
    sqlx::query("DROP TABLE record_mentions")
        .execute(&mut conn)
        .await
        .unwrap();
    sqlx::query("DROP TABLE alpha_tab_installs")
        .execute(&mut conn)
        .await
        .unwrap();
    sqlx::query("PRAGMA user_version=58")
        .execute(&mut conn)
        .await
        .unwrap();
    let registry = EngineMigrationRegistry::production();
    let step = registry.pending(58, 59).unwrap().pop().unwrap();
    step.preflight(&mut conn).await.unwrap();
    step.apply(&mut conn).await.unwrap();
    sqlx::query("PRAGMA user_version=59")
        .execute(&mut conn)
        .await
        .unwrap();
    for (from, to) in [(59, 60), (60, 61), (61, 62), (62, 63), (63, 64), (64, 65)] {
        let step = registry.pending(from, to).unwrap().pop().unwrap();
        step.preflight(&mut conn).await.unwrap();
        step.apply(&mut conn).await.unwrap();
        sqlx::query(&format!("PRAGMA user_version={to}"))
            .execute(&mut conn)
            .await
            .unwrap();
    }
    conn.close().await.unwrap();

    let migrated = native_ce::open_existing_database_at(&path).await.unwrap();
    assert_eq!(mention_rows(&migrated, &unit_id).await, live);
    let result = rebuild_and_diff(&migrated).await.unwrap();
    assert!(
        result.equal,
        "unit-revision rebuild drift: {}",
        serde_json::to_string_pretty(&result.tables).unwrap()
    );
    migrated.close().await;
}

// ---------------------------------------------------------------------------
// Slice 3: authorized current reads + rendering.
//
// The projection stores lexicon only; these tests pin resolution, visibility
// and pagination at the read boundary. A target is referenced by a bare
// seven-hex prefix so the grammar matches it deterministically, and caller
// visibility is toggled with an explicit policy so hidden peers are real.
// ---------------------------------------------------------------------------

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::render;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};

fn mention_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    tool: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap()
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: serde_json::Value,
) -> serde_json::Value {
    registry.call(db.clone(), caller, tool, args).await.unwrap()
}

fn bea() -> Caller {
    Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false)
}

async fn create(registry: &ToolRegistry, db: &Db, mut args: serde_json::Value) -> String {
    if let Some(object) = args.as_object_mut() {
        object
            .entry("reason")
            .or_insert_with(|| json!("mentions slice 3 test fixture"));
    }
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// Make `id` invisible to `bea` (visible only to `acct:alice`).
async fn hide_from_bea(db: &Db, id: &str) {
    replace_explicit_policy(
        db,
        "test:policy",
        id,
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();
}

fn hex_prefix(id: &str, len: usize) -> String {
    id.chars()
        .filter(|character| *character != '-')
        .take(len)
        .collect()
}

async fn note(registry: &ToolRegistry, db: &Db, name: &str) -> String {
    create(
        registry,
        db,
        json!({ "type": "Document", "kind": "note", "name": name }),
    )
    .await
}

async fn note_with_body(registry: &ToolRegistry, db: &Db, name: &str, body: String) -> String {
    create(
        registry,
        db,
        json!({ "type": "Document", "kind": "note", "name": name, "body": body }),
    )
    .await
}

fn mention_of<'a>(record: &'a serde_json::Value, form: &str) -> &'a serde_json::Value {
    record["mentions_out"]
        .as_array()
        .expect("mentions_out is an array")
        .iter()
        .find(|entry| entry["form"] == json!(form))
        .expect("an outgoing mention with the requested form")
}

#[tokio::test]
async fn outgoing_mentions_resolve_visible_targets_and_count_occurrences() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    let target = note(&registry, &db, "Target note").await;
    let prefix = hex_prefix(&target, 7);
    let body = format!("See {prefix} twice: {prefix}, and [[Missing note]].");
    let source = note_with_body(&registry, &db, "Source note", body).await;

    let payload = call(&registry, &db, "get_record", json!({ "ids": [source] })).await;
    let record = &payload["records"][0];
    assert_eq!(record["mentions_out_count"], 2, "{record:#}");
    let resolved = mention_of(record, "bare_hex");
    assert_eq!(resolved["resolution"]["state"], "resolved");
    assert_eq!(resolved["resolution"]["id"], json!(target));
    assert_eq!(resolved["resolution"]["name"], "Target note");
    assert_eq!(resolved["occurrence_count"], 2);
    let unresolved = mention_of(record, "wiki_name");
    assert_eq!(unresolved["resolution"]["state"], "unresolved");

    let text = render::render("get_record", &payload).unwrap();
    assert!(text.contains("Mentions"), "{text}");
    assert!(text.contains("resolved to Target note"), "{text}");
    assert!(text.contains("unresolved"), "{text}");
    db.close().await;
}

#[tokio::test]
async fn absent_when_no_mentions_or_no_sources() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    let plain = note_with_body(&registry, &db, "Plain", "no references here".into()).await;
    let payload = call(&registry, &db, "get_record", json!({ "ids": [plain] })).await;
    let record = &payload["records"][0];
    for key in [
        "mentions_out",
        "mentions_out_count",
        "mentions_in",
        "mentions_in_count",
    ] {
        assert!(record.get(key).is_none(), "{key} absent: {record:#}");
    }
    db.close().await;
}

#[tokio::test]
async fn incoming_mentions_name_visible_sources_with_counts() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    let target = note(&registry, &db, "Backlink target").await;
    let prefix = hex_prefix(&target, 7);
    let first = note_with_body(&registry, &db, "First source", format!("One {prefix}")).await;
    let second = note_with_body(
        &registry,
        &db,
        "Second source",
        format!("Two {prefix} then {prefix}"),
    )
    .await;

    let payload = call(&registry, &db, "get_record", json!({ "ids": [target] })).await;
    let record = &payload["records"][0];
    assert_eq!(record["mentions_in_count"], 2, "{record:#}");
    let entries = record["mentions_in"].as_array().unwrap();
    let by_id = |id: &str| {
        entries
            .iter()
            .find(|entry| entry["source_id"] == json!(id))
            .unwrap_or_else(|| panic!("source {id} in mentions_in: {record:#}"))
    };
    assert_eq!(by_id(&first)["occurrence_count"], 1);
    assert_eq!(by_id(&second)["occurrence_count"], 2);
    assert_eq!(by_id(&second)["authored_references"], json!([prefix]));

    let text = render::render("get_record", &payload).unwrap();
    assert!(text.contains("Mentioned by"), "{text}");
    assert!(text.contains("Second source"), "{text}");
    db.close().await;
}

#[tokio::test]
async fn hidden_source_is_absent_from_incoming_and_its_count() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    let target = note(&registry, &db, "Shared target").await;
    let prefix = hex_prefix(&target, 7);
    let visible = note_with_body(&registry, &db, "Open source", format!("see {prefix}")).await;
    let hidden = note_with_body(&registry, &db, "Sealed source", format!("see {prefix}")).await;
    hide_from_bea(&db, &hidden).await;

    let payload = call_as(
        &registry,
        &db,
        bea(),
        "get_record",
        json!({ "ids": [target] }),
    )
    .await;
    let record = &payload["records"][0];
    assert_eq!(record["status"], "found", "{record:#}");
    // The hidden source is neither named nor counted: the total is
    // caller-relative, so it cannot leak degree.
    assert_eq!(record["mentions_in_count"], 1, "{record:#}");
    let entries = record["mentions_in"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["source_id"], json!(visible));

    let text = render::render("get_record", &payload).unwrap();
    assert!(text.contains("Open source"), "{text}");
    assert!(!text.contains("Sealed source"), "{text}");
    assert!(!text.contains(&hidden), "{text}");
    db.close().await;
}

#[tokio::test]
async fn every_incoming_source_hidden_leaves_no_count_leak() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    let target = note(&registry, &db, "Quiet target").await;
    let prefix = hex_prefix(&target, 7);
    let hidden = note_with_body(&registry, &db, "Sealed source", format!("see {prefix}")).await;
    hide_from_bea(&db, &hidden).await;

    let payload = call_as(
        &registry,
        &db,
        bea(),
        "get_record",
        json!({ "ids": [target] }),
    )
    .await;
    let record = &payload["records"][0];
    assert!(record.get("mentions_in").is_none(), "{record:#}");
    assert!(record.get("mentions_in_count").is_none(), "{record:#}");
    let text = render::render("get_record", &payload).unwrap();
    assert!(!text.contains("Mentioned by"), "{text}");
    assert!(!text.contains(&hidden), "{text}");
    db.close().await;
}

#[tokio::test]
async fn visible_collision_is_ambiguous_and_names_nothing() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    // Two caller-chosen ids share a seven-hex prefix; both stay visible.
    let first = create(
        &registry,
        &db,
        json!({
            "id": "aaaaaaa0-0000-4000-8000-000000000001",
            "type": "Document", "kind": "note", "name": "First twin",
        }),
    )
    .await;
    let second = create(
        &registry,
        &db,
        json!({
            "id": "aaaaaaa0-0000-4000-8000-000000000002",
            "type": "Document", "kind": "note", "name": "Second twin",
        }),
    )
    .await;
    let source = note_with_body(
        &registry,
        &db,
        "Ambiguous source",
        "refs aaaaaaa now".into(),
    )
    .await;

    let payload = call(&registry, &db, "get_record", json!({ "ids": [source] })).await;
    let entry = mention_of(&payload["records"][0], "bare_hex");
    assert_eq!(entry["resolution"]["state"], "ambiguous", "{entry:#}");
    assert_eq!(entry["resolution"]["visible_candidate_count"], 2);
    // The ambiguity is not an enumeration: neither id is disclosed.
    let encoded = entry.to_string();
    assert!(!encoded.contains(&first), "{encoded}");
    assert!(!encoded.contains(&second), "{encoded}");

    let text = render::render("get_record", &payload).unwrap();
    assert!(text.contains("ambiguous (2 visible matches)"), "{text}");
    db.close().await;
}

#[tokio::test]
async fn hidden_prefix_collision_does_not_create_ambiguity() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    let visible = create(
        &registry,
        &db,
        json!({
            "id": "aaaaaaa0-0000-4000-8000-0000000000ff",
            "type": "Document", "kind": "note", "name": "Visible twin",
        }),
    )
    .await;
    let hidden = create(
        &registry,
        &db,
        json!({
            "id": "aaaaaaa0-0000-4000-8000-000000000001",
            "type": "Document", "kind": "note", "name": "Hidden twin",
        }),
    )
    .await;
    hide_from_bea(&db, &hidden).await;
    let source = note_with_body(
        &registry,
        &db,
        "Collision source",
        "refs aaaaaaa now".into(),
    )
    .await;

    let payload = call_as(
        &registry,
        &db,
        bea(),
        "get_record",
        json!({ "ids": [source] }),
    )
    .await;
    let entry = mention_of(&payload["records"][0], "bare_hex");
    // The invisible collision is indistinguishable from absence: the reference
    // stays uniquely resolved to the visible record.
    assert_eq!(entry["resolution"]["state"], "resolved", "{entry:#}");
    assert_eq!(entry["resolution"]["id"], json!(visible));
    assert!(!entry.to_string().contains(&hidden), "{entry:#}");
    db.close().await;
}

/// Regression for the pre-visibility cap: with more same-prefix hidden records
/// than a naive `LIMIT` would fetch, a visible match sorting last must still
/// resolve. Before the fix this returned `unresolved`.
#[tokio::test]
async fn hidden_collision_beyond_a_naive_cap_still_resolves() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    for index in 1..=40u32 {
        let id = format!("aaaaaaa0-0000-4000-8000-0000000000{index:02x}");
        let hidden = create(
            &registry,
            &db,
            json!({
                "id": id, "type": "Document", "kind": "note",
                "name": format!("Hidden twin {index}"),
            }),
        )
        .await;
        hide_from_bea(&db, &hidden).await;
    }
    let visible = create(
        &registry,
        &db,
        json!({
            "id": "aaaaaaa0-0000-4000-8000-0000000000ff",
            "type": "Document", "kind": "note", "name": "Surviving twin",
        }),
    )
    .await;
    let source = note_with_body(
        &registry,
        &db,
        "Deep collision source",
        "refs aaaaaaa now".into(),
    )
    .await;

    let payload = call_as(
        &registry,
        &db,
        bea(),
        "get_record",
        json!({ "ids": [source] }),
    )
    .await;
    let entry = mention_of(&payload["records"][0], "bare_hex");
    assert_eq!(entry["resolution"]["state"], "resolved", "{entry:#}");
    assert_eq!(entry["resolution"]["id"], json!(visible));
    db.close().await;
}

#[tokio::test]
async fn incoming_pagination_is_deterministic_after_filtering() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    let target = note(&registry, &db, "Paged target").await;
    let prefix = hex_prefix(&target, 7);
    let mut sources = Vec::new();
    for index in 0..5 {
        sources.push(
            note_with_body(
                &registry,
                &db,
                &format!("Paged source {index}"),
                format!("see {prefix}"),
            )
            .await,
        );
    }
    sources.sort();

    let full = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [target], "links_limit": 200 }),
    )
    .await;
    let full_ids = full["records"][0]["mentions_in"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["source_id"].as_str().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(full_ids, sources, "{full:#}");

    let mut paged = Vec::new();
    for offset in 0..sources.len() as i64 {
        let payload = call(
            &registry,
            &db,
            "get_record",
            json!({ "ids": [target], "links_limit": 1, "links_offset": offset }),
        )
        .await;
        let record = &payload["records"][0];
        assert_eq!(
            record["mentions_in_count"],
            sources.len() as i64,
            "{record:#}"
        );
        let entries = record["mentions_in"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{record:#}");
        paged.push(entries[0]["source_id"].as_str().unwrap().to_string());
    }
    assert_eq!(paged, sources, "paging repeats or skips");
    db.close().await;
}

#[tokio::test]
async fn tombstoned_source_drops_out_of_incoming() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    let target = note(&registry, &db, "Tombstone target").await;
    let prefix = hex_prefix(&target, 7);
    let source = note_with_body(&registry, &db, "Doomed source", format!("see {prefix}")).await;

    let before = call(&registry, &db, "get_record", json!({ "ids": [target] })).await;
    assert_eq!(before["records"][0]["mentions_in_count"], 1);

    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": source, "reason": "withdraw the source" }),
    )
    .await;
    let after = call(&registry, &db, "get_record", json!({ "ids": [target] })).await;
    let record = &after["records"][0];
    assert!(record.get("mentions_in").is_none(), "{record:#}");
    assert!(record.get("mentions_in_count").is_none(), "{record:#}");
    db.close().await;
}

#[tokio::test]
async fn historical_read_uses_snapshot_rows_with_live_authorization() {
    let db = create_database(":memory:").await.unwrap();
    let registry = mention_registry();
    let target = note(&registry, &db, "Historical target").await;
    let prefix = hex_prefix(&target, 7);
    let source = note_with_body(&registry, &db, "Historical source", format!("see {prefix}")).await;
    let mention_seq = latest_seq(&db, &source).await;
    let before = call(&registry, &db, "get_record", json!({ "ids": [source] })).await;
    let updated_at = before["records"][0]["updated_at"]
        .as_str()
        .unwrap()
        .to_string();

    // A later edit removes the reference from the current body.
    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": source,
            "body": "nothing here now",
            "if_unmodified_since": updated_at,
            "reason": "drop the reference",
        }),
    )
    .await;
    let current = call(&registry, &db, "get_record", json!({ "ids": [source] })).await;
    assert!(
        current["records"][0].get("mentions_out").is_none(),
        "{current:#}"
    );

    // The historical body still carries it, resolved against the live visible
    // namespace.
    let historical = call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": [source], "as_of": { "content_seq": mention_seq } }),
    )
    .await;
    let entry = mention_of(&historical["records"][0], "bare_hex");
    assert_eq!(entry["resolution"]["state"], "resolved", "{entry:#}");
    assert_eq!(entry["resolution"]["id"], json!(target));

    // Hiding the target now must change the historical resolution too: live
    // meta authorizes a historical body.
    hide_from_bea(&db, &target).await;
    let historical_hidden = call_as(
        &registry,
        &db,
        bea(),
        "get_record",
        json!({ "ids": [source], "as_of": { "content_seq": mention_seq } }),
    )
    .await;
    let entry = mention_of(&historical_hidden["records"][0], "bare_hex");
    assert_eq!(entry["resolution"]["state"], "unresolved", "{entry:#}");
    db.close().await;
}

#[test]
fn raw_record_mentions_is_excluded_from_the_query_sql_catalog() {
    // Lexical lookups can name a hidden record, so the projection must never be
    // addressable as a governed SQL relation.
    let error = native_ce::query::sql::validate("SELECT * FROM record_mentions")
        .expect_err("raw record_mentions must not validate");
    assert!(
        error.to_string().contains("unauthorized_relation"),
        "{error}"
    );
}
