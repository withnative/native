//! The executable form of the search contract's behavioural claims
//! (`docs/tool-surface.md`, decision `ea7e5bd`).
//!
//! Every claim of the shape "query X finds name Y" in the search contract has
//! a row or an assertion here. That rule exists because four defects in a row
//! got through review of `ea7e5bd` — a worked example that could not work, a
//! case-folding claim that folded nothing, a tokenizer that disagreed with the
//! index, and an equivalence asserted past its boundary. None of them were
//! measurement errors; all four were prose asserting engine behaviour that
//! nobody executed.
//!
//! Two halves:
//!
//! 1. **Engine facts** — what SQLite/FTS5 actually does, asserted directly.
//!    These pin the four review findings so a future contract edit that
//!    contradicts them fails here rather than in review.
//! 2. **The contract fixture table** — the Layer 1 `LIKE` pass's specified
//!    composition, implemented once as a reference and checked against a
//!    corpus. Stage 5 (`8e9f9d3`, tool 17) makes the real implementation agree
//!    with this table; the table is the acceptance criterion, not an
//!    illustration.
//!
//! Stage 5 landed tool 17 and settled what was owed here (`8e9f9d3`):
//!
//! - `real_infix_pass_agrees_with_the_contract_fixtures` runs the SAME fixture
//!   table through the shipped implementation (`query::fts::name_infix`) on a
//!   real engine database — the reference above and the product cannot drift
//!   apart without failing this file.
//! - The bm25() re-tune has ranking rows (`bm25_weights_*`) pinning the
//!   behaviour the weights were chosen for.
//! - The *bound* (thin-results threshold + row cap) is a tool-17 behaviour;
//!   its rows live in `tests/tools/tools_stage5.rs`, which asserts the threshold
//!   gates the near-miss pass and the cap holds. The time budget is
//!   structural, not asserted: the pass is ONE capped scan of `records.name`
//!   (0.26–1.9 ms measured over 30k names, b29a84a) — a timing assertion
//!   would only add CI flake.
//! - Layer 1's other two mechanisms (prefix neighbours, tree siblings) have
//!   rows in `tests/tools/tools_stage5.rs` alongside the payload shape they ride in.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::events::LinkAddedPayload;
use native_ce::query::fts::{self, FtsOptions};
use native_ce::store::{add_link, create_record, delete_record};
use serde_json::json;
use sqlx::{Row, SqlitePool};

// Record ids must be canonical v4/v7 UUIDs, so the derived-artifact fixture ids
// in `trusted_search_authorizes_derived_artifacts_through_one_live_bearer` are
// pinned literals.
const STRICT_HIDDEN_ARTIFACT: &str = "5ea4c000-0000-4000-8000-000000000004";
const STRICT_VISIBLE_ARTIFACT: &str = "5ea4c000-0000-4000-8000-000000000005";
const PREFIX_HIDDEN_ARTIFACT: &str = "5ea4c000-0000-4000-8000-000000000006";
const PREFIX_VISIBLE_ARTIFACT: &str = "5ea4c000-0000-4000-8000-000000000007";
const INFIX_HIDDEN_ARTIFACT: &str = "5ea4c000-0000-4000-8000-000000000008";
const INFIX_VISIBLE_ARTIFACT: &str = "5ea4c000-0000-4000-8000-000000000009";

async fn pool() -> SqlitePool {
    SqlitePool::connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite")
}

async fn names(db: &SqlitePool, sql: &str, params: &[&str]) -> Vec<String> {
    let mut q = sqlx::query(sql);
    for p in params {
        q = q.bind(*p);
    }
    q.fetch_all(db)
        .await
        .expect("query")
        .iter()
        .map(|r| r.get::<String, _>("name"))
        .collect()
}

async fn yes(db: &SqlitePool, sql: &str) -> bool {
    sqlx::query(sql)
        .fetch_one(db)
        .await
        .expect("scalar")
        .get::<i64, _>(0)
        == 1
}

// ---------------------------------------------------------------------------
// The Layer 1 `LIKE` pass, as specified. Reference implementation.
// ---------------------------------------------------------------------------

/// Tokenize the way `unicode61` does — on runs of non-alphanumeric characters,
/// NOT on whitespace. Whitespace-only splitting disagrees with the index on
/// every punctuation-bearing query: `detail-record layout` would yield the
/// literal predicate `%detail-record%`, which reaches nothing.
///
/// Every token is kept. There is no minimum length: under AND, dropping a
/// token removes a constraint and *widens* the result set ("AI policy" would
/// become "policy"), which is the opposite of a safeguard.
fn tokenize(query: &str) -> Vec<String> {
    query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// One `LIKE '%tok%'` predicate per token, `AND`-ed, with `%` `_` and the
/// escape character itself escaped.
///
/// Note the escaping is a safety net rather than a live path: `tokenize`
/// splits on every non-alphanumeric, so no token it produces can contain `%`
/// or `_` (asserted by `tokenization_cannot_emit_like_wildcards` below). It
/// stays because the guarantee lives in the tokenizer, and a tokenizer change
/// should not silently become an injection into the predicate.
fn like_pass(query: &str) -> (String, Vec<String>) {
    let tokens = tokenize(query);
    let params: Vec<String> = tokens
        .iter()
        .map(|t| {
            let escaped = t
                .replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_");
            format!("%{escaped}%")
        })
        .collect();
    let predicates = vec!["name LIKE ? ESCAPE '\\'"; params.len().max(1)];
    let sql = if params.is_empty() {
        // An all-separator query constrains nothing; the caller should not run
        // the pass at all. Encoded as "matches nothing" rather than "matches
        // everything" so a bug here fails closed.
        "SELECT name FROM records WHERE 0".to_string()
    } else {
        format!(
            "SELECT name FROM records WHERE {} ORDER BY name",
            predicates.join(" AND ")
        )
    };
    (sql, params)
}

const CORPUS: &[&str] = &[
    "DetailRecordLayout",
    "getInboxProjection",
    "AccordionTree",
    "Refactor the detail record layout hook",
    "AI policy review",
    "Policy review board",
    "query_record pipeline engine",
    "Retag entry → 6e2c984",
    "Rollout 100% complete",
    "ÉCOLE",
];

/// (query, exactly these names, why this row exists)
const FIXTURES: &[(&str, &[&str], &str)] = &[
    (
        "detail record layout",
        &[
            "DetailRecordLayout",
            "Refactor the detail record layout hook",
        ],
        "ea7e5bd's worked example. Whole-query LIKE reaches neither camel name.",
    ),
    (
        "detail-record layout",
        &[
            "DetailRecordLayout",
            "Refactor the detail record layout hook",
        ],
        "Punctuation must tokenize like the index, not like whitespace.",
    ),
    (
        "inbox projection",
        &["getInboxProjection"],
        "The camelCase class this mechanism exists for: one unicode61 token.",
    ),
    (
        "AI policy",
        &["AI policy review"],
        "Short tokens stay constraints. Dropping 'AI' would also match 'Policy review board'.",
    ),
    (
        "query record",
        &["query_record pipeline engine"],
        "Splitting on '_' cannot lose the target: predicates are substring tests.",
    ),
    (
        "e2c98",
        &["Retag entry → 6e2c984"],
        "Inner-fragment ID recall — the marginal infix case b29a84a measured.",
    ),
    (
        "accordion",
        &["AccordionTree"],
        "Single-token query is the degenerate case of the same rule.",
    ),
    (
        "100 complete",
        &["Rollout 100% complete"],
        "'%' is a separator, so it never reaches the predicate as a wildcard.",
    ),
    (
        "éco",
        &[],
        "Unicode case folding is OUT of v1 scope: stock LIKE folds ASCII only. \
         This row is a limitation, not a goal — if it ever passes, that is a \
         deliberate contract change (see ea7e5bd's second reopening trigger).",
    ),
];

async fn corpus() -> SqlitePool {
    let db = pool().await;
    sqlx::query("CREATE TABLE records(name TEXT)")
        .execute(&db)
        .await
        .unwrap();
    for n in CORPUS {
        sqlx::query("INSERT INTO records VALUES(?)")
            .bind(*n)
            .execute(&db)
            .await
            .unwrap();
    }
    db
}

#[tokio::test]
async fn contract_fixtures_hold() {
    let db = corpus().await;
    for (query, expected, why) in FIXTURES {
        let (sql, params) = like_pass(query);
        let borrowed: Vec<&str> = params.iter().map(String::as_str).collect();
        let mut got = names(&db, &sql, &borrowed).await;
        got.sort();
        let mut want: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(got, want, "query {query:?} — {why}");
    }
}

/// The acceptance criterion of stage 5's infix obligation: the SHIPPED pass
/// (`query::fts::name_infix`, what tool 17 runs) produces exactly the fixture
/// table's answers on a real engine database. The reference implementation
/// above pins the specification; this pins the product to it.
#[tokio::test]
async fn real_infix_pass_agrees_with_the_contract_fixtures() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    for n in CORPUS {
        create_record(
            &db,
            json!({ "type": "WorkItem", "kind": "task", "name": n }),
        )
        .await
        .unwrap();
    }
    for (query, expected, why) in FIXTURES {
        let hits = fts::name_infix(&db, "test-account", query, &FtsOptions::default())
            .await
            .unwrap();
        let mut got: Vec<String> = hits.into_iter().map(|h| h.name).collect();
        got.sort();
        let mut want: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(got, want, "shipped name_infix, query {query:?} — {why}");
    }
}

// ---------------------------------------------------------------------------
// The bm25() re-tune (stage 5). The weights are settled by these rows, not by
// guessing: each pins a ranking behaviour the chosen (name, body) weights must
// produce, so a future re-weighting has to confront the behaviour it changes.
// ---------------------------------------------------------------------------

/// A name hit must outrank a body-only hit — even a body that repeats the
/// term. Repetition concentrates bm25 term frequency, so an under-weighted
/// name loses exactly this comparison; the weights ship because it passes.
#[tokio::test]
async fn bm25_weights_name_hit_outranks_body_spam() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Budget review", "body": "quarterly numbers" }),
    )
    .await
    .unwrap();
    create_record(
        &db,
        json!({
            "type": "WorkItem",
            "kind": "task",
            "name": "Meeting notes",
            "body": "budget budget budget budget budget budget budget budget"
        }),
    )
    .await
    .unwrap();
    let hits = fts::search(&db, "test-account", "budget", &FtsOptions::default())
        .await
        .unwrap();
    let names: Vec<&str> = hits.iter().map(|h| h.name.as_str()).collect();
    assert_eq!(
        names,
        vec!["Budget review", "Meeting notes"],
        "the name column must dominate ranking"
    );
}

/// Body-only matches still rank and still return — the name weighting must
/// not become name-only search.
#[tokio::test]
async fn bm25_weights_keep_body_only_matches() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Offsite planning", "body": "book the venue" }),
    )
    .await
    .unwrap();
    let hits = fts::search(&db, "test-account", "venue", &FtsOptions::default())
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].name, "Offsite planning");
    assert!(
        hits[0].snippet.contains("[venue]"),
        "body snippet marks the match: {}",
        hits[0].snippet
    );
}

/// Hidden FTS rows may affect SQLite's raw BM25/IDF, so the trusted boundary
/// must neither return nor order by that signal. Adding a Bea-only hit leaves
/// Alice's rows, snippets, count, score, and order byte-for-byte unchanged.
#[tokio::test]
async fn hidden_corpus_cannot_change_visible_ranking_or_pool_signal() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let visible = create_record(
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Visible alpha",
            "body": "exclusivealpha visible text"
        }),
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &visible,
        vec![AllowEntry::account("alice", Capability::View)],
    )
    .await
    .unwrap();
    let opts = FtsOptions::default();
    let before = fts::search(&db, "alice", "exclusivealpha", &opts)
        .await
        .unwrap();
    let count_before = fts::search_pool_count(&db, "alice", "exclusivealpha", &opts)
        .await
        .unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(count_before, 1);

    let hidden = create_record(
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Hidden alpha",
            "body": "exclusivealpha exclusivealpha exclusivealpha hidden text"
        }),
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        &hidden,
        vec![AllowEntry::account("bea", Capability::View)],
    )
    .await
    .unwrap();

    let after = fts::search(&db, "alice", "exclusivealpha", &opts)
        .await
        .unwrap();
    let count_after = fts::search_pool_count(&db, "alice", "exclusivealpha", &opts)
        .await
        .unwrap();
    assert_eq!(count_after, 1);
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].id, before[0].id);
    assert_eq!(after[0].snippet, before[0].snippet);
    assert_eq!(after[0].score.to_bits(), before[0].score.to_bits());
    let bea = fts::search(&db, "bea", "exclusivealpha", &opts)
        .await
        .unwrap();
    assert_eq!(bea.len(), 1);
    assert_eq!(bea[0].id, hidden);
}

#[tokio::test]
async fn trusted_search_authorizes_derived_artifacts_through_one_live_bearer() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    create_record(
        &db,
        json!({
            "id": "5ea4c000-0000-4000-8000-000000000001",
            "type": "Document",
            "kind": "note",
            "name": "KindlessPrefixCamelRecall",
            "body": "kindlessstrictterm"
        }),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE records SET kind = NULL WHERE id = '5ea4c000-0000-4000-8000-000000000001'")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    replace_explicit_policy(
        &db,
        "test:policy",
        "5ea4c000-0000-4000-8000-000000000001",
        vec![AllowEntry::account("alice", Capability::View)],
    )
    .await
    .unwrap();
    for (id, grants) in [
        ("5ea4c000-0000-4000-8000-000000000002", vec!["bea"]),
        ("5ea4c000-0000-4000-8000-000000000003", vec!["bea"]),
    ] {
        create_record(
            &db,
            json!({ "id": id, "type": "Document", "kind": "note", "name": id }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            grants
                .into_iter()
                .map(|account| AllowEntry::account(account, Capability::View))
                .collect(),
        )
        .await
        .unwrap();
    }

    let artifacts = [
        (
            "5ea4c000-0000-4000-8000-000000000004",
            "Annotation",
            "note",
            "Strict hidden",
            Some("artifactstrictterm"),
            "5ea4c000-0000-4000-8000-000000000001",
            "bea",
        ),
        (
            "5ea4c000-0000-4000-8000-000000000005",
            "Annotation",
            "note",
            "Strict visible",
            Some("artifactstrictterm"),
            "5ea4c000-0000-4000-8000-000000000002",
            "alice",
        ),
        (
            "5ea4c000-0000-4000-8000-000000000006",
            "Document",
            "attachment",
            "ArtifactPrefixHidden",
            None,
            "5ea4c000-0000-4000-8000-000000000001",
            "bea",
        ),
        (
            "5ea4c000-0000-4000-8000-000000000007",
            "Document",
            "attachment",
            "ArtifactPrefixVisible",
            None,
            "5ea4c000-0000-4000-8000-000000000002",
            "alice",
        ),
        (
            "5ea4c000-0000-4000-8000-000000000008",
            "Annotation",
            "note",
            "HiddenArtifactCamelRecall",
            None,
            "5ea4c000-0000-4000-8000-000000000001",
            "bea",
        ),
        (
            "5ea4c000-0000-4000-8000-000000000009",
            "Annotation",
            "note",
            "VisibleArtifactCamelRecall",
            None,
            "5ea4c000-0000-4000-8000-000000000002",
            "alice",
        ),
    ];
    for (id, record_type, kind, name, body, bearer, own_grant) in artifacts {
        create_record(
            &db,
            json!({
                "id": id,
                "type": record_type,
                "kind": kind,
                "name": name,
                "body": body
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![AllowEntry::account(own_grant, Capability::View)],
        )
        .await
        .unwrap();
        add_link(
            &db,
            LinkAddedPayload {
                id: Some(format!("part-{id}")),
                source_id: id.into(),
                target_id: bearer.into(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();
    }

    let opts = FtsOptions::default();
    let kindless_strict = fts::search(&db, "alice", "kindlessstrictterm", &opts)
        .await
        .unwrap();
    assert_eq!(kindless_strict.len(), 1);
    assert_eq!(
        kindless_strict[0].id,
        "5ea4c000-0000-4000-8000-000000000001"
    );
    let kindless_prefix = fts::name_prefix(&db, "alice", "kindlessprefix", &opts)
        .await
        .unwrap();
    assert_eq!(kindless_prefix.len(), 1);
    assert_eq!(
        kindless_prefix[0].id,
        "5ea4c000-0000-4000-8000-000000000001"
    );
    let kindless_infix = fts::name_infix(&db, "alice", "kindless camel recall", &opts)
        .await
        .unwrap();
    assert_eq!(kindless_infix.len(), 1);
    assert_eq!(kindless_infix[0].id, "5ea4c000-0000-4000-8000-000000000001");
    // Record ids must be canonical v4/v7 UUIDs, so the expected ids can no
    // longer be spelled from the visible/hidden suffix. Each credential still
    // sees exactly the one record of each family it is allowed to see.
    for (credential, strict_id, prefix_id, infix_id) in [
        (
            "alice",
            STRICT_HIDDEN_ARTIFACT,
            PREFIX_HIDDEN_ARTIFACT,
            INFIX_HIDDEN_ARTIFACT,
        ),
        (
            "bea",
            STRICT_VISIBLE_ARTIFACT,
            PREFIX_VISIBLE_ARTIFACT,
            INFIX_VISIBLE_ARTIFACT,
        ),
    ] {
        let strict = fts::search(&db, credential, "artifactstrictterm", &opts)
            .await
            .unwrap();
        assert_eq!(strict.len(), 1);
        assert_eq!(strict[0].id, strict_id);
        let prefix = fts::name_prefix(&db, credential, "artifactprefix", &opts)
            .await
            .unwrap();
        assert_eq!(prefix.len(), 1);
        assert_eq!(prefix[0].id, prefix_id);
        let infix = fts::name_infix(&db, credential, "artifact camel recall", &opts)
            .await
            .unwrap();
        assert_eq!(infix.len(), 1);
        assert_eq!(infix[0].id, infix_id);
    }

    for id in [
        "5ea4c000-0000-4000-8000-000000000010",
        "5ea4c000-0000-4000-8000-000000000011",
        "5ea4c000-0000-4000-8000-000000000012",
        "5ea4c000-0000-4000-8000-000000000013",
        "5ea4c000-0000-4000-8000-000000000014",
    ] {
        create_record(
            &db,
            json!({
                "id": id,
                "type": "Annotation",
                "kind": "note",
                "name": id,
                "body": "malformedartifactterm"
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
    }
    for (id, source, target) in [
        (
            "part-multiple-a",
            "5ea4c000-0000-4000-8000-000000000011",
            "5ea4c000-0000-4000-8000-000000000001",
        ),
        (
            "part-multiple-b",
            "5ea4c000-0000-4000-8000-000000000011",
            "5ea4c000-0000-4000-8000-000000000002",
        ),
        (
            "part-cycle-a",
            "5ea4c000-0000-4000-8000-000000000012",
            "5ea4c000-0000-4000-8000-000000000013",
        ),
        (
            "part-cycle-b",
            "5ea4c000-0000-4000-8000-000000000013",
            "5ea4c000-0000-4000-8000-000000000012",
        ),
        (
            "part-dead",
            "5ea4c000-0000-4000-8000-000000000014",
            "5ea4c000-0000-4000-8000-000000000003",
        ),
    ] {
        add_link(
            &db,
            LinkAddedPayload {
                id: Some(id.into()),
                source_id: source.into(),
                target_id: target.into(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .unwrap();
    }
    delete_record(&db, "5ea4c000-0000-4000-8000-000000000003")
        .await
        .unwrap();
    assert!(fts::search(&db, "bea", "malformedartifactterm", &opts)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn trusted_search_slices_oversized_stored_name_body_and_snippet_before_materializing() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let huge_name = format!("Oversized {}", "n".repeat(100_000));
    let huge_body = format!("boundedterm {}", "b".repeat(2_000_000));
    create_record(
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": huge_name,
            "body": huge_body
        }),
    )
    .await
    .unwrap();

    let hits = fts::search(&db, "test-account", "boundedterm", &FtsOptions::default())
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert!(hits[0].name.chars().count() <= 512);
    assert!(hits[0].snippet.chars().count() <= 2_048);
    assert!(hits[0].snippet.contains("[boundedterm]"));
}

#[tokio::test]
async fn trusted_snippet_tracks_a_match_beyond_the_bounded_rank_slice() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    create_record(
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Late match document",
            "body": format!("{} latebodymatch after", "leading filler ".repeat(400))
        }),
    )
    .await
    .unwrap();

    let hits = fts::search(&db, "test-account", "latebodymatch", &FtsOptions::default())
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert!(
        hits[0].snippet.contains("[latebodymatch]"),
        "{}",
        hits[0].snippet
    );
    assert!(hits[0].snippet.chars().count() <= 2_048);
}

#[tokio::test]
async fn trusted_snippet_uses_the_fts_stemmed_match_not_literal_prefix_search() {
    let db = native_ce::create_database(":memory:").await.unwrap();
    create_record(
        &db,
        json!({
            "type": "Document",
            "kind": "note",
            "name": "Exercise log",
            "body": "we were running quickly through the park"
        }),
    )
    .await
    .unwrap();

    let hits = fts::search(&db, "test-account", "runs", &FtsOptions::default())
        .await
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert!(hits[0].snippet.contains("[running]"), "{}", hits[0].snippet);
}

// ---------------------------------------------------------------------------
// Engine facts. Each one is a defect that reached review of `ea7e5bd`.
// ---------------------------------------------------------------------------

/// Round 1. The contract originally specified a whole-query `LIKE '%term%'`
/// pass and illustrated it with `DetailRecordLayout` — which that pass cannot
/// reach, because the stored name has no spaces.
#[tokio::test]
async fn whole_query_like_cannot_reach_camelcase() {
    let db = pool().await;
    assert!(
        !yes(
            &db,
            "SELECT 'DetailRecordLayout' LIKE '%detail record layout%'"
        )
        .await,
        "whole-query LIKE must not be presented as reaching camelCase names"
    );
    assert!(
        yes(
            &db,
            "SELECT 'DetailRecordLayout' LIKE '%detail%' \
             AND 'DetailRecordLayout' LIKE '%record%' \
             AND 'DetailRecordLayout' LIKE '%layout%'"
        )
        .await,
        "per-token AND is what reaches them"
    );
}

/// Round 2. `lower()` was described as "full case folding". SQLite's built-in
/// is ASCII-only, and `LIKE` already folds ASCII by default — so the wrapped
/// variant measured 1.8x the cost for identical results.
#[tokio::test]
async fn lower_is_ascii_only_and_like_already_folds_ascii() {
    let db = pool().await;
    assert!(
        yes(&db, "SELECT 'ABC' LIKE '%b%'").await,
        "default LIKE folds ASCII — the pass needs no lower()"
    );
    assert_eq!(
        sqlx::query("SELECT lower('É') AS name")
            .fetch_one(&db)
            .await
            .unwrap()
            .get::<String, _>("name"),
        "É",
        "lower() is ASCII-only: Unicode folding needs ICU or an app-side fold"
    );
}

/// Round 3. The fallback tokenized on whitespace while the index tokenized on
/// runs of non-alphanumerics, so the two disagreed about what a query's terms
/// were on any punctuation-bearing input.
#[tokio::test]
async fn unicode61_splits_on_non_alphanumerics() {
    let db = pool().await;
    sqlx::query("CREATE VIRTUAL TABLE t USING fts5(name, tokenize='unicode61')")
        .execute(&db)
        .await
        .unwrap();
    for n in ["detail-record layout", "query_record pipeline"] {
        sqlx::query("INSERT INTO t VALUES(?)")
            .bind(n)
            .execute(&db)
            .await
            .unwrap();
    }
    sqlx::query("CREATE VIRTUAL TABLE v USING fts5vocab(t, row)")
        .execute(&db)
        .await
        .unwrap();
    let mut terms: Vec<String> = sqlx::query("SELECT term AS name FROM v ORDER BY term")
        .fetch_all(&db)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<String, _>("name"))
        .collect();
    terms.sort();
    assert_eq!(
        terms,
        vec!["detail", "layout", "pipeline", "query", "record"],
        "the LIKE pass must split the same way, or it and the index disagree"
    );
    assert_eq!(
        tokenize("detail-record layout"),
        vec!["detail", "record", "layout"]
    );
    assert_eq!(
        tokenize("query_record pipeline"),
        vec!["query", "record", "pipeline"]
    );
}

/// Round 3, second half. Under the specified tokenization no token can carry a
/// `LIKE` wildcard, which is why the `ESCAPE` clause is a safety net rather
/// than a live path. Asserted so a tokenizer change has to confront it.
#[tokio::test]
async fn tokenization_cannot_emit_like_wildcards() {
    for q in ["100% complete", "a_b", "50%_off", "%%%"] {
        for token in tokenize(q) {
            assert!(
                !token.contains('%') && !token.contains('_'),
                "token {token:?} from {q:?} carries a LIKE wildcard"
            );
        }
    }
}

/// Round 4. The contract claimed trigram and `LIKE` have identical substring
/// semantics. The equivalence holds only for ASCII terms of three characters
/// or more, and it breaks in BOTH directions outside that band.
#[tokio::test]
async fn trigram_and_like_diverge_outside_ascii_trigrams() {
    let db = pool().await;
    sqlx::query("CREATE VIRTUAL TABLE g USING fts5(name, tokenize='trigram')")
        .execute(&db)
        .await
        .unwrap();
    for n in ["RecordAI", "ÉCOLE"] {
        sqlx::query("INSERT INTO g VALUES(?)")
            .bind(n)
            .execute(&db)
            .await
            .unwrap();
    }

    // Inside the band: identical.
    assert_eq!(
        names(&db, "SELECT name FROM g WHERE name MATCH ?", &["rec"]).await,
        vec!["RecordAI"]
    );
    assert_eq!(
        names(&db, "SELECT name FROM g WHERE name LIKE ?", &["%rec%"]).await,
        vec!["RecordAI"]
    );

    // Below three characters, LIKE is strictly stronger — trigram cannot match
    // a term shorter than a trigram. This is why the pass keeps short tokens.
    assert!(
        names(&db, "SELECT name FROM g WHERE name MATCH ?", &["ai"])
            .await
            .is_empty(),
        "trigram cannot match a sub-trigram term"
    );
    assert_eq!(
        names(&db, "SELECT name FROM g WHERE name LIKE ?", &["%ai%"]).await,
        vec!["RecordAI"]
    );

    // On non-ASCII case, trigram is stronger — its default case_sensitive=0
    // folds Unicode case, stock LIKE does not. Real recall v1 gives up; the
    // second reopening trigger in ea7e5bd.
    assert_eq!(
        names(&db, "SELECT name FROM g WHERE name MATCH ?", &["éco"]).await,
        vec!["ÉCOLE"],
        "trigram folds Unicode case"
    );
    assert!(
        names(&db, "SELECT name FROM g WHERE name LIKE ?", &["%éco%"])
            .await
            .is_empty(),
        "stock LIKE does not — do not claim parity outside ASCII"
    );
}

/// Round 1's other half, kept because it is the load-bearing latency claim:
/// token count is not a multiplier, since `AND` short-circuits per row. Asserted
/// as a behavioural equivalence rather than a timing, so it cannot flake in CI —
/// the timings themselves live in `b29a84a`.
#[tokio::test]
async fn added_tokens_only_narrow() {
    let db = corpus().await;
    let (one_sql, one_params) = like_pass("detail");
    let (three_sql, three_params) = like_pass("detail record layout");
    let one = names(
        &db,
        &one_sql,
        &one_params.iter().map(String::as_str).collect::<Vec<_>>(),
    )
    .await;
    let three = names(
        &db,
        &three_sql,
        &three_params.iter().map(String::as_str).collect::<Vec<_>>(),
    )
    .await;
    assert!(
        three.iter().all(|n| one.contains(n)),
        "AND-composition can only narrow: {three:?} must be a subset of {one:?}"
    );
}
