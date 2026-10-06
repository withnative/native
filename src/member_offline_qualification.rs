//! Independent qualification differentials (Q1, Native task c25df88).
//!
//! Each test compares the fixture world's E(m) ([`online_visible_ids`],
//! the engine's online evaluator) against what an online member-scoped
//! read path actually returns for m. A disagreement is a FINDING: it is
//! recorded in the test message and the Q1 report, never fixed here.
//! Worlds come from [`crate::member_offline_fixtures`] READ-ONLY.
//!
//! Contract: Native record c323277 rev 7, §0 (E(m)), §2.3(a) parity rows,
//! §2.4 audit, §3.3 closure rules, §7.2 fixtures 1–4, 6, 8 (online side).
//!
//! Oracle strength (round-2 review F4). `online_visible_ids` reads
//! `temp._query_sql_visible_records`, the same private visibility view
//! that backs governed `query_sql` (`src/query/sql.rs:123-125,208-213`).
//! Equalities between a governed view and E(m) (records view, links view)
//! are therefore CIRCULAR for leaks inside that shared view: they catch
//! principal/plumbing regressions, not evaluator leaks. The load-bearing
//! assertions are the explicit hidden-membership pins and the paths with
//! an INDEPENDENT evaluator — `effective_capability` (`get_as`),
//! `visible_ids_in_pool` (tool-path filter, `descendants_as`), and the
//! FTS `view_predicate` (`search`).

use std::collections::HashSet;

use serde_json::{json, Value};

use crate::authorization::Principal;
use crate::member_offline_fixtures::{
    assert_no_counter_fields, online_visible_ids, two_caller, ACCT_A, ACCT_B,
};
use crate::query::lens::ReadLens;
use crate::query::{read, QueryPrincipal};

/// Ids from a `SELECT id ...` governed-view result.
fn ids_of(rows: &[Value]) -> HashSet<String> {
    rows.iter()
        .filter_map(|row| row.get("id")?.as_str().map(str::to_string))
        .collect()
}

async fn records_view(db: &crate::db::Db, account: &str) -> Vec<Value> {
    crate::query::sql::query_sql(
        db,
        QueryPrincipal::authenticated(account, true),
        "SELECT id FROM records",
    )
    .await
    .unwrap()
    .rows
}

async fn get_as(db: &crate::db::Db, account: &str, id: &str) -> Option<read::EnrichedRecord> {
    read::get_record_with_lens_as(
        &ReadLens::live(db),
        id,
        read::EnrichOptions::default(),
        Principal::bound(account, true),
    )
    .await
    .unwrap()
}

/// The online-as-m answer: the real `get_record` tool path with a member
/// caller (live lens read + `filter_enriched_record` viewer fold + `rec:`
/// version stamp). Raw `get_record_with_lens_as` checks target
/// readability but leaves counts, successor names and path flags
/// unfiltered (`src/query/read.rs` docs on `load_superseded_by`), so it
/// is the wrong oracle for derived state.
async fn get_record_tool(db: &crate::db::Db, account: &str, ids: &[&str]) -> Value {
    crate::mcp::tools::lifecycle::get_record(
        db.clone(),
        crate::mcp::Caller::authenticated(account),
        json!({"ids": ids}),
    )
    .await
    .unwrap()
}

/// The `found` item for `id` in a `get_record` tool response.
fn found_item<'v>(response: &'v Value, id: &str) -> Option<&'v Value> {
    response.get("records")?.as_array()?.iter().find(|item| {
        item.get("id").and_then(Value::as_str) == Some(id)
            && item.get("status").and_then(Value::as_str) == Some("found")
    })
}

/// Group 1 — owner floor + bearer changes (matrix rows A, B; §7.2.3).
///
/// Owner floor: A_OWNED has no grants and `owner_id = PERSON_A`; only A
/// may see it (§3.2 records row, owner floor + bearer minimum).
#[tokio::test]
async fn owner_floor_records_view_matches_e_of_m() {
    let world = two_caller::build().await;
    let ea = online_visible_ids(&world.db, ACCT_A).await;
    let eb = online_visible_ids(&world.db, ACCT_B).await;
    assert!(ea.contains(two_caller::A_OWNED));
    assert!(!eb.contains(two_caller::A_OWNED));
    let rows_a = ids_of(&records_view(&world.db, ACCT_A).await);
    let rows_b = ids_of(&records_view(&world.db, ACCT_B).await);
    assert!(rows_a.contains(two_caller::A_OWNED));
    assert!(
        !rows_b.contains(two_caller::A_OWNED),
        "FINDING: owner-floor record visible to B in records view"
    );
    assert_eq!(rows_a, ea, "records view as A must equal E(A)");
    assert_eq!(rows_b, eb, "records view as B must equal E(B)");
}
#[tokio::test]
async fn bearer_restricted_attachment_matches_e_of_m() {
    let world = two_caller::build().await;
    let ea = online_visible_ids(&world.db, ACCT_A).await;
    let eb = online_visible_ids(&world.db, ACCT_B).await;
    for id in [two_caller::BEARER_A, two_caller::ATT_A] {
        assert!(ea.contains(id), "E(A) must contain bearer-side {id}");
        assert!(!eb.contains(id), "E(B) must exclude bearer-side {id}");
    }
    // Single-record path: hidden bearer/attachment is absent for B.
    assert!(get_as(&world.db, ACCT_A, two_caller::ATT_A).await.is_some());
    assert!(
        get_as(&world.db, ACCT_B, two_caller::ATT_A).await.is_none(),
        "FINDING: restricted-bearer attachment resolves for B"
    );
    assert!(
        get_as(&world.db, ACCT_B, two_caller::BEARER_A)
            .await
            .is_none(),
        "FINDING: restricted bearer resolves for B"
    );
    // Blob rows follow the bearer: B sees the both-visible external blob
    // but must not reach the A-only inline blob.
    async fn blob_ids(db: &crate::db::Db, account: &str) -> HashSet<String> {
        ids_of(
            &crate::query::sql::query_sql(
                db,
                QueryPrincipal::authenticated(account, true),
                "SELECT id FROM blobs",
            )
            .await
            .unwrap()
            .rows,
        )
    }
    let blobs_a = blob_ids(&world.db, ACCT_A).await;
    let blobs_b = blob_ids(&world.db, ACCT_B).await;
    assert!(blobs_b.contains(two_caller::EXT_BLOB));
    assert!(blobs_b.is_subset(&blobs_a));
    assert_eq!(
        blobs_a.len(),
        blobs_b.len() + 1,
        "FINDING: blob reachability does not follow the bearer: A={blobs_a:?} B={blobs_b:?}"
    );
}
/// Group 2 — hidden parents, links, mentions (matrix row C; §7.2.3).
///
/// §3.3 rule 1: the child stays, `home_id` NULLs, no ancestor leaks.
/// §3.3 rule 2: a link ships only when both endpoints are eligible.
#[tokio::test]
async fn hidden_parent_child_link_endpoints_match_e_of_m() {
    use crate::query::tree::{descendants_as, TreeOptions};
    use crate::schema::ROOT_RECORD_ID;

    let world = two_caller::build().await;
    let eb = online_visible_ids(&world.db, ACCT_B).await;
    assert!(eb.contains(two_caller::VISIBLE_CHILD));
    assert!(!eb.contains(two_caller::HIDDEN_PARENT));

    // Containment walk as B: every listed node must be in E(B).
    let nodes = descendants_as(
        &world.db,
        ROOT_RECORD_ID,
        TreeOptions::default(),
        Principal::bound(ACCT_B, true),
    )
    .await
    .unwrap();
    let walked: HashSet<String> = nodes.iter().map(|node| node.id.clone()).collect();
    for id in &walked {
        assert!(
            eb.contains(id),
            "FINDING: containment walk lists {id} outside E(B)"
        );
    }
    // The visible child of the hidden parent keeps a false path flag
    // on the member-facing path (raw reads leave it unfiltered).
    let child_response = get_record_tool(&world.db, ACCT_B, &[two_caller::VISIBLE_CHILD]).await;
    let child = found_item(&child_response, two_caller::VISIBLE_CHILD)
        .expect("VISIBLE_CHILD must resolve for B");
    assert_eq!(
        child.get("containment_path_visible"),
        Some(&Value::Bool(false)),
        "FINDING: hidden-parent child reports a visible path for B"
    );

    // Links view as B: both endpoints of every row must be in E(B).
    let link_rows = crate::query::sql::query_sql(
        &world.db,
        QueryPrincipal::authenticated(ACCT_B, true),
        "SELECT source_id, target_id FROM links",
    )
    .await
    .unwrap()
    .rows;
    for row in &link_rows {
        let source = row.get("source_id").and_then(Value::as_str).unwrap_or("?");
        let target = row.get("target_id").and_then(Value::as_str).unwrap_or("?");
        assert!(
            eb.contains(source) && eb.contains(target),
            "FINDING: link row {source}->{target} touches outside E(B)"
        );
    }
    // The visible->hidden link exists online but must not appear for B.
    assert!(
        !link_rows.iter().any(|row| row
            .get("source_id")
            .and_then(Value::as_str)
            .is_some_and(|source| source == two_caller::SHARED_CHILD)
            && row
                .get("target_id")
                .and_then(Value::as_str)
                .is_some_and(|target| target == two_caller::HIDDEN_PARENT)),
        "FINDING: visible->hidden link listed for B"
    );
}
/// Group 3 — caller bindings and addressed identity (matrix row D).
///
/// §3.2 caller-bound: the bindings view shows only the caller's own
/// account/email bindings; a message addressed only to A is absent for B.
#[tokio::test]
async fn caller_bindings_view_is_caller_only() {
    let world = two_caller::build().await;
    for (account, other) in [(ACCT_A, ACCT_B), (ACCT_B, ACCT_A)] {
        let rows = crate::query::sql::query_sql(
            &world.db,
            QueryPrincipal::authenticated(account, true),
            "SELECT identifier FROM bindings",
        )
        .await
        .unwrap()
        .rows;
        assert!(!rows.is_empty(), "caller {account} must see own bindings");
        for row in &rows {
            let identifier = row.get("identifier").and_then(Value::as_str).unwrap_or("?");
            assert_eq!(
                identifier, account,
                "FINDING: {account} sees binding for {identifier}"
            );
            assert_ne!(identifier, other);
        }
    }
}

#[tokio::test]
async fn message_addressed_to_a_is_absent_for_b() {
    let world = two_caller::build().await;
    let ea = online_visible_ids(&world.db, ACCT_A).await;
    let eb = online_visible_ids(&world.db, ACCT_B).await;
    assert!(ea.contains(two_caller::MSG_A));
    assert!(!eb.contains(two_caller::MSG_A));
    assert!(get_as(&world.db, ACCT_A, two_caller::MSG_A).await.is_some());
    assert!(
        get_as(&world.db, ACCT_B, two_caller::MSG_A).await.is_none(),
        "FINDING: A-addressed message resolves for B"
    );
    // Instruction stacks are caller-derived: every record-sourced entry
    // must name a record inside the caller's own E(m).
    for account in [ACCT_A, ACCT_B] {
        let resolution = crate::instructions::resolve_for_account(
            world.db.write_pool(),
            account,
            true,
            false,
            None,
        )
        .await
        .unwrap();
        let visible = online_visible_ids(&world.db, account).await;
        for entry in &resolution.instructions.entries {
            if let crate::instructions::InstructionSource::Record { record_id, .. } = &entry.source
            {
                assert!(
                    visible.contains(record_id),
                    "FINDING: {account} instruction entry sources hidden {record_id}"
                );
            }
        }
    }
}
/// Group 4 — counts and derived state (matrix row E; §2.4 items 1–7).
///
/// R1 carve-out (§2.4 item 1): online `superseded_by.total_count` still
/// counts invisible successors pending product fix e5f171c; the member
/// copy must count visible successors only. This test pins the online
/// side of that divergence so the producer strip has a fixed target.
#[tokio::test]
async fn superseded_by_carve_out_is_pinned_online() {
    let world = two_caller::build().await;
    let eb = online_visible_ids(&world.db, ACCT_B).await;
    assert!(!eb.contains(two_caller::NEWER_HIDDEN));
    let response = get_record_tool(&world.db, ACCT_B, &[two_caller::OLD_RECORD]).await;
    let old_b =
        found_item(&response, two_caller::OLD_RECORD).expect("OLD_RECORD must resolve for B");
    let superseded = old_b
        .get("superseded_by")
        .expect("OLD_RECORD must carry superseded_by for B");
    assert_eq!(
        superseded.get("items"),
        Some(&Value::Array(Vec::new())),
        "FINDING: invisible successor named in items for B"
    );
    assert_eq!(
        superseded.get("total_count"),
        Some(&json!(1)),
        "online carve-out: invisible successor counted for B (e5f171c pending)"
    );
    // links_in carries the visible bearer edge (EXT_ATTACH part_of) but
    // must not name the hidden successor: every source stays in E(B).
    let links_in = old_b
        .get("links_in")
        .and_then(Value::as_array)
        .expect("OLD_RECORD must carry links_in for B");
    for link in links_in {
        let source = link.get("source_id").and_then(Value::as_str).unwrap_or("?");
        assert!(
            eb.contains(source),
            "FINDING: links_in names {source} outside E(B)"
        );
        assert_ne!(
            source,
            two_caller::NEWER_HIDDEN,
            "FINDING: links_in names the hidden successor for B"
        );
    }
    assert_eq!(
        old_b.get("links_in_count"),
        Some(&json!(links_in.len())),
        "FINDING: links_in_count disagrees with the visible links_in window for B"
    );
}

#[tokio::test]
async fn child_counts_and_search_are_post_visibility() {
    use crate::query::fts::{search, FtsOptions};

    let world = two_caller::build().await;
    // SHARED has two raw children (SHARED_CHILD, A_OWNED); B sees one.
    let response_a = get_record_tool(&world.db, ACCT_A, &[two_caller::SHARED]).await;
    let response_b = get_record_tool(&world.db, ACCT_B, &[two_caller::SHARED]).await;
    let shared_a = found_item(&response_a, two_caller::SHARED).expect("SHARED must resolve for A");
    let shared_b = found_item(&response_b, two_caller::SHARED).expect("SHARED must resolve for B");
    assert_eq!(shared_a.get("child_count"), Some(&json!(2)));
    assert_eq!(
        shared_b.get("child_count"),
        Some(&json!(1)),
        "FINDING: child_count for B includes the hidden owner-floor child"
    );
    // Search hits as m must be a subset of E(m) — never a hidden record.
    for (account, probe) in [(ACCT_A, "b-only"), (ACCT_B, "b-only")] {
        let hits = search(&world.db, account, true, probe, &FtsOptions::default())
            .await
            .unwrap();
        let visible = online_visible_ids(&world.db, account).await;
        for hit in &hits {
            assert!(
                visible.contains(&hit.id),
                "FINDING: search as {account} hit {0} outside E(m)",
                hit.id
            );
        }
        let found = hits.iter().any(|hit| hit.id == two_caller::B_ONLY);
        assert_eq!(
            found,
            account == ACCT_B,
            "B_ONLY search visibility must follow E(m), got {found} for {account}"
        );
    }
}
/// Group 5 — folders and collections, online side (matrix §7.2.6).
///
/// Folder listing/counts cover visible children only; the scoped-schema
/// gate inputs are pinned so the producer withhold has a fixed target:
// GATED_COLL_SCHEMA embeds a hidden id (must be withheld + refusal
/// scoped to SHARED), HIDDEN_COLL_SCHEMA lives on a hidden collection.
#[tokio::test]
async fn folder_and_scoped_schema_views_match_e_of_m() {
    use crate::query::tree::{descendants_as, TreeOptions};

    let world = two_caller::build().await;
    let eb = online_visible_ids(&world.db, ACCT_B).await;

    // Visible folder SHARED: B walks one visible child, never the hidden.
    let nodes = descendants_as(
        &world.db,
        two_caller::SHARED,
        TreeOptions::default(),
        Principal::bound(ACCT_B, true),
    )
    .await
    .unwrap();
    let walked: HashSet<String> = nodes.iter().map(|node| node.id.clone()).collect();
    assert!(walked.contains(two_caller::SHARED_CHILD));
    assert!(
        !walked.contains(two_caller::A_OWNED),
        "FINDING: folder walk lists hidden child for B"
    );
    for id in &walked {
        assert!(
            eb.contains(id),
            "FINDING: folder walk lists {id} outside E(B)"
        );
    }

    // Scoped schema rows: hidden-collection row excluded for B; the
    // gate-failing row on the visible collection still ships online
    // (withholding is the producer's job, §3.3 rule 6).
    async fn schema_ids(db: &crate::db::Db, account: &str) -> HashSet<String> {
        ids_of(
            &crate::query::sql::query_sql(
                db,
                QueryPrincipal::authenticated(account, true),
                "SELECT id FROM schema_config",
            )
            .await
            .unwrap()
            .rows,
        )
    }
    let schema_a = schema_ids(&world.db, ACCT_A).await;
    let schema_b = schema_ids(&world.db, ACCT_B).await;
    assert!(schema_a.contains(two_caller::HIDDEN_COLL_SCHEMA));
    assert!(
        !schema_b.contains(two_caller::HIDDEN_COLL_SCHEMA),
        "FINDING: hidden-collection schema row visible to B"
    );
    assert!(
        schema_b.contains(two_caller::GATED_COLL_SCHEMA),
        "online gate input: gated row ships online, producer must withhold it"
    );
}

/// Group 7 (round 2, F1) — instruction bindings with hidden sources.
///
/// `two_caller` seeds no instruction bindings, so the round-1 stack loop
/// was dead. This setup adds, on top of the read-only world: a
/// DATABASE-scope binding whose source only A can read, and an
/// account-scope (private) binding for A. §2.4 item 13 requires the
/// hidden-sourced entry to never reach B.
const GUIDE_DB: &str = "f2000000-0000-4000-8000-000000000001";
const GUIDE_DB_BODY: &str = "hidden database guide body";
const GUIDE_ACCT: &str = "f2000000-0000-4000-8000-000000000002";
const GUIDE_ACCT_BODY: &str = "a private member guide body";

async fn instruction_world() -> crate::db::Db {
    use crate::authorization::{AllowEntry, Capability};
    use crate::member_offline_fixtures::{grant, mk_doc};
    use crate::schema::ROOT_RECORD_ID;

    let world = two_caller::build().await;
    mk_doc(
        &world.db,
        GUIDE_DB,
        ROOT_RECORD_ID,
        Some(GUIDE_DB_BODY),
        None,
    )
    .await;
    grant(
        &world.db,
        GUIDE_DB,
        vec![AllowEntry::account(ACCT_A, Capability::View)],
    )
    .await;
    mk_doc(
        &world.db,
        GUIDE_ACCT,
        ROOT_RECORD_ID,
        Some(GUIDE_ACCT_BODY),
        None,
    )
    .await;
    grant(
        &world.db,
        GUIDE_ACCT,
        vec![AllowEntry::account(ACCT_A, Capability::View)],
    )
    .await;
    for (id, scope_kind, scope_id, source) in [
        ("q1-db-binding", "database", "native:database", GUIDE_DB),
        ("q1-acct-binding", "account", ACCT_A, GUIDE_ACCT),
    ] {
        sqlx::query(
            "INSERT INTO instruction_bindings
               (id, scope_kind, scope_id, source_record_id, position,
                enabled, created_by, created_at, updated_at)
             VALUES (?, ?, ?, ?, 100, 1, 'q1-qualifier',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(id)
        .bind(scope_kind)
        .bind(scope_id)
        .bind(source)
        .execute(world.db.write_pool())
        .await
        .unwrap();
    }
    world.db
}

fn guide_digest(body: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(body.as_bytes()))
}

#[tokio::test]
async fn instruction_sources_hidden_from_b_never_resolve_for_b() {
    let db = instruction_world().await;
    // Positive controls: A's stack is ready and names both sources.
    let a = crate::instructions::resolve_for_account(db.write_pool(), ACCT_A, true, true, None)
        .await
        .unwrap();
    assert_eq!(a.instructions.status, "ready");
    let a_text = serde_json::to_string(&a).unwrap();
    for id in [GUIDE_DB, GUIDE_ACCT] {
        assert!(a_text.contains(id), "control: A must resolve {id}");
    }
    // B's stack must yield no hidden id, title (= id), body or digest.
    let b = crate::instructions::resolve_for_account(db.write_pool(), ACCT_B, true, false, None)
        .await
        .unwrap();
    let b_text = serde_json::to_string(&b).unwrap();
    for secret in [
        GUIDE_DB,
        GUIDE_ACCT,
        GUIDE_DB_BODY,
        GUIDE_ACCT_BODY,
        &guide_digest(GUIDE_DB_BODY),
        &guide_digest(GUIDE_ACCT_BODY),
    ] {
        assert!(
            !b_text.contains(secret),
            "FINDING: B's instruction stack discloses {secret}"
        );
    }
}

#[tokio::test]
async fn instruction_tool_path_hides_hidden_sources_from_b() {
    use crate::mcp::tools::register_surface_tools;
    use crate::mcp::ToolRegistry;

    let db = instruction_world().await;
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    for (account, expect) in [(ACCT_A, true), (ACCT_B, false)] {
        // Model hosted footing so the owner flag matches the product's
        // `require_owner` signal: A is the database owner, B is a member.
        let caller = crate::mcp::Caller::authenticated(account)
            .with_hosting_context("host:db", "db:test")
            .with_hosting_owner(expect)
            .with_hosting_member(true);
        let bootstrap = registry
            .call(db.clone(), caller.clone(), "bootstrap", json!({}))
            .await
            .unwrap();
        let run_key = bootstrap["run"]["run_key"].as_str().unwrap().to_string();
        let resolved = registry
            .call(
                db.clone(),
                caller.clone(),
                "manage_instructions",
                json!({"action": "resolve", "run_key": run_key}),
            )
            .await
            .unwrap();
        let text = serde_json::to_string(&resolved).unwrap();
        for secret in [GUIDE_DB, GUIDE_DB_BODY, &guide_digest(GUIDE_DB_BODY)] {
            assert_eq!(
                text.contains(secret),
                expect,
                "{account} resolve tool path disclosure of {secret}"
            );
        }
        // Item 3: the member-facing listing must not expose a database-scope
        // binding id or source the caller cannot View.
        let listed = registry
            .call(
                db.clone(),
                caller,
                "manage_instructions",
                json!({"action": "list"}),
            )
            .await
            .unwrap();
        let listed_text = serde_json::to_string(&listed).unwrap();
        for secret in ["q1-db-binding", GUIDE_DB] {
            assert_eq!(
                listed_text.contains(secret),
                expect,
                "{account} list tool path disclosure of {secret}"
            );
        }
    }
}

/// Oracle closure (product fix 0b7d366): with the hidden-sourced
/// database binding active, B's stack is `ready` and byte-identical to
/// the world where that binding does not exist. A hidden database
/// binding is therefore no longer distinguishable from no binding
/// (`src/instructions.rs:490-500`).
#[tokio::test]
async fn hidden_binding_oracle_closed_for_members() {
    let db = instruction_world().await;
    let with_binding =
        crate::instructions::resolve_for_account(db.write_pool(), ACCT_B, true, false, None)
            .await
            .unwrap();
    assert_eq!(with_binding.instructions.status, "ready");
    assert!(with_binding.instructions.entries.is_empty());
    assert!(with_binding.instructions.diagnostics.is_empty());
    sqlx::query("UPDATE instruction_bindings SET enabled = 0 WHERE id = 'q1-db-binding'")
        .execute(db.write_pool())
        .await
        .unwrap();
    let without_binding =
        crate::instructions::resolve_for_account(db.write_pool(), ACCT_B, true, false, None)
            .await
            .unwrap();
    assert_eq!(without_binding.instructions.status, "ready");
    assert_eq!(
        serde_json::to_value(&with_binding).unwrap(),
        serde_json::to_value(&without_binding).unwrap(),
        "hidden database binding must be byte-identical to the no-binding world"
    );
}

/// Round 2 item 2: for a member, a deleted workspace source is skipped
/// exactly like a hidden one and like an absent binding — all three
/// resolutions are byte-identical. The owner keeps the fail-closed
/// `instruction_source_invalid` diagnostic for the deleted source.
#[tokio::test]
async fn deleted_workspace_source_is_skipped_like_hidden_for_members() {
    let db = instruction_world().await;
    let hidden =
        crate::instructions::resolve_for_account(db.write_pool(), ACCT_B, true, false, None)
            .await
            .unwrap();
    assert_eq!(hidden.instructions.status, "ready");
    assert!(hidden.instructions.entries.is_empty());

    sqlx::query("UPDATE records SET deleted_at='2026-02-01T00:00:00Z' WHERE id=?")
        .bind(GUIDE_DB)
        .execute(db.write_pool())
        .await
        .unwrap();
    let deleted =
        crate::instructions::resolve_for_account(db.write_pool(), ACCT_B, true, false, None)
            .await
            .unwrap();
    assert_eq!(deleted.instructions.status, "ready");
    assert_eq!(
        serde_json::to_value(&hidden).unwrap(),
        serde_json::to_value(&deleted).unwrap(),
        "deleted workspace source must be byte-identical to hidden for a member"
    );

    sqlx::query("UPDATE instruction_bindings SET enabled = 0 WHERE id = 'q1-db-binding'")
        .execute(db.write_pool())
        .await
        .unwrap();
    let absent =
        crate::instructions::resolve_for_account(db.write_pool(), ACCT_B, true, false, None)
            .await
            .unwrap();
    assert_eq!(
        serde_json::to_value(&hidden).unwrap(),
        serde_json::to_value(&absent).unwrap(),
        "absent binding must be byte-identical to hidden for a member"
    );

    // Re-enable the binding so the owner must face the deleted source.
    sqlx::query("UPDATE instruction_bindings SET enabled = 1 WHERE id = 'q1-db-binding'")
        .execute(db.write_pool())
        .await
        .unwrap();
    let owner = crate::instructions::resolve_for_account(db.write_pool(), ACCT_A, true, true, None)
        .await
        .unwrap();
    assert_eq!(owner.instructions.status, "invalid");
    assert_eq!(
        owner.instructions.diagnostics[0].code,
        "instruction_source_invalid"
    );
}

/// Round 3 F2: the entry-count ceiling must be applied after the non-owner
/// layer-0 skip. A member with visible rows at exactly the limit plus one
/// hidden layer-0 binding is byte-identical to the same world without that
/// binding (still `ready`); the owner, who can view the extra row, still
/// sees `instruction_entry_count_exceeded`.
#[tokio::test]
async fn hidden_workspace_binding_does_not_count_against_a_members_entry_ceiling() {
    use crate::authorization::{AllowEntry, Capability};
    use crate::member_offline_fixtures::{grant, mk_doc};
    use crate::schema::ROOT_RECORD_ID;

    let world = two_caller::build().await;
    let limit = crate::instructions::MAX_BOOTSTRAP_INSTRUCTION_ENTRIES;

    let mut visible = Vec::with_capacity(limit);
    for position in 0..limit {
        let id = uuid::Uuid::new_v4().to_string();
        // Empty bodies keep the entry *metadata* budget out of the way so the
        // row-count ceiling is the bound under test; the rows are still
        // counted towards it.
        mk_doc(&world.db, &id, ROOT_RECORD_ID, None, None).await;
        sqlx::query(
            "INSERT INTO instruction_bindings
               (id, scope_kind, scope_id, source_record_id, position,
                enabled, created_by, created_at, updated_at)
             VALUES (?, 'database', 'native:database', ?, ?, 1, 'test',
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(format!("visible-ceiling-binding-{position}"))
        .bind(&id)
        .bind(position as i64)
        .execute(world.db.write_pool())
        .await
        .unwrap();
        visible.push(id);
    }

    // One extra layer-0 binding whose source only A can read.
    let hidden_id = uuid::Uuid::new_v4().to_string();
    mk_doc(&world.db, &hidden_id, ROOT_RECORD_ID, Some("hidden"), None).await;
    grant(
        &world.db,
        &hidden_id,
        vec![AllowEntry::account(ACCT_A, Capability::View)],
    )
    .await;
    sqlx::query(
        "INSERT INTO instruction_bindings
           (id, scope_kind, scope_id, source_record_id, position,
            enabled, created_by, created_at, updated_at)
         VALUES ('hidden-ceiling-binding', 'database', 'native:database', ?, ?, 1, 'test',
                 '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
    )
    .bind(&hidden_id)
    .bind(limit as i64)
    .execute(world.db.write_pool())
    .await
    .unwrap();

    let member_with =
        crate::instructions::resolve_for_account(world.db.write_pool(), ACCT_B, true, false, None)
            .await
            .unwrap();
    assert_eq!(
        member_with.instructions.status, "ready",
        "{:?}",
        member_with.instructions.diagnostics
    );
    assert!(member_with.instructions.entries.is_empty());

    sqlx::query("UPDATE instruction_bindings SET enabled = 0 WHERE id = 'hidden-ceiling-binding'")
        .execute(world.db.write_pool())
        .await
        .unwrap();
    let member_without =
        crate::instructions::resolve_for_account(world.db.write_pool(), ACCT_B, true, false, None)
            .await
            .unwrap();
    assert_eq!(member_without.instructions.status, "ready");
    assert_eq!(
        serde_json::to_value(&member_with).unwrap(),
        serde_json::to_value(&member_without).unwrap(),
        "hidden layer-0 binding must not count against a member's entry ceiling"
    );

    sqlx::query("UPDATE instruction_bindings SET enabled = 1 WHERE id = 'hidden-ceiling-binding'")
        .execute(world.db.write_pool())
        .await
        .unwrap();
    let owner =
        crate::instructions::resolve_for_account(world.db.write_pool(), ACCT_A, true, true, None)
            .await
            .unwrap();
    assert_eq!(owner.instructions.status, "invalid");
    assert_eq!(
        owner.instructions.diagnostics[0].code,
        "instruction_entry_count_exceeded"
    );
}
/// Group 8 (round 2, F3) — mention resolution follows E(m) (§3.3 rule 4).
///
/// SHARED_CHILD's body cites HIDDEN_MENTIONED in full (url form), which
/// ships verbatim as authored text. Resolution is recomputed over the
/// slice: A resolves it, B must see `unresolved` — never the hidden id.
#[tokio::test]
async fn mention_of_hidden_record_resolves_only_for_a() {
    let world = two_caller::build().await;
    let response_b = get_record_tool(&world.db, ACCT_B, &[two_caller::SHARED_CHILD]).await;
    let child_b =
        found_item(&response_b, two_caller::SHARED_CHILD).expect("SHARED_CHILD must resolve for B");
    let mentions_b = child_b
        .get("mentions_out")
        .and_then(Value::as_array)
        .expect("SHARED_CHILD must carry mentions_out for B");
    assert!(
        !mentions_b.is_empty(),
        "control: SHARED_CHILD body must carry a mention group"
    );
    for group in mentions_b {
        let state = group
            .get("resolution")
            .and_then(|resolution| resolution.get("state"))
            .and_then(Value::as_str)
            .unwrap_or("?");
        let id = group
            .get("resolution")
            .and_then(|resolution| resolution.get("id"))
            .and_then(Value::as_str);
        assert_ne!(
            id,
            Some(two_caller::HIDDEN_MENTIONED),
            "FINDING: hidden mention target resolved for B"
        );
        assert_eq!(
            state, "unresolved",
            "FINDING: hidden mention not unresolved for B: {state}"
        );
    }
    let response_a = get_record_tool(&world.db, ACCT_A, &[two_caller::SHARED_CHILD]).await;
    let child_a =
        found_item(&response_a, two_caller::SHARED_CHILD).expect("SHARED_CHILD must resolve for A");
    let mentions_a = child_a
        .get("mentions_out")
        .and_then(Value::as_array)
        .expect("SHARED_CHILD must carry mentions_out for A");
    assert!(
        mentions_a.iter().any(|group| group
            .get("resolution")
            .and_then(|resolution| resolution.get("id"))
            .and_then(Value::as_str)
            == Some(two_caller::HIDDEN_MENTIONED)),
        "control: A must resolve the HIDDEN_MENTIONED citation"
    );
}
/// Group 9 (round 2, F3) — selection and query collections, online half.
///
/// Selections resolve through incoming `member_of` links as the caller;
/// query collections run the saved definition as the caller. Both must
/// list only E(m) members. The `as_of` saved query is answered-or-errored
/// online (never silently partial); refusing it is offline-only work
/// (consumer da0a471), recorded in the matrix gap column.
const SEL: &str = "f2000000-0000-4000-8000-000000000011";
const H_SEL: &str = "f2000000-0000-4000-8000-000000000012";
const V_SEL: &str = "f2000000-0000-4000-8000-000000000013";
const QCOLL: &str = "f2000000-0000-4000-8000-000000000014";
const QASOF: &str = "f2000000-0000-4000-8000-000000000015";

async fn collection_world() -> crate::db::Db {
    use crate::authorization::{AllowEntry, Capability};
    use crate::events::FacetSetPayload;
    use crate::member_offline_fixtures::{grant, link, mk_doc};
    use crate::schema::ROOT_RECORD_ID;
    use crate::store::{create_record, set_facet};

    let world = two_caller::build().await;
    for (id, kind) in [(SEL, "selection"), (QCOLL, "query"), (QASOF, "query")] {
        create_record(
            &world.db,
            json!({"id": id, "type": "Collection", "kind": kind,
                   "name": id, "home_id": ROOT_RECORD_ID}),
        )
        .await
        .unwrap();
        grant(&world.db, id, vec![AllowEntry::members(Capability::View)]).await;
    }
    mk_doc(
        &world.db,
        H_SEL,
        ROOT_RECORD_ID,
        Some("hidden selection member"),
        None,
    )
    .await;
    grant(
        &world.db,
        H_SEL,
        vec![AllowEntry::account(ACCT_A, Capability::View)],
    )
    .await;
    mk_doc(
        &world.db,
        V_SEL,
        ROOT_RECORD_ID,
        Some("visible selection member"),
        None,
    )
    .await;
    grant(
        &world.db,
        V_SEL,
        vec![AllowEntry::members(Capability::View)],
    )
    .await;
    link(&world.db, "q1-member-of-hidden", H_SEL, SEL, "member_of").await;
    link(&world.db, "q1-member-of-visible", V_SEL, SEL, "member_of").await;
    let envelope = |extra: serde_json::Map<String, Value>| {
        let mut query = serde_json::Map::new();
        query.insert(
            "steps".into(),
            json!([{"step": "filter", "ids": [V_SEL, H_SEL]}]),
        );
        query.insert("order".into(), Value::String("name_asc".into()));
        query.extend(extra);
        json!({"v": "0.2", "query": Value::Object(query)}).to_string()
    };
    for (id, extra) in [
        (QCOLL, serde_json::Map::new()),
        (QASOF, {
            let mut extra = serde_json::Map::new();
            extra.insert("as_of".into(), json!({"content_seq": 1}));
            extra
        }),
    ] {
        set_facet(
            &world.db,
            id,
            FacetSetPayload {
                key: "query".into(),
                value: Some(envelope(extra)),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
    }
    world.db
}

#[tokio::test]
async fn selection_and_query_members_follow_e_of_m_online() {
    use crate::mcp::tools::artifacts::resolve_collection;

    let db = collection_world().await;
    let eb = online_visible_ids(&db, ACCT_B).await;
    assert!(eb.contains(V_SEL));
    assert!(!eb.contains(H_SEL));
    let lens = ReadLens::live(&db);
    let caller_b = crate::mcp::Caller::authenticated(ACCT_B);
    // Selection: hidden member_of source is not listed and not counted.
    let selected = resolve_collection(&lens, &caller_b, SEL, "selection")
        .await
        .unwrap();
    let selected_ids: Vec<&str> = selected.iter().map(|record| record.id.as_str()).collect();
    assert_eq!(selected_ids, vec![V_SEL]);
    // Plain query collection: parity with online-as-B.
    let queried = resolve_collection(&lens, &caller_b, QCOLL, "query")
        .await
        .unwrap();
    assert!(!queried.is_empty(), "control: plain query must resolve");
    for record in &queried {
        assert!(
            eb.contains(record.id.as_str()),
            "FINDING: query collection lists {} outside E(B)",
            record.id
        );
    }
    assert!(!queried.iter().any(|record| record.id == H_SEL));
    // as_of saved query, online half: the v0.2 saved-query envelope
    // rejects top-level `as_of` at parse time (observed:
    // "unknown field `as_of`"), so online fails closed with an
    // invalid-arguments error. The offline equivalent is the typed
    // `unavailable_offline` (consumer-owned). Either way nothing hidden
    // may appear in the outcome.
    match resolve_collection(&lens, &caller_b, QASOF, "query").await {
        Ok(records) => {
            for record in &records {
                assert!(
                    eb.contains(record.id.as_str()),
                    "FINDING: as_of collection lists {} outside E(B)",
                    record.id
                );
            }
        }
        Err(error) => {
            let text = error.to_string();
            assert!(
                !text.contains(H_SEL) && !text.contains(V_SEL),
                "FINDING: as_of collection error carries record ids (R4): {text}"
            );
        }
    }
}
/// Group 6 — §7.2.8 scanner over live online responses (matrix §7.2.8).
///
/// Online member responses still carry counter-bearing fields today
/// (out of scope, tracked as 1233e34); the member copy must omit them
/// (R5, §2.6). These tests pin exactly what the producer must strip by
/// proving the pinned scanner fires on the live online shapes.
#[tokio::test]
async fn item8_scanner_fires_on_live_online_responses() {
    let world = two_caller::build().await;
    let response = get_record_tool(&world.db, ACCT_B, &[two_caller::OLD_RECORD]).await;
    let old_b =
        found_item(&response, two_caller::OLD_RECORD).expect("OLD_RECORD must resolve for B");
    // The online record version token is present and counter-bearing.
    let version = old_b
        .get("version")
        .and_then(Value::as_str)
        .expect("online record must carry a version token");
    assert!(
        version.starts_with("rec:") && version[4..].bytes().all(|byte| byte.is_ascii_digit()),
        "online version token must be rec:<seq>, got {version}"
    );
    // And the item-8 scanner rejects this live shape (it must never ship).
    let probe =
        std::panic::AssertUnwindSafe(|| assert_no_counter_fields(old_b, "online get_record as B"));
    assert!(
        std::panic::catch_unwind(probe).is_err(),
        "FINDING: item-8 scanner accepts a live online response; strip-list may be wrong"
    );
}
