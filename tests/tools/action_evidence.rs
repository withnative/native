//! The action-evidence carve-out of the interaction log, pinned end to end.
//!
//! Native's shared world contains only what was done to it, so the attention
//! tier of the interaction log is foldable. The calls that are evidence about
//! *acts* are not: `get_run_activity`'s work-overlap outcome evaluation reads
//! them raw, per call, in order. `native_ce::mcp::action_evidence` is the
//! single authority for which calls those are; this suite asserts that real
//! capture actually keeps what that authority promises.
//!
//! What this reaches: the set itself, that every surface in it is a live
//! registered tool, verbatim `arguments` after a real call, one `mutated`
//! touch co-located on that call's own row, capture order, and retention of
//! a `result_annotation` on a real disclosed overlap. What it cannot reach:
//! a future capture change is only caught where it changes one of those
//! observable properties — see the module docs in `src/mcp/action_evidence.rs`.

use native_ce::mcp::action_evidence::{
    action_evidence_surfaces, is_action_evidence, is_action_evidence_surface,
};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn local_create(registry: &ToolRegistry, db: &Db, name: &str) -> String {
    let id = registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            crate::common::with_test_reason(
                "create_record",
                json!({
                    "type": "WorkItem",
                    "kind": "task",
                    "name": name,
                    "lifecycle": "in_progress",
                }),
            ),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    db.drain_captures_for_tests().await;
    id
}

async fn ensure_account_binding(db: &Db, account: &str, person_id: &str) {
    let pool = crate::common::fixture_write_pool(db).await;
    sqlx::query(
        "INSERT OR IGNORE INTO records
            (id, type, kind, name, home_id, policy_anchor_id, persistence)
         VALUES (?, 'Entity', 'person', 'Test account', ?, ?, 'enduring')",
    )
    .bind(person_id)
    .bind(native_ce::schema::UNFILED_RECORD_ID)
    .bind(native_ce::schema::ROOT_RECORD_ID)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT OR IGNORE INTO bindings
            (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(person_id)
    .bind(account)
    .execute(&pool)
    .await
    .unwrap();
}

/// The captured row for the one call of `tool` in this database: its seq, its
/// stored arguments, its retained annotation, and the records it mutated.
async fn captured(db: &Db, tool: &str, marker: &str) -> (i64, Value, Option<String>, Vec<String>) {
    let row: (i64, String, Option<String>) = sqlx::query_as(
        "SELECT seq, arguments, result_annotation FROM read_log_calls
          WHERE tool=? AND arguments LIKE '%' || ? || '%' AND outcome='ok'
          ORDER BY seq",
    )
    .bind(tool)
    .bind(marker)
    .fetch_one(db.pool())
    .await
    .unwrap_or_else(|error| panic!("{tool} call was not captured raw: {error}"));
    let mutated: Vec<String> = sqlx::query_scalar(
        "SELECT dictionary.record_id
           FROM read_log_touches touch
           JOIN read_log_record_ids dictionary ON dictionary.record_ref=touch.record_ref
          WHERE touch.call_seq=? AND touch.interaction='mutated'
          ORDER BY dictionary.record_id",
    )
    .bind(row.0)
    .fetch_all(db.pool())
    .await
    .unwrap();
    (row.0, serde_json::from_str(&row.1).unwrap(), row.2, mutated)
}

#[test]
fn the_carve_out_is_one_named_set_the_evaluator_surfaces_belong_to() {
    let surfaces = action_evidence_surfaces();
    // The surfaces `get_run_activity` reads by shape, and the notice surface
    // whose own row anchors the evaluation.
    for tool in [
        "start_work",
        "manage_links",
        "create_record",
        "set_intent",
        "update_record",
    ] {
        assert!(
            surfaces.contains(&tool),
            "{tool} is read by the overlap evaluator but is not action evidence"
        );
        assert!(is_action_evidence(tool, false));
    }
    // Attention, not action: a pure read is only action evidence when it
    // carries a retained overlap notice, which it cannot.
    for tool in ["get_record", "query_record", "get_history", "read_guide"] {
        assert!(!is_action_evidence_surface(tool), "{tool} is attention");
    }
    assert_eq!(surfaces.len(), 27, "the action-evidence set changed size");
}

#[test]
fn every_action_evidence_surface_is_a_live_registered_tool() {
    let registry = registry();
    let registered = registry
        .specs()
        .map(|spec| spec.name.clone())
        .collect::<Vec<_>>();
    for tool in action_evidence_surfaces() {
        assert!(
            registered.iter().any(|name| name == tool),
            "{tool} is carved out of the attention tier but no longer ships"
        );
    }
}

#[tokio::test]
async fn action_evidence_calls_keep_arguments_touches_and_order_through_real_capture() {
    let db = db().await;
    let registry = registry();
    ensure_account_binding(&db, "account:evidence", "test:account-evidence-person").await;

    let parent = local_create(&registry, &db, "Evidence parent").await;
    let target = local_create(&registry, &db, "Evidence target").await;
    let caller = Caller::authenticated("account:evidence");

    // 1. A claim: `start_work` is both a coordination surface (its `release`
    //    action decides the `released` verdict) and material work.
    let claim_arguments = json!({
        "record_id": target,
        "action": "claim",
        "run_key": "evidence-anchor-a10b2c",
    });
    registry
        .call(
            db.clone(),
            caller.clone(),
            "start_work",
            claim_arguments.clone(),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;

    // 2. A durable link: the v1 generic coordination primitive. The verdict
    //    turns on `action=add` surviving verbatim in this row's arguments.
    let link_arguments = json!({
        "action": "add",
        "source_id": target,
        "target_id": parent,
        "relationship": "part_of",
        "run_key": "evidence-anchor-a10b2c",
    });
    registry
        .call(
            db.clone(),
            caller.clone(),
            "manage_links",
            link_arguments.clone(),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;

    // 3. Material work on the same record.
    let update_arguments = crate::common::with_test_reason(
        "update_record",
        json!({
            "id": target,
            "name": "Evidence target, worked on",
            "run_key": "evidence-anchor-a10b2c",
        }),
    );
    registry
        .call(
            db.clone(),
            caller.clone(),
            "update_record",
            update_arguments.clone(),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;

    // 4. Attention, for contrast: disposable exhaust under capture filtering
    //    (task 8a6377f PR A). It earns no row; nothing reads its shape.
    registry
        .call(
            db.clone(),
            caller.clone(),
            "get_record",
            json!({ "ids": [target.clone()], "run_key": "evidence-anchor-a10b2c" }),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;

    let (claim_seq, claim_stored, _, claim_mutated) =
        captured(&db, "start_work", "evidence-anchor-a10b2c").await;
    let (link_seq, link_stored, _, link_mutated) =
        captured(&db, "manage_links", "evidence-anchor-a10b2c").await;
    let (update_seq, update_stored, _, update_mutated) =
        captured(&db, "update_record", "evidence-anchor-a10b2c").await;

    // Verbatim arguments. Not "contains the fields we happen to check": the
    // evaluator reads structure, so any shaping at capture is a narrowing.
    assert_eq!(claim_stored, claim_arguments, "start_work arguments shaped");
    assert_eq!(link_stored, link_arguments, "manage_links arguments shaped");
    assert_eq!(
        update_stored, update_arguments,
        "update_record arguments shaped"
    );

    // This call's own mutations, co-located on this call's own row. The
    // evaluator asks "did *this* action mutate an eligible record".
    assert_eq!(claim_mutated, vec![target.clone()]);
    let mut both = vec![parent.clone(), target.clone()];
    both.sort();
    assert_eq!(link_mutated, both);
    assert_eq!(update_mutated, vec![target.clone()]);

    // Intra-episode order, which chooses between the verdicts.
    assert!(
        claim_seq < link_seq && link_seq < update_seq,
        "capture order lost: {claim_seq}, {link_seq}, {update_seq}"
    );

    // Folding: each action-evidence call is still its own row.
    let rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_calls
          WHERE tool IN ('start_work','manage_links','update_record')
            AND arguments LIKE '%evidence-anchor-a10b2c%'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(rows, 3, "action-evidence calls were folded at capture");
}

#[tokio::test]
async fn a_disclosed_overlap_notice_is_retained_on_its_own_call_row() {
    let db = db().await;
    let registry = registry();
    ensure_account_binding(&db, "account:holder", "test:account-holder-person").await;
    ensure_account_binding(&db, "account:second", "test:account-second-person").await;

    let parent = local_create(&registry, &db, "Notice parent").await;
    let sibling = local_create(&registry, &db, "Notice sibling").await;
    let target = local_create(&registry, &db, "Notice target").await;
    for (source, relationship) in [(&sibling, "part_of"), (&target, "part_of")] {
        registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_links",
                json!({
                    "action": "add",
                    "source_id": source,
                    "target_id": parent,
                    "relationship": relationship,
                }),
            )
            .await
            .unwrap();
        db.drain_captures_for_tests().await;
    }

    registry
        .call(
            db.clone(),
            Caller::authenticated("account:holder"),
            "start_work",
            json!({ "record_id": sibling, "run_key": "holder-notice-b31f4a" }),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;

    // Establish the second caller's run before it claims, as a real agent
    // does: the claim is the surface whose notice must be retained.
    registry
        .call(
            db.clone(),
            Caller::authenticated("account:second"),
            "set_intent",
            json!({
                "intent": "pin the retained overlap notice",
                "run_key": "second-notice-c42a5b",
            }),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;

    let claim = registry
        .call(
            db.clone(),
            Caller::authenticated("account:second"),
            "start_work",
            json!({
                "record_id": target,
                "action": "claim",
                "run_key": "second-notice-c42a5b",
            }),
        )
        .await
        .unwrap();
    db.drain_captures_for_tests().await;
    assert!(
        claim.get("work_overlap").is_some(),
        "fixture no longer discloses an overlap: {claim}"
    );

    let (_, _, annotation, _) = captured(&db, "start_work", "second-notice-c42a5b").await;
    let annotation = annotation.expect("the disclosed overlap notice was not retained");
    let annotation: Value = serde_json::from_str(&annotation).unwrap();
    assert_eq!(annotation["kind"], "work_overlap_emission");
    assert_eq!(annotation["surface"], "claim");
    // A call carrying a notice is action evidence whatever its tool is.
    assert!(is_action_evidence("start_work", true));
}
