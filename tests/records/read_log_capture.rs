//! Behavioural coverage for the involuntary ToolRegistry read-log wrapper.

use std::collections::HashSet;
use std::sync::Arc;

use native_ce::export::LocalSnapshotSource;
use native_ce::mcp::{
    register_builtin_tools, register_snapshot_tool, register_surface_tools, Caller,
    ExposureProfile, ToolKind, ToolRegistry,
};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sqlx::Row;

// Record ids must be canonical v4/v7 UUIDs, so every fixture id here is a
// pinned literal rather than a readable slug. The root id is named because the
// creation helper below branches on it.
const ROOT_ID: &str = "4ead1096-0000-4000-8000-000000000001";

const RUN_KEY: &str = "scout-chair-a748b2";
const REASON: &str =
    "Exercise the registry capture boundary with a real authoring event and inspect its trace.";

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    register_snapshot_tool(&mut registry, Arc::new(LocalSnapshotSource::new())).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, arguments: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), tool, arguments)
        .await
        .unwrap()
}

async fn create(registry: &ToolRegistry, db: &Db, id: &str, name: &str, parent: Option<&str>) {
    let mut arguments = json!({
        "type": if id == ROOT_ID { "Collection" } else { "Document" },
        "kind": if id == ROOT_ID { "folder" } else { "note" },
        "id": id,
        "name": name,
        "reason": REASON,
        "run_key": RUN_KEY,
    });
    if let Some(parent) = parent {
        arguments
            .as_object_mut()
            .unwrap()
            .insert("home_id".into(), json!(parent));
    }
    call(registry, db, "create_record", arguments).await;
}

#[test]
fn every_local_registration_uses_the_exhaustive_tool_kind_path() {
    let registry = registry();
    let specs = registry.specs().collect::<Vec<_>>();
    assert_eq!(specs.len(), ToolKind::ALL.len() - 2);
    assert!(
        specs.iter().all(|spec| spec.kind.is_some()),
        "a local tool used the custom/no-record registration escape hatch"
    );
    let registered = specs
        .iter()
        .map(|spec| spec.kind.unwrap())
        .collect::<HashSet<_>>();
    let exhaustive = ToolKind::ALL.into_iter().collect::<HashSet<_>>();
    assert_eq!(
        registered.len(),
        specs.len(),
        "each local registration must use a distinct ToolKind"
    );
    let hosted_only = HashSet::from([ToolKind::ManageMemberships, ToolKind::StandbyStatus]);
    let expected_local = exhaustive
        .difference(&hosted_only)
        .copied()
        .collect::<HashSet<_>>();
    assert_eq!(registered, expected_local);
    assert_eq!(
        exhaustive
            .difference(&registered)
            .copied()
            .collect::<HashSet<_>>(),
        hosted_only,
        "hosted membership management and standby-only status stay off the local registry"
    );
    for spec in &specs {
        assert_eq!(spec.name, spec.kind.unwrap().name());
        assert_eq!(spec.exposure, spec.kind.unwrap().exposure());
    }
    assert_eq!(registry.exposure_profile(), ExposureProfile::Complete);
    assert_eq!(
        registry.advertised_specs().count(),
        specs.len(),
        "complete discovery must advertise every exhaustive local registration"
    );
    assert_eq!(
        registry.specs_for_profile(ExposureProfile::Focused).count(),
        27,
        "focused remains an explicit lossy compatibility surface"
    );
    registry
        .validate_profile_budgets()
        .expect("both named production profiles fit their exact byte budgets");
}

#[tokio::test]
async fn success_error_and_zero_result_calls_are_raw_rows() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    let create_arguments = json!({
        "type": "Document",
        "kind": "note",
        "id": "4ead1096-0000-4000-8000-000000000002",
        "name": "Capture one",
        "reason": REASON,
        "run_key": RUN_KEY,
        "parent_key": "pilot-river-b748b2",
    });
    let create_result = call(&registry, &db, "create_record", create_arguments.clone()).await;

    let row = sqlx::query(
        "SELECT tool, run_key, parent_key, actor, arguments, outcome, error_kind,
                result_count, result_bytes, started_at, ended_at
           FROM read_log_calls WHERE tool = 'create_record'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.get::<String, _>("tool"), "create_record");
    assert_eq!(row.get::<String, _>("run_key"), RUN_KEY);
    assert_eq!(row.get::<String, _>("parent_key"), "pilot-river-b748b2");
    assert_eq!(row.get::<String, _>("actor"), "local");
    assert_eq!(
        serde_json::from_str::<Value>(&row.get::<String, _>("arguments")).unwrap(),
        create_arguments
    );
    assert_eq!(row.get::<String, _>("outcome"), "ok");
    assert_eq!(row.get::<Option<String>, _>("error_kind"), None);
    assert_eq!(row.get::<i64, _>("result_count"), 1);
    assert_eq!(
        row.get::<i64, _>("result_bytes"),
        serde_json::to_vec(&create_result).unwrap().len() as i64
    );
    assert!(
        row.get::<String, _>("started_at") <= row.get::<String, _>("ended_at"),
        "the call interval must be ordered"
    );

    let touch = sqlx::query(
        "SELECT t.record_id, t.interaction, t.result_rank
           FROM read_log_touches t
           JOIN read_log_calls c ON c.seq = t.call_seq
          WHERE c.tool = 'create_record'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        touch.get::<String, _>("record_id"),
        "4ead1096-0000-4000-8000-000000000002"
    );
    assert_eq!(touch.get::<String, _>("interaction"), "mutated");
    assert_eq!(touch.get::<Option<i64>, _>("result_rank"), None);

    let error_arguments = json!({
        "id": "4ead1096-0000-4000-8000-000000000003",
        "name": "cannot update",
        "run_key": RUN_KEY,
    });
    let error = registry
        .call(
            db.clone(),
            Caller::local(),
            "update_record",
            error_arguments.clone(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("missing field `reason`"));
    let error_row = sqlx::query(
        "SELECT arguments, outcome, error_kind, result_count, result_bytes
           FROM read_log_calls WHERE tool = 'update_record'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&error_row.get::<String, _>("arguments")).unwrap(),
        error_arguments
    );
    assert_eq!(error_row.get::<String, _>("outcome"), "error");
    assert_eq!(error_row.get::<String, _>("error_kind"), "engine");
    assert_eq!(error_row.get::<Option<i64>, _>("result_count"), None);
    assert!(error_row.get::<i64, _>("result_bytes") > 0);
    let error_touches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_touches t
          JOIN read_log_calls c ON c.seq = t.call_seq
         WHERE c.tool = 'update_record'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(error_touches, 0);

    let search_arguments = json!({ "query": "zzzz-no-such-token", "run_key": RUN_KEY });
    for _ in 0..2 {
        let result = call(&registry, &db, "search", search_arguments.clone()).await;
        assert_eq!(result["hits"], json!([]));
    }
    let search_rows = sqlx::query(
        "SELECT arguments, result_count FROM read_log_calls
          WHERE tool = 'search' ORDER BY seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(search_rows.len(), 2, "per-call rows must never be folded");
    for row in search_rows {
        assert_eq!(row.get::<i64, _>("result_count"), 0);
        assert_eq!(
            serde_json::from_str::<Value>(&row.get::<String, _>("arguments")).unwrap(),
            search_arguments
        );
    }

    let guide_arguments = json!({ "topic": "about", "run_key": RUN_KEY });
    let guide = call(&registry, &db, "read_guide", guide_arguments.clone()).await;
    assert_eq!(guide["topic"], "about");
    let guide_row = sqlx::query(
        "SELECT arguments, outcome, result_count FROM read_log_calls
          WHERE tool = 'read_guide'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(guide_row.get::<String, _>("outcome"), "ok");
    assert_eq!(guide_row.get::<i64, _>("result_count"), 0);
    assert_eq!(
        serde_json::from_str::<Value>(&guide_row.get::<String, _>("arguments")).unwrap(),
        guide_arguments
    );
    let guide_touches: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM read_log_touches t
          JOIN read_log_calls c ON c.seq = t.call_seq
         WHERE c.tool = 'read_guide'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(guide_touches, 0, "guide reads touch no content records");
    db.close().await;
}

#[tokio::test]
async fn extraction_distinguishes_opened_surfaced_and_mutated_with_rank() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();
    create(
        &registry,
        &db,
        "4ead1096-0000-4000-8000-000000000001",
        "Root",
        None,
    )
    .await;
    create(
        &registry,
        &db,
        "4ead1096-0000-4000-8000-000000000004",
        "Alpha child",
        Some("4ead1096-0000-4000-8000-000000000001"),
    )
    .await;
    create(
        &registry,
        &db,
        "4ead1096-0000-4000-8000-000000000005",
        "Beta child",
        Some("4ead1096-0000-4000-8000-000000000001"),
    )
    .await;
    sqlx::query("DELETE FROM read_log_calls")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    call(
        &registry,
        &db,
        "get_record",
        json!({ "ids": ["4ead1096-0000-4000-8000-000000000001"], "run_key": RUN_KEY }),
    )
    .await;
    let touches = sqlx::query(
        "SELECT t.record_id, t.interaction, t.result_rank
           FROM read_log_touches t
           JOIN read_log_calls c ON c.seq = t.call_seq
          WHERE c.tool = 'get_record'
          ORDER BY CASE t.interaction WHEN 'opened' THEN 0 ELSE 1 END, t.result_rank",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    let actual = touches
        .iter()
        .map(|row| {
            (
                row.get::<String, _>("record_id"),
                row.get::<String, _>("interaction"),
                row.get::<Option<i64>, _>("result_rank"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![
            (
                "4ead1096-0000-4000-8000-000000000001".into(),
                "opened".into(),
                None
            ),
            (
                "4ead1096-0000-4000-8000-000000000004".into(),
                "surfaced".into(),
                Some(1)
            ),
            (
                "4ead1096-0000-4000-8000-000000000005".into(),
                "surfaced".into(),
                Some(2)
            ),
            ("native:root".into(), "surfaced".into(), Some(3)),
            ("native:unfiled".into(), "surfaced".into(), Some(4)),
        ]
    );

    call(
        &registry,
        &db,
        "create_record",
        json!({
            "type": "Document",
            "kind": "note",
            "id": "4ead1096-0000-4000-8000-000000000006",
            "name": "Created enriched",
            "home_id": "4ead1096-0000-4000-8000-000000000001",
            "links": [{
                "target_id": "4ead1096-0000-4000-8000-000000000004",
                "relationship": "relates_to",
            }],
            "reason": REASON,
            "run_key": RUN_KEY,
        }),
    )
    .await;
    let created_touches = sqlx::query(
        "SELECT t.record_id, t.interaction, t.result_rank
           FROM read_log_touches t
           JOIN read_log_calls c ON c.seq = t.call_seq
          WHERE c.tool = 'create_record'
          ORDER BY CASE t.interaction WHEN 'mutated' THEN 0 ELSE 1 END, t.result_rank",
    )
    .fetch_all(db.pool())
    .await
    .unwrap()
    .iter()
    .map(|row| {
        (
            row.get::<String, _>("record_id"),
            row.get::<String, _>("interaction"),
            row.get::<Option<i64>, _>("result_rank"),
        )
    })
    .collect::<Vec<_>>();
    assert_eq!(
        created_touches,
        vec![
            ("4ead1096-0000-4000-8000-000000000006".into(), "mutated".into(), None),
            ("native:root".into(), "surfaced".into(), Some(1)),
            ("native:unfiled".into(), "surfaced".into(), Some(2)),
            ("4ead1096-0000-4000-8000-000000000001".into(), "surfaced".into(), Some(3)),
            ("4ead1096-0000-4000-8000-000000000004".into(), "surfaced".into(), Some(4)),
        ],
        "create_record returns a flattened EnrichedRecord; visible ancestor/link endpoints must be surfaced"
    );

    call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": "4ead1096-0000-4000-8000-000000000001",
            "summary": "changed",
            "reason": REASON,
            "run_key": RUN_KEY,
        }),
    )
    .await;
    let update_touches = sqlx::query(
        "SELECT t.record_id, t.interaction, t.result_rank
           FROM read_log_touches t
           JOIN read_log_calls c ON c.seq = t.call_seq
          WHERE c.tool = 'update_record'
          ORDER BY CASE t.interaction WHEN 'mutated' THEN 0 ELSE 1 END, t.result_rank",
    )
    .fetch_all(db.pool())
    .await
    .unwrap()
    .iter()
    .map(|row| {
        (
            row.get::<String, _>("record_id"),
            row.get::<String, _>("interaction"),
            row.get::<Option<i64>, _>("result_rank"),
        )
    })
    .collect::<Vec<_>>();
    assert_eq!(
        update_touches,
        vec![
            (
                "4ead1096-0000-4000-8000-000000000001".into(),
                "mutated".into(),
                None
            ),
            (
                "4ead1096-0000-4000-8000-000000000004".into(),
                "surfaced".into(),
                Some(1)
            ),
            (
                "4ead1096-0000-4000-8000-000000000005".into(),
                "surfaced".into(),
                Some(2)
            ),
            (
                "4ead1096-0000-4000-8000-000000000006".into(),
                "surfaced".into(),
                Some(3)
            ),
            ("native:root".into(), "surfaced".into(), Some(4)),
            ("native:unfiled".into(), "surfaced".into(), Some(5)),
        ],
        "update_record returns a flattened EnrichedRecord; visible children must be surfaced"
    );
    db.close().await;
}

#[tokio::test]
async fn every_recording_failure_is_fail_open_and_touch_writes_are_atomic() {
    let db = create_database(":memory:").await.unwrap();
    let registry = registry();

    // The call envelope insert succeeds, then the touch insert fails because
    // only the touch table is absent. The transaction must roll the envelope
    // back, and none of this may change the tool result.
    sqlx::query("DROP TABLE read_log_touches")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    create(
        &registry,
        &db,
        "4ead1096-0000-4000-8000-000000000007",
        "Still created",
        None,
    )
    .await;
    let calls: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM read_log_calls")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(calls, 0, "a partial trace must not survive a touch failure");
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE id = '4ead1096-0000-4000-8000-000000000007'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(exists, 1);

    // Dropping the remaining envelope table exercises the earliest persistence
    // failure. Both a read and a write continue to return their normal values.
    sqlx::query("DROP TABLE read_log_calls")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let ping = call(&registry, &db, "ping", json!({ "run_key": RUN_KEY })).await;
    assert_eq!(ping["ok"], true);
    create(
        &registry,
        &db,
        "4ead1096-0000-4000-8000-000000000008",
        "Also created",
        None,
    )
    .await;
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM records WHERE id = '4ead1096-0000-4000-8000-000000000008'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(exists, 1);
    db.close().await;
}
