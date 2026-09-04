use std::time::Duration;

use native_ce::authorization::{
    replace_explicit_policy, restore_inheritance, AllowEntry, Capability,
};
use native_ce::conformance::rebuild_and_diff_policy;
use native_ce::events::EventRow;
use native_ce::policy::PolicyReplacedPayload;
use native_ce::projector::replay;
use native_ce::schema::ROOT_RECORD_ID;
use native_ce::store::create_record;
use native_ce::{apply_schema, create_database, open_database, open_existing_database_at};
use serde_json::json;
use sqlx::Row;

/// Fixture record ids. Record ids must be canonical lowercase UUIDs, so the
/// readable name lives in the constant. Pinned literals, never generated.
const PRIVATE: &str = "901c0000-0000-4000-8000-000000000001";
const ATOMIC: &str = "901c0000-0000-4000-8000-000000000002";

async fn create_note(db: &native_ce::Db, id: &str) {
    create_record(
        db,
        json!({
            "id": id,
            "type": "Document",
            "kind": "note",
            "name": id,
        }),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn fresh_database_has_one_root_genesis_and_content_replay_creates_no_policy() {
    let db = create_database(":memory:").await.unwrap();
    let row = sqlx::query("SELECT record_id, type, payload, actor FROM policy_events ORDER BY seq")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("record_id"), ROOT_RECORD_ID);
    assert_eq!(row.get::<String, _>("type"), "policy.replaced");
    assert_eq!(row.get::<String, _>("actor"), "engine:seed");
    let payload: PolicyReplacedPayload =
        serde_json::from_str(&row.get::<String, _>("payload")).unwrap();
    assert_eq!(payload.entries.len(), 1);
    assert_eq!(payload.entries[0].subject_kind, "members");
    assert_eq!(payload.entries[0].capability, "edit");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);

    let rows = sqlx::query(
        "SELECT seq,id,record_id,type,payload,actor,run_key,parent_key,intent,created_at
           FROM content_events ORDER BY seq",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    let events = rows
        .into_iter()
        .map(|row| EventRow {
            local_seq: row.get("seq"),
            id: row.get("id"),
            record_id: row.get("record_id"),
            event_type: row.get("type"),
            payload: row.get("payload"),
            actor: row.get("actor"),
            run_key: row.get("run_key"),
            parent_key: row.get("parent_key"),
            intent: row.get("intent"),
            created_at: row.get("created_at"),
            causal_envelope: native_ce::events::CausalEnvelopeV1::legacy_unknown(),
        })
        .collect::<Vec<_>>();
    let scratch = open_database(":memory:").await.unwrap();
    apply_schema(&scratch).await.unwrap();
    let mut conn = crate::common::fixture_write_pool(&scratch)
        .await
        .acquire()
        .await
        .unwrap();
    replay(&mut conn, &events).await.unwrap();
    let policies: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM record_policies")
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    assert_eq!(policies, 0);
}

#[tokio::test]
async fn replacements_and_restoration_are_full_state_actor_stamped_and_replayable() {
    let db = create_database(":memory:").await.unwrap();
    create_note(&db, PRIVATE).await;
    replace_explicit_policy(
        &db,
        "acct:alice",
        PRIVATE,
        vec![
            AllowEntry::account("acct:bea", Capability::View),
            AllowEntry::account("acct:bea", Capability::Edit),
        ],
    )
    .await
    .unwrap();
    let original_created_at: String =
        sqlx::query_scalar("SELECT created_at FROM record_policies WHERE record_id=?")
            .bind(PRIVATE)
            .fetch_one(db.pool())
            .await
            .unwrap();
    replace_explicit_policy(&db, "acct:bea", PRIVATE, vec![])
        .await
        .unwrap();
    let preserved_created_at: String =
        sqlx::query_scalar("SELECT created_at FROM record_policies WHERE record_id=?")
            .bind(PRIVATE)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(preserved_created_at, original_created_at);
    restore_inheritance(&db, "acct:bea", PRIVATE).await.unwrap();
    tokio::time::sleep(Duration::from_millis(2)).await;
    replace_explicit_policy(&db, "acct:alice", PRIVATE, vec![])
        .await
        .unwrap();
    let recreated_at: String =
        sqlx::query_scalar("SELECT created_at FROM record_policies WHERE record_id=?")
            .bind(PRIVATE)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_ne!(recreated_at, original_created_at);

    let rows = sqlx::query(
        "SELECT type,payload,actor FROM policy_events
          WHERE record_id=? ORDER BY seq",
    )
    .bind(PRIVATE)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0].get::<String, _>("actor"), "acct:alice");
    let first: PolicyReplacedPayload =
        serde_json::from_str(&rows[0].get::<String, _>("payload")).unwrap();
    assert_eq!(first.entries.len(), 1);
    assert_eq!(first.entries[0].capability, "edit");
    let second: PolicyReplacedPayload =
        serde_json::from_str(&rows[1].get::<String, _>("payload")).unwrap();
    assert!(second.entries.is_empty());
    assert_eq!(
        rows[2].get::<String, _>("type"),
        "policy.inheritance_restored"
    );
    assert_eq!(rows[2].get::<Option<String>, _>("payload"), None);
    assert!(rebuild_and_diff_policy(&db).await.unwrap().equal);
}

#[tokio::test]
async fn append_and_projection_are_atomic_and_the_log_is_append_only() {
    let db = create_database(":memory:").await.unwrap();
    create_note(&db, ATOMIC).await;
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    for reserved_actor in ["engine:seed", "engine:migration", "engine:future"] {
        let error = replace_explicit_policy(&db, reserved_actor, ATOMIC, vec![])
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reserved"));
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM policy_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        before
    );
    sqlx::query(
        "CREATE TRIGGER injected_policy_projection_failure
           BEFORE INSERT ON policy_entries
           BEGIN SELECT RAISE(ABORT, 'injected projection failure'); END",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    assert!(replace_explicit_policy(
        &db,
        "acct:alice",
        ATOMIC,
        vec![AllowEntry::account("acct:bea", Capability::View)],
    )
    .await
    .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM policy_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM record_policies WHERE record_id=?")
            .bind(ATOMIC)
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
    sqlx::query("DROP TRIGGER injected_policy_projection_failure")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    sqlx::query(
        "CREATE TRIGGER injected_policy_append_failure
           BEFORE INSERT ON policy_events
           BEGIN SELECT RAISE(ABORT, 'injected append failure'); END",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    assert!(replace_explicit_policy(&db, "acct:alice", ATOMIC, vec![])
        .await
        .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM policy_events")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        before
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM record_policies WHERE record_id=?")
            .bind(ATOMIC)
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
    sqlx::query("DROP TRIGGER injected_policy_append_failure")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();

    for statement in [
        "UPDATE policy_events SET actor='tampered' WHERE seq=1",
        "DELETE FROM policy_events WHERE seq=1",
    ] {
        assert!(sqlx::query(statement)
            .execute(&crate::common::fixture_write_pool(&db).await)
            .await
            .is_err());
    }
}

#[tokio::test]
async fn malformed_policy_log_is_reported_without_panicking_or_repairing_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("malformed-policy.db");
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    let mut connection = crate::common::fixture_write_pool(&db)
        .await
        .acquire()
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER policy_events_no_update")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("UPDATE policy_events SET type='policy.unknown' WHERE seq=1")
        .execute(&mut *connection)
        .await
        .unwrap();
    drop(connection);
    assert!(rebuild_and_diff_policy(&db).await.is_err());
    let policy_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM record_policies")
        .fetch_one(db.pool())
        .await
        .unwrap();
    db.close().await;
    let error = open_existing_database_at(&path)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("malformed policy event log"), "{error}");
    let raw = open_database(&path.to_string_lossy()).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM record_policies")
            .fetch_one(raw.pool())
            .await
            .unwrap(),
        policy_count
    );
}

#[tokio::test]
async fn existing_database_open_never_synthesizes_a_missing_root_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-policy-genesis.db");
    let db = create_database(&path.to_string_lossy()).await.unwrap();
    let mut connection = crate::common::fixture_write_pool(&db)
        .await
        .acquire()
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER policy_events_no_delete")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query("DELETE FROM policy_events")
        .execute(&mut *connection)
        .await
        .unwrap();
    sqlx::query(
        "CREATE TRIGGER policy_events_no_delete BEFORE DELETE ON policy_events
           BEGIN SELECT RAISE(ABORT, 'policy_events is append-only'); END",
    )
    .execute(&mut *connection)
    .await
    .unwrap();
    drop(connection);
    db.close().await;

    let error = open_existing_database_at(&path)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("no canonical root genesis"), "{error}");
    let raw = open_database(&path.to_string_lossy()).await.unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM policy_events")
            .fetch_one(raw.pool())
            .await
            .unwrap(),
        0
    );
}

/// Engine 46 narrowed every authorization-epoch UPDATE trigger to genuine
/// value changes. The two policy-projection tables are proved here rather than
/// beside the migration because the policy write funnel confines every
/// `policy_entries` / `record_policies` mutation under `src/` to the two named
/// projectors, and a fixture that re-asserts a row's own values is not one.
#[tokio::test]
async fn the_authorization_epoch_ignores_value_preserving_policy_projection_rewrites() {
    let db = create_database(":memory:").await.unwrap();
    let pool = crate::common::fixture_write_pool(&db).await;
    let epoch = || async {
        sqlx::query_scalar::<_, i64>("SELECT epoch FROM authorization_revision WHERE id = 1")
            .fetch_one(&pool)
            .await
            .unwrap()
    };

    // Root genesis seeds exactly one explicit policy and one entry, so both
    // guarded tables have a row to rewrite.
    let quiet = epoch().await;
    for value_preserving in [
        "UPDATE record_policies SET record_id = record_id, created_at = created_at",
        "UPDATE policy_entries SET capability = capability, subject_id = subject_id",
    ] {
        let affected = sqlx::query(value_preserving)
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected();
        assert!(affected > 0, "{value_preserving} must reach a row");
        assert_eq!(
            epoch().await,
            quiet,
            "{value_preserving} must not advance the authorization epoch"
        );
    }

    // Narrowed, not withdrawn.
    let changed =
        sqlx::query("UPDATE policy_entries SET capability = 'view' WHERE capability = 'edit'")
            .execute(&pool)
            .await
            .unwrap()
            .rows_affected();
    assert!(changed > 0);
    assert!(
        epoch().await > quiet,
        "a real capability change must advance the authorization epoch"
    );
    db.close().await;
}
