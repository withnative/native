//! Gated Increment 1 consumer-registry tests: register/retire roundtrip,
//! exact retry, move-with-precondition, stale refusal, validation, fail-closed
//! tamper reads, and replay equivalence. Storage only — no adoption
//! enforcement, no rule/query execution. Nothing touches production DDL.

use crate::db::{begin_write, create_database, Db};
use crate::definition_registry::ensure_registry_tables;
use crate::meta::consumer::{
    ensure_consumer_tables, list_consumers_in, read_consumer_in, register_consumer_in,
    retire_consumer_in,
};

const SCOPE: &str = "home:test-scope";
const KIND: &str = "saved-query";
const NS: &str = "acme";
const NAME: &str = "finance-board";
const FAMILY: &str = "example.records";

fn envelope(family: &str, version: u32) -> Vec<u8> {
    serde_json::json!({
        "family": family,
        "version": version,
        "kinds": [{"token": "note"}],
    })
    .to_string()
    .into_bytes()
}

async fn test_db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    ensure_registry_tables(&db).await.unwrap();
    ensure_consumer_tables(&db).await.unwrap();
    db
}

async fn install(db: &Db, family: &str, version: u32) -> String {
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    let outcome = crate::definition_registry::install_definition_artifact_as_in(
        &mut tx,
        family,
        version,
        &envelope(family, version),
        Some("test:installer"),
        &mut alloc,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    outcome.identity.digest
}

async fn meta_count(db: &Db, event_type: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM meta_events WHERE type = ?")
        .bind(event_type)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}

async fn register(
    db: &Db,
    family: &str,
    version: u32,
    digest: &str,
    expected_seq: Option<i64>,
) -> Result<crate::meta::consumer::StoredConsumer, crate::error::Error> {
    register_as(db, family, version, digest, expected_seq, "test:registrar").await
}

async fn register_as(
    db: &Db,
    family: &str,
    version: u32,
    digest: &str,
    expected_seq: Option<i64>,
    actor: &str,
) -> Result<crate::meta::consumer::StoredConsumer, crate::error::Error> {
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    let outcome = register_consumer_in(
        &mut tx,
        SCOPE,
        KIND,
        NS,
        NAME,
        family,
        version,
        digest,
        expected_seq,
        Some(actor),
        &mut alloc,
    )
    .await;
    match outcome {
        Ok(o) => {
            tx.commit().await.unwrap();
            Ok(o.stored)
        }
        Err(e) => {
            tx.rollback().await.unwrap();
            Err(e)
        }
    }
}

#[tokio::test]
async fn register_roundtrip_lists_verified() {
    let db = test_db().await;
    let digest = install(&db, FAMILY, 1).await;
    let stored = register(&db, FAMILY, 1, &digest, None).await.unwrap();
    assert!(stored.active);
    assert_eq!(stored.version, 1);
    let mut conn = db.write_pool().acquire().await.unwrap();
    let back = read_consumer_in(&mut conn, SCOPE, KIND, NS, NAME, FAMILY)
        .await
        .unwrap()
        .expect("registered requirement reads back");
    assert_eq!(back, stored);
    let listed = list_consumers_in(&mut conn, SCOPE).await.unwrap();
    assert_eq!(listed, vec![stored]);
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn consumer_exact_retry_appends_nothing() {
    let db = test_db().await;
    let digest = install(&db, FAMILY, 1).await;
    let first = register(&db, FAMILY, 1, &digest, None).await.unwrap();
    let before = meta_count(&db, "consumer_required.v1").await;
    let second = register(&db, FAMILY, 1, &digest, Some(first.event_seq))
        .await
        .unwrap();
    assert_eq!(second.event_seq, first.event_seq);
    assert_eq!(meta_count(&db, "consumer_required.v1").await, before);
    db.close().await;
}

#[tokio::test]
async fn move_pin_updates_with_precondition_and_stale_refuses() {
    let db = test_db().await;
    let d1 = install(&db, FAMILY, 1).await;
    let d2 = install(&db, FAMILY, 2).await;
    let first = register(&db, FAMILY, 1, &d1, None).await.unwrap();
    // Blind move (no precondition over an existing row) refuses.
    assert!(register(&db, FAMILY, 2, &d2, None).await.is_err());
    let moved = register(&db, FAMILY, 2, &d2, Some(first.event_seq))
        .await
        .unwrap();
    assert_eq!(moved.version, 2);
    assert!(moved.event_seq > first.event_seq);
    // Stale precondition (old seq) refuses even though the pin matches.
    let stale = register(&db, FAMILY, 2, &d2, Some(first.event_seq)).await;
    assert!(stale.is_err());
    db.close().await;
}

async fn retire(
    db: &Db,
    expected_seq: Option<i64>,
) -> Result<crate::meta::consumer::StoredConsumer, crate::error::Error> {
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    let outcome = retire_consumer_in(
        &mut tx,
        SCOPE,
        KIND,
        NS,
        NAME,
        FAMILY,
        expected_seq,
        Some("test:registrar"),
        &mut alloc,
    )
    .await;
    match outcome {
        Ok(o) => {
            tx.commit().await.unwrap();
            Ok(o.stored)
        }
        Err(e) => {
            tx.rollback().await.unwrap();
            Err(e)
        }
    }
}

#[tokio::test]
async fn retire_then_reregister() {
    let db = test_db().await;
    let d1 = install(&db, FAMILY, 1).await;
    let first = register(&db, FAMILY, 1, &d1, None).await.unwrap();
    // Blind retire over a live row refuses; preconditioned retire works.
    assert!(retire(&db, None).await.is_err());
    let retired = retire(&db, Some(first.event_seq)).await.unwrap();
    assert!(!retired.active);
    // Already-retired retire is a verified no-op under the same seq.
    let again = retire(&db, Some(retired.event_seq)).await.unwrap();
    assert_eq!(again.event_seq, retired.event_seq);
    // Re-registration after retire appends a fresh active event.
    let back = register(&db, FAMILY, 1, &d1, Some(retired.event_seq))
        .await
        .unwrap();
    assert!(back.active);
    assert!(back.event_seq > retired.event_seq);
    // Retiring an absent key refuses.
    assert!(retire(&db, None).await.is_err());
    db.close().await;
}

#[tokio::test]
async fn registration_validates_kind_pin_and_bytes() {
    let db = test_db().await;
    let d1 = install(&db, FAMILY, 1).await;
    // Unknown consumer kind refuses.
    {
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let r = register_consumer_in(
            &mut tx,
            SCOPE,
            "dashboard",
            NS,
            NAME,
            FAMILY,
            1,
            &d1,
            None,
            Some("test:registrar"),
            &mut alloc,
        )
        .await;
        tx.rollback().await.unwrap();
        assert!(r.is_err());
    }
    // Uninstalled pin refuses (no such revision retained).
    {
        let fake = "0".repeat(64);
        let r = register(&db, FAMILY, 9, &fake, None).await;
        assert!(r.is_err());
    }
    // Installed version with a wrong digest refuses.
    {
        let wrong = "f".repeat(64);
        let r = register(&db, FAMILY, 1, &wrong, None).await;
        assert!(r.is_err());
    }
    // Malformed digest refuses.
    {
        let r = register(&db, FAMILY, 1, "not-hex", None).await;
        assert!(r.is_err());
    }
    assert_eq!(meta_count(&db, "consumer_required.v1").await, 0);
    db.close().await;
}

#[tokio::test]
async fn second_principal_gets_own_attributed_event() {
    let db = test_db().await;
    let d1 = install(&db, FAMILY, 1).await;
    let first = register_as(&db, FAMILY, 1, &d1, None, "test:alice")
        .await
        .unwrap();
    // Same pin, same seq, different principal: not the previous receipt but
    // a fresh attributed event.
    let before = meta_count(&db, "consumer_required.v1").await;
    let second = register_as(&db, FAMILY, 1, &d1, Some(first.event_seq), "test:bob")
        .await
        .unwrap();
    assert!(second.event_seq > first.event_seq);
    assert_eq!(second.actor, "test:bob");
    assert_eq!(meta_count(&db, "consumer_required.v1").await, before + 1);
    // Same principal retrying the new seq is a no-op again.
    let third = register_as(&db, FAMILY, 1, &d1, Some(second.event_seq), "test:bob")
        .await
        .unwrap();
    assert_eq!(third.event_seq, second.event_seq);
    db.close().await;
}

#[tokio::test]
async fn reserved_package_surface_kind_refused() {
    let db = test_db().await;
    let d1 = install(&db, FAMILY, 1).await;
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    let r = register_consumer_in(
        &mut tx,
        SCOPE,
        "package-surface",
        NS,
        NAME,
        FAMILY,
        1,
        &d1,
        None,
        Some("test:registrar"),
        &mut alloc,
    )
    .await;
    tx.rollback().await.unwrap();
    assert!(r.is_err());
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    let r = retire_consumer_in(
        &mut tx,
        SCOPE,
        "package-surface",
        NS,
        NAME,
        FAMILY,
        None,
        Some("test:registrar"),
        &mut alloc,
    )
    .await;
    tx.rollback().await.unwrap();
    assert!(r.is_err());
    db.close().await;
}

#[tokio::test]
async fn corrupt_row_is_never_overwritten_or_blessed() {
    let db = test_db().await;
    let d1 = install(&db, FAMILY, 1).await;
    let d2 = install(&db, FAMILY, 2).await;
    let first = register(&db, FAMILY, 1, &d1, None).await.unwrap();
    // Tamper the projection pin while the event stands.
    sqlx::query("UPDATE consumer_requirements SET digest = ? WHERE scope_home = ?")
        .bind("e".repeat(64))
        .bind(SCOPE)
        .execute(db.write_pool())
        .await
        .unwrap();
    // A move must refuse (verification fails), not overwrite the corruption.
    assert!(register(&db, FAMILY, 2, &d2, Some(first.event_seq))
        .await
        .is_err());
    // A retire must refuse too, not clear or bless it.
    assert!(retire(&db, Some(first.event_seq)).await.is_err());
    // And the corruption is still there, not papered over.
    let mut conn = db.write_pool().acquire().await.unwrap();
    assert!(read_consumer_in(&mut conn, SCOPE, KIND, NS, NAME, FAMILY)
        .await
        .is_err());
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn missing_projection_with_events_fails_closed() {
    let db = test_db().await;
    let d1 = install(&db, FAMILY, 1).await;
    register(&db, FAMILY, 1, &d1, None).await.unwrap();
    // Tamper the projection away while the event stands.
    sqlx::query("DELETE FROM consumer_requirements")
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    assert!(read_consumer_in(&mut conn, SCOPE, KIND, NS, NAME, FAMILY)
        .await
        .is_err());
    assert!(list_consumers_in(&mut conn, SCOPE).await.is_err());
    drop(conn);
    db.close().await;
}

#[tokio::test]
async fn inactive_pin_corruption_blocks_all_paths() {
    let db = test_db().await;
    let d1 = install(&db, FAMILY, 1).await;
    let first = register(&db, FAMILY, 1, &d1, None).await.unwrap();
    let retired = retire(&db, Some(first.event_seq)).await.unwrap();
    // Tamper the RETAINED inactive pin while the retirement event stands.
    sqlx::query("UPDATE consumer_requirements SET digest = ? WHERE scope_home = ?")
        .bind("e".repeat(64))
        .bind(SCOPE)
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut conn = db.write_pool().acquire().await.unwrap();
    assert!(read_consumer_in(&mut conn, SCOPE, KIND, NS, NAME, FAMILY)
        .await
        .is_err());
    assert!(list_consumers_in(&mut conn, SCOPE).await.is_err());
    drop(conn);
    // Re-registration over the corrupted inactive row refuses (the
    // pre-change verification fails); it must not overwrite the corruption.
    assert!(register(&db, FAMILY, 1, &d1, Some(retired.event_seq))
        .await
        .is_err());
    // Retiring it again refuses too; nothing blesses the tampered pin.
    assert!(retire(&db, Some(retired.event_seq)).await.is_err());
    db.close().await;
}

#[tokio::test]
async fn replay_reproduces_consumer_rows() {
    let db = test_db().await;
    let d1 = install(&db, FAMILY, 1).await;
    let d2 = install(&db, FAMILY, 2).await;
    let first = register(&db, FAMILY, 1, &d1, None).await.unwrap();
    let moved = register(&db, FAMILY, 2, &d2, Some(first.event_seq))
        .await
        .unwrap();
    let retired = retire(&db, Some(moved.event_seq)).await.unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let live = list_consumers_in(&mut tx, SCOPE).await.unwrap();
    assert_eq!(live, vec![retired.clone()]);
    let events = crate::meta::read_all_meta_events(&mut tx).await.unwrap();
    let registry_events: Vec<_> = events
        .iter()
        .filter(|event| {
            matches!(
                event.event_type.as_str(),
                "definition_artifact.installed" | "consumer_required.v1" | "consumer_retired.v1"
            )
        })
        .cloned()
        .collect();
    // Rebuild projections from the retained log. A separately bootstrapped
    // database has different vocabulary ids and its own unrelated log; it
    // cannot support this registry's event-vs-projection verification.
    for table in ["consumer_requirements", "definition_artifacts"] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    // Only these registry projections were cleared; production vocabulary
    // projections and their seed events remain outside this isolated proof.
    crate::projector::meta::replay_meta(&mut tx, &registry_events)
        .await
        .unwrap();
    let rebuilt = list_consumers_in(&mut tx, SCOPE).await.unwrap();
    assert_eq!(rebuilt, vec![retired]);
    assert_eq!(
        crate::meta::read_all_meta_events(&mut tx).await.unwrap(),
        events
    );
    tx.commit().await.unwrap();
    db.close().await;
}
