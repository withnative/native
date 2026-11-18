//! Synthetic fixture oracle retained from base 9f65455. This intentionally
//! preserves the prior algorithm so full metadata and canonical content digest
//! can be compared on the same source read cut, including authority helpers.
use super::*;
use std::future::Future;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

async fn baseline_record_metadata(
    source: &mut sqlx::SqliteConnection,
    destination: &mut Connection,
    principal: &str,
    shape_ids: &BTreeSet<String>,
) -> Result<()> {
    let ids: Vec<String> = storage(
        storage(destination.prepare("SELECT id FROM records ORDER BY id"))?
            .query_map([], |row| row.get(0)),
    )?
    .collect::<std::result::Result<_, _>>()
    .map_err(|_| Refusal::Storage)?;
    let visible: std::collections::HashSet<_> = ids.iter().cloned().collect();
    let mut owners = std::collections::BTreeMap::<String, Option<String>>::new();
    for id in ids {
        let raw: Option<String> = storage(
            sqlx::query_scalar("SELECT owner_id FROM main.kernel_records WHERE id=?")
                .bind(&id)
                .fetch_optional(&mut *source)
                .await,
        )?
        .flatten();
        let owner = if let Some(raw) = raw {
            if visible.contains(&raw) {
                Some(raw)
            } else if let Some(owner) = owners.get(&raw) {
                owner.clone()
            } else {
                let owner =
                    crate::mcp::kernel_v2::member_visible_person_on(source, principal, Some(&raw))
                        .await
                        .map_err(|_| Refusal::Authorization)?
                        .filter(|id| visible.contains(id));
                owners.insert(raw, owner.clone());
                owner
            }
        } else {
            None
        };
        let boundary = crate::mcp::kernel_v2::custody_boundary_on(source, &id)
            .await
            .map_err(|_| Refusal::Storage)?;
        let containment_path_visible =
            crate::mcp::kernel_v2::native_containment_path_visible_on(source, principal, &id)
                .await
                .map_err(|_| Refusal::Authorization)?;
        let display_reference = crate::mcp::kernel_v2::member_display_reference_on(source, &id)
            .await
            .map_err(|_| Refusal::Storage)?;
        let native_comment = crate::kernel::comments_v2::is_comment_on(source, &id)
            .await
            .map_err(|_| Refusal::Storage)?;
        let bears_shape = shape_ids.contains(&id);
        let comment_context = if native_comment {
            let bearers = crate::kernel::comments_v2::bearer_on(source, &id)
                .await
                .map_err(|_| Refusal::Authorization)?;
            let [bearer] = bearers.as_slice() else {
                return Err(Refusal::Content);
            };
            let position = crate::kernel::comments_v2::position_on(source, bearer)
                .await
                .map_err(|_| Refusal::Content)?;
            let (position, root_id) = match position {
                crate::kernel::comments_v2::Position::Root => ("root", id.as_str()),
                crate::kernel::comments_v2::Position::Reply => ("reply", bearer.as_str()),
            };
            Some(storage(serde_json::to_string(
                &serde_json::json!({"position":position,"root_id":root_id}),
            ))?)
        } else {
            None
        };
        let native_identity = if id == crate::events::KERNEL_ROOT_ID {
            serde_json::json!({"virtual_root":true})
        } else {
            let record = crate::kernel::read_record_on(source, principal, &id)
                .await
                .map_err(|_| Refusal::Authorization)?
                .ok_or(Refusal::Authorization)?;
            let created_at: String = storage(
                sqlx::query_scalar("SELECT created_at FROM main.kernel_records WHERE id=?")
                    .bind(&id)
                    .fetch_one(&mut *source)
                    .await,
            )?;
            crate::mcp::kernel_v2::native_record_identity(&record, &created_at)
        };
        let native_identity = storage(serde_json::to_string(&native_identity))?;
        let (typ, kind): (String, Option<String>) = storage(destination.query_row(
            "SELECT type,kind FROM records WHERE id=?",
            [&id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ))?;
        let blob_metadata = if typ == "Document" && kind.as_deref() == Some("attachment") {
            let metadata = crate::kernel::blobs::metadata_optional(source, principal, &id)
                .await
                .map_err(|_| Refusal::Authorization)?;
            metadata
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| Refusal::Content)?
        } else {
            None
        };
        storage(destination.execute(
            "INSERT INTO member_record_metadata VALUES (?,?,?,?,?,?,?,?,?,?)",
            rusqlite::params![
                id,
                owner,
                boundary,
                display_reference,
                native_comment,
                bears_shape,
                blob_metadata,
                native_identity,
                comment_context,
                containment_path_visible
            ],
        ))?;
    }
    Ok(())
}

// SQLite's preparation authorizer measures structural work without enabling
// extra dependency features or timing source authority helpers.
fn metadata_rows(destination: &Connection) -> Vec<Vec<rusqlite::types::Value>> {
    destination
        .prepare("SELECT * FROM member_record_metadata ORDER BY record_id")
        .unwrap()
        .query_map([], |row| (0..10).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

// Called by the existing rich lifecycle fixture, which already asserts live
// owner/reference/comment/attachment behavior, hidden records, and reopening.
// The two algorithms share one pinned physical source transaction; all member
// tables and private identity/scope footing participate in the original digest.
pub(super) async fn same_cut_metadata(db: &crate::Db, produced: &ProducedMemberFile) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("metadata-comparison.db");
    produced.persist(&path).unwrap();
    let mut destination = Connection::open(path).unwrap();
    let expected = metadata_rows(&destination);
    let expected_digest = digest(&destination).unwrap();
    assert_eq!(expected_digest, produced.manifest.content_digest);
    for predicate in [
        "owner_id IS NOT NULL",
        "native_comment=1 AND comment_context IS NOT NULL",
        "blob_metadata IS NOT NULL",
        "display_reference IS NOT NULL",
    ] {
        let count: i64 = destination
            .query_row(
                &format!("SELECT count(*) FROM member_record_metadata WHERE {predicate}"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(count > 0, "oracle fixture must exercise {predicate}");
    }
    let mut source = db.pool().acquire().await.unwrap();
    source.close_on_drop();
    sqlx::query("BEGIN").execute(&mut *source).await.unwrap();
    assert!(
        matches!(capture_in(&mut source, &produced.cut.origin_database_id,
        &produced.cut.account_binding).await.unwrap(), NativeMemberSource::Ready(cut) if cut == produced.cut)
    );
    let selected_ids: Vec<_> = expected
        .iter()
        .map(|row| match &row[0] {
            rusqlite::types::Value::Text(id) => id.clone(),
            _ => panic!("selected id must be text"),
        })
        .collect();
    let repeated_raw_owners: Vec<String> = sqlx::query_scalar(
        "SELECT owner_id FROM main.kernel_records WHERE id IN (SELECT value FROM json_each(?)) AND owner_id IS NOT NULL GROUP BY owner_id HAVING count(*)>1")
        .bind(serde_json::to_string(&selected_ids).unwrap()).fetch_all(&mut *source).await.unwrap();
    assert!(
        repeated_raw_owners
            .iter()
            .any(|owner| !selected_ids.contains(owner)),
        "fixture exercises repeated non-selected raw owner resolution and cache hits"
    );
    let shape_ids = kernel::v1_state::schema_rows_on(&mut source, &produced.cut.principal_id)
        .await
        .unwrap()
        .into_iter()
        .filter_map(|row| row.applies_to_collection_id)
        .collect();
    for baseline in [true, false] {
        destination
            .execute("DELETE FROM member_record_metadata", [])
            .unwrap();
        if baseline {
            baseline_record_metadata(
                &mut source,
                &mut destination,
                &produced.cut.principal_id,
                &shape_ids,
            )
            .await
            .unwrap();
        } else {
            use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
            let counts = Arc::new(std::sync::Mutex::new([0usize; 4]));
            let observed = counts.clone();
            destination.authorizer(Some(move |context: AuthContext<'_>| {
                let mut counts = observed.lock().unwrap();
                match context.action {
                    AuthAction::Select => counts[0] += 1,
                    AuthAction::Insert {
                        table_name: "member_record_metadata",
                    } => counts[1] += 1,
                    AuthAction::Transaction {
                        operation: TransactionOperation::Begin,
                    } => counts[2] += 1,
                    _ => {}
                }
                Authorization::Allow
            }));
            let committed = counts.clone();
            destination.commit_hook(Some(move || {
                committed.lock().unwrap()[3] += 1;
                false
            }));
            let future = selection::record_metadata(
                &mut source,
                &mut destination,
                &produced.cut.principal_id,
                &shape_ids,
            );
            fn require_send<T: Send>(_: &T) {}
            require_send(&future);
            future.await.unwrap();
            destination.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
            destination.commit_hook(None::<fn() -> bool>);
            assert_eq!(
                *counts.lock().unwrap(),
                [1, 1, 1, 1],
                "one selected-record SELECT, one prepared INSERT, one transaction"
            );
        }
        assert_eq!(
            metadata_rows(&destination),
            expected,
            "all metadata cells, including identity and scope interpretation"
        );
        validate_closure(&destination).unwrap();
        assert_eq!(
            digest(&destination).unwrap(),
            expected_digest,
            "entire canonical member cut, including mentions and attachments"
        );
    }
    // A caller may have memoized labels while a logical TEMP projection was
    // installed. The same canonical main heads do not identify TEMP state.
    // Seed that exact typed label cache, then release TEMP and verify that the
    // production entrypoint ignores it, without changing the caller's entries.
    destination
        .execute("DELETE FROM member_record_metadata", [])
        .unwrap();
    crate::kernel::read_cache::scope_request(async {
        type Labels = std::sync::Mutex<std::collections::BTreeMap<String, Option<Json>>>;
        sqlx::query("SAVEPOINT synthetic_projection; CREATE TEMP TABLE content_events AS SELECT * FROM main.content_events WHERE 0")
            .execute(&mut *source).await.unwrap();
        let key = crate::kernel::read_cache::key_on(&mut source, &produced.cut.principal_id, "ancestor_descriptors").await.unwrap();
        let labels: Arc<Labels> = Arc::new(std::sync::Mutex::new(
            selected_ids.iter().cloned().chain([KERNEL_ROOT_ID.to_owned(), "native:root".into()])
                .map(|id| (id, None)).collect()));
        crate::kernel::read_cache::put(key.clone(), labels.clone());
        sqlx::query("ROLLBACK TO synthetic_projection; RELEASE synthetic_projection")
            .execute(&mut *source).await.unwrap();
        crate::kernel::read_cache::with_capabilities(selection::record_metadata(
            &mut source, &mut destination, &produced.cut.principal_id, &shape_ids,
        )).await.unwrap();
        assert!(Arc::ptr_eq(&crate::kernel::read_cache::get::<Labels>(&key).unwrap(), &labels));
    }).await;
    assert_eq!(
        metadata_rows(&destination),
        expected,
        "TEMP-seeded caller labels must not alter any output cell"
    );
    validate_closure(&destination).unwrap();
    assert_eq!(digest(&destination).unwrap(), expected_digest);
    sqlx::query("ROLLBACK").execute(&mut *source).await.unwrap();
}

#[tokio::test]
async fn metadata_refusal_order_and_cancel_roll_back_without_reusing_the_snapshot() {
    let (directory, db, _, principal) = fixture(true).await;
    let produced = produce(&db, MEMBER, directory.path()).await;
    let path = directory.path().join("metadata-refusal.db");
    produced.persist(&path).unwrap();
    let mut destination = Connection::open(path).unwrap();
    let mut source = db.pool().acquire().await.unwrap();
    source.close_on_drop();
    sqlx::query("BEGIN").execute(&mut *source).await.unwrap();
    let shape_ids = BTreeSet::new();
    // An appended unavailable record refuses only after earlier records wrote.
    // An invalid destination type must not overtake its source authorization
    // refusal. The old id-only prefetch also refuses any invalid id up front.
    for (mutation, expected) in [
        ("INSERT INTO records(id,type,kind) VALUES ('zz:missing','Document','attachment')", Refusal::Authorization),
        ("INSERT INTO records(id,type,kind) VALUES ('zz:missing',123,'attachment')", Refusal::Authorization),
        ("UPDATE records SET type=123 WHERE id='person:member'", Refusal::Storage),
        ("CREATE TRIGGER fail_metadata BEFORE INSERT ON member_record_metadata WHEN NEW.record_id='person:owner' BEGIN SELECT RAISE(ABORT,'synthetic'); END", Refusal::Storage),
        ("INSERT INTO records(id,type,kind) VALUES (NULL,'Document','attachment')", Refusal::Storage),
    ] {
        destination.execute_batch("DELETE FROM member_record_metadata; SAVEPOINT malformed").unwrap();
        destination.execute_batch(mutation).unwrap();
        let baseline = baseline_record_metadata(&mut source, &mut destination, &principal, &shape_ids).await;
        assert_eq!(baseline, Err(expected));
        destination.execute_batch("DELETE FROM member_record_metadata; RELEASE malformed; INSERT INTO member_record_metadata(record_id) VALUES ('sentinel')").unwrap();
        assert_eq!(selection::record_metadata(&mut source, &mut destination, &principal, &shape_ids).await, baseline);
        assert!(destination.is_autocommit());
        let remaining = metadata_rows(&destination);
        assert_eq!(remaining.len(), 1, "rollback retains only the preexisting row");
        assert_eq!(remaining[0][0], rusqlite::types::Value::Text("sentinel".into()));
        // Restore the original selected rows before the next malformed case.
        drop(destination);
        std::fs::remove_file(directory.path().join("metadata-refusal.db")).unwrap();
        produced.persist(&directory.path().join("metadata-refusal.db")).unwrap();
        destination = Connection::open(directory.path().join("metadata-refusal.db")).unwrap();
    }
    // Exercise the virtual-root identity branch explicitly; the ordinary
    // native fixture's structural root need not be a physical selected record.
    destination
        .execute(
            "INSERT INTO records(id,type,kind) VALUES (?,'Collection','root')",
            [KERNEL_ROOT_ID],
        )
        .unwrap();
    destination
        .execute("DELETE FROM member_record_metadata", [])
        .unwrap();
    baseline_record_metadata(&mut source, &mut destination, &principal, &shape_ids)
        .await
        .unwrap();
    let root_expected = metadata_rows(&destination);
    let identity: String = destination
        .query_row(
            "SELECT native_identity FROM member_record_metadata WHERE record_id=?",
            [KERNEL_ROOT_ID],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Json>(&identity).unwrap(),
        json!({"virtual_root": true})
    );
    destination
        .execute("DELETE FROM member_record_metadata", [])
        .unwrap();
    selection::record_metadata(&mut source, &mut destination, &principal, &shape_ids)
        .await
        .unwrap();
    assert_eq!(metadata_rows(&destination), root_expected);
    destination
        .execute("DELETE FROM records WHERE id=?", [KERNEL_ROOT_ID])
        .unwrap();
    // Duplicate ids retain the first physical row's type/kind and the same
    // eventual closure refusal, even when a later duplicate has an invalid type.
    destination.execute_batch("DELETE FROM member_record_metadata; INSERT INTO records(id,type,kind) VALUES ('person:member',123,NULL)").unwrap();
    baseline_record_metadata(&mut source, &mut destination, &principal, &shape_ids)
        .await
        .unwrap();
    let duplicate_expected = metadata_rows(&destination);
    destination
        .execute("DELETE FROM member_record_metadata", [])
        .unwrap();
    selection::record_metadata(&mut source, &mut destination, &principal, &shape_ids)
        .await
        .unwrap();
    assert_eq!(metadata_rows(&destination), duplicate_expected);
    assert_eq!(validate_closure(&destination), Err(Refusal::Content));
    // A failed commit must also leave no partially publishable metadata.
    destination
        .execute("DELETE FROM member_record_metadata", [])
        .unwrap();
    destination.commit_hook(Some(|| true));
    assert_eq!(
        selection::record_metadata(&mut source, &mut destination, &principal, &shape_ids).await,
        Err(Refusal::Storage)
    );
    destination.commit_hook(None::<fn() -> bool>);
    assert!(destination.is_autocommit());
    assert!(metadata_rows(&destination).is_empty());
    // Cancellation after at least one insert, while a later source await is
    // pending. No timers, racing writer, or changes to source authority.
    destination
        .execute("DELETE FROM member_record_metadata", [])
        .unwrap();
    let inserts = Arc::new(AtomicUsize::new(0));
    let observed = inserts.clone();
    destination.update_hook(Some(move |action, _: &str, table: &str, _: i64| {
        if action == rusqlite::hooks::Action::SQLITE_INSERT && table == "member_record_metadata" {
            observed.fetch_add(1, Ordering::SeqCst);
        }
    }));
    let mut future = Box::pin(selection::record_metadata(
        &mut source,
        &mut destination,
        &principal,
        &shape_ids,
    ));
    std::future::poll_fn(|cx| {
        let state = future.as_mut().poll(cx);
        assert!(state.is_pending(), "must cancel inside a source await");
        if inserts.load(Ordering::SeqCst) > 0 {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    })
    .await;
    drop(future);
    assert!(destination.is_autocommit());
    assert!(metadata_rows(&destination).is_empty());
    // The producer's cleanup-on-drop builder still owns the unpublished file.
    let owned_path = produced.builder._file.path().to_owned();
    drop(produced);
    assert!(!owned_path.exists());
    sqlx::query("ROLLBACK").execute(&mut *source).await.unwrap();
    drop(source);
    db.close().await;
}
