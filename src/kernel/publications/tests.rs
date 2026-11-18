use super::*;
use serde_json::json;

struct World {
    db: Db,
    admin: String,
    manager: String,
    editor: String,
    record: String,
}
impl World {
    async fn new() -> Self {
        let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
            .await
            .unwrap();
        let manager = create_principal(&db, "account", "Manager", "test:manager", &admin)
            .await
            .unwrap();
        let editor = create_principal(&db, "account", "Editor", "test:editor", &admin)
            .await
            .unwrap();
        replace_home_policy(
            &db,
            &admin,
            KERNEL_ROOT_ID,
            &[(&admin, "manage"), (&manager, "manage"), (&editor, "edit")],
        )
        .await
        .unwrap();
        let package = crate::v2_standard::document4_package();
        let installed = install_package_as(&db, &admin, &package).await.unwrap();
        adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &package, Some(&installed), &[])
            .await
            .unwrap();
        let record = create_json_as(
            &db,
            &admin,
            "native.standard.document",
            "note",
            r#"{"title":"Public title","body":"Saved **body**"}"#,
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
        Self {
            db,
            admin,
            manager,
            editor,
            record,
        }
    }
    async fn request(&self, action: PublicationAction, key: &str) -> PublicationRequest {
        PublicationRequest {
            record_id: self.record.clone(),
            action,
            expected_revision: read_record_as(&self.db, &self.admin, &self.record)
                .await
                .unwrap()
                .unwrap()
                .revision,
            expected_publication_version: inspect_as(&self.db, &self.admin, &self.record)
                .await
                .unwrap()
                .map(|s| s.version),
            operation_key: key.into(),
        }
    }
    async fn publish(&self, key: &str) -> PublicationReceipt {
        change_as(
            &self.db,
            &self.manager,
            self.request(PublicationAction::Publish, key).await,
        )
        .await
        .unwrap()
    }
    async fn document(&self, id: &str) -> PublicDocument {
        match read_public(&self.db, id).await.unwrap() {
            PublicRead::Available(v) => v,
            other => panic!("{other:?}"),
        }
    }
    async fn head(&self) -> i64 {
        read_record_as(&self.db, &self.admin, &self.record)
            .await
            .unwrap()
            .unwrap()
            .revision
    }
}

#[tokio::test]
async fn manage_delegation_retry_conflicts_revoke_and_republish() {
    let w = World::new().await;
    assert_eq!(
        read_public(&w.db, &w.record).await.unwrap(),
        PublicRead::Unavailable
    );
    assert_eq!(
        read_public(&w.db, &"a".repeat(32)).await.unwrap(),
        PublicRead::Unavailable
    );
    let req = w.request(PublicationAction::Publish, "publish").await;
    assert_eq!(
        receipt_for_request_as(&w.db, &w.manager, &req)
            .await
            .unwrap(),
        None
    );
    assert!(receipt_for_request_as(&w.db, &w.editor, &req)
        .await
        .is_err());
    let before = projection_dump::dump(&w.db).await.unwrap();
    assert!(change_as(&w.db, &w.editor, req.clone()).await.is_err());
    assert!(inspect_as(&w.db, &w.editor, &w.record).await.is_err());
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), before);
    let receipt = change_as(&w.db, &w.manager, req.clone()).await.unwrap();
    assert_eq!(
        receipt_for_request_as(&w.db, &w.manager, &req)
            .await
            .unwrap(),
        Some(receipt.clone())
    );
    assert_eq!(
        change_as(&w.db, &w.manager, req.clone()).await.unwrap(),
        receipt
    );
    assert_ne!(receipt.state.public_id, w.record.replace('-', ""));
    assert_eq!(
        w.document(&receipt.state.public_id).await.body,
        "Saved **body**"
    );
    let mut collision = req.clone();
    collision.expected_revision += 1;
    assert!(receipt_for_request_as(&w.db, &w.manager, &collision)
        .await
        .is_err());
    assert!(change_as(&w.db, &w.manager, collision).await.is_err());
    let mut stale = w
        .request(
            PublicationAction::Revoke {
                public_id: receipt.state.public_id.clone(),
            },
            "revoke",
        )
        .await;
    stale.expected_publication_version = None;
    assert!(change_as(&w.db, &w.manager, stale).await.is_err());
    let wrong = w
        .request(
            PublicationAction::Revoke {
                public_id: "b".repeat(32),
            },
            "wrong",
        )
        .await;
    assert!(change_as(&w.db, &w.manager, wrong).await.is_err());
    let revoke = w
        .request(
            PublicationAction::Revoke {
                public_id: receipt.state.public_id.clone(),
            },
            "revoke",
        )
        .await;
    let revoked = change_as(&w.db, &w.manager, revoke.clone()).await.unwrap();
    assert!(!revoked.state.active);
    assert_eq!(change_as(&w.db, &w.manager, revoke).await.unwrap(), revoked);
    assert_eq!(
        change_as(&w.db, &w.manager, req.clone()).await.unwrap(),
        receipt
    );
    assert_eq!(
        read_public(&w.db, &receipt.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
    let new = w.publish("republish").await;
    assert_ne!(new.state.public_id, receipt.state.public_id);
    assert_eq!(
        receipt_for_request_as(&w.db, &w.manager, &req)
            .await
            .unwrap(),
        Some(receipt.clone())
    );
    assert_eq!(
        read_public(&w.db, &receipt.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
    let before = projection_dump::dump(&w.db).await.unwrap();
    replay_all_projections(&w.db).await.unwrap();
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), before);
    assert!(change_as(
        &w.db,
        &w.manager,
        w.request(PublicationAction::Publish, "republish").await
    )
    .await
    .is_err()); // changed request cannot reuse key
}

#[tokio::test]
async fn live_title_body_one_snapshot_and_no_uncommitted_or_asset_projection() {
    let w = World::new().await;
    let publication = w.publish("publish").await;
    let first = w.document(&publication.state.public_id).await;
    let stale = w
        .request(
            PublicationAction::Revoke {
                public_id: publication.state.public_id.clone(),
            },
            "stale-source",
        )
        .await;
    revise_json_as_expected(
        &w.db,
        &w.editor,
        &w.record,
        r#"{"title":"New title"}"#,
        Some(w.head().await),
    )
    .await
    .unwrap();
    assert!(change_as(&w.db, &w.manager, stale).await.is_err());
    let titled = w.document(&publication.state.public_id).await;
    assert_eq!(titled.title, "New title");
    assert_eq!(titled.body, first.body);
    assert_ne!(titled.version, first.version);
    assert_eq!(titled.body_sha256, first.body_sha256);
    let body = "Live 😀 ![private](blob:sha256:deadbeef) [private record](native:secret)";
    hq::set_body_as(&w.db, &w.editor, &w.record, body, w.head().await)
        .await
        .unwrap();
    let live = w.document(&publication.state.public_id).await;
    assert_eq!(live.body, body);
    assert_ne!(live.version, titled.version);
    assert_eq!(
        live.body_sha256,
        format!("{:x}", Sha256::digest(body.as_bytes()))
    );
    let mut keys = serde_json::to_value(&live)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    keys.sort();
    assert_eq!(
        keys,
        vec!["body", "body_sha256", "format", "title", "version"]
    );
    // Real write transaction: the uncommitted folded body must remain invisible.
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        &w.db,
        &mut tx,
        AppendSpec {
            record_id: w.record.clone(),
            event_type: "kernel.body_set.v1".into(),
            payload: json!({"body":"Uncommitted"}),
            actor: Some(w.admin.clone()),
        },
        &mut acts,
    )
    .await
    .unwrap();
    assert_eq!(w.document(&publication.state.public_id).await, live);
    tx.rollback().await.unwrap();
    // Removing the publisher's grant does not revoke a record publication.
    replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[(&w.admin, "manage")])
        .await
        .unwrap();
    assert_eq!(w.document(&publication.state.public_id).await, live);
}

#[tokio::test]
async fn archive_restore_and_delete_restore_never_revive_id() {
    let w = World::new().await;
    let p = w.publish("publish").await;
    hq::set_archived_as(&w.db, &w.admin, &w.record, true, w.head().await)
        .await
        .unwrap();
    assert_eq!(
        read_public(&w.db, &p.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
    hq::set_archived_as(&w.db, &w.admin, &w.record, false, w.head().await)
        .await
        .unwrap();
    assert_eq!(
        read_public(&w.db, &p.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
    let invalidated = projection_dump::dump(&w.db).await.unwrap();
    // Rewind just this derived authority row to the verified pre-archive base;
    // tail folding both archive and restore must retain the invalidation.
    sqlx::query("UPDATE kernel_publications SET active=1,event_seq=? WHERE public_id=?")
        .bind(p.event_seq)
        .bind(&p.state.public_id)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let mut tail = begin_write(w.db.write_pool()).await.unwrap();
    replay_projection_tail_on(&mut tail, p.event_seq, i64::MAX)
        .await
        .unwrap();
    tail.commit().await.unwrap();
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), invalidated);
    let second = w.publish("again").await;
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        &w.db,
        &mut tx,
        AppendSpec {
            record_id: w.record.clone(),
            event_type: deletion::EVENT.into(),
            payload: json!({"reason":"Test deletion","previous_seq":w.head().await}),
            actor: Some(w.admin.clone()),
        },
        &mut acts,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        read_public(&w.db, &second.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
    // No ordinary restore command exists. The import path also refuses to
    // restore a tombstoned native identity; archive restoration above is live.
    let before = projection_dump::dump(&w.db).await.unwrap();
    replay_all_projections(&w.db).await.unwrap();
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), before);
    assert_eq!(
        read_public(&w.db, &p.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
    assert_eq!(
        read_public(&w.db, &second.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
}

#[tokio::test]
async fn preparation_tail_fold_unknown_version_and_sealed_append() {
    let w = World::new().await;
    let p = w.publish("publish").await;
    assert!(crate::store::append(
        &w.db,
        AppendSpec {
            record_id: w.record.clone(),
            event_type: EVENT.into(),
            payload: json!({}),
            actor: Some(w.admin.clone())
        }
    )
    .await
    .is_err());
    let before = projection_dump::dump(&w.db).await.unwrap();
    sqlx::query("DROP TABLE kernel_publication_receipts")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    sqlx::query("DROP TABLE kernel_publications")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(verify_v2_ready(&w.db).await.is_err());
    assert!(read_public(&w.db, &p.state.public_id).await.is_err());
    prepare_v2_database(&w.db).await.unwrap();
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), before);
    // Tail replay from just before the publication, retaining its base state.
    sqlx::query("DELETE FROM kernel_publication_receipts")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM kernel_publications")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    replay_projection_tail_on(&mut tx, p.event_seq - 1, i64::MAX)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), before);
    assert_eq!(w.document(&p.state.public_id).await.title, "Public title");
    // Future event versions refuse readiness/admission, never disappear.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,actor,causal_envelope_version,causal_status) VALUES(?,?,'kernel.publication_changed.v999','{}','2026-10-29T00:00:00Z',?,1,'complete')").bind(Uuid::new_v4().to_string()).bind(&w.record).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
    assert!(verify_v2_ready(&w.db).await.is_err());
    assert!(read_public(&w.db, &p.state.public_id).await.is_err());
}

#[tokio::test]
async fn imported_lifecycle_deltas_and_tombstones_preserve_invalidation() {
    let w = World::new().await;
    let importer = resolve_principal_by_binding(&w.db, HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let record = Uuid::new_v4().to_string();
    let mut state = hq::ImportRecordState {
        body: Some("Imported".into()),
        ..Default::default()
    };
    hq::import_record_as(
        &w.db,
        &importer,
        &record,
        KERNEL_ROOT_ID,
        Some(&w.admin),
        &state,
    )
    .await
    .unwrap();
    let publish = |revision, version, key: &str| PublicationRequest {
        record_id: record.clone(),
        action: PublicationAction::Publish,
        expected_revision: revision,
        expected_publication_version: version,
        operation_key: key.into(),
    };
    let revision = read_record_as(&w.db, &w.admin, &record)
        .await
        .unwrap()
        .unwrap()
        .revision;
    let p = change_as(&w.db, &w.manager, publish(revision, None, "imported"))
        .await
        .unwrap();
    state.archived = true;
    hq::resume_record_with_blob_as(
        &w.db,
        &importer,
        &record,
        KERNEL_ROOT_ID,
        Some(&w.admin),
        &state,
        None,
    )
    .await
    .unwrap();
    state.archived = false;
    hq::resume_record_with_blob_as(
        &w.db,
        &importer,
        &record,
        KERNEL_ROOT_ID,
        Some(&w.admin),
        &state,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        read_public(&w.db, &p.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
    let revision = read_record_as(&w.db, &w.admin, &record)
        .await
        .unwrap()
        .unwrap()
        .revision;
    let version = inspect_as(&w.db, &w.admin, &record)
        .await
        .unwrap()
        .unwrap()
        .version;
    let second = change_as(
        &w.db,
        &w.manager,
        publish(revision, Some(version), "imported-again"),
    )
    .await
    .unwrap();
    hq::import_removal_as(
        &w.db,
        &importer,
        &record,
        hq::ImportedRemovalKind::Record,
        &hq::ImportRemovalEvidence {
            source_origin: "test".into(),
            snapshot: "test".into(),
            reason: "source deleted".into(),
            deleted_at: Some("2026-10-29T00:00:00Z".into()),
            source_event: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        read_public(&w.db, &second.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
    // Existing canonical import policy requires review rather than resurrecting
    // the identity. No restore exception is introduced for publication.
    assert!(hq::resume_record_with_blob_as(
        &w.db,
        &importer,
        &record,
        KERNEL_ROOT_ID,
        Some(&w.admin),
        &state,
        None
    )
    .await
    .is_err());
    let before = projection_dump::dump(&w.db).await.unwrap();
    replay_all_projections(&w.db).await.unwrap();
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), before);
    assert_eq!(
        read_public(&w.db, &second.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
}

#[tokio::test]
async fn unsupported_formats_wrong_birth_and_failed_commit_expose_nothing() {
    let w = World::new().await;
    // Artifact/program carriers cannot gain public body access or blob access.
    let package = crate::v2_standard::v1_compat::package();
    let installed = install_package_as(&w.db, &w.admin, &package).await.unwrap();
    adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &[],
    )
    .await
    .unwrap();
    for (typ, kind) in [
        ("Document", "artifact"),
        ("Document", "attachment"),
        ("Program", "app"),
        ("Collection", "folder"),
        ("Annotation", "comment"),
    ] {
        let record = create_json_as(
            &w.db,
            &w.admin,
            "native.v1.record",
            "record",
            &json!({"title":"Secret","v1_type":typ,"v1_kind":kind}).to_string(),
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
        let revision: i64 =
            sqlx::query_scalar("SELECT max(seq) FROM content_events WHERE record_id=?")
                .bind(&record)
                .fetch_one(w.db.pool())
                .await
                .unwrap();
        assert!(change_as(
            &w.db,
            &w.admin,
            PublicationRequest {
                record_id: record,
                action: PublicationAction::Publish,
                expected_revision: revision,
                expected_publication_version: None,
                operation_key: kind.into(),
            }
        )
        .await
        .is_err());
    }
    // A fold/storage failure rolls back both publication and receipt/act.
    sqlx::query("CREATE TRIGGER refuse_publication_receipt BEFORE INSERT ON kernel_publication_receipts BEGIN SELECT RAISE(ABORT,'test refusal'); END").execute(w.db.write_pool()).await.unwrap();
    let before = projection_dump::dump(&w.db).await.unwrap();
    let log_before: (i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM content_events),(SELECT next_act FROM act_state WHERE singleton=1)").fetch_one(w.db.pool()).await.unwrap();
    let request = w.request(PublicationAction::Publish, "failed").await;
    assert!(change_as(&w.db, &w.manager, request.clone()).await.is_err());
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), before);
    let log_after: (i64,i64)=sqlx::query_as("SELECT (SELECT count(*) FROM content_events),(SELECT next_act FROM act_state WHERE singleton=1)").fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(log_after, log_before);
    sqlx::query("DROP TRIGGER refuse_publication_receipt")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let p = change_as(&w.db, &w.manager, request).await.unwrap();
    // Corrupt routing/birth evidence fails closed, including an ID rebound to
    // another database birth. Projection repair reconstructs the canonical row.
    sqlx::query("UPDATE kernel_publications SET database_birth='wrong' WHERE public_id=?")
        .bind(&p.state.public_id)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert_eq!(
        read_public(&w.db, &p.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
    replay_all_projections(&w.db).await.unwrap();
    assert_eq!(w.document(&p.state.public_id).await.title, "Public title");
    sqlx::query("UPDATE kernel_publications SET record_birth='wrong' WHERE public_id=?")
        .bind(&p.state.public_id)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert_eq!(
        read_public(&w.db, &p.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn canonical_read_only_handles_refuse_public_admission_and_mutation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel.db");
    let path = path.to_str().unwrap();
    let (db, admin) = create_v2_database(path, "account", "Admin", "test:admin")
        .await
        .unwrap();
    let record = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
    let revision = read_record_as(&db, &admin, &record)
        .await
        .unwrap()
        .unwrap()
        .revision;
    let request = PublicationRequest {
        record_id: record,
        action: PublicationAction::Publish,
        expected_revision: revision,
        expected_publication_version: None,
        operation_key: "read-only".into(),
    };
    let p = change_as(&db, &admin, request.clone()).await.unwrap();
    let read_only = crate::db::open_kernel_v2_standby_read_only(path)
        .await
        .unwrap();
    assert!(prepare_as(&read_only, &admin, &request.record_id)
        .await
        .is_err());
    assert!(receipt_for_request_as(&read_only, &admin, &request)
        .await
        .is_err());
    assert!(change_as(&read_only, &admin, request).await.is_err());
    assert!(read_public(&read_only, &p.state.public_id).await.is_err());
    read_only.close().await;
}

#[tokio::test]
async fn management_preparation_and_publish_enforce_the_same_committed_limits() {
    let w = World::new().await;
    let before = projection_dump::dump(&w.db).await.unwrap();
    assert!(prepare_as(&w.db, &w.editor, &w.record).await.is_err());
    let preview = prepare_as(&w.db, &w.manager, &w.record).await.unwrap();
    assert_eq!(preview.record_revision, w.head().await);
    assert_eq!(preview.publication, None);
    assert_eq!(preview.title, "Public title");
    assert_eq!(preview.body, "Saved **body**");
    assert_eq!(
        preview.body_sha256,
        format!("{:x}", Sha256::digest(preview.body.as_bytes()))
    );
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), before);
    let stale = w.request(PublicationAction::Publish, "stale-preview").await;
    hq::set_body_as(
        &w.db,
        &w.editor,
        &w.record,
        &"x".repeat(BODY_MAX_BYTES + 1),
        preview.record_revision,
    )
    .await
    .unwrap();
    let before_refusal = projection_dump::dump(&w.db).await.unwrap();
    assert!(change_as(&w.db, &w.manager, stale).await.is_err());
    assert!(prepare_as(&w.db, &w.manager, &w.record)
        .await
        .unwrap_err()
        .to_string()
        .contains("public reader limits"));
    let oversized = w.request(PublicationAction::Publish, "oversized").await;
    assert!(change_as(&w.db, &w.manager, oversized)
        .await
        .unwrap_err()
        .to_string()
        .contains("public reader limits"));
    assert_eq!(
        inspect_as(&w.db, &w.manager, &w.record).await.unwrap(),
        None
    );
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), before_refusal);

    let boundary_body = "x".repeat(BODY_MAX_BYTES);
    let boundary_title = "t".repeat(TITLE_MAX_BYTES);
    revise_json_as_expected(
        &w.db,
        &w.editor,
        &w.record,
        &json!({"title": boundary_title}).to_string(),
        Some(w.head().await),
    )
    .await
    .unwrap();
    hq::set_body_as(&w.db, &w.editor, &w.record, &boundary_body, w.head().await)
        .await
        .unwrap();
    let prepared = prepare_as(&w.db, &w.manager, &w.record).await.unwrap();
    let published = change_as(
        &w.db,
        &w.manager,
        PublicationRequest {
            record_id: w.record.clone(),
            action: PublicationAction::Publish,
            expected_revision: prepared.record_revision,
            expected_publication_version: prepared.publication.map(|state| state.version),
            operation_key: "reviewed-publish".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(
        w.document(&published.state.public_id).await.body,
        prepared.body
    );
    assert_eq!(prepared.body, boundary_body);
    assert_eq!(
        w.document(&published.state.public_id).await.title,
        boundary_title
    );
    let title_refusal = revise_json_as_expected(
        &w.db,
        &w.editor,
        &w.record,
        &json!({"title": "t".repeat(TITLE_MAX_BYTES + 1)}).to_string(),
        Some(w.head().await),
    )
    .await
    .unwrap_err();
    assert!(title_refusal.to_string().contains("limit_exceeded"));
    hq::set_body_as(
        &w.db,
        &w.editor,
        &w.record,
        &"x".repeat(BODY_MAX_BYTES + 1),
        w.head().await,
    )
    .await
    .unwrap();
    assert!(prepare_as(&w.db, &w.manager, &w.record).await.is_err());
    assert_eq!(
        read_public(&w.db, &published.state.public_id)
            .await
            .unwrap(),
        PublicRead::Unavailable
    );
    let revoke = w
        .request(
            PublicationAction::Revoke {
                public_id: published.state.public_id.clone(),
            },
            "withdraw-over-limit",
        )
        .await;
    assert!(
        !change_as(&w.db, &w.manager, revoke)
            .await
            .unwrap()
            .state
            .active
    );
}

#[tokio::test]
async fn oversized_saved_body_is_unavailable_without_an_asset_or_metadata_fallback() {
    let w = World::new().await;
    let p = w.publish("publish").await;
    hq::set_body_as(
        &w.db,
        &w.admin,
        &w.record,
        &"x".repeat(4 * 1024 * 1024 + 1),
        w.head().await,
    )
    .await
    .unwrap();
    assert_eq!(
        read_public(&w.db, &p.state.public_id).await.unwrap(),
        PublicRead::Unavailable
    );
    hq::set_body_as(
        &w.db,
        &w.admin,
        &w.record,
        "Back within bounds",
        w.head().await,
    )
    .await
    .unwrap();
    assert_eq!(
        w.document(&p.state.public_id).await.body,
        "Back within bounds"
    );
}

#[tokio::test]
async fn legacy_request_replay_and_inspection_snapshot() {
    let w = World::new().await;
    let request = w.request(PublicationAction::Publish, "legacy").await;
    let raw = serde_json::to_string(&request).unwrap();
    assert!(!raw.contains("reason"));
    let old: PublicationRequest = serde_json::from_str(&raw).unwrap();
    assert_eq!(serde_json::to_string(&old).unwrap(), raw);
    let mut unknown: serde_json::Value = serde_json::from_str(&raw).unwrap();
    unknown["reason"] = json!("unrecognized v1 field");
    assert!(serde_json::from_value::<PublicationRequest>(unknown).is_err());
    let published = change_as(&w.db, &w.manager, old.clone()).await.unwrap();
    let event: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
        .bind(&published.event_id)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert!(!event.contains("reason"));
    replay_all_projections(&w.db).await.unwrap();
    assert_eq!(change_as(&w.db, &w.manager, old).await.unwrap(), published);
    let (revision, state) = inspect_revision_as(&w.db, &w.manager, &w.record)
        .await
        .unwrap();
    assert_eq!(revision, published.event_seq);
    assert_eq!(state, Some(published.state.clone()));
}
