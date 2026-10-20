use super::*;
use crate::{
    events::KERNEL_ROOT_ID,
    mcp::{kernel_v2::tests::registry, registry::Caller},
};

struct World {
    _dir: tempfile::TempDir,
    db: Db,
    admin: String,
    viewer: String,
    home: String,
    private: String,
}
async fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("writes.db").to_str().unwrap(),
        "account",
        "Admin",
        "acct:admin",
    )
    .await
    .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
        .await
        .unwrap();
    for manifest in [
        v1_compat::package(),
        crate::v2_standard::document4_package(),
        relation::package(),
    ] {
        let identity = manifest.identity().unwrap();
        kernel::install_package_as(&db, &admin, &manifest)
            .await
            .unwrap();
        kernel::adopt_package_at(
            &db,
            &admin,
            KERNEL_ROOT_ID,
            &manifest,
            Some(&identity),
            &manifest.declared_reads,
        )
        .await
        .unwrap();
    }
    let home = kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(&admin, "manage"), (&viewer, "view")]),
        &admin,
    )
    .await
    .unwrap();
    let private = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    World {
        _dir: dir,
        db,
        admin,
        viewer,
        home,
        private,
    }
}
async fn call(w: &World, credential: &str, tool: &str, args: Value) -> Result<Value> {
    registry()
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            Caller::authenticated(credential),
            tool,
            args,
        )
        .await
}
async fn admin(w: &World, tool: &str, args: Value) -> Value {
    call(w, "acct:admin", tool, args).await.unwrap()
}
async fn count(w: &World) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap()
}
async fn record(w: &World, id: &str) -> kernel::KernelRecordView {
    kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn registry_create_update_body_facets_archive_and_links() {
    let w = world().await;
    let note = admin(&w,"create_record",json!({"type":"Document","kind":"note","name":"Note","body":"Note body","home_id":w.home,"reason":"fixture"})).await;
    let note_id = note["id"].as_str().unwrap();
    let create_args = json!({"type":"WorkItem","kind":"task","name":"Task","summary":"Summary","lifecycle":"open","body":"hello","facets":{"priority":"high"},"home_id":w.home,"links":[{"relationship":"relates_to","target_id":note_id,"note":"basis"}],"idempotency_key":"create-task","reason":"fixture"});
    let task = admin(&w, "create_record", create_args.clone()).await;
    let id = task["id"].as_str().unwrap();
    assert!(task["short_ref"]
        .as_str()
        .is_some_and(|reference| reference.len() >= 7));
    assert_eq!(
        admin(&w, "get_record", json!({"ids":[task["short_ref"]]})).await["records"][0]["id"],
        id
    );
    let created = record(&w, id).await;
    assert_eq!(created.family.as_deref(), Some(v1_compat::FAMILY));
    assert_eq!(created.fields["v1_type"], "WorkItem");
    assert_eq!(created.fields["v1_kind"], "task");
    assert!(!created.fields.contains_key("body"));
    assert_eq!(created.body.as_deref(), Some("hello"));
    assert_eq!(
        record(&w, note_id).await.family.as_deref(),
        Some(crate::v2_standard::DOCUMENT_FAMILY)
    );
    let before = count(&w).await;
    assert_eq!(admin(&w, "create_record", create_args).await, task);
    assert_eq!(count(&w).await, before);
    // All creation events, including relation outcome, share the kernel act.
    let acts: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT act) FROM content_events WHERE seq>= (SELECT MIN(seq) FROM content_events WHERE record_id=?)").bind(id).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(acts, 1);
    let read = admin(&w, "get_record", json!({"ids":[id]})).await;
    assert_eq!(read["records"][0]["body"], "hello");
    assert_eq!(read["records"][0]["body_digest"], task["body_digest"]);
    let updated = admin(&w,"update_record",json!({"id":id,"name":"Renamed","summary":"Changed","lifecycle":"in_progress","body_set":"one","if_body_digest":task["body_digest"],"facets":{"priority":null,"status":{"value":"active","as_of":"2026-10-01T00:00:00Z"}},"idempotency_key":"update-task","reason":"edit"})).await;
    assert_eq!(updated["previous_record_version"], task["record_version"]);
    assert_eq!(record(&w, id).await.fields["title"], "Renamed");
    assert_eq!(record(&w, id).await.fields["lifecycle"], "in_progress");
    let facets = kernel::facets_as(&w.db, &w.admin, id).await.unwrap();
    assert!(!facets.iter().any(|f| f.key == "priority"));
    assert!(facets
        .iter()
        .any(|f| f.key == "status" && f.value.as_deref() == Some("active")));
    admin(
        &w,
        "update_record",
        json!({"id":id,"body_append":" two","reason":"append"}),
    )
    .await;
    let replace_args = json!({"id":id,"body_replace":[{"old":"one","new":"three"}],"idempotency_key":"replace","reason":"targeted"});
    let replaced = admin(&w, "update_record", replace_args.clone()).await;
    assert_eq!(record(&w, id).await.body.as_deref(), Some("three two"));
    let before = count(&w).await;
    assert_eq!(admin(&w, "update_record", replace_args).await, replaced);
    assert_eq!(before, count(&w).await);
    admin(&w, "archive_record", json!({"id":id,"reason":"archive"})).await;
    assert!(record(&w, id).await.archived);
    admin(
        &w,
        "archive_record",
        json!({"id":id,"archived":false,"reason":"restore"}),
    )
    .await;
    assert!(!record(&w, id).await.archived);
    admin(
        &w,
        "update_record",
        json!({"id":note_id,"name":"Note renamed","body_append":"!","reason":"note edit"}),
    )
    .await;
    admin(
        &w,
        "archive_record",
        json!({"id":note_id,"reason":"archive note"}),
    )
    .await;
    assert!(record(&w, note_id).await.archived);
    assert_eq!(
        record(&w, note_id).await.body.as_deref(),
        Some("Note body!")
    );
    let listed = admin(&w, "manage_links", json!({"action":"list","record_id":id})).await;
    assert!(crate::mcp::render::render("manage_links", &listed)
        .unwrap()
        .contains("visible links"));
    assert!(crate::mcp::render::render("create_record", &task)
        .unwrap()
        .contains("Created"));
    assert_eq!(listed["links"][0]["relationship"], "relates_to");
    assert_eq!(listed["links"][0]["target_id"], note_id);
    let remove = json!({"action":"remove","source_id":id,"target_id":note_id,"relationship":"relates_to","idempotency_key":"unlink"});
    let counterpart_activity = record(&w, note_id).await.metadata;
    let removed = admin(&w, "manage_links", remove.clone()).await;
    let removed_activity = record(&w, id).await.metadata;
    let seq: i64 = sqlx::query_scalar("SELECT MAX(event_seq) FROM kernel_provider_receipts WHERE json_extract(request_json,'$.anchor.record_id')=?").bind(id).fetch_one(w.db.pool()).await.unwrap();
    let timestamp: String = sqlx::query_scalar("SELECT created_at FROM content_events WHERE seq=?")
        .bind(seq)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(removed_activity.last_activity_at, timestamp);
    assert_eq!(record(&w, note_id).await.metadata, counterpart_activity);
    let before = count(&w).await;
    assert_eq!(admin(&w, "manage_links", remove).await, removed);
    assert_eq!(before, count(&w).await);
    assert_eq!(record(&w, id).await.metadata, removed_activity);
    assert_eq!(
        admin(&w, "manage_links", json!({"action":"list","record_id":id})).await["links"],
        json!([])
    );
    let add = json!({"action":"add","source_id":id,"target_id":note_id,"relationship":"relates_to","idempotency_key":"relink"});
    let added = admin(&w, "manage_links", add.clone()).await;
    assert_eq!(added["changed"], true);
    assert_eq!(added["write_receipt"]["kind"], "kernel_content_event");
    assert!(crate::mcp::render::render("manage_links", &added)
        .unwrap()
        .contains("committed"));
    let before = count(&w).await;
    assert_eq!(admin(&w, "manage_links", add).await, added);
    assert_eq!(before, count(&w).await);
    assert_eq!(
        admin(
            &w,
            "manage_links",
            json!({"action":"list","record_id":note_id})
        )
        .await["links"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let seq: i64 = sqlx::query_scalar("SELECT MAX(event_seq) FROM kernel_provider_receipts WHERE json_extract(request_json,'$.anchor.record_id')=?").bind(id).fetch_one(w.db.pool()).await.unwrap();
    let timestamp: String = sqlx::query_scalar("SELECT created_at FROM content_events WHERE seq=?")
        .bind(seq)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(record(&w, id).await.metadata.last_activity_at, timestamp);
    assert_eq!(record(&w, note_id).await.metadata, counterpart_activity);
    let expected = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    sqlx::query("DROP TABLE kernel_record_metadata")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    kernel::ensure_record_metadata(&w.db).await.unwrap();
    assert_eq!(
        kernel::dump_all_kernel_tables(&w.db).await.unwrap(),
        expected
    );
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        kernel::dump_all_kernel_tables(&w.db).await.unwrap(),
        expected
    );
    w.db.close().await;
}

#[tokio::test]
async fn registry_guards_atomic_failures_and_hidden_edit_refusals() {
    let w = world().await;
    let task = admin(&w,"create_record",json!({"type":"WorkItem","kind":"task","name":"Task","body":"original","home_id":w.home,"reason":"fixture"})).await;
    let secret = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","home_id":w.private,"reason":"fixture"}),
    )
    .await;
    let id = task["id"].as_str().unwrap();
    for args in [
        json!({"id":id,"name":"must roll back","body_set":"lost","if_body_digest":"bad","reason":"stale"}),
        json!({"id":id,"body_append":"lost","if_unmodified_since":"2000-01-01T00:00:00Z","reason":"stale"}),
        json!({"id":id,"body_set":"unguarded","reason":"unguarded"}),
        json!({"id":id,"body_replace":[{"old":"absent","new":"lost"}],"reason":"match"}),
        json!({"id":id,"name":"must roll back","body_append":"lost","links":[{"relationship":"blocks","target_id":"missing"}],"reason":"missing link target"}),
        json!({"id":id,"name":"must roll back","body_append":"lost","facets":{"key":{"value":"x","as_of":"invalid"}},"reason":"facet"}),
    ] {
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        assert!(call(&w, "acct:admin", "update_record", args).await.is_err());
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    assert_eq!(record(&w, id).await.body.as_deref(), Some("original"));
    for args in [
        json!({"type":"WorkItem","kind":"task","name":"bad","body":"text","links":[{"relationship":"relates_to","target_id":"missing"}],"reason":"bad"}),
        json!({"type":"Document","kind":"note","summary":42,"reason":"bad"}),
    ] {
        let before = count(&w).await;
        assert!(call(&w, "acct:admin", "create_record", args).await.is_err());
        assert_eq!(before, count(&w).await);
    }
    let error = Error::engine(kernel::HIDDEN_OR_MISSING).to_string();
    for target in [id, secret["id"].as_str().unwrap(), "missing"] {
        let before = count(&w).await;
        assert_eq!(
            call(
                &w,
                "acct:viewer",
                "update_record",
                json!({"id":target,"name":"denied","reason":"denied"})
            )
            .await
            .unwrap_err()
            .to_string(),
            error
        );
        assert_eq!(before, count(&w).await);
    }
    assert_eq!(
        call(
            &w,
            "acct:viewer",
            "create_record",
            json!({"type":"WorkItem","kind":"task","home_id":w.home,"reason":"denied"})
        )
        .await
        .unwrap_err()
        .to_string(),
        error
    );
    assert_eq!(call(&w,"acct:viewer","manage_links",json!({"action":"add","source_id":id,"target_id":secret["id"],"relationship":"relates_to"})).await.unwrap_err().to_string(),error);
    // Free-form names share endpoint authorization and atomic rollback.
    for relationship in [
        "part_of",
        "derived_from",
        "draws_from",
        "member_of",
        "depends_on",
        "supersedes",
    ] {
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        for action in ["add", "remove"] {
            let error = call(&w,"acct:viewer","manage_links",json!({"action":action,"source_id":id,"target_id":secret["id"],"relationship":relationship})).await.unwrap_err();
            assert!(
                error.to_string().contains(kernel::HIDDEN_OR_MISSING),
                "{error}"
            );
        }
        let error = call(&w,"acct:admin","create_record",json!({"type":"WorkItem","kind":"task","body":"must roll back","links":[{"target_id":"missing","relationship":relationship}],"reason":"missing link target"})).await.unwrap_err();
        assert!(
            error.to_string().contains(kernel::HIDDEN_OR_MISSING),
            "{error}"
        );
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    let args = json!({"id":id,"body_append":"!","idempotency_key":"durable","reason":"retry"});
    let first = admin(&w, "update_record", args.clone()).await;
    // A later operation cannot change the original replay result.
    admin(
        &w,
        "update_record",
        json!({"id":id,"body_append":"?","reason":"later"}),
    )
    .await;
    let before = count(&w).await;
    assert_eq!(admin(&w, "update_record", args.clone()).await, first);
    assert_eq!(before, count(&w).await);
    let reordered = Value::Object(
        args.as_object()
            .unwrap()
            .iter()
            .rev()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    );
    assert_eq!(admin(&w, "update_record", reordered).await, first);
    let mut different = args;
    different["body_append"] = json!("different");
    assert!(call(&w, "acct:admin", "update_record", different)
        .await
        .unwrap_err()
        .to_string()
        .contains("idempotency_key reused"));
    assert_ne!(w.admin, w.viewer);
    w.db.close().await;
}

#[tokio::test]
async fn registry_concurrent_retries_commit_once_and_receipt_survives_reopen() {
    let w = world().await;
    let args = json!({"type":"WorkItem","kind":"task","body":"once","idempotency_key":"concurrent","reason":"retry"});
    let before = count(&w).await;
    let (a, b) = tokio::join!(
        call(&w, "acct:admin", "create_record", args.clone()),
        call(&w, "acct:admin", "create_record", args.clone())
    );
    let a = a.unwrap();
    assert_eq!(a, b.unwrap());
    assert_eq!(count(&w).await, before + 2);
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(admin(&w, "create_record", args.clone()).await, a);
    let path = w._dir.path().join("writes.db");
    w.db.close().await;
    let db = crate::db::open_database(path.to_str().unwrap())
        .await
        .unwrap();
    let replay = registry()
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("acct:admin"),
            "create_record",
            args,
        )
        .await
        .unwrap();
    assert_eq!(a, replay);
    db.close().await;
}

#[tokio::test]
async fn registry_receipt_failure_rolls_back_and_replay_rechecks_access() {
    let w = world().await;
    let args = json!({"type":"WorkItem","kind":"task","home_id":w.home,"idempotency_key":"scoped","reason":"fixture"});
    let first = admin(&w, "create_record", args.clone()).await;
    // A second principal can use the same operation key for their own write.
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    let second = call(&w, "acct:viewer", "create_record", args.clone())
        .await
        .unwrap();
    assert_ne!(first["id"], second["id"]);
    // Receipt failure must roll back the events as well as the projection.
    sqlx::query("CREATE TRIGGER fail_mcp_receipt BEFORE INSERT ON kernel_mcp_write_receipts BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END").execute(w.db.write_pool()).await.unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let fail = json!({"id":first["id"],"body_append":"lost","idempotency_key":"fail-receipt","reason":"fixture"});
    assert!(call(&w, "acct:admin", "update_record", fail).await.is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    sqlx::query("DROP TRIGGER fail_mcp_receipt")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    // Revocation on a record not owned by the viewer blocks keyed replay.
    let edit = json!({"id":first["id"],"body_append":"ok","idempotency_key":"viewer-edit","reason":"fixture"});
    call(&w, "acct:viewer", "update_record", edit.clone())
        .await
        .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "view")],
    )
    .await
    .unwrap();
    let before = count(&w).await;
    assert_eq!(
        call(&w, "acct:viewer", "update_record", edit)
            .await
            .unwrap_err()
            .to_string(),
        Error::engine(kernel::HIDDEN_OR_MISSING).to_string()
    );
    assert_eq!(count(&w).await, before);
    w.db.close().await;
}

#[tokio::test]
async fn registry_archive_round_trip_is_independent_of_lifecycle() {
    let w = world().await;
    let task = admin(&w,"create_record",json!({"type":"WorkItem","kind":"task","lifecycle":"open","home_id":w.home,"reason":"fixture"})).await;
    let id = task["id"].as_str().unwrap();
    let previous_revision = record(&w, id).await.revision;
    let args = json!({"id":id,"reason":"archive","idempotency_key":"archive-task"});
    let archived = admin(&w, "archive_record", args.clone()).await;
    assert_eq!(archived["changed"], true);
    assert_eq!(archived["archived"], true);
    assert_eq!(archived["previous_seq"], previous_revision);
    // The registry withholds workspace act counters from unhosted callers;
    // confirm the committed event has an act without bypassing that fence.
    assert!(archived.get("act").is_none());
    let stored_act: Option<i64> = sqlx::query_scalar(
        "SELECT act FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(id)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert!(stored_act.is_some());
    assert_eq!(record(&w, id).await.fields["lifecycle"], "open");
    let before = count(&w).await;
    assert_eq!(admin(&w, "archive_record", args).await, archived);
    assert_eq!(before, count(&w).await);
    let unchanged = admin(
        &w,
        "archive_record",
        json!({"id":id,"reason":"already archived"}),
    )
    .await;
    assert_eq!(unchanged["changed"], false);
    assert!(unchanged.get("act").is_none());
    assert_eq!(before, count(&w).await);
    let before = count(&w).await;
    admin(
        &w,
        "update_record",
        json!({"id":id,"lifecycle":"completed","reason":"complete"}),
    )
    .await;
    assert_eq!(
        count(&w).await,
        before + 1,
        "a lifecycle edit emits only its field revision"
    );
    assert!(record(&w, id).await.archived);
    assert_eq!(record(&w, id).await.fields["lifecycle"], "completed");
    let restore = admin(
        &w,
        "archive_record",
        json!({"id":id,"archived":false,"reason":"restore"}),
    )
    .await;
    assert_eq!(restore["changed"], true);
    assert!(!record(&w, id).await.archived);
    assert_eq!(record(&w, id).await.fields["lifecycle"], "completed");
    let noop_args = json!({"id":id,"archived":false,"reason":"already restored","idempotency_key":"restore-noop"});
    let before = count(&w).await;
    let noop = admin(&w, "archive_record", noop_args.clone()).await;
    let mut operation_receipt = noop.clone();
    operation_receipt
        .as_object_mut()
        .unwrap()
        .remove("run_context");
    assert_eq!(
        operation_receipt,
        json!({"id":id,"archived":false,"changed":false})
    );
    assert_eq!(before, count(&w).await);
    admin(
        &w,
        "archive_record",
        json!({"id":id,"reason":"archive again"}),
    )
    .await;
    let before = count(&w).await;
    assert_eq!(admin(&w, "archive_record", noop_args).await, noop);
    assert_eq!(before, count(&w).await);
    assert!(record(&w, id).await.archived);
    // The reserved facet refuses both sets and unsets with v1's exact guidance.
    for value in [
        Value::Null,
        json!(true),
        json!(false),
        json!("true"),
        json!({"value":"true"}),
    ] {
        for tool in ["create_record", "update_record"] {
            let mut args = if tool == "create_record" {
                json!({"type":"WorkItem","kind":"task","reason":"invalid"})
            } else {
                json!({"id":id,"name":"must not change","reason":"invalid"})
            };
            args["facets"] = json!({"archived":value});
            let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
            let err = call(&w, "acct:admin", tool, args).await.unwrap_err();
            assert_eq!(err.to_string(),Error::engine(format!("{tool}: facet 'archived' is engine-reserved — archive and restore via the archive_record tool")).to_string());
            assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
        }
    }
    for args in [
        json!({"id":id,"lifecycle":"archived","reason":"invalid"}),
        json!({"id":id,"reason":""}),
    ] {
        let tool = if args.get("lifecycle").is_some() {
            "update_record"
        } else {
            "archive_record"
        };
        let before = count(&w).await;
        assert!(call(&w, "acct:admin", tool, args).await.is_err());
        assert_eq!(before, count(&w).await);
    }
    let before = count(&w).await;
    assert!(call(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"WorkItem","kind":"task","lifecycle":"archived","reason":"invalid"})
    )
    .await
    .is_err());
    assert_eq!(before, count(&w).await);
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    for target in [id, "missing"] {
        assert_eq!(
            call(
                &w,
                "acct:viewer",
                "archive_record",
                json!({"id":target,"reason":"requires Manage"})
            )
            .await
            .unwrap_err()
            .to_string(),
            Error::engine(kernel::HIDDEN_OR_MISSING).to_string()
        );
    }
    let viewer_archive = json!({"id":id,"archived":false,"reason":"keyed access check","idempotency_key":"viewer-restore"});
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "manage")],
    )
    .await
    .unwrap();
    call(&w, "acct:viewer", "archive_record", viewer_archive.clone())
        .await
        .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    assert!(call(&w, "acct:viewer", "archive_record", viewer_archive)
        .await
        .is_err());
    // Compare the actual v1 operation shape for archive, repeated archive,
    // restore and repeated restore; archived:false is the restore operation.
    let v1 = crate::create_database(":memory:").await.unwrap();
    let legacy = registry()
        .call(
            v1.clone(),
            Caller::local(),
            "create_record",
            json!({"type":"Document","kind":"note","reason":"parity fixture"}),
        )
        .await
        .unwrap();
    let note = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","reason":"parity fixture"}),
    )
    .await;
    for state in [true, true, false, false] {
        let old = registry()
            .call(
                v1.clone(),
                Caller::local(),
                "archive_record",
                json!({"id":legacy["id"],"archived":state,"reason":"parity"}),
            )
            .await
            .unwrap();
        let new = admin(
            &w,
            "archive_record",
            json!({"id":note["id"],"archived":state,"reason":"parity"}),
        )
        .await;
        assert_eq!(old["changed"], new["changed"]);
        assert_eq!(old["archived"], new["archived"]);
        assert_eq!(
            old.get("previous_seq").is_some(),
            new.get("previous_seq").is_some()
        );
        // v1's local owner can see the act; the authenticated v2 caller cannot.
        assert_eq!(old.get("act").is_some(), old["changed"] == true);
        assert!(new.get("act").is_none());
        assert!(new.get("write_receipt").is_none());
    }
    v1.drain_captures().await;
    v1.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn registry_noops_preserve_revision_timestamp_and_do_not_claim_a_write() {
    let w = world().await;
    let task = admin(&w,"create_record",json!({"type":"WorkItem","kind":"task","name":"Same","summary":"same","lifecycle":"open","body":"hello","facets":{"priority":"high"},"reason":"fixture"})).await;
    let id = task["id"].as_str().unwrap();
    // There is a later global event that no-op receipts must not claim.
    admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","reason":"unrelated"}),
    )
    .await;
    for patch in [
        json!({"facets":{}}),
        json!({"links":[]}),
        json!({"name":"Same","summary":"same","lifecycle":"open"}),
        json!({"facets":{"priority":"high","missing":null}}),
        json!({"facets":{"priority":{"value":"obsolete","as_of":"2000-01-01T00:00:00Z"}}}),
        json!({"body_append":""}),
        json!({"body_replace":[{"old":"hello","new":"hello"}]}),
        json!({"body_set":"hello","if_body_digest":task["body_digest"]}),
    ] {
        let mut args = patch;
        args["id"] = json!(id);
        args["reason"] = json!("no-op");
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        let result = admin(&w, "update_record", args).await;
        assert_eq!(result["effect"], "unchanged");
        assert_eq!(result["changed"], false);
        assert_eq!(result["record_version"], task["record_version"]);
        assert_eq!(result["updated_at"], task["updated_at"]);
        assert!(result.get("act").is_none());
        assert!(result.get("write_receipt").is_none());
        let rendered = crate::mcp::render::render("update_record", &result).unwrap();
        assert!(
            rendered.contains("Unchanged") && rendered.contains("no write"),
            "{rendered}"
        );
        assert!(!rendered.contains("Effect: record updated"), "{rendered}");
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    let noop_args = json!({"id":id,"facets":{},"reason":"keyed no-op","idempotency_key":"noop"});
    let noop = admin(&w, "update_record", noop_args.clone()).await;
    let before = count(&w).await;
    let body = admin(&w,"update_record",json!({"id":id,"body_set":"next","if_unmodified_since":task["updated_at"],"reason":"timestamp still valid"})).await;
    assert_eq!(
        count(&w).await,
        before + 1,
        "body-only edit emits no empty field revision"
    );
    assert_eq!(body["changed"], true);
    let before = count(&w).await;
    assert_eq!(admin(&w, "update_record", noop_args).await, noop);
    assert_eq!(before, count(&w).await);
    let before = count(&w).await;
    admin(
        &w,
        "update_record",
        json!({"id":id,"facets":{"priority":"low"},"reason":"facet only"}),
    )
    .await;
    assert_eq!(
        count(&w).await,
        before + 1,
        "facet-only edit emits no empty field revision"
    );
    let before = count(&w).await;
    assert!(call(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":id,"name":"Same","if_body_digest":task["body_digest"],"reason":"stale no-op"})
    )
    .await
    .is_err());
    assert_eq!(before, count(&w).await);
    w.db.close().await;
}

#[tokio::test]
async fn registry_first_body_write_on_absent_or_empty_body_needs_no_guard() {
    let w = world().await;
    for body in [None, Some("")] {
        for operation in ["body", "body_set"] {
            let mut args = json!({"type":"Document","kind":"note","reason":"empty fixture"});
            if let Some(body) = body {
                args["body"] = json!(body);
            }
            let created = admin(&w, "create_record", args).await;
            let id = created["id"].as_str().unwrap();
            let before = count(&w).await;
            assert!(call(&w,"acct:admin","update_record",json!({"id":id,"body_set":"first","if_body_digest":"stale","reason":"optional guard still checked"})).await.is_err());
            assert_eq!(before, count(&w).await);
            let mut args = json!({"id":id,"reason":"first write"});
            args[operation] = json!("first");
            let first = admin(&w, "update_record", args.clone()).await;
            assert_eq!(first["changed"], true);
            assert_eq!(record(&w, id).await.body.as_deref(), Some("first"));
            args[operation] = json!("destructive");
            let before = count(&w).await;
            assert!(call(&w, "acct:admin", "update_record", args).await.is_err());
            assert_eq!(before, count(&w).await);
            let cleared = admin(&w,"update_record",json!({"id":id,"body_set":null,"if_body_digest":first["body_digest"],"reason":"clear"})).await;
            assert_eq!(cleared["changed"], true);
            admin(
                &w,
                "update_record",
                json!({"id":id,"body_set":"again","reason":"empty body again"}),
            )
            .await;
            assert_eq!(record(&w, id).await.body.as_deref(), Some("again"));
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn registry_generic_links_round_trip_and_retry_receipts() {
    let w = world().await;
    let epic = admin(
        &w,
        "create_record",
        json!({"type":"WorkItem","kind":"epic","name":"Epic","home_id":w.home}),
    )
    .await;
    let task = admin(
        &w,
        "create_record",
        json!({"type":"WorkItem","kind":"task","name":"Task","home_id":w.home}),
    )
    .await;
    let source = task["id"].as_str().unwrap();
    let target = epic["id"].as_str().unwrap();
    let add = json!({"action":"add","source_id":source,"target_id":target,"relationship":"part_of","note":"first","idempotency_key":"part-of"});
    let receipt = admin(&w, "manage_links", add.clone()).await;
    assert_eq!(receipt["effect"], "link_added");
    assert_eq!(receipt["relationship"], "part_of");
    assert_eq!(receipt["status"], "added");
    let before = count(&w).await;
    let retry = admin(&w, "manage_links", add.clone()).await;
    assert_eq!(receipt, retry);
    assert_eq!(count(&w).await, before);
    let listed = admin(
        &w,
        "manage_links",
        json!({"action":"list","record_id":source}),
    )
    .await;
    let link = listed["links_out"][0].clone();
    assert!(link["id"].is_string());
    assert_eq!(receipt["link"], link);
    assert!(link["created_at"].is_string());
    assert_eq!(link["source_id"], source);
    assert_eq!(link["target_id"], target);
    assert_eq!(link["note"], "first");
    let incoming = admin(
        &w,
        "manage_links",
        json!({"action":"list","record_id":target}),
    )
    .await;
    assert_eq!(incoming["links_in"][0], link);
    let get = admin(&w, "get_record", json!({"ids":[source,target]})).await;
    assert_eq!(get["records"][0]["links_out"][0], link);
    assert_eq!(get["records"][1]["links_in"][0], link);
    let traverse = json!({"steps":[{"step":"filter","ids":[target]},{"step":"traverse","target":"links","relationship":"part_of","direction":"in"},{"step":"filter","types":["WorkItem"],"kinds":["task"]}]});
    let found = admin(&w, "query_record", traverse.clone()).await;
    assert_eq!(found["total"], 1);
    assert_eq!(found["records"][0]["id"], source);
    let mut update = add.clone();
    update["note"] = json!("updated");
    update["idempotency_key"] = json!("update-note");
    let updated_receipt = admin(&w, "manage_links", update.clone()).await;
    assert_eq!(updated_receipt["link"]["id"], link["id"]);
    assert_eq!(updated_receipt["effect"], "link_note_updated");
    assert_eq!(updated_receipt["changed"], true);
    assert_eq!(updated_receipt["status"], "added");
    assert!(render_links(&updated_receipt).contains("Existing link note updated:"));
    assert_eq!(
        admin(&w, "manage_links", update.clone()).await,
        updated_receipt
    );
    let updated = admin(
        &w,
        "manage_links",
        json!({"action":"list","record_id":source}),
    )
    .await;
    assert_eq!(updated["links_out"][0]["id"], link["id"]);
    assert_eq!(updated["links_out"][0]["created_at"], link["created_at"]);
    assert_eq!(updated["links_out"][0]["note"], "updated");
    // A delayed retry returns the original receipt and never restores its note.
    assert_eq!(admin(&w, "manage_links", add).await, receipt);
    update.as_object_mut().unwrap().remove("idempotency_key");
    let before = count(&w).await;
    let unchanged = admin(&w, "manage_links", update).await;
    assert_eq!(unchanged["effect"], "unchanged");
    assert_eq!(unchanged["changed"], false);
    assert!(unchanged["write_receipt"].is_null());
    assert_eq!(count(&w).await, before);
    let remove = json!({"action":"remove","source_id":source,"target_id":target,"relationship":"part_of","idempotency_key":"remove-part-of"});
    let removed = admin(&w, "manage_links", remove.clone()).await;
    assert_eq!(removed["status"], "removed");
    assert_eq!(admin(&w, "manage_links", remove).await, removed);
    assert_eq!(admin(&w, "query_record", traverse).await["total"], 0);
    let get = admin(&w, "get_record", json!({"ids":[source,target]})).await;
    assert_eq!(get["records"][0]["links_out_count"], 0);
    assert_eq!(get["records"][1]["links_in_count"], 0);
    w.db.close().await;
}

#[tokio::test]
async fn registry_generic_create_links_paging_and_atomic_failure() {
    let w = world().await;
    let target = admin(
        &w,
        "create_record",
        json!({"type":"WorkItem","kind":"epic","name":"Epic","home_id":w.home}),
    )
    .await["id"]
        .clone();
    let create = json!({"type":"WorkItem","kind":"task","name":"Task","home_id":w.home,"links":[{"target_id":target,"relationship":"part_of","note":"parent"},{"target_id":target,"relationship":"derived_from","note":"basis"},{"target_id":target,"relationship":"relates_to"}],"idempotency_key":"create-linked"});
    let task = admin(&w, "create_record", create.clone()).await;
    assert_eq!(admin(&w, "create_record", create).await, task);
    let mut cursor = Value::Null;
    let mut collected = Vec::new();
    loop {
        let page = admin(
            &w,
            "manage_links",
            json!({"action":"list","record_id":target,"limit":1,"cursor":cursor}),
        )
        .await;
        assert_eq!(page["returned"], 1);
        collected.push(
            page["links_out"]
                .as_array()
                .unwrap()
                .iter()
                .chain(page["links_in"].as_array().unwrap())
                .next()
                .unwrap()
                .clone(),
        );
        if page["has_more"] == false {
            break;
        }
        cursor = page["next_cursor"].clone();
        assert!(cursor.is_string());
    }
    // relates_to is symmetric: one outgoing and one incoming candidate.
    assert_eq!(collected.len(), 4);
    let mut unique: Vec<_> = collected.iter().map(Value::to_string).collect();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), 4);
    let before = count(&w).await;
    assert!(call(
        &w,
        "acct:admin",
        "manage_links",
        json!({"action":"list","record_id":task["id"],"limit":1,"cursor":cursor})
    )
    .await
    .is_err());
    let bad = json!({"type":"WorkItem","kind":"task","name":"rollback","home_id":w.home,"links":[{"target_id":target,"relationship":"part_of"},{"target_id":"missing","relationship":"depends_on"}]});
    assert!(call(&w, "acct:admin", "create_record", bad).await.is_err());
    assert_eq!(count(&w).await, before);
    w.db.close().await;
}

#[tokio::test]
async fn registry_generic_links_hidden_endpoints_and_revoked_retry() {
    let w = world().await;
    // Viewer may edit the public source but cannot view the private target.
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    let source = admin(
        &w,
        "create_record",
        json!({"type":"WorkItem","kind":"task","name":"Public","home_id":w.home}),
    )
    .await["id"]
        .clone();
    let target = admin(
        &w,
        "create_record",
        json!({"type":"WorkItem","kind":"epic","name":"Secret","home_id":w.private}),
    )
    .await["id"]
        .clone();
    let add = json!({"action":"add","source_id":source,"target_id":target,"relationship":"part_of","idempotency_key":"hidden-link"});
    let receipt = admin(&w, "manage_links", add.clone()).await;
    for action in ["add", "remove"] {
        let mut hidden = add.clone();
        hidden["action"] = json!(action);
        let mut missing = hidden.clone();
        missing["target_id"] = json!("missing");
        let before = count(&w).await;
        let hidden = call(&w, "acct:viewer", "manage_links", hidden)
            .await
            .unwrap_err()
            .to_string();
        let missing = call(&w, "acct:viewer", "manage_links", missing)
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(hidden, missing);
        assert_eq!(count(&w).await, before);
    }
    let get = call(
        &w,
        "acct:viewer",
        "get_record",
        json!({"ids":[source,target]}),
    )
    .await
    .unwrap();
    assert_eq!(get["records"][0]["links_out_count"], 0);
    assert_eq!(get["records"][1]["status"], "not_found");
    let list = call(
        &w,
        "acct:viewer",
        "manage_links",
        json!({"action":"list","record_id":source}),
    )
    .await
    .unwrap();
    assert_eq!(list["returned"], 0);
    for anchor in [target.clone(), source.clone(), json!("missing")] {
        let query = call(&w,"acct:viewer","query_record",json!({"steps":[{"step":"filter","ids":[anchor]},{"step":"traverse","target":"links","relationship":"part_of","direction":"both"},{"step":"filter","types":["WorkItem"]}]})).await.unwrap();
        assert_eq!(query["total"], 0);
    }
    assert_eq!(admin(&w, "manage_links", add.clone()).await, receipt);
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.private,
        &[(&w.admin, "manage"), (&w.viewer, "view")],
    )
    .await
    .unwrap();
    let viewer_receipt = call(&w, "acct:viewer", "manage_links", add.clone())
        .await
        .unwrap();
    assert_eq!(viewer_receipt["relationship"], "part_of");
    kernel::replace_home_policy(&w.db, &w.admin, &w.private, &[(&w.admin, "manage")])
        .await
        .unwrap();
    let before = count(&w).await;
    assert!(call(&w, "acct:viewer", "manage_links", add)
        .await
        .unwrap_err()
        .to_string()
        .contains(kernel::HIDDEN_OR_MISSING));
    assert_eq!(count(&w).await, before);
    w.db.close().await;
}

#[tokio::test]
async fn registry_imported_generic_link_preserves_v1_identity_and_provenance() {
    let w = world().await;
    let source = admin(
        &w,
        "create_record",
        json!({"type":"WorkItem","kind":"task","name":"Imported task","home_id":w.home}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let target = admin(
        &w,
        "create_record",
        json!({"type":"WorkItem","kind":"epic","name":"Imported epic","home_id":w.home}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let imported = kernel::GenericLink {
        link_id: "original-v1-link".into(),
        source_id: source.clone(),
        target_id: target.clone(),
        relationship: "depends_on".into(),
        note: Some("original note".into()),
        created_at: "2026-09-03 12:34:56".into(),
        actor: Some("v1-account".into()),
    };
    kernel::import_generic_link_as(&w.db, &host, &imported)
        .await
        .unwrap();
    let list = admin(
        &w,
        "manage_links",
        json!({"action":"list","record_id":source}),
    )
    .await;
    assert_eq!(
        list["links_out"][0],
        json!({"id":imported.link_id,"source_id":source,"target_id":target,"relationship":"depends_on","note":"original note","created_at":imported.created_at})
    );
    admin(&w,"manage_links",json!({"action":"add","source_id":source,"target_id":target,"relationship":"depends_on","note":"new note"})).await;
    let get = admin(&w, "get_record", json!({"ids":[source]})).await;
    assert_eq!(get["records"][0]["links_out"][0]["id"], imported.link_id);
    assert_eq!(
        get["records"][0]["links_out"][0]["created_at"],
        imported.created_at
    );
    assert_eq!(get["records"][0]["links_out"][0]["note"], "new note");
    w.db.close().await;
}

#[tokio::test]
async fn tool_created_updated_and_archived_records_follow_the_search_index() {
    let w = world().await;
    // Created through the tool: title, summary and lane body are searchable.
    let created = admin(
        &w,
        "create_record",
        json!({"type":"WorkItem","kind":"task","name":"Zebra quest","summary":"seek striped equids","body":"savanna notes","home_id":w.home,"reason":"fixture"}),
    )
    .await;
    let id = created["id"].as_str().unwrap();
    for query in ["Zebra", "striped", "savanna"] {
        let hits = call(&w, "acct:viewer", "search", json!({"query": query}))
            .await
            .unwrap();
        assert_eq!(hits["total"], 1, "{query}");
        assert_eq!(hits["hits"][0]["id"], id);
    }
    // Renamed through the tool: the index follows, old title stops matching.
    admin(
        &w,
        "update_record",
        json!({"id": id, "name": "Giraffe quest", "reason": "edit"}),
    )
    .await;
    let gone = call(&w, "acct:viewer", "search", json!({"query": "Zebra"}))
        .await
        .unwrap();
    assert_eq!(gone["total"], 0);
    let found = call(&w, "acct:viewer", "search", json!({"query": "Giraffe"}))
        .await
        .unwrap();
    assert_eq!(found["total"], 1);
    assert_eq!(found["hits"][0]["id"], id);
    // Archived through the tool: excluded by default, visible opt-in.
    admin(&w, "archive_record", json!({"id": id, "reason": "done"})).await;
    let hidden = call(&w, "acct:viewer", "search", json!({"query": "Giraffe"}))
        .await
        .unwrap();
    assert_eq!(hidden["total"], 0);
    let shown = call(
        &w,
        "acct:viewer",
        "search",
        json!({"query": "Giraffe", "include_archived": true}),
    )
    .await
    .unwrap();
    assert_eq!(shown["total"], 1);
    assert_eq!(shown["hits"][0]["id"], id);
    w.db.close().await;
}

#[tokio::test]
async fn registry_generic_traversal_scopes_before_scan_and_count() {
    let w = world().await;
    let epic = admin(
        &w,
        "create_record",
        json!({"type":"WorkItem","kind":"epic","name":"Epic","home_id":w.home}),
    )
    .await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let task = admin(&w, "create_record", json!({"type":"WorkItem","kind":"task","name":"Visible task","home_id":w.home,"links":[{"relationship":"part_of","target_id":epic}]})).await["id"].as_str().unwrap().to_owned();
    // More than a scan page of linked records in the same family/kind must
    // neither enter the counting walk nor change its hydration cost.
    for n in 0..510 {
        admin(&w, "create_record", json!({"type":"WorkItem","kind":"task","name":format!("Hidden {n}"),"home_id":w.private,"links":[{"relationship":"part_of","target_id":epic}]})).await;
    }
    let groups = kernel::search_v2::distinct_groups(&w.db).await.unwrap();
    let counters = kernel::search_v2::S7aCounters::default();
    let page = kernel::search_v2::bounded_query_as(
        &w.db,
        &w.viewer,
        &groups,
        None,
        Some(&["WorkItem".into()]),
        Some(&["task".into()]),
        Some(("part_of", &epic, "out")),
        1,
        0,
        &counters,
    )
    .await
    .unwrap();
    assert_eq!(page.total, 1);
    assert_eq!(page.records[0].id, task);
    // One carrier-label read plus one page hydration, independent of hidden rows.
    assert_eq!(counters.snapshot(), (groups.len(), 2, 0, 1));
    let query = json!({"steps":[{"step":"filter","ids":[epic]},{"step":"traverse","target":"links","relationship":"part_of","direction":"in"},{"step":"filter","types":["WorkItem"],"kinds":["task"]}],"limit":1});
    let result = call(&w, "acct:viewer", "query_record", query.clone())
        .await
        .unwrap();
    assert_eq!(result["total"], 1);
    assert_eq!(result["records"][0]["id"], task);
    // Exact-ID filters use the same scoped edge predicate, in both directions.
    let mut exact = query;
    exact["steps"][2] = json!({"step":"filter","ids":[task]});
    assert_eq!(
        call(&w, "acct:viewer", "query_record", exact.clone())
            .await
            .unwrap()["total"],
        1
    );
    exact["steps"][1]["direction"] = json!("out");
    assert_eq!(
        call(&w, "acct:viewer", "query_record", exact)
            .await
            .unwrap()["total"],
        0
    );
    w.db.close().await;
}

#[tokio::test]
async fn registry_link_reads_preserve_principal_targets_and_prefer_generic_triples() {
    let w = world().await;
    let source = kernel::create_record_as(&w.db, &w.admin, &w.home)
        .await
        .unwrap();
    let hidden = kernel::create_record_as(&w.db, &w.admin, &w.private)
        .await
        .unwrap();
    let target = kernel::create_record_as(&w.db, &w.admin, &w.home)
        .await
        .unwrap();
    for id in [&source, &hidden] {
        kernel::link_as(&w.db, &w.admin, id, "authored_by", &w.admin)
            .await
            .unwrap();
    }
    kernel::link_as(&w.db, &w.admin, &source, "depends_on", &target)
        .await
        .unwrap();
    let listed = call(
        &w,
        "acct:viewer",
        "manage_links",
        json!({"action":"list","record_id":source}),
    )
    .await
    .unwrap();
    assert_eq!(listed["returned"], 2);
    assert!(listed["links_out"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l["target_id"] == w.admin && l["relationship"] == "authored_by"));
    let get = call(
        &w,
        "acct:viewer",
        "get_record",
        json!({"ids":[source,hidden]}),
    )
    .await
    .unwrap();
    assert_eq!(get["records"][0]["links_out"], listed["links_out"]);
    assert_eq!(get["records"][1]["status"], "not_found");
    assert!(
        kernel::generic_links::visible_link_rows_as(&w.db, &w.viewer, &hidden)
            .await
            .unwrap()
            .is_empty()
    );
    let receipt = admin(&w,"manage_links",json!({"action":"add","source_id":source,"target_id":target,"relationship":"depends_on","note":"generic provenance"})).await;
    let listed = call(
        &w,
        "acct:viewer",
        "manage_links",
        json!({"action":"list","record_id":source}),
    )
    .await
    .unwrap();
    assert_eq!(listed["returned"], 2);
    let merged = listed["links_out"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["relationship"] == "depends_on")
        .unwrap();
    assert_eq!(*merged, receipt["link"]);
    let incoming = call(
        &w,
        "acct:viewer",
        "manage_links",
        json!({"action":"list","record_id":target}),
    )
    .await
    .unwrap();
    assert_eq!(incoming["links_in"], json!([receipt["link"]]));
    // Generic removal never silently deletes a definition-declared legacy row.
    admin(&w,"manage_links",json!({"action":"remove","source_id":source,"target_id":target,"relationship":"depends_on"})).await;
    let incoming = call(
        &w,
        "acct:viewer",
        "manage_links",
        json!({"action":"list","record_id":target}),
    )
    .await
    .unwrap();
    assert_eq!(incoming["returned"], 1);
    assert!(incoming["links_in"][0]["id"].is_null());
    // A self-link is selected once physically, and appears once per direction.
    admin(&w,"manage_links",json!({"action":"add","source_id":source,"target_id":source,"relationship":"self_reference"})).await;
    let get = admin(&w, "get_record", json!({"ids":[source]})).await;
    for field in ["links_in", "links_out"] {
        assert_eq!(
            get["records"][0][field]
                .as_array()
                .unwrap()
                .iter()
                .filter(|l| l["relationship"] == "self_reference")
                .count(),
            1
        );
    }
    w.db.close().await;
}

#[tokio::test]
async fn registry_link_reads_work_without_optional_indexes() {
    let mut w = world().await;
    let target = admin(
        &w,
        "create_record",
        json!({"type":"WorkItem","kind":"epic","name":"Epic","home_id":w.home}),
    )
    .await["id"]
        .clone();
    let source = admin(&w,"create_record",json!({"type":"WorkItem","kind":"task","name":"Task","home_id":w.home,"links":[{"relationship":"part_of","target_id":target},{"relationship":"relates_to","target_id":target}]})).await["id"].clone();
    let get_args = json!({"ids":[source,target]});
    let expected_get = admin(&w, "get_record", get_args.clone()).await;
    let mut expected_lists = Vec::new();
    for id in [&source, &target] {
        let args = json!({"action":"list","record_id":id});
        expected_lists.push((args.clone(), admin(&w, "manage_links", args).await));
    }
    for index in [
        "idx_kernel_generic_links_source_page",
        "idx_kernel_generic_links_target_page",
        "idx_kernel_links_target",
        "idx_kernel_provider_subjects_aggregate",
    ] {
        sqlx::query(&format!("DROP INDEX {index}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
    // Open through KernelV2(Db), without the stdio startup index upgrade.
    w.db.close().await;
    w.db = crate::db::open_database(w._dir.path().join("writes.db").to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(admin(&w, "get_record", get_args).await, expected_get);
    for (args, expected) in expected_lists {
        assert_eq!(admin(&w, "manage_links", args).await, expected);
    }
    w.db.close().await;
}

#[tokio::test]
async fn registry_w1_metadata_and_note4_fields_are_atomic_visible_and_replayable() {
    let w = world().await;
    for (typ, kind) in [
        ("Document", "note"),
        ("WorkItem", "task"),
        ("Entity", "person"),
    ] {
        let created=admin(&w,"create_record",json!({"type":typ,"kind":kind,"name":"Synthetic metadata","summary":"Initial summary","lifecycle":"open","persistence":"occurrent","maturity":"captured","home_id":w.home,"reason":"fixture"})).await;
        let id = created["id"].as_str().unwrap();
        let initial = record(&w, id).await;
        assert_eq!(initial.metadata.persistence, "occurrent");
        assert_eq!(initial.metadata.maturity.as_deref(), Some("captured"));
        assert_eq!(initial.fields["summary"], "Initial summary");
        if typ == "Document" {
            assert_eq!(initial.pin.as_ref().unwrap().version, 4);
        }
        let patch = json!({"id":id,"summary":"Revised summary","lifecycle":"completed","persistence":"enduring","maturity":null,"body_append":"text","idempotency_key":format!("w1:{typ}"),"reason":"edit"});
        let receipt = admin(&w, "update_record", patch.clone()).await;
        let read = admin(&w, "get_record", json!({"ids":[id]})).await;
        let row = &read["records"][0];
        assert_eq!(row["persistence"], "enduring");
        assert!(row["maturity"].is_null());
        assert_eq!(row["summary"], "Revised summary");
        assert_eq!(row["lifecycle"], "completed");
        let clock = record(&w, id).await.metadata.last_activity_at;
        assert_eq!(row["last_activity_at"], clock);
        let sql=admin(&w,"query_sql",json!({"sql":format!("SELECT persistence,maturity,last_activity_at,last_activity_at_ms,summary,lifecycle FROM records WHERE id='{id}'")})).await;
        assert_eq!(sql["rows"][0]["persistence"], "enduring");
        assert!(sql["rows"][0]["maturity"].is_null());
        assert_eq!(sql["rows"][0]["last_activity_at"], clock);
        assert!(sql["rows"][0]["last_activity_at_ms"].is_number());
        assert_eq!(sql["rows"][0]["summary"], "Revised summary");
        let before = count(&w).await;
        assert_eq!(admin(&w, "update_record", patch).await, receipt);
        assert_eq!(count(&w).await, before);
        assert_eq!(record(&w, id).await.metadata.last_activity_at, clock);
        for patch in [
            json!({"persistence":null}),
            json!({"persistence":"unknown"}),
            json!({"maturity":42}),
            json!({"last_activity_at":"2000-01-01T00:00:00Z"}),
        ] {
            let mut args = patch.as_object().unwrap().clone();
            args.insert("id".into(), id.into());
            args.insert("name".into(), "must roll back".into());
            let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
            assert!(call(&w, "acct:admin", "update_record", args.into())
                .await
                .is_err());
            assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
        }
        let before = count(&w).await;
        admin(
            &w,
            "update_record",
            json!({"id":id,"persistence":"enduring","maturity":null,"reason":"no op"}),
        )
        .await;
        assert_eq!(count(&w).await, before);
        assert_eq!(record(&w, id).await.metadata.last_activity_at, clock);
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(kernel::dump_all_kernel_tables(&w.db).await.unwrap(), before);
}

#[tokio::test]
async fn attachment_shared_blob_mcp_privacy_receipts_and_bearer_immutability() {
    let w = world().await;
    let visible_bearer = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"Public","home_id":w.home}),
    )
    .await;
    let hidden_bearer = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"Private","home_id":w.private}),
    )
    .await;
    let args = json!({"record_id":visible_bearer["id"],"text":"shared synthetic bytes","filename":"visible.txt","idempotency_key":"shared-key"});
    let visible = admin(&w, "attach_text", args.clone()).await;
    let hidden = admin(&w, "attach_text", json!({"record_id":hidden_bearer["id"],"text":"shared synthetic bytes","filename":"secret-filename.txt"})).await;
    assert_eq!(visible["blob"]["sha256"], hidden["blob"]["sha256"]);
    let blobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_blobs")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(blobs, 1);
    let read = call(
        &w,
        "acct:viewer",
        "read_attachment",
        json!({"attachment_id":visible["attachment_id"]}),
    )
    .await
    .unwrap();
    assert_eq!(read["content"], "shared synthetic bytes");
    assert_eq!(read["blob"]["original_filename"], "visible.txt");
    for tool in ["read_attachment", "manage_attachments"] {
        let mut errors = Vec::new();
        for id in [hidden["attachment_id"].as_str().unwrap(), "missing"] {
            let mut args = json!({"attachment_id":id});
            if tool == "manage_attachments" {
                args["action"] = json!("inspect");
            }
            errors.push(
                call(&w, "acct:viewer", tool, args)
                    .await
                    .unwrap_err()
                    .to_string(),
            );
        }
        assert_eq!(errors[0], errors[1]);
    }
    let batch = call(
        &w,
        "acct:viewer",
        "get_record",
        json!({"ids":[visible["attachment_id"],hidden["attachment_id"]]}),
    )
    .await
    .unwrap();
    assert_eq!(
        batch["records"][1],
        json!({"id":hidden["attachment_id"],"status":"not_found"})
    );
    assert!(!batch.to_string().contains("secret-filename"));
    let listed = call(
        &w,
        "acct:viewer",
        "manage_attachments",
        json!({"action":"list","record_id":visible_bearer["id"]}),
    )
    .await
    .unwrap();
    assert!(!listed.to_string().contains("secret-filename"));
    for action in ["add", "remove"] {
        let err = call(&w, "acct:admin", "manage_links", json!({"action":action,"source_id":visible["attachment_id"],"target_id":if action=="remove" { &visible_bearer["id"] } else { &hidden_bearer["id"] },"relationship":"part_of"})).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("requires exactly one outgoing part_of"));
    }
    admin(&w, "manage_links", json!({"action":"add","source_id":visible["attachment_id"],"target_id":visible_bearer["id"],"relationship":"part_of","note":"same bearer, updated note"})).await;
    assert_eq!(admin(&w, "attach_text", args.clone()).await, visible);
    let request: String = sqlx::query_scalar(
        "SELECT request_json FROM kernel_mcp_write_receipts WHERE operation_key='shared-key'",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert!(!request.contains("shared synthetic bytes"));
    assert_eq!(
        serde_json::from_str::<Value>(&request).unwrap()["arguments"]["text"]["sha256"],
        visible["blob"]["sha256"]
    );
    // Upgrade old full-text receipts without changing their retry identity.
    sqlx::query(
        "UPDATE kernel_mcp_write_receipts SET request_json=? WHERE operation_key='shared-key'",
    )
    .bind(serde_json::to_string(&args).unwrap())
    .execute(w.db.write_pool())
    .await
    .unwrap();
    assert_eq!(admin(&w, "attach_text", args.clone()).await, visible);
    let stored: String = sqlx::query_scalar(
        "SELECT request_json FROM kernel_mcp_write_receipts WHERE operation_key='shared-key'",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(stored, request);
    let mut changed = args;
    changed["text"] = json!("different bytes");
    assert!(call(&w, "acct:admin", "attach_text", changed)
        .await
        .unwrap_err()
        .to_string()
        .contains("different request"));
}

#[tokio::test]
async fn attachment_without_binding_reopen_and_v1_facet_wire_shape() {
    let w = world().await;
    assert!(call(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Document","kind":"attachment","home_id":w.home})
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("use attach_text"));
    // Trusted fixture models a pre-W2 attachment with a valid bearer but no byte binding.
    let note = admin(&w,"create_record",json!({"type":"Document","kind":"note","home_id":w.home,"facets":{"priority":"high","json_text":"{\"literal\":true}"}})).await;
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = ActAllocation::new();
    let fields = serde_json::to_string(&v1_compat::compat_fields(
        "Document",
        "attachment",
        Some("Legacy"),
        None,
        None,
    ))
    .unwrap();
    let carrier = v1_compat::v1_carrier_for("Document", "attachment");
    let id = kernel::create_input_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.admin,
        carrier.family(),
        carrier.kind(),
        kernel::FieldInput::Raw(&fields),
        &w.home,
    )
    .await
    .unwrap();
    kernel::comments_v2::append_bearer_link_in(
        &w.db,
        &mut tx,
        &mut acts,
        &w.admin,
        &id,
        note["id"].as_str().unwrap(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    for table in [
        "kernel_attachment_blobs",
        "kernel_blob_handles",
        "kernel_blobs",
    ] {
        sqlx::query(&format!("DROP TABLE {table}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
    }
    // Schema upgrades are explicit; raw reopen must never repair tables.
    kernel::prepare_v2_database(&w.db).await.unwrap();
    let reopened = crate::db::open_database(w.db.path().to_str().unwrap())
        .await
        .unwrap();
    let response = registry()
        .call_engine(
            EngineHandle::KernelV2(reopened.clone()),
            Caller::authenticated("acct:viewer"),
            "get_record",
            json!({"ids":[id,note["id"],"missing"]}),
        )
        .await
        .unwrap();
    assert_eq!(response["records"][0]["status"], "found");
    assert_eq!(response["records"][0].get("blob"), Some(&Value::Null));
    assert_eq!(response["records"][0]["facets"], json!([]));
    let facets = response["records"][1]["facets"].as_array().unwrap();
    assert_eq!(facets.len(), 2);
    assert_eq!(facets[0]["value"], "{\"literal\":true}");
    for facet in facets {
        assert_eq!(facet.as_object().unwrap().len(), 4);
        assert!(
            native_artifact_runtime::artifact_intents::FacetVersion::parse(
                facet["version"].as_str().unwrap()
            )
            .is_some()
        );
        assert_eq!(facet["vocab_ref"], Value::Null);
    }
    assert!(response["records"][2].get("facets").is_none());
    reopened.close().await;
}

#[tokio::test]
async fn body_replace_repairs_are_bounded_and_fail_without_writes() {
    let w = world().await;
    let body = "# Overview\nRepeated token here.\n# Details\nRepeated token there.\nA sufficiently long shared prefix ends here.\n";
    let created = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","body":body,"home_id":w.home,"reason":"fixture"}),
    )
    .await;
    let id = created["id"].as_str().unwrap();
    for (old, expected_count, expected) in [
        ("unfindable text", None, "heading outline"),
        (
            "A sufficiently long shared prefix differs",
            None,
            "longest matching prefix",
        ),
        (
            "Repeated token",
            Some(1),
            "expected 1 occurrences but matched 2",
        ),
        ("Repeated token", None, "set replace_all: true"),
    ] {
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        let error = call(&w, "acct:admin", "update_record", json!({"id":id,"name":"must roll back","body_replace":[{"old":old,"new":"replacement","expected_count":expected_count}],"reason":"repair"})).await.unwrap_err().to_string();
        assert!(error.contains(expected), "{error}");
        assert!(error.len() < 4096, "unbounded repair context");
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
    admin(&w, "update_record", json!({"id":id,"body_replace":[{"old":"Repeated token","new":"Changed","expected_count":2},{"old":"Changed here.","new":"Done."}],"reason":"repaired"})).await;
    assert_eq!(
        record(&w, id).await.body.as_deref(),
        Some("# Overview\nDone.\n# Details\nChanged there.\nA sufficiently long shared prefix ends here.\n")
    );
}

#[tokio::test]
async fn member_link_removal_keeps_other_authors_even_with_manage() {
    let w = world().await;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    let a = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"A","home_id":w.home}),
    )
    .await["id"]
        .clone();
    let b = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"B","home_id":w.home}),
    )
    .await["id"]
        .clone();
    let args = json!({"action":"add","source_id":a,"target_id":b,"relationship":"relates_to"});
    admin(&w, "manage_links", args.clone()).await;
    call(&w, "acct:viewer", "manage_links", args).await.unwrap();
    let remove = json!({"action":"remove","source_id":a,"target_id":b,"relationship":"relates_to"});
    let receipt = admin(&w, "manage_links", remove.clone()).await;
    assert_eq!(receipt["status"], "assertions_retracted");
    assert_eq!(receipt["relationship_active_after_operation"], true);
    assert!(crate::mcp::render::render("manage_links", &receipt)
        .unwrap()
        .contains("keep this relationship active"));
    let relations = kernel::relates_to_port::relations_as(&w.db, &w.admin, a.as_str().unwrap())
        .await
        .unwrap();
    let state: relation::State = serde_json::from_value(relations[0]["state"].clone()).unwrap();
    assert!(state
        .assertions
        .iter()
        .any(|a| a.asserted_by.as_deref() == Some(&w.admin) && a.retracted));
    assert!(state
        .assertions
        .iter()
        .any(|a| a.asserted_by.as_deref() == Some(&w.viewer) && !a.retracted));
    assert!(call(&w, "acct:admin", "manage_links", remove.clone())
        .await
        .is_err());
    call(&w, "acct:viewer", "manage_links", remove)
        .await
        .unwrap();
    let projections = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        projections,
        kernel::dump_all_kernel_tables(&w.db).await.unwrap()
    );
}

#[tokio::test]
async fn move_with_comments_switches_every_read_surface_atomically() {
    let w = world().await;
    let new_reader =
        kernel::create_principal(&w.db, "account", "New reader", "acct:new-reader", &w.admin)
            .await
            .unwrap();
    let mover = kernel::create_principal(&w.db, "account", "Mover", "acct:mover", &w.admin)
        .await
        .unwrap();
    let editor = kernel::create_principal(&w.db, "account", "Editor", "acct:editor", &w.admin)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[
            (&w.admin, "manage"),
            (&w.viewer, "view"),
            (&mover, "manage"),
            (&editor, "edit"),
        ],
    )
    .await
    .unwrap();
    let destination = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[
            (&w.admin, "manage"),
            (&mover, "edit"),
            (&editor, "edit"),
            (&new_reader, "view"),
        ]),
        &w.admin,
    )
    .await
    .unwrap();
    assert_eq!(
        kernel::kernel_effective_capability(&w.db, &mover, &destination)
            .await
            .unwrap(),
        Capability::Edit
    );
    let note = admin(&w,"create_record",json!({"type":"Document","kind":"note","name":"Migrationneedle","body":"Migrationneedle body","home_id":w.home})).await["id"].clone();
    let root = call(&w,"acct:viewer","create_record",json!({"type":"Annotation","kind":"comment","body":"Migrationneedle root","links":[{"target_id":note,"relationship":"part_of"}]})).await.unwrap()["id"].clone();
    let reply = call(&w,"acct:viewer","create_record",json!({"type":"Annotation","kind":"comment","body":"Migrationneedle reply","links":[{"target_id":root,"relationship":"part_of"}]})).await.unwrap()["id"].clone();
    let ids = vec![
        note.as_str().unwrap(),
        root.as_str().unwrap(),
        reply.as_str().unwrap(),
    ];
    let old = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(call(
        &w,
        "acct:editor",
        "update_record",
        json!({"id":note,"home_id":destination})
    )
    .await
    .is_err());
    assert_eq!(old, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    // An explicit home must be available and writable, including on replay.
    assert!(call(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":note,"home_id":"missing"})
    )
    .await
    .is_err());
    // This refusal happens after the cohort's move events are appended;
    // the caller transaction must roll back all three homes and events.
    let before_move = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let error = call(
        &w,
        "acct:mover",
        "update_record",
        json!({"id":note,"home_id":destination,"facets":{"blob_ref":"forbidden"}}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("engine-owned"), "{error}");
    assert_eq!(
        before_move,
        kernel::dump_all_kernel_tables(&w.db).await.unwrap()
    );
    let args = json!({"id":note,"home_id":destination,"idempotency_key":"move-thread"});
    call(&w, "acct:mover", "update_record", args.clone())
        .await
        .unwrap();
    for id in &ids {
        assert_eq!(record(&w, id).await.home_id, destination);
    }
    let events: Vec<(String, i64)> = sqlx::query_as(
        "SELECT record_id,act FROM content_events WHERE type='kernel.record_rehomed.v2'",
    )
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert_eq!(events.len(), 3);
    assert!(events.iter().all(|(_, act)| *act == events[0].1));
    for (credential, visible) in [("acct:viewer", false), ("acct:new-reader", true)] {
        let get = call(
            &w,
            credential,
            "get_record",
            json!({"ids":ids,"include_comments":true}),
        )
        .await
        .unwrap();
        assert_eq!(get["records"].as_array().unwrap().len(), 3);
        for row in get["records"].as_array().unwrap() {
            if visible {
                assert_eq!(row["home_id"], destination);
                assert!(row.get("body").is_some());
            } else {
                assert_eq!(row["status"], "not_found");
                assert!(row.get("body").is_none());
                assert!(row.get("home_id").is_none());
            }
        }
        let sql = call(
            &w,
            credential,
            "query_sql",
            json!({"sql":"SELECT id,home_id FROM records ORDER BY id"}),
        )
        .await
        .unwrap();
        let rows = sql["rows"].as_array().unwrap();
        for id in &ids {
            assert_eq!(rows.iter().any(|row| row["id"] == *id), visible);
        }
        if visible {
            for row in rows
                .iter()
                .filter(|row| ids.contains(&row["id"].as_str().unwrap_or("")))
            {
                assert_eq!(row["home_id"], destination);
            }
        }
        for (home, expected) in [(&w.home, 0), (&destination, if visible { 3 } else { 0 })] {
            let out=call(&w,credential,"query_sql",json!({"sql":format!("SELECT id FROM records WHERE home_id='{}' ORDER BY id",home)})).await.unwrap();
            assert_eq!(out["rows"].as_array().unwrap().len(), expected);
        }
        let search = call(&w, credential, "search", json!({"query":"Migrationneedle"}))
            .await
            .unwrap();
        for id in &ids {
            assert_eq!(
                search["hits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|hit| hit["id"] == *id),
                visible
            );
        }
        for (source, target) in [(&root, &note), (&reply, &root)] {
            let listed = call(
                &w,
                credential,
                "manage_links",
                json!({"action":"list","record_id":source}),
            )
            .await;
            if visible {
                assert!(listed.unwrap()["links"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|link| link["target_id"] == *target));
            } else if let Ok(listed) = listed {
                assert!(listed["links"].as_array().unwrap().is_empty());
            }
        }
    }
    // Like v1, replay re-proves source Manage under the current policy.
    // Moving to an Edit-only destination does not preserve the old grant.
    let before = count(&w).await;
    assert!(call(&w, "acct:mover", "update_record", args.clone())
        .await
        .is_err());
    assert_eq!(before, count(&w).await);
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &destination,
        &[
            (&w.admin, "manage"),
            (&mover, "manage"),
            (&editor, "edit"),
            (&new_reader, "view"),
        ],
    )
    .await
    .unwrap();
    let before = count(&w).await;
    call(&w, "acct:mover", "update_record", args).await.unwrap();
    assert_eq!(before, count(&w).await);
    let projections = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        projections,
        kernel::dump_all_kernel_tables(&w.db).await.unwrap()
    );
}

#[tokio::test]
async fn comment_author_archive_matches_v1_bearer_manage_rule() {
    let w = world().await;
    let note = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"Bearer","home_id":w.home}),
    )
    .await["id"]
        .clone();
    let comment=call(&w,"acct:viewer","create_record",json!({"type":"Annotation","kind":"comment","body":"My comment","links":[{"target_id":note,"relationship":"part_of"}]})).await.unwrap()["id"].clone();
    let before = count(&w).await;
    assert!(call(
        &w,
        "acct:viewer",
        "archive_record",
        json!({"id":comment,"reason":"my own comment"})
    )
    .await
    .is_err());
    assert_eq!(before, count(&w).await);
    admin(
        &w,
        "archive_record",
        json!({"id":comment,"reason":"bearer manager"}),
    )
    .await;
    assert!(record(&w, comment.as_str().unwrap()).await.archived);
}

#[tokio::test]
async fn malformed_thread_move_rolls_back_other_record_changes() {
    let w = world().await;
    let note = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"Unchanged","home_id":w.home}),
    )
    .await["id"]
        .clone();
    let root=call(&w,"acct:viewer","create_record",json!({"type":"Annotation","kind":"comment","body":"Thread","links":[{"target_id":note,"relationship":"part_of"}]})).await.unwrap()["id"].clone();
    let other = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"Second bearer","home_id":w.home}),
    )
    .await["id"]
        .clone();
    sqlx::query("INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,note,active,event_seq,created_at,actor,imported) SELECT 'duplicate-bearer',source_id,?,relationship,note,active,event_seq,created_at,actor,imported FROM kernel_generic_links WHERE source_id=?").bind(other.as_str().unwrap()).bind(root.as_str().unwrap()).execute(w.db.write_pool()).await.unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let error = call(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":note,"name":"Must roll back","home_id":w.private}),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("invalid comment thread"),
        "{error}"
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn move_attachments_and_their_threads_switches_all_surfaces_both_directions() {
    let w = world().await;
    let reader = kernel::create_principal(
        &w.db,
        "account",
        "Private reader",
        "acct:private-reader",
        &w.admin,
    )
    .await
    .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.private,
        &[(&w.admin, "manage"), (&reader, "view")],
    )
    .await
    .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    let note = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"Attachmentmoveneedle","home_id":w.home}),
    )
    .await["id"]
        .clone();
    let attachment = call(&w,"acct:viewer","attach_text",json!({"record_id":note,"text":"Attachmentmoveneedle bytes","filename":"Attachmentmoveneedle.txt"})).await.unwrap();
    let aid = attachment["attachment_id"].clone();
    let root = admin(&w,"create_record",json!({"type":"Annotation","kind":"comment","body":"Attachmentmoveneedle thread","links":[{"target_id":aid,"relationship":"part_of"}]})).await["id"].clone();
    let reply = admin(&w,"create_record",json!({"type":"Annotation","kind":"comment","body":"Attachmentmoveneedle reply","links":[{"target_id":root,"relationship":"part_of"}]})).await["id"].clone();
    let annotation = call(&w,"acct:viewer","create_record",json!({"type":"Annotation","kind":"suggestion","name":"Attachmentmoveneedle suggestion","home_id":w.home,"links":[{"target_id":note,"relationship":"part_of"}]})).await.unwrap()["id"].clone();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "view")],
    )
    .await
    .unwrap();
    let ids = vec![
        note.clone(),
        aid.clone(),
        root.clone(),
        reply.clone(),
        annotation.clone(),
    ];
    let unrelated = admin(&w,"create_record",json!({"type":"WorkItem","kind":"task","name":"Independent task","home_id":w.home,"links":[{"target_id":note,"relationship":"part_of"}]})).await["id"].clone();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(
        kernel::rehome_record_as(&w.db, &w.admin, note.as_str().unwrap(), &w.private)
            .await
            .is_err()
    );
    assert!(call(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":aid,"home_id":w.private})
    )
    .await
    .is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    // A refusal after appending cohort events rolls back attachment placement too.
    assert!(call(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":note,"home_id":w.private,"facets":{"blob_ref":"forbidden"}})
    )
    .await
    .is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    for (destination, visible_reader, hidden_reader) in [
        (&w.private, "acct:private-reader", "acct:viewer"),
        (&w.home, "acct:viewer", "acct:private-reader"),
    ] {
        let before: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        admin(
            &w,
            "update_record",
            json!({"id":note,"home_id":destination}),
        )
        .await;
        assert_eq!(
            record(&w, unrelated.as_str().unwrap()).await.home_id,
            w.home
        );
        let acts: Vec<i64> = sqlx::query_scalar(
            "SELECT act FROM content_events WHERE seq>? AND type='kernel.record_rehomed.v2'",
        )
        .bind(before)
        .fetch_all(w.db.pool())
        .await
        .unwrap();
        assert_eq!(acts.len(), ids.len());
        assert!(acts.iter().all(|act| *act == acts[0]));
        for (credential, visible) in [(visible_reader, true), (hidden_reader, false)] {
            let get = call(
                &w,
                credential,
                "get_record",
                json!({"ids":ids,"include_comments":true}),
            )
            .await
            .unwrap();
            assert_eq!(get["records"].as_array().unwrap().len(), ids.len());
            for row in get["records"].as_array().unwrap() {
                if visible {
                    assert_eq!(row["home_id"], *destination);
                    if row["id"] == aid {
                        assert_eq!(row["blob"]["original_filename"], "Attachmentmoveneedle.txt");
                    }
                } else {
                    assert_eq!(row["status"], "not_found");
                    assert!(row.get("blob").is_none());
                }
            }
            let sql = call(
                &w,
                credential,
                "query_sql",
                json!({"sql":"SELECT id,home_id FROM records"}),
            )
            .await
            .unwrap();
            let search = call(
                &w,
                credential,
                "search",
                json!({"query":"Attachmentmoveneedle"}),
            )
            .await
            .unwrap();
            for id in &ids {
                assert_eq!(
                    sql["rows"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|r| r["id"] == *id),
                    visible,
                    "SQL {id}"
                );
                if visible {
                    assert_eq!(
                        sql["rows"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|r| r["id"] == *id)
                            .unwrap()["home_id"],
                        *destination
                    );
                    assert_eq!(
                        search["hits"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .find(|r| r["id"] == *id)
                            .unwrap()["home_id"],
                        *destination
                    );
                }
                assert_eq!(
                    search["hits"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|r| r["id"] == *id),
                    visible,
                    "search {id}"
                );
            }
            for (source, target) in [(&aid, &note), (&root, &aid), (&reply, &root)] {
                let links = call(
                    &w,
                    credential,
                    "manage_links",
                    json!({"action":"list","record_id":source}),
                )
                .await;
                if visible {
                    assert!(links.unwrap()["links"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|l| l["target_id"] == *target));
                } else if let Ok(links) = links {
                    assert!(links["links"].as_array().unwrap().is_empty());
                }
            }
            let bytes = call(
                &w,
                credential,
                "read_attachment",
                json!({"attachment_id":aid}),
            )
            .await;
            let metadata = call(
                &w,
                credential,
                "manage_attachments",
                json!({"action":"inspect","attachment_id":aid}),
            )
            .await;
            if visible {
                let bytes = bytes.unwrap();
                assert_eq!(bytes["content"], "Attachmentmoveneedle bytes");
                assert_eq!(
                    bytes["blob"]["original_filename"],
                    "Attachmentmoveneedle.txt"
                );
                assert_eq!(bytes["blob"]["sha256"], attachment["blob"]["sha256"]);
                assert!(metadata
                    .unwrap()
                    .to_string()
                    .contains("Attachmentmoveneedle.txt"));
            } else {
                assert!(bytes.is_err());
                assert!(metadata.is_err());
                assert!(!get.to_string().contains("Attachmentmoveneedle"));
            }
        }
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn native_folder_children_inherit_policy_and_follow_nested_moves_on_all_surfaces() {
    let w = world().await;
    let outer = admin(&w, "create_record", json!({"type":"Collection","kind":"folder","name":"Folderbindingneedle outer","home_id":w.home})).await["id"].clone();
    let inner = admin(&w, "create_record", json!({"type":"Collection","kind":"folder","name":"Folderbindingneedle inner","home_id":outer})).await["id"].clone();
    let note = admin(&w, "create_record", json!({"type":"Document","kind":"note","name":"Folderbindingneedle note","home_id":inner,"links":[{"relationship":"relates_to","target_id":inner}]})).await["id"].clone();
    let not_folder = call(
        &w,
        "acct:viewer",
        "create_record",
        json!({"type":"Document","kind":"note","home_id":note}),
    )
    .await
    .unwrap_err();
    assert_eq!(
        not_folder.to_string(),
        "home_id must name a live unarchived folder"
    );
    let ids = [outer.clone(), inner.clone(), note.clone()];
    let before = count(&w).await;
    // View is insufficient, including when the physical home is supplied.
    for home in [
        inner.clone(),
        json!(kernel::v1_import_home_id(inner.as_str().unwrap())),
    ] {
        let error = call(
            &w,
            "acct:viewer",
            "create_record",
            json!({"type":"Document","kind":"note","home_id":home}),
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("Edit on the destination folder is required"));
    }
    assert_eq!(count(&w).await, before);
    // Moving into a descendant is refused atomically.
    assert!(call(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":outer,"home_id":inner})
    )
    .await
    .is_err());
    assert_eq!(count(&w).await, before);
    for (destination, visible) in [(&w.home, true), (&w.private, false), (&w.home, true)] {
        admin(
            &w,
            "update_record",
            json!({"id":outer,"home_id":destination}),
        )
        .await;
        let get = call(&w, "acct:viewer", "get_record", json!({"ids":ids}))
            .await
            .unwrap();
        let sql = call(
            &w,
            "acct:viewer",
            "query_sql",
            json!({"sql":"SELECT id,home_id FROM records"}),
        )
        .await
        .unwrap();
        let search = call(
            &w,
            "acct:viewer",
            "search",
            json!({"query":"Folderbindingneedle"}),
        )
        .await
        .unwrap();
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(
                get["records"][i]["status"] != "not_found",
                visible,
                "get {id}"
            );
            assert_eq!(
                sql["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["id"] == *id),
                visible,
                "SQL {id}"
            );
            assert_eq!(
                search["hits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["id"] == *id),
                visible,
                "search {id}"
            );
        }
        if visible {
            assert_eq!(get["records"][2]["home_id"], inner);
            assert_eq!(
                sql["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["id"] == note)
                    .unwrap()["home_id"],
                inner
            );
            assert_eq!(
                search["hits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|r| r["id"] == note)
                    .unwrap()["home_id"],
                inner
            );
        }
        let links = call(
            &w,
            "acct:viewer",
            "manage_links",
            json!({"action":"list","record_id":note}),
        )
        .await;
        if visible {
            assert!(links.unwrap()["links"]
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l["target_id"] == inner));
        } else {
            if let Ok(links) = links {
                assert!(links["links"].as_array().unwrap().is_empty());
            }
            let before = count(&w).await;
            let error = call(
                &w,
                "acct:viewer",
                "create_record",
                json!({"type":"Document","kind":"note","home_id":inner}),
            )
            .await
            .unwrap_err();
            assert_eq!(error.to_string(), kernel::HIDDEN_OR_MISSING);
            assert_eq!(count(&w).await, before);
        }
    }
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    call(
        &w,
        "acct:viewer",
        "create_record",
        json!({"type":"Document","kind":"note","name":"Member child","home_id":inner}),
    )
    .await
    .unwrap();
    // Archival is checked even when addressing the backing home directly.
    admin(&w, "archive_record", json!({"id":inner,"reason":"fixture"})).await;
    let before = count(&w).await;
    for home in [
        inner.clone(),
        json!(kernel::v1_import_home_id(inner.as_str().unwrap())),
    ] {
        assert!(call(
            &w,
            "acct:admin",
            "create_record",
            json!({"type":"Document","kind":"note","home_id":home})
        )
        .await
        .is_err());
    }
    assert_eq!(count(&w).await, before);
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn native_folder_existing_unbound_record_gets_one_binding_on_first_child_write() {
    let w = world().await;
    let fields = v1_compat::compat_fields(
        "Collection",
        "folder",
        Some("Older native folder"),
        None,
        None,
    );
    let folder = kernel::create_json_as(
        &w.db,
        &w.admin,
        v1_compat::FAMILY,
        "record",
        &serde_json::to_string(&fields).unwrap(),
        &w.home,
    )
    .await
    .unwrap();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let error = crate::v1_import::resolve_home_on(&mut tx, &w.viewer, &folder)
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("folder has no child-home binding"));
    let hidden = crate::v1_import::resolve_home_on(&mut tx, &w.viewer, "missing-folder")
        .await
        .unwrap_err();
    assert!(hidden.to_string().contains(kernel::HIDDEN_OR_MISSING));
    tx.rollback().await.unwrap();
    // The member, not the folder owner, can bind it with Edit alone.
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &w.home,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    for _ in 0..2 {
        call(
            &w,
            "acct:viewer",
            "create_record",
            json!({"type":"Document","kind":"note","home_id":folder}),
        )
        .await
        .unwrap();
    }
    let bindings: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type='kernel.home_created.v1' AND json_extract(payload,'$.source_record_id')=?").bind(&folder).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(bindings, 1);
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn native_folder_binding_refuses_forged_owner_parent_policy_and_actor() {
    let w = world().await;
    let fields =
        v1_compat::compat_fields("Collection", "folder", Some("Unbound folder"), None, None);
    let folder = kernel::create_json_as(
        &w.db,
        &w.admin,
        v1_compat::FAMILY,
        v1_compat::KIND,
        &serde_json::to_string(&fields).unwrap(),
        &w.home,
    )
    .await
    .unwrap();
    let home = kernel::v1_import_home_id(&folder);
    let payload =
        json!({"source_record_id":folder,"parent_id":w.home,"owner_id":w.admin,"entries":null});
    let mut wrong_parent = payload.clone();
    wrong_parent["parent_id"] = json!(w.private);
    let mut wrong_owner = payload.clone();
    wrong_owner["owner_id"] = json!(w.viewer);
    let mut own_policy = payload.clone();
    own_policy["entries"] = json!([]);
    for (actor, id, payload) in [
        (&w.admin, home.clone(), wrong_parent),
        (&w.admin, home.clone(), wrong_owner),
        (&w.admin, home.clone(), own_policy),
        (&w.admin, uuid::Uuid::new_v4().to_string(), payload.clone()),
        (&w.viewer, home.clone(), payload),
    ] {
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        let mut tx = begin_write(w.db.write_pool()).await.unwrap();
        let mut acts = ActAllocation::new();
        assert!(event(
            &w.db,
            &mut tx,
            &mut acts,
            actor,
            &id,
            kernel::KERNEL_HOME_CREATED_EVENT,
            payload
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }
}

#[tokio::test]
async fn native_folder_binding_refuses_excessive_depth_without_writing() {
    let w = world().await;
    let mut parent = KERNEL_ROOT_ID.to_owned();
    for _ in 0..100 {
        parent = kernel::create_home(&w.db, &parent, None, &w.admin)
            .await
            .unwrap();
    }
    let fields = v1_compat::compat_fields(
        "Collection",
        "folder",
        Some("Deep unbound folder"),
        None,
        None,
    );
    let folder = kernel::create_json_as(
        &w.db,
        &w.admin,
        v1_compat::FAMILY,
        v1_compat::KIND,
        &serde_json::to_string(&fields).unwrap(),
        &parent,
    )
    .await
    .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = ActAllocation::new();
    let error = kernel::folder_home_in(&w.db, &mut tx, &mut acts, &w.admin, &folder)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("depth limit"), "{error}");
    tx.rollback().await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    let error = call(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Document","kind":"note","home_id":folder}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("depth limit"));
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn native_folder_move_needs_no_import_home_binding() {
    let w = world().await;
    let folder = admin(
        &w,
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Native folder","home_id":w.home}),
    )
    .await["id"]
        .clone();
    for destination in [&w.private, &w.home] {
        admin(
            &w,
            "update_record",
            json!({"id":folder,"home_id":destination}),
        )
        .await;
        assert_eq!(
            record(&w, folder.as_str().unwrap()).await.home_id,
            *destination
        );
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn derived_visibility_agrees_despite_wrong_stored_home_and_missing_bearer() {
    let w = world().await;
    let mut cases = Vec::new();
    for (home, wrong_home, visible) in [(&w.private, &w.home, false), (&w.home, &w.private, true)] {
        let note = admin(
            &w,
            "create_record",
            json!({"type":"Document","kind":"note","name":"Derivedagreement","home_id":home}),
        )
        .await["id"]
            .clone();
        let attachment = admin(
            &w,
            "attach_text",
            json!({"record_id":note,"text":"Derivedagreement bytes","filename":"Derivedagreement.txt"}),
        )
        .await["attachment_id"]
            .clone();
        let annotation=admin(&w,"create_record",json!({"type":"Annotation","kind":"suggestion","name":"Derivedagreement suggestion","home_id":home,"links":[{"target_id":note,"relationship":"part_of"}]})).await["id"].clone();
        for id in [attachment, annotation] {
            sqlx::query("UPDATE kernel_records SET home_id=? WHERE id=?")
                .bind(wrong_home)
                .bind(id.as_str().unwrap())
                .execute(w.db.write_pool())
                .await
                .unwrap();
            cases.push((id, note.clone(), visible));
        }
    }
    let fields = v1_compat::compat_fields(
        "Annotation",
        "suggestion",
        Some("Derivedagreement orphan"),
        None,
        None,
    );
    let orphan = kernel::create_json_as(
        &w.db,
        &w.admin,
        v1_compat::FAMILY,
        v1_compat::KIND,
        &serde_json::to_string(&fields).unwrap(),
        &w.home,
    )
    .await
    .unwrap();
    cases.push((json!(orphan), json!("missing"), false));
    for credential in ["acct:viewer", "acct:admin"] {
        let sql = call(
            &w,
            credential,
            "query_sql",
            json!({"sql":"SELECT id FROM records"}),
        )
        .await
        .unwrap();
        let search = call(
            &w,
            credential,
            "search",
            json!({"query":"Derivedagreement"}),
        )
        .await
        .unwrap();
        for (id, bearer, viewer_visible) in &cases {
            let visible = if credential == "acct:admin" {
                id != &json!(orphan)
            } else {
                *viewer_visible
            };
            let get = call(&w, credential, "get_record", json!({"ids":[id]}))
                .await
                .unwrap();
            assert_eq!(
                get["records"][0]["status"] != "not_found",
                visible,
                "get {id}"
            );
            assert_eq!(
                sql["rows"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["id"] == *id),
                visible,
                "SQL {id}"
            );
            assert_eq!(
                search["hits"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|r| r["id"] == *id),
                visible,
                "search {id}"
            );
            let links = call(
                &w,
                credential,
                "manage_links",
                json!({"action":"list","record_id":id}),
            )
            .await;
            if visible {
                assert!(links.unwrap()["links"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|l| l["target_id"] == *bearer));
            } else if let Ok(links) = links {
                assert!(links["links"].as_array().unwrap().is_empty());
            }
        }
    }
}

#[cfg(all(unix, feature = "v2-kernel-probe"))]
#[tokio::test]
async fn vault_native_folders_and_attachment_visibility_follow_moves() {
    let w = world().await;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&w.viewer, "view")],
    )
    .await
    .unwrap();
    let folder = admin(
        &w,
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Native folder","home_id":w.home}),
    )
    .await;
    let note = admin(
        &w,
        "create_record",
        json!({"type":"Document","kind":"note","name":"Native note","home_id":w.home}),
    )
    .await;
    let attached = admin(
        &w,
        "attach_text",
        json!({"record_id":note["id"],"text":"synthetic attachment","filename":"visible-file.txt"}),
    )
    .await;
    let snapshot = crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:viewer", true),
    )
    .await
    .unwrap();
    let note_id = note["id"].as_str().unwrap();
    let attachment_id = attached["attachment_id"].as_str().unwrap();
    assert_eq!(
        snapshot.records[note_id].home_id.as_deref(),
        Some("native:root")
    );
    assert!(snapshot.records.contains_key(attachment_id));
    admin(
        &w,
        "update_record",
        json!({"id":note_id,"home_id":w.private}),
    )
    .await;
    let snapshot = crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:viewer", true),
    )
    .await
    .unwrap();
    assert!(!snapshot.records.contains_key(note_id));
    assert!(!snapshot.records.contains_key(attachment_id));
    assert!(!snapshot
        .links
        .iter()
        .any(|l| l.source_id == attachment_id || l.target_id == attachment_id));
    assert!(snapshot
        .records
        .contains_key(folder["id"].as_str().unwrap()));
    // Native folder records move through their actual home, without an
    // invented import binding. Their source projection follows the same rule.
    admin(
        &w,
        "update_record",
        json!({"id":folder["id"],"home_id":w.private}),
    )
    .await;
    let moved = crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:viewer", true),
    )
    .await
    .unwrap();
    assert!(!moved.records.contains_key(folder["id"].as_str().unwrap()));
}
