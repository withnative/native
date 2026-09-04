//! Stage 7 — blobs & attachments (tools 22, 24, 25) + the `blob` byte tier.
//! Tool 23 (`attach_from_url`) and its SSRF guard live in
//! `tests/tools/fetch_guard.rs`.
//!
//! The substrate boundary under test: attachment BYTES are direct writes to
//! `blobs` (never events), the RECORDS referencing them go append-event →
//! project, and the rebuild-and-diff replay stays equal throughout.

use base64::Engine as _;
use native_ce::blob;
use native_ce::conformance::rebuild_and_diff;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::store::{append_batch, create_record, AppendSpec};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::common::count;

async fn db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    db
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(
    registry: &ToolRegistry,
    db: &Db,
    tool: &str,
    args: Value,
) -> native_ce::Result<Value> {
    registry.call(db.clone(), Caller::local(), tool, args).await
}

async fn parent(db: &Db) -> String {
    create_record(
        db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap()
}

/// Attach `text` and return the tool's payload.
async fn attach(
    registry: &ToolRegistry,
    db: &Db,
    record_id: &str,
    text: &str,
    extra: Value,
) -> Value {
    let mut args = json!({ "record_id": record_id, "text": text });
    if let (Some(target), Some(source)) = (args.as_object_mut(), extra.as_object()) {
        for (k, v) in source {
            target.insert(k.clone(), v.clone());
        }
    }
    call(registry, db, "attach_text", args).await.unwrap()
}

// ---------------------------------------------------------------------------
// Tool 22 — attach_text
// ---------------------------------------------------------------------------

#[tokio::test]
async fn attach_text_writes_blob_directly_and_record_through_events() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;
    let events_before = count(&db, "SELECT COUNT(*) AS n FROM content_events").await;

    let result = attach(
        &registry,
        &db,
        &root,
        "hello attachment",
        json!({
            "filename": "notes.md",
            "mime": "text/markdown",
            "facets": {
                "capture_method": "manual",
                "review": { "value": "needed" }
            }
        }),
    )
    .await;

    // Blob metadata is computed by the shared helper: sha256/size/tier.
    let blob = &result["blob"];
    assert_eq!(blob["mime"], "text/markdown");
    assert_eq!(blob["size_bytes"], 16);
    assert_eq!(
        blob["sha256"].as_str().unwrap(),
        hex::encode(Sha256::digest(b"hello attachment"))
    );
    assert_eq!(blob["storage_tier"], "inline");
    assert_eq!(blob["original_filename"], "notes.md");
    assert_eq!(result["record_id"], json!(root));
    assert_eq!(result["name"], "notes.md");

    // The record went through the log: record.created + part_of + the engine
    // binding + caller facets, atomically.
    let attachment_id = result["attachment_id"].as_str().unwrap();
    let events_after = count(&db, "SELECT COUNT(*) AS n FROM content_events").await;
    assert_eq!(events_after - events_before, 5);
    let record = sqlx::query(&format!(
        "SELECT type, kind, home_id FROM records WHERE id = '{attachment_id}'"
    ))
    .fetch_one(db.pool())
    .await
    .unwrap();
    use sqlx::Row as _;
    assert_eq!(record.get::<String, _>("type"), "Document");
    assert_eq!(record.get::<String, _>("kind"), "attachment");
    assert_eq!(record.get::<String, _>("home_id"), root);
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT target_id FROM links WHERE source_id = '{attachment_id}' AND relationship = 'part_of'"),
            "target_id"
        )
        .await
        .as_deref(),
        Some(root.as_str())
    );
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT value FROM facet_values WHERE record_id = '{attachment_id}' AND key = 'blob_ref'"),
            "value"
        )
        .await
        .as_deref(),
        blob["id"].as_str()
    );
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT value FROM facet_values WHERE record_id = '{attachment_id}' AND key = 'capture_method'"),
            "value"
        )
        .await
        .as_deref(),
        Some("manual")
    );
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT value FROM facet_values WHERE record_id = '{attachment_id}' AND key = 'review'"),
            "value"
        )
        .await
        .as_deref(),
        Some("needed")
    );

    // The BYTES did not go through the log — no event mentions the blob — and
    // replay equality holds with direct blob writes in the database.
    let blob_id = blob["id"].as_str().unwrap();
    assert_eq!(
        count(
            &db,
            &format!("SELECT COUNT(*) AS n FROM content_events WHERE payload LIKE '%{blob_id}%' AND type NOT IN ('facet.set')")
        )
        .await,
        0
    );
    let diff = rebuild_and_diff(&db).await.unwrap();
    assert!(diff.equal, "{diff:?}");
    db.close().await;
}

#[tokio::test]
async fn attach_text_defaults_mime_and_name() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;
    let result = attach(&registry, &db, &root, "x", json!({})).await;
    assert_eq!(result["blob"]["mime"], "text/plain; charset=utf-8");
    assert_eq!(result["name"], "attachment");
    assert_eq!(result["blob"]["original_filename"], Value::Null);
    db.close().await;
}

#[tokio::test]
async fn update_record_cannot_overwrite_or_unset_attachment_blob_binding() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;
    let created = attach(&registry, &db, &root, "original", json!({})).await;
    let id = created["attachment_id"].as_str().unwrap();

    for attempted in [json!("garbage"), Value::Null] {
        let err = call(
            &registry,
            &db,
            "update_record",
            json!({
                "id": id,
                "reason": "attempt to corrupt engine-owned facet",
                "facets": { "blob_ref": attempted }
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "update_record: facet 'blob_ref' is engine-reserved — create attachment bindings via the attach_text or attach_from_url tool"
        );
    }

    let read = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": id }),
    )
    .await
    .unwrap();
    assert_eq!(read["content"], "original");
    db.close().await;
}

#[tokio::test]
async fn attach_text_inherits_spine_and_engine_reserved_facet_guards() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;

    for (key, expected) in [
        (
            "blob_ref",
            "attach_text: facet 'blob_ref' is engine-reserved — create attachment bindings via the attach_text or attach_from_url tool",
        ),
        (
            "archived",
            "attach_text: facet 'archived' is engine-reserved — archive and restore via the archive_record tool",
        ),
    ] {
        let err = call(
            &registry,
            &db,
            "attach_text",
            json!({ "record_id": root, "text": "x", "facets": { (key): "bad" } }),
        )
        .await
        .unwrap_err();
        assert_eq!(err.to_string(), expected);
    }
    let err = call(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": root, "text": "x", "facets": { "lifecycle": "ready" } }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "attach_text: 'lifecycle' is a spine facet — set it via the top-level 'lifecycle' argument, not 'facets'"
    );

    assert_eq!(count(&db, "SELECT COUNT(*) AS n FROM blobs").await, 0);
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) AS n FROM records WHERE kind = 'attachment'"
        )
        .await,
        0
    );
    db.close().await;
}

#[tokio::test]
async fn attach_text_rejects_bad_arguments_and_dead_targets() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;

    let err = call(&registry, &db, "attach_text", json!({ "text": "x" }))
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid arguments for attach_text: missing field `record_id`"
    );
    let err = call(&registry, &db, "attach_text", json!({ "record_id": root }))
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid arguments for attach_text: missing field `text`"
    );
    let err = call(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": "nope", "text": "x" }),
    )
    .await
    .unwrap_err();
    assert_eq!(err.to_string(), "attach_text: record nope does not exist");

    native_ce::store::delete_record(&db, &root).await.unwrap();
    let err = call(
        &registry,
        &db,
        "attach_text",
        json!({ "record_id": root, "text": "x" }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("attach_text: record {root} is deleted (tombstoned)")
    );
    db.close().await;
}

// ---------------------------------------------------------------------------
// Tool 24 — read_attachment
// ---------------------------------------------------------------------------

#[tokio::test]
async fn read_attachment_pages_through_byte_ranges() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;
    let created = attach(&registry, &db, &root, "0123456789", json!({})).await;
    let id = created["attachment_id"].as_str().unwrap();

    let page = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": id, "offset": 0, "length": 4 }),
    )
    .await
    .unwrap();
    assert_eq!(page["content"], "0123");
    assert_eq!(page["content_encoding"], "utf-8");
    assert_eq!(page["length"], 4);
    assert_eq!(page["eof"], false);
    assert_eq!(page["blob"]["size_bytes"], 10);

    let page = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": id, "offset": 8, "length": 4 }),
    )
    .await
    .unwrap();
    assert_eq!(page["content"], "89");
    assert_eq!(page["length"], 2);
    assert_eq!(page["eof"], true);

    // Past the end: empty page, eof.
    let page = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": id, "offset": 100, "length": 4 }),
    )
    .await
    .unwrap();
    assert_eq!(page["content"], "");
    assert_eq!(page["eof"], true);

    // Default read covers the whole small blob.
    let page = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": id }),
    )
    .await
    .unwrap();
    assert_eq!(page["content"], "0123456789");
    assert_eq!(page["eof"], true);
    db.close().await;
}

/// Build an attachment record over raw bytes without the text tool — the
/// byte-tier helper + the event batch, exactly what the tools compose.
async fn attach_bytes(db: &Db, home_id: &str, bytes: &[u8], mime: &str) -> String {
    let meta = blob::insert_blob(db, bytes, Some(mime), None)
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    append_batch(
        db,
        vec![
            AppendSpec {
                record_id: id.clone(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Document", "kind": "attachment",
                    "name": "bin", "home_id": home_id,
                }),
                actor: None,
            },
            AppendSpec {
                record_id: id.clone(),
                event_type: "facet.set".into(),
                payload: json!({ "key": "blob_ref", "value": meta.id }),
                actor: None,
            },
            AppendSpec {
                record_id: id.clone(),
                event_type: "link.added".into(),
                payload: json!({
                    "source_id": id, "target_id": home_id, "relationship": "part_of"
                }),
                actor: None,
            },
        ],
    )
    .await
    .unwrap();
    id
}

#[tokio::test]
async fn read_attachment_returns_binary_as_base64() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;
    let bytes: Vec<u8> = vec![0x00, 0x9f, 0x92, 0x96, 0xff, 0x01];
    let id = attach_bytes(&db, &root, &bytes, "application/octet-stream").await;

    let page = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": id }),
    )
    .await
    .unwrap();
    assert_eq!(page["content_encoding"], "base64");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(page["content"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, bytes);

    // A texty mime whose RANGE splits a multi-byte sequence still comes back
    // safely, as base64.
    let id = attach_bytes(&db, &root, "héllo".as_bytes(), "text/plain").await;
    let page = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": id, "offset": 0, "length": 2 }),
    )
    .await
    .unwrap();
    assert_eq!(page["content_encoding"], "base64");
    db.close().await;
}

#[tokio::test]
async fn read_attachment_rejects_non_attachments_and_bad_ranges() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;

    let err = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": "nope" }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "read_attachment: attachment nope does not exist"
    );

    let err = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": root }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("read_attachment: attachment {root} does not exist")
    );

    // A Document kind:attachment with no blob_ref facet is malformed.
    let orphan = create_record(
        &db,
        json!({ "type": "Document", "kind": "attachment", "name": "no-blob", "home_id": root }),
    )
    .await
    .unwrap();
    let err = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": orphan }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("read_attachment: attachment {orphan} does not exist")
    );

    let created = attach(&registry, &db, &root, "x", json!({})).await;
    let id = created["attachment_id"].as_str().unwrap();
    let err = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": id, "length": 10_000_000 }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "read_attachment: 'length' must be between 1 and 524288"
    );
    db.close().await;
}

// ---------------------------------------------------------------------------
// Tool 25 — manage_attachments
// ---------------------------------------------------------------------------

#[tokio::test]
async fn manage_attachments_lists_live_attachments_with_metadata() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;
    let a = attach(&registry, &db, &root, "aaa", json!({ "filename": "a.txt" })).await;
    let b = attach(
        &registry,
        &db,
        &root,
        "bbbb",
        json!({ "filename": "b.txt" }),
    )
    .await;
    let c = attach(&registry, &db, &root, "c", json!({ "filename": "c.txt" })).await;
    // A non-attachment child must not appear.
    create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "not an attachment", "home_id": root }),
    )
    .await
    .unwrap();

    call(
        &registry,
        &db,
        "manage_attachments",
        json!({ "action": "detach", "attachment_id": c["attachment_id"] }),
    )
    .await
    .unwrap();

    let listed = call(
        &registry,
        &db,
        "manage_attachments",
        json!({ "action": "list", "record_id": root }),
    )
    .await
    .unwrap();
    let attachments = listed["attachments"].as_array().unwrap();
    assert_eq!(attachments.len(), 2); // c is detached, the task is not listed
                                      // Same-millisecond creation makes the (created_at, id) sort order
                                      // nondeterministic BETWEEN a and b, so look entries up by id.
    let entry = |of: &serde_json::Value| {
        attachments
            .iter()
            .find(|e| e["attachment_id"] == of["attachment_id"])
            .unwrap_or_else(|| panic!("{} not listed", of["attachment_id"]))
            .clone()
    };
    let listed_a = entry(&a);
    assert_eq!(listed_a["name"], "a.txt");
    assert_eq!(listed_a["size_bytes"], 3);
    assert_eq!(listed_a["mime"], "text/plain; charset=utf-8");
    assert_eq!(listed_a["sha256"], a["blob"]["sha256"]);
    assert_eq!(listed_a["blob_id"], a["blob"]["id"]);
    let listed_b = entry(&b);
    assert_eq!(listed_b["name"], "b.txt");
    assert_eq!(listed_b["size_bytes"], 4);

    let err = call(
        &registry,
        &db,
        "manage_attachments",
        json!({ "action": "list", "record_id": "nope" }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "manage_attachments: record nope does not exist"
    );
    db.close().await;
}

#[tokio::test]
async fn detach_soft_deletes_the_record_and_retains_the_blob() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;
    let created = attach(&registry, &db, &root, "keep my bytes", json!({})).await;
    let id = created["attachment_id"].as_str().unwrap();
    let blob_id = created["blob"]["id"].as_str().unwrap();

    let detached = call(
        &registry,
        &db,
        "manage_attachments",
        json!({ "action": "detach", "attachment_id": id }),
    )
    .await
    .unwrap();
    assert_eq!(detached["detached"], true);
    assert_eq!(detached["blob_retained"], true);
    assert_eq!(detached["blob_id"], json!(blob_id));

    // Soft delete went THROUGH the log: a record.deleted event exists and the
    // projection is tombstoned.
    assert_eq!(
        count(
            &db,
            &format!("SELECT COUNT(*) AS n FROM content_events WHERE record_id = '{id}' AND type = 'record.deleted'")
        )
        .await,
        1
    );
    assert!(crate::common::text_of(
        &db,
        &format!("SELECT deleted_at FROM records WHERE id = '{id}'"),
        "deleted_at"
    )
    .await
    .is_some());

    // The BLOB is retained, but the detached artifact is no longer readable.
    assert_eq!(
        count(
            &db,
            &format!("SELECT COUNT(*) AS n FROM blobs WHERE id = '{blob_id}'")
        )
        .await,
        1
    );
    let read_error = call(
        &registry,
        &db,
        "read_attachment",
        json!({ "attachment_id": id }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        read_error,
        format!("read_attachment: attachment {id} does not exist")
    );

    // Inspect and a second detach use the same artifact-level not-found shape.
    let inspected = call(
        &registry,
        &db,
        "manage_attachments",
        json!({ "action": "inspect", "attachment_id": id }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(
        inspected,
        format!("manage_attachments: attachment {id} does not exist")
    );
    let err = call(
        &registry,
        &db,
        "manage_attachments",
        json!({ "action": "detach", "attachment_id": id }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("manage_attachments: attachment {id} does not exist")
    );

    // Replay equality holds across the whole attach/detach lifecycle.
    let diff = rebuild_and_diff(&db).await.unwrap();
    assert!(diff.equal, "{diff:?}");
    db.close().await;
}

#[tokio::test]
async fn manage_attachments_rejects_bad_actions_and_targets() {
    let db = db().await;
    let registry = registry();
    let root = parent(&db).await;

    let err = call(
        &registry,
        &db,
        "manage_attachments",
        json!({ "action": "zap" }),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("invalid arguments for manage_attachments: unknown variant `zap`"),
        "{err}"
    );
    let err = call(&registry, &db, "manage_attachments", json!({}))
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "invalid arguments for manage_attachments: missing field `action`"
    );
    let err = call(
        &registry,
        &db,
        "manage_attachments",
        json!({ "action": "detach", "attachment_id": root }),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("manage_attachments: attachment {root} does not exist")
    );
    db.close().await;
}

// ---------------------------------------------------------------------------
// The blob byte tier directly
// ---------------------------------------------------------------------------

#[tokio::test]
async fn blob_helpers_round_trip_metadata_and_ranges() {
    let db = db().await;
    let meta = blob::insert_blob(&db, b"0123456789", Some("text/plain"), Some("digits.txt"))
        .await
        .unwrap();
    assert_eq!(meta.size_bytes, 10);
    assert_eq!(meta.sha256, hex::encode(Sha256::digest(b"0123456789")));
    assert_eq!(meta.storage_tier, "inline");

    let fetched = blob::get_meta(&db, &meta.id).await.unwrap().unwrap();
    assert_eq!(fetched.sha256, meta.sha256);
    assert_eq!(fetched.original_filename.as_deref(), Some("digits.txt"));
    assert!(blob::get_meta(&db, "nope").await.unwrap().is_none());

    let slice = blob::read_range(&db, &meta.id, 2, 4)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(slice.bytes, b"2345");
    assert_eq!(slice.total_size, 10);
    assert!(!slice.eof);
    let slice = blob::read_range(&db, &meta.id, 8, 100)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(slice.bytes, b"89");
    assert!(slice.eof);
    assert!(blob::read_range(&db, "nope", 0, 1).await.unwrap().is_none());

    // An external-tier row refuses ranged reads in v1.
    sqlx::query("INSERT INTO blobs (id, bytes, storage_tier, external_ref) VALUES ('ext', NULL, 'external', 's3://x')")
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let err = blob::read_range(&db, "ext", 0, 1).await.unwrap_err();
    assert!(err.to_string().contains("stored externally"), "{err}");
    db.close().await;
}
