//! Keyed receipts are recovery state: retry against a promoted disposable copy
//! must return the original response, even when later events changed the body.
use super::delta_transport::*;
use super::generation_store::tests::{observed, stage};
use super::*;
use crate::body_merge_flag::{scoped, BodyMergeConfig};
use crate::mcp::registry::{Caller, EngineHandle, ToolRegistry};
use crate::{kernel, Db};
use serde_json::{json, Value};
use std::sync::Arc;

struct Hosted(Db);
impl AuthorityActHttpClient for Hosted {
    fn call(&self, _endpoint: String, _bearer: String, body: Value) -> AuthorityCallFuture {
        let db = self.0.clone();
        Box::pin(async move {
            let args = &body["params"]["arguments"]["arguments"];
            let inventory = serde_json::from_value::<Vec<String>>(args["blob_inventory"].clone())?;
            let delta = observe_authority_act_delta_with_inventory(
                &db,
                "route-1",
                args["from_exclusive_act"].as_i64().unwrap(),
                Some(&inventory),
            )
            .await?;
            Ok(serde_json::to_vec(
                &json!({"jsonrpc":"2.0","id":body["id"],
                "result":{"isError":false,"content":[],"structuredContent":delta}}),
            )?)
        })
    }
}

struct Recovery {
    dir: tempfile::TempDir,
    store: GenerationStore,
    base: InstalledGeneration,
    transport: AuthorityActTransport,
    from: i64,
}
impl Recovery {
    async fn snapshot(db: &Db) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let head = observe_authority_act_head(db, "route-1").await.unwrap();
        let origin = head.head().origin_database_id();
        let store =
            GenerationStore::open(dir.path().join("replica"), "route-1", Some(origin.into()))
                .unwrap();
        let (snapshot, manifest) = stage(&store, db, "before-keyed-write").await;
        let base = store
            .install_staged(&snapshot, &manifest, &observed())
            .await
            .unwrap();
        let transport = AuthorityActTransport::with_client(
            "https://fixture.example",
            "route-1",
            origin,
            "test-token",
            Arc::new(Hosted(db.clone())),
        )
        .unwrap();
        Self {
            dir,
            store,
            base,
            transport,
            from: head.head().head_act(),
        }
    }
    async fn promote(&self) -> Db {
        let inventory = kernel_v2::blob_inventory_path(&self.base.snapshot_path)
            .await
            .unwrap();
        let trusted = self
            .transport
            .kernel_delta(self.from, &inventory)
            .await
            .unwrap();
        let prepared = self
            .store
            .prepare_kernel_delta(&self.base, &trusted, &chrono::Utc::now().to_rfc3339())
            .await
            .unwrap();
        let generation = self
            .store
            .publish_kernel_delta(prepared, &observed())
            .await
            .unwrap();
        // This is a simulated replacement canonical database. Never open the
        // published generation itself writable or enable writes on a standby.
        let path = self.dir.path().join("replacement-canonical.db");
        std::fs::copy(&generation.snapshot_path, &path).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o600);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        std::fs::set_permissions(&path, permissions).unwrap();
        crate::db::open_kernel_v2_head_writer(&path).await.unwrap()
    }
}

async fn fixture() -> (Db, String) {
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
        .await
        .unwrap();
    kernel::prepare_v2_database(&db).await.unwrap();
    let package = crate::v2_standard::v1_compat::package();
    kernel::install_package_as(&db, &admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &admin,
        crate::events::KERNEL_ROOT_ID,
        &package,
        Some(&package.identity().unwrap()),
        &package.declared_reads,
    )
    .await
    .unwrap();
    let document = crate::v2_standard::document4_package();
    kernel::install_package_as(&db, &admin, &document)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &admin,
        crate::events::KERNEL_ROOT_ID,
        &document,
        Some(&document.identity().unwrap()),
        &document.declared_reads,
    )
    .await
    .unwrap();
    // Import the same sealed kind vocabulary that ordinary create admission
    // uses; production writes below still go through the actual registry.
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let v1 = crate::create_database(":memory:").await.unwrap();
    for (section, sql) in [
        ("vocabularies", "SELECT json_object('id',id,'name',name,'created_at',created_at) FROM vocabularies"),
        ("vocabulary_values", "SELECT json_object('id',id,'vocabulary_id',vocabulary_id,'value',value,'gloss',gloss,'status',status,'ordinal',ordinal,'terminality',terminality,'metadata',metadata,'alias_of',alias_of) FROM vocabulary_values"),
    ] {
        let raw: Vec<String> = sqlx::query_scalar(sql).fetch_all(v1.pool()).await.unwrap();
        let rows = raw.into_iter().map(|raw| {
            let row: Value = serde_json::from_str(&raw).unwrap();
            kernel::v1_state::ImportedState { section: section.into(), source_id: row["id"].as_str().unwrap().into(),
                origin: "keyed-recovery-proof".into(), value_json: Some(raw), account_principal: None,
                record_id: None, observed_at: "2026-11-08T00:00:00Z".into(), snapshot: json!({}) }
        }).collect::<Vec<_>>();
        for batch in rows.chunks(256) { kernel::v1_state::import_state_batch_as(&db, &host, batch).await.unwrap(); }
    }
    v1.close().await;
    (db, admin)
}
async fn call(db: &Db, operation: &str, args: Value) -> crate::Result<Value> {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("acct:owner"),
            operation,
            args,
        )
        .await
}
async fn record(db: &Db, body: &str) -> String {
    call(db, "create_record", json!({"type":"Document","kind":"note","name":"Recovery proof","body":body,"reason":"fixture"}))
        .await.unwrap()["id"].as_str().unwrap().into()
}
async fn set_body(db: &Db, actor: &str, id: &str, body: &str) {
    let revision = kernel::read_record_as(db, actor, id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_body_as(db, actor, id, body, revision)
        .await
        .unwrap();
}
async fn version(db: &Db, id: &str) -> String {
    let seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    format!("rec:{seq}")
}
fn intent(id: &str, base_version: &str, base: &str, mine: &str, key: &str) -> Value {
    json!({"record_id":id,"base_version":base_version,"base_text":base,"my_text":mine,"reason":"held edit","idempotency_key":key})
}
async fn event_count(db: &Db) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE type!='kernel.mcp_write_receipt_recorded.v1'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn kernel_v2_promoted_merge_replays_original_full_receipt_after_newer_body() {
    let _flag = scoped(BodyMergeConfig {
        enabled: true,
        accounts: None,
    });
    let (db, admin) = fixture().await;
    let base = format!("{}\nend\n", "large original body line\n".repeat(1000));
    let mine = format!("{base}my addition\n");
    let id = record(&db, &base).await;
    let args = intent(&id, &version(&db, &id).await, &base, &mine, "original");
    let recovery = Recovery::snapshot(&db).await;
    let original = call(&db, "merge_body", args.clone()).await.unwrap();
    assert_eq!(original["outcome"], "merged");
    assert_eq!(original["result"]["body"], mine);
    assert!(original.get("write_receipt").is_some());
    set_body(&db, &admin, &id, "later canonical body").await;
    let promoted = recovery.promote().await;
    let before = event_count(&promoted).await;
    for _ in 0..2 {
        assert_eq!(call(&promoted, "merge_body", args.clone()).await.unwrap(), original,
            "recovery must retain the full original response, not re-evaluate against the newer body");
    }
    let mut changed = args;
    changed["my_text"] = json!("different request under original key");
    assert!(call(&promoted, "merge_body", changed).await.is_err());
    assert_eq!(event_count(&promoted).await, before);
    assert_eq!(
        kernel::read_record_as(&promoted, &admin, &id)
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some("later canonical body")
    );
    promoted.close().await;
    db.close().await;
}

#[tokio::test(flavor = "current_thread")]
async fn kernel_v2_promoted_receipt_only_clash_and_unchanged_merges_never_reapply() {
    let _flag = scoped(BodyMergeConfig {
        enabled: true,
        accounts: None,
    });
    let (db, admin) = fixture().await;
    let clash_id = record(&db, "abc").await;
    let unchanged_id = record(&db, "abc").await;
    let clash_args = intent(
        &clash_id,
        &version(&db, &clash_id).await,
        "abc",
        "axc",
        "clash",
    );
    let unchanged_args = intent(
        &unchanged_id,
        &version(&db, &unchanged_id).await,
        "abc",
        "abc",
        "unchanged",
    );
    set_body(&db, &admin, &clash_id, "ayc").await;
    set_body(&db, &admin, &unchanged_id, "abcd").await;
    let recovery = Recovery::snapshot(&db).await;
    let before = event_count(&db).await;
    let clash = call(&db, "merge_body", clash_args.clone()).await.unwrap();
    let unchanged = call(&db, "merge_body", unchanged_args.clone())
        .await
        .unwrap();
    assert_eq!(clash["outcome"], "merged_with_clashes");
    assert_eq!(clash["applied_hunks"], 0);
    assert_eq!(unchanged["changed"], false);
    assert_eq!(
        event_count(&db).await,
        before,
        "these receipts have no content events"
    );
    // Restore the bases after the original responses. Re-evaluating the clash
    // now would apply 'axc', so exact response plus unchanged body proves replay.
    set_body(&db, &admin, &clash_id, "abc").await;
    set_body(&db, &admin, &unchanged_id, "abc").await;
    let promoted = recovery.promote().await;
    let before = event_count(&promoted).await;
    for (args, expected) in [(clash_args, clash), (unchanged_args, unchanged)] {
        assert_eq!(
            call(&promoted, "merge_body", args.clone()).await.unwrap(),
            expected
        );
        let mut changed = args;
        changed["reason"] = json!("different intent");
        assert!(call(&promoted, "merge_body", changed).await.is_err());
    }
    assert_eq!(event_count(&promoted).await, before);
    for id in [&clash_id, &unchanged_id] {
        assert_eq!(
            kernel::read_record_as(&promoted, &admin, id)
                .await
                .unwrap()
                .unwrap()
                .body
                .as_deref(),
            Some("abc")
        );
    }
    promoted.close().await;
    db.close().await;
}

#[tokio::test]
async fn kernel_v2_promoted_keyed_create_returns_same_record_without_duplicate_effect() {
    let (db, admin) = fixture().await;
    let recovery = Recovery::snapshot(&db).await;
    let args = json!({"type":"Document","kind":"note","name":"Exactly once","body":"original","reason":"recovery proof","idempotency_key":"create-once"});
    let original = call(&db, "create_record", args.clone()).await.unwrap();
    let promoted = recovery.promote().await;
    let before = event_count(&promoted).await;
    assert_eq!(
        call(&promoted, "create_record", args.clone())
            .await
            .unwrap(),
        original
    );
    let mut changed = args;
    changed["name"] = json!("Different request");
    assert!(call(&promoted, "create_record", changed).await.is_err());
    assert_eq!(
        event_count(&promoted).await,
        before,
        "recovery retry must not create a second record"
    );

    // Recovery must permit new canonical work that survives reopening.
    let fresh_args = json!({"type":"Document","kind":"note","name":"After recovery",
        "body":"Persisted after recovery","reason":"writable recovery proof",
        "idempotency_key":"after-recovery"});
    let fresh = call(&promoted, "create_record", fresh_args.clone())
        .await
        .unwrap();
    assert_ne!(fresh["id"], original["id"]);
    let after_fresh = event_count(&promoted).await;
    assert!(after_fresh > before);
    promoted.close().await;

    let reopened = crate::db::open_kernel_v2_head_writer(
        &recovery.dir.path().join("replacement-canonical.db"),
    )
    .await
    .unwrap();
    assert_eq!(
        kernel::read_record_as(&reopened, &admin, fresh["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some("Persisted after recovery")
    );
    assert_eq!(
        call(&reopened, "create_record", fresh_args).await.unwrap(),
        fresh
    );
    let original_args = json!({"type":"Document","kind":"note","name":"Exactly once",
        "body":"original","reason":"recovery proof","idempotency_key":"create-once"});
    assert_eq!(
        call(&reopened, "create_record", original_args)
            .await
            .unwrap(),
        original
    );
    assert_eq!(event_count(&reopened).await, after_fresh);
    reopened.close().await;
    db.close().await;
}

mod in_place;
