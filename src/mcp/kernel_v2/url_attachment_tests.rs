//! KernelV2 `attach_from_url`: guarded fetch, provenance, preflight without
//! HTTP, keyed replay/conflict and atomic rollback.
//!
//! Fixture-only: every fetch hits a loopback server through an explicit
//! test-only `FetchConfig { allow_loopback: true, .. }`. No production
//! fetch runs here. The handler under test is the same
//! `writes::url_attachment::execute` the engine dispatches; only the config
//! differs.

use super::*;
use crate::mcp::fetch::FetchConfig;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct World {
    _dir: tempfile::TempDir,
    db: Db,
    admin: String,
    first: String,
    hidden: String,
}

async fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("v2.db").to_str().unwrap(),
        "account",
        "Admin",
        "acct:admin",
    )
    .await
    .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
        .await
        .unwrap();
    let definition = json!({
        "family": "fixture.mcp", "version": 1, "interpreter": "native.defn/2",
        "primary_type": "Document", "kinds": [{"token": "note", "description": "MCP fixture",
            "maturity": "current", "identity": {"field": "title"},
            "fields": [{"name": "title", "type": "text", "required": true}, {"name": "body", "type": "text", "required": false}],
            "links": [{"predicate": "relates_to", "target": {"primary_type": "Document", "kind": "note"}, "direction": "out", "cardinality": "many"}]}]
    });
    let pin = kernel::install_definition_as(
        &db,
        &admin,
        "fixture.mcp",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&db, &admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    // Attachment creation resolves the v1_compat family through adoption:
    // without this every success case fails before reaching assertions.
    let manifest = crate::v2_standard::v1_compat::package();
    let identity = manifest.identity().unwrap();
    kernel::install_package_as(&db, &admin, &manifest)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &admin,
        crate::events::KERNEL_ROOT_ID,
        &manifest,
        Some(&identity),
        &manifest.declared_reads,
    )
    .await
    .unwrap();
    let home = kernel::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&viewer, "view")]),
        &admin,
    )
    .await
    .unwrap();
    let private = kernel::create_home(&db, crate::events::KERNEL_ROOT_ID, Some(&[]), &admin)
        .await
        .unwrap();
    let mut ids = Vec::new();
    for (title, home) in [("Alpha", &home), ("Secret", &private)] {
        ids.push(
            kernel::create_as(
                &db,
                &admin,
                "fixture.mcp",
                "note",
                json!({"title": title, "body": "original"})
                    .as_object()
                    .unwrap(),
                home,
            )
            .await
            .unwrap(),
        );
    }
    World {
        _dir: dir,
        db,
        admin,
        first: ids[0].clone(),
        hidden: ids[1].clone(),
    }
}

fn loopback_config() -> FetchConfig {
    FetchConfig {
        allow_loopback: true,
        ..FetchConfig::default()
    }
}

async fn attach(
    world: &World,
    credential: &str,
    args: Value,
    config: &FetchConfig,
) -> Result<Value> {
    let caller = Caller::authenticated(credential);
    let actor = super::principal(&world.db, &caller).await?;
    super::writes::url_attachment::execute(&world.db, &actor, args, config).await
}

/// Scriptable loopback HTTP: `routes(path)` returns the complete raw
/// response for each request. Every accepted connection counts one hit.
async fn serve(
    routes: impl Fn(&str) -> Vec<u8> + Send + Sync + 'static,
    hits: Arc<AtomicUsize>,
) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while let Ok(n) = socket.read(&mut chunk).await {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&buf);
            let path = request.split_whitespace().nth(1).unwrap_or("/").to_string();
            hits.fetch_add(1, Ordering::SeqCst);
            let _ = socket.write_all(&routes(&path)).await;
            let _ = socket.shutdown().await;
        }
    });
    addr
}

fn ok_bytes(body: &[u8], content_type: &str) -> Vec<u8> {
    let mut head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    head.extend_from_slice(body);
    head
}

fn redirect(location: &str) -> Vec<u8> {
    format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

/// Non-UTF8 binary, PNG header included so the bytes are unmistakably binary.
fn png_bytes() -> Vec<u8> {
    let mut bytes = vec![137, 80, 78, 71, 13, 10, 26, 10, 0, 1, 2, 3];
    bytes.extend_from_slice(&[0xff, 0xfe, 0x00, 0x80, 0x01, 0x02, 0x03, 0x04]);
    bytes
}

async fn facet_value(db: &Db, id: &str, key: &str) -> Option<String> {
    sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key=?")
        .bind(id)
        .bind(key)
        .fetch_optional(db.pool())
        .await
        .unwrap()
}

async fn attachment_count(db: &Db, bearer: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM kernel_generic_links WHERE target_id=? AND relationship='part_of' AND active=1",
    )
    .bind(bearer)
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[tokio::test]
async fn attaches_binary_bytes_with_source_provenance() {
    let w = world().await;
    let config = loopback_config();
    let body = png_bytes();
    let addr = serve(
        {
            let body = body.clone();
            move |path| {
                assert_eq!(path, "/files/pixel.png");
                ok_bytes(&body, "image/png")
            }
        },
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    let url = format!("http://{addr}/files/pixel.png");
    let receipt = attach(
        &w,
        "acct:admin",
        json!({"record_id": w.first, "url": url}),
        &config,
    )
    .await
    .unwrap();
    let id = receipt["attachment_id"].as_str().unwrap().to_owned();
    assert_eq!(receipt["record_id"], json!(w.first));
    assert_eq!(receipt["name"], json!("pixel.png"));
    assert_eq!(receipt["url"], json!(url));
    assert_eq!(receipt["final_url"], json!(url));
    assert_eq!(receipt["redirects"], json!(0));
    assert_eq!(receipt["blob"]["mime"], json!("image/png"));
    assert_eq!(receipt["blob"]["size_bytes"], json!(body.len() as i64));
    // Binary bytes round-trip intact at the blob tier.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT bytes FROM kernel_blobs WHERE sha256=?")
        .bind(receipt["blob"]["sha256"].as_str().unwrap())
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(stored, body);
    // Provenance names the requested URL and the attachment hangs under
    // its bearer via exactly one part_of link.
    assert_eq!(
        facet_value(&w.db, &id, "source_url").await.as_deref(),
        Some(url.as_str())
    );
    let links: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM kernel_generic_links WHERE source_id=? AND relationship='part_of' AND active=1",
    )
    .bind(&id)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert_eq!(links, [w.first]);
    w.db.close().await;
}

#[tokio::test]
async fn records_redirect_chain_and_keeps_request_provenance() {
    let w = world().await;
    let config = loopback_config();
    let body = png_bytes();
    let addr = serve(
        {
            let body = body.clone();
            move |path| match path {
                "/old" => redirect("/final.bin"),
                "/final.bin" => ok_bytes(&body, "application/octet-stream"),
                other => panic!("unexpected path {other}"),
            }
        },
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    let url = format!("http://{addr}/old");
    let receipt = attach(
        &w,
        "acct:admin",
        json!({"record_id": w.first, "url": url}),
        &config,
    )
    .await
    .unwrap();
    let id = receipt["attachment_id"].as_str().unwrap().to_owned();
    assert_eq!(
        receipt["final_url"],
        json!(format!("http://{addr}/final.bin"))
    );
    assert_eq!(receipt["redirects"], json!(1));
    // The filename follows the FINAL url; provenance still names the request.
    assert_eq!(receipt["name"], json!("final.bin"));
    assert_eq!(
        facet_value(&w.db, &id, "source_url").await.as_deref(),
        Some(url.as_str())
    );
    w.db.close().await;
}

#[tokio::test]
async fn preflight_denies_without_http() {
    let w = world().await;
    let config = loopback_config();
    let hits = Arc::new(AtomicUsize::new(0));
    let addr = serve(
        |_| ok_bytes(b"must never fetch", "text/plain"),
        hits.clone(),
    )
    .await;
    let url = format!("http://{addr}/never");
    // Missing bearer.
    attach(
        &w,
        "acct:admin",
        json!({"record_id": "00000000-0000-0000-0000-000000000000", "url": url}),
        &config,
    )
    .await
    .unwrap_err();
    // Hidden bearer for the viewer.
    attach(
        &w,
        "acct:viewer",
        json!({"record_id": w.hidden, "url": url}),
        &config,
    )
    .await
    .unwrap_err();
    // Visible but not editable for the viewer (home grants view only).
    attach(
        &w,
        "acct:viewer",
        json!({"record_id": w.first, "url": url}),
        &config,
    )
    .await
    .unwrap_err();
    // Invalid cap and scheme never reach the network either.
    attach(
        &w,
        "acct:admin",
        json!({"record_id": w.first, "url": url, "max_bytes": 0}),
        &config,
    )
    .await
    .unwrap_err();
    attach(
        &w,
        "acct:admin",
        json!({"record_id": w.first, "url": "ftp://example.com/file"}),
        &config,
    )
    .await
    .unwrap_err();
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no denied call may fetch");
    w.db.close().await;
}

#[tokio::test]
async fn keyed_replay_skips_refetch_and_returns_same_receipt() {
    let w = world().await;
    let config = loopback_config();
    let hits = Arc::new(AtomicUsize::new(0));
    let addr = serve(|_| ok_bytes(b"stable bytes", "text/plain"), hits.clone()).await;
    let args = json!({"record_id": w.first, "url": format!("http://{addr}/stable"), "idempotency_key": "url-attach-replay-1"});
    let first = attach(&w, "acct:admin", args.clone(), &config)
        .await
        .unwrap();
    let second = attach(&w, "acct:admin", args.clone(), &config)
        .await
        .unwrap();
    assert_eq!(first["attachment_id"], second["attachment_id"]);
    assert_eq!(first, second, "replay returns the stored receipt verbatim");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "the retry must not refetch");
    assert_eq!(attachment_count(&w.db, &w.first).await, 1);
    // Keyed receipts omit the unattested redirect chain (v1 parity).
    assert!(first.get("final_url").is_none());
    assert!(first.get("redirects").is_none());
    w.db.close().await;
}

#[tokio::test]
async fn keyed_reuse_with_changed_args_conflicts_without_refetch() {
    let w = world().await;
    let config = loopback_config();
    let hits = Arc::new(AtomicUsize::new(0));
    let addr = serve(|_| ok_bytes(b"bytes", "text/plain"), hits.clone()).await;
    attach(
        &w,
        "acct:admin",
        json!({"record_id": w.first, "url": format!("http://{addr}/a"), "idempotency_key": "url-attach-conflict-1"}),
        &config,
    )
    .await
    .unwrap();
    let error = attach(
        &w,
        "acct:admin",
        json!({"record_id": w.first, "url": format!("http://{addr}/b"), "idempotency_key": "url-attach-conflict-1"}),
        &config,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("different request"), "{error}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the conflict must not refetch"
    );
    assert_eq!(attachment_count(&w.db, &w.first).await, 1);
    w.db.close().await;
}

#[tokio::test]
async fn keyed_replay_after_archive_replays_without_refetch() {
    let w = world().await;
    let config = loopback_config();
    let hits = Arc::new(AtomicUsize::new(0));
    let addr = serve(|_| ok_bytes(b"stable", "text/plain"), hits.clone()).await;
    let args = json!({"record_id": w.first, "url": format!("http://{addr}/stable"), "idempotency_key": "url-attach-replay-archived-1"});
    let first = attach(&w, "acct:admin", args.clone(), &config)
        .await
        .unwrap();
    // Archive after the commit: an identical retry still replays the
    // committed outcome (current Edit/View authority re-proved inside the
    // lookup) instead of refusing on liveness or fetching again.
    let record = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&w.db, &w.admin, &w.first, true, record.revision)
        .await
        .unwrap();
    let second = attach(&w, "acct:admin", args.clone(), &config)
        .await
        .unwrap();
    assert_eq!(first["attachment_id"], second["attachment_id"]);
    assert_eq!(first, second);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "the archived-bearer retry must not refetch"
    );
    assert_eq!(attachment_count(&w.db, &w.first).await, 1);
    w.db.close().await;
}

#[tokio::test]
async fn commit_after_bearer_archived_rolls_back_everything() {
    let w = world().await;
    let bytes = png_bytes();
    let digest = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(&bytes))
    };
    let args = json!({"record_id": w.first, "url": "http://127.0.0.1:9/archived.png"});
    let request_json =
        super::writes::dispatched_fingerprint("attach_from_url", args.clone()).unwrap();
    let fetched = super::writes::url_attachment::FetchedUrl {
        bytes: bytes.clone(),
        mime: "image/png".into(),
        filename: Some("archived.png".into()),
        name: "archived.png".into(),
        final_url: "http://127.0.0.1:9/archived.png".into(),
        redirects: 0,
    };
    // Archive between fetch and commit: current authority at commit refuses.
    let record = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_archived_as(&w.db, &w.admin, &w.first, true, record.revision)
        .await
        .unwrap();
    let caller = Caller::authenticated("acct:admin");
    let actor = super::principal(&w.db, &caller).await.unwrap();
    let error = super::writes::url_attachment::commit(&w.db, &actor, &args, &request_json, fetched)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("archived"), "{error}");
    // Atomic rollback: no attachment, no blob row, no receipt row.
    assert_eq!(attachment_count(&w.db, &w.first).await, 0);
    let blob: Option<Vec<u8>> = sqlx::query_scalar("SELECT bytes FROM kernel_blobs WHERE sha256=?")
        .bind(&digest)
        .fetch_optional(w.db.pool())
        .await
        .unwrap();
    assert!(blob.is_none(), "rolled-back blob bytes must not persist");
    let receipts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM kernel_mcp_write_receipts WHERE operation='attach_from_url'",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(receipts, 0);
    w.db.close().await;
}

/// Keyed ingress through the real `call_engine` path: the registry's
/// adapter-write gate must let the key reach the handler, and replay plus
/// conflict through that path must not refetch.
#[tokio::test]
async fn registry_keyed_replay_and_conflict_skip_refetch() {
    let w = world().await;
    let hits = Arc::new(AtomicUsize::new(0));
    let addr = serve(|_| ok_bytes(b"registry bytes", "text/plain"), hits.clone()).await;
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    super::writes::register_with_fetch(
        &mut registry,
        FetchConfig {
            allow_loopback: true,
            ..FetchConfig::default()
        },
    )
    .unwrap();
    let key = "url-attach-registry-1";
    let args = |url: String| json!({"record_id": w.first, "url": url, "idempotency_key": key});
    let first = registry
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            Caller::authenticated("acct:admin"),
            "attach_from_url",
            args(format!("http://{addr}/a")),
        )
        .await
        .unwrap();
    let second = registry
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            Caller::authenticated("acct:admin"),
            "attach_from_url",
            args(format!("http://{addr}/a")),
        )
        .await
        .unwrap();
    assert_eq!(first["attachment_id"], second["attachment_id"]);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "registry replay must not refetch"
    );
    let error = registry
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            Caller::authenticated("acct:admin"),
            "attach_from_url",
            args(format!("http://{addr}/b")),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("different request"), "{error}");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "registry conflict must not refetch"
    );
    assert_eq!(attachment_count(&w.db, &w.first).await, 1);
    w.db.close().await;
}

#[tokio::test]
async fn v2_contract_is_truthful() {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    super::register_kernel_v2_tools(&mut registry).unwrap();
    assert!(registry.has_engine_operation("attach_from_url", EngineKind::KernelV2, None));
    let spec = registry.get("attach_from_url").expect("source tool");
    let schema = spec.input_schema_for_engine(EngineKind::KernelV2);
    let required: Vec<&str> = schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(required.contains(&"record_id"));
    assert!(required.contains(&"url"));
    let properties = schema["properties"].as_object().unwrap();
    for available in [
        "record_id",
        "url",
        "filename",
        "name",
        "lifecycle",
        "facets",
        "max_bytes",
        "idempotency_key",
    ] {
        assert!(properties.contains_key(available), "missing {available}");
    }
    // Owner, persistence and maturity overrides are unavailable, as with
    // v2 attach_text — the schema must not advertise them.
    for unavailable in ["owner_id", "persistence", "maturity"] {
        assert!(
            !properties.contains_key(unavailable),
            "must not advertise {unavailable}"
        );
    }
    assert!(spec
        .description_for_engine(EngineKind::KernelV2)
        .contains("SSRF"));
}
