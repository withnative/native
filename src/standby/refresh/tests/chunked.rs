//! Controller-level proofs for catching a stale copy up over the chunked delta
//! route, its fall back to the MCP tool on an older host, and the typed
//! too-large diagnostics.
//!
//! The fixture host serves the head over MCP and, when it has the route, the
//! chunked start/poll/bytes/cancel family backed by the real authority capture.

use std::collections::HashMap;

use super::*;
use crate::export::BinaryDeltaMeta;
use crate::standby::delta_transport::{
    capture_authority_act_delta_export, observe_authority_act_delta, observe_authority_act_head,
    AUTHORITY_ACT_DELTA_EXPORT_CONTRACT, AUTHORITY_ACT_DELTA_EXPORT_MEDIA_TYPE,
    AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum HostRoute {
    /// An older host: the chunked start answers a bare 404.
    Absent,
    /// The chunked family, capturing the real cut.
    Present,
    /// The chunked family, whose capture fails as `delta_too_large`.
    CaptureTooLarge,
    /// The chunked family, serving inner-corrupted bytes with the outer
    /// digest recomputed over the corruption: only the client's inner
    /// document validation can still refuse the cut.
    TamperedInner,
}

type ExportedDeltas = Arc<Mutex<HashMap<String, (Vec<u8>, BinaryDeltaMeta)>>>;

#[derive(Default)]
pub(super) struct Calls {
    mcp_delta: AtomicUsize,
    starts: AtomicUsize,
    reads: AtomicUsize,
    cancels: AtomicUsize,
}

struct RawRequest {
    line: String,
    headers: String,
    body: Vec<u8>,
}

async fn read_raw_request(stream: &mut TcpStream) -> RawRequest {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "HTTP request ended before its headers");
        bytes.extend_from_slice(&chunk[..read]);
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
    let content_length = header_value(&headers, "content-length")
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(0);
    while bytes.len() < header_end + content_length {
        let mut chunk = [0_u8; 2048];
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0, "HTTP request ended before its body");
        bytes.extend_from_slice(&chunk[..read]);
    }
    RawRequest {
        line: headers.lines().next().unwrap().to_string(),
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    }
}

fn header_value(headers: &str, name: &str) -> Option<String> {
    headers.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

async fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, String)], body: &[u8]) {
    let mut head = format!("HTTP/1.1 {status}\r\nConnection: close\r\n");
    head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    stream.shutdown().await.unwrap();
}

fn control_headers() -> Vec<(&'static str, String)> {
    vec![
        ("Content-Type", "application/json".into()),
        (
            "x-native-export-api",
            AUTHORITY_ACT_DELTA_EXPORT_CONTRACT.into(),
        ),
    ]
}

async fn respond_json(stream: &mut TcpStream, status: &str, body: &Value) {
    respond(
        stream,
        status,
        &control_headers(),
        &serde_json::to_vec(body).unwrap(),
    )
    .await;
}

async fn respond_mcp(stream: &mut TcpStream, result: crate::Result<Value>) {
    let envelope = match result {
        Ok(structured) => json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {"content": [], "structuredContent": structured,
                       "isError": false, "resultType": "complete", "_meta": {}}
        }),
        // The shape the real tool framing gives an engine error.
        Err(error) => json!({
            "jsonrpc": "2.0", "id": 1,
            "result": {"content": [{"type": "text", "text": error.to_string()}],
                       "structuredContent": {"error": error.to_string(), "run_context": {}},
                       "isError": true}
        }),
    };
    respond_json(stream, "200 OK", &envelope).await;
}

/// Serve the authority until the returned task is aborted.
pub(super) async fn serve_host(
    db: crate::Db,
    route: HostRoute,
) -> (u16, tokio::task::JoinHandle<()>, Arc<Calls>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let calls = Arc::new(Calls::default());
    let served = calls.clone();
    let task = tokio::spawn(async move {
        let spool = Arc::new(tempfile::tempdir().unwrap());
        let exports: ExportedDeltas = Arc::new(Mutex::new(HashMap::new()));
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (db, calls, spool, exports) =
                (db.clone(), served.clone(), spool.clone(), exports.clone());
            tokio::spawn(async move {
                let request = read_raw_request(&mut stream).await;
                assert!(request
                    .headers
                    .to_ascii_lowercase()
                    .lines()
                    .any(|line| matches!(
                        line,
                        "authorization: bearer secret" | "authorization: bearer rotated"
                    )));
                let mut parts = request.line.split(' ');
                let (method, path) = (parts.next().unwrap(), parts.next().unwrap());
                if path.starts_with("/mcp/") {
                    let body: Value = serde_json::from_slice(&request.body).unwrap();
                    let result = match body["params"]["arguments"]["operation"].as_str().unwrap() {
                        "authority_act_head" => observe_authority_act_head(&db, "route-1")
                            .await
                            .map(|value| serde_json::to_value(value).unwrap()),
                        "authority_act_delta" => {
                            calls.mcp_delta.fetch_add(1, Ordering::SeqCst);
                            let from = body["params"]["arguments"]["arguments"]
                                ["from_exclusive_act"]
                                .as_i64()
                                .unwrap();
                            observe_authority_act_delta(&db, "route-1", from)
                                .await
                                .map(|value| serde_json::to_value(value).unwrap())
                        }
                        other => panic!("unexpected authority operation {other}"),
                    };
                    respond_mcp(&mut stream, result).await;
                    return;
                }
                let base = "/v1/databases/route%2D1/standby-delta/exports";
                if route == HostRoute::Absent {
                    respond(&mut stream, "404 Not Found", &[], b"").await;
                    return;
                }
                if method == "POST" && path == base {
                    calls.starts.fetch_add(1, Ordering::SeqCst);
                    let body: Value = serde_json::from_slice(&request.body).unwrap();
                    assert_eq!(body["contract"], AUTHORITY_ACT_DELTA_EXPORT_CONTRACT);
                    assert_eq!(body["version"], 1);
                    assert_eq!(body.as_object().unwrap().len(), 3, "F2 is never supplied");
                    let handle = uuid::Uuid::new_v4().to_string();
                    if route == HostRoute::Present || route == HostRoute::TamperedInner {
                        let from = body["from_exclusive_act"].as_i64().unwrap();
                        let (export, meta) = capture_authority_act_delta_export(
                            &db,
                            "route-1",
                            from,
                            spool.path(),
                            AUTHORITY_ACT_DELTA_SPOOL_MAX_BYTES,
                        )
                        .await
                        .unwrap();
                        let mut bytes = fs::read(export.path()).unwrap();
                        if route == HostRoute::TamperedInner {
                            let at = bytes.len() / 2;
                            bytes[at] ^= 0x01;
                        }
                        export.cleanup().await;
                        exports
                            .lock()
                            .unwrap()
                            .insert(handle.clone(), (bytes, meta));
                    }
                    respond_json(
                        &mut stream,
                        "202 Accepted",
                        &json!({"api": AUTHORITY_ACT_DELTA_EXPORT_CONTRACT,
                                "export_handle": handle, "status": "pending",
                                "expires_at": "2099-01-01T00:00:00.000Z"}),
                    )
                    .await;
                    return;
                }
                let tail = path.strip_prefix(&format!("{base}/")).unwrap();
                let (handle, bytes_route) = match tail.strip_suffix("/bytes") {
                    Some(handle) => (handle.to_string(), true),
                    None => (tail.to_string(), false),
                };
                if method == "DELETE" {
                    calls.cancels.fetch_add(1, Ordering::SeqCst);
                    exports.lock().unwrap().remove(&handle);
                    respond_json(&mut stream, "200 OK", &json!({"status": "cancelled"})).await;
                    return;
                }
                if route == HostRoute::CaptureTooLarge {
                    respond_json(
                        &mut stream,
                        "200 OK",
                        &json!({"api": AUTHORITY_ACT_DELTA_EXPORT_CONTRACT,
                                "export_handle": handle, "status": "failed",
                                "error_code": "delta_too_large",
                                "expires_at": "2099-01-01T00:00:00.000Z"}),
                    )
                    .await;
                    return;
                }
                let (bytes, meta) = exports.lock().unwrap().get(&handle).cloned().unwrap();
                // A tampering host recomputes the outer digest over its
                // corruption, so the outer check passes and only the inner
                // document validation can refuse the cut.
                let outer = if route == HostRoute::TamperedInner {
                    hex::encode(Sha256::digest(&bytes))
                } else {
                    meta.outer_sha256.clone()
                };
                if !bytes_route {
                    respond_json(
                        &mut stream,
                        "200 OK",
                        &json!({"api": AUTHORITY_ACT_DELTA_EXPORT_CONTRACT,
                                "export_handle": handle, "status": "ready",
                                "route_database_id": meta.route_database_id,
                                "origin_database_id": meta.origin_database_id,
                                "from_exclusive_act": meta.from_exclusive_act,
                                "to_inclusive_act": meta.to_inclusive_act,
                                "content_sha256": meta.content_sha256,
                                "outer_sha256": outer,
                                "size_bytes": bytes.len(),
                                "expires_at": "2099-01-01T00:00:00.000Z"}),
                    )
                    .await;
                    return;
                }
                calls.reads.fetch_add(1, Ordering::SeqCst);
                let range = header_value(&request.headers, "range").unwrap();
                let (start, end) = range
                    .strip_prefix("bytes=")
                    .unwrap()
                    .split_once('-')
                    .unwrap();
                let (start, end) = (
                    start.parse::<usize>().unwrap(),
                    end.parse::<usize>().unwrap(),
                );
                assert!(end - start < 1024 * 1024, "one MiB per request at most");
                let end = end.min(bytes.len() - 1);
                let mut headers = control_headers();
                headers[0].1 = AUTHORITY_ACT_DELTA_EXPORT_MEDIA_TYPE.into();
                headers.push(("ETag", format!("\"{outer}\"")));
                headers.push((
                    "Content-Range",
                    format!("bytes {start}-{end}/{}", bytes.len()),
                ));
                respond(
                    &mut stream,
                    "206 Partial Content",
                    &headers,
                    &bytes[start..=end],
                )
                .await;
            });
        }
    });
    (port, task, calls)
}

async fn append_facet(db: &crate::Db, record_id: &str, key: &str, value: &str) {
    crate::store::append(
        db,
        crate::store::AppendSpec {
            record_id: record_id.into(),
            event_type: "facet.set".into(),
            payload: json!({ "key": key, "value": value }),
            actor: None,
        },
    )
    .await
    .unwrap();
}

async fn create_note(db: &crate::Db, record_id: &str, name: &str) {
    crate::store::append(
        db,
        crate::store::AppendSpec {
            record_id: record_id.into(),
            event_type: "record.created".into(),
            payload: json!({"type": "Document", "kind": "note", "name": name}),
            actor: None,
        },
    )
    .await
    .unwrap();
}

/// A controller holding an installed checkpoint of `authority`, with deltas on
/// and a snapshot client that fails if a whole snapshot is ever attempted.
async fn stale_controller(
    directory: &tempfile::TempDir,
    authority: &crate::Db,
    tag: &str,
) -> (
    StandbyRefreshController,
    Arc<AlwaysFailClient>,
    InstalledGeneration,
) {
    let origin = crate::identity::database_id(authority).await.unwrap();
    let (bytes, manifest) = snapshot_fixture(authority).await;
    let mut controller = controller_for_origin(
        directory,
        origin,
        Arc::new(ScriptedClient::new(paged_replies(tag, &bytes, &manifest))),
    );
    let StandbyRefreshOutcome::Installed {
        generation: checkpoint,
        ..
    } = controller
        .refresh_once(RefreshCause::Startup)
        .await
        .unwrap()
    else {
        panic!("the first refresh installs a whole snapshot")
    };
    // Installation maintenance shares attempt.lock with the measured refresh.
    controller.store.maintenance_idle().await;
    let no_full = Arc::new(AlwaysFailClient {
        class: RefreshFailureClass::Protocol,
        calls: AtomicUsize::new(0),
    });
    controller.client = no_full.clone();
    enable_deltas(&mut controller);
    (controller, no_full, *checkpoint)
}

/// A single event above 6 MB and a large blob it does not itself carry: the
/// cut the MCP tool's 700,000-byte ceiling can never express.
async fn append_large_cut(db: &crate::Db) -> (String, String) {
    const TARGET: &str = "1a7e4000-0000-4000-8000-00000000d301";
    const BLOB_HOLDER: &str = "1a7e4000-0000-4000-8000-00000000d302";
    create_note(db, TARGET, "large event target").await;
    create_note(db, BLOB_HOLDER, "large blob holder").await;
    let big_event = "x".repeat(6_500_000);
    append_facet(db, TARGET, "large_text", &big_event).await;
    let blob_bytes: Vec<u8> = (0..2_000_000_u32).map(|n| (n % 251) as u8).collect();
    let blob = crate::blob::insert_blob(db, &blob_bytes, Some("application/octet-stream"), None)
        .await
        .unwrap();
    append_facet(db, BLOB_HOLDER, "blob_ref", &blob.id).await;
    (TARGET.into(), blob.id)
}

#[tokio::test]
async fn stale_copy_catches_up_through_a_multi_megabyte_cut_over_the_chunked_route_without_a_full()
{
    let authority = crate::db::create_database(":memory:").await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (mut controller, no_full, checkpoint) =
        stale_controller(&directory, &authority, "chunked-large").await;
    let (target, blob_id) = append_large_cut(&authority).await;
    let expected_head = read_authority_act_head(&authority).await.unwrap().head_act;

    let (port, server, calls) = serve_host(authority.clone(), HostRoute::Present).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    let outcome = controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .unwrap();
    server.abort();

    let StandbyRefreshOutcome::Advanced {
        generation,
        head_act,
    } = outcome
    else {
        panic!("the chunked route must carry the cut without a whole snapshot")
    };
    assert_eq!(generation.id, checkpoint.id, "advanced in place");
    assert_eq!(head_act, expected_head);
    assert_eq!(no_full.calls.load(Ordering::SeqCst), 0, "no FULL attempted");
    assert_eq!(calls.mcp_delta.load(Ordering::SeqCst), 0);
    assert_eq!(calls.starts.load(Ordering::SeqCst), 1);
    assert!(
        calls.reads.load(Ordering::SeqCst) >= 8,
        "an ~8.6 MB cut takes many one-MiB ranges, got {}",
        calls.reads.load(Ordering::SeqCst)
    );
    assert_eq!(calls.cancels.load(Ordering::SeqCst), 1, "spool released");
    assert_eq!(controller.state().unwrap().last_delta_fallback_class, None);

    let serving = crate::db::open_existing_database_standby_read_only(
        generation.snapshot_path.to_string_lossy().as_ref(),
    )
    .await
    .unwrap();
    let carried: i64 = sqlx::query_scalar(
        "SELECT LENGTH(json_extract(payload, '$.value')) FROM content_events \
         WHERE record_id = ? AND type = 'facet.set'",
    )
    .bind(&target)
    .fetch_one(serving.pool())
    .await
    .unwrap();
    assert_eq!(carried, 6_500_000);
    let blob_len: i64 = sqlx::query_scalar("SELECT LENGTH(bytes) FROM blobs WHERE id = ?")
        .bind(&blob_id)
        .fetch_one(serving.pool())
        .await
        .unwrap();
    assert_eq!(blob_len, 2_000_000);
    serving.close().await;
    controller.store.maintenance_idle().await;
    authority.close().await;
}

#[tokio::test]
async fn small_delta_still_advances_over_the_chunked_route() {
    let authority = crate::db::create_database(":memory:").await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (mut controller, no_full, _) =
        stale_controller(&directory, &authority, "chunked-small").await;
    create_note(&authority, "1a7e4000-0000-4000-8000-00000000d310", "small").await;

    let (port, server, calls) = serve_host(authority.clone(), HostRoute::Present).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    let outcome = controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .unwrap();
    server.abort();

    assert!(matches!(outcome, StandbyRefreshOutcome::Advanced { .. }));
    assert_eq!(no_full.calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls.starts.load(Ordering::SeqCst), 1);
    assert_eq!(calls.reads.load(Ordering::SeqCst), 1);
    assert_eq!(calls.mcp_delta.load(Ordering::SeqCst), 0);
    controller.store.maintenance_idle().await;
    authority.close().await;
}

#[tokio::test]
async fn older_host_without_the_chunked_route_falls_back_to_the_mcp_delta() {
    let authority = crate::db::create_database(":memory:").await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (mut controller, no_full, _) =
        stale_controller(&directory, &authority, "chunked-absent").await;
    create_note(
        &authority,
        "1a7e4000-0000-4000-8000-00000000d320",
        "older host",
    )
    .await;

    let (port, server, calls) = serve_host(authority.clone(), HostRoute::Absent).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    let outcome = controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .unwrap();
    server.abort();

    assert!(matches!(outcome, StandbyRefreshOutcome::Advanced { .. }));
    assert_eq!(no_full.calls.load(Ordering::SeqCst), 0);
    assert_eq!(calls.mcp_delta.load(Ordering::SeqCst), 1);
    assert_eq!(calls.reads.load(Ordering::SeqCst), 0);
    controller.store.maintenance_idle().await;
    authority.close().await;
}

/// The reported failure: a cut the MCP tool refuses as oversize, with a whole
/// snapshot held back by the six-hour interval. It must read as too large and
/// deferred, never as an integrity refusal or an installed snapshot.
async fn assert_too_large_is_deferred(route: HostRoute, large: bool, tag: &str) {
    let authority = crate::db::create_database(":memory:").await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (mut controller, no_full, checkpoint) = stale_controller(&directory, &authority, tag).await;
    controller.config.full_refresh_min_interval_seconds = Some(6 * 60 * 60);
    if large {
        append_large_cut(&authority).await;
    } else {
        create_note(&authority, "1a7e4000-0000-4000-8000-00000000d330", "small").await;
    }

    let (port, server, _) = serve_host(authority.clone(), route).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    let outcome = controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .unwrap();
    server.abort();

    let StandbyRefreshOutcome::Deferred { generation, reason } = outcome else {
        panic!("a whole snapshot inside the interval is deferred, not installed")
    };
    assert_eq!(reason, "full_refresh_interval");
    assert_eq!(generation.id, checkpoint.id, "the copy is unchanged");
    assert_eq!(no_full.calls.load(Ordering::SeqCst), 0);
    let state = controller.state().unwrap();
    assert_eq!(
        state.last_delta_fallback_class,
        Some(DeltaFallbackClass::DeltaTooLarge)
    );
    let message = state.last_delta_fallback.unwrap();
    assert!(!message.contains("installed"), "{message}");
    assert_eq!(
        state.last_deferral.as_deref(),
        Some("full_refresh_interval")
    );
    let eligible = chrono::DateTime::parse_from_rfc3339(
        state.next_full_refresh_eligible_at.as_deref().unwrap(),
    )
    .unwrap();
    assert!(eligible > chrono::Utc::now() + chrono::Duration::hours(5));
    controller.store.maintenance_idle().await;
    authority.close().await;
}

#[tokio::test]
async fn legacy_mcp_oversize_with_a_recent_full_reports_too_large_and_the_deferral() {
    assert_too_large_is_deferred(HostRoute::Absent, true, "legacy-oversize").await;
}

#[tokio::test]
async fn chunked_delta_too_large_with_a_recent_full_reports_too_large_and_the_deferral() {
    // A small cut with a capture that reports the stable code: proves the
    // classification rests on the code, not on how big the fixture's bytes are.
    assert_too_large_is_deferred(HostRoute::CaptureTooLarge, false, "chunked-too-large").await;
}

/// The reported failure: the host corrupts the inner document after capture
/// but recomputes the outer digest over the corruption, so the outer check
/// passes and only the client's inner validation can refuse the cut. With a
/// whole snapshot held back by the six-hour interval it must read as an
/// integrity refusal and deferred, never installed.
#[tokio::test]
async fn chunked_inner_corruption_with_recomputed_outer_reports_integrity_and_the_deferral() {
    let authority = crate::db::create_database(":memory:").await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (mut controller, no_full, checkpoint) =
        stale_controller(&directory, &authority, "chunked-tampered").await;
    controller.config.full_refresh_min_interval_seconds = Some(6 * 60 * 60);
    create_note(
        &authority,
        "1a7e4000-0000-4000-8000-00000000d340",
        "tampered",
    )
    .await;

    let (port, server, _) = serve_host(authority.clone(), HostRoute::TamperedInner).await;
    controller.config.hosted_origin = format!("http://127.0.0.1:{port}");
    let outcome = controller
        .refresh_once(RefreshCause::Scheduled)
        .await
        .unwrap();
    server.abort();

    let StandbyRefreshOutcome::Deferred { generation, reason } = outcome else {
        panic!("a corrupted delta inside the interval is deferred, not installed")
    };
    assert_eq!(reason, "full_refresh_interval");
    assert_eq!(generation.id, checkpoint.id, "the copy is unchanged");
    assert_eq!(no_full.calls.load(Ordering::SeqCst), 0);
    let state = controller.state().unwrap();
    assert_eq!(
        state.last_delta_fallback_class,
        Some(DeltaFallbackClass::IntegrityOrApplyRefusal)
    );
    let message = state.last_delta_fallback.unwrap();
    assert!(message.contains("integrity"), "{message}");
    assert!(!message.contains("installed"), "{message}");
    assert_eq!(
        state.last_deferral.as_deref(),
        Some("full_refresh_interval")
    );
    controller.store.maintenance_idle().await;
    authority.close().await;
}
