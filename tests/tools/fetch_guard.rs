//! Tool 23 (`attach_from_url`) and its SSRF guard (`mcp::fetch`) — the guard
//! is CONTRACT (docs/tool-surface.md), so the rejection cases come first:
//! scheme allowlist, non-public address rejection, PINNED DNS (the
//! rebinding/TOCTOU case), PER-HOP redirect revalidation (the 302 into
//! 169.254.169.254 case), and the streamed size cap.
//!
//! Loopback note: tests that must actually connect stand a server on
//! 127.0.0.1 and open the guard's `allow_loopback` test seam. That seam
//! exempts loopback ONLY — link-local/private/… stay enforced, which is
//! exactly what the redirect tests rely on.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use native_ce::mcp::fetch::{
    fetch_url, ip_rejection, system_resolver, FetchConfig, Resolver, DEFAULT_MAX_FETCH_BYTES,
};
use native_ce::mcp::tools::attachments::register_attachment_tools_with;
use native_ce::mcp::{Caller, ToolRegistry};
use native_ce::store::create_record;
use native_ce::{create_database, Db};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::common::count;

// ---------------------------------------------------------------------------
// Harness: a scriptable local HTTP server + a scriptable resolver
// ---------------------------------------------------------------------------

/// Serve raw HTTP responses on 127.0.0.1: `routes(path)` returns the complete
/// response text for each request. Connections are closed after one exchange.
async fn serve(routes: impl Fn(&str) -> String + Send + Sync + 'static) -> SocketAddr {
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
            let _ = socket.write_all(routes(&path).as_bytes()).await;
            let _ = socket.shutdown().await;
        }
    });
    addr
}

fn ok_response(body: &str, content_type: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn redirect_response(location: &str) -> String {
    format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

/// A resolver that always answers `addr` and counts its calls — the DNS seam
/// for the pinning/rebinding tests.
fn scripted_resolver(addr: SocketAddr, calls: Arc<AtomicUsize>) -> Resolver {
    Arc::new(move |_host, _port| {
        let calls = calls.clone();
        Box::pin(async move {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![addr])
        })
    })
}

fn loopback_config() -> FetchConfig {
    FetchConfig {
        allow_loopback: true,
        ..FetchConfig::default()
    }
}

// ---------------------------------------------------------------------------
// Guarantee 1 — scheme allowlist
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_non_http_schemes() {
    for url in [
        "ftp://example.com/file",
        "file:///etc/passwd",
        "gopher://example.com/",
    ] {
        let err = fetch_url(url, &FetchConfig::default()).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("is not allowed — only http and https"),
            "{url}: {err}"
        );
    }
    let err = fetch_url("not a url", &FetchConfig::default())
        .await
        .unwrap_err();
    assert!(err.to_string().starts_with("invalid url"), "{err}");
}

// ---------------------------------------------------------------------------
// Guarantee 2 — non-public addresses, literal and resolved
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rejects_literal_non_public_addresses() {
    for url in [
        "http://127.0.0.1/x",
        "http://127.8.8.8/x",
        "http://10.0.0.1/x",
        "http://172.16.0.1/x",
        "http://192.168.1.1/x",
        "http://169.254.169.254/latest/meta-data/",
        "http://100.64.0.1/x",
        "http://0.0.0.0/x",
        "http://198.18.0.1/x",
        "http://192.0.2.1/x",
        "http://224.0.0.1/x",
        "http://240.0.0.1/x",
        "https://[::1]/x",
        "http://[fe80::1]/x",
        "http://[fc00::1]/x",
        "http://[fec0::1]/x",
        "http://[::ffff:10.0.0.1]/x",
        "http://[64:ff9b::a00:1]/x",
        "http://[2001:db8::1]/x",
    ] {
        let err = fetch_url(url, &FetchConfig::default()).await.unwrap_err();
        assert!(
            err.to_string().starts_with("refusing to fetch"),
            "{url}: {err}"
        );
    }
}

#[test]
fn ip_policy_classifies_public_and_non_public() {
    for public in ["93.184.216.34", "8.8.8.8", "2001:4860:4860::8888"] {
        assert_eq!(
            ip_rejection(public.parse().unwrap(), false),
            None,
            "{public}"
        );
    }
    for (addr, reason) in [
        ("127.0.0.1", "loopback"),
        ("10.1.2.3", "private"),
        ("169.254.169.254", "link-local"),
        ("::1", "loopback"),
        ("::", "unspecified"),
        ("::ffff:192.168.0.1", "private"),
        ("fe80::1", "link-local"),
    ] {
        let rejection = ip_rejection(addr.parse().unwrap(), false);
        assert!(
            rejection.is_some_and(|r| r.contains(reason)),
            "{addr}: {rejection:?}"
        );
    }
    // The test seam exempts loopback ONLY.
    assert_eq!(ip_rejection("127.0.0.1".parse().unwrap(), true), None);
    assert!(ip_rejection("169.254.169.254".parse().unwrap(), true).is_some());
    assert!(ip_rejection("10.0.0.1".parse().unwrap(), true).is_some());
}

#[tokio::test]
async fn rejects_hostnames_that_resolve_to_non_public_addresses() {
    let config = FetchConfig {
        resolver: Arc::new(|_host, port| {
            Box::pin(async move { Ok(vec![SocketAddr::new("10.0.0.5".parse().unwrap(), port)]) })
        }),
        ..FetchConfig::default()
    };
    let err = fetch_url("http://internal.corp/secrets", &config)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("host 'internal.corp' resolves to 10.0.0.5"),
        "{err}"
    );

    // One bad address among several poisons the set — no partial trust.
    let config = FetchConfig {
        resolver: Arc::new(|_host, port| {
            Box::pin(async move {
                Ok(vec![
                    SocketAddr::new("93.184.216.34".parse().unwrap(), port),
                    SocketAddr::new("169.254.169.254".parse().unwrap(), port),
                ])
            })
        }),
        ..FetchConfig::default()
    };
    let err = fetch_url("http://mixed.example/", &config)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("169.254.169.254"), "{err}");
}

// ---------------------------------------------------------------------------
// Guarantee 3 — pinned DNS: resolve once, no check/connect TOCTOU
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dns_is_resolved_once_and_the_connection_is_pinned_to_it() {
    let addr = serve(|_| ok_response("pinned", "text/plain")).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let config = FetchConfig {
        resolver: scripted_resolver(addr, calls.clone()),
        ..loopback_config()
    };
    let fetched = fetch_url(&format!("http://rebind.test:{}/x", addr.port()), &config)
        .await
        .unwrap();
    assert_eq!(fetched.bytes, b"pinned");
    // ONE resolution for the whole request: the checked addresses ARE the
    // connected addresses, so a rebinding resolver has no second answer to
    // poison — there is no separate connect-time lookup to race.
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_rebinding_resolver_cannot_reach_a_private_address() {
    // The classic rebinding script: answer public-looking first, private
    // afterwards. Because the guard's single resolution is also the pinned
    // connect set, the FIRST answer decides — here it is private, so the
    // fetch dies before any connection; a flipped script would connect to the
    // first (checked) address and never consult the resolver again (proved by
    // the call count above).
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in = calls.clone();
    let config = FetchConfig {
        resolver: Arc::new(move |_host, port| {
            let calls = calls_in.clone();
            Box::pin(async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                let ip = if n == 0 {
                    "192.168.0.10"
                } else {
                    "93.184.216.34"
                };
                Ok(vec![SocketAddr::new(ip.parse().unwrap(), port)])
            })
        }),
        ..FetchConfig::default()
    };
    let err = fetch_url("http://rebind.test/x", &config)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("192.168.0.10"), "{err}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

// ---------------------------------------------------------------------------
// Guarantee 4 — per-hop redirect revalidation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_redirect_into_the_metadata_service_is_rejected() {
    // Hop 1 is allowed (loopback seam); hop 2 is a 302 into 169.254.169.254,
    // which must fail EXACTLY like a direct request to it — the guard reruns
    // on every hop, not just the original URL.
    let addr = serve(|path| match path {
        "/start" => redirect_response("http://169.254.169.254/latest/meta-data/"),
        _ => ok_response("nope", "text/plain"),
    })
    .await;
    let err = fetch_url(
        &format!("http://127.0.0.1:{}/start", addr.port()),
        &loopback_config(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("169.254.169.254") && err.to_string().contains("link-local"),
        "{err}"
    );
}

#[tokio::test]
async fn a_redirect_to_a_privately_resolving_hostname_is_rejected() {
    // Hop 2 is a hostname, so the resolver runs again FOR THAT HOP and its
    // answer is judged afresh.
    let addr = serve(|path| match path {
        "/start" => redirect_response("http://internal.test/loot"),
        _ => ok_response("nope", "text/plain"),
    })
    .await;
    let config = FetchConfig {
        resolver: Arc::new(|host, port| {
            Box::pin(async move {
                let ip = if host == "internal.test" {
                    "10.0.0.9"
                } else {
                    "127.0.0.1"
                };
                Ok(vec![SocketAddr::new(ip.parse().unwrap(), port)])
            })
        }),
        ..loopback_config()
    };
    let err = fetch_url(&format!("http://127.0.0.1:{}/start", addr.port()), &config)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("host 'internal.test' resolves to 10.0.0.9"),
        "{err}"
    );
}

#[tokio::test]
async fn a_redirect_cannot_downgrade_the_scheme() {
    let addr = serve(|_| redirect_response("file:///etc/passwd")).await;
    let err = fetch_url(
        &format!("http://127.0.0.1:{}/x", addr.port()),
        &loopback_config(),
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("scheme 'file' is not allowed"),
        "{err}"
    );
}

#[tokio::test]
async fn redirect_chains_are_bounded_and_relative_locations_join() {
    let addr = serve(|path| match path {
        "/a" => redirect_response("/b"), // relative Location joins against the hop
        "/b" => ok_response("made it", "text/plain"),
        _ => redirect_response("/loop"),
    })
    .await;
    let fetched = fetch_url(
        &format!("http://127.0.0.1:{}/a", addr.port()),
        &loopback_config(),
    )
    .await
    .unwrap();
    assert_eq!(fetched.bytes, b"made it");
    assert_eq!(fetched.redirects, 1);
    assert!(fetched.final_url.ends_with("/b"));

    let config = FetchConfig {
        max_redirects: 3,
        ..loopback_config()
    };
    let err = fetch_url(&format!("http://127.0.0.1:{}/loop", addr.port()), &config)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("too many redirects"), "{err}");
}

// ---------------------------------------------------------------------------
// Guarantee 5 — streamed size cap
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_size_cap_rejects_a_declared_content_length() {
    let addr = serve(|_| ok_response(&"x".repeat(4096), "text/plain")).await;
    let config = FetchConfig {
        max_bytes: 1024,
        ..loopback_config()
    };
    let err = fetch_url(&format!("http://127.0.0.1:{}/big", addr.port()), &config)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("exceeds the 1024 byte cap"),
        "{err}"
    );
}

#[tokio::test]
async fn the_size_cap_is_enforced_on_the_stream_without_a_content_length() {
    // No Content-Length: a close-delimited body must still hit the cap while
    // STREAMING, not after buffering.
    let addr = serve(|_| {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
            "y".repeat(8192)
        )
    })
    .await;
    let config = FetchConfig {
        max_bytes: 1024,
        ..loopback_config()
    };
    let err = fetch_url(&format!("http://127.0.0.1:{}/sneaky", addr.port()), &config)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("exceeds the 1024 byte cap"),
        "{err}"
    );
}

// ---------------------------------------------------------------------------
// Tool 23 end to end — through the registry
// ---------------------------------------------------------------------------

async fn db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    native_ce::meta::seed_vocabularies(&db).await.unwrap();
    db
}

#[tokio::test]
async fn attach_from_url_stores_the_capture_as_an_attachment() {
    let addr = serve(|_| ok_response("# fetched doc", "text/markdown; charset=utf-8")).await;
    let mut registry = ToolRegistry::new();
    register_attachment_tools_with(&mut registry, loopback_config()).unwrap();
    let db = db().await;
    let root = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap();

    let url = format!("http://127.0.0.1:{}/docs/readme.md", addr.port());
    let result = registry
        .call(
            db.clone(),
            Caller::local(),
            "attach_from_url",
            json!({
                "record_id": root,
                "url": url,
                "facets": { "capture_method": "fetch" }
            }),
        )
        .await
        .unwrap();
    assert_eq!(result["blob"]["mime"], "text/markdown; charset=utf-8");
    assert_eq!(result["blob"]["size_bytes"], 13);
    assert_eq!(result["blob"]["storage_tier"], "inline");
    assert_eq!(result["name"], "readme.md"); // filename inferred from the URL path
    assert_eq!(result["url"], json!(url));
    assert_eq!(result["redirects"], 0);

    // Provenance facets on the attachment record.
    let attachment_id = result["attachment_id"].as_str().unwrap();
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT value FROM facet_values WHERE record_id = '{attachment_id}' AND key = 'source_url'"),
            "value"
        )
        .await,
        Some(url)
    );
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT value FROM facet_values WHERE record_id = '{attachment_id}' AND key = 'capture_method'"),
            "value"
        )
        .await,
        Some("fetch".into())
    );

    // Round-trips through tool 24, and replay equality holds.
    let page = registry
        .call(
            db.clone(),
            Caller::local(),
            "read_attachment",
            json!({ "attachment_id": attachment_id }),
        )
        .await
        .unwrap();
    assert_eq!(page["content"], "# fetched doc");
    assert_eq!(page["content_encoding"], "utf-8");
    let diff = native_ce::conformance::rebuild_and_diff(&db).await.unwrap();
    assert!(diff.equal, "{diff:?}");
    db.close().await;
}

#[tokio::test]
async fn attach_from_url_allows_an_explicit_source_url_correction() {
    let addr = serve(|_| ok_response("captured", "text/plain")).await;
    let mut registry = ToolRegistry::new();
    register_attachment_tools_with(&mut registry, loopback_config()).unwrap();
    let db = db().await;
    let root = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap();

    let fetched_url = format!("http://127.0.0.1:{}/capture", addr.port());
    let result = registry
        .call(
            db.clone(),
            Caller::local(),
            "attach_from_url",
            json!({
                "record_id": root,
                "url": fetched_url,
                "facets": { "source_url": "https://canonical.example/source" }
            }),
        )
        .await
        .unwrap();
    let attachment_id = result["attachment_id"].as_str().unwrap();
    assert_eq!(
        crate::common::text_of(
            &db,
            &format!("SELECT value FROM facet_values WHERE record_id = '{attachment_id}' AND key = 'source_url'"),
            "value"
        )
        .await
        .as_deref(),
        Some("https://canonical.example/source")
    );
    assert_eq!(
        count(
            &db,
            &format!("SELECT COUNT(*) AS n FROM content_events WHERE record_id = '{attachment_id}' AND type = 'facet.set'")
        )
        .await,
        2,
        "blob_ref plus one caller-selected source_url; no duplicate provenance event"
    );
    db.close().await;
}

#[tokio::test]
async fn attach_from_url_validates_arguments_and_guards_by_default() {
    let mut registry = ToolRegistry::new();
    native_ce::mcp::register_surface_tools(&mut registry).unwrap(); // PRODUCTION posture
    let db = db().await;
    let root = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap();

    // The default registration carries the real guard: the metadata service
    // is unreachable through the tool, message verbatim through the seam.
    let err = registry
        .call(
            db.clone(),
            Caller::local(),
            "attach_from_url",
            json!({ "record_id": root, "url": "http://169.254.169.254/latest/meta-data/" }),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().starts_with("refusing to fetch"), "{err}");

    let err = registry
        .call(
            db.clone(),
            Caller::local(),
            "attach_from_url",
            json!({ "record_id": root, "url": "https://example.com/x", "max_bytes": 0 }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "attach_from_url: 'max_bytes' must be between 1 and 20971520"
    );
    let err = registry
        .call(
            db.clone(),
            Caller::local(),
            "attach_from_url",
            json!({ "record_id": "nope", "url": "https://example.com/x" }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "attach_from_url: record nope does not exist"
    );

    // No fetch happened: nothing was written anywhere.
    assert_eq!(count(&db, "SELECT COUNT(*) AS n FROM blobs").await, 0);
    // The default config exposes the documented cap constants.
    assert_eq!(FetchConfig::default().max_bytes, DEFAULT_MAX_FETCH_BYTES);
    assert!(!FetchConfig::default().allow_loopback);
    // And the production resolver is the system one (constructible).
    let _ = system_resolver();
    db.close().await;
}

#[tokio::test]
async fn attach_from_url_fails_cleanly_on_http_errors() {
    let addr = serve(|_| {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    })
    .await;
    let mut registry = ToolRegistry::new();
    register_attachment_tools_with(&mut registry, loopback_config()).unwrap();
    let db = db().await;
    let root = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap();
    let err = registry
        .call(
            db.clone(),
            Caller::local(),
            "attach_from_url",
            json!({ "record_id": root, "url": format!("http://127.0.0.1:{}/gone", addr.port()) }),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("failed with status 404"), "{err}");
    // A failed fetch writes NOTHING — no orphan blob, no record, no events
    // beyond the seed.
    assert_eq!(count(&db, "SELECT COUNT(*) AS n FROM blobs").await, 0);
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        3
    );
    db.close().await;
}

#[tokio::test]
async fn a_parent_deleted_mid_fetch_cannot_gain_an_attachment() {
    // TOCTOU guard (PR 20 review, P1): the pre-fetch liveness check passes,
    // the parent is soft-deleted WHILE the fetch is in flight, and the
    // in-transaction recheck inside the append batch must refuse — nothing
    // attaches under a tombstone (frozen-after-soft-delete, ef32e44).
    let db = db().await;
    let root = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (db_in, root_in) = (db.clone(), root.clone());
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let _ = socket.read(&mut buf).await; // the fetch is now in flight
        native_ce::store::delete_record(&db_in, &root_in)
            .await
            .unwrap(); // tombstone the parent mid-fetch
        let _ = socket
            .write_all(ok_response("too late", "text/plain").as_bytes())
            .await;
        let _ = socket.shutdown().await;
    });

    let mut registry = ToolRegistry::new();
    register_attachment_tools_with(&mut registry, loopback_config()).unwrap();
    let err = registry
        .call(
            db.clone(),
            Caller::local(),
            "attach_from_url",
            json!({ "record_id": root, "url": format!("http://127.0.0.1:{}/x", addr.port()) }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!("attach_from_url: record {root} is deleted (tombstoned)")
    );
    // The fetch DID happen (the deletion ran on request receipt), but no
    // attachment record or event was committed under the tombstone; only the
    // seed create + the delete are in the log.
    assert_eq!(
        count(
            &db,
            "SELECT COUNT(*) AS n FROM records WHERE kind = 'attachment'"
        )
        .await,
        0
    );
    assert_eq!(
        count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        4
    );
    db.close().await;
}

#[tokio::test]
async fn malformed_arguments_never_cost_an_outbound_request() {
    // PR 20 review, P2: the registry does not enforce the JSON Schema, so
    // EVERY argument must be validated before any network I/O.
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_in = hits.clone();
    let addr = serve(move |_| {
        hits_in.fetch_add(1, Ordering::SeqCst);
        ok_response("should never be fetched", "text/plain")
    })
    .await;
    let mut registry = ToolRegistry::new();
    register_attachment_tools_with(&mut registry, loopback_config()).unwrap();
    let db = db().await;
    let root = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap();
    let url = format!("http://127.0.0.1:{}/x", addr.port());
    for args in [
        json!({ "record_id": root, "url": url, "filename": 42 }),
        json!({ "record_id": root, "url": url, "name": [] }),
        json!({ "record_id": root, "url": url, "max_bytes": -1 }),
        json!({ "record_id": root, "url": url, "surprise": true }), // deny_unknown_fields
    ] {
        let err = registry
            .call(db.clone(), Caller::local(), "attach_from_url", args)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .starts_with("invalid arguments for attach_from_url:"),
            "{err}"
        );
    }
    let err = registry
        .call(
            db.clone(),
            Caller::local(),
            "attach_from_url",
            json!({
                "record_id": root,
                "url": url,
                "facets": { "blob_ref": "caller-controlled" }
            }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "attach_from_url: facet 'blob_ref' is engine-reserved — create attachment bindings via the attach_text or attach_from_url tool"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0, "no request may be sent");
    assert_eq!(count(&db, "SELECT COUNT(*) AS n FROM blobs").await, 0);
    db.close().await;
}

// ---------------------------------------------------------------------------
// Keyed attach_from_url (task 8bef361, slice A2): a replay never fetches
// ---------------------------------------------------------------------------

/// A server that counts every request it answers.
async fn counting_server(body: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_in = hits.clone();
    let addr = serve(move |_| {
        hits_in.fetch_add(1, Ordering::SeqCst);
        ok_response(body, "text/plain")
    })
    .await;
    (addr, hits)
}

fn attachment_registry() -> Arc<ToolRegistry> {
    let mut registry = ToolRegistry::new();
    register_attachment_tools_with(&mut registry, loopback_config()).unwrap();
    Arc::new(registry)
}

async fn attachment_footprint(db: &Db) -> (i64, i64, i64) {
    (
        count(db, "SELECT COUNT(*) AS n FROM content_events").await,
        count(db, "SELECT COUNT(*) AS n FROM blobs").await,
        count(
            db,
            "SELECT COUNT(*) AS n FROM provenance_action_attestations",
        )
        .await,
    )
}

#[tokio::test]
async fn keyed_attach_from_url_replays_and_conflicts_without_fetching_again() {
    let (addr, hits) = counting_server("captured once").await;
    let registry = attachment_registry();
    let db = db().await;
    let home = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap();
    let url = format!("http://127.0.0.1:{}/notes.txt", addr.port());
    let args = json!({ "record_id": home, "url": url, "idempotency_key": "capture" });

    let first = registry
        .call(db.clone(), Caller::local(), "attach_from_url", args.clone())
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(first["url"], json!(url));
    assert!(first.get("final_url").is_none(), "{first}");
    assert!(first.get("redirects").is_none(), "{first}");
    let footprint = attachment_footprint(&db).await;

    let replay = registry
        .call(db.clone(), Caller::local(), "attach_from_url", args.clone())
        .await
        .unwrap();
    assert_eq!(
        replay.to_string(),
        first.to_string(),
        "byte-identical replay"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1, "a replay must not fetch");
    assert_eq!(attachment_footprint(&db).await, footprint);

    // A conflicting reuse is refused before any network I/O too.
    let mut conflicting = args;
    conflicting["name"] = json!("Another name");
    let error = registry
        .call(db.clone(), Caller::local(), "attach_from_url", conflicting)
        .await
        .unwrap_err();
    assert!(error.is_idempotency_conflict(), "{error}");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "a conflict must not fetch");
    assert_eq!(attachment_footprint(&db).await, footprint);
    db.close().await;
}

/// The liveness check follows the replay lookup, so a fresh key on a
/// tombstoned bearer is refused by it before it spends a fetch. A retry of a
/// committed attach is not refused by liveness at all: the replay re-checks
/// View on the bearer its receipt names, and a tombstone is not viewable, so it
/// is refused there. Neither case fetches or writes.
#[tokio::test]
async fn keyed_attach_from_url_on_a_tombstoned_bearer_is_refused_without_a_fetch() {
    let (addr, hits) = counting_server("captured before the delete").await;
    let registry = attachment_registry();
    let db = db().await;
    let home = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Bearer" }),
    )
    .await
    .unwrap();
    let url = format!("http://127.0.0.1:{}/notes.txt", addr.port());
    let args = json!({ "record_id": home, "url": url, "idempotency_key": "tombstoned" });
    registry
        .call(db.clone(), Caller::local(), "attach_from_url", args.clone())
        .await
        .unwrap();
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    native_ce::store::delete_record(&db, &home).await.unwrap();
    let footprint = attachment_footprint(&db).await;
    let retry = registry
        .call(db.clone(), Caller::local(), "attach_from_url", args.clone())
        .await
        .unwrap_err()
        .to_string();
    let mut fresh_args = args;
    fresh_args["idempotency_key"] = json!("never-used");
    let fresh = registry
        .call(db.clone(), Caller::local(), "attach_from_url", fresh_args)
        .await
        .unwrap_err()
        .to_string();
    assert!(retry.contains("does not exist"), "{retry}");
    assert!(fresh.contains("is deleted (tombstoned)"), "{fresh}");
    assert_eq!(hits.load(Ordering::SeqCst), 1, "a refusal must not fetch");
    assert_eq!(attachment_footprint(&db).await, footprint);
    db.close().await;
}

/// Same-key calls that all miss before any of them commits each fetch, but
/// only one attaches: the others find its row in their commit transaction and
/// replay it, rolling back their tentative blob. Later retries never fetch.
#[tokio::test]
async fn keyed_attach_from_url_concurrent_calls_attach_once() {
    let (addr, hits) = counting_server("raced").await;
    let registry = attachment_registry();
    let db = db().await;
    let home = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap();
    let args = json!({
        "record_id": home,
        "url": format!("http://127.0.0.1:{}/race.txt", addr.port()),
        "idempotency_key": "race",
    });
    let created = "SELECT COUNT(*) AS n FROM content_events WHERE type = 'record.created'";
    let before = count(&db, created).await;
    let calls = (0..4).map(|_| {
        let registry = registry.clone();
        let db = db.clone();
        let args = args.clone();
        tokio::spawn(async move {
            registry
                .call(db, Caller::local(), "attach_from_url", args)
                .await
        })
    });
    let receipts = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|joined| joined.unwrap().unwrap().to_string())
        .collect::<Vec<_>>();
    assert!(receipts.iter().all(|receipt| *receipt == receipts[0]));
    assert_eq!(count(&db, "SELECT COUNT(*) AS n FROM blobs").await, 1);
    assert_eq!(count(&db, created).await, before + 1, "one attachment");
    let fetched = hits.load(Ordering::SeqCst);
    let replay = registry
        .call(db.clone(), Caller::local(), "attach_from_url", args)
        .await
        .unwrap();
    assert_eq!(replay.to_string(), receipts[0]);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        fetched,
        "a replay must not fetch"
    );
    db.close().await;
}

/// A server that answers nothing until `count` requests are in flight, so
/// every caller has passed the pre-fetch lookup before anyone commits.
async fn barrier_server(body: &'static str, count: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_in = hits.clone();
    tokio::spawn(async move {
        loop {
            let mut waiting = Vec::new();
            while waiting.len() < count {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
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
                hits_in.fetch_add(1, Ordering::SeqCst);
                waiting.push(socket);
            }
            for mut socket in waiting {
                let _ = socket
                    .write_all(ok_response(body, "text/plain").as_bytes())
                    .await;
                let _ = socket.shutdown().await;
            }
        }
    });
    (addr, hits)
}

/// The commit-step replay, made deterministic: both same-key calls miss the
/// pre-fetch lookup and fetch (the server holds both requests), so the one
/// that commits second must replay the first's attachment inside its commit
/// transaction. Two fetches, one blob and one attachment prove that path ran.
#[tokio::test]
async fn keyed_attach_from_url_commit_step_replays_a_call_that_committed_during_the_fetch() {
    let (addr, hits) = barrier_server("held", 2).await;
    let registry = attachment_registry();
    let db = db().await;
    let home = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap();
    let args = json!({
        "record_id": home,
        "url": format!("http://127.0.0.1:{}/held.txt", addr.port()),
        "idempotency_key": "commit-step",
    });
    let created = "SELECT COUNT(*) AS n FROM content_events WHERE type = 'record.created'";
    let before = count(&db, created).await;
    let calls = (0..2).map(|_| {
        let registry = registry.clone();
        let db = db.clone();
        let args = args.clone();
        tokio::spawn(async move {
            registry
                .call(db, Caller::local(), "attach_from_url", args)
                .await
        })
    });
    let receipts = futures::future::join_all(calls)
        .await
        .into_iter()
        .map(|joined| joined.unwrap().unwrap().to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        receipts[0], receipts[1],
        "both answer with the one attachment"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        2,
        "both passed the pre-fetch lookup"
    );
    assert_eq!(count(&db, "SELECT COUNT(*) AS n FROM blobs").await, 1);
    assert_eq!(count(&db, created).await, before + 1, "one attachment");
    db.close().await;
}

/// The lookup runs only after the Edit check: a caller who lost Edit on the
/// bearer gets the denial a fresh key gets, nothing is fetched, and the
/// attachment the first call created is not disclosed.
#[tokio::test]
async fn keyed_attach_from_url_after_lost_access_matches_a_fresh_key() {
    use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};

    let (addr, hits) = counting_server("private").await;
    let registry = attachment_registry();
    let db = db().await;
    let home = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Home" }),
    )
    .await
    .unwrap();
    replace_explicit_policy(
        &db,
        "attach:test",
        &home,
        vec![
            AllowEntry::account("acct:owner", Capability::Manage),
            AllowEntry::account("acct:alice", Capability::Edit),
        ],
    )
    .await
    .unwrap();
    let person = create_record(
        &db,
        json!({ "type": "Entity", "kind": "person", "name": "Alice" }),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', 'acct:alice', 1)",
    )
    .bind(&person)
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let alice = Caller::authenticated("acct:alice");
    let args = json!({
        "record_id": home,
        "url": format!("http://127.0.0.1:{}/private.txt", addr.port()),
        "idempotency_key": "lost",
    });
    let first = registry
        .call(db.clone(), alice.clone(), "attach_from_url", args.clone())
        .await
        .unwrap();
    replace_explicit_policy(
        &db,
        "attach:test",
        &home,
        vec![AllowEntry::account("acct:owner", Capability::Manage)],
    )
    .await
    .unwrap();
    let footprint = attachment_footprint(&db).await;
    let denied = registry
        .call(db.clone(), alice.clone(), "attach_from_url", args.clone())
        .await
        .unwrap_err()
        .to_string();
    let mut fresh = args;
    fresh["idempotency_key"] = json!("never-used");
    let fresh = registry
        .call(db.clone(), alice, "attach_from_url", fresh)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(denied, fresh);
    assert!(
        !denied.contains(first["attachment_id"].as_str().unwrap()),
        "{denied}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert_eq!(attachment_footprint(&db).await, footprint);
    db.close().await;
}
