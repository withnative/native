use super::*;
use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use std::collections::{HashMap, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

fn parse_all(chunks: &[&[u8]]) -> Vec<SseEvent> {
    let mut parser = SseParser::default();
    chunks
        .iter()
        .flat_map(|chunk| parser.push(chunk).unwrap())
        .collect()
}

#[test]
fn parser_reads_id_event_and_data() {
    let events = parse_all(&[b"id: 7\nevent: content\ndata: {\"local_seq\":7}\n\n"]);
    assert_eq!(
        events,
        vec![SseEvent {
            event: Some("content".into()),
            data: "{\"local_seq\":7}".into(),
            id: Some("7".into()),
        }]
    );
}

#[test]
fn parser_joins_multiline_data_and_strips_one_space() {
    let events = parse_all(&[b"data: a\ndata:  b\ndata\ndata:c\n\n"]);
    assert_eq!(events[0].data, "a\n b\n\nc");
}

#[test]
fn parser_ignores_comments_and_does_not_dispatch_without_data() {
    let events = parse_all(&[b": heartbeat\n\n: another\nevent: ready\nid: 3\n\n"]);
    assert!(events.is_empty());
}

#[test]
fn parser_handles_crlf_cr_and_chunk_splits() {
    let events = parse_all(&[b"event: con", b"tent\r", b"\ndata: x\r\r", b"\ndata: y\n\n"]);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].event.as_deref(), Some("content"));
    assert_eq!(events[0].data, "x");
    assert_eq!(events[1].data, "y");
    assert_eq!(events[1].event, None);
}

#[test]
fn parser_id_does_not_persist_across_blocks() {
    let events = parse_all(&[b"id: 4\ndata: a\n\ndata: b\n\n"]);
    assert_eq!(events[0].id.as_deref(), Some("4"));
    assert_eq!(events[1].id, None);
}

#[test]
fn parser_rejects_ids_with_nul_and_reads_retry() {
    let mut parser = SseParser::default();
    let events = parser
        .push(b"retry: 2500\nretry: soon\nid: a\0b\ndata: x\n\n")
        .unwrap();
    assert_eq!(events[0].id, None);
    assert_eq!(parser.retry(), Some(Duration::from_millis(2500)));
}

#[test]
fn parser_strips_bom_and_tolerates_unknown_fields() {
    let events = parse_all(&[b"\xEF\xBB\xBFdata: x\nbogus: 1\nnocolon\n\n"]);
    assert_eq!(events[0].data, "x");
}

#[test]
fn parser_bounds_lines_and_events() {
    let mut parser = SseParser::default();
    assert_eq!(
        parser.push(&vec![b'a'; MAX_LINE + 1]),
        Err(ParseError::LineTooLong)
    );
    let mut parser = SseParser::default();
    let line = format!("data: {}\n", "a".repeat(MAX_LINE - 16));
    let mut result = Ok(Vec::new());
    for _ in 0..8 {
        result = parser.push(line.as_bytes());
    }
    assert_eq!(result, Err(ParseError::EventTooLarge));
}

#[test]
fn backoff_grows_is_capped_and_jittered() {
    let (min, max) = (Duration::from_secs(1), Duration::from_secs(60));
    assert_eq!(backoff_delay(0, min, max, 1.0), Duration::from_secs(1));
    assert_eq!(backoff_delay(0, min, max, 0.0), Duration::from_millis(500));
    assert_eq!(backoff_delay(3, min, max, 1.0), Duration::from_secs(8));
    assert_eq!(backoff_delay(40, min, max, 1.0), max);
    assert_eq!(backoff_delay(40, min, max, 0.0), max / 2);
}

#[derive(Clone)]
enum Script {
    Status(u16),
    /// Send these chunks, then close.
    Chunks(Vec<&'static str>),
    /// Send headers (and these chunks), then stay open and silent.
    Hold(Vec<&'static str>),
    /// 200 with a non-SSE content type.
    Json,
    /// 307 to `/elsewhere`.
    Redirect,
}

/// One recorded request: the `after` cursor and the authorization header.
type StubRequest = (Option<String>, String);

#[derive(Clone, Default)]
struct Stub {
    scripts: Arc<Mutex<VecDeque<Script>>>,
    requests: Arc<Mutex<Vec<StubRequest>>>,
    redirected: Arc<AtomicUsize>,
}

async fn events(
    State(stub): State<Stub>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    stub.requests.lock().unwrap().push((
        q.get("after").cloned(),
        headers["authorization"].to_str().unwrap().to_owned(),
    ));
    assert_eq!(headers["accept"], "text/event-stream");
    assert_eq!(
        headers[crate::client_compatibility::HEADER],
        crate::client_compatibility::advertisement()
    );
    let script = stub
        .scripts
        .lock()
        .unwrap()
        .pop_front()
        .unwrap_or(Script::Hold(vec![]));
    let sse = |body: Body| ([("content-type", "text/event-stream")], body).into_response();
    match script {
        Script::Json => ([("content-type", "application/json")], "{}").into_response(),
        Script::Redirect => {
            (StatusCode::TEMPORARY_REDIRECT, [("location", "/elsewhere")]).into_response()
        }
        Script::Status(code) => StatusCode::from_u16(code).unwrap().into_response(),
        Script::Chunks(chunks) => sse(Body::from_stream(futures::stream::iter(
            chunks
                .into_iter()
                .map(|c| Ok::<axum::body::Bytes, std::convert::Infallible>(c.into())),
        ))),
        Script::Hold(chunks) => sse(Body::from_stream(
            futures::stream::iter(
                chunks
                    .into_iter()
                    .map(|c| Ok::<axum::body::Bytes, std::convert::Infallible>(c.into())),
            )
            .chain(futures::stream::pending()),
        )),
    }
}
use futures::StreamExt as _;

struct Harness {
    _dir: tempfile::TempDir,
    stub: Stub,
    hints: Arc<AtomicUsize>,
    status: Arc<EventStatus>,
    task: tokio::task::JoinHandle<()>,
    server: tokio::task::JoinHandle<()>,
}
impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
        self.server.abort();
    }
}

fn fast() -> Timing {
    Timing {
        heartbeat_timeout: Duration::from_millis(150),
        connect_timeout: Duration::from_secs(2),
        backoff_min: Duration::from_millis(10),
        backoff_max: Duration::from_millis(40),
        refused_backoff: Duration::from_secs(3600),
        stable_after: Duration::from_secs(3600),
    }
}

async fn harness(scripts: Vec<Script>, timing: Timing) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let credential = dir.path().join("token");
    std::fs::write(&credential, "stream-token\n").unwrap();
    std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
    let stub = Stub {
        scripts: Arc::new(Mutex::new(scripts.into())),
        ..Stub::default()
    };
    let app = Router::new()
        .route("/databases/{db}/events", get(events))
        .route(
            "/elsewhere",
            get(|State(stub): State<Stub>| async move {
                stub.redirected.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }),
        )
        .with_state(stub.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = reqwest::Url::parse(&format!(
        "http://{}/databases/route-1/events",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let hints = Arc::new(AtomicUsize::new(0));
    let counter = hints.clone();
    let stream = EventStream::new(
        url,
        credential,
        Arc::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
        }),
        timing,
    )
    .unwrap();
    let status = stream.status();
    let task = tokio::spawn(stream.run());
    Harness {
        _dir: dir,
        stub,
        hints,
        status,
        task,
        server,
    }
}

async fn until(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..200 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn content_events_hint_and_other_events_do_not() {
    let h = harness(
        vec![Script::Hold(vec![
            "event: authorization\ndata: {}\n\nevent: stream\ndata: {}\n\n",
            "id: 5\nevent: ready\ndata: {\"cursor\":5}\n\n: heartbeat\n\n",
            "id: 6\nevent: content\ndata: {}\n\n",
            "id: 7\nevent: content\ndata: {}\n\n",
        ])],
        fast(),
    )
    .await;
    // One hint for the cursorless connect, one per content event.
    until("hints", || h.hints.load(Ordering::SeqCst) == 3).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(h.hints.load(Ordering::SeqCst), 3);
    let summary = h.status.summary();
    assert_eq!(summary["connected"], true);
    assert_eq!(summary["events"], 2);
    assert!(summary["last_event_at"].is_string());
    assert_eq!(h.stub.requests.lock().unwrap()[0].1, "Bearer stream-token");
}

#[tokio::test]
async fn reconnect_resumes_after_the_last_seen_id() {
    let h = harness(
        vec![
            Script::Chunks(vec![
                "id: 5\nevent: ready\ndata: {}\n\nid: 9\nevent: content\ndata: {}\n\n",
                "event: lagged\ndata: {}\n\n",
            ]),
            Script::Chunks(vec!["id: 12\nevent: content\ndata: {}\n\n"]),
            Script::Hold(vec![]),
        ],
        fast(),
    )
    .await;
    until("third connection", || {
        h.stub.requests.lock().unwrap().len() >= 3
    })
    .await;
    let requests = h.stub.requests.lock().unwrap().clone();
    assert_eq!(requests[0].0, None);
    assert_eq!(requests[1].0.as_deref(), Some("9"));
    assert_eq!(requests[2].0.as_deref(), Some("12"));
    // Cursorless connect once, plus one hint per content event; resumes do not
    // add a connect hint because hosted replays the backlog itself.
    assert_eq!(h.hints.load(Ordering::SeqCst), 3);
    // The stub records a request before the client counts the reconnect, so
    // wait for the counter rather than reading it once.
    until("two reconnects counted", || {
        h.status.summary()["reconnects"].as_u64().unwrap() >= 2
    })
    .await;
}

#[tokio::test]
async fn cursor_reset_reconnects_from_the_head_and_asks_for_a_delta() {
    let h = harness(
        vec![
            Script::Chunks(vec!["id: 9\nevent: content\ndata: {}\n\n"]),
            Script::Status(409),
            Script::Hold(vec![]),
        ],
        fast(),
    )
    .await;
    until("third connection", || {
        h.stub.requests.lock().unwrap().len() >= 3
    })
    .await;
    let requests = h.stub.requests.lock().unwrap().clone();
    assert_eq!(requests[1].0.as_deref(), Some("9"));
    assert_eq!(requests[2].0, None);
    // connect, content, connect-after-reset: the third request alone does not
    // establish that the client has accepted the response and emitted its hint.
    until("connect-after-reset hint", || {
        h.hints.load(Ordering::SeqCst) == 3
    })
    .await;
    assert_eq!(h.hints.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn missed_heartbeats_drop_the_connection_and_reconnect() {
    let h = harness(
        vec![Script::Hold(vec![": heartbeat\n\n"]), Script::Hold(vec![])],
        fast(),
    )
    .await;
    until("second connection", || {
        h.stub.requests.lock().unwrap().len() >= 2
    })
    .await;
    // The stub records a request before its response is sent. Observe the
    // client after it has validated the response headers and SSE content type.
    until("connected", || h.status.summary()["state"] == "connected").await;
    assert_eq!(h.status.summary()["state"], "connected");
}

#[tokio::test]
async fn a_repeated_auth_refusal_stops_the_stream_without_hinting() {
    for code in [401, 403] {
        let h = harness(
            vec![
                Script::Status(code),
                Script::Status(code),
                Script::Hold(vec![]),
            ],
            fast(),
        )
        .await;
        until("auth_refused", || {
            h.status.summary()["state"] == "auth_refused"
        })
        .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            h.stub.requests.lock().unwrap().len(),
            2,
            "no retry within the long backoff"
        );
        assert_eq!(h.hints.load(Ordering::SeqCst), 0);
        assert_eq!(h.status.summary()["connected"], false);
    }
}

#[tokio::test]
async fn a_single_401_is_an_ordinary_failed_connect() {
    // v2 hosted answers 401 for maintenance and "reconnect" cases.
    let h = harness(vec![Script::Status(401), Script::Hold(vec![])], fast()).await;
    until("connected", || h.status.summary()["state"] == "connected").await;
    assert_eq!(h.stub.requests.lock().unwrap().len(), 2);
    // A success in between resets the count: 401, ok-then-close, 401 is not a refusal.
    let h = harness(
        vec![
            Script::Status(401),
            Script::Chunks(vec![": x\n\n"]),
            Script::Status(401),
            Script::Hold(vec![]),
        ],
        fast(),
    )
    .await;
    until("fourth connection", || {
        h.stub.requests.lock().unwrap().len() >= 4
    })
    .await;
    // The stub records a request before its response is sent. Observe the
    // client after it has validated the response headers and SSE content type.
    until("connected", || h.status.summary()["state"] == "connected").await;
    assert_eq!(h.status.summary()["state"], "connected");
}

#[tokio::test]
async fn first_refusal_reports_reconnecting_not_auth_refused() {
    let timing = Timing {
        backoff_min: Duration::from_secs(5),
        backoff_max: Duration::from_secs(5),
        ..fast()
    };
    let h = harness(vec![Script::Status(401)], timing).await;
    until("first request", || {
        !h.stub.requests.lock().unwrap().is_empty()
    })
    .await;
    // Wait for the state rather than sleeping a fixed time: the backoff is 5 s,
    // so "reconnecting" holds long enough to be observed on a loaded runner.
    until("reconnecting", || {
        h.status.summary()["state"] == "reconnecting"
    })
    .await;
}

#[tokio::test]
async fn a_bounded_replay_close_reconnects_promptly_without_backoff() {
    let timing = Timing {
        backoff_min: Duration::from_secs(5),
        backoff_max: Duration::from_secs(5),
        ..fast()
    };
    let h = harness(
        vec![
            Script::Chunks(vec!["id: 3\nevent: content\ndata: {}\n\nid: 4\nevent: ready\ndata: {\"cursor\":4,\"has_more\":true}\n\n"]),
            Script::Chunks(vec!["id: 8\nevent: ready\ndata: {\"cursor\":8,\"has_more\":true}\n\n"]),
            Script::Hold(vec![]),
        ],
        timing,
    )
    .await;
    until("third connection", || {
        h.stub.requests.lock().unwrap().len() >= 3
    })
    .await;
    let requests = h.stub.requests.lock().unwrap().clone();
    assert_eq!(requests[1].0.as_deref(), Some("4"));
    assert_eq!(requests[2].0.as_deref(), Some("8"));
}

#[tokio::test]
async fn a_close_after_has_more_without_progress_is_a_failure() {
    let timing = Timing {
        backoff_min: Duration::from_secs(5),
        backoff_max: Duration::from_secs(5),
        ..fast()
    };
    let h = harness(
        vec![
            Script::Chunks(vec!["id: 4\nevent: ready\ndata: {\"has_more\":true}\n\n"]),
            Script::Chunks(vec!["id: 4\nevent: ready\ndata: {\"has_more\":true}\n\n"]),
            Script::Hold(vec![]),
        ],
        timing,
    )
    .await;
    until("second connection", || {
        h.stub.requests.lock().unwrap().len() >= 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        h.stub.requests.lock().unwrap().len(),
        2,
        "second close backs off"
    );
}

#[tokio::test]
async fn a_non_sse_content_type_is_not_a_connection() {
    let h = harness(
        vec![Script::Json, Script::Json, Script::Hold(vec![])],
        fast(),
    )
    .await;
    until("third connection", || {
        h.stub.requests.lock().unwrap().len() >= 3
    })
    .await;
    until("genuine connect hint", || {
        h.hints.load(Ordering::SeqCst) == 1
    })
    .await;
    assert_eq!(
        h.hints.load(Ordering::SeqCst),
        1,
        "only the genuine connect hints"
    );
}

#[tokio::test]
async fn redirects_are_refused_not_followed() {
    let timing = Timing {
        backoff_min: Duration::from_secs(5),
        backoff_max: Duration::from_secs(5),
        ..fast()
    };
    let h = harness(vec![Script::Redirect, Script::Hold(vec![])], timing).await;
    until("first request", || {
        !h.stub.requests.lock().unwrap().is_empty()
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.stub.redirected.load(Ordering::SeqCst), 0);
    assert_eq!(h.status.summary()["connected"], false);
    assert_eq!(h.hints.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_endpoint_backs_off_long() {
    let h = harness(vec![Script::Status(404), Script::Hold(vec![])], fast()).await;
    until("unsupported", || {
        h.status.summary()["state"] == "unsupported"
    })
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(h.stub.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn server_errors_retry_with_backoff() {
    let h = harness(
        vec![
            Script::Status(503),
            Script::Status(502),
            Script::Hold(vec![]),
        ],
        fast(),
    )
    .await;
    until("third connection", || {
        h.stub.requests.lock().unwrap().len() >= 3
    })
    .await;
    // The stub records a request before its response is sent. Observe the
    // client after it has validated the response headers and SSE content type.
    until("connected", || h.status.summary()["state"] == "connected").await;
    assert_eq!(h.status.summary()["state"], "connected");
}
