use super::*;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

#[derive(Clone, Default)]
struct Fake {
    requests: Arc<Mutex<Vec<(HeaderMap, String)>>>,
}

async fn hosted(
    State(fake): State<Fake>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let body = String::from_utf8(body.to_vec()).unwrap();
    let request: Value = serde_json::from_str(&body).unwrap();
    fake.requests.lock().await.push((headers.clone(), body));
    assert_eq!(headers["content-type"], "application/json");
    assert_eq!(headers["accept"], "application/json, text/event-stream");
    assert!(headers["authorization"]
        .to_str()
        .unwrap()
        .starts_with("Bearer "));
    let method = request["method"].as_str().unwrap();
    if crate::mcp::is_modern_request(&request) {
        assert_eq!(
            request["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        assert!(
            request["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"].is_object()
        );
        assert!(headers.get("mcp-protocol-version").is_none());
    }
    if method != "initialize" && !crate::mcp::is_modern_request(&request) {
        assert_eq!(headers["mcp-protocol-version"], "2025-03-26");
    }
    match method {
        "rpc_error" => (StatusCode::SERVICE_UNAVAILABLE, r#"{ "jsonrpc":"2.0", "id":17, "error":{"code":-32042,"message":"partial","data":{"outcome":"unknown","applied":1}} }"#).into_response(),
        "malformed" => (StatusCode::OK, r#"{"jsonrpc":"2.0","id":17,"error":{"code":"text","message":"broken"}}"#).into_response(),
        "notify" | "empty_request" => StatusCode::ACCEPTED.into_response(),
        "unauthorized" => (StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized","code":"auth_expired","outcome":"refused","recovery":"sign in"}"#).into_response(),
        "maintenance" => (StatusCode::SERVICE_UNAVAILABLE, axum::Json(maintenance_body())).into_response(),
        "unavailable" => (StatusCode::SERVICE_UNAVAILABLE, r#"{"error":{"code":"partial_replay","outcome":"unknown","applied":2,"partial":true,"recovery":{"action":"inspect"}}}"#).into_response(),
        "gateway" => (StatusCode::BAD_GATEWAY, "<html>bad gateway</html>").into_response(),
        "gateway_json" => (StatusCode::BAD_GATEWAY, axum::Json(json!({"code":502,"error":"proxy gateway"}))).into_response(),
        "redirect" => (StatusCode::TEMPORARY_REDIRECT, [("location", "/mcp/test-workspace")], "redirect").into_response(),
        "slow" => {
            tokio::time::sleep(Duration::from_secs(1)).await;
            axum::Json(json!({"jsonrpc":"2.0","id":request["id"],"result":"slow"})).into_response()
        }
        "sse" => ([("content-type", "text/event-stream")], format!("event: message\ndata: {{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":\"sse\"}}\n\n",request["id"])).into_response(),
        "initialize" => axum::Json(json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"2025-03-26"}})).into_response(),
        _ => {
            if request.pointer("/params/delay").is_some() { tokio::time::sleep(Duration::from_millis(40)).await; }
            // Deliberate whitespace and field order prove byte-preserving replies.
            ([("content-type", "application/json")], format!("{{ \"result\": {}, \"id\": {}, \"jsonrpc\": \"2.0\" }}", request["params"], request["id"])).into_response()
        }
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    config: NodeConfig,
    fake: Fake,
    http: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.http.abort();
    }
}

impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let token = temp.path().join("token");
        fs::write(&token, "first-token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let fake = Fake::default();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/mcp/test-workspace", post(hosted))
            .with_state(fake.clone());
        let http = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = NodeConfig {
            working_note_appends: false,
            working_refusal_drafts: false,
            markdown_folder: None,
            hosted_base_url: format!("http://{address}"),
            home_id: "test-home".into(),
            db_id: "test-workspace".into(),
            credential_file: token,
            socket_directory: temp.path().join("socket"),
            oauth_auth_file: None,
            node_install_key_file: None,
            node_install_id: None,
            standby_config: None,
            account_id: None,
            refresh_config: None,
            disk_floor_bytes: None,
            online_local_reads: None,
            local_reads_by_default: false,
            desktop_app_proof_transport: false,
            desktop_app_proof_resource_origin: None,
            pending_fork_reads: false,
            hosted_kernel_v2: false,
        };
        Self {
            _temp: temp,
            config,
            fake,
            http,
        }
    }
    fn upstream(&self, deadline: Duration) -> Arc<Upstream> {
        Arc::new(Upstream::new(self.config.clone(), deadline).unwrap())
    }
    async fn send(&self, method: &str, deadline: Duration) -> Value {
        let request = json!({"jsonrpc":"2.0","id":17,"method":method});
        let reply = self
            .upstream(deadline)
            .send(
                &request.to_string(),
                &request,
                Some("2025-03-26"),
                request.get("id"),
            )
            .await
            .unwrap();
        serde_json::from_str(&reply).unwrap()
    }
}

struct Connection {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
    task: tokio::task::JoinHandle<Result<()>>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Connection {
    fn new(upstream: Arc<Upstream>) -> Self {
        Self::with_broker(upstream, None)
    }
    fn with_broker(
        upstream: Arc<Upstream>,
        broker: Option<Arc<crate::node::agent_sessions::broker::AgentSessionsBroker>>,
    ) -> Self {
        let (client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(serve_connection_with_broker(server, upstream, broker));
        let (reader, writer) = client.into_split();
        Self {
            reader: BufReader::new(reader),
            writer,
            task,
        }
    }
    async fn send_raw(&mut self, body: &str) {
        self.writer
            .write_all(format!("{body}\n").as_bytes())
            .await
            .unwrap();
    }
    async fn send(&mut self, request: Value) {
        self.send_raw(&request.to_string()).await;
    }
    async fn reply_raw(&mut self) -> String {
        let mut line = String::new();
        timeout(Duration::from_secs(2), self.reader.read_line(&mut line))
            .await
            .unwrap()
            .unwrap();
        line.strip_suffix('\n').unwrap().to_owned()
    }
    async fn reply(&mut self) -> Value {
        serde_json::from_str(&self.reply_raw().await).unwrap()
    }
    async fn initialize(&mut self) {
        self.send(json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"fixture","version":"1"},"capabilities":{}}})).await;
        assert_eq!(
            self.reply().await["result"]["protocolVersion"],
            "2025-03-26"
        );
    }
}

#[tokio::test]
async fn legacy_negotiation_and_unchanged_bodies() {
    let fixture = Fixture::new().await;
    let mut connection = Connection::new(fixture.upstream(REQUEST_TIMEOUT));
    // Pipeline behind initialize: negotiation must finish before either send.
    let init = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#;
    let list = r#"{ "jsonrpc":"2.0", "id":1, "method":"tools/list" }"#;
    let call = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"bootstrap","arguments":{}}}"#;
    connection.send_raw(init).await;
    connection.send_raw(list).await;
    connection.send_raw(call).await;
    let _ = connection.reply().await;
    let first = connection.reply_raw().await;
    let second = connection.reply_raw().await;
    assert!(first.starts_with("{ \"result\":") && second.starts_with("{ \"result\":"));
    let captured = fixture.fake.requests.lock().await;
    assert_eq!(captured.len(), 3);
    assert!(captured[0].0.get("mcp-protocol-version").is_none());
    for (headers, body) in &captured[1..] {
        assert_eq!(headers["mcp-protocol-version"], "2025-03-26");
        assert!(body == list || body == call);
        assert!(!body.contains("clientInfo"));
    }
}

#[tokio::test]
async fn modern_body_passes_unchanged_without_legacy_header() {
    let fixture = Fixture::new().await;
    let mut connection = Connection::new(fixture.upstream(REQUEST_TIMEOUT));
    connection.initialize().await;
    let body = r#"{ "jsonrpc":"2.0","id":"modern","method":"tools/call","params":{"name":"bootstrap","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"agent","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    connection.send_raw(body).await;
    assert_eq!(connection.reply().await["id"], "modern");
    let captured = fixture.fake.requests.lock().await;
    assert_eq!(captured[1].1, body);
    assert!(captured[1].0.get("mcp-protocol-version").is_none());
    drop(captured);
    connection.send(json!({"jsonrpc":"2.0","id":"discover","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}})).await;
    assert_eq!(connection.reply().await["id"], "discover");
}

#[tokio::test]
async fn colliding_ids_and_concurrent_requests_stay_on_their_connection() {
    let fixture = Fixture::new().await;
    let upstream = fixture.upstream(REQUEST_TIMEOUT);
    let mut a = Connection::new(upstream.clone());
    let mut b = Connection::new(upstream);
    a.initialize().await;
    b.initialize().await;
    a.send(
        json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"owner":"a","delay":true}}),
    )
    .await;
    a.send(json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"owner":"a-fast"}}))
        .await;
    b.send(json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"owner":"b"}}))
        .await;
    let fast = a.reply().await;
    assert_eq!(fast["id"], 8);
    assert_eq!(fast["result"]["owner"], "a-fast");
    assert_eq!(b.reply().await["result"]["owner"], "b");
    let slow = a.reply().await;
    assert_eq!(slow["id"], 7);
    assert_eq!(slow["result"]["owner"], "a");
}

#[tokio::test]
async fn notifications_202_and_errors_produce_no_output() {
    let fixture = Fixture::new().await;
    let mut connection = Connection::new(fixture.upstream(REQUEST_TIMEOUT));
    connection.initialize().await;
    connection
        .send(json!({"jsonrpc":"2.0","method":"notify"}))
        .await;
    connection
        .send(json!({"jsonrpc":"2.0","method":"unauthorized"}))
        .await;
    connection.writer.shutdown().await.unwrap();
    let mut remaining = String::new();
    timeout(
        Duration::from_secs(2),
        connection.reader.read_to_string(&mut remaining),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(remaining.is_empty());
    assert_eq!(fixture.fake.requests.lock().await.len(), 3);
}

#[tokio::test]
async fn http_error_bodies_preserve_native_fields() {
    let fixture = Fixture::new().await;
    let auth = fixture.send("unauthorized", REQUEST_TIMEOUT).await;
    assert_eq!(auth["id"], 17);
    assert!(auth["error"]["code"].is_i64());
    let data = &auth["error"]["data"];
    assert_eq!(data["http_status"], 401);
    assert_eq!(data["code"], "auth_expired");
    assert_eq!(data["outcome"], "refused");
    assert_eq!(data["recovery"], "sign in");
    let unavailable = fixture.send("unavailable", REQUEST_TIMEOUT).await;
    let data = &unavailable["error"]["data"];
    assert_eq!(data["http_status"], 503);
    assert_eq!(data["code"], "partial_replay");
    assert_eq!(data["outcome"], "unknown");
    assert_eq!(data["applied"], 2);
    assert_eq!(data["partial"], true);
    assert_eq!(data["recovery"]["action"], "inspect");
    assert_eq!(data["upstream_body"]["error"]["applied"], 2);
}

fn maintenance_body() -> Value {
    json!({
        "error": "this Native deployment is temporarily read-only",
        "error_code": "DEPLOYMENT_READ_ONLY",
        "retryable": true,
        "applied": false,
        "operation": "outbox_handoff",
        "recovery": "This write was not applied or queued; retry after maintenance",
        "retry_after_secs": 30
    })
}

#[tokio::test]
async fn http_maintenance_refusal_is_clear_and_preserves_the_complete_body() {
    let fixture = Fixture::new().await;
    let reply = fixture.send("maintenance", REQUEST_TIMEOUT).await;
    let data = &reply["error"]["data"];
    assert_eq!(data["http_status"], 503);
    assert_eq!(data["outcome"], "refused");
    assert_eq!(data["applied"], false);
    assert_eq!(data["retryable"], true);
    assert_eq!(data["retry_after_secs"], 30);
    assert_eq!(data["upstream_body"], maintenance_body());
    for (key, value) in maintenance_body().as_object().unwrap() {
        assert_eq!(&data[key], value, "{key}");
    }
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("not applied or queued"));
}

#[tokio::test]
async fn gateway_and_timeout_are_unknown_and_redirect_is_not_followed() {
    let fixture = Fixture::new().await;
    let empty = fixture.send("empty_request", REQUEST_TIMEOUT).await;
    assert_eq!(empty["error"]["data"]["http_status"], 202);
    assert_eq!(empty["error"]["data"]["outcome"], "unknown");
    let gateway = fixture.send("gateway", REQUEST_TIMEOUT).await;
    assert_eq!(gateway["error"]["data"]["http_status"], 502);
    assert_eq!(gateway["error"]["data"]["outcome"], "unknown");
    let slow = fixture.send("slow", Duration::from_millis(250)).await;
    assert_eq!(slow["error"]["data"]["outcome"], "unknown");
    assert!(slow["error"]["message"]
        .as_str()
        .unwrap()
        .contains("check against hosted"));
    let redirect = fixture.send("redirect", REQUEST_TIMEOUT).await;
    assert_eq!(redirect["error"]["data"]["http_status"], 307);
    assert_eq!(fixture.fake.requests.lock().await.len(), 4);
}

#[tokio::test]
async fn connection_refused_is_not_sent() {
    let mut fixture = Fixture::new().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    fixture.config.hosted_base_url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let reply = fixture.send("tools/list", REQUEST_TIMEOUT).await;
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert!(fixture.fake.requests.lock().await.is_empty());
}

#[tokio::test]
async fn rotated_credentials_are_used_and_insecure_rotation_is_not_sent() {
    let fixture = Fixture::new().await;
    let upstream = fixture.upstream(REQUEST_TIMEOUT);
    let mut connection = Connection::new(upstream);
    connection.initialize().await;
    let replacement = fixture.config.credential_file.with_extension("new");
    fs::write(&replacement, "second-token").unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
    fs::rename(replacement, &fixture.config.credential_file).unwrap();
    connection
        .send(json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .await;
    let _ = connection.reply().await;
    assert_eq!(
        fixture.fake.requests.lock().await[1].0["authorization"],
        "Bearer second-token"
    );
    fs::write(&fixture.config.credential_file, "third-token").unwrap();
    connection
        .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}))
        .await;
    let _ = connection.reply().await;
    assert_eq!(
        fixture.fake.requests.lock().await[2].0["authorization"],
        "Bearer third-token"
    );
    fs::set_permissions(
        &fixture.config.credential_file,
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    connection
        .send(json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}))
        .await;
    assert_eq!(
        connection.reply().await["error"]["data"]["outcome"],
        "not_sent"
    );
    assert_eq!(fixture.fake.requests.lock().await.len(), 3);
}

#[tokio::test]
async fn socket_permissions_live_refusal_stale_removal_and_path_guards() {
    let fixture = Fixture::new().await;
    let (listener, guard) = bind_socket(&fixture.config).await.unwrap();
    assert_eq!(
        fs::metadata(&fixture.config.socket_directory)
            .unwrap()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(fixture.config.socket_path()).unwrap().mode() & 0o777,
        0o600
    );
    assert!(bind_socket(&fixture.config).await.is_err());
    // A listener outside our lock still prevents stale removal.
    drop(listener);
    drop(guard);
    let live = UnixListener::bind(fixture.config.socket_path()).unwrap();
    fs::set_permissions(
        fixture.config.socket_path(),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(bind_socket(&fixture.config).await.is_err());
    drop(live); // Leaves a stale inode.
    let (listener, guard) = bind_socket(&fixture.config).await.unwrap();
    drop(listener);
    drop(guard);
    assert!(!fixture.config.socket_path().exists());
    fs::write(fixture.config.socket_path(), "do not remove").unwrap();
    assert!(bind_socket(&fixture.config).await.is_err());
    assert_eq!(
        fs::read_to_string(fixture.config.socket_path()).unwrap(),
        "do not remove"
    );
    fs::remove_file(fixture.config.socket_path()).unwrap();
    std::os::unix::fs::symlink(
        &fixture.config.credential_file,
        fixture.config.socket_path(),
    )
    .unwrap();
    assert!(bind_socket(&fixture.config).await.is_err());
    fs::remove_file(fixture.config.socket_path()).unwrap();
    fs::set_permissions(
        &fixture.config.socket_directory,
        fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    assert!(bind_socket(&fixture.config).await.is_err());
}

#[tokio::test]
async fn shim_socket_to_hosted_and_eof_reply_drain() {
    let fixture = Fixture::new().await;
    let upstream = fixture.upstream(REQUEST_TIMEOUT);
    let (listener, _guard) = bind_socket(&fixture.config).await.unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve_connection(stream, upstream).await.unwrap();
    });
    let (mut input, shim_input) = tokio::io::duplex(8192);
    let (shim_output, mut output) = tokio::io::duplex(8192);
    let socket = fixture.config.socket_path();
    let shim = tokio::spawn(async move {
        connect(&socket, shim_input, shim_output).await.unwrap();
    });
    input.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sse\"}\n").await.unwrap();
    input.shutdown().await.unwrap();
    let mut replies = String::new();
    timeout(Duration::from_secs(2), output.read_to_string(&mut replies))
        .await
        .unwrap()
        .unwrap();
    let replies: Vec<Value> = replies
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[1]["result"], "sse");
    shim.await.unwrap();
    server.await.unwrap();
}

#[test]
fn sse_requires_one_message_and_rpc_requires_numeric_error_code() {
    assert!(decode_reply("data: {}\n\ndata: {}\n\n").is_none());
    assert!(decode_reply("data: not-json\n\n").is_none());
    assert!(!is_rpc_reply(
        &json!({"jsonrpc":"2.0","id":1,"error":{"code":"bad","message":"bad"}})
    ));
    assert!(!is_rpc_reply(
        &json!({"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"bad"}})
    ));
}

#[tokio::test]
async fn rpc_errors_are_verbatim_and_malformed_rpc_is_framed() {
    let fixture = Fixture::new().await;
    let upstream = fixture.upstream(REQUEST_TIMEOUT);
    let request = json!({"jsonrpc":"2.0","id":17,"method":"rpc_error"});
    let raw = upstream
        .send(
            &request.to_string(),
            &request,
            Some("2025-03-26"),
            request.get("id"),
        )
        .await
        .unwrap();
    assert_eq!(
        raw,
        r#"{ "jsonrpc":"2.0", "id":17, "error":{"code":-32042,"message":"partial","data":{"outcome":"unknown","applied":1}} }"#
    );
    let malformed = fixture.send("malformed", REQUEST_TIMEOUT).await;
    assert_eq!(malformed["id"], 17);
    assert_eq!(malformed["error"]["code"], -32000);
    assert_eq!(malformed["error"]["data"]["outcome"], "unknown");
    assert_eq!(
        malformed["error"]["data"]["upstream_body"]["error"]["code"],
        "text"
    );
}

fn shim_test_policy(window: Duration) -> shim::ShimPolicy {
    shim::ShimPolicy {
        window,
        initial_delay: Duration::from_millis(10),
        max_delay: Duration::from_millis(50),
    }
}

struct ShimClient {
    input: tokio::io::DuplexStream,
    lines: BufReader<tokio::io::DuplexStream>,
    task: tokio::task::JoinHandle<Result<()>>,
}

fn spawn_shim(socket: &Path, window: Duration) -> ShimClient {
    let (input, shim_input) = tokio::io::duplex(16384);
    let (shim_output, output) = tokio::io::duplex(16384);
    let socket = socket.to_owned();
    let task = tokio::spawn(async move {
        shim::connect_with_policy(&socket, shim_input, shim_output, shim_test_policy(window)).await
    });
    ShimClient {
        input,
        lines: BufReader::new(output),
        task,
    }
}

impl ShimClient {
    async fn send(&mut self, frame: Value) {
        self.input
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
    }
    async fn next(&mut self) -> Value {
        let mut line = String::new();
        timeout(Duration::from_secs(3), self.lines.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for shim output"))
            .unwrap();
        assert!(!line.is_empty(), "shim closed its output");
        serde_json::from_str(line.trim()).unwrap_or_else(|_| panic!("bad shim output: {line}"))
    }
}

struct PeerConn {
    lines: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

impl PeerConn {
    fn new(stream: UnixStream) -> Self {
        let (read, writer) = stream.into_split();
        Self {
            lines: BufReader::new(read),
            writer,
        }
    }
    async fn next(&mut self) -> Value {
        let mut line = String::new();
        timeout(Duration::from_secs(3), self.lines.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for a frame at the fake node"))
            .unwrap();
        assert!(!line.is_empty(), "shim closed the node connection");
        serde_json::from_str(line.trim()).unwrap_or_else(|_| panic!("bad frame: {line}"))
    }
    async fn send(&mut self, frame: Value) {
        self.writer
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
    }
    async fn initialize(&mut self, version: &str, capabilities: Value) -> Value {
        let request = self.next().await;
        assert_eq!(request["method"], "initialize");
        self.send(json!({"jsonrpc":"2.0","id":request["id"],
            "result":{"protocolVersion":version,"capabilities":capabilities,"serverInfo":{"name":"fake","version":"1"}}}))
            .await;
        request
    }
}

async fn bind_peer() -> (tempfile::TempDir, PathBuf, tokio::net::UnixListener) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    (dir, path, listener)
}

const SHIM_INIT: &str = r#"{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","clientInfo":{"name":"fixture","version":"1"},"capabilities":{}}}"#;

#[tokio::test]
async fn shim_stays_alive_on_node_eof_while_stdin_is_open() {
    let fixture = Fixture::new().await;
    let (listener, _guard) = bind_socket(&fixture.config).await.unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"node reply\n").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let (mut input, shim_input) = tokio::io::duplex(8192);
    let (shim_output, output) = tokio::io::duplex(8192);
    let socket = fixture.config.socket_path();
    let mut shim = tokio::spawn(async move {
        shim::connect_with_policy(
            &socket,
            shim_input,
            shim_output,
            shim_test_policy(Duration::from_secs(30)),
        )
        .await
        .unwrap();
    });
    let mut lines = BufReader::new(output);
    let mut reply = String::new();
    timeout(Duration::from_secs(2), lines.read_line(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, "node reply\n");
    // Node EOF no longer ends the shim: it is reconnecting.
    assert!(timeout(Duration::from_millis(300), &mut shim)
        .await
        .is_err());
    // Closing stdin during the reconnect ends it promptly.
    input.shutdown().await.unwrap();
    timeout(Duration::from_secs(2), shim)
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn shim_reconnects_mid_idle_and_sends_queued_requests() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_secs(5));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    let init = gen1.initialize("2025-03-26", json!({"tools":{}})).await;
    assert_eq!(init["params"]["clientInfo"]["name"], "fixture");
    let init_reply = client.next().await;
    assert_eq!(init_reply["result"]["protocolVersion"], "2025-03-26");
    // The shim advertises its own listChanged notification capability.
    assert_eq!(
        init_reply["result"]["capabilities"]["tools"]["listChanged"],
        true
    );
    drop(gen1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}))
        .await;
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen2 = PeerConn::new(stream);
    let replay = gen2.initialize("2025-03-26", json!({"tools":{}})).await;
    assert!(
        replay["id"].is_string(),
        "replay must use a shim-internal id"
    );
    assert_eq!(replay["params"]["clientInfo"]["name"], "fixture");
    assert_eq!(replay["params"]["protocolVersion"], "2025-06-18");
    assert_eq!(gen2.next().await["method"], "notifications/initialized");
    let queued = gen2.next().await;
    assert_eq!(queued["id"], 1);
    assert_eq!(queued["method"], "tools/list");
    gen2.send(json!({"jsonrpc":"2.0","id":1,"result":{"tools":[]}}))
        .await;
    assert_eq!(client.next().await["result"]["tools"], json!([]));
}

#[tokio::test]
async fn shim_answers_unknown_mid_request_and_never_replays_it() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_secs(5));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    gen1.initialize("2025-03-26", json!({"tools":{}})).await;
    client.next().await;
    client
        .send(json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"records_write.create_record","arguments":{}}}))
        .await;
    assert_eq!(gen1.next().await["id"], 2);
    drop(gen1); // No reply: the call may have been applied.
    let lost = client.next().await;
    assert_eq!(lost["id"], 2);
    assert_eq!(lost["error"]["data"]["outcome"], "unknown");
    client
        .send(json!({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}))
        .await;
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen2 = PeerConn::new(stream);
    gen2.initialize("2025-03-26", json!({"tools":{}})).await;
    assert_eq!(gen2.next().await["method"], "notifications/initialized");
    let forwarded = gen2.next().await;
    assert_eq!(
        forwarded["id"], 3,
        "only the queued request may be forwarded"
    );
    gen2.send(json!({"jsonrpc":"2.0","id":3,"result":{"tools":[]}}))
        .await;
    assert_eq!(client.next().await["id"], 3);
}

#[tokio::test]
async fn shim_exits_when_reconnect_negotiates_a_different_protocol() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_secs(5));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    gen1.initialize("2025-03-26", json!({"tools":{}})).await;
    client.next().await;
    drop(gen1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}))
        .await;
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen2 = PeerConn::new(stream);
    gen2.initialize("2024-11-05", json!({"tools":{}})).await;
    let refused = client.next().await;
    assert_eq!(refused["id"], 5);
    assert_eq!(refused["error"]["data"]["outcome"], "not_sent");
    timeout(Duration::from_secs(2), client.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shim_settles_queue_when_reconnect_initialize_is_auth_refused() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_secs(5));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    gen1.initialize("2025-03-26", json!({"tools":{}})).await;
    client.next().await;
    drop(gen1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}))
        .await;
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen2 = PeerConn::new(stream);
    let replay = gen2.next().await;
    assert_eq!(replay["method"], "initialize");
    gen2.send(json!({"jsonrpc":"2.0","id":replay["id"],"error":{"code":-32000,"message":"refused","data":{"http_status":401,"outcome":"refused"}}}))
        .await;
    let refused = client.next().await;
    assert_eq!(refused["id"], 4);
    assert_eq!(refused["error"]["data"]["outcome"], "not_sent");
    assert_eq!(refused["error"]["data"]["reason"], "node_auth_refused");
    timeout(Duration::from_secs(2), client.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shim_refuses_a_held_initialize_when_reconnect_is_auth_refused() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_secs(5));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    assert_eq!(gen1.next().await["method"], "initialize");
    drop(gen1); // Initialize sent, never answered: held, not answered unknown.
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen2 = PeerConn::new(stream);
    let replay = gen2.next().await;
    assert_eq!(replay["method"], "initialize");
    gen2.send(json!({"jsonrpc":"2.0","id":replay["id"],"error":{"code":-32000,"message":"refused","data":{"http_status":403,"outcome":"refused"}}}))
        .await;
    let refused = client.next().await;
    assert_eq!(refused["id"], 0);
    assert_eq!(refused["error"]["data"]["reason"], "node_auth_refused");
    timeout(Duration::from_secs(2), client.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shim_settles_queue_when_the_tools_probe_is_auth_refused() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_secs(5));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    gen1.initialize("2025-03-26", json!({"tools":{}})).await;
    client.next().await;
    client
        .send(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}))
        .await;
    assert_eq!(gen1.next().await["method"], "tools/list");
    gen1.send(json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}}))
        .await;
    client.next().await;
    drop(gen1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":8,"method":"ping","params":{}}))
        .await;
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen2 = PeerConn::new(stream);
    gen2.initialize("2025-03-26", json!({"tools":{}})).await;
    assert_eq!(gen2.next().await["method"], "notifications/initialized");
    let probe = gen2.next().await;
    assert_eq!(probe["method"], "tools/list");
    gen2.send(json!({"jsonrpc":"2.0","id":probe["id"],"error":{"code":-32000,"message":"refused","data":{"http_status":401,"outcome":"refused"}}}))
        .await;
    let refused = client.next().await;
    assert_eq!(refused["id"], 8);
    assert_eq!(refused["error"]["data"]["outcome"], "not_sent");
    timeout(Duration::from_secs(2), client.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shim_exits_when_tools_capability_is_removed_on_reconnect() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_secs(5));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    gen1.initialize("2025-03-26", json!({"tools":{"listChanged":true}}))
        .await;
    client.next().await;
    drop(gen1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}}))
        .await;
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen2 = PeerConn::new(stream);
    // Same version, but `tools` (and its listChanged promise) is gone.
    gen2.initialize("2025-03-26", json!({})).await;
    let refused = client.next().await;
    assert_eq!(refused["id"], 6);
    assert_eq!(refused["error"]["data"]["outcome"], "not_sent");
    assert_eq!(
        refused["error"]["data"]["reason"],
        "protocol_changed_on_reconnect"
    );
    timeout(Duration::from_secs(2), client.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shim_notifies_when_the_tool_list_changes_on_reconnect() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_secs(5));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    gen1.initialize("2025-03-26", json!({"tools":{}})).await;
    client.next().await;
    client
        .send(json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}))
        .await;
    assert_eq!(gen1.next().await["method"], "tools/list");
    gen1.send(json!({"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a"}]}}))
        .await;
    client.next().await;
    drop(gen1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":9,"method":"ping","params":{}}))
        .await;
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen2 = PeerConn::new(stream);
    gen2.initialize("2025-03-26", json!({"tools":{}})).await;
    assert_eq!(gen2.next().await["method"], "notifications/initialized");
    let probe = gen2.next().await;
    assert_eq!(probe["method"], "tools/list");
    gen2.send(
        json!({"jsonrpc":"2.0","id":probe["id"],"result":{"tools":[{"name":"a"},{"name":"b"}]}}),
    )
    .await;
    assert_eq!(
        client.next().await["method"],
        "notifications/tools/list_changed"
    );
    let queued = gen2.next().await;
    assert_eq!(queued["id"], 9);
    gen2.send(json!({"jsonrpc":"2.0","id":9,"result":"pong"}))
        .await;
    assert_eq!(client.next().await["result"], "pong");
}

#[tokio::test]
async fn shim_fails_queued_requests_when_the_reconnect_window_expires() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_millis(400));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    gen1.initialize("2025-03-26", json!({"tools":{}})).await;
    client.next().await;
    drop(gen1);
    drop(listener);
    std::fs::remove_file(&path).unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}))
        .await;
    let expired = client.next().await;
    assert_eq!(expired["id"], 7);
    assert_eq!(expired["error"]["data"]["outcome"], "not_sent");
    assert_eq!(
        expired["error"]["data"]["reason"],
        "reconnect_window_expired"
    );
    timeout(Duration::from_secs(2), client.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shim_exits_promptly_when_stdin_closes_during_reconnect() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_secs(30));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    gen1.initialize("2025-03-26", json!({"tools":{}})).await;
    client.next().await;
    drop(gen1);
    drop(listener);
    std::fs::remove_file(&path).unwrap();
    drop(client.input);
    timeout(Duration::from_secs(2), client.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn shim_reconnects_modern_clients_without_replaying_initialize() {
    let (_dir, path, listener) = bind_peer().await;
    let mut client = spawn_shim(&path, Duration::from_secs(5));
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen1 = PeerConn::new(stream);
    let meta = json!({"io.modelcontextprotocol/protocolVersion":"2026-07-28",
        "io.modelcontextprotocol/clientInfo":{"name":"fixture","version":"1"},
        "io.modelcontextprotocol/clientCapabilities":{}});
    client
        .send(json!({"jsonrpc":"2.0","id":"m1","method":"server/discover","params":{"_meta":meta}}))
        .await;
    let discover = gen1.next().await;
    assert_eq!(discover["method"], "server/discover");
    gen1.send(json!({"jsonrpc":"2.0","id":"m1","result":{"supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"resources":{}}}}))
        .await;
    assert_eq!(
        client.next().await["result"]["capabilities"]["tools"]["listChanged"],
        true
    );
    client
        .send(json!({"jsonrpc":"2.0","id":"m2","method":"tools/list","params":{"_meta":meta}}))
        .await;
    assert_eq!(gen1.next().await["method"], "tools/list");
    gen1.send(json!({"jsonrpc":"2.0","id":"m2","result":{"tools":[{"name":"a"}]}}))
        .await;
    client.next().await;
    drop(gen1);
    tokio::time::sleep(Duration::from_millis(150)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":"m3","method":"tools/call","params":{"name":"bootstrap","arguments":{},"_meta":meta}}))
        .await;
    let (stream, _) = listener.accept().await.unwrap();
    let mut gen2 = PeerConn::new(stream);
    let probe = gen2.next().await;
    assert_eq!(
        probe["method"], "server/discover",
        "modern clients must not get a replayed initialize"
    );
    gen2.send(json!({"jsonrpc":"2.0","id":probe["id"],"result":{"supportedVersions":["2026-07-28"],"capabilities":{"tools":{},"resources":{}}}}))
        .await;
    let tools_probe = gen2.next().await;
    assert_eq!(tools_probe["method"], "tools/list");
    gen2.send(json!({"jsonrpc":"2.0","id":tools_probe["id"],"result":{"tools":[{"name":"a"}]}}))
        .await;
    let forwarded = gen2.next().await;
    assert_eq!(forwarded["id"], "m3");
    gen2.send(json!({"jsonrpc":"2.0","id":"m3","result":"ok"}))
        .await;
    assert_eq!(client.next().await["result"], "ok");
}

#[tokio::test]
async fn native_http_outcomes_are_not_gateway_failover_signals() {
    let fixture = Fixture::new().await;
    for (method, expected) in [
        ("unavailable", None),
        ("gateway", Some(Health::Unreachable)),
        ("gateway_json", Some(Health::Unreachable)),
        ("unauthorized", Some(Health::AuthRefused)),
    ] {
        let message = json!({"jsonrpc":"2.0","id":17,"method":method});
        let report = fixture
            .upstream(Duration::from_secs(1))
            .send_classified(
                &message.to_string(),
                &message,
                Some("2025-03-26"),
                message.get("id"),
            )
            .await;
        assert!(report.failure == expected);
        assert!(report.reply.is_some());
    }
}

#[test]
fn the_disk_floor_is_an_optional_setting() {
    let base = |extra: &str| {
        format!(
            r#"{{"hosted_base_url":"https://h.example","home_id":"h","db_id":"d","credential_file":"/c","socket_directory":"/s"{extra}}}"#
        )
    };
    let default: NodeConfig = serde_json::from_str(&base("")).unwrap();
    assert_eq!(default.disk_floor_bytes, None);
    let set: NodeConfig = serde_json::from_str(&base(r#","disk_floor_bytes":42"#)).unwrap();
    assert_eq!(set.disk_floor_bytes, Some(42));
}

#[test]
fn markdown_folder_defaults_on_and_accepts_an_off_switch() {
    let base = |extra: &str| {
        format!(
            r#"{{"hosted_base_url":"https://h.example","home_id":"h","db_id":"d","credential_file":"/c","socket_directory":"/s"{extra}}}"#
        )
    };
    // Absent and null mean the default path (on with a standby copy).
    let default: NodeConfig = serde_json::from_str(&base("")).unwrap();
    assert_eq!(default.markdown_folder, None);
    let null: NodeConfig = serde_json::from_str(&base(r#","markdown_folder":null"#)).unwrap();
    assert_eq!(null.markdown_folder, None);
    // Explicit true is the default as well.
    let on: NodeConfig = serde_json::from_str(&base(r#","markdown_folder":true"#)).unwrap();
    assert_eq!(on.markdown_folder, None);
    // A string path keeps working unchanged.
    let explicit: NodeConfig =
        serde_json::from_str(&base(r#","markdown_folder":"/private/vault""#)).unwrap();
    assert_eq!(
        explicit.markdown_folder,
        Some(MarkdownFolder::Explicit(PathBuf::from("/private/vault")))
    );
    // False turns the vault off.
    let off: NodeConfig = serde_json::from_str(&base(r#","markdown_folder":false"#)).unwrap();
    assert_eq!(off.markdown_folder, Some(MarkdownFolder::Disabled));
    // Empty and non-absolute paths are rejected at parse time with a message
    // that names the rule.
    // Empty and non-absolute paths are rejected at parse time with a message
    // that names the rule.
    for bad in [r#""""#, r#""relative/vault""#, r#""~/vault""#] {
        let json = base(&format!(r#","markdown_folder":{bad}"#));
        let err = match serde_json::from_str::<NodeConfig>(&json) {
            Ok(_) => panic!("relative markdown_folder must not parse: {json}"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains("node markdown_folder must be an absolute path"),
            "unexpected parse error: {err}"
        );
    }
    // Other shapes are rejected by kind, without echoing the value.
    for (bad, kind) in [
        (r#"{"path":"/x"}"#, "an object"),
        (r#"["/x"]"#, "an array"),
        (r#"42"#, "a number"),
    ] {
        let json = base(&format!(r#","markdown_folder":{bad}"#));
        let err = match serde_json::from_str::<NodeConfig>(&json) {
            Ok(_) => panic!("structured markdown_folder must not parse: {json}"),
            Err(err) => err.to_string(),
        };
        assert!(
            err.contains(&format!("got {kind}")) && !err.contains("/x"),
            "unexpected parse error: {err}"
        );
    }
}

#[tokio::test]
async fn local_route_without_standby_refuses_before_write_gate() {
    let mut fixture = Fixture::new().await;
    fixture.config.account_id = Some("acct_status_binding".into());
    let upstream = Upstream::new(fixture.config.clone(), REQUEST_TIMEOUT).unwrap();
    let (_listener, _guard) = bind_socket(&fixture.config).await.unwrap();
    #[cfg(feature = "mcp-executor-prototype")]
    let gate = Arc::new(
        WriteGate::open(
            &fixture.config.socket_directory,
            gate::GateConfig::default(),
        )
        .unwrap(),
    );
    #[cfg(feature = "mcp-executor-prototype")]
    let route_gate = Some(&gate);
    #[cfg(not(feature = "mcp-executor-prototype"))]
    let route_gate = None;
    let direct = std::sync::atomic::AtomicBool::new(false);
    for name in ["records_read", "records_write"] {
        let message = json!({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":name,"arguments":{},"_meta":{"native/route":"local"}}});
        let ctx = crate::node::agent_sessions::routing::test_ctx().0;
        let reply = route_message(
            &upstream,
            None,
            route_gate,
            None,
            &ctx,
            &message.to_string(),
            message.clone(),
            None,
            &direct,
            &Caller::new(None, Cancel::new()),
        )
        .await
        .0
        .unwrap();
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    }
    assert!(fixture.fake.requests.lock().await.is_empty());
    #[cfg(feature = "mcp-executor-prototype")]
    assert_eq!(gate.status(&Default::default())["entry_counts"], json!({}));
}

#[tokio::test]
async fn agent_sessions_tools_are_answered_locally_and_never_forwarded() {
    use crate::node::agent_sessions::protocol::{
        TOOL_CAPABILITIES, TOOL_FOLLOW, TOOL_HISTORY, TOOL_LIST, TOOL_UNFOLLOW,
    };
    let fixture = Fixture::new().await;
    let mut connection = Connection::new(fixture.upstream(REQUEST_TIMEOUT));
    connection.initialize().await;
    // `initialize` is the only frame allowed upstream from this connection.
    let sent = fixture.fake.requests.lock().await.len();
    assert!(!fixture.fake.requests.lock().await.is_empty());
    let calls = [
        (TOOL_CAPABILITIES, json!({})),
        (TOOL_LIST, json!({})),
        (
            TOOL_HISTORY,
            json!({"hostId": "h", "hostEpoch": "e", "sessionId": "s"}),
        ),
        (
            TOOL_FOLLOW,
            json!({"hostId": "h", "hostEpoch": "e", "sessionId": "s"}),
        ),
        (TOOL_UNFOLLOW, json!({"subscriptionId": "sub-1"})),
    ];
    for (name, arguments) in &calls {
        connection
            .send(json!({"jsonrpc":"2.0","id":name,"method":"tools/call","params":{"name":name,"arguments":arguments}}))
            .await;
    }
    let mut replies = std::collections::HashMap::new();
    for _ in &calls {
        let reply = connection.reply().await;
        let id = reply["id"].as_str().unwrap_or("").to_owned();
        replies.insert(id, reply);
    }
    assert_eq!(replies.len(), calls.len());
    for (name, _) in &calls {
        let reply = &replies[*name];
        if *name == TOOL_CAPABILITIES {
            assert_eq!(reply["result"]["isError"], false, "{reply}");
            assert_eq!(
                reply["result"]["structuredContent"]["contract"], "native.node.agent-sessions.v1",
                "{reply}"
            );
            assert_eq!(
                reply["result"]["structuredContent"]["operations"],
                json!([]),
                "{reply}"
            );
        } else {
            assert_eq!(reply["result"]["isError"], true, "{reply}");
            assert_eq!(
                reply["result"]["structuredContent"]["code"], "unavailable",
                "{reply}"
            );
        }
    }
    // No agent-sessions frame reached the upstream fake.
    assert_eq!(fixture.fake.requests.lock().await.len(), sent);
}

#[tokio::test]
async fn agent_sessions_batch_is_refused_and_never_forwarded() {
    use crate::node::agent_sessions::protocol::{TOOL_FOLLOW, TOOL_LIST};
    let fixture = Fixture::new().await;
    let mut connection = Connection::new(fixture.upstream(REQUEST_TIMEOUT));
    connection.initialize().await;
    let sent = fixture.fake.requests.lock().await.len();
    // One frame, one batch: a session tool inside refuses the whole array.
    connection
        .send(json!([
            {"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":TOOL_FOLLOW,"arguments":{"hostId":"h","hostEpoch":"e","sessionId":"s"}}},
            {"jsonrpc":"2.0","id":"b","method":"tools/call","params":{"name":TOOL_LIST,"arguments":{}}},
            {"jsonrpc":"2.0","id":"c","method":"tools/call","params":{"name":"bootstrap","arguments":{}}},
        ]))
        .await;
    let reply = connection.reply().await;
    assert_eq!(reply["id"], Value::Null);
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert_eq!(reply["error"]["data"]["reason"], "batch_refused");
    // Neither the session tools nor the bundled bootstrap reached upstream.
    assert_eq!(fixture.fake.requests.lock().await.len(), sent);
}

#[tokio::test]
async fn agent_sessions_tools_with_configured_broker_stay_local() {
    use crate::node::agent_sessions::protocol::{
        TOOL_CAPABILITIES, TOOL_FOLLOW, TOOL_HISTORY, TOOL_LIST, TOOL_UNFOLLOW,
    };
    use crate::node::agent_sessions::test_support::{
        broker_for, epoch_of, password_env, run_until_reachable, FakeDaemon, FakeScript,
    };
    let fixture = Fixture::new().await;
    let fake = FakeDaemon::new(FakeScript::one()).await;
    let dir = tempfile::tempdir().unwrap();
    let env = password_env(dir.path());
    let broker = broker_for(&fake.url, "srv_test", &env);
    let run = run_until_reachable(&broker).await;
    let epoch = epoch_of(&broker).await;
    let mut connection =
        Connection::with_broker(fixture.upstream(REQUEST_TIMEOUT), Some(broker.clone()));
    connection.initialize().await;
    let sent = fixture.fake.requests.lock().await.len();
    // Capabilities, list, history: answered locally with live daemon data.
    for (name, arguments) in [
        (TOOL_CAPABILITIES, json!({})),
        (TOOL_LIST, json!({})),
        (
            TOOL_HISTORY,
            json!({"hostId": "srv_test", "hostEpoch": epoch, "sessionId": "a"}),
        ),
    ] {
        connection
            .send(json!({"jsonrpc":"2.0","id":name,"method":"tools/call","params":{"name":name,"arguments":arguments}}))
            .await;
    }
    for _ in 0..3 {
        let reply = connection.reply().await;
        assert_eq!(reply["result"]["isError"], false, "{reply}");
    }
    // Follow then unfollow through the socket: the reply carries the
    // subscription, and the slot frees for the next follow.
    connection
        .send(json!({"jsonrpc":"2.0","id":"follow-1","method":"tools/call","params":{"name":TOOL_FOLLOW,"arguments":{"hostId":"srv_test","hostEpoch":epoch,"sessionId":"a"}}}))
        .await;
    let follow = connection.reply().await;
    assert_eq!(follow["id"], "follow-1");
    assert_eq!(follow["result"]["isError"], false, "{follow}");
    // The pusher stays silent on a quiet session; unfollow by id.
    let sub = follow["result"]["structuredContent"]["subscriptionId"]
        .as_str()
        .unwrap()
        .to_owned();
    connection
        .send(json!({"jsonrpc":"2.0","id":"unfollow-1","method":"tools/call","params":{"name":TOOL_UNFOLLOW,"arguments":{"subscriptionId":sub}}}))
        .await;
    let unfollowed = connection.reply().await;
    assert_eq!(
        unfollowed["result"]["structuredContent"]["unfollowed"],
        true
    );
    // Local route hint: still answered locally, still nothing upstream.
    connection
        .send(json!({"jsonrpc":"2.0","id":"local-1","method":"tools/call","params":{"name":TOOL_LIST,"arguments":{},"_meta":{"native/route":"local"}}}))
        .await;
    let local = connection.reply().await;
    assert_eq!(local["result"]["isError"], false, "{local}");
    // Refused route value: refused as not sent, never forwarded.
    connection
        .send(json!({"jsonrpc":"2.0","id":"refused-1","method":"tools/call","params":{"name":TOOL_LIST,"arguments":{},"_meta":{"native/route":"remote"}}}))
        .await;
    let refused = connection.reply().await;
    assert_eq!(refused["error"]["data"]["outcome"], "not_sent");
    assert_eq!(fixture.fake.requests.lock().await.len(), sent);
    run.abort();
    fake.stop();
}

fn expected_connection_scope() -> connection_binding::Scope {
    connection_binding::Scope {
        account_id: "acct_owner".into(),
        database_id: "workspace".into(),
        hosted_origin: "https://native.test".into(),
    }
}
fn spawn_bound_shim(socket: &Path, scope: connection_binding::Scope) -> ShimClient {
    let (input, shim_input) = tokio::io::duplex(16384);
    let (shim_output, output) = tokio::io::duplex(16384);
    let socket = socket.to_owned();
    let task = tokio::spawn(async move {
        shim::connect_scoped_with_policy(
            &socket,
            shim_input,
            shim_output,
            shim_test_policy(Duration::from_secs(5)),
            Some(scope),
        )
        .await
    });
    ShimClient {
        input,
        lines: BufReader::new(output),
        task,
    }
}
impl PeerConn {
    async fn bind_scope(&mut self, actual: connection_binding::Scope) -> Value {
        let request = self.next().await;
        assert_eq!(
            request["method"], "native/connection/bind",
            "no MCP traffic before the scope guard"
        );
        let reply = connection_binding::dispatch(&request, Some(actual), &mut None)
            .reply
            .unwrap();
        self.writer
            .write_all(format!("{reply}\n").as_bytes())
            .await
            .unwrap();
        request
    }
    async fn assert_closed_without_mcp(&mut self) {
        let mut line = String::new();
        assert_eq!(timeout(Duration::from_secs(2),self.lines.read_line(&mut line)).await.unwrap().unwrap(),0,
            "wrong-scope node must receive no initialization, queued call or other MCP frame: {line}");
    }
}
#[tokio::test]
async fn shim_binding_blocks_wrong_account_workspace_origin_and_cached_relaunch() {
    for field in ["account_id", "database_id", "hosted_origin"] {
        let (_dir, path, listener) = bind_peer().await;
        let expected = expected_connection_scope();
        let mut different = json!(expected);
        different[field] = if field == "hosted_origin" {
            json!("https://other.test")
        } else {
            json!("another")
        };
        let different: connection_binding::Scope = serde_json::from_value(different).unwrap();
        // Two launches with the identical cached command/scope must both refuse.
        for _ in 0..2 {
            let mut client = spawn_bound_shim(&path, expected.clone());
            client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
            let (stream, _) = listener.accept().await.unwrap();
            let mut peer = PeerConn::new(stream);
            let request = peer.bind_scope(different.clone()).await;
            assert_eq!(request["params"], json!(expected));
            assert!(timeout(Duration::from_secs(2), client.task)
                .await
                .unwrap()
                .unwrap()
                .is_err());
            peer.assert_closed_without_mcp().await;
        }
    }
}
#[tokio::test]
async fn shim_binding_refuses_scope_change_before_reconnect_initialization_or_calls() {
    for field in ["account_id", "database_id"] {
        let (_dir, path, listener) = bind_peer().await;
        let expected = expected_connection_scope();
        let mut client = spawn_bound_shim(&path, expected.clone());
        let (stream, _) = listener.accept().await.unwrap();
        let mut first = PeerConn::new(stream);
        first.bind_scope(expected.clone()).await;
        client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
        first.initialize("2025-03-26", json!({"tools":{}})).await;
        client.next().await;
        drop(first);
        tokio::time::sleep(Duration::from_millis(150)).await;
        client.send(json!({"jsonrpc":"2.0","id":91,"method":"tools/call","params":{"name":"must_not_reach_new_scope","arguments":{}}})).await;
        let (stream, _) = listener.accept().await.unwrap();
        let mut replacement = PeerConn::new(stream);
        let mut different = json!(expected);
        different[field] = json!("another");
        replacement
            .bind_scope(serde_json::from_value(different).unwrap())
            .await;
        assert!(timeout(Duration::from_secs(2), client.task)
            .await
            .unwrap()
            .unwrap()
            .is_err());
        replacement.assert_closed_without_mcp().await;
    }
}
#[tokio::test]
async fn shim_binding_preserves_same_scope_restart_and_queued_read() {
    let (_dir, path, listener) = bind_peer().await;
    let expected = expected_connection_scope();
    let mut client = spawn_bound_shim(&path, expected.clone());
    let (stream, _) = listener.accept().await.unwrap();
    let mut first = PeerConn::new(stream);
    first.bind_scope(expected.clone()).await;
    client.send(serde_json::from_str(SHIM_INIT).unwrap()).await;
    first.initialize("2025-03-26", json!({"tools":{}})).await;
    client.next().await;
    drop(first);
    tokio::time::sleep(Duration::from_millis(150)).await;
    client
        .send(json!({"jsonrpc":"2.0","id":92,"method":"tools/list","params":{}}))
        .await;
    let (stream, _) = listener.accept().await.unwrap();
    let mut replacement = PeerConn::new(stream);
    replacement.bind_scope(expected).await;
    replacement
        .initialize("2025-03-26", json!({"tools":{}}))
        .await;
    assert_eq!(
        replacement.next().await["method"],
        "notifications/initialized"
    );
    assert_eq!(replacement.next().await["id"], 92);
    replacement
        .send(json!({"jsonrpc":"2.0","id":92,"result":{"tools":[]}}))
        .await;
    assert_eq!(client.next().await["id"], 92);
    client.input.shutdown().await.unwrap();
    drop(replacement); // The fake node finishes draining and closes its output.
    timeout(Duration::from_secs(2), client.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[test]
fn enrolled_install_lock_fences_duplicate_daemons() {
    let root = tempfile::tempdir().unwrap();
    let locks = root.path().join("locks");
    let first = super::open_install_lock(&locks, "install-one").unwrap();
    assert!(super::open_install_lock(&locks, "install-one").is_err());
    let _other = super::open_install_lock(&locks, "install-two").unwrap();
    drop(first);
    assert!(super::open_install_lock(&locks, "install-one").is_ok());
}

#[cfg(feature = "v2-kernel-probe")]
#[test]
fn original_settlement_enrolled_writer_rejects_a_changed_install_key() {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let temp = tempfile::tempdir().unwrap();
    let key_path = temp.path().join("node-install-key");
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&key_path)
        .unwrap()
        .write_all(hex::encode([7; 32]).as_bytes())
        .unwrap();
    let config: super::NodeConfig = serde_json::from_value(serde_json::json!({
        "hosted_base_url": "https://example.test",
        "home_id": "home",
        "db_id": "fixture",
        "credential_file": temp.path().join("unused-credential"),
        "socket_directory": temp.path().join("unused-socket"),
        "oauth_auth_file": temp.path().join("unused-auth"),
        "hosted_kernel_v2": true,
        "node_install_key_file": key_path,
        "node_install_id": "a".repeat(64),
    }))
    .unwrap();
    let error = super::Upstream::new(config, std::time::Duration::from_secs(1))
        .err()
        .unwrap();
    assert!(error.to_string().contains("configured install key changed"));
}
