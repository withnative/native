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
            markdown_folder: None,
            hosted_base_url: format!("http://{address}"),
            home_id: "test-home".into(),
            db_id: "test-workspace".into(),
            credential_file: token,
            socket_directory: temp.path().join("socket"),
            oauth_auth_file: None,
            standby_config: None,
            account_id: None,
            refresh_config: None,
            disk_floor_bytes: None,
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
        let (client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(serve_connection(server, upstream));
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

#[tokio::test]
async fn shim_exits_on_node_eof_while_stdin_is_open() {
    let fixture = Fixture::new().await;
    let (listener, _guard) = bind_socket(&fixture.config).await.unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(b"node reply\n").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let (_input, shim_input) = tokio::io::duplex(8192);
    let (shim_output, mut output) = tokio::io::duplex(8192);
    let socket = fixture.config.socket_path();
    let shim = tokio::spawn(async move {
        connect(&socket, shim_input, shim_output).await.unwrap();
    });
    let mut reply = String::new();
    timeout(Duration::from_secs(2), output.read_to_string(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, "node reply\n");
    timeout(Duration::from_secs(2), shim)
        .await
        .unwrap()
        .unwrap();
    server.await.unwrap();
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
        let reply = route_message(
            &upstream,
            None,
            route_gate,
            &message.to_string(),
            message.clone(),
            None,
            &direct,
            &Caller::new(None, Cancel::new()),
        )
        .await
        .unwrap();
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    }
    assert!(fixture.fake.requests.lock().await.is_empty());
    #[cfg(feature = "mcp-executor-prototype")]
    assert_eq!(gate.status(&Default::default())["entry_counts"], json!({}));
}
