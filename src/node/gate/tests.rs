//! Fault injection for the journal-then-forward gate. The fake hosted is a
//! raw HTTP server so a test can drop a connection after applying a write,
//! stall past an attempt's timeout, or answer 503: the three ways a reply is
//! lost in practice. It stores records by idempotency key like the engine,
//! so "exactly one record" is a count of distinct creations.
use super::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Clone)]
enum Fault {
    /// Close the connection before applying anything.
    DropBeforeApply,
    /// Apply, then close without replying.
    ApplyThenDrop,
    /// Apply, then sit on the reply past the attempt timeout.
    ApplyThenStall(Duration),
    /// Keep a server-side write alive after the node's attempt times out.
    ParkBeforeApply(
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
    ),
    /// Answer with this status and body without applying.
    Http(u16, &'static str),
    /// An owned MCP tool result, allowing full-size merge recovery receipts.
    ToolReply(Value),
    /// Send a status line and a body shorter than its content-length, then
    /// close: a reply lost mid-body.
    Truncated(u16),
    /// Apply, close, and take the node's credential away.
    ApplyDropThenRevokeCredentials,
    /// Do not apply; answer a plain result after this long.
    Hold(Duration),
    /// Handle this request normally (to let one of a scripted run through).
    None_,
    /// Hold this request open until a second `Rendezvous` request has arrived
    /// (at most 10 s), then handle both normally. Proves two calls were in
    /// flight at once without depending on timing.
    Rendezvous,
    /// Answer with this status and body after a delay, without applying.
    DelayedHttp(Duration, u16, &'static str),
    /// Refuse a keyed call the way hosted refuses a key on a live co-edit
    /// body route; apply an unkeyed one.
    RefuseKey,
}

#[derive(Default)]
struct HostedState {
    store: StdMutex<HashMap<String, Value>>,
    outcomes: StdMutex<HashMap<String, Value>>,
    status_reads: StdMutex<Vec<Value>>,
    created: AtomicUsize,
    unkeyed_applied: AtomicUsize,
    requests: StdMutex<Vec<Value>>,
    script: StdMutex<VecDeque<Fault>>,
    describe_fails: AtomicBool,
    rendezvous_arrived: AtomicUsize,
    rendezvous_notify: tokio::sync::Notify,
    /// Hosted creates the record under the `id` it is given, as the engine does.
    honour_ids: AtomicBool,
    access_fails: AtomicBool,
    describes: AtomicUsize,
    access_lookups: AtomicUsize,
    /// Milliseconds each contract or access lookup takes at hosted.
    lookup_delay_ms: AtomicUsize,
    token_path: StdMutex<Option<PathBuf>>,
    always: StdMutex<Option<Fault>>,
}

impl HostedState {
    fn script(&self, faults: impl IntoIterator<Item = Fault>) {
        self.script.lock().unwrap().extend(faults);
    }
    fn writes(&self) -> Vec<Value> {
        self.requests.lock().unwrap().clone()
    }
    fn keys_sent(&self) -> Vec<Option<String>> {
        self.writes()
            .iter()
            .map(|r| {
                r.pointer("/params/arguments/arguments/idempotency_key")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect()
    }
    fn apply(&self, request: &Value) -> Value {
        let operation = request
            .pointer("/params/arguments/operation")
            .and_then(Value::as_str)
            .unwrap_or("");
        let id = request["id"].clone();
        if operation == "set_intent" {
            let n = self.unkeyed_applied.fetch_add(1, Ordering::SeqCst) + 1;
            return json!({"jsonrpc":"2.0","id":id,"result":{"content":[],"structuredContent":{"intent":n},"isError":false}});
        }
        // Hosted's rule: the key is trimmed, and a blank key (or null) is no
        // key, so the call is never deduplicated.
        let key = request
            .pointer("/params/arguments/arguments/idempotency_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .unwrap_or("")
            .to_owned();
        let mut store = self.store.lock().unwrap();
        let found = if key.is_empty() {
            None
        } else {
            store.get(&key)
        };
        let (record, replay) = match found {
            Some(record) => (record.clone(), true),
            None => {
                let n = self.created.fetch_add(1, Ordering::SeqCst) + 1;
                let given = request
                    .pointer("/params/arguments/arguments/id")
                    .and_then(Value::as_str)
                    .filter(|_| self.honour_ids.load(Ordering::SeqCst));
                let record = if operation == "merge_body" {
                    let args = &request["params"]["arguments"]["arguments"];
                    json!({
                        "outcome":"merged", "applied":true,
                        "record_id":args["record_id"], "idempotency_key":key,
                        "base":{"version":args["base_version"],"verified":true},
                        "result":{"version":format!("rec:{n}"),"body":args["my_text"]},
                        "act":n, "changed":true
                    })
                } else {
                    json!({"record_id": given.map_or(format!("rec-{n}"), str::to_owned)})
                };
                if !key.is_empty() {
                    store.insert(key, record.clone());
                }
                (record, false)
            }
        };
        let mut structured = record;
        structured["idempotent_replay"] = json!(replay);
        json!({"jsonrpc":"2.0","id":id,"result":{"content":[],"structuredContent":structured,"isError":false}})
    }
}

fn schema_for(operation: &str) -> Value {
    match operation {
        "merge_body" => crate::mcp::tools::merge_body::input_schema(),
        "create_record" | "create_many" | "manage_links.add" | "attach_text" | "update_record" => {
            json!({"type":"object","properties":{"type":{"type":"string"},"idempotency_key":{"type":"string"}},"additionalProperties":false})
        }
        "update_either" => json!({"oneOf":[
            {"properties":{"id":{"type":"string"},"idempotency_key":{"type":"string"}}},
            {"properties":{"ids":{"type":"array"},"idempotency_key":{"type":"string"}}}]}),
        // No idempotency_key anywhere: a declarative write.
        _ => {
            json!({"type":"object","properties":{"intent":{"type":"string"}},"additionalProperties":false})
        }
    }
}

struct Hosted {
    state: Arc<HostedState>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Hosted {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> Option<Value> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let (head_end, length) = loop {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_lowercase();
            assert!(
                head.contains("native-client-identity:"),
                "node must send its build identity"
            );
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (end + 4, length);
        }
    };
    while buffer.len() < head_end + length {
        let n = socket.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
    serde_json::from_slice(&buffer[head_end..head_end + length]).ok()
}

async fn respond(socket: &mut tokio::net::TcpStream, status: u16, content_type: &str, body: &str) {
    let text = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = socket.write_all(text.as_bytes()).await;
    let _ = socket.shutdown().await;
}

async fn serve_hosted(state: Arc<HostedState>, mut socket: tokio::net::TcpStream) {
    let Some(request) = read_request(&mut socket).await else {
        return;
    };
    match request["method"].as_str().unwrap_or("") {
        "tools/call" => {}
        "initialize" => {
            let reply = json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"2025-03-26"}});
            return respond(&mut socket, 200, "application/json", &reply.to_string()).await;
        }
        _ => return respond(&mut socket, 202, "application/json", "").await,
    }
    let name = request
        .pointer("/params/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    if name == "describe_operation" {
        state.describes.fetch_add(1, Ordering::SeqCst);
        let delay = state.lookup_delay_ms.load(Ordering::SeqCst) as u64;
        tokio::time::sleep(Duration::from_millis(delay)).await;
        let operation = request
            .pointer("/params/arguments/operation")
            .and_then(Value::as_str)
            .unwrap_or("");
        if state.describe_fails.load(Ordering::SeqCst) {
            return respond(&mut socket, 503, "text/html", "down").await;
        }
        let reply = json!({"jsonrpc":"2.0","id":request["id"],"result":{"content":[],"structuredContent":{"input_schema":schema_for(operation)},"isError":false}});
        return respond(&mut socket, 200, "application/json", &reply.to_string()).await;
    }
    if name == "sql_read" {
        state.access_lookups.fetch_add(1, Ordering::SeqCst);
        let delay = state.lookup_delay_ms.load(Ordering::SeqCst) as u64;
        tokio::time::sleep(Duration::from_millis(delay)).await;
        if state.access_fails.load(Ordering::SeqCst) {
            return respond(&mut socket, 503, "text/html", "down").await;
        }
        let sql = request
            .pointer("/params/arguments/arguments/sql")
            .and_then(Value::as_str)
            .unwrap_or("");
        let access = match sql
            .split("operation = '")
            .nth(1)
            .and_then(|r| r.split('\'').next())
        {
            Some(
                "create_record" | "create_many" | "manage_links.add" | "attach_text"
                | "update_record" | "set_intent",
            ) => Some("mutation"),
            Some("get_record") => Some("read"),
            _ => None,
        };
        let operation = sql
            .split("operation = '")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .unwrap_or("");
        let contracts = crate::mcp::executor_prototype::NodeOperationContracts::local().unwrap();
        let rows: Vec<Value> = access.map(|a| json!({"access": a, "contract_digest":contracts.digest("records_write", operation)})).into_iter().collect();
        let reply = json!({"jsonrpc":"2.0","id":request["id"],"result":{"content":[],"structuredContent":{"rows":rows},"isError":false}});
        return respond(&mut socket, 200, "application/json", &reply.to_string()).await;
    }
    if name == "system_read"
        && request
            .pointer("/params/arguments/operation")
            .and_then(Value::as_str)
            == Some("outbox_status")
    {
        state.status_reads.lock().unwrap().push(request.clone());
        let handle = request
            .pointer("/params/arguments/arguments/journal_entry")
            .and_then(Value::as_str)
            .unwrap_or("");
        let result = state
            .outcomes
            .lock()
            .unwrap()
            .get(handle)
            .cloned()
            .unwrap_or_else(
                || json!({"isError":false,"structuredContent":{"entries":[]},"content":[]}),
            );
        let reply = json!({"jsonrpc":"2.0","id":request["id"],"result":result});
        return respond(&mut socket, 200, "application/json", &reply.to_string()).await;
    }
    state.requests.lock().unwrap().push(request.clone());
    let fault = state
        .script
        .lock()
        .unwrap()
        .pop_front()
        .or_else(|| state.always.lock().unwrap().clone());
    match fault {
        Some(Fault::ToolReply(result)) => {
            let reply = json!({"jsonrpc":"2.0","id":request["id"],"result":result});
            respond(&mut socket, 200, "application/json", &reply.to_string()).await;
        }
        Some(Fault::ParkBeforeApply(started, release, done)) => {
            started.notify_one();
            release.notified().await;
            state.apply(&request);
            done.notify_one();
        }
        Some(Fault::DropBeforeApply) => {}
        Some(Fault::ApplyThenDrop) => {
            state.apply(&request);
        }
        Some(Fault::Truncated(status)) => {
            let text = format!("HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: 500\r\nconnection: close\r\n\r\n{{\"par");
            let _ = socket.write_all(text.as_bytes()).await;
            let _ = socket.shutdown().await;
        }
        Some(Fault::ApplyDropThenRevokeCredentials) => {
            state.apply(&request);
            if let Some(path) = state.token_path.lock().unwrap().clone() {
                let _ = fs::remove_file(path);
            }
        }
        Some(Fault::RefuseKey) => {
            let keyed = request
                .pointer("/params/arguments/arguments/idempotency_key")
                .is_some();
            let reply = if keyed {
                let error = "update_record: idempotency_key is not supported while a live editing session is routing this record's body; retry without a key";
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"content":[{"type":"text","text":error}],"structuredContent":{"error":error,"run_context":{}},"isError":true}})
            } else {
                state.apply(&request)
            };
            respond(&mut socket, 200, "application/json", &reply.to_string()).await;
        }
        Some(Fault::Rendezvous) => {
            state.rendezvous_arrived.fetch_add(1, Ordering::SeqCst);
            state.rendezvous_notify.notify_waiters();
            let met = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let notified = state.rendezvous_notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if state.rendezvous_arrived.load(Ordering::SeqCst) >= 2 {
                        return;
                    }
                    notified.await;
                }
            })
            .await
            .is_ok();
            if met {
                let reply = state.apply(&request);
                respond(&mut socket, 200, "application/json", &reply.to_string()).await;
            } else {
                respond(
                    &mut socket,
                    500,
                    "application/json",
                    r#"{"error":"no second request arrived"}"#,
                )
                .await;
            }
        }
        Some(Fault::DelayedHttp(delay, status, body)) => {
            tokio::time::sleep(delay).await;
            respond(&mut socket, status, "application/json", body).await;
        }
        Some(Fault::None_) | None => {
            let reply = state.apply(&request);
            respond(&mut socket, 200, "application/json", &reply.to_string()).await;
        }
        Some(Fault::Hold(delay)) => {
            tokio::time::sleep(delay).await;
            let reply = json!({"jsonrpc":"2.0","id":request["id"],"result":{"content":[],"structuredContent":{"held":true},"isError":false}});
            respond(&mut socket, 200, "application/json", &reply.to_string()).await;
        }
        Some(Fault::ApplyThenStall(delay)) => {
            state.apply(&request);
            tokio::time::sleep(delay).await;
            respond(&mut socket, 200, "application/json", "{}").await;
        }
        Some(Fault::Http(status, body)) => {
            let content_type = if body.starts_with('{') {
                "application/json"
            } else {
                "text/html"
            };
            respond(&mut socket, status, content_type, body).await;
        }
    }
}

fn fast() -> GateConfig {
    GateConfig {
        budget: Duration::from_secs(4),
        merge_short_budget: Duration::from_millis(200),
        attempt_timeout: Duration::from_millis(300),
        min_attempt: Duration::from_millis(50),
        backoff_start: Duration::from_millis(20),
        backoff_max: Duration::from_millis(100),
        contract_timeout: Duration::from_secs(1),
        contract_ttl: Duration::from_secs(60),
        retention: CONFIRMED_RETENTION,
        housekeeping_every: Duration::from_secs(3600),
        queue_gap: Duration::from_millis(40),
        queue_retry: Duration::from_millis(100),
        refusal_retention: Duration::from_secs(3600),
        disk_floor_bytes: 0,
        record_url_base: Some("https://hosted.example".into()),
        account_binding: None,
    }
}

#[path = "body_merge_acceptance.rs"]
mod body_merge_acceptance;
#[cfg(feature = "v2-kernel-probe")]
#[path = "body_merge_real_home_tests.rs"]
mod body_merge_real_home_tests;

fn seed_hosted_contracts(gate: &WriteGate) {
    let contracts = crate::mcp::executor_prototype::NodeOperationContracts::local().unwrap();
    for (executor, operation) in hold::HOLDABLE {
        gate.hosted_contracts.lock().unwrap().insert(
            (executor.into(), operation.into()),
            Cached {
                checked: Instant::now(),
                ttl: gate.config.contract_ttl,
                value: contracts.digest(executor, operation).unwrap().to_owned(),
            },
        );
    }
}

struct Rig {
    _temp: tempfile::TempDir,
    config: NodeConfig,
    hosted: Hosted,
    gate: Arc<WriteGate>,
    upstream: Arc<Upstream>,
}

impl Rig {
    async fn new(gate_config: GateConfig) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let token = temp.path().join("token");
        fs::write(&token, "first-token\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let socket_directory = temp.path().join("socket");
        fs::create_dir(&socket_directory).unwrap();
        fs::set_permissions(&socket_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(HostedState::default());
        let task = tokio::spawn({
            let state = state.clone();
            async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        return;
                    };
                    tokio::spawn(serve_hosted(state.clone(), socket));
                }
            }
        });
        let config = NodeConfig {
            working_note_appends: false,
            working_refusal_drafts: false,
            markdown_folder: None,
            hosted_base_url: format!("http://{address}"),
            home_id: "test-home".into(),
            db_id: "test-workspace".into(),
            credential_file: token,
            socket_directory,
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
        *state.token_path.lock().unwrap() = Some(config.credential_file.clone());
        let gate = Arc::new(WriteGate::open(&config.socket_directory, gate_config).unwrap());
        seed_hosted_contracts(&gate);
        let upstream = Arc::new(Upstream::new(config.clone(), Duration::from_secs(30)).unwrap());
        Self {
            _temp: temp,
            config,
            hosted: Hosted { state, task },
            gate,
            upstream,
        }
    }
    fn state(&self) -> &HostedState {
        &self.hosted.state
    }
    fn connect(&self) -> Client {
        self.connect_with(Arc::new(Admission::new()))
    }
    fn connect_with(&self, admission: Arc<Admission>) -> Client {
        let (client, server) = UnixStream::pair().unwrap();
        let upstream = self.upstream.clone();
        let gate = self.gate.clone();
        let task = tokio::spawn(serve_routed_connection(
            server,
            upstream,
            None,
            Some(gate),
            None,
            admission,
        ));
        let (read, write) = client.into_split();
        Client {
            reader: BufReader::new(read),
            writer: write,
            task,
        }
    }
    /// A fresh gate over the same journal directory: a node restart.
    fn restart(&mut self, gate_config: GateConfig) {
        self.gate = Arc::new(WriteGate::open(&self.config.socket_directory, gate_config).unwrap());
        seed_hosted_contracts(&self.gate);
    }
}

struct Client {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl Client {
    async fn send(&mut self, message: Value) {
        self.writer
            .write_all(format!("{message}\n").as_bytes())
            .await
            .unwrap();
    }
    async fn recv(&mut self) -> Option<Value> {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(10), self.reader.read_line(&mut line))
            .await
            .expect("reply within 10s")
            .unwrap();
        (n > 0).then(|| serde_json::from_str(&line).unwrap())
    }
    async fn call(&mut self, id: u64, arguments: Value) -> Value {
        self.send(tool_call(id, "call_executor", arguments)).await;
        self.recv().await.expect("a reply")
    }
}

fn tool_call(id: u64, name: &str, arguments: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}})
}

fn create(key: Option<&str>, body: &str) -> Value {
    let mut arguments = json!({"type":"Document","kind":"note","reason":"test write","body":body});
    if let Some(key) = key {
        arguments["idempotency_key"] = json!(key);
    }
    json!({"executor":"records_write","operation":"create_record","run_key":"run-xyz","arguments":arguments})
}

fn receipt(reply: &Value) -> &Value {
    &reply["result"]["structuredContent"]
}

async fn eventually(mut condition: impl FnMut() -> bool) {
    for _ in 0..200 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not reached");
}

fn entries(rig: &Rig) -> Vec<Value> {
    let mut found = Vec::new();
    for item in fs::read_dir(rig.config.socket_directory.join("journal")).unwrap() {
        let path = item.unwrap().path();
        found.push(serde_json::from_slice(&fs::read(path).unwrap()).unwrap());
    }
    found
}

#[test]
fn contract_decides_keyedness() {
    assert!(schema_accepts_key(&schema_for("create_record")));
    assert!(schema_accepts_key(&schema_for("update_either")));
    assert!(!schema_accepts_key(&schema_for("set_intent")));
    // Only some branches accept it: injecting would be refused by the others.
    assert!(!schema_accepts_key(&json!({"oneOf":[
        {"properties":{"idempotency_key":{"type":"string"}}},
        {"properties":{"other":{"type":"string"}}}]})));
    // The shape records_write.update_record really has (describe_operation,
    // 14 Oct 2026): oneOf branches, each an allOf whose first member declares
    // the key, with unrelated constraints beside it.
    assert!(schema_accepts_key(&json!({
        "required":["reason"],
        "oneOf":[
            {"allOf":[
                {"properties":{"id":{},"idempotency_key":{"type":"string"}},"additionalProperties":false},
                {"oneOf":[{"required":["id"]},{"required":["record_id"]}],"properties":{}},
                {"not":{"required":["body","body_set"]}}]},
            {"allOf":[
                {"properties":{"ids":{},"idempotency_key":{"type":"string"}}},
                {"anyOf":[{"required":["facets"]},{"required":["maturity"]}]}]}]
    })));
    // Shared via allOf, and nested keys are not the operation's own key.
    assert!(schema_accepts_key(
        &json!({"allOf":[{"properties":{"idempotency_key":{}}}]})
    ));
    assert!(!schema_accepts_key(
        &json!({"properties":{"items":{"properties":{"idempotency_key":{}}}}})
    ));
}

#[tokio::test]
async fn caller_supplied_key_is_used_unchanged() {
    let rig = Rig::new(fast()).await;
    let mut client = rig.connect();
    let reply = client.call(1, create(Some("caller-key-1"), "hello")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(rig.state().keys_sent(), vec![Some("caller-key-1".into())]);
    // Node-added fields: none. The forwarded call is the caller's call.
    let forwarded = &rig.state().writes()[0];
    assert_eq!(forwarded["params"]["arguments"]["run_key"], "run-xyz");
    assert_eq!(
        forwarded["params"]["arguments"]["arguments"]["body"],
        "hello"
    );
    let saved = entries(&rig);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0]["state"], "confirmed");
    assert_eq!(saved[0]["key_origin"], "caller");
    assert_eq!(saved[0]["idempotency_key"], "caller-key-1");
    assert!(saved[0]["arguments"].is_null());
}

#[tokio::test]
async fn missing_key_and_record_id_are_minted_once_and_nothing_else_is_touched() {
    let rig = Rig::new(fast()).await;
    let mut client = rig.connect();
    client
        .send(json!({"jsonrpc":"2.0","id":0,"method":"initialize","params":{"clientInfo":{"name":"claude-code","version":"9"}}}))
        .await;
    let _ = client.recv().await;
    let sent = create(None, "hello");
    let reply = client.call(1, sent.clone()).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    let forwarded = rig.state().writes()[0]
        .pointer("/params/arguments")
        .cloned()
        .unwrap();
    let key = forwarded["arguments"]["idempotency_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(key.starts_with("node-"));
    // The key, and for a create the record's ID (chosen before the first send
    // so that a held write can be sent again unchanged).
    let record_id = forwarded["arguments"]["id"].as_str().unwrap().to_owned();
    let mut expected = sent;
    expected["arguments"]["idempotency_key"] = json!(key);
    expected["arguments"]["id"] = json!(record_id);
    assert_eq!(forwarded, expected, "only the key and the id were added");
    let saved = entries(&rig);
    assert_eq!(saved[0]["key_origin"], "node");
    assert_eq!(saved[0]["record_id"], json!(record_id));
    assert_eq!(saved[0]["run_key"], "run-xyz");
    assert_eq!(saved[0]["client_info"]["name"], "claude-code");
    assert!(saved[0]["received_at"].is_string());
}

/// 960f47f: a routerless (hosted-only) node cannot observe the hosted engine.
/// Against kernel-v2 hosted it must not derive a create `id`, which v2 refuses
/// ("id is only supported for messaging sends"). `serve` obtains its gate only
/// from `open_gate`, which applies the operator's declaration before returning
/// it, so no request can reach an undeclared gate. Status reports the basis
/// (`declared`, never `observed`), and a router observation replaces it.
/// Without the declaration, v1 semantics are unchanged (see the test above).
#[tokio::test]
async fn routerless_kernel_v2_declaration_creates_without_a_derived_id() {
    let mut rig = Rig::new(fast()).await;
    let mut config = rig.config.clone();
    config.hosted_kernel_v2 = true;
    // The gate exactly as `serve` opens it.
    rig.gate = crate::node::open_gate(&config).unwrap();
    seed_hosted_contracts(&rig.gate);
    assert!(rig.gate.kernel_v2_upstream(), "declared before first use");
    let holding = rig.gate.status(&Default::default())["holding"].clone();
    assert_eq!(holding["basis"], "declared", "{holding}");
    assert_eq!(holding["supported"], false);
    assert_eq!(holding["reason"], "kernel_v2_upstream_drain_first");

    let mut client = rig.connect();
    let sent = create(None, "hello");
    let reply = client.call(1, sent.clone()).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1", "{reply}");
    let forwarded = rig.state().writes()[0]
        .pointer("/params/arguments")
        .cloned()
        .unwrap();
    assert!(forwarded["arguments"].get("id").is_none(), "{forwarded}");
    let key = forwarded["arguments"]["idempotency_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(key.starts_with("node-"));
    let mut expected = sent;
    expected["arguments"]["idempotency_key"] = json!(key);
    assert_eq!(forwarded, expected, "only the key was added");
    drop(client);

    // A router observation replaces the declaration and is reported as such.
    rig.gate.set_kernel_v2_upstream(true);
    assert_eq!(
        rig.gate.status(&Default::default())["holding"]["basis"],
        "observed"
    );
    rig.gate.set_kernel_v2_upstream(false);
    assert_eq!(
        rig.gate.status(&Default::default())["holding"]["basis"],
        "not_observed"
    );

    // Absent declaration: the gate `serve` opens keeps v1 semantics.
    let mut undeclared = rig.config.clone();
    undeclared.hosted_kernel_v2 = false;
    rig.gate = crate::node::open_gate(&undeclared).unwrap();
    assert!(
        !rig.gate.kernel_v2_upstream(),
        "absent declaration keeps v1"
    );
    assert_eq!(
        rig.gate.status(&Default::default())["holding"]["basis"],
        "not_observed"
    );
}

#[tokio::test]
async fn timeout_then_in_call_retry_creates_exactly_one_record() {
    let rig = Rig::new(fast()).await;
    rig.state()
        .script([Fault::ApplyThenStall(Duration::from_secs(2))]);
    let mut client = rig.connect();
    let reply = client.call(1, create(None, "once")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    let keys = rig.state().keys_sent();
    assert_eq!(keys.len(), 2, "one timed-out attempt and one retry");
    assert_eq!(keys[0], keys[1], "the retry reuses the first attempt's key");
    // Hosted answered the retry from its first application.
    assert_eq!(receipt(&reply)["idempotent_replay"], true);
    assert_eq!(entries(&rig)[0]["state"], "confirmed");
    assert_eq!(entries(&rig)[0]["attempts"], 2);
}

#[tokio::test]
async fn dropped_connection_then_in_call_retry_creates_exactly_one_record() {
    for fault in [Fault::ApplyThenDrop, Fault::DropBeforeApply] {
        let rig = Rig::new(fast()).await;
        rig.state().script([fault]);
        let mut client = rig.connect();
        let reply = client.call(1, create(Some("k-drop"), "once")).await;
        assert_eq!(receipt(&reply)["record_id"], "rec-1");
        assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
        assert_eq!(rig.state().writes().len(), 2);
    }
}

#[tokio::test]
async fn gateway_errors_are_retried_and_other_answers_are_not() {
    let rig = Rig::new(fast()).await;
    rig.state().script([
        Fault::Http(502, "<html>bad gateway</html>"),
        Fault::Http(503, "<html>unavailable</html>"),
        Fault::Http(504, "<html>timeout</html>"),
    ]);
    let mut client = rig.connect();
    let reply = client.call(1, create(Some("k-gw"), "once")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(rig.state().writes().len(), 4);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);

    // Everything below is hosted's answer, passed through after one attempt.
    let cases: Vec<(&'static str, u16)> = vec![
        (
            r#"{"error":"unauthorized","code":"auth_expired","outcome":"refused"}"#,
            401,
        ),
        (r#"{"error":"bad input","code":"invalid_params"}"#, 400),
        (
            r#"{"error":{"code":"DEPLOYMENT_DRAINING","applied":false},"applied":false}"#,
            503,
        ),
        (
            r#"{"error":{"code":"partial_replay","outcome":"unknown","applied":2,"partial":true}}"#,
            503,
        ),
    ];
    for (n, (body, status)) in cases.into_iter().enumerate() {
        let before = rig.state().writes().len();
        rig.state().script([Fault::Http(status, body)]);
        let reply = client
            .call(10 + n as u64, create(Some(&format!("k-pass-{n}")), "x"))
            .await;
        assert_eq!(
            rig.state().writes().len(),
            before + 1,
            "{status} {body} was retried"
        );
        assert_eq!(reply["error"]["data"]["http_status"], status);
        assert_eq!(
            reply["error"]["data"]["upstream_body"],
            serde_json::from_str::<Value>(body).unwrap()
        );
    }
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn engine_refusals_preserve_hosted_fields_and_annotate_uncertainty() {
    // Hosted reports "replay bound exceeded" as an isError tool result, not an
    // HTTP error. (DEPLOYMENT_READ_ONLY arrives the same way and is held
    // instead: see the hold tests.)
    let rig = Rig::new(fast()).await;
    let read_only = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"this Native deployment is temporarily draining"}],"structuredContent":{"error_code":"DEPLOYMENT_DRAINING","applied":false,"retryable":true},"isError":true}}"#;
    let bound = r#"{"jsonrpc":"2.0","id":2,"result":{"content":[],"structuredContent":{"error_code":"replay_bound_exceeded","applied":"partial","completed_items":2,"total_items":5,"retryable":true},"isError":true}}"#;
    let mut client = rig.connect();
    for (id, raw) in [(1u64, read_only), (2, bound)] {
        let before = rig.state().writes().len();
        rig.state().script([Fault::Http(200, raw)]);
        client
            .send(tool_call(
                id,
                "call_executor",
                create(Some(&format!("k{id}")), "x"),
            ))
            .await;
        let mut line = String::new();
        client.reader.read_line(&mut line).await.unwrap();
        if id == 1 {
            assert_eq!(line.trim_end(), raw);
        } else {
            let mut annotated: Value = serde_json::from_str(&line).unwrap();
            let note = annotated["result"]["structuredContent"]
                .as_object_mut()
                .unwrap()
                .remove("node_journal")
                .unwrap();
            assert_eq!(note["outcome"], "uncertain");
            assert_eq!(note["idempotency_key"], "k2");
            annotated["result"]["content"].as_array_mut().unwrap().pop();
            assert_eq!(annotated, serde_json::from_str::<Value>(raw).unwrap());
        }
        assert_eq!(rig.state().writes().len(), before + 1);
    }
    let saved = entries(&rig);
    let state_of =
        |key: &str| saved.iter().find(|e| e["idempotency_key"] == key).unwrap()["state"].clone();
    assert_eq!(state_of("k1"), "confirmed");
    // A partly committed receipt stays an open question in the journal.
    assert_eq!(state_of("k2"), "uncertain");
}

#[tokio::test]
async fn exhausted_budget_returns_uncertain_with_the_key_and_the_agent_retry_gets_the_original() {
    let mut config = fast();
    config.budget = Duration::from_millis(900);
    let rig = Rig::new(config).await;
    rig.state().script([Fault::ApplyThenDrop]);
    *rig.state().always.lock().unwrap() = Some(Fault::Http(503, "<html>down</html>"));
    let mut client = rig.connect();
    let sent = create(None, "survive");
    let reply = client.call(1, sent.clone()).await;
    let data = &reply["error"]["data"];
    assert_eq!(data["outcome"], "uncertain");
    let key = data["idempotency_key"].as_str().unwrap().to_owned();
    assert!(reply["error"]["message"].as_str().unwrap().contains(&key));
    assert!(
        data["retry"].as_str().unwrap().contains("same call")
            || data["retry"].as_str().unwrap().contains("exact call")
    );
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    let open = rig.gate.status(&Default::default());
    assert_eq!(open["uncertain"].as_array().unwrap().len(), 1);
    assert_eq!(open["uncertain"][0]["idempotency_key"], key);

    // Hosted recovers; the agent retries the same call with the returned key.
    *rig.state().always.lock().unwrap() = None;
    let mut retry = sent;
    retry["arguments"]["idempotency_key"] = json!(key);
    let reply = client.call(2, retry).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(receipt(&reply)["idempotent_replay"], true);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    // Following the advice settles the earlier open entry.
    assert_eq!(
        rig.gate.status(&Default::default())["uncertain"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn unkeyed_writes_are_journaled_with_or_without_a_router_and_sent_once() {
    let rig = Rig::new(fast()).await;
    let arguments = json!({"executor":"coordination_write","operation":"set_intent","arguments":{"intent":"x"}});

    // No router: the gate learns from hosted's catalogue that this is a
    // write, saves it, sends it once, and leaves it honestly uncertain.
    rig.state().script([Fault::Http(503, "<html>down</html>")]);
    let mut client = rig.connect();
    let reply = client.call(1, arguments.clone()).await;
    assert_eq!(
        rig.state().writes().len(),
        1,
        "no retry without a keyed contract"
    );
    assert!(rig.state().writes()[0]["params"]["arguments"]["arguments"]
        .get("idempotency_key")
        .is_none());
    assert_eq!(reply["error"]["data"]["outcome"], "unknown");
    assert!(reply["error"]["data"].get("idempotency_key").is_none());
    let saved = entries(&rig);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0]["state"], "uncertain");
    assert!(saved[0]["idempotency_key"].is_null());
    assert_eq!(saved[0]["attempts"], 1);

    // A router that already knows it is a write skips the catalogue lookup
    // and behaves the same.
    rig.state().script([Fault::Http(503, "<html>down</html>")]);
    let message = tool_call(2, "call_executor", arguments);
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    let report = rig
        .gate
        .forward(
            &rig.upstream,
            &WriteRequest {
                body: &body,
                message: &message,
                revision: None,
                caller: &caller,
                outage: None,
                no_hold: false,
            },
            true,
        )
        .await;
    assert_eq!(rig.state().writes().len(), 2);
    let reply: Value = serde_json::from_str(&report.reply.unwrap()).unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "unknown");
    assert_eq!(entries(&rig).len(), 2);
}

#[tokio::test]
async fn reads_are_not_journaled_and_unknown_classification_is_journaled_without_a_key() {
    let rig = Rig::new(fast()).await;
    let mut client = rig.connect();
    let read =
        json!({"executor":"records_read","operation":"get_record","arguments":{"ids":["x"]}});
    let _ = client.call(1, read.clone()).await;
    assert_eq!(rig.state().writes().len(), 1);
    assert!(entries(&rig).is_empty(), "a read leaves no journal entry");

    // Hosted cannot say what the operation is, or what its contract is: the
    // call is saved anyway, but no key is invented and nothing is retried.
    rig.state().access_fails.store(true, Ordering::SeqCst);
    rig.state().describe_fails.store(true, Ordering::SeqCst);
    rig.state().script([Fault::DropBeforeApply]);
    let reply = client.call(2, create(None, "x")).await;
    assert_eq!(
        rig.state().writes().len(),
        2,
        "one more attempt, not a retry"
    );
    assert!(rig.state().keys_sent()[1].is_none());
    assert!(reply.get("error").is_some());
    let saved = entries(&rig);
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0]["state"], "uncertain");
    assert!(saved[0]["idempotency_key"].is_null());
}

#[tokio::test]
async fn unreadable_contract_means_single_attempt_unless_the_node_may_hold_the_operation() {
    // Not on the node's list: no contract, no key, one attempt, as in slice A.
    let rig = Rig::new(fast()).await;
    rig.state().describe_fails.store(true, Ordering::SeqCst);
    rig.state().script([Fault::DropBeforeApply]);
    let mut client = rig.connect();
    let reply = client
        .call(
            1,
            json!({"executor":"coordination_write","operation":"set_intent","arguments":{"intent":"x"}}),
        )
        .await;
    assert_eq!(rig.state().writes().len(), 1);
    assert!(
        rig.state().keys_sent()[0].is_none(),
        "no key invented without a contract"
    );
    assert!(reply.get("error").is_some());

    // On the list: the contract is known to take a key, so an outage that
    // also stops the lookup does not stop the write being keyed and retried.
    let rig = Rig::new(fast()).await;
    rig.state().describe_fails.store(true, Ordering::SeqCst);
    rig.state().script([Fault::DropBeforeApply]);
    let mut client = rig.connect();
    let reply = client.call(1, create(None, "x")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    let keys = rig.state().keys_sent();
    assert_eq!(keys.len(), 2);
    assert!(keys[0].as_deref().unwrap().starts_with("node-"));
    assert_eq!(keys[0], keys[1]);
}

#[tokio::test]
async fn restart_between_save_and_send_leaves_an_honest_uncertain_entry_and_no_duplicate() {
    let mut rig = Rig::new(fast()).await;
    // The node saved the write and died before the first byte went out.
    let id = rig
        .gate
        .journal
        .begin(super::NewEntry {
            executor: "records_write".into(),
            operation: "create_record".into(),
            tool: "call_executor".into(),
            run_key: Some("run-xyz".into()),
            client_info: None,
            app_identity: None,
            idempotency_key: Some("k-saved".into()),
            key_origin: Some(KeyOrigin::Caller),
            arguments: json!({"type":"Document","idempotency_key":"k-saved"}),
            parent_key: None,
            title: None,
            record_id: None,
            record_ids: Vec::new(),
            envelope: None,
            intent_digest: None,
        })
        .unwrap()
        .id;
    rig.restart(fast());
    let entry = rig.gate.journal.get(&id).unwrap();
    assert_eq!(entry.state, EntryState::Uncertain);
    assert_eq!(
        entry.attempts, 0,
        "the journal shows it was never attempted"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        rig.state().writes().is_empty(),
        "the node never replays by itself"
    );
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
    // The agent, told the key, sends it; it is applied exactly once.
    let mut client = rig.connect();
    let reply = client.call(1, create(Some("k-saved"), "x")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn restart_between_send_and_reply_leaves_an_honest_uncertain_entry_and_no_duplicate() {
    let mut rig = Rig::new(fast()).await;
    rig.state()
        .script([Fault::ApplyThenStall(Duration::from_secs(30))]);
    let client = rig.connect();
    // Run the write on its own connection and kill the node's task mid-flight,
    // as a shutdown or crash would.
    let mut client = client;
    client
        .send(tool_call(
            1,
            "call_executor",
            create(Some("k-inflight"), "x"),
        ))
        .await;
    eventually(|| rig.state().created.load(Ordering::SeqCst) == 1).await;
    client.task.abort();
    let _ = (&mut client.task).await;
    rig.restart(fast());
    let saved = entries(&rig);
    assert_eq!(saved[0]["state"], "uncertain");
    assert_eq!(saved[0]["attempts"], 1);
    assert!(saved[0]["detail"].as_str().unwrap().contains("in flight"));
    assert_eq!(
        rig.gate.status(&Default::default())["uncertain"][0]["idempotency_key"],
        "k-inflight"
    );
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(
        rig.state().writes().len(),
        1,
        "nothing was sent after the restart"
    );
    // The agent retries with the key it holds: the original receipt comes back.
    let mut client = rig.connect();
    let reply = client.call(2, create(Some("k-inflight"), "x")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(receipt(&reply)["idempotent_replay"], true);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert_eq!(
        rig.gate.status(&Default::default())["uncertain"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn cancellation_stops_retries_and_suppresses_the_reply() {
    let rig = Rig::new(fast()).await;
    *rig.state().always.lock().unwrap() = Some(Fault::Http(503, "<html>down</html>"));
    let mut client = rig.connect();
    client
        .send(tool_call(7, "call_executor", create(Some("k-cancel"), "x")))
        .await;
    eventually(|| !rig.state().writes().is_empty()).await;
    client
        .send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}))
        .await;
    tokio::time::sleep(Duration::from_millis(600)).await;
    let attempts = rig.state().writes().len();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(rig.state().writes().len(), attempts, "retries stopped");
    assert!(attempts < 12, "stopped well inside the budget, not at it");
    // The cancel notification itself is forwarded as before (a 503 here, no id, no reply).
    client.writer.shutdown().await.unwrap();
    assert!(
        client.recv().await.is_none(),
        "a cancelled request gets no reply"
    );
    assert_eq!(
        entries(&rig)
            .iter()
            .filter(|e| e["state"] == "uncertain")
            .count(),
        1
    );
}

#[tokio::test]
async fn disconnect_stops_retries_but_a_half_close_does_not() {
    let rig = Rig::new(fast()).await;
    // Half-close first: the shim closes its write side at stdin EOF and still
    // waits for the reply, so retries must carry on and the reply arrive.
    rig.state().script([
        Fault::Http(503, "<html>x</html>"),
        Fault::Http(503, "<html>x</html>"),
    ]);
    let mut client = rig.connect();
    client
        .send(tool_call(1, "call_executor", create(Some("k-half"), "x")))
        .await;
    client.writer.shutdown().await.unwrap();
    let reply = client.recv().await.unwrap();
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(rig.state().writes().len(), 3);

    // A real disconnect: the caller is gone, so nobody can use a retry.
    *rig.state().always.lock().unwrap() = Some(Fault::Http(503, "<html>down</html>"));
    let before = rig.state().writes().len();
    let mut client = rig.connect();
    client
        .send(tool_call(2, "call_executor", create(Some("k-gone"), "x")))
        .await;
    eventually(|| rig.state().writes().len() > before).await;
    drop(client);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let attempts = rig.state().writes().len();
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        rig.state().writes().len(),
        attempts,
        "retries stopped after the disconnect"
    );
    eventually(|| {
        entries(&rig)
            .iter()
            .any(|e| e["idempotency_key"] == "k-gone" && e["state"] == "uncertain")
    })
    .await;
}

#[tokio::test]
async fn node_status_lists_uncertain_entries_without_bodies() {
    let mut config = fast();
    config.budget = Duration::from_millis(400);
    let rig = Rig::new(config).await;
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let mut client = rig.connect();
    let reply = client.call(1, create(Some("k-open"), "SECRET-BODY")).await;
    assert_eq!(reply["error"]["data"]["outcome"], "uncertain");
    client.send(tool_call(2, "node_status", json!({}))).await;
    let status = client.recv().await.unwrap();
    let structured = &status["result"]["structuredContent"];
    assert_eq!(structured["uncertain"][0]["idempotency_key"], "k-open");
    assert_eq!(structured["uncertain"][0]["operation"], "create_record");
    assert!(!status.to_string().contains("SECRET-BODY"));
    // The entry on disk does keep the call, for the person inspecting it.
    assert_eq!(entries(&rig)[0]["arguments"]["body"], "SECRET-BODY");
}

#[tokio::test]
async fn journal_store_is_owner_only_while_serving() {
    let rig = Rig::new(fast()).await;
    let mut client = rig.connect();
    client.call(1, create(Some("k-perm"), "x")).await;
    let directory = rig.config.socket_directory.join("journal");
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    for item in fs::read_dir(&directory).unwrap() {
        assert_eq!(
            item.unwrap().metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn a_blank_caller_key_is_left_alone_and_the_write_is_sent_once() {
    // Hosted treats null keys and strings blank after `str::trim` as absent,
    // so retrying such a write would create a second record. ASCII and Unicode
    // whitespace both count.
    let blanks: Vec<Value> = vec![
        json!(""),
        json!(" "),
        json!("\t\n\r"),
        json!("\u{00a0}"),
        json!("\u{2003}\u{2009}"),
        json!("\u{3000}"),
        json!(null),
    ];
    for blank in blanks {
        let rig = Rig::new(fast()).await;
        rig.state().script([Fault::ApplyThenDrop]);
        let mut call = create(None, "once");
        call["arguments"]["idempotency_key"] = blank.clone();
        let mut client = rig.connect();
        let reply = client.call(1, call).await;
        assert_eq!(rig.state().writes().len(), 1, "{blank} was retried");
        assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
        assert_eq!(
            rig.state().writes()[0]["params"]["arguments"]["arguments"]["idempotency_key"],
            blank,
            "the caller's value is forwarded exactly as sent"
        );
        assert!(reply.get("error").is_some(), "the caller sees the failure");
        assert!(entries(&rig)[0]["idempotency_key"].is_null());
    }
    // A key with content around its whitespace is a real key and is kept as is.
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::ApplyThenDrop]);
    let mut client = rig.connect();
    let reply = client.call(1, create(Some("  padded  "), "once")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert_eq!(rig.state().keys_sent(), vec![Some("  padded  ".into()); 2]);
}

/// Pretend the contract lookup already found `create_record` keyed, so a test
/// can exercise the send itself without the lookups consuming its budget.
fn seed_keyed(gate: &WriteGate) {
    gate.keyed.lock().unwrap().insert(
        ("records_write".into(), "create_record".into()),
        Cached {
            checked: Instant::now(),
            ttl: Duration::from_secs(60),
            value: Keyed::Yes,
        },
    );
}

const READ_ONLY: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"this Native deployment is temporarily read-only"}],"structuredContent":{"error_code":"DEPLOYMENT_READ_ONLY","applied":false,"retryable":true},"isError":true}}"#;

#[tokio::test]
async fn a_later_refusal_does_not_erase_an_earlier_possible_application() {
    // Attempt 1 is applied and its reply lost; attempt 2 is refused. Each
    // kind of "later" answer (read-only is held instead: see hold tests) must leave the entry uncertain with its key
    // visible, and hosted's own refusal must still reach the caller.
    let later: Vec<(&str, Fault)> = vec![
        (
            "auth",
            Fault::Http(
                401,
                r#"{"error":"unauthorized","code":"auth_expired","outcome":"refused"}"#,
            ),
        ),
        (
            "validation",
            Fault::Http(
                400,
                r#"{"error":"bad input","error_code":"invalid_params"}"#,
            ),
        ),
    ];
    for (name, fault) in later {
        let rig = Rig::new(fast()).await;
        rig.state().script([Fault::ApplyThenDrop, fault]);
        let mut client = rig.connect();
        let reply = client.call(1, create(None, "survive")).await;
        assert_eq!(rig.state().created.load(Ordering::SeqCst), 1, "{name}");
        assert_eq!(
            rig.state().writes().len(),
            2,
            "{name}: refusals are not retried"
        );
        let key = rig.state().keys_sent()[0].clone().unwrap();
        // The refusal is hosted's, and the node's note sits beside it.
        let note = reply
            .pointer("/result/structuredContent/node_journal")
            .or_else(|| reply.pointer("/error/data/node_journal"))
            .unwrap_or_else(|| panic!("{name}: no node_journal note in {reply}"));
        assert_eq!(note["idempotency_key"], key, "{name}");
        assert_eq!(note["outcome"], "uncertain", "{name}");
        assert!(
            reply["error"]["data"]["upstream_body"].is_object(),
            "{name}"
        );
        let saved = entries(&rig);
        assert_eq!(saved[0]["state"], "uncertain", "{name}");
        assert_eq!(
            saved[0]["arguments"]["body"], "survive",
            "{name}: arguments kept"
        );
        assert_eq!(
            rig.gate.status(&Default::default())["uncertain"][0]["idempotency_key"],
            key,
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_stopped_attempt_after_a_possible_application_is_uncertain_not_not_sent() {
    let rig = Rig::new(fast()).await;
    // Attempt 1 applies and drops; the credential then disappears, so attempt
    // 2 cannot even be sent.
    rig.state().script([Fault::ApplyDropThenRevokeCredentials]);
    let mut client = rig.connect();
    let reply = client.call(1, create(None, "survive")).await;
    assert_eq!(reply["error"]["data"]["outcome"], "uncertain");
    let key = rig.state().keys_sent()[0].clone().unwrap();
    assert_eq!(reply["error"]["data"]["idempotency_key"], key);
    let saved = entries(&rig);
    assert_eq!(saved[0]["state"], "uncertain");
    assert_eq!(
        saved[0]["attempts"], 1,
        "the attempt that never went out is not counted"
    );
}

#[tokio::test]
async fn only_a_receipt_settles_an_earlier_uncertain_entry() {
    let mut config = fast();
    config.budget = Duration::from_millis(500);
    let rig = Rig::new(config).await;
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let mut client = rig.connect();
    let first = create(Some("k-open"), "same");
    let reply = client.call(1, first.clone()).await;
    assert_eq!(reply["error"]["data"]["outcome"], "uncertain");
    *rig.state().always.lock().unwrap() = None;

    // The agent retries with the key; hosted refuses it. Refused is not a
    // receipt: the earlier question stays open, and so does the new one if
    // it could not be told apart from it (it can: nothing landed this time).
    rig.state().script([Fault::Http(
        400,
        r#"{"error":"bad input","error_code":"invalid_params"}"#,
    )]);
    let reply = client.call(1, first.clone()).await;
    assert_eq!(reply["error"]["data"]["http_status"], 400);
    let open = rig.gate.status(&Default::default())["uncertain"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(open, 1, "the earlier entry is still open after a refusal");

    // A receipt settles it.
    let reply = client.call(3, first).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(
        rig.gate.status(&Default::default())["uncertain"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[tokio::test]
async fn gateway_html_or_a_bare_proxy_code_is_still_retried() {
    // A generic gateway body is a proxy speaking, not Native: only Native's own
    // envelope fields (outcome, applied, partial, error_code, recovery,
    // retryable) make a 502/503/504 an answer.
    let rig = Rig::new(fast()).await;
    rig.state().script([
        Fault::Http(503, r#"{"code":"ServiceUnavailable"}"#),
        Fault::Http(502, r#"{"error":"Bad Gateway","code":"BadGateway"}"#),
        Fault::Http(504, r#"{"message":"upstream timed out"}"#),
    ]);
    let mut client = rig.connect();
    let reply = client.call(1, create(Some("k-proxy"), "once")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(rig.state().writes().len(), 4);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_refusal_whose_body_is_lost_is_not_retried_and_marks_auth() {
    for status in [401u16, 403, 400, 404] {
        let rig = Rig::new(fast()).await;
        rig.state().script([Fault::Truncated(status)]);
        let mut client = rig.connect();
        let reply = client.call(1, create(Some("k-lost-refusal"), "once")).await;
        assert_eq!(rig.state().writes().len(), 1, "{status} was retried");
        assert_eq!(reply["error"]["data"]["outcome"], "refused", "{status}");
        assert_eq!(reply["error"]["data"]["http_status"], status);
        assert_eq!(entries(&rig)[0]["state"], "confirmed", "{status}");
    }
    // The auth classification survives the lost body.
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Truncated(403)]);
    let message =
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{}}});
    let report = rig
        .upstream
        .send_attempt(
            &message.to_string(),
            &message,
            None,
            message.get("id"),
            None,
        )
        .await;
    assert_eq!(report.failure, Some(Health::AuthRefused));
    assert_eq!(report.attempt, Attempt::Answered);

    // A body lost on a 2xx is the dropped connection a retry is for.
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Truncated(200)]);
    let mut client = rig.connect();
    let reply = client.call(1, create(Some("k-lost-200"), "once")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(rig.state().writes().len(), 2);
}

#[tokio::test]
async fn an_ambiguous_reply_on_a_keyed_write_carries_the_key() {
    // A 2xx the node cannot read, and an unexplained 500, are not retried (the
    // brief's list is connection, timeout, 502/503/504) but must not leave
    // the agent without the key.
    for fault in [
        Fault::Http(200, "this is not json"),
        Fault::Http(500, "<html>oops</html>"),
        Fault::Truncated(500),
    ] {
        let rig = Rig::new(fast()).await;
        rig.state().script([fault]);
        let mut client = rig.connect();
        let reply = client.call(1, create(None, "once")).await;
        assert_eq!(rig.state().writes().len(), 1);
        let key = rig.state().keys_sent()[0].clone().unwrap();
        assert_eq!(reply["error"]["data"]["outcome"], "uncertain");
        assert_eq!(reply["error"]["data"]["idempotency_key"], key);
        assert!(reply["error"]["message"].as_str().unwrap().contains(&key));
    }
}

#[tokio::test]
async fn one_deadline_covers_credential_renewal_and_the_whole_attempt() {
    // A token endpoint that accepts and never answers.
    let hang = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/oauth2/token", hang.local_addr().unwrap());
    let holder = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = hang.accept().await {
            held.push(socket);
        }
    });
    let mut config = fast();
    config.budget = Duration::from_millis(600);
    let rig = Rig::new(config).await;
    let dir = tempfile::tempdir().unwrap();
    let auth_path = dir.path().join("auth.json");
    let token_path = dir.path().join("native.token");
    let auth = json!({
        "contract": super::super::oauth::CONTRACT,
        "access_token": "old", "refresh_token": "old", "client_id": "c",
        "expires_at": 1_000, "token_endpoint": endpoint,
    });
    fs::write(&auth_path, serde_json::to_vec(&auth).unwrap()).unwrap();
    fs::set_permissions(&auth_path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&token_path, "old").unwrap();
    fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
    seed_keyed(&rig.gate);
    let mut upstream = Upstream::new(rig.config.clone(), Duration::from_secs(30)).unwrap();
    upstream.oauth = Some(Arc::new(super::super::oauth::OAuthRenewer::new(
        auth_path,
        token_path,
        endpoint.clone(),
        super::super::oauth::renew_client().unwrap(),
    )));

    let message = tool_call(1, "call_executor", create(Some("k-oauth"), "x"));
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    let started = Instant::now();
    let report = rig
        .gate
        .forward(
            &upstream,
            &WriteRequest {
                body: &body,
                message: &message,
                revision: None,
                caller: &caller,
                outage: None,
                no_hold: false,
            },
            true,
        )
        .await;
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "renewal and lookups ran past the budget: {:?}",
        started.elapsed()
    );
    assert!(rig.state().writes().is_empty(), "nothing was sent");
    let reply: Value = serde_json::from_str(&report.reply.unwrap()).unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("renewal"));
    assert_eq!(entries(&rig)[0]["state"], "not_sent");
    holder.abort();
}

#[tokio::test]
async fn an_attempt_does_not_start_with_less_than_the_minimum_left() {
    let mut config = fast();
    config.budget = Duration::from_millis(300);
    config.min_attempt = Duration::from_secs(5);
    let rig = Rig::new(config).await;
    seed_keyed(&rig.gate);
    let message = tool_call(1, "call_executor", create(Some("k-late"), "x"));
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    let report = rig
        .gate
        .forward(
            &rig.upstream,
            &WriteRequest {
                body: &body,
                message: &message,
                revision: None,
                caller: &caller,
                outage: None,
                no_hold: false,
            },
            true,
        )
        .await;
    assert!(rig.state().writes().is_empty());
    let reply: Value = serde_json::from_str(&report.reply.unwrap()).unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert_eq!(entries(&rig)[0]["state"], "not_sent");
    assert_eq!(entries(&rig)[0]["attempts"], 0);
}

#[tokio::test]
async fn cancel_before_dispatch_sends_nothing_and_a_queued_request_cannot_block_the_cancel() {
    // 64 requests fill every permit and are held by hosted. The 65th queues.
    // The cancel for it arrives behind it on the same connection and must be
    // read at once, not after a permit frees.
    let rig = Rig::new(fast()).await;
    *rig.state().always.lock().unwrap() = Some(Fault::Hold(Duration::from_millis(1500)));
    let mut client = rig.connect();
    let read =
        json!({"executor":"records_read","operation":"get_record","arguments":{"ids":["x"]}});
    for id in 1..=64u64 {
        client
            .send(tool_call(id, "call_executor", read.clone()))
            .await;
    }
    eventually(|| rig.state().writes().len() == 64).await;
    client
        .send(tool_call(65, "call_executor", read.clone()))
        .await;
    client
        .send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":65}}))
        .await;
    let mut replies = 0;
    for _ in 0..64 {
        let reply = client.recv().await.unwrap();
        assert_ne!(reply["id"], 65);
        replies += 1;
    }
    assert_eq!(replies, 64);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        rig.state().writes().len(),
        64,
        "the cancelled request never ran"
    );
    client.writer.shutdown().await.unwrap();
    assert!(client.recv().await.is_none(), "and got no reply");
}

#[test]
fn finishing_a_request_and_noticing_its_cancel_is_one_step() {
    let in_flight = InFlight::default();
    let id = json!(7);
    let (key, cancel) = in_flight.register(Some(&id));
    in_flight.cancel(&id);
    assert!(cancel.is_cancelled());
    assert!(
        in_flight.finish(&key),
        "a cancel seen before finishing suppresses the reply"
    );

    let id = json!(8);
    let (key, _) = in_flight.register(Some(&id));
    assert!(!in_flight.finish(&key));
    in_flight.cancel(&id); // too late: nothing is tracked, nothing changes
    assert!(!in_flight.finish(&key));
}

#[tokio::test]
async fn cancel_during_the_backoff_wins_over_the_next_attempt() {
    let mut config = fast();
    config.backoff_start = Duration::from_secs(3);
    config.backoff_max = Duration::from_secs(3);
    config.budget = Duration::from_secs(20);
    let rig = Rig::new(config).await;
    *rig.state().always.lock().unwrap() = Some(Fault::Http(503, "<html>down</html>"));
    let mut client = rig.connect();
    client
        .send(tool_call(7, "call_executor", create(Some("k-bo"), "x")))
        .await;
    eventually(|| rig.state().writes().len() == 1).await;
    client
        .send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}))
        .await;
    client.writer.shutdown().await.unwrap();
    let started = Instant::now();
    assert!(client.recv().await.is_none());
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "did not sit out the backoff"
    );
    assert_eq!(rig.state().writes().len(), 1);
}

#[tokio::test]
async fn restart_between_save_and_send_through_the_real_forwarding_path() {
    // Park the real forwarding code after it has saved the entry and before it
    // sends, then kill the node's task there.
    let mut rig = Rig::new(fast()).await;
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    *rig.gate.pause_before_send.lock().unwrap() = Some((entered.clone(), release));
    let mut client = rig.connect();
    client
        .send(tool_call(1, "call_executor", create(Some("k-saved"), "x")))
        .await;
    entered.notified().await;
    assert_eq!(entries(&rig)[0]["state"], "sent", "saved, not yet sent");
    assert!(rig.state().writes().is_empty());
    client.task.abort();
    let _ = (&mut client.task).await;
    rig.restart(fast());
    let saved = entries(&rig);
    assert_eq!(saved[0]["state"], "uncertain");
    assert_eq!(saved[0]["attempts"], 0);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        rig.state().writes().is_empty(),
        "never replayed by the node"
    );
    let mut client = rig.connect();
    let reply = client.call(2, create(Some("k-saved"), "x")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn two_concurrent_calls_with_the_same_caller_key_create_one_record() {
    let rig = Rig::new(fast()).await;
    // The first request to reach hosted is applied and then sits on its reply
    // past the attempt timeout, so it is retried while the other is in flight.
    rig.state()
        .script([Fault::ApplyThenStall(Duration::from_secs(2))]);
    let mut a = rig.connect();
    let mut b = rig.connect();
    let call = create(Some("k-shared"), "same");
    a.send(tool_call(1, "call_executor", call.clone())).await;
    b.send(tool_call(1, "call_executor", call)).await;
    let (ra, rb) = (a.recv().await.unwrap(), b.recv().await.unwrap());
    assert_eq!(receipt(&ra)["record_id"], "rec-1");
    assert_eq!(receipt(&rb)["record_id"], "rec-1");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert!(rig
        .state()
        .keys_sent()
        .iter()
        .all(|k| k.as_deref() == Some("k-shared")));
    let saved = entries(&rig);
    assert_eq!(saved.len(), 2, "two calls, two entries");
    assert!(saved.iter().all(|e| e["state"] == "confirmed"));
    assert_eq!(
        rig.gate.status(&Default::default())["uncertain"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn a_closed_allof_member_without_the_key_means_not_keyed() {
    // allOf members are all in force: one declaring the key does not help if
    // another closes the object without it.
    assert!(!schema_accepts_key(&json!({"allOf":[
        {"properties":{"idempotency_key":{"type":"string"}}},
        {"properties":{"id":{}},"additionalProperties":false}]})));
    // The member that closes the object also declares the key: fine.
    assert!(schema_accepts_key(&json!({"allOf":[
        {"properties":{"idempotency_key":{"type":"string"},"id":{}},"additionalProperties":false},
        {"required":["id"]}]})));
    // A closed top level that lacks the key rejects it whatever the branches say.
    assert!(!schema_accepts_key(&json!({
        "properties":{"reason":{}},"additionalProperties":false,
        "oneOf":[{"properties":{"idempotency_key":{}}}]})));
    // patternProperties are not evaluated: be conservative.
    assert!(!schema_accepts_key(&json!({
        "properties":{"idempotency_key":{}},
        "allOf":[{"patternProperties":{"^x":{}}}]})));
    // A closed branch lacking the key makes the whole oneOf not keyed.
    assert!(!schema_accepts_key(&json!({"oneOf":[
        {"properties":{"idempotency_key":{}}},
        {"allOf":[{"properties":{"idempotency_key":{}}},{"additionalProperties":false,"properties":{"a":{}}}]}]})));
}

#[tokio::test]
async fn an_idle_node_prunes_settled_entries() {
    let mut config = fast();
    config.retention = Duration::ZERO;
    let rig = Rig::new(config).await;
    let mut client = rig.connect();
    client.call(1, create(Some("k-a"), "x")).await;
    assert_eq!(entries(&rig).len(), 1);
    tokio::time::sleep(Duration::from_millis(10)).await;
    // Asking for status tidies up...
    let _ = rig.gate.status(&Default::default());
    assert!(entries(&rig).is_empty());

    // ...and so does the background housekeeping, with nobody asking.
    let mut config = fast();
    config.retention = Duration::ZERO;
    config.housekeeping_every = Duration::from_millis(50);
    let rig = Rig::new(config).await;
    let task = rig.gate.spawn_housekeeping();
    let mut client = rig.connect();
    client.call(1, create(Some("k-b"), "x")).await;
    eventually(|| entries(&rig).is_empty()).await;
    task.abort();
}

#[tokio::test]
async fn a_plain_rpc_error_after_a_possible_application_still_carries_the_key() {
    // Hosted's protocol::error_response gives {"code","message"} with no data;
    // a non-object `data` must survive too.
    let bare = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params"}}"#;
    let stringy = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params","data":"see docs"}}"#;
    for (raw, original_data) in [(bare, None), (stringy, Some("see docs"))] {
        let rig = Rig::new(fast()).await;
        rig.state()
            .script([Fault::ApplyThenDrop, Fault::Http(200, raw)]);
        let mut client = rig.connect();
        let reply = client.call(1, create(None, "survive")).await;
        let key = rig.state().keys_sent()[0].clone().unwrap();
        assert_eq!(rig.state().writes().len(), 2);
        assert_eq!(reply["error"]["code"], -32602, "hosted's error is intact");
        assert_eq!(reply["error"]["message"], "Invalid params");
        let data = &reply["error"]["data"];
        match original_data {
            None => assert_eq!(data["node_journal"]["idempotency_key"], key),
            Some(original) => {
                assert_eq!(data["upstream_data"], original, "hosted's data is kept");
                assert_eq!(data["node_journal"]["idempotency_key"], key);
            }
        }
        assert_eq!(entries(&rig)[0]["state"], "uncertain");
    }
}

#[tokio::test]
async fn unknown_access_never_prepares_a_key_or_retries_even_when_the_contract_is_keyed() {
    let rig = Rig::new(fast()).await;
    // Only the access lookup fails; describe_operation works and says keyed.
    rig.state().access_fails.store(true, Ordering::SeqCst);
    rig.state().script([Fault::DropBeforeApply]);
    let mut client = rig.connect();
    let reply = client.call(1, create(None, "x")).await;
    assert_eq!(
        rig.state().describes.load(Ordering::SeqCst),
        0,
        "no contract is even consulted"
    );
    assert_eq!(rig.state().writes().len(), 1, "no retry");
    assert!(rig.state().keys_sent()[0].is_none(), "no key minted");
    assert!(reply.get("error").is_some());
    let saved = entries(&rig);
    assert_eq!(saved[0]["state"], "uncertain");
    assert!(saved[0]["idempotency_key"].is_null());

    // A cached keyed contract changes nothing: access decides first.
    seed_keyed(&rig.gate);
    rig.state().script([Fault::DropBeforeApply]);
    let _ = client.call(2, create(None, "y")).await;
    assert_eq!(rig.state().writes().len(), 2);
    assert!(rig.state().keys_sent()[1].is_none());
}

#[tokio::test]
async fn a_burst_of_new_operations_makes_one_lookup_each_to_hosted() {
    let rig = Rig::new(fast()).await;
    rig.state().lookup_delay_ms.store(100, Ordering::SeqCst);
    let mut clients: Vec<Client> = (0..8).map(|_| rig.connect()).collect();
    for (n, client) in clients.iter_mut().enumerate() {
        client
            .send(tool_call(
                1,
                "call_executor",
                create(Some(&format!("k-burst-{n}")), "x"),
            ))
            .await;
    }
    for client in clients.iter_mut() {
        let reply = client.recv().await.unwrap();
        assert!(receipt(&reply)["record_id"].is_string());
    }
    assert_eq!(rig.state().access_lookups.load(Ordering::SeqCst), 1);
    assert_eq!(rig.state().describes.load(Ordering::SeqCst), 1);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 8);
}

#[tokio::test]
async fn time_spent_queued_counts_against_the_write_budget() {
    // The frame arrived 480 ms ago against a 500 ms budget: not enough left
    // for an attempt of at least 50 ms, so nothing is sent.
    let mut config = fast();
    config.budget = Duration::from_millis(500);
    let rig = Rig::new(config).await;
    seed_keyed(&rig.gate);
    let message = tool_call(1, "call_executor", create(Some("k-queued"), "x"));
    let body = message.to_string();
    let mut caller = Caller::new(None, Cancel::new());
    caller.received = Instant::now() - Duration::from_millis(480);
    let report = rig
        .gate
        .forward(
            &rig.upstream,
            &WriteRequest {
                body: &body,
                message: &message,
                revision: None,
                caller: &caller,
                outage: None,
                no_hold: false,
            },
            true,
        )
        .await;
    assert!(rig.state().writes().is_empty());
    let reply: Value = serde_json::from_str(&report.reply.unwrap()).unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
}

/// Fill a connection's 64 capacity permits with requests hosted holds.
async fn fill_capacity(rig: &Rig, client: &mut Client, first_id: u64, hold: Duration) {
    *rig.state().always.lock().unwrap() = Some(Fault::Hold(hold));
    let read =
        json!({"executor":"records_read","operation":"get_record","arguments":{"ids":["x"]}});
    let before = rig.state().writes().len();
    for id in first_id..first_id + 64 {
        client
            .send(tool_call(id, "call_executor", read.clone()))
            .await;
    }
    eventually(|| rig.state().writes().len() == before + 64).await;
}

#[tokio::test]
async fn the_queue_is_bounded_by_count_across_connections_and_overflow_is_not_sent() {
    let rig = Rig::new(fast()).await;
    // One queued request node-wide.
    let admission = Arc::new(Admission::with_limits(
        1,
        32 * 1024 * 1024,
        Duration::from_secs(30),
    ));
    let mut a = rig.connect_with(admission.clone());
    let mut b = rig.connect_with(admission);
    fill_capacity(&rig, &mut a, 1, Duration::from_millis(1500)).await;
    fill_capacity(&rig, &mut b, 1, Duration::from_millis(1500)).await;
    let read =
        json!({"executor":"records_read","operation":"get_record","arguments":{"ids":["x"]}});
    a.send(tool_call(100, "call_executor", read.clone())).await; // takes the one place
    b.send(tool_call(200, "call_executor", read.clone())).await; // refused at once
    let started = Instant::now();
    let refused = b.recv().await.unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(800),
        "refused immediately, not after capacity frees"
    );
    assert_eq!(refused["id"], 200);
    assert_eq!(refused["error"]["data"]["outcome"], "not_sent");
    assert_eq!(refused["error"]["data"]["reason"], "node_busy");
    // The queued one runs once capacity frees, and everything else completes.
    *rig.state().always.lock().unwrap() = None;
    let mut ids_a = Vec::new();
    for _ in 0..65 {
        ids_a.push(a.recv().await.unwrap()["id"].as_u64().unwrap());
    }
    assert!(ids_a.contains(&100));
    assert_eq!(
        rig.state().writes().len(),
        64 + 64 + 1,
        "only the admitted queued request ran"
    );
}

#[tokio::test]
async fn the_queue_is_bounded_by_bytes() {
    let rig = Rig::new(fast()).await;
    let admission = Arc::new(Admission::with_limits(100, 2_000, Duration::from_secs(30)));
    let mut client = rig.connect_with(admission);
    fill_capacity(&rig, &mut client, 1, Duration::from_millis(1200)).await;
    client
        .send(tool_call(
            100,
            "call_executor",
            create(Some("k-big"), &"x".repeat(5_000)),
        ))
        .await;
    let refused = client.recv().await.unwrap();
    assert_eq!(refused["id"], 100);
    assert_eq!(refused["error"]["data"]["reason"], "node_busy");
    // A small one still fits.
    let read =
        json!({"executor":"records_read","operation":"get_record","arguments":{"ids":["x"]}});
    client.send(tool_call(101, "call_executor", read)).await;
    *rig.state().always.lock().unwrap() = None;
    let mut seen = Vec::new();
    for _ in 0..65 {
        seen.push(client.recv().await.unwrap()["id"].as_u64().unwrap());
    }
    assert!(seen.contains(&101) && !seen.contains(&100));
}

#[tokio::test]
async fn a_request_queued_past_its_budget_is_answered_not_sent_without_running() {
    let rig = Rig::new(fast()).await;
    let admission = Arc::new(Admission::with_limits(
        10,
        32 * 1024 * 1024,
        Duration::from_millis(300),
    ));
    let mut client = rig.connect_with(admission);
    fill_capacity(&rig, &mut client, 1, Duration::from_millis(1500)).await;
    client
        .send(tool_call(100, "call_executor", create(Some("k-late"), "x")))
        .await;
    let reply = client.recv().await.unwrap();
    assert_eq!(reply["id"], 100);
    assert_eq!(reply["error"]["data"]["reason"], "queue_timeout");
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert_eq!(rig.state().writes().len(), 64, "it never reached hosted");
    assert!(entries(&rig).is_empty(), "and was never journaled");
}

#[tokio::test]
async fn disconnecting_cancels_queued_requests() {
    let rig = Rig::new(fast()).await;
    let mut client = rig.connect();
    fill_capacity(&rig, &mut client, 1, Duration::from_millis(1500)).await;
    let read =
        json!({"executor":"records_read","operation":"get_record","arguments":{"ids":["x"]}});
    client.send(tool_call(100, "call_executor", read)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(client);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        rig.state().writes().len(),
        64,
        "the queued request was cancelled, not run later"
    );
}

#[test]
fn a_closed_connection_cancels_whatever_registers_later() {
    let in_flight = InFlight::default();
    let (early_key, early) = in_flight.register(Some(&json!(1)));
    let (_, anonymous) = in_flight.register(None);
    in_flight.close();
    assert!(early.is_cancelled() && anonymous.is_cancelled());
    // A request the reader had not yet registered when the connection closed.
    let (late_key, late) = in_flight.register(Some(&json!(2)));
    assert!(late.is_cancelled());
    assert!(in_flight.finish(&late_key));
    assert!(in_flight.finish(&early_key));
}

// ---- Holding writes (slice 2B) ----

/// Hosted is down or not, as the follow-up check sees it.
struct FakeOutage {
    down: AtomicBool,
    known: AtomicBool,
    asked: AtomicUsize,
}
impl FakeOutage {
    fn new(down: bool) -> Self {
        Self {
            down: AtomicBool::new(down),
            known: AtomicBool::new(false),
            asked: AtomicUsize::new(0),
        }
    }
}
impl Outage for FakeOutage {
    fn known_unreachable(&self) -> Ready<'_, bool> {
        let known = self.known.load(Ordering::SeqCst);
        Box::pin(async move { known })
    }
    fn contract_digest<'a>(
        &'a self,
        executor: &'a str,
        operation: &'a str,
        _protocol: Option<&'a str>,
    ) -> Ready<'a, Option<String>> {
        let digest = crate::mcp::executor_prototype::NodeOperationContracts::local()
            .unwrap()
            .digest(executor, operation)
            .map(str::to_owned);
        Box::pin(async move { digest })
    }
    fn confirm_down(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        self.asked.fetch_add(1, Ordering::SeqCst);
        let down = self.down.load(Ordering::SeqCst);
        Box::pin(async move { down })
    }
}

/// Run one call through the gate directly, with a follow-up check if given.
async fn forward_with(rig: &Rig, arguments: Value, outage: Option<&dyn Outage>) -> Value {
    let message = tool_call(7, "call_executor", arguments);
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    let report = rig
        .gate
        .forward(
            &rig.upstream,
            &WriteRequest {
                body: &body,
                message: &message,
                revision: None,
                caller: &caller,
                outage,
                no_hold: false,
            },
            true,
        )
        .await;
    serde_json::from_str(&report.reply.expect("a reply")).unwrap()
}

fn listed_writes() -> Vec<(&'static str, Value)> {
    let target = "70110000-0000-4000-8000-0000000000e1";
    vec![
        ("create_record", create(None, "one")),
        (
            "create_many",
            json!({"executor":"records_write","operation":"create_many","run_key":"run-xyz","arguments":{
                "reason":"r","records":[{"type":"Document","kind":"note","name":"A"},{"type":"Document","kind":"note"}]}}),
        ),
        (
            "manage_links.add",
            json!({"executor":"records_write","operation":"manage_links.add","run_key":"run-xyz","arguments":{
                "source_id":target,"target_id":"70110000-0000-4000-8000-0000000000e2","relationship":"relates_to"}}),
        ),
        (
            "attach_text",
            json!({"executor":"records_write","operation":"attach_text","run_key":"run-xyz","arguments":{
                "record_id":target,"text":"notes","filename":"n.txt"}}),
        ),
        (
            "update_record",
            json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
                "id":target,"reason":"r","body_append":"more"}}),
        ),
    ]
}

#[tokio::test]
async fn a_missing_local_operation_contract_refuses_instead_of_holding() {
    let mut rig = Rig::new(fast()).await;
    Arc::get_mut(&mut rig.gate).unwrap().local_contracts =
        Arc::new(crate::mcp::executor_prototype::NodeOperationContracts::default());
    let before = rig.gate.status(&Default::default());
    let down = FakeOutage::new(true);
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let reply = forward_with(&rig, create(None, "valid write"), Some(&down)).await;
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("contract unavailable"));
    let after = rig.gate.status(&Default::default());
    assert_eq!(before["queue"]["pending"], 0);
    assert_eq!(after["queue"]["pending"], 0);
    assert_eq!(after["entry_counts"]["not_sent"], 1);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_prepared_arguments_are_refused_before_a_held_entry_is_journaled() {
    let rig = Rig::new(fast()).await;
    let down = FakeOutage::new(true);
    down.known.store(true, Ordering::SeqCst);
    let mut exact = create(None, "valid write")["arguments"].clone();
    exact["id"] = json!("broken-generated-id");
    *rig.gate.prepared_arguments_override.lock().unwrap() = Some(exact);
    let reply = forward_with(&rig, create(None, "valid write"), Some(&down)).await;
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    assert_eq!(receipt(&reply)["outcome"], "not_sent");
    assert_eq!(
        receipt(&reply)["repair"]["error_class"],
        "validation_failure"
    );
    assert!(entries(&rig).is_empty());
    assert!(rig.state().writes().is_empty());
}

fn pending(reply: &Value) -> &Value {
    assert_eq!(reply["result"]["isError"], false, "{reply}");
    let info = &reply["result"]["structuredContent"];
    assert_eq!(info["outcome"], "accepted_pending", "{reply}");
    info
}

#[tokio::test]
async fn read_only_holds_each_listed_write_without_retrying_or_losing_its_bytes() {
    for (name, call) in listed_writes() {
        let rig = Rig::new(fast()).await;
        rig.state().script([Fault::Http(200, READ_ONLY)]);
        let mut client = rig.connect();
        let reply = client.call(1, call).await;
        let info = pending(&reply);
        assert_eq!(info["reason"], "deployment_read_only", "{name}");
        assert_eq!(info["may_already_be_applied"], false, "{name}");
        assert!(info["idempotency_key"]
            .as_str()
            .unwrap()
            .starts_with("node-"));
        assert_eq!(info["queue_position"], 1);
        assert!(info["how_to_check"].as_str().unwrap().contains("Repeat"));
        // Hosted's "not applied or queued" wording is replaced, not repeated.
        assert!(!reply.to_string().contains("not applied or queued"));
        assert_eq!(rig.state().writes().len(), 1, "{name}: no retry");
        assert_eq!(rig.state().created.load(Ordering::SeqCst), 0, "{name}");

        // Creates tell the caller the record's ID up front, and it is the ID
        // hosted was sent.
        let sent = rig.state().writes()[0]
            .pointer("/params/arguments/arguments")
            .cloned()
            .unwrap();
        match name {
            "create_record" => {
                assert_eq!(info["record_id"], sent["id"]);
            }
            "create_many" => {
                let ids = info["record_ids"].as_array().unwrap();
                assert_eq!(ids.len(), 2);
                assert_eq!(ids[0], sent["records"][0]["id"]);
                assert_eq!(ids[1], sent["records"][1]["id"]);
                assert!(info.get("record_id").is_none());
            }
            _ => {
                assert!(info.get("record_id").is_none(), "{name}");
                assert!(info["target_record_id"].is_string(), "{name}");
            }
        }

        // The journal holds the write, with the bytes it will be sent with.
        let saved = entries(&rig);
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0]["state"], "pending", "{name}");
        assert_eq!(saved[0]["hold_reason"], "deployment_read_only");
        assert_eq!(
            serde_json::to_string(&saved[0]["arguments"]).unwrap(),
            serde_json::to_string(&sent).unwrap(),
            "{name}: stored arguments are what was sent"
        );
        assert_eq!(saved[0]["idempotency_key"], info["idempotency_key"]);
        assert_eq!(saved[0]["envelope"]["run_key"], "run-xyz");
        assert_eq!(
            rig.gate.status(&Default::default())["entry_counts"]["pending"],
            1
        );
    }
}

#[tokio::test]
async fn a_held_write_records_its_title_run_and_parent_run() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let mut call = create(Some("k-meta"), "x");
    call["parent_key"] = json!("parent-run");
    call["arguments"]["name"] = json!("Meeting notes");
    let reply = forward_with(&rig, call, None).await;
    let info = pending(&reply);
    assert_eq!(info["idempotency_key"], "k-meta");
    assert_eq!(info["key_origin"], "caller");
    let saved = entries(&rig);
    assert_eq!(saved[0]["title"], "Meeting notes");
    assert_eq!(saved[0]["parent_key"], "parent-run");
    assert_eq!(saved[0]["run_key"], "run-xyz");
    assert_eq!(saved[0]["record_id"], info["record_id"]);
    assert!(saved[0]["seq"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn a_repeat_of_a_held_call_returns_pending_without_sending_or_saving_again() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let call = create(None, "hold me");
    let first = forward_with(&rig, call.clone(), None).await;
    let info = pending(&first).clone();
    let key = info["idempotency_key"].as_str().unwrap().to_owned();

    // The agent repeats its call, as told, with the key the node returned.
    let mut repeat = call.clone();
    repeat["arguments"]["idempotency_key"] = json!(key);
    let again = forward_with(&rig, repeat.clone(), None).await;
    let again = pending(&again);
    assert_eq!(again["record_id"], info["record_id"]);
    assert_eq!(again["journal_entry"], info["journal_entry"]);
    assert_eq!(
        rig.state().writes().len(),
        1,
        "nothing was sent for the repeat"
    );
    assert_eq!(entries(&rig).len(), 1, "nothing was saved for the repeat");

    // Field order does not matter to recognising the same call.
    let mut reordered = json!({"arguments":{},"run_key":"run-xyz","operation":"create_record","executor":"records_write"});
    reordered["arguments"]["idempotency_key"] = json!(key);
    reordered["arguments"]["body"] = json!("hold me");
    reordered["arguments"]["type"] = json!("Document");
    reordered["arguments"]["kind"] = json!("note");
    reordered["arguments"]["reason"] = json!("test write");
    let again = forward_with(&rig, reordered, None).await;
    assert_eq!(pending(&again)["journal_entry"], info["journal_entry"]);

    // The same key with different content is a different question.
    let mut changed = repeat;
    changed["arguments"]["body"] = json!("something else");
    let refused = forward_with(&rig, changed, None).await;
    assert_eq!(refused["error"]["data"]["reason"], "idempotency_conflict");
    assert_eq!(refused["error"]["data"]["outcome"], "not_sent");
    assert_eq!(rig.state().writes().len(), 1);
    assert_eq!(entries(&rig).len(), 1);
}

#[tokio::test]
async fn a_held_write_survives_a_restart_and_a_repeat_after_it_still_returns_pending() {
    let mut rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let first = forward_with(&rig, create(None, "keep"), None).await;
    let info = pending(&first).clone();
    let before = entries(&rig);

    rig.restart(fast());
    let after = entries(&rig);
    assert_eq!(
        after[0]["state"], "pending",
        "not turned uncertain by restart"
    );
    assert_eq!(after[0]["arguments"], before[0]["arguments"]);
    assert_eq!(after[0]["seq"], before[0]["seq"]);

    let mut repeat = create(None, "keep");
    repeat["arguments"]["idempotency_key"] = info["idempotency_key"].clone();
    let again = forward_with(&rig, repeat, None).await;
    assert_eq!(pending(&again)["record_id"], info["record_id"]);
    assert_eq!(rig.state().writes().len(), 1);
}

#[tokio::test]
async fn read_only_is_not_held_for_writes_the_node_may_not_hold() {
    // Not on the list, and an update that is more than an append: hosted's
    // refusal reaches the caller untouched, as in slice A.
    let rig = Rig::new(fast()).await;
    for call in [
        json!({"executor":"coordination_write","operation":"set_intent","arguments":{"intent":"x"}}),
        json!({"executor":"records_write","operation":"update_record","arguments":{
            "id":"70110000-0000-4000-8000-0000000000e1","reason":"r","body_set":"replaced"}}),
        json!({"executor":"records_write","operation":"update_record","arguments":{
            "id":"70110000-0000-4000-8000-0000000000e1","reason":"r","body_append":"x","summary":"s"}}),
    ] {
        rig.state().script([Fault::Http(200, READ_ONLY)]);
        let mut client = rig.connect();
        client
            .send(tool_call(3, "call_executor", call.clone()))
            .await;
        let mut line = String::new();
        client.reader.read_line(&mut line).await.unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(
            reply["result"]["structuredContent"]["error_code"], "DEPLOYMENT_READ_ONLY",
            "{call}"
        );
    }
    assert!(entries(&rig).iter().all(|e| e["state"] != "pending"));
}

#[tokio::test]
async fn other_failures_never_hold_a_write() {
    // Credentials refused, a malformed answer, a validation refusal, a
    // mid-reply drain: each keeps slice A's behaviour whatever the follow-up
    // check would say, because none of them is hosted being away.
    let outage = FakeOutage::new(true);
    for fault in [
        Fault::Http(
            401,
            r#"{"error":"unauthorized","code":"auth_expired","outcome":"refused"}"#,
        ),
        Fault::Http(403, r#"{"error":"forbidden","error_code":"forbidden"}"#),
        Fault::Http(200, "this is not a json-rpc reply"),
        Fault::Http(
            400,
            r#"{"error":"bad input","error_code":"invalid_params"}"#,
        ),
    ] {
        let rig = Rig::new(fast()).await;
        rig.state().script([fault]);
        let reply = forward_with(&rig, create(None, "x"), Some(&outage)).await;
        assert!(
            reply["result"]["structuredContent"]["outcome"] != "accepted_pending",
            "{reply}"
        );
        assert!(entries(&rig).iter().all(|e| e["state"] != "pending"));
    }
    assert_eq!(
        outage.asked.load(Ordering::SeqCst),
        0,
        "none of them is a transport failure, so nobody asked"
    );
}

#[tokio::test]
async fn a_failed_forward_alone_does_not_hold_it_takes_a_failed_follow_up_check() {
    let mut config = fast();
    config.budget = Duration::from_millis(600);
    let rig = Rig::new(config).await;
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    // Hosted looks fine to the follow-up check: keep retrying as slice A did,
    // and end uncertain when the budget runs out.
    let up = FakeOutage::new(false);
    let reply = forward_with(&rig, create(None, "x"), Some(&up)).await;
    assert_eq!(reply["error"]["data"]["outcome"], "uncertain");
    assert!(
        up.asked.load(Ordering::SeqCst) >= 1,
        "each failure was checked"
    );
    assert!(rig.state().writes().len() >= 2, "it kept retrying");
    assert!(entries(&rig).iter().all(|e| e["state"] == "uncertain"));
}

#[tokio::test]
async fn a_failed_forward_plus_a_failed_check_holds_and_says_it_may_already_be_applied() {
    // The reply is lost after hosted applied it; the follow-up check finds
    // hosted down. Holding is safe because the resend carries the same key.
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::ApplyThenDrop]);
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let down = FakeOutage::new(true);
    let reply = forward_with(&rig, create(None, "x"), Some(&down)).await;
    let info = pending(&reply);
    assert_eq!(info["reason"], "hosted_unreachable");
    assert_eq!(info["may_already_be_applied"], true);
    assert!(reply.to_string().contains("may already have been applied"));
    assert_eq!(
        rig.state().writes().len(),
        1,
        "held at once, not after the budget"
    );
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    let saved = entries(&rig);
    assert_eq!(saved[0]["state"], "pending");
    assert_eq!(saved[0]["hold_reason"], "hosted_unreachable");
    assert_eq!(saved[0]["maybe_applied"], true);
    assert!(saved[0]["arguments"].is_object());
}

#[tokio::test]
async fn an_uncertain_keyed_write_becomes_pending_once_hosted_is_confirmed_down() {
    let mut config = fast();
    config.budget = Duration::from_millis(500);
    let rig = Rig::new(config).await;
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let first = create(Some("k-open"), "same");
    let reply = forward_with(&rig, first.clone(), None).await;
    assert_eq!(reply["error"]["data"]["outcome"], "uncertain");

    // The agent repeats it with the key; hosted is now confirmed down.
    let down = FakeOutage::new(true);
    let reply = forward_with(&rig, first, Some(&down)).await;
    let info = pending(&reply);
    assert_eq!(info["idempotency_key"], "k-open");
    assert_eq!(info["may_already_be_applied"], true);
    // The first request's bytes and the held ones are the same id.
    let sent = rig.state().writes();
    assert_eq!(
        sent[0].pointer("/params/arguments/arguments/id"),
        sent.last()
            .unwrap()
            .pointer("/params/arguments/arguments/id"),
    );
}

#[tokio::test]
async fn a_cancelled_caller_does_not_have_its_write_taken_over() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let message = tool_call(7, "call_executor", create(None, "x"));
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    // Cancelled while hosted is answering.
    caller.cancel.cancel();
    let report = rig
        .gate
        .forward(
            &rig.upstream,
            &WriteRequest {
                body: &body,
                message: &message,
                revision: None,
                caller: &caller,
                outage: None,
                no_hold: false,
            },
            true,
        )
        .await;
    let reply: Value = serde_json::from_str(&report.reply.unwrap()).unwrap();
    assert_ne!(
        reply["result"]["structuredContent"]["outcome"],
        "accepted_pending"
    );
    assert!(entries(&rig).iter().all(|e| e["state"] != "pending"));
}

// ---- The send queue (slice 2B) ----

use super::queue::Halt;

const HOSTED_PENDING: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"outcome":"accepted_pending","canonical":false,"journal_entry":"hosted-entry","window_id":"window-1"},"isError":false}}"#;
const OUTBOX_NOT_READY: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"error_code":"OUTBOX_NOT_READY","retryable":true,"applied":false,"outcome":"not_sent"},"isError":true}}"#;

#[test]
fn hosted_outbox_answers_are_not_canonical_receipts_or_terminal_refusals() {
    assert_eq!(answer_of(Some(HOSTED_PENDING)), Answer::HostedPending);
    assert_eq!(answer_of(Some(OUTBOX_NOT_READY)), Answer::RetryableNotReady);
    for source in [HOSTED_PENDING, OUTBOX_NOT_READY] {
        let mut value: Value = serde_json::from_str(source).unwrap();
        let body = value["result"]
            .as_object_mut()
            .unwrap()
            .remove("structuredContent")
            .unwrap();
        value["result"]["content"] = json!([{"type":"text","text":body.to_string()}]);
        assert_eq!(answer_of(Some(&value.to_string())), answer_of(Some(source)));
    }
    for (status, expected) in [
        ("conflict", Answer::Refused),
        ("stale", Answer::Partial),
        ("rejected", Answer::Partial),
    ] {
        let reply = json!({"result":{"structuredContent":{"status":status},"isError":false}});
        assert_eq!(answer_of(Some(&reply.to_string())), expected);
    }
    assert_eq!(
        judge(&json!({"status":"rejected","act":42})),
        Some(Answer::Receipt)
    );
    // A generic retryable error must not acquire these stronger semantics.
    assert_eq!(
        judge(&json!({"retryable":true,"applied":false})),
        Some(Answer::Refused)
    );
    let gateway = json!({"error":{"data":{"http_status":503,"upstream_body":{
        "error_code":"OUTBOX_NOT_READY","retryable":true,"applied":false,"outcome":"not_sent"
    }}}});
    assert_eq!(
        answer_of(Some(&gateway.to_string())),
        Answer::RetryableNotReady
    );
}

#[tokio::test]
async fn hosted_pending_first_forward_survives_restart_and_repeats_reach_hosted() {
    let mut rig = Rig::new(fast()).await;
    let call = create(Some("hosted-first"), "body");
    rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
    let reply = forward_with(&rig, call.clone(), None).await;
    assert_eq!(reply["result"]["structuredContent"]["canonical"], false);
    let entry = by_key(&rig, "hosted-first");
    assert_eq!(entry["state"], "hosted_pending");
    assert_eq!(entry["hosted_journal_entry"], "hosted-entry");
    assert!(entry["arguments"].is_object());
    let node_id = entry["id"].clone();
    rig.restart(fast());
    let status = rig.gate.status(&Default::default());
    assert_eq!(
        status["held_writes"]["writes"][0]["state"],
        "hosted_pending"
    );
    assert_eq!(
        status["held_writes"]["writes"][0]["hosted_journal_entry"],
        "hosted-entry"
    );
    let before = rig.state().writes().len();
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(
        rig.state().writes().len(),
        before,
        "node does not replay hosted custody"
    );
    receipt(&forward_with(&rig, call, None).await);
    assert_eq!(rig.state().writes().len(), before + 1, "repeat asks hosted");
    let original = entries(&rig)
        .into_iter()
        .find(|e| e["id"] == node_id)
        .unwrap();
    assert_eq!(
        original["state"], "confirmed",
        "canonical retry resolves hosted custody"
    );
    assert_eq!(original["answer"], "receipt");
}

#[tokio::test]
async fn hosted_pending_does_not_resolve_an_earlier_uncertain_call() {
    let rig = Rig::new(fast()).await;
    let call = create(Some("hosted-uncertain"), "body");
    rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
    forward_with(&rig, call.clone(), None).await;
    let original = entry_id(&rig, "hosted-uncertain");
    rig.gate
        .journal
        .settle(&original, EntryState::Uncertain, None, None)
        .unwrap();
    rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
    forward_with(&rig, call.clone(), None).await;
    assert_eq!(
        rig.gate.journal.get(&original).unwrap().state,
        EntryState::Uncertain
    );
    receipt(&forward_with(&rig, call, None).await);
    assert_eq!(
        rig.gate.journal.get(&original).unwrap().state,
        EntryState::Confirmed
    );
}

#[tokio::test]
async fn legacy_cached_outbox_answers_are_reconciled_without_rewriting_history() {
    for cached in [HOSTED_PENDING, OUTBOX_NOT_READY] {
        let rig = Rig::new(fast()).await;
        let call = create(Some("legacy-outbox"), "body");
        hold_create(&rig, "legacy-outbox", "body").await;
        let original = entry_id(&rig, "legacy-outbox");
        rig.gate
            .journal
            .finish_held(
                &original,
                EntryState::Confirmed,
                Some("refused"),
                "legacy classifier".into(),
                Some(cached.into()),
                true,
                None,
            )
            .unwrap();
        let before = rig.state().writes().len();
        receipt(&forward_with(&rig, call, None).await);
        assert_eq!(
            rig.state().writes().len(),
            before + 1,
            "asks hosted instead of replaying legacy cache"
        );
        assert_eq!(
            rig.gate.journal.get(&original).unwrap().detail.as_deref(),
            Some("legacy classifier")
        );
    }
}

#[tokio::test]
async fn hosted_not_ready_keeps_node_custody_and_does_not_refuse_dependants() {
    let rig = Rig::new(fast()).await;
    let id = hold_create(&rig, "not-ready", "body").await["record_id"].clone();
    let dependent = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz",
        "arguments":{"id":id,"body_append":"tail","reason":"test dependent append","idempotency_key":"dependent"}});
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    pending(&forward_with(&rig, dependent, None).await);
    rig.state().script([Fault::Http(200, OUTBOX_NOT_READY)]);
    assert_eq!(drain(&rig).await, Halt::ReadOnly);
    let entry = by_key(&rig, "not-ready");
    assert_eq!(entry["state"], "pending");
    assert!(entry["reply"].is_null());
    assert!(!entry["in_flight"].as_bool().unwrap_or(false));
    assert_eq!(by_key(&rig, "dependent")["state"], "pending");
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 2);
    assert_eq!(by_key(&rig, "not-ready")["answer"], "receipt");
}

#[tokio::test]
async fn hosted_not_ready_on_first_forward_is_held_with_the_nodes_minted_key() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(200, OUTBOX_NOT_READY)]);
    let response = forward_with(&rig, create(None, "body"), None).await;
    let info = pending(&response);
    let key = info["idempotency_key"].as_str().unwrap();
    assert!(key.starts_with("node-"));
    assert_eq!(info["reason"], "deployment_read_only");
    assert_eq!(by_key(&rig, key)["state"], "pending");
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(
        rig.state().keys_sent(),
        vec![Some(key.to_owned()), Some(key.to_owned())]
    );
    assert_eq!(by_key(&rig, key)["answer"], "receipt");
}

#[tokio::test]
async fn hosted_pending_drain_is_not_delivered_and_blocks_queued_dependants() {
    let mut rig = Rig::new(fast()).await;
    let call = create(Some("hosted-drain"), "body");
    let id = hold_create(&rig, "hosted-drain", "body").await["record_id"].clone();
    let dependent = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz",
        "arguments":{"id":id,"body_append":"tail","reason":"test dependent append","idempotency_key":"dependent"}});
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    pending(&forward_with(&rig, dependent, None).await);
    rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
    assert_eq!(drain(&rig).await, Halt::ReadOnly);
    assert_eq!(by_key(&rig, "hosted-drain")["state"], "hosted_pending");
    assert!(by_key(&rig, "hosted-drain")["reply"].is_null());
    let before = rig.state().writes().len();
    rig.restart(fast());
    assert_eq!(drain(&rig).await, Halt::ReadOnly);
    assert_eq!(
        rig.state().writes().len(),
        before,
        "dependent never overtakes hosted custody"
    );
    receipt(&forward_with(&rig, call, None).await);
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(by_key(&rig, "dependent")["answer"], "receipt");
}

const DIFFERENT_INTENT: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"idempotency command identity was reused under a different resolved intent"}],"structuredContent":{"error":"idempotency command identity was reused under a different resolved intent","error_code":"idempotency_conflict"},"isError":true}}"#;

/// Hold a create (hosted is read-only for it) and return the node's answer.
async fn hold_create(rig: &Rig, key: &str, body: &str) -> Value {
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let reply = forward_with(rig, create(Some(key), body), None).await;
    pending(&reply).clone()
}

async fn drain(rig: &Rig) -> Halt {
    rig.gate.drain(&rig.upstream, None, None, None).await
}

fn by_key(rig: &Rig, key: &str) -> Value {
    entries(rig)
        .into_iter()
        .find(|e| e["idempotency_key"] == key)
        .unwrap_or_else(|| panic!("no entry for {key}"))
}

#[tokio::test]
async fn held_writes_are_sent_in_order_after_recovery_each_creating_one_record() {
    let rig = Rig::new(fast()).await;
    let mut ids = Vec::new();
    for n in 1..=3 {
        ids.push(
            hold_create(&rig, &format!("k{n}"), &format!("body {n}")).await["record_id"].clone(),
        );
    }
    let after_holds = rig.state().writes().len();
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);

    let started = Instant::now();
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert!(
        started.elapsed() >= Duration::from_millis(80),
        "two gaps of 40 ms between three sends"
    );
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 3);
    let sent = rig.state().writes()[after_holds..].to_vec();
    assert_eq!(sent.len(), 3, "each exactly once");
    let keys: Vec<_> = sent
        .iter()
        .map(|w| w["params"]["arguments"]["arguments"]["idempotency_key"].clone())
        .collect();
    assert_eq!(
        keys,
        vec![json!("k1"), json!("k2"), json!("k3")],
        "oldest first"
    );
    let sent_record_ids: Vec<_> = sent
        .iter()
        .map(|w| w["params"]["arguments"]["arguments"]["id"].clone())
        .collect();
    assert_eq!(sent_record_ids, ids, "the IDs the agent was given");
    // Same run key in the envelope as the original call.
    assert_eq!(sent[0]["params"]["arguments"]["run_key"], "run-xyz");
    for n in 1..=3 {
        let entry = by_key(&rig, &format!("k{n}"));
        assert_eq!(entry["state"], "confirmed");
        assert_eq!(entry["answer"], "receipt");
        assert!(entry["arguments"].is_null(), "settled: content dropped");
    }
    assert_eq!(
        rig.gate.status(&Default::default())["entry_counts"].get("pending"),
        None
    );
}

#[tokio::test]
async fn pending_writes_survive_a_restart_and_are_sent_after_it_in_order_exactly_once() {
    let mut rig = Rig::new(fast()).await;
    let mut ids = Vec::new();
    for n in 1..=3 {
        ids.push(
            hold_create(&rig, &format!("k{n}"), &format!("body {n}")).await["record_id"].clone(),
        );
    }
    let after_holds = rig.state().writes().len();
    rig.restart(fast());
    assert_eq!(
        rig.gate.status(&Default::default())["entry_counts"]["pending"],
        3
    );
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 3);
    let sent = rig.state().writes()[after_holds..].to_vec();
    let sent_ids: Vec<_> = sent
        .iter()
        .map(|w| w["params"]["arguments"]["arguments"]["id"].clone())
        .collect();
    assert_eq!(sent_ids, ids);
    // A second restart-and-drain sends nothing more.
    rig.restart(fast());
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().writes().len(), after_holds + 3);
}

#[tokio::test]
async fn a_repeat_gets_pending_then_the_original_receipt() {
    let rig = Rig::new(fast()).await;
    let info = hold_create(&rig, "k-repeat", "body").await;
    let repeat = create(Some("k-repeat"), "body");
    let again = forward_with(&rig, repeat.clone(), None).await;
    assert_eq!(pending(&again)["journal_entry"], info["journal_entry"]);

    assert_eq!(drain(&rig).await, Halt::Empty);
    let writes = rig.state().writes().len();
    let done = forward_with(&rig, repeat, None).await;
    assert_eq!(receipt(&done)["record_id"], "rec-1");
    assert_eq!(done["id"], 7, "addressed to the repeating request");
    assert_eq!(
        rig.state().writes().len(),
        writes,
        "answered from the journal"
    );
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_refusal_stops_only_its_dependants_and_is_never_dropped() {
    let rig = Rig::new(fast()).await;
    let a = hold_create(&rig, "k-a", "refused").await;
    let a_id = a["record_id"].as_str().unwrap().to_owned();
    // An append to A, an unrelated create, a link to A, and a create whose
    // home is A.
    let mut calls = vec![
        json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
            "id":a_id,"reason":"r","body_append":"more","idempotency_key":"k-b"}}),
        create(Some("k-c"), "unrelated"),
        json!({"executor":"records_write","operation":"manage_links.add","run_key":"run-xyz","arguments":{
            "source_id":"70110000-0000-4000-8000-0000000000e9","target_id":a_id,"relationship":"relates_to","idempotency_key":"k-d"}}),
    ];
    let mut inside = create(Some("k-e"), "inside");
    inside["arguments"]["home_id"] = json!(a_id);
    calls.push(inside);
    for call in calls {
        rig.state().script([Fault::Http(200, READ_ONLY)]);
        pending(&forward_with(&rig, call, None).await);
    }
    let after_holds = rig.state().writes().len();

    // Hosted refuses A when it is sent; everything else it takes.
    rig.state().script([Fault::Http(
        400,
        r#"{"error":"bad input","error_code":"invalid_params"}"#,
    )]);
    assert_eq!(drain(&rig).await, Halt::Empty);
    let sent = rig.state().writes()[after_holds..].to_vec();
    assert_eq!(
        sent.len(),
        2,
        "A, then the unrelated create; no dependant sent"
    );
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);

    let a_entry = by_key(&rig, "k-a");
    assert_eq!(a_entry["state"], "confirmed");
    assert_eq!(a_entry["answer"], "refused");
    assert_eq!(a_entry["arguments"]["body"], "refused", "content kept");
    assert_eq!(by_key(&rig, "k-c")["answer"], "receipt");
    for key in ["k-b", "k-d", "k-e"] {
        let entry = by_key(&rig, key);
        assert_eq!(entry["answer"], "refused", "{key}");
        assert_eq!(entry["refused_because"], a_entry["id"], "{key}");
        assert!(entry["arguments"].is_object(), "{key}: content kept");
    }

    // The agents hear it through their keyed repeats.
    let b = forward_with(
        &rig,
        json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
            "id":a_id,"reason":"r","body_append":"more","idempotency_key":"k-b"}}),
        None,
    )
    .await;
    assert_eq!(b["error"]["data"]["reason"], "depends_on_refused_write");
    assert_eq!(b["error"]["data"]["depends_on"], a_entry["id"]);
    let a_repeat = forward_with(&rig, create(Some("k-a"), "refused"), None).await;
    assert_eq!(a_repeat["error"]["data"]["http_status"], 400);
    assert_eq!(rig.state().writes().len(), after_holds + 2);
}

#[tokio::test]
async fn a_refused_create_many_refuses_writes_naming_any_of_its_records() {
    let rig = Rig::new(fast()).await;
    let many = json!({"executor":"records_write","operation":"create_many","run_key":"run-xyz","arguments":{
        "reason":"r","idempotency_key":"k-many","records":[
            {"type":"Document","kind":"note","name":"one"},
            {"type":"Document","kind":"note","name":"two"}]}});
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let info = pending(&forward_with(&rig, many, None).await).clone();
    let ids = info["record_ids"].as_array().unwrap().clone();
    for (key, id) in [("k-first", &ids[0]), ("k-second", &ids[1])] {
        rig.state().script([Fault::Http(200, READ_ONLY)]);
        let append = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
            "id":id,"reason":"r","body_append":"x","idempotency_key":key}});
        pending(&forward_with(&rig, append, None).await);
    }
    let after_holds = rig.state().writes().len();
    rig.state().script([Fault::Http(
        400,
        r#"{"error":"bad input","error_code":"invalid_params"}"#,
    )]);
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(
        rig.state().writes().len(),
        after_holds + 1,
        "only the create_many"
    );
    for key in ["k-first", "k-second"] {
        assert_eq!(by_key(&rig, key)["answer"], "refused", "{key}");
    }
}

#[tokio::test]
async fn a_dependant_of_a_dependant_is_refused_too_and_an_append_refusal_has_none() {
    let rig = Rig::new(fast()).await;
    let a = hold_create(&rig, "k-a", "a").await["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut b = create(Some("k-b"), "b");
    b["arguments"]["home_id"] = json!(a);
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let b_id = pending(&forward_with(&rig, b, None).await)["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let append = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
        "id":b_id,"reason":"r","body_append":"x","idempotency_key":"k-c"}});
    pending(&forward_with(&rig, append, None).await);
    rig.state().script([Fault::Http(
        400,
        r#"{"error":"bad input","error_code":"invalid_params"}"#,
    )]);
    drain(&rig).await;
    assert_eq!(by_key(&rig, "k-b")["answer"], "refused");
    assert_eq!(by_key(&rig, "k-c")["answer"], "refused");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn different_intent_on_a_resend_is_reported_as_already_applied_not_refused() {
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-first", "x").await;
    let a_id = by_key(&rig, "k-first")["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let append = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
        "id":a_id,"reason":"r","body_append":"y","idempotency_key":"k-after"}});
    pending(&forward_with(&rig, append, None).await);
    rig.state().script([Fault::Http(200, DIFFERENT_INTENT)]);
    assert_eq!(drain(&rig).await, Halt::Empty);

    let first = by_key(&rig, "k-first");
    assert_eq!(first["state"], "confirmed");
    assert_eq!(first["answer"], "already_applied");
    assert!(first["detail"]
        .as_str()
        .unwrap()
        .contains("already applied"));
    // Its dependant is not refused: the record exists.
    assert_eq!(by_key(&rig, "k-after")["answer"], "receipt");
    let repeat = forward_with(&rig, create(Some("k-first"), "x"), None).await;
    assert_eq!(
        repeat["result"]["structuredContent"]["outcome"],
        "already_applied"
    );
    assert_eq!(repeat["result"]["isError"], false);
}

#[tokio::test]
async fn the_queue_stops_and_keeps_everything_when_hosted_cannot_take_writes() {
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k1", "one").await;
    hold_create(&rig, "k2", "two").await;
    let after_holds = rig.state().writes().len();

    // Unreachable: stays pending, nothing lost.
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    assert_eq!(drain(&rig).await, Halt::Unreachable);
    assert_eq!(
        rig.state().writes().len(),
        after_holds + 1,
        "stops at the first"
    );
    assert_eq!(by_key(&rig, "k1")["state"], "pending");
    assert_eq!(by_key(&rig, "k1")["maybe_applied"], true);
    assert_eq!(by_key(&rig, "k2")["state"], "pending");

    // Still read-only.
    *rig.state().always.lock().unwrap() = Some(Fault::Http(200, READ_ONLY));
    assert_eq!(drain(&rig).await, Halt::ReadOnly);
    assert_eq!(by_key(&rig, "k1")["hold_reason"], "deployment_read_only");

    // Credentials refused says nothing about the write: not a refusal.
    *rig.state().always.lock().unwrap() = Some(Fault::Http(
        401,
        r#"{"error":"unauthorized","code":"auth_expired","outcome":"refused"}"#,
    ));
    assert_eq!(drain(&rig).await, Halt::Credentials(Some(401)));
    assert_eq!(by_key(&rig, "k1")["state"], "pending");
    assert_eq!(by_key(&rig, "k2")["state"], "pending");

    // Recovery: both go, in order, once each.
    *rig.state().always.lock().unwrap() = None;
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_new_write_waits_for_held_writes_and_queues_behind_a_stalled_backlog() {
    // Hosted recovered: the held write goes first, then the new one.
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-held", "held").await;
    let reply = forward_with(&rig, create(Some("k-new"), "new"), None).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-2");
    let keys: Vec<_> = rig
        .state()
        .keys_sent()
        .into_iter()
        .flatten()
        .filter(|k| k.starts_with("k-"))
        .collect();
    assert_eq!(
        keys,
        vec!["k-held", "k-held", "k-new"],
        "held write sent before the new one"
    );
    assert_eq!(by_key(&rig, "k-held")["state"], "confirmed");

    // Hosted still read-only: the new write is held behind, not sent ahead.
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-held", "held").await;
    *rig.state().always.lock().unwrap() = Some(Fault::Http(200, READ_ONLY));
    let reply = forward_with(&rig, create(Some("k-new"), "new"), None).await;
    let info = pending(&reply);
    assert_eq!(info["queue_position"], 2);
    assert_eq!(by_key(&rig, "k-new")["state"], "pending");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
    *rig.state().always.lock().unwrap() = None;
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert!(by_key(&rig, "k-held")["seq"].as_u64() < by_key(&rig, "k-new")["seq"].as_u64());
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn refused_held_writes_outlast_ordinary_retention_and_receipts_do_not() {
    let mut config = fast();
    config.retention = Duration::ZERO;
    let rig = Rig::new(config).await;
    hold_create(&rig, "k-bad", "bad").await;
    hold_create(&rig, "k-good", "good").await;
    rig.state().script([Fault::Http(
        400,
        r#"{"error":"bad input","error_code":"invalid_params"}"#,
    )]);
    drain(&rig).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    rig.gate.journal.prune();
    let left = entries(&rig);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["idempotency_key"], "k-bad");
}

#[tokio::test]
async fn the_background_queue_sends_held_writes_when_woken() {
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k1", "one").await;
    let queue = rig.gate.spawn_queue(rig.upstream.clone(), None);
    rig.gate.wake_queue();
    eventually(|| rig.state().created.load(Ordering::SeqCst) == 1).await;
    queue.abort();
}

#[tokio::test]
async fn a_healthy_online_create_without_an_id_succeeds_and_returns_the_minted_id() {
    let rig = Rig::new(fast()).await;
    rig.state().honour_ids.store(true, Ordering::SeqCst);
    let mut client = rig.connect();
    let reply = client.call(1, create(None, "online")).await;
    assert!(reply.get("error").is_none(), "{reply}");
    let record_id = receipt(&reply)["record_id"].as_str().unwrap().to_owned();

    // It is the ID the node chose before sending, and it is a valid one.
    let sent = rig.state().writes();
    assert_eq!(sent.len(), 1);
    assert_eq!(
        sent[0]["params"]["arguments"]["arguments"]["id"],
        json!(record_id)
    );
    let bytes = record_id.as_bytes();
    assert_eq!((record_id.len(), bytes[14]), (36, b'4'));
    assert!(matches!(bytes[19], b'8' | b'9' | b'a' | b'b'));
    let saved = entries(&rig);
    assert_eq!(saved[0]["state"], "confirmed");
    assert_eq!(saved[0]["record_id"], json!(record_id));
    assert!(rig.gate.status(&Default::default())["entry_counts"]
        .get("pending")
        .is_none());

    // And an agent that repeats the call with the node's key gets the same record.
    let key = rig.state().keys_sent()[0].clone().unwrap();
    let again = client.call(2, create(Some(&key), "online")).await;
    assert_eq!(receipt(&again)["record_id"], json!(record_id));
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
}

// ---- Status, bootstrap, disk floor, rollback (slice 2B) ----

fn create_in(run: &str, parent: Option<&str>, key: &str, name: &str) -> Value {
    let mut call = create(Some(key), "x");
    call["run_key"] = json!(run);
    if let Some(parent) = parent {
        call["parent_key"] = json!(parent);
    }
    call["arguments"]["name"] = json!(name);
    call
}

async fn hold_call(rig: &Rig, call: Value) -> Value {
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    pending(&forward_with(rig, call, None).await).clone()
}

async fn status_of(client: &mut Client, id: u64, filter: Value) -> Value {
    client.send(tool_call(id, "node_status", filter)).await;
    client.recv().await.unwrap()["result"]["structuredContent"].clone()
}

#[tokio::test]
async fn node_status_lists_held_sent_and_refused_writes_filtered_by_run_parent_and_state() {
    let rig = Rig::new(fast()).await;
    rig.state().honour_ids.store(true, Ordering::SeqCst);
    hold_call(&rig, create_in("run-a", Some("lead"), "k-a", "Alpha notes")).await;
    hold_call(&rig, create_in("run-b", Some("lead"), "k-b", "Bravo notes")).await;
    hold_call(&rig, create_in("run-c", None, "k-c", "Charlie notes")).await;
    let mut client = rig.connect();

    let all = status_of(&mut client, 1, json!({})).await;
    let held = &all["held_writes"];
    assert_eq!(held["matched"], 3);
    assert_eq!(held["counts"]["pending"], 3);
    let first = &held["writes"][0];
    assert_eq!(first["operation"], "create_record");
    assert_eq!(first["title"], "Alpha notes");
    assert_eq!(first["state"], "pending");
    assert_eq!(first["reason"], "deployment_read_only");
    assert!(first["accepted_at"].is_string());
    assert!(
        first.get("record_links").is_none(),
        "nothing exists yet to link to"
    );
    // Never a body.
    assert!(!all.to_string().contains("\"body\""));

    let by_run = status_of(&mut client, 2, json!({"run": "run-b"})).await;
    assert_eq!(by_run["held_writes"]["writes"][0]["title"], "Bravo notes");
    assert_eq!(by_run["held_writes"]["matched"], 1);
    let by_parent = status_of(&mut client, 3, json!({"parent_run": "lead"})).await;
    assert_eq!(by_parent["held_writes"]["matched"], 2);
    let none = status_of(
        &mut client,
        4,
        json!({"run": "run-b", "parent_run": "other"}),
    )
    .await;
    assert_eq!(none["held_writes"]["matched"], 0);
    let limited = status_of(&mut client, 5, json!({"limit": 1})).await;
    assert_eq!(limited["held_writes"]["shown"], 1);
    assert_eq!(limited["held_writes"]["matched"], 3);

    // Send two, refuse one (the second).
    rig.state().script([
        Fault::None_,
        Fault::Http(
            400,
            r#"{"error":"bad input","error_code":"invalid_params"}"#,
        ),
    ]);
    drain(&rig).await;
    let sent = status_of(&mut client, 6, json!({"state": "sent"})).await;
    assert_eq!(sent["held_writes"]["matched"], 2);
    let link = sent["held_writes"]["writes"][0]["record_links"][0]
        .as_str()
        .unwrap();
    assert!(link.starts_with("https://hosted.example/"), "{link}");
    let refused = status_of(&mut client, 7, json!({"state": ["refused"]})).await;
    assert_eq!(refused["held_writes"]["matched"], 1);
    assert_eq!(refused["held_writes"]["writes"][0]["title"], "Bravo notes");
    assert!(refused["held_writes"]["writes"][0]
        .get("record_links")
        .is_none());
    assert_eq!(refused["held_writes"]["counts"]["refused"], 1);
}

#[tokio::test]
async fn bootstrap_reports_held_writes_for_the_run_and_for_the_runs_it_started() {
    let rig = Rig::new(fast()).await;
    hold_call(&rig, create_in("child", Some("lead"), "k1", "Child note")).await;
    hold_call(&rig, create_in("lead", None, "k2", "Lead note")).await;
    let mut client = rig.connect();
    let bootstrap = |run: &str| tool_call(9, "bootstrap", json!({"run_key": run}));

    client.send(bootstrap("lead")).await;
    let lead = client.recv().await.unwrap();
    let held = &lead["result"]["structuredContent"]["node_held_writes"];
    assert_eq!(held["this_run"]["pending"], 1);
    assert_eq!(held["runs_it_started"]["pending"], 1);
    assert!(lead["result"]["content"]
        .to_string()
        .contains("Runs it started: 1 pending"));

    client.send(bootstrap("child")).await;
    let child = client.recv().await.unwrap();
    assert_eq!(
        child["result"]["structuredContent"]["node_held_writes"]["this_run"]["pending"],
        1
    );
    assert!(
        child["result"]["structuredContent"]["node_held_writes"]["runs_it_started"]
            .as_object()
            .unwrap()
            .is_empty()
    );

    // A fresh run still hears about the account's unresolved backlog.
    client.send(bootstrap("someone-else")).await;
    let other = client.recv().await.unwrap();
    assert_eq!(
        other["result"]["structuredContent"]["node_held_writes"]["account"]["waiting"],
        2
    );
    client.send(tool_call(10, "bootstrap", json!({}))).await;
    let fresh = client.recv().await.unwrap();
    assert_eq!(
        fresh["result"]["structuredContent"]["node_held_writes"]["account"]["counts"]["pending"],
        2
    );
    assert!(!fresh.to_string().contains("Child note"));
    assert!(!fresh.to_string().contains("Lead note"));
}

#[tokio::test]
async fn below_the_disk_floor_a_write_is_refused_as_not_sent_never_dropped() {
    let mut config = fast();
    config.disk_floor_bytes = 5_000;
    let rig = Rig::new(config).await;
    *rig.gate.free_override.lock().unwrap() = Some(1_000);

    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let reply = forward_with(&rig, create(Some("k1"), "low"), None).await;
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert_eq!(reply["error"]["data"]["reason"], "disk_floor");
    assert_eq!(reply["error"]["data"]["floor_bytes"], 5_000);
    assert_eq!(by_key(&rig, "k1")["state"], "not_sent");
    assert_eq!(rig.state().writes().len(), 1);
    assert_eq!(
        rig.gate.status(&Default::default())["disk"]["below_floor"],
        true
    );

    // A write that may already be in flight is not refused: it keeps its
    // arguments as an uncertain entry, as in slice 2A.
    rig.state().script([Fault::ApplyThenDrop]);
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let down = FakeOutage::new(true);
    let reply = forward_with(&rig, create(Some("k2"), "in flight"), Some(&down)).await;
    assert_eq!(reply["error"]["data"]["outcome"], "uncertain");
    assert!(by_key(&rig, "k2")["arguments"].is_object());
    *rig.state().always.lock().unwrap() = None;

    // Room again: held as usual.
    *rig.gate.free_override.lock().unwrap() = Some(50_000);
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let reply = forward_with(&rig, create(Some("k3"), "room"), None).await;
    pending(&reply);
}

#[tokio::test]
async fn the_floor_is_the_larger_of_the_setting_and_twice_the_local_copy() {
    let mut config = fast();
    config.disk_floor_bytes = 1_000;
    let rig = Rig::new(config).await;
    let copy = rig._temp.path().join("replica");
    fs::create_dir(&copy).unwrap();
    fs::write(copy.join("generation"), vec![0u8; 3_000]).unwrap();
    rig.gate.set_copy_root(copy);
    *rig.gate.free_override.lock().unwrap() = Some(5_000);
    let disk = rig.gate.status(&Default::default())["disk"].clone();
    assert_eq!(disk["local_copy_bytes"], 3_000);
    assert_eq!(disk["floor_bytes"], 6_000);
    assert_eq!(disk["configured_floor_bytes"], 1_000);
    assert_eq!(disk["free_bytes"], 5_000);
    assert_eq!(disk["below_floor"], true);
    // The real figure, with no override, is a number the filesystem reports.
    *rig.gate.free_override.lock().unwrap() = None;
    assert!(rig.gate.status(&Default::default())["disk"]["free_bytes"].is_u64());
}

#[tokio::test]
async fn status_shows_the_queue_and_warns_before_a_rollback() {
    let rig = Rig::new(fast()).await;
    let quiet = rig.gate.status(&Default::default());
    assert_eq!(quiet["queue"]["pending"], 0);
    assert!(quiet.get("rollback").is_none());
    hold_create(&rig, "k1", "one").await;
    hold_create(&rig, "k2", "two").await;
    let status = rig.gate.status(&Default::default());
    assert_eq!(status["queue"]["pending"], 2);
    assert!(status["queue"]["bytes"].as_u64().unwrap() > 0);
    assert!(status["queue"]["oldest_accepted_at"].is_string());
    assert!(status["rollback"]["warning"]
        .as_str()
        .unwrap()
        .contains("unrecognised"));
}

#[tokio::test]
async fn entries_in_a_state_this_build_does_not_know_are_shown_and_left_alone() {
    let mut rig = Rig::new(fast()).await;
    hold_create(&rig, "k-held", "one").await;
    // A newer build's state, as a rolled-back build would meet this one's.
    let path = rig.config.socket_directory.join("journal").join(format!(
        "{}.json",
        by_key(&rig, "k-held")["id"].as_str().unwrap()
    ));
    let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    saved["state"] = json!("quarantined");
    fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
    rig.restart(fast());

    let status = rig.gate.status(&Default::default());
    assert_eq!(status["entry_counts"]["unrecognised"], 1);
    assert_eq!(status["unrecognised"][0]["idempotency_key"], "k-held");
    assert!(status["unrecognised_note"]
        .as_str()
        .unwrap()
        .contains("leaves them alone"));
    let writes = rig.state().writes().len();
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().writes().len(), writes, "never sent");
    let again: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(again["state"], "quarantined");
}

// ---- A drained write that hosted refuses a key for ----

fn append_call(key: Option<&str>) -> Value {
    let mut arguments = json!({
        "id": "70110000-0000-4000-8000-0000000000e1",
        "reason": "r",
        "body_append": "more",
    });
    if let Some(key) = key {
        arguments["idempotency_key"] = json!(key);
    }
    json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":arguments})
}

fn is_keyed(request: &Value) -> bool {
    request
        .pointer("/params/arguments/arguments/idempotency_key")
        .is_some()
}

/// Hold an append the node keys itself (no caller key) and return its entry.
async fn hold_minted_append(rig: &Rig) -> Value {
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let info = pending(&forward_with(rig, append_call(None), None).await).clone();
    entries(rig)
        .into_iter()
        .find(|e| e["id"] == info["journal_entry"])
        .unwrap()
}

#[tokio::test]
async fn a_caller_supplied_key_is_never_dropped_whatever_hosted_says() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    pending(&forward_with(&rig, append_call(Some("k-mine")), None).await);
    let before = rig.state().writes().len();
    rig.state().script([Fault::RefuseKey]);
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(
        rig.state().writes().len(),
        before + 1,
        "sent once, with the key"
    );
    assert!(is_keyed(&rig.state().writes()[before]));
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
    let entry = by_key(&rig, "k-mine");
    assert_eq!(entry["answer"], "refused");
    assert_eq!(entry["idempotency_key"], "k-mine");
    // Hosted's own reason reaches the agent through the repeat.
    let again = forward_with(&rig, append_call(Some("k-mine")), None).await;
    assert!(again.to_string().contains("retry without a key"));
}

// ---- From #2364: the online path ----

#[tokio::test]
async fn a_refused_minted_key_is_dropped_and_the_call_sent_once_unkeyed() {
    // Hosted refuses a key on a live co-edit body route (and a few other
    // routes) before any effect and says to retry without one. The caller sent
    // no key, so the node must not trap it: drop its own key and send once.
    let rig = Rig::new(fast()).await;
    *rig.state().always.lock().unwrap() = Some(Fault::RefuseKey);
    let mut client = rig.connect();
    let reply = client.call(1, create(None, "live")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-1", "{reply}");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    let keys = rig.state().keys_sent();
    assert_eq!(keys.len(), 2);
    assert!(keys[0].as_deref().is_some_and(|k| k.starts_with("node-")));
    assert_eq!(keys[1], None, "the re-send carries no key");
    let entry = &entries(&rig)[0];
    assert_eq!(entry["state"], "confirmed");
    assert_eq!(entry["answer"], "receipt");
    assert!(entry["idempotency_key"].is_null());
    assert!(entry["key_origin"].is_null());
    assert_eq!(entry["attempts"], 2);
    // The contract still accepts a key: the next call is keyed again first.
    let reply = client.call(2, create(None, "again")).await;
    assert_eq!(receipt(&reply)["record_id"], "rec-2", "{reply}");
    assert_eq!(rig.state().keys_sent().len(), 4);
}

#[tokio::test]
async fn a_refused_caller_key_is_passed_back_not_dropped() {
    // The caller chose its key; only the caller may decide to drop it.
    let rig = Rig::new(fast()).await;
    *rig.state().always.lock().unwrap() = Some(Fault::RefuseKey);
    let mut client = rig.connect();
    let reply = client.call(1, create(Some("mine"), "live")).await;
    assert_eq!(reply["result"]["isError"], true, "{reply}");
    assert_eq!(rig.state().keys_sent(), vec![Some("mine".to_owned())]);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_minted_key_refused_after_a_lost_attempt_is_not_resent_unkeyed() {
    // The first attempt may have landed under the minted key, so an unkeyed
    // re-send could write twice: the outcome stays uncertain instead.
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::ApplyThenDrop, Fault::RefuseKey]);
    let mut client = rig.connect();
    let _ = client.call(1, create(None, "once")).await;
    assert_eq!(rig.state().keys_sent().len(), 2);
    assert!(rig.state().keys_sent().iter().all(Option::is_some));
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert_eq!(entries(&rig)[0]["state"], "uncertain");
}

#[tokio::test]
async fn a_lost_unkeyed_resend_is_uncertain_without_key_advice() {
    // The re-send has no key, so the node cannot offer one to retry with.
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::RefuseKey, Fault::ApplyThenDrop]);
    let mut client = rig.connect();
    let reply = client.call(1, create(None, "live")).await;
    assert_eq!(rig.state().keys_sent().len(), 2);
    assert_eq!(rig.state().keys_sent()[1], None);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert!(
        !reply.to_string().contains("idempotency_key=node-"),
        "{reply}"
    );
    let entry = &entries(&rig)[0];
    assert_eq!(entry["state"], "uncertain");
    assert!(entry["idempotency_key"].is_null());
}

#[test]
fn refuses_key_reads_hosteds_key_refusals_only() {
    let refusal = |error: &str| {
        json!({"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{"error":error},"isError":true}}).to_string()
    };
    for error in [
        "update_record: idempotency_key is not supported while a live editing session is routing this record's body; retry without a key",
        "enrolled update_record does not accept idempotency_key yet; retry without a key",
        "update_record: idempotency_key is supported on the SQLite engine only, not turso; retry without it",
        "manage_messages.share_history does not accept idempotency_key; retry without a key (it is already safe to repeat: a repeated share grants nothing twice)",
    ] {
        assert!(refuses_key(Some(&refusal(error))), "{error}");
    }
    for error in [
        "update_record: body_set must not be empty",
        "idempotency_key was reused for different intent",
        "retry without a key",
        "x: idempotency_key; retry without a key and then something else",
    ] {
        assert!(!refuses_key(Some(&refusal(error))), "{error}");
    }
    let ok = json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"error":"x idempotency_key; retry without a key"},"isError":false}});
    assert!(!refuses_key(Some(&ok.to_string())));
    assert!(!refuses_key(None));
}

#[tokio::test]
async fn status_filters_narrow_the_uncertain_list_too() {
    let mut config = fast();
    config.budget = Duration::from_millis(400);
    let rig = Rig::new(config).await;
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    for (run, parent, key) in [("run-a", "lead", "k-a"), ("run-b", "other", "k-b")] {
        let reply = forward_with(&rig, create_in(run, Some(parent), key, "n"), None).await;
        assert_eq!(reply["error"]["data"]["outcome"], "uncertain");
    }
    let all = rig.gate.status(&Default::default());
    assert_eq!(all["uncertain"].as_array().unwrap().len(), 2);
    let filter = |run: Option<&str>, parent: Option<&str>, states: &[&str]| StatusFilter {
        run: run.map(str::to_owned),
        parent_run: parent.map(str::to_owned),
        states: states.iter().map(|s| s.to_string()).collect(),
        limit: 10,
        newest_first: false,
    };
    let by_run = rig.gate.status(&filter(Some("run-a"), None, &[]));
    assert_eq!(by_run["uncertain"].as_array().unwrap().len(), 1);
    assert_eq!(by_run["uncertain"][0]["idempotency_key"], "k-a");
    let by_parent = rig.gate.status(&filter(None, Some("other"), &[]));
    assert_eq!(by_parent["uncertain"][0]["idempotency_key"], "k-b");
    let by_state = rig.gate.status(&filter(None, None, &["pending"]));
    assert!(by_state["uncertain"].as_array().unwrap().is_empty());
    let wanted = rig.gate.status(&filter(None, None, &["uncertain"]));
    assert_eq!(wanted["uncertain"].as_array().unwrap().len(), 2);
    // Counts stay whole.
    assert_eq!(by_state["entry_counts"]["uncertain"], 2);
}

#[tokio::test]
async fn a_write_that_merely_mentions_a_refused_records_id_is_not_refused() {
    let rig = Rig::new(fast()).await;
    let a = hold_create(&rig, "k-a", "a").await["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Same id appears only in free text: a body, a name, a reason.
    let mut mention = create(Some("k-mention"), &a);
    mention["arguments"]["name"] = json!(a);
    mention["arguments"]["reason"] = json!(a);
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    pending(&forward_with(&rig, mention, None).await);
    rig.state().script([Fault::Http(
        400,
        r#"{"error":"bad input","error_code":"invalid_params"}"#,
    )]);
    drain(&rig).await;
    assert_eq!(by_key(&rig, "k-a")["answer"], "refused");
    assert_eq!(by_key(&rig, "k-mention")["answer"], "receipt");
}

/// Persist a refusal the way the queue does, but stop there: as if the node
/// had died before refusing anything that depends on it.
fn refuse_only(rig: &Rig, key: &str) {
    let entry = by_key(rig, key);
    rig.gate
        .journal
        .finish_held(
            entry["id"].as_str().unwrap(),
            EntryState::Confirmed,
            Some("refused"),
            "hosted refused this write".into(),
            Some("{}".into()),
            true,
            None,
        )
        .unwrap();
}

#[tokio::test]
async fn dependants_of_a_refusal_are_refused_after_a_crash_and_when_they_arrive_later() {
    let mut rig = Rig::new(fast()).await;
    let a = hold_create(&rig, "k-a", "a").await["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // B is a create inside A; C appends to B.
    let mut b = create(Some("k-b"), "b");
    b["arguments"]["home_id"] = json!(a);
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let b_id = pending(&forward_with(&rig, b, None).await)["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let c = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
        "id":b_id,"reason":"r","body_append":"x","idempotency_key":"k-c"}});
    pending(&forward_with(&rig, c, None).await);
    let unrelated = hold_create(&rig, "k-free", "free").await;
    assert!(unrelated["record_id"].is_string());

    // The node dies after persisting A's refusal and nothing else.
    refuse_only(&rig, "k-a");
    rig.restart(fast());
    // D arrives later, after the refusal, naming A.
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let d = json!({"executor":"records_write","operation":"manage_links.add","run_key":"run-xyz","arguments":{
        "source_id":"70110000-0000-4000-8000-0000000000e9","target_id":a,"relationship":"relates_to","idempotency_key":"k-d"}});
    pending(&forward_with(&rig, d, None).await);
    let before = rig.state().writes().len();

    assert_eq!(drain(&rig).await, Halt::Empty);
    for key in ["k-b", "k-c", "k-d"] {
        let entry = by_key(&rig, key);
        assert_eq!(entry["answer"], "refused", "{key}");
        assert!(entry["refused_because"].is_string(), "{key}");
    }
    assert_eq!(
        by_key(&rig, "k-b")["refused_because"],
        by_key(&rig, "k-a")["id"]
    );
    assert_eq!(
        by_key(&rig, "k-c")["refused_because"],
        by_key(&rig, "k-b")["id"]
    );
    assert_eq!(by_key(&rig, "k-free")["answer"], "receipt");
    assert_eq!(
        rig.state().writes().len(),
        before + 1,
        "only the unrelated create was sent"
    );
}

const UNAUTHORIZED: &str = r#"{"error":"unauthorized","code":"auth_expired","outcome":"refused"}"#;

#[tokio::test]
async fn a_refused_credential_does_not_hold_a_new_write_or_let_it_overtake_the_backlog() {
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-old", "old").await;
    // The queue's send of the old write is refused for credentials. The new
    // write's own send would succeed (the credential has recovered), but it
    // must not be sent: it would commit ahead of the old one.
    rig.state().script([Fault::Http(401, UNAUTHORIZED)]);
    let before = rig.state().writes().len();
    let reply = forward_with(&rig, create(Some("k-new"), "new"), None).await;
    assert_ne!(
        reply["result"]["structuredContent"]["outcome"],
        "accepted_pending"
    );
    assert_eq!(reply["error"]["data"]["http_status"], 401);
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert_eq!(
        rig.state().writes().len(),
        before + 1,
        "only the queue's send went out"
    );
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
    assert_eq!(
        by_key(&rig, "k-old")["state"],
        "pending",
        "the old one still waits"
    );
    assert!(entries(&rig)
        .iter()
        .all(|e| e["idempotency_key"] != "k-new"));
    // Once the credential recovers, the old write goes first.
    assert_eq!(drain(&rig).await, Halt::Empty);
    let after = forward_with(&rig, create(Some("k-new"), "new"), None).await;
    assert_eq!(receipt(&after)["record_id"], "rec-2");
}

#[tokio::test]
async fn a_new_write_is_held_behind_the_backlog_only_for_what_hosted_is_doing_now() {
    // Old write held for an outage; hosted is now read-only: the new write is
    // held for read-only, not under the older reason.
    let rig = Rig::new(fast()).await;
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let down = FakeOutage::new(true);
    pending(&forward_with(&rig, create(Some("k-old"), "old"), Some(&down)).await);
    assert_eq!(by_key(&rig, "k-old")["hold_reason"], "hosted_unreachable");
    *rig.state().always.lock().unwrap() = Some(Fault::Http(200, READ_ONLY));
    let reply = forward_with(&rig, create(Some("k-new"), "new"), Some(&down)).await;
    assert_eq!(pending(&reply)["reason"], "deployment_read_only");
    assert_eq!(by_key(&rig, "k-new")["hold_reason"], "deployment_read_only");

    // The other way round: held for read-only, hosted now confirmed down.
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-old", "old").await;
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let reply = forward_with(&rig, create(Some("k-new"), "new"), Some(&down)).await;
    assert_eq!(pending(&reply)["reason"], "hosted_unreachable");
    assert_eq!(by_key(&rig, "k-new")["hold_reason"], "hosted_unreachable");

    // A failed send that the follow-up check does not confirm is not an
    // outage: the new write is not held and not sent ahead of the backlog.
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-old", "old").await;
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let up = FakeOutage::new(false);
    let before = rig.state().writes().len();
    let reply = forward_with(&rig, create(Some("k-new"), "new"), Some(&up)).await;
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert_eq!(
        rig.state().writes().len(),
        before + 1,
        "only the backlog's send was tried"
    );
    assert!(entries(&rig)
        .iter()
        .all(|e| e["idempotency_key"] != "k-new"));
}

#[tokio::test]
async fn a_holdable_write_that_starts_after_an_older_one_was_accepted_cannot_overtake_it() {
    let rig = Rig::new(fast()).await;
    // A is turned away as read-only and the node accepts it. Hosted then
    // recovers. B starts after A's reply, so it depends on A being first.
    rig.state().script([Fault::DelayedHttp(
        Duration::from_millis(100),
        200,
        READ_ONLY,
    )]);
    pending(&forward_with(&rig, create(Some("k-a"), "a"), None).await);
    let b = forward_with(&rig, create(Some("k-b"), "b"), None).await;
    assert_eq!(
        receipt(&b)["record_id"],
        "rec-2",
        "A was applied first, B second"
    );
    let order: Vec<_> = rig.state().keys_sent().into_iter().flatten().collect();
    assert_eq!(
        order,
        vec!["k-a", "k-a", "k-b"],
        "hosted saw A, A again, then B"
    );
    assert_eq!(by_key(&rig, "k-a")["state"], "confirmed");
}

#[tokio::test]
async fn a_live_write_does_not_start_while_the_queue_is_sending() {
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-a", "a").await;
    // The queue's send of A is slow and turned away; a live write arriving
    // meanwhile must wait for the drain, then find A still ahead of it.
    rig.state().script([Fault::DelayedHttp(
        Duration::from_millis(200),
        200,
        READ_ONLY,
    )]);
    let drainer = drain(&rig);
    let live = async {
        tokio::time::sleep(Duration::from_millis(60)).await;
        forward_with(&rig, create(Some("k-b"), "b"), None).await
    };
    let (_, b) = tokio::join!(drainer, live);
    assert_eq!(receipt(&b)["record_id"], "rec-2", "A first, then B");
    assert_eq!(by_key(&rig, "k-a")["state"], "confirmed");
}

#[tokio::test]
async fn concurrent_live_writes_on_a_healthy_hosted_run_in_parallel() {
    let mut config = fast();
    config.budget = Duration::from_secs(30);
    config.attempt_timeout = Duration::from_secs(15);
    let rig = Rig::new(config).await;
    // Hosted holds each request open until the other has arrived, so both
    // answer only if both were in flight together. One after the other, the
    // first would wait out the 10 s limit and fail.
    rig.state().script([Fault::Rendezvous, Fault::Rendezvous]);
    let (a, b) = tokio::join!(
        forward_with(&rig, create(Some("k-1"), "one"), None),
        forward_with(&rig, create(Some("k-2"), "two"), None),
    );
    assert!(a.get("error").is_none(), "{a}");
    assert!(b.get("error").is_none(), "{b}");
    assert_eq!(rig.state().rendezvous_arrived.load(Ordering::SeqCst), 2);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_write_refused_for_a_backlog_says_it_was_not_sent_and_may_be_retried() {
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-old", "old").await;
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let up = FakeOutage::new(false);
    let reply = forward_with(&rig, create(Some("k-new"), "new"), Some(&up)).await;
    let data = &reply["error"]["data"];
    assert_eq!(data["outcome"], "not_sent");
    assert_eq!(data["reason"], "backlog_pending");
    assert_eq!(data["retryable"], true);
    assert!(reply["error"]["message"]
        .as_str()
        .unwrap()
        .contains("safe to send the same call again"));
}

// ---- Crashes and honest replies around queue sends ----

fn entry_id(rig: &Rig, key: &str) -> String {
    by_key(rig, key)["id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_crash_during_a_keyed_send_means_possibly_applied_in_every_later_reply() {
    let mut rig = Rig::new(fast()).await;
    hold_create(&rig, "k-crash", "body").await;
    rig.gate
        .journal
        .begin_queue_send(&entry_id(&rig, "k-crash"))
        .unwrap();
    rig.restart(fast());
    let entry = by_key(&rig, "k-crash");
    assert_eq!(
        entry["state"], "pending",
        "resending with its key stays on the table"
    );
    assert_eq!(entry["maybe_applied"], true);
    assert!(entry["in_flight"].is_null());

    let again = forward_with(&rig, create(Some("k-crash"), "body"), None).await;
    assert_eq!(pending(&again)["may_already_be_applied"], true);
    assert!(again.to_string().contains("may already have been applied"));
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert_eq!(by_key(&rig, "k-crash")["state"], "confirmed");
}

#[tokio::test]
async fn an_oversize_receipt_is_not_kept_and_a_keyed_repeat_goes_to_hosted_with_its_key() {
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-big", "body").await;
    let big: &'static str = Box::leak(
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":{{"content":[{{"type":"text","text":"{}"}}],"structuredContent":{{"record_id":"rec-big"}},"isError":false}}}}"#,
            "x".repeat(300 * 1024)
        )
        .into_boxed_str(),
    );
    rig.state().script([Fault::Http(200, big)]);
    assert_eq!(drain(&rig).await, Halt::Empty);
    let entry = by_key(&rig, "k-big");
    assert_eq!(entry["answer"], "receipt");
    assert!(entry["reply"].is_null(), "too large to keep");
    let writes = rig.state().writes().len();
    let again = forward_with(&rig, create(Some("k-big"), "body"), None).await;
    assert_eq!(
        rig.state().writes().len(),
        writes + 1,
        "sent to hosted, keyed"
    );
    assert!(is_keyed(rig.state().writes().last().unwrap()));
    assert_eq!(receipt(&again)["record_id"], "rec-1");
}

#[tokio::test]
async fn a_pending_repeat_that_only_changes_response_mode_is_still_pending() {
    let rig = Rig::new(fast()).await;
    let held = hold_minted_append(&rig).await;
    let key = held["idempotency_key"].as_str().unwrap().to_owned();
    let mut verbose = append_call(None);
    verbose["arguments"]["idempotency_key"] = json!(key);
    verbose["arguments"]["response_mode"] = json!("verbose");
    let writes = rig.state().writes().len();
    let again = forward_with(&rig, verbose, None).await;
    assert_eq!(pending(&again)["journal_entry"], held["id"]);
    assert_eq!(rig.state().writes().len(), writes);
}

#[tokio::test]
async fn a_dependant_that_cannot_be_settled_stops_the_drain_instead_of_spinning() {
    use std::os::unix::fs::PermissionsExt;
    let rig = Rig::new(fast()).await;
    let a = hold_create(&rig, "k-a", "a").await["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let append = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
        "id":a,"reason":"r","body_append":"x","idempotency_key":"k-b"}});
    pending(&forward_with(&rig, append, None).await);
    refuse_only(&rig, "k-a");
    // Nothing can be written to the journal any more.
    let directory = rig.config.socket_directory.join("journal");
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
    let gate = rig.gate.clone();
    let upstream = rig.upstream.clone();
    // On its own thread, so that a drain that spins fails this test cleanly
    // instead of hanging it.
    let (done, result) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let _ = done.send(runtime.block_on(gate.drain(&upstream, None, None, None)));
    });
    let halted = result.recv_timeout(Duration::from_secs(5));
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(halted.expect("the drain stopped"), Halt::Local);
    assert_eq!(by_key(&rig, "k-b")["state"], "pending");
}

#[tokio::test]
async fn the_gates_own_open_path_applies_refusal_retention_to_startup_pruning() {
    let mut config = fast();
    config.retention = Duration::ZERO;
    config.refusal_retention = Duration::from_secs(3600);
    let mut rig = Rig::new(config.clone()).await;
    hold_create(&rig, "k-bad", "bad").await;
    hold_create(&rig, "k-good", "good").await;
    rig.state().script([Fault::Http(
        400,
        r#"{"error":"bad input","error_code":"invalid_params"}"#,
    )]);
    drain(&rig).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    // A restart goes through WriteGate::open, which prunes at startup.
    rig.restart(config);
    let left = entries(&rig);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0]["idempotency_key"], "k-bad");
}

// ---- A key hosted will not accept: the node does not send without it ----

#[tokio::test]
async fn hosted_refusing_a_minted_key_during_the_drain_is_a_refusal_and_never_an_unkeyed_resend() {
    let rig = Rig::new(fast()).await;
    let held = hold_minted_append(&rig).await;
    let key = held["idempotency_key"].as_str().unwrap().to_owned();
    let before = rig.state().writes().len();
    rig.state().script([Fault::RefuseKey]);
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(
        rig.state().writes().len(),
        before + 1,
        "sent once, with its key"
    );
    assert!(rig.state().writes().iter().all(is_keyed));
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);

    let entry = by_key(&rig, &key);
    assert_eq!(entry["state"], "confirmed");
    assert_eq!(entry["answer"], "refused");
    let detail = entry["detail"].as_str().unwrap();
    assert!(detail.contains("did not send it without one"), "{detail}");
    assert!(detail.contains("send it again without a key"), "{detail}");
    assert!(!detail.contains("may already have been applied"));
    assert!(
        entry["arguments"].is_object(),
        "kept for the refusal retention"
    );
    // Status, the keyed repeat and the bootstrap counts show it like any refusal.
    let status = rig.gate.status(&Default::default());
    assert_eq!(status["held_writes"]["counts"]["refused"], 1);
    let mut repeat = append_call(None);
    repeat["arguments"]["idempotency_key"] = json!(key);
    let again = forward_with(&rig, repeat, None).await;
    assert_eq!(again["result"]["isError"], true);
    assert!(again.to_string().contains("retry without a key"));
    assert_eq!(rig.state().writes().len(), before + 1);
    let note = rig.gate.note_held_writes(
        r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#,
        "run-xyz",
    );
    assert!(note.contains("1 refused"), "{note}");
}

#[tokio::test]
async fn a_key_refusal_on_a_possibly_applied_write_says_so() {
    let rig = Rig::new(fast()).await;
    // Applied, reply lost, hosted confirmed down: held, possibly applied.
    rig.state().script([Fault::ApplyThenDrop]);
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let down = FakeOutage::new(true);
    let info = pending(&forward_with(&rig, append_call(None), Some(&down)).await).clone();
    *rig.state().always.lock().unwrap() = None;
    let key = info["idempotency_key"].as_str().unwrap().to_owned();
    let before = rig.state().writes().len();
    rig.state().script([Fault::RefuseKey]);
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().writes().len(), before + 1, "no unkeyed resend");
    let entry = by_key(&rig, &key);
    assert_eq!(entry["answer"], "refused");
    assert!(entry["detail"]
        .as_str()
        .unwrap()
        .contains("may already have been applied"));
    let mut repeat = append_call(None);
    repeat["arguments"]["idempotency_key"] = json!(key);
    let again = forward_with(&rig, repeat, None).await;
    assert!(
        again.to_string().contains("may have been applied"),
        "{again}"
    );
}

#[tokio::test]
async fn a_key_refusal_refuses_the_dependants_of_a_create_like_any_refusal() {
    let rig = Rig::new(fast()).await;
    let a = hold_create(&rig, "k-a", "a").await["record_id"]
        .as_str()
        .unwrap()
        .to_owned();
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let append = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
        "id":a,"reason":"r","body_append":"x","idempotency_key":"k-b"}});
    pending(&forward_with(&rig, append, None).await);
    let before = rig.state().writes().len();
    rig.state().script([Fault::RefuseKey]);
    assert_eq!(drain(&rig).await, Halt::Empty);
    // The create is refused (create_record has no key refusal in the rig, so
    // refuse it as hosted would: keyed and refused), and B with it.
    assert_eq!(rig.state().writes().len(), before + 1);
    assert_eq!(by_key(&rig, "k-a")["answer"], "refused");
    assert_eq!(by_key(&rig, "k-b")["answer"], "refused");
    assert_eq!(
        by_key(&rig, "k-b")["refused_because"],
        by_key(&rig, "k-a")["id"]
    );
}

// ---- R3: honest replies after a lost outcome ----

#[tokio::test]
async fn possibly_applied_survives_a_lost_outcome_save_and_non_applying_answers() {
    let rig = Rig::new(fast()).await;
    // Hold a write that was applied with its reply lost.
    rig.state().script([Fault::ApplyThenDrop]);
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let down = FakeOutage::new(true);
    let info = pending(&forward_with(&rig, append_call(None), Some(&down)).await).clone();
    *rig.state().always.lock().unwrap() = None;
    let key = info["idempotency_key"].as_str().unwrap().to_owned();
    assert_eq!(by_key(&rig, &key)["maybe_applied"], true);

    // Another entry whose attempt was in flight when its outcome could not be
    // saved: it only has the marker on disk.
    let rig2 = Rig::new(fast()).await;
    let held = hold_minted_append(&rig2).await;
    let key2 = held["idempotency_key"].as_str().unwrap().to_owned();
    rig2.gate
        .journal
        .fail_after
        .store(1, std::sync::atomic::Ordering::SeqCst);
    rig2.state().script([Fault::DropBeforeApply]);
    assert_eq!(drain(&rig2).await, Halt::Local);
    let on_disk = by_key(&rig2, &key2);
    assert_eq!(on_disk["in_flight"], true);
    assert_ne!(
        on_disk["maybe_applied"], true,
        "the lost save left only the marker"
    );

    // The next attempt promotes the marker to maybe_applied in the write that
    // begins it, and a read-only answer must not clear it.
    rig2.state().script([Fault::Http(200, READ_ONLY)]);
    assert_eq!(drain(&rig2).await, Halt::ReadOnly);
    let after = by_key(&rig2, &key2);
    assert_eq!(after["maybe_applied"], true, "promoted, and kept");
    assert!(after["in_flight"].is_null());
    let mut repeat = append_call(None);
    repeat["arguments"]["idempotency_key"] = json!(key2);
    let pending_again = forward_with(&rig2, repeat.clone(), None).await;
    assert_eq!(pending(&pending_again)["may_already_be_applied"], true);

    // An auth refusal does not clear it either.
    rig2.state().script([Fault::Http(401, UNAUTHORIZED)]);
    assert_eq!(drain(&rig2).await, Halt::Credentials(Some(401)));
    assert_eq!(by_key(&rig2, &key2)["maybe_applied"], true);

    // And a final refusal still says the write may already have been applied.
    rig2.state().script([Fault::Http(
        400,
        r#"{"error":"bad input","error_code":"invalid_params"}"#,
    )]);
    assert_eq!(drain(&rig2).await, Halt::Empty);
    let refused = by_key(&rig2, &key2);
    assert_eq!(refused["answer"], "refused");
    assert_eq!(refused["maybe_applied"], true);
    assert!(refused["detail"]
        .as_str()
        .unwrap()
        .contains("may already have been applied"));
    let said = forward_with(&rig2, repeat, None).await;
    assert!(
        said.to_string().contains("may_already_be_applied"),
        "{said}"
    );
}

#[tokio::test]
async fn a_failed_save_while_settling_stops_the_drain_for_a_receipt_and_for_a_missing_request() {
    // A receipt that cannot be saved: Halt::Local, not on to the next entry,
    // and the entry is still pending (and marked in flight) on disk.
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-1", "one").await;
    hold_create(&rig, "k-2", "two").await;
    rig.gate
        .journal
        .fail_after
        .store(1, std::sync::atomic::Ordering::SeqCst);
    let before = rig.state().writes().len();
    assert_eq!(drain(&rig).await, Halt::Local);
    assert_eq!(
        rig.state().writes().len(),
        before + 1,
        "stopped after the first"
    );
    assert_eq!(by_key(&rig, "k-1")["state"], "pending");
    assert_eq!(by_key(&rig, "k-2")["state"], "pending");
    // Recovery: the first is seen as possibly applied, then both go.
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(by_key(&rig, "k-1")["maybe_applied"], true);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 2);

    // The early branch: an entry that lost its saved request is settled as
    // uncertain without a send. If that cannot be saved the drain stops too.
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-gone", "gone").await;
    hold_create(&rig, "k-next", "next").await;
    let id = entry_id(&rig, "k-gone");
    rig.gate.journal.update(&id, |e| e.envelope = None).unwrap();
    rig.gate
        .journal
        .fail_after
        .store(0, std::sync::atomic::Ordering::SeqCst);
    let before = rig.state().writes().len();
    assert_eq!(drain(&rig).await, Halt::Local);
    assert_eq!(rig.state().writes().len(), before, "nothing was sent");
    assert_eq!(
        by_key(&rig, "k-gone")["state"],
        "pending",
        "as it was on disk"
    );
    assert_eq!(by_key(&rig, "k-next")["state"], "pending");
    // Once it can be saved, it is uncertain and the drain goes on.
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(by_key(&rig, "k-gone")["state"], "uncertain");
    assert_eq!(by_key(&rig, "k-next")["state"], "confirmed");
}

#[tokio::test]
async fn a_backlog_credential_refusal_reports_the_real_status_or_none() {
    for status in [401u16, 403] {
        let rig = Rig::new(fast()).await;
        hold_create(&rig, "k-old", "old").await;
        rig.state().script([Fault::Http(status, UNAUTHORIZED)]);
        let reply = forward_with(&rig, create(Some("k-new"), "new"), None).await;
        assert_eq!(reply["error"]["data"]["http_status"], status, "{reply}");
        assert_eq!(reply["error"]["data"]["reason"], "credentials_refused");
    }
    // No usable credential at all: there was no status, so none is invented.
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-old", "old").await;
    fs::remove_file(&rig.config.credential_file).unwrap();
    let reply = forward_with(&rig, create(Some("k-new"), "new"), None).await;
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent");
    assert_eq!(reply["error"]["data"]["reason"], "credentials_unavailable");
    assert!(
        reply["error"]["data"].get("http_status").is_none(),
        "{reply}"
    );
}

#[tokio::test]
async fn a_repeat_that_changes_response_mode_after_the_receipt_is_pruned_gets_the_same_record() {
    let mut config = fast();
    config.retention = Duration::ZERO;
    let rig = Rig::new(config).await;
    rig.state().honour_ids.store(true, Ordering::SeqCst);
    let first = forward_with(&rig, create(None, "online"), None).await;
    let record_id = receipt(&first)["record_id"].as_str().unwrap().to_owned();
    let key = rig.state().keys_sent()[0].clone().unwrap();
    tokio::time::sleep(Duration::from_millis(10)).await;
    rig.gate.journal.prune();
    assert!(entries(&rig).is_empty(), "the receipt is gone");

    let mut repeat = create(Some(&key), "online");
    repeat["arguments"]["response_mode"] = json!("verbose");
    let again = forward_with(&rig, repeat, None).await;
    assert_eq!(receipt(&again)["record_id"], json!(record_id));
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    let sent = rig.state().writes();
    assert_eq!(
        sent[0]["params"]["arguments"]["arguments"]["id"],
        sent[1]["params"]["arguments"]["arguments"]["id"],
        "the same record ID was sent both times"
    );
}

#[tokio::test]
async fn a_framed_403_keeps_its_status_and_classification_on_the_backlog_path() {
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "k-old", "old").await;
    // A valid JSON-RPC error body: nothing in it says 403.
    rig.state().script([Fault::Http(
        403,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"forbidden"}}"#,
    )]);
    assert_eq!(drain(&rig).await, Halt::Credentials(Some(403)));
    assert_eq!(
        by_key(&rig, "k-old")["state"],
        "pending",
        "a credential problem is not a refusal"
    );
    rig.state().script([Fault::Http(
        403,
        r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"forbidden"}}"#,
    )]);
    let reply = forward_with(&rig, create(Some("k-new"), "new"), None).await;
    assert_eq!(reply["error"]["data"]["http_status"], 403, "{reply}");
    assert_eq!(reply["error"]["data"]["reason"], "credentials_refused");
}

/// Exercise the socket boundary the client sees, including a retry using the
/// node-minted key and a settled reply saved before this version of the node.
#[tokio::test]
async fn node_built_tool_replies_follow_the_callers_protocol_era() {
    for modern in [false, true] {
        let rig = Rig::new(fast()).await;
        let mut client = rig.connect();
        let message = |id, name: &str, args| {
            let mut call = tool_call(id, name, args);
            if modern {
                call["params"]["_meta"] = super::super::failover::probe_meta();
            }
            call
        };
        let check_result = |reply: &Value| {
            assert!(reply.get("error").is_none(), "{reply}");
            assert_eq!(reply["result"]["isError"], false, "{reply}");
            if modern {
                assert_eq!(reply["result"]["resultType"], "complete", "{reply}");
                assert!(reply["result"]["_meta"]["io.modelcontextprotocol/serverInfo"].is_object());
            } else {
                assert!(reply["result"].get("resultType").is_none(), "{reply}");
            }
        };
        rig.state().script([Fault::Http(200, READ_ONLY)]);
        client
            .send(message(1, "call_executor", create(None, "held")))
            .await;
        let first = client.recv().await.unwrap();
        check_result(&first);
        let info = pending(&first).clone();
        let key = info["idempotency_key"].as_str().unwrap();
        assert!(first["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(key));
        let repeat = create(Some(key), "held");
        client
            .send(message(2, "call_executor", repeat.clone()))
            .await;
        let again = client.recv().await.unwrap();
        check_result(&again);
        assert_eq!(pending(&again)["journal_entry"], info["journal_entry"]);
        assert_eq!(rig.state().writes().len(), 1, "pending retry never sends");

        client.send(message(3, "node_status", json!({}))).await;
        let status = client.recv().await.unwrap();
        check_result(&status);
        assert_eq!(status["result"]["structuredContent"]["queue"]["pending"], 1);

        client
            .send(message(4, "call_executor", create(Some(key), "changed")))
            .await;
        let conflict = client.recv().await.unwrap();
        assert_eq!(conflict["error"]["data"]["reason"], "idempotency_conflict");
        assert!(
            conflict.get("result").is_none(),
            "RPC errors are not tool results"
        );

        // A route refusal is also a JSON-RPC error, not a tools/call result.
        let mut refused = message(5, "call_executor", repeat.clone());
        refused["params"]["_meta"]["native/route"] = json!("unsupported");
        client.send(refused).await;
        let refused = client.recv().await.unwrap();
        assert_eq!(refused["error"]["data"]["outcome"], "not_sent");
        assert!(refused.get("result").is_none());

        rig.state().script([Fault::Http(200, DIFFERENT_INTENT)]);
        assert_eq!(drain(&rig).await, Halt::Empty);
        // Existing journals may contain an already-applied note without the
        // modern fields. Reframe it for this retry rather than replaying it raw.
        let entry = rig
            .gate
            .journal
            .settled_held_with_key("records_write", "create_record", key, None)
            .unwrap();
        rig.gate
            .journal
            .update(&entry.id, |saved| {
                let mut old: Value = serde_json::from_str(saved.reply.as_deref().unwrap()).unwrap();
                old["result"].as_object_mut().unwrap().remove("resultType");
                old["result"].as_object_mut().unwrap().remove("_meta");
                saved.reply = Some(old.to_string());
            })
            .unwrap();
        client.send(message(6, "call_executor", repeat)).await;
        let applied = client.recv().await.unwrap();
        check_result(&applied);
        assert_eq!(applied["id"], 6);
        assert_eq!(receipt(&applied)["outcome"], "already_applied");
        assert_eq!(receipt(&applied)["idempotency_key"], key);

        let mut notification = message(7, "call_executor", create(Some(key), "held"));
        notification.as_object_mut().unwrap().remove("id");
        client.send(notification).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.recv())
                .await
                .is_err(),
            "a settled retry notification must not reply"
        );

        const HOSTED_REPLY: &str = r#"{"jsonrpc":"2.0","id":8,"result":{"resultType":"complete","content":[{"type":"text","text":"original hosted receipt"}],"structuredContent":{"record_id":"hosted-record"},"_meta":{"hosted":"preserve"},"isError":false}}"#;
        rig.state().script([Fault::Http(200, HOSTED_REPLY)]);
        client
            .send(message(
                8,
                "call_executor",
                create(Some("fresh-hosted-key"), "new write"),
            ))
            .await;
        assert_eq!(
            client.recv().await.unwrap(),
            serde_json::from_str::<Value>(HOSTED_REPLY).unwrap(),
            "hosted result fields must remain untouched"
        );
    }
}

/// Run one call through the gate with the saver no-hold opt-out set.
async fn forward_no_hold(rig: &Rig, arguments: Value, outage: Option<&dyn Outage>) -> Value {
    let message = tool_call(7, "call_executor", arguments);
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    let report = rig
        .gate
        .forward(
            &rig.upstream,
            &WriteRequest {
                body: &body,
                message: &message,
                revision: None,
                caller: &caller,
                outage,
                no_hold: true,
            },
            true,
        )
        .await;
    serde_json::from_str(&report.reply.expect("a reply")).unwrap()
}

const HTTP_MAINTENANCE: &str = r#"{"error":"this Native deployment is temporarily read-only","error_code":"DEPLOYMENT_READ_ONLY","applied":false,"retryable":true,"retry_after_secs":30,"recovery":"This write was not applied or queued"}"#;

#[tokio::test]
async fn http_maintenance_without_holding_preserves_refusal_and_prior_uncertainty() {
    for earlier_attempt in [false, true] {
        let rig = Rig::new(fast()).await;
        if earlier_attempt {
            rig.state().script([Fault::ApplyThenDrop]);
        }
        rig.state().script([Fault::Http(503, HTTP_MAINTENANCE)]);
        let reply = forward_no_hold(&rig, create(Some("maintenance-key"), "step"), None).await;
        let data = &reply["error"]["data"];
        assert_eq!(data["outcome"], "refused");
        assert_eq!(data["applied"], false);
        assert_eq!(data["retryable"], true);
        assert_eq!(data["retry_after_secs"], 30);
        assert_eq!(
            data["upstream_body"],
            serde_json::from_str::<Value>(HTTP_MAINTENANCE).unwrap()
        );
        assert_eq!(
            rig.state().writes().len(),
            if earlier_attempt { 2 } else { 1 }
        );
        assert_eq!(
            rig.state().created.load(Ordering::SeqCst),
            usize::from(earlier_attempt)
        );
        assert_eq!(
            entries(&rig)[0]["state"],
            if earlier_attempt {
                "uncertain"
            } else {
                "confirmed"
            }
        );
        assert_eq!(rig.gate.status(&Default::default())["queue"]["pending"], 0);
        if earlier_attempt {
            assert_eq!(data["node_journal"]["outcome"], "uncertain");
            assert_eq!(data["node_journal"]["idempotency_key"], "maintenance-key");
        } else {
            assert!(data.get("node_journal").is_none());
        }
        let verdict = super::super::session_writer::GateVerdict {
            auth_refused: false,
            attempt: super::super::session_writer::AttemptClass::Answered,
            reply: Some(reply.to_string()),
            http_status: Some(503),
        };
        assert_eq!(
            super::super::session_writer::classify_send(&verdict),
            if earlier_attempt {
                super::super::session_writer::SendClass::Uncertain
            } else {
                super::super::session_writer::SendClass::NotSent
            }
        );
    }
}

#[tokio::test]
async fn ambiguous_http_maintenance_bodies_stay_uncertain_without_holding() {
    for body in [
        r#"{"error":"transient","retryable":true}"#,
        r#"{"error_code":"DEPLOYMENT_READ_ONLY","applied":"partial","retryable":true}"#,
        r#"{"error_code":"DEPLOYMENT_READ_ONLY","outcome":"unknown","retryable":true}"#,
        r#"{"error_code":"DEPLOYMENT_READ_ONLY","applied":false,"partial":true}"#,
        r#"{"applied":false,"error":{"error_code":"DEPLOYMENT_READ_ONLY","outcome":"unknown"}}"#,
        r#"{"partial":true,"error":{"code":"DEPLOYMENT_READ_ONLY","applied":false}}"#,
        r#"{"applied":true,"error":{"code":"DEPLOYMENT_READ_ONLY","applied":false}}"#,
        r#"{"outcome":"refused","applied":true,"error":{"code":"DEPLOYMENT_READ_ONLY","applied":false}}"#,
    ] {
        let rig = Rig::new(fast()).await;
        rig.state().script([Fault::Http(503, body)]);
        let reply =
            forward_no_hold(&rig, create(Some("ambiguous-maintenance"), "step"), None).await;
        assert_eq!(entries(&rig)[0]["state"], "uncertain", "{body}: {reply}");
        assert_eq!(
            reply["error"]["data"]["node_journal"]["outcome"], "uncertain",
            "{body}: {reply}"
        );
        let verdict = super::super::session_writer::GateVerdict {
            auth_refused: false,
            attempt: super::super::session_writer::AttemptClass::Answered,
            reply: Some(reply.to_string()),
            http_status: Some(503),
        };
        assert_eq!(
            super::super::session_writer::classify_send(&verdict),
            super::super::session_writer::SendClass::Uncertain,
            "{body}: {reply}"
        );
        assert!(
            !reply["error"]["message"]
                .as_str()
                .unwrap()
                .contains("not applied or queued"),
            "{body}: {reply}"
        );
        assert_eq!(
            reply["error"]["data"]["upstream_body"],
            serde_json::from_str::<Value>(body).unwrap()
        );
        assert_eq!(rig.gate.status(&Default::default())["queue"]["pending"], 0);
    }
}

#[tokio::test]
async fn no_hold_flag_never_holds_on_read_only() {
    // Same fault that holds an ordinary write (cf.
    // read_only_holds_each_listed_write_...): the flagged write must not be
    // held. It is sent once and hosted's answer passes through.
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let reply = forward_no_hold(&rig, create(None, "saver step"), None).await;
    assert_ne!(
        reply["result"]["structuredContent"].get("outcome"),
        Some(&json!("accepted_pending")),
        "flagged write must not be held: {reply}"
    );
    assert_eq!(rig.state().writes().len(), 1, "sent once, never retried");
    let sent_key = rig.state().keys_sent()[0].clone();
    assert!(
        sent_key
            .as_deref()
            .is_some_and(|key| key.starts_with("node-")),
        "unknown contract still mints the node key; never silently unkeyed"
    );
    let status = rig.gate.status(&Default::default());
    assert_eq!(
        status["queue"]["pending"], 0,
        "nothing enters the held queue"
    );
}

#[tokio::test]
async fn no_hold_flag_reports_not_sent_when_hosted_unreachable() {
    // An outage that would hold an ordinary write instead reports not-sent
    // for a flagged one, with nothing queued.
    let rig = Rig::new(fast()).await;
    let down = FakeOutage::new(true);
    down.known.store(true, Ordering::SeqCst);
    // Persistent fault: every attempt drops before applying, so in-call
    // retries exhaust the budget without ever reaching hosted.
    *rig.state().always.lock().unwrap() = Some(Fault::DropBeforeApply);
    let reply = forward_no_hold(&rig, create(None, "saver step"), Some(&down)).await;
    assert_eq!(
        reply["error"]["data"]["outcome"], "not_sent",
        "unreachable flagged write reports not-sent: {reply}"
    );
    // Short-circuited before any send: nothing reached hosted, nothing was
    // journaled (the caller's own spool owns the key and the retry), and
    // nothing entered the held queue.
    assert!(rig.state().writes().is_empty(), "nothing sent while down");
    assert!(entries(&rig).is_empty(), "nothing journaled");
    let status = rig.gate.status(&Default::default());
    assert_eq!(
        status["queue"]["pending"], 0,
        "nothing enters the held queue"
    );
}

#[tokio::test]
async fn no_hold_flag_preserves_a_caller_supplied_key() {
    // The caller's bytes are forwarded unchanged: a caller key survives the
    // no-hold path untouched (prepare_key only mints when absent).
    let rig = Rig::new(fast()).await;
    rig.state().describe_fails.store(true, Ordering::SeqCst);
    rig.state().script([Fault::DropBeforeApply]);
    let reply = forward_no_hold(&rig, create(Some("k-caller"), "saver step"), None).await;
    assert!(reply.get("error").is_none(), "{reply}");
    let keys = rig.state().keys_sent();
    assert!(!keys.is_empty());
    assert!(
        keys.iter().all(|key| key.as_deref() == Some("k-caller")),
        "caller key preserved on every attempt: {keys:?}"
    );
}

#[tokio::test]
async fn gate_injects_no_run_or_intent_on_the_saver_path() {
    // The saver persistence contract (design §6.1) requires that no run key
    // and no declared intent reach hosted on any attempt or writer. The gate
    // must forward the caller's bytes (plus a key) without adding either.
    let rig = Rig::new(fast()).await;
    let arguments = json!({"executor":"records_write","operation":"create_record","arguments":{
        "type":"Document","kind":"note","reason":"Saved agent session step","body":"step"}});
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let _ = forward_no_hold(&rig, arguments, None).await;
    assert_eq!(rig.state().writes().len(), 1);
    let sent = &rig.state().writes()[0];
    let envelope = sent
        .pointer("/params/arguments")
        .cloned()
        .unwrap_or(Value::Null);
    assert!(
        envelope.get("run_key").is_none(),
        "gate must not inject run_key: {sent}"
    );
    assert!(
        envelope.get("parent_key").is_none(),
        "gate must not inject parent_key: {sent}"
    );
    assert!(
        envelope.get("intent").is_none(),
        "gate must not inject intent: {sent}"
    );
}

#[tokio::test]
async fn kernel_v2_upstream_refuses_holding_and_preserves_old_pending_writes() {
    let rig = Rig::new(fast()).await;
    // Establish a genuine pending v1 write, then change upstream engine.
    hold_create(&rig, "v1-before-cutover", "retained").await;
    assert_eq!(rig.gate.status(&Default::default())["queue"]["pending"], 1);
    let sent_before = rig.state().writes().len();
    rig.gate.set_kernel_v2_upstream(true);
    assert_eq!(
        rig.gate.drain(&rig.upstream, None, None, None).await,
        queue::Halt::EngineV2
    );
    assert_eq!(
        rig.state().writes().len(),
        sent_before,
        "v1 envelope never replayed into v2"
    );
    let down = FakeOutage::new(true);
    down.known.store(true, Ordering::SeqCst);
    let reply = forward_with(&rig, create(Some("v2-refused"), "new"), Some(&down)).await;
    assert_eq!(reply["error"]["data"]["outcome"], "not_sent", "{reply}");
    assert_eq!(rig.state().writes().len(), sent_before);
    let status = rig.gate.status(&Default::default());
    assert_eq!(status["holding"]["supported"], false);
    assert_eq!(
        status["holding"]["reason"],
        "kernel_v2_upstream_drain_first"
    );
    assert_eq!(
        status["queue"]["pending"], 1,
        "retained for explicit resolution or rollback"
    );
}

#[tokio::test]
async fn database_freeze_refusal_enters_the_existing_node_hold_path() {
    let dir = tempfile::tempdir().unwrap();
    let store = crate::mcp::database_freeze::DatabaseFreezeStore::new(dir.path());
    store.freeze("hq").await.unwrap();
    let barrier =
        crate::mcp::DeploymentMutationBarrier::default().with_database_freezes(dir.path());
    let error = barrier
        .for_database("hq")
        .admit(
            &crate::DeploymentReadOnlyOperation::server("create_record"),
            crate::mcp::OperationAccess::Mutation,
        )
        .unwrap_err();
    let result = crate::mcp::hosted_protocol::call_error_content(&error, Value::Null, None);
    assert_eq!(result["structuredContent"]["retry_after_secs"], 30);
    let reply = json!({"jsonrpc":"2.0","id":1,"result":result}).to_string();
    // This test harness scripts static HTTP bodies; retain this single bounded
    // generated refusal for the fixture's lifetime.
    let reply = Box::leak(reply.into_boxed_str());
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(200, reply)]);
    let mut client = rig.connect();
    let reply = client.call(1, create(None, "held during HQ cutover")).await;
    let info = pending(&reply);
    assert_eq!(info["reason"], "deployment_read_only");
    assert_eq!(info["may_already_be_applied"], false);
    assert_eq!(entries(&rig)[0]["hold_reason"], "deployment_read_only");
    assert_eq!(
        rig.state().writes().len(),
        1,
        "refusal must not trigger an immediate retry"
    );
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicate_gate_engine_error_settles_as_refused_never_a_receipt() {
    let detail = json!({"code":"likely_duplicate", "applied":false, "outcome":"refused",
        "message":"Nothing was created.", "candidates":[{"id":"existing"}]});
    let reply = json!({"result":{"isError":true,
        "structuredContent":{"error":detail.to_string()},
        "content":[{"type":"text", "text":detail.to_string()}]}});
    assert_eq!(answer_of(Some(&reply.to_string())), Answer::Refused);
}

// ---- Hosted custody settlement ----

fn hosted_status(rig: &Rig, key: &str, phase: &str, ancestor: Option<&str>) -> Value {
    let entry = by_key(rig, key);
    json!({"isError":false,"content":[],"structuredContent":{"entries":[{
        "journal_entry":entry["hosted_journal_entry"],"idempotency_key":key,
        "run_key":entry["run_key"],"status":phase,
        "terminal_at":if matches!(phase,"applied"|"refused"|"dependency_failed") {json!(123)} else {Value::Null},
        "refusal":matches!(phase,"refused"|"dependency_failed"),
        "outcome_reason":"safe hosted reason","dependency_failed_because":ancestor
    }]}})
}

async fn hosted_create(rig: &Rig, key: &str, handle: &str) {
    rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
    forward_with(rig, create(Some(key), "kept draft"), None).await;
    let id = entry_id(rig, key);
    rig.gate
        .journal
        .hosted_pending(&id, Some(handle.into()))
        .unwrap();
}

#[tokio::test]
async fn hosted_settlement_four_trial_outcomes_survive_restart_without_replaying_writes() {
    let mut rig = Rig::new(fast()).await;
    for (key, handle) in [
        ("expired", "hosted-a"),
        ("refused", "hosted-b"),
        ("dependent", "hosted-c"),
        ("applied-b", "hosted-d"),
    ] {
        hosted_create(&rig, key, handle).await;
    }
    for (key, handle, phase, ancestor) in [
        ("expired", "hosted-a", "refused", None),
        ("refused", "hosted-b", "refused", None),
        (
            "dependent",
            "hosted-c",
            "dependency_failed",
            Some("hosted-b"),
        ),
        ("applied-b", "hosted-d", "applied", None),
    ] {
        rig.state()
            .outcomes
            .lock()
            .unwrap()
            .insert(handle.into(), hosted_status(&rig, key, phase, ancestor));
    }
    let before = rig.state().writes().len();
    rig.restart(fast());
    rig.gate.settle_hosted_batch(&rig.upstream).await;
    assert_eq!(
        rig.state().writes().len(),
        before,
        "background only reads status"
    );
    assert_eq!(rig.state().status_reads.lock().unwrap().len(), 4);
    {
        let entry = by_key(&rig, "applied-b");
        assert_eq!(entry["state"], "confirmed");
        assert_eq!(entry["answer"], "receipt");
        assert!(entry["arguments"].is_null());
        assert!(
            entry["reply"].is_null(),
            "status is not the original operation receipt"
        );
    }
    for key in ["expired", "refused", "dependent"] {
        let entry = by_key(&rig, key);
        assert_eq!(entry["answer"], "refused");
        assert_eq!(entry["arguments"]["body"], "kept draft");
    }
    assert_eq!(
        by_key(&rig, "dependent")["refused_because"],
        by_key(&rig, "refused")["id"]
    );
    let status = rig.gate.status(&Default::default());
    assert_eq!(status["held_writes"]["counts"]["sent"], 1);
    assert_eq!(status["held_writes"]["counts"]["refused"], 3);
    assert!(!status.to_string().contains("kept draft"));
    rig.restart(fast());
    rig.gate.settle_hosted_batch(&rig.upstream).await;
    assert_eq!(
        rig.state().status_reads.lock().unwrap().len(),
        4,
        "settled entries stop polling"
    );
    assert_eq!(by_key(&rig, "dependent")["answer"], "refused");
}

#[tokio::test]
async fn hosted_settlement_failed_or_mismatched_status_never_loses_custody() {
    let rig = Rig::new(fast()).await;
    hosted_create(&rig, "status-check", "hosted-status").await;
    let correct = hosted_status(&rig, "status-check", "applied", None);
    let mut bad = Vec::new();
    bad.push(json!({"isError":true,"structuredContent":{"entries":correct["structuredContent"]["entries"]}}));
    bad.push(json!({"isError":false,"structuredContent":{"entries":[]}}));
    for (field, value) in [
        ("journal_entry", json!("wrong")),
        ("idempotency_key", json!("wrong")),
        ("run_key", json!("other-run")),
        ("status", json!("unknown")),
        ("terminal_at", Value::Null),
        ("refusal", json!(true)),
    ] {
        let mut result = correct.clone();
        result["structuredContent"]["entries"][0][field] = value;
        bad.push(result);
    }
    for phase in ["pending", "sending", "uncertain"] {
        bad.push(hosted_status(&rig, "status-check", phase, None));
    }
    for status in bad {
        rig.state()
            .outcomes
            .lock()
            .unwrap()
            .insert("hosted-status".into(), status);
        rig.gate.settle_hosted_batch(&rig.upstream).await;
        let entry = by_key(&rig, "status-check");
        assert_eq!(entry["state"], "hosted_pending");
        assert!(entry["arguments"].is_object());
    }
    // Legacy text-only success is also an explicit status response.
    rig.state().outcomes.lock().unwrap().insert("hosted-status".into(),json!({"isError":false,"content":[{"type":"text","text":correct["structuredContent"].to_string()}]}));
    rig.gate.settle_hosted_batch(&rig.upstream).await;
    assert_eq!(by_key(&rig, "status-check")["answer"], "receipt");
}

#[tokio::test]
async fn hosted_settlement_same_key_pending_checks_reuse_one_entry_and_original_arguments() {
    let rig = Rig::new(fast()).await;
    hosted_create(&rig, "repeat-custody", "hosted-repeat").await;
    let original = by_key(&rig, "repeat-custody");
    for _ in 0..3 {
        rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
        let response = forward_with(&rig, create(Some("repeat-custody"), "kept draft"), None).await;
        assert_eq!(response["result"]["structuredContent"]["canonical"], false);
        assert_eq!(entries(&rig).len(), 1);
        assert_eq!(
            by_key(&rig, "repeat-custody")["arguments"],
            original["arguments"]
        );
    }
    receipt(&forward_with(&rig, create(Some("repeat-custody"), "kept draft"), None).await);
    assert_eq!(entries(&rig).len(), 1);
    assert_eq!(by_key(&rig, "repeat-custody")["answer"], "receipt");
    for request in rig.state().writes() {
        assert_eq!(
            request["params"]["arguments"]["arguments"],
            original["arguments"]
        );
    }
}

#[tokio::test]
async fn hosted_settlement_same_key_refusal_is_checked_and_saved_in_original_slot() {
    let rig = Rig::new(fast()).await;
    hosted_create(&rig, "repeat-refusal", "hosted-refusal").await;
    rig.state().outcomes.lock().unwrap().insert(
        "hosted-refusal".into(),
        hosted_status(&rig, "repeat-refusal", "refused", None),
    );
    rig.state().script([Fault::Http(200, OUTBOX_NOT_READY)]);
    let reply = forward_with(&rig, create(Some("repeat-refusal"), "kept draft"), None).await;
    assert_eq!(reply["result"]["structuredContent"]["needs_you"], true);
    assert_eq!(entries(&rig).len(), 1);
    assert_eq!(by_key(&rig, "repeat-refusal")["answer"], "refused");
    let before = rig.state().writes().len();
    let repeated = forward_with(&rig, create(Some("repeat-refusal"), "kept draft"), None).await;
    assert_eq!(repeated["result"]["isError"], true);
    assert_eq!(rig.state().writes().len(), before);
}

#[tokio::test]
async fn hosted_settlement_releases_or_refuses_queued_dependants_from_hosted_create() {
    for phase in ["applied", "refused"] {
        let rig = Rig::new(fast()).await;
        let record = hold_create(&rig, "parent", "kept draft").await["record_id"].clone();
        let child = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{"id":record,"body_append":"tail","reason":"test","idempotency_key":"child"}});
        rig.state().script([Fault::Http(200, READ_ONLY)]);
        pending(&forward_with(&rig, child, None).await);
        rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
        assert_eq!(drain(&rig).await, Halt::ReadOnly);
        rig.state().outcomes.lock().unwrap().insert(
            "hosted-entry".into(),
            hosted_status(&rig, "parent", phase, None),
        );
        let before = rig.state().writes().len();
        rig.gate.settle_hosted_batch(&rig.upstream).await;
        assert_eq!(drain(&rig).await, Halt::Empty);
        let child = by_key(&rig, "child");
        if phase == "applied" {
            assert_eq!(child["answer"], "receipt");
            assert_eq!(rig.state().writes().len(), before + 1);
        } else {
            assert_eq!(child["answer"], "refused");
            assert_eq!(child["refused_because"], by_key(&rig, "parent")["id"]);
            assert_eq!(rig.state().writes().len(), before);
        }
    }
}

#[tokio::test]
async fn hosted_settlement_journal_failure_retains_request_and_retries_after_repair() {
    let rig = Rig::new(fast()).await;
    hosted_create(&rig, "disk-failure", "hosted-disk").await;
    rig.state().outcomes.lock().unwrap().insert(
        "hosted-disk".into(),
        hosted_status(&rig, "disk-failure", "applied", None),
    );
    rig.gate.journal.fail_after.store(0, Ordering::SeqCst);
    rig.gate.settle_hosted_batch(&rig.upstream).await;
    assert_eq!(by_key(&rig, "disk-failure")["state"], "hosted_pending");
    rig.gate.settle_hosted_batch(&rig.upstream).await;
    assert_eq!(by_key(&rig, "disk-failure")["answer"], "receipt");
}

#[tokio::test]
async fn hosted_settlement_background_loop_runs_with_empty_node_queue() {
    let rig = Rig::new(fast()).await;
    hosted_create(&rig, "background", "hosted-background").await;
    rig.state().outcomes.lock().unwrap().insert(
        "hosted-background".into(),
        hosted_status(&rig, "background", "applied", None),
    );
    let task = rig.gate.spawn_queue(rig.upstream.clone(), None);
    let result = tokio::time::timeout(Duration::from_secs(3), async {
        while by_key(&rig, "background")["state"] != "confirmed" {
            tokio::task::yield_now().await;
        }
    })
    .await;
    task.abort();
    result.unwrap();
    assert_eq!(rig.state().writes().len(), 1);
}

#[tokio::test]
async fn hosted_settlement_rotates_bounded_sweeps_past_unresolved_entries() {
    let rig = Rig::new(fast()).await;
    for n in 0..35 {
        hosted_create(&rig, &format!("rotate-{n}"), &format!("handle-{n}")).await;
    }
    rig.state().outcomes.lock().unwrap().insert(
        "handle-34".into(),
        hosted_status(&rig, "rotate-34", "applied", None),
    );
    rig.gate.settle_hosted_batch(&rig.upstream).await;
    assert_eq!(rig.state().status_reads.lock().unwrap().len(), 32);
    assert_eq!(by_key(&rig, "rotate-34")["state"], "hosted_pending");
    rig.gate.settle_hosted_batch(&rig.upstream).await;
    assert_eq!(by_key(&rig, "rotate-34")["answer"], "receipt");
    assert_eq!(rig.state().writes().len(), 35);
}

#[tokio::test]
async fn hosted_settlement_same_key_checks_cover_non_node_holdable_updates_and_legacy_envelopes() {
    let rig = Rig::new(fast()).await;
    let call = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz",
        "arguments":{"id":"record-id","name":"new title","reason":"test rename","idempotency_key":"rename"}});
    rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
    forward_with(&rig, call.clone(), None).await;
    let id = entry_id(&rig, "rename");
    // Older builds left both absent on writes outside the node's hold allowlist.
    rig.gate
        .journal
        .update(&id, |e| {
            e.envelope = None;
            e.intent_digest = None;
        })
        .unwrap();
    rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
    forward_with(&rig, call.clone(), None).await;
    assert_eq!(entries(&rig).len(), 1);
    receipt(&forward_with(&rig, call, None).await);
    assert_eq!(entries(&rig).len(), 1);
    assert_eq!(by_key(&rig, "rename")["answer"], "receipt");
}

#[tokio::test]
async fn hosted_settlement_same_key_check_can_recover_a_missing_hosted_handle() {
    let rig = Rig::new(fast()).await;
    hosted_create(&rig, "missing-handle", "unused").await;
    let id = entry_id(&rig, "missing-handle");
    rig.gate
        .journal
        .update(&id, |e| e.hosted_journal_entry = None)
        .unwrap();
    rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
    forward_with(&rig, create(Some("missing-handle"), "kept draft"), None).await;
    assert_eq!(entries(&rig).len(), 1);
    assert_eq!(
        by_key(&rig, "missing-handle")["hosted_journal_entry"],
        "hosted-entry"
    );
}

fn batch(key: Value) -> Value {
    let mut call = listed_writes()
        .into_iter()
        .find(|(name, _)| *name == "create_many")
        .unwrap()
        .1;
    call["arguments"]["idempotency_key"] = key;
    call
}

#[tokio::test]
async fn keyed_batch_timeout_does_not_overlap_a_server_side_write_still_running() {
    let rig = Rig::new(fast()).await;
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let done = Arc::new(tokio::sync::Notify::new());
    rig.state().script([Fault::ParkBeforeApply(
        started.clone(),
        release.clone(),
        done.clone(),
    )]);
    let mut client = rig.connect();
    client.send(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"call_executor","arguments":batch(json!("batch-timeout"))}})).await;
    started.notified().await;
    let reply = client.recv().await.unwrap();
    assert_eq!(reply["error"]["data"]["outcome"], "uncertain");
    assert!(reply["error"]["data"]["retry"]
        .as_str()
        .unwrap()
        .contains("reconcile"));
    assert_eq!(
        rig.state().writes().len(),
        1,
        "no overlapping second attempt"
    );
    assert_eq!(
        rig.state().created.load(Ordering::SeqCst),
        0,
        "server still working after timeout"
    );
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(2), done.notified())
        .await
        .unwrap();
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert_eq!(entries(&rig)[0]["state"], "uncertain");
    assert_eq!(entries(&rig)[0]["attempts"], 1);
    assert_eq!(entries(&rig)[0]["maybe_applied"], true);
    assert!(rig.gate.status(&Default::default())["how_to_settle"]
        .as_str()
        .unwrap()
        .contains("create_many"));
}

#[tokio::test]
async fn lost_keyless_batch_response_is_never_retried() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::ApplyThenDrop]);
    let mut client = rig.connect();
    let reply = client.call(1, batch(Value::Null)).await;
    assert_eq!(reply["error"]["data"]["outcome"], "unknown");
    assert_eq!(rig.state().writes().len(), 1);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert_eq!(entries(&rig)[0]["state"], "uncertain");
}

#[tokio::test]
async fn batch_queue_lost_reply_and_recovered_in_flight_marker_stop_replay() {
    for crash in [false, true] {
        let mut rig = Rig::new(fast()).await;
        rig.state().script([Fault::Http(200, READ_ONLY)]);
        let held = forward_with(&rig, batch(json!("batch-queue")), None).await;
        let entry_id = pending(&held)["journal_entry"].as_str().unwrap().to_owned();
        if crash {
            rig.gate.journal.begin_queue_send(&entry_id).unwrap();
            rig.restart(fast());
        } else {
            rig.state().script([Fault::ApplyThenDrop]);
        }
        let before = rig.state().writes().len();
        assert_eq!(drain(&rig).await, Halt::Empty);
        assert_eq!(rig.state().writes().len(), before + usize::from(!crash));
        assert_eq!(
            rig.gate.journal.get(&entry_id).unwrap().state,
            EntryState::Uncertain
        );
        assert!(rig.gate.journal.get(&entry_id).unwrap().arguments.is_some());
        assert!(rig.gate.journal.get(&entry_id).unwrap().maybe_applied);
        let after = rig.state().writes().len();
        assert_eq!(drain(&rig).await, Halt::Empty);
        assert_eq!(rig.state().writes().len(), after, "no recovery resend");
    }
}

#[tokio::test]
async fn operator_withdrawal_refuses_repeat_and_dependants_without_dispatch() {
    let rig = Rig::new(fast()).await;
    let root = hold_create(&rig, "withdraw-root", "recoverable body").await;
    let record_id = root["record_id"].as_str().unwrap();
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let append = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
        "id":record_id,"body_append":"dependent text","reason":"r","idempotency_key":"withdraw-child"}});
    pending(&forward_with(&rig, append, None).await);
    let before = rig.state().writes().len();
    let root_id = root["journal_entry"].as_str().unwrap();
    let mut client = rig.connect();
    client.send(json!({"jsonrpc":"2.0","id":10,"method":"node/journal/withdraw","params":{"entry_id":root_id,"reason":"operator no longer wants this work"}})).await;
    let decision = client.recv().await.unwrap();
    assert_eq!(decision["result"]["state"], "confirmed");
    assert_eq!(decision["result"]["operator_audit"]["uid"], owner_uid());
    assert_eq!(by_key(&rig, "withdraw-child")["answer"], "refused");
    assert_eq!(by_key(&rig, "withdraw-child")["refused_because"], root_id);
    let repeat = client
        .call(11, create(Some("withdraw-root"), "recoverable body"))
        .await;
    assert_eq!(repeat["error"]["data"]["reason"], "operator_withdrawn");
    let changed = client
        .call(12, create(Some("withdraw-root"), "changed body"))
        .await;
    assert!(changed.to_string().contains("conflict"));
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().writes().len(), before);
    assert_eq!(
        by_key(&rig, "withdraw-root")["arguments"]["body"],
        "recoverable body"
    );

    // An append can cease to be holdable when its repeat adds an edit. That
    // shape change must still hit the withdrawn key's local conflict.
    let mut append = json!({"executor":"records_write","operation":"update_record","run_key":"run-xyz","arguments":{
        "id":"70110000-0000-4000-8000-0000000000ee", "body_append":"text", "reason":"r", "idempotency_key":"withdraw-append"}});
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let held_append = forward_with(&rig, append.clone(), None).await;
    let append_id = pending(&held_append)["journal_entry"].as_str().unwrap();
    rig.gate
        .operator_decision(append_id, None, "withdraw append", None)
        .await
        .unwrap();
    let before_changed_shape = rig.state().writes().len();
    append["arguments"]["name"] = json!("edit changes eligibility");
    let conflict = client.call(13, append).await;
    assert!(conflict.to_string().contains("conflict"));
    assert_eq!(rig.state().writes().len(), before_changed_shape);
}

#[tokio::test]
async fn operator_decision_refuses_active_gates_and_acknowledges_hosted_custody_locally() {
    let rig = Rig::new(fast()).await;
    let held = hold_create(&rig, "ack-hosted", "retained body").await;
    let id = held["journal_entry"].as_str().unwrap();
    rig.gate
        .journal
        .hosted_pending(id, Some("hosted-handle".into()))
        .unwrap();
    let before = rig.state().writes().len();
    {
        let _turn = rig.gate.drain_lock.write().await;
        assert!(rig
            .gate
            .operator_decision(id, Some("landed"), "canonical history checked", None)
            .await
            .is_err());
    }
    {
        let _turn = rig.gate.hosted_check.lock().await;
        assert!(rig
            .gate
            .operator_decision(id, Some("landed"), "canonical history checked", None)
            .await
            .is_err());
    }
    let mut client = rig.connect();
    // Notifications are ignored and never mutate the journal.
    client.send(json!({"jsonrpc":"2.0","method":"node/journal/acknowledge","params":{"entry_id":id,"outcome":"landed","reason":"must be ignored"}})).await;
    client.send(json!({"jsonrpc":"2.0","id":1,"method":"node/journal/acknowledge","params":{"entry_id":id,"outcome":"landed","reason":"canonical history checked"}})).await;
    let reply = client.recv().await.unwrap();
    assert_eq!(reply["result"]["state"], "acknowledged");
    assert_eq!(reply["result"]["canonical"], false);
    assert_eq!(
        reply["result"]["operator_audit"]["reason"],
        "canonical history checked"
    );
    assert_eq!(rig.state().writes().len(), before);
    assert_eq!(rig.gate.status(&Default::default())["outstanding_count"], 0);
}

#[tokio::test]
async fn keyed_batch_retries_connect_failures_known_not_sent() {
    let mut config = fast();
    config.backoff_start = Duration::from_millis(100);
    let mut rig = Rig::new(config).await;
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let held = forward_with(&rig, batch(json!("batch-not-sent")), None).await;
    let entry_id = pending(&held)["journal_entry"].as_str().unwrap();
    let entry = rig.gate.journal.get(entry_id).unwrap();
    rig.hosted.task.abort();
    let _ = (&mut rig.hosted.task).await;
    let address = rig
        .config
        .hosted_base_url
        .strip_prefix("http://")
        .unwrap()
        .to_owned();
    let mut call = batch(json!("batch-not-sent"));
    call["arguments"] = entry.arguments.clone().unwrap();
    let message = tool_call(88, "call_executor", call);
    let body = message.to_string();
    let caller = Caller::new(None, Cancel::new());
    let request = WriteRequest {
        body: &body,
        message: &message,
        revision: None,
        caller: &caller,
        outage: None,
        no_hold: true,
    };
    let restore = async {
        // Two new attempts started, so the first connect refusal has already
        // passed the retry policy. Bind only then: no possibly-applied send.
        eventually(|| rig.gate.journal.get(entry_id).unwrap().attempts >= entry.attempts + 2).await;
        let listener = TcpListener::bind(&address).await.unwrap();
        let (socket, _) = listener.accept().await.unwrap();
        serve_hosted(rig.hosted.state.clone(), socket).await;
    };
    let (result, _) = tokio::join!(
        rig.gate
            .send_with_retry(&rig.upstream, &request, &message, &body, &entry, false),
        restore
    );
    assert_eq!(result.0.attempt, Attempt::Answered);
    assert!(!result.1);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert_eq!(
        rig.state().writes().len(),
        2,
        "initial non-applying refusal and one actual send"
    );
}

#[tokio::test]
async fn journal_cli_routes_acknowledgement_and_rejects_incomplete_flags() {
    let rig = Rig::new(fast()).await;
    let held = hold_create(&rig, "cli-ack", "body").await;
    let id = held["journal_entry"].as_str().unwrap();
    rig.gate
        .journal
        .hosted_pending(id, Some("hosted-entry".into()))
        .unwrap();
    let socket = rig.config.socket_directory.join("cli-test.sock");
    let args = |tail: &[&str]| {
        [
            vec![
                "journal".to_owned(),
                "--socket".into(),
                socket.to_str().unwrap().into(),
            ],
            tail.iter().map(|s| (*s).to_owned()).collect(),
        ]
        .concat()
    };
    assert!(run_cli(&args(&["acknowledge", id, "--reason"]))
        .await
        .is_err());
    let listener = UnixListener::bind(&socket).unwrap();
    let gate = rig.gate.clone();
    let upstream = rig.upstream.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        serve_routed_connection(
            stream,
            upstream,
            None,
            Some(gate),
            None,
            Arc::new(Admission::new()),
        )
        .await
        .unwrap();
    });
    let before = rig.state().writes().len();
    run_cli(&args(&[
        "acknowledge",
        id,
        "--reason",
        "matched canonical history",
        "--outcome",
        "landed",
    ]))
    .await
    .unwrap();
    server.await.unwrap();
    assert_eq!(
        rig.gate.journal.get(id).unwrap().state,
        EntryState::Acknowledged
    );
    assert_eq!(rig.state().writes().len(), before);
}

#[tokio::test]
async fn hosted_retry_with_stale_custody_snapshot_reports_operator_audit_without_resending() {
    for outcome in ["not_applied", "landed", "superseded"] {
        let rig = Rig::new(fast()).await;
        let call = create(Some("ack-wins-hosted-check"), "preserved body");
        rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
        forward_with(&rig, call.clone(), None).await;
        let id = entry_id(&rig, "ack-wins-hosted-check");
        // Model a caller that captured hosted custody before the operator won
        // hosted_check. Pass that stale snapshot after the operator releases it.
        let stale = rig.gate.journal.get(&id).unwrap();
        assert_eq!(stale.state, EntryState::HostedPending);
        rig.gate
            .operator_decision(&id, Some(outcome), "checked canonical history", None)
            .await
            .unwrap();
        let acknowledged = rig.gate.journal.get(&id).unwrap();
        let before = rig.state().writes().len();
        let message = tool_call(99, "call_executor", call);
        let body = message.to_string();
        let caller = Caller::new(None, Cancel::new());
        let request = WriteRequest {
            body: &body,
            message: &message,
            revision: None,
            caller: &caller,
            outage: None,
            no_hold: false,
        };
        let report = rig.gate.repeat_hosted(&rig.upstream, &request, stale).await;
        assert_eq!(report.attempt, Attempt::Answered);
        let reply: Value = serde_json::from_str(&report.reply.unwrap()).unwrap();
        let content = &reply["result"]["structuredContent"];
        assert_eq!(content["outcome"], "acknowledged");
        assert_eq!(content["canonical"], false);
        assert_eq!(content["receipt_available"], false);
        assert!(
            content.get("applied").is_none(),
            "even landed is an operator assertion"
        );
        assert_eq!(
            content["operator_audit"],
            serde_json::to_value(acknowledged.operator_audit).unwrap()
        );
        assert_eq!(content["operator_audit"]["outcome"], outcome);
        assert_eq!(content["node_journal_entry"], id);
        assert_eq!(
            rig.state().writes().len(),
            before,
            "no resend after acknowledgement"
        );
        assert_eq!(
            rig.gate.journal.get(&id).unwrap().state,
            EntryState::Acknowledged
        );
        assert_eq!(
            rig.gate.journal.get(&id).unwrap().arguments,
            acknowledged.arguments
        );
    }
}

async fn app_rig() -> (Rig, super::super::app_proof::Connection) {
    let mut rig = Rig::new(fast()).await;
    rig.config.desktop_app_proof_transport = true;
    rig.config.desktop_app_proof_resource_origin = Some("https://plugin.test".into());
    rig.config.account_id = Some("acct_owner".into());
    rig.upstream = Arc::new(Upstream::new(rig.config.clone(), Duration::from_secs(30)).unwrap());
    let connection =
        super::super::app_proof::Connection::new(Some(super::super::app_proof::Binding {
            account_id: "acct_owner".into(),
            hosted_db_id: rig.config.db_id.clone(),
            origin_database_id: "ndb_origin".into(),
            resource_origin: "https://plugin.test".into(),
            forwarding_origin: rig.upstream.endpoint.origin().ascii_serialization(),
        }));
    let reply=connection.dispatch(&rig.config,&json!({"jsonrpc":"2.0","id":0,"method":"native/app-proof/install","params":{
        "account_id":"acct_owner","hosted_db_id":rig.config.db_id,"origin_database_id":"ndb_origin",
        "resource_origin":"https://plugin.test","forwarding_origin":rig.upstream.endpoint.origin().ascii_serialization(),"app":"docs@1; install=evt",
        "proof":"opaque-test-proof","expires_in_ms":60000}})).unwrap();
    assert!(reply.contains("ready"));
    (rig, connection)
}
async fn forward_app(
    rig: &Rig,
    connection: &super::super::app_proof::Connection,
    arguments: Value,
    outage: Option<&dyn Outage>,
) -> Value {
    let mut message = tool_call(8, "call_executor", arguments);
    message["params"]["_meta"] = json!({"native/app":"docs@1; install=evt"});
    let body = message.to_string();
    let mut caller = Caller::new(None, Cancel::new());
    caller.context = connection.context();
    let report = rig
        .gate
        .forward(
            &rig.upstream,
            &WriteRequest {
                body: &body,
                message: &message,
                revision: None,
                caller: &caller,
                outage,
                // Defence in depth: app attribution alone must prevent custody even
                // if a future caller forgets the production buildsite no_hold flag.
                no_hold: false,
            },
            true,
        )
        .await;
    serde_json::from_str(&report.reply.unwrap()).unwrap()
}
#[tokio::test]
async fn app_writes_never_hold_or_automatically_replay_across_failures() {
    for fault in [
        Fault::Http(200, READ_ONLY),
        Fault::ApplyThenDrop,
        Fault::Http(503, "unavailable"),
        Fault::RefuseKey,
    ] {
        let (rig, connection) = app_rig().await;
        *rig.state().always.lock().unwrap() = Some(fault);
        let reply = forward_app(&rig, &connection, create(None, "app step"), None).await;
        assert_ne!(
            reply.pointer("/result/structuredContent/outcome"),
            Some(&json!("accepted_pending")),
            "{reply}"
        );
        let persisted = entries(&rig);
        assert!(!persisted.is_empty());
        assert!(persisted
            .iter()
            .all(|e| e["state"] != "pending" && e["app_identity"] == "docs@1; install=evt"));
        assert!(
            rig.state().keys_sent().iter().all(Option::is_some),
            "no keyless resend"
        );
        let sends = rig.state().writes().len();
        *rig.state().always.lock().unwrap() = None;
        rig.gate.drain(&rig.upstream, None, None, None).await;
        rig.gate.settle_hosted_batch(&rig.upstream).await;
        assert_eq!(
            rig.state().writes().len(),
            sends,
            "recovery must not replay app calls"
        );
        let reopened =
            super::super::journal::Journal::open(&rig.config.socket_directory, CONFIRMED_RETENTION)
                .unwrap();
        assert_eq!(reopened.pending_count(), 0);
        let files = fs::read_dir(rig.config.socket_directory.join("journal")).unwrap();
        for file in files {
            let file = file.unwrap();
            if file.path().extension().is_some_and(|e| e == "json") {
                assert!(!fs::read_to_string(file.path())
                    .unwrap()
                    .contains("opaque-test-proof"));
            }
        }
    }
}
#[tokio::test]
async fn app_missing_proof_offline_and_backlog_refuse_before_mutation_or_journal() {
    let (rig, connection) = app_rig().await;
    let absent = super::super::app_proof::Connection::default();
    let missing = forward_app(&rig, &absent, create(Some("caller-key"), "app"), None).await;
    assert_eq!(missing["error"]["data"]["outcome"], "not_sent");
    assert!(entries(&rig).is_empty());
    assert!(rig.state().writes().is_empty());
    let down = FakeOutage::new(true);
    down.known.store(true, Ordering::SeqCst);
    let offline = forward_app(
        &rig,
        &connection,
        create(Some("caller-key"), "app"),
        Some(&down),
    )
    .await;
    assert_eq!(offline["error"]["data"]["outcome"], "not_sent");
    assert!(entries(&rig).is_empty());
    assert!(rig.state().writes().is_empty());
    let entry = rig
        .gate
        .journal
        .begin(super::NewEntry {
            executor: "records_write".into(),
            operation: "create_record".into(),
            tool: "call_executor".into(),
            run_key: None,
            client_info: None,
            app_identity: None,
            idempotency_key: Some("ordinary".into()),
            key_origin: Some(KeyOrigin::Caller),
            arguments: json!({"type":"Document"}),
            parent_key: None,
            title: None,
            record_id: None,
            record_ids: vec![],
            envelope: None,
            intent_digest: None,
        })
        .unwrap();
    rig.gate
        .journal
        .hold(
            &entry.id,
            HoldReason::DeploymentReadOnly,
            "read-only".into(),
            false,
        )
        .unwrap();
    let backlog = forward_app(&rig, &connection, create(Some("caller-key"), "app"), None).await;
    assert_eq!(backlog["error"]["data"]["outcome"], "not_sent");
    assert_eq!(entries(&rig).len(), 1);
    assert!(rig.state().writes().is_empty());
}
#[tokio::test]
async fn app_caller_key_survives_and_hosted_custody_never_replays() {
    let (rig, connection) = app_rig().await;
    rig.state().script([Fault::Http(200, HOSTED_PENDING)]);
    let arguments = create(Some("caller-app-key"), "app custody");
    let first = forward_app(&rig, &connection, arguments.clone(), None).await;
    assert_eq!(
        first["result"]["structuredContent"]["outcome"],
        "accepted_pending"
    );
    assert_eq!(rig.state().keys_sent(), vec![Some("caller-app-key".into())]);
    let entry = entries(&rig).pop().unwrap();
    assert_eq!(entry["state"], "hosted_pending");
    rig.gate.settle_hosted_batch(&rig.upstream).await;
    let mut arguments = arguments;
    arguments["arguments"]["response_mode"] = json!("compact");
    let repeat = forward_app(&rig, &connection, arguments, None).await;
    assert_eq!(
        repeat["result"]["structuredContent"]["outcome"],
        "accepted_pending"
    );
    assert_eq!(
        rig.state().writes().len(),
        1,
        "even an explicit custody check must not reconstruct an app mutation"
    );
    assert!(rig.state().status_reads.lock().unwrap().is_empty());
}

#[tokio::test]
async fn app_after_possible_send_credential_refusal_stays_uncertain() {
    let (rig, connection) = app_rig().await;
    rig.state().script([Fault::ApplyDropThenRevokeCredentials]);
    let reply = forward_app(
        &rig,
        &connection,
        create(Some("app-uncertain"), "possibly applied"),
        None,
    )
    .await;
    assert_eq!(reply["error"]["data"]["outcome"], "uncertain", "{reply}");
    let entry = entries(&rig).pop().unwrap();
    assert_eq!(entry["state"], "uncertain");
    assert_eq!(entry["app_identity"], "docs@1; install=evt");
    assert_eq!(
        rig.gate.status(&Default::default())["app_outstanding_count"],
        1
    );
    assert_eq!(rig.state().writes().len(), 1);
    assert_eq!(rig.gate.journal.pending_count(), 0);
}

#[tokio::test]
async fn app_proof_clear_after_possible_send_preserves_uncertainty_without_rest_or_keyless_replay()
{
    let (mut rig, connection) = app_rig().await;
    Arc::get_mut(&mut rig.gate).unwrap().config.backoff_start = Duration::from_millis(250);
    rig.state().script([Fault::ApplyThenDrop]);
    let forwarded = forward_app(
        &rig,
        &connection,
        create(Some("proof-expired-after-send"), "app"),
        None,
    );
    let revoke = async {
        eventually(|| rig.state().created.load(Ordering::SeqCst) == 1).await;
        connection.context().clear();
    };
    let (reply, ()) = tokio::join!(forwarded, revoke);
    assert_eq!(reply["error"]["data"]["outcome"], "uncertain", "{reply}");
    assert_eq!(rig.state().writes().len(), 1);
    assert_eq!(entries(&rig)[0]["state"], "uncertain");
    assert_eq!(rig.gate.journal.pending_count(), 0);
}

#[path = "body_merge_lineage_fault_tests.rs"]
mod body_merge_lineage_fault_tests;

#[tokio::test]
async fn fork_payloads_leave_every_terminal_settlement_and_disable_restores_pruning() {
    let mut config = fast();
    config.retention = Duration::ZERO;
    let rig = Rig::new(config).await;
    rig.gate.enable_pending_fork();
    for (index, state) in [
        EntryState::Confirmed,
        EntryState::NotSent,
        EntryState::Uncertain,
    ]
    .into_iter()
    .enumerate()
    {
        let held = hold_create(
            &rig,
            &format!("terminal-{index}"),
            "private preview payload",
        )
        .await;
        let id = held["journal_entry"].as_str().unwrap();
        assert!(rig.gate.journal.get(id).unwrap().fork_arguments.is_some());
        let settled = rig
            .gate
            .journal
            .settle(id, state, Some("receipt"), None)
            .unwrap();
        assert!(settled.fork_arguments.is_none());
        assert!(settled.fork_run_key.is_none());
        assert!(settled.fork_accepted_act.is_none());
    }
    let held = hold_create(&rig, "operator-terminal", "operator preview payload").await;
    let id = held["journal_entry"].as_str().unwrap();
    rig.gate
        .operator_decision(id, None, "withdraw preview", None)
        .await
        .unwrap();
    assert!(rig.gate.journal.get(id).unwrap().fork_arguments.is_none());
    let held = hold_create(&rig, "disable-terminal", "retained preview payload").await;
    let id = held["journal_entry"].as_str().unwrap();
    let accepted = rig
        .gate
        .journal
        .update(id, |e| {
            e.state = EntryState::Confirmed;
            e.answer = Some("receipt".into());
            e.fork_accepted_act = Some(999);
        })
        .unwrap();
    assert!(accepted.fork_arguments.is_some());
    tokio::time::sleep(Duration::from_millis(10)).await;
    rig.gate.disable_pending_fork();
    assert!(
        rig.gate.journal.get(id).is_none(),
        "disabled preview metadata cannot block ordinary pruning"
    );
}

#[tokio::test]
async fn preview_retention_does_not_change_hosted_replay() {
    let rig = Rig::new(fast()).await;
    rig.gate.enable_pending_fork();
    // This gate has no serving generation, the same state as failed preparation.
    let held = hold_create(&rig, "preview-replay", "durable replay payload").await;
    let id = held["journal_entry"].as_str().unwrap();
    assert!(rig.gate.journal.get(id).unwrap().fork_arguments.is_some());
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert_eq!(by_key(&rig, "preview-replay")["answer"], "receipt");
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
}

struct DescriptionCompatibilityOutage {
    evidence: Option<NodeHoldingContract>,
}
impl Outage for DescriptionCompatibilityOutage {
    fn contract_digest<'a>(
        &'a self,
        _executor: &'a str,
        _operation: &'a str,
        _protocol: Option<&'a str>,
    ) -> Ready<'a, Option<String>> {
        Box::pin(async { Some("different-hosted-digest".into()) })
    }
    fn holding_contract<'a>(
        &'a self,
        _executor: &'a str,
        _operation: &'a str,
        _protocol: Option<&'a str>,
    ) -> Ready<'a, Option<NodeHoldingContract>> {
        Box::pin(async { self.evidence.clone() })
    }
    fn confirm_down(&self) -> Ready<'_, bool> {
        Box::pin(async { false })
    }
}

#[tokio::test]
async fn holding_contract_description_only_custody_survives_restart_without_preview() {
    let mut rig = Rig::new(fast()).await;
    let mut evidence = rig
        .gate
        .local_contracts
        .holding_contract("records_write", "create_record")
        .unwrap();
    evidence.description["source"]["tool_description"] = json!("Updated source guidance");
    evidence.description["contract_digest"] = json!("different-hosted-digest");
    let outage = DescriptionCompatibilityOutage {
        evidence: Some(evidence),
    };
    rig.gate.enable_pending_fork();
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    let asked = create(Some("description-key"), "durable pending");
    let reply = forward_with(&rig, asked.clone(), Some(&outage)).await;
    assert_eq!(
        reply["result"]["structuredContent"]["outcome"], "accepted_pending",
        "{reply}"
    );
    assert_eq!(
        reply["result"]["structuredContent"]["contract_compatibility"],
        "source_description_only"
    );
    assert_eq!(
        reply["result"]["structuredContent"]["preview_available"],
        false
    );
    let entry = rig.gate.journal.oldest_pending().unwrap();
    assert!(entry.custody_compatibility.is_some());
    assert_eq!(
        entry.version,
        super::super::journal::DESCRIPTION_CUSTODY_VERSION
    );
    assert!(!super::super::pending_fork::previewable(&entry));
    assert!(entry.fork_arguments.is_none());
    let original = entry.arguments.clone();
    // This is the previous reader's exact version guard: ignoring the new
    // optional marker cannot make the saved format replayable or previewable.
    let saved_path = rig
        .config
        .socket_directory
        .join("journal")
        .join(format!("{}.json", entry.id));
    let mut old_shape: Value = serde_json::from_slice(&fs::read(&saved_path).unwrap()).unwrap();
    old_shape
        .as_object_mut()
        .unwrap()
        .remove("custody_compatibility");
    let old_reader: Entry = serde_json::from_value(old_shape).unwrap();
    assert!(
        old_reader.version > super::super::journal::ENTRY_VERSION
            && !(old_reader.version == 2
                && old_reader.is_merge()
                && (old_reader.prepared || old_reader.lineage_required))
    );
    rig.restart(fast());
    let entry = rig.gate.journal.oldest_pending().unwrap();
    assert!(entry.custody_compatibility.is_some());
    assert_eq!(entry.arguments, original);
    assert!(!super::super::pending_fork::previewable(&entry));
    // Replay uses the retained bytes and hosted admission, not local execution.
    rig.gate.drain(&rig.upstream, None, None, None).await;
    assert_eq!(rig.state().writes().len(), 2);
    assert_eq!(
        rig.state().writes()[0]["params"]["arguments"],
        rig.state().writes()[1]["params"]["arguments"]
    );
    assert_eq!(rig.gate.status(&Default::default())["queue"]["pending"], 0);
    let settled_id = entry.id;
    rig.restart(fast());
    assert_eq!(rig.gate.status(&Default::default())["unreadable_files"], 0);
    let settled = rig.gate.journal.get(&settled_id).unwrap();
    assert_eq!(settled.answer.as_deref(), Some("receipt"));
    assert!(settled.arguments.is_none());
    assert!(!super::super::pending_fork::previewable(&settled));
}

#[tokio::test]
async fn holding_contract_malformed_custody_format_is_preserved_unreadable() {
    let mut rig = Rig::new(fast()).await;
    let mut evidence = rig
        .gate
        .local_contracts
        .holding_contract("records_write", "create_record")
        .unwrap();
    evidence.description["source"]["tool_description"] = json!("Changed explanation");
    let outage = DescriptionCompatibilityOutage {
        evidence: Some(evidence),
    };
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    forward_with(
        &rig,
        create(Some("malformed-format-key"), "retain this draft"),
        Some(&outage),
    )
    .await;
    let entry = rig.gate.journal.oldest_pending().unwrap();
    let path = rig
        .config
        .socket_directory
        .join("journal")
        .join(format!("{}.json", entry.id));
    let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    saved["custody_compatibility"] = Value::Null;
    fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
    let before = fs::read(&path).unwrap();
    rig.restart(fast());
    assert!(rig.gate.journal.oldest_pending().is_none());
    assert_eq!(rig.gate.status(&Default::default())["unreadable_files"], 1);
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[tokio::test]
async fn holding_contract_incompatible_or_missing_evidence_never_takes_custody() {
    for variant in [
        "missing",
        "schema",
        "selector",
        "plan",
        "access",
        "acceptance",
        "malformed",
    ] {
        let rig = Rig::new(fast()).await;
        let mut evidence = rig
            .gate
            .local_contracts
            .holding_contract("records_write", "create_record")
            .unwrap();
        evidence.description["source"]["tool_description"] = json!("Updated guidance");
        match variant {
            "schema" => {
                evidence.description["input_schema"]["properties"]["future_optional"] =
                    json!({"type":"string"})
            }
            "selector" => {
                evidence.description["source"]["selector"] =
                    json!({"field":"action","value":"different"})
            }
            "plan" => evidence.description["prototype"]["plan_required"] = json!(true),
            "access" => evidence.catalog["access"] = json!("read"),
            "acceptance" => evidence.catalog["requires_acceptance"] = json!(true),
            "malformed" => evidence.description = json!({}),
            _ => (),
        }
        let outage = DescriptionCompatibilityOutage {
            evidence: (variant != "missing").then_some(evidence),
        };
        rig.state().script([Fault::Http(200, READ_ONLY)]);
        let reply = forward_with(&rig, create(None, "must stay with caller"), Some(&outage)).await;
        assert_eq!(
            reply["error"]["data"]["outcome"], "not_sent",
            "{variant}: {reply}"
        );
        let message = reply["error"]["message"].as_str().unwrap();
        assert!(
            message.contains(if variant == "missing" {
                "missing or malformed"
            } else {
                "incompatible"
            }),
            "{variant}: {reply}"
        );
        assert_eq!(rig.gate.status(&Default::default())["queue"]["pending"], 0);
    }
}

#[tokio::test]
async fn holding_contract_replay_refusal_retains_content_and_custody_format() {
    let mut rig = Rig::new(fast()).await;
    let evidence = rig
        .gate
        .local_contracts
        .holding_contract("records_write", "create_record")
        .unwrap();
    let outage = DescriptionCompatibilityOutage {
        evidence: Some(evidence),
    };
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    forward_with(
        &rig,
        create(Some("description-refusal"), "draft must survive rejection"),
        Some(&outage),
    )
    .await;
    let entry = rig.gate.journal.oldest_pending().unwrap();
    let original = entry.arguments.clone();
    rig.state().script([Fault::ToolReply(json!({"isError":true,"content":[],"structuredContent":{"error_code":"validation_failure","applied":false}}))]);
    rig.gate.drain(&rig.upstream, None, None, None).await;
    rig.restart(fast());
    let refused = rig.gate.journal.get(&entry.id).unwrap();
    assert_eq!(refused.answer.as_deref(), Some("refused"));
    assert_eq!(refused.arguments, original);
    assert_eq!(
        refused.version,
        super::super::journal::DESCRIPTION_CUSTODY_VERSION
    );
    assert!(!super::super::pending_fork::previewable(&refused));
    assert_eq!(rig.gate.status(&Default::default())["unreadable_files"], 0);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn holding_contract_possibly_applied_attempt_never_grants_exact_preview() {
    for variant in ["description", "missing", "schema"] {
        let mut rig = Rig::new(fast()).await;
        let mut evidence = rig
            .gate
            .local_contracts
            .holding_contract("records_write", "create_record")
            .unwrap();
        evidence.description["source"]["tool_description"] = json!("Changed hosted explanation");
        if variant == "schema" {
            evidence.description["input_schema"]["properties"]["future_optional"] =
                json!({"type":"string"});
        }
        let outage = DescriptionCompatibilityOutage {
            evidence: (variant != "missing").then_some(evidence),
        };
        rig.gate.enable_pending_fork();
        rig.state()
            .script([Fault::ApplyThenDrop, Fault::Http(200, READ_ONLY)]);
        let reply = forward_with(
            &rig,
            create(
                Some("possibly-applied-description-key"),
                "keep uncertain draft",
            ),
            Some(&outage),
        )
        .await;
        let expected = if variant == "description" {
            "source_description_only"
        } else {
            "prior_attempt_unverified"
        };
        assert_eq!(
            reply["result"]["structuredContent"]["outcome"], "accepted_pending",
            "{variant}: {reply}"
        );
        assert_eq!(
            reply["result"]["structuredContent"]["may_already_be_applied"],
            true
        );
        assert_eq!(
            reply["result"]["structuredContent"]["contract_compatibility"],
            expected
        );
        assert_eq!(
            reply["result"]["structuredContent"]["preview_available"],
            false
        );
        let held = rig.gate.journal.oldest_pending().unwrap();
        assert_eq!(
            held.version,
            super::super::journal::DESCRIPTION_CUSTODY_VERSION
        );
        assert!(!super::super::pending_fork::previewable(&held));
        rig.restart(fast());
        let reloaded = rig.gate.journal.oldest_pending().unwrap();
        assert_eq!(reloaded.arguments, held.arguments);
        assert!(reloaded.maybe_applied);
        assert!(!super::super::pending_fork::previewable(&reloaded));
    }
}

#[tokio::test]
async fn holding_contract_custody_format_mutations_are_atomic_and_rejected() {
    let rig = Rig::new(fast()).await;
    let evidence = rig
        .gate
        .local_contracts
        .holding_contract("records_write", "create_record")
        .unwrap();
    let outage = DescriptionCompatibilityOutage {
        evidence: Some(evidence),
    };
    rig.state().script([Fault::Http(200, READ_ONLY)]);
    forward_with(
        &rig,
        create(Some("immutable-custody-key"), "immutable held content"),
        Some(&outage),
    )
    .await;
    let held = rig.gate.journal.oldest_pending().unwrap();
    let path = rig
        .config
        .socket_directory
        .join("journal")
        .join(format!("{}.json", held.id));
    let before = fs::read(&path).unwrap();
    for mutation in [
        "marker",
        "version",
        "fork",
        "key",
        "arguments",
        "retire_pending",
    ] {
        let result = rig.gate.journal.update(&held.id, |entry| match mutation {
            "marker" => entry.custody_compatibility = None,
            "version" => entry.version = 1,
            "fork" => entry.fork_arguments = entry.arguments.clone(),
            "key" => entry.idempotency_key = Some("different-key".into()),
            "arguments" => entry.arguments.as_mut().unwrap()["body"] = json!("different draft"),
            "retire_pending" => {
                entry.arguments = None;
                entry.envelope = None;
            }
            _ => unreachable!(),
        });
        assert!(result.is_err(), "{mutation}");
        assert_eq!(fs::read(&path).unwrap(), before, "{mutation}");
        assert_eq!(
            serde_json::to_value(rig.gate.journal.get(&held.id).unwrap()).unwrap(),
            serde_json::to_value(&held).unwrap()
        );
    }
}

fn seed_forwarded_uncertainty(rig: &Rig) {
    let entry = rig
        .gate
        .journal
        .begin(NewEntry {
            executor: "records_write".into(),
            operation: "create_record".into(),
            tool: "call_executor".into(),
            run_key: Some("old-run".into()),
            client_info: None,
            app_identity: None,
            idempotency_key: None,
            key_origin: None,
            arguments: json!({"body":"private original"}),
            parent_key: None,
            title: Some("private title".into()),
            record_id: None,
            record_ids: vec![],
            envelope: None,
            intent_digest: None,
        })
        .unwrap();
    rig.gate
        .journal
        .settle(
            &entry.id,
            EntryState::Uncertain,
            None,
            Some("reply lost".into()),
        )
        .unwrap();
}

#[tokio::test]
async fn bootstrap_combines_legacy_and_scoped_backlogs_without_record_contents() {
    let legacy = Rig::new(fast()).await;
    seed_forwarded_uncertainty(&legacy);
    let scoped = Rig::new(fast()).await;
    hold_call(
        &scoped,
        create_in("old-run", None, "scoped-key", "Scoped private title"),
    )
    .await;
    let reply = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"canonical bootstrap"}],"structuredContent":{}}}"#;
    let combined =
        WriteGate::note_held_writes_across(&[&legacy.gate, &scoped.gate], reply, "new-run");
    let value: Value = serde_json::from_str(&combined).unwrap();
    let note = &value["result"]["structuredContent"]["node_held_writes"];
    assert_eq!(note["account"]["waiting"], 2);
    assert_eq!(
        note["account"]["counts"],
        json!({"pending":1,"uncertain":1})
    );
    assert!(note["account"]["oldest_accepted_at"].is_string());
    assert_eq!(value["result"]["content"].as_array().unwrap().len(), 2);
    assert_eq!(value["result"]["content"][0]["text"], "canonical bootstrap");
    assert!(combined.contains("This account: 2"));
    assert!(!combined.contains("private title") && !combined.contains("private original"));
    assert!(
        legacy.state().writes().is_empty(),
        "disclosure never replays the forward"
    );
    assert_eq!(legacy.gate.journal.waiting_summary()["waiting"], 1);
}

/// 7e99834: a text-format bootstrap carries no structuredContent. With held
/// writes waiting, the node must not create one holding only its note: clients
/// that prefer structuredContent would then hide bootstrap's text, run key and
/// the note itself. Both journals' totals still reach the visible text.
#[tokio::test]
async fn text_format_bootstrap_with_held_writes_keeps_the_hosted_text_visible() {
    let legacy = Rig::new(fast()).await;
    seed_forwarded_uncertainty(&legacy);
    let scoped = Rig::new(fast()).await;
    hold_call(
        &scoped,
        create_in("old-run", None, "scoped-key", "Scoped private title"),
    )
    .await;
    let reply = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"bootstrap text run_key=calm-otter-abc123"}],"isError":false}}"#;
    let noted = WriteGate::note_held_writes_across(&[&legacy.gate, &scoped.gate], reply, "new-run");
    let value: Value = serde_json::from_str(&noted).unwrap();
    assert!(
        value["result"].get("structuredContent").is_none(),
        "{noted}"
    );
    let content = value["result"]["content"].as_array().unwrap();
    assert_eq!(
        content[0]["text"],
        "bootstrap text run_key=calm-otter-abc123"
    );
    let note = content[1]["text"].as_str().unwrap();
    assert!(note.contains("This account: 2 ("), "{note}");
    assert!(
        note.contains("1 pending") && note.contains("1 uncertain"),
        "{note}"
    );
    assert!(!noted.contains("private title"), "{noted}");
}

/// 7e99834, the same shape on the uncertain-write note: a text-format reply
/// to a write whose outcome is uncertain keeps hosted's text visible, with the
/// retry key in a text line rather than a structured payload the node made up.
#[test]
fn an_uncertain_note_on_a_text_reply_does_not_create_structured_content() {
    let reply = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hosted receipt"}],"isError":false}}"#;
    let noted = annotate_hosted_reply(reply, json!({"outcome":"uncertain"}), "retry-key");
    let value: Value = serde_json::from_str(&noted).unwrap();
    assert!(
        value["result"].get("structuredContent").is_none(),
        "{noted}"
    );
    assert_eq!(value["result"]["content"][0]["text"], "hosted receipt");
    assert!(value["result"]["content"][1]["text"]
        .as_str()
        .unwrap()
        .contains("idempotency_key=retry-key"));
    // Still machine-readable, so the CLI and session writer classify it.
    assert_eq!(
        value["result"]["_meta"]["node_journal"]["outcome"],
        "uncertain"
    );
}

#[tokio::test]
async fn bootstrap_preserves_the_response_without_disclosing_a_previous_accounts_backlog() {
    let mut config = fast();
    config.account_binding = Some(json!({"account_id":"first"}));
    let mut rig = Rig::new(config.clone()).await;
    seed_forwarded_uncertainty(&rig);
    config.account_binding = Some(json!({"account_id":"second"}));
    rig.restart(config);
    let reply = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[],"structuredContent":{}}}"#;
    assert_eq!(rig.gate.note_held_writes(reply, "new-run"), reply);
}

const CLIENT_UPDATE: &str =
    r#"{"error_code":"client_update_required","outcome":"refused","applied":false}"#;

#[tokio::test]
async fn update_required_holds_new_write_and_preserves_queue_originals_without_cascade() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(426, CLIENT_UPDATE)]);
    let reply = forward_with(&rig, create(Some("update-original"), "original body"), None).await;
    pending(&reply);
    let original = rig
        .gate
        .journal
        .get(by_key(&rig, "update-original")["id"].as_str().unwrap())
        .unwrap();
    let before = serde_json::to_value(&original).unwrap();
    // A later refusal is update demand, never a terminal business verdict.
    rig.state().script([Fault::Http(426, CLIENT_UPDATE)]);
    assert_eq!(drain(&rig).await, Halt::ClientUpdateRequired);
    let after = serde_json::to_value(rig.gate.journal.get(&original.id).unwrap()).unwrap();
    for key in [
        "arguments",
        "idempotency_key",
        "envelope",
        "key_origin",
        "contract",
        "kernel_v2_custody",
    ] {
        assert_eq!(before[key], after[key], "{key}");
    }
    assert_eq!(after["state"], "pending");
    assert!(after["answer"].is_null());
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
    assert_eq!(
        rig.upstream.compatibility.status()["status"],
        "demand_recorded"
    );
    assert_eq!(drain(&rig).await, Halt::Empty);
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 1);
    assert_eq!(
        rig.state().keys_sent(),
        vec![Some("update-original".into()); 3]
    );
}

#[tokio::test]
async fn update_required_preserves_earlier_uncertainty_and_never_finalizes_original() {
    let rig = Rig::new(fast()).await;
    hold_create(&rig, "update-uncertain", "body").await;
    let id = by_key(&rig, "update-uncertain")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    rig.gate
        .journal
        .update(&id, |e| {
            e.maybe_applied = true;
        })
        .unwrap();
    rig.state().script([Fault::Http(426, CLIENT_UPDATE)]);
    assert_eq!(drain(&rig).await, Halt::ClientUpdateRequired);
    let entry = rig.gate.journal.get(&id).unwrap();
    assert!(entry.maybe_applied);
    assert_eq!(entry.state, EntryState::Pending);
    assert!(entry.answer.is_none());
    assert!(entry.envelope.is_some());
    assert_eq!(entry.idempotency_key.as_deref(), Some("update-uncertain"));
}

#[tokio::test]
async fn contradictory_update_refusal_keeps_original_uncertain_instead_of_confirming_refusal() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(
        426,
        r#"{"error_code":"client_update_required","outcome":"refused","applied":true}"#,
    )]);
    let _ = forward_with(&rig, create(Some("update-contradiction"), "body"), None).await;
    let entry = by_key(&rig, "update-contradiction");
    assert!(entry["answer"].is_null(), "{entry}");
    assert_ne!(entry["state"], "confirmed", "{entry}");
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn update_required_nonholdable_call_is_honestly_unapplied_without_terminal_refusal() {
    let rig = Rig::new(fast()).await;
    rig.state().script([Fault::Http(426, CLIENT_UPDATE)]);
    let reply = forward_with(&rig,json!({"executor":"coordination_write","operation":"set_intent","arguments":{"intent":"new intent"}}),None).await;
    assert_eq!(
        reply["error"]["data"]["error_code"], "client_update_required",
        "{reply}"
    );
    assert_eq!(reply["error"]["data"]["applied"], false);
    assert_eq!(reply["error"]["data"]["updater"], "unavailable");
    assert_eq!(rig.state().unkeyed_applied.load(Ordering::SeqCst), 0);
    assert_eq!(rig.gate.journal.pending_count(), 0);
    for entry in entries(&rig) {
        assert_eq!(entry["state"], "not_sent", "{entry}");
        assert!(entry["answer"].is_null());
    }
}

#[tokio::test]
async fn update_required_backlog_keeps_compatibility_reason_and_queued_dependant() {
    let rig = Rig::new(fast()).await;
    let first = hold_create(&rig, "update-parent", "base").await;
    rig.state().script([Fault::Http(426, CLIENT_UPDATE)]);
    let reply = forward_with(&rig,json!({"executor":"records_write","operation":"update_record","arguments":{
        "id":first["record_id"],"body_append":"later","reason":"r","idempotency_key":"update-child"
    }}),None).await;
    assert_eq!(
        pending(&reply)["reason"],
        "client_update_required",
        "{reply}"
    );
    rig.state().script([Fault::Http(426, CLIENT_UPDATE)]);
    assert_eq!(drain(&rig).await, Halt::ClientUpdateRequired);
    assert_eq!(rig.gate.journal.pending_count(), 2);
    for key in ["update-parent", "update-child"] {
        let entry = by_key(&rig, key);
        assert_eq!(entry["state"], "pending", "{entry}");
        assert_eq!(entry["hold_reason"], "client_update_required", "{entry}");
        assert!(entry["answer"].is_null());
        assert!(!entry["arguments"].is_null());
    }
    assert_eq!(rig.state().created.load(Ordering::SeqCst), 0);
}
