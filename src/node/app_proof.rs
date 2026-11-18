//! Memory-only forwarding hints on one owner-bound socket. Hosted verifies
//! cryptographic admission; registration never grants local app authority.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::{Mutex as StdMutex, Weak};
use std::time::Instant;

pub(super) const HEADER: &str = "X-Native-Desktop-App-Proof";
const PREFIX: &str = "native/";
const MAX_PROOF: usize = 16 * 1024;
const MAX_BYTES: usize = 128 * 1024;
const MAX_APPS: usize = 32;

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub account_id: String,
    pub hosted_db_id: String,
    pub origin_database_id: String,
    pub resource_origin: String,
    pub forwarding_origin: String,
}
#[derive(Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
struct App {
    package: String,
    version: String,
    install_event_id: String,
}
impl App {
    fn from_carrier(raw: &str) -> Option<Self> {
        #[cfg(feature = "mcp-executor-prototype")]
        {
            let a = crate::mcp::app_attribution::parse_header(raw).ok()?;
            Some(Self {
                package: a.package,
                version: a.version,
                install_event_id: a.install_event_id,
            })
        }
        #[cfg(not(feature = "mcp-executor-prototype"))]
        {
            let _ = raw;
            None
        }
    }
}
// No Debug or Serialize on anything containing secret bytes.
struct Registration {
    proof: reqwest::header::HeaderValue,
    deadline: Instant,
    bytes: usize,
}
#[derive(Default)]
struct State {
    binding: Option<Binding>,
    apps: BTreeMap<App, Registration>,
}
#[derive(Default)]
pub(super) struct Connection(Arc<StdMutex<State>>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.lock().expect("app proof state").apps.clear();
    }
}
/// Weak connection reference: work outliving teardown cannot retain authority.
#[derive(Clone, Default)]
pub(super) struct RequestContext(Weak<StdMutex<State>>);
impl Connection {
    pub(super) fn new(binding: Option<Binding>) -> Self {
        Self(Arc::new(StdMutex::new(State {
            binding,
            apps: BTreeMap::new(),
        })))
    }
    pub(super) fn context(&self) -> RequestContext {
        RequestContext(Arc::downgrade(&self.0))
    }
    pub(super) fn dispatch(&self, config: &NodeConfig, message: &Value) -> Option<String> {
        let reject = || refusal(message);
        if message.is_array()
            || !message
                .get("id")
                .is_some_and(|id| id.is_string() || id.is_number())
        {
            return reject();
        }
        let mut state = self.0.lock().expect("app proof state");
        state.apps.retain(|_, r| Instant::now() < r.deadline);
        // Readiness is configuration+binding readiness, never cryptographic verification.
        if !config.desktop_app_proof_transport || state.binding.is_none() {
            return reject();
        }
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "native/app-proof/install" => {
                let Some(params) = message.get("params").cloned() else {
                    return reject();
                };
                let Ok(install) = serde_json::from_value::<Install>(params) else {
                    return reject();
                };
                let binding = Binding {
                    account_id: install.account_id,
                    hosted_db_id: install.hosted_db_id,
                    origin_database_id: install.origin_database_id,
                    resource_origin: install.resource_origin,
                    forwarding_origin: install.forwarding_origin,
                };
                if state.binding.as_ref() != Some(&binding) || !matches_config(config, &binding) {
                    state.apps.clear();
                    return reject();
                }
                let Some(app) = App::from_carrier(&install.app) else {
                    return reject();
                };
                if !(1..=60_000).contains(&install.expires_in_ms)
                    || install.proof.is_empty()
                    || install.proof.len() > MAX_PROOF
                    || !install.proof.bytes().all(|b| b.is_ascii_graphic())
                {
                    return reject();
                }
                let used: usize = state.apps.values().map(|r| r.bytes).sum();
                let old = state.apps.get(&app).map_or(0, |r| r.bytes);
                if (!state.apps.contains_key(&app) && state.apps.len() >= MAX_APPS)
                    || used - old + install.proof.len() > MAX_BYTES
                {
                    return reject();
                }
                let Ok(mut proof) = reqwest::header::HeaderValue::from_str(&install.proof) else {
                    return reject();
                };
                proof.set_sensitive(true);
                state.apps.insert(
                    app,
                    Registration {
                        proof,
                        bytes: install.proof.len(),
                        deadline: Instant::now() + Duration::from_millis(install.expires_in_ms),
                    },
                );
                json!({"ready":true,"cryptographically_verified":false})
            }
            "native/app-proof/clear" => {
                let Some(params) = message.get("params").cloned() else {
                    return reject();
                };
                let Ok(clear) = serde_json::from_value::<Clear>(params) else {
                    return reject();
                };
                match clear {
                    Clear::All {} => state.apps.clear(),
                    Clear::App { app } => {
                        let Some(app) = App::from_carrier(&app) else {
                            return reject();
                        };
                        state.apps.remove(&app);
                    }
                }
                json!({"cleared":true})
            }
            _ => return reject(),
        };
        Some(json!({"jsonrpc":"2.0","id":message["id"],"result":result}).to_string())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Install {
    account_id: String,
    hosted_db_id: String,
    origin_database_id: String,
    resource_origin: String,
    forwarding_origin: String,
    app: String,
    proof: String,
    expires_in_ms: u64,
}
#[derive(Deserialize)]
#[serde(untagged, deny_unknown_fields)]
enum Clear {
    All {},
    App { app: String },
}
/// Only an explicit canonical HTTP(S) origin is accepted. No endpoint/path,
/// credentials, URL aliases or discovery performed implicitly by the node.
pub(super) fn resource_origin(config: &NodeConfig) -> Option<String> {
    let raw = config.desktop_app_proof_resource_origin.as_deref()?;
    let url = reqwest::Url::parse(raw).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.origin().ascii_serialization() == raw)
        .then(|| raw.to_owned())
}
fn matches_config(config: &NodeConfig, binding: &Binding) -> bool {
    resource_origin(config).as_deref() == Some(binding.resource_origin.as_str())
        && config.account_id.as_deref() == Some(binding.account_id.as_str())
        && config.db_id == binding.hosted_db_id
        && reqwest::Url::parse(&config.hosted_base_url)
            .ok()
            .is_some_and(|u| u.origin().ascii_serialization() == binding.forwarding_origin)
}
pub(super) fn identity(message: &Value) -> Option<&str> {
    message
        .pointer("/params/_meta/native~1app")
        .and_then(Value::as_str)
}
pub(super) fn canonical_identity(message: &Value) -> Option<String> {
    let app = App::from_carrier(identity(message)?)?;
    Some(format!(
        "{}@{}; install={}",
        app.package, app.version, app.install_event_id
    ))
}
impl RequestContext {
    pub(super) fn clear(&self) {
        if let Some(state) = self.0.upgrade() {
            state.lock().expect("app proof state").apps.clear();
        }
    }
    /// Public scope only; release the proof-map lock before any async work.
    pub(super) fn binding(&self, config: &NodeConfig) -> Option<Binding> {
        if !config.desktop_app_proof_transport {
            return None;
        }
        let connection = self.0.upgrade()?;
        let state = connection.lock().expect("app proof state");
        state
            .binding
            .as_ref()
            .filter(|b| matches_config(config, b))
            .cloned()
    }
    pub(super) fn capability(&self, config: &NodeConfig) -> Value {
        let binding = self.binding(config);
        let supported = binding.is_some();
        json!({"contract":"native.desktop-app-proof-transport.v2", "binding":binding,
            "enabled":config.desktop_app_proof_transport,"supported":supported,
            "connection_scoped":true,"max_apps":MAX_APPS,"max_proof_bytes":MAX_PROOF,
            "max_total_proof_bytes":MAX_BYTES,"max_lifetime_ms":60000,
            "cryptographic_admission":"hosted"})
    }
}
pub(super) fn attributed(message: &Value) -> bool {
    message.pointer("/params/_meta/native~1app").is_some()
        || message.as_array().is_some_and(|a| a.iter().any(attributed))
}
pub(super) fn is_control(message: &Value) -> bool {
    message
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|m| m.starts_with(PREFIX) && !m.starts_with("native/changes/"))
        || message.as_array().is_some_and(|a| a.iter().any(is_control))
}
pub(super) fn refusal(message: &Value) -> Option<String> {
    frame_error(
        if message.is_array() {
            Some(&Value::Null)
        } else {
            message.get("id")
        },
        "Desktop app proof unavailable or invalid; request was not sent",
        json!({"outcome":"not_sent","reason":"app_proof_unavailable"}),
    )
}
pub(super) fn header(
    config: &NodeConfig,
    message: &Value,
    context: Option<&RequestContext>,
) -> std::result::Result<Option<reqwest::header::HeaderValue>, ()> {
    if !attributed(message) {
        return Ok(None);
    }
    if !config.desktop_app_proof_transport || message.is_array() {
        return Err(());
    }
    let app = App::from_carrier(identity(message).ok_or(())?).ok_or(())?;
    let connection = context.and_then(|c| c.0.upgrade()).ok_or(())?;
    let mut state = connection.lock().expect("app proof state");
    if !state
        .binding
        .as_ref()
        .is_some_and(|b| matches_config(config, b))
    {
        state.apps.clear();
        return Err(());
    }
    state.apps.retain(|_, r| Instant::now() < r.deadline);
    state
        .apps
        .get(&app)
        .map(|r| Some(r.proof.clone()))
        .ok_or(())
}

#[cfg(all(test, feature = "mcp-executor-prototype"))]
mod tests {
    use super::*;
    fn config() -> NodeConfig {
        serde_json::from_value(json!({"hosted_base_url":"https://mcp.test/prefix","home_id":"h","db_id":"route",
            "account_id":"acct_owner","credential_file":"/unused","socket_directory":"/unused","desktop_app_proof_transport":true,"desktop_app_proof_resource_origin":"https://plugin.test"})).unwrap()
    }
    fn binding() -> Binding {
        Binding {
            account_id: "acct_owner".into(),
            hosted_db_id: "route".into(),
            origin_database_id: "ndb_origin".into(),
            resource_origin: "https://plugin.test".into(),
            forwarding_origin: "https://mcp.test".into(),
        }
    }
    fn install(app: &str, proof: &str) -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"native/app-proof/install","params":{
            "account_id":"acct_owner","hosted_db_id":"route","origin_database_id":"ndb_origin","resource_origin":"https://plugin.test","forwarding_origin":"https://mcp.test",
            "app":app,"proof":proof,"expires_in_ms":60000}})
    }
    fn call(app: &str) -> Value {
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"_meta":{"native/app":app}}})
    }
    fn accepted(connection: &Connection, config: &NodeConfig, value: &Value) {
        let reply = connection.dispatch(config, value).unwrap();
        assert!(
            serde_json::from_str::<Value>(&reply)
                .unwrap()
                .get("result")
                .is_some(),
            "{reply}"
        );
    }
    #[test]
    fn v2_requires_explicit_independent_canonical_origins() {
        let config = config();
        let c = Connection::new(Some(binding()));
        let capability = c.context().capability(&config);
        assert_eq!(
            capability["contract"],
            "native.desktop-app-proof-transport.v2"
        );
        assert_eq!(capability["supported"], true);
        assert_eq!(
            capability["binding"]["resource_origin"],
            "https://plugin.test"
        );
        assert_eq!(
            capability["binding"]["forwarding_origin"],
            "https://mcp.test"
        );
        accepted(&c, &config, &install("docs@1; install=e1", "opaque-secret"));
        assert!(!capability.to_string().contains("opaque-secret"));
        for raw in [
            None,
            Some("https://plugin.test/"),
            Some("HTTPS://PLUGIN.TEST"),
            Some("https://plugin.test:443"),
            Some("https://plugin.test/path"),
            Some("https://u:p@plugin.test"),
            Some("https://plugin.test?x"),
            Some("https://plugin.test#x"),
            Some("file:///tmp"),
            Some("null"),
        ] {
            let mut bad = config.clone();
            bad.desktop_app_proof_resource_origin = raw.map(str::to_owned);
            assert_eq!(c.context().capability(&bad)["supported"], false);
            assert!(header(&bad, &call("docs@1; install=e1"), Some(&c.context())).is_err());
            assert!(c
                .dispatch(&bad, &install("docs@1; install=e1", "opaque-secret"))
                .unwrap()
                .contains("not_sent"));
        }
        let old_config: NodeConfig = serde_json::from_value(json!({
            "hosted_base_url":"https://mcp.test", "home_id":"h", "db_id":"route",
            "credential_file":"/unused", "socket_directory":"/unused"}))
        .unwrap();
        assert!(!old_config.desktop_app_proof_transport);
        assert!(old_config.desktop_app_proof_resource_origin.is_none());
        let mut legacy = install("docs@1; install=e1", "opaque-secret");
        legacy["params"]
            .as_object_mut()
            .unwrap()
            .remove("resource_origin");
        legacy["params"]
            .as_object_mut()
            .unwrap()
            .remove("forwarding_origin");
        legacy["params"]["hosted_origin"] = json!("https://mcp.test");
        assert!(c.dispatch(&config, &legacy).unwrap().contains("not_sent"));
        for field in ["resource_origin", "forwarding_origin"] {
            for wrong in [
                "https://plugin.test/",
                "https://mcp.test/",
                "https://other.test",
            ] {
                let mut message = install("docs@1; install=e1", "opaque-secret");
                message["params"][field] = json!(wrong);
                assert!(c.dispatch(&config, &message).unwrap().contains("not_sent"));
            }
        }
    }
    #[test]
    fn registrations_are_socket_scoped_canonical_and_revocable() {
        let config = config();
        let a = Connection::new(Some(binding()));
        let b = Connection::new(Some(binding()));
        let ctx = a.context();
        accepted(&a, &config, &install("docs@1; install=e1", "secret-docs"));
        accepted(
            &a,
            &config,
            &install("tracker@2; install=e2", "secret-tracker"),
        );
        assert_eq!(
            header(&config, &call("docs@1;install=e1"), Some(&ctx))
                .unwrap()
                .unwrap(),
            "secret-docs"
        );
        assert!(header(&config, &call("docs@1; install=e1"), Some(&b.context())).is_err());
        assert!(header(&config, &call("docs@2; install=e1"), Some(&ctx)).is_err());
        let clear = json!({"jsonrpc":"2.0","id":3,"method":"native/app-proof/clear","params":{"app":"docs@1;install=e1"}});
        accepted(&a, &config, &clear);
        assert!(header(&config, &call("docs@1; install=e1"), Some(&ctx)).is_err());
        assert!(header(&config, &call("tracker@2; install=e2"), Some(&ctx))
            .unwrap()
            .is_some());
        accepted(
            &a,
            &config,
            &json!({"jsonrpc":"2.0","id":4,"method":"native/app-proof/clear","params":{}}),
        );
        assert!(header(&config, &call("tracker@2; install=e2"), Some(&ctx)).is_err());
        accepted(&a, &config, &install("docs@1; install=e1", "secret-docs"));
        drop(a);
        assert!(header(&config, &call("docs@1; install=e1"), Some(&ctx)).is_err());
    }
    #[test]
    fn strict_controls_bound_scope_expiry_and_never_echo_secret() {
        let config = config();
        let c = Connection::new(Some(binding()));
        let secret = "DO-NOT-ECHO-SECRET";
        for (field, value) in [
            ("account_id", json!("acct_foreign")),
            ("hosted_db_id", json!("wrong")),
            ("origin_database_id", json!("wrong")),
            ("forwarding_origin", json!("https://cookie.test")),
            ("resource_origin", json!("https://mcp.test")),
            ("hosted_origin", json!("https://plugin.test")),
            ("expires_in_ms", json!(0)),
            ("expires_in_ms", json!(60001)),
            ("expires_in_ms", json!(-1)),
            ("extra", json!(secret)),
            ("contract", json!("native.desktop-app-proof-transport.v1")),
            ("proof", json!("bad\r\nheader")),
            ("app", json!({"package":"docs"})),
            ("proof", json!("x".repeat(MAX_PROOF + 1))),
        ] {
            let mut message = install("docs@1; install=e1", secret);
            message["params"][field] = value;
            let reply = c.dispatch(&config, &message).unwrap();
            assert!(!reply.contains(secret));
            assert_eq!(
                serde_json::from_str::<Value>(&reply).unwrap()["error"]["data"]["outcome"],
                "not_sent"
            );
        }
        for params in [
            json!({"all":true}),
            json!({"app":"docs@1; install=e1","extra":1}),
            json!({"app":null}),
        ] {
            let reply=c.dispatch(&config,&json!({"jsonrpc":"2.0","id":3,"method":"native/app-proof/clear","params":params})).unwrap();
            assert!(serde_json::from_str::<Value>(&reply)
                .unwrap()
                .get("error")
                .is_some());
        }
        let ctx = c.context();
        accepted(&c, &config, &install("docs@1; install=e1", secret));
        let app = App::from_carrier("docs@1; install=e1").unwrap();
        c.0.lock().unwrap().apps.get_mut(&app).unwrap().deadline = Instant::now();
        assert!(header(&config, &call("docs@1; install=e1"), Some(&ctx)).is_err());
        assert!(c.0.lock().unwrap().apps.is_empty());
        let mut wrong = config.clone();
        wrong.account_id = Some("acct_other".into());
        accepted(&c, &config, &install("docs@1; install=e1", secret));
        assert!(header(&wrong, &call("docs@1; install=e1"), Some(&ctx)).is_err());
        assert!(c.0.lock().unwrap().apps.is_empty());
        let mut disabled = config.clone();
        disabled.desktop_app_proof_transport = false;
        assert!(c
            .dispatch(&disabled, &install("docs@1; install=e1", secret))
            .unwrap()
            .contains("not_sent"));
        let unbound = Connection::default();
        assert!(unbound
            .dispatch(&config, &install("docs@1; install=e1", secret))
            .unwrap()
            .contains("not_sent"));
        assert_eq!(unbound.context().capability(&config)["supported"], false);
        for message in [
            json!({"id":1,"method":"native/app-proof/unknown","params":{"proof":secret}}),
            json!([install("docs@1; install=e1", secret)]),
        ] {
            assert!(is_control(&message));
            let reply = c.dispatch(&config, &message).unwrap();
            assert!(!reply.contains(secret));
            assert!(reply.contains("not_sent"));
        }
    }
    #[test]
    fn proof_counts_bytes_replacement_and_sensitive_debug_are_bounded() {
        let config = config();
        let c = Connection::new(Some(binding()));
        for i in 0..MAX_APPS {
            accepted(
                &c,
                &config,
                &install(&format!("app{i}@1; install=e"), "secret"),
            );
        }
        assert!(c
            .dispatch(&config, &install("overflow@1; install=e", "secret"))
            .unwrap()
            .contains("not_sent"));
        accepted(&c, &config, &install("app0@1; install=e", "replacement"));
        assert_eq!(c.0.lock().unwrap().apps.len(), MAX_APPS);
        let c = Connection::new(Some(binding()));
        let bytes = "s".repeat(MAX_PROOF);
        for i in 0..8 {
            accepted(
                &c,
                &config,
                &install(&format!("app{i}@1; install=e"), &bytes),
            );
        }
        assert!(c
            .dispatch(&config, &install("overflow@1; install=e", "s"))
            .unwrap()
            .contains("not_sent"));
        let value = header(&config, &call("app0@1; install=e"), Some(&c.context()))
            .unwrap()
            .unwrap();
        assert!(value.is_sensitive());
        assert!(!format!("{value:?}").contains(&bytes));
    }
}

#[cfg(all(test, feature = "mcp-executor-prototype"))]
mod transport_tests {
    use super::*;
    #[tokio::test]
    async fn upstream_carries_sensitive_proof_only_with_matching_live_request_context() {
        let directory = tempfile::tempdir().unwrap();
        let token = directory.path().join("token");
        fs::write(&token, "bearer").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let config:NodeConfig=serde_json::from_value(json!({"hosted_base_url":origin,"home_id":"h","db_id":"route","account_id":"acct_owner",
            "credential_file":token,"socket_directory":directory.path(),"desktop_app_proof_transport":true,"desktop_app_proof_resource_origin":"https://plugin.test"})).unwrap();
        let upstream = Upstream::new(config.clone(), Duration::from_secs(2)).unwrap();
        let connection = Connection::new(Some(Binding {
            account_id: "acct_owner".into(),
            hosted_db_id: "route".into(),
            origin_database_id: "ndb_origin".into(),
            resource_origin: "https://plugin.test".into(),
            forwarding_origin: origin.clone(),
        }));
        let registration = json!({"jsonrpc":"2.0","id":1,"method":"native/app-proof/install","params":{
            "account_id":"acct_owner","hosted_db_id":"route","origin_database_id":"ndb_origin","resource_origin":"https://plugin.test","forwarding_origin":origin,
            "app":"docs@1; install=evt","proof":"opaque-header-secret","expires_in_ms":60000}});
        assert!(connection
            .dispatch(&config, &registration)
            .unwrap()
            .contains("ready"));
        for operation in ["get_record", "create_record"] {
            let message = json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"call_executor",
                "_meta":{"native/app":"docs@1; install=evt"},"arguments":{"executor":"records_read","operation":operation,"arguments":{"id":"record"}}}});
            let raw = message.to_string();
            let server = async {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut chunk = [0; 4096];
                loop {
                    let n = socket.read(&mut chunk).await.unwrap();
                    assert_ne!(n, 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8(bytes[..end].to_vec())
                            .unwrap()
                            .to_lowercase();
                        let length: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .unwrap()
                            .trim()
                            .parse()
                            .unwrap();
                        if bytes.len() < end + 4 + length {
                            continue;
                        }
                        assert!(head
                            .lines()
                            .any(|l| l == "x-native-desktop-app-proof: opaque-header-secret"));
                        assert_eq!(&bytes[end + 4..end + 4 + length], raw.as_bytes());
                        assert!(!raw.contains("opaque-header-secret"));
                        break;
                    }
                }
                let body = "{\"jsonrpc\":\"2.0\",\"id\":4,\"result\":{}}";
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).as_bytes()).await.unwrap();
            };
            let context = connection.context();
            let send =
                upstream.send_classified_context(&raw, &message, None, message.get("id"), &context);
            let (report, ()) = tokio::join!(send, server);
            assert_eq!(report.attempt, Attempt::Answered);
            let unscoped = upstream
                .send_classified(&raw, &message, None, message.get("id"))
                .await;
            assert_eq!(unscoped.attempt, Attempt::Stopped);
            assert!(unscoped.reply.unwrap().contains("not_sent"));
        }
    }
}
