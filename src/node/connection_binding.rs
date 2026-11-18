//! Optional, fail-closed scope negotiation before a shim forwards MCP traffic.
//! A constraint only: it neither authenticates a new principal nor grants access.
use super::*;
use serde::{Deserialize, Serialize};

const METHOD: &str = "native/connection/bind";
const PREFIX: &str = "native/connection/";
const CONTRACT: &str = "native.connection-binding.v1";
pub(super) fn runtime_declaration() -> Value {
    json!({"family":"shim_connection_binding","variant":"scope","version":1,
        "contract":CONTRACT,"transport":"shim_node","persisted":false,
        "decoder_compiled":true,"required_features":[],
        "unknown_fields":"scope_reject","continuation_conditions":["account","database","hosted_origin"],
        "source":"src/node/connection_binding.rs#Scope"})
}

const MAX_REPLY: usize = 8192;
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Scope {
    /// Engine principal, not the human login id.
    pub account_id: String,
    pub database_id: String,
    pub hosted_origin: String,
}
impl Scope {
    pub(super) fn valid(&self) -> bool {
        let identifier =
            |s: &str| !s.trim().is_empty() && s.len() <= 512 && !s.chars().any(char::is_control);
        identifier(&self.account_id)
            && identifier(&self.database_id)
            && reqwest::Url::parse(&self.hosted_origin)
                .ok()
                .is_some_and(|url| {
                    matches!(url.scheme(), "http" | "https")
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.path() == "/"
                        && url.query().is_none()
                        && url.fragment().is_none()
                        && url.origin().ascii_serialization() == self.hosted_origin
                })
    }
}

pub(super) fn parse_cli(args: &[String]) -> Result<(PathBuf, Option<Scope>)> {
    let mut socket = None;
    let mut account = None;
    let mut database = None;
    let mut origin = None;
    if !args.len().is_multiple_of(2) {
        return Err(Error::engine("node connect requires flag/value pairs"));
    }
    for pair in args.as_chunks::<2>().0 {
        let slot = match pair[0].as_str() {
            "--socket" => &mut socket,
            "--expect-account" => &mut account,
            "--expect-database" => &mut database,
            "--expect-origin" => &mut origin,
            _ => return Err(Error::engine("unknown node connect flag")),
        };
        if slot.replace(pair[1].clone()).is_some() {
            return Err(Error::engine("duplicate node connect flag"));
        }
    }
    let socket = socket
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::engine("node connect requires --socket"))?;
    let scope = match (account, database, origin) {
        (None, None, None) => None,
        (Some(account_id), Some(database_id), Some(hosted_origin)) => {
            let scope = Scope {account_id, database_id, hosted_origin};
            if !scope.valid() { return Err(Error::engine("invalid expected node binding")); }
            Some(scope)
        }
        _ => return Err(Error::engine("expected node binding requires --expect-account, --expect-database and --expect-origin together")),
    };
    Ok((PathBuf::from(socket), scope))
}

pub(super) fn is_control(message: &Value) -> bool {
    message
        .get("method")
        .and_then(Value::as_str)
        .is_some_and(|m| m.starts_with(PREFIX))
        || message
            .as_array()
            .is_some_and(|items| items.iter().any(is_control))
}
pub(super) fn refusal(message: &Value) -> Option<String> {
    frame_error(Some(message.get("id").unwrap_or(&Value::Null)),
        "Native connection binding is unavailable or changed; update the node and reconnect Native explicitly",
        json!({"outcome":"not_sent","reason":"connection_binding_refused","contract":CONTRACT}))
}
pub(super) struct BindReply {
    pub reply: Option<String>,
    pub accepted: bool,
}
impl BindReply {
    fn refused(message: &Value) -> Self {
        Self {
            reply: refusal(message),
            accepted: false,
        }
    }
}
pub(super) fn dispatch(
    message: &Value,
    actual: Option<Scope>,
    pinned: &mut Option<Scope>,
) -> BindReply {
    let expected = message
        .get("params")
        .cloned()
        .and_then(|p| serde_json::from_value::<Scope>(p).ok());
    let valid_envelope = message.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && message.get("method").and_then(Value::as_str) == Some(METHOD)
        && message
            .get("id")
            .is_some_and(|id| id.is_string() || id.is_number())
        && message.as_object().is_some_and(|m| {
            m.keys()
                .all(|k| matches!(k.as_str(), "jsonrpc" | "method" | "id" | "params"))
        });
    let Some(expected) = expected.filter(|s| s.valid()).filter(|_| valid_envelope) else {
        return BindReply::refused(message);
    };
    if actual.as_ref() != Some(&expected) || pinned.as_ref().is_some_and(|p| p != &expected) {
        return BindReply::refused(message);
    }
    *pinned = Some(expected.clone());
    BindReply {reply:Some(json!({"jsonrpc":"2.0","id":message["id"],"result":{"contract":CONTRACT,"binding":expected}}).to_string()),accepted:true}
}

pub(super) async fn served_scope(upstream: &Upstream, router: Option<&Router>) -> Option<Scope> {
    #[cfg(feature = "mcp-executor-prototype")]
    {
        let scope = router?.connection_scope().await?;
        (upstream.config.account_id.as_deref() == Some(scope.account_id.as_str())
            && upstream.config.db_id == scope.database_id
            && upstream.endpoint.origin().ascii_serialization() == scope.hosted_origin)
            .then_some(scope)
    }
    #[cfg(not(feature = "mcp-executor-prototype"))]
    {
        let _ = (upstream, router);
        None
    }
}

/// No client frame is sent until the same-UID node acknowledges the exact scope.
/// The control must work without MCP initialization, and is repeated on every socket.
pub(super) async fn connect(socket: &Path, scope: Option<&Scope>) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(socket).await?;
    let refused = || {
        io::Error::new(io::ErrorKind::PermissionDenied,
        "Native connection binding could not be verified; update the node and reconnect Native explicitly")
    };
    if stream.peer_cred()?.uid() != owner_uid() {
        return Err(refused());
    }
    if let Some(expected) = scope {
        if !expected.valid() {
            return Err(refused());
        }
        let id = format!("native-shim-binding-{}", uuid::Uuid::new_v4());
        let handshake = async {
            let request = json!({"jsonrpc":"2.0","id":id,"method":METHOD,"params":expected});
            stream.write_all(format!("{request}\n").as_bytes()).await?;
            let mut bytes = Vec::new();
            // Do not read ahead and discard subsequent protocol frames.
            loop {
                let byte = stream.read_u8().await.map_err(|_| refused())?;
                bytes.push(byte);
                if byte == b'\n' || bytes.len() > MAX_REPLY {
                    break;
                }
            }
            if bytes.len() > MAX_REPLY || !bytes.ends_with(b"\n") {
                return Err(refused());
            }
            let reply: Value = serde_json::from_slice(&bytes).map_err(|_| refused())?;
            let actual = reply
                .pointer("/result/binding")
                .cloned()
                .and_then(|b| serde_json::from_value::<Scope>(b).ok());
            if reply.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
                || reply.get("id").and_then(Value::as_str) != Some(id.as_str())
                || reply.get("error").is_some()
                || reply.pointer("/result/contract").and_then(Value::as_str) != Some(CONTRACT)
                || actual.as_ref() != Some(expected)
            {
                return Err(refused());
            }
            Ok(())
        };
        tokio::time::timeout(TIMEOUT, handshake)
            .await
            .map_err(|_| refused())??;
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> Scope {
        Scope {
            account_id: "acct_owner".into(),
            database_id: "workspace".into(),
            hosted_origin: "https://native.test".into(),
        }
    }
    fn request(scope: &Scope) -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":METHOD,"params":scope})
    }
    #[test]
    fn bound_cli_requires_complete_unambiguous_canonical_scope() {
        let args = |values: &[&str]| values.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(parse_cli(&args(&["--socket", "/tmp/node.sock"]))
            .unwrap()
            .1
            .is_none());
        let valid = args(&[
            "--expect-origin",
            "https://native.test",
            "--socket",
            "/tmp/node.sock",
            "--expect-account",
            "acct_owner",
            "--expect-database",
            "workspace",
        ]);
        assert_eq!(parse_cli(&valid).unwrap().1, Some(scope()));
        for bad in [
            args(&[
                "--socket",
                "/tmp/node.sock",
                "--expect-account",
                "acct_owner",
            ]),
            args(&["--socket", "/tmp/node.sock", "--socket", "/other"]),
            args(&["--socket", "/tmp/node.sock", "--unknown", "value"]),
            args(&["--socket"]),
        ] {
            assert!(parse_cli(&bad).is_err());
        }
        for origin in [
            "https://native.test/",
            "https://user@native.test",
            "https://native.test/path",
            "https://native.test?query",
            "file:///tmp",
        ] {
            let mut invalid = scope();
            invalid.hosted_origin = origin.into();
            assert!(!invalid.valid());
        }
    }
    #[test]
    fn binding_control_is_strict_and_never_changes_a_pinned_scope() {
        let expected = scope();
        let mut pinned = None;
        let reply: Value = serde_json::from_str(
            &dispatch(&request(&expected), Some(expected.clone()), &mut pinned)
                .reply
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reply["result"]["binding"], json!(expected));
        assert_eq!(pinned.as_ref(), Some(&expected));
        for field in ["account_id", "database_id", "hosted_origin"] {
            let mut changed = json!(expected);
            changed[field] = if field == "hosted_origin" {
                json!("https://other.test")
            } else {
                json!("different")
            };
            let changed: Scope = serde_json::from_value(changed).unwrap();
            let reply = dispatch(&request(&changed), Some(changed), &mut pinned)
                .reply
                .unwrap();
            assert!(reply.contains("connection_binding_refused"));
            assert_eq!(pinned.as_ref(), Some(&expected));
        }
        for malformed in [
            json!({"id":1,"method":METHOD,"params":expected}),
            json!({"jsonrpc":"2.0","method":METHOD,"params":expected}),
            json!({"jsonrpc":"2.0","id":1,"method":METHOD,"params":{"extra":true}}),
            json!([request(&expected),{"id":2,"method":"tools/call"}]),
        ] {
            assert!(dispatch(&malformed, Some(expected.clone()), &mut pinned)
                .reply
                .unwrap()
                .contains("connection_binding_refused"));
        }
        assert!(dispatch(&request(&expected), None, &mut pinned)
            .reply
            .unwrap()
            .contains("connection_binding_refused"));
    }
    #[tokio::test]
    async fn negotiation_preserves_bytes_after_the_acknowledgement() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("node.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let expected = scope();
        let actual = expected.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut lines = BufReader::new(stream);
            let mut line = String::new();
            lines.read_line(&mut line).await.unwrap();
            let message: Value = serde_json::from_str(&line).unwrap();
            let reply = dispatch(&message, Some(actual), &mut None).reply.unwrap();
            lines
                .get_mut()
                .write_all(format!("{reply}\nfollowing-frame\n").as_bytes())
                .await
                .unwrap();
        });
        let stream = connect(&socket, Some(&expected)).await.unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, "following-frame\n");
        server.await.unwrap();
    }
    #[tokio::test]
    async fn unsupported_or_unverifiable_node_cannot_acknowledge_a_binding() {
        for kind in ["unsupported", "different", "malformed"] {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("node.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let expected = scope();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                reader.read_line(&mut line).await.unwrap();
                let message: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(message["method"], METHOD);
                let reply=match kind {
                    "unsupported"=>json!({"jsonrpc":"2.0","id":message["id"],"error":{"code":-32601,"message":"unsupported"}}).to_string(),
                    "different"=>{let mut other=scope();other.database_id="another".into();json!({"jsonrpc":"2.0","id":message["id"],"result":{"contract":CONTRACT,"binding":other}}).to_string()},
                    _=>json!({"jsonrpc":"2.0","id":message["id"],"result":{"binding":scope()}}).to_string(),
                };
                reader
                    .get_mut()
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .unwrap();
                line.clear();
                assert_eq!(
                    reader.read_line(&mut line).await.unwrap(),
                    0,
                    "no client traffic before acknowledgement"
                );
            });
            assert_eq!(
                connect(&socket, Some(&expected)).await.unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            server.await.unwrap();
        }
    }
}
