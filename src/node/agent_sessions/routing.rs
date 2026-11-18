//! Socket-tool interception for the five `node_agent_sessions_*` tools.
//!
//! These are answered locally like `node_status` and never forwarded
//! upstream. Follow pushes go out as `notifications/node_agent_sessions/event`
//! on the connection that followed, through that connection's writer, outside
//! the `MAX_IN_FLIGHT` permits. Connection close ends its follows.

use std::sync::Arc;

use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};

use super::broker::{AgentSessionsBroker, PushEvent};
use super::protocol::{
    self, MAX_FOLLOWS_PER_CONNECTION, TOOL_CAPABILITIES, TOOL_FOLLOW, TOOL_HISTORY, TOOL_LIST,
    TOOL_UNFOLLOW,
};

/// Per-connection follow state: the socket writer pushes go out on, and the
/// subscription ids this connection owns (max [`MAX_FOLLOWS_PER_CONNECTION`];
/// connection close unfollows all of them).
#[derive(Clone)]
pub struct FollowCtx {
    pub writer: Arc<tokio::sync::Mutex<tokio::net::unix::OwnedWriteHalf>>,
    pub follows: Arc<std::sync::Mutex<Vec<String>>>,
}

/// Test-only follow context over a socket pair. Pushes written by the
/// server writer arrive on the peer reader; the caller holds the peer writer
/// so those writes never fail while pushes are expected.
#[cfg(test)]
pub(crate) fn test_ctx() -> (
    FollowCtx,
    tokio::net::unix::OwnedReadHalf,
    tokio::net::unix::OwnedWriteHalf,
) {
    let (peer, server) = tokio::net::UnixStream::pair().expect("test socket pair");
    let (_server_reader, server_writer) = server.into_split();
    let (peer_reader, peer_writer) = peer.into_split();
    (
        FollowCtx {
            writer: Arc::new(tokio::sync::Mutex::new(server_writer)),
            follows: Arc::new(std::sync::Mutex::new(Vec::new())),
        },
        peer_reader,
        peer_writer,
    )
}

/// Frame a locally built tool result through the era-specific helper, like
/// `node_status_reply`. JSON-RPC errors and forwarded hosted replies retain
/// their own envelopes; only these five tools route here.
fn tool_frame(id: Option<&Value>, mut result: Value, modern: bool) -> Option<String> {
    #[cfg(feature = "mcp-executor-prototype")]
    {
        if modern {
            crate::mcp::hosted_protocol::add_modern_result_fields(&mut result);
        }
    }
    #[cfg(not(feature = "mcp-executor-prototype"))]
    {
        let _ = modern;
    }
    id.map(|id| json!({"jsonrpc":"2.0","id":id,"result":result}).to_string())
}

fn str_arg(args: Option<&Value>, field: &str) -> Option<String> {
    args.and_then(|a| a.get(field))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Release fired by the serving task after the follow reply frame is
/// written. The pusher buffers behind it, so no event can precede the reply.
pub struct PushRelease {
    release: oneshot::Sender<()>,
}

impl PushRelease {
    /// Release the pusher now that the reply is on the wire. Dropping
    /// without firing (cancelled request) tears the orphaned follow down
    /// without writing anything.
    pub fn fire(self) {
        let _ = self.release.send(());
    }
}

/// Forward one follow's pushes to the connection that followed it. Nothing
/// is written before the follow reply hits the wire: the loop waits for the
/// release first, and every exit frees this connection's slot (plus the
/// broker record, which self-cleans on poll exit but may still be live when
/// the socket end dies first).
#[allow(clippy::too_many_arguments)]
async fn forward_pushes(
    ctx: FollowCtx,
    broker: Arc<AgentSessionsBroker>,
    mut rx: mpsc::Receiver<PushEvent>,
    release: oneshot::Receiver<()>,
    subscription_id: String,
    host_id: String,
    host_epoch: String,
    session_id: String,
) {
    // The reply was never written (the request was cancelled): tear the
    // orphaned follow down without writing anything.
    if release.await.is_err() {
        cleanup_follow(&ctx, &broker, &subscription_id).await;
        return;
    }
    while let Some(event) = rx.recv().await {
        let terminal = matches!(event, PushEvent::Ended { .. });
        let line = event
            .notification(&subscription_id, &host_id, &host_epoch, &session_id)
            .to_string();
        let failed = super::super::write_reply(&ctx.writer, Some(line + "\n"))
            .await
            .is_err();
        if terminal || failed {
            break;
        }
    }
    cleanup_follow(&ctx, &broker, &subscription_id).await;
}

/// Free one connection follow slot and its broker record, idempotently: both
/// sides self-clean on their own exits, and this covers whichever side dies
/// first.
async fn cleanup_follow(ctx: &FollowCtx, broker: &Arc<AgentSessionsBroker>, subscription_id: &str) {
    ctx.follows
        .lock()
        .expect("follow registry")
        .retain(|id| id != subscription_id);
    broker.unfollow(subscription_id).await;
}

/// Handle one intercepted agent-sessions tool call. Always returns a local
/// reply (or `None` for a notification-shaped call without an id) plus, for
/// `follow`, a release the serving task fires after writing the reply frame;
/// nothing here is ever forwarded upstream.
pub async fn handle_agent_sessions_tool(
    broker: Option<&Arc<AgentSessionsBroker>>,
    ctx: &FollowCtx,
    message: &Value,
    modern: bool,
) -> (Option<String>, Option<PushRelease>) {
    let id = message.get("id");
    let name = message
        .pointer("/params/name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let args = message.pointer("/params/arguments");
    let (reply_value, release) = dispatch(broker, ctx, name, args).await;
    (tool_frame(id, reply_value, modern), release)
}

async fn dispatch(
    broker: Option<&Arc<AgentSessionsBroker>>,
    ctx: &FollowCtx,
    name: &str,
    args: Option<&Value>,
) -> (Value, Option<PushRelease>) {
    if name == TOOL_CAPABILITIES {
        let reply = match broker {
            None => protocol::tool_result(json!({
                "contract": super::config::AGENT_SESSIONS_CONTRACT,
                "operations": [],
            })),
            Some(broker) => protocol::tool_result(broker.capabilities_payload().await),
        };
        return (reply, None);
    }
    let Some(broker) = broker else {
        return (
            protocol::tool_refusal(
                "unavailable",
                "agent sessions are not configured on this node",
                json!({}),
            ),
            None,
        );
    };
    match name {
        TOOL_LIST => {
            let cursor = str_arg(args, "cursor");
            let reply = match broker.list(cursor.as_deref()).await {
                Ok(payload) => protocol::tool_result(payload),
                Err(refusal) => refusal.tool_value(),
            };
            (reply, None)
        }
        TOOL_HISTORY => {
            let (Some(host_id), Some(host_epoch), Some(session_id)) = (
                str_arg(args, "hostId"),
                str_arg(args, "hostEpoch"),
                str_arg(args, "sessionId"),
            ) else {
                return (invalid_history(), None);
            };
            if host_id.is_empty() || host_epoch.is_empty() || session_id.is_empty() {
                return (invalid_history(), None);
            }
            let cursor = args.and_then(|a| a.get("cursor")).cloned();
            let limit = args.and_then(|a| a.get("limit")).and_then(Value::as_u64);
            let reply = match broker
                .history(&host_id, &host_epoch, &session_id, cursor, limit)
                .await
            {
                Ok(page) => protocol::tool_result(page),
                Err(refusal) => refusal.tool_value(),
            };
            (reply, None)
        }
        TOOL_FOLLOW => {
            let (Some(host_id), Some(host_epoch), Some(session_id)) = (
                str_arg(args, "hostId"),
                str_arg(args, "hostEpoch"),
                str_arg(args, "sessionId"),
            ) else {
                return (invalid_follow(), None);
            };
            if host_id.is_empty() || host_epoch.is_empty() || session_id.is_empty() {
                return (invalid_follow(), None);
            }
            // Reserve the slot before awaiting the broker: concurrent
            // follows on this connection can never exceed the cap, and the
            // placeholder is released if the broker refuses.
            let placeholder = format!("pending:{}", uuid::Uuid::new_v4());
            {
                let mut follows = ctx.follows.lock().expect("follow registry");
                if follows.len() >= MAX_FOLLOWS_PER_CONNECTION {
                    return (
                        protocol::tool_refusal(
                            "busy",
                            "too many follows for this connection",
                            json!({}),
                        ),
                        None,
                    );
                }
                follows.push(placeholder.clone());
            }
            let release_slot = |ctx: &FollowCtx| {
                ctx.follows
                    .lock()
                    .expect("follow registry")
                    .retain(|id| id != &placeholder);
            };
            let (tx, rx) = mpsc::channel::<PushEvent>(super::broker::PUSH_CHANNEL_BOUND);
            match broker.follow(&host_id, &host_epoch, &session_id, tx).await {
                Ok((subscription_id, snapshot)) => {
                    // Swap the placeholder for the real id; the pusher
                    // frees the slot again when it ends.
                    {
                        let mut follows = ctx.follows.lock().expect("follow registry");
                        if let Some(slot) = follows.iter_mut().find(|id| *id == &placeholder) {
                            *slot = subscription_id.clone();
                        } else {
                            follows.push(subscription_id.clone());
                        }
                    }
                    let (release_tx, release_rx) = oneshot::channel();
                    tokio::spawn(forward_pushes(
                        ctx.clone(),
                        broker.clone(),
                        rx,
                        release_rx,
                        subscription_id.clone(),
                        host_id.clone(),
                        host_epoch.clone(),
                        session_id.clone(),
                    ));
                    (
                        protocol::tool_result(json!({
                            "subscriptionId": subscription_id,
                            "hostId": host_id,
                            "hostEpoch": host_epoch,
                            "sessionId": session_id,
                            "snapshot": snapshot,
                        })),
                        Some(PushRelease {
                            release: release_tx,
                        }),
                    )
                }
                Err(refusal) => {
                    release_slot(ctx);
                    (refusal.tool_value(), None)
                }
            }
        }
        TOOL_UNFOLLOW => {
            let Some(subscription_id) = str_arg(args, "subscriptionId") else {
                return (
                    protocol::tool_refusal("invalid", "unfollow needs subscriptionId", json!({})),
                    None,
                );
            };
            let owned = ctx
                .follows
                .lock()
                .expect("follow registry")
                .iter()
                .any(|id| id == &subscription_id);
            if owned {
                // The push task frees the slot again on exit; drop it here
                // too so a replacement follow is accepted at once.
                cleanup_follow(ctx, broker, &subscription_id).await;
            }
            (
                protocol::tool_result(json!({
                    "subscriptionId": subscription_id,
                    "unfollowed": owned,
                })),
                None,
            )
        }
        _ => (
            protocol::tool_refusal("invalid", "unknown agent-sessions tool", json!({})),
            None,
        ),
    }
}

fn invalid_history() -> Value {
    protocol::tool_refusal(
        "invalid",
        "history needs hostId, hostEpoch and sessionId",
        json!({}),
    )
}

fn invalid_follow() -> Value {
    protocol::tool_refusal(
        "invalid",
        "follow needs hostId, hostEpoch and sessionId",
        json!({}),
    )
}

/// Unfollow every subscription a closing connection owns. Frees poll tasks
/// and push buffers.
pub async fn close_connection_follows(broker: Option<&Arc<AgentSessionsBroker>>, ctx: &FollowCtx) {
    let ids: Vec<String> = std::mem::take(&mut *ctx.follows.lock().expect("follow registry"));
    if let Some(broker) = broker {
        for id in ids {
            broker.unfollow(&id).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{
        broker_for, epoch_of, password_env, run_until_reachable, FakeDaemon, FakeScript,
    };
    use super::*;
    use serde_json::json;

    fn configured_broker(url: &str) -> (tempfile::TempDir, Arc<AgentSessionsBroker>) {
        let dir = tempfile::tempdir().unwrap();
        let env = password_env(dir.path());
        let broker = broker_for(url, "srv_test", &env);
        // Keep the dir alive alongside the broker's env path.
        (dir, broker)
    }

    fn call(name: &str, arguments: Value) -> Value {
        json!({
            "jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":name,"arguments":arguments},
        })
    }

    fn code_of(reply: &str) -> String {
        let reply: Value = serde_json::from_str(reply).unwrap();
        reply["result"]["structuredContent"]["code"]
            .as_str()
            .unwrap_or("")
            .to_owned()
    }

    #[tokio::test]
    async fn unconfigured_capabilities_are_empty_and_others_unavailable() {
        let (ctx, _peer_reader, _peer_writer) = test_ctx();
        for name in [
            TOOL_CAPABILITIES,
            TOOL_LIST,
            TOOL_HISTORY,
            TOOL_FOLLOW,
            TOOL_UNFOLLOW,
        ] {
            let (reply, release) =
                handle_agent_sessions_tool(None, &ctx, &call(name, json!({})), false).await;
            assert!(release.is_none());
            let reply = reply.expect("a reply");
            let reply: Value = serde_json::from_str(&reply).unwrap();
            if name == TOOL_CAPABILITIES {
                assert_eq!(reply["result"]["isError"], false);
                assert_eq!(
                    reply["result"]["structuredContent"]["contract"],
                    super::super::config::AGENT_SESSIONS_CONTRACT
                );
                assert_eq!(
                    reply["result"]["structuredContent"]["operations"],
                    json!([])
                );
            } else {
                assert_eq!(reply["result"]["isError"], true);
                assert_eq!(reply["result"]["structuredContent"]["code"], "unavailable");
            }
        }
    }

    #[tokio::test]
    async fn unconfigured_history_is_unavailable_regardless_of_arguments() {
        let (ctx, _peer_reader, _peer_writer) = test_ctx();
        let (reply, _) = handle_agent_sessions_tool(
            None,
            &ctx,
            &call(TOOL_HISTORY, json!({"sessionId": "a"})),
            false,
        )
        .await;
        assert_eq!(code_of(&reply.expect("a reply")), "unavailable");
    }

    #[tokio::test]
    async fn argument_validation_with_configured_broker() {
        let fake = FakeDaemon::new(FakeScript::one()).await;
        let (_dir, broker) = configured_broker(&fake.url);
        let (ctx, _peer_reader, _peer_writer) = test_ctx();
        let some = Some(&broker);
        // Missing or empty address fields are refused before any daemon use:
        // the fake sees no reads for any of these.
        for (name, arguments) in [
            (TOOL_HISTORY, json!({"sessionId": "a"})),
            (
                TOOL_HISTORY,
                json!({"hostId": "h", "hostEpoch": "", "sessionId": "a"}),
            ),
            (TOOL_FOLLOW, json!({"hostId": "h"})),
            (
                TOOL_FOLLOW,
                json!({"hostId": "h", "hostEpoch": "e", "sessionId": ""}),
            ),
            (TOOL_UNFOLLOW, json!({})),
        ] {
            let (reply, release) =
                handle_agent_sessions_tool(some, &ctx, &call(name, arguments), false).await;
            assert!(release.is_none());
            assert_eq!(code_of(&reply.expect("a reply")), "invalid", "{name}");
        }
        // Unknown tool names are refused, never forwarded.
        let (reply, _) = handle_agent_sessions_tool(
            some,
            &ctx,
            &call("node_agent_sessions_bogus", json!({})),
            false,
        )
        .await;
        assert_eq!(code_of(&reply.expect("a reply")), "invalid");
        assert!(
            fake.received.lock().await.is_empty(),
            "validation must not touch the daemon"
        );
        fake.stop();
    }

    #[tokio::test]
    async fn wrong_host_is_gone_when_reachable() {
        let fake = FakeDaemon::new(FakeScript::one()).await;
        let (_dir, broker) = configured_broker(&fake.url);
        let run = run_until_reachable(&broker).await;
        let (ctx, _peer_reader, _peer_writer) = test_ctx();
        let some = Some(&broker);
        let (reply, _) = handle_agent_sessions_tool(
            some,
            &ctx,
            &call(
                TOOL_HISTORY,
                json!({"hostId": "srv_nope", "hostEpoch": "e", "sessionId": "a"}),
            ),
            false,
        )
        .await;
        assert_eq!(code_of(&reply.expect("a reply")), "gone");
        run.abort();
        fake.stop();
    }

    #[tokio::test]
    async fn full_connection_refuses_follow_with_busy() {
        let fake = FakeDaemon::new(FakeScript::one()).await;
        let (_dir, broker) = configured_broker(&fake.url);
        let (ctx, _peer_reader, _peer_writer) = test_ctx();
        ctx.follows
            .lock()
            .unwrap()
            .extend((0..MAX_FOLLOWS_PER_CONNECTION).map(|i| format!("sub-{i}")));
        let (reply, release) = handle_agent_sessions_tool(
            Some(&broker),
            &ctx,
            &call(
                TOOL_FOLLOW,
                json!({"hostId": "h", "hostEpoch": "e", "sessionId": "s"}),
            ),
            false,
        )
        .await;
        assert!(release.is_none());
        assert_eq!(code_of(&reply.expect("a reply")), "busy");
        fake.stop();
    }

    #[tokio::test]
    async fn concurrent_follows_cannot_exceed_the_cap() {
        let fake = FakeDaemon::new(FakeScript::one()).await;
        let (_dir, broker) = configured_broker(&fake.url);
        let run = run_until_reachable(&broker).await;
        let epoch = epoch_of(&broker).await;
        let (ctx, _peer_reader, _peer_writer) = test_ctx();
        let args = json!({"hostId": "srv_test", "hostEpoch": epoch, "sessionId": "a"});
        let attempts = (0..MAX_FOLLOWS_PER_CONNECTION + 2).map(|_| {
            let ctx = &ctx;
            let broker = &broker;
            let args = args.clone();
            async move {
                handle_agent_sessions_tool(Some(broker), ctx, &call(TOOL_FOLLOW, args), false).await
            }
        });
        let replies: Vec<_> = futures::future::join_all(attempts).await;
        let mut ok = 0;
        let mut busy = 0;
        let mut releases = Vec::new();
        for (reply, release) in replies {
            match code_of(&reply.expect("a reply")).as_str() {
                "" => {
                    ok += 1;
                    releases.push(release);
                }
                "busy" => {
                    busy += 1;
                    assert!(release.is_none());
                }
                other => panic!("unexpected follow outcome: {other}"),
            }
        }
        assert_eq!(ok, MAX_FOLLOWS_PER_CONNECTION);
        assert_eq!(busy, 2);
        // Fire the releases (the serve task does this after writing each
        // reply) so the established follows hold their slots.
        for release in releases.into_iter().flatten() {
            release.fire();
        }
        assert_eq!(
            ctx.follows.lock().unwrap().len(),
            MAX_FOLLOWS_PER_CONNECTION
        );
        // Clean up: unfollow everything this connection holds.
        let ids: Vec<String> = ctx.follows.lock().unwrap().clone();
        for id in ids {
            if id.starts_with("pending:") {
                continue;
            }
            let (reply, _) = handle_agent_sessions_tool(
                Some(&broker),
                &ctx,
                &call(TOOL_UNFOLLOW, json!({"subscriptionId": id})),
                false,
            )
            .await;
            assert_eq!(code_of(&reply.expect("a reply")), "");
        }
        run.abort();
        fake.stop();
    }

    #[tokio::test]
    async fn ended_follow_frees_its_slot() {
        let fake = FakeDaemon::new(FakeScript::one()).await;
        let (_dir, broker) = configured_broker(&fake.url);
        let run = run_until_reachable(&broker).await;
        let epoch = epoch_of(&broker).await;
        let (ctx, mut reader, _peer_writer) = test_ctx();
        let args = json!({"hostId": "srv_test", "hostEpoch": epoch, "sessionId": "a"});
        let (reply, release) = handle_agent_sessions_tool(
            Some(&broker),
            &ctx,
            &call(TOOL_FOLLOW, args.clone()),
            false,
        )
        .await;
        let reply: Value = serde_json::from_str(&reply.expect("a reply")).unwrap();
        let sub = reply["result"]["structuredContent"]["subscriptionId"]
            .as_str()
            .unwrap()
            .to_owned();
        release.expect("follow release").fire();
        // Remove the session: the poll ends the follow, the pusher writes
        // `ended` and frees this connection's slot.
        fake.script.lock().await.agents.clear();
        let mut ended = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(8);
        let mut buf = Vec::new();
        {
            use tokio::io::{AsyncBufReadExt, BufReader};
            let mut lines = BufReader::new(&mut reader).lines();
            while tokio::time::Instant::now() < deadline && !ended {
                let left = deadline.saturating_duration_since(tokio::time::Instant::now());
                match tokio::time::timeout(left, lines.next_line()).await {
                    Ok(Ok(Some(line))) => {
                        if line.contains("\"kind\":\"ended\"") {
                            ended = true;
                        }
                        buf.push(line);
                    }
                    _ => break,
                }
            }
        }
        assert!(ended, "expected an ended notification, got: {buf:?}");
        assert!(
            ctx.follows.lock().unwrap().is_empty(),
            "the ended follow must free its slot"
        );
        // A replacement follow is accepted at once on the freed slot.
        fake.script
            .lock()
            .await
            .agents
            .push(super::super::test_support::snap("a"));
        let (reply, release) =
            handle_agent_sessions_tool(Some(&broker), &ctx, &call(TOOL_FOLLOW, args), false).await;
        let reply: Value = serde_json::from_str(&reply.expect("a reply")).unwrap();
        assert_eq!(reply["result"]["isError"], false);
        assert!(release.is_some());
        let _ = sub;
        run.abort();
        fake.stop();
    }
}
