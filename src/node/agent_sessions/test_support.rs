//! Shared fake Paseo daemon for agent-sessions tests: speaks the broker's
//! wire (bare `hello` in, session-wrapped `server_info` back, then session
//! envelopes both ways), records every inner post-hello frame, and lets tests
//! mutate sessions/timelines and drop the connection mid-test.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;

use super::broker::{AgentSessionsBroker, PushEvent};
use super::config::{AgentSessionsConfig, DaemonAuth, DaemonRef, AGENT_SESSIONS_CONTRACT};

pub fn snap(id: &str) -> Value {
    json!({
        "id": id,
        "provider": "claude",
        "model": "m",
        "status": "idle",
        "title": format!("title {id}"),
        "updatedAt": "2026-11-04T00:00:00.000Z",
        "createdAt": "2026-11-04T00:00:00.000Z",
        "workspaceId": "w1",
        "labels": {},
    })
}

pub fn text_entry(seq: i64, text: &str) -> Value {
    json!({"seqStart": seq, "item": {"type": "user_message", "text": text}})
}

pub struct FakeScript {
    pub server_id: String,
    pub agents: Vec<Value>,
    pub timelines: HashMap<String, Vec<Value>>,
}

impl FakeScript {
    pub fn one() -> Self {
        Self {
            server_id: "srv_test".into(),
            agents: vec![snap("a")],
            timelines: HashMap::from([("a".into(), vec![text_entry(1, "hi")])]),
        }
    }
}

fn server_info_frame(server_id: &str) -> Value {
    json!({
        "type": "session",
        "message": {
            "type": "status",
            "payload": {
                "status": "server_info",
                "protocolVersion": 1,
                "serverId": server_id,
            },
        },
    })
}

pub struct FakeDaemon {
    pub url: String,
    pub hellos: Arc<Mutex<Vec<Value>>>,
    pub received: Arc<Mutex<Vec<Value>>>,
    pub kill: Arc<AtomicBool>,
    /// When set, `fetch_agents_request` hangs instead of answering, to
    /// simulate a wedged daemon mid-discovery.
    pub hang_fetch: Arc<AtomicBool>,
    pub script: Arc<Mutex<FakeScript>>,
    task: JoinHandle<()>,
}

impl FakeDaemon {
    pub async fn new(script: FakeScript) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hellos = Arc::new(Mutex::new(Vec::new()));
        let received = Arc::new(Mutex::new(Vec::new()));
        let kill = Arc::new(AtomicBool::new(false));
        let hang_fetch = Arc::new(AtomicBool::new(false));
        let script = Arc::new(Mutex::new(script));
        let task = {
            let hellos = hellos.clone();
            let received = received.clone();
            let kill = kill.clone();
            let hang_fetch = hang_fetch.clone();
            let script = script.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let hellos = hellos.clone();
                    let received = received.clone();
                    let kill = kill.clone();
                    let hang_fetch = hang_fetch.clone();
                    let script = script.clone();
                    tokio::spawn(async move {
                        let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                            return;
                        };
                        let Some(Ok(tokio_tungstenite::tungstenite::Message::Text(hello))) =
                            ws.next().await
                        else {
                            return;
                        };
                        let Ok(hello): std::result::Result<Value, _> = serde_json::from_str(&hello)
                        else {
                            return;
                        };
                        hellos.lock().await.push(hello);
                        let server_id = script.lock().await.server_id.clone();
                        if ws
                            .send(tokio_tungstenite::tungstenite::Message::Text(
                                server_info_frame(&server_id).to_string().into(),
                            ))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        loop {
                            if kill.swap(false, Ordering::SeqCst) {
                                let _ = ws.close(None).await;
                                break;
                            }
                            let next =
                                tokio::time::timeout(Duration::from_millis(50), ws.next()).await;
                            let msg = match next {
                                Ok(Some(Ok(tokio_tungstenite::tungstenite::Message::Text(
                                    text,
                                )))) => text,
                                Ok(Some(Ok(_))) => continue,
                                Ok(Some(Err(_))) => break,
                                Ok(None) | Err(_) => continue,
                            };
                            let Ok(frame): std::result::Result<Value, _> =
                                serde_json::from_str(&msg)
                            else {
                                continue;
                            };
                            if frame.get("type").and_then(Value::as_str) != Some("session") {
                                break;
                            }
                            let inner = crate::node::daemon_client::unwrap_session(&frame).clone();
                            received.lock().await.push(inner.clone());
                            if inner.get("type").and_then(Value::as_str)
                                == Some("fetch_agents_request")
                            {
                                while hang_fetch.load(Ordering::SeqCst) {
                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                }
                            }
                            let reply = Self::reply_for(&script, &inner).await;
                            if let Some(reply) = reply {
                                let text = tokio_tungstenite::tungstenite::Message::Text(
                                    reply.to_string().into(),
                                );
                                if ws.send(text).await.is_err() {
                                    break;
                                }
                            }
                        }
                    });
                }
            })
        };
        Self {
            url: format!("ws://{addr}/ws"),
            hellos,
            received,
            kill,
            hang_fetch,
            script,
            task,
        }
    }

    async fn reply_for(script: &Arc<Mutex<FakeScript>>, inner: &Value) -> Option<Value> {
        let kind = inner.get("type").and_then(Value::as_str)?;
        match kind {
            "fetch_agents_request" => {
                let request_id = inner.get("requestId").cloned().unwrap_or(Value::Null);
                let script = script.lock().await;
                let entries: Vec<Value> = script
                    .agents
                    .iter()
                    .map(|agent| json!({"agent": agent, "project": {"workspaceName": "proj"}}))
                    .collect();
                Some(json!({
                    "type": "session",
                    "message": {
                        "type": "fetch_agents_response",
                        "payload": {
                            "requestId": request_id,
                            "entries": entries,
                            "pageInfo": {"nextCursor": null, "hasMore": false},
                        },
                    },
                }))
            }
            "fetch_agent_timeline_request" => {
                let request_id = inner.get("requestId").cloned().unwrap_or(Value::Null);
                let agent_id = inner.get("agentId").and_then(Value::as_str).unwrap_or("");
                let script = script.lock().await;
                let live = script
                    .agents
                    .iter()
                    .find(|a| a.get("id").and_then(Value::as_str) == Some(agent_id));
                match live {
                    None => Some(json!({
                        "type": "session",
                        "message": {
                            "type": "fetch_agent_timeline_response",
                            "payload": {
                                "requestId": request_id,
                                "agent": null,
                                "entries": [],
                                "epoch": "fake-epoch",
                            },
                        },
                    })),
                    Some(agent) => {
                        let entries = script.timelines.get(agent_id).cloned().unwrap_or_default();
                        Some(json!({
                            "type": "session",
                            "message": {
                                "type": "fetch_agent_timeline_response",
                                "payload": {
                                    "requestId": request_id,
                                    "agent": {"id": agent_id, "status": agent.get("status").and_then(Value::as_str).unwrap_or("idle")},
                                    "entries": entries,
                                    "epoch": "fake-epoch",
                                    "startCursor": null,
                                    "endCursor": null,
                                    "hasOlder": false,
                                    "hasNewer": false,
                                },
                            },
                        }))
                    }
                }
            }
            "ping" => Some(json!({
                "type": "session",
                "message": {"type": "pong"},
            })),
            _ => None,
        }
    }

    pub fn stop(&self) {
        self.task.abort();
    }
}

pub fn password_env(dir: &std::path::Path) -> std::path::PathBuf {
    let env = dir.join("p.env");
    std::fs::write(&env, "PASEO_PASSWORD=test-password\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    env
}

pub fn broker_for(url: &str, server_id: &str, env: &std::path::Path) -> Arc<AgentSessionsBroker> {
    let config = AgentSessionsConfig {
        contract: AGENT_SESSIONS_CONTRACT.into(),
        remote: None,
        daemon: DaemonRef {
            url: url.into(),
            server_id: server_id.into(),
            auth: DaemonAuth::PasswordEnvFile {
                path: env.to_str().unwrap().into(),
                key: "PASEO_PASSWORD".into(),
            },
        },
    };
    AgentSessionsBroker::new(config)
}

pub async fn recv_timeout(rx: &mut mpsc::Receiver<PushEvent>, label: &str) -> PushEvent {
    tokio::time::timeout(Duration::from_secs(8), rx.recv())
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"))
        .expect("sender alive")
}

/// Spawn the broker worker and wait until the host table reports reachable.
pub async fn run_until_reachable(broker: &Arc<AgentSessionsBroker>) -> tokio::task::JoinHandle<()> {
    let task = tokio::spawn(broker.clone().run());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if broker.host_summary().await["status"] == "reachable" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("broker did not become reachable");
    task
}

/// Current host epoch, for stale-epoch assertions.
pub async fn epoch_of(broker: &Arc<AgentSessionsBroker>) -> String {
    broker.host_summary().await["epoch"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}
