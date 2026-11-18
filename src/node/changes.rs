//! Node-local coarse invalidations. No event payloads, query execution or replay log.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::watch;

use super::failover::Failover;
use super::{write_reply, Result};

const CONTRACT: &str = "native.node-changes.v1";
const MAX_FOLLOWS: usize = 64;
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(super) struct Floor {
    pub act: Option<i64>,
    pub pending: u64,
    pub unresolved: bool,
    pub persistence_failed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Serving {
    pub generation_id: Option<String>,
    pub applied_act: Option<i64>,
    pub freshness: String,
    pub degraded_reasons: Vec<String>,
}
impl Default for Serving {
    fn default() -> Self {
        Self {
            generation_id: None,
            applied_act: None,
            freshness: "unavailable".into(),
            degraded_reasons: vec![],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Authority {
    pub hosted: String,
    pub checked: bool,
    pub revision_unsupported: bool,
}
impl Default for Authority {
    fn default() -> Self {
        Self {
            hosted: "not_checked".into(),
            checked: false,
            revision_unsupported: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cursor {
    epoch: String,
    sequence: u64,
}

#[derive(Clone, Debug, Serialize)]
struct Snapshot {
    contract: &'static str,
    account_id: String,
    origin_database_id: String,
    cursor: Cursor,
    serving: Serving,
    authority: Authority,
    write_floor: Floor,
    reason: &'static str,
}
struct State {
    snapshot: Snapshot,
    follows: usize,
}

/// One latest-value slot for the node. Each connection can retain just one
/// receiver; skipped sequences explicitly require a full host revalidation.
pub(super) struct Broker {
    state: Mutex<State>,
    sender: watch::Sender<Snapshot>,
}
impl Broker {
    pub fn new(account_id: String, origin_database_id: String, floor: Floor) -> Arc<Self> {
        let snapshot = Snapshot {
            contract: CONTRACT,
            account_id,
            origin_database_id,
            cursor: Cursor {
                epoch: uuid::Uuid::new_v4().to_string(),
                sequence: 0,
            },
            serving: Serving::default(),
            authority: Authority::default(),
            write_floor: floor,
            reason: "reset",
        };
        Arc::new(Self {
            sender: watch::channel(snapshot.clone()).0,
            state: Mutex::new(State {
                snapshot,
                follows: 0,
            }),
        })
    }
    pub fn has_followers(&self) -> bool {
        self.state.lock().expect("changes state").follows != 0
    }
    fn publish(&self, state: &mut State, reason: &'static str) {
        // Keep cursor numbers lossless for JavaScript consumers.
        if state.snapshot.cursor.sequence == 9_007_199_254_740_991 {
            state.snapshot.cursor.epoch = uuid::Uuid::new_v4().to_string();
            state.snapshot.cursor.sequence = 0;
        } else {
            state.snapshot.cursor.sequence += 1;
        }
        state.snapshot.reason = reason;
        self.sender.send_replace(state.snapshot.clone());
    }
    pub fn note_floor(&self, floor: Floor) {
        let mut state = self.state.lock().expect("changes state");
        if state.snapshot.write_floor != floor {
            state.snapshot.write_floor = floor;
            // Uses the previously observed serving stamp. A receipt or floor
            // is never evidence that the local reader advanced.
            self.publish(&mut state, "write_floor_changed");
        }
    }
    pub fn observe(&self, serving: Serving, authority: Authority) {
        let mut state = self.state.lock().expect("changes state");
        let old = &state.snapshot;
        if old.serving == serving && old.authority == authority {
            return;
        }
        let reason = if serving.generation_id.is_some()
            && old.serving.generation_id != serving.generation_id
        {
            "reset"
        } else if old.authority != authority || serving.generation_id.is_none() {
            "availability_changed"
        } else if old.serving.applied_act != serving.applied_act {
            match (old.serving.applied_act, serving.applied_act) {
                (Some(before), Some(after)) if after > before => "serving_advanced",
                _ => "reset",
            }
        } else {
            "availability_changed"
        };
        state.snapshot.serving = serving;
        state.snapshot.authority = authority;
        self.publish(&mut state, reason);
    }
    fn follow(
        self: &Arc<Self>,
        args: FollowArgs,
    ) -> std::result::Result<(Lease, watch::Receiver<Snapshot>, Snapshot, bool), &'static str> {
        let mut state = self.state.lock().expect("changes state");
        if args.account_id != state.snapshot.account_id
            || args.origin_database_id != state.snapshot.origin_database_id
        {
            return Err("binding_mismatch");
        }
        if state.follows == MAX_FOLLOWS {
            return Err("follow_limit");
        }
        // Register and take the baseline under the same lock used to publish.
        let receiver = self.sender.subscribe();
        let snapshot = state.snapshot.clone();
        let reset = args.after.as_ref() != Some(&snapshot.cursor);
        state.follows += 1;
        Ok((Lease(self.clone()), receiver, snapshot, reset))
    }
}
struct Lease(Arc<Broker>);
impl Drop for Lease {
    fn drop(&mut self) {
        self.0.state.lock().expect("changes state").follows -= 1;
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FollowArgs {
    account_id: String,
    origin_database_id: String,
    after: Option<Cursor>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnfollowArgs {
    subscription_id: String,
}

struct Follow {
    id: String,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Follow {
    fn drop(&mut self) {
        self.task.abort();
    }
}
/// Dropping this on ANY connection exit (including malformed frame, failed
/// write or task cancellation) stops its pusher and releases the node slot.
pub(super) struct Connection {
    follow: Option<Follow>,
    failed: super::Cancel,
}
impl Default for Connection {
    fn default() -> Self {
        Self {
            follow: None,
            failed: super::Cancel::new(),
        }
    }
}

fn delivery(snapshot: &Snapshot, id: &str, reset: bool) -> Value {
    json!({
        "contract":snapshot.contract,
        "subscription_id":id,
        "account_id":snapshot.account_id,
        "origin_database_id":snapshot.origin_database_id,
        "cursor":snapshot.cursor,
        "serving_generation_id":snapshot.serving.generation_id,
        "applied_act":snapshot.serving.applied_act,
        "availability":{
            "local_copy":if snapshot.serving.generation_id.is_some() && snapshot.serving.applied_act.is_some() {"serving"} else {"status_only"},
            "hosted":snapshot.authority.hosted,
            "checked":snapshot.authority.checked,
            "revision_unsupported":snapshot.authority.revision_unsupported,
            "freshness":snapshot.serving.freshness,
            "degraded_reasons":snapshot.serving.degraded_reasons,
        },
        "write_floor":snapshot.write_floor,
        "reason":if reset {"reset"} else {snapshot.reason},
        "reset_required":reset,
        "invalidate_all":true,
    })
}
fn error(request: &Value, reason: &str) -> Option<String> {
    request.get("id").map(|id| {
        json!({"jsonrpc":"2.0","id":id,"error":{
            "code":-32602,"message":"Node changes control refused", "data":{"reason":reason}
        }})
        .to_string()
    })
}
async fn control_reply(
    writer: &Arc<tokio::sync::Mutex<OwnedWriteHalf>>,
    reply: Option<String>,
) -> Result<()> {
    tokio::time::timeout(WRITE_TIMEOUT, write_reply(writer, reply))
        .await
        .map_err(|_| super::Error::engine("node changes reply timed out"))??;
    Ok(())
}
impl Connection {
    pub async fn failed(&self) {
        self.failed.cancelled().await;
    }

    pub async fn dispatch(
        &mut self,
        router: Option<&Arc<Failover>>,
        writer: &Arc<tokio::sync::Mutex<OwnedWriteHalf>>,
        request: &Value,
    ) -> Result<()> {
        let id = request.get("id");
        // Controls need reply IDs; notification-shaped calls allocate nothing.
        if id.is_none() {
            return Ok(());
        }
        if request["jsonrpc"] != "2.0" || !id.is_some_and(|id| id.is_number() || id.is_string()) {
            return control_reply(writer, error(request, "invalid_request")).await;
        }
        let Some(router) = router else {
            return control_reply(writer, error(request, "changes_unavailable")).await;
        };
        let method = request["method"].as_str().unwrap_or("");
        match method {
            "native/changes/follow" => {
                if self
                    .follow
                    .as_ref()
                    .is_some_and(|follow| follow.task.is_finished())
                {
                    self.follow.take();
                }
                if self.follow.is_some() {
                    return control_reply(writer, error(request, "already_following")).await;
                }
                let args = match serde_json::from_value::<FollowArgs>(request["params"].clone()) {
                    Ok(args) => args,
                    Err(_) => return control_reply(writer, error(request, "invalid_params")).await,
                };
                router.sample_changes().await;
                let (lease, mut receiver, snapshot, reset) = match router.changes.follow(args) {
                    Ok(follow) => follow,
                    Err(reason) => return control_reply(writer, error(request, reason)).await,
                };
                let subscription = uuid::Uuid::new_v4().to_string();
                // Do not spawn the pusher until the reply is fully on the wire.
                // Any change during this write remains in the receiver slot.
                tokio::time::timeout(WRITE_TIMEOUT, write_reply(writer, Some(json!({"jsonrpc":"2.0","id":id,"result":delivery(&snapshot, &subscription, reset)}).to_string())))
                    .await.map_err(|_| super::Error::engine("node changes reply timed out"))??;
                let writer = writer.clone();
                let push_id = subscription.clone();
                let failed = self.failed.clone();
                let task = tokio::spawn(async move {
                    let _lease = lease;
                    let mut cursor = snapshot.cursor;
                    while receiver.changed().await.is_ok() {
                        let current = receiver.borrow_and_update().clone();
                        let gap = current.cursor.epoch != cursor.epoch
                            || current.cursor.sequence != cursor.sequence.saturating_add(1);
                        let reset = gap || current.reason == "reset";
                        let params = delivery(&current, &push_id, reset);
                        let reply = json!({"jsonrpc":"2.0","method":"notifications/native_changes","params":params}).to_string();
                        // A bounded slow-consumer policy. This writes through
                        // the connection's sole serialized writer.
                        if !matches!(
                            tokio::time::timeout(WRITE_TIMEOUT, write_reply(&writer, Some(reply)))
                                .await,
                            Ok(Ok(()))
                        ) {
                            // End the socket rather than leave a silently dead follow.
                            failed.cancel();
                            break;
                        }
                        cursor = current.cursor;
                    }
                });
                self.follow = Some(Follow {
                    id: subscription,
                    task,
                });
                Ok(())
            }
            "native/changes/unfollow" => {
                let args = match serde_json::from_value::<UnfollowArgs>(request["params"].clone()) {
                    Ok(args) => args,
                    Err(_) => return control_reply(writer, error(request, "invalid_params")).await,
                };
                let removed = self
                    .follow
                    .as_ref()
                    .is_some_and(|follow| follow.id == args.subscription_id);
                if removed {
                    self.follow.take();
                }
                control_reply(
                    writer,
                    Some(
                        json!({"jsonrpc":"2.0","id":id,"result":{"unfollowed":removed}})
                            .to_string(),
                    ),
                )
                .await
            }
            _ => control_reply(writer, error(request, "unknown_changes_method")).await,
        }
    }
}

#[cfg(test)]
mod tests;
