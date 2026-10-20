//! Hosted persistence worker over the connection owner's typed mailbox.
//! A selection revision fences every await; this module never owns a socket.

use std::collections::BTreeMap;
use std::future::Future;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::session_actor::{AgentView, DaemonHandle, Selection};
use super::session_control::{SaveRequest, SaveStatus};
use super::session_persist::SessionStore;
use super::session_stream::{BoundedSource, SourcePoll};
use super::session_writer::{CatchupAction, CatchupContext, HostedSink, StateAction, Writer};
use crate::error::{Error, Result};

pub(super) const UNSUPPORTED_WRITER: &str = "saved-session keyed writes are unsupported";
pub(super) const QUARANTINED_BATCH: &str = "saved-session batch quarantined";

/// All fields come from the node binding or authenticated connection, never
/// from agent labels. The boot clock is shared across all source windows.
pub struct WorkerContext<'a> {
    pub server: &'a str,
    pub boot: &'a str,
    pub host_label: &'a str,
    pub pending_limit: usize,
    pub started: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentActivity {
    Working,
    Idle,
    WaitingPermission,
}
impl AgentActivity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Working => "working",
            Self::Idle => "idle",
            Self::WaitingPermission => "waiting_permission",
        }
    }
}

/// Read the shipping protocol's lifecycle rather than an inferred UI state.
/// Missing fields conservatively retain the open group.
pub fn turn_ended(snapshot: &Value) -> bool {
    snapshot.get("activeTurn").is_some_and(Value::is_null)
        && snapshot
            .get("pendingPermissions")
            .and_then(Value::as_array)
            .is_some_and(|p| p.is_empty())
        && matches!(
            snapshot.get("status").and_then(Value::as_str),
            Some("idle" | "error" | "closed")
        )
}
pub fn activity(snapshot: &Value) -> AgentActivity {
    if snapshot
        .get("pendingPermissions")
        .and_then(Value::as_array)
        .is_some_and(|p| !p.is_empty())
    {
        AgentActivity::WaitingPermission
    } else if snapshot.get("status").and_then(Value::as_str) == Some("running")
        || snapshot.get("activeTurn").is_some_and(|v| !v.is_null())
    {
        AgentActivity::Working
    } else {
        AgentActivity::Idle
    }
}

pub fn archived(snapshot: &Value) -> bool {
    super::session_control::agent_archived(snapshot)
}

fn current(handle: &DaemonHandle, agent: &str, selection: &Selection) -> Option<AgentView> {
    let view = handle.view.borrow();
    (!view.closed)
        .then(|| {
            view.agents
                .get(agent)
                .filter(|a| &a.selection == selection && !archived(&a.snapshot))
                .cloned()
        })
        .flatten()
}

/// Dropping an in-flight write leaves its frozen intent/journal for keyed
/// recovery. A late reply cannot authorize the next source step after Stop.
async fn selected_call<T>(
    handle: &DaemonHandle,
    agent: &str,
    selection: &Selection,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    let mut view = handle.view.clone();
    tokio::pin!(operation);
    loop {
        if current(handle, agent, selection).is_none() {
            return Err(Error::engine("saved-session selection revoked"));
        }
        tokio::select! {
            result = &mut operation => {
                if current(handle, agent, selection).is_none() { return Err(Error::engine("saved-session selection revoked")); }
                return result;
            }
            changed = view.changed() => {
                if changed.is_err() { return Err(Error::engine("daemon connection closed")); }
            }
        }
    }
}

async fn wait_selected(
    handle: &DaemonHandle,
    agent: &str,
    selection: &Selection,
    duration: Duration,
) -> Result<()> {
    selected_call(handle, agent, selection, async {
        tokio::time::sleep(duration).await;
        Ok(())
    })
    .await
}

async fn wait_changed_selected(
    handle: &DaemonHandle,
    agent: &str,
    selection: &Selection,
    duration: Duration,
) -> Result<()> {
    let mut changed = handle.view.clone();
    selected_call(handle,agent,selection,async {
        tokio::select! {
            change = changed.changed() => change.map_err(|_|Error::engine("daemon connection closed")),
            _ = tokio::time::sleep(duration) => Ok(()),
        }
    }).await
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
fn tick(context: &WorkerContext<'_>) -> u64 {
    context.started.elapsed().as_millis().min(u64::MAX as u128) as u64
}
fn check_action(action: &StateAction) -> Result<()> {
    match action {
        StateAction::AuthRefused => Err(Error::Auth(
            "saved-session state write refused authentication".into(),
        )),
        StateAction::Unsupported => Err(Error::engine(UNSUPPORTED_WRITER)),
        StateAction::Superseded => Err(Error::engine(format!(
            "saved-session state writer stopped: {action:?}"
        ))),
        _ => Ok(()),
    }
}

/// A successful keyed replay may describe an older proposal. Verify the
/// desired state and current lease before advancing the driver's state cache.
async fn desired_state<S: HostedSink>(
    writer: &Writer<'_, S>,
    store: &SessionStore,
    handle: &DaemonHandle,
    agent: &str,
    selection: &Selection,
    context: &WorkerContext<'_>,
    facets: BTreeMap<String, Value>,
) -> Result<()> {
    loop {
        let action = selected_call(
            handle,
            agent,
            selection,
            writer.write_session_state(agent, context.server, context.boot, &now(), facets.clone()),
        )
        .await?;
        check_action(&action)?;
        if matches!(action, StateAction::Written | StateAction::Settled) {
            let state = selected_call(
                handle,
                agent,
                selection,
                writer.read_owned_session_state(agent),
            )
            .await?;
            let checkpoint = store.load_checkpoint(agent)?;
            if state.claim.generation != checkpoint.writer_generation
                || checkpoint.lease_writer.as_deref() != Some(state.claim.writer.as_str())
            {
                store.latch_lease_stopped(agent)?;
                return Err(Error::engine("state replay settled under another writer"));
            }
            if facets.iter().all(|(key, value)| {
                state.facets.get(key).is_some_and(|text| match value {
                    Value::String(s) => text == s,
                    _ => serde_json::from_str::<Value>(text).ok().as_ref() == Some(value),
                })
            }) {
                return Ok(());
            }
        }
        wait_selected(handle, agent, selection, Duration::from_secs(1)).await?;
    }
}

/// Drive one positively selected agent. The supervisor serializes revisions
/// of the same agent and handles retirement after this future is cancelled.
pub async fn drive_selected<S: HostedSink>(
    writer: &Writer<'_, S>,
    store: &SessionStore,
    handle: &DaemonHandle,
    agent: &str,
    selection: &Selection,
    context: &WorkerContext<'_>,
    observed_replacement: bool,
) -> Result<()> {
    let request = SaveRequest::parse(&selection.label)
        .filter(|r| r.authorizes_save(store.binding()))
        .ok_or_else(|| Error::engine("hosted worker requires a bound Save request"))?;
    if store.load_checkpoint(agent)?.lease_stopped {
        return Err(Error::engine("saved-session writer is superseded"));
    }
    let checkpoint = store.load_checkpoint(agent)?;
    if checkpoint.terminal_save_label.as_deref() == Some(selection.label.as_str()) {
        return Err(match checkpoint.terminal_save_code.as_deref() {
            Some("auth") => {
                Error::Auth("saved-session request stopped after authentication refusal".into())
            }
            Some("quarantined") => Error::engine(QUARANTINED_BATCH),
            Some("unsupported") => Error::engine(UNSUPPORTED_WRITER),
            Some("schema") => Error::engine(super::session_writer::SCHEMA_REQUIRED),
            _ => Error::engine("saved-session request is durably stopped after an error"),
        });
    }
    let accepted = SaveStatus::Accepted {
        request: request.request_id().to_owned(),
    };
    // A restored same UUID may be rate limited. Do not start saving until
    // this selection's actual Accepted send succeeds.
    loop {
        let sent = selected_call(
            handle,
            agent,
            selection,
            handle.status(agent, selection, accepted.clone()),
        )
        .await?;
        if sent == Some(accepted.clone()) {
            break;
        }
        wait_selected(handle, agent, selection, Duration::from_secs(1)).await?;
    }
    let selected =
        current(handle, agent, selection).ok_or_else(|| Error::engine("Save selection revoked"))?;
    let title = selected
        .snapshot
        .get("title")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("Agent session");
    let provider = selected
        .snapshot
        .get("provider")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::engine("agent snapshot lacks provider"))?;
    selected_call(
        handle,
        agent,
        selection,
        writer.ensure_session(
            agent,
            context.server,
            "Saved sessions",
            title,
            context.host_label,
            provider,
            context.boot,
            &now(),
        ),
    )
    .await?;
    loop {
        let action = selected_call(
            handle,
            agent,
            selection,
            writer.claim_state_lease(agent, context.server, context.boot, &now()),
        )
        .await?;
        check_action(&action)?;
        match action {
            StateAction::Held => break,
            StateAction::NotEligible => {
                return Err(Error::engine("saved-session lease held by a fresh writer"))
            }
            _ => wait_selected(handle, agent, selection, Duration::from_secs(1)).await?,
        }
    }
    let selected =
        current(handle, agent, selection).ok_or_else(|| Error::engine("Save selection revoked"))?;
    let mut checkpoint = store.load_checkpoint(agent)?;
    if checkpoint.terminal_save_label.is_some() {
        checkpoint.terminal_save_label = None;
        checkpoint.terminal_save_code = None;
        store.save_checkpoint(&checkpoint)?;
    }
    let initial_activity = activity(&selected.snapshot);
    desired_state(
        writer,
        store,
        handle,
        agent,
        selection,
        context,
        BTreeMap::from([
            ("native.session.state".into(), json!("saving")),
            (
                "native.session.activity".into(),
                json!(initial_activity.as_str()),
            ),
        ]),
    )
    .await?;
    store.mark_needs_realign(agent)?;
    let chain = selected_call(
        handle,
        agent,
        selection,
        writer.verified_chain_live(agent, context.server, context.boot),
    )
    .await?;
    let state = selected_call(
        handle,
        agent,
        selection,
        writer.read_owned_session_state(agent),
    )
    .await?;
    let branch = state
        .facets
        .get("native.session.source_branch")
        .map(|s| {
            s.parse::<u64>()
                .map_err(|_| Error::engine("invalid hosted source branch"))
        })
        .transpose()?;
    let checkpoint = store.load_checkpoint(agent)?;
    let mut source = BoundedSource::new(
        agent,
        chain,
        branch,
        checkpoint.cursor_epoch,
        observed_replacement,
        false,
        context.pending_limit,
    )?;
    let mut source_dirty = selected.dirty;
    let mut source_ended = turn_ended(&selected.snapshot);
    let mut saved_activity = Some(initial_activity);
    let mut saving = true;
    let mut backlogged = false;
    let mut heartbeat_at = 0;
    loop {
        let selected = current(handle, agent, selection)
            .ok_or_else(|| Error::engine("Save selection revoked"))?;
        match source.poll(turn_ended(&selected.snapshot))? {
            SourcePoll::Fetch { cursor } => {
                let frame = selected_call(
                    handle,
                    agent,
                    selection,
                    handle.fetch(agent, selection, cursor),
                )
                .await?;
                let id = frame
                    .pointer("/payload/requestId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::engine("timeline response lacks correlation"))?;
                let action = source.accept_page(&frame, id)?;
                if matches!(action, super::session_catchup::FetchAction::Backlog) {
                    let facets = BTreeMap::from([
                        ("native.session.state".into(), json!("paused")),
                        ("native.session.paused_reason".into(), json!("backlog")),
                    ]);
                    desired_state(writer, store, handle, agent, selection, context, facets).await?;
                    selected_call(
                        handle,
                        agent,
                        selection,
                        handle.status(
                            agent,
                            selection,
                            SaveStatus::Paused {
                                reason: "backlog".into(),
                            },
                        ),
                    )
                    .await?;
                    return Err(Error::engine(
                        "source page exceeds bounded pending byte budget",
                    ));
                }
                if matches!(action, super::session_catchup::FetchAction::Restart) {
                    store.mark_needs_realign(agent)?;
                    return Err(Error::Conflict(
                        "source changed during bounded fetch".into(),
                    ));
                }
            }
            SourcePoll::Window => {
                let produced = source.take_window()?;
                let snapshot = produced.source.snapshot.clone();
                let catchup_context = CatchupContext {
                    agent_id: agent.to_owned(),
                    daemon_server_id: context.server.to_owned(),
                    boot_id: context.boot.to_owned(),
                    host_label: context.host_label.to_owned(),
                    observed_replacement: produced.observed_replacement,
                    unknown_continuity: produced.unknown_continuity,
                };
                let mut run = selected_call(
                    handle,
                    agent,
                    selection,
                    writer.prepare_catchup_live(produced.source, catchup_context),
                )
                .await?;
                source.settle_from(&run)?;
                loop {
                    let action = selected_call(
                        handle,
                        agent,
                        selection,
                        writer.pump_catchup(&mut run, &snapshot, &now(), tick(context)),
                    )
                    .await?;
                    source.settle_from(&run)?;
                    match action {
                        CatchupAction::WindowComplete | CatchupAction::Complete => {
                            let chain = selected_call(
                                handle,
                                agent,
                                selection,
                                writer.verified_chain_live(agent, context.server, context.boot),
                            )
                            .await?;
                            source.finish_window(&run, chain, &action)?;
                            break;
                        }
                        CatchupAction::Quarantined => return Err(Error::engine(QUARANTINED_BATCH)),
                        CatchupAction::Realign => {
                            return Err(Error::Conflict(
                                "saved-session chain requires realignment".into(),
                            ))
                        }
                        CatchupAction::State(ref action) => check_action(action)?,
                        _ => {}
                    }
                    wait_selected(handle, agent, selection, Duration::from_millis(250)).await?;
                }
                loop {
                    let action = selected_call(
                        handle,
                        agent,
                        selection,
                        writer.recover_quote_links(agent, context.server, context.boot),
                    )
                    .await?;
                    check_action(&action)?;
                    if action == StateAction::Written {
                        break;
                    }
                    wait_selected(handle, agent, selection, Duration::from_secs(1)).await?;
                }
                backlogged = false;
                let checkpoint = store.load_checkpoint(agent)?;
                let status = SaveStatus::Persisted {
                    confirmed_pos: checkpoint.head_pos.unwrap_or(0),
                    folder: checkpoint
                        .folder_id
                        .ok_or_else(|| Error::engine("confirmed session lacks folder"))?,
                    pending: source.pending_entries() as u64,
                };
                selected_call(
                    handle,
                    agent,
                    selection,
                    handle.status(agent, selection, status),
                )
                .await?;
            }
            SourcePoll::Backlog => {
                let facets = BTreeMap::from([
                    ("native.session.state".into(), json!("paused")),
                    ("native.session.paused_reason".into(), json!("backlog")),
                ]);
                if !backlogged {
                    desired_state(writer, store, handle, agent, selection, context, facets).await?;
                    saving = false;
                    backlogged = true;
                }
                selected_call(
                    handle,
                    agent,
                    selection,
                    handle.status(
                        agent,
                        selection,
                        SaveStatus::Paused {
                            reason: "backlog".into(),
                        },
                    ),
                )
                .await?;
                wait_changed_selected(handle, agent, selection, Duration::from_secs(5)).await?;
                let selected = current(handle, agent, selection)
                    .ok_or_else(|| Error::engine("Save selection revoked"))?;
                source_dirty = selected.dirty;
                source_ended = turn_ended(&selected.snapshot);
                source.refresh()?;
                continue;
            }
            SourcePoll::Idle => {
                if selected.dirty != source_dirty || turn_ended(&selected.snapshot) != source_ended
                {
                    source_dirty = selected.dirty;
                    source_ended = turn_ended(&selected.snapshot);
                    source.refresh()?;
                } else {
                    // A clean, caught-up source sleeps on the coalesced watch;
                    // heartbeat checks do not trigger a full history re-fetch.
                    wait_changed_selected(handle, agent, selection, Duration::from_secs(30))
                        .await?;
                }
            }
        }
        let selected = current(handle, agent, selection)
            .ok_or_else(|| Error::engine("Save selection revoked"))?;
        let next_activity = activity(&selected.snapshot);
        if !backlogged && (!saving || saved_activity != Some(next_activity)) {
            let facets = BTreeMap::from([
                ("native.session.state".into(), json!("saving")),
                (
                    "native.session.activity".into(),
                    json!(next_activity.as_str()),
                ),
            ]);
            desired_state(writer, store, handle, agent, selection, context, facets).await?;
            saving = true;
            saved_activity = Some(next_activity);
        }
        if saving && tick(context) >= heartbeat_at {
            let action = selected_call(
                handle,
                agent,
                selection,
                writer.heartbeat(agent, context.server, context.boot, &now()),
            )
            .await?;
            check_action(&action)?;
            heartbeat_at = tick(context).saturating_add(30_000);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn stop_revokes_an_inflight_operation_even_when_the_same_request_is_restored() {
        use crate::node::session_actor::mailbox;
        use crate::node::session_persist::Binding;
        let binding = Binding::new("server", "acct", "db", None).unwrap();
        let (handle, mut mailbox) = mailbox(binding);
        let label = "v1;acct=acct;db=db;req=00000000-0000-4000-8000-000000000000";
        mailbox
            .directory(&std::collections::HashMap::from([(
                "a".into(),
                json!({"id":"a","labels":{"native.save":label}}),
            )]))
            .unwrap();
        let selection = handle.view.borrow().agents["a"].selection.clone();
        let operation = selected_call(
            &handle,
            "a",
            &selection,
            std::future::pending::<Result<()>>(),
        );
        let revoke = async {
            tokio::task::yield_now().await;
            mailbox
                .directory(&std::collections::HashMap::new())
                .unwrap();
            mailbox
                .directory(&std::collections::HashMap::from([(
                    "a".into(),
                    json!({"id":"a","labels":{"native.save":label}}),
                )]))
                .unwrap();
        };
        let (result, ()) = tokio::join!(operation, revoke);
        assert!(result.is_err());
        assert_ne!(handle.view.borrow().agents["a"].selection, selection);
    }

    #[test]
    fn incomplete_or_permission_blocked_turn_never_forces_source_closed() {
        assert!(!turn_ended(&json!({"status":"idle"})));
        assert!(!turn_ended(
            &json!({"status":"running","activeTurn":{"turnId":"t"},"pendingPermissions":[]})
        ));
        assert!(!turn_ended(
            &json!({"status":"idle","activeTurn":null,"pendingPermissions":[{"id":"p"}]})
        ));
        assert!(turn_ended(
            &json!({"status":"idle","activeTurn":null,"pendingPermissions":[]})
        ));
    }
    #[test]
    fn permission_state_takes_precedence_over_running_activity() {
        assert_eq!(
            activity(
                &json!({"status":"running","activeTurn":{"turnId":"t"},"pendingPermissions":[{}]})
            ),
            AgentActivity::WaitingPermission
        );
        assert_eq!(
            activity(
                &json!({"status":"running","activeTurn":{"turnId":"t"},"pendingPermissions":[]})
            ),
            AgentActivity::Working
        );
    }
}
