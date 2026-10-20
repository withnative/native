//! Connection-local mailbox for the serialized daemon reader. A hosted worker
//! cannot send arbitrary daemon messages, retain authority across a selection
//! change, or mistake a response from a prior connection for its own fetch.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::Value;
use tokio::sync::{mpsc, oneshot, watch};

use crate::error::{Error, Result};

use super::session_control::{SaveRequest, SaveStatus};
use super::session_persist::Binding;

const COMMAND_CAPACITY: usize = 16;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    pub label: String,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentView {
    pub selection: Selection,
    pub snapshot: Value,
    pub dirty: u64,
    pub replacements: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionView {
    pub agents: HashMap<String, AgentView>,
    pub snapshots: HashMap<String, Value>,
    pub ready: bool,
    pub closed: bool,
}

/// The only worker requests accepted by the connection owner. There is no
/// prompt, create-agent, label patch, or arbitrary JSON send operation.
pub(super) enum Command {
    Fetch {
        agent: String,
        selection: Selection,
        cursor: Option<Value>,
        reply: oneshot::Sender<Result<Value>>,
    },
    Status {
        agent: String,
        selection: Selection,
        status: SaveStatus,
        reply: oneshot::Sender<Result<Option<SaveStatus>>>,
    },
}

#[derive(Clone)]
pub struct DaemonHandle {
    commands: mpsc::Sender<Command>,
    pub view: watch::Receiver<ConnectionView>,
}

impl DaemonHandle {
    pub async fn fetch(
        &self,
        agent: &str,
        selection: &Selection,
        cursor: Option<Value>,
    ) -> Result<Value> {
        let (reply, received) = oneshot::channel();
        let command = Command::Fetch {
            agent: agent.to_owned(),
            selection: selection.clone(),
            cursor,
            reply,
        };
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            self.commands
                .send(command)
                .await
                .map_err(|_| Error::engine("daemon connection closed"))?;
            received
                .await
                .map_err(|_| Error::engine("daemon fetch cancelled"))?
        })
        .await
        .map_err(|_| Error::engine("daemon timeline request timed out"))?
    }

    pub async fn status(
        &self,
        agent: &str,
        selection: &Selection,
        status: SaveStatus,
    ) -> Result<Option<SaveStatus>> {
        let (reply, received) = oneshot::channel();
        let command = Command::Status {
            agent: agent.to_owned(),
            selection: selection.clone(),
            status,
            reply,
        };
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            self.commands
                .send(command)
                .await
                .map_err(|_| Error::engine("daemon connection closed"))?;
            received
                .await
                .map_err(|_| Error::engine("daemon status cancelled"))?
        })
        .await
        .map_err(|_| Error::engine("daemon status request timed out"))?
    }
}

struct Pending {
    agent: String,
    selection: Selection,
    reply: oneshot::Sender<Result<Value>>,
}

pub(super) struct Mailbox {
    pub commands: mpsc::Receiver<Command>,
    view: watch::Sender<ConnectionView>,
    pending: HashMap<String, Pending>,
    /// Tombstones preserve revisions across remove/re-add. Otherwise an old
    /// request could gain authority again when the same label is restored.
    revisions: HashMap<String, u64>,
    binding: Binding,
}

pub(super) fn mailbox(binding: Binding) -> (DaemonHandle, Mailbox) {
    let (commands_tx, commands) = mpsc::channel(COMMAND_CAPACITY);
    let (view, receiver) = watch::channel(ConnectionView::default());
    (
        DaemonHandle {
            commands: commands_tx,
            view: receiver,
        },
        Mailbox {
            commands,
            view,
            pending: HashMap::new(),
            revisions: HashMap::new(),
            binding,
        },
    )
}

impl Mailbox {
    pub fn selected(&self, agent: &str, selection: &Selection) -> bool {
        let view = self.view.borrow();
        !view.closed
            && view
                .agents
                .get(agent)
                .is_some_and(|a| &a.selection == selection)
            && SaveRequest::parse(&selection.label)
                .is_some_and(|r| r.authorizes_save(&self.binding))
    }

    /// Atomically publish the latest directory to workers; never queue old
    /// directory frames behind hosted I/O. Retire outstanding replies before
    /// waking workers so no old selection can consume a newer result.
    pub fn directory(&mut self, snapshots: &HashMap<String, Value>) -> Result<()> {
        let previous = self.view.borrow().clone();
        if previous.closed {
            return Err(Error::engine("daemon connection already closed"));
        }
        let mut next = ConnectionView {
            snapshots: snapshots.clone(),
            ready: true,
            ..ConnectionView::default()
        };
        for (id, snapshot) in snapshots {
            if super::session_control::agent_archived(snapshot) {
                continue;
            }
            let Some(label) = snapshot
                .pointer("/labels/native.save")
                .and_then(Value::as_str)
            else {
                continue;
            };
            let Some(request) = SaveRequest::parse(label) else {
                continue;
            };
            if !request.authorizes_save(&self.binding) {
                continue;
            }
            let old = previous.agents.get(id);
            let revision = if old.is_some_and(|a| a.selection.label == label) {
                old.expect("checked old view").selection.revision
            } else {
                self.next_revision(id)?
            };
            next.agents.insert(
                id.clone(),
                AgentView {
                    selection: Selection {
                        label: label.to_owned(),
                        revision,
                    },
                    snapshot: snapshot.clone(),
                    dirty: old.map_or(0, |a| a.dirty),
                    replacements: old.map_or(0, |a| a.replacements),
                },
            );
        }
        for id in previous.agents.keys() {
            if !next.agents.contains_key(id) {
                self.next_revision(id)?;
            }
        }
        self.pending.retain(|_, p| {
            !p.reply.is_closed()
                && next
                    .agents
                    .get(&p.agent)
                    .is_some_and(|a| a.selection == p.selection)
        });
        if previous != next {
            self.view.send_replace(next);
        }
        Ok(())
    }

    fn next_revision(&mut self, agent: &str) -> Result<u64> {
        let previous = self.revisions.get(agent).copied().unwrap_or(0);
        let next = previous
            .checked_add(1)
            .ok_or_else(|| Error::engine("daemon selection revision exhausted"))?;
        self.revisions.insert(agent.to_owned(), next);
        Ok(next)
    }

    /// Replacement invalidates both the in-flight page and already queued
    /// commands, even when the Save label and agent id stayed identical.
    pub fn wake(&mut self, agent: &str, replacement: bool) -> Result<()> {
        let mut view = self.view.borrow().clone();
        let Some(current) = view.agents.get_mut(agent) else {
            return Ok(());
        };
        current.dirty = current.dirty.saturating_add(1);
        if replacement {
            current.replacements = current
                .replacements
                .checked_add(1)
                .ok_or_else(|| Error::engine("source replacement counter exhausted"))?;
            current.selection.revision = self.next_revision(agent)?;
            self.pending.retain(|_, p| p.agent != agent);
        }
        self.view.send_replace(view);
        Ok(())
    }

    pub fn register(
        &mut self,
        id: String,
        agent: String,
        selection: Selection,
        reply: oneshot::Sender<Result<Value>>,
    ) -> Result<()> {
        self.pending.retain(|_, p| !p.reply.is_closed());
        if !self.selected(&agent, &selection) || reply.is_closed() {
            return Err(Error::engine("timeline request lost its Save authority"));
        }
        if self.pending.values().any(|p| p.agent == agent) || self.pending.contains_key(&id) {
            return Err(Error::engine("timeline request already outstanding"));
        }
        self.pending.insert(
            id,
            Pending {
                agent,
                selection,
                reply,
            },
        );
        Ok(())
    }

    pub fn response(&mut self, frame: &Value) {
        let Some(id) = frame.pointer("/payload/requestId").and_then(Value::as_str) else {
            return;
        };
        let Some(pending) = self.pending.remove(id) else {
            return;
        };
        let answer = if frame["type"] != "fetch_agent_timeline_response"
            || frame["payload"]["agentId"] != pending.agent
            || !self.selected(&pending.agent, &pending.selection)
        {
            Err(Error::engine(
                "timeline response lost correlation or Save authority",
            ))
        } else {
            Ok(frame.clone())
        };
        let _ = pending.reply.send(answer);
    }

    pub fn close(&mut self) {
        self.pending.clear();
        self.commands.close();
        self.view.send_replace(ConnectionView {
            closed: true,
            ..ConnectionView::default()
        });
    }
}

impl Drop for Mailbox {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshots() -> HashMap<String, Value> {
        HashMap::from([(
            "agent".into(),
            json!({"id":"agent", "labels":{"native.save":"v1;acct=a;db=d;req=123e4567-e89b-12d3-a456-426614174000"}}),
        )])
    }
    fn setup() -> (DaemonHandle, Mailbox) {
        mailbox(Binding::new("server", "a", "d", None).unwrap())
    }
    fn selection(handle: &DaemonHandle) -> Selection {
        handle.view.borrow().agents["agent"].selection.clone()
    }

    #[test]
    fn archive_then_unarchive_cannot_restore_old_fetch_authority() {
        let (handle, mut actor) = setup();
        actor.directory(&snapshots()).unwrap();
        let old = selection(&handle);
        let (tx, mut rx) = oneshot::channel();
        actor
            .register("r".into(), "agent".into(), old.clone(), tx)
            .unwrap();
        let mut archived = snapshots();
        archived.get_mut("agent").unwrap()["archivedAt"] = json!("2026-10-18T00:00:00Z");
        actor.directory(&archived).unwrap();
        assert!(!actor.selected("agent", &old));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        actor.directory(&snapshots()).unwrap();
        assert_ne!(selection(&handle), old);
        assert!(!actor.selected("agent", &old));
    }

    #[test]
    fn stop_and_same_label_readd_never_restore_old_authority() {
        let (handle, mut actor) = setup();
        actor.directory(&snapshots()).unwrap();
        let old = selection(&handle);
        let (tx, mut rx) = oneshot::channel();
        actor
            .register("r".into(), "agent".into(), old.clone(), tx)
            .unwrap();
        actor.directory(&HashMap::new()).unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        actor.directory(&snapshots()).unwrap();
        assert!(!actor.selected("agent", &old));
        assert!(actor.selected("agent", &selection(&handle)));
    }

    #[test]
    fn live_wakeup_preserves_fetch_but_replacement_fences_it() {
        let (handle, mut actor) = setup();
        actor.directory(&snapshots()).unwrap();
        let old = selection(&handle);
        let (tx, mut rx) = oneshot::channel();
        actor
            .register("r".into(), "agent".into(), old.clone(), tx)
            .unwrap();
        actor.wake("agent", false).unwrap();
        assert!(actor.selected("agent", &old));
        assert_eq!(actor.pending.len(), 1);
        actor.wake("agent", true).unwrap();
        assert!(!actor.selected("agent", &old));
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
    }

    #[tokio::test]
    async fn foreign_response_cannot_be_received_as_this_agents_page() {
        let (handle, mut actor) = setup();
        actor.directory(&snapshots()).unwrap();
        let (tx, rx) = oneshot::channel();
        actor
            .register("r".into(), "agent".into(), selection(&handle), tx)
            .unwrap();
        actor.response(&json!({"type":"fetch_agent_timeline_response", "payload":{"requestId":"other","agentId":"agent"}}));
        assert_eq!(actor.pending.len(), 1);
        actor.response(&json!({"type":"fetch_agent_timeline_response", "payload":{"requestId":"r","agentId":"foreign"}}));
        assert!(rx.await.unwrap().is_err());
    }

    #[test]
    fn refreshed_metadata_does_not_revoke_same_selection() {
        let (handle, mut actor) = setup();
        let mut entries = snapshots();
        actor.directory(&entries).unwrap();
        let old = selection(&handle);
        entries.get_mut("agent").unwrap()["title"] = json!("new title");
        actor.directory(&entries).unwrap();
        assert!(actor.selected("agent", &old));
        assert_eq!(
            handle.view.borrow().agents["agent"].snapshot["title"],
            "new title"
        );
        actor.close();
        assert!(handle.view.borrow().closed);
        assert!(!actor.selected("agent", &old));
    }
}
