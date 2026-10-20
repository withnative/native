//! Connection-scoped hosted workers and durable per-host store selection.
//! No task owns a WebSocket; all requests use the serialized reader mailbox.

use std::collections::HashMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{stream::FuturesUnordered, StreamExt};
use sha2::{Digest, Sha256};

use super::session_actor::{ConnectionView, DaemonHandle, Selection};
use super::session_control::SaveStatus;
use super::session_hosted::{self, WorkerContext};
use super::session_identity::SaverIdentity;
use super::session_persist::{Binding, SessionStore};
use super::session_writer::{GateSink, StateAction, Writer, SCHEMA_REQUIRED};
use crate::error::{Error, Result};

const MAX_WORKERS: usize = 16;

fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    match std::fs::symlink_metadata(path) {
        Ok(m) if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 => {
            return Err(Error::engine("unsafe saved-session host directory"))
        }
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::engine(format!("cannot inspect host directory: {e}"))),
    }
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    std::fs::File::open(
        path.parent()
            .ok_or_else(|| Error::engine("host directory lacks parent"))?,
    )?
    .sync_all()?;
    Ok(())
}
fn read_binding(path: &Path) -> Result<Option<Binding>> {
    let path = path.join("binding.json");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(m) if !m.is_file() || m.len() > 64 * 1024 => {
            return Err(Error::engine("unsafe saved-session binding file"))
        }
        _ => {}
    }
    let binding: Binding = serde_json::from_slice(&std::fs::read(path)?)
        .map_err(|_| Error::engine("corrupt saved-session host binding"))?;
    binding.validate()?;
    Ok(Some(binding))
}
fn partition(binding: &Binding) -> Result<String> {
    let bytes = serde_json::to_vec(&[&binding.server_id, &binding.account_id, &binding.db_id])
        .map_err(|_| Error::engine("cannot encode host partition"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Preserve a legacy store in place; new host identities use disjoint private
/// partitions. A reset never overwrites a binding or reuses the old spool.
pub struct HostRegistry {
    base: PathBuf,
    account: String,
    database: String,
    stores: HashMap<String, Arc<SessionStore>>,
}
impl HostRegistry {
    pub fn new(base: &Path, account: &str, database: &str) -> Result<Self> {
        private_dir(base)?;
        let mut registry = Self {
            base: base.to_owned(),
            account: account.to_owned(),
            database: database.to_owned(),
            stores: HashMap::new(),
        };
        if let Some(binding) = read_binding(base)? {
            registry.admit(base, binding)?;
        }
        let hosts = base.join("hosts");
        private_dir(&hosts)?;
        for entry in std::fs::read_dir(&hosts)? {
            let entry = entry?;
            let path = entry.path();
            private_dir(&path)?;
            let Some(binding) = read_binding(&path)? else {
                if std::fs::read_dir(&path)?.next().is_none() {
                    continue;
                }
                return Err(Error::engine("nonempty host partition has no binding"));
            };
            if path.file_name().and_then(|n| n.to_str()) != Some(partition(&binding)?.as_str()) {
                return Err(Error::engine(
                    "host partition name disagrees with its binding",
                ));
            }
            registry.admit(&path, binding)?;
        }
        Ok(registry)
    }
    fn admit(&mut self, path: &Path, binding: Binding) -> Result<()> {
        if binding.account_id != self.account || binding.db_id != self.database {
            return Err(Error::engine(
                "foreign account/database in saved-session host registry",
            ));
        }
        if self.stores.contains_key(&binding.server_id) {
            return Err(Error::engine(
                "duplicate stores for the same saved-session host",
            ));
        }
        self.stores.insert(
            binding.server_id.clone(),
            Arc::new(SessionStore::open(path, binding)?),
        );
        Ok(())
    }
    pub fn connect(
        &mut self,
        binding: Binding,
    ) -> Result<(Arc<SessionStore>, Vec<Arc<SessionStore>>)> {
        binding.validate()?;
        if binding.account_id != self.account || binding.db_id != self.database {
            return Err(Error::engine(
                "host registry connection has a foreign binding",
            ));
        }
        if !self.stores.contains_key(&binding.server_id) {
            let path = self.base.join("hosts").join(partition(&binding)?);
            private_dir(&path)?;
            self.admit(&path, binding.clone())?;
        }
        let store = self.stores[&binding.server_id].clone();
        if store.host_retired()? {
            return Err(Error::engine(
                "a retired daemon identity cannot resume saving",
            ));
        }
        let old: Vec<Arc<SessionStore>> = self
            .stores
            .values()
            .filter(|s| s.binding().server_id != binding.server_id)
            .cloned()
            .collect();
        for old in &old {
            old.retire_host()?;
        }
        Ok((store, old))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Intent {
    Save(Selection),
    Lifecycle {
        state: &'static str,
        reason: Option<&'static str>,
    },
}
fn intent(view: &ConnectionView, agent: &str) -> Option<Intent> {
    if !view.ready {
        return None;
    }
    if view.closed {
        return Some(Intent::Lifecycle {
            state: "paused",
            reason: Some("host_daemon_stopped"),
        });
    }
    match view.snapshots.get(agent) {
        None => Some(Intent::Lifecycle {
            state: "ended",
            reason: None,
        }),
        Some(snapshot) if session_hosted::archived(snapshot) => Some(Intent::Lifecycle {
            state: "ended",
            reason: None,
        }),
        Some(_) => match view.agents.get(agent) {
            Some(agent) => Some(Intent::Save(agent.selection.clone())),
            None => Some(Intent::Lifecycle {
                state: "stopped",
                reason: None,
            }),
        },
    }
}
struct Attempt {
    intent: Intent,
    running: bool,
    terminal: bool,
    after: Instant,
    backoff: Duration,
}
struct Completion {
    agent: String,
    intent: Intent,
    result: Result<()>,
}
type Job = Pin<Box<dyn Future<Output = Completion> + Send>>;

pub struct Supervisor {
    store: Arc<SessionStore>,
    old: Vec<Arc<SessionStore>>,
    sink: Arc<GateSink>,
    identity: SaverIdentity,
    limit: usize,
    started: Instant,
}
impl Supervisor {
    pub(super) fn new(
        store: Arc<SessionStore>,
        old: Vec<Arc<SessionStore>>,
        sink: Arc<GateSink>,
        identity: SaverIdentity,
        limit: usize,
        started: Instant,
    ) -> Self {
        Self {
            store,
            old,
            sink,
            identity,
            limit,
            started,
        }
    }
    fn writer<'a>(&'a self, store: &'a SessionStore) -> Writer<'a, GateSink> {
        let b = store.binding();
        Writer::new(
            store,
            &*self.sink,
            &b.server_id,
            &b.account_id,
            &b.db_id,
            &self.identity.instance,
        )
    }
    async fn retire_old(&self) {
        for store in &self.old {
            let Ok(agents) = store.checkpoint_agents() else {
                continue;
            };
            for agent in agents {
                let writer = self.writer(store);
                let now = chrono::Utc::now().to_rfc3339();
                let retirement = writer.retire_host_session(
                    &agent,
                    self.store.binding(),
                    &self.identity.boot,
                    &now,
                );
                let _ = tokio::time::timeout(Duration::from_secs(30), retirement).await;
            }
        }
    }
    async fn lifecycle(&self, handle: &DaemonHandle, agent: &str, desired: &Intent) -> Result<()> {
        let Intent::Lifecycle { state, reason } = desired else {
            return Err(Error::engine("expected lifecycle intent"));
        };
        let mut view = handle.view.clone();
        let writer = self.writer(&self.store);
        loop {
            if intent(&view.borrow(), agent).as_ref() != Some(desired) {
                return Err(Error::Conflict("lifecycle intent changed".into()));
            }
            let now = chrono::Utc::now().to_rfc3339();
            let transition = writer.transition_session(
                agent,
                &self.store.binding().server_id,
                &self.identity.boot,
                &now,
                state,
                *reason,
            );
            tokio::pin!(transition);
            let action = loop {
                tokio::select! {
                    action=&mut transition => break action?,
                    changed=view.changed() => {
                        if changed.is_err() || intent(&view.borrow(),agent).as_ref()!=Some(desired) {return Err(Error::Conflict("lifecycle intent changed".into()));}
                    }
                }
            };
            match action {
                StateAction::Superseded | StateAction::NotEligible => {
                    return Err(Error::engine("lifecycle lease superseded"))
                }
                StateAction::AuthRefused => {
                    return Err(Error::Auth("lifecycle authentication refused".into()))
                }
                StateAction::Unsupported => {
                    return Err(Error::engine("lifecycle mutation unsupported"))
                }
                _ => {}
            }
            if matches!(
                action,
                StateAction::Settled | StateAction::Written | StateAction::NotDue
            ) {
                let actual = writer.read_owned_session_state(agent).await?;
                let cp = self.store.load_checkpoint(agent)?;
                if actual.claim.generation != cp.writer_generation
                    || cp.lease_writer.as_deref() != Some(actual.claim.writer.as_str())
                {
                    self.store.latch_lease_stopped(agent)?;
                    return Err(Error::engine("lifecycle replay lost its lease"));
                }
                if actual
                    .facets
                    .get("native.session.state")
                    .is_some_and(|s| s == state)
                    && reason.is_none_or(|r| {
                        actual
                            .facets
                            .get("native.session.paused_reason")
                            .is_some_and(|s| s == r)
                    })
                {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    async fn record_failure(
        &self,
        handle: &DaemonHandle,
        agent: &str,
        expected: &Intent,
        error: &Error,
    ) {
        if intent(&handle.view.borrow(), agent).as_ref() != Some(expected) {
            return;
        }
        let Ok(cp) = self.store.load_checkpoint(agent) else {
            return;
        };
        if cp.lease_stopped || cp.session_record_id.is_none() {
            return;
        }
        // Authentication refusals remain terminal, never retried as outages.
        let (state, reason) = match error {
            Error::Io(_) => ("paused", Some("hosted_unreachable")),
            Error::Engine(message)
                if message == session_hosted::UNSUPPORTED_WRITER || message == SCHEMA_REQUIRED =>
            {
                return
            }
            Error::Engine(_) => ("error", None),
            _ => return,
        };
        let writer = self.writer(&self.store);
        let now = chrono::Utc::now().to_rfc3339();
        let transition = writer.transition_session(
            agent,
            &self.store.binding().server_id,
            &self.identity.boot,
            &now,
            state,
            reason,
        );
        // Preserve an uncertain frozen transition rather than blocking all
        // other selected workers on a failed hosted connection.
        let _ = tokio::time::timeout(Duration::from_secs(5), transition).await;
    }

    pub async fn disconnected(&self) {
        let Ok(agents) = self.store.checkpoint_agents() else {
            return;
        };
        for agent in agents {
            let Ok(cp) = self.store.load_checkpoint(&agent) else {
                continue;
            };
            if cp.lease_stopped || cp.last_state.as_deref() != Some("saving") {
                continue;
            }
            let writer = self.writer(&self.store);
            let now = chrono::Utc::now().to_rfc3339();
            let transition = writer.transition_session(
                &agent,
                &self.store.binding().server_id,
                &self.identity.boot,
                &now,
                "paused",
                Some("host_daemon_stopped"),
            );
            let _ = tokio::time::timeout(Duration::from_secs(10), transition).await;
        }
    }
    pub async fn run(self: Arc<Self>, handle: DaemonHandle) {
        let retirement = self.retire_old();
        tokio::pin!(retirement);
        let mut retirement_done = false;
        let mut view = handle.view.clone();
        let mut jobs = FuturesUnordered::<Job>::new();
        let mut attempts = HashMap::<String, Attempt>::new();
        loop {
            let snapshot = view.borrow().clone();
            if snapshot.closed {
                return;
            }
            let mut agents = match self.store.checkpoint_agents() {
                Ok(a) => a,
                Err(_) => return,
            };
            agents.extend(snapshot.agents.keys().cloned());
            agents.sort();
            agents.dedup();
            for agent in agents {
                let Some(next) = intent(&snapshot, &agent) else {
                    continue;
                };
                let previous = attempts.get(&agent);
                if previous.is_some_and(|p| p.running) {
                    continue;
                }
                if previous.is_none_or(|p| p.intent != next) {
                    attempts.insert(
                        agent.clone(),
                        Attempt {
                            intent: next.clone(),
                            running: false,
                            terminal: false,
                            after: Instant::now(),
                            backoff: Duration::from_secs(1),
                        },
                    );
                }
                let attempt = attempts.get_mut(&agent).expect("registered intent");
                if jobs.len() >= MAX_WORKERS || attempt.terminal || attempt.after > Instant::now() {
                    continue;
                }
                attempt.running = true;
                let supervisor = self.clone();
                let handle = handle.clone();
                let desired = next.clone();
                let observed_replacement = snapshot
                    .agents
                    .get(&agent)
                    .is_some_and(|a| a.replacements > 0);
                jobs.push(Box::pin(async move {
                    let result = match &desired {
                        Intent::Save(selection) => {
                            let binding = supervisor.store.binding();
                            let writer = supervisor.writer(&supervisor.store);
                            let context = WorkerContext {
                                server: &binding.server_id,
                                boot: &supervisor.identity.boot,
                                host_label: "Paseo host",
                                pending_limit: supervisor.limit,
                                started: supervisor.started,
                            };
                            session_hosted::drive_selected(
                                &writer,
                                &supervisor.store,
                                &handle,
                                &agent,
                                selection,
                                &context,
                                observed_replacement,
                            )
                            .await
                        }
                        Intent::Lifecycle { .. } => {
                            supervisor.lifecycle(&handle, &agent, &desired).await
                        }
                    };
                    Completion {
                        agent,
                        intent: desired,
                        result,
                    }
                }));
            }
            tokio::select! {
                _=&mut retirement,if !retirement_done=>retirement_done=true,
                changed=view.changed()=>if changed.is_err(){return;},
                completion=jobs.next(),if !jobs.is_empty()=>{
                    let Some(done)=completion else {continue};
                    let Some(attempt)=attempts.get_mut(&done.agent) else {continue};
                    attempt.running=false;
                    let transient=matches!(done.result,Err(Error::Io(_)|Error::Conflict(_)));
                    attempt.terminal = !transient;
                    if let Intent::Save(selection)=&done.intent {
                        if attempt.terminal && intent(&handle.view.borrow(),&done.agent).as_ref()==Some(&done.intent) {
                            if let Ok(mut cp)=self.store.load_checkpoint(&done.agent) {
                                if !cp.lease_stopped {
                                    let code=match &done.result {
                                        Err(Error::Auth(_))=>"auth",
                                        Err(Error::Engine(message)) if message==SCHEMA_REQUIRED=>"schema",
                                        Err(Error::Engine(message)) if message==session_hosted::QUARANTINED_BATCH=>"quarantined",
                                        Err(Error::Engine(message)) if message==session_hosted::UNSUPPORTED_WRITER=>"unsupported",
                                        _=>"saver",
                                    };
                                    cp.terminal_save_label=Some(selection.label.clone());
                                    cp.terminal_save_code=Some(code.into());
                                    if let Err(error)=self.store.save_checkpoint(&cp) {
                                        tracing::error!(%error,"cannot persist saved-session terminal request fence");
                                    }
                                }
                            }
                        }
                        if let Err(error)=&done.result {self.record_failure(&handle,&done.agent,&done.intent,error).await;}
                        let superseded=self.store.load_checkpoint(&done.agent).is_ok_and(|c|c.lease_stopped);
                        attempt.terminal|=superseded;
                        let status=if superseded {Some(SaveStatus::Error {code:"superseded".into()})}else{match &done.result {
                            Ok(())=>None,
                            Err(Error::Io(_))=>Some(SaveStatus::Paused {reason:"hosted_unreachable".into()}),
                            Err(Error::Auth(_))=>Some(SaveStatus::Error {code:"auth".into()}),
                            Err(Error::Engine(message)) if message==SCHEMA_REQUIRED=>Some(SaveStatus::Error {code:"schema".into()}),
                            Err(Error::Conflict(_))=>None,
                            Err(Error::Engine(message)) if message==session_hosted::UNSUPPORTED_WRITER=>Some(SaveStatus::Error {code:"unsupported".into()}),
                            Err(Error::Engine(message)) if message==session_hosted::QUARANTINED_BATCH=>Some(SaveStatus::Error {code:"quarantined".into()}),
                            Err(_)=>Some(SaveStatus::Error {code:if self.store.load_checkpoint(&done.agent).is_ok_and(|c|c.lease_stopped){"superseded"}else{"saver"}.into()}),
                        }};
                        if let Some(status)=status {let _=handle.status(&done.agent,selection,status).await;}
                    }
                    attempt.after=Instant::now()+attempt.backoff;
                    attempt.backoff=(attempt.backoff*2).min(Duration::from_secs(60));
                },
                _=tokio::time::sleep(Duration::from_secs(1))=>{},
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::session_actor;
    use super::*;
    use serde_json::json;

    #[test]
    fn reset_partitions_preserve_bindings_and_retirement_survives_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("sessions");
        let a = Binding::new("srv-a", "acct", "db", None).unwrap();
        let b = Binding::new("srv-b", "acct", "db", None).unwrap();
        let mut registry = HostRegistry::new(&base, "acct", "db").unwrap();
        let (old, none) = registry.connect(a.clone()).unwrap();
        assert!(none.is_empty());
        let (new, retired) = registry.connect(b.clone()).unwrap();
        assert_eq!(retired.len(), 1);
        assert_eq!(old.binding(), &a);
        assert_eq!(new.binding(), &b);
        assert!(old.host_retired().unwrap());
        assert!(!new.host_retired().unwrap());
        drop(registry);
        let mut restored = HostRegistry::new(&base, "acct", "db").unwrap();
        assert!(restored.connect(a).is_err());
        assert_eq!(restored.connect(b).unwrap().1.len(), 1);
        assert!(restored
            .connect(Binding::new("srv-c", "foreign", "db", None).unwrap())
            .is_err());
    }

    #[test]
    fn host_registry_refuses_symlinks_before_changing_target_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("sessions");
        private_dir(&base).unwrap();
        private_dir(&base.join("hosts")).unwrap();
        let target = temp.path().join("outside");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&target, base.join("hosts").join("alias")).unwrap();
        assert!(HostRegistry::new(&base, "acct", "db").is_err());
        assert_eq!(
            std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[test]
    fn initial_empty_view_cannot_end_cached_sessions_before_complete_discovery() {
        let binding = Binding::new("srv", "acct", "db", None).unwrap();
        let (handle, mut mailbox) = session_actor::mailbox(binding);
        assert_eq!(intent(&handle.view.borrow(), "agent"), None);
        let label = "v1;acct=acct;db=db;req=123e4567-e89b-12d3-a456-426614174000";
        mailbox
            .directory(&HashMap::from([(
                "agent".into(),
                json!({"id":"agent","labels":{"native.save":label}}),
            )]))
            .unwrap();
        assert!(matches!(
            intent(&handle.view.borrow(), "agent"),
            Some(Intent::Save(_))
        ));
        mailbox.directory(&HashMap::new()).unwrap();
        assert_eq!(
            intent(&handle.view.borrow(), "agent"),
            Some(Intent::Lifecycle {
                state: "ended",
                reason: None
            })
        );
    }
}
