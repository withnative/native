//! Journal-then-forward gate for writes, with safe in-call retry (slice 2A).
//!
//! A write is saved to the [`Journal`] before it is sent. If the operation's
//! own contract accepts `idempotency_key`, the node uses the caller's key (or
//! mints one) and may send the same bytes again while the caller is still
//! waiting, because hosted answers a repeated key with the original receipt.
//! Otherwise the write is sent once, exactly as before.
//!
//! Who retries: the node keeps one MCP request open, retries inside it within
//! a total budget, and replies once. An uncertain write is the caller's: the
//! node does not replay it, later or after a restart, and the caller retries
//! with the key. The one exception is a write the node has told the caller it
//! is holding (`accepted_pending`, slice 2B): that is the node's, and the queue
//! sends it automatically, in order, when hosted can take it.
//!
//! # Retry budget
//!
//! The budget must end well before the shortest MCP tool-call timeout among
//! the harnesses that call this node, or the caller gives up while the node
//! is still retrying and never sees the key. Checked on 14 Oct 2026:
//!
//! * Codex: `tool_timeout_sec`, default 60 s per MCP server (docs:
//!   learn.chatgpt.com/docs/extend/mcp). Not overridden on the VM.
//! * OpenCode 1.18: `mcp.<server>.timeout` is only passed to `callTool` when
//!   set (read from the installed binary: `k0` returns `config.timeout ??
//!   remote timeout ?? experimental.mcp_timeout`), so an unset value falls to
//!   the MCP SDK's 60 s request default, reset by progress notifications the
//!   node does not send. Its documented 5 s `timeout` covers tool listing,
//!   not calls. Not overridden on the VM.
//! * Claude Code: `MCP_TOOL_TIMEOUT`, default about 28 hours, with a 30 minute
//!   idle limit for stdio servers (code.claude.com/docs/en/mcp).
//!
//! The binding limit is therefore 60 s. The budget is 40 s: two thirds of it,
//! leaving 20 s for the stdio shim, scheduling and the reply to reach the
//! harness. A single attempt is capped at 20 s so that one timeout still
//! leaves room for a retry. The node's own 300 s client timeout still applies
//! to unkeyed single-attempt writes; that predates this slice and is not
//! changed here.
//!
//! # What counts as a write
//!
//! "Is this a write" and "is it keyed" are separate questions. The router
//! answers the first from the local catalogue. Without one, the gate asks
//! hosted for the operation's `access` (`catalog_operations`); if that cannot
//! be learned it journals the call anyway, since saving a read costs a file
//! and skipping a write costs the record of it. `describe_operation` carries
//! the input schema but not `access`, so keyedness comes from it and
//! classification from the catalogue. A failed lookup never invents a key or
//! enables a retry.
use super::hold;
use super::journal::{
    Entry, EntryState, HoldReason, Journal, KeyOrigin, NewEntry, StatusFilter, CONFIRMED_RETENTION,
};
use super::*;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex as StdMutex;
use std::time::Instant;

/// The follow-up check may run this far past the end of the reply budget, and
/// never longer than the cap.
const CONFIRM_GRACE: Duration = Duration::from_secs(3);
const CONFIRM_CAP: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub(super) struct GateConfig {
    /// Total time from receipt to the single reply, retries included.
    pub(super) budget: Duration,
    pub(super) attempt_timeout: Duration,
    /// Do not start an attempt with less than this left.
    pub(super) min_attempt: Duration,
    pub(super) backoff_start: Duration,
    pub(super) backoff_max: Duration,
    /// Bound on each contract or classification lookup.
    pub(super) contract_timeout: Duration,
    pub(super) contract_ttl: Duration,
    pub(super) retention: Duration,
    /// How often an idle node drops settled entries past their retention.
    pub(super) housekeeping_every: Duration,
    /// Pause between sends of held writes, so a large backlog reaches hosted
    /// as a trickle rather than a burst.
    pub(super) queue_gap: Duration,
    /// How often the queue tries again when nothing woke it.
    pub(super) queue_retry: Duration,
    /// How long a refused held write stays in the journal.
    pub(super) refusal_retention: Duration,
    /// New writes the node would hold are refused (as not sent) when free disk
    /// is below the larger of this and twice the local copy's size.
    pub(super) disk_floor_bytes: u64,
    /// Where hosted's records can be opened, for links in `node_status`.
    pub(super) record_url_base: Option<String>,
}

/// 10 GiB: the default free-disk floor.
pub(super) const DEFAULT_DISK_FLOOR: u64 = 10 * 1024 * 1024 * 1024;

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            budget: super::REQUEST_BUDGET,
            attempt_timeout: Duration::from_secs(20),
            min_attempt: super::MIN_ATTEMPT,
            backoff_start: Duration::from_millis(500),
            backoff_max: Duration::from_secs(4),
            contract_timeout: Duration::from_secs(5),
            contract_ttl: Duration::from_secs(300),
            retention: CONFIRMED_RETENTION,
            housekeeping_every: Duration::from_secs(10 * 60),
            queue_gap: Duration::from_millis(250),
            queue_retry: Duration::from_secs(30),
            refusal_retention: Duration::from_secs(7 * 24 * 60 * 60),
            disk_floor_bytes: DEFAULT_DISK_FLOOR,
            record_url_base: None,
        }
    }
}

pub(super) struct WriteRequest<'a> {
    pub(super) body: &'a str,
    pub(super) message: &'a Value,
    pub(super) revision: Option<&'a str>,
    pub(super) caller: &'a Caller,
    /// How to confirm hosted is down. Without it the node never holds a write
    /// for unreachability (a `DEPLOYMENT_READ_ONLY` answer still holds).
    pub(super) outage: Option<&'a dyn Outage>,
    /// Internal saver-to-gate hold opt-out (session saver, S1). When true the
    /// gate never holds this write: a condition that would otherwise hold it
    /// is reported as not-sent instead. This is an in-process flag, never
    /// parsed from the hosted wire and never sent to hosted.
    pub(super) no_hold: bool,
}

pub(super) type Ready<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// What the gate needs from the router that owns hosted's health and the
/// own-write floor.
pub(super) trait Outage: Send + Sync {
    /// A second, independent look at whether hosted is unreachable.
    fn confirm_down(&self) -> Ready<'_, bool>;
    fn known_unreachable(&self) -> Ready<'_, bool> {
        Box::pin(async { false })
    }
    /// Only cached hosted discovery is authority for schema compatibility.
    fn contract_digest<'a>(
        &'a self,
        _executor: &'a str,
        _operation: &'a str,
        _protocol: Option<&'a str>,
    ) -> Ready<'a, Option<String>> {
        Box::pin(async { None })
    }
    /// Called before the queue sends a held write: record it in the own-write
    /// floor. `false` means that could not be saved, so nothing may be sent.
    fn before_send(&self) -> Ready<'_, bool> {
        Box::pin(async { true })
    }
    /// Called after the send, with whether the write may have committed.
    fn after_send(&self, _may_commit: bool) -> Ready<'_, ()> {
        Box::pin(async {})
    }
}

/// What a write the node may hold finds when it takes its turn.
enum Turn<'a> {
    /// Nothing is ahead of it (or the credential is refused): send it.
    Clear(tokio::sync::RwLockReadGuard<'a, ()>),
    /// Hosted cannot take writes: queue it behind the backlog.
    Behind(HoldReason, tokio::sync::RwLockReadGuard<'a, ()>),
    /// The backlog could not be sent and hosted is not known to be away.
    Refuse,
    /// The backlog could not be sent because hosted refused the credential.
    Credentials(Option<u16>),
}

/// What the gate learned about whether an operation takes `idempotency_key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Keyed {
    Yes,
    No,
    /// Hosted could not be asked (or gave no schema).
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    /// Could not be learned; treated as a write for journaling only.
    Unknown,
}

struct Cached<T> {
    checked: Instant,
    ttl: Duration,
    value: T,
}

type Lookups = StdMutex<HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>>;

pub(super) struct WriteGate {
    journal: Journal,
    local_contracts: Arc<crate::mcp::executor_prototype::NodeOperationContracts>,
    config: GateConfig,
    /// Whether the operation's input schema accepts `idempotency_key`.
    keyed: StdMutex<HashMap<(String, String), Cached<Keyed>>>,
    access: StdMutex<HashMap<(String, String), Cached<Access>>>,
    hosted_contracts: StdMutex<HashMap<(String, String), Cached<String>>>,
    /// One lookup at a time per operation: a burst that misses the cache
    /// together makes a single request to hosted, and the rest read its result.
    keyed_lookups: Lookups,
    access_lookups: Lookups,
    /// Test hook: park a forward after its entry is saved, before any send.
    #[cfg(test)]
    pause_before_send: StdMutex<Option<(Arc<tokio::sync::Notify>, Arc<tokio::sync::Notify>)>>,
    /// The local copy whose size sets the free-disk floor, when there is one.
    copy_root: std::sync::OnceLock<PathBuf>,
    copy_size: StdMutex<Option<(Instant, u64)>>,
    /// Test hook: pretend this many bytes are free.
    #[cfg(test)]
    free_override: StdMutex<Option<u64>>,
    #[cfg(test)]
    prepared_arguments_override: StdMutex<Option<Value>>,
    /// Wakes the queue when hosted looks reachable again or a write is held.
    queue_wake: tokio::sync::Notify,
    /// The queue's turn. A drain takes it exclusively; a live write the node
    /// may hold takes it shared, across its backlog check and its own send, so
    /// live writes run in parallel but none starts while a drain is sending
    /// and none passes a backlog that existed when it looked.
    drain_lock: tokio::sync::RwLock<()>,
}

pub(super) mod queue;

/// Names that are never writes and never need a contract lookup.
const NOT_WRITES: [&str; 4] = [
    "bootstrap",
    "describe_operation",
    "standby_status",
    "node_status",
];

impl WriteGate {
    pub(super) fn open(socket_directory: &Path, config: GateConfig) -> Result<Self> {
        let journal =
            Journal::open_with(socket_directory, config.retention, config.refusal_retention)?;
        Ok(Self {
            journal,
            local_contracts: crate::mcp::executor_prototype::NodeOperationContracts::local()?,
            config,
            keyed: StdMutex::new(HashMap::new()),
            access: StdMutex::new(HashMap::new()),
            hosted_contracts: StdMutex::new(HashMap::new()),
            keyed_lookups: StdMutex::new(HashMap::new()),
            access_lookups: StdMutex::new(HashMap::new()),
            #[cfg(test)]
            pause_before_send: StdMutex::new(None),
            copy_root: std::sync::OnceLock::new(),
            copy_size: StdMutex::new(None),
            #[cfg(test)]
            free_override: StdMutex::new(None),
            #[cfg(test)]
            prepared_arguments_override: StdMutex::new(None),
            queue_wake: tokio::sync::Notify::new(),
            drain_lock: tokio::sync::RwLock::new(()),
        })
    }

    /// The `node_status` read: open questions first, never record bodies.
    /// Also drops settled entries past their retention, so an idle node that
    /// is only ever asked for status still tidies itself.
    pub(super) fn status(&self, filter: &StatusFilter) -> Value {
        self.journal.prune();
        let mut status = self.journal.status_for(filter);
        let pending = self.journal.queue_summary();
        let disk = self.disk();
        let object = status.as_object_mut().expect("object");
        object.insert(
            "held_writes".into(),
            self.journal
                .held_writes(filter, self.config.record_url_base.as_deref()),
        );
        object.insert("queue".into(), pending.clone());
        object.insert("disk".into(), disk);
        let unrecognised = self.journal.unrecognised();
        if !unrecognised.is_empty() {
            object.insert("unrecognised".into(), json!(unrecognised));
            object.insert(
                "unrecognised_note".into(),
                json!("These entries were written by a build with states this one does not know (for example a newer build, before a rollback). This build leaves them alone: it neither sends nor settles them. Roll forward to the build that wrote them, or settle them by hand."),
            );
        }
        if pending["pending"].as_u64().unwrap_or(0) > 0 {
            object.insert(
                "rollback".into(),
                json!({
                    "warning": "Writes are pending. A node build older than slice 2B cannot send them: it reads them as 'unrecognised', leaves them on disk and unsent. Let the queue empty before rolling back, or expect them to wait for the next 2B build.",
                    "pending": pending["pending"],
                }),
            );
        }
        status
    }

    /// Add what the node is holding for this run, and for the runs it started,
    /// to a bootstrap reply. Replies it cannot read, and runs with nothing
    /// held, are returned as they were.
    pub(super) fn note_held_writes(&self, reply: &str, run: &str) -> String {
        let (own, children) = self.journal.held_counts_for_run(run);
        let nothing = |counts: &Value| counts.as_object().is_none_or(|c| c.is_empty());
        if nothing(&own) && nothing(&children) {
            return reply.to_owned();
        }
        let Ok(mut value) = serde_json::from_str::<Value>(reply) else {
            return reply.to_owned();
        };
        let Some(result) = value.get_mut("result").and_then(Value::as_object_mut) else {
            return reply.to_owned();
        };
        let describe = |counts: &Value| {
            counts
                .as_object()
                .map(|c| {
                    c.iter()
                        .map(|(state, n)| format!("{n} {state}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        };
        let mut line =
            String::from("Node note: writes waiting for delivery or a canonical hosted outcome.");
        if !nothing(&own) {
            line.push_str(&format!(" This run: {}.", describe(&own)));
        }
        if !nothing(&children) {
            line.push_str(&format!(" Runs it started: {}.", describe(&children)));
        }
        line.push_str(" Call node_status (filters: run, parent_run, state) to see them.");
        if let Some(content) = result.get_mut("content").and_then(Value::as_array_mut) {
            content.push(json!({"type":"text","text":line}));
        }
        if let Some(structured) = result
            .entry("structuredContent")
            .or_insert_with(|| json!({}))
            .as_object_mut()
        {
            structured.insert(
                "node_held_writes".into(),
                json!({"this_run": own, "runs_it_started": children, "see": "node_status"}),
            );
        }
        value.to_string()
    }

    pub(super) fn set_copy_root(&self, root: PathBuf) {
        let _ = self.copy_root.set(root);
    }

    /// Free space where the journal lives, the floor, and the local copy.
    fn disk(&self) -> Value {
        let free = self.free_bytes();
        let copy = self.copy_bytes();
        let floor = self.config.disk_floor_bytes.max(copy.saturating_mul(2));
        json!({
            "free_bytes": free,
            "floor_bytes": floor,
            "configured_floor_bytes": self.config.disk_floor_bytes,
            "local_copy_bytes": copy,
            "below_floor": free.is_some_and(|free| free < floor),
        })
    }

    // `statvfs` field widths differ by platform (u32 on macOS), so convert.
    #[allow(clippy::useless_conversion)]
    fn free_bytes(&self) -> Option<u64> {
        #[cfg(test)]
        if let Some(free) = *self.free_override.lock().unwrap() {
            return Some(free);
        }
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(self.journal.directory().as_os_str().as_bytes()).ok()?;
        // SAFETY: a valid NUL-terminated path and a zeroed out-parameter.
        let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
        (unsafe { libc::statvfs(path.as_ptr(), &mut stats) } == 0)
            .then(|| u64::from(stats.f_bavail).saturating_mul(u64::from(stats.f_frsize)))
    }

    /// The local copy's size, remeasured at most every ten minutes.
    fn copy_bytes(&self) -> u64 {
        let Some(root) = self.copy_root.get() else {
            return 0;
        };
        let mut cached = self.copy_size.lock().expect("copy size");
        if let Some((at, size)) = *cached {
            if at.elapsed() < Duration::from_secs(600) {
                return size;
            }
        }
        fn walk(path: &Path) -> u64 {
            let Ok(entries) = fs::read_dir(path) else {
                return 0;
            };
            entries
                .flatten()
                .map(|entry| match entry.file_type() {
                    Ok(kind) if kind.is_dir() => walk(&entry.path()),
                    Ok(kind) if kind.is_file() => entry.metadata().map_or(0, |m| m.len()),
                    _ => 0,
                })
                .sum()
        }
        let size = walk(root);
        *cached = Some((Instant::now(), size));
        size
    }

    /// `Some((free, floor))` when free disk is below the floor.
    fn below_floor(&self) -> Option<(u64, u64)> {
        let disk = self.disk();
        (disk["below_floor"] == json!(true)).then(|| {
            (
                disk["free_bytes"].as_u64().unwrap_or(0),
                disk["floor_bytes"].as_u64().unwrap_or(0),
            )
        })
    }

    /// Drop settled entries past retention now and then even when nothing is
    /// being written or read.
    pub(super) fn spawn_housekeeping(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let gate = self.clone();
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(gate.config.housekeeping_every);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                timer.tick().await;
                gate.journal.prune();
            }
        })
    }

    #[cfg(test)]
    async fn test_pause(&self) {
        let hook = self.pause_before_send.lock().unwrap().clone();
        if let Some((entered, release)) = hook {
            entered.notify_one();
            release.notified().await;
        }
    }

    /// Take the per-operation lookup turn, giving up on cancellation or when
    /// the request's budget runs out (the caller then treats it as unknown).
    async fn lookup_turn(
        &self,
        lookups: &Lookups,
        key: &(String, String),
        started: Instant,
        cancel: &Cancel,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        let turn = lookups
            .lock()
            .expect("lookup turns")
            .entry(key.clone())
            .or_default()
            .clone();
        let left = (started + self.config.budget).saturating_duration_since(Instant::now());
        tokio::select! {
            biased;
            _ = cancel.cancelled() => None,
            held = tokio::time::timeout(left, turn.lock_owned()) => held.ok(),
        }
    }

    fn limits(&self, started: Instant, attempt_timeout: Duration, cancel: &Cancel) -> Limits {
        Limits {
            deadline: started + self.config.budget,
            attempt_timeout,
            min_attempt: self.config.min_attempt,
            cancel: Some(cancel.clone()),
        }
    }

    /// Send a write once or, when its contract allows, with in-call retry.
    /// `known_write` is the router's own classification from the local
    /// catalogue; without it the gate classifies the operation itself.
    pub(super) async fn forward(
        &self,
        upstream: &Upstream,
        request: &WriteRequest<'_>,
        known_write: bool,
    ) -> SendReport {
        // The budget runs from the frame's arrival, queueing included.
        let started = request.caller.received;
        let id = request.message.get("id");
        let cancel = &request.caller.cancel;
        let plain =
            || upstream.send_classified(request.body, request.message, request.revision, id);
        let Some((executor, operation, envelope)) = super::failover::target(request.message) else {
            return plain().await;
        };
        if operation.is_empty() || NOT_WRITES.contains(&executor.as_str()) {
            return plain().await;
        }
        if cancel.is_cancelled() {
            return not_sent(id, "Request cancelled; request was not sent");
        }

        // Is this a write? Then, separately, is it keyed? An operation whose
        // class could not be learned is journaled but never keyed or retried.
        let access = if known_write {
            Access::Write
        } else {
            self.access_of(upstream, &executor, &operation, started, cancel)
                .await
        };
        if access == Access::Read {
            return plain().await;
        }
        // Whether this write may be held. The internal saver opt-out
        // (`no_hold`) only removes holding; it never changes keying.
        let holdable = hold::is_holdable(
            &executor,
            &operation,
            envelope.get("arguments").unwrap_or(&Value::Null),
        );
        let holdable = holdable && !request.no_hold;
        let keyed = if access == Access::Write {
            match self
                .accepts_key(upstream, &executor, &operation, started, cancel)
                .await
            {
                Keyed::Yes => true,
                Keyed::No => false,
                // The contract could not be read, most likely because hosted
                // is down. The operations the node may hold are known to take
                // a key (a test checks that), which is what lets a write be
                // keyed — and held — in the very outage that stops the
                // lookup. Key eligibility is independent of the saver
                // opt-out: a flagged write with an unknown contract is still
                // keyed (never silently unkeyed); it is only never held.
                // Anything else is sent once, as before.
                Keyed::Unknown => hold::is_holdable(
                    &executor,
                    &operation,
                    envelope.get("arguments").unwrap_or(&Value::Null),
                ),
            }
        } else {
            false
        };
        if cancel.is_cancelled() {
            return not_sent(id, "Request cancelled; request was not sent");
        }

        let mut message = request.message.clone();
        let mut key = None;
        if keyed {
            key = prepare_key(&mut message, &envelope);
        }
        let mut plan = hold::Plan::default();
        let mut intent = None;
        let mut checking_hosted_pending = false;
        let mut rewritten = key
            .as_ref()
            .is_some_and(|(_, origin)| *origin == KeyOrigin::Node);
        if let (true, Some((key, _))) = (holdable, key.as_ref()) {
            if let Some(arguments) = message.pointer_mut("/params/arguments/arguments") {
                let digest = hold::intent_digest(arguments);
                if let Some(hosted) = self
                    .journal
                    .hosted_pending_with_key(&executor, &operation, key)
                {
                    if hosted.intent_digest.as_deref() != Some(digest.as_str()) {
                        return SendReport {
                            reply: hold::conflict_reply(id, &hosted),
                            failure: None,
                            attempt: Attempt::Answered,
                            status: None,
                        };
                    }
                    // A same-key check must reach hosted even when queued
                    // dependants are waiting for this create's canonical outcome.
                    checking_hosted_pending = true;
                }
                // A repeat of a call the node is holding is answered from the
                // journal: nothing is sent and nothing new is saved.
                if let Some(held) = self.journal.pending_with_key(&executor, &operation, key) {
                    if held.intent_digest.as_deref() == Some(digest.as_str()) {
                        let position = self.journal.pending_position(held.seq);
                        return SendReport {
                            reply: hold::pending_reply(
                                id,
                                &held,
                                position,
                                crate::mcp::is_modern_request(request.message),
                            ),
                            failure: None,
                            attempt: Attempt::Answered,
                            status: None,
                        };
                    }
                    return SendReport {
                        reply: hold::conflict_reply(id, &held),
                        failure: None,
                        attempt: Attempt::Answered,
                        status: None,
                    };
                }
                // A held write the node has since sent: the repeat gets the
                // original receipt or refusal.
                if let Some(done) = self
                    .journal
                    .settled_held_with_key(&executor, &operation, key)
                    // Older builds cached hosted pending/not-ready as terminal.
                    // Reconcile through hosted without rewriting historical files.
                    .filter(|done| {
                        !matches!(
                            answer_of(done.reply.as_deref()),
                            Answer::HostedPending | Answer::RetryableNotReady
                        )
                    })
                {
                    if done.intent_digest.as_deref() == Some(digest.as_str()) {
                        return SendReport {
                            reply: done
                                .reply
                                .as_deref()
                                .filter(|_| id.is_some())
                                .map(|stored| {
                                    if done.answer.as_deref() == Some("already_applied") {
                                        with_request_id(
                                            &queue::already_applied_reply(
                                                &done,
                                                crate::mcp::is_modern_request(request.message),
                                            ),
                                            id,
                                        )
                                    } else {
                                        with_request_id(stored, id)
                                    }
                                }),
                            failure: None,
                            attempt: Attempt::Answered,
                            status: None,
                        };
                    }
                }
                let before = arguments.clone();
                plan = hold::prepare(&operation, arguments, key, &digest);
                rewritten |= *arguments != before;
                intent = Some(digest);
            }
        }
        // Held writes go before any new one.
        //
        // A write the node may hold takes the queue's turn and keeps it until
        // its own send is done, so nothing can be held (or sent from the
        // backlog) between "is anything waiting?" and the send: it cannot
        // overtake an older write. If the backlog cannot be sent it is held
        // behind it only when hosted is read-only or confirmed down, and
        // otherwise not sent at all; a refused credential gets the usual
        // refusal from hosted. Any other write waits up to half its budget for
        // the backlog and then goes ahead (see docs/local-node.md).
        let mut behind = None;
        if holdable && key.is_some() {
            if let Some(outage) = request.outage {
                if outage.known_unreachable().await
                    && self
                        .confirm_down(request, started + self.config.budget)
                        .await
                {
                    behind = Some(HoldReason::HostedUnreachable);
                }
            }
        }
        // A saver-flagged write is never held. When hosted is confirmed down
        // — the condition that would otherwise hold it — report not-sent
        // without sending, instead of burning the retry budget against a
        // dead endpoint. The caller (S3's spool) owns the key and the retry.
        if !holdable && request.no_hold && key.is_some() {
            if let Some(outage) = request.outage {
                if outage.known_unreachable().await
                    && self
                        .confirm_down(request, started + self.config.budget)
                        .await
                {
                    let id = request.message.get("id");
                    return not_sent_report(
                        id,
                        "Hosted is unreachable; the write was not sent and not held (saver opt-out)",
                    );
                }
            }
        }
        let mut _turn = None;
        if access != Access::Read {
            let limit = started + self.config.budget / 2;
            if holdable && key.is_some() && !checking_hosted_pending {
                match self.backlog_turn(upstream, request, limit).await {
                    Turn::Clear(guard) => _turn = Some(guard),
                    Turn::Behind(reason, guard) => {
                        behind = Some(reason);
                        _turn = Some(guard);
                    }
                    Turn::Credentials(status) => {
                        // Nothing is sent. Only a status hosted really gave is
                        // reported; with none (no usable credential at all)
                        // there is no status to report.
                        let mut data = json!({
                            "outcome": "not_sent",
                            "reason": if status.is_some() {
                                "credentials_refused"
                            } else {
                                "credentials_unavailable"
                            },
                        });
                        if let Some(status) = status {
                            data["http_status"] = json!(status);
                        }
                        return SendReport {
                            reply: frame_error(
                                id,
                                "Held writes are still waiting because the node's credentials were not accepted, so this write was not sent",
                                data,
                            ),
                            failure: status.map(|_| Health::AuthRefused),
                            attempt: Attempt::Stopped,
                            status: None,
                        };
                    }
                    Turn::Refuse => {
                        return SendReport {
                            reply: frame_error(
                                id,
                                "Held writes are still waiting to be sent, and this write must not overtake them; it was not sent. Nothing was applied, so it is safe to send the same call again in a little while",
                                json!({
                                    "outcome": "not_sent",
                                    "reason": "backlog_pending",
                                    "retryable": true,
                                }),
                            ),
                            failure: None,
                            attempt: Attempt::Stopped,
                            status: None,
                        };
                    }
                }
            } else if !checking_hosted_pending && self.journal.pending_count() > 0 {
                Box::pin(self.drain(upstream, request.outage, Some(limit), Some(cancel))).await;
            }
        }
        #[cfg(test)]
        if behind.is_some() {
            if let Some(arguments) = self.prepared_arguments_override.lock().unwrap().take() {
                message["params"]["arguments"]["arguments"] = arguments;
            }
        }
        let body = if rewritten {
            message.to_string()
        } else {
            request.body.to_owned()
        };
        let operation_arguments = message
            .pointer("/params/arguments/arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let envelope_extra = holdable.then(|| {
            let mut extra = message
                .pointer("/params/arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if let Some(object) = extra.as_object_mut() {
                for field in ["arguments", "executor", "operation"] {
                    object.remove(field);
                }
            }
            extra
        });
        if behind.is_some() {
            if let Some(refusal) = self.validate_hold(request, &message).await {
                return refusal;
            }
        }
        let entry = match self.journal.begin(NewEntry {
            executor: executor.clone(),
            operation: operation.clone(),
            tool: message
                .pointer("/params/name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
            run_key: message
                .pointer("/params/arguments/run_key")
                .and_then(Value::as_str)
                .map(str::to_owned),
            client_info: request.caller.client_info.clone(),
            idempotency_key: key.as_ref().map(|(key, _)| key.clone()),
            key_origin: key.as_ref().map(|(_, origin)| *origin),
            arguments: operation_arguments,
            parent_key: message
                .pointer("/params/arguments/parent_key")
                .and_then(Value::as_str)
                .map(str::to_owned),
            title: plan.title,
            record_id: plan.record_id,
            record_ids: plan.record_ids,
            envelope: envelope_extra,
            intent_digest: intent,
        }) {
            Ok(entry) => entry,
            Err(_) => {
                return not_sent(id, "Cannot save the write journal entry; nothing was sent");
            }
        };
        #[cfg(test)]
        self.test_pause().await;
        if cancel.is_cancelled() {
            let _ = self.journal.settle(
                &entry.id,
                EntryState::NotSent,
                None,
                Some("cancelled before anything was sent".into()),
            );
            return not_sent(id, "Request cancelled; request was not sent");
        }

        if let Some(reason) = behind {
            let no_room = self.refuse_for_disk(&entry, reason, false, id);
            if let Some(Some(refusal)) = no_room {
                return refusal;
            }
            if let Some(reply) = no_room
                .is_none()
                .then(|| {
                    self.hold(
                        &entry,
                        reason,
                        false,
                        id,
                        crate::mcp::is_modern_request(request.message),
                    )
                })
                .flatten()
            {
                return SendReport {
                    reply,
                    failure: None,
                    attempt: Attempt::Answered,
                    status: None,
                };
            }
        }
        let (report, maybe_sent, held) = if key.is_some() {
            let (report, maybe_sent, held) = Box::pin(
                self.send_with_retry(upstream, request, &message, &body, &entry, holdable),
            )
            .await;
            let minted = key
                .as_ref()
                .is_some_and(|(_, origin)| *origin == KeyOrigin::Node);
            // Hosted refused the key the node minted, before any effect: send
            // the caller's call once more without it (not for a held write).
            if held.is_none()
                && minted
                && !maybe_sent
                && report.attempt == Attempt::Answered
                && refuses_key(report.reply.as_deref())
                && !cancel.is_cancelled()
            {
                let (report, maybe_sent) = self.resend_unkeyed(upstream, request, &entry).await;
                (report, maybe_sent, None)
            } else {
                (report, maybe_sent, held)
            }
        } else {
            let _ = self.journal.note_attempt(&entry.id);
            let report = upstream
                .send_attempt(&body, &message, request.revision, id, None)
                .await;
            let maybe_sent = matches!(report.attempt, Attempt::Lost | Attempt::Unclear);
            (report, maybe_sent, None)
        };
        if let Some(reason) = held {
            // Once a send may have applied, retain the prepared call and its
            // key for replay: hosted must decide its outcome. Local admission
            // checks may only refuse a write that has not reached hosted.
            if !maybe_sent {
                if let Some(mut refusal) = self.validate_hold(request, &message).await {
                    refusal.failure = report.failure;
                    return self.finish(refusal, false, &entry, &executor, &operation, id);
                }
            }
            let no_room = self.refuse_for_disk(&entry, reason, maybe_sent, id);
            if let Some(Some(refusal)) = no_room {
                return refusal;
            }
            if let Some(reply) = no_room
                .is_none()
                .then(|| {
                    self.hold(
                        &entry,
                        reason,
                        maybe_sent,
                        id,
                        crate::mcp::is_modern_request(request.message),
                    )
                })
                .flatten()
            {
                return SendReport {
                    reply,
                    // Hosted's health is still what the failed send saw.
                    failure: report.failure,
                    attempt: Attempt::Answered,
                    status: None,
                };
            }
        }
        // `resend_unkeyed` may have dropped the key from the entry.
        let entry = self.journal.get(&entry.id).unwrap_or(entry);
        self.finish(report, maybe_sent, &entry, &executor, &operation, id)
    }

    async fn validate_hold(
        &self,
        request: &WriteRequest<'_>,
        prepared: &Value,
    ) -> Option<SendReport> {
        let (executor, operation, original) = super::failover::target(request.message)?;
        let id = request.message.get("id");
        let outcome = "not_sent";
        let refusal = |message: &str| SendReport {
            reply: frame_error(id, message, json!({"outcome":outcome, "held":false})),
            failure: None,
            attempt: Attempt::Stopped,
            status: None,
        };
        let Some(local) = self.local_contracts.digest(&executor, &operation) else {
            return Some(refusal(
                "Local operation contract unavailable; write was not held",
            ));
        };
        let hosted = if let Some(outage) = request.outage {
            outage
                .contract_digest(&executor, &operation, request.revision)
                .await
        } else {
            self.hosted_contracts
                .lock()
                .expect("hosted contracts")
                .get(&(executor.clone(), operation.clone()))
                .filter(|cached| cached.checked.elapsed() < cached.ttl)
                .map(|cached| cached.value.clone())
        };
        if hosted.as_deref() != Some(local) {
            return Some(refusal("Cached hosted operation contract is missing or differs from the local contract; write was not held"));
        }
        let Some((prepared_executor, prepared_operation, exact)) =
            super::failover::target(prepared)
        else {
            return Some(refusal(
                "Prepared write has no operation contract; write was not held",
            ));
        };
        if prepared_executor != executor || prepared_operation != operation {
            return Some(refusal(
                "Prepared write changed operation; write was not held",
            ));
        }
        for envelope in [&original, &exact] {
            match self.local_contracts.validate(
                &executor,
                &operation,
                envelope,
                crate::mcp::is_modern_request(request.message),
            ) {
                Some(Ok(())) => {}
                Some(Err(mut result)) => {
                    result["structuredContent"]["outcome"] = json!(outcome);
                    return Some(SendReport {
                        reply: id
                            .map(|id| json!({"jsonrpc":"2.0","id":id,"result":result}).to_string()),
                        failure: None,
                        attempt: Attempt::Stopped,
                        status: None,
                    });
                }
                None => {
                    return Some(refusal(
                        "Local operation contract unavailable; write was not held",
                    ))
                }
            }
        }
        None
    }

    /// Hosted refused the key the node minted, before any effect, and said to
    /// retry without one (a live co-edit body route, artifact-input
    /// continuity, enrolled custody). The caller sent no key, so send its call
    /// once more exactly as it would have gone before slice 2A: unkeyed, a
    /// single attempt, no retry. Mirrors appHost's `KEY_UNSUPPORTED`.
    async fn resend_unkeyed(
        &self,
        upstream: &Upstream,
        request: &WriteRequest<'_>,
        entry: &Entry,
    ) -> (SendReport, bool) {
        let id = request.message.get("id");
        // The caller's own bytes, which carried no key: exactly the request
        // the node would have sent before slice 2A.
        let arguments = request
            .message
            .pointer("/params/arguments/arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let saved = self.journal.update(&entry.id, |e| {
            e.idempotency_key = None;
            e.key_origin = None;
            e.arguments_digest = super::journal::arguments_digest(&arguments);
            e.arguments_bytes = arguments.to_string().len();
            e.arguments = Some(arguments.clone());
            e.attempts += 1;
        });
        if saved.is_err() {
            return (
                not_sent_report(id, "Cannot save the write journal entry; nothing was sent"),
                false,
            );
        }
        tracing::info!(
            target: "native_ce::node::journal",
            "hosted refused the node's key for this call; re-sending it once without one"
        );
        let report = upstream
            .send_attempt(request.body, request.message, request.revision, id, None)
            .await;
        let maybe_sent = matches!(report.attempt, Attempt::Lost | Attempt::Unclear);
        (report, maybe_sent)
    }

    async fn send_with_retry(
        &self,
        upstream: &Upstream,
        request: &WriteRequest<'_>,
        message: &Value,
        body: &str,
        entry: &Entry,
        holdable: bool,
    ) -> (SendReport, bool, Option<HoldReason>) {
        let id = message.get("id");
        let started = request.caller.received;
        let cancel = &request.caller.cancel;
        let deadline = started + self.config.budget;
        let limits = self.limits(started, self.config.attempt_timeout, cancel);
        let mut backoff = self.config.backoff_start;
        let mut maybe_sent = false;
        loop {
            if self.journal.note_attempt(&entry.id).is_err() && !maybe_sent {
                return (
                    not_sent_report(id, "Cannot save the write journal entry; nothing was sent"),
                    false,
                    None,
                );
            }
            let report = upstream
                .send_attempt(body, message, request.revision, id, Some(&limits))
                .await;
            match report.attempt {
                Attempt::Lost | Attempt::Unclear => maybe_sent = true,
                // Nothing went out (cancelled, out of time, no credential).
                Attempt::Stopped => {
                    let _ = self.journal.update(&entry.id, |e| e.attempts -= 1);
                }
                _ => {}
            }
            // A caller that has gone is not told anything, so the node does not
            // take its write over.
            if holdable && !cancel.is_cancelled() {
                if report.attempt == Attempt::Answered
                    && report.reply.as_deref().is_some_and(|reply| {
                        hold::is_deployment_read_only(reply)
                            || answer_of(Some(reply)) == Answer::RetryableNotReady
                    })
                {
                    return (report, maybe_sent, Some(HoldReason::DeploymentReadOnly));
                }
                if matches!(report.attempt, Attempt::NotSent | Attempt::Lost)
                    && report.failure == Some(Health::Unreachable)
                    && self.confirm_down(request, deadline).await
                {
                    return (report, maybe_sent, Some(HoldReason::HostedUnreachable));
                }
            }
            if !matches!(report.attempt, Attempt::NotSent | Attempt::Lost) {
                return (report, maybe_sent, None);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if cancel.is_cancelled() || remaining < backoff + self.config.min_attempt {
                return (report, maybe_sent, None);
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return (report, maybe_sent, None),
                _ = tokio::time::sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(self.config.backoff_max);
        }
    }

    /// Take the queue's turn for a write the node may hold, and clear what is
    /// waiting ahead of it if hosted lets it.
    async fn backlog_turn<'a>(
        &'a self,
        upstream: &Upstream,
        request: &WriteRequest<'_>,
        limit: Instant,
    ) -> Turn<'a> {
        let cancel = &request.caller.cancel;
        let wait = |limit: Instant| limit.saturating_duration_since(Instant::now());
        let Ok(guard) = tokio::time::timeout(wait(limit), self.drain_lock.read()).await else {
            // A drain has been sending for half this call's budget.
            return Turn::Refuse;
        };
        if self.journal.pending_count() == 0 {
            return Turn::Clear(guard);
        }
        // Something is waiting. Clearing it is a drain: take the exclusive
        // side, and keep our turn by downgrading to shared afterwards (the
        // downgrade lets no other drain in between).
        drop(guard);
        let Ok(exclusive) = tokio::time::timeout(wait(limit), self.drain_lock.write()).await else {
            return Turn::Refuse;
        };
        if self.journal.pending_count() == 0 {
            return Turn::Clear(exclusive.downgrade());
        }
        let halt =
            Box::pin(self.drain_locked(upstream, request.outage, Some(limit), Some(cancel))).await;
        let guard = exclusive.downgrade();
        if self.journal.pending_count() == 0 {
            return Turn::Clear(guard);
        }
        match halt {
            queue::Halt::ReadOnly => Turn::Behind(HoldReason::DeploymentReadOnly, guard),
            queue::Halt::Unreachable
                if self
                    .confirm_down(request, limit + self.config.budget / 2)
                    .await =>
            {
                Turn::Behind(HoldReason::HostedUnreachable, guard)
            }
            // The credential was refused. That is not an outage, so the new
            // write is not held, but it must not be sent either: it would
            // commit ahead of the backlog if the credential recovered.
            queue::Halt::Credentials(status) => Turn::Credentials(status),
            _ => Turn::Refuse,
        }
    }

    /// The second failure that makes an outage: a fresh look at hosted after a
    /// failed forward. It may run a little past the reply budget (which leaves
    /// 20 s of the tightest harness timeout spare) but is capped.
    async fn confirm_down(&self, request: &WriteRequest<'_>, deadline: Instant) -> bool {
        let Some(outage) = request.outage else {
            return false;
        };
        let cap =
            (deadline.saturating_duration_since(Instant::now()) + CONFIRM_GRACE).min(CONFIRM_CAP);
        matches!(
            tokio::time::timeout(cap, outage.confirm_down()).await,
            Ok(true)
        )
    }

    /// Below the free-disk floor the node takes no more writes over. A write
    /// that was never sent is refused as `not_sent`, never dropped: the caller
    /// is told, and nothing was saved beyond the settled entry. A write that
    /// may already be in flight stays `uncertain`, with its arguments, as in
    /// slice 2A. `None` means there is room, and the write is held; `Some(None)` is the
    /// in-flight case, settled as before.
    fn refuse_for_disk(
        &self,
        entry: &Entry,
        reason: HoldReason,
        maybe_sent: bool,
        id: Option<&Value>,
    ) -> Option<Option<SendReport>> {
        let (free, floor) = self.below_floor()?;
        if maybe_sent {
            return Some(None);
        }
        let _ = self.journal.settle(
            &entry.id,
            EntryState::NotSent,
            None,
            Some(format!(
                "not held: free disk ({free} bytes) is below the floor ({floor} bytes); nothing was sent"
            )),
        );
        Some(Some(SendReport {
            reply: frame_error(
                id,
                "Not held: the node is low on disk space, so it will not take this write over; nothing was sent",
                json!({
                    "outcome": "not_sent",
                    "reason": "disk_floor",
                    "hosted_state": reason.as_str(),
                    "free_bytes": free,
                    "floor_bytes": floor,
                }),
            ),
            failure: None,
            attempt: Attempt::Answered,
            status: None,
        }))
    }

    /// Take the write over: it stays in the journal, with its arguments, as
    /// `pending`, and the caller is told so. `None` if it could not be saved,
    /// in which case the write is settled as it would have been before.
    fn hold(
        &self,
        entry: &Entry,
        reason: HoldReason,
        maybe_applied: bool,
        id: Option<&Value>,
        modern: bool,
    ) -> Option<Option<String>> {
        let detail = match (reason, maybe_applied) {
            (HoldReason::DeploymentReadOnly, false) => {
                "hosted refused the write as read-only for a deployment; held to send later"
            }
            (HoldReason::DeploymentReadOnly, true) => {
                "hosted is read-only for a deployment; an earlier attempt may have been applied; held to send later with the same key"
            }
            (_, false) => "hosted is unreachable; nothing reached it; held to send later",
            (_, true) => {
                "hosted is unreachable; an earlier attempt may have been applied; held to send later with the same key"
            }
        };
        let held = self
            .journal
            .hold(&entry.id, reason, detail.to_owned(), maybe_applied)
            .ok()
            .filter(|held| held.state == EntryState::Pending)?;
        let position = self.journal.pending_position(held.seq);
        Some(hold::pending_reply(id, &held, position, modern))
    }

    /// Settle the journal entry and shape the one reply.
    ///
    /// An entry only leaves `uncertain` on a receipt, or on a refusal when no
    /// attempt can have landed: a later refusal says nothing about an earlier
    /// attempt that may have been applied.
    fn finish(
        &self,
        mut report: SendReport,
        maybe_sent: bool,
        entry: &Entry,
        executor: &str,
        operation: &str,
        id: Option<&Value>,
    ) -> SendReport {
        let attempts = self.journal.get(&entry.id).map_or(0, |e| e.attempts);
        let answer =
            (report.attempt == Attempt::Answered).then(|| answer_of(report.reply.as_deref()));
        let (state, answer_label, detail) = match (report.attempt, &answer) {
            (Attempt::Answered, Some(Answer::HostedPending)) => {
                if self
                    .journal
                    .hosted_pending(&entry.id, hosted_pending_journal(report.reply.as_deref()))
                    .is_err()
                {
                    tracing::warn!(target: "native_ce::node::journal", "hosted custody could not be recorded");
                }
                return report;
            }
            (Attempt::Answered, Some(Answer::RetryableNotReady)) if !maybe_sent => (
                EntryState::NotSent,
                None,
                Some(
                    "hosted outbox is not ready; this attempt was not accepted; retry the same key"
                        .into(),
                ),
            ),
            (Attempt::Answered, Some(Answer::Receipt)) => {
                (EntryState::Confirmed, Some("receipt"), None)
            }
            (Attempt::Answered, Some(Answer::Refused)) if !maybe_sent => {
                (EntryState::Confirmed, Some("refused"), None)
            }
            (Attempt::Answered, Some(Answer::Refused)) => (
                EntryState::Uncertain,
                None,
                Some(
                    "an earlier attempt may have been applied; hosted's later answer was a refusal"
                        .to_owned(),
                ),
            ),
            (Attempt::Answered, _) => (
                EntryState::Uncertain,
                None,
                Some(
                    "hosted reported a partial or unknown outcome; inspect before retrying"
                        .to_owned(),
                ),
            ),
            (Attempt::Stopped | Attempt::NotSent, _) if !maybe_sent => (
                EntryState::NotSent,
                None,
                Some("nothing reached hosted".to_owned()),
            ),
            _ => (
                EntryState::Uncertain,
                None,
                Some(format!(
                    "no definitive answer from hosted after {attempts} attempt(s)"
                )),
            ),
        };
        let settled = self.journal.settle(&entry.id, state, answer_label, detail);
        match &settled {
            // Only a receipt establishes what an earlier same-key entry asked.
            Ok(settled) if answer_label == Some("receipt") => self.journal.resolve_earlier(settled),
            Ok(_) => {}
            Err(_) => {
                tracing::warn!(target: "native_ce::node::journal", "journal entry could not be settled");
            }
        }
        // A key the node minted that hosted refused may mean the cached
        // contract is stale: look it up again next time.
        if answer_label == Some("refused") && entry.key_origin == Some(KeyOrigin::Node) {
            self.keyed
                .lock()
                .expect("contract cache")
                .remove(&(executor.to_owned(), operation.to_owned()));
        }
        if state != EntryState::Uncertain {
            return report;
        }
        let Some(key) = entry.idempotency_key.as_deref() else {
            return report;
        };
        let info = json!({
            "outcome": "uncertain",
            "idempotency_key": key,
            "key_origin": entry.key_origin,
            "journal_entry": entry.id,
            "attempts": attempts,
            "retry": "Send this exact call again with idempotency_key set to the value above: hosted returns the original receipt if the write was applied and applies it once if not. Or read the record first. The node does not replay an uncertain write; only a write it reports as accepted_pending is sent by the node.",
        });
        if report.attempt != Attempt::Answered {
            report.reply = frame_error(
                id,
                &format!(
                    "Write outcome uncertain. Retry the same call with idempotency_key={key}, or read the record before writing again"
                ),
                info,
            );
        } else if maybe_sent || entry.key_origin == Some(KeyOrigin::Node) {
            // Hosted's own answer stays as it was; the node adds what the
            // caller cannot otherwise see: an earlier attempt may have landed,
            // or the key is the node's.
            report.reply = report
                .reply
                .map(|reply| annotate_hosted_reply(&reply, info, key));
        }
        report
    }

    /// Whether the operation is a read, a write, or unknown, from hosted's
    /// catalogue, cached briefly.
    async fn access_of(
        &self,
        upstream: &Upstream,
        executor: &str,
        operation: &str,
        started: Instant,
        cancel: &Cancel,
    ) -> Access {
        let cache_key = (executor.to_owned(), operation.to_owned());
        if let Some(cached) = self.access.lock().expect("access cache").get(&cache_key) {
            if cached.checked.elapsed() < cached.ttl {
                return cached.value;
            }
        }
        let Some(_turn) = self
            .lookup_turn(&self.access_lookups, &cache_key, started, cancel)
            .await
        else {
            return Access::Unknown;
        };
        // Someone ahead of us may have just looked it up.
        if let Some(cached) = self.access.lock().expect("access cache").get(&cache_key) {
            if cached.checked.elapsed() < cached.ttl {
                return cached.value;
            }
        }
        let plain_name = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        };
        if !plain_name(executor) || !plain_name(operation) {
            return Access::Unknown;
        }
        let message = json!({
            "jsonrpc": "2.0",
            "id": "node-access",
            "method": "tools/call",
            "params": {
                "name": "sql_read",
                "arguments": {
                    "operation": "query_sql",
                    "arguments": {"sql": format!(
                        "SELECT access, contract_digest FROM catalog_operations WHERE executor = '{executor}' AND operation = '{operation}'"
                    )},
                    "format": "json",
                },
                "_meta": super::failover::probe_meta(),
            },
        });
        let limits = self.limits(started, self.config.contract_timeout, cancel);
        let report = upstream
            .send_attempt(
                &message.to_string(),
                &message,
                None,
                message.get("id"),
                Some(&limits),
            )
            .await;
        if let Some(digest) = report
            .reply
            .as_deref()
            .and_then(|reply| serde_json::from_str::<Value>(reply).ok())
            .and_then(|reply| {
                reply
                    .pointer("/result/structuredContent/rows/0/contract_digest")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
        {
            self.hosted_contracts
                .lock()
                .expect("hosted contracts")
                .insert(
                    cache_key.clone(),
                    Cached {
                        checked: Instant::now(),
                        ttl: self.config.contract_ttl,
                        value: digest,
                    },
                );
        }
        let value = report
            .reply
            .as_deref()
            .and_then(|reply| serde_json::from_str::<Value>(reply).ok())
            .and_then(|reply| {
                reply
                    .pointer("/result/structuredContent/rows/0/access")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .map_or(Access::Unknown, |access| match access.as_str() {
                "read" => Access::Read,
                "mutation" => Access::Write,
                _ => Access::Unknown,
            });
        if !cancel.is_cancelled() {
            let ttl = if value == Access::Unknown {
                Duration::from_secs(15).min(self.config.contract_ttl)
            } else {
                self.config.contract_ttl
            };
            self.access.lock().expect("access cache").insert(
                cache_key,
                Cached {
                    checked: Instant::now(),
                    ttl,
                    value,
                },
            );
        }
        value
    }

    /// Whether the operation's own input schema accepts `idempotency_key`,
    /// read from hosted's `describe_operation` and cached briefly. When hosted
    /// cannot say, the answer is `Unknown`, and only the operations the node
    /// may hold are then treated as keyed; the rest are sent once, as before.
    async fn accepts_key(
        &self,
        upstream: &Upstream,
        executor: &str,
        operation: &str,
        started: Instant,
        cancel: &Cancel,
    ) -> Keyed {
        let cache_key = (executor.to_owned(), operation.to_owned());
        if let Some(cached) = self.keyed.lock().expect("contract cache").get(&cache_key) {
            if cached.checked.elapsed() < cached.ttl {
                return cached.value;
            }
        }
        let Some(_turn) = self
            .lookup_turn(&self.keyed_lookups, &cache_key, started, cancel)
            .await
        else {
            return Keyed::Unknown;
        };
        if let Some(cached) = self.keyed.lock().expect("contract cache").get(&cache_key) {
            if cached.checked.elapsed() < cached.ttl {
                return cached.value;
            }
        }
        let message = json!({
            "jsonrpc": "2.0",
            "id": "node-contract",
            "method": "tools/call",
            "params": {
                "name": "describe_operation",
                "arguments": {"executor": executor, "operation": operation},
                "_meta": super::failover::probe_meta(),
            },
        });
        let limits = self.limits(started, self.config.contract_timeout, cancel);
        let report = upstream
            .send_attempt(
                &message.to_string(),
                &message,
                None,
                message.get("id"),
                Some(&limits),
            )
            .await;
        let schema = report
            .reply
            .as_deref()
            .and_then(|reply| serde_json::from_str::<Value>(reply).ok())
            .and_then(|reply| {
                reply
                    .pointer("/result/structuredContent/input_schema")
                    .cloned()
            });
        let (accepts_key, ttl) = match &schema {
            Some(schema) if schema_accepts_key(schema) => (Keyed::Yes, self.config.contract_ttl),
            Some(_) => (Keyed::No, self.config.contract_ttl),
            // Do not hammer a hosted that cannot describe right now.
            None => (
                Keyed::Unknown,
                Duration::from_secs(15).min(self.config.contract_ttl),
            ),
        };
        if !cancel.is_cancelled() {
            self.keyed.lock().expect("contract cache").insert(
                cache_key,
                Cached {
                    checked: Instant::now(),
                    ttl,
                    value: accepts_key,
                },
            );
        }
        accepts_key
    }
}

/// A stored reply, addressed to the request that is repeating the call.
fn with_request_id(stored: &str, id: Option<&Value>) -> String {
    match (serde_json::from_str::<Value>(stored), id) {
        (Ok(mut value), Some(id)) => {
            value["id"] = id.clone();
            value.to_string()
        }
        _ => stored.to_owned(),
    }
}

fn not_sent_report(id: Option<&Value>, message: &str) -> SendReport {
    SendReport {
        reply: frame_error(id, message, json!({"outcome":"not_sent"})),
        failure: None,
        attempt: Attempt::Stopped,
        status: None,
    }
}

fn not_sent(id: Option<&Value>, message: &str) -> SendReport {
    not_sent_report(id, message)
}

/// Add the node's journal note to hosted's own reply without altering any of
/// hosted's fields: a text line and a `node_journal` object, beside them.
fn annotate_hosted_reply(reply: &str, info: Value, key: &str) -> String {
    let Ok(mut value) = serde_json::from_str::<Value>(reply) else {
        return reply.to_owned();
    };
    if let Some(result) = value.get_mut("result").and_then(Value::as_object_mut) {
        if let Some(content) = result
            .entry("content")
            .or_insert_with(|| json!([]))
            .as_array_mut()
        {
            content.push(json!({"type":"text","text":format!(
                "Node note: an earlier attempt of this write may have been applied, so its outcome is uncertain. Retry the same call with idempotency_key={key}, or read the record before writing again."
            )}));
        }
        let structured = result
            .entry("structuredContent")
            .or_insert_with(|| json!({}));
        if let Some(structured) = structured.as_object_mut() {
            structured.insert("node_journal".into(), info);
        }
    } else if let Some(error) = value.get_mut("error").and_then(Value::as_object_mut) {
        // A plain JSON-RPC error may carry no `data`, or data that is not an
        // object. Make room for the note without discarding hosted's value.
        match error.get_mut("data") {
            Some(Value::Object(data)) => {
                data.insert("node_journal".into(), info);
            }
            Some(other) if !other.is_null() => {
                let original = other.take();
                *other = json!({"upstream_data": original, "node_journal": info});
            }
            _ => {
                error.insert("data".into(), json!({"node_journal": info}));
            }
        }
    } else {
        return reply.to_owned();
    }
    value.to_string()
}

/// True when every valid call to the operation may carry a top-level
/// `idempotency_key`. Conservative about JSON Schema's closed objects: a
/// schema that declares `additionalProperties: false` without the key (or
/// `patternProperties` we do not evaluate) rejects it, and `allOf` members
/// are all in force, so one member declaring the key does not help if
/// another closes the object. A key accepted by only some `oneOf`/`anyOf`
/// branches is not injected either. `if`/`then` and nested objects are not
/// considered.
pub(super) fn schema_accepts_key(schema: &Value) -> bool {
    declares_key(schema) && !closes_out_key(schema)
}

fn declares_key(schema: &Value) -> bool {
    if schema
        .pointer("/properties/idempotency_key")
        .is_some_and(Value::is_object)
    {
        return true;
    }
    if schema
        .get("allOf")
        .and_then(Value::as_array)
        .is_some_and(|members| members.iter().any(declares_key))
    {
        return true;
    }
    ["oneOf", "anyOf"].iter().any(|keyword| {
        schema
            .get(*keyword)
            .and_then(Value::as_array)
            .is_some_and(|branches| !branches.is_empty() && branches.iter().all(schema_accepts_key))
    })
}

/// A schema (or an `allOf` member of it) that would refuse the key.
fn closes_out_key(schema: &Value) -> bool {
    let declares_here = schema
        .pointer("/properties/idempotency_key")
        .is_some_and(Value::is_object);
    let closed = schema.get("additionalProperties") == Some(&Value::Bool(false))
        || schema.get("patternProperties").is_some()
        || schema.get("unevaluatedProperties") == Some(&Value::Bool(false));
    (closed && !declares_here)
        || schema
            .get("allOf")
            .and_then(Value::as_array)
            .is_some_and(|members| members.iter().any(closes_out_key))
}

/// The caller's key if it sent a usable one, else a minted key written into
/// `message`. Returns `None` (nothing changed) when the arguments cannot hold
/// a key. Run key and attribution are never touched.
fn prepare_key(message: &mut Value, envelope: &Value) -> Option<(String, KeyOrigin)> {
    match envelope.get("arguments") {
        Some(Value::Object(arguments)) => match arguments.get("idempotency_key") {
            // Hosted trims the key and treats a blank one (and null) as no
            // key at all, so a retry would not be deduplicated. `str::trim`
            // is the rule hosted applies (`keyed_replay.rs`, `lifecycle.rs`).
            Some(Value::String(key)) if !key.trim().is_empty() => {
                return Some((key.clone(), KeyOrigin::Caller))
            }
            // Present but not a usable key: leave the caller's value exactly
            // as sent, send once, and let hosted judge it.
            Some(_) => return None,
            None => {}
        },
        Some(_) => return None,
        None => {}
    }
    let key = format!("node-{}", uuid::Uuid::new_v4());
    let arguments = message
        .pointer_mut("/params/arguments")?
        .as_object_mut()?
        .entry("arguments")
        .or_insert_with(|| json!({}))
        .as_object_mut()?;
    arguments.insert("idempotency_key".into(), json!(key));
    Some((key, KeyOrigin::Node))
}

#[derive(Debug, PartialEq, Eq)]
enum Answer {
    Receipt,
    Refused,
    HostedPending,
    RetryableNotReady,
    /// Hosted says some of it may have been applied.
    Partial,
}

/// Read hosted's own words. Engine errors arrive as a tool result with
/// `isError` and `structuredContent` carrying `applied` (`false` refused,
/// `true` committed but receipt not rebuilt, `"partial"`) or
/// `outcome: unknown`; gateway-shaped bodies arrive framed with the hosted
/// body under `upstream_body`.
fn answer_of(reply: Option<&str>) -> Answer {
    let Some(reply) = reply.and_then(|r| serde_json::from_str::<Value>(r).ok()) else {
        return Answer::Receipt;
    };
    if let Some(body) = reply.pointer("/error/data/upstream_body") {
        let nested = body.get("error").filter(|error| error.is_object());
        if let Some(answer) = [Some(body), nested].into_iter().flatten().find_map(judge) {
            return answer;
        }
        let status = reply
            .pointer("/error/data/http_status")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        return if (400..500).contains(&status) {
            Answer::Refused
        } else {
            Answer::Partial
        };
    }
    if let Some(answer) = reply.pointer("/result/structuredContent").and_then(judge) {
        return answer;
    }
    if let Some(answer) = outbox_text_body(&reply).as_ref().and_then(judge) {
        return answer;
    }
    if reply.pointer("/result/isError") == Some(&Value::Bool(true)) || reply.get("error").is_some()
    {
        Answer::Refused
    } else {
        Answer::Receipt
    }
}

/// Hosted's refusal of a key it cannot honour on this call, which it makes
/// before any effect: "... idempotency_key ...; retry without a key", or
/// "without it", sometimes followed by a parenthetical such as
/// `manage_messages.share_history`'s "(it is already safe to repeat ...)".
/// The engine puts its message in `structuredContent.error`. appHost's
/// `KEY_UNSUPPORTED` anchors the tail at the end and so misses the
/// parenthetical form.
fn refuses_key(reply: Option<&str>) -> bool {
    let Some(reply) = reply.and_then(|r| serde_json::from_str::<Value>(r).ok()) else {
        return false;
    };
    if reply.pointer("/result/isError") != Some(&Value::Bool(true)) {
        return false;
    }
    reply
        .pointer("/result/structuredContent/error")
        .and_then(Value::as_str)
        .is_some_and(|message| {
            message.contains("idempotency_key")
                && ["; retry without a key", "; retry without it"]
                    .iter()
                    .any(|tail| {
                        message.match_indices(tail).any(|(at, _)| {
                            let rest = message[at + tail.len()..].trim();
                            rest.is_empty() || (rest.starts_with('(') && rest.ends_with(')'))
                        })
                    })
        })
}

fn judge(body: &Value) -> Option<Answer> {
    if body.get("outcome").and_then(Value::as_str) == Some("accepted_pending")
        && body.get("canonical").and_then(Value::as_bool) == Some(false)
    {
        return Some(Answer::HostedPending);
    }
    if body.get("error_code").and_then(Value::as_str) == Some("OUTBOX_NOT_READY")
        && body.get("retryable").and_then(Value::as_bool) == Some(true)
        && body.get("applied").and_then(Value::as_bool) == Some(false)
        && body.get("outcome").and_then(Value::as_str) == Some("not_sent")
    {
        return Some(Answer::RetryableNotReady);
    }
    match body.get("applied") {
        Some(Value::Bool(false)) => return Some(Answer::Refused),
        Some(Value::Bool(true)) => return Some(Answer::Receipt),
        Some(Value::String(_)) => return Some(Answer::Partial),
        _ => {}
    }
    if body.get("partial").and_then(Value::as_bool) == Some(true) {
        return Some(Answer::Partial);
    }
    match body.get("outcome").and_then(Value::as_str) {
        Some("refused" | "not_sent") => Some(Answer::Refused),
        Some("unknown" | "uncertain" | "partial") => Some(Answer::Partial),
        _ => match body.get("status").and_then(Value::as_str) {
            Some("conflict") => Some(Answer::Refused),
            // A stale suggestion can itself have been marked failed. A
            // successful rejection commits an act, so it is not a refusal.
            Some("rejected")
                if body
                    .get("act")
                    .and_then(Value::as_i64)
                    .is_some_and(|act| act > 0) =>
            {
                Some(Answer::Receipt)
            }
            Some("stale" | "rejected") => Some(Answer::Partial),
            _ => None,
        },
    }
}

fn hosted_pending_journal(reply: Option<&str>) -> Option<String> {
    let value: Value = serde_json::from_str(reply?).ok()?;
    let body = value
        .pointer("/result/structuredContent")
        .cloned()
        .or_else(|| {
            value.pointer("/error/data/upstream_body").map(|body| {
                body.get("error")
                    .filter(|error| error.is_object())
                    .unwrap_or(body)
                    .clone()
            })
        })
        .or_else(|| outbox_text_body(&value))?;
    if judge(&body) != Some(Answer::HostedPending) {
        return None;
    }
    body.get("journal_entry")?
        .as_str()
        .filter(|entry| !entry.is_empty() && entry.len() <= 256)
        .map(str::to_owned)
}

/// Legacy MCP replies carry JSON in a text block. Only recognise the explicit
/// outbox protocol here, never arbitrary status fields in authored content.
fn outbox_text_body(reply: &Value) -> Option<Value> {
    reply
        .pointer("/result/content")?
        .as_array()?
        .iter()
        .find_map(|block| {
            let body: Value = serde_json::from_str(block.get("text")?.as_str()?).ok()?;
            matches!(
                judge(&body),
                Some(Answer::HostedPending | Answer::RetryableNotReady)
            )
            .then_some(body)
        })
}

#[cfg(test)]
mod tests;
