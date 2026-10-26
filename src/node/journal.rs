//! Write-ahead journal for writes the node forwards to hosted (slice 2A).
//!
//! Every forwarded write is saved here *before* it is sent, then settled when
//! hosted answers. The journal exists so that a crash, a restart or a lost
//! reply leaves an honest, inspectable record of what may or may not have
//! been applied. It is never a replay queue: nothing in this module sends
//! anything, and entries left in flight at startup become `uncertain`.
//!
//! Layout: one JSON file per entry in `<socket_directory>/journal/`
//! (directory 0700, files 0600), written by temp-file + fsync + rename. Entry
//! files carry the call's arguments and so may hold record bodies; settled
//! entries drop them and are pruned after a short retention.
use super::hold;
use super::*;
use serde::Serialize;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::Mutex as StdMutex;

/// Still 1 after slice 2B, deliberately. Every field 2B adds is optional or
/// defaulted and absent from entries that don't use it, so a 2B build reads
/// slice 2A files unchanged. The reverse matters more: a 2A build refuses a
/// file whose `version` is newer than its own and counts it only as an
/// "unreadable file". At version 1 it parses a held entry, meets the state
/// `pending` it does not know, files it as `Unrecognised` and leaves it alone,
/// which is the rollback behaviour the format reserved `pending` for, and it
/// keeps showing that entry in its state counts. Raise this only for a change
/// an older reader could misread, not for new optional fields.
pub(super) const ENTRY_VERSION: u32 = 1;
const MAX_ENTRY_BYTES: u64 = MAX_FRAME as u64 * 2 + 64 * 1024;
/// Settled entries are kept this long so a person can see what just happened.
pub(super) const CONFIRMED_RETENTION: Duration = Duration::from_secs(60 * 60);
const PRUNE_EVERY: Duration = Duration::from_secs(60);

/// Entry states. `pending` (slice 2B) is a write the node has accepted on the
/// caller's behalf and will send later. A build that predates it reads the
/// state as `Unrecognised` and leaves the entry alone, neither settling nor
/// sending it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum EntryState {
    /// Saved, and being (or about to be) sent. Not a terminal state.
    Sent,
    /// Hosted gave a definitive answer: a receipt, or a refusal.
    Confirmed,
    /// Every attempt failed before anything reached hosted.
    NotSent,
    /// The outcome is unknown. Only the caller (or a person) can settle it.
    Uncertain,
    /// Accepted by the node while hosted could not take writes, and waiting to
    /// be sent in sequence order. Keeps its arguments; never pruned.
    Pending,
    /// Hosted durably accepted the write but has not reported a canonical
    /// outcome. Never pruned or automatically sent by the node.
    HostedPending,
    /// A state written by a newer build.
    #[serde(other)]
    Unrecognised,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum KeyOrigin {
    Caller,
    Node,
}

/// Why the node took a write over instead of forwarding it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HoldReason {
    /// Hosted answered `DEPLOYMENT_READ_ONLY`.
    DeploymentReadOnly,
    /// Hosted was unreachable on a forward and on a follow-up check.
    HostedUnreachable,
    /// A reason written by a newer build.
    #[serde(other)]
    Other,
}

impl HoldReason {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::DeploymentReadOnly => "deployment_read_only",
            Self::HostedUnreachable => "hosted_unreachable",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Entry {
    pub(super) version: u32,
    pub(super) id: String,
    pub(super) state: EntryState,
    pub(super) received_at: String,
    pub(super) received_unix_ms: u64,
    pub(super) updated_at: String,
    pub(super) executor: String,
    pub(super) operation: String,
    /// The MCP tool name the call arrived under (`call_executor` or an executor).
    pub(super) tool: String,
    pub(super) run_key: Option<String>,
    pub(super) client_info: Option<Value>,
    /// `None` when the operation's contract has no `idempotency_key`.
    pub(super) idempotency_key: Option<String>,
    pub(super) key_origin: Option<KeyOrigin>,
    pub(super) attempts: u32,
    /// SHA-256 of the operation arguments (including the key).
    pub(super) arguments_digest: String,
    pub(super) arguments_bytes: usize,
    /// Present while the outcome is open; dropped once settled.
    pub(super) arguments: Option<Value>,
    /// `receipt` or `refused`, once hosted has answered.
    pub(super) answer: Option<String>,
    pub(super) detail: Option<String>,
    pub(super) resolved_by: Option<String>,
    // Added in slice 2B. All defaulted, and absent from the file unless used.
    /// Order of receipt, monotonic across restarts. Millisecond times can
    /// tie, so the send queue orders by this. 0 on entries from slice 2A.
    #[serde(default)]
    pub(super) seq: u64,
    /// The run that started the calling run, for status and bootstrap views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) parent_key: Option<String>,
    /// The record's title, where the arguments give one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) title: Option<String>,
    /// The record this write creates or changes. For a held create it is the
    /// node-chosen ID, returned to the caller before anything is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) hold_reason: Option<HoldReason>,
    /// Every record a held `create_many` creates, in input order. Node-chosen
    /// where the caller gave none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) record_ids: Vec<String>,
    /// The call's envelope without its `arguments`: `run_key`, `parent_key`,
    /// `format`. With `arguments`, `executor`, `operation` and `tool` it is
    /// enough to rebuild the request exactly. Kept only while the entry is open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) envelope: Option<Value>,
    /// Digest of what the caller asked (key set, node-chosen IDs left out),
    /// so a repeat of the same call can be recognised whatever the node added.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) intent_digest: Option<String>,
    /// The write was already in flight when the node took it over, so it may
    /// have been applied. Resending with its key settles that either way.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) maybe_applied: bool,
    /// What a repeat of a held call is answered with once the node has sent
    /// it: hosted's receipt or refusal, or the node's own note. Bounded;
    /// absent when too large, and a repeat then goes to hosted with its key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) reply: Option<String>,
    /// A queue send of this entry was started and its outcome not yet saved.
    /// Found set at startup, it means the node died mid-send.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) in_flight: bool,
    /// The held write this one was refused for depending on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) refused_because: Option<String>,
    /// Hosted's custody handle, distinct from this node journal's entry id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) hosted_journal_entry: Option<String>,
}

/// What a `node_status` read asks for. Every field narrows the list.
#[derive(Clone, Debug, Default)]
pub(super) struct StatusFilter {
    pub(super) run: Option<String>,
    pub(super) parent_run: Option<String>,
    /// View states: pending, hosted_pending, sent, refused, uncertain,
    /// not_sent, unrecognised.
    pub(super) states: Vec<String>,
    pub(super) limit: usize,
    /// List the newest writes first (`order: "newest_first"`). The default is
    /// the order they were accepted in.
    pub(super) newest_first: bool,
}

/// A stored reply larger than this is dropped rather than kept.
const MAX_STORED_REPLY: usize = 256 * 1024;

/// What the caller provides for a new entry.
pub(super) struct NewEntry {
    pub(super) executor: String,
    pub(super) operation: String,
    pub(super) tool: String,
    pub(super) run_key: Option<String>,
    pub(super) client_info: Option<Value>,
    pub(super) idempotency_key: Option<String>,
    pub(super) key_origin: Option<KeyOrigin>,
    pub(super) arguments: Value,
    pub(super) parent_key: Option<String>,
    pub(super) title: Option<String>,
    pub(super) record_id: Option<String>,
    pub(super) record_ids: Vec<String>,
    pub(super) envelope: Option<Value>,
    pub(super) intent_digest: Option<String>,
}

pub(super) fn arguments_digest(arguments: &Value) -> String {
    crate::canonical_json::digest_json(arguments)
}

/// Canonical argument equivalence for same-key settlement. Both sides with
/// retained arguments compare canonical digests directly; a settled receipt
/// drops its arguments, so a retained earlier entry re-digests canonically
/// against the receipt's stored digest. Stored-digest equality stays as a
/// fallback for entries written before the canonical digest. All branches
/// preserve array order through the canonical form.
fn arguments_equivalent(earlier: &Entry, settled: &Entry) -> bool {
    match (&earlier.arguments, &settled.arguments) {
        (Some(a), Some(b)) => {
            crate::canonical_json::digest_json(a) == crate::canonical_json::digest_json(b)
        }
        (Some(a), None) => {
            let canonical = crate::canonical_json::digest_json(a);
            canonical == settled.arguments_digest
                || earlier.arguments_digest == settled.arguments_digest
        }
        (None, _) => earlier.arguments_digest == settled.arguments_digest,
    }
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

fn stamp() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

pub(super) struct Journal {
    directory: PathBuf,
    entries: StdMutex<BTreeMap<String, Entry>>,
    last_prune: StdMutex<std::time::Instant>,
    retention: Duration,
    /// How long a refused held write is kept. A refusal is not dropped after
    /// the usual retention: it is the answer to "what didn't make it".
    pub(super) refusal_retention: Duration,
    /// Entries found on disk that this build cannot read or does not own.
    unreadable: usize,
    /// The next sequence number to hand out; recovered from the entries.
    next_seq: std::sync::atomic::AtomicU64,
    /// Test hook: fail the write after this many more (negative: never).
    #[cfg(test)]
    pub(super) fail_after: std::sync::atomic::AtomicI64,
}

impl Journal {
    /// Open (creating if needed) and recover. Entries left `sent` by a
    /// previous process become `uncertain`; nothing is sent.
    #[cfg(test)]
    pub(super) fn open(socket_directory: &Path, retention: Duration) -> Result<Self> {
        Self::open_with(socket_directory, retention, retention)
    }

    /// As `open`, with the (usually longer) retention for refused held
    /// writes in force from the start, so the pruning done at startup cannot
    /// drop a refusal earlier than the running node would.
    pub(super) fn open_with(
        socket_directory: &Path,
        retention: Duration,
        refusal_retention: Duration,
    ) -> Result<Self> {
        let directory = socket_directory.join("journal");
        validate_credential_path(&directory, "node journal directory")?;
        match fs::symlink_metadata(&directory) {
            Ok(meta) => {
                if !meta.is_dir() {
                    return Err(Error::engine("invalid node journal directory"));
                }
                check_owned(&meta, 0o700)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new().mode(0o700).create(&directory)?;
                // The new directory's entry lives in its parent: until that
                // is on disk, every fsynced entry file inside could vanish
                // with it. Failing here fails startup.
                File::open(socket_directory)?.sync_all()?;
            }
            Err(e) => return Err(e.into()),
        }
        let mut journal = Self {
            directory,
            entries: StdMutex::new(BTreeMap::new()),
            last_prune: StdMutex::new(std::time::Instant::now()),
            retention,
            refusal_retention,
            unreadable: 0,
            next_seq: std::sync::atomic::AtomicU64::new(1),
            #[cfg(test)]
            fail_after: std::sync::atomic::AtomicI64::new(-1),
        };
        journal.load()?;
        journal.prune();
        Ok(journal)
    }

    fn path(&self, id: &str) -> PathBuf {
        self.directory.join(format!("{id}.json"))
    }

    fn load(&mut self) -> Result<()> {
        let mut entries = BTreeMap::new();
        for item in fs::read_dir(&self.directory)? {
            let path = item?.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_owned();
            if name.contains(".tmp") {
                // A write that never reached its rename: the entry it was
                // about to create or replace is still intact (or absent).
                let _ = fs::remove_file(&path);
                continue;
            }
            let Some(id) = name.strip_suffix(".json") else {
                self.unreadable += 1;
                continue;
            };
            match read_entry(&path) {
                Ok(entry) if entry.id == id => {
                    entries.insert(entry.id.clone(), entry);
                }
                _ => self.unreadable += 1,
            }
        }
        for entry in entries.values_mut() {
            if entry.state == EntryState::Sent {
                entry.state = EntryState::Uncertain;
                entry.detail = Some(
                    "the node stopped while this write was in flight; whether hosted applied it is unknown".into(),
                );
                entry.updated_at = stamp();
                self.write(entry)?;
            }
        }
        // A queue send the node died in the middle of. Resending with its key
        // is safe and stays on the table, but the write may already have been
        // applied, and every later reply says so.
        for entry in entries.values_mut() {
            if !entry.in_flight {
                continue;
            }
            entry.in_flight = false;
            entry.updated_at = stamp();
            if entry.state == EntryState::Pending {
                entry.maybe_applied = true;
                entry.detail = Some(
                    "the node stopped while sending this write; it may already have been applied. Sending it again with its key is safe".into(),
                );
            }
            self.write(entry)?;
        }
        // Pending entries are never pruned, so the highest sequence among the
        // survivors is above every pending one and ordering holds. Numbers
        // already handed to pruned entries may be reused; nothing orders by them.
        let top = entries.values().map(|e| e.seq).max().unwrap_or(0);
        *self.next_seq.get_mut() = top + 1;
        *self.entries.get_mut().expect("journal entries") = entries;
        Ok(())
    }

    fn write(&self, entry: &Entry) -> Result<()> {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering::SeqCst;
            // After this many more successful writes, fail one.
            let left = self.fail_after.load(SeqCst);
            if left == 0 {
                self.fail_after.store(-1, SeqCst);
                return Err(Error::engine("injected journal write failure"));
            }
            if left > 0 {
                self.fail_after.store(left - 1, SeqCst);
            }
        }
        let path = self.path(&entry.id);
        let temporary = self
            .directory
            .join(format!("{}.{}.tmp", entry.id, uuid::Uuid::new_v4()));
        let result = (|| {
            let bytes = serde_json::to_vec(entry)?;
            if bytes.len() as u64 > MAX_ENTRY_BYTES {
                return Err(Error::engine("journal entry exceeds bound"));
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            output.write_all(&bytes)?;
            output.sync_all()?;
            fs::rename(&temporary, &path)?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    /// Save a new entry in state `sent`. Failure means nothing may be sent.
    pub(super) fn begin(&self, new: NewEntry) -> Result<Entry> {
        let digest = arguments_digest(&new.arguments);
        let bytes = new.arguments.to_string().len();
        let received_ms = now_ms();
        let entry = Entry {
            version: ENTRY_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            state: EntryState::Sent,
            received_at: stamp(),
            received_unix_ms: received_ms,
            updated_at: stamp(),
            executor: new.executor,
            operation: new.operation,
            tool: new.tool,
            run_key: new.run_key,
            client_info: new.client_info,
            idempotency_key: new.idempotency_key,
            key_origin: new.key_origin,
            attempts: 0,
            arguments_digest: digest,
            arguments_bytes: bytes,
            arguments: Some(new.arguments),
            answer: None,
            detail: None,
            resolved_by: None,
            seq: self
                .next_seq
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel),
            parent_key: new.parent_key,
            title: new.title,
            record_id: new.record_id,
            hold_reason: None,
            record_ids: new.record_ids,
            envelope: new.envelope,
            intent_digest: new.intent_digest,
            maybe_applied: false,
            reply: None,
            in_flight: false,
            refused_because: None,
            hosted_journal_entry: None,
        };
        self.write(&entry)?;
        self.entries
            .lock()
            .expect("journal entries")
            .insert(entry.id.clone(), entry.clone());
        self.maybe_prune();
        Ok(entry)
    }

    /// Apply `change` to an entry and persist it. The in-memory copy changes
    /// only if the write succeeds.
    pub(super) fn update(&self, id: &str, change: impl FnOnce(&mut Entry)) -> Result<Entry> {
        let mut entries = self.entries.lock().expect("journal entries");
        let Some(current) = entries.get(id) else {
            return Err(Error::engine("journal entry missing"));
        };
        let mut next = current.clone();
        change(&mut next);
        next.updated_at = stamp();
        self.write(&next)?;
        entries.insert(id.to_owned(), next.clone());
        Ok(next)
    }

    /// Record that an attempt is about to be made. Saved before the send.
    pub(super) fn note_attempt(&self, id: &str) -> Result<Entry> {
        self.update(id, |entry| entry.attempts += 1)
    }

    pub(super) fn settle(
        &self,
        id: &str,
        state: EntryState,
        answer: Option<&str>,
        detail: Option<String>,
    ) -> Result<Entry> {
        let entry = self.update(id, |entry| {
            entry.state = state;
            entry.answer = answer.map(str::to_owned);
            entry.detail = detail;
            if !matches!(
                state,
                EntryState::Uncertain | EntryState::Pending | EntryState::HostedPending
            ) {
                // Settled: keep the shape of the call, not its content.
                entry.arguments = None;
                entry.envelope = None;
            }
        })?;
        Ok(entry)
    }

    /// The node takes this write over: it stays on disk with its arguments,
    /// in order, until it is sent. From `sent` (a forward hosted refused as
    /// read-only, or could not be reached for) or from `uncertain` (a keyed
    /// write that may already have landed, which resending with its key
    /// settles safely). Any other state is left as it is.
    pub(super) fn hold(
        &self,
        id: &str,
        reason: HoldReason,
        detail: String,
        maybe_applied: bool,
    ) -> Result<Entry> {
        self.update(id, |entry| {
            if matches!(entry.state, EntryState::Sent | EntryState::Uncertain) {
                entry.state = EntryState::Pending;
                entry.hold_reason = Some(reason);
                entry.detail = Some(detail);
                entry.maybe_applied = maybe_applied;
            }
        })
    }

    pub(super) fn hosted_pending(
        &self,
        id: &str,
        hosted_journal_entry: Option<String>,
    ) -> Result<Entry> {
        self.update(id, |entry| {
            entry.state = EntryState::HostedPending;
            entry.hosted_journal_entry = hosted_journal_entry;
            entry.answer = None;
            entry.reply = None;
            entry.in_flight = false;
            entry.detail = Some("held by hosted; not yet a canonical receipt; repeat the same keyed call to check hosted".into());
        })
    }

    /// Do not send a dependent node-held write ahead of a create that hosted
    /// still holds. Its caller's canonical retry can resolve that custody.
    pub(super) fn hosted_pending_creator_of(&self, entry: &Entry) -> bool {
        let Some(arguments) = &entry.arguments else {
            return false;
        };
        let wanted = hold::references(&entry.operation, arguments);
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .any(|prior| {
                prior.state == EntryState::HostedPending
                    && prior.seq < entry.seq
                    && hold::creates(&prior.operation)
                    && prior
                        .record_ids
                        .iter()
                        .chain(prior.record_id.iter())
                        .any(|id| wanted.contains(id))
            })
    }

    /// Save that a queue send of this entry is about to start: one more
    /// attempt, in flight. One write, before the send; if it fails the caller
    /// must not send. An in-flight marker that survived an earlier attempt
    /// whose outcome could not be saved means that attempt may have been
    /// applied: it is promoted to `maybe_applied` in this same write, before the
    /// marker is replaced, and `maybe_applied` is never cleared afterwards.
    pub(super) fn begin_queue_send(&self, id: &str) -> Result<Entry> {
        self.update(id, |entry| {
            entry.maybe_applied |= entry.in_flight;
            entry.attempts += 1;
            entry.in_flight = true;
        })
    }

    /// The oldest pending entry: the next to be sent.
    pub(super) fn oldest_pending(&self) -> Option<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| e.state == EntryState::Pending)
            .min_by_key(|e| e.seq)
            .cloned()
    }

    pub(super) fn pending_count(&self) -> usize {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| e.state == EntryState::Pending)
            .count()
    }

    /// A held write the node has since settled, found by its key, for
    /// answering a repeat of the call.
    pub(super) fn settled_held_with_key(
        &self,
        executor: &str,
        operation: &str,
        key: &str,
    ) -> Option<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                e.state == EntryState::Confirmed
                    && e.hold_reason.is_some()
                    && e.reply.is_some()
                    && e.executor == executor
                    && e.operation == operation
                    && e.idempotency_key.as_deref() == Some(key)
            })
            .max_by_key(|e| e.seq)
            .cloned()
    }

    /// A refused held create that `entry` refers to: it would have made a
    /// record the entry needs. Read from what is on disk, so it holds across a
    /// crash between a refusal and the refusals that follow from it.
    pub(super) fn refused_creator_of(&self, entry: &Entry) -> Option<(Entry, Vec<String>)> {
        let wanted = hold::references(&entry.operation, entry.arguments.as_ref()?);
        if wanted.is_empty() {
            return None;
        }
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|r| {
                r.id != entry.id
                    && r.seq < entry.seq
                    && r.state == EntryState::Confirmed
                    && r.answer.as_deref() == Some("refused")
                    && r.hold_reason.is_some()
                    && hold::creates(&r.operation)
            })
            .filter_map(|r| {
                let matched: Vec<String> = r
                    .record_ids
                    .iter()
                    .chain(r.record_id.iter())
                    .filter(|id| wanted.contains(id))
                    .cloned()
                    .collect();
                (!matched.is_empty()).then(|| (r.clone(), matched))
            })
            .min_by_key(|(r, _)| r.seq)
    }

    /// Pending entries after `seq` that refer to any of `ids`, by the
    /// fields that hold references (see [`hold::references`]).
    pub(super) fn pending_referring_to(&self, ids: &[String], after_seq: u64) -> Vec<Entry> {
        let mut found: Vec<Entry> = self
            .entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                e.state == EntryState::Pending
                    && e.seq > after_seq
                    && e.arguments.as_ref().is_some_and(|a| {
                        hold::references(&e.operation, a)
                            .iter()
                            .any(|reference| ids.contains(reference))
                    })
            })
            .cloned()
            .collect();
        found.sort_by_key(|e| e.seq);
        found
    }

    /// Settle a held write the node has sent (or refused to send). A refused
    /// write keeps its arguments, so what did not make it can be recovered.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn finish_held(
        &self,
        id: &str,
        state: EntryState,
        answer: Option<&str>,
        detail: String,
        reply: Option<String>,
        keep_arguments: bool,
        refused_because: Option<String>,
    ) -> Result<Entry> {
        self.update(id, |entry| {
            entry.state = state;
            entry.answer = answer.map(str::to_owned);
            entry.detail = Some(detail);
            entry.reply = reply.filter(|r| r.len() <= MAX_STORED_REPLY);
            entry.refused_because = refused_because;
            entry.in_flight = false;
            if !keep_arguments {
                entry.arguments = None;
                entry.envelope = None;
            }
        })
    }

    /// The pending entry, if any, that holds this keyed call.
    pub(super) fn pending_with_key(
        &self,
        executor: &str,
        operation: &str,
        key: &str,
    ) -> Option<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                e.state == EntryState::Pending
                    && e.executor == executor
                    && e.operation == operation
                    && e.idempotency_key.as_deref() == Some(key)
            })
            .min_by_key(|e| e.seq)
            .cloned()
    }

    pub(super) fn hosted_pending_with_key(
        &self,
        executor: &str,
        operation: &str,
        key: &str,
    ) -> Option<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                e.state == EntryState::HostedPending
                    && e.executor == executor
                    && e.operation == operation
                    && e.idempotency_key.as_deref() == Some(key)
            })
            .min_by_key(|e| e.seq)
            .cloned()
    }

    /// 1 for the entry next to be sent: pending entries up to and including
    /// this sequence number.
    pub(super) fn pending_position(&self, seq: u64) -> usize {
        self.entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| e.state == EntryState::Pending && e.seq <= seq)
            .count()
    }

    /// An agent that retried an uncertain call with its returned key and got
    /// an answer has settled the earlier entry too. Match on the same
    /// executor, operation, key *and* arguments: the same key with different
    /// content is a different question. Arguments compare under RFC 8785
    /// canonical JSON (array order preserved), so reordered object fields
    /// still match while different values, array order or calls do not.
    /// Entries written before the canonical digest keep working through a
    /// stored-digest fallback; settled entries drop their arguments, so a
    /// retained earlier entry re-digests canonically against the receipt's
    /// stored digest. Only `uncertain`/`hosted_pending` entries settle, and both sides must
    /// carry the same key: an unkeyed earlier entry never matches.
    pub(super) fn resolve_earlier(&self, settled: &Entry) {
        // Only a receipt says what the earlier call became; a refusal of the
        // retry (read-only, auth, validation) leaves that question open.
        if settled.state != EntryState::Confirmed || settled.answer.as_deref() != Some("receipt") {
            return;
        }
        let Some(key) = settled.idempotency_key.as_deref() else {
            return;
        };
        let earlier: Vec<String> = self
            .entries
            .lock()
            .expect("journal entries")
            .values()
            .filter(|e| {
                matches!(e.state, EntryState::Uncertain | EntryState::HostedPending)
                    && e.id != settled.id
                    && e.executor == settled.executor
                    && e.operation == settled.operation
                    && e.idempotency_key.as_deref() == Some(key)
                    && arguments_equivalent(e, settled)
            })
            .map(|e| e.id.clone())
            .collect();
        for id in earlier {
            let by = settled.id.clone();
            let answer = settled.answer.clone();
            let _ = self.update(&id, |entry| {
                entry.state = EntryState::Confirmed;
                entry.answer = answer;
                entry.arguments = None;
                entry.envelope = None;
                entry.resolved_by = Some(by.clone());
                entry.detail = Some(format!(
                    "settled by the caller's retry with the same key (entry {by})"
                ));
            });
        }
    }

    fn maybe_prune(&self) {
        let due = {
            let mut last = self.last_prune.lock().expect("journal prune clock");
            if last.elapsed() < PRUNE_EVERY {
                false
            } else {
                *last = std::time::Instant::now();
                true
            }
        };
        if due {
            self.prune();
        }
    }

    /// Remove settled entries older than the retention. Uncertain and pending
    /// entries are never pruned: they are the open questions, and a pending
    /// entry is the only copy of a write the caller was told was accepted.
    pub(super) fn prune(&self) {
        let now = now_ms();
        let cutoff = now.saturating_sub(self.retention.as_millis() as u64);
        let refusal_cutoff = now.saturating_sub(self.refusal_retention.as_millis() as u64);
        let mut entries = self.entries.lock().expect("journal entries");
        let expired: Vec<String> = entries
            .values()
            .filter(|e| {
                let refused_held = e.hold_reason.is_some()
                    && e.state == EntryState::Confirmed
                    && e.answer.as_deref() == Some("refused");
                let limit = if refused_held { refusal_cutoff } else { cutoff };
                matches!(e.state, EntryState::Confirmed | EntryState::NotSent)
                    && chrono::DateTime::parse_from_rfc3339(&e.updated_at)
                        .map(|t| (t.timestamp_millis().max(0) as u64) < limit)
                        .unwrap_or(false)
            })
            .map(|e| e.id.clone())
            .collect();
        for id in expired {
            if fs::remove_file(self.path(&id)).is_ok() {
                entries.remove(&id);
            }
        }
    }

    pub(super) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(super) fn get(&self, id: &str) -> Option<Entry> {
        self.entries
            .lock()
            .expect("journal entries")
            .get(id)
            .cloned()
    }

    /// Where a write stands, in the words a person uses. `None` for a write
    /// that was never held and has settled: only the open questions and the
    /// held writes are listed.
    fn view_state(entry: &Entry) -> Option<&'static str> {
        let held = entry.hold_reason.is_some();
        match entry.state {
            EntryState::Pending => Some("pending"),
            EntryState::HostedPending => Some("hosted_pending"),
            EntryState::Unrecognised => Some("unrecognised"),
            EntryState::Confirmed if held => Some(match entry.answer.as_deref() {
                Some("refused") => "refused",
                _ => "sent",
            }),
            EntryState::Uncertain if held => Some("uncertain"),
            EntryState::NotSent if held => Some("not_sent"),
            _ => None,
        }
    }

    /// Held, sent and refused writes, filtered, for `node_status`. Never
    /// carries record bodies.
    pub(super) fn held_writes(&self, filter: &StatusFilter, record_base: Option<&str>) -> Value {
        let entries = self.entries.lock().expect("journal entries");
        let mut counts = serde_json::Map::new();
        let mut rows: Vec<&Entry> = Vec::new();
        for entry in entries.values() {
            let Some(state) = Self::view_state(entry) else {
                continue;
            };
            let wanted = filter
                .run
                .as_ref()
                .is_none_or(|r| entry.run_key.as_ref() == Some(r))
                && filter
                    .parent_run
                    .as_ref()
                    .is_none_or(|p| entry.parent_key.as_ref() == Some(p))
                && (filter.states.is_empty() || filter.states.iter().any(|s| s == state));
            if !wanted {
                continue;
            }
            let count = counts.entry(state).or_insert(json!(0));
            *count = json!(count.as_u64().unwrap_or(0) + 1);
            rows.push(entry);
        }
        rows.sort_by_key(|e| e.seq);
        if filter.newest_first {
            rows.reverse();
        }
        let matched = rows.len();
        let limit = filter.limit.max(1);
        let writes: Vec<Value> = rows
            .into_iter()
            .take(limit)
            .map(|entry| {
                let state = Self::view_state(entry).unwrap_or("unknown");
                let mut view = json!({
                    "id": entry.id,
                    "state": state,
                    "operation": entry.operation,
                    "title": entry.title,
                    "accepted_at": entry.received_at,
                    "updated_at": entry.updated_at,
                    "reason": entry.hold_reason.map(HoldReason::as_str),
                    "detail": entry.detail,
                    "idempotency_key": entry.idempotency_key,
                    "run_key": entry.run_key,
                    "parent_key": entry.parent_key,
                    "seq": entry.seq,
                    "attempts": entry.attempts,
                    "may_already_be_applied": entry.maybe_applied,
                    "arguments_bytes": entry.arguments_bytes,
                    "hosted_journal_entry": entry.hosted_journal_entry,
                });
                let object = view.as_object_mut().expect("object");
                if let Some(cause) = &entry.refused_because {
                    object.insert("depends_on".into(), json!(cause));
                }
                // A record to point at once there is one: what a sent create
                // made, or the record an append, link or attachment is on.
                // A create that is still waiting has made nothing yet.
                let exists = state == "sent"
                    || !matches!(entry.operation.as_str(), "create_record" | "create_many");
                if exists && state != "refused" {
                    let ids: Vec<&String> = if entry.record_ids.is_empty() {
                        entry.record_id.iter().collect()
                    } else {
                        entry.record_ids.iter().collect()
                    };
                    if !ids.is_empty() {
                        object.insert("record_ids".into(), json!(ids));
                        if let Some(base) = record_base {
                            let links: Vec<String> =
                                ids.iter().map(|id| format!("{base}/{id}")).collect();
                            object.insert("record_links".into(), json!(links));
                        }
                    }
                }
                view
            })
            .collect();
        json!({
            "matched": matched,
            "shown": writes.len(),
            "order": if filter.newest_first { "newest_first" } else { "oldest_first" },
            "counts": counts,
            "writes": writes,
        })
    }

    /// Counts of held writes by state for one run, and for the runs it started.
    pub(super) fn held_counts_for_run(&self, run: &str) -> (Value, Value) {
        let entries = self.entries.lock().expect("journal entries");
        let mut own = serde_json::Map::new();
        let mut children = serde_json::Map::new();
        for entry in entries.values() {
            let Some(state) = Self::view_state(entry) else {
                continue;
            };
            let target = if entry.run_key.as_deref() == Some(run) {
                &mut own
            } else if entry.parent_key.as_deref() == Some(run) {
                &mut children
            } else {
                continue;
            };
            let count = target.entry(state).or_insert(json!(0));
            *count = json!(count.as_u64().unwrap_or(0) + 1);
        }
        (Value::Object(own), Value::Object(children))
    }

    /// When the oldest write that still needs attention was accepted: the same
    /// states a status reader counts as waiting (pending, hosted_pending,
    /// uncertain, not_sent, refused, unrecognised), not just the send queue.
    fn oldest_waiting(&self) -> Option<String> {
        let entries = self.entries.lock().expect("journal entries");
        entries
            .values()
            .filter(|e| {
                e.state == EntryState::Uncertain
                    || matches!(
                        Self::view_state(e),
                        Some(
                            "pending"
                                | "hosted_pending"
                                | "uncertain"
                                | "not_sent"
                                | "refused"
                                | "unrecognised"
                        )
                    )
            })
            .min_by_key(|e| (e.seq, e.received_unix_ms))
            .map(|e| e.received_at.clone())
    }

    /// The queue: how many writes wait and how much they hold.
    pub(super) fn queue_summary(&self) -> Value {
        let oldest_waiting = self.oldest_waiting();
        let entries = self.entries.lock().expect("journal entries");
        let pending: Vec<&Entry> = entries
            .values()
            .filter(|e| e.state == EntryState::Pending)
            .collect();
        json!({
            "pending": pending.len(),
            "bytes": pending.iter().map(|e| e.arguments_bytes).sum::<usize>(),
            "oldest_accepted_at": pending.iter().min_by_key(|e| e.seq).map(|e| e.received_at.clone()),
            "oldest_waiting_accepted_at": oldest_waiting,
        })
    }

    /// Entries a build that does not know their state left on disk. They are
    /// never sent or settled here.
    pub(super) fn unrecognised(&self) -> Vec<Value> {
        let entries = self.entries.lock().expect("journal entries");
        let mut found: Vec<&Entry> = entries
            .values()
            .filter(|e| e.state == EntryState::Unrecognised)
            .collect();
        found.sort_by_key(|e| e.seq);
        found
            .into_iter()
            .map(|e| {
                json!({
                    "id": e.id, "operation": e.operation, "title": e.title,
                    "accepted_at": e.received_at, "idempotency_key": e.idempotency_key,
                    "run_key": e.run_key, "record_id": e.record_id,
                })
            })
            .collect()
    }

    /// Bodies are deliberately left out: the entry file on disk holds them.
    #[cfg(test)]
    pub(super) fn status(&self) -> Value {
        self.status_for(&StatusFilter::default())
    }

    /// As `status`, with the `uncertain` list narrowed by the same `run`,
    /// `parent_run` and `state` filters as the held-writes view. The counts
    /// stay whole: they say what the journal holds, not what was asked about.
    pub(super) fn status_for(&self, filter: &StatusFilter) -> Value {
        let entries = self.entries.lock().expect("journal entries");
        let mut counts = serde_json::Map::new();
        let mut uncertain = Vec::new();
        for entry in entries.values() {
            let key = serde_json::to_value(entry.state)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            let count = counts.entry(key).or_insert(json!(0));
            *count = json!(count.as_u64().unwrap_or(0) + 1);
            let wanted = filter
                .run
                .as_ref()
                .is_none_or(|r| entry.run_key.as_ref() == Some(r))
                && filter
                    .parent_run
                    .as_ref()
                    .is_none_or(|p| entry.parent_key.as_ref() == Some(p))
                && (filter.states.is_empty() || filter.states.iter().any(|s| s == "uncertain"));
            if entry.state == EntryState::Uncertain && wanted {
                uncertain.push(json!({
                    "id": entry.id,
                    "parent_key": entry.parent_key,
                    "executor": entry.executor,
                    "operation": entry.operation,
                    "idempotency_key": entry.idempotency_key,
                    "key_origin": entry.key_origin,
                    "run_key": entry.run_key,
                    "received_at": entry.received_at,
                    "updated_at": entry.updated_at,
                    "attempts": entry.attempts,
                    "reason": entry.detail,
                    "arguments_bytes": entry.arguments_bytes,
                }));
            }
        }
        uncertain.sort_by(|a, b| a["received_at"].as_str().cmp(&b["received_at"].as_str()));
        let has_keyed = entries
            .values()
            .any(|e| e.state == EntryState::Uncertain && e.idempotency_key.is_some());
        let has_keyless = entries
            .values()
            .any(|e| e.state == EntryState::Uncertain && e.idempotency_key.is_none());
        let how_to_settle = match (has_keyed, has_keyless) {
            (false, false) => "No uncertain entries. The node does not replay uncertain writes; writes it holds (pending) are its own and are sent automatically.",
            (true, false) => "Retry the same call with the entry's idempotency_key, or read the record before writing again. The node does not replay uncertain writes; writes it holds (pending) are its own and are sent automatically.",
            (false, true) => "Keyless uncertain entries cannot be settled by retrying with a key: inspect the record and reconcile with hosted before writing again. The node does not replay uncertain writes; writes it holds (pending) are its own and are sent automatically.",
            (true, true) => "Keyed entries: retry the same call with the entry's idempotency_key, or read the record before writing again. Keyless entries: inspect the record and reconcile with hosted before writing again; do not retry blindly. The node does not replay uncertain writes; writes it holds (pending) are its own and are sent automatically.",
        };
        json!({
            "journal_directory": self.directory.display().to_string(),
            "entry_counts": counts,
            "unreadable_files": self.unreadable,
            "uncertain": uncertain,
            "how_to_settle": how_to_settle,
        })
    }
}

fn read_entry(path: &Path) -> Result<Entry> {
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = input.metadata()?;
    check_owned(&meta, 0o600)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.len() > MAX_ENTRY_BYTES {
        return Err(Error::engine("invalid node journal entry"));
    }
    let mut bytes = Vec::new();
    input.read_to_end(&mut bytes)?;
    let entry: Entry = serde_json::from_slice(&bytes)?;
    if entry.version > ENTRY_VERSION {
        return Err(Error::engine("journal entry from a newer node"));
    }
    Ok(entry)
}

#[cfg(test)]
mod tests;
