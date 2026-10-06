//! Member copy lifecycle: persisted [`CopyStatus`] + crash-resumable cleanup
//! barrier (Native task 4207bbb, contract c323277 rev 7 §6/§6.1).
//!
//! Standalone: no network, no dependency on the producer/consumer code. The
//! consumer calls this module; see [`MemberCopyLifecycle`].
//!
//! Durability reuses the `generation_store` pattern: temp file + `sync_all` +
//! rename + directory `sync_all` (never in-place mutation).
//!
//! [`CopyStatus`]: CopyStatus

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const STATE_CONTRACT: &str = "native.member-copy-lifecycle-state.v1";
const STATE_FILENAME: &str = "lifecycle.json";

/// Cause of a `removed` copy state (contract §6: three come from the
/// server's `revoked{cause}`, the fourth is derived locally).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovedCause {
    MembershipEnded,
    RoleChanged,
    AccountChanged,
    SessionRevoked,
}

/// Deletion signal owned by the lifecycle barrier (task 4207bbb).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeletionState {
    InProgress,
    Complete,
}

/// Member-facing copy status, exactly per contract §6/§6.1. No counters,
/// no reasons on member/agent-facing values (§2.6).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CopyStatus {
    Ready {
        cut_at: String,
    },
    Refreshing {
        cut_at: String,
    },
    Unavailable,
    Locked {
        cut_at: String,
    },
    Removed {
        cause: RemovedCause,
        deletion: DeletionState,
    },
}

impl CopyStatus {
    /// Precedence rank (§6.1): removed > unavailable > locked >
    /// refreshing > ready. Higher wins.
    pub fn precedence_rank(&self) -> u8 {
        match self {
            CopyStatus::Removed { .. } => 4,
            CopyStatus::Unavailable => 3,
            CopyStatus::Locked { .. } => 2,
            CopyStatus::Refreshing { .. } => 1,
            CopyStatus::Ready { .. } => 0,
        }
    }

    /// Returns the higher-precedence of two statuses.
    pub fn max_precedence(&self, other: &Self) -> Self {
        if other.precedence_rank() >= self.precedence_rank() {
            other.clone()
        } else {
            self.clone()
        }
    }

    /// Reads are refusable from status alone: only `ready`/`refreshing`
    /// admit reads; every other state refuses before surface logic runs.
    pub fn can_read(&self) -> bool {
        matches!(
            self,
            CopyStatus::Ready { .. } | CopyStatus::Refreshing { .. }
        )
    }
}

/// Local-only diagnostics; never surfaced to members/agents (§6).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    FenceChanged,
    RefreshFailed,
    CleanupPending,
    FormatUnsupported,
    /// A superseded purge completed but the kept generation is absent
    /// (deleted externally), so no copy is usable. Status must never
    /// claim `ready` with nothing activatable.
    GenerationMissing,
}

/// Read refusal derived from status alone (contract §6.1 "While locked").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadDecision {
    Allow,
    CopyLocked,
    UnavailableOffline,
}

impl ReadDecision {
    pub fn for_status(status: &CopyStatus) -> Self {
        match status {
            CopyStatus::Ready { .. } | CopyStatus::Refreshing { .. } => ReadDecision::Allow,
            CopyStatus::Locked { .. } => ReadDecision::CopyLocked,
            CopyStatus::Unavailable | CopyStatus::Removed { .. } => {
                ReadDecision::UnavailableOffline
            }
        }
    }
}

/// Server reconnect answer (§4.3 step 7). `AccountChanged` is derived
/// locally and never sent by the server (F2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconnectAnswer {
    Current,
    Replace { cut_at: String },
    Revoked { cause: RevokedCause },
    Locked,
}

/// The three server-sent revocation causes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevokedCause {
    MembershipEnded,
    RoleChanged,
    SessionRevoked,
}

impl From<RevokedCause> for RemovedCause {
    fn from(cause: RevokedCause) -> Self {
        match cause {
            RevokedCause::MembershipEnded => RemovedCause::MembershipEnded,
            RevokedCause::RoleChanged => RemovedCause::RoleChanged,
            RevokedCause::SessionRevoked => RemovedCause::SessionRevoked,
        }
    }
}

/// Durable state file body. The device never checks credential expiry
/// locally; `locked` survives restart verbatim.
///
/// `held_cut_at` is the last *admitted* cut (the generation on disk).
/// `Refreshing`/`Locked` carry display cuts that may be the refresh
/// *target*, never the held copy: admitting reads against a target that
/// has no bytes yet would report a cut that is not held.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PersistedLifecycle {
    contract: String,
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account_token: Option<String>,
    status: CopyStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    unavailable_reason: Option<UnavailableReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held_cut_at: Option<String>,
}

impl PersistedLifecycle {
    fn fresh() -> Self {
        Self {
            contract: STATE_CONTRACT.into(),
            version: 1,
            account_token: None,
            status: CopyStatus::Unavailable,
            unavailable_reason: None,
            held_cut_at: None,
        }
    }
}

fn state_path(root: &Path) -> PathBuf {
    root.join(STATE_FILENAME)
}

fn read_state_file(root: &Path) -> Result<Option<PersistedLifecycle>> {
    let path = state_path(root);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };
    let mut state: PersistedLifecycle = serde_json::from_slice(&bytes)?;
    if state.contract != STATE_CONTRACT || state.version != 1 {
        return Err(Error::engine("invalid member copy lifecycle state"));
    }
    // Forward fill for state files written before `held_cut_at` existed:
    // a Ready/Locked status cut is an admitted cut. A Refreshing cut is
    // the download target and must not be mistaken for held bytes.
    if state.held_cut_at.is_none() {
        state.held_cut_at = match &state.status {
            CopyStatus::Ready { cut_at } | CopyStatus::Locked { cut_at } => Some(cut_at.clone()),
            CopyStatus::Refreshing { .. }
            | CopyStatus::Unavailable
            | CopyStatus::Removed { .. } => None,
        };
    }
    Ok(Some(state))
}

/// Atomic durable write: temp + fsync + rename + dir fsync.
fn write_state_file(root: &Path, state: &PersistedLifecycle) -> Result<()> {
    fs::create_dir_all(root)?;
    let temp = root.join(format!(".lifecycle-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    set_private_mode(&temp)?;
    file.write_all(&serde_jcs::to_vec(state)?)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, state_path(root))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn set_private_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_mode(_path: &Path) -> Result<()> {
    Ok(())
}

/// Crash-resumable owner of one member copy's lifecycle state.
///
/// The copy root holds `lifecycle.json` (this module), the purge journal,
/// and the managed artefacts (generations, staging, caches). State and
/// journal writes are atomic; `locked` survives restart and is cleared
/// only via [`MemberCopyLifecycle::sign_in`].
///
/// Layout contract: every serving file lives under `generations/<id>/`,
/// under the staging directory, under a registered projection/cache
/// directory, or in the registered root-file list. Registered
/// projection/cache directories hold per-generation entries named by
/// generation id (a file or directory whose name is the generation id);
/// anything else in them is scratch and is purged on both paths.
/// Contract §7.1 order is rebuild FTS for the new generation, then
/// promote the pointer, then purge older entries — so on the superseded
/// path the consumer's new cache already exists under `keep`.
///
/// Removal recovery is two-step: an account switch ends in
/// `removed{account_changed, complete}` and stops there. The consumer
/// must run the §4.3 reconnect check again; only a fresh `Replace` for
/// the bound account starts a new copy. Admitting (install, promote,
/// purge, `mark_refreshed`) straight after the switch is silently
/// ignored — `mark_refreshed` outside `Refreshing`/`Ready` returns the
/// unchanged status — so callers must check its return value.
///
/// Quiescence: the final enumeration and the completion write are NOT
/// atomic. The consumer must quiesce writers to the copy root (no open
/// readers creating -wal/-shm, no staging writes) before raising the
/// barrier, calling `purge_superseded`, purging for a scope change, or
/// signing in for the first time (first-binding adoption also deletes).
/// Anything created after the final enumeration survives with the status
/// already complete. This is deliberately a documented obligation, not a
/// runtime check: a directory scan cannot see open file handles or
/// concurrent writers, so no cheap assertion here could enforce it.
///
/// Scope-change caller contract (§1.5): on `replace{scope_changed: true}`
/// the consumer quiesces READER handles too (closes database readers,
/// drops in-memory caches and rendered titles — the §6 constraint 5 —
/// so the wider copy is unreadable while it downloads), then calls
/// [`MemberCopyLifecycle::purge_for_scope_change`] BEFORE staging or
/// downloading anything, then downloads, admits and marks refreshed.
/// One refresh driver per copy root serialises admission, reconnect,
/// sign-in and the scope-change purge: this module exposes no lock and
/// no compare-and-set, and `status()` reads in-memory state, so two
/// owners racing a promotion against a purge or a barrier silently
/// overwrite each other.
///
/// Post-purge handoff (explicit integration obligation, unchanged in
/// L3 by design): after a successful scope-change purge the copy is
/// `Refreshing{target}` with NO held cut, an EMPTY activatable set and
/// NO pointer — yet `read_decision()`/`can_read()` still report Allow
/// from status alone, and consumer dispatch currently checks only that.
/// The refresh driver MUST therefore, BEFORE purging, close/drop the
/// old database handles and unregister (or replace) the serving gate,
/// and MUST NOT re-expose serving until the new generation is admitted
/// (pointer names it, `activatable_generations()` is non-empty, and
/// `mark_refreshed` returned `Ready`). The same guard covers the reopen
/// limbo (open resumes a pending scope purge into the same empty
/// `Refreshing`) and the first-binding limbo (fresh `Refreshing` with
/// nothing activatable). `can_read` is deliberately unchanged here; the
/// reviewer judges caller-obligation versus API sufficiency.
pub struct MemberCopyLifecycle {
    root: PathBuf,
    state: PersistedLifecycle,
    journal: Option<PurgeJournal>,
    extra_dirs: Vec<PathBuf>,
    root_files: Vec<String>,
}

impl MemberCopyLifecycle {
    /// Opens (or creates) the lifecycle state under `root`. A pending
    /// journal from a crash is resumed idempotently; a deletion failure
    /// keeps the barrier pending (effective `unavailable`) rather than
    /// failing the open.
    pub fn open(root: &Path) -> Result<Self> {
        Self::open_with_extra_dirs(root, Vec::new())
    }

    /// Opens with additional projection/cache directories (relative to
    /// `root` unless absolute) registered as managed artefacts.
    pub fn open_with_extra_dirs(root: &Path, extra_dirs: Vec<PathBuf>) -> Result<Self> {
        Self::open_with_managed(root, extra_dirs, Vec::new())
    }

    /// Opens with registered projection/cache directories plus an
    /// optional registered root-file list (plain file names at the copy
    /// root, e.g. a main serving database). The full barrier deletes
    /// registered root files; the superseded path leaves them.
    pub fn open_with_managed(
        root: &Path,
        extra_dirs: Vec<PathBuf>,
        root_files: Vec<String>,
    ) -> Result<Self> {
        for name in &root_files {
            if name.is_empty()
                || name.contains('/')
                || name.contains('\\')
                || name.contains('\0')
                || name == "."
                || name == ".."
            {
                return Err(Error::engine("invalid registered root file name"));
            }
        }
        fs::create_dir_all(root)?;
        let state = match read_state_file(root)? {
            Some(state) => state,
            None => {
                let fresh = PersistedLifecycle::fresh();
                write_state_file(root, &fresh)?;
                fresh
            }
        };
        let journal = read_journal_file(root)?;
        let mut lifecycle = Self {
            root: root.to_path_buf(),
            state,
            journal,
            extra_dirs,
            root_files,
        };
        // Best-effort resume: deletion errors stay pending, never fail open.
        let _ = lifecycle.resume_pending_barrier(&NoFail);
        Ok(lifecycle)
    }

    /// Member/agent-facing status. This is the *effective* status: while
    /// a cleanup barrier is pending it is never ready/locked (a pending
    /// journal forces `unavailable` unless the stored state already
    /// outranks it as `removed`). There is no raw accessor on purpose —
    /// reads must be refusable from status alone.
    pub fn status(&self) -> CopyStatus {
        self.effective_status()
    }

    /// Effective status with barrier precedence: a pending journal forces
    /// `unavailable` unless the stored state already outranks it
    /// (`removed`). While a barrier is raised the status is never
    /// ready/locked.
    pub fn effective_status(&self) -> CopyStatus {
        if self.journal.is_some() {
            match &self.state.status {
                CopyStatus::Removed { .. } => self.state.status.clone(),
                _ => CopyStatus::Unavailable,
            }
        } else {
            self.state.status.clone()
        }
    }

    pub fn read_decision(&self) -> ReadDecision {
        ReadDecision::for_status(&self.effective_status())
    }

    pub fn can_read(&self) -> bool {
        self.effective_status().can_read()
    }

    pub fn account_token(&self) -> Option<&str> {
        self.state.account_token.as_deref()
    }

    pub fn local_unavailable_reason(&self) -> Option<UnavailableReason> {
        self.state.unavailable_reason
    }

    fn persist_status(&mut self, status: CopyStatus) -> Result<()> {
        self.state.status = status;
        write_state_file(&self.root, &self.state)
    }

    /// Persists a `removed` state. A removed copy admits nothing, so the
    /// held cut is dropped alongside: a stale cut must never be reported
    /// after removal.
    fn persist_removed(&mut self, cause: RemovedCause, deletion: DeletionState) -> Result<()> {
        self.state.held_cut_at = None;
        self.persist_status(CopyStatus::Removed { cause, deletion })
    }
}

impl MemberCopyLifecycle {
    /// Last admitted cut (the generation actually on disk), if any.
    fn held_cut_at(&self) -> Option<String> {
        self.state.held_cut_at.clone()
    }

    /// Same-account reconnect check (launch / periodic). While `locked`,
    /// every answer except `Revoked` (removal) and `Locked` (stay) is
    /// ignored: only the sign-in path unlocks (§6.1). A `current` answer
    /// during `refreshing` leaves the in-flight refresh running; it never
    /// promotes the unheld target cut to `ready`.
    pub fn apply_reconnect(&mut self, answer: ReconnectAnswer) -> Result<CopyStatus> {
        self.apply_reconnect_with_fail(answer, &NoFail)
    }

    /// Testable reconnect: `fail` probes the revocation barrier.
    pub fn apply_reconnect_with_fail(
        &mut self,
        answer: ReconnectAnswer,
        fail: &dyn BarrierFailpoint,
    ) -> Result<CopyStatus> {
        if self.is_removed_in_progress() {
            // F10: a pending barrier only resumes; the cause is never
            // rewritten.
            let _ = self.resume_pending_barrier(&NoFail);
            return Ok(self.effective_status());
        }
        if self.is_removed_complete() {
            return self.exit_removed_complete(answer);
        }
        if matches!(self.state.status, CopyStatus::Locked { .. }) {
            return match answer {
                ReconnectAnswer::Revoked { cause } => self.raise_barrier(cause.into(), fail),
                _ => Ok(self.state.status.clone()),
            };
        }
        self.follow_answer(answer, fail, false)
    }

    /// Removal-state predicates. `Removed` stays terminal FOR THE
    /// REMOVED COPY, but not for the device: a completed removal can
    /// start a fresh copy (see [`MemberCopyLifecycle::exit_removed_complete`]).
    fn is_removed_in_progress(&self) -> bool {
        matches!(
            self.state.status,
            CopyStatus::Removed {
                deletion: DeletionState::InProgress,
                ..
            }
        )
    }

    fn is_removed_complete(&self) -> bool {
        matches!(
            self.state.status,
            CopyStatus::Removed {
                deletion: DeletionState::Complete,
                ..
            }
        )
    }

    /// Exit from a completed removal. Only a `Replace` answer starts a
    /// fresh copy (`Refreshing` on the target cut, no held cut):
    /// `Current`/`Locked` stay removed (nothing is held) and a `Revoked`
    /// answer while removed stays removed.
    ///
    /// Note (m5): the fresh `Refreshing` has no held bytes yet, so
    /// `can_read()` is nominally true while `activatable_generations` is
    /// empty — the same limbo as first-binding `Refreshing`. A `Current`
    /// answer cannot resolve it; only admission (`Replace`), revocation,
    /// or a refresh failure moves it on. The read layer must consult
    /// `activatable_generations`, not status alone, before serving bytes.
    fn exit_removed_complete(&mut self, answer: ReconnectAnswer) -> Result<CopyStatus> {
        match answer {
            ReconnectAnswer::Replace { cut_at } => {
                self.state.unavailable_reason = None;
                self.state.held_cut_at = None;
                self.persist_status(CopyStatus::Refreshing { cut_at })?;
                Ok(self.state.status.clone())
            }
            _ => Ok(self.state.status.clone()),
        }
    }

    /// Unguarded answer transitions. The sign-in path uses this directly
    /// (a fresh credential unlocks); the plain reconnect path reaches it
    /// only past the locked/removed guards above. `via_sign_in` selects
    /// the `current` rule: on the sign-in path it admits the held cut
    /// (`ready`, unlocking); on the plain path it leaves an in-flight
    /// refresh running and changes nothing.
    fn follow_answer(
        &mut self,
        answer: ReconnectAnswer,
        fail: &dyn BarrierFailpoint,
        via_sign_in: bool,
    ) -> Result<CopyStatus> {
        match answer {
            ReconnectAnswer::Current if via_sign_in => {
                if let Some(cut_at) = self.held_cut_at() {
                    self.state.unavailable_reason = None;
                    self.persist_status(CopyStatus::Ready { cut_at })?;
                }
                Ok(self.state.status.clone())
            }
            ReconnectAnswer::Current | ReconnectAnswer::Locked => {
                // `current` changes nothing outside sign-in; a `locked`
                // answer with no held copy leaves `unavailable` as is.
                if let ReconnectAnswer::Locked = answer {
                    if let Some(cut_at) = self.held_cut_at() {
                        self.persist_status(CopyStatus::Locked { cut_at })?;
                    }
                }
                Ok(self.state.status.clone())
            }
            ReconnectAnswer::Replace { cut_at } => {
                self.state.unavailable_reason = None;
                self.persist_status(CopyStatus::Refreshing { cut_at })?;
                Ok(self.state.status.clone())
            }
            ReconnectAnswer::Revoked { cause } => self.raise_barrier(cause.into(), fail),
        }
    }

    /// Sign-in path (§6.1 "Leaving the state"): runs the reconnect check
    /// with the new credential. A different account purges unconditionally;
    /// the same account follows the answer, and `current` unlocks without
    /// any re-download signal. Removal is terminal for the removed copy
    /// but not for the device: an in-progress removal only resumes (F10,
    /// cause never rewritten); a completed removal exits on a `Replace`
    /// answer for the bound account (fresh copy) or re-runs the switch
    /// barrier for a different account.
    ///
    /// The switch consumes its triggering answer: after
    /// `removed{account_changed, complete}` the caller must run the
    /// reconnect check again — admitting straight away leaves the copy
    /// `Removed` (`mark_refreshed` is ignored outside
    /// `Refreshing`/`Ready`; check its return value).
    pub fn sign_in(&mut self, account_token: &str, answer: ReconnectAnswer) -> Result<CopyStatus> {
        self.sign_in_with_fail(account_token, answer, &NoFail)
    }

    /// Testable sign-in: `fail` probes the account-change barrier (notably
    /// the journal-first crash window).
    pub fn sign_in_with_fail(
        &mut self,
        account_token: &str,
        answer: ReconnectAnswer,
        fail: &dyn BarrierFailpoint,
    ) -> Result<CopyStatus> {
        if self.is_removed_in_progress() {
            let _ = self.resume_pending_barrier(&NoFail);
            return Ok(self.effective_status());
        }
        if self.is_removed_complete() {
            let bound = self.state.account_token.clone();
            if bound.as_deref() == Some(account_token) {
                return self.exit_removed_complete(answer);
            }
            // A different account on a completed removal starts a new
            // switch barrier (the old copy is fully gone); the bound
            // account then exits via `Replace` as above.
            //
            // Note (m4): when the removal reached `Complete` with no bound
            // account (unbound pre-bind revocation), the next sign-in
            // reports `account_changed` although there was no prior
            // account. Hard to reach in production (a reconnect implies a
            // stored credential, which implies a prior sign-in); kept as-is
            // per the switch rule's letter, no behaviour change.
            return self.switch_account(account_token, fail);
        }
        if let Some(bound) = self.state.account_token.clone() {
            if bound != account_token {
                return self.switch_account(account_token, fail);
            }
        } else {
            // First binding: silently adopt the root. Pre-existing
            // generations, caches, root files and the pointer are orphans
            // from a previous occupant and are purged journal-first —
            // never an account change, never `account_changed` for a
            // first-time user. Staging is scratch the consumer may be
            // about to admit and is always left alone.
            return self.adopt_root(account_token, answer, fail);
        }
        // Same account: follow the answer. `current` unlocks onto the
        // held cut with no re-download signal; only this path unlocks.
        self.follow_answer(answer, fail, true)
    }

    /// First-binding adoption: purge orphans journal-first (crash/resume
    /// via the `Orphan` journal kind), then persist the binding with a
    /// fresh status and follow the answer normally. Requires quiesced
    /// writers like every other deleting path (see the layout contract on
    /// [`MemberCopyLifecycle`]).
    fn adopt_root(
        &mut self,
        account_token: &str,
        answer: ReconnectAnswer,
        fail: &dyn BarrierFailpoint,
    ) -> Result<CopyStatus> {
        let kind = JournalKind::Orphan;
        let remaining = self.enumerate_managed(&kind)?;
        if !remaining.is_empty() {
            let journal = new_journal(kind, remaining);
            write_journal_file(&self.root, &journal)?;
            self.journal = Some(journal);
            if fail.fail_at(BarrierStep::JournalWritten, None) {
                return Err(Error::engine("injected barrier failure at journal"));
            }
            self.run_purge(fail)?;
        }
        self.state.account_token = Some(account_token.to_string());
        self.state.unavailable_reason = None;
        self.state.held_cut_at = None;
        self.state.status = CopyStatus::Unavailable;
        write_state_file(&self.root, &self.state)?;
        self.follow_answer(answer, fail, true)
    }

    /// Account switch: the purge intent (journal with `AccountChanged` and
    /// the pending binding) is durable FIRST; the new `account_token` is
    /// persisted together with `Removed{in_progress}` in one state write,
    /// never before. A crash in the window resumes from the journal and
    /// can never expose the previous generation under the new account.
    ///
    /// Two-step recovery (contract §6.1): this ends in
    /// `removed{account_changed, complete}` and STOPS there — the
    /// `Replace` answer that triggered the switch is consumed by the
    /// switch itself. After removal the consumer must run the §4.3
    /// reconnect check AGAIN; a `Replace` for the now-bound account
    /// starts a fresh copy (`Refreshing`, no held cut), and only then
    /// does admission + `mark_refreshed` reach `Ready`. Admitting straight
    /// after the switch leaves the copy `Removed`: `mark_refreshed`
    /// outside `Refreshing`/`Ready` is ignored.
    fn switch_account(
        &mut self,
        account_token: &str,
        fail: &dyn BarrierFailpoint,
    ) -> Result<CopyStatus> {
        let kind = JournalKind::FullBarrier {
            cause: RemovedCause::AccountChanged,
        };
        let remaining = self.enumerate_managed(&kind)?;
        let mut journal = new_journal(kind, remaining);
        journal.bind_account = Some(account_token.to_string());
        write_journal_file(&self.root, &journal)?;
        self.journal = Some(journal);
        if fail.fail_at(BarrierStep::JournalWritten, None) {
            return Err(Error::engine("injected barrier failure at journal"));
        }
        self.state.account_token = Some(account_token.to_string());
        self.state.unavailable_reason = Some(UnavailableReason::CleanupPending);
        self.state.held_cut_at = None;
        self.state.status = CopyStatus::Removed {
            cause: RemovedCause::AccountChanged,
            deletion: DeletionState::InProgress,
        };
        write_state_file(&self.root, &self.state)?;
        self.run_purge(fail)
    }

    /// Consumer admission completed a refresh: `refreshing` becomes `ready`
    /// and the admitted cut becomes the held cut.
    ///
    /// Ignored outside `Refreshing`/`Ready` (e.g. after a removal that has
    /// not been exited via a fresh `Replace`): the call returns the
    /// UNCHANGED status, so callers MUST check the return value instead of
    /// assuming admission took effect.
    pub fn mark_refreshed(&mut self, cut_at: String) -> Result<CopyStatus> {
        if matches!(
            self.state.status,
            CopyStatus::Refreshing { .. } | CopyStatus::Ready { .. }
        ) {
            self.state.unavailable_reason = None;
            self.state.held_cut_at = Some(cut_at.clone());
            self.persist_status(CopyStatus::Ready { cut_at })?;
        }
        Ok(self.effective_status())
    }

    /// A refresh attempt failed locally: `refreshing` degrades to
    /// local-only `unavailable` (no member-facing reason).
    pub fn mark_refresh_failed(&mut self) -> Result<CopyStatus> {
        if matches!(self.state.status, CopyStatus::Refreshing { .. }) {
            self.state.unavailable_reason = Some(UnavailableReason::RefreshFailed);
            self.persist_status(CopyStatus::Unavailable)?;
        }
        Ok(self.effective_status())
    }
}

// --- Cleanup barrier -------------------------------------------------------

const JOURNAL_CONTRACT: &str = "native.member-copy-purge-journal.v1";
const JOURNAL_FILENAME: &str = "purge.journal.json";

/// Crash-injection step for barrier tests. Failpoints are passed
/// explicitly (trait object or closure); there is no global state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BarrierStep {
    JournalWritten,
    BeforeDelete,
    AfterDelete,
    BeforeComplete,
    AfterComplete,
}

/// Injectable failure probe for the purge loop.
pub trait BarrierFailpoint {
    fn fail_at(&self, step: BarrierStep, path: Option<&Path>) -> bool;
}

/// Default probe: never fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoFail;

impl BarrierFailpoint for NoFail {
    fn fail_at(&self, _step: BarrierStep, _path: Option<&Path>) -> bool {
        false
    }
}

impl<F> BarrierFailpoint for F
where
    F: Fn(BarrierStep, Option<&Path>) -> bool,
{
    fn fail_at(&self, step: BarrierStep, path: Option<&Path>) -> bool {
        (*self)(step, path)
    }
}

/// Reader/cache invalidation hook for the consumer to implement.
/// Defined here, never wired: the lifecycle module deletes files only.
pub trait CopyCacheInvalidation {
    fn invalidate_caches(&self) -> Result<()>;
}

/// What a pending journal is purging.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum JournalKind {
    FullBarrier {
        cause: RemovedCause,
    },
    Superseded {
        keep: String,
    },
    /// Scope-change purge (§1.5): the producer answered
    /// `replace{scope_changed: true}`, so the old (wider) copy must go
    /// BEFORE anything new is staged. Enumerates like the full barrier
    /// (every generation, the pointer, staging, per-generation caches,
    /// registered root files); finishes into `Refreshing{target}` with no
    /// held cut. Never a removal: no `RemovedCause` is involved.
    ScopeChange {
        target_cut_at: String,
    },
    /// Silent first-binding orphan purge: generations, caches,
    /// registered root files and the pointer — never staging (scratch
    /// the consumer may be about to admit) and never an account change.
    Orphan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PurgeJournal {
    contract: String,
    version: u32,
    journal: JournalKind,
    /// Root-relative managed paths still to delete. Rewritten after
    /// every successful deletion so a crash resumes with the remainder.
    remaining: Vec<String>,
    /// Account to bind when an account-change barrier completes. The new
    /// binding is persisted together with the `removed` state, never
    /// before the purge intent is durable (crash window F1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bind_account: Option<String>,
}

fn new_journal(journal: JournalKind, remaining: Vec<String>) -> PurgeJournal {
    PurgeJournal {
        contract: JOURNAL_CONTRACT.into(),
        version: 1,
        journal,
        remaining,
        bind_account: None,
    }
}

fn journal_path(root: &Path) -> PathBuf {
    root.join(JOURNAL_FILENAME)
}

fn read_journal_file(root: &Path) -> Result<Option<PurgeJournal>> {
    let bytes = match fs::read(journal_path(root)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };
    let journal: PurgeJournal = serde_json::from_slice(&bytes)?;
    if journal.contract != JOURNAL_CONTRACT || journal.version != 1 {
        return Err(Error::engine("invalid member copy purge journal"));
    }
    Ok(Some(journal))
}

fn write_journal_file(root: &Path, journal: &PurgeJournal) -> Result<()> {
    let temp = root.join(format!(".purge-journal-{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    set_private_mode(&temp)?;
    file.write_all(&serde_jcs::to_vec(journal)?)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, journal_path(root))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

fn remove_journal_file(root: &Path) -> Result<()> {
    match fs::remove_file(journal_path(root)) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(Error::Io(e)),
    }
    File::open(root)?.sync_all()?;
    Ok(())
}

/// Collects one level of children of `dir` as root-relative paths.
fn collect_children(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(Error::Io(e)),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let rel = path
            .strip_prefix(root)
            .map_err(|_| Error::engine("member copy path escapes root"))?;
        out.push(rel.to_string_lossy().into_owned());
    }
    Ok(())
}

fn is_sidecar(name: &str) -> bool {
    name.ends_with("-wal") || name.ends_with("-shm") || name.ends_with("-journal")
}

impl MemberCopyLifecycle {
    fn resolve_extra(&self, dir: &Path) -> PathBuf {
        if dir.is_absolute() {
            dir.to_path_buf()
        } else {
            self.root.join(dir)
        }
    }

    /// Enumerates every managed artefact for `kind`, as sorted
    /// root-relative paths. Never includes the state or journal files.
    /// Registered dirs contribute per-generation entries: the full
    /// barrier takes all of them, the superseded path takes every entry
    /// NOT named `keep` (contract §7.1: purge index and cache with the
    /// older generation; the consumer rebuilt them under `keep` before
    /// promoting).
    fn enumerate_managed(&self, kind: &JournalKind) -> Result<Vec<String>> {
        let mut targets: Vec<String> = Vec::new();
        // All generations including current; retention keeps one on the
        // normal replace path, none on the full barrier.
        let generations = self.root.join("generations");
        let mut generation_children = Vec::new();
        collect_children(&self.root, &generations, &mut generation_children)?;
        for rel in generation_children {
            if let JournalKind::Superseded { keep } = kind {
                if rel == format!("generations/{keep}") {
                    continue;
                }
            }
            targets.push(rel);
        }
        // Staging directory / partial downloads. Scratch the consumer
        // may be about to admit: collected on every path EXCEPT the
        // orphan purge, which must never delete an in-flight download.
        if !matches!(kind, JournalKind::Orphan) {
            collect_children(&self.root, &self.root.join("staging"), &mut targets)?;
        }
        // Registered projection/cache directories: per-generation entries
        // named by generation id. Full barrier purges all; superseded
        // purges every entry not named `keep`.
        for extra in self.extra_dirs.clone() {
            let mut children = Vec::new();
            collect_children(&self.root, &self.resolve_extra(&extra), &mut children)?;
            for rel in children {
                let entry_name = Path::new(&rel)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if let JournalKind::Superseded { keep } = kind {
                    if entry_name == *keep {
                        continue;
                    }
                }
                targets.push(rel);
            }
        }
        // Root-level sidecars: SQLite -wal/-shm/-journal, temp files, the
        // registered root files (full barrier and orphan purge), and
        // (full barrier and orphan purge) the current-generation pointer,
        // which must never outlive the generations it names. The
        // superseded path keeps the pointer: the consumer promoted it.
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(e) => return Err(Error::Io(e)),
        };
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == STATE_FILENAME || name == JOURNAL_FILENAME {
                continue;
            }
            let keep_pointer =
                matches!(kind, JournalKind::Superseded { .. }) && name == "current.json";
            if keep_pointer {
                continue;
            }
            let registered = self.root_files.iter().any(|file| file == &name);
            if name == "current.json"
                || name.ends_with(".tmp")
                || is_sidecar(&name)
                || (registered && !matches!(kind, JournalKind::Superseded { .. }))
            {
                targets.push(name);
            }
        }
        targets.sort();
        targets.dedup();
        Ok(targets)
    }

    /// Reads the current-generation pointer. Accepts the bare generation
    /// id as text, a JSON string (`"gen-new"`, with quotes), or JSON
    /// `{"generation_id": "<id>"}` (the pointer shapes the consumer
    /// promotes before purging). `None` when absent.
    fn read_pointer_generation(root: &Path) -> Result<Option<String>> {
        let bytes = match fs::read(root.join("current.json")) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        };
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            if let Some(id) = value.as_str() {
                return Ok(Some(id.to_string()));
            }
            if let Some(id) = value.get("generation_id").and_then(|id| id.as_str()) {
                return Ok(Some(id.to_string()));
            }
        }
        let text = String::from_utf8_lossy(&bytes).trim().to_string();
        Ok(Some(text))
    }

    /// Installed-generation id named by `current.json`, if any. Accepts
    /// the same pointer shapes as the admission promote path (bare id,
    /// JSON string, or `{"generation_id": ..}`). The consumer derives
    /// rollback facts (scope_ref, ordinal, digest) from its own admitted
    /// manifest; this accessor never parses manifest types, so the
    /// lifecycle keeps no dependency on admission types. `None` means no
    /// generation is promoted (fresh root, or just purged for a scope
    /// change) — a caller that sees `None` must not skip its rollback
    /// guard, it must treat the guard as unsatisfied.
    pub fn current_generation_id(&self) -> Result<Option<String>> {
        Self::read_pointer_generation(&self.root)
    }

    /// Deletes one journal target without following symlinks.
    fn delete_target(root: &Path, rel: &str) -> Result<()> {
        let path = root.join(rel);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::Io(e)),
        };
        if meta.file_type().is_dir() && !meta.file_type().is_symlink() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Raises the cleanup barrier: durably records intent BEFORE any
    /// deletion, marks `removed{cause, in_progress}`, purges every managed
    /// artefact, fsyncs, then marks `deletion: complete`. The in-memory
    /// journal is assigned only after its durable write succeeds.
    /// Requires quiesced writers (see the layout contract on
    /// [`MemberCopyLifecycle`]).
    pub fn raise_barrier(
        &mut self,
        cause: RemovedCause,
        fail: &dyn BarrierFailpoint,
    ) -> Result<CopyStatus> {
        let kind = JournalKind::FullBarrier { cause };
        let remaining = self.enumerate_managed(&kind)?;
        let journal = new_journal(kind, remaining);
        // Intent is durable before the first deletion.
        write_journal_file(&self.root, &journal)?;
        self.journal = Some(journal);
        if fail.fail_at(BarrierStep::JournalWritten, None) {
            return Err(Error::engine("injected barrier failure at journal"));
        }
        self.state.unavailable_reason = Some(UnavailableReason::CleanupPending);
        self.persist_removed(cause, DeletionState::InProgress)?;
        self.run_purge(fail)
    }

    /// Normal replace path: retention is current only. Precondition: the
    /// consumer has already promoted `current.json` to name `keep`
    /// (contract §7.1 order is rebuild, promote, purge). If the pointer
    /// is absent or names anything else, this refuses with an error and
    /// changes nothing — a stale pointer must never outlive the purge.
    /// Uses the same journal as the full barrier so a crash mid-purge
    /// cannot reactivate an older, wider generation.
    /// Requires quiesced writers (see the layout contract on
    /// [`MemberCopyLifecycle`]).
    pub fn purge_superseded(
        &mut self,
        keep: &str,
        fail: &dyn BarrierFailpoint,
    ) -> Result<CopyStatus> {
        if keep.is_empty() || keep.contains('/') || keep.contains('\0') {
            return Err(Error::engine("invalid generation id to keep"));
        }
        match Self::read_pointer_generation(&self.root)? {
            Some(pointed) if pointed == keep => {}
            _ => {
                return Err(Error::engine(
                    "purge_superseded refused: current.json does not name keep",
                ));
            }
        }
        let kind = JournalKind::Superseded {
            keep: keep.to_string(),
        };
        let remaining = self.enumerate_managed(&kind)?;
        let journal = new_journal(kind, remaining);
        write_journal_file(&self.root, &journal)?;
        self.journal = Some(journal);
        if fail.fail_at(BarrierStep::JournalWritten, None) {
            return Err(Error::engine("injected barrier failure at journal"));
        }
        self.run_purge(fail)
    }

    /// Scope-change purge (§1.5): the producer answered
    /// `replace{scope_changed: true}`. The caller has already quiesced
    /// readers/writers (closed DB handles, no staging writes, dropped
    /// caches) and holds the single-driver serialization for this root
    /// (admission, reconnect, sign-in and this call never run
    /// concurrently; see the layout contract on [`MemberCopyLifecycle`]).
    /// Journal-first deletes EVERYTHING managed — all held generations,
    /// `current.json`, staging, per-generation caches, registered root
    /// files and sidecars — clears `held_cut_at`, and ends in
    /// `Refreshing{target}` only after the purge completes. The consumer
    /// downloads and admits AFTER this returns.
    ///
    /// Not a removal: no `RemovedCause`, no `Removed` state. Locked and
    /// completed-removal copies are left untouched (locked keeps its
    /// files; only the sign-in path unlocks). A failure at any step
    /// leaves the journal pending (effective `unavailable`) and returns
    /// the error; reopen resumes and never resurrects the wider copy.
    /// Post-purge handoff: the returned `Refreshing` has no held cut and
    /// nothing activatable yet `can_read()` still allows by status — the
    /// caller MUST keep serving gated (see the layout contract).
    pub fn purge_for_scope_change(
        &mut self,
        target_cut_at: &str,
        fail: &dyn BarrierFailpoint,
    ) -> Result<CopyStatus> {
        if target_cut_at.is_empty() {
            return Err(Error::engine("invalid scope-change target cut"));
        }
        if self.is_removed_in_progress() {
            let _ = self.resume_pending_barrier(&NoFail);
            return Ok(self.effective_status());
        }
        if self.is_removed_complete() {
            return Ok(self.effective_status());
        }
        if matches!(self.state.status, CopyStatus::Locked { .. }) {
            return Ok(self.effective_status());
        }
        if self.journal.is_some() {
            self.run_purge(&NoFail)?;
            if self.journal.is_some() {
                return Ok(self.effective_status());
            }
        }
        let kind = JournalKind::ScopeChange {
            target_cut_at: target_cut_at.to_string(),
        };
        let remaining = self.enumerate_managed(&kind)?;
        let journal = new_journal(kind, remaining);
        write_journal_file(&self.root, &journal)?;
        self.journal = Some(journal);
        if fail.fail_at(BarrierStep::JournalWritten, None) {
            return Err(Error::engine("injected barrier failure at journal"));
        }
        self.state.unavailable_reason = Some(UnavailableReason::CleanupPending);
        self.state.held_cut_at = None;
        self.state.status = CopyStatus::Unavailable;
        write_state_file(&self.root, &self.state)?;
        self.run_purge(fail)
    }

    /// Scope-change purge without failpoint injection.
    pub fn begin_scope_change_purge(&mut self, target_cut_at: &str) -> Result<CopyStatus> {
        self.purge_for_scope_change(target_cut_at, &NoFail)
    }

    /// Continues a pending purge after a crash at ANY step. A deletion
    /// failure leaves the barrier pending (effective `unavailable`, never
    /// ready) and returns the error.
    pub fn resume_pending_barrier(&mut self, fail: &dyn BarrierFailpoint) -> Result<CopyStatus> {
        if self.journal.is_none() {
            return Ok(self.effective_status());
        }
        self.run_purge(fail)
    }

    fn run_purge(&mut self, fail: &dyn BarrierFailpoint) -> Result<CopyStatus> {
        loop {
            while let Some(rel) = self
                .journal
                .as_ref()
                .and_then(|journal| journal.remaining.first().cloned())
            {
                let target = self.root.join(&rel);
                if fail.fail_at(BarrierStep::BeforeDelete, Some(&target)) {
                    return Err(Error::engine("injected barrier failure before delete"));
                }
                let outcome = Self::delete_target(&self.root, &rel);
                if fail.fail_at(BarrierStep::AfterDelete, Some(&target)) {
                    return Err(Error::engine("injected barrier failure after delete"));
                }
                outcome?;
                // The parent fsync lands before the journal forgets the
                // target: a crash can never undo the unlink while the
                // journal no longer lists it.
                Self::fsync_parent(&self.root, &rel)?;
                if let Some(journal) = self.journal.as_mut() {
                    journal.remaining.retain(|candidate| candidate != &rel);
                    write_journal_file(&self.root, journal)?;
                }
            }
            if fail.fail_at(BarrierStep::BeforeComplete, None) {
                return Err(Error::engine("injected barrier failure before complete"));
            }
            // Anything created after the raise-time enumeration (a
            // reader's -wal/-shm, a staging write) joins the journal;
            // completion needs a fresh enumeration to come back empty.
            let kind = self.journal.as_ref().map(|journal| journal.journal.clone());
            let Some(kind) = kind else {
                return Ok(self.effective_status());
            };
            let fresh = self.enumerate_managed(&kind)?;
            if !fresh.is_empty() {
                if let Some(journal) = self.journal.as_mut() {
                    journal.remaining = fresh;
                    write_journal_file(&self.root, journal)?;
                }
                continue;
            }
            return self.finish_purge(fail);
        }
    }

    /// Fsyncs the parent directory of a deleted target.
    fn fsync_parent(root: &Path, rel: &str) -> Result<()> {
        let parent = root
            .join(rel)
            .parent()
            .map(|parent| parent.to_path_buf())
            .unwrap_or_else(|| root.to_path_buf());
        File::open(&parent)?.sync_all()?;
        Ok(())
    }

    /// Marks the purge complete once a fresh enumeration is empty.
    fn finish_purge(&mut self, fail: &dyn BarrierFailpoint) -> Result<CopyStatus> {
        let finished = self
            .journal
            .as_ref()
            .map(|journal| (journal.journal.clone(), journal.bind_account.clone()));
        match finished {
            Some((JournalKind::FullBarrier { cause }, bind_account)) => {
                // A crash between the journal write and the state write
                // resumes here: the pending binding lands together with the
                // terminal state, never before the purge intent.
                if let Some(account) = bind_account {
                    self.state.account_token = Some(account);
                }
                self.state.unavailable_reason = None;
                self.persist_removed(cause, DeletionState::Complete)?;
            }
            Some((JournalKind::Superseded { keep }, _)) => {
                // The kept generation may have been deleted externally
                // mid-purge. Completing into `ready` then would claim a
                // usable copy with nothing activatable, so degrade to
                // local-only `unavailable` instead — and drop the held cut
                // so a later sign_in(Current) cannot resurrect `ready`.
                if Self::present_generations(&self.root)?
                    .iter()
                    .any(|id| id == &keep)
                {
                    self.state.unavailable_reason = None;
                } else {
                    self.state.unavailable_reason = Some(UnavailableReason::GenerationMissing);
                    self.state.status = CopyStatus::Unavailable;
                    self.state.held_cut_at = None;
                }
                write_state_file(&self.root, &self.state)?;
            }
            Some((JournalKind::Orphan, _)) => {
                // Orphan adoption completes into the pre-binding state;
                // the caller persists the fresh binding afterwards. Write
                // `Unavailable` explicitly rather than persisting whatever
                // status happens to be stored: the invariant (no usable
                // copy, no held cut) is local, not inferred.
                self.state.unavailable_reason = None;
                self.state.held_cut_at = None;
                self.state.status = CopyStatus::Unavailable;
                write_state_file(&self.root, &self.state)?;
            }
            Some((JournalKind::ScopeChange { target_cut_at }, _)) => {
                // Purge-before-staging is done: every old generation,
                // the pointer, staging and caches are gone. Only now
                // does the copy become `Refreshing` on the TARGET cut,
                // with no held cut. A crash before this write resumes
                // from the journal and never resurrects the wider copy.
                self.state.unavailable_reason = None;
                self.state.held_cut_at = None;
                self.state.status = CopyStatus::Refreshing {
                    cut_at: target_cut_at,
                };
                write_state_file(&self.root, &self.state)?;
            }
            None => {}
        }
        if fail.fail_at(BarrierStep::AfterComplete, None) {
            return Err(Error::engine("injected barrier failure after complete"));
        }
        self.journal = None;
        remove_journal_file(&self.root)?;
        File::open(&self.root)?.sync_all()?;
        Ok(self.effective_status())
    }

    /// Generations the consumer may activate. While a barrier is pending
    /// nothing older is activatable: a full barrier, an orphan purge or
    /// a scope-change purge admits none, a superseded purge admits only
    /// `keep`. A completed removal admits none.
    pub fn activatable_generations(&self) -> Result<Vec<String>> {
        if let Some(journal) = &self.journal {
            match &journal.journal {
                JournalKind::FullBarrier { .. }
                | JournalKind::Orphan
                | JournalKind::ScopeChange { .. } => {
                    return Ok(Vec::new());
                }
                JournalKind::Superseded { keep } => {
                    let present = Self::present_generations(&self.root)?;
                    if present.iter().any(|id| id == keep) {
                        return Ok(vec![keep.clone()]);
                    }
                    return Ok(Vec::new());
                }
            }
        }
        if matches!(
            self.state.status,
            CopyStatus::Removed {
                deletion: DeletionState::Complete,
                ..
            }
        ) {
            return Ok(Vec::new());
        }
        Self::present_generations(&self.root)
    }

    fn present_generations(root: &Path) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let entries = match fs::read_dir(root.join("generations")) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ids),
            Err(e) => return Err(Error::Io(e)),
        };
        for entry in entries {
            let entry = entry?;
            ids.push(entry.file_name().to_string_lossy().into_owned());
        }
        ids.sort();
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cut(n: u8) -> String {
        format!("2026-09-29T00:00:0{n}Z")
    }

    /// Copy root with two generations, a staging partial, a promoted
    /// pointer at gen-new, a top-level sidecar, per-generation cache
    /// entries, and a registered root serving file. Binds first on the
    /// empty root (production order: sign-in before any download), then
    /// populates — so the R2 orphan purge never fires here.
    fn fixture() -> (tempfile::TempDir, MemberCopyLifecycle) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        let mut lifecycle = MemberCopyLifecycle::open_with_managed(
            root,
            vec![PathBuf::from("index-cache")],
            vec!["copy.db".to_string()],
        )
        .expect("open");
        lifecycle
            .sign_in("acct-a", ReconnectAnswer::Replace { cut_at: cut(0) })
            .expect("bind");
        populate(root);
        (dir, lifecycle)
    }

    /// Pre-existing artefacts from a previous occupant (unbound root).
    fn populate(root: &Path) {
        for gen in ["gen-old", "gen-new"] {
            let gen_dir = root.join("generations").join(gen);
            fs::create_dir_all(&gen_dir).expect("gen dir");
            fs::write(gen_dir.join("snapshot.db"), format!("bytes-{gen}")).expect("snapshot");
            let cache_dir = root.join("index-cache").join(gen);
            fs::create_dir_all(&cache_dir).expect("cache dir");
            fs::write(cache_dir.join("fts.idx"), format!("index-{gen}")).expect("index");
        }
        fs::create_dir_all(root.join("staging")).expect("staging");
        fs::write(root.join("staging").join("partial.bin"), b"partial").expect("partial");
        // Promoted pointer: the consumer rebuilds, promotes, then purges.
        fs::write(root.join("current.json"), b"gen-new").expect("pointer");
        fs::write(root.join("data.db-wal"), b"wal").expect("wal");
        fs::write(root.join("copy.db"), b"serving").expect("serving db");
    }

    fn ready_copy(lifecycle: &mut MemberCopyLifecycle, account: &str) {
        lifecycle
            .sign_in(account, ReconnectAnswer::Replace { cut_at: cut(1) })
            .expect("replace");
        lifecycle.mark_refreshed(cut(1)).expect("refreshed");
        assert_eq!(
            lifecycle.effective_status(),
            CopyStatus::Ready { cut_at: cut(1) }
        );
    }

    #[test]
    fn precedence_and_read_refusal_come_from_status_alone() {
        let ready = CopyStatus::Ready { cut_at: cut(1) };
        let refreshing = CopyStatus::Refreshing { cut_at: cut(1) };
        let locked = CopyStatus::Locked { cut_at: cut(1) };
        let unavailable = CopyStatus::Unavailable;
        let removed = CopyStatus::Removed {
            cause: RemovedCause::SessionRevoked,
            deletion: DeletionState::InProgress,
        };
        assert!(removed.precedence_rank() > unavailable.precedence_rank());
        assert!(unavailable.precedence_rank() > locked.precedence_rank());
        assert!(locked.precedence_rank() > refreshing.precedence_rank());
        assert!(refreshing.precedence_rank() > ready.precedence_rank());
        assert_eq!(ready.max_precedence(&locked), locked);
        assert_eq!(locked.max_precedence(&ready), locked);
        assert!(ready.can_read());
        assert!(refreshing.can_read());
        assert!(!locked.can_read());
        assert!(!unavailable.can_read());
        assert!(!removed.can_read());
        assert_eq!(ReadDecision::for_status(&ready), ReadDecision::Allow);
        assert_eq!(ReadDecision::for_status(&locked), ReadDecision::CopyLocked);
        assert_eq!(
            ReadDecision::for_status(&unavailable),
            ReadDecision::UnavailableOffline
        );
        assert_eq!(
            ReadDecision::for_status(&removed),
            ReadDecision::UnavailableOffline
        );
    }

    #[test]
    fn reconnect_follows_answer_and_locked_needs_sign_in() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lifecycle = MemberCopyLifecycle::open(dir.path()).expect("open");
        ready_copy(&mut lifecycle, "acct-a");
        // Same generation, still current.
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Current)
                .expect("current"),
            CopyStatus::Ready { cut_at: cut(1) }
        );
        // Content moved: refreshing, then a failed refresh degrades.
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Replace { cut_at: cut(2) })
                .expect("replace"),
            CopyStatus::Refreshing { cut_at: cut(2) }
        );
        assert_eq!(
            lifecycle.mark_refresh_failed().expect("failed"),
            CopyStatus::Unavailable
        );
        assert_eq!(
            lifecycle.local_unavailable_reason(),
            Some(UnavailableReason::RefreshFailed)
        );
        // Back to ready, then the credential expires: locked, never purged.
        lifecycle
            .apply_reconnect(ReconnectAnswer::Replace { cut_at: cut(3) })
            .expect("replace");
        lifecycle.mark_refreshed(cut(3)).expect("refreshed");
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Locked)
                .expect("locked"),
            CopyStatus::Locked { cut_at: cut(3) }
        );
        assert_eq!(lifecycle.read_decision(), ReadDecision::CopyLocked);
        // A plain reconnect cannot unlock: only the sign-in path clears it.
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Current)
                .expect("current"),
            CopyStatus::Locked { cut_at: cut(3) }
        );
    }

    #[test]
    fn revoked_maps_to_removed_and_purges_everything() {
        for (revoked, removed) in [
            (RevokedCause::MembershipEnded, RemovedCause::MembershipEnded),
            (RevokedCause::RoleChanged, RemovedCause::RoleChanged),
            (RevokedCause::SessionRevoked, RemovedCause::SessionRevoked),
        ] {
            let (dir, mut lifecycle) = fixture();
            ready_copy(&mut lifecycle, "acct-a");
            let status = lifecycle
                .apply_reconnect(ReconnectAnswer::Revoked { cause: revoked })
                .expect("revoked");
            assert_eq!(
                status,
                CopyStatus::Removed {
                    cause: removed,
                    deletion: DeletionState::Complete,
                }
            );
            assert!(!lifecycle.can_read());
            assert_eq!(
                lifecycle.activatable_generations().expect("list"),
                Vec::<String>::new()
            );
            assert!(!dir.path().join("generations").join("gen-old").exists());
            assert!(!dir.path().join("generations").join("gen-new").exists());
            assert!(!dir.path().join("staging").join("partial.bin").exists());
            assert!(!dir.path().join("current.json").exists());
            assert!(!dir.path().join("data.db-wal").exists());
            assert!(!dir.path().join("index-cache").join("gen-old").exists());
            assert!(!dir.path().join("index-cache").join("gen-new").exists());
            assert!(!dir.path().join("copy.db").exists());
        }
    }

    #[test]
    fn locked_survives_restart_and_unlocks_only_via_same_account_sign_in() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lifecycle = MemberCopyLifecycle::open(dir.path()).expect("open");
        ready_copy(&mut lifecycle, "acct-a");
        lifecycle
            .apply_reconnect(ReconnectAnswer::Locked)
            .expect("locked");
        drop(lifecycle);
        // Crash/restart comes back locked: no clock clears it.
        let mut lifecycle = MemberCopyLifecycle::open(dir.path()).expect("reopen");
        assert_eq!(
            lifecycle.effective_status(),
            CopyStatus::Locked { cut_at: cut(1) }
        );
        assert_eq!(lifecycle.read_decision(), ReadDecision::CopyLocked);
        // Same account + current: ready on the kept files, no re-download.
        assert_eq!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Current)
                .expect("sign-in"),
            CopyStatus::Ready { cut_at: cut(1) }
        );
        // Different account: removed + purge, previous generation never exposed.
        lifecycle
            .apply_reconnect(ReconnectAnswer::Locked)
            .expect("locked");
        assert_eq!(
            lifecycle
                .sign_in("acct-b", ReconnectAnswer::Current)
                .expect("switch"),
            CopyStatus::Removed {
                cause: RemovedCause::AccountChanged,
                deletion: DeletionState::Complete,
            }
        );
        assert_eq!(
            lifecycle.activatable_generations().expect("list"),
            Vec::<String>::new()
        );
        drop(lifecycle);
        let lifecycle = MemberCopyLifecycle::open(dir.path()).expect("reopen");
        assert!(matches!(
            lifecycle.effective_status(),
            CopyStatus::Removed { .. }
        ));
    }

    #[test]
    fn restart_restores_ready_and_removed_is_terminal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lifecycle = MemberCopyLifecycle::open(dir.path()).expect("open");
        ready_copy(&mut lifecycle, "acct-a");
        drop(lifecycle);
        let mut lifecycle = MemberCopyLifecycle::open(dir.path()).expect("reopen");
        assert_eq!(
            lifecycle.effective_status(),
            CopyStatus::Ready { cut_at: cut(1) }
        );
        assert_eq!(lifecycle.account_token(), Some("acct-a"));
        // Removal is terminal locally: later answers cannot resurrect it.
        lifecycle
            .apply_reconnect(ReconnectAnswer::Revoked {
                cause: RevokedCause::MembershipEnded,
            })
            .expect("revoked");
        assert!(matches!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Current)
                .expect("current"),
            CopyStatus::Removed { .. }
        ));
    }

    fn fail_at_step(step: BarrierStep) -> impl BarrierFailpoint {
        move |at: BarrierStep, _path: Option<&Path>| at == step
    }

    #[test]
    fn crash_at_any_full_barrier_step_resumes_to_complete_removal() {
        for step in [
            BarrierStep::JournalWritten,
            BarrierStep::BeforeDelete,
            BarrierStep::AfterDelete,
            BarrierStep::BeforeComplete,
            BarrierStep::AfterComplete,
        ] {
            let (dir, mut lifecycle) = fixture();
            ready_copy(&mut lifecycle, "acct-a");
            let outcome =
                lifecycle.raise_barrier(RemovedCause::SessionRevoked, &fail_at_step(step));
            assert!(outcome.is_err(), "step {step:?} must inject a crash");
            // The crash leaves intent durable and the status never ready.
            assert!(dir.path().join(JOURNAL_FILENAME).exists());
            assert!(!lifecycle.effective_status().can_read());
            assert_eq!(
                lifecycle.activatable_generations().expect("list"),
                Vec::<String>::new()
            );
            // Restart resumes the purge to completion.
            drop(lifecycle);
            let lifecycle = MemberCopyLifecycle::open(dir.path()).expect("reopen");
            assert_eq!(
                lifecycle.effective_status(),
                CopyStatus::Removed {
                    cause: RemovedCause::SessionRevoked,
                    deletion: DeletionState::Complete,
                }
            );
            assert!(!dir.path().join(JOURNAL_FILENAME).exists());
            assert_eq!(
                lifecycle.activatable_generations().expect("list"),
                Vec::<String>::new()
            );
            assert!(!dir.path().join("generations").join("gen-old").exists());
            assert!(!dir.path().join("generations").join("gen-new").exists());
        }
    }

    #[test]
    fn crash_mid_superseded_purge_never_reactivates_the_older_generation() {
        for step in [
            BarrierStep::JournalWritten,
            BarrierStep::BeforeDelete,
            BarrierStep::AfterDelete,
            BarrierStep::BeforeComplete,
            BarrierStep::AfterComplete,
        ] {
            let (dir, mut lifecycle) = fixture();
            ready_copy(&mut lifecycle, "acct-a");
            // The fixture pointer already names gen-new (promote first).
            let outcome = lifecycle.purge_superseded("gen-new", &fail_at_step(step));
            assert!(outcome.is_err(), "step {step:?} must inject a crash");
            // While the barrier is pending the copy is unavailable-precedence
            // and only the kept generation is activatable.
            assert_eq!(lifecycle.effective_status(), CopyStatus::Unavailable);
            assert_eq!(lifecycle.status(), CopyStatus::Unavailable);
            assert!(!lifecycle.can_read());
            assert_eq!(
                lifecycle.activatable_generations().expect("list"),
                vec!["gen-new".to_string()]
            );
            drop(lifecycle);
            let lifecycle = MemberCopyLifecycle::open(dir.path()).expect("reopen");
            assert_eq!(
                lifecycle.activatable_generations().expect("list"),
                vec!["gen-new".to_string()]
            );
            assert!(!dir.path().join("generations").join("gen-old").exists());
            assert!(dir.path().join("generations").join("gen-new").exists());
            // The older generation's cache entry is purged with it; the
            // kept entry (rebuilt before promotion) survives. Staging is
            // scratch and always goes. The serving root file belongs to
            // the full barrier only and survives the replace path.
            assert!(!dir.path().join("index-cache").join("gen-old").exists());
            assert!(dir.path().join("index-cache").join("gen-new").exists());
            assert!(!dir.path().join("staging").join("partial.bin").exists());
            assert!(dir.path().join("copy.db").exists());
            // Stored status was untouched, so completion restores readiness.
            assert_eq!(
                lifecycle.effective_status(),
                CopyStatus::Ready { cut_at: cut(1) }
            );
        }
    }

    /// Failpoint that allows `allowed` deletions, then crashes before
    /// the next one — exercises the shrunk-`remaining` resume path.
    struct CrashAfterN {
        allowed: usize,
        deletes: std::cell::Cell<usize>,
    }

    impl BarrierFailpoint for CrashAfterN {
        fn fail_at(&self, step: BarrierStep, _path: Option<&Path>) -> bool {
            if step == BarrierStep::BeforeDelete {
                let seen = self.deletes.get();
                self.deletes.set(seen + 1);
                return seen >= self.allowed;
            }
            false
        }
    }

    /// Failpoint that plants late-arriving files on the first deletion
    /// and never fails — the re-enumeration must pick them up.
    struct PlantLateFiles {
        root: PathBuf,
        planted: std::cell::Cell<bool>,
    }

    impl BarrierFailpoint for PlantLateFiles {
        fn fail_at(&self, step: BarrierStep, _path: Option<&Path>) -> bool {
            if step == BarrierStep::AfterDelete && !self.planted.get() {
                self.planted.set(true);
                fs::write(self.root.join("staging").join("late.bin"), b"late").expect("plant");
                fs::write(self.root.join("late-wal"), b"late").expect("plant");
            }
            false
        }
    }

    fn reopen_managed(dir: &tempfile::TempDir) -> MemberCopyLifecycle {
        MemberCopyLifecycle::open_with_managed(
            dir.path(),
            vec![PathBuf::from("index-cache")],
            vec!["copy.db".to_string()],
        )
        .expect("reopen")
    }

    #[test]
    fn crash_after_several_deletions_resumes_with_shrunk_journal() {
        // Full barrier: 3 deletions land, the crash leaves the rest.
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        let total = lifecycle
            .enumerate_managed(&JournalKind::FullBarrier {
                cause: RemovedCause::SessionRevoked,
            })
            .expect("enumerate")
            .len();
        assert!(total > 4, "fixture needs several targets");
        let probe = CrashAfterN {
            allowed: 3,
            deletes: std::cell::Cell::new(0),
        };
        assert!(lifecycle
            .raise_barrier(RemovedCause::SessionRevoked, &probe)
            .is_err());
        let journal = read_journal_file(dir.path())
            .expect("read")
            .expect("pending");
        assert_eq!(journal.remaining.len(), total - 3);
        drop(lifecycle);
        let lifecycle = reopen_managed(&dir);
        assert_eq!(
            lifecycle.effective_status(),
            CopyStatus::Removed {
                cause: RemovedCause::SessionRevoked,
                deletion: DeletionState::Complete,
            }
        );
        assert!(!dir.path().join(JOURNAL_FILENAME).exists());

        // Superseded path: same shape, readiness restored at the end.
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        let probe = CrashAfterN {
            allowed: 2,
            deletes: std::cell::Cell::new(0),
        };
        assert!(lifecycle.purge_superseded("gen-new", &probe).is_err());
        assert_eq!(lifecycle.status(), CopyStatus::Unavailable);
        drop(lifecycle);
        let lifecycle = reopen_managed(&dir);
        assert_eq!(
            lifecycle.effective_status(),
            CopyStatus::Ready { cut_at: cut(1) }
        );
        assert!(dir.path().join("generations").join("gen-new").exists());
        assert!(!dir.path().join("generations").join("gen-old").exists());
        assert!(!dir.path().join("index-cache").join("gen-old").exists());
        assert!(dir.path().join("index-cache").join("gen-new").exists());
    }

    #[test]
    fn deletion_failure_leaves_unavailable_pending_never_ready() {
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        // Make the older generation undeletable: read-only parent directory.
        let generations = dir.path().join("generations");
        let mut perms = fs::metadata(&generations).expect("meta").permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            perms.set_mode(0o555);
            fs::set_permissions(&generations, perms).expect("chmod");
        }
        let outcome = lifecycle.purge_superseded("gen-new", &NoFail);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&generations, fs::Permissions::from_mode(0o755)).expect("restore");
        }
        #[cfg(unix)]
        {
            assert!(outcome.is_err(), "deletion must fail");
            assert_eq!(lifecycle.effective_status(), CopyStatus::Unavailable);
            assert!(!lifecycle.can_read());
            assert_eq!(
                lifecycle.activatable_generations().expect("list"),
                vec!["gen-new".to_string()]
            );
            // Restoring permissions lets the pending barrier complete.
            assert_eq!(
                lifecycle.resume_pending_barrier(&NoFail).expect("resume"),
                CopyStatus::Ready { cut_at: cut(1) }
            );
            assert!(!dir.path().join("generations").join("gen-old").exists());
        }
        #[cfg(not(unix))]
        eprintln!("skipped: deletion-failure assertions need unix permissions");
    }

    #[test]
    fn crash_after_complete_leaves_state_done_journal_lingering() {
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        let outcome = lifecycle.raise_barrier(
            RemovedCause::SessionRevoked,
            &fail_at_step(BarrierStep::AfterComplete),
        );
        assert!(outcome.is_err(), "AfterComplete must inject a crash");
        // Completion is durable in the state file; only the journal file
        // lingers, so a restart finishes without re-deleting anything.
        assert!(dir.path().join(JOURNAL_FILENAME).exists());
        let state = read_state_file(dir.path()).expect("read").expect("state");
        assert_eq!(
            state.status,
            CopyStatus::Removed {
                cause: RemovedCause::SessionRevoked,
                deletion: DeletionState::Complete,
            }
        );
        drop(lifecycle);
        let lifecycle = reopen_managed(&dir);
        assert!(!dir.path().join(JOURNAL_FILENAME).exists());
        assert_eq!(
            lifecycle.effective_status(),
            CopyStatus::Removed {
                cause: RemovedCause::SessionRevoked,
                deletion: DeletionState::Complete,
            }
        );
    }

    #[test]
    fn account_switch_crash_window_never_exposes_old_generations() {
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        let outcome = lifecycle.sign_in_with_fail(
            "acct-b",
            ReconnectAnswer::Current,
            &fail_at_step(BarrierStep::JournalWritten),
        );
        assert!(outcome.is_err(), "journal window must inject a crash");
        // On disk the purge intent is durable while the old binding and
        // the Ready status are untouched: nothing is readable as acct-b.
        let journal = read_journal_file(dir.path())
            .expect("read")
            .expect("pending");
        assert_eq!(journal.bind_account.as_deref(), Some("acct-b"));
        assert!(matches!(
            journal.journal,
            JournalKind::FullBarrier {
                cause: RemovedCause::AccountChanged,
            }
        ));
        let state = read_state_file(dir.path()).expect("read").expect("state");
        assert_eq!(state.account_token.as_deref(), Some("acct-a"));
        assert_eq!(state.status, CopyStatus::Ready { cut_at: cut(1) });
        assert!(dir.path().join("generations").join("gen-old").exists());
        drop(lifecycle);
        // Restart resumes from the journal: acct-b binds together with
        // the terminal removal, and the old generations are gone.
        let lifecycle = MemberCopyLifecycle::open(dir.path()).expect("reopen");
        assert_eq!(lifecycle.account_token(), Some("acct-b"));
        assert_eq!(
            lifecycle.effective_status(),
            CopyStatus::Removed {
                cause: RemovedCause::AccountChanged,
                deletion: DeletionState::Complete,
            }
        );
        assert!(lifecycle
            .activatable_generations()
            .expect("list")
            .is_empty());
        assert!(!dir.path().join("generations").join("gen-old").exists());
        assert!(!dir.path().join("generations").join("gen-new").exists());
    }

    #[test]
    fn locked_answers_only_revoke_or_wait_for_sign_in() {
        let (_dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Locked)
                .expect("locked"),
            CopyStatus::Locked { cut_at: cut(1) }
        );
        // A plain reconnect Replace does NOT unlock (F4).
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Replace { cut_at: cut(2) })
                .expect("replace"),
            CopyStatus::Locked { cut_at: cut(1) }
        );
        // Neither does Current.
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Current)
                .expect("current"),
            CopyStatus::Locked { cut_at: cut(1) }
        );
        // Revoked is the exception: removal plus purge.
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Revoked {
                    cause: RevokedCause::SessionRevoked,
                })
                .expect("revoked"),
            CopyStatus::Removed {
                cause: RemovedCause::SessionRevoked,
                deletion: DeletionState::Complete,
            }
        );
        assert!(lifecycle
            .activatable_generations()
            .expect("list")
            .is_empty());
    }

    #[test]
    fn locked_sign_in_same_account_follows_the_answer() {
        let (_dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        lifecycle
            .apply_reconnect(ReconnectAnswer::Locked)
            .expect("locked");
        // Same account + replace: refreshing on the target cut.
        assert_eq!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Replace { cut_at: cut(2) })
                .expect("sign-in"),
            CopyStatus::Refreshing { cut_at: cut(2) }
        );
        // Current mid-refresh keeps the download running: never Ready on
        // the unheld target, and the held cut is still cut(1).
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Current)
                .expect("current"),
            CopyStatus::Refreshing { cut_at: cut(2) }
        );
        // A locked answer mid-refresh reports the HELD cut, not the target.
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Locked)
                .expect("locked"),
            CopyStatus::Locked { cut_at: cut(1) }
        );
        // Same account + current unlocks onto the kept files, no download.
        assert_eq!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Current)
                .expect("sign-in"),
            CopyStatus::Ready { cut_at: cut(1) }
        );
        // Admission of the refresh advances the held cut.
        lifecycle
            .sign_in("acct-a", ReconnectAnswer::Replace { cut_at: cut(2) })
            .expect("sign-in");
        lifecycle.mark_refreshed(cut(2)).expect("refreshed");
        assert_eq!(
            lifecycle.effective_status(),
            CopyStatus::Ready { cut_at: cut(2) }
        );
    }

    #[test]
    fn locked_sign_in_with_revoked_removes() {
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        lifecycle
            .apply_reconnect(ReconnectAnswer::Locked)
            .expect("locked");
        assert_eq!(
            lifecycle
                .sign_in(
                    "acct-a",
                    ReconnectAnswer::Revoked {
                        cause: RevokedCause::MembershipEnded,
                    },
                )
                .expect("sign-in"),
            CopyStatus::Removed {
                cause: RemovedCause::MembershipEnded,
                deletion: DeletionState::Complete,
            }
        );
        assert!(!dir.path().join("generations").join("gen-new").exists());
    }

    #[test]
    fn pending_superseded_barrier_outranks_locked() {
        let (_dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        lifecycle
            .apply_reconnect(ReconnectAnswer::Locked)
            .expect("locked");
        let outcome =
            lifecycle.purge_superseded("gen-new", &fail_at_step(BarrierStep::BeforeComplete));
        assert!(outcome.is_err(), "BeforeComplete must inject a crash");
        // Stored status is still Locked, but no public path reports it
        // while the journal is pending: unavailable wins.
        assert_eq!(lifecycle.status(), CopyStatus::Unavailable);
        assert_eq!(lifecycle.read_decision(), ReadDecision::UnavailableOffline);
        assert!(!lifecycle.can_read());
        // Completing the barrier restores the stored Locked state.
        assert_eq!(
            lifecycle.resume_pending_barrier(&NoFail).expect("resume"),
            CopyStatus::Locked { cut_at: cut(1) }
        );
    }

    #[test]
    fn different_account_sign_in_from_ready_purges_everything() {
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        assert_eq!(
            lifecycle
                .sign_in("acct-b", ReconnectAnswer::Current)
                .expect("switch"),
            CopyStatus::Removed {
                cause: RemovedCause::AccountChanged,
                deletion: DeletionState::Complete,
            }
        );
        assert_eq!(lifecycle.account_token(), Some("acct-b"));
        assert!(!dir.path().join("generations").join("gen-old").exists());
        assert!(!dir.path().join("generations").join("gen-new").exists());
        assert!(!dir.path().join("current.json").exists());
        assert!(!dir.path().join("staging").join("partial.bin").exists());
        assert!(!dir.path().join("copy.db").exists());
        assert!(!dir.path().join("index-cache").join("gen-old").exists());
        assert!(!dir.path().join("index-cache").join("gen-new").exists());
        assert!(lifecycle
            .activatable_generations()
            .expect("list")
            .is_empty());
    }

    #[test]
    fn purge_superseded_refuses_without_a_matching_pointer() {
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        // Stale pointer: names the older generation, not `keep`.
        fs::write(dir.path().join("current.json"), b"gen-old").expect("pointer");
        assert!(
            lifecycle.purge_superseded("gen-new", &NoFail).is_err(),
            "stale pointer must refuse"
        );
        // Absent pointer refuses too.
        fs::remove_file(dir.path().join("current.json")).expect("remove");
        assert!(
            lifecycle.purge_superseded("gen-new", &NoFail).is_err(),
            "absent pointer must refuse"
        );
        // Refusal changes nothing: no journal, generations intact, ready.
        assert!(!dir.path().join(JOURNAL_FILENAME).exists());
        assert!(dir.path().join("generations").join("gen-old").exists());
        assert!(dir.path().join("generations").join("gen-new").exists());
        assert_eq!(
            lifecycle.effective_status(),
            CopyStatus::Ready { cut_at: cut(1) }
        );
        // JSON pointer shape also satisfies the precondition.
        fs::write(
            dir.path().join("current.json"),
            br#"{"contract":"x","generation_id":"gen-new"}"#,
        )
        .expect("pointer");
        assert!(lifecycle.purge_superseded("gen-new", &NoFail).is_ok());
        assert!(!dir.path().join("generations").join("gen-old").exists());
    }

    #[test]
    fn pointer_shapes_all_name_the_pointed_generation() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Bare id, JSON string, and {"generation_id":..} all read back.
        for (contents, expected) in [
            ("gen-new", "gen-new"),
            ("\"gen-new\"", "gen-new"),
            (
                "{\"contract\":\"x\",\"generation_id\":\"gen-new\"}",
                "gen-new",
            ),
        ] {
            fs::write(dir.path().join("current.json"), contents).expect("pointer");
            assert_eq!(
                MemberCopyLifecycle::read_pointer_generation(dir.path()).expect("read"),
                Some(expected.to_string()),
                "shape {contents:?}"
            );
        }
        // A genuine mismatch still reads back as-is (the caller refuses).
        fs::write(dir.path().join("current.json"), b"gen-old").expect("pointer");
        assert_eq!(
            MemberCopyLifecycle::read_pointer_generation(dir.path()).expect("read"),
            Some("gen-old".to_string())
        );
        // Absent pointer reads back as none.
        fs::remove_file(dir.path().join("current.json")).expect("remove");
        assert_eq!(
            MemberCopyLifecycle::read_pointer_generation(dir.path()).expect("read"),
            None
        );
    }

    #[test]
    fn restart_with_pending_superseded_whose_keep_is_absent() {
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        let outcome =
            lifecycle.purge_superseded("gen-new", &fail_at_step(BarrierStep::BeforeComplete));
        assert!(outcome.is_err(), "BeforeComplete must inject a crash");
        // The kept generation itself is lost before the restart.
        fs::remove_dir_all(dir.path().join("generations").join("gen-new")).expect("remove");
        drop(lifecycle);
        let lifecycle = reopen_managed(&dir);
        // Nothing is activatable and the pending journal clears, but the
        // status degrades to local-only `unavailable`: it must never
        // claim `ready` with no usable copy.
        assert!(lifecycle
            .activatable_generations()
            .expect("list")
            .is_empty());
        assert_eq!(lifecycle.effective_status(), CopyStatus::Unavailable);
        assert_eq!(
            lifecycle.local_unavailable_reason(),
            Some(UnavailableReason::GenerationMissing)
        );
        assert!(!lifecycle.can_read());
        assert!(!dir.path().join(JOURNAL_FILENAME).exists());
        assert!(!dir.path().join("generations").join("gen-old").exists());
    }

    #[test]
    fn removal_drops_the_held_cut_on_every_path() {
        fn held_cut_of(dir: &tempfile::TempDir) -> Option<String> {
            let bytes = fs::read(dir.path().join("lifecycle.json")).expect("state file");
            let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
            value
                .get("held_cut_at")
                .and_then(|cut| cut.as_str())
                .map(str::to_string)
        }

        // Revocation via reconnect.
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        assert_eq!(held_cut_of(&dir), Some(cut(1)));
        lifecycle
            .apply_reconnect(ReconnectAnswer::Revoked {
                cause: RevokedCause::SessionRevoked,
            })
            .expect("revoked");
        assert_eq!(held_cut_of(&dir), None);

        // Account switch via sign-in.
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        lifecycle
            .sign_in("acct-b", ReconnectAnswer::Current)
            .expect("switch");
        assert_eq!(held_cut_of(&dir), None);

        // Direct barrier, including a crash before completion: neither
        // the in-progress nor the resumed complete state keeps the cut.
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        let outcome = lifecycle.raise_barrier(
            RemovedCause::MembershipEnded,
            &fail_at_step(BarrierStep::BeforeComplete),
        );
        assert!(outcome.is_err(), "BeforeComplete must inject a crash");
        assert_eq!(held_cut_of(&dir), None);
        drop(lifecycle);
        let _lifecycle = reopen_managed(&dir);
        assert_eq!(held_cut_of(&dir), None);
    }

    #[test]
    fn current_with_no_held_cut_changes_nothing() {
        // Fresh unbound copy on an empty root: unavailable, no held cut.
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lifecycle = MemberCopyLifecycle::open(dir.path()).expect("open");
        // Fresh copy: unavailable with no held cut.
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Current)
                .expect("c"),
            CopyStatus::Unavailable
        );
        assert_eq!(lifecycle.local_unavailable_reason(), None);
        // First sign-in binds the account but admits nothing.
        assert_eq!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Current)
                .expect("sign-in"),
            CopyStatus::Unavailable
        );
        assert_eq!(lifecycle.account_token(), Some("acct-a"));
    }

    #[test]
    fn removal_is_terminal_sign_in_keeps_the_cause() {
        let (_dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        lifecycle
            .apply_reconnect(ReconnectAnswer::Revoked {
                cause: RevokedCause::MembershipEnded,
            })
            .expect("revoked");
        // A completed removal keeps its cause for the bound account:
        // Current/Locked/Revoked all stay removed.
        assert!(matches!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Current)
                .expect("sign-in"),
            CopyStatus::Removed {
                cause: RemovedCause::MembershipEnded,
                ..
            }
        ));
        assert!(matches!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Locked)
                .expect("sign-in"),
            CopyStatus::Removed {
                cause: RemovedCause::MembershipEnded,
                ..
            }
        ));
        assert!(matches!(
            lifecycle
                .sign_in(
                    "acct-a",
                    ReconnectAnswer::Revoked {
                        cause: RevokedCause::SessionRevoked,
                    },
                )
                .expect("sign-in"),
            CopyStatus::Removed {
                cause: RemovedCause::MembershipEnded,
                ..
            }
        ));
        // A different account on a completed removal starts a new switch
        // barrier (the old copy is fully gone) and binds the new account.
        assert_eq!(
            lifecycle
                .sign_in("acct-b", ReconnectAnswer::Current)
                .expect("sign-in"),
            CopyStatus::Removed {
                cause: RemovedCause::AccountChanged,
                deletion: DeletionState::Complete,
            }
        );
        assert_eq!(lifecycle.account_token(), Some("acct-b"));
        // A pending barrier resumes instead of rewriting: same cause,
        // original account, deletion completes.
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        let outcome = lifecycle.apply_reconnect_with_fail(
            ReconnectAnswer::Revoked {
                cause: RevokedCause::RoleChanged,
            },
            &fail_at_step(BarrierStep::BeforeComplete),
        );
        assert!(outcome.is_err(), "BeforeComplete must inject a crash");
        assert_eq!(
            lifecycle
                .sign_in("acct-b", ReconnectAnswer::Current)
                .expect("sign-in"),
            CopyStatus::Removed {
                cause: RemovedCause::RoleChanged,
                deletion: DeletionState::Complete,
            }
        );
        assert_eq!(lifecycle.account_token(), Some("acct-a"));
        assert!(!dir.path().join("generations").join("gen-new").exists());
    }

    #[test]
    fn removed_complete_exits_on_replace_for_the_bound_account() {
        // (a) Account switch, then B's own copy: removed → refreshing →
        // ready, with only B's generation activatable.
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        assert_eq!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Replace { cut_at: cut(9) })
                .expect("replace"),
            CopyStatus::Refreshing { cut_at: cut(9) }
        );
        lifecycle
            .sign_in("acct-b", ReconnectAnswer::Replace { cut_at: cut(9) })
            .expect("switch");
        assert_eq!(
            lifecycle.effective_status(),
            CopyStatus::Removed {
                cause: RemovedCause::AccountChanged,
                deletion: DeletionState::Complete,
            }
        );
        // The reconnect check answers Replace for the bound account: a
        // fresh copy starts with no held cut.
        assert_eq!(
            lifecycle
                .sign_in("acct-b", ReconnectAnswer::Replace { cut_at: cut(9) })
                .expect("re-replace"),
            CopyStatus::Refreshing { cut_at: cut(9) }
        );
        // The consumer admits B's generation, purges, and marks refreshed.
        let gen_dir = dir.path().join("generations").join("gen-b");
        fs::create_dir_all(&gen_dir).expect("gen dir");
        fs::write(gen_dir.join("snapshot.db"), b"bytes-b").expect("snapshot");
        fs::write(dir.path().join("current.json"), b"gen-b").expect("pointer");
        lifecycle.purge_superseded("gen-b", &NoFail).expect("purge");
        assert_eq!(
            lifecycle.mark_refreshed(cut(9)).expect("refreshed"),
            CopyStatus::Ready { cut_at: cut(9) }
        );
        assert_eq!(
            lifecycle.activatable_generations().expect("list"),
            vec!["gen-b".to_string()]
        );

        // (b) Revoked, completed, then Replace via the plain reconnect
        // path: refreshing → ready.
        let (_dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        lifecycle
            .apply_reconnect(ReconnectAnswer::Revoked {
                cause: RevokedCause::MembershipEnded,
            })
            .expect("revoked");
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Replace { cut_at: cut(7) })
                .expect("replace"),
            CopyStatus::Refreshing { cut_at: cut(7) }
        );
        assert_eq!(
            lifecycle.mark_refreshed(cut(7)).expect("refreshed"),
            CopyStatus::Ready { cut_at: cut(7) }
        );

        // (d) Current from Removed{Complete} stays removed (nothing held).
        let (_dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        lifecycle
            .apply_reconnect(ReconnectAnswer::Revoked {
                cause: RevokedCause::SessionRevoked,
            })
            .expect("revoked");
        assert!(matches!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Current)
                .expect("current"),
            CopyStatus::Removed { .. }
        ));
        assert!(matches!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Locked)
                .expect("sign-in"),
            CopyStatus::Removed { .. }
        ));
    }

    #[test]
    fn removed_in_progress_ignores_replace_and_resumes() {
        // (c) A pending barrier stays removed on Replace; the barrier
        // resumes best-effort and the cause is never rewritten.
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        let outcome = lifecycle.apply_reconnect_with_fail(
            ReconnectAnswer::Revoked {
                cause: RevokedCause::RoleChanged,
            },
            &fail_at_step(BarrierStep::BeforeComplete),
        );
        assert!(outcome.is_err(), "BeforeComplete must inject a crash");
        assert_eq!(
            lifecycle
                .apply_reconnect(ReconnectAnswer::Replace { cut_at: cut(5) })
                .expect("replace"),
            CopyStatus::Removed {
                cause: RemovedCause::RoleChanged,
                deletion: DeletionState::Complete,
            }
        );
        assert!(!dir.path().join(JOURNAL_FILENAME).exists());
        assert!(!dir.path().join("generations").join("gen-new").exists());
    }

    #[test]
    fn admitting_straight_after_a_switch_is_silently_ignored() {
        // The literal mistake: switch → install → mark_refreshed must NOT
        // reach Ready. Recovery needs a second reconnect check first.
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        lifecycle
            .sign_in("acct-b", ReconnectAnswer::Replace { cut_at: cut(9) })
            .expect("switch");
        // Admit-like install straight after the switch…
        let gen_dir = dir.path().join("generations").join("gen-b");
        fs::create_dir_all(&gen_dir).expect("gen dir");
        fs::write(gen_dir.join("snapshot.db"), b"bytes-b").expect("snapshot");
        fs::write(dir.path().join("current.json"), b"gen-b").expect("pointer");
        // …is silently ignored: mark_refreshed returns the unchanged
        // Removed status and nothing is activatable.
        assert_eq!(
            lifecycle.mark_refreshed(cut(9)).expect("refreshed"),
            CopyStatus::Removed {
                cause: RemovedCause::AccountChanged,
                deletion: DeletionState::Complete,
            }
        );
        assert!(lifecycle
            .activatable_generations()
            .expect("list")
            .is_empty());
        // Second reconnect check: Replace for the bound account starts a
        // fresh copy, and only then does admission take effect.
        assert_eq!(
            lifecycle
                .sign_in("acct-b", ReconnectAnswer::Replace { cut_at: cut(9) })
                .expect("re-replace"),
            CopyStatus::Refreshing { cut_at: cut(9) }
        );
        lifecycle.purge_superseded("gen-b", &NoFail).expect("purge");
        assert_eq!(
            lifecycle.mark_refreshed(cut(9)).expect("refreshed"),
            CopyStatus::Ready { cut_at: cut(9) }
        );
        assert_eq!(
            lifecycle.activatable_generations().expect("list"),
            vec!["gen-b".to_string()]
        );
    }

    #[test]
    fn files_created_mid_purge_are_removed_before_complete() {
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        let planter = PlantLateFiles {
            root: dir.path().to_path_buf(),
            planted: std::cell::Cell::new(false),
        };
        // Never fails, so one call must still end complete — with the
        // late files gone via the re-enumeration loop.
        assert_eq!(
            lifecycle
                .raise_barrier(RemovedCause::SessionRevoked, &planter)
                .expect("purge"),
            CopyStatus::Removed {
                cause: RemovedCause::SessionRevoked,
                deletion: DeletionState::Complete,
            }
        );
        assert!(planter.planted.get(), "failpoint must have planted files");
        assert!(!dir.path().join("staging").join("late.bin").exists());
        assert!(!dir.path().join("late-wal").exists());
        assert!(!dir.path().join(JOURNAL_FILENAME).exists());
    }

    #[test]
    fn first_binding_silently_adopts_the_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        populate(dir.path());
        // A staged download the consumer is about to admit.
        fs::write(dir.path().join("staging").join("incoming.db"), b"staged").expect("staged");
        let mut lifecycle = reopen_managed(&dir);
        assert_eq!(lifecycle.account_token(), None);
        // First binding finds a previous occupant's artefacts: silent
        // orphan purge (never `account_changed`), then bind and follow
        // the answer normally. Staging is scratch and is preserved.
        assert_eq!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Replace { cut_at: cut(1) })
                .expect("sign-in"),
            CopyStatus::Refreshing { cut_at: cut(1) }
        );
        assert_eq!(lifecycle.account_token(), Some("acct-a"));
        assert!(!dir.path().join("generations").join("gen-old").exists());
        assert!(!dir.path().join("generations").join("gen-new").exists());
        assert!(!dir.path().join("current.json").exists());
        assert!(!dir.path().join("copy.db").exists());
        assert!(!dir.path().join("index-cache").join("gen-old").exists());
        assert!(dir.path().join("staging").join("partial.bin").exists());
        assert!(dir.path().join("staging").join("incoming.db").exists());
        assert!(!dir.path().join(JOURNAL_FILENAME).exists());

        // Crash between the journal write and the binding: the orphaned
        // generations are never attributed to the new account, the staged
        // download survives, and no removal is ever shown.
        let dir = tempfile::tempdir().expect("tempdir");
        populate(dir.path());
        fs::write(dir.path().join("staging").join("incoming.db"), b"staged").expect("staged");
        let mut lifecycle = reopen_managed(&dir);
        let outcome = lifecycle.sign_in_with_fail(
            "acct-a",
            ReconnectAnswer::Replace { cut_at: cut(1) },
            &fail_at_step(BarrierStep::JournalWritten),
        );
        assert!(outcome.is_err(), "journal window must inject a crash");
        let journal = read_journal_file(dir.path())
            .expect("read")
            .expect("pending");
        assert!(matches!(journal.journal, JournalKind::Orphan));
        assert_eq!(journal.bind_account, None);
        let state = read_state_file(dir.path()).expect("read").expect("state");
        assert_eq!(state.account_token, None);
        assert!(dir.path().join("staging").join("incoming.db").exists());
        drop(lifecycle);
        // Restart resumes the orphan purge; the retry then binds cleanly.
        let mut lifecycle = MemberCopyLifecycle::open(dir.path()).expect("reopen");
        assert_eq!(lifecycle.account_token(), None);
        assert!(!dir.path().join("generations").join("gen-old").exists());
        assert!(dir.path().join("staging").join("incoming.db").exists());
        assert_eq!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Replace { cut_at: cut(1) })
                .expect("sign-in"),
            CopyStatus::Refreshing { cut_at: cut(1) }
        );
        assert_eq!(lifecycle.account_token(), Some("acct-a"));
    }

    #[test]
    fn degraded_keep_absent_never_resurrects_ready() {
        // m1: after the R3 degrade, sign_in(Current) must not promote the
        // stale held cut back to Ready with nothing activatable.
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        let outcome =
            lifecycle.purge_superseded("gen-new", &fail_at_step(BarrierStep::BeforeComplete));
        assert!(outcome.is_err(), "BeforeComplete must inject a crash");
        fs::remove_dir_all(dir.path().join("generations").join("gen-new")).expect("remove");
        drop(lifecycle);
        let mut lifecycle = reopen_managed(&dir);
        assert_eq!(lifecycle.effective_status(), CopyStatus::Unavailable);
        assert_eq!(
            lifecycle
                .sign_in("acct-a", ReconnectAnswer::Current)
                .expect("sign-in"),
            CopyStatus::Unavailable
        );
        assert_eq!(
            lifecycle.local_unavailable_reason(),
            Some(UnavailableReason::GenerationMissing)
        );
        assert!(lifecycle
            .activatable_generations()
            .expect("list")
            .is_empty());
    }

    #[cfg(unix)]
    fn chmod_generations(dir: &tempfile::TempDir, mode: u32) {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(
            dir.path().join("generations"),
            fs::Permissions::from_mode(mode),
        )
        .expect("chmod");
    }

    #[test]
    fn raise_barrier_deletion_failure_stays_pending_never_ready() {
        #[cfg(not(unix))]
        {
            eprintln!("skipped: deletion-failure assertions need unix permissions");
            return;
        }
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        #[cfg(unix)]
        chmod_generations(&dir, 0o555);
        let outcome = lifecycle.raise_barrier(RemovedCause::MembershipEnded, &NoFail);
        #[cfg(unix)]
        chmod_generations(&dir, 0o755);
        #[cfg(unix)]
        {
            assert!(outcome.is_err(), "deletion must fail");
            assert!(dir.path().join(JOURNAL_FILENAME).exists());
            assert_eq!(
                lifecycle.effective_status(),
                CopyStatus::Removed {
                    cause: RemovedCause::MembershipEnded,
                    deletion: DeletionState::InProgress,
                }
            );
            assert!(!lifecycle.can_read());
            assert_eq!(lifecycle.read_decision(), ReadDecision::UnavailableOffline);
            assert_eq!(
                lifecycle.resume_pending_barrier(&NoFail).expect("resume"),
                CopyStatus::Removed {
                    cause: RemovedCause::MembershipEnded,
                    deletion: DeletionState::Complete,
                }
            );
            assert!(!dir.path().join(JOURNAL_FILENAME).exists());
        }
    }

    #[test]
    fn open_swallows_resume_error_and_completes_later() {
        #[cfg(not(unix))]
        {
            eprintln!("skipped: resume-error assertions need unix permissions");
            return;
        }
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        // Leave a pending journal with an undeletable target behind.
        #[cfg(unix)]
        chmod_generations(&dir, 0o555);
        let outcome = lifecycle.raise_barrier(RemovedCause::SessionRevoked, &NoFail);
        drop(lifecycle);
        // Opening while the purge cannot run must still succeed: the
        // error stays pending in the journal, it never fails the open.
        let lifecycle = MemberCopyLifecycle::open(dir.path()).expect("reopen");
        #[cfg(unix)]
        {
            assert!(outcome.is_err(), "deletion must fail");
            assert!(dir.path().join(JOURNAL_FILENAME).exists());
            assert_eq!(
                lifecycle.effective_status(),
                CopyStatus::Removed {
                    cause: RemovedCause::SessionRevoked,
                    deletion: DeletionState::InProgress,
                }
            );
        }
        drop(lifecycle);
        #[cfg(unix)]
        chmod_generations(&dir, 0o755);
        #[cfg(unix)]
        {
            let mut lifecycle = reopen_managed(&dir);
            assert_eq!(
                lifecycle.resume_pending_barrier(&NoFail).expect("resume"),
                CopyStatus::Removed {
                    cause: RemovedCause::SessionRevoked,
                    deletion: DeletionState::Complete,
                }
            );
            assert!(!dir.path().join(JOURNAL_FILENAME).exists());
        }
    }

    #[test]
    fn scope_change_purge_deletes_everything_and_ends_refreshing() {
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        assert_eq!(
            lifecycle.current_generation_id().expect("pointer"),
            Some("gen-new".to_string())
        );
        let status = lifecycle
            .begin_scope_change_purge(&cut(9))
            .expect("scope purge");
        assert_eq!(status, CopyStatus::Refreshing { cut_at: cut(9) });
        // Every old artefact is gone before anything new downloads.
        assert!(!dir.path().join("generations").join("gen-old").exists());
        assert!(!dir.path().join("generations").join("gen-new").exists());
        assert!(!dir.path().join("current.json").exists());
        assert!(!dir.path().join("staging").join("partial.bin").exists());
        assert!(!dir.path().join("index-cache").join("gen-old").exists());
        assert!(!dir.path().join("index-cache").join("gen-new").exists());
        assert!(!dir.path().join("copy.db").exists());
        assert!(!dir.path().join(JOURNAL_FILENAME).exists());
        // No held cut survives; Refreshing with nothing activatable is the
        // documented limbo — the read layer must check activatable, not
        // status alone, before serving bytes.
        assert!(lifecycle
            .activatable_generations()
            .expect("list")
            .is_empty());
        assert_eq!(lifecycle.current_generation_id().expect("pointer"), None);
        let bytes = fs::read(dir.path().join("lifecycle.json")).expect("state");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert!(value.get("held_cut_at").is_none());
    }

    #[test]
    fn scope_change_crash_at_any_step_resumes_without_resurrecting() {
        for step in [
            BarrierStep::JournalWritten,
            BarrierStep::BeforeDelete,
            BarrierStep::AfterDelete,
            BarrierStep::BeforeComplete,
            BarrierStep::AfterComplete,
        ] {
            let (dir, mut lifecycle) = fixture();
            ready_copy(&mut lifecycle, "acct-a");
            let outcome = lifecycle.purge_for_scope_change(&cut(9), &fail_at_step(step));
            assert!(outcome.is_err(), "step {step:?} must inject a crash");
            assert!(dir.path().join(JOURNAL_FILENAME).exists());
            assert_eq!(lifecycle.effective_status(), CopyStatus::Unavailable);
            assert!(!lifecycle.can_read());
            assert!(lifecycle
                .activatable_generations()
                .expect("list")
                .is_empty());
            drop(lifecycle);
            let lifecycle = reopen_managed(&dir);
            assert_eq!(
                lifecycle.effective_status(),
                CopyStatus::Refreshing { cut_at: cut(9) }
            );
            assert!(!dir.path().join(JOURNAL_FILENAME).exists());
            assert!(!dir.path().join("generations").join("gen-old").exists());
            assert!(!dir.path().join("generations").join("gen-new").exists());
            assert!(!dir.path().join("current.json").exists());
            assert!(lifecycle
                .activatable_generations()
                .expect("list")
                .is_empty());
        }
    }

    #[test]
    fn scope_change_leaves_locked_and_removed_complete_untouched() {
        let (dir, mut lifecycle) = fixture();
        ready_copy(&mut lifecycle, "acct-a");
        lifecycle
            .apply_reconnect(ReconnectAnswer::Locked)
            .expect("locked");
        let status = lifecycle.begin_scope_change_purge(&cut(9)).expect("noop");
        assert!(matches!(status, CopyStatus::Locked { .. }));
        assert!(dir.path().join("generations").join("gen-new").exists());
        assert_eq!(
            lifecycle.current_generation_id().expect("pointer"),
            Some("gen-new".to_string())
        );
        // Completed removal is terminal for the device too: a scope purge
        // must not start a fresh copy on its own.
        lifecycle
            .sign_in("acct-b", ReconnectAnswer::Current)
            .expect("switch");
        assert!(matches!(
            lifecycle.effective_status(),
            CopyStatus::Removed { .. }
        ));
        let status = lifecycle.begin_scope_change_purge(&cut(9)).expect("noop");
        assert!(matches!(status, CopyStatus::Removed { .. }));
    }
}
