//! Restricted cooperative execution for existing enrolled SQLite custody.
//!
//! Singular ordinary Document body updates use a generation-shared owned lane.
//! Exposed connections permanently refuse main writes; capture has a separate
//! private INSERT-only role. Catalog, migrations and reconciliation do not gain
//! an enrollment writer. Statement roles never change after installation.
//!
//! The accepted-task ceiling is availability policy, not a session limit. Jobs
//! retain request admissions despite waiter loss. The lane is released normally
//! only after explicit physical close acknowledgement; uncertain setup/cleanup,
//! panic or task loss permanently poisons the process owner. A bounded retained
//! entry owns the whole runner and admissions before spawn. Timeout reports an
//! uncertain outcome while the same cleanup future continues; aborted polling
//! resumes only on explicit shutdown drain. Without ACK (including setup loss),
//! admissions remain strongly held until process exit, so freeze cannot pretend
//! that poison is physical completion. SQLx pool lifetime,
//! detach, after_release invocation and worker Drop are not close witnesses.
//!
//! Cooperative custody excludes raw/admin mutation after enrollment. This is no
//! activated session ingress or backend parity. The crate-private stage-1
//! driver shares this runner but remains unavailable to public consumers.
use super::*;
use futures::FutureExt;
use std::ffi::{c_char, CStr};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use tokio::sync::{oneshot, Notify};

/// Availability ceiling for accepted tasks, not a protocol/session limit.
const JOB_CAPACITY: usize = 32;
const CLEANUP_LIMIT: Duration = Duration::from_secs(30);
const CONTEXT_KEY: &[u8] = b"native.enrolled.execution.v1\0";

#[derive(Debug)]
pub(crate) struct ExecutionOwner {
    pub(crate) path: std::path::PathBuf,
    pub(crate) generation: String,
    lane: tokio::sync::Mutex<()>,
    pub(crate) sessions: Mutex<crate::coedit::driver::DriverState>,
    poisoned: AtomicBool,
    accepted: AtomicUsize,
    active_job: Mutex<Option<uuid::Uuid>>,
    // At most JOB_CAPACITY accepted entries; unresolved admissions/futures are
    // strongly retained by the process-lifetime custody owner, never evicted.
    retained: Mutex<std::collections::HashMap<uuid::Uuid, Arc<RetainedJob>>>,
    #[cfg(test)]
    submitted: Notify,
    #[cfg(test)]
    document_installations: AtomicUsize,
}
impl ExecutionOwner {
    pub(crate) fn new(path: std::path::PathBuf, generation: String) -> Self {
        Self {
            path,
            generation,
            lane: tokio::sync::Mutex::new(()),
            sessions: Mutex::new(crate::coedit::driver::DriverState::default()),
            poisoned: AtomicBool::new(false),
            accepted: AtomicUsize::new(0),
            active_job: Mutex::new(None),
            retained: Mutex::new(std::collections::HashMap::new()),
            #[cfg(test)]
            submitted: Notify::new(),
            #[cfg(test)]
            document_installations: AtomicUsize::new(0),
        }
    }
    pub(super) fn check(&self) -> Result<()> {
        if self.poisoned.load(Ordering::Acquire) {
            Err(Error::engine(
                "enrolled execution owner is poisoned; restart and reconcile required",
            ))
        } else {
            Ok(())
        }
    }
    #[cfg(test)]
    pub(crate) async fn wait_for_accepted(&self, minimum: usize) {
        loop {
            let notified = self.submitted.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.accepted.load(Ordering::Acquire) >= minimum {
                return;
            }
            notified.await;
        }
    }

    fn sessions_clean(&self) -> bool {
        self.sessions.lock().is_ok_and(|state| !state.has_unsaved())
    }

    pub(super) fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }
}

// Drop poisons BEFORE its mutex field releases the lane. Keeping poison only
// in the job ticket would leave a task-abort/setup-panic destructor race.
struct LaneLease<'a> {
    _guard: tokio::sync::MutexGuard<'a, ()>,
    owner: &'a ExecutionOwner,
    armed: bool,
}
impl Drop for LaneLease<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.owner.poison();
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct HandleJobs {
    state: Mutex<(bool, usize)>,
    changed: Notify,
}
struct Ticket {
    owner: Arc<ExecutionOwner>,
    handle: Arc<HandleJobs>,
    armed: bool,
    job: uuid::Uuid,
}
impl Drop for Ticket {
    fn drop(&mut self) {
        if self.armed {
            self.owner.poison();
        }
        if let Ok(mut active) = self.owner.active_job.lock() {
            if *active == Some(self.job) {
                *active = None;
            }
        }
        self.owner.accepted.fetch_sub(1, Ordering::AcqRel);
        if let Ok(mut state) = self.handle.state.lock() {
            state.1 -= 1;
        }
        self.handle.changed.notify_waiters();
    }
}
impl HandleJobs {
    // These are per-handle close observations, not a terminal owner-handoff
    // seal. Independent handles may still admit work after a clean observation.
    // Activating session consumers requires a separate atomic admission seal
    // held through physical generation retirement.
    pub(super) fn retirement_ready(&self, owner: Option<&Arc<ExecutionOwner>>) -> bool {
        owner.is_none_or(|owner| {
            owner.check().is_ok()
                && owner.accepted.load(Ordering::Acquire) == 0
                && owner.sessions_clean()
        }) && self.state.lock().is_ok_and(|state| state.0 && state.1 == 0)
    }
    pub(super) fn stop_submission(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.0 = true;
        }
    }
    fn register(self: &Arc<Self>, owner: &Arc<ExecutionOwner>) -> Result<Ticket> {
        owner.check()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::engine("enrolled handle job state poisoned"))?;
        if state.0 {
            return Err(Error::engine("enrolled handle is closing"));
        }
        owner
            .accepted
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < JOB_CAPACITY).then_some(n + 1)
            })
            .map_err(|_| {
                Error::engine("enrolled execution queue capacity exhausted; request not accepted")
            })?;
        state.1 += 1;
        #[cfg(test)]
        owner.submitted.notify_waiters();
        Ok(Ticket {
            owner: owner.clone(),
            handle: self.clone(),
            armed: true,
            job: uuid::Uuid::new_v4(),
        })
    }
    pub(super) async fn stop_and_drain(&self, owner: Option<&Arc<ExecutionOwner>>) -> bool {
        if let Ok(mut state) = self.state.lock() {
            state.0 = true;
        } else {
            if let Some(owner) = owner {
                owner.poison();
            }
            return false;
        }
        self.changed.notify_waiters();
        if let Some(owner) = owner {
            owner.resume_retained();
        }
        let drain = async {
            loop {
                let notified = self.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.state.lock().is_ok_and(|state| state.1 == 0) {
                    return;
                }
                notified.await;
            }
        };
        if tokio::time::timeout(CLEANUP_LIMIT, drain).await.is_err() {
            if let Some(owner) = owner {
                owner.poison();
            }
            return false;
        }
        if let Some(owner) = owner {
            // Check AFTER this handle's admitted work settles. Independent
            // handles share this lane and state; HandleJobs alone is no witness.
            // Another handle can retain the lane through uncertain physical
            // cleanup. Refuse conservatively rather than waiting beyond this
            // handle's bounded drain; never cancel that retained cleanup.
            let Ok(_lane) = owner.lane.try_lock() else {
                return false;
            };
            return owner.check().is_ok()
                && owner.accepted.load(Ordering::Acquire) == 0
                && owner.sessions_clean();
        }
        true
    }
}

#[cfg(test)]
pub(crate) async fn wait_for_handle_stop(db: &Db) {
    loop {
        let notified = db.execution_jobs.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if db.execution_jobs.state.lock().is_ok_and(|state| state.0) {
            return;
        }
        notified.await;
    }
}

// Separate, NONAUTHORIZING body custody. The reader's existing process owner
// must hold one of its two slots before registration and retain startup and
// admissions through completion. This per-handle state is NOT a second queue.
// No ExecutionOwner, Document role, or managed Ticket Drop is involved.
const BODY_HANDLE_CAPACITY: usize = 2;
type BodyCloseFuture = futures::future::Shared<futures::future::BoxFuture<'static, bool>>;

#[derive(Debug, Default)]
pub(crate) struct BodyHandleJobs {
    state: Mutex<BodyHandleState>,
    changed: Notify,
}
#[derive(Debug, Default)]
struct BodyHandleState {
    stopping: bool,
    jobs: std::collections::HashMap<uuid::Uuid, BodyJob>,
}
#[derive(Debug, Default)]
struct BodyJob {
    started: bool,
    unknown: bool,
    // SAME owned driver/CPU close future survives every abandoned drain.
    close: Option<BodyCloseFuture>,
}
pub(crate) struct BodyJobTicket {
    handle: Arc<BodyHandleJobs>,
    job: uuid::Uuid,
    armed: bool,
}
impl Drop for BodyJobTicket {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Even an unpolled ticket needs EXPLICIT no-start proof. Unknown and
        // removal are serialized by the SAME registration/fence mutex.
        let mut state = self.handle.state_for_cleanup();
        if let Some(job) = state.jobs.get_mut(&self.job) {
            job.unknown = true;
        }
        drop(state);
        self.handle.changed.notify_waiters();
    }
}
impl BodyHandleJobs {
    /// Nonregistering observation only. Capacity, physical uncertainty and
    /// authority remain separate; register still fences submission atomically.
    pub(super) fn submission_available(&self) -> Result<bool> {
        let state = self
            .state
            .lock()
            .map_err(|_| Error::engine("body handle state poisoned"))?;
        Ok(!state.stopping)
    }

    // Poison never grants readiness. Recover custody solely to retain/drive
    // original cleanup; all surviving entries remain permanently unknown.
    fn state_for_cleanup(&self) -> std::sync::MutexGuard<'_, BodyHandleState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(error) => {
                let mut state = error.into_inner();
                state.stopping = true;
                for job in state.jobs.values_mut() {
                    job.unknown = true;
                }
                state
            }
        }
    }
    pub(super) fn register(self: &Arc<Self>) -> Result<BodyJobTicket> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| Error::engine("body handle state poisoned"))?;
        if state.stopping || state.jobs.len() >= BODY_HANDLE_CAPACITY {
            return Err(Error::engine("body handle unavailable"));
        }
        let job = uuid::Uuid::new_v4();
        state.jobs.insert(job, BodyJob::default());
        Ok(BodyJobTicket {
            handle: self.clone(),
            job,
            armed: true,
        })
    }
    pub(super) fn stop_submission(&self) {
        self.state_for_cleanup().stopping = true;
        self.changed.notify_waiters();
    }
    pub(super) fn retirement_ready(&self) -> bool {
        self.state
            .lock()
            .is_ok_and(|s| s.stopping && s.jobs.is_empty())
    }
    pub(super) async fn drain(&self) -> bool {
        self.stop_submission();
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let jobs = {
                let state = self.state_for_cleanup();
                state
                    .jobs
                    .iter()
                    .map(|(id, job)| (*id, job.close.clone(), job.unknown))
                    .collect::<Vec<_>>()
            };
            if jobs.is_empty() {
                return self.retirement_ready();
            }
            let mut complete = true;
            for (id, close, unknown) in jobs {
                if let Some(close) = close {
                    // Unknown still drives its stored ORIGINAL cleanup. A
                    // successful close cannot clear that distinct uncertainty.
                    complete &= self.finish_job(id, close).await;
                } else if unknown {
                    complete = false;
                }
            }
            if !complete {
                return false;
            }
            if self.retirement_ready() {
                return true;
            }
            notified.await;
        }
    }
    async fn finish_job(&self, id: uuid::Uuid, close: BodyCloseFuture) -> bool {
        let physical_complete = close.await;
        let mut state = self.state_for_cleanup();
        let complete = if let Some(job) = state.jobs.get_mut(&id) {
            if !physical_complete {
                job.unknown = true;
            }
            physical_complete && !job.unknown
        } else {
            // Another observer may have completed/removal under this SAME
            // mutex. No-start and physical transfer consume the sole ticket;
            // there is no later transfer that can reuse a removed entry.
            physical_complete && !self.state.is_poisoned()
        };
        if complete {
            state.jobs.remove(&id);
        }
        drop(state);
        self.changed.notify_waiters();
        complete
    }
    #[cfg(test)]
    pub(super) fn poison_state_for_test(&self) {
        let _state = self.state.lock().unwrap();
        panic!("body lifecycle test state poison");
    }
    #[cfg(test)]
    pub(super) fn retained_close_result_for_test(&self) -> Option<bool> {
        self.state_for_cleanup()
            .jobs
            .values()
            .find_map(|job| job.close.as_ref().and_then(|close| close.peek().copied()))
    }
}

#[cfg(test)]
mod body_availability_tests {
    use super::*;

    fn snapshot(handle: &BodyHandleJobs) -> (bool, Vec<(uuid::Uuid, bool, bool, bool)>) {
        let state = handle.state.lock().unwrap();
        let mut jobs = state
            .jobs
            .iter()
            .map(|(id, job)| (*id, job.started, job.unknown, job.close.is_some()))
            .collect::<Vec<_>>();
        jobs.sort_by_key(|job| job.0);
        (state.stopping, jobs)
    }

    fn available_without_mutation(handle: &BodyHandleJobs) {
        let before = snapshot(handle);
        assert!(handle.submission_available().unwrap());
        assert_eq!(snapshot(handle), before);
    }

    #[test]
    fn query_preserves_initial_registered_and_no_start_release_state() {
        let handle = Arc::new(BodyHandleJobs::default());
        available_without_mutation(&handle);
        let first = handle.register().unwrap();
        available_without_mutation(&handle);
        let second = handle.register().unwrap();
        assert_eq!(snapshot(&handle).1.len(), BODY_HANDLE_CAPACITY);
        // Observing availability neither reserves capacity nor bypasses the
        // actual registration limit on the SAME state.
        available_without_mutation(&handle);
        assert!(handle.register().is_err());
        first.no_physical_started().unwrap();
        assert_eq!(snapshot(&handle).1.len(), 1);
        available_without_mutation(&handle);
        second.no_physical_started().unwrap();
        assert!(snapshot(&handle).1.is_empty());
        available_without_mutation(&handle);
    }

    #[test]
    fn query_preserves_stopping_before_and_after_no_start_release() {
        let handle = Arc::new(BodyHandleJobs::default());
        let ticket = handle.register().unwrap();
        handle.stop_submission();
        let before = snapshot(&handle);
        assert!(!handle.submission_available().unwrap());
        assert_eq!(snapshot(&handle), before);
        assert!(handle.register().is_err());
        ticket.no_physical_started().unwrap();
        let after = snapshot(&handle);
        assert!(after.0 && after.1.is_empty());
        assert!(!handle.submission_available().unwrap());
        assert_eq!(snapshot(&handle), after);
    }

    #[test]
    fn query_does_not_reclassify_unknown_as_stopping_or_capacity() {
        let handle = Arc::new(BodyHandleJobs::default());
        let ticket = handle.register().unwrap();
        drop(ticket); // Existing armed Drop retains an unknown witness.
        let before = snapshot(&handle);
        assert!(!before.0);
        assert_eq!(before.1.len(), 1);
        assert!(before.1[0].2);
        available_without_mutation(&handle);
        assert_eq!(snapshot(&handle), before);
        // No physical work/ACK or retirement readiness is inferred by query.
        assert!(!handle.retirement_ready());
    }

    #[test]
    fn poisoned_query_refuses_without_cleanup_recovery_or_ready_mutation() {
        let handle = BodyHandleJobs::default();
        let poison = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _state = handle.state.lock().unwrap();
            panic!("body availability test mutex poison");
        }));
        assert!(poison.is_err());
        for _ in 0..2 {
            assert!(matches!(
                handle.submission_available(),
                Err(Error::Engine(message)) if message == "body handle state poisoned"
            ));
            assert!(handle.state.is_poisoned());
            // Inspection is test-only; unlike state_for_cleanup it changes
            // neither stopping nor jobs and never clears the poison flag.
            let state = handle.state.lock().unwrap_err().into_inner();
            assert!(!state.stopping);
            assert!(state.jobs.is_empty());
        }
    }
}

impl BodyJobTicket {
    /// The retained reader owner calls this immediately BEFORE the first
    /// startup poll; it already owns the process slot, future and admissions.
    pub(crate) fn physical_started(&self) -> Result<()> {
        let mut state = self.handle.state_for_cleanup();
        let job = state
            .jobs
            .get_mut(&self.job)
            .ok_or_else(|| Error::engine("body physical startup state invalid"))?;
        if job.unknown || job.started {
            job.unknown = true;
            drop(state);
            self.handle.changed.notify_waiters();
            return Err(Error::engine("body physical startup state invalid"));
        }
        job.started = true;
        Ok(())
    }
    /// Consumes an unstarted ticket. No driver or CPU completion is claimed.
    pub(crate) fn no_physical_started(mut self) -> Result<()> {
        let mut state = self.handle.state_for_cleanup();
        let job = state
            .jobs
            .get(&self.job)
            .ok_or_else(|| Error::engine("body no-start proof unavailable"))?;
        if job.started || job.unknown {
            drop(state);
            return Err(Error::engine("body no-start proof unavailable"));
        }
        state.jobs.remove(&self.job);
        self.armed = false;
        drop(state);
        self.handle.changed.notify_waiters();
        Ok(())
    }
    /// ONE-SHOT transfer: consumes the sole ticket, so a second transfer before
    /// or after terminal completion is not representable through this API.
    /// Retain ORIGINAL raw-close/ALL registered CPU handles before observation.
    /// H5 retains outer admissions and its process slot through actual ACK.
    pub(crate) fn finish_physical(
        mut self,
        connection: SqliteConnection,
        cpu: Vec<tokio::task::JoinHandle<()>>,
    ) -> futures::future::BoxFuture<'static, bool> {
        let close = async move {
            // Always attempt real close even when a CPU job panicked.
            let mut complete = true;
            for job in cpu {
                complete &= job.await.is_ok();
            }
            matches!(
                AssertUnwindSafe(connection.close()).catch_unwind().await,
                Ok(Ok(()))
            ) && complete
        }
        .boxed()
        .shared();
        let mut state = self.handle.state_for_cleanup();
        // Only this consuming method can install close. The entry cannot have
        // been removed: no-start also consumes this same sole ticket, and drain
        // cannot finish an entry before its close exists. Recover a missing
        // entry as unknown rather than drop already-transferred raw/CPU custody.
        let job = state.jobs.entry(self.job).or_insert_with(|| BodyJob {
            unknown: true,
            ..BodyJob::default()
        });
        if !job.started {
            job.unknown = true;
        }
        job.close = Some(close.clone());
        self.armed = false; // custody belongs to the retained entry, not Drop
        drop(state);
        self.handle.changed.notify_waiters();
        let handle = self.handle.clone();
        let job = self.job;
        // Stored synchronously BEFORE the returned observer's first poll.
        // Invalid startup/poison retains and drives this same physical future,
        // but finish_job will refuse to remove its unknown witness.
        async move { handle.finish_job(job, close).await }.boxed()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Ordinary,
    Capture,
    Document,
}
static ORDINARY: Role = Role::Ordinary;
static CAPTURE: Role = Role::Capture;
static DOCUMENT: Role = Role::Document;
struct ConnectionContext {
    owner: Arc<ExecutionOwner>,
    role: Role,
    job: Option<uuid::Uuid>,
}
unsafe extern "C" fn destroy_context(pointer: *mut c_void) {
    // SAFETY: exactly one Box is transferred to SQLite clientdata. Its fields
    // have non-panicking destructors; no user callback runs here.
    unsafe {
        drop(Box::from_raw(pointer.cast::<ConnectionContext>()));
    }
}
unsafe fn equals(pointer: *const c_char, bytes: &[u8]) -> bool {
    !pointer.is_null() && unsafe { CStr::from_ptr(pointer) }.to_bytes() == bytes
}
unsafe extern "C" fn authorize(
    data: *mut c_void,
    action: i32,
    first: *const c_char,
    second: *const c_char,
    database: *const c_char,
    trigger: *const c_char,
) -> i32 {
    use libsqlite3_sys::*;
    // The only userdata values installed are these process-static policies.
    if data.is_null() {
        return SQLITE_DENY;
    }
    let role = unsafe { &*data.cast::<Role>() };
    let temp = unsafe { equals(database, b"temp") };
    let main = unsafe { equals(database, b"main") };
    let allowed = match action {
        SQLITE_SELECT | SQLITE_RECURSIVE => true,
        SQLITE_READ => !first.is_null() && (main || temp || database.is_null()),
        SQLITE_TRANSACTION | SQLITE_SAVEPOINT => !first.is_null(),
        SQLITE_INSERT | SQLITE_UPDATE | SQLITE_DELETE if temp => true,
        SQLITE_CREATE_TEMP_TABLE
        | SQLITE_DROP_TEMP_TABLE
        | SQLITE_CREATE_TEMP_VIEW
        | SQLITE_DROP_TEMP_VIEW
        | SQLITE_CREATE_TEMP_INDEX
        | SQLITE_DROP_TEMP_INDEX => temp,
        SQLITE_INSERT if main && *role == Role::Capture => unsafe {
            equals(first, b"read_log_calls")
                || equals(first, b"read_log_record_ids")
                || equals(first, b"read_log_touches")
        },
        SQLITE_INSERT | SQLITE_UPDATE | SQLITE_DELETE if main && *role == Role::Document => true,
        SQLITE_FUNCTION if unsafe { equals(second, b"hex") } => {
            // Authenticated read authorization encodes record IDs in its
            // recursive traversal path. Capture/content roles do not need it.
            *role == Role::Ordinary
        }
        SQLITE_FUNCTION if unsafe { equals(second, b"->") } => {
            // Only this installed content-event trigger requires the operator.
            // Direct expressions and every other role/context remain denied.
            *role == Role::Document
                && unsafe { equals(trigger, b"content_event_claim_meta_insert") }
        }
        SQLITE_FUNCTION
            if !second.is_null()
                && crate::query::sql_contract::PORTABLE_FUNCTIONS
                    .iter()
                    .any(|name| unsafe { equals(second, name.as_bytes()) }) =>
        {
            true
        }
        SQLITE_FUNCTION => unsafe {
            // Fixed engine scalar/aggregate functions, including installed FTS
            // trigger support. Extension loading and arbitrary functions deny.
            [
                b"abs".as_slice(),
                b"match",
                b"bm25",
                b"highlight",
                b"snippet",
                b"coalesce",
                b"char",
                b"date",
                b"datetime",
                b"glob",
                b"julianday",
                b"time",
                b"typeof",
                b"unicode",
                b"unixepoch",
                b"count",
                b"ifnull",
                b"instr",
                b"json",
                b"json_array",
                b"json_array_length",
                b"json_each",
                b"json_extract",
                b"json_group_array",
                b"json_group_object",
                b"json_set",
                b"json_remove",
                b"json_object",
                b"json_quote",
                b"json_type",
                b"json_valid",
                b"length",
                b"like",
                b"lower",
                b"max",
                b"min",
                b"nullif",
                b"printf",
                b"regexp",
                b"replace",
                b"round",
                b"strftime",
                b"substr",
                b"substring",
                b"sum",
                b"total",
                b"trim",
                b"upper",
            ]
            .iter()
            .any(|name| equals(second, name))
        },
        SQLITE_PRAGMA
            if unsafe {
                [
                    b"table_info".as_slice(),
                    b"table_xinfo",
                    b"table_list",
                    b"index_list",
                    b"index_info",
                    b"index_xinfo",
                    b"foreign_key_list",
                    b"quick_check",
                    b"integrity_check",
                ]
                .iter()
                .any(|name| equals(first, name))
            } =>
        {
            true
        }
        SQLITE_PRAGMA if second.is_null() => unsafe {
            [
                b"user_version".as_slice(),
                b"schema_version",
                b"foreign_keys",
                b"query_only",
                b"journal_mode",
                b"database_list",
                b"data_version",
                b"page_size",
            ]
            .iter()
            .any(|name| equals(first, name))
        },
        _ => false,
    };
    if allowed {
        SQLITE_OK
    } else {
        SQLITE_DENY
    }
}

/// Physically read-only connections need no owner/job context. Prevent ATTACH
/// from turning a read-only main into an alternate enrolled writable consumer.
pub(super) async fn install_read_guard(connection: &mut SqliteConnection) -> sqlx::Result<()> {
    {
        let mut locked = connection.lock_handle().await?;
        let rc = unsafe {
            libsqlite3_sys::sqlite3_set_authorizer(
                locked.as_raw_handle().as_ptr(),
                Some(authorize),
                (&ORDINARY as *const Role).cast_mut().cast(),
            )
        };
        if rc != libsqlite3_sys::SQLITE_OK {
            return Err(sqlx::Error::Protocol(format!(
                "enrolled readonly guard installation failed: {rc}"
            )));
        }
    }
    connection.clear_cached_statements().await
}

pub(super) async fn install(
    connection: &mut SqliteConnection,
    owner: Arc<ExecutionOwner>,
    role: Role,
    job: Option<uuid::Uuid>,
) -> sqlx::Result<()> {
    owner
        .check()
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    if role == Role::Document
        && (!owner.active_job.lock().is_ok_and(|active| *active == job) || job.is_none())
    {
        return Err(sqlx::Error::Protocol("enrolled job is not active".into()));
    }
    {
        let mut locked = connection.lock_handle().await?;
        let raw = locked.as_raw_handle().as_ptr();
        // SAFETY: locked handle excludes the worker; key is static NUL-terminated.
        if !unsafe { libsqlite3_sys::sqlite3_get_clientdata(raw, CONTEXT_KEY.as_ptr().cast()) }
            .is_null()
        {
            return Err(sqlx::Error::Protocol(
                "enrolled connection already has authority".into(),
            ));
        }
        let policy = match role {
            Role::Ordinary => &ORDINARY,
            Role::Capture => &CAPTURE,
            Role::Document => &DOCUMENT,
        };
        #[cfg(test)]
        let installation_owner = owner.clone();
        let context = Box::into_raw(Box::new(ConnectionContext { owner, role, job }));
        let rc = unsafe {
            libsqlite3_sys::sqlite3_set_clientdata(
                raw,
                CONTEXT_KEY.as_ptr().cast(),
                context.cast(),
                Some(destroy_context),
            )
        };
        // SQLite destroys context on OOM. Never free it again on failure.
        if rc != libsqlite3_sys::SQLITE_OK {
            return Err(sqlx::Error::Protocol(format!(
                "enrolled context registration failed: {rc}"
            )));
        }
        let rc = unsafe {
            libsqlite3_sys::sqlite3_set_authorizer(
                raw,
                Some(authorize),
                (policy as *const Role).cast_mut().cast(),
            )
        };
        if rc != libsqlite3_sys::SQLITE_OK {
            return Err(sqlx::Error::Protocol(format!(
                "enrolled guard installation failed: {rc}"
            )));
        }
        #[cfg(test)]
        if role == Role::Document {
            installation_owner
                .document_installations
                .fetch_add(1, Ordering::AcqRel);
        }
    }
    connection.clear_cached_statements().await
}

/// Inspect every attached physical file, not just main. Unknown/pending markers
/// refuse through custody discovery; an external connection cannot mint context.
pub(crate) async fn require_content_connection(
    connection: &mut SqliteConnection,
    db: Option<&Db>,
) -> Result<()> {
    let mut locked = connection.lock_handle().await?;
    let raw = locked.as_raw_handle().as_ptr();
    let mut main_owner = None;
    for index in 0.. {
        let name = unsafe { libsqlite3_sys::sqlite3_db_name(raw, index) };
        if name.is_null() {
            break;
        }
        let filename = unsafe { libsqlite3_sys::sqlite3_db_filename(raw, name) };
        if filename.is_null() {
            continue;
        }
        let bytes = unsafe { CStr::from_ptr(filename) }.to_bytes();
        if bytes.is_empty() {
            continue;
        }
        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::OsStrExt;
            Path::new(std::ffi::OsStr::from_bytes(bytes)).to_path_buf()
        };
        #[cfg(not(unix))]
        let path = std::path::PathBuf::from(
            std::str::from_utf8(bytes)
                .map_err(|_| Error::engine("SQLite filename is not representable"))?,
        );
        if let Some(owner) = crate::managed_custody::execution_for_filename(&path)? {
            if !unsafe { equals(name, b"main") } {
                return Err(Error::engine("enrolled attached databases are unsupported"));
            }
            main_owner = Some(owner);
        }
    }
    let context =
        unsafe { libsqlite3_sys::sqlite3_get_clientdata(raw, CONTEXT_KEY.as_ptr().cast()) };
    if let Some(owner) = main_owner {
        owner.check()?;
        if context.is_null() {
            return Err(Error::engine(
                "enrolled content connection has no job authority",
            ));
        }
        let context = unsafe { &*context.cast::<ConnectionContext>() };
        if context.role != Role::Document
            || context.job.is_none()
            || !owner
                .active_job
                .lock()
                .is_ok_and(|active| *active == context.job)
            || context.owner.generation != owner.generation
            || !Arc::ptr_eq(&owner, &context.owner)
            || db.is_some_and(|db| {
                !db.execution_owner
                    .as_ref()
                    .is_some_and(|expected| Arc::ptr_eq(expected, &owner))
            })
        {
            return Err(Error::engine(
                "enrolled content connection authority mismatch",
            ));
        }
    } else if !context.is_null() || db.is_some_and(|db| db.execution_owner.is_some()) {
        return Err(Error::engine(
            "enrolled content connection lost its physical generation",
        ));
    }
    Ok(())
}

tokio::task_local! { static JOB_COMMITTED: Arc<AtomicBool>; }
pub(super) fn note_committed() {
    let _ = JOB_COMMITTED.try_with(|committed| committed.store(true, Ordering::Release));
}

tokio::task_local! { static DOCUMENT_CONNECTION: Arc<Mutex<Option<sqlx::pool::PoolConnection<sqlx::Sqlite>>>>; }
pub(crate) async fn begin_document_write(
    db: &Db,
) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>> {
    if db.execution_owner.is_none() {
        return super::begin_write(db.write_pool()).await;
    }
    let slot = DOCUMENT_CONNECTION
        .try_with(Clone::clone)
        .map_err(|_| Error::engine("enrolled document update requires owned execution"))?;
    let connection = slot
        .lock()
        .map_err(|_| Error::engine("enrolled checkout slot poisoned"))?
        .take()
        .ok_or_else(|| Error::engine("enrolled job already began its transaction"))?;
    phase(Phase::BeforeBegin).await;
    let mut transaction =
        sqlx::Transaction::begin(connection, Some("BEGIN IMMEDIATE".into())).await?;
    phase(Phase::AfterBegin).await;
    crate::storage_profile::enforce_write_boundary(&mut transaction).await?;
    Ok(transaction)
}

/// Only the closed lifecycle operation can submit this future. Neither pool nor
/// abort handle leaves the task. The ticket is armed before physical creation.
pub(crate) async fn document_job<F>(db: Db, future: F) -> Result<serde_json::Value>
where
    F: Future<Output = Result<serde_json::Value>> + Send + 'static,
{
    owned_job(db, future).await
}

/// Closed session commands share exactly the ordinary writer's retained runner.
pub(crate) async fn session_job(
    db: Db,
    command: crate::coedit::driver::AdmittedCommand,
) -> Result<crate::coedit::driver::Reply> {
    let job_db = db.clone();
    let future = Box::pin(crate::coedit::driver::execute(job_db, command));
    owned_job(db, future).await
}

// Neither checkout nor an arbitrary SQL submitter is exported by the driver.
async fn owned_job<F, T>(db: Db, future: F) -> Result<T>
where
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let owner = db
        .execution_owner
        .clone()
        .ok_or_else(|| Error::engine("missing enrolled owner"))?;
    let storage = crate::storage_profile::current_admission()?;
    let provenance = crate::provenance::current_dispatch()
        .ok_or_else(|| Error::engine("enrolled update has no resolved provenance dispatch"))?;
    let annotations = crate::store::current_event_annotations();
    let deployment = crate::mcp::deployment_read_only::current_job_lease();
    let (result_tx, result_rx) = oneshot::channel();
    {
        let mut entries = owner
            .retained
            .lock()
            .map_err(|_| Error::engine("enrolled quarantine state poisoned"))?;
        if entries.len() >= JOB_CAPACITY {
            return Err(Error::engine(
                "enrolled retained job capacity exhausted; request not accepted",
            ));
        }
        let ticket = db.execution_jobs.register(&owner)?;
        #[cfg(test)]
        let test_gate = TEST_GATE.try_with(Clone::clone).ok();
        let context = JobContext {
            owner: owner.clone(),
            storage,
            provenance,
            annotations,
            deployment,
            #[cfg(test)]
            test_gate,
            #[cfg(test)]
            session_fault: crate::coedit::driver::TEST_FAULT
                .try_with(|fault| *fault)
                .ok(),
            #[cfg(test)]
            cleanup_limit: TEST_CLEANUP_LIMIT
                .try_with(|limit| *limit)
                .unwrap_or(CLEANUP_LIMIT),
            #[cfg(test)]
            fail_cache: TEST_CACHE_FAILURE
                .try_with(|failure| *failure)
                .unwrap_or(false),
        };
        // Store admissions and the whole owned runner before spawning. Task abort,
        // including before its first poll, cannot destroy physical work or leases.
        let job = ticket.job;
        let retained = Arc::new(RetainedJob {
            future: Mutex::new(None),
            admissions: Mutex::new(Some(RetainedAdmissions {
                _storage: context.storage.clone(),
                _deployment: context.deployment.clone(),
            })),
            running: AtomicBool::new(false),
            #[cfg(test)]
            abort: Mutex::new(None),
        });
        let retained_runner = retained.clone();
        *retained.future.lock().expect("new retained slot") = Some(Box::pin(
            supervise_document_job(context, db, ticket, future, result_tx, retained_runner),
        ));
        entries.insert(job, retained.clone());
        drop(entries);
        spawn_retained(owner, job, retained);
    }
    result_rx
        .await
        .map_err(|_| Error::engine("enrolled execution task lost; owner poisoned"))?
}

// A retained future is polled in-place; timeout/abort never takes or drops it.
// Poisoned completed failures retain admissions forever. Removal requires
// original writer close ACK and read-only replacement pool housekeeping;
// pool.close() is not a physical-close acknowledgement.
struct RetainedAdmissions {
    _storage: crate::storage_profile::OperationAdmission,
    _deployment: Option<crate::mcp::DeploymentPersistenceLease>,
}
struct RetainedJob {
    future: Mutex<Option<std::pin::Pin<Box<dyn Future<Output = ()> + Send>>>>,
    admissions: Mutex<Option<RetainedAdmissions>>,
    running: AtomicBool,
    #[cfg(test)]
    abort: Mutex<Option<tokio::task::AbortHandle>>,
}
impl std::fmt::Debug for RetainedJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedJob")
            .field("running", &self.running.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}
struct PollerLifetime {
    owner: Arc<ExecutionOwner>,
    job: uuid::Uuid,
    retained: Arc<RetainedJob>,
    completed: bool,
}
impl Drop for PollerLifetime {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.poison();
        }
        self.retained.running.store(false, Ordering::Release);
    }
}
fn spawn_retained(owner: Arc<ExecutionOwner>, job: uuid::Uuid, retained: Arc<RetainedJob>) {
    if retained
        .running
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    // Construct outside async: dropping an unpolled spawn poisons and leaves the
    // retained future/admissions available to the next explicit drain attempt.
    let lifetime = PollerLifetime {
        owner,
        job,
        retained: retained.clone(),
        completed: false,
    };
    let task = tokio::spawn(async move {
        let mut lifetime = lifetime;
        futures::future::poll_fn(|cx| {
            let mut slot = lifetime
                .retained
                .future
                .lock()
                .expect("retained runner state poisoned");
            match slot.as_mut() {
                Some(future) => future.as_mut().poll(cx),
                None => std::task::Poll::Ready(()),
            }
        })
        .await;
        lifetime.completed = true;
        // Physical cleanup decides whether admissions can be released. Errors
        // with no ACK leave the bounded entry in process custody even if done.
        if lifetime
            .retained
            .admissions
            .lock()
            .is_ok_and(|slot| slot.is_none())
        {
            if let Ok(mut jobs) = lifetime.owner.retained.lock() {
                jobs.remove(&lifetime.job);
            }
        }
        if let Ok(mut future) = lifetime.retained.future.lock() {
            future.take();
        };
    });
    #[cfg(test)]
    {
        *retained.abort.lock().unwrap() = Some(task.abort_handle());
    }
    #[cfg(not(test))]
    drop(task);
}
impl ExecutionOwner {
    fn resume_retained(self: &Arc<Self>) {
        let jobs = match self.retained.lock() {
            Ok(jobs) => jobs
                .iter()
                .map(|(id, entry)| (*id, entry.clone()))
                .collect::<Vec<_>>(),
            Err(_) => {
                self.poison();
                return;
            }
        };
        for (job, entry) in jobs {
            if entry.future.lock().is_ok_and(|future| future.is_some()) {
                spawn_retained(self.clone(), job, entry);
            }
        }
    }
}

struct JobContext {
    owner: Arc<ExecutionOwner>,
    storage: crate::storage_profile::OperationAdmission,
    provenance: crate::provenance::ProvenanceDispatch,
    annotations: crate::store::EventAnnotations,
    deployment: Option<crate::mcp::DeploymentPersistenceLease>,
    #[cfg(test)]
    test_gate: Option<Arc<TestGate>>,
    #[cfg(test)]
    session_fault: Option<crate::coedit::driver::TestFault>,
    #[cfg(test)]
    cleanup_limit: Duration,
    #[cfg(test)]
    fail_cache: bool,
}

async fn supervise_document_job<F, T>(
    context: JobContext,
    db: Db,
    mut ticket: Ticket,
    future: F,
    result_tx: oneshot::Sender<Result<T>>,
    retained: Arc<RetainedJob>,
) where
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let JobContext {
        owner,
        storage,
        provenance,
        annotations,
        deployment,
        #[cfg(test)]
        test_gate,
        #[cfg(test)]
        session_fault,
        #[cfg(test)]
        cleanup_limit,
        #[cfg(test)]
        fail_cache,
    } = context;
    #[cfg(not(test))]
    let cleanup_limit = CLEANUP_LIMIT;
    let _deployment = deployment;
    let mut result_tx = Some(result_tx);
    let _storage = storage.clone();
    #[cfg(test)]
    if let Some(gate) = &test_gate {
        TEST_GATE
            .scope(gate.clone(), phase(Phase::BeforeLane))
            .await;
    }
    let mut lane = LaneLease {
        _guard: owner.lane.lock().await,
        owner: &owner,
        armed: true,
    };
    let result = async {
            #[cfg(test)]
            if let Some(gate) = &test_gate { TEST_GATE.scope(gate.clone(), phase(Phase::BeforeSetup)).await; }
            owner.check()?;
            *owner.active_job.lock().map_err(|_| Error::engine("enrolled active job state poisoned"))? = Some(ticket.job);
            let sacrificial = tokio::time::timeout(CLEANUP_LIMIT, SqliteConnection::connect_with(&super::enrolled_immutable_options(&owner.path)?.optimize_on_close(false, None))).await.map_err(|_| Error::engine("enrolled readonly setup timed out; owner poisoned"))??;
            let (cleanup_tx, cleanup_rx) = oneshot::channel();
            let transfer = Arc::new(Mutex::new(Some((sacrificial, cleanup_tx))));
            let after_owner = owner.clone();
            let job = ticket.job;
            let pool = SqlitePoolOptions::new().max_connections(1).min_connections(0).idle_timeout(None).max_lifetime(None).test_before_acquire(false)
                .after_connect(move |connection, _| {
                    let owner = after_owner.clone();
                    Box::pin(async move {
                        // Any install/cache failure can bypass after_release and
                        // trigger SQLx retry: poison before it can grant authority again.
                        match tokio::time::timeout(CLEANUP_LIMIT, async {
                            install(connection, owner.clone(), Role::Document, Some(job)).await?;
                            #[cfg(test)]
                            if fail_cache { return Err(sqlx::Error::Protocol("test cache-clear failure after permanent installation".into())); }
                            Ok(())
                        }).await {
                            Ok(Ok(())) => Ok(()),
                            Ok(Err(error)) => { owner.poison(); Err(error) }
                            Err(_) => { owner.poison(); Err(sqlx::Error::Protocol("enrolled guard/cache setup timed out".into())) }
                        }
                    })
                })
                .after_release(move |connection, _| {
                    // Movement happens synchronously, before constructing a future.
                    if let Ok(mut slot) = transfer.lock() {
                        if let Some((replacement, sender)) = slot.take() {
                            let original = std::mem::replace(connection, replacement);
                            if let Err(original) = sender.send(original) { drop(original); }
                        }
                    }
                    Box::pin(async { Ok(false) })
                })
                .connect_lazy_with(super::enrolled_connect_options(&owner.path)?.optimize_on_close(false, None));
            let checkout = Arc::new(Mutex::new(Some(pool.acquire().await?)));
            let committed = Arc::new(AtomicBool::new(false));
            let execution = JOB_COMMITTED.scope(committed.clone(), future);
            #[cfg(test)]
            let execution_gate = test_gate.clone();
            #[cfg(test)]
            let execution = async move { match execution_gate { Some(gate) => TEST_GATE.scope(gate, execution).await, None => execution.await } };
            #[cfg(test)]
            let execution = async move { match session_fault {
                Some(fault) => crate::coedit::driver::TEST_FAULT.scope(fault, execution).await,
                None => execution.await,
            } };
            let operation = AssertUnwindSafe(storage.scope(provenance.scope(crate::store::with_event_annotations(annotations, db.with_request_realtime_completion(DOCUMENT_CONNECTION.scope(checkout.clone(), execution)))))).catch_unwind().await;
            #[cfg(test)]
            if let Some(gate) = &test_gate {
                let error = match &operation {
                    Ok(Err(error)) => Some(error.to_string().chars().take(512).collect::<String>()),
                    Err(_) => Some("operation panicked".to_owned()),
                    Ok(Ok(_)) => None,
                };
                *gate.outcome.lock().expect("test outcome lock") = Some((committed.load(Ordering::Acquire), error));
            }
            // Pre-BEGIN parse/refusal paths still return the one checkout.
            drop(checkout.lock().map_err(|_| Error::engine("enrolled checkout slot poisoned"))?.take());
            let cleanup = async {
                let original = cleanup_rx.await.map_err(|_| Error::engine("enrolled connection recovery was lost"))?;
                #[cfg(test)]
                if let Some(gate) = &test_gate { TEST_GATE.scope(gate.clone(), phase(Phase::BeforeClose)).await; }
                let closed = original.close().await.map_err(Error::from);
                #[cfg(test)]
                if closed.is_ok() {
                    if let Some(gate) = &test_gate { gate.writer_close_ack.store(true, Ordering::Release); }
                }
                closed
            };
            tokio::pin!(cleanup);
            let closed = match tokio::time::timeout(cleanup_limit, cleanup.as_mut()).await {
                Ok(result) => result,
                Err(_) => {
                    owner.poison();
                    if let Some(sender) = result_tx.take() {
                        let _ = sender.send(Err(Error::engine(if committed.load(Ordering::Acquire) { "enrolled transaction committed but cleanup timed out; admissions quarantined; do not retry" } else { "enrolled cleanup timed out; admissions quarantined; outcome uncertain, do not retry" })));
                    }
                    // Continue polling the SAME close/recovery future. Runtime
                    // loss retains it and both admissions in the owner entry.
                    cleanup.as_mut().await
                }
            };
            match closed {
                Ok(()) => {
                    // Original closure is acknowledged; only the read-only
                    // replacement remains subject to SQLx pool housekeeping.
                    let replacement_cleanup = pool.close();
                    tokio::pin!(replacement_cleanup);
                    if tokio::time::timeout(CLEANUP_LIMIT, replacement_cleanup.as_mut()).await.is_err() {
                        owner.poison();
                        if let Some(sender) = result_tx.take() { let _ = sender.send(Err(Error::engine("enrolled replacement cleanup timed out; admissions quarantined; do not retry"))); }
                        replacement_cleanup.as_mut().await;
                    }
                    retained.admissions.lock().map_err(|_| Error::engine("enrolled quarantine admissions poisoned"))?.take();
                    if owner.check().is_err() { return Err(Error::engine(if committed.load(Ordering::Acquire) { "enrolled transaction committed but owner poisoned; do not retry the mutation" } else { "enrolled owner poisoned during execution; restart and reconcile required" })); }
                    if operation.is_ok() { ticket.armed = false; lane.armed = false; }
                }
                _ => return Err(Error::engine(if committed.load(Ordering::Acquire) { "enrolled transaction committed but cleanup unacknowledged; owner poisoned; do not retry the mutation" } else { "enrolled cleanup unacknowledged; owner poisoned; outcome uncertain, do not blindly retry" })),
            }
            match operation {
                Ok(Err(error)) if committed.load(Ordering::Acquire) => Err(Error::engine(format!("enrolled transaction committed but response failed; do not retry the mutation: {error}"))),
                Ok(result) => result,
                Err(_) => Err(Error::engine(if committed.load(Ordering::Acquire) { "enrolled transaction committed but completion panicked; owner poisoned; do not retry the mutation" } else { "enrolled update panicked; owner poisoned" })),
            }
        }.await;
    // Ticket stays armed for setup failures, panic and unknown cleanup.
    drop(ticket);
    drop(lane);
    drop(_storage);
    drop(storage);
    drop(_deployment);
    if let Some(sender) = result_tx {
        let _ = sender.send(result);
    }
}

#[cfg(test)]
tokio::task_local! { static TEST_CLEANUP_LIMIT: Duration; static TEST_CACHE_FAILURE: bool; }

/// Closed enrolled operation grammar; context fields are stripped by request
/// dispatch but included here because admission also runs before that stage.
pub(crate) fn admit_body_arguments(arguments: &serde_json::Value) -> Result<()> {
    let object = arguments
        .as_object()
        .ok_or_else(|| Error::engine("update_record arguments must be an object"))?;
    let allowed = [
        "id",
        "record_id",
        "body",
        "body_set",
        "body_append",
        "body_replace",
        "reason",
        "sources",
        "if_body_digest",
        "if_unmodified_since",
        "response_mode",
        "format",
        "run_key",
        "parent_key",
        "agent_key",
    ];
    let count = ["body", "body_set", "body_append", "body_replace"]
        .iter()
        .filter(|key| object.contains_key(**key))
        .count();
    if count != 1 || object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(Error::engine(
            "enrolled update_record accepts exactly one body operation and its guards, reason, sources and response options",
        ));
    }
    Ok(())
}

/// Phase probes are test-owned only; production has no wait or ordering hook.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    #[cfg(test)]
    BeforeLane,
    #[cfg(test)]
    BeforeSetup,
    BeforeBegin,
    AfterBegin,
    AfterAppend,
    BeforeCommit,
    AfterCommit,
    BeforeRollback,
    #[cfg(test)]
    BeforeClose,
}
pub(crate) async fn phase(_phase: Phase) {
    #[cfg(test)]
    if let Ok(gate) = TEST_GATE.try_with(Clone::clone) {
        if gate.phase == _phase {
            if let Some(sender) = gate.entered.lock().expect("test gate poisoned").take() {
                let _ = sender.send(());
            }
            gate.release
                .acquire()
                .await
                .expect("test gate closed")
                .forget();
        }
    }
}
#[cfg(test)]
pub(crate) struct TestGate {
    pub(crate) phase: Phase,
    pub(crate) entered: Mutex<Option<oneshot::Sender<()>>>,
    pub(crate) release: tokio::sync::Semaphore,
    // Actual operation result and commit witness, never inferred from gate entry.
    pub(crate) outcome: Mutex<Option<(bool, Option<String>)>>,
    // Set only after the original writer's explicit close returns success.
    pub(crate) writer_close_ack: AtomicBool,
}
#[cfg(test)]
tokio::task_local! { pub(crate) static TEST_GATE: Arc<TestGate>; }

#[cfg(all(test, unix))]
mod tests;
