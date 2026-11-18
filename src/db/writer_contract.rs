//! The writer-connection contract for stored-visibility marking (design
//! 73ad275 rev 2.1, M4).
//!
//! Marking triggers live in the main schema, so they fire for every write to a
//! main input table on any connection whose triggers are enabled. Two
//! connection-local conditions can still defeat them, and both also make a
//! save untruthful:
//!
//! * **Triggers disabled** (`SQLITE_DBCONFIG_ENABLE_TRIGGER` off). The only
//!   code that turns them off is registered and invalidates explicitly (M6).
//! * **A TEMP shadow.** An unqualified write to a name that also exists as a
//!   TEMP table lands in `temp`, not `main`. The canonical row never changes,
//!   nothing is marked, and the caller would report a save that did not
//!   happen. A TEMP `BEFORE` trigger on a main input can do the same with
//!   `RAISE(IGNORE)`, which silently skips the row.
//!
//! The contract holds for the whole writer lease:
//!
//! 1. **No protected TEMP object can be created on a writer connection.** An
//!    authorizer installed at connect time refuses, at prepare time:
//!    - `CREATE TEMP TABLE` named after a protected relation (rowid or
//!      `WITHOUT ROWID`);
//!    - `CREATE TEMP VIEW` named with the accelerator prefix;
//!    - any TEMP trigger on, or named after, a protected relation;
//!    - `ALTER TABLE` in `temp` (a rename could otherwise produce a shadow).
//!
//!    TEMP *views* named after inputs stay allowed: the governed SQL surface
//!    installs them (`content_events`, …), and writing through a view without
//!    an `INSTEAD OF` trigger, which the trigger rule refuses, fails loudly.
//!    SQLite holds one authorizer per connection, so the enrolled-storage
//!    policy composes through [`set_authorizer`]: the contract decides first
//!    and delegates everything else to it.
//! 2. **Checkout.** Every acquisition from a workspace writer pool (and from
//!    the governed SQL pool) checks that triggers are enabled and that
//!    `temp.sqlite_schema` holds no protected shadow, and re-installs the
//!    hooks. A connection that fails is discarded, never
//!    cleaned in place, and the pool hands out another; a freshly opened
//!    connection is clean by construction. The write itself is never refused
//!    for this reason.
//! 3. **Defence in depth.** An update hook flags any row written to a
//!    protected name in `temp`, and a commit hook converts the commit of a
//!    flagged connection into a rollback; the release hook then discards the
//!    connection.
//!
//! None of these hooks runs SQL, allocates or takes a lock. `data_version`
//! would not see any of this, because TEMP changes are connection-local.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use sqlx::SqliteConnection;

/// Every table the stored visibility and readiness state is derived from
/// (design §2.1): the 15 kernel input tables plus `content_events`. The
/// marking triggers cover exactly this set, which a test pins.
pub(crate) const MARKED_INPUT_TABLES: [&str; 16] = [
    "kernel_records",
    "kernel_roots",
    "kernel_policies",
    "kernel_policy_entries",
    "kernel_principals",
    "kernel_generic_links",
    "kernel_import_tombstones",
    "kernel_record_fields",
    "kernel_messages",
    "kernel_facets",
    "kernel_record_metadata",
    "kernel_lifecycle",
    "kernel_legacy_sql_events",
    "kernel_app_installs",
    "kernel_record_bodies",
    "content_events",
];

/// Stored accelerator objects (`p_dirty`, `p_state`, …) are all named with
/// this prefix. A TEMP object with the prefix would shadow them for readers.
pub(crate) const ACCELERATOR_PREFIX: &str = "p_";

/// Whether `name` is protected from TEMP shadowing on a writer connection.
/// SQLite identifiers are case-insensitive.
pub(crate) fn is_protected_name(name: &[u8]) -> bool {
    let prefix = ACCELERATOR_PREFIX.as_bytes();
    (name.len() > prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(prefix))
        || MARKED_INPUT_TABLES
            .iter()
            .any(|table| table.as_bytes().eq_ignore_ascii_case(name))
}

/// Connection-owned lease state. SQLite owns the allocation through its
/// client-data slot and frees it when the connection closes, so the hook
/// pointers can never outlive it.
struct LeaseState {
    /// A row was written to a protected name in `temp`. Sticky until the
    /// connection is discarded.
    captured: AtomicBool,
    /// The authorizer composed behind the contract (enrolled storage), as
    /// `(callback, user data)` addresses; 0 when none. Written only under the
    /// locked handle, read by the callback on the same connection.
    inner_callback: AtomicUsize,
    inner_data: AtomicUsize,
    /// Test-only proof that the regressions fail without the guard.
    #[cfg(test)]
    bypass: AtomicBool,
}

/// SQLite's authorizer callback signature.
pub(crate) type AuthorizerCallback = unsafe extern "C" fn(
    *mut c_void,
    c_int,
    *const c_char,
    *const c_char,
    *const c_char,
    *const c_char,
) -> c_int;

fn is_accelerator_name(name: &[u8]) -> bool {
    let prefix = ACCELERATOR_PREFIX.as_bytes();
    name.len() > prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// SAFETY: `pointer` is NULL or a NUL-terminated string live for the call.
unsafe fn bytes<'a>(pointer: *const c_char) -> Option<&'a [u8]> {
    (!pointer.is_null()).then(|| unsafe { CStr::from_ptr(pointer) }.to_bytes())
}

/// The lease-wide refusal (rule 1 in the module documentation).
fn refuses(
    action: c_int,
    first: Option<&[u8]>,
    second: Option<&[u8]>,
    database: Option<&[u8]>,
) -> bool {
    use libsqlite3_sys::*;
    let protected = |name: Option<&[u8]>| name.is_some_and(is_protected_name);
    // `CREATE TABLE temp.x` arrives as the plain action with database `temp`.
    let temp = database.is_some_and(|d| d.eq_ignore_ascii_case(b"temp"));
    match action {
        SQLITE_CREATE_TEMP_TABLE => protected(first),
        SQLITE_CREATE_TABLE => temp && protected(first),
        SQLITE_CREATE_TEMP_VIEW => first.is_some_and(is_accelerator_name),
        SQLITE_CREATE_VIEW => temp && first.is_some_and(is_accelerator_name),
        SQLITE_CREATE_TEMP_TRIGGER => protected(first) || protected(second),
        SQLITE_CREATE_TRIGGER => temp && (protected(first) || protected(second)),
        // The first argument is the database name.
        SQLITE_ALTER_TABLE => first.is_some_and(|d| d.eq_ignore_ascii_case(b"temp")),
        _ => false,
    }
}

unsafe extern "C" fn guard(
    data: *mut c_void,
    action: c_int,
    first: *const c_char,
    second: *const c_char,
    database: *const c_char,
    trigger: *const c_char,
) -> c_int {
    if data.is_null() {
        return libsqlite3_sys::SQLITE_DENY;
    }
    // SAFETY: the live client-data allocation; atomics only.
    let state = unsafe { &*data.cast::<LeaseState>() };
    #[cfg(test)]
    let bypass = state.bypass.load(Ordering::Relaxed);
    #[cfg(not(test))]
    let bypass = false;
    // SAFETY: SQLite passes NUL-terminated strings live for the call.
    if !bypass
        && refuses(
            action,
            unsafe { bytes(first) },
            unsafe { bytes(second) },
            unsafe { bytes(database) },
        )
    {
        REFUSED_SHADOWS.fetch_add(1, Ordering::Relaxed);
        return libsqlite3_sys::SQLITE_DENY;
    }
    let callback = state.inner_callback.load(Ordering::Relaxed);
    if callback == 0 {
        return libsqlite3_sys::SQLITE_OK;
    }
    // SAFETY: stored by `set_authorizer` from a valid callback; the user data
    // was supplied with it and outlives the connection (static policies).
    let callback: AuthorizerCallback = unsafe { std::mem::transmute(callback) };
    unsafe {
        callback(
            state.inner_data.load(Ordering::Relaxed) as *mut c_void,
            action,
            first,
            second,
            database,
            trigger,
        )
    }
}

/// Install an authorizer on `raw`. On a writer connection carrying the
/// contract, the contract's guard stays installed and `callback` is composed
/// behind it; on any other connection this is `sqlite3_set_authorizer`.
///
/// # Safety
/// `raw` must be a live, exclusively locked handle, and `data` must outlive
/// the connection.
pub(crate) unsafe fn set_authorizer(
    raw: *mut libsqlite3_sys::sqlite3,
    callback: Option<AuthorizerCallback>,
    data: *mut c_void,
) -> c_int {
    let state = state_on(raw);
    if state.is_null() {
        // SAFETY: per this function's contract.
        return unsafe { libsqlite3_sys::sqlite3_set_authorizer(raw, callback, data) };
    }
    // SAFETY: live client-data allocation.
    let lease = unsafe { &*state };
    lease
        .inner_callback
        .store(callback.map_or(0, |c| c as usize), Ordering::Relaxed);
    lease.inner_data.store(data as usize, Ordering::Relaxed);
    // SAFETY: per this function's contract; `state` lives as long as `raw`.
    unsafe { libsqlite3_sys::sqlite3_set_authorizer(raw, Some(guard), state.cast()) }
}

const CLIENT_DATA_KEY: &CStr = c"native.writer_contract";

/// Checkouts refused since process start (diagnostic only; payload-free).
static REFUSED_CHECKOUTS: AtomicU64 = AtomicU64::new(0);
/// Protected TEMP objects refused at prepare time.
static REFUSED_SHADOWS: AtomicU64 = AtomicU64::new(0);
/// Commits vetoed because a write landed in a TEMP shadow.
static VETOED_COMMITS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
pub(crate) fn refused_checkouts() -> u64 {
    REFUSED_CHECKOUTS.load(Ordering::Relaxed)
}

#[cfg(test)]
pub(crate) fn vetoed_commits() -> u64 {
    VETOED_COMMITS.load(Ordering::Relaxed)
}

unsafe extern "C" fn destroy_state(state: *mut c_void) {
    if !state.is_null() {
        // SAFETY: allocated by `Box::into_raw` in `install` and handed to
        // SQLite exactly once; SQLite calls this destructor exactly once.
        drop(unsafe { Box::from_raw(state.cast::<LeaseState>()) });
    }
}

unsafe extern "C" fn update_hook(
    state: *mut c_void,
    _operation: c_int,
    database: *const c_char,
    table: *const c_char,
    _rowid: i64,
) {
    if state.is_null() || database.is_null() || table.is_null() {
        return;
    }
    // SAFETY: SQLite passes NUL-terminated names that live for the callback.
    let database = unsafe { CStr::from_ptr(database) }.to_bytes();
    if !database.eq_ignore_ascii_case(b"temp") {
        return;
    }
    // SAFETY: as above.
    let table = unsafe { CStr::from_ptr(table) }.to_bytes();
    if is_protected_name(table) {
        // SAFETY: the pointer is the live client-data allocation (see
        // `LeaseState`); only atomics are touched.
        unsafe { &*state.cast::<LeaseState>() }
            .captured
            .store(true, Ordering::Release);
    }
}

unsafe extern "C" fn commit_hook(state: *mut c_void) -> c_int {
    if state.is_null() {
        return 0;
    }
    // SAFETY: the live client-data allocation; atomics only.
    if unsafe { &*state.cast::<LeaseState>() }
        .captured
        .load(Ordering::Acquire)
    {
        VETOED_COMMITS.fetch_add(1, Ordering::Relaxed);
        // Non-zero converts this COMMIT into a ROLLBACK.
        return 1;
    }
    0
}

fn state_on(raw: *mut libsqlite3_sys::sqlite3) -> *mut LeaseState {
    // SAFETY: `raw` is a live, exclusively locked handle; the key is static.
    unsafe { libsqlite3_sys::sqlite3_get_clientdata(raw, CLIENT_DATA_KEY.as_ptr()) }
        .cast::<LeaseState>()
}

/// Register the lease hooks on `raw`, creating the connection's state on
/// first use. Re-registering is idempotent and restores hooks that other
/// code (a test probe) may have replaced during an earlier lease.
fn register(raw: *mut libsqlite3_sys::sqlite3, authorizer: bool) -> sqlx::Result<()> {
    let mut state = state_on(raw);
    if state.is_null() {
        let fresh = Box::into_raw(Box::new(LeaseState {
            captured: AtomicBool::new(false),
            inner_callback: AtomicUsize::new(0),
            inner_data: AtomicUsize::new(0),
            #[cfg(test)]
            bypass: AtomicBool::new(false),
        }));
        // SAFETY: live locked handle; on failure SQLite has already invoked
        // the destructor, so the allocation must not be freed again.
        let rc = unsafe {
            libsqlite3_sys::sqlite3_set_clientdata(
                raw,
                CLIENT_DATA_KEY.as_ptr(),
                fresh.cast(),
                Some(destroy_state),
            )
        };
        if rc != libsqlite3_sys::SQLITE_OK {
            return Err(sqlx::Error::Protocol(format!(
                "writer contract state registration failed: {rc}"
            )));
        }
        state = fresh;
    }
    // SAFETY: live locked handle; `state` stays valid until the connection
    // closes, which also discards these hooks.
    unsafe {
        libsqlite3_sys::sqlite3_update_hook(raw, Some(update_hook), state.cast());
        libsqlite3_sys::sqlite3_commit_hook(raw, Some(commit_hook), state.cast());
        // Installed once per connection: `sqlite3_set_authorizer` expires
        // every prepared statement, so re-installing per checkout would cost
        // a re-prepare on each write. Every writer-connection authorizer
        // goes through `set_authorizer`, which keeps the guard in front.
        if authorizer
            && libsqlite3_sys::sqlite3_set_authorizer(raw, Some(guard), state.cast())
                != libsqlite3_sys::SQLITE_OK
        {
            return Err(sqlx::Error::Protocol(
                "writer contract authorizer installation failed".into(),
            ));
        }
    }
    Ok(())
}

/// Test-only: run without the lease guard, to prove a regression fails.
#[cfg(test)]
pub(crate) async fn bypass_guard_for_test(connection: &mut SqliteConnection, bypass: bool) {
    let mut handle = connection.lock_handle().await.unwrap();
    let state = state_on(handle.as_raw_handle().as_ptr());
    assert!(!state.is_null(), "not a writer-contract connection");
    // SAFETY: live client-data allocation; atomics only.
    unsafe { &*state }.bypass.store(bypass, Ordering::Relaxed);
}

/// Install the lease hooks on a newly opened writer connection.
pub(crate) async fn install(connection: &mut SqliteConnection) -> sqlx::Result<()> {
    let mut handle = connection.lock_handle().await?;
    register(handle.as_raw_handle().as_ptr(), true)
}

/// Whether triggers are enabled on `raw`.
fn triggers_enabled(raw: *mut libsqlite3_sys::sqlite3) -> bool {
    let mut enabled: c_int = 0;
    // SAFETY: live locked handle; -1 queries without changing the setting.
    let rc = unsafe {
        libsqlite3_sys::sqlite3_db_config(
            raw,
            libsqlite3_sys::SQLITE_DBCONFIG_ENABLE_TRIGGER,
            -1 as c_int,
            &mut enabled as *mut c_int,
        )
    };
    rc == libsqlite3_sys::SQLITE_OK && enabled != 0
}

/// The TEMP-shadow probe. One indexed read of the connection-local schema,
/// which is empty on an ordinary writer.
fn shadow_probe_sql() -> &'static str {
    static SQL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SQL.get_or_init(|| {
        let names = MARKED_INPUT_TABLES
            .iter()
            .map(|name| format!("'{name}'"))
            .collect::<Vec<_>>()
            .join(",");
        // GLOB is case-sensitive, so compare the lowered name. `_` is a
        // literal in GLOB patterns.
        format!(
            "SELECT EXISTS(SELECT 1 FROM temp.sqlite_schema \
              WHERE lower(name) IN ({names}) OR lower(name) GLOB '{prefix}?*' \
                 OR (type='trigger' AND (lower(tbl_name) IN ({names}) OR lower(tbl_name) GLOB '{prefix}?*')))",
            prefix = ACCELERATOR_PREFIX
        )
    })
}

/// Why a connection was refused at checkout. Payload-free by construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Violation {
    TriggersDisabled,
    TempShadow,
    Captured,
    ProbeFailed,
}

impl Violation {
    fn label(self) -> &'static str {
        match self {
            Violation::TriggersDisabled => "triggers_disabled",
            Violation::TempShadow => "temp_shadow",
            Violation::Captured => "captured_write",
            Violation::ProbeFailed => "probe_failed",
        }
    }
}

/// The checkout check: `None` when the connection satisfies the contract.
pub(crate) async fn violation_on(connection: &mut SqliteConnection) -> Option<Violation> {
    {
        let Ok(mut handle) = connection.lock_handle().await else {
            return Some(Violation::ProbeFailed);
        };
        let raw = handle.as_raw_handle().as_ptr();
        if !triggers_enabled(raw) {
            return Some(Violation::TriggersDisabled);
        }
        let state = state_on(raw);
        // SAFETY: live client-data allocation; atomics only.
        if !state.is_null() && unsafe { &*state }.captured.load(Ordering::Acquire) {
            return Some(Violation::Captured);
        }
        if register(raw, false).is_err() {
            return Some(Violation::ProbeFailed);
        }
    }
    match sqlx::query_scalar::<_, bool>(shadow_probe_sql())
        .fetch_one(&mut *connection)
        .await
    {
        Ok(false) => None,
        Ok(true) => Some(Violation::TempShadow),
        Err(_) => Some(Violation::ProbeFailed),
    }
}

/// `before_acquire` half of the contract: `false` discards the connection
/// and lets the pool hand out (or open) another one.
pub(crate) async fn admit_checkout(connection: &mut SqliteConnection) -> bool {
    match violation_on(connection).await {
        None => true,
        Some(violation) => {
            REFUSED_CHECKOUTS.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                diagnostic = "writer_contract_refused_checkout",
                reason = violation.label(),
                "writer connection discarded at checkout; the pool reacquires a clean one"
            );
            false
        }
    }
}

/// `after_release` half: a connection that ever captured a protected write
/// in `temp` never returns to the pool.
pub(crate) async fn reusable_after_release(connection: &mut SqliteConnection) -> bool {
    let Ok(mut handle) = connection.lock_handle().await else {
        return false;
    };
    let state = state_on(handle.as_raw_handle().as_ptr());
    // SAFETY: live client-data allocation; atomics only.
    state.is_null() || !unsafe { &*state }.captured.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    #[test]
    fn protected_names_cover_inputs_and_accelerators_case_insensitively() {
        for name in MARKED_INPUT_TABLES {
            assert!(is_protected_name(name.as_bytes()), "{name}");
            assert!(is_protected_name(name.to_uppercase().as_bytes()), "{name}");
        }
        for name in ["p_dirty", "P_STATE", "p_home_anchor"] {
            assert!(is_protected_name(name.as_bytes()), "{name}");
        }
        for name in [
            "p_",
            "records",
            "_query_sql_principal",
            "kernel_records_x",
            "pdirty",
        ] {
            assert!(!is_protected_name(name.as_bytes()), "{name}");
        }
    }

    async fn connection() -> SqliteConnection {
        let mut c = SqliteConnection::connect("sqlite::memory:").await.unwrap();
        sqlx::query("CREATE TABLE main.kernel_records(id TEXT PRIMARY KEY, v INTEGER)")
            .execute(&mut c)
            .await
            .unwrap();
        install(&mut c).await.unwrap();
        c
    }

    #[tokio::test]
    async fn clean_connection_passes_checkout() {
        let mut c = connection().await;
        assert_eq!(violation_on(&mut c).await, None);
        // Unrelated TEMP state (the query_sql contract) is not a violation.
        sqlx::query("CREATE TEMP TABLE _query_sql_principal(id TEXT)")
            .execute(&mut c)
            .await
            .unwrap();
        assert_eq!(violation_on(&mut c).await, None);
    }

    #[tokio::test]
    async fn temp_shadow_of_an_input_or_accelerator_is_refused() {
        for ddl in [
            "CREATE TEMP TABLE kernel_records(id TEXT, v INTEGER)",
            "CREATE TEMP TABLE Content_Events(seq INTEGER)",
            "CREATE TEMP VIEW content_events AS SELECT 1 AS seq",
            "CREATE TEMP TABLE p_dirty(kind TEXT, key TEXT)",
            "CREATE TEMP TRIGGER t AFTER INSERT ON main.kernel_records BEGIN SELECT 1; END",
        ] {
            let mut c = connection().await;
            // Planted with the lease guard off: checkout is the second line.
            bypass_guard_for_test(&mut c, true).await;
            sqlx::query(ddl).execute(&mut c).await.unwrap();
            assert_eq!(
                violation_on(&mut c).await,
                Some(Violation::TempShadow),
                "{ddl}"
            );
        }
    }

    #[tokio::test]
    async fn disabled_triggers_are_refused() {
        let mut c = connection().await;
        {
            let mut handle = c.lock_handle().await.unwrap();
            let mut out: c_int = 0;
            unsafe {
                libsqlite3_sys::sqlite3_db_config(
                    handle.as_raw_handle().as_ptr(),
                    libsqlite3_sys::SQLITE_DBCONFIG_ENABLE_TRIGGER,
                    0 as c_int,
                    &mut out as *mut c_int,
                );
            }
        }
        assert_eq!(
            violation_on(&mut c).await,
            Some(Violation::TriggersDisabled)
        );
    }

    /// A write captured by a TEMP shadow mid-lease is never acknowledged: the
    /// commit fails, nothing persists in either schema, and the connection is
    /// not reusable.
    #[tokio::test]
    async fn captured_temp_write_vetoes_commit_and_poisons_the_connection() {
        let mut c = connection().await;
        bypass_guard_for_test(&mut c, true).await;
        let before = vetoed_commits();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut c)
            .await
            .unwrap();
        sqlx::query("CREATE TEMP TABLE kernel_records(id TEXT, v INTEGER)")
            .execute(&mut c)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kernel_records(id,v) VALUES('a',1)")
            .execute(&mut c)
            .await
            .unwrap();
        let commit = sqlx::query("COMMIT").execute(&mut c).await;
        assert!(commit.is_err(), "a shadow-captured write must not commit");
        assert!(vetoed_commits() > before);
        let main_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM main.kernel_records")
            .fetch_one(&mut c)
            .await
            .unwrap();
        assert_eq!(main_rows, 0);
        assert!(!reusable_after_release(&mut c).await);
        assert_eq!(violation_on(&mut c).await, Some(Violation::Captured));
        // Autocommit writes are vetoed too.
        let autocommit = sqlx::query("INSERT INTO temp.kernel_records(id,v) VALUES('b',2)")
            .execute(&mut c)
            .await;
        assert!(autocommit.is_err());
    }

    #[tokio::test]
    async fn ordinary_main_and_unprotected_temp_writes_commit() {
        let mut c = connection().await;
        sqlx::query("CREATE TEMP TABLE _scratch(v INTEGER)")
            .execute(&mut c)
            .await
            .unwrap();
        sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut c)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kernel_records(id,v) VALUES('a',1)")
            .execute(&mut c)
            .await
            .unwrap();
        sqlx::query("INSERT INTO _scratch VALUES(1)")
            .execute(&mut c)
            .await
            .unwrap();
        sqlx::query("COMMIT").execute(&mut c).await.unwrap();
        assert!(reusable_after_release(&mut c).await);
        assert_eq!(violation_on(&mut c).await, None);
    }

    /// The lease guard refuses every protected TEMP object at prepare time
    /// and leaves the governed SQL surface's TEMP relations alone.
    #[tokio::test]
    async fn lease_guard_refuses_protected_temp_objects_only() {
        for ddl in [
            "CREATE TEMP TABLE kernel_records(id TEXT, v INTEGER)",
            "CREATE TEMP TABLE Content_Events(seq INTEGER PRIMARY KEY) WITHOUT ROWID",
            "CREATE TABLE temp.kernel_roots(root_id TEXT)",
            "CREATE TEMP TABLE p_dirty(kind TEXT, key TEXT)",
            "CREATE TEMP VIEW p_state AS SELECT 1",
            "CREATE TEMP TRIGGER t BEFORE INSERT ON main.kernel_records BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER t AFTER DELETE ON main.kernel_records BEGIN SELECT 1; END",
            "CREATE TEMP TRIGGER p_mark_x AFTER INSERT ON _scratch BEGIN SELECT 1; END",
            "ALTER TABLE temp._scratch RENAME TO kernel_records",
        ] {
            let mut c = connection().await;
            sqlx::query("CREATE TEMP TABLE _scratch(v INTEGER)")
                .execute(&mut c)
                .await
                .unwrap();
            assert!(sqlx::query(ddl).execute(&mut c).await.is_err(), "{ddl}");
            assert_eq!(violation_on(&mut c).await, None, "{ddl}");
        }
        let mut c = connection().await;
        for ddl in [
            "CREATE TEMP VIEW content_events AS SELECT 1 AS seq",
            "CREATE TEMP VIEW records AS SELECT 1 AS id",
            "CREATE TEMP TABLE _query_sql_visible_ids(id TEXT PRIMARY KEY) WITHOUT ROWID",
            "CREATE TEMP TRIGGER fine AFTER INSERT ON _query_sql_visible_ids BEGIN SELECT 1; END",
            "CREATE TABLE main.unrelated(x)",
        ] {
            sqlx::query(ddl)
                .execute(&mut c)
                .await
                .unwrap_or_else(|e| panic!("{ddl}: {e}"));
        }
    }

    unsafe extern "C" fn deny_deletes(
        _: *mut c_void,
        action: c_int,
        _: *const c_char,
        _: *const c_char,
        _: *const c_char,
        _: *const c_char,
    ) -> c_int {
        if action == libsqlite3_sys::SQLITE_DELETE {
            libsqlite3_sys::SQLITE_DENY
        } else {
            libsqlite3_sys::SQLITE_OK
        }
    }

    /// A policy installed through `set_authorizer` (enrolled storage) is
    /// composed behind the guard: both decide, neither replaces the other.
    #[tokio::test]
    async fn composed_authorizer_keeps_both_policies() {
        let mut c = connection().await;
        {
            let mut handle = c.lock_handle().await.unwrap();
            // SAFETY: locked live handle; the callback has no user data.
            let rc = unsafe {
                set_authorizer(
                    handle.as_raw_handle().as_ptr(),
                    Some(deny_deletes),
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(rc, libsqlite3_sys::SQLITE_OK);
        }
        c.clear_cached_statements().await.unwrap();
        assert!(sqlx::query("DELETE FROM kernel_records")
            .execute(&mut c)
            .await
            .is_err());
        assert!(sqlx::query("CREATE TEMP TABLE kernel_records(id TEXT)")
            .execute(&mut c)
            .await
            .is_err());
        sqlx::query("INSERT INTO kernel_records(id, v) VALUES('a', 1)")
            .execute(&mut c)
            .await
            .unwrap();
        // A checkout keeps the composition in place.
        assert_eq!(violation_on(&mut c).await, None);
        assert!(sqlx::query("DELETE FROM kernel_records")
            .execute(&mut c)
            .await
            .is_err());
    }
}
