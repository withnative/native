//! Memoization only inside one dispatched request. Every lookup obtains its
//! identity from the caller's live transaction; changed content/meta heads,
//! another database, or another principal cannot reuse an earlier result.
use crate::Result;
use sqlx::SqliteConnection;
use std::{
    any::{Any, TypeId},
    cell::RefCell,
    collections::HashMap,
    future::Future,
    sync::Arc,
};

#[derive(Clone, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    file: String,
    kind: &'static str,
    actor: String,
    content: Option<String>,
    meta: Option<String>,
    /// Fingerprint of the app folder scope narrowing this dispatch, so a
    /// scoped app never reuses the person's (or another scope's) entries.
    app_scope: Option<String>,
}
type Entries = HashMap<(Key, TypeId), Arc<dyn Any + Send + Sync>>;
tokio::task_local! { static ENTRIES: RefCell<Entries>; }
tokio::task_local! { static APP_SCOPES: RefCell<HashMap<String, String>>; }

/// Per-request resolved app-scope JSON by `principal\0package`, so the
/// capability hot path resolves a grant synchronously after first use.
pub(crate) fn app_scope_cached(key: &str) -> Option<String> {
    APP_SCOPES
        .try_with(|scopes| scopes.borrow().get(key).cloned())
        .ok()
        .flatten()
}

pub(crate) fn app_scope_put(key: String, scope_json: String) {
    let _ = APP_SCOPES.try_with(|scopes| scopes.borrow_mut().insert(key, scope_json));
}
tokio::task_local! { static READ_CAPABILITIES: bool; }
tokio::task_local! { static PINNED_SNAPSHOT: Option<(Key, usize)>; }

/// Only for a borrowed, pinned read connection. The closed callback must use
/// connection-scoped helpers exclusively; no other database or transaction.
/// Every build checks the borrowed connection identity on each lookup. Debug
/// builds additionally verify database and event heads against SQLite itself.
/// Only sql::{in_snapshot,with_scoped_read_session}, history_page_selected_as
/// and query/search placement callbacks install this scope. Each captures identity after
/// BEGIN has pinned one connection's SQLite snapshot. Their closed callbacks
/// use that connection exclusively and never commit, replace it, or write main;
/// none dispatches arbitrary tool code. SQL-session entry checks DB handle and
/// actor. The scope ends before rollback/release, including cancellation. A
/// scope never spans dispatches or wraps a writer; write caches still read heads.
/// Re-querying SQLite for every nested lookup would undo the batch optimization.
/// Keep this contract when adding a callback: the snapshot/concurrent-writer
/// tests exercise it, and debug adds an identity diagnostic for future misuse.
pub(crate) async fn in_pinned_snapshot<F: Future>(
    key: Option<Key>,
    connection: usize,
    work: F,
) -> F::Output {
    match key {
        Some(key) => {
            // The admission scope nests inside the pinned snapshot scope: both
            // helpers are async fns, so nothing runs until the outer scope polls.
            #[cfg(feature = "v2-kernel-probe")]
            let work = crate::kernel::app_installs::scope_read_admissions(
                connection,
                Arc::default(),
                work,
            );
            PINNED_SNAPSHOT.scope(Some((key, connection)), work).await
        }
        None => {
            #[cfg(feature = "v2-kernel-probe")]
            {
                crate::kernel::app_installs::without_read_admissions(work).await
            }
            #[cfg(not(feature = "v2-kernel-probe"))]
            {
                work.await
            }
        }
    }
}

/// Reenter the same closed SQL read session without sharing authority with
/// any other snapshot. Its owner retains the cache until rollback/close.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn in_pinned_snapshot_with_admissions<F: Future>(
    key: Option<Key>,
    connection: usize,
    admissions: Arc<crate::kernel::app_installs::ReadAdmissions>,
    work: F,
) -> F::Output {
    match key {
        Some(key) => {
            PINNED_SNAPSHOT
                .scope(
                    Some((key, connection)),
                    crate::kernel::app_installs::scope_read_admissions(
                        connection, admissions, work,
                    ),
                )
                .await
        }
        None => crate::kernel::app_installs::without_read_admissions(work).await,
    }
}

/// Identity of the borrowed connection for the lifetime of a closed scope.
/// Never dereferenced or persisted; checked before returning a pinned key.
pub(crate) fn connection_id(conn: &mut SqliteConnection) -> usize {
    conn as *mut SqliteConnection as usize
}

// Opt in only for closed, read-only Get, search, collection resolution and the
// imported-content semantic parity renderer on its disposable target. Writes
// retain fresh admission even if a future writer edits a projection before
// appending.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn with_capabilities<F: Future>(work: F) -> F::Output {
    READ_CAPABILITIES.scope(true, work).await
}
pub(crate) async fn capability_key_on(
    conn: &mut SqliteConnection,
    actor: &str,
) -> Result<Option<Key>> {
    if !READ_CAPABILITIES
        .try_with(|enabled| *enabled)
        .unwrap_or(false)
    {
        return Ok(None);
    }
    key_on(conn, actor, "effective_capabilities").await
}

pub(crate) async fn scope_request<F: Future>(work: F) -> F::Output {
    if ENTRIES.try_with(|_| ()).is_ok() {
        work.await
    } else {
        ENTRIES
            .scope(
                RefCell::new(HashMap::new()),
                APP_SCOPES.scope(RefCell::new(HashMap::new()), work),
            )
            .await
    }
}

/// Canonical member metadata runs after logical TEMP staging has been released.
/// Never reuse caller entries (which may describe that staging), a pinned key,
/// or capability/body memoization. Each lookup still reads live identity. Tokio
/// restores all parent scopes on return, refusal and cancellation. This scope
/// must wrap only the read-only source helper loop, never a source writer.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) async fn scope_member_metadata<F: Future>(work: F) -> F::Output {
    // Lazy (async fn): the admission scope runs innermost, under all three below.
    #[cfg(feature = "v2-kernel-probe")]
    let work = crate::kernel::app_installs::without_read_admissions(work);
    ENTRIES
        .scope(
            RefCell::new(HashMap::new()),
            READ_CAPABILITIES.scope(false, PINNED_SNAPSHOT.scope(None, work)),
        )
        .await
}

pub(crate) async fn key_on(
    conn: &mut SqliteConnection,
    actor: &str,
    kind: &'static str,
) -> Result<Option<Key>> {
    if ENTRIES.try_with(|_| ()).is_err() {
        return Ok(None);
    }
    if let Ok(Some((pinned, connection))) = PINNED_SNAPSHOT.try_with(Clone::clone) {
        if connection != connection_id(conn) {
            return Err(crate::Error::engine(
                "pinned read cache connection mismatch",
            ));
        }
        #[cfg(debug_assertions)]
        {
            let actual = identity_on(conn, actor, kind).await?;
            debug_assert!(
                actual
                    .as_ref()
                    .is_some_and(|actual| actual.file == pinned.file
                        && actual.content == pinned.content
                        && actual.meta == pinned.meta),
                "pinned read cache crossed a database or event snapshot"
            );
        }
        return Ok(Some(Key {
            kind,
            actor: actor.into(),
            ..pinned
        }));
    }
    identity_on(conn, actor, kind).await
}
async fn identity_on(
    conn: &mut SqliteConnection,
    actor: &str,
    kind: &'static str,
) -> Result<Option<Key>> {
    // One statement binds all three facts to the same read snapshot. Do not
    // cache anonymous in-memory databases: their empty filename is not unique.
    let (file, content, meta): (String, Option<String>, Option<String>) = sqlx::query_as(
        "SELECT (SELECT file FROM pragma_database_list WHERE name='main'),(SELECT id FROM main.content_events ORDER BY seq DESC LIMIT 1),(SELECT id FROM main.meta_events ORDER BY seq DESC LIMIT 1)",
    ).fetch_one(&mut *conn).await?;
    if file.is_empty() {
        return Ok(None);
    }
    let app_scope = match super::app_installs::scope::active_scope_cached(actor) {
        super::app_installs::scope::ActiveScope::None => None,
        super::app_installs::scope::ActiveScope::Known(scope) => Some(scope.fingerprint()),
        super::app_installs::scope::ActiveScope::Unresolved(_) => {
            super::app_installs::scope::active_fingerprint_on(conn, actor).await?
        }
    };
    Ok(Some(Key {
        file,
        kind,
        actor: actor.into(),
        content,
        meta,
        app_scope,
    }))
}

pub(crate) fn get<T: Any + Send + Sync>(key: &Option<Key>) -> Option<Arc<T>> {
    let key = key.as_ref()?;
    let value = ENTRIES
        .try_with(|entries| {
            entries
                .borrow()
                .get(&(key.clone(), TypeId::of::<T>()))
                .cloned()
        })
        .ok()
        .flatten()
        .and_then(|value| value.downcast().ok());
    tracing::debug!(target: "native_ce::read_staging", phase = "request_cache", cache = key.kind, hit = value.is_some());
    value
}

pub(crate) fn put<T: Any + Send + Sync>(key: Option<Key>, value: Arc<T>) {
    if let Some(key) = key {
        let _ = ENTRIES
            .try_with(|entries| entries.borrow_mut().insert((key, TypeId::of::<T>()), value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Connection;

    #[tokio::test]
    async fn provider_link_release_pinned_cache_refuses_another_connection() {
        let mut first = SqliteConnection::connect(":memory:").await.unwrap();
        let mut second = SqliteConnection::connect(":memory:").await.unwrap();
        let key = Key {
            file: "test-only-pinned-file".into(),
            kind: "test",
            actor: "viewer".into(),
            content: None,
            meta: None,
            app_scope: None,
        };
        scope_request(in_pinned_snapshot(
            Some(key),
            connection_id(&mut first),
            async {
                let refusal = key_on(&mut second, "viewer", "home_visibility")
                    .await
                    .err()
                    .expect("release builds must reject another connection too");
                assert!(refusal.to_string().contains("connection mismatch"));
            },
        ))
        .await;
    }

    // File-backed synthetic identities: anonymous memory databases deliberately
    // disable memoization. No application schema, product runtime or HQ inputs.
    async fn identity_fixture(path: &std::path::Path) -> SqliteConnection {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("CREATE TABLE content_events(seq INTEGER PRIMARY KEY,id TEXT); CREATE TABLE meta_events(seq INTEGER PRIMARY KEY,id TEXT)")
            .execute(&mut conn).await.unwrap();
        conn
    }

    #[tokio::test]
    async fn member_metadata_fresh_cache_uses_live_db_actor_and_both_heads() {
        let dir = tempfile::tempdir().unwrap();
        let mut first = identity_fixture(&dir.path().join("one.db")).await;
        let mut second = identity_fixture(&dir.path().join("two.db")).await;
        scope_member_metadata(async {
            let key = key_on(&mut first, "actor", "ancestor_descriptors")
                .await
                .unwrap();
            assert!(key.is_some());
            put(key.clone(), Arc::new(7usize));
            assert_eq!(
                *get::<usize>(
                    &key_on(&mut first, "actor", "ancestor_descriptors")
                        .await
                        .unwrap()
                )
                .unwrap(),
                7
            );
            assert!(get::<usize>(
                &key_on(&mut first, "other", "ancestor_descriptors")
                    .await
                    .unwrap()
            )
            .is_none());
            assert!(get::<usize>(
                &key_on(&mut second, "actor", "ancestor_descriptors")
                    .await
                    .unwrap()
            )
            .is_none());
            sqlx::query("INSERT INTO content_events(id) VALUES('new-content')")
                .execute(&mut first)
                .await
                .unwrap();
            let content = key_on(&mut first, "actor", "ancestor_descriptors")
                .await
                .unwrap();
            assert!(get::<usize>(&content).is_none());
            put(content, Arc::new(8usize));
            sqlx::query("INSERT INTO meta_events(id) VALUES('new-meta')")
                .execute(&mut first)
                .await
                .unwrap();
            assert!(get::<usize>(
                &key_on(&mut first, "actor", "ancestor_descriptors")
                    .await
                    .unwrap()
            )
            .is_none());
        })
        .await;
        assert!(key_on(&mut first, "actor", "ancestor_descriptors")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn member_metadata_fresh_cache_restores_parent_on_return_error_and_cancel() {
        let dir = tempfile::tempdir().unwrap();
        let mut source = identity_fixture(&dir.path().join("source.db")).await;
        scope_request(async {
            let key = key_on(&mut source, "actor", "ancestor_descriptors")
                .await
                .unwrap();
            let parent = Arc::new(17usize);
            put(key.clone(), parent.clone());
            // Model labels seeded by logical TEMP staging at the same main head.
            // A deliberately wrong pinned connection must also be masked.
            let pinned = key.clone().unwrap();
            READ_CAPABILITIES
                .scope(
                    true,
                    in_pinned_snapshot(Some(pinned), usize::MAX, async {
                        let result: std::result::Result<(), ()> = scope_member_metadata(async {
                            assert!(!READ_CAPABILITIES.with(|enabled| *enabled));
                            assert!(capability_key_on(&mut source, "actor")
                                .await
                                .unwrap()
                                .is_none());
                            let fresh = key_on(&mut source, "actor", "ancestor_descriptors")
                                .await
                                .unwrap();
                            assert!(
                                fresh == key,
                                "fresh scope uses actual DB/head, not inherited pin"
                            );
                            assert!(get::<usize>(&fresh).is_none());
                            put(fresh, Arc::new(99usize));
                            Ok(())
                        })
                        .await;
                        assert_eq!(result, Ok(()));
                        let result: std::result::Result<(), ()> = scope_member_metadata(async {
                            assert!(get::<usize>(&key).is_none());
                            put(key.clone(), Arc::new(98usize));
                            Err(())
                        })
                        .await;
                        assert_eq!(result, Err(()));
                        // Poll the actual scoped future to pending, then drop it. No
                        // timer or spawned task can disguise the cancellation boundary.
                        let mut pending = Box::pin(scope_member_metadata(async {
                            put(key.clone(), Arc::new(97usize));
                            std::future::pending::<()>().await;
                        }));
                        fn require_send<T: Send>(_: &T) {}
                        require_send(&pending);
                        std::future::poll_fn(|cx| {
                            use std::future::Future;
                            assert!(pending.as_mut().poll(cx).is_pending());
                            std::task::Poll::Ready(())
                        })
                        .await;
                        drop(pending);
                        assert!(Arc::ptr_eq(&get::<usize>(&key).unwrap(), &parent));
                        assert!(READ_CAPABILITIES.with(|enabled| *enabled));
                        assert!(key_on(&mut source, "actor", "ancestor_descriptors")
                            .await
                            .err()
                            .unwrap()
                            .to_string()
                            .contains("connection mismatch"));
                    }),
                )
                .await;
            assert!(Arc::ptr_eq(&get::<usize>(&key).unwrap(), &parent));
            assert!(
                key_on(&mut source, "actor", "ancestor_descriptors")
                    .await
                    .unwrap()
                    == key
            );
        })
        .await;
    }
}
