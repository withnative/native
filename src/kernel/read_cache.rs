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
}
type Entries = HashMap<(Key, TypeId), Arc<dyn Any + Send + Sync>>;
tokio::task_local! { static ENTRIES: RefCell<Entries>; }
tokio::task_local! { static READ_CAPABILITIES: bool; }
tokio::task_local! { static PINNED_SNAPSHOT: (Key, usize); }

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
        Some(key) => PINNED_SNAPSHOT.scope((key, connection), work).await,
        None => work.await,
    }
}

/// Identity of the borrowed connection for the lifetime of a closed scope.
/// Never dereferenced or persisted; checked before returning a pinned key.
pub(crate) fn connection_id(conn: &mut SqliteConnection) -> usize {
    conn as *mut SqliteConnection as usize
}

// Opt in only for closed, read-only Get, search and collection resolution. Writes
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
        ENTRIES.scope(RefCell::new(HashMap::new()), work).await
    }
}

pub(crate) async fn key_on(
    conn: &mut SqliteConnection,
    actor: &str,
    kind: &'static str,
) -> Result<Option<Key>> {
    if ENTRIES.try_with(|_| ()).is_err() {
        return Ok(None);
    }
    if let Ok((pinned, connection)) = PINNED_SNAPSHOT.try_with(Clone::clone) {
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
    ).fetch_one(conn).await?;
    Ok((!file.is_empty()).then(|| Key {
        file,
        kind,
        actor: actor.into(),
        content,
        meta,
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
}
