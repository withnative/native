//! Serialises HCP mutations per person.
//!
//! Lookup-or-create of a preference record, definition changes and preference
//! writes all read, decide, then write. Run concurrently they can create two
//! records for one slug or validate against a definition that is changing
//! underneath them. One async lock per (workspace, person) makes every
//! `mutatePreferences` call for that person atomic with respect to the others.
//!
//! An in-process lock is sufficient because a hosted data directory is served
//! by exactly one process: `Hosting::open` takes the hosting authority lock
//! and refuses a second live facade (see `HostingAuthorityLock`), and the
//! deployment runs one instance on one volume. This lock is the uniqueness
//! guard for "one preference record per person and definition". A deployment
//! with several processes sharing one database would need a durable uniqueness
//! guard of its own; revisions are still guarded by the digest of the body
//! they read, but record creation is not.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

type Registry = Mutex<HashMap<String, Arc<AsyncMutex<()>>>>;

fn registry() -> &'static Registry {
    static LOCKS: OnceLock<Registry> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Wait for exclusive use of `key`; released when the guard drops.
pub(crate) async fn acquire(key: &str) -> OwnedMutexGuard<()> {
    let lock = {
        let mut locks = registry().lock().expect("HCP lock table poisoned");
        // Forget keys nobody holds or waits on, so the table does not grow
        // with every person who ever wrote a preference.
        if locks.len() > 256 {
            locks.retain(|_, lock| Arc::strong_count(lock) > 1);
        }
        locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    };
    lock.lock_owned().await
}
