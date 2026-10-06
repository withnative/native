//! Per-process memo of the immutable half of the `live_read` gate chain
//! (task `9be4011`).
//!
//! Every tab read re-runs the whole gate on its own snapshot: install row and
//! CAS, install gates, target and View, runtime facet, then the source and
//! declaration checks. The last group is the expensive part. It loads the full
//! source body and hashes it, and recomputes the JCS declaration digest. A SQL
//! need then also re-parses and re-validates every declared statement. None of
//! that can change while the pin stays put:
//!
//! - the declaration digest and the parsed SQL needs are pure functions of the
//!   consented declaration;
//! - the bundle hash is a function of one content event's body, and content
//!   events are append-only (`crate::schema::ddl::CONTENT_EVENTS_APPEND_ONLY_TRIGGERS`).
//!
//! So once a gate passes in full, its result is kept under (database handle,
//! account, package, install event id). A later gate that finds an entry whose
//! pin inputs equal its row's skips that group. It still reads the install
//! row, checks CAS, the install gates, target, View and runtime on its own
//! snapshot, probes that the source event exists, and recomputes the pin
//! digest from the cached hashes and the current runtime.
//!
//! An entry holds nothing that can change without a new install event. Status
//! and adoption are re-read from the row every time, and `adoption_provenance`
//! (backfilled in place) and `body_read_admission_event_id` are not used by
//! the gate at all. A hit compares every pin input anyway, so a projection
//! edited in place, as several tests do, misses and runs the full chain.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use serde_json::Value;
use uuid::Uuid;

use super::{alpha_tab_digest, sql_needs_in, InstallRow, SqlNeed};
use crate::error::Result;

/// Entries kept per process. Most hold one declaration of a few kilobytes;
/// the declaration bounds cap a single entry well under 100 KB.
const CAPACITY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    database: Uuid,
    account_id: String,
    package: String,
    install_event_id: String,
}

impl Key {
    fn new(database: Uuid, account_id: &str, package: &str, install_event_id: &str) -> Self {
        Self {
            database,
            account_id: account_id.to_owned(),
            package: package.to_owned(),
            install_event_id: install_event_id.to_owned(),
        }
    }
}

/// The immutable gate work for one install pin, verified in full once.
pub(super) struct VerifiedInstall {
    digest: String,
    artifact_id: String,
    source_revision: String,
    declaration_digest: String,
    declaration: Value,
    /// SHA-256 of the source body, as `alpha_tab_bundle_digest` gives it.
    pub(super) bundle_sha256: String,
    /// `None` when the declaration's SQL needs do not parse: a read that
    /// asks for them re-parses and refuses exactly as before.
    sql_needs: Option<Vec<SqlNeed>>,
}

impl VerifiedInstall {
    /// Record a gate that has just passed in full for `row`, whose source
    /// body hashed to `bundle_sha256`.
    pub(super) fn new(row: &InstallRow, bundle_sha256: String) -> Self {
        Self {
            digest: row.digest.clone(),
            artifact_id: row.artifact_id.clone(),
            source_revision: row.consented_source_revision.clone(),
            declaration_digest: row.declaration_digest.clone(),
            declaration: row.consented_declaration.clone(),
            bundle_sha256,
            sql_needs: sql_needs_in(&row.consented_declaration).ok(),
        }
    }

    /// Whether this entry was verified for exactly `row`'s pin inputs.
    fn covers(&self, row: &InstallRow) -> bool {
        self.digest == row.digest
            && self.artifact_id == row.artifact_id
            && self.source_revision == row.consented_source_revision
            && self.declaration_digest == row.declaration_digest
            && self.declaration == row.consented_declaration
    }

    /// The pin digest check with the current runtime. `None` never matches.
    pub(super) fn pin_digest_matches(&self, runtime: Option<&str>, pin_digest: &str) -> bool {
        runtime.is_some_and(|runtime| {
            alpha_tab_digest(&self.bundle_sha256, &self.declaration_digest, runtime) == pin_digest
        })
    }

    /// The declaration's SQL needs, as `sql_needs_in` returns them.
    pub(super) fn sql_needs(&self) -> Result<Vec<SqlNeed>> {
        match &self.sql_needs {
            Some(needs) => Ok(needs.clone()),
            None => sql_needs_in(&self.declaration),
        }
    }
}

/// A bounded map that evicts the least recently used entry.
struct Cache {
    capacity: usize,
    tick: u64,
    entries: HashMap<Key, (Arc<VerifiedInstall>, u64)>,
}

impl Cache {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            tick: 0,
            entries: HashMap::new(),
        }
    }

    fn lookup(&mut self, key: &Key, row: &InstallRow) -> Option<Arc<VerifiedInstall>> {
        self.tick += 1;
        let tick = self.tick;
        let (verified, used) = self.entries.get_mut(key)?;
        if !verified.covers(row) {
            return None;
        }
        *used = tick;
        Some(Arc::clone(verified))
    }

    fn remember(&mut self, key: Key, verified: Arc<VerifiedInstall>) {
        self.tick += 1;
        self.entries.insert(key, (verified, self.tick));
        while self.entries.len() > self.capacity {
            let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    fn holds(&self, key: &Key) -> bool {
        self.entries.contains_key(key)
    }
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Cache::new(CAPACITY)))
}

/// The verified entry for `row`'s install event, if one covers its pin.
pub(super) fn lookup(
    database: Uuid,
    account_id: &str,
    package: &str,
    row: &InstallRow,
) -> Option<Arc<VerifiedInstall>> {
    let key = Key::new(database, account_id, package, &row.event_id);
    cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .lookup(&key, row)
}

/// Keep a gate that passed in full for `install_event_id`.
pub(super) fn remember(
    database: Uuid,
    account_id: &str,
    package: &str,
    install_event_id: &str,
    verified: Arc<VerifiedInstall>,
) {
    let key = Key::new(database, account_id, package, install_event_id);
    cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remember(key, verified);
}

/// Whether the source event a cached pin names is still there. Its type and
/// body were checked when the entry was made, and an existing content event
/// cannot change, so presence is all that is left to check.
/// Immutability: `crate::schema::ddl::CONTENT_EVENTS_APPEND_ONLY_TRIGGERS`.
pub(super) async fn source_event_present_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    artifact_id: &str,
    source_revision: &str,
) -> Result<bool> {
    let present: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM content_events WHERE record_id=? AND id=?")
            .bind(artifact_id)
            .bind(source_revision)
            .fetch_optional(&mut **tx)
            .await?;
    Ok(present.is_some())
}

/// Whether this process holds a verified gate for the install event.
///
/// Public only so integration tests can show a read ran against a warm
/// entry. Nothing else should depend on what the cache holds.
#[doc(hidden)]
pub fn holds(db: &crate::db::Db, account_id: &str, package: &str, install_event_id: &str) -> bool {
    let key = Key::new(db.handle_id(), account_id, package, install_event_id);
    cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .holds(&key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(event_id: &str) -> InstallRow {
        InstallRow {
            package: "agent.cache".into(),
            version: "0.1.0".into(),
            digest: "sha256:pin".into(),
            artifact_id: "artifact".into(),
            consented_source_revision: "source".into(),
            declaration_digest: "declaration".into(),
            consented_declaration: json!({"needs": ["records.search.v1"], "effects": []}),
            adoption: "shell_adopt.v1".into(),
            adoption_provenance: None,
            request: None,
            status: "installed".into(),
            event_id: event_id.into(),
            event_seq: 1,
        }
    }

    fn key(database: Uuid, event_id: &str) -> Key {
        Key::new(database, "alice", "agent.cache", event_id)
    }

    fn verified(row: &InstallRow) -> Arc<VerifiedInstall> {
        Arc::new(VerifiedInstall::new(row, "sha256:bundle".into()))
    }

    #[test]
    fn a_hit_needs_the_same_database_event_and_pin() {
        let mut cache = Cache::new(8);
        let database = Uuid::new_v4();
        let installed = row("event-1");
        cache.remember(key(database, "event-1"), verified(&installed));
        assert!(cache
            .lookup(&key(database, "event-1"), &installed)
            .is_some());
        assert!(cache
            .lookup(&key(Uuid::new_v4(), "event-1"), &installed)
            .is_none());
        assert!(cache
            .lookup(&key(database, "event-2"), &row("event-2"))
            .is_none());
        assert!(cache
            .lookup(
                &Key::new(database, "bea", "agent.cache", "event-1"),
                &installed
            )
            .is_none());
        assert!(cache
            .lookup(
                &Key::new(database, "alice", "agent.other", "event-1"),
                &installed
            )
            .is_none());
        // Same key, pin inputs edited in place: every one of them misses.
        let edits: [fn(&mut InstallRow); 5] = [
            |row| row.digest = "sha256:other".into(),
            |row| row.artifact_id = "other".into(),
            |row| row.consented_source_revision = "other".into(),
            |row| row.declaration_digest = "other".into(),
            |row| row.consented_declaration = json!({"needs": [], "effects": []}),
        ];
        for edit in edits {
            let mut edited = row("event-1");
            edit(&mut edited);
            assert!(cache.lookup(&key(database, "event-1"), &edited).is_none());
        }
        // Fields the gate re-reads every time do not affect a hit.
        let mut disabled = row("event-1");
        disabled.status = "disabled".into();
        disabled.adoption = "caller_asserted".into();
        disabled.adoption_provenance = Some("{}".into());
        assert!(cache.lookup(&key(database, "event-1"), &disabled).is_some());
    }

    #[test]
    fn capacity_evicts_the_least_recently_used_entry() {
        let mut cache = Cache::new(2);
        let database = Uuid::new_v4();
        let (first, second, third) = (row("event-1"), row("event-2"), row("event-3"));
        cache.remember(key(database, "event-1"), verified(&first));
        cache.remember(key(database, "event-2"), verified(&second));
        assert!(cache.lookup(&key(database, "event-1"), &first).is_some());
        cache.remember(key(database, "event-3"), verified(&third));
        assert_eq!(cache.entries.len(), 2);
        assert!(cache.holds(&key(database, "event-1")));
        assert!(!cache.holds(&key(database, "event-2")));
        assert!(cache.holds(&key(database, "event-3")));
    }

    #[test]
    fn pin_digest_follows_the_runtime() {
        let installed = row("event-1");
        let entry = VerifiedInstall::new(&installed, "sha256:bundle".into());
        let pin = alpha_tab_digest("sha256:bundle", "declaration", "native.html.v1");
        assert!(entry.pin_digest_matches(Some("native.html.v1"), &pin));
        assert!(!entry.pin_digest_matches(Some("native.html.artifact.v2"), &pin));
        assert!(!entry.pin_digest_matches(None, &pin));
    }

    #[test]
    fn unparseable_sql_needs_still_refuse_through_the_entry() {
        let mut installed = row("event-1");
        installed.consented_declaration = json!({"needs": [{"need": "sql.snapshot.v1", "key": "Bad", "label": "L", "sql": "SELECT 1"}], "effects": []});
        let entry = VerifiedInstall::new(&installed, "sha256:bundle".into());
        assert_eq!(
            entry.sql_needs().unwrap_err().to_string(),
            sql_needs_in(&installed.consented_declaration)
                .unwrap_err()
                .to_string()
        );
    }
}
