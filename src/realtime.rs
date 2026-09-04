//! Durable, database-scoped content invalidations.
//!
//! The broadcast channel is latency machinery only. SQLite's `content_events`
//! sequence is the source of truth for pump recovery and client reconnects.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use tokio::sync::{broadcast, Mutex, Notify};

use crate::authorization::{Capability, Principal};
use crate::db::Db;
use crate::query::events::{
    content_high_water_on, content_invalidations_on, content_retention_floor_on,
};

pub const HUB_CAPACITY: usize = 256;
const PAGE_SIZE: i64 = 256;

/// Public invalidation envelope, owned by `query::events` (the content-log
/// read contract). Re-exported here so the public
/// `native_ce::realtime::ContentInvalidation` path is preserved.
pub use crate::query::events::ContentInvalidation;

/// Wake-up cursor for Inbox consumers. The components are captured from one
/// SQLite read transaction; it carries no Message body and is never evidence
/// of presentation, acknowledgement, or channel delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxInvalidationVector {
    pub content: i64,
    pub awareness: i64,
    pub candidates: i64,
    pub control: i64,
    pub authorization: i64,
}

async fn inbox_vector_on(pool: &SqlitePool) -> crate::Result<InboxInvalidationVector> {
    let mut tx = pool.begin().await?;
    let value = InboxInvalidationVector {
        content: sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
            .fetch_one(&mut *tx)
            .await?,
        awareness: sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM awareness_events")
            .fetch_one(&mut *tx)
            .await?,
        candidates: sqlx::query_scalar(
            "SELECT COALESCE(MAX(seq),0) FROM notification_candidate_events",
        )
        .fetch_one(&mut *tx)
        .await?,
        control: sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM control_events")
            .fetch_one(&mut *tx)
            .await?,
        authorization: sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id=1")
            .fetch_one(&mut *tx)
            .await?,
    };
    tx.commit().await?;
    Ok(value)
}

pub async fn inbox_invalidation_vector(db: &Db) -> crate::Result<InboxInvalidationVector> {
    inbox_vector_on(db.write_pool()).await
}

/// One database's bounded live fan-out and durable tail pump.
#[derive(Debug)]
pub struct RealtimeHub {
    database_id: String,
    pool: RwLock<SqlitePool>,
    sender: RwLock<Option<broadcast::Sender<ContentInvalidation>>>,
    inbox_sender: RwLock<Option<broadcast::Sender<InboxInvalidationVector>>>,
    notify: Arc<Notify>,
    terminal: AtomicBool,
    last_published_seq: Mutex<i64>,
    last_inbox_vector: Mutex<InboxInvalidationVector>,
    published: Notify,
    #[cfg(test)]
    fail_next_high_water_read: AtomicBool,
    #[cfg(test)]
    fail_next_inbox_vector_read: AtomicBool,
    #[cfg(test)]
    read_failure_observed: Notify,
    #[cfg(test)]
    read_failure_release: Notify,
    #[cfg(test)]
    inbox_vector_failure_observed: Notify,
    #[cfg(test)]
    inbox_vector_failure_release: Notify,
}

impl RealtimeHub {
    /// Return the durable realtime capability installed on an opened database.
    ///
    /// Callers should retain this hub, rather than the opened [`Db`]: when the
    /// database handle is replaced or reopened, the hub refreshes its own
    /// connection while the old handle is closed.
    pub fn for_database(db: &Db) -> Option<Arc<Self>> {
        db.realtime_hub()
    }

    /// Attach a durable realtime hub to an opened database handle.
    ///
    /// Reusing an existing hub preserves subscribers across handle replacement
    /// while refreshing every durable read to the newly opened connection.
    pub async fn attach(db: Db, existing: Option<Arc<Self>>) -> crate::Result<(Db, Arc<Self>)> {
        match existing {
            Some(hub) => {
                let database_id = crate::identity::database_id(&db).await?;
                if database_id != hub.database_id {
                    return Err(crate::Error::engine(format!(
                        "realtime hub database identity mismatch: expected {}, got {database_id}",
                        hub.database_id
                    )));
                }
                hub.refresh_pool(db.write_pool().clone());
                Ok((db.with_realtime_hub(hub.clone()), hub))
            }
            None => Self::install(db).await,
        }
    }

    pub(crate) async fn install(db: Db) -> crate::Result<(Db, Arc<Self>)> {
        let database_id = crate::identity::database_id(&db).await?;
        let last_published_seq = content_high_water_on(db.write_pool()).await?;
        let (sender, _) = broadcast::channel(HUB_CAPACITY);
        let (inbox_sender, _) = broadcast::channel(HUB_CAPACITY);
        let last_inbox_vector = inbox_vector_on(db.write_pool()).await?;
        let hub = Arc::new(Self {
            database_id,
            pool: RwLock::new(db.write_pool().clone()),
            sender: RwLock::new(Some(sender)),
            inbox_sender: RwLock::new(Some(inbox_sender)),
            notify: Arc::new(Notify::new()),
            terminal: AtomicBool::new(false),
            last_published_seq: Mutex::new(last_published_seq),
            last_inbox_vector: Mutex::new(last_inbox_vector),
            published: Notify::new(),
            #[cfg(test)]
            fail_next_high_water_read: AtomicBool::new(false),
            #[cfg(test)]
            fail_next_inbox_vector_read: AtomicBool::new(false),
            #[cfg(test)]
            read_failure_observed: Notify::new(),
            #[cfg(test)]
            read_failure_release: Notify::new(),
            #[cfg(test)]
            inbox_vector_failure_observed: Notify::new(),
            #[cfg(test)]
            inbox_vector_failure_release: Notify::new(),
        });
        let installed = db.with_realtime_hub(hub.clone());
        Self::spawn_pump(&hub);
        Ok((installed, hub))
    }

    fn spawn_pump(hub: &Arc<Self>) {
        let weak = Arc::downgrade(hub);
        let notify = hub.notify.clone();
        tokio::spawn(async move {
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if let Some(hub) = weak.upgrade() {
                    if hub.terminal.load(Ordering::SeqCst) {
                        return;
                    }
                } else {
                    return;
                }
                notified.await;
                let Some(hub) = weak.upgrade() else {
                    return;
                };
                if hub.terminal.load(Ordering::SeqCst) {
                    return;
                }
                loop {
                    if hub.terminal.load(Ordering::SeqCst) {
                        return;
                    }
                    let after = *hub.last_published_seq.lock().await;
                    let pool = hub.pool.read().expect("realtime pool poisoned").clone();
                    #[cfg(test)]
                    let inject_inbox_vector_failure = hub
                        .fail_next_inbox_vector_read
                        .swap(false, Ordering::SeqCst);
                    #[cfg(not(test))]
                    let inject_inbox_vector_failure = false;
                    let vector = if inject_inbox_vector_failure {
                        #[cfg(test)]
                        {
                            eprintln!(
                                "[native-ce] realtime inbox-vector read failed: injected test failure"
                            );
                            hub.inbox_vector_failure_observed.notify_one();
                            hub.inbox_vector_failure_release.notified().await;
                        }
                        Err(crate::Error::engine(
                            "injected realtime inbox-vector read failure",
                        ))
                    } else {
                        inbox_vector_on(&pool).await
                    };
                    match vector {
                        Ok(vector) => {
                            let mut prior = hub.last_inbox_vector.lock().await;
                            if *prior != vector {
                                *prior = vector.clone();
                                if let Some(sender) = hub
                                    .inbox_sender
                                    .read()
                                    .expect("realtime inbox sender poisoned")
                                    .as_ref()
                                {
                                    let _ = sender.send(vector);
                                }
                            }
                        }
                        Err(error) => {
                            eprintln!("[native-ce] realtime inbox-vector read failed: {error}");
                            // Authorization-only commits do not advance the
                            // content cursor. Preserve a retry permit here or a
                            // transient vector failure could remain invisible
                            // until an unrelated later write wakes the pump.
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            hub.notify.notify_one();
                        }
                    }
                    #[cfg(test)]
                    if hub.fail_next_high_water_read.swap(false, Ordering::SeqCst) {
                        eprintln!(
                            "[native-ce] realtime tail high-water read failed: injected test failure"
                        );
                        hub.read_failure_observed.notify_one();
                        hub.read_failure_release.notified().await;
                        hub.notify.notify_one();
                        break;
                    }
                    let fence = match content_high_water_on(&pool).await {
                        Ok(fence) => fence,
                        Err(error) => {
                            eprintln!("[native-ce] realtime tail high-water read failed: {error}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            hub.notify.notify_one();
                            break;
                        }
                    };
                    if after >= fence {
                        break;
                    }
                    let page = match content_invalidations_on(&pool, after, fence, PAGE_SIZE).await
                    {
                        Ok(page) => page,
                        Err(error) => {
                            eprintln!("[native-ce] realtime tail page read failed: {error}");
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            hub.notify.notify_one();
                            break;
                        }
                    };
                    if page.is_empty() {
                        break;
                    }
                    let mut published = after;
                    for envelope in page {
                        published = envelope.local_seq;
                        // No receiver is a normal state. The durable cursor may
                        // still advance because future clients establish their
                        // own fence and replay from SQLite.
                        if let Some(sender) = hub
                            .sender
                            .read()
                            .expect("realtime sender poisoned")
                            .as_ref()
                        {
                            let _ = sender.send(envelope);
                        }
                    }
                    *hub.last_published_seq.lock().await = published;
                    hub.published.notify_one();
                }
            }
        });
    }

    pub(crate) fn wake(&self) {
        self.notify.notify_one();
    }

    pub(crate) fn refresh_pool(&self, pool: SqlitePool) {
        *self.pool.write().expect("realtime pool poisoned") = pool;
    }

    /// Permanently close this hub's live channels and stop its tail pump.
    /// Durable cursors remain in SQLite; a later ready lifecycle opens a fresh
    /// hub rather than splitting fan-out with subscribers to a retired pool.
    pub(crate) fn terminalize(&self) {
        self.terminal.store(true, Ordering::SeqCst);
        self.sender
            .write()
            .expect("realtime sender poisoned")
            .take();
        self.inbox_sender
            .write()
            .expect("realtime inbox sender poisoned")
            .take();
        self.notify.notify_waiters();
    }

    fn current_pool(&self) -> SqlitePool {
        self.pool.read().expect("realtime pool poisoned").clone()
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ContentInvalidation> {
        self.sender
            .read()
            .expect("realtime sender poisoned")
            .as_ref()
            .map_or_else(closed_content_receiver, broadcast::Sender::subscribe)
    }

    pub fn subscribe_inbox(&self) -> broadcast::Receiver<InboxInvalidationVector> {
        self.inbox_sender
            .read()
            .expect("realtime inbox sender poisoned")
            .as_ref()
            .map_or_else(closed_inbox_receiver, broadcast::Sender::subscribe)
    }

    /// Highest durable content cursor visible through the hub's current pool.
    pub async fn content_high_water(&self) -> crate::Result<i64> {
        content_high_water_on(&self.current_pool()).await
    }

    /// Oldest reconnect cursor retained by this database.
    pub async fn content_retention_floor(&self) -> crate::Result<i64> {
        content_retention_floor_on(&self.current_pool()).await
    }

    /// Capture the durable Inbox invalidation vector from the current pool.
    pub async fn inbox_invalidation_vector(&self) -> crate::Result<InboxInvalidationVector> {
        inbox_vector_on(&self.current_pool()).await
    }

    /// Read a bounded durable invalidation page through the current pool.
    pub async fn content_invalidations(
        &self,
        after: i64,
        fence: i64,
        limit: i64,
    ) -> crate::Result<Vec<ContentInvalidation>> {
        content_invalidations_on(&self.current_pool(), after, fence, limit).await
    }

    /// Fail-closed visibility check for one payload-free invalidation.
    pub async fn can_view_invalidation_for_account(
        &self,
        account_id: &str,
        envelope: &ContentInvalidation,
    ) -> bool {
        if matches!(
            envelope.event_type.as_str(),
            "reconciliation.recorded.v1" | "unit.superseded.v1" | "receipt.dependency_audited.v1"
        ) {
            return false;
        }
        let pool = self.current_pool();
        let principal = Principal::bound(account_id, true);
        let capability = if envelope.event_type == "record.deleted" {
            crate::authorization::effective_capability_for_tombstone_in_pool(
                &pool,
                principal,
                &envelope.record_id,
            )
            .await
        } else {
            crate::authorization::effective_capability_in_pool(
                &pool,
                principal,
                &envelope.record_id,
            )
            .await
        };
        if !capability.is_ok_and(|capability| capability.allows(Capability::View)) {
            return false;
        }
        if envelope.event_type != "occurrence.bound.v1" {
            return true;
        }
        let artefact_id: Option<String> =
            sqlx::query_scalar("SELECT artefact_id FROM occurrences WHERE binding_event_id = ?")
                .bind(&envelope.id)
                .fetch_optional(&pool)
                .await
                .ok()
                .flatten();
        let Some(artefact_id) = artefact_id else {
            return false;
        };
        crate::authorization::effective_capability_in_pool(&pool, principal, &artefact_id)
            .await
            .is_ok_and(|capability| capability.allows(Capability::View))
    }

    #[cfg(test)]
    pub(crate) fn receiver_count(&self) -> usize {
        self.sender
            .read()
            .expect("realtime sender poisoned")
            .as_ref()
            .map_or(0, broadcast::Sender::receiver_count)
    }
}

/// Permanently retire the live channels owned by a hosted router entry.
/// Durable cursors remain available for a later ready lifecycle.
#[doc(hidden)]
pub fn terminalize_hosted_router_hub(hub: &RealtimeHub) {
    hub.terminalize();
}

fn closed_content_receiver() -> broadcast::Receiver<ContentInvalidation> {
    let (sender, receiver) = broadcast::channel(1);
    drop(sender);
    receiver
}

fn closed_inbox_receiver() -> broadcast::Receiver<InboxInvalidationVector> {
    let (sender, receiver) = broadcast::channel(1);
    drop(sender);
    receiver
}

/// Hidden deterministic seam for router lifecycle coverage.
#[doc(hidden)]
pub fn subscribe_for_lifecycle_tests(db: &Db) -> broadcast::Receiver<ContentInvalidation> {
    db.realtime_hub()
        .expect("routed database has realtime hub")
        .subscribe()
}

/// Wait until the in-process tail pump has observed `seq`. This is a hidden
/// deterministic test seam; delivery and reconnect never depend on it.
#[doc(hidden)]
pub async fn wait_until_published_for_tests(db: &Db, seq: i64) {
    let hub = db.realtime_hub().expect("routed database has realtime hub");
    loop {
        let notified = hub.published.notified();
        if *hub.last_published_seq.lock().await >= seq {
            return;
        }
        notified.await;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorError {
    Invalid,
    ResetRequired,
}

pub fn parse_cursor(
    after: Option<&str>,
    last_event_id: Option<&str>,
) -> Result<Option<i64>, CursorError> {
    fn one(raw: &str) -> Result<i64, CursorError> {
        if raw.is_empty() || raw.starts_with('-') || !raw.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(CursorError::Invalid);
        }
        raw.parse::<i64>().map_err(|_| CursorError::Invalid)
    }
    let after = after.map(one).transpose()?;
    let header = last_event_id.map(one).transpose()?;
    match (after, header) {
        (Some(left), Some(right)) if left != right => Err(CursorError::Invalid),
        (Some(value), _) | (_, Some(value)) => Ok(Some(value)),
        (None, None) => Ok(None),
    }
}

pub fn validate_cursor(
    cursor: Option<i64>,
    floor: i64,
    fence: i64,
) -> Result<Option<i64>, CursorError> {
    if cursor.is_some_and(|value| value < floor || value > fence) {
        Err(CursorError::ResetRequired)
    } else {
        Ok(cursor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::store::{append, append_batch, append_in, AppendSpec};

    fn spec(record_id: &str, event_type: &str) -> AppendSpec {
        AppendSpec {
            record_id: record_id.into(),
            event_type: event_type.into(),
            payload: json!({ "type": "Document", "kind": "x-realtime-test", "name": record_id }),
            actor: Some("test actor".into()),
        }
    }

    #[test]
    fn cursor_parsing_is_strict() {
        assert_eq!(parse_cursor(None, None), Ok(None));
        assert_eq!(parse_cursor(Some("0"), None), Ok(Some(0)));
        assert_eq!(parse_cursor(Some("42"), Some("42")), Ok(Some(42)));
        for invalid in ["", "-1", "+1", " 1", "1.0", "abc"] {
            assert_eq!(parse_cursor(Some(invalid), None), Err(CursorError::Invalid));
        }
        assert_eq!(
            parse_cursor(Some("1"), Some("2")),
            Err(CursorError::Invalid)
        );
        assert_eq!(validate_cursor(Some(4), 0, 5), Ok(Some(4)));
        assert_eq!(
            validate_cursor(Some(6), 0, 5),
            Err(CursorError::ResetRequired)
        );
        assert_eq!(
            validate_cursor(Some(2), 3, 5),
            Err(CursorError::ResetRequired)
        );
    }

    #[test]
    fn envelope_has_exact_public_fields() {
        let envelope = ContentInvalidation {
            local_seq: 7,
            id: "event".into(),
            record_id: "record".into(),
            event_type: "facet.set".into(),
            created_at: "now".into(),
        };
        assert_eq!(
            serde_json::to_value(envelope).unwrap(),
            json!({ "local_seq": 7, "id": "event", "record_id": "record", "type": "facet.set", "created_at": "now" })
        );
    }

    #[tokio::test]
    async fn committed_batches_publish_in_durable_order_and_rollback_is_silent() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (db, hub) = RealtimeHub::install(db).await.unwrap();
        let mut receiver = hub.subscribe();

        let events = append_batch(
            &db,
            vec![
                spec("4ea17000-0000-4000-8000-000000000001", "record.created"),
                spec("4ea17000-0000-4000-8000-000000000002", "record.created"),
            ],
        )
        .await
        .unwrap();
        let first = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        let second = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            [first.local_seq, second.local_seq],
            [events[0].local_seq, events[1].local_seq]
        );

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        append_in(
            &db,
            &mut tx,
            spec("4ea17000-0000-4000-8000-000000000003", "record.created"),
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), receiver.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn awareness_commit_advances_inbox_vector_without_content_or_delivery_claims() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (db, hub) = RealtimeHub::install(db).await.unwrap();
        let before = inbox_invalidation_vector(&db).await.unwrap();
        let mut receiver = hub.subscribe_inbox();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        crate::awareness::advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            crate::awareness::HumanStage::Presented,
            0,
            "present",
            &crate::awareness::VerifiedHumanInteraction {
                nonce: "nonce".into(),
                executor_ref: "ui".into(),
            },
            "rendered exact id",
        )
        .await
        .unwrap();
        db.commit_awareness(tx).await.unwrap();
        let vector = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(vector.content, before.content);
        assert_eq!(vector.awareness, before.awareness + 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM notification_candidate_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn hubs_are_database_isolated_and_bounded() {
        let db_a = crate::db::create_database(":memory:").await.unwrap();
        let db_b = crate::db::create_database(":memory:").await.unwrap();
        let (db_a, hub_a) = RealtimeHub::install(db_a).await.unwrap();
        let (_db_b, hub_b) = RealtimeHub::install(db_b).await.unwrap();
        let mut a = hub_a.subscribe();
        let mut b = hub_b.subscribe();
        append(
            &db_a,
            spec("4ea17000-0000-4000-8000-000000000004", "record.created"),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), a.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), b.recv())
            .await
            .is_err());
        crate::meta::create_vocabulary(&db_a, "realtime:test-meta-only", None)
            .await
            .unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), a.recv())
            .await
            .is_err());

        let mut slow = hub_a.subscribe();
        for seq in 1..=(HUB_CAPACITY as i64 + 1) {
            let _ = hub_a
                .sender
                .read()
                .unwrap()
                .as_ref()
                .unwrap()
                .send(ContentInvalidation {
                    local_seq: seq,
                    id: format!("event-{seq}"),
                    record_id: "record".into(),
                    event_type: "record.updated".into(),
                    created_at: "now".into(),
                });
        }
        assert!(matches!(
            slow.recv().await,
            Err(broadcast::error::RecvError::Lagged(_))
        ));
        assert_eq!(hub_a.receiver_count(), 2);
    }

    #[tokio::test]
    async fn attach_rejects_a_different_database_without_cross_wiring_the_hub() {
        let db_a = crate::db::create_database(":memory:").await.unwrap();
        let db_b = crate::db::create_database(":memory:").await.unwrap();
        let (db_a, hub_a) = RealtimeHub::install(db_a).await.unwrap();
        let mut receiver = hub_a.subscribe();

        let Err(error) = RealtimeHub::attach(db_b, Some(hub_a.clone())).await else {
            panic!("a realtime hub must not attach to a different database");
        };
        assert!(error
            .to_string()
            .contains("realtime hub database identity mismatch"));

        let committed = append(
            &db_a,
            spec("4ea17000-0000-4000-8000-000000000006", "record.created"),
        )
        .await
        .unwrap();
        let delivered = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.local_seq, committed.local_seq);
    }

    #[tokio::test]
    async fn tail_read_failure_retries_without_advancing_the_cursor() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (db, hub) = RealtimeHub::install(db).await.unwrap();
        let mut receiver = hub.subscribe();
        let before = *hub.last_published_seq.lock().await;

        hub.fail_next_high_water_read.store(true, Ordering::SeqCst);
        let failure_observed = hub.read_failure_observed.notified();
        let committed = append(
            &db,
            spec("4ea17000-0000-4000-8000-000000000005", "record.created"),
        )
        .await
        .unwrap();
        failure_observed.await;

        assert_eq!(*hub.last_published_seq.lock().await, before);
        assert!(matches!(
            receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        hub.read_failure_release.notify_one();
        let delivered = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.local_seq, committed.local_seq);
        assert_eq!(*hub.last_published_seq.lock().await, committed.local_seq);
    }

    #[tokio::test]
    async fn inbox_vector_read_failure_retries_without_another_commit() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (db, hub) = RealtimeHub::install(db).await.unwrap();
        let mut receiver = hub.subscribe_inbox();
        let before = hub.last_inbox_vector.lock().await.clone();

        hub.fail_next_inbox_vector_read
            .store(true, Ordering::SeqCst);
        let failure_observed = hub.inbox_vector_failure_observed.notified();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        sqlx::query("UPDATE authorization_revision SET epoch=epoch+1 WHERE id=1")
            .execute(&mut *tx)
            .await
            .unwrap();
        db.commit_authorization(tx).await.unwrap();
        failure_observed.await;

        assert!(matches!(
            receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
        hub.inbox_vector_failure_release.notify_one();

        let delivered = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.authorization, before.authorization + 1);
        assert_eq!(delivered.content, before.content);
    }
}
