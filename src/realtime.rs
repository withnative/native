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
use crate::need_subscriptions::NeedRegistry;
use crate::query::events::{
    content_high_water_on, content_invalidations_on, content_invalidations_with_act_on,
    content_retention_floor_on,
};

mod personal_registry;
mod personal_registry_test_support;
mod personal_scope;
#[doc(hidden)]
pub use personal_registry_test_support::{
    with_personal_alpha_registry_test_controls, with_personal_alpha_registry_test_controls_sync,
    PersonalAlphaRegistryReadTestPoint, PersonalAlphaRegistryStageTestPoint,
    PersonalAlphaRegistryTestControls,
};
pub use personal_scope::{
    PersonalAlphaRegistryIdentity, PersonalAlphaRegistryObservation, PersonalAlphaRegistryPrompt,
    PersonalAlphaRegistryScope,
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
        // Grant-only revision for the realtime authorization context. The
        // broad `authorization_revision.epoch` stays as the cache fence
        // elsewhere; the stream hashes this governed counter instead, so
        // ordinary creates/deletes/filings do not move it.
        authorization: sqlx::query_scalar(
            "SELECT epoch FROM authorization_grant_revision WHERE id = 1",
        )
        .fetch_one(&mut *tx)
        .await?,
    };
    tx.commit().await?;
    Ok(value)
}

pub async fn inbox_invalidation_vector(db: &Db) -> crate::Result<InboxInvalidationVector> {
    inbox_vector_on(db.write_pool()).await
}

/// Addressed-bell check for one subscriber's inbox prompt.
///
/// Returns true when an `awareness_events` row with `subject_account_id =
/// account` committed with `seq` in `(prev.awareness, cur.awareness]`, or a
/// `notification_candidate_events` row with `recipient_account_id = account`
/// committed with `seq` in `(prev.candidates, cur.candidates]`. Both probes
/// are single-row `LIMIT 1` range reads over the
/// `idx_awareness_events_subject_seq` and
/// `idx_notification_candidate_events_recipient` indexes. Content, control,
/// and authorization movement never rings this bell.
pub async fn inbox_addressed_since(
    pool: &SqlitePool,
    account: &str,
    prev: &InboxInvalidationVector,
    cur: &InboxInvalidationVector,
) -> crate::Result<bool> {
    if cur.awareness > prev.awareness {
        let hit = sqlx::query_scalar::<_, i64>(
            "SELECT seq FROM awareness_events WHERE subject_account_id = ?1 AND seq > ?2 AND seq <= ?3 LIMIT 1",
        )
        .bind(account)
        .bind(prev.awareness)
        .bind(cur.awareness)
        .fetch_optional(pool)
        .await?;
        if hit.is_some() {
            return Ok(true);
        }
    }
    if cur.candidates > prev.candidates {
        let hit = sqlx::query_scalar::<_, i64>(
            "SELECT seq FROM notification_candidate_events WHERE recipient_account_id = ?1 AND seq > ?2 AND seq <= ?3 LIMIT 1",
        )
        .bind(account)
        .bind(prev.candidates)
        .bind(cur.candidates)
        .fetch_optional(pool)
        .await?;
        if hit.is_some() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// One database's bounded live fan-out and durable tail pump.
#[derive(Debug)]
pub struct RealtimeHub {
    database_id: String,
    pool: RwLock<SqlitePool>,
    sender: RwLock<Option<broadcast::Sender<ContentInvalidation>>>,
    inbox_sender: RwLock<Option<broadcast::Sender<InboxInvalidationVector>>>,
    /// Live-tab need subscriptions (task `61e11ad`, design `ee12faf` §2.2).
    /// A hub field so `attach` (hub reuse) and `refresh_pool` (pool swap)
    /// both preserve it: neither path replaces the hub. `std` mutex — the
    /// registry methods are synchronous with short critical sections.
    need_registry: std::sync::Mutex<NeedRegistry>,
    /// M3 server-only bounded counters; never serialized into stream frames.
    need_metrics: std::sync::Mutex<crate::need_metrics::NeedMetrics>,
    /// Random per-hub log correlation token. A replaced hub resets cumulative
    /// metrics, so reports from distinct lifetimes must not be subtracted.
    metrics_hub_id: uuid::Uuid,
    /// Claimed once when the held layer spawns the database's need
    /// scheduler; `attach` reuses the hub, so the flag keeps exactly one
    /// scheduler per database across handle replacements.
    scheduler_claimed: AtomicBool,
    /// Detached scheduler handle and registry acceptance share one slot.
    /// Attach refreshes only the staged pool; router acceptance pairs the
    /// exact handle with its private incarnation. Matched retirement precedes
    /// close. No `Db ↔ hub` cycle or separately sampled authority atomics.
    current_db: RwLock<personal_scope::CurrentDbSlot>,
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
    /// The hub's SQL pool refreshes here; the scheduler's current `Db`
    /// handle moves only when the caller commits it via
    /// `refresh_scheduler_handle` — router acceptance, not `attach` — so a
    /// replacement that fails admission leaves the scheduler serving the
    /// surviving old handle.
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
            need_registry: std::sync::Mutex::new(NeedRegistry::new()),
            need_metrics: std::sync::Mutex::new(crate::need_metrics::NeedMetrics::default()),
            metrics_hub_id: uuid::Uuid::new_v4(),
            scheduler_claimed: AtomicBool::new(false),
            current_db: RwLock::new(personal_scope::CurrentDbSlot::Retired),
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
        hub.set_current_db(installed.clone().without_realtime_hub());
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
                    let page =
                        match content_invalidations_with_act_on(&pool, after, fence, PAGE_SIZE)
                            .await
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
                    for row in page {
                        let envelope = row.envelope;
                        published = envelope.local_seq;
                        // One durable content-log row, before any receiver
                        // sees it. This is the single dirtying point even
                        // when several SSE clients share the same hub.
                        {
                            // Publish the act sample before a scheduler can
                            // pop the newly queued work. Both locks are short
                            // and no await occurs under either one.
                            let mut registry =
                                hub.need_registry.lock().expect("need registry poisoned");
                            let (targets, queued, pending, distinct_act_targets) = registry
                                .mark_content_event_with_act_and_type(
                                    row.act,
                                    Some(&envelope.event_type),
                                );
                            hub.need_metrics
                                .lock()
                                .expect("need metrics poisoned")
                                .note_content_event(
                                    row.act,
                                    distinct_act_targets,
                                    targets,
                                    queued,
                                    pending,
                                );
                        }
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
        {
            let mut slot = self
                .current_db
                .write()
                .expect("realtime current db poisoned");
            self.terminal.store(true, Ordering::SeqCst);
            *slot = personal_scope::CurrentDbSlot::Retired;
        }
        self.sender
            .write()
            .expect("realtime sender poisoned")
            .take();
        self.inbox_sender
            .write()
            .expect("realtime inbox sender poisoned")
            .take();
        // Subscriptions are ephemeral: hub teardown drops them outright.
        self.need_registry
            .lock()
            .expect("need registry poisoned")
            .clear();
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

    /// Token-keyed live-tab need subscriptions on this database's hub
    /// (design `ee12faf` §2.2). Survives `attach`/`refresh_pool` by
    /// construction: both keep the hub. Lock briefly; registry methods are
    /// synchronous and never block on IO.
    pub fn need_registry(&self) -> &std::sync::Mutex<NeedRegistry> {
        &self.need_registry
    }

    pub(crate) fn need_metrics(&self) -> &std::sync::Mutex<crate::need_metrics::NeedMetrics> {
        &self.need_metrics
    }

    pub(crate) fn metrics_hub_id(&self) -> uuid::Uuid {
        self.metrics_hub_id
    }

    /// Deterministic integration-test seam. No identity or digest leaves
    /// the server; production reporting uses the internal tracing target.
    #[doc(hidden)]
    pub fn need_probe_totals_for_tests(&self) -> (u64, u64, u64) {
        let metrics = self.need_metrics.lock().expect("need metrics poisoned");
        (
            metrics.probe_attempts,
            metrics.probe_mismatches,
            metrics.probe_inconclusive,
        )
    }

    #[doc(hidden)]
    pub fn need_clock_probe_totals_for_tests(&self) -> (u64, u64, [u64; 7]) {
        let metrics = self.need_metrics.lock().expect("need metrics poisoned");
        (
            metrics.clock_probe_attempts,
            metrics.clock_probe_mismatches,
            metrics.clock_probe_suppressed,
        )
    }

    /// Probe fence: only compare a sampled digest after the durable content
    /// tail has published through the current high-water mark. This remains
    /// internal; no global sequence enters a need result or frame.
    pub(crate) async fn settled_content_seq(&self) -> Option<i64> {
        let high = self.inbox_invalidation_vector().await.ok()?.content;
        let published = *self.last_published_seq.lock().await;
        (high <= published).then_some(high)
    }

    /// Claim the one scheduler spawn for this database. The held layer calls
    /// this after `attach`; only the first call returns true, so handle
    /// replacements never start a second scheduler on a reused hub.
    pub fn claim_scheduler_spawn(&self) -> bool {
        !self.scheduler_claimed.swap(true, Ordering::SeqCst)
    }

    /// Record the current open handle (detached: no hub back-link). Set at
    /// `install` and committed per accepted handle via
    /// `refresh_scheduler_handle`, so the need scheduler never pins a
    /// handle the router LRU has closed.
    pub(crate) fn set_current_db(&self, db: Db) {
        *self
            .current_db
            .write()
            .expect("realtime current db poisoned") =
            personal_scope::CurrentDbSlot::Provisional(db);
    }

    /// Router acceptance, under its cache-admission mutex. Only a different
    /// accepted handle mints an incarnation; staged attach never reaches here.
    pub fn refresh_scheduler_handle(&self, db: &Db) {
        let mut slot = self
            .current_db
            .write()
            .expect("realtime current db poisoned");
        if self.terminal.load(Ordering::SeqCst) {
            return;
        }
        let incarnation = match &*slot {
            personal_scope::CurrentDbSlot::Accepted {
                db: current,
                incarnation,
            } if current.handle_id() == db.handle_id() => incarnation.clone(),
            _ => Arc::new(personal_scope::Incarnation),
        };
        *slot = personal_scope::CurrentDbSlot::Accepted {
            db: db.clone().without_realtime_hub(),
            incarnation,
        };
    }

    /// Synchronous matched retirement before the router schedules pool close.
    /// Retiring an old or rejected staged handle cannot retire a replacement.
    #[doc(hidden)]
    pub fn retire_scheduler_handle(&self, db: &Db) {
        let mut slot = if let Some(controls) = personal_registry_test_support::current() {
            match self.current_db.try_write() {
                Ok(slot) => slot,
                Err(std::sync::TryLockError::WouldBlock) => {
                    controls.retirement_contended();
                    self.current_db
                        .write()
                        .expect("realtime current db poisoned")
                }
                Err(std::sync::TryLockError::Poisoned(_)) => panic!("realtime current db poisoned"),
            }
        } else {
            self.current_db
                .write()
                .expect("realtime current db poisoned")
        };
        if slot
            .db()
            .is_some_and(|current| current.handle_id() == db.handle_id())
        {
            *slot = personal_scope::CurrentDbSlot::Retired;
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.terminal.load(Ordering::SeqCst)
    }

    /// Existing scheduler facade; provisional handles remain usable during
    /// installation, while retired/terminal handles cannot start re-runs.
    pub(crate) fn current_db(&self) -> Option<Db> {
        self.current_db
            .read()
            .expect("realtime current db poisoned")
            .db()
            .filter(|db| !db.pool().is_closed() && !db.write_pool().is_closed())
            .cloned()
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

    /// Whether the inbox wake-up between two vectors addresses `account`: an
    /// awareness row with this viewer as subject, or a notification candidate
    /// with this viewer as recipient, committed in the covered range.
    pub async fn inbox_addressed_since(
        &self,
        account: &str,
        prev: &InboxInvalidationVector,
        cur: &InboxInvalidationVector,
    ) -> crate::Result<bool> {
        inbox_addressed_since(&self.current_pool(), account, prev, cur).await
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
    /// `is_member` is the subscriber's subscribe-time catalog footing: guests
    /// evaluate with their own account grants only, never the members
    /// baseline.
    pub async fn can_view_invalidation_for_account(
        &self,
        account_id: &str,
        is_member: bool,
        envelope: &ContentInvalidation,
    ) -> bool {
        if matches!(
            envelope.event_type.as_str(),
            "reconciliation.recorded.v1" | "unit.superseded.v1" | "receipt.dependency_audited.v1"
        ) {
            return false;
        }
        let pool = self.current_pool();
        let principal = Principal::bound(account_id, is_member);
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
    use crate::need_subscriptions::{params_digest, SurfaceBinding};
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
        let mut act_alloc = crate::act::ActAllocation::new();
        append_in(
            &db,
            &mut tx,
            spec("4ea17000-0000-4000-8000-000000000003", "record.created"),
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), receiver.recv())
                .await
                .is_err()
        );
        assert_eq!(hub.need_metrics().lock().unwrap().known_content_acts, 1);
    }

    #[tokio::test]
    async fn one_content_commit_with_two_events_queues_one_need_rerun() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (db, hub) = RealtimeHub::install(db).await.unwrap();
        let mut first_receiver = hub.subscribe();
        let mut second_receiver = hub.subscribe();
        let token = {
            let mut needs = hub.need_registry().lock().unwrap();
            let token = needs.register_connection("alice", "db-1", true);
            let id = needs
                .subscribe_pending(
                    &token,
                    "alice",
                    "db-1",
                    SurfaceBinding::alpha_tab("agent.attention-cockpit", "event-1"),
                    "attention.query.v1",
                    &params_digest(None),
                )
                .unwrap();
            needs.activate(&token, &id, "held");
            token
        };
        let events = append_batch(
            &db,
            vec![
                spec("4ea17000-0000-4000-8000-000000000011", "record.created"),
                spec("4ea17000-0000-4000-8000-000000000012", "record.created"),
            ],
        )
        .await
        .unwrap();
        wait_until_published_for_tests(&db, events[1].local_seq).await;
        for _ in 0..2 {
            assert!(first_receiver.try_recv().is_ok());
            assert!(second_receiver.try_recv().is_ok());
        }
        let metrics = hub.need_metrics().lock().unwrap().clone();
        assert_eq!(metrics.known_content_acts, 1);
        assert_eq!(metrics.known_act_distinct_dirtied_targets, 1);
        assert_eq!(metrics.recent_acts[0].content_events, 2);
        assert_eq!(metrics.content_events, 2);
        assert_eq!(metrics.content_event_queue_inserts, 1);
        assert_eq!(metrics.content_event_coalesced, 1);
        assert_eq!(hub.need_registry().lock().unwrap().dirty_len(&token), 1);
    }

    #[tokio::test]
    async fn content_event_marks_need_without_any_broadcast_receiver() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (db, hub) = RealtimeHub::install(db).await.unwrap();
        let token = {
            let mut needs = hub.need_registry().lock().unwrap();
            let token = needs.register_connection("alice", "db-1", true);
            let id = needs
                .subscribe_pending(
                    &token,
                    "alice",
                    "db-1",
                    SurfaceBinding::alpha_tab("agent.attention-cockpit", "event-1"),
                    "attention.query.v1",
                    &params_digest(None),
                )
                .unwrap();
            needs.activate(&token, &id, "held");
            token
        };
        let event = append(
            &db,
            spec("4ea17000-0000-4000-8000-000000000013", "record.created"),
        )
        .await
        .unwrap();
        wait_until_published_for_tests(&db, event.local_seq).await;
        assert_eq!(hub.need_registry().lock().unwrap().dirty_len(&token), 1);
        assert_eq!(hub.need_metrics().lock().unwrap().content_events, 1);
    }

    #[tokio::test]
    async fn lagged_content_receiver_does_not_lose_the_single_hub_wake() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (db, hub) = RealtimeHub::install(db).await.unwrap();
        let mut slow = hub.subscribe();
        let token = {
            let mut needs = hub.need_registry().lock().unwrap();
            let token = needs.register_connection("alice", "db-1", true);
            let id = needs
                .subscribe_pending(
                    &token,
                    "alice",
                    "db-1",
                    SurfaceBinding::alpha_tab("agent.attention-cockpit", "event-1"),
                    "attention.query.v1",
                    &params_digest(None),
                )
                .unwrap();
            needs.activate(&token, &id, "held");
            token
        };
        let specs = (0..=HUB_CAPACITY)
            .map(|index| {
                spec(
                    &format!("4ea17000-0000-4000-8000-{index:012x}"),
                    "record.created",
                )
            })
            .collect();
        let events = append_batch(&db, specs).await.unwrap();
        wait_until_published_for_tests(&db, events.last().unwrap().local_seq).await;
        assert!(matches!(
            slow.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(_))
        ));
        assert_eq!(hub.need_registry().lock().unwrap().dirty_len(&token), 1);
        let metrics = hub.need_metrics().lock().unwrap().clone();
        assert_eq!(metrics.content_events, (HUB_CAPACITY + 1) as u64);
        assert_eq!(metrics.content_event_queue_inserts, 1);
        assert_eq!(metrics.known_content_acts, 1);
        assert_eq!(
            metrics.recent_acts[0].content_events,
            (HUB_CAPACITY + 1) as u64
        );
        assert_eq!(metrics.recent_acts[0].distinct_dirtied_targets, 1);
    }

    #[tokio::test]
    async fn null_act_content_is_counted_without_inventing_a_transaction() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (db, hub) = RealtimeHub::install(db).await.unwrap();
        let (token, id) = {
            let mut needs = hub.need_registry().lock().unwrap();
            let token = needs.register_connection("alice", "db-1", true);
            let id = needs
                .subscribe_pending(
                    &token,
                    "alice",
                    "db-1",
                    SurfaceBinding::alpha_tab("agent.attention-cockpit", "event-1"),
                    "attention.query.v1",
                    &params_digest(None),
                )
                .unwrap();
            needs.activate(&token, &id, "held");
            (token, id)
        };
        let seq: i64 = sqlx::query_scalar(
            "INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status)
             VALUES('m3-null-act','4ea17000-0000-4000-8000-00000000abcd','record.created','{}','engine:seed','2026-01-01T00:00:00.000Z',1,'legacy_unknown')
             RETURNING seq",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        hub.wake();
        wait_until_published_for_tests(&db, seq).await;
        let metrics = hub.need_metrics().lock().unwrap().clone();
        assert_eq!(metrics.known_content_acts, 0);
        assert_eq!(metrics.unknown_act_events, 1);
        assert_eq!(metrics.unknown_act_target_pairs, 1);
        let mut needs = hub.need_registry().lock().unwrap();
        needs.pop_dirty(&token).unwrap();
        let measurement = needs.clear_dirty(&token, &id).unwrap();
        assert!(measurement.unknown_act);
        assert!(measurement.content_acts.is_empty());
    }

    #[tokio::test]
    async fn awareness_commit_advances_inbox_vector_without_content_or_delivery_claims() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let (db, hub) = RealtimeHub::install(db).await.unwrap();
        let before = inbox_invalidation_vector(&db).await.unwrap();
        let mut receiver = hub.subscribe_inbox();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
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
            &mut act_alloc,
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
    async fn need_registry_survives_attach_and_refresh_pool() {
        use crate::need_subscriptions::{params_digest, SurfaceBinding};

        // Production reopens reach `attach` with the hub the router retained
        // for the database id (`held/hosting/src/hosting/router.rs`); a
        // clone carries the same identity, exercising the reuse branch.
        // (Reopening one SQLite file twice concurrently is unsupported by
        // `create_database` migrations — "table content_events already
        // exists" — so the test does not reopen the file.)
        let db_first = crate::db::create_database(":memory:").await.unwrap();
        let (db_first, hub) = RealtimeHub::install(db_first).await.unwrap();
        let digest = params_digest(None);
        let token = hub
            .need_registry()
            .lock()
            .expect("need registry poisoned")
            .register_connection("alice", "db-1", true);
        hub.need_registry()
            .lock()
            .expect("need registry poisoned")
            .subscribe_pending(
                &token,
                "alice",
                "db-1",
                SurfaceBinding::alpha_tab("agent.attention-cockpit", "event-1"),
                "attention.query.v1",
                &digest,
            )
            .unwrap();
        // A pool refresh swaps the pool only; the registry is a hub field.
        hub.refresh_pool(db_first.write_pool().clone());
        // `attach` with the retained hub reuses it (same database identity),
        // so the connection and its subscription survive handle replacement.
        let (_db_reopened, hub_reused) = RealtimeHub::attach(db_first.clone(), Some(hub.clone()))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&hub, &hub_reused));
        assert_eq!(
            hub_reused
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .connection_subscription_count(&token),
            1
        );
        // Hub teardown retires the registry with it: subscriptions are
        // ephemeral and never outlive the hub.
        hub_reused.terminalize();
        assert_eq!(
            hub_reused
                .need_registry()
                .lock()
                .expect("need registry poisoned")
                .connection_subscription_count(&token),
            0
        );
    }

    #[tokio::test]
    async fn scheduler_handle_commits_only_at_acceptance() {
        // Handle replacement as the router does it: open the replacement
        // before closing the old handle, `attach` for hub reuse, commit the
        // scheduler handle only at acceptance.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scheduler-handle.db");
        let db_first = crate::db::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        let (db_first, hub) = RealtimeHub::install(db_first).await.unwrap();
        assert_eq!(
            hub.current_db()
                .expect("hub holds its install handle")
                .handle_id(),
            db_first.handle_id()
        );
        let db_second = crate::db::open_existing_database(path.to_str().unwrap())
            .await
            .unwrap();
        let (db_second, hub_reused) = RealtimeHub::attach(db_second, Some(hub.clone()))
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&hub, &hub_reused));
        // Staged, not committed: a replacement that fails admission must
        // leave the scheduler serving the surviving old handle.
        assert_eq!(
            hub.current_db()
                .expect("hub still serves the old handle")
                .handle_id(),
            db_first.handle_id()
        );
        hub.refresh_scheduler_handle(&db_second);
        assert_eq!(
            hub.current_db().expect("committed handle").handle_id(),
            db_second.handle_id()
        );
        // Closing the replaced handle leaves the committed one usable: read
        // through the scheduler's handle itself, not the hub pool (which
        // `attach` refreshes pre-acceptance and is a separate path).
        db_first.close().await;
        let current = hub.current_db().expect("committed handle survives");
        assert_eq!(current.handle_id(), db_second.handle_id());
        assert!(crate::identity::database_id(&current).await.is_ok());
        assert!(hub.claim_scheduler_spawn());
        assert!(!hub.claim_scheduler_spawn());
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
        sqlx::query("UPDATE authorization_grant_revision SET epoch=epoch+1 WHERE id=1")
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
