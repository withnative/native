use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Bytes};
use axum::extract::{ConnectInfo, Path as AxumPath, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use rand::RngCore as _;
use rusqlite::OpenFlags;
use serde_json::{json, Map, Value};
use sha2::Sha256;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, Sqlite, SqlitePool, Transaction};
use tokio::sync::Notify;
use uuid::Uuid;

use super::authority::{
    AuthenticatedCaller, DirectoryAuthority, PrincipalAddress, RecipientAuthorization,
};
use super::crypto::{
    canonical_json, decode_base64url, digest_value, parse_ijson, sha256_digest, sign_detached,
    PROFILE,
};

const PROTOCOL_VERSION: &str = "1.0";
const CAPABILITY_RECEIPTS: &str = "native.relay.receipts";
const MAX_ENVELOPE_LIFETIME_DAYS: i64 = 30;

#[derive(Debug, Clone)]
pub struct RelayLimits {
    pub max_envelope_bytes: usize,
    pub max_recipients: usize,
    pub max_collection: usize,
    pub max_wait: Duration,
    pub lease_duration: Duration,
    pub default_expiry: Duration,
    pub retention: Duration,
    pub terminal_retention: Duration,
    pub mailbox_bytes: i64,
    pub mailbox_deliveries: i64,
    pub sender_requests_per_minute: i64,
    pub sender_deliveries_per_day: i64,
    pub recipient_ingress_per_day: i64,
    pub source_requests_per_minute: i64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: 1_048_576,
            max_recipients: 128,
            max_collection: 100,
            max_wait: Duration::from_secs(30),
            lease_duration: Duration::from_secs(300),
            default_expiry: Duration::from_secs(7 * 24 * 60 * 60),
            retention: Duration::from_secs(7 * 24 * 60 * 60),
            terminal_retention: Duration::from_secs(30 * 24 * 60 * 60),
            mailbox_bytes: 256 * 1024 * 1024,
            mailbox_deliveries: 10_000,
            sender_requests_per_minute: 60,
            sender_deliveries_per_day: 10_000,
            recipient_ingress_per_day: 10_000,
            source_requests_per_minute: 120,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub public_origin: String,
    pub limits: RelayLimits,
}

pub trait RelayClock: Send + Sync + 'static {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug)]
pub struct SystemClock;

impl RelayClock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

pub trait RelaySigner: Send + Sync + 'static {
    fn relay_id(&self) -> &str;
    fn key_id(&self) -> &str;
    fn sign_receipt(&self, receipt: &Value) -> Result<String, RelayError>;
}

/// Best-effort push seam. The token is only a wake hint; collection remains
/// the authenticated authority for delivery.
pub trait DeliveryNotifier: Send + Sync + 'static {
    fn delivery_available(&self, recipient: &PrincipalAddress, wake_token: &str);
}

struct NoopNotifier;

impl DeliveryNotifier for NoopNotifier {
    fn delivery_available(&self, _recipient: &PrincipalAddress, _wake_token: &str) {}
}

pub struct Ed25519RelaySigner {
    relay_id: String,
    key_id: String,
    key: SigningKey,
}

impl Ed25519RelaySigner {
    pub fn new(relay_id: String, key_id: String, key: SigningKey) -> Result<Self, RelayError> {
        if !key_id.starts_with("n1.relay.") {
            return Err(RelayError::invalid_request(
                "relay signing kid must use the n1.relay namespace",
            ));
        }
        Ok(Self {
            relay_id,
            key_id,
            key,
        })
    }
}

impl RelaySigner for Ed25519RelaySigner {
    fn relay_id(&self) -> &str {
        &self.relay_id
    }

    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn sign_receipt(&self, receipt: &Value) -> Result<String, RelayError> {
        sign_detached(receipt, &self.key, &self.key_id, "native-relay-receipt+jws")
    }
}

#[derive(Debug, Clone)]
pub struct RelayError {
    pub code: &'static str,
    pub detail: String,
    pub retry_after: Option<u64>,
}

impl RelayError {
    pub fn named(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
            retry_after: None,
        }
    }

    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self::named("invalid_request", detail)
    }
    pub fn malformed_envelope(detail: impl Into<String>) -> Self {
        Self::named("malformed_envelope", detail)
    }
    pub fn signature_invalid(detail: impl Into<String>) -> Self {
        Self::named("signature_invalid", detail)
    }
    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::named("unauthorized", detail)
    }
    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::named("forbidden", detail)
    }
    pub fn unknown_principal(detail: impl Into<String>) -> Self {
        Self::named("unknown_principal", detail)
    }
    pub fn principal_revoked(detail: impl Into<String>) -> Self {
        Self::named("principal_revoked", detail)
    }
    pub fn key_revoked(detail: impl Into<String>) -> Self {
        Self::named("key_revoked", detail)
    }
    pub fn directory_unavailable(detail: impl Into<String>) -> Self {
        Self::named("directory_unavailable", detail)
    }
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::named("internal", detail)
    }
    fn retryable(mut self, seconds: u64) -> Self {
        self.retry_after = Some(seconds);
        self
    }
    fn status(&self) -> StatusCode {
        match self.code {
            "invalid_request" | "malformed_envelope" | "signature_invalid"
            | "recipient_mismatch" => StatusCode::BAD_REQUEST,
            "unauthorized" => StatusCode::UNAUTHORIZED,
            "forbidden" => StatusCode::FORBIDDEN,
            "unknown_principal" | "delivery_unknown" => StatusCode::NOT_FOUND,
            "principal_revoked" | "key_revoked" | "expired" => StatusCode::GONE,
            "idempotency_conflict" | "delivery_terminal" => StatusCode::CONFLICT,
            "required_capability_unsupported" => StatusCode::UNPROCESSABLE_ENTITY,
            "payload_too_large" => StatusCode::PAYLOAD_TOO_LARGE,
            "unsupported_media_type" => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "rate_limited" | "quota_exceeded" => StatusCode::TOO_MANY_REQUESTS,
            "directory_unavailable" | "relay_unavailable" => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for RelayError {}

fn db_error(error: sqlx::Error) -> RelayError {
    RelayError::internal(format!("relay database operation failed: {error}"))
}

pub struct Relay {
    pool: SqlitePool,
    authority: Arc<dyn DirectoryAuthority>,
    signer: Arc<dyn RelaySigner>,
    clock: Arc<dyn RelayClock>,
    notifier: Arc<dyn DeliveryNotifier>,
    config: RelayConfig,
    notify: Notify,
    cursor_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupReport {
    pub expired: u64,
    pub ciphertext_deleted: u64,
    pub tombstones_deleted: u64,
    pub request_proofs_deleted: u64,
    pub rate_counters_deleted: u64,
    pub envelope_replays_deleted: u64,
}

impl Relay {
    pub async fn open(
        path: impl AsRef<Path>,
        config: RelayConfig,
        authority: Arc<dyn DirectoryAuthority>,
        signer: Arc<dyn RelaySigner>,
        clock: Arc<dyn RelayClock>,
    ) -> Result<Arc<Self>, RelayError> {
        Self::open_with_notifier(
            path,
            config,
            authority,
            signer,
            clock,
            Arc::new(NoopNotifier),
        )
        .await
    }

    pub async fn open_with_notifier(
        path: impl AsRef<Path>,
        config: RelayConfig,
        authority: Arc<dyn DirectoryAuthority>,
        signer: Arc<dyn RelaySigner>,
        clock: Arc<dyn RelayClock>,
        notifier: Arc<dyn DeliveryNotifier>,
    ) -> Result<Arc<Self>, RelayError> {
        validate_config(&config)?;
        let path = path.as_ref();
        validate_database_target(path)?;
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .map_err(db_error)?;
        initialize(&pool).await?;
        let cursor_key = load_cursor_key(&pool).await?;
        Ok(Arc::new(Self {
            pool,
            authority,
            signer,
            clock,
            notifier,
            config,
            notify: Notify::new(),
            cursor_key,
        }))
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub async fn healthy(&self) -> bool {
        sqlx::query_scalar::<_, i64>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok()
    }

    pub async fn cleanup(&self) -> Result<CleanupReport, RelayError> {
        let now = self.clock.now();
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let due = sqlx::query(
            "SELECT delivery_id, envelope_id, envelope_digest, recipient_network, recipient_id, state \
             FROM relay_deliveries WHERE state IN ('queued','collected') AND effective_expiry <= ?",
        )
        .bind(format_time(now))
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        for row in &due {
            let previous: String = row.get("state");
            let receipt = self.receipt(
                row.get("delivery_id"),
                row.get("envelope_id"),
                row.get("envelope_digest"),
                PrincipalAddress {
                    network_id: row.get("recipient_network"),
                    principal_id: row.get("recipient_id"),
                },
                "rejected",
                Some(&previous),
                None,
                Some("expired"),
                now,
            )?;
            sqlx::query(
                "UPDATE relay_deliveries SET state='rejected', rejection_reason='expired', \
                 rejected_receipt=?, envelope_json=NULL, terminal_at=?, ciphertext_delete_at=NULL, \
                 lease_token=NULL, lease_expires_at=NULL WHERE delivery_id=?",
            )
            .bind(
                serde_json::to_vec(&receipt)
                    .map_err(|_| RelayError::internal("receipt encoding failed"))?,
            )
            .bind(format_time(now))
            .bind(row.get::<String, _>("delivery_id"))
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
        }
        let ciphertext_deleted = sqlx::query(
            "UPDATE relay_deliveries SET envelope_json=NULL, ciphertext_delete_at=NULL \
             WHERE ciphertext_delete_at IS NOT NULL AND ciphertext_delete_at <= ?",
        )
        .bind(format_time(now))
        .execute(&mut *tx)
        .await
        .map_err(db_error)?
        .rows_affected();
        let tombstones_deleted = sqlx::query(
            "DELETE FROM relay_deliveries WHERE terminal_at IS NOT NULL AND terminal_at <= ?",
        )
        .bind(format_time(
            now - chrono::Duration::from_std(self.config.limits.terminal_retention)
                .map_err(|_| RelayError::internal("invalid terminal retention"))?,
        ))
        .execute(&mut *tx)
        .await
        .map_err(db_error)?
        .rows_affected();
        let request_proofs_deleted =
            sqlx::query("DELETE FROM relay_request_proofs WHERE expires_at <= ?")
                .bind(format_time(now))
                .execute(&mut *tx)
                .await
                .map_err(db_error)?
                .rows_affected();
        let rate_counters_deleted =
            sqlx::query("DELETE FROM relay_rate_counters WHERE window_start < ?")
                .bind(now.timestamp() - 2 * 24 * 60 * 60)
                .execute(&mut *tx)
                .await
                .map_err(db_error)?
                .rows_affected();
        let envelope_replays_deleted =
            sqlx::query("DELETE FROM relay_envelopes WHERE retain_until <= ?")
                .bind(format_time(now))
                .execute(&mut *tx)
                .await
                .map_err(db_error)?
                .rows_affected();
        tx.commit().await.map_err(db_error)?;
        Ok(CleanupReport {
            expired: due.len() as u64,
            ciphertext_deleted,
            tombstones_deleted,
            request_proofs_deleted,
            rate_counters_deleted,
            envelope_replays_deleted,
        })
    }

    fn authenticate(
        &self,
        headers: &HeaderMap,
        operation: &str,
        body: &[u8],
    ) -> Result<AuthenticatedCaller, RelayError> {
        let authorization = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok());
        self.authority.verify_request(
            authorization,
            operation,
            &self.config.public_origin,
            body,
            self.clock.now(),
        )
    }

    async fn claim_proof(&self, caller: &AuthenticatedCaller) -> Result<(), RelayError> {
        let expires_at = format_time(self.clock.now() + chrono::Duration::minutes(10));
        let result = sqlx::query(
            "INSERT INTO relay_request_proofs(kid, nonce, request_id, body_digest, expires_at) \
             VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING",
        )
        .bind(&caller.key_id)
        .bind(&caller.nonce)
        .bind(&caller.request_id)
        .bind(&caller.body_digest)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(db_error)?;
        if result.rows_affected() == 1 {
            return Ok(());
        }
        let rows = sqlx::query(
            "SELECT request_id, body_digest FROM relay_request_proofs \
             WHERE kid=? AND (nonce=? OR request_id=?)",
        )
        .bind(&caller.key_id)
        .bind(&caller.nonce)
        .bind(&caller.request_id)
        .fetch_all(&self.pool)
        .await
        .map_err(db_error)?;
        if rows.len() == 1
            && rows[0].get::<String, _>("request_id") == caller.request_id
            && rows[0].get::<String, _>("body_digest") == caller.body_digest
        {
            Ok(())
        } else {
            Err(RelayError::named(
                "idempotency_conflict",
                "request proof nonce or request id was reused with another request",
            ))
        }
    }

    async fn check_rate(
        &self,
        scope: &str,
        key: &str,
        limit: i64,
        window: Duration,
    ) -> Result<(), RelayError> {
        if limit <= 0 {
            return Ok(());
        }
        let now = self.clock.now().timestamp();
        let seconds = window.as_secs() as i64;
        let window_start = now - now.rem_euclid(seconds);
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        sqlx::query(
            "INSERT INTO relay_rate_counters(scope, subject, window_start, count) VALUES(?,?,?,1) \
             ON CONFLICT(scope,subject,window_start) DO UPDATE SET count=count+1",
        )
        .bind(scope)
        .bind(key)
        .bind(window_start)
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let count: i64 = sqlx::query_scalar(
            "SELECT count FROM relay_rate_counters WHERE scope=? AND subject=? AND window_start=?",
        )
        .bind(scope)
        .bind(key)
        .bind(window_start)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        if count > limit {
            return Err(RelayError::named("rate_limited", "request rate exceeded")
                .retryable((window_start + seconds - now).max(1) as u64));
        }
        Ok(())
    }

    async fn submit(&self, caller: &AuthenticatedCaller, body: Value) -> Result<Value, RelayError> {
        let object = exact_object(&body, &["operation", "envelope"])?;
        if required_string(object, "operation")? != "relay.submit" {
            return Err(RelayError::invalid_request("operation mismatch"));
        }
        let wrapper = object
            .get("envelope")
            .ok_or_else(|| RelayError::invalid_request("missing envelope"))?;
        let validated = self.validate_envelope(wrapper)?;
        let sender = self
            .authority
            .verify_envelope_sender(wrapper, self.clock.now())?;
        if sender != caller.principal {
            return Err(RelayError::forbidden(
                "request proof principal does not match envelope sender",
            ));
        }
        self.cleanup().await?;
        self.check_rate(
            "sender-submit",
            &sender.storage_key(),
            self.config.limits.sender_requests_per_minute,
            Duration::from_secs(60),
        )
        .await?;

        let mut recipient_decisions = Vec::with_capacity(validated.recipients.len());
        for recipient in &validated.recipients {
            recipient_decisions.push(self.authority.authorize_recipient(
                &recipient.principal,
                &recipient.encryption_key_id,
                self.clock.now(),
            )?);
        }
        let now = self.clock.now();
        let wrapper_bytes = canonical_json(wrapper)?;
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let retain_until = std::cmp::max(
            validated.effective_expiry,
            now + chrono::Duration::from_std(self.config.limits.terminal_retention)
                .map_err(|_| RelayError::internal("invalid replay retention"))?,
        );
        sqlx::query(
            "INSERT INTO relay_envelopes(sender_network,sender_id,envelope_id,envelope_digest,retain_until) \
             VALUES(?,?,?,?,?) ON CONFLICT(sender_network,sender_id,envelope_id) DO UPDATE SET \
             retain_until=MAX(relay_envelopes.retain_until,excluded.retain_until)",
        )
        .bind(&sender.network_id)
        .bind(&sender.principal_id)
        .bind(&validated.envelope_id)
        .bind(&validated.digest)
        .bind(format_time(retain_until))
        .execute(&mut *tx)
        .await
        .map_err(db_error)?;
        let existing_digest: String = sqlx::query_scalar(
            "SELECT envelope_digest FROM relay_envelopes \
             WHERE sender_network=? AND sender_id=? AND envelope_id=?",
        )
        .bind(&sender.network_id)
        .bind(&sender.principal_id)
        .bind(&validated.envelope_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        if existing_digest != validated.digest {
            return Err(RelayError::named(
                "idempotency_conflict",
                "envelope id was reused with different signed bytes",
            ));
        }

        let sender_day_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM relay_deliveries WHERE sender_network=? AND sender_id=? AND created_at>=?",
        )
        .bind(&sender.network_id)
        .bind(&sender.principal_id)
        .bind(format_time(now - chrono::Duration::days(1)))
        .fetch_one(&mut *tx)
        .await
        .map_err(db_error)?;
        let sender_limited = sender_day_count + validated.recipients.len() as i64
            > self.config.limits.sender_deliveries_per_day;
        let mut results = Vec::with_capacity(validated.recipients.len());
        let mut created_any = false;
        let mut wake_recipients = Vec::new();
        for (recipient, decision) in validated.recipients.iter().zip(recipient_decisions) {
            if let Some(row) = existing_delivery(
                &mut tx,
                &sender,
                &validated.envelope_id,
                &recipient.principal,
            )
            .await?
            {
                results.push(result_from_existing(&row)?);
                continue;
            }
            if sender_limited {
                results.push(error_result(&recipient.principal, "rate_limited", 86_400));
                continue;
            }
            if let RecipientAuthorization::Rejected(reason) = decision {
                let delivery_id = Uuid::new_v4().to_string();
                let receipt = self.receipt(
                    &delivery_id,
                    &validated.envelope_id,
                    &validated.digest,
                    recipient.principal.clone(),
                    "rejected",
                    None,
                    None,
                    Some(reason),
                    now,
                )?;
                let receipt_bytes = serde_json::to_vec(&receipt)
                    .map_err(|_| RelayError::internal("receipt encoding failed"))?;
                insert_delivery(
                    &mut tx,
                    &delivery_id,
                    &sender,
                    &validated,
                    &recipient.principal,
                    "rejected",
                    Some(reason),
                    None,
                    Some(&receipt_bytes),
                    now,
                )
                .await?;
                results.push(json!({
                    "recipient": recipient.principal,
                    "outcome": "rejected",
                    "delivery_id": delivery_id,
                    "code": reason,
                    "receipt": receipt
                }));
                continue;
            }
            let (active_count, active_bytes): (i64, i64) = sqlx::query_as(
                "SELECT COUNT(*), COALESCE(SUM(envelope_bytes),0) FROM relay_deliveries \
                 WHERE recipient_network=? AND recipient_id=? AND state IN ('queued','collected')",
            )
            .bind(&recipient.principal.network_id)
            .bind(&recipient.principal.principal_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?;
            let ingress_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM relay_deliveries WHERE recipient_network=? AND recipient_id=? AND created_at>=?",
            )
            .bind(&recipient.principal.network_id)
            .bind(&recipient.principal.principal_id)
            .bind(format_time(now - chrono::Duration::days(1)))
            .fetch_one(&mut *tx)
            .await
            .map_err(db_error)?;
            if active_count + 1 > self.config.limits.mailbox_deliveries
                || active_bytes + validated.envelope_bytes as i64 > self.config.limits.mailbox_bytes
                || ingress_count + 1 > self.config.limits.recipient_ingress_per_day
            {
                results.push(error_result(&recipient.principal, "quota_exceeded", 3600));
                continue;
            }
            let delivery_id = Uuid::new_v4().to_string();
            let receipt = self.receipt(
                &delivery_id,
                &validated.envelope_id,
                &validated.digest,
                recipient.principal.clone(),
                "queued",
                None,
                None,
                None,
                now,
            )?;
            let receipt_bytes = serde_json::to_vec(&receipt)
                .map_err(|_| RelayError::internal("receipt encoding failed"))?;
            insert_delivery(
                &mut tx,
                &delivery_id,
                &sender,
                &validated,
                &recipient.principal,
                "queued",
                None,
                Some(&wrapper_bytes),
                Some(&receipt_bytes),
                now,
            )
            .await?;
            created_any = true;
            wake_recipients.push(recipient.principal.clone());
            results.push(json!({
                "recipient": recipient.principal,
                "outcome": "queued",
                "delivery_id": delivery_id,
                "receipt": receipt
            }));
        }
        tx.commit().await.map_err(db_error)?;
        if created_any {
            self.notify.notify_waiters();
            for recipient in wake_recipients {
                self.notifier
                    .delivery_available(&recipient, &random_token(16));
            }
        }
        Ok(json!({
            "operation": "relay.submit.result",
            "envelope_id": validated.envelope_id,
            "envelope_digest": validated.digest,
            "results": results
        }))
    }

    async fn collect(
        &self,
        caller: &AuthenticatedCaller,
        installation_id: &str,
        body: Value,
    ) -> Result<Value, RelayError> {
        if caller.installation_id.as_deref() != Some(installation_id) {
            return Err(RelayError::forbidden("collector installation mismatch"));
        }
        self.cleanup().await?;
        let object = body
            .as_object()
            .ok_or_else(|| RelayError::invalid_request("body must be an object"))?;
        let allowed: HashSet<_> = ["operation", "cursor", "limit", "wait_seconds"]
            .into_iter()
            .collect();
        if object.keys().any(|key| !allowed.contains(key.as_str()))
            || required_string(object, "operation")? != "relay.collect"
        {
            return Err(RelayError::invalid_request("invalid collect body"));
        }
        let limit = object
            .get("limit")
            .and_then(Value::as_u64)
            .ok_or_else(|| RelayError::invalid_request("invalid collection limit"))?
            as usize;
        let wait_seconds = object
            .get("wait_seconds")
            .and_then(Value::as_u64)
            .ok_or_else(|| RelayError::invalid_request("invalid wait_seconds"))?;
        if limit == 0
            || limit > self.config.limits.max_collection
            || wait_seconds > self.config.limits.max_wait.as_secs()
        {
            return Err(RelayError::invalid_request("collection bounds exceeded"));
        }
        if let Some(cursor) = object.get("cursor").and_then(Value::as_str) {
            self.verify_cursor(cursor, &caller.principal, installation_id)?;
        }
        let mut result = self.collect_now(caller, installation_id, limit).await?;
        if result
            .get("deliveries")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
            && wait_seconds > 0
        {
            let notified = self.notify.notified();
            let _ = tokio::time::timeout(Duration::from_secs(wait_seconds), notified).await;
            result = self.collect_now(caller, installation_id, limit).await?;
        }
        Ok(result)
    }

    async fn collect_now(
        &self,
        caller: &AuthenticatedCaller,
        installation_id: &str,
        limit: usize,
    ) -> Result<Value, RelayError> {
        let now = self.clock.now();
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let rows = sqlx::query(
            "SELECT * FROM relay_deliveries WHERE recipient_network=? AND recipient_id=? \
             AND state IN ('queued','collected') AND effective_expiry>? \
             AND (lease_expires_at IS NULL OR lease_expires_at<=?) ORDER BY created_at, delivery_id LIMIT ?",
        )
        .bind(&caller.principal.network_id)
        .bind(&caller.principal.principal_id)
        .bind(format_time(now))
        .bind(format_time(now))
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await
        .map_err(db_error)?;
        let mut deliveries = Vec::with_capacity(rows.len());
        for row in rows {
            let state: String = row.get("state");
            let attempt = row.get::<i64, _>("attempt") + 1;
            let lease_token = random_token(32);
            let lease_expires = now
                + chrono::Duration::from_std(self.config.limits.lease_duration)
                    .map_err(|_| RelayError::internal("invalid lease duration"))?;
            let collected_receipt = if state == "queued" {
                Some(self.receipt(
                    row.get("delivery_id"),
                    row.get("envelope_id"),
                    row.get("envelope_digest"),
                    PrincipalAddress {
                        network_id: row.get("recipient_network"),
                        principal_id: row.get("recipient_id"),
                    },
                    "collected",
                    Some("queued"),
                    Some(installation_id),
                    None,
                    now,
                )?)
            } else {
                row.try_get::<Option<Vec<u8>>, _>("collected_receipt")
                    .map_err(db_error)?
                    .map(|bytes| serde_json::from_slice(&bytes))
                    .transpose()
                    .map_err(|_| RelayError::internal("stored receipt is invalid"))?
            };
            let collected_bytes = collected_receipt
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()
                .map_err(|_| RelayError::internal("receipt encoding failed"))?;
            sqlx::query(
                "UPDATE relay_deliveries SET state='collected', attempt=?, lease_token=?, \
                 lease_expires_at=?, collector_installation=?, collected_receipt=COALESCE(collected_receipt,?) \
                 WHERE delivery_id=? AND (lease_expires_at IS NULL OR lease_expires_at<=?)",
            )
            .bind(attempt)
            .bind(&lease_token)
            .bind(format_time(lease_expires))
            .bind(installation_id)
            .bind(collected_bytes)
            .bind(row.get::<String, _>("delivery_id"))
            .bind(format_time(now))
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            let envelope_bytes: Vec<u8> = row
                .try_get::<Option<Vec<u8>>, _>("envelope_json")
                .map_err(db_error)?
                .ok_or_else(|| RelayError::internal("active delivery has no envelope"))?;
            let envelope: Value = serde_json::from_slice(&envelope_bytes)
                .map_err(|_| RelayError::internal("stored envelope is invalid"))?;
            let queued: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>("queued_receipt"))
                .map_err(|_| RelayError::internal("stored receipt is invalid"))?;
            let mut delivery = json!({
                "delivery_id": row.get::<String, _>("delivery_id"),
                "envelope_digest": row.get::<String, _>("envelope_digest"),
                "envelope": envelope,
                "state": "collected",
                "attempt": attempt,
                "lease_token": lease_token,
                "lease_expires_at": format_time(lease_expires),
                "queued_receipt": queued
            });
            if let Some(receipt) = collected_receipt {
                delivery
                    .as_object_mut()
                    .expect("JSON object")
                    .insert("collected_receipt".into(), receipt);
            }
            deliveries.push(delivery);
        }
        tx.commit().await.map_err(db_error)?;
        Ok(json!({
            "operation": "relay.collect.result",
            "cursor": self.cursor(&caller.principal, installation_id),
            "deliveries": deliveries
        }))
    }

    async fn acknowledge(
        &self,
        caller: &AuthenticatedCaller,
        installation_id: &str,
        body: Value,
    ) -> Result<Value, RelayError> {
        if caller.installation_id.as_deref() != Some(installation_id) {
            return Err(RelayError::forbidden("collector installation mismatch"));
        }
        self.cleanup().await?;
        let object = exact_object(&body, &["operation", "acknowledgements"])?;
        if required_string(object, "operation")? != "relay.acknowledge" {
            return Err(RelayError::invalid_request("operation mismatch"));
        }
        let acknowledgements = object
            .get("acknowledgements")
            .and_then(Value::as_array)
            .ok_or_else(|| RelayError::invalid_request("missing acknowledgements"))?;
        if acknowledgements.is_empty() || acknowledgements.len() > 100 {
            return Err(RelayError::invalid_request(
                "acknowledgement bounds exceeded",
            ));
        }
        let now = self.clock.now();
        let mut tx = self.pool.begin().await.map_err(db_error)?;
        let mut receipts = Vec::with_capacity(acknowledgements.len());
        for acknowledgement in acknowledgements {
            let ack = exact_object(
                acknowledgement,
                &[
                    "delivery_id",
                    "envelope_id",
                    "envelope_digest",
                    "lease_token",
                    "disposition",
                ],
            )?;
            if required_string(ack, "disposition")? != "received" {
                return Err(RelayError::invalid_request(
                    "unsupported acknowledgement disposition",
                ));
            }
            let delivery_id = required_string(ack, "delivery_id")?;
            let row = sqlx::query("SELECT * FROM relay_deliveries WHERE delivery_id=?")
                .bind(delivery_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db_error)?
                .ok_or_else(|| RelayError::named("delivery_unknown", "delivery not found"))?;
            if row.get::<String, _>("recipient_network") != caller.principal.network_id
                || row.get::<String, _>("recipient_id") != caller.principal.principal_id
                || row.get::<String, _>("envelope_id") != required_string(ack, "envelope_id")?
                || row.get::<String, _>("envelope_digest")
                    != required_string(ack, "envelope_digest")?
            {
                return Err(RelayError::forbidden(
                    "acknowledgement delivery scope mismatch",
                ));
            }
            let state: String = row.get("state");
            if state == "acknowledged" {
                if row
                    .try_get::<Option<String>, _>("collector_installation")
                    .map_err(db_error)?
                    .as_deref()
                    != Some(installation_id)
                    || row
                        .try_get::<Option<String>, _>("acknowledged_lease_token")
                        .map_err(db_error)?
                        .as_deref()
                        != Some(required_string(ack, "lease_token")?)
                {
                    return Err(RelayError::forbidden("acknowledgement lease mismatch"));
                }
                let receipt = row
                    .try_get::<Option<Vec<u8>>, _>("acknowledged_receipt")
                    .map_err(db_error)?
                    .ok_or_else(|| RelayError::internal("acknowledged delivery has no receipt"))?;
                receipts.push(
                    serde_json::from_slice(&receipt)
                        .map_err(|_| RelayError::internal("stored receipt is invalid"))?,
                );
                continue;
            }
            if state != "collected" {
                return Err(RelayError::named(
                    "delivery_terminal",
                    "delivery is not awaiting acknowledgement",
                ));
            }
            if row
                .try_get::<Option<String>, _>("collector_installation")
                .map_err(db_error)?
                .as_deref()
                != Some(installation_id)
                || row
                    .try_get::<Option<String>, _>("lease_token")
                    .map_err(db_error)?
                    .as_deref()
                    != Some(required_string(ack, "lease_token")?)
            {
                return Err(RelayError::forbidden("acknowledgement lease mismatch"));
            }
            let receipt = self.receipt(
                delivery_id,
                required_string(ack, "envelope_id")?,
                required_string(ack, "envelope_digest")?,
                caller.principal.clone(),
                "acknowledged",
                Some("collected"),
                Some(installation_id),
                None,
                now,
            )?;
            let receipt_bytes = serde_json::to_vec(&receipt)
                .map_err(|_| RelayError::internal("receipt encoding failed"))?;
            sqlx::query(
                "UPDATE relay_deliveries SET state='acknowledged', acknowledged_receipt=?, \
                 acknowledged_lease_token=lease_token, terminal_at=?, ciphertext_delete_at=?, \
                 envelope_json=NULL, lease_token=NULL, \
                 lease_expires_at=NULL WHERE delivery_id=?",
            )
            .bind(receipt_bytes)
            .bind(format_time(now))
            .bind(format_time(now))
            .bind(delivery_id)
            .execute(&mut *tx)
            .await
            .map_err(db_error)?;
            receipts.push(receipt);
        }
        tx.commit().await.map_err(db_error)?;
        Ok(json!({
            "operation": "relay.acknowledge.result",
            "receipts": receipts
        }))
    }

    async fn delivery_get(
        &self,
        caller: &AuthenticatedCaller,
        delivery_id: &str,
    ) -> Result<Value, RelayError> {
        self.cleanup().await?;
        let row = sqlx::query("SELECT * FROM relay_deliveries WHERE delivery_id=?")
            .bind(delivery_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_error)?
            .ok_or_else(|| RelayError::named("delivery_unknown", "delivery not found"))?;
        let sender_match = row.get::<String, _>("sender_network") == caller.principal.network_id
            && row.get::<String, _>("sender_id") == caller.principal.principal_id;
        let recipient_match = row.get::<String, _>("recipient_network")
            == caller.principal.network_id
            && row.get::<String, _>("recipient_id") == caller.principal.principal_id
            && caller.installation_id.is_some();
        if !sender_match && !recipient_match {
            return Err(RelayError::named(
                "delivery_unknown",
                "delivery absent or outside caller scope",
            ));
        }
        let mut receipts = Vec::new();
        for field in [
            "queued_receipt",
            "collected_receipt",
            "acknowledged_receipt",
            "rejected_receipt",
        ] {
            if let Some(bytes) = row.try_get::<Option<Vec<u8>>, _>(field).map_err(db_error)? {
                receipts.push(
                    serde_json::from_slice::<Value>(&bytes)
                        .map_err(|_| RelayError::internal("stored receipt is invalid"))?,
                );
            }
        }
        Ok(json!({
            "operation": "relay.delivery.get.result",
            "delivery_id": delivery_id,
            "envelope_id": row.get::<String, _>("envelope_id"),
            "envelope_digest": row.get::<String, _>("envelope_digest"),
            "recipient": {
                "network_id": row.get::<String, _>("recipient_network"),
                "principal_id": row.get::<String, _>("recipient_id")
            },
            "state": row.get::<String, _>("state"),
            "receipts": receipts
        }))
    }

    fn validate_envelope(&self, wrapper: &Value) -> Result<ValidatedEnvelope, RelayError> {
        let wrapper_object = exact_object(wrapper, &["envelope", "signature"])
            .map_err(|_| RelayError::malformed_envelope("invalid signed envelope wrapper"))?;
        if wrapper_object
            .get("signature")
            .and_then(Value::as_str)
            .is_none()
        {
            return Err(RelayError::malformed_envelope("missing envelope signature"));
        }
        let bytes = canonical_json(wrapper)?;
        if bytes.len() > self.config.limits.max_envelope_bytes {
            return Err(RelayError::named(
                "payload_too_large",
                "signed envelope exceeds advertised limit",
            ));
        }
        let envelope = wrapper_object
            .get("envelope")
            .and_then(Value::as_object)
            .ok_or_else(|| RelayError::malformed_envelope("envelope must be an object"))?;
        if required_string(envelope, "envelope_type")? != "native.federation.transport"
            || required_string(envelope, "protocol_version")? != PROTOCOL_VERSION
        {
            return Err(RelayError::malformed_envelope(
                "unsupported envelope version",
            ));
        }
        if required_string(envelope, "profile")? != PROFILE {
            return Err(RelayError::named(
                "unsupported_profile",
                "unsupported exact federation profile",
            ));
        }
        let envelope_id = required_string(envelope, "envelope_id")?.to_owned();
        if !is_uuid_v4(&envelope_id) {
            return Err(RelayError::malformed_envelope("invalid envelope id"));
        }
        let sender_key = required_string(envelope, "sender_key_id")?;
        if !valid_namespaced_kid(sender_key, "signing") {
            return Err(RelayError::malformed_envelope(
                "invalid sender signing key id",
            ));
        }
        let sender: PrincipalAddress = serde_json::from_value(
            envelope
                .get("sender_principal")
                .cloned()
                .ok_or_else(|| RelayError::malformed_envelope("missing sender principal"))?,
        )
        .map_err(|_| RelayError::malformed_envelope("invalid sender principal"))?;
        validate_principal(&sender)?;
        let content_type = required_string(envelope, "content_type")?;
        if content_type.len() > 127
            || content_type.split_once('/').is_none()
            || !content_type.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"!#$&^_.+-/".contains(&byte)
            })
        {
            return Err(RelayError::malformed_envelope("invalid content type"));
        }
        let content_version = required_string(envelope, "content_version")?;
        let Some((major, minor)) = content_version.split_once('.') else {
            return Err(RelayError::malformed_envelope("invalid content version"));
        };
        if !valid_version_component(major) || !valid_version_component(minor) {
            return Err(RelayError::malformed_envelope("invalid content version"));
        }
        let extensions = envelope
            .get("extensions")
            .and_then(Value::as_object)
            .ok_or_else(|| RelayError::malformed_envelope("extensions must be an object"))?;
        if extensions.len() > 64 || extensions.keys().any(|name| !valid_profile_token(name)) {
            return Err(RelayError::malformed_envelope(
                "invalid extension member name",
            ));
        }
        let required_capabilities = envelope
            .get("required_capabilities")
            .and_then(Value::as_array)
            .ok_or_else(|| RelayError::malformed_envelope("missing required capabilities"))?;
        if required_capabilities.len() > 32
            || required_capabilities.iter().any(|value| {
                value
                    .as_str()
                    .is_none_or(|token| !valid_profile_token(token))
            })
        {
            return Err(RelayError::malformed_envelope(
                "invalid required capabilities",
            ));
        }
        let capability_count = required_capabilities
            .iter()
            .filter_map(Value::as_str)
            .collect::<HashSet<_>>()
            .len();
        if capability_count != required_capabilities.len() {
            return Err(RelayError::malformed_envelope(
                "duplicate required capability",
            ));
        }
        if required_capabilities
            .iter()
            .filter_map(Value::as_str)
            .any(|capability| capability != CAPABILITY_RECEIPTS)
        {
            return Err(RelayError::named(
                "required_capability_unsupported",
                "envelope requires an unsupported capability",
            ));
        }
        let recipients_value = envelope
            .get("recipients")
            .and_then(Value::as_array)
            .ok_or_else(|| RelayError::malformed_envelope("missing recipients"))?;
        if recipients_value.is_empty() || recipients_value.len() > self.config.limits.max_recipients
        {
            return Err(RelayError::malformed_envelope("recipient bounds exceeded"));
        }
        let mut recipients = Vec::with_capacity(recipients_value.len());
        let mut seen = HashSet::new();
        let mut previous_binding: Option<String> = None;
        for value in recipients_value {
            let object = exact_object(value, &["principal", "encryption_key_id"])
                .map_err(|_| RelayError::malformed_envelope("invalid recipient"))?;
            let principal: PrincipalAddress =
                serde_json::from_value(object.get("principal").cloned().ok_or_else(|| {
                    RelayError::malformed_envelope("missing recipient principal")
                })?)
                .map_err(|_| RelayError::malformed_envelope("invalid recipient principal"))?;
            let encryption_key_id = required_string(object, "encryption_key_id")?.to_owned();
            validate_principal(&principal)?;
            if !valid_namespaced_kid(&encryption_key_id, "encryption") {
                return Err(RelayError::malformed_envelope(
                    "invalid recipient encryption key id",
                ));
            }
            let binding = format!("{}/{}", principal.network_id, principal.principal_id);
            if previous_binding
                .as_ref()
                .is_some_and(|previous| previous.as_bytes() >= binding.as_bytes())
            {
                return Err(RelayError::malformed_envelope(
                    "recipients are not strictly sorted by binding form",
                ));
            }
            previous_binding = Some(binding);
            if !seen.insert(principal.storage_key()) {
                return Err(RelayError::malformed_envelope("duplicate recipient"));
            }
            recipients.push(ValidatedRecipient {
                principal,
                encryption_key_id,
            });
        }
        validate_jwe(envelope, &recipients)?;
        let created_at_raw = required_string(envelope, "created_at")?;
        let created_at = parse_time(created_at_raw)?;
        if format_time(created_at) != created_at_raw {
            return Err(RelayError::malformed_envelope(
                "created_at is not canonical UTC",
            ));
        }
        let declared_expiry = envelope
            .get("expires_at")
            .and_then(Value::as_str)
            .map(parse_time)
            .transpose()?;
        if envelope
            .get("expires_at")
            .and_then(Value::as_str)
            .zip(declared_expiry)
            .is_some_and(|(raw, parsed)| format_time(parsed) != raw)
        {
            return Err(RelayError::malformed_envelope(
                "expires_at is not canonical UTC",
            ));
        }
        if created_at > self.clock.now() + chrono::Duration::minutes(5) {
            return Err(RelayError::malformed_envelope(
                "envelope is from the future",
            ));
        }
        if declared_expiry.is_some_and(|expiry| {
            expiry <= created_at
                || expiry > created_at + chrono::Duration::days(MAX_ENVELOPE_LIFETIME_DAYS)
        }) {
            return Err(RelayError::malformed_envelope("invalid envelope expiry"));
        }
        let default_expiry = created_at
            + chrono::Duration::from_std(self.config.limits.default_expiry)
                .map_err(|_| RelayError::internal("invalid default expiry"))?;
        let retention_expiry = created_at
            + chrono::Duration::from_std(self.config.limits.retention)
                .map_err(|_| RelayError::internal("invalid retention"))?;
        let maximum_expiry = created_at + chrono::Duration::days(MAX_ENVELOPE_LIFETIME_DAYS);
        let effective_expiry = [
            declared_expiry.unwrap_or(default_expiry),
            retention_expiry,
            maximum_expiry,
        ]
        .into_iter()
        .min()
        .expect("three expiry values");
        if self.clock.now() >= effective_expiry {
            return Err(RelayError::named("expired", "envelope is expired"));
        }
        Ok(ValidatedEnvelope {
            envelope_id,
            digest: digest_value(wrapper)?,
            envelope_bytes: bytes.len(),
            effective_expiry,
            recipients,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn receipt(
        &self,
        delivery_id: &str,
        envelope_id: &str,
        envelope_digest: &str,
        recipient: PrincipalAddress,
        state: &str,
        previous_state: Option<&str>,
        collector_installation_id: Option<&str>,
        reason_code: Option<&str>,
        observed_at: DateTime<Utc>,
    ) -> Result<Value, RelayError> {
        let mut receipt = Map::new();
        receipt.insert(
            "receipt_type".into(),
            json!("native.relay.delivery-receipt"),
        );
        receipt.insert("protocol_version".into(), json!(PROTOCOL_VERSION));
        receipt.insert("profile".into(), json!(PROFILE));
        receipt.insert("receipt_id".into(), json!(Uuid::new_v4().to_string()));
        receipt.insert("relay_id".into(), json!(self.signer.relay_id()));
        receipt.insert("relay_key_id".into(), json!(self.signer.key_id()));
        receipt.insert("delivery_id".into(), json!(delivery_id));
        receipt.insert("envelope_id".into(), json!(envelope_id));
        receipt.insert("envelope_digest".into(), json!(envelope_digest));
        receipt.insert(
            "recipient".into(),
            serde_json::to_value(recipient).expect("serializable"),
        );
        if let Some(previous_state) = previous_state {
            receipt.insert("previous_state".into(), json!(previous_state));
        }
        receipt.insert("state".into(), json!(state));
        receipt.insert("observed_at".into(), json!(format_time(observed_at)));
        if let Some(installation_id) = collector_installation_id {
            receipt.insert("collector_installation_id".into(), json!(installation_id));
        }
        if let Some(reason_code) = reason_code {
            receipt.insert("reason_code".into(), json!(reason_code));
        }
        let receipt = Value::Object(receipt);
        let signature = self.signer.sign_receipt(&receipt)?;
        Ok(json!({"receipt": receipt, "signature": signature}))
    }

    fn cursor(&self, principal: &PrincipalAddress, installation_id: &str) -> String {
        let payload = format!(
            "{}\0{}\0{}",
            principal.network_id, principal.principal_id, installation_id
        );
        let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.cursor_key).expect("HMAC key length");
        mac.update(encoded.as_bytes());
        format!(
            "c1.{encoded}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
    }

    fn verify_cursor(
        &self,
        cursor: &str,
        principal: &PrincipalAddress,
        installation_id: &str,
    ) -> Result<(), RelayError> {
        if cursor.len() > 512 || cursor != self.cursor(principal, installation_id) {
            return Err(RelayError::invalid_request(
                "cursor is outside mailbox scope",
            ));
        }
        Ok(())
    }
}

pub fn relay_router(relay: Arc<Relay>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/envelopes", post(submit_handler))
        .route("/v1/mailboxes/{*mailbox_operation}", post(mailbox_handler))
        .route("/v1/deliveries/{delivery}", get(delivery_handler))
        .with_state(relay)
}

async fn health(State(relay): State<Arc<Relay>>) -> Response {
    if relay.healthy().await {
        (StatusCode::OK, axum::Json(json!({"status": "ok"}))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"status": "unavailable"})),
        )
            .into_response()
    }
}

async fn submit_handler(State(relay): State<Arc<Relay>>, request: Request) -> Response {
    let fallback = Uuid::new_v4().to_string();
    let (headers, connection, body) =
        match request_parts(request, relay.config.limits.max_envelope_bytes).await {
            Ok(parts) => parts,
            Err(error) => return problem_response(error, &fallback),
        };
    if let Err(error) = require_domain_content_type(&headers) {
        return problem_response(error, &fallback);
    }
    if let Err(error) = check_source_rate(&relay, connection).await {
        return problem_response(error, &fallback);
    }
    let caller = match relay.authenticate(&headers, "relay.submit", &body) {
        Ok(caller) => caller,
        Err(error) => return problem_response(error, &fallback),
    };
    let request_id = caller.request_id.clone();
    let result = async {
        relay.claim_proof(&caller).await?;
        let value = parse_body(&body)?;
        relay.submit(&caller, value).await
    }
    .await;
    operation_response(result, &request_id)
}

async fn mailbox_handler(
    State(relay): State<Arc<Relay>>,
    AxumPath(mailbox_operation): AxumPath<String>,
    request: Request,
) -> Response {
    let (operation, installation, limit) =
        if let Some(installation) = mailbox_operation.strip_suffix(":collect") {
            ("relay.collect", installation.to_owned(), 16 * 1024)
        } else if let Some(installation) = mailbox_operation.strip_suffix("/acknowledgements") {
            ("relay.acknowledge", installation.to_owned(), 128 * 1024)
        } else {
            return StatusCode::NOT_FOUND.into_response();
        };
    if installation.contains('/') || !is_uuid_v4(&installation) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let fallback = Uuid::new_v4().to_string();
    let (headers, connection, body) = match request_parts(request, limit).await {
        Ok(parts) => parts,
        Err(error) => return problem_response(error, &fallback),
    };
    if let Err(error) = require_domain_content_type(&headers) {
        return problem_response(error, &fallback);
    }
    if let Err(error) = check_source_rate(&relay, connection).await {
        return problem_response(error, &fallback);
    }
    let caller = match relay.authenticate(&headers, operation, &body) {
        Ok(caller) => caller,
        Err(error) => return problem_response(error, &fallback),
    };
    let request_id = caller.request_id.clone();
    let result = async {
        relay.claim_proof(&caller).await?;
        if operation == "relay.collect" {
            relay
                .collect(&caller, &installation, parse_body(&body)?)
                .await
        } else {
            relay
                .acknowledge(&caller, &installation, parse_body(&body)?)
                .await
        }
    }
    .await;
    operation_response(result, &request_id)
}

async fn delivery_handler(
    State(relay): State<Arc<Relay>>,
    AxumPath(delivery): AxumPath<String>,
    request: Request,
) -> Response {
    let headers = request.headers().clone();
    let connection = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied();
    let fallback = Uuid::new_v4().to_string();
    if let Err(error) = check_source_rate(&relay, connection).await {
        return problem_response(error, &fallback);
    }
    let caller = match relay.authenticate(&headers, "relay.delivery.get", &[]) {
        Ok(caller) => caller,
        Err(error) => return problem_response(error, &fallback),
    };
    let request_id = caller.request_id.clone();
    let result = async {
        relay.claim_proof(&caller).await?;
        relay.delivery_get(&caller, &delivery).await
    }
    .await;
    operation_response(result, &request_id)
}

async fn request_parts(
    request: Request,
    limit: usize,
) -> Result<(HeaderMap, Option<ConnectInfo<SocketAddr>>, Bytes), RelayError> {
    let headers = request.headers().clone();
    let connection = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .copied();
    let body = to_bytes(request.into_body(), limit).await.map_err(|_| {
        RelayError::named(
            "payload_too_large",
            "request body exceeds its operation limit",
        )
    })?;
    Ok((headers, connection, body))
}

async fn check_source_rate(
    relay: &Relay,
    connection: Option<ConnectInfo<SocketAddr>>,
) -> Result<(), RelayError> {
    if let Some(ConnectInfo(address)) = connection {
        relay
            .check_rate(
                "source-ip",
                &address.ip().to_string(),
                relay.config.limits.source_requests_per_minute,
                Duration::from_secs(60),
            )
            .await?;
    }
    Ok(())
}

fn require_domain_content_type(headers: &HeaderMap) -> Result<(), RelayError> {
    if headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        == Some("application/vnd.native.federation+json")
    {
        Ok(())
    } else {
        Err(RelayError::named(
            "unsupported_media_type",
            "domain request Content-Type must be application/vnd.native.federation+json",
        ))
    }
}

fn operation_response(operation: Result<Value, RelayError>, request_id: &str) -> Response {
    match operation {
        Ok(value) => json_response(StatusCode::OK, value, request_id, None),
        Err(error) => problem_response(error, request_id),
    }
}

fn json_response(
    status: StatusCode,
    value: Value,
    request_id: &str,
    retry_after: Option<u64>,
) -> Response {
    let mut response = (status, axum::Json(value)).into_response();
    response.headers_mut().insert(
        HeaderName::from_static("native-request-id"),
        HeaderValue::from_str(request_id).expect("UUID header value"),
    );
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.native.federation+json"),
    );
    if let Some(seconds) = retry_after {
        response.headers_mut().insert(
            axum::http::header::RETRY_AFTER,
            HeaderValue::from_str(&seconds.to_string()).expect("integer header value"),
        );
    }
    response
}

fn problem_response(error: RelayError, request_id: &str) -> Response {
    let status = error.status();
    let retryable = error.retry_after.is_some()
        || matches!(error.code, "directory_unavailable" | "relay_unavailable");
    let mut problem = json!({
        "type": format!("urn:native:federation:error:{}", error.code),
        "title": error.code.replace('_', " "),
        "status": status.as_u16(),
        "code": error.code,
        "detail": error.detail,
        "request_id": request_id,
        "retryable": retryable
    });
    if let Some(seconds) = error.retry_after {
        problem
            .as_object_mut()
            .expect("problem object")
            .insert("retry_after".into(), json!(seconds));
    }
    let mut response = json_response(status, problem, request_id, error.retry_after);
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    response
}

#[derive(Debug)]
struct ValidatedRecipient {
    principal: PrincipalAddress,
    encryption_key_id: String,
}

#[derive(Debug)]
struct ValidatedEnvelope {
    envelope_id: String,
    digest: String,
    envelope_bytes: usize,
    effective_expiry: DateTime<Utc>,
    recipients: Vec<ValidatedRecipient>,
}

fn validate_jwe(
    envelope: &Map<String, Value>,
    recipients: &[ValidatedRecipient],
) -> Result<(), RelayError> {
    let jwe = envelope
        .get("jwe")
        .and_then(Value::as_object)
        .ok_or_else(|| RelayError::malformed_envelope("missing JWE"))?;
    if jwe.len() != 6
        || ["protected", "aad", "recipients", "iv", "ciphertext", "tag"]
            .iter()
            .any(|field| !jwe.contains_key(*field))
    {
        return Err(RelayError::malformed_envelope("forbidden JWE member"));
    }
    let protected = required_string(jwe, "protected")?;
    let protected_bytes = decode_base64url(protected, "malformed_envelope")?;
    let protected_value: Value = serde_json::from_slice(&protected_bytes)
        .map_err(|_| RelayError::malformed_envelope("invalid JWE protected header"))?;
    if canonical_json(&protected_value)? != protected_bytes
        || protected_value
            != json!({
                "alg": "HPKE-3-KE",
                "enc": "A256GCM",
                "typ": "native-federation+jwe",
                "cty": required_string(envelope, "content_type")?,
                "native_profile": PROFILE,
                "crit": ["native_profile"]
            })
    {
        return Err(RelayError::malformed_envelope(
            "invalid JWE protected header",
        ));
    }
    let jwe_recipients = jwe
        .get("recipients")
        .and_then(Value::as_array)
        .ok_or_else(|| RelayError::malformed_envelope("missing JWE recipients"))?;
    if jwe_recipients.len() != recipients.len() {
        return Err(RelayError::named(
            "recipient_mismatch",
            "JWE recipient count mismatch",
        ));
    }
    for (jwe_recipient, outer) in jwe_recipients.iter().zip(recipients) {
        let jwe_recipient = exact_object(jwe_recipient, &["header", "encrypted_key"])
            .map_err(|_| RelayError::malformed_envelope("invalid JWE recipient"))?;
        let header = jwe_recipient
            .get("header")
            .and_then(Value::as_object)
            .ok_or_else(|| RelayError::malformed_envelope("invalid JWE recipient header"))?;
        if header.len() != 2
            || required_string(header, "kid")? != outer.encryption_key_id
            || header.get("ek").and_then(Value::as_str).is_none()
        {
            return Err(RelayError::named(
                "recipient_mismatch",
                "JWE recipient mapping mismatch",
            ));
        }
        if decode_base64url(required_string(header, "ek")?, "malformed_envelope")?.len() != 32
            || decode_base64url(
                required_string(jwe_recipient, "encrypted_key")?,
                "malformed_envelope",
            )?
            .len()
                != 48
        {
            return Err(RelayError::malformed_envelope(
                "invalid provisional HPKE fields",
            ));
        }
    }
    let mut context = envelope.clone();
    context.remove("jwe");
    context.remove("ciphertext_digest");
    let expected_aad = URL_SAFE_NO_PAD.encode(canonical_json(&Value::Object(context))?);
    if required_string(jwe, "aad")? != expected_aad {
        return Err(RelayError::malformed_envelope("JWE external AAD mismatch"));
    }
    if decode_base64url(required_string(jwe, "iv")?, "malformed_envelope")?.len() != 12
        || decode_base64url(required_string(jwe, "tag")?, "malformed_envelope")?.len() != 16
    {
        return Err(RelayError::malformed_envelope("invalid JWE AEAD fields"));
    }
    let ciphertext = decode_base64url(required_string(jwe, "ciphertext")?, "malformed_envelope")?;
    if required_string(envelope, "ciphertext_digest")? != sha256_digest(&ciphertext) {
        return Err(RelayError::malformed_envelope("ciphertext digest mismatch"));
    }
    Ok(())
}

async fn existing_delivery(
    tx: &mut Transaction<'_, Sqlite>,
    sender: &PrincipalAddress,
    envelope_id: &str,
    recipient: &PrincipalAddress,
) -> Result<Option<sqlx::sqlite::SqliteRow>, RelayError> {
    sqlx::query(
        "SELECT * FROM relay_deliveries WHERE sender_network=? AND sender_id=? AND envelope_id=? \
         AND recipient_network=? AND recipient_id=?",
    )
    .bind(&sender.network_id)
    .bind(&sender.principal_id)
    .bind(envelope_id)
    .bind(&recipient.network_id)
    .bind(&recipient.principal_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db_error)
}

fn result_from_existing(row: &sqlx::sqlite::SqliteRow) -> Result<Value, RelayError> {
    let state: String = row.get("state");
    let recipient = json!({
        "network_id": row.get::<String, _>("recipient_network"),
        "principal_id": row.get::<String, _>("recipient_id")
    });
    if state == "rejected" {
        let receipt = row
            .try_get::<Option<Vec<u8>>, _>("rejected_receipt")
            .map_err(db_error)?
            .ok_or_else(|| RelayError::internal("rejected delivery has no receipt"))?;
        Ok(json!({
            "recipient": recipient,
            "outcome": "rejected",
            "delivery_id": row.get::<String, _>("delivery_id"),
            "code": row.get::<String, _>("rejection_reason"),
            "receipt": serde_json::from_slice::<Value>(&receipt).map_err(|_| RelayError::internal("stored receipt is invalid"))?
        }))
    } else {
        let receipt: Value = serde_json::from_slice(&row.get::<Vec<u8>, _>("queued_receipt"))
            .map_err(|_| RelayError::internal("stored receipt is invalid"))?;
        Ok(json!({
            "recipient": recipient,
            "outcome": "queued",
            "delivery_id": row.get::<String, _>("delivery_id"),
            "receipt": receipt
        }))
    }
}

fn error_result(recipient: &PrincipalAddress, code: &str, retry_after: u64) -> Value {
    json!({
        "recipient": recipient,
        "outcome": "error",
        "code": code,
        "retry_after": retry_after
    })
}

#[allow(clippy::too_many_arguments)]
async fn insert_delivery(
    tx: &mut Transaction<'_, Sqlite>,
    delivery_id: &str,
    sender: &PrincipalAddress,
    envelope: &ValidatedEnvelope,
    recipient: &PrincipalAddress,
    state: &str,
    rejection_reason: Option<&str>,
    envelope_json: Option<&[u8]>,
    receipt: Option<&[u8]>,
    now: DateTime<Utc>,
) -> Result<(), RelayError> {
    let terminal_at = if state == "rejected" {
        Some(format_time(now))
    } else {
        None
    };
    sqlx::query(
        "INSERT INTO relay_deliveries( \
         delivery_id,sender_network,sender_id,envelope_id,recipient_network,recipient_id, \
         envelope_digest,envelope_json,envelope_bytes,state,rejection_reason,queued_receipt, \
         rejected_receipt,attempt,effective_expiry,created_at,terminal_at) \
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,?)",
    )
    .bind(delivery_id)
    .bind(&sender.network_id)
    .bind(&sender.principal_id)
    .bind(&envelope.envelope_id)
    .bind(&recipient.network_id)
    .bind(&recipient.principal_id)
    .bind(&envelope.digest)
    .bind(envelope_json)
    .bind(envelope.envelope_bytes as i64)
    .bind(state)
    .bind(rejection_reason)
    .bind(if state == "queued" { receipt } else { None })
    .bind(if state == "rejected" { receipt } else { None })
    .bind(format_time(envelope.effective_expiry))
    .bind(format_time(now))
    .bind(terminal_at)
    .execute(&mut **tx)
    .await
    .map_err(db_error)?;
    Ok(())
}

async fn initialize(pool: &SqlitePool) -> Result<(), RelayError> {
    for statement in [
        "CREATE TABLE IF NOT EXISTS relay_meta(key TEXT PRIMARY KEY, value BLOB NOT NULL)",
        "CREATE TABLE IF NOT EXISTS relay_request_proofs( \
         kid TEXT NOT NULL, nonce TEXT NOT NULL, request_id TEXT NOT NULL, body_digest TEXT NOT NULL, \
         expires_at TEXT NOT NULL, PRIMARY KEY(kid,nonce))",
        "CREATE UNIQUE INDEX IF NOT EXISTS relay_request_proof_request \
         ON relay_request_proofs(kid,request_id)",
        "CREATE TABLE IF NOT EXISTS relay_rate_counters( \
         scope TEXT NOT NULL, subject TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL, \
         PRIMARY KEY(scope,subject,window_start))",
        "CREATE TABLE IF NOT EXISTS relay_envelopes( \
         sender_network TEXT NOT NULL, sender_id TEXT NOT NULL, envelope_id TEXT NOT NULL, \
         envelope_digest TEXT NOT NULL, retain_until TEXT NOT NULL, \
         PRIMARY KEY(sender_network,sender_id,envelope_id))",
        "CREATE TABLE IF NOT EXISTS relay_deliveries( \
         delivery_id TEXT PRIMARY KEY, sender_network TEXT NOT NULL, sender_id TEXT NOT NULL, \
         envelope_id TEXT NOT NULL, recipient_network TEXT NOT NULL, recipient_id TEXT NOT NULL, \
         envelope_digest TEXT NOT NULL, envelope_json BLOB, envelope_bytes INTEGER NOT NULL, \
         state TEXT NOT NULL CHECK(state IN ('rejected','queued','collected','acknowledged')), \
         rejection_reason TEXT, queued_receipt BLOB, collected_receipt BLOB, acknowledged_receipt BLOB, \
         rejected_receipt BLOB, attempt INTEGER NOT NULL DEFAULT 0, lease_token TEXT, lease_expires_at TEXT, \
         collector_installation TEXT, acknowledged_lease_token TEXT, \
         effective_expiry TEXT NOT NULL, created_at TEXT NOT NULL, \
         terminal_at TEXT, ciphertext_delete_at TEXT, \
         UNIQUE(sender_network,sender_id,envelope_id,recipient_network,recipient_id))",
        "CREATE INDEX IF NOT EXISTS relay_mailbox_collect ON relay_deliveries( \
         recipient_network,recipient_id,state,effective_expiry,lease_expires_at,created_at)",
        "CREATE INDEX IF NOT EXISTS relay_terminal_cleanup ON relay_deliveries(terminal_at)",
    ] {
        sqlx::query(statement).execute(pool).await.map_err(db_error)?;
    }
    let acknowledgement_token_column: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pragma_table_info('relay_deliveries') WHERE name='acknowledged_lease_token'",
    )
    .fetch_one(pool)
    .await
    .map_err(db_error)?;
    if acknowledgement_token_column == 0 {
        sqlx::query("ALTER TABLE relay_deliveries ADD COLUMN acknowledged_lease_token TEXT")
            .execute(pool)
            .await
            .map_err(db_error)?;
    }
    Ok(())
}

async fn load_cursor_key(pool: &SqlitePool) -> Result<[u8; 32], RelayError> {
    if let Some(bytes) =
        sqlx::query_scalar::<_, Vec<u8>>("SELECT value FROM relay_meta WHERE key='cursor_hmac_key'")
            .fetch_optional(pool)
            .await
            .map_err(db_error)?
    {
        return bytes
            .try_into()
            .map_err(|_| RelayError::internal("stored cursor key has invalid length"));
    }
    let mut key = [0_u8; 32];
    rand::rng().fill_bytes(&mut key);
    sqlx::query("INSERT INTO relay_meta(key,value) VALUES('cursor_hmac_key',?)")
        .bind(key.as_slice())
        .execute(pool)
        .await
        .map_err(db_error)?;
    Ok(key)
}

fn validate_config(config: &RelayConfig) -> Result<(), RelayError> {
    let origin = url::Url::parse(&config.public_origin)
        .map_err(|_| RelayError::invalid_request("relay public origin is invalid"))?;
    if !matches!(origin.scheme(), "https" | "http")
        || origin.host_str().is_none()
        || origin.path() != "/"
        || origin.query().is_some()
        || origin.fragment().is_some()
        || (origin.scheme() == "http"
            && !matches!(origin.host_str(), Some("localhost" | "127.0.0.1" | "::1")))
    {
        return Err(RelayError::invalid_request(
            "relay public origin must be HTTPS (HTTP is loopback-only) with no path",
        ));
    }
    let limits = &config.limits;
    if limits.max_recipients == 0
        || limits.max_recipients > 128
        || limits.max_envelope_bytes > 1_048_576
        || limits.max_collection == 0
        || limits.max_collection > 100
        || !(Duration::from_secs(30)..=Duration::from_secs(900)).contains(&limits.lease_duration)
        || limits.default_expiry > Duration::from_secs(7 * 24 * 60 * 60)
        || limits.retention > Duration::from_secs(30 * 24 * 60 * 60)
        || limits.terminal_retention < Duration::from_secs(30 * 24 * 60 * 60)
    {
        return Err(RelayError::invalid_request(
            "relay limits violate the profile bounds",
        ));
    }
    Ok(())
}

fn validate_database_target(path: &Path) -> Result<(), RelayError> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = std::fs::metadata(path)
        .map_err(|error| RelayError::invalid_request(format!("relay database: {error}")))?;
    if !metadata.is_file() {
        return Err(RelayError::invalid_request(
            "relay database target is not a regular file",
        ));
    }
    if metadata.len() == 0 {
        return Ok(());
    }
    let connection = rusqlite::Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|_| RelayError::invalid_request("existing relay database is not valid SQLite"))?;
    let mut statement = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table'")
        .map_err(|_| RelayError::invalid_request("could not inspect existing relay database"))?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| RelayError::invalid_request("could not inspect existing relay database"))?
        .collect::<Result<HashSet<_>, _>>()
        .map_err(|_| RelayError::invalid_request("could not inspect existing relay database"))?;
    if names.is_empty() {
        return Ok(());
    }
    let allowed: HashSet<_> = [
        "relay_meta",
        "relay_request_proofs",
        "relay_rate_counters",
        "relay_envelopes",
        "relay_deliveries",
        "sqlite_sequence",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if !names.contains("relay_meta") || !names.is_subset(&allowed) {
        return Err(RelayError::invalid_request(
            "existing SQLite file is not a dedicated Native relay database",
        ));
    }
    Ok(())
}

fn parse_body(bytes: &[u8]) -> Result<Value, RelayError> {
    parse_ijson(bytes, "invalid_request")
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a Map<String, Value>, RelayError> {
    let object = value
        .as_object()
        .ok_or_else(|| RelayError::invalid_request("body must be an object"))?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(RelayError::invalid_request("body shape is invalid"));
    }
    Ok(object)
}

fn required_string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str, RelayError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| RelayError::invalid_request(format!("missing {name}")))
}

fn parse_time(value: &str) -> Result<DateTime<Utc>, RelayError> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|_| RelayError::malformed_envelope("invalid RFC 3339 timestamp"))
}

fn format_time(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn is_uuid_v4(value: &str) -> bool {
    Uuid::parse_str(value)
        .is_ok_and(|uuid| uuid.get_version_num() == 4 && uuid.to_string() == value)
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut value);
    URL_SAFE_NO_PAD.encode(value)
}

fn valid_namespaced_kid(value: &str, purpose: &str) -> bool {
    let prefix = format!("n1.{purpose}.");
    value.strip_prefix(&prefix).is_some_and(|suffix| {
        suffix.len() == 43
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    })
}

fn validate_principal(principal: &PrincipalAddress) -> Result<(), RelayError> {
    if principal.is_valid() {
        Ok(())
    } else {
        Err(RelayError::malformed_envelope("invalid principal address"))
    }
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_profile_token(value: &str) -> bool {
    if !(1..=96).contains(&value.len()) || !value.is_ascii() {
        return false;
    }
    let bytes = value.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    let mut previous_was_separator = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        let separator = matches!(byte, b'.' | b'_' | b':' | b'-');
        if index > 0 && !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || separator) {
            return false;
        }
        if separator && (index == 0 || previous_was_separator || index + 1 == bytes.len()) {
            return false;
        }
        previous_was_separator = separator;
    }
    if value.starts_with("native.") {
        true
    } else {
        value
            .split_once(':')
            .is_some_and(|(authority, suffix)| valid_dns_name(authority) && !suffix.is_empty())
    }
}

fn valid_version_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 5
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && value.parse::<u16>().is_ok()
}
