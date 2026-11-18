//! Tenant-resident webhook configuration and receipts. The canonical log is the
//! store: indexed event queries deliberately need no independently mutable cache.
use super::*;
use serde_json::Value;

// Keep the event predicates and extracted key identical in the actual DDL
// and prospective queries; concat! makes divergence a source change rather
// than an independently edited SQL literal.
macro_rules! configured_type {
    () => {
        "kernel.webhook_configured.v1"
    };
}
macro_rules! accepted_type {
    () => {
        "kernel.webhook_accepted.v1"
    };
}
macro_rules! accepted_key_expression {
    () => {
        "json_extract(payload,'$.submission_key')"
    };
}
pub const CONFIGURED: &str = configured_type!();
pub const REVOKED: &str = "kernel.webhook_revoked.v1";
pub const ACCEPTED: &str = accepted_type!();
pub const DIAGNOSTIC: &str = "kernel.webhook_diagnostic.v1";
pub(crate) const INDEX: &str = "CREATE INDEX IF NOT EXISTS idx_kernel_webhook_events ON content_events(record_id,type,seq) WHERE type GLOB 'kernel.webhook_*'";
pub(crate) const CONFIG_KEY: &str = concat!("CREATE UNIQUE INDEX IF NOT EXISTS idx_kernel_webhook_configuration ON content_events(record_id) WHERE type='", configured_type!(), "'");
pub(crate) const KEYS: &str = concat!("CREATE UNIQUE INDEX IF NOT EXISTS idx_kernel_webhook_accepted_key ON content_events(record_id,", accepted_key_expression!(), ") WHERE type='", accepted_type!(), "'");
pub(crate) const PREPARATION_INDEXES: [(&str, &str); 3] = [
    ("idx_kernel_webhook_events", INDEX),
    ("idx_kernel_webhook_configuration", CONFIG_KEY),
    ("idx_kernel_webhook_accepted_key", KEYS),
];

pub use crate::webhook_contract::{Acceptance, Endpoint, Field, FormConfig, Submission};
fn invalid() -> Error {
    Error::engine("invalid webhook configuration")
}
pub(crate) async fn prepare_on(conn: &mut SqliteConnection) -> Result<()> {
    for ddl in [INDEX, CONFIG_KEY, KEYS] {
        sqlx::query(ddl).execute(&mut *conn).await?;
    }
    Ok(())
}
pub async fn endpoint_on(conn: &mut SqliteConnection, id: &str) -> Result<Option<Endpoint>> {
    let raw:Option<String> = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='kernel.webhook_configured.v1' ORDER BY seq LIMIT 1")
        .bind(id).fetch_optional(conn).await?;
    raw.map(|s| serde_json::from_str(&s).map_err(Into::into))
        .transpose()
}
pub(crate) async fn revoked_on(conn: &mut SqliteConnection, id: &str) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.webhook_revoked.v1')").bind(id).fetch_one(conn).await?)
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn accepted_on(
    conn: &mut SqliteConnection,
    id: &str,
    key: &str,
) -> Result<Option<Acceptance>> {
    let raw:Option<String> = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND json_extract(payload,'$.submission_key')=? AND type='kernel.webhook_accepted.v1'")
        .bind(id).bind(key).fetch_optional(conn).await?;
    raw.map(|s| serde_json::from_str(&s).map_err(Into::into))
        .transpose()
}

/// Closed event codec used on admission and replay. Authorization is rechecked
/// on authoring only; replay never consults today's membership or credentials.
pub(crate) fn validate_event(event: &EventRow) -> Result<()> {
    match event.event_type.as_str() {
        CONFIGURED => {
            let e: Endpoint = event_payload(event)?;
            e.config.validate()?;
            if e.endpoint_id != event.record_id
                || event.actor.as_deref() != Some(&e.issuer_principal)
                || e.credential_hash.len() != 64
                || e.credential_id.is_empty()
                || e.issuer_user_id.is_empty()
            {
                return Err(invalid());
            }
        }
        ACCEPTED => {
            let p: Acceptance = event_payload(event)?;
            if [&p.submission_key, &p.payload_digest]
                .iter()
                .any(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
                || [&p.record_id, &p.attachment_id, &p.delivery_id]
                    .iter()
                    .any(|s| uuid::Uuid::parse_str(s).is_err())
            {
                return Err(invalid());
            }
        }
        REVOKED => {
            if event_payload::<Value>(event)? != serde_json::json!({"revoked":true}) {
                return Err(invalid());
            }
        }
        DIAGNOSTIC => {
            let v: Value = event_payload(event)?;
            if !matches!(
                v["code"].as_str(),
                Some("invalid_submission" | "duplicate_mismatch")
            ) || v.as_object().is_none_or(|o| o.len() != 1)
            {
                return Err(invalid());
            }
        }
        _ => {}
    }
    Ok(())
}
pub(crate) async fn validate_recorded(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    validate_event(event)?;
    if event.event_type == ACCEPTED {
        let p: Acceptance = event_payload(event)?;
        let configured:Option<String>=sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='kernel.webhook_configured.v1' AND seq<? ORDER BY seq LIMIT 1")
            .bind(&event.record_id).bind(event.local_seq).fetch_optional(&mut *conn).await?;
        let configured: Endpoint = serde_json::from_str(&configured.ok_or_else(invalid)?)?;
        if event.actor.as_deref() != Some(&configured.issuer_principal) {
            return Err(invalid());
        }
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events e WHERE e.record_id=?1 AND e.type IN ('kernel.record_created.v1','kernel.record_created.v2') AND e.act=?2 AND e.actor IS ?3 AND e.seq<?4 AND json_extract(e.payload,'$.origin.kind')='webhook' AND json_extract(e.payload,'$.origin.endpoint_id')=?5 AND json_extract(e.payload,'$.origin.delivery_id')=?6 AND json_extract(e.payload,'$.origin.submission_key')=?7 AND json_extract(e.payload,'$.origin.payload_digest')=?8 AND json_extract(e.payload,'$.origin.credential_id')=?9 AND EXISTS(SELECT 1 FROM content_events a WHERE a.record_id=?10 AND a.type='kernel.attachment_bound.v1' AND a.act=e.act AND a.actor=e.actor AND a.seq<?4))")
            .bind(&p.record_id).bind(event.act).bind(&event.actor).bind(event.local_seq).bind(&event.record_id).bind(&p.delivery_id).bind(&p.submission_key).bind(&p.payload_digest).bind(&configured.credential_id).bind(&p.attachment_id).fetch_one(&mut *conn).await?;
        if !valid {
            return Err(Error::engine(
                "webhook receipt lacks atomic creation lineage",
            ));
        }
        let revoked:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.webhook_revoked.v1' AND seq<?)").bind(&event.record_id).bind(event.local_seq).fetch_one(conn).await?;
        if revoked {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Explicit operator preparation of the three webhook indexes on an existing
/// marked v2 file. All other serving readiness checks must pass in the same
/// transaction before any index becomes durable. This is never a serving open.
pub async fn prepare_existing_indexes(db: &Db) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut *tx)
        .await?;
    if marker != crate::db::V2_APPLICATION_ID {
        return Err(Error::engine(
            "webhook preparation requires an existing marked v2 file",
        ));
    }
    prepare_on(&mut tx).await?;
    require_ready_on(&mut tx).await?;
    super::verify_v2_ready_on(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn require_ready_on(conn: &mut SqliteConnection) -> Result<()> {
    for (name, ddl) in PREPARATION_INDEXES {
        let actual: Option<String> =
            sqlx::query_scalar("SELECT sql FROM sqlite_schema WHERE type='index' AND name=?")
                .bind(name)
                .fetch_optional(&mut *conn)
                .await?;
        if actual.as_deref() != Some(ddl.replacen(" IF NOT EXISTS", "", 1).as_str()) {
            return Err(Error::engine(
                "v2 webhook indexes require explicit database preparation",
            ));
        }
    }
    Ok(())
}

/// Read-only prerequisites for the three exact preparation indexes. This is
/// not serving readiness. Match both unique-index predicates, including SQL's
/// allowance for NULL keys, so a shape-only release observation cannot conceal
/// data that the subsequent explicit CREATE UNIQUE INDEX would reject.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) enum PreparationSourceFailure {
    Shape(Error),
    KeysUnreadable(Error),
    KeysConflict,
}

#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) async fn require_preparation_source_on(
    conn: &mut SqliteConnection,
) -> std::result::Result<(), PreparationSourceFailure> {
    for (name, _) in PREPARATION_INDEXES {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?)")
                .bind(name)
                .fetch_one(&mut *conn)
                .await
                .map_err(|error| PreparationSourceFailure::Shape(error.into()))?;
        if exists {
            return Err(PreparationSourceFailure::Shape(Error::engine(
                "v2 release pre-preparation requires all webhook indexes absent",
            )));
        }
    }
    let duplicate_configuration: bool = sqlx::query_scalar(concat!(
        "SELECT EXISTS(SELECT 1 FROM content_events WHERE type='",
        configured_type!(),
        "' AND record_id IS NOT NULL GROUP BY record_id HAVING COUNT(*)>1)"
    ))
    .fetch_one(&mut *conn)
    .await
    .map_err(|error| PreparationSourceFailure::KeysUnreadable(error.into()))?;
    let duplicate_key: bool = sqlx::query_scalar(concat!(
        "SELECT EXISTS(SELECT 1 FROM content_events WHERE type='",
        accepted_type!(),
        "' AND record_id IS NOT NULL AND ",
        accepted_key_expression!(),
        " IS NOT NULL GROUP BY record_id,",
        accepted_key_expression!(),
        " HAVING COUNT(*)>1)"
    ))
    .fetch_one(&mut *conn)
    .await
    .map_err(|error| PreparationSourceFailure::KeysUnreadable(error.into()))?;
    if duplicate_configuration || duplicate_key {
        return Err(PreparationSourceFailure::KeysConflict);
    }
    Ok(())
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if !event.event_type.starts_with("kernel.webhook_") {
        return Ok(());
    }
    validate_event(event)?;
    let actor = event.actor.as_deref().ok_or_else(invalid)?;
    if event.event_type == CONFIGURED {
        let e: Endpoint = event_payload(event)?;
        if endpoint_on(conn, &event.record_id).await?.is_some() {
            return Err(invalid());
        }
        super::kernel_require(conn, actor, &e.config.home_id, Capability::Manage).await?;
    } else {
        let e = endpoint_on(conn, &event.record_id)
            .await?
            .ok_or_else(invalid)?;
        if e.issuer_principal != actor {
            return Err(Error::auth("issuer_not_authorized"));
        }
        if event.event_type != REVOKED && revoked_on(conn, &event.record_id).await? {
            return Err(Error::auth("invalid_credential"));
        }
    }
    Ok(())
}
