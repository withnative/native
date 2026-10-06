//! Gated v2 generic exact-pin consumer registry (task e2bfaf5, Increment 1).
//!
//! One row per whole-definition requirement: `(scope_home, consumer, family)`
//! pins exactly one `(version, digest)`. No kind list, no field sets, no
//! execution of rules or queries — storage only, no adoption enforcement.
//! Field/read sets, if ever needed, extend a NEW event version later.
//!
//! Events (meta log, attributed, replay-backed):
//! - `consumer_required.v1`: register (or move) a requirement pin.
//! - `consumer_retired.v1`: retire a requirement; the row stays with
//!   `active = 0` so union-keys reads fail closed instead of reading a
//!   retired-away row as absent.
//!
//! Fail-closed reads: keys are unioned from the projection AND the event log.
//! A subject with events but no projection row is corruption (error, never
//! absent). Exact retry appends nothing and returns the existing seq.

use sqlx::{Sqlite, SqliteConnection, Transaction};

use crate::error::{Error, Result};
use crate::meta::events::{ConsumerRequiredV1Payload, ConsumerRetiredV1Payload};
use crate::meta::log::{append_meta_in, MetaAppendSpec};

/// Consumer requirement projection DDL, owned by the v2 kernel (never frozen
/// v1 DDL, no migration). Gated setup code executes these explicitly.
pub const CONSUMER_DDL: [&str; 2] = [
    r#"CREATE TABLE consumer_requirements (
     scope_home         TEXT NOT NULL,
     consumer_kind      TEXT NOT NULL,
     consumer_namespace TEXT NOT NULL,
     consumer_name      TEXT NOT NULL,
     family             TEXT NOT NULL,
     version            INTEGER NOT NULL CHECK (version >= 0),
     digest             TEXT NOT NULL CHECK (length(digest) = 64),
     active             INTEGER NOT NULL CHECK (active IN (0, 1)),
     event_seq          INTEGER NOT NULL CHECK (event_seq >= 1),
     actor              TEXT NOT NULL,
     created_at         TEXT NOT NULL,
     PRIMARY KEY (scope_home, consumer_kind, consumer_namespace, consumer_name, family)
    )"#,
    r#"CREATE INDEX idx_consumer_requirements_scope
        ON consumer_requirements(scope_home)"#,
];

/// Generic consumer kinds allowed in Increment 1: fixture saved-query and
/// dependent-package consumers. Closed list so a typo'd kind cannot silently
/// partition the registry.
pub const CONSUMER_KINDS: [&str; 2] = ["saved-query", "dependent-package"];

/// Reserved for the future package-adoption derivation writer (Increment 2).
/// Generic register/retire APIs must refuse this kind so adoption-derived
/// requirements can never be forged or cleared through the generic seam.
pub const PACKAGE_SURFACE_KIND: &str = "package-surface";

pub(crate) async fn ensure_consumer_tables(db: &crate::db::Db) -> Result<()> {
    for statement in CONSUMER_DDL {
        sqlx::query(statement).execute(db.write_pool()).await?;
    }
    Ok(())
}

/// Deterministic meta-event subject for one consumer requirement key.
pub fn consumer_subject(
    scope_home: &str,
    consumer_kind: &str,
    consumer_namespace: &str,
    consumer_name: &str,
    family: &str,
) -> String {
    format!("consumer-requirement:{scope_home}:{consumer_kind}:{consumer_namespace}:{consumer_name}:{family}")
}

fn validate_token(kind: &str, part: &str) -> Result<()> {
    if part.is_empty() || part.len() > 128 {
        return Err(Error::engine(format!(
            "consumer {kind} must be 1..128 bytes"
        )));
    }
    if !part
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return Err(Error::engine(format!(
            "consumer {kind} '{part}' must match [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<()> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::engine(
            "consumer requirement digest must be 64 lowercase hex chars",
        ));
    }
    Ok(())
}

fn validate_key(
    scope_home: &str,
    consumer_kind: &str,
    consumer_namespace: &str,
    consumer_name: &str,
    family: &str,
    version: u32,
) -> Result<()> {
    if scope_home.is_empty() || scope_home.len() > 256 {
        return Err(Error::engine("consumer scope_home must be 1..256 bytes"));
    }
    if consumer_kind == PACKAGE_SURFACE_KIND {
        return Err(Error::engine(
            "consumer kind 'package-surface' is reserved for package-adoption derivation",
        ));
    }
    if !CONSUMER_KINDS.contains(&consumer_kind) {
        return Err(Error::engine(format!(
            "consumer kind '{consumer_kind}' is not one of saved-query, dependent-package"
        )));
    }
    validate_token("namespace", consumer_namespace)?;
    validate_token("name", consumer_name)?;
    crate::meta::definition_artifact::validate_family_version(family, version)?;
    Ok(())
}

/// Verify a required payload against its subject before append or projection.
pub fn verify_required_payload(
    subject_id: &str,
    payload: &ConsumerRequiredV1Payload,
) -> Result<()> {
    if subject_id
        != consumer_subject(
            &payload.scope_home,
            &payload.consumer_kind,
            &payload.consumer_namespace,
            &payload.consumer_name,
            &payload.family,
        )
    {
        return Err(Error::engine(
            "consumer requirement subject does not match requirement key",
        ));
    }
    validate_key(
        &payload.scope_home,
        &payload.consumer_kind,
        &payload.consumer_namespace,
        &payload.consumer_name,
        &payload.family,
        payload.version,
    )?;
    validate_digest(&payload.digest)?;
    Ok(())
}

/// Verify a retired payload against its subject before append or projection.
pub fn verify_retired_payload(subject_id: &str, payload: &ConsumerRetiredV1Payload) -> Result<()> {
    if subject_id
        != consumer_subject(
            &payload.scope_home,
            &payload.consumer_kind,
            &payload.consumer_namespace,
            &payload.consumer_name,
            &payload.family,
        )
    {
        return Err(Error::engine(
            "consumer retirement subject does not match requirement key",
        ));
    }
    validate_key(
        &payload.scope_home,
        &payload.consumer_kind,
        &payload.consumer_namespace,
        &payload.consumer_name,
        &payload.family,
        payload.version,
    )?;
    validate_digest(&payload.digest)?;
    Ok(())
}

/// One stored requirement as read back, with the authorizing event seq.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredConsumer {
    pub scope_home: String,
    pub consumer_kind: String,
    pub consumer_namespace: String,
    pub consumer_name: String,
    pub family: String,
    pub version: u32,
    pub digest: String,
    pub active: bool,
    pub event_seq: i64,
    pub actor: String,
}

pub(crate) struct ConsumerWriteOutcome {
    pub stored: StoredConsumer,
    /// Whether this call appended a new event (false = verified no-op).
    /// Read by the Increment 3 preflight to distinguish moves from retries;
    /// allowed dead until that increment lands.
    #[allow(dead_code)]
    pub appended: bool,
}

async fn event_count_for(tx: &mut Transaction<'static, Sqlite>, subject: &str) -> Result<i64> {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM meta_events
          WHERE (type = 'consumer_required.v1' OR type = 'consumer_retired.v1')
            AND subject_id = ?",
    )
    .bind(subject)
    .fetch_one(&mut **tx)
    .await
    .map_err(crate::error::Error::from)
}

async fn require_pin_installed(
    tx: &mut Transaction<'static, Sqlite>,
    family: &str,
    version: u32,
    digest: &str,
) -> Result<()> {
    let installed =
        crate::definition_registry::read_definition_artifact_on(&mut *tx, family, version, digest)
            .await?;
    if installed.is_none() {
        return Err(Error::engine(
            "consumer requirement selects a definition revision that is not installed",
        ));
    }
    Ok(())
}

/// Revision precondition for register/retire: updates and retires must name
/// the event seq they saw, so a stale writer cannot clobber a moved pin.
/// `None` means no precondition (fresh registration path only; preflight and
/// future callers pass `Some`).
pub type ExpectedSeq = Option<i64>;

/// Register (or move) one exact-pin requirement inside the caller's tx.
/// Exact active retry (same pin) appends nothing; a moved pin or a
/// re-registration after retire appends a new event. A subject with prior
/// events but no projection row refuses (fail closed) before any append.
/// A `Some` precondition must equal the current row's event seq, else the
/// write refuses as stale — including on the exact-retry path, so a retry
/// never blesses state it did not verify.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn register_consumer_in(
    tx: &mut Transaction<'static, Sqlite>,
    scope_home: &str,
    consumer_kind: &str,
    consumer_namespace: &str,
    consumer_name: &str,
    family: &str,
    version: u32,
    digest: &str,
    expected_seq: ExpectedSeq,
    actor: Option<&str>,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<ConsumerWriteOutcome> {
    validate_key(
        scope_home,
        consumer_kind,
        consumer_namespace,
        consumer_name,
        family,
        version,
    )?;
    validate_digest(digest)?;
    require_pin_installed(tx, family, version, digest).await?;
    let subject = consumer_subject(
        scope_home,
        consumer_kind,
        consumer_namespace,
        consumer_name,
        family,
    );
    let row: Option<(i64, String, i64, i64, i64)> = sqlx::query_as(
        "SELECT version, digest, active, event_seq, 1 FROM consumer_requirements
          WHERE scope_home = ? AND consumer_kind = ? AND consumer_namespace = ?
            AND consumer_name = ? AND family = ?",
    )
    .bind(scope_home)
    .bind(consumer_kind)
    .bind(consumer_namespace)
    .bind(consumer_name)
    .bind(family)
    .fetch_optional(&mut **tx)
    .await?;
    match row {
        Some((v, d, _, seq, _)) => {
            // Updates move a live row: they must name the seq they saw.
            // `None` here is a blind write and refuses, so only a fresh
            // registration (no row) may skip the precondition.
            let Some(expected) = expected_seq else {
                return Err(Error::engine(
                    "stale consumer registration: updates must name the current event seq",
                ));
            };
            if expected != seq {
                return Err(Error::engine(
                    "stale consumer registration: the requirement moved under this writer",
                ));
            }
            // Verify the existing row against its authorizing event BEFORE
            // changing anything: a corrupt nonmatching active row must fail
            // here, never be overwritten or blessed as a no-op.
            let verified = read_consumer_in(
                &mut *tx,
                scope_home,
                consumer_kind,
                consumer_namespace,
                consumer_name,
                family,
            )
            .await?
            .ok_or_else(|| Error::engine("consumer projection vanished mid-register"))?;
            debug_assert_eq!(verified.event_seq, seq);
            // Exact-state retry is actor-inclusive: only the same attributor
            // gets the existing receipt. A different principal falls through
            // and records their own attributed event below.
            if verified.active
                && v == version as i64
                && d == digest
                && actor.unwrap_or("") == verified.actor
            {
                return Ok(ConsumerWriteOutcome {
                    stored: verified,
                    appended: false,
                });
            }
        }
        None => {
            if expected_seq.is_some() {
                return Err(Error::engine(
                    "stale consumer registration: the requirement moved under this writer",
                ));
            }
            if event_count_for(tx, &subject).await? != 0 {
                return Err(Error::engine(
                    "consumer projection/log disagreement: requirement has prior events but no projection row",
                ));
            }
        }
    }
    let payload = ConsumerRequiredV1Payload {
        scope_home: scope_home.to_string(),
        consumer_kind: consumer_kind.to_string(),
        consumer_namespace: consumer_namespace.to_string(),
        consumer_name: consumer_name.to_string(),
        family: family.to_string(),
        version,
        digest: digest.to_string(),
    };
    verify_required_payload(&subject, &payload)?;
    let event = append_meta_in(
        tx,
        MetaAppendSpec::with_payload(
            &subject,
            "consumer_required.v1",
            serde_json::to_value(&payload)?,
        )
        .with_actor(actor),
        act_alloc,
    )
    .await?;
    let stored = read_consumer_in(
        &mut *tx,
        scope_home,
        consumer_kind,
        consumer_namespace,
        consumer_name,
        family,
    )
    .await?
    .ok_or_else(|| Error::engine("consumer projection missing after register"))?;
    debug_assert_eq!(stored.event_seq, event.seq);
    Ok(ConsumerWriteOutcome {
        stored,
        appended: true,
    })
}

/// Retire one requirement inside the caller's tx. The row stays with
/// `active = 0`. Retiring an absent requirement refuses; retiring an
/// already-retired one is an exact no-op (verified, appends nothing).
/// A `Some` precondition must equal the current row's event seq, else the
/// retire refuses as stale.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn retire_consumer_in(
    tx: &mut Transaction<'static, Sqlite>,
    scope_home: &str,
    consumer_kind: &str,
    consumer_namespace: &str,
    consumer_name: &str,
    family: &str,
    expected_seq: ExpectedSeq,
    actor: Option<&str>,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<ConsumerWriteOutcome> {
    validate_key(
        scope_home,
        consumer_kind,
        consumer_namespace,
        consumer_name,
        family,
        0,
    )?;
    let subject = consumer_subject(
        scope_home,
        consumer_kind,
        consumer_namespace,
        consumer_name,
        family,
    );
    let row: Option<(i64, String, i64, i64)> = sqlx::query_as(
        "SELECT version, digest, active, event_seq FROM consumer_requirements
          WHERE scope_home = ? AND consumer_kind = ? AND consumer_namespace = ?
            AND consumer_name = ? AND family = ?",
    )
    .bind(scope_home)
    .bind(consumer_kind)
    .bind(consumer_namespace)
    .bind(consumer_name)
    .bind(family)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((_, _, _, seq)) = row else {
        if event_count_for(tx, &subject).await? != 0 {
            return Err(Error::engine(
                "consumer projection/log disagreement: retirement has prior events but no projection row",
            ));
        }
        return Err(Error::engine("no active consumer requirement to retire"));
    };
    // Retires name the seq they saw, like updates: a blind retire over an
    // existing row refuses even when the row is live.
    let Some(expected) = expected_seq else {
        return Err(Error::engine(
            "stale consumer retirement: retirements must name the current event seq",
        ));
    };
    if expected != seq {
        return Err(Error::engine(
            "stale consumer retirement: the requirement moved under this writer",
        ));
    }
    // Verify the existing row against its authorizing event BEFORE retiring:
    // a corrupt row must fail here, never be cleared or blessed.
    let verified = read_consumer_in(
        &mut *tx,
        scope_home,
        consumer_kind,
        consumer_namespace,
        consumer_name,
        family,
    )
    .await?
    .ok_or_else(|| Error::engine("consumer projection vanished mid-retire"))?;
    debug_assert_eq!(verified.event_seq, seq);
    // Inactive retry is actor-inclusive like registration: only the same
    // attributor gets the existing receipt; a different principal records
    // their own retirement below.
    if !verified.active && actor.unwrap_or("") == verified.actor {
        return Ok(ConsumerWriteOutcome {
            stored: verified,
            appended: false,
        });
    }
    // The retirement carries the verified live pin, so the fold and later
    // reads can prove the retained inactive pin was never tampered with.
    let payload = ConsumerRetiredV1Payload {
        scope_home: scope_home.to_string(),
        consumer_kind: consumer_kind.to_string(),
        consumer_namespace: consumer_namespace.to_string(),
        consumer_name: consumer_name.to_string(),
        family: family.to_string(),
        version: verified.version,
        digest: verified.digest.clone(),
    };
    verify_retired_payload(&subject, &payload)?;
    let event = append_meta_in(
        tx,
        MetaAppendSpec::with_payload(
            &subject,
            "consumer_retired.v1",
            serde_json::to_value(&payload)?,
        )
        .with_actor(actor),
        act_alloc,
    )
    .await?;
    let stored = read_consumer_in(
        &mut *tx,
        scope_home,
        consumer_kind,
        consumer_namespace,
        consumer_name,
        family,
    )
    .await?
    .ok_or_else(|| Error::engine("consumer projection missing after retire"))?;
    debug_assert_eq!(stored.event_seq, event.seq);
    debug_assert!(!stored.active);
    Ok(ConsumerWriteOutcome {
        stored,
        appended: true,
    })
}

/// Verified read of one requirement: projection row + authorizing event must
/// agree (payload pin for required, key for retired, actor, seq). A missing
/// row is `Ok(None)` only when no event exists for the subject; otherwise
/// fail closed. Any disagreement is an error, never a fallback.
pub(crate) async fn read_consumer_in(
    conn: &mut SqliteConnection,
    scope_home: &str,
    consumer_kind: &str,
    consumer_namespace: &str,
    consumer_name: &str,
    family: &str,
) -> Result<Option<StoredConsumer>> {
    let row: Option<(i64, String, i64, i64, String)> = sqlx::query_as(
        "SELECT version, digest, active, event_seq, actor FROM consumer_requirements
          WHERE scope_home = ? AND consumer_kind = ? AND consumer_namespace = ?
            AND consumer_name = ? AND family = ?",
    )
    .bind(scope_home)
    .bind(consumer_kind)
    .bind(consumer_namespace)
    .bind(consumer_name)
    .bind(family)
    .fetch_optional(&mut *conn)
    .await?;
    let subject = consumer_subject(
        scope_home,
        consumer_kind,
        consumer_namespace,
        consumer_name,
        family,
    );
    let event: Option<(String, String, i64, Option<String>)> = sqlx::query_as(
        "SELECT type, payload, seq, actor FROM meta_events
          WHERE subject_id = ?
            AND (type = 'consumer_required.v1' OR type = 'consumer_retired.v1')
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(&subject)
    .fetch_optional(&mut *conn)
    .await?;
    match (row, event) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(Error::engine(
            "consumer projection/log disagreement: requirement has events but no projection row",
        )),
        (Some(_), None) => Err(Error::engine(
            "consumer projection/log disagreement: requirement has a projection row but no authorizing event",
        )),
        (Some((version, digest, active, event_seq, actor)), Some((etype, payload, seq, eactor))) => {
            if seq != event_seq {
                return Err(Error::engine(
                    "consumer projection disagrees with its authorizing log event",
                ));
            }
            if eactor.as_deref().unwrap_or("") != actor {
                return Err(Error::engine(
                    "consumer actor disagrees with its authorizing log event",
                ));
            }
            if etype == "consumer_required.v1" {
                let p: ConsumerRequiredV1Payload = serde_json::from_str(&payload)?;
                if p.version as i64 != version || p.digest != digest || active != 1 {
                    return Err(Error::engine(
                        "consumer projection disagrees with its authorizing log event",
                    ));
                }
                if p.scope_home != scope_home
                    || p.consumer_kind != consumer_kind
                    || p.consumer_namespace != consumer_namespace
                    || p.consumer_name != consumer_name
                    || p.family != family
                {
                    return Err(Error::engine(
                        "consumer authorizing event names a different requirement key",
                    ));
                }
            } else {
                let p: ConsumerRetiredV1Payload = serde_json::from_str(&payload)?;
                if active != 0 {
                    return Err(Error::engine(
                        "consumer projection disagrees with its authorizing log event",
                    ));
                }
                // The retained inactive pin must equal the pin the
                // retirement verified: a tampered inactive pin fails here,
                // never reads as a benign retired row.
                if version != p.version as i64 || digest != p.digest {
                    return Err(Error::engine(
                        "consumer retained pin disagrees with its retirement event",
                    ));
                }
                if p.scope_home != scope_home
                    || p.consumer_kind != consumer_kind
                    || p.consumer_namespace != consumer_namespace
                    || p.consumer_name != consumer_name
                    || p.family != family
                {
                    return Err(Error::engine(
                        "consumer authorizing event names a different requirement key",
                    ));
                }
            }
            Ok(Some(StoredConsumer {
                scope_home: scope_home.to_string(),
                consumer_kind: consumer_kind.to_string(),
                consumer_namespace: consumer_namespace.to_string(),
                consumer_name: consumer_name.to_string(),
                family: family.to_string(),
                version: u32::try_from(version).map_err(|_| {
                    Error::engine("consumer projection version is corrupt")
                })?,
                digest,
                active: active == 1,
                event_seq,
                actor,
            }))
        }
    }
}

/// Typed list of one scope's requirements, every row verified. Union-keys
/// fail-closed: subjects carrying events for this scope without a projection
/// row abort the whole list (never silently skipped).
pub(crate) async fn list_consumers_in(
    conn: &mut SqliteConnection,
    scope_home: &str,
) -> Result<Vec<StoredConsumer>> {
    let subjects: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT subject_id FROM meta_events
          WHERE (type = 'consumer_required.v1' OR type = 'consumer_retired.v1')",
    )
    .fetch_all(&mut *conn)
    .await?;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT consumer_kind, consumer_namespace, consumer_name, family
           FROM consumer_requirements WHERE scope_home = ?",
    )
    .bind(scope_home)
    .fetch_all(&mut *conn)
    .await?;
    for (kind, ns, name, family) in &rows {
        seen.insert(consumer_subject(scope_home, kind, ns, name, family));
        let stored = read_consumer_in(conn, scope_home, kind, ns, name, family)
            .await?
            .ok_or_else(|| Error::engine("consumer projection vanished mid-list"))?;
        out.push(stored);
    }
    for (subject,) in subjects {
        let prefix = format!("consumer-requirement:{scope_home}:");
        if !subject.starts_with(&prefix) {
            continue;
        }
        if !seen.contains(&subject) {
            return Err(Error::engine(
                "consumer projection/log disagreement: requirement has events but no projection row",
            ));
        }
    }
    out.sort_by(|a, b| {
        (
            &a.consumer_kind,
            &a.consumer_namespace,
            &a.consumer_name,
            &a.family,
        )
            .cmp(&(
                &b.consumer_kind,
                &b.consumer_namespace,
                &b.consumer_name,
                &b.family,
            ))
    });
    Ok(out)
}
