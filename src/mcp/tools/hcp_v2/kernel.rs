//! Kernel-native HCP persistence. The content log is the authority; these
//! private, feature-specific tables are disposable projections of that log.
use super::{fold, store::stored_subject_id_of};
#[cfg(feature = "v2-kernel-probe")]
use crate::db::Db;
use crate::{
    control::{self, ControlEventRow},
    events::EventRow,
    Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Row, SqliteConnection};

pub(crate) const AUDIT_DDL: &str = "CREATE TABLE kernel_hcp_audit (principal_id TEXT NOT NULL, event_id TEXT NOT NULL UNIQUE, event_key TEXT NOT NULL, event_type TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)), created_at TEXT NOT NULL, event_seq INTEGER NOT NULL UNIQUE, PRIMARY KEY(principal_id,event_key))";
pub(crate) const ENTRIES_DDL: &str = "CREATE TABLE kernel_hcp_entries (principal_id TEXT NOT NULL, entry_id TEXT NOT NULL, entry TEXT NOT NULL CHECK(json_valid(entry)), PRIMARY KEY(principal_id,entry_id))";
pub(crate) const DISCLOSURES_DDL: &str = "CREATE TABLE kernel_hcp_disclosures (principal_id TEXT NOT NULL, client_id TEXT NOT NULL, entry_id TEXT NOT NULL, PRIMARY KEY(principal_id,client_id,entry_id))";
pub(crate) const RESOLUTIONS_DDL: &str = "CREATE TABLE kernel_hcp_resolutions (principal_id TEXT NOT NULL,suggestion_id TEXT NOT NULL,receipt_id TEXT NOT NULL,nonce TEXT NOT NULL,event_id TEXT NOT NULL UNIQUE,payload TEXT NOT NULL CHECK(json_valid(payload)),event_seq INTEGER NOT NULL,PRIMARY KEY(principal_id,suggestion_id),UNIQUE(principal_id,nonce),UNIQUE(principal_id,receipt_id))";
#[cfg(feature = "v2-kernel-probe")]
pub(crate) const TYPES: &[&str] = &[
    "kernel.hcp_entry_versioned.v1",
    "kernel.hcp_entry_status_set.v1",
    "kernel.hcp_read.v1",
    "kernel.hcp_entry_suggestion.v1",
    "kernel.hcp_entry_confirmed.v1",
    "kernel.hcp_human_resolution.v1",
];
fn core_type(ty: &str) -> Result<&'static str> {
    match ty {
        "kernel.hcp_entry_versioned.v1" => Ok("hcp.entry.versioned.v1"),
        "kernel.hcp_entry_status_set.v1" => Ok("hcp.entry.status_set.v1"),
        "kernel.hcp_read.v1" => Ok("hcp.read.v1"),
        "kernel.hcp_entry_suggestion.v1" => Ok("hcp.entry.suggestion.v1"),
        "kernel.hcp_entry_confirmed.v1" => Ok("hcp.entry.confirmed.v1"),
        _ => Err(Error::engine("unknown sealed kernel HCP event")),
    }
}
#[cfg(feature = "v2-kernel-probe")]
fn kernel_type(ty: &str) -> Result<&'static str> {
    TYPES
        .iter()
        .copied()
        .find(|candidate| core_type(candidate).ok() == Some(ty))
        .ok_or_else(|| Error::engine("invalid kernel HCP payload"))
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    key: String,
    reason: String,
    payload: Value,
}

/// Explicit compatibility preparation may add empty HCP projections only to
/// a file with no HCP history. Full replay owns recovery after projection loss:
/// human-evidence folds must see ordinary state at each event's boundary.
pub(crate) async fn prepare_schema(conn: &mut SqliteConnection) -> Result<()> {
    let present: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('kernel_hcp_audit','kernel_hcp_entries','kernel_hcp_disclosures','kernel_hcp_resolutions')",
    ).fetch_one(&mut *conn).await?;
    if present != 4 {
        let history: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM content_events WHERE type GLOB 'kernel.hcp_*')",
        )
        .fetch_one(&mut *conn)
        .await?;
        if history {
            return Err(Error::engine(
                "v2 preparation refuses missing HCP projections with retained HCP history; run explicit full-projection replay/recovery (replay_all_projections) before serving",
            ));
        }
    }
    ensure_schema(conn).await
}

pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    for ddl in [AUDIT_DDL, ENTRIES_DDL, DISCLOSURES_DDL, RESOLUTIONS_DDL] {
        sqlx::query(&ddl.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}
/// Only the HCP module can mint the seal. Subject is already resolved from
/// the authenticated kernel binding, never supplied by a tool argument.
#[cfg(feature = "v2-kernel-probe")]
pub(super) async fn append(
    db: &Db,
    tx: &mut super::store::WriteTx,
    act: &mut crate::act::ActAllocation,
    principal: &str,
    key: String,
    reason: String,
    payload: control::ControlEventPayload,
) -> Result<()> {
    let ty = kernel_type(payload.event_type())?;
    let encoded = payload.to_json()?;
    let previous: Option<(String, String)> = sqlx::query_as(
        "SELECT event_type,payload FROM kernel_hcp_audit WHERE principal_id=? AND event_key=?",
    )
    .bind(principal)
    .bind(&key)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some((old_type, old_payload)) = previous {
        if old_type != payload.event_type() || old_payload != encoded {
            return Err(Error::conflict(
                "kernel HCP event key reused with different content",
            ));
        }
        return Ok(());
    }

    crate::store::append_kernel_hcp_in(
        db,
        tx,
        &super::HcpWriteSeal::mint(),
        crate::store::AppendSpec {
            record_id: principal.into(),
            event_type: ty.into(),
            actor: Some(principal.into()),
            payload: serde_json::to_value(Envelope {
                key,
                reason,
                payload: serde_json::from_str(&payload.to_json()?)?,
            })?,
        },
        act,
    )
    .await?;
    Ok(())
}
/// Shared shape validation, without v1 persistence. The borrowed v1 envelope
/// exists only in memory to reuse its closed payload/identity validators.
async fn decode(conn: &mut SqliteConnection, event: &EventRow) -> Result<ControlEventRow> {
    let p: Envelope = serde_json::from_str(event.payload.as_deref().unwrap_or("null"))?;
    let ty = core_type(&event.event_type)?;
    if event.actor.as_deref() != Some(event.record_id.as_str()) {
        return Err(Error::engine("kernel HCP actor must be its principal"));
    }
    let account: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=? AND kind='account')",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if !account {
        return Err(Error::engine("kernel HCP requires an account principal"));
    }
    let read = ty == "hcp.read.v1";
    let row = ControlEventRow {
        seq: event.local_seq.max(1),
        id: event.id.clone(),
        idempotency_key: p.key,
        event_type: ty.into(),
        schema_version: 1,
        aggregate_kind: if read { "hcp_audit" } else { "hcp_state" }.into(),
        aggregate_id: if read {
            control::hcp_audit_aggregate_id(&event.record_id)
        } else {
            control::hcp_state_aggregate_id(&event.record_id)
        },
        actor: event.record_id.clone(),
        run_key: event.run_key.clone(),
        reason: p.reason,
        payload: p.payload.to_string(),
        created_at: event.created_at.clone(),
        act: event.act,
    };
    control::validate_stored_control_event(&row)?;
    Ok(row)
}
pub(super) async fn events(
    conn: &mut SqliteConnection,
    principal: &str,
    entry: Option<&str>,
) -> Result<Vec<fold::StoredEvent>> {
    let rows = sqlx::query("SELECT event_seq,event_type,payload FROM kernel_hcp_audit WHERE principal_id=? AND event_type!='hcp.read.v1' AND (? IS NULL OR json_extract(payload,'$.entry_id')=?) ORDER BY event_seq")
        .bind(principal).bind(entry).bind(entry).fetch_all(conn).await?;
    rows.into_iter()
        .map(|r| {
            Ok(fold::StoredEvent {
                seq: r.try_get("event_seq")?,
                event_type: r.try_get("event_type")?,
                payload: r.try_get("payload")?,
            })
        })
        .collect()
}
pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    #[cfg(feature = "v2-kernel-probe")]
    if event.event_type == "kernel.hcp_human_resolution.v1" {
        return super::kernel_human::project(conn, event).await;
    }
    let row = decode(conn, event).await?;
    if row.event_type == "hcp.entry.confirmed.v1" {
        #[cfg(feature = "v2-kernel-probe")]
        super::kernel_human::validate_confirmation(conn, &row).await?;
        #[cfg(not(feature = "v2-kernel-probe"))]
        return Err(Error::engine(
            "kernel HCP human confirmation requires v2-kernel-probe",
        ));
    }

    let principal = &row.actor;
    let mut history = events(conn, principal, None).await?;
    let payload: Value = serde_json::from_str(&row.payload)?;
    let mut disclosure = Vec::new();
    if row.event_type == "hcp.read.v1" {
        let read: control::HcpReadPayload = serde_json::from_value(payload.clone())?;
        let prior = fold::fold(principal, &stored_subject_id_of(principal), &history);
        if read
            .entry_ids
            .iter()
            .any(|id| !prior.entries.contains_key(id))
        {
            return Err(Error::engine("HCP read names an unknown entry"));
        }
        disclosure = read.entry_ids;
    } else {
        history.push(fold::StoredEvent {
            seq: row.seq,
            event_type: row.event_type.clone(),
            payload: row.payload.clone(),
        });
    }
    let folded = fold::fold(principal, &stored_subject_id_of(principal), &history);
    if !folded.rejected.is_empty() {
        return Err(Error::engine("invalid kernel HCP event chain"));
    }
    sqlx::query("INSERT INTO kernel_hcp_audit VALUES(?,?,?,?,?,?,?)")
        .bind(principal)
        .bind(&row.id)
        .bind(&row.idempotency_key)
        .bind(&row.event_type)
        .bind(&row.payload)
        .bind(&row.created_at)
        .bind(event.local_seq)
        .execute(&mut *conn)
        .await?;
    for (id, entry) in &folded.entries {
        sqlx::query("INSERT INTO kernel_hcp_entries VALUES(?,?,?) ON CONFLICT(principal_id,entry_id) DO UPDATE SET entry=excluded.entry")
            .bind(principal).bind(id).bind(entry.current().0.to_string()).execute(&mut *conn).await?;
    }
    if row.event_type == "hcp.entry.versioned.v1"
        && matches!(payload["cause"].as_str(), Some("add" | "update"))
    {
        // decode() already checked this closed payload; retain a typed error
        // path here too, so damaged persisted data cannot panic the projector.
        let version: control::HcpEntryVersionedPayload = serde_json::from_value(payload.clone())?;
        disclosure.push(version.entry_id);
    }
    let client: control::HcpClientPayload = serde_json::from_value(payload["client"].clone())?;
    for id in disclosure {
        sqlx::query("INSERT OR IGNORE INTO kernel_hcp_disclosures VALUES(?,?,?)")
            .bind(principal)
            .bind(&client.id)
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod tests {
    use super::super::{
        client::ClientIdentity,
        model::{new_entry, Assertion},
        store::{entry_urn, payload_of, sha256_hex},
    };
    use super::*;
    use serde_json::json;

    async fn add(db: &Db, principal: &str, key: &str, preference: &str, id: &str) -> Result<()> {
        let client = ClientIdentity::native();
        let subject = stored_subject_id_of(principal);
        let value = json!(preference);
        let entry = new_entry(
            &entry_urn(id),
            "general_preferences",
            None,
            &subject,
            &Assertion {
                preference: &value,
                declaration_type: "user-declared",
                confidence: None,
                asserted_by: &subject,
                source: "test",
                client: &client,
                recorded_at: "2026-10-24T00:00:00Z",
                asserted_at: None,
            },
        );
        let p = control::HcpEntryVersionedPayload {
            account_id: principal.into(),
            entry_id: entry.id().into(),
            version: 1,
            cause: "add".into(),
            prior_category: None,
            client: payload_of(&client),
            reason: None,
            view_digest: sha256_hex(&entry.0.to_string()),
            entry: entry.0,
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await?;
        append(
            db,
            &mut tx,
            &mut crate::act::ActAllocation::new(),
            principal,
            key.into(),
            "test add".into(),
            control::ControlEventPayload::HcpEntryVersioned(p),
        )
        .await?;
        db.commit_kernel_content(tx).await
    }

    #[tokio::test]
    async fn kernel_hcp_sealed_private_atomic_retry_and_replay() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("hcp.db").display());
        let (db, admin) = crate::kernel::create_v2_database(&url, "account", "Admin", "acct:admin")
            .await
            .unwrap();
        let other = crate::kernel::create_principal(&db, "account", "Other", "acct:other", &admin)
            .await
            .unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        add(&db, &other, "one", "Be concise", &id).await.unwrap();
        add(&db, &other, "one", "Be concise", &id).await.unwrap();
        assert!(add(&db, &other, "one", "Different", &id).await.is_err());
        let mut conn = db.write_pool().acquire().await.unwrap();
        assert!(events(&mut conn, &admin, None).await.unwrap().is_empty());
        assert_eq!(events(&mut conn, &other, None).await.unwrap().len(), 1);
        drop(conn);
        let spec = crate::store::AppendSpec {
            record_id: other.clone(),
            actor: Some(other.clone()),
            event_type: TYPES[0].into(),
            payload: json!({}),
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        assert!(
            crate::store::append_in(&db, &mut tx, spec, &mut crate::act::ActAllocation::new())
                .await
                .is_err()
        );
        tx.rollback().await.unwrap();
        assert!(crate::kernel::history_as(&db, &admin, &other)
            .await
            .unwrap()
            .iter()
            .all(|e| !e.event_type.starts_with("kernel.hcp_")));
        let before = crate::kernel::dump_all_kernel_tables(&db).await.unwrap();
        crate::kernel::replay_all_projections(&db).await.unwrap();
        assert_eq!(
            before,
            crate::kernel::dump_all_kernel_tables(&db).await.unwrap()
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM sqlite_master WHERE name='control_events'"
            )
            .fetch_one(db.pool())
            .await
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn kernel_hcp_prepare_older_file_without_hcp_history_restores_readonly_readiness() {
        use sqlx::Connection;
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("older.db").display());
        let (db, _) = crate::kernel::create_v2_database(&url, "account", "Admin", "test:older")
            .await
            .unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        for table in [
            "kernel_hcp_audit",
            "kernel_hcp_entries",
            "kernel_hcp_disclosures",
            "kernel_hcp_resolutions",
        ] {
            sqlx::query(&format!("DROP TABLE {table}"))
                .execute(&mut *tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        assert!(crate::kernel::verify_v2_ready(&db).await.is_err());
        crate::kernel::prepare_v2_database(&db).await.unwrap();
        let mut readonly = sqlx::SqliteConnection::connect(&format!("{url}?mode=ro"))
            .await
            .unwrap();
        crate::kernel::verify_v2_ready_on(&mut readonly)
            .await
            .unwrap();
        readonly.close().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kernel_hcp_audit")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn kernel_hcp_prepare_missing_projection_with_history_requires_explicit_full_replay() {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("lost.db").display());
        let (db, admin) = crate::kernel::create_v2_database(&url, "account", "Admin", "test:lost")
            .await
            .unwrap();
        add(
            &db,
            &admin,
            "retained",
            "Be concise",
            &uuid::Uuid::new_v4().to_string(),
        )
        .await
        .unwrap();
        let expected = crate::kernel::dump_all_kernel_tables(&db).await.unwrap();
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        for table in [
            "kernel_hcp_audit",
            "kernel_hcp_entries",
            "kernel_hcp_disclosures",
            "kernel_hcp_resolutions",
        ] {
            sqlx::query(&format!("DROP TABLE {table}"))
                .execute(db.write_pool())
                .await
                .unwrap();
            let error = crate::kernel::prepare_v2_database(&db)
                .await
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("explicit full-projection replay/recovery"),
                "{error}"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?"
                )
                .bind(table)
                .fetch_one(db.pool())
                .await
                .unwrap(),
                0,
                "failed preparation must not create empty projections"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                    .fetch_one(db.pool())
                    .await
                    .unwrap(),
                events
            );
            crate::kernel::replay_all_projections(&db).await.unwrap();
            assert_eq!(
                expected,
                crate::kernel::dump_all_kernel_tables(&db).await.unwrap()
            );
            crate::kernel::verify_v2_ready(&db).await.unwrap();
        }
    }
}
