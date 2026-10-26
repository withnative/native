//! Canonical private account configurations. Source mappings are sealed import
//! state; native provisioning binds a newly created private record atomically.
use super::*;
use serde_json::Value;

pub(crate) const EVENT: &str = "kernel.account_config_bound.v1";
pub(crate) const DDL: &str = "CREATE TABLE kernel_account_configs (
 principal_id TEXT NOT NULL REFERENCES kernel_principals(principal_id),
 kind TEXT NOT NULL, record_id TEXT NOT NULL UNIQUE, source_origin TEXT,
 source_deleted INTEGER NOT NULL, source_missing INTEGER NOT NULL,
 event_seq INTEGER NOT NULL, PRIMARY KEY(principal_id,kind))";

pub(crate) const BINDING_INDEX: &str = "CREATE INDEX idx_kernel_account_config_binding ON content_events(actor,json_extract(payload,'$.kind')) WHERE type='kernel.account_config_bound.v1'";

pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    sqlx::query(&DDL.replacen("CREATE TABLE", "CREATE TABLE IF NOT EXISTS", 1))
        .execute(&mut *conn)
        .await?;
    sqlx::query(&BINDING_INDEX.replacen("CREATE INDEX", "CREATE INDEX IF NOT EXISTS", 1))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub(crate) struct Mapping {
    pub record_id: String,
    pub source_origin: Option<String>,
    pub source_deleted: bool,
    pub source_missing: bool,
    pub event_seq: i64,
}
pub(crate) async fn mapping_on(
    conn: &mut SqliteConnection,
    principal: &str,
    kind: &str,
) -> Result<Option<Mapping>> {
    Ok(sqlx::query_as("SELECT record_id,source_origin,source_deleted,source_missing,event_seq FROM main.kernel_account_configs WHERE principal_id=? AND kind=?")
        .bind(principal).bind(kind).fetch_optional(conn).await?)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    created_act: i64,
    principal_id: String,
    kind: String,
    record_id: String,
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn bind_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    actor: &str,
    record: &str,
) -> Result<()> {
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: record.into(),
            event_type: EVENT.into(),
            payload: serde_json::to_value(Bound {
                created_act: acts.get().ok_or_else(|| {
                    Error::engine("account config must be created in this transaction")
                })?,
                principal_id: actor.into(),
                kind: "focus_preferences".into(),
                record_id: record.into(),
            })?,
            actor: Some(actor.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}

pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type != EVENT {
        return Ok(());
    }
    let p: Bound = event_payload(event)?;
    if event.actor.as_deref() != Some(p.principal_id.as_str())
        || event.record_id != p.record_id
        || p.kind != "focus_preferences"
    {
        return Err(Error::engine("invalid account configuration binding"));
    }
    if mapping_on(conn, &p.principal_id, &p.kind).await?.is_some() {
        return Err(Error::conflict(
            "account configuration mapping already exists",
        ));
    }
    // Only provisioning in this very act may bind a fresh record. Neither
    // adoption of an arbitrary same-kind record nor a root-owner override.
    validate_lineage_on(conn, event, &p).await?;
    if !kernel_effective_capability_on(conn, &p.principal_id, &p.record_id)
        .await?
        .allows(Capability::Manage)
    {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    Ok(())
}

async fn validate_lineage_on(
    conn: &mut SqliteConnection,
    event: &EventRow,
    p: &Bound,
) -> Result<()> {
    if p.created_act <= 0 || event.act.is_some_and(|act| act != p.created_act) {
        return Err(Error::engine(
            "account config creation act differs from its binding",
        ));
    }
    let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_records r JOIN main.kernel_principals p ON p.principal_id=r.owner_id WHERE r.id=?1 AND r.owner_id=?2 AND p.kind='account' AND EXISTS(SELECT 1 FROM main.content_events e WHERE e.record_id=r.id AND e.type='kernel.record_created.v1' AND e.actor=?2 AND e.act=?3) AND EXISTS(SELECT 1 FROM main.kernel_record_fields t WHERE t.record_id=r.id AND t.name='v1_type' AND t.value_json='\"Configuration\"') AND EXISTS(SELECT 1 FROM main.kernel_record_fields k WHERE k.record_id=r.id AND k.name='v1_kind' AND k.value_json='\"focus_preferences\"') AND EXISTS(SELECT 1 FROM main.content_events e WHERE e.record_id=r.home_id AND e.type='kernel.home_created.v1' AND json_extract(e.payload,'$.source_record_id')=r.id) AND (SELECT count(*) FROM main.kernel_policy_entries e WHERE e.root_id=r.home_id)=1 AND EXISTS(SELECT 1 FROM main.kernel_policy_entries e WHERE e.root_id=r.home_id AND e.subject_kind='account' AND e.subject_id=?2 AND e.effect='allow' AND e.capability='manage'))")
        .bind(&p.record_id).bind(&p.principal_id).bind(p.created_act).fetch_one(&mut *conn).await?;
    if !valid {
        return Err(Error::engine("account config provisioning requires a new, caller-owned account-only configuration in the same act"));
    }
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Bound = event_payload(event)?;
    // Reprojection validates event lineage without using today's roster.
    if event.actor.as_deref() != Some(p.principal_id.as_str())
        || event.record_id != p.record_id
        || p.kind != "focus_preferences"
    {
        return Err(Error::engine("invalid account configuration binding"));
    }
    if event.act != Some(p.created_act) {
        return Err(Error::engine(
            "account config creation act differs from its binding",
        ));
    }
    validate_lineage_on(conn, event, &p).await?;
    sqlx::query("INSERT INTO main.kernel_account_configs VALUES(?,?,?,NULL,0,0,?)")
        .bind(p.principal_id)
        .bind(p.kind)
        .bind(p.record_id)
        .bind(event.local_seq)
        .execute(conn)
        .await?;
    Ok(())
}

/// Called only by the sealed v1-state projector, never a member command.
pub(crate) async fn project_imported_on(
    conn: &mut SqliteConnection,
    row: &v1_state::ImportedState,
    seq: i64,
) -> Result<()> {
    if row.section != "account_configs" {
        return Ok(());
    }
    if let Some(value) = &row.value_json {
        let value: Value = serde_json::from_str(value)?;
        let principal = row
            .account_principal
            .as_deref()
            .ok_or_else(|| Error::engine("account config principal missing"))?;
        let kind = value["kind"]
            .as_str()
            .filter(|k| !k.is_empty())
            .ok_or_else(|| Error::engine("account config kind missing"))?;
        let record = value["record_id"]
            .as_str()
            .ok_or_else(|| Error::engine("account config record missing"))?;
        let account = value["account_id"]
            .as_str()
            .ok_or_else(|| Error::engine("account config account missing"))?;
        if row.source_id != serde_json::to_string(&serde_json::json!([account, kind]))? {
            return Err(Error::engine(
                "account config source key differs from its scope",
            ));
        }
        let deleted = value["_target_deleted"]
            .as_bool()
            .ok_or_else(|| Error::engine("account config deletion evidence missing"))?;
        let missing = value["_target_missing"]
            .as_bool()
            .ok_or_else(|| Error::engine("account config target evidence missing"))?;
        if let Some(old) = mapping_on(conn, principal, kind).await? {
            if old.source_origin.as_deref() != Some(row.origin.as_str()) {
                return Err(Error::conflict(
                    "account config mapping has native or different-source authority",
                ));
            }
        }
        sqlx::query("INSERT INTO main.kernel_account_configs VALUES(?,?,?,?,?,?,?) ON CONFLICT(principal_id,kind) DO UPDATE SET record_id=excluded.record_id,source_deleted=excluded.source_deleted,source_missing=excluded.source_missing,event_seq=excluded.event_seq")
            .bind(principal).bind(kind).bind(record).bind(&row.origin).bind(deleted).bind(missing).bind(seq).execute(conn).await?;
    } else {
        // The stable source key is the canonical [account_id,kind] tuple.
        let key: Vec<String> = serde_json::from_str(&row.source_id)?;
        if key.len() != 2 {
            return Err(Error::engine("invalid account config source key"));
        }
        let principal: Option<String>=sqlx::query_scalar("SELECT principal_id FROM main.kernel_principals WHERE auth_binding=? AND kind='account'").bind(&key[0]).fetch_optional(&mut *conn).await?;
        if let Some(principal) = principal {
            if let Some(old) = mapping_on(conn, &principal, &key[1]).await? {
                if old.source_origin.as_deref() != Some(row.origin.as_str()) {
                    return Err(Error::conflict(
                        "account config mapping has native or different-source authority",
                    ));
                }
            }
            sqlx::query("DELETE FROM main.kernel_account_configs WHERE principal_id=? AND kind=? AND source_origin=?")
                .bind(principal).bind(&key[1]).bind(&row.origin).execute(conn).await?;
        }
    }
    Ok(())
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn require_prepared_on(conn: &mut SqliteConnection) -> Result<()> {
    let origin: Option<String>=sqlx::query_scalar("SELECT json_extract(payload,'$.origin') FROM main.content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_optional(&mut *conn).await?;
    if let Some(origin) = origin {
        let prepared: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_v1_state WHERE section='account_config_capture' AND source_id='account_configs/v1' AND origin=? AND json_extract(payload,'$.version')=1)").bind(origin).fetch_one(conn).await?;
        if !prepared {
            return Err(Error::engine("manage_account_config: imported account mappings need preparation; resume the original import before activation, not just schema preparation"));
        }
    }
    Ok(())
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn verify_mapping_on(
    conn: &mut SqliteConnection,
    actor: &str,
    kind: &str,
    mapping: Option<&Mapping>,
) -> Result<()> {
    let valid = if let Some(mapping) = mapping {
        if let Some(origin) = &mapping.source_origin {
            let row: Option<(String,i64)>=sqlx::query_as("SELECT payload,event_seq FROM main.kernel_v1_state WHERE section='account_configs' AND account_principal=? AND origin=? AND json_extract(payload,'$.kind')=?")
                .bind(actor).bind(origin).bind(kind).fetch_optional(&mut *conn).await?;
            row.is_some_and(|(raw, seq)| {
                serde_json::from_str::<Value>(&raw).is_ok_and(|v| {
                    v["record_id"] == mapping.record_id
                        && v["_target_deleted"] == mapping.source_deleted
                        && v["_target_missing"] == mapping.source_missing
                        && seq == mapping.event_seq
                })
            })
        } else {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE seq=? AND type='kernel.account_config_bound.v1' AND actor=? AND record_id=? AND json_extract(payload,'$.principal_id')=? AND json_extract(payload,'$.kind')=?)")
                .bind(mapping.event_seq).bind(actor).bind(&mapping.record_id).bind(actor).bind(kind).fetch_one(&mut *conn).await?
        }
    } else {
        let imported: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_v1_state WHERE section='account_configs' AND account_principal=? AND json_extract(payload,'$.kind')=?)")
            .bind(actor).bind(kind).fetch_one(&mut *conn).await?;
        let native: bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE type='kernel.account_config_bound.v1' AND actor=? AND json_extract(payload,'$.kind')=?)")
            .bind(actor).bind(kind).fetch_one(&mut *conn).await?;
        !imported && !native
    };
    if !valid {
        return Err(Error::engine("manage_account_config: canonical mapping projection incomplete; reproject the prepared database, never provision a replacement"));
    }
    Ok(())
}

pub(crate) async fn imported_matches_on(
    conn: &mut SqliteConnection,
    row: &v1_state::ImportedState,
) -> Result<bool> {
    if row.section != "account_configs" {
        return Ok(true);
    }
    if let Some(raw) = &row.value_json {
        let value: Value = serde_json::from_str(raw)?;
        let principal = row
            .account_principal
            .as_deref()
            .ok_or_else(|| Error::engine("account config principal missing"))?;
        let kind = value["kind"]
            .as_str()
            .ok_or_else(|| Error::engine("account config kind missing"))?;
        let Some(mapping) = mapping_on(conn, principal, kind).await? else {
            return Ok(false);
        };
        let expected_seq: Option<i64> = sqlx::query_scalar("SELECT event_seq FROM main.kernel_v1_state WHERE section='account_configs' AND source_id=? AND origin=?")
            .bind(&row.source_id).bind(&row.origin).fetch_optional(&mut *conn).await?;
        Ok(Some(mapping.event_seq) == expected_seq
            && mapping.source_origin.as_deref() == Some(row.origin.as_str())
            && value["record_id"] == mapping.record_id
            && value["_target_deleted"] == mapping.source_deleted
            && value["_target_missing"] == mapping.source_missing)
    } else {
        Ok(true)
    }
}
