//! Exact imported caller footing, distinct from native workspace authority.
//! No directory/home/config fallback and no provisioning on read.
use super::*;

pub(crate) const SECTION: &str = "member_contexts";
pub(crate) const CAPTURE: &str = "member_context_capture";
pub(crate) const CAPTURE_ID: &str = "member-contexts/v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Context {
    pub account_id: String,
    pub person_record_id: String,
    pub root_record_id: String,
    pub created_at: String,
    pub person_missing: bool,
    pub person_deleted: bool,
    pub root_missing: bool,
    pub root_deleted: bool,
    /// Malformed/conflicting source state is retained, never silently remapped.
    pub invalid: bool,
}
impl Context {
    fn validate(&self) -> Result<()> {
        if [
            &self.account_id,
            &self.person_record_id,
            &self.root_record_id,
        ]
        .iter()
        .any(|s| s.trim().is_empty())
            || chrono::DateTime::parse_from_rfc3339(&self.created_at).is_err()
        {
            return Err(Error::engine("invalid imported member context"));
        }
        Ok(())
    }
}
pub(super) fn validate_envelope(row: &ImportedState) -> Result<()> {
    if row.section == SECTION {
        // Removal retains the source key, but carries no account authority.
        if let Some(raw) = &row.value_json {
            let value: Context = serde_json::from_str(raw)?;
            value.validate()?;
            if row.source_id != serde_json::to_string(&[&value.account_id])?
                || row.record_id.as_deref() != Some(value.root_record_id.as_str())
            {
                return Err(Error::engine("imported member context envelope differs"));
            }
        }
    }
    Ok(())
}
async fn origin_on(conn: &mut SqliteConnection) -> Result<Option<String>> {
    Ok(sqlx::query_scalar("SELECT json_extract(payload,'$.origin') FROM main.content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1")
        .fetch_optional(conn).await?)
}
/// Imported empty is evidence, not the absence of a table or receipt. No DDL.
pub(crate) async fn require_capture_on(conn: &mut SqliteConnection) -> Result<()> {
    let Some(origin) = origin_on(conn).await? else {
        return Ok(());
    };
    let raw: Option<(String, String)> = sqlx::query_as(
        "SELECT payload,origin FROM main.kernel_v1_state WHERE section=? AND source_id=?",
    )
    .bind(CAPTURE)
    .bind(CAPTURE_ID)
    .fetch_optional(&mut *conn)
    .await?;
    let error = || {
        Error::engine(
            "member contexts need preparation from the original source before H3 activation",
        )
    };
    let (raw, actual_origin) = raw.ok_or_else(error)?;
    let value: Value = serde_json::from_str(&raw)?;
    let count = value["rows"]
        .as_i64()
        .filter(|n| *n >= 0)
        .ok_or_else(error)?;
    if actual_origin != origin || value["version"] != 1 || value["refused"] != 0 {
        return Err(error());
    }
    // Selected columns: source ID, payload, account principal, record ID, origin.
    type CapturedContextRow = (String, String, Option<String>, Option<String>, String);
    let rows:Vec<CapturedContextRow>=sqlx::query_as("SELECT source_id,payload,account_principal,record_id,origin FROM main.kernel_v1_state WHERE section=?")
        .bind(SECTION).fetch_all(&mut *conn).await?;
    if rows.len() as i64 != count {
        return Err(error());
    }
    for (source_id, raw, principal, record_id, row_origin) in rows {
        let context: Context = serde_json::from_str(&raw)?;
        if context.invalid || row_origin != origin {
            return Err(error());
        }
        let row = ImportedState {
            section: SECTION.into(),
            source_id,
            origin: row_origin,
            value_json: Some(raw),
            account_principal: principal,
            record_id,
            observed_at: context.created_at.clone(),
            snapshot: serde_json::json!({}),
        };
        validate_envelope(&row)?;
        // Validate the exact authenticated account binding, not just row counts.
        super::validate_account(&mut *conn, &row).await?;
    }
    Ok(())
}
async fn own_on(conn: &mut SqliteConnection, actor: &str) -> Result<Option<Context>> {
    let raw:Option<String>=sqlx::query_scalar("SELECT s.payload FROM main.kernel_v1_state s JOIN main.kernel_principals p ON p.principal_id=s.account_principal AND p.kind='account' AND p.auth_binding=json_extract(s.payload,'$.account_id') WHERE s.section=? AND s.account_principal=?")
        .bind(SECTION).bind(actor).fetch_optional(conn).await?;
    raw.map(|r| serde_json::from_str(&r).map_err(Into::into))
        .transpose()
}
fn unavailable(reason: &str) -> Value {
    serde_json::json!({"status":"unavailable","reason":reason,"identity_basis":"retained v1 member context"})
}
/// Native bootstrap enrichment. Person View and own-root Manage are independent.
/// No canonical run lookup, no writes, no raw private metadata in the result.
pub(crate) async fn online_on(conn: &mut SqliteConnection, actor: &str) -> Result<Value> {
    if origin_on(conn).await?.is_none() {
        return Ok(serde_json::json!({"status":"not_applicable"}));
    }
    // Distinguish old imports from a verified empty source. Storage errors remain
    // errors; only a missing/mismatched preparation receipt is unavailable.
    if let Err(error) = require_capture_on(conn).await {
        if matches!(error, Error::Engine(_)) {
            return Ok(unavailable("source_capture_not_prepared"));
        }
        return Err(error);
    }
    let Some(row) = own_on(conn, actor).await? else {
        return Ok(
            serde_json::json!({"status":"absent","identity_basis":"verified source capture"}),
        );
    };
    if row.invalid {
        return Ok(unavailable("source_context_invalid"));
    }
    let person = if row.person_missing || row.person_deleted {
        None
    } else {
        super::super::read_record_on(conn, actor, &row.person_record_id)
            .await?
            .map(|v| v.id)
    };
    let root = if row.root_missing || row.root_deleted {
        None
    } else {
        let visible = super::super::read_record_on(conn, actor, &row.root_record_id).await?;
        let manage = super::super::kernel_effective_capability_on(conn, actor, &row.root_record_id)
            .await?
            .allows(Capability::Manage);
        visible.filter(|_| manage).map(|v| v.id)
    };
    Ok(
        serde_json::json!({"status":if person.is_some() || root.is_some(){"available"}else{"unavailable"},
        "identity_basis":"retained v1 member context; current native authorization",
        "person_record_id":person,"root_record_id":root,
        "root_authority":if root.is_some(){Some("current_manage")}else{None}}),
    )
}
/// Delivery seam: both references must be visible in the caller's current cut.
/// This is stricter reference closure, not an online private-root authority claim.
#[allow(dead_code)] // N3 consumes this seam after independent integration review.
pub(crate) async fn member_delivery_on(
    conn: &mut SqliteConnection,
    actor: &str,
) -> Result<Option<Value>> {
    require_capture_on(conn).await?;
    let Some(row) = own_on(conn, actor).await? else {
        return Ok(None);
    };
    if row.invalid
        || row.person_missing
        || row.person_deleted
        || row.root_missing
        || row.root_deleted
    {
        return Ok(None);
    }
    if super::super::read_record_on(conn, actor, &row.person_record_id)
        .await?
        .is_none()
        || super::super::read_record_on(conn, actor, &row.root_record_id)
            .await?
            .is_none()
    {
        return Ok(None);
    }
    Ok(Some(
        serde_json::json!({"person_record_id":row.person_record_id,"root_record_id":row.root_record_id}),
    ))
}
