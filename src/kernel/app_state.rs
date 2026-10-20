//! Sealed v1 app-state custody (HQ W7). Retained bytes are not executable
//! grants or v2 canvas versions. Live adapters must revalidate the closure
//! and authorize each referenced record/account before exposing it.
use super::*;
use serde_json::Value;
use sqlx::Row;
use std::collections::BTreeMap;

pub(crate) const DDL: &str = "CREATE TABLE kernel_app_state (
 record_id TEXT PRIMARY KEY,
 origin TEXT NOT NULL, payload TEXT NOT NULL CHECK(json_valid(payload)),
 event_seq INTEGER NOT NULL REFERENCES content_events(seq))";
pub(crate) const IMPORTED_EVENT: &str = "kernel.app_state_imported.v1";

pub(crate) const ACCOUNT_ORDER_PREFIX: &str = "kernel:app-custody:order:";

pub(crate) const HISTORY_CUSTODY_VERSION: u64 = 1;

/// A declared account is only an isolation key. Blank or contradictory
/// declarations are quarantined per event, never assigned an inferred owner.
pub(crate) fn declared_account(payload: &Value) -> Option<&str> {
    let nonblank = |v: &Value| v.as_str().is_some_and(|s| !s.trim().is_empty());
    let account = payload.get("account_id");
    let scope = (payload["scope_kind"] == "account").then(|| &payload["scope_id"]);
    if account.is_some_and(|v| !nonblank(v)) || scope.is_some_and(|v| !nonblank(v)) {
        return None;
    }
    match (
        account.and_then(Value::as_str),
        scope.and_then(Value::as_str),
    ) {
        (Some(a), Some(b)) if a != b => None,
        (Some(a), _) | (_, Some(a)) => Some(a),
        _ => None,
    }
}

pub(crate) fn private_control(legacy: &hq::LegacyEvent) -> bool {
    legacy.event_type.starts_with("alpha_tab.")
        || legacy.source.as_ref().is_some_and(|source| {
            source["stream"] == "control_events"
                && (legacy.payload.get("account_id").is_some()
                    || legacy.payload["scope_kind"] == "account")
        })
}

/// Account-private app controls are forensic custody, not artifact changes.
/// The declared account is an isolation key, never execution authority. Rows
/// without proven account scope get an event-specific quarantine aggregate.
pub(crate) fn history_aggregate(legacy: &hq::LegacyEvent) -> Result<Option<String>> {
    let Some(source) = &legacy.source else {
        return Ok(None);
    };
    if source["stream"] != "control_events" || !private_control(legacy) {
        return Ok(None);
    }
    let origin = source["origin"]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| Error::engine("app history source origin missing"))?;
    let account = declared_account(&legacy.payload);
    let scope = account.map_or_else(
        || serde_json::json!(["unowned-event", legacy.id]),
        |account| serde_json::json!(["account", account]),
    );
    let bytes = serde_json::to_vec(&(origin, scope))?;
    Ok(Some(format!(
        "{AGGREGATE_PREFIX}control:{}",
        Uuid::new_v5(&Uuid::NAMESPACE_OID, &bytes)
    )))
}

/// Exact source projection rows. JSON-valued source columns remain strings:
/// declaration spelling, attestations and digests must not be reserialized.
/// SQL REAL cells are tagged objects with `native.v1.sqlite.real_bits`, an
/// exact 16-digit hexadecimal IEEE-754 encoding, not rounded JSON numbers.
/// Live adapters must decode that tag explicitly before returning v1 shapes.
/// Source event positions remain in the v1 namespace, never native CAS tokens.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetainedAppState {
    pub custody: Option<CustodyFrontier>,
    pub artifact_source_attestations: Vec<Value>,
    pub artifact_inputs: Vec<Value>,
    pub artifact_module_grants: Vec<Value>,
    pub module_releases: Vec<Value>,
    pub module_release_imports: Vec<Value>,
    pub canvas_objects: Vec<Value>,
    pub canvas_batches: Vec<Value>,
    pub alpha_tab_installs: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpha_tab_orders: Vec<Value>,
    /// Negative source evidence: live adapters must refuse this bearer.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub source_deleted: bool,
    /// Exact referenced source and batch event rows, keyed by original id.
    pub source_events: BTreeMap<String, Value>,
    pub control_events: BTreeMap<String, Value>,
}

/// Describes capture, not executable closure admission. A later activation must
/// independently validate dependencies, policies and command retry evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyFrontier {
    pub format: u32,
    pub source_user_version: i64,
    pub content_frontier: i64,
    pub control_frontier: i64,
    pub missing_source_events: Vec<String>,
    pub missing_control_events: Vec<String>,
    pub closure_admission: String,
}

impl RetainedAppState {
    pub(crate) fn is_empty(&self) -> bool {
        let mut rows = self.clone();
        rows.custody = None;
        rows.source_deleted = false;
        rows == Self::default()
    }
    fn follows(&self, prior: &Self) -> Result<()> {
        if let Some(previous) = &prior.custody {
            let Some(current) = &self.custody else {
                return Err(Error::conflict("app-state custody frontier removed"));
            };
            if current.source_user_version < previous.source_user_version
                || current.content_frontier < previous.content_frontier
                || current.control_frontier < previous.control_frontier
            {
                return Err(Error::conflict("app-state source frontier regressed"));
            }
        }
        Ok(())
    }
    fn validate(&self, id: &str) -> Result<()> {
        if let Some(custody) = &self.custody {
            if custody.format != 1 || custody.closure_admission != "not_evaluated" {
                return Err(Error::engine("unsupported app custody contract"));
            }
        }
        for (rows, field) in [
            (&self.artifact_source_attestations, "artifact_id"),
            (&self.artifact_inputs, "artifact_id"),
            (&self.artifact_module_grants, "artifact_id"),
            (&self.module_releases, "module_record_id"),
            (&self.canvas_objects, "canvas_id"),
            (&self.canvas_batches, "canvas_id"),
            (&self.alpha_tab_installs, "artifact_id"),
        ] {
            for row in rows {
                if row[field].as_str() != Some(id) {
                    return Err(Error::engine("app-state row bearer mismatch"));
                }
            }
        }
        for row in &self.alpha_tab_orders {
            if row["account_id"].as_str().map(account_bearer).as_deref() != Some(id) {
                return Err(Error::engine("app order account bearer mismatch"));
            }
        }
        for row in &self.module_release_imports {
            if !self.module_releases.iter().any(|release| {
                release["publication_event_id"] == row["consumer_publication_event_id"]
            }) {
                return Err(Error::engine(
                    "app-state release dependency bearer mismatch",
                ));
            }
        }
        for (event_id, row) in self.source_events.iter().chain(&self.control_events) {
            if row["id"].as_str() != Some(event_id) {
                return Err(Error::engine("app-state source event identity mismatch"));
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Imported {
    origin: String,
    bearer: String,
    previous: Option<i64>,
    state: RetainedAppState,
}

/// Additive upgrade/recovery for pre-W7 imported targets. Rebuild only from
/// the sealed log, never from a second raw database or a local authority path.
pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='kernel_app_state')",
    )
    .fetch_one(&mut *conn)
    .await?;
    if exists {
        // Custody bearers include account bindings as well as records. Only
        // sealed imports can populate this table; neither is public authority.
        let foreign_keys = sqlx::query("PRAGMA foreign_key_list(kernel_app_state)")
            .fetch_all(&mut *conn)
            .await?;
        if foreign_keys
            .iter()
            .any(|row| row.get::<String, _>("table") == "kernel_records")
        {
            sqlx::query("ALTER TABLE kernel_app_state RENAME TO kernel_app_state_old")
                .execute(&mut *conn)
                .await?;
            sqlx::query(DDL).execute(&mut *conn).await?;
            sqlx::query("INSERT INTO kernel_app_state SELECT * FROM kernel_app_state_old")
                .execute(&mut *conn)
                .await?;
            sqlx::query("DROP TABLE kernel_app_state_old")
                .execute(&mut *conn)
                .await?;
        }
        return Ok(());
    }
    sqlx::query(DDL).execute(&mut *conn).await?;
    let events = crate::conformance::rebuild::read_all_events(conn).await?;
    for event in events
        .iter()
        .filter(|event| event.event_type == IMPORTED_EVENT)
    {
        project(conn, event).await?;
    }
    Ok(())
}

pub(crate) async fn ensure_as(db: &Db, host: &str) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    hq::require_source_import_open(&mut tx).await?;
    ensure_schema(&mut tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn require_bearer(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
    before: i64,
) -> Result<()> {
    if let Some(account) = id.strip_prefix(ACCOUNT_ORDER_PREFIX) {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE auth_binding=? AND kind='account')")
            .bind(account).fetch_one(&mut *conn).await?;
        if exists {
            return Ok(());
        }
        return Err(Error::engine("app order account was not imported"));
    }
    let owned: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.import_state.v1' AND actor=? AND seq<?)")
        .bind(id).bind(actor).bind(before).fetch_one(conn).await?;
    if !owned {
        return Err(Error::engine("app-state bearer is not owned by importer"));
    }
    Ok(())
}

// A custody receipt must not advance a public artifact's version/time when
// the only changed state is another account's private installation consent.
pub(super) const AGGREGATE_PREFIX: &str = "kernel:app-custody:";
fn aggregate(id: &str) -> String {
    format!(
        "{AGGREGATE_PREFIX}{}",
        Uuid::new_v5(&Uuid::NAMESPACE_OID, id.as_bytes())
    )
}

/// The only mutation seam: the reserved importer, against an imported bearer.
/// Retention neither advances the bearer CAS token nor implies app adoption.
pub(crate) async fn import_as(
    db: &Db,
    host: &str,
    id: &str,
    origin: &str,
    state: &RetainedAppState,
) -> Result<ImportResult> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    hq::require_source_import_open(&mut tx).await?;
    state.validate(id)?;
    if origin.trim().is_empty() {
        return Err(Error::engine("app-state source origin is required"));
    }
    require_bearer(&mut tx, host, id, i64::MAX).await?;
    let prior: Option<(String, String, i64)> =
        sqlx::query_as("SELECT origin,payload,event_seq FROM kernel_app_state WHERE record_id=?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if let Some((previous_origin, payload, _)) = &prior {
        if previous_origin != origin {
            return Err(Error::conflict("app-state source origin changed"));
        }
        let previous = serde_json::from_str::<RetainedAppState>(payload)?;
        state.follows(&previous)?;
        if previous == *state {
            tx.rollback().await?;
            return Ok(ImportResult::Unchanged);
        }
    } else if state.is_empty() {
        tx.rollback().await?;
        return Ok(ImportResult::Unchanged);
    }
    let imported = Imported {
        origin: origin.into(),
        bearer: id.into(),
        previous: prior.as_ref().map(|(_, _, seq)| *seq),
        state: state.clone(),
    };
    let mut allocation = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: aggregate(id),
            event_type: IMPORTED_EVENT.into(),
            payload: serde_json::to_value(imported)?,
            actor: Some(host.into()),
        },
        &mut allocation,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(if prior.is_some() {
        ImportResult::Updated
    } else {
        ImportResult::Created
    })
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let actor = event.actor.as_deref().unwrap_or("");
    hq::require_import(conn, actor).await?;
    let p: Imported = event_payload(event)?;
    p.state.validate(&p.bearer)?;
    if event.record_id != aggregate(&p.bearer) {
        return Err(Error::engine("app-state aggregate identity mismatch"));
    }
    refuse_entity_collision(conn, &event.record_id).await?;
    if p.origin.trim().is_empty() {
        return Err(Error::engine("app-state source origin is required"));
    }
    require_bearer(conn, actor, &p.bearer, event.local_seq).await?;
    let prior: Option<(String, i64, String)> =
        sqlx::query_as("SELECT origin,event_seq,payload FROM kernel_app_state WHERE record_id=?")
            .bind(&p.bearer)
            .fetch_optional(&mut *conn)
            .await?;
    if prior.as_ref().map(|(_, seq, _)| *seq) != p.previous
        || prior
            .as_ref()
            .is_some_and(|(origin, _, _)| origin != &p.origin)
    {
        return Err(Error::conflict("app-state predecessor changed"));
    }
    if let Some((_, _, payload)) = &prior {
        p.state.follows(&serde_json::from_str(payload)?)?;
    }
    sqlx::query("INSERT INTO kernel_app_state(record_id,origin,payload,event_seq) VALUES(?,?,?,?) ON CONFLICT(record_id) DO UPDATE SET payload=excluded.payload,event_seq=excluded.event_seq")
        .bind(&p.bearer).bind(&p.origin).bind(serde_json::to_string(&p.state)?).bind(event.local_seq).execute(conn).await?;
    Ok(())
}

/// Reserved streams must never share an identity with any public entity.
pub(super) async fn refuse_entity_collision(conn: &mut SqliteConnection, id: &str) -> Result<()> {
    let collision: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?1 UNION ALL SELECT 1 FROM kernel_roots WHERE root_id=?1 UNION ALL SELECT 1 FROM kernel_principals WHERE principal_id=?1)")
        .bind(id).fetch_one(conn).await?;
    if collision {
        return Err(Error::conflict("app-state aggregate id collision"));
    }
    Ok(())
}

/// Decode a particular sealed capsule, rather than whichever projection is
/// current on reopen. Live authority pins evidence by event identity.
pub(crate) async fn evidence_at(
    conn: &mut SqliteConnection,
    bearer: &str,
    seq: i64,
    before: i64,
) -> Result<(String, RetainedAppState)> {
    let raw: Option<String> =
        sqlx::query_scalar("SELECT payload FROM content_events WHERE seq=? AND type=? AND seq<?")
            .bind(seq)
            .bind(IMPORTED_EVENT)
            .bind(before)
            .fetch_optional(&mut *conn)
            .await?;
    let p: Imported =
        serde_json::from_str(&raw.ok_or_else(|| Error::engine("app custody evidence missing"))?)?;
    if p.bearer != bearer {
        return Err(Error::engine("app custody evidence bearer mismatch"));
    }
    let latest: Option<i64> = sqlx::query_scalar(
        "SELECT max(seq) FROM content_events WHERE type=? AND record_id=? AND seq<?",
    )
    .bind(IMPORTED_EVENT)
    .bind(aggregate(bearer))
    .bind(before)
    .fetch_one(conn)
    .await?;
    if latest != Some(seq) {
        return Err(Error::conflict(
            "app custody evidence was superseded before activation",
        ));
    }
    p.state.validate(bearer)?;
    Ok((p.origin, p.state))
}

/// Private custody key; it is never an ordinary record ID.
pub(crate) fn account_bearer(account: &str) -> String {
    format!("{ACCOUNT_ORDER_PREFIX}{account}")
}

/// Order custody is visible only to its authenticated account, never through
/// public artifact history or SQL. A missing row means no saved arrangement.
#[allow(dead_code)] // consumed by the installed-app adapter slice
pub(crate) async fn account_order_as(db: &Db, principal: &str) -> Result<Option<Value>> {
    let mut tx = db.pool().begin().await?;
    let row = account_order_on(&mut tx, principal).await?;
    tx.rollback().await?;
    Ok(row)
}

pub(crate) async fn account_order_on(
    conn: &mut SqliteConnection,
    principal: &str,
) -> Result<Option<Value>> {
    let binding: Option<String> = sqlx::query_scalar(
        "SELECT auth_binding FROM kernel_principals WHERE principal_id=? AND kind='account'",
    )
    .bind(principal)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(binding) = binding else {
        return Err(Error::engine("account required"));
    };
    let payload: Option<String> =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id=?")
            .bind(account_bearer(&binding))
            .fetch_optional(conn)
            .await?;
    let state = payload
        .map(|p| serde_json::from_str::<RetainedAppState>(&p))
        .transpose()?;
    Ok(state
        .filter(|s| !s.source_deleted)
        .and_then(|s| s.alpha_tab_orders.into_iter().next()))
}
