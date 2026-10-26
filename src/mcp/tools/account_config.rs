//! Caller-bound canonical preferences. Control identities are independent of
//! ordinary intent-bound keyed replay; no kind scan or adoption occurs here.
use super::super::{
    registry::{Caller, ToolRegistry},
    ToolKind,
};
use super::{parse_args, principal, require_nonblank_reason};
use crate::authorization::{AllowEntry, Capability, PolicyMode};
use crate::control::{
    append_control_event_in, AccountConfigProvisionedPayload, AccountConfigReplacedPayload,
    ControlEventPayload, NewControlEvent,
};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::query::cascade;
use crate::store::{append_in, AppendSpec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};
use std::collections::BTreeSet;
use uuid::Uuid;

const TOOL: &str = "manage_account_config";
pub(crate) const KIND: &str = "focus_preferences";
const FACET: &str = "focus.preferences";
const APPROVED: &str = include_str!("account_config/preferences-shape.json");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum Args {
    Inspect {
        kind: String,
    },
    Ensure {
        kind: String,
        reason: String,
    },
    Replace {
        kind: String,
        expected_record_id: String,
        reason: String,
    },
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Healthy,
    Absent,
    Unusable,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    Inspected,
    Created,
    Existing,
    Replaced,
    Replayed,
    Refused,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    Deleted,
    Forbidden,
    WrongKind,
    PolicyNotAccountOnly,
    Archived,
    InvalidContent,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Refusal {
    Absent,
    NotUnusable,
    CasMismatch,
    MappingChanged,
    UnsupportedRecovery,
    AlreadyReplaced,
}
#[derive(Debug, Serialize)]
pub(crate) struct Receipt {
    pub(crate) status: Status,
    pub(crate) outcome: Outcome,
    pub(crate) reason: Option<Reason>,
    pub(crate) refusal: Option<Refusal>,
    pub(crate) record_id: Option<String>,
    pub(crate) content_revision: Option<String>,
    pub(crate) policy_revision: Option<String>,
    pub(crate) created: Option<bool>,
}
impl Receipt {
    pub(crate) fn absent() -> Self {
        Self {
            status: Status::Absent,
            outcome: Outcome::Inspected,
            reason: None,
            refusal: None,
            record_id: None,
            content_revision: None,
            policy_revision: None,
            created: None,
        }
    }
    pub(crate) fn unusable(id: &str, reason: Reason) -> Self {
        Self {
            status: Status::Unusable,
            reason: Some(reason),
            record_id: (reason != Reason::Forbidden).then(|| id.to_owned()),
            ..Self::absent()
        }
    }
    pub(crate) fn refused(mut self, refusal: Option<Refusal>) -> Self {
        self.outcome = Outcome::Refused;
        self.refusal = refusal;
        self.created = None;
        self
    }
}

pub(crate) fn canonical_record_id(id: &str) -> bool {
    Uuid::parse_str(id).is_ok_and(|u| {
        u.to_string() == id
            && matches!(u.get_version_num(), 4 | 7)
            && u.get_variant() == uuid::Variant::RFC4122
    })
}
fn provision_key(account: &str) -> String {
    format!("provision:v1:account-config:{account}:{KIND}")
}
fn rebound_key(account: &str, old: &str) -> String {
    format!("provision:v1:account-config-replace:{account}:{KIND}:{old}")
}
async fn mapping(conn: &mut SqliteConnection, account: &str) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT record_id FROM account_configs WHERE account_id=? AND kind=?")
            .bind(account)
            .bind(KIND)
            .fetch_optional(conn)
            .await?,
    )
}
pub(crate) async fn registered(conn: &mut SqliteConnection) -> Result<bool> {
    let kind = crate::meta::kind::resolve_on(conn, "Configuration", KIND).await?;
    Ok(kind.canonical_kind_for_write() == Some(KIND))
}
pub(crate) async fn shape(conn: &mut SqliteConnection) -> Result<Option<Value>> {
    let rows = cascade::schema_config_rows_with(
        &mut crate::portable_sql::BorrowedSqliteStatementExecutor::new(&mut *conn),
    )
    .await?;
    let view = cascade::resolve_from_rows(&rows).resolved;
    let facets = cascade::facets_for_type(&view, "Configuration", Some(KIND));
    Ok(facets
        .get(FACET)
        .filter(|s| {
            s.get("type").and_then(Value::as_str) == Some("object")
                && s.get("required") == Some(&Value::Bool(true))
                && s.get("json_schema").is_some()
        })
        .cloned())
}
pub(crate) fn valid_value(shape: &Value, value: &Value) -> bool {
    let approved: Value = serde_json::from_str(APPROVED).expect("checked-in approved shapes");
    if crate::meta::schema_config::validate_object_facet_value(shape, value).is_err()
        || crate::meta::schema_config::validate_object_facet_value(&approved, value).is_err()
    {
        return false;
    }
    let Some(foci) = value.get("foci").and_then(Value::as_array) else {
        return false;
    };
    let mut seen = BTreeSet::new();
    foci.iter().all(|f| {
        f.get("focus_id")
            .and_then(Value::as_str)
            .is_some_and(|id| seen.insert(id))
    })
}
/// Shared append-time health precondition; replay folds validate lineage rather
/// than historical content against today's evolving schema.
pub(crate) async fn validate_new_target_on(conn: &mut SqliteConnection, id: &str) -> Result<()> {
    let row = sqlx::query("SELECT type,kind,deleted_at,archived FROM records WHERE id=?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("account config target missing"))?;
    if row.try_get::<String, _>("type")? != "Configuration"
        || row.try_get::<Option<String>, _>("kind")?.as_deref() != Some(KIND)
        || row.try_get::<Option<String>, _>("deleted_at")?.is_some()
        || row.try_get::<i64, _>("archived")? != 0
        || !registered(conn).await?
        || crate::authorization::authorization_target_with(
            &mut crate::portable_sql::BorrowedSqliteStatementExecutor::new(&mut *conn),
            id,
            false,
        )
        .await?
            != id
    {
        return Err(Error::engine(
            "account config target must be live registered self-bearer preferences",
        ));
    }
    if !valid_facet(conn, id).await? {
        return Err(Error::engine(
            "account config target must have one required valid preferences facet",
        ));
    }
    Ok(())
}
async fn valid_facet(conn: &mut SqliteConnection, id: &str) -> Result<bool> {
    let Some(shape) = shape(conn).await? else {
        return Ok(false);
    };
    let values: Vec<Option<String>> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key=?")
            .bind(id)
            .bind(FACET)
            .fetch_all(conn)
            .await?;
    Ok(values.len() == 1
        && values[0].as_deref().is_some_and(|raw| {
            serde_json::from_str::<Value>(raw).is_ok_and(|v| valid_value(&shape, &v))
        }))
}
async fn evaluate(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    id: Option<&str>,
) -> Result<Receipt> {
    let Some(id) = id else {
        return Ok(Receipt::absent());
    };
    let row =
        sqlx::query("SELECT type,kind,deleted_at,archived,updated_at FROM records WHERE id=?")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some(row) = row else {
        return Ok(Receipt::unusable(id, Reason::Deleted));
    };
    if row.try_get::<Option<String>, _>("deleted_at")?.is_some() {
        return Ok(Receipt::unusable(id, Reason::Deleted));
    }
    if !crate::authorization::effective_capability_on(tx, principal(caller), id)
        .await?
        .allows(Capability::Manage)
    {
        return Ok(Receipt::unusable(id, Reason::Forbidden));
    }
    if row.try_get::<String, _>("type")? != "Configuration"
        || row.try_get::<Option<String>, _>("kind")?.as_deref() != Some(KIND)
        || !registered(tx).await?
    {
        return Ok(Receipt::unusable(id, Reason::WrongKind));
    }
    let policy = super::policy::policy_snapshot(tx, id).await?;
    if crate::authorization::authorization_target_on(tx, id).await? != id
        || policy.mode != PolicyMode::Explicit
        || policy.anchor_id != id
        || policy.entries != vec![AllowEntry::account(caller.credential(), Capability::Manage)]
    {
        return Ok(Receipt::unusable(id, Reason::PolicyNotAccountOnly));
    }
    if row.try_get::<i64, _>("archived")? != 0 {
        return Ok(Receipt::unusable(id, Reason::Archived));
    }
    if !valid_facet(tx, id).await? {
        return Ok(Receipt::unusable(id, Reason::InvalidContent));
    }
    Ok(Receipt {
        status: Status::Healthy,
        record_id: Some(id.into()),
        content_revision: Some(row.try_get("updated_at")?),
        policy_revision: Some(policy.revision),
        ..Receipt::absent()
    })
}
async fn create_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    reason: &str,
    old: Option<&str>,
) -> Result<Receipt> {
    if !registered(tx).await? {
        return Err(Error::engine("manage_account_config: kind_not_registered"));
    }
    let empty = json!({"version":1,"foci":[]});
    if !shape(tx).await?.is_some_and(|s| valid_value(&s, &empty)) {
        return Err(Error::engine("manage_account_config: kind_not_registered"));
    }
    super::require_record_in(
        tx,
        caller,
        TOOL,
        crate::schema::UNFILED_RECORD_ID,
        Capability::Edit,
    )
    .await?;
    let id = Uuid::new_v4().to_string();
    let mut act = crate::act::ActAllocation::new();
    crate::authorization_grant::certify_birth_on(tx, &id).await?;
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: "record.created".into(),
            payload: json!({"type":"Configuration","kind":KIND,"name":"Focus preferences",
            "home_id":crate::schema::UNFILED_RECORD_ID,"persistence":"enduring","reason":reason}),
            actor: Some(caller.actor().into()),
        },
        &mut act,
    )
    .await?;
    let mut facets = [super::lifecycle::FacetWrite {
        key: FACET.into(),
        value: empty,
        vocab_ref: None,
        time_type: None,
    }];
    let rows = cascade::schema_config_rows_in(tx).await?;
    super::lifecycle::assert_facet_value_predicates_in(
        tx,
        &rows,
        TOOL,
        "Configuration",
        Some(KIND),
        None,
        &mut facets,
    )
    .await?;
    append_in(
        db,
        tx,
        super::lifecycle::facet_set_spec(&id, &facets[0], caller.actor()),
        &mut act,
    )
    .await?;
    super::private_create::install_account_only_policy_in(tx, caller, TOOL, &id, &mut act).await?;
    crate::authorization_grant::finish_birth_on(tx, &id).await?;
    let missing = super::lifecycle::required_violations_in(tx, &rows, &[&id]).await?;
    crate::domain_transaction::assert_required_not_worsened(TOOL, &Default::default(), &missing)?;
    let created_at = crate::store::now_iso();
    let account_id = caller.credential().to_owned();
    let (key, payload) = match old {
        None => (
            provision_key(&account_id),
            ControlEventPayload::AccountConfigProvisioned(AccountConfigProvisionedPayload {
                account_id: account_id.clone(),
                kind: KIND.into(),
                record_id: id.clone(),
                created_at,
            }),
        ),
        Some(old) => (
            rebound_key(&account_id, old),
            ControlEventPayload::AccountConfigReplaced(AccountConfigReplacedPayload {
                account_id: account_id.clone(),
                kind: KIND.into(),
                previous_record_id: old.into(),
                record_id: id.clone(),
                created_at,
            }),
        ),
    };
    append_control_event_in(
        tx,
        NewControlEvent::authored(
            key,
            account_id,
            caller.credential(),
            caller.run_key().map(str::to_owned),
            reason,
            payload,
        )?,
        &mut act,
    )
    .await?;
    let mut result = evaluate(tx, caller, Some(&id)).await?;
    if result.status != Status::Healthy {
        return Err(Error::engine(
            "account config creation failed health precondition",
        ));
    }
    result.outcome = if old.is_some() {
        Outcome::Replaced
    } else {
        Outcome::Created
    };
    result.created = Some(true);
    Ok(result)
}
async fn mutate_once(db: &Db, caller: &Caller, args: &Args) -> Result<Receipt> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    // A rebound key is checked first, before current-mapping CAS or health.
    let replay: Option<String> = if let Args::Replace {
        expected_record_id, ..
    } = args
    {
        sqlx::query_scalar("SELECT json_extract(payload,'$.record_id') FROM control_events WHERE idempotency_key=?")
            .bind(rebound_key(caller.credential(), expected_record_id)).fetch_optional(&mut *tx).await?
    } else {
        None
    };
    let id = mapping(&mut tx, caller.credential()).await?;
    let current = evaluate(&mut tx, caller, id.as_deref()).await?;
    if let Some(winner) = replay {
        let result = if id.as_deref() != Some(&winner) {
            current.refused(Some(Refusal::MappingChanged))
        } else if current.status != Status::Healthy {
            current.refused(Some(Refusal::AlreadyReplaced))
        } else {
            Receipt {
                outcome: Outcome::Replayed,
                created: Some(false),
                ..current
            }
        };
        tx.rollback().await?;
        return Ok(result);
    }
    let result = match args {
        Args::Ensure { reason, .. } => match current.status {
            Status::Healthy => Receipt {
                outcome: Outcome::Existing,
                created: Some(false),
                ..current
            },
            Status::Unusable => current.refused(None),
            Status::Absent => create_in(db, &mut tx, caller, reason, None).await?,
        },
        Args::Replace {
            expected_record_id,
            reason,
            ..
        } => {
            if id.is_none() {
                current.refused(Some(Refusal::Absent))
            } else if id.as_deref() != Some(expected_record_id) {
                current.refused(Some(Refusal::CasMismatch))
            } else if current.status == Status::Healthy {
                current.refused(Some(Refusal::NotUnusable))
            } else if !matches!(
                current.reason,
                Some(
                    Reason::Deleted
                        | Reason::Forbidden
                        | Reason::WrongKind
                        | Reason::PolicyNotAccountOnly
                )
            ) {
                current.refused(Some(Refusal::UnsupportedRecovery))
            } else {
                create_in(db, &mut tx, caller, reason, Some(expected_record_id)).await?
            }
        }
        Args::Inspect { .. } => unreachable!(),
    };
    if result.created == Some(true) {
        db.commit_content(tx).await?
    } else {
        tx.rollback().await?
    }
    Ok(result)
}
async fn manage_account_config(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    if super::is_legacy_local(&caller)
        || !crate::identity::account::is_account_token(caller.credential())
    {
        return Err(Error::engine(
            "manage_account_config: authenticated canonical account required",
        ));
    }
    let args: Args = parse_args(TOOL, arguments)?;
    let kind = match &args {
        Args::Inspect { kind } | Args::Ensure { kind, .. } | Args::Replace { kind, .. } => kind,
    };
    if kind != KIND {
        return Err(Error::engine("manage_account_config: unsupported kind"));
    }
    match &args {
        Args::Inspect { .. } => {
            let mut tx = db.pool().begin().await?;
            let id = mapping(&mut tx, caller.credential()).await?;
            let result = evaluate(&mut tx, &caller, id.as_deref()).await?;
            tx.rollback().await?;
            Ok(serde_json::to_value(result)?)
        }
        Args::Ensure { reason, .. } | Args::Replace { reason, .. } => {
            require_nonblank_reason(TOOL, reason)?;
            if let Args::Replace {
                expected_record_id, ..
            } = &args
            {
                if !canonical_record_id(expected_record_id) {
                    return Err(Error::engine(
                        "manage_account_config: expected_record_id requires canonical UUIDv4/v7",
                    ));
                }
            }
            // Serialized writers normally converge before collision. If an
            // external importer races a UNIQUE, rollback and re-read once.
            let result = match mutate_once(&db, &caller, &args).await {
                Err(Error::Sqlx(sqlx::Error::Database(ref e))) if e.is_unique_violation() => {
                    mutate_once(&db, &caller, &args).await?
                }
                result => result?,
            };
            Ok(serde_json::to_value(result)?)
        }
    }
}
pub fn register_account_config_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(ToolKind::ManageAccountConfig,
        "Private canonical focus preferences. Inspect never provisions; ensure creates only if absent; replace CAS recovers deleted, forbidden, wrong-kind or nonprivate mappings without changing the old record. Archived/invalid content require guarded ordinary recovery.",
        json!({"type":"object","properties":{
            "action":{"enum":["inspect","ensure","replace"]},"kind":{"const":KIND},
            "reason":{"type":"string","minLength":1},
            "expected_record_id":{"type":"string","pattern":"^[0-9a-f]{8}-[0-9a-f]{4}-[47][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"}
        },"required":["action","kind"],"additionalProperties":false,"oneOf":[
            {"properties":{"action":{"const":"inspect"}},"not":{"anyOf":[{"required":["reason"]},{"required":["expected_record_id"]}]}},
            {"properties":{"action":{"const":"ensure"}},"required":["reason"],"not":{"required":["expected_record_id"]}},
            {"properties":{"action":{"const":"replace"}},"required":["reason","expected_record_id"]}
        ]}),manage_account_config)?;
    Ok(())
}
#[cfg(test)]
mod tests;
