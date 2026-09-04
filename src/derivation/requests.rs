//! Durable, database-owned coordination for derived-state execution.
//!
//! The row is the authority for deduplication and leases. Queues may wake a
//! worker, but they never own a request. Execution happens outside these short
//! transactions and every worker mutation is fenced by both owner and the
//! monotonically increasing lease generation.

use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::db::{begin_write, Db};
use crate::error::{Error, Result};

use super::{
    append_derivation_event_in, canonical_json, digest_json, CanonicalDerivationRequest,
    DerivationAttemptFailed, DerivationEventPayload, DerivationEventRow, EffectiveSourceBoundary,
    NewDerivationEvent, RecipeRevisionRef,
};

pub const MAX_DERIVATION_LEASE_DURATION: StdDuration = StdDuration::from_secs(15 * 60);
pub const MAX_DERIVATION_WAIT_DURATION: StdDuration = StdDuration::from_secs(30);
const DEFAULT_WAIT_POLL_INTERVAL: StdDuration = StdDuration::from_millis(25);
pub const DERIVATION_AUDIENCE_SCHEMA: &str = "native.derivation-audience.v1";
type LiveMembershipResolver<'a> = dyn Fn(&str) -> Option<bool> + Send + Sync + 'a;

pub(super) trait DerivationCoordinatorClock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Clone, Copy)]
struct SystemCoordinatorClock;

impl DerivationCoordinatorClock for SystemCoordinatorClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationAudiencePrincipal {
    pub account_id: String,
    pub is_member: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationAudiencePolicy {
    pub schema: String,
    pub policy_anchor_id: String,
    pub principals: Vec<DerivationAudiencePrincipal>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationRequestSpec {
    pub series_id: String,
    pub definition_sha256: String,
    pub canonical_request: CanonicalDerivationRequest,
    pub recipe_revision: RecipeRevisionRef,
    pub effective_source_boundary: EffectiveSourceBoundary,
    /// The exact output-side basis, for example binding generation and target
    /// version. Its concrete contract belongs to the workflow layer.
    pub target_basis: Value,
    /// The normalized semantic execution budget. Coordination does not
    /// interpret it, but it participates in identity.
    pub budget: Value,
    /// Canonical explicit audience policy. Legacy v25 coordination rows may
    /// omit it; controlled publication always requires it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience_policy: Option<DerivationAudiencePolicy>,
    pub audience_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateOrJoinRequest {
    pub requested_by: String,
    pub requested_run_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationRequestState {
    Pending,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DerivationRequestSnapshot {
    pub id: String,
    pub request_key_sha256: String,
    pub spec: DerivationRequestSpec,
    pub requested_by: String,
    pub requested_run_key: Option<String>,
    pub state: DerivationRequestState,
    pub lease_owner: Option<String>,
    pub lease_run_key: Option<String>,
    pub lease_generation: i64,
    pub lease_expires_at: Option<String>,
    pub attempt_count: i64,
    pub retryable: bool,
    pub next_attempt_at: Option<String>,
    pub failure_code: Option<String>,
    pub failure_metadata: Option<Value>,
    pub result_revision_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl DerivationRequestSnapshot {
    pub fn is_terminal(&self) -> bool {
        self.state == DerivationRequestState::Succeeded
            || (self.state == DerivationRequestState::Failed && !self.retryable)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CreatedOrJoinedRequest {
    pub request: DerivationRequestSnapshot,
    pub created: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationRequestLease {
    pub request_id: String,
    pub owner: String,
    pub run_key: Option<String>,
    pub generation: i64,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DerivationRequestFailure {
    pub lease: DerivationRequestLease,
    pub event_idempotency_key: String,
    pub actor: String,
    pub run_key: Option<String>,
    pub reason: String,
    pub evidence: DerivationAttemptFailed,
    /// Delay from the coordinator's trusted failure time. `None` means an
    /// immediately retryable failure when `evidence.retryable` is true.
    pub retry_after: Option<StdDuration>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationExecutorDescriptor {
    pub provider: String,
    pub model: String,
    pub executor_revision: String,
    pub execution_profile_id: String,
    pub capabilities: Vec<crate::recipe::RecipeModelCapability>,
    pub parameters: Value,
    pub usage: DerivationExecutionUsage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationExecutionUsage {
    pub input_bytes: u64,
    pub input_items: u64,
    pub input_tokens: u64,
    pub output_bytes: u64,
    pub output_tokens: u64,
}

#[derive(Debug, Clone)]
pub struct CompleteDerivationRequest {
    pub lease: DerivationRequestLease,
    pub expected_recipe_status_event_seq: i64,
    pub structured_result: Value,
    /// Complete value checked against the recipe output contract. For a
    /// record-body target its `body` field must equal the published body.
    pub rendered_output: Value,
    pub executor: DerivationExecutorDescriptor,
    pub publication: super::bindings::PublishRecordBodyRevision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcquireRequestResult {
    Acquired(DerivationRequestLease),
    Busy,
    Terminal,
    NotFound,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RequestWaitOutcome {
    Terminal(DerivationRequestSnapshot),
    TimedOut(DerivationRequestSnapshot),
    NotFound,
}

fn nonblank(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::engine(format!(
            "derivation request {label} cannot be empty"
        )));
    }
    Ok(())
}

fn sha256(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Error::engine(format!(
            "derivation request {label} must be lowercase sha256"
        )));
    }
    Ok(())
}

fn object(label: &str, value: &Value) -> Result<()> {
    if !value.is_object() {
        return Err(Error::engine(format!(
            "derivation request {label} must be an object"
        )));
    }
    Ok(())
}

fn canonical_text(value: &Value) -> String {
    String::from_utf8(canonical_json(value)).expect("canonical JSON is UTF-8")
}

pub fn audience_policy_sha256(policy: &DerivationAudiencePolicy) -> Result<String> {
    validate_audience_policy(policy)?;
    Ok(digest_json(&serde_json::to_value(policy)?))
}

fn validate_audience_policy(policy: &DerivationAudiencePolicy) -> Result<()> {
    if policy.schema != DERIVATION_AUDIENCE_SCHEMA {
        return Err(Error::engine("derivation audience schema is unsupported"));
    }
    nonblank("audience policy anchor", &policy.policy_anchor_id)?;
    if policy.principals.is_empty() {
        return Err(Error::engine(
            "derivation audience must contain at least one principal",
        ));
    }
    for principal in &policy.principals {
        nonblank("audience principal account", &principal.account_id)?;
    }
    if !policy
        .principals
        .windows(2)
        .all(|pair| pair[0].account_id < pair[1].account_id)
    {
        return Err(Error::engine(
            "derivation audience principals must be sorted and unique",
        ));
    }
    Ok(())
}

fn validate_spec(spec: &DerivationRequestSpec) -> Result<()> {
    nonblank("series id", &spec.series_id)?;
    sha256("definition digest", &spec.definition_sha256)?;
    nonblank("query contract", &spec.canonical_request.query_contract)?;
    if spec.canonical_request.query_contract_version < 1 {
        return Err(Error::engine(
            "derivation request query contract version must be positive",
        ));
    }
    object("selection", &spec.canonical_request.selection)?;
    object("scope", &spec.canonical_request.scope)?;
    nonblank("recipe definition id", &spec.recipe_revision.definition_id)?;
    nonblank(
        "recipe publication id",
        &spec.recipe_revision.publication_id,
    )?;
    sha256("recipe digest", &spec.recipe_revision.sha256)?;
    if spec.effective_source_boundary.through_seq < 0
        || spec
            .effective_source_boundary
            .after_seq
            .is_some_and(|after| after < 0 || after > spec.effective_source_boundary.through_seq)
    {
        return Err(Error::engine(
            "derivation request source boundary is invalid",
        ));
    }
    sha256(
        "scope membership digest",
        &spec
            .effective_source_boundary
            .resolved_scope_membership_sha256,
    )?;
    object(
        "source boundary metadata",
        &spec.effective_source_boundary.metadata,
    )?;
    object("target basis", &spec.target_basis)?;
    object("budget", &spec.budget)?;
    sha256("audience digest", &spec.audience_sha256)?;
    if let Some(policy) = &spec.audience_policy {
        if audience_policy_sha256(policy)? != spec.audience_sha256 {
            return Err(Error::engine(
                "derivation audience digest does not match its canonical policy",
            ));
        }
    }
    Ok(())
}

fn request_identity(spec: &DerivationRequestSpec) -> Result<(String, Value)> {
    validate_spec(spec)?;
    let schema = if spec.audience_policy.is_some() {
        "native.derivation-request.v2"
    } else {
        "native.derivation-request.v1"
    };
    let mut value = json!({
        "schema": schema,
        "series_id": spec.series_id,
        "definition_sha256": spec.definition_sha256,
        "canonical_request": spec.canonical_request,
        "recipe_revision": spec.recipe_revision,
        "effective_source_boundary": spec.effective_source_boundary,
        "target_basis": spec.target_basis,
        "budget": spec.budget,
        "audience_sha256": spec.audience_sha256,
    });
    if let Some(policy) = &spec.audience_policy {
        value
            .as_object_mut()
            .expect("request identity is an object")
            .insert("audience_policy".into(), serde_json::to_value(policy)?);
    }
    Ok((digest_json(&value), value))
}

fn controlled_series_matches(definition: &Value, spec: &DerivationRequestSpec) -> Result<bool> {
    Ok(definition.get("audience_sha256").and_then(Value::as_str)
        == Some(spec.audience_sha256.as_str())
        && definition.get("recipe_revision") == Some(&serde_json::to_value(&spec.recipe_revision)?)
        && definition.get("budget") == Some(&spec.budget))
}

fn format_time(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn parse_time(label: &str, value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| Error::engine(format!("derivation request {label} is not RFC3339")))
}

fn checked_expiry(now: DateTime<Utc>, lease_duration: StdDuration) -> Result<DateTime<Utc>> {
    if lease_duration.is_zero() || lease_duration > MAX_DERIVATION_LEASE_DURATION {
        return Err(Error::engine(format!(
            "derivation request lease duration must be between 1ms and {}s",
            MAX_DERIVATION_LEASE_DURATION.as_secs()
        )));
    }
    let duration = Duration::from_std(lease_duration)
        .map_err(|_| Error::engine("derivation request lease duration is invalid"))?;
    now.checked_add_signed(duration)
        .ok_or_else(|| Error::engine("derivation request lease expiry overflows"))
}

fn state(value: &str) -> Result<DerivationRequestState> {
    match value {
        "pending" => Ok(DerivationRequestState::Pending),
        "running" => Ok(DerivationRequestState::Running),
        "succeeded" => Ok(DerivationRequestState::Succeeded),
        "failed" => Ok(DerivationRequestState::Failed),
        _ => Err(Error::engine("derivation request state is unknown")),
    }
}

fn row_snapshot(row: sqlx::sqlite::SqliteRow) -> Result<DerivationRequestSnapshot> {
    let stored_identity: String = row.try_get("request_identity")?;
    let stored_identity_value: Value = serde_json::from_str(&stored_identity)?;
    let stored_key: String = row.try_get("request_key_sha256")?;
    let canonical_request: CanonicalDerivationRequest =
        serde_json::from_str(row.try_get("canonical_request")?)?;
    let recipe_revision: RecipeRevisionRef = serde_json::from_str(row.try_get("recipe_revision")?)?;
    let effective_source_boundary: EffectiveSourceBoundary =
        serde_json::from_str(row.try_get("effective_source_boundary")?)?;
    let target_basis = serde_json::from_str(row.try_get("target_basis")?)?;
    let budget = serde_json::from_str(row.try_get("budget")?)?;
    let failure_metadata: Option<String> = row.try_get("failure_metadata")?;
    let snapshot = DerivationRequestSnapshot {
        id: row.try_get("id")?,
        request_key_sha256: stored_key.clone(),
        spec: DerivationRequestSpec {
            series_id: row.try_get("series_id")?,
            definition_sha256: row.try_get("definition_sha256")?,
            canonical_request,
            recipe_revision,
            effective_source_boundary,
            target_basis,
            budget,
            audience_policy: stored_identity_value
                .get("audience_policy")
                .cloned()
                .map(serde_json::from_value)
                .transpose()?,
            audience_sha256: row.try_get("audience_sha256")?,
        },
        requested_by: row.try_get("requested_by")?,
        requested_run_key: row.try_get("requested_run_key")?,
        state: state(row.try_get("state")?)?,
        lease_owner: row.try_get("lease_owner")?,
        lease_run_key: row.try_get("lease_run_key")?,
        lease_generation: row.try_get("lease_generation")?,
        lease_expires_at: row.try_get("lease_expires_at")?,
        attempt_count: row.try_get("attempt_count")?,
        retryable: row.try_get::<i64, _>("retryable")? != 0,
        next_attempt_at: row.try_get("next_attempt_at")?,
        failure_code: row.try_get("failure_code")?,
        failure_metadata: failure_metadata
            .map(|value| serde_json::from_str(&value))
            .transpose()?,
        result_revision_id: row.try_get("result_revision_id")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    };
    let (expected_key, expected_identity) = request_identity(&snapshot.spec)?;
    if expected_key != stored_key || canonical_text(&expected_identity) != stored_identity {
        return Err(Error::engine(
            "derivation request row does not match its canonical identity",
        ));
    }
    Ok(snapshot)
}

const SELECT_REQUEST: &str =
    "SELECT id,request_key_sha256,request_identity,series_id,definition_sha256,
    canonical_request,recipe_revision,effective_source_boundary,target_basis,budget,
    audience_sha256,requested_by,requested_run_key,state,lease_owner,
    lease_run_key,lease_generation,lease_expires_at,attempt_count,retryable,
    next_attempt_at,failure_code,failure_metadata,result_revision_id,created_at,updated_at
    FROM derivation_requests";

pub(crate) async fn inspect_request_in(
    tx: &mut Transaction<'_, Sqlite>,
    id: &str,
) -> Result<Option<DerivationRequestSnapshot>> {
    let query = format!("{SELECT_REQUEST} WHERE id=?");
    sqlx::query(&query)
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .map(row_snapshot)
        .transpose()
}

pub async fn create_or_join_request(
    db: &Db,
    spec: DerivationRequestSpec,
    requester: CreateOrJoinRequest,
) -> Result<CreatedOrJoinedRequest> {
    let mut tx = begin_write(db.write_pool()).await?;
    let result = create_or_join_request_in(&mut tx, spec, requester).await?;
    tx.commit().await?;
    Ok(result)
}

pub(crate) async fn create_or_join_request_in(
    tx: &mut Transaction<'_, Sqlite>,
    spec: DerivationRequestSpec,
    requester: CreateOrJoinRequest,
) -> Result<CreatedOrJoinedRequest> {
    nonblank("requester", &requester.requested_by)?;
    let (request_key_sha256, identity) = request_identity(&spec)?;
    let canonical_request = canonical_text(&serde_json::to_value(&spec.canonical_request)?);
    let recipe_revision = canonical_text(&serde_json::to_value(&spec.recipe_revision)?);
    let boundary = canonical_text(&serde_json::to_value(&spec.effective_source_boundary)?);
    let target_basis = canonical_text(&spec.target_basis);
    let budget = canonical_text(&spec.budget);
    let now = crate::store::now_iso();
    let id = Uuid::new_v4().to_string();
    let series: Option<(String, String)> =
        sqlx::query_as("SELECT definition_sha256,definition FROM derivation_series WHERE id=?")
            .bind(&spec.series_id)
            .fetch_optional(&mut **tx)
            .await?;
    let Some((series_definition_sha256, series_definition)) = series else {
        return Err(Error::engine(
            "derivation request definition digest does not match its stable series",
        ));
    };
    if series_definition_sha256 != spec.definition_sha256 {
        return Err(Error::engine(
            "derivation request definition digest does not match its stable series",
        ));
    }
    if spec.audience_policy.is_some()
        && !controlled_series_matches(&serde_json::from_str(&series_definition)?, &spec)?
    {
        return Err(Error::engine(
            "derivation request audience does not match its stable series",
        ));
    }
    let inserted = sqlx::query(
        "INSERT INTO derivation_requests
         (id,request_key_sha256,request_identity,series_id,definition_sha256,
          canonical_request,recipe_revision,effective_source_boundary,target_basis,budget,
          audience_sha256,requested_by,requested_run_key,created_at,updated_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(request_key_sha256) DO NOTHING",
    )
    .bind(&id)
    .bind(&request_key_sha256)
    .bind(canonical_text(&identity))
    .bind(&spec.series_id)
    .bind(&spec.definition_sha256)
    .bind(canonical_request)
    .bind(recipe_revision)
    .bind(boundary)
    .bind(target_basis)
    .bind(budget)
    .bind(&spec.audience_sha256)
    .bind(&requester.requested_by)
    .bind(&requester.requested_run_key)
    .bind(&now)
    .bind(&now)
    .execute(&mut **tx)
    .await?
    .rows_affected()
        == 1;
    let query = format!("{SELECT_REQUEST} WHERE request_key_sha256=?");
    let row = sqlx::query(&query)
        .bind(&request_key_sha256)
        .fetch_one(&mut **tx)
        .await?;
    let request = row_snapshot(row)?;
    let (_, stored_identity) = request_identity(&request.spec)?;
    if canonical_text(&stored_identity) != canonical_text(&identity) {
        return Err(Error::engine(
            "derivation request key collision names different canonical intent",
        ));
    }
    Ok(CreatedOrJoinedRequest {
        request,
        created: inserted,
    })
}

pub async fn inspect_request(
    db: &Db,
    request_id: &str,
) -> Result<Option<DerivationRequestSnapshot>> {
    nonblank("id", request_id)?;
    let query = format!("{SELECT_REQUEST} WHERE id=?");
    sqlx::query(&query)
        .bind(request_id)
        .fetch_optional(db.pool())
        .await?
        .map(row_snapshot)
        .transpose()
}

pub async fn acquire_or_steal_request(
    db: &Db,
    request_id: &str,
    owner: &str,
    run_key: Option<&str>,
    lease_duration: StdDuration,
) -> Result<AcquireRequestResult> {
    acquire_or_steal_request_with_clock(
        db,
        request_id,
        owner,
        run_key,
        lease_duration,
        &SystemCoordinatorClock,
    )
    .await
}

pub(super) async fn acquire_or_steal_request_with_clock(
    db: &Db,
    request_id: &str,
    owner: &str,
    run_key: Option<&str>,
    lease_duration: StdDuration,
    clock: &dyn DerivationCoordinatorClock,
) -> Result<AcquireRequestResult> {
    nonblank("id", request_id)?;
    nonblank("lease owner", owner)?;
    // Acquire the serialized writer before sampling time. A worker that waited
    // behind another transaction must not make lease decisions using a stale
    // pre-lock timestamp.
    let mut tx = begin_write(db.write_pool()).await?;
    if inspect_request_in(&mut tx, request_id)
        .await?
        .is_some_and(|request| request.spec.audience_policy.is_some())
    {
        tx.rollback().await?;
        return Err(Error::engine(
            "governed derivation requests require controlled execution acquisition",
        ));
    }
    let result = acquire_or_steal_request_in_with_clock(
        &mut tx,
        request_id,
        owner,
        run_key,
        lease_duration,
        clock,
    )
    .await?;
    if matches!(result, AcquireRequestResult::Acquired(_)) {
        tx.commit().await?;
    } else {
        tx.rollback().await?;
    }
    Ok(result)
}

/// Acquire a request using a transaction already owned by a controlled
/// execution path. Callers can authorize the pinned recipe release under the
/// same write lock before invoking this mutation.
#[allow(dead_code)]
pub(crate) async fn acquire_or_steal_request_in(
    tx: &mut Transaction<'static, Sqlite>,
    request_id: &str,
    owner: &str,
    run_key: Option<&str>,
    lease_duration: StdDuration,
) -> Result<AcquireRequestResult> {
    acquire_or_steal_request_in_with_clock(
        tx,
        request_id,
        owner,
        run_key,
        lease_duration,
        &SystemCoordinatorClock,
    )
    .await
}

async fn acquire_or_steal_request_in_with_clock(
    tx: &mut Transaction<'static, Sqlite>,
    request_id: &str,
    owner: &str,
    run_key: Option<&str>,
    lease_duration: StdDuration,
    clock: &dyn DerivationCoordinatorClock,
) -> Result<AcquireRequestResult> {
    nonblank("id", request_id)?;
    nonblank("lease owner", owner)?;
    // The caller already owns the serialized writer. Sample immediately
    // before reading the fence so time spent waiting for that lock is excluded.
    let now = clock.now();
    let expiry = checked_expiry(now, lease_duration)?;
    let now_text = format_time(now);
    let expiry_text = format_time(expiry);
    let Some(current) = inspect_request_in(tx, request_id).await? else {
        return Ok(AcquireRequestResult::NotFound);
    };
    if current.is_terminal() {
        return Ok(AcquireRequestResult::Terminal);
    }
    let acquirable = match current.state {
        DerivationRequestState::Pending => true,
        DerivationRequestState::Running => current
            .lease_expires_at
            .as_deref()
            .map(|value| parse_time("lease expiry", value))
            .transpose()?
            .is_some_and(|value| value <= now),
        DerivationRequestState::Failed => {
            current.retryable
                && current
                    .next_attempt_at
                    .as_deref()
                    .map(|value| parse_time("next attempt time", value))
                    .transpose()?
                    .is_none_or(|value| value <= now)
        }
        DerivationRequestState::Succeeded => false,
    };
    if !acquirable {
        return Ok(AcquireRequestResult::Busy);
    }
    let next_generation = current
        .lease_generation
        .checked_add(1)
        .ok_or_else(|| Error::engine("derivation request lease generation overflows"))?;
    let affected = sqlx::query(
        "UPDATE derivation_requests
            SET state='running', lease_owner=?, lease_run_key=?, lease_generation=?,
                lease_expires_at=?, attempt_count=?, retryable=0, next_attempt_at=NULL,
                failure_code=NULL, failure_metadata=NULL, updated_at=?
          WHERE id=? AND state=? AND lease_generation=?",
    )
    .bind(owner)
    .bind(run_key)
    .bind(next_generation)
    .bind(&expiry_text)
    .bind(next_generation)
    .bind(&now_text)
    .bind(request_id)
    .bind(match current.state {
        DerivationRequestState::Pending => "pending",
        DerivationRequestState::Running => "running",
        DerivationRequestState::Failed => "failed",
        DerivationRequestState::Succeeded => "succeeded",
    })
    .bind(current.lease_generation)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if affected != 1 {
        return Err(Error::engine(
            "derivation request acquire lost its serialized state",
        ));
    }
    Ok(AcquireRequestResult::Acquired(DerivationRequestLease {
        request_id: request_id.into(),
        owner: owner.into(),
        run_key: run_key.map(str::to_owned),
        generation: next_generation,
        expires_at: expiry_text,
    }))
}

pub async fn renew_request(
    db: &Db,
    lease: &DerivationRequestLease,
    lease_duration: StdDuration,
) -> Result<Option<DerivationRequestLease>> {
    renew_request_with_clock(db, lease, lease_duration, &SystemCoordinatorClock).await
}

pub(super) async fn renew_request_with_clock(
    db: &Db,
    lease: &DerivationRequestLease,
    lease_duration: StdDuration,
    clock: &dyn DerivationCoordinatorClock,
) -> Result<Option<DerivationRequestLease>> {
    nonblank("id", &lease.request_id)?;
    nonblank("lease owner", &lease.owner)?;
    let mut tx = begin_write(db.write_pool()).await?;
    let now = clock.now();
    let new_expiry = checked_expiry(now, lease_duration)?;
    let Some(current) = inspect_request_in(&mut tx, &lease.request_id).await? else {
        tx.rollback().await?;
        return Ok(None);
    };
    if current.state != DerivationRequestState::Running
        || current.lease_owner.as_deref() != Some(lease.owner.as_str())
        || current.lease_generation != lease.generation
    {
        tx.rollback().await?;
        return Ok(None);
    }
    let Some(old_expiry_text) = current.lease_expires_at else {
        return Err(Error::engine(
            "running derivation request is missing its lease expiry",
        ));
    };
    let old_expiry = parse_time("lease expiry", &old_expiry_text)?;
    if old_expiry <= now || new_expiry <= old_expiry {
        tx.rollback().await?;
        return Ok(None);
    }
    let now_text = format_time(now);
    let expiry_text = format_time(new_expiry);
    let affected = sqlx::query(
        "UPDATE derivation_requests SET lease_expires_at=?,updated_at=?
          WHERE id=? AND state='running' AND lease_owner=? AND lease_generation=?
            AND lease_expires_at=?",
    )
    .bind(&expiry_text)
    .bind(&now_text)
    .bind(&lease.request_id)
    .bind(&lease.owner)
    .bind(lease.generation)
    .bind(&old_expiry_text)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    tx.commit().await?;
    Ok((affected == 1).then(|| DerivationRequestLease {
        request_id: lease.request_id.clone(),
        owner: lease.owner.clone(),
        run_key: lease.run_key.clone(),
        generation: lease.generation,
        expires_at: expiry_text,
    }))
}

fn same_canonical<T: Serialize>(left: &T, right: &T) -> Result<bool> {
    Ok(canonical_text(&serde_json::to_value(left)?)
        == canonical_text(&serde_json::to_value(right)?))
}

fn validate_executor(
    executor: &DerivationExecutorDescriptor,
    profile: &crate::recipe::RecipeExecutionProfile,
) -> Result<()> {
    nonblank("executor provider", &executor.provider)?;
    nonblank("executor model", &executor.model)?;
    nonblank("executor revision", &executor.executor_revision)?;
    nonblank("execution profile id", &executor.execution_profile_id)?;
    object("executor parameters", &executor.parameters)?;
    let expected_parameters = json!({
        "temperature_milli": profile.temperature_milli,
        "max_output_tokens": profile.max_output_tokens,
    });
    if executor.execution_profile_id != profile.profile_id
        || executor.capabilities != profile.required_capabilities
        || !same_canonical(&executor.parameters, &expected_parameters)?
    {
        return Err(Error::engine(
            "derivation executor evidence does not match its pinned execution profile",
        ));
    }
    Ok(())
}

fn validate_contract_instance(
    contract: &crate::recipe::RecipeContract,
    value: &Value,
    label: &str,
) -> Result<()> {
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(&contract.schema)
        .map_err(|_| Error::engine(format!("derivation pinned {label} contract is invalid")))?;
    validator.validate(value).map_err(|_| {
        Error::engine(format!(
            "derivation {label} does not satisfy its pinned recipe contract"
        ))
    })
}

fn input_class(value: &str) -> Option<crate::recipe::RecipeInputClass> {
    match value {
        "blob" => Some(crate::recipe::RecipeInputClass::Blob),
        "content_event" => Some(crate::recipe::RecipeInputClass::ContentEvent),
        "record_body" => Some(crate::recipe::RecipeInputClass::RecordBody),
        "versioned" => Some(crate::recipe::RecipeInputClass::Versioned),
        _ => None,
    }
}

fn validate_budget(budget: &Value, policy: &crate::recipe::RecipeBudgetPolicy) -> Result<()> {
    let object = budget
        .as_object()
        .ok_or_else(|| Error::engine("derivation request budget must be an object"))?;
    for (key, value) in object {
        let Some(value) = value.as_u64().filter(|value| *value > 0) else {
            return Err(Error::engine(
                "derivation request budget fields must be positive integers",
            ));
        };
        let (field, maximum) = match key.as_str() {
            "max_input_bytes" => (
                crate::recipe::RecipeBudgetField::MaxInputBytes,
                policy.maxima.max_input_bytes,
            ),
            "max_input_items" => (
                crate::recipe::RecipeBudgetField::MaxInputItems,
                u64::from(policy.maxima.max_input_items),
            ),
            "max_input_tokens" => (
                crate::recipe::RecipeBudgetField::MaxInputTokens,
                u64::from(policy.maxima.max_input_tokens),
            ),
            "max_output_bytes" => (
                crate::recipe::RecipeBudgetField::MaxOutputBytes,
                policy.maxima.max_output_bytes,
            ),
            "max_output_tokens" => (
                crate::recipe::RecipeBudgetField::MaxOutputTokens,
                u64::from(policy.maxima.max_output_tokens),
            ),
            _ => {
                return Err(Error::engine(
                    "derivation request budget field is unsupported",
                ))
            }
        };
        if !policy.supported_fields.contains(&field) || value > maximum {
            return Err(Error::engine(
                "derivation request budget exceeds its pinned recipe policy",
            ));
        }
    }
    Ok(())
}

fn budget_limit(budget: &Value, key: &str, default: u64) -> u64 {
    budget.get(key).and_then(Value::as_u64).unwrap_or(default)
}

async fn measured_input_bytes(
    tx: &mut Transaction<'_, Sqlite>,
    inputs: &[super::DerivationInput],
) -> Result<u64> {
    let mut total = 0_u64;
    for input in inputs {
        let bytes = match input.input_kind.as_str() {
            "content_event" => {
                let payload: String = sqlx::query_scalar::<_, Option<String>>(
                    "SELECT payload FROM content_events WHERE id=?",
                )
                .bind(&input.portable_id)
                .fetch_one(&mut **tx)
                .await?
                .ok_or_else(|| Error::engine("derivation manifest input has no payload"))?;
                let value: Value = serde_json::from_str(&payload)?;
                u64::try_from(canonical_json(&value).len())
                    .map_err(|_| Error::engine("derivation input byte count overflows"))?
            }
            "record_body" => {
                let payload: String = sqlx::query_scalar::<_, Option<String>>(
                    "SELECT payload FROM content_events WHERE id=?",
                )
                .bind(&input.portable_id)
                .fetch_one(&mut **tx)
                .await?
                .ok_or_else(|| Error::engine("derivation record-body input has no payload"))?;
                let value: Value = serde_json::from_str(&payload)?;
                let body = value
                    .get("body")
                    .and_then(Value::as_str)
                    .ok_or_else(|| Error::engine("derivation record-body input is malformed"))?;
                u64::try_from(body.len())
                    .map_err(|_| Error::engine("derivation input byte count overflows"))?
            }
            "blob" => {
                let size: i64 = sqlx::query_scalar("SELECT size_bytes FROM blobs WHERE id=?")
                    .bind(&input.portable_id)
                    .fetch_one(&mut **tx)
                    .await?;
                u64::try_from(size).map_err(|_| Error::engine("derivation blob size is invalid"))?
            }
            _ => {
                return Err(Error::engine(
                    "derivation input byte measurement is unavailable",
                ))
            }
        };
        total = total
            .checked_add(bytes)
            .ok_or_else(|| Error::engine("derivation input byte count overflows"))?;
    }
    Ok(total)
}

async fn prove_audience_on_inner(
    tx: &mut Transaction<'_, Sqlite>,
    request: &DerivationRequestSnapshot,
    inputs: &[super::DerivationInput],
    target_record_id: &str,
    live_membership: Option<&LiveMembershipResolver<'_>>,
) -> Result<i64> {
    let policy = request
        .spec
        .audience_policy
        .as_ref()
        .ok_or_else(|| Error::engine("missing audience policy"))?;
    if audience_policy_sha256(policy)? != request.spec.audience_sha256 {
        return Err(Error::engine("audience digest mismatch"));
    }
    let target = crate::authorization::authorization_target_on(tx, target_record_id).await?;
    let target_anchor: String = sqlx::query_scalar(
        "SELECT policy_anchor_id FROM records WHERE id=? AND deleted_at IS NULL",
    )
    .bind(&target)
    .fetch_one(&mut **tx)
    .await?;
    if target_anchor != policy.policy_anchor_id {
        return Err(Error::engine("output policy mismatch"));
    }

    let mut records = Vec::with_capacity(inputs.len() + 1);
    records.push(target_record_id.to_string());
    for input in inputs {
        let record_id = input
            .metadata
            .get("record_id")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| Error::engine("uninstrumented manifest input"))?;
        if input.metadata.get("schema").and_then(Value::as_str)
            == Some("native.change-summary.input.v1")
        {
            let metadata = input
                .metadata
                .as_object()
                .ok_or_else(|| Error::engine("change-summary input metadata is malformed"))?;
            let valid_source = input.input_role == "source"
                && input.input_kind == "content_event"
                && metadata.len() == 3
                && metadata.contains_key("record_id")
                && metadata.contains_key("record_head_event_seq");
            let valid_context = input.input_role == "context"
                && input.input_kind == "record_body"
                && metadata.len() == 3
                && metadata.contains_key("record_id")
                && metadata.contains_key("record_state");
            if !valid_source && !valid_context {
                return Err(Error::engine("change-summary input metadata is malformed"));
            }
        }
        if matches!(input.input_kind.as_str(), "content_event" | "record_body") {
            let row = sqlx::query("SELECT record_id,payload FROM content_events WHERE id=?")
                .bind(&input.portable_id)
                .fetch_optional(&mut **tx)
                .await?
                .ok_or_else(|| Error::engine("missing manifest input"))?;
            let event_record_id: String = row.try_get("record_id")?;
            let payload: Option<String> = row.try_get("payload")?;
            let payload = payload
                .as_deref()
                .map(serde_json::from_str::<Value>)
                .transpose()?
                .ok_or_else(|| Error::engine("missing manifest payload"))?;
            let digest_matches = if input.input_kind == "content_event" {
                digest_json(&payload) == input.sha256
            } else {
                payload
                    .get("body")
                    .and_then(Value::as_str)
                    .is_some_and(|body| {
                        hex::encode(sha2::Sha256::digest(body.as_bytes())) == input.sha256
                    })
            };
            if event_record_id != record_id || !digest_matches {
                return Err(Error::engine("manifest input mismatch"));
            }
            if input.input_kind == "record_body" {
                let current_body_event_id: Option<String> = sqlx::query_scalar(
                    "SELECT id FROM content_events WHERE record_id=?
                       AND json_type(payload,'$.body')='text' ORDER BY seq DESC LIMIT 1",
                )
                .bind(record_id)
                .fetch_optional(&mut **tx)
                .await?;
                if current_body_event_id.as_deref() != Some(input.portable_id.as_str()) {
                    return Err(Error::engine(
                        "manifest record-body input is no longer current",
                    ));
                }
            }
            if let Some(expected_head) = input.metadata.get("record_head_event_seq") {
                let expected_head = expected_head
                    .as_i64()
                    .filter(|value| *value > 0)
                    .ok_or_else(|| Error::engine("manifest record head is malformed"))?;
                let current_head: Option<i64> =
                    sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
                        .bind(record_id)
                        .fetch_one(&mut **tx)
                        .await?;
                if current_head != Some(expected_head) {
                    return Err(Error::engine(
                        "manifest record head changed before publication",
                    ));
                }
            }
            if let Some(expected_state) = input.metadata.get("record_state") {
                let Some(state_object) = expected_state.as_object() else {
                    return Err(Error::engine("manifest record state is malformed"));
                };
                if state_object.len() != 4
                    || !["type", "kind", "is_live", "is_realised"]
                        .iter()
                        .all(|key| state_object.contains_key(*key))
                {
                    return Err(Error::engine("manifest record state is malformed"));
                }
                let expected_type = expected_state.get("type").and_then(Value::as_str);
                let expected_kind = expected_state.get("kind").and_then(Value::as_str);
                let expected_live = expected_state.get("is_live").and_then(Value::as_bool);
                let expected_realised = expected_state.get("is_realised").and_then(Value::as_bool);
                let (
                    Some(expected_type),
                    Some(expected_kind),
                    Some(expected_live),
                    Some(expected_realised),
                ) = (
                    expected_type,
                    expected_kind,
                    expected_live,
                    expected_realised,
                )
                else {
                    return Err(Error::engine("manifest record state is malformed"));
                };
                let row = sqlx::query("SELECT type,kind,deleted_at FROM records WHERE id=?")
                    .bind(record_id)
                    .fetch_optional(&mut **tx)
                    .await?
                    .ok_or_else(|| Error::engine("manifest record state is unavailable"))?;
                let record_type: String = row.try_get("type")?;
                let record_kind: String = row.try_get("kind")?;
                let is_live = row.try_get::<Option<String>, _>("deleted_at")?.is_none();
                let is_realised = record_type == "Outcome" && record_kind == "impact";
                if record_type != expected_type
                    || record_kind != expected_kind
                    || is_live != expected_live
                    || is_realised != expected_realised
                {
                    return Err(Error::engine(
                        "manifest record state changed before publication",
                    ));
                }
            }
        } else if input.input_kind == "blob" {
            let bound: bool = sqlx::query_scalar(
                "SELECT EXISTS(
                   SELECT 1 FROM facet_values
                    WHERE record_id=? AND key=? AND value=?
                 )",
            )
            .bind(record_id)
            .bind(crate::blob::BLOB_REF_FACET_KEY)
            .bind(&input.portable_id)
            .fetch_one(&mut **tx)
            .await?;
            if !bound {
                return Err(Error::engine("manifest input mismatch"));
            }
        }
        records.push(record_id.to_string());
    }
    records.sort();
    records.dedup();
    for record_id in records {
        for audience_principal in &policy.principals {
            let is_member = live_membership.map_or(audience_principal.is_member, |resolve| {
                resolve(&audience_principal.account_id).unwrap_or(false)
            });
            let capability = crate::authorization::effective_capability_on(
                tx,
                crate::authorization::Principal::bound(&audience_principal.account_id, is_member),
                &record_id,
            )
            .await?;
            if !capability.allows(crate::authorization::Capability::View) {
                return Err(Error::engine("audience principal cannot view input"));
            }
        }
    }
    crate::authorization::authorization_revision_on(tx).await
}

async fn prove_audience_on(
    tx: &mut Transaction<'static, Sqlite>,
    request: &DerivationRequestSnapshot,
    inputs: &[super::DerivationInput],
    target_record_id: &str,
) -> Result<i64> {
    prove_audience_on_inner(tx, request, inputs, target_record_id, None)
        .await
        .map_err(|_| Error::engine("derivation audience proof failed"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CompletionFailurePoint {
    None,
    AfterPublication,
    AfterRequestTransition,
}

pub async fn complete_request_with_publication(
    db: &Db,
    principal: crate::authorization::Principal<'_>,
    completion: CompleteDerivationRequest,
) -> Result<Option<super::bindings::PublishedRecordBodyRevision>> {
    complete_request_with_publication_at(
        db,
        principal,
        completion,
        &SystemCoordinatorClock,
        CompletionFailurePoint::None,
    )
    .await
}

pub(super) async fn complete_request_with_publication_at(
    db: &Db,
    principal: crate::authorization::Principal<'_>,
    mut completion: CompleteDerivationRequest,
    clock: &dyn DerivationCoordinatorClock,
    failure_point: CompletionFailurePoint,
) -> Result<Option<super::bindings::PublishedRecordBodyRevision>> {
    let mut tx = begin_write(db.write_pool()).await?;
    let now = clock.now();
    let Some(request) = inspect_request_in(&mut tx, &completion.lease.request_id).await? else {
        tx.rollback().await?;
        return Ok(None);
    };
    let lease_is_live = request.state == DerivationRequestState::Running
        && request.lease_owner.as_deref() == Some(completion.lease.owner.as_str())
        && request.lease_generation == completion.lease.generation
        && request.lease_run_key == completion.lease.run_key
        && request
            .lease_expires_at
            .as_deref()
            .map(|value| parse_time("lease expiry", value))
            .transpose()?
            .is_some_and(|expires| expires > now);
    if !lease_is_live {
        tx.rollback().await?;
        return Ok(None);
    }
    if completion.publication.run_key != completion.lease.run_key {
        return Err(Error::engine(
            "derivation publication run key does not match its winning lease",
        ));
    }

    let pinned_recipe = &request.spec.recipe_revision;
    let release = crate::recipe::require_recipe_release_for_execution_on(
        &mut tx,
        principal,
        &pinned_recipe.definition_id,
        &pinned_recipe.publication_id,
        completion.expected_recipe_status_event_seq,
    )
    .await?;
    if release.descriptor_sha256 != pinned_recipe.sha256 {
        return Err(Error::engine(
            "derivation request recipe digest does not match its governed release",
        ));
    }
    validate_executor(
        &completion.executor,
        &release.descriptor.definition.execution_profile,
    )?;
    if release.descriptor.definition.query_contract.id
        != request.spec.canonical_request.query_contract
        || i64::from(release.descriptor.definition.query_contract.version)
            != request.spec.canonical_request.query_contract_version
    {
        return Err(Error::engine(
            "derivation request does not match its pinned query contract",
        ));
    }
    validate_budget(&request.spec.budget, &release.descriptor.definition.budgets)?;
    validate_contract_instance(
        &release.descriptor.definition.result_contract,
        &completion.structured_result,
        "structured result",
    )?;
    let output_body = completion
        .rendered_output
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::engine("derivation rendered output is missing its body"))?;
    if output_body != completion.publication.body {
        return Err(Error::engine(
            "derivation rendered output body does not match its publication",
        ));
    }
    validate_contract_instance(
        &release.descriptor.definition.output_contract,
        &completion.rendered_output,
        "rendered output",
    )?;
    let effective_output_bytes = budget_limit(
        &request.spec.budget,
        "max_output_bytes",
        release
            .descriptor
            .definition
            .budgets
            .defaults
            .max_output_bytes,
    );
    let measured_output_bytes = u64::try_from(completion.publication.body.len())
        .map_err(|_| Error::engine("derivation output byte count overflows"))?;
    if measured_output_bytes > effective_output_bytes {
        return Err(Error::engine(
            "derivation rendered output exceeds its pinned recipe budget",
        ));
    }
    if completion.publication.revision.series_id != request.spec.series_id
        || !same_canonical(
            &completion.publication.revision.canonical_request,
            &request.spec.canonical_request,
        )?
        || !same_canonical(
            &completion.publication.revision.recipe_revision,
            &request.spec.recipe_revision,
        )?
        || !same_canonical(
            &completion.publication.revision.effective_source_boundary,
            &request.spec.effective_source_boundary,
        )?
    {
        return Err(Error::engine(
            "derivation publication does not match its canonical request",
        ));
    }
    let series: (String, String) =
        sqlx::query_as("SELECT definition,definition_sha256 FROM derivation_series WHERE id=?")
            .bind(&request.spec.series_id)
            .fetch_one(&mut *tx)
            .await?;
    let series_definition: Value = serde_json::from_str(&series.0)?;
    if series.1 != request.spec.definition_sha256
        || !controlled_series_matches(&series_definition, &request.spec)?
    {
        return Err(Error::engine(
            "derivation request does not match its stable series definition",
        ));
    }
    let expected_target_basis = json!({
        "target": completion.publication.target,
        "binding_id": completion.publication.binding_id,
        "binding_generation": completion.publication.expected_generation,
        "target_version": completion.publication.expected_target_version,
    });
    if canonical_text(&request.spec.target_basis) != canonical_text(&expected_target_basis) {
        return Err(Error::engine(
            "derivation publication does not match its pinned target basis",
        ));
    }
    for input in &completion.publication.revision.inputs {
        let class = input_class(&input.input_kind)
            .ok_or_else(|| Error::engine("derivation manifest input class is unsupported"))?;
        if !release
            .descriptor
            .definition
            .allowed_input_classes
            .contains(&class)
        {
            return Err(Error::engine(
                "derivation manifest input class is not allowed by its pinned recipe",
            ));
        }
    }
    let effective_input_items = budget_limit(
        &request.spec.budget,
        "max_input_items",
        u64::from(
            release
                .descriptor
                .definition
                .budgets
                .defaults
                .max_input_items,
        ),
    );
    if completion.publication.revision.inputs.len() as u64 > effective_input_items {
        return Err(Error::engine(
            "derivation manifest exceeds its pinned recipe budget",
        ));
    }
    let measured_input_items = completion.publication.revision.inputs.len() as u64;
    let measured_input_bytes =
        measured_input_bytes(&mut tx, &completion.publication.revision.inputs).await?;
    let effective_input_bytes = budget_limit(
        &request.spec.budget,
        "max_input_bytes",
        release
            .descriptor
            .definition
            .budgets
            .defaults
            .max_input_bytes,
    );
    let effective_input_tokens = budget_limit(
        &request.spec.budget,
        "max_input_tokens",
        u64::from(
            release
                .descriptor
                .definition
                .budgets
                .defaults
                .max_input_tokens,
        ),
    );
    let effective_output_tokens = budget_limit(
        &request.spec.budget,
        "max_output_tokens",
        u64::from(
            release
                .descriptor
                .definition
                .budgets
                .defaults
                .max_output_tokens,
        ),
    );
    let usage = &completion.executor.usage;
    if usage.input_items != measured_input_items
        || usage.input_bytes != measured_input_bytes
        || usage.output_bytes != measured_output_bytes
        || measured_input_bytes > effective_input_bytes
        || usage.input_tokens > effective_input_tokens
        || usage.output_tokens > effective_output_tokens
        || usage.output_tokens
            > u64::from(
                release
                    .descriptor
                    .definition
                    .execution_profile
                    .max_output_tokens,
            )
    {
        return Err(Error::engine(
            "derivation execution usage exceeds or contradicts its pinned budget",
        ));
    }
    let authorization_revision = prove_audience_on(
        &mut tx,
        &request,
        &completion.publication.revision.inputs,
        &completion.publication.target.record_id,
    )
    .await?;
    completion.publication.revision.completion_metadata = json!({
        "schema": "native.derivation-completion.v1",
        "request_key_sha256": request.request_key_sha256,
        "attempt_ordinal": completion.lease.generation,
        "attempt": {
            "lease_owner": completion.lease.owner.clone(),
            "lease_run_key": completion.lease.run_key.clone(),
            "lease_generation": completion.lease.generation,
            "lease_expires_at": request.lease_expires_at.clone(),
            "publication_actor": completion.publication.actor.clone(),
            "publication_run_key": completion.publication.run_key.clone(),
        },
        "target_basis": request.spec.target_basis,
        "budget": request.spec.budget,
        "audience": {
            "policy": request.spec.audience_policy,
            "sha256": request.spec.audience_sha256,
            "authorization_revision": authorization_revision,
        },
        "executor": completion.executor,
        "measured_usage": {
            "input_bytes": measured_input_bytes,
            "input_items": measured_input_items,
            "output_bytes": measured_output_bytes,
        },
        "structured_result": completion.structured_result,
        "result_contract": {
            "id": release.descriptor.definition.result_contract.id,
            "version": release.descriptor.definition.result_contract.version,
            "schema_sha256": release.descriptor.definition.result_contract.schema_sha256,
        },
        "output_contract": {
            "id": release.descriptor.definition.output_contract.id,
            "version": release.descriptor.definition.output_contract.version,
            "schema_sha256": release.descriptor.definition.output_contract.schema_sha256,
        },
        "renderer": release.descriptor.definition.renderer,
    });
    let revision_id = completion.publication.revision.id.clone();
    let published = super::bindings::publish_record_body_revision_in(
        db,
        &mut tx,
        principal,
        completion.publication,
        super::bindings::PublicationFailurePoint::None,
        super::bindings::PublicationAuthority::ControlledRequest,
    )
    .await?;
    if failure_point == CompletionFailurePoint::AfterPublication {
        return Err(Error::engine(
            "injected derivation completion failure after publication",
        ));
    }
    let now_text = format_time(now);
    let affected = sqlx::query(
        "UPDATE derivation_requests
            SET state='succeeded',lease_owner=NULL,lease_run_key=NULL,lease_expires_at=NULL,
                retryable=0,next_attempt_at=NULL,failure_code=NULL,failure_metadata=NULL,
                result_revision_id=?,updated_at=?
          WHERE id=? AND state='running' AND lease_owner=? AND lease_generation=?
            AND lease_expires_at=?",
    )
    .bind(&revision_id)
    .bind(now_text)
    .bind(&completion.lease.request_id)
    .bind(&completion.lease.owner)
    .bind(completion.lease.generation)
    .bind(&request.lease_expires_at)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if affected != 1 {
        return Err(Error::engine(
            "derivation request completion lost its serialized state",
        ));
    }
    if failure_point == CompletionFailurePoint::AfterRequestTransition {
        return Err(Error::engine(
            "injected derivation completion failure after request transition",
        ));
    }
    db.commit_content(tx).await?;
    Ok(Some(published))
}

/// Revalidate a completed revision against the request's entire explicit
/// audience in one read snapshot. The function is fail-closed and returns no
/// input identities, counts, or policy details on failure.
pub(crate) async fn revision_audience_is_available_in(
    snapshot: &mut Transaction<'_, Sqlite>,
    request_id: &str,
    revision_id: &str,
    live_membership: &LiveMembershipResolver<'_>,
) -> Result<bool> {
    let outcome = async {
        let request = inspect_request_in(snapshot, request_id)
            .await?
            .ok_or_else(|| Error::engine("unavailable"))?;
        if request.state != DerivationRequestState::Succeeded
            || request.result_revision_id.as_deref() != Some(revision_id)
        {
            return Err(Error::engine("unavailable"));
        }
        let metadata: String = sqlx::query_scalar(
            "SELECT completion_metadata FROM derivation_revisions
              WHERE id=? AND series_id=?",
        )
        .bind(revision_id)
        .bind(&request.spec.series_id)
        .fetch_one(&mut **snapshot)
        .await?;
        let metadata: Value = serde_json::from_str(&metadata)?;
        if metadata.get("request_key_sha256").and_then(Value::as_str)
            != Some(request.request_key_sha256.as_str())
            || metadata.pointer("/audience/sha256").and_then(Value::as_str)
                != Some(request.spec.audience_sha256.as_str())
        {
            return Err(Error::engine("unavailable"));
        }
        let target_record_id: String = sqlx::query_scalar(
            "SELECT b.target_record_id
               FROM derivation_target_publications p
               JOIN derivation_target_bindings b ON b.binding_id=p.binding_id
              WHERE p.revision_id=?",
        )
        .bind(revision_id)
        .fetch_one(&mut **snapshot)
        .await?;
        let rows = sqlx::query(
            "SELECT input_role,input_kind,portable_id,sha256,metadata
               FROM derivation_revision_inputs WHERE revision_id=? ORDER BY ordinal",
        )
        .bind(revision_id)
        .fetch_all(&mut **snapshot)
        .await?;
        let mut inputs = Vec::with_capacity(rows.len());
        for row in rows {
            inputs.push(super::DerivationInput {
                input_role: row.try_get("input_role")?,
                input_kind: row.try_get("input_kind")?,
                portable_id: row.try_get("portable_id")?,
                sha256: row.try_get("sha256")?,
                metadata: serde_json::from_str(row.try_get("metadata")?)?,
            });
        }
        prove_audience_on_inner(
            snapshot,
            &request,
            &inputs,
            &target_record_id,
            Some(live_membership),
        )
        .await?;
        Ok::<(), Error>(())
    }
    .await;
    Ok(outcome.is_ok())
}

/// Revalidate a completed revision against live host membership supplied by
/// the caller. Missing membership answers fail closed for members grants;
/// direct account and owner grants remain independently effective.
pub async fn revision_audience_is_available(
    db: &Db,
    request_id: &str,
    revision_id: &str,
    live_membership: &LiveMembershipResolver<'_>,
) -> Result<bool> {
    let mut snapshot = db.pool().begin().await?;
    let available =
        revision_audience_is_available_in(&mut snapshot, request_id, revision_id, live_membership)
            .await?;
    snapshot.rollback().await?;
    Ok(available)
}

fn validate_failure_evidence(
    request: &DerivationRequestSnapshot,
    failure: &DerivationRequestFailure,
) -> Result<()> {
    let evidence = &failure.evidence;
    if evidence.series_id != request.spec.series_id
        || evidence.coordination_request_key_sha256.as_deref()
            != Some(request.request_key_sha256.as_str())
        || !same_canonical(&evidence.canonical_request, &request.spec.canonical_request)?
        || !same_canonical(&evidence.recipe_revision, &request.spec.recipe_revision)?
        || !same_canonical(
            &evidence.effective_source_boundary,
            &request.spec.effective_source_boundary,
        )?
        || evidence.attempt_ordinal != request.attempt_count
        || evidence.attempt_ordinal != failure.lease.generation
    {
        return Err(Error::engine(
            "derivation failure evidence does not match its fenced request attempt",
        ));
    }
    nonblank("failure code", &evidence.failure_code)?;
    object("failure metadata", &evidence.failure_metadata)?;
    object("executor descriptor", &evidence.executor_descriptor)?;
    if !evidence.retryable && failure.retry_after.is_some() {
        return Err(Error::engine(
            "terminal derivation failure cannot schedule a retry",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RequestFailurePoint {
    None,
    AfterEvidence,
    AfterTransition,
}

async fn fail_request_in_with_clock(
    tx: &mut Transaction<'static, Sqlite>,
    failure: &DerivationRequestFailure,
    clock: &dyn DerivationCoordinatorClock,
    failure_point: RequestFailurePoint,
) -> Result<Option<DerivationEventRow>> {
    let now = clock.now();
    let now_text = format_time(now);
    let Some(current) = inspect_request_in(tx, &failure.lease.request_id).await? else {
        return Ok(None);
    };
    let lease_is_live = current.state == DerivationRequestState::Running
        && current.lease_owner.as_deref() == Some(failure.lease.owner.as_str())
        && current.lease_generation == failure.lease.generation
        && current
            .lease_expires_at
            .as_deref()
            .map(|value| parse_time("lease expiry", value))
            .transpose()?
            .is_some_and(|expires| expires > now);
    if !lease_is_live {
        return Ok(None);
    }
    validate_failure_evidence(&current, failure)?;
    let next_attempt_at = if failure.evidence.retryable {
        failure
            .retry_after
            .map(|delay| {
                let delay = Duration::from_std(delay)
                    .map_err(|_| Error::engine("derivation retry delay is invalid"))?;
                now.checked_add_signed(delay)
                    .map(format_time)
                    .ok_or_else(|| Error::engine("derivation retry time overflows"))
            })
            .transpose()?
    } else {
        None
    };
    let event = append_derivation_event_in(
        tx,
        NewDerivationEvent::authored(
            failure.event_idempotency_key.clone(),
            failure.actor.clone(),
            failure.run_key.clone(),
            failure.reason.clone(),
            DerivationEventPayload::AttemptFailed(failure.evidence.clone()),
        )?,
    )
    .await?;
    if failure_point == RequestFailurePoint::AfterEvidence {
        return Err(Error::engine(
            "injected derivation request crash after failure evidence",
        ));
    }
    let affected = sqlx::query(
        "UPDATE derivation_requests
            SET state='failed',lease_owner=NULL,lease_run_key=NULL,lease_expires_at=NULL,
                retryable=?,next_attempt_at=?,failure_code=?,failure_metadata=?,updated_at=?
          WHERE id=? AND state='running' AND lease_owner=? AND lease_generation=?
            AND lease_expires_at=?",
    )
    .bind(i64::from(failure.evidence.retryable))
    .bind(next_attempt_at)
    .bind(&failure.evidence.failure_code)
    .bind(canonical_text(&failure.evidence.failure_metadata))
    .bind(now_text)
    .bind(&failure.lease.request_id)
    .bind(&failure.lease.owner)
    .bind(failure.lease.generation)
    .bind(&current.lease_expires_at)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if affected != 1 {
        return Err(Error::engine(
            "derivation request failure lost its serialized state",
        ));
    }
    if failure_point == RequestFailurePoint::AfterTransition {
        return Err(Error::engine(
            "injected derivation request crash after failure transition",
        ));
    }
    Ok(Some(event))
}

/// Transaction-owned failure primitive for execution paths that already hold
/// the write lock. The authoritative attempt event and fenced state transition
/// either both commit with the caller's transaction or neither does.
#[allow(dead_code)]
pub(crate) async fn fail_request_in(
    tx: &mut Transaction<'static, Sqlite>,
    failure: &DerivationRequestFailure,
) -> Result<Option<DerivationEventRow>> {
    fail_request_in_with_clock(
        tx,
        failure,
        &SystemCoordinatorClock,
        RequestFailurePoint::None,
    )
    .await
}

pub async fn fail_request(
    db: &Db,
    failure: DerivationRequestFailure,
) -> Result<Option<DerivationEventRow>> {
    fail_request_with_clock(
        db,
        failure,
        &SystemCoordinatorClock,
        RequestFailurePoint::None,
    )
    .await
}

pub(super) async fn fail_request_with_clock(
    db: &Db,
    failure: DerivationRequestFailure,
    clock: &dyn DerivationCoordinatorClock,
    failure_point: RequestFailurePoint,
) -> Result<Option<DerivationEventRow>> {
    let mut tx = begin_write(db.write_pool()).await?;
    match fail_request_in_with_clock(&mut tx, &failure, clock, failure_point).await {
        Ok(Some(event)) => {
            tx.commit().await?;
            Ok(Some(event))
        }
        Ok(None) => {
            tx.rollback().await?;
            Ok(None)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

pub async fn wait_for_request(
    db: &Db,
    request_id: &str,
    timeout: StdDuration,
    poll_interval: Option<StdDuration>,
) -> Result<RequestWaitOutcome> {
    if timeout > MAX_DERIVATION_WAIT_DURATION {
        return Err(Error::engine(format!(
            "derivation request wait exceeds {}s bound",
            MAX_DERIVATION_WAIT_DURATION.as_secs()
        )));
    }
    let poll = poll_interval.unwrap_or(DEFAULT_WAIT_POLL_INTERVAL);
    if poll.is_zero() {
        return Err(Error::engine(
            "derivation request wait poll interval must be positive",
        ));
    }
    let started = tokio::time::Instant::now();
    loop {
        let Some(snapshot) = inspect_request(db, request_id).await? else {
            return Ok(RequestWaitOutcome::NotFound);
        };
        if snapshot.is_terminal() {
            return Ok(RequestWaitOutcome::Terminal(snapshot));
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Ok(RequestWaitOutcome::TimedOut(snapshot));
        }
        tokio::time::sleep(poll.min(timeout - elapsed)).await;
    }
}
