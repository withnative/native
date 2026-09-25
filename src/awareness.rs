//! Portable, event-authoritative Message awareness.
//!
//! This tier is intentionally independent from the content, policy, control,
//! and disposable read logs. Every accepted mutation appends one immutable
//! event and folds its exact projection in the caller's existing SQLite write
//! transaction. Missing projection rows are meaningful defaults: human
//! `unsurfaced`, agent `unhandled`, no personal preference.

use base64::Engine as _;
use futures::future::BoxFuture;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, SqliteConnection};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::portable_sql::{
    BindValue, BorrowedSqliteStatementExecutor, ColumnSpec, DomainStatementExecutor, LogicalType,
    NormalizedRow, NormalizedValue, SqlResult, StatementKind, StatementTemplate,
};
use crate::store::now_iso;

pub const AWARENESS_RETENTION_FLOOR: i64 = 0;
pub const CANDIDATE_RETENTION_FLOOR: i64 = 0;
pub const MESSAGE_INBOX_SCHEMA: &str = "native.message-inbox.v2";

/// The schema this surface used before `home_id` joined every item. Retained
/// so the version story is legible in code rather than only in a changelog:
/// nothing serves it any more, and nothing negotiates it.
pub const MESSAGE_INBOX_SCHEMA_V1: &str = "native.message-inbox.v1";

/// One canonical serialization contract for every MCP/App consumer. There is
/// no separate UI adapter in this repository; hosted and self-hosted clients
/// consume the same MCP value and can pin this fixture in their own tests.
///
/// VERSION 2 (26 Aug 2026) adds `home_id` to `item_fields`. The added field is
/// additive on the wire — a v1 reader that ignores unknown keys is unaffected —
/// but `item_fields` is itself the pinned value, and a client that asserts the
/// exact list would break silently against an unchanged version string. The
/// version therefore moves with the list, which is the only way a pinning
/// client learns it must re-pin. There is no dual serving and no negotiation
/// parameter: `list_inbox` emits exactly one schema, `validate_messaging_surface_response`
/// enforces exactly one contract. The engine's historical database baseline
/// (`db::SUPPORTED_ENGINE_SCHEMA_BASELINE`) governs physical SQLite migration,
/// not parallel serving of historical MCP response schemas, so inventing a v1
/// compatibility path would build a mechanism nothing in the system consumes.
/// The compatibility that does exist is the field's own shape: `home_id` is
/// always emitted, carrying `native:unfiled` for a Message sent without a home
/// and `null` only for a record with no home at all, so grouping by destination
/// is total rather than something a client has to special-case.
pub fn messaging_surface_contract() -> Value {
    json!({
        "schema": MESSAGE_INBOX_SCHEMA,
        "response_fields": ["schema","view","items","snapshot","next_after","newer_available","heads","counts_are_distinct_message_ids"],
        "item_fields": ["message_id","home_id","name","body","created_at","human","agent","obligation","route","mention","attention","delivery"],
        "human_stages": ["unsurfaced","presented","opened","acknowledged"],
        "agent_states": ["unhandled","triaged","deferred","escalated","acted","resolved"],
        "head_fields": ["content","awareness","candidates","control","authorization"],
        "views": ["needs_me","agent_queue","handled_without_me","all_new","browse"],
        "errors": {
            "human_attestation_required": "human awareness requires a server-verified interaction attestation",
            "routing_authority_required": "routing requires attested principal choice or trusted policy authority",
            "version_conflict_suffix": "version conflict"
        }
    })
}

pub fn validate_messaging_surface_response(value: &Value) -> Result<()> {
    let contract = messaging_surface_contract();
    if value["schema"] != contract["schema"] {
        return Err(Error::engine("message Inbox response schema mismatch"));
    }
    for field in contract["response_fields"].as_array().unwrap() {
        if value.get(field.as_str().unwrap()).is_none() {
            return Err(Error::engine(format!(
                "message Inbox response missing canonical field {}",
                field.as_str().unwrap()
            )));
        }
    }
    let heads = value["heads"]
        .as_object()
        .ok_or_else(|| Error::engine("message Inbox response heads must be an object"))?;
    for field in contract["head_fields"].as_array().unwrap() {
        let name = field.as_str().unwrap();
        if !heads.get(name).is_some_and(Value::is_number) {
            return Err(Error::engine(format!(
                "message Inbox response missing numeric canonical head {name}"
            )));
        }
    }
    for item in value["items"].as_array().into_iter().flatten() {
        for field in contract["item_fields"].as_array().unwrap() {
            if item.get(field.as_str().unwrap()).is_none() {
                return Err(Error::engine(format!(
                    "message Inbox item missing canonical field {}",
                    field.as_str().unwrap()
                )));
            }
        }
    }
    Ok(())
}
pub const MAX_EXACT_MESSAGE_BATCH: usize = 500;

/// One portable notification candidate that remains effective and viewable by
/// its recipient at harvest time. Hosted delivery owns endpoint policy and job
/// materialization; the portable engine owns candidate and authorization
/// reads.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostNotificationCandidate {
    pub candidate_id: String,
    pub reason: String,
    pub priority: String,
    pub redaction_class: String,
    pub evaluator_kind: String,
    pub policy_version: String,
    pub muted: bool,
}

/// The bounded portable harvest projection and the event frontier scanned to
/// produce it. The frontier advances across withdrawn and unauthorized rows so
/// a hosted installation cannot replay them forever.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostNotificationHarvest {
    pub scanned_through: i64,
    pub candidates: Vec<HostNotificationCandidate>,
}

/// Portable facts revalidated immediately before hosted delivery. Absence
/// means the candidate is missing; present-but-invalid candidates remain
/// distinguishable so hosted policy corruption keeps its historical error
/// precedence before the final eligibility decision.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostNotificationRevalidation {
    pub message_id: String,
    pub not_before: Option<String>,
    pub priority: String,
    pub evaluator_kind: String,
    pub policy_version: String,
    pub effective_viewable_unmuted: bool,
}

/// Read a bounded notification-candidate suffix under portable authorization.
/// Authorization errors are denials, matching ordinary record reads.
/// `is_member` is the recipient's live catalog footing: guests evaluate the
/// candidate message with their own account grants only. It is a required
/// parameter so a future delivery pipeline must resolve and supply the
/// footing rather than inheriting member resolution silently.
#[doc(hidden)]
pub async fn harvest_host_notification_candidates(
    db: &crate::Db,
    recipient_account_id: &str,
    recipient_is_member: bool,
    after_candidate_seq: i64,
    limit: i64,
) -> Result<HostNotificationHarvest> {
    if !(1..=500).contains(&limit) {
        return Err(Error::engine("harvest limit must be 1..=500"));
    }
    let rows = sqlx::query(
        "SELECT candidate_id,message_id,reason,priority,redaction_class,evaluator_kind,policy_version,candidate_event_seq,status FROM notification_candidates WHERE recipient_account_id=? AND candidate_event_seq>? ORDER BY candidate_event_seq LIMIT ?",
    )
    .bind(recipient_account_id)
    .bind(after_candidate_seq)
    .bind(limit)
    .fetch_all(db.write_pool())
    .await?;
    let mut scanned_through = after_candidate_seq;
    let mut candidates = Vec::new();
    for row in rows {
        scanned_through = scanned_through.max(row.try_get("candidate_event_seq")?);
        if row.try_get::<String, _>("status")? != "effective" {
            continue;
        }
        let message_id: String = row.try_get("message_id")?;
        let access = crate::authorization::effective_capability_in_pool(
            db.write_pool(),
            crate::authorization::Principal::bound(recipient_account_id, recipient_is_member),
            &message_id,
        )
        .await;
        if !access.is_ok_and(|capability| capability.allows(crate::authorization::Capability::View))
        {
            continue;
        }
        let muted = sqlx::query_scalar(
            "SELECT COALESCE((SELECT muted FROM message_preferences WHERE subject_account_id=? AND message_id=?),0)",
        )
        .bind(recipient_account_id)
        .bind(&message_id)
        .fetch_one(db.write_pool())
        .await?;
        candidates.push(HostNotificationCandidate {
            candidate_id: row.try_get("candidate_id")?,
            reason: row.try_get("reason")?,
            priority: row.try_get("priority")?,
            redaction_class: row.try_get("redaction_class")?,
            evaluator_kind: row.try_get("evaluator_kind")?,
            policy_version: row.try_get("policy_version")?,
            muted,
        });
    }
    Ok(HostNotificationHarvest {
        scanned_through,
        candidates,
    })
}

/// Revalidate one portable candidate for a hosted delivery attempt.
/// `recipient_is_member` is the recipient's live catalog footing; see
/// [`harvest_host_notification_candidates`].
#[doc(hidden)]
pub async fn revalidate_host_notification_candidate(
    db: &crate::Db,
    candidate_id: &str,
    recipient_account_id: &str,
    recipient_is_member: bool,
) -> Result<Option<HostNotificationRevalidation>> {
    let candidate = sqlx::query(
        "SELECT message_id,not_before,status,priority,evaluator_kind,policy_version FROM notification_candidates WHERE candidate_id=? AND recipient_account_id=?",
    )
    .bind(candidate_id)
    .bind(recipient_account_id)
    .fetch_optional(db.write_pool())
    .await?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let message_id: String = candidate.try_get("message_id")?;
    let access = crate::authorization::effective_capability_in_pool(
        db.write_pool(),
        crate::authorization::Principal::bound(recipient_account_id, recipient_is_member),
        &message_id,
    )
    .await;
    let muted: bool = sqlx::query_scalar(
        "SELECT COALESCE((SELECT muted FROM message_preferences WHERE subject_account_id=? AND message_id=?),0)",
    )
    .bind(recipient_account_id)
    .bind(&message_id)
    .fetch_one(db.write_pool())
    .await?;
    let not_before = candidate.try_get("not_before")?;
    let priority = candidate.try_get("priority")?;
    let evaluator_kind = candidate.try_get("evaluator_kind")?;
    let policy_version = candidate.try_get("policy_version")?;
    let effective_viewable_unmuted = candidate.try_get::<String, _>("status")? == "effective"
        && access.is_ok_and(|capability| capability.allows(crate::authorization::Capability::View))
        && !muted;
    Ok(Some(HostNotificationRevalidation {
        message_id,
        not_before,
        priority,
        evaluator_kind,
        policy_version,
        effective_viewable_unmuted,
    }))
}

/// Resolve a candidate's Message after send revalidation. Keeping this lookup
/// separate preserves the digest renderer's existing post-revalidation race
/// behavior and error surface.
#[doc(hidden)]
pub async fn host_notification_candidate_message_id(
    db: &crate::Db,
    candidate_id: &str,
) -> Result<String> {
    Ok(
        sqlx::query_scalar("SELECT message_id FROM notification_candidates WHERE candidate_id=?")
            .bind(candidate_id)
            .fetch_one(db.write_pool())
            .await?,
    )
}

/// Timestamp shape shared by portable events and hosted notification custody.
#[doc(hidden)]
pub fn host_notification_timestamp() -> String {
    now_iso()
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HumanStage {
    Unsurfaced,
    Presented,
    Opened,
    Acknowledged,
}

impl HumanStage {
    fn rank(self) -> u8 {
        match self {
            Self::Unsurfaced => 0,
            Self::Presented => 1,
            Self::Opened => 2,
            Self::Acknowledged => 3,
        }
    }

    fn stored(self) -> Option<&'static str> {
        match self {
            Self::Unsurfaced => None,
            Self::Presented => Some("presented"),
            Self::Opened => Some("opened"),
            Self::Acknowledged => Some("acknowledged"),
        }
    }

    fn parse(value: Option<&str>) -> Result<Self> {
        match value {
            None => Ok(Self::Unsurfaced),
            Some("presented") => Ok(Self::Presented),
            Some("opened") => Ok(Self::Opened),
            Some("acknowledged") => Ok(Self::Acknowledged),
            Some(other) => Err(Error::engine(format!(
                "invalid projected human awareness stage '{other}'"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedHumanInteraction {
    /// Opaque, host-verified nonce. It never comes from manage_messages args.
    pub nonce: String,
    /// Host-established UI/client action issuer.
    pub executor_ref: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAgentExecutor {
    pub executor_ref: String,
    pub delegation_ref: String,
}

#[derive(Clone)]
pub struct HumanInteractionTokenIssuer {
    key: [u8; 32],
    issuer_ref: String,
}

#[derive(Serialize, Deserialize)]
struct HumanInteractionClaims {
    account: String,
    action: String,
    message_digest: String,
    nonce: String,
    expires_at: i64,
}

impl HumanInteractionTokenIssuer {
    pub fn random(issuer_ref: impl Into<String>) -> Self {
        use rand::RngCore;
        let mut key = [0; 32];
        rand::rng().fill_bytes(&mut key);
        Self {
            key,
            issuer_ref: issuer_ref.into(),
        }
    }
    fn message_digest(message_ids: &[String]) -> String {
        let mut ids = message_ids.to_vec();
        ids.sort();
        let mut hash = Sha256::new();
        for id in ids {
            hash.update(id.as_bytes());
            hash.update([0]);
        }
        hex::encode(hash.finalize())
    }
    pub fn issue(
        &self,
        account: &str,
        action: &str,
        message_ids: &[String],
        ttl_seconds: i64,
    ) -> Result<String> {
        if account.is_empty()
            || action.is_empty()
            || message_ids.is_empty()
            || !(1..=300).contains(&ttl_seconds)
        {
            return Err(Error::engine("invalid human interaction token request"));
        }
        let claims = HumanInteractionClaims {
            account: account.into(),
            action: action.into(),
            message_digest: Self::message_digest(message_ids),
            nonce: Uuid::new_v4().to_string(),
            expires_at: chrono::Utc::now().timestamp() + ttl_seconds,
        };
        let body =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key");
        mac.update(body.as_bytes());
        Ok(format!(
            "{body}.{}",
            hex::encode(mac.finalize().into_bytes())
        ))
    }
    pub fn verify(
        &self,
        token: &str,
        account: &str,
        action: &str,
        message_ids: &[String],
    ) -> Result<VerifiedHumanInteraction> {
        let (body, signature) = token
            .split_once('.')
            .ok_or_else(|| Error::engine("invalid human interaction attestation"))?;
        let signature = hex::decode(signature)
            .map_err(|_| Error::engine("invalid human interaction attestation"))?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key");
        mac.update(body.as_bytes());
        mac.verify_slice(&signature)
            .map_err(|_| Error::engine("invalid human interaction attestation"))?;
        let claims: HumanInteractionClaims = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| Error::engine("invalid human interaction attestation"))?,
        )?;
        if claims.account != account
            || claims.action != action
            || claims.message_digest != Self::message_digest(message_ids)
            || claims.expires_at < chrono::Utc::now().timestamp()
        {
            return Err(Error::engine(
                "human interaction attestation binding mismatch or expired",
            ));
        }
        Ok(VerifiedHumanInteraction {
            nonce: claims.nonce,
            executor_ref: self.issuer_ref.clone(),
        })
    }

    pub(crate) fn verify_for_provenance(
        &self,
        token: &str,
        account: &str,
        action: &str,
        message_ids: &[String],
    ) -> Result<(
        VerifiedHumanInteraction,
        crate::provenance::VerifiedInteractionEvidence,
    )> {
        let verified = self.verify(token, account, action, message_ids)?;
        let (body, _) = token
            .split_once('.')
            .ok_or_else(|| Error::engine("invalid human interaction attestation"))?;
        let claims: HumanInteractionClaims = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| Error::engine("invalid human interaction attestation"))?,
        )?;
        let scope_digest = crate::canonical_json::digest_json(&serde_json::json!({
            "action": claims.action,
            "message_digest": claims.message_digest,
        }));
        let evidence_digest = hex::encode(Sha256::digest(body.as_bytes()));
        let mut receipt_bytes = [0_u8; 16];
        receipt_bytes.copy_from_slice(
            &Sha256::digest(
                format!("{}:{}:{}", self.issuer_ref, claims.nonce, evidence_digest).as_bytes(),
            )[..16],
        );
        receipt_bytes[6] = (receipt_bytes[6] & 0x0f) | 0x50;
        receipt_bytes[8] = (receipt_bytes[8] & 0x3f) | 0x80;
        let evidence = crate::provenance::VerifiedInteractionEvidence {
            receipt_id: Uuid::from_bytes(receipt_bytes).to_string(),
            principal: account.to_string(),
            scope_digest,
            nonce: claims.nonce,
            verifier: self.issuer_ref.clone(),
            verified_at: crate::store::now_iso(),
            evidence_digest,
            sealed_evidence_ref: None,
            retention_class: Some("digest".into()),
            accepted_action_digest: None,
        };
        Ok((verified, evidence))
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceInput {
    pub record_id: String,
    pub role: String,
}

#[derive(Clone, Debug)]
pub struct MutationContext<'a> {
    pub subject_account_id: &'a str,
    pub authenticated_actor: &'a str,
    pub executor_kind: &'a str,
    pub executor_ref: Option<&'a str>,
    pub delegation_ref: Option<&'a str>,
    pub reason_code: &'a str,
}

/// Which subject one awareness event is about. The tier keys its four Message
/// lanes on a `message_id` and its destination lane on a `collection_id`; the
/// log column and the intent digest both follow from this one choice, so no
/// lane can silently borrow another's subject column.
#[derive(Clone, Copy, Debug)]
enum Subject<'a> {
    Message(&'a str),
    Destination(&'a str),
}

impl<'a> Subject<'a> {
    fn message_id(self) -> Option<&'a str> {
        match self {
            Self::Message(id) => Some(id),
            Self::Destination(_) => None,
        }
    }

    fn destination_id(self) -> Option<&'a str> {
        match self {
            Self::Destination(id) => Some(id),
            Self::Message(_) => None,
        }
    }

    /// The intent digest names the subject by its own field. Message lanes keep
    /// the exact `{"message_id":...}` shape they have always hashed, so no
    /// existing idempotency key changes meaning.
    fn intent_field(self) -> &'static str {
        match self {
            Self::Message(_) => "message_id",
            Self::Destination(_) => "destination_id",
        }
    }

    fn id(self) -> &'a str {
        match self {
            Self::Message(id) | Self::Destination(id) => id,
        }
    }
}

#[derive(Debug)]
struct ExistingEvent {
    id: String,
    seq: i64,
    intent_sha256: String,
    expected_version: i64,
    payload: Value,
    created_at: String,
    act: Option<i64>,
}

fn sha256_json(value: &Value) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

async fn existing_idempotency(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    account: &str,
    key: &str,
) -> Result<Option<ExistingEvent>> {
    let row = sqlx::query(
        "SELECT id,seq,intent_sha256,expected_version,payload,created_at,act FROM awareness_events
          WHERE subject_account_id=? AND idempotency_key=?",
    )
    .bind(account)
    .bind(key)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        Ok(ExistingEvent {
            id: row.try_get("id")?,
            seq: row.try_get("seq")?,
            intent_sha256: row.try_get("intent_sha256")?,
            expected_version: row.try_get("expected_version")?,
            payload: serde_json::from_str(&row.try_get::<String, _>("payload")?)?,
            created_at: row.try_get("created_at")?,
            act: row.try_get("act")?,
        })
    })
    .transpose()
}

#[allow(clippy::too_many_arguments)]
async fn exact_retry(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    account: &str,
    key: &str,
    subject: Subject<'_>,
    lane: &str,
    action: &str,
    expected_version: i64,
    payload: &Value,
) -> Result<Option<ExistingEvent>> {
    let intent = json!({subject.intent_field():subject.id(),"lane":lane,"action":action,"expected_version":expected_version,"payload":payload});
    let expected = sha256_json(&intent)?;
    if let Some(existing) = existing_idempotency(tx, account, key).await? {
        if existing.intent_sha256 != expected {
            return Err(Error::engine(
                "awareness idempotency key was already used for different intent",
            ));
        }
        return Ok(Some(existing));
    }
    Ok(None)
}

/// One decoded `awareness_events` row. This is the typed seam shared by the
/// live lane writers and `rebuild_projections`: the live path builds one from
/// the values it is about to insert, the repair path decodes one from the log,
/// and both hand it to [`project_awareness_event`]. `seq`/`act` are carried
/// verbatim but never re-derived by the fold; `payload` is decoded once here so
/// the fold never parses text.
#[derive(Clone, Debug)]
pub(crate) struct AwarenessEventRow {
    pub seq: i64,
    pub id: String,
    pub subject_account_id: String,
    pub message_id: Option<String>,
    pub destination_id: Option<String>,
    pub lane: String,
    /// Carried verbatim from the canonical envelope. The fold is lane- and
    /// payload-driven, so the action is not read here; the row is the one
    /// decoder the act-range seam will reuse.
    #[allow(dead_code)]
    pub action: String,
    pub reason_code: String,
    pub executor_ref: Option<String>,
    pub delegation_ref: Option<String>,
    pub payload: Value,
    pub created_at: String,
    /// The act-range coordinate. Retained so the bounded fold can select and
    /// carry stamped rows; the repair fold never re-derives it.
    #[allow(dead_code)]
    pub act: Option<i64>,
}

fn awareness_row_from_sql(row: sqlx::sqlite::SqliteRow) -> Result<AwarenessEventRow> {
    let payload: String = row.try_get("payload")?;
    Ok(AwarenessEventRow {
        seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        subject_account_id: row.try_get("subject_account_id")?,
        message_id: row.try_get("message_id")?,
        destination_id: row.try_get("destination_id")?,
        lane: row.try_get("lane")?,
        action: row.try_get("action")?,
        reason_code: row.try_get("reason_code")?,
        executor_ref: row.try_get("executor_ref")?,
        delegation_ref: row.try_get("delegation_ref")?,
        payload: serde_json::from_str(&payload)?,
        created_at: row.try_get("created_at")?,
        act: row.try_get("act")?,
    })
}

/// The whole awareness log in `seq` order — the input to the awareness half of
/// the projection rebuild.
pub(crate) async fn read_all_awareness_events(
    conn: &mut SqliteConnection,
) -> Result<Vec<AwarenessEventRow>> {
    sqlx::query(
        "SELECT seq,id,subject_account_id,message_id,destination_id,lane,action,reason_code,
                executor_ref,delegation_ref,payload,created_at,act
           FROM awareness_events ORDER BY seq",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(awareness_row_from_sql)
    .collect()
}

/// The awareness-only act-range reader: exactly the rows whose `act` falls in
/// the half-open interval `(from_exclusive, to_inclusive]`, in `seq` order,
/// decoded by the same [`awareness_row_from_sql`] the full reader uses. Legacy
/// rows whose act is `NULL` never satisfy the strict `act > ?` predicate and
/// are excluded.
#[allow(dead_code)] // R3 wires the bounded fold; the reader lands ahead of its caller.
pub(crate) async fn awareness_events_in_act_range(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Vec<AwarenessEventRow>> {
    sqlx::query(
        "SELECT seq,id,subject_account_id,message_id,destination_id,lane,action,reason_code,
                executor_ref,delegation_ref,payload,created_at,act
           FROM awareness_events WHERE act > ? AND act <= ? ORDER BY seq",
    )
    .bind(from_exclusive_act)
    .bind(to_inclusive_act)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(awareness_row_from_sql)
    .collect()
}

#[allow(clippy::too_many_arguments)]
async fn append_event(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    subject: Subject<'_>,
    lane: &str,
    action: &str,
    expected_version: i64,
    idempotency_key: &str,
    interaction_nonce: Option<&str>,
    intent_payload: Option<&Value>,
    payload: &Value,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<(AwarenessEventRow, bool)> {
    let intent = json!({
        subject.intent_field(): subject.id(),
        "lane": lane,
        "action": action,
        "expected_version": expected_version,
        "payload": intent_payload.unwrap_or(payload),
    });
    let intent_sha256 = sha256_json(&intent)?;
    if let Some(existing) =
        existing_idempotency(tx, context.subject_account_id, idempotency_key).await?
    {
        if existing.intent_sha256 != intent_sha256 {
            return Err(Error::engine(
                "awareness idempotency key was already used for different intent",
            ));
        }
        // An exact retry never projects: the existing event and its projection
        // already agree, so the reconstructed row exists only to keep the seam
        // total for readers.
        return Ok((
            AwarenessEventRow {
                seq: existing.seq,
                id: existing.id,
                subject_account_id: context.subject_account_id.to_string(),
                message_id: subject.message_id().map(str::to_owned),
                destination_id: subject.destination_id().map(str::to_owned),
                lane: lane.to_string(),
                action: action.to_string(),
                reason_code: context.reason_code.to_string(),
                executor_ref: context.executor_ref.map(str::to_owned),
                delegation_ref: context.delegation_ref.map(str::to_owned),
                payload: existing.payload,
                created_at: existing.created_at,
                act: existing.act,
            },
            false,
        ));
    }
    let id = Uuid::new_v4().to_string();
    let created_at = now_iso();
    let act = act_alloc.get_or_allocate(&mut *tx).await?;
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO awareness_events
           (id,idempotency_key,intent_sha256,schema_version,subject_account_id,message_id,
            destination_id,lane,action,authenticated_actor,executor_kind,executor_ref,
            delegation_ref,expected_version,reason_code,interaction_nonce,payload,created_at,act)
         VALUES (?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq",
    )
    .bind(&id)
    .bind(idempotency_key)
    .bind(intent_sha256)
    .bind(context.subject_account_id)
    .bind(subject.message_id())
    .bind(subject.destination_id())
    .bind(lane)
    .bind(action)
    .bind(context.authenticated_actor)
    .bind(context.executor_kind)
    .bind(context.executor_ref)
    .bind(context.delegation_ref)
    .bind(expected_version)
    .bind(context.reason_code)
    .bind(interaction_nonce)
    .bind(serde_json::to_string(payload)?)
    .bind(&created_at)
    .bind(act)
    .fetch_one(&mut **tx)
    .await?;
    Ok((
        AwarenessEventRow {
            seq,
            id,
            subject_account_id: context.subject_account_id.to_string(),
            message_id: subject.message_id().map(str::to_owned),
            destination_id: subject.destination_id().map(str::to_owned),
            lane: lane.to_string(),
            action: action.to_string(),
            reason_code: context.reason_code.to_string(),
            executor_ref: context.executor_ref.map(str::to_owned),
            delegation_ref: context.delegation_ref.map(str::to_owned),
            payload: payload.clone(),
            created_at,
            act: Some(act),
        },
        true,
    ))
}

/// The `message_id` of one of the four Message lanes. The DDL's paired CHECKs
/// mean exactly one subject column is present, so the destination lane never
/// reaches here and a Message lane's subject is never borrowed from a
/// destination. The default matches the historical replay reader byte for byte.
fn message_subject(event: &AwarenessEventRow) -> String {
    event.message_id.clone().unwrap_or_default()
}

/// Fold one awareness event into its single lane projection. This is the only
/// writer of the awareness projection tables: each live lane writer calls it
/// once after a newly inserted event, and `rebuild_projections` calls it in
/// `seq` order over the whole retained log. It allocates no act and performs no
/// cross-lane fanout — the caller owns both, so a rebuild cannot re-emit the
/// candidate events the candidate log already carries.
pub(crate) async fn project_awareness_event(
    conn: &mut SqliteConnection,
    event: &AwarenessEventRow,
) -> Result<()> {
    let account = event.subject_account_id.as_str();
    let seq = event.seq;
    let payload = &event.payload;
    match event.lane.as_str() {
        "human" => {
            let message = message_subject(event);
            let stage = payload["stage"]
                .as_str()
                .ok_or_else(|| Error::engine("invalid human replay payload"))?;
            let now = payload["attained_at"]
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| event.created_at.clone());
            let current: Option<(String, i64, Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT stage,version,opened_at,acknowledged_at FROM human_message_awareness
                  WHERE subject_account_id=? AND message_id=?",
            )
            .bind(account)
            .bind(&message)
            .fetch_optional(&mut *conn)
            .await?;
            let current_stage = HumanStage::parse(current.as_ref().map(|v| v.0.as_str()))?;
            let requested = HumanStage::parse(Some(stage))?;
            let next = if requested.rank() > current_stage.rank() {
                requested
            } else {
                current_stage
            };
            let version = current.as_ref().map_or(1, |v| v.1 + 1);
            let opened_at = current
                .as_ref()
                .and_then(|value| value.2.clone())
                .or_else(|| (requested.rank() >= HumanStage::Opened.rank()).then(|| now.clone()));
            let acknowledged_at =
                current
                    .as_ref()
                    .and_then(|value| value.3.clone())
                    .or_else(|| {
                        (requested.rank() >= HumanStage::Acknowledged.rank()).then(|| now.clone())
                    });
            sqlx::query("INSERT INTO human_message_awareness(subject_account_id,message_id,stage,first_presented_at,last_presented_at,opened_at,acknowledged_at,last_event_seq,version) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(subject_account_id,message_id) DO UPDATE SET stage=excluded.stage,last_presented_at=excluded.last_presented_at,opened_at=excluded.opened_at,acknowledged_at=excluded.acknowledged_at,last_event_seq=excluded.last_event_seq,version=excluded.version")
                .bind(account)
                .bind(&message)
                .bind(next.stored())
                .bind(&now)
                .bind(&now)
                .bind(opened_at)
                .bind(acknowledged_at)
                .bind(seq)
                .bind(version)
                .execute(&mut *conn)
                .await?;
        }
        "agent" => {
            let message = message_subject(event);
            let state = payload["state"]
                .as_str()
                .ok_or_else(|| Error::engine("invalid agent replay payload"))?;
            let version: i64 = sqlx::query_scalar(
                "SELECT version FROM agent_message_dispositions
                  WHERE subject_account_id=? AND message_id=?",
            )
            .bind(account)
            .bind(&message)
            .fetch_optional(&mut *conn)
            .await?
            .unwrap_or(0)
                + 1;
            sqlx::query("INSERT INTO agent_message_dispositions(subject_account_id,message_id,state,reason_code,last_executor_ref,delegation_ref,last_event_seq,version) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(subject_account_id,message_id) DO UPDATE SET state=excluded.state,reason_code=excluded.reason_code,last_executor_ref=excluded.last_executor_ref,delegation_ref=excluded.delegation_ref,last_event_seq=excluded.last_event_seq,version=excluded.version")
                .bind(account)
                .bind(&message)
                .bind(state)
                .bind(&event.reason_code)
                .bind(event.executor_ref.as_deref())
                .bind(event.delegation_ref.as_deref())
                .bind(seq)
                .bind(version)
                .execute(&mut *conn)
                .await?;
            for evidence in payload["evidence"].as_array().into_iter().flatten() {
                sqlx::query("INSERT INTO awareness_event_evidence(event_id,evidence_record_id,evidence_role) VALUES(?,?,?)")
                    .bind(&event.id)
                    .bind(evidence["record_id"].as_str())
                    .bind(evidence["role"].as_str())
                    .execute(&mut *conn)
                    .await?;
            }
        }
        "preference" => {
            let message = message_subject(event);
            let version: i64 = sqlx::query_scalar(
                "SELECT version FROM message_preferences
                  WHERE subject_account_id=? AND message_id=?",
            )
            .bind(account)
            .bind(&message)
            .fetch_optional(&mut *conn)
            .await?
            .unwrap_or(0)
                + 1;
            sqlx::query("INSERT INTO message_preferences(subject_account_id,message_id,attention_flag,muted,snoozed_until,archived,last_event_seq,version) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(subject_account_id,message_id) DO UPDATE SET attention_flag=excluded.attention_flag,muted=excluded.muted,snoozed_until=excluded.snoozed_until,archived=excluded.archived,last_event_seq=excluded.last_event_seq,version=excluded.version")
                .bind(account)
                .bind(&message)
                .bind(payload["attention_flag"].as_bool())
                .bind(payload["muted"].as_bool())
                .bind(payload["snoozed_until"].as_str())
                .bind(payload["archived"].as_bool())
                .bind(seq)
                .bind(version)
                .execute(&mut *conn)
                .await?;
        }
        "routing" => {
            let message = message_subject(event);
            let version: i64 = sqlx::query_scalar(
                "SELECT version FROM message_inbox_routing
                  WHERE subject_account_id=? AND message_id=?",
            )
            .bind(account)
            .bind(&message)
            .fetch_optional(&mut *conn)
            .await?
            .unwrap_or(0)
                + 1;
            sqlx::query("INSERT INTO message_inbox_routing(subject_account_id,message_id,obligation_state,executor_route,reason_code,policy_version,last_event_seq,version) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(subject_account_id,message_id) DO UPDATE SET obligation_state=excluded.obligation_state,executor_route=excluded.executor_route,reason_code=excluded.reason_code,policy_version=excluded.policy_version,last_event_seq=excluded.last_event_seq,version=excluded.version")
                .bind(account)
                .bind(&message)
                .bind(payload["obligation_state"].as_str())
                .bind(payload["executor_route"].as_str())
                .bind(&event.reason_code)
                .bind(payload["policy_version"].as_str())
                .bind(seq)
                .bind(version)
                .execute(&mut *conn)
                .await?;
        }
        "destination" => {
            let collection = event
                .destination_id
                .clone()
                .ok_or_else(|| Error::engine("destination event without a destination_id"))?;
            let version: i64 = sqlx::query_scalar(
                "SELECT version FROM member_destinations
                  WHERE subject_account_id=? AND collection_id=?",
            )
            .bind(account)
            .bind(&collection)
            .fetch_optional(&mut *conn)
            .await?
            .unwrap_or(0)
                + 1;
            sqlx::query("INSERT INTO member_destinations(subject_account_id,collection_id,present,joined_at,joined_by,last_event_seq,version) VALUES(?,?,?,?,?,?,?) ON CONFLICT(subject_account_id,collection_id) DO UPDATE SET present=excluded.present,joined_at=excluded.joined_at,joined_by=excluded.joined_by,last_event_seq=excluded.last_event_seq,version=excluded.version")
                .bind(account)
                .bind(&collection)
                .bind(payload["present"].as_bool())
                .bind(payload["joined_at"].as_str())
                .bind(payload["joined_by"].as_str())
                .bind(seq)
                .bind(version)
                .execute(&mut *conn)
                .await?;
        }
        _ => return Err(Error::engine("unknown awareness replay lane")),
    }
    Ok(())
}

/// Fold every awareness event in order through [`project_awareness_event`].
pub(crate) async fn replay_awareness(
    conn: &mut SqliteConnection,
    events: &[AwarenessEventRow],
) -> Result<()> {
    for event in events {
        project_awareness_event(conn, event).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn advance_human(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    account: &str,
    message_id: &str,
    stage: HumanStage,
    expected_version: i64,
    idempotency_key: &str,
    attestation: &VerifiedHumanInteraction,
    reason_code: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<Value> {
    if stage == HumanStage::Unsurfaced {
        return Err(Error::engine(
            "human awareness cannot regress to unsurfaced",
        ));
    }
    if attestation.nonce.trim().is_empty() || attestation.executor_ref.trim().is_empty() {
        return Err(Error::engine("verified human interaction is malformed"));
    }
    let intent_payload = json!({"stage":stage,"interaction_attested":true});
    if let Some(existing) = exact_retry(
        tx,
        account,
        idempotency_key,
        Subject::Message(message_id),
        "human",
        stage.stored().expect("non-default stage"),
        expected_version,
        &intent_payload,
    )
    .await?
    {
        let stage = HumanStage::parse(existing.payload.get("stage").and_then(Value::as_str))?;
        return Ok(
            json!({"message_id":message_id,"stage":stage,"version":existing.expected_version+1,"changed":false,"idempotent":true}),
        );
    }
    let row = sqlx::query(
        "SELECT stage,version,first_presented_at,last_presented_at,opened_at,acknowledged_at
           FROM human_message_awareness WHERE subject_account_id=? AND message_id=?",
    )
    .bind(account)
    .bind(message_id)
    .fetch_optional(&mut **tx)
    .await?;
    let current_stage = HumanStage::parse(
        row.as_ref()
            .map(|row| row.get::<String, _>("stage"))
            .as_deref(),
    )?;
    let current_version = row
        .as_ref()
        .map(|row| row.get::<i64, _>("version"))
        .unwrap_or(0);
    if current_version != expected_version {
        return Err(Error::engine(format!(
            "awareness version conflict: expected {expected_version}, current {current_version}"
        )));
    }
    let context = MutationContext {
        subject_account_id: account,
        authenticated_actor: account,
        executor_kind: "human_attested",
        executor_ref: Some(&attestation.executor_ref),
        delegation_ref: None,
        reason_code,
    };
    let next = if stage.rank() > current_stage.rank() {
        stage
    } else {
        current_stage
    };
    let attained_at = now_iso();
    let payload = json!({
        "stage": next,
        "interaction_attested": true,
        "attained_at": attained_at.clone(),
    });
    let (event, inserted) = append_event(
        tx,
        &context,
        Subject::Message(message_id),
        "human",
        stage.stored().expect("non-default stage"),
        expected_version,
        idempotency_key,
        Some(&attestation.nonce),
        Some(&intent_payload),
        &payload,
        act_alloc,
    )
    .await?;
    if !inserted {
        return Ok(
            json!({"message_id":message_id,"stage":current_stage,"version":current_version,"changed":false,"idempotent":true}),
        );
    }
    project_awareness_event(&mut *tx, &event).await?;
    let next_version = current_version + 1;
    if next.rank() >= HumanStage::Opened.rank() {
        withdraw_notification_candidates_in(
            tx,
            account,
            message_id,
            None,
            "awareness.human.opened",
            &event.id,
            act_alloc,
        )
        .await?;
    }
    Ok(
        json!({"message_id":message_id,"stage":next,"version":next_version,"changed":true,"idempotent":false}),
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn register_human_batch_command(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    account: &str,
    stage: HumanStage,
    message_ids: &[String],
    expected_versions: &std::collections::BTreeMap<String, i64>,
    idempotency_key: &str,
    snapshot: Option<&str>,
    _attestation: &VerifiedHumanInteraction,
    _reason_code: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<bool> {
    let payload = json!({
        "stage": stage,
        "exact_message_ids": message_ids,
        "expected_versions": expected_versions,
        "snapshot": snapshot,
    });
    let intent = json!({"action": stage.stored().unwrap_or("unsurfaced"), "payload": payload});
    let digest = sha256_json(&intent)?;
    if let Some(existing) = sqlx::query_scalar::<_, String>(
        "SELECT intent_sha256 FROM awareness_command_intents
          WHERE subject_account_id=? AND idempotency_key=?",
    )
    .bind(account)
    .bind(idempotency_key)
    .fetch_optional(&mut **tx)
    .await?
    {
        if existing != digest {
            return Err(Error::engine(
                "awareness idempotency key was already used for different intent",
            ));
        }
        return Ok(false);
    }
    // Allocate only for a genuinely new intent, immediately before INSERT.
    // Exact retries return above without allocating; a first-time batch —
    // even an empty one — allocates a visible act of its own when the
    // transaction has not yet stamped one, and otherwise shares the
    // transaction's act with the awareness events that follow.
    let act = act_alloc.get_or_allocate(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO awareness_command_intents
           (subject_account_id,idempotency_key,intent_sha256,created_at,act)
         VALUES (?,?,?,?,?)",
    )
    .bind(account)
    .bind(idempotency_key)
    .bind(digest)
    .bind(now_iso())
    .bind(act)
    .execute(&mut **tx)
    .await?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
pub async fn set_agent_disposition(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    message_id: &str,
    state: &str,
    expected_version: i64,
    idempotency_key: &str,
    evidence: &[EvidenceInput],
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<Value> {
    if !matches!(
        state,
        "triaged" | "deferred" | "escalated" | "acted" | "resolved"
    ) {
        return Err(Error::engine("invalid agent disposition state"));
    }
    if context.executor_kind != "agent" {
        return Err(Error::engine(
            "agent disposition requires agent executor context",
        ));
    }
    if matches!(state, "acted" | "resolved") && evidence.is_empty() {
        return Err(Error::engine(
            "acted/resolved agent disposition requires exact evidence",
        ));
    }
    let payload = json!({"state":state,"evidence":evidence.iter().map(|e|json!({"record_id":e.record_id,"role":e.role})).collect::<Vec<_>>()});
    if let Some(existing) = exact_retry(
        tx,
        context.subject_account_id,
        idempotency_key,
        Subject::Message(message_id),
        "agent",
        state,
        expected_version,
        &payload,
    )
    .await?
    {
        return Ok(
            json!({"message_id":message_id,"state":existing.payload["state"],"version":existing.expected_version+1,"changed":false,"idempotent":true}),
        );
    }
    let current_version: i64 = sqlx::query_scalar(
        "SELECT version FROM agent_message_dispositions
          WHERE subject_account_id=? AND message_id=?",
    )
    .bind(context.subject_account_id)
    .bind(message_id)
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or(0);
    if current_version != expected_version {
        return Err(Error::engine(format!(
            "agent disposition version conflict: expected {expected_version}, current {current_version}"
        )));
    }
    let (event, inserted) = append_event(
        tx,
        context,
        Subject::Message(message_id),
        "agent",
        state,
        expected_version,
        idempotency_key,
        None,
        None,
        &payload,
        act_alloc,
    )
    .await?;
    if !inserted {
        return Ok(
            json!({"message_id":message_id,"state":state,"version":current_version,"changed":false,"idempotent":true}),
        );
    }
    // The fold inserts the evidence rows from the payload; validating here keeps
    // the named refusal ahead of the schema CHECK.
    for item in evidence {
        if !matches!(
            item.role.as_str(),
            "reply" | "work" | "decision" | "resolution" | "other"
        ) {
            return Err(Error::engine("invalid awareness evidence role"));
        }
    }
    project_awareness_event(&mut *tx, &event).await?;
    let next_version = current_version + 1;
    Ok(
        json!({"message_id":message_id,"state":state,"version":next_version,"changed":true,"idempotent":false}),
    )
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreferenceAction {
    FlagAttention,
    ClearAttention,
    Mute,
    Unmute,
    Snooze,
    ClearSnooze,
    Archive,
    Restore,
}

impl PreferenceAction {
    fn name(&self) -> &'static str {
        match self {
            Self::FlagAttention => "attention.flagged",
            Self::ClearAttention => "attention.cleared",
            Self::Mute => "mute.set",
            Self::Unmute => "mute.cleared",
            Self::Snooze => "snooze.set",
            Self::ClearSnooze => "snooze.cleared",
            Self::Archive => "archive.set",
            Self::Restore => "archive.cleared",
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn set_preference(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    account: &str,
    message_id: &str,
    action: PreferenceAction,
    snoozed_until: Option<&str>,
    expected_version: i64,
    idempotency_key: &str,
    reason_code: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<Value> {
    if matches!(action, PreferenceAction::Snooze) {
        let value = snoozed_until.ok_or_else(|| Error::engine("snooze requires snoozed_until"))?;
        chrono::DateTime::parse_from_rfc3339(value)
            .map_err(|_| Error::engine("snoozed_until must be RFC3339"))?;
    } else if snoozed_until.is_some() {
        return Err(Error::engine("snoozed_until is only valid for snooze"));
    }
    // Build the intended post-state after reading the current row, but honor
    // an exact retry before comparing the stale expected version.
    let row = sqlx::query(
        "SELECT attention_flag,muted,snoozed_until,archived,version FROM message_preferences
          WHERE subject_account_id=? AND message_id=?",
    )
    .bind(account)
    .bind(message_id)
    .fetch_optional(&mut **tx)
    .await?;
    let current_version = row
        .as_ref()
        .map(|r| r.get::<i64, _>("version"))
        .unwrap_or(0);
    let mut attention = row
        .as_ref()
        .is_some_and(|r| r.get::<i64, _>("attention_flag") != 0);
    let mut muted = row.as_ref().is_some_and(|r| r.get::<i64, _>("muted") != 0);
    let mut snooze = row
        .as_ref()
        .and_then(|r| r.get::<Option<String>, _>("snoozed_until"));
    let mut archived = row
        .as_ref()
        .is_some_and(|r| r.get::<i64, _>("archived") != 0);
    match action {
        PreferenceAction::FlagAttention => attention = true,
        PreferenceAction::ClearAttention => attention = false,
        PreferenceAction::Mute => muted = true,
        PreferenceAction::Unmute => muted = false,
        PreferenceAction::Snooze => snooze = snoozed_until.map(str::to_owned),
        PreferenceAction::ClearSnooze => snooze = None,
        PreferenceAction::Archive => {
            let open_human: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM message_inbox_routing
                  WHERE subject_account_id=? AND message_id=? AND obligation_state='open'
                    AND executor_route='human')",
            )
            .bind(account)
            .bind(message_id)
            .fetch_one(&mut **tx)
            .await?;
            if open_human {
                return Err(Error::engine(
                    "cannot archive an open human-routed obligation",
                ));
            }
            archived = true;
        }
        PreferenceAction::Restore => archived = false,
    }
    let command_payload = json!({"snoozed_until":snoozed_until});
    let payload = json!({"attention_flag":attention,"muted":muted,"snoozed_until":snooze,"archived":archived});
    if let Some(existing) = exact_retry(
        tx,
        account,
        idempotency_key,
        Subject::Message(message_id),
        "preference",
        action.name(),
        expected_version,
        &command_payload,
    )
    .await?
    {
        return Ok(
            json!({"message_id":message_id,"version":existing.expected_version+1,"changed":false,"idempotent":true,"attention_flag":existing.payload["attention_flag"],"muted":existing.payload["muted"],"snoozed_until":existing.payload["snoozed_until"],"archived":existing.payload["archived"]}),
        );
    }
    if current_version != expected_version {
        return Err(Error::engine(format!(
            "preference version conflict: expected {expected_version}, current {current_version}"
        )));
    }
    let context = MutationContext {
        subject_account_id: account,
        authenticated_actor: account,
        executor_kind: "system",
        executor_ref: None,
        delegation_ref: None,
        reason_code,
    };
    let (event, inserted) = append_event(
        tx,
        &context,
        Subject::Message(message_id),
        "preference",
        action.name(),
        expected_version,
        idempotency_key,
        None,
        Some(&command_payload),
        &payload,
        act_alloc,
    )
    .await?;
    if !inserted {
        return Ok(
            json!({"message_id":message_id,"version":current_version,"changed":false,"idempotent":true}),
        );
    }
    project_awareness_event(&mut *tx, &event).await?;
    let next_version = current_version + 1;
    if matches!(
        action,
        PreferenceAction::Snooze | PreferenceAction::ClearSnooze
    ) {
        let withdrawn_reason =
            matches!(action, PreferenceAction::ClearSnooze).then_some("snooze_due");
        withdraw_notification_candidates_in(
            tx,
            account,
            message_id,
            withdrawn_reason,
            "awareness.preference.changed",
            &event.id,
            act_alloc,
        )
        .await?;
        if matches!(action, PreferenceAction::Snooze) {
            append_notification_candidate_in(
                tx,
                account,
                message_id,
                "snooze_due",
                "routine",
                snooze.as_deref(),
                "metadata_only",
                "recipient_policy",
                "explicit-snooze-v1",
                "awareness.snooze.set",
                &event.id,
                act_alloc,
            )
            .await?;
        }
    }
    Ok(
        json!({"message_id":message_id,"version":next_version,"changed":true,"attention_flag":attention,"muted":muted,"snoozed_until":snooze,"archived":archived}),
    )
}

#[allow(clippy::too_many_arguments)]
pub async fn set_routing(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    message_id: &str,
    obligation_state: &str,
    executor_route: &str,
    policy_version: Option<&str>,
    expected_version: i64,
    idempotency_key: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<Value> {
    if context.executor_kind != "human_attested" && context.executor_kind != "system" {
        return Err(Error::engine(
            "routing requires attested principal choice or trusted policy authority",
        ));
    }
    if !matches!(
        obligation_state,
        "none" | "open" | "satisfied" | "withdrawn"
    ) || !matches!(
        executor_route,
        "unassigned" | "human" | "agent" | "joint" | "closed"
    ) {
        return Err(Error::engine("invalid obligation or executor route"));
    }
    if matches!(executor_route, "agent" | "joint") && policy_version.is_none() {
        return Err(Error::engine(
            "agent routing requires an explicit versioned policy",
        ));
    }
    let payload = json!({"obligation_state":obligation_state,"executor_route":executor_route,"policy_version":policy_version});
    if let Some(existing) = exact_retry(
        tx,
        context.subject_account_id,
        idempotency_key,
        Subject::Message(message_id),
        "routing",
        "route.set",
        expected_version,
        &payload,
    )
    .await?
    {
        return Ok(
            json!({"message_id":message_id,"obligation_state":existing.payload["obligation_state"],"executor_route":existing.payload["executor_route"],"version":existing.expected_version+1,"changed":false,"idempotent":true}),
        );
    }
    let current: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT obligation_state,executor_route,version FROM message_inbox_routing WHERE subject_account_id=? AND message_id=?",
    )
    .bind(context.subject_account_id)
    .bind(message_id)
    .fetch_optional(&mut **tx)
    .await?;
    let current_version = current.as_ref().map_or(0, |value| value.2);
    if current_version != expected_version {
        return Err(Error::engine("routing version conflict"));
    }
    let (event, inserted) = append_event(
        tx,
        context,
        Subject::Message(message_id),
        "routing",
        "route.set",
        expected_version,
        idempotency_key,
        None,
        None,
        &payload,
        act_alloc,
    )
    .await?;
    if !inserted {
        return Ok(
            json!({"message_id":message_id,"version":current_version,"changed":false,"idempotent":true}),
        );
    }
    project_awareness_event(&mut *tx, &event).await?;
    let next_version = current_version + 1;
    let open_human = obligation_state == "open" && executor_route == "human";
    let was_open_human = current
        .as_ref()
        .is_some_and(|value| value.0 == "open" && value.1 == "human");
    let human_already_opened: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM human_message_awareness
          WHERE subject_account_id=? AND message_id=? AND stage IN ('opened','acknowledged'))",
    )
    .bind(context.subject_account_id)
    .bind(message_id)
    .fetch_one(&mut **tx)
    .await?;
    let obligation_candidate_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM notification_candidates
          WHERE recipient_account_id=? AND message_id=? AND reason='human_obligation'
            AND status='effective')",
    )
    .bind(context.subject_account_id)
    .bind(message_id)
    .fetch_one(&mut **tx)
    .await?;
    if open_human && !was_open_human && !human_already_opened && !obligation_candidate_exists {
        append_notification_candidate_in(
            tx,
            context.subject_account_id,
            message_id,
            "human_obligation",
            "routine",
            None,
            "metadata_only",
            "recipient_policy",
            policy_version.unwrap_or("explicit-human-route-v1"),
            "awareness.routing.set",
            &event.id,
            act_alloc,
        )
        .await?;
    } else if !open_human {
        withdraw_notification_candidates_in(
            tx,
            context.subject_account_id,
            message_id,
            Some("human_obligation"),
            "awareness.routing.set",
            &event.id,
            act_alloc,
        )
        .await?;
    }
    Ok(
        json!({"message_id":message_id,"obligation_state":obligation_state,"executor_route":executor_route,"version":next_version,"changed":true}),
    )
}

// ---------------------------------------------------------------------------
// The destination lane — a member's personal rail of Collections.
// ---------------------------------------------------------------------------
//
// A sibling of the four Message lanes, on the same log and with the same
// guarantees: one immutable `awareness_events` row per accepted mutation, an
// idempotency key bound to an intent digest, `expected_version` CAS against the
// projection, an `executor_kind` attestation, and export through the same
// portable sections. What differs is only the subject: this lane keys on
// `(subject_account_id, collection_id)`.
//
// Removal keeps the row as a tombstone with `present = 0` rather than deleting
// it, for the same reason `message_preferences` keeps an all-false row: version
// continuity is what makes CAS meaningful across a leave-and-rejoin, and a
// deleted row would silently reset every caller's `expected_version` to 0.
// A missing row is therefore the same meaningful default as elsewhere in this
// tier — not on the rail, and never has been.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestinationAction {
    Add,
    Remove,
}

impl DestinationAction {
    fn name(self) -> &'static str {
        match self {
            Self::Add => "destination.added",
            Self::Remove => "destination.removed",
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "add" => Ok(Self::Add),
            "remove" => Ok(Self::Remove),
            other => Err(Error::engine(format!(
                "invalid destination action '{other}'"
            ))),
        }
    }
}

/// The current rail row for one member and one Collection, or the meaningful
/// default (absent, version 0) when the member has never touched it.
struct DestinationState {
    present: bool,
    joined_at: Option<String>,
    joined_by: String,
    version: i64,
}

async fn destination_state(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    account: &str,
    collection_id: &str,
) -> Result<DestinationState> {
    let row = sqlx::query(
        "SELECT present,joined_at,joined_by,version FROM member_destinations
          WHERE subject_account_id=? AND collection_id=?",
    )
    .bind(account)
    .bind(collection_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(match row {
        Some(row) => DestinationState {
            present: row.try_get::<i64, _>("present")? != 0,
            joined_at: row.try_get("joined_at")?,
            joined_by: row.try_get("joined_by")?,
            version: row.try_get("version")?,
        },
        None => DestinationState {
            present: false,
            joined_at: None,
            joined_by: "explicit".into(),
            version: 0,
        },
    })
}

#[allow(clippy::too_many_arguments)]
async fn apply_destination(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    collection_id: &str,
    action: DestinationAction,
    joined_by: &str,
    expected_version: i64,
    idempotency_key: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<Value> {
    if collection_id.trim().is_empty() {
        return Err(Error::engine("destination requires a collection_id"));
    }
    let account = context.subject_account_id;
    let current = destination_state(tx, account, collection_id).await?;
    let present = matches!(action, DestinationAction::Add);
    let joined_at = match action {
        // Re-adding a Collection the member never left keeps the moment they
        // first joined it; a genuine rejoin takes the new one.
        DestinationAction::Add if current.present => current.joined_at.clone(),
        DestinationAction::Add => Some(now_iso()),
        DestinationAction::Remove => None,
    };
    let joined_by = match action {
        DestinationAction::Add if current.present => current.joined_by.clone(),
        DestinationAction::Add => joined_by.to_owned(),
        DestinationAction::Remove => current.joined_by.clone(),
    };
    let payload = json!({
        "present": present,
        "joined_at": joined_at,
        "joined_by": joined_by,
    });
    let command_payload = json!({});
    if let Some(existing) = exact_retry(
        tx,
        account,
        idempotency_key,
        Subject::Destination(collection_id),
        "destination",
        action.name(),
        expected_version,
        &command_payload,
    )
    .await?
    {
        return Ok(json!({
            "collection_id": collection_id,
            "version": existing.expected_version + 1,
            "changed": false,
            "idempotent": true,
            "present": existing.payload["present"],
            "joined_at": existing.payload["joined_at"],
            "joined_by": existing.payload["joined_by"],
        }));
    }
    if current.version != expected_version {
        return Err(Error::engine(format!(
            "destination version conflict: expected {expected_version}, current {}",
            current.version
        )));
    }
    let (event, inserted) = append_event(
        tx,
        context,
        Subject::Destination(collection_id),
        "destination",
        action.name(),
        expected_version,
        idempotency_key,
        None,
        Some(&command_payload),
        &payload,
        act_alloc,
    )
    .await?;
    if !inserted {
        return Ok(json!({
            "collection_id": collection_id,
            "version": current.version,
            "changed": false,
            "idempotent": true,
        }));
    }
    project_awareness_event(&mut *tx, &event).await?;
    let next_version = current.version + 1;
    Ok(json!({
        "collection_id": collection_id,
        "version": next_version,
        "changed": true,
        "idempotent": false,
        "present": present,
        "joined_at": joined_at,
        "joined_by": joined_by,
    }))
}

/// Explicit rail mutation: the member adds or removes a Collection themselves,
/// under CAS and with whatever attestation the ingress could establish.
pub async fn set_destination(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    collection_id: &str,
    action: DestinationAction,
    expected_version: i64,
    idempotency_key: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<Value> {
    apply_destination(
        tx,
        context,
        collection_id,
        action,
        "explicit",
        expected_version,
        idempotency_key,
        act_alloc,
    )
    .await
}

/// Send-side coupling: posting a Message into a Collection puts that Collection
/// on the sender's rail. Opening or browsing one does not, and this is the only
/// implicit writer of the lane.
///
/// It is deliberately not a CAS caller. The sender does not know their own rail
/// version, and the auto-join is a consequence of a send rather than a claim
/// about prior state — so it reads the current version and, when the Collection
/// is already on the rail, appends nothing at all. The idempotency key is
/// derived from the delivering content event, which makes a retried send join
/// exactly once while a later send to a Collection the member has since left
/// rejoins it.
pub async fn auto_join_destination_on_send_in(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    account: &str,
    actor: &str,
    collection_id: &str,
    source_event_id: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<Option<Value>> {
    if account.trim().is_empty() || collection_id.trim().is_empty() {
        return Ok(None);
    }
    let current = destination_state(tx, account, collection_id).await?;
    if current.present {
        return Ok(None);
    }
    let context = MutationContext {
        subject_account_id: account,
        authenticated_actor: actor,
        executor_kind: "system",
        executor_ref: None,
        delegation_ref: None,
        reason_code: "message sent into this Collection",
    };
    let result = apply_destination(
        tx,
        &context,
        collection_id,
        DestinationAction::Add,
        "send",
        current.version,
        &format!("destination.auto-join:{source_event_id}:{collection_id}"),
        act_alloc,
    )
    .await?;
    Ok(Some(result))
}

/// The member's rail, most recently joined first. Only present Collections are
/// on it; tombstones are retained state, not membership.
///
/// `include_removed` widens the read to those tombstones without widening the
/// rail. It exists because a version nobody can read is not a version a CAS
/// caller can state: removal keeps the row at a non-zero version, so a member
/// who left a Collection and wants back on the rail must assert that version
/// rather than 0, and before this argument the only place that number appeared
/// was the prose of the conflict error. The Message lanes never had the
/// problem — `list_inbox` LEFT JOINs every lane onto the Message and emits
/// `version` for the neutral row as readily as for the mutated one — so this is
/// the destination lane catching up to the tier's existing read idiom rather
/// than a new one. It stays opt-in so the default answer keeps meaning exactly
/// what it means today: the Collections the member is on.
///
/// `present` is emitted on every entry either way, so a client never has to
/// infer membership from which call it made.
pub async fn list_destinations_on<'e, E>(
    executor: E,
    account: &str,
    include_removed: bool,
) -> Result<Vec<Value>>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    // A tombstone has no `joined_at`, and SQLite sorts NULL last under DESC, so
    // removed entries fall after the live rail rather than on top of it.
    let rows = sqlx::query(
        "SELECT collection_id,present,joined_at,joined_by,version FROM member_destinations
          WHERE subject_account_id=? AND (present=1 OR ?)
          ORDER BY joined_at DESC,collection_id",
    )
    .bind(account)
    .bind(include_removed)
    .fetch_all(executor)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(json!({
                "collection_id": row.try_get::<String, _>("collection_id")?,
                "present": row.try_get::<i64, _>("present")? != 0,
                "joined_at": row.try_get::<Option<String>, _>("joined_at")?,
                "joined_by": row.try_get::<String, _>("joined_by")?,
                "version": row.try_get::<i64, _>("version")?,
            }))
        })
        .collect()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MentionInput {
    pub mention_id: String,
    pub target_kind: String,
    pub target_id: String,
    pub span_start: usize,
    pub span_end: usize,
    pub authored_label: String,
}

#[derive(Clone, Debug)]
pub struct ValidatedMention {
    pub input: MentionInput,
    pub target_binding: String,
    pub recipient_account: Option<String>,
}

pub async fn project_mentions_in(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    message_id: &str,
    source_event_seq: i64,
    mentions: &[ValidatedMention],
) -> Result<()> {
    for mention in mentions {
        sqlx::query(
            "INSERT INTO message_mentions
               (message_id,mention_id,target_kind,target_binding,target_record_id,span_start,
                span_end,authored_label,source_event_seq,effective)
             VALUES (?,?,?,?,?,?,?,?,?,1)",
        )
        .bind(message_id)
        .bind(&mention.input.mention_id)
        .bind(&mention.input.target_kind)
        .bind(&mention.target_binding)
        .bind(&mention.input.target_id)
        .bind(mention.input.span_start as i64)
        .bind(mention.input.span_end as i64)
        .bind(&mention.input.authored_label)
        .bind(source_event_seq)
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// One decoded `notification_candidate_events` row. The typed seam shared by
/// the live proposal/withdrawal writers and the candidate half of
/// `rebuild_projections`. The projection columns are the authority; the
/// portable `payload` envelope is carried for fidelity and never re-derived.
#[derive(Clone, Debug)]
pub(crate) struct NotificationCandidateEventRow {
    pub seq: i64,
    pub id: String,
    pub candidate_key: String,
    pub action: String,
    pub recipient_account_id: String,
    pub message_id: String,
    pub reason: String,
    pub priority: String,
    pub not_before: Option<String>,
    pub redaction_class: String,
    pub evaluator_kind: String,
    pub policy_version: String,
    pub source_event_type: String,
    pub source_event_id: String,
    /// The portable candidate envelope, carried verbatim for fidelity. The
    /// projection columns are the authority, so the fold reads none of it.
    #[allow(dead_code)]
    pub payload: Value,
    pub created_at: String,
    /// The act-range coordinate. Retained so the bounded fold can select and
    /// carry stamped rows; the repair fold never re-derives it.
    #[allow(dead_code)]
    pub act: Option<i64>,
}

fn notification_candidate_row_from_sql(
    row: sqlx::sqlite::SqliteRow,
) -> Result<NotificationCandidateEventRow> {
    let payload: String = row.try_get("payload")?;
    Ok(NotificationCandidateEventRow {
        seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        candidate_key: row.try_get("candidate_key")?,
        action: row.try_get("action")?,
        recipient_account_id: row.try_get("recipient_account_id")?,
        message_id: row.try_get("message_id")?,
        reason: row.try_get("reason")?,
        priority: row.try_get("priority")?,
        not_before: row.try_get("not_before")?,
        redaction_class: row.try_get("redaction_class")?,
        evaluator_kind: row.try_get("evaluator_kind")?,
        policy_version: row.try_get("policy_version")?,
        source_event_type: row.try_get("source_event_type")?,
        source_event_id: row.try_get("source_event_id")?,
        payload: serde_json::from_str(&payload)?,
        created_at: row.try_get("created_at")?,
        act: row.try_get("act")?,
    })
}

/// The whole candidate log in `seq` order — the input to the candidate half of
/// the projection rebuild.
pub(crate) async fn read_all_notification_candidate_events(
    conn: &mut SqliteConnection,
) -> Result<Vec<NotificationCandidateEventRow>> {
    sqlx::query(
        "SELECT seq,id,candidate_key,action,recipient_account_id,message_id,reason,priority,
                not_before,redaction_class,evaluator_kind,policy_version,source_event_type,
                source_event_id,payload,created_at,act
           FROM notification_candidate_events ORDER BY seq",
    )
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(notification_candidate_row_from_sql)
    .collect()
}

/// The candidate-only act-range reader: exactly the rows whose `act` falls in
/// the half-open interval `(from_exclusive, to_inclusive]`, in `seq` order,
/// decoded by the same [`notification_candidate_row_from_sql`] the full reader
/// uses. Legacy rows whose act is `NULL` never satisfy the strict `act > ?`
/// predicate and are excluded.
#[allow(dead_code)] // R3 wires the bounded fold; the reader lands ahead of its caller.
pub(crate) async fn notification_candidate_events_in_act_range(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<Vec<NotificationCandidateEventRow>> {
    sqlx::query(
        "SELECT seq,id,candidate_key,action,recipient_account_id,message_id,reason,priority,
                not_before,redaction_class,evaluator_kind,policy_version,source_event_type,
                source_event_id,payload,created_at,act
           FROM notification_candidate_events WHERE act > ? AND act <= ? ORDER BY seq",
    )
    .bind(from_exclusive_act)
    .bind(to_inclusive_act)
    .fetch_all(&mut *conn)
    .await?
    .into_iter()
    .map(notification_candidate_row_from_sql)
    .collect()
}

/// Read one candidate event by its `seq`, the way the SQLite withdrawal port
/// recovers the row it just appended so it can fold it through the same
/// projector the rebuild uses.
async fn notification_candidate_event_by_seq(
    conn: &mut SqliteConnection,
    seq: i64,
) -> Result<Option<NotificationCandidateEventRow>> {
    sqlx::query(
        "SELECT seq,id,candidate_key,action,recipient_account_id,message_id,reason,priority,
                not_before,redaction_class,evaluator_kind,policy_version,source_event_type,
                source_event_id,payload,created_at,act
           FROM notification_candidate_events WHERE seq = ?",
    )
    .bind(seq)
    .fetch_optional(&mut *conn)
    .await?
    .map(notification_candidate_row_from_sql)
    .transpose()
}

/// Fold one candidate event into `notification_candidates`. This is the only
/// writer of that projection: the live proposal path calls it after the
/// `proposed` insert, the withdrawal paths call it for the appended
/// `withdrawn` event, and `rebuild_projections` calls it in `seq` order.
///
/// The transition semantics are explicit. `proposed` inserts a candidate in
/// the `effective` state and is refused by the unique key if a proposal already
/// exists. `withdrawn` and `suppressed` transition exactly one existing
/// proposal projection and fail closed (`affected != 1`) when no proposal
/// exists, so a replayed or materialised log cannot silently drop a transition
/// whose proposal is missing; a repeated transition against the existing row
/// remains a valid single-row update. Any other action fails closed rather
/// than being silently reinterpreted.
pub(crate) async fn project_notification_candidate_event(
    conn: &mut SqliteConnection,
    event: &NotificationCandidateEventRow,
) -> Result<()> {
    match event.action.as_str() {
        "proposed" => {
            sqlx::query("INSERT INTO notification_candidates(candidate_id,candidate_key,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,candidate_event_seq,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'effective',?)")
                .bind(&event.id)
                .bind(&event.candidate_key)
                .bind(&event.recipient_account_id)
                .bind(&event.message_id)
                .bind(&event.reason)
                .bind(&event.priority)
                .bind(event.not_before.as_deref())
                .bind(&event.redaction_class)
                .bind(&event.evaluator_kind)
                .bind(&event.policy_version)
                .bind(&event.source_event_type)
                .bind(&event.source_event_id)
                .bind(event.seq)
                .bind(&event.created_at)
                .execute(&mut *conn)
                .await?;
        }
        "withdrawn" => {
            let affected = sqlx::query(
                "UPDATE notification_candidates SET status='withdrawn',candidate_event_seq=? WHERE candidate_key=?",
            )
            .bind(event.seq)
            .bind(&event.candidate_key)
            .execute(&mut *conn)
            .await?
            .rows_affected();
            require_single_candidate_transition(affected, "withdrawal", &event.candidate_key)?;
        }
        "suppressed" => {
            let affected = sqlx::query(
                "UPDATE notification_candidates SET status='suppressed',candidate_event_seq=? WHERE candidate_key=?",
            )
            .bind(event.seq)
            .bind(&event.candidate_key)
            .execute(&mut *conn)
            .await?
            .rows_affected();
            require_single_candidate_transition(affected, "suppression", &event.candidate_key)?;
        }
        other => {
            return Err(Error::engine(format!(
                "unknown notification candidate action '{other}'"
            )))
        }
    }
    Ok(())
}

/// Refuse a candidate transition that does not touch exactly one existing
/// proposal projection. The proposal insert is the only writer of a candidate
/// row, so a `withdrawn`/`suppressed` event without its `proposed` predecessor
/// is a malformed log: the shared projector must fail closed rather than let a
/// replay or a materialised delta silently drop the transition.
fn require_single_candidate_transition(
    affected: u64,
    transition: &str,
    candidate_key: &str,
) -> Result<()> {
    if affected != 1 {
        return Err(Error::engine(format!(
            "notification candidate {transition} for '{candidate_key}' must affect exactly one existing proposal, affected {affected}"
        )));
    }
    Ok(())
}

/// Fold every candidate event in order through
/// [`project_notification_candidate_event`].
pub(crate) async fn replay_notification_candidate_events(
    conn: &mut SqliteConnection,
    events: &[NotificationCandidateEventRow],
) -> Result<()> {
    for event in events {
        project_notification_candidate_event(conn, event).await?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn append_notification_candidate_in(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    recipient_account: &str,
    message_id: &str,
    reason: &str,
    priority: &str,
    not_before: Option<&str>,
    redaction_class: &str,
    evaluator_kind: &str,
    policy_version: &str,
    source_event_type: &str,
    source_event_id: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<Option<String>> {
    if !matches!(
        reason,
        "principal_mention"
            | "human_obligation"
            | "human_intervention"
            | "snooze_due"
            | "routine_arrival"
    ) || !matches!(priority, "routine" | "urgent")
        || !matches!(redaction_class, "metadata_only" | "minimal_context")
        || !matches!(
            evaluator_kind,
            "portable_default" | "recipient_policy" | "intervention_policy"
        )
        || policy_version.trim().is_empty()
        || (reason == "routine_arrival" && evaluator_kind != "recipient_policy")
        || (priority == "urgent" && evaluator_kind != "recipient_policy")
    {
        return Err(Error::engine(
            "invalid notification candidate policy provenance",
        ));
    }
    let candidate_key = format!("{recipient_account}:{message_id}:{reason}:{source_event_id}");
    if let Some(existing) = sqlx::query_scalar::<_, String>(
        "SELECT candidate_id FROM notification_candidates WHERE candidate_key=?",
    )
    .bind(&candidate_key)
    .fetch_optional(&mut **tx)
    .await?
    {
        return Ok(Some(existing));
    }
    let id = Uuid::new_v4().to_string();
    // Portable candidates intentionally contain no Message body, endpoint, or
    // provider payload. Rendering happens after host-side reauthorization.
    let payload = json!({"schema":"native.notification-candidate.v1"});
    let created_at = now_iso();
    let act = act_alloc.get_or_allocate(&mut *tx).await?;
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO notification_candidate_events
           (id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,
            redaction_class,evaluator_kind,policy_version,source_event_type,
            source_event_id,payload,created_at,act)
         VALUES (?,?,'proposed',?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq",
    )
    .bind(&id)
    .bind(&candidate_key)
    .bind(recipient_account)
    .bind(message_id)
    .bind(reason)
    .bind(priority)
    .bind(not_before)
    .bind(redaction_class)
    .bind(evaluator_kind)
    .bind(policy_version)
    .bind(source_event_type)
    .bind(source_event_id)
    .bind(serde_json::to_string(&payload)?)
    .bind(&created_at)
    .bind(act)
    .fetch_one(&mut **tx)
    .await?;
    let event = NotificationCandidateEventRow {
        seq,
        id: id.clone(),
        candidate_key,
        action: "proposed".into(),
        recipient_account_id: recipient_account.to_string(),
        message_id: message_id.to_string(),
        reason: reason.to_string(),
        priority: priority.to_string(),
        not_before: not_before.map(str::to_owned),
        redaction_class: redaction_class.to_string(),
        evaluator_kind: evaluator_kind.to_string(),
        policy_version: policy_version.to_string(),
        source_event_type: source_event_type.to_string(),
        source_event_id: source_event_id.to_string(),
        payload,
        created_at,
        act: Some(act),
    };
    project_notification_candidate_event(&mut *tx, &event).await?;
    Ok(Some(id))
}

/// One effective candidate carried through the portable withdrawal fold.
/// The semantic fields are copied verbatim into the immutable withdrawal
/// event; only its action, source event, id, sequence and timestamp change.
#[derive(Clone, Debug)]
pub(crate) struct CandidateWithdrawal {
    pub candidate_id: String,
    pub candidate_key: String,
    pub recipient_account_id: String,
    pub reason: String,
    pub priority: String,
    pub not_before: Option<String>,
    pub redaction_class: String,
    pub evaluator_kind: String,
    pub policy_version: String,
}

/// Backend-owned writes needed by the shared event-authoritative candidate
/// withdrawal fold. Both writes run inside the caller's deletion transaction.
pub(crate) trait CandidateWithdrawalPhysicalPort {
    fn append_candidate_withdrawal<'a>(
        &'a mut self,
        withdrawal_event_id: &'a str,
        candidate: &'a CandidateWithdrawal,
        message_id: &'a str,
        source_event_type: &'a str,
        source_event_id: &'a str,
        created_at: &'a str,
    ) -> BoxFuture<'a, Result<i64>>;

    fn project_candidate_withdrawal<'a>(
        &'a mut self,
        candidate_id: &'a str,
        event_seq: i64,
    ) -> BoxFuture<'a, Result<()>>;
}

fn candidate_text(row: &NormalizedRow, column: &str) -> Result<String> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "notification candidate column '{column}' is invalid"
        ))),
    }
}

fn candidate_optional_text(row: &NormalizedRow, column: &str) -> Result<Option<String>> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(Some(value.clone())),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "notification candidate column '{column}' is invalid"
        ))),
    }
}

/// Withdraw every currently effective candidate for one deleted Message.
/// This is the canonical portable fold used by SQLite, Postgres and Turso:
/// append one immutable `withdrawn` event per candidate, then advance that
/// candidate's projection to the new event sequence in the same transaction.
pub(crate) async fn withdraw_message_candidates_with<P>(
    port: &mut P,
    message_id: &str,
    source_event_type: &str,
    source_event_id: &str,
) -> Result<usize>
where
    P: DomainStatementExecutor + CandidateWithdrawalPhysicalPort,
{
    let query = StatementTemplate::new(
        StatementKind::Select,
        "notification_candidates",
        &[
            "SELECT candidate_id, candidate_key, recipient_account_id, reason, priority, not_before, redaction_class, evaluator_kind, policy_version FROM {{relation}} WHERE message_id = ",
            " AND status = 'effective' ORDER BY candidate_id",
        ],
    )
    .map_err(|error| Error::engine(error.stable_message()))?;
    let rows = port
        .fetch_all(
            &query,
            &[BindValue::Text(message_id.into())],
            &[
                ColumnSpec::required("candidate_id", LogicalType::Text),
                ColumnSpec::required("candidate_key", LogicalType::Text),
                ColumnSpec::required("recipient_account_id", LogicalType::Text),
                ColumnSpec::required("reason", LogicalType::Text),
                ColumnSpec::required("priority", LogicalType::Text),
                ColumnSpec::nullable("not_before", LogicalType::Text),
                ColumnSpec::required("redaction_class", LogicalType::Text),
                ColumnSpec::required("evaluator_kind", LogicalType::Text),
                ColumnSpec::required("policy_version", LogicalType::Text),
            ],
        )
        .await
        .map_err(|error| Error::engine(error.stable_message()))?;
    for row in &rows {
        let candidate = CandidateWithdrawal {
            candidate_id: candidate_text(row, "candidate_id")?,
            candidate_key: candidate_text(row, "candidate_key")?,
            recipient_account_id: candidate_text(row, "recipient_account_id")?,
            reason: candidate_text(row, "reason")?,
            priority: candidate_text(row, "priority")?,
            not_before: candidate_optional_text(row, "not_before")?,
            redaction_class: candidate_text(row, "redaction_class")?,
            evaluator_kind: candidate_text(row, "evaluator_kind")?,
            policy_version: candidate_text(row, "policy_version")?,
        };
        let event_id = Uuid::new_v4().to_string();
        let created_at = now_iso();
        let seq = port
            .append_candidate_withdrawal(
                &event_id,
                &candidate,
                message_id,
                source_event_type,
                source_event_id,
                &created_at,
            )
            .await?;
        port.project_candidate_withdrawal(&candidate.candidate_id, seq)
            .await?;
    }
    Ok(rows.len())
}

struct SqliteCandidateWithdrawalPort<'a> {
    tx: &'a mut sqlx::Transaction<'static, Sqlite>,
    act_alloc: &'a mut crate::act::ActAllocation,
}

impl DomainStatementExecutor for SqliteCandidateWithdrawalPort<'_> {
    fn fetch_all<'a>(
        &'a mut self,
        statement: &'a StatementTemplate,
        bindings: &'a [BindValue],
        columns: &'a [ColumnSpec],
    ) -> BoxFuture<'a, SqlResult<Vec<NormalizedRow>>> {
        Box::pin(async move {
            let mut executor = BorrowedSqliteStatementExecutor::new(self.tx);
            executor.fetch_all(statement, bindings, columns).await
        })
    }
}

impl CandidateWithdrawalPhysicalPort for SqliteCandidateWithdrawalPort<'_> {
    fn append_candidate_withdrawal<'a>(
        &'a mut self,
        withdrawal_event_id: &'a str,
        candidate: &'a CandidateWithdrawal,
        message_id: &'a str,
        source_event_type: &'a str,
        source_event_id: &'a str,
        created_at: &'a str,
    ) -> BoxFuture<'a, Result<i64>> {
        Box::pin(async move {
            let act = self.act_alloc.get_or_allocate(self.tx).await?;
            Ok(sqlx::query_scalar("INSERT INTO notification_candidate_events(id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at,act) VALUES(?,?,'withdrawn',?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq")
                .bind(withdrawal_event_id)
                .bind(&candidate.candidate_key)
                .bind(&candidate.recipient_account_id)
                .bind(message_id)
                .bind(&candidate.reason)
                .bind(&candidate.priority)
                .bind(&candidate.not_before)
                .bind(&candidate.redaction_class)
                .bind(&candidate.evaluator_kind)
                .bind(&candidate.policy_version)
                .bind(source_event_type)
                .bind(source_event_id)
                .bind("{\"schema\":\"native.notification-candidate.v1\"}")
                .bind(created_at)
                .bind(act)
                .fetch_one(&mut **self.tx)
                .await?)
        })
    }

    fn project_candidate_withdrawal<'a>(
        &'a mut self,
        candidate_id: &'a str,
        event_seq: i64,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // Recover the row just appended, verify it names the proposal it
            // claims to withdraw (the `candidate_id`/`candidate_key` identity is
            // 1:1 and both unique), then fold it through the one shared
            // key-based projector. Portable adapters keep their own physical
            // update; this only unifies the SQLite live and rebuild paths.
            let event = notification_candidate_event_by_seq(self.tx, event_seq)
                .await?
                .ok_or_else(|| {
                    Error::engine("notification candidate withdrawal event was not found")
                })?;
            let proposed_key: Option<String> = sqlx::query_scalar(
                "SELECT candidate_key FROM notification_candidates WHERE candidate_id=?",
            )
            .bind(candidate_id)
            .fetch_optional(&mut **self.tx)
            .await?;
            match proposed_key {
                Some(key) if key == event.candidate_key => {}
                _ => {
                    return Err(Error::engine(
                        "notification candidate withdrawal does not match its proposal",
                    ))
                }
            }
            project_notification_candidate_event(self.tx, &event).await
        })
    }
}

pub async fn withdraw_message_candidates_in(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    message_id: &str,
    source_event_type: &str,
    source_event_id: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<usize> {
    let mut port = SqliteCandidateWithdrawalPort { tx, act_alloc };
    withdraw_message_candidates_with(&mut port, message_id, source_event_type, source_event_id)
        .await
}

/// Apply awareness effects that are meaningful only once a Message has been
/// delivered. Blocked sends retain their authored facets, mentions, and
/// correction links, but none of those facts may surface or alter another
/// Message's candidates until delivery is authorized.
pub(crate) async fn apply_delivered_message_awareness_in(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    message_id: &str,
    recipient_accounts: &[String],
    source_event_type: &str,
    source_event_id: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<()> {
    let has_obligation: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM facet_values
            WHERE record_id=? AND key='expectation' AND value<>'none'
         )",
    )
    .bind(message_id)
    .fetch_one(&mut **tx)
    .await?;
    if has_obligation {
        for account in recipient_accounts {
            append_notification_candidate_in(
                tx,
                account,
                message_id,
                "human_obligation",
                "routine",
                None,
                "metadata_only",
                "portable_default",
                "messaging-awareness-v1",
                source_event_type,
                source_event_id,
                act_alloc,
            )
            .await?;
        }
    }

    // A correction participates in awareness conflict handling only after it
    // has an addressed audience. Sender-only and policy-blocked drafts have no
    // addressed_to audience until an authorized delivery event projects one.
    let correction_conflicted: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT correction.target_id
             FROM links correction
            WHERE correction.relationship='supersedes'
              AND correction.target_id IN (
                    SELECT target_id FROM links
                     WHERE source_id=? AND relationship='supersedes'
                  )
              AND EXISTS (
                    SELECT 1 FROM message_audiences audience
                     WHERE audience.message_id=correction.source_id
                       AND audience.source='addressed_to'
                  )
            GROUP BY correction.target_id
           HAVING COUNT(DISTINCT correction.source_id)>1
         )",
    )
    .bind(message_id)
    .fetch_one(&mut **tx)
    .await?;
    if correction_conflicted {
        let competing_sources: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT correction.source_id
               FROM links correction
              WHERE correction.relationship='supersedes'
                AND correction.target_id IN (
                      SELECT target_id FROM links
                       WHERE source_id=? AND relationship='supersedes'
                    )
                AND EXISTS (
                      SELECT 1 FROM message_audiences audience
                       WHERE audience.message_id=correction.source_id
                         AND audience.source='addressed_to'
                    )",
        )
        .bind(message_id)
        .fetch_all(&mut **tx)
        .await?;
        for source_id in competing_sources {
            withdraw_message_candidates_in(
                tx,
                &source_id,
                "correction.conflicted",
                source_event_id,
                act_alloc,
            )
            .await?;
        }
    } else {
        let mention_accounts: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT account.identifier
               FROM message_mentions mention
               JOIN bindings account
                 ON account.record_id=mention.target_record_id
                AND account.system='account' AND account.is_canonical=1
              WHERE mention.message_id=? AND mention.target_kind='principal'
                AND mention.effective=1
              ORDER BY account.identifier",
        )
        .bind(message_id)
        .fetch_all(&mut **tx)
        .await?;
        for account in mention_accounts {
            append_notification_candidate_in(
                tx,
                &account,
                message_id,
                "principal_mention",
                "routine",
                None,
                "metadata_only",
                "portable_default",
                "messaging-awareness-v1",
                source_event_type,
                source_event_id,
                act_alloc,
            )
            .await?;
        }
    }

    let superseded: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links
          WHERE source_id=? AND relationship='supersedes'
          ORDER BY target_id",
    )
    .bind(message_id)
    .fetch_all(&mut **tx)
    .await?;
    for target_id in superseded {
        withdraw_message_candidates_in(
            tx,
            &target_id,
            source_event_type,
            source_event_id,
            act_alloc,
        )
        .await?;
    }
    Ok(())
}

pub async fn withdraw_notification_candidates_in(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    recipient_account: &str,
    message_id: &str,
    reason: Option<&str>,
    source_event_type: &str,
    source_event_id: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<usize> {
    let rows=sqlx::query("SELECT candidate_key,recipient_account_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version FROM notification_candidates WHERE message_id=? AND status='effective' AND (?='%' OR recipient_account_id=?) AND (? IS NULL OR reason=?)")
        .bind(message_id).bind(recipient_account).bind(recipient_account).bind(reason).bind(reason)
        .fetch_all(&mut **tx).await?;
    for row in &rows {
        let id = Uuid::new_v4().to_string();
        let created_at = now_iso();
        let act = act_alloc.get_or_allocate(&mut *tx).await?;
        let seq:i64=sqlx::query_scalar("INSERT INTO notification_candidate_events(id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at,act) VALUES(?,?,'withdrawn',?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq")
            .bind(&id).bind(row.try_get::<String,_>("candidate_key")?).bind(row.try_get::<String,_>("recipient_account_id")?).bind(message_id)
            .bind(row.try_get::<String,_>("reason")?).bind(row.try_get::<String,_>("priority")?).bind(row.try_get::<Option<String>,_>("not_before")?)
            .bind(row.try_get::<String,_>("redaction_class")?).bind(row.try_get::<String,_>("evaluator_kind")?).bind(row.try_get::<String,_>("policy_version")?)
            .bind(source_event_type).bind(source_event_id).bind("{\"schema\":\"native.notification-candidate.v1\"}").bind(&created_at).bind(act).fetch_one(&mut **tx).await?;
        let event = NotificationCandidateEventRow {
            seq,
            id,
            candidate_key: row.try_get("candidate_key")?,
            action: "withdrawn".into(),
            recipient_account_id: row.try_get("recipient_account_id")?,
            message_id: message_id.to_string(),
            reason: row.try_get("reason")?,
            priority: row.try_get("priority")?,
            not_before: row.try_get("not_before")?,
            redaction_class: row.try_get("redaction_class")?,
            evaluator_kind: row.try_get("evaluator_kind")?,
            policy_version: row.try_get("policy_version")?,
            source_event_type: source_event_type.to_string(),
            source_event_id: source_event_id.to_string(),
            payload: json!({"schema":"native.notification-candidate.v1"}),
            created_at,
            act: Some(act),
        };
        project_notification_candidate_event(&mut *tx, &event).await?;
    }
    Ok(rows.len())
}

pub async fn heads_on<'e, E>(executor: E) -> Result<(i64, i64)>
where
    E: sqlx::Executor<'e, Database = Sqlite> + Copy,
{
    let awareness: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM awareness_events")
        .fetch_one(executor)
        .await?;
    let candidates: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM notification_candidate_events")
            .fetch_one(executor)
            .await?;
    Ok((awareness, candidates))
}

/// Deterministically rebuild awareness and candidate projections from their
/// retained semantic ledgers. This is repair/conformance machinery: it never
/// invents events and v1's semantic retention floors remain zero.
pub(crate) const REBUILD_PROJECTION_TABLES: &[&str] = &[
    "awareness_event_evidence",
    "human_message_awareness",
    "agent_message_dispositions",
    "message_inbox_routing",
    "message_preferences",
    "member_destinations",
    "notification_candidates",
];

pub async fn rebuild_projections(db: &crate::Db) -> Result<()> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    for table in REBUILD_PROJECTION_TABLES {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await?;
    }
    let events = read_all_awareness_events(&mut tx).await?;
    replay_awareness(&mut tx, &events).await?;
    let candidates = read_all_notification_candidate_events(&mut tx).await?;
    replay_notification_candidate_events(&mut tx, &candidates).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn exact_retry_is_stable_and_different_intent_fails() {
        let db = crate::create_database(":memory:").await.unwrap();
        let attestation = VerifiedHumanInteraction {
            nonce: "verified-nonce".into(),
            executor_ref: "trusted-ui".into(),
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let first = advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Acknowledged,
            0,
            "same-key",
            &attestation,
            "explicit review",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert_eq!(first["changed"], true);
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Presented,
            1,
            "later-key",
            &VerifiedHumanInteraction {
                nonce: "later-verified-nonce".into(),
                executor_ref: "trusted-ui".into(),
            },
            "later presentation",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let retry = advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Acknowledged,
            0,
            "same-key",
            &attestation,
            "explicit review",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert_eq!(retry["idempotent"], true);
        assert_eq!(retry["stage"], "acknowledged");
        assert_eq!(retry["version"], 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM awareness_events")
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            2
        );
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let error = advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Opened,
            1,
            "same-key",
            &attestation,
            "different",
            &mut act_alloc,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("different intent"));
    }

    /// Prerequisite 781a566a: a genuinely new batch intent allocates a
    /// visible act immediately before INSERT; an exact retry allocates
    /// nothing and leaves the counter untouched; a first-time empty batch
    /// still allocates a visible act.
    #[tokio::test]
    async fn batch_command_intent_allocates_act_once_and_retries_allocate_nothing() {
        let db = crate::create_database(":memory:").await.unwrap();
        let attestation = VerifiedHumanInteraction {
            nonce: "batch-nonce".into(),
            executor_ref: "trusted-ui".into(),
        };
        let counter = || async {
            sqlx::query_scalar::<_, i64>("SELECT next_act FROM act_state WHERE singleton = 1")
                .fetch_one(db.write_pool())
                .await
                .unwrap()
        };
        let before = counter().await;

        // First-time batch allocates a visible act.
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let first = register_human_batch_command(
            &mut tx,
            "acct:batch",
            HumanStage::Acknowledged,
            &["m1".to_string()],
            &std::collections::BTreeMap::from([("m1".to_string(), 0)]),
            "batch-key-1",
            None,
            &attestation,
            "reviewed",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert!(first);
        let intent_act: Option<i64> = sqlx::query_scalar(
            "SELECT act FROM awareness_command_intents WHERE subject_account_id = 'acct:batch' AND idempotency_key = 'batch-key-1'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        let allocated = intent_act.expect("new intent carries an act");
        assert!(allocated > before);
        tx.commit().await.unwrap();
        assert_eq!(counter().await, allocated);

        // Exact retry allocates nothing: no new row, counter untouched.
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let retry = register_human_batch_command(
            &mut tx,
            "acct:batch",
            HumanStage::Acknowledged,
            &["m1".to_string()],
            &std::collections::BTreeMap::from([("m1".to_string(), 0)]),
            "batch-key-1",
            None,
            &attestation,
            "reviewed",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert!(!retry);
        assert!(act_alloc.get().is_none());
        tx.commit().await.unwrap();
        assert_eq!(counter().await, allocated);

        // First-time empty batch remains visible: it still allocates.
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let empty_first = register_human_batch_command(
            &mut tx,
            "acct:batch",
            HumanStage::Acknowledged,
            &[],
            &std::collections::BTreeMap::new(),
            "batch-key-empty",
            None,
            &attestation,
            "reviewed",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert!(empty_first);
        let empty_act: Option<i64> = sqlx::query_scalar(
            "SELECT act FROM awareness_command_intents WHERE subject_account_id = 'acct:batch' AND idempotency_key = 'batch-key-empty'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert!(empty_act.expect("empty batch carries an act") > allocated);
        tx.commit().await.unwrap();
        db.close().await;
    }

    /// Prerequisite 781a566a: the batch intent and every awareness event the
    /// same command causes share one act. The intent allocates first, and the
    /// per-message `advance_human` appends reuse the shared allocation.
    #[tokio::test]
    async fn batch_intent_and_awareness_events_share_one_act() {
        let db = crate::create_database(":memory:").await.unwrap();
        let attestation = VerifiedHumanInteraction {
            nonce: "batch-share".into(),
            executor_ref: "trusted-ui".into(),
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let first = register_human_batch_command(
            &mut tx,
            "acct:share",
            HumanStage::Acknowledged,
            &["m-share".to_string()],
            &std::collections::BTreeMap::from([("m-share".to_string(), 0)]),
            "batch-share-key",
            None,
            &attestation,
            "reviewed",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert!(first);
        advance_human(
            &mut tx,
            "acct:share",
            "m-share",
            HumanStage::Acknowledged,
            0,
            "batch-share-key:m-share",
            &attestation,
            "reviewed",
            &mut act_alloc,
        )
        .await
        .unwrap();
        let intent_act: Option<i64> = sqlx::query_scalar(
            "SELECT act FROM awareness_command_intents
              WHERE subject_account_id = 'acct:share' AND idempotency_key = 'batch-share-key'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        let event_acts: Vec<Option<i64>> = sqlx::query_scalar(
            "SELECT act FROM awareness_events WHERE message_id = 'm-share' ORDER BY seq",
        )
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        let shared = intent_act.expect("the batch intent carries an act");
        assert!(!event_acts.is_empty(), "the batch appends awareness events");
        assert!(
            event_acts.iter().all(|act| *act == Some(shared)),
            "intent and awareness events must share one act, got intent {shared} vs events {event_acts:?}"
        );
        tx.commit().await.unwrap();
        db.close().await;
    }

    /// Prerequisite 781a566a: a batch intent whose transaction rolls back
    /// consumes no act, so the next committed writer reuses it.
    #[tokio::test]
    async fn batch_intent_rollback_consumes_no_act() {
        let db = crate::create_database(":memory:").await.unwrap();
        let attestation = VerifiedHumanInteraction {
            nonce: "batch-rollback".into(),
            executor_ref: "trusted-ui".into(),
        };
        let before: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let first = register_human_batch_command(
            &mut tx,
            "acct:rollback",
            HumanStage::Acknowledged,
            &["m-rollback".to_string()],
            &std::collections::BTreeMap::from([("m-rollback".to_string(), 0)]),
            "batch-rollback-key",
            None,
            &attestation,
            "reviewed",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert!(first);
        assert!(
            act_alloc.get().is_some(),
            "the rolled-back intent did allocate before the rollback"
        );
        tx.rollback().await.unwrap();
        let after: i64 = sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton = 1")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(after, before, "a rolled-back intent consumes no act");
        db.close().await;
    }

    #[tokio::test]
    async fn lanes_preferences_and_delivery_facts_are_independent_and_rebuildable() {
        let db = crate::create_database(":memory:").await.unwrap();
        let attestation = VerifiedHumanInteraction {
            nonce: "nonce-human".into(),
            executor_ref: "ui".into(),
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Acknowledged,
            0,
            "human",
            &attestation,
            "read",
            &mut act_alloc,
        )
        .await
        .unwrap();
        let context = MutationContext {
            subject_account_id: "acct:a",
            authenticated_actor: "acct:a",
            executor_kind: "agent",
            executor_ref: Some("run"),
            delegation_ref: Some("delegation"),
            reason_code: "handled",
        };
        set_agent_disposition(
            &mut tx,
            &context,
            "message:a",
            "resolved",
            0,
            "agent",
            &[EvidenceInput {
                record_id: "reply:a".into(),
                role: "reply".into(),
            }],
            &mut act_alloc,
        )
        .await
        .unwrap();
        set_preference(
            &mut tx,
            "acct:a",
            "message:a",
            PreferenceAction::FlagAttention,
            None,
            0,
            "flag",
            "show again",
            &mut act_alloc,
        )
        .await
        .unwrap();
        append_notification_candidate_in(
            &mut tx,
            "acct:a",
            "message:a",
            "principal_mention",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.created",
            "event:a",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT stage FROM human_message_awareness")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            "acknowledged"
        );
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT state FROM agent_message_dispositions")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            "resolved"
        );
        assert!(
            sqlx::query_scalar::<_, bool>("SELECT attention_flag FROM message_preferences")
                .fetch_one(db.write_pool())
                .await
                .unwrap()
        );
        let candidate_payload: String =
            sqlx::query_scalar("SELECT payload FROM notification_candidate_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert!(!candidate_payload.contains("body"));
        let before:(String,String,bool,String)=sqlx::query_as("SELECT h.stage,a.state,p.attention_flag,n.status FROM human_message_awareness h JOIN agent_message_dispositions a USING(subject_account_id,message_id) JOIN message_preferences p USING(subject_account_id,message_id) JOIN notification_candidates n ON n.message_id=h.message_id").fetch_one(db.write_pool()).await.unwrap();
        for table in [
            "awareness_event_evidence",
            "human_message_awareness",
            "agent_message_dispositions",
            "message_preferences",
            "message_inbox_routing",
            "notification_candidates",
        ] {
            sqlx::query(&format!("DELETE FROM {table}"))
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        rebuild_projections(&db).await.unwrap();
        let after:(String,String,bool,String)=sqlx::query_as("SELECT h.stage,a.state,p.attention_flag,n.status FROM human_message_awareness h JOIN agent_message_dispositions a USING(subject_account_id,message_id) JOIN message_preferences p USING(subject_account_id,message_id) JOIN notification_candidates n ON n.message_id=h.message_id").fetch_one(db.write_pool()).await.unwrap();
        assert_eq!(before, after);
    }

    #[tokio::test]
    async fn snooze_schedules_one_due_candidate_and_clear_withdraws_it() {
        let db = crate::create_database(":memory:").await.unwrap();
        let due = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        append_notification_candidate_in(
            &mut tx,
            "acct:a",
            "message:a",
            "human_obligation",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.created",
            "source:a",
            &mut act_alloc,
        )
        .await
        .unwrap();
        set_preference(
            &mut tx,
            "acct:a",
            "message:a",
            PreferenceAction::Snooze,
            Some(&due),
            0,
            "snooze",
            "review later",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let row: (String, String, Option<String>, String) = sqlx::query_as(
            "SELECT reason,priority,not_before,status FROM notification_candidates WHERE status='effective'",
        )
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(
            row,
            (
                "snooze_due".into(),
                "routine".into(),
                Some(due),
                "effective".into()
            )
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM notification_candidates WHERE status='effective'"
            )
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            1
        );

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        set_preference(
            &mut tx,
            "acct:a",
            "message:a",
            PreferenceAction::ClearSnooze,
            None,
            1,
            "clear-snooze",
            "review now",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM notification_candidates WHERE reason='snooze_due'"
            )
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            "withdrawn"
        );
    }

    #[tokio::test]
    async fn lower_rank_presentation_preserves_attained_times_and_rebuild_is_exact() {
        let db = crate::create_database(":memory:").await.unwrap();
        for (version, stage, key) in [
            (0, HumanStage::Presented, "presented"),
            (1, HumanStage::Opened, "opened"),
            (2, HumanStage::Acknowledged, "acknowledged"),
            (3, HumanStage::Presented, "presented-again"),
        ] {
            let attestation = VerifiedHumanInteraction {
                nonce: format!("nonce-{key}"),
                executor_ref: "ui".into(),
            };
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let mut act_alloc = crate::act::ActAllocation::new();
            advance_human(
                &mut tx,
                "acct:a",
                "message:a",
                stage,
                version,
                key,
                &attestation,
                "explicit gesture",
                &mut act_alloc,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }
        let before: (String, String, String, String, String, i64) = sqlx::query_as(
            "SELECT stage,first_presented_at,last_presented_at,opened_at,acknowledged_at,version
               FROM human_message_awareness",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(before.0, "acknowledged");
        assert_eq!(before.5, 4);
        assert!(!before.1.is_empty() && !before.2.is_empty());
        assert!(!before.3.is_empty() && !before.4.is_empty());
        rebuild_projections(&db).await.unwrap();
        let after: (String, String, String, String, String, i64) = sqlx::query_as(
            "SELECT stage,first_presented_at,last_presented_at,opened_at,acknowledged_at,version
               FROM human_message_awareness",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(after, before);
    }

    #[tokio::test]
    async fn lower_rank_human_event_still_withdraws_candidates_after_message_was_opened() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Opened,
            0,
            "opened",
            &VerifiedHumanInteraction {
                nonce: "nonce-opened".into(),
                executor_ref: "ui".into(),
            },
            "explicit gesture",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        append_notification_candidate_in(
            &mut tx,
            "acct:a",
            "message:a",
            "principal_mention",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.updated",
            "source:a",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Presented,
            1,
            "presented-after-open",
            &VerifiedHumanInteraction {
                nonce: "nonce-presented-after-open".into(),
                executor_ref: "ui".into(),
            },
            "explicit gesture",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let state: (String, i64) = sqlx::query_as(
            "SELECT stage,version FROM human_message_awareness WHERE subject_account_id=? AND message_id=?",
        )
        .bind("acct:a")
        .bind("message:a")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(state, ("opened".into(), 2));
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM notification_candidates WHERE recipient_account_id=? AND message_id=?",
            )
            .bind("acct:a")
            .bind("message:a")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            "withdrawn"
        );
    }

    #[tokio::test]
    async fn preference_retry_uses_command_intent_not_later_combined_state() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        set_preference(
            &mut tx,
            "acct:a",
            "message:a",
            PreferenceAction::Mute,
            None,
            0,
            "mute",
            "quiet",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        set_preference(
            &mut tx,
            "acct:a",
            "message:a",
            PreferenceAction::FlagAttention,
            None,
            1,
            "flag",
            "important",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let retry = set_preference(
            &mut tx,
            "acct:a",
            "message:a",
            PreferenceAction::Mute,
            None,
            0,
            "mute",
            "quiet",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert_eq!(retry["idempotent"], true);
        assert_eq!(retry["version"], 1);
        assert_eq!(retry["muted"], true);
        assert_eq!(retry["attention_flag"], false);
        tx.commit().await.unwrap();
        let state: (bool, bool, i64) =
            sqlx::query_as("SELECT muted,attention_flag,version FROM message_preferences")
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(state, (true, true, 2));
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM awareness_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn agent_and_routing_retries_return_the_original_transition() {
        let db = crate::create_database(":memory:").await.unwrap();
        let agent = MutationContext {
            subject_account_id: "acct:a",
            authenticated_actor: "acct:a",
            executor_kind: "agent",
            executor_ref: Some("executor"),
            delegation_ref: Some("delegation"),
            reason_code: "agent transition",
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        set_agent_disposition(
            &mut tx,
            &agent,
            "message:a",
            "triaged",
            0,
            "agent-first",
            &[],
            &mut act_alloc,
        )
        .await
        .unwrap();
        set_agent_disposition(
            &mut tx,
            &agent,
            "message:a",
            "deferred",
            1,
            "agent-later",
            &[],
            &mut act_alloc,
        )
        .await
        .unwrap();
        let agent_retry = set_agent_disposition(
            &mut tx,
            &agent,
            "message:a",
            "triaged",
            0,
            "agent-first",
            &[],
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert_eq!(agent_retry["idempotent"], true);
        assert_eq!(agent_retry["state"], "triaged");
        assert_eq!(agent_retry["version"], 1);
        tx.commit().await.unwrap();

        let routing = MutationContext {
            subject_account_id: "acct:b",
            authenticated_actor: "policy",
            executor_kind: "system",
            executor_ref: Some("policy"),
            delegation_ref: None,
            reason_code: "routing transition",
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        set_routing(
            &mut tx,
            &routing,
            "message:b",
            "open",
            "human",
            Some("policy-v1"),
            0,
            "routing-first",
            &mut act_alloc,
        )
        .await
        .unwrap();
        set_routing(
            &mut tx,
            &routing,
            "message:b",
            "open",
            "agent",
            Some("policy-v2"),
            1,
            "routing-later",
            &mut act_alloc,
        )
        .await
        .unwrap();
        let routing_retry = set_routing(
            &mut tx,
            &routing,
            "message:b",
            "open",
            "human",
            Some("policy-v1"),
            0,
            "routing-first",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert_eq!(routing_retry["idempotent"], true);
        assert_eq!(routing_retry["obligation_state"], "open");
        assert_eq!(routing_retry["executor_route"], "human");
        assert_eq!(routing_retry["version"], 1);
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn routing_transition_creates_and_then_withdraws_human_obligation_candidate() {
        let db = crate::create_database(":memory:").await.unwrap();
        let context = MutationContext {
            subject_account_id: "acct:a",
            authenticated_actor: "acct:a",
            executor_kind: "system",
            executor_ref: Some("policy"),
            delegation_ref: None,
            reason_code: "route",
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        append_notification_candidate_in(
            &mut tx,
            "acct:a",
            "message:a",
            "human_obligation",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.created",
            "source:a",
            &mut act_alloc,
        )
        .await
        .unwrap();
        set_routing(
            &mut tx,
            &context,
            "message:a",
            "open",
            "human",
            Some("policy-v1"),
            0,
            "to-human",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM notification_candidates WHERE reason='human_obligation' AND status='effective'"
            )
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            1
        );
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        set_routing(
            &mut tx,
            &context,
            "message:a",
            "open",
            "agent",
            Some("policy-v2"),
            1,
            "to-agent",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM notification_candidates WHERE reason='human_obligation'"
            )
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            "withdrawn"
        );

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        advance_human(
            &mut tx,
            "acct:a",
            "message:b",
            HumanStage::Opened,
            0,
            "opened-b",
            &VerifiedHumanInteraction {
                nonce: "nonce-opened-b".into(),
                executor_ref: "ui".into(),
            },
            "explicit gesture",
            &mut act_alloc,
        )
        .await
        .unwrap();
        set_routing(
            &mut tx,
            &context,
            "message:b",
            "open",
            "human",
            Some("policy-v1"),
            0,
            "to-human-after-open",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM notification_candidates WHERE message_id='message:b' AND reason='human_obligation' AND status='effective'"
            )
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn invalid_batch_state_never_leaks_a_partial_event() {
        let db = crate::create_database(":memory:").await.unwrap();
        let context = MutationContext {
            subject_account_id: "acct:a",
            authenticated_actor: "acct:a",
            executor_kind: "agent",
            executor_ref: Some("run"),
            delegation_ref: None,
            reason_code: "claim",
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let error = set_agent_disposition(
            &mut tx,
            &context,
            "message:a",
            "resolved",
            0,
            "invalid",
            &[],
            &mut act_alloc,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("requires exact evidence"));
        tx.rollback().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM awareness_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            0
        );
    }

    #[test]
    fn bounded_two_message_two_device_agent_interleavings_preserve_lane_invariants() {
        #[derive(Clone, Copy)]
        enum Action {
            Present(usize),
            Ack(usize),
            AgentResolve(usize),
            Flag(usize),
        }
        let actions = [
            Action::Present(0),
            Action::Present(1),
            Action::Ack(0),
            Action::Ack(1),
            Action::AgentResolve(0),
            Action::AgentResolve(1),
            Action::Flag(0),
            Action::Flag(1),
        ];
        for a in actions {
            for b in actions {
                for c in actions {
                    for d in actions {
                        let mut human = [0_u8; 2];
                        let mut agent = [false; 2];
                        let mut attention = [false; 2];
                        for action in [a, b, c, d] {
                            let before = (human, agent, attention);
                            let target = match action {
                                Action::Present(i) => {
                                    human[i] = human[i].max(1);
                                    i
                                }
                                Action::Ack(i) => {
                                    human[i] = 3;
                                    i
                                }
                                Action::AgentResolve(i) => {
                                    agent[i] = true;
                                    i
                                }
                                Action::Flag(i) => {
                                    attention[i] = true;
                                    i
                                }
                            };
                            let other = 1 - target;
                            assert!(human[target] >= before.0[target]);
                            assert_eq!(human[other], before.0[other]);
                            assert_eq!(agent[other], before.1[other]);
                            assert_eq!(attention[other], before.2[other]);
                            if matches!(action, Action::AgentResolve(_)) {
                                assert_eq!(human, before.0);
                            }
                            if matches!(action, Action::Flag(_)) {
                                assert_eq!(human, before.0);
                                assert_eq!(agent, before.1);
                            }
                        }
                    }
                }
            }
        }
    }

    fn destination_context<'a>(account: &'a str, reason: &'a str) -> MutationContext<'a> {
        MutationContext {
            subject_account_id: account,
            authenticated_actor: account,
            executor_kind: "system",
            executor_ref: None,
            delegation_ref: None,
            reason_code: reason,
        }
    }

    #[tokio::test]
    async fn a_member_adds_removes_and_lists_their_destination_rail() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();

        // Absence is the meaningful default: nothing on the rail, version 0.
        assert!(list_destinations_on(&mut *tx, "acct:a", false)
            .await
            .unwrap()
            .is_empty());

        let added = set_destination(
            &mut tx,
            &destination_context("acct:a", "join the launch channel"),
            "collection:launch",
            DestinationAction::Add,
            0,
            "add-launch",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert_eq!(added["changed"], true);
        assert_eq!(added["version"], 1);
        assert_eq!(added["present"], true);
        assert_eq!(added["joined_by"], "explicit");

        set_destination(
            &mut tx,
            &destination_context("acct:a", "join the design channel"),
            "collection:design",
            DestinationAction::Add,
            0,
            "add-design",
            &mut act_alloc,
        )
        .await
        .unwrap();

        // Another member's rail is their own.
        set_destination(
            &mut tx,
            &destination_context("acct:b", "join the launch channel"),
            "collection:launch",
            DestinationAction::Add,
            0,
            "add-launch-b",
            &mut act_alloc,
        )
        .await
        .unwrap();

        let rail = list_destinations_on(&mut *tx, "acct:a", false)
            .await
            .unwrap();
        assert_eq!(rail.len(), 2);
        assert!(rail.iter().all(|entry| entry["present"] == true));
        let ids: Vec<&str> = rail
            .iter()
            .map(|entry| entry["collection_id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"collection:launch"));
        assert!(ids.contains(&"collection:design"));

        let removed = set_destination(
            &mut tx,
            &destination_context("acct:a", "leave the design channel"),
            "collection:design",
            DestinationAction::Remove,
            1,
            "remove-design",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert_eq!(removed["changed"], true);
        assert_eq!(removed["version"], 2);
        assert_eq!(removed["present"], false);

        let rail = list_destinations_on(&mut *tx, "acct:a", false)
            .await
            .unwrap();
        assert_eq!(rail.len(), 1);
        assert_eq!(rail[0]["collection_id"], "collection:launch");
        assert_eq!(rail[0]["present"], true);

        // The tombstone is readable on request, and it is the version — not
        // just the absence — that the caller came for. Removed entries sort
        // after the live rail because they have no `joined_at`.
        let full = list_destinations_on(&mut *tx, "acct:a", true)
            .await
            .unwrap();
        assert_eq!(full.len(), 2);
        assert_eq!(full[0]["collection_id"], "collection:launch");
        assert_eq!(full[1]["collection_id"], "collection:design");
        assert_eq!(full[1]["present"], false);
        assert_eq!(full[1]["version"], 2);
        assert_eq!(full[1]["joined_at"], Value::Null);

        // Removal is a tombstone, not a deletion: the version keeps counting,
        // which is what makes a later CAS meaningful.
        let retained: i64 = sqlx::query_scalar(
            "SELECT version FROM member_destinations
              WHERE subject_account_id='acct:a' AND collection_id='collection:design'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(retained, 2);

        // Every accepted mutation is one immutable event, and the removals are
        // events too — the log never shrinks.
        let events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM awareness_events WHERE lane='destination'")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(events, 4);
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn destination_idempotency_and_cas_match_the_message_lanes() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        set_destination(
            &mut tx,
            &destination_context("acct:a", "join"),
            "collection:launch",
            DestinationAction::Add,
            0,
            "same-key",
            &mut act_alloc,
        )
        .await
        .unwrap();

        // An exact retry is stable and appends nothing.
        let retry = set_destination(
            &mut tx,
            &destination_context("acct:a", "join"),
            "collection:launch",
            DestinationAction::Add,
            0,
            "same-key",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert_eq!(retry["idempotent"], true);
        assert_eq!(retry["changed"], false);
        assert_eq!(retry["version"], 1);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM awareness_events WHERE lane='destination'"
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
            1
        );

        // The same key for a different intent is refused, not silently reused.
        let reused = set_destination(
            &mut tx,
            &destination_context("acct:a", "leave"),
            "collection:launch",
            DestinationAction::Remove,
            1,
            "same-key",
            &mut act_alloc,
        )
        .await
        .unwrap_err();
        assert!(reused.to_string().contains("different intent"));

        // A stale expected_version loses.
        let stale = set_destination(
            &mut tx,
            &destination_context("acct:a", "leave"),
            "collection:launch",
            DestinationAction::Remove,
            0,
            "stale-remove",
            &mut act_alloc,
        )
        .await
        .unwrap_err();
        assert!(stale.to_string().contains("version conflict"));
        tx.commit().await.unwrap();
    }

    #[tokio::test]
    async fn the_destination_lane_rebuilds_exactly_from_its_events() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        for (collection, action, expected, key) in [
            ("collection:launch", DestinationAction::Add, 0, "a1"),
            ("collection:design", DestinationAction::Add, 0, "a2"),
            ("collection:design", DestinationAction::Remove, 1, "r1"),
            ("collection:design", DestinationAction::Add, 2, "a3"),
        ] {
            set_destination(
                &mut tx,
                &destination_context("acct:a", "rail"),
                collection,
                action,
                expected,
                key,
                &mut act_alloc,
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();

        let before: Vec<(String, i64, i64, String)> = sqlx::query_as(
            "SELECT collection_id,present,version,joined_by FROM member_destinations
              ORDER BY subject_account_id,collection_id",
        )
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        rebuild_projections(&db).await.unwrap();
        let after: Vec<(String, i64, i64, String)> = sqlx::query_as(
            "SELECT collection_id,present,version,joined_by FROM member_destinations
              ORDER BY subject_account_id,collection_id",
        )
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert_eq!(before, after);
        assert_eq!(before.len(), 2);
    }

    #[tokio::test]
    async fn sending_joins_once_and_a_retried_send_does_not_join_twice() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let first = auto_join_destination_on_send_in(
            &mut tx,
            "acct:a",
            "actor:a",
            "collection:launch",
            "event-1",
            &mut act_alloc,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(first["changed"], true);
        assert_eq!(first["joined_by"], "send");

        // The same send folded twice joins once.
        let retried = auto_join_destination_on_send_in(
            &mut tx,
            "acct:a",
            "actor:a",
            "collection:launch",
            "event-1",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert!(retried.is_none());

        // A second send into a Collection already on the rail appends nothing.
        assert!(auto_join_destination_on_send_in(
            &mut tx,
            "acct:a",
            "actor:a",
            "collection:launch",
            "event-2",
            &mut act_alloc,
        )
        .await
        .unwrap()
        .is_none());
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM awareness_events WHERE lane='destination'"
            )
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
            1
        );

        // Leaving and then sending again rejoins, under the version the
        // explicit removal left behind.
        set_destination(
            &mut tx,
            &destination_context("acct:a", "leave"),
            "collection:launch",
            DestinationAction::Remove,
            1,
            "leave-1",
            &mut act_alloc,
        )
        .await
        .unwrap();
        let rejoined = auto_join_destination_on_send_in(
            &mut tx,
            "acct:a",
            "actor:a",
            "collection:launch",
            "event-3",
            &mut act_alloc,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(rejoined["changed"], true);
        assert_eq!(rejoined["version"], 3);
        tx.commit().await.unwrap();
    }

    #[test]
    fn the_inbox_contract_carries_home_id_under_a_new_version() {
        let contract = messaging_surface_contract();
        assert_eq!(contract["schema"], MESSAGE_INBOX_SCHEMA);
        assert_eq!(contract["schema"], "native.message-inbox.v2");
        assert_ne!(MESSAGE_INBOX_SCHEMA, MESSAGE_INBOX_SCHEMA_V1);
        let fields: Vec<&str> = contract["item_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field.as_str().unwrap())
            .collect();
        assert!(fields.contains(&"home_id"));
        // An item without home_id is not a v2 item, even when every other
        // canonical field is present.
        let item = json!({
            "message_id":"m","name":"n","body":null,"created_at":"t","human":{},"agent":{},
            "obligation":{},"route":{},"mention":{},"attention":{},"delivery":{}
        });
        let response = json!({
            "schema":MESSAGE_INBOX_SCHEMA,"view":"browse","items":[item.clone()],
            "snapshot":"s","next_after":null,"newer_available":false,
            "heads":{"content":0,"awareness":0,"candidates":0,"control":0,"authorization":0},
            "counts_are_distinct_message_ids":true
        });
        let error = validate_messaging_surface_response(&response).unwrap_err();
        assert!(error.to_string().contains("home_id"));

        let mut complete = item;
        complete["home_id"] = json!(null);
        let mut response = response;
        response["items"] = json!([complete]);
        validate_messaging_surface_response(&response).unwrap();

        // A v1 schema string is no longer served, and is not accepted either.
        let mut stale = response;
        stale["schema"] = json!(MESSAGE_INBOX_SCHEMA_V1);
        assert!(validate_messaging_surface_response(&stale).is_err());
    }
}

#[cfg(test)]
mod guest_footing_tests {
    use super::*;

    #[tokio::test]
    async fn harvest_resolves_candidates_without_the_members_baseline_for_guests() {
        let db = crate::create_database(":memory:").await.unwrap();
        // A plain workspace document inherits the genesis members baseline:
        // members can view it, guests cannot.
        let record_id = "b4210000-0000-4000-8000-000000000001";
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": record_id,
                "type": "Document",
                "kind": "note",
                "name": "members-only",
                "home_id": "native:root",
            }),
        )
        .await
        .unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        append_notification_candidate_in(
            &mut tx,
            "acct:a",
            record_id,
            "human_obligation",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.created",
            "source:a",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let member = harvest_host_notification_candidates(&db, "acct:a", true, 0, 10)
            .await
            .unwrap();
        assert_eq!(member.candidates.len(), 1);
        let guest = harvest_host_notification_candidates(&db, "acct:a", false, 0, 10)
            .await
            .unwrap();
        assert!(
            guest.candidates.is_empty(),
            "guest footing must not match the members baseline"
        );

        let revalidated_member = revalidate_host_notification_candidate(
            &db,
            &member.candidates[0].candidate_id,
            "acct:a",
            true,
        )
        .await
        .unwrap();
        assert!(revalidated_member.is_some());
        let revalidated_guest = revalidate_host_notification_candidate(
            &db,
            &member.candidates[0].candidate_id,
            "acct:a",
            false,
        )
        .await
        .unwrap();
        assert!(
            revalidated_guest
                .as_ref()
                .is_none_or(|candidate| !candidate.effective_viewable_unmuted),
            "guest revalidation must not report a members-only message viewable"
        );
    }
}

#[cfg(test)]
mod fold_extraction_tests {
    use super::*;

    /// R3.0b: create the seven projection tables' expected copies, rebuild
    /// through the shared projectors, and require both directions of `EXCEPT`
    /// to be empty for every table. This is the same whole-table exactness the
    /// standby snapshot verifier uses, applied in-process.
    async fn assert_rebuild_matches_live(db: &crate::Db) {
        for table in REBUILD_PROJECTION_TABLES {
            sqlx::query(&format!(
                "CREATE TABLE _expected_{table} AS SELECT * FROM {table}"
            ))
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        rebuild_projections(db).await.unwrap();
        for table in REBUILD_PROJECTION_TABLES {
            for (left, right) in [
                (table.to_string(), format!("_expected_{table}")),
                (format!("_expected_{table}"), table.to_string()),
            ] {
                let drifted: i64 = sqlx::query_scalar(&format!(
                    "SELECT EXISTS(SELECT * FROM {left} EXCEPT SELECT * FROM {right})"
                ))
                .fetch_one(db.pool())
                .await
                .unwrap();
                assert_eq!(drifted, 0, "rebuild drifted projection table '{table}'");
            }
        }
    }

    /// R3.0b: the typed readers decode every live row, and the act-range readers
    /// select exactly the half-open `(from, to]` interval in `seq` order while
    /// excluding legacy NULL-act rows. Every stamped row comes from a real
    /// writer seam; the NULL rows are inserted narrow and schema-valid, exactly
    /// as a pre-cutover row would be.
    #[tokio::test]
    async fn act_range_readers_are_bounded_ordered_and_exclude_legacy_null_acts() {
        let db = crate::create_database(":memory:").await.unwrap();

        // Two awareness acts.
        for (version, stage, key) in [
            (0, HumanStage::Presented, "p"),
            (1, HumanStage::Opened, "o"),
        ] {
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let mut act_alloc = crate::act::ActAllocation::new();
            advance_human(
                &mut tx,
                "acct:range",
                "message:range",
                stage,
                version,
                key,
                &VerifiedHumanInteraction {
                    nonce: format!("nonce-{key}"),
                    executor_ref: "ui".into(),
                },
                "range",
                &mut act_alloc,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }

        // A candidate proposal and its withdrawal through the SQLite port:
        // two more acts.
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        append_notification_candidate_in(
            &mut tx,
            "acct:range",
            "message:range",
            "principal_mention",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.updated",
            "src:range",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        withdraw_message_candidates_in(
            &mut tx,
            "message:range",
            "record.updated",
            "src:withdraw",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // Legacy grouping-unknown rows in both logs.
        sqlx::query(
            "INSERT INTO awareness_events
               (id,idempotency_key,intent_sha256,schema_version,subject_account_id,message_id,
                destination_id,lane,action,authenticated_actor,executor_kind,expected_version,
                reason_code,payload,created_at,act)
             VALUES ('legacy-awareness','legacy-aware',?,1,'acct:range','message:legacy',
                     NULL,'preference','attention.flagged','acct:range','system',0,
                     'legacy',?,'2026-01-01T00:00:00.000Z',NULL)",
        )
        .bind("0".repeat(64))
        .bind(
            json!({"attention_flag":true,"muted":false,"snoozed_until":null,"archived":false})
                .to_string(),
        )
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO notification_candidate_events
               (id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,
                redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,
                payload,created_at,act)
             VALUES ('legacy-candidate','acct:legacy:message:legacy:principal_mention:src:legacy',
                     'withdrawn','acct:legacy','message:legacy','principal_mention','routine',NULL,
                     'metadata_only','portable_default','v1','record.updated','src:legacy',?,
                     '2026-01-01T00:00:00.000Z',NULL)",
        )
        .bind(json!({"schema":"native.notification-candidate.v1"}).to_string())
        .execute(db.write_pool())
        .await
        .unwrap();

        let mut conn = db.pool().acquire().await.unwrap();
        let awareness_full = read_all_awareness_events(&mut conn).await.unwrap();
        assert_eq!(
            awareness_full.len(),
            3,
            "two live events plus one legacy row"
        );
        assert!(awareness_full.iter().any(|event| event.act.is_none()));
        assert!(awareness_full.iter().any(|event| event.action == "opened"));

        let awareness_acts: Vec<(i64, Option<i64>)> =
            sqlx::query_as("SELECT seq, act FROM awareness_events ORDER BY seq")
                .fetch_all(&mut *conn)
                .await
                .unwrap();
        let (first_seq, first_act) = awareness_acts[0];
        let (last_seq, last_act) = awareness_acts[1];
        assert!(first_seq < last_seq);
        let first_act = first_act.expect("stamped first awareness event");
        let last_act = last_act.expect("stamped second awareness event");

        let bounded = awareness_events_in_act_range(&mut conn, first_act, last_act)
            .await
            .unwrap();
        assert_eq!(bounded.len(), 1, "the lower bound is exclusive");
        assert_eq!(bounded[0].seq, last_seq);
        assert_eq!(bounded[0].act, Some(last_act));
        let all_stamped = awareness_events_in_act_range(&mut conn, 0, i64::MAX)
            .await
            .unwrap();
        assert_eq!(all_stamped.len(), 2, "the NULL-act legacy row is excluded");
        assert!(all_stamped.windows(2).all(|pair| pair[0].seq < pair[1].seq));

        let candidates_full = read_all_notification_candidate_events(&mut conn)
            .await
            .unwrap();
        assert_eq!(
            candidates_full.len(),
            3,
            "proposal, withdrawal, and one legacy row"
        );
        let candidate_acts: Vec<(i64, Option<i64>)> =
            sqlx::query_as("SELECT seq, act FROM notification_candidate_events ORDER BY seq")
                .fetch_all(&mut *conn)
                .await
                .unwrap();
        let proposal_act = candidate_acts[0].1.expect("stamped proposal");
        let withdrawal_act = candidate_acts[1].1.expect("stamped withdrawal");
        let bounded =
            notification_candidate_events_in_act_range(&mut conn, proposal_act, withdrawal_act)
                .await
                .unwrap();
        assert_eq!(bounded.len(), 1, "the lower bound is exclusive");
        assert_eq!(bounded[0].action, "withdrawn");
        assert_eq!(bounded[0].act, Some(withdrawal_act));
        let all_stamped = notification_candidate_events_in_act_range(&mut conn, 0, i64::MAX)
            .await
            .unwrap();
        assert_eq!(all_stamped.len(), 2, "the NULL-act legacy row is excluded");
    }

    /// R3.0b: every live lane and both candidate transitions fold through the
    /// same projector the repair path uses, so a whole-log rebuild reproduces
    /// all seven projection tables exactly, including evidence rows, version
    /// counters, and the `last_event_seq` pointers.
    #[tokio::test]
    async fn live_projection_and_whole_log_rebuild_are_exact() {
        let db = crate::create_database(":memory:").await.unwrap();

        // A principal-mention candidate that the human-opened stage withdraws.
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        append_notification_candidate_in(
            &mut tx,
            "acct:x",
            "message:x",
            "principal_mention",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.created",
            "src:x",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // Routing creates a human-obligation candidate before the human opens.
        let policy_context = MutationContext {
            subject_account_id: "acct:x",
            authenticated_actor: "acct:x",
            executor_kind: "system",
            executor_ref: None,
            delegation_ref: None,
            reason_code: "route",
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        set_routing(
            &mut tx,
            &policy_context,
            "message:x",
            "open",
            "human",
            Some("policy-v1"),
            0,
            "route-open",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        for (version, stage, key) in [
            (0, HumanStage::Presented, "human-presented"),
            (1, HumanStage::Opened, "human-opened"),
        ] {
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let mut act_alloc = crate::act::ActAllocation::new();
            advance_human(
                &mut tx,
                "acct:x",
                "message:x",
                stage,
                version,
                key,
                &VerifiedHumanInteraction {
                    nonce: format!("nonce-{key}"),
                    executor_ref: "ui".into(),
                },
                "exact",
                &mut act_alloc,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }

        // A flag, a snooze (which schedules a due candidate), and a clear (which
        // withdraws it).
        let due = (chrono::Utc::now() + chrono::Duration::hours(2)).to_rfc3339();
        for (action, snooze, version, key) in [
            (PreferenceAction::FlagAttention, None, 0, "pref-flag"),
            (
                PreferenceAction::Snooze,
                Some(due.as_str()),
                1,
                "pref-snooze",
            ),
            (PreferenceAction::ClearSnooze, None, 2, "pref-clear"),
        ] {
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let mut act_alloc = crate::act::ActAllocation::new();
            set_preference(
                &mut tx,
                "acct:x",
                "message:x",
                action,
                snooze,
                version,
                key,
                "exact",
                &mut act_alloc,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }

        // An agent disposition with exact evidence.
        let agent_context = MutationContext {
            subject_account_id: "acct:x",
            authenticated_actor: "acct:x",
            executor_kind: "agent",
            executor_ref: Some("run"),
            delegation_ref: Some("delegation"),
            reason_code: "handled",
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        set_agent_disposition(
            &mut tx,
            &agent_context,
            "message:x",
            "resolved",
            0,
            "agent-resolve",
            &[EvidenceInput {
                record_id: "reply:x".into(),
                role: "reply".into(),
            }],
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // The destination lane: add then remove.
        let destination = MutationContext {
            subject_account_id: "acct:x",
            authenticated_actor: "acct:x",
            executor_kind: "system",
            executor_ref: None,
            delegation_ref: None,
            reason_code: "rail",
        };
        for (action, version, key) in [
            (DestinationAction::Add, 0, "dest-add"),
            (DestinationAction::Remove, 1, "dest-remove"),
        ] {
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let mut act_alloc = crate::act::ActAllocation::new();
            set_destination(
                &mut tx,
                &destination,
                "collection:exact",
                action,
                version,
                key,
                &mut act_alloc,
            )
            .await
            .unwrap();
            tx.commit().await.unwrap();
        }

        // A suppressed transition: no live writer emits it, so append the event
        // and fold it through the same projector the log would carry.
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        append_notification_candidate_in(
            &mut tx,
            "acct:y",
            "message:y",
            "human_obligation",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.created",
            "src:y",
            &mut act_alloc,
        )
        .await
        .unwrap();
        let act = act_alloc.get_or_allocate(&mut tx).await.unwrap();
        let created_at = crate::store::now_iso();
        let seq: i64 = sqlx::query_scalar(
            "INSERT INTO notification_candidate_events
               (id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,
                redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,
                payload,created_at,act)
             VALUES (?,?,'suppressed',?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq",
        )
        .bind("candidate-suppressed-exact")
        .bind("acct:y:message:y:human_obligation:src:y")
        .bind("acct:y")
        .bind("message:y")
        .bind("human_obligation")
        .bind("routine")
        .bind(Option::<String>::None)
        .bind("metadata_only")
        .bind("portable_default")
        .bind("v1")
        .bind("record.updated")
        .bind("src:suppressed")
        .bind(json!({"schema":"native.notification-candidate.v1"}).to_string())
        .bind(&created_at)
        .bind(act)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        let suppressed = read_all_notification_candidate_events(&mut tx)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.seq == seq)
            .expect("the suppressed event is readable");
        assert_eq!(suppressed.action, "suppressed");
        project_notification_candidate_event(&mut tx, &suppressed)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        assert_rebuild_matches_live(&db).await;
    }

    /// R3.0b: an exact retry short-circuits before the projector, so it appends
    /// no second event and advances no version counter.
    #[tokio::test]
    async fn idempotent_retry_does_not_double_project() {
        let db = crate::create_database(":memory:").await.unwrap();
        let attestation = VerifiedHumanInteraction {
            nonce: "retry-nonce".into(),
            executor_ref: "ui".into(),
        };

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        advance_human(
            &mut tx,
            "acct:i",
            "message:i",
            HumanStage::Acknowledged,
            0,
            "human-retry",
            &attestation,
            "retry",
            &mut act_alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let before: (String, i64, i64) = sqlx::query_as(
            "SELECT stage,version,last_event_seq FROM human_message_awareness
              WHERE subject_account_id='acct:i' AND message_id='message:i'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let retry = advance_human(
            &mut tx,
            "acct:i",
            "message:i",
            HumanStage::Acknowledged,
            0,
            "human-retry",
            &attestation,
            "retry",
            &mut act_alloc,
        )
        .await
        .unwrap();
        assert_eq!(retry["idempotent"], true);
        tx.commit().await.unwrap();
        let after: (String, i64, i64) = sqlx::query_as(
            "SELECT stage,version,last_event_seq FROM human_message_awareness
              WHERE subject_account_id='acct:i' AND message_id='message:i'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(before, after, "a retry must not re-fold the projection");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM awareness_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            1
        );

        // The candidate proposal is idempotent by `candidate_key`: the retry
        // returns the original id and writes nothing new.
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let first = append_notification_candidate_in(
            &mut tx,
            "acct:i",
            "message:i",
            "principal_mention",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.updated",
            "src:i",
            &mut act_alloc,
        )
        .await
        .unwrap()
        .unwrap();
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        let retried = append_notification_candidate_in(
            &mut tx,
            "acct:i",
            "message:i",
            "principal_mention",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.updated",
            "src:i",
            &mut act_alloc,
        )
        .await
        .unwrap()
        .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(first, retried);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM notification_candidate_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM notification_candidates")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            1
        );
    }

    /// R3.0b: the candidate fold names `suppressed` explicitly and fails closed
    /// on any other action rather than silently reinterpreting it.
    #[tokio::test]
    async fn candidate_suppressed_transition_is_explicit_and_unknown_action_fails_closed() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        append_notification_candidate_in(
            &mut tx,
            "acct:s",
            "message:s",
            "human_obligation",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.created",
            "src:s",
            &mut act_alloc,
        )
        .await
        .unwrap();
        let act = act_alloc.get_or_allocate(&mut tx).await.unwrap();
        sqlx::query(
            "INSERT INTO notification_candidate_events
               (id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,
                redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,
                payload,created_at,act)
             VALUES (?,?,'suppressed',?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind("candidate-suppressed")
        .bind("acct:s:message:s:human_obligation:src:s")
        .bind("acct:s")
        .bind("message:s")
        .bind("human_obligation")
        .bind("routine")
        .bind(Option::<String>::None)
        .bind("metadata_only")
        .bind("portable_default")
        .bind("v1")
        .bind("record.updated")
        .bind("src:suppressed")
        .bind(json!({"schema":"native.notification-candidate.v1"}).to_string())
        .bind(crate::store::now_iso())
        .bind(act)
        .execute(&mut *tx)
        .await
        .unwrap();
        let suppressed = read_all_notification_candidate_events(&mut tx)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.action == "suppressed")
            .expect("the suppressed event is readable");
        project_notification_candidate_event(&mut tx, &suppressed)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM notification_candidates WHERE candidate_key=?",
            )
            .bind("acct:s:message:s:human_obligation:src:s")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            "suppressed"
        );

        // The repair fold reaches the same suppressed state.
        rebuild_projections(&db).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT status FROM notification_candidates WHERE candidate_key=?",
            )
            .bind("acct:s:message:s:human_obligation:src:s")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            "suppressed"
        );

        let mut bogus = suppressed;
        bogus.action = "bogus".into();
        let mut conn = db.pool().acquire().await.unwrap();
        let error = project_notification_candidate_event(&mut conn, &bogus)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("unknown notification candidate action"));
    }

    /// R3.1 follow-up: the shared candidate projector fails closed when a
    /// withdrawal or suppression has no matching proposal projection, and a
    /// transition against an existing proposal stays a valid one-row update,
    /// including an exact retry.
    #[tokio::test]
    async fn candidate_transition_without_proposal_fails_closed() {
        let db = crate::create_database(":memory:").await.unwrap();
        let row = |action: &str, key: &str, seq: i64| NotificationCandidateEventRow {
            seq,
            id: format!("event-{seq}"),
            candidate_key: key.into(),
            action: action.into(),
            recipient_account_id: "acct:f".into(),
            message_id: "message:f".into(),
            reason: "human_obligation".into(),
            priority: "routine".into(),
            not_before: None,
            redaction_class: "metadata_only".into(),
            evaluator_kind: "portable_default".into(),
            policy_version: "v1".into(),
            source_event_type: "record.updated".into(),
            source_event_id: "src:f".into(),
            payload: json!({"schema": "native.notification-candidate.v1"}),
            created_at: crate::store::now_iso(),
            act: Some(1),
        };

        let mut conn = crate::db::begin_write(db.write_pool()).await.unwrap();
        for action in ["withdrawn", "suppressed"] {
            let error = project_notification_candidate_event(
                &mut conn,
                &row(action, "acct:f:message:f:human_obligation:absent", 2),
            )
            .await
            .unwrap_err();
            assert!(
                error.to_string().contains("exactly one existing proposal"),
                "{action} without a proposal must fail closed: {error}"
            );
        }
        conn.rollback().await.unwrap();

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        append_notification_candidate_in(
            &mut tx,
            "acct:f",
            "message:f",
            "human_obligation",
            "routine",
            None,
            "metadata_only",
            "portable_default",
            "v1",
            "record.updated",
            "src:f",
            &mut act_alloc,
        )
        .await
        .unwrap();
        let key: String = sqlx::query_scalar(
            "SELECT candidate_key FROM notification_candidates WHERE recipient_account_id='acct:f'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        project_notification_candidate_event(&mut tx, &row("withdrawn", &key, 99))
            .await
            .unwrap();
        // An exact retry of the same transition remains a valid one-row update.
        project_notification_candidate_event(&mut tx, &row("withdrawn", &key, 100))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let status: String =
            sqlx::query_scalar("SELECT status FROM notification_candidates WHERE candidate_key=?")
                .bind(&key)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(status, "withdrawn");
    }
}
