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
use sqlx::{Row, Sqlite};
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
#[doc(hidden)]
pub async fn harvest_host_notification_candidates(
    db: &crate::Db,
    recipient_account_id: &str,
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
            crate::authorization::Principal::bound(recipient_account_id, true),
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
#[doc(hidden)]
pub async fn revalidate_host_notification_candidate(
    db: &crate::Db,
    candidate_id: &str,
    recipient_account_id: &str,
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
        crate::authorization::Principal::bound(recipient_account_id, true),
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
        "SELECT id,seq,intent_sha256,expected_version,payload FROM awareness_events
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
) -> Result<(String, i64, bool)> {
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
        return Ok((existing.id, existing.seq, false));
    }
    let id = Uuid::new_v4().to_string();
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO awareness_events
           (id,idempotency_key,intent_sha256,schema_version,subject_account_id,message_id,
            destination_id,lane,action,authenticated_actor,executor_kind,executor_ref,
            delegation_ref,expected_version,reason_code,interaction_nonce,payload,created_at)
         VALUES (?,?,?,1,?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq",
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
    .bind(now_iso())
    .fetch_one(&mut **tx)
    .await?;
    Ok((id, seq, true))
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
    let (event_id, seq, inserted) = append_event(
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
    )
    .await?;
    if !inserted {
        return Ok(
            json!({"message_id":message_id,"stage":current_stage,"version":current_version,"changed":false,"idempotent":true}),
        );
    }
    let now = attained_at;
    let first_presented_at = row
        .as_ref()
        .and_then(|row| row.get::<Option<String>, _>("first_presented_at"))
        .or_else(|| Some(now.clone()));
    let last_presented_at = if stage.rank() >= HumanStage::Presented.rank() {
        Some(now.clone())
    } else {
        row.as_ref()
            .and_then(|row| row.get::<Option<String>, _>("last_presented_at"))
    };
    let opened_at = row
        .as_ref()
        .and_then(|row| row.get::<Option<String>, _>("opened_at"))
        .or_else(|| (stage.rank() >= HumanStage::Opened.rank()).then(|| now.clone()));
    let acknowledged_at = row
        .as_ref()
        .and_then(|row| row.get::<Option<String>, _>("acknowledged_at"))
        .or_else(|| (stage.rank() >= HumanStage::Acknowledged.rank()).then_some(now));
    let next_version = current_version + 1;
    sqlx::query(
        "INSERT INTO human_message_awareness
           (subject_account_id,message_id,stage,first_presented_at,last_presented_at,
            opened_at,acknowledged_at,last_event_seq,version)
         VALUES (?,?,?,?,?,?,?,?,?)
         ON CONFLICT(subject_account_id,message_id) DO UPDATE SET
           stage=excluded.stage,first_presented_at=excluded.first_presented_at,
           last_presented_at=excluded.last_presented_at,opened_at=excluded.opened_at,
           acknowledged_at=excluded.acknowledged_at,last_event_seq=excluded.last_event_seq,
           version=excluded.version",
    )
    .bind(account)
    .bind(message_id)
    .bind(next.stored())
    .bind(first_presented_at)
    .bind(last_presented_at)
    .bind(opened_at)
    .bind(acknowledged_at)
    .bind(seq)
    .bind(next_version)
    .execute(&mut **tx)
    .await?;
    if next.rank() >= HumanStage::Opened.rank() {
        withdraw_notification_candidates_in(
            tx,
            account,
            message_id,
            None,
            "awareness.human.opened",
            &event_id,
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
    sqlx::query(
        "INSERT INTO awareness_command_intents
           (subject_account_id,idempotency_key,intent_sha256,created_at)
         VALUES (?,?,?,?)",
    )
    .bind(account)
    .bind(idempotency_key)
    .bind(digest)
    .bind(now_iso())
    .execute(&mut **tx)
    .await?;
    Ok(true)
}

pub async fn set_agent_disposition(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    context: &MutationContext<'_>,
    message_id: &str,
    state: &str,
    expected_version: i64,
    idempotency_key: &str,
    evidence: &[EvidenceInput],
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
    let (event_id, seq, inserted) = append_event(
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
    )
    .await?;
    if !inserted {
        return Ok(
            json!({"message_id":message_id,"state":state,"version":current_version,"changed":false,"idempotent":true}),
        );
    }
    for item in evidence {
        if !matches!(
            item.role.as_str(),
            "reply" | "work" | "decision" | "resolution" | "other"
        ) {
            return Err(Error::engine("invalid awareness evidence role"));
        }
        sqlx::query(
            "INSERT INTO awareness_event_evidence(event_id,evidence_record_id,evidence_role)
             VALUES (?,?,?)",
        )
        .bind(&event_id)
        .bind(&item.record_id)
        .bind(&item.role)
        .execute(&mut **tx)
        .await?;
    }
    let next_version = current_version + 1;
    sqlx::query(
        "INSERT INTO agent_message_dispositions
           (subject_account_id,message_id,state,reason_code,last_executor_ref,delegation_ref,last_event_seq,version)
         VALUES (?,?,?,?,?,?,?,?)
         ON CONFLICT(subject_account_id,message_id) DO UPDATE SET
           state=excluded.state,reason_code=excluded.reason_code,
           last_executor_ref=excluded.last_executor_ref,delegation_ref=excluded.delegation_ref,
           last_event_seq=excluded.last_event_seq,version=excluded.version",
    )
    .bind(context.subject_account_id)
    .bind(message_id)
    .bind(state)
    .bind(context.reason_code)
    .bind(context.executor_ref)
    .bind(context.delegation_ref)
    .bind(seq)
    .bind(next_version)
    .execute(&mut **tx)
    .await?;
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
    let (event_id, seq, inserted) = append_event(
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
    )
    .await?;
    if !inserted {
        return Ok(
            json!({"message_id":message_id,"version":current_version,"changed":false,"idempotent":true}),
        );
    }
    let next_version = current_version + 1;
    sqlx::query(
        "INSERT INTO message_preferences
           (subject_account_id,message_id,attention_flag,muted,snoozed_until,archived,last_event_seq,version)
         VALUES (?,?,?,?,?,?,?,?)
         ON CONFLICT(subject_account_id,message_id) DO UPDATE SET
           attention_flag=excluded.attention_flag,muted=excluded.muted,
           snoozed_until=excluded.snoozed_until,archived=excluded.archived,
           last_event_seq=excluded.last_event_seq,version=excluded.version",
    )
    .bind(account)
    .bind(message_id)
    .bind(attention)
    .bind(muted)
    .bind(&snooze)
    .bind(archived)
    .bind(seq)
    .bind(next_version)
    .execute(&mut **tx)
    .await?;
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
            &event_id,
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
                &event_id,
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
    let (event_id, seq, inserted) = append_event(
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
    )
    .await?;
    if !inserted {
        return Ok(
            json!({"message_id":message_id,"version":current_version,"changed":false,"idempotent":true}),
        );
    }
    let next_version = current_version + 1;
    sqlx::query(
        "INSERT INTO message_inbox_routing
           (subject_account_id,message_id,obligation_state,executor_route,reason_code,policy_version,last_event_seq,version)
         VALUES (?,?,?,?,?,?,?,?)
         ON CONFLICT(subject_account_id,message_id) DO UPDATE SET
           obligation_state=excluded.obligation_state,executor_route=excluded.executor_route,
           reason_code=excluded.reason_code,policy_version=excluded.policy_version,
           last_event_seq=excluded.last_event_seq,version=excluded.version",
    )
    .bind(context.subject_account_id)
    .bind(message_id)
    .bind(obligation_state)
    .bind(executor_route)
    .bind(context.reason_code)
    .bind(policy_version)
    .bind(seq)
    .bind(next_version)
    .execute(&mut **tx)
    .await?;
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
            &event_id,
        )
        .await?;
    } else if !open_human {
        withdraw_notification_candidates_in(
            tx,
            context.subject_account_id,
            message_id,
            Some("human_obligation"),
            "awareness.routing.set",
            &event_id,
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
    let (_event_id, seq, inserted) = append_event(
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
    let next_version = current.version + 1;
    sqlx::query(
        "INSERT INTO member_destinations
           (subject_account_id,collection_id,present,joined_at,joined_by,last_event_seq,version)
         VALUES (?,?,?,?,?,?,?)
         ON CONFLICT(subject_account_id,collection_id) DO UPDATE SET
           present=excluded.present,joined_at=excluded.joined_at,joined_by=excluded.joined_by,
           last_event_seq=excluded.last_event_seq,version=excluded.version",
    )
    .bind(account)
    .bind(collection_id)
    .bind(present)
    .bind(&joined_at)
    .bind(&joined_by)
    .bind(seq)
    .bind(next_version)
    .execute(&mut **tx)
    .await?;
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
) -> Result<Value> {
    apply_destination(
        tx,
        context,
        collection_id,
        action,
        "explicit",
        expected_version,
        idempotency_key,
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
    let seq: i64 = sqlx::query_scalar(
        "INSERT INTO notification_candidate_events
           (id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,
            redaction_class,evaluator_kind,policy_version,source_event_type,
            source_event_id,payload,created_at)
         VALUES (?,?,'proposed',?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq",
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
    .bind(now_iso())
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query(
        "INSERT INTO notification_candidates
           (candidate_id,candidate_key,recipient_account_id,message_id,reason,priority,not_before,
            redaction_class,evaluator_kind,policy_version,source_event_type,
            source_event_id,candidate_event_seq,status,created_at)
         SELECT id,candidate_key,recipient_account_id,message_id,reason,priority,not_before,
                redaction_class,evaluator_kind,policy_version,source_event_type,
                source_event_id,seq,'effective',created_at
           FROM notification_candidate_events WHERE seq=?",
    )
    .bind(seq)
    .execute(&mut **tx)
    .await?;
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
            Ok(sqlx::query_scalar("INSERT INTO notification_candidate_events(id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at) VALUES(?,?,'withdrawn',?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq")
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
            sqlx::query("UPDATE notification_candidates SET status='withdrawn',candidate_event_seq=? WHERE candidate_id=?")
                .bind(event_seq)
                .bind(candidate_id)
                .execute(&mut **self.tx)
                .await?;
            Ok(())
        })
    }
}

pub async fn withdraw_message_candidates_in(
    tx: &mut sqlx::Transaction<'static, Sqlite>,
    message_id: &str,
    source_event_type: &str,
    source_event_id: &str,
) -> Result<usize> {
    let mut port = SqliteCandidateWithdrawalPort { tx };
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
        withdraw_message_candidates_in(tx, &target_id, source_event_type, source_event_id).await?;
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
) -> Result<usize> {
    let rows=sqlx::query("SELECT candidate_id,candidate_key,recipient_account_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version FROM notification_candidates WHERE message_id=? AND status='effective' AND (?='%' OR recipient_account_id=?) AND (? IS NULL OR reason=?)")
        .bind(message_id).bind(recipient_account).bind(recipient_account).bind(reason).bind(reason)
        .fetch_all(&mut **tx).await?;
    for row in &rows {
        let id = Uuid::new_v4().to_string();
        let seq:i64=sqlx::query_scalar("INSERT INTO notification_candidate_events(id,candidate_key,action,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,payload,created_at) VALUES(?,?,'withdrawn',?,?,?,?,?,?,?,?,?,?,?,?) RETURNING seq")
            .bind(id).bind(row.try_get::<String,_>("candidate_key")?).bind(row.try_get::<String,_>("recipient_account_id")?).bind(message_id)
            .bind(row.try_get::<String,_>("reason")?).bind(row.try_get::<String,_>("priority")?).bind(row.try_get::<Option<String>,_>("not_before")?)
            .bind(row.try_get::<String,_>("redaction_class")?).bind(row.try_get::<String,_>("evaluator_kind")?).bind(row.try_get::<String,_>("policy_version")?)
            .bind(source_event_type).bind(source_event_id).bind("{\"schema\":\"native.notification-candidate.v1\"}").bind(now_iso()).fetch_one(&mut **tx).await?;
        sqlx::query("UPDATE notification_candidates SET status='withdrawn',candidate_event_seq=? WHERE candidate_id=?")
            .bind(seq).bind(row.try_get::<String,_>("candidate_id")?).execute(&mut **tx).await?;
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
    let events=sqlx::query("SELECT id,seq,subject_account_id,message_id,destination_id,lane,action,reason_code,executor_ref,delegation_ref,payload,created_at FROM awareness_events ORDER BY seq").fetch_all(&mut *tx).await?;
    for event in events {
        let lane: String = event.try_get("lane")?;
        let account: String = event.try_get("subject_account_id")?;
        // Lane-determined subject: the four Message lanes read `message_id`,
        // the destination lane reads `destination_id`. The DDL's paired CHECKs
        // mean exactly one is present, so a wrong read is a fold failure rather
        // than a silently mis-keyed projection row.
        let message: String = event
            .try_get::<Option<String>, _>("message_id")?
            .unwrap_or_default();
        let seq: i64 = event.try_get("seq")?;
        let payload: Value = serde_json::from_str(&event.try_get::<String, _>("payload")?)?;
        match lane.as_str() {
            "human" => {
                let stage = payload["stage"]
                    .as_str()
                    .ok_or_else(|| Error::engine("invalid human replay payload"))?;
                let now = payload["attained_at"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or(event.try_get("created_at")?);
                let current:Option<(String,i64,Option<String>,Option<String>)>=sqlx::query_as("SELECT stage,version,opened_at,acknowledged_at FROM human_message_awareness WHERE subject_account_id=? AND message_id=?").bind(&account).bind(&message).fetch_optional(&mut *tx).await?;
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
                    .or_else(|| {
                        (requested.rank() >= HumanStage::Opened.rank()).then(|| now.clone())
                    });
                let acknowledged_at =
                    current
                        .as_ref()
                        .and_then(|value| value.3.clone())
                        .or_else(|| {
                            (requested.rank() >= HumanStage::Acknowledged.rank())
                                .then(|| now.clone())
                        });
                sqlx::query("INSERT INTO human_message_awareness(subject_account_id,message_id,stage,first_presented_at,last_presented_at,opened_at,acknowledged_at,last_event_seq,version) VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(subject_account_id,message_id) DO UPDATE SET stage=excluded.stage,last_presented_at=excluded.last_presented_at,opened_at=excluded.opened_at,acknowledged_at=excluded.acknowledged_at,last_event_seq=excluded.last_event_seq,version=excluded.version").bind(&account).bind(&message).bind(next.stored()).bind(&now).bind(&now).bind(opened_at).bind(acknowledged_at).bind(seq).bind(version).execute(&mut *tx).await?;
            }
            "agent" => {
                let state = payload["state"]
                    .as_str()
                    .ok_or_else(|| Error::engine("invalid agent replay payload"))?;
                let version: i64=sqlx::query_scalar("SELECT version FROM agent_message_dispositions WHERE subject_account_id=? AND message_id=?").bind(&account).bind(&message).fetch_optional(&mut *tx).await?.unwrap_or(0)+1;
                sqlx::query("INSERT INTO agent_message_dispositions(subject_account_id,message_id,state,reason_code,last_executor_ref,delegation_ref,last_event_seq,version) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(subject_account_id,message_id) DO UPDATE SET state=excluded.state,reason_code=excluded.reason_code,last_executor_ref=excluded.last_executor_ref,delegation_ref=excluded.delegation_ref,last_event_seq=excluded.last_event_seq,version=excluded.version").bind(&account).bind(&message).bind(state).bind(event.try_get::<String,_>("reason_code")?).bind(event.try_get::<Option<String>,_>("executor_ref")?).bind(event.try_get::<Option<String>,_>("delegation_ref")?).bind(seq).bind(version).execute(&mut *tx).await?;
                for evidence in payload["evidence"].as_array().into_iter().flatten() {
                    sqlx::query("INSERT INTO awareness_event_evidence(event_id,evidence_record_id,evidence_role) VALUES(?,?,?)").bind(event.try_get::<String,_>("id")?).bind(evidence["record_id"].as_str()).bind(evidence["role"].as_str()).execute(&mut *tx).await?;
                }
            }
            "preference" => {
                let version:i64=sqlx::query_scalar("SELECT version FROM message_preferences WHERE subject_account_id=? AND message_id=?").bind(&account).bind(&message).fetch_optional(&mut *tx).await?.unwrap_or(0)+1;
                sqlx::query("INSERT INTO message_preferences(subject_account_id,message_id,attention_flag,muted,snoozed_until,archived,last_event_seq,version) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(subject_account_id,message_id) DO UPDATE SET attention_flag=excluded.attention_flag,muted=excluded.muted,snoozed_until=excluded.snoozed_until,archived=excluded.archived,last_event_seq=excluded.last_event_seq,version=excluded.version").bind(&account).bind(&message).bind(payload["attention_flag"].as_bool()).bind(payload["muted"].as_bool()).bind(payload["snoozed_until"].as_str()).bind(payload["archived"].as_bool()).bind(seq).bind(version).execute(&mut *tx).await?;
            }
            "routing" => {
                let version:i64=sqlx::query_scalar("SELECT version FROM message_inbox_routing WHERE subject_account_id=? AND message_id=?").bind(&account).bind(&message).fetch_optional(&mut *tx).await?.unwrap_or(0)+1;
                sqlx::query("INSERT INTO message_inbox_routing(subject_account_id,message_id,obligation_state,executor_route,reason_code,policy_version,last_event_seq,version) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(subject_account_id,message_id) DO UPDATE SET obligation_state=excluded.obligation_state,executor_route=excluded.executor_route,reason_code=excluded.reason_code,policy_version=excluded.policy_version,last_event_seq=excluded.last_event_seq,version=excluded.version").bind(&account).bind(&message).bind(payload["obligation_state"].as_str()).bind(payload["executor_route"].as_str()).bind(event.try_get::<String,_>("reason_code")?).bind(payload["policy_version"].as_str()).bind(seq).bind(version).execute(&mut *tx).await?;
            }
            "destination" => {
                let collection: String = event
                    .try_get::<Option<String>, _>("destination_id")?
                    .ok_or_else(|| Error::engine("destination event without a destination_id"))?;
                let version: i64 = sqlx::query_scalar("SELECT version FROM member_destinations WHERE subject_account_id=? AND collection_id=?").bind(&account).bind(&collection).fetch_optional(&mut *tx).await?.unwrap_or(0)+1;
                sqlx::query("INSERT INTO member_destinations(subject_account_id,collection_id,present,joined_at,joined_by,last_event_seq,version) VALUES(?,?,?,?,?,?,?) ON CONFLICT(subject_account_id,collection_id) DO UPDATE SET present=excluded.present,joined_at=excluded.joined_at,joined_by=excluded.joined_by,last_event_seq=excluded.last_event_seq,version=excluded.version").bind(&account).bind(&collection).bind(payload["present"].as_bool()).bind(payload["joined_at"].as_str()).bind(payload["joined_by"].as_str()).bind(seq).bind(version).execute(&mut *tx).await?;
            }
            _ => return Err(Error::engine("unknown awareness replay lane")),
        }
    }
    let candidates = sqlx::query("SELECT * FROM notification_candidate_events ORDER BY seq")
        .fetch_all(&mut *tx)
        .await?;
    for event in candidates {
        let action: String = event.try_get("action")?;
        if action == "proposed" {
            sqlx::query("INSERT INTO notification_candidates(candidate_id,candidate_key,recipient_account_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,source_event_type,source_event_id,candidate_event_seq,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'effective',?)").bind(event.try_get::<String,_>("id")?).bind(event.try_get::<String,_>("candidate_key")?).bind(event.try_get::<String,_>("recipient_account_id")?).bind(event.try_get::<String,_>("message_id")?).bind(event.try_get::<String,_>("reason")?).bind(event.try_get::<String,_>("priority")?).bind(event.try_get::<Option<String>,_>("not_before")?).bind(event.try_get::<String,_>("redaction_class")?).bind(event.try_get::<String,_>("evaluator_kind")?).bind(event.try_get::<String,_>("policy_version")?).bind(event.try_get::<String,_>("source_event_type")?).bind(event.try_get::<String,_>("source_event_id")?).bind(event.try_get::<i64,_>("seq")?).bind(event.try_get::<String,_>("created_at")?).execute(&mut *tx).await?;
        } else {
            sqlx::query("UPDATE notification_candidates SET status=?,candidate_event_seq=? WHERE candidate_key=?").bind(if action=="withdrawn"{"withdrawn"}else{"suppressed"}).bind(event.try_get::<i64,_>("seq")?).bind(event.try_get::<String,_>("candidate_key")?).execute(&mut *tx).await?;
        }
    }
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
        let first = advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Acknowledged,
            0,
            "same-key",
            &attestation,
            "explicit review",
        )
        .await
        .unwrap();
        assert_eq!(first["changed"], true);
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
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
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let retry = advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Acknowledged,
            0,
            "same-key",
            &attestation,
            "explicit review",
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
        let error = advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Opened,
            1,
            "same-key",
            &attestation,
            "different",
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("different intent"));
    }

    #[tokio::test]
    async fn lanes_preferences_and_delivery_facts_are_independent_and_rebuildable() {
        let db = crate::create_database(":memory:").await.unwrap();
        let attestation = VerifiedHumanInteraction {
            nonce: "nonce-human".into(),
            executor_ref: "ui".into(),
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        advance_human(
            &mut tx,
            "acct:a",
            "message:a",
            HumanStage::Acknowledged,
            0,
            "human",
            &attestation,
            "read",
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
        set_preference(
            &mut tx,
            "acct:a",
            "message:a",
            PreferenceAction::ClearSnooze,
            None,
            1,
            "clear-snooze",
            "review now",
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
            advance_human(
                &mut tx,
                "acct:a",
                "message:a",
                stage,
                version,
                key,
                &attestation,
                "explicit gesture",
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
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
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
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
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
        set_preference(
            &mut tx,
            "acct:a",
            "message:a",
            PreferenceAction::Mute,
            None,
            0,
            "mute",
            "quiet",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        set_preference(
            &mut tx,
            "acct:a",
            "message:a",
            PreferenceAction::FlagAttention,
            None,
            1,
            "flag",
            "important",
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let retry = set_preference(
            &mut tx,
            "acct:a",
            "message:a",
            PreferenceAction::Mute,
            None,
            0,
            "mute",
            "quiet",
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
        set_agent_disposition(
            &mut tx,
            &agent,
            "message:a",
            "triaged",
            0,
            "agent-first",
            &[],
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
        set_routing(
            &mut tx,
            &routing,
            "message:b",
            "open",
            "human",
            Some("policy-v1"),
            0,
            "routing-first",
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
        set_routing(
            &mut tx,
            &context,
            "message:a",
            "open",
            "agent",
            Some("policy-v2"),
            1,
            "to-agent",
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
        let error = set_agent_disposition(
            &mut tx,
            &context,
            "message:a",
            "resolved",
            0,
            "invalid",
            &[],
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
        set_destination(
            &mut tx,
            &destination_context("acct:a", "join"),
            "collection:launch",
            DestinationAction::Add,
            0,
            "same-key",
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
        let first = auto_join_destination_on_send_in(
            &mut tx,
            "acct:a",
            "actor:a",
            "collection:launch",
            "event-1",
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
        )
        .await
        .unwrap();
        let rejoined = auto_join_destination_on_send_in(
            &mut tx,
            "acct:a",
            "actor:a",
            "collection:launch",
            "event-3",
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
