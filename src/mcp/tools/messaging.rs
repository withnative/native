//! Message-first Conversation operations.
//!
//! Conversations classify Messages; they never authorize them. Initial Message
//! audience is sealed at creation, while a history share appends an explicit
//! visibility fact and a record-local policy grant in one transaction.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::authorization::{AllowEntry, Capability};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::{LinkAddedPayload, LinkRemovedPayload, MessageSharedPayload};
use crate::store::{append_in, AppendSpec};

#[path = "messaging_inbox_identity.rs"]
mod inbox_identity;

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{
    can_record, can_record_in, echo_act, parse_args, require_nonblank_reason, require_record_in,
    REASON_DESCRIPTION,
};

// Missing means no claim; explicit null is an invalid supplied claim.
fn deserialize_speaker_claim<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
// This is the transport contract's closed action union. Boxing the Send
// fields solely to equalize in-memory variant sizes would complicate its
// generated schema and every dispatch arm without reducing request payloads.
#[allow(clippy::large_enum_variant)]
enum ManageMessagesArgs {
    Send {
        #[serde(default)]
        id: Option<String>,
        body: String,
        #[serde(default, deserialize_with = "deserialize_speaker_claim")]
        speaker: Option<Value>,
        #[serde(default)]
        preview: Option<String>,
        #[serde(default)]
        name: Option<String>,
        addressed_to: Vec<String>,
        origin: super::lifecycle::MessageOriginInput,
        expectation: String,
        #[serde(default)]
        home_id: Option<String>,
        #[serde(default)]
        owner_id: Option<String>,
        #[serde(default)]
        links: Option<Value>,
        #[serde(default)]
        mentions: Option<Vec<crate::awareness::MentionInput>>,
        idempotency_key: String,
        reason: String,
    },
    ListContext {
        origin: super::lifecycle::MessageOriginInput,
        #[serde(default = "default_context_limit")]
        limit: usize,
        #[serde(default)]
        cursor: Option<String>,
    },
    Classify {
        message_id: String,
        conversation_id: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    Unclassify {
        message_id: String,
        conversation_id: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    Move {
        message_id: String,
        from_conversation_id: String,
        to_conversation_id: String,
        #[serde(default)]
        idempotency_key: Option<String>,
    },
    ShareHistory {
        recipient_id: String,
        #[serde(default)]
        message_ids: Option<Vec<String>>,
        #[serde(default)]
        conversation_id: Option<String>,
        #[serde(default)]
        snapshot_seq: Option<i64>,
        reason: String,
        /// Parsed only so a key is refused by name, not as an unknown field.
        #[serde(default)]
        idempotency_key: Option<Value>,
    },
    AddReaction {
        message_id: String,
        emoji: String,
        idempotency_key: String,
        reason: String,
    },
    RemoveReaction {
        message_id: String,
        emoji: String,
        idempotency_key: String,
        reason: String,
    },
    SatisfyAcknowledgementExpectationWithReaction {
        message_id: String,
        idempotency_key: String,
        reason: String,
    },
    MarkNoLongerRelevant {
        message_id: String,
        #[serde(default)]
        note: Option<String>,
        idempotency_key: String,
        reason: String,
    },
    UnmarkNoLongerRelevant {
        message_id: String,
        idempotency_key: String,
        reason: String,
    },
    /// Author-only replacement of one Message's text; earlier text stays in
    /// stored history. `mentions`, when given, re-spans mentions of people the
    /// Message already mentions; it cannot add a new mention target.
    Edit {
        message_id: String,
        body: String,
        #[serde(default)]
        mentions: Option<Vec<crate::awareness::MentionInput>>,
        idempotency_key: String,
        reason: String,
    },
    /// Author-only tombstone of one Message; the body stays in stored history.
    Delete {
        message_id: String,
        idempotency_key: String,
        reason: String,
    },
    ListMessageState {
        message_ids: Vec<String>,
    },
    ListConversation {
        conversation_id: String,
    },
    ListUnclassified,
    ListMyConversations,
    MutateHumanAwareness {
        message_ids: Vec<String>,
        stage: crate::awareness::HumanStage,
        expected_versions: BTreeMap<String, i64>,
        idempotency_key: String,
        #[serde(default)]
        snapshot: Option<String>,
        reason: String,
    },
    SetAgentDisposition {
        message_id: String,
        state: String,
        expected_version: i64,
        idempotency_key: String,
        #[serde(default)]
        evidence: Vec<crate::awareness::EvidenceInput>,
        reason: String,
    },
    SetPreference {
        message_id: String,
        preference: crate::awareness::PreferenceAction,
        #[serde(default)]
        snoozed_until: Option<String>,
        expected_version: i64,
        idempotency_key: String,
        reason: String,
    },
    SetRouting {
        message_id: String,
        obligation_state: String,
        executor_route: String,
        #[serde(default)]
        policy_version: Option<String>,
        expected_version: i64,
        idempotency_key: String,
        reason: String,
    },
    ListInbox {
        #[serde(default = "default_inbox_view")]
        view: String,
        #[serde(default)]
        conversation_id: Option<String>,
        #[serde(default = "default_inbox_limit")]
        limit: usize,
        #[serde(default)]
        snapshot: Option<String>,
        #[serde(default)]
        after: Option<usize>,
        /// `"direct"` narrows the inbox to the viewer's own direct contexts
        /// before visibility and hydration (see `direct_scope_candidates`).
        #[serde(default)]
        scope: Option<String>,
        /// Truncate each `body` to this many characters (`body_truncated`
        /// says whether it was cut). Default 360 with `scope:"direct"`;
        /// otherwise the full body, as before.
        #[serde(default)]
        preview_chars: Option<usize>,
    },
    SetDestination {
        collection_id: String,
        destination: String,
        expected_version: i64,
        idempotency_key: String,
        reason: String,
    },
    ListDestinations {
        #[serde(default)]
        include_removed: bool,
    },
    ListNotificationCandidates {
        #[serde(default)]
        after_seq: i64,
        #[serde(default = "default_inbox_limit")]
        limit: usize,
    },
    GetAttention,
    GetNotificationPreference,
    SetNotificationPreference {
        arrival: String,
        idempotency_key: String,
        reason: String,
    },
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn validate_kernel_arguments(arguments: &Value) -> Result<()> {
    let _: ManageMessagesArgs = parse_args("manage_messages", arguments.clone())?;
    Ok(())
}

/// Cut an item's `body` to `limit` characters and say whether it was cut.
/// (`body_preview` semantics: characters, never a split code point.)
pub(crate) fn apply_preview(item: &mut Value, limit: usize) {
    let Some(body) = item["body"].as_str() else {
        item["body_truncated"] = json!(false);
        return;
    };
    match body.char_indices().nth(limit) {
        Some((cut, _)) => {
            let clipped = body[..cut].to_owned();
            item["body"] = json!(clipped);
            item["body_truncated"] = json!(true);
        }
        None => item["body_truncated"] = json!(false),
    }
}

fn default_inbox_view() -> String {
    "needs_me".into()
}
fn default_inbox_limit() -> usize {
    50
}
fn default_context_limit() -> usize {
    200
}

#[derive(Debug, Serialize, Deserialize)]
struct ContextCursor {
    schema: u8,
    account_id: String,
    context_key: String,
    created_at: String,
    message_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InboxSnapshot {
    schema: u8,
    database_id: String,
    account_id: String,
    view: String,
    conversation_id: Option<String>,
    content_head: i64,
    awareness_head: i64,
    candidate_head: i64,
    control_head: i64,
    authorization_revision: i64,
    items: Vec<Value>,
    /// `Some("direct")` for a scoped inbox; binds the cursor like `view`.
    #[serde(default)]
    scope: Option<String>,
    /// The scoped candidate set hit `DIRECT_SCOPE_CANDIDATE_CAP` and dropped
    /// the oldest messages.
    #[serde(default)]
    truncated: bool,
}

/// Most direct-scope candidates one snapshot will consider. Newest first, so
/// truncation drops the oldest; it is always disclosed in the response.
pub(crate) const DIRECT_SCOPE_CANDIDATE_CAP: usize = 2000;
pub(crate) const DIRECT_SCOPE_DEFAULT_PREVIEW_CHARS: usize = 360;

#[cfg(test)]
thread_local! {
    /// Test-only override of the candidate cap (tokio tests are single-thread).
    pub(crate) static DIRECT_SCOPE_CAP_OVERRIDE: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
}

pub(crate) fn direct_scope_cap() -> usize {
    #[cfg(test)]
    if let Some(cap) = DIRECT_SCOPE_CAP_OVERRIDE.with(std::cell::Cell::get) {
        return cap;
    }
    DIRECT_SCOPE_CANDIDATE_CAP
}
pub(crate) const MAX_PREVIEW_CHARS: usize = 1000;

/// Test seam: runs inside the page read transaction, after authorization and
/// before hydration, so a test can land a revocation and edit exactly there.
#[cfg(test)]
type PageSeam = std::sync::Arc<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync,
>;
#[cfg(test)]
thread_local! {
    pub(crate) static INBOX_PAGE_SEAM: std::cell::RefCell<Option<PageSeam>> =
        const { std::cell::RefCell::new(None) };
}

fn decode_snapshot(db: &Db, raw: &str) -> Result<InboxSnapshot> {
    let snapshot: InboxSnapshot = serde_json::from_value(db.get_inbox_snapshot(raw)?)
        .map_err(|_| Error::engine("cursor_reset_required: invalid inbox snapshot"))?;
    if snapshot.schema != 1 {
        return Err(Error::engine(
            "cursor_reset_required: invalid inbox snapshot",
        ));
    }
    Ok(snapshot)
}

/// Validate a classification action's optional key. Blank means no key.
fn classification_key(action: &str, key: Option<&str>) -> Result<bool> {
    Ok(super::keyed_replay::idempotency_key(&format!("manage_messages.{action}"), key)?.is_some())
}

/// `share_history` is not wired for keys, so a key is refused by name, and
/// before any work, rather than as an unknown field. A null or blank key is no
/// key, as everywhere else.
///
/// It cannot be keyed as written: it reserves one keyed attestation per shared
/// message inside a single transaction, and the authority index allows one per
/// command. More fundamentally its receipt carries `snapshot_seq`, the live
/// log head when the call ran, and `unchanged` messages leave no event, so a
/// replay could not reproduce the first call's receipt. It does not need a key
/// to be safe to retry: the grant id derives from the recipient and the exact
/// message set, so a repeat grants nothing twice and answers `unchanged`.
fn refuse_share_history_key(key: Option<&Value>) -> Result<()> {
    let blank = match key {
        None | Some(Value::Null) => true,
        Some(Value::String(key)) => key.trim().is_empty(),
        Some(_) => false,
    };
    if blank {
        Ok(())
    } else {
        Err(Error::engine(
            "manage_messages.share_history does not accept idempotency_key; retry without a key (it is already safe to repeat: a repeated share grants nothing twice)",
        ))
    }
}

/// What a classification action's replay must rebuild.
enum ClassificationReplay<'a> {
    Classify(&'a str),
    Unclassify(&'a str),
    Move { from: &'a str, to: &'a str },
}

/// Keyed replay for classify / unclassify / move (contract steps 2 and 3).
/// Returns the original receipt, with the attestation to settle once the
/// caller has rolled back, when this key already committed; `None` on a miss.
async fn replay_classification(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    provenance_arguments: Option<&Value>,
    message_id: &str,
    kind: ClassificationReplay<'_>,
) -> Result<Option<(Value, super::keyed_replay::KeyedReplay)>> {
    let arguments = provenance_arguments.ok_or_else(|| {
        Error::engine("manage_messages: keyed classification lost its dispatched arguments")
    })?;
    let Some(replay) =
        super::keyed_replay::keyed_replay_in(tx, caller, "manage_messages", arguments).await?
    else {
        return Ok(None);
    };
    // An anchor is a keyed no-op: nothing was classified or removed.
    let receipt = match kind {
        ClassificationReplay::Classify(conversation_id) => {
            if replay.is_noop() {
                json!({"status":"unchanged","message_id":message_id,"conversation_id":conversation_id,"changed":false})
            } else {
                json!({"status":"classified","message_id":message_id,"conversation_id":conversation_id,"changed":true})
            }
        }
        ClassificationReplay::Unclassify(conversation_id) => {
            if replay.is_noop() {
                json!({"status":"unchanged","message_id":message_id,"conversation_id":conversation_id,"changed":false})
            } else {
                json!({"status":"unclassified","message_id":message_id,"conversation_id":conversation_id,"changed":true})
            }
        }
        ClassificationReplay::Move { from, to } => {
            if replay.is_noop() {
                return Err(Error::engine(
                    "manage_messages: idempotent receipt is incomplete",
                ));
            }
            json!({"status":"moved","message_id":message_id,"from_conversation_id":from,"to_conversation_id":to,"changed":true})
        }
    };
    let receipt = echo_act(receipt, replay.act())?;
    Ok(Some((receipt, replay)))
}

async fn relation_exists(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    message_id: &str,
    conversation_id: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM message_conversations
          WHERE message_id=? AND conversation_id=?)",
    )
    .bind(message_id)
    .bind(conversation_id)
    .fetch_one(&mut **tx)
    .await?)
}

async fn append_classification(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
    conversation_id: &str,
    add: bool,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<()> {
    let spec = if add {
        AppendSpec {
            record_id: message_id.into(),
            event_type: "link.added".into(),
            payload: serde_json::to_value(LinkAddedPayload {
                id: None,
                source_id: message_id.into(),
                target_id: conversation_id.into(),
                relationship: "participates_in".into(),
                note: None,
            })?,
            actor: Some(caller.actor().into()),
        }
    } else {
        AppendSpec {
            record_id: message_id.into(),
            event_type: "link.removed".into(),
            payload: serde_json::to_value(LinkRemovedPayload {
                source_id: message_id.into(),
                target_id: conversation_id.into(),
                relationship: "participates_in".into(),
            })?,
            actor: Some(caller.actor().into()),
        }
    };
    append_in(db, tx, spec, act_alloc).await?;
    Ok(())
}

async fn require_classification_authority(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
    conversation_id: &str,
) -> Result<()> {
    require_record_in(tx, caller, "manage_messages", message_id, Capability::Edit).await?;
    require_record_in(
        tx,
        caller,
        "manage_messages",
        conversation_id,
        Capability::View,
    )
    .await
}

fn capability(value: &str) -> Result<Capability> {
    match value {
        "view" => Ok(Capability::View),
        "edit" => Ok(Capability::Edit),
        "manage" => Ok(Capability::Manage),
        other => Err(Error::engine(format!(
            "unsupported stored policy capability '{other}'"
        ))),
    }
}

async fn policy_entries_with_recipient(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    message_id: &str,
    recipient_account: &str,
) -> Result<Vec<AllowEntry>> {
    let explicit: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM record_policies WHERE record_id=?)")
            .bind(message_id)
            .fetch_one(&mut **tx)
            .await?;
    if !explicit {
        return Err(Error::engine(format!(
            "Message {message_id} has no record-local policy boundary"
        )));
    }
    let mut entries = Vec::new();
    for row in sqlx::query(
        "SELECT subject_kind,subject_id,capability FROM policy_entries
          WHERE policy_anchor_id=? ORDER BY subject_kind,subject_id",
    )
    .bind(message_id)
    .fetch_all(&mut **tx)
    .await?
    {
        let kind: String = row.try_get("subject_kind")?;
        let id: String = row.try_get("subject_id")?;
        let capability = capability(&row.try_get::<String, _>("capability")?)?;
        entries.push(if kind == "members" {
            AllowEntry::members(capability)
        } else {
            AllowEntry::account(id, capability)
        });
    }
    entries.push(AllowEntry::account(recipient_account, Capability::View));
    Ok(entries)
}

fn stable_selection_id(actor: &str, recipient_principal: &str, message_ids: &[String]) -> String {
    let mut digest = Sha256::new();
    for value in [actor, recipient_principal] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    for id in message_ids {
        digest.update(id.as_bytes());
        digest.update([0]);
    }
    format!("share:{}", hex::encode(digest.finalize()))
}

async fn resolved_share_set(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    message_ids: Option<Vec<String>>,
    conversation_id: Option<String>,
    snapshot_seq: Option<i64>,
) -> Result<(Vec<String>, i64, Option<String>)> {
    match (message_ids, conversation_id) {
        (Some(mut ids), None) if !ids.is_empty() => {
            if snapshot_seq.is_some() {
                return Err(Error::engine(
                    "share_history: snapshot_seq is only valid with conversation_id",
                ));
            }
            ids.sort();
            ids.dedup();
            let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
                .fetch_one(&mut **tx)
                .await?;
            Ok((ids, head, None))
        }
        (None, Some(conversation_id)) => {
            let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
                .fetch_one(&mut **tx)
                .await?;
            let frontier = snapshot_seq.unwrap_or(head);
            if frontier < 0 || frontier > head {
                return Err(Error::engine(format!(
                    "share_history: snapshot_seq must be between 0 and current head {head}"
                )));
            }
            // Resolve classification from the authoritative log, not today's
            // projection. A snapshot must retain memberships removed later and
            // exclude memberships added later.
            let ids = sqlx::query_scalar(
                "WITH ranked AS (
                   SELECT json_extract(payload,'$.source_id') AS message_id,
                          type,
                          seq,
                          ROW_NUMBER() OVER (
                            PARTITION BY json_extract(payload,'$.source_id'),
                                         json_extract(payload,'$.target_id'),
                                         json_extract(payload,'$.relationship')
                            ORDER BY seq DESC
                          ) AS recency
                     FROM content_events
                    WHERE seq<=?
                      AND type IN ('link.added','link.removed')
                      AND json_extract(payload,'$.target_id')=?
                      AND json_extract(payload,'$.relationship')='participates_in'
                 )
                 SELECT message_id
                   FROM ranked
                  WHERE recency=1 AND type='link.added'
                  ORDER BY seq,message_id",
            )
            .bind(frontier)
            .bind(&conversation_id)
            .fetch_all(&mut **tx)
            .await?;
            Ok((ids, frontier, Some(conversation_id)))
        }
        _ => Err(Error::engine(
            "share_history requires either non-empty message_ids or conversation_id, but not both",
        )),
    }
}

async fn share_history(
    db: &Db,
    caller: &Caller,
    recipient_id: String,
    message_ids: Option<Vec<String>>,
    conversation_id: Option<String>,
    snapshot_seq: Option<i64>,
    reason: String,
) -> Result<Value> {
    require_nonblank_reason("manage_messages.share_history", &reason)?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    let (message_ids, snapshot_seq, conversation_id) =
        resolved_share_set(&mut tx, message_ids, conversation_id, snapshot_seq).await?;
    if message_ids.is_empty() {
        return Err(Error::engine(
            "share_history: the resolved snapshot contains no Messages",
        ));
    }
    let recipient = sqlx::query(
        "SELECT
           (SELECT identifier FROM bindings WHERE record_id=? AND system='native-principal' AND is_canonical=1) principal,
           (SELECT identifier FROM bindings WHERE record_id=? AND system='account' AND is_canonical=1) account",
    )
    .bind(&recipient_id)
    .bind(&recipient_id)
    .fetch_one(&mut *tx)
    .await?;
    let recipient_principal: Option<String> = recipient.try_get("principal")?;
    let recipient_account: Option<String> = recipient.try_get("account")?;
    let recipient_principal = recipient_principal.ok_or_else(|| {
        Error::engine(
            "manage_messages.share_history: messaging unavailable for the recipient: hosted identity reconciliation has not installed a canonical native-principal binding",
        )
    })?;
    let recipient_account = recipient_account.ok_or_else(|| {
        Error::engine("share_history recipient has no canonical local account binding")
    })?;
    // `snapshot_seq` is audit metadata. The exact resolved set is the
    // idempotency identity, so unrelated later content cannot create a second
    // grant for an otherwise identical explicit share.
    let selection_id = stable_selection_id(caller.actor(), &recipient_principal, &message_ids);

    // Validate every target before the first write. BEGIN IMMEDIATE keeps this
    // authority snapshot stable through the complete policy/content batch.
    for message_id in &message_ids {
        require_record_in(
            &mut tx,
            caller,
            "manage_messages.share_history",
            message_id,
            Capability::Manage,
        )
        .await?;
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM message_audience_state WHERE message_id=?")
                .bind(message_id)
                .fetch_optional(&mut *tx)
                .await?;
        if status.as_deref() != Some("declared") {
            return Err(Error::engine(format!(
                "share_history: Message {message_id} has legacy-unknown or unsealed audience"
            )));
        }
        let delivered: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM content_events
                 WHERE record_id=? AND type='message.send_evaluated.v1'
                   AND json_extract(payload,'$.delivered')=1
                UNION ALL
                SELECT 1 FROM content_events
                 WHERE record_id=? AND type='message.delivery.authorized.v1'
                UNION ALL
                SELECT 1 FROM message_audiences
                 WHERE message_id=? AND source='addressed_to'
            )",
        )
        .bind(message_id)
        .bind(message_id)
        .bind(message_id)
        .fetch_one(&mut *tx)
        .await?;
        if !delivered {
            return Err(Error::engine(format!(
                "share_history: Message {message_id} is an undelivered draft"
            )));
        }
    }

    let mut shared = Vec::new();
    let mut unchanged = Vec::new();
    for message_id in &message_ids {
        let mut grant_digest = Sha256::new();
        grant_digest.update(selection_id.as_bytes());
        grant_digest.update([0]);
        grant_digest.update(message_id.as_bytes());
        let grant_id = format!("grant:{}", hex::encode(grant_digest.finalize()));
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM message_audiences
              WHERE message_id=? AND principal_id=? AND source='share' AND grant_id=?)",
        )
        .bind(message_id)
        .bind(&recipient_principal)
        .bind(&grant_id)
        .fetch_one(&mut *tx)
        .await?;
        if exists {
            unchanged.push(message_id.clone());
            continue;
        }
        let attestation = crate::provenance::reserve_action_attestation().ok();
        let shared_event = append_in(
            db,
            &mut tx,
            AppendSpec {
                record_id: message_id.clone(),
                event_type: "message.shared".into(),
                payload: serde_json::to_value(MessageSharedPayload {
                    grant_id,
                    selection_id: selection_id.clone(),
                    recipient_id: recipient_id.clone(),
                    recipient_principal: recipient_principal.clone(),
                    snapshot_seq,
                    reason: reason.clone(),
                })?,
                actor: Some(caller.actor().into()),
            },
            &mut act_alloc,
        )
        .await?;
        if let Some(attestation) = attestation {
            crate::provenance::issue_action_attestation_in(
                &mut tx,
                attestation,
                std::slice::from_ref(&shared_event),
            )
            .await?;
        }
        let policy = policy_entries_with_recipient(&mut tx, message_id, &recipient_account).await?;
        crate::authorization::replace_explicit_policy_on(
            &mut tx,
            caller.actor(),
            message_id,
            policy,
            &mut act_alloc,
        )
        .await?;
        shared.push(message_id.clone());
    }
    db.commit_content(tx).await?;
    echo_act(
        json!({
        "status": if shared.is_empty() { "unchanged" } else { "shared" },
        "selection_id": selection_id,
        "snapshot_seq": snapshot_seq,
        "conversation_id": conversation_id,
        "recipient_id": recipient_id,
        "recipient_principal": recipient_principal,
        "message_ids": message_ids,
        "shared": shared,
        "unchanged": unchanged,
        }),
        act_alloc.get(),
    )
}

fn reaction_executor(caller: &Caller) -> (&'static str, Option<String>) {
    if let Some(interaction) = caller.verified_human_interaction() {
        ("human_attested", Some(interaction.executor_ref.clone()))
    } else if let Some(executor) = caller.verified_delegated_service() {
        (
            "delegated_service",
            Some(format!("webhook:{}", executor.endpoint_id)),
        )
    } else if let Some(executor) = caller.verified_agent_executor() {
        ("agent", Some(executor.executor_ref.clone()))
    } else if caller.is_trusted_local() {
        ("local", None)
    } else {
        ("authenticated_principal", None)
    }
}

async fn caller_record_id_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT record_id FROM bindings
          WHERE system='account' AND identifier=? AND is_canonical=1
          ORDER BY record_id LIMIT 1",
    )
    .bind(caller.credential())
    .fetch_optional(&mut **tx)
    .await?)
}

/// Attention-local viewer resolution. The author-exclusion compares against
/// `records.owner_id`, which names a Person record — the same domain the
/// membership roster carries as `person_id` for the viewer's own row — so the
/// account binding must resolve to a live Person, not just any bound record.
/// A deleted, non-Person, or missing binding is "Person unknown" (no signal)
/// rather than someone else's dot. Kept separate from
/// [`caller_record_id_in`] so the reaction sender path keeps its exact
/// long-standing semantics.
///
/// The `kind = 'person'` literal is the governed canonical token
/// ([`crate::generated::kinds::CoreKind::EntityPerson`]): admission persists
/// the canonical kind for writes, so it cannot miss a governed Person, and it
/// is the same literal the send and list_context paths already require of
/// direct participants. Like the roster fallback it replaces, this resolves
/// the id with no record-View gate — the id only ever meets `owner_id`, so it
/// discloses nothing, and gating it would turn a hidden-but-bound Person into
/// someone else's signal instead of its own exclusion.
async fn attention_person_id_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar(
        "SELECT b.record_id FROM bindings b JOIN records r ON r.id=b.record_id
          WHERE b.system='account' AND b.identifier=? AND b.is_canonical=1
            AND r.type='Entity' AND r.kind='person' AND r.deleted_at IS NULL
          ORDER BY b.record_id LIMIT 1",
    )
    .bind(caller.credential())
    .fetch_optional(&mut **tx)
    .await?)
}

pub(crate) async fn require_local_message_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
) -> Result<()> {
    require_visible_message_in(tx, caller, message_id).await?;
    let replicated: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM destination_message_ingest WHERE message_id=?)",
    )
    .bind(message_id)
    .fetch_one(&mut **tx)
    .await?;
    if replicated {
        return Err(Error::engine(
            "Message reactions are local-database only; federated Message writes are unsupported",
        ));
    }
    Ok(())
}

pub(crate) async fn reaction_present_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    message_id: &str,
    actor: &str,
    emoji: &str,
) -> Result<bool> {
    let latest: Option<String> = sqlx::query_scalar(
        "SELECT type FROM content_events
          WHERE record_id=? AND actor=?
            AND type IN ('message.reaction.added.v1','message.reaction.removed.v1')
            AND json_extract(payload,'$.emoji')=?
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(message_id)
    .bind(actor)
    .bind(emoji)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(latest.as_deref() == Some("message.reaction.added.v1"))
}

async fn reaction_groups(db: &Db, viewer_account: &str, message_id: &str) -> Result<Vec<Value>> {
    let rows = sqlx::query(
        "WITH ranked AS (
           SELECT type,actor,payload,created_at,
                  ROW_NUMBER() OVER (
                    PARTITION BY actor,json_extract(payload,'$.emoji') ORDER BY seq DESC
                  ) recency
             FROM content_events
            WHERE record_id=?
              AND type IN ('message.reaction.added.v1','message.reaction.removed.v1')
         )
         SELECT actor,payload,created_at FROM ranked
          WHERE recency=1 AND type='message.reaction.added.v1'
          ORDER BY json_extract(payload,'$.emoji'),actor",
    )
    .bind(message_id)
    .fetch_all(db.write_pool())
    .await?;
    let mut groups = BTreeMap::<String, Vec<Value>>::new();
    for row in rows {
        let account_id: String = row.try_get("actor")?;
        let payload: crate::events::MessageReactionPayload =
            serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
        payload.validate(Some(&account_id))?;
        let actor_record_id: Option<String> = sqlx::query_scalar(
            "SELECT record_id FROM bindings WHERE system='account' AND identifier=?
              AND is_canonical=1 ORDER BY record_id LIMIT 1",
        )
        .bind(&account_id)
        .fetch_optional(db.write_pool())
        .await?;
        let name = if let Some(record_id) = actor_record_id.as_deref() {
            sqlx::query_scalar::<_, String>(
                "SELECT name FROM records WHERE id=? AND deleted_at IS NULL",
            )
            .bind(record_id)
            .fetch_optional(db.write_pool())
            .await?
        } else {
            None
        };
        let mut actor = json!({
            "record_id":actor_record_id,
            "name":name,
            "executor_kind":payload.executor_kind,
            "reacted_at":row.try_get::<String,_>("created_at")?,
            "viewer":account_id == viewer_account,
        });
        if actor["record_id"].is_null() {
            actor["account_id"] = json!(account_id);
        }
        groups.entry(payload.emoji).or_default().push(actor);
    }
    Ok(groups
        .into_iter()
        .map(|(emoji, actors)| {
            let viewer_reacted = actors.iter().any(|actor| actor["viewer"] == true);
            json!({"emoji":emoji,"count":actors.len(),"actors":actors,"viewer_reacted":viewer_reacted})
        })
        .collect())
}

#[cfg(test)]
pub(crate) async fn reaction_groups_for_projection_test(
    db: &Db,
    viewer: &str,
    message: &str,
) -> Result<Vec<Value>> {
    reaction_groups(db, viewer, message).await
}

async fn reaction_groups_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    viewer_account: &str,
    message_id: &str,
) -> Result<Vec<Value>> {
    let rows = sqlx::query(
        "WITH ranked AS (
           SELECT type,actor,payload,created_at,
                  ROW_NUMBER() OVER (
                    PARTITION BY actor,json_extract(payload,'$.emoji') ORDER BY seq DESC
                  ) recency
             FROM content_events
            WHERE record_id=?
              AND type IN ('message.reaction.added.v1','message.reaction.removed.v1')
         )
         SELECT actor,payload,created_at FROM ranked
          WHERE recency=1 AND type='message.reaction.added.v1'
          ORDER BY json_extract(payload,'$.emoji'),actor",
    )
    .bind(message_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut groups = BTreeMap::<String, Vec<Value>>::new();
    for row in rows {
        let account_id: String = row.try_get("actor")?;
        let payload: crate::events::MessageReactionPayload =
            serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
        payload.validate(Some(&account_id))?;
        let actor_record_id: Option<String> = sqlx::query_scalar(
            "SELECT record_id FROM bindings WHERE system='account' AND identifier=?
              AND is_canonical=1 ORDER BY record_id LIMIT 1",
        )
        .bind(&account_id)
        .fetch_optional(&mut **tx)
        .await?;
        let name = if let Some(record_id) = actor_record_id.as_deref() {
            sqlx::query_scalar::<_, String>(
                "SELECT name FROM records WHERE id=? AND deleted_at IS NULL",
            )
            .bind(record_id)
            .fetch_optional(&mut **tx)
            .await?
        } else {
            None
        };
        let mut actor = json!({
            "record_id":actor_record_id,"name":name,"executor_kind":payload.executor_kind,
            "reacted_at":row.try_get::<String,_>("created_at")?,"viewer":account_id == viewer_account,
        });
        if actor["record_id"].is_null() {
            actor["account_id"] = json!(account_id);
        }
        groups.entry(payload.emoji).or_default().push(actor);
    }
    Ok(groups
        .into_iter()
        .map(|(emoji, actors)| {
            let viewer_reacted = actors.iter().any(|actor| actor["viewer"] == true);
            json!({"emoji":emoji,"count":actors.len(),"actors":actors,"viewer_reacted":viewer_reacted})
        })
        .collect())
}

async fn acknowledgement_eligibility_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
) -> Result<(
    crate::message_expectation::MessageExpectationDerivation,
    bool,
)> {
    let state = crate::message_expectation::derive_message_expectation_state_in(
        tx,
        message_id,
        caller.credential(),
    )
    .await?;
    let local: bool = sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM destination_message_ingest WHERE message_id=?)",
    )
    .bind(message_id)
    .fetch_one(&mut **tx)
    .await?;
    let addressed: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM bindings account_binding
           JOIN bindings principal_binding
             ON principal_binding.record_id=account_binding.record_id
            AND principal_binding.system='native-principal'
            AND principal_binding.is_canonical=1
           JOIN message_audiences audience
             ON audience.principal_id=principal_binding.identifier
            AND audience.source='addressed_to'
          WHERE account_binding.system='account'
            AND account_binding.identifier=?
            AND account_binding.is_canonical=1
            AND audience.message_id=?)",
    )
    .bind(caller.credential())
    .bind(message_id)
    .fetch_one(&mut **tx)
    .await?;
    let eligible = local
        && addressed
        && state.expectation.as_deref() == Some("ack")
        && state.state == crate::message_expectation::MessageExpectationState::Open;
    Ok((state, eligible))
}

async fn message_state(db: &Db, caller: &Caller, message_id: &str) -> Result<Value> {
    let mut tx = db.write_pool().begin().await?;
    let state = message_state_in(&mut tx, caller, message_id).await?;
    tx.rollback().await?;
    Ok(state)
}

/// Mirrors `my_message_state.unread`: preferences never regress awareness,
/// and archive/own-human-message hiding takes precedence over an override.
fn private_message_unread(
    stage: &str,
    is_own: bool,
    archived: bool,
    unread_override: Option<bool>,
) -> bool {
    !is_own && !archived && unread_override.unwrap_or(!matches!(stage, "opened" | "acknowledged"))
}

async fn message_state_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
) -> Result<Value> {
    require_visible_message_in(tx, caller, message_id).await?;
    let (expectation, can_satisfy_acknowledgement) =
        acknowledgement_eligibility_in(tx, caller, message_id).await?;
    let attention = sqlx::query(
        "SELECT COALESCE(h.stage,'unsurfaced') stage, COALESCE(h.version,0) human_version,
                EXISTS(SELECT 1 FROM message_mentions mm JOIN bindings b ON b.record_id=mm.target_record_id AND b.system='account' AND b.is_canonical=1
                  WHERE mm.message_id=r.id AND mm.target_kind='principal' AND mm.effective=1 AND b.identifier=?) mentioned,
                p.unread_override, COALESCE(p.version,0) version,
                COALESCE(p.archived,0) archived,
                CASE WHEN r.owner_id=(SELECT account.record_id FROM bindings account JOIN records person ON person.id=account.record_id WHERE account.system='account' AND account.identifier=? AND account.is_canonical=1 AND person.type='Entity' AND person.kind='person' AND person.deleted_at IS NULL ORDER BY account.record_id LIMIT 1)
                     AND NOT EXISTS(SELECT 1 FROM message_speakers s WHERE s.message_id=r.id) THEN 1 ELSE 0 END is_own
           FROM records r
           LEFT JOIN human_message_awareness h ON h.message_id=r.id AND h.subject_account_id=?
           LEFT JOIN message_preferences p ON p.message_id=r.id AND p.subject_account_id=?
          WHERE r.id=?",
    )
    .bind(caller.credential()).bind(caller.credential()).bind(caller.credential()).bind(caller.credential())
    .bind(message_id).fetch_one(&mut **tx).await?;
    let stage: String = attention.try_get("stage")?;
    let unread_override: Option<bool> = attention.try_get("unread_override")?;
    let unread = private_message_unread(
        &stage,
        attention.try_get("is_own")?,
        attention.try_get("archived")?,
        unread_override,
    );
    Ok(json!({
        "message_id":message_id,
        "human":{"stage":stage,"version":attention.try_get::<i64,_>("human_version")?},
        "mention":{"principal":attention.try_get::<bool,_>("mentioned")?},
        "attention":{"unread":unread,"unread_override":unread_override,"version":attention.try_get::<i64,_>("version")?,"archived":attention.try_get::<bool,_>("archived")?},
        "reactions":reaction_groups_in(tx, caller.credential(), message_id).await?,
        "message_expectation_state":expectation,
        "can_satisfy_acknowledgement":can_satisfy_acknowledgement,
    }))
}

pub(crate) struct ReactionCommandSpec<'a> {
    pub message_id: &'a str,
    pub emoji: &'a str,
    pub command: &'a str,
    pub idempotency_key: &'a str,
    pub reason: &'a str,
    pub adding: bool,
    pub changed: bool,
    /// Artifact origin for tab-governed reactions; `None` on the ordinary
    /// path, whose events keep serializing without it.
    pub origin: Option<serde_json::Value>,
}

pub(crate) async fn append_reaction_command_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    spec: ReactionCommandSpec<'_>,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<()> {
    let (executor_kind, executor_ref) = reaction_executor(caller);
    let payload = crate::events::MessageReactionPayload {
        format: crate::events::MESSAGE_REACTION_FORMAT.into(),
        emoji: spec.emoji.into(),
        idempotency_key: spec.idempotency_key.into(),
        command: spec.command.into(),
        changed: spec.changed,
        actor_account_id: caller.actor().into(),
        executor_kind: executor_kind.into(),
        executor_ref,
        reason: spec.reason.into(),
        origin: spec.origin.clone(),
    };
    payload.validate(Some(caller.actor()))?;
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: spec.message_id.into(),
            event_type: if spec.adding {
                "message.reaction.added.v1"
            } else {
                "message.reaction.removed.v1"
            }
            .into(),
            payload: serde_json::to_value(payload)?,
            actor: Some(caller.actor().into()),
        },
        act_alloc,
    )
    .await?;
    Ok(())
}

pub(crate) fn verify_reaction_retry(
    existing: &(String, crate::events::MessageReactionPayload),
    message_id: &str,
    expected_type: &str,
    command: &str,
    emoji: &str,
    event_record_id: &str,
) -> Result<()> {
    if existing.0 != expected_type
        || existing.1.command != command
        || existing.1.emoji != emoji
        || event_record_id != message_id
    {
        return Err(Error::engine(
            "Message reaction idempotency key was already used for different intent",
        ));
    }
    Ok(())
}

async fn mutate_reaction(
    db: &Db,
    caller: &Caller,
    message_id: String,
    emoji: String,
    idempotency_key: String,
    reason: String,
    adding: bool,
) -> Result<Value> {
    crate::events::validate_message_reaction_emoji(&emoji)?;
    require_nonblank_reason(
        if adding {
            "manage_messages.add_reaction"
        } else {
            "manage_messages.remove_reaction"
        },
        &reason,
    )?;
    if idempotency_key.trim().is_empty() {
        return Err(Error::engine(
            "Message reaction idempotency_key must not be blank",
        ));
    }
    let command = if adding {
        "add_reaction"
    } else {
        "remove_reaction"
    };
    let event_type = if adding {
        "message.reaction.added.v1"
    } else {
        "message.reaction.removed.v1"
    };
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    require_local_message_in(&mut tx, caller, &message_id).await?;
    if let Some((existing_record_id, event_type_found, payload, replayed_act)) = sqlx::query(
        "SELECT record_id,type,payload,act FROM content_events
          WHERE actor=?
            AND type IN ('message.reaction.added.v1','message.reaction.removed.v1')
            AND json_extract(payload,'$.idempotency_key')=?
          ORDER BY seq LIMIT 1",
    )
    .bind(caller.actor())
    .bind(&idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    .map(|row| -> Result<_> {
        Ok((
            row.try_get::<String, _>("record_id")?,
            row.try_get::<String, _>("type")?,
            serde_json::from_str::<crate::events::MessageReactionPayload>(
                &row.try_get::<String, _>("payload")?,
            )?,
            row.try_get::<Option<i64>, _>("act")?,
        ))
    })
    .transpose()?
    {
        payload.validate(Some(caller.actor()))?;
        let original_changed = payload.changed;
        verify_reaction_retry(
            &(event_type_found, payload),
            &message_id,
            event_type,
            command,
            &emoji,
            &existing_record_id,
        )?;
        tx.rollback().await?;
        // A keyed replay returns the original reaction write's act, so the
        // replay receipt is indistinguishable from the first.
        return echo_act(
            json!({
            "status":if original_changed {if adding {"added"} else {"removed"}} else {"unchanged"},
            "message_id":message_id,"emoji":emoji,
            "changed":original_changed,"reactions":reaction_groups(db,caller.credential(),&message_id).await?,
            }),
            replayed_act,
        );
    }
    let present = reaction_present_in(&mut tx, &message_id, caller.actor(), &emoji).await?;
    let changed = present != adding;
    append_reaction_command_in(
        db,
        &mut tx,
        caller,
        ReactionCommandSpec {
            message_id: &message_id,
            emoji: &emoji,
            command,
            idempotency_key: &idempotency_key,
            reason: &reason,
            adding,
            changed,
            origin: None,
        },
        &mut act_alloc,
    )
    .await?;
    db.commit_content(tx).await?;
    echo_act(
        json!({
        "status":if changed {if adding {"added"} else {"removed"}} else {"unchanged"},
        "message_id":message_id,"emoji":emoji,"changed":changed,
        "reactions":reaction_groups(db,caller.credential(),&message_id).await?,
        }),
        act_alloc.get(),
    )
}

async fn append_link_if_missing_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    source_id: &str,
    target_id: &str,
    relationship: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<bool> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM links WHERE source_id=? AND target_id=? AND relationship=?)",
    )
    .bind(source_id)
    .bind(target_id)
    .bind(relationship)
    .fetch_one(&mut **tx)
    .await?;
    if exists {
        return Ok(false);
    }
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: source_id.into(),
            event_type: "link.added".into(),
            payload: serde_json::to_value(LinkAddedPayload {
                id: None,
                source_id: source_id.into(),
                target_id: target_id.into(),
                relationship: relationship.into(),
                note: None,
            })?,
            actor: Some(caller.actor().into()),
        },
        act_alloc,
    )
    .await?;
    Ok(true)
}

async fn clone_message_visibility_to_evidence_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
    evidence_id: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<()> {
    let message_anchor: String =
        sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id=?")
            .bind(message_id)
            .fetch_one(&mut **tx)
            .await?;
    let evidence_anchor: String =
        sqlx::query_scalar("SELECT policy_anchor_id FROM records WHERE id=?")
            .bind(evidence_id)
            .fetch_one(&mut **tx)
            .await?;
    if message_anchor == evidence_anchor {
        return Ok(());
    }
    let mut entries = Vec::new();
    for row in sqlx::query(
        "SELECT subject_kind,subject_id,capability FROM policy_entries
          WHERE policy_anchor_id=? ORDER BY subject_kind,subject_id",
    )
    .bind(&message_anchor)
    .fetch_all(&mut **tx)
    .await?
    {
        let kind: String = row.try_get("subject_kind")?;
        let id: String = row.try_get("subject_id")?;
        let capability = capability(&row.try_get::<String, _>("capability")?)?;
        entries.push(if kind == "members" {
            AllowEntry::members(capability)
        } else {
            AllowEntry::account(id, capability)
        });
    }
    crate::authorization::replace_explicit_policy_on(
        tx,
        caller.actor(),
        evidence_id,
        entries,
        act_alloc,
    )
    .await
}

async fn satisfy_acknowledgement_expectation_with_reaction(
    db: &Db,
    caller: &Caller,
    message_id: String,
    idempotency_key: String,
    reason: String,
) -> Result<Value> {
    const COMMAND: &str = "satisfy_acknowledgement_expectation_with_reaction";
    const EMOJI: &str = "👍";
    require_nonblank_reason(
        "manage_messages.satisfy_acknowledgement_expectation_with_reaction",
        &reason,
    )?;
    if idempotency_key.trim().is_empty() {
        return Err(Error::engine(
            "acknowledgement idempotency_key must not be blank",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    require_local_message_in(&mut tx, caller, &message_id).await?;
    if let Some(row) = sqlx::query(
        "SELECT record_id,type,payload,act FROM content_events
          WHERE actor=?
            AND type IN ('message.reaction.added.v1','message.reaction.removed.v1')
            AND json_extract(payload,'$.idempotency_key')=?
          ORDER BY seq LIMIT 1",
    )
    .bind(caller.actor())
    .bind(&idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        let existing_record_id: String = row.try_get("record_id")?;
        let event_type: String = row.try_get("type")?;
        let replayed_act: Option<i64> = row.try_get("act")?;
        let payload: crate::events::MessageReactionPayload =
            serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
        payload.validate(Some(caller.actor()))?;
        let original_changed = payload.changed;
        verify_reaction_retry(
            &(event_type, payload),
            &message_id,
            "message.reaction.added.v1",
            COMMAND,
            EMOJI,
            &existing_record_id,
        )?;
        let derivation = crate::message_expectation::derive_message_expectation_state_in(
            &mut tx,
            &message_id,
            caller.credential(),
        )
        .await?;
        let evidence_record_id = derivation
            .evidence
            .filter(|evidence| {
                evidence.kind
                    == crate::message_expectation::MessageExpectationEvidenceKind::Acknowledgement
            })
            .map(|evidence| evidence.record_id)
            .ok_or_else(|| Error::engine("acknowledgement retry has no valid durable evidence"))?;
        tx.rollback().await?;
        let state = message_state(db, caller, &message_id).await?;
        // A keyed replay returns the original write's act.
        return echo_act(
            json!({
            "status":"acknowledged","message_id":message_id,"emoji":EMOJI,"changed":original_changed,
            "reactions":state["reactions"],
            "acknowledgement":{"state":"satisfied","evidence_record_id":evidence_record_id},
            }),
            replayed_act,
        );
    }
    let actor_record_id = caller_record_id_in(&mut tx, caller).await?.ok_or_else(|| {
        Error::engine(
            "satisfying an acknowledgement expectation requires a portable account binding",
        )
    })?;
    let (expectation, eligible) =
        acknowledgement_eligibility_in(&mut tx, caller, &message_id).await?;
    let evidence_id = expectation.evidence.as_ref().and_then(|evidence| {
        (evidence.kind
            == crate::message_expectation::MessageExpectationEvidenceKind::Acknowledgement)
            .then(|| evidence.record_id.clone())
    });
    let own_existing_evidence = expectation.state
        == crate::message_expectation::MessageExpectationState::Satisfied
        && evidence_id.is_some();
    if !eligible && !own_existing_evidence {
        return Err(Error::engine(
            "caller cannot satisfy this acknowledgement expectation: it must be an open local ack expectation addressed to the caller",
        ));
    }
    let reaction_was_present =
        reaction_present_in(&mut tx, &message_id, caller.actor(), EMOJI).await?;
    let evidence_exists = evidence_id.is_some();
    let evidence_id = evidence_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let mut evidence_changed = false;
    if !evidence_exists {
        let home_id: Option<String> = sqlx::query_scalar("SELECT home_id FROM records WHERE id=?")
            .bind(&message_id)
            .fetch_one(&mut *tx)
            .await?;
        let mut fields = serde_json::Map::new();
        fields.insert("type".into(), json!("Annotation"));
        fields.insert(
            "kind".into(),
            json!(crate::generated::kinds::CoreKind::AnnotationAcknowledgement.token()),
        );
        fields.insert("name".into(), json!("Acknowledgement"));
        fields.insert(
            "body".into(),
            json!(format!("Acknowledged Message {message_id}.")),
        );
        fields.insert("owner_id".into(), json!(actor_record_id));
        fields.insert("reason".into(), json!(reason.clone()));
        if let Some(home_id) = home_id {
            fields.insert("home_id".into(), json!(home_id));
        }
        append_in(
            db,
            &mut tx,
            AppendSpec {
                record_id: evidence_id.clone(),
                event_type: "record.created".into(),
                payload: Value::Object(fields),
                actor: Some(caller.actor().into()),
            },
            &mut act_alloc,
        )
        .await?;
        clone_message_visibility_to_evidence_in(
            &mut tx,
            caller,
            &message_id,
            &evidence_id,
            &mut act_alloc,
        )
        .await?;
        evidence_changed = true;
    }
    evidence_changed |= append_link_if_missing_in(
        db,
        &mut tx,
        caller,
        &evidence_id,
        &message_id,
        "part_of",
        &mut act_alloc,
    )
    .await?;
    evidence_changed |= append_link_if_missing_in(
        db,
        &mut tx,
        caller,
        &evidence_id,
        &message_id,
        "acknowledges",
        &mut act_alloc,
    )
    .await?;
    let routing: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT obligation_state,executor_route,version FROM message_inbox_routing
          WHERE subject_account_id=? AND message_id=?",
    )
    .bind(caller.credential())
    .bind(&message_id)
    .fetch_optional(&mut *tx)
    .await?;
    let routing_changed = routing
        .as_ref()
        .is_none_or(|(obligation, route, _)| obligation != "satisfied" || route != "closed");
    let changed = !reaction_was_present || evidence_changed || routing_changed;
    append_reaction_command_in(
        db,
        &mut tx,
        caller,
        ReactionCommandSpec {
            message_id: &message_id,
            emoji: EMOJI,
            command: COMMAND,
            idempotency_key: &idempotency_key,
            reason: &reason,
            adding: true,
            changed,
            origin: None,
        },
        &mut act_alloc,
    )
    .await?;
    if routing_changed {
        let context = crate::awareness::MutationContext {
            subject_account_id: caller.credential(),
            authenticated_actor: caller.actor(),
            executor_kind: "system",
            executor_ref: Some(COMMAND),
            delegation_ref: None,
            reason_code: &reason,
        };
        crate::awareness::set_routing(
            &mut tx,
            &context,
            &message_id,
            "satisfied",
            "closed",
            None,
            routing.as_ref().map_or(0, |(_, _, version)| *version),
            &format!("{idempotency_key}:routing"),
            &mut act_alloc,
        )
        .await?;
    }
    db.commit_content(tx).await?;
    echo_act(
        json!({
        "status":"acknowledged","message_id":message_id,"emoji":EMOJI,"changed":changed,
        "reactions":reaction_groups(db,caller.credential(),&message_id).await?,
        "acknowledgement":{"state":"satisfied","evidence_record_id":evidence_id},
        }),
        act_alloc.get(),
    )
}

/// The caller's live no-longer-relevant marks on a Message: Annotation
/// records they own with a live `resolves`/`no_longer_relevant` link to the
/// Message, oldest link first. Normally at most one, but archiving plus
/// re-marking plus a restore can leave several; unmark removes all of them.
async fn own_no_longer_relevant_marks_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    owner_id: &str,
    message_id: &str,
) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar(
        "SELECT r.id FROM main.links l JOIN main.records r ON r.id = l.source_id
          WHERE l.target_id = ? AND l.relationship = ? AND l.note = ?
            AND r.owner_id = ? AND r.type = 'Annotation' AND r.kind = 'no_longer_relevant'
            AND r.deleted_at IS NULL AND r.archived = 0
          ORDER BY l.created_at, l.id",
    )
    .bind(message_id)
    .bind(crate::message_expectation::NO_LONGER_RELEVANT_RELATIONSHIP)
    .bind(crate::message_expectation::NO_LONGER_RELEVANT_NOTE)
    .bind(owner_id)
    .fetch_all(&mut **tx)
    .await?)
}

/// Delete one of the caller's own Messages: the existing `record.deleted`
/// tombstone (every listing already filters it, a later reaction is refused by
/// the projector, and its notification candidates are withdrawn in the same
/// transaction). The body is not erased; it stays in stored history.
///
/// Only the author may delete: the Message's `owner_id` must be the Person
/// bound to the authenticated caller, on top of the Edit capability the
/// sibling operations require. A persona-voiced Message has the same owner as
/// its sender, so its owner may delete it and nobody else can. A repeat with
/// the same idempotency key replays the first receipt; an already-deleted
/// Message sent again under a new key is refused by name to its author.
async fn delete_message(
    db: &Db,
    caller: &Caller,
    message_id: String,
    idempotency_key: String,
    reason: String,
    provenance_arguments: Option<&Value>,
) -> Result<Value> {
    const TOOL: &str = "manage_messages.delete";
    require_nonblank_reason(TOOL, &reason)?;
    super::keyed_replay::idempotency_key(TOOL, Some(&idempotency_key))?
        .ok_or_else(|| Error::engine("manage_messages.delete idempotency_key must not be blank"))?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    // The lookup is scoped to the caller's own keyed commands, so it runs
    // before the live-Message gate that the first call's tombstone now fails.
    if let Some(replay) = super::keyed_replay::keyed_replay_in(
        &mut tx,
        caller,
        "manage_messages",
        provenance_arguments
            .ok_or_else(|| Error::engine("manage_messages: keyed delete lost its arguments"))?,
    )
    .await?
    {
        if !replay
            .content()
            .iter()
            .any(|output| output.event_type == "record.deleted" && output.record_id == message_id)
        {
            return Err(Error::engine(
                "manage_messages.delete retry has no valid durable evidence",
            ));
        }
        let deleted_at = message_deleted_at_in(&mut tx, &message_id).await?;
        tx.rollback().await?;
        replay.settle();
        return echo_act(
            json!({"status":"deleted","message_id":message_id,"deleted_at":deleted_at}),
            replay.act(),
        );
    }
    require_author_in(&mut tx, caller, &message_id, AuthorAction::Delete).await?;
    let deletion = append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: message_id.clone(),
            event_type: "record.deleted".into(),
            payload: json!({ "reason": reason }),
            actor: Some(caller.actor().into()),
        },
        &mut act_alloc,
    )
    .await?;
    crate::awareness::withdraw_message_candidates_in(
        &mut tx,
        &message_id,
        "record.deleted",
        &deletion.id,
        &mut act_alloc,
    )
    .await?;
    db.commit_content(tx).await?;
    let deleted_at =
        sqlx::query_scalar::<_, Option<String>>("SELECT deleted_at FROM records WHERE id=?")
            .bind(&message_id)
            .fetch_one(db.write_pool())
            .await?;
    echo_act(
        json!({"status":"deleted","message_id":message_id,"deleted_at":deleted_at}),
        act_alloc.get(),
    )
}

#[derive(Clone, Copy)]
enum AuthorAction {
    Delete,
    Edit,
}

impl AuthorAction {
    fn tool(self) -> &'static str {
        match self {
            Self::Delete => "manage_messages.delete",
            Self::Edit => "manage_messages.edit",
        }
    }

    fn verb(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Edit => "edit",
        }
    }
}

/// The checks shared by the author-only Message operations, in order: a
/// deleted Message is named as such to its author (and reads as missing to
/// anyone else), the Message must be visible, local and Edit-able by the
/// caller, and the caller must be its author. A Message sent as a persona is
/// held to the same rule: its owner is its sender.
async fn require_author_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
    action: AuthorAction,
) -> Result<()> {
    let is_author = message_author_is_caller_in(tx, caller, message_id).await?;
    if is_author == Some(true) && message_deleted_at_in(tx, message_id).await?.is_some() {
        return Err(Error::engine(match action {
            AuthorAction::Delete => {
                format!("manage_messages.delete: Message {message_id} is already deleted")
            }
            AuthorAction::Edit => format!(
                "manage_messages.edit: Message {message_id} is deleted and cannot be edited"
            ),
        }));
    }
    require_local_message_in(tx, caller, message_id).await?;
    require_record_in(tx, caller, "manage_messages", message_id, Capability::Edit).await?;
    if is_author != Some(true) {
        let persona: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM message_speakers WHERE message_id=?)")
                .bind(message_id)
                .fetch_one(&mut **tx)
                .await?;
        return Err(Error::engine(format!(
            "{}: only the author can {} a Message{}",
            action.tool(),
            action.verb(),
            if persona { " sent as a persona" } else { "" }
        )));
    }
    Ok(())
}

/// Replace the text of one of the caller's own Messages. The new text is
/// recorded as a dedicated `message.revision.recorded.v1` event on the same
/// Message, so every earlier text stays in the log and the Message
/// immutability guard stays closed to every other path.
///
/// Authorship is exactly delete's. An edit never alerts anyone: awareness,
/// read state and notification candidates are untouched (candidates carry no
/// text, so none can go stale), except that a person whose mention the edit
/// removes has their mention candidate withdrawn. Structured mention spans
/// index the body, so they are re-established against the new text: given
/// `mentions` they replace the old set, and absent `mentions` the old ones are
/// relocated to wherever their label now sits (in order, scanning forward from
/// the previous match) or dropped if the label is gone. A mention of
/// someone not already mentioned is refused; that is a new alert, so it
/// needs a new Message. An unchanged body is refused, not silently ignored.
#[allow(clippy::too_many_arguments)]
async fn edit_message(
    db: &Db,
    caller: &Caller,
    message_id: String,
    body: String,
    mentions: Option<Vec<crate::awareness::MentionInput>>,
    idempotency_key: String,
    reason: String,
    provenance_arguments: Option<&Value>,
) -> Result<Value> {
    const TOOL: &str = "manage_messages.edit";
    require_nonblank_reason(TOOL, &reason)?;
    super::keyed_replay::idempotency_key(TOOL, Some(&idempotency_key))?
        .ok_or_else(|| Error::engine("manage_messages.edit idempotency_key must not be blank"))?;
    if body.trim().is_empty() {
        return Err(Error::engine(
            "manage_messages.edit: body must not be blank",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    if let Some(replay) = super::keyed_replay::keyed_replay_in(
        &mut tx,
        caller,
        "manage_messages",
        provenance_arguments
            .ok_or_else(|| Error::engine("manage_messages: keyed edit lost its arguments"))?,
    )
    .await?
    {
        let revision = replay
            .content()
            .iter()
            .find(|output| {
                output.event_type == "message.revision.recorded.v1"
                    && output.record_id == message_id
            })
            .ok_or_else(|| {
                Error::engine("manage_messages.edit retry has no valid durable evidence")
            })?
            .clone();
        let edit_count = message_edit_count_in(&mut tx, &message_id, revision.seq).await?;
        tx.rollback().await?;
        replay.settle();
        return echo_act(
            json!({"status":"edited","message_id":message_id,"edited_at":revision.created_at,"edit_count":edit_count}),
            replay.act(),
        );
    }
    require_author_in(&mut tx, caller, &message_id, AuthorAction::Edit).await?;
    let (current_body, audience_status): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT r.body,s.status FROM records r
           LEFT JOIN message_audience_state s ON s.message_id=r.id WHERE r.id=?",
    )
    .bind(&message_id)
    .fetch_one(&mut *tx)
    .await?;
    if audience_status.as_deref() != Some("declared") {
        return Err(Error::engine(format!(
            "{TOOL}: only a delivered Message can be edited"
        )));
    }
    if current_body.as_deref() == Some(body.as_str()) {
        return Err(Error::engine(format!(
            "{TOOL}: body is unchanged; there is nothing to edit"
        )));
    }
    let existing = sqlx::query(
        "SELECT mention_id,target_kind,target_binding,target_record_id,span_start,span_end,authored_label
           FROM message_mentions WHERE message_id=? AND effective=1 ORDER BY mention_id",
    )
    .bind(&message_id)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .map(|row| {
        Ok(crate::events::MessageRevisionMention {
            mention_id: row.try_get("mention_id")?,
            target_kind: row.try_get("target_kind")?,
            target_binding: row.try_get("target_binding")?,
            target_record_id: row.try_get("target_record_id")?,
            span_start: row.try_get("span_start")?,
            span_end: row.try_get("span_end")?,
            authored_label: row.try_get("authored_label")?,
        })
    })
    .collect::<Result<Vec<_>>>()?;
    let revised = match mentions {
        Some(given) => {
            let mut revised = Vec::with_capacity(given.len());
            for mention in given {
                crate::awareness::validate_mention_span(&body, &mention).map_err(|_| {
                    Error::engine(format!(
                        "{TOOL}: mention span must exactly match the edited prose"
                    ))
                })?;
                let known = existing.iter().find(|old| {
                    old.target_kind == mention.target_kind
                        && old.target_record_id == mention.target_id
                });
                let Some(known) = known else {
                    return Err(Error::engine(format!(
                        "{TOOL}: an edit cannot add a mention of someone the Message did not already mention; send a new Message to alert them"
                    )));
                };
                revised.push(crate::events::MessageRevisionMention {
                    mention_id: mention.mention_id,
                    target_kind: known.target_kind.clone(),
                    target_binding: known.target_binding.clone(),
                    target_record_id: known.target_record_id.clone(),
                    span_start: mention.span_start as i64,
                    span_end: mention.span_end as i64,
                    authored_label: mention.authored_label,
                });
            }
            revised
        }
        // No mentions given: relocate the existing ones into the new text (see
        // `relocate_mentions`). Targets never change and nobody is added, so
        // this cannot alert anyone new.
        None => relocate_mentions(current_body.as_deref(), &body, &existing),
    };
    let payload = crate::events::MessageRevisionRecordedPayload {
        format: crate::events::MESSAGE_REVISION_FORMAT.into(),
        body_sha256: hex::encode(Sha256::digest(body.as_bytes())),
        body,
        mentions: revised,
        reason,
    };
    payload.validate()?;
    let revision = append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: message_id.clone(),
            event_type: "message.revision.recorded.v1".into(),
            payload: serde_json::to_value(&payload)?,
            actor: Some(caller.actor().into()),
        },
        &mut act_alloc,
    )
    .await?;
    // A mention candidate does not record which mention target it was proposed
    // for; it records only the recipient account. So the target is recovered
    // from proposal time: the Person that account was bound to in the audited
    // binding ledger as of the candidate's own proposal (its act, else its
    // timestamp). Today's bindings are never consulted for that, so an account
    // later re-pointed or aliased onto another Person cannot change which
    // mention a candidate belongs to. Exactly the candidates proposed for a
    // dropped Person (and not also for one still mentioned) are withdrawn.
    let kept = payload
        .mentions
        .iter()
        .map(|mention| {
            (
                mention.target_kind.as_str(),
                mention.target_record_id.as_str(),
            )
        })
        .collect::<BTreeSet<_>>();
    let dropped_persons = existing
        .iter()
        .filter(|old| {
            old.target_kind == "principal"
                && !kept.contains(&(old.target_kind.as_str(), old.target_record_id.as_str()))
        })
        .map(|old| old.target_record_id.clone())
        .collect::<BTreeSet<_>>();
    if !dropped_persons.is_empty() {
        let kept_persons = payload
            .mentions
            .iter()
            .filter(|mention| mention.target_kind == "principal")
            .map(|mention| mention.target_record_id.clone())
            .collect::<BTreeSet<_>>();
        let candidates = sqlx::query(
            "SELECT c.recipient_account_id, c.created_at,
                    (SELECT e.act FROM notification_candidate_events e
                      WHERE e.candidate_key=c.candidate_key AND e.action='proposed'
                      ORDER BY e.seq LIMIT 1) AS act
               FROM notification_candidates c
              WHERE c.message_id=? AND c.reason='principal_mention' AND c.status='effective'
              ORDER BY c.recipient_account_id",
        )
        .bind(&message_id)
        .fetch_all(&mut *tx)
        .await?;
        let mut withdraw = BTreeSet::<String>::new();
        for candidate in candidates {
            let recipient: String = candidate.try_get("recipient_account_id")?;
            let proposed_for = account_person_at_proposal_in(
                &mut tx,
                &recipient,
                candidate.try_get::<Option<i64>, _>("act")?,
                &candidate.try_get::<String, _>("created_at")?,
            )
            .await?;
            let drop = match proposed_for {
                Some(person) => {
                    dropped_persons.contains(&person) && !kept_persons.contains(&person)
                }
                // No audited binding history for the account (a legacy row):
                // fall back to who it is bound to now, withdrawing unless that
                // is someone still mentioned.
                None => {
                    let bound: Option<String> = sqlx::query_scalar(
                        "SELECT record_id FROM bindings WHERE system='account' AND identifier=?",
                    )
                    .bind(&recipient)
                    .fetch_optional(&mut *tx)
                    .await?;
                    !bound.is_some_and(|person| kept_persons.contains(&person))
                }
            };
            if drop {
                withdraw.insert(recipient);
            }
        }
        for recipient in &withdraw {
            crate::awareness::withdraw_notification_candidates_in(
                &mut tx,
                recipient,
                &message_id,
                Some("principal_mention"),
                "message.revision.recorded.v1",
                &revision.id,
                &mut act_alloc,
            )
            .await?;
        }
    }
    let edit_count = message_edit_count_in(&mut tx, &message_id, revision.local_seq).await?;
    db.commit_content(tx).await?;
    echo_act(
        json!({"status":"edited","message_id":message_id,"edited_at":revision.created_at,"edit_count":edit_count}),
        act_alloc.get(),
    )
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Byte ranges of `body` where a mention label must not be matched: fenced
/// code blocks, inline code spans, and URLs (an `http://` or `https://` run up
/// to the next whitespace).
fn mention_exclusions(body: &str) -> Vec<(usize, usize)> {
    let mut ranges = Vec::new();
    // Fenced blocks: a line opening with ``` or ~~~ runs to the matching
    // closing line, or to the end of the body if it never closes.
    let mut fence_start: Option<usize> = None;
    let mut offset = 0usize;
    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            match fence_start.take() {
                Some(start) => ranges.push((start, offset + line.len())),
                None => fence_start = Some(offset),
            }
        }
        offset += line.len();
    }
    if let Some(start) = fence_start {
        ranges.push((start, body.len()));
    }
    // Inline code spans: a run of n backticks closes at the next run of exactly
    // n. An unclosed run is plain text.
    let bytes = body.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        if let Some(&(_, end)) = ranges
            .iter()
            .find(|(start, end)| index >= *start && index < *end)
        {
            index = end;
            continue;
        }
        if bytes[index] != b'`' {
            index += 1;
            continue;
        }
        let run_start = index;
        while index < bytes.len() && bytes[index] == b'`' {
            index += 1;
        }
        let run = index - run_start;
        let mut probe = index;
        let mut closed = None;
        while probe < bytes.len() {
            if bytes[probe] == b'`' {
                let close_start = probe;
                while probe < bytes.len() && bytes[probe] == b'`' {
                    probe += 1;
                }
                if probe - close_start == run {
                    closed = Some(probe);
                    break;
                }
            } else {
                probe += 1;
            }
        }
        if let Some(end) = closed {
            ranges.push((run_start, end));
            index = end;
        }
    }
    // URLs.
    let lowered = body.to_ascii_lowercase();
    for scheme in ["http://", "https://"] {
        for (start, _) in lowered.match_indices(scheme) {
            let end = body[start..]
                .find(char::is_whitespace)
                .map_or(body.len(), |length| start + length);
            ranges.push((start, end));
        }
    }
    ranges
}

/// Where each existing mention now sits in an edited body, when the caller gave
/// no new `mentions`. Mentions are taken in the order of their current spans.
/// Each is searched for by its authored label, starting after the previous
/// match: if the original spans overlapped, from that match's start (so two
/// overlapping mentions both survive), otherwise from its end. When a label
/// appears more than once, the first acceptable occurrence wins, so repeats
/// match in order.
///
/// An occurrence is acceptable only if it is not inside a fenced or inline code
/// span or a URL, and is bounded as the author wrote it: on a side where the
/// original mention stood against a non-word character (or the edge of the
/// body) the new one must too, so `Bob` never relocates into `Bobby`; and a
/// label that was preceded by `@` must be again. Word characters are Unicode
/// letters, digits and `_`. Anything not found drops the mention. Targets are
/// never changed.
fn relocate_mentions(
    original: Option<&str>,
    body: &str,
    existing: &[crate::events::MessageRevisionMention],
) -> Vec<crate::events::MessageRevisionMention> {
    let exclusions = mention_exclusions(body);
    let before = |text: &str, at: usize| text.get(..at).and_then(|head| head.chars().next_back());
    let after = |text: &str, at: usize| text.get(at..).and_then(|tail| tail.chars().next());
    let mut ordered = existing.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        (left.span_start, &left.mention_id).cmp(&(right.span_start, &right.mention_id))
    });
    // (original end, new start, new end) of the last mention that matched.
    let mut previous: Option<(i64, usize, usize)> = None;
    let mut relocated = Vec::with_capacity(ordered.len());
    for old in ordered {
        let label = old.authored_label.as_str();
        if label.is_empty() {
            continue;
        }
        let (start_at, end_at) = (old.span_start as usize, old.span_end as usize);
        let bounded_left =
            original.is_none_or(|text| before(text, start_at).is_none_or(|c| !is_word_char(c)));
        let bounded_right =
            original.is_none_or(|text| after(text, end_at).is_none_or(|c| !is_word_char(c)));
        let needs_at = !label.starts_with('@')
            && original.is_some_and(|text| before(text, start_at) == Some('@'));
        let cursor = match previous {
            Some((original_end, new_start, _)) if old.span_start < original_end => new_start,
            Some((_, _, new_end)) => new_end,
            None => 0,
        };
        let found = body[cursor..].match_indices(label).find_map(|(offset, _)| {
            let start = cursor + offset;
            let end = start + label.len();
            let ok = (!bounded_left || before(body, start).is_none_or(|c| !is_word_char(c)))
                && (!bounded_right || after(body, end).is_none_or(|c| !is_word_char(c)))
                && (!needs_at || before(body, start) == Some('@'))
                && !exclusions
                    .iter()
                    .any(|(from, to)| start < *to && end > *from);
            ok.then_some((start, end))
        });
        let Some((start, end)) = found else { continue };
        previous = Some((old.span_end, start, end));
        relocated.push(crate::events::MessageRevisionMention {
            span_start: start as i64,
            span_end: end as i64,
            ..old.clone()
        });
    }
    relocated.sort_by(|left, right| left.mention_id.cmp(&right.mention_id));
    relocated
}

/// The Person an account was bound to when a candidate was proposed: the last
/// audited `binding_audit` row for that account at or before the proposal.
/// Order is by act, with the cutover enforced first: an unstamped (NULL-act,
/// pre-cutover) row precedes every stamped proposal, and a stamped row never
/// precedes an unstamped proposal, whatever their timestamps say. Timestamps
/// order only two unstamped sides. `None` when the ledger has no row for it (a
/// removal also ends the binding).
async fn account_person_at_proposal_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    account: &str,
    proposal_act: Option<i64>,
    proposal_created_at: &str,
) -> Result<Option<String>> {
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT new_record_id FROM binding_audit
          WHERE system='account' AND identifier=?1
            AND CASE WHEN ?2 IS NOT NULL THEN (act IS NULL OR act<=?2)
                     ELSE (act IS NULL AND created_at<=?3) END
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(account)
    .bind(proposal_act)
    .bind(proposal_created_at)
    .fetch_optional(&mut **tx)
    .await?
    .flatten())
}

/// How many revisions the Message has recorded up to and including `seq`.
async fn message_edit_count_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    message_id: &str,
    seq: i64,
) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
          WHERE record_id=? AND type='message.revision.recorded.v1' AND seq<=?",
    )
    .bind(message_id)
    .bind(seq)
    .fetch_one(&mut **tx)
    .await?)
}

async fn message_deleted_at_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    message_id: &str,
) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT deleted_at FROM records WHERE id=? AND type='Message'")
            .bind(message_id)
            .fetch_optional(&mut **tx)
            .await?
            .flatten(),
    )
}

/// Whether the authenticated caller is the Message's author. Two independent
/// facts must both hold: the Message's `owner_id` is the live Person currently
/// bound to the caller's account, and the Message's creation event was written
/// by that same credential. The binding alone is mutable (re-pointing an
/// account at a Person would otherwise hand that Person's Messages to it); the
/// creation actor is the immutable send-time evidence.
///
/// A credential migration is the one accepted difference. The creation actor
/// may be a different credential if it is still bound to the owning Person
/// (a retained alias or reconciled predecessor) *and* the caller's own binding
/// to that Person was established through the identity layer: `binding_audit`
/// holds an `add`, `canonicalize` or `transfer` of the caller's account onto
/// the owner. A binding that appears with no audit row (a raw re-point) is not
/// verified continuity and does not qualify.
///
/// `None` when there is no such Message. Independent of visibility and
/// tombstone state.
async fn message_author_is_caller_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
) -> Result<Option<bool>> {
    Ok(sqlx::query_scalar(
        "WITH creator(actor) AS (
            SELECT e.actor FROM content_events e
             WHERE e.record_id=?1 AND e.type='record.created'
             ORDER BY e.seq LIMIT 1)
         SELECT COALESCE(
                  r.owner_id IS NOT NULL
                  AND r.owner_id=(
                    SELECT account.record_id FROM bindings account
                      JOIN records person ON person.id=account.record_id
                     WHERE account.system='account' AND account.identifier=?2 AND account.is_canonical=1
                       AND person.type='Entity' AND person.kind='person' AND person.deleted_at IS NULL
                     ORDER BY account.record_id LIMIT 1)
                  AND ((SELECT actor FROM creator)=?2
                       OR (EXISTS(SELECT 1 FROM bindings predecessor
                                   WHERE predecessor.record_id=r.owner_id
                                     AND predecessor.system='account'
                                     AND predecessor.identifier=(SELECT actor FROM creator))
                           AND EXISTS(SELECT 1 FROM binding_audit audit
                                       WHERE audit.system='account' AND audit.identifier=?2
                                         AND audit.new_record_id=r.owner_id
                                         AND audit.action IN ('add','canonicalize','transfer')))), 0)
           FROM records r WHERE r.id=?1 AND r.type='Message'",
    )
    .bind(message_id)
    .bind(caller.credential())
    .fetch_optional(&mut **tx)
    .await?)
}

async fn mark_message_no_longer_relevant(
    db: &Db,
    caller: &Caller,
    message_id: String,
    note: Option<String>,
    idempotency_key: String,
    reason: String,
    provenance_arguments: Option<&Value>,
) -> Result<Value> {
    require_nonblank_reason("manage_messages.mark_no_longer_relevant", &reason)?;
    super::keyed_replay::idempotency_key(
        "manage_messages.mark_no_longer_relevant",
        Some(&idempotency_key),
    )?
    .ok_or_else(|| Error::engine("no_longer_relevant idempotency_key must not be blank"))?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    require_local_message_in(&mut tx, caller, &message_id).await?;
    let actor_record_id = caller_record_id_in(&mut tx, caller).await?.ok_or_else(|| {
        Error::engine("marking no longer relevant requires a portable account binding")
    })?;
    // Keyed replay: after authorization, before the existing-mark check the
    // first call's own effect would now trip. The receipt is rebuilt from the
    // attestation's own outputs alone, never from live state: the effect
    // path leaves a `record.created` output, while the already-marked path
    // below re-appends the live mark's `resolves` link (a projection upsert,
    // so the projection is unchanged) precisely so the retry finds that
    // output and replays the original receipt.
    if let Some(replay) = super::keyed_replay::keyed_replay_in(
        &mut tx,
        caller,
        "manage_messages",
        provenance_arguments.ok_or_else(|| {
            Error::engine("manage_messages: keyed mark lost its dispatched arguments")
        })?,
    )
    .await?
    {
        let created = replay
            .content()
            .iter()
            .find(|output| output.event_type == "record.created")
            .map(|output| output.record_id.clone());
        let relinked = replay.content().iter().find_map(|output| {
            (output.event_type == "link.added"
                && output.payload.get("relationship").and_then(Value::as_str)
                    == Some(crate::message_expectation::NO_LONGER_RELEVANT_RELATIONSHIP))
            .then(|| {
                output
                    .payload
                    .get("source_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .flatten()
        });
        let (evidence_record_id, changed) = match (created, relinked) {
            (Some(id), _) => (id, true),
            (None, Some(id)) => (id, false),
            (None, None) => {
                return Err(Error::engine(
                    "no_longer_relevant retry has no valid durable evidence",
                ));
            }
        };
        tx.rollback().await?;
        replay.settle();
        // A keyed replay returns the original write's act.
        return echo_act(
            json!({
            "status":"marked","message_id":message_id,
            "evidence_record_id":evidence_record_id,"changed":changed,
            }),
            replay.act(),
        );
    }
    if let Some(existing) = own_no_longer_relevant_marks_in(&mut tx, &actor_record_id, &message_id)
        .await?
        .into_iter()
        .next()
    {
        // Already marked: re-append the live mark's link so this call leaves
        // the attested output a retry replays. This is a real `link.added`
        // event, not a silent no-op: it touches the mark's `updated_at` and
        // `last_activity_at`, appears in history, and can wake need
        // subscriptions, even though the receipt says `changed:false`. That
        // is accepted: it happens only when a caller marks an already-marked
        // message with a new idempotency key, and the projection itself is
        // unchanged (the links fold upserts on source, target and
        // relationship). The receipt reports the live mark unchanged.
        append_in(
            db,
            &mut tx,
            AppendSpec {
                record_id: existing.clone(),
                event_type: "link.added".into(),
                payload: serde_json::to_value(LinkAddedPayload {
                    id: None,
                    source_id: existing.clone(),
                    target_id: message_id.clone(),
                    relationship: crate::message_expectation::NO_LONGER_RELEVANT_RELATIONSHIP
                        .into(),
                    note: Some(crate::message_expectation::NO_LONGER_RELEVANT_NOTE.into()),
                })?,
                actor: Some(caller.actor().into()),
            },
            &mut act_alloc,
        )
        .await?;
        db.commit_content(tx).await?;
        return echo_act(
            json!({
            "status":"marked","message_id":message_id,
            "evidence_record_id":existing,"changed":false,
            }),
            act_alloc.get(),
        );
    }
    // Each mark creates a fresh record with a random id carrying its own
    // note, so a squatted id can never block a mark, a deleted or archived
    // record never wedges a re-mark, and a re-mark keeps its new note.
    let evidence_id = uuid::Uuid::new_v4().to_string();
    let home_id: Option<String> = sqlx::query_scalar("SELECT home_id FROM records WHERE id=?")
        .bind(&message_id)
        .fetch_one(&mut *tx)
        .await?;
    // The mark is an inert Annotation container with the open kind
    // `no_longer_relevant`: it must stay visible to the caller-relative
    // `messages_awaiting_reply` derivation, whose shared visibility relation
    // excludes the governed `acknowledgement` (and `attribution`) kinds, and
    // it must not read as a real acknowledgement, so the governed
    // acknowledgement kind is wrong on both counts. The semantics live on
    // the `resolves`/`no_longer_relevant` link, never on the kind. The
    // optional note becomes the body; an empty body is fine.
    let mut fields = serde_json::Map::new();
    fields.insert("type".into(), json!("Annotation"));
    fields.insert("kind".into(), json!("no_longer_relevant"));
    fields.insert("name".into(), json!("No longer relevant"));
    fields.insert("body".into(), json!(note.unwrap_or_default()));
    fields.insert("owner_id".into(), json!(actor_record_id));
    fields.insert("reason".into(), json!(reason.clone()));
    if let Some(home_id) = home_id {
        fields.insert("home_id".into(), json!(home_id));
    }
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: evidence_id.clone(),
            event_type: "record.created".into(),
            payload: Value::Object(fields),
            actor: Some(caller.actor().into()),
        },
        &mut act_alloc,
    )
    .await?;
    clone_message_visibility_to_evidence_in(
        &mut tx,
        caller,
        &message_id,
        &evidence_id,
        &mut act_alloc,
    )
    .await?;
    append_link_if_missing_in(
        db,
        &mut tx,
        caller,
        &evidence_id,
        &message_id,
        "part_of",
        &mut act_alloc,
    )
    .await?;
    let mark_link_event = append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: evidence_id.clone(),
            event_type: "link.added".into(),
            payload: serde_json::to_value(LinkAddedPayload {
                id: None,
                source_id: evidence_id.clone(),
                target_id: message_id.clone(),
                relationship: crate::message_expectation::NO_LONGER_RELEVANT_RELATIONSHIP.into(),
                note: Some(crate::message_expectation::NO_LONGER_RELEVANT_NOTE.into()),
            })?,
            actor: Some(caller.actor().into()),
        },
        &mut act_alloc,
    )
    .await?;
    // The mark may close the obligation for the marking recipient, or for every
    // recipient when the sender withdrew the request. A third party's mark
    // closes nothing, and the same derivation leaves those candidates alone.
    crate::awareness::withdraw_closed_obligation_candidates_in(
        &mut tx,
        &message_id,
        "message.no_longer_relevant.marked",
        &mark_link_event.id,
        &mut act_alloc,
    )
    .await?;
    db.commit_content(tx).await?;
    echo_act(
        json!({
        "status":"marked","message_id":message_id,
        "evidence_record_id":evidence_id,"changed":true,
        }),
        act_alloc.get(),
    )
}

async fn unmark_message_no_longer_relevant(
    db: &Db,
    caller: &Caller,
    message_id: String,
    idempotency_key: String,
    reason: String,
    provenance_arguments: Option<&Value>,
) -> Result<Value> {
    require_nonblank_reason("manage_messages.unmark_no_longer_relevant", &reason)?;
    super::keyed_replay::idempotency_key(
        "manage_messages.unmark_no_longer_relevant",
        Some(&idempotency_key),
    )?
    .ok_or_else(|| Error::engine("no_longer_relevant idempotency_key must not be blank"))?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    require_local_message_in(&mut tx, caller, &message_id).await?;
    let actor_record_id = caller_record_id_in(&mut tx, caller).await?.ok_or_else(|| {
        Error::engine("unmarking no longer relevant requires a portable account binding")
    })?;
    // Keyed replay: after authorization, before the existing-mark check the
    // first call's own effect would now trip.
    if let Some(replay) = super::keyed_replay::keyed_replay_in(
        &mut tx,
        caller,
        "manage_messages",
        provenance_arguments.ok_or_else(|| {
            Error::engine("manage_messages: keyed unmark lost its dispatched arguments")
        })?,
    )
    .await?
    {
        let changed = !replay.is_noop();
        tx.rollback().await?;
        replay.settle();
        return echo_act(
            json!({
            "status":"unmarked","message_id":message_id,"changed":changed,
            }),
            replay.act(),
        );
    }
    // Undoing removes all of the caller's own live mark links, which
    // reopens the expectation at the next derivation. There is normally one,
    // but an archived mark plus a re-mark plus a restore can leave several.
    // The evidence records themselves are kept as history.
    let existing = own_no_longer_relevant_marks_in(&mut tx, &actor_record_id, &message_id).await?;
    let changed = !existing.is_empty();
    for evidence_id in existing {
        append_in(
            db,
            &mut tx,
            AppendSpec {
                record_id: evidence_id.clone(),
                event_type: "link.removed".into(),
                payload: serde_json::to_value(LinkRemovedPayload {
                    source_id: evidence_id,
                    target_id: message_id.clone(),
                    relationship: crate::message_expectation::NO_LONGER_RELEVANT_RELATIONSHIP
                        .into(),
                })?,
                actor: Some(caller.actor().into()),
            },
            &mut act_alloc,
        )
        .await?;
    }
    if !changed {
        super::keyed_replay::anchor_noop_in(&mut tx).await?;
    }
    db.commit_content(tx).await?;
    echo_act(
        json!({
        "status":"unmarked","message_id":message_id,"changed":changed,
        }),
        act_alloc.get(),
    )
}

async fn visible_message_rows(
    db: &Db,
    caller: &Caller,
    candidates: Vec<String>,
) -> Result<Vec<Value>> {
    let mut rows = Vec::new();
    for id in candidates {
        if !can_record(db, caller, &id, Capability::View).await? {
            continue;
        }
        let row = sqlx::query(
            "SELECT r.id,r.name,r.body,r.created_at,s.status
               FROM records r LEFT JOIN message_audience_state s ON s.message_id=r.id
              WHERE r.id=? AND r.type='Message' AND r.deleted_at IS NULL",
        )
        .bind(&id)
        .fetch_optional(db.write_pool())
        .await?;
        if let Some(row) = row {
            rows.push(json!({
                "id": row.try_get::<String,_>("id")?,
                "name": row.try_get::<String,_>("name")?,
                "body": row.try_get::<Option<String>,_>("body")?,
                "created_at": row.try_get::<String,_>("created_at")?,
                "audience_status": row.try_get::<Option<String>,_>("status")?.unwrap_or_else(|| "legacy_unknown".into()),
                "reactions": reaction_groups(db,caller.credential(),&id).await?,
            }));
        }
    }
    Ok(rows)
}

async fn resolve_context_selector(
    db: &Db,
    caller: &Caller,
    input: super::lifecycle::MessageOriginInput,
) -> Result<crate::events::MessageOriginDeclaredPayload> {
    match input {
        super::lifecycle::MessageOriginInput::Collection { collection_id } => {
            if crate::identity::decode_native_record(&collection_id).is_ok() {
                return Ok(crate::events::MessageOriginDeclaredPayload::Collection {
                    collection_id,
                });
            }
            if !can_record(db, caller, &collection_id, Capability::View).await? {
                return Err(Error::engine(format!(
                    "manage_messages.list_context: Collection {collection_id} does not exist"
                )));
            }
            let valid: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM records
                  WHERE id=? AND type='Collection' AND kind='folder' AND deleted_at IS NULL)",
            )
            .bind(&collection_id)
            .fetch_one(db.write_pool())
            .await?;
            if !valid {
                return Err(Error::engine(format!(
                    "manage_messages.list_context: Collection {collection_id} does not exist"
                )));
            }
            Ok(crate::events::MessageOriginDeclaredPayload::Collection { collection_id })
        }
        super::lifecycle::MessageOriginInput::Direct { participant_ids } => {
            if participant_ids.len() < 2 {
                return Err(Error::engine(
                    "manage_messages.list_context: a direct context requires at least two participants",
                ));
            }
            let mut seen = BTreeSet::new();
            let mut principals = Vec::with_capacity(participant_ids.len());
            let mut includes_caller =
                caller.is_trusted_local() && caller.hosting_database().is_none();
            for participant_id in participant_ids {
                if !seen.insert(participant_id.clone()) {
                    return Err(Error::engine(format!(
                        "manage_messages.list_context: duplicate direct participant {participant_id}"
                    )));
                }
                if !can_record(db, caller, &participant_id, Capability::View).await? {
                    return Err(Error::engine(format!(
                        "manage_messages.list_context: direct participant {participant_id} does not exist"
                    )));
                }
                let row = sqlx::query(
                    "SELECT r.type,r.kind,p.identifier AS principal,a.identifier AS account
                       FROM records r
                       LEFT JOIN bindings p ON p.record_id=r.id
                            AND p.system='native-principal' AND p.is_canonical=1
                       LEFT JOIN bindings a ON a.record_id=r.id
                            AND a.system='account' AND a.is_canonical=1
                      WHERE r.id=? AND r.deleted_at IS NULL",
                )
                .bind(&participant_id)
                .fetch_optional(db.write_pool())
                .await?;
                let Some(row) = row else {
                    return Err(Error::engine(format!(
                        "manage_messages.list_context: direct participant {participant_id} does not exist"
                    )));
                };
                if row.try_get::<String, _>("type")? != "Entity"
                    || row.try_get::<String, _>("kind")? != "person"
                {
                    return Err(Error::engine(format!(
                        "manage_messages.list_context: direct participant {participant_id} is not a Person"
                    )));
                }
                let principal = row
                    .try_get::<Option<String>, _>("principal")?
                    .ok_or_else(|| Error::engine(format!(
                        "manage_messages.list_context: direct participant {participant_id} has no canonical native-principal binding"
                    )))?;
                if row.try_get::<Option<String>, _>("account")?.as_deref()
                    == Some(caller.credential())
                {
                    includes_caller = true;
                }
                principals.push(principal);
            }
            if !includes_caller {
                return Err(Error::engine(
                    "manage_messages.list_context: the caller must be one of the direct participants",
                ));
            }
            let principals = crate::events::normalize_direct_origin_principals(principals);
            if principals.len() != seen.len() {
                return Err(Error::engine(
                    "manage_messages.list_context: participants must resolve to distinct canonical principals",
                ));
            }
            Ok(crate::events::MessageOriginDeclaredPayload::Direct { principals })
        }
    }
}

async fn list_context(
    db: &Db,
    caller: &Caller,
    input: super::lifecycle::MessageOriginInput,
    limit: usize,
    cursor: Option<String>,
) -> Result<Value> {
    if !(1..=200).contains(&limit) {
        return Err(Error::engine(
            "manage_messages.list_context: limit must be between 1 and 200",
        ));
    }
    let origin = resolve_context_selector(db, caller, input).await?;
    let context_key = origin.context_key();
    let after = if let Some(cursor) = cursor {
        let cursor: ContextCursor = serde_json::from_value(db.get_inbox_snapshot(&cursor)?)
            .map_err(|_| Error::engine("cursor_reset_required: invalid context cursor"))?;
        if cursor.schema != 1
            || cursor.account_id != caller.credential()
            || cursor.context_key != context_key
        {
            return Err(Error::engine(
                "cursor_reset_required: context cursor does not match this caller and origin",
            ));
        }
        Some((cursor.created_at, cursor.message_id))
    } else {
        None
    };
    let mut snapshot = db.write_pool().begin().await?;
    let view = crate::query::fts::view_predicate("r");
    let mut clauses = vec!["s.status='declared'".to_string()];
    match &origin {
        crate::events::MessageOriginDeclaredPayload::Collection { .. } => {
            clauses.push("s.origin_type='collection' AND s.collection_id=?".into());
        }
        crate::events::MessageOriginDeclaredPayload::Direct { principals } => {
            let placeholders = vec!["?"; principals.len()].join(",");
            clauses.push(format!(
                "s.origin_type='direct' AND s.direct_set_digest=? AND s.participant_count=?
                 AND (SELECT COUNT(*) FROM message_origin_principals exact
                       WHERE exact.message_id=s.message_id)=?
                 AND NOT EXISTS (
                       SELECT 1 FROM message_origin_principals exact
                        WHERE exact.message_id=s.message_id
                          AND exact.principal_id NOT IN ({placeholders})
                 )"
            ));
        }
    }
    if after.is_some() {
        clauses.push("(r.created_at<? OR (r.created_at=? AND s.message_id<?))".into());
    }
    clauses.push(view);
    let sql = format!(
        "SELECT s.message_id,r.created_at
           FROM message_origin_state s JOIN records r ON r.id=s.message_id
          WHERE {}
          ORDER BY r.created_at DESC,s.message_id DESC LIMIT ?",
        clauses.join(" AND ")
    );
    let mut query = sqlx::query_as::<_, (String, String)>(&sql);
    match &origin {
        crate::events::MessageOriginDeclaredPayload::Collection { collection_id } => {
            query = query.bind(collection_id);
        }
        crate::events::MessageOriginDeclaredPayload::Direct { principals } => {
            let count = principals.len() as i64;
            query = query
                .bind(crate::events::direct_origin_set_digest(principals))
                .bind(count)
                .bind(count);
            for principal in principals {
                query = query.bind(principal);
            }
        }
    }
    if let Some((created_at, id)) = &after {
        query = query.bind(created_at).bind(created_at).bind(id);
    }
    let mut candidates = query
        .bind(super::is_legacy_local(caller))
        .bind(caller.credential())
        .bind(caller.is_host_member())
        .bind(caller.credential())
        .bind((limit + 1) as i64)
        .fetch_all(&mut *snapshot)
        .await?;
    let has_more = candidates.len() > limit;
    candidates.truncate(limit);
    let mut reply_targets = BTreeMap::<String, Vec<String>>::new();
    let mut supersedes_targets = BTreeMap::<String, String>::new();
    if !candidates.is_empty() {
        let placeholders = vec!["?"; candidates.len()].join(",");
        let sql = format!(
            "SELECT source_id,target_id,relationship
               FROM links
              WHERE source_id IN ({placeholders})
                AND relationship IN ('reply_to','supersedes')
              ORDER BY source_id,relationship,created_at,id"
        );
        let mut query = sqlx::query(&sql);
        for (message_id, _) in &candidates {
            query = query.bind(message_id);
        }
        for row in query.fetch_all(&mut *snapshot).await? {
            let source_id: String = row.try_get("source_id")?;
            let target_id: String = row.try_get("target_id")?;
            match row.try_get::<String, _>("relationship")?.as_str() {
                "reply_to" => reply_targets.entry(source_id).or_default().push(target_id),
                "supersedes" => {
                    if supersedes_targets
                        .insert(source_id.clone(), target_id)
                        .is_some()
                    {
                        return Err(Error::engine(format!(
                            "manage_messages.list_context: Message {source_id} has multiple supersedes targets"
                        )));
                    }
                }
                _ => unreachable!("query restricts projected Message relationships"),
            }
        }
    }
    // A deleted parent of a live reply stays addressable as a body-less stub,
    // so a client can render "This message was deleted" in place with the
    // replies kept. Only replies this call already returns can reach a stub,
    // and a stub carries no body, name, author or audience.
    let reply_parents = reply_targets
        .values()
        .flatten()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let mut deleted_parents = Vec::new();
    if !reply_parents.is_empty() {
        let placeholders = vec!["?"; reply_parents.len()].join(",");
        let sql = format!(
            "SELECT id,created_at,deleted_at FROM records
              WHERE id IN ({placeholders}) AND type='Message' AND deleted_at IS NOT NULL
              ORDER BY created_at,id"
        );
        let mut query = sqlx::query(&sql);
        for parent in &reply_parents {
            query = query.bind(parent);
        }
        for row in query.fetch_all(&mut *snapshot).await? {
            // Seeing the reply is not enough: the stub names the parent's
            // times, so the caller must be able to see the parent itself, as
            // it was before the tombstone.
            let parent_id: String = row.try_get("id")?;
            let visible = crate::authorization::effective_capability_including_tombstone_on(
                &mut snapshot,
                super::principal(caller),
                &parent_id,
            )
            .await
            .is_ok_and(|capability| capability.allows(Capability::View));
            if !visible {
                continue;
            }
            deleted_parents.push(json!({
                "id":parent_id,
                "deleted":true,
                "body":null,
                "created_at":row.try_get::<String,_>("created_at")?,
                "deleted_at":row.try_get::<Option<String>,_>("deleted_at")?,
            }));
        }
    }
    let mut messages = Vec::with_capacity(candidates.len());
    for (id, _) in &candidates {
        let mut items = crate::query::read::get_records_live_in(
            &mut snapshot,
            std::slice::from_ref(id),
            crate::query::read::EnrichOptions {
                children_limit: 0,
                links_limit: 0,
                ..crate::query::read::EnrichOptions::default()
            },
            (!super::is_legacy_local(caller)).then(|| super::principal(caller)),
        )
        .await?;
        let Some(crate::query::read::BatchGetItem::Found(record)) = items.pop() else {
            return Err(Error::engine(
                "manage_messages.list_context: authorization predicate disagreed with hydration",
            ));
        };
        let mut value = serde_json::to_value(&record.record)?;
        value["reply_to_ids"] = serde_json::to_value(reply_targets.remove(id).unwrap_or_default())?;
        if let Some(supersedes_id) = supersedes_targets.remove(id) {
            value["supersedes_id"] = Value::String(supersedes_id);
        }
        if let Some(speaker) = crate::persona::message_speaker(&mut snapshot, id).await? {
            value["speaker"] = speaker;
        }
        messages.push(value);
    }
    snapshot.rollback().await?;
    let next_cursor = if has_more {
        let (message_id, created_at) = candidates.last().cloned().ok_or_else(|| {
            Error::engine("manage_messages.list_context: continuation cursor could not be issued")
        })?;
        Some(db.put_inbox_snapshot(serde_json::to_value(ContextCursor {
            schema: 1,
            account_id: caller.credential().into(),
            context_key,
            created_at,
            message_id,
        })?)?)
    } else {
        None
    };
    Ok(json!({
        "origin": origin,
        "messages": messages,
        "deleted_parents": deleted_parents,
        "viewer_relative": true,
        "has_more": has_more,
        "next_cursor": next_cursor,
    }))
}

async fn require_visible_message_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
) -> Result<()> {
    require_record_in(tx, caller, "manage_messages", message_id, Capability::View).await?;
    let is_message: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND type='Message' AND deleted_at IS NULL)",
    )
    .bind(message_id)
    .fetch_one(&mut **tx)
    .await?;
    if !is_message {
        return Err(Error::engine(format!("record {message_id} does not exist")));
    }
    Ok(())
}

/// The viewer's direct-context candidates, newest first.
///
/// - Declared direct origins naming the viewer come from
///   `idx_message_origin_principals_principal`.
/// - Notes to self come from `idx_records_unfiled_message_owner` (engine 92):
///   exactly the viewer's Person's Messages in Unfiled, then origin collection
///   `native:unfiled`, the viewer's own sender row and no `addressed_to` row,
///   each probed by primary key. The viewer's channel posts and other people's
///   notes never enter the read, and `owner_id` (not the mutable principal
///   binding) is the authorship fact.
/// - Legacy Messages (no declared origin) are found from the viewer's own
///   sender and `addressed_to` audience rows via `idx_message_audiences_principal`
///   (not by `owner_id`: a legacy Message the viewer sent stays theirs even if
///   its owner differs). The index has no `source` column, so every audience
///   row of the viewer is visited: the cost is O(the viewer's own sent and
///   addressed traffic), never a function of other people's activity.
///
/// Every join is a `CROSS JOIN` over a driving set, which pins the order so
/// the planner cannot start from a scan of `records`, `message_audiences` or
/// `message_origin_state` even once `ANALYZE` statistics exist; the indexes
/// are named with `INDEXED BY`. Legacy and note-to-self Messages must sit in
/// Unfiled; collection posts are never selected. `?1` is the JSON array of the
/// viewer's principals (retained aliases included); `?2` is the viewer's
/// Person id.
pub(crate) const DIRECT_SCOPE_IDS_SQL: &str = "WITH
     direct_ids AS MATERIALIZED (
       SELECT mop.message_id AS id FROM json_each(?1) j
         CROSS JOIN message_origin_principals mop INDEXED BY idx_message_origin_principals_principal
           ON mop.principal_id=j.value
     ),
     legacy_ids AS MATERIALIZED (
       SELECT DISTINCT ma.message_id AS id FROM json_each(?1) j
         CROSS JOIN message_audiences ma INDEXED BY idx_message_audiences_principal
           ON ma.principal_id=j.value
         CROSS JOIN message_origin_state s ON s.message_id=ma.message_id
        WHERE ma.source IN ('sender','addressed_to') AND s.status='legacy_unknown'
     ),
     self_ids AS MATERIALIZED (
       SELECT r.id AS id FROM records r INDEXED BY idx_records_unfiled_message_owner
         CROSS JOIN message_origin_state s ON s.message_id=r.id
        WHERE r.type='Message' AND r.home_id='native:unfiled' AND r.deleted_at IS NULL
          AND r.owner_id=?2
          AND s.status='declared' AND s.origin_type='collection'
          AND s.collection_id='native:unfiled'
          AND EXISTS (SELECT 1 FROM json_each(?1) j
                        CROSS JOIN message_audiences ma ON ma.message_id=r.id AND ma.principal_id=j.value
                       WHERE ma.source='sender')
          AND NOT EXISTS (SELECT 1 FROM message_audiences x
                           WHERE x.message_id=r.id AND x.source='addressed_to')
     ),
     mine(id, direct) AS MATERIALIZED (
       SELECT id, 1 FROM direct_ids
       UNION
       SELECT id, 0 FROM legacy_ids
       UNION
       SELECT id, 0 FROM self_ids
     )
     SELECT r.id FROM mine CROSS JOIN records r ON r.id=mine.id
      WHERE r.type='Message' AND r.deleted_at IS NULL
        AND (mine.direct=1 OR r.home_id IS NULL OR r.home_id='native:unfiled')
      ORDER BY r.created_at DESC, r.id DESC";

/// Visible direct-scope Message ids, newest first, capped. Selection is by
/// indexed principal probes before any hydration; visibility is applied
/// **before** the cap, in newest-first batches, until `cap + 1` visible
/// messages are found or the candidates run out. So unreadable messages never
/// use up the cap or push older readable ones out, and `truncated` means
/// "more *visible* direct messages exist". The viewer's principals include
/// retained aliases (every `native-principal` binding on their Person), since
/// a stored direct origin names the principal that was current when it was
/// sent. An unresolved viewer fails closed rather than listing nothing.
async fn direct_scope_candidates(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
) -> Result<(Vec<String>, bool)> {
    let principals: Vec<(String, String)> = sqlx::query_as(
        "SELECT DISTINCT p.identifier, a.record_id FROM bindings a
           JOIN records person ON person.id=a.record_id
           JOIN bindings p ON p.record_id=a.record_id AND p.system='native-principal'
          WHERE a.system='account' AND a.identifier=? AND a.is_canonical=1
            AND person.type='Entity' AND person.kind='person' AND person.deleted_at IS NULL",
    )
    .bind(caller.credential())
    .fetch_all(&mut **tx)
    .await?;
    if principals.is_empty() {
        return Err(Error::engine(
            "manage_messages.list_inbox: scope direct needs a current member identity",
        ));
    }
    let viewer_person = principals[0].1.clone();
    let principals: Vec<&str> = principals.iter().map(|(p, _)| p.as_str()).collect();
    let principals_json = serde_json::to_string(&principals)?;
    let candidates: Vec<String> = sqlx::query_scalar(DIRECT_SCOPE_IDS_SQL)
        .bind(&principals_json)
        .bind(&viewer_person)
        .fetch_all(&mut **tx)
        .await?;
    let cap = direct_scope_cap();
    let mut visible_ids: Vec<String> = Vec::new();
    for batch in candidates.chunks(500) {
        let visible = super::visible_ids_in(tx, caller, batch.to_vec()).await?;
        visible_ids.extend(batch.iter().filter(|id| visible.contains(*id)).cloned());
        if visible_ids.len() > cap {
            break;
        }
    }
    let truncated = visible_ids.len() > cap;
    visible_ids.truncate(cap);
    Ok((visible_ids, truncated))
}

async fn build_inbox_snapshot(
    db: &Db,
    caller: &Caller,
    view: &str,
    conversation_id: Option<&str>,
    scope: Option<&str>,
) -> Result<InboxSnapshot> {
    if !matches!(
        view,
        "needs_me" | "agent_queue" | "handled_without_me" | "all_new" | "browse"
    ) {
        return Err(Error::engine("invalid inbox view"));
    }
    build_inbox_snapshot_attempt(db, caller, view, conversation_id, scope, 3).await
}

async fn visible_in_snapshot(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    record_id: &str,
) -> Result<bool> {
    if caller.is_trusted_local() && caller.hosting_database().is_none() {
        return Ok(sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND deleted_at IS NULL)",
        )
        .bind(record_id)
        .fetch_one(&mut **tx)
        .await?);
    }
    Ok(
        crate::authorization::effective_capability_on(tx, super::principal(caller), record_id)
            .await
            .is_ok_and(|capability| capability.allows(Capability::View)),
    )
}

async fn build_inbox_snapshot_attempt(
    db: &Db,
    caller: &Caller,
    view: &str,
    conversation_id: Option<&str>,
    scope: Option<&str>,
    remaining: usize,
) -> Result<InboxSnapshot> {
    let mut tx = db.write_pool().begin().await?;
    if let Some(conversation_id) = conversation_id {
        if !visible_in_snapshot(&mut tx, caller, conversation_id).await? {
            return Err(Error::engine(format!(
                "record {conversation_id} does not exist"
            )));
        }
    }
    let database_id: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut *tx)
            .await?;
    let content_head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    let awareness_head: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM awareness_events")
            .fetch_one(&mut *tx)
            .await?;
    let candidate_head: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM notification_candidate_events")
            .fetch_one(&mut *tx)
            .await?;
    let control_head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM control_events")
        .fetch_one(&mut *tx)
        .await?;
    let authorization_revision: i64 =
        sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id=1")
            .fetch_one(&mut *tx)
            .await?;
    let mut truncated = false;
    let candidates: Vec<String> = if scope == Some("direct") {
        let (ids, cut) = direct_scope_candidates(&mut tx, caller).await?;
        truncated = cut;
        ids
    } else if let Some(conversation_id) = conversation_id {
        sqlx::query_scalar(
            "SELECT r.id FROM records r JOIN message_conversations mc ON mc.message_id=r.id
              WHERE r.type='Message' AND r.deleted_at IS NULL AND mc.conversation_id=?
              ORDER BY r.created_at DESC,r.id DESC LIMIT 10001",
        )
        .bind(conversation_id)
        .fetch_all(&mut *tx)
        .await?
    } else {
        sqlx::query_scalar(
            "SELECT id FROM records WHERE type='Message' AND deleted_at IS NULL ORDER BY created_at DESC,id DESC LIMIT 10001",
        ).fetch_all(&mut *tx).await?
    };
    if scope != Some("direct") && candidates.len() > 10_000 {
        return Err(Error::engine(
            "Inbox snapshot exceeds the bounded 10000 Message selection",
        ));
    }
    // Batched visibility through the canonical set-wise admission helper
    // (`visible_ids_in`: one admission set query plus the constant-statement
    // preloaded authorization fold). Scalar `visible_in_snapshot` remains for
    // the single conversation-id gate above; the per-candidate loop it used
    // to serve here issued one full authorization walk per Message.
    let message_ids = filter_visible_in_snapshot(&mut tx, caller, candidates).await?;
    // Batched hydration inside the same snapshot transaction. The batch
    // hydration overhead is constant (one joined row query, two grouped
    // count queries, one ranked reaction query plus two batched
    // actor-resolution queries, and the three-statement expectation base
    // preload); per-Message evidence walks inside the shared evaluator remain
    // linear and are the explicitly measured residual cost.
    // A direct-scope browse pins only the ordered ids: items are hydrated for
    // the requested page alone (page time), so page one costs `limit` items
    // however many DMs the viewer has. Other scoped views need the state to
    // decide membership, so they hydrate the (bounded) scoped set here to
    // decide it, then pin ids only and re-hydrate each page at page time.
    let lazy = scope == Some("direct") && view == "browse";
    let mut hydrated = if lazy {
        message_ids
            .iter()
            .map(|id| json!({"message_id": id, "_predicates": {}}))
            .collect()
    } else {
        hydrate_inbox_items_in(&mut tx, caller, &message_ids).await?
    };
    tx.commit().await?;
    let mut items = Vec::new();
    for mut item in hydrated.drain(..) {
        if item_in_view(&item, view) {
            item.as_object_mut().unwrap().remove("_predicates");
            // A scoped inbox pins only which messages belong (decided from the
            // state just read); page-time hydration re-reads their content, so
            // an edit between pages shows, on every view.
            if scope == Some("direct") {
                item = json!({"message_id": item["message_id"]});
            }
            items.push(item);
        }
    }
    let current_content: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
            .fetch_one(db.write_pool())
            .await?;
    let (current_awareness, current_candidate) =
        crate::awareness::heads_on(db.write_pool()).await?;
    let current_control: i64 =
        sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM control_events")
            .fetch_one(db.write_pool())
            .await?;
    let current_authorization: i64 =
        sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id=1")
            .fetch_one(db.write_pool())
            .await?;
    if (
        current_content,
        current_awareness,
        current_candidate,
        current_control,
        current_authorization,
    ) != (
        content_head,
        awareness_head,
        candidate_head,
        control_head,
        authorization_revision,
    ) {
        if remaining > 1 {
            return Box::pin(build_inbox_snapshot_attempt(
                db,
                caller,
                view,
                conversation_id,
                scope,
                remaining - 1,
            ))
            .await;
        }
        return Err(Error::engine(
            "cursor_reset_required: Inbox changed while snapshotting",
        ));
    }
    Ok(InboxSnapshot {
        schema: 1,
        database_id,
        account_id: caller.credential().into(),
        view: view.into(),
        conversation_id: conversation_id.map(str::to_owned),
        scope: scope.map(str::to_owned),
        truncated,
        content_head,
        awareness_head,
        candidate_head,
        control_head,
        authorization_revision,
        items,
    })
}

/// Batched visibility for the inbox candidate set, preserving the scalar
/// admission order and semantics for every caller.
///
/// This is the canonical set-wise form of the old per-candidate
/// `visible_in_snapshot` + per-item `can_record` gates:
/// [`super::visible_ids_in`] combines ordinary record-family admission with
/// the preloaded authorization fold (the same grant/owner/derived/Unit rules
/// the scalar `effective_capability_on` evaluates, including the
/// trusted-local shape-validation semantics for legacy callers) in one extra
/// set query plus the constant-statement preload. The result is a set, so
/// membership filters the candidate list below and the original
/// newest-first ordering is retained.
async fn filter_visible_in_snapshot(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    candidates: Vec<String>,
) -> Result<Vec<String>> {
    let visible = super::visible_ids_in(tx, caller, candidates.clone()).await?;
    Ok(candidates
        .into_iter()
        .filter(|id| visible.contains(id))
        .collect())
}

/// Batched inbox hydration inside the caller's snapshot transaction.
///
/// The batch hydration overhead is a constant number of statements
/// regardless of item count: one joined row query, one grouped
/// mention-count query, one grouped delivery-candidate query, one ranked
/// reaction query plus two batched actor-resolution queries, and the
/// three-statement expectation base preload (recipient binding, record
/// types, expectation facets). That constant covers the hydration overhead
/// only — the per-Message evidence walks inside the shared expectation
/// evaluator deliberately stay scalar on this same transaction (see the
/// call site), so their semantics are unchanged and their statements remain
/// linear in the visible count; they are the measured residual.
///
/// Ordering follows the input `message_ids` order (candidate newest-first).
/// Rows missing from the snapshot are skipped, matching the scalar
/// `inbox_item` `Ok(None)` behaviour. All other fields, defaults, and the
/// `_predicates.snoozed` computation are byte-for-byte the scalar logic.
async fn hydrate_inbox_items_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_ids: &[String],
) -> Result<Vec<Value>> {
    if message_ids.is_empty() {
        return Ok(Vec::new());
    }
    let ids_json = serde_json::to_string(message_ids)?;
    let rows = sqlx::query(
        "SELECT r.id,r.name,r.body,r.created_at,r.home_id,
                CASE WHEN r.owner_id=(SELECT account.record_id FROM bindings account JOIN records person ON person.id=account.record_id WHERE account.system='account' AND account.identifier=? AND account.is_canonical=1 AND person.type='Entity' AND person.kind='person' AND person.deleted_at IS NULL ORDER BY account.record_id LIMIT 1) AND NOT EXISTS(SELECT 1 FROM message_speakers speaker WHERE speaker.message_id=r.id) THEN 1 ELSE 0 END AS is_own,
                p.unread_override,
                COALESCE(h.stage,'unsurfaced') human_stage,COALESCE(h.version,0) human_version,
                COALESCE(a.state,'unhandled') agent_state,COALESCE(a.version,0) agent_version,
                COALESCE(p.attention_flag,0) attention_flag,COALESCE(p.muted,0) muted,
                p.snoozed_until,COALESCE(p.archived,0) archived,COALESCE(p.version,0) preference_version,
                ir.obligation_state,ir.executor_route,COALESCE(ir.version,0) routing_version,
                EXISTS(SELECT 1 FROM message_speakers speaker WHERE speaker.message_id=r.id) AS has_speaker,
                EXISTS(SELECT 1 FROM message_audiences audience JOIN bindings owner
                  ON owner.identifier=audience.principal_id AND owner.system='native-principal' AND owner.is_canonical=1
                  JOIN bindings account ON account.record_id=owner.record_id AND account.system='account' AND account.is_canonical=1
                  WHERE audience.message_id=r.id AND audience.source='addressed_to' AND account.identifier=?) AS addressed_to_viewer
           FROM records r
           LEFT JOIN human_message_awareness h ON h.message_id=r.id AND h.subject_account_id=?
           LEFT JOIN agent_message_dispositions a ON a.message_id=r.id AND a.subject_account_id=?
           LEFT JOIN message_preferences p ON p.message_id=r.id AND p.subject_account_id=?
           LEFT JOIN message_inbox_routing ir ON ir.message_id=r.id AND ir.subject_account_id=?
          WHERE r.id IN (SELECT value FROM json_each(?)) AND r.type='Message' AND r.deleted_at IS NULL",
    )
    .bind(caller.credential()).bind(caller.credential()).bind(caller.credential()).bind(caller.credential()).bind(caller.credential()).bind(caller.credential())
    .bind(&ids_json).fetch_all(&mut **tx).await?;
    let mut rows_by_id = std::collections::HashMap::with_capacity(rows.len());
    for row in rows {
        let id: String = row.try_get("id")?;
        rows_by_id.insert(id, row);
    }
    let mut mention_by_id = std::collections::HashMap::new();
    for row in sqlx::query(
        "SELECT mm.message_id AS message_id,COUNT(*) AS n FROM message_mentions mm
           JOIN bindings b ON b.record_id=mm.target_record_id AND b.system='account'
            AND b.identifier=? AND b.is_canonical=1
          WHERE mm.message_id IN (SELECT value FROM json_each(?))
            AND mm.target_kind='principal' AND mm.effective=1
          GROUP BY mm.message_id",
    )
    .bind(caller.credential())
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?
    {
        let id: String = row.try_get("message_id")?;
        let n: i64 = row.try_get("n")?;
        mention_by_id.insert(id, n);
    }
    let mut candidate_by_id = std::collections::HashMap::new();
    for row in sqlx::query(
        "SELECT message_id,COUNT(*) AS n FROM notification_candidates
          WHERE recipient_account_id=? AND message_id IN (SELECT value FROM json_each(?))
            AND status='effective' GROUP BY message_id",
    )
    .bind(caller.credential())
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?
    {
        let id: String = row.try_get("message_id")?;
        let n: i64 = row.try_get("n")?;
        candidate_by_id.insert(id, n);
    }
    let reactions_by_id = batched_reaction_groups_in(tx, caller.credential(), message_ids).await?;
    // Batched expectation base preloads (recipient binding, record types,
    // expectation facets: three constant statements) for the hydrated rows
    // only; evidence walks stay per-Message scalar inside the shared
    // evaluator, so derivation semantics are unchanged.
    let present_ids: Vec<String> = message_ids
        .iter()
        .filter(|id| rows_by_id.contains_key(*id))
        .cloned()
        .collect();
    let batch = if present_ids.is_empty() {
        Vec::new()
    } else {
        crate::message_expectation::derive_message_expectation_states_in(
            tx,
            &present_ids,
            caller.credential(),
        )
        .await?
    };
    let mut expectation_by_id = std::collections::HashMap::with_capacity(present_ids.len());
    for derived in batch {
        expectation_by_id.insert(derived.message_id.clone(), derived);
    }
    let mut items = Vec::new();
    for message_id in message_ids {
        let Some(row) = rows_by_id.remove(message_id) else {
            continue;
        };
        let expectation = expectation_by_id
            .remove(message_id)
            .expect("batched expectation derivations cover every hydrated row");
        let default_obligation = if row.try_get::<bool, _>("has_speaker")?
            && !row.try_get::<bool, _>("addressed_to_viewer")?
        {
            "none"
        } else {
            match expectation.state {
                crate::message_expectation::MessageExpectationState::Open
                | crate::message_expectation::MessageExpectationState::Unknown => "open",
                crate::message_expectation::MessageExpectationState::Satisfied => "satisfied",
                crate::message_expectation::MessageExpectationState::NotRequired => "none",
            }
        };
        let obligation_state = row
            .try_get::<Option<String>, _>("obligation_state")?
            .unwrap_or_else(|| default_obligation.into());
        let executor_route = row
            .try_get::<Option<String>, _>("executor_route")?
            .unwrap_or_else(|| {
                if obligation_state == "open" {
                    "human".into()
                } else {
                    "unassigned".into()
                }
            });
        let human_stage: String = row.try_get("human_stage")?;
        let agent_state: String = row.try_get("agent_state")?;
        let snoozed_until: Option<String> = row.try_get("snoozed_until")?;
        let snoozed = snoozed_until
            .as_deref()
            .and_then(|v| chrono::DateTime::parse_from_rfc3339(v).ok())
            .is_some_and(|v| v > chrono::Utc::now());
        let mention_count: i64 = mention_by_id.remove(message_id).unwrap_or(0);
        let candidate_count: i64 = candidate_by_id.remove(message_id).unwrap_or(0);
        let reactions = reactions_by_id.get(message_id).cloned().unwrap_or_default();
        items.push(json!({
            // The destination this Message was filed in, carried on every item so a
            // per-destination rollup is a grouping rather than a second query.
            // A Message sent without a home is filed under `native:unfiled` rather
            // than left homeless, so the grouping is total; `null` stays reserved
            // for a record that genuinely has no home.
            "message_id":message_id,"home_id":row.try_get::<Option<String>,_>("home_id")?,"name":row.try_get::<String,_>("name")?,"body":row.try_get::<Option<String>,_>("body")?,"created_at":row.try_get::<String,_>("created_at")?,
            "human":{"stage":human_stage,"version":row.try_get::<i64,_>("human_version")?},
            "agent":{"state":agent_state,"version":row.try_get::<i64,_>("agent_version")?},
            "obligation":{"state":obligation_state,"expectation_state":expectation.state},
            "route":{"executor":executor_route,"version":row.try_get::<i64,_>("routing_version")?},
            "mention":{"principal":mention_count>0},
            "attention":{"unread":private_message_unread(&human_stage,row.try_get("is_own")?,row.try_get("archived")?,row.try_get("unread_override")?),"unread_override":row.try_get::<Option<bool>,_>("unread_override")?,"flagged":row.try_get::<i64,_>("attention_flag")?!=0,"muted":row.try_get::<i64,_>("muted")?!=0,"snoozed_until":snoozed_until,"archived":row.try_get::<i64,_>("archived")?!=0,"version":row.try_get::<i64,_>("preference_version")?},
            "delivery":{"candidate_count":candidate_count},
            "reactions":reactions,
            "_predicates":{"snoozed":snoozed}
        }));
    }
    Ok(items)
}

/// Batched form of `reaction_groups_in`: one ranked reaction query across
/// all `message_ids`, then one batched binding query and one batched name
/// query for the distinct actors. Grouping, ordering (emoji, actor), the
/// `viewer` flag, the `record_id`/`account_id` fallback, and payload
/// validation are identical to the scalar path.
async fn batched_reaction_groups_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    viewer_account: &str,
    message_ids: &[String],
) -> Result<std::collections::HashMap<String, Vec<Value>>> {
    use std::collections::{BTreeMap, HashMap};
    let mut out: HashMap<String, Vec<Value>> = HashMap::new();
    if message_ids.is_empty() {
        return Ok(out);
    }
    let ids_json = serde_json::to_string(message_ids)?;
    let rows = sqlx::query(
        "WITH ranked AS (
           SELECT record_id AS message_id,type,actor,payload,created_at,
                  ROW_NUMBER() OVER (
                    PARTITION BY record_id,actor,json_extract(payload,'$.emoji') ORDER BY seq DESC
                  ) recency
             FROM content_events
            WHERE record_id IN (SELECT value FROM json_each(?))
              AND type IN ('message.reaction.added.v1','message.reaction.removed.v1')
         )
         SELECT message_id,actor,payload,created_at FROM ranked
          WHERE recency=1 AND type='message.reaction.added.v1'
          ORDER BY message_id,json_extract(payload,'$.emoji'),actor",
    )
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?;
    if rows.is_empty() {
        return Ok(out);
    }
    let mut actors = std::collections::BTreeSet::new();
    let mut parsed: Vec<(
        String,
        String,
        crate::events::MessageReactionPayload,
        String,
    )> = Vec::with_capacity(rows.len());
    for row in rows {
        let message_id: String = row.try_get("message_id")?;
        let account_id: String = row.try_get("actor")?;
        let payload: crate::events::MessageReactionPayload =
            serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
        payload.validate(Some(&account_id))?;
        let reacted_at: String = row.try_get("created_at")?;
        actors.insert(account_id.clone());
        parsed.push((message_id, account_id, payload, reacted_at));
    }
    let actors: Vec<String> = actors.into_iter().collect();
    let actors_json = serde_json::to_string(&actors)?;
    let mut record_by_actor: HashMap<String, String> = HashMap::new();
    for row in sqlx::query(
        "SELECT identifier,record_id FROM bindings
          WHERE system='account' AND is_canonical=1 AND identifier IN (SELECT value FROM json_each(?))",
    )
    .bind(&actors_json)
    .fetch_all(&mut **tx)
    .await?
    {
        let identifier: String = row.try_get("identifier")?;
        let record_id: String = row.try_get("record_id")?;
        record_by_actor.entry(identifier).or_insert(record_id);
    }
    let record_ids: Vec<String> = {
        let mut set = std::collections::BTreeSet::new();
        for record_id in record_by_actor.values() {
            set.insert(record_id.clone());
        }
        set.into_iter().collect()
    };
    let mut name_by_record: HashMap<String, String> = HashMap::new();
    if !record_ids.is_empty() {
        let records_json = serde_json::to_string(&record_ids)?;
        for row in sqlx::query(
            "SELECT id,name FROM records WHERE id IN (SELECT value FROM json_each(?)) AND deleted_at IS NULL",
        )
        .bind(&records_json)
        .fetch_all(&mut **tx)
        .await?
        {
            let id: String = row.try_get("id")?;
            let name: String = row.try_get("name")?;
            name_by_record.insert(id, name);
        }
    }
    let mut grouped: HashMap<String, BTreeMap<String, Vec<Value>>> = HashMap::new();
    for (message_id, account_id, payload, reacted_at) in parsed {
        let record_id = record_by_actor.get(&account_id).cloned();
        let name = record_id
            .as_deref()
            .and_then(|record_id| name_by_record.get(record_id).cloned());
        let mut actor = json!({
            "record_id":record_id,
            "name":name,
            "executor_kind":payload.executor_kind,
            "reacted_at":reacted_at,
            "viewer":account_id == viewer_account,
        });
        if actor["record_id"].is_null() {
            actor["account_id"] = json!(account_id);
        }
        grouped
            .entry(message_id)
            .or_default()
            .entry(payload.emoji)
            .or_default()
            .push(actor);
    }
    for (message_id, groups) in grouped {
        out.insert(
            message_id,
            groups
                .into_iter()
                .map(|(emoji, actors)| {
                    let viewer_reacted =
                        actors.iter().any(|actor| actor["viewer"] == true);
                    json!({"emoji":emoji,"count":actors.len(),"actors":actors,"viewer_reacted":viewer_reacted})
                })
                .collect(),
        );
    }
    Ok(out)
}

/// Transaction-scoped evidence admission for the `set_agent_disposition`
/// handler, which holds its `BEGIN IMMEDIATE` write transaction across
/// admission. Deriving and re-reading on the caller's transaction keeps one
/// pool slot and one snapshot instead of two: a pool-backed read here would
/// take a second write-pool connection while that transaction (and the
/// SQLite write lock) is held.
async fn validate_strong_agent_evidence_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    account: &str,
    message_id: &str,
    state: &str,
    evidence: &[crate::awareness::EvidenceInput],
) -> Result<()> {
    if !matches!(state, "acted" | "resolved") {
        return Ok(());
    }
    let derived =
        crate::message_expectation::derive_message_expectation_state_in(tx, message_id, account)
            .await?;
    if let Some(governed) = derived.evidence {
        let role = match governed.kind {
            crate::message_expectation::MessageExpectationEvidenceKind::Acknowledgement
            | crate::message_expectation::MessageExpectationEvidenceKind::Reply => "reply",
            crate::message_expectation::MessageExpectationEvidenceKind::CompletedWorkItem => "work",
            crate::message_expectation::MessageExpectationEvidenceKind::Decision => "decision",
            crate::message_expectation::MessageExpectationEvidenceKind::NoLongerRelevant => {
                "resolution"
            }
        };
        if evidence
            .iter()
            .any(|item| item.record_id == governed.record_id && item.role == role)
        {
            return Ok(());
        }
    }
    for item in evidence {
        let relationship = match item.role.as_str() {
            "reply" => "reply_to",
            "work" | "decision" | "resolution" => "derived_from",
            _ => continue,
        };
        let valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(
               SELECT 1 FROM records e
               JOIN bindings b ON b.record_id=e.owner_id AND b.system='account'
                 AND b.identifier=? AND b.is_canonical=1
               JOIN links l ON l.source_id=e.id AND l.target_id=? AND l.relationship=?
              WHERE e.id=? AND e.deleted_at IS NULL)",
        )
        .bind(account)
        .bind(message_id)
        .bind(relationship)
        .bind(&item.record_id)
        .fetch_one(&mut **tx)
        .await?;
        if valid {
            return Ok(());
        }
    }
    Err(Error::engine(
        "acted/resolved agent disposition evidence does not satisfy governed Message semantics",
    ))
}

pub(crate) fn item_in_view(item: &Value, view: &str) -> bool {
    let archived = item["attention"]["archived"].as_bool().unwrap_or(false);
    let snoozed = item["_predicates"]["snoozed"].as_bool().unwrap_or(false);
    let obligation = item["obligation"]["state"].as_str().unwrap_or("none");
    let route = item["route"]["executor"].as_str().unwrap_or("unassigned");
    let human = item["human"]["stage"].as_str().unwrap_or("unsurfaced");
    let agent = item["agent"]["state"].as_str().unwrap_or("unhandled");
    match view {
        "needs_me" => obligation == "open" && route == "human" && !snoozed && !archived,
        "agent_queue" => {
            obligation == "open"
                && matches!(route, "agent" | "joint")
                && !matches!(agent, "acted" | "resolved")
        }
        "handled_without_me" => human == "unsurfaced" && matches!(agent, "acted" | "resolved"),
        "all_new" => {
            item["attention"]["unread"].as_bool().unwrap_or(false) && !snoozed && !archived
        }
        "browse" => true,
        _ => false,
    }
}

/// Typed response for `get_attention`. It is deliberately not an inbox
/// response: [`crate::awareness::validate_messaging_surface_response`] only
/// accepts `native.message-inbox.v3` shapes, and this endpoint never builds
/// one.
const ATTENTION_SCHEMA: &str = "native.message-attention.v1";

/// Bound on the newest-first filtered-candidate scan. The filter (unsurfaced,
/// not-self, unsuppressed) applies before the bound, so this caps attention
/// work rather than total Messages; exceeding it errors rather than answering
/// `false`.
const ATTENTION_CANDIDATE_LIMIT: i64 = 10_001;

/// Viewer-correct header-dot boolean without inbox hydration.
///
/// This is the server side of the workbench attention snapshot: one joined,
/// bounded newest-first candidate query plus, per surviving candidate, one
/// live visibility check through [`can_record_in`] in the same read
/// transaction, and a principal lookup only for a direct candidate that
/// survived everything else. The scan always fetches up to the bound; a match
/// ends per-candidate work early but never skips that bounded fetch. There is
/// no inbox item projection, no expectation derivation, no reaction groups,
/// no Message bodies, and no inbox snapshot token stored.
///
/// The predicate mirrors the workbench `adapter.newMessages` dot exactly:
/// explicit unread override or legacy unsurfaced human stage, author exclusion against the caller's own live
/// Person (`owner_id IS NOT` keeps the NULL-owner behaviour identical to the
/// `!==` comparison), unarchived/unmuted attention in SQL with the
/// not-future-snoozed check per surviving row in Rust, and a valid
/// destination (declared collection; declared direct with the stored
/// digest/count invariant and at least two principals; explicit
/// `legacy_unknown` filed under its home, with a homeless legacy Message
/// contributing no destination). A missing origin projection is a fail-closed
/// error like hydration — nothing is silently skipped into a `false`.
async fn get_attention(db: &Db, caller: &Caller) -> Result<Value> {
    let mut tx = db.write_pool().begin().await?;
    // The caller is the viewer. No request field names a Person: a
    // user-supplied id here would let one account ask after another's dot.
    let person_id = attention_person_id_in(&mut tx, caller).await?;
    let Some(person_id) = person_id else {
        tx.rollback().await?;
        return Ok(
            json!({"schema":ATTENTION_SCHEMA,"has_new_messages":false,"viewer_relative":true}),
        );
    };
    let rows = sqlx::query(
        "SELECT r.id AS message_id, r.home_id AS home_id,
                p.snoozed_until AS snoozed_until,
                s.status AS origin_status, s.origin_type AS origin_type,
                s.collection_id AS collection_id,
                s.direct_set_digest AS direct_set_digest,
                s.participant_count AS participant_count
           FROM records r
           LEFT JOIN human_message_awareness h
             ON h.message_id=r.id AND h.subject_account_id=?
           LEFT JOIN message_preferences p
             ON p.message_id=r.id AND p.subject_account_id=?
           LEFT JOIN message_origin_state s ON s.message_id=r.id
          WHERE r.type='Message' AND r.deleted_at IS NULL
            AND COALESCE(p.unread_override, CASE WHEN COALESCE(h.stage,'unsurfaced')='unsurfaced' THEN 1 ELSE 0 END)=1
            AND (r.owner_id IS NOT ? OR EXISTS(SELECT 1 FROM message_speakers speaker WHERE speaker.message_id=r.id))
            AND COALESCE(p.archived,0)=0 AND COALESCE(p.muted,0)=0
          ORDER BY r.created_at DESC, r.id DESC LIMIT ?",
    )
    .bind(caller.credential())
    .bind(caller.credential())
    .bind(&person_id)
    .bind(ATTENTION_CANDIDATE_LIMIT)
    .fetch_all(&mut *tx)
    .await?;
    if rows.len() as i64 >= ATTENTION_CANDIDATE_LIMIT {
        return Err(Error::engine(
            "get_attention exceeds the bounded 10000 Message selection",
        ));
    }
    for row in &rows {
        let message_id: String = row.try_get("message_id")?;
        if !can_record_in(&mut tx, caller, &message_id, Capability::View).await? {
            continue;
        }
        let snoozed = row
            .try_get::<Option<String>, _>("snoozed_until")?
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
            .is_some_and(|value| value > chrono::Utc::now());
        if snoozed {
            continue;
        }
        let status: Option<String> = row.try_get("origin_status")?;
        let has_destination = match status.as_deref() {
            None => {
                return Err(Error::engine(format!(
                    "Message {message_id} has no communication-origin projection state"
                )));
            }
            Some("legacy_unknown") => row.try_get::<Option<String>, _>("home_id")?.is_some(),
            Some("declared") => match row.try_get::<Option<String>, _>("origin_type")?.as_deref() {
                Some("collection") => row.try_get::<Option<String>, _>("collection_id")?.is_some(),
                Some("direct") => {
                    let stored = sqlx::query_scalar::<_, String>(
                        "SELECT principal_id FROM message_origin_principals
                          WHERE message_id=? ORDER BY principal_id",
                    )
                    .bind(&message_id)
                    .fetch_all(&mut *tx)
                    .await?;
                    // Same normalization the send and list_context paths
                    // canonicalize with: sorted distinct principals. The
                    // stored projection is already canonical, so this is a
                    // no-op on healthy rows and fail-closed on corrupt ones.
                    let principals = crate::events::normalize_direct_origin_principals(stored);
                    let stored_digest: Option<String> = row.try_get("direct_set_digest")?;
                    let stored_count: Option<i64> = row.try_get("participant_count")?;
                    if stored_count != Some(principals.len() as i64)
                        || stored_digest.as_deref()
                            != Some(crate::events::direct_origin_set_digest(&principals).as_str())
                    {
                        return Err(Error::engine(format!(
                            "Message {message_id} has inconsistent direct communication-origin projection"
                        )));
                    }
                    principals.len() >= 2
                }
                _ => {
                    return Err(Error::engine(format!(
                        "Message {message_id} has invalid declared communication-origin state"
                    )));
                }
            },
            _ => {
                return Err(Error::engine(format!(
                    "Message {message_id} has invalid declared communication-origin state"
                )));
            }
        };
        if has_destination {
            tx.rollback().await?;
            return Ok(
                json!({"schema":ATTENTION_SCHEMA,"has_new_messages":true,"viewer_relative":true}),
            );
        }
    }
    tx.rollback().await?;
    Ok(json!({"schema":ATTENTION_SCHEMA,"has_new_messages":false,"viewer_relative":true}))
}

async fn manage_messages(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    // The exact dispatched arguments, kept for the keyed classification and
    // no-longer-relevant actions: a keyed lookup recomputes their digest.
    let provenance_arguments = matches!(
        arguments.get("action").and_then(Value::as_str),
        Some(
            "classify"
                | "unclassify"
                | "move"
                | "mark_no_longer_relevant"
                | "unmark_no_longer_relevant"
                | "delete"
                | "edit"
        )
    )
    .then(|| arguments.clone());
    let arguments = parse_args("manage_messages", arguments)?;
    // Sending enters the creation kernel. Keep the unrelated read/awareness
    // branches out of its poll frame on normal worker and test-thread stacks.
    match arguments {
        arguments @ ManageMessagesArgs::Send { .. } => {
            Box::pin(manage_messages_send(db, caller, arguments)).await
        }
        arguments => {
            Box::pin(manage_messages_non_send(
                db,
                caller,
                arguments,
                provenance_arguments,
            ))
            .await
        }
    }
}

async fn manage_messages_send(
    db: Db,
    caller: Caller,
    arguments: ManageMessagesArgs,
) -> Result<Value> {
    match arguments {
        ManageMessagesArgs::Send {
            id,
            body,
            speaker,
            preview,
            name,
            addressed_to,
            origin,
            expectation,
            home_id,
            owner_id,
            links,
            mentions,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason("manage_messages.send", &reason)?;
            if body.trim().is_empty() {
                return Err(Error::engine(
                    "manage_messages.send: body must not be blank",
                ));
            }
            if preview
                .as_deref()
                .is_some_and(|value| value.trim().is_empty() || value.chars().count() > 500)
            {
                return Err(Error::engine(
                    "manage_messages.send: preview must be nonblank and at most 500 characters",
                ));
            }
            // Addressing carries expectation; communication origin carries
            // venue. An empty addressed_to is therefore valid in either
            // context only when no response is expected.
            if addressed_to.is_empty() && expectation != "none" {
                return Err(Error::engine(format!(
                    "manage_messages.send: an empty addressed_to requires expectation 'none', not '{expectation}'; address whoever carries the obligation",
                )));
            }
            let home_id = home_id.or_else(|| match &origin {
                super::lifecycle::MessageOriginInput::Collection { collection_id } => {
                    Some(collection_id.clone())
                }
                super::lifecycle::MessageOriginInput::Direct { .. } => {
                    Some(crate::schema::UNFILED_RECORD_ID.into())
                }
            });
            let mut create = json!({
                "type":"Message",
                "kind":"text",
                "body":body,
                "addressed_to":addressed_to,
                "origin":origin,
                "facets":{"expectation":expectation},
                "reason":reason,
            });
            let object = create.as_object_mut().expect("message create object");
            if let Some(id) = id {
                object.insert("id".into(), Value::String(id));
            }
            if let Some(name) = name {
                object.insert("name".into(), Value::String(name));
            }
            if let Some(home_id) = home_id {
                object.insert("home_id".into(), Value::String(home_id));
            }
            if let Some(owner_id) = owner_id {
                object.insert("owner_id".into(), Value::String(owner_id));
            }
            if let Some(links) = links {
                object.insert("links".into(), links);
            }
            if let Some(mentions) = mentions {
                object.insert("mentions".into(), serde_json::to_value(mentions)?);
            }
            let intent_digest = crate::interventions::sha256_json(&json!({
                "create":&create,
                "preview":&preview,
            }))?;
            super::lifecycle::send_message_record(
                db,
                caller,
                create,
                super::lifecycle::SendMessagePlan {
                    speaker,
                    idempotency_key,
                    intent_digest,
                    disclosure_preview: preview,
                },
            )
            .await
        }
        _ => unreachable!("send dispatch requires the send variant"),
    }
}

async fn manage_messages_non_send(
    db: Db,
    caller: Caller,
    arguments: ManageMessagesArgs,
    provenance_arguments: Option<Value>,
) -> Result<Value> {
    match arguments {
        ManageMessagesArgs::Send { .. } => unreachable!("send uses its dedicated dispatcher"),
        ManageMessagesArgs::ListContext {
            origin,
            limit,
            cursor,
        } => list_context(&db, &caller, origin, limit, cursor).await,
        ManageMessagesArgs::Classify {
            message_id,
            conversation_id,
            idempotency_key,
        } => {
            let keyed = classification_key("classify", idempotency_key.as_deref())?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            require_classification_authority(&mut tx, &caller, &message_id, &conversation_id)
                .await?;
            // Keyed replay: after authorization, before the existing-relation
            // check the first call's own effect would now trip.
            if keyed {
                if let Some((receipt, replay)) = replay_classification(
                    &mut tx,
                    &caller,
                    provenance_arguments.as_ref(),
                    &message_id,
                    ClassificationReplay::Classify(&conversation_id),
                )
                .await?
                {
                    tx.rollback().await?;
                    replay.settle();
                    return Ok(receipt);
                }
            }
            let changed = !relation_exists(&mut tx, &message_id, &conversation_id).await?;
            if changed {
                append_classification(
                    &db,
                    &mut tx,
                    &caller,
                    &message_id,
                    &conversation_id,
                    true,
                    &mut act_alloc,
                )
                .await?;
            }
            super::keyed_replay::anchor_noop_in(&mut tx).await?;
            db.commit_content(tx).await?;
            Ok(echo_act(
                json!({"status": if changed {"classified"} else {"unchanged"}, "message_id":message_id,"conversation_id":conversation_id,"changed":changed}),
                act_alloc.get(),
            )?)
        }
        ManageMessagesArgs::Unclassify {
            message_id,
            conversation_id,
            idempotency_key,
        } => {
            let keyed = classification_key("unclassify", idempotency_key.as_deref())?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            require_classification_authority(&mut tx, &caller, &message_id, &conversation_id)
                .await?;
            if keyed {
                if let Some((receipt, replay)) = replay_classification(
                    &mut tx,
                    &caller,
                    provenance_arguments.as_ref(),
                    &message_id,
                    ClassificationReplay::Unclassify(&conversation_id),
                )
                .await?
                {
                    tx.rollback().await?;
                    replay.settle();
                    return Ok(receipt);
                }
            }
            let changed = relation_exists(&mut tx, &message_id, &conversation_id).await?;
            if changed {
                append_classification(
                    &db,
                    &mut tx,
                    &caller,
                    &message_id,
                    &conversation_id,
                    false,
                    &mut act_alloc,
                )
                .await?;
            }
            super::keyed_replay::anchor_noop_in(&mut tx).await?;
            db.commit_content(tx).await?;
            Ok(echo_act(
                json!({"status": if changed {"unclassified"} else {"unchanged"}, "message_id":message_id,"conversation_id":conversation_id,"changed":changed}),
                act_alloc.get(),
            )?)
        }
        ManageMessagesArgs::Move {
            message_id,
            from_conversation_id,
            to_conversation_id,
            idempotency_key,
        } => {
            let keyed = classification_key("move", idempotency_key.as_deref())?;
            if from_conversation_id == to_conversation_id {
                return Err(Error::engine(
                    "manage_messages.move requires different Conversations",
                ));
            }
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            require_classification_authority(&mut tx, &caller, &message_id, &from_conversation_id)
                .await?;
            require_record_in(
                &mut tx,
                &caller,
                "manage_messages",
                &to_conversation_id,
                Capability::View,
            )
            .await?;
            // Keyed replay: after both authority checks, before the
            // source-classification check the first move already consumed.
            if keyed {
                if let Some((receipt, replay)) = replay_classification(
                    &mut tx,
                    &caller,
                    provenance_arguments.as_ref(),
                    &message_id,
                    ClassificationReplay::Move {
                        from: &from_conversation_id,
                        to: &to_conversation_id,
                    },
                )
                .await?
                {
                    tx.rollback().await?;
                    replay.settle();
                    return Ok(receipt);
                }
            }
            if !relation_exists(&mut tx, &message_id, &from_conversation_id).await? {
                return Err(Error::engine(
                    "manage_messages.move source classification does not exist",
                ));
            }
            append_classification(
                &db,
                &mut tx,
                &caller,
                &message_id,
                &from_conversation_id,
                false,
                &mut act_alloc,
            )
            .await?;
            if !relation_exists(&mut tx, &message_id, &to_conversation_id).await? {
                append_classification(
                    &db,
                    &mut tx,
                    &caller,
                    &message_id,
                    &to_conversation_id,
                    true,
                    &mut act_alloc,
                )
                .await?;
            }
            db.commit_content(tx).await?;
            Ok(echo_act(
                json!({"status":"moved","message_id":message_id,"from_conversation_id":from_conversation_id,"to_conversation_id":to_conversation_id,"changed":true}),
                act_alloc.get(),
            )?)
        }
        ManageMessagesArgs::ShareHistory {
            recipient_id,
            message_ids,
            conversation_id,
            snapshot_seq,
            reason,
            idempotency_key,
        } => {
            refuse_share_history_key(idempotency_key.as_ref())?;
            share_history(
                &db,
                &caller,
                recipient_id,
                message_ids,
                conversation_id,
                snapshot_seq,
                reason,
            )
            .await
        }
        ManageMessagesArgs::AddReaction {
            message_id,
            emoji,
            idempotency_key,
            reason,
        } => {
            mutate_reaction(
                &db,
                &caller,
                message_id,
                emoji,
                idempotency_key,
                reason,
                true,
            )
            .await
        }
        ManageMessagesArgs::RemoveReaction {
            message_id,
            emoji,
            idempotency_key,
            reason,
        } => {
            mutate_reaction(
                &db,
                &caller,
                message_id,
                emoji,
                idempotency_key,
                reason,
                false,
            )
            .await
        }
        ManageMessagesArgs::SatisfyAcknowledgementExpectationWithReaction {
            message_id,
            idempotency_key,
            reason,
        } => {
            satisfy_acknowledgement_expectation_with_reaction(
                &db,
                &caller,
                message_id,
                idempotency_key,
                reason,
            )
            .await
        }
        ManageMessagesArgs::MarkNoLongerRelevant {
            message_id,
            note,
            idempotency_key,
            reason,
        } => {
            mark_message_no_longer_relevant(
                &db,
                &caller,
                message_id,
                note,
                idempotency_key,
                reason,
                provenance_arguments.as_ref(),
            )
            .await
        }
        ManageMessagesArgs::UnmarkNoLongerRelevant {
            message_id,
            idempotency_key,
            reason,
        } => {
            unmark_message_no_longer_relevant(
                &db,
                &caller,
                message_id,
                idempotency_key,
                reason,
                provenance_arguments.as_ref(),
            )
            .await
        }
        ManageMessagesArgs::Edit {
            message_id,
            body,
            mentions,
            idempotency_key,
            reason,
        } => {
            edit_message(
                &db,
                &caller,
                message_id,
                body,
                mentions,
                idempotency_key,
                reason,
                provenance_arguments.as_ref(),
            )
            .await
        }
        ManageMessagesArgs::Delete {
            message_id,
            idempotency_key,
            reason,
        } => {
            delete_message(
                &db,
                &caller,
                message_id,
                idempotency_key,
                reason,
                provenance_arguments.as_ref(),
            )
            .await
        }
        ManageMessagesArgs::ListMessageState { mut message_ids } => {
            if message_ids.is_empty() || message_ids.len() > 200 {
                return Err(Error::engine(
                    "list_message_state requires 1..=200 exact Message ids",
                ));
            }
            let unique = message_ids.iter().collect::<BTreeSet<_>>();
            if unique.len() != message_ids.len() {
                return Err(Error::engine(
                    "list_message_state Message ids must be unique",
                ));
            }
            let mut tx = db.write_pool().begin().await?;
            let content_head: i64 =
                sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
                    .fetch_one(&mut *tx)
                    .await?;
            let mut messages = Vec::with_capacity(message_ids.len());
            for message_id in message_ids.drain(..) {
                messages.push(message_state_in(&mut tx, &caller, &message_id).await?);
            }
            tx.rollback().await?;
            Ok(json!({
                "schema":"native.message-state.v1","content_head":content_head,
                "messages":messages,"viewer_relative":true,"snapshot_consistent":true,
            }))
        }
        ManageMessagesArgs::ListConversation { conversation_id } => {
            if !can_record(&db, &caller, &conversation_id, Capability::View).await? {
                return Err(Error::engine(format!(
                    "record {conversation_id} does not exist"
                )));
            }
            let candidates: Vec<String> = sqlx::query_scalar(
                "SELECT message_id FROM message_conversations WHERE conversation_id=? ORDER BY classified_at,message_id",
            ).bind(&conversation_id).fetch_all(db.write_pool()).await?;
            let messages = visible_message_rows(&db, &caller, candidates).await?;
            let visible_ids: Vec<&str> = messages.iter().filter_map(|m| m["id"].as_str()).collect();
            let mut involved = BTreeSet::new();
            for id in visible_ids {
                for principal in sqlx::query_scalar::<_,String>("SELECT DISTINCT principal_id FROM message_audiences WHERE message_id=? ORDER BY principal_id").bind(id).fetch_all(db.write_pool()).await? {
                    involved.insert(principal);
                }
            }
            Ok(
                json!({"conversation_id":conversation_id,"messages":messages,"involved_principals":involved,"viewer_relative":true,"roster_authoritative":false}),
            )
        }
        ManageMessagesArgs::ListUnclassified => {
            let candidates: Vec<String> = sqlx::query_scalar(
                "SELECT r.id FROM records r WHERE r.type='Message' AND r.deleted_at IS NULL AND NOT EXISTS(SELECT 1 FROM message_conversations mc WHERE mc.message_id=r.id) ORDER BY r.created_at,r.id",
            ).fetch_all(db.write_pool()).await?;
            Ok(
                json!({"messages":visible_message_rows(&db,&caller,candidates).await?,"container":null,"query":"unclassified"}),
            )
        }
        ManageMessagesArgs::ListMyConversations => {
            let candidates: Vec<String> = sqlx::query_scalar("SELECT id FROM records WHERE type='Message' AND deleted_at IS NULL ORDER BY created_at,id").fetch_all(db.write_pool()).await?;
            let visible = visible_message_rows(&db, &caller, candidates).await?;
            let mut conversations = BTreeMap::<String, usize>::new();
            for message in visible {
                let Some(message_id) = message["id"].as_str() else {
                    continue;
                };
                for conversation_id in sqlx::query_scalar::<_,String>("SELECT conversation_id FROM message_conversations WHERE message_id=? ORDER BY conversation_id").bind(message_id).fetch_all(db.write_pool()).await? {
                    if can_record(&db,&caller,&conversation_id,Capability::View).await? {
                        *conversations.entry(conversation_id).or_default() += 1;
                    }
                }
            }
            Ok(
                json!({"conversations":conversations.into_iter().map(|(conversation_id,visible_message_count)|json!({"conversation_id":conversation_id,"visible_message_count":visible_message_count})).collect::<Vec<_>>(),"derived_from_readable_messages":true}),
            )
        }
        ManageMessagesArgs::MutateHumanAwareness {
            mut message_ids,
            stage,
            expected_versions,
            idempotency_key,
            snapshot,
            reason,
        } => {
            require_nonblank_reason("manage_messages.mutate_human_awareness", &reason)?;
            if message_ids.is_empty()
                || message_ids.len() > crate::awareness::MAX_EXACT_MESSAGE_BATCH
            {
                return Err(Error::engine(
                    "human awareness mutation requires 1..=500 exact Message ids",
                ));
            }
            let original_len = message_ids.len();
            message_ids.sort();
            message_ids.dedup();
            if message_ids.len() != original_len {
                return Err(Error::engine(
                    "duplicate Message id in exact awareness mutation",
                ));
            }
            if expected_versions.len() != message_ids.len()
                || message_ids
                    .iter()
                    .any(|message_id| !expected_versions.contains_key(message_id))
            {
                return Err(Error::engine(
                    "expected_versions must match the exact Message-id set",
                ));
            }
            if message_ids.len() > 1 && snapshot.is_none() {
                return Err(Error::engine(
                    "human awareness batch requires a pinned Inbox snapshot",
                ));
            }
            let attestation = caller
                .verified_human_interaction()
                .ok_or_else(|| {
                    Error::engine(
                        "human awareness requires a server-verified interaction attestation",
                    )
                })?
                .clone();
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            let first_application = crate::awareness::register_human_batch_command(
                &mut tx,
                caller.credential(),
                stage,
                &message_ids,
                &expected_versions,
                &idempotency_key,
                snapshot.as_deref(),
                &attestation,
                &reason,
                &mut act_alloc,
            )
            .await?;
            if first_application {
                if let Some(raw) = snapshot.as_deref() {
                    let parsed = decode_snapshot(&db, raw)?;
                    let current_db: String = sqlx::query_scalar(
                        "SELECT origin_db_id FROM database_identity WHERE singleton=1",
                    )
                    .fetch_one(&mut *tx)
                    .await?;
                    if parsed.database_id != current_db || parsed.account_id != caller.credential()
                    {
                        return Err(Error::engine(
                            "cursor_reset_required: inbox snapshot binding mismatch",
                        ));
                    }
                    let pinned_ids = parsed
                        .items
                        .iter()
                        .map(|item| {
                            item["message_id"].as_str().ok_or_else(|| {
                                Error::engine("cursor_reset_required: malformed Inbox snapshot")
                            })
                        })
                        .collect::<Result<BTreeSet<_>>>()?;
                    if message_ids
                        .iter()
                        .any(|message_id| !pinned_ids.contains(message_id.as_str()))
                    {
                        return Err(Error::engine(
                            "human awareness Message set is not contained in the supplied Inbox snapshot",
                        ));
                    }
                }
            }
            let mut results = Vec::new();
            for message_id in &message_ids {
                require_visible_message_in(&mut tx, &caller, message_id).await?;
                let expected = *expected_versions.get(message_id).ok_or_else(|| {
                    Error::engine(format!("missing expected version for Message {message_id}"))
                })?;
                results.push(
                    crate::awareness::advance_human(
                        &mut tx,
                        caller.credential(),
                        message_id,
                        stage,
                        expected,
                        &format!("{idempotency_key}:{message_id}"),
                        &attestation,
                        &reason,
                        &mut act_alloc,
                    )
                    .await?,
                );
            }
            db.commit_awareness(tx).await?;
            Ok(echo_act(
                json!({"status":"applied","results":results,"exact_message_ids":message_ids}),
                act_alloc.get(),
            )?)
        }
        ManageMessagesArgs::SetAgentDisposition {
            message_id,
            state,
            expected_version,
            idempotency_key,
            evidence,
            reason,
        } => {
            require_nonblank_reason("manage_messages.set_agent_disposition", &reason)?;
            let verified_executor = caller.verified_agent_executor().ok_or_else(|| {
                Error::engine(
                    "agent disposition requires server-verified executor and delegation context",
                )
            })?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            require_visible_message_in(&mut tx, &caller, &message_id).await?;
            for item in &evidence {
                require_record_in(
                    &mut tx,
                    &caller,
                    "manage_messages",
                    &item.record_id,
                    Capability::View,
                )
                .await?;
            }
            validate_strong_agent_evidence_in(
                &mut tx,
                caller.credential(),
                &message_id,
                &state,
                &evidence,
            )
            .await?;
            let context = crate::awareness::MutationContext {
                subject_account_id: caller.credential(),
                authenticated_actor: caller.actor(),
                executor_kind: "agent",
                executor_ref: Some(&verified_executor.executor_ref),
                delegation_ref: Some(&verified_executor.delegation_ref),
                reason_code: &reason,
            };
            let result = crate::awareness::set_agent_disposition(
                &mut tx,
                &context,
                &message_id,
                &state,
                expected_version,
                &idempotency_key,
                &evidence,
                &mut act_alloc,
            )
            .await?;
            db.commit_awareness(tx).await?;
            Ok(echo_act(result, act_alloc.get())?)
        }
        ManageMessagesArgs::SetPreference {
            message_id,
            preference,
            snoozed_until,
            expected_version,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason("manage_messages.set_preference", &reason)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            require_visible_message_in(&mut tx, &caller, &message_id).await?;
            let result = crate::awareness::set_preference(
                &mut tx,
                caller.credential(),
                &message_id,
                preference,
                snoozed_until.as_deref(),
                expected_version,
                &idempotency_key,
                &reason,
                &mut act_alloc,
            )
            .await?;
            db.commit_awareness(tx).await?;
            Ok(echo_act(result, act_alloc.get())?)
        }
        ManageMessagesArgs::SetRouting {
            message_id,
            obligation_state,
            executor_route,
            policy_version,
            expected_version,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason("manage_messages.set_routing", &reason)?;
            let (executor_kind, executor_ref) =
                if let Some(attestation) = caller.verified_human_interaction() {
                    ("human_attested", Some(attestation.executor_ref.as_str()))
                } else if caller.has_policy_authority() {
                    ("system", caller.run_key())
                } else {
                    return Err(Error::engine(
                        "routing requires attested principal choice or trusted policy authority",
                    ));
                };
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            require_visible_message_in(&mut tx, &caller, &message_id).await?;
            let context = crate::awareness::MutationContext {
                subject_account_id: caller.credential(),
                authenticated_actor: caller.actor(),
                executor_kind,
                executor_ref,
                delegation_ref: None,
                reason_code: &reason,
            };
            let result = crate::awareness::set_routing(
                &mut tx,
                &context,
                &message_id,
                &obligation_state,
                &executor_route,
                policy_version.as_deref(),
                expected_version,
                &idempotency_key,
                &mut act_alloc,
            )
            .await?;
            db.commit_awareness(tx).await?;
            Ok(echo_act(result, act_alloc.get())?)
        }
        ManageMessagesArgs::ListInbox {
            view,
            conversation_id,
            limit,
            snapshot,
            after,
            scope,
            preview_chars,
        } => {
            if limit == 0 || limit > 200 {
                return Err(Error::engine("inbox limit must be 1..=200"));
            }
            if scope.as_deref().is_some_and(|scope| scope != "direct") {
                return Err(Error::engine("inbox scope must be \"direct\""));
            }
            if scope.is_some() && conversation_id.is_some() {
                return Err(Error::engine(
                    "inbox scope and conversation_id are mutually exclusive",
                ));
            }
            if preview_chars.is_some_and(|n| n == 0 || n > MAX_PREVIEW_CHARS) {
                return Err(Error::engine("inbox preview_chars must be 1..=1000"));
            }
            let preview_chars =
                preview_chars.or((scope.is_some()).then_some(DIRECT_SCOPE_DEFAULT_PREVIEW_CHARS));
            let (snapshot, snapshot_token) = if let Some(raw) = snapshot {
                let parsed = decode_snapshot(&db, &raw)?;
                let current_db: String = sqlx::query_scalar(
                    "SELECT origin_db_id FROM database_identity WHERE singleton=1",
                )
                .fetch_one(db.write_pool())
                .await?;
                if parsed.database_id != current_db
                    || parsed.account_id != caller.credential()
                    || parsed.view != view
                    || parsed.conversation_id != conversation_id
                    || parsed.scope != scope
                {
                    return Err(Error::engine(
                        "cursor_reset_required: inbox snapshot binding mismatch",
                    ));
                }
                (parsed, raw)
            } else {
                let parsed = build_inbox_snapshot(
                    &db,
                    &caller,
                    &view,
                    conversation_id.as_deref(),
                    scope.as_deref(),
                )
                .await?;
                let token = db.put_inbox_snapshot(serde_json::to_value(&parsed)?)?;
                (parsed, token)
            };
            let offset = after.unwrap_or(0);
            if offset > snapshot.items.len() {
                return Err(Error::engine(
                    "cursor_reset_required: invalid seek position",
                ));
            }
            let mut items = Vec::new();
            let mut cursor = offset;
            // One read transaction (one snapshot) for authorization, hydration
            // and identity, so a revocation or edit that lands between the
            // check and the read cannot return content the viewer was not
            // authorized for in the snapshot being read. Messages that fail
            // the check are dropped from the page, as a revoked message always
            // was.
            let mut tx = db.write_pool().begin().await?;
            while cursor < snapshot.items.len() && items.len() < limit {
                let item = snapshot.items[cursor].clone();
                let message_id = item["message_id"].as_str().ok_or_else(|| {
                    Error::engine("cursor_reset_required: malformed Inbox snapshot")
                })?;
                // The semantic/view state is frozen; only live revocation can
                // shrink a later page.
                if can_record_in(&mut tx, &caller, message_id, Capability::View).await? {
                    items.push(item);
                }
                cursor += 1;
            }
            #[cfg(test)]
            {
                let seam = INBOX_PAGE_SEAM.with(|seam| seam.borrow().clone());
                if let Some(seam) = seam {
                    seam().await;
                }
            }
            // Page-time work: hydrate a lazily pinned page, then resolve the
            // v3 identity fields for this page only, under the viewer's
            // authority at this moment. Neither is part of the frozen
            // snapshot, so a later page cannot replay a name or reply target
            // the viewer has since lost sight of.
            if !items.is_empty() {
                if items.iter().any(|item| item.get("human").is_none()) {
                    let ids: Vec<String> = items
                        .iter()
                        .filter_map(|item| item["message_id"].as_str().map(str::to_owned))
                        .collect();
                    let mut hydrated: std::collections::HashMap<String, Value> =
                        hydrate_inbox_items_in(&mut tx, &caller, &ids)
                            .await?
                            .into_iter()
                            .filter_map(|mut item| {
                                item.as_object_mut()?.remove("_predicates");
                                Some((item["message_id"].as_str()?.to_owned(), item))
                            })
                            .collect();
                    items = ids.iter().filter_map(|id| hydrated.remove(id)).collect();
                }
                let page_ids: Vec<String> = items
                    .iter()
                    .filter_map(|item| item["message_id"].as_str().map(str::to_owned))
                    .collect();
                let mut identity = Box::pin(inbox_identity::batched_identity_in(
                    &mut tx, &caller, &page_ids,
                ))
                .await?;
                for item in &mut items {
                    if let Some(extra) = item["message_id"]
                        .as_str()
                        .and_then(|id| identity.remove(id))
                    {
                        item.as_object_mut().unwrap().extend(extra);
                    }
                }
            }
            tx.rollback().await?;
            if let Some(limit_chars) = preview_chars {
                for item in &mut items {
                    apply_preview(item, limit_chars);
                }
            }
            let heads = crate::awareness::heads_on(db.write_pool()).await?;
            let current_content: i64 =
                sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
                    .fetch_one(db.write_pool())
                    .await?;
            let current_control: i64 =
                sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM control_events")
                    .fetch_one(db.write_pool())
                    .await?;
            let current_authorization: i64 =
                sqlx::query_scalar("SELECT epoch FROM authorization_revision WHERE id=1")
                    .fetch_one(db.write_pool())
                    .await?;
            let response = json!({"schema":crate::awareness::MESSAGE_INBOX_SCHEMA,"view":view,"items":items,"snapshot":snapshot_token,"next_after":(cursor<snapshot.items.len()).then_some(cursor),"newer_available":current_content>snapshot.content_head||heads.0>snapshot.awareness_head||heads.1>snapshot.candidate_head||current_control>snapshot.control_head||current_authorization!=snapshot.authorization_revision,"heads":{"content":snapshot.content_head,"awareness":snapshot.awareness_head,"candidates":snapshot.candidate_head,"control":snapshot.control_head,"authorization":snapshot.authorization_revision},"counts_are_distinct_message_ids":true});
            let mut response = response;
            if let Some(scope) = &snapshot.scope {
                response["scope"] = json!(scope);
                response["candidate_cap"] = json!(direct_scope_cap());
                response["truncated"] = json!(snapshot.truncated);
            }
            crate::awareness::validate_messaging_surface_response(&response)?;
            Ok(response)
        }
        ManageMessagesArgs::SetDestination {
            collection_id,
            destination,
            expected_version,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason("manage_messages.set_destination", &reason)?;
            let action = crate::awareness::DestinationAction::parse(&destination)?;
            // The rail is personal state about a Collection, so the gate is the
            // same one that decides whether the member may see that Collection
            // at all. Adding demands present visibility; removing does not, so a
            // member is never trapped on a rail entry they have lost access to.
            // Attestation is recorded when the ingress could establish it and
            // is not demanded: this is the member's own rail, the same standing
            // as their own preferences, not an authority claim over anyone else.
            let (executor_kind, executor_ref) =
                if let Some(attestation) = caller.verified_human_interaction() {
                    ("human_attested", Some(attestation.executor_ref.as_str()))
                } else {
                    ("system", None)
                };
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            if matches!(action, crate::awareness::DestinationAction::Add) {
                // Authorization and destination-shape validation belong under
                // the same serialized write lock as the awareness append. A
                // check before BEGIN would allow a concurrent revoke, delete,
                // or reclassification to land between admission and mutation.
                require_record_in(
                    &mut tx,
                    &caller,
                    "manage_messages.set_destination",
                    &collection_id,
                    Capability::View,
                )
                .await?;
                super::lifecycle::assert_home_target_in(
                    &mut tx,
                    "manage_messages.set_destination",
                    &collection_id,
                )
                .await?;
            }
            let context = crate::awareness::MutationContext {
                subject_account_id: caller.credential(),
                authenticated_actor: caller.actor(),
                executor_kind,
                executor_ref,
                delegation_ref: None,
                reason_code: &reason,
            };
            let result = crate::awareness::set_destination(
                &mut tx,
                &context,
                &collection_id,
                action,
                expected_version,
                &idempotency_key,
                &mut act_alloc,
            )
            .await?;
            db.commit_awareness(tx).await?;
            Ok(echo_act(result, act_alloc.get())?)
        }
        ManageMessagesArgs::ListDestinations { include_removed } => {
            let rail = crate::awareness::list_destinations_on(
                db.write_pool(),
                caller.credential(),
                include_removed,
            )
            .await?;
            // Reading the rail is not joining it, and neither is opening what it
            // points at. Only a send couples.
            //
            // `include_removed` adds the member's own tombstones, each carrying
            // `present:false` and the version the CAS will demand on a rejoin.
            // The visibility filter below is unchanged and applies to them too:
            // re-adding already requires seeing the Collection, so a tombstone
            // the caller can no longer see carries no version they could spend,
            // and the pinned authorization threshold for this read stays
            // caller-self-visible-collection.
            let mut destinations = Vec::new();
            for entry in rail {
                let Some(collection_id) = entry["collection_id"].as_str() else {
                    continue;
                };
                if !can_record(&db, &caller, collection_id, Capability::View).await? {
                    continue;
                }
                destinations.push(entry);
            }
            Ok(json!({"destinations":destinations,"viewer_relative":true}))
        }
        ManageMessagesArgs::ListNotificationCandidates { after_seq, limit } => {
            if limit == 0 || limit > 200 {
                return Err(Error::engine("candidate limit must be 1..=200"));
            }
            let rows=sqlx::query("SELECT candidate_id,message_id,reason,priority,not_before,redaction_class,evaluator_kind,policy_version,candidate_event_seq,status,created_at FROM notification_candidates WHERE recipient_account_id=? AND candidate_event_seq>? ORDER BY candidate_event_seq LIMIT ?").bind(caller.credential()).bind(after_seq).bind(limit as i64).fetch_all(db.write_pool()).await?;
            let mut candidates = Vec::new();
            for row in rows {
                let message_id: String = row.try_get("message_id")?;
                if !can_record(&db, &caller, &message_id, Capability::View).await? {
                    continue;
                }
                candidates.push(json!({"candidate_id":row.try_get::<String,_>("candidate_id")?,"message_id":message_id,"reason":row.try_get::<String,_>("reason")?,"priority":row.try_get::<String,_>("priority")?,"not_before":row.try_get::<Option<String>,_>("not_before")?,"redaction_class":row.try_get::<String,_>("redaction_class")?,"evaluator_kind":row.try_get::<String,_>("evaluator_kind")?,"policy_version":row.try_get::<String,_>("policy_version")?,"seq":row.try_get::<i64,_>("candidate_event_seq")?,"status":row.try_get::<String,_>("status")?,"created_at":row.try_get::<String,_>("created_at")?}));
            }
            Ok(
                json!({"candidates":candidates,"delivery_facts_are_not_awareness":true,"retention_floor":crate::awareness::CANDIDATE_RETENTION_FLOOR}),
            )
        }
        ManageMessagesArgs::GetAttention => get_attention(&db, &caller).await,
        ManageMessagesArgs::GetNotificationPreference => Ok(json!({
            "arrival": crate::awareness::notification_arrival_on(db.write_pool(), caller.credential()).await?,
            "values": crate::control::NOTIFICATION_ARRIVAL_VALUES,
        })),
        ManageMessagesArgs::SetNotificationPreference {
            arrival,
            idempotency_key,
            reason,
        } => {
            require_nonblank_reason("manage_messages.set_notification_preference", &reason)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            let result = crate::awareness::set_notification_arrival_in(
                &mut tx,
                caller.credential(),
                caller.actor(),
                caller.run_key(),
                &arrival,
                &idempotency_key,
                &reason,
                &mut act_alloc,
            )
            .await?;
            db.commit_control(tx).await?;
            Ok(echo_act(result, act_alloc.get())?)
        }
    }
}

fn manage_messages_schema() -> Value {
    json!({
            "type":"object",
            "properties":{
                "action":{"type":"string","enum":["send","list_context","classify","unclassify","move","share_history","add_reaction","remove_reaction","satisfy_acknowledgement_expectation_with_reaction","mark_no_longer_relevant","unmark_no_longer_relevant","delete","edit","list_message_state","list_conversation","list_unclassified","list_my_conversations","mutate_human_awareness","set_agent_disposition","set_preference","set_routing","set_destination","list_destinations","list_inbox","list_notification_candidates","get_attention","get_notification_preference","set_notification_preference"]},
                "id":{"type":"string"},
                "body":{"type":"string","minLength":1},
                "speaker":{"type":"object","properties":{"persona_id":{"type":"string","pattern":"\\S"}},"required":["persona_id"],"additionalProperties":false,"description":"Persona claim."},
                "preview":{"type":"string","minLength":1,"maxLength":500},
                "name":{"type":"string"},
                "addressed_to":{"type":"array","uniqueItems":true,"items":{"type":"string"}},
                "origin":{"oneOf":[{"type":"object","properties":{"type":{"const":"collection"},"collection_id":{"type":"string"}},"required":["type","collection_id"],"additionalProperties":false},{"type":"object","properties":{"type":{"const":"direct"},"participant_ids":{"type":"array","minItems":2,"uniqueItems":true,"items":{"type":"string"}}},"required":["type","participant_ids"],"additionalProperties":false}],"description":"Immutable context; direct IDs resolve to an exact canonical-principal set."},
                "cursor":{"type":"string","description":"Opaque list_context cursor."},
                "expectation":{"type":"string","enum":["none","ack","reply","action","decision"]},
                "home_id":{"type":"string","description":"Filing only; never context."},
                "owner_id":{"type":"string"},
                "links":{"type":"array","items":{"type":"object","properties":{"target_id":{"type":"string"},"relationship":{"type":"string"},"note":{"type":"string"}},"required":["target_id","relationship"],"additionalProperties":false}},
                "mentions":{"type":"array","uniqueItems":true,"items":{"type":"object","properties":{"mention_id":{"type":"string"},"target_kind":{"type":"string","enum":["principal","record"]},"target_id":{"type":"string"},"span_start":{"type":"integer","minimum":0},"span_end":{"type":"integer","minimum":1},"authored_label":{"type":"string"}},"required":["mention_id","target_kind","target_id","span_start","span_end","authored_label"],"additionalProperties":false}},
                "message_id":{"type":"string"},
                "note":{"type":"string","description":"Optional note stored as the no-longer-relevant mark body."},
                "emoji":{"type":"string","enum":["👍","❤️","😂","🎉","👀"]},
                "conversation_id":{"type":"string"},
                "collection_id":{"type":"string"},
                "destination":{"type":"string","enum":["add","remove"]},
                "include_removed":{"type":"boolean"},
                "from_conversation_id":{"type":"string"},
                "to_conversation_id":{"type":"string"},
                "recipient_id":{"type":"string"},
                "message_ids":{"type":"array","uniqueItems":true,"items":{"type":"string"}},
                "snapshot_seq":{"type":"integer","minimum":0},
                "stage":{"type":"string","enum":["presented","opened","acknowledged"]},
                "expected_versions":{"type":"object","additionalProperties":{"type":"integer","minimum":0}},
                "expected_version":{"type":"integer","minimum":0},
                "idempotency_key":{"type":"string","minLength":1},
                "state":{"type":"string","enum":["triaged","deferred","escalated","acted","resolved"]},
                "evidence":{"type":"array","items":{"type":"object","properties":{"record_id":{"type":"string"},"role":{"type":"string","enum":["reply","work","decision","resolution","other"]}},"required":["record_id","role"],"additionalProperties":false}},
                "preference":{"type":"string","enum":["mark_read","mark_unread","flag_attention","clear_attention","mute","unmute","snooze","clear_snooze","archive","restore"],"description":"Private read/unread."},
                "snoozed_until":{"type":"string","format":"date-time"},
                "arrival":{"type":"string","enum":["all","dms_and_mentions","off"],"description":"Routine arrivals that notify: all (DMs and thread replies), dms_and_mentions (DMs only), off. Mentions and obligations always notify. Default all."},
                "obligation_state":{"type":"string","enum":["none","open","satisfied","withdrawn"]},
                "executor_route":{"type":"string","enum":["unassigned","human","agent","joint","closed"]},
                "policy_version":{"type":"string"},
                "view":{"type":"string","enum":["needs_me","agent_queue","handled_without_me","all_new","browse"]},
                "limit":{"type":"integer","minimum":1,"maximum":200},
                "snapshot":{"type":"string"},
                "after":{"type":"integer","minimum":0},
                "scope":{"enum":["direct"]},
                "preview_chars":{"type":"integer"},
                "after_seq":{"type":"integer","minimum":0},
                "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
            },
            "required":["action"],
            "additionalProperties":false
    })
}

fn describe_send_property(
    properties: &mut serde_json::Map<String, Value>,
    field: &str,
    description: &str,
) {
    if let Some(property) = properties.get_mut(field) {
        property["description"] = json!(description);
    }
}

pub(crate) fn manage_messages_send_operation_schema() -> Value {
    let source = manage_messages_schema();
    let source_properties = source["properties"]
        .as_object()
        .expect("manage_messages schema properties");
    let mut send_properties = serde_json::Map::new();
    for field in [
        "id",
        "body",
        "speaker",
        "preview",
        "name",
        "addressed_to",
        "origin",
        "expectation",
        "home_id",
        "owner_id",
        "links",
        "mentions",
        "idempotency_key",
        "reason",
    ] {
        send_properties.insert(field.into(), source_properties[field].clone());
    }
    for field in ["body", "preview", "idempotency_key", "reason"] {
        send_properties[field]
            .as_object_mut()
            .expect("send string property schema")
            .insert("pattern".into(), json!("\\S"));
    }
    // Operation-specific disclosure for correct first calls. The shared
    // direct-tool schema stays generic; only this selector-specific contract
    // names the creation-time reply shape and mention span units, because
    // only send authors immutable Message prose.
    describe_send_property(
        &mut send_properties,
        "body",
        "Immutable Message prose. Mention spans index these exact UTF-8 bytes.",
    );
    describe_send_property(
        &mut send_properties,
        "origin",
        "Immutable communication origin: the Collection venue or the exact direct participant set. A reply or correction must repeat its target's origin exactly; filing home never substitutes for origin.",
    );
    describe_send_property(
        &mut send_properties,
        "speaker",
        "Persona claim {persona_id}; engine selects assurance and the author remains the owner. After ordinary permission checks, invalid, foreign, nonexistent, retired or malformed claims all refuse as speaker not found. A speaker never grants authority. Self-addressing requires a valid speaker fact. Every send receipt, including retries, reports speaker_claim_status recorded|absent for the committed Message. Retries validate supplied claims and cannot add or replace its speaker. Federation export refuses speaker-bearing Messages (participant_message_not_federatable); canonical interchange preserves them.",
    );
    describe_send_property(
        &mut send_properties,
        "addressed_to",
        "Addressed audience carrying the obligation. An empty audience is valid only with expectation 'none'.",
    );
    describe_send_property(
        &mut send_properties,
        "expectation",
        "Obligation this send places: none, ack, reply, action, or decision. An empty addressed_to requires 'none'.",
    );
    describe_send_property(
        &mut send_properties,
        "home_id",
        "Filing home only; never communication context. A Collection-origin send must file in that Collection.",
    );
    describe_send_property(
        &mut send_properties,
        "idempotency_key",
        "Unique per distinct send intent. Reuse with a different intent is rejected.",
    );
    describe_send_property(
        &mut send_properties,
        "links",
        "Optional creation-time context only. At most one reply_to and at most one supersedes target; a reply or correction must retain its target's communication origin. reply_to is immutable Message content: it cannot be added after creation, so a flat send stays unthreaded.",
    );
    // The reply_to shape is the incident-proven ambiguity, so it carries the
    // contract's one schema example.
    if let Some(items) = send_properties
        .get_mut("links")
        .and_then(|links| links.get_mut("items"))
        .and_then(|items| items.get_mut("properties"))
    {
        if let Some(target) = items.get_mut("target_id") {
            target["description"] = json!("The Message this send replies to or corrects.");
        }
        if let Some(relationship) = items.get_mut("relationship") {
            relationship["description"] = json!(
                "reply_to threads this send under the target; supersedes corrects it. Other relationships carry no messaging semantics."
            );
        }
    }
    if let Some(links) = send_properties.get_mut("links") {
        links["examples"] = json!([[{"target_id": "<message-id>", "relationship": "reply_to"}]]);
    }
    describe_send_property(
        &mut send_properties,
        "mentions",
        "Mentions into immutable prose. Spans are zero-based half-open UTF-8 byte offsets [span_start, span_end) into body; both ends must be UTF-8 character boundaries and body[span_start..span_end] must equal authored_label. A principal mention target must already be addressed, except in a Collection-origin send, where a person who can see that Collection may be mentioned without being addressed: the mention alerts them, adds no obligation, and does not change who can read the Message.",
    );
    if let Some(items) = send_properties
        .get_mut("mentions")
        .and_then(|mentions| mentions.get_mut("items"))
        .and_then(|items| items.get_mut("properties"))
    {
        for (field, description) in [
            (
                "mention_id",
                "Unique within this send; non-empty.",
            ),
            (
                "target_kind",
                "principal mentions a person; record mentions a record.",
            ),
            (
                "target_id",
                "Mentioned Person or record. A principal target must already be addressed, unless the origin is a Collection the person can see.",
            ),
            (
                "span_start",
                "Zero-based UTF-8 byte offset where the mentioned slice begins; must be a character boundary.",
            ),
            (
                "span_end",
                "UTF-8 byte offset one past the mentioned slice; must be a character boundary greater than span_start.",
            ),
            (
                "authored_label",
                "Exact body slice body[span_start..span_end]; must match byte-for-byte, including multibyte text.",
            ),
        ] {
            if let Some(property) = items.get_mut(field) {
                property["description"] = json!(description);
            }
        }
    }
    // "Héllo recipient": é is two UTF-8 bytes, so "recipient" spans bytes
    // 7..16. Byte offsets, not character counts, are what the validator
    // checks.
    if let Some(mentions) = send_properties.get_mut("mentions") {
        mentions["examples"] = json!([[
            {
                "mention_id": "mention-1",
                "target_kind": "principal",
                "target_id": "<person-id>",
                "span_start": 7,
                "span_end": 16,
                "authored_label": "recipient"
            }
        ]]);
    }
    json!({
      "allOf":[
       {
        "type":"object",
        "properties":send_properties,
        "required":["body","addressed_to","origin","expectation","idempotency_key","reason"],
        "additionalProperties":false
       },
       {
        "oneOf":[
         {
          "title":"Send addressed message",
          "properties":{
           "addressed_to":{"type":"array","items":{"type":"string"},"minItems":1}
          }
         },
         {
          "title":"Send without an addressed obligation",
          "properties":{
           "addressed_to":{"type":"array","items":{"type":"string"},"maxItems":0},
           "expectation":{"type":"string","const":"none"}
          }
         }
        ]
       }
      ]
    })
}

pub fn register_messaging_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageMessages,
        "Direct/Collection send/read/classify/share; reactions/👍 ack; Inbox/destinations; awareness/routing/preferences. Filing/visibility ≠ context.",
        manage_messages_schema(),
        |db, caller, arguments| {
            // Keyed classify/unclassify/move replay inside their own
            // BEGIN IMMEDIATE, so the authority-index race is unreachable
            // today; wrapping it keeps the contract's step 5 backstop.
            super::keyed_replay::with_race_replay(move || {
                Box::pin(manage_messages(
                    db.clone(),
                    caller.clone(),
                    arguments.clone(),
                ))
            })
        },
    )?;
    registry.register_operation_schema(
        ToolKind::ManageMessages.name(),
        "send",
        manage_messages_send_operation_schema(),
    )
}

#[cfg(test)]
mod destination_authorization_tests {
    use super::*;
    use crate::authorization::{AllowEntry, Capability};
    use serde_json::json;
    use std::sync::Arc;

    #[tokio::test]
    async fn a_revoke_queued_before_destination_begin_wins_without_writing() {
        let db = crate::create_database(":memory:").await.unwrap();
        let collection_id = "47e70000-0000-4000-8000-000000000001";
        crate::store::create_record(
            &db,
            json!({
                "id": collection_id,
                "type": "Collection",
                "kind": "folder",
                "name": "Revoked while queued"
            }),
        )
        .await
        .unwrap();
        crate::authorization::replace_explicit_policy(
            &db,
            "test:grant",
            collection_id,
            vec![AllowEntry::account("acct:member", Capability::View)],
        )
        .await
        .unwrap();

        // Hold the writer with an uncommitted revoke. The destination call's
        // public reader can still see the old grant, but its BEGIN queues
        // behind this transaction. Once admitted it must re-evaluate policy in
        // that serialized snapshot and refuse without appending awareness.
        let mut revoke = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut act_alloc = crate::act::ActAllocation::new();
        crate::authorization::replace_explicit_policy_on(
            &mut revoke,
            "test:revoke",
            collection_id,
            vec![],
            &mut act_alloc,
        )
        .await
        .unwrap();

        let before_begin = Arc::new(tokio::sync::Notify::new());
        let queued_db = db.clone();
        let queued = tokio::spawn(crate::db::with_before_begin_write_notification(
            before_begin.clone(),
            async move {
                manage_messages(
                    queued_db,
                    Caller::authenticated("acct:member"),
                    json!({
                        "action":"set_destination",
                        "collection_id":collection_id,
                        "destination":"add",
                        "expected_version":0,
                        "idempotency_key":"queued-add",
                        "reason":"Try to join while access is being revoked."
                    }),
                )
                .await
            },
        ));
        before_begin.notified().await;
        assert!(!queued.is_finished());
        revoke.commit().await.unwrap();

        let error = queued.await.unwrap().unwrap_err().to_string();
        assert!(error.contains("does not exist"), "{error}");
        let writes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM awareness_events
              WHERE subject_account_id='acct:member' AND lane='destination'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(writes, 0, "revocation must win without an awareness append");
    }
}

#[cfg(test)]
mod inbox_snapshot_batching_tests {
    use super::*;
    use crate::db::with_write_pool_acquisition_counter;
    use sqlx::Row;

    const BUNCH_SENDER: &str = "4e55a9e0-0000-4000-8000-000000000004";
    const BUNCH_RECIPIENT: &str = "4e55a9e0-0000-4000-8000-000000000003";

    async fn install_bunch_people(db: &Db) {
        for (record_id, principal, account) in [
            (BUNCH_SENDER, "native/sender", "acct_sender"),
            (BUNCH_RECIPIENT, "native/recipient", "acct_recipient"),
        ] {
            crate::store::create_record(
                db,
                serde_json::json!({"id":record_id,"type":"Entity","kind":"person","name":record_id}),
            )
            .await
            .unwrap();
            for (system, identifier) in [("native-principal", principal), ("account", account)] {
                sqlx::query(
                    "INSERT INTO bindings(record_id,system,identifier,is_canonical)
                     VALUES (?,?,?,1)",
                )
                .bind(record_id)
                .bind(system)
                .bind(identifier)
                .execute(db.write_pool())
                .await
                .unwrap();
            }
        }
    }

    async fn seed_bunch(db: &Db, count: usize) -> Vec<String> {
        install_bunch_people(db).await;
        let mut ids = Vec::with_capacity(count);
        for index in 0..count {
            let arguments = serde_json::json!({
                "action": "send",
                "body": format!("bunch message {index}"),
                "owner_id": BUNCH_SENDER,
                "origin": {"type": "direct", "participant_ids": [BUNCH_SENDER, BUNCH_RECIPIENT]},
                "addressed_to": [BUNCH_RECIPIENT],
                "expectation": "none",
                "idempotency_key": format!("bunch-send-{count}-{index}"),
                "reason": "Seed the snapshot batching acquisition fixture.",
            });
            let id = manage_messages(db.clone(), Caller::local(), arguments)
                .await
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned();
            ids.push(id);
        }
        ids
    }

    async fn snapshot_acquisitions(db: &Db, caller: &Caller) -> (usize, u64) {
        let (result, acquisitions) = with_write_pool_acquisition_counter(build_inbox_snapshot(
            db, caller, "browse", None, None,
        ))
        .await;
        let snapshot = result.unwrap();
        (snapshot.items.len(), acquisitions)
    }

    /// Scalar control replaying the old per-Message pool path: for every id
    /// the same sequence the pre-batch `inbox_item` loop issued against the
    /// pool (admission, row, expectation, mention count, candidate count,
    /// reaction groups — each at least one checkout). Read-only; seeding
    /// stays outside the measured scope.
    async fn scalar_control_acquisitions(db: &Db, caller: &Caller, ids: &[String]) -> u64 {
        let (_, acquisitions) = with_write_pool_acquisition_counter(async {
            for id in ids {
                let _ = super::can_record(db, caller, id, Capability::View).await.unwrap();
                let _ = sqlx::query("SELECT id FROM records WHERE id=?")
                    .bind(id)
                    .fetch_optional(db.write_pool())
                    .await
                    .unwrap();
                let _ =
                    crate::message_expectation::derive_message_expectation_state(db, id, caller.credential())
                        .await
                        .unwrap();
                let _ = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM message_mentions WHERE message_id=?",
                )
                .bind(id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
                let _ = sqlx::query_scalar::<_, i64>(
                    "SELECT COUNT(*) FROM notification_candidates WHERE recipient_account_id=? AND message_id=?",
                )
                .bind(caller.credential())
                .bind(id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
                let _ = reaction_groups(db, caller.credential(), id).await.unwrap();
            }
        })
        .await;
        acquisitions
    }

    /// Deterministic pool-churn before/after evidence for the batched
    /// snapshot path: one snapshot transaction plus the constant optimistic
    /// head re-checks, regardless of item count, so batched acquisitions
    /// stay flat while the scalar control replaying the old per-Message
    /// pool loop grows linearly with Message count. Statement constancy for
    /// the visibility half is pinned separately by
    /// `preloaded_authorization_statement_count_is_constant_for_401_records`;
    /// the batch hydration overhead is likewise constant, and the
    /// expectation base preload (binding, types, facets) is now constant
    /// too — only per-Message evidence walks inside the shared evaluator
    /// remain linear, on the single snapshot connection: statements, zero
    /// acquisitions. No timing assertions anywhere.
    #[tokio::test]
    async fn inbox_snapshot_pool_acquisitions_do_not_grow_with_message_count() {
        let small_db = crate::create_database(":memory:").await.unwrap();
        let small_ids = seed_bunch(&small_db, 8).await;
        let large_db = crate::create_database(":memory:").await.unwrap();
        let large_ids = seed_bunch(&large_db, 64).await;
        let caller = Caller::authenticated("acct_recipient");
        let (small_items, small) = snapshot_acquisitions(&small_db, &caller).await;
        let (large_items, large) = snapshot_acquisitions(&large_db, &caller).await;
        assert_eq!(small_items, 8);
        assert_eq!(large_items, 64);
        // Legacy local parity: the same seeded Messages stay visible through
        // the canonical set-wise admission helper, which carries the
        // trusted-local shape-validation semantics the old per-item
        // `can_record` gate enforced after the scalar existence check.
        let (local_items, _) = snapshot_acquisitions(&large_db, &Caller::local()).await;
        assert_eq!(local_items, 64);
        let small_control = scalar_control_acquisitions(&small_db, &caller, &small_ids).await;
        let large_control = scalar_control_acquisitions(&large_db, &caller, &large_ids).await;
        eprintln!(
            "inbox snapshot acquisitions: batched small(8)={small} large(64)={large}; scalar control small(8)={small_control} large(64)={large_control}"
        );
        assert!(
            small <= 10,
            "8-message snapshot took {small} write-pool acquisitions, expected <= 10"
        );
        assert!(
            large <= small + 2,
            "64-message snapshot took {large} acquisitions vs {small} for 8 messages: hydration must not add pool checkouts"
        );
        assert!(
            large_control - small_control >= 100,
            "scalar control grew only {small_control} -> {large_control}: the control must demonstrate the old linear slope"
        );
        assert!(
            large + 100 <= large_control,
            "batched 64-message snapshot took {large} acquisitions vs scalar control {large_control}: expected an order-of-magnitude gap"
        );
        small_db.close().await;
        large_db.close().await;
    }

    /// A Message whose semantic-Unit bearer edge is cyclic fails the
    /// trusted-local shape validation the scalar gate enforces. The batched
    /// local path must agree with the scalar verdict exactly: this is the
    /// case the naive legacy bypass (returning every candidate) missed.
    #[tokio::test]
    async fn batched_local_visibility_matches_scalar_shape_rejection() {
        let db = crate::create_database(":memory:").await.unwrap();
        install_bunch_people(&db).await;
        let arguments = serde_json::json!({
            "action": "send",
            "body": "cyclic bearer victim",
            "owner_id": BUNCH_SENDER,
            "origin": {"type": "direct", "participant_ids": [BUNCH_SENDER, BUNCH_RECIPIENT]},
            "addressed_to": [BUNCH_RECIPIENT],
            "expectation": "none",
            "idempotency_key": "shape-victim-send",
            "reason": "Seed the shape-rejection parity fixture.",
        });
        let victim = manage_messages(db.clone(), Caller::local(), arguments)
            .await
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let creation = sqlx::query(
            "SELECT id, seq, created_at FROM content_events WHERE record_id = ? AND type = 'record.created'",
        )
        .bind(&victim)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO semantic_units
                (unit_id, authority_bearer_record_id, creation_event_id, creation_event_seq, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&victim)
        .bind(&victim)
        .bind(creation.try_get::<String, _>("id").unwrap())
        .bind(creation.try_get::<i64, _>("seq").unwrap())
        .bind(creation.try_get::<String, _>("created_at").unwrap())
        .execute(db.write_pool())
        .await
        .unwrap();
        let local = Caller::local();
        let mut tx = db.write_pool().begin().await.unwrap();
        let scalar = super::can_record_in(&mut tx, &local, &victim, Capability::View)
            .await
            .unwrap();
        let batched = super::super::visible_ids_in(&mut tx, &local, vec![victim.clone()])
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        assert!(
            !scalar,
            "scalar legacy gate must reject the cyclic-bearer Message"
        );
        assert!(
            !batched.contains(&victim),
            "batched local visibility must agree with the scalar shape rejection"
        );
        db.close().await;
    }
}

#[cfg(test)]
#[path = "messaging_delete_tests.rs"]
mod delete_tests;

#[cfg(test)]
#[path = "messaging_inbox_scope_tests.rs"]
pub(crate) mod inbox_scope_tests;

#[cfg(test)]
#[path = "messaging_inbox_identity_tests.rs"]
pub(crate) mod inbox_identity_tests;
