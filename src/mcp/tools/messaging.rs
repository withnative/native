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

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{
    can_record, parse_args, require_nonblank_reason, require_record_in, REASON_DESCRIPTION,
};

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
    },
    Unclassify {
        message_id: String,
        conversation_id: String,
    },
    Move {
        message_id: String,
        from_conversation_id: String,
        to_conversation_id: String,
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
    append_in(db, tx, spec).await?;
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
        )
        .await?;
        shared.push(message_id.clone());
    }
    db.commit_content(tx).await?;
    Ok(json!({
        "status": if shared.is_empty() { "unchanged" } else { "shared" },
        "selection_id": selection_id,
        "snapshot_seq": snapshot_seq,
        "conversation_id": conversation_id,
        "recipient_id": recipient_id,
        "recipient_principal": recipient_principal,
        "message_ids": message_ids,
        "shared": shared,
        "unchanged": unchanged,
    }))
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

async fn require_local_message_in(
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

async fn reaction_present_in(
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

async fn message_state_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
) -> Result<Value> {
    require_visible_message_in(tx, caller, message_id).await?;
    let (expectation, can_satisfy_acknowledgement) =
        acknowledgement_eligibility_in(tx, caller, message_id).await?;
    Ok(json!({
        "message_id":message_id,
        "reactions":reaction_groups_in(tx, caller.credential(), message_id).await?,
        "message_expectation_state":expectation,
        "can_satisfy_acknowledgement":can_satisfy_acknowledgement,
    }))
}

struct ReactionCommandSpec<'a> {
    message_id: &'a str,
    emoji: &'a str,
    command: &'a str,
    idempotency_key: &'a str,
    reason: &'a str,
    adding: bool,
    changed: bool,
}

async fn append_reaction_command_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    spec: ReactionCommandSpec<'_>,
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
    )
    .await?;
    Ok(())
}

fn verify_reaction_retry(
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
    require_local_message_in(&mut tx, caller, &message_id).await?;
    if let Some((existing_record_id, event_type_found, payload)) = sqlx::query(
        "SELECT record_id,type,payload FROM content_events
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
        return Ok(json!({
            "status":if original_changed {if adding {"added"} else {"removed"}} else {"unchanged"},
            "message_id":message_id,"emoji":emoji,
            "changed":original_changed,"reactions":reaction_groups(db,caller.credential(),&message_id).await?,
        }));
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
        },
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(json!({
        "status":if changed {if adding {"added"} else {"removed"}} else {"unchanged"},
        "message_id":message_id,"emoji":emoji,"changed":changed,
        "reactions":reaction_groups(db,caller.credential(),&message_id).await?,
    }))
}

async fn append_link_if_missing_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    source_id: &str,
    target_id: &str,
    relationship: &str,
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
    )
    .await?;
    Ok(true)
}

async fn clone_message_visibility_to_evidence_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    message_id: &str,
    evidence_id: &str,
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
    crate::authorization::replace_explicit_policy_on(tx, caller.actor(), evidence_id, entries).await
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
    require_local_message_in(&mut tx, caller, &message_id).await?;
    if let Some(row) = sqlx::query(
        "SELECT record_id,type,payload FROM content_events
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
        return Ok(json!({
            "status":"acknowledged","message_id":message_id,"emoji":EMOJI,"changed":original_changed,
            "reactions":state["reactions"],
            "acknowledgement":{"state":"satisfied","evidence_record_id":evidence_record_id},
        }));
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
        )
        .await?;
        clone_message_visibility_to_evidence_in(&mut tx, caller, &message_id, &evidence_id).await?;
        evidence_changed = true;
    }
    evidence_changed |=
        append_link_if_missing_in(db, &mut tx, caller, &evidence_id, &message_id, "part_of")
            .await?;
    evidence_changed |= append_link_if_missing_in(
        db,
        &mut tx,
        caller,
        &evidence_id,
        &message_id,
        "acknowledges",
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
        },
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
        )
        .await?;
    }
    db.commit_content(tx).await?;
    Ok(json!({
        "status":"acknowledged","message_id":message_id,"emoji":EMOJI,"changed":changed,
        "reactions":reaction_groups(db,caller.credential(),&message_id).await?,
        "acknowledgement":{"state":"satisfied","evidence_record_id":evidence_id},
    }))
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
    let mut messages = Vec::with_capacity(candidates.len());
    let read_lens = crate::query::lens::ReadLens::live(db);
    for (id, _) in &candidates {
        let mut items = crate::query::read::get_records_live_in(
            &mut snapshot,
            &read_lens,
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

async fn build_inbox_snapshot(
    db: &Db,
    caller: &Caller,
    view: &str,
    conversation_id: Option<&str>,
) -> Result<InboxSnapshot> {
    if !matches!(
        view,
        "needs_me" | "agent_queue" | "handled_without_me" | "all_new" | "browse"
    ) {
        return Err(Error::engine("invalid inbox view"));
    }
    build_inbox_snapshot_attempt(db, caller, view, conversation_id, 3).await
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
    let candidates: Vec<String> = if let Some(conversation_id) = conversation_id {
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
    if candidates.len() > 10_000 {
        return Err(Error::engine(
            "Inbox snapshot exceeds the bounded 10000 Message selection",
        ));
    }
    let mut message_ids = Vec::new();
    for id in candidates {
        if visible_in_snapshot(&mut tx, caller, &id).await? {
            message_ids.push(id);
        }
    }
    tx.commit().await?;
    let mut items = Vec::new();
    for id in message_ids {
        if let Some(mut item) = inbox_item(db, caller, &id).await? {
            if item_in_view(&item, view) {
                item.as_object_mut().unwrap().remove("_predicates");
                items.push(item);
            }
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
        content_head,
        awareness_head,
        candidate_head,
        control_head,
        authorization_revision,
        items,
    })
}

async fn inbox_item(db: &Db, caller: &Caller, message_id: &str) -> Result<Option<Value>> {
    if !can_record(db, caller, message_id, Capability::View).await? {
        return Ok(None);
    }
    let row = sqlx::query(
        "SELECT r.id,r.name,r.body,r.created_at,r.home_id,
                COALESCE(h.stage,'unsurfaced') human_stage,COALESCE(h.version,0) human_version,
                COALESCE(a.state,'unhandled') agent_state,COALESCE(a.version,0) agent_version,
                COALESCE(p.attention_flag,0) attention_flag,COALESCE(p.muted,0) muted,
                p.snoozed_until,COALESCE(p.archived,0) archived,COALESCE(p.version,0) preference_version,
                ir.obligation_state,ir.executor_route,COALESCE(ir.version,0) routing_version
           FROM records r
           LEFT JOIN human_message_awareness h ON h.message_id=r.id AND h.subject_account_id=?
           LEFT JOIN agent_message_dispositions a ON a.message_id=r.id AND a.subject_account_id=?
           LEFT JOIN message_preferences p ON p.message_id=r.id AND p.subject_account_id=?
           LEFT JOIN message_inbox_routing ir ON ir.message_id=r.id AND ir.subject_account_id=?
          WHERE r.id=? AND r.type='Message' AND r.deleted_at IS NULL",
    )
    .bind(caller.credential()).bind(caller.credential()).bind(caller.credential()).bind(caller.credential())
    .bind(message_id).fetch_optional(db.write_pool()).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let expectation = crate::message_expectation::derive_message_expectation_state(
        db,
        message_id,
        caller.credential(),
    )
    .await?;
    let default_obligation = match expectation.state {
        crate::message_expectation::MessageExpectationState::Open
        | crate::message_expectation::MessageExpectationState::Unknown => "open",
        crate::message_expectation::MessageExpectationState::Satisfied => "satisfied",
        crate::message_expectation::MessageExpectationState::NotRequired => "none",
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
    let mention_count:i64=sqlx::query_scalar("SELECT COUNT(*) FROM message_mentions mm JOIN bindings b ON b.record_id=mm.target_record_id AND b.system='account' AND b.identifier=? AND b.is_canonical=1 WHERE mm.message_id=? AND mm.target_kind='principal' AND mm.effective=1").bind(caller.credential()).bind(message_id).fetch_one(db.write_pool()).await?;
    Ok(Some(json!({
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
        "attention":{"flagged":row.try_get::<i64,_>("attention_flag")?!=0,"muted":row.try_get::<i64,_>("muted")?!=0,"snoozed_until":snoozed_until,"archived":row.try_get::<i64,_>("archived")?!=0,"version":row.try_get::<i64,_>("preference_version")?},
        "delivery":{"candidate_count":sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM notification_candidates WHERE recipient_account_id=? AND message_id=? AND status='effective'").bind(caller.credential()).bind(message_id).fetch_one(db.write_pool()).await?},
        "reactions":reaction_groups(db,caller.credential(),message_id).await?,
        "_predicates":{"snoozed":snoozed}
    })))
}

async fn validate_strong_agent_evidence(
    db: &Db,
    account: &str,
    message_id: &str,
    state: &str,
    evidence: &[crate::awareness::EvidenceInput],
) -> Result<()> {
    if !matches!(state, "acted" | "resolved") {
        return Ok(());
    }
    let derived =
        crate::message_expectation::derive_message_expectation_state(db, message_id, account)
            .await?;
    if let Some(governed) = derived.evidence {
        let role = match governed.kind {
            crate::message_expectation::MessageExpectationEvidenceKind::Acknowledgement
            | crate::message_expectation::MessageExpectationEvidenceKind::Reply => "reply",
            crate::message_expectation::MessageExpectationEvidenceKind::CompletedWorkItem => "work",
            crate::message_expectation::MessageExpectationEvidenceKind::Decision => "decision",
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
        .fetch_one(db.write_pool())
        .await?;
        if valid {
            return Ok(());
        }
    }
    Err(Error::engine(
        "acted/resolved agent disposition evidence does not satisfy governed Message semantics",
    ))
}

fn item_in_view(item: &Value, view: &str) -> bool {
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
        "all_new" => human != "acknowledged" && !snoozed && !archived,
        "browse" => true,
        _ => false,
    }
}

async fn manage_messages(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    match parse_args("manage_messages", arguments)? {
        ManageMessagesArgs::Send {
            id,
            body,
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
                    idempotency_key,
                    intent_digest,
                    disclosure_preview: preview,
                },
            )
            .await
        }
        ManageMessagesArgs::ListContext {
            origin,
            limit,
            cursor,
        } => list_context(&db, &caller, origin, limit, cursor).await,
        ManageMessagesArgs::Classify {
            message_id,
            conversation_id,
        } => {
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            require_classification_authority(&mut tx, &caller, &message_id, &conversation_id)
                .await?;
            let changed = !relation_exists(&mut tx, &message_id, &conversation_id).await?;
            if changed {
                append_classification(&db, &mut tx, &caller, &message_id, &conversation_id, true)
                    .await?;
            }
            db.commit_content(tx).await?;
            Ok(
                json!({"status": if changed {"classified"} else {"unchanged"}, "message_id":message_id,"conversation_id":conversation_id,"changed":changed}),
            )
        }
        ManageMessagesArgs::Unclassify {
            message_id,
            conversation_id,
        } => {
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            require_classification_authority(&mut tx, &caller, &message_id, &conversation_id)
                .await?;
            let changed = relation_exists(&mut tx, &message_id, &conversation_id).await?;
            if changed {
                append_classification(&db, &mut tx, &caller, &message_id, &conversation_id, false)
                    .await?;
            }
            db.commit_content(tx).await?;
            Ok(
                json!({"status": if changed {"unclassified"} else {"unchanged"}, "message_id":message_id,"conversation_id":conversation_id,"changed":changed}),
            )
        }
        ManageMessagesArgs::Move {
            message_id,
            from_conversation_id,
            to_conversation_id,
        } => {
            if from_conversation_id == to_conversation_id {
                return Err(Error::engine(
                    "manage_messages.move requires different Conversations",
                ));
            }
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
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
                )
                .await?;
            }
            db.commit_content(tx).await?;
            Ok(
                json!({"status":"moved","message_id":message_id,"from_conversation_id":from_conversation_id,"to_conversation_id":to_conversation_id,"changed":true}),
            )
        }
        ManageMessagesArgs::ShareHistory {
            recipient_id,
            message_ids,
            conversation_id,
            snapshot_seq,
            reason,
        } => {
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
                    )
                    .await?,
                );
            }
            db.commit_awareness(tx).await?;
            Ok(json!({"status":"applied","results":results,"exact_message_ids":message_ids}))
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
            validate_strong_agent_evidence(
                &db,
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
            )
            .await?;
            db.commit_awareness(tx).await?;
            Ok(result)
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
            )
            .await?;
            db.commit_awareness(tx).await?;
            Ok(result)
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
            )
            .await?;
            db.commit_awareness(tx).await?;
            Ok(result)
        }
        ManageMessagesArgs::ListInbox {
            view,
            conversation_id,
            limit,
            snapshot,
            after,
        } => {
            if limit == 0 || limit > 200 {
                return Err(Error::engine("inbox limit must be 1..=200"));
            }
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
                {
                    return Err(Error::engine(
                        "cursor_reset_required: inbox snapshot binding mismatch",
                    ));
                }
                (parsed, raw)
            } else {
                let parsed =
                    build_inbox_snapshot(&db, &caller, &view, conversation_id.as_deref()).await?;
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
            while cursor < snapshot.items.len() && items.len() < limit {
                let item = snapshot.items[cursor].clone();
                let message_id = item["message_id"].as_str().ok_or_else(|| {
                    Error::engine("cursor_reset_required: malformed Inbox snapshot")
                })?;
                // The semantic/view state is frozen; only live revocation can
                // shrink a later page.
                if can_record(&db, &caller, message_id, Capability::View).await? {
                    items.push(item);
                }
                cursor += 1;
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
            )
            .await?;
            db.commit_awareness(tx).await?;
            Ok(result)
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
    }
}

fn manage_messages_schema() -> Value {
    json!({
            "type":"object",
            "properties":{
                "action":{"type":"string","enum":["send","list_context","classify","unclassify","move","share_history","add_reaction","remove_reaction","satisfy_acknowledgement_expectation_with_reaction","list_message_state","list_conversation","list_unclassified","list_my_conversations","mutate_human_awareness","set_agent_disposition","set_preference","set_routing","set_destination","list_destinations","list_inbox","list_notification_candidates"]},
                "id":{"type":"string"},
                "body":{"type":"string","minLength":1},
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
                "preference":{"type":"string","enum":["flag_attention","clear_attention","mute","unmute","snooze","clear_snooze","archive","restore"]},
                "snoozed_until":{"type":"string","format":"date-time"},
                "obligation_state":{"type":"string","enum":["none","open","satisfied","withdrawn"]},
                "executor_route":{"type":"string","enum":["unassigned","human","agent","joint","closed"]},
                "policy_version":{"type":"string"},
                "view":{"type":"string","enum":["needs_me","agent_queue","handled_without_me","all_new","browse"]},
                "limit":{"type":"integer","minimum":1,"maximum":200},
                "snapshot":{"type":"string"},
                "after":{"type":"integer","minimum":0},
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
        "Mentions into immutable prose. Spans are zero-based half-open UTF-8 byte offsets [span_start, span_end) into body; both ends must be UTF-8 character boundaries and body[span_start..span_end] must equal authored_label. A principal mention target must already be addressed.",
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
                "Mentioned Person or record. A principal target must already be addressed.",
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
        "Send/read direct or Collection contexts; classify/share; manage reactions, 👍 acknowledgement, Inbox, destinations, awareness, routing, preferences. Filing or visibility never establishes context.",
        manage_messages_schema(),
        manage_messages,
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
        crate::authorization::replace_explicit_policy_on(
            &mut revoke,
            "test:revoke",
            collection_id,
            vec![],
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
