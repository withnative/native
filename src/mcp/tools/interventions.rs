//! Message-rooted human intervention commands and viewer-relative read model.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;
use uuid::Uuid;

use crate::authorization::{AllowEntry, Capability};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::{
    InterventionCancelledPayload, InterventionExecutionResumedPayload, InterventionRaisedPayload,
    MessageDeliveryAuthorizedPayload,
};
use crate::store::{append_in, append_with_event_id_in, AppendSpec};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::{parse_args, require_nonblank_reason, require_record_in, REASON_DESCRIPTION};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageInterventionsArgs {
    Get {
        intervention_id: String,
    },
    Query {
        #[serde(default)]
        execution: Option<String>,
        #[serde(default)]
        limit: Option<usize>,
        #[serde(default)]
        cursor: Option<String>,
    },
    Cancel {
        intervention_id: String,
        expected_intervention_seq: i64,
        idempotency_key: String,
        reason: String,
    },
    ResumeDelivery {
        intervention_id: String,
        expected_intervention_seq: i64,
        expected_evaluation_digest: String,
        authority_evidence_record_id: String,
        idempotency_key: String,
        reason: String,
    },
}

struct Raised {
    message_id: String,
    event_seq: i64,
    event_created_at: String,
    payload: InterventionRaisedPayload,
}

struct ResumeDeliveryParams {
    intervention_id: String,
    expected_intervention_seq: i64,
    expected_evaluation_digest: String,
    authority_evidence_record_id: String,
    idempotency_key: String,
    reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct InterventionQueryCursor {
    schema: u8,
    account_id: String,
    target_principal_id: String,
    execution: Option<String>,
    before_raised_seq: i64,
}

fn write_response(
    mut view: Value,
    action: &str,
    status: &str,
    replayed: bool,
    terminal_event: Value,
    transition: Value,
    delivery_event_id: Option<&str>,
) -> Value {
    view["action"] = json!(action);
    view["write_receipt"] = json!({
        "status":status,
        "replayed":replayed,
        "terminal_event":terminal_event,
        "transition":transition,
        "delivery_event_id":delivery_event_id,
    });
    view
}

fn cancelled_transition(payload: &InterventionCancelledPayload) -> Value {
    json!({
        "action_digest":payload.action_digest,
        "idempotency_key":payload.idempotency_key,
        "reason":payload.reason,
        "evidence_refs":payload.evidence_refs,
    })
}

fn resumed_transition(payload: &InterventionExecutionResumedPayload) -> Value {
    json!({
        "basis_kind":payload.basis_kind,
        "basis_record_id":payload.basis_record_id,
        "action_digest":payload.action_digest,
        "delivery_event_id":payload.delivery_event_id,
        "fresh_evaluation_digest":payload.fresh_evaluation_digest,
        "idempotency_key":payload.idempotency_key,
        "summary":payload.summary,
    })
}

async fn raised_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    intervention_id: &str,
) -> Result<Raised> {
    let row = sqlx::query(
        "SELECT record_id,seq,created_at,payload FROM content_events
          WHERE type='intervention.raised.v1'
            AND json_extract(payload,'$.intervention_id')=?
          ORDER BY seq LIMIT 1",
    )
    .bind(intervention_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::auth("manage_interventions: intervention unavailable"))?;
    Ok(Raised {
        message_id: row.try_get("record_id")?,
        event_seq: row.try_get("seq")?,
        event_created_at: row.try_get("created_at")?,
        payload: serde_json::from_str(&row.try_get::<String, _>("payload")?)?,
    })
}

async fn target_account_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    raised: &Raised,
) -> Result<String> {
    let principal: Option<String> = sqlx::query_scalar(
        "SELECT identifier FROM bindings
          WHERE record_id=? AND system='native-principal' AND is_canonical=1",
    )
    .bind(&raised.payload.target_person_record_id)
    .fetch_optional(&mut **tx)
    .await?;
    if principal.as_deref() != Some(raised.payload.target_principal_id.as_str()) {
        return Err(Error::auth(
            "manage_interventions: intervention unavailable",
        ));
    }
    let account: Option<String> = sqlx::query_scalar(
        "SELECT identifier FROM bindings
          WHERE record_id=? AND system='account' AND is_canonical=1",
    )
    .bind(&raised.payload.target_person_record_id)
    .fetch_optional(&mut **tx)
    .await?;
    account.ok_or_else(|| Error::auth("manage_interventions: intervention unavailable"))
}

async fn latest_seq_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    intervention_id: &str,
) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT COALESCE(MAX(seq),0) FROM content_events
          WHERE type IN ('intervention.raised.v1','intervention.cancelled.v1','intervention.execution_resumed.v1')
            AND json_extract(payload,'$.intervention_id')=?",
    )
    .bind(intervention_id)
    .fetch_one(&mut **tx)
    .await?)
}

async fn terminal_event_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    intervention_id: &str,
) -> Result<Option<(String, Value, i64)>> {
    sqlx::query(
        "SELECT type,payload,seq FROM content_events
          WHERE type IN ('intervention.cancelled.v1','intervention.execution_resumed.v1')
            AND json_extract(payload,'$.intervention_id')=?
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(intervention_id)
    .fetch_optional(&mut **tx)
    .await?
    .map(|row| {
        Ok((
            row.try_get("type")?,
            serde_json::from_str(&row.try_get::<String, _>("payload")?)?,
            row.try_get("seq")?,
        ))
    })
    .transpose()
}

fn sanitized_policy_reason_codes(trace: &Value) -> Vec<&'static str> {
    let mut codes = Vec::new();
    if trace
        .get("conflicts")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        codes.push("policy_invalid_or_conflicting");
    } else if trace
        .get("matched_hard_rules")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        codes.push("hard_rule_applied");
    } else if trace.get("judgment").is_some_and(|value| !value.is_null()) {
        codes.push("judgment_deferred_to_default");
    } else {
        codes.push("default_applied");
    }
    codes
}

async fn intervention_view(db: &Db, caller: &Caller, intervention_id: &str) -> Result<Value> {
    let mut tx = db.write_pool().begin().await?;
    let raised = raised_in(&mut tx, intervention_id).await?;
    let target_account = target_account_in(&mut tx, &raised).await?;
    if target_account != caller.credential() {
        return Err(Error::auth(
            "manage_interventions: intervention unavailable",
        ));
    }
    let terminal = terminal_event_in(&mut tx, intervention_id).await?;
    let latest_seq = latest_seq_in(&mut tx, intervention_id).await?;
    let database_id = crate::interventions::database_id_in(&mut tx).await?;
    let message = sqlx::query("SELECT created_at FROM records WHERE id=?")
        .bind(&raised.message_id)
        .fetch_one(&mut *tx)
        .await?;
    let execution = match terminal.as_ref().map(|(kind, _, _)| kind.as_str()) {
        Some("intervention.cancelled.v1") => "cancelled",
        Some("intervention.execution_resumed.v1") => "resumed",
        _ if raised.payload.disposition == "block_and_request_authority" => "blocked",
        _ => "proceeded",
    };
    let path = crate::interventions::canonical_route(&database_id, intervention_id);
    let affordances = if execution == "blocked" {
        json!([
            {"kind":"record_decision","enabled":true,"reason_code":null},
            {"kind":"resume","enabled":true,"reason_code":"requires_exact_authority_evidence"},
            {"kind":"cancel","enabled":true,"reason_code":null}
        ])
    } else {
        json!([])
    };
    tx.rollback().await?;
    let obligation = crate::message_expectation::derive_message_expectation_state(
        db,
        &raised.message_id,
        &target_account,
    )
    .await?;
    let message_summary = raised
        .payload
        .disclosure_preview
        .clone()
        .unwrap_or_else(|| "The sender did not supply a disclosure-safe preview".into());
    Ok(json!({
        "format":crate::interventions::VIEW_FORMAT,
        "identity":{"intervention_id":intervention_id,"resolver_database_id":database_id,"canonical_url":path},
        "lineage":{"predecessor_intervention_id":null,"successor_intervention_id":null},
        "trigger":{
            "message_id":raised.message_id,
            "message_content_seq":raised.event_seq,
            "summary":message_summary,
            "created_at":message.try_get::<String,_>("created_at")?,
        },
        "target":{"person_record_id":raised.payload.target_person_record_id,"principal_id":raised.payload.target_principal_id},
        "disposition":raised.payload.disposition,
        "action_snapshot":{"requested_outcome":raised.payload.requested_outcome,"action":raised.payload.action,"action_digest":raised.payload.action_digest},
        "request":raised.payload.request,
        "reason":{"summary":raised.payload.reason,"context_refs":raised.payload.context_refs},
        "state":{
            "attention":{"state":"unknown","source_format":null},
            "obligation":serde_json::to_value(obligation)?,
            "execution":{"state":execution,"basis_event_seq":latest_seq},
            "timing":{"state":"none","respond_by":null}
        },
        "policy_explanation":{"trace_digest":raised.payload.evaluation_digest,"disposition":raised.payload.disposition,"reason_codes":sanitized_policy_reason_codes(&raised.payload.policy_trace),"summary":"Effective policy was evaluated by Native. Private policy source details remain visible only to their authorized principals."},
        "intended_recipients":raised.payload.intended_recipients,
        "affordances":affordances,
        "viewer":{"intent_format":"native.viewer-intent.intervention.v1","supported_focus":["summary"],"supported_evidence":["collapsed","expanded"],"supported_controls":["primary","hidden"],"ref_supported":false},
        "guard_tokens":{"expected_intervention_seq":latest_seq,"expected_evaluation_digest":raised.payload.evaluation_digest},
        "projection_seq":latest_seq,
        "raised_at":raised.event_created_at,
    }))
}

async fn cancel(
    db: Db,
    caller: Caller,
    intervention_id: String,
    expected_intervention_seq: i64,
    idempotency_key: String,
    reason: String,
) -> Result<Value> {
    require_nonblank_reason("manage_interventions.cancel", &reason)?;
    if idempotency_key.trim().is_empty() {
        return Err(Error::engine(
            "manage_interventions.cancel: idempotency_key must not be blank",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let raised = raised_in(&mut tx, &intervention_id).await?;
    if target_account_in(&mut tx, &raised).await? != caller.credential() {
        return Err(Error::auth(
            "manage_interventions: intervention unavailable",
        ));
    }
    if let Some(row) = sqlx::query(
        "SELECT id,record_id,seq,type,payload FROM content_events
          WHERE type='intervention.cancelled.v1'
            AND json_extract(payload,'$.idempotency_key')=?
            AND json_extract(payload,'$.intervention_id')=? ORDER BY seq LIMIT 1",
    )
    .bind(&idempotency_key)
    .bind(&intervention_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        let payload: InterventionCancelledPayload =
            serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
        if payload.reason != reason
            || payload.target_principal_id != raised.payload.target_principal_id
            || payload.action_digest != raised.payload.action_digest
        {
            return Err(Error::engine(
                "manage_interventions.cancel: idempotency_key was reused for different intent",
            ));
        }
        let terminal_event = json!({
            "record_id":row.try_get::<String,_>("record_id")?,
            "event_id":row.try_get::<String,_>("id")?,
            "seq":row.try_get::<i64,_>("seq")?,
            "type":row.try_get::<String,_>("type")?,
        });
        tx.rollback().await?;
        let view = intervention_view(&db, &caller, &intervention_id).await?;
        return Ok(write_response(
            view,
            "cancel",
            "cancelled",
            true,
            terminal_event,
            cancelled_transition(&payload),
            None,
        ));
    }
    if raised.payload.disposition != "block_and_request_authority" {
        return Err(Error::engine(
            "manage_interventions.cancel: only a blocked delivery can be cancelled",
        ));
    }
    let latest = latest_seq_in(&mut tx, &intervention_id).await?;
    if latest != expected_intervention_seq {
        return Err(Error::engine(format!("manage_interventions.cancel: stale projection (expected {expected_intervention_seq}, current {latest})")));
    }
    if terminal_event_in(&mut tx, &intervention_id)
        .await?
        .is_some()
    {
        return Err(Error::engine(
            "manage_interventions.cancel: intervention is already terminal",
        ));
    }
    let payload = InterventionCancelledPayload {
        format: "native.intervention.cancelled.v1".into(),
        intervention_id: intervention_id.clone(),
        target_principal_id: raised.payload.target_principal_id.clone(),
        action_digest: raised.payload.action_digest.clone(),
        idempotency_key,
        reason,
        evidence_refs: vec![],
    };
    let transition = cancelled_transition(&payload);
    let terminal_event = append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: raised.message_id,
            event_type: "intervention.cancelled.v1".into(),
            payload: serde_json::to_value(payload)?,
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    db.commit_content(tx).await?;
    let view = intervention_view(&db, &caller, &intervention_id).await?;
    Ok(write_response(
        view,
        "cancel",
        "cancelled",
        false,
        json!({
            "record_id":terminal_event.record_id,
            "event_id":terminal_event.id,
            "seq":terminal_event.local_seq,
            "type":terminal_event.event_type,
        }),
        transition,
        None,
    ))
}

async fn resume_delivery(db: Db, caller: Caller, params: ResumeDeliveryParams) -> Result<Value> {
    let ResumeDeliveryParams {
        intervention_id,
        expected_intervention_seq,
        expected_evaluation_digest,
        authority_evidence_record_id,
        idempotency_key,
        reason,
    } = params;
    require_nonblank_reason("manage_interventions.resume_delivery", &reason)?;
    if idempotency_key.trim().is_empty() {
        return Err(Error::engine(
            "manage_interventions.resume_delivery: idempotency_key must not be blank",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let raised = raised_in(&mut tx, &intervention_id).await?;
    let target_account = target_account_in(&mut tx, &raised).await?;
    if target_account != caller.credential() {
        return Err(Error::auth(
            "manage_interventions: intervention unavailable",
        ));
    }
    if let Some(row) = sqlx::query(
        "SELECT id,record_id,seq,type,payload FROM content_events
          WHERE type='intervention.execution_resumed.v1'
            AND json_extract(payload,'$.idempotency_key')=?
            AND json_extract(payload,'$.intervention_id')=? ORDER BY seq LIMIT 1",
    )
    .bind(&idempotency_key)
    .bind(&intervention_id)
    .fetch_optional(&mut *tx)
    .await?
    {
        let payload: InterventionExecutionResumedPayload =
            serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
        if payload.basis_record_id != authority_evidence_record_id
            || payload.summary != reason
            || payload.target_principal_id != raised.payload.target_principal_id
            || payload.action_digest != raised.payload.action_digest
        {
            return Err(Error::engine("manage_interventions.resume_delivery: idempotency_key was reused for different intent"));
        }
        let terminal_event = json!({
            "record_id":row.try_get::<String,_>("record_id")?,
            "event_id":row.try_get::<String,_>("id")?,
            "seq":row.try_get::<i64,_>("seq")?,
            "type":row.try_get::<String,_>("type")?,
        });
        let delivery_event_id = payload.delivery_event_id.clone();
        let transition = resumed_transition(&payload);
        tx.rollback().await?;
        let view = intervention_view(&db, &caller, &intervention_id).await?;
        return Ok(write_response(
            view,
            "resume_delivery",
            "resumed",
            true,
            terminal_event,
            transition,
            Some(&delivery_event_id),
        ));
    }
    if raised.payload.disposition != "block_and_request_authority" {
        return Err(Error::engine(
            "manage_interventions.resume_delivery: only a blocked delivery can resume",
        ));
    }
    if raised.payload.evaluation_digest != expected_evaluation_digest {
        return Err(Error::engine(
            "manage_interventions.resume_delivery: evaluation digest mismatch",
        ));
    }
    let latest = latest_seq_in(&mut tx, &intervention_id).await?;
    if latest != expected_intervention_seq {
        return Err(Error::engine(format!("manage_interventions.resume_delivery: stale projection (expected {expected_intervention_seq}, current {latest})")));
    }
    if terminal_event_in(&mut tx, &intervention_id)
        .await?
        .is_some()
    {
        return Err(Error::engine(
            "manage_interventions.resume_delivery: intervention is already terminal",
        ));
    }
    require_record_in(
        &mut tx,
        &caller,
        "manage_interventions.resume_delivery",
        &authority_evidence_record_id,
        Capability::View,
    )
    .await?;
    let evidence = sqlx::query("SELECT type,kind,owner_id,deleted_at FROM records WHERE id=?")
        .bind(&authority_evidence_record_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            Error::engine("manage_interventions.resume_delivery: authority evidence does not exist")
        })?;
    if evidence.try_get::<String, _>("type")? != "Resolution"
        || evidence.try_get::<Option<String>, _>("kind")?.as_deref() != Some("decision")
        || evidence
            .try_get::<Option<String>, _>("owner_id")?
            .as_deref()
            != Some(raised.payload.target_person_record_id.as_str())
        || evidence
            .try_get::<Option<String>, _>("deleted_at")?
            .is_some()
    {
        return Err(Error::engine("manage_interventions.resume_delivery: evidence must be a live target-authored Resolution kind:decision"));
    }
    let authorizes: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM links WHERE source_id=? AND target_id=? AND relationship='authorizes')",
    ).bind(&authority_evidence_record_id).bind(&raised.message_id).fetch_one(&mut *tx).await?;
    if !authorizes {
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: authority_evidence_record_id.clone(),
                event_type: "link.added".into(),
                payload: serde_json::to_value(crate::events::LinkAddedPayload {
                    id: None,
                    source_id: authority_evidence_record_id.clone(),
                    target_id: raised.message_id.clone(),
                    relationship: "authorizes".into(),
                    note: Some(format!(
                        "Exact authority for intervention {intervention_id}"
                    )),
                })?,
                actor: Some(caller.actor().into()),
            },
        )
        .await?;
    }
    let mut recipients = Vec::new();
    let mut accounts = Vec::new();
    for frozen in &raised.payload.intended_recipients {
        require_record_in(
            &mut tx,
            &caller,
            "manage_interventions.resume_delivery",
            &frozen.recipient_id,
            Capability::View,
        )
        .await?;
        let current_principal: Option<String> = sqlx::query_scalar(
            "SELECT identifier FROM bindings WHERE record_id=? AND system='native-principal' AND is_canonical=1",
        ).bind(&frozen.recipient_id).fetch_optional(&mut *tx).await?;
        if current_principal.as_deref() != Some(frozen.principal.as_str()) {
            return Err(Error::engine("manage_interventions.resume_delivery: recipient principal binding changed; create a new send attempt"));
        }
        let account: String = sqlx::query_scalar(
            "SELECT identifier FROM bindings WHERE record_id=? AND system='account' AND is_canonical=1",
        ).bind(&frozen.recipient_id).fetch_optional(&mut *tx).await?
            .ok_or_else(|| Error::engine("manage_interventions.resume_delivery: intended recipient no longer has a canonical local account; create a new send attempt"))?;
        accounts.push(account);
        recipients.push(frozen.clone());
    }
    if recipients.is_empty() {
        return Err(Error::engine(
            "manage_interventions.resume_delivery: blocked draft has no intended recipients",
        ));
    }
    let correspondent_principals = recipients
        .iter()
        .map(|recipient| recipient.principal.clone())
        .collect::<Vec<_>>();
    let sender_account: Option<String> = sqlx::query_scalar(
        "SELECT account.identifier
           FROM bindings principal
           JOIN bindings account ON account.record_id=principal.record_id
          WHERE principal.system='native-principal' AND principal.identifier=?
            AND principal.is_canonical=1
            AND account.system='account' AND account.is_canonical=1
          LIMIT 1",
    )
    .bind(&raised.payload.sender_principal_id)
    .fetch_optional(&mut *tx)
    .await?;
    let sender_account = sender_account.ok_or_else(|| {
        Error::engine(
            "manage_interventions.resume_delivery: frozen sender principal no longer resolves",
        )
    })?;
    let policy_caller = Caller::authenticated(sender_account.clone());
    let fresh = crate::interventions::evaluate_in(
        &mut tx,
        &policy_caller,
        &raised.payload.sender_principal_id,
        &correspondent_principals,
        raised.payload.disclosure_preview.as_deref(),
    )
    .await?;
    if fresh.action_digest != raised.payload.action_digest {
        return Err(Error::engine("manage_interventions.resume_delivery: authoritative action facts changed; create a new send attempt"));
    }
    if fresh
        .trace
        .get("conflicts")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        return Err(Error::engine("manage_interventions.resume_delivery: current policy is invalid or conflicting; repair it before delivery"));
    }
    // A target-authored Decision linked with `authorizes` is the exact-action
    // override requested by the intervention. It does not bypass ACL checks or
    // a changed action digest, both revalidated above.
    let delivery_event_id = Uuid::new_v4().to_string();
    append_with_event_id_in(
        &db,
        &mut tx,
        delivery_event_id.clone(),
        AppendSpec {
            record_id: raised.message_id.clone(),
            event_type: "message.delivery.authorized.v1".into(),
            payload: serde_json::to_value(MessageDeliveryAuthorizedPayload {
                format: "native.message-delivery-authorized.v1".into(),
                intervention_id: intervention_id.clone(),
                idempotency_key: format!("{idempotency_key}:delivery"),
                action_digest: raised.payload.action_digest.clone(),
                authority_evidence_record_id: authority_evidence_record_id.clone(),
                recipients: recipients.clone(),
                fresh_policy_trace: fresh.trace.clone(),
                fresh_evaluation_digest: fresh.evaluation_digest.clone(),
            })?,
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    accounts.sort();
    accounts.dedup();
    type OriginStateRow = (String, Option<String>, Option<String>, Option<i64>);
    let origin: Option<OriginStateRow> = sqlx::query_as(
        "SELECT status,origin_type,collection_id,participant_count
           FROM message_origin_state WHERE message_id=?",
    )
    .bind(&raised.message_id)
    .fetch_optional(&mut *tx)
    .await?;
    let collection_origin = origin
        .as_ref()
        .and_then(|(status, origin_type, collection_id, _)| {
            (status == "declared" && origin_type.as_deref() == Some("collection"))
                .then(|| collection_id.clone())
                .flatten()
        });
    match origin {
        Some((status, Some(origin_type), _, _))
            if status == "declared" && origin_type == "collection" =>
        {
            crate::authorization::restore_inheritance_on(
                &mut tx,
                caller.actor(),
                &raised.message_id,
            )
            .await?;
        }
        Some((status, Some(origin_type), _, Some(participant_count)))
            if status == "declared" && origin_type == "direct" =>
        {
            let direct_accounts: Vec<String> = sqlx::query_scalar(
                "SELECT account.identifier
                   FROM message_origin_principals origin
                   JOIN bindings principal
                     ON principal.system='native-principal'
                    AND principal.identifier=origin.principal_id
                    AND principal.is_canonical=1
                   JOIN bindings account ON account.record_id=principal.record_id
                    AND account.system='account' AND account.is_canonical=1
                  WHERE origin.message_id=? ORDER BY account.identifier",
            )
            .bind(&raised.message_id)
            .fetch_all(&mut *tx)
            .await?;
            if direct_accounts.len() as i64 != participant_count {
                return Err(Error::engine(
                    "manage_interventions.resume_delivery: a direct-context participant no longer resolves; create a new send attempt",
                ));
            }
            crate::authorization::replace_explicit_policy_on(
                &mut tx,
                caller.actor(),
                &raised.message_id,
                direct_accounts
                    .into_iter()
                    .map(|account| AllowEntry::account(account, Capability::View))
                    .collect(),
            )
            .await?;
        }
        _ => {
            crate::authorization::replace_explicit_policy_on(
                &mut tx,
                caller.actor(),
                &raised.message_id,
                accounts
                    .iter()
                    .cloned()
                    .map(|account| AllowEntry::account(account, Capability::View))
                    .collect(),
            )
            .await?;
        }
    }
    crate::awareness::apply_delivered_message_awareness_in(
        &mut tx,
        &raised.message_id,
        &accounts,
        "message.delivery.authorized.v1",
        &delivery_event_id,
    )
    .await?;
    if let Some(collection_id) = collection_origin {
        // A resumed delivery is the successful send for a previously withheld
        // Message. Fold the sender's rail in this same transaction, keyed by
        // the immutable delivery event so an exact resume retry cannot append
        // a second destination event or rejoin after a later explicit leave.
        crate::awareness::auto_join_destination_on_send_in(
            &mut tx,
            &sender_account,
            caller.actor(),
            &collection_id,
            &delivery_event_id,
        )
        .await?;
    }
    let payload = InterventionExecutionResumedPayload {
        format: "native.intervention.execution-resumed.v1".into(),
        intervention_id: intervention_id.clone(),
        target_principal_id: raised.payload.target_principal_id,
        idempotency_key,
        basis_kind: "authority_evidence".into(),
        basis_record_id: authority_evidence_record_id,
        action_digest: raised.payload.action_digest,
        delivery_event_id: delivery_event_id.clone(),
        fresh_evaluation_digest: fresh.evaluation_digest,
        summary: reason,
    };
    let transition = resumed_transition(&payload);
    let terminal_event = append_in(
        &db,
        &mut tx,
        AppendSpec {
            record_id: raised.message_id.clone(),
            event_type: "intervention.execution_resumed.v1".into(),
            payload: serde_json::to_value(payload)?,
            actor: Some(caller.actor().into()),
        },
    )
    .await?;
    db.commit_content(tx).await?;
    let view = intervention_view(&db, &caller, &intervention_id).await?;
    Ok(write_response(
        view,
        "resume_delivery",
        "resumed",
        false,
        json!({
            "record_id":terminal_event.record_id,
            "event_id":terminal_event.id,
            "seq":terminal_event.local_seq,
            "type":terminal_event.event_type,
        }),
        transition,
        Some(&delivery_event_id),
    ))
}

async fn manage_interventions(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    match parse_args("manage_interventions", arguments)? {
        ManageInterventionsArgs::Get { intervention_id } => {
            let mut view = intervention_view(&db, &caller, &intervention_id).await?;
            view["action"] = json!("get");
            Ok(view)
        }
        ManageInterventionsArgs::Query {
            execution,
            limit,
            cursor,
        } => {
            const CANDIDATE_SCAN_LIMIT: usize = 200;
            let limit = limit.unwrap_or(25);
            if !(1..=50).contains(&limit) {
                return Err(Error::engine(
                    "manage_interventions.query: limit must be between 1 and 50",
                ));
            }
            if execution.as_deref().is_some_and(|execution| {
                !matches!(execution, "proceeded" | "blocked" | "resumed" | "cancelled")
            }) {
                return Err(Error::engine(
                    "manage_interventions.query: execution filter is invalid",
                ));
            }
            let principal: Option<String> = sqlx::query_scalar(
                "SELECT b.identifier FROM bindings a JOIN bindings b ON b.record_id=a.record_id
                  WHERE a.system='account' AND a.identifier=? AND a.is_canonical=1
                    AND b.system='native-principal' AND b.is_canonical=1 LIMIT 1",
            )
            .bind(caller.credential())
            .fetch_optional(db.write_pool())
            .await?;
            let Some(principal) = principal else {
                if cursor.is_some() {
                    return Err(Error::engine(
                        "cursor_reset_required: intervention query caller binding changed",
                    ));
                }
                return Ok(
                    json!({"action":"query","format":"native.intervention-query.v1","items":[],"count":0,"viewer_relative":true,"execution":execution,"limit":limit,"has_more":false,"next_cursor":null,"candidate_scan_limit":CANDIDATE_SCAN_LIMIT,"candidate_window_returned":0,"candidates_evaluated":0,"scan_limit_reached":false,"query_basis":"live_at_each_page_read"}),
                );
            };
            let before_raised_seq = if let Some(cursor) = cursor {
                let decoded: InterventionQueryCursor =
                    serde_json::from_value(db.get_inbox_snapshot(&cursor).map_err(|_| {
                        Error::engine("cursor_reset_required: invalid intervention query cursor")
                    })?)
                    .map_err(|_| {
                        Error::engine("cursor_reset_required: malformed intervention query cursor")
                    })?;
                if decoded.schema != 1
                    || decoded.account_id != caller.credential()
                    || decoded.target_principal_id != principal
                    || decoded.execution != execution
                    || decoded.before_raised_seq <= 0
                {
                    return Err(Error::engine(
                        "cursor_reset_required: intervention query cursor does not match this caller and filter",
                    ));
                }
                Some(decoded.before_raised_seq)
            } else {
                None
            };
            let query = "SELECT json_extract(payload,'$.intervention_id'),seq FROM content_events
                  WHERE type='intervention.raised.v1'
                    AND json_extract(payload,'$.target_principal_id')=?
                    AND (? IS NULL OR seq<?)
                  ORDER BY seq DESC LIMIT ?";
            let mut candidates: Vec<(String, i64)> = sqlx::query_as(query)
                .bind(&principal)
                .bind(before_raised_seq)
                .bind(before_raised_seq)
                .bind((CANDIDATE_SCAN_LIMIT + 1) as i64)
                .fetch_all(db.write_pool())
                .await?;
            let scan_limit_reached = candidates.len() > CANDIDATE_SCAN_LIMIT;
            candidates.truncate(CANDIDATE_SCAN_LIMIT);
            let candidate_window_returned = candidates.len();
            let mut candidates_evaluated = 0usize;
            let mut matches = Vec::new();
            let mut last_scanned_seq = None;
            for (id, raised_seq) in &candidates {
                candidates_evaluated += 1;
                last_scanned_seq = Some(*raised_seq);
                let view = intervention_view(&db, &caller, id).await?;
                if execution.as_deref().is_none_or(|wanted| {
                    view.pointer("/state/execution/state")
                        .and_then(Value::as_str)
                        == Some(wanted)
                }) {
                    matches.push((view, *raised_seq));
                    if matches.len() > limit {
                        break;
                    }
                }
            }
            let matching_overflow = matches.len() > limit;
            matches.truncate(limit);
            let continuation_seq = if matching_overflow {
                matches.last().map(|(_, seq)| *seq)
            } else if scan_limit_reached {
                last_scanned_seq
            } else {
                None
            };
            let next_cursor = continuation_seq
                .map(|before_raised_seq| {
                    db.put_inbox_snapshot(serde_json::to_value(InterventionQueryCursor {
                        schema: 1,
                        account_id: caller.credential().into(),
                        target_principal_id: principal,
                        execution: execution.clone(),
                        before_raised_seq,
                    })?)
                })
                .transpose()?;
            let items = matches
                .into_iter()
                .map(|(view, _)| view)
                .collect::<Vec<_>>();
            Ok(json!({
                "action":"query",
                "format":"native.intervention-query.v1",
                "items":items,
                "count":items.len(),
                "viewer_relative":true,
                "execution":execution,
                "limit":limit,
                "has_more":next_cursor.is_some(),
                "next_cursor":next_cursor,
                "candidate_scan_limit":CANDIDATE_SCAN_LIMIT,
                "candidate_window_returned":candidate_window_returned,
                "candidates_evaluated":candidates_evaluated,
                "scan_limit_reached":scan_limit_reached,
                "query_basis":"live_at_each_page_read",
            }))
        }
        ManageInterventionsArgs::Cancel {
            intervention_id,
            expected_intervention_seq,
            idempotency_key,
            reason,
        } => {
            cancel(
                db,
                caller,
                intervention_id,
                expected_intervention_seq,
                idempotency_key,
                reason,
            )
            .await
        }
        ManageInterventionsArgs::ResumeDelivery {
            intervention_id,
            expected_intervention_seq,
            expected_evaluation_digest,
            authority_evidence_record_id,
            idempotency_key,
            reason,
        } => {
            resume_delivery(
                db,
                caller,
                ResumeDeliveryParams {
                    intervention_id,
                    expected_intervention_seq,
                    expected_evaluation_digest,
                    authority_evidence_record_id,
                    idempotency_key,
                    reason,
                },
            )
            .await
        }
    }
}

pub fn register_intervention_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageInterventions,
        "Get/query viewer-relative Message-rooted interventions, cancel one, or atomically deliver and resume a blocked Message using exact target-authored authority evidence. Resume rechecks authorization, recipient bindings, action facts and active policy.",
        json!({
            "type":"object",
            "properties":{
                "action":{"type":"string","enum":["get","query","cancel","resume_delivery"]},
                "intervention_id":{"type":"string"},
                "execution":{"type":"string","enum":["proceeded","blocked","resumed","cancelled"]},
                "limit":{"type":"integer","minimum":1,"maximum":50},
                "cursor":{"type":"string"},
                "expected_intervention_seq":{"type":"integer","minimum":1},
                "expected_evaluation_digest":{"type":"string"},
                "authority_evidence_record_id":{"type":"string"},
                "idempotency_key":{"type":"string","minLength":1},
                "reason":{"type":"string","minLength":1,"description":REASON_DESCRIPTION}
            },
            "required":["action"],
            "additionalProperties":false
        }),
        manage_interventions,
    )
}
