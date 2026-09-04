use super::*;

pub(super) async fn project_message_reaction(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let is_live_message: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND type='Message' AND deleted_at IS NULL)",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if !is_live_message {
        return Err(Error::engine(
            "Message reaction event must target a live Message",
        ));
    }
    let payload: crate::events::MessageReactionPayload = serde_json::from_str(
        event
            .payload
            .as_deref()
            .ok_or_else(|| Error::engine("Message reaction event has no payload"))?,
    )?;
    payload.validate(event.actor.as_deref())?;
    let coherent = match event.event_type.as_str() {
        "message.reaction.added.v1" => matches!(
            payload.command.as_str(),
            "add_reaction" | "satisfy_acknowledgement_expectation_with_reaction"
        ),
        "message.reaction.removed.v1" => payload.command == "remove_reaction",
        _ => false,
    };
    if !coherent {
        return Err(Error::engine(
            "Message reaction event type and command disagree",
        ));
    }
    if payload.command == "satisfy_acknowledgement_expectation_with_reaction" {
        let kind_match =
            crate::generated::kinds::CoreKind::AnnotationAcknowledgement.sql_matches("evidence");
        let valid_evidence: bool = sqlx::query_scalar(&format!(
                    "SELECT EXISTS(
                       SELECT 1 FROM records evidence
                       JOIN bindings owner ON owner.record_id=evidence.owner_id
                         AND owner.system='account' AND owner.identifier=? AND owner.is_canonical=1
                       JOIN links part ON part.source_id=evidence.id AND part.target_id=? AND part.relationship='part_of'
                       JOIN links ack ON ack.source_id=evidence.id AND ack.target_id=? AND ack.relationship='acknowledges'
                      WHERE evidence.deleted_at IS NULL AND {kind_match}
                        AND EXISTS(SELECT 1 FROM content_events created
                          WHERE created.record_id=evidence.id AND created.type='record.created'
                            AND created.actor=? AND created.seq<?)
                        AND (SELECT linked.actor FROM content_events linked
                          WHERE linked.record_id=evidence.id AND linked.type='link.added'
                            AND json_extract(linked.payload,'$.target_id')=?
                            AND json_extract(linked.payload,'$.relationship')='acknowledges'
                            AND linked.seq<? ORDER BY linked.seq DESC LIMIT 1)=?)"
                ))
                .bind(payload.actor_account_id.as_str())
                .bind(&event.record_id)
                .bind(&event.record_id)
                .bind(payload.actor_account_id.as_str())
                .bind(event.local_seq)
                .bind(&event.record_id)
                .bind(event.local_seq)
                .bind(payload.actor_account_id.as_str())
                .fetch_one(&mut *conn)
                .await?;
        if !valid_evidence {
            return Err(Error::engine(
                "acknowledgement reaction has no valid durable evidence",
            ));
        }
    }
    Ok(())
}

pub(super) async fn project_message_audience_declared(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let row = sqlx::query("SELECT type, owner_id FROM records WHERE id = ?")
        .bind(&event.record_id)
        .fetch_one(&mut *conn)
        .await?;
    if row.try_get::<String, _>("type")? != "Message" {
        return Err(Error::engine(
            "message.audience.declared may target only a Message",
        ));
    }
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM message_audience_state WHERE message_id = ?")
            .bind(&event.record_id)
            .fetch_optional(&mut *conn)
            .await?;
    if status.as_deref() != Some("pending_local") {
        return Err(Error::engine(format!(
            "Message {} audience is already sealed or legacy-unknown",
            event.record_id
        )));
    }
    let payload: MessageAudienceDeclaredPayload = parse_payload(event)?;
    let owner_id: String = row
        .try_get::<Option<String>, _>("owner_id")?
        .ok_or_else(|| {
            Error::engine("a Message audience declaration requires an immutable sender owner")
        })?;
    if payload.sender_id != owner_id {
        return Err(Error::engine(
            "Message audience sender_id must equal the immutable owner_id",
        ));
    }
    assert_portable_person(conn, &owner_id, &event.event_type).await?;
    let sender = declared_principal(&payload.sender_principal, &event.event_type)?;
    let mut seen = std::collections::BTreeSet::new();
    for recipient in &payload.addressed_to {
        if recipient.recipient_id == owner_id {
            return Err(Error::engine(
                "Message addressed_to must exclude its sender",
            ));
        }
        if !seen.insert(recipient.recipient_id.as_str()) {
            return Err(Error::engine(format!(
                "Message audience contains duplicate recipient {}",
                recipient.recipient_id
            )));
        }
        assert_portable_person(conn, &recipient.recipient_id, &event.event_type).await?;
        let principal = declared_principal(&recipient.principal, &event.event_type)?;
        if principal == sender {
            return Err(Error::engine(
                "Message addressed_to must exclude its sender principal",
            ));
        }
        sqlx::query(
            "INSERT INTO links (id,source_id,target_id,relationship,note,created_at)
             VALUES (?,?,?,'addressed_to',NULL,?)",
        )
        .bind(format!(
            "lnk:{}:{}:addressed_to",
            event.record_id, recipient.recipient_id
        ))
        .bind(&event.record_id)
        .bind(&recipient.recipient_id)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "INSERT INTO message_audiences
                (message_id,principal_id,source,grant_id,event_seq,created_at)
             VALUES (?,?,'addressed_to','initial',?,?)",
        )
        .bind(&event.record_id)
        .bind(principal)
        .bind(event.local_seq)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    }
    sqlx::query(
        "INSERT INTO message_audiences
            (message_id,principal_id,source,grant_id,event_seq,created_at)
         VALUES (?,?,'sender','initial',?,?)",
    )
    .bind(&event.record_id)
    .bind(sender)
    .bind(event.local_seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE message_audience_state
            SET status='declared', declaration_event_seq=?, updated_at=?
          WHERE message_id=?",
    )
    .bind(event.local_seq)
    .bind(&event.created_at)
    .bind(&event.record_id)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_message_audience_legacy_unknown(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let record_type: Option<String> = sqlx::query_scalar("SELECT type FROM records WHERE id = ?")
        .bind(&event.record_id)
        .fetch_optional(&mut *conn)
        .await?;
    if record_type.as_deref() != Some("Message") {
        return Err(Error::engine(
            "message.audience.legacy_unknown may target only an existing Message",
        ));
    }
    let payload = payload_object(event)?;
    if !payload.is_empty() {
        return Err(Error::engine(
            "message.audience.legacy_unknown must carry an empty payload",
        ));
    }
    let changed = sqlx::query(
        "UPDATE message_audience_state
            SET status='legacy_unknown', declaration_event_seq=NULL, updated_at=?
          WHERE message_id=? AND status='pending_local'",
    )
    .bind(&event.created_at)
    .bind(&event.record_id)
    .execute(&mut *conn)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(Error::engine(format!(
            "Message {} audience cannot be marked legacy_unknown twice",
            event.record_id
        )));
    }
    Ok(())
}

pub(super) async fn project_message_origin_declared(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let record_type: String = sqlx::query_scalar("SELECT type FROM records WHERE id=?")
        .bind(&event.record_id)
        .fetch_one(&mut *conn)
        .await?;
    if record_type != "Message" {
        return Err(Error::engine(
            "message.origin.declared.v1 may target only a Message",
        ));
    }
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM message_origin_state WHERE message_id=?")
            .bind(&event.record_id)
            .fetch_optional(&mut *conn)
            .await?;
    if status.as_deref() != Some("legacy_unknown") {
        return Err(Error::engine(format!(
            "Message {} communication origin is already declared",
            event.record_id
        )));
    }
    let payload: MessageOriginDeclaredPayload = parse_payload(event)?;
    match payload {
        MessageOriginDeclaredPayload::Collection { collection_id } => {
            if collection_id.trim().is_empty() || collection_id.trim() != collection_id {
                return Err(Error::engine(
                    "message.origin.declared.v1 collection_id must be a nonblank canonical origin identity",
                ));
            }
            sqlx::query(
                "UPDATE message_origin_state
                    SET status='declared',origin_type='collection',collection_id=?,
                        direct_set_digest=NULL,participant_count=0,
                        declaration_event_seq=?,updated_at=?
                  WHERE message_id=? AND status='legacy_unknown'",
            )
            .bind(collection_id)
            .bind(event.local_seq)
            .bind(&event.created_at)
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
        }
        MessageOriginDeclaredPayload::Direct { principals } => {
            if principals.is_empty() {
                return Err(Error::engine(
                    "message.origin.declared.v1 direct principals must not be empty",
                ));
            }
            let mut previous: Option<&str> = None;
            for principal in &principals {
                declared_principal(principal, &event.event_type)?;
                if previous.is_some_and(|value| value >= principal.as_str()) {
                    return Err(Error::engine(
                        "message.origin.declared.v1 direct principals must be sorted and unique",
                    ));
                }
                previous = Some(principal);
            }
            // Sender membership is enforced by local authoring and verified
            // federation ingestion. It cannot be revalidated here: bindings
            // and transport provenance are not part of content-log replay.
            let digest = crate::events::direct_origin_set_digest(&principals);
            for principal in &principals {
                sqlx::query(
                    "INSERT INTO message_origin_principals
                        (message_id,principal_id,event_seq,created_at)
                     VALUES (?,?,?,?)",
                )
                .bind(&event.record_id)
                .bind(principal)
                .bind(event.local_seq)
                .bind(&event.created_at)
                .execute(&mut *conn)
                .await?;
            }
            sqlx::query(
                "UPDATE message_origin_state
                    SET status='declared',origin_type='direct',collection_id=NULL,
                        direct_set_digest=?,participant_count=?,
                        declaration_event_seq=?,updated_at=?
                  WHERE message_id=? AND status='legacy_unknown'",
            )
            .bind(digest)
            .bind(principals.len() as i64)
            .bind(event.local_seq)
            .bind(&event.created_at)
            .bind(&event.record_id)
            .execute(&mut *conn)
            .await?;
        }
    }
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_message_shared(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let payload: MessageSharedPayload = parse_payload(event)?;
    if payload.grant_id.trim().is_empty()
        || payload.selection_id.trim().is_empty()
        || payload.reason.trim().is_empty()
        || payload.snapshot_seq < 0
    {
        return Err(Error::engine("message.shared payload is incomplete"));
    }
    let status: Option<String> =
        sqlx::query_scalar("SELECT status FROM message_audience_state WHERE message_id = ?")
            .bind(&event.record_id)
            .fetch_optional(&mut *conn)
            .await?;
    if status.as_deref() != Some("declared") {
        return Err(Error::engine(
            "legacy-unknown or unsealed Messages cannot be canonically shared",
        ));
    }
    assert_portable_person(conn, &payload.recipient_id, &event.event_type).await?;
    declared_principal(&payload.recipient_principal, &event.event_type)?;
    sqlx::query(
        "INSERT INTO message_audiences
            (message_id,principal_id,source,grant_id,event_seq,created_at)
         VALUES (?,?,'share',?,?,?)
         ON CONFLICT(message_id,principal_id,source,grant_id) DO NOTHING",
    )
    .bind(&event.record_id)
    .bind(&payload.recipient_principal)
    .bind(&payload.grant_id)
    .bind(event.local_seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_message_send_evaluated(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_message_event(conn, event).await?;
    let payload: MessageSendEvaluatedPayload = parse_payload(event)?;
    if payload.format != "native.message-send-evaluation.v1"
        || payload.idempotency_key.trim().is_empty()
        || !matches!(
            payload.disposition.as_str(),
            "silent_autonomy" | "log_only" | "notify_and_proceed" | "block_and_request_authority"
        )
        || payload.delivered == (payload.disposition == "block_and_request_authority")
    {
        return Err(Error::engine(
            "invalid native.message-send-evaluation.v1 payload",
        ));
    }
    require_digest(&payload.intent_digest, "message send intent_digest")?;
    require_digest(&payload.action_digest, "message send action_digest")?;
    require_digest(&payload.evaluation_digest, "message send evaluation_digest")?;
    let action = payload
        .action
        .as_object()
        .ok_or_else(|| Error::engine("message send action facts must be an object"))?;
    let action_correspondents = action
        .get("correspondent_principal_ids")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::engine("message send action facts have no correspondents"))?;
    let intended_principals = payload
        .intended_recipients
        .iter()
        .map(|recipient| Value::String(recipient.principal.clone()))
        .collect::<Vec<_>>();
    if crate::interventions::sha256_json(&payload.action)? != payload.action_digest
        || action.len() != 8
        || action.get("class").and_then(Value::as_str) != Some("communicate")
        || action.get("operation").and_then(Value::as_str) != Some("send_message")
        || action.get("destination_kind").and_then(Value::as_str) != Some("same_workspace")
        || action
            .get("destination_workspace_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || action.get("reversible").and_then(Value::as_bool) != Some(false)
        || action.get("sensitivity").and_then(Value::as_str) != Some("unknown")
        || action_correspondents != &intended_principals
        || action.get("disclosure_preview")
            != Some(
                &payload
                    .disclosure_preview
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            )
    {
        return Err(Error::engine(
            "message send action facts or digest are inconsistent",
        ));
    }
    let workspace_id = action
        .get("destination_workspace_id")
        .and_then(Value::as_str)
        .expect("validated non-empty destination workspace");
    let reconstructed_context = serde_json::json!({
        "format":"native.escalation-context.v1",
        "message":{
            "sender_principal_id":payload.sender_principal_id,
            "workspace_id":workspace_id,
        },
        "action":payload.action,
    });
    if payload
        .policy_trace
        .get("context_digest")
        .and_then(Value::as_str)
        != Some(crate::interventions::sha256_json(&reconstructed_context)?.as_str())
    {
        return Err(Error::engine(
            "message send action facts do not match the evaluated policy context",
        ));
    }
    crate::interventions::verify_evaluation_trace(
        &payload.policy_trace,
        &payload.evaluation_digest,
    )?;
    if payload
        .policy_trace
        .get("final_disposition")
        .and_then(Value::as_str)
        != Some(payload.disposition.as_str())
        || payload
            .disclosure_preview
            .as_deref()
            .is_some_and(|preview| preview.trim().is_empty() || preview.chars().count() > 500)
        || (payload.disposition == "block_and_request_authority"
            && payload.disclosure_preview.is_none())
    {
        return Err(Error::engine(
            "message send evaluation trace or disclosure preview is inconsistent",
        ));
    }
    declared_principal(&payload.sender_principal_id, &event.event_type)?;
    let declared_sender: Option<String> = sqlx::query_scalar(
        "SELECT principal_id FROM message_audiences
          WHERE message_id=? AND source='sender' LIMIT 1",
    )
    .bind(&event.record_id)
    .fetch_optional(&mut *conn)
    .await?;
    if declared_sender.as_deref() != Some(payload.sender_principal_id.as_str()) {
        return Err(Error::engine(
            "message send evaluation sender does not match declared audience",
        ));
    }
    if payload.intended_recipients.is_empty() {
        // A channel post is the one send that addresses nobody: it is filed in
        // a Collection and takes its audience from there, so the addressing
        // checks below hold vacuously. Any other empty audience is an addressed
        // send that lost its recipients, and stays a fold failure.
        let filed_in_collection: bool = sqlx::query_scalar(
            "SELECT EXISTS(
               SELECT 1 FROM records message
                 JOIN records home ON home.id=message.home_id
                WHERE message.id=? AND home.type='Collection'
             )",
        )
        .bind(&event.record_id)
        .fetch_one(&mut *conn)
        .await?;
        if !filed_in_collection {
            return Err(Error::engine(
                "message send evaluation requires intended recipients unless the Message is filed in a Collection",
            ));
        }
    }
    let mut recipients = std::collections::BTreeSet::new();
    for recipient in &payload.intended_recipients {
        if !recipients.insert((&recipient.recipient_id, &recipient.principal)) {
            return Err(Error::engine(
                "message send evaluation contains duplicate recipients",
            ));
        }
        assert_portable_person(conn, &recipient.recipient_id, &event.event_type).await?;
        declared_principal(&recipient.principal, &event.event_type)?;
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='message.send_evaluated.v1'",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if count != 1 {
        return Err(Error::engine(
            "a Message may have exactly one send evaluation",
        ));
    }
    let addressed_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM links WHERE source_id=? AND relationship='addressed_to'",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if payload.delivered {
        if addressed_count != payload.intended_recipients.len() as i64 {
            return Err(Error::engine(
                "delivered send evaluation does not match the declared audience",
            ));
        }
        for recipient in &payload.intended_recipients {
            let declared: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM links
                  WHERE source_id=? AND target_id=? AND relationship='addressed_to')",
            )
            .bind(&event.record_id)
            .bind(&recipient.recipient_id)
            .fetch_one(&mut *conn)
            .await?;
            if !declared {
                return Err(Error::engine(
                    "delivered send recipient does not match the declared audience",
                ));
            }
        }
        invalidate_superseded_message_mentions(conn, &event.record_id).await?;
    } else if addressed_count != 0 {
        return Err(Error::engine(
            "blocked send evaluation must follow an empty declared audience",
        ));
    }
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_message_delivery_authorized(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_message_event(conn, event).await?;
    let payload: MessageDeliveryAuthorizedPayload = parse_payload(event)?;
    if payload.format != "native.message-delivery-authorized.v1"
        || payload.intervention_id.trim().is_empty()
        || payload.idempotency_key.trim().is_empty()
        || payload.authority_evidence_record_id.trim().is_empty()
        || payload.recipients.is_empty()
    {
        return Err(Error::engine(
            "invalid native.message-delivery-authorized.v1 payload",
        ));
    }
    require_digest(&payload.action_digest, "authorized delivery action_digest")?;
    require_digest(
        &payload.fresh_evaluation_digest,
        "authorized delivery fresh_evaluation_digest",
    )?;
    crate::interventions::verify_evaluation_trace(
        &payload.fresh_policy_trace,
        &payload.fresh_evaluation_digest,
    )?;
    let (_, raised): (_, InterventionRaisedPayload) =
        earlier_payload(conn, event, "intervention.raised.v1").await?;
    if raised.intervention_id != payload.intervention_id
        || raised.disposition != "block_and_request_authority"
        || raised.action_digest != payload.action_digest
        || raised.intended_recipients != payload.recipients
        || raised.policy_trace.get("context_digest")
            != payload.fresh_policy_trace.get("context_digest")
        || !matches!(
            payload
                .fresh_policy_trace
                .get("final_disposition")
                .and_then(Value::as_str),
            Some(
                "silent_autonomy"
                    | "log_only"
                    | "notify_and_proceed"
                    | "block_and_request_authority"
            )
        )
    {
        return Err(Error::engine(
            "authorized delivery contradicts its earlier intervention",
        ));
    }
    let evidence_valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM records evidence
            JOIN links authority
              ON authority.source_id=evidence.id
             AND authority.target_id=?
             AND authority.relationship='authorizes'
           WHERE evidence.id=? AND evidence.type='Resolution'
             AND evidence.kind='decision' AND evidence.deleted_at IS NULL
             AND evidence.owner_id=?
        )",
    )
    .bind(&event.record_id)
    .bind(&payload.authority_evidence_record_id)
    .bind(&raised.target_person_record_id)
    .fetch_one(&mut *conn)
    .await?;
    if !evidence_valid {
        return Err(Error::engine(
            "authorized delivery requires linked target-authored Decision evidence",
        ));
    }
    let prior_terminal: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
          WHERE record_id=? AND seq<?
            AND type IN ('intervention.cancelled.v1','intervention.execution_resumed.v1')
            AND json_extract(payload,'$.intervention_id')=?",
    )
    .bind(&event.record_id)
    .bind(event.local_seq)
    .bind(&payload.intervention_id)
    .fetch_one(&mut *conn)
    .await?;
    if prior_terminal != 0 {
        return Err(Error::engine(
            "authorized delivery cannot follow a terminal intervention event",
        ));
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='message.delivery.authorized.v1'",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if count != 1 {
        return Err(Error::engine(
            "a blocked Message may be delivered at most once",
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for recipient in &payload.recipients {
        if !seen.insert(recipient.recipient_id.as_str()) {
            return Err(Error::engine(
                "authorized delivery contains duplicate recipients",
            ));
        }
        assert_portable_person(conn, &recipient.recipient_id, &event.event_type).await?;
        let principal = declared_principal(&recipient.principal, &event.event_type)?;
        sqlx::query(
            "INSERT INTO links (id,source_id,target_id,relationship,note,created_at)
             VALUES (?,?,?,'addressed_to',NULL,?)",
        )
        .bind(format!(
            "lnk:{}:{}:addressed_to",
            event.record_id, recipient.recipient_id
        ))
        .bind(&event.record_id)
        .bind(&recipient.recipient_id)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
        sqlx::query(
            "INSERT INTO message_audiences
                (message_id,principal_id,source,grant_id,event_seq,created_at)
             VALUES (?,?,'addressed_to',?,?,?)",
        )
        .bind(&event.record_id)
        .bind(principal)
        .bind(format!("delivery:{}", payload.intervention_id))
        .bind(event.local_seq)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    }
    invalidate_superseded_message_mentions(conn, &event.record_id).await?;
    touch(conn, &event.record_id, &event.created_at).await
}

async fn invalidate_superseded_message_mentions(
    conn: &mut SqliteConnection,
    delivered_message_id: &str,
) -> Result<()> {
    sqlx::query(
        "UPDATE message_mentions SET effective=0
          WHERE message_id IN (
                SELECT target_id FROM links
                 WHERE source_id=? AND relationship='supersedes'
              )",
    )
    .bind(delivered_message_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}
