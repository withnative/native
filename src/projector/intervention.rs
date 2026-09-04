use super::*;

pub(super) async fn project_intervention_raised(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_message_event(conn, event).await?;
    let payload: InterventionRaisedPayload = parse_payload(event)?;
    if payload.format != "native.intervention.raised.v1"
        || payload.intervention_id.trim().is_empty()
        || payload.idempotency_key.trim().is_empty()
        || payload.reason.trim().is_empty()
        || !matches!(
            payload.disposition.as_str(),
            "notify_and_proceed" | "block_and_request_authority"
        )
    {
        return Err(Error::engine(
            "invalid native.intervention.raised.v1 payload",
        ));
    }
    require_digest(&payload.action_digest, "intervention action_digest")?;
    require_digest(&payload.evaluation_digest, "intervention evaluation_digest")?;
    crate::interventions::verify_evaluation_trace(
        &payload.policy_trace,
        &payload.evaluation_digest,
    )?;
    if payload
        .disclosure_preview
        .as_deref()
        .is_some_and(|preview| preview.trim().is_empty() || preview.chars().count() > 500)
        || (payload.disposition == "block_and_request_authority"
            && payload.disclosure_preview.is_none())
    {
        return Err(Error::engine(
            "blocking intervention requires a bounded disclosure preview",
        ));
    }
    assert_portable_person(conn, &payload.target_person_record_id, &event.event_type).await?;
    // The write command verifies this frozen address against the live binding.
    // The content projector validates only portable event bytes: consulting the
    // meta/control tier here would make content replay non-deterministic.
    declared_principal(&payload.target_principal_id, &event.event_type)?;
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
            "intervention sender does not match the declared Message sender",
        ));
    }
    let (_, send): (_, MessageSendEvaluatedPayload) =
        earlier_payload(conn, event, "message.send_evaluated.v1").await?;
    if send.disposition != payload.disposition
        || send.action != payload.action
        || send.action_digest != payload.action_digest
        || send.evaluation_digest != payload.evaluation_digest
        || send.policy_trace != payload.policy_trace
        || send.intended_recipients != payload.intended_recipients
        || send.disclosure_preview != payload.disclosure_preview
        || send.delivered != (payload.disposition == "notify_and_proceed")
        || payload.intended_recipients.len() != 1
        || payload.intended_recipients[0].recipient_id != payload.target_person_record_id
        || payload.intended_recipients[0].principal != payload.target_principal_id
    {
        return Err(Error::engine(
            "intervention raise contradicts its earlier send evaluation",
        ));
    }
    let duplicates: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
          WHERE type='intervention.raised.v1'
            AND json_extract(payload,'$.intervention_id')=?",
    )
    .bind(&payload.intervention_id)
    .fetch_one(&mut *conn)
    .await?;
    if duplicates != 1 {
        return Err(Error::engine("intervention_id must be globally unique"));
    }
    let message_raises: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
          WHERE record_id=? AND type='intervention.raised.v1'",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if message_raises != 1 {
        return Err(Error::engine(
            "a Message send may raise at most one intervention",
        ));
    }
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_intervention_cancelled(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_message_event(conn, event).await?;
    let payload: InterventionCancelledPayload = parse_payload(event)?;
    if payload.format != "native.intervention.cancelled.v1"
        || payload.intervention_id.trim().is_empty()
        || payload.target_principal_id.trim().is_empty()
        || payload.idempotency_key.trim().is_empty()
        || payload.reason.trim().is_empty()
    {
        return Err(Error::engine(
            "invalid native.intervention.cancelled.v1 payload",
        ));
    }
    require_digest(
        &payload.action_digest,
        "intervention cancellation action_digest",
    )?;
    let (_, raised): (_, InterventionRaisedPayload) =
        earlier_payload(conn, event, "intervention.raised.v1").await?;
    if raised.intervention_id != payload.intervention_id
        || raised.disposition != "block_and_request_authority"
        || raised.target_principal_id != payload.target_principal_id
        || raised.action_digest != payload.action_digest
    {
        return Err(Error::engine(
            "intervention cancellation contradicts its earlier raise",
        ));
    }
    assert_single_terminal(conn, event, &payload.intervention_id).await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_intervention_execution_resumed(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_message_event(conn, event).await?;
    let payload: InterventionExecutionResumedPayload = parse_payload(event)?;
    if payload.format != "native.intervention.execution-resumed.v1"
        || payload.intervention_id.trim().is_empty()
        || payload.target_principal_id.trim().is_empty()
        || payload.idempotency_key.trim().is_empty()
        || payload.basis_kind != "authority_evidence"
        || payload.basis_record_id.trim().is_empty()
        || payload.delivery_event_id.trim().is_empty()
        || payload.summary.trim().is_empty()
    {
        return Err(Error::engine(
            "invalid native.intervention.execution-resumed.v1 payload",
        ));
    }
    require_digest(&payload.action_digest, "intervention resume action_digest")?;
    require_digest(
        &payload.fresh_evaluation_digest,
        "intervention resume fresh_evaluation_digest",
    )?;
    let (_, raised): (_, InterventionRaisedPayload) =
        earlier_payload(conn, event, "intervention.raised.v1").await?;
    if raised.intervention_id != payload.intervention_id
        || raised.disposition != "block_and_request_authority"
        || raised.action_digest != payload.action_digest
        || raised.target_principal_id != payload.target_principal_id
    {
        return Err(Error::engine(
            "intervention resume contradicts its earlier raise",
        ));
    }
    let delivery_row = sqlx::query(
        "SELECT payload FROM content_events
          WHERE id=? AND record_id=? AND type='message.delivery.authorized.v1' AND seq<?",
    )
    .bind(&payload.delivery_event_id)
    .bind(&event.record_id)
    .bind(event.local_seq)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("intervention resume references no earlier delivery event"))?;
    let delivery: MessageDeliveryAuthorizedPayload =
        serde_json::from_str(&delivery_row.try_get::<String, _>("payload")?)?;
    if delivery.intervention_id != payload.intervention_id
        || delivery.action_digest != payload.action_digest
        || delivery.authority_evidence_record_id != payload.basis_record_id
        || delivery.fresh_evaluation_digest != payload.fresh_evaluation_digest
    {
        return Err(Error::engine(
            "intervention resume contradicts its authorized delivery event",
        ));
    }
    assert_single_terminal(conn, event, &payload.intervention_id).await?;
    touch(conn, &event.record_id, &event.created_at).await
}
