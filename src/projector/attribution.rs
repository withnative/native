use super::*;

async fn assert_attribution_annotation(
    conn: &mut SqliteConnection,
    record_id: &str,
    event_type: &str,
) -> Result<()> {
    assert_record_live(conn, record_id, event_type).await?;
    let row = sqlx::query("SELECT type,kind FROM records WHERE id=?")
        .bind(record_id)
        .fetch_one(&mut *conn)
        .await?;
    if row.try_get::<String, _>("type")? != "Annotation"
        || row.try_get::<Option<String>, _>("kind")?.as_deref() != Some("attribution")
    {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: record {record_id} is not Annotation kind:attribution"
        )));
    }
    Ok(())
}

pub(super) async fn project_attribution_target_bound(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_attribution_annotation(conn, &event.record_id, &event.event_type).await?;
    let payload: AttributionTargetBoundPayload = parse_payload(event)?;
    assert_record_live(conn, &payload.target_record_id, &event.event_type).await?;
    let bearers = sqlx::query_scalar::<_, String>(
        "SELECT target_id FROM links WHERE source_id=? AND relationship='part_of' ORDER BY target_id",
    )
    .bind(&event.record_id)
    .fetch_all(&mut *conn)
    .await?;
    if bearers.len() != 1 || bearers[0] != payload.target_record_id {
        return Err(Error::engine(format!(
            "cannot apply {}: attribution {} requires exactly one part_of bearer equal to its target",
            event.event_type, event.record_id
        )));
    }
    if payload.source_event_id.trim().is_empty()
        || payload.source_body_sha256.len() != 64
        || !payload
            .source_body_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::engine(format!(
            "cannot apply {}: invalid exact body source identity",
            event.event_type
        )));
    }
    let source =
        sqlx::query("SELECT seq,type,payload FROM content_events WHERE id=? AND record_id=?")
            .bind(&payload.source_event_id)
            .bind(&payload.target_record_id)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or_else(|| {
                Error::engine("attribution source event is unavailable on its target")
            })?;
    let source_seq: i64 = source.try_get("seq")?;
    let source_type: String = source.try_get("type")?;
    let source_payload: Value = serde_json::from_str(&source.try_get::<String, _>("payload")?)?;
    if source_type != "record.created"
        && !(source_type == "record.updated" && source_payload.get("body").is_some())
    {
        return Err(Error::engine(
            "attribution source event must be an exact body-producing record event",
        ));
    }
    let body_events = sqlx::query(
        "SELECT type,payload FROM content_events
          WHERE record_id=? AND seq<=? AND type IN ('record.created','record.updated')
          ORDER BY seq",
    )
    .bind(&payload.target_record_id)
    .bind(source_seq)
    .fetch_all(&mut *conn)
    .await?;
    let mut source_body: Option<String> = None;
    for body_event in body_events {
        let event_type: String = body_event.try_get("type")?;
        let event_payload: Value =
            serde_json::from_str(&body_event.try_get::<String, _>("payload")?)?;
        if event_type == "record.created" || event_payload.get("body").is_some() {
            source_body = event_payload
                .get("body")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
    }
    use sha2::Digest as _;
    let source_body = source_body.unwrap_or_default().into_bytes();
    let verified_sha256 = hex::encode(sha2::Sha256::digest(&source_body));
    if verified_sha256 != payload.source_body_sha256 {
        return Err(Error::engine(
            "attribution source body does not match its immutable SHA-256",
        ));
    }
    let selector_count = payload
        .selectors
        .as_array()
        .ok_or_else(|| Error::engine("attribution selectors must be an array"))?
        .len();
    match payload.target_scope.as_str() {
        "whole_revision" if selector_count == 0 => {}
        "passage" if selector_count > 0 => {
            let selectors: Vec<crate::citations::SelectorInput> =
                serde_json::from_value(payload.selectors.clone())?;
            let canonical = crate::citations::canonicalize_selectors(selectors, &source_body)?;
            if serde_json::to_value(canonical)? != payload.selectors {
                return Err(Error::engine(
                    "passage attribution selectors must carry Native's canonical integrity fields",
                ));
            }
        }
        "whole_revision" => {
            return Err(Error::engine(
                "whole_revision attribution target must not carry selectors",
            ))
        }
        "passage" => {
            return Err(Error::engine(
                "passage attribution target requires canonical selectors",
            ))
        }
        _ => return Err(Error::engine("invalid attribution target scope")),
    }
    sqlx::query(
        "INSERT INTO attribution_targets
           (annotation_id,target_record_id,target_scope,source_event_id,source_body_sha256,selectors,bound_event_id,bound_event_seq,bound_at)
         VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(&event.record_id)
    .bind(&payload.target_record_id)
    .bind(&payload.target_scope)
    .bind(&payload.source_event_id)
    .bind(&payload.source_body_sha256)
    .bind(serde_json::to_string(&payload.selectors)?)
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_attribution_asserted(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_attribution_annotation(conn, &event.record_id, &event.event_type).await?;
    let payload: AttributionAssertedPayload = parse_payload(event)?;
    if payload.contract_version != crate::attribution::CONTRACT_VERSION
        || payload.claimant_principal.trim().is_empty()
        || !matches!(payload.claim_mode.as_str(), "declaration" | "assessment")
        || !matches!(payload.relation.as_str(), "expresses_view" | "endorses")
        || !matches!(payload.polarity.as_str(), "affirmed" | "denied")
        || !matches!(
            payload.attributed_subject_kind.as_str(),
            "person_record" | "agent_execution"
        )
        || payload.attributed_subject_ref.trim().is_empty()
        || !matches!(
            payload.transformation.as_str(),
            "none" | "selection" | "paraphrase" | "summary" | "synthesis"
        )
        || (payload.claim_mode == "declaration"
            && (payload.attributed_subject_kind != "person_record"
                || payload.transformation != "none"))
        || payload.rationale.trim().is_empty()
        || chrono::DateTime::parse_from_rfc3339(&payload.stance_as_of).is_err()
    {
        return Err(Error::engine("invalid closed attribution assertion"));
    }
    let confidence_valid = matches!(
        (payload.claim_mode.as_str(), payload.confidence.as_deref()),
        ("declaration", None)
            | (
                "assessment",
                Some("tentative" | "plausible" | "likely" | "confident")
            )
    );
    if !confidence_valid {
        return Err(Error::engine(
            "declarations omit confidence and assessments require an ordinal confidence",
        ));
    }
    if payload.attributed_subject_kind == "person_record" {
        // Content-log replay is deliberately independent of the meta log, so
        // this closed event check cannot consult vocabulary projections. Kind
        // authoring has already canonicalized aliases to the durable token.
        let person: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM records r
              WHERE r.id=? AND r.deleted_at IS NULL
                AND r.type='Entity' AND r.kind='person')",
        )
        .bind(&payload.attributed_subject_ref)
        .fetch_one(&mut *conn)
        .await?;
        if person == 0 {
            return Err(Error::engine(
                "attribution person subject must name a live Entity kind:person",
            ));
        }
    } else if uuid::Uuid::parse_str(&payload.attributed_subject_ref).is_err() {
        return Err(Error::engine(
            "attribution agent_execution subject must name an action attestation UUID",
        ));
    }
    let targeted: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM attribution_targets WHERE annotation_id=?)",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if targeted == 0 {
        return Err(Error::engine(
            "attribution assertion requires an immutable target first",
        ));
    }
    sqlx::query(
        "INSERT INTO attribution_assertions
           (annotation_id,contract_version,claimant_principal,claim_mode,relation,polarity,attributed_subject_kind,attributed_subject_ref,
            asserted_at,stance_as_of,confidence,transformation,rationale,asserted_event_id,asserted_event_seq)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&event.record_id)
    .bind(&payload.contract_version)
    .bind(&payload.claimant_principal)
    .bind(&payload.claim_mode)
    .bind(&payload.relation)
    .bind(&payload.polarity)
    .bind(&payload.attributed_subject_kind)
    .bind(&payload.attributed_subject_ref)
    .bind(&event.created_at)
    .bind(&payload.stance_as_of)
    .bind(&payload.confidence)
    .bind(&payload.transformation)
    .bind(&payload.rationale)
    .bind(&event.id)
    .bind(event.local_seq)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_attribution_evidence_added(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_attribution_annotation(conn, &event.record_id, &event.event_type).await?;
    let payload: AttributionEvidenceAddedPayload = parse_payload(event)?;
    if payload.evidence_id.trim().is_empty()
        || payload.action_attestation_id.trim().is_empty()
        || !matches!(
            payload.role.as_str(),
            "basis" | "exact_target_confirmation" | "counterevidence"
        )
    {
        return Err(Error::engine("invalid attribution evidence reference"));
    }
    let asserted: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM attribution_assertions WHERE annotation_id=?)",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if asserted == 0 {
        return Err(Error::engine(
            "attribution evidence requires an assertion first",
        ));
    }
    if payload.role == "exact_target_confirmation" {
        let declaration: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM attribution_assertions
              WHERE annotation_id=? AND claim_mode='declaration')",
        )
        .bind(&event.record_id)
        .fetch_one(&mut *conn)
        .await?;
        let already: i64 = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM attribution_evidence
              WHERE annotation_id=? AND role='exact_target_confirmation')",
        )
        .bind(&event.record_id)
        .fetch_one(&mut *conn)
        .await?;
        if declaration == 0 || already != 0 {
            return Err(Error::engine(
                "exact target confirmation is reserved for one atomic direct declaration",
            ));
        }
    }
    let added_by = event
        .actor
        .as_deref()
        .filter(|actor| !actor.trim().is_empty())
        .ok_or_else(|| Error::engine("attribution evidence requires an authenticated actor"))?;
    sqlx::query(
        "INSERT INTO attribution_evidence
           (evidence_id,annotation_id,role,action_attestation_id,added_event_id,event_seq,added_at,added_by)
         VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(&payload.evidence_id)
    .bind(&event.record_id)
    .bind(&payload.role)
    .bind(&payload.action_attestation_id)
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(&event.created_at)
    .bind(added_by)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_attribution_retracted(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_attribution_annotation(conn, &event.record_id, &event.event_type).await?;
    let payload: AttributionRetractedPayload = parse_payload(event)?;
    if payload.retraction_id.trim().is_empty() || payload.reason.trim().is_empty() {
        return Err(Error::engine("invalid attribution retraction"));
    }
    let asserted: i64 = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM attribution_assertions WHERE annotation_id=?)",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if asserted == 0 {
        return Err(Error::engine(
            "attribution retraction requires an assertion",
        ));
    }
    let retracted_by = event
        .actor
        .as_deref()
        .filter(|actor| !actor.trim().is_empty())
        .ok_or_else(|| Error::engine("attribution retraction requires an authenticated actor"))?;
    sqlx::query(
        "INSERT INTO attribution_retractions
           (retraction_id,annotation_id,reason,retracted_event_id,retracted_event_seq,retracted_at,retracted_by)
         VALUES(?,?,?,?,?,?,?)",
    )
    .bind(&payload.retraction_id)
    .bind(&event.record_id)
    .bind(&payload.reason)
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(&event.created_at)
    .bind(retracted_by)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}
