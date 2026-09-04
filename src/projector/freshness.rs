use super::*;

async fn project_runtime_command(
    conn: &mut SqliteConnection,
    event: &EventRow,
    command: &SemanticCommandFinalization,
    expected_scope: &str,
    expected_operation: &str,
) -> Result<()> {
    crate::freshness::IdempotencyKey::new(command.idempotency_key.clone())?;
    if command.operation != expected_operation
        || command.scope_record_id != expected_scope
        || command.authorization_revision_observed < 0
        || !valid_sha256(&command.intent_sha256)
    {
        return Err(Error::engine(
            "invalid freshness runtime command finalization",
        ));
    }
    sqlx::query(
        "INSERT INTO freshness_runtime_command_results
           (scope_record_id,idempotency_key,operation,intent_sha256,result_event_id,event_seq,
            authorization_revision_observed,created_at) VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(&command.scope_record_id)
    .bind(&command.idempotency_key)
    .bind(&command.operation)
    .bind(&command.intent_sha256)
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(command.authorization_revision_observed)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn project_semantic_command(
    conn: &mut SqliteConnection,
    event: &EventRow,
    command: &SemanticCommandFinalization,
    expected_scope_record_id: &str,
) -> Result<()> {
    crate::freshness::IdempotencyKey::new(command.idempotency_key.clone())?;
    if !matches!(
        command.operation.as_str(),
        "promote_idea" | "bind_occurrence" | "revise_unit"
    ) || command.scope_record_id != expected_scope_record_id
        || command.idempotency_key.trim().is_empty()
        || command.authorization_revision_observed < 0
        || command.intent_sha256.len() != 64
        || command
            .intent_sha256
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Err(Error::engine("invalid freshness command finalization"));
    }
    sqlx::query(
        "INSERT INTO freshness_command_results
           (scope_record_id,idempotency_key,operation,intent_sha256,result_event_id,event_seq,
            authorization_revision_observed,created_at)
         VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(&command.scope_record_id)
    .bind(&command.idempotency_key)
    .bind(&command.operation)
    .bind(&command.intent_sha256)
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(command.authorization_revision_observed)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

fn require_semantic_actor(event: &EventRow) -> Result<()> {
    if event
        .actor
        .as_deref()
        .is_none_or(|actor| actor.trim().is_empty())
    {
        Err(Error::engine(format!(
            "{} requires a nonblank immutable actor",
            event.event_type
        )))
    } else {
        Ok(())
    }
}

pub(super) async fn project_unit_created(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    require_semantic_actor(event)?;
    crate::freshness::UnitId::new(event.record_id.clone())?;
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let payload: UnitCreatedPayload = parse_payload(event)?;
    if payload.semantic_contract_version != SEMANTIC_CONTRACT_VERSION
        || payload.authority_bearer_record_id == event.record_id
        || payload
            .label
            .as_deref()
            .is_some_and(|label| label.trim().is_empty())
    {
        return Err(Error::engine("invalid unit.created.v1 payload"));
    }
    let envelope = sqlx::query("SELECT type,kind,body FROM records WHERE id=?")
        .bind(&event.record_id)
        .fetch_one(&mut *conn)
        .await?;
    if envelope.try_get::<String, _>("type")? != "Entity"
        || envelope.try_get::<Option<String>, _>("kind")?.as_deref() != Some("semantic-unit")
        || envelope.try_get::<Option<String>, _>("body")?.is_some()
    {
        return Err(Error::engine(
            "unit identity envelope must be an Entity kind:semantic-unit with no generic body",
        ));
    }
    assert_record_live(conn, &payload.authority_bearer_record_id, &event.event_type).await?;
    sqlx::query(
        "INSERT INTO semantic_units
           (unit_id,authority_bearer_record_id,creation_event_id,creation_event_seq,label,created_at)
         VALUES(?,?,?,?,?,?)",
    )
    .bind(&event.record_id)
    .bind(&payload.authority_bearer_record_id)
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(&payload.label)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_unit_revision_recorded(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    require_semantic_actor(event)?;
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let payload: UnitRevisionRecordedPayload = parse_payload(event)?;
    payload.content.validate()?;
    if payload.format != UNIT_REVISION_FORMAT
        || payload.semantic_contract_version != SEMANTIC_CONTRACT_VERSION
        || payload.content.sha256() != payload.content_sha256
        || payload
            .rationale
            .as_deref()
            .is_some_and(|rationale| rationale.trim().is_empty())
    {
        return Err(Error::engine("invalid unit.revision.recorded.v1 payload"));
    }
    let unit_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM semantic_units WHERE unit_id=?)")
            .bind(&event.record_id)
            .fetch_one(&mut *conn)
            .await?;
    if !unit_exists {
        return Err(Error::engine(
            "unit revision requires an authoritative unit.created.v1 event",
        ));
    }
    if let Some(based_on) = payload.based_on_revision_event_id.as_deref() {
        let parent_unit: Option<String> =
            sqlx::query_scalar("SELECT unit_id FROM unit_revisions WHERE revision_event_id=?")
                .bind(based_on)
                .fetch_optional(&mut *conn)
                .await?;
        if parent_unit.as_deref() != Some(event.record_id.as_str()) {
            return Err(Error::engine(
                "unit revision based_on must identify a revision of the same Unit",
            ));
        }
    } else {
        let prior: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM unit_revisions WHERE unit_id=?)")
                .bind(&event.record_id)
                .fetch_one(&mut *conn)
                .await?;
        if prior {
            return Err(Error::engine(
                "only the first Unit revision may omit based_on_revision_event_id",
            ));
        }
    }
    sqlx::query(
        "INSERT INTO unit_revisions
           (revision_event_id,unit_id,revision_seq,based_on_revision_event_id,content_sha256,
            content_media_type,encoding_version,rationale,actor,created_at)
         VALUES(?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&event.id)
    .bind(&event.record_id)
    .bind(event.local_seq)
    .bind(&payload.based_on_revision_event_id)
    .bind(&payload.content_sha256)
    .bind(payload.content.content_media_type.as_str())
    .bind(i64::from(payload.content.encoding_version.get()))
    .bind(&payload.rationale)
    .bind(&event.actor)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    if let Some(based_on) = payload.based_on_revision_event_id.as_deref() {
        sqlx::query("DELETE FROM unit_heads WHERE unit_id=? AND revision_event_id=?")
            .bind(&event.record_id)
            .bind(based_on)
            .execute(&mut *conn)
            .await?;
    }
    sqlx::query("INSERT INTO unit_heads(unit_id,revision_event_id) VALUES(?,?)")
        .bind(&event.record_id)
        .bind(&event.id)
        .execute(&mut *conn)
        .await?;
    let updated_at = next_record_updated_at(conn, &event.record_id, &event.created_at).await?;
    sqlx::query("UPDATE records SET body=?,updated_at=?,last_activity_at=? WHERE id=?")
        .bind(&payload.content.content)
        .bind(updated_at)
        .bind(&event.created_at)
        .bind(&event.record_id)
        .execute(&mut *conn)
        .await?;
    if let Some(command) = payload.command.as_ref() {
        if command.operation != "revise_unit" {
            return Err(Error::engine(
                "Unit revision command finalization must be revise_unit",
            ));
        }
        project_semantic_command(conn, event, command, &event.record_id).await?;
    }
    Ok(())
}

pub(super) async fn project_occurrence_bound(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    require_semantic_actor(event)?;
    let payload: OccurrenceBoundPayload = parse_payload(event)?;
    payload.occurrence_id.validate()?;
    if payload.semantic_contract_version != SEMANTIC_CONTRACT_VERSION
        || payload.unit_revision.subject_kind != RevisionSubjectKind::Unit
        || payload.unit_revision.source_slot != RevisionSourceSlot::UnitContent
        || payload.artefact_revision.subject_kind != RevisionSubjectKind::Artefact
        || payload.artefact_revision.source_slot != RevisionSourceSlot::RecordBody
        || payload.unit_revision.subject_id != event.record_id
        || !matches!(
            payload.expression_role.as_str(),
            "canonical" | "paraphrase" | "summary" | "quotation"
        )
        || payload.selectors.is_empty()
    {
        return Err(Error::engine("invalid occurrence.bound.v1 payload"));
    }
    payload.unit_revision.validate()?;
    payload.artefact_revision.validate()?;
    let unit_bytes = crate::freshness::verify_revision_ref_on(conn, &payload.unit_revision).await?;
    let artefact_bytes =
        crate::freshness::verify_revision_ref_on(conn, &payload.artefact_revision).await?;
    if unit_bytes.is_empty() {
        return Err(Error::engine("Occurrence Unit revision is empty"));
    }
    let canonical = crate::freshness::canonicalize_occurrence_selectors(
        payload.selectors.clone(),
        &artefact_bytes,
    )?;
    if canonical != payload.selectors {
        return Err(Error::engine(
            "occurrence.bound.v1 selectors must be canonical capture evidence",
        ));
    }
    let selectors_sha256 = intent_sha256(&payload.selectors)?;
    let unit_id = payload.unit_revision.subject_id.clone();
    sqlx::query(
        "INSERT INTO occurrences
           (occurrence_id,binding_event_id,binding_event_seq,unit_id,unit_revision_event_id,
            artefact_id,artefact_revision_event_id,artefact_revision_seq,artefact_sha256,
            selectors,selectors_sha256,expression_role,actor,created_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(payload.occurrence_id.as_str())
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(&unit_id)
    .bind(&payload.unit_revision.revision_event_id)
    .bind(&payload.artefact_revision.subject_id)
    .bind(&payload.artefact_revision.revision_event_id)
    .bind(payload.artefact_revision.revision_seq)
    .bind(&payload.artefact_revision.sha256)
    .bind(serde_json::to_string(&payload.selectors)?)
    .bind(selectors_sha256)
    .bind(&payload.expression_role)
    .bind(&event.actor)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    if !matches!(
        payload.command.operation.as_str(),
        "promote_idea" | "bind_occurrence"
    ) {
        return Err(Error::engine(
            "Occurrence command finalization must be promotion or binding",
        ));
    }
    let command_scope = if payload.command.operation == "promote_idea" {
        &payload.artefact_revision.subject_id
    } else {
        &payload.unit_revision.subject_id
    };
    project_semantic_command(conn, event, &payload.command, command_scope).await?;
    // An Occurrence is independently protected by its artefact. Advancing the
    // Unit envelope's public activity timestamp here would reveal a private
    // binding to callers who can see the Unit but not that artefact.
    Ok(())
}

pub(super) async fn project_receipt_committed_aggregate(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    require_semantic_actor(event)?;
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let payload: ReceiptCommittedPayload = parse_payload(event)?;
    payload.receipt_id.validate()?;
    payload.expected_consumer_revision.validate()?;
    payload.context_request.validate()?;
    payload.resolution_policy.validate()?;
    payload.history_high_water.validate()?;
    if payload.format != RECEIPT_FORMAT
        || payload.semantic_contract_version != SEMANTIC_CONTRACT_VERSION
        || payload.runtime_contract_version != RUNTIME_CONTRACT_VERSION
        || payload.expected_consumer_revision.subject_kind != RevisionSubjectKind::Artefact
        || payload.expected_consumer_revision.source_slot != RevisionSourceSlot::RecordBody
        || payload.expected_consumer_revision.subject_id != event.record_id
        || payload.expected_consumer_revision.revision_seq > payload.history_high_water.content_seq
        || payload.history_high_water.content_seq >= event.local_seq
        || payload.dependency_declaration_outcome.trim().is_empty()
        || payload.dependency_budget_used as usize != payload.dependencies.len()
        || payload.dependency_budget_used > payload.resolution_policy.dependency_budget
        || payload
            .requested_source_record_ids
            .iter()
            .any(|record_id| record_id.trim().is_empty())
        || payload
            .requested_source_record_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || !valid_sha256(&payload.assembly_sha256)
    {
        return Err(Error::engine(
            "invalid aggregate receipt.committed.v1 payload",
        ));
    }

    let pre_output_event_id: String = sqlx::query_scalar(
        "SELECT id FROM content_events
          WHERE record_id=? AND seq <= ?
            AND type IN ('record.created','record.updated','receipt.committed.v1')
            AND json_type(payload,'$.body') IS NOT NULL
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(&event.record_id)
    .bind(payload.history_high_water.content_seq)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("Receipt has no consumer revision at its high-water"))?;
    if pre_output_event_id != payload.expected_consumer_revision.revision_event_id {
        return Err(Error::engine(
            "Receipt expected consumer revision is not the head at its high-water",
        ));
    }
    let exact_pre_receipt_head: String = sqlx::query_scalar(
        "SELECT id FROM content_events
          WHERE record_id=? AND seq < ?
            AND type IN ('record.created','record.updated','receipt.committed.v1')
            AND json_type(payload,'$.body') IS NOT NULL
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(&event.record_id)
    .bind(event.local_seq)
    .fetch_one(&mut *conn)
    .await?;
    if exact_pre_receipt_head != payload.expected_consumer_revision.revision_event_id {
        return Err(Error::engine(
            "Receipt expected consumer revision is not the exact pre-Receipt head",
        ));
    }
    crate::freshness::verify_revision_ref_on(conn, &payload.expected_consumer_revision).await?;

    let output_revision = crate::freshness::RevisionRef {
        subject_kind: RevisionSubjectKind::Artefact,
        subject_id: event.record_id.clone(),
        revision_event_id: event.id.clone(),
        revision_seq: event.local_seq,
        source_slot: RevisionSourceSlot::RecordBody,
        sha256: crate::freshness::sha256(payload.body.as_bytes()),
    };

    let mut selected_events = std::collections::BTreeSet::new();
    let mut prior_selected: Option<(String, String)> = None;
    for selected in &payload.selected_sources {
        selected.validate()?;
        let key = (
            selected.subject_id.clone(),
            selected.revision_event_id.clone(),
        );
        if selected.revision_seq > payload.history_high_water.content_seq
            || prior_selected.as_ref().is_some_and(|prior| prior >= &key)
            || !selected_events.insert(selected.revision_event_id.clone())
        {
            return Err(Error::engine(
                "Receipt selected sources must be exact and canonically ordered",
            ));
        }
        crate::freshness::verify_revision_ref_on(conn, selected).await?;
        prior_selected = Some(key);
    }
    let mut deterministically_inherited_withheld: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM receipts
          WHERE output_revision_event_id=? AND withheld_context=1)",
    )
    .bind(&payload.expected_consumer_revision.revision_event_id)
    .fetch_one(&mut *conn)
    .await?;
    for selected in &payload.selected_sources {
        deterministically_inherited_withheld |= sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM receipts
              WHERE output_revision_event_id=? AND withheld_context=1)",
        )
        .bind(&selected.revision_event_id)
        .fetch_one(&mut *conn)
        .await?;
    }
    if deterministically_inherited_withheld && !payload.withheld_context {
        return Err(Error::engine(
            "Receipt cannot clear inherited authorization-redacted context",
        ));
    }

    let mut comparison_keys = std::collections::BTreeSet::new();
    let mut comparison_pins = std::collections::BTreeSet::new();
    let mut prior_comparison: Option<(String, String)> = None;
    for comparison in &payload.comparisons {
        comparison.dependency_id.validate()?;
        comparison.receipt_id.validate()?;
        comparison.pinned_source_revision.validate()?;
        comparison.candidate_source_revision.validate()?;
        let key = (
            comparison.dependency_id.as_str().to_owned(),
            comparison
                .candidate_source_revision
                .revision_event_id
                .clone(),
        );
        if comparison.pinned_source_revision.revision_seq > payload.history_high_water.content_seq
            || comparison.candidate_source_revision.revision_seq
                > payload.history_high_water.content_seq
            || prior_comparison.as_ref().is_some_and(|prior| prior >= &key)
            || !selected_events.contains(&comparison.candidate_source_revision.revision_event_id)
            || !comparison_keys.insert(key.clone())
        {
            return Err(Error::engine("invalid or noncanonical Receipt comparison"));
        }
        let debt = sqlx::query(
            "SELECT receipt_id,source_revision FROM dependencies WHERE dependency_id=?",
        )
        .bind(comparison.dependency_id.as_str())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("Receipt comparison dependency is unavailable"))?;
        if debt.try_get::<String, _>("receipt_id")? != comparison.receipt_id.as_str()
            || serde_json::from_str::<crate::freshness::RevisionRef>(
                &debt.try_get::<String, _>("source_revision")?,
            )? != comparison.pinned_source_revision
        {
            return Err(Error::engine(
                "Receipt comparison does not match exact debt",
            ));
        }
        crate::freshness::verify_revision_ref_on(conn, &comparison.pinned_source_revision).await?;
        crate::freshness::verify_revision_ref_on(conn, &comparison.candidate_source_revision)
            .await?;
        comparison_pins.insert(comparison.pinned_source_revision.revision_event_id.clone());
        prior_comparison = Some(key);
    }

    let mut dependency_ids = std::collections::BTreeSet::new();
    let mut structural_dependencies = std::collections::BTreeSet::new();
    let mut prior_dependency: Option<String> = None;
    for dependency in &payload.dependencies {
        dependency.validate()?;
        if prior_dependency
            .as_deref()
            .is_some_and(|prior| prior >= dependency.dependency_id.as_str())
            || !dependency_ids.insert(dependency.dependency_id.as_str().to_owned())
            || (!selected_events.contains(&dependency.source_revision.revision_event_id)
                && !comparison_pins.contains(&dependency.source_revision.revision_event_id))
            || !structural_dependencies.insert((
                dependency.source_revision.revision_event_id.clone(),
                dependency.semantic_role.clone(),
                serde_json::to_string(&dependency.affected_conclusion)?,
                dependency.reconsideration_trigger.clone(),
            ))
        {
            return Err(Error::engine("invalid or duplicate Receipt dependency"));
        }
        crate::freshness::verify_revision_ref_on(conn, &dependency.source_revision).await?;
        prior_dependency = Some(dependency.dependency_id.as_str().to_owned());
    }

    let mut assessment_keys = std::collections::BTreeSet::new();
    let mut prior_assessment: Option<String> = None;
    for assessment in &payload.assessments {
        assessment.assessment_id.validate()?;
        assessment.dependency_id.validate()?;
        assessment.compared_source_revision.validate()?;
        crate::freshness::validate_assessment_materiality(assessment)?;
        let key = (
            assessment.dependency_id.as_str().to_owned(),
            assessment
                .compared_source_revision
                .revision_event_id
                .clone(),
        );
        if assessment.category.trim().is_empty()
            || assessment.rationale.trim().is_empty()
            || assessment.compared_source_revision.revision_seq
                > payload.history_high_water.content_seq
            || prior_assessment
                .as_deref()
                .is_some_and(|prior| prior >= assessment.assessment_id.as_str())
            || !assessment_keys.insert(key)
        {
            return Err(Error::engine("invalid or duplicate Receipt assessment"));
        }
        crate::freshness::verify_revision_ref_on(conn, &assessment.compared_source_revision)
            .await?;
        prior_assessment = Some(assessment.assessment_id.as_str().to_owned());
    }
    if assessment_keys != comparison_keys {
        return Err(Error::engine(
            "every Receipt comparison requires exactly one task-relative assessment",
        ));
    }

    let mut prior_reconciliation: Option<String> = None;
    for reconciliation in &payload.reconciliations {
        reconciliation.reconciliation_id.validate()?;
        reconciliation.dependency_id.validate()?;
        reconciliation.consumer_revision.validate()?;
        reconciliation.pinned_source_revision.validate()?;
        reconciliation.assessed_source_revision.validate()?;
        if reconciliation.consumer_revision != payload.expected_consumer_revision
            || reconciliation.task_scope != payload.context_request.task_scope
            || reconciliation.rationale.trim().is_empty()
            || prior_reconciliation
                .as_deref()
                .is_some_and(|prior| prior >= reconciliation.reconciliation_id.as_str())
            || !payload.comparisons.iter().any(|comparison| {
                comparison.dependency_id == reconciliation.dependency_id
                    && comparison.pinned_source_revision == reconciliation.pinned_source_revision
                    && comparison.candidate_source_revision
                        == reconciliation.assessed_source_revision
            })
            || !payload.assessments.iter().any(|assessment| {
                assessment.dependency_id == reconciliation.dependency_id
                    && assessment.compared_source_revision
                        == reconciliation.assessed_source_revision
                    && assessment.outcome == reconciliation.outcome
            })
        {
            return Err(Error::engine("invalid aggregate Receipt reconciliation"));
        }
        let debt = sqlx::query(
            "SELECT d.consumer_revision,d.source_revision,d.affected_conclusion
               FROM dependencies d JOIN receipts r ON r.receipt_id=d.receipt_id
              WHERE d.dependency_id=?",
        )
        .bind(reconciliation.dependency_id.as_str())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("aggregate Receipt reconciliation debt is unavailable"))?;
        if serde_json::from_str::<crate::freshness::RevisionRef>(
            &debt.try_get::<String, _>("consumer_revision")?,
        )? != reconciliation.consumer_revision
            || serde_json::from_str::<crate::freshness::RevisionRef>(
                &debt.try_get::<String, _>("source_revision")?,
            )? != reconciliation.pinned_source_revision
            || serde_json::from_str::<crate::freshness::AffectedConclusion>(
                &debt.try_get::<String, _>("affected_conclusion")?,
            )? != reconciliation.affected_conclusion
        {
            return Err(Error::engine(
                "aggregate Receipt reconciliation does not cover the exact dependency debt",
            ));
        }
        prior_reconciliation = Some(reconciliation.reconciliation_id.as_str().to_owned());
    }

    let mut prior_provenance: Option<(String, String, String)> = None;
    for provenance in &payload.provenance {
        provenance.source_revision.validate()?;
        let key = (
            provenance.source_revision.subject_id.clone(),
            provenance.source_revision.revision_event_id.clone(),
            provenance.reason.clone(),
        );
        if provenance.reason.trim().is_empty()
            || !selected_events.contains(&provenance.source_revision.revision_event_id)
            || prior_provenance.as_ref().is_some_and(|prior| prior >= &key)
        {
            return Err(Error::engine("invalid or noncanonical Receipt provenance"));
        }
        crate::freshness::verify_revision_ref_on(conn, &provenance.source_revision).await?;
        prior_provenance = Some(key);
    }

    let mut uncertainty_ids = std::collections::BTreeSet::new();
    for uncertainty in &payload.unresolved_uncertainty {
        uncertainty.uncertainty_id.validate()?;
        uncertainty.dependency_id.validate()?;
        if uncertainty.assessment_task_scope.trim().is_empty()
            || uncertainty.evidence.trim().is_empty()
            || uncertainty.detail.trim().is_empty()
            || !uncertainty_ids.insert(uncertainty.uncertainty_id.as_str().to_owned())
        {
            return Err(Error::engine("invalid Receipt uncertainty lineage"));
        }
        for reference in [
            &uncertainty.consumer_revision,
            &uncertainty.pinned_source_revision,
            &uncertainty.selected_source_revision,
        ] {
            reference.validate()?;
            crate::freshness::verify_revision_ref_on(conn, reference).await?;
        }
        let encoded_lineage = serde_json::to_string(uncertainty)?;
        let carried: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1
               FROM receipt_uncertainty_lineage u
               JOIN receipts r ON r.receipt_id=u.receipt_id
              WHERE u.lineage=? AND r.receipt_event_seq < ?)",
        )
        .bind(&encoded_lineage)
        .bind(event.local_seq)
        .fetch_one(&mut *conn)
        .await?;
        if carried {
            continue;
        }
        let comparison = payload
            .comparisons
            .iter()
            .find(|comparison| {
                comparison.dependency_id == uncertainty.dependency_id
                    && comparison.pinned_source_revision == uncertainty.pinned_source_revision
                    && comparison.candidate_source_revision == uncertainty.selected_source_revision
            })
            .ok_or_else(|| {
                Error::engine("uncertainty lineage does not bind an exact sealed comparison")
            })?;
        let assessment_matches = payload.assessments.iter().any(|assessment| {
            assessment.dependency_id == uncertainty.dependency_id
                && assessment.compared_source_revision == uncertainty.selected_source_revision
                && assessment.outcome == uncertainty.verdict
                && (assessment.outcome == MaterialityOutcome::MateriallyUncertain
                    || (assessment.outcome == MaterialityOutcome::UnableToAssess
                        && assessment.could_materially_change))
        });
        let debt = sqlx::query(
            "SELECT d.consumer_revision,d.source_revision,d.affected_conclusion
               FROM dependencies d JOIN receipts r ON r.receipt_id=d.receipt_id
              WHERE d.dependency_id=? AND d.receipt_id=?",
        )
        .bind(uncertainty.dependency_id.as_str())
        .bind(comparison.receipt_id.as_str())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("uncertainty lineage debt is unavailable"))?;
        if !assessment_matches
            || uncertainty.inherited_from_receipt_id.as_ref() != Some(&comparison.receipt_id)
            || uncertainty.consumer_revision != payload.expected_consumer_revision
            || serde_json::from_str::<crate::freshness::RevisionRef>(
                &debt.try_get::<String, _>("consumer_revision")?,
            )? != uncertainty.consumer_revision
            || serde_json::from_str::<crate::freshness::RevisionRef>(
                &debt.try_get::<String, _>("source_revision")?,
            )? != uncertainty.pinned_source_revision
            || serde_json::from_str::<crate::freshness::AffectedConclusion>(
                &debt.try_get::<String, _>("affected_conclusion")?,
            )? != uncertainty.affected_conclusion
            || uncertainty.assessment_task_scope != payload.context_request.task_scope
        {
            return Err(Error::engine(
                "uncertainty lineage does not bind the exact dependency debt tuple",
            ));
        }
    }
    for assessment in &payload.assessments {
        if (assessment.outcome == MaterialityOutcome::MateriallyUncertain
            || (assessment.outcome == MaterialityOutcome::UnableToAssess
                && assessment.could_materially_change))
            && !payload.unresolved_uncertainty.iter().any(|lineage| {
                lineage.dependency_id == assessment.dependency_id
                    && lineage.selected_source_revision == assessment.compared_source_revision
                    && lineage.verdict == assessment.outcome
            })
        {
            return Err(Error::engine(
                "uncertainty cannot be omitted: material uncertainty requires explicit lineage",
            ));
        }
    }

    let seal = receipt_assembly_sha256(&ReceiptAssemblySeal {
        request: &payload.context_request,
        policy: &payload.resolution_policy,
        requested_source_record_ids: &payload.requested_source_record_ids,
        selected_sources: &payload.selected_sources,
        provenance: &payload.provenance,
        comparisons: &payload.comparisons,
        dependencies: &payload.dependencies,
        assessments: &payload.assessments,
        reconciliations: &payload.reconciliations,
        lineage: &payload.unresolved_uncertainty,
        withheld_context: payload.withheld_context,
        high_water: &payload.history_high_water,
    })?;
    if seal != payload.assembly_sha256 {
        return Err(Error::engine("Receipt assembly seal does not verify"));
    }
    let (execution, disclosure) = crate::freshness::receipt_decisions(
        &payload.resolution_policy,
        &payload.assessments,
        payload.withheld_context,
    );
    if payload.execution != execution || payload.disclosure != disclosure {
        return Err(Error::engine(
            "Receipt execution and disclosure must be derived",
        ));
    }

    sqlx::query(
        "INSERT INTO receipts
           (receipt_id,receipt_event_id,receipt_event_seq,consumer_record_id,
            output_revision_event_id,output_revision,context_request,resolution_policy,
            requested_source_record_ids,selected_sources,history_high_water,
            withheld_context,execution,disclosure,actor,created_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(payload.receipt_id.as_str())
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(&event.record_id)
    .bind(&event.id)
    .bind(serde_json::to_string(&output_revision)?)
    .bind(serde_json::to_string(&payload.context_request)?)
    .bind(serde_json::to_string(&payload.resolution_policy)?)
    .bind(serde_json::to_string(&payload.requested_source_record_ids)?)
    .bind(serde_json::to_string(&payload.selected_sources)?)
    .bind(serde_json::to_string(&payload.history_high_water)?)
    .bind(payload.withheld_context)
    .bind(match payload.execution {
        ExecutionDisposition::Continued => "continued",
        ExecutionDisposition::Stopped => "stopped",
    })
    .bind(match payload.disclosure {
        DisclosureDecision::Silent => "silent",
        DisclosureDecision::ExplainOnInspection => "explain_on_inspection",
        DisclosureDecision::SurfaceNow => "surface_now",
    })
    .bind(event.actor.as_deref().expect("semantic actor checked"))
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;

    for dependency in &payload.dependencies {
        sqlx::query(
            "INSERT INTO dependencies
             (dependency_id,receipt_id,declaration_event_id,declaration_event_seq,
              consumer_record_id,consumer_revision_event_id,consumer_revision,
              source_record_id,source_revision_event_id,source_revision,semantic_role,
              affected_conclusion,rationale,reconsideration_trigger,confidence,actor,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(dependency.dependency_id.as_str())
        .bind(payload.receipt_id.as_str())
        .bind(&event.id)
        .bind(event.local_seq)
        .bind(&event.record_id)
        .bind(&event.id)
        .bind(serde_json::to_string(&output_revision)?)
        .bind(&dependency.source_revision.subject_id)
        .bind(&dependency.source_revision.revision_event_id)
        .bind(serde_json::to_string(&dependency.source_revision)?)
        .bind(&dependency.semantic_role)
        .bind(serde_json::to_string(&dependency.affected_conclusion)?)
        .bind(&dependency.rationale)
        .bind(&dependency.reconsideration_trigger)
        .bind(dependency.confidence)
        .bind(event.actor.as_deref().expect("semantic actor checked"))
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    }
    for assessment in &payload.assessments {
        sqlx::query(
            "INSERT INTO dependency_assessments
             (assessment_id,assessment_event_id,assessment_event_seq,receipt_id,dependency_id,
              compared_source_revision_event_id,compared_source_revision,task_scope,category,
              outcome,could_materially_change,rationale,actor,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(assessment.assessment_id.as_str())
        .bind(&event.id)
        .bind(event.local_seq)
        .bind(payload.receipt_id.as_str())
        .bind(assessment.dependency_id.as_str())
        .bind(&assessment.compared_source_revision.revision_event_id)
        .bind(serde_json::to_string(&assessment.compared_source_revision)?)
        .bind(&payload.context_request.task_scope)
        .bind(&assessment.category)
        .bind(assessment.outcome.as_str())
        .bind(assessment.could_materially_change)
        .bind(&assessment.rationale)
        .bind(event.actor.as_deref().expect("semantic actor checked"))
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    }
    for reconciliation in &payload.reconciliations {
        sqlx::query(
            "INSERT INTO reconciliations
             (reconciliation_id,reconciliation_event_id,reconciliation_event_seq,dependency_id,
              resolving_receipt_id,resolving_output_revision_event_id,
              consumer_revision_event_id,pinned_source_revision_event_id,
              assessed_source_revision_event_id,assessed_source_revision,task_scope,
              affected_conclusion,outcome,rationale,actor,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(reconciliation.reconciliation_id.as_str())
        .bind(&event.id)
        .bind(event.local_seq)
        .bind(reconciliation.dependency_id.as_str())
        .bind(payload.receipt_id.as_str())
        .bind(&event.id)
        .bind(&reconciliation.consumer_revision.revision_event_id)
        .bind(&reconciliation.pinned_source_revision.revision_event_id)
        .bind(&reconciliation.assessed_source_revision.revision_event_id)
        .bind(serde_json::to_string(
            &reconciliation.assessed_source_revision,
        )?)
        .bind(&reconciliation.task_scope)
        .bind(serde_json::to_string(&reconciliation.affected_conclusion)?)
        .bind(reconciliation.outcome.as_str())
        .bind(&reconciliation.rationale)
        .bind(event.actor.as_deref().expect("semantic actor checked"))
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    }
    for (ordinal, provenance) in payload.provenance.iter().enumerate() {
        sqlx::query(
            "INSERT INTO receipt_provenance
             (receipt_id,ordinal,source_record_id,source_revision_event_id,source_revision,reason)
             VALUES(?,?,?,?,?,?)",
        )
        .bind(payload.receipt_id.as_str())
        .bind(ordinal as i64)
        .bind(&provenance.source_revision.subject_id)
        .bind(&provenance.source_revision.revision_event_id)
        .bind(serde_json::to_string(&provenance.source_revision)?)
        .bind(&provenance.reason)
        .execute(&mut *conn)
        .await?;
    }
    for (ordinal, comparison) in payload.comparisons.iter().enumerate() {
        sqlx::query(
            "INSERT INTO receipt_comparisons
             (receipt_id,ordinal,dependency_id,pinned_source_revision_event_id,
              pinned_source_revision,selected_source_revision_event_id,selected_source_revision)
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind(payload.receipt_id.as_str())
        .bind(ordinal as i64)
        .bind(comparison.dependency_id.as_str())
        .bind(&comparison.pinned_source_revision.revision_event_id)
        .bind(serde_json::to_string(&comparison.pinned_source_revision)?)
        .bind(&comparison.candidate_source_revision.revision_event_id)
        .bind(serde_json::to_string(
            &comparison.candidate_source_revision,
        )?)
        .execute(&mut *conn)
        .await?;
    }
    for (ordinal, uncertainty) in payload.unresolved_uncertainty.iter().enumerate() {
        sqlx::query(
            "INSERT INTO receipt_uncertainty_lineage
             (receipt_id,ordinal,uncertainty_id,dependency_id,inherited_from_receipt_id,lineage,detail)
             VALUES(?,?,?,?,?,?,?)",
        )
        .bind(payload.receipt_id.as_str())
        .bind(ordinal as i64)
        .bind(uncertainty.uncertainty_id.as_str())
        .bind(uncertainty.dependency_id.as_str())
        .bind(
            uncertainty
                .inherited_from_receipt_id
                .as_ref()
                .map(|id| id.as_str()),
        )
        .bind(serde_json::to_string(uncertainty)?)
        .bind(&uncertainty.detail)
        .execute(&mut *conn)
        .await?;
    }
    project_runtime_command(
        conn,
        event,
        &payload.command,
        &event.record_id,
        "commit_durable_output",
    )
    .await?;

    let mut body_event = event.clone();
    body_event.event_type = "record.updated".into();
    body_event.payload = Some(serde_json::to_string(&serde_json::json!({
        "body": payload.body
    }))?);
    project_record_updated(conn, &body_event).await
}

pub(super) async fn project_reconciliation_recorded(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    require_semantic_actor(event)?;
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let payload: ReconciliationRecordedPayload = parse_payload(event)?;
    payload.reconciliation_id.validate()?;
    payload.dependency_id.validate()?;
    payload.consumer_revision.validate()?;
    payload.pinned_source_revision.validate()?;
    payload.assessed_source_revision.validate()?;
    if payload.semantic_contract_version != SEMANTIC_CONTRACT_VERSION
        || payload.runtime_contract_version != RUNTIME_CONTRACT_VERSION
        || payload.rationale.trim().is_empty()
        || payload.task_scope.trim().is_empty()
    {
        return Err(Error::engine("invalid reconciliation.recorded.v1 payload"));
    }
    crate::freshness::verify_revision_ref_on(conn, &payload.consumer_revision).await?;
    crate::freshness::verify_revision_ref_on(conn, &payload.pinned_source_revision).await?;
    crate::freshness::verify_revision_ref_on(conn, &payload.assessed_source_revision).await?;
    if payload.finalizing_receipt_id.is_some() {
        return Err(Error::engine(
            "package reconciliation must be embedded in its aggregate Receipt",
        ));
    }
    let dependency = sqlx::query(
        "SELECT d.consumer_record_id,d.consumer_revision,d.source_revision,
                d.affected_conclusion
           FROM dependencies d
          WHERE d.dependency_id=?",
    )
    .bind(payload.dependency_id.as_str())
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("reconciliation dependency is missing"))?;
    if dependency.try_get::<String, _>("consumer_record_id")? != event.record_id
        || serde_json::from_str::<crate::freshness::RevisionRef>(
            &dependency.try_get::<String, _>("consumer_revision")?,
        )? != payload.consumer_revision
        || serde_json::from_str::<crate::freshness::RevisionRef>(
            &dependency.try_get::<String, _>("source_revision")?,
        )? != payload.pinned_source_revision
        || serde_json::from_str::<crate::freshness::AffectedConclusion>(
            &dependency.try_get::<String, _>("affected_conclusion")?,
        )? != payload.affected_conclusion
    {
        return Err(Error::engine(
            "reconciliation does not cover the dependency source",
        ));
    }
    let current_candidate = match payload.pinned_source_revision.subject_kind {
        RevisionSubjectKind::Artefact => {
            let current_id: Option<String> = sqlx::query_scalar(
                "SELECT id FROM content_events
                      WHERE record_id=? AND seq < ? AND type IN ('record.created','record.updated','receipt.committed.v1')
                        AND json_type(payload,'$.body') IS NOT NULL
                      ORDER BY seq DESC LIMIT 1",
            )
            .bind(&payload.pinned_source_revision.subject_id)
            .bind(event.local_seq)
            .fetch_optional(&mut *conn)
            .await?;
            payload.assessed_source_revision.subject_kind == RevisionSubjectKind::Artefact
                && payload.assessed_source_revision.subject_id
                    == payload.pinned_source_revision.subject_id
                && current_id.as_deref()
                    == Some(payload.assessed_source_revision.revision_event_id.as_str())
        }
        RevisionSubjectKind::Unit => {
            payload.assessed_source_revision.subject_kind == RevisionSubjectKind::Unit
                && sqlx::query_scalar::<_, bool>(
                    "WITH RECURSIVE reachable(unit_id,depth) AS (
                        SELECT ?1,0
                        UNION
                        SELECT s.successor_unit_id,r.depth+1 FROM unit_supersessions s
                          JOIN reachable r ON s.predecessor_unit_id=r.unit_id
                         WHERE s.supersession_event_seq < ?2 AND r.depth < 256
                     )
                     SELECT EXISTS(
                        SELECT 1 FROM reachable r JOIN unit_revisions u ON u.unit_id=r.unit_id
                         WHERE u.unit_id=?3 AND u.revision_event_id=?4 AND u.revision_seq < ?2
                           AND NOT EXISTS(
                             SELECT 1 FROM unit_revisions child
                              WHERE child.unit_id=u.unit_id
                                AND child.based_on_revision_event_id=u.revision_event_id
                                AND child.revision_seq < ?2))",
                )
                .bind(&payload.pinned_source_revision.subject_id)
                .bind(event.local_seq)
                .bind(&payload.assessed_source_revision.subject_id)
                .bind(&payload.assessed_source_revision.revision_event_id)
                .fetch_one(&mut *conn)
                .await?
        }
    };
    if !current_candidate || payload.assessed_source_revision == payload.pinned_source_revision {
        return Err(Error::engine(
            "reconciliation must name an exact current reachable source candidate",
        ));
    }
    let assessed_in_scope: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM dependency_assessments
          WHERE dependency_id=? AND compared_source_revision_event_id=? AND task_scope=?)",
    )
    .bind(payload.dependency_id.as_str())
    .bind(&payload.assessed_source_revision.revision_event_id)
    .bind(&payload.task_scope)
    .fetch_one(&mut *conn)
    .await?;
    if !assessed_in_scope {
        return Err(Error::engine(
            "reconciliation must bind an exact prior task-relative assessment",
        ));
    }
    sqlx::query(
        "INSERT INTO reconciliations
           (reconciliation_id,reconciliation_event_id,reconciliation_event_seq,dependency_id,
            resolving_receipt_id,resolving_output_revision_event_id,
            consumer_revision_event_id,pinned_source_revision_event_id,
            assessed_source_revision_event_id,assessed_source_revision,task_scope,
            affected_conclusion,outcome,rationale,actor,created_at)
         VALUES(?,?,?,?,NULL,NULL,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(payload.reconciliation_id.as_str())
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(payload.dependency_id.as_str())
    .bind(&payload.consumer_revision.revision_event_id)
    .bind(&payload.pinned_source_revision.revision_event_id)
    .bind(&payload.assessed_source_revision.revision_event_id)
    .bind(serde_json::to_string(&payload.assessed_source_revision)?)
    .bind(&payload.task_scope)
    .bind(serde_json::to_string(&payload.affected_conclusion)?)
    .bind(payload.outcome.as_str())
    .bind(&payload.rationale)
    .bind(event.actor.as_deref().expect("semantic actor checked"))
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    project_runtime_command(
        conn,
        event,
        payload
            .command
            .as_ref()
            .ok_or_else(|| Error::engine("standalone reconciliation command is missing"))?,
        &event.record_id,
        "reconcile_dependency",
    )
    .await
}

pub(super) async fn project_unit_superseded(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    require_semantic_actor(event)?;
    let payload: UnitSupersededPayload = parse_payload(event)?;
    if payload.semantic_contract_version != SEMANTIC_CONTRACT_VERSION
        || payload.runtime_contract_version != RUNTIME_CONTRACT_VERSION
        || payload.successors.is_empty()
        || payload.rationale.trim().is_empty()
    {
        return Err(Error::engine("invalid unit.superseded.v1 payload"));
    }
    let predecessor_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM semantic_units WHERE unit_id=?)")
            .bind(&event.record_id)
            .fetch_one(&mut *conn)
            .await?;
    if !predecessor_exists {
        return Err(Error::engine("supersession predecessor is not a Unit"));
    }
    let mut prior: Option<String> = None;
    for successor in &payload.successors {
        successor.validate()?;
        if successor.subject_kind != RevisionSubjectKind::Unit
            || successor.source_slot != RevisionSourceSlot::UnitContent
            || successor.subject_id == event.record_id
            || prior
                .as_deref()
                .is_some_and(|value| value >= successor.subject_id.as_str())
        {
            return Err(Error::engine(
                "supersession successors must be distinct canonical Units",
            ));
        }
        prior = Some(successor.subject_id.clone());
        crate::freshness::verify_revision_ref_on(conn, successor).await?;
        let reaches_predecessor_or_limit: bool = sqlx::query_scalar(
            "WITH RECURSIVE walk(unit_id,depth) AS (
                SELECT successor_unit_id,1 FROM unit_supersessions WHERE predecessor_unit_id=?
                UNION
                SELECT s.successor_unit_id,w.depth+1 FROM unit_supersessions s
                  JOIN walk w ON s.predecessor_unit_id=w.unit_id WHERE w.depth < 256
             ) SELECT EXISTS(SELECT 1 FROM walk WHERE unit_id=? OR depth=256)",
        )
        .bind(&successor.subject_id)
        .bind(&event.record_id)
        .fetch_one(&mut *conn)
        .await?;
        if reaches_predecessor_or_limit {
            return Err(Error::engine(
                "Unit supersession would create a cycle or exceed the traversal limit",
            ));
        }
    }
    for (ordinal, successor) in payload.successors.iter().enumerate() {
        sqlx::query(
            "INSERT INTO unit_supersessions
               (supersession_event_id,supersession_event_seq,predecessor_unit_id,ordinal,
                successor_unit_id,successor_revision_event_id,successor_revision,rationale,actor,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(&event.id)
        .bind(event.local_seq)
        .bind(&event.record_id)
        .bind(ordinal as i64)
        .bind(&successor.subject_id)
        .bind(&successor.revision_event_id)
        .bind(serde_json::to_string(successor)?)
        .bind(&payload.rationale)
        .bind(event.actor.as_deref().expect("semantic actor checked"))
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    }
    project_runtime_command(
        conn,
        event,
        &payload.command,
        &event.record_id,
        "supersede_unit",
    )
    .await
}

pub(super) async fn project_receipt_dependency_audited(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    require_semantic_actor(event)?;
    let payload: ReceiptDependencyAuditedPayload = parse_payload(event)?;
    payload.receipt_id.validate()?;
    if let Some(dependency_id) = payload.declared_dependency_id.as_ref() {
        dependency_id.validate()?;
    }
    if let Some(observed) = payload.observed_dependency.as_ref() {
        observed.validate()?;
    }
    let audits_declared = matches!(payload.outcome.as_str(), "confirmed" | "overdeclared");
    if payload.semantic_contract_version != SEMANTIC_CONTRACT_VERSION
        || payload.runtime_contract_version != RUNTIME_CONTRACT_VERSION
        || !matches!(
            payload.outcome.as_str(),
            "confirmed" | "missing" | "overdeclared" | "underdeclared"
        )
        || !matches!(
            (
                audits_declared,
                payload.declared_dependency_id.as_ref(),
                payload.observed_dependency.as_ref(),
            ),
            (true, Some(_), None) | (false, None, Some(_))
        )
        || payload.rationale.trim().is_empty()
    {
        return Err(Error::engine(
            "invalid receipt.dependency_audited.v1 payload",
        ));
    }
    let receipt_consumer: String =
        sqlx::query_scalar("SELECT consumer_record_id FROM receipts WHERE receipt_id=?")
            .bind(payload.receipt_id.as_str())
            .fetch_optional(&mut *conn)
            .await?
            .ok_or_else(|| Error::engine("dependency audit receipt is missing"))?;
    if receipt_consumer != event.record_id {
        return Err(Error::engine("dependency audit envelope mismatch"));
    }
    if let Some(dependency_id) = payload.declared_dependency_id.as_ref() {
        let belongs: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM dependencies WHERE dependency_id=? AND receipt_id=?)",
        )
        .bind(dependency_id.as_str())
        .bind(payload.receipt_id.as_str())
        .fetch_one(&mut *conn)
        .await?;
        if !belongs {
            return Err(Error::engine("declared dependency audit target is missing"));
        }
    }
    if let Some(observed) = payload.observed_dependency.as_ref() {
        let already_declared: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM dependencies
              WHERE receipt_id=?1 AND (
                    dependency_id=?2 OR (
                      source_revision=?3 AND semantic_role=?4
                      AND affected_conclusion=?5 AND reconsideration_trigger=?6)))",
        )
        .bind(payload.receipt_id.as_str())
        .bind(observed.dependency_id.as_str())
        .bind(serde_json::to_string(&observed.source_revision)?)
        .bind(&observed.semantic_role)
        .bind(serde_json::to_string(&observed.affected_conclusion)?)
        .bind(&observed.reconsideration_trigger)
        .fetch_one(&mut *conn)
        .await?;
        if already_declared {
            return Err(Error::engine(
                "observed dependency was already declared by the Receipt",
            ));
        }
        crate::freshness::verify_revision_ref_on(conn, &observed.source_revision).await?;
    }
    sqlx::query(
        "INSERT INTO dependency_audits
           (audit_event_id,audit_event_seq,receipt_id,declared_dependency_id,
            observed_dependency,outcome,rationale,actor,created_at)
         VALUES(?,?,?,?,?,?,?,?,?)",
    )
    .bind(&event.id)
    .bind(event.local_seq)
    .bind(payload.receipt_id.as_str())
    .bind(
        payload
            .declared_dependency_id
            .as_ref()
            .map(|dependency_id| dependency_id.as_str()),
    )
    .bind(
        payload
            .observed_dependency
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?,
    )
    .bind(&payload.outcome)
    .bind(&payload.rationale)
    .bind(event.actor.as_deref().expect("semantic actor checked"))
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    project_runtime_command(
        conn,
        event,
        &payload.command,
        &event.record_id,
        "audit_dependency",
    )
    .await
}
