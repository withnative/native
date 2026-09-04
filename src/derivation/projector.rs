use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqliteConnection};

use crate::error::{Error, Result};

use super::events::{
    canonical_json, digest_json, CanonicalDerivationRequest, DerivationAttemptFailed,
    DerivationEventRow, DerivationInput, DerivationOutputRef, DerivationRevisionCompleted,
    DerivationSeriesCreated, EffectiveSourceBoundary, RecipeRevisionRef,
    DERIVATION_EVENT_SCHEMA_VERSION, DERIVATION_EVENT_TYPES,
};

fn nonblank(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::engine(format!(
            "derivation event {label} cannot be empty"
        )));
    }
    Ok(())
}

fn object(label: &str, value: &Value) -> Result<()> {
    if !value.is_object() {
        return Err(Error::engine(format!(
            "derivation event {label} must be an object"
        )));
    }
    Ok(())
}

fn digest_text(value: &Value) -> Result<(String, String)> {
    let bytes = canonical_json(value);
    Ok((
        String::from_utf8(bytes.clone()).expect("canonical JSON is UTF-8"),
        hex::encode(Sha256::digest(bytes)),
    ))
}

fn decode<T: DeserializeOwned>(event: &DerivationEventRow) -> Result<T> {
    serde_json::from_str(&event.payload).map_err(|error| {
        Error::engine(format!(
            "derivation event {} ({}) has invalid v{} payload: {error}",
            event.id, event.event_type, event.schema_version
        ))
    })
}

fn normalized_inputs(inputs: &[DerivationInput]) -> Result<Vec<DerivationInput>> {
    let mut values = inputs.to_vec();
    for value in &values {
        nonblank("input portable_id", &value.portable_id)?;
        if !matches!(value.input_role.as_str(), "source" | "context") {
            return Err(Error::engine("derivation event input_role is unknown"));
        }
        if !matches!(
            value.input_kind.as_str(),
            "content_event" | "record_body" | "blob" | "versioned"
        ) {
            return Err(Error::engine("derivation event input_kind is unknown"));
        }
        if value.sha256.len() != 64
            || !value
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(Error::engine("derivation event input sha256 is invalid"));
        }
        object("input metadata", &value.metadata)?;
    }
    values.sort_by(|left, right| {
        (&left.input_role, &left.input_kind, &left.portable_id).cmp(&(
            &right.input_role,
            &right.input_kind,
            &right.portable_id,
        ))
    });
    for pair in values.windows(2) {
        if pair[0].input_role == pair[1].input_role
            && pair[0].input_kind == pair[1].input_kind
            && pair[0].portable_id == pair[1].portable_id
        {
            return Err(Error::engine(
                "derivation event input identity is duplicated",
            ));
        }
    }
    Ok(values)
}

fn manifest(
    request: &CanonicalDerivationRequest,
    recipe: &RecipeRevisionRef,
    boundary: &EffectiveSourceBoundary,
    inputs: &[DerivationInput],
) -> Result<Value> {
    Ok(json!({
        "schema_version": 1,
        "canonical_request": request,
        "recipe_revision": recipe,
        "effective_source_boundary": boundary,
        "inputs": normalized_inputs(inputs)?,
    }))
}

fn request_identity(
    series_id: &str,
    definition_sha256: &str,
    request: &Value,
    recipe: &Value,
    boundary: &Value,
) -> String {
    digest_json(&json!({
        "series_id": series_id,
        "definition_sha256": definition_sha256,
        "canonical_request": request,
        "recipe_revision": recipe,
        "effective_source_boundary": boundary,
    }))
}

fn revision_request_identity(
    series_id: &str,
    definition_sha256: &str,
    request: &Value,
    recipe: &Value,
    boundary: &Value,
    completion_metadata: &Value,
) -> Result<String> {
    if completion_metadata.get("schema").and_then(Value::as_str)
        == Some("native.derivation-completion.v1")
    {
        let key = completion_metadata
            .get("request_key_sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::engine("controlled derivation completion is missing its request key")
            })?;
        sha256_ref("controlled completion request key", key)?;
        return Ok(key.into());
    }
    Ok(request_identity(
        series_id,
        definition_sha256,
        request,
        recipe,
        boundary,
    ))
}

fn sha256_ref(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(Error::engine(format!(
            "derivation event {label} must be lowercase sha256"
        )));
    }
    Ok(())
}

fn validate_request(value: &CanonicalDerivationRequest) -> Result<()> {
    nonblank("query contract", &value.query_contract)?;
    if value.query_contract_version < 1 {
        return Err(Error::engine(
            "derivation event query contract version must be positive",
        ));
    }
    object("request selection", &value.selection)?;
    object("request scope", &value.scope)
}

fn validate_recipe_ref(value: &RecipeRevisionRef) -> Result<()> {
    nonblank("recipe definition id", &value.definition_id)?;
    nonblank("recipe publication id", &value.publication_id)?;
    sha256_ref("recipe publication digest", &value.sha256)
}

fn validate_boundary(value: &EffectiveSourceBoundary) -> Result<()> {
    if value.through_seq < 0
        || value
            .after_seq
            .is_some_and(|after| after < 0 || after > value.through_seq)
    {
        return Err(Error::engine("derivation event source boundary is invalid"));
    }
    sha256_ref(
        "resolved scope membership digest",
        &value.resolved_scope_membership_sha256,
    )?;
    object("source boundary metadata", &value.metadata)
}

fn validate_output_ref(value: &DerivationOutputRef) -> Result<()> {
    if value.output_kind != "content_event" {
        return Err(Error::engine("derivation event output kind is unsupported"));
    }
    nonblank("output event id", &value.event_id)?;
    sha256_ref("output digest", &value.sha256)
}

pub(super) fn validate_event(event: &DerivationEventRow) -> Result<()> {
    for (label, value) in [
        ("id", event.id.as_str()),
        ("idempotency key", event.idempotency_key.as_str()),
        ("aggregate id", event.aggregate_id.as_str()),
        ("actor", event.actor.as_str()),
        ("reason", event.reason.as_str()),
    ] {
        nonblank(label, value)?;
    }
    if event.schema_version != DERIVATION_EVENT_SCHEMA_VERSION {
        return Err(Error::engine(format!(
            "unsupported derivation event schema version {}",
            event.schema_version
        )));
    }
    let expected_kind = match event.event_type.as_str() {
        value if value == DERIVATION_EVENT_TYPES[0] => "derivation_series",
        value if value == DERIVATION_EVENT_TYPES[1] => "derivation_revision",
        value if value == DERIVATION_EVENT_TYPES[2] => "derivation_attempt",
        value if value == DERIVATION_EVENT_TYPES[3] || value == DERIVATION_EVENT_TYPES[4] => {
            "derivation_binding"
        }
        value if value == DERIVATION_EVENT_TYPES[5] => "derivation_publication",
        value if value == DERIVATION_EVENT_TYPES[6] || value == DERIVATION_EVENT_TYPES[7] => {
            "derivation_artifact_role"
        }
        value if value == DERIVATION_EVENT_TYPES[8] || value == DERIVATION_EVENT_TYPES[9] => {
            "derivation_confirmation"
        }
        _ => return Err(Error::engine("unknown derivation event type")),
    };
    if event.aggregate_kind != expected_kind {
        return Err(Error::engine(
            "derivation event aggregate kind does not match type",
        ));
    }
    Ok(())
}

async fn already_applied(conn: &mut SqliteConnection, event: &DerivationEventRow) -> Result<bool> {
    let row = sqlx::query("SELECT event_seq FROM derivation_event_applications WHERE event_id=?")
        .bind(&event.id)
        .fetch_optional(&mut *conn)
        .await?;
    if let Some(row) = row {
        let seq: i64 = row.try_get("event_seq")?;
        if seq != event.seq {
            return Err(Error::engine(
                "derivation application marker sequence mismatch",
            ));
        }
        return Ok(true);
    }
    Ok(false)
}

async fn series_definition_digest(conn: &mut SqliteConnection, series_id: &str) -> Result<String> {
    sqlx::query_scalar("SELECT definition_sha256 FROM derivation_series WHERE id=?")
        .bind(series_id)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("derivation series does not exist"))
}

pub(super) async fn project_event(
    conn: &mut SqliteConnection,
    event: &DerivationEventRow,
) -> Result<()> {
    validate_event(event)?;
    if already_applied(conn, event).await? {
        return Ok(());
    }
    match event.event_type.as_str() {
        "derivation.series.created" => {
            let value: DerivationSeriesCreated = decode(event)?;
            if value.id != event.aggregate_id {
                return Err(Error::engine(
                    "derivation series payload id does not match aggregate",
                ));
            }
            nonblank("series key", &value.series_key)?;
            object("series definition", &value.definition)?;
            let (definition, definition_sha256) = digest_text(&value.definition)?;
            sqlx::query(
                "INSERT INTO derivation_series
                 (id,series_key,definition,definition_sha256,created_event_id,created_event_seq,created_at)
                 VALUES(?,?,?,?,?,?,?)",
            )
            .bind(value.id)
            .bind(value.series_key)
            .bind(definition)
            .bind(definition_sha256)
            .bind(&event.id)
            .bind(event.seq)
            .bind(&event.created_at)
            .execute(&mut *conn)
            .await?;
        }
        "derivation.revision.completed" => {
            let value: DerivationRevisionCompleted = decode(event)?;
            if value.id != event.aggregate_id {
                return Err(Error::engine(
                    "derivation revision payload id does not match aggregate",
                ));
            }
            for (label, item) in [
                ("revision id", value.id.as_str()),
                ("revision series id", value.series_id.as_str()),
            ] {
                nonblank(label, item)?;
            }
            validate_request(&value.canonical_request)?;
            validate_recipe_ref(&value.recipe_revision)?;
            validate_boundary(&value.effective_source_boundary)?;
            validate_output_ref(&value.output_ref)?;
            object("completion metadata", &value.completion_metadata)?;
            let definition_sha256 = series_definition_digest(conn, &value.series_id).await?;
            if let Some(predecessor) = &value.predecessor_revision_id {
                nonblank("predecessor revision id", predecessor)?;
                let predecessor_series: Option<String> =
                    sqlx::query_scalar("SELECT series_id FROM derivation_revisions WHERE id=?")
                        .bind(predecessor)
                        .fetch_optional(&mut *conn)
                        .await?;
                if predecessor_series.as_deref() != Some(value.series_id.as_str()) {
                    return Err(Error::engine(
                        "derivation predecessor must be an existing revision in the same series",
                    ));
                }
            } else {
                let count: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM derivation_revisions WHERE series_id=?",
                )
                .bind(&value.series_id)
                .fetch_one(&mut *conn)
                .await?;
                if count != 0 {
                    return Err(Error::engine(
                        "a non-initial derivation revision requires a predecessor",
                    ));
                }
            }
            let input_values = normalized_inputs(&value.inputs)?;
            let request_value = serde_json::to_value(&value.canonical_request)?;
            let recipe_value = serde_json::to_value(&value.recipe_revision)?;
            let boundary_value = serde_json::to_value(&value.effective_source_boundary)?;
            let output_value = serde_json::to_value(&value.output_ref)?;
            let manifest_value = manifest(
                &value.canonical_request,
                &value.recipe_revision,
                &value.effective_source_boundary,
                &input_values,
            )?;
            let (canonical_request, canonical_request_sha256) = digest_text(&request_value)?;
            let (recipe_revision, recipe_revision_ref_sha256) = digest_text(&recipe_value)?;
            let (effective_source_boundary, effective_source_boundary_sha256) =
                digest_text(&boundary_value)?;
            let (input_manifest, input_manifest_sha256) = digest_text(&manifest_value)?;
            let (output_ref, output_ref_sha256) = digest_text(&output_value)?;
            let (completion_metadata, completion_metadata_sha256) =
                digest_text(&value.completion_metadata)?;
            // Controlled completions use the full durable coordination key,
            // which includes target basis, budget, and audience. Historical
            // generic revisions retain their original five-part identity.
            let request_identity_sha256 = revision_request_identity(
                &value.series_id,
                &definition_sha256,
                &request_value,
                &recipe_value,
                &boundary_value,
                &value.completion_metadata,
            )?;
            sqlx::query(
                "INSERT INTO derivation_revisions
                 (id,series_id,predecessor_revision_id,definition_sha256,canonical_request,
                  canonical_request_sha256,request_identity_sha256,recipe_revision,
                  recipe_revision_ref_sha256,effective_source_boundary,
                  effective_source_boundary_sha256,input_manifest,input_manifest_sha256,
                  output_ref,output_ref_sha256,completion_metadata,completion_metadata_sha256,
                  completed_event_id,completed_event_seq,completed_at)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )
            .bind(&value.id)
            .bind(&value.series_id)
            .bind(&value.predecessor_revision_id)
            .bind(&definition_sha256)
            .bind(canonical_request)
            .bind(canonical_request_sha256)
            .bind(request_identity_sha256)
            .bind(recipe_revision)
            .bind(recipe_revision_ref_sha256)
            .bind(effective_source_boundary)
            .bind(effective_source_boundary_sha256)
            .bind(input_manifest)
            .bind(input_manifest_sha256)
            .bind(output_ref)
            .bind(output_ref_sha256)
            .bind(completion_metadata)
            .bind(completion_metadata_sha256)
            .bind(&event.id)
            .bind(event.seq)
            .bind(&event.created_at)
            .execute(&mut *conn)
            .await?;
            for (ordinal, input) in input_values.into_iter().enumerate() {
                let metadata = String::from_utf8(canonical_json(&input.metadata))
                    .expect("canonical JSON is UTF-8");
                sqlx::query(
                    "INSERT INTO derivation_revision_inputs
                     (revision_id,ordinal,input_role,input_kind,portable_id,sha256,metadata)
                     VALUES(?,?,?,?,?,?,?)",
                )
                .bind(&value.id)
                .bind(ordinal as i64)
                .bind(input.input_role)
                .bind(input.input_kind)
                .bind(input.portable_id)
                .bind(input.sha256)
                .bind(metadata)
                .execute(&mut *conn)
                .await?;
            }
        }
        "derivation.attempt.failed" => {
            let value: DerivationAttemptFailed = decode(event)?;
            if value.id != event.aggregate_id {
                return Err(Error::engine(
                    "derivation attempt payload id does not match aggregate",
                ));
            }
            nonblank("attempt series id", &value.series_id)?;
            nonblank("failure code", &value.failure_code)?;
            if value.attempt_ordinal < 1 {
                return Err(Error::engine("derivation attempt ordinal must be positive"));
            }
            validate_request(&value.canonical_request)?;
            validate_recipe_ref(&value.recipe_revision)?;
            validate_boundary(&value.effective_source_boundary)?;
            object("executor descriptor", &value.executor_descriptor)?;
            object("failure metadata", &value.failure_metadata)?;
            let definition_sha256 = series_definition_digest(conn, &value.series_id).await?;
            let request_value = serde_json::to_value(&value.canonical_request)?;
            let recipe_value = serde_json::to_value(&value.recipe_revision)?;
            let boundary_value = serde_json::to_value(&value.effective_source_boundary)?;
            let (canonical_request, canonical_request_sha256) = digest_text(&request_value)?;
            let (recipe_revision, recipe_revision_ref_sha256) = digest_text(&recipe_value)?;
            let (effective_source_boundary, effective_source_boundary_sha256) =
                digest_text(&boundary_value)?;
            let (executor_descriptor, executor_descriptor_sha256) =
                digest_text(&value.executor_descriptor)?;
            let (failure_metadata, failure_metadata_sha256) = digest_text(&value.failure_metadata)?;
            let request_identity_sha256 = request_identity(
                &value.series_id,
                &definition_sha256,
                &request_value,
                &recipe_value,
                &boundary_value,
            );
            let coordination_request_key_sha256 = value
                .coordination_request_key_sha256
                .unwrap_or_else(|| request_identity_sha256.clone());
            sha256_ref("coordination request key", &coordination_request_key_sha256)?;
            sqlx::query(
                "INSERT INTO derivation_attempts
                 (id,series_id,canonical_request,canonical_request_sha256,recipe_revision,
                  recipe_revision_ref_sha256,effective_source_boundary,
                  effective_source_boundary_sha256,request_identity_sha256,
                  coordination_request_key_sha256,attempt_ordinal,retryable,
                  executor_descriptor,executor_descriptor_sha256,failure_code,failure_metadata,
                  failure_metadata_sha256,failed_event_id,failed_event_seq,failed_at)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )
            .bind(value.id)
            .bind(value.series_id)
            .bind(canonical_request)
            .bind(canonical_request_sha256)
            .bind(recipe_revision)
            .bind(recipe_revision_ref_sha256)
            .bind(effective_source_boundary)
            .bind(effective_source_boundary_sha256)
            .bind(request_identity_sha256)
            .bind(coordination_request_key_sha256)
            .bind(value.attempt_ordinal)
            .bind(value.retryable)
            .bind(executor_descriptor)
            .bind(executor_descriptor_sha256)
            .bind(value.failure_code)
            .bind(failure_metadata)
            .bind(failure_metadata_sha256)
            .bind(&event.id)
            .bind(event.seq)
            .bind(&event.created_at)
            .execute(&mut *conn)
            .await?;
        }
        "derivation.target.bound" => {
            let value: super::bindings::DerivationTargetBound = decode(event)?;
            super::bindings::project_target_bound(conn, event, value).await?;
        }
        "derivation.target.detached" => {
            let value: super::bindings::DerivationTargetDetached = decode(event)?;
            super::bindings::project_target_detached(conn, event, value).await?;
        }
        "derivation.target.published" => {
            let value: super::bindings::DerivationTargetPublished = decode(event)?;
            super::bindings::project_target_published(conn, event, value).await?;
        }
        "derivation.artifact_role.assigned" => {
            let value: super::confirmation::ArtifactRoleAssigned = decode(event)?;
            super::confirmation::project_role_assigned(conn, event, value).await?;
        }
        "derivation.artifact_role.retired" => {
            let value: super::confirmation::ArtifactRoleRetired = decode(event)?;
            super::confirmation::project_role_retired(conn, event, value).await?;
        }
        "derivation.revision.confirmed" => {
            let value: super::confirmation::RevisionConfirmed = decode(event)?;
            super::confirmation::project_revision_confirmed(conn, event, value).await?;
        }
        "derivation.confirmation.retracted" => {
            let value: super::confirmation::ConfirmationRetracted = decode(event)?;
            super::confirmation::project_confirmation_retracted(conn, event, value).await?;
        }
        _ => unreachable!("validated event type"),
    }
    sqlx::query(
        "INSERT INTO derivation_event_applications(event_id,event_seq,applied_at) VALUES(?,?,?)",
    )
    .bind(&event.id)
    .bind(event.seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}
