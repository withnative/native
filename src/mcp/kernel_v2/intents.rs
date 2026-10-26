//! Exact-source MDX facet interactions on the native kernel.
use super::{artifacts, principal, writes};
use crate::{
    act::ActAllocation,
    authorization::Capability,
    db::{begin_write, Db},
    kernel,
    mcp::registry::{Caller, EngineHandle, EngineKind, ToolRegistry},
    Error, Result,
};
use native_artifact_runtime::{
    artifact_intents::{
        ArtifactIntentResult, ArtifactInvocation, IntentChange, IntentError, INTENT_RESULT_VERSION,
    },
    mdx, mdx_v2,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Sqlite, Transaction};

mod declared;

const TOOL: &str = "invoke_artifact_interaction";
const RECEIPTS: &str = "CREATE TABLE IF NOT EXISTS kernel_artifact_intent_receipts (principal_id TEXT NOT NULL, idempotency_key TEXT NOT NULL, request_digest TEXT NOT NULL, receipt_json TEXT NOT NULL, PRIMARY KEY(principal_id,idempotency_key))";

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.register_engine_handler(
        TOOL,
        EngineKind::KernelV2,
        |engine, caller, arguments| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let actor = principal(&db, &caller).await?;
            invoke(&db, &caller, &actor, arguments).await
        },
    )
}

fn result(invocation: &ArtifactInvocation, code: &str, message: &str) -> Value {
    serde_json::to_value(ArtifactIntentResult::Rejected {
        version: INTENT_RESULT_VERSION.into(),
        idempotency_key: invocation.idempotency_key.clone(),
        error: IntentError::new(code, message),
    })
    .expect("intent result serializes")
}

fn invalid(invocation: &ArtifactInvocation, message: &str) -> Value {
    serde_json::to_value(ArtifactIntentResult::Invalid {
        version: INTENT_RESULT_VERSION.into(),
        idempotency_key: invocation.idempotency_key.clone(),
        error: IntentError::new("invalid_invocation", message),
    })
    .expect("intent result serializes")
}

fn fingerprint(invocation: &ArtifactInvocation) -> Result<String> {
    let mut request = serde_json::to_value(invocation)?;
    request.as_object_mut().unwrap().remove("include_next_plan");
    let mut full = json!({
        "request":request,
        "app":kernel::app_installs::dispatched_identity(),
    });
    full.sort_all_objects();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&full)?)))
}

async fn authorized_source(
    tx: &mut Transaction<'static, Sqlite>,
    actor: &str,
    invocation: &ArtifactInvocation,
) -> Result<
    Option<(
        String,
        String,
        String,
        Vec<Value>,
        Vec<Value>,
        mdx_v2::ArtifactManifest,
    )>,
> {
    let Some(record) = kernel::read_record_on(tx, actor, &invocation.artifact_id).await? else {
        return Err(Error::engine(kernel::HIDDEN_OR_MISSING));
    };
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(&invocation.artifact_id)
            .fetch_one(&mut **tx)
            .await?;
    let kind = crate::v2_standard::v1_compat::v1_type_and_kind(
        record.family.as_deref(),
        record.pin.as_ref().map(|pin| pin.version),
        primary.as_deref(),
        record.kind.as_deref(),
        &record.fields,
    );
    if kind != (Some("Document"), Some("artifact")) {
        return Ok(None);
    }
    let closure: Option<(String, String, String, String, String, i64)> = sqlx::query_as(
        "SELECT source_body,source_sha256,source_event_id,bindings,grants,event_seq FROM kernel_artifact_closures WHERE artifact_id=?",
    )
    .bind(&invocation.artifact_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((body, digest, source_event_id, bindings, grants, activation_seq)) = closure else {
        return Ok(None);
    };
    let current: Option<(String, i64)> =
        sqlx::query_as("SELECT body,event_seq FROM kernel_record_bodies WHERE record_id=?")
            .bind(&invocation.artifact_id)
            .fetch_optional(&mut **tx)
            .await?;
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'")
            .bind(&invocation.artifact_id)
            .fetch_optional(&mut **tx)
            .await?;
    if record.archived
        || kernel::hq::tombstoned_on(tx, &invocation.artifact_id).await?
        || !matches!(
            runtime.as_deref(),
            Some(mdx_v2::RUNTIME_ID | crate::artifact_html::RUNTIME_ID)
        )
        || current
            .as_ref()
            .is_none_or(|(live, seq)| live != &body || *seq > activation_seq)
        || mdx::sha256_hex(body.as_bytes()) != digest
    {
        return Ok(None);
    }
    let manifest = if runtime.as_deref() == Some(crate::artifact_html::RUNTIME_ID) {
        let limit = kernel::artifact_closures::html_limit_on(tx, &invocation.artifact_id).await?;
        match crate::artifact_html::validate_cached_with_limit(&body, limit) {
            Ok(html) => html.interaction_manifest(),
            Err(_) => return Ok(None),
        }
    } else {
        let parsed = match mdx_v2::parse_artifact(&body) {
            Ok(parsed) if parsed.imports.is_empty() => parsed,
            _ => return Ok(None),
        };
        let mdx_v2::Manifest::Artifact(manifest) = parsed.manifest else {
            return Ok(None);
        };
        manifest
    };
    Ok(Some((
        body,
        digest,
        source_event_id,
        serde_json::from_str(&bindings)?,
        serde_json::from_str(&grants)?,
        manifest,
    )))
}

pub(crate) async fn invoke(
    db: &Db,
    caller: &Caller,
    actor: &str,
    arguments: Value,
) -> Result<Value> {
    let invocation: ArtifactInvocation = serde_json::from_value(arguments)
        .map_err(|error| Error::engine(format!("{TOOL}: {error}")))?;
    if let Err(message) = invocation.validate_shape() {
        return Ok(invalid(&invocation, message));
    }
    // Reversal has separate v1 admission and undo semantics; it cannot
    // silently inherit the native effect lane.
    if invocation.reverses.is_some() {
        return Ok(result(
            &invocation,
            "unsupported_on_v2",
            "reversal is unavailable on this deployment",
        ));
    }
    if invocation.alpha_install_guard.is_some() {
        return declared::invoke(db, caller, actor, &invocation).await;
    }
    let mut tx = begin_write(db.write_pool()).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    let Some((_body, digest, source_event_id, bindings, grants, manifest)) =
        authorized_source(&mut tx, actor, &invocation).await?
    else {
        return Ok(result(
            &invocation,
            "artifact_source_unavailable",
            "verified artifact source is unavailable",
        ));
    };
    let gesture_evidence =
        match crate::mcp::tools::artifact_interactions::kernel_v2_gesture_evidence(
            caller,
            &invocation,
        ) {
            Ok(evidence) => evidence,
            Err((code, message)) => return Ok(result(&invocation, code, message)),
        };
    if digest != invocation.source_digest {
        return Ok(result(
            &invocation,
            "stale_source_digest",
            "artifact source changed; render again",
        ));
    }
    let Some(entry) = manifest.interaction(&invocation.entry_id) else {
        return Ok(result(
            &invocation,
            "unknown_entry",
            "artifact does not declare this interaction",
        ));
    };
    let snapshot_seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    let bound = artifacts::bound_inputs_on(
        db,
        &mut tx,
        actor,
        &invocation.artifact_id,
        &source_event_id,
        &manifest,
        &bindings,
        &grants,
        &format!("kernel-v2-snapshot:{snapshot_seq}"),
        snapshot_seq,
    )
    .await?;
    if entry.effect == mdx_v2::InteractionEffect::RecordCreate {
        return create_from_entry(
            db,
            tx,
            actor,
            &invocation,
            entry,
            &bound,
            &source_event_id,
            gesture_evidence,
        )
        .await;
    }
    let Some(port) = artifacts::facet_entry_port(entry) else {
        return Ok(result(
            &invocation,
            "unsupported_on_v2",
            "this interaction effect is unavailable on this deployment",
        ));
    };
    let Some((slot_name, _)) = entry
        .slots
        .iter()
        .find(|(_, declaration)| declaration.domain.is_record())
    else {
        return Ok(invalid(&invocation, "entry has no record operand"));
    };
    let Some(record_id) = invocation.slots.get(slot_name) else {
        return Ok(invalid(&invocation, "record operand is missing"));
    };
    let admitted = match port {
        Some(port) => bound
            .records_by_port
            .get(port)
            .is_some_and(|records| records.contains(record_id)),
        None => bound
            .records_by_port
            .values()
            .any(|records| records.contains(record_id)),
    };
    if !admitted {
        return Ok(result(
            &invocation,
            "outside_bound_input",
            "record is outside the authorized artifact input",
        ));
    }
    if invocation.slots.len() != 1
        || invocation
            .values
            .keys()
            .any(|name| !entry.slots.contains_key(name))
    {
        return Ok(invalid(
            &invocation,
            "interaction fills undeclared operands",
        ));
    }
    let mut resolved_values = std::collections::BTreeMap::new();
    for (name, declaration) in &entry.slots {
        let mdx_v2::SlotDomain::Values { values } = &declaration.domain else {
            continue;
        };
        let value = invocation
            .values
            .get(name)
            .or_else(|| values.first().filter(|_| values.len() == 1));
        let Some(value) = value.filter(|value| values.contains(value)) else {
            return Ok(invalid(
                &invocation,
                "interaction value is outside its declared domain",
            ));
        };
        resolved_values.insert(name, value.clone());
    }
    let after = if entry.effect == mdx_v2::InteractionEffect::FacetUnset {
        None
    } else {
        match entry.value.as_ref() {
            Some(mdx_v2::ValueSource::Literal { value }) => Some(value.clone()),
            Some(mdx_v2::ValueSource::Slot { slot }) => resolved_values.get(slot).cloned(),
            None => None,
        }
    };
    if after.as_ref().is_some_and(|value| !value.is_string())
        || (entry.effect == mdx_v2::InteractionEffect::FacetSet && after.is_none())
    {
        return Ok(result(
            &invocation,
            "unsupported_on_v2",
            "only text facet values are executable on this deployment",
        ));
    }
    kernel::hq::record_edit(&mut tx, actor, record_id, None).await?;
    let observed = invocation
        .observed
        .get(record_id)
        .and_then(|facets| facets.get(&entry.facet));
    if invocation.observed.len() != 1
        || invocation
            .observed
            .get(record_id)
            .is_none_or(|facets| facets.len() != 1)
        || observed.is_none()
    {
        return Ok(invalid(&invocation, "one observed facet token is required"));
    }
    sqlx::query(RECEIPTS).execute(&mut *tx).await?;
    let request_digest = fingerprint(&invocation)?;
    if let Some((old_digest, old_receipt)) = sqlx::query_as::<_, (String, String)>(
        "SELECT request_digest,receipt_json FROM kernel_artifact_intent_receipts WHERE principal_id=? AND idempotency_key=?",
    )
    .bind(actor)
    .bind(&invocation.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        if old_digest != request_digest {
            return Ok(result(
                &invocation,
                "idempotency_conflict",
                "idempotency key was used for a different interaction",
            ));
        }
        return Ok(serde_json::from_str(&old_receipt)?);
    }
    let current = artifacts::facet_token_on(&mut tx, record_id, &entry.facet).await?;
    if observed != Some(&current) {
        let seq = current
            .strip_prefix("obs:")
            .or_else(|| current.strip_prefix("rec:"))
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap_or(0);
        let event_id: Option<String> =
            sqlx::query_scalar("SELECT id FROM content_events WHERE seq=?")
                .bind(seq)
                .fetch_optional(&mut *tx)
                .await?;
        return Ok(serde_json::to_value(ArtifactIntentResult::Conflict {
            version: INTENT_RESULT_VERSION.into(),
            idempotency_key: invocation.idempotency_key,
            error: IntentError::new("facet_conflict", "facet changed since it was read"),
            current_version: current,
            conflicting_event_id: event_id.unwrap_or_else(|| "no-observation".into()),
            competing_actor: None,
            refresh: None,
        })?);
    }
    let before = if entry.facet == "lifecycle" {
        kernel::read_record_on(&mut tx, actor, record_id)
            .await?
            .and_then(|record| record.fields.get("lifecycle").cloned())
            .filter(|value| !value.is_null())
    } else {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT value FROM kernel_facets WHERE record_id=? AND key=?",
        )
        .bind(record_id)
        .bind(&entry.facet)
        .fetch_optional(&mut *tx)
        .await?
        .flatten()
        .map(Value::String)
    };
    let mut acts = ActAllocation::new();
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        TOOL,
        request_digest.clone(),
        invocation.gesture.clone(),
        &mut acts,
    )
    .await?;
    let mut origin = json!({"artifact_id":invocation.artifact_id,
        "source_event_id":source_event_id,"source_digest":invocation.source_digest,
        "entry_id":entry.id,"idempotency_key":invocation.idempotency_key});
    if let Some(evidence) = gesture_evidence {
        origin["gesture_evidence"] = evidence;
    }
    if entry.facet == "lifecycle" {
        writes::update_with_origin(
            db,
            &mut tx,
            &mut acts,
            actor,
            &json!({"id":record_id,"lifecycle":after}),
            Some(origin),
        )
        .await?;
    } else {
        let mut facet_patch = serde_json::Map::new();
        facet_patch.insert(entry.facet.clone(), after.clone().unwrap_or(Value::Null));
        writes::facets_with_origin(
            db,
            &mut tx,
            &mut acts,
            actor,
            record_id,
            Some(&Value::Object(facet_patch)),
            TOOL,
            Some(origin),
        )
        .await?;
    }
    let version = artifacts::facet_token_on(&mut tx, record_id, &entry.facet).await?;
    let attribution =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?;
    let mut receipt = serde_json::to_value(ArtifactIntentResult::Committed {
        version: INTENT_RESULT_VERSION.into(),
        idempotency_key: invocation.idempotency_key.clone(),
        changes: vec![IntentChange {
            record_id: record_id.clone(),
            key: entry.facet.clone(),
            before,
            after,
            version: Some(version),
        }],
        refresh: None,
    })?;
    if let Some(attribution) = attribution {
        receipt["app_attribution"] = attribution;
    }
    sqlx::query("INSERT INTO kernel_artifact_intent_receipts VALUES(?,?,?,?)")
        .bind(actor)
        .bind(&invocation.idempotency_key)
        .bind(request_digest)
        .bind(serde_json::to_string(&receipt)?)
        .execute(&mut *tx)
        .await?;
    db.commit_kernel_content(tx).await?;
    Ok(receipt)
}

fn create_declarations(
    create: &mdx_v2::RecordCreateDecl,
) -> impl Iterator<Item = &mdx_v2::RecordCreateValue> {
    std::iter::once(&create.shape.record_type)
        .chain(std::iter::once(&create.shape.kind))
        .chain(create.shape.fields.values())
        .chain(create.shape.facets.values())
}

fn resolve_created_value(
    declaration: &mdx_v2::RecordCreateValue,
    invocation: &ArtifactInvocation,
    bound: &artifacts::BoundInput,
) -> std::result::Result<Value, &'static str> {
    use mdx_v2::RecordCreateValueSource as Source;
    let value = match &declaration.source {
        Source::Literal { value } => value.clone(),
        Source::Input { input } => invocation
            .values
            .get(input)
            .cloned()
            .ok_or("creation input is missing")?,
        Source::BoundInput { slot } => {
            let id = invocation
                .slots
                .get(slot)
                .ok_or("bound record input is missing")?;
            let mdx_v2::RecordCreateValueDomain::BoundInput { port } = &declaration.domain else {
                return Err("bound record input has an invalid declaration");
            };
            if !bound
                .records_by_port
                .get(port)
                .is_some_and(|records| records.contains(id))
            {
                return Err("record is outside its authorized bound input");
            }
            return Ok(Value::String(id.clone()));
        }
    };
    if !declaration.domain.admits(&value) {
        return Err("creation value is outside its declared domain");
    }
    Ok(value)
}

#[allow(clippy::too_many_arguments)]
async fn create_from_entry(
    db: &Db,
    mut tx: Transaction<'static, Sqlite>,
    actor: &str,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    bound: &artifacts::BoundInput,
    source_event_id: &str,
    gesture_evidence: Option<Value>,
) -> Result<Value> {
    let Some(create) = entry
        .create
        .as_ref()
        .filter(|create| crate::mcp::tools::artifacts::record_create_is_render_supported(create))
    else {
        return Ok(result(
            invocation,
            "unsupported_on_v2",
            "this creation shape is unavailable on this deployment",
        ));
    };
    if !invocation.observed.is_empty() {
        return Ok(invalid(
            invocation,
            "record.create accepts no observed facet tokens",
        ));
    }
    let destination = match &create.destination {
        mdx_v2::RecordCreateDestination::Literal { record_id } => record_id.clone(),
        mdx_v2::RecordCreateDestination::BoundInput { port } => {
            let Some(id) = bound.collections_by_port.get(port) else {
                return Ok(result(
                    invocation,
                    "named_input_unbound",
                    "creation destination is not an authorized bound Collection",
                ));
            };
            id.clone()
        }
    };
    if !artifacts::artifacts_destination_available(&mut tx, actor, &destination).await? {
        return Ok(result(
            invocation,
            "permission_denied",
            "creation destination is unavailable or not editable",
        ));
    }
    let mut declared_values = std::collections::BTreeSet::new();
    let mut declared_slots = std::collections::BTreeSet::new();
    for declaration in create_declarations(create) {
        match &declaration.source {
            mdx_v2::RecordCreateValueSource::Literal { .. } => {}
            mdx_v2::RecordCreateValueSource::Input { input } => {
                declared_values.insert(input.as_str());
            }
            mdx_v2::RecordCreateValueSource::BoundInput { slot } => {
                declared_slots.insert(slot.as_str());
            }
        }
    }
    if invocation
        .values
        .keys()
        .any(|name| !declared_values.contains(name.as_str()))
        || invocation
            .slots
            .keys()
            .any(|name| !declared_slots.contains(name.as_str()))
    {
        return Ok(invalid(invocation, "creation fills an undeclared input"));
    }
    let resolve = |value: &mdx_v2::RecordCreateValue| {
        resolve_created_value(value, invocation, bound)
            .map_err(|message| result(invocation, "value_outside_domain", message))
    };
    let record_type = match resolve(&create.shape.record_type) {
        Ok(value) => value,
        Err(refusal) => return Ok(refusal),
    };
    let kind = match resolve(&create.shape.kind) {
        Ok(value) => value,
        Err(refusal) => return Ok(refusal),
    };
    let (Some(record_type), Some(kind)) = (record_type.as_str(), kind.as_str()) else {
        return Ok(invalid(invocation, "creation type and kind must be text"));
    };
    let mut arguments = json!({
        "type":record_type,"kind":kind,"home_id":destination,
        "reason":format!("Artifact interaction {}", entry.id),
    });
    for (name, declaration) in &create.shape.fields {
        let value = match resolve(declaration) {
            Ok(value) => value,
            Err(refusal) => return Ok(refusal),
        };
        if !value.is_string() {
            return Ok(result(
                invocation,
                "unsupported_on_v2",
                "creation fields must be text on this deployment",
            ));
        }
        arguments[name] = value;
    }
    let mut facets = serde_json::Map::new();
    for (name, declaration) in &create.shape.facets {
        let value = match resolve(declaration) {
            Ok(value) => value,
            Err(refusal) => return Ok(refusal),
        };
        let value = match value {
            Value::String(_) => value,
            Value::Number(number) if number.as_f64().is_some() => {
                json!({"value_num":number})
            }
            _ => {
                return Ok(result(
                    invocation,
                    "unsupported_on_v2",
                    "creation facet value is unavailable on this deployment",
                ));
            }
        };
        facets.insert(name.clone(), value);
    }
    if !facets.is_empty() {
        arguments["facets"] = Value::Object(facets);
    }
    sqlx::query(RECEIPTS).execute(&mut *tx).await?;
    let request_digest = fingerprint(invocation)?;
    if let Some((old_digest, old_receipt)) = sqlx::query_as::<_, (String, String)>(
        "SELECT request_digest,receipt_json FROM kernel_artifact_intent_receipts WHERE principal_id=? AND idempotency_key=?",
    )
    .bind(actor)
    .bind(&invocation.idempotency_key)
    .fetch_optional(&mut *tx)
    .await?
    {
        if old_digest != request_digest {
            return Ok(result(
                invocation,
                "idempotency_conflict",
                "idempotency key was used for a different interaction",
            ));
        }
        let receipt: Value = serde_json::from_str(&old_receipt)?;
        if let Some(id) = receipt["changes"][0]["record_id"].as_str() {
            kernel::kernel_require(&mut tx, actor, id, Capability::View).await?;
        }
        return Ok(receipt);
    }
    let mut acts = ActAllocation::new();
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        actor,
        TOOL,
        request_digest.clone(),
        invocation.gesture.clone(),
        &mut acts,
    )
    .await?;
    let mut origin = json!({
        "artifact_id": invocation.artifact_id,
        "source_event_id": source_event_id,
        "source_digest": invocation.source_digest,
        "entry_id": entry.id,
        "idempotency_key": invocation.idempotency_key,
        "invocation_digest": request_digest,
    });
    if let Some(evidence) = gesture_evidence {
        origin["gesture_evidence"] = evidence;
    }
    let created =
        writes::create_with_origin(db, &mut tx, &mut acts, actor, &arguments, origin).await?;
    let id = created["id"]
        .as_str()
        .ok_or_else(|| Error::engine("create_record returned no record identity"))?;
    let attribution =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?;
    let mut receipt = serde_json::to_value(ArtifactIntentResult::Committed {
        version: INTENT_RESULT_VERSION.into(),
        idempotency_key: invocation.idempotency_key.clone(),
        changes: vec![IntentChange {
            record_id: id.to_owned(),
            key: "record".into(),
            before: None,
            after: Some(json!({"created":true})),
            version: None,
        }],
        refresh: Some(json!({"record":created})),
    })?;
    if let Some(act) = created.get("act") {
        receipt["act"] = act.clone();
    }
    if let Some(attribution) = attribution {
        receipt["app_attribution"] = attribution;
    }
    sqlx::query("INSERT INTO kernel_artifact_intent_receipts VALUES(?,?,?,?)")
        .bind(actor)
        .bind(&invocation.idempotency_key)
        .bind(request_digest)
        .bind(serde_json::to_string(&receipt)?)
        .execute(&mut *tx)
        .await?;
    db.commit_kernel_content(tx).await?;
    Ok(receipt)
}
