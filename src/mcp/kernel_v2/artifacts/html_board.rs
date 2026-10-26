//! Ordinary HTML and board rendering. Source authority is a sealed native
//! closure; the HTML sanitizer, injector, CSP and bridge remain the v1 ones.
use super::*;
use crate::mcp::{tools::alpha_tabs::AppBundleDelivery, Caller};
use kernel::artifact_closures::legacy_renders_on;

// Refusals must not mislabel an HTML/board source as MDX. Hidden records
// disclose no runtime at all.
fn refusal(id: &str, code: &str, message: &str) -> Value {
    crate::mcp::tools::artifacts::diagnostic(code, message, json!({"artifact_id":id}))
}

// Payload-free reason: never return the underlying SQL/validator error, which
// may contain private rows or source text.
fn input_failure(error: &Error) -> &'static str {
    let message = error.to_string();
    if message.contains("SQL relation staging exceeded query deadline") {
        return "sql_staging_timeout";
    }
    for category in crate::query::sql_contract::ERROR_CATEGORIES {
        if message.starts_with(&format!("query_sql [{}]", category.as_str())) {
            return category.as_str();
        }
    }
    for (detail, rule) in [
        ("non-canonical typed facet", "typed_facet"),
        ("saved query filter unsupported", "saved_filter"),
        ("saved query order unsupported", "saved_order"),
        ("saved query pipeline unsupported", "saved_pipeline"),
        ("saved traversal unsupported", "saved_traversal"),
        ("governed query pin changed", "query_pin"),
        ("governed input kind changed", "input_kind"),
    ] {
        if message.contains(detail) {
            return rule;
        }
    }
    match error {
        Error::Json(_) => "input_json",
        Error::Sqlx(_) => "input_storage",
        _ => "input_unavailable",
    }
}

struct Source {
    body: String,
    digest: String,
    event_id: String,
    source_seq: i64,
    runtime: String,
    descriptor: Value,
    bindings: Vec<Value>,
    grants: Vec<Value>,
    revision: i64,
    activation: i64,
    limit: usize,
}

async fn source_on(tx: &mut SqliteConnection, actor: &str, id: &str) -> Result<Source> {
    if !kernel::hosted_identity::admitted(tx, actor).await? {
        return Err(Error::auth("artifact caller unavailable"));
    }
    kernel::app_installs::admit_dispatched_on(tx, actor).await?;
    let record = kernel::read_record_on(tx, actor, id)
        .await?
        .ok_or_else(|| Error::engine("artifact unavailable"))?;
    if kernel::hq::tombstoned_on(tx, id).await? {
        return Err(Error::engine("artifact unavailable"));
    }
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if !kernel::artifact_closures::is_artifact_kind_on(
        &mut *tx,
        crate::v2_standard::v1_compat::v1_type_and_kind(
            record.family.as_deref(),
            record.pin.as_ref().map(|p| p.version),
            primary.as_deref(),
            record.kind.as_deref(),
            &record.fields,
        ),
    )
    .await?
    {
        return Err(Error::engine("artifact unavailable"));
    }
    let (body,digest,event_id,descriptor,bindings,grants,activation): (String,String,String,String,String,String,i64) =
        sqlx::query_as("SELECT source_body,source_sha256,source_event_id,descriptor,bindings,grants,event_seq FROM kernel_artifact_closures WHERE artifact_id=?")
        .bind(id).fetch_optional(&mut *tx).await?.ok_or_else(|| Error::engine("frozen artifact closure unavailable"))?;
    let descriptor: Value = serde_json::from_str(&descriptor)?;
    let runtime: String =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    let current: Option<(String, i64)> =
        sqlx::query_as("SELECT body,event_seq FROM kernel_record_bodies WHERE record_id=?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if descriptor["runtime"] != runtime
        || descriptor["source_event_id"] != event_id
        || descriptor["source_sha256"] != digest
        || mdx::sha256_hex(body.as_bytes()) != digest
        || current
            .as_ref()
            .is_none_or(|(text, seq)| text != &body || *seq > activation)
    {
        return Err(Error::engine("frozen artifact source changed"));
    }
    let source_seq:i64=sqlx::query_scalar("SELECT seq FROM kernel_legacy_sql_events WHERE source_stream='content_events' AND source_id=? AND record_id=?")
        .bind(&event_id).bind(id).fetch_one(&mut *tx).await?;
    // v1's ordinary render_artifact path uses validate_cached's ceiling.
    // Installed app preview/launch has its own larger package-source lane.
    let limit = crate::artifact_html::BODY_LIMIT;
    Ok(Source {
        body,
        digest,
        event_id,
        source_seq,
        runtime,
        descriptor,
        bindings: serde_json::from_str(&bindings)?,
        grants: serde_json::from_str(&grants)?,
        revision: record.revision,
        activation,
        limit,
    })
}

/// Called after fresh H2/H3 admission, inside delivery's retained read snapshot.
/// No install/preview fallback exists, including for cached compiled bytes.
pub(crate) async fn bundle_source_on(
    tx: &mut SqliteConnection,
    actor: &str,
    id: &str,
    digest: &str,
) -> Result<(String, usize)> {
    let source = source_on(tx, actor, id).await?;
    if source.runtime != crate::artifact_html::RUNTIME_ID || source.digest != digest {
        return Err(Error::engine("artifact render pin mismatch"));
    }
    let manifest = crate::artifact_html::validate_cached_with_limit(&source.body, source.limit)
        .map_err(|_| Error::engine("artifact HTML validation refused"))?;
    manifest
        .require_available_kit()
        .map_err(|_| Error::engine("artifact kit unavailable"))?;
    Ok((source.body, source.limit))
}

async fn legacy_input_on(
    tx: &mut SqliteConnection,
    actor: &str,
    id: &str,
    source: &Source,
) -> Result<Value> {
    let targets = legacy_renders_on(tx, id).await?;
    if json!(targets) != source.descriptor["_kernel_legacy_renders"] || targets.len() > 1 {
        return Err(Error::engine("frozen renders binding changed"));
    }
    let (mode, collection, records) = if let Some(target) = targets.first() {
        let kind = collection_kind_on(tx, actor, target)
            .await?
            .ok_or_else(|| Error::engine("artifact binding unavailable"))?;
        let schema = authorized_schema_on(tx, actor).await?;
        let interpreter = kernel::v1_state::interpreter_on(tx, actor).await?;
        let records = collection_records_on(
            tx,
            actor,
            target,
            &kind,
            &schema,
            &interpreter,
            InputLimits::HTML,
        )
        .await?;
        ("bound", json!({"id":target,"kind":kind}), records)
    } else {
        ("standalone", Value::Null, Vec::new())
    };
    Ok(
        json!({"version":"native.artifact-input.v1","mode":mode,"collection":collection,"records":records}),
    )
}

async fn html_input_on(
    db: &Db,
    tx: &mut SqliteConnection,
    actor: &str,
    id: &str,
    source: &Source,
    manifest: &crate::artifact_html::Manifest,
    seq: i64,
) -> Result<(Value, Value, Value, Value)> {
    if !manifest.named_inputs_declared {
        return Ok((
            legacy_input_on(tx, actor, id, source).await?,
            Value::Null,
            json!({}),
            Value::Null,
        ));
    }
    if !legacy_renders_on(tx, id).await?.is_empty() {
        return Err(Error::engine("named HTML cannot also have a renders edge"));
    }
    let declaration = manifest.interaction_manifest();
    let bound = bound_inputs_on(
        db,
        tx,
        actor,
        id,
        &source.event_id,
        &declaration,
        &source.bindings,
        &source.grants,
        &format!("kernel-v2-snapshot:{seq}"),
        seq,
    )
    .await?;
    let (observed, availability) =
        interaction_plan_on(tx, actor, &declaration.interactions, &bound, true).await?;
    let schema = authorized_schema_on(tx, actor).await?;
    let meta: Vec<_> = schema.iter().map(|row| json!({"id":row.id,"layer":row.layer,"data":row.data,
        "applies_to_collection_id":row.applies_to_collection_id,"version_lineage":row.version_lineage})).collect();
    let receipt = crate::mcp::tools::artifacts::named_input_bundle_receipt(
        &bound.runtime_input,
        &format!("kernel-v2-snapshot:{seq}"),
        seq,
        seq,
        &mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&json!(meta))),
    );
    Ok((bound.runtime_input, receipt, json!(observed), availability))
}

pub(crate) async fn try_render(
    db: &Db,
    caller: &Caller,
    actor: &str,
    arguments: &Value,
    delivery: Option<&AppBundleDelivery>,
) -> Result<Option<Value>> {
    try_render_inner(db, caller, actor, arguments, delivery, false).await
}

/// Source/input/compiler parity without minting an authenticated browser URL.
/// Used only by the local staging probe on its disposable target copy.
pub(crate) async fn try_render_for_cutover(
    db: &Db,
    caller: &Caller,
    actor: &str,
    arguments: &Value,
) -> Result<Option<Value>> {
    try_render_inner(db, caller, actor, arguments, None, true).await
}

async fn try_render_inner(
    db: &Db,
    caller: &Caller,
    actor: &str,
    arguments: &Value,
    delivery: Option<&AppBundleDelivery>,
    semantic_only: bool,
) -> Result<Option<Value>> {
    let args: Args = parse("render_artifact", arguments.clone())?;
    let mut tx = db.pool().begin().await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    // Speculative routing never discloses an unreadable record's runtime.
    if kernel::read_record_on(&mut tx, actor, &args.id)
        .await?
        .is_none()
    {
        return Ok(Some(refusal(
            &args.id,
            "artifact_unavailable",
            "artifact is unavailable",
        )));
    }
    if args.as_of.is_none() {
        if let Some(outcome) =
            kernel::artifact_closures::exclusion_outcome_on(&mut tx, actor, &args.id).await?
        {
            return Ok(Some(outcome));
        }
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'")
            .bind(&args.id)
            .fetch_optional(&mut *tx)
            .await?;
    let html = runtime.as_deref() == Some(crate::artifact_html::RUNTIME_ID);
    if !html && runtime.as_deref() != Some("native.board.v1") {
        return Ok(None);
    }
    if args.as_of.is_some() {
        return Err(Error::engine(
            "render_artifact: only the frozen live source is activated",
        ));
    }
    if !html && args.parent_origin.is_some() {
        return Err(Error::engine(
            "render_artifact: parent_origin is only supported for native.html.v1",
        ));
    }
    let source = match source_on(&mut tx, actor, &args.id).await {
        Ok(source) => source,
        Err(_) => {
            return Ok(Some(refusal(
                &args.id,
                "artifact_source_unavailable",
                "frozen artifact is unavailable",
            )))
        }
    };
    let seq: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    let manifest = if html {
        match crate::artifact_html::validate_cached_with_limit(&source.body, source.limit) {
            Ok(manifest) => Some(manifest),
            Err(failure) => {
                return Ok(Some(crate::mcp::tools::artifacts::diagnostic(
                    failure.code,
                    failure.message,
                    failure.details,
                )))
            }
        }
    } else {
        None
    };
    let input = if let Some(manifest) = &manifest {
        html_input_on(db, &mut tx, actor, &args.id, &source, manifest, seq).await
    } else {
        legacy_input_on(&mut tx, actor, &args.id, &source)
            .await
            .map(|input| (input, Value::Null, json!({}), Value::Null))
    };
    let (input, bundle, observed, availability) = match input {
        Ok(input) => input,
        Err(error) => {
            let mut diagnostic = refusal(
                &args.id,
                if error.to_string().contains("required input missing")
                    || error.to_string().contains("root input missing")
                {
                    "named_input_missing"
                } else if error
                    .to_string()
                    .contains("exact source capability grant missing")
                {
                    "module_capability_denied"
                } else if error.to_string().contains("exceeds byte limit")
                    || error.to_string().contains("exceeds record limit")
                    || error
                        .to_string()
                        .contains("governed input exceeds size limit")
                {
                    "html_input_too_large"
                } else {
                    "named_input_unavailable"
                },
                "an authorized artifact input is unavailable",
            );
            diagnostic["diagnostic"]["details"]["input_failure"] = json!(input_failure(&error));
            return Ok(Some(diagnostic));
        }
    };
    let input_bytes = if let Some(manifest) = &manifest {
        if manifest.named_inputs_declared {
            if let Some(path) =
                crate::mcp::tools::artifacts::named_html_input_unsafe_integer_path(&input)
            {
                return Ok(Some(crate::mcp::tools::artifacts::diagnostic(
                    "html_named_input_unsafe_integer",
                    "named HTML input contains an integer outside JavaScript's safe range",
                    json!({"artifact_id":args.id,"runtime":source.runtime,"path":path,
                        "safe_integer_min":crate::artifact_html::NAMED_INPUT_SAFE_INTEGER_MIN,
                        "safe_integer_max":crate::artifact_html::NAMED_INPUT_SAFE_INTEGER_MAX}),
                )));
            }
            crate::mcp::tools::artifacts::named_html_input_digest_bytes(&input)
        } else {
            if input["records"]
                .as_array()
                .is_some_and(|rows| rows.len() > crate::artifact_html::INPUT_RECORD_LIMIT)
            {
                return Ok(Some(refusal(
                    &args.id,
                    "html_input_too_large",
                    "artifact input exceeds the HTML record limit",
                )));
            }
            serde_json::to_vec(&input)?
        }
    } else {
        Vec::new()
    };
    if html
        && (input_bytes.len() > crate::artifact_html::INPUT_JSON_LIMIT
            || input_bytes.len() > crate::artifact_html::BRIDGE_MESSAGE_LIMIT)
    {
        return Ok(Some(refusal(
            &args.id,
            "html_input_too_large",
            "artifact input exceeds the HTML bridge limit",
        )));
    }
    let expected = comparable_input(&input);
    tx.rollback().await?;
    #[cfg(test)]
    if let Ok((captured, resume)) = RENDER_PAUSE.try_with(Clone::clone) {
        captured.notify_one();
        resume.notified().await;
    }
    let mut plan = if let Some(manifest) = &manifest {
        json!({"kind":"isolated_html","profile":manifest.profile.as_str(),"body_digest":source.digest,
            "slides":manifest.slides,"interactions":manifest.interactions,"observed":observed,
            "interaction_availability":availability})
    } else {
        match crate::mcp::tools::artifacts::render_board_compat(
            &source.body,
            if input["mode"] == "bound" {
                "bound"
            } else {
                "standalone"
            },
            input.get("collection").filter(|v| !v.is_null()).cloned(),
            input["records"].as_array().cloned().unwrap_or_default(),
        ) {
            Ok(plan) => plan,
            Err(mut diagnostic) => {
                // Match v1's render failure context, not just the adapter error.
                if let Some(details) = diagnostic
                    .pointer_mut("/diagnostic/details")
                    .and_then(Value::as_object_mut)
                {
                    details.insert("artifact_id".into(), json!(args.id));
                    details.insert("runtime".into(), json!(source.runtime));
                    details.insert("mode".into(), input["mode"].clone());
                }
                return Ok(Some(diagnostic));
            }
        }
    };
    let mut fresh = db.pool().begin().await?;
    let live = source_on(&mut fresh, actor, &args.id).await;
    if live.as_ref().map_or(true, |s| {
        s.digest != source.digest
            || s.event_id != source.event_id
            || s.revision != source.revision
            || s.activation != source.activation
    }) {
        return Ok(Some(refusal(
            &args.id,
            "artifact_unavailable",
            "artifact is unavailable",
        )));
    }
    let fresh_input = if let Some(manifest) = &manifest {
        html_input_on(db, &mut fresh, actor, &args.id, &source, manifest, seq)
            .await
            .map(|x| x.0)
    } else {
        legacy_input_on(&mut fresh, actor, &args.id, &source).await
    };
    if fresh_input.map_or(true, |input| comparable_input(&input) != expected) {
        return Ok(Some(refusal(
            &args.id,
            "artifact_snapshot_changed",
            "artifact inputs changed while rendering; retry",
        )));
    }
    fresh.rollback().await?;
    let descriptor = if html {
        crate::artifact_html::descriptor()
    } else {
        crate::mcp::tools::artifacts::board_descriptor_compat()
    };
    let descriptor = crate::mcp::tools::artifacts::with_verification(descriptor, &source.runtime);
    let mut result = json!({"status":"rendered","artifact_id":args.id,"runtime":descriptor,
        "input":if html {input.clone()} else {json!({"version":"native.artifact-input.v1","mode":input["mode"],"collection":input["collection"]})}});
    if let Some(manifest) = manifest {
        manifest
            .require_available_kit()
            .map_err(|_| Error::engine("artifact kit unavailable"))?;
        if semantic_only {
            return Ok(Some(result));
        }
        let now = u64::try_from(chrono::Utc::now().timestamp())
            .map_err(|_| Error::engine("artifact launch clock unavailable"))?;
        let Some(launch) = delivery.and_then(|d| {
            d.artifact_launch(
                caller,
                &args.id,
                &source.digest,
                args.parent_origin.as_deref(),
                now,
            )
        }) else {
            return Ok(Some(refusal(
                &args.id,
                "html_delivery_failed",
                "authenticated artifact delivery is unavailable",
            )));
        };
        let digest = hex::encode(Sha256::digest(&input_bytes));
        result["input_digest"] = json!(digest);
        result["launch"] = launch;
        if !bundle.is_null() {
            plan["input_bundle"] = bundle.clone();
            plan["provenance"] = json!({"record_id":args.id,"source_event_id":source.event_id,
                "source_event_seq":source.source_seq,"snapshot_event_id":format!("kernel-v2-snapshot:{seq}"),"snapshot_event_seq":seq,
                "body_sha256":source.digest,"input_digest":digest,"input_bundle":bundle});
            result["source_event_id"] = json!(source.event_id);
            result["source_event_seq"] = json!(source.source_seq);
            result["snapshot_event_id"] = json!(format!("kernel-v2-snapshot:{seq}"));
            result["snapshot_event_seq"] = json!(seq);
        }
        if let Some(findings) = source
            .descriptor
            .get("write_diagnostics")
            .filter(|v| v.as_array().is_some_and(|a| !a.is_empty()))
        {
            result["write_diagnostics"] = findings.clone();
        }
    }
    result["plan"] = plan;
    Ok(Some(
        crate::mcp::tools::artifacts::attach_empty_timing_if_requested(result, args.include_timing),
    ))
}
