//! Installed HTML body/title effects. Consent, binding, SQL membership, CAS,
//! mutation and app attribution all use one caller-owned writer transaction.
use super::*;
use crate::mcp::tools::{alpha_tabs, effect_bounds};
use native_artifact_runtime::mdx_v2::{InteractionEffect, SlotDomain};

fn body_summary(value: Option<&str>) -> Value {
    value.map_or_else(|| json!({"kind":"null"}), |text| json!({"kind":"text","sha256":crate::mcp::tools::lifecycle::body_digest(Some(text)),"utf8_bytes":text.len()}))
}

async fn body_target_on(
    conn: &mut sqlx::SqliteConnection,
    actor: &str,
    record: &kernel::KernelRecordView,
) -> Result<bool> {
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(&record.id)
            .fetch_one(&mut *conn)
            .await?;
    let (typ, kind) = super::super::v1_type_and_kind(
        record.family.as_deref(),
        record.pin.as_ref().map(|p| p.version),
        primary.as_deref(),
        record.kind.as_deref(),
        &record.fields,
    );
    if typ != Some("Document")
        || record.id.is_empty()
        || record.id.len() > 128
        || record.id.starts_with("native:")
        || record.id.chars().any(char::is_control)
    {
        return Ok(false);
    }
    if let Some(kind) = kind {
        let canonical = kernel::v1_state::interpreter_on(conn, actor)
            .await?
            .canonical_imported_kind("Document", kind);
        if matches!(canonical.as_str(), "artifact" | "instruction")
            || crate::freshness::reject_reserved_semantic_unit_kind(&canonical, TOOL).is_err()
        {
            return Ok(false);
        }
    }
    let runtime: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_facets WHERE record_id=? AND key='runtime')",
    )
    .bind(&record.id)
    .fetch_one(&mut *conn)
    .await?;
    let instruction:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_instruction_bindings WHERE source_record_id=? AND enabled=1)").bind(&record.id).fetch_one(&mut *conn).await?;
    let sources = kernel::v1_state::rows_on(conn, "onboarding_programme_sources").await?;
    let programmes = kernel::v1_state::rows_on(conn, "onboarding_programmes").await?;
    let programme = sources
        .iter()
        .filter(|source| source["source_record_id"] == record.id)
        .any(|source| {
            programmes.iter().any(|p| {
                p["id"] == source["programme_id"] && (p["enabled"] == true || p["enabled"] == 1)
            })
        });
    Ok(!runtime && !instruction && !programme)
}

pub(super) async fn invoke(
    db: &Db,
    caller: &Caller,
    actor: &str,
    invocation: &ArtifactInvocation,
) -> Result<Value> {
    let guard = invocation
        .alpha_install_guard
        .as_ref()
        .expect("guard dispatch");
    if caller.host_asserted_app().is_some() || kernel::app_installs::dispatched_identity().is_some()
    {
        return Ok(result(
            invocation,
            "alpha_guard_identity_mismatch",
            "declared effects require the installed-app guard surface",
        ));
    }

    let mut tx = begin_write(db.write_pool()).await?;
    let admitted = kernel::app_installs::admit_install_on(
        &mut tx,
        actor,
        &guard.package,
        &guard.expected_install_event_id,
    )
    .await?;
    let declaration: Value = serde_json::from_str(
        admitted.pin["consented_declaration"]
            .as_str()
            .ok_or_else(|| Error::engine("installed declaration unavailable"))?,
    )?;
    kernel::app_installs::declarations::declarative(&declaration)?;
    if guard.artifact_id != invocation.artifact_id
        || guard.version != admitted.version
        || guard.artifact_id != admitted.pin["artifact_id"]
        || guard.source_revision != admitted.pin["source_revision"]
        || guard.digest != admitted.pin["digest"]
        || guard.declaration_digest != admitted.pin["declaration_digest"]
    {
        return Ok(result(
            invocation,
            "alpha_guard_pin_mismatch",
            "installed app pin changed",
        ));
    }
    let Some((_body, digest, source_event_id, bindings, grants, manifest)) =
        authorized_source(&mut tx, actor, invocation).await?
    else {
        return Ok(result(
            invocation,
            "artifact_source_unavailable",
            "verified source unavailable",
        ));
    };
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'")
            .bind(&invocation.artifact_id)
            .fetch_optional(&mut *tx)
            .await?;
    if runtime.as_deref() != Some(crate::artifact_html::RUNTIME_ID)
        || digest != invocation.source_digest
        || source_event_id != guard.source_revision
        || admitted.pin["bundle_sha256"] != digest
    {
        return Ok(result(
            invocation,
            "stale_source_digest",
            "installed HTML source changed",
        ));
    }
    let evidence = match crate::mcp::tools::artifact_interactions::kernel_v2_gesture_evidence(
        caller, invocation,
    ) {
        Ok(evidence) => evidence,
        Err((code, message)) => return Ok(result(invocation, code, message)),
    };
    let Some(entry) = manifest.interaction(&invocation.entry_id) else {
        return Ok(result(
            invocation,
            "unknown_entry",
            "interaction is not declared",
        ));
    };
    let body = entry.effect == InteractionEffect::BodySet;
    if !body && entry.effect != InteractionEffect::TitleSet {
        return Ok(result(
            invocation,
            "alpha_guard_effect_unconsented",
            "effect is not supported by this declaration",
        ));
    }
    let Some((slot, slot_decl)) = entry.slots.iter().next().filter(|_| entry.slots.len() == 1)
    else {
        return Ok(invalid(
            invocation,
            "effect requires exactly one record slot",
        ));
    };
    let SlotDomain::BoundInput { port: Some(port) } = &slot_decl.domain else {
        return Ok(result(
            invocation,
            "named_input_unbound",
            "explicit record port required",
        ));
    };
    if port.is_empty()
        || port == "default"
        || invocation.slots.len() != 1
        || (body && invocation.include_next_plan)
    {
        return Ok(invalid(
            invocation,
            "effect requires one explicit port and fixed envelope",
        ));
    }
    let Some(record_id) = invocation.slots.get(slot) else {
        return Ok(invalid(invocation, "record slot missing"));
    };
    let (need, cap) = if body {
        match effect_bounds::body_admission(&declaration, &entry.id) {
            Ok((bound, need)) => (
                need,
                Some(
                    bound
                        .max_body_bytes
                        .min(entry.body.as_ref().map_or(0, |b| b.max_bytes)),
                ),
            ),
            Err((code, message)) => return Ok(result(invocation, &code, &message)),
        }
    } else {
        match effect_bounds::title_admission(&declaration, &entry.id) {
            Ok((_, need)) => (need, None),
            Err((code, message)) => return Ok(result(invocation, &code, &message)),
        }
    };
    let Some(value) = invocation
        .values
        .get(if body { "body" } else { "title" })
        .and_then(Value::as_str)
    else {
        return Ok(invalid(invocation, "effect value must be text"));
    };
    let expected_body = invocation
        .values
        .get("expected_body_digest")
        .and_then(Value::as_str);
    if (body
        && (invocation.values.len() != 2
            || expected_body.is_none()
            || !invocation.observed.is_empty()))
        || (!body && (invocation.values.len() != 1 || entry.title.is_none()))
    {
        return Ok(invalid(invocation, "unexpected effect envelope"));
    }
    if body
        && expected_body.is_some_and(|digest| {
            digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Ok(result(
            invocation,
            "invalid_digest",
            "body precondition requires a lowercase SHA-256 digest",
        ));
    }
    if cap.is_some_and(|cap| value.len() > cap) {
        return Ok(result(
            invocation,
            "body_too_large",
            "body exceeds the manifest or consent UTF-8 byte cap",
        ));
    }
    if !body && value.trim().is_empty() {
        return Ok(result(invocation, "title_blank", "title must be nonblank"));
    }
    // v1 replay identity is semantic: a refreshed CAS token or gesture
    // never turns an otherwise identical retry into a different command.
    let request_digest = crate::canonical_json::digest_json(&json!({"version":invocation.version,
        "artifact_id":invocation.artifact_id,"entry_id":invocation.entry_id,"source_digest":invocation.source_digest,
        "slots":invocation.slots,"values":invocation.values,"guard":guard}));
    let receipt_key = format!(
        "declared:{}",
        crate::canonical_json::digest_json(&json!([
            invocation.artifact_id,
            invocation.entry_id,
            invocation.idempotency_key
        ]))
    );
    sqlx::query(RECEIPTS).execute(&mut *tx).await?;
    // Static authority precedes replay; mutable membership and CAS follow it.
    if let Some((old,receipt))=sqlx::query_as::<_,(String,String)>("SELECT request_digest,receipt_json FROM kernel_artifact_intent_receipts WHERE principal_id=? AND idempotency_key=?")
        .bind(actor).bind(&receipt_key).fetch_optional(&mut *tx).await? {
        if old!=request_digest { return Ok(result(invocation,"idempotency_conflict","key already names another invocation")); }
        kernel::read_record_on(&mut tx,actor,record_id).await?.ok_or_else(||Error::engine(kernel::HIDDEN_OR_MISSING))?;
        return Ok(serde_json::from_str(&receipt)?);
    }
    let seq: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
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
        &format!("kernel-v2-snapshot:{seq}"),
        seq,
    )
    .await?;
    if !bound
        .records_by_port
        .get(port)
        .is_some_and(|ids| ids.contains(record_id))
    {
        return Ok(result(
            invocation,
            "record_outside_input",
            "target is outside the current bound input",
        ));
    }
    let params = if body {
        Some(json!({"record_id":record_id}))
    } else {
        None
    };
    if (!body && !need.params.is_empty())
        || (body
            && (need.params.len() != 1
                || need.params[0].name != "record_id"
                || need.params[0].param_type != alpha_tabs::SqlParamType::Text
                || !need.params[0].required
                || need.params[0].max_len != 128))
    {
        return Ok(result(
            invocation,
            if body {
                "body_need_parameterized"
            } else {
                "title_need_parameterized"
            },
            "target need has unsupported parameters",
        ));
    }
    let parameters = alpha_tabs::bind_sql_params(&need, params.as_ref()).map_err(Error::engine)?;
    let delivery = super::super::sql::query_sql_on(
        &mut tx,
        actor,
        json!({"sql":need.sql,"parameters":parameters}),
        if body { 2 } else { 200 },
    )
    .await?;
    if delivery["time_dependent"] == true {
        return Ok(result(
            invocation,
            if body {
                "body_need_time_dependent"
            } else {
                "title_need_time_dependent"
            },
            "effect target need must be static",
        ));
    }
    let rows = delivery["rows"]
        .as_array()
        .ok_or_else(|| Error::engine("invalid SQL delivery"))?;
    // v1 titles admit the first 200 delivered rows even if truncated; body
    // replacement requires a complete singleton and exactly one id column.
    let member = if body {
        delivery["truncated"] == false
            && rows.len() == 1
            && delivery["row_count"] == 1
            && delivery["columns"]
                .as_array()
                .is_some_and(|cols| cols.iter().filter(|c| c.as_str() == Some("id")).count() == 1)
            && rows[0]["id"].as_str() == Some(record_id)
    } else {
        rows.iter()
            .take(200)
            .any(|row| row["id"].as_str() == Some(record_id))
    };
    if !member {
        return Ok(result(
            invocation,
            "record_outside_need",
            "target is outside the delivered consented need",
        ));
    }
    let previous = kernel::read_record_on(&mut tx, actor, record_id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    kernel::hq::record_edit(&mut tx, actor, record_id, Some(previous.revision)).await?;
    if !body {
        if let Err(error) = crate::mcp::tools::require_workspace_rename_authority(
            TOOL,
            caller,
            record_id,
            Some(&json!(value)),
        ) {
            return Ok(result(invocation, "permission_denied", &error.to_string()));
        }
    }
    if !body {
        let token = invocation
            .observed
            .get(record_id)
            .and_then(|keys| keys.get("title"));
        let parsed = match token {
            Some(token) => {
                match crate::position::parse_facet_version(&mut tx, caller.counter_footing(), token)
                    .await
                {
                    Ok(parsed) => parsed,
                    Err(error) if crate::position::is_unknown_position(&error) => None,
                    Err(error) => return Err(error),
                }
            }
            None => None,
        };
        let Some(native_artifact_runtime::artifact_intents::FacetVersion::Record { event_seq }) =
            parsed
        else {
            return Ok(result(
                invocation,
                "invalid_precondition",
                "title requires a host-issued record token",
            ));
        };
        let issued: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND seq=?)",
        )
        .bind(record_id)
        .bind(event_seq)
        .fetch_one(&mut *tx)
        .await?;
        if !issued {
            return Ok(result(
                invocation,
                "invalid_precondition",
                "title token was not issued for this record",
            ));
        }
        if event_seq != previous.revision {
            let event_id: String = sqlx::query_scalar("SELECT id FROM content_events WHERE seq=?")
                .bind(previous.revision)
                .fetch_one(&mut *tx)
                .await?;
            return Ok(serde_json::to_value(ArtifactIntentResult::Conflict {
                version: INTENT_RESULT_VERSION.into(),
                idempotency_key: invocation.idempotency_key.clone(),
                error: IntentError::retryable(
                    "title_conflict",
                    "record changed; re-read and retry",
                ),
                current_version: format!("rec:{}", previous.revision),
                conflicting_event_id: event_id,
                competing_actor: None,
                refresh: None,
            })?);
        }
    }
    let current_body: Option<String> = if body {
        if !body_target_on(&mut tx, actor, &previous).await? {
            return Ok(result(invocation,"unsupported_target","body effects require an ordinary Document without runtime or instruction authority"));
        }
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT body FROM kernel_record_bodies WHERE record_id=?",
        )
        .bind(record_id)
        .fetch_optional(&mut *tx)
        .await?
        .flatten()
    } else {
        None
    };
    if body
        && current_body
            .as_ref()
            .is_some_and(|text| text.len() > mdx_v2::BODY_SET_MAX_BODY_BYTES)
    {
        return Ok(result(
            invocation,
            "body_or_inverse_oversize",
            "current body exceeds the effect limit",
        ));
    }
    if body
        && expected_body
            != Some(crate::mcp::tools::lifecycle::body_digest(current_body.as_deref()).as_str())
    {
        return Ok(result(
            invocation,
            "body_digest_conflict",
            "body changed; re-read and retry",
        ));
    }
    let before = if body {
        Some(body_summary(current_body.as_deref()))
    } else {
        previous
            .fields
            .get("title")
            .or_else(|| previous.fields.get("name"))
            .cloned()
    };
    let mut acts = ActAllocation::new();
    let pending = kernel::app_installs::start_declared_app_action_in(
        db,
        &mut tx,
        actor,
        admitted,
        TOOL,
        request_digest.clone(),
        invocation.gesture.clone(),
        &mut acts,
    )
    .await?;
    let mut origin = json!({"artifact_id":invocation.artifact_id,"source_event_id":source_event_id,"source_digest":digest,"entry_id":entry.id,"idempotency_key":invocation.idempotency_key,"effect":if body {"body.set"} else {"title.set"}});
    if let Some(evidence) = evidence {
        origin["gesture_evidence"] = evidence;
    }
    let args = if body {
        json!({"id":record_id,"body_set":value,"if_body_digest":expected_body})
    } else {
        json!({"id":record_id,"name":value})
    };
    let written =
        writes::update_with_origin(db, &mut tx, &mut acts, actor, &args, Some(origin)).await?;
    let attribution =
        kernel::app_installs::finish_app_action_in(db, &mut tx, actor, pending, &mut acts).await?;
    let mut receipt = serde_json::to_value(ArtifactIntentResult::Committed {
        version: INTENT_RESULT_VERSION.into(),
        idempotency_key: invocation.idempotency_key.clone(),
        changes: vec![IntentChange {
            record_id: record_id.clone(),
            key: if body { "body" } else { "name" }.into(),
            before,
            after: Some(if body {
                body_summary(Some(value))
            } else {
                json!(value)
            }),
            version: written["version"].as_str().map(str::to_owned),
        }],
        refresh: None,
    })?;
    if let Some(attribution) = attribution {
        receipt["app_attribution"] = attribution;
    }
    sqlx::query("INSERT INTO kernel_artifact_intent_receipts VALUES(?,?,?,?)")
        .bind(actor)
        .bind(&receipt_key)
        .bind(request_digest)
        .bind(serde_json::to_string(&receipt)?)
        .execute(&mut *tx)
        .await?;
    db.commit_kernel_content(tx).await?;
    Ok(receipt)
}
