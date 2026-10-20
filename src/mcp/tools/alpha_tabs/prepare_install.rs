//! Read-only preparation of a current source pin. No receipt, consent or lock.
use super::*;

const FINDINGS_MAX: usize = 8;
const MESSAGE_MAX: usize = 512;
// Bound the declaration echoed in next_call; legacy admission has entry limits
// but no total serialized-byte limit.
const DECLARATION_MAX_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Args {
    pub artifact_id: String,
    pub package: String,
    pub version: String,
    pub declaration: Value,
    pub reason: String,
    pub request: Option<String>,
    pub expected_body_digest: Option<String>,
    pub expected_source_revision: Option<String>,
}

fn finding(code: &str, severity: &str, message: &str) -> Value {
    json!({"code": code, "severity": severity,
        "message": message.chars().take(MESSAGE_MAX).collect::<String>()})
}

fn invalid(code: &str, message: &str) -> Value {
    json!({"ready": false, "next_call": null,
        "findings": [finding(code, "error", message)], "findings_truncated": false})
}

fn digest_refusal(manifest_digest: &str, bundle_digest: &str) -> Option<Value> {
    (manifest_digest != bundle_digest).then(|| {
        invalid(
            "digest_mismatch",
            "Validated body digest differs from bundle digest",
        )
    })
}

pub(super) async fn prepare(db: &Db, caller: &Caller, args: Args) -> Result<Value> {
    require_package(&args.package)?;
    require_version(&args.version)?;
    require_reason(TOOL, &args.reason)?;
    let request = require_request(args.request)?;
    let account_id = require_account(caller)?;
    if args.artifact_id.trim().is_empty()
        || (args.expected_body_digest.is_none() && args.expected_source_revision.is_none())
        || args
            .expected_body_digest
            .as_ref()
            .is_some_and(|guard| guard.len() != 64 || !guard.bytes().all(|b| b.is_ascii_hexdigit()))
        || args
            .expected_source_revision
            .as_ref()
            .is_some_and(|guard| guard.trim().is_empty() || guard.len() > 256)
    {
        return Err(Error::engine(format!(
            "{TOOL}: prepare_install requires artifact_id and a body digest or source revision [invalid_source_guard]"
        )));
    }

    // All source, authority and install-state reads share one snapshot. Rollback
    // makes the lack of durable effects explicit, including on the success path.
    let mut tx = db.pool().begin().await?;
    super::super::require_record_in(&mut tx, caller, TOOL, &args.artifact_id, Capability::View)
        .await?;
    let target = target_state_in(&mut tx, &args.artifact_id).await?;
    if target != TargetState::Resolvable {
        return Ok(invalid("invalid_target", target_state_name(target)));
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&args.artifact_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    if runtime.as_deref() != Some("native.html.v1") {
        return Ok(invalid(
            "runtime_mismatch",
            "Source must use native.html.v1",
        ));
    }
    // Select the latest body writer, including clears/non-text bodies. The
    // classification fallback `latest_guarded_text_on` would skip those and
    // prepare a superseded source. Metadata-only writes do not move this pin.
    let source_revision: Option<String> = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE record_id=?
         AND type IN ('record.created','record.updated','receipt.committed.v1')
         AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
    )
    .bind(&args.artifact_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(source_revision) = source_revision else {
        return Ok(invalid(
            "source_revision_unresolved",
            "No body-carrying source revision",
        ));
    };
    let source = crate::record_body::pinned::exact_source_on(
        &mut *tx,
        &source_revision,
        crate::record_body::pinned::ExactSourcePolicy::AnyEvent,
    )
    .await?
    .ok_or_else(|| Error::engine("source disappeared within preparation snapshot"))?;
    if source.try_get::<Option<String>, _>("body_type")?.as_deref() != Some("text") {
        return Ok(invalid(
            "source_revision_unresolved",
            "Current source has no text body",
        ));
    }
    let body: String = source.try_get("body")?;
    let bundle_sha256 = alpha_tab_bundle_digest(&body);
    if args
        .expected_body_digest
        .as_ref()
        .is_some_and(|guard| !guard.eq_ignore_ascii_case(&bundle_sha256))
        || args
            .expected_source_revision
            .as_ref()
            .is_some_and(|guard| guard != &source_revision)
    {
        return Ok(invalid(
            "source_changed",
            "Read the current source and prepare again",
        ));
    }
    if serde_json::to_vec(&args.declaration)?.len() > DECLARATION_MAX_BYTES {
        return Ok(invalid(
            "invalid_declaration",
            "Preparation declaration exceeds 65536 serialized JSON bytes",
        ));
    }
    if let Err(error) = require_declaration(&args.declaration) {
        return Ok(invalid("invalid_declaration", &error.to_string()));
    }
    let declaration_digest = match alpha_tab_declaration_digest(&args.declaration) {
        Ok(digest) => digest,
        Err(error) => return Ok(invalid("invalid_declaration", &error.to_string())),
    };
    let body_limit =
        super::super::artifacts::html_body_limit_in(&mut tx, &args.artifact_id).await?;
    let manifest = match crate::artifact_html::validate_cached_with_limit(&body, body_limit) {
        Ok(manifest) => manifest,
        Err(failure) => return Ok(invalid(failure.code, &failure.message)),
    };
    let digest = alpha_tab_digest(&bundle_sha256, &declaration_digest, "native.html.v1");
    if let Some(refusal) = digest_refusal(&manifest.body_digest, &bundle_sha256) {
        return Ok(refusal);
    }
    let current = install_row_in(&mut tx, &account_id, &args.package).await?;
    let update = current.as_ref().is_some_and(|row| row.status != "removed");
    if update
        && request
            .as_ref()
            .is_some_and(|value| current.as_ref().unwrap().request.as_ref() != Some(value))
    {
        return Ok(invalid(
            "invalid_request",
            "Update must preserve the install request",
        ));
    }
    let adoption = if update
        && crate::control::alpha_tab_provenance::prepare_update_adoption_in(
            &mut tx,
            &account_id,
            &args.package,
            &declaration_digest,
        )
        .await?
    {
        "carried"
    } else {
        "requires_person_preview_adopt"
    };
    let current_install_event_id = current.as_ref().map(|row| row.event_id.clone());
    let mut arguments = json!({"package": args.package, "version": args.version,
        "artifact_id": args.artifact_id, "source_revision": source_revision,
        "declaration": args.declaration, "digest": digest, "reason": args.reason});
    if let Some(event) = &current_install_event_id {
        arguments["expected_install_event_id"] = json!(event);
    }
    if let Some(request) = request {
        arguments["request"] = json!(request);
    }
    let mut findings: Vec<Value> = manifest
        .diagnostics
        .iter()
        .take(FINDINGS_MAX)
        .map(|d| finding(d.code, d.severity, &d.message))
        .collect();
    let availability = manifest.require_available_kit();
    if let Err(failure) = &availability {
        findings.insert(0, finding(failure.code, "warning", &failure.message));
    }
    let findings_truncated =
        manifest.diagnostics.len() + usize::from(availability.is_err()) > FINDINGS_MAX;
    findings.truncate(FINDINGS_MAX);
    let result = json!({"ready": true, "artifact_id": args.artifact_id,
        "source_revision": source_revision, "source_bytes": body.len(),
        "runtime": "native.html.v1", "digest_version": ALPHA_TAB_DIGEST_VERSION,
        "bundle_sha256": bundle_sha256, "declaration_digest": declaration_digest, "digest": digest,
        "current_install_event_id": current_install_event_id,
        "current_install_status": current.as_ref().map(|row| row.status.as_str()),
        "adoption": adoption,
        "kit": {"policy": manifest.kit_policy, "available": availability.is_ok(),
            "basis": "packaged_default", "delivery_rechecks": true},
        "findings": findings, "findings_truncated": findings_truncated,
        "next_call": {"executor": "artifacts_write",
            "operation": if update {"manage_alpha_tabs.update"} else {"manage_alpha_tabs.install"},
            "arguments": arguments}});
    tx.rollback().await?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_install_refuses_manifest_digest_mismatch() {
        assert!(digest_refusal("same", "same").is_none());
        let refusal = digest_refusal("manifest", "bundle").unwrap();
        assert_eq!(refusal["ready"], false);
        assert_eq!(refusal["findings"][0]["code"], "digest_mismatch");
        assert!(refusal["next_call"].is_null());
    }
}
