//! Frozen imported content staging. This module grants no ingress authority:
//! the local operator must hold the same freeze, import and receipt guards as
//! installed-app activation before constructing these proofs.
use super::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub struct Plan {
    artifacts: Vec<artifact_closures::VerifiedArtifactClosure>,
    canvases: Vec<canvas_v2::VerifiedFrozenCanvas>,
    exclusions: Vec<artifact_closures::FrozenExclusion>,
    pub summary: Value,
    pub already_active: bool,
    expected: Vec<(String, String, Option<String>)>,
}

fn refusal(class: &str, count: usize) -> Error {
    Error::engine(format!(
        "imported content refused; class={class} count={count}"
    ))
}

/// All reads use the frozen source and imported custody. No schema preparation,
/// email synthesis, grants, bindings, module versions or empty scenes are added.
/// # Safety
/// The caller holds freeze/drain and exclusive importer locks, and has verified
/// complete final-resume, H3, source identity and source/target digest receipts.
pub async unsafe fn inspect_on(
    conn: &mut SqliteConnection,
    source: &std::path::Path,
    source_head: Value,
    report_digest: String,
    members: &std::collections::BTreeSet<String>,
) -> Result<Plan> {
    let v1 = crate::db::open_current_database_read_only_at(source).await?;
    let result = inspect_inner(conn, &v1, source_head, report_digest, members).await;
    v1.close().await;
    result
}

async fn inspect_inner(
    conn: &mut SqliteConnection,
    v1: &Db,
    head: Value,
    digest: String,
    members: &std::collections::BTreeSet<String>,
) -> Result<Plan> {
    let mut plan = Plan {
        artifacts: Vec::new(),
        exclusions: Vec::new(),
        canvases: Vec::new(),
        summary: json!({"artifacts":{"html":{"eligible":0,"excluded":0,"already_active":0},"board":{"eligible":0,"excluded":0,"already_active":0},"mdx":{"eligible":0,"excluded":0,"already_active":0},"other_runtime":{"eligible":0,"excluded":0,"already_active":0}},"canvases":{"eligible":0,"already_active":0},"refusals":{},"exclusions":{}}),
        already_active: true,
        expected: Vec::new(),
    };
    let sources = crate::mcp::tools::artifacts::frozen_artifact_sources(v1).await?;
    for (id, runtime) in sources {
        let class = match runtime.as_deref() {
            Some("native.html.v1") => "html",
            Some("native.board.v1") => "board",
            Some("native.mdx.v2") => "mdx",
            _ => "other_runtime",
        };
        let mut served = false;
        let mut non_string_failure = false;
        let mut expected = Vec::new();
        let mut outcomes = std::collections::BTreeSet::<String>::new();
        let mut diagnostics = BTreeMap::new();
        for member in members {
            let caller =
                crate::mcp::Caller::authenticated(member).with_suppressed_request_persistence();
            // Permission failures are expected for private artifacts. Other
            // failures must not be silently treated as v1 render refusals.
            let visible = crate::authorization::effective_capability(
                v1,
                crate::authorization::Principal::bound(member, true),
                &id,
            )
            .await?
            .allows(Capability::View);
            if !visible {
                continue;
            }
            let result = match crate::mcp::tools::artifacts::frozen_render_outcome(v1, &caller, &id)
                .await
            {
                Ok(result) => result,
                Err(error) => {
                    // v1 preserves SQLx's refusal for numeric body cells, which
                    // has no structured diagnostic. Only that known source-cell
                    // incompatibility becomes an unsupported exclusion. Storage
                    // and unrelated decoder failures still abort.
                    let body_decode = matches!(&error, Error::Sqlx(sqlx::Error::ColumnDecode { index, .. }) if index.trim_matches('"') == "body");
                    if !body_decode {
                        return Err(error);
                    }
                    let source = crate::record_body::live_artifact::latest_present_source_on(
                        v1.pool(),
                        &id,
                        None,
                    )
                    .await?
                    .ok_or_else(|| refusal("served_source_missing", 1))?;
                    let event: String = source.try_get("id")?;
                    let kind: Option<String> = sqlx::query_scalar(
                        "SELECT json_type(payload,'$.body') FROM content_events WHERE id=?",
                    )
                    .bind(event)
                    .fetch_one(v1.pool())
                    .await?;
                    if !matches!(kind.as_deref(), Some("integer" | "real" | "true" | "false")) {
                        return Err(error);
                    }
                    non_string_failure = true;
                    artifact_closures::unsupported_outcome(&id)
                }
            };
            let actor: String = sqlx::query_scalar(
                "SELECT principal_id FROM kernel_principals WHERE auth_binding=?",
            )
            .bind(member)
            .fetch_optional(&mut *conn)
            .await?
            .ok_or_else(|| refusal("parity_identity_missing", 1))?;
            if result["status"] != "rendered" {
                diagnostics.insert(actor, result.clone());
            } else {
                diagnostics.insert(actor, artifact_closures::unsupported_outcome(&id));
            }
            if result["status"] == "rendered" {
                served = true;
                expected.push((id.clone(), member.clone(), None));
            } else {
                let code = result["diagnostic"]["code"]
                    .as_str()
                    .ok_or_else(|| refusal("unclassified_v1_outcome", 1))?;
                outcomes.insert(code.to_owned());
                expected.push((id.clone(), member.clone(), Some(code.to_owned())));
            }
        }
        if expected.is_empty() {
            // A source outside every imported member's View scope is not an
            // imported executable artifact. Do not fabricate custody for it.
            increment(&mut plan.summary["artifacts"][class], "excluded");
            increment(
                &mut plan.summary["exclusions"],
                "outside_imported_view_scope",
            );
            continue;
        }
        // Retain expected refusals as well as successes. Every visible member's
        // artifact is exercised on the disposable copy, including exclusions.
        let capsule: Option<i64> =
            sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id=?")
                .bind(&id)
                .fetch_optional(&mut *conn)
                .await?;
        let inspected = if non_string_failure {
            Err(Error::engine(
                "imported artifact compatibility: non_string_body",
            ))
        } else if served {
            inspect_artifact_on(conn, v1, &head, &digest, &id, runtime.as_deref(), capsule).await
        } else {
            Err(Error::engine("imported artifact compatibility: v1_refused"))
        };
        match inspected {
            Ok((proof, already)) => {
                increment(&mut plan.summary["artifacts"][class], "eligible");
                if already {
                    increment(&mut plan.summary["artifacts"][class], "already_active");
                }
                plan.already_active &= already;
                plan.artifacts.push(proof);
            }
            Err(error) => {
                let reason = compatibility_class(&error).ok_or(error)?;
                increment(&mut plan.summary["artifacts"][class], "excluded");
                if served || non_string_failure {
                    increment(&mut plan.summary["exclusions"], reason);
                    for (_, _, code) in &mut expected {
                        if code.is_none() {
                            *code = Some("unsupported_on_v2".into());
                        }
                    }
                } else {
                    for code in outcomes {
                        increment(&mut plan.summary["refusals"], refusal_class(&code));
                    }
                }
                let proof = artifact_closures::FrozenExclusion {
                    format: 1,
                    source_head: head.clone(),
                    report_sha256: digest.clone(),
                    artifact_id: id,
                    capsule_seq: capsule,
                    outcomes: diagnostics,
                };
                plan.already_active &=
                    artifact_closures::inspect_exclusion_on(conn, &proof).await?;
                plan.exclusions.push(proof);
            }
        }
        plan.expected.extend(expected);
    }
    let canvases: Vec<String> = sqlx::query_scalar("SELECT id FROM records WHERE type='Document' AND kind='canvas' AND deleted_at IS NULL ORDER BY id")
        .fetch_all(v1.pool()).await?;
    for id in canvases {
        let seq: i64 =
            sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id=?")
                .bind(&id)
                .fetch_optional(&mut *conn)
                .await?
                .ok_or_else(|| refusal("canvas_custody_missing", 1))?;
        // SAFETY: same host guards; the canvas verifier proves the exact scene
        // by replaying the retained ledger, including floating-point bits/CAS.
        let proof = unsafe {
            canvas_v2::VerifiedFrozenCanvas::from_verified_import_unchecked(
                id,
                head.clone(),
                digest.clone(),
                seq,
            )
        };
        let already = canvas_v2::inspect_frozen_activation_on(conn, &proof).await?;
        increment(&mut plan.summary["canvases"], "eligible");
        if already {
            increment(&mut plan.summary["canvases"], "already_active");
        }
        plan.already_active &= already;
        plan.canvases.push(proof);
    }
    Ok(plan)
}

/// Compare each selected artifact for each authorized imported member. Aggregate
/// totals cannot hide a swapped success/refusal or a diagnostic disagreement.
/// This executes only on an operator-owned disposable native target copy.
pub async fn verify_parity_as(db: &Db, plan: &Plan) -> Result<()> {
    let mut mismatches = 0;
    for (id, member, expected) in &plan.expected {
        let actor = resolve_principal_by_binding(db, member)
            .await?
            .ok_or_else(|| refusal("parity_identity_missing", 1))?
            .0;
        let caller =
            crate::mcp::Caller::authenticated(member).with_suppressed_request_persistence();
        let args = json!({"id":id});
        let actual = match crate::mcp::kernel_v2::artifacts::html_board::try_render_for_cutover(
            db, &caller, &actor, &args,
        )
        .await?
        {
            Some(value) => value,
            None => {
                crate::mcp::kernel_v2::artifacts::render_with_database(db, &actor, None, args)
                    .await?
            }
        };
        let equal = match expected {
            None => actual["status"] == "rendered",
            Some(code) => actual["status"] != "rendered" && actual["diagnostic"]["code"] == *code,
        };
        if !equal {
            mismatches += 1;
        }
    }
    if mismatches != 0 {
        return Err(refusal("artifact_outcome_parity", mismatches));
    }
    Ok(())
}

/// Commit the complete preflighted content batch atomically. Every verifier is
/// re-run inside the write transaction; a late failure leaves no activation.
pub async fn activate_as(
    db: &Db,
    host: &str,
    apps: &app_installs::VerifiedFrozenApps,
    plan: &Plan,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    app_installs::activate_on(db, &mut tx, host, apps).await?;
    for proof in &plan.artifacts {
        artifact_closures::activate_on(db, &mut tx, host, proof).await?;
    }
    for proof in &plan.exclusions {
        artifact_closures::exclude_on(db, &mut tx, host, proof).await?;
    }
    for proof in &plan.canvases {
        canvas_v2::activate_on(db, &mut tx, host, proof).await?;
    }
    db.commit_kernel_content(tx).await?;
    Ok(())
}
fn increment(value: &mut Value, key: &str) {
    if !value.is_object() {
        *value = json!({});
    }
    value[key] = json!(value[key].as_u64().unwrap_or(0) + 1);
}
fn refusal_class(code: &str) -> &str {
    match code {
        "named_input_missing"
        | "module_capability_denied"
        | "html_source_too_large"
        | "html_body_too_large"
        | "html_input_too_large"
        | "html_invalid_document"
        | "artifact_source_unattested"
        | "named_input_incompatible"
        | "named_input_ambiguous"
        | "binding_unavailable"
        | "input_resolution_failed"
        | "invalid_artifact_body"
        | "module_release_missing"
        | "missing_runtime"
        | "unsupported_runtime"
        | "unsupported_runtime_revision"
        | "invalid_artifact_shape"
        | "ambiguous_binding"
        | "invalid_collection_shape"
        | "invalid_target_shape"
        | "missing_target"
        | "html_named_input_unsafe_integer" => code,
        _ => "other_v1_refusal",
    }
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty() && self.exclusions.is_empty() && self.canvases.is_empty()
    }
}

fn compatibility_class(error: &Error) -> Option<&'static str> {
    let Error::Engine(message) = error else {
        return None;
    };
    let message = message
        .strip_prefix("native artifact activation: ")
        .unwrap_or(message);
    // Exhaustive compatibility-only allowlist. Broken hashes, witnesses,
    // capsule/frontier state, and all storage errors remain hard refusals.
    for (detail, class) in [
        ("imported artifact compatibility: v1_refused", "v1_refused"),
        (
            "imported artifact compatibility: native_mdx_v1",
            "native_mdx_v1",
        ),
        (
            "imported artifact compatibility: other_runtime",
            "other_runtime",
        ),
        (
            "imported artifact compatibility: non_string_body",
            "non_string_body",
        ),
        (
            "imported artifact compatibility: attestation_source_not_current",
            "attestation_source_not_current",
        ),
        ("module closure unsupported on v2", "module_closure"),
        ("module or runtime closure unsupported", "module_closure"),
        ("unattested HTML interactions", "old_html_descriptor"),
        (
            "attestation does not describe current source",
            "old_source_descriptor",
        ),
        (
            "exact current source revision is not attested",
            "attestation_source_not_current",
        ),
        ("unsupported native frozen source", "legacy_source_closure"),
        (
            "legacy source requires its retained v1 closure",
            "legacy_source_closure",
        ),
        (
            "named HTML requires a v1 source attestation",
            "legacy_source_closure",
        ),
        ("source compiler refused artifact", "source_compiler"),
        ("HTML source validator refused artifact", "source_compiler"),
        ("source is not an MDX artifact", "source_compiler"),
    ] {
        if message == detail {
            return Some(class);
        }
    }
    None
}

async fn inspect_artifact_on(
    conn: &mut SqliteConnection,
    v1: &Db,
    head: &Value,
    digest: &str,
    id: &str,
    runtime: Option<&str>,
    capsule: Option<i64>,
) -> Result<(artifact_closures::VerifiedArtifactClosure, bool)> {
    let runtime = runtime.ok_or_else(|| refusal("served_runtime_missing", 1))?;
    if !matches!(
        runtime,
        "native.html.v1" | "native.board.v1" | "native.mdx.v2"
    ) {
        return Err(Error::engine(format!(
            "imported artifact compatibility: {}",
            if runtime == "native.mdx.v1" {
                "native_mdx_v1"
            } else {
                "other_runtime"
            }
        )));
    }
    let source = crate::record_body::live_artifact::latest_present_source_on(v1.pool(), id, None)
        .await?
        .ok_or_else(|| refusal("served_source_missing", 1))?;
    let event: String = source.try_get("id")?;
    let body_type: Option<String> =
        sqlx::query_scalar("SELECT json_type(payload,'$.body') FROM content_events WHERE id=?")
            .bind(&event)
            .fetch_one(v1.pool())
            .await?;
    if body_type.as_deref() != Some("text") {
        return Err(Error::engine(
            "imported artifact compatibility: non_string_body",
        ));
    }
    let body: String = source.try_get("body")?;
    let attested: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM artifact_source_attestations WHERE artifact_id=? AND source_event_id=?)")
        .bind(id).bind(&event).fetch_one(v1.pool()).await?;
    let proof = if attested {
        let latest: String = sqlx::query_scalar("SELECT source_event_id FROM artifact_source_attestations WHERE artifact_id=? ORDER BY event_seq DESC LIMIT 1")
            .bind(id).fetch_one(v1.pool()).await?;
        if latest != event {
            return Err(Error::engine(
                "imported artifact compatibility: attestation_source_not_current",
            ));
        }
        // SAFETY: inspect_on's host guards bind the complete frozen custody;
        // the kernel verifier rechecks the supplied source closure.
        unsafe {
            artifact_closures::VerifiedArtifactClosure::from_verified_import_unchecked(
                head.clone(),
                digest.into(),
                id.into(),
                capsule.ok_or_else(|| refusal("artifact_custody_missing", 1))?,
            )
        }
    } else {
        let renders: Vec<String> = sqlx::query_scalar("SELECT target_id FROM links WHERE source_id=? AND relationship='renders' ORDER BY target_id")
            .bind(id).fetch_all(v1.pool()).await?;
        // SAFETY: same guards, with exact current source history and v1 edges.
        unsafe {
            artifact_closures::VerifiedArtifactClosure::from_verified_legacy_import_unchecked(
                head.clone(),
                digest.into(),
                id.into(),
                event,
                native_artifact_runtime::mdx::sha256_hex(body.as_bytes()),
                runtime.into(),
                renders,
            )
        }
    };
    let already = artifact_closures::inspect_frozen_activation_on(conn, &proof).await?;
    Ok((proof, already))
}
