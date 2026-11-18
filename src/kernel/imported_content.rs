//! Frozen imported content staging. This module grants no ingress authority:
//! the local operator must hold the same freeze, import and receipt guards as
//! installed-app activation before constructing these proofs.
use super::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;
mod preinspection;
use preinspection::observe;
pub use preinspection::{preinspect, reuse_probe, Preinspection};

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
    inspect_on_with_progress(
        conn,
        source,
        source_head,
        report_digest,
        members,
        &mut |_, _, _| {},
    )
    .await
}

/// Same guarded preflight, with content-free progress for the local operator.
/// # Safety
/// The caller must satisfy the same guards as [`inspect_on`].
pub async unsafe fn inspect_on_with_progress(
    conn: &mut SqliteConnection,
    source: &std::path::Path,
    source_head: Value,
    report_digest: String,
    members: &std::collections::BTreeSet<String>,
    progress: &mut (dyn FnMut(&'static str, usize, usize) + Send),
) -> Result<Plan> {
    inspect_on_with_preinspection(
        conn,
        source,
        source_head,
        report_digest,
        members,
        None,
        None,
        progress,
    )
    .await
}

/// Reuse only v1 observations whose complete conservative dependency key still
/// matches. Kernel closure/custody checks and whole-batch parity are unchanged.
/// # Safety
/// Same guards as [`inspect_on`]; evidence must be computed from this frozen source.
#[allow(clippy::too_many_arguments)]
pub async unsafe fn inspect_on_with_preinspection(
    conn: &mut SqliteConnection,
    source: &std::path::Path,
    source_head: Value,
    report_digest: String,
    members: &std::collections::BTreeSet<String>,
    receipt: Option<&Preinspection>,
    evidence: Option<&crate::v1_import::cutover::SnapshotEvidence>,
    progress: &mut (dyn FnMut(&'static str, usize, usize) + Send),
) -> Result<Plan> {
    progress("source_open", 0, 1);
    let v1 = crate::db::open_current_database_read_only_at(source).await?;
    progress("source_open", 1, 1);
    let result = inspect_inner(
        conn,
        &v1,
        source_head,
        report_digest,
        members,
        receipt,
        evidence,
        progress,
    )
    .await;
    v1.close().await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn inspect_inner(
    conn: &mut SqliteConnection,
    v1: &Db,
    head: Value,
    digest: String,
    members: &std::collections::BTreeSet<String>,
    receipt: Option<&Preinspection>,
    evidence: Option<&crate::v1_import::cutover::SnapshotEvidence>,
    progress: &mut (dyn FnMut(&'static str, usize, usize) + Send),
) -> Result<Plan> {
    let mut reused = 0;
    let mut inspected = 0;
    let mut slowest = Vec::new();
    let mut plan = Plan {
        artifacts: Vec::new(),
        exclusions: Vec::new(),
        canvases: Vec::new(),
        summary: json!({"artifacts":{"html":{"eligible":0,"excluded":0,"already_active":0},"board":{"eligible":0,"excluded":0,"already_active":0},"mdx":{"eligible":0,"excluded":0,"already_active":0},"other_runtime":{"eligible":0,"excluded":0,"already_active":0}},"canvases":{"eligible":0,"already_active":0},"refusals":{},"exclusions":{}}),
        already_active: true,
        expected: Vec::new(),
    };
    let sources = crate::mcp::tools::artifacts::frozen_artifact_sources(v1).await?;
    let total = sources.len();
    progress("artifacts", 0, total);
    for (index, (id, runtime)) in sources.into_iter().enumerate() {
        let class = match runtime.as_deref() {
            Some("native.html.v1") => "html",
            Some("native.board.v1") => "board",
            Some("native.mdx.v2") => "mdx",
            _ => "other_runtime",
        };
        let started = std::time::Instant::now();
        let cached = match (receipt, evidence) {
            (Some(receipt), Some(evidence)) => {
                receipt
                    .observation(v1, &id, runtime.as_deref(), members, evidence)
                    .await?
            }
            _ => None,
        };
        let observation = if let Some(observation) = cached {
            reused += 1;
            observation.clone()
        } else {
            inspected += 1;
            observe(v1, &id, members).await?
        };
        slowest.push((started.elapsed().as_secs_f64(), id.clone()));
        let mut served = false;
        let non_string_failure = observation.non_string_failure;
        let mut expected = Vec::new();
        let mut outcomes = std::collections::BTreeSet::<String>::new();
        let mut diagnostics = BTreeMap::new();
        for (member, result) in &observation.outcomes {
            let Some(result) = result else { continue };
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
            progress("artifacts", index + 1, total);
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
        progress("artifacts", index + 1, total);
    }
    let canvases: Vec<String> = sqlx::query_scalar("SELECT id FROM records WHERE type='Document' AND kind='canvas' AND deleted_at IS NULL ORDER BY id")
        .fetch_all(v1.pool()).await?;
    let total = canvases.len();
    progress("canvases", 0, total);
    for (index, id) in canvases.into_iter().enumerate() {
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
        progress("canvases", index + 1, total);
    }
    slowest.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    plan.summary["v1_observations"] = json!({"reused":reused,"inspected":inspected});
    plan.summary["slowest_v1_artifacts"] = json!(slowest
        .into_iter()
        .take(10)
        .map(|(seconds, id)| json!({"artifact_id":id,"seconds":seconds}))
        .collect::<Vec<_>>());
    Ok(plan)
}

/// Compare each selected artifact for each authorized imported member. Aggregate
/// totals cannot hide a swapped success/refusal or a diagnostic disagreement.
/// This executes only on an operator-owned disposable native target copy.
pub async fn verify_parity_as(db: &Db, plan: &Plan) -> Result<()> {
    verify_parity_as_with_progress(db, plan, &mut |_, _, _| {}).await
}

/// Per authorized artifact/member comparison progress, without identifiers.
pub async fn verify_parity_as_with_progress(
    db: &Db,
    plan: &Plan,
    progress: &mut (dyn FnMut(&'static str, usize, usize) + Send),
) -> Result<()> {
    let mut mismatches = 0;
    let total = plan.expected.len();
    progress("artifact_members", 0, total);
    for (index, (id, member, expected)) in plan.expected.iter().enumerate() {
        let actor = resolve_principal_by_binding(db, member)
            .await?
            .ok_or_else(|| refusal("parity_identity_missing", 1))?
            .0;
        let caller =
            crate::mcp::Caller::authenticated(member).with_suppressed_request_persistence();
        let args = json!({"id":id});
        // This closed semantic probe only reads its disposable database: no
        // dispatch, delivery URL or writer runs here. Unlike live render_artifact,
        // parity opts into the capability cache already used by get/query/search/
        // history serving. This is safe with no parity writes: each lookup checks
        // the actor, database file and content/meta event heads, within this render.
        // Keep the renderer behind one allocation before nesting task-local
        // scopes. Otherwise debug builds copy its large future into each scope
        // and overflow the operator's main-thread stack during parity checks.
        let actual = read_cache::scope_request(hosted_identity::scope_request(
            read_cache::with_capabilities(Box::pin(async {
                match crate::mcp::kernel_v2::artifacts::html_board::try_render_for_cutover(
                    db, &caller, &actor, &args,
                )
                .await?
                {
                    Some(value) => Ok(value),
                    None => {
                        crate::mcp::kernel_v2::artifacts::render_with_database(
                            db, &actor, None, args,
                        )
                        .await
                    }
                }
            })),
        ))
        .await?;
        let equal = match expected {
            None => actual["status"] == "rendered",
            Some(code) => actual["status"] != "rendered" && actual["diagnostic"]["code"] == *code,
        };
        if !equal {
            mismatches += 1;
        }
        progress("artifact_members", index + 1, total);
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
    activate_as_with_progress(db, host, apps, plan, &mut |_, _, _| {}).await
}

/// Atomic activation with bounded content-free operator progress.
pub async fn activate_as_with_progress(
    db: &Db,
    host: &str,
    apps: &app_installs::VerifiedFrozenApps,
    plan: &Plan,
    progress: &mut (dyn FnMut(&'static str, usize, usize) + Send),
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    app_installs::activate_on(db, &mut tx, host, apps).await?;
    progress("activate_artifacts", 0, plan.artifacts.len());
    for (index, proof) in plan.artifacts.iter().enumerate() {
        artifact_closures::activate_on(db, &mut tx, host, proof).await?;
        progress("activate_artifacts", index + 1, plan.artifacts.len());
    }
    progress("activate_exclusions", 0, plan.exclusions.len());
    for (index, proof) in plan.exclusions.iter().enumerate() {
        artifact_closures::exclude_on(db, &mut tx, host, proof).await?;
        progress("activate_exclusions", index + 1, plan.exclusions.len());
    }
    progress("activate_canvases", 0, plan.canvases.len());
    for (index, proof) in plan.canvases.iter().enumerate() {
        canvas_v2::activate_on(db, &mut tx, host, proof).await?;
        progress("activate_canvases", index + 1, plan.canvases.len());
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
    /// Synthetic parity fault injection; absent from the production feature closure.
    #[cfg(feature = "body-read-test-support")]
    #[doc(hidden)]
    pub fn expected_outcomes_mut_for_test(&mut self) -> &mut Vec<(String, String, Option<String>)> {
        &mut self.expected
    }

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
