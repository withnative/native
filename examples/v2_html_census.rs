//! Counts-only, disposable-copy rehearsal; never use a serving generation.
//! The caller owns copying the frozen source and verified target into one fresh
//! temporary directory and deleting it after this process exits.
use native_ce::{
    artifact_html, kernel,
    mcp::{self, Caller, EngineHandle, ToolRegistry},
};
use serde_json::{json, Value};
use sqlx::{Connection, SqliteConnection};
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[tokio::main]
async fn main() {
    if execute().await.is_err() {
        // Engine/validator errors may contain private source. Never print them.
        eprintln!("Disposable HTML census refused; no private diagnostics emitted");
        std::process::exit(1);
    }
}

async fn execute() -> Result<()> {
    let directory =
        PathBuf::from(std::env::args().nth(1).ok_or("directory required")?).canonicalize()?;
    if !directory.starts_with(std::env::temp_dir())
        || !directory
            .file_name()
            .is_some_and(|n| n.to_string_lossy().starts_with("w7-html-census-"))
    {
        return Err("fresh temporary census directory required".into());
    }
    for name in ["source.db", "target.db", "import-report.json"] {
        let metadata = std::fs::symlink_metadata(directory.join(name))?;
        if !metadata.file_type().is_file() {
            return Err("regular disposable copies required".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1 {
                return Err("hard-linked files are not disposable copies".into());
            }
        }
    }
    // A diagnostic range is always partial and cannot pass the full HQ gate.
    let diagnostic_range = std::env::var("NATIVE_CE_HTML_CENSUS_RANGE")
        .ok()
        .map(|raw| -> Result<(usize, usize)> {
            let (start, end) = raw.split_once("..").ok_or("invalid diagnostic range")?;
            let (start, end) = (start.parse::<usize>()?, end.parse::<usize>()?);
            if start >= end {
                return Err("invalid diagnostic range".into());
            }
            Ok((start, end))
        })
        .transpose()?;
    let source = directory.join("source.db");
    if !source.metadata()?.permissions().readonly() {
        return Err("source copy must be read-only".into());
    }
    let mut v1 = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&source)
            .read_only(true)
            .immutable(true),
    )
    .await?;
    let sources:Vec<(String,String,String)>=sqlx::query_as("SELECT r.id,f.value,r.body FROM records r JOIN facet_values f ON f.record_id=r.id AND f.key='runtime' WHERE r.type='Document' AND r.kind='artifact' AND r.archived=0 AND r.deleted_at IS NULL AND f.value IN ('native.html.v1','native.board.v1') ORDER BY r.id").fetch_all(&mut v1).await?;
    let admin:String=sqlx::query_scalar("SELECT subject_id FROM policy_entries WHERE policy_anchor_id='native:root' AND subject_kind='account' AND capability='manage' AND effect='allow'").fetch_one(&mut v1).await?;
    let target = directory.join("target.db");
    // Explicit preparation belongs to this disposable rehearsal, never serving.
    // A previously prepared copy can need additive schema from the current
    // binary. Never relax readiness or hand-patch provenance/frontier facts.
    let preparing = native_ce::db::open_database(target.to_str().ok_or("path")?).await?;
    if std::env::var_os("NATIVE_CE_HTML_CENSUS_REPLAY_COPY").is_some() {
        kernel::replay_all_projections(&preparing).await?;
    }
    kernel::prepare_v2_database(&preparing).await?;
    preparing.close().await;
    let db = kernel::open_v2_database(target.to_str().ok_or("path")?).await?;
    let roster_raw:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_members_roster.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await?;
    let members: Vec<String> =
        serde_json::from_value(serde_json::from_str::<Value>(&roster_raw)?["members"].clone())?;
    if !members.contains(&admin) {
        return Err("frozen admin missing from roster".into());
    }
    let users: BTreeMap<String, String> = members
        .iter()
        .enumerate()
        .map(|(i, id)| (id.clone(), format!("census-{i}@example.test")))
        .collect();
    let authenticated = admin.clone();
    // SAFETY: exclusive disposable copy, complete imported member roster. The
    // synthetic catalogue preserves portable bindings; it grants no real session.
    kernel::hosted_identity::reconcile_hosted_caller(&db, |_| async move {
        Ok(unsafe {
            kernel::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                authenticated,
                users,
                BTreeMap::new(),
            )
        })
    })
    .await?;
    let host = kernel::resolve_principal_by_binding(&db, "host:v1-import")
        .await?
        .ok_or("import host")?
        .0;
    let head_raw:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' ORDER BY seq DESC LIMIT 1").fetch_one(db.pool()).await?;
    let head: Value = serde_json::from_str(&head_raw)?;
    let evidence = std::fs::read(directory.join("import-report.json"))?;
    let report: Value = serde_json::from_slice(&evidence)?;
    if report["app_state"]["capture_complete"] != true
        || report["refusals"].as_array().is_none_or(|a| !a.is_empty())
        || report["review"].as_array().is_none_or(|a| !a.is_empty())
    {
        return Err("complete verified import required".into());
    }
    let report_digest = native_artifact_runtime::mdx::sha256_hex(&evidence);
    let ring = Arc::new(
        native_artifact_runtime::deployment_keyring::DeploymentKeyring::from_json_bundle(
            r#"{"active_key_id":"census","keys":[{"id":"census","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}"#,
        )?,
    );
    let delivery = mcp::tools::alpha_tabs::AppBundleDelivery {
        enabled: true,
        runtime: artifact_html::RuntimeConfig::new(
            "https://parent.census.test",
            "https://artifact.census.test",
        )?,
        keyring: Some(ring),
    };
    let v1_db = native_ce::db::open_current_database_read_only_at(&source).await?;
    let mut v1_registry = ToolRegistry::new();
    mcp::register_builtin_tools(&mut v1_registry)?;
    mcp::register_surface_tools(&mut v1_registry)?;
    native_artifact_html::html::configure(artifact_html::RuntimeConfig::new(
        "https://parent.census.test",
        "https://artifact.census.test",
    )?);
    let v1_caller = Caller::authenticated(&admin).with_suppressed_request_persistence();
    let mut registry = ToolRegistry::new();
    registry.set_app_bundle_delivery(Some(delivery));
    mcp::register_builtin_tools(&mut registry)?;
    mcp::register_surface_tools(&mut registry)?;
    mcp::kernel_v2::register_hosted_kernel_v2_tools(&mut registry)?;
    // SAFETY: process-local rehearsal ingress; no bearer is issued or exported.
    let caller = unsafe {
        Caller::authenticated(&admin)
            .with_hosting_context(&admin, "census-db")
            .with_verified_hosting_session("11111111-1111-4111-8111-111111111111")
    };
    let mut counts = json!({"html_total":0,"html_rendered":0,"board_total":0,"board_rendered":0,"activation_refused":0,"render_refused":0,"bundle_refused":0,"v1_attested":0,"native_legacy_attested":0,"refusal_categories":{},"v1_refusal_categories":{},"v1_checked_refusals":0,"v1_checked_artifacts":0,"compared_artifacts":0,"v1_html_rendered":0,"v1_board_rendered":0,"disagreements":0,"native_not_comparable":0,"v1_not_comparable":0,"native_regressions":0,"diagnostic_mismatches":0,"input_failure_categories":{}});
    counts["census_finished"] = json!(false);
    counts["partial_census"] = json!(diagnostic_range.is_some());
    for (ordinal, (id, runtime, frozen_body)) in sources.into_iter().enumerate() {
        if diagnostic_range.is_some_and(|(start, end)| ordinal < start || ordinal >= end) {
            continue;
        }
        // Counts-only progress; a partial census is never a cutover result.
        std::fs::write(directory.join("counts.json"), serde_json::to_vec(&counts)?)?;

        let html = runtime == artifact_html::RUNTIME_ID;
        increment(&mut counts, if html { "html_total" } else { "board_total" });
        // Both engines run for every artifact, including native successes.
        // Equal aggregate totals alone cannot establish per-artifact parity.
        let baseline = read_v1_outcome(&v1_registry, &v1_db, &v1_caller, &id).await;
        increment(&mut counts, "v1_checked_artifacts");
        match &baseline {
            RenderOutcome::Rendered => increment(
                &mut counts,
                if html {
                    "v1_html_rendered"
                } else {
                    "v1_board_rendered"
                },
            ),
            RenderOutcome::Refused(code) => {
                increment(&mut counts, "v1_checked_refusals");
                increment(&mut counts["v1_refusal_categories"], refusal_class(code));
            }
            RenderOutcome::Unavailable => increment(&mut counts, "v1_not_comparable"),
        }
        let has_attestation: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM artifact_source_attestations WHERE artifact_id=?)",
        )
        .bind(&id)
        .fetch_one(&mut v1)
        .await?;
        // SAFETY: frozen full-history evidence, exclusive copy. Activation checks
        // the exact retained attestation or canonical imported source revision.
        let proof = if has_attestation {
            increment(&mut counts, "v1_attested");
            let seq: i64 =
                sqlx::query_scalar("SELECT event_seq FROM kernel_app_state WHERE record_id=?")
                    .bind(&id)
                    .fetch_one(db.pool())
                    .await?;
            unsafe {
                kernel::artifact_closures::VerifiedArtifactClosure::from_verified_import_unchecked(
                    head.clone(),
                    report_digest.clone(),
                    id.clone(),
                    seq,
                )
            }
        } else {
            increment(&mut counts, "native_legacy_attested");
            let event:String=sqlx::query_scalar("SELECT id FROM content_events WHERE record_id=? AND type IN ('record.created','record.updated','record.body.updated') AND json_type(payload,'$.body')='text' ORDER BY seq DESC LIMIT 1").bind(&id).fetch_one(&mut v1).await?;
            let renders:Vec<String>=sqlx::query_scalar("SELECT target_id FROM links WHERE source_id=? AND relationship='renders' ORDER BY target_id").bind(&id).fetch_all(&mut v1).await?;
            unsafe {
                kernel::artifact_closures::VerifiedArtifactClosure::from_verified_legacy_import_unchecked(head.clone(),report_digest.clone(),id.clone(),event,native_artifact_runtime::mdx::sha256_hex(frozen_body.as_bytes()),runtime,renders)
            }
        };
        if let Err(error) = kernel::artifact_closures::activate_as(&db, &host, proof).await {
            increment(&mut counts, "activation_refused");
            classify(&mut counts, &error.to_string());
            compare_outcomes(&mut counts, &baseline, &RenderOutcome::Unavailable);
            continue;
        }
        let retained: String = sqlx::query_scalar(
            "SELECT source_body FROM kernel_artifact_closures WHERE artifact_id=?",
        )
        .bind(&id)
        .fetch_one(db.pool())
        .await?;
        if retained != frozen_body {
            increment(&mut counts, "frozen_source_mismatch");
            compare_outcomes(&mut counts, &baseline, &RenderOutcome::Unavailable);
            continue;
        }
        let result = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                caller.clone(),
                "render_artifact",
                json!({"id":id}),
            )
            .await;
        let result = match result {
            Ok(v) if v["status"] == "rendered" => v,
            Ok(v) => {
                increment(&mut counts, "render_refused");
                if let Some(reason) = v
                    .pointer("/diagnostic/details/input_failure")
                    .and_then(Value::as_str)
                {
                    let category = if [
                        "sql_staging_timeout",
                        "query_timeout",
                        "typed_facet",
                        "saved_filter",
                        "saved_order",
                        "saved_pipeline",
                        "saved_traversal",
                        "query_pin",
                        "input_kind",
                        "input_json",
                        "input_storage",
                        "input_unavailable",
                    ]
                    .contains(&reason)
                    {
                        reason
                    } else {
                        "other"
                    };
                    increment(&mut counts["input_failure_categories"], category);
                }
                let code = v["diagnostic"]["code"].as_str().unwrap_or("other");
                compare_outcomes(
                    &mut counts,
                    &baseline,
                    &RenderOutcome::Refused(code.to_owned()),
                );
                increment(&mut counts["refusal_categories"], refusal_class(code));
                continue;
            }
            Err(_) => {
                increment(&mut counts, "render_refused");
                compare_outcomes(&mut counts, &baseline, &RenderOutcome::Unavailable);
                continue;
            }
        };
        if html {
            let body: String = sqlx::query_scalar(
                "SELECT source_body FROM kernel_artifact_closures WHERE artifact_id=?",
            )
            .bind(&id)
            .fetch_one(db.pool())
            .await?;
            let marker: Option<String> = sqlx::query_scalar(
                "SELECT value FROM kernel_facets WHERE record_id=? AND key='app_package'",
            )
            .bind(&id)
            .fetch_optional(db.pool())
            .await?;
            if artifact_html::compose_bundle_delivery(
                &body,
                "https://parent.census.test",
                artifact_html::body_limit_for_package_marker(marker.as_deref()),
            )
            .is_err()
                || result["launch"]["url"].as_str().is_none()
            {
                increment(&mut counts, "bundle_refused");
                compare_outcomes(&mut counts, &baseline, &RenderOutcome::Unavailable);
                continue;
            }
        }
        compare_outcomes(&mut counts, &baseline, &RenderOutcome::Rendered);
        increment(
            &mut counts,
            if html {
                "html_rendered"
            } else {
                "board_rendered"
            },
        );
    }
    v1_db.close().await;
    v1.close().await?;
    db.close().await;
    counts["census_finished"] = json!(true);
    std::fs::write(directory.join("counts.json"), serde_json::to_vec(&counts)?)?;
    println!("{}", serde_json::to_string(&counts)?);
    // Exact outcome parity is the gate. Pre-existing source/permission
    // refusals are acceptable only when this same artifact has the same class.
    if diagnostic_range.is_some()
        || counts["html_total"] != 183
        || counts["board_total"] != 1
        || counts["v1_checked_artifacts"] != 184
        || counts["compared_artifacts"] != 184
        || counts["html_rendered"] != counts["v1_html_rendered"]
        || counts["board_rendered"] != counts["v1_board_rendered"]
        || counts["refusal_categories"] != counts["v1_refusal_categories"]
        || counts["activation_refused"] != 0
        || counts["bundle_refused"] != 0
        || counts["disagreements"] != 0
        || counts["v1_not_comparable"] != 0
        || counts["native_not_comparable"] != 0
    {
        return Err("HQ artifact-by-artifact render parity not established".into());
    }
    Ok(())
}

#[derive(PartialEq)]
enum RenderOutcome {
    Rendered,
    Refused(String),
    Unavailable,
}

async fn read_v1_outcome(
    registry: &ToolRegistry,
    db: &native_ce::db::Db,
    caller: &Caller,
    id: &str,
) -> RenderOutcome {
    match registry
        .call(
            db.clone(),
            caller.clone(),
            "render_artifact",
            json!({"id":id}),
        )
        .await
    {
        Ok(result) if result["status"] == "rendered" => RenderOutcome::Rendered,
        Ok(result) => result["diagnostic"]["code"]
            .as_str()
            .map(|code| RenderOutcome::Refused(code.to_owned()))
            .unwrap_or(RenderOutcome::Unavailable),
        Err(_) => RenderOutcome::Unavailable,
    }
}

fn compare_outcomes(counts: &mut Value, baseline: &RenderOutcome, native: &RenderOutcome) {
    increment(counts, "compared_artifacts");
    if *native == RenderOutcome::Unavailable {
        increment(counts, "native_not_comparable");
    }
    // Unclassified errors are not proof of equal refusal classes.
    if baseline != native || *baseline == RenderOutcome::Unavailable {
        increment(counts, "disagreements");
        if *baseline == RenderOutcome::Rendered {
            increment(counts, "native_regressions");
        }
        if matches!(
            (baseline, native),
            (RenderOutcome::Refused(_), RenderOutcome::Refused(_))
        ) {
            increment(counts, "diagnostic_mismatches");
        }
    }
}

fn refusal_class(code: &str) -> &str {
    // Closed report vocabulary; raw codes are still compared exactly above.
    match code {
        "named_input_missing"
        | "invalid_artifact_shape"
        | "invalid_collection_shape"
        | "invalid_target_shape"
        | "missing_runtime"
        | "missing_target"
        | "unsupported_runtime_revision"
        | "ambiguous_binding"
        | "module_release_missing"
        | "named_input_incompatible"
        | "module_capability_denied"
        | "binding_unavailable"
        | "html_input_too_large"
        | "html_named_input_unsafe_integer"
        | "html_body_too_large"
        | "html_source_too_large"
        | "html_invalid_document"
        | "html_delivery_failed"
        | "artifact_source_unattested"
        | "input_resolution_failed"
        | "invalid_artifact_body"
        | "binding_repinned_by_source_edit"
        | "authorization_revision_changed"
        | "named_input_ambiguous"
        | "html_verifier_unavailable"
        | "html_verifier_contract_mismatch" => code,
        _ => "other",
    }
}

fn increment(value: &mut Value, key: &str) {
    value[key] = json!(value[key].as_u64().unwrap_or(0) + 1);
}
fn classify(value: &mut Value, error: &str) {
    // Closed diagnostic vocabulary: never echo engine/validator strings.
    let category = [
        "attestation does not describe current source",
        "HTML source validator refused",
        "incomplete or stale source capsule",
        "named input bindings do not match",
        "source event missing",
        "source digest mismatch",
        "exact current source revision",
        "named_input_missing",
        "module_capability_denied",
        "html_input_too_large",
        "artifact_snapshot_changed",
        "named_input_unavailable",
        "artifact_source_unavailable",
        "native source witness missing",
    ]
    .into_iter()
    .find(|s| error.contains(s))
    .unwrap_or("other");
    increment(&mut value["refusal_categories"], category);
}
