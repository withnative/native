//! Frozen package management. Package code cannot grant its own consent.
use super::*;
use crate::kernel::app_installs::{
    self as installs, AdoptRequest, InstallRequest, ManagementOutcome,
};
use crate::mcp::tools::alpha_tabs::{self, AppBundleDelivery, ManageAlphaTabsArgs};

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    let delivery = registry.app_bundle_delivery();
    registry.register_engine_handler_for_selector_values(
        "manage_alpha_tabs",
        EngineKind::KernelV2,
        "action",
        &[
            "list",
            "inspect",
            "prepare_install",
            "install",
            "preview",
            "adopt",
            "remove",
            "launch",
            "live_read",
            "live_unsubscribe",
        ],
        move |engine, caller, args| {
            let delivery = delivery.clone();
            async move {
                let EngineHandle::KernelV2(db) = engine else {
                    unreachable!()
                };
                let actor = principal(&db, &caller).await?;
                if caller.host_asserted_app().is_some() {
                    return Err(Error::engine(
                        "manage_alpha_tabs: app callers cannot manage consent",
                    ));
                }
                execute(&db, &actor, &caller, args, delivery.as_ref()).await
            }
        },
    )
}

fn availability(entry: &mut Value, delivery: Option<&AppBundleDelivery>) {
    if entry["launch_binding"]["delivery"] != "reusable.v1"
        || entry["launch_binding"]["reason"] == "readopt_required_on_v2"
    {
        return;
    }
    if !delivery.is_some_and(|config| config.enabled && config.keyring.is_some()) {
        entry["skip_reason"] = json!("delivery_unavailable");
        entry["launch_binding"]["reason"] = json!("delivery_unavailable");
    }
}

fn outcome(
    package: String,
    mut result: ManagementOutcome,
    delivery: Option<&AppBundleDelivery>,
) -> Value {
    availability(&mut result.install, delivery);
    json!({"package":package,"changed":result.outcome.changed,
        "idempotent_retry":!result.outcome.changed,"install":result.install})
}

fn refusal(code: &str, message: &str) -> Value {
    json!({"ready":false,"next_call":null,"findings":[{"code":code,"severity":"error","message":message}],"findings_truncated":false})
}

fn reason_valid(reason: &str) -> Result<()> {
    if reason.trim().is_empty() || reason.len() > 1024 {
        return Err(Error::engine(
            "manage_alpha_tabs: reason must be 1..1024 bytes",
        ));
    }
    Ok(())
}

async fn execute(
    db: &Db,
    actor: &str,
    caller: &Caller,
    args: Value,
    delivery: Option<&AppBundleDelivery>,
) -> Result<Value> {
    let args: ManageAlphaTabsArgs = serde_json::from_value(args)?;
    match args {
        ManageAlphaTabsArgs::LiveRead {
            package,
            expected_install_event_id,
            need,
            params,
            subscribe,
            if_revision,
            watch,
            reads,
        } => {
            if let Some(reads) = reads {
                if need.is_some()
                    || params.is_some()
                    || subscribe.is_some()
                    || if_revision.is_some()
                    || watch.is_some()
                {
                    return Err(Error::engine("manage_alpha_tabs: reads excludes need, params, subscribe, if_revision and watch [invalid_params]"));
                }
                return super::app_data::batch_read(
                    db,
                    caller,
                    package,
                    expected_install_event_id,
                    reads,
                )
                .await;
            }
            if watch.is_some() {
                return Err(Error::engine(
                    "manage_alpha_tabs: live read refused [undeclared_need]",
                ));
            }
            super::app_data::live_read(
                db,
                caller,
                crate::realtime::v2::AppDataRequest {
                    package,
                    expected_install_event_id,
                    need,
                    params: params.unwrap_or_else(|| json!({})),
                },
                subscribe,
                if_revision,
            )
            .await
        }
        ManageAlphaTabsArgs::LiveUnsubscribe {
            stream,
            subscription,
        } => Ok(super::app_data::unsubscribe(
            db,
            caller,
            &stream,
            &subscription,
        )),
        ManageAlphaTabsArgs::Launch {
            package,
            expected_install_event_id,
            parent_origin,
            delivery: protocol,
        } => {
            alpha_tabs::require_package(&package)?;
            if protocol.as_deref() != Some("reusable.v1") {
                return Err(Error::engine(
                    "manage_alpha_tabs: reusable.v1 delivery required",
                ));
            }
            let config = delivery
                .filter(|config| config.enabled && config.keyring.is_some())
                .ok_or_else(|| Error::engine("manage_alpha_tabs: delivery_unavailable"))?;
            let mut snapshot = db.write_pool().begin().await?;
            let source = installs::launch_source_on(
                &mut snapshot,
                actor,
                caller,
                &package,
                &expected_install_event_id,
            )
            .await?;
            let manifest =
                crate::artifact_html::validate_cached_with_limit(&source.body, source.body_limit)
                    .map_err(|failure| {
                    Error::engine(format!(
                        "manage_alpha_tabs: launch refused [{}]",
                        failure.code
                    ))
                })?;
            manifest.require_available_kit().map_err(|failure| {
                Error::engine(format!(
                    "manage_alpha_tabs: launch refused [{}]",
                    failure.code
                ))
            })?;
            let now = u64::try_from(chrono::Utc::now().timestamp())
                .map_err(|_| Error::engine("manage_alpha_tabs: launch clock unavailable"))?;
            let launch = config
                .launch(
                    caller,
                    &package,
                    &source.generation,
                    source.pin["digest"].as_str().unwrap_or_default(),
                    parent_origin.as_deref(),
                    now,
                )
                .ok_or_else(|| Error::engine("manage_alpha_tabs: delivery_unavailable"))?;
            snapshot.rollback().await?;
            let sample = alpha_tabs::alpha_tab_sample_input();
            Ok(
                json!({"package":package, "install_event_id":source.generation,
                "pin":{"package":source.package,"version":source.version,
                    "digest":source.pin["digest"],"artifact_id":source.pin["artifact_id"],
                    "source_revision":source.pin["source_revision"],"declaration_digest":source.pin["declaration_digest"]},
                "source":{"event_id":source.pin["source_revision"],"bundle_sha256":source.pin["bundle_sha256"],
                    "body_digest":manifest.body_digest,"runtime":"native.html.v1"},
                "launch":launch,
                "sandbox":{"sandbox":"allow-scripts","referrerPolicy":"no-referrer","allow":"","bridge_version":crate::artifact_html::BRIDGE_VERSION},
                "input_digest":alpha_tabs::alpha_tab_sample_input_digest(&sample),"input":sample,
                "live_reads":source.pin["consented_declaration"].as_str().and_then(|raw| serde_json::from_str::<Value>(raw).ok()).is_some_and(|d| d.get("contract").is_none()),"effects_wired":false}),
            )
        }
        ManageAlphaTabsArgs::List {
            view,
            include_removed,
        } => {
            let mut result = installs::list_as(db, actor, view, include_removed).await?;
            // A host-owned development contract, never app-supplied admission.
            // Keep ordinary shipping responses and tool-name lists unchanged.
            #[cfg(feature = "package-cel-dev")]
            {
                result["development_package_operations"] = json!("native.package-cel-dev.reads/1");
            }
            if let Some(entries) = result["installs"].as_array_mut() {
                for entry in entries {
                    availability(entry, delivery);
                }
            }
            Ok(result)
        }
        ManageAlphaTabsArgs::Inspect { package } => {
            alpha_tabs::require_package(&package)?;
            let mut result = installs::inspect_as(db, actor, &package).await?;
            if result["installed"] == true {
                availability(&mut result["install"], delivery);
            }
            Ok(result)
        }
        ManageAlphaTabsArgs::PrepareInstall(args) => {
            alpha_tabs::require_package(&args.package)?;
            reason_valid(&args.reason)?;
            if args.artifact_id.trim().is_empty()
                || (args.expected_body_digest.is_none() && args.expected_source_revision.is_none())
                || args
                    .expected_body_digest
                    .as_ref()
                    .is_some_and(|d| d.len() != 64 || !d.bytes().all(|c| c.is_ascii_hexdigit()))
                || args
                    .expected_source_revision
                    .as_ref()
                    .is_some_and(|s| s.trim().is_empty() || s.len() > 256)
            {
                return Err(Error::engine("manage_alpha_tabs: prepare_install requires a source revision or body digest guard"));
            }
            let pins = installs::frozen_sources_as(db, actor).await?;
            let mut matches = Vec::new();
            for pin in pins {
                let declaration: Value = serde_json::from_str(
                    pin["consented_declaration"]
                        .as_str()
                        .ok_or_else(|| Error::engine("invalid frozen declaration"))?,
                )?;
                if pin["package"] == args.package
                    && pin["version"] == args.version
                    && pin["artifact_id"] == args.artifact_id
                    && declaration == args.declaration
                    && args
                        .expected_source_revision
                        .as_ref()
                        .is_none_or(|s| pin["source_revision"] == *s)
                    && args
                        .expected_body_digest
                        .as_ref()
                        .is_none_or(|s| pin["bundle_sha256"] == *s)
                {
                    matches.push(pin);
                }
            }
            if matches.len() != 1 {
                return Ok(refusal(
                    "unsupported_on_v2",
                    "Select one exact frozen source pin available to this account.",
                ));
            }
            let pin = matches.pop().expect("one matching frozen pin");
            let request = InstallRequest {
                package: args.package,
                version: args.version,
                artifact_id: args.artifact_id,
                digest: pin["digest"]
                    .as_str()
                    .ok_or_else(|| Error::engine("invalid frozen digest"))?
                    .into(),
                source_revision: pin["source_revision"]
                    .as_str()
                    .ok_or_else(|| Error::engine("invalid frozen revision"))?
                    .into(),
                declaration: args.declaration,
                reason: args.reason,
                request: args.request,
                idempotency_key: None,
                expected_install_event_id: None,
            };
            let prepared = installs::prepare_source_as(db, actor, &request).await?;
            if prepared
                .current_install
                .as_ref()
                .is_some_and(|(_, status)| status != "removed")
            {
                return Ok(refusal(
                    "already_installed",
                    "This account already has this package installed.",
                ));
            }
            let manifest = match crate::artifact_html::validate_cached_with_limit(
                &prepared.body,
                prepared.body_limit,
            ) {
                Ok(manifest) => manifest,
                Err(error) => {
                    return Ok(refusal(
                        error.code,
                        "The frozen source is not valid native HTML.",
                    ))
                }
            };
            if let Err(error) = manifest.require_available_kit() {
                return Ok(refusal(
                    error.code,
                    "The frozen source's required app kit is unavailable.",
                ));
            }
            let previous = prepared
                .current_install
                .as_ref()
                .map(|(generation, _)| generation.clone());
            let arguments = json!({"action":"install","package":request.package,"version":request.version,
                "digest":request.digest,"artifact_id":request.artifact_id,"source_revision":request.source_revision,
                "declaration":request.declaration,"reason":request.reason,"request":request.request,
                "expected_install_event_id":previous});
            Ok(
                json!({"ready":true,"artifact_id":request.artifact_id,"source_revision":request.source_revision,
                "source_bytes":prepared.body.len(),"runtime":"native.html.v1",
                "digest_version":alpha_tabs::ALPHA_TAB_DIGEST_VERSION,"bundle_sha256":prepared.pin["bundle_sha256"],
                "declaration_digest":prepared.pin["declaration_digest"],"digest":request.digest,
                "current_install_event_id":previous,"current_install_status":prepared.current_install.as_ref().map(|(_,s)|s),
                "adoption":"caller_asserted","kit":{"policy":manifest.kit_policy,"available":true,"basis":"packaged_default","delivery_rechecks":true},
                "findings":[],"findings_truncated":false,
                "next_call":{"executor":"artifacts_write","operation":"manage_alpha_tabs.install","arguments":arguments}}),
            )
        }
        ManageAlphaTabsArgs::Install {
            package,
            version,
            digest,
            artifact_id,
            source_revision,
            declaration,
            reason,
            request,
            idempotency_key,
            expected_install_event_id,
        } => {
            alpha_tabs::require_package(&package)?;
            let result = installs::install_for_user_as(
                db,
                actor,
                InstallRequest {
                    package: package.clone(),
                    version,
                    digest,
                    artifact_id,
                    source_revision,
                    declaration,
                    reason,
                    request,
                    idempotency_key,
                    expected_install_event_id,
                },
            )
            .await?;
            Ok(outcome(package, result, delivery))
        }
        ManageAlphaTabsArgs::Preview {
            package,
            version,
            digest,
            artifact_id,
            source_revision,
            declaration,
            reason,
        } => {
            alpha_tabs::require_package(&package)?;
            let result = installs::preview_as(
                db,
                actor,
                caller,
                InstallRequest {
                    package: package.clone(),
                    version,
                    digest,
                    artifact_id: artifact_id.clone(),
                    source_revision: source_revision.clone(),
                    declaration,
                    reason,
                    request: None,
                    idempotency_key: None,
                    expected_install_event_id: None,
                },
            )
            .await?;
            let manifest =
                crate::artifact_html::validate_cached_with_limit(&result.body, result.body_limit)
                    .map_err(|error| {
                    Error::engine(format!(
                        "manage_alpha_tabs: preview refused [{}]",
                        error.code
                    ))
                })?;
            manifest.require_available_kit().map_err(|error| {
                Error::engine(format!(
                    "manage_alpha_tabs: preview refused [{}]",
                    error.code
                ))
            })?;
            let now = u64::try_from(chrono::Utc::now().timestamp())
                .map_err(|_| Error::engine("manage_alpha_tabs: preview clock unavailable"))?;
            let expires = u64::try_from(result.receipt.expires_at_secs)
                .map_err(|_| Error::engine("manage_alpha_tabs: preview expiry unavailable"))?;
            let launch = delivery
                .and_then(|config| {
                    config.preview_launch(
                        caller,
                        &package,
                        result
                            .receipt
                            .last_update_event_id
                            .as_deref()
                            .unwrap_or_default(),
                        result.pin["digest"].as_str().unwrap_or_default(),
                        &result.receipt.receipt_id,
                        now,
                        expires,
                    )
                })
                .ok_or_else(|| Error::engine("manage_alpha_tabs: delivery_unavailable"))?;
            let sample = alpha_tabs::alpha_tab_sample_input();
            let sample_digest = alpha_tabs::alpha_tab_sample_input_digest(&sample);
            Ok(
                json!({"package":package,"preview":{"artifact_id":artifact_id,"source_revision":source_revision,
                "source_event_id":source_revision,"bundle_sha256":result.pin["bundle_sha256"],
                "declaration_digest":result.pin["declaration_digest"],"digest":result.pin["digest"],
                "digest_version":alpha_tabs::ALPHA_TAB_DIGEST_VERSION,"runtime":"native.html.v1","body_digest":manifest.body_digest,
                "sample_input":sample,"sample_input_digest":sample_digest,
                "sandbox":{"sandbox":"allow-scripts","referrerPolicy":"no-referrer","allow":"","bridge_version":crate::artifact_html::BRIDGE_VERSION},
                "launch":launch,
                "live_reads":false,"effects_wired":false},
                "receipt":{"receipt_id":result.receipt.receipt_id,"nonce":result.receipt.nonce,
                    "preview_session":result.receipt.preview_session,"account_id":result.receipt.account_id,
                    "expires_at_secs":result.receipt.expires_at_secs,"ttl_secs":alpha_tabs::ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS}}),
            )
        }
        ManageAlphaTabsArgs::Adopt {
            package,
            version,
            digest,
            artifact_id,
            source_revision,
            declaration,
            receipt_id,
            nonce,
            preview_session,
            expected_install_event_id,
            reason,
            idempotency_key,
        } => {
            alpha_tabs::require_package(&package)?;
            let result = installs::adopt_as(
                db,
                actor,
                caller,
                AdoptRequest {
                    pin: InstallRequest {
                        package: package.clone(),
                        version,
                        digest,
                        artifact_id,
                        source_revision,
                        declaration,
                        reason,
                        request: None,
                        idempotency_key,
                        expected_install_event_id: Some(expected_install_event_id),
                    },
                    receipt_id,
                    nonce,
                    preview_session,
                },
            )
            .await?;
            Ok(outcome(package, result, delivery))
        }
        ManageAlphaTabsArgs::Remove {
            package,
            expected_install_event_id,
            reason,
            idempotency_key,
        } => {
            alpha_tabs::require_package(&package)?;
            let result = installs::remove_for_user_as(
                db,
                actor,
                &package,
                &expected_install_event_id,
                reason,
                idempotency_key,
            )
            .await?;
            Ok(outcome(package, result, delivery))
        }
        _ => Err(Error::engine(
            "manage_alpha_tabs: operation unsupported_on_v2",
        )),
    }
}
