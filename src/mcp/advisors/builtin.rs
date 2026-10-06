//! In-process advisors addressed as `builtin:<id>` endpoints.
//!
//! A manifest whose endpoint is `builtin:<id>` names an advisor that runs in
//! the engine process instead of over HTTP. Builtins are constructed with the
//! manifest's `settings` value, so demo thresholds live in config, not code.
//! The `test` builtin serves S4's own tests; `long_record`,
//! `completion_outcome` and `release_after_completion` are the product
//! builtins, installed by default (see `startup::default_installs`).

use std::sync::Arc;

use futures::future::BoxFuture;

use super::manifest::{watches_match, AdvisorManifest, EndpointKind};
use super::{AdviceContext, Advisor, AdvisorRef, Advisory, AdvisoryLevel};

/// Build the in-process advisor for a `builtin:<id>` endpoint, or `None`
/// when the endpoint names no known builtin. The caller passes the install's
/// `manifest_digest` so emissions stay attributable after installs move into
/// Native records (S8).
pub fn builtin_advisor(manifest: &AdvisorManifest, manifest_digest: &str) -> Option<AdvisorRef> {
    let id = match super::manifest::endpoint_kind(&manifest.endpoint) {
        Some(EndpointKind::Builtin(id)) => id,
        _ => return None,
    };
    match id.as_str() {
        "test" => Some(Arc::new(TestBuiltin {
            manifest: manifest.clone(),
            digest: manifest_digest.to_owned(),
        })),
        "long_record" => Some(Arc::new(
            super::long_record::LongRecordAdvisor::for_manifest(manifest, manifest_digest),
        )),
        "completion_outcome" => Some(completion_outcome_from_install(manifest, manifest_digest)),
        "release_after_completion" => Some(release_after_completion_from_install(
            manifest,
            manifest_digest,
        )),
        unknown => {
            tracing::warn!(
                target: "native::advisors",
                advisor_id = manifest.id.as_str(),
                endpoint = %unknown,
                "unknown builtin advisor; skipping"
            );
            None
        }
    }
}

/// The S4 test builtin: fires one advisory on every write its manifest
/// watches, echoing its `settings` so tests can prove config reaches it.
struct TestBuiltin {
    manifest: AdvisorManifest,
    digest: String,
}

impl Advisor for TestBuiltin {
    fn id(&self) -> &str {
        &self.manifest.id
    }

    fn version(&self) -> &str {
        &self.manifest.version
    }

    fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
        watches_match(&self.manifest.watches.tools, tool)
            && watches_match(&self.manifest.watches.types, record_type)
            && watches_match(&self.manifest.watches.kinds, record_kind)
    }

    fn advise<'a>(
        &'a self,
        ctx: &'a AdviceContext,
    ) -> BoxFuture<'a, crate::error::Result<Vec<Advisory>>> {
        Box::pin(async move {
            let message = match &self.manifest.settings {
                Some(settings) => format!("builtin test fired ({settings})"),
                None => "builtin test fired".to_owned(),
            };
            Ok(vec![Advisory {
                advisor_id: self.manifest.id.clone(),
                level: settings_level(
                    &self.manifest.id,
                    self.manifest.settings.as_ref(),
                    AdvisoryLevel::Advise,
                ),
                version: self.manifest.version.clone(),
                manifest_digest: Some(self.digest.clone()),
                code: "builtin_test".to_owned(),
                record_id: ctx.record_id.clone(),
                message,
                details: None,
            }])
        })
    }
}

/// Stable advisor id for the completion-outcome nudge.
pub const COMPLETION_OUTCOME_ADVISOR_ID: &str = "builtin.completion_outcome";
/// Stable advisor id for the release-after-completion nudge.
pub const RELEASE_AFTER_COMPLETION_ADVISOR_ID: &str = "builtin.release_after_completion";
/// Version shipped for both completion advisors.
pub const COMPLETION_ADVISOR_VERSION: &str = "1.0.0";

/// Resolve a builtin advisor's `level` from an install's `settings.level`
/// (`"advise"` | `"warn"`). Absent means the advisor's own default; an
/// invalid value falls back to the default with a `tracing::warn!`, never a
/// failure. The workspace owner, not the code, decides how firmly a rule
/// speaks.
fn settings_level(
    advisor_id: &str,
    settings: Option<&serde_json::Value>,
    default: AdvisoryLevel,
) -> AdvisoryLevel {
    let Some(value) = settings.and_then(|settings| settings.get("level")) else {
        return default;
    };
    match value.as_str() {
        Some("warn") => AdvisoryLevel::Warn,
        Some("advise") => AdvisoryLevel::Advise,
        _ => {
            tracing::warn!(
                target: "native::advisors",
                advisor_id = advisor_id,
                level = %value,
                "builtin advisor settings.level must be \"advise\" or \"warn\"; using the default"
            );
            default
        }
    }
}

/// Build the `builtin:completion_outcome` advisor (default level `warn`,
/// overridable per install via `settings.level`). Watches
/// `create_record`/`update_record` on `WorkItem` and fires when this write
/// moved lifecycle from a non-terminal value to a terminal-positive one
/// without a recorded outcome.
pub fn completion_outcome_advisor() -> AdvisorRef {
    Arc::new(CompletionOutcomeAdvisor {
        id: COMPLETION_OUTCOME_ADVISOR_ID.to_owned(),
        version: COMPLETION_ADVISOR_VERSION.to_owned(),
        digest: None,
        level: AdvisoryLevel::Warn,
    })
}

fn completion_outcome_from_install(
    manifest: &AdvisorManifest,
    manifest_digest: &str,
) -> AdvisorRef {
    Arc::new(CompletionOutcomeAdvisor {
        // Bind manifest identity (like LongRecordAdvisor::for_manifest):
        // registry dedup and suppression reconcile by install id, so the
        // emission id must match it.
        id: manifest.id.clone(),
        version: manifest.version.clone(),
        digest: Some(manifest_digest.to_owned()),
        level: settings_level(
            &manifest.id,
            manifest.settings.as_ref(),
            AdvisoryLevel::Warn,
        ),
    })
}

/// Build the `builtin:release_after_completion` advisor (default level
/// `advise`, overridable per install via `settings.level`). Same transition
/// gate; fires when a claim is still held after the write.
pub fn release_after_completion_advisor() -> AdvisorRef {
    Arc::new(ReleaseAfterCompletionAdvisor {
        id: RELEASE_AFTER_COMPLETION_ADVISOR_ID.to_owned(),
        version: COMPLETION_ADVISOR_VERSION.to_owned(),
        digest: None,
        level: AdvisoryLevel::Advise,
    })
}

fn release_after_completion_from_install(
    manifest: &AdvisorManifest,
    manifest_digest: &str,
) -> AdvisorRef {
    Arc::new(ReleaseAfterCompletionAdvisor {
        id: manifest.id.clone(),
        version: manifest.version.clone(),
        digest: Some(manifest_digest.to_owned()),
        level: settings_level(
            &manifest.id,
            manifest.settings.as_ref(),
            AdvisoryLevel::Advise,
        ),
    })
}

/// Shared transition gate: this write moved lifecycle from a non-terminal
/// value to a terminal-positive one. Terminality comes from the governed
/// lifecycle interpretation resolved into the context (never a hard-coded
/// token list): `completed` is the canonical terminal-positive value.
/// An unknown/absent before-terminality counts as non-terminal; an unknown
/// after-terminality never counts as terminal-positive. Cancelled/closed
/// (terminal-negative) and already-terminal befores do not pass.
fn completion_transition(ctx: &AdviceContext) -> bool {
    if ctx.record_type != "WorkItem" {
        return false;
    }
    if ctx.lifecycle_after_terminality.as_deref() != Some("terminal_positive") {
        return false;
    }
    !matches!(
        ctx.lifecycle_before_terminality.as_deref(),
        Some("terminal_positive" | "terminal_negative")
    )
}

struct CompletionOutcomeAdvisor {
    id: String,
    version: String,
    digest: Option<String>,
    level: AdvisoryLevel,
}

impl Advisor for CompletionOutcomeAdvisor {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn watches(&self, tool: &str, record_type: &str, _record_kind: &str) -> bool {
        matches!(tool, "create_record" | "update_record") && record_type == "WorkItem"
    }

    fn needs_completion_context(&self) -> bool {
        true
    }

    fn advise<'a>(
        &'a self,
        ctx: &'a AdviceContext,
    ) -> BoxFuture<'a, crate::error::Result<Vec<Advisory>>> {
        Box::pin(async move {
            if !completion_transition(ctx) {
                return Ok(Vec::new());
            }
            // No recorded outcome: the summary is empty/absent, or it was
            // neither set by this write nor touched since the task last
            // entered an active (governed-open) lifecycle state. Any unknown
            // stays silent rather than guessing.
            let missing = match ctx.summary_present {
                Some(false) => true,
                Some(true) => {
                    ctx.summary_changed_in_write == Some(false)
                        && ctx.summary_changed_since_active == Some(false)
                }
                None => return Ok(Vec::new()),
            };
            if !missing {
                return Ok(Vec::new());
            }
            Ok(vec![Advisory {
                advisor_id: self.id().to_owned(),
                version: self.version().to_owned(),
                manifest_digest: self.digest.clone(),
                code: "completion_outcome.missing".to_owned(),
                record_id: ctx.record_id.clone(),
                message: "Warning: this task was marked completed without a recorded outcome. \
                    Set its summary to describe what was achieved \
                    (the same update_record can carry `summary`)."
                    .to_owned(),
                level: self.level,
                details: Some(serde_json::json!({
                    "lifecycle_before": ctx.lifecycle_before,
                    "lifecycle_after": ctx.lifecycle_after,
                })),
            }])
        })
    }
}

struct ReleaseAfterCompletionAdvisor {
    id: String,
    version: String,
    digest: Option<String>,
    level: AdvisoryLevel,
}

impl Advisor for ReleaseAfterCompletionAdvisor {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn watches(&self, tool: &str, record_type: &str, _record_kind: &str) -> bool {
        matches!(tool, "create_record" | "update_record") && record_type == "WorkItem"
    }

    fn needs_completion_context(&self) -> bool {
        true
    }

    fn advise<'a>(
        &'a self,
        ctx: &'a AdviceContext,
    ) -> BoxFuture<'a, crate::error::Result<Vec<Advisory>>> {
        Box::pin(async move {
            if !completion_transition(ctx) {
                return Ok(Vec::new());
            }
            if ctx.claim_held != Some(true) {
                return Ok(Vec::new());
            }
            let message = if ctx.writer_holds_claim == Some(true) {
                "You completed this task and still hold a claim on it. \
                Consider releasing it: start_work with action \"release\"."
            } else {
                "You completed this task. It is still claimed by another run; \
                they may want to release it."
            };
            Ok(vec![Advisory {
                advisor_id: self.id().to_owned(),
                version: self.version().to_owned(),
                manifest_digest: self.digest.clone(),
                code: "release_after_completion.claim_held".to_owned(),
                record_id: ctx.record_id.clone(),
                message: message.to_owned(),
                level: self.level,
                details: Some(serde_json::json!({
                    "claim_held": true,
                    "writer_holds_claim": ctx.writer_holds_claim,
                })),
            }])
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::manifest::Watches;
    use super::*;

    fn make_manifest(endpoint: &str) -> (AdvisorManifest, String) {
        let manifest = AdvisorManifest {
            id: "test.builtin".into(),
            version: "0.1.0".into(),
            description: "test".into(),
            endpoint: endpoint.into(),
            watches: Watches {
                tools: vec!["update_record".into()],
                types: vec!["*".into()],
                kinds: vec!["*".into()],
            },
            context: vec![],
            budget_ms: 150,
            enabled: true,
            settings: Some(serde_json::json!({"threshold": 3})),
        };
        let digest =
            super::super::manifest::digest_value(&serde_json::to_value(&manifest).unwrap());
        (manifest, digest)
    }

    #[tokio::test]
    async fn resolves_known_builtin_and_fires() {
        let (manifest, digest) = make_manifest("builtin:test");
        let advisor = builtin_advisor(&manifest, &digest).expect("test builtin resolves");
        assert!(advisor.watches("update_record", "WorkItem", "task"));
        assert!(!advisor.watches("create_record", "WorkItem", "task"));
        let ctx = AdviceContext {
            tool: "update_record".into(),
            record_id: "rec-1".into(),
            record_type: "WorkItem".into(),
            record_kind: "task".into(),
            record_name: None,
            body_chars_before: None,
            body_chars_after: None,
            recent_body_revisions: None,
            recent_same_run_append_streak: None,
            links_out_count: None,
            mentions_out_count: None,
            run_key: None,
            lifecycle_before: None,
            lifecycle_after: None,
            lifecycle_before_terminality: None,
            lifecycle_after_terminality: None,
            summary_changed_in_write: None,
            summary_changed_since_active: None,
            summary_present: None,
            claim_held: None,
            writer_holds_claim: None,
        };
        let out = advisor.advise(&ctx).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].manifest_digest, Some(digest));
        assert!(out[0].message.contains("threshold"));
    }

    fn long_record_manifest() -> (AdvisorManifest, String) {
        let manifest = AdvisorManifest {
            id: "native.long_record".into(),
            version: "0.1.0".into(),
            description: "long-record probe".into(),
            endpoint: "builtin:long_record".into(),
            watches: Watches {
                tools: vec!["update_record".into()],
                types: vec!["WorkItem".into(), "Document".into()],
                kinds: vec!["task".into(), "note".into()],
            },
            context: vec![],
            budget_ms: 150,
            enabled: true,
            settings: None,
        };
        let digest =
            super::super::manifest::digest_value(&serde_json::to_value(&manifest).unwrap());
        (manifest, digest)
    }

    #[tokio::test]
    async fn long_record_resolves_with_manifest_identity_and_fires() {
        let (manifest, digest) = long_record_manifest();
        let advisor = builtin_advisor(&manifest, &digest).expect("long_record resolves");
        assert_eq!(advisor.id(), "native.long_record");
        assert!(advisor.watches("update_record", "WorkItem", "task"));
        assert!(advisor.watches("update_record", "Document", "note"));
        let ctx = AdviceContext {
            tool: "update_record".into(),
            record_id: "rec-1".into(),
            record_type: "WorkItem".into(),
            record_kind: "task".into(),
            record_name: None,
            body_chars_before: Some(10),
            body_chars_after: Some(41_000),
            recent_body_revisions: Some(5),
            recent_same_run_append_streak: None,
            links_out_count: None,
            mentions_out_count: None,
            run_key: None,
            lifecycle_before: None,
            lifecycle_after: None,
            lifecycle_before_terminality: None,
            lifecycle_after_terminality: None,
            summary_changed_in_write: None,
            summary_changed_since_active: None,
            summary_present: None,
            claim_held: None,
            writer_holds_claim: None,
        };
        let out = advisor.advise(&ctx).await.unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, "task_body_length_advisory");
        assert_eq!(out[0].manifest_digest, Some(digest));
        assert!(out[0].message.contains("40000"));
    }

    #[test]
    fn unknown_builtin_and_http_resolve_to_none() {
        let (manifest, digest) = make_manifest("builtin:nope");
        assert!(builtin_advisor(&manifest, &digest).is_none());
        let (manifest, digest) = make_manifest("http://127.0.0.1:9/x");
        assert!(builtin_advisor(&manifest, &digest).is_none());
    }

    // --- completion advisors: shared harness ---

    async fn completion_setup() -> (crate::db::Db, crate::mcp::ToolRegistry) {
        let db = crate::create_database(":memory:").await.unwrap();
        // Generous hook budget: these are presence/behaviour assertions,
        // not budget assertions — a loaded runner must not flip them into
        // silence. Scoped to this test Db; budget tests never opt in.
        db.advisors()
            .set_test_timeout_ms(crate::mcp::advisors::TEST_ADVISOR_BUDGET_MS);
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        (db, registry)
    }

    /// Run keys are validated (`handle-disambiguator-run_id`) and travel in
    /// the arguments envelope — dispatch lifts them there and rebuilds the
    /// caller's run context from them, so setting them on the `Caller`
    /// alone would leave `claimed_run_key` null. Short names map to fixed
    /// wordlist-shaped keys.
    fn valid_run_key(short: &str) -> &'static str {
        match short {
            "run-1" => "scout-chair-a748b2",
            "run-2" => "scout-chair-b748b2",
            "run-a" => "pilot-river-b748b2",
            "run-b" => "otter-field-d748b2",
            _ => panic!("unknown test run short name"),
        }
    }

    async fn create_task(
        db: &crate::db::Db,
        registry: &crate::mcp::ToolRegistry,
        run: &str,
        extra: serde_json::Value,
    ) -> String {
        let mut args = serde_json::json!({
            "type": "WorkItem",
            "kind": "task",
            "name": "completion probe",
            "body": "probe prose",
            "reason": "seed a completion probe",
            "run_key": valid_run_key(run),
        });
        for (key, value) in extra.as_object().unwrap() {
            args[key] = value.clone();
        }
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                args,
            )
            .await
            .unwrap();
        created["id"].as_str().unwrap().to_owned()
    }

    async fn update(
        db: &crate::db::Db,
        registry: &crate::mcp::ToolRegistry,
        run: &str,
        id: &str,
        extra: serde_json::Value,
    ) -> serde_json::Value {
        let mut args = serde_json::json!({
            "id": id,
            "reason": "drive a completion probe",
            "run_key": valid_run_key(run),
        });
        for (key, value) in extra.as_object().unwrap() {
            args[key] = value.clone();
        }
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                args,
            )
            .await
            .unwrap()
    }

    async fn claim(db: &crate::db::Db, registry: &crate::mcp::ToolRegistry, run: &str, id: &str) {
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "start_work",
                serde_json::json!({
                    "record_id": id,
                    "action": "claim",
                    "run_key": valid_run_key(run),
                }),
            )
            .await
            .unwrap();
    }

    fn advisories_by_code<'a>(
        receipt: &'a serde_json::Value,
        code: &str,
    ) -> Vec<&'a serde_json::Value> {
        receipt
            .get("advisories")
            .and_then(serde_json::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter(|item| item.get("code").and_then(|c| c.as_str()) == Some(code))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A completing update: move to `in_progress` first (creation defaults to
    /// `open`), then complete. Mirrors the real task story in every test.
    async fn complete(
        db: &crate::db::Db,
        registry: &crate::mcp::ToolRegistry,
        run: &str,
        id: &str,
        extra: serde_json::Value,
    ) -> serde_json::Value {
        update(
            db,
            registry,
            run,
            id,
            serde_json::json!({"lifecycle": "in_progress"}),
        )
        .await;
        let mut args = serde_json::json!({"lifecycle": "completed"});
        for (key, value) in extra.as_object().unwrap() {
            args[key] = value.clone();
        }
        update(db, registry, run, id, args).await
    }

    #[tokio::test]
    async fn outcome_fires_on_completed_with_empty_summary() {
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        let id = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        let completed = complete(&db, &registry, "run-1", &id, serde_json::json!({})).await;
        let found = advisories_by_code(&completed, "completion_outcome.missing");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["level"], serde_json::json!("warn"));
        assert_eq!(
            found[0]["advisor_id"],
            serde_json::json!(COMPLETION_OUTCOME_ADVISOR_ID)
        );
        assert!(found[0]["message"].as_str().unwrap().contains("summary"));
        db.close().await;
    }

    #[tokio::test]
    async fn outcome_fires_on_stale_summary_set_before_active() {
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        // Summary recorded at creation, while the task is still `open`: the
        // later entries into `in_progress` make it stale.
        let id = create_task(
            &db,
            &registry,
            "run-1",
            serde_json::json!({"summary": "initial sketch"}),
        )
        .await;
        let completed = complete(&db, &registry, "run-1", &id, serde_json::json!({})).await;
        assert_eq!(
            advisories_by_code(&completed, "completion_outcome.missing").len(),
            1
        );
        db.close().await;
    }

    #[tokio::test]
    async fn outcome_silent_when_same_value_rewrite_follows_summary() {
        // in_progress (10) → summary-only (11) → re-sent in_progress (12) →
        // completed with no new summary (13): the rewrite at 12 is not an
        // entry into active, so the marker stays at 10 and the summary from
        // 11 counts as recorded since active. Must stay silent.
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        let id = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"lifecycle": "in_progress"}),
        )
        .await;
        update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"summary": "outcome recorded while active"}),
        )
        .await;
        update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"lifecycle": "in_progress"}),
        )
        .await;
        let completed = update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"lifecycle": "completed"}),
        )
        .await;
        assert!(completed.get("advisories").is_none());
        // Positive control in the same run: a second task completed with no
        // recorded outcome still warns, so a timed-out (silent) hook fails
        // this test instead of passing it vacuously.
        let other = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        let completed_other =
            complete(&db, &registry, "run-1", &other, serde_json::json!({})).await;
        assert_eq!(
            advisories_by_code(&completed_other, "completion_outcome.missing").len(),
            1
        );
        db.close().await;
    }

    #[tokio::test]
    async fn outcome_fires_without_summary_despite_same_value_rewrite() {
        // Control for the above: the same sequence minus the summary update
        // leaves no recorded outcome, so completing still warns.
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        let id = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"lifecycle": "in_progress"}),
        )
        .await;
        update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"lifecycle": "in_progress"}),
        )
        .await;
        let completed = update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"lifecycle": "completed"}),
        )
        .await;
        assert_eq!(
            advisories_by_code(&completed, "completion_outcome.missing").len(),
            1
        );
        db.close().await;
    }

    #[tokio::test]
    async fn outcome_silent_when_completing_write_sets_summary() {
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        let id = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        let completed = complete(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"summary": "shipped the probe"}),
        )
        .await;
        assert!(completed.get("advisories").is_none());
        db.close().await;
    }

    #[tokio::test]
    async fn outcome_silent_when_summary_updated_after_active_by_another_run() {
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        let id = create_task(&db, &registry, "run-a", serde_json::json!({})).await;
        // Richard's case: another run records the outcome after the task
        // became active; a later completion by a different run stays silent.
        update(
            &db,
            &registry,
            "run-a",
            &id,
            serde_json::json!({"lifecycle": "in_progress"}),
        )
        .await;
        update(
            &db,
            &registry,
            "run-a",
            &id,
            serde_json::json!({"summary": "run A did the work"}),
        )
        .await;
        let completed = update(
            &db,
            &registry,
            "run-b",
            &id,
            serde_json::json!({"lifecycle": "completed"}),
        )
        .await;
        assert!(completed.get("advisories").is_none());
        db.close().await;
    }

    #[tokio::test]
    async fn outcome_silent_for_non_workitem_and_non_terminal_writes() {
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        db.advisors().register(release_after_completion_advisor());
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                serde_json::json!({
                    "type": "Document", "kind": "note",
                    "name": "not a task", "body": "probe",
                    "reason": "non-WorkItem must stay silent",
                }),
            )
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        let updated = update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"body_append": " plus"}),
        )
        .await;
        assert!(updated.get("advisories").is_none());
        // A non-terminal WorkItem transition stays silent too.
        let task = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        let moved = update(
            &db,
            &registry,
            "run-1",
            &task,
            serde_json::json!({"lifecycle": "in_progress"}),
        )
        .await;
        assert!(moved.get("advisories").is_none());
        db.close().await;
    }

    #[tokio::test]
    async fn outcome_silent_for_completed_rewrite_and_cancellation() {
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        let id = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        // Complete with an outcome: silent.
        complete(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"summary": "done"}),
        )
        .await;
        // A same-value completed rewrite alongside a body edit is not a new
        // completion: the lifecycle never moved on this write.
        let rewritten = update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"lifecycle": "completed", "body_append": " plus"}),
        )
        .await;
        assert!(rewritten.get("advisories").is_none());
        // Cancellation (terminal-negative) never asks for an outcome.
        let other = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        update(
            &db,
            &registry,
            "run-1",
            &other,
            serde_json::json!({"lifecycle": "in_progress"}),
        )
        .await;
        let closed = update(
            &db,
            &registry,
            "run-1",
            &other,
            serde_json::json!({"lifecycle": "closed"}),
        )
        .await;
        assert!(closed.get("advisories").is_none());
        db.close().await;
    }

    #[tokio::test]
    async fn outcome_fires_on_create_completed_without_summary() {
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                serde_json::json!({
                    "type": "WorkItem", "kind": "task",
                    "name": "born done", "body": "probe",
                    "lifecycle": "completed",
                    "reason": "created already completed",
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            advisories_by_code(&created, "completion_outcome.missing").len(),
            1
        );
        db.close().await;
    }

    #[tokio::test]
    async fn release_fires_for_self_holder_with_self_wording() {
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        db.advisors().register(release_after_completion_advisor());
        let id = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        claim(&db, &registry, "run-1", &id).await;
        // The completing write sets the summary, so only the release nudge
        // may fire.
        let completed = complete(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"summary": "done and claimed"}),
        )
        .await;
        assert!(advisories_by_code(&completed, "completion_outcome.missing").is_empty());
        let found = advisories_by_code(&completed, "release_after_completion.claim_held");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["level"], serde_json::json!("advise"));
        assert!(found[0]["message"]
            .as_str()
            .unwrap()
            .contains("still hold a claim"));
        assert!(found[0]["message"].as_str().unwrap().contains("release"));
        db.close().await;
    }

    #[tokio::test]
    async fn release_fires_for_other_holder_with_other_wording() {
        let (db, registry) = completion_setup().await;
        db.advisors().register(release_after_completion_advisor());
        let id = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        claim(&db, &registry, "run-1", &id).await;
        let completed = complete(
            &db,
            &registry,
            "run-2",
            &id,
            serde_json::json!({"summary": "done by run-2"}),
        )
        .await;
        let found = advisories_by_code(&completed, "release_after_completion.claim_held");
        assert_eq!(found.len(), 1);
        assert!(found[0]["message"]
            .as_str()
            .unwrap()
            .contains("claimed by another run"));
        db.close().await;
    }

    #[tokio::test]
    async fn release_silent_without_claim_or_transition() {
        let (db, registry) = completion_setup().await;
        db.advisors().register(completion_outcome_advisor());
        db.advisors().register(release_after_completion_advisor());
        // Completion with an outcome and no claim: nothing fires at all.
        let id = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        let completed = complete(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"summary": "done unclaimed"}),
        )
        .await;
        assert!(completed.get("advisories").is_none());
        // A held claim on a non-completion write: still silent.
        let other = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        claim(&db, &registry, "run-1", &other).await;
        let edited = update(
            &db,
            &registry,
            "run-1",
            &other,
            serde_json::json!({"body_append": " plus"}),
        )
        .await;
        assert!(edited.get("advisories").is_none());
        db.close().await;
    }

    fn completion_manifest(id: &str, endpoint: &str) -> (AdvisorManifest, String) {
        let (mut manifest, _) = make_manifest(endpoint);
        manifest.id = id.to_owned();
        let digest =
            super::super::manifest::digest_value(&serde_json::to_value(&manifest).unwrap());
        (manifest, digest)
    }

    #[test]
    fn completion_builtins_resolve_and_watch_workitem_writes() {
        let (manifest, digest) =
            completion_manifest(COMPLETION_OUTCOME_ADVISOR_ID, "builtin:completion_outcome");
        let advisor = builtin_advisor(&manifest, &digest).expect("completion_outcome resolves");
        // Emission binds manifest identity, so install-id reconciliation
        // (replace/suppress by id) addresses the firing advisor.
        assert_eq!(advisor.id(), COMPLETION_OUTCOME_ADVISOR_ID);
        assert!(advisor.watches("update_record", "WorkItem", "task"));
        assert!(advisor.watches("create_record", "WorkItem", "task"));
        assert!(!advisor.watches("update_record", "Document", "note"));
        assert!(!advisor.watches("archive_record", "WorkItem", "task"));
        let (manifest, digest) = completion_manifest(
            RELEASE_AFTER_COMPLETION_ADVISOR_ID,
            "builtin:release_after_completion",
        );
        let advisor =
            builtin_advisor(&manifest, &digest).expect("release_after_completion resolves");
        assert_eq!(advisor.id(), RELEASE_AFTER_COMPLETION_ADVISOR_ID);
        assert!(advisor.watches("update_record", "WorkItem", "epic"));
        assert!(!advisor.watches("update_record", "WorkItem ", "task"));
    }

    /// Records every context it sees so tests can prove which completion
    /// fields the hook filled — and which expensive reads it skipped.
    struct RecordingAdvisor {
        seen: std::sync::Arc<std::sync::Mutex<Vec<AdviceContext>>>,
    }

    impl Advisor for RecordingAdvisor {
        fn id(&self) -> &str {
            "test.recorder"
        }

        fn version(&self) -> &str {
            "0.0.1"
        }

        fn watches(&self, tool: &str, record_type: &str, _record_kind: &str) -> bool {
            matches!(tool, "create_record" | "update_record") && record_type == "WorkItem"
        }

        fn needs_completion_context(&self) -> bool {
            true
        }

        fn advise<'a>(
            &'a self,
            ctx: &'a AdviceContext,
        ) -> BoxFuture<'a, crate::error::Result<Vec<Advisory>>> {
            let seen = self.seen.clone();
            let ctx = ctx.clone();
            Box::pin(async move {
                seen.lock().unwrap().push(ctx);
                Ok(Vec::new())
            })
        }
    }

    #[tokio::test]
    async fn completion_fill_skips_what_the_gate_cannot_use() {
        let (db, registry) = completion_setup().await;
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        db.advisors()
            .register(Arc::new(RecordingAdvisor { seen: seen.clone() }));
        let last_ctx = || seen.lock().unwrap().last().cloned().unwrap();
        let id = create_task(&db, &registry, "run-1", serde_json::json!({})).await;
        // A summary-only update carries no lifecycle arg: no interpreter
        // load, no history walk — only the projection-derived summary flag.
        update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"summary": "outcome sketch"}),
        )
        .await;
        let ctx = last_ctx();
        assert_eq!(ctx.lifecycle_after_terminality, None);
        assert_eq!(ctx.lifecycle_before, None);
        assert_eq!(ctx.summary_changed_since_active, None);
        assert_eq!(ctx.summary_present, Some(true));
        // A non-terminal lifecycle update interprets `after` but skips the
        // walk: `before` stays None (with history it would be `open`).
        update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"lifecycle": "in_progress"}),
        )
        .await;
        let ctx = last_ctx();
        assert_eq!(ctx.lifecycle_after_terminality.as_deref(), Some("open"));
        assert_eq!(ctx.lifecycle_before, None);
        assert_eq!(ctx.summary_changed_since_active, None);
        // A completion runs the full fill.
        update(
            &db,
            &registry,
            "run-1",
            &id,
            serde_json::json!({"lifecycle": "completed"}),
        )
        .await;
        let ctx = last_ctx();
        assert_eq!(
            ctx.lifecycle_after_terminality.as_deref(),
            Some("terminal_positive")
        );
        assert_eq!(ctx.lifecycle_before_terminality.as_deref(), Some("open"));
        assert_eq!(ctx.summary_changed_in_write, Some(false));
        // The sketch predates the `in_progress` entry, so it is stale.
        assert_eq!(ctx.summary_changed_since_active, Some(false));
        db.close().await;
    }

    fn completion_ctx(levels: (Option<&str>, Option<&str>)) -> AdviceContext {
        AdviceContext {
            tool: "update_record".into(),
            record_id: "rec-1".into(),
            record_type: "WorkItem".into(),
            record_kind: "task".into(),
            record_name: Some("probe".into()),
            body_chars_before: None,
            body_chars_after: None,
            recent_body_revisions: None,
            recent_same_run_append_streak: None,
            links_out_count: None,
            mentions_out_count: None,
            run_key: Some("run-1".into()),
            lifecycle_before: levels.0.map(str::to_owned),
            lifecycle_after: Some("completed".into()),
            lifecycle_before_terminality: levels.0.map(str::to_owned),
            lifecycle_after_terminality: levels.1.map(str::to_owned),
            summary_changed_in_write: Some(false),
            summary_changed_since_active: Some(false),
            summary_present: Some(false),
            claim_held: Some(false),
            writer_holds_claim: Some(false),
        }
    }

    #[tokio::test]
    async fn completion_gate_uses_governed_terminality_not_tokens() {
        let advisor = completion_outcome_advisor();
        // Unknown before-terminality counts as non-terminal: fires.
        let ctx = completion_ctx((None, Some("terminal_positive")));
        assert_eq!(advisor.advise(&ctx).await.unwrap().len(), 1);
        // Terminal-negative before (cancelled/closed): silent.
        let ctx = completion_ctx((Some("terminal_negative"), Some("terminal_positive")));
        assert!(advisor.advise(&ctx).await.unwrap().is_empty());
        // Already-terminal before: silent.
        let ctx = completion_ctx((Some("terminal_positive"), Some("terminal_positive")));
        assert!(advisor.advise(&ctx).await.unwrap().is_empty());
        // Unclassified after: never terminal-positive, silent.
        let ctx = completion_ctx((Some("open"), None));
        assert!(advisor.advise(&ctx).await.unwrap().is_empty());
        // Non-WorkItem with terminal-looking values: silent.
        let mut ctx = completion_ctx((Some("open"), Some("terminal_positive")));
        ctx.record_type = "Document".into();
        assert!(advisor.advise(&ctx).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn advisor_levels_default_and_follow_settings() {
        // Defaults: outcome warns, release advises, test builtin advises.
        let ctx = completion_ctx((Some("open"), Some("terminal_positive")));
        let out = completion_outcome_advisor().advise(&ctx).await.unwrap();
        assert_eq!(out[0].level, AdvisoryLevel::Warn);
        let mut release_ctx = completion_ctx((Some("open"), Some("terminal_positive")));
        release_ctx.claim_held = Some(true);
        release_ctx.writer_holds_claim = Some(true);
        let out = release_after_completion_advisor()
            .advise(&release_ctx)
            .await
            .unwrap();
        assert_eq!(out[0].level, AdvisoryLevel::Advise);
        // Per-install override via settings.level.
        let (mut manifest, digest) = make_manifest("builtin:completion_outcome");
        manifest.settings = Some(serde_json::json!({"level": "advise"}));
        let advisor = builtin_advisor(&manifest, &digest).unwrap();
        let out = advisor.advise(&ctx).await.unwrap();
        assert_eq!(out[0].level, AdvisoryLevel::Advise);
        let (mut manifest, digest) = make_manifest("builtin:release_after_completion");
        manifest.settings = Some(serde_json::json!({"level": "warn"}));
        let advisor = builtin_advisor(&manifest, &digest).unwrap();
        let out = advisor.advise(&release_ctx).await.unwrap();
        assert_eq!(out[0].level, AdvisoryLevel::Warn);
        // Invalid values fall back to the default, never fail.
        let (mut manifest, digest) = make_manifest("builtin:completion_outcome");
        manifest.settings = Some(serde_json::json!({"level": "loud"}));
        let advisor = builtin_advisor(&manifest, &digest).unwrap();
        let out = advisor.advise(&ctx).await.unwrap();
        assert_eq!(out[0].level, AdvisoryLevel::Warn);
        let (mut manifest, digest) = make_manifest("builtin:test");
        manifest.settings = Some(serde_json::json!({"level": 7}));
        let advisor = builtin_advisor(&manifest, &digest).unwrap();
        let out = advisor.advise(&ctx).await.unwrap();
        assert_eq!(out[0].level, AdvisoryLevel::Advise);
    }
}
