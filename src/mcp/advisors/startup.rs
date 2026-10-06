//! Startup wiring: fill the registry from layered install sets.
//!
//! Entrypoints that honour `NATIVE_ADVISORS_DIR`: `mcp-stdio` (which is also
//! the binary the `native-local` standby install runs). The hosted
//! multi-account server (`held/runtime/src/serve.rs`) does NOT: per-workspace
//! installs there are a later slice (installs as Native records).
//!
//! Local binaries call [`apply_from_env`] once after opening their [`Db`].
//! Unset or empty env means the [`default_installs`] set alone. Every listed
//! install is logged on `native::advisors`; disabled installs stay listed
//! but are never activated (and suppress a same-id default, since Db
//! constructors already installed it — see [`apply_installs`]).
//!
//! Layers (lowest precedence first): [`default_installs`] overlaid by the
//! config dir, where an install with the same id overrides — or, when
//! disabled, suppresses — the earlier layer. See [`merge_layers`].

use crate::db::Db;
use crate::mcp::advisors::builtin;
use crate::mcp::advisors::builtin::builtin_advisor;
use crate::mcp::advisors::http::HttpAdvisor;
use crate::mcp::advisors::install::{
    ConfigDirSource, Install, InstallSource, InstallSourceKind, ADVISORS_DIR_ENV,
};
use crate::mcp::advisors::long_record::{DEFAULT_MILESTONES, DEFAULT_MIN_REVISIONS};
use crate::mcp::advisors::manifest::{
    digest_value, endpoint_kind, validate_manifest, AdvisorManifest, EndpointKind, Watches,
};
use crate::mcp::advisors::AdvisorRegistry;

/// The built-in default layer: the long-record nudge plus the two completion
/// advisors (`completion_outcome`, `release_after_completion`), so the
/// advisor capability is on without any env var. Db constructors install
/// this set; `apply_from_env` overlays the config dir by id, where a
/// same-id install overrides — or, when disabled, suppresses — the default.
///
/// Built once per process: every Db open clones the prebuilt installs
/// instead of re-validating and re-hashing the manifest.
pub fn default_installs() -> Vec<Install> {
    static DEFAULTS: std::sync::OnceLock<Vec<Install>> = std::sync::OnceLock::new();
    DEFAULTS.get_or_init(build_default_installs).clone()
}

fn build_default_installs() -> Vec<Install> {
    vec![
        default_install(
            "native.long_record",
            "0.1.0",
            "Nudges when a task or note body grows past length milestones, or a run uploads a body in pieces.",
            "builtin:long_record",
            Watches {
                tools: vec!["update_record".to_owned()],
                types: vec!["WorkItem".to_owned(), "Document".to_owned()],
                kinds: vec!["task".to_owned(), "note".to_owned()],
            },
            vec![
                "body_chars_before".to_owned(),
                "body_chars_after".to_owned(),
                "recent_body_revisions".to_owned(),
                "recent_same_run_append_streak".to_owned(),
            ],
            Some(serde_json::json!({
                "milestones": DEFAULT_MILESTONES,
                "min_revisions": DEFAULT_MIN_REVISIONS,
            })),
        ),
        default_install(
            builtin::COMPLETION_OUTCOME_ADVISOR_ID,
            builtin::COMPLETION_ADVISOR_VERSION,
            "Warns when a task is marked completed without a recorded outcome.",
            "builtin:completion_outcome",
            Watches {
                tools: vec!["create_record".to_owned(), "update_record".to_owned()],
                types: vec!["WorkItem".to_owned()],
                kinds: vec!["*".to_owned()],
            },
            vec![
                "lifecycle_before".to_owned(),
                "lifecycle_after".to_owned(),
                "lifecycle_before_terminality".to_owned(),
                "lifecycle_after_terminality".to_owned(),
                "summary_changed_in_write".to_owned(),
                "summary_changed_since_active".to_owned(),
                "summary_present".to_owned(),
            ],
            // Explicit default level: an install may retune it via
            // `settings.level`, exactly like the long-record thresholds.
            Some(serde_json::json!({"level": "warn"})),
        ),
        default_install(
            builtin::RELEASE_AFTER_COMPLETION_ADVISOR_ID,
            builtin::COMPLETION_ADVISOR_VERSION,
            "Advises releasing a still-held claim after completing a task.",
            "builtin:release_after_completion",
            Watches {
                tools: vec!["create_record".to_owned(), "update_record".to_owned()],
                types: vec!["WorkItem".to_owned()],
                kinds: vec!["*".to_owned()],
            },
            vec![
                "lifecycle_before".to_owned(),
                "lifecycle_after".to_owned(),
                "lifecycle_before_terminality".to_owned(),
                "lifecycle_after_terminality".to_owned(),
                "claim_held".to_owned(),
                "writer_holds_claim".to_owned(),
            ],
            Some(serde_json::json!({"level": "advise"})),
        ),
    ]
}

/// One default install: manifest, digest and [`InstallSourceKind::Default`]
/// wrapper, validated like any config-dir manifest. Same-id config-dir
/// entries override these (or, when disabled, suppress them) through the
/// usual [`merge_layers`] reconciliation.
fn default_install(
    id: &str,
    version: &str,
    description: &str,
    endpoint: &str,
    watches: Watches,
    context: Vec<String>,
    settings: Option<serde_json::Value>,
) -> Install {
    let manifest = AdvisorManifest {
        id: id.to_owned(),
        version: version.to_owned(),
        description: description.to_owned(),
        endpoint: endpoint.to_owned(),
        watches,
        context,
        budget_ms: super::ADVISOR_TIMEOUT_MS,
        enabled: true,
        settings,
    };
    let raw = serde_json::to_value(&manifest).expect("default manifest serialises");
    debug_assert!(validate_manifest(&raw).is_ok());
    let digest = digest_value(&raw);
    Install {
        advisor_id: manifest.id.clone(),
        version: manifest.version.clone(),
        manifest_digest: digest,
        manifest,
        manifest_raw: raw,
        enabled: true,
        source: InstallSourceKind::Default,
    }
}

/// Merge install layers, lowest precedence first. A later layer's install
/// with the same `advisor_id` replaces the earlier one (including a disabled
/// entry, which thereby suppresses the default). Output is sorted by id for
/// deterministic registration order.
pub fn merge_layers(layers: &[Vec<Install>]) -> Vec<Install> {
    let mut by_id: std::collections::HashMap<String, Install> = std::collections::HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for layer in layers {
        for install in layer {
            if !by_id.contains_key(&install.advisor_id) {
                order.push(install.advisor_id.clone());
            }
            by_id.insert(install.advisor_id.clone(), install.clone());
        }
    }
    order.sort();
    order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect()
}

/// Load installs from `NATIVE_ADVISORS_DIR` and register the active ones on
/// `db`. Never fails: an unreadable directory means no advisors.
pub fn apply_from_env(db: &Db) {
    let merged = match ConfigDirSource::from_env() {
        None => merge_layers(&[default_installs()]),
        Some(source) => {
            let dir = source.dir().display().to_string();
            match source.list() {
                Ok(installs) => {
                    tracing::info!(
                        target: "native::advisors",
                        dir = dir.as_str(),
                        count = installs.len(),
                        "loaded advisor installs"
                    );
                    merge_layers(&[default_installs(), installs])
                }
                Err(error) => {
                    tracing::warn!(
                        target: "native::advisors",
                        dir = dir.as_str(),
                        error = %error,
                        "failed to list advisor installs; continuing without advisors"
                    );
                    return;
                }
            }
        }
    };
    apply_installs(db.advisors(), &merged);
}

/// Build the per-Db advisor registry with the default install set applied.
/// Db constructors use this so every handle — local, hosted, or test —
/// carries the capability with no env var; [`apply_from_env`] reconciles
/// the config dir over it by id.
pub fn registry_with_defaults() -> AdvisorRegistry {
    let registry = AdvisorRegistry::default();
    apply_installs(&registry, &default_installs());
    registry
}

/// Register every enabled install on `registry`, logging each one. Pure
/// enough to reuse for the future `NativeRecordSource`: it only reads
/// `[Install]`. Reconciling, not additive: Db constructors already installed
/// the defaults, so a disabled install unregisters its same-id advisor
/// (config-dir suppression) and an enabled one replaces it (same-id
/// override or retune).
pub fn apply_installs(registry: &AdvisorRegistry, installs: &[Install]) {
    for install in installs {
        tracing::info!(
            target: "native::advisors",
            advisor_id = install.advisor_id.as_str(),
            version = install.version.as_str(),
            manifest_digest = install.manifest_digest.as_str(),
            enabled = install.enabled,
            source = %install.source,
            "advisor install"
        );
        if !install.enabled {
            registry.unregister(&install.advisor_id);
            continue;
        }
        match endpoint_kind(&install.manifest.endpoint) {
            Some(EndpointKind::Http) => {
                registry.register(std::sync::Arc::new(HttpAdvisor::new(
                    install.manifest.clone(),
                    install.manifest_digest.clone(),
                )));
            }
            Some(EndpointKind::Builtin(_)) => {
                match builtin_advisor(&install.manifest, &install.manifest_digest) {
                    Some(advisor) => registry.register(advisor),
                    None => continue,
                }
            }
            None => {
                tracing::warn!(
                    target: "native::advisors",
                    advisor_id = install.advisor_id.as_str(),
                    "advisor endpoint unusable; skipping activation"
                );
            }
        }
    }
}

/// Name of the env var, re-exported for binary entrypoints.
pub const ENV: &str = ADVISORS_DIR_ENV;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn builtin_install_from_config_dir_fires_on_update() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("nudge");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("advisor.json"),
            serde_json::json!({
                "id": "test.nudge",
                "version": "0.1.0",
                "description": "e2e builtin",
                "endpoint": "builtin:test",
                "watches": {"tools": ["update_record"], "types": ["WorkItem"], "kinds": ["task"]},
                "context": [],
                "budget_ms": 150,
                "enabled": true
            })
            .to_string(),
        )
        .unwrap();
        let db = crate::create_database(":memory:").await.unwrap();
        db.advisors()
            .set_test_timeout_ms(crate::mcp::advisors::TEST_ADVISOR_BUDGET_MS);
        let source = ConfigDirSource::new(dir.path());
        let installs = source.list().unwrap();
        assert_eq!(installs.len(), 1);
        apply_installs(db.advisors(), &installs);
        assert!(!db.advisors().is_empty());

        let mut tools = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut tools).unwrap();
        let created = tools
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": "WorkItem", "kind": "task",
                    "name": "startup probe", "body": "probe",
                    "reason": "seed a startup probe",
                }),
            )
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        let updated = tools
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({"id": id, "body_append": " plus", "reason": "fire builtin"}),
            )
            .await
            .unwrap();
        let advisories = updated["advisories"].as_array().expect("advisories fire");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0]["advisor_id"], json!("test.nudge"));
        assert_eq!(
            advisories[0]["manifest_digest"],
            json!(installs[0].manifest_digest)
        );
        db.close().await;
    }

    fn layer_install(id: &str, version: &str, enabled: bool) -> Install {
        use crate::mcp::advisors::install::InstallSourceKind;
        use crate::mcp::advisors::manifest::{AdvisorManifest, Watches};
        let manifest = AdvisorManifest {
            id: id.into(),
            version: version.into(),
            description: "layer probe".into(),
            endpoint: "builtin:test".into(),
            watches: Watches {
                tools: vec!["update_record".into()],
                types: vec!["*".into()],
                kinds: vec!["*".into()],
            },
            context: vec![],
            budget_ms: 150,
            enabled,
            settings: None,
        };
        Install {
            advisor_id: id.into(),
            version: version.into(),
            manifest_digest: "layer-digest".into(),
            manifest,
            manifest_raw: serde_json::Value::Null,
            enabled,
            source: InstallSourceKind::ConfigDir,
        }
    }

    #[test]
    fn default_installs_carry_long_record_with_valid_manifest() {
        let installs = default_installs();
        let install = installs
            .iter()
            .find(|install| install.advisor_id == "native.long_record")
            .expect("long_record default");
        assert_eq!(install.manifest.endpoint, "builtin:long_record");
        assert!(install.enabled);
        assert_eq!(install.source, InstallSourceKind::Default);
        // Valid by the same rules as a config-dir manifest, with the digest
        // pinned over the raw bytes like any other install.
        assert!(validate_manifest(&install.manifest_raw).is_ok());
        assert_eq!(install.manifest_digest, digest_value(&install.manifest_raw));
        assert_eq!(
            install.manifest.settings,
            Some(json!({"milestones": [40000, 80000, 160000], "min_revisions": 5}))
        );
        let advisor = builtin_advisor(&install.manifest, &install.manifest_digest)
            .expect("default long_record resolves");
        assert!(advisor.watches("update_record", "WorkItem", "task"));
        assert!(!advisor.watches("create_record", "WorkItem", "task"));
    }

    #[test]
    fn default_installs_carry_completion_advisors_with_default_levels() {
        let installs = default_installs();
        assert_eq!(installs.len(), 3);
        for (id, endpoint, level) in [
            (
                builtin::COMPLETION_OUTCOME_ADVISOR_ID,
                "builtin:completion_outcome",
                "warn",
            ),
            (
                builtin::RELEASE_AFTER_COMPLETION_ADVISOR_ID,
                "builtin:release_after_completion",
                "advise",
            ),
        ] {
            let install = installs
                .iter()
                .find(|install| install.advisor_id == id)
                .unwrap_or_else(|| panic!("{id} default"));
            assert_eq!(install.manifest.endpoint, endpoint);
            assert!(install.enabled);
            assert_eq!(install.source, InstallSourceKind::Default);
            assert!(validate_manifest(&install.manifest_raw).is_ok());
            assert_eq!(install.manifest_digest, digest_value(&install.manifest_raw));
            assert_eq!(
                install.manifest.settings,
                Some(json!({"level": level})),
                "{id} ships its default level as an install setting"
            );
            let advisor = builtin_advisor(&install.manifest, &install.manifest_digest)
                .unwrap_or_else(|| panic!("{id} resolves"));
            assert!(advisor.watches("update_record", "WorkItem", "task"));
            assert!(advisor.watches("create_record", "WorkItem", "task"));
            assert!(!advisor.watches("update_record", "Document", "note"));
        }
    }

    #[tokio::test]
    async fn completion_advisors_fire_end_to_end_from_defaults() {
        // No manual registration: the Db carries the default installs, so
        // this proves the default path fires through a real update_record
        // completion (the completing receipt carries the advisory).
        let db = crate::create_database(":memory:").await.unwrap();
        db.advisors()
            .set_test_timeout_ms(crate::mcp::advisors::TEST_ADVISOR_BUDGET_MS);
        let mut tools = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut tools).unwrap();
        let created = tools
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": "WorkItem", "kind": "task",
                    "name": "defaults probe", "body": "probe",
                    "reason": "seed a defaults probe",
                }),
            )
            .await
            .unwrap();
        assert!(created.get("advisories").is_none());
        let id = created["id"].as_str().unwrap().to_owned();
        tools
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({"id": id, "lifecycle": "in_progress", "reason": "start the probe"}),
            )
            .await
            .unwrap();
        let completed = tools
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({"id": id, "lifecycle": "completed", "reason": "complete the probe"}),
            )
            .await
            .unwrap();
        let advisories = completed["advisories"]
            .as_array()
            .expect("default completion_outcome fires end to end");
        assert_eq!(advisories.len(), 1);
        assert_eq!(advisories[0]["code"], json!("completion_outcome.missing"));
        assert_eq!(advisories[0]["level"], json!("warn"));
        assert_eq!(
            advisories[0]["advisor_id"],
            json!(builtin::COMPLETION_OUTCOME_ADVISOR_ID)
        );
        db.close().await;
    }

    fn long_record_override(settings: serde_json::Value, enabled: bool) -> Install {
        let installs = default_installs();
        // Select by id: the default set carries several installs, so a
        // positional pop would grab the wrong one.
        let mut install = installs
            .iter()
            .find(|install| install.advisor_id == "native.long_record")
            .expect("long_record default")
            .clone();
        install.manifest.settings = Some(settings);
        install.manifest.enabled = enabled;
        install.enabled = enabled;
        install.source = InstallSourceKind::ConfigDir;
        install
    }

    #[tokio::test]
    async fn disabled_default_suppresses_long_record() {
        let registry = registry_with_defaults();
        assert!(registry.watches("update_record", "WorkItem", "task"));
        apply_installs(
            &registry,
            &[long_record_override(
                json!({"milestones": [40000, 80000, 160000], "min_revisions": 5}),
                false,
            )],
        );
        // The completion defaults still watch the shape, so `watches` stays
        // true; suppression is proven by firing conditions instead: a
        // milestone crossing that long_record would answer stays silent.
        assert!(registry.watches("update_record", "WorkItem", "task"));
        let ctx = crate::mcp::advisors::AdviceContext {
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
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1_000);
        let out = registry.advise_all(&ctx, deadline).await;
        assert!(
            out.iter()
                .all(|advisory| advisory.code != "task_body_length_advisory"),
            "suppressed long_record must not fire: {out:?}"
        );
    }

    #[tokio::test]
    async fn retuned_settings_replace_default_without_doubling() {
        let registry = registry_with_defaults();
        apply_installs(
            &registry,
            &[long_record_override(
                json!({"milestones": [15000, 30000], "min_revisions": 3}),
                true,
            )],
        );
        let ctx = crate::mcp::advisors::AdviceContext {
            tool: "update_record".into(),
            record_id: "rec-1".into(),
            record_type: "WorkItem".into(),
            record_kind: "task".into(),
            record_name: None,
            body_chars_before: Some(10),
            body_chars_after: Some(16_000),
            recent_body_revisions: Some(3),
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
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(1_000);
        let out = registry.advise_all(&ctx, deadline).await;
        // Exactly one advisory at the retuned milestone: the override
        // replaced the default rather than doubling it.
        assert_eq!(out.len(), 1);
        assert!(out[0].message.contains("15000"));
    }

    #[test]
    fn later_layer_overrides_or_suppresses_same_id() {
        let base = vec![layer_install("a", "1", true), layer_install("b", "1", true)];
        let higher = vec![
            layer_install("b", "2", true),
            layer_install("a", "1", false),
        ];
        let merged = merge_layers(&[base, higher]);
        assert_eq!(merged.len(), 2);
        let by_id: std::collections::HashMap<_, _> = merged
            .iter()
            .map(|install| (install.advisor_id.as_str(), install))
            .collect();
        assert_eq!(by_id["b"].version, "2");
        assert!(by_id["b"].enabled);
        assert!(!by_id["a"].enabled);
    }
}
