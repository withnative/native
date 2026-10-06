//! Gated S2a public registry tests: admission/read/call happy paths, label
//! uniqueness, engine veto/fixture/unavailable typing, off-runtime validation,
//! uniform hidden-scope refusal, stale Conflict, replacement/settings/
//! re-enable freshness, incompatible disable, call language/build rules,
//! eligibility, integrity refusal, and request shape. No evaluator, no K6a.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::error::Error;
use crate::events::KERNEL_ROOT_ID;
use crate::kernel::{create_home, create_principal, create_v2_database};
use crate::query::rule_install::{
    EngineValidationEvidence, ParameterDecl, ParameterSource, RuleCardinality, RuleInputDecl,
    RuleRevision, RuleValidationError, RuleValidationRequest, RuleValidator,
};
use crate::rule_registry::{
    disable_rule, inspect_rule, prepare_rule_call, register_rule, RuleAdmissionRequest,
    RuleRegistryError,
};

/// Accepting test engine: echoes digests/language, stamps a NON-reserved id.
/// Never the fixture identity — storage must never see fixture evidence.
struct AcceptValidator {
    engine: String,
    calls: AtomicUsize,
}

impl AcceptValidator {
    fn new(engine: &str) -> Self {
        Self {
            engine: engine.to_owned(),
            calls: AtomicUsize::new(0),
        }
    }
}

impl RuleValidator for AcceptValidator {
    fn validate(
        &self,
        request: RuleValidationRequest<'_>,
    ) -> std::result::Result<EngineValidationEvidence, RuleValidationError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(EngineValidationEvidence {
            revision_digest: request.revision_digest.to_owned(),
            settings_digest: request.settings_digest.to_owned(),
            language_identity: request.revision.language.clone(),
            policy_version: "g3-1".to_owned(),
            engine_id: self.engine.clone(),
            engine_version: "1.0".to_owned(),
            bundle_sha256: None,
        })
    }
}

/// Always-veto test engine with a caller-chosen authoring failure.
struct VetoValidator {
    error: RuleValidationError,
}

impl RuleValidator for VetoValidator {
    fn validate(
        &self,
        request: RuleValidationRequest<'_>,
    ) -> std::result::Result<EngineValidationEvidence, RuleValidationError> {
        let _ = request;
        Err(self.error.clone())
    }
}

/// Blocking test engine: signals start (with its thread id) on entry, then
/// waits on a channel, proving validation runs off the writer path while
/// blocked. The receiver sits behind a `Mutex` because the trait is `Sync`.
struct BlockingValidator {
    started: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<std::thread::ThreadId>>>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl RuleValidator for BlockingValidator {
    fn validate(
        &self,
        request: RuleValidationRequest<'_>,
    ) -> std::result::Result<EngineValidationEvidence, RuleValidationError> {
        if let Some(tx) = self.started.lock().unwrap().take() {
            let _ = tx.send(std::thread::current().id());
        }
        self.release
            .lock()
            .unwrap()
            .recv_timeout(std::time::Duration::from_secs(30))
            .expect("test releases the validator");
        Ok(EngineValidationEvidence {
            revision_digest: request.revision_digest.to_owned(),
            settings_digest: request.settings_digest.to_owned(),
            language_identity: request.revision.language.clone(),
            policy_version: "g3-1".to_owned(),
            engine_id: "test-engine".to_owned(),
            engine_version: "1.0".to_owned(),
            bundle_sha256: None,
        })
    }
}

fn sample_revision() -> RuleRevision {
    RuleRevision {
        scalar_arguments: vec![],
        binding_contract: None,
        namespace: "acme".to_owned(),
        name: "overdue".to_owned(),
        language: "cel-subset@1".to_owned(),
        inputs: vec![RuleInputDecl {
            contract: None,
            name: "deal".to_owned(),
            sql: "SELECT id FROM records WHERE id = ?1".to_owned(),
            cardinality: RuleCardinality::One,
            required_fields: vec!["id".to_owned()],
            parameters: vec![ParameterDecl {
                slot: 1,
                param_type: "text".to_owned(),
                nullable: false,
                source: ParameterSource::Argument {
                    name: "bid".to_owned(),
                },
            }],
        }],
        clauses: "true".to_owned(),
        examples: vec![],
        definition_pins: vec![],
    }
}

fn settings() -> serde_json::Value {
    serde_json::json!({"level": "advise"})
}

fn request(scope: &str, revision: RuleRevision) -> RuleAdmissionRequest {
    RuleAdmissionRequest {
        scope_home: scope.to_owned(),
        revision,
        settings: settings(),
        expected_seq: None,
    }
}

async fn admin_db() -> (crate::db::Db, String) {
    create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap()
}

async fn managed_scope(db: &crate::db::Db, admin: &str) -> String {
    create_home(db, KERNEL_ROOT_ID, Some(&[(admin, "manage")]), admin)
        .await
        .unwrap()
}

async fn meta_count(db: &crate::db::Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM meta_events WHERE type = 'rule_installation.set.v1'")
        .fetch_one(db.write_pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn good_admission_inspect_and_call() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    let validator: Arc<dyn RuleValidator> = Arc::new(AcceptValidator::new("test-engine"));
    let view = register_rule(&db, &admin, &validator, &request(&scope, sample_revision()))
        .await
        .unwrap();
    assert!(view.active);
    assert_eq!(view.language, "cel-subset@1");
    assert_eq!(view.inputs.len(), 1);
    assert_eq!(view.readsets["deal"].relations[0].name, "records");
    assert_eq!(view.catalog_revision, 4);
    assert_eq!(view.engine_id, "test-engine");
    // Inspect as the actor discloses; call returns the inert recipe.
    let seen = inspect_rule(&db, &admin, &scope, "acme", "overdue")
        .await
        .unwrap();
    assert_eq!(seen.actor, Some(admin.clone()));
    assert_eq!(seen, view);
    let recipe = prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "cel-subset@1")
        .await
        .unwrap();
    assert_eq!(recipe.input_order, vec!["deal".to_owned()]);
    assert_eq!(recipe.revision_digest, view.revision_digest);
    assert_eq!(recipe.engine_id, "test-engine");
    db.close().await;
}

#[tokio::test]
async fn zero_sql_fact_declarations_reach_validator_and_pinned_call_recipe() {
    use crate::rule_registry::{
        BindingContractVersion, CompletionFact, ScalarArgument, ScalarSource, ScalarType,
    };
    struct Capture(std::sync::Mutex<Vec<RuleRevision>>);
    impl RuleValidator for Capture {
        fn validate(
            &self,
            request: RuleValidationRequest<'_>,
        ) -> std::result::Result<EngineValidationEvidence, RuleValidationError> {
            self.0.lock().unwrap().push(request.revision.clone());
            AcceptValidator::new("test-engine").validate(request)
        }
    }
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    let capture = Arc::new(Capture(std::sync::Mutex::new(vec![])));
    let validator: Arc<dyn RuleValidator> = capture.clone();
    let mut revision = sample_revision();
    revision.inputs.clear();
    revision.binding_contract = Some(BindingContractVersion::ScalarRowsV1);
    revision.scalar_arguments = vec![ScalarArgument {
        name: "fact".into(),
        scalar_type: ScalarType::Bool,
        nullable: true,
        source: ScalarSource::CompletionV1 {
            fact: CompletionFact::CompletionTransition,
        },
    }];
    let mut admission = request(&scope, revision.clone());
    admission.settings = serde_json::json!({});
    let first = register_rule(&db, &admin, &validator, &admission)
        .await
        .unwrap();
    let recipe = prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "cel-subset@1")
        .await
        .unwrap();
    assert_eq!(recipe.revision, revision);
    assert!(recipe.input_order.is_empty());
    assert_eq!(*capture.0.lock().unwrap(), [revision]);
    admission.expected_seq = Some(first.event_seq);
    admission.revision.scalar_arguments[0].source = ScalarSource::CompletionV1 {
        fact: CompletionFact::ClaimHeld,
    };
    let second = register_rule(&db, &admin, &validator, &admission)
        .await
        .unwrap();
    assert_ne!(second.revision_digest, first.revision_digest);
    assert_eq!(capture.0.lock().unwrap().len(), 2);
    assert_eq!(
        inspect_rule(&db, &admin, &scope, "acme", "overdue")
            .await
            .unwrap()
            .revision,
        admission.revision
    );
    db.close().await;
}

#[tokio::test]
async fn duplicate_labels_and_ineligible_relations_refuse_without_append() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    let validator: Arc<dyn RuleValidator> = Arc::new(AcceptValidator::new("test-engine"));
    for sql in [
        "SELECT id, id FROM records",
        "SELECT activity_id FROM agent_activity",
        "SELECT message_id FROM messages_awaiting_reply",
        "SELECT count(*) FROM records WHERE id = ?1 OR id = ?3",
    ] {
        let mut revision = sample_revision();
        revision.inputs[0].sql = sql.to_owned();
        revision.inputs[0].required_fields = vec![];
        revision.inputs[0].parameters = vec![];
        let before = meta_count(&db).await;
        let err = register_rule(&db, &admin, &validator, &request(&scope, revision))
            .await
            .unwrap_err();
        assert!(
            !matches!(err, RuleRegistryError::Validation(_)),
            "{sql}: {err}"
        );
        assert_eq!(meta_count(&db).await, before, "{sql}");
    }
    db.close().await;
}

#[tokio::test]
async fn engine_veto_fixture_and_unavailable_typing() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    // Authoring veto preserves its code, never retries, appends nothing.
    let veto: Arc<dyn RuleValidator> = Arc::new(VetoValidator {
        error: RuleValidationError::Parse {
            message: "bad clause".to_owned(),
        },
    });
    let before = meta_count(&db).await;
    let err = register_rule(&db, &admin, &veto, &request(&scope, sample_revision()))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RuleRegistryError::Validation(RuleValidationError::Parse { .. })
    ));
    assert!(!err.is_retryable());
    assert_eq!(meta_count(&db).await, before);
    for failure in [
        RuleValidationError::CapCost {
            message: "static work cap exceeded".to_owned(),
        },
        RuleValidationError::EngineFault {
            message: "guest protocol fault".to_owned(),
        },
    ] {
        let veto: Arc<dyn RuleValidator> = Arc::new(VetoValidator {
            error: failure.clone(),
        });
        let err = register_rule(&db, &admin, &veto, &request(&scope, sample_revision()))
            .await
            .unwrap_err();
        assert!(matches!(&err, RuleRegistryError::Validation(actual) if actual == &failure));
        assert!(!err.is_retryable());
        assert_eq!(meta_count(&db).await, before);
    }
    // Fixture engine evidence is refused on the admission path too.
    struct FixtureEcho;
    impl RuleValidator for FixtureEcho {
        fn validate(
            &self,
            request: RuleValidationRequest<'_>,
        ) -> std::result::Result<EngineValidationEvidence, RuleValidationError> {
            Ok(EngineValidationEvidence {
                revision_digest: request.revision_digest.to_owned(),
                settings_digest: request.settings_digest.to_owned(),
                language_identity: request.revision.language.clone(),
                policy_version: "fixture-policy-0".to_owned(),
                engine_id: crate::query::rule_install::FIXTURE_ENGINE_ID.to_owned(),
                engine_version: "0.0.0-fixture".to_owned(),
                bundle_sha256: None,
            })
        }
    }
    let fixture: Arc<dyn RuleValidator> = Arc::new(FixtureEcho);
    let err = register_rule(&db, &admin, &fixture, &request(&scope, sample_revision()))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("fixture"), "{err}");
    assert_eq!(meta_count(&db).await, before);
    // Transport failure is the only retryable code.
    let down: Arc<dyn RuleValidator> = Arc::new(VetoValidator {
        error: RuleValidationError::EngineUnavailable {
            message: "sandbox gone".to_owned(),
        },
    });
    let err = register_rule(&db, &admin, &down, &request(&scope, sample_revision()))
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RuleRegistryError::Validation(RuleValidationError::EngineUnavailable { .. })
    ));
    assert!(err.is_retryable());
    assert_eq!(meta_count(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn wrapper_rejects_malformed_and_mismatched_evidence() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    // Evidence with empty engine id fails shape validation at the wrapper.
    let malformed: Arc<dyn RuleValidator> = Arc::new(VetoValidator {
        error: RuleValidationError::Parse {
            message: "unused".to_owned(),
        },
    });
    let _ = malformed;
    struct EmptyEngine;
    impl RuleValidator for EmptyEngine {
        fn validate(
            &self,
            request: RuleValidationRequest<'_>,
        ) -> std::result::Result<EngineValidationEvidence, RuleValidationError> {
            Ok(EngineValidationEvidence {
                revision_digest: request.revision_digest.to_owned(),
                settings_digest: request.settings_digest.to_owned(),
                language_identity: request.revision.language.clone(),
                policy_version: "g3-1".to_owned(),
                engine_id: String::new(),
                engine_version: "1.0".to_owned(),
                bundle_sha256: None,
            })
        }
    }
    struct WrongDigest;
    impl RuleValidator for WrongDigest {
        fn validate(
            &self,
            request: RuleValidationRequest<'_>,
        ) -> std::result::Result<EngineValidationEvidence, RuleValidationError> {
            Ok(EngineValidationEvidence {
                revision_digest: "0".repeat(64),
                settings_digest: request.settings_digest.to_owned(),
                language_identity: request.revision.language.clone(),
                policy_version: "g3-1".to_owned(),
                engine_id: "test-engine".to_owned(),
                engine_version: "1.0".to_owned(),
                bundle_sha256: None,
            })
        }
    }
    struct WrongLanguage;
    impl RuleValidator for WrongLanguage {
        fn validate(
            &self,
            request: RuleValidationRequest<'_>,
        ) -> std::result::Result<EngineValidationEvidence, RuleValidationError> {
            Ok(EngineValidationEvidence {
                revision_digest: request.revision_digest.to_owned(),
                settings_digest: request.settings_digest.to_owned(),
                language_identity: "other-lang@9".to_owned(),
                policy_version: "g3-1".to_owned(),
                engine_id: "test-engine".to_owned(),
                engine_version: "1.0".to_owned(),
                bundle_sha256: None,
            })
        }
    }
    for validator in [
        Arc::new(EmptyEngine) as Arc<dyn RuleValidator>,
        Arc::new(WrongDigest),
        Arc::new(WrongLanguage),
    ] {
        let before = meta_count(&db).await;
        let err = register_rule(&db, &admin, &validator, &request(&scope, sample_revision()))
            .await
            .unwrap_err();
        assert!(!err.is_retryable(), "{err}");
        assert_eq!(meta_count(&db).await, before, "{err}");
    }
    db.close().await;
}

#[tokio::test]
async fn validator_panic_maps_to_nonretryable_fault() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    struct PanicEngine;
    impl RuleValidator for PanicEngine {
        fn validate(
            &self,
            _request: RuleValidationRequest<'_>,
        ) -> std::result::Result<EngineValidationEvidence, RuleValidationError> {
            panic!("test engine crash")
        }
    }
    let panicking: Arc<dyn RuleValidator> = Arc::new(PanicEngine);
    let before = meta_count(&db).await;
    let err = register_rule(&db, &admin, &panicking, &request(&scope, sample_revision()))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            RuleRegistryError::Validation(RuleValidationError::EngineFault { .. })
        ),
        "{err:?}"
    );
    assert!(!err.is_retryable());
    assert_eq!(meta_count(&db).await, before);
    db.close().await;
}

#[tokio::test(flavor = "current_thread")]
async fn validation_runs_off_the_writer_path() {
    let (db, admin) = admin_db().await;
    // Delegated non-owner manager: the owner floor (kernel.rs) keeps admin's
    // Manage regardless of policy, so revocation must target this grant.
    let mgr = create_principal(&db, "account", "Mgr", "test:mgr", &admin)
        .await
        .unwrap();
    let scope = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (mgr.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel::<std::thread::ThreadId>();
    let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
    let validator: Arc<dyn RuleValidator> = Arc::new(BlockingValidator {
        started: std::sync::Mutex::new(Some(started_tx)),
        release: std::sync::Mutex::new(release_rx),
    });
    let request = request(&scope, sample_revision());
    let caller_thread = std::thread::current().id();
    let before = meta_count(&db).await;
    let (db2, mgr2) = (db.clone(), mgr.clone());
    let handle =
        tokio::spawn(async move { register_rule(&db2, &mgr2, &validator, &request).await });
    // Explicit started signal (bounded): no yield-count guessing about
    // whether the validator has begun.
    let validator_thread = tokio::time::timeout(std::time::Duration::from_secs(10), started_rx)
        .await
        .expect("validator starts promptly")
        .expect("started signal sent");
    assert_ne!(
        validator_thread, caller_thread,
        "validation left the runtime thread"
    );
    // While demonstrably blocked, an unrelated writer still acquires the
    // write lock (bounded): validation holds no write lock.
    let tx = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        crate::db::begin_write(db.write_pool()),
    )
    .await
    .expect("writer acquirable while validator blocked")
    .unwrap();
    tx.rollback().await.unwrap();
    // Revoke the delegated grant while blocked (admin keeps its own entry so
    // final state stays inspectable): the writer-tx recheck must refuse with
    // no registration event appended.
    crate::kernel::replace_home_policy(&db, &admin, &scope, &[(admin.as_str(), "manage")])
        .await
        .unwrap();
    release_tx.send(()).unwrap();
    let err = handle.await.unwrap().unwrap_err();
    assert!(
        err.to_string().contains("kernel target missing or hidden"),
        "{err}"
    );
    assert_eq!(
        meta_count(&db).await,
        before,
        "refused admission appends nothing"
    );
    db.close().await;
}

#[tokio::test]
async fn hidden_missing_and_capability_refuse_uniformly() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    let op = create_principal(&db, "account", "Op", "test:op", &admin)
        .await
        .unwrap();
    let validator: Arc<dyn RuleValidator> = Arc::new(AcceptValidator::new("test-engine"));
    let hidden = "kernel target missing or hidden";
    // No View/Manage for op: register, inspect, and call refuse identically —
    // before any validator or SQL diagnostics run.
    let refusals = [
        register_rule(&db, &op, &validator, &request(&scope, sample_revision()))
            .await
            .unwrap_err()
            .to_string(),
        inspect_rule(&db, &op, &scope, "acme", "overdue")
            .await
            .unwrap_err()
            .to_string(),
        prepare_rule_call(&db, &op, &scope, "acme", "overdue", "cel-subset@1")
            .await
            .unwrap_err()
            .to_string(),
    ];
    for refusal in &refusals {
        assert_eq!(
            refusal,
            &format!("rule registry refused: {hidden}"),
            "{refusal}"
        );
    }
    // Missing scope and missing principal refuse with the same oracle.
    let err = register_rule(
        &db,
        &admin,
        &validator,
        &request("home:absent", sample_revision()),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(err, format!("rule registry refused: {hidden}"));
    let err = register_rule(
        &db,
        "principal:absent",
        &validator,
        &request(&scope, sample_revision()),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(err, format!("rule registry refused: {hidden}"));
    db.close().await;
}

#[tokio::test]
async fn stale_expected_seq_is_typed_conflict() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    let validator: Arc<dyn RuleValidator> = Arc::new(AcceptValidator::new("test-engine"));
    let first = register_rule(&db, &admin, &validator, &request(&scope, sample_revision()))
        .await
        .unwrap();
    // Blind update and wrong seq both refuse as Conflict — never re-wrapped
    // as Engine. (Any matching seq on identical bytes is a verified no-op.)
    let mut blind = request(&scope, sample_revision());
    blind.expected_seq = None;
    let err = register_rule(&db, &admin, &validator, &blind)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RuleRegistryError::Refused(Error::Conflict(_))),
        "{err:?}"
    );
    // Create-only seq on an existing-but-empty scope refuses as Conflict.
    let empty = managed_scope(&db, &admin).await;
    let mut fresh = request(&empty, sample_revision());
    fresh.expected_seq = Some(1);
    let err = register_rule(&db, &admin, &validator, &fresh)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RuleRegistryError::Refused(Error::Conflict(_))),
        "{err:?}"
    );
    let mut stale = request(&scope, sample_revision());
    stale.expected_seq = Some(first.event_seq + 41);
    let err = register_rule(&db, &admin, &validator, &stale)
        .await
        .unwrap_err();
    assert!(
        matches!(err, RuleRegistryError::Refused(Error::Conflict(_))),
        "{err:?}"
    );
    // Cross-actor same bytes appends a fresh attributed snapshot.
    let op = create_principal(&db, "account", "Op", "test:op2", &admin)
        .await
        .unwrap();
    let scoped = create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (op.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let first = register_rule(
        &db,
        &admin,
        &validator,
        &request(&scoped, sample_revision()),
    )
    .await
    .unwrap();
    let mut cross = request(&scoped, sample_revision());
    cross.expected_seq = Some(first.event_seq);
    let moved = register_rule(&db, &op, &validator, &cross).await.unwrap();
    assert_eq!(moved.actor, Some(op.clone()));
    assert!(moved.event_seq > first.event_seq);
    db.close().await;
}

#[tokio::test]
async fn call_checks_language_not_build_and_honors_active() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    let old_build: Arc<dyn RuleValidator> = Arc::new(AcceptValidator::new("old-engine"));
    let view = register_rule(&db, &admin, &old_build, &request(&scope, sample_revision()))
        .await
        .unwrap();
    // Same language, older build/policy metadata: callable (builds never gate).
    let recipe = prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "cel-subset@1")
        .await
        .unwrap();
    assert_eq!(recipe.engine_id, "old-engine");
    assert_eq!(recipe.policy_version, "g3-1");
    // Wrong language refuses.
    let err = prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "other-lang@9")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("language"), "{err}");
    // Disabled installations refuse calls but stay inspectable.
    let disabled = disable_rule(&db, &admin, &scope, "acme", "overdue", Some(view.event_seq))
        .await
        .unwrap();
    assert!(!disabled.active);
    assert_eq!(disabled.revision_digest, view.revision_digest);
    let err = prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "cel-subset@1")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not active"), "{err}");
    let seen = inspect_rule(&db, &admin, &scope, "acme", "overdue")
        .await
        .unwrap();
    assert!(!seen.active);
    assert_eq!(seen.settings, view.settings);
    db.close().await;
}

#[tokio::test]
async fn inspection_redacts_foreign_actors_and_rejects_tamper() {
    let (db, admin) = admin_db().await;
    let op = create_principal(&db, "account", "Op", "test:op3", &admin)
        .await
        .unwrap();
    let scope = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (op.as_str(), "view")]),
        &admin,
    )
    .await
    .unwrap();
    let validator: Arc<dyn RuleValidator> = Arc::new(AcceptValidator::new("test-engine"));
    register_rule(&db, &admin, &validator, &request(&scope, sample_revision()))
        .await
        .unwrap();
    // Viewer with scope View but no root View sees no actor.
    let seen = inspect_rule(&db, &op, &scope, "acme", "overdue")
        .await
        .unwrap();
    assert_eq!(seen.actor, None);
    assert_eq!(seen.revision, sample_revision());
    // Tampered projection pins fail the call gate.
    sqlx::query("UPDATE rule_installations SET catalog_revision = 99 WHERE scope_home = ?")
        .bind(&scope)
        .execute(db.write_pool())
        .await
        .unwrap();
    let err = prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "cel-subset@1")
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("disagrees") || err.to_string().contains("incompatible"),
        "{err}"
    );
    db.close().await;
}

/// Coherent catalog/profile pins for a historical fixture: the triple travels
/// as one value so a fixture can never mix pins from different catalogs.
struct CatalogPins {
    revision: u32,
    profile_id: String,
    profile_revision: u32,
}

/// Test-only sealed-S1 historical fixture: a snapshot with old catalog pins
/// (or removed relations) that no public API could mint today. Never a
/// public proof input — drives `set_installation_in` directly, replay-free.
async fn seed_historical(
    db: &crate::db::Db,
    scope: &str,
    revision: &crate::rule_registry::RuleRevision,
    readsets: &std::collections::BTreeMap<
        String,
        native_query_contract::rule_contract::RuleInputReadset,
    >,
    pins: CatalogPins,
    actor: &str,
) -> crate::meta::rule_installation::StoredInstallation {
    use crate::query::rule_install as ri;
    let settings = settings();
    let pairs: Vec<(
        &str,
        &native_query_contract::rule_contract::RuleInputReadset,
    )> = readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let digest = ri::readset_digest(
        pins.revision,
        &pins.profile_id,
        pins.profile_revision,
        &pairs,
    );
    let evidence = EngineValidationEvidence {
        revision_digest: ri::revision_digest(revision).unwrap(),
        settings_digest: ri::settings_digest(&settings).unwrap(),
        language_identity: revision.language.clone(),
        policy_version: "g3-1".to_owned(),
        engine_id: "test-engine".to_owned(),
        engine_version: "1.0".to_owned(),
        bundle_sha256: None,
    };
    let receipt = ri::RuleAdmissionReceipt::issue(evidence, digest);
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    let (stored, appended) = crate::meta::rule_installation::set_installation_in(
        &mut tx,
        scope,
        revision,
        &settings,
        pins.revision,
        &pins.profile_id,
        pins.profile_revision,
        readsets,
        &receipt,
        true,
        None,
        Some(actor),
        &mut alloc,
    )
    .await
    .unwrap();
    assert!(appended);
    tx.commit().await.unwrap();
    stored
}

fn deal_readsets(
) -> std::collections::BTreeMap<String, native_query_contract::rule_contract::RuleInputReadset> {
    use native_query_contract::rule_contract::{PinnedRelation, RuleInputReadset};
    std::collections::BTreeMap::from([(
        "deal".to_owned(),
        RuleInputReadset {
            relations: vec![PinnedRelation {
                identity: "native.query-sql.records".to_owned(),
                name: "records".to_owned(),
                semantic_version: 1,
                columns: ["id"].iter().map(|s| s.to_string()).collect(),
                population_only: false,
            }],
            parameter_slots: vec![1],
            uses_now_ms: false,
        },
    )])
}

#[tokio::test]
async fn stale_pins_call_refuses_but_disable_and_fresh_reenable_succeed() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    let revision = sample_revision();
    // Old catalog pins, SQL still valid today.
    let old = seed_historical(
        &db,
        &scope,
        &revision,
        &deal_readsets(),
        CatalogPins {
            revision: 1,
            profile_id: "sqlite-local".to_owned(),
            profile_revision: 1,
        },
        &admin,
    )
    .await;
    assert_eq!(old.catalog_revision, 1);
    let err = prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "cel-subset@1")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("catalog revision"), "{err}");
    // Inspect succeeds; disable preserves old bytes/read-sets/receipt.
    let seen = inspect_rule(&db, &admin, &scope, "acme", "overdue")
        .await
        .unwrap();
    assert_eq!(seen.catalog_revision, 1);
    let disabled = disable_rule(&db, &admin, &scope, "acme", "overdue", Some(old.event_seq))
        .await
        .unwrap();
    assert!(!disabled.active);
    assert_eq!(disabled.revision_digest, old.revision_digest);
    assert_eq!(disabled.readset_digest, old.readset_digest);
    assert_eq!(disabled.engine_id, old.receipt.engine_id);
    assert_eq!(disabled.settings_digest, old.settings_digest);
    // Fresh public re-enable re-extracts against today's catalog: same
    // immutable revision digest, current pins, fresh validator, new event.
    let validator: Arc<dyn RuleValidator> = Arc::new(AcceptValidator::new("test-engine"));
    let mut req = request(&scope, revision);
    req.expected_seq = Some(disabled.event_seq);
    let renewed = register_rule(&db, &admin, &validator, &req).await.unwrap();
    assert_eq!(renewed.revision_digest, old.revision_digest);
    assert_eq!(renewed.catalog_revision, 4);
    assert!(renewed.active);
    let recipe = prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "cel-subset@1")
        .await
        .unwrap();
    assert_eq!(recipe.event_seq, renewed.event_seq);
    db.close().await;
}

#[tokio::test]
async fn removed_relation_inspect_disable_succeed_reenable_refuses() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    // Historical snapshot whose SQL names a removed relation: the fold only
    // checks internal consistency, never prepares SQL.
    let mut revision = sample_revision();
    revision.inputs[0].sql = "SELECT id FROM gone_relation WHERE id = ?1".to_owned();
    let mut readsets = deal_readsets();
    let rel = &mut readsets.get_mut("deal").unwrap().relations[0];
    rel.identity = "native.query-sql.gone".to_owned();
    rel.name = "gone_relation".to_owned();
    let old = seed_historical(
        &db,
        &scope,
        &revision,
        &readsets,
        CatalogPins {
            revision: 4,
            profile_id: "sqlite-local".to_owned(),
            profile_revision: 1,
        },
        &admin,
    )
    .await;
    // Call refuses (relation unserved); inspect/disable succeed with no SQL
    // prepare and no validator.
    let err = prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "cel-subset@1")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("no longer served"), "{err}");
    let seen = inspect_rule(&db, &admin, &scope, "acme", "overdue")
        .await
        .unwrap();
    assert_eq!(
        seen.revision.inputs[0].sql,
        "SELECT id FROM gone_relation WHERE id = ?1"
    );
    let disabled = disable_rule(&db, &admin, &scope, "acme", "overdue", Some(old.event_seq))
        .await
        .unwrap();
    assert!(!disabled.active);
    // Fresh public re-enable re-extracts the SQL and refuses: no append.
    let validator: Arc<dyn RuleValidator> = Arc::new(AcceptValidator::new("test-engine"));
    let before = meta_count(&db).await;
    let mut req = request(&scope, revision);
    req.expected_seq = Some(disabled.event_seq);
    let err = register_rule(&db, &admin, &validator, &req)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("inadmissible"), "{err}");
    assert_eq!(meta_count(&db).await, before);
    db.close().await;
}

fn artifact_envelope(family: &str, version: u32) -> Vec<u8> {
    serde_json::json!({"family": family, "version": version, "kinds": [{"token": "note"}]})
        .to_string()
        .into_bytes()
}

async fn install_and_adopt(
    db: &crate::db::Db,
    admin: &str,
    family: &str,
    version: u32,
) -> crate::meta::definition_artifact::RevisionIdentity {
    use crate::definition_registry::install_definition_artifact_as_in;
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    let outcome = install_definition_artifact_as_in(
        &mut tx,
        family,
        version,
        &artifact_envelope(family, version),
        Some(admin),
        &mut alloc,
    )
    .await
    .unwrap();
    crate::meta::adoption::append_definition_adoption_in(
        &mut tx,
        family,
        Some(&outcome.identity),
        &mut alloc,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    outcome.identity
}

#[tokio::test]
async fn definition_pin_admission_and_call_routing() {
    use crate::query::rule_install::DefinitionPin;
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    let pin_v1 = install_and_adopt(&db, &admin, "r9.demo", 1).await;
    let validator: Arc<dyn RuleValidator> = Arc::new(AcceptValidator::new("test-engine"));
    // Unadopted pin refuses admission with no append.
    let mut lonely = sample_revision();
    lonely.definition_pins.push(DefinitionPin {
        family: "r9.other".to_owned(),
        version: 1,
        digest: "a".repeat(64),
    });
    let before = meta_count(&db).await;
    let err = register_rule(&db, &admin, &validator, &request(&scope, lonely))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not effectively adopted"), "{err}");
    assert_eq!(meta_count(&db).await, before);
    // Adopted pin admits and calls.
    let mut revision = sample_revision();
    revision.definition_pins.push(DefinitionPin {
        family: pin_v1.family.clone(),
        version: pin_v1.version,
        digest: pin_v1.digest.clone(),
    });
    let view = register_rule(&db, &admin, &validator, &request(&scope, revision.clone()))
        .await
        .unwrap();
    assert_eq!(view.definition_pins.len(), 1);
    prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "cel-subset@1")
        .await
        .unwrap();
    // Moving adoption to v2 breaks the old pin at call and at admission.
    let pin_v2 = install_and_adopt(&db, &admin, "r9.demo", 2).await;
    assert_ne!(pin_v2.digest, pin_v1.digest);
    let err = prepare_rule_call(&db, &admin, &scope, "acme", "overdue", "cel-subset@1")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not effectively adopted"), "{err}");
    let mut stale = request(&scope, revision);
    stale.expected_seq = Some(view.event_seq);
    let err = register_rule(&db, &admin, &validator, &stale)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not effectively adopted"), "{err}");
    assert_eq!(meta_count(&db).await, before + 1);
    db.close().await;
}

#[tokio::test]
async fn admission_request_rejects_unknown_fields() {
    let mut value = serde_json::to_value(request("home:x", sample_revision())).unwrap();
    value["proof"] = serde_json::json!({"receipt": "forged"});
    let err = serde_json::from_value::<RuleAdmissionRequest>(value).unwrap_err();
    assert!(err.to_string().contains("unknown field"), "{err}");
}

#[tokio::test]
async fn replacement_settings_and_reenable_need_fresh_validation() {
    let (db, admin) = admin_db().await;
    let scope = managed_scope(&db, &admin).await;
    let validator = Arc::new(AcceptValidator::new("test-engine"));
    let validator_dyn: Arc<dyn RuleValidator> = validator.clone();
    let first = register_rule(
        &db,
        &admin,
        &validator_dyn,
        &request(&scope, sample_revision()),
    )
    .await
    .unwrap();
    assert_eq!(validator.calls.load(Ordering::SeqCst), 1);
    // New clauses re-run the validator and mint a new snapshot.
    let mut next = sample_revision();
    next.clauses = "deal.id != ''".to_owned();
    let mut req = request(&scope, next);
    req.expected_seq = Some(first.event_seq);
    let replaced = register_rule(&db, &admin, &validator_dyn, &req)
        .await
        .unwrap();
    assert_eq!(validator.calls.load(Ordering::SeqCst), 2);
    assert_ne!(replaced.revision_digest, first.revision_digest);
    // Settings-only change is a new snapshot with fresh validation too.
    let mut settings_req = request(&scope, sample_revision());
    settings_req.settings = serde_json::json!({"level": "block"});
    settings_req.expected_seq = Some(replaced.event_seq);
    let changed = register_rule(&db, &admin, &validator_dyn, &settings_req)
        .await
        .unwrap();
    assert_eq!(validator.calls.load(Ordering::SeqCst), 3);
    assert_ne!(changed.settings_digest, replaced.settings_digest);
    // Disable runs no validation; re-enable with a vetoing engine fails.
    let disabled = disable_rule(
        &db,
        &admin,
        &scope,
        "acme",
        "overdue",
        Some(changed.event_seq),
    )
    .await
    .unwrap();
    assert!(!disabled.active);
    assert_eq!(validator.calls.load(Ordering::SeqCst), 3);
    assert_eq!(disabled.revision_digest, changed.revision_digest);
    let veto: Arc<dyn RuleValidator> = Arc::new(VetoValidator {
        error: RuleValidationError::SettingsInvalid {
            message: "nope".to_owned(),
        },
    });
    let mut reenable = request(&scope, sample_revision());
    reenable.expected_seq = Some(disabled.event_seq);
    let err = register_rule(&db, &admin, &veto, &reenable)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        RuleRegistryError::Validation(RuleValidationError::SettingsInvalid { .. })
    ));
    // The disabled snapshot is untouched by the failed re-enable.
    let seen = inspect_rule(&db, &admin, &scope, "acme", "overdue")
        .await
        .unwrap();
    assert!(!seen.active);
    assert_eq!(seen.event_seq, disabled.event_seq);
    db.close().await;
}
