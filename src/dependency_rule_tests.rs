//! Gated S2b rule-dependency collector tests (task 81c1d95): latest ACTIVE
//! rule snapshot pins flow into the single K6a preflight through direct,
//! inherited-scoped, global, and package paths; inspection identity and actor
//! redaction; disable/replacement/settings semantics; pin-free neutrality;
//! non-worsening; hidden domains; corrupt/fixture fail-closed; generic-kind
//! refusal; replay equality. No evaluator, no v1 DDL.

use std::sync::Arc;

use crate::dependency::DEPENDENCY_REFUSAL;
use crate::events::KERNEL_ROOT_ID;
use crate::kernel::{
    adopt_definition_as, adopt_definition_at, adopt_package_at, create_home, create_principal,
    create_v2_database, install_package_as,
};
use crate::package_manifest::{
    BehaviourDescriptor, DefinitionEntry, PackageManifest, SurfaceDescriptor, BEHAVIOUR_KIND,
    SURFACE_KIND,
};
use crate::query::rule_install::{
    DefinitionPin, EngineValidationEvidence, ParameterDecl, ParameterSource, RuleCardinality,
    RuleInputDecl, RuleRevision, RuleValidationRequest,
};
use crate::rule_registry::{register_rule, RuleAdmissionRequest};

const FAMILY: &str = "example.records";
const NS: &str = "acme";
const NAME: &str = "notes";

fn def_bytes(family: &str, version: u32) -> String {
    format!(r#"{{"family":"{family}","version":{version},"kinds":["note"]}}"#)
}

fn entry_v(family: &str, version: u32) -> DefinitionEntry {
    let bytes = def_bytes(family, version);
    let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
    DefinitionEntry {
        family: family.to_string(),
        version,
        artifact_bytes: bytes,
        digest,
    }
}

fn manifest_v(version: u32, entry_version: u32) -> PackageManifest {
    PackageManifest {
        namespace: NS.to_string(),
        name: NAME.to_string(),
        version,
        definitions: vec![entry_v(FAMILY, entry_version)],
        behaviour: Some(BehaviourDescriptor {
            kind: BEHAVIOUR_KIND.to_string(),
            reads: vec!["linked_record:view".to_string()],
            effects: vec![],
        }),
        surface: Some(SurfaceDescriptor {
            kind: SURFACE_KIND.to_string(),
            view: "pack.view".to_string(),
            fallback: "pack.unavailable".to_string(),
        }),
        declared_reads: vec!["linked_record:view".to_string()],
    }
}

fn pin_v(entry_version: u32) -> crate::meta::definition_artifact::RevisionIdentity {
    let e = entry_v(FAMILY, entry_version);
    crate::meta::definition_artifact::RevisionIdentity {
        family: FAMILY.to_string(),
        version: e.version,
        digest: e.digest,
    }
}

fn rule_revision(pins: Vec<DefinitionPin>) -> RuleRevision {
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
        definition_pins: pins,
    }
}

struct AcceptEngine;

impl crate::query::rule_install::RuleValidator for AcceptEngine {
    fn validate(
        &self,
        request: RuleValidationRequest<'_>,
    ) -> std::result::Result<
        EngineValidationEvidence,
        crate::query::rule_install::RuleValidationError,
    > {
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

async fn admin_db() -> (crate::db::Db, String) {
    create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap()
}

async fn snapshot(db: &crate::db::Db) -> (i64, i64, crate::kernel::KernelTableDump) {
    let meta: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let content: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let dump = crate::kernel::dump_all_kernel_tables(db).await.unwrap();
    (meta, content, dump)
}

async fn register_pinned(
    db: &crate::db::Db,
    admin: &str,
    scope: &str,
    pins: Vec<DefinitionPin>,
) -> crate::rule_registry::InstallationView {
    let validator: Arc<dyn crate::query::rule_install::RuleValidator> = Arc::new(AcceptEngine);
    register_rule(
        db,
        admin,
        &validator,
        &RuleAdmissionRequest {
            scope_home: scope.to_owned(),
            revision: rule_revision(pins),
            settings: serde_json::json!({"level": "advise"}),
            expected_seq: None,
        },
    )
    .await
    .unwrap()
}

fn pin(version: u32) -> DefinitionPin {
    let p = pin_v(version);
    DefinitionPin {
        family: p.family,
        version: p.version,
        digest: p.digest,
    }
}

#[tokio::test]
async fn rule_pin_blocks_direct_scoped_replacement_and_disable() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    let home = create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .unwrap();
    register_pinned(&db, &admin, &home, vec![pin(1)]).await;
    let before = snapshot(&db).await;
    let p2 = pin_v(2);
    assert!(adopt_definition_at(&db, &admin, FAMILY, Some(&p2), &home)
        .await
        .is_err());
    assert!(adopt_definition_at(&db, &admin, FAMILY, None, &home)
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn rule_pin_blocks_inherited_scoped_move() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    let parent = create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let child = create_home(&db, &parent, None, &admin).await.unwrap();
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &parent)
        .await
        .unwrap();
    // Rule at the child inherits the parent pin; moving the parent refuses.
    register_pinned(&db, &admin, &child, vec![pin(1)]).await;
    let before = snapshot(&db).await;
    let p2 = pin_v(2);
    assert!(adopt_definition_at(&db, &admin, FAMILY, Some(&p2), &parent)
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn rule_pin_blocks_global_move() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    let p1 = pin_v(1);
    adopt_definition_as(&db, &admin, FAMILY, Some(&p1))
        .await
        .unwrap();
    let child = create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    register_pinned(&db, &admin, &child, vec![pin(1)]).await;
    let before = snapshot(&db).await;
    let p2 = pin_v(2);
    assert!(adopt_definition_as(&db, &admin, FAMILY, Some(&p2))
        .await
        .is_err());
    assert!(adopt_definition_as(&db, &admin, FAMILY, None)
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn rule_pin_blocks_package_replace_and_disable() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    let id1 = install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    let home = create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    adopt_package_at(&db, &admin, &home, &m1, Some(&id1), &m1.declared_reads)
        .await
        .unwrap();
    // Package-surface adoption makes v1 effective; the rule pin satisfies.
    register_pinned(&db, &admin, &home, vec![pin(1)]).await;
    let before = snapshot(&db).await;
    assert!(adopt_package_at(&db, &admin, &home, &m2, None, &[])
        .await
        .is_err());
    assert!(adopt_package_at(&db, &admin, &home, &m1, None, &[])
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn rule_impact_carries_identity_with_redacted_actor() {
    use crate::dependency::preview_definition_change;
    let (db, admin) = admin_db().await;
    let op = create_principal(&db, "account", "Op", "test:op", &admin)
        .await
        .unwrap();
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    let home = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (op.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .unwrap();
    register_pinned(&db, &admin, &home, vec![pin(1)]).await;
    let p2 = pin_v(2);
    // Same breaking preview: admin sees the attributor, op sees redaction.
    let admin_impact = preview_definition_change(&db, &admin, Some(&home), FAMILY, Some(&p2))
        .await
        .unwrap();
    let op_impact = preview_definition_change(&db, &op, Some(&home), FAMILY, Some(&p2))
        .await
        .unwrap();
    assert!(admin_impact.refuses());
    assert!(op_impact.refuses());
    let (admin_entry, op_entry) = (
        admin_impact
            .broken
            .iter()
            .find(|e| e.consumer_kind == "rule")
            .unwrap(),
        op_impact
            .broken
            .iter()
            .find(|e| e.consumer_kind == "rule")
            .unwrap(),
    );
    assert_eq!(admin_entry.consumer_namespace, "acme");
    assert_eq!(admin_entry.consumer_name, "overdue");
    assert_eq!(admin_entry.family, FAMILY);
    assert_eq!(admin_entry.actor, Some(admin.clone()));
    assert_eq!(op_entry.actor, None);
    db.close().await;
}

#[tokio::test]
async fn disable_and_replacement_drop_pins_settings_retains() {
    use crate::rule_registry::disable_rule;
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    let home = create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .unwrap();
    let first = register_pinned(&db, &admin, &home, vec![pin(1)]).await;
    // Disable retires the live pin: the breaking move now succeeds.
    disable_rule(&db, &admin, &home, "acme", "overdue", Some(first.event_seq))
        .await
        .unwrap();
    let p2 = pin_v(2);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p2), &home)
        .await
        .unwrap();
    // Replacement with a pin-free revision keeps no dependency either.
    let validator: Arc<dyn crate::query::rule_install::RuleValidator> = Arc::new(AcceptEngine);
    let view = crate::rule_registry::inspect_rule(&db, &admin, &home, "acme", "overdue")
        .await
        .unwrap();
    let req = RuleAdmissionRequest {
        scope_home: home.clone(),
        revision: rule_revision(vec![]),
        settings: serde_json::json!({"level": "advise"}),
        expected_seq: Some(view.event_seq),
    };
    register_rule(&db, &admin, &validator, &req).await.unwrap();
    // Re-pin v2 with changed settings: admits (v2 effective), and the
    // retained pins keep blocking — moving back to v1 refuses.
    let view = crate::rule_registry::inspect_rule(&db, &admin, &home, "acme", "overdue")
        .await
        .unwrap();
    let req = RuleAdmissionRequest {
        scope_home: home.clone(),
        revision: rule_revision(vec![pin(2)]),
        settings: serde_json::json!({"level": "block"}),
        expected_seq: Some(view.event_seq),
    };
    let before = snapshot(&db).await;
    let repinned = register_rule(&db, &admin, &validator, &req).await.unwrap();
    assert_ne!(repinned.settings_digest, view.settings_digest);
    assert_eq!(repinned.definition_pins, vec![pin(2)]);
    assert_eq!(snapshot(&db).await.0, before.0 + 1);
    assert!(adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .is_err());
    assert_eq!(snapshot(&db).await.0, before.0 + 1);
    // Settings-only new snapshot: same revision digest and pins preserved,
    // and the v1 move still refuses with full no-change state.
    let view = crate::rule_registry::inspect_rule(&db, &admin, &home, "acme", "overdue")
        .await
        .unwrap();
    let req = RuleAdmissionRequest {
        scope_home: home.clone(),
        revision: rule_revision(vec![pin(2)]),
        settings: serde_json::json!({"level": "warn"}),
        expected_seq: Some(view.event_seq),
    };
    let settings_only = register_rule(&db, &admin, &validator, &req).await.unwrap();
    assert_eq!(settings_only.revision_digest, repinned.revision_digest);
    assert_eq!(settings_only.definition_pins, vec![pin(2)]);
    let before = snapshot(&db).await;
    assert!(adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    // Replacing the ACTIVE rule with a pin-free revision retires the old v2
    // pin: the v1 move now succeeds.
    let view = crate::rule_registry::inspect_rule(&db, &admin, &home, "acme", "overdue")
        .await
        .unwrap();
    let req = RuleAdmissionRequest {
        scope_home: home.clone(),
        revision: rule_revision(vec![]),
        settings: serde_json::json!({"level": "advise"}),
        expected_seq: Some(view.event_seq),
    };
    register_rule(&db, &admin, &validator, &req).await.unwrap();
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .unwrap();
    db.close().await;
}

#[tokio::test]
async fn already_unsatisfied_rule_never_freezes() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    let m3 = manifest_v(3, 3);
    install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    install_package_as(&db, &admin, &m3).await.unwrap();
    let home = create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .unwrap();
    register_pinned(&db, &admin, &home, vec![pin(1)]).await;
    // Legacy displacement bypassing preflight: the rule is now unsatisfied.
    // The prospective impact reports it as already-unsatisfied `rule` kind
    // before the move succeeds — reported, never frozen.
    crate::dependency_tests::legacy_override(&db, &admin, &home, &pin_v(2)).await;
    let p3 = pin_v(3);
    let impact =
        crate::dependency::preview_definition_change(&db, &admin, Some(&home), FAMILY, Some(&p3))
            .await
            .unwrap();
    assert!(!impact.refuses());
    let reported = impact
        .already_unsatisfied
        .iter()
        .find(|e| e.consumer_kind == "rule")
        .unwrap();
    assert_eq!(reported.consumer_namespace, "acme");
    assert_eq!(reported.required_digest, pin_v(1).digest);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p3), &home)
        .await
        .unwrap();
    db.close().await;
}

#[tokio::test]
async fn hidden_rule_domain_refuses_uniformly() {
    let (db, admin) = admin_db().await;
    let op = create_principal(&db, "account", "Op", "test:op", &admin)
        .await
        .unwrap();
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    let target = create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (op.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let hidden = create_home(&db, &target, Some(&[(admin.as_str(), "manage")]), &admin)
        .await
        .unwrap();
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &hidden)
        .await
        .unwrap();
    // Baseline without any rule: op's move still refuses uniformly (hidden
    // domain), with identical error and no-change state.
    let p2 = pin_v(2);
    let before = snapshot(&db).await;
    let bare_err = adopt_definition_at(&db, &op, FAMILY, Some(&p2), &target)
        .await
        .unwrap_err();
    assert_eq!(bare_err.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(snapshot(&db).await, before);
    // Rule registered by admin inside the hidden child (Manage there).
    register_pinned(&db, &admin, &hidden, vec![pin(1)]).await;
    // Op moves the parent scope: the hidden rule breaks the change, and the
    // refusal matches the rule-free baseline exactly — never a presence leak.
    let before = snapshot(&db).await;
    let err = adopt_definition_at(&db, &op, FAMILY, Some(&p2), &target)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), DEPENDENCY_REFUSAL);
    assert_eq!(err.to_string(), bare_err.to_string());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn corrupt_and_logonly_rule_state_fails_preflight_closed() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    let home = create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .unwrap();
    register_pinned(&db, &admin, &home, vec![pin(1)]).await;
    // Tampered projection digest: any preflight touching the domain refuses.
    sqlx::query("UPDATE rule_installations SET revision_digest = ? WHERE scope_home = ?")
        .bind("0".repeat(64))
        .bind(&home)
        .execute(db.write_pool())
        .await
        .unwrap();
    let before = snapshot(&db).await;
    let p2 = pin_v(2);
    assert!(adopt_definition_at(&db, &admin, FAMILY, Some(&p2), &home)
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    // Log-only (row dropped, events live): same closed refusal.
    sqlx::query("DELETE FROM rule_installations WHERE scope_home = ?")
        .bind(&home)
        .execute(db.write_pool())
        .await
        .unwrap();
    let before = snapshot(&db).await;
    assert!(adopt_definition_at(&db, &admin, FAMILY, Some(&p2), &home)
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn generic_registry_refuses_rule_kind() {
    let (db, admin) = admin_db().await;
    let home = create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    // The closed generic kind list never admits `rule`: neither registration
    // nor retirement flows can touch rule-derived requirements — with full
    // no-append state proof around both refusals.
    let before = snapshot(&db).await;
    assert!(crate::dependency::register_consumer_at(
        &db,
        &admin,
        &home,
        "rule",
        "acme",
        "overdue",
        FAMILY,
        1,
        &"a".repeat(64),
        None,
    )
    .await
    .is_err());
    assert!(crate::dependency::retire_consumer_at(
        &db, &admin, &home, "rule", "acme", "overdue", FAMILY, None,
    )
    .await
    .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn replay_preserves_rule_requirements() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    let home = create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .unwrap();
    register_pinned(&db, &admin, &home, vec![pin(1)]).await;
    let before = snapshot(&db).await;
    crate::kernel::replay_all_projections(&db).await.unwrap();
    assert_eq!(snapshot(&db).await, before);
    // The rebuilt collector still blocks the breaking move.
    let p2 = pin_v(2);
    assert!(adopt_definition_at(&db, &admin, FAMILY, Some(&p2), &home)
        .await
        .is_err());
    assert_eq!(snapshot(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn pinfree_rule_creates_no_implicit_dependency() {
    let (db, admin) = admin_db().await;
    let m1 = manifest_v(1, 1);
    let m2 = manifest_v(2, 2);
    install_package_as(&db, &admin, &m1).await.unwrap();
    install_package_as(&db, &admin, &m2).await.unwrap();
    let home = create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let p1 = pin_v(1);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p1), &home)
        .await
        .unwrap();
    register_pinned(&db, &admin, &home, vec![]).await;
    // Unrelated family moves never consult pin-free rules: v2 move succeeds.
    let p2 = pin_v(2);
    adopt_definition_at(&db, &admin, FAMILY, Some(&p2), &home)
        .await
        .unwrap();
    db.close().await;
}
