use super::*;
use crate::events::KERNEL_ROOT_ID;
use crate::kernel as k;
use crate::package_manifest::PackageManifest;

use crate::package_operations::{
    call_package_operation_as as call, describe_package_operations_as,
};

fn package(name: &str) -> PackageManifest {
    let bytes = match name {
        "quote" => include_str!("../../../examples/packages/cel-scalar-dev/quote.package.json"),
        "dispatch" => {
            include_str!("../../../examples/packages/cel-scalar-dev/dispatch.package.json")
        }
        _ => unreachable!(),
    };
    PackageManifest::from_canonical_value(&serde_json::from_str(bytes).unwrap()).unwrap()
}

fn executable() -> ExecutableDeclaration {
    package("quote").operations[0].executable.clone().unwrap()
}

async fn activate(db: &crate::db::Db, admin: &str, manifest: &PackageManifest) {
    let identity = k::install_package_as(db, admin, manifest).await.unwrap();
    k::adopt_package_at(
        db,
        admin,
        KERNEL_ROOT_ID,
        manifest,
        Some(&identity),
        &manifest.declared_reads,
    )
    .await
    .unwrap();
}

async fn create(
    db: &crate::db::Db,
    admin: &str,
    manifest: &PackageManifest,
    source: &str,
) -> String {
    let op = &manifest.operations[0];
    k::create_as(
        db,
        admin,
        &op.family,
        &op.kind,
        json!({"inputs_json":source}).as_object().unwrap(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn independently_authored_packages_upgrade_disable_and_retain_data() {
    let _serial = RUNTIME_TEST.lock().await;
    let (db, admin) = k::create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let quote = package("quote");
    let shipping = package("dispatch");
    for manifest in [&quote, &shipping] {
        activate(&db, &admin, manifest).await;
        let described = describe_package_operations_as(
            &db,
            &admin,
            KERNEL_ROOT_ID,
            &manifest.namespace,
            &manifest.name,
        )
        .await
        .unwrap();
        assert_eq!(
            described["operations"][0]["executable"]["language"],
            LANGUAGE
        );
        let schema = &described["provider_schemas"][PROVIDER];
        assert_eq!(schema["profile"], PROFILE);
        assert_eq!(schema["interim"], true);
        assert_eq!(schema["request"]["required"], json!(["record_id"]));
        assert_eq!(
            schema["request"]["properties"]["record_id"]["type"],
            "string"
        );
        assert_eq!(schema["source"]["max_bindings"], MAX_BINDINGS);
        assert_eq!(
            schema["result"]["oneOf"][0]["properties"]["value"]["type"],
            json!(["null", "boolean", "number", "string"])
        );
        assert_eq!(
            schema["result"]["oneOf"][1]["properties"]["error"]["properties"]["kind"]["enum"],
            json!(["invalid_bindings", "evaluation_failed", "invalid_result"])
        );
        assert_eq!(
            manifest,
            &PackageManifest::from_canonical_value(&manifest.canonical_value().unwrap()).unwrap()
        );
    }
    let world = k::describe_world_as(&db, &admin).await.unwrap();
    assert_eq!(world["package_operations"].as_array().unwrap().len(), 2);
    let quote_id = create(
        &db,
        &admin,
        &quote,
        r#"{"subtotal":1000,"discount_pct":10}"#,
    )
    .await;
    let shipping_id = create(
        &db,
        &admin,
        &shipping,
        r#"{"country":"GB","weight_kg":12.5,"prepaid":true}"#,
    )
    .await;
    let history = k::history_as(&db, &admin, &quote_id).await.unwrap();
    let first = call(
        &db,
        &admin,
        &quote.namespace,
        &quote.name,
        "compute",
        &quote_id,
    )
    .await
    .unwrap();
    assert_eq!(first.result, json!({"value":900,"error":null}));
    let receipt = first.receipt.execution.unwrap();
    assert_eq!(receipt.language, LANGUAGE);
    assert_eq!(receipt.profile, PROFILE);
    assert_eq!(receipt.policy, cel::Policy::P1.id());
    assert!(receipt.interim);
    assert_eq!(
        receipt.expression_digest,
        crate::meta::definition_artifact::digest_artifact_bytes(
            quote.operations[0]
                .executable
                .as_ref()
                .unwrap()
                .expression
                .as_bytes()
        )
    );
    let dispatched = call(
        &db,
        &admin,
        &shipping.namespace,
        &shipping.name,
        "compute",
        &shipping_id,
    )
    .await
    .unwrap();
    assert_eq!(dispatched.result, json!({"value":true,"error":null}));
    assert_eq!(
        k::history_as(&db, &admin, &quote_id).await.unwrap().len(),
        history.len(),
        "pure call appends nothing"
    );

    // Viewer authority comes from the kernel; package consent cannot grant it.
    let outsider = k::create_principal(&db, "account", "Outsider", "test:outsider", &admin)
        .await
        .unwrap();
    let hidden = call(
        &db,
        &outsider,
        &quote.namespace,
        &quote.name,
        "compute",
        &quote_id,
    )
    .await
    .err()
    .unwrap();
    let missing = call(
        &db,
        &outsider,
        &quote.namespace,
        &quote.name,
        "compute",
        "missing",
    )
    .await
    .err()
    .unwrap();
    assert_eq!(hidden.to_string(), missing.to_string());

    // Malformed input stays readable; a corrected call succeeds on the same engine.
    k::revise_as(
        &db,
        &admin,
        &quote_id,
        json!({"inputs_json":"{\"subtotal\":true,\"discount_pct\":10}"})
            .as_object()
            .unwrap(),
    )
    .await
    .unwrap();
    let invalid = call(
        &db,
        &admin,
        &quote.namespace,
        &quote.name,
        "compute",
        &quote_id,
    )
    .await
    .unwrap();
    assert_eq!(invalid.result["error"]["kind"], "invalid_bindings");
    // The development binding cap produces a receipted domain error; the
    // generic stored-source materialization guard refuses before a receipt.
    for (bytes, outer_refusal) in [(MAX_SOURCE_BYTES + 1, false), (262145, true)] {
        k::revise_as(
            &db,
            &admin,
            &quote_id,
            json!({"inputs_json":"x".repeat(bytes)})
                .as_object()
                .unwrap(),
        )
        .await
        .unwrap();
        let outcome = call(
            &db,
            &admin,
            &quote.namespace,
            &quote.name,
            "compute",
            &quote_id,
        )
        .await;
        if outer_refusal {
            let error = outcome.unwrap_err();
            assert!(
                error.to_string().contains("over the cap of 262144"),
                "{error}"
            );
        } else {
            let outcome = outcome.unwrap();
            assert_eq!(outcome.result["error"]["kind"], "invalid_bindings");
            assert!(outcome.receipt.execution.is_some());
        }
    }
    k::revise_as(
        &db,
        &admin,
        &quote_id,
        json!({"inputs_json":"{\"subtotal\":1000,\"discount_pct\":10}"})
            .as_object()
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        call(
            &db,
            &admin,
            &quote.namespace,
            &quote.name,
            "compute",
            &quote_id
        )
        .await
        .unwrap()
        .result["value"],
        900
    );

    let mut upgraded = quote.clone();
    upgraded.version = 2;
    upgraded.operations[0]
        .executable
        .as_mut()
        .unwrap()
        .expression
        .push_str(" + 25");
    activate(&db, &admin, &upgraded).await;
    let second = call(
        &db,
        &admin,
        &quote.namespace,
        &quote.name,
        "compute",
        &quote_id,
    )
    .await
    .unwrap();
    assert_eq!(second.result["value"], 925);
    assert_eq!(second.receipt.package_version, 2);
    assert_eq!(
        second.receipt.definition_digest,
        first.receipt.definition_digest
    );
    k::adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &upgraded, None, &[])
        .await
        .unwrap();
    assert!(call(
        &db,
        &admin,
        &quote.namespace,
        &quote.name,
        "compute",
        &quote_id
    )
    .await
    .is_err());
    assert!(k::read_record_as(&db, &admin, &quote_id)
        .await
        .unwrap()
        .is_some());
    assert!(!k::history_as(&db, &admin, &quote_id)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        call(
            &db,
            &admin,
            &shipping.namespace,
            &shipping.name,
            "compute",
            &shipping_id
        )
        .await
        .unwrap()
        .result["value"],
        true
    );
    db.close().await;
}

#[tokio::test]
async fn invalid_admission_is_event_free_and_followup_valid_call_succeeds() {
    let _serial = RUNTIME_TEST.lock().await;
    let (db, admin) = k::create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let original = package("quote");
    let outsider = k::create_principal(&db, "account", "Outsider", "test:outsider", &admin)
        .await
        .unwrap();
    let count = || sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events");
    let before = count().fetch_one(db.pool()).await.unwrap();
    let mut malformed = original.clone();
    malformed.operations[0]
        .executable
        .as_mut()
        .unwrap()
        .expression = "subtotal +".into();
    // Count actual guest-boundary calls; unauthorized paths must never enter it.
    let before_guest = GUEST_CALLS.load(std::sync::atomic::Ordering::SeqCst);
    for manifest in [&original, &malformed, &crate::v2_budget::budget_package()] {
        let error = k::install_package_as(&db, &outsider, manifest)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            Error::engine(k::HIDDEN_OR_MISSING).to_string()
        );
    }
    assert_eq!(
        GUEST_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        before_guest
    );
    assert!(k::install_package_as(&db, &admin, &malformed)
        .await
        .is_err());
    assert_eq!(
        GUEST_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        before_guest + 1
    );
    assert_eq!(count().fetch_one(db.pool()).await.unwrap(), before);
    // Authorized admission reaches CEL only after the authority preflight.
    let parse = k::install_package_as(&db, &admin, &malformed)
        .await
        .unwrap_err();
    assert!(
        parse.to_string().contains("CEL guest check refused"),
        "{parse}"
    );
    for (field, value) in [
        ("language", "other@1"),
        ("profile", "other/1"),
        ("provider", "host.unknown/1"),
        ("expression", "subtotal +"),
        ("expression", "unknown_host_capability()"),
        ("expression", "[1,2].map(x, x + 1)"),
    ] {
        let mut wire = original.canonical_value().unwrap();
        if field == "provider" {
            wire["operations"][0][field] = json!(value);
        } else {
            wire["operations"][0]["executable"][field] = json!(value);
        }
        if let Ok(manifest) = PackageManifest::from_canonical_value(&wire) {
            assert!(
                k::install_package_as(&db, &admin, &manifest).await.is_err(),
                "{field}: {value}"
            );
        }
        assert_eq!(count().fetch_one(db.pool()).await.unwrap(), before);
    }
    activate(&db, &admin, &original).await;
    let id = create(
        &db,
        &admin,
        &original,
        r#"{"subtotal":100,"discount_pct":0}"#,
    )
    .await;
    assert_eq!(
        call(
            &db,
            &admin,
            &original.namespace,
            &original.name,
            "compute",
            &id
        )
        .await
        .unwrap()
        .result["value"],
        100
    );
    db.close().await;
}

#[tokio::test]
async fn profile_caps_and_closed_scalars_use_checked_ast() {
    let _serial = RUNTIME_TEST.lock().await;
    let base = executable();
    let check = |d: ExecutableDeclaration| async move {
        guest(Request::Check {
            declaration: wire(d)?,
        })
        .await
    };
    assert!(check(base.clone()).await.unwrap().report.unwrap().check_ok);
    for expression in ["[1].all(x, x > 0)", "host.read()", "subtotal +"] {
        let mut d = base.clone();
        d.expression = expression.into();
        assert!(
            !check(d).await.unwrap().report.unwrap().check_ok,
            "{expression}"
        );
    }
    let mut d = base.clone();
    d.expression = " ".repeat(MAX_EXPRESSION_BYTES + 1);
    assert!(d.validate_shape().is_err());
    d = base.clone();
    d.bindings = (0..17)
        .map(|i| ScalarBinding {
            name: format!("n{i}"),
            kind: ScalarType::Int,
        })
        .collect();
    assert!(d.validate_shape().is_err());
    d = base.clone();
    d.bindings[1].name = d.bindings[0].name.clone();
    assert!(d.validate_shape().is_err());
    d = base.clone();
    d.expression = format!("{}subtotal{}", "-(".repeat(17), ")".repeat(17));
    assert!(!check(d).await.unwrap().report.unwrap().check_ok);
    for source in [
        "[]",
        "null",
        r#"{"subtotal":1,"subtotal":2,"discount_pct":0}"#,
        r#"{"subtotal":1,"discount_pct":0,"extra":true}"#,
        r#"{"subtotal":1}"#,
        r#"{"subtotal":null,"discount_pct":0}"#,
        r#"{"subtotal":[],"discount_pct":0}"#,
        r#"{"subtotal":9007199254740992,"discount_pct":0}"#,
        r#"{"subtotal":1e999,"discount_pct":0}"#,
    ] {
        let (r, _) = run(base.clone(), source.into()).await.unwrap();
        assert_eq!(r["error"]["kind"], "invalid_bindings", "{source}");
    }
    assert_eq!(
        run(base.clone(), " ".repeat(MAX_SOURCE_BYTES + 1))
            .await
            .unwrap()
            .0["error"]["kind"],
        "invalid_bindings"
    );
    let mut string = base;
    string.expression = "text".into();
    string.bindings = vec![ScalarBinding {
        name: "text".into(),
        kind: ScalarType::String,
    }];
    assert_eq!(
        run(
            string.clone(),
            json!({"text":"x".repeat(MAX_STRING_BYTES+1)}).to_string()
        )
        .await
        .unwrap()
        .0["error"]["kind"],
        "invalid_bindings"
    );
    assert_eq!(
        run(
            string,
            json!({"text":"x".repeat(MAX_STRING_BYTES)}).to_string()
        )
        .await
        .unwrap()
        .0["value"],
        "x".repeat(MAX_STRING_BYTES)
    );
    // Guest result conversion, not a native helper, exercises safe/null/nonfinite scalars.
    for (expression, bad) in [
        ("9007199254740991 + 1", true),
        ("1.0 / 0.0", true),
        ("0.0 / 0.0", true),
        ("null", false),
    ] {
        let mut d = executable();
        d.expression = expression.into();
        let (r, _) = run(d, r#"{"subtotal":1,"discount_pct":0}"#.into())
            .await
            .unwrap();
        assert_eq!(r["error"].is_null(), !bad);
    }
}

#[test]
fn executable_bytes_are_hashed_and_legacy_canonical_values_stay_unchanged() {
    let base = package("quote");
    let digest = base.package_digest().unwrap();
    for mutate in 0..3 {
        let mut changed = base.clone();
        let executable = changed.operations[0].executable.as_mut().unwrap();
        match mutate {
            0 => executable.expression.push(' '),
            1 => executable.bindings[0].kind = ScalarType::Double,
            _ => executable.bindings.swap(0, 1),
        }
        assert_ne!(changed.package_digest().unwrap(), digest);
    }
    let legacy = crate::v2_budget::budget_package();
    let mut expected = legacy.canonical_value().unwrap();
    assert!(expected["operations"][0].get("executable").is_none());
    // Independent pre-extension descriptor bytes, not a serialization roundtrip
    // through the newly extended operation type.
    expected["operations"] = json!([{
        "description":"Evaluate every budget cell from cells_json and return each cell's value, or a named error.",
        "effects":[], "family":"demo.budget.sheet", "kind":"sheet", "name":"recalculate",
        "provider":"host.table-arithmetic/1", "reads":["record:view"], "source_field":"cells_json"
    }]);
    assert_eq!(legacy.canonical_value().unwrap(), expected);
    assert_eq!(
        legacy.package_digest().unwrap(),
        crate::canonical_json::digest_json(&expected)
    );
    assert_eq!(
        legacy.package_digest().unwrap(),
        "911b3d3cec40d5233284c5b242550a1498d4d575498bbb92e32f5988e0f98c77"
    );
    let mut invalid = base.canonical_value().unwrap();
    invalid["operations"][0]["executable"]["bindings"][0]["type"] = json!("any");
    assert!(PackageManifest::from_canonical_value(&invalid).is_err());
    invalid = base.canonical_value().unwrap();
    invalid["operations"][0]["executable"]["host_capabilities"] = json!(["network"]);
    assert!(PackageManifest::from_canonical_value(&invalid).is_err());
}

#[test]
fn retained_relationship_sources_only_add_absent_executable_initializers() {
    for (compiled, retained) in [
        (
            include_str!("../../v2_standard/relates_to_v1.rs"),
            include_str!("../../v2_standard/relates_to_v1.pre-cel.rs.txt"),
        ),
        (
            include_str!("../../v2_standard/relates_to_v2.rs"),
            include_str!("../../v2_standard/relates_to_v2.pre-cel.rs.txt"),
        ),
        (
            include_str!("../../v2_standard/relates_to_v3.rs"),
            include_str!("../../v2_standard/relates_to_v3.pre-cel.rs.txt"),
        ),
    ] {
        assert_eq!(compiled.matches(",executable:None").count(), 1);
        assert_eq!(compiled.replace(",executable:None", ""), retained);
    }
}

#[tokio::test]
async fn evaluation_failures_are_bounded_and_do_not_poison_followup_calls() {
    let _serial = RUNTIME_TEST.lock().await;
    for (expression, expected) in [
        ("subtotal / discount_pct", "evaluation_failed"),
        ("[subtotal]", "invalid_result"),
        ("9007199254740991 + 1", "invalid_result"),
        ("1.0 / 0.0", "invalid_result"),
    ] {
        let mut declaration = executable();
        declaration.expression = expression.into();
        let (result, receipt) = run(declaration, r#"{"subtotal":1,"discount_pct":0}"#.into())
            .await
            .unwrap();
        assert_eq!(result["error"]["kind"], expected, "{expression}: {result}");
        assert!(serde_json::to_vec(&result).unwrap().len() < MAX_RESULT_BYTES);
        assert!(receipt.interim);
    }
    let (result, _) = run(executable(), r#"{"subtotal":100,"discount_pct":0}"#.into())
        .await
        .unwrap();
    assert_eq!(result, json!({"value":100,"error":null}));
}

#[tokio::test]
async fn guest_check_only_installs_without_invented_binding_values() {
    let _serial = RUNTIME_TEST.lock().await;
    let (db, admin) = k::create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let mut manifest = package("quote");
    manifest.operations[0]
        .executable
        .as_mut()
        .unwrap()
        .expression = "subtotal / discount_pct".into();
    // Installation has declarations only; zero/default values would make evaluation fail.
    k::install_package_as(&db, &admin, &manifest).await.unwrap();
    let declaration = manifest.operations[0].executable.clone().unwrap();
    let (bad, receipt) = run(
        declaration.clone(),
        r#"{"subtotal":100,"discount_pct":0}"#.into(),
    )
    .await
    .unwrap();
    assert_eq!(bad["error"]["kind"], "evaluation_failed");
    let pins = receipt.guest.unwrap();
    assert_eq!(pins.abi, native_package_cel_wire::ABI);
    assert_eq!(
        pins.module_sha256,
        native_package_cel_host::GUEST_MODULE_SHA256
    );
    assert_eq!(
        pins.source_sha256,
        native_package_cel_host::GUEST_SOURCE_SHA256
    );
    assert_eq!(
        pins.build_manifest_sha256,
        native_package_cel_host::BUILD_MANIFEST_SHA256
    );
    assert_eq!(pins.runtime, native_package_cel_host::RUNTIME);
    assert_eq!(pins.configuration, native_package_cel_host::CONFIGURATION);
    assert_eq!(pins.phase, "Deliver");
    assert!(pins.fuel_used > 0 && pins.fuel_used <= pins.fuel_budget);
    assert_eq!(
        run(declaration, r#"{"subtotal":100,"discount_pct":1}"#.into())
            .await
            .unwrap()
            .0["value"],
        100
    );
    db.close().await;
}

// Real slot/cancellation/Store-drop assertions now live in the CEL-free host
// library's deterministic hostile-WAT + async cancellation matrix. Root calls
// exercise the actual guest and the unchanged delivery wrapper instead.

#[tokio::test]
async fn legacy_provider_receipt_and_result_omit_execution_fields() {
    let _serial = RUNTIME_TEST.lock().await;
    let (db, admin) = k::create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let manifest = crate::v2_budget::budget_package();
    activate(&db, &admin, &manifest).await;
    let id = k::create_as(
        &db,
        &admin,
        "demo.budget.sheet",
        "sheet",
        json!({"title":"Legacy", "cells_json":"{\"A1\":\"100\"}"})
            .as_object()
            .unwrap(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let outcome = call(
        &db,
        &admin,
        &manifest.namespace,
        &manifest.name,
        "recalculate",
        &id,
    )
    .await
    .unwrap();
    assert_eq!(outcome.result["cells"]["A1"]["value"], 100.0);
    let receipt = serde_json::to_value(&outcome.receipt).unwrap();
    assert_eq!(receipt.as_object().unwrap().len(), 15);
    assert!(receipt.get("execution").is_none());
    assert_eq!(receipt["provider"], "host.table-arithmetic/1");
    db.close().await;
}

#[tokio::test]
async fn delivery_discards_computed_results_on_authority_selection_and_input_drift() {
    let _serial = RUNTIME_TEST.lock().await;
    delivery_drift_cases(false).await;
}

#[tokio::test]
async fn discovery_discards_metadata_on_authority_selection_and_record_drift() {
    let _serial = RUNTIME_TEST.lock().await;
    delivery_drift_cases(true).await;
}

async fn delivery_drift_cases(discovery: bool) {
    let mut changes = vec![
        "disable",
        "reenable",
        "upgrade",
        "input",
        "view",
        "credential",
        "membership",
        "home",
    ];
    if discovery {
        changes.push("selection_set");
    }
    for change in changes {
        let (db, admin) = k::create_v2_database(":memory:", "account", "Admin", "test:admin")
            .await
            .unwrap();
        if change == "membership" {
            crate::kernel::hosted_identity::reconcile_hosted_caller(&db, |_| async {
                // SAFETY: complete synthetic authenticated membership roster.
                Ok(unsafe { crate::kernel::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                    "test:admin".into(), vec![("test:admin".into(),"admin@example.test".into()),("test:other".into(),"other@example.test".into())].into_iter().collect(), std::collections::BTreeMap::new(),
                ) })
            }).await.unwrap();
        }
        let manifest = package("quote");
        activate(&db, &admin, &manifest).await;
        let id = create(
            &db,
            &admin,
            &manifest,
            r#"{"subtotal":1000,"discount_pct":10}"#,
        )
        .await;
        // The home/record owner has a permanent Manage floor. Revoke a
        // separately granted viewer, rather than pretending to revoke ownership.
        let (call_actor, call_binding) = if change == "view" {
            let viewer = k::create_principal(&db, "account", "Viewer", "test:viewer", &admin)
                .await
                .unwrap();
            k::replace_home_policy(&db, &admin, KERNEL_ROOT_ID, &[(&viewer, "view")])
                .await
                .unwrap();
            (viewer, "test:viewer")
        } else {
            (admin.clone(), "test:admin")
        };
        let (computed_tx, computed_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let worker_db = db.clone();
        let worker_admin = call_actor;
        let worker_id = id.clone();
        let worker_manifest = manifest.clone();
        let pending = tokio::spawn(async move {
            let pause = async {
                computed_tx.send(()).unwrap();
                resume_rx.await.unwrap();
            };
            if discovery {
                crate::package_operations::discovery::describe_record_checked(
                    &worker_db,
                    &worker_admin,
                    call_binding,
                    &worker_id,
                    pause,
                )
                .await
                .map(|_| ())
            } else {
                crate::package_operations::call_checked(
                    &worker_db,
                    &worker_admin,
                    Some(call_binding),
                    &worker_manifest.namespace,
                    &worker_manifest.name,
                    "compute",
                    &worker_id,
                    pause,
                )
                .await
                .map(|_| ())
            }
        });
        computed_rx.await.unwrap();
        // A real concurrent writer succeeds while the completed result is held.
        match change {
            "home" => {
                let home = k::create_home(&db, KERNEL_ROOT_ID, None, &admin)
                    .await
                    .unwrap();
                k::rehome_record_as(&db, &admin, &id, &home).await.unwrap();
            }
            "selection_set" => {
                let mut added = manifest.clone();
                added.name = "another-selection".into();
                activate(&db, &admin, &added).await;
            }

            "disable" | "reenable" => {
                k::adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &manifest, None, &[])
                    .await
                    .unwrap();
                if change == "reenable" {
                    activate(&db, &admin, &manifest).await;
                }
            }
            "upgrade" => {
                let mut next = manifest.clone();
                next.version += 1;
                next.operations[0].executable.as_mut().unwrap().expression = "subtotal + 1".into();
                activate(&db, &admin, &next).await;
            }
            "input" => {
                k::revise_as(
                    &db,
                    &admin,
                    &id,
                    json!({"inputs_json":r#"{"subtotal":2000,"discount_pct":10}"#})
                        .as_object()
                        .unwrap(),
                )
                .await
                .unwrap();
            }
            "view" => {
                k::replace_home_policy(&db, &admin, KERNEL_ROOT_ID, &[])
                    .await
                    .unwrap();
            }
            "membership" => {
                crate::kernel::hosted_identity::reconcile_hosted_caller(&db, |_| async {
                    // SAFETY: a later complete synthetic roster excludes Admin.
                    Ok(unsafe { crate::kernel::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                        "test:other".into(), vec![("test:other".into(),"other@example.test".into())].into_iter().collect(), std::collections::BTreeMap::new(),
                    ) })
                }).await.unwrap();
            }
            "credential" => {
                // Private fixture seam emulates credential rebinding, without
                // granting the captured principal authority over the new caller.
                sqlx::query(
                    "UPDATE kernel_principals SET auth_binding='test:rebound' WHERE principal_id=?",
                )
                .bind(&admin)
                .execute(db.write_pool())
                .await
                .unwrap();
            }
            _ => unreachable!(),
        }
        resume_tx.send(()).unwrap();
        let refusal = pending.await.unwrap().expect_err(change);
        assert!(
            refusal
                .to_string()
                .contains("result discarded; explicitly retry"),
            "{change}: {refusal}"
        );
        if matches!(change, "reenable" | "upgrade" | "input") {
            let fresh = call(
                &db,
                &admin,
                &manifest.namespace,
                &manifest.name,
                "compute",
                &id,
            )
            .await
            .unwrap();
            assert_eq!(
                fresh.result["value"],
                match change {
                    "upgrade" => 1001,
                    "input" => 1800,
                    _ => 900,
                }
            );
        }
    }
}

#[tokio::test]
async fn development_transport_uses_identifiers_and_refuses_executable_arguments() {
    let _serial = RUNTIME_TEST.lock().await;
    use crate::mcp::{Caller, EngineHandle, ToolRegistry};
    let (db, admin) = k::create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let manifest = package("quote");
    activate(&db, &admin, &manifest).await;
    let id = create(
        &db,
        &admin,
        &manifest,
        r#"{"subtotal":1000,"discount_pct":10}"#,
    )
    .await;
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let caller = Caller::authenticated("test:admin");
    let engine = EngineHandle::KernelV2(db.clone());
    let args = json!({"namespace":manifest.namespace,"name":manifest.name,"package_operation":"compute","record_id":id});
    let value = registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "call_package_operation",
            args.clone(),
        )
        .await
        .unwrap();
    assert_eq!(value["result"]["value"], 900);
    let described = registry.call_engine(engine.clone(),caller.clone(),"describe_package_operations",
        json!({"namespace":manifest.namespace,"name":manifest.name,"scope_home":KERNEL_ROOT_ID})).await.unwrap();
    assert_eq!(described["provider_schemas"][PROVIDER]["profile"], PROFILE);
    let mut forged = args.clone();
    forged["executable"] = json!({"expression":"1"});
    assert!(registry
        .call_engine(
            engine.clone(),
            caller.clone(),
            "call_package_operation",
            forged
        )
        .await
        .is_err());
    assert!(registry
        .call_engine(
            engine,
            Caller::authenticated("unknown"),
            "call_package_operation",
            args
        )
        .await
        .is_err());
    assert!(!registry.has_engine_operation(
        "call_package_operation",
        crate::mcp::registry::EngineKind::Sqlite,
        None
    ));
}

#[tokio::test]
async fn record_discovery_uses_selection_identity_and_is_bounded_without_evaluation() {
    use crate::package_operations::discovery::describe_record_checked as discover;
    let _serial = RUNTIME_TEST.lock().await;
    let (db, admin) = k::create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let mut first = package("quote");
    first.namespace = "author.unrelated".into();
    first.name = "arbitrary".into();
    activate(&db, &admin, &first).await;
    let mut second = first.clone();
    second.namespace = "another.author".into();
    second.name = "independent".into();
    second.operations[0].executable.as_mut().unwrap().expression = "subtotal + discount_pct".into();
    activate(&db, &admin, &second).await;
    // A real compiled effectful service is installed in the same scope, but
    // is not a candidate for this read/compute invocation port.
    activate(&db, &admin, &crate::v2_standard::relates_to::package()).await;
    let service = crate::v2_standard::relates_to::package();
    let service_id = k::create_as(
        &db,
        &admin,
        &service.definitions[0].family,
        "relation",
        json!({"body":"{}"}).as_object().unwrap(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    assert!(discover(
        &db,
        &admin,
        "test:admin",
        &service_id,
        std::future::ready(())
    )
    .await
    .unwrap()["packages"]
        .as_array()
        .unwrap()
        .is_empty());
    let home = k::create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    let op = &first.operations[0];
    let id = k::create_as(
        &db,
        &admin,
        &op.family,
        &op.kind,
        json!({"inputs_json":"malformed source is not parsed by discovery"})
            .as_object()
            .unwrap(),
        &home,
    )
    .await
    .unwrap();
    // Discovery must not enter even the guest request boundary or read source.
    let before_guest = GUEST_CALLS.load(std::sync::atomic::Ordering::SeqCst);
    let found = discover(&db, &admin, "test:admin", &id, std::future::ready(()))
        .await
        .unwrap();
    assert_eq!(
        GUEST_CALLS.load(std::sync::atomic::Ordering::SeqCst),
        before_guest
    );
    assert_eq!(found["complete"], true);
    assert_eq!(found["packages"].as_array().unwrap().len(), 2);
    assert_eq!(found["packages"][0]["namespace"], second.namespace);
    assert_eq!(found["packages"][1]["name"], first.name);
    let exact = describe_package_operations_as(&db, &admin, &home, &first.namespace, &first.name)
        .await
        .unwrap();
    assert_eq!(found["packages"][1]["operations"], exact["operations"]);
    // A stored record pin must match exactly; it is never reinterpreted.
    sqlx::query("UPDATE kernel_records SET pin_version=999 WHERE id=?")
        .bind(&id)
        .execute(db.write_pool())
        .await
        .unwrap();
    assert!(
        discover(&db, &admin, "test:admin", &id, std::future::ready(()))
            .await
            .unwrap()["packages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    sqlx::query("UPDATE kernel_records SET pin_version=1 WHERE id=?")
        .bind(&id)
        .execute(db.write_pool())
        .await
        .unwrap();
    // Child tombstone suppresses only that package, while the other inherits.
    k::adopt_package_at(&db, &admin, &home, &first, None, &[])
        .await
        .unwrap();
    assert_eq!(
        discover(&db, &admin, "test:admin", &id, std::future::ready(()))
            .await
            .unwrap()["packages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let identity = second.identity().unwrap();
    assert!(
        k::adopt_package_at(&db, &admin, &home, &second, Some(&identity), &[])
            .await
            .is_err()
    );
    k::adopt_package_at(
        &db,
        &admin,
        &home,
        &second,
        Some(&identity),
        &second.declared_reads,
    )
    .await
    .unwrap();
    let outsider = k::create_principal(&db, "account", "Other", "test:other", &admin)
        .await
        .unwrap();
    let hidden = discover(&db, &outsider, "test:other", &id, std::future::ready(()))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        hidden,
        discover(
            &db,
            &outsider,
            "test:other",
            "missing",
            std::future::ready(())
        )
        .await
        .unwrap_err()
        .to_string()
    );

    // Genuine pre-enforcement displacement uses the repository's legacy event
    // fixture, never a relaxed live admission path or an edited log entry.
    let mut newer = second.clone();
    newer.version = 2;
    let entry = &mut newer.definitions[0];
    entry.version = 2;
    let mut bytes: Value = serde_json::from_str(&entry.artifact_bytes).unwrap();
    bytes["version"] = json!(2);
    entry.artifact_bytes = serde_json::to_string(&bytes).unwrap();
    entry.digest =
        crate::meta::definition_artifact::digest_artifact_bytes(entry.artifact_bytes.as_bytes());
    let pin = crate::meta::definition_artifact::RevisionIdentity {
        family: entry.family.clone(),
        version: entry.version,
        digest: entry.digest.clone(),
    };
    k::install_package_as(&db, &admin, &newer).await.unwrap();
    crate::dependency_tests::legacy_override(&db, &admin, &home, &pin).await;
    assert!(
        discover(&db, &admin, "test:admin", &id, std::future::ready(()))
            .await
            .unwrap()["packages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let entry = &second.definitions[0];
    crate::dependency_tests::legacy_override(
        &db,
        &admin,
        &home,
        &crate::meta::definition_artifact::RevisionIdentity {
            family: entry.family.clone(),
            version: entry.version,
            digest: entry.digest.clone(),
        },
    )
    .await;
    assert_eq!(
        discover(&db, &admin, "test:admin", &id, std::future::ready(()))
            .await
            .unwrap()["packages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );

    // Projection/log disagreement is an error, not an empty complete result.
    sqlx::query("UPDATE kernel_package_selections SET ack_reads='[\"forged\"]' WHERE scope_home=? AND namespace=?").bind(&home).bind(&second.namespace).execute(db.write_pool()).await.unwrap();
    assert!(
        discover(&db, &admin, "test:admin", &id, std::future::ready(()))
            .await
            .unwrap_err()
            .to_string()
            .contains("disagrees")
    );
    sqlx::query(
        "UPDATE kernel_package_selections SET ack_reads=? WHERE scope_home=? AND namespace=?",
    )
    .bind(serde_json::to_string(&second.declared_reads).unwrap())
    .bind(&home)
    .bind(&second.namespace)
    .execute(db.write_pool())
    .await
    .unwrap();

    // Deliberately damaged private storage, NOT a valid adoption or replay:
    // append a raw invalid event (without editing append-only history) and a
    // matching projection. The live writer and fold both reject this payload.
    // Discovery must still exclude its unacknowledged read even when the row
    // matches that broken event. No production admission bypass is added.
    let payload = json!({"scope_home":home,"namespace":second.namespace,"name":second.name,
        "selected":{"version":identity.version,"digest":identity.digest},"acknowledged_reads":[]});
    let seq:i64=sqlx::query_scalar("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status,created_at) VALUES(?,?,'kernel.package_adopted.v1',?,?,1,'complete','2026-10-27T00:00:00Z') RETURNING seq")
        .bind(uuid::Uuid::new_v4().to_string()).bind(&home).bind(payload.to_string()).bind(&admin).fetch_one(db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_package_selections SET ack_reads='[]',event_seq=? WHERE scope_home=? AND namespace=?").bind(seq).bind(&home).bind(&second.namespace).execute(db.write_pool()).await.unwrap();
    assert!(
        discover(&db, &admin, "test:admin", &id, std::future::ready(()))
            .await
            .unwrap()["packages"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    db.close().await;

    let (db, admin) = k::create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let base = package("quote");
    activate(&db, &admin, &base).await;
    let id = create(&db, &admin, &base, r#"{"subtotal":1,"discount_pct":0}"#).await;
    // Eight valid packages with eight large but legal descriptors exceed the
    // response budget without changing language admission bounds.
    for i in 0..8 {
        let mut large = base.clone();
        large.name = format!("large-{i}");
        large.operations = (0..8)
            .map(|j| {
                let mut op = base.operations[0].clone();
                op.name = format!("compute-{j}");
                op.description = "d".repeat(1024);
                op.executable.as_mut().unwrap().expression =
                    format!("{}subtotal", " ".repeat(1000));
                op
            })
            .collect();
        activate(&db, &admin, &large).await;
    }
    assert!(
        discover(&db, &admin, "test:admin", &id, std::future::ready(()))
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds development bounds")
    );
    // Cap+1 must refuse BEFORE manifest/projection verification. These private
    // deliberately unauthorised rows would fail log integrity if inspected.
    for i in 0..33 {
        sqlx::query("INSERT INTO kernel_package_selections(scope_home,namespace,name,selected_version,selected_digest,ack_actor,ack_reads,event_seq,created_at) VALUES(?,'cap',?,1,'invalid',?,'[]',1,'test')")
            .bind(KERNEL_ROOT_ID).bind(format!("{i:02}")).bind(&admin).execute(db.write_pool()).await.unwrap();
    }
    assert!(
        discover(&db, &admin, "test:admin", &id, std::future::ready(()))
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeds development bounds")
    );
    db.close().await;
}
