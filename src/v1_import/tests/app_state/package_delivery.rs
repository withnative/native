use super::*;
use crate::mcp::Caller;

#[cfg(feature = "package-cel-dev")]
#[tokio::test]
async fn development_package_delivery_rechecks_installed_app_source_consent_and_generation() {
    let _serial = crate::package_cel_dev::RUNTIME_TEST.lock().await;
    use crate::package_manifest::PackageManifest;
    use crate::package_operations::{call_authenticated_as, call_checked};
    for change in [
        "uninstall",
        "source_runtime",
        "source_witness",
        "consent",
        "retained_body",
    ] {
        let (_fixture, db, report) = super::declarative_apps::fixture(
            &json!({"contract":"native.app.v2","needs":[],"effects":[]}),
        )
        .await;
        let admin = &report.principals["account-a"];
        // Private fixture setup: imported roots deliberately have no ordinary
        // package manager. Model a locally prepared package workspace owned by
        // this authenticated member; no route under test changes ownership or
        // installs anything on behalf of an app.
        sqlx::query("UPDATE kernel_roots SET owner_id=? WHERE root_id=?")
            .bind(admin)
            .bind(KERNEL_ROOT_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        let manifest = PackageManifest::from_canonical_value(
            &serde_json::from_str(include_str!(
                "../../../../examples/packages/cel-scalar-dev/quote.package.json"
            ))
            .unwrap(),
        )
        .unwrap();
        let identity = k::install_package_as(&db, admin, &manifest).await.unwrap();
        k::adopt_package_at(
            &db,
            admin,
            KERNEL_ROOT_ID,
            &manifest,
            Some(&identity),
            &manifest.declared_reads,
        )
        .await
        .unwrap();
        let op = &manifest.operations[0];
        let id = k::create_as(
            &db,
            admin,
            &op.family,
            &op.kind,
            json!({"inputs_json":r#"{"subtotal":1000,"discount_pct":10}"#})
                .as_object()
                .unwrap(),
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
        let caller = Caller::authenticated("account-a").with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new(
                "agent.notion-pages",
                "999.42.0",
                "install",
            )
            .unwrap(),
        );
        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &caller,
            "call_package_operation",
            &json!({}),
            None,
        );
        let first = dispatch
            .scope(call_authenticated_as(
                &db,
                admin,
                "account-a",
                &manifest.namespace,
                &manifest.name,
                "compute",
                &id,
            ))
            .await
            .unwrap();
        assert_eq!(first.result["value"], 900);
        // The actual shared transport accepts the host assertion and performs
        // native read admission; no app lifecycle tool is involved in a call.
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let listed = registry
            .call_engine(
                crate::mcp::EngineHandle::KernelV2(db.clone()),
                Caller::authenticated("account-a"),
                "manage_alpha_tabs",
                json!({"action":"list"}),
            )
            .await
            .unwrap();
        assert_eq!(
            listed["development_package_operations"],
            "native.package-cel-dev.reads/1"
        );
        let value = registry.call_engine(crate::mcp::EngineHandle::KernelV2(db.clone()),caller.clone(),"call_package_operation",
            json!({"namespace":manifest.namespace,"name":manifest.name,"package_operation":"compute","record_id":id})).await.unwrap();
        assert_eq!(value["result"]["value"], 900);
        let discovered = registry
            .call_engine(
                crate::mcp::EngineHandle::KernelV2(db.clone()),
                caller.clone(),
                "describe_package_operations",
                json!({"record_id":id}),
            )
            .await
            .unwrap();
        assert_eq!(discovered["packages"][0]["namespace"], manifest.namespace);
        let (computed_tx, computed_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        let worker_db = db.clone();
        let worker_admin = admin.clone();
        let worker_id = id.clone();
        let worker_manifest = manifest.clone();
        let pending = tokio::spawn(async move {
            dispatch
                .scope(call_checked(
                    &worker_db,
                    &worker_admin,
                    Some("account-a"),
                    &worker_manifest.namespace,
                    &worker_manifest.name,
                    "compute",
                    &worker_id,
                    async {
                        computed_tx.send(()).unwrap();
                        resume_rx.await.unwrap();
                    },
                ))
                .await
        });
        computed_rx.await.unwrap();
        let (metadata_tx, metadata_rx) = tokio::sync::oneshot::channel();
        let (deliver_tx, deliver_rx) = tokio::sync::oneshot::channel();
        let metadata_db = db.clone();
        let metadata_actor = admin.clone();
        let metadata_id = id.clone();
        let metadata_dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &caller,
            "describe_package_operations",
            &json!({}),
            None,
        );
        let metadata = tokio::spawn(async move {
            metadata_dispatch
                .scope(
                    crate::package_operations::discovery::describe_record_checked(
                        &metadata_db,
                        &metadata_actor,
                        "account-a",
                        &metadata_id,
                        async {
                            metadata_tx.send(()).unwrap();
                            deliver_rx.await.unwrap();
                        },
                    ),
                )
                .await
        });
        metadata_rx.await.unwrap();

        match change {
            "uninstall" => {
                k::app_installs::remove_as(&db, admin, "agent.notion-pages", "install")
                    .await
                    .unwrap();
            }
            "source_runtime" => {
                k::observe_facet_as(
                    &db,
                    admin,
                    "secret",
                    &k::FacetObservation {
                        key: "runtime".into(),
                        value: Some("native.mdx.v2".into()),
                        value_num: None,
                        vocab_ref: None,
                        as_of: "2026-10-27T00:00:00Z".into(),
                    },
                    None,
                )
                .await
                .unwrap();
            }
            "source_witness" => {
                // Private storage boundary models a host source-witness repin
                // while keeping the same installed generation, bytes and consent.
                // Fresh admission alone still succeeds; delivery must compare
                // the exact source witness captured before computation.
                sqlx::query("UPDATE kernel_app_package_sources SET event_seq=event_seq+1 WHERE package='agent.notion-pages'")
                    .execute(db.write_pool()).await.unwrap();
                assert!(k::app_installs::admit_account_app_as(
                    &db,
                    "account-a",
                    caller.host_asserted_app().unwrap()
                )
                .await
                .is_ok());
            }
            "retained_body" => {
                let revision = k::read_record_as(&db, admin, "secret")
                    .await
                    .unwrap()
                    .unwrap()
                    .revision;
                k::hq::set_body_as(&db, admin, "secret", "Changed after computation", revision)
                    .await
                    .unwrap();
            }
            "consent" => {
                // Private fixture boundary models a new consent epoch, as used
                // by offboarding; delivery must not rely on earlier consent.
                sqlx::query("INSERT INTO kernel_app_consent_revocations(principal,event_seq) VALUES(?,999999)")
                    .bind(admin).execute(db.write_pool()).await.unwrap();
            }
            _ => unreachable!(),
        }
        resume_tx.send(()).unwrap();
        deliver_tx.send(()).unwrap();
        let metadata_result = metadata.await.unwrap();
        if change == "retained_body" {
            assert_eq!(
                metadata_result.unwrap()["packages"]
                    .as_array()
                    .unwrap()
                    .len(),
                1
            );
        } else {
            assert!(
                metadata_result
                    .unwrap_err()
                    .to_string()
                    .contains("result discarded; explicitly retry"),
                "{change}"
            );
        }

        let delivered = pending.await.unwrap();
        if change == "retained_body" {
            // Existing installs execute their frozen source, not the editable
            // artifact head. Preserve that established app contract.
            assert_eq!(delivered.unwrap().result["value"], 900);
        } else {
            let refused = delivered.expect_err(change);
            assert!(
                refused
                    .to_string()
                    .contains("result discarded; explicitly retry"),
                "{change}: {refused}"
            );
        }
        // An app failure does not poison a valid independent agent call.
        assert_eq!(
            call_authenticated_as(
                &db,
                admin,
                "account-a",
                &manifest.namespace,
                &manifest.name,
                "compute",
                &id
            )
            .await
            .unwrap()
            .result["value"],
            900
        );
    }
}
