//! Explicitly opted-in local development CLI subset.
use super::v2_contract_smoke::{init_admin_world, World};

#[test]
fn v2_contract_smoke_cel_scalar_packages() {
    let w = World::fresh();
    let (_, home) = init_admin_world(&w);
    let mut receipts = Vec::new();
    for (name, namespace, package_bytes, record_bytes, expected) in [
        (
            "quote",
            "example.sales",
            include_bytes!("../../examples/packages/cel-scalar-dev/quote.package.json").as_slice(),
            include_bytes!("../../examples/packages/cel-scalar-dev/quote.record.json").as_slice(),
            serde_json::json!(900),
        ),
        (
            "dispatch",
            "example.shipping",
            include_bytes!("../../examples/packages/cel-scalar-dev/dispatch.package.json")
                .as_slice(),
            include_bytes!("../../examples/packages/cel-scalar-dev/dispatch.record.json")
                .as_slice(),
            serde_json::json!(true),
        ),
    ] {
        let package = w.write(&format!("{name}.package.json"), package_bytes);
        let record = w.write(&format!("{name}.record.json"), record_bytes);
        w.run_ok("acct:admin", &["package-install", "--json", &package]);
        w.run_ok(
            "acct:admin",
            &[
                "package-adopt",
                "--json",
                &package,
                "--scope",
                "kernel:root",
                "--ack-reads",
                r#"["record:view"]"#,
            ],
        );
        let described = w.run_ok(
            "acct:admin",
            &[
                "package-describe",
                "--scope",
                &home,
                "--namespace",
                namespace,
                "--name",
                name,
            ],
        );
        assert_eq!(
            described["operations"][0]["executable"]["language"],
            "cel-subset@1"
        );
        let created = w.run_ok(
            "acct:admin",
            &[
                "create",
                "--family",
                &format!("{namespace}.{name}"),
                "--kind",
                name,
                "--home",
                &home,
                "--json",
                &record,
            ],
        );
        let request = w.write(
            &format!("{name}.call.json"),
            serde_json::to_string(&serde_json::json!({"record_id":created["id"]}))
                .unwrap()
                .as_bytes(),
        );
        let result = w.run_ok(
            "acct:admin",
            &[
                "package-call",
                "--namespace",
                namespace,
                "--name",
                name,
                "--operation",
                "compute",
                "--json",
                &request,
            ],
        );
        assert_eq!(result["result"]["value"], expected);
        assert_eq!(result["receipt"]["execution"]["interim"], true);
        let guest = &result["receipt"]["execution"]["guest"];
        assert_eq!(guest["abi"], native_package_cel_wire::ABI);
        assert_eq!(
            guest["module_sha256"],
            native_package_cel_host::GUEST_MODULE_SHA256
        );
        assert_eq!(guest["runtime"], native_package_cel_host::RUNTIME);
        assert_eq!(
            guest["configuration"],
            native_package_cel_host::CONFIGURATION
        );
        assert_eq!(guest["phase"], "Deliver");
        assert!(guest["fuel_used"].as_u64().unwrap() > 0);
        receipts.push(serde_json::json!({"namespace":namespace,"package":name,"outcome":result}));
    }
    let bytes = serde_json::to_vec_pretty(&receipts).unwrap();
    assert!(bytes.len() < 32 * 1024);
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/package-cel-guest-stage3/cli-receipts.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}
