//! End-to-end smoke for the `v2_contract` example harness: init, install,
//! adopt, create, link, query, revise, history, and a refusal — over a
//! throwaway `demo.widget` ontology that shares no names with lab fixtures.

use std::path::PathBuf;
use std::process::Command;

const WIDGET_BYTES: &str = r#"{"family":"demo.widget","version":1,"primary_type":"Widget","interpreter":"native.defn/2","kinds":[{"token":"Widget","fields":[{"name":"accession","type":"text","required":true},{"name":"mass_kg","type":"number","required":true},{"name":"color","type":"text","required":false}],"identity":{"field":"accession"},"links":[],"maturity":"current","description":"A demo widget."},{"token":"Cog","fields":[{"name":"accession","type":"text","required":true},{"name":"teeth","type":"integer","required":true}],"identity":{"field":"accession"},"links":[{"predicate":"fitted_to","target":{"primary_type":"Widget","kind":"Widget"},"direction":"out","cardinality":"many"}],"maturity":"current","description":"A cog fitted to a widget."}]}"#;

/// A deliberately renamed generic fixture: a different namespace, family,
/// primary type, kind, and source-field name, bound to the same trusted
/// provider. It exists to prove the seam and provider carry no budget-specific
/// branches.
const CUSTOM_MODEL_BYTES: &str = r#"{"family":"demo.custom.model","version":1,"interpreter":"native.defn/3","primary_type":"Model","kinds":[{"token":"model","description":"A generic model held in one text field.","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"title","type":"text","required":true,"description":"Short human title."},{"name":"model_json","type":"text","required":true,"description":"JSON object of address -> expression."}],"links":[]}]}"#;

fn custom_model_package() -> native_ce::package_manifest::PackageManifest {
    use native_ce::package_manifest::{
        DefinitionEntry, OperationDescriptor, PackageManifest,
        OPERATION_PROVIDER_HOST_TABLE_ARITHMETIC,
    };
    PackageManifest {
        operations: vec![OperationDescriptor {
            name: "recalculate".to_string(),
            description: "Evaluate the model_json field with the generic provider.".to_string(),
            provider: OPERATION_PROVIDER_HOST_TABLE_ARITHMETIC.to_string(),
            family: "demo.custom.model".to_string(),
            kind: "model".to_string(),
            source_field: "model_json".to_string(),
            reads: vec!["record:view".to_string()],
            effects: vec![],
        }],
        namespace: "demo.custom".to_string(),
        name: "model".to_string(),
        version: 1,
        definitions: vec![DefinitionEntry {
            family: "demo.custom.model".to_string(),
            version: 1,
            artifact_bytes: CUSTOM_MODEL_BYTES.to_string(),
            digest: native_ce::meta::definition_artifact::digest_artifact_bytes(
                CUSTOM_MODEL_BYTES.as_bytes(),
            ),
        }],
        behaviour: None,
        surface: None,
        declared_reads: vec!["record:view".to_string()],
    }
}

struct World {
    dir: tempfile::TempDir,
    db: String,
    bin: PathBuf,
}

impl World {
    fn fresh() -> Self {
        // Parallel tests can observe the same clock timestamp. Reserve the
        // directory atomically so their init subprocesses cannot share a DB.
        let dir = tempfile::Builder::new()
            .prefix("v2-contract-smoke-")
            .tempdir()
            .unwrap();
        let db = dir.path().join("probe.db").to_str().unwrap().to_string();
        // Examples get no CARGO_BIN_EXE; resolve sibling-side: this test
        // binary runs from $TARGET/debug/deps/, the example from
        // $TARGET/debug/examples/. Survives custom CARGO_TARGET_DIR.
        let bin = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|p| p.to_path_buf()))
            .and_then(|deps| deps.parent().map(|p| p.to_path_buf()))
            .map(|debug| debug.join("examples").join("v2_contract"))
            .unwrap();
        World { dir, db, bin }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        path.to_str().unwrap().to_string()
    }

    fn run(&self, as_binding: &str, args: &[&str]) -> (bool, serde_json::Value) {
        let out = Command::new(&self.bin)
            .arg("--db")
            .arg(&self.db)
            .arg("--as")
            .arg(as_binding)
            .args(args)
            .output()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or_else(|_| {
            panic!("non-JSON stdout: {}", String::from_utf8_lossy(&out.stdout))
        });
        (out.status.success(), value)
    }

    fn run_ok(&self, as_binding: &str, args: &[&str]) -> serde_json::Value {
        let (ok, value) = self.run(as_binding, args);
        assert!(ok, "command failed: {args:?} -> {value}");
        assert!(value.get("error").is_none(), "{value}");
        value
    }
}

#[test]
fn v2_contract_smoke_demo_widget() {
    let w = World::fresh();
    // init ignores --as (no principals exist yet): pass a placeholder.
    let out = std::process::Command::new(&w.bin)
        .arg("--db")
        .arg(&w.db)
        .arg("init")
        .arg("--label")
        .arg("Admin")
        .arg("--binding")
        .arg("acct:admin")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init exited {}; stdout: {}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let admin: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(admin.get("principal_id").is_some(), "{admin}");

    let op = w.run_ok(
        "acct:admin",
        &[
            "principal",
            "--kind",
            "agent",
            "--label",
            "Op",
            "--binding",
            "agent:op",
        ],
    );
    let op_id = op["principal_id"].as_str().unwrap().to_string();

    let grants = w.write(
        "admin.json",
        format!(
            r#"{{"{}": "manage"}}"#,
            admin["principal_id"].as_str().unwrap()
        )
        .as_bytes(),
    );
    let h = w.run_ok(
        "acct:admin",
        &["home", "--parent", "kernel:root", "--json", &grants],
    );
    let home_id = h["home_id"].as_str().unwrap().to_string();
    let op_grant = w.write("op.json", format!(r#"{{"{op_id}": "manage"}}"#).as_bytes());
    w.run_ok(
        "acct:admin",
        &["grant", "--home", &home_id, "--json", &op_grant],
    );

    let bytes = w.write("widget.json", WIDGET_BYTES.as_bytes());
    let installed = w.run_ok(
        "acct:admin",
        &[
            "install",
            "--family",
            "demo.widget",
            "--version",
            "1",
            "--json",
            &bytes,
        ],
    );
    let digest = installed["digest"].as_str().unwrap().to_string();
    w.run_ok(
        "acct:admin",
        &[
            "adopt",
            "--family",
            "demo.widget",
            "--version",
            "1",
            "--digest",
            &digest,
            "--scope",
            &home_id,
        ],
    );

    let catalog = w.run_ok("agent:op", &["tools"]);
    assert_eq!(catalog.as_object().unwrap().len(), 2);
    assert_eq!(
        catalog["rules"],
        serde_json::json!(native_ce::definition_shape::TYPED_TOOL_RULES)
    );
    let rules = catalog["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap())
        .collect::<Vec<_>>()
        .join(" ");
    for required in [
        "Kernel refusals are returned unchanged",
        "compare-and-swap",
        "record's own pin",
        "Queries span versions",
        "Query predicates are suggestions",
        "Link cardinalities are declaration metadata",
        "generic link subcommand",
    ] {
        assert!(rules.contains(required), "missing shared rule: {required}");
    }
    let tools = catalog["tools"].as_array().unwrap();
    for tool in tools {
        for rule in native_ce::definition_shape::TYPED_TOOL_RULES {
            assert!(!tool["description"].as_str().unwrap().contains(rule));
        }
    }
    let create_tool = tools
        .iter()
        .find(|t| t["name"] == "create_demo_widget_Widget")
        .unwrap();
    assert_eq!(
        create_tool["inputSchema"]["properties"]["home"]["enum"],
        serde_json::json!([home_id])
    );
    let typed_input =
        serde_json::json!({"home":home_id,"fields":{"accession":"TYPED-1","mass_kg":3}})
            .to_string();
    let typed = w.run_ok(
        "agent:op",
        &["call", "create_demo_widget_Widget", &typed_input],
    );
    assert!(typed["id"].is_string());
    let query_input = serde_json::json!({"field_equals":{"accession":"TYPED-1"}}).to_string();
    let page = w.run_ok(
        "agent:op",
        &["call", "query_demo_widget_Widget", &query_input],
    );
    assert_eq!(page["hits"][0]["pin"]["digest"], digest);
    let (ok, refused) = w.run(
        "agent:op",
        &["call", "create_demo_widget_Widget", &typed_input],
    );
    assert!(!ok);
    assert!(refused["error"]
        .as_str()
        .unwrap()
        .contains("identity value unavailable"));

    let fields = w.write(
        "w1.json",
        br#"{"accession": "W-1", "mass_kg": 2.5, "color": "red"}"#,
    );
    let created = w.run_ok(
        "agent:op",
        &[
            "create",
            "--family",
            "demo.widget",
            "--kind",
            "Widget",
            "--home",
            &home_id,
            "--json",
            &fields,
        ],
    );
    let wid = created["id"].as_str().unwrap().to_string();
    let cog = w.write("c1.json", br#"{"accession": "C-1", "teeth": 12}"#);
    let created_cog = w.run_ok(
        "agent:op",
        &[
            "create",
            "--family",
            "demo.widget",
            "--kind",
            "Cog",
            "--home",
            &home_id,
            "--json",
            &cog,
        ],
    );
    let cid = created_cog["id"].as_str().unwrap().to_string();

    w.run_ok(
        "agent:op",
        &[
            "link",
            "--source",
            &cid,
            "--predicate",
            "fitted_to",
            "--target",
            &wid,
        ],
    );

    let filt = w.write(
        "q.json",
        format!(
            r#"{{"linked_to": {{"predicate": "fitted_to", "id": "{wid}", "direction": "out"}}}}"#
        )
        .as_bytes(),
    );
    let found = w.run_ok(
        "agent:op",
        &[
            "query",
            "--family",
            "demo.widget",
            "--kind",
            "Cog",
            "--json",
            &filt,
        ],
    );
    assert_eq!(found["hits"].as_array().unwrap().len(), 1, "{found}");
    assert_eq!(found["hits"][0]["id"].as_str().unwrap(), cid);

    let patch = w.write("p.json", br#"{"color": "blue"}"#);
    w.run_ok("agent:op", &["revise", "--id", &wid, "--json", &patch]);
    let seen = w.run_ok("agent:op", &["read", "--id", &wid]);
    assert_eq!(seen["id"].as_str().unwrap(), wid);
    let hist = w.run_ok("agent:op", &["history", "--id", &wid]);
    let types: Vec<&str> = hist
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event_type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        vec!["kernel.record_created.v1", "kernel.record_revised.v1"],
        "{hist:?}"
    );

    // Refusal: the identity is taken, reported uniformly as JSON.
    let dup = w.write("dup.json", br#"{"accession": "W-1", "mass_kg": 1.0}"#);
    let (ok, err) = w.run(
        "agent:op",
        &[
            "create",
            "--family",
            "demo.widget",
            "--kind",
            "Widget",
            "--home",
            &home_id,
            "--json",
            &dup,
        ],
    );
    assert!(!ok);
    assert_eq!(
        err,
        serde_json::json!({"error": "identity value unavailable"}),
        "{err}"
    );
}

fn pkg_artifact(family: &str, primary: &str, token: &str) -> String {
    serde_json::json!({
        "family": family, "version": 1,
        "interpreter": "native.defn/2", "primary_type": primary,
        "kinds": [{"token": token,
            "fields": [{"name": "title", "type": "text", "required": true}],
            "identity": {"field": "title"},
            "links": [{"predicate": "relates_to",
                "target": {"primary_type": primary, "kind": token},
                "direction": "either"}],
            "maturity": "current", "description": "Smoke package kind."}],
    })
    .to_string()
}

fn pkg_manifest(
    name: &str,
    family: &str,
    primary: &str,
    token: &str,
    view: &str,
    fallback: &str,
) -> serde_json::Value {
    use sha2::{Digest, Sha256};
    let artifact = pkg_artifact(family, primary, token);
    let digest = format!("{:x}", Sha256::digest(artifact.as_bytes()));
    serde_json::json!({
        "format": "native.package-manifest@1",
        "namespace": "smoke", "name": name, "version": 1,
        "definitions": [{"family": family, "version": 1,
            "artifact_bytes": artifact, "digest": digest}],
        "behaviour": {"kind": "host.readonly.v1",
            "reads": ["linked_record:view"], "effects": []},
        "surface": {"kind": "host.surface.v1",
            "view": view, "fallback": fallback},
        "declared_reads": ["linked_record:view"],
    })
}

#[test]
fn v2_contract_smoke_package_disable_keeps_other_surface() {
    let w = World::fresh();
    let out = std::process::Command::new(&w.bin)
        .arg("--db")
        .arg(&w.db)
        .arg("init")
        .arg("--label")
        .arg("Admin")
        .arg("--binding")
        .arg("acct:admin")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init exited {}; stdout: {}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let admin: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(admin.get("principal_id").is_some(), "{admin}");

    let op = w.run_ok(
        "acct:admin",
        &[
            "principal",
            "--kind",
            "agent",
            "--label",
            "Op",
            "--binding",
            "agent:op",
        ],
    );
    let op_id = op["principal_id"].as_str().unwrap().to_string();
    let grants = w.write(
        "admin.json",
        format!(
            r#"{{"{}": "manage"}}"#,
            admin["principal_id"].as_str().unwrap()
        )
        .as_bytes(),
    );
    let h = w.run_ok(
        "acct:admin",
        &["home", "--parent", "kernel:root", "--json", &grants],
    );
    let home_id = h["home_id"].as_str().unwrap().to_string();
    let op_grant = w.write("op.json", format!(r#"{{"{op_id}": "manage"}}"#).as_bytes());
    w.run_ok(
        "acct:admin",
        &["grant", "--home", &home_id, "--json", &op_grant],
    );

    // Two disjoint fixture packages: no shared families, no shared names.
    let keep_m = pkg_manifest(
        "keep",
        "smoke.keep",
        "keepnote",
        "KeepNote",
        "keep.view",
        "keep.unavailable",
    );
    let opt_m = pkg_manifest(
        "opt",
        "smoke.opt",
        "optnote",
        "OptNote",
        "opt.view",
        "opt.unavailable",
    );
    let keep_f = w.write("keep-pkg.json", &serde_json::to_vec(&keep_m).unwrap());
    let opt_f = w.write("opt-pkg.json", &serde_json::to_vec(&opt_m).unwrap());
    let ack = r#"["linked_record:view"]"#;
    let keep_id = w.run_ok("acct:admin", &["package-install", "--json", &keep_f]);
    assert_eq!(keep_id["name"].as_str().unwrap(), "keep", "{keep_id}");
    let opt_id = w.run_ok("acct:admin", &["package-install", "--json", &opt_f]);
    assert_eq!(opt_id["name"].as_str().unwrap(), "opt", "{opt_id}");
    w.run_ok(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &keep_f,
            "--scope",
            &home_id,
            "--ack-reads",
            ack,
        ],
    );
    w.run_ok(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &opt_f,
            "--scope",
            &home_id,
            "--ack-reads",
            ack,
        ],
    );

    // Populated rows: one explicit link target per package plus a visible row.
    let tk = w.write("tk.json", br#"{"title": "Keep-Target"}"#);
    let t_keep = w.run_ok(
        "agent:op",
        &[
            "create",
            "--family",
            "smoke.keep",
            "--kind",
            "KeepNote",
            "--home",
            &home_id,
            "--json",
            &tk,
        ],
    );
    let target_keep = t_keep["id"].as_str().unwrap().to_string();
    let sk = w.write("sk.json", br#"{"title": "Keep-Row"}"#);
    let s_keep = w.run_ok(
        "agent:op",
        &[
            "create",
            "--family",
            "smoke.keep",
            "--kind",
            "KeepNote",
            "--home",
            &home_id,
            "--json",
            &sk,
        ],
    );
    let row_keep = s_keep["id"].as_str().unwrap().to_string();
    w.run_ok(
        "agent:op",
        &[
            "link",
            "--source",
            &row_keep,
            "--predicate",
            "relates_to",
            "--target",
            &target_keep,
        ],
    );
    let to = w.write("to.json", br#"{"title": "Opt-Target"}"#);
    let t_opt = w.run_ok(
        "agent:op",
        &[
            "create",
            "--family",
            "smoke.opt",
            "--kind",
            "OptNote",
            "--home",
            &home_id,
            "--json",
            &to,
        ],
    );
    let target_opt = t_opt["id"].as_str().unwrap().to_string();
    let so = w.write("so.json", br#"{"title": "Opt-Row"}"#);
    let s_opt = w.run_ok(
        "agent:op",
        &[
            "create",
            "--family",
            "smoke.opt",
            "--kind",
            "OptNote",
            "--home",
            &home_id,
            "--json",
            &so,
        ],
    );
    let row_opt = s_opt["id"].as_str().unwrap().to_string();
    w.run_ok(
        "agent:op",
        &[
            "link",
            "--source",
            &row_opt,
            "--predicate",
            "relates_to",
            "--target",
            &target_opt,
        ],
    );

    // Fixed-gate surface read needs the explicit linked target: hits served.
    let fk = w.write("fk.json", format!(r#"{{"linked_to": {{"predicate": "relates_to", "id": "{target_keep}", "direction": "out"}}}}"#).as_bytes());
    let seen = w.run_ok(
        "agent:op",
        &[
            "package-surface-read",
            "--scope",
            &home_id,
            "--namespace",
            "smoke",
            "--name",
            "keep",
            "--read-token",
            "linked_record:view",
            "--family",
            "smoke.keep",
            "--kind",
            "KeepNote",
            "--json",
            &fk,
        ],
    );
    assert_eq!(
        seen["List"]["title"].as_str().unwrap(),
        "keep.view",
        "{seen}"
    );
    let keep_rows = seen["List"]["rows"].as_array().unwrap();
    assert!(
        keep_rows
            .iter()
            .any(|r| r["id"].as_str() == Some(row_keep.as_str())),
        "{seen}"
    );

    // The removable surface serves its exact row before the change.
    let fo = w.write("fo.json", format!(r#"{{"linked_to": {{"predicate": "relates_to", "id": "{target_opt}", "direction": "out"}}}}"#).as_bytes());
    let opt_seen = w.run_ok(
        "agent:op",
        &[
            "package-surface-read",
            "--scope",
            &home_id,
            "--namespace",
            "smoke",
            "--name",
            "opt",
            "--read-token",
            "linked_record:view",
            "--family",
            "smoke.opt",
            "--kind",
            "OptNote",
            "--json",
            &fo,
        ],
    );
    assert_eq!(
        opt_seen["List"]["title"].as_str().unwrap(),
        "opt.view",
        "{opt_seen}"
    );
    let opt_rows = opt_seen["List"]["rows"].as_array().unwrap();
    assert!(
        opt_rows
            .iter()
            .any(|r| r["id"].as_str() == Some(row_opt.as_str())),
        "{opt_seen}"
    );

    // Disable the optional package: kept surface still reads, opt falls back.
    // Admin keeps Manage on the home via owner semantics across the op grant
    // above; runtime will confirm the disable authorisation on execution.
    w.run_ok(
        "acct:admin",
        &["package-disable", "--json", &opt_f, "--scope", &home_id],
    );
    let again = w.run_ok(
        "agent:op",
        &[
            "package-surface-read",
            "--scope",
            &home_id,
            "--namespace",
            "smoke",
            "--name",
            "keep",
            "--read-token",
            "linked_record:view",
            "--family",
            "smoke.keep",
            "--kind",
            "KeepNote",
            "--json",
            &fk,
        ],
    );
    assert_eq!(
        again["List"]["title"].as_str().unwrap(),
        "keep.view",
        "{again}"
    );
    let again_rows = again["List"]["rows"].as_array().unwrap();
    assert!(
        again_rows
            .iter()
            .any(|r| r["id"].as_str() == Some(row_keep.as_str())),
        "{again}"
    );
    let gone = w.run_ok(
        "agent:op",
        &[
            "package-surface-read",
            "--scope",
            &home_id,
            "--namespace",
            "smoke",
            "--name",
            "opt",
            "--read-token",
            "linked_record:view",
            "--family",
            "smoke.opt",
            "--kind",
            "OptNote",
            "--json",
            &fo,
        ],
    );
    assert_eq!(
        gone["Notice"]["notice"].as_str().unwrap(),
        "opt.unavailable",
        "{gone}"
    );
    // The old optional row stays directly readable after its package disables.
    let back = w.run_ok("agent:op", &["read", "--id", &row_opt]);
    assert_eq!(back["id"].as_str().unwrap(), row_opt, "{back}");
    assert_eq!(
        back["fields"]["title"],
        serde_json::json!("Opt-Row"),
        "{back}"
    );
}

#[test]
fn v2_contract_smoke_consumer_blocks_disable_until_retired() {
    let w = World::fresh();
    let out = std::process::Command::new(&w.bin)
        .arg("--db")
        .arg(&w.db)
        .arg("init")
        .arg("--label")
        .arg("Admin")
        .arg("--binding")
        .arg("acct:admin")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init exited {}; stdout: {}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let admin: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let op = w.run_ok(
        "acct:admin",
        &[
            "principal",
            "--kind",
            "agent",
            "--label",
            "Op",
            "--binding",
            "agent:op",
        ],
    );
    let op_id = op["principal_id"].as_str().unwrap().to_string();
    let grants = w.write(
        "admin.json",
        format!(
            r#"{{"{}": "manage"}}"#,
            admin["principal_id"].as_str().unwrap()
        )
        .as_bytes(),
    );
    let h = w.run_ok(
        "acct:admin",
        &["home", "--parent", "kernel:root", "--json", &grants],
    );
    let home_id = h["home_id"].as_str().unwrap().to_string();
    let op_grant = w.write("op.json", format!(r#"{{"{op_id}": "manage"}}"#).as_bytes());
    w.run_ok(
        "acct:admin",
        &["grant", "--home", &home_id, "--json", &op_grant],
    );

    // Guarded package plus its definition pin digest for the requirement.
    let guarded_m = pkg_manifest(
        "guarded",
        "smoke.guarded",
        "guardnote",
        "GuardedNote",
        "guard.view",
        "guard.unavailable",
    );
    let guarded_f = w.write("guarded-pkg.json", &serde_json::to_vec(&guarded_m).unwrap());
    let ack = r#"["linked_record:view"]"#;
    w.run_ok("acct:admin", &["package-install", "--json", &guarded_f]);
    w.run_ok(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &guarded_f,
            "--scope",
            &home_id,
            "--ack-reads",
            ack,
        ],
    );
    let artifact = pkg_artifact("smoke.guarded", "guardnote", "GuardedNote");
    let def_digest = {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(artifact.as_bytes()))
    };

    // External saved-query requirement pinned to the live definition pin.
    let reg = w.run_ok(
        "acct:admin",
        &[
            "consumer-register",
            "--scope",
            &home_id,
            "--consumer-kind",
            "saved-query",
            "--namespace",
            "smoke",
            "--name",
            "watcher",
            "--family",
            "smoke.guarded",
            "--version",
            "1",
            "--digest",
            &def_digest,
        ],
    );
    assert_eq!(reg["active"], serde_json::json!(true), "{reg}");
    let seq = reg["event_seq"].as_i64().unwrap().to_string();

    // Preview names the breakage before anything mutates.
    let preview = w.run_ok(
        "acct:admin",
        &[
            "package-preview-disable",
            "--json",
            &guarded_f,
            "--scope",
            &home_id,
        ],
    );
    assert_eq!(preview["broken"].as_array().unwrap().len(), 1, "{preview}");

    // The guarded disable refuses with no state change: requirement intact.
    let (ok, err) = w.run(
        "acct:admin",
        &["package-disable", "--json", &guarded_f, "--scope", &home_id],
    );
    assert!(!ok, "disable must refuse while a consumer requires the pin");
    assert!(err.get("error").is_some(), "{err}");
    let listed = w.run_ok("agent:op", &["consumer-list", "--scope", &home_id]);
    let kept = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["consumer_name"] == "watcher")
        .unwrap();
    assert_eq!(kept["active"], serde_json::json!(true), "{listed}");
    assert_eq!(
        kept["event_seq"].as_i64().unwrap().to_string(),
        seq,
        "{listed}"
    );

    // Retire with the exact event-seq precondition, then the preview is clean.
    let retired = w.run_ok(
        "acct:admin",
        &[
            "consumer-retire",
            "--scope",
            &home_id,
            "--consumer-kind",
            "saved-query",
            "--namespace",
            "smoke",
            "--name",
            "watcher",
            "--family",
            "smoke.guarded",
            "--expected-seq",
            &seq,
        ],
    );
    assert_eq!(retired["active"], serde_json::json!(false), "{retired}");
    let clean = w.run_ok(
        "acct:admin",
        &[
            "package-preview-disable",
            "--json",
            &guarded_f,
            "--scope",
            &home_id,
        ],
    );
    assert!(clean["broken"].as_array().unwrap().is_empty(), "{clean}");

    // A populated row predates the disable so retention is observable.
    let gr = w.write("gr.json", br#"{"title": "Guarded-Row"}"#);
    let g_row = w.run_ok(
        "agent:op",
        &[
            "create",
            "--family",
            "smoke.guarded",
            "--kind",
            "GuardedNote",
            "--home",
            &home_id,
            "--json",
            &gr,
        ],
    );
    let guarded_row = g_row["id"].as_str().unwrap().to_string();

    // Disable now works; the surface falls back and the old row still reads.
    w.run_ok(
        "acct:admin",
        &["package-disable", "--json", &guarded_f, "--scope", &home_id],
    );
    let tg = w.write("tg.json", br#"{"title": "Guarded-Target"}"#);
    let (_, view) = w.run(
        "agent:op",
        &[
            "package-surface-read",
            "--scope",
            &home_id,
            "--namespace",
            "smoke",
            "--name",
            "guarded",
            "--read-token",
            "linked_record:view",
            "--family",
            "smoke.guarded",
            "--kind",
            "GuardedNote",
            "--json",
            &tg,
        ],
    );
    assert_eq!(
        view["Notice"]["notice"].as_str().unwrap(),
        "guard.unavailable",
        "{view}"
    );
    let back = w.run_ok("agent:op", &["read", "--id", &guarded_row]);
    assert_eq!(back["id"].as_str().unwrap(), guarded_row, "{back}");
    assert_eq!(
        back["fields"]["title"],
        serde_json::json!("Guarded-Row"),
        "{back}"
    );
}

/// Initialize a blank v2 database and a child home the genesis admin can use.
fn init_admin_world(w: &World) -> (String, String) {
    let out = std::process::Command::new(&w.bin)
        .arg("--db")
        .arg(&w.db)
        .arg("init")
        .arg("--label")
        .arg("Admin")
        .arg("--binding")
        .arg("acct:admin")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "init exited {}; stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr),
    );
    let admin: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let admin_id = admin["principal_id"].as_str().unwrap().to_string();
    let grants = w.write(
        "admin.json",
        format!(r#"{{"{admin_id}": "manage"}}"#).as_bytes(),
    );
    let h = w.run_ok(
        "acct:admin",
        &["home", "--parent", "kernel:root", "--json", &grants],
    );
    let home = h["home_id"].as_str().unwrap().to_string();
    (admin_id, home)
}

/// Write a manifest's canonical value to a file the harness can read.
fn write_package(
    w: &World,
    manifest: &native_ce::package_manifest::PackageManifest,
    name: &str,
) -> String {
    let value = manifest
        .canonical_value()
        .unwrap_or_else(|e| panic!("manifest {name}: {e}"));
    w.write(
        &format!("{name}-pkg.json"),
        &serde_json::to_vec(&value).unwrap(),
    )
}

/// Upgrade fixtures own their namespace; only compiled revisions may publish native.*.
fn fixture_standard_package(
    mut manifest: native_ce::package_manifest::PackageManifest,
) -> native_ce::package_manifest::PackageManifest {
    manifest.namespace = "fixture.standard".to_string();
    for entry in &mut manifest.definitions {
        entry.family = entry.family.replace("native.standard", "fixture.standard");
        entry.artifact_bytes = entry
            .artifact_bytes
            .replace("native.standard", "fixture.standard");
        entry.digest = native_ce::meta::definition_artifact::digest_artifact_bytes(
            entry.artifact_bytes.as_bytes(),
        );
    }
    manifest
}

#[tokio::test]
async fn v2_contract_smoke_native_standard_packages() {
    let w = World::fresh();
    init_admin_world(&w);
    let blank = w.run_ok("acct:admin", &["describe"]);
    assert_eq!(
        blank["namespace_policy"]["publication"],
        "exact_compiled_first_party_package"
    );
    for manifest in native_ce::v2_standard::standard_packages() {
        let pkg = write_package(&w, &manifest, &manifest.name);
        w.run_ok("acct:admin", &["package-install", "--json", &pkg]);
        w.run_ok(
            "acct:admin",
            &[
                "package-adopt",
                "--json",
                &pkg,
                "--scope",
                "kernel:root",
                "--ack-reads",
                "[]",
            ],
        );
        let described = w.run_ok("acct:admin", &["describe"]);
        assert!(described["definitions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["family"] == manifest.definitions[0].family));
    }
    let own_package = write_package(&w, &document_v3_package(), "own-namespace");
    // The upgrade fixture owns fixture.standard. Re-label it as native.* to
    // confirm the generic CLI returns the admission reason.
    let mut reserved = document_v3_package();
    reserved.namespace = "native.standard".to_string();
    let reserved = write_package(&w, &reserved, "reserved");
    let (ok, err) = w.run("acct:admin", &["package-install", "--json", &reserved]);
    assert!(!ok, "{err}");
    assert!(err.to_string().contains("reserved namespace"), "{err}");
    w.run_ok("acct:admin", &["package-install", "--json", &own_package]);
}

/// A definitions-only `fixture.standard/document@3` whose definition adds an
/// optional `summary` field. Used by the replace step. (Version 3 because the
/// real loosened note ships as definition/package version 2.)
fn document_v3_package() -> native_ce::package_manifest::PackageManifest {
    const BYTES: &str = r#"{"family":"fixture.standard.document","version":3,"interpreter":"native.defn/3","primary_type":"Document","kinds":[{"token":"note","description":"An ordinary authored prose or capture document. Each note is distinct; matching titles or content do not make two notes the same.","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"title","type":"text","required":false,"description":"Short human title. May be absent: v1 notes are often untitled and no title is invented."},{"name":"body","type":"text","required":false,"description":"The prose, as Markdown."},{"name":"summary","type":"text","required":false,"description":"An optional one-line summary."}],"links":[{"predicate":"relates_to","target":{"primary_type":"Document","kind":"note"},"direction":"either","cardinality":"many"}]}]}"#;
    let digest = native_ce::meta::definition_artifact::digest_artifact_bytes(BYTES.as_bytes());
    native_ce::package_manifest::PackageManifest {
        operations: vec![],
        namespace: "fixture.standard".to_string(),
        name: "document".to_string(),
        version: 3,
        definitions: vec![native_ce::package_manifest::DefinitionEntry {
            family: "fixture.standard.document".to_string(),
            version: 3,
            artifact_bytes: BYTES.to_string(),
            digest,
        }],
        behaviour: None,
        surface: None,
        declared_reads: Vec::new(),
    }
}

fn describe_entry(value: &serde_json::Value, family: &str, kind: &str) -> serde_json::Value {
    value["definitions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["family"] == family && d["kind"] == kind)
        .cloned()
        .unwrap_or_else(|| panic!("no {family}/{kind} in describe output {value}"))
}

#[tokio::test]
async fn v2_contract_smoke_fixture_standard_upgrades() {
    let w = World::fresh();
    let (admin, home) = init_admin_world(&w);
    let document_family = "fixture.standard.document";
    let outcome_family = "fixture.standard.outcome";

    // ---- Step 1: blank. describe lists nothing; create refuses. ----
    let blank = w.run_ok("acct:admin", &["describe"]);
    assert_eq!(blank["definitions"].as_array().unwrap().len(), 0, "{blank}");
    let note = w.write("note.json", br#"{"title": "Same title"}"#);
    let (ok, err) = w.run(
        "acct:admin",
        &[
            "create",
            "--family",
            document_family,
            "--kind",
            "note",
            "--home",
            &home,
            "--json",
            &note,
        ],
    );
    assert!(!ok, "create must refuse with nothing adopted: {err}");
    assert!(err.get("error").is_some(), "{err}");

    // ---- Step 2: install, then adopt (install is not adoption). ----
    let doc_pkg = write_package(
        &w,
        &fixture_standard_package(native_ce::v2_standard::document_package()),
        "document",
    );
    let out_pkg = write_package(
        &w,
        &fixture_standard_package(native_ce::v2_standard::outcome_package()),
        "outcome",
    );
    for pkg in [&doc_pkg, &out_pkg] {
        w.run_ok("acct:admin", &["package-install", "--json", pkg]);
    }
    let installed = w.run_ok("acct:admin", &["describe"]);
    assert_eq!(
        installed["definitions"].as_array().unwrap().len(),
        0,
        "installing is not adopting: {installed}"
    );
    for pkg in [&doc_pkg, &out_pkg] {
        w.run_ok(
            "acct:admin",
            &[
                "package-adopt",
                "--json",
                pkg,
                "--scope",
                "kernel:root",
                "--ack-reads",
                "[]",
            ],
        );
    }
    let adopted = w.run_ok("acct:admin", &["describe"]);
    let doc_entry = describe_entry(&adopted, document_family, "note");
    assert_eq!(
        doc_entry["package"]["namespace"], "fixture.standard",
        "{adopted}"
    );
    assert_eq!(doc_entry["package"]["name"], "document", "{adopted}");
    assert_eq!(doc_entry["adoption"]["state"], "adopted", "{adopted}");
    assert_eq!(doc_entry["identity"]["mode"], "record", "{adopted}");
    let out_entry = describe_entry(&adopted, outcome_family, "impact");
    assert_eq!(out_entry["package"]["name"], "outcome", "{adopted}");
    assert_eq!(out_entry["adoption"]["state"], "adopted", "{adopted}");

    // ---- Step 3: use. Two notes share a title; link and linked_to query. ----
    let n1 = w.run_ok(
        "acct:admin",
        &[
            "create",
            "--family",
            document_family,
            "--kind",
            "note",
            "--home",
            &home,
            "--json",
            &note,
        ],
    );
    let n1_id = n1["id"].as_str().unwrap().to_string();
    let n2 = w.run_ok(
        "acct:admin",
        &[
            "create",
            "--family",
            document_family,
            "--kind",
            "note",
            "--home",
            &home,
            "--json",
            &note,
        ],
    );
    let n2_id = n2["id"].as_str().unwrap().to_string();
    assert_ne!(
        n1_id, n2_id,
        "same title must not collide under record identity"
    );
    w.run_ok(
        "acct:admin",
        &[
            "link",
            "--source",
            &n1_id,
            "--predicate",
            "relates_to",
            "--target",
            &n2_id,
        ],
    );
    let linked = w.write(
        "linked.json",
        format!(r#"{{"linked_to": {{"predicate": "relates_to", "id": "{n2_id}", "direction": "either"}}}}"#).as_bytes(),
    );
    let found = w.run_ok(
        "acct:admin",
        &[
            "query",
            "--family",
            document_family,
            "--kind",
            "note",
            "--json",
            &linked,
        ],
    );
    assert!(
        found["hits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["id"].as_str() == Some(n1_id.as_str())),
        "{found}"
    );

    // An impact with a magnitude and a window; query it by method.
    let impact = w.write(
        "impact.json",
        br#"{"claim":"Widget throughput rose.","method":"derived","effective_at":"2026-09-01","magnitude_value":3.0,"magnitude_unit":"kg","magnitude_per":"day","window_start":"2026-09-01","window_end":"2026-09-30"}"#,
    );
    let impact_created = w.run_ok(
        "acct:admin",
        &[
            "create",
            "--family",
            outcome_family,
            "--kind",
            "impact",
            "--home",
            &home,
            "--json",
            &impact,
        ],
    );
    let impact_id = impact_created["id"].as_str().unwrap().to_string();
    let by_method = w.write("by-method.json", br#"{"equals": {"method": "derived"}}"#);
    let derived = w.run_ok(
        "acct:admin",
        &[
            "query",
            "--family",
            outcome_family,
            "--kind",
            "impact",
            "--json",
            &by_method,
        ],
    );
    assert!(
        derived["hits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["id"].as_str() == Some(impact_id.as_str())),
        "{derived}"
    );

    // Revise the claim; history shows create then revise.
    let patch = w.write(
        "patch.json",
        br#"{"claim":"Widget throughput rose sharply."}"#,
    );
    w.run_ok(
        "acct:admin",
        &["revise", "--id", &impact_id, "--json", &patch],
    );
    let history = w.run_ok("acct:admin", &["history", "--id", &impact_id]);
    let types: Vec<&str> = history
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["event_type"].as_str().unwrap())
        .collect();
    assert_eq!(
        types,
        vec!["kernel.record_created.v1", "kernel.record_revised.v1"],
        "{history:?}"
    );

    // Refusals: bad method, missing/blank claim, unknown field.
    for (payload, needle, label) in [
        (
            br#"{"claim":"x","method":"guessed","effective_at":"2026-09-01"}"#.to_vec(),
            "not an allowed choice",
            "bad method",
        ),
        (
            br#"{"method":"derived","effective_at":"2026-09-01"}"#.to_vec(),
            "missing required field 'claim'",
            "missing claim",
        ),
        (
            br#"{"claim":"   ","method":"derived","effective_at":"2026-09-01"}"#.to_vec(),
            "required field 'claim' must not be blank",
            "blank claim",
        ),
        (
            br#"{"claim":"x","method":"derived","effective_at":"2026-09-01","bogus":1}"#.to_vec(),
            "unknown field 'bogus'",
            "unknown field",
        ),
    ] {
        let file = w.write("refuse.json", &payload);
        let (ok, err) = w.run(
            "acct:admin",
            &[
                "create",
                "--family",
                outcome_family,
                "--kind",
                "impact",
                "--home",
                &home,
                "--json",
                &file,
            ],
        );
        assert!(!ok, "{label} must refuse: {err}");
        let message = err["error"].as_str().unwrap_or_default();
        assert!(message.contains(needle), "{label}: {message}");
    }

    // ---- Step 4: disable Outcome; old impacts stay readable; notes live on. ----
    w.run_ok(
        "acct:admin",
        &[
            "package-disable",
            "--json",
            &out_pkg,
            "--scope",
            "kernel:root",
        ],
    );
    let (ok, err) = w.run(
        "acct:admin",
        &[
            "create",
            "--family",
            outcome_family,
            "--kind",
            "impact",
            "--home",
            &home,
            "--json",
            &impact,
        ],
    );
    assert!(!ok, "create must refuse while Outcome is disabled: {err}");
    let old_impact = w.run_ok("acct:admin", &["read", "--id", &impact_id]);
    assert_eq!(old_impact["pin"]["family"], outcome_family, "{old_impact}");
    assert_eq!(old_impact["pin"]["version"], 1, "{old_impact}");
    assert_eq!(old_impact["interpreter"], "native.defn/3", "{old_impact}");
    assert_eq!(
        old_impact["fields"]["claim"],
        serde_json::json!("Widget throughput rose sharply."),
        "{old_impact}"
    );
    // A note still creates fine while Outcome is disabled.
    w.run_ok(
        "acct:admin",
        &[
            "create",
            "--family",
            document_family,
            "--kind",
            "note",
            "--home",
            &home,
            "--json",
            &note,
        ],
    );
    let after_disable = w.run_ok("acct:admin", &["describe"]);
    let disabled = describe_entry(&after_disable, outcome_family, "impact");
    assert_eq!(disabled["adoption"]["state"], "disabled", "{after_disable}");
    assert!(
        disabled["package"].is_null(),
        "a disabled entry takes no package provenance: {after_disable}"
    );

    // ---- Step 5: replace Document with @3 (adds optional summary). ----
    // The K6a retained-data guard
    // (`dependency_transition_tests::visible_outside_rows_block_replacement_with_retained_data`)
    // refuses a *direct* package replacement while records still pin the old
    // revision, because mapping data across revisions is out of scope. The
    // supported replacement path is disable-then-adopt, which leaves old
    // records on their original pin (v2 here).
    let doc_v3 = document_v3_package();
    let doc_v3_file = write_package(&w, &doc_v3, "document-v3");
    w.run_ok("acct:admin", &["package-install", "--json", &doc_v3_file]);

    // A saved-query consumer pinned to v2 refuses the v3 adoption with no
    // state change.
    let v2_digest = fixture_standard_package(native_ce::v2_standard::document_package())
        .definitions[0]
        .digest
        .clone();
    let registered = w.run_ok(
        "acct:admin",
        &[
            "consumer-register",
            "--scope",
            &home,
            "--consumer-kind",
            "saved-query",
            "--namespace",
            "fixture.standard",
            "--name",
            "document-watcher",
            "--family",
            document_family,
            "--version",
            "2",
            "--digest",
            &v2_digest,
        ],
    );
    let consumer_seq = registered["event_seq"].as_i64().unwrap().to_string();
    let preview = w.run_ok(
        "acct:admin",
        &[
            "package-preview-adopt",
            "--json",
            &doc_v3_file,
            "--scope",
            "kernel:root",
        ],
    );
    assert!(
        preview["broken"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["consumer_kind"] == "saved-query"),
        "preview must name the consumer impact: {preview}"
    );
    let db = native_ce::db::open_database(&w.db).await.unwrap();
    let before = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    db.close().await;
    let (ok, err) = w.run(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &doc_v3_file,
            "--scope",
            "kernel:root",
            "--ack-reads",
            "[]",
        ],
    );
    assert!(
        !ok,
        "v3 adoption must refuse while the v2 consumer lives: {err}"
    );
    let db = native_ce::db::open_database(&w.db).await.unwrap();
    let after = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    db.close().await;
    assert_eq!(before, after, "a refused adoption appends nothing");

    // Retire the consumer. A direct replacement is still refused, now by the
    // retained-data guard: the old notes pin Document v2.
    w.run_ok(
        "acct:admin",
        &[
            "consumer-retire",
            "--scope",
            &home,
            "--consumer-kind",
            "saved-query",
            "--namespace",
            "fixture.standard",
            "--name",
            "document-watcher",
            "--family",
            document_family,
            "--expected-seq",
            &consumer_seq,
        ],
    );
    let still = w.run_ok(
        "acct:admin",
        &[
            "package-preview-adopt",
            "--json",
            &doc_v3_file,
            "--scope",
            "kernel:root",
        ],
    );
    assert!(
        still["broken"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["consumer_kind"] == "retained-data"),
        "the retained-data guard names the stranded v2 pin: {still}"
    );
    let db = native_ce::db::open_database(&w.db).await.unwrap();
    let before = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    db.close().await;
    let (ok, err) = w.run(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &doc_v3_file,
            "--scope",
            "kernel:root",
            "--ack-reads",
            "[]",
        ],
    );
    assert!(
        !ok,
        "a direct replacement of a pinned revision refuses: {err}"
    );
    let db = native_ce::db::open_database(&w.db).await.unwrap();
    let after = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    db.close().await;
    assert_eq!(before, after, "a refused replacement appends nothing");

    // Disable-then-adopt is the replacement path that leaves old records on
    // their original pin. Old notes keep their v2 pin and read under v2; a
    // new note pins v3.
    w.run_ok(
        "acct:admin",
        &[
            "package-disable",
            "--json",
            &doc_pkg,
            "--scope",
            "kernel:root",
        ],
    );
    w.run_ok(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &doc_v3_file,
            "--scope",
            "kernel:root",
            "--ack-reads",
            "[]",
        ],
    );
    let old_note = w.run_ok("acct:admin", &["read", "--id", &n1_id]);
    assert_eq!(old_note["pin"]["version"], 2, "{old_note}");
    let new_note = w.run_ok(
        "acct:admin",
        &[
            "create",
            "--family",
            document_family,
            "--kind",
            "note",
            "--home",
            &home,
            "--json",
            &note,
        ],
    );
    let new_note_id = new_note["id"].as_str().unwrap().to_string();
    let new_read = w.run_ok("acct:admin", &["read", "--id", &new_note_id]);
    assert_eq!(new_read["pin"]["version"], 3, "{new_read}");
    let after_replace = w.run_ok("acct:admin", &["describe"]);
    let doc_v3_entry = describe_entry(&after_replace, document_family, "note");
    assert_eq!(doc_v3_entry["version"], 3, "{after_replace}");

    // ---- Step 6: replay reproduces every projection; history carries the pin. ----
    let db = native_ce::db::open_database(&w.db).await.unwrap();
    let before = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    native_ce::kernel::replay_all_projections(&db)
        .await
        .unwrap();
    let after = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    let replayed_impact = native_ce::kernel::read_record_as(&db, &admin, &impact_id)
        .await
        .unwrap()
        .expect("impact visible");
    db.close().await;
    assert_eq!(before, after, "replay must reproduce every projection");
    // The record keeps the pin and interpreter `native.defn/3`; the harness
    // history read confirms the create and revise events both survive replay.
    assert_eq!(replayed_impact.pin.as_ref().unwrap().family, outcome_family);
    assert_eq!(replayed_impact.pin.as_ref().unwrap().version, 1);
    assert_eq!(
        replayed_impact.interpreter.as_deref(),
        Some("native.defn/3")
    );
    let final_history = w.run_ok("acct:admin", &["history", "--id", &impact_id]);
    assert!(
        final_history.as_array().unwrap().len() >= 2,
        "history keeps the create and revise events: {final_history}"
    );
}

/// D7 (task 9d70658): the loosened `native.standard/document@2` accepts an
/// untitled note, while a record pinned to the strict v1 revision keeps its
/// pin and replays exactly after the disable-then-adopt replacement.
#[tokio::test]
async fn v2_contract_smoke_loosened_note_accepts_untitled_and_keeps_v1_pin() {
    /// The shipped v1 definition bytes (title required), verbatim: the
    /// digest assertion below pins the exact bytes.
    const V1_BYTES: &str = "{\n  \"family\": \"native.standard.document\",\n  \"version\": 1,\n  \"interpreter\": \"native.defn/3\",\n  \"primary_type\": \"Document\",\n  \"kinds\": [\n    {\n      \"token\": \"note\",\n      \"description\": \"An ordinary authored prose or capture document. Each note is distinct; matching titles or content do not make two notes the same.\",\n      \"maturity\": \"current\",\n      \"identity\": { \"mode\": \"record\" },\n      \"fields\": [\n        { \"name\": \"title\", \"type\": \"text\", \"required\": true, \"description\": \"Short human title.\" },\n        { \"name\": \"body\", \"type\": \"text\", \"required\": false, \"description\": \"The prose, as Markdown.\" }\n      ],\n      \"links\": [\n        { \"predicate\": \"relates_to\", \"target\": { \"primary_type\": \"Document\", \"kind\": \"note\" }, \"direction\": \"either\", \"cardinality\": \"many\" }\n      ]\n    }\n  ]\n}\n";
    assert_eq!(
        native_ce::meta::definition_artifact::digest_artifact_bytes(V1_BYTES.as_bytes()),
        "6f0dab56958edc57378098a3f5bcde76d32f2d34f0e58d590cb534fecb91da61",
        "v1 fixture must be the shipped bytes",
    );
    fn v1_package() -> native_ce::package_manifest::PackageManifest {
        native_ce::package_manifest::PackageManifest {
            operations: vec![],
            namespace: "native.standard".to_string(),
            name: "document".to_string(),
            version: 1,
            definitions: vec![native_ce::package_manifest::DefinitionEntry {
                family: "native.standard.document".to_string(),
                version: 1,
                artifact_bytes: V1_BYTES.to_string(),
                digest: native_ce::meta::definition_artifact::digest_artifact_bytes(
                    V1_BYTES.as_bytes(),
                ),
            }],
            behaviour: None,
            surface: None,
            declared_reads: Vec::new(),
        }
    }

    let w = World::fresh();
    let (admin, home) = init_admin_world(&w);
    let document_family = "native.standard.document";

    // Seed the shipped @1 bytes and a historical package event. The shared
    // registry/fold validates history without re-running current admission;
    // this setup adds no bypass to the kernel/package installation wrappers.
    let legacy = v1_package();
    let db = native_ce::db::open_database(&w.db).await.unwrap();
    native_ce::definition_registry::install_definition_artifact(
        &db,
        document_family,
        1,
        V1_BYTES.as_bytes(),
    )
    .await
    .unwrap();
    let payload = native_ce::meta::events::PackageArtifactInstalledV1Payload {
        namespace: legacy.namespace.clone(),
        name: legacy.name.clone(),
        version: legacy.version,
        digest: legacy.package_digest().unwrap(),
        manifest_bytes: String::from_utf8(
            serde_jcs::to_vec(&legacy.canonical_value().unwrap()).unwrap(),
        )
        .unwrap(),
    };
    let subject = format!(
        "package:{}/{}@{}#{}",
        payload.namespace, payload.name, payload.version, payload.digest
    );
    let mut event = native_ce::meta::events::MetaEventRow {
        seq: -1,
        id: uuid::Uuid::new_v4().to_string(),
        subject_id: subject,
        event_type: "package_artifact.installed.v1".to_string(),
        payload: Some(serde_json::to_string(&payload).unwrap()),
        actor: Some(admin.clone()),
        created_at: "2026-10-01T00:00:00.000Z".to_string(),
    };
    db.close().await;
    use sqlx::{Connection, SqliteConnection};
    let mut connection = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&w.db)
            .foreign_keys(true),
    )
    .await
    .unwrap();
    let mut tx = connection.begin().await.unwrap();
    // Legacy rows may have no act grouping; their event identity is retained.
    event.seq = sqlx::query_scalar(
        "INSERT INTO meta_events (id, subject_id, type, payload, actor, created_at)
         VALUES (?, ?, ?, ?, ?, ?) RETURNING seq",
    )
    .bind(&event.id)
    .bind(&event.subject_id)
    .bind(&event.event_type)
    .bind(&event.payload)
    .bind(&event.actor)
    .bind(&event.created_at)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    native_ce::projector::meta::project_meta(&mut tx, &event)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    connection.close().await.unwrap();

    // Adopt the seeded strict @1 package plus the installed current outcome.
    let v1_pkg = write_package(&w, &legacy, "document-v1");
    let out_pkg = write_package(&w, &native_ce::v2_standard::outcome_package(), "outcome");
    w.run_ok("acct:admin", &["package-install", "--json", &out_pkg]);
    let (ok, err) = w.run("acct:admin", &["package-install", "--json", &v1_pkg]);
    assert!(
        !ok,
        "an older compiled revision cannot be reinstalled: {err}"
    );
    assert!(err.to_string().contains("reserved namespace"), "{err}");
    for pkg in [&v1_pkg, &out_pkg] {
        w.run_ok(
            "acct:admin",
            &[
                "package-adopt",
                "--json",
                pkg,
                "--scope",
                "kernel:root",
                "--ack-reads",
                "[]",
            ],
        );
    }

    // An untitled note refuses on v1.
    let untitled = w.write("untitled.json", br#"{"body": "A note with no title."}"#);
    let create_args = |file: &str| {
        vec![
            "create".to_string(),
            "--family".to_string(),
            document_family.to_string(),
            "--kind".to_string(),
            "note".to_string(),
            "--home".to_string(),
            home.clone(),
            "--json".to_string(),
            file.to_string(),
        ]
    };
    let owned: Vec<String> = create_args(&untitled);
    let borrowed: Vec<&str> = owned.iter().map(String::as_str).collect();
    let (ok, err) = w.run("acct:admin", &borrowed);
    assert!(!ok, "v1 must refuse a missing title: {err}");
    assert!(
        err["error"]
            .as_str()
            .unwrap_or_default()
            .contains("missing required field 'title'"),
        "{err}"
    );

    // A titled note pins v1.
    let titled = w.write(
        "titled.json",
        br#"{"title": "Old note", "body": "Pinned to v1."}"#,
    );
    let owned = create_args(&titled);
    let borrowed: Vec<&str> = owned.iter().map(String::as_str).collect();
    let created = w.run_ok("acct:admin", &borrowed);
    let old_id = created["id"].as_str().unwrap().to_string();

    // Replace via disable-then-adopt with the loosened @2.
    let doc_pkg = write_package(&w, &native_ce::v2_standard::document_package(), "document");
    w.run_ok("acct:admin", &["package-install", "--json", &doc_pkg]);
    w.run_ok(
        "acct:admin",
        &[
            "package-disable",
            "--json",
            &v1_pkg,
            "--scope",
            "kernel:root",
        ],
    );
    w.run_ok(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &doc_pkg,
            "--scope",
            "kernel:root",
            "--ack-reads",
            "[]",
        ],
    );

    // The old note keeps its v1 pin and fields.
    let old = w.run_ok("acct:admin", &["read", "--id", &old_id]);
    assert_eq!(old["pin"]["family"], document_family, "{old}");
    assert_eq!(old["pin"]["version"], 1, "{old}");
    assert_eq!(
        old["fields"]["title"],
        serde_json::json!("Old note"),
        "{old}"
    );

    // Revising the @1-pinned note still validates under @1 even after @2 is
    // adopted: clearing or removing the title refuses, while a body-only
    // revise succeeds and keeps the v1 pin.
    for (patch, needle) in [
        (
            br#"{"title": null}"#.to_vec(),
            "missing required field 'title'",
        ),
        (
            br#"{"title": "   "}"#.to_vec(),
            "required field 'title' must not be blank",
        ),
    ] {
        let file = w.write("clear-title.json", &patch);
        let (ok, err) = w.run("acct:admin", &["revise", "--id", &old_id, "--json", &file]);
        assert!(!ok, "clearing the @1 title must refuse: {err}");
        assert!(
            err["error"].as_str().unwrap_or_default().contains(needle),
            "{err}"
        );
    }
    let body_patch = w.write(
        "body-patch.json",
        br#"{"body": "Revised under @2, still pinned @1."}"#,
    );
    w.run_ok(
        "acct:admin",
        &["revise", "--id", &old_id, "--json", &body_patch],
    );
    let revised = w.run_ok("acct:admin", &["read", "--id", &old_id]);
    assert_eq!(revised["pin"]["version"], 1, "{revised}");
    assert_eq!(
        revised["fields"]["title"],
        serde_json::json!("Old note"),
        "{revised}"
    );
    assert_eq!(
        revised["fields"]["body"],
        serde_json::json!("Revised under @2, still pinned @1."),
        "{revised}"
    );

    // The untitled note is now accepted and pins v2 with no title.
    let owned = create_args(&untitled);
    let borrowed: Vec<&str> = owned.iter().map(String::as_str).collect();
    let new = w.run_ok("acct:admin", &borrowed);
    let new_id = new["id"].as_str().unwrap().to_string();
    let read_new = w.run_ok("acct:admin", &["read", "--id", &new_id]);
    assert_eq!(read_new["pin"]["version"], 2, "{read_new}");
    assert!(
        read_new["fields"].get("title").is_none_or(|v| v.is_null()),
        "no title is invented: {read_new}"
    );

    // Pinned edge-case behaviour on @2: an explicit null stores as absent,
    // while an empty string stores as given (non-blank is only enforced for
    // required fields, and title is optional now). Importers must therefore
    // omit empty v1 names rather than writing "".
    let null_title = w.write(
        "null-title.json",
        br#"{"title": null, "body": "Null title."}"#,
    );
    let owned = create_args(&null_title);
    let borrowed: Vec<&str> = owned.iter().map(String::as_str).collect();
    let null_created = w.run_ok("acct:admin", &borrowed);
    let null_read = w.run_ok(
        "acct:admin",
        &["read", "--id", null_created["id"].as_str().unwrap()],
    );
    assert!(
        null_read["fields"].get("title").is_none_or(|v| v.is_null()),
        "{null_read}"
    );
    let empty_title = w.write(
        "empty-title.json",
        br#"{"title": "", "body": "Empty title."}"#,
    );
    let owned = create_args(&empty_title);
    let borrowed: Vec<&str> = owned.iter().map(String::as_str).collect();
    let empty_created = w.run_ok("acct:admin", &borrowed);
    let empty_read = w.run_ok(
        "acct:admin",
        &["read", "--id", empty_created["id"].as_str().unwrap()],
    );
    assert_eq!(
        empty_read["fields"]["title"],
        serde_json::json!(""),
        "{empty_read}"
    );

    // note→note links still work after the loosening.
    w.run_ok(
        "acct:admin",
        &[
            "link",
            "--source",
            &new_id,
            "--predicate",
            "relates_to",
            "--target",
            &old_id,
        ],
    );

    // Replay reproduces every projection with both pins intact.
    let db = native_ce::db::open_database(&w.db).await.unwrap();
    let before = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    native_ce::kernel::replay_all_projections(&db)
        .await
        .unwrap();
    let after = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    let replayed = native_ce::kernel::read_record_as(&db, &admin, &old_id)
        .await
        .unwrap()
        .expect("old note visible");
    db.close().await;
    assert_eq!(before, after, "replay must reproduce every projection");
    assert_eq!(replayed.pin.as_ref().unwrap().version, 1);
}

/// End-to-end proof of the generic package-operation seam over the
/// `demo.budget/sheet@1` fixture: install/adopt, create, call to totals,
/// compare-and-swap edit, whole-operation domain failure, view-only compute,
/// disable, and the read/history/replay invariants around a call.
#[tokio::test]
async fn v2_contract_smoke_budget_operations() {
    let w = World::fresh();
    let (admin, home) = init_admin_world(&w);
    let family = "demo.budget.sheet";

    // ---- blank: describe-with-no-operations refuses. ----
    let (blank_ok, blank_err) = w.run(
        "acct:admin",
        &[
            "package-describe",
            "--scope",
            &home,
            "--namespace",
            "demo.budget",
            "--name",
            "sheet",
        ],
    );
    assert!(!blank_ok, "nothing adopted yet: {blank_err}");

    // ---- install + adopt at the root (children inherit). ----
    let pkg = write_package(&w, &native_ce::v2_budget::budget_package(), "budget");
    w.run_ok("acct:admin", &["package-install", "--json", &pkg]);
    w.run_ok(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &pkg,
            "--scope",
            "kernel:root",
            "--ack-reads",
            r#"["record:view"]"#,
        ],
    );

    // ---- package-describe advertises the operation and its schema. ----
    let described = w.run_ok(
        "acct:admin",
        &[
            "package-describe",
            "--scope",
            &home,
            "--namespace",
            "demo.budget",
            "--name",
            "sheet",
        ],
    );
    assert_eq!(described["operations"][0]["name"], "recalculate");
    assert_eq!(
        described["operations"][0]["provider"],
        "host.table-arithmetic/1"
    );
    assert!(described["provider_schemas"]["host.table-arithmetic/1"].is_object());

    // ---- discovery: describe advertises the visible operation with no hints.
    let world = w.run_ok("acct:admin", &["describe"]);
    let discovered = world["package_operations"]
        .as_array()
        .expect("visible operation is discoverable");
    assert!(
        discovered.iter().any(|entry| {
            entry["namespace"] == "demo.budget"
                && entry["name"] == "sheet"
                && entry["operation"]["name"] == "recalculate"
                && entry["operation"]["provider"] == "host.table-arithmetic/1"
        }),
        "{world}"
    );

    // ---- create a budget sheet. ----
    let cells = w.write(
        "budget-cells.json",
        br#"{"title":"Q3","cells_json":"{\"A1\":\"100\",\"A2\":\"250\",\"B1\":\"=A1+A2\"}"}"#,
    );
    let created = w.run_ok(
        "acct:admin",
        &[
            "create", "--family", family, "--kind", "sheet", "--home", &home, "--json", &cells,
        ],
    );
    let id = created["id"].as_str().unwrap().to_string();
    let read1 = w.run_ok("acct:admin", &["read", "--id", &id]);
    let rev1 = read1["revision"].as_i64().expect("revision token");
    assert!(read1["fields"]["cells_json"]
        .as_str()
        .unwrap()
        .contains("A1"));

    // ---- call: totals; a call appends nothing. ----
    let req1 = w.write(
        "call1.json",
        format!(r#"{{"record_id":"{id}"}}"#).as_bytes(),
    );
    let call1 = w.run_ok(
        "acct:admin",
        &[
            "package-call",
            "--namespace",
            "demo.budget",
            "--name",
            "sheet",
            "--operation",
            "recalculate",
            "--json",
            &req1,
        ],
    );
    assert_eq!(
        call1["result"]["cells"]["B1"]["value"],
        serde_json::json!(350.0),
        "{call1}"
    );
    assert_eq!(call1["result"]["error"], serde_json::Value::Null);
    assert_eq!(call1["receipt"]["record_revision"], rev1);
    assert_eq!(call1["receipt"]["provider"], "host.table-arithmetic/1");
    let read_after_call = w.run_ok("acct:admin", &["read", "--id", &id]);
    assert_eq!(
        read_after_call["revision"], rev1,
        "a call must not append an event"
    );

    // ---- edit through compare-and-swap: totals change. ----
    let patched = w.write(
        "budget-patch.json",
        br#"{"cells_json":"{\"A1\":\"200\",\"A2\":\"250\",\"B1\":\"=A1+A2\"}"}"#,
    );
    w.run_ok(
        "acct:admin",
        &[
            "revise",
            "--id",
            &id,
            "--expected-seq",
            &rev1.to_string(),
            "--json",
            &patched,
        ],
    );
    let read2 = w.run_ok("acct:admin", &["read", "--id", &id]);
    let rev2 = read2["revision"].as_i64().unwrap();
    assert!(rev2 > rev1, "edit moves the revision");
    let req2 = w.write(
        "call2.json",
        format!(r#"{{"record_id":"{id}"}}"#).as_bytes(),
    );
    let call2 = w.run_ok(
        "acct:admin",
        &[
            "package-call",
            "--namespace",
            "demo.budget",
            "--name",
            "sheet",
            "--operation",
            "recalculate",
            "--json",
            &req2,
        ],
    );
    assert_eq!(
        call2["result"]["cells"]["B1"]["value"],
        serde_json::json!(450.0)
    );

    // ---- a stale editor refuses and appends nothing. ----
    let (stale_ok, stale_err) = w.run(
        "acct:admin",
        &[
            "revise",
            "--id",
            &id,
            "--expected-seq",
            &rev1.to_string(),
            "--json",
            &patched,
        ],
    );
    assert!(!stale_ok, "stale edit must refuse: {stale_err}");
    let read_after_stale = w.run_ok("acct:admin", &["read", "--id", &id]);
    assert_eq!(read_after_stale["revision"], rev2);

    // ---- whole-operation domain failure: a malformed source is a named
    // result error, not a transport failure, and it still appends nothing. ----
    let bad_patched = w.write("budget-bad.json", br#"{"cells_json":"{\"A1\":\"=B9\"}"}"#);
    w.run_ok(
        "acct:admin",
        &[
            "revise",
            "--id",
            &id,
            "--expected-seq",
            &rev2.to_string(),
            "--json",
            &bad_patched,
        ],
    );
    let rev3 = w.run_ok("acct:admin", &["read", "--id", &id])["revision"]
        .as_i64()
        .unwrap();
    let req3 = w.write(
        "call3.json",
        format!(r#"{{"record_id":"{id}"}}"#).as_bytes(),
    );
    let call3 = w.run_ok(
        "acct:admin",
        &[
            "package-call",
            "--namespace",
            "demo.budget",
            "--name",
            "sheet",
            "--operation",
            "recalculate",
            "--json",
            &req3,
        ],
    );
    assert_eq!(call3["result"]["error"]["kind"], "MissingReference");
    assert_eq!(call3["result"]["error"]["address"], "A1");
    assert_eq!(call3["receipt"]["record_revision"], rev3);
    // Repair the source and compute again.
    w.run_ok(
        "acct:admin",
        &[
            "revise",
            "--id",
            &id,
            "--expected-seq",
            &rev3.to_string(),
            "--json",
            &patched,
        ],
    );
    let call4 = w.run_ok(
        "acct:admin",
        &[
            "package-call",
            "--namespace",
            "demo.budget",
            "--name",
            "sheet",
            "--operation",
            "recalculate",
            "--json",
            &req1,
        ],
    );
    assert_eq!(
        call4["result"]["cells"]["B1"]["value"],
        serde_json::json!(450.0)
    );

    // ---- view-only can compute but not edit. ----
    let viewer = w.run_ok(
        "acct:admin",
        &[
            "principal",
            "--kind",
            "agent",
            "--label",
            "Viewer",
            "--binding",
            "agent:viewer",
        ],
    );
    let viewer_id = viewer["principal_id"].as_str().unwrap().to_string();
    let viewer_grant = w.write(
        "viewer-grant.json",
        format!(r#"{{"{viewer_id}": "view"}}"#).as_bytes(),
    );
    w.run_ok(
        "acct:admin",
        &["grant", "--home", &home, "--json", &viewer_grant],
    );
    let viewer_call = w.run_ok(
        "agent:viewer",
        &[
            "package-call",
            "--namespace",
            "demo.budget",
            "--name",
            "sheet",
            "--operation",
            "recalculate",
            "--json",
            &req1,
        ],
    );
    assert_eq!(
        viewer_call["result"]["cells"]["B1"]["value"],
        serde_json::json!(450.0)
    );
    let (viewer_edit_ok, viewer_edit_err) =
        w.run("agent:viewer", &["revise", "--id", &id, "--json", &patched]);
    assert!(
        !viewer_edit_ok,
        "view-only must not edit: {viewer_edit_err}"
    );

    // ---- hidden and nonexistent targets refuse identically. ----
    let admin_manage = w.write(
        "admin-manage.json",
        format!(r#"{{"{admin}": "manage"}}"#).as_bytes(),
    );
    let other_home = w.run_ok(
        "acct:admin",
        &["home", "--parent", "kernel:root", "--json", &admin_manage],
    );
    let other_home_id = other_home["home_id"].as_str().unwrap().to_string();
    let hidden_cells = w.write(
        "hidden-cells.json",
        br#"{"title":"Secret","cells_json":"{\"A1\":\"1\"}"}"#,
    );
    let hidden = w.run_ok(
        "acct:admin",
        &[
            "create",
            "--family",
            family,
            "--kind",
            "sheet",
            "--home",
            &other_home_id,
            "--json",
            &hidden_cells,
        ],
    );
    let hidden_id = hidden["id"].as_str().unwrap().to_string();
    let hidden_req = w.write(
        "hidden-call.json",
        format!(r#"{{"record_id":"{hidden_id}"}}"#).as_bytes(),
    );
    let missing_req = w.write(
        "missing-call.json",
        br#"{"record_id":"kernel:no-such-record"}"#,
    );
    let (hidden_ok, hidden_err) = w.run(
        "agent:viewer",
        &[
            "package-call",
            "--namespace",
            "demo.budget",
            "--name",
            "sheet",
            "--operation",
            "recalculate",
            "--json",
            &hidden_req,
        ],
    );
    let (missing_ok, missing_err) = w.run(
        "agent:viewer",
        &[
            "package-call",
            "--namespace",
            "demo.budget",
            "--name",
            "sheet",
            "--operation",
            "recalculate",
            "--json",
            &missing_req,
        ],
    );
    assert!(!hidden_ok && !missing_ok);
    assert_eq!(
        hidden_err["error"], missing_err["error"],
        "hidden and missing must be indistinguishable"
    );

    // ---- disable: calls refuse; data, history and replay are unchanged. ----
    w.run_ok(
        "acct:admin",
        &["package-disable", "--json", &pkg, "--scope", "kernel:root"],
    );
    let (disabled_ok, disabled_err) = w.run(
        "acct:admin",
        &[
            "package-call",
            "--namespace",
            "demo.budget",
            "--name",
            "sheet",
            "--operation",
            "recalculate",
            "--json",
            &req1,
        ],
    );
    assert!(!disabled_ok, "disabled package must refuse: {disabled_err}");
    let disabled_read = w.run_ok("acct:admin", &["read", "--id", &id]);
    assert!(
        disabled_read["fields"]["cells_json"].is_string(),
        "disable preserves readable data: {disabled_read}"
    );
    let history = w.run_ok("acct:admin", &["history", "--id", &id]);
    assert!(history.as_array().unwrap().len() >= 2);
    let after_disable = w.run_ok("acct:admin", &["describe"]);
    assert!(
        after_disable.get("package_operations").is_none(),
        "a disabled package is not discoverable: {after_disable}"
    );

    // ---- replay reproduces every projection with no evaluator involved. ----
    let db = native_ce::db::open_database(&w.db).await.unwrap();
    let before = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    native_ce::kernel::replay_all_projections(&db)
        .await
        .unwrap();
    let after = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    let replayed = native_ce::kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .expect("budget record visible after replay");
    db.close().await;
    assert_eq!(before, after, "replay must reproduce every projection");
    assert_eq!(replayed.pin.as_ref().unwrap().family, family);
    assert!(replayed.fields["cells_json"]
        .as_str()
        .unwrap()
        .contains("A1"));
}

/// The same generic provider, driven end-to-end through a renamed custom
/// fixture (`demo.custom/model`, source field `model_json`) — proving there
/// are no budget-specific branches in the seam or provider, rather than
/// asserting it statically.
#[test]
fn v2_contract_smoke_generic_provider_renamed_fixture() {
    let w = World::fresh();
    let (admin, home) = init_admin_world(&w);
    let family = "demo.custom.model";
    let expected_definition_digest =
        native_ce::meta::definition_artifact::digest_artifact_bytes(CUSTOM_MODEL_BYTES.as_bytes());

    // ---- install + adopt a wholly different package. ----
    let pkg = write_package(&w, &custom_model_package(), "custom-model");
    w.run_ok("acct:admin", &["package-install", "--json", &pkg]);
    w.run_ok(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &pkg,
            "--scope",
            "kernel:root",
            "--ack-reads",
            r#"["record:view"]"#,
        ],
    );

    // ---- create + query + read a record of the custom kind. ----
    let source = r#"{"A1":"3","A2":"4","B1":"=SUM(A1:A2)","C1":"=B1*2"}"#;
    let payload = serde_json::json!({"title": "Model", "model_json": source});
    let create_file = w.write(
        "custom-model-create.json",
        &serde_json::to_vec(&payload).unwrap(),
    );
    let created = w.run_ok(
        "acct:admin",
        &[
            "create",
            "--family",
            family,
            "--kind",
            "model",
            "--home",
            &home,
            "--json",
            &create_file,
        ],
    );
    let id = created["id"].as_str().unwrap().to_string();

    let queried = w.run_ok(
        "acct:admin",
        &["query", "--family", family, "--kind", "model"],
    );
    let hits = queried["hits"].as_array().unwrap();
    assert_eq!(hits.len(), 1, "{queried}");
    assert_eq!(hits[0]["id"], id);

    let read = w.run_ok("acct:admin", &["read", "--id", &id]);
    assert_eq!(read["pin"]["family"], family);
    assert_eq!(read["pin"]["version"], 1);
    assert_eq!(
        read["pin"]["digest"].as_str().unwrap(),
        expected_definition_digest
    );
    assert_eq!(read["fields"]["model_json"], source);
    let revision = read["revision"].as_i64().unwrap();

    // ---- call: the provider computes the known chained SUM. ----
    let req = w.write(
        "custom-model-call.json",
        format!(r#"{{"record_id":"{id}"}}"#).as_bytes(),
    );
    let call = w.run_ok(
        "acct:admin",
        &[
            "package-call",
            "--namespace",
            "demo.custom",
            "--name",
            "model",
            "--operation",
            "recalculate",
            "--json",
            &req,
        ],
    );
    assert_eq!(
        call["result"]["cells"]["B1"]["value"],
        serde_json::json!(7.0),
        "{call}"
    );
    assert_eq!(
        call["result"]["cells"]["C1"]["value"],
        serde_json::json!(14.0)
    );
    assert_eq!(call["result"]["error"], serde_json::Value::Null);
    assert_eq!(call["receipt"]["family"], family);
    assert_eq!(call["receipt"]["kind"], "model");
    assert_eq!(call["receipt"]["definition_version"], 1);
    assert_eq!(
        call["receipt"]["definition_digest"].as_str().unwrap(),
        expected_definition_digest
    );
    assert_eq!(call["receipt"]["provider"], "host.table-arithmetic/1");
    assert_eq!(call["receipt"]["operation"], "recalculate");
    assert_eq!(call["receipt"]["record_id"], id);
    assert_eq!(call["receipt"]["record_revision"], revision);
    assert_eq!(
        call["receipt"]["input_digest"].as_str().unwrap(),
        native_ce::meta::definition_artifact::digest_artifact_bytes(source.as_bytes())
    );

    // ---- a sibling scope stays callable after a child scope is disabled. ----
    let sibling_grant = w.write(
        "sibling-grant.json",
        format!(r#"{{"{admin}":"manage"}}"#).as_bytes(),
    );
    let sibling_home = w.run_ok(
        "acct:admin",
        &["home", "--parent", "kernel:root", "--json", &sibling_grant],
    )["home_id"]
        .as_str()
        .unwrap()
        .to_string();
    let sibling_payload =
        serde_json::json!({"title": "Sibling", "model_json": r#"{"A1":"5","B1":"=A1+1"}"#});
    let sibling_file = w.write(
        "sibling-create.json",
        &serde_json::to_vec(&sibling_payload).unwrap(),
    );
    let sibling_id = w.run_ok(
        "acct:admin",
        &[
            "create",
            "--family",
            family,
            "--kind",
            "model",
            "--home",
            &sibling_home,
            "--json",
            &sibling_file,
        ],
    )["id"]
        .as_str()
        .unwrap()
        .to_string();

    w.run_ok(
        "acct:admin",
        &["package-disable", "--json", &pkg, "--scope", &home],
    );
    let (disabled_ok, disabled_err) = w.run(
        "acct:admin",
        &[
            "package-call",
            "--namespace",
            "demo.custom",
            "--name",
            "model",
            "--operation",
            "recalculate",
            "--json",
            &req,
        ],
    );
    assert!(
        !disabled_ok,
        "disabled child scope must refuse: {disabled_err}"
    );
    let sibling_req = w.write(
        "sibling-call.json",
        format!(r#"{{"record_id":"{sibling_id}"}}"#).as_bytes(),
    );
    let sibling_call = w.run_ok(
        "acct:admin",
        &[
            "package-call",
            "--namespace",
            "demo.custom",
            "--name",
            "model",
            "--operation",
            "recalculate",
            "--json",
            &sibling_req,
        ],
    );
    assert_eq!(
        sibling_call["result"]["cells"]["B1"]["value"],
        serde_json::json!(6.0),
        "{sibling_call}"
    );
}

#[tokio::test]
async fn v2_contract_smoke_document4_adoption_retains_document3_and_enables_note_metadata() {
    let w = World::fresh();
    let (_, home) = init_admin_world(&w);
    let old_package = write_package(
        &w,
        &native_ce::v2_standard::document3_package(),
        "document3",
    );
    let new_package = write_package(
        &w,
        &native_ce::v2_standard::document4_package(),
        "document4",
    );
    for package in [&old_package, &new_package] {
        w.run_ok("acct:admin", &["package-install", "--json", package]);
    }
    w.run_ok(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &old_package,
            "--scope",
            "kernel:root",
            "--ack-reads",
            "[]",
        ],
    );
    let old_fields = w.write("old-note.json", br#"{"title":"Old synthetic note"}"#);
    let old = w.run_ok(
        "acct:admin",
        &[
            "create",
            "--family",
            "native.standard.document",
            "--kind",
            "note",
            "--home",
            &home,
            "--json",
            &old_fields,
        ],
    );
    let id = old["id"].as_str().unwrap();
    w.run_ok(
        "acct:admin",
        &[
            "package-disable",
            "--json",
            &old_package,
            "--scope",
            "kernel:root",
        ],
    );
    w.run_ok(
        "acct:admin",
        &[
            "package-adopt",
            "--json",
            &new_package,
            "--scope",
            "kernel:root",
            "--ack-reads",
            "[]",
        ],
    );
    let retained = w.run_ok("acct:admin", &["read", "--id", id]);
    assert_eq!(retained["pin"]["version"], 3);
    let fields = w.write(
        "new-note.json",
        br#"{"summary":"Synthetic summary","lifecycle":"published"}"#,
    );
    let new = w.run_ok(
        "acct:admin",
        &[
            "create",
            "--family",
            "native.standard.document",
            "--kind",
            "note",
            "--home",
            &home,
            "--json",
            &fields,
        ],
    );
    let new_id = new["id"].as_str().unwrap();
    assert_ne!(new_id, id);
    let read = w.run_ok("acct:admin", &["read", "--id", new_id]);
    assert_eq!(read["pin"]["version"], 4);
    assert_eq!(read["fields"]["summary"], "Synthetic summary");
    assert_eq!(read["fields"]["lifecycle"], "published");
    assert!(read["fields"].get("title").is_none());
}

#[tokio::test]
async fn v2_contract_smoke_kernel_mcp_banner_describes_persisted_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("banner.db");
    let (db, _) = native_ce::kernel::create_v2_database(
        path.to_str().unwrap(),
        "account",
        "Admin",
        "banner-account",
    )
    .await
    .unwrap();
    db.close().await;
    let output = Command::new(env!("CARGO_BIN_EXE_mcp-stdio"))
        .args([
            "--kernel-v2",
            "--account",
            "banner-account",
            path.to_str().unwrap(),
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(
        stderr.contains("ordinary MCP reads, writes, search and coordination"),
        "{stderr}"
    );
    assert!(stderr.contains("runs and receipts persisted"), "{stderr}");
    assert!(!stderr.contains("run keys echoed"), "{stderr}");
}
