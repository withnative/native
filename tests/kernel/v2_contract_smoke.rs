//! End-to-end smoke for the `v2_contract` example harness: init, install,
//! adopt, create, link, query, revise, history, and a refusal — over a
//! throwaway `demo.widget` ontology that shares no names with lab fixtures.

use std::path::PathBuf;
use std::process::Command;

const WIDGET_BYTES: &str = r#"{"family":"demo.widget","version":1,"primary_type":"Widget","interpreter":"native.defn/2","kinds":[{"token":"Widget","fields":[{"name":"accession","type":"text","required":true},{"name":"mass_kg","type":"number","required":true},{"name":"color","type":"text","required":false}],"identity":{"field":"accession"},"links":[],"maturity":"current","description":"A demo widget."},{"token":"Cog","fields":[{"name":"accession","type":"text","required":true},{"name":"teeth","type":"integer","required":true}],"identity":{"field":"accession"},"links":[{"predicate":"fitted_to","target":{"primary_type":"Widget","kind":"Widget"},"direction":"out","cardinality":"many"}],"maturity":"current","description":"A cog fitted to a widget."}]}"#;

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

/// A definitions-only `native.standard/document@2` whose definition adds an
/// optional `summary` field. Used by the replace step.
fn document_v2_package() -> native_ce::package_manifest::PackageManifest {
    const BYTES: &str = r#"{"family":"native.standard.document","version":2,"interpreter":"native.defn/3","primary_type":"Document","kinds":[{"token":"note","description":"An ordinary authored prose or capture document. Each note is distinct; matching titles or content do not make two notes the same.","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"title","type":"text","required":true,"description":"Short human title."},{"name":"body","type":"text","required":false,"description":"The prose, as Markdown."},{"name":"summary","type":"text","required":false,"description":"An optional one-line summary."}],"links":[{"predicate":"relates_to","target":{"primary_type":"Document","kind":"note"},"direction":"either","cardinality":"many"}]}]}"#;
    let digest = native_ce::meta::definition_artifact::digest_artifact_bytes(BYTES.as_bytes());
    native_ce::package_manifest::PackageManifest {
        namespace: "native.standard".to_string(),
        name: "document".to_string(),
        version: 2,
        definitions: vec![native_ce::package_manifest::DefinitionEntry {
            family: "native.standard.document".to_string(),
            version: 2,
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
async fn v2_contract_smoke_native_standard_packages() {
    let w = World::fresh();
    let (admin, home) = init_admin_world(&w);
    let document_family = "native.standard.document";
    let outcome_family = "native.standard.outcome";

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
    let doc_pkg = write_package(&w, &native_ce::v2_standard::document_package(), "document");
    let out_pkg = write_package(&w, &native_ce::v2_standard::outcome_package(), "outcome");
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
        doc_entry["package"]["namespace"], "native.standard",
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

    // ---- Step 5: replace Document with @2 (adds optional summary). ----
    // The merged K6a retained-data guard
    // (`dependency_transition_tests::visible_outside_rows_block_replacement_with_retained_data`)
    // refuses a *direct* package replacement while records still pin the old
    // revision, because mapping data across revisions is out of scope. The
    // approved brief did not anticipate that guard; the demo records it and
    // then replaces via disable-then-adopt, which leaves old records on v1.
    let doc_v2 = document_v2_package();
    let doc_v2_file = write_package(&w, &doc_v2, "document-v2");
    w.run_ok("acct:admin", &["package-install", "--json", &doc_v2_file]);

    // (b) A saved-query consumer pinned to v1 refuses the v2 adoption with no
    // state change.
    let v1_digest = native_ce::v2_standard::document_package().definitions[0]
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
            "native.standard",
            "--name",
            "document-watcher",
            "--family",
            document_family,
            "--version",
            "1",
            "--digest",
            &v1_digest,
        ],
    );
    let consumer_seq = registered["event_seq"].as_i64().unwrap().to_string();
    let preview = w.run_ok(
        "acct:admin",
        &[
            "package-preview-adopt",
            "--json",
            &doc_v2_file,
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
            &doc_v2_file,
            "--scope",
            "kernel:root",
            "--ack-reads",
            "[]",
        ],
    );
    assert!(
        !ok,
        "v2 adoption must refuse while the v1 consumer lives: {err}"
    );
    let db = native_ce::db::open_database(&w.db).await.unwrap();
    let after = native_ce::kernel::dump_all_kernel_tables(&db)
        .await
        .unwrap();
    db.close().await;
    assert_eq!(before, after, "a refused adoption appends nothing");

    // Retire the consumer. A direct replacement is still refused, now by the
    // retained-data guard: the old notes pin Document v1.
    w.run_ok(
        "acct:admin",
        &[
            "consumer-retire",
            "--scope",
            &home,
            "--consumer-kind",
            "saved-query",
            "--namespace",
            "native.standard",
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
            &doc_v2_file,
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
        "the retained-data guard names the stranded v1 pin: {still}"
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
            &doc_v2_file,
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
    // their original pin. Old notes keep their v1 pin and read under v1; a
    // new note pins v2.
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
            &doc_v2_file,
            "--scope",
            "kernel:root",
            "--ack-reads",
            "[]",
        ],
    );
    let old_note = w.run_ok("acct:admin", &["read", "--id", &n1_id]);
    assert_eq!(old_note["pin"]["version"], 1, "{old_note}");
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
    assert_eq!(new_read["pin"]["version"], 2, "{new_read}");
    let after_replace = w.run_ok("acct:admin", &["describe"]);
    let doc_v2_entry = describe_entry(&after_replace, document_family, "note");
    assert_eq!(doc_v2_entry["version"], 2, "{after_replace}");

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
