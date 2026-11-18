#!/usr/bin/env python3
"""Manual sealed-ingress qualification using real historical executables.

Builds only a temporary joined test; restores both source files on every exit.
Missing/wrong artifacts fail. Ordinary CI does not silently skip this cell.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

REFERENCE = "79570567dc19b5fd1b91191d302a7a573265073f"
OLD = "03b1bbb3f4204591b69e0e80a2d14788bf0535ef"
MODULE = "held/hosting/tests/oauth_resource_server/installed_node_v2_holding.rs"
PREFIX = "jwt_v2_admission::installed_node_v2_holding::"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replace_once(text, old, new):
    assert text.count(old) == 1, (old, text.count(old))
    return text.replace(old, new, 1)


def compile_helper(root, target, source, name, env, evidence):
    command = ["cargo", "test", "--manifest-path", "held/Cargo.toml", "-p", "native-held-hosting", "--features", "v2-kernel-probe", "--test", "oauth_resource_server", "--no-run", "--message-format=json"]
    with (evidence / f"{name}-compile.jsonl").open("w") as output, (evidence / f"{name}-compile.stderr").open("w") as errors:
        subprocess.run(command, cwd=root, env={**env, "CARGO_TARGET_DIR":str(target),"NATIVE_CE_GIT_SHA":source}, stdout=output, stderr=errors, check=True)
    artifacts = [json.loads(line) for line in (evidence / f"{name}-compile.jsonl").read_text().splitlines() if line.startswith("{")]
    executables = [Path(value["executable"]) for value in artifacts if value.get("reason") == "compiler-artifact" and value.get("executable") and value["target"]["name"] == "oauth_resource_server"]
    assert len(executables) == 1, executables
    return executables[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer-root",type=Path)
    parser.add_argument("--producer-test-binary",type=Path)
    parser.add_argument("--old-binary",required=True,type=Path)
    parser.add_argument("--a-binary",required=True,type=Path)
    parser.add_argument("--evidence",required=True,type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    assert bool(args.producer_root) != bool(args.producer_test_binary), "supply one frozen producer source or artifact"
    producer = args.producer_root.resolve(strict=True) if args.producer_root else None
    if producer:
        assert producer != root
        assert subprocess.check_output(["git","rev-parse","HEAD"],cwd=producer,text=True).strip() == REFERENCE
    current = subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip()
    old = args.old_binary.resolve(strict=True)
    a_binary = args.a_binary.resolve(strict=True)
    for binary, expected in [(old,OLD),(a_binary,current)]:
        identity = json.loads(subprocess.check_output([str(binary),"--standby-identity"],env={"PATH":"/usr/bin:/bin"}))
        assert identity["source_sha"] == expected, identity
        assert identity["artifact_sha256"] == digest(binary), identity
        assert identity["engine_schema_version"] == 94, identity
        assert ("accepted_shapes" in identity) == (binary == a_binary)
    evidence = args.evidence.resolve(); evidence.mkdir(parents=True,exist_ok=True)
    fixture = Path(__file__).resolve().parent
    producer_module = producer/MODULE if producer else None
    module = root/MODULE
    original_producer = producer_module.read_bytes() if producer else None
    original = module.read_bytes()
    env = {**os.environ,"RUST_MIN_STACK":"67108864"}
    try:
        if producer:
            producer_module.write_bytes(original_producer + (fixture/"producer95-runtime.rs.inc").read_bytes())
            producer_binary = compile_helper(producer,producer/"target",REFERENCE,"producer95",env,evidence)
        else:
            producer_binary = args.producer_test_binary.resolve(strict=True)
            provenance = json.loads((producer_binary.parent/"artifact.json").read_text())
            assert provenance["source"] == REFERENCE and provenance["artifact_sha256"] == digest(producer_binary)
            assert provenance["artifact_sha256"] == "18b5a32492b1cf64ee5cf451a55c98333868823c64d549b5885f1d73f45de6ad"
        text = original.decode()
        text = replace_once(text, '        let target = root.path().join("hosted-v2.db");', '''        // Explicit artifact-qualified fixture only: use the other supported
        // managed layout from the outset, before import/catalog publication.
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let original_catalog = ctx.hosting.catalog.get_database_by_id(&db_id).await.unwrap().unwrap();
        assert_eq!(original_catalog.id, db_id);
        assert_eq!(original_catalog.engine, "v1");
        assert_eq!(ctx.hosting.catalog.get_provisioned_user(&owner.id).await.unwrap().unwrap().db_id, db_id);
        assert!(!db_id.is_empty() && db_id.len() <= 128 && db_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let original_path = PathBuf::from(&original_catalog.path);
        assert!(original_path.is_absolute());
        assert_eq!(original_path.file_stem().unwrap().to_str().unwrap(), db_id);
        let users = original_path.parent().unwrap();
        assert_eq!(users.file_name().unwrap(), "users");
        let data = users.parent().unwrap();
        assert_eq!(std::fs::canonicalize(data).unwrap(), std::fs::canonicalize(ctx._dir.path()).unwrap());
        assert_eq!(std::fs::canonicalize(&original_path).unwrap(), std::fs::canonicalize(source_db.path()).unwrap());
        let root_metadata = std::fs::symlink_metadata(data).unwrap();
        assert!(root_metadata.is_dir() && !root_metadata.file_type().is_symlink());
        assert_eq!(root_metadata.permissions().mode() & 0o077, 0);
        for path in [users, original_path.as_path()] {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            assert!(!metadata.file_type().is_symlink());
            assert_eq!(metadata.uid(), root_metadata.uid());
        }
        let databases = data.join("databases");
        assert!(matches!(std::fs::symlink_metadata(&databases), Err(e) if e.kind() == std::io::ErrorKind::NotFound));
        std::fs::DirBuilder::new().mode(0o700).create(&databases).unwrap();
        let metadata = std::fs::symlink_metadata(&databases).unwrap();
        assert!(metadata.is_dir() && !metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), root_metadata.uid());
        assert_eq!(metadata.permissions().mode() & 0o077, 0);
        let target = databases.join(format!("{db_id}.db"));
        assert!(matches!(std::fs::symlink_metadata(&target), Err(e) if e.kind() == std::io::ErrorKind::NotFound));''')
        text = replace_once(text,"struct FaultProxy {\n","struct FaultProxy {\n    destination: Arc<Mutex<std::net::SocketAddr>>,\n    writes: Arc<Mutex<Vec<String>>>,\n")
        text = replace_once(text,"        let task = tokio::spawn(async move {\n            let mut connections", "        let writes = Arc::new(Mutex::new(Vec::new()));\n        let recorded = writes.clone();\n        let destination = Arc::new(Mutex::new(hosted));\n        let routed = destination.clone();\n        let task = tokio::spawn(async move {\n            let mut connections")
        text = replace_once(text,"                        let (socket, _) = accepted.unwrap();","                        let (socket, _) = accepted.unwrap();\n                        let hosted = *routed.lock().unwrap();\n                        let writes = recorded.clone();")
        text = replace_once(text,"        Self {\n            addr,\n            mode,", "        Self {\n            destination,\n            writes,\n            addr,\n            mode,")
        text = replace_once(text,'key == Some(&json!("working-first"))', '(key == Some(&json!("working-first")) || key == Some(&json!("installed-lost")))')
        text = replace_once(text,"proxy_connection(socket, hosted, state, receipt, client, stall).await;", "proxy_connection(socket, hosted, state, receipt, client, stall, writes).await;")
        text = replace_once(text,"    stall: Arc<StallWrite>,\n) {", "    stall: Arc<StallWrite>,\n    writes: Arc<Mutex<Vec<String>>>,\n) {")
        text = replace_once(text,'    let key = message.pointer("/params/arguments/arguments/idempotency_key");', '    let key = message.pointer("/params/arguments/arguments/idempotency_key");\n    if key.is_some() { writes.lock().unwrap().push(String::from_utf8(body.to_vec()).unwrap()); }')
        module.write_bytes(text.encode()+(fixture/"installed-v7-runtime.rs.inc").read_bytes())
        test_binary = compile_helper(root,root/"target",current,"receiver-a",env,evidence)
        receipt = evidence/"installed-v7-receipt.json"
        with (evidence/"installed-v7-run.log").open("w") as log:
            subprocess.run([str(test_binary),PREFIX+"receiver_installed_pre_a_v7_real95_restart_retry","--exact","--nocapture","--test-threads=1"],cwd=root,env={**env,"NATIVE_NODE_TEST_BINARY":str(a_binary),"NATIVE_RECEIVER_OLD_BINARY":str(old),"NATIVE_RECEIVER95_TEST_BINARY":str(producer_binary),"NATIVE_RECEIVER_V7_RECEIPT":str(receipt)},stdout=log,stderr=subprocess.STDOUT,check=True,timeout=600)
        assert receipt.is_file()
        print(json.dumps({"result":"passed","head":current,"receipt":str(receipt),"producer":REFERENCE,"producer_test_artifact":digest(producer_binary)}))
    finally:
        module.write_bytes(original)
        if producer: producer_module.write_bytes(original_producer)


if __name__ == "__main__":
    main()
