//! Actual CLI process contract; excluded unless both exporter features are on.
use native_ce::{events::KERNEL_ROOT_ID, kernel};
use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};

fn invoke(args: &[&std::ffi::OsStr], input: &[u8]) -> Output {
    // CI builds this one product binary first; avoid linking every dev-tools
    // binary merely to obtain Cargo's integration-test executable variables.
    let binary = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("named-view-export");
    assert!(
        binary.is_file(),
        "build --bin named-view-export before this test"
    );
    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Early usage refusal may close stdin without reading it.
    let written = child.stdin.take().unwrap().write_all(input);
    if let Err(error) = written {
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
    child.wait_with_output().unwrap()
}
fn refused(output: Output, reason: &str) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(reason),
        "{output:?}"
    );
}

#[test]
fn exporter_cli_refuses_invalid_invocations_without_success_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("never-created.db");
    refused(invoke(&[], b""), "usage:");
    refused(
        invoke(&[missing.as_os_str(), "extra".as_ref()], b""),
        "exactly one",
    );
    refused(
        invoke(&[missing.as_os_str()], &vec![b' '; 16 * 1024 + 1]),
        "16 KiB",
    );
    let unknown = json!({"actor":"a","bearer":"b","record_type":"WorkItem","home":"native:root","selection":{"kind":"all"},"untrusted_evidence":{}});
    refused(
        invoke(
            &[missing.as_os_str()],
            &serde_json::to_vec(&unknown).unwrap(),
        ),
        "unknown field",
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn exporter_cli_success_is_exact_canonical_candidate_plus_one_newline() {
    let dir = tempfile::tempdir().unwrap();
    let (db, actor) = kernel::create_v2_database(
        dir.path().join("source.db").to_str().unwrap(),
        "account",
        "Admin",
        "acct:export-cli",
    )
    .await
    .unwrap();
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&actor, "manage")]), &actor)
        .await
        .unwrap();
    let bearer = kernel::create_record_as(&db, &actor, &home).await.unwrap();
    let row = json!({"id":"declared","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area":{"description":"Declared area"}}}}}).to_string(),"applies_to_collection_id":KERNEL_ROOT_ID,"version_lineage":"cli-fixture-v1","created_at":"2026-10-27T00:00:00Z"});
    kernel::v1_state::import_state_batch_as(
        &db,
        &host,
        &[kernel::v1_state::ImportedState {
            section: "schema_config".into(),
            source_id: json!(["declared"]).to_string(),
            origin: "fixture:cli".into(),
            value_json: Some(row.to_string()),
            account_principal: None,
            record_id: None,
            observed_at: "2026-10-27T00:00:00Z".into(),
            snapshot: json!({"origin_db_id":"fixture:cli"}),
        }],
    )
    .await
    .unwrap();
    let copy = dir.path().join("offline.db");
    sqlx::query("VACUUM main INTO ?")
        .bind(copy.to_str().unwrap())
        .execute(db.pool())
        .await
        .unwrap();
    db.close().await;
    let selector = json!({"actor":actor,"bearer":bearer,"record_type":"WorkItem","kind":"task","home":"native:root","selection":{"kind":"keys","keys":["area"]}});
    let expected = native_ce::named_view_export::export_file(
        &copy,
        serde_json::from_value(selector.clone()).unwrap(),
    )
    .await
    .unwrap();
    let before = std::fs::read(&copy).unwrap();
    let output = invoke(&[copy.as_os_str()], &serde_json::to_vec(&selector).unwrap());
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let mut newline = expected;
    newline.push(b'\n');
    assert_eq!(output.stdout, newline);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        &output.stdout[..output.stdout.len() - 1],
        native_artifact_runtime::mdx_v2::canonical_json_bytes(&value)
    );
    assert_eq!(std::fs::read(&copy).unwrap(), before);
    for suffix in ["-wal", "-shm", "-journal"] {
        assert!(!Path::new(&format!("{}{suffix}", copy.display())).exists());
    }
}
