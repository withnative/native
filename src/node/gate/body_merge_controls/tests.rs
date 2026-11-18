use super::*;

fn private_dir() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn control_files_are_private_durable_and_refuse_links_or_bad_permissions() {
    use std::os::unix::fs::symlink;
    let directory = private_dir();
    let path = directory.path().join(FORGET);
    let marker = ForgetMarker {
        version: 2,
        reason: "sign_out".into(),
    };
    atomic_private(&path, &marker).unwrap();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let saved: ForgetMarker =
        serde_json::from_slice(&read_private(&path).unwrap().unwrap()).unwrap();
    assert_eq!(saved.reason, "sign_out");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_private(&path).is_err());
    assert!(atomic_private(&path, &marker).is_err());
    fs::remove_file(&path).unwrap();
    let target = directory.path().join("target");
    fs::write(&target, "untouched").unwrap();
    symlink(&target, &path).unwrap();
    assert!(atomic_private(&path, &marker).is_err());
    assert!(remove_private(&path).is_err());
    assert_eq!(fs::read_to_string(target).unwrap(), "untouched");
}

#[test]
fn local_control_argument_types_are_strict() {
    let args = arguments(&json!({"params":{"arguments":{"confirm":"true","extra":1}}})).unwrap();
    assert!(optional_bool(&args, "confirm").is_err());
    assert!(allowed(&args, &["confirm"]).is_err());
    assert!(arguments(&json!({"params":{"arguments":null}})).is_err());
    assert!(required_string(&serde_json::Map::new(), "id").is_err());
    assert!(optional_string(&serde_json::from_value(json!({"id":null})).unwrap(), "id").is_err());
    assert!(is_tool("node_unmerged"));
    assert!(!is_tool("records_write"));
}

#[tokio::test]
async fn account_switch_requires_confirmed_forget_and_marker_resumes_after_restart() {
    let directory = private_dir();
    let config = GateConfig {
        account_binding: Some(json!({"account_id":"old"})),
        ..Default::default()
    };
    let mut gate = WriteGate::open(directory.path(), config.clone()).unwrap();
    gate.ensure_account_binding().unwrap();
    let mut new_config = config.clone();
    new_config.account_binding = Some(json!({"account_id":"new"}));
    // Configuration changes are checked before any recovery text is exposed.
    let binding_path = directory.path().join(ACCOUNT);
    let binding = read_private(&binding_path).unwrap().unwrap();
    let old: AccountBinding = serde_json::from_slice(&binding).unwrap();
    assert_ne!(old.account, new_config.account_binding.clone().unwrap());
    gate.config.account_binding = new_config.account_binding.clone();
    assert!(gate.ensure_account_binding().is_err());
    assert_eq!(read_private(&binding_path).unwrap().unwrap(), binding);
    let warning = gate.body_merge_control(&json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"node_body_merge_forget","arguments":{"reason":"account_switch"}}})).await.unwrap();
    let warning: Value = serde_json::from_str(&warning).unwrap();
    assert_eq!(
        warning["result"]["structuredContent"]["requires_confirmation"],
        true
    );
    assert!(binding_path.exists());
    // Simulate a crash after confirmation was fsynced but before any erase.
    atomic_private(
        &directory.path().join(FORGET),
        &ForgetMarker {
            version: 2,
            reason: "account_switch".into(),
        },
    )
    .unwrap();
    assert!(gate.body_merge_forget_pending());
    assert!(gate.ensure_account_binding().is_err());
    drop(gate);
    let gate = WriteGate::open(directory.path(), new_config).unwrap();
    gate.resume_body_merge_forget().unwrap();
    assert!(!gate.body_merge_forget_pending());
    gate.ensure_account_binding().unwrap();
    let new: AccountBinding =
        serde_json::from_slice(&read_private(&binding_path).unwrap().unwrap()).unwrap();
    assert_eq!(new.account, json!({"account_id":"new"}));
    let error = gate.body_merge_control(&json!({"id":2,"params":{"name":"node_body_merge_forget","arguments":{"confirm":"yes"}}})).await.unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&error).unwrap()["result"]["isError"],
        true
    );
}

#[tokio::test]
async fn housekeeping_prunes_dismissed_payload_without_reads_and_keeps_open_custody() {
    use crate::node::unmerged::{RecoveryItem, RecoveryKind, ITEM_VERSION};
    let directory = private_dir();
    let config = GateConfig {
        housekeeping_every: Duration::from_millis(10),
        account_binding: Some(json!({"account_id":"housekeeping-account"})),
        ..Default::default()
    };
    let gate = Arc::new(WriteGate::open(directory.path(), config).unwrap());
    let dismissed = RecoveryItem {
        version: ITEM_VERSION,
        id: "expired-dismissal".into(),
        kind: RecoveryKind::Refusal,
        record_id: "record".into(),
        journal_entry: "entry".into(),
        editor: "editor".into(),
        made_at: Some(1),
        created_at: 1,
        last_seen_at: 1,
        state: RecoveryState::Dismissed,
        dismissed_at: Some(1),
        reason: Some("not_permitted".into()),
        base_text: Some("private dismissed base".into()),
        my_text: Some("private dismissed draft".into()),
        passage: None,
    };
    let mut open = dismissed.clone();
    open.id = "ancient-open".into();
    open.state = RecoveryState::Open;
    open.dismissed_at = None;
    open.base_text = Some("private unresolved base".into());
    open.my_text = Some("private unresolved draft".into());
    gate.unmerged.upsert(dismissed.clone()).unwrap();
    gate.unmerged.upsert(open.clone()).unwrap();
    let dismissed_path = directory.path().join("unmerged/expired-dismissal.json");
    let open_path = directory.path().join("unmerged/ancient-open.json");
    let open_bytes = fs::read(&open_path).unwrap();
    assert!(fs::read_to_string(&dismissed_path)
        .unwrap()
        .contains("private dismissed draft"));
    let task = gate.spawn_housekeeping();
    // Observe disk directly: neither a control read, store reopen nor a test
    // call to prune may accidentally do the timer's work for it.
    let pruned = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let raw: Value = serde_json::from_slice(&fs::read(&dismissed_path).unwrap()).unwrap();
            if raw["payload_pruned"] == true {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    task.abort();
    let _ = task.await;
    pruned.expect("housekeeping must prune expired dismissed payload without a read");
    let compact = fs::read_to_string(&dismissed_path).unwrap();
    assert!(!compact.contains("private dismissed"));
    assert_eq!(fs::read(&open_path).unwrap(), open_bytes);
    assert_eq!(
        gate.unmerged.get(&open.id, true).unwrap().unwrap().my_text,
        open.my_text
    );
    let mut retry = dismissed;
    retry.state = RecoveryState::Open;
    retry.dismissed_at = None;
    assert_eq!(
        gate.unmerged.upsert(retry).unwrap().state,
        RecoveryState::Dismissed
    );
    assert_eq!(fs::read_to_string(dismissed_path).unwrap(), compact);
    assert_eq!(gate.unmerged.counts().unwrap().open, 1);
    assert_eq!(gate.unmerged.counts().unwrap().tombstones, 1);
}
