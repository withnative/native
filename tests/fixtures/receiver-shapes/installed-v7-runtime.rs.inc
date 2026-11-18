
// Manual artifact-qualified proof. Appended only by qualify-installed-v7.py;
// absent historical artifacts cannot turn ordinary CI into a false success.
#[tokio::test]
async fn receiver_installed_pre_a_v7_real95_restart_retry() {
    let mut f = Fixture::with_working_option(false, true).await;
    struct PreservePrivateFixture { roots: Vec<(PathBuf,PathBuf)> }
    impl Drop for PreservePrivateFixture {
        fn drop(&mut self) {
            fn copy(source:&Path,target:&Path) {
                let Ok(metadata)=std::fs::symlink_metadata(source) else {return};
                if metadata.file_type().is_symlink() {return;}
                if metadata.is_dir() {
                    if std::fs::create_dir_all(target).is_err() {return;}
                    if let Ok(entries)=std::fs::read_dir(source) { for entry in entries.flatten() {copy(&entry.path(),&target.join(entry.file_name()));} }
                } else if metadata.is_file() {let _=std::fs::copy(source,target);}
            }
            for (source,target) in &self.roots {copy(source,target);}
        }
    }
    let _preserve=PreservePrivateFixture {roots:vec![(f.root.path().to_path_buf(),f.evidence.join("private-runtime")),(f.ctx._dir.path().to_path_buf(),f.evidence.join("private-hosted-data"))]};
    let old = PathBuf::from(std::env::var("NATIVE_RECEIVER_OLD_BINARY").unwrap());
    let old_identity: Value = serde_json::from_slice(&command(&old).arg("--standby-identity").output().await.unwrap().stdout).unwrap();
    assert_eq!(old_identity["source_sha"], "03b1bbb3f4204591b69e0e80a2d14788bf0535ef");
    assert_eq!(old_identity["artifact_sha256"], file_digest(&old));
    assert!(old_identity.get("accepted_shapes").is_none());
    let new_binary = f.binary.clone();
    f.binary = old;
    let mut node = f.start("receiver-authentic-pre-a").await;
    f.wait_verified(&mut node).await;
    f.proxy.offline();
    let args = json!({"id":f.record,"body_append":" authentic receiver append","reason":"Private receiver upgrade proof","idempotency_key":"installed-lost"});
    let ack = node.write("update_record", args.clone()).await;
    assert_pending(&ack);
    assert_eq!(ack["result"]["structuredContent"]["local_visibility"], "working_applied");
    node.stop().await;
    let before = f.entries();
    assert_eq!(before.len(), 1);
    let original = before[0].clone();
    assert_eq!(original["version"],7);
    assert_eq!(original["arguments"],args);
    assert!(original["kernel_v2_custody"]["original"].is_null());
    assert_eq!(original["kernel_v2_custody"]["contract_digest"],"4eb0ca37e1d1caa6d8981b65f4f7ed5f26ab6f929c9de0d2304d57635798cc3a");
    assert_eq!(f.body().await, "base");
    fn entry_file(root: &Path, id: &str) -> PathBuf {
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                let found = entry_file(&path,id);
                if !found.as_os_str().is_empty() { return found; }
            } else if path.file_name().unwrap() == format!("{id}.json").as_str() { return path; }
        }
        PathBuf::new()
    }
    let journal_file = entry_file(&f.root.path().join("socket"),original["id"].as_str().unwrap());
    assert!(journal_file.is_file());
    let original_bytes = std::fs::read(&journal_file).unwrap();
    // All canonical fixture writers close before the reference95 executable
    // takes Hosting's exclusive volume authority and performs maintenance.
    let canonical_file = f.db.path().to_path_buf();
    let catalog = f.ctx.hosting.catalog.get_database_by_id(&f.route).await.unwrap().unwrap();
    assert_eq!(catalog.id, f.route);
    assert_eq!(catalog.engine, "v2");
    assert_eq!(std::fs::canonicalize(&catalog.path).unwrap(), std::fs::canonicalize(&canonical_file).unwrap());
    assert!(canonical_file.starts_with(f.ctx._dir.path()));
    assert_eq!(canonical_file.parent().unwrap(), f.ctx._dir.path().join("databases"));
    let node_config: Value = serde_json::from_slice(&std::fs::read(&f.config).unwrap()).unwrap();
    assert_eq!(node_config["account_id"], f.account);
    assert_eq!(node_config["db_id"], f.route);
    let standby_config: Value = serde_json::from_slice(&std::fs::read(node_config["standby_config"].as_str().unwrap()).unwrap()).unwrap();
    let head = native_ce::standby::delta_transport::observe_authority_act_head(&f.db, &f.route).await.unwrap();
    assert_eq!(head.route_database_id(), f.route);
    let head_wire = serde_json::to_value(head).unwrap();
    assert_eq!(head_wire["contract"], "native.standby-authority-act-head-response.v1");
    assert_eq!(head_wire["version"], 1);
    assert_eq!(head_wire["head"]["contract"], "native.standby-kernel-v2-head.v1");
    assert!(head_wire["head"]["generation"].is_object());
    assert_eq!(head_wire["head"]["generation"]["schema_sha256"], "0295db140abe29a6c4c2dce429e325eb37d1235031a6d1068d2df561e8618da7");
    let canonical_origin = head_wire["head"]["origin_database_id"].as_str()
        .filter(|origin| !origin.trim().is_empty()).expect("actual canonical origin").to_owned();
    assert_eq!(standby_config["hosted_route_database_id"], f.route);
    assert_eq!(standby_config["origin_database_id"], canonical_origin);
    f.db.close().await;
    f.ctx.hosting.close().await;
    let volume = std::fs::File::open(f.ctx._dir.path().join("users")).unwrap();
    fs2::FileExt::try_lock_exclusive(&volume).expect("old hosting volume is still owned");
    fs2::FileExt::unlock(&volume).unwrap();
    std::fs::write(f.ctx._dir.path().join("receiver-runtime-fixture.json"),b"{\"private\":true}").unwrap();
    let ready = f.root.path().join("producer95-ready.json");
    let runtime_config = f.root.path().join("producer95-runtime.json");
    std::fs::write(&runtime_config,serde_json::to_vec(&json!({"data":f.ctx._dir.path(),"database":&canonical_file,"account":f.account,"route":f.route,"ready":ready})).unwrap()).unwrap();
    let producer = PathBuf::from(std::env::var("NATIVE_RECEIVER95_TEST_BINARY").unwrap());
    let mut hosted95 = command(&producer).env("NATIVE_RECEIVER_RUNTIME_CONFIG",runtime_config)
        .args(["jwt_v2_admission::installed_node_v2_holding::receiver95_private_runtime","--exact","--nocapture"])
        .stdout(std::fs::File::create(f.evidence.join("producer95.stdout")).unwrap())
        .stderr(std::fs::File::create(f.evidence.join("producer95.stderr")).unwrap()).spawn().unwrap();
    tokio::time::timeout(WAIT,async {
        while !ready.is_file() {
            assert!(hosted95.try_wait().unwrap().is_none(),"producer95 exited: {}",std::fs::read_to_string(f.evidence.join("producer95.stderr")).unwrap());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.expect("producer95 did not become ready");
    let producer_evidence: Value = serde_json::from_slice(&std::fs::read(&ready).unwrap()).unwrap();
    assert_eq!(producer_evidence["source"],"79570567dc19b5fd1b91191d302a7a573265073f");
    assert_eq!(producer_evidence["artifact_sha256"],file_digest(&producer));
    *f.proxy.destination.lock().unwrap() = producer_evidence["addr"].as_str().unwrap().parse().unwrap();
    f.binary = new_binary;
    let mut node = f.start("receiver-a-restart").await;
    assert_eq!(std::fs::read(&journal_file).unwrap(),original_bytes,"restart may not rewrite retained journal provenance");
    f.proxy.mode.store(STALL_WORKING_WRITE, Ordering::SeqCst);
    node.exchange("tools/list", json!({})).await;
    f.wait_verified(&mut node).await;
    let current95 = tokio::time::timeout(WAIT,async {
        loop {
            for file in std::fs::read_dir(f.root.path().join("socket/state")).unwrap() {
                let path=file.unwrap().path();
                let Ok(bytes)=std::fs::read(path) else {continue};
                let Ok(state)=serde_json::from_slice::<Value>(&bytes) else {continue};
                if state["binding"]["account"]==f.account && state["binding"]["route"]==f.route
                    && !state["verified_custody_credential"].is_null()
                    && state["discovery"][PROTOCOL_VERSION]["holding_contracts"].as_array().is_some_and(|contracts| contracts.iter().any(|entry| entry["contract"]["description"]["contract_digest"]=="c25709f1f76520556c3c74be6bb720d237e841640f8d5c44faec6948ce59e8d2")) { return state; }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }).await.expect("current authenticated95 discovery never entered this namespace");
    let description = node.exchange("tools/call",json!({"name":"describe_operation","arguments":{"executor":"records_write","operation":"update_record","format":"json"}})).await;
    assert_mcp_value_ok(&description);
    assert_eq!(description["result"]["structuredContent"]["contract_digest"],"c25709f1f76520556c3c74be6bb720d237e841640f8d5c44faec6948ce59e8d2");
    tokio::time::timeout(WAIT,f.proxy.stall.entered.acquire()).await.unwrap().unwrap().forget();
    f.proxy.mode.store(DROP_COMMITTED_REPLY, Ordering::SeqCst);
    f.proxy.stall.release.add_permits(1);
    tokio::time::timeout(WAIT,async {
        while f.proxy.dropped.lock().unwrap().is_none() { tokio::time::sleep(Duration::from_millis(50)).await; }
    }).await.expect("authentic retained v7 did not reach real95 acceptance");
    let first_receipt = f.proxy.dropped.lock().unwrap().clone().unwrap();
    node.stop().await;
    let ambiguous = f.entries()[0].clone();
    for key in ["arguments","idempotency_key","working_original","kernel_v2_custody","version","id"] {
        assert_eq!(ambiguous[key],original[key],"{key}");
    }
    let mut node = f.start("receiver-a-ambiguous-retry").await;
    f.proxy.online();
    node.exchange("tools/list",json!({})).await;
    f.wait_settled(&mut node,1,"confirmed").await;
    let retained = f.entries()[0].clone();
    for key in ["arguments","idempotency_key","working_original","kernel_v2_custody","version","id"] { assert_eq!(retained[key],original[key],"{key}"); }
    let read = node.exchange("tools/call",json!({"name":"records_read","arguments":{"operation":"get_record","arguments":{"ids":[f.record]},"format":"json"}})).await;
    assert_mcp_value_ok(&read);
    assert_eq!(read["result"]["structuredContent"]["records"][0]["body"],"base authentic receiver append");
    let retry = node.write("update_record",args).await;
    assert_mcp_value_ok(&retry);
    node.stop().await;
    let writes=f.proxy.writes.lock().unwrap().clone();
    assert!(writes.len()>=2,"real ambiguous send must retry");
    assert!(writes.iter().all(|request|request==&writes[0]),"first canonical request bytes must survive restart/retry");
    use sqlx::Connection;
    let mut audit=sqlx::SqliteConnection::connect_with(&sqlx::sqlite::SqliteConnectOptions::new().filename(&canonical_file).read_only(true).create_if_missing(false)).await.unwrap();
    let outcomes:i64=sqlx::query_scalar("SELECT count(*) FROM content_events WHERE type='kernel.mcp_write_receipt_recorded.v1' AND actor=? AND json_extract(payload,'$.operation')='update_record' AND json_extract(payload,'$.operation_key')='installed-lost'").bind(&f.actor).fetch_one(&mut audit).await.unwrap();
    assert_eq!(outcomes,1,"one original key has one canonical outcome");
    audit.close().await.unwrap();
    let receipt = json!({"canonical_fixture":{"path":canonical_file,"catalog_id":f.route,"account":f.account,"origin":canonical_origin,"data_root":f.ctx._dir.path()},"canonical_outcomes_for_original_key":outcomes,"wire_requests":writes,"current95_discovery":current95,"old":old_identity,"a_source":native_ce::FULL_GIT_SHA,"a_artifact_sha256":file_digest(&f.binary),"producer95":producer_evidence,"original_entry":original,"retained_entry":retained,"first_receipt":first_receipt,"retry":retry,"record":read,"evidence":f.evidence});
    std::fs::write(std::env::var("NATIVE_RECEIVER_V7_RECEIPT").unwrap(),serde_json::to_vec_pretty(&receipt).unwrap()).unwrap();
    hosted95.kill().await.unwrap();
}
