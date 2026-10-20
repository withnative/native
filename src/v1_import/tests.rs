use super::*;
use serde_json::Value;
use sqlx::Executor;

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_relation_removal_needs_only_source_edit_and_keeps_provenance() {
    let f = Fixture::new().await;
    let imported = run(f.options(&["task", "epic"], false)).await.unwrap();
    assert!(imported.refusals.is_empty());
    let db = f.db().await;
    let member = &imported.principals["account-b"];
    assert_eq!(
        k::kernel_effective_capability(&db, member, "task")
            .await
            .unwrap(),
        crate::authorization::Capability::Edit
    );
    let before = k::relates_to_port::relations_as(&db, &imported.principals["account-a"], "task")
        .await
        .unwrap();
    assert!(!before.is_empty());
    ordinary_kernel_call(&db,"account-b","manage_links",json!({"action":"remove","source_id":"task","target_id":"epic","relationship":"relates_to"})).await.unwrap();
    let after = k::relates_to_port::relations_as(&db, &imported.principals["account-a"], "task")
        .await
        .unwrap();
    let old: standard::relates_to::State =
        serde_json::from_value(before[0]["state"].clone()).unwrap();
    let new: standard::relates_to::State =
        serde_json::from_value(after[0]["state"].clone()).unwrap();
    assert!(new.assertions.iter().all(|a| a.retracted));
    for prior in old.assertions {
        let retracted = new.assertions.iter().find(|a| a.id == prior.id).unwrap();
        assert_eq!(retracted.sources, prior.sources);
        assert_eq!(retracted.asserted_by, prior.asserted_by);
        assert_eq!(retracted.retracted_by.as_deref(), Some(member.as_str()));
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_member_move_preserves_record_local_policy_by_refusing_unsafe_relocation() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO record_policies VALUES('task'); INSERT INTO policy_entries VALUES('task','account','account-a','manage'); UPDATE records SET policy_anchor_id='task' WHERE id='task'").await.unwrap();
    let imported = run(f.options(&["task"], false)).await.unwrap();
    assert!(imported.refusals.is_empty());
    let db = f.db().await;
    let root=ordinary_kernel_call(&db,"account-a","create_record",json!({"type":"Annotation","kind":"comment","body":"Private thread","links":[{"target_id":"task","relationship":"part_of"}]})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let reply=ordinary_kernel_call(&db,"account-a","create_record",json!({"type":"Annotation","kind":"comment","body":"Private reply","links":[{"target_id":root,"relationship":"part_of"}]})).await.unwrap()["id"].as_str().unwrap().to_owned();
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id='task'")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let policy:Vec<(String,String,String)>=sqlx::query_as("SELECT subject_id,capability,effect FROM kernel_policy_entries WHERE root_id=? ORDER BY subject_id,capability,effect").bind(&home).fetch_all(db.pool()).await.unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(ordinary_kernel_call(
        &db,
        "account-b",
        "update_record",
        json!({"id":"task","home_id":"native:root"})
    )
    .await
    .is_err());
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"task","home_id":"native:root"}),
    )
    .await
    .unwrap();
    let after:Vec<(String,String,String)>=sqlx::query_as("SELECT subject_id,capability,effect FROM kernel_policy_entries WHERE root_id=? ORDER BY subject_id,capability,effect").bind(&home).fetch_all(db.pool()).await.unwrap();
    assert_eq!(policy, after);
    for id in ["task", root.as_str(), reply.as_str()] {
        let physical: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(physical, home);
        let get = ordinary_kernel_call(&db, "account-a", "get_record", json!({"ids":[id]}))
            .await
            .unwrap();
        assert_eq!(get["records"][0]["home_id"], "native:root");
        let hidden = ordinary_kernel_call(&db, "account-b", "get_record", json!({"ids":[id]}))
            .await
            .unwrap();
        assert_eq!(hidden["records"][0]["status"], "not_found");
    }
    for account in ["account-a", "account-b"] {
        let hits = ordinary_kernel_call(&db, account, "search", json!({"query":"Private"}))
            .await
            .unwrap();
        for id in [&root, &reply] {
            let hit = hits["hits"]
                .as_array()
                .unwrap()
                .iter()
                .find(|hit| hit["id"] == id.as_str());
            if account == "account-a" {
                assert_eq!(hit.unwrap()["home_id"], "native:root");
            } else {
                assert!(hit.is_none());
            }
        }
    }
    let sql = ordinary_kernel_call(
        &db,
        "account-a",
        "query_sql",
        json!({"sql":"SELECT home_id FROM records WHERE id='task'"}),
    )
    .await
    .unwrap();
    assert_eq!(sql["rows"][0]["home_id"], "native:root");
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_folder_home_shape_and_archive_rules_match_v1_create_and_send() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO record_policies VALUES('note'),('epic'); INSERT INTO policy_entries VALUES('note','members','native:members','edit'),('epic','members','native:members','edit'); UPDATE records SET policy_anchor_id='note' WHERE id='note'; UPDATE records SET type='Collection',kind='project',policy_anchor_id='epic' WHERE id='epic'").await.unwrap();
    source.close().await.unwrap();
    let imported = run(f.options(&["folder", "task", "note", "epic"], false))
        .await
        .unwrap();
    assert!(
        imported.refusals.is_empty(),
        "{}",
        serde_json::to_string(&imported.refusals).unwrap()
    );
    let db = f.db().await;
    let note_home: String =
        sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id='note'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    for home in ["note".to_string(), note_home.clone(), derived("epic")] {
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        let error = ordinary_kernel_call(
            &db,
            "account-a",
            "create_record",
            json!({"type":"Document","kind":"note","home_id":home}),
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "home_id must name a live unarchived folder"
        );
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    }
    // V1 accepts an annotation filed in the live folder, even when its
    // bearer has an independent policy anchor. The physical alias is just
    // another spelling of that annotation's scope, not a new filing parent.
    for home in ["folder".to_string(), note_home.clone()] {
        let annotation = ordinary_kernel_call(&db,"account-a","create_record",json!({"type":"Annotation","kind":"suggestion","name":"Explicit filing","home_id":home,"links":[{"relationship":"part_of","target_id":"note"}]})).await.unwrap()["id"].clone();
        let actual: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
            .bind(annotation.as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(actual, note_home);
    }
    // Known v2 strictness: another editable live folder is still refused.
    let other_folder = ordinary_kernel_call(&db,"account-a","create_record",json!({"type":"Collection","kind":"folder","name":"Other editable folder","home_id":"folder"})).await.unwrap()["id"].clone();
    let before_mismatch = k::dump_all_kernel_tables(&db).await.unwrap();
    let mismatch = ordinary_kernel_call(&db,"account-a","create_record",json!({"type":"Annotation","kind":"suggestion","home_id":other_folder,"links":[{"relationship":"part_of","target_id":"note"}]})).await.unwrap_err();
    assert_eq!(
        mismatch.to_string(),
        "kernel-v2 write: Annotation home must match its bearer"
    );
    assert_eq!(
        before_mismatch,
        k::dump_all_kernel_tables(&db).await.unwrap()
    );
    let send = |collection: &str| json!({"action":"send","idempotency_key":uuid::Uuid::new_v4().to_string(),"body":"Folder parity","origin":{"type":"collection","collection_id":collection},"addressed_to":[],"expectation":"none","reason":"fixture"});
    let non_folder = ordinary_kernel_call(&db, "account-a", "manage_messages", send("epic"))
        .await
        .unwrap_err();
    assert_eq!(
        non_folder.to_string(),
        "home_id must name a live unarchived folder"
    );
    ordinary_kernel_call(&db, "account-a", "manage_messages", send("folder"))
        .await
        .unwrap();
    ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"Document","kind":"note","home_id":"folder"}),
    )
    .await
    .unwrap();
    ordinary_kernel_call(
        &db,
        "account-a",
        "archive_record",
        json!({"id":"folder","reason":"fixture"}),
    )
    .await
    .unwrap();
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let archived_create = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"Document","kind":"note","home_id":"folder"}),
    )
    .await
    .unwrap_err();
    assert_eq!(
        archived_create.to_string(),
        "home_id must name a live unarchived folder"
    );
    let archived_send = ordinary_kernel_call(&db, "account-a", "manage_messages", send("folder"))
        .await
        .unwrap_err();
    assert_eq!(
        archived_send.to_string(),
        "home_id must name a live unarchived folder"
    );
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    ordinary_kernel_call(
        &db,
        "account-a",
        "archive_record",
        json!({"id":"folder","archived":false,"reason":"fixture"}),
    )
    .await
    .unwrap();
    ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"Document","kind":"note","home_id":"folder"}),
    )
    .await
    .unwrap();
    ordinary_kernel_call(&db, "account-a", "manage_messages", send("folder"))
        .await
        .unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_folder_accepts_native_nested_folders_and_children() {
    let f = Fixture::new().await;
    let imported = run(f.options(&["folder", "task", "private", "secret"], false))
        .await
        .unwrap();
    assert!(imported.refusals.is_empty());
    let db = f.db().await;
    let folder = ordinary_kernel_call(&db,"account-b","create_record",json!({"type":"Collection","kind":"folder","name":"Member native folder","home_id":"folder"})).await.unwrap()["id"].clone();
    let nested = ordinary_kernel_call(
        &db,
        "account-b",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Member nested folder","home_id":folder}),
    )
    .await
    .unwrap()["id"]
        .clone();
    let note = ordinary_kernel_call(
        &db,
        "account-b",
        "create_record",
        json!({"type":"Document","kind":"note","name":"Nested child","home_id":nested}),
    )
    .await
    .unwrap()["id"]
        .clone();
    let get = ordinary_kernel_call(
        &db,
        "account-a",
        "get_record",
        json!({"ids":[folder,nested,note]}),
    )
    .await
    .unwrap();
    assert_eq!(get["records"][0]["home_id"], "folder");
    assert_eq!(get["records"][1]["home_id"], folder);
    assert_eq!(get["records"][2]["home_id"], nested);
    let unowned_folder = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"Other author subtree","home_id":folder}),
    )
    .await
    .unwrap()["id"]
        .clone();
    let unowned_note = ordinary_kernel_call(&db,"account-a","create_record",json!({"type":"Document","kind":"note","name":"Other author child","home_id":unowned_folder})).await.unwrap()["id"].clone();
    let visible = ordinary_kernel_call(
        &db,
        "account-b",
        "get_record",
        json!({"ids":[unowned_folder,unowned_note]}),
    )
    .await
    .unwrap();
    assert!(visible["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["status"] != "not_found"));
    // Source Manage and destination Edit move the entire native subtree.
    ordinary_kernel_call(
        &db,
        "account-b",
        "update_record",
        json!({"id":folder,"home_id":"private"}),
    )
    .await
    .unwrap_err();
    ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"folder","home_id":"private"}),
    )
    .await
    .unwrap();
    // Author owner floors remain v1-compatible; another member with no floor
    // cannot see or add records under the now-private tree.
    let hidden = ordinary_kernel_call(
        &db,
        "account-b",
        "get_record",
        json!({"ids":[unowned_folder,unowned_note]}),
    )
    .await
    .unwrap();
    assert!(hidden["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["status"] == "not_found"));
    let before_write = k::dump_all_kernel_tables(&db).await.unwrap();
    let hidden_create = ordinary_kernel_call(
        &db,
        "account-b",
        "create_record",
        json!({"type":"Document","kind":"note","home_id":unowned_folder}),
    )
    .await
    .unwrap_err();
    assert_eq!(hidden_create.to_string(), k::HIDDEN_OR_MISSING);
    let hidden_move = ordinary_kernel_call(
        &db,
        "account-b",
        "update_record",
        json!({"id":note,"home_id":unowned_folder}),
    )
    .await
    .unwrap_err();
    assert_eq!(hidden_move.to_string(), k::HIDDEN_OR_MISSING);
    assert_eq!(before_write, k::dump_all_kernel_tables(&db).await.unwrap());
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_folder_move_reparents_children_and_refuses_cycles_atomically() {
    let f = Fixture::new().await;
    let imported = run(f.options(&["folder", "task", "private", "secret"], false))
        .await
        .unwrap();
    assert!(imported.refusals.is_empty());
    let db = f.db().await;
    let mut deep = KERNEL_ROOT_ID.to_owned();
    for _ in 0..100 {
        deep = k::create_home(&db, &deep, None, &imported.principals["account-a"])
            .await
            .unwrap();
    }
    let before_depth = k::dump_all_kernel_tables(&db).await.unwrap();
    let error = ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"folder","home_id":deep}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("depth limit"), "{error}");
    assert_eq!(before_depth, k::dump_all_kernel_tables(&db).await.unwrap());
    let visible = ordinary_kernel_call(&db, "account-b", "get_record", json!({"ids":["task"]}))
        .await
        .unwrap();
    assert_ne!(visible["records"][0]["status"], "not_found");
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"folder","home_id":"folder"})
    )
    .await
    .is_err());
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"folder","home_id":"private"}),
    )
    .await
    .unwrap();
    let parent: String = sqlx::query_scalar("SELECT parent_id FROM kernel_roots WHERE root_id=?")
        .bind(derived("folder"))
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(parent, derived("private"));
    let get = ordinary_kernel_call(
        &db,
        "account-a",
        "get_record",
        json!({"ids":["folder","task"]}),
    )
    .await
    .unwrap();
    assert_eq!(get["records"][0]["home_id"], "private");
    assert_eq!(get["records"][1]["home_id"], "folder");
    let hidden = ordinary_kernel_call(
        &db,
        "account-b",
        "get_record",
        json!({"ids":["folder","task"]}),
    )
    .await
    .unwrap();
    assert!(hidden["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["status"] == "not_found"));
    let sql = ordinary_kernel_call(
        &db,
        "account-b",
        "query_sql",
        json!({"sql":"SELECT id FROM records WHERE id IN ('folder','task')"}),
    )
    .await
    .unwrap();
    assert!(sql["rows"].as_array().unwrap().is_empty());
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"private","home_id":"folder"})
    )
    .await
    .is_err());
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn resume_refuses_hosted_activation_before_target_writes() {
    let fixture = Fixture::new().await;
    run(fixture.options(&["note"], false)).await.unwrap();
    let before = cutover::snapshot_digest(&fixture.target).await.unwrap();
    let mut db = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&fixture.target),
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,causal_envelope_version,causal_status) VALUES('hosted-activation-test','kernel:root','kernel.hosted_membership.v1',1,'complete')")
        .execute(&mut db).await.unwrap();
    db.close().await.unwrap();
    let activated = cutover::snapshot_digest(&fixture.target).await.unwrap();
    assert_ne!(before, activated);
    let error = run(fixture.options(&["note"], true)).await.err().unwrap();
    assert!(error.to_string().contains("--resume is forbidden"));
    assert_eq!(
        activated,
        cutover::snapshot_digest(&fixture.target).await.unwrap()
    );
}

struct Fixture {
    _dir: tempfile::TempDir,
    source: PathBuf,
    target: PathBuf,
    members: PathBuf,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.db");
        let target = dir.path().join("target.db");
        let mut db = SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&source)
                .create_if_missing(true),
        )
        .await
        .unwrap();
        db.execute(r#"CREATE TABLE database_identity(singleton INTEGER,origin_db_id TEXT);
            INSERT INTO database_identity VALUES(1,'test-origin');
            CREATE TABLE records(id TEXT PRIMARY KEY,type TEXT,kind TEXT,name TEXT,body TEXT,home_id TEXT,owner_id TEXT,lifecycle TEXT,summary TEXT,created_at TEXT,updated_at TEXT,archived INTEGER,policy_anchor_id TEXT,deleted_at TEXT,persistence TEXT NOT NULL DEFAULT 'enduring',maturity TEXT,last_activity_at TEXT NOT NULL DEFAULT '2026-01-01T00:00:00Z');
            CREATE TABLE bindings(record_id TEXT,system TEXT,identifier TEXT,is_canonical INTEGER);
            INSERT INTO bindings VALUES('person-a','account','account-a',1),('person-b','account','account-b',1);
            CREATE TABLE record_policies(record_id TEXT PRIMARY KEY);
            INSERT INTO record_policies VALUES('native:root'),('private');
            CREATE TABLE policy_entries(policy_anchor_id TEXT,subject_kind TEXT,subject_id TEXT,capability TEXT);
            INSERT INTO policy_entries VALUES('native:root','account','account-a','manage'),('native:root','members','native:members','edit'),('private','account','account-a','manage');
            CREATE TABLE content_events(seq INTEGER PRIMARY KEY,id TEXT,record_id TEXT,type TEXT,payload TEXT,actor TEXT,created_at TEXT);
            CREATE TABLE facet_values(record_id TEXT,key TEXT,value TEXT,value_num REAL,vocab_ref TEXT,created_at TEXT);
            CREATE TABLE facet_observations(record_id TEXT,key TEXT,as_of TEXT,event_seq INTEGER);
            CREATE TABLE instruction_bindings(id TEXT,scope_kind TEXT,scope_id TEXT,source_record_id TEXT,position INTEGER,enabled INTEGER,created_by TEXT,created_at TEXT,updated_at TEXT);
            CREATE TABLE links(id TEXT,source_id TEXT,target_id TEXT,relationship TEXT,note TEXT,created_at TEXT);
            CREATE TABLE relationship_legacy_links(relationship_origin_db_id TEXT,relationship_id TEXT,source_facts TEXT,created_at TEXT);
            CREATE TABLE relationship_events(seq INTEGER PRIMARY KEY,relationship_origin_db_id TEXT,relationship_id TEXT,type TEXT,actor TEXT,occurred_at TEXT,id TEXT,payload TEXT);
            INSERT INTO relationship_legacy_links VALUES('test-origin','relation-b','[]','2026-01-02T00:00:00Z');
            INSERT INTO relationship_events VALUES(1,'test-origin','relation-b','relationship.created.v1','governed-author','2026-01-02T00:00:00Z','relationship-created','{"endpoints":[{"record_id":"task"},{"record_id":"epic"}]}');"#).await.unwrap();
        db.execute(r#"CREATE TABLE artifact_source_attestations(artifact_id TEXT,attestation_event_id TEXT,source_event_id TEXT,descriptor TEXT);
CREATE TABLE artifact_module_grants(artifact_id TEXT,subject_kind TEXT,subject_record_id TEXT,subject_event_id TEXT,capability TEXT,scope_sha256 TEXT);
CREATE TABLE module_releases(module_record_id TEXT,publication_event_id TEXT);
CREATE TABLE module_release_imports(consumer_publication_event_id TEXT,ordinal INTEGER);
CREATE TABLE artifact_inputs(artifact_id TEXT,port_name TEXT,collection_id TEXT);
CREATE TABLE alpha_tab_orders(account_id TEXT PRIMARY KEY,tab_order TEXT,event_id TEXT);
CREATE TABLE alpha_tab_installs(artifact_id TEXT,account_id TEXT,package TEXT,consented_source_revision TEXT,event_id TEXT,status TEXT,adoption TEXT);
CREATE TABLE canvas_objects(canvas_id TEXT,object_id TEXT,geometry_seq INTEGER,content_seq INTEGER,props TEXT,x REAL);
CREATE TABLE canvas_batches(canvas_id TEXT,batch_id TEXT,event_id TEXT,event_seq INTEGER,actor TEXT,ops_sha256 TEXT);
CREATE TABLE control_events(seq INTEGER PRIMARY KEY,id TEXT,subject_id TEXT,type TEXT,payload TEXT,actor TEXT,created_at TEXT);"#).await.unwrap();
        for (id, typ, kind, parent, policy, owner) in [
            (V1_ROOT, "Collection", "root", None, V1_ROOT, None),
            (
                "folder",
                "Collection",
                "folder",
                Some(V1_ROOT),
                V1_ROOT,
                Some("person-a"),
            ),
            (
                "task",
                "WorkItem",
                "task",
                Some("folder"),
                V1_ROOT,
                Some("person-a"),
            ),
            (
                "epic",
                "WorkItem",
                "epic",
                Some("folder"),
                V1_ROOT,
                Some("unverified"),
            ),
            (
                "note",
                "Document",
                "note",
                Some("folder"),
                V1_ROOT,
                Some("person-b"),
            ),
            (
                "archived",
                "WorkItem",
                "task",
                Some("folder"),
                V1_ROOT,
                Some("person-a"),
            ),
            (
                "private",
                "Collection",
                "folder",
                Some(V1_ROOT),
                "private",
                Some("person-a"),
            ),
            (
                "secret",
                "Document",
                "note",
                Some("private"),
                "private",
                None,
            ),
        ] {
            sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)")
                .bind(id)
                .bind(typ)
                .bind(kind)
                .bind(if id == "note" { "" } else { id })
                .bind(if id == "task" {
                    "x".repeat(70_000)
                } else {
                    "body".into()
                })
                .bind(parent)
                .bind(owner)
                .bind("open")
                .bind("summary")
                .bind("2026-01-01T00:00:00Z")
                .bind("2026-02-01T00:00:00Z")
                .bind(0)
                .bind(policy)
                .execute(&mut db)
                .await
                .unwrap();
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'record.created','{}','original-creator','2026-01-01T00:00:00Z'),(?,?,'record.updated','{}','last-editor','2026-02-01T00:00:00Z')")
                .bind(format!("created:{id}")).bind(id).bind(format!("edited:{id}")).bind(id).execute(&mut db).await.unwrap();
        }
        db.execute("INSERT INTO facet_values VALUES('task','score','0.84551240822557006',0.84551240822557006,NULL,'2026-01-01T00:00:00Z'),('archived','archived','true',NULL,NULL,'2026-01-01T00:00:00Z');
            INSERT INTO facet_observations VALUES('task','score','2026-02-01T00:00:00Z',1),('archived','archived','2026-03-01T00:00:00Z',2);
            INSERT INTO links VALUES('link-a','task','epic','relates_to','original note','2026-01-01T00:00:00Z'),('rel:test-origin:relation-b','epic','task','relates_to',NULL,'2026-01-02T00:00:00Z'),('link-c','task','outside','part_of',NULL,'2026-01-02T00:00:00Z'),('link-d','task','epic','part_of',NULL,'2026-01-02T00:00:00Z');
            INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('obsolete-link-event','task','link.added','{\"id\":\"link-a\",\"source_id\":\"task\",\"target_id\":\"epic\",\"relationship\":\"relates_to\"}','obsolete-author','2026-01-01T00:00:00Z'),('removed-link-event','task','link.removed','{\"source_id\":\"task\",\"target_id\":\"epic\",\"relationship\":\"relates_to\"}',NULL,'2026-01-01T00:00:00Z'),('link-event','task','link.added','{\"id\":\"link-a\",\"source_id\":\"task\",\"target_id\":\"epic\",\"relationship\":\"relates_to\"}','original-author','2026-01-01T00:00:00Z');").await.unwrap();
        let members = dir.path().join("members.txt");
        std::fs::write(&members, "account-a\naccount-b\n").unwrap();
        Self {
            members,
            _dir: dir,
            source,
            target,
        }
    }
    fn options(&self, seeds: &[&str], resume: bool) -> Options {
        Options {
            source: self.source.clone(),
            target: self.target.clone(),
            seeds: seeds.iter().map(|s| (*s).into()).collect(),
            all: false,
            history: false,
            resume,
            members_file: Some(self.members.clone()),
        }
    }
    async fn db(&self) -> Db {
        crate::db::open_database(self.target.to_str().unwrap())
            .await
            .unwrap()
    }
}

async fn private_policy_for_b(source: &mut SqliteConnection) {
    account_policy_for_b(source, "private").await;
}
async fn account_policy_for_b(source: &mut SqliteConnection, anchor: &str) {
    sqlx::query("UPDATE policy_entries SET subject_id='account-b' WHERE policy_anchor_id=? AND subject_kind='account'").bind(anchor).execute(source).await.unwrap();
}

async fn seed_instruction_bindings(f: &Fixture) {
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO instruction_bindings VALUES
        ('binding-workspace','database','native:database','epic',0,1,'binding-author','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),
        ('binding-member','account','account-a','note',1,1,'binding-author','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),
        ('binding-outside','account','account-guest','outside',0,0,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')").await.unwrap();
}

#[tokio::test]
async fn private_member_instruction_targets_resume_without_re_adopting_packages() {
    let f = Fixture::new().await;
    seed_instruction_bindings(&f).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    private_policy_for_b(&mut source).await;
    source.execute("UPDATE records SET owner_id='person-b' WHERE id IN ('private','secret');
        INSERT INTO instruction_bindings VALUES('binding-private-member','account','account-b','secret',2,1,'binding-author','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')").await.unwrap();
    let first = run(f.options(&["task"], false)).await.unwrap();
    assert!(first.review.is_empty());
    assert!(first.refusals.is_empty());
    assert_eq!(first.instruction_bindings.created, 3);
    for name in [
        "snapshot_read",
        "principals_homes_policies_packages",
        "records",
        "comments",
        "links",
        "instruction_bindings",
        "verify",
    ] {
        assert!(first.phase_seconds[name].is_finite());
        assert!(first.phase_seconds[name] >= 0.0);
        assert!(first.phase_seconds[name] <= first.phase_seconds["total"]);
    }
    let db = f.db().await;
    let admin = &first.principals["account-a"];
    assert!(k::read_record_as(&db, admin, "secret")
        .await
        .unwrap()
        .is_none());
    let before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.package_adopted.v1'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    let retry = run(f.options(&["task"], true)).await.unwrap();
    assert!(retry.review.is_empty());
    assert!(retry.refusals.is_empty());
    assert_eq!(retry.instruction_bindings.unchanged, 3);
    assert_eq!(retry.instruction_bindings.verified, 3);
    assert!(k::read_record_as(&db, admin, "secret")
        .await
        .unwrap()
        .is_none());
    assert!(
        k::read_record_as(&db, &first.principals["account-b"], "secret")
            .await
            .unwrap()
            .is_some()
    );
    let after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.package_adopted.v1'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
async fn instruction_bindings_expand_standing_targets_preserve_mapping_and_update_idempotently() {
    let f = Fixture::new().await;
    seed_instruction_bindings(&f).await;
    let mut missing_roster = f.options(&["task"], false);
    missing_roster.members_file = None;
    let missing = run(missing_roster).await.unwrap();
    assert!(missing.refusals[0]
        .reason
        .contains("member instruction bindings require --members-file"));
    assert!(!f.target.exists());
    let first = run(f.options(&["task"], false)).await.unwrap();
    assert!(first.refusals.is_empty());
    assert!(first.review.is_empty());
    assert_eq!(first.instruction_bindings.created, 2);
    assert_eq!(first.instruction_bindings.verified, 2);
    assert_eq!(first.instruction_bindings.standing_targets_added, 2);
    assert!(first.verified_ids.contains(&"note".into()));
    assert!(first.verified_ids.contains(&"epic".into()));
    let db = f.db().await;
    let mapping:(String,String,String,String)=sqlx::query_as("SELECT b.scope_id,b.account_principal,p.auth_binding,b.legacy_actor FROM kernel_instruction_bindings b JOIN kernel_principals p ON p.principal_id=b.account_principal WHERE b.id='binding-member'").fetch_one(db.write_pool()).await.unwrap();
    assert_eq!(
        mapping,
        (
            "account-a".into(),
            first.principals["account-a"].clone(),
            "account-a".into(),
            "v1:binding-author".into()
        )
    );
    assert_eq!(
        k::read_record_as(&db, &first.principals["account-a"], "note")
            .await
            .unwrap()
            .unwrap()
            .owner_id
            .as_ref(),
        Some(&first.principals["account-b"])
    );
    let event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type LIKE 'kernel.instruction_binding%'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    let same = run(f.options(&["task"], true)).await.unwrap();
    assert_eq!(same.instruction_bindings.unchanged, 2);
    let after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type LIKE 'kernel.instruction_binding%'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(event_count, after);
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE instruction_bindings SET enabled=0,position=9,source_record_id='task' WHERE id='binding-workspace'").await.unwrap();
    let update = run(f.options(&["task"], true)).await.unwrap();
    assert!(update.refusals.is_empty());
    assert_eq!(update.instruction_bindings.updated, 1);
    assert_eq!(update.instruction_bindings.verified, 2);
    let again = run(f.options(&["task"], true)).await.unwrap();
    assert_eq!(again.instruction_bindings.unchanged, 2);
    source.execute("INSERT INTO instruction_bindings VALUES('binding-guest-selected','account','account-guest','note',4,0,'binding-author','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')").await.unwrap();
    let guest = run(f.options(&["task"], true)).await.unwrap();
    assert_eq!(guest.instruction_bindings.created, 1);
    assert_eq!(guest.instruction_bindings.verified, 3);
    assert!(
        k::read_record_as(&db, &guest.principals["account-guest"], "note")
            .await
            .unwrap()
            .is_none()
    );
    source.execute("UPDATE instruction_bindings SET created_by='different-author' WHERE id='binding-workspace'").await.unwrap();
    let refused = run(f.options(&["task"], true)).await.unwrap();
    assert_eq!(refused.instruction_bindings.refused, 1);
    assert_eq!(refused.refusals[0].id, "binding-workspace");
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

async fn add_fixture_link(f: &Fixture, link: &Link, actor: Option<&str>) {
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    sqlx::query("INSERT INTO links VALUES(?,?,?,?,?,?)")
        .bind(&link.id)
        .bind(&link.source_id)
        .bind(&link.target_id)
        .bind(&link.relationship)
        .bind(&link.note)
        .bind(&link.created_at)
        .execute(&mut source)
        .await
        .unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'link.added',?,?,?)")
        .bind(format!("added:{}",link.id)).bind(&link.source_id)
        .bind(json!({"id":link.id,"source_id":link.source_id,"target_id":link.target_id,"relationship":link.relationship}).to_string())
        .bind(actor).bind(&link.created_at).execute(&mut source).await.unwrap();
}

#[tokio::test]
async fn generic_links_preserve_identity_provenance_visibility_and_resume() {
    let f = Fixture::new().await;
    for (id, target, relationship) in [
        ("generic-alias", "epic", "related_to"),
        ("generic-hyphen", "epic", "relates-to"),
        ("generic-private", "secret", "supersedes"),
        ("generic-self", "task", "part_of"),
    ] {
        add_fixture_link(
            &f,
            &Link {
                id: id.into(),
                source_id: "task".into(),
                target_id: target.into(),
                relationship: relationship.into(),
                note: Some("fixture legacy note".into()),
                created_at: "2026-01-03 04:05:06.123".into(),
            },
            Some("legacy-author"),
        )
        .await;
    }
    let seeds = ["task", "epic", "secret"];
    let first = run(f.options(&seeds, false)).await.unwrap();
    assert!(first.review.is_empty());
    assert!(first.refusals.is_empty());
    assert_eq!(first.links_imported, 7);
    for (name, n) in [
        ("part_of", 2),
        ("related_to", 1),
        ("relates-to", 1),
        ("supersedes", 1),
    ] {
        let counts = &first.links_by_relationship[name];
        assert_eq!(counts.created, n);
        assert_eq!(counts.verified, n);
    }
    assert_eq!(first.links_by_relationship["part_of"].skipped, 1);
    let db = f.db().await;
    let a = &first.principals["account-a"];
    let b = &first.principals["account-b"];
    let links = k::generic_links_as(&db, a, "task", false, None, None, 200)
        .await
        .unwrap()
        .links;
    assert_eq!(links.len(), 5);
    let private = links
        .iter()
        .find(|l| l.link_id == "generic-private")
        .unwrap();
    assert_eq!(private.actor.as_deref(), Some("v1:legacy-author"));
    assert_eq!(private.created_at, "2026-01-03 04:05:06.123");
    assert_eq!(private.note.as_deref(), Some("fixture legacy note"));
    assert!(
        k::generic_links_as(&db, b, "task", false, Some("supersedes"), None, 200)
            .await
            .unwrap()
            .links
            .is_empty()
    );
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type LIKE 'kernel.generic_link%'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    let retry = run(f.options(&seeds, true)).await.unwrap();
    assert!(retry.review.is_empty());
    assert!(retry.refusals.is_empty());
    assert_eq!(retry.links_by_relationship["part_of"].unchanged, 2);
    let after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type LIKE 'kernel.generic_link%'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(count, after);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn generic_link_active_identity_collision_requires_review() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("DELETE FROM links WHERE id='link-d'")
        .await
        .unwrap();
    let seeds = ["task", "epic"];
    let first = run(f.options(&seeds, false)).await.unwrap();
    let db = f.db().await;
    let native = k::add_generic_link_as(
        &db,
        &first.principals["account-a"],
        "task",
        "epic",
        "part_of",
        None,
    )
    .await
    .unwrap();
    add_fixture_link(
        &f,
        &Link {
            id: "link-d".into(),
            source_id: "task".into(),
            target_id: "epic".into(),
            relationship: "part_of".into(),
            note: None,
            created_at: "2026-01-02T00:00:00Z".into(),
        },
        Some("legacy-author"),
    )
    .await;
    let retry = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(retry.review.len(), 1);
    assert_eq!(retry.review[0].id, "link-d");
    assert!(retry.review[0].reason.contains(&native.link.link_id));
    // The native link write legitimately advanced activity after the frozen
    // source snapshot. Resume reports that drift and never rewrites it.
    assert_eq!(retry.refusals.len(), 1);
    assert_eq!(retry.refusals[0].id, "task");
    assert_eq!(
        retry.refusals[0].reason,
        "kernel read reconciliation mismatch"
    );
    assert_eq!(retry.links_by_relationship["part_of"].review, 1);
    let links = k::generic_links_as(
        &db,
        &first.principals["account-a"],
        "task",
        false,
        Some("part_of"),
        None,
        200,
    )
    .await
    .unwrap()
    .links;
    assert_eq!(links, vec![native.link]);
    // An unrelated admission failure must not be mislabeled as a collision.
    source
        .execute("UPDATE links SET created_at='not-a-time' WHERE id='link-d'")
        .await
        .unwrap();
    let invalid = run(f.options(&seeds, true)).await.unwrap();
    assert!(invalid.review.is_empty());
    assert_eq!(invalid.refusals.len(), 2);
    assert!(invalid
        .refusals
        .iter()
        .any(|issue| issue.reason == "generic link admission refused"));
    assert!(invalid
        .refusals
        .iter()
        .any(|issue| issue.id == "task" && issue.reason == "kernel read reconciliation mismatch"));
}

#[tokio::test]
async fn generic_link_provenance_conflicts_are_refusals_and_note_updates_keep_identity() {
    let f = Fixture::new().await;
    let seeds = ["task", "epic"];
    let first = run(f.options(&seeds, false)).await.unwrap();
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("UPDATE links SET note='updated fixture note' WHERE id='link-d'")
        .await
        .unwrap();
    let updated = run(f.options(&seeds, true)).await.unwrap();
    assert!(updated.refusals.is_empty());
    assert_eq!(updated.links_by_relationship["part_of"].updated, 1);
    source
        .execute("UPDATE links SET created_at='2026-06-01T00:00:00Z' WHERE id='link-d'")
        .await
        .unwrap();
    let conflict = run(f.options(&seeds, true)).await.unwrap();
    assert!(conflict.review.is_empty());
    assert_eq!(conflict.refusals.len(), 1);
    assert_eq!(
        conflict.refusals[0].reason,
        "generic link identity or provenance conflict"
    );
    source
        .execute("UPDATE links SET created_at='not-a-time' WHERE id='link-d'")
        .await
        .unwrap();
    let refused = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(refused.refusals.len(), 1);
    assert_eq!(refused.refusals[0].id, "link-d");
    assert_eq!(refused.refusals[0].reason, "generic link admission refused");
    assert_eq!(refused.links_by_relationship["part_of"].refused, 1);
    let db = f.db().await;
    let links = k::generic_links_as(
        &db,
        &first.principals["account-a"],
        "task",
        false,
        Some("part_of"),
        None,
        200,
    )
    .await
    .unwrap()
    .links;
    assert_eq!(links[0].link_id, "link-d");
    assert_eq!(links[0].created_at, "2026-01-02T00:00:00Z");
    assert_eq!(links[0].note.as_deref(), Some("updated fixture note"));
}

#[tokio::test]
async fn subset_resume_provenance_long_body_and_private_visibility() {
    let f = Fixture::new().await;
    let first = run(f.options(&["task"], false)).await.unwrap();
    assert_eq!(first.created, 2);
    assert_eq!(first.verified, 2);
    assert_eq!(first.skipped_links["endpoint_outside_imported_subset"], 4);
    assert!(first.refusals.is_empty());
    assert!(run(f.options(&["task"], false)).await.is_err());
    let seeds = ["task", "epic", "note", "archived", "secret"];
    let second = run(f.options(&seeds, true)).await.unwrap();
    assert!(
        second.refusals.is_empty(),
        "{}",
        serde_json::to_string(&second.refusals).unwrap()
    );
    assert!(second.review.is_empty());
    assert_eq!(second.created, 5);
    assert_eq!(second.unchanged, 2);
    assert_eq!(second.verified, 7);
    assert_eq!(second.links_imported, 3);
    assert_eq!(second.skipped_links["endpoint_outside_imported_subset"], 1);
    assert_eq!(second.links_by_relationship["part_of"].created, 1);
    assert_eq!(second.links_by_relationship["part_of"].verified, 1);
    assert_eq!(second.assumed_owners, vec!["epic", "secret"]);
    let db = f.db().await;
    let a = &second.principals["account-a"];
    let b = &second.principals["account-b"];
    for id in ["private", "secret"] {
        assert!(k::read_record_as(&db, b, id).await.unwrap().is_none());
        assert!(k::read_record_as(&db, a, id).await.unwrap().is_some());
    }
    assert_eq!(
        placement_as(&db, a, "task")
            .await
            .unwrap()
            .unwrap()
            .home_id
            .as_deref(),
        Some("folder")
    );
    assert!(placement_as(&db, b, "secret").await.unwrap().is_none());
    let task = k::read_record_as(&db, a, "task").await.unwrap().unwrap();
    assert_eq!(task.body.unwrap().len(), 70_000);
    assert_eq!(task.fields["lifecycle"], "open");
    let facet = k::facets_as(&db, a, "task").await.unwrap();
    assert_eq!(facet[0].as_of, "2026-02-01T00:00:00Z");
    assert!(
        k::read_record_as(&db, a, "archived")
            .await
            .unwrap()
            .unwrap()
            .archived
    );
    assert!(!k::read_record_as(&db, b, "note")
        .await
        .unwrap()
        .unwrap()
        .fields
        .contains_key("title"));
    let wrong_actor:i64=sqlx::query_scalar("SELECT count(*) FROM content_events e JOIN kernel_principals p ON p.principal_id=e.actor WHERE e.type='kernel.import_home_policy.v1' AND p.auth_binding<>?").bind(k::HOST_IMPORT_BINDING).fetch_one(db.write_pool()).await.unwrap();
    assert_eq!(wrong_actor, 0);
    let policy_acts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.import_home_policy.v1'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert!(policy_acts > 0);
    let relations = k::relations_as(&db, a, "task").await.unwrap();
    assert_eq!(relations.len(), 1);
    assert_eq!(
        relations[0]["state"]["assertions"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        relations[0]["state"]["assertions"][0]["sources"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let encoded = serde_json::to_value(&relations).unwrap();
    assert!(encoded.to_string().contains("original-author"));
    assert!(encoded.to_string().contains("relation-b"));
    assert!(encoded.to_string().contains("governed-author"));
    assert!(!encoded.to_string().contains("obsolete-author"));
    let provenance:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id='task' AND type='kernel.legacy_recorded.v1'").fetch_one(db.write_pool()).await.unwrap();
    let provenance: Value = serde_json::from_str(&provenance).unwrap();
    assert_eq!(
        provenance["legacy"]["payload"]["creator"],
        "original-creator"
    );
    assert_eq!(
        provenance["legacy"]["payload"]["last_editor"],
        "last-editor"
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id='task'")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    let third = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(third.unchanged, 7);
    assert_eq!(third.created, 0);
    assert!(third.refusals.is_empty());
    let after: i64 =
        sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id='task'")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(count, after);
    k::rehome_record_as(&db, a, "task", &derived("private"))
        .await
        .unwrap();
    assert_eq!(
        placement_as(&db, a, "task")
            .await
            .unwrap()
            .unwrap()
            .home_id
            .as_deref(),
        Some("private")
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn changed_source_refuses_without_mutating_record_and_wrong_source_refuses() {
    let f = Fixture::new().await;
    let first = run(f.options(&["task"], false)).await.unwrap();
    // Delta resume advances import-only state; native edits still require review.
    let db = f.db().await;
    let view = k::read_record_as(&db, &first.principals["account-a"], "task")
        .await
        .unwrap()
        .unwrap();
    k::set_body_as(
        &db,
        &first.principals["account-a"],
        "task",
        "native edit",
        view.revision,
    )
    .await
    .unwrap();
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source
        .execute("UPDATE records SET body='changed' WHERE id='task'")
        .await
        .unwrap();
    let second = run(f.options(&["task"], true)).await.unwrap();
    assert!(second.refusals.iter().any(|i| i.id == "task"));
    let db = f.db().await;
    assert_eq!(
        k::read_record_as(&db, &first.principals["account-a"], "task")
            .await
            .unwrap()
            .unwrap()
            .body
            .unwrap(),
        "native edit"
    );
    source
        .execute("UPDATE database_identity SET origin_db_id='different-origin'")
        .await
        .unwrap();
    assert!(run(f.options(&["task"], true)).await.is_err());
}

#[tokio::test]
async fn sealed_home_import_rejects_spoof_and_changed_policy() {
    let f = Fixture::new().await;
    let report = run(f.options(&["task"], false)).await.unwrap();
    let db = f.db().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO relationship_legacy_links VALUES('test-origin','migrated',?,'2026-01-01T00:00:00Z')")
        .bind(json!([{"operation":"add","actor":"historical-author","occurred_at":"2026-01-01T00:00:00Z"}]).to_string()).execute(&mut source).await.unwrap();
    let migrated = Link {
        id: "rel:test-origin:migrated".into(),
        source_id: "task".into(),
        target_id: "epic".into(),
        relationship: "relates_to".into(),
        note: None,
        created_at: "2026-01-01T00:00:00Z".into(),
    };
    assert_eq!(
        link_provenance(&mut source, &migrated, true, false)
            .await
            .unwrap()
            .0
            .as_deref(),
        Some("historical-author")
    );
    let a = &report.principals["account-a"];
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(k::import_home_policy_as(&db, a, KERNEL_ROOT_ID, &[])
        .await
        .is_err());
    assert!(
        k::import_home_as(&db, a, &derived("other"), "other", KERNEL_ROOT_ID, a, None)
            .await
            .is_err()
    );
    assert!(k::import_home_as(
        &db,
        &host,
        &derived("folder"),
        "folder",
        KERNEL_ROOT_ID,
        a,
        Some(&[])
    )
    .await
    .is_err());
    assert!(crate::store::append(
        &db,
        crate::store::AppendSpec {
            record_id: derived("spoof"),
            event_type: "kernel.import_home.v1".into(),
            payload: json!({"source_record_id":"spoof","home":{"parent_id":KERNEL_ROOT_ID,"owner_id":a,"entries":null}}),
            actor: Some(host)
        }
    )
    .await
    .is_err());
}

#[tokio::test]
async fn source_alias_and_conflicting_private_owner_refuse_safely() {
    let f = Fixture::new().await;
    let mut alias = f.options(&["task"], true);
    alias.target = f.source.clone();
    assert!(run(alias).await.is_err());
    #[cfg(unix)]
    {
        let link = f._dir.path().join("source-hardlink.db");
        std::fs::hard_link(&f.source, &link).unwrap();
        let mut alias = f.options(&["task"], true);
        alias.target = link;
        assert!(run(alias).await.is_err());
    }
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source
        .execute("UPDATE records SET owner_id='person-b' WHERE id='secret'")
        .await
        .unwrap();
    let report = run(f.options(&["secret"], false)).await.unwrap();
    assert!(report.review.is_empty());
    assert!(report.refusals.is_empty());
    assert_eq!(report.owner_overrides.len(), 1);
    assert_eq!(report.owner_overrides[0].record_id, "secret");
    assert_eq!(
        report.owner_overrides[0].verified_owner_account.as_deref(),
        Some("account-b")
    );
    assert_eq!(
        report.owner_overrides[0].private_policy_account,
        "account-a"
    );
    assert_eq!(report.created, 2);
    assert_eq!(report.verified, 2);
    assert!(!report.assumed_owners.iter().any(|id| id == "secret"));
    source.execute("UPDATE records SET owner_id='person-b' WHERE id='private'; UPDATE records SET owner_id=NULL WHERE id='secret'").await.unwrap();
    let report = run(f.options(&["secret"], true)).await.unwrap();
    assert!(report.review.is_empty());
    assert!(report.refusals.is_empty());
    assert_eq!(report.owner_overrides.len(), 1);
    assert_eq!(report.owner_overrides[0].record_id, "private");
    assert_eq!(report.created, 0);
    assert_eq!(report.verified, 2);
    let db = f.db().await;
    for id in ["private", "secret"] {
        assert!(k::read_record_as(&db, &report.principals["account-a"], id)
            .await
            .unwrap()
            .is_some());
        assert!(k::read_record_as(&db, &report.principals["account-b"], id)
            .await
            .unwrap()
            .is_none());
    }
    let evidence = snapshot_provenance_as(&db, &report.principals["account-a"], "private")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(evidence["original_owner"], "person-b");
    assert_eq!(
        evidence["owner_override"]["private_policy_account"],
        "account-a"
    );
    db.close().await;
    let retry = run(f.options(&["secret"], true)).await.unwrap();
    assert!(retry.review.is_empty());
    assert!(retry.refusals.is_empty());
    assert_eq!(retry.updated, 0);
    assert_eq!(retry.unchanged, 2);
    assert_eq!(retry.verified, 2);
    assert_eq!(retry.owner_overrides.len(), 1);
}

#[tokio::test]
async fn restricted_unknown_and_ambiguous_owners_never_gain_admin_access() {
    for empty in [false, true] {
        let f = Fixture::new().await;
        let mut source = SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
        )
        .await
        .unwrap();
        source.execute("INSERT INTO record_policies VALUES('task');
            INSERT INTO bindings VALUES('ambiguous','account','account-b',1),('ambiguous','account','account-c',1);
            UPDATE records SET policy_anchor_id='task',owner_id='ambiguous' WHERE id='task';").await.unwrap();
        if !empty {
            source.execute("INSERT INTO policy_entries VALUES('task','account','account-b','view'),('task','account','account-c','edit'); UPDATE records SET owner_id=NULL WHERE id='task'").await.unwrap();
        }
        let report = run(f.options(&["task"], false)).await.unwrap();
        assert!(report.review.iter().any(|i| i.id == "task"));
        assert!(!report.assumed_owners.iter().any(|id| id == "task"));
        let db = f.db().await;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_records WHERE id='task'")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
    // A replacement boundary that actually grants admin View admits the fallback.
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute("INSERT INTO record_policies VALUES('task');
        INSERT INTO policy_entries VALUES('task','account','account-a','view'),('task','account','account-b','view');
        UPDATE records SET policy_anchor_id='task',owner_id=NULL WHERE id='task'").await.unwrap();
    let report = run(f.options(&["task"], false)).await.unwrap();
    assert!(report.review.is_empty());
    assert!(report.refusals.is_empty());
    assert_eq!(report.verified, 2);
    assert_eq!(report.assumed_owners, ["task"]);
}

#[tokio::test]
async fn explicit_roster_required_and_verified_nonmembers_are_excluded() {
    let f = Fixture::new().await;
    let mut options = f.options(&["task"], false);
    options.members_file = None;
    let refused = run(options).await.unwrap();
    assert_eq!(refused.refusals.len(), 1);
    assert!(refused.refusals[0].reason.contains("--members-file"));
    assert!(!f.target.exists()); // Refusal precedes any target installation/commit.
    std::fs::write(&f.members, "account-a\naccount-without-binding\n").unwrap();
    let report = run(f.options(&["task"], false)).await.unwrap();
    assert!(report.refusals.is_empty());
    assert_eq!(report.verified, 2);
    assert_eq!(
        report.expanded_members,
        BTreeSet::from(["account-a".into(), "account-without-binding".into()])
    );
    assert_eq!(
        report.excluded_bound_accounts,
        BTreeSet::from(["account-b".into()])
    );
    let db = f.db().await;
    assert!(
        k::read_record_as(&db, &report.principals["account-b"], "task")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        k::read_record_as(&db, &report.principals["account-without-binding"], "task")
            .await
            .unwrap()
            .is_some()
    );
    // Unrelated members policies do not require a roster for the chosen subset.
    let other = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&other.source),
    )
    .await
    .unwrap();
    source.execute("DELETE FROM policy_entries WHERE policy_anchor_id='native:root' AND subject_kind='members'; INSERT INTO record_policies VALUES('outside'); INSERT INTO policy_entries VALUES('outside','members','native:members','view')").await.unwrap();
    let mut options = other.options(&["task"], false);
    options.members_file = None;
    assert!(run(options).await.unwrap().refusals.is_empty());
}

#[tokio::test]
async fn folder_child_seed_orders_have_identical_immutable_provenance() {
    for first_seeds in [vec!["folder"], vec!["task"]] {
        let f = Fixture::new().await;
        let first = run(f.options(&first_seeds, false)).await.unwrap();
        assert!(first.refusals.is_empty());
        let report = run(f.options(&["folder", "task"], true)).await.unwrap();
        assert!(report.refusals.is_empty());
        assert!(report.review.is_empty());
        assert_eq!(report.verified, 2);
        let db = f.db().await;
        let provenance = snapshot_provenance_as(&db, &report.principals["account-a"], "folder")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(provenance["derived_home"], derived("folder"));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id='folder' AND type='kernel.legacy_recorded.v1'")
            .fetch_one(db.write_pool()).await.unwrap();
        assert_eq!(count, 1);
    }
}

#[tokio::test]
async fn legacy_float_payload_retries_compare_stored_bytes_and_archive_time_survives() {
    let f = Fixture::new().await;
    let report = run(f.options(&["task", "archived"], false)).await.unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    let a = &report.principals["account-a"];
    let stamp = snapshot_provenance_as(&db, a, "archived")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stamp["archive_observed_at"], "2026-03-01T00:00:00Z");
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let mut event = k::LegacyEvent {
        source: None,
        id: "float-legacy-receipt".into(),
        event_type: "test.float".into(),
        created_at: "2026-01-01T00:00:00Z".into(),
        actor: None,
        run_key: None,
        payload: json!({"value": 0.845_512_408_225_570_1_f64}),
    };
    assert_eq!(
        k::import_event_as(&db, &host, "task", &event)
            .await
            .unwrap(),
        k::ImportResult::Created
    );
    assert_eq!(
        k::import_event_as(&db, &host, "task", &event)
            .await
            .unwrap(),
        k::ImportResult::Unchanged
    );
    event.payload = json!({"value": 0.9});
    assert!(k::import_event_as(&db, &host, "task", &event)
        .await
        .is_err());
    let history = k::facet_history_as(&db, a, "task", "score").await.unwrap();
    assert_eq!(
        history[0].observation.value_num,
        Some(0.845_512_408_225_570_1_f64)
    );
    assert!(run(f.options(&["task", "archived"], true))
        .await
        .unwrap()
        .refusals
        .is_empty());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_account_callers_resolve_through_kernel_v2_registry_and_bootstrap_is_ready() {
    use crate::mcp::registry::{Caller, EngineHandle, ToolRegistry};
    let f = Fixture::new().await;
    seed_instruction_bindings(&f).await;
    let report = run(f.options(&["task", "secret"], false)).await.unwrap();
    assert!(report.refusals.is_empty());
    let pending = &report.instruction_bindings;
    assert!(pending.source_table_present);
    assert_eq!(pending.total, 3);
    assert_eq!(pending.targets_in_subset, 2);
    assert_eq!(pending.created, 2);
    assert_eq!(pending.verified, 2);
    assert_eq!(pending.by_scope["database"], 1);
    assert_eq!(pending.by_scope["account"], 2);
    assert_eq!(pending.not_yet_imported.len(), 1);
    assert!(pending
        .not_yet_imported
        .iter()
        .any(|b| b.id == "binding-outside" && !b.enabled && !b.target_in_subset));
    let db = f.db().await;
    for (account, principal) in &report.principals {
        assert_eq!(
            k::resolve_principal_by_binding(&db, account)
                .await
                .unwrap()
                .unwrap()
                .0,
            *principal
        );
    }
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let result = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-a"),
            "get_record",
            json!({"ids":["task", "secret"]}),
        )
        .await
        .unwrap();
    assert_eq!(result["records"].as_array().unwrap().len(), 2);
    assert!(result["records"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["status"] == "found"));
    let bootstrap = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-a"),
            "bootstrap",
            json!({}),
        )
        .await
        .unwrap();
    assert_eq!(bootstrap["instructions"]["status"], "ready");
    assert_eq!(
        bootstrap["instructions"]["entries"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert!(bootstrap["instructions"]["diagnostics"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        bootstrap["instructions"]["entries"][0]["entry_id"],
        "binding-workspace"
    );
    assert_eq!(
        bootstrap["instructions"]["entries"][1]["entry_id"],
        "binding-member"
    );
    let hidden = registry
        .call_engine(
            EngineHandle::KernelV2(db),
            Caller::authenticated("account-b"),
            "get_record",
            json!({"ids":["secret"]}),
        )
        .await
        .unwrap();
    assert_eq!(hidden["records"][0]["status"], "not_found");
    assert!(hidden["records"][0].get("body").is_none());
}

#[tokio::test]
async fn frozen_roster_set_refuses_changes_before_root_or_folder_policy_writes() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source
        .execute(
            "INSERT INTO record_policies VALUES('folder');
        INSERT INTO policy_entries VALUES('folder','members','native:members','edit');
        UPDATE records SET policy_anchor_id='folder' WHERE id IN ('folder','task')",
        )
        .await
        .unwrap();
    let first = run(f.options(&["task"], false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(
        k::import_members_roster_as(&db, &first.principals["account-a"], None)
            .await
            .is_err()
    );
    assert!(crate::store::append(
        &db,
        crate::store::AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: "kernel.import_members_roster.v1".into(),
            payload: json!({"members":["account-c"]}),
            actor: Some(host),
        }
    )
    .await
    .is_err());
    // Order, duplicate lines and whitespace do not change the frozen set.
    std::fs::write(&f.members, " account-b\naccount-a\naccount-a\n").unwrap();
    let same = run(f.options(&["task"], true)).await.unwrap();
    assert!(same.refusals.is_empty());
    assert_eq!(same.unchanged, 2);
    let seals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.import_members_roster.v1'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(seals, 1);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    std::fs::write(&f.members, "account-a\naccount-c\n").unwrap();
    let changed = run(f.options(&["task"], true)).await.unwrap();
    assert_eq!(changed.refusals.len(), 1);
    assert_eq!(changed.created, 0);
    assert_eq!(changed.verified, 0);
    let difference = changed.roster_change.unwrap();
    assert_eq!(difference.added, BTreeSet::from(["account-c".into()]));
    assert_eq!(difference.removed, BTreeSet::from(["account-b".into()]));
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    assert_eq!(
        events,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    );
    assert!(k::resolve_principal_by_binding(&db, "account-c")
        .await
        .unwrap()
        .is_none());
    assert!(
        k::read_record_as(&db, &first.principals["account-b"], "task")
            .await
            .unwrap()
            .is_some()
    );
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn expanded_subset_can_require_and_freeze_its_first_roster() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute("DELETE FROM policy_entries WHERE policy_anchor_id='native:root' AND subject_kind='members';
        DELETE FROM policy_entries WHERE policy_anchor_id='private';
        INSERT INTO policy_entries VALUES('private','members','native:members','edit')").await.unwrap();
    let mut first = f.options(&["task"], false);
    first.members_file = None;
    let first = run(first).await.unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let mut missing = f.options(&["task", "secret"], true);
    missing.members_file = None;
    let missing = run(missing).await.unwrap();
    assert!(missing
        .refusals
        .iter()
        .any(|i| i.reason.contains("--members-file")));
    assert_eq!(
        events,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    );
    let expanded = run(f.options(&["task", "secret"], true)).await.unwrap();
    assert!(expanded.refusals.is_empty());
    assert_eq!(expanded.verified, 4);
    let seals: Vec<String> = sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_members_roster.v1' ORDER BY seq").fetch_all(db.write_pool()).await.unwrap();
    assert_eq!(seals.len(), 2);
    assert_eq!(
        serde_json::from_str::<Value>(&seals[0]).unwrap()["members"],
        Value::Null
    );
    assert_eq!(
        serde_json::from_str::<Value>(&seals[1]).unwrap()["members"],
        json!(["account-a", "account-b"])
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn pre_roster_policy_targets_refuse_instead_of_guessing_a_previous_roster() {
    let f = Fixture::new().await;
    // Reproduce an older target's source marker and policy setup, with no seal.
    let (db, admin) = k::create_v2_database(
        f.target.to_str().unwrap(),
        "account",
        "Administrator",
        "account-a",
    )
    .await
    .unwrap();
    k::create_principal(
        &db,
        "agent",
        "V1 import source",
        "v1:test-origin:import-source",
        &admin,
    )
    .await
    .unwrap();
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::import_home_policy_as(&db, &host, KERNEL_ROOT_ID, &[(&admin, "manage")])
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let report = run(f.options(&["task"], true)).await.unwrap();
    assert_eq!(report.refusals.len(), 1);
    assert!(report.refusals[0].reason.contains("recreate target"));
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    );
}

#[cfg(feature = "v2-kernel-probe")]
async fn ordinary_kernel_call(
    db: &Db,
    account: &str,
    tool: &str,
    args: Value,
) -> crate::Result<Value> {
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry)?;
    crate::mcp::tools::register_surface_tools(&mut registry)?;
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry)?;
    registry
        .call_engine(
            crate::mcp::registry::EngineHandle::KernelV2(db.clone()),
            crate::mcp::Caller::authenticated(account),
            tool,
            args,
        )
        .await
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_runtime_packages_support_ordinary_claims_and_resume() {
    let f = Fixture::new().await;
    let seeds = ["task", "secret"];
    let report = run(f.options(&seeds, false)).await.unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    let families: Vec<String> = sqlx::query_scalar(
        "SELECT family FROM kernel_adoptions WHERE scope_home=? ORDER BY family",
    )
    .bind(KERNEL_ROOT_ID)
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        families,
        vec![
            standard::claims_v1::FAMILY,
            "native.relationship.relates_to",
            standard::DOCUMENT_FAMILY,
            standard::v1_compat::FAMILY,
        ]
    );
    let adopted: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.package_adopted.v1'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    let boot = ordinary_kernel_call(&db, "account-a", "bootstrap", json!({}))
        .await
        .unwrap();
    let key = &boot["session"]["run_key"];
    let before_claim = k::read_record_as(&db, &report.principals["account-a"], "task")
        .await
        .unwrap()
        .unwrap()
        .metadata;
    let args = json!({"run_key":key,"record_id":"task","operation_key":"fixture-claim"});
    let claim = ordinary_kernel_call(&db, "account-a", "start_work", args.clone())
        .await
        .unwrap();
    assert_eq!(claim["claimed"], true);
    let claimed = k::read_record_as(&db, &report.principals["account-a"], "task")
        .await
        .unwrap()
        .unwrap()
        .metadata;
    assert_ne!(claimed.last_activity_at, before_claim.last_activity_at);
    assert_eq!(claimed.persistence, before_claim.persistence);
    assert_eq!(claimed.maturity, before_claim.maturity);
    let claim_time: String =
        sqlx::query_scalar("SELECT created_at FROM content_events WHERE seq=?")
            .bind(claim["head"].as_i64().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(claimed.last_activity_at, claim_time);
    let retry = ordinary_kernel_call(&db, "account-a", "start_work", args)
        .await
        .unwrap();
    assert_eq!(retry["receipt"], claim["receipt"]);
    assert_eq!(retry["changed"], false);
    assert_eq!(
        k::read_record_as(&db, &report.principals["account-a"], "task")
            .await
            .unwrap()
            .unwrap()
            .metadata,
        claimed
    );
    let release_args = json!({"run_key":key,"record_id":"task","action":"release","operation_key":"fixture-release",
        "expected_holder_run_key":key,"expected_generation":claim["generation"],"expected_head":claim["head"]});
    let release = ordinary_kernel_call(&db, "account-a", "start_work", release_args.clone())
        .await
        .unwrap();
    assert_eq!(release["claimed"], false);
    let released = k::read_record_as(&db, &report.principals["account-a"], "task")
        .await
        .unwrap()
        .unwrap()
        .metadata;
    let release_time: String =
        sqlx::query_scalar("SELECT created_at FROM content_events WHERE seq=?")
            .bind(release["receipt"]["event_seq"].as_i64().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(released.last_activity_at, release_time);
    let activity_seq: i64 =
        sqlx::query_scalar("SELECT event_seq FROM kernel_record_metadata WHERE record_id='task'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        activity_seq,
        release["receipt"]["event_seq"].as_i64().unwrap()
    );
    let resumed = run(f.options(&seeds, true)).await.unwrap();
    // Native claim activity differs from the frozen source; resume reports
    // that drift without overwriting the native clock.
    assert_eq!(resumed.refusals.len(), 1);
    assert_eq!(resumed.refusals[0].id, "task");
    assert_eq!(
        resumed.refusals[0].reason,
        "kernel read reconciliation mismatch"
    );
    assert_eq!(
        k::read_record_as(&db, &report.principals["account-a"], "task")
            .await
            .unwrap()
            .unwrap()
            .metadata,
        released
    );
    assert!(resumed.review.is_empty());
    let adopted_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.package_adopted.v1'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(adopted, adopted_after);
    db.close().await;
    let db = f.db().await;
    let retry = ordinary_kernel_call(&db, "account-a", "start_work", release_args)
        .await
        .unwrap();
    assert_eq!(retry["receipt"], release["receipt"]);
    assert_eq!(retry["changed"], false);
    ordinary_kernel_call(&db, "account-a", "close_run", json!({"run_key":key}))
        .await
        .unwrap();
    assert_eq!(
        k::read_record_as(&db, &report.principals["account-a"], "task")
            .await
            .unwrap()
            .unwrap()
            .metadata,
        released
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(k::dump_all_kernel_tables(&db).await.unwrap(), before);
    db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_editor_provenance_is_visible_legacy_metadata_with_actor_redaction() {
    let f = Fixture::new().await;
    let report = run(f.options(&["task", "epic", "note", "secret"], false))
        .await
        .unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    let read = ordinary_kernel_call(&db, "account-a", "get_record", json!({"ids":["task"]}))
        .await
        .unwrap();
    // The ordinary envelope must retain both snapshot provenance and generic links.
    assert!(read["records"][0]["links_out"]
        .as_array()
        .unwrap()
        .iter()
        .any(|link| link["id"] == "link-d"
            && link["relationship"] == "part_of"
            && link["target_id"] == "epic"));
    let legacy = &read["records"][0]["legacy_provenance"];
    assert_eq!(
        legacy,
        &json!({"kind":"v1.snapshot_provenance","creator":"v1:original-creator",
        "created_at":"2026-01-01T00:00:00Z","last_editor":"v1:last-editor","updated_at":"2026-02-01T00:00:00Z","actors_withheld":false})
    );
    assert_ne!(read["records"][0]["updated_at"], legacy["updated_at"]);
    let history = ordinary_kernel_call(
        &db,
        "account-a",
        "get_history",
        json!({"record_id":"task","limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(
        &history["legacy_provenance"], legacy,
        "snapshot metadata must survive history pagination"
    );
    for (tool, value) in [("get_record", &read), ("get_history", &history)] {
        let text = crate::mcp::render::render(tool, value).unwrap();
        assert!(text.contains("Imported v1 provenance (snapshot)"));
        assert!(text.contains("last editor: v1:last-editor"));
        assert!(text.contains("last edited at: 2026-02-01T00:00:00Z"));
    }
    ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"task","body_append":"native edit"}),
    )
    .await
    .unwrap();
    let after = ordinary_kernel_call(&db, "account-a", "get_record", json!({"ids":["task"]}))
        .await
        .unwrap();
    assert_eq!(&after["records"][0]["legacy_provenance"], legacy);
    let actor: String = sqlx::query_scalar(
        "SELECT actor FROM content_events WHERE record_id='task' ORDER BY seq DESC LIMIT 1",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(actor, report.principals["account-a"]);
    let native = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"WorkItem","kind":"task","name":"native control"}),
    )
    .await
    .unwrap();
    let native = ordinary_kernel_call(
        &db,
        "account-a",
        "get_record",
        json!({"ids":[native["id"]]}),
    )
    .await
    .unwrap();
    assert!(native["records"][0]["legacy_provenance"].is_null());
    let admin = &report.principals["account-a"];
    k::replace_home_policy(&db, admin, KERNEL_ROOT_ID, &[(admin, "manage")])
        .await
        .unwrap();
    let viewer = ordinary_kernel_call(
        &db,
        "account-b",
        "get_record",
        json!({"ids":["note","secret","missing"]}),
    )
    .await
    .unwrap();
    assert_eq!(viewer["records"][0]["status"], "found");
    let redacted = &viewer["records"][0]["legacy_provenance"];
    assert!(redacted["creator"].is_null());
    assert!(redacted["last_editor"].is_null());
    assert_eq!(redacted["updated_at"], "2026-02-01T00:00:00Z");
    assert_eq!(redacted["actors_withheld"], true);
    for index in [1, 2] {
        assert_eq!(viewer["records"][index]["status"], "not_found");
        assert!(viewer["records"][index].get("legacy_provenance").is_none());
    }
    let history =
        ordinary_kernel_call(&db, "account-b", "get_history", json!({"record_id":"note"}))
            .await
            .unwrap();
    assert_eq!(&history["legacy_provenance"], redacted);
    assert!(!history.to_string().contains("last-editor"));
    assert!(!history.to_string().contains("original-creator"));
    for id in ["secret", "missing"] {
        assert!(
            ordinary_kernel_call(&db, "account-b", "get_history", json!({"record_id":id}))
                .await
                .is_err()
        );
        assert!(
            legacy_record_provenance_as(&db, &report.principals["account-b"], id)
                .await
                .unwrap()
                .is_none()
        );
    }
    db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
async fn add_comment_fixture(f: &Fixture) {
    use sha2::{Digest, Sha256};
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute(
            "CREATE TABLE annotation_targets(annotation_id TEXT PRIMARY KEY,
             target_record_id TEXT,source_slot TEXT,source_event_seq INTEGER,
             blob_id TEXT,source_sha256 TEXT,selectors TEXT,purpose TEXT,
             created_at TEXT,updated_at TEXT)",
        )
        .await
        .unwrap();
    for (id, bearer, lifecycle, summary, body) in [
        (
            "c-root",
            "note",
            Some("open"),
            None::<&str>,
            "Root remark on the note.",
        ),
        (
            "c-reply",
            "c-root",
            None::<&str>,
            None::<&str>,
            "Reply to the root.",
        ),
    ] {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)")
            .bind(id)
            .bind("Annotation")
            .bind("comment")
            .bind(id)
            .bind(body)
            .bind("folder")
            .bind("person-b")
            .bind(lifecycle)
            .bind(summary)
            .bind("2026-01-04T00:00:00Z")
            .bind("2026-01-05T00:00:00Z")
            .bind(0)
            .bind(V1_ROOT)
            .execute(&mut source)
            .await
            .unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'record.created','{}','comment-author','2026-01-04T00:00:00Z'),(?,?,'record.updated','{}','last-editor','2026-01-05T00:00:00Z')")
            .bind(format!("created:{id}")).bind(id).bind(format!("edited:{id}")).bind(id).execute(&mut source).await.unwrap();
        add_fixture_link(
            f,
            &Link {
                id: format!("link-{id}"),
                source_id: id.into(),
                target_id: bearer.into(),
                relationship: "part_of".into(),
                note: None,
                created_at: "2026-01-04T00:00:00Z".into(),
            },
            Some("comment-author"),
        )
        .await;
    }
    let sha = format!("{:x}", Sha256::digest("body"));
    sqlx::query("INSERT INTO annotation_targets VALUES(?,?,?,?,?,?,?,?,?,?)")
        .bind("c-root")
        .bind("note")
        .bind("body")
        .bind(7_i64)
        .bind(Option::<String>::None)
        .bind(&sha)
        .bind(
            r#"[{"type":"text_quote","exact":"body"},{"type":"data_position","start":0,"end":4}]"#,
        )
        .bind("comment_context")
        .bind("2026-01-04T00:00:00Z")
        .bind("2026-01-04T00:00:00Z")
        .execute(&mut source)
        .await
        .unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
async fn add_cross_home_fixture(f: &Fixture) {
    use sha2::{Digest, Sha256};
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute(
            "CREATE TABLE IF NOT EXISTS annotation_targets(annotation_id TEXT PRIMARY KEY,
             target_record_id TEXT,source_slot TEXT,source_event_seq INTEGER,
             blob_id TEXT,source_sha256 TEXT,selectors TEXT,purpose TEXT,
             created_at TEXT,updated_at TEXT)",
        )
        .await
        .unwrap();
    // Comment home != bearer home in both directions: c-cross-a sits in the
    // open folder while its note lives in the private home; c-cross-b is
    // the reverse. c-orphan bears on a record that was never seeded.
    for (id, home, bearer, body, deleted_at) in [
        (
            "c-cross-a",
            "folder",
            "secret",
            "Cross remark on the secret.",
            None,
        ),
        (
            "c-cross-b",
            "private",
            "note",
            "Cross remark on the note.",
            None,
        ),
        ("c-orphan", "folder", "ghost", "Orphan remark.", None),
        (
            "c-deleted",
            "folder",
            "note",
            "Deleted remark.",
            Some("2026-01-06T00:00:00Z"),
        ),
    ] {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(id)
            .bind("Annotation")
            .bind("comment")
            .bind(id)
            .bind(body)
            .bind(home)
            .bind("person-b")
            .bind("open")
            .bind(Option::<&str>::None)
            .bind("2026-01-04T00:00:00Z")
            .bind("2026-01-05T00:00:00Z")
            .bind(0)
            .bind(V1_ROOT)
            .bind(deleted_at)
            .execute(&mut source)
            .await
            .unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'record.created','{}','comment-author','2026-01-04T00:00:00Z')")
            .bind(format!("created:{id}")).bind(id).execute(&mut source).await.unwrap();
        // A soft-deleted comment keeps its bearer link: the import must
        // still refuse it rather than resurrect it live.
        add_fixture_link(
            f,
            &Link {
                id: format!("link-{id}"),
                source_id: id.into(),
                target_id: bearer.into(),
                relationship: "part_of".into(),
                note: None,
                created_at: "2026-01-04T00:00:00Z".into(),
            },
            Some("comment-author"),
        )
        .await;
    }
    // A v1 fragment paired with a data position keeps its anchor on import.
    let sha = format!("{:x}", Sha256::digest("body"));
    sqlx::query("INSERT INTO annotation_targets VALUES(?,?,?,?,?,?,?,?,?,?)")
        .bind("c-cross-b")
        .bind("note")
        .bind("body")
        .bind(3_i64)
        .bind(Option::<String>::None)
        .bind(&sha)
        .bind(r#"[{"type":"text_quote","exact":"body"},{"type":"data_position","start":0,"end":4},{"type":"fragment","conforms_to":"https://www.rfc-editor.org/rfc/rfc7111","value":"row=1"}]"#)
        .bind("comment_context")
        .bind("2026-01-04T00:00:00Z")
        .bind("2026-01-04T00:00:00Z")
        .execute(&mut source)
        .await
        .unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_comment_homes_follow_bearers_and_dead_bearers_refuse() {
    use crate::mcp::registry::{Caller, EngineHandle, ToolRegistry};
    let f = Fixture::new().await;
    add_cross_home_fixture(&f).await;
    let seeds = [
        "secret",
        "note",
        "c-cross-a",
        "c-cross-b",
        "c-orphan",
        "c-deleted",
    ];
    let report = run(f.options(&seeds, false)).await.unwrap();
    assert_eq!(report.imported["Annotation/comment"], 2);
    assert_eq!(report.comment_anchors_imported, 1);
    assert_eq!(report.comment_anchors_verified, 1);
    assert!(report.refusals.iter().any(|issue| issue.id == "c-orphan"));
    // V1 cannot undelete: count the deleted comment without resurrecting it.
    assert!(report
        .counted
        .iter()
        .any(|issue| issue.id == "c-deleted" && issue.reason == "excluded_deleted"));
    assert!(!report.refusals.iter().any(|issue| issue.id == "c-deleted"));
    assert!(report.review.is_empty());
    let db = f.db().await;
    let admin = report.principals["account-a"].clone();
    let secret = k::read_record_as(&db, &admin, "secret")
        .await
        .unwrap()
        .unwrap();
    let note = k::read_record_as(&db, &admin, "note")
        .await
        .unwrap()
        .unwrap();
    // Placement follows the bearer, never the v1 home.
    assert_eq!(
        k::read_record_as(&db, &admin, "c-cross-a")
            .await
            .unwrap()
            .unwrap()
            .home_id,
        secret.home_id
    );
    assert_eq!(
        k::read_record_as(&db, &admin, "c-cross-b")
            .await
            .unwrap()
            .unwrap()
            .home_id,
        note.home_id
    );
    assert!(k::read_record_as(&db, &admin, "c-orphan")
        .await
        .unwrap()
        .is_none());
    assert!(k::read_record_as(&db, &admin, "c-deleted")
        .await
        .unwrap()
        .is_none());
    // The paired fragment anchor survives import verbatim.
    let anchor: k::comments_v2::CommentAnchor = sqlx::query_as(
        "SELECT annotation_id,target_record_id,source_slot,selectors,body_revision,body_revision_source,body_sha256,purpose,created_at,actor,event_seq FROM kernel_comment_anchors WHERE annotation_id='c-cross-b'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(anchor.body_revision_source, "v1_source_seq");
    assert!(anchor.selectors.contains("fragment"));
    // Thread listing honours the same derivation through ordinary tools.
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    async fn list(registry: &ToolRegistry, db: &Db, account: &str, id: &str) -> serde_json::Value {
        registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated(account),
                "get_record",
                serde_json::json!({"ids": [id], "include_comments": true}),
            )
            .await
            .unwrap()
    }
    // Visibility derives through the bearer chain in both directions — via
    // the ordinary read path, never the comment's own home or owner floor.
    // The member authors c-cross-a but cannot see its hidden terminal.
    let hidden_thread = list(&registry, &db, "account-b", "c-cross-a").await;
    assert_eq!(hidden_thread["records"][0]["status"], "not_found");
    let shown_thread = list(&registry, &db, "account-b", "c-cross-b").await;
    assert_eq!(shown_thread["records"][0]["status"], "found");
    let note_list = list(&registry, &db, "account-b", "note").await;
    assert_eq!(note_list["records"][0]["comment_count"], 1);
    assert_eq!(
        note_list["records"][0]["comments"][0]["body"],
        "Cross remark on the note."
    );
    let secret_list = list(&registry, &db, "account-b", "secret").await;
    assert_eq!(secret_list["records"][0]["status"], "not_found");
    let secret_seen = list(&registry, &db, "account-a", "secret").await;
    assert_eq!(secret_seen["records"][0]["comment_count"], 1);
    // The member authors c-cross-a but lost the note: the comment is hidden
    // on every path, not just get_record.
    let staged = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-b"),
            "query_sql",
            serde_json::json!({"sql": "SELECT id FROM records WHERE id IN ('c-cross-a','c-cross-b') ORDER BY id"}),
        )
        .await
        .unwrap();
    assert_eq!(
        staged["rows"],
        serde_json::json!([{"id": "c-cross-b"}]),
        "{staged:#}"
    );
    let sought = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-b"),
            "query_record",
            serde_json::json!({"steps": [{"step": "filter", "ids": ["c-cross-a", "c-cross-b"]}]}),
        )
        .await
        .unwrap();
    assert!(
        sought.to_string().contains("c-cross-b") && !sought.to_string().contains("c-cross-a"),
        "{sought:#}"
    );
    let links = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-b"),
            "manage_links",
            serde_json::json!({"action": "list", "record_id": "c-cross-a"}),
        )
        .await
        .unwrap();
    assert_eq!(links["returned"], 0, "{links:#}");
    db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_comment_thread_anchor_provenance_visibility_and_resume() {
    let f = Fixture::new().await;
    add_comment_fixture(&f).await;
    // The ordinary edge sorts before both bearer links. Its reply endpoint
    // becomes visible only after the complete thread has been installed.
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO links(id,source_id,target_id,relationship,note,created_at) VALUES('00-derived-reply','note','c-reply','derived_from','Synthetic source note.','2026-01-02T00:00:00Z')").await.unwrap();
    source.close().await.unwrap();
    let seeds = ["note", "c-root", "c-reply"];
    let first = run(f.options(&seeds, false)).await.unwrap();
    assert!(first.review.is_empty());
    assert!(first.refusals.is_empty());
    assert_eq!(first.imported["Annotation/comment"], 2);
    assert_eq!(first.comment_anchors_imported, 1);
    assert_eq!(first.comment_anchors_verified, 1);
    assert_eq!(first.links_by_relationship["derived_from"].created, 1);
    assert_eq!(first.links_by_relationship["derived_from"].verified, 1);
    let db = f.db().await;
    let b = &first.principals["account-b"];
    // Bearer links ride with their v1 ids and legacy provenance.
    let links = k::generic_links_as(&db, b, "c-root", false, Some("part_of"), None, 200)
        .await
        .unwrap()
        .links;
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].link_id, "link-c-root");
    assert_eq!(links[0].target_id, "note");
    assert_eq!(links[0].actor.as_deref(), Some("v1:comment-author"));
    // The anchor pins the v1 target revision, hash, and selectors.
    let anchor: k::comments_v2::CommentAnchor = sqlx::query_as(
        "SELECT annotation_id,target_record_id,source_slot,selectors,body_revision,body_revision_source,body_sha256,purpose,created_at,actor,event_seq FROM kernel_comment_anchors WHERE annotation_id='c-root'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(anchor.target_record_id, "note");
    assert_eq!(anchor.body_revision, 7);
    assert_eq!(anchor.purpose.as_deref(), Some("comment_context"));
    assert_eq!(anchor.actor.as_deref(), Some("v1:comment-author"));
    let selectors: Value = serde_json::from_str(&anchor.selectors).unwrap();
    assert_eq!(selectors[0]["exact"], "body");
    // Thread reads through the ordinary tools: roots on the note with the
    // anchored passage, the reply on the root with the root's context.
    let note = ordinary_kernel_call(
        &db,
        "account-b",
        "get_record",
        json!({"ids": ["note"], "include_comments": true}),
    )
    .await
    .unwrap();
    assert_eq!(note["records"][0]["comment_count"], 1);
    let root = &note["records"][0]["comments"][0];
    assert_eq!(root["body"], "Root remark on the note.");
    assert_eq!(root["lifecycle"], "open");
    assert_eq!(root["target"]["validation"]["status"], "current");
    let thread = ordinary_kernel_call(
        &db,
        "account-b",
        "get_record",
        json!({"ids": ["c-root"], "include_comments": true}),
    )
    .await
    .unwrap();
    assert_eq!(thread["records"][0]["comment_count"], 1);
    assert_eq!(
        thread["records"][0]["comments"][0]["body"],
        "Reply to the root."
    );
    assert_eq!(
        thread["records"][0]["comments"][0]["target"]["target_record_id"],
        "note"
    );
    // Resume replays nothing and verifies the same anchor.
    let retry = run(f.options(&seeds, true)).await.unwrap();
    assert!(retry.review.is_empty());
    assert!(retry.refusals.is_empty());
    assert_eq!(retry.comment_anchors_imported, 0);
    assert_eq!(retry.comment_anchors_verified, 1);
    assert_eq!(retry.links_by_relationship["derived_from"].unchanged, 1);
    assert_eq!(retry.links_by_relationship["derived_from"].verified, 1);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type LIKE 'kernel.comment_anchor%'",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(count, 1);
    // Replay rebuilds records, bearer links, and anchors exactly.
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    let after = k::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(before, after);
    assert_eq!(after.comment_anchors.len(), 1);
    db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_attachments_bytes_mcp_retry_privacy_and_replay() {
    use crate::mcp::registry::{Caller, EngineHandle};
    use sha2::{Digest, Sha256};
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute("CREATE TABLE blobs(id TEXT PRIMARY KEY,bytes BLOB,mime TEXT,size_bytes INTEGER,sha256 TEXT,original_filename TEXT,storage_tier TEXT,created_at TEXT)").await.unwrap();
    source.execute("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at) VALUES('empty-folder','Collection','folder','Empty',NULL,'folder','person-a',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root',NULL)").await.unwrap();
    for (id, home, policy, bytes, mime) in [
        (
            "text-attachment",
            "folder",
            V1_ROOT,
            b"hello attachment".as_slice(),
            "text/plain",
        ),
        (
            "binary-attachment",
            "folder",
            V1_ROOT,
            b"\x00\xff\x01".as_slice(),
            "application/octet-stream",
        ),
        (
            "hidden-attachment",
            "private",
            "private",
            b"secret bytes".as_slice(),
            "text/plain",
        ),
    ] {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at) VALUES(?,'Document','attachment',? ,NULL,?,'person-a',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,?,NULL)").bind(id).bind(id).bind(home).bind(policy).execute(&mut source).await.unwrap();
        sqlx::query("INSERT INTO blobs VALUES(?,?,?,?,?,?,'inline','2026-01-01T00:00:00Z')")
            .bind(format!("blob:{id}"))
            .bind(bytes)
            .bind(mime)
            .bind(bytes.len() as i64)
            .bind(hex::encode(Sha256::digest(bytes)))
            .bind(format!("{id}.dat"))
            .execute(&mut source)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO facet_values VALUES(?,'blob_ref',?,NULL,NULL,'2026-01-01T00:00:00Z')",
        )
        .bind(id)
        .bind(format!("blob:{id}"))
        .execute(&mut source)
        .await
        .unwrap();
        sqlx::query("INSERT INTO facet_observations VALUES(?,'blob_ref','2026-01-01T00:00:00Z',1)")
            .bind(id)
            .execute(&mut source)
            .await
            .unwrap();
        sqlx::query("INSERT INTO links VALUES(?,?,?,'part_of',NULL,'2026-01-01T00:00:00Z')")
            .bind(format!("link:{id}"))
            .bind(id)
            .bind(home)
            .execute(&mut source)
            .await
            .unwrap();
    }
    source.close().await.unwrap();
    let options = |resume| {
        let mut options = f.options(&[], resume);
        options.all = true;
        options
    };
    let report = run(options(false)).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{:?}",
        serde_json::to_value(&report).unwrap()
    );
    assert_eq!(report.imported["Document/attachment"], 3);
    let resumed = run(options(true)).await.unwrap();
    assert!(resumed.refusals.is_empty());
    let db = f.db().await;
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    for replay in [false, true] {
        if replay {
            k::replay_all_projections(&db).await.unwrap();
        }
        let call = |account: &'static str, tool: &'static str, args: Value| {
            registry.call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated(account),
                tool,
                args,
            )
        };
        let text = call(
            "account-a",
            "read_attachment",
            json!({"attachment_id":"text-attachment"}),
        )
        .await
        .unwrap();
        assert_eq!(text["content"], "hello attachment");
        assert_eq!(text["content_encoding"], "utf-8");
        assert_eq!(text["blob"]["id"], "blob:text-attachment");
        let mapped: String = sqlx::query_scalar(
            "SELECT sha256 FROM kernel_blob_handles WHERE handle='blob:text-attachment'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(mapped, text["blob"]["sha256"].as_str().unwrap());
        let binary = call(
            "account-a",
            "read_attachment",
            json!({"attachment_id":"binary-attachment"}),
        )
        .await
        .unwrap();
        assert_eq!(binary["content"], "AP8B");
        assert_eq!(binary["content_encoding"], "base64");
        let hidden = call(
            "account-b",
            "read_attachment",
            json!({"attachment_id":"hidden-attachment"}),
        )
        .await
        .unwrap_err()
        .to_string();
        let missing = call(
            "account-b",
            "read_attachment",
            json!({"attachment_id":"missing"}),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(hidden, missing);
        k::replace_home_policy(
            &db,
            &report.principals["account-a"],
            &report.homes["private"],
            &[
                (&report.principals["account-a"], "manage"),
                (&report.principals["account-b"], "view"),
            ],
        )
        .await
        .unwrap();
        let revealed = call(
            "account-b",
            "read_attachment",
            json!({"attachment_id":"hidden-attachment"}),
        )
        .await
        .unwrap();
        assert_eq!(revealed["content"], "secret bytes");
        let view_only = call(
            "account-b",
            "attach_text",
            json!({"record_id":"hidden-attachment","text":"view is insufficient"}),
        )
        .await;
        assert!(view_only.is_err());
        k::replace_home_policy(
            &db,
            &report.principals["account-a"],
            &report.homes["private"],
            &[(&report.principals["account-a"], "manage")],
        )
        .await
        .unwrap();
        assert_eq!(
            call(
                "account-b",
                "read_attachment",
                json!({"attachment_id":"hidden-attachment"})
            )
            .await
            .unwrap_err()
            .to_string(),
            missing
        );

        let args = json!({"record_id":"empty-folder","text":"new bytes","filename":"new.txt","idempotency_key":"new-attachment"});
        let first = call("account-a", "attach_text", args.clone())
            .await
            .unwrap();
        let retry = call("account-a", "attach_text", args).await.unwrap();
        assert_eq!(first, retry);
        let read = call(
            "account-a",
            "read_attachment",
            json!({"attachment_id":first["attachment_id"]}),
        )
        .await
        .unwrap();
        assert_eq!(read["content"], "new bytes");
        let record = call(
            "account-a",
            "get_record",
            json!({"ids":[first["attachment_id"]]}),
        )
        .await
        .unwrap();
        assert_eq!(record["records"][0]["kind"], "attachment");
        assert_eq!(record["records"][0]["blob"]["original_filename"], "new.txt");
        let inspected = call(
            "account-a",
            "manage_attachments",
            json!({"action":"inspect","attachment_id":first["attachment_id"]}),
        )
        .await
        .unwrap();
        assert_eq!(inspected["blob"], first["blob"]);
        let listed = call(
            "account-a",
            "manage_attachments",
            json!({"action":"list","record_id":"empty-folder"}),
        )
        .await
        .unwrap();
        assert!(listed["attachments"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["attachment_id"] == first["attachment_id"]
                && a["blob_id"] == first["blob"]["id"]));
        let range = call(
            "account-a",
            "read_attachment",
            json!({"attachment_id":"binary-attachment","offset":1,"length":1}),
        )
        .await
        .unwrap();
        assert_eq!(range["content"], "/w==");
        assert_eq!(range["eof"], false);
        let failed=call("account-a","attach_text",json!({"record_id":"text-attachment","text":"rollback bytes","facets":{"blob_ref":"forged"}})).await;
        assert!(failed.is_err());
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let denied = call(
            "account-b",
            "attach_text",
            json!({"record_id":"hidden-attachment","text":"denied bytes"}),
        )
        .await;
        assert!(denied.is_err());
        assert_eq!(
            events,
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap()
        );
        let conflict=call("account-a","attach_text",json!({"record_id":"empty-folder","text":"changed","filename":"new.txt","idempotency_key":"new-attachment"})).await.unwrap_err().to_string();
        assert!(conflict.contains("different request"));
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kernel_blobs")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        4
    );
    // Owning a bearer confers Edit even when its home grants only View.
    k::replace_home_policy(
        &db,
        &report.principals["account-a"],
        KERNEL_ROOT_ID,
        &[
            (&report.principals["account-a"], "manage"),
            (&report.principals["account-b"], "view"),
        ],
    )
    .await
    .unwrap();
    let owned=registry.call_engine(EngineHandle::KernelV2(db.clone()),Caller::authenticated("account-b"),"attach_text",json!({"record_id":"note","text":"owned bearer bytes","idempotency_key":"owned-bearer"})).await.unwrap();
    let read = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("account-b"),
            "read_attachment",
            json!({"attachment_id":owned["attachment_id"]}),
        )
        .await
        .unwrap();
    assert_eq!(read["content"], "owned bearer bytes");
    k::replace_home_policy(
        &db,
        &report.principals["account-a"],
        KERNEL_ROOT_ID,
        &[
            (&report.principals["account-a"], "manage"),
            (&report.principals["account-b"], "edit"),
        ],
    )
    .await
    .unwrap();
    // Corrupt source checksums cannot replace verified target bytes on resume.
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source
        .execute("UPDATE blobs SET sha256='wrong' WHERE id='blob:text-attachment'")
        .await
        .unwrap();
    source.close().await.unwrap();
    let refused = run(options(true)).await.unwrap();
    assert!(!refused.refusals.is_empty());
}

#[tokio::test]
async fn all_requires_a_roster_before_creating_the_target() {
    let f = Fixture::new().await;
    let mut options = f.options(&[], false);
    options.all = true;
    options.members_file = None;
    let report = run(options).await.unwrap();
    assert_eq!(report.refusals.len(), 1);
    assert_eq!(
        report.refusals[0].reason,
        "full import requires --members-file from the live hosted roster"
    );
    assert!(!f.target.exists());
}

#[tokio::test]
async fn all_selects_unseeded_records_bindings_and_accounts_for_dangling_links() {
    let f = Fixture::new().await;
    seed_instruction_bindings(&f).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE instruction_bindings SET source_record_id='archived' WHERE id='binding-outside';
        INSERT INTO links VALUES('dangling','missing-a','missing-b','part_of',NULL,'2026-01-01T00:00:00Z')").await.unwrap();
    let mut options = f.options(&[], false);
    options.all = true;
    let first = run(options).await.unwrap();
    assert!(first.refusals.is_empty());
    assert!(first.review.is_empty());
    assert_eq!(first.created, 7);
    assert_eq!(first.verified, 7);
    assert_eq!(first.instruction_bindings.total, 3);
    assert_eq!(first.instruction_bindings.created, 3);
    assert_eq!(first.instruction_bindings.verified, 3);
    assert_eq!(first.instruction_bindings.standing_targets_added, 0);
    assert!(first.instruction_bindings.not_yet_imported.is_empty());
    assert_eq!(first.links_by_relationship["part_of"].imported, 1);
    assert_eq!(first.links_by_relationship["relates_to"].imported, 2);
    assert_eq!(first.skipped_links["endpoint_missing_from_source"], 2);
    let db = f.db().await;
    assert!(
        k::read_record_as(&db, &first.principals["account-b"], "secret")
            .await
            .unwrap()
            .is_none()
    );
    db.close().await;
    let mut options = f.options(&[], true);
    options.all = true;
    let second = run(options).await.unwrap();
    assert_eq!(second.created, 0);
    assert_eq!(second.unchanged, 7);
    assert_eq!(second.verified, 7);
    assert_eq!(second.instruction_bindings.unchanged, 3);
    assert_eq!(second.skipped_links["endpoint_missing_from_source"], 2);
    assert!(second.review.is_empty());
    assert!(second.refusals.is_empty());
}

#[tokio::test]
async fn reviewed_homes_quarantine_dependents_without_blocking_unrelated_records() {
    let f = Fixture::new().await;
    seed_instruction_bindings(&f).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute(
            "UPDATE records SET owner_id=NULL WHERE id='private';
        UPDATE records SET owner_id='person-b' WHERE id='secret';
        UPDATE policy_entries SET subject_id='account-b' WHERE policy_anchor_id='private';
        INSERT INTO policy_entries VALUES('private','account','account-c','view');
        UPDATE records SET home_id='private' WHERE id='folder';
        UPDATE records SET home_id='native:root' WHERE id='epic'",
        )
        .await
        .unwrap();
    for resume in [false, true] {
        let mut options = f.options(&[], resume);
        options.all = true;
        let report = run(options).await.unwrap();
        assert_eq!(report.created, usize::from(!resume));
        assert_eq!(report.unchanged, usize::from(resume));
        assert_eq!(report.verified, 1);
        assert_eq!(report.homes.len(), 1);
        let reviewed: BTreeSet<_> = report
            .review
            .iter()
            .map(|issue| issue.id.as_str())
            .collect();
        assert_eq!(
            reviewed,
            BTreeSet::from(["private", "secret", "folder", "task", "note", "archived"])
        );
        assert!(report.review.iter().any(|issue| issue.id == "private"
            && issue.reason == "unknown or ambiguous owner: workspace administrator cannot view the source record"));
        for dependent in ["secret", "folder", "task", "note", "archived"] {
            assert!(report.review.iter().any(|issue| issue.id == dependent
                && issue.reason == "home requires ownership review: private"));
        }
        assert_eq!(report.instruction_bindings.verified, 1);
        assert_eq!(report.instruction_bindings.not_yet_imported.len(), 2);
        assert_eq!(report.instruction_bindings.refused, 2);
        assert_eq!(report.skipped_links["endpoint_outside_imported_subset"], 3);
        assert_eq!(report.skipped_links["endpoint_missing_from_source"], 1);
        let db = f.db().await;
        let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM kernel_records ORDER BY id")
            .fetch_all(db.write_pool())
            .await
            .unwrap();
        assert_eq!(ids, vec!["epic"]);
        let homes: Vec<String> =
            sqlx::query_scalar("SELECT root_id FROM kernel_roots ORDER BY root_id")
                .fetch_all(db.write_pool())
                .await
                .unwrap();
        assert_eq!(homes, vec![KERNEL_ROOT_ID]);
        for principal in report.principals.values() {
            for id in &reviewed {
                assert!(k::read_record_as(&db, principal, id)
                    .await
                    .unwrap()
                    .is_none());
            }
        }
        db.close().await;
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_w1_metadata_notes_and_nonfinite_home_facets_preserve_state_on_resume() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE records SET persistence='occurrent',maturity='draft',last_activity_at='2025-12-31T12:34:56Z' WHERE id='task';
        UPDATE records SET summary='note summary',lifecycle='published',maturity='accepted' WHERE id='note';
        INSERT INTO facet_values VALUES('folder','overflow','1e999',NULL,NULL,'2026-01-01T00:00:00Z');
        INSERT INTO facet_observations VALUES('folder','overflow','2026-02-02T00:00:00Z',3)").await.unwrap();
    sqlx::query("UPDATE facet_values SET value_num=? WHERE record_id='folder' AND key='overflow'")
        .bind(f64::INFINITY)
        .execute(&mut source)
        .await
        .unwrap();
    let first = run(f.options(&["task", "note"], false)).await.unwrap();
    assert!(first.refusals.is_empty());
    assert!(first.review.is_empty());
    assert_eq!(first.metadata_coverage.persistence, 3);
    assert_eq!(first.metadata_coverage.last_activity_at, 3);
    assert_eq!(first.metadata_coverage.maturity, 2);
    assert_eq!(first.metadata_coverage.note_summary, 1);
    assert_eq!(first.metadata_coverage.note_lifecycle, 1);
    assert_eq!(first.nonfinite_facets.len(), 1);
    assert_eq!(first.nonfinite_facets[0].record_id, "folder");
    let db = f.db().await;
    let admin = &first.principals["account-a"];
    let task = k::read_record_as(&db, admin, "task")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        task.metadata,
        k::RecordMetadata {
            persistence: "occurrent".into(),
            maturity: Some("draft".into()),
            last_activity_at: "2025-12-31T12:34:56Z".into()
        }
    );
    assert_eq!(task.home_id, k::v1_import_home_id("folder"));
    assert_eq!(
        placement_as(&db, admin, "task")
            .await
            .unwrap()
            .unwrap()
            .home_id
            .as_deref(),
        Some("folder")
    );
    let note = k::read_record_as(&db, admin, "note")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(note.pin.unwrap().version, 4);
    assert_eq!(note.fields["summary"], "note summary");
    assert_eq!(note.fields["lifecycle"], "published");
    let facet = k::facets_as(&db, admin, "folder")
        .await
        .unwrap()
        .into_iter()
        .find(|f| f.key == "overflow")
        .unwrap();
    assert_eq!(facet.value.as_deref(), Some("1e999"));
    assert_eq!(facet.value_num, None);
    let retry = run(f.options(&["task", "note"], true)).await.unwrap();
    assert!(retry.refusals.is_empty());
    assert!(retry.review.is_empty());
    assert_eq!(retry.created, 0);
    assert_eq!(retry.nonfinite_facets.len(), 1);
    assert_eq!(
        k::read_record_as(&db, admin, "task")
            .await
            .unwrap()
            .unwrap(),
        task
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(k::dump_all_kernel_tables(&db).await.unwrap(), before);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_w1_admission_errors_keep_kernel_diagnostics_and_redact_content() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("UPDATE records SET persistence='not-a-mode' WHERE id='task'")
        .await
        .unwrap();
    let report = run(f.options(&["task"], false)).await.unwrap();
    let reason = &report
        .refusals
        .iter()
        .find(|r| r.id == "task")
        .unwrap()
        .reason;
    assert!(
        reason.contains("persistence must be enduring or occurrent"),
        "{reason}"
    );
    let record: Record = sqlx::query_as("SELECT * FROM records WHERE id='task'")
        .fetch_one(&mut source)
        .await
        .unwrap();
    let secret = "A synthetic confidential title";
    let mut record = record;
    record.name = secret.into();
    let error = format!("field validation refused: {secret}");
    assert_eq!(
        redact_record_error(&error, &record, &k::ImportRecordState::default()),
        "field validation refused: [redacted]"
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_w1_registry_home_and_metadata_match_sql_without_hidden_folder_disclosure() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    // Existing private policy moves to B. A owns the child, with a source
    // replacement anchor at root; the logical folder remains hidden from A.
    private_policy_for_b(&mut source).await;
    source
        .execute(
            "UPDATE records SET owner_id='person-b' WHERE id='private';
        UPDATE records SET owner_id='person-a',policy_anchor_id='native:root' WHERE id='secret'",
        )
        .await
        .unwrap();
    let report = run(f.options(&["task", "secret"], false)).await.unwrap();
    assert!(report.refusals.is_empty());
    assert!(report.review.is_empty());
    let db = f.db().await;
    for (account, id, expected) in [
        ("account-a", "task", Some("folder")),
        ("account-a", "secret", None),
        ("account-b", "secret", Some("private")),
        ("account-b", "private", Some(V1_ROOT)),
    ] {
        let read = ordinary_kernel_call(&db, account, "get_record", json!({"ids":[id]}))
            .await
            .unwrap();
        let sql=ordinary_kernel_call(&db,account,"query_sql",json!({"sql":format!("SELECT home_id,persistence,maturity,last_activity_at FROM records WHERE id='{id}'")})).await.unwrap();
        assert_eq!(read["records"][0]["status"], "found");
        assert_eq!(
            read["records"][0]["home_id"],
            serde_json::to_value(expected).unwrap()
        );
        let query = ordinary_kernel_call(
            &db,
            account,
            "query_record",
            json!({"steps":[{"step":"filter","ids":[id]}],"limit":1}),
        )
        .await
        .unwrap();
        assert_eq!(
            query["records"][0]["home_id"],
            read["records"][0]["home_id"]
        );
        for key in ["home_id", "persistence", "maturity", "last_activity_at"] {
            assert_eq!(
                read["records"][0][key], sql["rows"][0][key],
                "{account} {id} {key}"
            );
        }
    }
    // Both read surfaces must yield a home that ordinary writes can reuse.
    for tool in ["get_record", "query_sql", "query_record"] {
        let result = ordinary_kernel_call(
            &db,
            "account-a",
            tool,
            match tool {
                "get_record" => json!({"ids":["task"]}),
                "query_sql" => json!({"sql":"SELECT home_id FROM records WHERE id='task'"}),
                _ => json!({"steps":[{"step":"filter","ids":["task"]}],"limit":1}),
            },
        )
        .await
        .unwrap();
        let home = if tool == "query_sql" {
            &result["rows"][0]["home_id"]
        } else {
            &result["records"][0]["home_id"]
        };
        let created = ordinary_kernel_call(
            &db,
            "account-a",
            "create_record",
            json!({"type":"WorkItem","kind":"task","home_id":home}),
        )
        .await
        .unwrap();
        let id = created["id"].as_str().unwrap();
        assert_eq!(
            k::read_record_as(&db, &report.principals["account-a"], id)
                .await
                .unwrap()
                .unwrap()
                .home_id,
            derived("folder")
        );
    }
    for (account, home, expected) in [
        ("account-a", derived("folder"), derived("folder")),
        ("account-b", "private".to_owned(), derived("private")),
        ("account-b", V1_ROOT.to_owned(), KERNEL_ROOT_ID.to_owned()),
        (
            "account-b",
            KERNEL_ROOT_ID.to_owned(),
            KERNEL_ROOT_ID.to_owned(),
        ),
    ] {
        let created = ordinary_kernel_call(
            &db,
            account,
            "create_record",
            json!({"type":"Document","kind":"note","home_id":home}),
        )
        .await
        .unwrap();
        assert_eq!(
            k::read_record_as(
                &db,
                &report.principals[account],
                created["id"].as_str().unwrap()
            )
            .await
            .unwrap()
            .unwrap()
            .home_id,
            expected
        );
    }
    let denied = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"Document","kind":"note","home_id":"private"}),
    )
    .await
    .unwrap_err();
    let missing = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"Document","kind":"note","home_id":"missing-folder"}),
    )
    .await
    .unwrap_err();
    assert_eq!(denied.to_string(), missing.to_string());
    let attachment = ordinary_kernel_call(
        &db,
        "account-a",
        "attach_text",
        json!({"record_id":"folder","text":"Synthetic attachment"}),
    )
    .await
    .unwrap();
    assert_eq!(
        k::read_record_as(
            &db,
            &report.principals["account-a"],
            attachment["attachment_id"].as_str().unwrap()
        )
        .await
        .unwrap()
        .unwrap()
        .home_id,
        derived("folder")
    );
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"folder","persistence":"occurrent","reason":"invalid folder"})
    )
    .await
    .is_err());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_full_history_resumes_preserves_envelopes_and_current_state() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("ALTER TABLE content_events ADD COLUMN run_key TEXT;
        ALTER TABLE content_events ADD COLUMN act INTEGER;
        INSERT INTO content_events(id,record_id,type,payload,actor,created_at,run_key,act) VALUES
        ('body-old','task','record.updated','{ \"body\": \"old\" }','writer','2026-02-02T00:00:00Z','old-run',42),
        ('facet-set','task','facet.set','{\"key\":\"score\",\"value\":\"old\"}','writer','2026-02-03T00:00:00Z',NULL,43),
        ('facet-unset','task','facet.unset','{\"key\":\"score\"}',NULL,'2026-02-04T00:00:00Z',NULL,44),
        ('archive-old','archived','record.archived','{}','archiver','2026-03-01T00:00:00Z',NULL,45);
        CREATE TABLE policy_events(seq INTEGER PRIMARY KEY,id TEXT,record_id TEXT,type TEXT,payload TEXT,actor TEXT,created_at TEXT,act INTEGER);
        INSERT INTO policy_events VALUES(1,'old-policy','native:root','policy.replaced','{\"entries\":[]}','policy-writer','2026-01-01T00:00:00Z',1);
        DROP TABLE control_events; CREATE TABLE control_events(seq INTEGER PRIMARY KEY,id TEXT,type TEXT,payload TEXT,actor TEXT,run_key TEXT,created_at TEXT,act INTEGER);
        INSERT INTO control_events VALUES(1,'old-control','agent_run.started.v1','{}','runner','old-run','2026-01-01T00:00:00Z',2);").await.unwrap();
    source.execute("ALTER TABLE relationship_events ADD COLUMN act INTEGER; UPDATE relationship_events SET act=43;").await.unwrap();
    let first = run(f.options(&["task", "epic", "archived"], false))
        .await
        .unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    let admin = &first.principals["account-a"];
    let before = k::read_record_as(&db, admin, "task")
        .await
        .unwrap()
        .unwrap();
    let body = before.body.clone();
    let facets = k::facets_as(&db, admin, "task").await.unwrap();
    let mut options = f.options(&["task", "epic", "archived"], true);
    options.history = true;
    source
        .execute("UPDATE content_events SET payload='invalid-json' WHERE id='facet-unset'")
        .await
        .unwrap();
    assert!(run(options).await.is_err());
    source
        .execute("UPDATE content_events SET payload='{\"key\":\"score\"}' WHERE id='facet-unset'")
        .await
        .unwrap();
    let mut options = f.options(&["task", "epic", "archived"], true);
    options.history = true;
    let report = run(options).await.unwrap();
    assert!(report.history.streams["content_events"].unchanged > 0);
    assert!(report.history.streams["content_events"].created > 0);
    assert!(report.refusals.is_empty());
    assert_eq!(report.history.streams["policy_events"].verified, 1);
    assert_eq!(report.history.streams["relationship_events"].verified, 1);
    assert_eq!(report.history.streams["control_events"].verified, 1);
    let page = crate::mcp::kernel_v2::get_history(
        &db,
        admin,
        json!({"record_id":"task","detail":"full","limit":1000}),
    )
    .await
    .unwrap();
    let legacy: Vec<_> = page["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["legacy_interpretation"] == true && e["id"] != "relationship-created")
        .collect();
    type SourceEvent = (String, String, Option<String>, String, Option<String>);
    let originals: Vec<SourceEvent> = sqlx::query_as("SELECT id,type,actor,created_at,payload FROM content_events WHERE record_id='task' ORDER BY COALESCE(act,0),created_at,seq").fetch_all(&mut source).await.unwrap();
    assert_eq!(legacy.len(), originals.len());
    for (event, (id, typ, actor, time, payload)) in legacy.iter().zip(originals) {
        assert_eq!(event["id"], id);
        assert_eq!(event["type"], typ);
        assert_eq!(event["actor"], json!(actor.map(|a| format!("v1:{a}"))));
        assert_eq!(event["created_at"], time);
        let stored: String = sqlx::query_scalar(
            "SELECT json_extract(payload,'$.legacy.payload') FROM content_events WHERE id=?",
        )
        .bind(&id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&stored).unwrap(),
            serde_json::from_str::<Value>(payload.as_deref().unwrap()).unwrap()
        );
        assert!(event.get("legacy_source").is_none());
    }
    let old = legacy.iter().find(|e| e["id"] == "body-old").unwrap();
    assert_eq!(old["payload"]["body"], "old");
    assert_eq!(old["run_key"], "old-run");
    let source_metadata: i64 = sqlx::query_scalar("SELECT json_extract(payload,'$.legacy.source.metadata.act') FROM content_events WHERE id='body-old'").fetch_one(db.write_pool()).await.unwrap();
    assert_eq!(source_metadata, 42);
    let other = crate::mcp::kernel_v2::get_history(
        &db,
        admin,
        json!({"record_id":"epic","detail":"full","limit":1000}),
    )
    .await
    .unwrap();
    assert!(other["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == "relationship-created"));
    let all = page["events"].as_array().unwrap();
    let position = |id: &str| all.iter().position(|e| e["id"] == id).unwrap();
    assert!(position("body-old") < position("relationship-created"));
    assert!(position("relationship-created") < position("facet-unset"));
    let newest = crate::mcp::kernel_v2::get_history(
        &db,
        admin,
        json!({"record_id":"task","order":"newest_first","limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(newest["events"][0]["id"], "facet-unset");
    let next = crate::mcp::kernel_v2::get_history(&db, admin, json!({"record_id":"task","order":"newest_first","limit":1,"after_local_seq":newest["next_after_local_seq"]})).await.unwrap();
    assert_eq!(next["events"][0]["id"], "facet-set");
    let after = k::read_record_as(&db, admin, "task")
        .await
        .unwrap()
        .unwrap();
    assert!(after.revision > before.revision);
    assert_eq!(after.fields, before.fields);
    assert_eq!(after.archived, before.archived);
    assert_eq!(after.body, body);
    assert_eq!(k::facets_as(&db, admin, "task").await.unwrap(), facets);
    let mut options = f.options(&["task", "epic", "archived"], true);
    options.history = true;
    let resumed = run(options).await.unwrap();
    for counts in resumed.history.streams.values() {
        assert_eq!(counts.created, 0);
        assert_eq!(counts.unchanged, counts.verified);
    }
    let projected: Vec<(String, i64)> =
        sqlx::query_as("SELECT subject_id,seq FROM kernel_legacy_subjects ORDER BY subject_id,seq")
            .fetch_all(db.write_pool())
            .await
            .unwrap();
    assert!(!projected.is_empty());
    let dump = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(k::dump_all_kernel_tables(&db).await.unwrap(), dump);
    assert_eq!(
        sqlx::query_as::<_, (String, i64)>(
            "SELECT subject_id,seq FROM kernel_legacy_subjects ORDER BY subject_id,seq"
        )
        .fetch_all(db.write_pool())
        .await
        .unwrap(),
        projected
    );
    assert_eq!(
        crate::mcp::kernel_v2::get_history(
            &db,
            admin,
            json!({"record_id":"task","detail":"full","limit":1000})
        )
        .await
        .unwrap(),
        page
    );
    // An interrupted pass resumes: one already committed event is unchanged,
    // and changed source bytes refuse rather than silently replacing history.
    source
        .execute("UPDATE content_events SET payload='{\"body\":\"changed\"}' WHERE id='body-old'")
        .await
        .unwrap();
    let mut options = f.options(&["task", "epic", "archived"], true);
    options.history = true;
    assert!(run(options).await.is_err());
    // The row digest detects spelling changes even with an identical parsed
    // payload, without retaining a second escaped payload copy.
    source
        .execute(r#"UPDATE content_events SET payload='{"body":"old"}' WHERE id='body-old'"#)
        .await
        .unwrap();
    let mut options = f.options(&["task", "epic", "archived"], true);
    options.history = true;
    assert!(run(options).await.is_err());
    // Removing a subject's entire source stream must also refuse: checking
    // only anchors still present in the source would overlook these old IDs.
    sqlx::query("UPDATE content_events SET payload=? WHERE id='body-old'")
        .bind("{ \"body\": \"old\" }")
        .execute(&mut source)
        .await
        .unwrap();
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let imported: BTreeSet<String> = sqlx::query_scalar("SELECT id FROM kernel_records")
        .fetch_all(db.write_pool())
        .await
        .unwrap()
        .into_iter()
        .collect();
    history::import(
        &mut source,
        &db,
        &host,
        "test-origin",
        history::Scope {
            imported: imported.clone(),
            selected: imported.clone(),
            homes: &report.homes,
            all: false,
        },
        &mut history::HistoryReport::default(),
    )
    .await
    .unwrap();
    sqlx::query("DELETE FROM content_events WHERE record_id='archived'")
        .execute(&mut source)
        .await
        .unwrap();
    assert!(history::import(
        &mut source,
        &db,
        &host,
        "test-origin",
        history::Scope {
            imported: imported.clone(),
            selected: imported,
            homes: &report.homes,
            all: false,
        },
        &mut history::HistoryReport::default()
    )
    .await
    .is_err());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_history_redacts_attribution_and_hides_other_endpoints() {
    let f = Fixture::new().await;
    add_comment_fixture(&f).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('hidden-old-link','task','link.added','{\"source_id\":\"task\",\"target_id\":\"secret\"}','secret-writer','2026-01-01T00:00:00Z')").await.unwrap();
    source.execute(r#"INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('unselected-source-link','epic','link.added','{"source_id":"epic","target_id":"task"}','writer','2026-01-01T00:00:00Z')"#).await.unwrap();
    source.execute(r#"INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES
        ('visible-unanchored-comment','task','record.updated','{"target_record_id":"c-root"}','account-b','2026-01-01T00:00:00Z'),
        ('identity-old','task','record.updated','{"email":"private@example.test","account_id":"account-a","actor":"private-actor","owner_id":"person-a","nested":{"id":"missing","owner":"missing","home":"missing"}}','account-a','2026-01-01T00:00:00Z'),
        ('hidden-annotation','task','attribution.target_bound','{"target_record_id":"secret","selectors":[{"quote":"secret"}]}','account-a','2026-01-01T00:00:00Z'),
        ('hidden-occurrence','task','occurrence.bound.v1','{"artefact_revision":{"subject_id":"secret"},"selectors":[{"quote":"secret"}]}','account-a','2026-01-01T00:00:00Z'),
        ('visible-occurrence','task','occurrence.bound.v1','{"artefact_revision":{"subject_id":"task"},"selectors":[]}','account-a','2026-01-01T00:00:00Z'),
        ('hidden-type','task','reconciliation.recorded.v1','{}','account-a','2026-01-01T00:00:00Z'),
        ('claim-old','task','record.updated','{"claimed_by_account":"account-a","claimed_run_key":"private-run"}','account-a','2026-01-01T00:00:00Z');
        DROP TABLE control_events; CREATE TABLE control_events(seq INTEGER PRIMARY KEY,id TEXT,type TEXT,payload TEXT,actor TEXT,run_key TEXT,created_at TEXT);
        INSERT INTO control_events VALUES
        (1,'config-other','account_config.updated.v1','{"account_id":"account-a","config_record_id":"task"}','account-a',NULL,'2026-01-01T00:00:00Z'),
        (2,'run-other','agent_run.started.v1','{"account_id":"account-a"}','account-a','private-run','2026-01-01T00:00:00Z'),
        (3,'config-own','account_config.updated.v1','{"account_id":"account-b","email":"private@example.test"}','account-b',NULL,'2026-01-01T00:00:00Z'),
        (4,'run-own','agent_run.started.v1','{"account_id":"account-b"}','account-b','own-run','2026-01-01T00:00:00Z'),
        (5,'empty-unknown','relationship.updated.v1','{}',NULL,NULL,'2026-01-01T00:00:00Z'),
        (6,'instruction-other','instruction_binding.changed','{"scope_kind":"account","scope_id":"account-a","source_record_id":"task"}','account-b',NULL,'2026-01-01T00:00:00Z'),
        (7,'instruction-own','instruction_binding.changed','{"scope_kind":"account","scope_id":"account-b","source_record_id":"task"}','account-a',NULL,'2026-01-01T00:00:00Z'),
        (8,'private-setting-other','private_setting.changed','{"account_id":"account-a","source_record_id":"task"}','account-b',NULL,'2026-01-01T00:00:00Z'),
        (9,'unowned-control','agent_run.closed','{}','account-b',NULL,'2026-01-01T00:00:00Z');"#).await.unwrap();
    for (id, artifact) in [
        ("visible-occurrence", "task"),
        ("hidden-occurrence", "secret"),
    ] {
        let revision = |kind: &str, subject: &str, slot: &str| json!({"subject_kind":kind,"subject_id":subject,"revision_event_id":"fixture-revision","revision_seq":1,"source_slot":slot,"sha256":"0".repeat(64)});
        let payload = json!({"semantic_contract_version":"fixture-v1","occurrence_id":"fixture-occurrence",
            "unit_revision":revision("unit","task","unit_content"),"artefact_revision":revision("artefact",artifact,"record_body"),
            "selectors":[],"expression_role":"fixture","command":{"operation":"fixture","scope_record_id":"task","idempotency_key":"fixture-key","intent_sha256":"0".repeat(64),"authorization_revision_observed":1}});
        // The v1 visibility check must be able to deserialize this fixture.
        serde_json::from_value::<crate::events::OccurrenceBoundPayload>(payload.clone()).unwrap();
        sqlx::query("UPDATE content_events SET payload=? WHERE id=?")
            .bind(payload.to_string())
            .bind(id)
            .execute(&mut source)
            .await
            .unwrap();
    }
    source.execute("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('malformed-occurrence','task','occurrence.bound.v1','{}','account-a','2026-01-01T00:00:00Z')").await.unwrap();
    source.execute("ALTER TABLE content_events ADD COLUMN run_key TEXT; UPDATE content_events SET run_key='private-claim-run' WHERE id='claim-old'").await.unwrap();
    source
        .execute("UPDATE annotation_targets SET selectors='[]' WHERE annotation_id='c-root'")
        .await
        .unwrap();
    source.execute(r#"INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at)
        SELECT 'ack','Annotation','acknowledgement','ack','',home_id,'person-b',lifecycle,summary,created_at,updated_at,0,'ack',NULL FROM records WHERE id='task';
        INSERT INTO record_policies VALUES('ack');
        INSERT INTO policy_entries VALUES('ack','account','account-b','manage');
        INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('ack-history','ack','record.updated','{}','account-b','2026-01-01T00:00:00Z');"#).await.unwrap();
    let mut options = f.options(
        &["task", "secret", "note", "c-root", "c-reply", "ack"],
        false,
    );
    options.history = true;
    let report = run(options).await.unwrap();
    assert_eq!(report.refusals.len(), 2);
    let db = f.db().await;
    let admin = &report.principals["account-a"];
    let unselected: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE id='unselected-source-link'")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(unselected, 0);
    // A directory viewer is not a root administrator. Payload walks still
    // erase identity and claims; selectors from hidden bearers never travel.
    let viewer = &report.principals["account-b"];
    let ack_home = crate::mcp::kernel_v2::get_history(
        &db,
        viewer,
        json!({"record_id":report.homes["ack"],"detail":"full","limit":1000}),
    )
    .await
    .unwrap();
    assert!(!ack_home["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == "ack-history"));

    assert!(k::read_record_as(&db, viewer, "c-root")
        .await
        .unwrap()
        .is_some());
    // A refused/missing anchor does not erase a valid thread's history.
    // Both the root and reply derive capability from the terminal bearer.
    let hidden = k::create_principal(&db, "account", "Hidden", "history-hidden", admin)
        .await
        .unwrap();
    for id in ["c-root", "c-reply"] {
        for detail in ["metadata", "full"] {
            let page = crate::mcp::kernel_v2::get_history(
                &db,
                viewer,
                json!({"record_id":id,"detail":detail}),
            )
            .await
            .unwrap();
            assert!(page["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|e| e["id"] == format!("created:{id}")));
        }
        assert!(k::history_as(&db, &hidden, id).await.unwrap().is_empty());
        assert!(
            crate::mcp::kernel_v2::get_history(&db, &hidden, json!({"record_id":id}),)
                .await
                .is_err()
        );
    }
    let visible = crate::mcp::kernel_v2::get_history(
        &db,
        viewer,
        json!({"record_id":"task","detail":"full","limit":1000}),
    )
    .await
    .unwrap();
    let events = visible["events"].as_array().unwrap();
    for id in [
        "hidden-annotation",
        "hidden-occurrence",
        "malformed-occurrence",
        "hidden-type",
        "instruction-other",
        "private-setting-other",
    ] {
        assert!(!events.iter().any(|e| e["id"] == id));
    }
    assert!(events
        .iter()
        .any(|e| e["id"] == "visible-unanchored-comment"));
    assert!(events.iter().any(|e| e["id"] == "visible-occurrence"));
    // Account-private control history is forensic custody, including the
    // caller's own controls; it cannot affect a record's public clocks.
    assert!(!events.iter().any(|e| e["id"] == "instruction-own"));
    let metadata = crate::mcp::kernel_v2::get_history(
        &db,
        viewer,
        json!({"record_id":"task","detail":"metadata","limit":1000}),
    )
    .await
    .unwrap();
    let metadata = metadata["events"].as_array().unwrap();
    for id in ["instruction-other", "private-setting-other"] {
        assert!(!metadata.iter().any(|e| e["id"] == id));
    }
    assert!(!metadata.iter().any(|e| e["id"] == "instruction-own"));

    let identity = events.iter().find(|e| e["id"] == "identity-old").unwrap();
    for key in ["email", "account_id", "actor", "owner_id"] {
        assert!(identity["payload"][key].is_null());
    }
    for key in ["id", "owner", "home"] {
        assert!(identity["payload"]["nested"][key].is_null());
    }
    let claim = events.iter().find(|e| e["id"] == "claim-old").unwrap();
    assert!(claim["run_key"].is_null());
    assert!(claim["payload"]["claimed_run_key"].is_null());
    assert!(claim["payload"]["claimed_by_account"].is_null());
    assert!(events.iter().all(|e| e.get("legacy_source").is_none()));
    for detail in ["metadata", "full"] {
        let root = crate::mcp::kernel_v2::get_history(
            &db,
            viewer,
            json!({"record_id":KERNEL_ROOT_ID,"detail":detail,"limit":1000}),
        )
        .await
        .unwrap();
        let root = root["events"].as_array().unwrap();
        for id in [
            "config-other",
            "run-other",
            "empty-unknown",
            "unowned-control",
        ] {
            assert!(!root.iter().any(|e| e["id"] == id));
        }
        for id in ["config-own", "run-own"] {
            assert!(!root.iter().any(|e| e["id"] == id));
        }
    }
    let root = crate::mcp::kernel_v2::get_history(
        &db,
        admin,
        json!({"record_id":KERNEL_ROOT_ID,"detail":"full","limit":1000}),
    )
    .await
    .unwrap();
    assert!(!root["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == "config-other"));
    assert!(root["events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["type"] != "kernel.import_receipt.v1"));
    let detailed = crate::mcp::kernel_v2::get_history(
        &db,
        admin,
        json!({"record_id":KERNEL_ROOT_ID,"include_import_receipts":true,"limit":1000}),
    )
    .await
    .unwrap();
    assert!(detailed["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["type"] == "kernel.import_receipt.v1"));
    // Receipt visibility is the witnessed legacy row's visibility, including
    // private root controls, hidden types, acknowledgements and hidden targets.
    let receipts: Vec<(String, String)> = sqlx::query_as(
        "SELECT id,json_extract(payload,'$.legacy_event_id') FROM content_events WHERE type='kernel.import_receipt.v1'",
    ).fetch_all(db.write_pool()).await.unwrap();
    let receipts: BTreeMap<_, _> = receipts.into_iter().collect();
    for actor in [viewer, admin] {
        for subject in ["task", KERNEL_ROOT_ID, &report.homes["ack"]] {
            let allowed: BTreeSet<_> = k::history_as(&db, actor, subject)
                .await
                .unwrap()
                .into_iter()
                .map(|e| e.id)
                .collect();
            let detailed = k::history_page_as(&db, actor, subject, None, false, 1000, false, true)
                .await
                .unwrap();
            for e in &detailed {
                if let Some(legacy_id) = receipts.get(&e.id) {
                    assert!(
                        allowed.contains(legacy_id),
                        "receipt for withheld event: {legacy_id}"
                    );
                    assert!(e.retained_legacy.is_none());
                }
            }
            // Keyset pagination must also apply the rule when the witnessed
            // event is outside the receipt's page.
            let mut paged = Vec::new();
            let mut after = None;
            loop {
                let page = k::history_page_as(&db, actor, subject, after, false, 1, false, true)
                    .await
                    .unwrap();
                let Some(event) = page.into_iter().next() else {
                    break;
                };
                after = Some(event.seq);
                paged.push(event.id);
            }
            assert_eq!(
                paged,
                detailed.into_iter().map(|e| e.id).collect::<Vec<_>>()
            );
        }
    }
    // Repairing a refused anchor changes current authorization, not immutable
    // retained events. Replies inherit that root anchor as in v1.
    sqlx::query("UPDATE annotation_targets SET selectors=? WHERE annotation_id='c-root'")
        .bind(
            r#"[{"type":"text_quote","exact":"body"},{"type":"data_position","start":0,"end":4}]"#,
        )
        .execute(&mut source)
        .await
        .unwrap();
    let mut options = f.options(
        &["task", "secret", "note", "c-root", "c-reply", "ack"],
        true,
    );
    options.history = true;
    let repaired = run(options).await.unwrap();
    assert_eq!(
        repaired.refusals.len(),
        1,
        "{}",
        serde_json::to_string(&repaired.refusals).unwrap()
    );
    assert!(repaired
        .history
        .streams
        .values()
        .all(|counts| counts.created == 0));
    let mut pages = Vec::new();
    for id in ["c-root", "c-reply"] {
        let page = crate::mcp::kernel_v2::get_history(
            &db,
            viewer,
            json!({"record_id":id,"detail":"full","limit":1000}),
        )
        .await
        .unwrap();
        assert!(page["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["id"] == format!("created:{id}")));
        pages.push((id, page));
    }
    k::replay_all_projections(&db).await.unwrap();
    for (id, page) in pages {
        assert_eq!(
            crate::mcp::kernel_v2::get_history(
                &db,
                viewer,
                json!({"record_id":id,"detail":"full","limit":1000})
            )
            .await
            .unwrap(),
            page
        );
    }
    let reader = k::create_principal(&db, "account", "Reader", "history-reader", admin)
        .await
        .unwrap();
    let home = k::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin, "manage"), (&reader, "view")]),
        admin,
    )
    .await
    .unwrap();
    k::rehome_record_as(&db, admin, "task", &home)
        .await
        .unwrap();
    let page = crate::mcp::kernel_v2::get_history(
        &db,
        &reader,
        json!({"record_id":"task","detail":"full","limit":1000}),
    )
    .await
    .unwrap();
    let events = page["events"].as_array().unwrap();
    assert!(events.iter().any(|e| e["id"] == "created:task"));
    assert!(!events.iter().any(|e| e["id"] == "hidden-old-link"));
    assert!(!events
        .iter()
        .any(|e| e["id"] == "visible-unanchored-comment"));
    for event in events {
        assert!(event["actor"].is_null());
        assert!(event["run_key"].is_null());
        assert!(event["payload"].is_null());
        assert!(event["legacy_source"].is_null());
    }
    let admin_page = crate::mcp::kernel_v2::get_history(
        &db,
        admin,
        json!({"record_id":"task","detail":"full","limit":1000}),
    )
    .await
    .unwrap();
    assert!(admin_page["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == "hidden-old-link"));
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_history_all_retains_tombstones_without_resurrection() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("UPDATE records SET deleted_at='2026-03-01T00:00:00Z' WHERE id='epic'")
        .await
        .unwrap();
    source.execute("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('deleted-source-link','epic','link.added','{\"source_id\":\"epic\",\"target_id\":\"task\"}','writer','2026-01-01T00:00:00Z')").await.unwrap();
    let mut options = f.options(&[], false);
    options.all = true;
    let report = run(options).await.unwrap();
    let counts = &report.history.streams["content_events"];
    assert_eq!(counts.source, counts.verified);
    assert_eq!(counts.skipped_subject_not_selected, 0);
    assert!(counts.retained_without_imported_subject >= 2);
    let db = f.db().await;
    let admin = &report.principals["account-a"];
    assert!(k::read_record_as(&db, admin, "epic")
        .await
        .unwrap()
        .is_none());
    let retained: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE id IN ('created:epic','edited:epic','deleted-source-link') AND record_id='kernel:root' AND type='kernel.legacy_recorded.v1'").fetch_one(db.write_pool()).await.unwrap();
    assert_eq!(retained, 3);
    let root = k::history_as(&db, admin, KERNEL_ROOT_ID).await.unwrap();
    assert!(!root.iter().any(|e| e.id == "created:epic"));
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(k::dump_all_kernel_tables(&db).await.unwrap(), before);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_history_batches_preserve_causality_and_atomic_resume() {
    let f = Fixture::new().await;
    let report = run(f.options(&["task", "epic"], false)).await.unwrap();
    let db = f.db().await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let admin = &report.principals["account-a"];
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let mut entries: Vec<_> = (0..256)
        .map(|n| {
            let record = if n % 2 == 0 { "task" } else { "epic" };
            (
                record.to_string(),
                k::LegacyEvent {
                    source: Some(json!({"stream":"content_events","subjects":[record]})),
                    id: format!("batch-history-{n}"),
                    event_type: "record.updated".into(),
                    payload: json!({"body":"historical"}),
                    created_at: "2025-01-01T00:00:00Z".into(),
                    actor: Some("old-writer".into()),
                    run_key: None,
                },
            )
        })
        .collect();
    let count_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    entries[255].0 = "missing-subject".into();
    assert!(k::import_history_batch_as(&db, &host, &entries)
        .await
        .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        count_before
    );
    entries[255].0 = "epic".into();
    assert!(k::import_history_batch_as(&db, admin, &entries)
        .await
        .is_err());
    let mut heads: BTreeSet<String> = sqlx::query_scalar("SELECT e.id FROM content_events e WHERE NOT EXISTS(SELECT 1 FROM content_event_causal_frontier f WHERE f.parent_event_id=e.id)").fetch_all(db.write_pool()).await.unwrap().into_iter().collect();
    let outcome = k::import_history_batch_as(&db, &host, &entries)
        .await
        .unwrap();
    assert!(outcome.iter().all(|r| *r == k::ImportResult::Created));
    let rows: Vec<(String, String, i64, String)> = sqlx::query_as(
        "SELECT id,type,act,causal_status FROM content_events ORDER BY seq LIMIT -1 OFFSET ?",
    )
    .bind(count_before)
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 512);
    let act = rows[0].2;
    for (index, (id, kind, event_act, status)) in rows.iter().enumerate() {
        assert_eq!(*event_act, act);
        let parents: BTreeSet<String> = sqlx::query_scalar(
            "SELECT parent_event_id FROM content_event_causal_frontier WHERE event_id=?",
        )
        .bind(id)
        .fetch_all(db.write_pool())
        .await
        .unwrap()
        .into_iter()
        .collect();
        if index < 256 {
            assert_eq!(kind, "kernel.import_receipt.v1");
            assert_eq!(status, "complete");
            assert_eq!(parents, heads);
            heads = BTreeSet::from([id.clone()]);
        } else {
            assert_eq!(kind, "kernel.legacy_recorded.v1");
            assert_eq!(status, "legacy_unknown");
            assert!(parents.is_empty());
            assert_eq!(id, &entries[index - 256].1.id);
            heads.insert(id.clone());
        }
    }
    let actual_heads: BTreeSet<String> = sqlx::query_scalar("SELECT e.id FROM content_events e WHERE NOT EXISTS(SELECT 1 FROM content_event_causal_frontier f WHERE f.parent_event_id=e.id)").fetch_all(db.write_pool()).await.unwrap().into_iter().collect();
    assert_eq!(actual_heads, heads);
    let retry = k::import_history_batch_as(&db, &host, &entries)
        .await
        .unwrap();
    assert!(retry.iter().all(|r| *r == k::ImportResult::Unchanged));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        count_before + 512
    );
    // Retained history now has derived SQL headers and a scanned frontier.
    // Those may advance; every current-state projection must stay identical.
    let mut current = k::dump_all_kernel_tables(&db).await.unwrap();
    current.legacy_sql_events = before.legacy_sql_events.clone();
    current.legacy_sql_progress = before.legacy_sql_progress.clone();
    assert_eq!(current, before);
    let with_history = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(k::dump_all_kernel_tables(&db).await.unwrap(), with_history);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_link_provenance_cache_preserves_generations_nulls_and_json_affinity() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.db");
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true),
    )
    .await
    .unwrap();
    source.execute("CREATE TABLE content_events(seq INTEGER PRIMARY KEY,type TEXT,payload TEXT,actor TEXT,created_at TEXT); CREATE TABLE relationship_legacy_links(relationship_origin_db_id TEXT,relationship_id TEXT,source_facts TEXT,created_at TEXT); CREATE TABLE relationship_events(seq INTEGER,relationship_origin_db_id TEXT,relationship_id TEXT,type TEXT,actor TEXT,occurred_at TEXT)").await.unwrap();
    let first = "2026-01-01T00:00:00Z";
    let second = "2026-01-02T00:00:00Z";
    let events = vec![
        (
            "link.added",
            Some(json!({"id":"old","source_id":"a","target_id":"b","relationship":"r"})),
            Some("old"),
            first,
        ),
        (
            "link.removed",
            Some(json!({"source_id":"a","target_id":"b","relationship":"r"})),
            None,
            first,
        ),
        (
            "link.added",
            Some(json!({"id":"current","source_id":"a","target_id":"b","relationship":"r"})),
            Some("new"),
            second,
        ),
        (
            "link.added",
            Some(json!({"source_id":"c","target_id":"d","relationship":"r"})),
            Some("fallback"),
            first,
        ),
        (
            "link.added",
            Some(
                json!({"id":"rel:test:null-actor","source_id":"e","target_id":"f","relationship":"r"}),
            ),
            None,
            first,
        ),
        (
            "link.added",
            Some(json!({"id":"","source_id":"g","target_id":"h","relationship":"r"})),
            Some("empty-id"),
            first,
        ),
        (
            "link.added",
            Some(json!({"id":"numeric","source_id":123,"target_id":"j","relationship":"r"})),
            Some("numeric-must-not-match"),
            first,
        ),
        (
            "link.added",
            Some(json!({"id":"different","source_id":"a","target_id":"b","relationship":"r"})),
            Some("other"),
            first,
        ),
        (
            "link.added",
            Some(json!({"id":"current","source_id":"a","target_id":"b","relationship":"r"})),
            Some("later"),
            second,
        ),
        (
            "link.removed",
            Some(json!({"source_id":"other","target_id":"edge","relationship":"r"})),
            None,
            second,
        ),
        ("link.added", None, None, first),
    ];
    let count = events.len() as i64;
    for (position, (typ, payload, actor, time)) in events.into_iter().enumerate() {
        sqlx::query("INSERT INTO content_events VALUES(?,?,?,?,?)")
            .bind(position as i64 + 1)
            .bind(typ)
            .bind(payload.map(|v| v.to_string()))
            .bind(actor)
            .bind(time)
            .execute(&mut source)
            .await
            .unwrap();
    }
    sqlx::query("INSERT INTO relationship_legacy_links VALUES('test','null-actor',?,?)")
        .bind(
            json!([{"operation":"add","occurred_at":first,"actor":"must-not-fall-through"}])
                .to_string(),
        )
        .bind(first)
        .execute(&mut source)
        .await
        .unwrap();
    source.close().await.unwrap();
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .read_only(true),
    )
    .await
    .unwrap();
    source.execute("BEGIN").await.unwrap();
    assert!(cache_link_provenance(&mut source).await.unwrap());
    for (id, from, to, time, actor) in [
        ("old", "a", "b", first, None),
        ("current", "a", "b", second, Some("new")),
        ("current", "a", "b", first, None),
        ("lnk:c:d:r", "c", "d", first, Some("fallback")),
        ("rel:test:null-actor", "e", "f", first, None),
        ("lnk:g:h:r", "g", "h", first, None),
        ("numeric", "123", "j", first, None),
    ] {
        let link = Link {
            id: id.into(),
            source_id: from.into(),
            target_id: to.into(),
            relationship: "r".into(),
            note: None,
            created_at: time.into(),
        };
        let direct = link_provenance(&mut source, &link, true, false)
            .await
            .unwrap();
        let cached = link_provenance(&mut source, &link, true, true)
            .await
            .unwrap();
        assert_eq!(cached, direct, "{id}");
        assert_eq!(cached, (actor.map(str::to_owned), time.to_owned()), "{id}");
    }
    assert!(source
        .execute(
            "INSERT INTO content_events VALUES(1000,'link.added','{}',NULL,'2026-01-01T00:00:00Z')"
        )
        .await
        .is_err());
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM main.content_events")
            .fetch_one(&mut source)
            .await
            .unwrap(),
        count
    );
    source.execute("ROLLBACK").await.unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_link_provenance_cache_keeps_direct_fallback_for_malformed_unreached_facts() {
    let mut source = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    source.execute("CREATE TABLE content_events(seq INTEGER PRIMARY KEY,type TEXT,payload TEXT,actor TEXT,created_at TEXT)").await.unwrap();
    let time = "2026-01-01T00:00:00Z";
    sqlx::query("INSERT INTO content_events VALUES(1,'link.added',?,'kept',?)")
        .bind(json!({"id":"link","source_id":"a","target_id":"b","relationship":"r"}).to_string())
        .bind(time)
        .execute(&mut source)
        .await
        .unwrap();
    sqlx::query("INSERT INTO content_events VALUES(2,'link.added','{broken',NULL,?)")
        .bind(time)
        .execute(&mut source)
        .await
        .unwrap();
    assert!(!cache_link_provenance(&mut source).await.unwrap());
    let link = Link {
        id: "link".into(),
        source_id: "a".into(),
        target_id: "b".into(),
        relationship: "r".into(),
        note: None,
        created_at: time.into(),
    };
    assert_eq!(
        link_provenance(&mut source, &link, false, false)
            .await
            .unwrap(),
        (Some("kept".into()), time.into())
    );
}

#[tokio::test]
async fn imported_delta_updates_body_metadata_facets_home_and_retries() {
    let f = Fixture::new().await;
    let seeds = ["task", "epic", "note", "archived"];
    let first = run(f.options(&seeds, false)).await.unwrap();
    assert!(
        first.refusals.is_empty(),
        "{}",
        serde_json::to_string(&first.refusals).unwrap()
    );
    let db = f.db().await;
    let owner = first.principals["account-a"].clone();
    let before = k::read_record_as(&db, &owner, "task")
        .await
        .unwrap()
        .unwrap();
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE records SET body='delta body',maturity='ready',last_activity_at='2026-04-01T00:00:00Z',updated_at='2026-04-01T00:00:00Z',home_id='native:root' WHERE id='task'; DELETE FROM facet_values WHERE record_id='task' AND key='score'; UPDATE records SET archived=1 WHERE id='note'; DELETE FROM facet_values WHERE record_id='archived' AND key='archived';").await.unwrap();
    let changed = run(f.options(&seeds, true)).await.unwrap();
    assert!(
        changed.refusals.is_empty(),
        "{}",
        serde_json::to_string(&changed.refusals).unwrap()
    );
    assert_eq!(changed.updated, 3);
    let task = k::read_record_as(&db, &owner, "task")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(task.body.as_deref(), Some("delta body"));
    assert_eq!(task.metadata.maturity.as_deref(), Some("ready"));
    assert_eq!(task.home_id, KERNEL_ROOT_ID);
    assert!(k::facets_as(&db, &owner, "task").await.unwrap().is_empty());
    assert!(task.revision > before.revision);
    let retry = run(f.options(&seeds, true)).await.unwrap();
    assert!(retry.refusals.is_empty());
    assert_eq!(retry.updated, 0);
    let projections = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projections, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn imported_delta_removes_generic_d9_bindings_and_tombstones_without_erasure() {
    let f = Fixture::new().await;
    seed_instruction_bindings(&f).await;
    let seeds = ["task", "epic", "note", "archived"];
    let first = run(f.options(&seeds, false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    let final_body = "final deleted body ".repeat(5_000);
    sqlx::query("UPDATE records SET name='final deleted title',body=?,summary='final summary',lifecycle='completed',home_id='native:root',maturity='mature',last_activity_at='2026-04-01T00:00:00Z',updated_at='2026-04-01T00:00:00Z' WHERE id='archived'").bind(&final_body).execute(&mut source).await.unwrap();
    source.execute("INSERT INTO facet_values VALUES('archived','final','value',NULL,NULL,'2026-04-01T00:00:00Z'); INSERT INTO facet_observations VALUES('archived','final','2026-04-01T00:00:00Z',3)").await.unwrap();
    source.execute("DELETE FROM links WHERE id IN ('link-d','link-a'); DELETE FROM instruction_bindings; UPDATE records SET deleted_at='2026-04-01T00:00:00Z' WHERE id='archived'; DELETE FROM records WHERE id='note';").await.unwrap();
    // Excluded from the new seed set is not absent from the source.
    let changed = run(f.options(&["epic", "task", "archived"], true))
        .await
        .unwrap();
    assert_eq!(changed.delta["generic_links_removed"], 1);
    assert_eq!(changed.delta["records_tombstoned"], 2);
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(
        k::read_imported_snapshot_as(&db, &first.principals["account-a"], "archived")
            .await
            .is_err()
    );
    let tombstone = k::read_imported_snapshot_as(&db, &host, "archived")
        .await
        .unwrap()
        .unwrap();
    assert!(tombstone.tombstoned);
    assert!(tombstone.record.body.as_deref() == Some(final_body.as_str()));
    assert_eq!(tombstone.record.fields["title"], "final deleted title");
    assert_eq!(tombstone.record.fields["summary"], "final summary");
    assert_eq!(tombstone.record.fields["lifecycle"], "completed");
    assert_eq!(tombstone.record.home_id, KERNEL_ROOT_ID);
    assert_eq!(
        tombstone.record.metadata.maturity.as_deref(),
        Some("mature")
    );
    assert_eq!(
        tombstone.record.metadata.last_activity_at,
        "2026-04-01T00:00:00Z"
    );
    assert_eq!(tombstone.facets.len(), 1);
    assert_eq!(tombstone.facets[0].key, "final");

    assert_eq!(changed.delta["relates_to_directions_removed"], 1);
    let active: bool =
        sqlx::query_scalar("SELECT active FROM kernel_generic_links WHERE link_id='link-d'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert!(!active);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_records WHERE id IN ('note','archived')")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(count, 2);
    for id in ["note", "archived"] {
        assert!(k::read_record_as(&db, &first.principals["account-a"], id)
            .await
            .unwrap()
            .is_none());
    }
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_instruction_bindings WHERE enabled=1")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(count, 0);
    let retry = run(f.options(&["epic", "task", "archived"], true))
        .await
        .unwrap();
    assert_eq!(retry.delta.get("generic_links_removed"), None);
    assert_eq!(retry.delta.get("records_tombstoned"), None);
    source
        .execute("DELETE FROM links WHERE relationship='relates_to'")
        .await
        .unwrap();
    let removed = run(f.options(&["epic", "task", "archived"], true))
        .await
        .unwrap();
    assert_eq!(removed.delta["relates_to_directions_removed"], 1);
    let relations = k::relations_as(&db, &first.principals["account-a"], "task")
        .await
        .unwrap();
    assert!(relations.iter().all(|r| r["state"]["assertions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["retracted"] == true)));
    let projections = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projections, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_delta_rehomes_terminal_with_comments_and_removes_anchors() {
    let f = Fixture::new().await;
    add_comment_fixture(&f).await;
    let seeds = ["note", "c-root", "c-reply"];
    let first = run(f.options(&seeds, false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE records SET home_id='native:root',updated_at='2026-04-01T00:00:00Z' WHERE id='note'; DELETE FROM annotation_targets;").await.unwrap();
    let changed = run(f.options(&seeds, true)).await.unwrap();
    assert!(
        changed.refusals.is_empty(),
        "{}",
        serde_json::to_string(&changed.refusals).unwrap()
    );
    assert_eq!(changed.delta["comment_anchors_removed"], 1);
    for id in seeds {
        let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(home, KERNEL_ROOT_ID);
    }
    let retry = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(retry.updated, 0);
    assert!(retry.refusals.is_empty());
    source
        .execute("UPDATE records SET deleted_at='2026-04-02T00:00:00Z' WHERE id='c-root'")
        .await
        .unwrap();
    let deleted = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(deleted.delta["records_tombstoned"], 2);
    for id in ["c-root", "c-reply"] {
        assert!(k::read_record_as(&db, &first.principals["account-b"], id)
            .await
            .unwrap()
            .is_none());
    }
    let rows = ordinary_kernel_call(
        &db,
        "account-b",
        "query_sql",
        json!({"sql":"SELECT id FROM records WHERE id IN ('c-root','c-reply')"}),
    )
    .await
    .unwrap();
    assert!(rows["rows"].as_array().unwrap().is_empty());
    let hits = ordinary_kernel_call(
        &db,
        "account-b",
        "search",
        json!({"query":"remark","include_archived":true}),
    )
    .await
    .unwrap();
    assert!(hits["hits"].as_array().unwrap().is_empty());
    let query = ordinary_kernel_call(
        &db,
        "account-b",
        "query_record",
        json!({"steps":[{"step":"filter","ids":["c-root","c-reply"]}]}),
    )
    .await
    .unwrap();
    assert!(query["records"].as_array().unwrap().is_empty());
    source
        .execute("DELETE FROM links WHERE id='link-c-reply'")
        .await
        .unwrap();
    let detached = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(detached.delta.get("comments_detached"), None);
    source
        .execute("UPDATE records SET deleted_at='2026-04-03T00:00:00Z' WHERE id='folder'")
        .await
        .unwrap();
    let folder_deleted = run(f.options(&seeds, true)).await.unwrap();
    assert!(folder_deleted
        .review
        .iter()
        .any(|i| i.id == "folder" && i.reason.contains("source tombstone")));
    for home in ["folder".to_owned(), derived("folder")] {
        let refused = ordinary_kernel_call(
            &db,
            "account-b",
            "create_record",
            json!({"type":"Document","kind":"note","home_id":home}),
        )
        .await;
        assert!(refused.is_err());
    }
    let projections = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projections, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn imported_delta_detaches_attachment_refs_retaining_bytes_and_history() {
    use sha2::{Digest, Sha256};
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("CREATE TABLE blobs(id TEXT PRIMARY KEY,bytes BLOB,mime TEXT,size_bytes INTEGER,sha256 TEXT,original_filename TEXT,storage_tier TEXT,created_at TEXT); UPDATE records SET type='Document',kind='attachment' WHERE id='task';").await.unwrap();
    // Blob-ref detachment is independent of bearer integrity: begin with
    // a valid attachment, as the live import guard now requires.
    source
        .execute(
            "DELETE FROM links WHERE source_id='task' AND relationship='part_of' AND id<>'link-d'",
        )
        .await
        .unwrap();
    let bytes = b"synthetic blob";
    sqlx::query("INSERT INTO blobs VALUES('synthetic',?,'text/plain',?,?,NULL,'inline','2026-01-01T00:00:00Z')").bind(bytes.as_slice()).bind(bytes.len() as i64).bind(hex::encode(Sha256::digest(bytes))).execute(&mut source).await.unwrap();
    source.execute("INSERT INTO facet_values VALUES('task','blob_ref','synthetic',NULL,NULL,'2026-01-01T00:00:00Z'); INSERT INTO facet_observations VALUES('task','blob_ref','2026-01-01T00:00:00Z',3)").await.unwrap();
    let first = run(f.options(&["task"], false)).await.unwrap();
    assert!(first.refusals.is_empty());
    source
        .execute("DELETE FROM facet_values WHERE record_id='task' AND key='blob_ref'")
        .await
        .unwrap();
    let changed = run(f.options(&["task"], true)).await.unwrap();
    assert!(
        changed.refusals.is_empty(),
        "{}",
        serde_json::to_string(&changed.refusals).unwrap()
    );
    assert_eq!(changed.updated, 1);
    let db = f.db().await;
    let refs: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_attachment_blobs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(refs, 0);
    let blobs: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_blobs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(blobs, 1);
    let retry = run(f.options(&["task"], true)).await.unwrap();
    assert!(retry.refusals.is_empty());
    assert_eq!(retry.updated, 0);
    let projections = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projections, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn imported_delta_retargets_bindings_and_restores_disabled_import_identity() {
    let f = Fixture::new().await;
    seed_instruction_bindings(&f).await;
    let first = run(f.options(&["task"], false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE instruction_bindings SET source_record_id='task',position=7 WHERE id='binding-member'; DELETE FROM instruction_bindings WHERE id='binding-workspace'").await.unwrap();
    let changed = run(f.options(&["task"], true)).await.unwrap();
    assert!(changed.refusals.is_empty());
    assert_eq!(changed.instruction_bindings.updated, 1);
    assert_eq!(changed.delta["instruction_bindings_removed"], 1);
    source.execute("INSERT INTO instruction_bindings VALUES('binding-workspace','database','native:database','epic',0,1,'binding-author','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')").await.unwrap();
    let restored = run(f.options(&["task"], true)).await.unwrap();
    assert!(restored.refusals.is_empty());
    assert_eq!(restored.instruction_bindings.updated, 1);
    let db = f.db().await;
    let projections = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projections, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn imported_delta_preserves_native_rows_and_refuses_native_edits_or_older_snapshots() {
    let f = Fixture::new().await;
    let first = run(f.options(&["task"], false)).await.unwrap();
    let db = f.db().await;
    let owner = &first.principals["account-a"];
    let native = k::create_record_as(&db, owner, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let old = k::read_record_as(&db, owner, "task")
        .await
        .unwrap()
        .unwrap();
    k::set_body_as(&db, owner, "task", "native edit", old.revision)
        .await
        .unwrap();
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("UPDATE records SET body='source edit' WHERE id='task'")
        .await
        .unwrap();
    let changed = run(f.options(&["task"], true)).await.unwrap();
    assert!(changed
        .refusals
        .iter()
        .any(|i| i.id == "task" && i.reason.contains("native record edits")));
    assert_eq!(
        k::read_record_as(&db, owner, "task")
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some("native edit")
    );
    assert!(k::read_record_as(&db, owner, &native)
        .await
        .unwrap()
        .is_some());
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::import_source_head_as(
        &db,
        &host,
        "test-origin",
        1_000_000,
        Some("future-source-event".into()),
        0,
        None,
    )
    .await
    .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let stale = run(f.options(&["task"], true)).await.unwrap();
    assert!(stale
        .refusals
        .iter()
        .any(|i| i.reason.contains("source snapshot is older")));
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
async fn imported_duplicate_source_link_ids_refuse_before_target_writes() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO links VALUES('link-d','note','epic','part_of',NULL,'2026-01-02T00:00:00Z')").await.unwrap();
    let refused = run(f.options(&["task", "epic", "note"], false))
        .await
        .unwrap();
    assert!(refused
        .refusals
        .iter()
        .any(|i| i.id == "link-d" && i.reason.contains("duplicate source link_id: 2 rows")));
    assert!(!f.target.exists());
    source
        .execute("DELETE FROM links WHERE rowid=(SELECT max(rowid) FROM links WHERE id='link-d')")
        .await
        .unwrap();
    let first = run(f.options(&["task", "epic", "note"], false))
        .await
        .unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    source.execute("INSERT INTO links VALUES('link-d','note','epic','part_of',NULL,'2026-01-02T00:00:00Z')").await.unwrap();
    let refused = run(f.options(&["task", "epic", "note"], true))
        .await
        .unwrap();
    assert_eq!(refused.refusals.len(), 1);
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[tokio::test]
async fn imported_delta_updates_home_policy_and_owner_without_admin_bypass() {
    let f = Fixture::new().await;
    let first = run(f.options(&["secret"], false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    private_policy_for_b(&mut source).await;
    source
        .execute("UPDATE records SET owner_id='person-b' WHERE id IN ('private','secret')")
        .await
        .unwrap();
    let changed = run(f.options(&["secret"], true)).await.unwrap();
    assert!(
        changed.refusals.is_empty(),
        "{}",
        serde_json::to_string(&changed.refusals).unwrap()
    );
    let db = f.db().await;
    for id in ["private", "secret"] {
        assert!(k::read_record_as(&db, &first.principals["account-a"], id)
            .await
            .unwrap()
            .is_none());
        assert!(k::read_record_as(&db, &first.principals["account-b"], id)
            .await
            .unwrap()
            .is_some());
    }
    let projections = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projections, k::dump_all_kernel_tables(&db).await.unwrap());
    account_policy_for_b(&mut source, V1_ROOT).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let refused = run(f.options(&["secret"], true)).await.unwrap();
    assert!(refused
        .refusals
        .iter()
        .any(|i| i.id == "native:workspace-owner"
            && i.reason.contains("explicit ownership review required")));
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_delta_detached_comment_keeps_final_state_without_regrant() {
    let f = Fixture::new().await;
    add_comment_fixture(&f).await;
    let seeds = ["note", "c-root", "c-reply"];
    let first = run(f.options(&seeds, false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE records SET body='final detached reply',updated_at='2026-04-01T00:00:00Z' WHERE id='c-reply'; DELETE FROM links WHERE id='link-c-reply'").await.unwrap();
    let changed = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(changed.delta["comments_detached"], 1);
    assert_eq!(changed.tombstones_verified, 1);
    let db = f.db().await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let state = k::read_imported_snapshot_as(&db, &host, "c-reply")
        .await
        .unwrap()
        .unwrap();
    assert!(state.tombstoned);
    assert_eq!(state.record.body.as_deref(), Some("final detached reply"));
    assert!(
        k::read_record_as(&db, &first.principals["account-b"], "c-reply")
            .await
            .unwrap()
            .is_none()
    );
    let retry = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(retry.updated, 0);
    assert_eq!(retry.delta.get("comments_detached"), None);
    let projections = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projections, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_delta_seed_drop_keeps_live_comment_threads() {
    let f = Fixture::new().await;
    add_comment_fixture(&f).await;
    let seeds = ["note", "c-root", "c-reply"];
    let first = run(f.options(&seeds, false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    let mut before = Vec::new();
    for id in seeds {
        before.push(
            k::read_record_as(&db, &first.principals["account-b"], id)
                .await
                .unwrap(),
        );
    }
    let dropped = run(f.options(&["c-root"], true)).await.unwrap();
    assert_eq!(dropped.delta.get("records_tombstoned"), None);
    assert_eq!(dropped.tombstones_verified, 0);
    for id in seeds {
        assert!(k::read_record_as(&db, &first.principals["account-b"], id)
            .await
            .unwrap()
            .is_some());
    }
    let restored = run(f.options(&seeds, true)).await.unwrap();
    assert!(
        restored.refusals.is_empty(),
        "{}",
        serde_json::to_string(&restored.refusals).unwrap()
    );
    assert_eq!(restored.updated, 0);
    for (index, id) in seeds.iter().enumerate() {
        assert_eq!(
            before[index],
            k::read_record_as(&db, &first.principals["account-b"], id)
                .await
                .unwrap()
        );
    }
}

#[tokio::test]
async fn imported_delta_refused_live_binding_targets_retain_prior_bindings() {
    let f = Fixture::new().await;
    seed_instruction_bindings(&f).await;
    let first = run(f.options(&["task"], false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO facet_values VALUES('note','unobserved','value',NULL,NULL,'2026-04-01T00:00:00Z')").await.unwrap();
    let refused = run(f.options(&["task"], true)).await.unwrap();
    assert!(refused
        .review
        .iter()
        .any(|i| i.id == "binding-member" && i.reason.contains("prior binding retained")));
    let enabled: bool = sqlx::query_scalar(
        "SELECT enabled FROM kernel_instruction_bindings WHERE id='binding-member'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(enabled);
    source
        .execute("DELETE FROM facet_values WHERE record_id='note' AND key='unobserved'")
        .await
        .unwrap();
    let view = k::read_record_as(&db, &first.principals["account-b"], "note")
        .await
        .unwrap()
        .unwrap();
    k::set_body_as(
        &db,
        &first.principals["account-b"],
        "note",
        "native content",
        view.revision,
    )
    .await
    .unwrap();
    source
        .execute("UPDATE records SET body='source content' WHERE id='note'")
        .await
        .unwrap();
    let refused = run(f.options(&["task"], true)).await.unwrap();
    assert!(refused
        .review
        .iter()
        .any(|i| i.id == "binding-member" && i.reason.contains("prior binding retained")));
    let enabled: bool = sqlx::query_scalar(
        "SELECT enabled FROM kernel_instruction_bindings WHERE id='binding-member'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(enabled);
    // A real retarget to an unsafe target disables the old association.
    source.execute("UPDATE instruction_bindings SET source_record_id='secret' WHERE id='binding-member'; INSERT INTO facet_values VALUES('secret','unobserved','value',NULL,NULL,'2026-04-01T00:00:00Z'); DELETE FROM instruction_bindings WHERE id='binding-workspace'").await.unwrap();
    let retargeted = run(f.options(&["task"], true)).await.unwrap();
    assert!(retargeted
        .review
        .iter()
        .any(|i| i.id == "binding-member" && i.reason.contains("prior binding disabled")));
    let enabled: bool = sqlx::query_scalar(
        "SELECT enabled FROM kernel_instruction_bindings WHERE id='binding-member'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert!(!enabled);
    let snapshots: Vec<String> = sqlx::query_scalar("SELECT json_extract(payload,'$.evidence.snapshot') FROM content_events WHERE type='kernel.import_removed.v1'").fetch_all(db.pool()).await.unwrap();
    assert_eq!(snapshots.len(), 2);
    for snapshot in snapshots {
        let value: Value = serde_json::from_str(&snapshot).unwrap();
        assert!(value.is_object());
        assert_eq!(value.as_object().unwrap().len(), 2);
        assert!(value.get("content").is_some() && value.get("control").is_some());
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_delta_native_attachments_and_anchors_are_not_removal_candidates() {
    let f = Fixture::new().await;
    add_comment_fixture(&f).await;
    let first = run(f.options(&["note"], false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    let attachment = ordinary_kernel_call(
        &db,
        "account-b",
        "attach_text",
        json!({"record_id":"note","text":"Native attachment"}),
    )
    .await
    .unwrap();
    let comment=ordinary_kernel_call(&db,"account-b","create_record",json!({"type":"Annotation","kind":"comment","body":"Native comment","links":[{"relationship":"part_of","target_id":"note"}],"target":{"target_record_id":"note","source_slot":"body","selectors":[{"type":"text_quote","exact":"body"}]}})).await.unwrap();
    let resumed = run(f.options(&["note"], true)).await.unwrap();
    assert!(
        resumed.review.is_empty(),
        "{}",
        serde_json::to_string(&resumed.review).unwrap()
    );
    assert!(
        resumed.refusals.is_empty(),
        "{}",
        serde_json::to_string(&resumed.refusals).unwrap()
    );
    for id in [
        attachment["attachment_id"].as_str().unwrap(),
        comment["id"].as_str().unwrap(),
    ] {
        assert!(k::read_record_as(&db, &first.principals["account-b"], id)
            .await
            .unwrap()
            .is_some());
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_comment_anchors")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_delta_all_history_resume_keeps_tombstoned_anchors_and_receipts() {
    let f = Fixture::new().await;
    add_comment_fixture(&f).await;
    seed_instruction_bindings(&f).await;
    let mut setup = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    setup.execute("DELETE FROM instruction_bindings WHERE id='binding-outside'; INSERT INTO instruction_bindings VALUES('binding-deleted','account','account-a','task',2,1,'binding-author','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')").await.unwrap();
    // Keep exercising a home-only retained history anchor. Artifacts now
    // import as live records, while this bearerless annotation stays refused.
    setup.execute("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id) SELECT 'retained-home','Annotation','legacy-retained-only','synthetic home','',home_id,owner_id,NULL,NULL,created_at,updated_at,0,policy_anchor_id FROM records WHERE id='folder'; INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id) SELECT 'home-child','WorkItem','task','synthetic child','', 'retained-home',owner_id,lifecycle,summary,created_at,updated_at,0,policy_anchor_id FROM records WHERE id='task'; INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('retained-home-history','retained-home','record.updated','{}','old-author','2026-01-01T00:00:00Z')").await.unwrap();
    setup.close().await.unwrap();
    let mut options = f.options(&[], false);
    options.all = true;
    options.history = true;
    let first = run(options).await.unwrap();
    assert!(
        first.refusals.len() == 1
            && first.refusals[0].id == "retained-home"
            && first.refusals[0].reason
                == "derived record requires exactly one live part_of chain to a terminal bearer",
        "{}",
        serde_json::to_string(&first.refusals).unwrap()
    );
    let db = f.db().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE records SET home_id='native:root' WHERE id='home-child'; DELETE FROM records WHERE id='retained-home'; UPDATE records SET home_id='native:root',updated_at='2026-04-01T00:00:00Z' WHERE id='note'; UPDATE records SET body='Final deleted task',deleted_at='2026-04-01T00:00:00Z',updated_at='2026-04-01T00:00:00Z' WHERE id='task'; UPDATE records SET deleted_at='2026-04-01T00:00:00Z',updated_at='2026-04-01T00:00:00Z' WHERE id='c-reply'; DELETE FROM links WHERE id='link-d'; UPDATE instruction_bindings SET source_record_id='epic',position=7 WHERE id='binding-member'; DELETE FROM instruction_bindings WHERE id='binding-workspace'; DROP TABLE control_events; CREATE TABLE control_events(seq INTEGER PRIMARY KEY,id TEXT,aggregate_id TEXT,type TEXT,payload TEXT,actor TEXT,created_at TEXT); INSERT INTO control_events VALUES(1,'w9-binding-remove','binding-workspace','instruction_binding.removed','{}','binding-author','2026-04-01T00:00:00Z'),(2,'w9-binding-retarget','binding-member','instruction_binding.updated','{\"source_record_id\":\"epic\"}','binding-author','2026-04-01T00:00:00Z'); INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('retained-home-delete','retained-home','record.deleted','{}','deleting-author','2026-04-01T00:00:00Z'),('w9-task-delete','task','record.deleted','{}','deleting-author','2026-04-01T00:00:00Z'),('w9-reply-delete','c-reply','record.deleted','{}','deleting-author','2026-04-01T00:00:00Z'),('w9-note-move','note','record.updated','{\"home_id\":\"native:root\"}','editing-author','2026-04-01T00:00:00Z'),('w9-link-remove','task','link.removed','{\"id\":\"link-d\",\"source_id\":\"task\",\"target_id\":\"epic\",\"relationship\":\"part_of\"}','deleting-author','2026-04-01T00:00:00Z')").await.unwrap();
    let mut options = f.options(&[], true);
    options.all = true;
    options.history = true;
    let delta = run(options).await.unwrap();
    assert!(
        delta.refusals.is_empty(),
        "{}",
        serde_json::to_string(&delta.refusals).unwrap()
    );
    assert_eq!(delta.delta["records_tombstoned"], 2);
    assert_eq!(delta.delta["generic_links_removed"], 1);
    assert_eq!(delta.history.streams["content_events"].created, 5);
    assert_eq!(delta.instruction_bindings.disabled_target_deleted, 1);
    assert_eq!(delta.instruction_bindings.updated, 1);
    assert_eq!(delta.delta["instruction_bindings_removed"], 1);
    assert_eq!(delta.history.streams["control_events"].created, 2);
    let rows: Vec<(String,String)> = sqlx::query_as("SELECT id,record_id FROM content_events WHERE id IN ('w9-task-delete','w9-reply-delete','w9-note-move','w9-link-remove') AND type='kernel.legacy_recorded.v1' ORDER BY id").fetch_all(db.pool()).await.unwrap();
    assert_eq!(
        rows,
        vec![
            ("w9-link-remove".into(), "task".into()),
            ("w9-note-move".into(), "note".into()),
            ("w9-reply-delete".into(), "c-reply".into()),
            ("w9-task-delete".into(), "task".into())
        ]
    );
    for id in ["task", "c-reply"] {
        assert!(k::read_record_as(&db, &first.principals["account-a"], id)
            .await
            .unwrap()
            .is_none());
    }
    let retained_anchor: String =
        sqlx::query_scalar("SELECT record_id FROM content_events WHERE id='retained-home-history'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(retained_anchor, derived("retained-home"));
    let new_home_anchor: String =
        sqlx::query_scalar("SELECT record_id FROM content_events WHERE id='retained-home-delete'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(new_home_anchor, retained_anchor);
    for id in ["note", "c-root", "home-child"] {
        assert_eq!(
            k::read_record_as(&db, &first.principals["account-b"], id)
                .await
                .unwrap()
                .unwrap()
                .home_id,
            KERNEL_ROOT_ID
        );
    }
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let task = k::read_imported_snapshot_as(&db, &host, "task")
        .await
        .unwrap()
        .unwrap();
    assert!(task.tombstoned);
    assert_eq!(task.record.body.as_deref(), Some("Final deleted task"));
    assert_eq!(
        k::read_imported_snapshot_as(&db, &host, "c-reply")
            .await
            .unwrap()
            .unwrap()
            .record
            .home_id,
        KERNEL_ROOT_ID
    );
    let target:String=sqlx::query_scalar("SELECT source_record_id FROM kernel_instruction_bindings WHERE id='binding-member' AND enabled=1").fetch_one(db.pool()).await.unwrap();
    assert_eq!(target, "epic");

    let count_before: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.legacy_recorded.v1'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let mut options = f.options(&[], true);
    options.all = true;
    options.history = true;
    let retry = run(options).await.unwrap();
    assert!(
        retry.refusals.is_empty(),
        "{}",
        serde_json::to_string(&retry.refusals).unwrap()
    );
    assert_eq!(retry.updated, 0);
    assert_eq!(retry.instruction_bindings.disabled_target_deleted, 1);
    assert_eq!(retry.instruction_bindings.refused, 0);
    assert!(retry.delta.is_empty());
    assert!(retry
        .history
        .streams
        .values()
        .all(|c| c.created == 0 && c.verified == c.source));
    let count_after: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.legacy_recorded.v1'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count_before, count_after);
    // Physical source-row disappearance is resolved by the same disabled
    // binding evidence; the early all-mode missing-target diagnostic clears.
    source
        .execute("DELETE FROM records WHERE id='task'")
        .await
        .unwrap();
    let mut options = f.options(&[], true);
    options.all = true;
    options.history = true;
    let missing = run(options).await.unwrap();
    assert!(
        missing.refusals.is_empty(),
        "{}",
        serde_json::to_string(&missing.refusals).unwrap()
    );
    assert_eq!(missing.instruction_bindings.disabled_target_deleted, 1);
    assert_eq!(missing.instruction_bindings.refused, 0);
    assert!(missing.history.streams.values().all(|c| c.created == 0));
    let projections = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(projections, k::dump_all_kernel_tables(&db).await.unwrap());
    source.execute("UPDATE content_events SET payload='{\"changed\":true}' WHERE id='retained-home-history'").await.unwrap();
    let mut options = f.options(&[], true);
    options.all = true;
    options.history = true;
    assert!(run(options)
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("retained source history row changed"));
}

#[tokio::test]
async fn imported_history_resume_upgrades_older_targets_and_recovers_disclosure_projections() {
    type DisclosureRow = (i64, String, String, Option<String>, bool, bool, bool);
    let f = Fixture::new().await;
    let first = run(f.options(&["task", "epic"], false)).await.unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    db.write_pool()
        .execute("DROP TABLE kernel_legacy_subjects; DROP TABLE kernel_legacy_history")
        .await
        .unwrap();
    let mut options = f.options(&[], true);
    options.all = true;
    options.history = true;
    let imported = run(options).await.unwrap();
    assert!(
        imported.refusals.is_empty(),
        "{}",
        serde_json::to_string(&imported.refusals).unwrap()
    );
    let total: usize = imported.history.streams.values().map(|c| c.source).sum();
    assert!(total > 0);
    assert_eq!(
        imported
            .history
            .streams
            .values()
            .map(|c| c.created)
            .sum::<usize>(),
        total
    );
    let before: Vec<DisclosureRow> =
        sqlx::query_as("SELECT seq,event_type,subjects,owner,hidden,restricted,claim_sensitive FROM kernel_legacy_history ORDER BY seq")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(before.len(), total);
    let subjects: Vec<(String, i64)> =
        sqlx::query_as("SELECT * FROM kernel_legacy_subjects ORDER BY subject_id,seq")
            .fetch_all(db.pool())
            .await
            .unwrap();
    let events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM content_events WHERE type='kernel.legacy_recorded.v1'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    db.write_pool()
        .execute("DROP TABLE kernel_legacy_subjects")
        .await
        .unwrap();
    let mut options = f.options(&[], true);
    options.all = true;
    options.history = true;
    let recovered = run(options).await.unwrap();
    assert!(recovered.refusals.is_empty());
    assert!(recovered
        .history
        .streams
        .values()
        .all(|c| c.created == 0 && c.verified == c.source));
    let after: Vec<DisclosureRow> =
        sqlx::query_as("SELECT seq,event_type,subjects,owner,hidden,restricted,claim_sensitive FROM kernel_legacy_history ORDER BY seq")
            .fetch_all(db.pool())
            .await
            .unwrap();
    let recovered_subjects: Vec<(String, i64)> =
        sqlx::query_as("SELECT * FROM kernel_legacy_subjects ORDER BY subject_id,seq")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(before, after);
    assert_eq!(subjects, recovered_subjects);
    assert_eq!(
        events,
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM content_events WHERE type='kernel.legacy_recorded.v1'"
        )
        .fetch_one(db.pool())
        .await
        .unwrap()
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[path = "tests/app_state.rs"]
mod app_state;

#[cfg(feature = "v2-kernel-probe")]
async fn catalogue_fixture(f: &Fixture) {
    let mut c = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    c.execute(r#"
 CREATE TABLE vocabularies(id TEXT,name TEXT,created_at TEXT);
 CREATE TABLE vocabulary_values(id TEXT,vocabulary_id TEXT,value TEXT,gloss TEXT,status TEXT,ordinal REAL,terminality TEXT,metadata TEXT,alias_of TEXT);
 CREATE TABLE schema_config(id TEXT,layer TEXT,name TEXT,data TEXT,applies_to_collection_id TEXT,version_lineage TEXT,created_at TEXT);
 INSERT INTO vocabularies VALUES('voc:lifecycle','lifecycle','2026-01-01T00:00:00Z'),('voc:kind:WorkItem','kind:WorkItem','2026-01-01T00:00:00Z'),('custom','custom','2026-01-01T00:00:00Z');
 INSERT INTO vocabulary_values VALUES('open','voc:lifecycle','open',NULL,'active',0,'open','{}',NULL),('done','voc:lifecycle','completed',NULL,'active',1,'terminal_positive','{}',NULL),('alias','voc:lifecycle','done',NULL,'deprecated',2,'terminal_positive','{}','done'),('task','voc:kind:WorkItem','task',NULL,'active',0,'open','{}',NULL),('epic','voc:kind:WorkItem','epic',NULL,'active',1,'open','{}',NULL),('custom-value','custom','preserved',NULL,'active',0.84551240822557006,'open','{"custom":true}',NULL),('kind-alias','voc:kind:WorkItem','task-alias',NULL,'deprecated',2,'open','{}','task');
 INSERT INTO schema_config VALUES('schema','pack',NULL,'{"shapes":{"WorkItem:task":{"facets":{"lifecycle":{"axis":{"key":"work_status","label":"Work status"},"vocab_ref":"lifecycle","required":true}}}}}',NULL,NULL,'2026-01-01T00:00:00Z');
 CREATE TABLE onboarding_programmes(id TEXT,trigger_key TEXT,generation INTEGER,position INTEGER,enabled INTEGER,created_by TEXT,legacy_baseline_before TEXT,created_at TEXT,updated_at TEXT);
 CREATE TABLE onboarding_programme_sources(programme_id TEXT,source_record_id TEXT,source_role TEXT,position INTEGER);
 CREATE TABLE member_obligations(account_id TEXT,programme_id TEXT,generation INTEGER,state TEXT,created_at TEXT,updated_at TEXT,updated_by TEXT,updated_run_key TEXT,reason TEXT);
 CREATE TABLE member_obligation_progress(account_id TEXT,programme_id TEXT,generation INTEGER,phase TEXT,evidence TEXT,resume_after TEXT,artifact_id TEXT,selected_route_id TEXT,updated_at TEXT,updated_by TEXT,updated_run_key TEXT,reason TEXT);
 INSERT INTO onboarding_programmes VALUES('programme','joined',1,0,1,'account-a',NULL,'2026-01-01T00:00:00Z','2026-01-02T00:00:00Z');
 INSERT INTO onboarding_programme_sources VALUES('programme','secret','guidance',0);
 INSERT INTO member_obligations VALUES('account-a','programme',1,'completed','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','account-a','old-run','complete'),('account-b','programme',1,'declined','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z','account-b',NULL,'declined');
 INSERT INTO member_obligation_progress VALUES('account-a','programme',1,'value_delivered','{"test":true}',NULL,'secret','practical_workflow','2026-01-02T00:00:00Z','account-a','old-run','done');
 INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id) VALUES('person-a','Entity','person','private profile','synthetic profile','private','person-a',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'private');
 CREATE TABLE agent_runs(activity_id TEXT,run_key TEXT,account_id TEXT,started_at TEXT,ended_at TEXT,start_event_id TEXT,start_event_seq INTEGER,close_event_id TEXT,close_event_seq INTEGER,reported_mcp_client_name TEXT,reported_mcp_client_version TEXT,reported_model TEXT);
 INSERT INTO agent_runs VALUES('run-id','scout-chair-a749b2','account-a','2026-01-01T00:00:00Z',NULL,'run-start',1,NULL,NULL,'synthetic-client','1','synthetic-model');
 CREATE TABLE read_log_calls(seq INTEGER,id TEXT,tool TEXT,run_key TEXT,actor TEXT,outcome TEXT,intent TEXT,started_at TEXT);
 INSERT INTO read_log_calls VALUES(1,'intent-id','set_intent','scout-chair-a749b2','account-a','ok','synthetic intent','2026-01-01T00:00:01Z'),(2,'ignored-intent','set_intent','scout-chair-a749b2','account-b','ok','wrong actor','2026-01-01T00:00:02Z'),(3,'intent-second','set_intent','scout-chair-a749b2','account-a','ok','second synthetic intent','2026-01-01T00:00:03Z');
 ALTER TABLE records ADD COLUMN claimed_by_account TEXT;
 ALTER TABLE records ADD COLUMN claimed_run_key TEXT;
 ALTER TABLE records ADD COLUMN claimed_at TEXT;
 UPDATE records SET claimed_by_account='account-a',claimed_run_key='scout-chair-a749b2',claimed_at='2026-01-01T00:00:03Z' WHERE id='task';
 INSERT INTO content_events VALUES(99,'orphan-claim','secret','record.updated','{"claimed_by_account":"account-a","claimed_run_key":"scout-chair-a749b3"}','account-a','2026-01-01T00:00:03Z');
 INSERT INTO content_events VALUES(100,'original-claim','task','record.updated','{"claimed_by_account":"account-a","claimed_run_key":"scout-chair-a749b2"}','account-a','2026-01-01T00:00:03Z');
 "#).await.unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_catalogue_interprets_aliases_validates_new_writes_and_replays() {
    let f = Fixture::new().await;
    catalogue_fixture(&f).await;
    let seeds = ["task", "epic", "note", "secret"];
    let r = run(f.options(&seeds, false)).await.unwrap();
    assert!(
        r.refusals.is_empty(),
        "{:?}",
        r.refusals.iter().map(|i| &i.reason).collect::<Vec<_>>()
    );
    assert_eq!(r.state.sections["vocabularies"].verified, 3);
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    let original: f64 =
        sqlx::query_scalar("SELECT ordinal FROM vocabulary_values WHERE id='custom-value'")
            .fetch_one(&mut source)
            .await
            .unwrap();
    let target = f.db().await;
    let retained:f64=sqlx::query_scalar("SELECT json_extract(payload,'$.ordinal') FROM kernel_v1_state WHERE section='vocabulary_values' AND json_extract(payload,'$.id')='custom-value'").fetch_one(target.write_pool()).await.unwrap();
    assert_eq!(original.to_bits(), retained.to_bits());
    let db = f.db().await;
    let get = ordinary_kernel_call(&db, "account-a", "get_record", json!({"ids":["task"]}))
        .await
        .unwrap();
    assert_eq!(
        get["records"][0]["lifecycle_interpretation"]["status"],
        "governed"
    );
    let sql=ordinary_kernel_call(&db,"account-a","query_sql",json!({"sql":"SELECT status,canonical,terminality FROM record_lifecycle_interpretations WHERE record_id='task'"})).await.unwrap();
    assert_eq!(sql["rows"][0]["canonical"], "open");
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"WorkItem","kind":"unknown","name":"synthetic"})
    )
    .await
    .is_ok());
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"task","lifecycle":"unknown"})
    )
    .await
    .is_err());
    ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"task","lifecycle":"done"}),
    )
    .await
    .unwrap();
    let get = ordinary_kernel_call(&db, "account-a", "get_record", json!({"ids":["task"]}))
        .await
        .unwrap();
    assert_eq!(
        get["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "completed"
    );
    assert_eq!(
        get["records"][0]["lifecycle_interpretation"]["terminality"],
        "terminal_positive"
    );
    let new = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"WorkItem","kind":"task","name":"synthetic new task"}),
    )
    .await
    .unwrap();
    assert!(new["id"].is_string());
    assert_eq!(new["lifecycle"], "open");
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"task","lifecycle":null})
    )
    .await
    .is_err());
    let alias = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"WorkItem","kind":"task-alias","name":"synthetic alias","lifecycle":"open"}),
    )
    .await
    .unwrap();
    assert_eq!(alias["kind"], "task");
    let rows = sqlx::query_as::<_, (String, String, String)>(
        "SELECT section,source_id,payload FROM kernel_v1_state ORDER BY section,source_id",
    )
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(
        rows,
        sqlx::query_as::<_, (String, String, String)>(
            "SELECT section,source_id,payload FROM kernel_v1_state ORDER BY section,source_id"
        )
        .fetch_all(db.write_pool())
        .await
        .unwrap()
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_onboarding_completed_state_is_read_only_private_and_retry_stable() {
    let f = Fixture::new().await;
    catalogue_fixture(&f).await;
    let seeds = ["task", "secret"];
    let r = run(f.options(&seeds, false)).await.unwrap();
    assert!(r.refusals.is_empty());
    let db = f.db().await;
    for account in ["account-a", "account-b"] {
        let boot = ordinary_kernel_call(&db, account, "bootstrap", json!({}))
            .await
            .unwrap();
        let p = &boot["pending_obligations"];
        assert_eq!(p["status"], "read_only");
        assert_eq!(p["delivery_enabled"], false);
        assert_eq!(p["pending"].as_array().unwrap().len(), 0);
        assert_eq!(p["states"].as_array().unwrap().len(), 1);
        if account == "account-b" {
            assert_eq!(p["progress"].as_array().unwrap().len(), 0);
            assert_eq!(p["programmes"].as_array().unwrap().len(), 0);
            assert!(!p.to_string().contains("secret"));
        }
    }
    let events = k::history_as(&db, &r.principals["account-b"], KERNEL_ROOT_ID)
        .await
        .unwrap();
    assert!(events
        .iter()
        .all(|e| e.event_type != "kernel.v1_state_imported.v1"));
    let again = run(f.options(&seeds, true)).await.unwrap();
    for c in again.state.sections.values() {
        assert_eq!(c.created + c.updated + c.removed, 0);
    }
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE member_obligations SET state='pending' WHERE account_id='account-b'; DELETE FROM member_obligation_progress;").await.unwrap();
    let resumed = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(resumed.state.sections["member_obligations"].updated, 1);
    assert_eq!(
        resumed.state.sections["member_obligation_progress"].removed,
        1
    );
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let mut conn = db.write_pool().acquire().await.unwrap();
    let value = k::v1_state::rows_on(&mut conn, "member_obligations")
        .await
        .unwrap()
        .pop()
        .unwrap();
    drop(conn);
    let bad = k::v1_state::ImportedState {
        section: "member_obligations".into(),
        source_id: "bad".into(),
        origin: "test-origin".into(),
        value_json: Some(serde_json::to_string(&value).unwrap()),
        account_principal: Some(r.principals["account-a"].clone()),
        record_id: None,
        observed_at: "2026-01-01T00:00:00Z".into(),
        snapshot: json!({}),
    };
    assert!(
        k::v1_state::import_state_batch_as(&db, &host, std::slice::from_ref(&bad))
            .await
            .is_err()
    );
    assert!(
        k::v1_state::import_state_batch_as(&db, &r.principals["account-a"], &[bad])
            .await
            .is_err()
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_runs_intents_claims_are_historical_without_live_authority() {
    let f = Fixture::new().await;
    catalogue_fixture(&f).await;
    let seeds = ["task", "secret", "person-a"];
    let r = run(f.options(&seeds, false)).await.unwrap();
    assert!(r.refusals.is_empty());
    assert_eq!(r.state.claims_held_at_snapshot, 1);
    assert_eq!(r.state.sections["run_intents"].source, 2);
    let db = f.db().await;
    let runs = ordinary_kernel_call(
        &db,
        "account-a",
        "query_sql",
        json!({"sql":"SELECT run_key,ended_at_ms,reported_model,model_assurance FROM runs"}),
    )
    .await
    .unwrap();
    assert_eq!(runs["rows"][0]["model_assurance"], "imported_historical");
    assert!(runs["rows"][0]["ended_at_ms"].is_number());
    let intents = ordinary_kernel_call(
        &db,
        "account-a",
        "query_sql",
        json!({"sql":"SELECT intent FROM run_intents ORDER BY ordinal"}),
    )
    .await
    .unwrap();
    assert_eq!(intents["rows"].as_array().unwrap().len(), 2);
    assert_eq!(intents["rows"][0]["intent"], "synthetic intent");
    let claims = ordinary_kernel_call(
        &db,
        "account-a",
        "query_sql",
        json!({"sql":"SELECT claim_id,is_current,released_at FROM agent_activity_claims"}),
    )
    .await
    .unwrap();
    let claims = claims["rows"].as_array().unwrap();
    assert_eq!(claims.len(), 2);
    assert!(claims
        .iter()
        .all(|claim| claim["is_current"] == 0 && claim["released_at"].is_string()));
    assert!(claims
        .iter()
        .any(|claim| claim["claim_id"] == "original-claim"));
    assert!(claims
        .iter()
        .any(|claim| claim["claim_id"] == "orphan-claim"));
    assert!(
        k::open_run_as(&db, &r.principals["account-a"], "scout-chair-a749b2")
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("historical imported run")
    );
    assert!(
        k::open_run_as(&db, &r.principals["account-a"], "scout-chair-a749b3")
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("historical imported run")
    );
    let hidden = ordinary_kernel_call(
        &db,
        "account-b",
        "query_sql",
        json!({"sql":"SELECT count(*) AS n FROM runs WHERE model_assurance='imported_historical'"}),
    )
    .await
    .unwrap();
    assert_eq!(hidden["rows"][0]["n"], 0);
    let hidden = ordinary_kernel_call(
        &db,
        "account-b",
        "query_sql",
        json!({"sql":"SELECT count(*) AS n FROM run_intents"}),
    )
    .await
    .unwrap();
    assert_eq!(hidden["rows"][0]["n"], 0);
    assert!(ordinary_kernel_call(&db,"account-a","create_record",json!({"run_key":"scout-chair-a749b3","type":"Document","kind":"note","name":"must not replay"})).await.is_err());
    let before = k::claims_as(&db, &r.principals["account-a"], &["task".into()])
        .await
        .unwrap();
    assert!(!before[0].occupied);
    let boot = ordinary_kernel_call(&db, "account-a", "bootstrap", json!({}))
        .await
        .unwrap();
    let claim=ordinary_kernel_call(&db,"account-a","start_work",json!({"run_key":boot["session"]["run_key"],"record_id":"task","operation_key":"fresh-claim"})).await.unwrap();
    assert_eq!(claim["claimed"], true);
    let repeat = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(repeat.state.sections["claims"].unchanged, 2);
    let still = k::claims_as(&db, &r.principals["account-a"], &["task".into()])
        .await
        .unwrap();
    assert!(still[0].occupied);
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE records SET claimed_by_account=NULL,claimed_run_key=NULL,claimed_at=NULL WHERE id='task';INSERT INTO content_events VALUES(101,'released-claim','task','record.updated','{\"claimed_by_account\":null}','account-a','2026-01-02T00:00:00Z');").await.unwrap();
    let released = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(released.state.claims_held_at_snapshot, 0);
    assert_eq!(released.state.sections["claims"].updated, 1);
    source.execute("DELETE FROM read_log_calls WHERE id='intent-id'; INSERT INTO read_log_calls VALUES(4,'intent-third','set_intent','scout-chair-a749b2','account-a','ok','third synthetic intent','2026-01-01T00:00:04Z');").await.unwrap();
    let declarations = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(
        declarations.state.sections["run_intents"].retained_missing_source,
        1
    );
    let ordered = ordinary_kernel_call(
        &db,
        "account-a",
        "query_sql",
        json!({"sql":"SELECT ordinal FROM run_intents ORDER BY ordinal"}),
    )
    .await
    .unwrap();
    assert_eq!(
        ordered["rows"],
        json!([{"ordinal":1},{"ordinal":2},{"ordinal":3}])
    );
    let native_key = boot["session"]["run_key"].as_str().unwrap();
    sqlx::query("INSERT INTO agent_runs VALUES('collision',?,'account-a','2026-01-01T00:00:00Z',NULL,'native-collision',3,NULL,NULL,NULL,NULL,NULL)").bind(native_key).execute(&mut source).await.unwrap();
    let collision = run(f.options(&seeds, true)).await.unwrap();
    assert_eq!(collision.state.sections["runs"].refused, 1);
    assert!(collision
        .refusals
        .iter()
        .any(|i| i.reason.contains("collides with native runtime authority")));
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let legacy = k::LegacyEvent {
        source: None,
        id: "native-key-collision".into(),
        event_type: "synthetic.legacy".into(),
        payload: json!({}),
        created_at: "2026-01-01T00:00:00Z".into(),
        actor: Some("account-a".into()),
        run_key: Some(native_key.into()),
    };
    assert!(k::import_event_as(&db, &host, "task", &legacy)
        .await
        .err()
        .unwrap()
        .to_string()
        .contains("collides with native runtime authority"));
    source
        .execute("DELETE FROM agent_runs WHERE activity_id='collision';")
        .await
        .unwrap();
    source.execute("DELETE FROM agent_runs; DELETE FROM read_log_calls; DELETE FROM content_events WHERE id IN ('original-claim','orphan-claim');").await.unwrap();
    let pruned = run(f.options(&seeds, true)).await.unwrap();
    for (section, expected) in [("runs", 1), ("run_intents", 3), ("claims", 2)] {
        assert_eq!(
            pruned.state.sections[section].retained_missing_source,
            expected
        );
    }
    assert!(
        k::open_run_as(&db, &r.principals["account-a"], "scout-chair-a749b2")
            .await
            .err()
            .unwrap()
            .to_string()
            .contains("historical imported run")
    );
    k::replay_all_projections(&db).await.unwrap();
    assert!(
        k::open_run_as(&db, &r.principals["account-a"], "scout-chair-a749b2")
            .await
            .is_err()
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_uuid_legacy_vocabularies_bypass_only_host_runtime_validation() {
    let f = Fixture::new().await;
    catalogue_fixture(&f).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO vocabulary_values VALUES('retired','voc:lifecycle','retired',NULL,'retired',3,'open','{}',NULL)").await.unwrap();
    let ids: Vec<_> = (1..=4)
        .map(|n| format!("00000000-0000-4000-8000-{n:012}"))
        .collect();
    for (id, life, kind) in [
        (&ids[0], Some("retired"), "task"),
        (&ids[1], Some("unknown"), "task"),
        (&ids[2], None, "task"),
        (&ids[3], Some("open"), "task-alias"),
    ] {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,created_at,updated_at,archived,policy_anchor_id) VALUES(?,'WorkItem',?,'synthetic legacy','legacy body','folder','person-a',?,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root')")
            .bind(id).bind(kind).bind(life).execute(&mut source).await.unwrap();
    }
    let seeds: Vec<_> = ids.iter().map(String::as_str).collect();
    let first = run(f.options(&seeds, false)).await.unwrap();
    assert!(
        first.refusals.is_empty(),
        "{}",
        serde_json::to_string(&first.refusals).unwrap()
    );
    assert_eq!(first.verified, 5);
    let db = f.db().await;
    for id in &ids[..2] {
        let value = ordinary_kernel_call(&db, "account-a", "get_record", json!({"ids":[id]}))
            .await
            .unwrap();
        assert_eq!(
            value["records"][0]["lifecycle_interpretation"]["status"],
            "unclassified"
        );
    }
    let alias = k::read_record_as(&db, &first.principals["account-a"], &ids[3])
        .await
        .unwrap()
        .unwrap();
    assert_eq!(alias.fields["v1_kind"], "task-alias");
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":ids[0],"lifecycle":"runtime-unknown"})
    )
    .await
    .is_err());
    // Sealed resume revisions preserve new unknown evidence too; every id is
    // UUID-shaped and therefore traverses the native-shaped record projector.
    for id in &ids {
        sqlx::query("UPDATE records SET lifecycle='new-unknown',body='changed legacy body',updated_at='2026-01-02T00:00:00Z' WHERE id=?").bind(id).execute(&mut source).await.unwrap();
    }
    let second = run(f.options(&seeds, true)).await.unwrap();
    assert!(
        second.refusals.is_empty(),
        "{}",
        serde_json::to_string(&second.refusals).unwrap()
    );
    assert_eq!(second.verified, 5);
    assert_eq!(second.updated, 4);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_collection_schema_uses_immediate_logical_home_for_reads_and_writes() {
    let f = Fixture::new().await;
    catalogue_fixture(&f).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO schema_config VALUES('scoped','user',NULL,'{\"shapes\":{\"WorkItem:task\":{\"facets\":{\"lifecycle\":{\"axis\":{\"key\":\"scoped_status\",\"label\":\"Scoped status\"},\"vocab_ref\":\"custom\",\"required\":true}}}}}','folder',NULL,'2026-01-02T00:00:00Z'); UPDATE records SET lifecycle='preserved' WHERE id='task'").await.unwrap();
    // Reuse the fixture's exclusive per-record policy: its kernel home is
    // the task itself, but lifecycle schema still belongs to its collection.
    source.execute("UPDATE records SET type='WorkItem',kind='task',home_id='folder',lifecycle='preserved' WHERE id='private'").await.unwrap();
    let r = run(f.options(&["task", "private"], false)).await.unwrap();
    assert!(r.refusals.is_empty());
    let db = f.db().await;
    let get = ordinary_kernel_call(&db, "account-a", "get_record", json!({"ids":["task"]}))
        .await
        .unwrap();
    assert_eq!(
        get["records"][0]["lifecycle_interpretation"]["axis"]["key"],
        "scoped_status"
    );
    let sql=ordinary_kernel_call(&db,"account-a","query_sql",json!({"sql":"SELECT axis_key,canonical FROM record_lifecycle_interpretations WHERE record_id='task'"})).await.unwrap();
    assert_eq!(sql["rows"][0]["axis_key"], "scoped_status");
    assert_eq!(sql["rows"][0]["canonical"], "preserved");
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"task","lifecycle":"open"})
    )
    .await
    .is_err());
    assert!(ordinary_kernel_call(&db,"account-a","create_record",json!({"type":"WorkItem","kind":"task","name":"scoped invalid","home_id":"folder","lifecycle":"open"})).await.is_err());
    assert!(ordinary_kernel_call(&db,"account-a","create_record",json!({"type":"WorkItem","kind":"task","name":"scoped valid","home_id":"folder","lifecycle":"preserved"})).await.is_ok());
    let private = ordinary_kernel_call(&db, "account-a", "get_record", json!({"ids":["private"]}))
        .await
        .unwrap();
    assert_eq!(private["records"][0]["home_id"], "folder");
    assert_eq!(
        private["records"][0]["lifecycle_interpretation"]["axis"]["key"],
        "scoped_status"
    );
    let private_sql=ordinary_kernel_call(&db,"account-a","query_sql",json!({"sql":"SELECT r.home_id,l.axis_key,l.canonical FROM records r JOIN record_lifecycle_interpretations l ON l.record_id=r.id WHERE r.id='private'"})).await.unwrap();
    assert_eq!(
        private_sql["rows"],
        json!([{"home_id":"folder","axis_key":"scoped_status","canonical":"preserved"}])
    );
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":"private","lifecycle":"open"})
    )
    .await
    .is_err());
    ordinary_kernel_call(&db,"account-a","update_record",json!({"id":"private","lifecycle":"preserved","body_append":"\nSynthetic valid scoped edit"})).await.unwrap();
    let hidden = ordinary_kernel_call(&db, "account-b", "get_record", json!({"ids":["private"]}))
        .await
        .unwrap();
    assert_eq!(hidden["records"][0]["status"], "not_found");
    assert!(hidden["records"][0].get("body").is_none());
    // Unscoped root still uses the pack vocabulary.
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"WorkItem","kind":"task","name":"root valid","lifecycle":"open"})
    )
    .await
    .is_ok());
    let root_task = ordinary_kernel_call(
        &db,
        "account-a",
        "create_record",
        json!({"type":"WorkItem","kind":"task","name":"Move schema fixture","lifecycle":"open"}),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let before_move = k::dump_all_kernel_tables(&db).await.unwrap();
    assert!(ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":root_task,"home_id":"folder"})
    )
    .await
    .is_err());
    assert_eq!(before_move, k::dump_all_kernel_tables(&db).await.unwrap());
    ordinary_kernel_call(
        &db,
        "account-a",
        "update_record",
        json!({"id":root_task,"home_id":"folder","lifecycle":"preserved"}),
    )
    .await
    .unwrap();
    let moved = ordinary_kernel_call(&db, "account-a", "get_record", json!({"ids":[root_task]}))
        .await
        .unwrap();
    assert_eq!(moved["records"][0]["home_id"], "folder");
    assert_eq!(
        moved["records"][0]["lifecycle_interpretation"]["axis"]["key"],
        "scoped_status"
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn imported_ambiguous_private_owner_visibility_changes_are_explicit_overrides() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("INSERT INTO bindings VALUES('person-a','account','account-b',1)")
        .await
        .unwrap();
    let r = run(f.options(&["secret"], false)).await.unwrap();
    assert!(r.refusals.is_empty());
    assert!(r.review.is_empty());
    let change = r
        .owner_overrides
        .iter()
        .find(|o| o.record_id == "private")
        .unwrap();
    assert_eq!(change.verified_owner_account, None);
    assert_eq!(
        change.verified_owner_accounts,
        vec!["account-a", "account-b"]
    );
    assert_eq!(change.private_policy_account, "account-a");
    let db = f.db().await;
    assert!(
        k::read_record_as(&db, &r.principals["account-b"], "private")
            .await
            .unwrap()
            .is_none()
    );
    let stamp = snapshot_provenance_as(&db, &r.principals["account-a"], "private")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stamp["owner_override"]["verified_owner_accounts"],
        json!(["account-a", "account-b"])
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_w6_sealed_messages_private_delta_history_and_replay() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute(r#"
      INSERT INTO bindings VALUES('person-a','native-principal','principal-a',1),('person-b','native-principal','principal-b',1);
      INSERT INTO records(id,type,kind,name,body,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id)
      VALUES('person-b','Entity','person','Member','Fixture recipient','native:root','person-b','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root');

      INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,created_at,updated_at,archived,policy_anchor_id) VALUES('w6-message','Message','text','W6','Sealed message body','folder','person-a',NULL,'2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',0,'native:root');
      CREATE TABLE schema_config(id TEXT,layer TEXT,name TEXT,data TEXT,applies_to_collection_id TEXT,version_lineage TEXT,created_at TEXT);
      INSERT INTO schema_config VALUES('work-rules','pack',NULL,'{"shapes":{"WorkItem":{"facets":{"lifecycle":{"vocab":"rec:voc:work-state"}}}}}',NULL,NULL,'2026-01-01T00:00:00Z');
      CREATE TABLE vocabularies(id TEXT,name TEXT);
      INSERT INTO vocabularies VALUES('voc:work-state','work-state');
      CREATE TABLE vocabulary_values(id TEXT,vocabulary_id TEXT,value TEXT,status TEXT,terminality TEXT,alias_of TEXT,ordinal REAL);
      INSERT INTO vocabulary_values VALUES('open','voc:work-state','open','active','open',NULL,0),('done','voc:work-state','done','active','terminal_positive',NULL,1),('finished','voc:work-state','finished','active','open','done',2),('failed','voc:work-state','failed','active','terminal_negative',NULL,3);
      CREATE TABLE member_destinations(subject_account_id TEXT,collection_id TEXT,present INTEGER,joined_at TEXT,joined_by TEXT,version INTEGER);
      INSERT INTO member_destinations VALUES('account-a','folder',1,'2026-01-01T00:00:00Z','explicit',1);
      CREATE TABLE message_audience_state(message_id TEXT,status TEXT);
      INSERT INTO message_audience_state VALUES('w6-message','declared');
      CREATE TABLE message_audiences(message_id TEXT,principal_id TEXT,source TEXT,event_seq INTEGER);
      INSERT INTO message_audiences VALUES('w6-message','principal-a','sender',1);
      CREATE TABLE notification_candidate_events(seq INTEGER PRIMARY KEY,id TEXT,message_id TEXT,recipient_account_id TEXT);
      INSERT INTO notification_candidate_events VALUES(9000,'v1-pending','w6-message','account-a');
      CREATE TABLE notification_candidates(candidate_id TEXT,candidate_key TEXT,recipient_account_id TEXT,message_id TEXT,reason TEXT,priority TEXT,not_before TEXT,redaction_class TEXT,evaluator_kind TEXT,policy_version TEXT,source_event_type TEXT,source_event_id TEXT,candidate_event_seq INTEGER,status TEXT,created_at TEXT);
      INSERT INTO notification_candidates VALUES('v1-pending','v1-key','account-a','w6-message','principal_mention','routine',NULL,'metadata_only','portable_default','messaging-awareness-v1','record.created','w6-created',9000,'effective','2026-01-01T00:00:00Z');
      CREATE TABLE message_preferences(message_id TEXT,subject_account_id TEXT,unread_override INTEGER,muted INTEGER,archived INTEGER,version INTEGER);
      INSERT INTO message_preferences VALUES('w6-message','account-a',1,0,0,1);
      INSERT INTO facet_values VALUES('w6-message','expectation','none',NULL,NULL,'2026-01-01T00:00:00Z');
      INSERT INTO facet_observations VALUES('w6-message','expectation','2026-01-01T00:00:00Z',1);
      INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('w6-created','w6-message','record.created','{}','account-a','2026-01-01T00:00:00Z');
    "#).await.unwrap();
    // Conflicting verified owner loses to the private policy; the override
    // cannot make a policy account outside the audience a reader either.
    source.execute(r#"
      INSERT INTO records(id,type,kind,name,body,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id)
      VALUES('w6-override','Message','text','W6','Sealed','private','person-b','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',0,'private'),
            ('w6-override-empty','Message','text','W6','Sealed','private','person-b','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',0,'private');
      INSERT INTO message_audience_state VALUES('w6-override','declared'),('w6-override-empty','declared');
      INSERT INTO message_audiences VALUES('w6-override','principal-b','sender',1),('w6-override','principal-a','recipient',1),('w6-override-empty','principal-b','sender',1);
      INSERT INTO links VALUES('w6-generic','w6-message','w6-override','derived_from',NULL,'2026-01-01T00:00:00Z'),('w6-relation','w6-message','w6-override','relates_to',NULL,'2026-01-01T00:00:00Z');
      INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES
        ('w6-private-1','w6-override-empty','record.updated','{}','account-b','2026-01-01T00:00:00Z'),
        ('w6-private-2','w6-override-empty','record.updated','{}','account-b','2026-01-01T00:00:00Z'),
        ('w6-private-3','w6-override-empty','record.updated','{}','account-b','2026-01-01T00:00:00Z');
    "#).await.unwrap();
    let mut options = f.options(
        &["w6-message", "w6-override", "w6-override-empty", "person-b"],
        false,
    );
    options.history = true;
    let first = run(options).await.unwrap();
    assert!(
        first.refusals.is_empty(),
        "{}",
        serde_json::to_string(&first.refusals).unwrap()
    );
    assert_eq!(first.message_destinations_verified, 1);
    assert_eq!(first.message_owner_override_visibility.len(), 2);
    assert!(first.message_owner_override_visibility.values().all(|v| *v));
    let db = f.db().await;
    let admin = &first.principals["account-a"];
    let outside = &first.principals["account-b"];
    let pending = ordinary_kernel_call(
        &db,
        "account-a",
        "manage_messages",
        json!({"action":"list_notification_candidates"}),
    )
    .await
    .unwrap();
    assert_eq!(pending["candidates"][0]["candidate_id"], "v1-pending");
    assert_eq!(pending["candidates"][0]["status"], "suppressed");
    assert_eq!(pending["candidates"][0]["assurance"], "imported_historical");
    assert_eq!(pending["candidates"][0]["source_status"], "effective");
    assert!(
        crate::awareness::harvest_host_notification_candidates(&db, "account-a", true, 0, 500)
            .await
            .unwrap()
            .candidates
            .is_empty()
    );
    assert!(
        !crate::awareness::revalidate_host_notification_candidate(
            &db,
            "v1-pending",
            "account-a",
            true
        )
        .await
        .unwrap()
        .unwrap()
        .effective_viewable_unmuted
    );
    let old_cursor = 9000;
    let native=ordinary_kernel_call(&db,"account-a","manage_messages",json!({"action":"send","body":"New after cutover","addressed_to":["person-b"],"expectation":"ack","origin":{"type":"collection","collection_id":"native:root"},"idempotency_key":"w6b-after-import","reason":"Candidate cutover proof"})).await.unwrap();
    let fresh = crate::awareness::harvest_host_notification_candidates(
        &db,
        "account-b",
        true,
        old_cursor,
        500,
    )
    .await
    .unwrap();
    assert_eq!(fresh.candidates.len(), 1);
    assert!(fresh.scanned_through > old_cursor);
    assert_eq!(
        crate::awareness::host_live_notification_candidate_message_id(
            &db,
            &fresh.candidates[0].candidate_id
        )
        .await
        .unwrap(),
        native["id"].as_str().map(str::to_owned)
    );

    assert_eq!(first.links_by_relationship["derived_from"].verified, 1);
    assert_eq!(first.links_by_relationship["relates_to"].refused, 0);
    let transform = k::resolve_principal_by_binding(&db, "host:relates-to:transform")
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(k::read_record_as(&db, &transform, "w6-message")
        .await
        .unwrap()
        .is_none());
    assert!(k::relations_as(&db, &transform, "w6-message")
        .await
        .unwrap()
        .is_empty());
    assert!(k::prepare_provider_as(
        &db,
        &transform,
        "w6-message",
        "w6-override",
        "outside-import",
        standard::relates_to::Command::Assert {
            sources: vec![standard::relates_to::Source {
                source_id: "scoped-test-source".into(),
                from: "w6-message".into(),
                to: "w6-override".into(),
                claimed_author: None,
                claimed_timestamp: None,
                note: None
            }]
        }
    )
    .await
    .is_err());
    assert_eq!(
        k::kernel_effective_capability(&db, admin, "w6-override")
            .await
            .unwrap(),
        crate::authorization::Capability::Manage
    );
    assert!(k::read_record_as(&db, outside, "w6-message")
        .await
        .unwrap()
        .is_some());
    assert!(!k::history_as(&db, outside, "w6-message")
        .await
        .unwrap()
        .is_empty());
    assert!(k::read_record_as(&db, admin, "w6-override-empty")
        .await
        .unwrap()
        .is_some());
    assert!(k::read_record_as(&db, outside, "w6-override")
        .await
        .unwrap()
        .is_none());
    assert_eq!(first.message_v2_visible_but_v1_hidden, 0);
    assert_eq!(first.message_v1_visible_but_v2_denied, 0);
    // A W5 target may already retain Message history on its public policy
    // home. Upgrade only disclosure facts, never rewrite the old envelope.
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let home = &first.homes["folder"];
    let mut policies = Vec::new();
    for root in [KERNEL_ROOT_ID, first.homes["private"].as_str()] {
        let entries: Vec<(String,String)> = sqlx::query_as("SELECT subject_id,capability FROM kernel_policy_entries WHERE root_id=? AND subject_kind='account' AND effect='allow' ORDER BY subject_id,capability")
            .bind(root).fetch_all(db.pool()).await.unwrap();
        let mut temporary = entries.clone();
        temporary.push((transform.clone(), "edit".into()));
        k::import_home_policy_as(
            &db,
            &host,
            root,
            &temporary
                .iter()
                .map(|(p, c)| (p.as_str(), c.as_str()))
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap();
        policies.push((root.to_owned(), entries));
    }
    let prepared = k::prepare_provider_as(
        &db,
        &transform,
        "w6-message",
        "w6-override",
        "scoped-import-proof",
        standard::relates_to::Command::Assert {
            sources: vec![standard::relates_to::Source {
                source_id: "scoped-test-source".into(),
                from: "w6-message".into(),
                to: "w6-override".into(),
                claimed_author: None,
                claimed_timestamp: None,
                note: None,
            }],
        },
    )
    .await
    .unwrap();
    assert!(k::read_record_as(&db, &transform, "w6-message")
        .await
        .unwrap()
        .is_none());
    assert!(k::relations_as(&db, &transform, "w6-message")
        .await
        .unwrap()
        .is_empty());
    assert!(
        k::generic_links_as(&db, &transform, "w6-message", false, None, None, 100)
            .await
            .unwrap()
            .links
            .is_empty()
    );
    for (root, entries) in policies {
        k::import_home_policy_as(
            &db,
            &host,
            &root,
            &entries
                .iter()
                .map(|(p, c)| (p.as_str(), c.as_str()))
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap();
    }
    assert!(k::commit_provider_as(&db, &transform, &prepared)
        .await
        .is_err());
    let link = k::GenericLink {
        link_id: "w6-generic".into(),
        source_id: "w6-message".into(),
        target_id: "w6-override".into(),
        relationship: "derived_from".into(),
        note: None,
        created_at: "2026-01-01T00:00:00Z".into(),
        actor: None,
    };
    assert!(k::read_imported_generic_link_as(&db, admin, &link)
        .await
        .is_err());
    assert!(k::read_imported_generic_link_as(&db, &host, &link)
        .await
        .unwrap()
        .is_some());
    for (id, stream, payload) in [
        (
            "w6-old-home",
            "content_events",
            json!({"body":"old sealed body"}),
        ),
        (
            "w6-old-link",
            "content_events",
            json!({"target_id":"w6-override"}),
        ),
        ("w6-old-removal", "relationship_events", json!({})),
    ] {
        k::import_event_as(&db, &host, home, &k::LegacyEvent {
            source: Some(json!({"stream":stream,"subjects":[home],"metadata":{"record_id":if id == "w6-old-home" { Some("w6-override") } else { None }}})),
            id:id.into(),event_type:"record.updated".into(),payload,
            created_at:"2026-01-01T00:00:00Z".into(),actor:Some("account-a".into()),run_key:None,
        }).await.unwrap();
    }
    let envelopes: Vec<(String, String)> = sqlx::query_as(
        "SELECT id,payload FROM content_events WHERE id LIKE 'w6-old-%' ORDER BY id",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    db.write_pool().execute("UPDATE kernel_legacy_history SET subjects=json_array((SELECT home_id FROM kernel_records WHERE id='w6-message')) WHERE seq IN (SELECT seq FROM content_events WHERE id LIKE 'w6-old-%'); ALTER TABLE kernel_legacy_history DROP COLUMN disclosure_version")
        .await.unwrap();
    k::ensure_record_metadata(&db).await.unwrap();
    assert_eq!(
        envelopes,
        sqlx::query_as::<_, (String, String)>(
            "SELECT id,payload FROM content_events WHERE id LIKE 'w6-old-%' ORDER BY id"
        )
        .fetch_all(db.pool())
        .await
        .unwrap()
    );
    for event in k::history_as(&db, outside, home).await.unwrap() {
        assert!(!event.id.starts_with("w6-old-"));
    }
    let allowed = k::history_as(&db, admin, home).await.unwrap();
    assert!(allowed.iter().any(|e| e.id == "w6-old-home"));
    assert!(!allowed.iter().any(|e| e.id == "w6-old-removal"));
    let mut tx = db.pool().begin().await.unwrap();
    let state = k::messaging::on(&mut tx, "w6-message")
        .await
        .unwrap()
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(state.private[admin]["preference"]["unread_override"], 1);
    assert_eq!(state.expectations[admin]["state"], "not_required");
    let positive = &state.rules.as_ref().unwrap().positive["voc:work-state"];
    assert!(
        positive.contains("done") && positive.contains("finished") && !positive.contains("failed")
    );

    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let mut options = f.options(&["w6-message", "w6-override", "w6-override-empty"], true);
    options.history = true;
    run(options).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    // Awareness-only deltas have no content-head movement; they still reconcile.
    source.execute("UPDATE message_preferences SET unread_override=0,version=2 WHERE message_id='w6-message'").await.unwrap();
    let mut options = f.options(&["w6-message", "w6-override", "w6-override-empty"], true);
    options.history = true;
    let resumed = run(options).await.unwrap();
    assert!(resumed.refusals.is_empty());
    assert_eq!(resumed.updated, 1);
    let mut tx = db.pool().begin().await.unwrap();
    let state = k::messaging::on(&mut tx, "w6-message")
        .await
        .unwrap()
        .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(state.private[admin]["preference"]["unread_override"], 0);
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    let mut registry = crate::mcp::registry::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let events = registry
        .call_engine(
            crate::mcp::registry::EngineHandle::KernelV2(db.clone()),
            crate::mcp::registry::Caller::authenticated("account-b"),
            "query_sql",
            json!({"sql":"SELECT id FROM content_events WHERE id LIKE 'w6-old-%'"}),
        )
        .await
        .unwrap();
    assert_eq!(events["rows"], json!([]));
    registry.call_engine(crate::mcp::registry::EngineHandle::KernelV2(db.clone()),crate::mcp::registry::Caller::authenticated("account-a"),"manage_messages",json!({"action":"set_preference","message_id":"w6-message","preference":"mark_unread","expected_version":2,"idempotency_key":"native-read","reason":"Private edit proof"})).await.unwrap();
    let review = run(f.options(&["w6-message", "w6-override", "w6-override-empty"], true))
        .await
        .unwrap();
    assert!(!review.refusals.is_empty());
    source
        .execute("UPDATE records SET deleted_at='2026-04-01T00:00:00Z' WHERE id='w6-message'")
        .await
        .unwrap();
    let mut fresh = f.options(&["w6-message"], false);
    fresh.target = f.target.with_file_name("deleted-first.db");
    fresh.history = true;
    let path = fresh.target.clone();
    let result = run(fresh).await.unwrap();
    assert!(result.refusals.is_empty());
    assert_eq!(result.tombstones_verified, 1);
    let deleted = crate::db::open_database(path.to_str().unwrap())
        .await
        .unwrap();
    for principal in result.principals.values() {
        assert!(k::read_record_as(&deleted, principal, "w6-message")
            .await
            .unwrap()
            .is_none());
    }
    let mut snapshot = deleted.pool().begin().await.unwrap();
    assert!(k::messaging::on(&mut snapshot, "w6-message")
        .await
        .unwrap()
        .is_some());
    snapshot.rollback().await.unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_hosted_member_policy_provenance_tracks_live_catalogue_members() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute("INSERT INTO record_policies VALUES('folder'),('message-home'); INSERT INTO policy_entries VALUES('folder','members','native:members','view'),('message-home','account','account-b','manage'); UPDATE records SET policy_anchor_id='folder' WHERE id IN ('folder','task')").await.unwrap();
    source.execute("INSERT INTO records(id,type,kind,name,home_id,owner_id,lifecycle,policy_anchor_id,archived,created_at,updated_at) VALUES('person-a','Entity','person','Owner','native:root','person-a','open','native:root',0,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),('person-b','Entity','person','Member','native:root','person-b','open','native:root',0,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'),('message-home','Collection','folder','Private conversation','native:root','person-b','open','message-home',0,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z'); INSERT INTO bindings VALUES('person-a','email','owner@example.test',1),('person-b','email','member@example.test',0)").await.unwrap();
    source.close().await.unwrap();
    let report = run(f.options(&["task", "private", "message-home"], false))
        .await
        .unwrap();
    assert!(report.refusals.is_empty());
    let db = f.db().await;
    // The current CLI excludes Message seeds. Exercise its exact compatibility
    // carrier through the sealed snapshot port, without widening importer scope.
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let definition = crate::v2_standard::v1_compat::package()
        .definitions
        .remove(0);
    k::import_record_as(
        &db,
        &host,
        "private-message",
        &report.homes["message-home"],
        Some(&report.principals["account-b"]),
        &k::ImportRecordState {
            definition: Some(k::ImportDefinition {
                pin: crate::meta::definition_artifact::RevisionIdentity {
                    family: definition.family,
                    version: definition.version,
                    digest: definition.digest,
                },
                primary_type: "V1".into(),
                kind: "record".into(),
                fields: crate::v2_standard::v1_compat::compat_fields(
                    "Message",
                    "message",
                    Some("Private message"),
                    None,
                    None,
                ),
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let directory = [
        ("catalog-owner".to_owned(), "owner@example.test".to_owned()),
        (
            "catalog-member".to_owned(),
            "member@example.test".to_owned(),
        ),
    ]
    .into_iter()
    .collect::<std::collections::BTreeMap<_, _>>();
    let existing = k::hosted_identity::reconcile_hosted_caller(&db, |_| async {
        // SAFETY: complete fixture catalogue for the original imported roster.
        Ok(unsafe {
            k::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                "catalog-member".into(),
                [
                    ("catalog-owner".to_owned(), "owner@example.test".to_owned()),
                    (
                        "catalog-member".to_owned(),
                        "member@example.test".to_owned(),
                    ),
                ]
                .into_iter()
                .collect(),
                directory.clone(),
            )
        })
    })
    .await
    .unwrap();
    assert_eq!(existing.credential(), "account-b");
    assert_eq!(
        k::resolve_principal_by_binding(&db, existing.credential())
            .await
            .unwrap()
            .unwrap()
            .0,
        report.principals["account-b"]
    );
    let recipient = &report.principals["account-a"];
    let author = &report.principals["account-b"];
    let envelope: String =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id='private-message'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_ne!(
        envelope, "Message",
        "regression must use the imported carrier"
    );
    assert_eq!(
        k::kernel_effective_capability(&db, recipient, "private-message")
            .await
            .unwrap(),
        crate::authorization::Capability::None
    );
    let caller = k::hosted_identity::reconcile_hosted_caller(&db, |_| async {
        // SAFETY: fixture-owned complete catalogue, including post-import join.
        Ok(unsafe {
            k::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                "joined-after-import".into(),
                [
                    ("catalog-owner".to_owned(), "owner@example.test".to_owned()),
                    (
                        "joined-after-import".to_owned(),
                        "joined@example.test".to_owned(),
                    ),
                ]
                .into_iter()
                .collect(),
                std::collections::BTreeMap::new(),
            )
        })
    })
    .await
    .unwrap();
    // SAFETY: the synthetic catalogue fenced the member above; its owner is
    // the persisted operation's transfer recipient, not caller-selected input.
    let cleanup = unsafe {
        k::hosted_identity::offboarding::VerifiedOffboarding::from_catalog_unchecked(
            uuid::Uuid::new_v4().to_string(),
            "catalog-owner".into(),
            "catalog-member".into(),
            "catalog-owner".into(),
            "member removed".into(),
        )
    };
    let counts = k::hosted_identity::offboarding::apply(&db, cleanup)
        .await
        .unwrap();
    assert_eq!(counts.retained_authorship_count, 1);
    for replay in [false, true] {
        if replay {
            k::replay_all_projections(&db).await.unwrap();
        }
        let owner: String =
            sqlx::query_scalar("SELECT owner_id FROM kernel_records WHERE id='private-message'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            &owner, author,
            "Message authorship survives cleanup and replay"
        );
        assert_eq!(
            k::kernel_effective_capability(&db, recipient, "private-message")
                .await
                .unwrap(),
            crate::authorization::Capability::None
        );
        assert!(k::read_record_as(&db, recipient, "private-message")
            .await
            .unwrap()
            .is_none());
    }
    let joined = k::resolve_principal_by_binding(&db, caller.credential())
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(k::kernel_effective_capability(&db, &joined, "task")
        .await
        .unwrap()
        .allows(crate::authorization::Capability::View));
    assert_eq!(
        k::kernel_effective_capability(&db, &joined, &report.homes["private"])
            .await
            .unwrap(),
        crate::authorization::Capability::None
    );
    assert_eq!(
        k::kernel_effective_capability(&db, &joined, "task")
            .await
            .unwrap(),
        crate::authorization::Capability::View
    );
    assert_eq!(
        k::kernel_effective_capability(&db, &joined, KERNEL_ROOT_ID)
            .await
            .unwrap(),
        crate::authorization::Capability::Edit
    );
    let (hits, _) = k::search_v2::search_as(&db, &joined, "task", 10, false)
        .await
        .unwrap();
    assert!(
        hits.iter().any(|hit| hit.id == "task"),
        "cached search policy must include new members"
    );
    k::replay_all_projections(&db).await.unwrap();
    assert!(k::kernel_effective_capability(&db, &joined, "task")
        .await
        .unwrap()
        .allows(crate::authorization::Capability::View));
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(k::import_members_roster_as(&db, &host, None).await.is_err());
    db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_workspace_metadata_is_idempotent_and_delta_updated() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("UPDATE records SET name='HQ',summary='Shared workspace' WHERE id='native:root'")
        .await
        .unwrap();
    let first = run(f.options(&["note"], false)).await.unwrap();
    assert!(
        first.refusals.is_empty(),
        "{}",
        serde_json::to_string(&first.refusals).unwrap()
    );
    let db = f.db().await;
    let metadata = k::workspace_metadata::read(&db).await.unwrap().unwrap();
    assert_eq!(metadata.name, "HQ");
    assert_eq!(metadata.summary.as_deref(), Some("Shared workspace"));
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events WHERE type='kernel.workspace_metadata_imported.v1'").fetch_one(db.pool()).await.unwrap()
    };
    assert_eq!(count().await, 1);
    run(f.options(&["note"], true)).await.unwrap();
    assert_eq!(
        count().await,
        1,
        "unchanged resume must not mint metadata events"
    );
    source
        .execute("UPDATE records SET name='HQ renamed' WHERE id='native:root'")
        .await
        .unwrap();
    run(f.options(&["note"], true)).await.unwrap();
    assert_eq!(count().await, 2);
    assert_eq!(
        k::workspace_metadata::read(&db)
            .await
            .unwrap()
            .unwrap()
            .name,
        "HQ renamed"
    );
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(
        k::workspace_metadata::read(&db)
            .await
            .unwrap()
            .unwrap()
            .name,
        "HQ renamed"
    );
    let actor: String = sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
        .bind(KERNEL_ROOT_ID)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(
        k::read_record_as(&db, &actor, k::workspace_metadata::RECORD_ID)
            .await
            .unwrap()
            .is_none()
    );
    assert!(k::workspace_metadata::import_as(
        &db,
        &actor,
        k::workspace_metadata::WorkspaceMetadata {
            name: "Spoof".into(),
            source_root_id: V1_ROOT.into(),
            summary: None,
        }
    )
    .await
    .is_err());
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_hosted_kernel_v2_tools(&mut registry).unwrap();
    let bootstrap = registry
        .call_engine(
            crate::mcp::registry::EngineHandle::KernelV2(db.clone()),
            crate::mcp::Caller::authenticated("account-a"),
            "bootstrap",
            json!({}),
        )
        .await
        .unwrap();
    assert_eq!(
        bootstrap["workspace"]["primary_workspace"]["name"],
        "HQ renamed"
    );
    source.close().await.unwrap();
    db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_app_authors_follow_visible_person_for_non_root_members() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect_with(
        &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
    )
    .await
    .unwrap();
    source.execute(r#"
      DELETE FROM policy_entries WHERE policy_anchor_id='native:root' AND subject_kind='members';
      INSERT INTO record_policies VALUES('folder');
      INSERT INTO policy_entries VALUES('folder','account','account-a','manage'),('folder','account','account-b','view');
      UPDATE records SET policy_anchor_id='folder' WHERE id IN ('folder','note');
      INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id,deleted_at)
      VALUES('person-a','Entity','person','Visible Author',NULL,'folder','person-a',NULL,NULL,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'folder',NULL);
      INSERT INTO content_events(id,record_id,type,payload,actor,created_at)
      VALUES('app-author-event','note','record.updated','{}','account-a','2026-01-01T00:00:00Z');
    "#).await.unwrap();
    let mut options = f.options(&["note", "person-a"], false);
    options.history = true;
    let report = run(options).await.unwrap();
    let db = f.db().await;
    let member = &report.principals["account-b"];
    assert!(!k::kernel_effective_capability_on(
        &mut db.write_pool().acquire().await.unwrap(),
        member,
        KERNEL_ROOT_ID
    )
    .await
    .unwrap()
    .allows(crate::authorization::Capability::View));
    let profile = k::read_record_as(&db, member, "person-a").await.unwrap();
    assert!(profile.is_some(), "the member must see the author profile");
    let query = || json!({"sql":"SELECT e.actor,a.person_id,a.display_name FROM content_events e LEFT JOIN actors a ON e.actor=a.actor WHERE e.id='app-author-event'"});
    let visible = ordinary_kernel_call(&db, "account-b", "query_sql", query())
        .await
        .unwrap();
    assert_eq!(visible["rows"].as_array().unwrap().len(), 1, "{visible}");
    assert_eq!(visible["rows"][0]["actor"], "v1:account-a");
    assert_eq!(visible["rows"][0]["person_id"], "person-a");
    assert_eq!(visible["rows"][0]["display_name"], "Visible Author");
    source
        .execute(
            "UPDATE records SET home_id='private',policy_anchor_id='private' WHERE id='person-a'",
        )
        .await
        .unwrap();
    let mut options = f.options(&["note", "person-a"], true);
    options.history = true;
    run(options).await.unwrap();
    let hidden = ordinary_kernel_call(&db, "account-b", "query_sql", query())
        .await
        .unwrap();
    assert_eq!(hidden["rows"].as_array().unwrap().len(), 1);
    assert!(hidden["rows"][0]["actor"].is_null());
    assert!(hidden["rows"][0]["display_name"].is_null());
    db.close().await;
}

#[tokio::test]
async fn imported_attachment_refuses_missing_or_duplicate_bearers_before_blob_binding() {
    for bearers in [0, 2] {
        let f = Fixture::new().await;
        let mut source = SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new().filename(&f.source),
        )
        .await
        .unwrap();
        source.execute("INSERT INTO records(id,type,kind,name,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id) VALUES('bad-attachment','Document','attachment','Fixture','folder','person-a','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root')").await.unwrap();
        for index in 0..bearers {
            sqlx::query("INSERT INTO links VALUES(?,'bad-attachment','folder','part_of',NULL,'2026-01-01T00:00:00Z')").bind(format!("bad-bearer-{index}")).execute(&mut source).await.unwrap();
        }
        source.close().await.unwrap();
        let report = run(f.options(&["bad-attachment"], false)).await.unwrap();
        assert!(!report.verified_ids.iter().any(|id| id == "bad-attachment"));
        if bearers == 0 {
            assert!(report.refusals.is_empty());
            assert_eq!(report.excluded_invisible_in_v1, 1);
            assert!(report
                .counted
                .iter()
                .any(|i| i.id == "bad-attachment" && i.reason == "excluded_invisible_in_v1"));
        } else {
            assert!(
                report
                    .refusals
                    .iter()
                    .any(|issue| issue.id == "bad-attachment"
                        && issue
                            .reason
                            .contains(&format!("exactly one part_of bearer; found {bearers}"))),
                "{}",
                serde_json::to_string(&report).unwrap()
            );
        }
        let target = crate::db::open_database(f.target.to_str().unwrap())
            .await
            .unwrap();
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id='bad-attachment')",
        )
        .fetch_one(target.pool())
        .await
        .unwrap();
        assert!(!exists);
        let blobs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_blobs")
            .fetch_one(target.pool())
            .await
            .unwrap();
        let bindings: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_attachment_blobs")
            .fetch_one(target.pool())
            .await
            .unwrap();
        assert_eq!((blobs, bindings), (0, 0));
        target.close().await;
    }
}

#[cfg(feature = "v2-kernel-probe")]
async fn add_derived_attachment(f: &Fixture, id: &str, bearer: &str, owner: &str) {
    use sha2::{Digest, Sha256};
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("CREATE TABLE IF NOT EXISTS blobs(id TEXT PRIMARY KEY,bytes BLOB,mime TEXT,size_bytes INTEGER,sha256 TEXT,original_filename TEXT,storage_tier TEXT,created_at TEXT)").await.unwrap();
    sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id) VALUES(?,'Document','attachment','Derivedneedle','Derivedneedle text','folder',?,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root')").bind(id).bind(owner).execute(&mut source).await.unwrap();
    let bytes = b"Derivedneedle bytes";
    sqlx::query("INSERT INTO blobs VALUES(?,?,'text/plain',?,?,'synthetic.txt','inline','2026-01-01T00:00:00Z')").bind(id).bind(bytes.as_slice()).bind(bytes.len() as i64).bind(hex::encode(Sha256::digest(bytes))).execute(&mut source).await.unwrap();
    sqlx::query(
        "INSERT INTO facet_values VALUES(?,'blob_ref',?,NULL,NULL,'2026-01-01T00:00:00Z');",
    )
    .bind(id)
    .bind(id)
    .execute(&mut source)
    .await
    .unwrap();
    sqlx::query("INSERT INTO facet_observations VALUES(?,'blob_ref','2026-01-01T00:00:00Z',1)")
        .bind(id)
        .execute(&mut source)
        .await
        .unwrap();
    sqlx::query("INSERT INTO links VALUES(?,?,?,'part_of',NULL,'2026-01-01T00:00:00Z')")
        .bind(format!("bearer-{id}"))
        .bind(id)
        .bind(bearer)
        .execute(&mut source)
        .await
        .unwrap();
    source.close().await.unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
async fn assert_private_derived_surfaces(db: &Db, id: &str, bearer: &str) {
    for (account, visible) in [("account-a", true), ("account-b", false)] {
        let get = ordinary_kernel_call(db, account, "get_record", json!({"ids":[id]}))
            .await
            .unwrap();
        assert_eq!(get["records"][0]["status"] != "not_found", visible);
        let sql = ordinary_kernel_call(
            db,
            account,
            "query_sql",
            json!({"sql":"SELECT id FROM records"}),
        )
        .await
        .unwrap();
        assert_eq!(
            sql["rows"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["id"] == id),
            visible
        );
        let search = ordinary_kernel_call(db, account, "search", json!({"query":"Derivedneedle"}))
            .await
            .unwrap();
        assert_eq!(
            search["hits"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["id"] == id),
            visible
        );
        let links = ordinary_kernel_call(
            db,
            account,
            "manage_links",
            json!({"action":"list","record_id":id}),
        )
        .await;
        if visible {
            assert!(links.unwrap()["links"]
                .as_array()
                .unwrap()
                .iter()
                .any(|l| l["target_id"] == bearer));
        } else if let Ok(links) = links {
            assert!(links["links"].as_array().unwrap().is_empty());
        }
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_stale_anchor_attachment_follows_terminal_home_and_visibility() {
    let f = Fixture::new().await;
    add_derived_attachment(&f, "stale-attachment", "secret", "person-a").await;
    let report = run(f.options(&["stale-attachment"], false)).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report).unwrap()
    );
    assert_eq!(report.derived_replaced["attachments"], 1);
    let db = f.db().await;
    assert_private_derived_surfaces(&db, "stale-attachment", "secret").await;
    let home: String =
        sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id='stale-attachment'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(home, derived("private"));
    let resumed = run(f.options(&["stale-attachment"], true)).await.unwrap();
    assert!(resumed.refusals.is_empty());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_attachment_uploader_does_not_override_bearer_visibility() {
    let f = Fixture::new().await;
    add_derived_attachment(&f, "other-uploader", "secret", "person-b").await;
    let report = run(f.options(&["other-uploader"], false)).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report).unwrap()
    );
    let db = f.db().await;
    let owner: String =
        sqlx::query_scalar("SELECT owner_id FROM kernel_records WHERE id='other-uploader'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(owner, report.principals["account-b"]);
    assert_private_derived_surfaces(&db, "other-uploader", "secret").await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_noncomment_annotation_without_any_bearer_is_refused() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO records(id,type,kind,name,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id) VALUES('unbound-annotation','Annotation','suggestion','Derivedneedle','folder','person-b','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root')").await.unwrap();
    source.close().await.unwrap();
    let report = run(f.options(&["unbound-annotation"], false))
        .await
        .unwrap();
    assert!(report.refusals.iter().any(
        |r| r.id == "unbound-annotation" && r.reason.contains("exactly one live part_of chain")
    ));
    assert!(!report
        .verified_ids
        .iter()
        .any(|id| id == "unbound-annotation"));
    assert_eq!(report.derived_refused.values().sum::<usize>(), 1);
}

/// Normal CI exercises a small shape. The explicitly selected 10k run measures
/// the same public/private topology without using any private workspace data.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_hq_shaped_derived_visibility_counts_and_timings() {
    use sha2::{Digest, Sha256};
    let total: usize = std::env::var("NATIVE_SYNTHETIC_IMPORT_RECORDS")
        .ok()
        .map(|v| v.parse().unwrap())
        .unwrap_or(64);
    assert!((64..=100_000).contains(&total));
    let derived_each = total * 15 / 100;
    let malformed = if total >= 10_000 { 10 } else { 2 };
    let ordinary = total - 2 * derived_each - malformed;
    let folders = (ordinary / 100).clamp(2, 96);
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("CREATE TABLE blobs(id TEXT PRIMARY KEY,bytes BLOB,mime TEXT,size_bytes INTEGER,sha256 TEXT,original_filename TEXT,storage_tier TEXT,created_at TEXT); UPDATE records SET owner_id='person-a' WHERE id='epic'; BEGIN IMMEDIATE").await.unwrap();
    let bytes = b"Derivedbenchmark synthetic bytes";
    sqlx::query("INSERT INTO blobs VALUES('shared',?,'text/plain',?,?,'synthetic.txt','inline','2026-01-01T00:00:00Z')").bind(bytes.as_slice()).bind(bytes.len() as i64).bind(hex::encode(Sha256::digest(bytes))).execute(&mut source).await.unwrap();
    let notes = ordinary - 8 - folders;
    for index in 0..(total - 8) {
        let id = format!("synthetic-{index}");
        let (typ, kind, home, anchor, owner) = if index < folders {
            (
                "Collection",
                "folder",
                if index.is_multiple_of(2) {
                    "private".to_owned()
                } else {
                    "folder".to_owned()
                },
                if index.is_multiple_of(2) {
                    "private"
                } else {
                    V1_ROOT
                },
                "person-a",
            )
        } else if index < folders + notes {
            let folder = (index - folders) % folders;
            (
                "Document",
                "note",
                format!("synthetic-{folder}"),
                if folder.is_multiple_of(2) {
                    "private"
                } else {
                    V1_ROOT
                },
                "person-a",
            )
        } else {
            let derived_index = index - folders - notes;
            let target = folders + derived_index % notes;
            let private = ((target - folders) % folders).is_multiple_of(2);
            (
                if derived_index < derived_each {
                    "Document"
                } else {
                    "Annotation"
                },
                if derived_index < derived_each {
                    "attachment"
                } else if derived_index.is_multiple_of(2) {
                    "comment"
                } else {
                    "suggestion"
                },
                if private {
                    "folder".to_owned()
                } else {
                    "private".to_owned()
                },
                if private { V1_ROOT } else { "private" },
                "person-b",
            )
        };
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id) VALUES(?,?,?,'Derivedbenchmark','Derivedbenchmark synthetic text',?,?,'2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,?)").bind(&id).bind(typ).bind(kind).bind(home).bind(owner).bind(anchor).execute(&mut source).await.unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'record.created','{}','synthetic-author','2026-01-01T00:00:00Z')").bind(format!("event-{index}")).bind(&id).execute(&mut source).await.unwrap();
        if index >= folders + notes {
            let derived_index = index - folders - notes;
            if derived_index < 2 * derived_each {
                sqlx::query(
                    "INSERT INTO links VALUES(?,?,?,'part_of',NULL,'2026-01-01T00:00:00Z')",
                )
                .bind(format!("link-{index}"))
                .bind(&id)
                .bind(format!("synthetic-{}", folders + derived_index % notes))
                .execute(&mut source)
                .await
                .unwrap();
            }
            if typ == "Document" {
                sqlx::query("INSERT INTO facet_values VALUES(?,'blob_ref','shared',NULL,NULL,'2026-01-01T00:00:00Z')").bind(&id).execute(&mut source).await.unwrap();
                sqlx::query(
                    "INSERT INTO facet_observations VALUES(?,'blob_ref','2026-01-01T00:00:00Z',1)",
                )
                .bind(&id)
                .execute(&mut source)
                .await
                .unwrap();
            }
        }
    }
    source.execute("COMMIT").await.unwrap();
    source.close().await.unwrap();
    let mut options = f.options(&[], false);
    options.all = true;
    options.history = true;
    let started = Instant::now();
    let report = run(options).await.unwrap();
    let import_seconds = started.elapsed().as_secs_f64();
    assert_eq!(
        report.refusals.len(),
        malformed,
        "{}",
        serde_json::to_string(&report).unwrap()
    );
    assert!(report.refusals.iter().all(|r| r.reason.contains("part_of")));
    assert!(report.review.is_empty());
    assert_eq!(
        report.derived_replaced.get("attachments"),
        Some(&derived_each)
    );
    assert_eq!(
        report.derived_replaced.get("annotations"),
        Some(&derived_each)
    );
    let db = f.db().await;
    let mut timings = BTreeMap::<String, Vec<f64>>::new();
    for account in ["account-a", "account-b"] {
        for _ in 0..5 {
            for (tool, args) in [
                (
                    "query_sql",
                    json!({"sql":"SELECT count(*) AS count FROM records"}),
                ),
                ("search", json!({"query":"Derivedbenchmark","limit":50})),
            ] {
                let start = Instant::now();
                ordinary_kernel_call(&db, account, tool, args)
                    .await
                    .unwrap();
                timings
                    .entry(format!(
                        "{tool}_{}",
                        if account == "account-a" {
                            "admin"
                        } else {
                            "restricted"
                        }
                    ))
                    .or_default()
                    .push(start.elapsed().as_secs_f64() * 1000.0);
            }
        }
    }
    let metrics = json!({"shape":{"records":total,"ordinary":ordinary,"attachments":derived_each,"annotations":derived_each+malformed,"malformed_bearers":malformed,"generated_folders":folders,"history":"one creation event per generated record","body":"short synthetic text","blob":"shared synthetic text bytes"},"import_seconds":import_seconds,"replaced":report.derived_replaced,"refused":report.derived_refused,"total_refusals":report.refusals.len(),"query_ms_samples":timings});
    println!(
        "SYNTHETIC_DERIVED_IMPORT {}",
        serde_json::to_string(&metrics).unwrap()
    );
    if let Ok(path) = std::env::var("NATIVE_SYNTHETIC_IMPORT_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&metrics).unwrap()).unwrap();
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_artifact_attachment_missing_blob_blocks_capture() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO records(id,type,kind,name,home_id,owner_id,policy_anchor_id,created_at,updated_at,archived) VALUES('artifact','Document','artifact','Synthetic artifact','folder','person-a','native:root','2026-01-01','2026-01-02',0),('child','Document','attachment','Synthetic child','folder','person-a','native:root','2026-01-01','2026-01-02',0); INSERT INTO links VALUES('bearer-child','child','artifact','part_of',NULL,'2026-01-01')").await.unwrap();
    let report = run(Options {
        all: true,
        history: true,
        ..f.options(&[], false)
    })
    .await
    .unwrap();
    assert_eq!(report.refusals.len(), 1);
    assert_eq!(report.refusals[0].id, "child");
    assert_eq!(
        report.refusals[0].reason,
        "attachment has no blob reference"
    );
    assert!(report
        .refusal_breakdown
        .iter()
        .any(|r| r.reason_category == "attachment_validation"
            && r.shape == "bearer_imported"
            && r.count == 1));
    let capture = cutover::capture_report(&report, &f.source, true, true, false)
        .await
        .unwrap();
    assert_eq!(capture["capture_complete"], false);
    assert_eq!(capture["mismatches"], 1);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_noncomment_annotation_resume_verifies_final_tombstone() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,policy_anchor_id,created_at,updated_at,archived) VALUES('suggestion','Annotation','suggestion','Synthetic suggestion','initial body','folder','person-a','native:root','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0); INSERT INTO links VALUES('suggestion-bearer','suggestion','note','part_of',NULL,'2026-01-01T00:00:00Z')").await.unwrap();
    let first = run(Options {
        all: true,
        history: true,
        ..f.options(&[], false)
    })
    .await
    .unwrap();
    assert!(first.refusals.is_empty());
    let db = f.db().await;
    assert!(
        k::read_record_as(&db, &first.principals["account-a"], "suggestion")
            .await
            .unwrap()
            .is_some()
    );
    source.execute("UPDATE records SET body='final body',updated_at='2026-01-03T00:00:00Z',deleted_at='2026-01-03T00:00:00Z' WHERE id='suggestion'").await.unwrap();
    let options = || Options {
        all: true,
        history: true,
        ..f.options(&[], true)
    };
    let resumed = run(options()).await.unwrap();
    assert!(resumed.refusals.is_empty());
    assert_eq!(resumed.tombstones_verified, 1);
    assert_eq!(resumed.excluded_deleted, 0);
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let snapshot = k::read_imported_snapshot_as(&db, &host, "suggestion")
        .await
        .unwrap()
        .unwrap();
    assert!(snapshot.tombstoned);
    assert_eq!(snapshot.record.body.as_deref(), Some("final body"));
    for principal in resumed.principals.values() {
        assert!(k::read_record_as(&db, principal, "suggestion")
            .await
            .unwrap()
            .is_none());
    }
    assert_eq!(
        cutover::capture_report(&resumed, &f.source, true, true, true)
            .await
            .unwrap()["capture_complete"],
        true
    );
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let retry = run(options()).await.unwrap();
    assert_eq!(retry.tombstones_verified, 1);
    assert_eq!(retry.updated, 0);
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_refusal_breakdown_accounts_for_actual_scope_refusals() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("UPDATE records SET deleted_at='2026-01-03T00:00:00Z' WHERE id IN ('task','note'); INSERT INTO records(id,type,kind,name,home_id,owner_id,policy_anchor_id,created_at,updated_at,archived,deleted_at) VALUES('deleted-attachment','Document','attachment','PRIVATE deleted attachment','folder','person-a','native:root','2026-01-01','2026-01-02',0,'2026-01-03'),('deleted-other','Custom','custom','PRIVATE deleted other','folder','person-a','native:root','2026-01-01','2026-01-02',0,'2026-01-03')").await.unwrap();
    let mut options = f.options(&[], false);
    options.all = true;
    options.history = true;
    let mut report = run(Options {
        all: true,
        history: true,
        ..f.options(&[], false)
    })
    .await
    .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(report.review.is_empty());
    assert_eq!(report.excluded_deleted, 4);
    assert_eq!(
        report
            .counted_breakdown
            .iter()
            .map(|r| r.count)
            .sum::<usize>(),
        4
    );
    assert!(report
        .counted_breakdown
        .iter()
        .all(|r| r.reason_category == "excluded_deleted"));
    for kind in ["task", "note", "attachment", "other"] {
        assert!(report
            .counted_breakdown
            .iter()
            .any(|r| r.v1_kind == kind && r.count == 1));
    }
    let capture = cutover::capture_report(&report, &f.source, true, true, false)
        .await
        .unwrap();
    assert_eq!(capture["capture_complete"], true);
    assert_eq!(capture["mismatches"], 0);
    assert!(report
        .history
        .streams
        .values()
        .all(|s| s.source == s.verified));
    let safe = refusal_breakdown::sanitized_report(&capture);
    assert_eq!(safe["excluded_deleted"], 4);
    assert!(!safe.to_string().contains("PRIVATE"));
    assert!(safe.get("principals").is_none());
    assert!(safe.get("refusals").is_none());
    report.counted[0].reason = "not_a_waiver".into();
    assert_eq!(
        cutover::capture_report(&report, &f.source, true, true, false)
            .await
            .unwrap()["capture_complete"],
        false
    );
    // The approved invisible attachment is counted only; the artifact and its
    // byte-verified attachment both remain available after resume.
    source.execute("INSERT INTO records(id,type,kind,name,home_id,owner_id,policy_anchor_id,created_at,updated_at,archived) VALUES('orphan','Document','attachment','PRIVATE orphan','folder','person-a','native:root','2026-01-01','2026-01-02',0),('retained','Document','artifact','PRIVATE retained','folder','person-a','native:root','2026-01-01','2026-01-02',0)").await.unwrap();
    add_derived_attachment(&f, "retained-child", "retained", "person-a").await;
    options.resume = true;
    let resumed = run(options).await.unwrap();
    assert!(resumed.refusals.is_empty());
    let target = f.db().await;
    for id in ["retained", "retained-child"] {
        assert!(
            k::read_record_as(&target, &resumed.principals["account-a"], id)
                .await
                .unwrap()
                .is_some()
        );
    }
    target.close().await;
    assert_eq!(resumed.excluded_invisible_in_v1, 1);
    assert!(resumed
        .counted_breakdown
        .iter()
        .any(|r| r.reason_category == "excluded_invisible_in_v1"
            && r.shape == "attachment_part_of_count=0"
            && r.count == 1));
    let capture = cutover::capture_report(&resumed, &f.source, true, true, true)
        .await
        .unwrap();
    assert_eq!(capture["capture_complete"], true);
    assert_eq!(capture["mismatches"], 0);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_comments_inherit_bearer_tombstone_and_keep_history() {
    for deleted in ["note", "c-root"] {
        let f = Fixture::new().await;
        add_comment_fixture(&f).await;
        let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
            .await
            .unwrap();
        sqlx::query("UPDATE records SET deleted_at='2026-01-08T00:00:00Z' WHERE id=?")
            .bind(deleted)
            .execute(&mut source)
            .await
            .unwrap();
        let mut options = f.options(&[], false);
        options.all = true;
        options.history = true;
        let report = run(Options {
            all: true,
            history: true,
            ..f.options(&[], false)
        })
        .await
        .unwrap();
        assert!(
            report.refusals.is_empty(),
            "{}",
            serde_json::to_string(&report.refusals).unwrap()
        );
        assert!(report.review.is_empty());
        let count = if deleted == "note" { 2 } else { 1 };
        assert_eq!(report.inherited_bearer_tombstones, count);
        assert_eq!(report.tombstones_verified, count);
        assert_eq!(report.excluded_deleted, 1);
        assert_eq!(
            report
                .counted_breakdown
                .iter()
                .filter(|r| r.reason_category == "inherited_bearer_tombstone")
                .map(|r| r.count)
                .sum::<usize>(),
            count
        );
        assert_eq!(
            cutover::capture_report(&report, &f.source, true, true, false)
                .await
                .unwrap()["capture_complete"],
            true
        );
        let db = f.db().await;
        // Use the sealed import actor, never expose hidden history to a member.
        let host: String = sqlx::query_scalar(
            "SELECT actor FROM content_events WHERE type='kernel.import_state.v1' LIMIT 1",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        for id in if count == 2 {
            vec!["c-root", "c-reply"]
        } else {
            vec!["c-reply"]
        } {
            let snapshot = k::read_imported_snapshot_as(&db, &host, id)
                .await
                .unwrap()
                .unwrap();
            assert!(snapshot.tombstoned);
            for principal in report.principals.values() {
                assert!(k::read_record_as(&db, principal, id)
                    .await
                    .unwrap()
                    .is_none());
            }
            let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id=? AND type='kernel.legacy_recorded.v1'").bind(id).fetch_one(db.pool()).await.unwrap();
            assert!(events > 0);
        }
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        options.resume = true;
        let resumed = run(options).await.unwrap();
        assert!(resumed.refusals.is_empty());
        assert_eq!(resumed.updated, 0);
        assert_eq!(resumed.inherited_bearer_tombstones, count);
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        k::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_invisible_attachment_exclusion_has_receipt_history_and_resumes() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,policy_anchor_id,created_at,updated_at,archived) VALUES('PRIVATE-orphan','Document','attachment','PRIVATE orphan title','PRIVATE orphan text','folder',NULL,'native:root','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',0); INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('PRIVATE-orphan-event','PRIVATE-orphan','record.created','{}','original-creator','2026-01-01T00:00:00Z')").await.unwrap();
    let mut before = None;
    for resume in [false, true] {
        let report = run(Options {
            all: true,
            history: true,
            ..f.options(&[], resume)
        })
        .await
        .unwrap();
        assert!(report.refusals.is_empty());
        assert!(report.review.is_empty());
        assert_eq!(report.excluded_invisible_in_v1, 1);
        assert!(!report
            .assumed_owners
            .iter()
            .any(|id| id == "PRIVATE-orphan"));
        assert!(report
            .counted
            .iter()
            .any(|i| i.id == "PRIVATE-orphan" && i.reason == "excluded_invisible_in_v1"));
        assert!(report.counted_breakdown.iter().any(|i| i.reason_category
            == "excluded_invisible_in_v1"
            && i.v1_type == "Document"
            && i.v1_kind == "attachment"
            && i.shape == "attachment_part_of_count=0"
            && i.count == 1));
        let capture = cutover::capture_report(&report, &f.source, true, true, resume)
            .await
            .unwrap();
        assert_eq!(capture["capture_complete"], true);
        assert_eq!(capture["mismatches"], 0);
        let safe = refusal_breakdown::sanitized_report(&capture);
        assert_eq!(safe["excluded_invisible_in_v1"], 1);
        assert!(!safe.to_string().contains("PRIVATE"));
        assert!(report
            .history
            .streams
            .values()
            .all(|s| s.source == s.verified));
        let target = f.db().await;
        for principal in report.principals.values() {
            assert!(k::read_record_as(&target, principal, "PRIVATE-orphan")
                .await
                .unwrap()
                .is_none());
        }
        let retained: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events WHERE id='PRIVATE-orphan-event' AND record_id='kernel:root' AND type='kernel.legacy_recorded.v1'").fetch_one(target.pool()).await.unwrap();
        assert_eq!(retained, 1);
        let state = k::dump_all_kernel_tables(&target).await.unwrap();
        if let Some(before) = &before {
            assert_eq!(before, &state);
            assert_eq!(report.updated, 0);
        }
        before = Some(state);
    }
    let db = f.db().await;
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(
        before.unwrap(),
        k::dump_all_kernel_tables(&db).await.unwrap()
    );
    // A previously imported attachment that loses its bearer must be hidden,
    // receipted as excluded, and represented once in source coverage.
    let f = Fixture::new().await;
    add_derived_attachment(&f, "detached", "note", "person-a").await;
    let first = run(Options {
        all: true,
        history: true,
        ..f.options(&[], false)
    })
    .await
    .unwrap();
    assert!(first.refusals.is_empty());
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source
        .execute("DELETE FROM links WHERE source_id='detached' AND relationship='part_of'; UPDATE records SET owner_id=NULL WHERE id='detached'")
        .await
        .unwrap();
    let report = run(Options {
        all: true,
        history: true,
        ..f.options(&[], true)
    })
    .await
    .unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(
        report.review.is_empty(),
        "{}",
        serde_json::to_string(&report.review).unwrap()
    );
    assert_eq!(report.excluded_invisible_in_v1, 1);
    assert_eq!(report.excluded_invisible_tombstones_verified, 1);
    assert!(report
        .counted
        .iter()
        .any(|i| i.id == "detached" && i.reason == "excluded_invisible_in_v1"));
    assert_eq!(report.tombstones_verified, 1);
    assert_eq!(
        cutover::capture_report(&report, &f.source, true, true, true)
            .await
            .unwrap()["capture_complete"],
        true
    );
    let db = f.db().await;
    let retained_owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM kernel_records WHERE id='detached'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(retained_owner.as_ref(), first.principals.get("account-a"));
    for principal in report.principals.values() {
        assert!(k::read_record_as(&db, principal, "detached")
            .await
            .unwrap()
            .is_none());
    }
}

#[cfg(all(unix, feature = "v2-kernel-probe"))]
#[tokio::test]
async fn imported_vault_root_metadata_and_logical_homes_survive_resume() {
    let f = Fixture::new().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    sqlx::query("UPDATE database_identity SET origin_db_id='ndb_11111111111141118111111111111111'; UPDATE records SET name='Synthetic workspace',summary='Synthetic summary' WHERE id='native:root'").execute(&mut source).await.unwrap();
    let report = run(f.options(&["task", "secret"], false)).await.unwrap();
    assert!(report.review.is_empty());
    let db = f.db().await;
    let snapshot = crate::query::sql::projection_snapshot(
        &db,
        crate::query::QueryPrincipal::authenticated("account-b", true),
    )
    .await
    .unwrap();
    assert_eq!(snapshot.origin, "ndb_11111111111141118111111111111111");
    assert_eq!(
        snapshot.records["native:root"].name.as_deref(),
        Some("Synthetic workspace")
    );
    assert_eq!(
        snapshot.records["native:root"].metadata["summary"],
        "Synthetic summary"
    );
    assert_eq!(snapshot.records["task"].home_id.as_deref(), Some("folder"));
    assert!(!snapshot.records.contains_key("secret"));
    sqlx::query("UPDATE records SET name='Renamed synthetic workspace' WHERE id='native:root'")
        .execute(&mut source)
        .await
        .unwrap();
    run(f.options(&["task", "secret"], true)).await.unwrap();
    let snapshot = crate::query::sql::projection_snapshot(
        &db,
        crate::query::QueryPrincipal::authenticated("account-b", true),
    )
    .await
    .unwrap();
    assert_eq!(
        snapshot.records["native:root"].name.as_deref(),
        Some("Renamed synthetic workspace")
    );
    // A native policy-only container nested in an imported folder has no
    // domain name. Its vault path uses the nearest visible logical folder.
    let home = k::create_home(
        &db,
        &derived("folder"),
        Some(&[
            (&report.principals["account-a"], "manage"),
            (&report.principals["account-b"], "view"),
        ]),
        &report.principals["account-a"],
    )
    .await
    .unwrap();
    let note = k::create_record_as(&db, &report.principals["account-a"], &home)
        .await
        .unwrap();
    let snapshot = crate::query::sql::projection_snapshot(
        &db,
        crate::query::QueryPrincipal::authenticated("account-b", true),
    )
    .await
    .unwrap();
    assert_eq!(snapshot.records[&note].home_id.as_deref(), Some("folder"));
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn imported_native_delete_retains_derivation_guards_and_requires_known_evidence() {
    let f = Fixture::new().await;
    let imported = run(f.options(&["task", "epic"], false)).await.unwrap();
    assert!(imported.refusals.is_empty());
    let db = f.db().await;
    let before = k::dump_all_kernel_tables(&db).await.unwrap();
    let error = ordinary_kernel_call(
        &db,
        "account-a",
        "delete_record",
        json!({"id":"task","reason":"Unknown source guard"}),
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("imported deletion guard unavailable"),
        "{error}"
    );
    assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    source.execute("CREATE TABLE derivation_target_heads(target_kind TEXT,target_record_id TEXT,target_slot TEXT,active_binding_id TEXT); CREATE TABLE derivation_artifact_role_assignments(assignment_id TEXT,target_kind TEXT,target_record_id TEXT,target_slot TEXT); CREATE TABLE derivation_artifact_role_heads(active_assignment_id TEXT); INSERT INTO derivation_target_heads VALUES('record','task','body','active-body'); INSERT INTO derivation_artifact_role_assignments VALUES('active-role','record','epic','body'); INSERT INTO derivation_artifact_role_heads VALUES('active-role')").await.unwrap();
    let imported = run(f.options(&["task", "epic"], true)).await.unwrap();
    assert!(imported.refusals.is_empty());
    let db = f.db().await;
    for (id, expected) in [
        ("task", "derived body binding is active"),
        ("epic", "derivation artifact role is active"),
    ] {
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        let error = ordinary_kernel_call(
            &db,
            "account-a",
            "delete_record",
            json!({"id":id,"reason":"Guarded import"}),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
    }
    db.close().await;
    source.execute("UPDATE derivation_target_heads SET active_binding_id=NULL; UPDATE derivation_artifact_role_heads SET active_assignment_id=NULL").await.unwrap();
    let imported = run(f.options(&["task", "epic"], true)).await.unwrap();
    assert!(imported.refusals.is_empty());
    let db = f.db().await;
    for id in ["task", "epic"] {
        assert_eq!(
            ordinary_kernel_call(
                &db,
                "account-a",
                "delete_record",
                json!({"id":id,"reason":"No active derivation"})
            )
            .await
            .unwrap()["deleted"],
            true
        );
        assert!(
            k::read_record_as(&db, &imported.principals["account-a"], id)
                .await
                .unwrap()
                .is_none()
        );
    }
    let after = k::dump_all_kernel_tables(&db).await.unwrap();
    k::replay_all_projections(&db).await.unwrap();
    assert_eq!(after, k::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}
