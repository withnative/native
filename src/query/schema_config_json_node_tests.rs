//! Independent config occurrence, authorization and storage oracles.
use super::*;
use crate::meta::schema_config::{write_user_schema_config, SchemaConfigOptions};
use serde_json::json;

const ID: &str = "config:json-test";
const COLUMNS: [&str; 12] = [
    "config_id",
    "ordinal",
    "path",
    "parent_path",
    "parent_ordinal",
    "member_key",
    "array_index",
    "depth",
    "node_type",
    "text_value",
    "number_text",
    "bool_value",
];
fn local() -> QueryPrincipal {
    crate::mcp::Caller::local().into()
}
async fn write(db: &Db, id: &str, source: &str, scope: Option<&str>) {
    write_user_schema_config(
        db,
        source,
        SchemaConfigOptions {
            id: Some(id.into()),
            applies_to_collection_id: scope.map(str::to_owned),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}
async fn nodes(db: &Db) -> SqlResult {
    query_sql(db, local(), "SELECT * FROM schema_config_json_nodes WHERE config_id='config:json-test' ORDER BY ordinal").await.unwrap()
}
fn values(result: &SqlResult) -> Value {
    assert_eq!(result.columns, COLUMNS);
    Value::Array(
        result
            .rows
            .iter()
            .map(|row| Value::Array(COLUMNS.iter().map(|column| row[*column].clone()).collect()))
            .collect(),
    )
}

#[tokio::test]
async fn schema_config_nodes_literal_occurrences_and_parent_join() {
    let db = crate::create_database(":memory:").await.unwrap();
    let source = r#"{"a":{"x":1.00},"a":{"x":2E+09},"~\/":null,"arr":[true,false,null,"line\nquoted",[],{},-0,0.0100e-02],"":{"z":3}}"#;
    write(&db, ID, source, None).await;
    // All slots, parent occurrences, keys and indices are independently authored.
    let expected: Value = serde_json::from_str(
        r#"[
      ["config:json-test",0,"",null,null,null,null,0,"object",null,null,null],
      ["config:json-test",1,"/a","",0,"a",null,1,"object",null,null,null],
      ["config:json-test",2,"/a/x","/a",1,"x",null,2,"number",null,"1.00",null],
      ["config:json-test",3,"/a","",0,"a",null,1,"object",null,null,null],
      ["config:json-test",4,"/a/x","/a",3,"x",null,2,"number",null,"2E+09",null],
      ["config:json-test",5,"/~0~1","",0,"~/",null,1,"null",null,null,null],
      ["config:json-test",6,"/arr","",0,"arr",null,1,"array",null,null,null],
      ["config:json-test",7,"/arr/0","/arr",6,null,0,2,"boolean",null,null,1],
      ["config:json-test",8,"/arr/1","/arr",6,null,1,2,"boolean",null,null,0],
      ["config:json-test",9,"/arr/2","/arr",6,null,2,2,"null",null,null,null],
      ["config:json-test",10,"/arr/3","/arr",6,null,3,2,"string","line\nquoted",null,null],
      ["config:json-test",11,"/arr/4","/arr",6,null,4,2,"array",null,null,null],
      ["config:json-test",12,"/arr/5","/arr",6,null,5,2,"object",null,null,null],
      ["config:json-test",13,"/arr/6","/arr",6,null,6,2,"number",null,"-0",null],
      ["config:json-test",14,"/arr/7","/arr",6,null,7,2,"number",null,"0.0100e-02",null],
      ["config:json-test",15,"/","",0,"",null,1,"object",null,null,null],
      ["config:json-test",16,"//z","/",15,"z",null,2,"number",null,"3",null]
    ]"#,
    )
    .unwrap();
    assert_eq!(values(&nodes(&db).await), expected);
    let stored: String = sqlx::query_scalar("SELECT data FROM schema_config WHERE id=?")
        .bind(ID)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(
        stored, source,
        "Text JSON must survive public write without normalization"
    );
    let joined = query_sql(&db, local(), "SELECT n.ordinal,p.ordinal AS parent,c.id FROM schema_config_json_nodes n JOIN schema_config c ON c.id=n.config_id LEFT JOIN schema_config_json_nodes p ON p.config_id=n.config_id AND p.ordinal=n.parent_ordinal WHERE n.config_id='config:json-test' AND n.path='/a/x' ORDER BY n.ordinal").await.unwrap();
    assert_eq!(
        joined.rows,
        vec![
            json!({"ordinal":2,"parent":1,"id":ID}),
            json!({"ordinal":4,"parent":3,"id":ID})
        ]
    );
    assert!(
        crate::conformance::rebuild::rebuild_and_diff_meta(&db)
            .await
            .unwrap()
            .equal
    );
}

#[tokio::test]
async fn schema_config_nodes_escaped_paths_remain_readable_through_bounded_sql() {
    let db = crate::create_database(":memory:").await.unwrap();
    // Source 128030 bytes; escaped parent/child paths 96001/96003 bytes.
    // The duplicate parent paths still identify different occurrences.
    let key = "/~é".repeat(16_000);
    let source = format!("{{\"{key}\":{{\"x\":1.00}},\"{key}\":{{\"x\":2E+09}}}}");
    assert_eq!(source.len(), 128_030);
    write(&db, ID, &source, None).await;
    let parent_path = format!("/{}", "~1~0é".repeat(16_000));
    let path = format!("{parent_path}/x");
    assert_eq!(parent_path.len(), 96_001);
    assert_eq!(path.len(), 96_003);
    let result = query_sql(
        &db,
        local(),
        "SELECT ordinal,path,parent_path,parent_ordinal,number_text FROM schema_config_json_nodes WHERE config_id='config:json-test' AND node_type='number' ORDER BY ordinal LIMIT 2",
    )
    .await
    .unwrap();
    assert_eq!(
        result.rows,
        vec![
            json!({"ordinal":2,"path":path,"parent_path":parent_path,"parent_ordinal":1,"number_text":"1.00"}),
            json!({"ordinal":4,"path":path,"parent_path":parent_path,"parent_ordinal":3,"number_text":"2E+09"}),
        ]
    );
    // A cell at the admission ceiling remains readable through bounded results.
    // Returning the full path can hit SQLite's row-encoding limit before the
    // encoded-result cell budget. Both existing SQL limits remain enforced.
    let key = format!("{}a", "/".repeat(131_071));
    write(&db, ID, &format!("{{\"{key}\":0}}"), None).await;
    let path = format!("/{}a", "~1".repeat(131_071));
    assert_eq!(path.len(), 262_144);
    let result = query_sql(
        &db,
        local(),
        "SELECT length(path) AS bytes,substr(path,1,16) AS prefix FROM schema_config_json_nodes WHERE config_id='config:json-test' AND ordinal=1 ORDER BY ordinal LIMIT 1",
    )
    .await
    .unwrap();
    assert_eq!(
        result.rows,
        vec![json!({"bytes":262_144,"prefix":"/~1~1~1~1~1~1~1~"})]
    );
    let error = query_sql(
        &db,
        local(),
        "SELECT path FROM schema_config_json_nodes WHERE config_id='config:json-test' AND ordinal=1 ORDER BY ordinal LIMIT 1",
    )
    .await
    .unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("262144-byte SQLite value ceiling")
            || message.contains("262144-byte encoded limit"),
        "{message}"
    );
}

#[tokio::test]
async fn schema_config_nodes_replacement_caps_keep_source_nodes_and_events() {
    let db = crate::create_database(":memory:").await.unwrap();
    write(&db, ID, r#"{"old":{"x":7}}"#, None).await;
    write(&db, ID, "{}", None).await;
    let empty = json!([[ID, 0, "", null, null, null, null, 0, "object", null, null, null]]);
    assert_eq!(values(&nodes(&db).await), empty);
    let before_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    for (source, message) in crate::schema_config_json_nodes::invalid_sources() {
        let error = write_user_schema_config(
            &db,
            source.clone(),
            SchemaConfigOptions {
                id: Some(ID.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(message), "{message}: {error}");
        assert_eq!(values(&nodes(&db).await), empty);
        let stored: String = sqlx::query_scalar("SELECT data FROM schema_config WHERE id=?")
            .bind(ID)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(stored, "{}");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM meta_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            before_events
        );
        // Fold/replay also validates before source upsert or destructive replacement.
        let event = crate::meta::events::MetaEventRow {
            seq: 1,
            id: "test:config-fold".into(),
            subject_id: ID.into(),
            event_type: "schema_config.set".into(),
            payload: Some(json!({"layer":"user","data":source}).to_string()),
            actor: None,
            created_at: "2026-10-03T00:00:00.000Z".into(),
        };
        let mut tx = db.write_pool().begin().await.unwrap();
        assert!(crate::projector::meta::project_meta(&mut tx, &event)
            .await
            .unwrap_err()
            .to_string()
            .contains(message));
        // Inspect inside the still-open transaction to prove prevalidation, not
        // merely a caller rollback restoring destructively changed rows.
        assert_eq!(
            sqlx::query_scalar::<_, String>("SELECT data FROM schema_config WHERE id=?")
                .bind(ID)
                .fetch_one(&mut *tx)
                .await
                .unwrap(),
            "{}"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM schema_config_json_nodes WHERE config_id=?"
            )
            .bind(ID)
            .fetch_one(&mut *tx)
            .await
            .unwrap(),
            1
        );
        tx.rollback().await.unwrap();
    }
    // A storage failure after source upsert/delete must roll back the event
    // and the entire replacement, not just parser failures before mutation.
    sqlx::query("CREATE TRIGGER reject_config_node BEFORE INSERT ON schema_config_json_nodes WHEN NEW.config_id='config:json-test' AND NEW.ordinal=2 BEGIN SELECT RAISE(ABORT,'injected config-node storage failure'); END")
        .execute(db.write_pool()).await.unwrap();
    let error = write_user_schema_config(
        &db,
        r#"{"a":[true]}"#,
        SchemaConfigOptions {
            id: Some(ID.into()),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("injected config-node storage failure"),
        "{error}"
    );
    assert_eq!(values(&nodes(&db).await), empty);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT data FROM schema_config WHERE id=?")
            .bind(ID)
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        "{}"
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM meta_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        before_events
    );
    sqlx::query("DROP TRIGGER reject_config_node")
        .execute(db.write_pool())
        .await
        .unwrap();
    // Source IDs are stable; the existing FK refuses a raw rename rather
    // than permitting orphan nodes. Public updates replace rows by that ID.
    assert!(
        sqlx::query("UPDATE schema_config SET id='renamed' WHERE id=?")
            .bind(ID)
            .execute(db.write_pool())
            .await
            .is_err()
    );
    assert_eq!(values(&nodes(&db).await), empty);
    assert!(
        crate::conformance::rebuild::rebuild_and_diff_meta(&db)
            .await
            .unwrap()
            .equal
    );
}

#[tokio::test]
async fn schema_config_nodes_scope_visibility_query_shapes_and_cascades() {
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    let db = crate::create_database(":memory:").await.unwrap();
    const A: &str = "9e795ca1-0000-4000-8000-000000000001";
    const B: &str = "9e795ca1-0000-4000-8000-000000000002";
    for (id, account) in [(A, "acct:config-alice"), (B, "acct:config-bea")] {
        crate::store::create_record(&db, json!({"id":id,"type":"Collection","kind":"folder","name":account,"home_id":crate::schema::ROOT_RECORD_ID})).await.unwrap();
        replace_explicit_policy(
            &db,
            &format!("policy:{id}"),
            id,
            vec![AllowEntry::account(account, Capability::View)],
        )
        .await
        .unwrap();
    }
    for (id, scope) in [
        ("config:global", None),
        ("config:alice", Some(A)),
        ("config:bea", Some(B)),
    ] {
        write(&db, id, r#"{"secret":"value"}"#, scope).await;
    }
    for (account, visible, hidden) in [
        ("acct:config-alice", "config:alice", "config:bea"),
        ("acct:config-bea", "config:bea", "config:alice"),
    ] {
        let caller = QueryPrincipal::authenticated(account, true);
        for relation in ["schema_config", "schema_config_json_nodes"] {
            let (key, predicate) = if relation == "schema_config" {
                ("id", "")
            } else {
                ("config_id", "AND ordinal=0")
            };
            let rows = query_sql(&db,caller.clone(),&format!("SELECT {key} AS id FROM {relation} WHERE {key} IN ('config:global','config:alice','config:bea') {predicate} ORDER BY {key}")).await.unwrap().rows;
            let mut expected = vec![json!({"id":"config:global"}), json!({"id":visible})];
            expected.sort_by_key(|row| row["id"].as_str().unwrap().to_owned());
            assert_eq!(rows, expected);
        }
        for sql in [
            format!("SELECT config_id,path,text_value FROM schema_config_json_nodes WHERE config_id='{hidden}' OR (config_id='{hidden}' AND path='/secret') ORDER BY ordinal"),
            format!("SELECT c.id,n.text_value FROM schema_config c JOIN schema_config_json_nodes n ON n.config_id=c.id WHERE c.id='{hidden}' ORDER BY n.ordinal"),
            format!("SELECT n.path,p.path AS parent FROM schema_config_json_nodes n LEFT JOIN schema_config_json_nodes p ON p.config_id=n.config_id AND p.ordinal=n.parent_ordinal WHERE n.config_id='{hidden}' ORDER BY n.ordinal"),
        ] { assert!(query_sql(&db,caller.clone(),&sql).await.unwrap().rows.is_empty(), "{sql}"); }
        for sql in [
            format!("SELECT count(*) AS n FROM schema_config_json_nodes WHERE config_id='{hidden}'"),
            format!("SELECT count(*) AS n FROM schema_config_json_nodes WHERE config_id='{hidden}' AND path='/secret'"),
            format!("SELECT EXISTS(SELECT 1 FROM schema_config_json_nodes WHERE config_id='{hidden}' AND text_value='value') AS n"),
        ] { assert_eq!(query_sql(&db,caller.clone(),&sql).await.unwrap().rows,vec![json!({"n":0})],"{sql}"); }
        let count=query_sql(&db,caller,&format!("SELECT count(*) AS n FROM schema_config_json_nodes WHERE config_id IN ('config:global','{visible}','{hidden}')")).await.unwrap();
        assert_eq!(count.rows, vec![json!({"n":4})]);
    }
    // Moving an existing config's scope must immediately move its whole node set.
    write(&db, "config:alice", r#"{"moved":[]}"#, Some(B)).await;
    assert!(query_sql(
        &db,
        QueryPrincipal::authenticated("acct:config-alice", true),
        "SELECT path FROM schema_config_json_nodes WHERE config_id='config:alice'"
    )
    .await
    .unwrap()
    .rows
    .is_empty());
    assert_eq!(query_sql(&db,QueryPrincipal::authenticated("acct:config-bea",true),"SELECT path FROM schema_config_json_nodes WHERE config_id='config:alice' ORDER BY ordinal").await.unwrap().rows,vec![json!({"path":""}),json!({"path":"/moved"})]);
    // Soft-deleted anchor remains stored but is absent through the visibility fence.
    crate::store::delete_record(&db, B).await.unwrap();
    assert!(query_sql(&db,local(),"SELECT config_id FROM schema_config_json_nodes WHERE config_id IN ('config:alice','config:bea')").await.unwrap().rows.is_empty());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM schema_config_json_nodes WHERE config_id='config:bea'"
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap(),
        2
    );
    // Physical deletion cascades record -> source -> nodes. Global rows survive.
    sqlx::query("DELETE FROM records WHERE id=?")
        .bind(B)
        .execute(db.write_pool())
        .await
        .unwrap();
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT count(*) FROM schema_config_json_nodes WHERE config_id IN ('config:alice','config:bea')").fetch_one(db.write_pool()).await.unwrap(),0);
    sqlx::query("DELETE FROM schema_config WHERE id='config:global'")
        .execute(db.write_pool())
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM schema_config_json_nodes WHERE config_id='config:global'"
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap(),
        0
    );
}

#[tokio::test]
async fn schema_config_nodes_catalog_sandbox_and_result_truncation() {
    let db = crate::create_database(":memory:").await.unwrap();
    write(
        &db,
        ID,
        &format!("{{\"a\":[{}]}}", vec!["0"; 1001].join(",")),
        None,
    )
    .await;
    let catalog=query_sql(&db,local(),"SELECT identity,semantic_version,caller_relative,completeness,profiles FROM catalog_relations WHERE relation_name='schema_config_json_nodes'").await.unwrap();
    assert_eq!(
        catalog.rows,
        vec![
            json!({"identity":"native.query-sql.schema-config-json-nodes","semantic_version":1,"caller_relative":1,"completeness":"complete","profiles":"sqlite-local"})
        ]
    );
    let columns=query_sql(&db,local(),"SELECT column_name FROM catalog_columns WHERE relation_name='schema_config_json_nodes' ORDER BY column_position").await.unwrap();
    assert_eq!(
        columns.rows,
        COLUMNS.map(|column| json!({"column_name":column}))
    );
    for sql in [
        "SELECT * FROM main.schema_config_json_nodes",
        "WITH schema_config_json_nodes AS (SELECT * FROM main.schema_config_json_nodes) SELECT * FROM schema_config_json_nodes",
        "INSERT INTO schema_config_json_nodes(config_id,ordinal) VALUES('x',0)",
        "DELETE FROM schema_config_json_nodes",
        "UPDATE schema_config_json_nodes SET path='changed'",
        "SELECT json_extract(data,'$') FROM schema_config",
    ] { assert!(query_sql(&db,local(),sql).await.is_err(),"{sql}"); }
    let result = nodes(&db).await;
    assert_eq!(result.rows.len(), 1000);
    assert!(result.truncated);
    assert!(result.truncation_hint.is_some());
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM schema_config_json_nodes WHERE config_id=?"
        )
        .bind(ID)
        .fetch_one(db.write_pool())
        .await
        .unwrap(),
        1003,
        "stored projection never truncates"
    );
    let limited=query_sql(&db,local(),"SELECT config_id,ordinal FROM schema_config_json_nodes WHERE config_id='config:json-test' LIMIT 2").await.unwrap();
    assert_eq!(
        limited.rows,
        vec![
            json!({"config_id":ID,"ordinal":0}),
            json!({"config_id":ID,"ordinal":1})
        ]
    );
    assert!(limited.assumed_order.is_some());
}

#[test]
fn schema_config_nodes_saved_pins_and_unsupported_profiles() {
    use native_query_contract::rule_contract::{check_catalog_pin, check_relation_pin};
    let snapshot = current_catalog_snapshot();
    check_catalog_pin(&snapshot, 4, "sqlite-local", 1).unwrap();
    let readset=extract_rule_input_dependencies("SELECT n.ordinal,n.number_text FROM schema_config_json_nodes n JOIN schema_config c ON c.id=n.config_id WHERE c.id=?1 ORDER BY n.ordinal").unwrap();
    let pin = readset
        .relations
        .iter()
        .find(|pin| pin.identity == "native.query-sql.schema-config-json-nodes")
        .unwrap();
    assert_eq!(pin.semantic_version, 1);
    for pin in &readset.relations {
        check_relation_pin(&snapshot, pin).unwrap();
    }
    let old = extract_rule_input_dependencies("SELECT id FROM records ORDER BY id").unwrap();
    for pin in &old.relations {
        check_relation_pin(&snapshot, pin).unwrap();
    }
    let mut changed = snapshot.clone();
    changed
        .relations
        .iter_mut()
        .find(|r| r.identity == pin.identity)
        .unwrap()
        .semantic_version = 2;
    assert!(check_relation_pin(&changed, pin).is_err());
    for profile in [
        sql_contract::QuerySqlProfile::PostgresServer,
        sql_contract::QuerySqlProfile::TursoLocal,
    ] {
        assert!(sql_contract::logical_columns("schema_config_json_nodes", profile).is_none());
        let mut other = snapshot.clone();
        other.profile_id = profile.contract().id.into();
        assert!(check_relation_pin(&other, pin)
            .unwrap_err()
            .to_string()
            .contains("unavailable in profile"));
    }
    assert_eq!(
        sql_contract::logical_columns(
            "schema_config_json_nodes",
            sql_contract::QuerySqlProfile::SqliteLocal
        )
        .unwrap(),
        COLUMNS
    );
    let card = sql_contract::sql_read_catalog_card();
    assert!(card.len() <= 6144, "{} bytes", card.len());
    assert!(card.contains("Queryable relations"));
    assert!(card.contains("config_id=schema_config.id"));
}

#[tokio::test]
async fn schema_config_nodes_admit_source_depth_and_node_boundaries() {
    let db = crate::create_database(":memory:").await.unwrap();
    // Exactly 256KiB of declared stored source is valid, while the next byte
    // is refused by the failure fixture. Independent byte arithmetic.
    let source = format!("{{\"s\":\"{}\"}}", "x".repeat(262_136));
    assert_eq!(source.len(), 262_144);
    write(&db, ID, &source, None).await;
    let len=query_sql(&db,local(),"SELECT length(text_value) AS n FROM schema_config_json_nodes WHERE config_id='config:json-test' AND ordinal=1").await.unwrap();
    assert_eq!(len.rows, vec![json!({"n":262_136})]);
    write(
        &db,
        ID,
        &format!("{{\"a\":{}0{}}}", "[".repeat(63), "]".repeat(63)),
        None,
    )
    .await;
    let depth=query_sql(&db,local(),"SELECT ordinal,depth,number_text FROM schema_config_json_nodes WHERE config_id='config:json-test' AND node_type='number'").await.unwrap();
    assert_eq!(
        depth.rows,
        vec![json!({"ordinal":64,"depth":64,"number_text":"0"})]
    );
    write(
        &db,
        ID,
        &format!("{{\"a\":[{}]}}", vec!["0"; 4094].join(",")),
        None,
    )
    .await;
    let count = query_sql(
        &db,
        local(),
        "SELECT count(*) AS n FROM schema_config_json_nodes WHERE config_id='config:json-test'",
    )
    .await
    .unwrap();
    assert_eq!(count.rows, vec![json!({"n":4096})]);
}
