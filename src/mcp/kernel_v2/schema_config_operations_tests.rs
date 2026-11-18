use super::*;
use serde_json::json;

async fn fixture() -> (tempfile::TempDir, Db, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let (db, owner) = kernel::create_v2_database(
        dir.path().join("schema.db").to_str().unwrap(),
        "account",
        "Owner",
        "schema:owner",
    )
    .await
    .unwrap();
    let member = kernel::create_principal(&db, "account", "Member", "schema:member", &owner)
        .await
        .unwrap();
    (dir, db, owner, member)
}
async fn call(db: &Db, credential: &str, args: Value) -> Result<Value> {
    super::tests::registry()
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated(credential),
            "manage_schema_config",
            args,
        )
        .await
}
fn write(id: &str, data: Value) -> Value {
    json!({"action":"write","id":id,"data":data})
}
fn imported(section: &str, id: &str, value: Value) -> kernel::v1_state::ImportedState {
    kernel::v1_state::ImportedState {
        section: section.into(),
        source_id: json!([id]).to_string(),
        origin: "schema:source".into(),
        value_json: Some(value.to_string()),
        account_principal: None,
        record_id: None,
        observed_at: "2026-01-01T00:00:00Z".into(),
        snapshot: json!({}),
    }
}
fn schema(id: &str, layer: &str, data: Value, scope: Option<&str>) -> Value {
    json!({"id":id,"layer":layer,"name":null,"data":data.to_string(),"applies_to_collection_id":scope,"version_lineage":null,"created_at":"2026-01-01T00:00:00Z"})
}
async fn import(db: &Db, rows: Vec<kernel::v1_state::ImportedState>) {
    let host = kernel::resolve_principal_by_binding(db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    kernel::v1_state::import_state_batch_as(db, &host, &rows)
        .await
        .unwrap();
}
async fn create_record(db: &Db, owner: &str, typ: &str, kind: &str, home: &str) -> String {
    let family = format!("fixture.schema.{typ}");
    let definition = json!({"family":family,"version":1,"interpreter":"native.defn/2","primary_type":typ,"kinds":[{"token":kind,"description":"Schema fixture","maturity":"current","identity":{"field":"title"},"fields":[{"name":"title","type":"text","required":true}],"links":[]}]});
    let pin = kernel::install_definition_as(
        db,
        owner,
        &family,
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(db, owner, &family, Some(&pin))
        .await
        .unwrap();
    kernel::create_as(
        db,
        owner,
        &family,
        kind,
        json!({"title":format!("Schema fixture {home}")})
            .as_object()
            .unwrap(),
        home,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn direct_schema_write_preserves_floors_canonical_identity_and_replays() {
    let (_dir, db, _owner, _member) = fixture().await;
    // V2 retains meta_events for definition registry authority, while these
    // schema writes belong exclusively to native content events.
    let meta_before: Vec<String> = sqlx::query_scalar(
        "SELECT json_array(seq,id,subject_id,type,payload,actor,created_at,act) FROM meta_events ORDER BY seq",
    ).fetch_all(db.pool()).await.unwrap();
    let axis = json!({"key":"status","label":"Status"});
    let pack = json!({"shapes":{"Document":{"facets":{"lifecycle":{"vocab_ref":"status","required":true,"axis":axis},"score":{"type":"number"},"payload":{"type":"object","json_schema":{"type":"object","required":["start"]}}}}}});
    import(
        &db,
        vec![
            imported(
                "vocabularies",
                "voc:status",
                json!({"id":"voc:status","name":"status","created_at":"2026-01-01T00:00:00Z"}),
            ),
            imported(
                "schema_config",
                "pack:floor",
                schema("pack:floor", "pack", pack.clone(), None),
            ),
        ],
    )
    .await;
    let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
    let invalid = [
        write(
            "bad:required",
            json!({"shapes":{"Document":{"facets":{"lifecycle":{"vocab_ref":"rec:voc:status","required":false,"axis":axis}}}}}),
        ),
        write(
            "bad:type",
            json!({"shapes":{"Document":{"facets":{"score":{}}}}}),
        ),
        write(
            "bad:object",
            json!({"shapes":{"Document":{"facets":{"payload":{"type":"object"}}}}}),
        ),
        write(
            "bad:reserved",
            json!({"shapes":{"Document":{"facets":{"archived":{}}}}}),
        ),
        write(
            "bad:multi",
            json!({"shapes":{"Document":{"facets":{"x":{"multi":false}}}}}),
        ),
        write(
            "bad:kind-array",
            json!({"shapes":{"Document":{"kinds":["fake"]}}}),
        ),
        write(
            "bad:spine-type",
            json!({"shapes":{"Document":{"facets":{"lifecycle":{"type":"number"}}}}}),
        ),
        write("pack:floor", json!({"shapes":{}})),
    ];
    for args in invalid {
        assert!(call(&db, "schema:owner", args).await.is_err());
        assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
    }
    let data = json!({"shapes":{"Document":{"facets":{"lifecycle":{"vocab_ref":"rec:status","required":true,"axis":axis},"score":{"type":"number"},"payload":{"type":"object","json_schema":{"type":"object","required":["start"]}}}}}});
    let result = call(&db, "schema:owner", write("user:config", data.clone()))
        .await
        .unwrap();
    assert_eq!(result["changed"], true);
    let resolved = super::tests::registry()
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("schema:owner"),
            "resolve_facets",
            json!({"type":"Document"}),
        )
        .await
        .unwrap();
    assert_eq!(
        resolved["shape"]["lifecycle"]["vocab_ref"],
        "rec:voc:status"
    );
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert!(kernel::v1_state::import_state_batch_as(
        &db,
        &host,
        &[imported(
            "schema_config",
            "pack:floor",
            schema("pack:floor", "pack", pack, None)
        )]
    )
    .await
    .is_err());
    let raw:String=sqlx::query_scalar("SELECT payload FROM kernel_v1_state WHERE section='schema_config' AND json_extract(payload,'$.id')='user:config'").fetch_one(db.pool()).await.unwrap();
    let row: Value = serde_json::from_str(&raw).unwrap();
    let saved: Value = serde_json::from_str(row["data"].as_str().unwrap()).unwrap();
    assert_eq!(
        saved["shapes"]["Document"]["facets"]["lifecycle"]["vocab_ref"],
        "rec:voc:status"
    );
    assert_eq!(
        call(&db, "schema:owner", write("user:config", data))
            .await
            .unwrap()["changed"],
        false
    );
    let expected = kernel::dump_all_kernel_tables(&db).await.unwrap();
    kernel::replay_all_projections(&db).await.unwrap();
    assert_eq!(expected, kernel::dump_all_kernel_tables(&db).await.unwrap());
    let frozen:Vec<String>=sqlx::query_scalar("SELECT name FROM sqlite_schema WHERE type='table' AND name IN ('schema_config','vocabularies','vocabulary_values','meta_events') ORDER BY name").fetch_all(db.pool()).await.unwrap();
    assert_eq!(frozen, vec!["meta_events".to_owned()]);
    let meta_after: Vec<String> = sqlx::query_scalar(
        "SELECT json_array(seq,id,subject_id,type,payload,actor,created_at,act) FROM meta_events ORDER BY seq",
    ).fetch_all(db.pool()).await.unwrap();
    assert_eq!(
        meta_before, meta_after,
        "native schema writes never mutate the registry log"
    );
}

#[tokio::test]
async fn direct_schema_scope_owner_and_revision_checks_are_atomic() {
    let (_dir, db, owner, member) = fixture().await;
    let registry = super::tests::registry();
    let descriptor = registry.get("manage_schema_config").unwrap();
    assert!(descriptor.input_schema["properties"]
        .get("if_schema_state_revision")
        .is_none());
    assert_eq!(
        descriptor.input_schema_for_engine(EngineKind::KernelV2)["properties"]
            ["if_schema_state_revision"]["type"],
        "string"
    );
    let home = kernel::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&member, "manage")]),
        &owner,
    )
    .await
    .unwrap();
    let collection = create_record(&db, &owner, "Collection", "folder", &home).await;
    let global = call(
        &db,
        "schema:owner",
        write("user:global", json!({"shapes":{}})),
    )
    .await
    .unwrap();
    let hidden = create_record(
        &db,
        &owner,
        "Collection",
        "folder",
        crate::events::KERNEL_ROOT_ID,
    )
    .await;
    let mut hidden_schema = write("user:hidden", json!({"shapes":{}}));
    hidden_schema["applies_to_collection_id"] = json!(hidden);
    call(&db, "schema:owner", hidden_schema).await.unwrap();
    let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
    let mut steal_scoped = write("user:hidden", json!({"shapes":{}}));
    steal_scoped["applies_to_collection_id"] = json!(collection);
    assert!(call(&db, "schema:member", steal_scoped).await.is_err());
    assert!(call(
        &db,
        "schema:member",
        write("member:global", json!({"shapes":{}}))
    )
    .await
    .is_err());
    let mut steal = write("user:global", json!({"shapes":{}}));
    steal["applies_to_collection_id"] = json!(collection);
    assert!(call(&db, "schema:member", steal).await.is_err());
    let mut stale = write("user:stale", json!({"shapes":{}}));
    stale["if_schema_state_revision"] = json!("schema-state-v1:meta:0:content:0");
    assert!(call(&db, "schema:owner", stale).await.is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
    let mut scoped = write(
        "member:scoped",
        json!({"shapes":{"Document":{"facets":{"score":{"type":"number"}}}}}),
    );
    scoped["applies_to_collection_id"] = json!(collection);
    let caller = Caller::authenticated("schema:member")
        .with_hosting_context("synthetic-member", "schema-fixture")
        .with_hosting_member(true)
        .with_hosting_owner(false);
    let result = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            caller,
            "manage_schema_config",
            scoped,
        )
        .await
        .unwrap();
    assert!(
        crate::mcp::counter_fence::find_counters(&result).is_empty(),
        "{result}"
    );
    assert_eq!(result["applies_to_collection_id"], collection);
    let mut wrong = write("user:stale-valid-token", json!({"shapes":{}}));
    wrong["if_schema_state_revision"] = global["schema_state_revision"].clone();
    assert!(call(&db, "schema:owner", wrong).await.is_err());
    let expected = kernel::dump_all_kernel_tables(&db).await.unwrap();
    kernel::replay_all_projections(&db).await.unwrap();
    assert_eq!(expected, kernel::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn direct_schema_reports_historical_values_without_rewriting_them() {
    let (_dir, db, owner, _member) = fixture().await;
    let record = create_record(
        &db,
        &owner,
        "Document",
        "note",
        crate::events::KERNEL_ROOT_ID,
    )
    .await;
    kernel::hq::observe_facet_as(
        &db,
        &owner,
        &record,
        &kernel::hq::FacetObservation {
            key: "score".into(),
            value: Some("legacy-text".into()),
            value_num: None,
            vocab_ref: None,
            as_of: "2026-01-01T00:00:00Z".into(),
        },
        None,
    )
    .await
    .unwrap();
    let result = call(
        &db,
        "schema:owner",
        write(
            "user:typed",
            json!({"shapes":{"Document":{"facets":{"score":{"type":"number"}}}}}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(result["nonconforming_stored_values"], 1);
    let value: String =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='score'")
            .bind(&record)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(value, "legacy-text");
    let mut next = kernel::hq::FacetObservation {
        key: "score".into(),
        value: Some("still-not-a-number".into()),
        value_num: None,
        vocab_ref: None,
        as_of: "2026-01-02T00:00:00Z".into(),
    };
    assert!(
        kernel::hq::observe_facet_as(&db, &owner, &record, &next, None)
            .await
            .is_err()
    );
    next.value = Some("42".into());
    next.value_num = Some(42.0);
    kernel::hq::observe_facet_as(&db, &owner, &record, &next, None)
        .await
        .unwrap();
    let numeric: Option<f64> =
        sqlx::query_scalar("SELECT value_num FROM kernel_facets WHERE record_id=? AND key='score'")
            .bind(&record)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(numeric, Some(42.0));
    let expected = kernel::dump_all_kernel_tables(&db).await.unwrap();
    kernel::replay_all_projections(&db).await.unwrap();
    assert_eq!(expected, kernel::dump_all_kernel_tables(&db).await.unwrap());
}

#[tokio::test]
async fn direct_schema_requires_active_canonical_kinds_and_preserves_imported_row_identity() {
    let (_dir, db, _owner, _member) = fixture().await;
    import(
        &db,
        vec![imported(
            "schema_config",
            "user:imported",
            schema("user:imported", "user", json!({"shapes":{}}), None),
        )],
    )
    .await;
    let args = write(
        "user:imported",
        json!({"shapes":{"WorkItem:local-task":{"facets":{"score":{"type":"number"}}}}}),
    );
    assert!(call(&db, "schema:owner", args.clone()).await.is_err());
    let registry = super::tests::registry();
    for args in [
        json!({"action":"create_vocabulary","name":"kind:WorkItem"}),
        json!({"action":"propose_value","vocabulary":"kind:WorkItem","value":"local-task","metadata":crate::meta::kind::core_kind_manifest().unwrap().kinds.into_iter().find(|k|k.record_type=="WorkItem").unwrap().metadata}),
    ] {
        registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated("schema:owner"),
                "manage_vocabularies",
                args,
            )
            .await
            .unwrap();
    }
    assert!(call(&db, "schema:owner", args.clone()).await.is_err());
    registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("schema:owner"),
            "manage_vocabularies",
            json!({"action":"promote_value","value_id":"vv:voc:kind:WorkItem:local-task"}),
        )
        .await
        .unwrap();
    call(&db, "schema:owner", args).await.unwrap();
    let rows:Vec<(String,String,String)>=sqlx::query_as("SELECT source_id,origin,json_extract(payload,'$.created_at') FROM kernel_v1_state WHERE section='schema_config' AND json_extract(payload,'$.id')='user:imported'").fetch_all(db.pool()).await.unwrap();
    assert_eq!(
        rows,
        vec![(
            json!(["user:imported"]).to_string(),
            "schema:source".into(),
            "2026-01-01T00:00:00Z".into()
        )]
    );
}
