use super::*;
use crate::{events::KERNEL_ROOT_ID as ROOT, kernel};

fn definition(version: u32, marker: &str) -> String {
    let mut doc = json!({"family":"shape.tools","version":version,"interpreter":marker,"primary_type":"Item","description":"Tool test ontology.","kinds":[{"token":"item","description":"A numbered item.","maturity":"current","identity":{"field":"code"},"fields":[{"name":"code","type":"text","required":true,"description":"Stable code."},{"name":"value","type":"text","required":false}],"links":[]}]});
    if marker == "native.defn/5" || marker == "native.defn/6" {
        doc.as_object_mut().unwrap().remove("description");
        doc["kinds"][0]["fields"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":"measure","type":"number","required":false}));
    }
    if version == 2 {
        doc["kinds"][0]["fields"][1] = json!({"name":"value","type":"integer","required":false});
    }
    doc.to_string()
}
async fn install(db: &crate::db::Db, admin: &str, version: u32) -> RevisionIdentity {
    kernel::install_definition_as(
        db,
        admin,
        "shape.tools",
        version,
        definition(version, "native.defn/3").as_bytes(),
    )
    .await
    .unwrap()
}
async fn call(db: &crate::db::Db, admin: &str, name: &str, input: Value) -> Result<Value> {
    dispatch_typed_tool(db, admin, None, name, &input.to_string()).await
}
#[tokio::test]
async fn adoption_disable_skew_old_pin_and_refusals() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    assert!(typed_tools_for(&db, &admin, None).await.unwrap().is_empty());
    let pin1 = install(&db, &admin, 1).await;
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin1), ROOT)
        .await
        .unwrap();
    let tools = typed_tools_for(&db, &admin, None).await.unwrap();
    assert_eq!(tools.len(), 3);
    let create = tools.iter().find(|t| t.operation == "create").unwrap();
    assert_eq!(create.name, "create_shape_tools_item");
    assert!(create.description.contains("Stable code."));
    assert_eq!(
        create.input_schema["properties"]["home"]["enum"],
        json!([ROOT])
    );
    let created = call(
        &db,
        &admin,
        &create.name,
        json!({"home":ROOT,"fields":{"code":"A","value":"old"}}),
    )
    .await
    .unwrap();
    let id = created["id"].as_str().unwrap();
    let duplicate = call(
        &db,
        &admin,
        &create.name,
        json!({"home":ROOT,"fields":{"code":"A"}}),
    )
    .await
    .unwrap_err();
    let direct =
        kernel::create_json_as(&db, &admin, "shape.tools", "item", r#"{"code":"A"}"#, ROOT)
            .await
            .unwrap_err();
    assert_eq!(duplicate.to_string(), direct.to_string());
    assert!(duplicate.to_string().contains(kernel::IDENTITY_UNAVAILABLE));
    let invalid = call(
        &db,
        &admin,
        &create.name,
        json!({"home":ROOT,"fields":{"code":false}}),
    )
    .await
    .unwrap_err();
    assert!(invalid.to_string().contains("typed tool input"));
    let pin2 = install(&db, &admin, 2).await;
    let home = kernel::create_home(&db, ROOT, None, &admin).await.unwrap();
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin2), &home)
        .await
        .unwrap();
    let tools = typed_tools_for(&db, &admin, None).await.unwrap();
    assert_eq!(tools.len(), 6);
    let v1 = tools
        .iter()
        .find(|t| t.name == "create_shape_tools_item_v1")
        .unwrap();
    let v2 = tools
        .iter()
        .find(|t| t.name == "create_shape_tools_item_v2")
        .unwrap();
    assert_eq!(v1.input_schema["properties"]["home"]["enum"], json!([ROOT]));
    assert_eq!(v2.input_schema["properties"]["home"]["enum"], json!([home]));
    let scoped = typed_tools_for(&db, &admin, Some(&home)).await.unwrap();
    assert_eq!(scoped.len(), 3);
    assert!(!scoped[0].name.ends_with("_v2"));
    let record = kernel::read_record_as(&db, &admin, id)
        .await
        .unwrap()
        .unwrap();
    let revised = call(
        &db,
        &admin,
        "revise_shape_tools_item_v2",
        json!({"id":id,"expected_revision":record.revision,"fields":{"value":"still a v1 string"}}),
    )
    .await
    .unwrap();
    assert_eq!(revised["validated_pin"], json!(pin1));
    assert_eq!(revised["used_record_pin"], true);
    let updated = kernel::read_record_as(&db, &admin, id)
        .await
        .unwrap()
        .unwrap();
    let identity_patch = call(
        &db,
        &admin,
        "revise_shape_tools_item_v2",
        json!({"id":id,"expected_revision":updated.revision,"fields":{"code":"changed"}}),
    )
    .await
    .unwrap_err();
    let direct_identity = kernel::revise_json_as_expected(
        &db,
        &admin,
        id,
        r#"{"code":"changed"}"#,
        Some(updated.revision),
    )
    .await
    .unwrap_err();
    assert_eq!(identity_patch.to_string(), direct_identity.to_string());
    let stale = call(
        &db,
        &admin,
        "revise_shape_tools_item_v2",
        json!({"id":id,"expected_revision":record.revision,"fields":{"value":"stale"}}),
    )
    .await
    .unwrap_err();
    let direct = kernel::revise_json_as_expected(
        &db,
        &admin,
        id,
        r#"{"value":"stale"}"#,
        Some(record.revision),
    )
    .await
    .unwrap_err();
    assert_eq!(stale.to_string(), direct.to_string());
    call(
        &db,
        &admin,
        "create_shape_tools_item_v2",
        json!({"home":home,"fields":{"code":"B","value":2}}),
    )
    .await
    .unwrap();
    let page = call(&db, &admin, "query_shape_tools_item_v2", json!({}))
        .await
        .unwrap();
    assert_eq!(page["hits"].as_array().unwrap().len(), 2);
    assert!(page["hits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["pin"] == json!(pin1)));
    assert!(page["hits"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["pin"] == json!(pin2)));
    kernel::adopt_definition_at(&db, &admin, "shape.tools", None, &home)
        .await
        .unwrap();
    assert!(typed_tools_for(&db, &admin, Some(&home))
        .await
        .unwrap()
        .iter()
        .all(|t| t.operation == "query"));
    kernel::adopt_definition_at(&db, &admin, "shape.tools", None, ROOT)
        .await
        .unwrap();
    let disabled = typed_tools_for(&db, &admin, None).await.unwrap();
    assert_eq!(disabled.len(), 1);
    assert_eq!(disabled[0].operation, "query");
    let retained_page = call(&db, &admin, &disabled[0].name, json!({}))
        .await
        .unwrap();
    assert_eq!(retained_page["hits"].as_array().unwrap().len(), 2);
}
#[tokio::test]
async fn visibility_and_structured_raw_ingress() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    let reader = kernel::create_principal(&db, "account", "Reader", "shape:reader", &admin)
        .await
        .unwrap();
    let reader = reader.as_str();
    let private = kernel::create_home(&db, ROOT, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let visible = kernel::create_home(
        &db,
        ROOT,
        Some(&[(&admin, "manage"), (reader, "view")]),
        &admin,
    )
    .await
    .unwrap();
    let bytes = definition(1, "native.defn/6");
    let pin = kernel::install_definition_as(&db, &admin, "shape.tools", 1, bytes.as_bytes())
        .await
        .unwrap();
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin), &private)
        .await
        .unwrap();
    assert!(typed_tools_for(&db, reader, None).await.unwrap().is_empty());
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin), &visible)
        .await
        .unwrap();
    let tools = typed_tools_for(&db, reader, None).await.unwrap();
    assert_eq!(tools.len(), 2);
    assert!(tools.iter().all(|t| t.operation != "create"));
    for input in [
        Value::Null,
        json!([{"code":"A"}]),
        json!({"home":private,"fields":[]}),
    ] {
        assert!(call(&db, &admin, "create_shape_tools_item", input)
            .await
            .is_err());
    }
    let raw = format!(r#"{{"home":"{private}","fields":{{"code":"A","code":"B"}}}}"#);
    let err = dispatch_typed_tool(&db, &admin, None, "create_shape_tools_item", &raw)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("duplicate_key"));
    let precision = format!(
        r#"{{"home":"{private}","fields":{{"code":"precision","measure":1.000000000000000001}}}}"#
    );
    let err = dispatch_typed_tool(&db, &admin, None, "create_shape_tools_item", &precision)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("number_precision_loss"));

    let created = call(
        &db,
        &admin,
        "create_shape_tools_item",
        json!({"home":private,"fields":{"code":"A","value":"x"}}),
    )
    .await
    .unwrap();
    let id = created["id"].as_str().unwrap();
    let record = kernel::read_record_as(&db, &admin, id)
        .await
        .unwrap()
        .unwrap();
    call(
        &db,
        &admin,
        "revise_shape_tools_item",
        json!({"id":id,"expected_revision":record.revision,"fields":{"value":null}}),
    )
    .await
    .unwrap();
    assert!(!kernel::read_record_as(&db, &admin, id)
        .await
        .unwrap()
        .unwrap()
        .fields
        .contains_key("value"));
}

#[tokio::test]
async fn retained_fields_and_patches_survive_replaced_adoption() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    let mut v1: Value = serde_json::from_str(&definition(1, "native.defn/3")).unwrap();
    v1["kinds"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"old","type":"text","required":false}));
    let pin1 =
        kernel::install_definition_as(&db, &admin, "shape.tools", 1, v1.to_string().as_bytes())
            .await
            .unwrap();
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin1), ROOT)
        .await
        .unwrap();
    let id1 = kernel::create_json_as(
        &db,
        &admin,
        "shape.tools",
        "item",
        r#"{"code":"A","old":"retained","value":"text"}"#,
        ROOT,
    )
    .await
    .unwrap();
    let pin2 = install(&db, &admin, 2).await;
    // Replace the only adoption: the v1 schema can now be found only via retention.
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin2), ROOT)
        .await
        .unwrap();
    let id2 = kernel::create_json_as(
        &db,
        &admin,
        "shape.tools",
        "item",
        r#"{"code":"B","value":2}"#,
        ROOT,
    )
    .await
    .unwrap();
    let tools = typed_tools_for(&db, &admin, None).await.unwrap();
    assert_eq!(tools.len(), 3);
    let query = tools.iter().find(|t| t.operation == "query").unwrap();
    assert!(TYPED_TOOL_RULES
        .iter()
        .any(|r| r.contains("Older-version records may carry other fields")));
    let properties = &query.input_schema["properties"]["field_equals"]["properties"];
    let alternatives = properties["value"]["anyOf"].as_array().unwrap();
    assert!(alternatives.contains(&json!({"type":"string"})));
    assert!(alternatives.contains(&json!({"type":"integer"})));
    for (fields, expected_id) in [
        (json!({"old":"retained"}), &id1),
        (json!({"value":"text"}), &id1),
        (json!({"value":2}), &id2),
    ] {
        let input = json!({"field_equals":fields});
        assert!(jsonschema::validator_for(&query.input_schema)
            .unwrap()
            .is_valid(&input));
        let direct_fields: Vec<_> = fields
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.as_str(), v.clone()))
            .collect();
        let direct = kernel::query_as(
            &db,
            &admin,
            "shape.tools",
            "item",
            &direct_fields,
            None,
            50,
            None,
        )
        .await
        .unwrap();
        assert_eq!(direct.hits.len(), 1);
        assert_eq!(&direct.hits[0].id, expected_id);
        let page = call(&db, &admin, &query.name, input).await.unwrap();
        assert_eq!(page["hits"].as_array().unwrap().len(), 1);
        assert_eq!(page["hits"][0]["id"], json!(expected_id));
    }
    // A scalar comparison need not match the declared type to be a valid query.
    let no_match = json!({"field_equals":{"old":false}});
    assert!(jsonschema::validator_for(&query.input_schema)
        .unwrap()
        .is_valid(&no_match));
    assert!(
        call(&db, &admin, &query.name, no_match).await.unwrap()["hits"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let revise = tools.iter().find(|t| t.operation == "revise").unwrap();
    assert_eq!(
        revise.input_schema["properties"]["fields"]["anyOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for (id, fields, pin) in [
        (&id1, json!({"value":"still text","old":"updated"}), &pin1),
        (&id2, json!({"value":3}), &pin2),
    ] {
        let record = kernel::read_record_as(&db, &admin, id)
            .await
            .unwrap()
            .unwrap();
        let input = json!({"id":id,"expected_revision":record.revision,"fields":fields});
        assert!(jsonschema::validator_for(&revise.input_schema)
            .unwrap()
            .is_valid(&input));
        let result = call(&db, &admin, &revise.name, input).await.unwrap();
        assert_eq!(result["validated_pin"], json!(pin));
        assert_eq!(result["used_record_pin"], json!(pin == &pin1));
        assert_eq!(
            kernel::read_record_as(&db, &admin, id)
                .await
                .unwrap()
                .unwrap()
                .fields["value"],
            fields["value"]
        );
    }
    // The union is discovery; exact dispatch must still refuse the other pin's type.
    let record = kernel::read_record_as(&db, &admin, &id1)
        .await
        .unwrap()
        .unwrap();
    let input = json!({"id":id1,"expected_revision":record.revision,"fields":{"value":4}});
    assert!(jsonschema::validator_for(&revise.input_schema)
        .unwrap()
        .is_valid(&input));
    assert!(call(&db, &admin, &revise.name, input).await.is_err());
}

#[tokio::test]
async fn hidden_pins_are_absent_from_every_tool_output() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    let reader = kernel::create_principal(&db, "account", "Reader", "shape:reader", &admin)
        .await
        .unwrap();
    let private = kernel::create_home(&db, ROOT, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let visible = kernel::create_home(
        &db,
        ROOT,
        Some(&[(&admin, "manage"), (&reader, "view")]),
        &admin,
    )
    .await
    .unwrap();
    let mut v1: Value = serde_json::from_str(&definition(1, "native.defn/3")).unwrap();
    v1["kinds"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"secret_field","type":"time","required":false,"description":"Private field prose marker"}));
    v1["description"] = json!("Private definition prose marker");
    v1["kinds"][0]["description"] = json!("Private kind prose marker");
    v1["kinds"][0]["links"] = json!([{"predicate":"secret_link","target":{"primary_type":"Item","kind":"item"},"direction":"out","cardinality":"many"}]);
    let pin1 =
        kernel::install_definition_as(&db, &admin, "shape.tools", 1, v1.to_string().as_bytes())
            .await
            .unwrap();
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin1), &private)
        .await
        .unwrap();
    kernel::create_json_as(
        &db,
        &admin,
        "shape.tools",
        "item",
        r#"{"code":"A","secret_field":"2026-10-18T12:00:00Z"}"#,
        &private,
    )
    .await
    .unwrap();
    let pin2 = install(&db, &admin, 2).await;
    for home in [&visible] {
        kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin2), home)
            .await
            .unwrap();
    }
    let tools = typed_tools_for(&db, &reader, None).await.unwrap();
    let published = serde_json::to_string(&tools).unwrap();
    let generic = kernel::describe_world_as(&db, &reader)
        .await
        .unwrap()
        .to_string();
    for hidden in [
        "secret_field",
        "Private field prose marker",
        "Private definition prose marker",
        "Private kind prose marker",
        "secret_link",
        &pin1.digest,
        "chrono",
    ] {
        assert!(
            !generic.contains(hidden),
            "generic describe leaked {hidden}"
        );
        assert!(!published.contains(hidden), "typed tools leaked {hidden}");
    }
    let query = tools.iter().find(|t| t.operation == "query").unwrap();
    assert!(
        query.input_schema["properties"]["field_equals"]["properties"]
            .get("secret_field")
            .is_none()
    );
    let revise = tools.iter().find(|t| t.operation == "revise").unwrap();
    assert_eq!(
        revise.input_schema["properties"]["fields"]["anyOf"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let admin_tools = typed_tools_for(&db, &admin, Some(&visible)).await.unwrap();
    let query = admin_tools.iter().find(|t| t.operation == "query").unwrap();
    // Discovery scope does not restrict the visible homes searched by query_as.
    assert!(
        query.input_schema["properties"]["field_equals"]["properties"]
            .get("secret_field")
            .is_some()
    );
}

#[tokio::test]
async fn lab_and_estate_relationship_discovery_and_queries() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    // Trial fixtures are test inputs, outside the production Docker context.
    let fixtures =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/prototypes/slice2_trial");
    for family in ["lab", "estate"] {
        let bytes = std::fs::read_to_string(fixtures.join(format!("{family}.defn.json")))
            .expect("trial definition fixture present");
        let pin = kernel::install_definition_as(&db, &admin, family, 1, bytes.as_bytes())
            .await
            .unwrap();
        kernel::adopt_definition_at(&db, &admin, family, Some(&pin), ROOT)
            .await
            .unwrap();
    }
    let tools = typed_tools_for(&db, &admin, None).await.unwrap();
    assert_eq!(tools.len(), 24);
    for tool in &tools {
        for generic in TYPED_TOOL_RULES {
            assert!(
                !tool.description.contains(generic),
                "generic rule repeated in {}: {generic}",
                tool.name
            );
        }
        for generic in tool
            .shape
            .non_expressible
            .iter()
            .filter(|r| matches!(r.rule.as_str(), "scope_adoption" | "revise_state"))
        {
            assert!(!tool.description.contains(&generic.reason));
        }
        assert!(tool
            .description
            .starts_with(tool.shape.description.as_deref().unwrap()));
        if tool.operation == "query" {
            for rule in tool.shape.non_expressible.iter().filter(|r| {
                matches!(
                    r.rule.as_str(),
                    "integer_spelling" | "temporal_grammar" | "value_budget" | "raw_json"
                )
            }) {
                assert!(!tool.description.contains(&rule.reason));
            }
        }
    }
    assert!(tools.iter().all(|t| !t.name.starts_with("link_")));
    for operation in ["create", "revise", "query"] {
        for (kind, expected) in [
            (
                "lab_Aliquot",
                "derived_from to lab/Specimen (out; cardinality many)",
            ),
            (
                "estate_Offer",
                "offer_on to estate/Listing (out; cardinality many)",
            ),
            (
                "lab_Specimen",
                "derived_from from lab/Aliquot (in; source out; cardinality many)",
            ),
            (
                "estate_Listing",
                "offer_on from estate/Offer (in; source out; cardinality many)",
            ),
        ] {
            let tool = tools
                .iter()
                .find(|t| t.name == format!("{operation}_{kind}"))
                .unwrap();
            assert!(
                tool.description.contains(expected),
                "{}: {}",
                tool.name,
                tool.description
            );
            assert!(tool.description.contains("cardinality many"));
        }
    }
    let specimen =
        kernel::create_json_as(&db, &admin, "lab", "Specimen", r#"{"accession":"S"}"#, ROOT)
            .await
            .unwrap();
    let aliquot = kernel::create_json_as(
        &db,
        &admin,
        "lab",
        "Aliquot",
        r#"{"accession":"A","volume_ml":1}"#,
        ROOT,
    )
    .await
    .unwrap();
    let listing = kernel::create_json_as(
        &db,
        &admin,
        "estate",
        "Listing",
        r#"{"listing_ref":"L","asking_price":10,"status":"active"}"#,
        ROOT,
    )
    .await
    .unwrap();
    let offer = kernel::create_json_as(
        &db,
        &admin,
        "estate",
        "Offer",
        r#"{"offer_ref":"O","amount":10,"made_at":"2026-10-18T12:00:00Z","status":"pending"}"#,
        ROOT,
    )
    .await
    .unwrap();
    for (family, source_kind, target_kind, source, target, predicate) in [
        (
            "lab",
            "Aliquot",
            "Specimen",
            &aliquot,
            &specimen,
            "derived_from",
        ),
        ("estate", "Offer", "Listing", &offer, &listing, "offer_on"),
    ] {
        kernel::link_as(&db, &admin, source, predicate, target)
            .await
            .unwrap();
        for (kind, linked_id, expected_id, direction) in [
            (source_kind, target, source, "out"),
            (target_kind, source, target, "in"),
        ] {
            let query = tools
                .iter()
                .find(|t| t.name == format!("query_{family}_{kind}"))
                .unwrap();
            let predicate_schema =
                &query.input_schema["properties"]["linked_to"]["properties"]["predicate"];
            assert!(predicate_schema["anyOf"][0]["enum"]
                .as_array()
                .unwrap()
                .contains(&json!(predicate)));
            let input =
                json!({"linked_to":{"predicate":predicate,"id":linked_id,"direction":direction}});
            assert!(jsonschema::validator_for(&query.input_schema)
                .unwrap()
                .is_valid(&input));
            let page = call(&db, &admin, &query.name, input).await.unwrap();
            assert_eq!(page["hits"].as_array().unwrap().len(), 1);
            assert_eq!(page["hits"][0]["id"], json!(expected_id));
            // The kernel permits undeclared strings and every query direction.
            for direction in ["out", "in", "either"] {
                let input = json!({"linked_to":{"predicate":"not_declared","id":linked_id,"direction":direction}});
                assert!(jsonschema::validator_for(&query.input_schema)
                    .unwrap()
                    .is_valid(&input));
                let direct = kernel::query_as(
                    &db,
                    &admin,
                    family,
                    kind,
                    &[],
                    Some(("not_declared", linked_id, direction)),
                    50,
                    None,
                )
                .await
                .unwrap();
                assert!(direct.hits.is_empty());
                assert!(call(&db, &admin, &query.name, input).await.unwrap()["hits"]
                    .as_array()
                    .unwrap()
                    .is_empty());
            }
        }
    }
    // /4 selectors and governed references must remain visible as metadata too.
    let bytes = json!({"family":"shape.links","version":1,"primary_type":"Thing","interpreter":"native.defn/4",
        "kinds":[{"token":"thing","description":"Link metadata.","maturity":"current","identity":{"mode":"record"},"fields":[],"links":[
        {"relationship_ref":{"namespace":"demo","package":"links","version":1,"relationship":"mentions"},"target":{"any_record":true},"direction":"out"},
        {"predicate":"parent","target":{"family":"shape.links","kind":"thing"},"direction":"either","cardinality":"one"}]}]}).to_string();
    let shape = TypedShape::from_bytes(&bytes, "thing").unwrap();
    let (description, predicates) = relationship_view(&shape, &[]);
    assert!(description.contains("relationship_ref demo/links version 1 relationship mentions to any record (out; cardinality unspecified)"));
    assert!(description.contains("parent to shape.links/thing (either; cardinality one)"));
    assert!(TYPED_TOOL_RULES
        .iter()
        .any(|r| r.contains("does not create symmetry")));
    assert_eq!(predicates, vec!["parent"]);
}

#[tokio::test]
async fn unknown_scalar_filters_match_kernel_without_advertising_names() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    let pin = install(&db, &admin, 1).await;
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin), ROOT)
        .await
        .unwrap();
    kernel::create_json_as(&db, &admin, "shape.tools", "item", r#"{"code":"A"}"#, ROOT)
        .await
        .unwrap();
    let tools = typed_tools_for(&db, &admin, None).await.unwrap();
    let query = tools.iter().find(|t| t.operation == "query").unwrap();
    assert!(
        query.input_schema["properties"]["field_equals"]["properties"]
            .get("unknown_field")
            .is_none()
    );
    for scalar in [
        json!("absent"),
        json!(3),
        json!(1.5),
        json!(true),
        Value::Null,
    ] {
        let input = json!({"field_equals":{"unknown_field":scalar}});
        assert!(jsonschema::validator_for(&query.input_schema)
            .unwrap()
            .is_valid(&input));
        let direct = kernel::query_as(
            &db,
            &admin,
            "shape.tools",
            "item",
            &[("unknown_field", scalar)],
            None,
            50,
            None,
        )
        .await
        .unwrap();
        assert!(direct.hits.is_empty());
        assert!(call(&db, &admin, &query.name, input).await.unwrap()["hits"]
            .as_array()
            .unwrap()
            .is_empty());
    }
    for structured in [json!({}), json!([])] {
        assert!(!jsonschema::validator_for(&query.input_schema)
            .unwrap()
            .is_valid(&json!({"field_equals":{"unknown_field":structured}})));
    }
}

#[tokio::test]
async fn legacy_link_selectors_ignore_newer_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    let mut doc: Value = serde_json::from_str(&definition(1, "native.defn/3")).unwrap();
    for token in ["other", "unrelated"] {
        let mut kind = doc["kinds"][0].clone();
        kind["token"] = json!(token);
        doc["kinds"].as_array_mut().unwrap().push(kind);
    }
    doc["kinds"][0]["links"] = json!([{"predicate":"only_other","target":{
        "primary_type":"Item","kind":"other","any_record":true,"family":"ignored.selector"},
        "relationship_ref":"ignored.reference","direction":"out","cardinality":"many"}]);
    let bytes = doc.to_string();
    let shape = TypedShape::from_bytes(&bytes, "item").unwrap();
    assert_eq!(
        shape.links[0]["target"],
        json!({"primary_type":"Item","kind":"other"})
    );
    assert!(shape.links[0].get("relationship_ref").is_none());
    let pin = kernel::install_definition_as(&db, &admin, "shape.tools", 1, bytes.as_bytes())
        .await
        .unwrap();
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin), ROOT)
        .await
        .unwrap();
    let tools = typed_tools_for(&db, &admin, None).await.unwrap();
    let source_tool = tools
        .iter()
        .find(|t| t.name == "query_shape_tools_item")
        .unwrap();
    assert!(source_tool.description.contains("shape.tools/other"));
    assert!(!source_tool.description.contains("any record"));
    assert!(!serde_json::to_string(&tools)
        .unwrap()
        .contains("ignored.selector"));
    for tool in tools.iter().filter(|t| t.shape.kind == "unrelated") {
        assert!(!tool.description.contains("only_other"));
        assert!(!tool.input_schema.to_string().contains("only_other"));
    }
    let target_tool = tools
        .iter()
        .find(|t| t.name == "query_shape_tools_other")
        .unwrap();
    assert!(target_tool
        .description
        .contains("only_other from shape.tools/item (in;"));
    let mut ids = vec![];
    for kind in ["item", "other", "unrelated"] {
        ids.push(
            kernel::create_json_as(&db, &admin, "shape.tools", kind, r#"{"code":"A"}"#, ROOT)
                .await
                .unwrap(),
        );
    }
    kernel::link_as(&db, &admin, &ids[0], "only_other", &ids[1])
        .await
        .unwrap();
    assert!(kernel::link_as(&db, &admin, &ids[0], "only_other", &ids[2])
        .await
        .is_err());
    let page = call(
        &db,
        &admin,
        &target_tool.name,
        json!({"linked_to":{"predicate":"only_other","id":ids[0],"direction":"in"}}),
    )
    .await
    .unwrap();
    assert_eq!(page["hits"][0]["id"], json!(ids[1]));
}

#[tokio::test]
async fn revise_describes_limitations_of_every_visible_pin() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    let mut old: Value = serde_json::from_str(&definition(1, "native.defn/6")).unwrap();
    old["kinds"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"when","type":"time","required":false}));
    let bytes = old.to_string();
    let old_shape = TypedShape::from_bytes(&bytes, "item").unwrap();
    let old_pin = kernel::install_definition_as(&db, &admin, "shape.tools", 1, bytes.as_bytes())
        .await
        .unwrap();
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&old_pin), ROOT)
        .await
        .unwrap();
    let id = kernel::create_json_as(
        &db,
        &admin,
        "shape.tools",
        "item",
        r#"{"code":"A","when":"2026-10-18T12:00:00Z"}"#,
        ROOT,
    )
    .await
    .unwrap();
    let new_pin = install(&db, &admin, 2).await;
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&new_pin), ROOT)
        .await
        .unwrap();
    let tools = typed_tools_for(&db, &admin, None).await.unwrap();
    let revise = tools.iter().find(|t| t.operation == "revise").unwrap();
    let create = tools.iter().find(|t| t.operation == "create").unwrap();
    for rule in ["temporal_grammar", "value_budget", "raw_json"] {
        let reason = &old_shape
            .non_expressible
            .iter()
            .find(|r| r.rule == rule)
            .unwrap()
            .reason;
        assert!(
            revise.description.contains(reason),
            "missing retained rule {rule}"
        );
        assert!(
            !create.description.contains(reason),
            "current create gained retained rule {rule}"
        );
    }
    let record = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    let input = json!({"id":id,"expected_revision":record.revision,"fields":{"when":"2026-10-19T12:00:00Z"}});
    assert!(jsonschema::validator_for(&revise.input_schema)
        .unwrap()
        .is_valid(&input));
    assert_eq!(
        call(&db, &admin, &revise.name, input).await.unwrap()["validated_pin"],
        json!(old_pin)
    );
}

#[tokio::test]
async fn descriptions_put_meaning_before_shape_specific_rules() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    let mut doc: Value = serde_json::from_str(&definition(1, "native.defn/3")).unwrap();
    doc["kinds"][0]["fields"][1]["description"] = json!("Changeable text.");
    doc["kinds"][0]["fields"].as_array_mut().unwrap().push(
        json!({"name":"when","type":"time","required":false,"description":"Observation instant."}),
    );
    doc["kinds"][0]["links"] = json!([{"predicate":"previous","target":{"primary_type":"Item","kind":"item"},"direction":"out","cardinality":"one"}]);
    let pin =
        kernel::install_definition_as(&db, &admin, "shape.tools", 1, doc.to_string().as_bytes())
            .await
            .unwrap();
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin), ROOT)
        .await
        .unwrap();
    let tools = typed_tools_for(&db, &admin, None).await.unwrap();
    assert_eq!(
        TYPED_TOOL_RULES
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        TYPED_TOOL_RULES.len()
    );
    for tool in tools {
        assert!(tool
            .description
            .starts_with("Tool test ontology. A numbered item."));
        let mut end = 0;
        for phrase in [
            "Tool test ontology.",
            "A numbered item.",
            "code: Stable code.",
            "value: Changeable text.",
            "when: Observation instant.",
            "Identity is the code field,",
            "Links:",
        ] {
            let at = tool.description.find(phrase).unwrap();
            assert!(at >= end, "{} put {phrase} out of order", tool.name);
            end = at + phrase.len();
        }
        assert!(tool
            .description
            .contains("previous to shape.tools/item (out; cardinality one)"));
        for generic in TYPED_TOOL_RULES {
            assert!(!tool.description.contains(generic));
        }
        for generic in tool
            .shape
            .non_expressible
            .iter()
            .filter(|r| matches!(r.rule.as_str(), "scope_adoption" | "revise_state"))
        {
            assert!(!tool.description.contains(&generic.reason));
        }
        let temporal = &tool
            .shape
            .non_expressible
            .iter()
            .find(|r| r.rule == "temporal_grammar")
            .unwrap()
            .reason;
        if tool.operation == "query" {
            assert!(!tool.description.contains(temporal));
        } else {
            assert!(tool.description.find(temporal).unwrap() >= end);
        }
        assert!(!tool.description.contains("i64/u64"));
    }
}

#[tokio::test]
async fn opaque_v1_link_metadata_does_not_panic_discovery() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    let bytes = json!({"family":"shape.opaque","version":1,"primary_type":"Item",
        "kinds":[{"token":"item","links":[false]}]})
    .to_string();
    let pin = kernel::install_definition_as(&db, &admin, "shape.opaque", 1, bytes.as_bytes())
        .await
        .unwrap();
    kernel::adopt_definition_at(&db, &admin, "shape.opaque", Some(&pin), ROOT)
        .await
        .unwrap();
    kernel::describe_world_as(&db, &admin).await.unwrap();
    let id = kernel::create_json_as(&db, &admin, "shape.opaque", "item", "{}", ROOT)
        .await
        .unwrap();
    assert!(TypedShape::from_bytes(&bytes, "item")
        .unwrap()
        .links
        .is_empty());
    let tools = typed_tools_for(&db, &admin, None).await.unwrap();
    assert_eq!(tools.len(), 3);
    assert!(tools.iter().all(|t| !t.description.contains("Links:")));
    let query = tools.iter().find(|t| t.operation == "query").unwrap();
    let page = call(&db, &admin, &query.name, json!({})).await.unwrap();
    assert_eq!(page["hits"][0]["id"], json!(id));
}

#[tokio::test]
async fn revise_identity_rules_are_scoped_to_each_records_pin() {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("test.db").to_str().unwrap(),
        "account",
        "Admin",
        "shape:admin",
    )
    .await
    .unwrap();
    let mut old: Value = serde_json::from_str(&definition(1, "native.defn/3")).unwrap();
    old["kinds"][0]["identity"] = json!({"mode":"record"});
    let pin1 =
        kernel::install_definition_as(&db, &admin, "shape.tools", 1, old.to_string().as_bytes())
            .await
            .unwrap();
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin1), ROOT)
        .await
        .unwrap();
    let id1 = kernel::create_json_as(&db, &admin, "shape.tools", "item", r#"{"code":"A"}"#, ROOT)
        .await
        .unwrap();
    // Equal code values do not collide under record identity.
    let duplicate =
        kernel::create_json_as(&db, &admin, "shape.tools", "item", r#"{"code":"A"}"#, ROOT)
            .await
            .unwrap();
    assert_ne!(id1, duplicate);
    let pin2 = install(&db, &admin, 2).await;
    kernel::adopt_definition_at(&db, &admin, "shape.tools", Some(&pin2), ROOT)
        .await
        .unwrap();
    let id2 = kernel::create_json_as(&db, &admin, "shape.tools", "item", r#"{"code":"C"}"#, ROOT)
        .await
        .unwrap();
    let tools = typed_tools_for(&db, &admin, None).await.unwrap();
    let revise = tools.iter().find(|t| t.operation == "revise").unwrap();
    let description = &revise.description;
    assert!(description.contains("Identity by record pin:"));
    assert!(description.contains(&format!(
        "{}: Each record has its own identity; fields may be revised subject to this pin's schema.",
        pin1.value_string()
    )));
    assert!(description.contains(&format!("{}: Identity is the code field, immutable and unique workspace-wide for this family and kind.", pin2.value_string())));
    assert_eq!(description.matches("Identity is the code field").count(), 1);
    let create = tools.iter().find(|t| t.operation == "create").unwrap();
    assert!(create
        .description
        .contains("Identity is the code field, immutable"));
    assert!(!create.description.contains(&pin1.value_string()));
    let record = kernel::read_record_as(&db, &admin, &id1)
        .await
        .unwrap()
        .unwrap();
    let patch = json!({"id":id1,"expected_revision":record.revision,"fields":{"code":"B"}});
    assert!(jsonschema::validator_for(&revise.input_schema)
        .unwrap()
        .is_valid(&patch));
    let result = call(&db, &admin, &revise.name, patch).await.unwrap();
    assert_eq!(result["validated_pin"], json!(pin1));
    assert_eq!(result["used_record_pin"], true);
    assert_eq!(
        kernel::read_record_as(&db, &admin, &id1)
            .await
            .unwrap()
            .unwrap()
            .fields["code"],
        "B"
    );
    let record = kernel::read_record_as(&db, &admin, &id2)
        .await
        .unwrap()
        .unwrap();
    let patch = json!({"id":id2,"expected_revision":record.revision,"fields":{"code":"D"}});
    assert!(jsonschema::validator_for(&revise.input_schema)
        .unwrap()
        .is_valid(&patch));
    let refused = call(&db, &admin, &revise.name, patch).await.unwrap_err();
    let direct = kernel::revise_json_as_expected(
        &db,
        &admin,
        &id2,
        r#"{"code":"D"}"#,
        Some(record.revision),
    )
    .await
    .unwrap_err();
    assert_eq!(refused.to_string(), direct.to_string());
    assert_eq!(
        kernel::read_record_as(&db, &admin, &id2)
            .await
            .unwrap()
            .unwrap()
            .fields["code"],
        "C"
    );
}
