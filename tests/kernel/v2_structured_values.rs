//! Gated structural proof only: these saved-view shapes are not product evidence.
use native_ce::{events::KERNEL_ROOT_ID, kernel};
use serde_json::{json, Value};

fn map(value: Value) -> serde_json::Map<String, Value> {
    value.as_object().unwrap().clone()
}

async fn world(bytes: &str) -> (tempfile::TempDir, native_ce::db::Db, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proof.db");
    let (db, admin) =
        kernel::create_v2_database(path.to_str().unwrap(), "account", "Admin", "acct:admin")
            .await
            .unwrap();
    let package = native_ce::package_manifest::PackageManifest {
        namespace: "fixture.structured".into(),
        name: "proof".into(),
        version: 1,
        definitions: vec![native_ce::package_manifest::DefinitionEntry {
            family: "fixture.structured".into(),
            version: 1,
            artifact_bytes: bytes.into(),
            digest: native_ce::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes()),
        }],
        behaviour: None,
        surface: None,
        declared_reads: vec![],
        operations: vec![],
    };
    let identity = package.identity().unwrap();
    kernel::install_package_as(&db, &admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &package, Some(&identity), &[])
        .await
        .unwrap();
    (dir, db, admin)
}

async fn create(
    db: &native_ce::db::Db,
    actor: &str,
    family: &str,
    kind: &str,
    fields: &serde_json::Map<String, Value>,
    home: &str,
) -> native_ce::Result<String> {
    kernel::create_json_as(
        db,
        actor,
        family,
        kind,
        &serde_json::to_string(fields)?,
        home,
    )
    .await
}
async fn revise(
    db: &native_ce::db::Db,
    actor: &str,
    id: &str,
    fields: &serde_json::Map<String, Value>,
    revision: Option<i64>,
) -> native_ce::Result<()> {
    kernel::revise_json_as_expected(db, actor, id, &serde_json::to_string(fields)?, revision).await
}
async fn revise_unconditional(
    db: &native_ce::db::Db,
    actor: &str,
    id: &str,
    fields: &serde_json::Map<String, Value>,
) -> native_ce::Result<()> {
    revise(db, actor, id, fields, None).await
}

async fn events(db: &native_ce::db::Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn integer_spelling_rule_is_event_free_on_create_and_revise() {
    for interpreter in ["native.defn/3", native_ce::structured_values::INTERPRETER] {
        let bytes = json!({"family":"fixture.structured","version":1,"interpreter":interpreter,
        "primary_type":"Proof","kinds":[{"token":"integer","description":"Integer proof","maturity":"current",
        "identity":{"mode":"record"},"fields":[{"name":"count","type":"integer","required":true}],"links":[]}]}).to_string();
        let (_dir, db, admin) = world(&bytes).await;
        let id = create(
            &db,
            &admin,
            "fixture.structured",
            "integer",
            &map(json!({"count":1})),
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
        let revision = kernel::read_record_as(&db, &admin, &id)
            .await
            .unwrap()
            .unwrap()
            .revision;
        for spelling in ["1.0", "1e0", "-0", "-0.0", "2.5"] {
            let fields = map(serde_json::from_str(&format!("{{\"count\":{spelling}}}")).unwrap());
            let before = events(&db).await;
            let error = create(
                &db,
                &admin,
                "fixture.structured",
                "integer",
                &fields,
                KERNEL_ROOT_ID,
            )
            .await
            .unwrap_err();
            let expected = if interpreter == "native.defn/3" {
                "field 'count' has wrong type, expected integer for kind 'integer'"
            } else {
                "wrong_type at /count"
            };
            assert_engine(error, expected);
            assert_engine(
                revise(&db, &admin, &id, &fields, Some(revision))
                    .await
                    .unwrap_err(),
                expected,
            );
            assert_eq!(events(&db).await, before);
        }
        assert_eq!(
            kernel::read_record_as(&db, &admin, &id)
                .await
                .unwrap()
                .unwrap()
                .fields["count"],
            json!(1)
        );
        db.close().await;
    }
}

fn field(name: &str, ty: &str, required: bool) -> Value {
    json!({"name":name,"type":ty,"required":required})
}
fn object(name: &str, required: bool, fields: Vec<Value>) -> Value {
    json!({"name":name,"type":"object","required":required,"fields":fields})
}
fn choice(name: &str, values: &[&str]) -> Value {
    json!({"name":name,"type":"choice","required":true,"values":values})
}
fn list(name: &str, max: usize, fields: Vec<Value>) -> Value {
    json!({"name":name,"type":"list","required":true,"max_items":max,"items":{"type":"object","fields":fields}})
}
fn proof_definition() -> Value {
    let docs = object(
        "definition",
        true,
        vec![
            choice("app", &["fixture.docs"]),
            choice("format", &["docs-start/1"]),
            object(
                "target",
                true,
                vec![
                    field("database", "text", true),
                    field("record", "text", true),
                    field("hint", "text", false),
                ],
            ),
        ],
    );
    let tracker = object(
        "definition",
        true,
        vec![
            choice("app", &["fixture.tracker"]),
            choice("format", &["tracker-start/1"]),
            field("scope", "text", true),
            list(
                "sort",
                8,
                vec![
                    field("field", "text", true),
                    choice("direction", &["asc", "desc"]),
                ],
            ),
            object(
                "filter",
                true,
                vec![
                    choice("combine", &["all"]),
                    list(
                        "terms",
                        16,
                        vec![
                            field("field", "text", true),
                            choice("op", &["eq", "neq"]),
                            field("value", "text", true),
                        ],
                    ),
                ],
            ),
            choice("layout", &["table", "board"]),
        ],
    );
    let impact = vec![
        object(
            "magnitude",
            false,
            vec![
                field("value", "number", true),
                field("unit", "text", true),
                field("per", "text", false),
            ],
        ),
        object(
            "window",
            false,
            vec![field("start", "date", true), field("end", "date", true)],
        ),
    ];
    let kind = |token: &str, fields: Vec<Value>| json!({"token":token,"description":"Structural proof only; not product evidence.","maturity":"current","identity":{"mode":"record"},"fields":fields,"links":[]});
    json!({"family":"fixture.structured","version":1,"interpreter":native_ce::structured_values::INTERPRETER,"primary_type":"Proof",
        "kinds":[kind("docs_view", vec![field("label", "text", true), docs]),kind("tracker_view", vec![field("label", "text", true), tracker]),kind("impact", impact)]})
}
fn docs() -> Value {
    json!({"label":"Plan","definition":{"app":"fixture.docs","format":"docs-start/1","target":{"database":"somewhere","record":"nonexistent-but-nonblank","hint":"optional"}}})
}
fn tracker() -> Value {
    json!({"label":"Work","definition":{"app":"fixture.tracker","format":"tracker-start/1","scope":"launch","sort":[{"field":"priority","direction":"desc"},{"field":"title","direction":"asc"}],"filter":{"combine":"all","terms":[{"field":"status","op":"eq","value":"open"}]},"layout":"table"}})
}

#[tokio::test]
async fn closed_shapes_and_grouping_with_nested_event_free_refusals() {
    let (_dir, db, admin) = world(&proof_definition().to_string()).await;
    for (kind, value) in [
        ("docs_view", docs()),
        ("tracker_view", tracker()),
        ("impact", json!({})),
        // Grouping does not enforce date ordering or unit consistency.
        (
            "impact",
            json!({"magnitude":{"value":3,"unit":"hours"},"window":{"start":"2026-10-08","end":"2026-10-01"}}),
        ),
    ] {
        create(
            &db,
            &admin,
            "fixture.structured",
            kind,
            &map(value),
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
    }
    let mut missing = docs();
    missing["definition"]["target"]
        .as_object_mut()
        .unwrap()
        .remove("record");
    let mut unknown = docs();
    unknown["definition"]["target"]["url"] = Value::Null;
    let mut null = docs();
    null["definition"]["target"]["record"] = Value::Null;
    let mut blank = docs();
    blank["definition"]["target"]["record"] = " ".into();
    let mut wrong_choice = tracker();
    wrong_choice["definition"]["sort"][0]["direction"] = "down".into();
    let mut numeric = tracker();
    numeric["definition"]["filter"]["terms"][0]["value"] = 3.into();
    let mut any = tracker();
    any["definition"]["filter"]["combine"] = "any".into();
    let mut overflow = tracker();
    overflow["definition"]["sort"] = json!(vec![json!({"field":"x","direction":"asc"}); 9]);
    for (kind, value, path) in [
        (
            "docs_view",
            missing,
            "required_missing at /definition/target/record",
        ),
        (
            "docs_view",
            unknown,
            "unknown_member at /definition/target/url",
        ),
        (
            "docs_view",
            null,
            "null_not_supported at /definition/target/record",
        ),
        (
            "docs_view",
            blank,
            "wrong_type at /definition/target/record",
        ),
        (
            "tracker_view",
            wrong_choice,
            "wrong_type at /definition/sort/0/direction",
        ),
        (
            "tracker_view",
            numeric,
            "wrong_type at /definition/filter/terms/0/value",
        ),
        (
            "tracker_view",
            any,
            "wrong_type at /definition/filter/combine",
        ),
        (
            "tracker_view",
            overflow,
            "limit_exceeded at /definition/sort",
        ),
        (
            "impact",
            json!({"magnitude":{"value":3}}),
            "required_missing at /magnitude/unit",
        ),
        (
            "impact",
            json!({"unknown":null}),
            "unknown_member at /unknown",
        ),
    ] {
        let before = events(&db).await;
        let err = create(
            &db,
            &admin,
            "fixture.structured",
            kind,
            &map(value),
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains(path), "{err}");
        assert_eq!(events(&db).await, before);
    }
    let mut empty = tracker();
    empty["definition"]["sort"] = json!([]);
    empty["definition"]["filter"]["terms"] = json!([]);
    create(
        &db,
        &admin,
        "fixture.structured",
        "tracker_view",
        &map(empty),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    db.close().await;
}

#[test]
fn strict_schema_and_raw_json_budgets() {
    use native_ce::{
        meta::definition_artifact::validate_kernel_definition_bytes as validate,
        structured_values::parse_json,
    };
    assert!(validate(&proof_definition().to_string()).is_ok());
    for key in ["nullable", "min_items", "typo"] {
        let mut def = proof_definition();
        def["kinds"][0]["fields"][1][key] = true.into();
        assert_engine(
            validate(&def.to_string()).unwrap_err(),
            &format!("unknown_member at /kinds/0/fields/1/{key}"),
        );
    }
    let mut def = proof_definition();
    def["kinds"][1]["fields"][1]["fields"][3]["max_items"] = 129.into();
    assert_engine(
        validate(&def.to_string()).unwrap_err(),
        "limit_exceeded at /kinds/1/fields/1/fields/3/max_items",
    );
    let mut def = proof_definition();
    def["kinds"][0]["identity"] = json!({"field":"definition"});
    assert_engine(
        validate(&def.to_string()).unwrap_err(),
        "invalid_identity at /kinds/0/identity",
    );
    assert!(parse_json(r#"{"x":1,"x":2}"#)
        .unwrap_err()
        .to_string()
        .contains("duplicate_key"));
    let oversized = format!("{{\"value\":\"{}\"}}", "x".repeat(256 * 1024));
    assert_engine(parse_json(&oversized).unwrap_err(), "limit_exceeded at ");
    let raw = proof_definition()
        .to_string()
        .replace("\"label\"", "\"label\",\"name\":\"duplicate\"");
    assert_json_code(validate(&raw).unwrap_err(), "duplicate_key");
}

#[tokio::test]
async fn guarded_replacement_conflict_and_atomic_refusal() {
    let (_dir, db, admin) = world(&proof_definition().to_string()).await;
    let initial = map(tracker());
    let id = create(
        &db,
        &admin,
        "fixture.structured",
        "tracker_view",
        &initial,
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let first = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    let second = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    let before = events(&db).await;
    assert!(
        revise_unconditional(&db, &admin, &id, &map(json!({"label":"No token"})))
            .await
            .unwrap_err()
            .to_string()
            .contains("expected_revision_required")
    );
    assert_eq!(events(&db).await, before);
    let mut changed_sort = tracker();
    changed_sort["definition"]["sort"]
        .as_array_mut()
        .unwrap()
        .reverse();
    revise(
        &db,
        &admin,
        &id,
        &map(json!({"definition":changed_sort["definition"]})),
        Some(first.revision),
    )
    .await
    .unwrap();
    let before = events(&db).await;
    let err = revise(
        &db,
        &admin,
        &id,
        &map(json!({"definition":tracker()["definition"]})),
        Some(second.revision),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, native_ce::Error::Conflict(_)));
    assert_eq!(events(&db).await, before);
    let current = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    // Whole-field replacement: partial objects never merge with their old members.
    for (patch, expected) in [
        (
            json!({"label":"Must not persist","definition":{"layout":"board"}}),
            "required_missing at /definition/app",
        ),
        (
            json!({"not_declared":null}),
            "unknown_member at /not_declared",
        ),
        (
            json!({"definition":null}),
            "required_missing at /definition",
        ),
    ] {
        assert_engine(
            revise(&db, &admin, &id, &map(patch), Some(current.revision))
                .await
                .unwrap_err(),
            expected,
        );
        assert_eq!(events(&db).await, before);
        assert_eq!(
            kernel::read_record_as(&db, &admin, &id)
                .await
                .unwrap()
                .unwrap(),
            current
        );
    }
    // Reread/reconcile succeeds and keeps the record's identity and pin.
    let mut reconciled = changed_sort;
    reconciled["definition"]["filter"]["terms"] = json!([]);
    revise(
        &db,
        &admin,
        &id,
        &map(json!({"label":"Reconciled","definition":reconciled["definition"]})),
        Some(current.revision),
    )
    .await
    .unwrap();
    let after = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.id, current.id);
    assert_eq!(after.pin, current.pin);
    assert_eq!(after.fields["definition"]["filter"]["terms"], json!([]));
    let docs_id = create(
        &db,
        &admin,
        "fixture.structured",
        "docs_view",
        &map(docs()),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let current = kernel::read_record_as(&db, &admin, &docs_id)
        .await
        .unwrap()
        .unwrap();
    let mut replacement = docs();
    replacement["definition"]["target"]
        .as_object_mut()
        .unwrap()
        .remove("hint");
    revise(
        &db,
        &admin,
        &docs_id,
        &map(json!({"definition":replacement["definition"]})),
        Some(current.revision),
    )
    .await
    .unwrap();
    assert!(kernel::read_record_as(&db, &admin, &docs_id)
        .await
        .unwrap()
        .unwrap()
        .fields["definition"]["target"]
        .get("hint")
        .is_none());
    let grouped = create(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        &map(json!({"magnitude":{"value":3,"unit":"hours"}})),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let current = kernel::read_record_as(&db, &admin, &grouped)
        .await
        .unwrap()
        .unwrap();
    revise(
        &db,
        &admin,
        &grouped,
        &map(json!({"magnitude":null})),
        Some(current.revision),
    )
    .await
    .unwrap();
    assert!(kernel::read_record_as(&db, &admin, &grouped)
        .await
        .unwrap()
        .unwrap()
        .fields
        .is_empty());
    db.close().await;
}

#[tokio::test]
async fn whole_value_matching_normalizes_objects_but_preserves_lists() {
    let (_dir, db, admin) = world(&proof_definition().to_string()).await;
    let one = create(
        &db,
        &admin,
        "fixture.structured",
        "tracker_view",
        &map(tracker()),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let two = create(
        &db,
        &admin,
        "fixture.structured",
        "tracker_view",
        &map(tracker()),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    assert_ne!(
        one, two,
        "identical saved configurations have distinct record identity"
    );
    let definition = tracker()["definition"].clone();
    let permuted: Value = serde_json::from_str(r#"{"layout":"table","filter":{"terms":[{"value":"open","op":"eq","field":"status"}],"combine":"all"},"sort":[{"direction":"desc","field":"priority"},{"direction":"asc","field":"title"}],"scope":"launch","format":"tracker-start/1","app":"fixture.tracker"}"#).unwrap();
    let first = kernel::query_as(
        &db,
        &admin,
        "fixture.structured",
        "tracker_view",
        &[("definition", permuted.clone())],
        None,
        1,
        None,
    )
    .await
    .unwrap();
    assert_eq!(first.hits.len(), 1);
    let next = kernel::query_as(
        &db,
        &admin,
        "fixture.structured",
        "tracker_view",
        &[("definition", definition.clone())],
        None,
        1,
        first.cursor.as_deref(),
    )
    .await
    .unwrap();
    assert_eq!(next.hits.len(), 1);
    assert_ne!(first.hits[0].id, next.hits[0].id);
    let mut reversed = permuted;
    reversed["sort"].as_array_mut().unwrap().reverse();
    assert!(kernel::query_as(
        &db,
        &admin,
        "fixture.structured",
        "tracker_view",
        &[("definition", reversed.clone())],
        None,
        10,
        None
    )
    .await
    .unwrap()
    .hits
    .is_empty());
    let current = kernel::read_record_as(&db, &admin, &one)
        .await
        .unwrap()
        .unwrap();
    revise(
        &db,
        &admin,
        &one,
        &map(json!({"definition":reversed})),
        Some(current.revision),
    )
    .await
    .unwrap();
    let page = kernel::query_as(
        &db,
        &admin,
        "fixture.structured",
        "tracker_view",
        &[("definition", definition)],
        None,
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(page.hits.len(), 1);
    assert_eq!(page.hits[0].id, two);
    // Duplicate elements are valid, but their order and multiplicity participate in equality.
    let mut duplicates = tracker();
    duplicates["definition"]["sort"] =
        json!([{"field":"title","direction":"asc"},{"field":"title","direction":"asc"}]);
    create(
        &db,
        &admin,
        "fixture.structured",
        "tracker_view",
        &map(duplicates),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let impact = create(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        &map(json!({"magnitude":{"value":3,"unit":"hours"}})),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let integer_rep = kernel::query_as(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        &[("magnitude", json!({"unit":"hours","value":3}))],
        None,
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(integer_rep.hits[0].id, impact);
    let float_rep = kernel::query_as(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        &[("magnitude", json!({"unit":"hours","value":3.0}))],
        None,
        10,
        None,
    )
    .await
    .unwrap();
    assert!(
        float_rep.hits.is_empty(),
        "number equality preserves representation rather than coercing 3.0 to 3"
    );
    db.close().await;
}

#[test]
fn normalization_v1_numeric_and_string_golden_cases() {
    use native_ce::structured_values::{normalize, parse_json};
    for (raw, expected) in [
        ("1", "1"),
        ("1.0", "1.0"),
        ("1e2", "100.0"),
        ("-0.0", "0.0"),
        ("-0", "0.0"),
        (r#"{"z":[1,1.0],"a":"\u0061"}"#, r#"{"a":"a","z":[1,1.0]}"#),
    ] {
        assert_eq!(
            serde_json::to_string(&normalize(&parse_json(raw).unwrap())).unwrap(),
            expected
        );
    }
    assert_ne!(normalize(&json!(1)), normalize(&json!(1.0)));
}

#[tokio::test]
async fn describe_discovers_shapes_package_pins_and_guarded_edit_contract() {
    let (_dir, db, admin) = world(&proof_definition().to_string()).await;
    let package_bytes: String = sqlx::query_scalar("SELECT manifest_bytes FROM package_artifacts WHERE namespace = 'fixture.structured' AND name = 'proof'").fetch_one(db.pool()).await.unwrap();
    let installed: Value = serde_json::from_str(&package_bytes).unwrap();
    let supplied_pin = &installed["definitions"][0];
    let described = kernel::describe_world_as(&db, &admin).await.unwrap();
    let entries = described["definitions"].as_array().unwrap();
    for kind in ["docs_view", "tracker_view", "impact"] {
        let entry = entries.iter().find(|e| e["kind"] == kind).unwrap();
        assert_eq!(
            entry["interpreter"],
            native_ce::structured_values::INTERPRETER
        );
        assert_eq!(entry["package"]["namespace"], "fixture.structured");
        assert_eq!(entry["package"]["name"], "proof");
        assert_eq!(
            entry["value_contract"]["revise"]["expected_revision_required"],
            true
        );
        assert_eq!(entry["value_contract"]["matching"]["nested_paths"], false);
        assert_eq!(entry["value_contract"]["limits"]["container_depth"], 4);
        assert_eq!(entry["value_contract"]["semantic_rules"], false);
        assert_eq!(
            entry["value_contract"]["text_locators_grant_authority"],
            false
        );
        assert_eq!(
            entry["fields"],
            proof_definition()["kinds"]
                .as_array()
                .unwrap()
                .iter()
                .find(|k| k["token"] == kind)
                .unwrap()["fields"]
        );
        assert_eq!(entry["version"], supplied_pin["version"]);
        assert_eq!(entry["digest"], supplied_pin["digest"]);
        assert_eq!(entry["adoption"]["pin"]["family"], supplied_pin["family"]);
        assert_eq!(entry["adoption"]["pin"]["version"], supplied_pin["version"]);
        assert_eq!(entry["adoption"]["pin"]["digest"], supplied_pin["digest"]);
    }
    db.close().await;
}

#[test]
fn descriptor_depth_field_and_node_ceilings() {
    use native_ce::meta::definition_artifact::validate_kernel_definition_bytes as validate;
    let mut def = proof_definition();
    let mut nested = field("leaf", "text", true);
    for _ in 0..4 {
        nested = object("nested", true, vec![nested]);
    }
    def["kinds"][0]["fields"] = json!([nested.clone()]);
    assert!(validate(&def.to_string()).is_ok());
    def["kinds"][0]["fields"] = json!([object("too_deep", true, vec![nested])]);
    assert!(validate(&def.to_string())
        .unwrap_err()
        .to_string()
        .contains("limit_exceeded"));
    def["kinds"][0]["fields"] = json!((0..65)
        .map(|i| field(&format!("f{i}"), "text", false))
        .collect::<Vec<_>>());
    assert_engine(
        validate(&def.to_string()).unwrap_err(),
        "limit_exceeded at /kinds/0/fields",
    );
    def["kinds"][0]["fields"] = json!((0..4)
        .map(|i| object(
            &format!("g{i}"),
            false,
            (0..64)
                .map(|j| field(&format!("f{j}"), "text", false))
                .collect()
        ))
        .collect::<Vec<_>>());
    assert!(validate(&def.to_string())
        .unwrap_err()
        .to_string()
        .contains("limit_exceeded"));
}

#[tokio::test]
async fn value_budgets_and_escaped_error_paths() {
    let mut def = proof_definition();
    def["kinds"] = json!([
        {"token":"escaped","description":"Escaped paths","maturity":"current","identity":{"mode":"record"},"links":[],"fields":[object("a/b~c", true, vec![field("required", "text", true)])]},
        {"token":"bytes","description":"Byte budget","maturity":"current","identity":{"mode":"record"},"links":[],"fields":(0..64).map(|i| field(&format!("f{i}"), "text", false)).collect::<Vec<_>>()},
        {"token":"nodes","description":"Node budget","maturity":"current","identity":{"mode":"record"},"links":[],"fields":[list("items", 128, (0..8).map(|i| field(&format!("f{i}"), "text", true)).collect())]}
    ]);
    let (_dir, db, admin) = world(&def.to_string()).await;
    let bytes: serde_json::Map<String, Value> = (0..64)
        .map(|i| (format!("f{i}"), Value::String("x".repeat(2000))))
        .collect();
    let item: serde_json::Map<String, Value> =
        (0..8).map(|i| (format!("f{i}"), json!("x"))).collect();
    for (kind, values, expected) in [
        (
            "escaped",
            map(json!({"a/b~c":{}})),
            "required_missing at /a~1b~0c/required",
        ),
        ("bytes", bytes, "limit_exceeded"),
        (
            "bytes",
            map(json!({"f0":"x".repeat(4097)})),
            "limit_exceeded at /f0",
        ),
        (
            "nodes",
            map(json!({"items":vec![Value::Object(item);128]})),
            "limit_exceeded",
        ),
    ] {
        let before = events(&db).await;
        let error = create(
            &db,
            &admin,
            "fixture.structured",
            kind,
            &values,
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(events(&db).await, before);
    }
    db.close().await;
}

#[tokio::test]
async fn raw_write_ingress_rejects_duplicate_keys_before_values_collapse() {
    let (_dir, db, admin) = world(&proof_definition().to_string()).await;
    let before = events(&db).await;
    assert!(kernel::create_json_as(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        r#"{"magnitude":{"value":1,"value":2,"unit":"hours"}}"#,
        KERNEL_ROOT_ID
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("duplicate_key"));
    assert!(kernel::create_json_as(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        &" ".repeat(256 * 1024 + 1),
        KERNEL_ROOT_ID
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("limit_exceeded"));
    assert_eq!(events(&db).await, before);
    let id = kernel::create_json_as(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        "{}",
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let current = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    let before = events(&db).await;
    assert!(kernel::revise_json_as_expected(
        &db,
        &admin,
        &id,
        r#"{"magnitude":null,"magnitude":{"value":3,"unit":"hours"}}"#,
        Some(current.revision)
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("duplicate_key"));
    assert_eq!(events(&db).await, before);
    db.close().await;
}

#[tokio::test]
async fn legacy_marker_probe_preserves_legacy_parsing() {
    use native_ce::meta::definition_artifact::validate_kernel_definition_bytes as validate;
    let legacy = json!({"family":"fixture.structured","version":1,"interpreter":"native.defn/3",
        "primary_type":"Proof","kinds":[{"token":"integer","description":"Legacy parsing","maturity":"current",
        "identity":{"mode":"record"},"fields":[{"name":"count","type":"integer","required":true,"ignored_legacy_key":true}],"links":[]}]}).to_string();
    assert!(validate(&legacy).is_ok());
    let duplicate = legacy.replace(
        "\"interpreter\":\"native.defn/3\"",
        "\"interpreter\":\"native.defn/5\",\"interpreter\":\"native.defn/3\"",
    );
    assert!(
        validate(&duplicate).is_ok(),
        "legacy duplicate marker retains last-key interpretation"
    );
    let (_dir, db, admin) = world(&duplicate).await;
    let id = kernel::create_json_as(
        &db,
        &admin,
        "fixture.structured",
        "integer",
        r#"{"count":1,"count":2}"#,
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    assert_eq!(
        kernel::read_record_as(&db, &admin, &id)
            .await
            .unwrap()
            .unwrap()
            .fields["count"],
        2
    );
    // Inject correctly hashed retained bytes to exercise live create's fold
    // refusal independently of the install validator. This is isolated
    // projection-corruption setup, never a supported installation path.
    let fixture_writer = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        _dir.path().join("proof.db").display()
    ))
    .await
    .unwrap();
    let new_wins = legacy.replace(
        "\"interpreter\":\"native.defn/3\"",
        "\"interpreter\":\"native.defn/3\",\"interpreter\":\"native.defn/5\"",
    );
    assert_json_code(validate(&new_wins).unwrap_err(), "duplicate_key");
    let digest = native_ce::meta::definition_artifact::digest_artifact_bytes(new_wins.as_bytes());
    let pin = native_ce::meta::definition_artifact::RevisionIdentity {
        family: "fixture.structured".into(),
        version: 1,
        digest: digest.clone(),
    };
    sqlx::query(
        "UPDATE definition_artifacts SET id = ?, digest = ?, artifact_bytes = ? WHERE family = ?",
    )
    .bind(pin.value_id())
    .bind(&digest)
    .bind(&new_wins)
    .bind("fixture.structured")
    .execute(&fixture_writer)
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_adoptions SET selected_digest = ? WHERE family = ?")
        .bind(&digest)
        .bind("fixture.structured")
        .execute(&fixture_writer)
        .await
        .unwrap();
    let before = events(&db).await;
    assert_json_code(
        kernel::create_json_as(
            &db,
            &admin,
            "fixture.structured",
            "integer",
            r#"{"count":1}"#,
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap_err(),
        "duplicate_key",
    );
    assert_eq!(events(&db).await, before);
    db.close().await;
    let mut non_string: Value = serde_json::from_str(&legacy).unwrap();
    non_string["interpreter"] = json!(17);
    assert!(
        validate(&non_string.to_string()).is_ok(),
        "legacy non-string marker is still interpreted as absent"
    );
}

#[tokio::test]
async fn parsed_maps_refuse_structured_writes_without_events() {
    let (_dir, db, admin) = world(&proof_definition().to_string()).await;
    let fields = map(tracker());
    let before = events(&db).await;
    let expected =
        "raw_json_required: use create_json_as or revise_json_as_expected for structured values";
    assert_engine(
        kernel::create_as(
            &db,
            &admin,
            "fixture.structured",
            "tracker_view",
            &fields,
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap_err(),
        expected,
    );
    assert_eq!(events(&db).await, before);
    let id = create(
        &db,
        &admin,
        "fixture.structured",
        "tracker_view",
        &fields,
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let revision = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    let before = events(&db).await;
    assert_engine(
        kernel::revise_as_expected(&db, &admin, &id, &fields, Some(revision))
            .await
            .unwrap_err(),
        expected,
    );
    assert_engine(
        kernel::revise_as(&db, &admin, &id, &fields)
            .await
            .unwrap_err(),
        expected,
    );
    assert_eq!(events(&db).await, before);
    db.close().await;
}

fn assert_engine(error: native_ce::Error, expected: &str) {
    match error {
        native_ce::Error::Engine(message) => assert_eq!(message, expected),
        other => panic!("expected engine refusal {expected:?}, got {other:?}"),
    }
}

#[tokio::test]
async fn fieldless_creation_validates_required_fields_and_optional_null_is_absent() {
    let mut def = proof_definition();
    def["kinds"].as_array_mut().unwrap().push(json!({"token":"named","description":"Named identity","maturity":"current","identity":{"field":"name"},"fields":[field("name", "text", true)],"links":[]}));
    let (_dir, db, admin) = world(&def.to_string()).await;
    let fixture_writer = sqlx::SqlitePool::connect(&format!(
        "sqlite://{}",
        _dir.path().join("proof.db").display()
    ))
    .await
    .unwrap();
    sqlx::query("INSERT INTO kernel_policy_entries (root_id, subject_kind, subject_id, effect, capability) VALUES (?, 'members', ?, 'allow', 'edit')")
        .bind(KERNEL_ROOT_ID).bind(native_ce::authorization::MEMBERS_SUBJECT_ID).execute(&fixture_writer).await.unwrap();
    for (kind, path) in [("docs_view", "/label"), ("named", "/name")] {
        let before = events(&db).await;
        assert_engine(
            kernel::create_package_record_as(
                &db,
                &admin,
                KERNEL_ROOT_ID,
                "Proof",
                kind,
                "unused",
                "fixture.structured",
            )
            .await
            .unwrap_err(),
            &format!("required_missing at {path}"),
        );
        assert_engine(
            kernel::create_package_record(&db, "Proof", kind, "unused", "fixture.structured")
                .await
                .unwrap_err(),
            &format!("required_missing at {path}"),
        );
        assert_eq!(events(&db).await, before);
    }
    let id = kernel::create_package_record_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "Proof",
        "impact",
        "empty-impact",
        "fixture.structured",
    )
    .await
    .unwrap();
    assert!(kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap()
        .fields
        .is_empty());
    let id = kernel::create_json_as(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        r#"{"magnitude":null}"#,
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let payload: String =
        sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id = ?")
            .bind(&id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&payload).unwrap()["fields"],
        json!({})
    );
    db.close().await;
}

#[tokio::test]
async fn raw_numbers_refuse_precision_collisions_and_match_floating_zero() {
    use native_ce::structured_values::{normalize, parse_json};
    for token in ["18446744073709551617", "0.1234567890123456789", "1e-500"] {
        let error = parse_json(&format!(
            "{{\"magnitude\":{{\"value\":{token},\"unit\":\"hours\"}}}}"
        ))
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("number_precision_loss at /magnitude/value"),
            "{error}"
        );
    }
    for token in [
        "9223372036854775807",
        "-9223372036854775808",
        "18446744073709551615",
        "1",
        "1.0",
        "0.1",
        "1e2",
    ] {
        assert!(parse_json(token).is_ok(), "{token}");
    }
    assert_eq!(normalize(&parse_json("-0.0").unwrap()).to_string(), "0.0");
    assert_ne!(
        normalize(&parse_json("1").unwrap()),
        normalize(&parse_json("1.0").unwrap())
    );
    let (_dir, db, admin) = world(&proof_definition().to_string()).await;
    let before = events(&db).await;
    let error = kernel::create_json_as(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        r#"{"magnitude":{"value":18446744073709551617,"unit":"hours"}}"#,
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("number_precision_loss at /magnitude/value"),
        "{error}"
    );
    assert_eq!(events(&db).await, before);
    let id = kernel::create_json_as(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        r#"{"magnitude":{"value":-0.0,"unit":"hours"}}"#,
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let read = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.fields["magnitude"]["value"].to_string(), "0.0");
    let matched = kernel::query_as(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        &[("magnitude", json!({"value":0.0,"unit":"hours"}))],
        None,
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(matched.hits.len(), 1);
    assert_eq!(matched.hits[0].id, id);
    db.close().await;
}

fn assert_json_code(error: native_ce::Error, expected: &str) {
    match error {
        native_ce::Error::Json(error) => assert_eq!(
            error.to_string().split(" at line").next().unwrap(),
            expected
        ),
        other => panic!("expected JSON refusal {expected:?}, got {other:?}"),
    }
}

#[test]
fn language_capabilities_preserve_legacy_and_inherit_closed_links() {
    use native_ce::meta::definition_artifact::language_capabilities as capabilities;
    assert!(!capabilities(None).supports_fields);
    assert!(!capabilities(Some("native.defn/2")).supports_record_identity);
    assert!(capabilities(Some("native.defn/3")).supports_record_identity);
    assert!(!capabilities(Some("native.defn/3")).requires_required_identity);
    let structured = capabilities(Some(native_ce::structured_values::INTERPRETER));
    assert!(structured.supports_fields);
    assert!(structured.supports_record_identity);
    assert!(structured.supports_structured_values);
    assert!(structured.requires_required_identity);
    let links = capabilities(Some("native.defn/4"));
    assert!(links.supports_closed_links);
    assert!(links.requires_required_identity);
    assert!(!links.supports_structured_values);
    assert!(structured.supports_closed_links);
    assert_eq!(structured.scalar_base_interpreter, Some("native.defn/4"));
}

#[tokio::test]
async fn closed_link_selectors_are_inherited_through_install_create_and_link() {
    let mut definition = proof_definition();
    definition["kinds"].as_array_mut().unwrap().push(json!({
        "token":"linked", "description":"Structured and closed-link integration proof.",
        "maturity":"current", "identity":{"field":"title"},
        "fields":[field("title", "text", true), object("config", true, vec![field("enabled", "boolean", true)])],
        "links":[
            {"predicate":"documents","target":{"family":"fixture.links_target","kind":"task"},"direction":"out","cardinality":"many"},
            {"predicate":"associates","target":{"any_record":true},"direction":"out","cardinality":"many"}
        ]
    }));
    let (_dir, db, admin) = world(&definition.to_string()).await;
    let target_definition = json!({
        "family":"fixture.links_target", "version":1, "interpreter":"native.defn/4",
        "primary_type":"Proof", "kinds":[{"token":"task", "description":"Foreign target.",
        "maturity":"current", "identity":{"mode":"record"}, "fields":[], "links":[]}]
    });
    let pin = kernel::install_definition_as(
        &db,
        &admin,
        "fixture.links_target",
        1,
        &serde_json::to_vec(&target_definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&db, &admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let target = kernel::create_as(
        &db,
        &admin,
        "fixture.links_target",
        "task",
        &map(json!({})),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let source = kernel::create_json_as(
        &db,
        &admin,
        "fixture.structured",
        "linked",
        r#"{"title":"source","config":{"enabled":true}}"#,
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let any_target = kernel::create_json_as(
        &db,
        &admin,
        "fixture.structured",
        "impact",
        "{}",
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    for (predicate, target) in [("documents", &target), ("associates", &any_target)] {
        kernel::link_as(&db, &admin, &source, predicate, target)
            .await
            .unwrap();
        let witness: String = sqlx::query_scalar("SELECT witness_json FROM kernel_link4_edges WHERE source_id = ? AND target_id = ? AND predicate = ?")
            .bind(&source).bind(target).bind(predicate).fetch_one(db.pool()).await.unwrap();
        let witness: Value = serde_json::from_str(&witness).unwrap();
        assert_eq!(witness["source"]["binding"]["interpreter"], "native.defn/5");
        assert_eq!(
            witness["declaration"]["target"],
            if predicate == "documents" {
                json!({"family":"fixture.links_target","kind":"task"})
            } else {
                json!({"any_record":true})
            }
        );
    }
    assert_eq!(
        kernel::read_record_as(&db, &admin, &source)
            .await
            .unwrap()
            .unwrap()
            .fields["config"],
        json!({"enabled":true})
    );
    db.close().await;
}
