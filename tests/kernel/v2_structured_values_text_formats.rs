//! Gated end-to-end proof for `native.defn/6` text formats and `max_length`
//! (design a328c07), beside the same shapes under `/5`.
use native_ce::{events::KERNEL_ROOT_ID, kernel, structured_values};
use serde_json::{json, Value};

const V5: &str = structured_values::INTERPRETER;
const V6: &str = structured_values::INTERPRETER_V6;
const V4_ID: &str = "0b9c6c0e-5d2b-4a40-8e0f-1f2e3d4c5b6a";

fn family(interpreter: &str) -> &'static str {
    if interpreter == V6 {
        "fixture.text6"
    } else {
        "fixture.text5"
    }
}

/// One kind whose fields use the new keys under `/6` and only the `/5`
/// vocabulary otherwise. `formatted` adds the keys; `plain` does not.
fn definition(interpreter: &str, with_keys: bool) -> Value {
    let keyed = |extra: Value| -> Value {
        let mut field = extra;
        if !with_keys {
            let obj = field.as_object_mut().unwrap();
            obj.remove("text_format");
            obj.remove("max_length");
        }
        field
    };
    json!({"family":family(interpreter),"version":1,"interpreter":interpreter,
    "primary_type":"Proof","kinds":[{"token":"item","description":"Text format proof","maturity":"current",
      "identity":{"mode":"record"},"links":[],"fields":[
        keyed(json!({"name":"colour","type":"text","required":false,"text_format":"hex_colour"})),
        keyed(json!({"name":"label","type":"text","required":false,"max_length":3})),
        {"name":"title","type":"text","required":true},
        {"name":"note","type":"text","required":false},
        {"name":"definition","type":"object","required":false,"fields":[
          keyed(json!({"name":"app","type":"text","required":true,"text_format":"dotted_id","max_length":128})),
          {"name":"terms","type":"list","required":false,"max_items":8,"items":{"type":"object","fields":[
            keyed(json!({"name":"field","type":"text","required":true,"text_format":"snake_field","max_length":64}))]}}]},
        {"name":"ids","type":"list","required":false,"max_items":8,
          "items": keyed(json!({"type":"text","text_format":"uuid_v4v7"}))}
      ]}]})
}

async fn world(defs: &[Value]) -> (tempfile::TempDir, native_ce::db::Db, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("proof.db");
    let (db, admin) =
        kernel::create_v2_database(path.to_str().unwrap(), "account", "Admin", "acct:admin")
            .await
            .unwrap();
    let definitions = defs
        .iter()
        .map(|def| {
            let bytes = def.to_string();
            native_ce::package_manifest::DefinitionEntry {
                family: def["family"].as_str().unwrap().into(),
                version: 1,
                digest: native_ce::meta::definition_artifact::digest_artifact_bytes(
                    bytes.as_bytes(),
                ),
                artifact_bytes: bytes,
            }
        })
        .collect();
    let package = native_ce::package_manifest::PackageManifest {
        namespace: "fixture.text".into(),
        name: "proof".into(),
        version: 1,
        definitions,
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
    admin: &str,
    interpreter: &str,
    fields: Value,
) -> native_ce::Result<String> {
    kernel::create_json_as(
        db,
        admin,
        family(interpreter),
        "item",
        &fields.to_string(),
        KERNEL_ROOT_ID,
    )
    .await
}
async fn revise(
    db: &native_ce::db::Db,
    admin: &str,
    id: &str,
    fields: Value,
) -> native_ce::Result<()> {
    let revision = kernel::read_record_as(db, admin, id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::revise_json_as_expected(db, admin, id, &fields.to_string(), Some(revision)).await
}
async fn events(db: &native_ce::db::Db) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap()
}
async fn refused(
    db: &native_ce::db::Db,
    admin: &str,
    interpreter: &str,
    fields: Value,
    expected: &str,
) {
    let before = events(db).await;
    let error = create(db, admin, interpreter, fields).await.unwrap_err();
    assert!(
        error.to_string().contains(expected),
        "{error} !~ {expected}"
    );
    assert_eq!(events(db).await, before, "refusal must be event-free");
}
async fn revise_refused(
    db: &native_ce::db::Db,
    admin: &str,
    id: &str,
    fields: Value,
    expected: &str,
) {
    let before = events(db).await;
    let error = revise(db, admin, id, fields).await.unwrap_err();
    assert!(
        error.to_string().contains(expected),
        "{error} !~ {expected}"
    );
    assert_eq!(events(db).await, before, "refusal must be event-free");
}
async fn revise_event_interpreters(db: &native_ce::db::Db, id: &str) -> Vec<String> {
    let payloads: Vec<String> = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id = ? AND type = 'kernel.record_revised.v2' ORDER BY seq",
    )
    .bind(id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    payloads
        .iter()
        .map(|p| {
            serde_json::from_str::<Value>(p).unwrap()["interpreter"]
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

#[tokio::test]
async fn v6_create_revise_and_replay_with_formats() {
    // A top-level formatted text field (`colour`, `label`) passes the /4 adapter
    // at install; the retained bytes keep the keys.
    let def = definition(V6, true);
    let (_dir, db, admin) = world(std::slice::from_ref(&def)).await;
    let stored: String = sqlx::query_scalar(
        "SELECT artifact_bytes FROM definition_artifacts WHERE family = 'fixture.text6'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(stored, def.to_string());

    let good = json!({"title":"One","colour":"#aBcDeF","label":"日本語",
        "definition":{"app":"native.foci","terms":[{"field":"status"},{"field":"sort_key"}]},"ids":[V4_ID]});
    let id = create(&db, &admin, V6, good.clone()).await.unwrap();
    let read = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.interpreter.as_deref(), Some(V6));
    assert_eq!(
        read.fields["colour"], "#aBcDeF",
        "values are never rewritten"
    );

    for (fields, expected) in [
        (
            json!({"title":"x","colour":"#12345"}),
            "text_format_mismatch at /colour",
        ),
        (
            json!({"title":"x","colour":"#abcdef\n"}),
            "text_format_mismatch at /colour",
        ),
        (
            json!({"title":"x","label":"abcd"}),
            "limit_exceeded at /label",
        ),
        (
            json!({"title":"x","label":"日本語字"}),
            "limit_exceeded at /label",
        ),
        (json!({"title":"\u{FEFF}"}), "wrong_type at /title"),
        (json!({"title":"\u{3000}\u{FEFF}"}), "wrong_type at /title"),
        (
            json!({"title":"x","ids":[V4_ID, "NATIVE:root"]}),
            "text_format_mismatch at /ids/1",
        ),
        (
            json!({"title":"x","definition":{"app":"nodots"}}),
            "text_format_mismatch at /definition/app",
        ),
        (
            json!({"title":"x","definition":{"app":"a.b","terms":[{"field":"ok"},{"field":"Bad"}]}}),
            "text_format_mismatch at /definition/terms/1/field",
        ),
        (
            json!({"title":"x","definition":{"app":format!("a.{}", "b".repeat(127))}}),
            "limit_exceeded at /definition/app",
        ),
    ] {
        refused(&db, &admin, V6, fields, expected).await;
    }
    // A boundary-length app passes.
    create(
        &db,
        &admin,
        V6,
        json!({"title":"edge","definition":{"app":format!("a.{}", "b".repeat(126))}}),
    )
    .await
    .unwrap();

    // Revise: whole-field replacement validates under the retained /6 pin.
    revise_refused(
        &db,
        &admin,
        &id,
        json!({"colour":"red"}),
        "text_format_mismatch at /colour",
    )
    .await;
    revise_refused(
        &db,
        &admin,
        &id,
        json!({"title":"\u{FEFF}"}),
        "wrong_type at /title",
    )
    .await;
    revise_refused(
        &db,
        &admin,
        &id,
        json!({"label":"abcd"}),
        "limit_exceeded at /label",
    )
    .await;
    revise(
        &db,
        &admin,
        &id,
        json!({"colour":"#000000","label":"e\u{301}x"}),
    )
    .await
    .unwrap();
    revise(&db, &admin, &id, json!({"label":null}))
        .await
        .unwrap();
    assert_eq!(revise_event_interpreters(&db, &id).await, [V6, V6]);

    // Replay reproduces every projection, including the /6 revise stamp check.
    let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
    kernel::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
    let replayed = kernel::read_record_as(&db, &admin, &id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(replayed.fields["colour"], "#000000");
    assert!(replayed.fields.get("label").is_none());
    assert_eq!(replayed.interpreter.as_deref(), Some(V6));
    db.close().await;
}

#[tokio::test]
async fn v5_refuses_the_keys_and_behaves_as_before() {
    // Installing /5 bytes that use the new keys fails, so no /5 record can
    // depend on them.
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("p.db").to_str().unwrap(),
        "account",
        "Admin",
        "acct:admin",
    )
    .await
    .unwrap();
    let bytes = definition(V5, true).to_string();
    let package = native_ce::package_manifest::PackageManifest {
        namespace: "fixture.text".into(),
        name: "proof".into(),
        version: 1,
        definitions: vec![native_ce::package_manifest::DefinitionEntry {
            family: "fixture.text5".into(),
            version: 1,
            digest: native_ce::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes()),
            artifact_bytes: bytes,
        }],
        behaviour: None,
        surface: None,
        declared_reads: vec![],
        operations: vec![],
    };
    let error = kernel::install_package_as(&db, &admin, &package)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unknown_member at /kinds/0/fields/0/text_format"),
        "{error}"
    );
    db.close().await;

    // A /5 definition without the keys: the old Rust-trim blank rule and no
    // format or length checks; U+FEFF is accepted for required text.
    let (_dir, db, admin) = world(&[definition(V5, false)]).await;
    let id = create(
        &db,
        &admin,
        V5,
        json!({"title":"\u{FEFF}","colour":"anything","label":"much longer than three"}),
    )
    .await
    .unwrap();
    refused(
        &db,
        &admin,
        V5,
        json!({"title":"\u{3000}"}),
        "wrong_type at /title",
    )
    .await;
    refused(
        &db,
        &admin,
        V5,
        json!({"title":" "}),
        "wrong_type at /title",
    )
    .await;
    revise(
        &db,
        &admin,
        &id,
        json!({"title":"\u{FEFF}\u{FEFF}","colour":"#zzz"}),
    )
    .await
    .unwrap();
    revise_refused(
        &db,
        &admin,
        &id,
        json!({"title":"\t"}),
        "wrong_type at /title",
    )
    .await;
    assert_eq!(revise_event_interpreters(&db, &id).await, [V5]);
    let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
    kernel::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());
    db.close().await;
}

#[tokio::test]
async fn feff_is_accepted_under_v5_and_refused_under_v6_in_one_world() {
    let (_dir, db, admin) = world(&[definition(V5, false), definition(V6, true)]).await;
    create(&db, &admin, V5, json!({"title":"\u{FEFF}"}))
        .await
        .unwrap();
    refused(
        &db,
        &admin,
        V6,
        json!({"title":"\u{FEFF}"}),
        "wrong_type at /title",
    )
    .await;
    // Each family's revise events carry its own record's interpreter.
    let five = create(&db, &admin, V5, json!({"title":"a"})).await.unwrap();
    let six = create(&db, &admin, V6, json!({"title":"a"})).await.unwrap();
    revise(&db, &admin, &five, json!({"title":"\u{FEFF}"}))
        .await
        .unwrap();
    revise_refused(
        &db,
        &admin,
        &six,
        json!({"title":"\u{FEFF}"}),
        "wrong_type at /title",
    )
    .await;
    revise(&db, &admin, &six, json!({"title":"b"}))
        .await
        .unwrap();
    assert_eq!(revise_event_interpreters(&db, &five).await, [V5]);
    assert_eq!(revise_event_interpreters(&db, &six).await, [V6]);
    let before = kernel::dump_all_kernel_tables(&db).await.unwrap();
    kernel::replay_all_projections(&db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&db).await.unwrap());

    // Describe is version-specific: formats appear only for the /6 kind.
    let described = kernel::describe_world_as(&db, &admin).await.unwrap();
    let entries = described["definitions"].as_array().unwrap();
    let entry = |fam: &str| {
        entries
            .iter()
            .find(|e| e["family"] == fam && e["kind"] == "item")
            .unwrap()
            .clone()
    };
    let (e5, e6) = (entry("fixture.text5"), entry("fixture.text6"));
    assert_eq!(e5["interpreter"], V5);
    assert_eq!(e6["interpreter"], V6);
    assert!(e5["value_contract"].get("text_formats").is_none());
    assert_eq!(e5["value_contract"]["limits"].get("max_length_unit"), None);
    assert_eq!(
        e6["value_contract"]["limits"]["max_length_unit"],
        "unicode_scalar_values"
    );
    assert_eq!(e6["value_contract"]["limits"]["text_bytes"], 4096);
    let names: Vec<&str> = e6["value_contract"]["text_formats"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(names.len(), 7);
    assert!(e6["value_contract"]["text_formats"][0]["abnf"]
        .as_str()
        .unwrap()
        .starts_with("uuid-v4v7 = "));
    db.close().await;
}

#[tokio::test]
async fn normalised_matching_works_for_v5_and_v6() {
    let (_dir, db, admin) = world(&[definition(V5, false), definition(V6, true)]).await;
    for interpreter in [V5, V6] {
        let one = create(
            &db,
            &admin,
            interpreter,
            json!({"title":"t","definition":{"app":"a.b","terms":[{"field":"x"}]}}),
        )
        .await
        .unwrap();
        // Stored normalised (sorted keys); the permuted probe still matches.
        let probe: Value =
            serde_json::from_str(r#"{"terms":[{"field":"x"}],"app":"a.b"}"#).unwrap();
        let hits = kernel::query_as(
            &db,
            &admin,
            family(interpreter),
            "item",
            &[("definition", probe)],
            None,
            10,
            None,
        )
        .await
        .unwrap();
        assert_eq!(hits.hits.len(), 1, "{interpreter}");
        assert_eq!(hits.hits[0].id, one);
        // After a revise the matching still sees the normalised value.
        revise(
            &db,
            &admin,
            &one,
            json!({"definition":{"terms":[{"field":"y"}],"app":"a.c"}}),
        )
        .await
        .unwrap();
        let probe: Value =
            serde_json::from_str(r#"{"terms":[{"field":"y"}],"app":"a.c"}"#).unwrap();
        let hits = kernel::query_as(
            &db,
            &admin,
            family(interpreter),
            "item",
            &[("definition", probe)],
            None,
            10,
            None,
        )
        .await
        .unwrap();
        assert_eq!(hits.hits.len(), 1, "{interpreter}");
    }
    db.close().await;
}

#[tokio::test]
async fn v6_definition_refusals_at_install() {
    for (field, expected) in [
        (
            json!({"name":"t","type":"text","required":false,"text_format":"uuid"}),
            "unknown_text_format at /kinds/0/fields/0/text_format",
        ),
        (
            json!({"name":"t","type":"text","required":false,"max_length":0}),
            "limit_exceeded at /kinds/0/fields/0/max_length",
        ),
        (
            json!({"name":"t","type":"text","required":false,"max_length":4097}),
            "limit_exceeded at /kinds/0/fields/0/max_length",
        ),
        (
            json!({"name":"t","type":"integer","required":false,"max_length":5}),
            "unknown_member at /kinds/0/fields/0/max_length",
        ),
    ] {
        let mut def = definition(V6, true);
        def["kinds"][0]["fields"] = json!([field]);
        let error = native_ce::meta::definition_artifact::validate_kernel_definition_bytes(
            &def.to_string(),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "{error} !~ {expected}"
        );
    }
}
