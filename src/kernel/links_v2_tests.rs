#![cfg(feature = "v2-kernel-probe")]

use crate::{db::Db, events::KERNEL_ROOT_ID, kernel, meta::definition_artifact::RevisionIdentity};
use serde_json::{json, Value};

struct World {
    _dir: tempfile::TempDir,
    db: Db,
    admin: String,
}

fn definition(family: &str, version: u32, kind: &str, links: Value) -> Value {
    json!({"family":family,"version":version,"interpreter":"native.defn/4","primary_type":"SameLabel",
        "kinds":[{"token":kind,"fields":[{"name":"title","type":"text","required":false}],
        "identity":{"mode":"record"},"links":links,"maturity":"current","description":"Fixture."}]})
}
fn link(predicate: &str, target: Value) -> Value {
    json!({"predicate":predicate,"target":target,"direction":"out","cardinality":"many"})
}
fn assert_engine(error: crate::Error, expected: &str) {
    match error {
        crate::Error::Engine(message) => assert_eq!(message, expected),
        other => panic!("expected Engine({expected:?}), got {other:?}"),
    }
}
fn assert_conflict(error: crate::Error, expected: &str) {
    match error {
        crate::Error::Conflict(message) => assert_eq!(message, expected),
        other => panic!("expected Conflict({expected:?}), got {other:?}"),
    }
}
impl World {
    async fn fresh() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let url = format!("sqlite://{}", dir.path().join("links.db").display());
        let (db, admin) = kernel::create_v2_database(&url, "account", "Admin", "acct:admin")
            .await
            .unwrap();
        Self {
            _dir: dir,
            db,
            admin,
        }
    }
    async fn install(&self, doc: &Value) -> RevisionIdentity {
        kernel::install_definition_as(
            &self.db,
            &self.admin,
            doc["family"].as_str().unwrap(),
            doc["version"].as_u64().unwrap() as u32,
            &serde_json::to_vec(doc).unwrap(),
        )
        .await
        .unwrap()
    }
    async fn adopt(&self, pin: &RevisionIdentity) {
        kernel::adopt_definition_as(&self.db, &self.admin, &pin.family, Some(pin))
            .await
            .unwrap();
    }
    async fn record(&self, family: &str, kind: &str) -> String {
        kernel::create_as(
            &self.db,
            &self.admin,
            family,
            kind,
            &serde_json::Map::new(),
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap()
    }
    async fn count(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT (SELECT COUNT(*) FROM content_events) + (SELECT COUNT(*) FROM meta_events)",
        )
        .fetch_one(self.db.pool())
        .await
        .unwrap()
    }
    async fn head(&self, record: &str) -> i64 {
        sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events WHERE record_id = ?")
            .bind(record)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
    async fn setup(&self) -> (String, String, String) {
        // Install source before the foreign family exists: no circular adoption dependency.
        let note = self
            .install(&definition(
                "fixture.note",
                1,
                "note",
                json!([
                    link("documents", json!({"family":"fixture.work","kind":"task"})),
                    link("associates", json!({"any_record":true})),
                    link("relates_to", json!({"any_record":true}))
                ]),
            ))
            .await;
        self.adopt(&note).await;
        let work = self
            .install(&definition("fixture.work", 1, "task", json!([])))
            .await;
        self.adopt(&work).await;
        let wrong = self
            .install(&definition("fixture.wrong", 1, "task", json!([])))
            .await;
        self.adopt(&wrong).await;
        (
            self.record("fixture.note", "note").await,
            self.record("fixture.work", "task").await,
            self.record("fixture.wrong", "task").await,
        )
    }
}

#[tokio::test]
async fn field_identity_requires_a_declared_required_scalar_only_on_four() {
    let w = World::fresh().await;
    let count = w.count().await;
    for (index, (name, required, field_type)) in [
        (json!("title"), json!(false), "text"),
        (json!("missing"), json!(true), "text"),
        (Value::Null, json!(true), "text"),
        (json!(7), json!(true), "text"),
        (json!("title"), Value::Null, "text"),
        (json!("title"), json!(true), "object"),
        (json!("title"), json!(true), "list"),
    ]
    .into_iter()
    .enumerate()
    {
        let family = format!("fixture.identity{index}");
        let mut doc = definition(&family, 1, "note", json!([]));
        doc["kinds"][0]["identity"] = json!({"field":name});
        doc["kinds"][0]["fields"][0]["required"] = required;
        doc["kinds"][0]["fields"][0]["type"] = json!(field_type);
        assert_engine(
            kernel::install_definition_as(
                &w.db,
                &w.admin,
                &family,
                1,
                &serde_json::to_vec(&doc).unwrap(),
            )
            .await
            .unwrap_err(),
            "defn/4 $.kinds[0].identity.field: must name a declared, required scalar field",
        );
        assert_eq!(count, w.count().await);
    }
    let mut valid = definition("fixture.requiredidentity", 1, "note", json!([]));
    valid["kinds"][0]["identity"] = json!({"field":"title"});
    valid["kinds"][0]["fields"][0]["required"] = json!(true);
    let pin = w.install(&valid).await;
    w.adopt(&pin).await;
    kernel::create_as(
        &w.db,
        &w.admin,
        &pin.family,
        "note",
        json!({"title":"required identity"}).as_object().unwrap(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    for marker in [None, Some("native.defn/2"), Some("native.defn/3")] {
        valid["kinds"][0]["fields"][0]["required"] = json!(false);
        if let Some(marker) = marker {
            valid["interpreter"] = json!(marker);
        } else {
            valid.as_object_mut().unwrap().remove("interpreter");
        }
        crate::meta::definition_artifact::validate_kernel_definition_bytes(&valid.to_string())
            .unwrap();
    }
}

#[tokio::test]
async fn closed_selectors_and_legacy_language_are_distinct() {
    let w = World::fresh().await;
    let count = w.count().await;
    for (i, target) in [
        json!({"any_record":false}),
        json!({"any_record":true,"kind":"task"}),
        json!({"family":"fixture.work","kind":"task","extra":0}),
        json!({"family":"","kind":"task"}),
        json!({"family":"fixture.work","kind":" "}),
        json!({"family":"fixture.work","kind":"task/other"}),
        json!({"primary_type":"SameLabel","kind":"note"}),
        json!({"family":"fixture.work","kind":"task","any_record":true}),
        json!({"any_record":"true"}),
    ]
    .into_iter()
    .enumerate()
    {
        let doc = definition(
            &format!("fixture.invalid{i}"),
            1,
            "note",
            json!([link("p", target)]),
        );
        assert!(kernel::install_definition_as(
            &w.db,
            &w.admin,
            doc["family"].as_str().unwrap(),
            1,
            &serde_json::to_vec(&doc).unwrap()
        )
        .await
        .is_err());
    }
    let mut governed = definition(
        "fixture.unsupported-governed",
        1,
        "note",
        json!([link("p", json!({"any_record":true}))]),
    );
    governed["kinds"][0]["links"][0]["relationship_ref"] = json!("relates_to.v1");
    assert!(kernel::install_definition_as(
        &w.db,
        &w.admin,
        "fixture.unsupported-governed",
        1,
        &serde_json::to_vec(&governed).unwrap()
    )
    .await
    .is_err());
    assert_eq!(count, w.count().await);
    let mut doc = definition(
        "fixture.legacy",
        1,
        "note",
        json!([link("p", json!({"primary_type":"SameLabel","kind":"note"}))]),
    );
    doc["interpreter"] = json!("native.defn/3");
    let pin = w.install(&doc).await;
    w.adopt(&pin).await;
    let a = w.record("fixture.legacy", "note").await;
    let b = w.record("fixture.legacy", "note").await;
    kernel::link_as(&w.db, &w.admin, &a, "p", &b).await.unwrap();
    let event_type: String =
        sqlx::query_scalar("SELECT type FROM content_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(event_type, "kernel.link_added.v1");
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn new_language_keywords_are_closed_with_nested_paths_only() {
    let w = World::fresh().await;
    let count = w.count().await;
    for (index, (pointer, keyword, value, path)) in [
        (
            "/kinds/0/fields/0",
            "minimum",
            json!(1),
            "$.kinds[0].fields[0].minimum",
        ),
        (
            "/kinds/0/fields/0",
            "properties",
            json!({}),
            "$.kinds[0].fields[0].properties",
        ),
        (
            "/kinds/0/fields/0",
            "format",
            json!("email"),
            "$.kinds[0].fields[0].format",
        ),
        (
            "/kinds/0/fields/0",
            "default",
            json!("implicit"),
            "$.kinds[0].fields[0].default",
        ),
        (
            "/kinds/0/fields/0",
            "values",
            json!(["unsupported on text"]),
            "$.kinds[0].fields[0].values",
        ),
        (
            "/kinds/0/fields/0",
            "typo",
            json!(true),
            "$.kinds[0].fields[0].typo",
        ),
        (
            "/kinds/0/links/0",
            "relationship_ref",
            json!("relates_to.v1"),
            "$.kinds[0].links[0].relationship_ref",
        ),
        (
            "/kinds/0/links/0",
            "provider",
            json!("unsupported"),
            "$.kinds[0].links[0].provider",
        ),
        (
            "/kinds/0/links/0",
            "where",
            json!(true),
            "$.kinds[0].links[0].where",
        ),
        (
            "/kinds/0/links/0/target",
            "version",
            json!(1),
            "$.kinds[0].links[0].target.version",
        ),
        (
            "/kinds/0/identity",
            "normalize",
            json!(true),
            "$.kinds[0].identity.normalize",
        ),
        ("/kinds/0", "checks", json!([]), "$.kinds[0].checks"),
        ("", "unknown", json!(true), "$.unknown"),
    ]
    .into_iter()
    .enumerate()
    {
        let family = format!("fixture.closed{index}");
        let mut doc = definition(
            &family,
            1,
            "note",
            json!([link("p", json!({"any_record":true}))]),
        );
        doc.pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(keyword.into(), value);
        let error = kernel::install_definition_as(
            &w.db,
            &w.admin,
            &family,
            1,
            &serde_json::to_vec(&doc).unwrap(),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains(path), "{error}");
        assert_eq!(count, w.count().await);
    }
    // Supported choice metadata remains a feature of the new language.
    let mut supported = definition("fixture.closedchoice", 1, "note", json!([]));
    supported["kinds"][0]["fields"][0]["type"] = json!("choice");
    supported["kinds"][0]["fields"][0]["values"] = json!(["a", "b"]);
    supported["kinds"][0]["fields"][0]["description"] = json!("A supported scalar choice.");
    w.install(&supported).await;
    // Earlier interpreters still ignore these same unknown keys. No new
    // keyword closure is applied to their immutable language contracts.
    for marker in [None, Some("native.defn/2"), Some("native.defn/3")] {
        let mut legacy = definition(
            "fixture.legacykeywords",
            1,
            "note",
            json!([link("p", json!({"primary_type":"SameLabel","kind":"note"}))]),
        );
        if let Some(marker) = marker {
            legacy["interpreter"] = json!(marker);
        } else {
            legacy.as_object_mut().unwrap().remove("interpreter");
        }
        legacy["kinds"][0]["identity"] = json!({"field":"title"});
        legacy["kinds"][0]["fields"][0]["minimum"] = json!(1);
        legacy["kinds"][0]["links"][0]["provider"] = json!("ignored");
        crate::meta::definition_artifact::validate_kernel_definition_bytes(&legacy.to_string())
            .unwrap();
    }
}

#[tokio::test]
async fn legacy_one_and_two_events_keep_their_original_results() {
    let w = World::fresh().await;
    let one = json!({"family":"fixture.old1","version":1,"primary_type":"Old","kinds":["item"]});
    let pin = w.install(&one).await;
    w.adopt(&pin).await;
    let a = kernel::create_package_record_as(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        "Old",
        "item",
        "a",
        "fixture.old1",
    )
    .await
    .unwrap();
    let b = kernel::create_package_record_as(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        "Old",
        "item",
        "b",
        "fixture.old1",
    )
    .await
    .unwrap();
    kernel::link_records_as(&w.db, &w.admin, &a, &b)
        .await
        .unwrap();
    let mut two = definition(
        "fixture.old2",
        1,
        "item",
        json!([link(
            "points",
            json!({"primary_type":"SameLabel","kind":"item"})
        )]),
    );
    two["interpreter"] = json!("native.defn/2");
    two["kinds"][0]["identity"] = json!({"field":"title"});
    two["kinds"][0]["fields"][0]["required"] = json!(true);
    let pin = w.install(&two).await;
    w.adopt(&pin).await;
    let a = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.old2",
        "item",
        json!({"title":"a"}).as_object().unwrap(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let b = kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.old2",
        "item",
        json!({"title":"b"}).as_object().unwrap(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    kernel::link_as(&w.db, &w.admin, &a, "points", &b)
        .await
        .unwrap();
    let types: Vec<String> =
        sqlx::query_scalar("SELECT type FROM content_events WHERE type LIKE 'kernel.link_added.%'")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(types, vec!["kernel.link_added.v1", "kernel.link_added.v1"]);
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn cross_family_and_bare_targets_use_recorded_binding() {
    let w = World::fresh().await;
    let (note, task, wrong) = w.setup().await;
    let bare = kernel::create_record_as(&w.db, &w.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let count = w.count().await;
    for (p, t) in [("documents", wrong.as_str()), ("documents", bare.as_str())] {
        assert!(kernel::link_as(&w.db, &w.admin, &note, p, t).await.is_err());
        assert_eq!(count, w.count().await);
    }
    for target in [w.admin.as_str(), KERNEL_ROOT_ID] {
        assert_engine(
            kernel::link_as(&w.db, &w.admin, &note, "associates", target)
                .await
                .unwrap_err(),
            kernel::HIDDEN_OR_MISSING,
        );
        assert_eq!(count, w.count().await);
    }
    assert_engine(
        kernel::link_as(&w.db, &w.admin, &note, "associates", &note)
            .await
            .unwrap_err(),
        "invalid directed-link witness",
    );
    assert_eq!(count, w.count().await);
    kernel::link_as(&w.db, &w.admin, &note, "documents", &task)
        .await
        .unwrap();
    kernel::link_as(&w.db, &w.admin, &note, "associates", &bare)
        .await
        .unwrap();
    assert_eq!(
        kernel::links_from_as(&w.db, &w.admin, &note)
            .await
            .unwrap()
            .len(),
        2
    );
    // Synthetic decision → option, independent of source-envelope kinds.
    let option = w
        .install(&definition("fixture.option", 1, "option", json!([])))
        .await;
    let decision = w
        .install(&definition(
            "fixture.decision",
            1,
            "decision",
            json!([link(
                "considers",
                json!({"family":"fixture.option","kind":"option"})
            )]),
        ))
        .await;
    w.adopt(&option).await;
    w.adopt(&decision).await;
    let d = w.record("fixture.decision", "decision").await;
    let o = w.record("fixture.option", "option").await;
    kernel::link_as(&w.db, &w.admin, &d, "considers", &o)
        .await
        .unwrap();
}

#[tokio::test]
async fn any_record_accepts_a_bound_foreign_family() {
    let w = World::fresh().await;
    let (note, _, foreign) = w.setup().await;
    kernel::link_as(&w.db, &w.admin, &note, "associates", &foreign)
        .await
        .unwrap();
    let witness: String = sqlx::query_scalar("SELECT witness_json FROM kernel_link4_edges")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&witness).unwrap()["target"]["binding"]["pin"]["family"],
        "fixture.wrong"
    );
    assert_eq!(
        kernel::links_from_as(&w.db, &w.admin, &note)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn hidden_missing_and_revoked_permission_refuse_without_events() {
    let w = World::fresh().await;
    let (note, task, _) = w.setup().await;
    let reader = kernel::create_principal(&w.db, "account", "Reader", "acct:reader", &w.admin)
        .await
        .unwrap();
    let shared = [(&w.admin[..], "manage"), (&reader[..], "edit")];
    let private = [(&w.admin[..], "manage")];
    kernel::replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &shared)
        .await
        .unwrap();
    let target_home = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&shared), &w.admin)
        .await
        .unwrap();
    let source_home = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&shared), &w.admin)
        .await
        .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, &task, &target_home)
        .await
        .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, &note, &source_home)
        .await
        .unwrap();
    let request = kernel::prepare_link4_as(&w.db, &reader, &note, "documents", &task, "race")
        .await
        .unwrap();
    // Policy changes leave both endpoint heads alone: this must refuse for visibility.
    kernel::replace_home_policy(&w.db, &w.admin, &target_home, &private)
        .await
        .unwrap();
    assert_eq!(request.target.head, w.head(&task).await);
    assert_eq!(request.source.head, w.head(&note).await);
    let count = w.count().await;
    for target in [&task[..], "absent"] {
        assert_engine(
            kernel::prepare_link4_as(&w.db, &reader, &note, "documents", target, "hidden")
                .await
                .unwrap_err(),
            kernel::HIDDEN_OR_MISSING,
        );
        let mut commit = request.clone();
        commit.target.record_id = target.into();
        assert_engine(
            kernel::link4_as(&w.db, &reader, &commit).await.unwrap_err(),
            kernel::HIDDEN_OR_MISSING,
        );
    }
    assert_eq!(count, w.count().await);
    kernel::replace_home_policy(&w.db, &w.admin, &target_home, &shared)
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &source_home, &private)
        .await
        .unwrap();
    assert_eq!(request.source.head, w.head(&note).await);
    let count = w.count().await;
    for source in [&note[..], "absent"] {
        assert_engine(
            kernel::prepare_link4_as(&w.db, &reader, source, "documents", &task, "hidden-source")
                .await
                .unwrap_err(),
            kernel::HIDDEN_OR_MISSING,
        );
        let mut commit = request.clone();
        commit.source.record_id = source.into();
        assert_engine(
            kernel::link4_as(&w.db, &reader, &commit).await.unwrap_err(),
            kernel::HIDDEN_OR_MISSING,
        );
    }
    assert_eq!(count, w.count().await);
    kernel::replace_home_policy(&w.db, &w.admin, &source_home, &shared)
        .await
        .unwrap();
    let request = kernel::prepare_link4_as(&w.db, &reader, &note, "documents", &task, "revocation")
        .await
        .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &source_home,
        &[(&w.admin, "manage"), (&reader, "view")],
    )
    .await
    .unwrap();
    let count = w.count().await;
    assert_eq!(request.source.head, w.head(&note).await);
    assert_engine(
        kernel::link4_as(&w.db, &reader, &request)
            .await
            .unwrap_err(),
        kernel::HIDDEN_OR_MISSING,
    );
    assert_eq!(count, w.count().await);
}

#[tokio::test]
async fn hidden_associations_disappear_from_reads_and_live_projection() {
    use crate::store::{append, AppendSpec};
    let w = World::fresh().await;
    let (note, task, _) = w.setup().await;
    let editor = kernel::create_principal(&w.db, "account", "Editor", "acct:editor", &w.admin)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "edit")],
    )
    .await
    .unwrap();
    let request = kernel::prepare_link4_as(&w.db, &editor, &note, "documents", &task, "visible")
        .await
        .unwrap();
    let event = append(
        &w.db,
        AppendSpec {
            record_id: note.clone(),
            event_type: "kernel.link_added.v2".into(),
            payload: serde_json::to_value(&request).unwrap(),
            actor: Some(editor.clone()),
        },
    )
    .await
    .unwrap();
    let hidden_home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, &task, &hidden_home)
        .await
        .unwrap();
    assert!(kernel::links_from_as(&w.db, &editor, &note)
        .await
        .unwrap()
        .is_empty());
    assert!(!kernel::history_as(&w.db, &editor, &note)
        .await
        .unwrap()
        .iter()
        .any(|e| e.event_type == "kernel.link_added.v2"));
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let error = crate::projector::project(&mut tx, &event)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("kernel target missing or hidden"), "{error}");
    tx.rollback().await.unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn stale_endpoint_binding_and_edge_heads_are_event_free() {
    let w = World::fresh().await;
    let (note, task, _) = w.setup().await;
    let request = kernel::prepare_link4_as(&w.db, &w.admin, &note, "documents", &task, "stale")
        .await
        .unwrap();
    kernel::revise_as(
        &w.db,
        &w.admin,
        &task,
        json!({"title":"changed"}).as_object().unwrap(),
    )
    .await
    .unwrap();
    let count = w.count().await;
    assert_conflict(
        kernel::link4_as(&w.db, &w.admin, &request)
            .await
            .unwrap_err(),
        "directed-link endpoint or binding revision mismatch",
    );
    assert_eq!(count, w.count().await);
    let mut request =
        kernel::prepare_link4_as(&w.db, &w.admin, &note, "documents", &task, "binding")
            .await
            .unwrap();
    request.target.binding_revision -= 1;
    assert_conflict(
        kernel::link4_as(&w.db, &w.admin, &request)
            .await
            .unwrap_err(),
        "directed-link endpoint or binding revision mismatch",
    );
    assert_eq!(count, w.count().await);
    let mut request = kernel::prepare_link4_as(&w.db, &w.admin, &note, "documents", &task, "edge")
        .await
        .unwrap();
    request.expected_edge_head = Some(0);
    assert_engine(
        kernel::link4_as(&w.db, &w.admin, &request)
            .await
            .unwrap_err(),
        "invalid directed-link witness",
    );
    assert_eq!(count, w.count().await);
    let request = kernel::prepare_link4_as(&w.db, &w.admin, &note, "documents", &task, "success")
        .await
        .unwrap();
    let competing = kernel::prepare_link4_as(&w.db, &w.admin, &note, "documents", &task, "other")
        .await
        .unwrap();
    kernel::link4_as(&w.db, &w.admin, &request).await.unwrap();
    let count = w.count().await;
    assert_conflict(
        kernel::link4_as(&w.db, &w.admin, &competing)
            .await
            .unwrap_err(),
        "directed-link endpoint or binding revision mismatch",
    );
    // Fresh endpoint snapshots now pass; only the occupied edge refuses.
    assert_conflict(
        kernel::prepare_link4_as(
            &w.db,
            &w.admin,
            &note,
            "documents",
            &task,
            "fresh-occupied-edge",
        )
        .await
        .unwrap_err(),
        "directed-link edge head mismatch",
    );
    assert_eq!(count, w.count().await);
}

#[tokio::test]
async fn concurrent_retries_keep_one_stable_identity() {
    let w = World::fresh().await;
    let (note, task, _) = w.setup().await;
    let a = kernel::prepare_link4_as(&w.db, &w.admin, &note, "documents", &task, "same")
        .await
        .unwrap();
    let b = kernel::prepare_link4_as(&w.db, &w.admin, &note, "documents", &task, "same")
        .await
        .unwrap();
    assert_eq!(a, b);
    let count = w.count().await;
    let (a_result, b_result) = tokio::join!(
        kernel::link4_as(&w.db, &w.admin, &a),
        kernel::link4_as(&w.db, &w.admin, &b)
    );
    assert_eq!(a_result.unwrap(), b_result.unwrap());
    assert_eq!(count + 1, w.count().await);
    let retry = kernel::prepare_link4_as(&w.db, &w.admin, &note, "documents", &task, "same")
        .await
        .unwrap();
    assert_eq!(a, retry);
    kernel::link4_as(&w.db, &w.admin, &retry).await.unwrap();
    assert_eq!(count + 1, w.count().await);
    assert!(
        kernel::prepare_link4_as(&w.db, &w.admin, &note, "associates", &task, "same")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn convenience_wrappers_retry_after_commit_without_another_event() {
    let w = World::fresh().await;
    let (note, task, _) = w.setup().await;
    kernel::link_as(&w.db, &w.admin, &note, "documents", &task)
        .await
        .unwrap();
    kernel::link_records_as(&w.db, &w.admin, &note, &task)
        .await
        .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db)
        .await
        .unwrap()
        .link4_edges;
    assert_eq!(before.len(), 2);
    // Retry remains a receipt even if a later target revision makes old heads stale.
    kernel::revise_as(
        &w.db,
        &w.admin,
        &task,
        json!({"title":"later"}).as_object().unwrap(),
    )
    .await
    .unwrap();
    let count = w.count().await;
    kernel::link_as(&w.db, &w.admin, &note, "documents", &task)
        .await
        .unwrap();
    kernel::link_records_as(&w.db, &w.admin, &note, &task)
        .await
        .unwrap();
    kernel::link_as(&w.db, &w.admin, &note, "relates_to", &task)
        .await
        .unwrap();
    assert_eq!(count, w.count().await);
    assert_eq!(
        before,
        kernel::dump_all_kernel_tables(&w.db)
            .await
            .unwrap()
            .link4_edges
    );
}

#[tokio::test]
async fn disabled_replaced_target_retains_matching_pins_and_replay() {
    let w = World::fresh().await;
    let (note, task, _) = w.setup().await;
    kernel::adopt_definition_as(&w.db, &w.admin, "fixture.work", None)
        .await
        .unwrap();
    kernel::link_as(&w.db, &w.admin, &note, "documents", &task)
        .await
        .unwrap();
    let replacement = w
        .install(&definition("fixture.work", 2, "task", json!([])))
        .await;
    w.adopt(&replacement).await;
    let new_task = w.record("fixture.work", "task").await;
    kernel::link_as(&w.db, &w.admin, &note, "documents", &new_task)
        .await
        .unwrap();
    let witnesses: Vec<String> =
        sqlx::query_scalar("SELECT witness_json FROM kernel_link4_edges ORDER BY target_id")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    let versions: Vec<u64> = witnesses
        .iter()
        .map(|s| {
            serde_json::from_str::<Value>(s).unwrap()["target"]["binding"]["pin"]["version"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert!(versions.contains(&1) && versions.contains(&2));
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    let after: Vec<String> =
        sqlx::query_scalar("SELECT witness_json FROM kernel_link4_edges ORDER BY target_id")
            .fetch_all(w.db.pool())
            .await
            .unwrap();
    assert_eq!(witnesses, after);
}

#[tokio::test]
async fn explicit_semantic_consumer_blocks_disable_without_implicit_edge_dependency() {
    let w = World::fresh().await;
    let (note, task, _) = w.setup().await;
    // Own the target definition through an ordinary definitions-only package.
    let bytes = definition("fixture.work", 1, "task", json!([])).to_string();
    let manifest = crate::package_manifest::PackageManifest {
        namespace: "fixture".into(),
        name: "work".into(),
        version: 1,
        definitions: vec![crate::package_manifest::DefinitionEntry {
            family: "fixture.work".into(),
            version: 1,
            digest: crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes()),
            artifact_bytes: bytes,
        }],
        operations: vec![],
        behaviour: None,
        surface: None,
        declared_reads: vec![],
    };
    let package = kernel::install_package_as(&w.db, &w.admin, &manifest)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &manifest,
        Some(&package),
        &[],
    )
    .await
    .unwrap();
    kernel::link_as(&w.db, &w.admin, &note, "documents", &task)
        .await
        .unwrap();
    kernel::adopt_package_at(&w.db, &w.admin, KERNEL_ROOT_ID, &manifest, None, &[])
        .await
        .unwrap();
    assert_eq!(
        kernel::links_from_as(&w.db, &w.admin, &note)
            .await
            .unwrap()
            .len(),
        1
    );
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &manifest,
        Some(&package),
        &[],
    )
    .await
    .unwrap();
    let pin_digest: String =
        sqlx::query_scalar("SELECT pin_digest FROM kernel_records WHERE id = ?")
            .bind(&task)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    crate::dependency::register_consumer_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        "saved-query",
        "fixture.consumer",
        "work-fields",
        "fixture.work",
        1,
        &pin_digest,
        None,
    )
    .await
    .unwrap();
    let count = w.count().await;
    assert!(
        kernel::adopt_package_at(&w.db, &w.admin, KERNEL_ROOT_ID, &manifest, None, &[])
            .await
            .is_err()
    );
    assert_eq!(count, w.count().await);
}

#[tokio::test]
async fn all_generic_append_routes_and_projector_witnesses_fail_closed() {
    use crate::store::{append, append_batch, AppendSpec};
    let w = World::fresh().await;
    let (note, task, _) = w.setup().await;
    let request = kernel::prepare_link4_as(&w.db, &w.admin, &note, "documents", &task, "raw")
        .await
        .unwrap();
    let count = w.count().await;
    let spec = || AppendSpec {
        record_id: note.clone(),
        event_type: "kernel.link_added.v1".into(),
        payload: json!({"source_id":note,"target_id":task,"relationship":"documents"}),
        actor: Some(w.admin.clone()),
    };
    assert!(append(&w.db, spec()).await.is_err());
    assert!(append_batch(&w.db, vec![spec()]).await.is_err());
    assert_eq!(count, w.count().await);
    let reader = kernel::create_principal(&w.db, "account", "Reader", "acct:raw-reader", &w.admin)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&reader, "view")],
    )
    .await
    .unwrap();
    let v2 = |payload: Value, actor: &str| AppendSpec {
        record_id: note.clone(),
        event_type: "kernel.link_added.v2".into(),
        payload,
        actor: Some(actor.into()),
    };
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&reader, "edit")],
    )
    .await
    .unwrap();
    let no_edit =
        kernel::prepare_link4_as(&w.db, &reader, &note, "documents", &task, "raw-no-edit")
            .await
            .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&reader, "view")],
    )
    .await
    .unwrap();
    let count = w.count().await;
    // Everything except the caller's Edit capability is valid; admission checks it first.
    assert_engine(
        append(&w.db, v2(serde_json::to_value(&no_edit).unwrap(), &reader))
            .await
            .unwrap_err(),
        kernel::HIDDEN_OR_MISSING,
    );
    assert_engine(
        append(&w.db, v2(serde_json::to_value(&request).unwrap(), &reader))
            .await
            .unwrap_err(),
        "invalid directed-link actor or anchor",
    );
    // A valid earlier event in the batch is rolled back when the second v2 act loses authority.
    assert_engine(
        append_batch(
            &w.db,
            vec![
                v2(serde_json::to_value(&request).unwrap(), &w.admin),
                v2(serde_json::to_value(&no_edit).unwrap(), &reader),
            ],
        )
        .await
        .unwrap_err(),
        kernel::HIDDEN_OR_MISSING,
    );
    assert_eq!(count, w.count().await);
    assert_eq!(
        kernel::dump_all_kernel_tables(&w.db)
            .await
            .unwrap()
            .link4_edges
            .len(),
        0
    );
    let mut forged = serde_json::to_value(&request).unwrap();
    forged["target"]["head"] = json!(0);
    assert!(append(
        &w.db,
        AppendSpec {
            record_id: note.clone(),
            event_type: "kernel.link_added.v2".into(),
            payload: forged,
            actor: Some(w.admin.clone())
        }
    )
    .await
    .is_err());
    assert_eq!(count, w.count().await);
    kernel::link_records_as(&w.db, &w.admin, &note, &task)
        .await
        .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    // Bypass the append-only guard only in this isolated corruption fixture.
    sqlx::query("DROP TRIGGER content_events_no_update")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    // Corrupt retained admission evidence: replay refuses instead of accepting current labels.
    sqlx::query("UPDATE content_events SET payload = json_set(payload, '$.target.head', 0) WHERE type = 'kernel.link_added.v2'").execute(w.db.write_pool()).await.unwrap();
    assert!(kernel::replay_all_projections(&w.db).await.is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn describe_discovers_record_pins_and_unresolved_selectors() {
    let w = World::fresh().await;
    let (note, task, _) = w.setup().await;
    let newer = w
        .install(&definition("fixture.note", 2, "note", json!([])))
        .await;
    w.adopt(&newer).await;
    kernel::adopt_definition_as(&w.db, &w.admin, "fixture.work", None)
        .await
        .unwrap();
    let scope = kernel::describe_world_as(&w.db, &w.admin).await.unwrap();
    assert_eq!(
        scope["directed_links"]["targets"][1],
        json!({"any_record":true})
    );
    let record = kernel::describe_record_links_as(&w.db, &w.admin, &note)
        .await
        .unwrap();
    assert_eq!(record["record"]["binding"]["pin"]["version"], 1);
    assert_eq!(
        record["links"][0]["declaration"]["target"],
        json!({"family":"fixture.work","kind":"task"})
    );
    assert!(record["links"][0]["target_creation"]
        .as_str()
        .unwrap()
        .starts_with("unresolved"));
    kernel::link_as(&w.db, &w.admin, &note, "documents", &task)
        .await
        .unwrap();
}

#[tokio::test]
async fn retries_verify_recorded_witness_and_recheck_authority() {
    let w = World::fresh().await;
    let (note, task, _) = w.setup().await;
    let editor = kernel::create_principal(&w.db, "account", "Editor", "acct:editor", &w.admin)
        .await
        .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "edit")],
    )
    .await
    .unwrap();
    let request = kernel::prepare_link4_as(&w.db, &editor, &note, "documents", &task, "retry")
        .await
        .unwrap();
    kernel::link4_as(&w.db, &editor, &request).await.unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "view")],
    )
    .await
    .unwrap();
    let count = w.count().await;
    assert!(kernel::link4_as(&w.db, &editor, &request).await.is_err());
    assert_eq!(count, w.count().await);
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "edit")],
    )
    .await
    .unwrap();
    sqlx::query("UPDATE kernel_link4_edges SET created_seq = created_seq + 1")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let count = w.count().await;
    assert!(kernel::link4_as(&w.db, &editor, &request).await.is_err());
    assert!(
        kernel::prepare_link4_as(&w.db, &editor, &note, "documents", &task, "retry")
            .await
            .is_err()
    );
    assert_eq!(count, w.count().await);
}

#[tokio::test]
async fn generic_unlink_retains_witness_history_and_allows_new_link_generation() {
    let w = World::fresh().await;
    let (source, target, _) = w.setup().await;
    let request = kernel::prepare_link4_as(
        &w.db,
        &w.admin,
        &source,
        "documents",
        &target,
        "before-unlink",
    )
    .await
    .unwrap();
    kernel::link4_as(&w.db, &w.admin, &request).await.unwrap();
    let head = w.head(&source).await;
    kernel::unlink_as(&w.db, &w.admin, &source, "documents", &target, head)
        .await
        .unwrap();
    assert!(kernel::links_from_as(&w.db, &w.admin, &source)
        .await
        .unwrap()
        .is_empty());
    assert!(matches!(
        kernel::link4_as(&w.db, &w.admin, &request).await,
        Err(crate::Error::Conflict(_))
    ));
    kernel::link_as(&w.db, &w.admin, &source, "documents", &target)
        .await
        .unwrap();
    kernel::unlink_as(
        &w.db,
        &w.admin,
        &source,
        "documents",
        &target,
        w.head(&source).await,
    )
    .await
    .unwrap();
    kernel::link_as(&w.db, &w.admin, &source, "documents", &target)
        .await
        .unwrap();
    let before = w.count().await;
    kernel::link_as(&w.db, &w.admin, &source, "documents", &target)
        .await
        .unwrap();
    assert_eq!(w.count().await, before);
    let history = kernel::history_as(&w.db, &w.admin, &source).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        kernel::links_from_as(&w.db, &w.admin, &source)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        kernel::history_as(&w.db, &w.admin, &source).await.unwrap(),
        history
    );
}

#[tokio::test]
async fn duplicate_legacy_accessions_refuse_uniformly_without_writes() {
    let w = World::fresh().await;
    let doc =
        json!({"family":"fixture.old.identity","version":1,"primary_type":"Old","kinds":["item"]});
    let pin = w.install(&doc).await;
    w.adopt(&pin).await;
    kernel::create_package_record_as(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        "Old",
        "item",
        "explicit-identity",
        "fixture.old.identity",
    )
    .await
    .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert_engine(
        kernel::create_package_record_as(
            &w.db,
            &w.admin,
            KERNEL_ROOT_ID,
            "Old",
            "item",
            "explicit-identity",
            "fixture.old.identity",
        )
        .await
        .unwrap_err(),
        kernel::IDENTITY_UNAVAILABLE,
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.old.identity",
        "item",
        &serde_json::Map::new(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert_engine(
        kernel::create_as(
            &w.db,
            &w.admin,
            "fixture.old.identity",
            "item",
            &serde_json::Map::new(),
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap_err(),
        kernel::IDENTITY_UNAVAILABLE,
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}
