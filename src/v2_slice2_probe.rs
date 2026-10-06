//! v2 slice 2, increment 1: `native.defn/2` envelope + pin, coexisting with
//! `/1` in one database. The fold dispatches on the pinned interpreter
//! (contract K4); malformed `/2` envelopes refuse at install with no event.

const SPECIMEN_V1_BYTES: &str = r#"{"family":"lab.specimen","version":1,"primary_type":"Specimen","kinds":[{"token":"field-sample"},{"token":"lab-aliquot"}]}"#;

const ALIQUOT_V2_BYTES: &str = r#"{"family":"lab.aliquot","version":1,"primary_type":"Aliquot","interpreter":"native.defn/2","kinds":[{"token":"field-sample","fields":[{"name":"accession","type":"text","required":true}],"identity":{"field":"accession"},"links":[],"maturity":"current","description":"A field sample."},{"token":"lab-aliquot","fields":[{"name":"accession","type":"text","required":true},{"name":"volume_ml","type":"number","required":true}],"identity":{"field":"accession"},"links":[{"predicate":"derived_from","target":{"primary_type":"Aliquot","kind":"field-sample"},"direction":"out","cardinality":"many"}],"maturity":"current","description":"An aliquot split from a field sample."}]}"#;

const BAD_FIELD_TYPE_BYTES: &str = r#"{"family":"bad.fieldtype","version":1,"primary_type":"Aliquot","interpreter":"native.defn/2","kinds":[{"token":"lab-aliquot","fields":[{"name":"accession","type":"text","required":true},{"name":"volume_ml","type":"volume","required":true}],"identity":{"field":"accession"},"links":[],"maturity":"current","description":"Bad field type."}]}"#;

const BAD_IDENTITY_BYTES: &str = r#"{"family":"bad.identity","version":1,"primary_type":"Aliquot","interpreter":"native.defn/2","kinds":[{"token":"lab-aliquot","fields":[{"name":"accession","type":"text","required":true}],"identity":{"field":"missing_col"},"links":[],"maturity":"current","description":"Bad identity."}]}"#;

const BAD_LINK_BYTES: &str = r#"{"family":"bad.link","version":1,"primary_type":"Aliquot","interpreter":"native.defn/2","kinds":[{"token":"lab-aliquot","fields":[{"name":"accession","type":"text","required":true}],"identity":{"field":"accession"},"links":[{"predicate":"derived_from","target":{"primary_type":"Aliquot","kind":"ghost-kind"},"direction":"out"}],"maturity":"current","description":"Bad link."}]}"#;

const BAD_INTERP_BYTES: &str = r#"{"family":"bad.interp","version":1,"primary_type":"Aliquot","interpreter":"native.defn/999","kinds":[{"token":"lab-aliquot"}]}"#;

fn content_event(
    record_id: &str,
    event_type: &str,
    payload: serde_json::Value,
) -> crate::events::EventRow {
    crate::events::EventRow {
        local_seq: 99,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: record_id.to_string(),
        event_type: event_type.to_string(),
        payload: Some(serde_json::to_string(&payload).unwrap()),
        actor: Some("test:v2".to_string()),
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-01-01T00:00:00.000Z".to_string(),
        causal_envelope: crate::events::CausalEnvelopeV1::complete(
            crate::events::CausalFrontierV1::empty(),
        ),
        act: None,
    }
}

#[tokio::test]
async fn v2_defn_v2_envelope_pinned() {
    use crate::kernel as v2;
    let dir = tempfile::tempdir().unwrap();
    let url = dir.path().join("v2-defn2.db").to_str().unwrap().to_string();
    let (db, a) = v2::create_v2_database(&url, "account", "A", "acct:a")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();

    // `/1` and `/2` definitions install side by side; records pin their own.
    let v1 = v2::install_definition_as(&db, &a, "lab.specimen", 1, SPECIMEN_V1_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_as(&db, &a, "lab.specimen", Some(&v1))
        .await
        .unwrap();
    let s1 = v2::create_package_record_as(
        &db,
        &a,
        &h,
        "Specimen",
        "field-sample",
        "LAB-001",
        "lab.specimen",
    )
    .await
    .unwrap();
    let v2id = v2::install_definition_as(&db, &a, "lab.aliquot", 1, ALIQUOT_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_as(&db, &a, "lab.aliquot", Some(&v2id))
        .await
        .unwrap();
    let a1 = v2::create_package_record_as(
        &db,
        &a,
        &h,
        "Aliquot",
        "lab-aliquot",
        "A-001",
        "lab.aliquot",
    )
    .await
    .unwrap();

    let pin_row =
        "SELECT accession, pin_family, pin_version, interpreter FROM kernel_records WHERE id = ?";
    let s1row: (Option<String>, Option<String>, Option<i64>, Option<String>) =
        sqlx::query_as(pin_row)
            .bind(&s1)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(s1row.0.as_deref(), Some("LAB-001"));
    assert_eq!(s1row.1.as_deref(), Some("lab.specimen"));
    assert_eq!(s1row.3.as_deref(), Some("native.defn/1"));
    let a1row: (Option<String>, Option<String>, Option<i64>, Option<String>) =
        sqlx::query_as(pin_row)
            .bind(&a1)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(a1row.0.as_deref(), Some("A-001"));
    assert_eq!(a1row.1.as_deref(), Some("lab.aliquot"));
    assert_eq!(a1row.3.as_deref(), Some("native.defn/2"));

    // Malformed `/2` envelopes refuse at install with no event anywhere.
    let content_count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    };
    let meta_count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM meta_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    };
    for (family, bytes, needle) in [
        ("bad.fieldtype", BAD_FIELD_TYPE_BYTES, "unknown field type"),
        ("bad.identity", BAD_IDENTITY_BYTES, "unknown identity field"),
        ("bad.link", BAD_LINK_BYTES, "unknown link target"),
        (
            "bad.interp",
            BAD_INTERP_BYTES,
            "unknown definition interpreter",
        ),
    ] {
        let (before_content, before_meta) = (content_count().await, meta_count().await);
        let err = v2::install_definition_as(&db, &a, family, 1, bytes.as_bytes())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(needle), "family {family}: {err}");
        assert_eq!(content_count().await, before_content, "family {family}");
        assert_eq!(meta_count().await, before_meta, "family {family}");
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM definition_artifacts WHERE family = ?")
                .bind(family)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(rows, 0, "family {family}");
    }

    // Close/reopen: both records read back whole with their interpreters.
    db.close().await;
    let reopened = crate::db::open_database(&url).await.unwrap();
    let s1again: (Option<String>, Option<String>) =
        sqlx::query_as("SELECT accession, interpreter FROM kernel_records WHERE id = ?")
            .bind(&s1)
            .fetch_one(reopened.write_pool())
            .await
            .unwrap();
    assert_eq!(
        s1again,
        (Some("LAB-001".into()), Some("native.defn/1".into()))
    );
    let a1again: (Option<String>, Option<String>) =
        sqlx::query_as("SELECT accession, interpreter FROM kernel_records WHERE id = ?")
            .bind(&a1)
            .fetch_one(reopened.write_pool())
            .await
            .unwrap();
    assert_eq!(
        a1again,
        (Some("A-001".into()), Some("native.defn/2".into()))
    );
    assert!(!v2::history_as(&reopened, &a, &s1).await.unwrap().is_empty());
    assert!(!v2::history_as(&reopened, &a, &a1).await.unwrap().is_empty());

    // Full replay reproduces both with the correct interpreter.
    let before = v2::dump_all_kernel_tables(&reopened).await.unwrap();
    assert_eq!(before.records.len(), 2);
    v2::replay_all_projections(&reopened).await.unwrap();
    let after = v2::dump_all_kernel_tables(&reopened).await.unwrap();
    assert_eq!(before, after);
    let mut interpreters: Vec<Option<String>> = after.records.iter().map(|r| r.9.clone()).collect();
    interpreters.sort();
    assert_eq!(
        interpreters,
        vec![Some("native.defn/1".into()), Some("native.defn/2".into())]
    );

    // Unknown interpreter on a `/2`-pinned event fails the fold loudly.
    let record_id = uuid::Uuid::new_v4().to_string();
    let home: String = sqlx::query_scalar("SELECT root_id FROM kernel_roots LIMIT 1")
        .fetch_one(reopened.write_pool())
        .await
        .unwrap();
    let event = content_event(
        &record_id,
        "kernel.record_created.v1",
        serde_json::json!({
            "home_id": home, "owner_id": None::<String>,
            "primary_type": "Aliquot", "kind": "lab-aliquot", "accession": "A-9",
            "pin": {"family": "lab.aliquot", "version": 1, "digest": &v2id.digest},
            "interpreter": "native.defn/999",
        }),
    );
    let mut conn = reopened.write_pool().acquire().await.unwrap();
    let err = crate::projector::project(&mut conn, &event)
        .await
        .unwrap_err()
        .to_string();
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records WHERE id = ?")
        .bind(&record_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    drop(conn);
    reopened.close().await;
    assert!(err.contains(&record_id), "{err}");
    assert!(err.contains("unknown definition interpreter"), "{err}");
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn v2_shared_parser_ignores_interpreter_key() {
    // The shared production parser is language-blind: an arbitrary extra
    // `interpreter` value is preserved bytes, not an error. Only the
    // kernel-side gate interprets it.
    let parsed = crate::meta::definition_artifact::parse_artifact_envelope(
        r#"{"family":"x.y","version":1,"kinds":[],"interpreter":"whatever/9"}"#,
    )
    .unwrap();
    assert_eq!(parsed.family, "x.y");
    assert_eq!(parsed.version, 1);
}

const LAB_V2_BYTES: &str = r#"{"family":"lab","version":1,"primary_type":"Specimen","interpreter":"native.defn/2","kinds":[{"token":"field-sample","fields":[{"name":"accession","type":"text","required":true},{"name":"site","type":"text","required":false}],"identity":{"field":"accession"},"links":[],"maturity":"current","description":"A field-collected specimen."},{"token":"lab-aliquot","fields":[{"name":"accession","type":"text","required":true},{"name":"volume_ml","type":"number","required":true}],"identity":{"field":"accession"},"links":[{"predicate":"derived_from","target":{"primary_type":"Specimen","kind":"field-sample"},"direction":"out","cardinality":"many"}],"maturity":"current","description":"An aliquot split from a specimen."}]}"#;

const PRIV_V2_BYTES: &str = r#"{"family":"priv.review","version":1,"primary_type":"Review","interpreter":"native.defn/2","kinds":[{"token":"internal-review","fields":[{"name":"score","type":"integer","required":true}],"identity":{"field":"score"},"links":[],"maturity":"draft","description":"A private internal review."}]}"#;

fn defs_of(out: &serde_json::Value) -> &Vec<serde_json::Value> {
    out.get("definitions")
        .and_then(|d| d.as_array())
        .expect("definitions array")
}

fn find<'a>(out: &'a serde_json::Value, family: &str, kind: &str) -> Option<&'a serde_json::Value> {
    defs_of(out).iter().find(|d| {
        d.get("family").and_then(|f| f.as_str()) == Some(family)
            && d.get("kind").and_then(|k| k.as_str()) == Some(kind)
    })
}

#[tokio::test]
async fn v2_describe_filters_unseen_home() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "agent", "B", "agent:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h_lab = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "manage"), (b.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();

    let lab = v2::install_definition_as(&db, &a, "lab", 1, LAB_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab", Some(&lab), &h_lab)
        .await
        .unwrap();

    // Oracle probe: B's describe is byte-identical before and after the
    // private definition comes into existence elsewhere.
    let before = v2::describe_world_as(&db, &b).await.unwrap();
    let h_priv = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let priv_id = v2::install_definition_as(&db, &a, "priv.review", 1, PRIV_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "priv.review", Some(&priv_id), &h_priv)
        .await
        .unwrap();
    let after = v2::describe_world_as(&db, &b).await.unwrap();
    assert_eq!(
        before.to_string(),
        after.to_string(),
        "B's describe must not move"
    );

    // B sees lab with full semantics and generic ops; the private family is
    // absent entirely — no family, kind, description, or home id leaks.
    let b_out = after;
    let b_text = b_out.to_string();
    assert!(find(&b_out, "lab", "field-sample").is_some());
    let aliquot = find(&b_out, "lab", "lab-aliquot").expect("lab-aliquot visible");
    assert_eq!(
        aliquot
            .get("adoption")
            .and_then(|x| x.get("state"))
            .and_then(|s| s.as_str()),
        Some("adopted")
    );
    assert_eq!(
        aliquot.get("maturity").and_then(|m| m.as_str()),
        Some("current")
    );
    assert_eq!(
        aliquot
            .get("identity")
            .and_then(|i| i.get("field"))
            .and_then(|f| f.as_str()),
        Some("accession")
    );
    let fields = aliquot
        .get("fields")
        .and_then(|f| f.as_array())
        .expect("fields");
    assert!(fields.iter().any(
        |f| f.get("name").and_then(|n| n.as_str()) == Some("volume_ml")
            && f.get("type").and_then(|t| t.as_str()) == Some("number")
    ));
    let ops = aliquot
        .get("operations")
        .and_then(|o| o.as_array())
        .expect("operations");
    assert_eq!(ops.len(), 5);
    for op in ops {
        assert!(["create", "link", "query", "revise", "history"]
            .contains(&op.get("name").and_then(|n| n.as_str()).unwrap_or("")));
        assert!(
            ["Edit", "View"].contains(&op.get("requires").and_then(|r| r.as_str()).unwrap_or(""))
        );
    }
    assert!(!b_text.contains("priv.review"), "{b_text}");
    assert!(!b_text.contains("internal-review"), "{b_text}");
    assert!(!b_text.contains(&h_priv), "private home id leaks");
    assert!(
        !b_text.contains("LAB-") && !b_text.contains("accession-value"),
        "no record data"
    );
    // Creatable homes: B may create the lab kinds in h_lab only; A sees the
    // private scope too.
    let homes_of = |entry: &serde_json::Value| {
        entry
            .get("adoption")
            .and_then(|x| x.get("creatable_homes"))
            .and_then(|h| h.as_array())
            .expect("creatable_homes")
            .iter()
            .map(|h| h.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(homes_of(aliquot), vec![h_lab.clone()]);
    // One more hidden home changes nothing in B's output.
    let h_priv2 = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    assert!(!v2::describe_world_as(&db, &b)
        .await
        .unwrap()
        .to_string()
        .contains(&h_priv2));
    assert_eq!(
        v2::describe_world_as(&db, &b).await.unwrap().to_string(),
        b_out.to_string()
    );

    // A sees both families.
    let a_out = v2::describe_world_as(&db, &a).await.unwrap();
    assert!(find(&a_out, "lab", "lab-aliquot").is_some());
    let review = find(&a_out, "priv.review", "internal-review").expect("A sees private");
    assert_eq!(
        review.get("maturity").and_then(|m| m.as_str()),
        Some("draft")
    );
    let a_lab = find(&a_out, "lab", "lab-aliquot").expect("A sees lab");
    assert_eq!(homes_of(a_lab), vec![h_lab.clone()]);
    assert_eq!(homes_of(review), vec![h_priv.clone()]);

    // B cannot adopt into the private home: uniform refusal, nothing echoed.
    let events_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let err = v2::adopt_definition_at(&db, &b, "priv.review", Some(&priv_id), &h_priv)
        .await
        .unwrap_err()
        .to_string();
    assert!(!err.contains(&h_priv), "{err}");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
        events_before
    );

    // `/1` definitions still appear, with the fields they have (none).
    let v1 = v2::install_definition_as(&db, &a, "lab.specimen", 1, SPECIMEN_V1_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab.specimen", Some(&v1), &h_lab)
        .await
        .unwrap();
    let b_v1 = v2::describe_world_as(&db, &b).await.unwrap();
    let spec = find(&b_v1, "lab.specimen", "field-sample").expect("/1 kind visible");
    assert_eq!(
        spec.get("primary_type").and_then(|t| t.as_str()),
        Some("Specimen")
    );
    assert_eq!(
        spec.get("fields")
            .and_then(|f| f.as_array())
            .map(|f| f.len()),
        Some(0)
    );
    assert_eq!(spec.get("maturity"), Some(&serde_json::Value::Null));
    assert_eq!(
        spec.get("operations")
            .and_then(|o| o.as_array())
            .map(|o| o.len()),
        Some(5)
    );

    // Disable in the shared home: entries stay, state flips, ops empty.
    v2::adopt_definition_at(&db, &a, "lab", None, &h_lab)
        .await
        .unwrap();
    let b_dis = v2::describe_world_as(&db, &b).await.unwrap();
    for kind in ["field-sample", "lab-aliquot"] {
        let entry = find(&b_dis, "lab", kind).expect("disabled kind still listed");
        assert_eq!(
            entry
                .get("adoption")
                .and_then(|x| x.get("state"))
                .and_then(|s| s.as_str()),
            Some("disabled"),
            "{kind}"
        );
        assert_eq!(
            entry
                .get("operations")
                .and_then(|o| o.as_array())
                .map(|o| o.len()),
            Some(0),
            "{kind}"
        );
        assert_eq!(homes_of(entry), Vec::<String>::new(), "{kind}");
    }
    // The `/1` adoption in the same home is untouched by lab's disable.
    assert!(find(&b_dis, "lab.specimen", "field-sample").is_some());

    // Replay leaves both principals' describe output identical.
    let (a_pre, b_pre) = (
        v2::describe_world_as(&db, &a).await.unwrap(),
        v2::describe_world_as(&db, &b).await.unwrap(),
    );
    v2::replay_all_projections(&db).await.unwrap();
    assert_eq!(
        v2::describe_world_as(&db, &a).await.unwrap().to_string(),
        a_pre.to_string()
    );
    assert_eq!(
        v2::describe_world_as(&db, &b).await.unwrap().to_string(),
        b_pre.to_string()
    );
}

// Slice-2 increment 3a test data (from the §6 draft; test-only, never
// seeded into any trial path): Specimen / Aliquot / Observation.
const LAB3_V2_BYTES: &str = r#"{"family":"lab3","version":1,"primary_type":"Specimen","interpreter":"native.defn/2","kinds":[{"token":"Specimen","fields":[{"name":"accession","type":"text","required":true},{"name":"collected_at","type":"time","required":false},{"name":"site","type":"text","required":false}],"identity":{"field":"accession"},"links":[{"predicate":"sample_of","target":{"primary_type":"Specimen","kind":"Aliquot"},"direction":"in"}],"maturity":"current","description":"A field-collected specimen."},{"token":"Aliquot","fields":[{"name":"accession","type":"text","required":true},{"name":"volume_ml","type":"number","required":true}],"identity":{"field":"accession"},"links":[{"predicate":"derived_from","target":{"primary_type":"Specimen","kind":"Specimen"},"direction":"out","cardinality":"many"}],"maturity":"current","description":"An aliquot split from a specimen."},{"token":"Observation","fields":[{"name":"accession","type":"text","required":true},{"name":"note","type":"text","required":true},{"name":"observed_at","type":"time","required":true}],"identity":{"field":"accession"},"links":[{"predicate":"about","target":{"primary_type":"Specimen","kind":"Specimen"},"direction":"out","cardinality":"many"},{"predicate":"about","target":{"primary_type":"Specimen","kind":"Aliquot"},"direction":"out","cardinality":"many"}],"maturity":"current","description":"An observation note."}]}"#;

fn field_map(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value.as_object().expect("object payload").clone()
}

#[tokio::test]
async fn v2_generic_create_validates() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "agent", "B", "agent:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h_lab = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "manage"), (b.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();
    let h_priv = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let h_bare = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "manage"), (b.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();

    let lab3 = v2::install_definition_as(&db, &a, "lab3", 1, LAB3_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_lab)
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_priv)
        .await
        .unwrap();

    let content_count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    };

    // Valid creates across all three kinds, incl. a fractional `number`.
    let s104 = v2::create_as(
        &db,
        &a,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "S-104", "site": "ridge"})),
        &h_lab,
    )
    .await
    .unwrap();
    let a104a = v2::create_as(
        &db,
        &a,
        "lab3",
        "Aliquot",
        &field_map(serde_json::json!({"accession": "A-104a", "volume_ml": 2.0})),
        &h_lab,
    )
    .await
    .unwrap();
    v2::create_as(&db, &b, "lab3", "Observation",
        &field_map(serde_json::json!({"accession": "O-1", "note": "cloudy", "observed_at": "2026-09-01T10:00:00Z"})),
        &h_lab).await.unwrap();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, value_json FROM kernel_record_fields WHERE record_id = ? ORDER BY name",
    )
    .bind(&s104)
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        rows,
        vec![
            ("accession".to_string(), "\"S-104\"".to_string()),
            ("site".to_string(), "\"ridge\"".to_string()),
        ]
    );
    let aliq: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, value_json FROM kernel_record_fields WHERE record_id = ? ORDER BY name",
    )
    .bind(&a104a)
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        aliq,
        vec![
            ("accession".to_string(), "\"A-104a\"".to_string()),
            ("volume_ml".to_string(), "2.0".to_string()),
        ]
    );

    // Each validation failure names its field and appends nothing.
    for (kind, payload, needle) in [
        (
            "Specimen",
            serde_json::json!({"accession": "X-1", "nope": 1}),
            "unknown field 'nope'",
        ),
        (
            "Aliquot",
            serde_json::json!({"accession": "X-2", "volume_ml": "lots"}),
            "field 'volume_ml' has wrong type",
        ),
        (
            "Aliquot",
            serde_json::json!({"accession": "X-3"}),
            "missing required field 'volume_ml'",
        ),
        (
            "Specimen",
            serde_json::json!({"accession": "X-4", "collected_at": "yesterday"}),
            "field 'collected_at' has wrong type",
        ),
        (
            "Specimen",
            serde_json::json!({"site": "ridge"}),
            "missing required field 'accession'",
        ),
    ] {
        let before = content_count().await;
        let err = v2::create_as(&db, &a, "lab3", kind, &field_map(payload), &h_lab)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(needle), "{kind}: {err}");
        assert_eq!(content_count().await, before, "{kind}");
    }

    // No adoption in scope refuses (home without any adoption row).
    assert!(v2::create_as(
        &db,
        &a,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "X-9"})),
        &h_bare
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("not adopted"));

    // Duplicate identity: identical uniform text whether the existing row
    // is visible (S-104 in h_lab) or hidden (HID-1 in h_priv, unseen by B).
    v2::create_as(
        &db,
        &a,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "HID-1"})),
        &h_priv,
    )
    .await
    .unwrap();
    let before = content_count().await;
    let visible_dupe = v2::create_as(
        &db,
        &b,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "S-104"})),
        &h_lab,
    )
    .await
    .unwrap_err()
    .to_string();
    let hidden_dupe = v2::create_as(
        &db,
        &b,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "HID-1"})),
        &h_lab,
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(visible_dupe, crate::kernel::IDENTITY_UNAVAILABLE);
    assert_eq!(hidden_dupe, crate::kernel::IDENTITY_UNAVAILABLE);
    assert_eq!(visible_dupe, hidden_dupe);
    assert_eq!(content_count().await, before);

    // Replay reproduces records and fields exactly.
    let dumped = v2::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(dumped.record_fields.len(), 8);
    v2::replay_all_projections(&db).await.unwrap();
    assert_eq!(v2::dump_all_kernel_tables(&db).await.unwrap(), dumped);
}

#[tokio::test]
async fn v2_generic_link_validates() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "agent", "B", "agent:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h_lab = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "manage"), (b.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();
    let h_priv = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();

    let lab3 = v2::install_definition_as(&db, &a, "lab3", 1, LAB3_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_lab)
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_priv)
        .await
        .unwrap();
    let s104 = v2::create_as(
        &db,
        &a,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "S-104"})),
        &h_lab,
    )
    .await
    .unwrap();
    let a104a = v2::create_as(
        &db,
        &a,
        "lab3",
        "Aliquot",
        &field_map(serde_json::json!({"accession": "A-104a", "volume_ml": 2.0})),
        &h_lab,
    )
    .await
    .unwrap();
    let o1 = v2::create_as(&db, &a, "lab3", "Observation",
        &field_map(serde_json::json!({"accession": "O-1", "note": "cloudy", "observed_at": "2026-09-01T10:00:00Z"})),
        &h_lab).await.unwrap();
    let s_hid = v2::create_as(
        &db,
        &a,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "S-HID"})),
        &h_priv,
    )
    .await
    .unwrap();

    let link_count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM kernel_links")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    };
    let content_count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    };

    // Valid declared links succeed.
    v2::link_as(&db, &a, &a104a, "derived_from", &s104)
        .await
        .unwrap();
    v2::link_as(&db, &a, &o1, "about", &s104).await.unwrap();
    v2::link_as(&db, &a, &o1, "about", &a104a).await.unwrap();
    assert_eq!(link_count().await, 3);
    let edges: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT source_id, target_id, relationship FROM kernel_links ORDER BY source_id, target_id",
    )
    .fetch_all(db.write_pool())
    .await
    .unwrap();
    assert!(edges.contains(&(a104a.clone(), s104.clone(), "derived_from".to_string())));
    assert!(edges.contains(&(o1.clone(), a104a.clone(), "about".to_string())));

    // Undeclared predicate, wrong target kind, and wrong direction each
    // refuse with no event.
    for (source, predicate, target, needle) in [
        (
            a104a.clone(),
            "eats",
            s104.clone(),
            "undeclared predicate 'eats'",
        ),
        (
            a104a.clone(),
            "derived_from",
            o1.clone(),
            "not allowed for predicate 'derived_from'",
        ),
        (
            s104.clone(),
            "sample_of",
            a104a.clone(),
            "not allowed for predicate 'sample_of'",
        ),
    ] {
        let (before_links, before_content) = (link_count().await, content_count().await);
        let err = v2::link_as(&db, &a, &source, predicate, &target)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(needle), "{predicate}: {err}");
        assert_eq!(link_count().await, before_links, "{predicate}");
        assert_eq!(content_count().await, before_content, "{predicate}");
    }

    // A hidden target returns the uniform error, never a validation message:
    // B can Edit the aliquot but cannot View the private specimen.
    let (before_links, before_content) = (link_count().await, content_count().await);
    let err = v2::link_as(&db, &b, &a104a, "derived_from", &s_hid)
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(err, "kernel target missing or hidden");
    assert_eq!(link_count().await, before_links);
    assert_eq!(content_count().await, before_content);

    // `/1` sources keep legacy behaviour through the legacy entry point.
    let v1 = v2::install_definition_as(&db, &a, "lab.specimen", 1, SPECIMEN_V1_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab.specimen", Some(&v1), &h_lab)
        .await
        .unwrap();
    let old = v2::create_package_record_as(
        &db,
        &a,
        &h_lab,
        "Specimen",
        "field-sample",
        "LAB-1",
        "lab.specimen",
    )
    .await
    .unwrap();
    v2::link_records_as(&db, &a, &old, &s104).await.unwrap();
    assert_eq!(link_count().await, before_links + 1);

    // Replay reproduces links exactly.
    let dumped = v2::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(dumped.links.len(), 4);
    v2::replay_all_projections(&db).await.unwrap();
    assert_eq!(v2::dump_all_kernel_tables(&db).await.unwrap(), dumped);
}

fn hit_ids(page: &crate::kernel::QueryPage) -> Vec<String> {
    page.hits.iter().map(|h| h.id.clone()).collect()
}

#[tokio::test]
async fn v2_generic_query() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "agent", "B", "agent:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h_lab = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "manage"), (b.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();
    let h_priv = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();

    let lab3 = v2::install_definition_as(&db, &a, "lab3", 1, LAB3_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_lab)
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_priv)
        .await
        .unwrap();
    let s104 = v2::create_as(
        &db,
        &a,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "S-104"})),
        &h_lab,
    )
    .await
    .unwrap();
    let a104a = v2::create_as(
        &db,
        &a,
        "lab3",
        "Aliquot",
        &field_map(serde_json::json!({"accession": "A-104a", "volume_ml": 2.0})),
        &h_lab,
    )
    .await
    .unwrap();
    let a104b = v2::create_as(
        &db,
        &a,
        "lab3",
        "Aliquot",
        &field_map(serde_json::json!({"accession": "A-104b", "volume_ml": 1.0})),
        &h_lab,
    )
    .await
    .unwrap();
    let a_hid = v2::create_as(
        &db,
        &a,
        "lab3",
        "Aliquot",
        &field_map(serde_json::json!({"accession": "A-HID", "volume_ml": 5.0})),
        &h_priv,
    )
    .await
    .unwrap();
    for aliquot in [&a104a, &a104b, &a_hid] {
        v2::link_as(&db, &a, aliquot, "derived_from", &s104)
            .await
            .unwrap();
    }

    // "Aliquots derived_from S-104": B sees exactly its two, in identity
    // order; A additionally sees the hidden one.
    let b_page = v2::query_as(
        &db,
        &b,
        "lab3",
        "Aliquot",
        &[],
        Some(("derived_from", &s104, "out")),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(hit_ids(&b_page), vec![a104a.clone(), a104b.clone()]);
    assert_eq!(b_page.cursor, None);
    let a_page = v2::query_as(
        &db,
        &a,
        "lab3",
        "Aliquot",
        &[],
        Some(("derived_from", &s104, "out")),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        hit_ids(&a_page),
        vec![a104a.clone(), a104b.clone(), a_hid.clone()]
    );

    // Field equality.
    let vol = v2::query_as(
        &db,
        &b,
        "lab3",
        "Aliquot",
        &[("volume_ml", serde_json::json!(2.0))],
        None,
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(hit_ids(&vol), vec![a104a.clone()]);
    assert_eq!(
        vol.hits[0].fields.get("accession"),
        Some(&serde_json::json!("A-104a"))
    );

    // `linked_to` a hidden id behaves exactly like a nonexistent id: same
    // empty page, no distinguishing error.
    let ghost = uuid::Uuid::new_v4().to_string();
    let hidden_link = v2::query_as(
        &db,
        &b,
        "lab3",
        "Specimen",
        &[],
        Some(("derived_from", &a_hid, "in")),
        10,
        None,
    )
    .await
    .unwrap();
    let ghost_link = v2::query_as(
        &db,
        &b,
        "lab3",
        "Specimen",
        &[],
        Some(("derived_from", &ghost, "in")),
        10,
        None,
    )
    .await
    .unwrap();
    assert!(hidden_link.hits.is_empty() && ghost_link.hits.is_empty());
    assert_eq!(hidden_link.cursor, ghost_link.cursor);
    assert_eq!(hidden_link.hits.len(), ghost_link.hits.len());

    // Pagination with limit 1 walks every visible row exactly once.
    let mut walked = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let page = v2::query_as(&db, &b, "lab3", "Aliquot", &[], None, 1, cursor.as_deref())
            .await
            .unwrap();
        walked.extend(hit_ids(&page));
        cursor = page.cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(walked, vec![a104a.clone(), a104b.clone()]);

    // `/1` records are queryable by family and kind; field filters match
    // nothing over their empty field set.
    let v1 = v2::install_definition_as(&db, &a, "lab.specimen", 1, SPECIMEN_V1_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab.specimen", Some(&v1), &h_lab)
        .await
        .unwrap();
    let old = v2::create_package_record_as(
        &db,
        &a,
        &h_lab,
        "Specimen",
        "field-sample",
        "LAB-1",
        "lab.specimen",
    )
    .await
    .unwrap();
    let v1_page = v2::query_as(&db, &b, "lab.specimen", "field-sample", &[], None, 10, None)
        .await
        .unwrap();
    assert_eq!(hit_ids(&v1_page), vec![old.clone()]);
    let v1_filtered = v2::query_as(
        &db,
        &b,
        "lab.specimen",
        "field-sample",
        &[("volume_ml", serde_json::json!(2.0))],
        None,
        10,
        None,
    )
    .await
    .unwrap();
    assert!(v1_filtered.hits.is_empty());

    // Output identical after full replay (pages, walk, and linked query).
    let (pre_b, pre_a, pre_vol) = (b_page, a_page, vol);
    v2::replay_all_projections(&db).await.unwrap();
    let post_b = v2::query_as(
        &db,
        &b,
        "lab3",
        "Aliquot",
        &[],
        Some(("derived_from", &s104, "out")),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(hit_ids(&post_b), hit_ids(&pre_b));
    let post_a = v2::query_as(
        &db,
        &a,
        "lab3",
        "Aliquot",
        &[],
        Some(("derived_from", &s104, "out")),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(hit_ids(&post_a), hit_ids(&pre_a));
    let post_vol = v2::query_as(
        &db,
        &b,
        "lab3",
        "Aliquot",
        &[("volume_ml", serde_json::json!(2.0))],
        None,
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(post_vol, pre_vol);
}

#[tokio::test]
async fn v2_query_cursor_hides_hidden() {
    use crate::kernel as v2;
    // Leak probe: B's full paginated output (hits AND cursors of every page)
    // must be byte-identical before and after 250 records land in a home B
    // cannot View. Single database, so visible ids are stable across the two
    // walks (fresh UUIDs would defeat a two-database byte comparison); the
    // hidden accessions sort *before* the visible ones to force the scan to
    // skip through them on every page.
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "agent", "B", "agent:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h_lab = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "manage"), (b.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();
    let h_priv = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();

    let lab3 = v2::install_definition_as(&db, &a, "lab3", 1, LAB3_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_lab)
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_priv)
        .await
        .unwrap();
    for acc in ["A-1", "A-2"] {
        v2::create_as(
            &db,
            &a,
            "lab3",
            "Aliquot",
            &field_map(serde_json::json!({"accession": acc, "volume_ml": 1.0})),
            &h_lab,
        )
        .await
        .unwrap();
    }
    let walk = || async {
        let mut pages = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = v2::query_as(&db, &b, "lab3", "Aliquot", &[], None, 1, cursor.as_deref())
                .await
                .unwrap();
            // An empty page always ends the walk: no cursor leaks the skip.
            let end = page.cursor.is_none();
            pages.push(format!("{page:?}"));
            cursor = page.cursor;
            if end {
                break;
            }
        }
        pages
    };
    let before = walk().await;
    assert_eq!(
        before.len(),
        2,
        "one hit per page, then the cursor runs out"
    );
    for i in 0..250 {
        v2::create_as(
            &db,
            &a,
            "lab3",
            "Aliquot",
            &field_map(serde_json::json!({"accession": format!("A-0-{i:03}"), "volume_ml": 0.0})),
            &h_priv,
        )
        .await
        .unwrap();
    }
    assert_eq!(walk().await, before);
}

#[tokio::test]
async fn v2_revise_fields_only_loud_replay() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "agent", "B", "agent:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h_lab = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "manage"), (b.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();
    let h_a = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();

    let lab3 = v2::install_definition_as(&db, &a, "lab3", 1, LAB3_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_lab)
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_a)
        .await
        .unwrap();
    let a104a = v2::create_as(
        &db,
        &a,
        "lab3",
        "Aliquot",
        &field_map(serde_json::json!({"accession": "A-104a", "volume_ml": 2.0})),
        &h_lab,
    )
    .await
    .unwrap();
    let pin_row = "SELECT accession, pin_family, pin_version, pin_digest, interpreter FROM kernel_records WHERE id = ?";
    #[allow(clippy::type_complexity)]
    let pin_before: (
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(pin_row)
        .bind(&a104a)
        .fetch_one(db.write_pool())
        .await
        .unwrap();

    // Volume 2.0 -> 1.8 lands as exactly one revise event.
    v2::revise_as(
        &db,
        &a,
        &a104a,
        &field_map(serde_json::json!({"volume_ml": 1.8})),
    )
    .await
    .unwrap();
    let revised: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id = ? AND type = 'kernel.record_revised.v1'",
    )
    .bind(&a104a)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(revised, 1);
    let vol: String = sqlx::query_scalar(
        "SELECT value_json FROM kernel_record_fields WHERE record_id = ? AND name = 'volume_ml'",
    )
    .bind(&a104a)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(vol, "1.8");
    // Identity, pin and interpreter are unchanged.
    #[allow(clippy::type_complexity)]
    let pin_after: (
        Option<String>,
        Option<String>,
        Option<i64>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(pin_row)
        .bind(&a104a)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(pin_before, pin_after);
    // History shows create then revise, attributed to A under slice-1 rules.
    let hist: Vec<(String, Option<String>)> = v2::history_as(&db, &a, &a104a)
        .await
        .unwrap()
        .iter()
        .map(|e| (e.event_type.clone(), e.actor.clone()))
        .collect();
    assert_eq!(
        hist,
        vec![
            ("kernel.record_created.v1".to_string(), Some(a.clone())),
            ("kernel.record_revised.v1".to_string(), Some(a.clone())),
        ]
    );

    // Identity-change, kind-change and unknown-field patches refuse event-free.
    let content_count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    };
    for (payload, needle) in [
        (serde_json::json!({"accession": "A-999"}), "immutable"),
        (
            serde_json::json!({"kind": "Aliquot"}),
            "unknown field 'kind'",
        ),
        (serde_json::json!({"nope": 1}), "unknown field 'nope'"),
        (serde_json::json!({"volume_ml": "lots"}), "wrong type"),
    ] {
        let before = content_count().await;
        let err = v2::revise_as(&db, &a, &a104a, &field_map(payload))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(needle), "{err}");
        assert_eq!(content_count().await, before);
    }
    // Clearing a required field refuses too.
    let before = content_count().await;
    let err = v2::revise_as(
        &db,
        &a,
        &a104a,
        &field_map(serde_json::json!({"volume_ml": null})),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("missing required field 'volume_ml'"), "{err}");
    assert_eq!(content_count().await, before);

    // B without Edit on the home is refused uniformly, naming nothing.
    let hid = v2::create_as(
        &db,
        &a,
        "lab3",
        "Aliquot",
        &field_map(serde_json::json!({"accession": "A-HID", "volume_ml": 5.0})),
        &h_a,
    )
    .await
    .unwrap();
    let before = content_count().await;
    let err = v2::revise_as(
        &db,
        &b,
        &hid,
        &field_map(serde_json::json!({"volume_ml": 6.0})),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(err, "kernel target missing or hidden");
    assert_eq!(content_count().await, before);

    // Full replay reproduces the revised fields exactly.
    let dumped = v2::dump_all_kernel_tables(&db).await.unwrap();
    v2::replay_all_projections(&db).await.unwrap();
    assert_eq!(v2::dump_all_kernel_tables(&db).await.unwrap(), dumped);
    let vol: String = sqlx::query_scalar(
        "SELECT value_json FROM kernel_record_fields WHERE record_id = ? AND name = 'volume_ml'",
    )
    .bind(&a104a)
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    assert_eq!(vol, "1.8");

    // Tampered pin bytes make content replay of the revise fail loudly,
    // naming the record.
    sqlx::query(
        "UPDATE definition_artifacts SET artifact_bytes = ? WHERE family = 'lab3' AND version = 1",
    )
    .bind(LAB3_V2_BYTES.replace(
        "\"volume_ml\",\"type\":\"number\"",
        "\"volume_ml\",\"type\":\"text\"",
    ))
    .execute(db.write_pool())
    .await
    .unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let events = crate::conformance::rebuild::read_all_events(&mut tx)
        .await
        .unwrap();
    for table in [
        "kernel_links",
        "kernel_record_fields",
        "kernel_records",
        "kernel_adoptions",
        "kernel_policy_entries",
        "kernel_policies",
        "kernel_root_bootstrap",
        // Roots before principals: homes reference their owner principal.
        "kernel_roots",
        "kernel_principals",
    ] {
        sqlx::query(&format!("DELETE FROM {table}"))
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    let mut failure = None;
    for event in &events {
        if let Err(error) = crate::projector::project(&mut tx, event).await {
            failure = Some(error.to_string());
            break;
        }
    }
    tx.rollback().await.unwrap();
    let err = failure.expect("replay must refuse tampered pin bytes");
    assert!(err.contains(&a104a), "{err}");
}

#[tokio::test]
async fn v2_home_owner_recoverable_history() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "agent", "B", "agent:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;

    // Owners: the root admin owns the workspace root; the creator owns H.
    let h = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let owner_of = || async {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT owner_id FROM kernel_roots WHERE root_id = ?",
        )
        .bind(&h)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
    };
    assert_eq!(owner_of().await.as_deref(), Some(a.as_str()));
    let root_owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id = ?")
            .bind(root)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    assert_eq!(root_owner.as_deref(), Some(a.as_str()));

    // A empties H's policy through the event path and still holds Manage via
    // the owner floor; B, who owns nothing here, holds None and cannot
    // replace or restore.
    v2::replace_home_policy(&db, &a, &h, &[]).await.unwrap();
    assert_eq!(
        v2::kernel_effective_capability(&db, &a, &h).await.unwrap(),
        crate::authorization::Capability::Manage
    );
    assert_eq!(
        v2::kernel_effective_capability(&db, &b, &h).await.unwrap(),
        crate::authorization::Capability::None
    );
    assert_eq!(
        v2::replace_home_policy(&db, &b, &h, &[(b.as_str(), "manage")])
            .await
            .unwrap_err()
            .to_string(),
        "kernel target missing or hidden"
    );
    // The owner restores a grant for B through the same event path.
    v2::replace_home_policy(&db, &a, &h, &[(b.as_str(), "view")])
        .await
        .unwrap();
    assert_eq!(
        v2::kernel_effective_capability(&db, &b, &h).await.unwrap(),
        crate::authorization::Capability::View
    );

    // Home history: create, empty, restore — all attributed to A.
    let hist: Vec<(String, Option<String>)> = v2::history_as(&db, &a, &h)
        .await
        .unwrap()
        .iter()
        .map(|e| (e.event_type.clone(), e.actor.clone()))
        .collect();
    assert_eq!(
        hist,
        vec![
            ("kernel.home_created.v1".to_string(), Some(a.clone())),
            (
                "kernel.home_policy_replaced.v1".to_string(),
                Some(a.clone())
            ),
            (
                "kernel.home_policy_replaced.v1".to_string(),
                Some(a.clone())
            ),
        ]
    );
    // A home B cannot View reads exactly like a nonexistent id: empty.
    let h2 = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let ghost = uuid::Uuid::new_v4().to_string();
    assert!(v2::history_as(&db, &b, &h2).await.unwrap().is_empty());
    assert_eq!(
        v2::history_as(&db, &b, &h2).await.unwrap(),
        v2::history_as(&db, &b, &ghost).await.unwrap()
    );

    // Principal history follows the directory rule: B sees its own events
    // (foreign actor redacted without root View); A, holding root View,
    // sees B's actor; B sees nothing of A's, exactly like a missing id.
    let b_self = v2::history_as(&db, &b, &b).await.unwrap();
    assert_eq!(b_self.len(), 1);
    assert_eq!(b_self[0].event_type, "kernel.principal_created.v1");
    assert_eq!(b_self[0].actor, None);
    let b_by_a = v2::history_as(&db, &a, &b).await.unwrap();
    assert_eq!(b_by_a.len(), 1);
    assert_eq!(b_by_a[0].actor.as_deref(), Some("test:v2"));
    assert!(v2::history_as(&db, &b, &a).await.unwrap().is_empty());
    assert_eq!(
        v2::history_as(&db, &b, &a).await.unwrap(),
        v2::history_as(&db, &b, &ghost).await.unwrap()
    );

    // Full replay reproduces owners, policies, and entries exactly.
    let dumped = v2::dump_all_kernel_tables(&db).await.unwrap();
    assert!(dumped
        .roots
        .iter()
        .any(|(id, _, owner, _, _)| { id == &h && owner.as_deref() == Some(a.as_str()) }));
    v2::replay_all_projections(&db).await.unwrap();
    assert_eq!(v2::dump_all_kernel_tables(&db).await.unwrap(), dumped);
}

#[tokio::test]
async fn v2_read_returns_fields() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let b = v2::create_principal(&db, "agent", "B", "agent:b", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h_lab = v2::create_home(
        &db,
        root,
        Some(&[(a.as_str(), "manage"), (b.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();
    let h_priv = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();

    let lab3 = v2::install_definition_as(&db, &a, "lab3", 1, LAB3_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_lab)
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "lab3", Some(&lab3), &h_priv)
        .await
        .unwrap();
    let s104 = v2::create_as(
        &db,
        &a,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "S-104", "site": "ridge"})),
        &h_lab,
    )
    .await
    .unwrap();
    let hid = v2::create_as(
        &db,
        &a,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "S-HID"})),
        &h_priv,
    )
    .await
    .unwrap();

    // Visible read carries query-hit-shaped fields plus pin coordinates;
    // owner redaction follows the record rule (B lacks root View here).
    let seen = v2::read_record_as(&db, &b, &s104)
        .await
        .unwrap()
        .expect("visible");
    assert_eq!(seen.id, s104);
    assert_eq!(
        seen.fields.get("accession"),
        Some(&serde_json::json!("S-104"))
    );
    assert_eq!(seen.fields.get("site"), Some(&serde_json::json!("ridge")));
    assert_eq!(seen.family.as_deref(), Some("lab3"));
    assert_eq!(seen.kind.as_deref(), Some("Specimen"));
    assert_eq!(seen.pin.as_ref().map(|p| &p.digest), Some(&lab3.digest));
    assert_eq!(seen.interpreter.as_deref(), Some("native.defn/2"));
    assert_eq!(seen.owner_id, None);
    let seen_a = v2::read_record_as(&db, &a, &s104)
        .await
        .unwrap()
        .expect("visible");
    assert_eq!(seen_a.owner_id.as_deref(), Some(a.as_str()));

    // Hidden and missing ids both read null.
    assert!(v2::read_record_as(&db, &b, &hid).await.unwrap().is_none());
    let ghost = uuid::Uuid::new_v4().to_string();
    assert!(v2::read_record_as(&db, &b, &ghost).await.unwrap().is_none());
}

#[tokio::test]
async fn v2_describe_matches_resolution() {
    use crate::kernel as v2;
    // F1: admin adopts at the workspace root; op holds Manage on child H
    // with no root View. Describe must show exactly what op can use.
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let op = v2::create_principal(&db, "agent", "Op", "agent:op", "test:v2")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;
    let h = v2::create_home(&db, root, Some(&[(op.as_str(), "manage")]), &a)
        .await
        .unwrap();

    let lab3 = v2::install_definition_as(&db, &a, "lab3", 1, LAB3_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_as(&db, &a, "lab3", Some(&lab3))
        .await
        .unwrap();

    let out = v2::describe_world_as(&db, &op).await.unwrap();
    let entry = find(&out, "lab3", "Specimen").expect("op sees root-adopted lab3");
    let adoption = entry.get("adoption").expect("adoption");
    assert_eq!(
        adoption
            .get("resolved_in")
            .and_then(|v| v.as_array())
            .map(|v| v.len()),
        Some(1)
    );
    assert_eq!(
        adoption
            .get("resolved_in")
            .and_then(|v| v.as_array())
            .unwrap()[0]
            .as_str(),
        Some(h.as_str())
    );
    let creatable: Vec<&str> = adoption
        .get("creatable_homes")
        .and_then(|v| v.as_array())
        .expect("creatable_homes")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(creatable, vec![h.as_str()]);
    assert!(
        !out.to_string().contains("kernel:root"),
        "no unseen scope leaks"
    );

    // Op can create in H: describe told the truth.
    let s1 = v2::create_as(
        &db,
        &op,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "S-1"})),
        &h,
    )
    .await
    .unwrap();
    assert!(!s1.is_empty());

    // F2: the admin sees root and child scopes, both creatable.
    let a_out = v2::describe_world_as(&db, &a).await.unwrap();
    let a_entry = find(&a_out, "lab3", "Specimen").expect("admin sees lab3");
    let a_adoption = a_entry.get("adoption").expect("adoption");
    let mut a_resolved: Vec<&str> = a_adoption
        .get("resolved_in")
        .and_then(|v| v.as_array())
        .expect("resolved_in")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    a_resolved.sort_unstable();
    let mut expected = vec![h.as_str(), root];
    expected.sort_unstable();
    assert_eq!(a_resolved, expected);
    let mut a_creatable: Vec<&str> = a_adoption
        .get("creatable_homes")
        .and_then(|v| v.as_array())
        .expect("creatable_homes")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    a_creatable.sort_unstable();
    assert_eq!(a_creatable, expected);

    // A principal with no visible resolving home sees nothing and is
    // refused uniformly when creating there.
    let b2 = v2::create_principal(&db, "agent", "B2", "agent:b2", "test:v2")
        .await
        .unwrap();
    let b2_out = v2::describe_world_as(&db, &b2).await.unwrap();
    assert!(find(&b2_out, "lab3", "Specimen").is_none());
    let err = v2::create_as(
        &db,
        &b2,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "S-2"})),
        &h,
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(err, "kernel target missing or hidden");
}

#[tokio::test]
async fn v2_root_disable_is_tombstone() {
    use crate::kernel as v2;
    // R1: a root-scope disable shows `disabled` entries, exactly like a
    // scoped disable; a never-adopted family stays absent.
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let root = crate::events::KERNEL_ROOT_ID;

    let lab3 = v2::install_definition_as(&db, &a, "lab3", 1, LAB3_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_as(&db, &a, "lab3", Some(&lab3))
        .await
        .unwrap();
    assert!(find(
        &v2::describe_world_as(&db, &a).await.unwrap(),
        "lab3",
        "Specimen"
    )
    .is_some());

    v2::adopt_definition_as(&db, &a, "lab3", None)
        .await
        .unwrap();
    let h = v2::create_home(&db, root, Some(&[(a.as_str(), "manage")]), &a)
        .await
        .unwrap();
    let out = v2::describe_world_as(&db, &a).await.unwrap();
    for kind in ["Specimen", "Aliquot", "Observation"] {
        let entry = find(&out, "lab3", kind).expect("disabled kind still listed");
        assert_eq!(
            entry
                .get("adoption")
                .and_then(|x| x.get("state"))
                .and_then(|s| s.as_str()),
            Some("disabled"),
            "{kind}"
        );
        assert_eq!(
            entry
                .get("operations")
                .and_then(|o| o.as_array())
                .map(|o| o.len()),
            Some(0),
            "{kind}"
        );
    }
    // Create still refuses after the root disable.
    let err = v2::create_as(
        &db,
        &a,
        "lab3",
        "Specimen",
        &field_map(serde_json::json!({"accession": "S-9"})),
        &h,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("not adopted"), "{err}");
    // A never-adopted family is absent, not disabled.
    let ghost_out = v2::describe_world_as(&db, &a).await.unwrap();
    assert!(
        defs_of(&ghost_out)
            .iter()
            .all(|d| d.get("family").and_then(|f| f.as_str()) != Some("nope")),
        "{ghost_out}"
    );

    // Full replay reproduces the tombstone exactly.
    let dumped = v2::dump_all_kernel_tables(&db).await.unwrap();
    v2::replay_all_projections(&db).await.unwrap();
    assert_eq!(v2::dump_all_kernel_tables(&db).await.unwrap(), dumped);
    let post = v2::describe_world_as(&db, &a).await.unwrap();
    assert_eq!(post.to_string(), out.to_string());
}

// --- PR1 `native.defn/3` probes (additive over `/2`) -------------------------

/// Record-identity kind: no identity field, no uniqueness check.
const RECORD_ID_V3_BYTES: &str = r#"{"family":"v3.records","version":1,"primary_type":"Note","interpreter":"native.defn/3","kinds":[{"token":"note","description":"A record-identified note.","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"title","type":"text","required":true}],"links":[]}]}"#;

/// A `/3` envelope that still uses a named identity field.
const FIELD_ID_V3_BYTES: &str = r#"{"family":"v3.fields","version":1,"primary_type":"Code","interpreter":"native.defn/3","kinds":[{"token":"code","description":"A named-identity code.","maturity":"current","identity":{"field":"label"},"fields":[{"name":"label","type":"text","required":true}],"links":[]}]}"#;

#[tokio::test]
async fn v2_defn3_record_identity_distinct_and_replayable() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let h = v2::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(a.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();
    let pin = v2::install_definition_as(&db, &a, "v3.records", 1, RECORD_ID_V3_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "v3.records", Some(&pin), &h)
        .await
        .unwrap();

    // Identical field payloads both succeed: each record is its own identity.
    let one = v2::create_as(
        &db,
        &a,
        "v3.records",
        "note",
        &field_map(serde_json::json!({"title": "same"})),
        &h,
    )
    .await
    .unwrap();
    let two = v2::create_as(
        &db,
        &a,
        "v3.records",
        "note",
        &field_map(serde_json::json!({"title": "same"})),
        &h,
    )
    .await
    .unwrap();
    assert_ne!(one, two);
    for id in [&one, &two] {
        let (accession, interpreter): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT accession, interpreter FROM kernel_records WHERE id = ?")
                .bind(id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        let expected = format!("v3.records:note:{id}");
        assert_eq!(accession.as_deref(), Some(expected.as_str()));
        assert_eq!(interpreter.as_deref(), Some("native.defn/3"));
    }

    // Revise succeeds; the record id, not a field, is the identity.
    v2::revise_as(
        &db,
        &a,
        &one,
        &field_map(serde_json::json!({"title": "renamed"})),
    )
    .await
    .unwrap();
    assert!(!v2::history_as(&db, &a, &one).await.unwrap().is_empty());

    // Named identity still works under `/3` and still dedups.
    let fpin = v2::install_definition_as(&db, &a, "v3.fields", 1, FIELD_ID_V3_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "v3.fields", Some(&fpin), &h)
        .await
        .unwrap();
    v2::create_as(
        &db,
        &a,
        "v3.fields",
        "code",
        &field_map(serde_json::json!({"label": "L-1"})),
        &h,
    )
    .await
    .unwrap();
    let dupe = v2::create_as(
        &db,
        &a,
        "v3.fields",
        "code",
        &field_map(serde_json::json!({"label": "L-1"})),
        &h,
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(dupe, v2::IDENTITY_UNAVAILABLE);

    // Full replay reproduces the record-identity accessions exactly.
    let before = v2::dump_all_kernel_tables(&db).await.unwrap();
    v2::replay_all_projections(&db).await.unwrap();
    assert_eq!(v2::dump_all_kernel_tables(&db).await.unwrap(), before);
}

#[tokio::test]
async fn v2_defn3_identity_refusals_append_nothing() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let count = || async {
        let content: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let meta: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        content + meta
    };
    for (family, bytes, needle) in [
        (
            "v3.badmode",
            r#"{"family":"v3.badmode","version":1,"primary_type":"Note","interpreter":"native.defn/3","kinds":[{"token":"note","description":"x","maturity":"current","identity":{"mode":"nope"},"fields":[{"name":"title","type":"text","required":true}],"links":[]}]}"#,
            "unknown identity mode",
        ),
        (
            "v3.both",
            r#"{"family":"v3.both","version":1,"primary_type":"Note","interpreter":"native.defn/3","kinds":[{"token":"note","description":"x","maturity":"current","identity":{"mode":"record","field":"title"},"fields":[{"name":"title","type":"text","required":true}],"links":[]}]}"#,
            "both 'mode' and 'field'",
        ),
        (
            "v3.noident",
            r#"{"family":"v3.noident","version":1,"primary_type":"Note","interpreter":"native.defn/3","kinds":[{"token":"note","description":"x","maturity":"current","identity":{},"fields":[{"name":"title","type":"text","required":true}],"links":[]}]}"#,
            "must carry 'identity.field'",
        ),
        (
            "v3.choicenovalues",
            r#"{"family":"v3.choicenovalues","version":1,"primary_type":"Impact","interpreter":"native.defn/3","kinds":[{"token":"impact","description":"x","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"method","type":"choice","required":true}],"links":[]}]}"#,
            "needs a non-empty 'values'",
        ),
        (
            "v3.choiceempty",
            r#"{"family":"v3.choiceempty","version":1,"primary_type":"Impact","interpreter":"native.defn/3","kinds":[{"token":"impact","description":"x","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"method","type":"choice","values":[],"required":true}],"links":[]}]}"#,
            "needs a non-empty 'values'",
        ),
        (
            "v3.choicenonstring",
            r#"{"family":"v3.choicenonstring","version":1,"primary_type":"Impact","interpreter":"native.defn/3","kinds":[{"token":"impact","description":"x","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"method","type":"choice","values":["declared",1],"required":true}],"links":[]}]}"#,
            "'values' entries must be strings",
        ),
        (
            "v3.valuesontext",
            r#"{"family":"v3.valuesontext","version":1,"primary_type":"Impact","interpreter":"native.defn/3","kinds":[{"token":"impact","description":"x","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"claim","type":"text","values":["a"],"required":true}],"links":[]}]}"#,
            "must not carry 'values'",
        ),
        (
            "v3.baddescription",
            r#"{"family":"v3.baddescription","version":1,"primary_type":"Impact","interpreter":"native.defn/3","kinds":[{"token":"impact","description":"x","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"claim","type":"text","required":true,"description":"  "}],"links":[]}]}"#,
            "'description' must be a non-empty string",
        ),
    ] {
        let before = count().await;
        let err = v2::install_definition_as(&db, &a, family, 1, bytes.as_bytes())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(needle), "{family}: {err}");
        assert_eq!(count().await, before, "{family}");
    }
}

/// A `/3` kind exercising `choice`, `date`, `time` and per-field descriptions.
const TYPED_V3_BYTES: &str = r#"{"family":"v3.typed","version":1,"primary_type":"Impact","interpreter":"native.defn/3","kinds":[{"token":"impact","description":"A claimed effect.","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"claim","type":"text","required":true,"description":"The effect claimed, in one sentence."},{"name":"method","type":"choice","values":["declared","derived"],"required":true},{"name":"effective_at","type":"date","required":true},{"name":"at_time","type":"time","required":false}],"links":[]}]}"#;

#[tokio::test]
async fn v2_defn3_choice_and_date() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let h = v2::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(a.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();
    let pin = v2::install_definition_as(&db, &a, "v3.typed", 1, TYPED_V3_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "v3.typed", Some(&pin), &h)
        .await
        .unwrap();

    // Describe passes the new keys straight through: per-field description,
    // `choice` with its values list, and the record identity mode.
    let out = v2::describe_world_as(&db, &a).await.unwrap();
    let impact = find(&out, "v3.typed", "impact").expect("impact visible");
    assert_eq!(
        impact
            .get("identity")
            .and_then(|i| i.get("mode"))
            .and_then(|m| m.as_str()),
        Some("record")
    );
    let fields = impact
        .get("fields")
        .and_then(|f| f.as_array())
        .expect("fields");
    let method = fields
        .iter()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some("method"))
        .expect("method field");
    assert_eq!(method.get("type").and_then(|t| t.as_str()), Some("choice"));
    assert_eq!(
        method
            .get("values")
            .and_then(|v| v.as_array())
            .map(|v| v.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>()),
        Some(vec!["declared", "derived"])
    );
    let claim = fields
        .iter()
        .find(|f| f.get("name").and_then(|n| n.as_str()) == Some("claim"))
        .expect("claim field");
    assert_eq!(
        claim.get("description").and_then(|d| d.as_str()),
        Some("The effect claimed, in one sentence.")
    );

    // Calendar date and RFC 3339 date-time both accepted.
    v2::create_as(
        &db,
        &a,
        "v3.typed",
        "impact",
        &field_map(
            serde_json::json!({"claim": "c1", "method": "derived", "effective_at": "2026-09-01"}),
        ),
        &h,
    )
    .await
    .unwrap();
    v2::create_as(
        &db,
        &a,
        "v3.typed",
        "impact",
        &field_map(serde_json::json!({"claim": "c2", "method": "declared", "effective_at": "2026-09-01T10:00:00Z"})),
        &h,
    )
    .await
    .unwrap();

    let content_count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    };
    for (payload, needle) in [
        (
            serde_json::json!({"claim": "x", "method": "guessed", "effective_at": "2026-09-01"}),
            "field 'method' value is not an allowed choice",
        ),
        (
            serde_json::json!({"claim": "x", "method": "derived", "effective_at": "2026-9-1"}),
            "field 'effective_at' has wrong type, expected date",
        ),
        // An impossible calendar date refuses too (month has no 30th).
        (
            serde_json::json!({"claim": "x", "method": "derived", "effective_at": "2026-02-30"}),
            "field 'effective_at' has wrong type, expected date",
        ),
        (
            serde_json::json!({"claim": "x", "method": "derived", "effective_at": "2026-13-01"}),
            "field 'effective_at' has wrong type, expected date",
        ),
        (
            serde_json::json!({"claim": "x", "method": "derived", "effective_at": "yesterday"}),
            "field 'effective_at' has wrong type, expected date",
        ),
        // `time` stays strict: a calendar date is not an RFC 3339 date-time.
        (
            serde_json::json!({"claim": "x", "method": "derived", "effective_at": "2026-09-01", "at_time": "2026-09-01"}),
            "field 'at_time' has wrong type, expected time",
        ),
    ] {
        let before = content_count().await;
        let err = v2::create_as(&db, &a, "v3.typed", "impact", &field_map(payload), &h)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains(needle), "{err}");
        assert_eq!(content_count().await, before, "{err}");
    }

    let before = v2::dump_all_kernel_tables(&db).await.unwrap();
    v2::replay_all_projections(&db).await.unwrap();
    assert_eq!(v2::dump_all_kernel_tables(&db).await.unwrap(), before);
}

/// Required `text` is non-blank under `/3`, but `/2` keeps accepting a blank
/// required string exactly as before.
const BLANK_V3_BYTES: &str = r#"{"family":"v3.blank","version":1,"primary_type":"Label","interpreter":"native.defn/3","kinds":[{"token":"label","description":"A labelled thing.","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"label","type":"text","required":true}],"links":[]}]}"#;
const BLANK_V2_BYTES: &str = r#"{"family":"v2.blank","version":1,"primary_type":"Label","interpreter":"native.defn/2","kinds":[{"token":"label","description":"A labelled thing.","maturity":"current","identity":{"field":"label"},"fields":[{"name":"label","type":"text","required":true}],"links":[]}]}"#;

#[tokio::test]
async fn v2_defn3_required_text_non_blank_but_defn2_allows_blank() {
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();
    let h = v2::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(a.as_str(), "manage")]),
        &a,
    )
    .await
    .unwrap();
    let content_count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    };

    let v3pin = v2::install_definition_as(&db, &a, "v3.blank", 1, BLANK_V3_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "v3.blank", Some(&v3pin), &h)
        .await
        .unwrap();
    let v2pin = v2::install_definition_as(&db, &a, "v2.blank", 1, BLANK_V2_BYTES.as_bytes())
        .await
        .unwrap();
    v2::adopt_definition_at(&db, &a, "v2.blank", Some(&v2pin), &h)
        .await
        .unwrap();

    // `/3`: whitespace-only required text refuses and names the field.
    let before = content_count().await;
    let err = v2::create_as(
        &db,
        &a,
        "v3.blank",
        "label",
        &field_map(serde_json::json!({"label": "   "})),
        &h,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("required field 'label' must not be blank"),
        "{err}"
    );
    assert_eq!(content_count().await, before);
    assert!(v2::create_as(
        &db,
        &a,
        "v3.blank",
        "label",
        &field_map(serde_json::json!({"label": "kept"})),
        &h,
    )
    .await
    .is_ok());

    // `/3`: a revise that blanks a required text refuses too.
    let before = content_count().await;
    let rec: String = sqlx::query_scalar(
        "SELECT id FROM kernel_records WHERE kind = 'label' AND pin_family = 'v3.blank' LIMIT 1",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    let err = v2::revise_as(
        &db,
        &a,
        &rec,
        &field_map(serde_json::json!({"label": "  "})),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        err.contains("required field 'label' must not be blank"),
        "{err}"
    );
    assert_eq!(content_count().await, before);

    // `/2` unchanged: a blank required string is still accepted.
    v2::create_as(
        &db,
        &a,
        "v2.blank",
        "label",
        &field_map(serde_json::json!({"label": "   "})),
        &h,
    )
    .await
    .unwrap();
}

/// One small `/3` definition for the disabled-provenance fixture.
fn provenance_definition(family: &str, version: u32) -> String {
    serde_json::json!({
        "family": family,
        "version": version,
        "interpreter": "native.defn/3",
        "primary_type": "ProvDoc",
        "kinds": [{
            "token": "doc",
            "description": "A provenance fixture.",
            "maturity": "current",
            "identity": {"mode": "record"},
            "fields": [{"name": "title", "type": "text", "required": true}],
            "links": [],
        }],
    })
    .to_string()
}

/// One definitions-only package embedding `family@version`.
fn provenance_package(
    name: &str,
    package_version: u32,
    family: &str,
    definition_version: u32,
) -> crate::package_manifest::PackageManifest {
    let bytes = provenance_definition(family, definition_version);
    let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
    crate::package_manifest::PackageManifest {
        namespace: "prov".to_string(),
        name: name.to_string(),
        version: package_version,
        definitions: vec![crate::package_manifest::DefinitionEntry {
            family: family.to_string(),
            version: definition_version,
            artifact_bytes: bytes,
            digest,
        }],
        behaviour: None,
        surface: None,
        declared_reads: Vec::new(),
    }
}

/// Carried PR2 review nit: a disabled definition entry's `package` provenance
/// must come from the adopted pin, or be null — never from a newer installed
/// revision that was never adopted here.
#[tokio::test]
async fn v2_disabled_entry_provenance_is_null_not_a_newer_install() {
    use crate::events::KERNEL_ROOT_ID;
    use crate::kernel as v2;
    let (db, a) = v2::create_v2_database(":memory:", "account", "A", "acct:a")
        .await
        .unwrap();

    // v1 is installed, adopted at the root, then disabled (package tombstone
    // plus its pinned family tombstone).
    let v1 = provenance_package("doc", 1, "prov.doc", 1);
    let v1_id = v1.identity().unwrap();
    v2::install_package_as(&db, &a, &v1).await.unwrap();
    v2::adopt_package_at(&db, &a, KERNEL_ROOT_ID, &v1, Some(&v1_id), &[])
        .await
        .unwrap();
    v2::adopt_package_at(&db, &a, KERNEL_ROOT_ID, &v1, None, &[])
        .await
        .unwrap();

    // A newer revision of the same family, supplied by a second package that
    // is installed but never adopted. It is now the newest installed bytes.
    let v2m = provenance_package("doc", 2, "prov.doc", 2);
    v2::install_package_as(&db, &a, &v2m).await.unwrap();

    let out = v2::describe_world_as(&db, &a).await.unwrap();
    let entry = find(&out, "prov.doc", "doc").expect("disabled entry visible");
    assert_eq!(
        entry["adoption"]["state"],
        serde_json::json!("disabled"),
        "{entry}"
    );
    assert!(
        entry["package"].is_null(),
        "disabled entry must not borrow a never-adopted revision's package: {entry}"
    );
    assert!(entry["version"].is_null(), "{entry}");
    assert!(entry["digest"].is_null(), "{entry}");
}
