use super::*;

fn descriptor() -> Value {
    json!({"need":BODY_READ_NEED,"scope":BODY_READ_SCOPE})
}
fn sql(key: &str) -> Value {
    json!({"need":"sql.snapshot.v1","key":key,"label":"rows","sql":"SELECT id FROM records ORDER BY id"})
}

#[test]
fn frozen_baseline_and_descriptor_commitment_vectors() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/alpha-tab-body-admission-v1/vectors.json"
    ))
    .unwrap();
    for case in corpus["vectors"].as_array().unwrap() {
        let canonical = canonical_declaration(&case["declaration"]).unwrap();
        assert_eq!(canonical, case["canonical"], "{}", case["name"]);
        assert_eq!(
            String::from_utf8(crate::canonical_json::canonical_json(&canonical)).unwrap(),
            case["canonical_bytes"].as_str().unwrap()
        );
        assert_eq!(
            declaration_digest(&case["declaration"]).unwrap(),
            case["declaration_digest"].as_str().unwrap()
        );
    }
    assert_eq!(
        install_digest(
            "44a905b57d7957f3d8411ac4ce8fcedd5dcd202454cfbed87ec84cfda75efda0",
            "9c6045ec2a73034d6e1a55463fec891dc38db088202f556a0e89bee7ae7bcb15",
            "native.html.v1"
        ),
        "sha256:abd4e377416d6cecec1afff72b4281ee5ffde53d8649b6a7b9530a94dc3b0f40"
    );
}

#[test]
fn union_current_feature_canonicalization_matches_fixed_valid_commitments() {
    let corpus: Value = serde_json::from_str(include_str!(
        "../../tests/fixtures/alpha-tab-body-admission-v1/vectors.json"
    ))
    .unwrap();
    for case in corpus["vectors"].as_array().unwrap() {
        // These are released valid vectors, not evolving current SQL proofs of history.
        assert_eq!(
            crate::mcp::tools::alpha_tabs::alpha_tab_canonical_declaration(&case["declaration"])
                .unwrap(),
            case["canonical"],
            "{}",
            case["name"]
        );
        assert_eq!(
            crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&case["declaration"])
                .unwrap(),
            case["declaration_digest"].as_str().unwrap()
        );
    }
}

#[test]
fn frozen_structure_does_not_replay_current_sql_safety() {
    // Explicit trusted historical commitment, NOT a fresh issuance fixture.
    // Even obviously unsafe raw SQL stays committed structurally; current
    // governed execution admission still refuses it independently.
    for query in [
        "DELETE FROM records",
        "SELECT id FROM control_events",
        "SELECT id FROM records LIMIT 1",
        "SELECT ?2",
    ] {
        let mut need = sql("rows");
        need["sql"] = json!(query);
        let d = json!({"needs":[descriptor(),need],"effects":[]});
        let canonical = canonical_declaration(&d).unwrap();
        assert_eq!(canonical["sql_needs"][0]["sql"], query);
        assert!(
            crate::query::sql::validate(query).is_err()
                || crate::query::sql_contract::check_positional_arguments(
                    crate::query::sql_contract::QuerySqlProfile::SqliteLocal,
                    query,
                    0
                )
                .is_err(),
            "{query}"
        );
    }
}

#[test]
fn frozen_closed_objects_collisions_counts_and_parameter_bounds() {
    let good = json!({"needs":[descriptor(),sql("rows")],"effects":[]});
    let mut invalid = vec![
        json!({"needs":[],"effects":[],"reads":{}}),
        json!({"needs":[],"effects":[],"body_read_needs":[]}),
        json!({"needs":[],"effects":[],"other":0}),
        json!({"needs":[],"effects":"no"}),
        json!({"needs":[{"need":"unknown"}],"effects":[]}),
        json!({"needs":[descriptor(),descriptor()],"effects":[]}),
        json!({"needs":[descriptor(),BODY_READ_NEED],"effects":[]}),
        json!({"needs":[descriptor(),sql(BODY_READ_NEED)],"effects":[]}),
        json!({"needs":[sql("rows"),"rows"],"effects":[]}),
        json!({"needs":[sql("rows"),sql("rows")],"effects":[]}),
    ];
    for mut body in [descriptor(), descriptor()] {
        body["extra"] = json!(true);
        invalid.push(json!({"needs":[body],"effects":[]}));
    }
    invalid.push(json!({"needs":[{"need":BODY_READ_NEED,"scope":"all"}],"effects":[]}));
    for param in [
        json!({"name":"x","type":"boolean"}),
        json!({"name":"X","type":"text"}),
        json!({"name":"x","type":"integer","max_len":4}),
        json!({"name":"x","type":"text","max_len":0}),
        json!({"name":"x","type":"text","max_len":1025}),
        json!({"name":"x","type":"text","required":1}),
        json!({"name":"x","type":"text","extra":0}),
    ] {
        let mut d = good.clone();
        d["needs"][1]["params"] = json!([param]);
        invalid.push(d);
    }
    for params in [
        json!([{"name":"x","type":"text"},{"name":"x","type":"integer"}]),
        json!("no"),
        json!(vec![json!({"name":"x","type":"text"}); 9]),
    ] {
        let mut d = good.clone();
        d["needs"][1]["params"] = params;
        invalid.push(d);
    }
    for (field, value) in [
        ("key", json!("a".repeat(41))),
        ("label", json!("é".repeat(121))),
        ("sql", json!("x".repeat(4097))),
        ("extra", json!(0)),
    ] {
        let mut d = good.clone();
        d["needs"][1][field] = value;
        invalid.push(d);
    }
    let mut bounded = good.clone();
    bounded["needs"][1]["label"] = json!("é".repeat(120));
    bounded["needs"][1]["sql"] = json!("x".repeat(4096));
    assert!(canonical_declaration(&bounded).is_ok());
    assert!(canonical_declaration(&json!({"needs":["é".repeat(64)],"effects":[]})).is_ok());
    invalid.push(json!({"needs":["é".repeat(65)],"effects":[]}));
    let effects = vec![json!("inert"); 64];
    assert!(canonical_declaration(&json!({"needs":[],"effects":effects})).is_ok());
    invalid.push(json!({"needs":[],"effects":vec![json!("inert");65]}));
    for key in [
        "attention.query.v1",
        "records.search.v1",
        "records.resolve_reference.v1",
        "canvas.scene.v1",
        "records.changes.v1",
        "Upper",
        "a-b",
    ] {
        invalid.push(json!({"needs":[sql(key)],"effects":[]}));
    }
    for d in invalid {
        assert!(canonical_declaration(&d).is_err(), "{d}");
    }
    let mut needs = vec![descriptor()];
    for i in 0..8 {
        needs.push(sql(&format!("k{i}")));
    }
    needs.extend(std::iter::repeat_n(json!("name"), 55));
    assert!(canonical_declaration(&json!({"needs":needs,"effects":[]})).is_ok());
    needs.push(json!("name"));
    assert!(canonical_declaration(&json!({"needs":needs,"effects":[]})).is_err());
    let nine: Vec<_> = (0..9).map(|i| sql(&format!("k{i}"))).collect();
    assert!(canonical_declaration(&json!({"needs":nine,"effects":[]})).is_err());
    // Legacy same-name SQL alone and a bare string never become descriptors.
    assert!(!has_body_descriptor(&json!({"needs":[sql(BODY_READ_NEED)],"effects":[]})).unwrap());
    assert!(!has_body_descriptor(&json!({"needs":[BODY_READ_NEED],"effects":[]})).unwrap());
}

#[test]
fn frozen_effect_exclusions_overlap_and_sql_target_linkage() {
    for key in [
        "lifecycle",
        "owner",
        "persistence",
        "maturity",
        "archived",
        "blob_ref",
        "runtime",
        "canvas.promoted_from",
        "retraction",
        "name",
        "body",
        "summary",
        "triage",
    ] {
        assert!(canonical_declaration(&json!({"needs":[sql("rows")],"effects":[{"effect":FACET_SET_EFFECT,"key":key,"values":["x"],"target":{"need":"rows"}}]})).is_err(),"{key}");
    }
    let react = json!({"effect":MESSAGE_REACT_EFFECT,"emoji":["👍"],"target":{"need":"rows"}});
    let comment = json!({"effect":COMMENT_CREATE_EFFECT,"positions":["root"],"max_body_bytes":1,"target":{"need":"rows"}});
    let title = json!({"effect":TITLE_SET_EFFECT,"target":{"need":"rows"}});
    let facet =
        json!({"effect":FACET_SET_EFFECT,"key":"priority","values":["x"],"target":{"need":"rows"}});
    for effect in [react, comment, title, facet] {
        assert!(canonical_declaration(
            &json!({"needs":[sql("rows")],"effects":[effect.clone(),effect.clone()]})
        )
        .is_err());
        let mut target = effect;
        target["target"]["need"] = json!(BODY_READ_NEED);
        assert!(canonical_declaration(
            &json!({"needs":[descriptor(),sql("rows")],"effects":[target]})
        )
        .is_err());
    }
    assert!(canonical_declaration(&json!({"needs":[sql(BODY_READ_NEED)],"effects":[{"effect":TITLE_SET_EFFECT,"target":{"need":BODY_READ_NEED}}]})).is_ok());
    for bad in [
        json!({"effect":MESSAGE_REACT_EFFECT,"emoji":["unknown"],"target":{"need":"rows"}}),
        json!({"effect":COMMENT_CREATE_EFFECT,"positions":["root","root"],"max_body_bytes":1,"target":{"need":"rows"}}),
        json!({"effect":FACET_SET_EFFECT,"key":"priority","values":["x","x"],"target":{"need":"rows"}}),
        json!({"effect":"unknown","target":{"need":"rows"}}),
    ] {
        assert!(canonical_declaration(&json!({"needs":[sql("rows")],"effects":[bad]})).is_err());
    }
    for bare in [
        FACET_SET_EFFECT,
        COMMENT_CREATE_EFFECT,
        MESSAGE_REACT_EFFECT,
        TITLE_SET_EFFECT,
    ] {
        assert!(canonical_declaration(&json!({"needs":[],"effects":[bare]})).is_err());
    }
    assert!(canonical_declaration(&json!({"needs":[sql("rows")],"effects":[{"effect":COMMENT_CREATE_EFFECT,"positions":["root"],"max_body_bytes":1.0,"target":{"need":"rows"}}]})).is_ok());
    for cap in [json!(0), json!(4097), json!(1.5), json!("1")] {
        assert!(canonical_declaration(&json!({"needs":[sql("rows")],"effects":[{"effect":COMMENT_CREATE_EFFECT,"positions":["root"],"max_body_bytes":cap,"target":{"need":"rows"}}]})).is_err());
    }
}

#[test]
fn frozen_sessions_preserve_absence_empty_duplicates_and_unbounded_count() {
    let session = json!({"session":"session.body.v1","key":"x","scope":{"type":"Document","kind":"*"},"mode":"view","presence":false});
    let absent = canonical_declaration(&json!({"needs":[],"effects":[]})).unwrap();
    let empty = canonical_declaration(&json!({"needs":[],"effects":[],"sessions":[]})).unwrap();
    assert!(absent.get("sessions").is_none());
    assert_ne!(absent, empty);
    let d = json!({"needs":[],"effects":[],"sessions":vec![session.clone();65]});
    assert_eq!(
        canonical_declaration(&d).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .len(),
        65
    );
    for field in ["extra", "presence", "mode", "scope"] {
        let mut bad = session.clone();
        bad[field] = json!(1);
        assert!(canonical_declaration(&json!({"needs":[],"effects":[],"sessions":[bad]})).is_err());
    }
}
