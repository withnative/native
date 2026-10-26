use super::*;
use std::time::Duration;

fn row(id: &str, layer: &str, home: Option<&str>, data: Value) -> SchemaConfigRow {
    SchemaConfigRow {
        id: id.into(),
        layer: layer.into(),
        name: None,
        data,
        applies_to_collection_id: home.map(str::to_owned),
        version_lineage: Some("fixture-source-revision".into()),
        created_at: "2026-10-26T00:00:00Z".into(),
    }
}
fn schema() -> Vec<SchemaConfigRow> {
    vec![
        row(
            "base",
            "pack",
            None,
            json!({"shapes":{"WorkItem":{"facets":{"area":{"description":"Area"},"effort":{"type":"number"},"due":{"type":"date"}}}}}),
        ),
        row(
            "local",
            "user",
            Some("H"),
            json!({"shapes":{"WorkItem:task":{"facets":{"priority":{"vocab_ref":"rec:priority"}}}}}),
        ),
    ]
}
fn vocabulary() -> Vec<Vocabulary> {
    vec![Vocabulary {
        id: "priority".into(),
        reference: "rec:priority".into(),
        evidence: json!({"revision":"fixture-v1"}),
        required_anchors: vec!["vocab-anchor".into()],
        values: vec![
            VocabularyValue {
                id: "p1".into(),
                value: "high".into(),
                status: "active".into(),
                alias_of: None,
            },
            VocabularyValue {
                id: "p2".into(),
                value: "urgent".into(),
                status: "active".into(),
                alias_of: Some("p1".into()),
            },
            VocabularyValue {
                id: "p3".into(),
                value: "low".into(),
                status: "deprecated".into(),
                alias_of: None,
            },
            VocabularyValue {
                id: "p4".into(),
                value: "maybe".into(),
                status: "proposed".into(),
                alias_of: None,
            },
        ],
    }]
}
fn input<'a>(rows: &'a [SchemaConfigRow], vocabs: &'a [Vocabulary], keys: &[&str]) -> Input<'a> {
    Input {
        workspace: "workspace",
        bearer: "bearer",
        source_identity: "hq-tasks",
        record_type: "WorkItem",
        kind: Some("task"),
        home: "H",
        selection: Selection::Keys(keys.iter().map(|s| s.to_string()).collect()),
        schema: rows,
        vocabularies: vocabs,
    }
}
fn run(input: Input<'_>) -> Result<Proposal> {
    compile(input, Instant::now() + Duration::from_secs(2))
}
fn database() -> rusqlite::Connection {
    let db = rusqlite::Connection::open_in_memory().unwrap();
    db.execute_batch("CREATE TABLE records(id TEXT PRIMARY KEY,name TEXT,type TEXT,kind TEXT,home_id TEXT,archived INTEGER,lifecycle TEXT,is_current INTEGER);
        CREATE TABLE facet_values(record_id TEXT,key TEXT,value TEXT,value_num REAL,vocab_ref TEXT,UNIQUE(record_id,key));
        CREATE TABLE facet_times(record_id TEXT,key TEXT,kind TEXT,all_day INTEGER,start_date TEXT,UNIQUE(record_id,key));
        INSERT INTO records VALUES('one','One','WorkItem','task','H',0,NULL,1),('sparse','Sparse','WorkItem','task','H',1,NULL,NULL),('other','Other','WorkItem','task','J',0,NULL,1),('grandchild','Grandchild','WorkItem','task','nested',0,NULL,1);") .unwrap();
    db
}
fn cells(
    db: &rusqlite::Connection,
    proposal: &Proposal,
    id: &str,
    names: &[&str],
) -> Vec<rusqlite::types::Value> {
    let sql = format!(
        "SELECT {} FROM ({}) WHERE id = ?1",
        names
            .iter()
            .map(|n| quoted(n))
            .collect::<Vec<_>>()
            .join(","),
        proposal.sql
    );
    db.query_row(&sql, [id], |row| {
        names.iter().enumerate().map(|(i, _)| row.get(i)).collect()
    })
    .unwrap()
}
fn text(s: &str) -> rusqlite::types::Value {
    rusqlite::types::Value::Text(s.into())
}

#[test]
fn facet_compiler_text_sql_golden_and_portable_contract() {
    let proposal = run(input(&schema(), &[], &["area"])).unwrap();
    assert_eq!(
        proposal.sql.trim(),
        include_str!("fixtures/area.sql").trim()
    );
    assert_eq!(
        proposal.manifest,
        serde_json::from_str::<Value>(include_str!("fixtures/area.manifest.json")).unwrap()
    );
    assert_eq!(
        proposal.columns["area"]["meaning"],
        "Area; raw stored text; original JSON type unspecified"
    );
    assert_eq!(
        proposal.manifest["declarations"],
        json!({"area":{"description":"Area"}})
    );
    assert_eq!(
        proposal.manifest["context_evidence"],
        json!([{"id":"base","layer":"pack","home":null,"lineage":"fixture-source-revision","created_at":"2026-10-26T00:00:00Z","shape_key":"WorkItem","selected":{"area":{"description":"Area"}}}])
    );
    super::super::sql::validate(&proposal.sql).unwrap();
    let mut columns: Vec<_> = proposal.columns.keys().cloned().collect();
    columns.sort();
    let mut output: Vec<_> = proposal.output["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["name"].as_str().unwrap().to_string())
        .collect();
    output.sort();
    assert_eq!(columns, output);
    assert_eq!(proposal.output["row_identity"], json!(["id"]));
    assert_eq!(
        proposal.output["schema_sha256"],
        digest(&proposal.output["columns"])
    );
    assert_eq!(proposal.manifest_sha256, digest(&proposal.manifest));
    assert_eq!(
        proposal.relations.keys().collect::<Vec<_>>(),
        vec!["facet_values", "records"]
    );
}
#[test]
fn facet_compiler_deterministic_rows_maps_and_frozen_vocabulary() {
    let mut rows = schema();
    let mut vocabs = vocabulary();
    let p = run(input(&rows, &vocabs, &["priority", "area"])).unwrap();
    rows.reverse();
    vocabs[0].values.reverse();
    let q = run(input(&rows, &vocabs, &["area", "priority"])).unwrap();
    assert_eq!(
        serde_json::to_value(&p).unwrap(),
        serde_json::to_value(q).unwrap()
    );
    assert!(!p.sql.contains("vocabulary_values"));
    super::super::sql::validate(&p.sql).unwrap();
    let db = database();
    db.execute(
        "INSERT INTO facet_values VALUES('one','priority','future',NULL,NULL)",
        [],
    )
    .unwrap();
    assert_eq!(
        cells(
            &db,
            &p,
            "one",
            &["priority", "priority__raw", "priority__status"]
        ),
        vec![
            rusqlite::types::Value::Null,
            text("future"),
            text("invalid")
        ]
    );
    vocabs[0].values.push(VocabularyValue {
        id: "p5".into(),
        value: "future".into(),
        status: "active".into(),
        alias_of: None,
    });
    let new = run(input(&rows, &vocabs, &["area", "priority"])).unwrap();
    assert_eq!(p.name, new.name);
    assert_ne!(p.manifest_sha256, new.manifest_sha256);
    assert_eq!(cells(&db, &new, "one", &["priority"]), vec![text("future")]);
    assert_eq!(
        cells(&db, &p, "one", &["priority__status"]),
        vec![text("invalid")]
    );
}
#[test]
fn facet_compiler_selected_absence_overrides_and_all_fields() {
    let mut rows = schema();
    let p = run(input(&rows, &[], &["area"])).unwrap();
    rows[0].data["shapes"]["WorkItem"]["facets"]["unrelated"] = json!({});
    assert_eq!(
        p.manifest_sha256,
        run(input(&rows, &[], &["area"])).unwrap().manifest_sha256
    );
    let vocabs = vocabulary();
    let mut all = input(&rows, &vocabs, &[]);
    all.selection = Selection::All;
    let all = run(all).unwrap();
    assert!(all.manifest["declarations"].get("unrelated").is_some());
    rows.push(row(
        "override",
        "user",
        Some("H"),
        json!({"shapes":{"WorkItem:task":{"facets":{"area":{"type":"number"}}}}}),
    ));
    let q = run(input(&rows, &[], &["area"])).unwrap();
    assert_eq!(p.name, q.name);
    assert_ne!(p.manifest_sha256, q.manifest_sha256);
    assert_eq!(
        p.manifest["declarations"]["area"],
        json!({"description":"Area"})
    );
    assert_eq!(q.manifest["declarations"]["area"], json!({"type":"number"}));
    assert_eq!(
        run(input(&rows, &[], &["absent"])).unwrap_err(),
        CompileError::MissingDeclaration("absent".into())
    );
}
#[test]
fn facet_compiler_eight_slot_precedence_and_direct_home_membership() {
    let mut rows = Vec::new();
    for (home, layer, key) in [
        (None, "pack", "WorkItem"),
        (None, "user", "WorkItem"),
        (None, "pack", "WorkItem:task"),
        (None, "user", "WorkItem:task"),
        (Some("H"), "pack", "WorkItem"),
        (Some("H"), "user", "WorkItem"),
        (Some("H"), "pack", "WorkItem:task"),
        (Some("H"), "user", "WorkItem:task"),
    ] {
        let id = format!("slot{}", rows.len());
        rows.push(row(
            &id,
            layer,
            home,
            json!({"shapes":{(key):{"facets":{"area":{"description":id}}}}}),
        ));
    }
    let p = run(input(&rows, &[], &["area"])).unwrap();
    assert_eq!(
        p.manifest["declarations"]["area"],
        json!({"description":"slot7"})
    );
    let db = database();
    let count: i64 = db
        .query_row(&format!("SELECT count(*) FROM ({})", p.sql), [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 2);
    assert_eq!(
        cells(&db, &p, "sparse", &["archived", "is_current"]),
        vec![
            rusqlite::types::Value::Integer(1),
            rusqlite::types::Value::Null
        ]
    );
    assert!(run(input(&[], &[], &["area"])).is_err());
    let mut i = input(&rows, &[], &["area"]);
    i.home = "J";
    assert!(run(i).is_err());
}
#[test]
fn facet_compiler_number_date_sparse_and_ambiguous_raw_cells() {
    let p = run(input(&schema(), &[], &["area", "due", "effort"])).unwrap();
    super::super::sql::validate(&p.sql).unwrap();
    let db = database();
    db.execute_batch("INSERT INTO facet_values VALUES('one','area','',NULL,NULL),('one','effort','0',0,NULL),('one','due','2026-10-26',NULL,NULL); INSERT INTO facet_times VALUES('one','due','date',1,'2026-10-26');").unwrap();
    assert_eq!(
        cells(
            &db,
            &p,
            "one",
            &["area", "area__status", "effort", "effort__status", "due"]
        ),
        vec![
            text(""),
            text("valid"),
            rusqlite::types::Value::Real(0.0),
            text("valid"),
            text("2026-10-26")
        ]
    );
    assert_eq!(
        cells(
            &db,
            &p,
            "sparse",
            &["effort", "effort__raw", "effort__status", "due__status"]
        ),
        vec![
            rusqlite::types::Value::Null,
            rusqlite::types::Value::Null,
            text("missing"),
            text("missing")
        ]
    );
    db.execute_batch("UPDATE facet_values SET value='12junk',value_num=NULL WHERE key='effort'; DELETE FROM facet_times;").unwrap();
    assert_eq!(
        cells(
            &db,
            &p,
            "one",
            &[
                "effort",
                "effort__raw",
                "effort__status",
                "due",
                "due__raw",
                "due__status"
            ]
        ),
        vec![
            rusqlite::types::Value::Null,
            text("12junk"),
            text("unclassified"),
            rusqlite::types::Value::Null,
            text("2026-10-26"),
            text("unclassified")
        ]
    );
    assert!(!p.sql.contains("CAST("));
    assert!(!p.sql.contains("date("));
}
#[test]
fn facet_compiler_vocabulary_alias_status_and_reference_conflicts() {
    let p = run(input(&schema(), &vocabulary(), &["priority"])).unwrap();
    let db = database();
    for (value, reference, want, status) in [
        ("urgent", None, Some("high"), "valid"),
        ("low", Some("priority"), Some("low"), "valid"),
        ("high", Some("rec:other"), None, "invalid"),
        ("maybe", None, None, "invalid"),
        ("unknown", None, None, "invalid"),
    ] {
        db.execute(
            "INSERT OR REPLACE INTO facet_values VALUES('one','priority',?1,NULL,?2)",
            rusqlite::params![value, reference],
        )
        .unwrap();
        assert_eq!(
            cells(
                &db,
                &p,
                "one",
                &["priority", "priority__raw", "priority__status"]
            ),
            vec![
                want.map_or(rusqlite::types::Value::Null, text),
                text(value),
                text(status)
            ]
        );
    }
}
#[test]
fn facet_compiler_refuses_unsupported_malformed_and_ambiguous_inputs() {
    for shape in [
        json!({"type":"object"}),
        json!({"type":"instant"}),
        json!({"type":true}),
        json!({"values":["a"]}),
        json!({"type":"number","vocab":"priority"}),
        json!({"required":"yes"}),
    ] {
        let mut rows = schema();
        rows[0].data["shapes"]["WorkItem"]["facets"]["area"] = shape;
        assert!(run(input(&rows, &[], &["area"])).is_err());
    }
    let mut vocabs = vocabulary();
    vocabs[0].values[1].alias_of = Some("missing".into());
    assert!(run(input(&schema(), &vocabs, &["priority"])).is_err());
    let mut vocabs = vocabulary();
    vocabs[0].values[0].alias_of = Some("p2".into());
    assert!(run(input(&schema(), &vocabs, &["priority"])).is_err());
    let mut vocabs = vocabulary();
    vocabs[0].values[0].value = "urgent".into();
    assert!(run(input(&schema(), &vocabs, &["priority"])).is_err());
    let mut rows = schema();
    rows.push(rows[0].clone());
    assert!(run(input(&rows, &[], &["area"])).is_err());
    assert!(run(input(&schema(), &[], &["priority"])).is_err());
    assert!(run(input(&schema(), &[], &["lifecycle"])).is_err());
}
#[test]
fn facet_compiler_labels_and_literals_cannot_escape_sources() {
    let key = "quo'te\"; DROP TABLE records;--";
    let mut rows = schema();
    rows[0].data["shapes"]["WorkItem"]["facets"][key] = json!({});
    rows[1].applies_to_collection_id = Some("H' OR 1=1--".into());
    let mut i = input(&rows, &[], &[key]);
    i.home = "H' OR 1=1--";
    let p = run(i).unwrap();
    super::super::sql::validate(&p.sql).unwrap();
    let db = database();
    assert_eq!(
        db.query_row(&format!("SELECT count(*) FROM ({})", p.sql), [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM records", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        4
    );
    let mut rows = schema();
    rows[0].data["shapes"]["WorkItem"]["facets"]["area__raw"] = json!({});
    assert_eq!(
        run(input(&rows, &[], &["area", "area__raw"])).unwrap_err(),
        CompileError::Invalid("output label collision")
    );
    rows[0].data["shapes"]["WorkItem"]["facets"]["id"] = json!({});
    assert!(run(input(&rows, &[], &["id"])).is_err());
}
#[test]
fn facet_compiler_budgets_deadline_and_structure_are_bounded() {
    let mut vocab = vocabulary();
    vocab[0].values = (0..64)
        .map(|n| VocabularyValue {
            id: format!("p{n}"),
            value: format!("{n:03}{}", "x".repeat(509)),
            status: "active".into(),
            alias_of: None,
        })
        .collect();
    assert_eq!(
        run(input(&schema(), &vocab, &["priority"])).unwrap_err(),
        CompileError::Budget("SQL bytes")
    );
    let mut nul_rows = schema();
    nul_rows[0].data["shapes"]["WorkItem"]["facets"]["area"]["description"] = json!("bad\0text");
    assert_eq!(
        run(input(&nul_rows, &[], &["area"])).unwrap_err(),
        CompileError::Invalid("NUL in source")
    );
    assert_eq!(
        compile(input(&schema(), &[], &["area"]), Instant::now()).unwrap_err(),
        CompileError::Deadline
    );
    let rows = (0..129)
        .map(|i| row(&format!("r{i}"), "pack", None, json!({})))
        .collect::<Vec<_>>();
    assert_eq!(
        run(input(&rows, &[], &["area"])).unwrap_err(),
        CompileError::Budget("input rows")
    );
    let mut rows = schema();
    rows[0].data["huge"] = json!("x".repeat(INPUT_BYTES));
    assert_eq!(
        run(input(&rows, &[], &["area"])).unwrap_err(),
        CompileError::Budget("bytes")
    );
    let mut nested = json!(0);
    for _ in 0..18 {
        nested = json!([nested]);
    }
    let mut rows = schema();
    rows[0].data["deep"] = nested;
    assert_eq!(
        run(input(&rows, &[], &["area"])).unwrap_err(),
        CompileError::Budget("input structure")
    );
    let mut rows = schema();
    let keys = (0..19).map(|n| format!("f{n}")).collect::<Vec<_>>();
    for key in &keys {
        rows[0].data["shapes"]["WorkItem"]["facets"][key] = json!({});
    }
    let names = keys.iter().map(String::as_str).collect::<Vec<_>>();
    assert_eq!(
        run(input(&rows, &[], &names)).unwrap_err(),
        CompileError::Budget("selected columns")
    );
}

#[test]
fn facet_compiler_metadata_distinguishes_usable_raw_and_status_carriers() {
    let mut rows = schema();
    rows[0].data["shapes"]["WorkItem"]["facets"]["effort"]["unit"] = json!("hours");
    let p = run(input(&rows, &vocabulary(), &["effort", "priority"])).unwrap();
    assert_eq!(p.columns["effort"]["unit"], "hours");
    assert_eq!(p.columns["effort__raw"]["unit"], Value::Null);
    assert!(p.columns["effort"]["encoding"]
        .as_str()
        .unwrap()
        .contains("binary64"));
    assert_eq!(
        p.columns["effort__raw"]["encoding"],
        "stored UTF-8 text; original JSON carrier unspecified"
    );
    assert_eq!(p.columns["priority"]["vocabulary"], "rec:priority");
    assert_eq!(p.columns["priority__raw"]["vocabulary"], Value::Null);
    assert_eq!(
        p.columns["priority__status"]["encoding"],
        "read-status/v1: missing, valid, invalid, unclassified"
    );
    assert!(p.columns["effort"]["source_mapping"]
        .as_str()
        .unwrap()
        .contains("value_num"));
}

#[test]
fn facet_compiler_missing_facets_map_is_empty_but_present_nonobject_refuses() {
    let mut rows = schema();
    rows.push(row(
        "metadata",
        "user",
        None,
        json!({"shapes":{"WorkItem:task":{"description":"Only metadata"}}}),
    ));
    let p = run(input(&rows, &[], &["area"])).unwrap();
    assert_eq!(
        p.manifest["declarations"]["area"],
        json!({"description":"Area"})
    );
    for invalid in [Value::Null, json!(false), json!([]), json!("facets")] {
        rows.last_mut().unwrap().data["shapes"]["WorkItem:task"]["facets"] = invalid;
        assert_eq!(
            run(input(&rows, &[], &["area"])).unwrap_err(),
            CompileError::Invalid("facet map")
        );
    }
}

#[test]
fn facet_compiler_retains_governance_even_when_selected_keys_are_inherited() {
    let mut rows = schema();
    rows[1].data = json!({"shapes":{"WorkItem:task":{"description":"Governs direct members"}}});
    let p = run(input(&rows, &[], &["area"])).unwrap();
    let basis = &p.manifest["governance_basis"];
    assert_eq!(basis.as_array().unwrap().len(), 1);
    assert_eq!(
        basis[0],
        json!({"id":"local","layer":"user","home":"H",
        "lineage":"fixture-source-revision","created_at":"2026-10-26T00:00:00Z",
        "shape_key":"WorkItem:task","context":{"type":"WorkItem","kind":"task","logical_home":"H"}})
    );
    assert!(p.manifest["context_evidence"]
        .as_array()
        .unwrap()
        .iter()
        .all(|v| v["id"] != "local"));
    rows.reverse();
    assert_eq!(
        p.manifest_sha256,
        run(input(&rows, &[], &["area"])).unwrap().manifest_sha256
    );
    rows.retain(|r| r.id != "local");
    assert_eq!(
        run(input(&rows, &[], &["area"])).unwrap_err(),
        CompileError::Invalid("home has no governing declaration")
    );
    assert_eq!(p.manifest["governance_basis"][0]["id"], "local");
}
