use super::*;

fn sample(f: &FieldShape) -> Value {
    match f.value_type.as_str() {
        "text" => match f.text_format.as_deref() {
            Some("uuid_v4v7") => json!("01234567-89ab-4def-0123-456789abcdef"),
            Some("record_locator") => json!("native:root"),
            Some("hex_colour") => json!("#Ab01fF"),
            Some("dotted_id") => json!("demo.item"),
            Some("versioned_token") => json!("demo/1"),
            Some("snake_field") => json!("demo_field"),
            _ => json!("x"),
        },
        "integer" => json!(1),
        "number" => json!(1.5),
        "boolean" => json!(true),
        "time" => json!("2026-10-18T12:00:00Z"),
        "date" => json!("2026-10-18"),
        "choice" => f.choices[0].clone(),
        "object" => Value::Object(
            f.fields
                .iter()
                .map(|f| (f.name.clone(), sample(f)))
                .collect(),
        ),
        "list" => json!([sample(f.items.as_ref().unwrap())]),
        _ => unreachable!(),
    }
}
// Mutate each nested member/item, retaining the rest of the valid witness.
fn mutations(f: &FieldShape, value: &Value) -> Vec<Value> {
    let mut out = vec![
        Value::Null,
        json!(false),
        json!(0),
        json!(1.0),
        json!(1.5),
        json!(i64::MIN),
        json!(u64::MAX),
        json!(1e100),
        json!(-1e100),
        json!(""),
        json!(" \t\n"),
        json!("\u{feff}"),
        json!("\u{0085}"),
        json!("not-a-choice"),
        json!({}),
        json!([]),
        json!("x".repeat(4097)),
        json!("é".repeat(2049)),
    ];
    if let Some(n) = f.max_length {
        for text in ["x", "é", "🦀"] {
            out.push(json!(text.repeat(n as usize)));
            out.push(json!(text.repeat(n as usize + 1)));
        }
    }
    if f.value_type == "object" {
        for child in &f.fields {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(&child.name);
            out.push(missing);
            for variant in mutations(child, &value[&child.name]) {
                let mut obj = value.clone();
                obj[&child.name] = variant;
                out.push(obj);
            }
        }
        for unknown in [Value::Null, json!(true)] {
            let mut obj = value.clone();
            obj["unknown"] = unknown;
            out.push(obj);
        }
    }
    if f.value_type == "list" {
        let item = f.items.as_ref().unwrap();
        for variant in mutations(item, &sample(item)) {
            out.push(json!([variant]));
        }
        for n in [
            f.max_items.unwrap() as usize,
            f.max_items.unwrap() as usize + 1,
        ] {
            out.push(json!(vec![sample(item); n]));
        }
        if item.value_type == "text" {
            out.push(json!(vec![
                json!("x".repeat(4096));
                f.max_items.unwrap() as usize
            ]));
        }
    }
    if matches!(f.value_type.as_str(), "time" | "date") {
        for s in [
            "2024-02-29",
            "2025-02-29",
            "2026-1-01",
            "2026-10-18 12:00:00+00:00",
            "2026-10-18T12:00:60Z",
            "not-time",
        ] {
            out.push(json!(s));
        }
    }
    if f.value_type == "text" {
        for s in [
            "#ffffff\n",
            "native:root\n",
            "demo/1\n",
            "demo.field\n",
            "name\n",
            "01234567-89ab-4def-0123-456789abcdef\n",
        ] {
            out.push(json!(s));
        }
    }
    out
}
fn contains_unrepresentable(fs: &[FieldShape], value: &Value) -> Option<&'static str> {
    for f in fs {
        let v = &value[&f.name];
        if v.is_null() {
            continue;
        }
        if f.value_type == "integer"
            && v.as_f64().is_some_and(|n| n.fract() == 0.0)
            && !crate::kernel::integer_spelling_matches(v)
        {
            return Some("integer_spelling");
        }
        if f.value_type == "time"
            && v.as_str()
                .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_err())
        {
            return Some("temporal_grammar");
        }
        if f.value_type == "date"
            && v.as_str()
                .is_some_and(|s| !crate::kernel::is_calendar_date_or_rfc3339(s))
        {
            return Some("temporal_grammar");
        }
        if f.value_type == "object" {
            if let Some(r) = contains_unrepresentable(&f.fields, v) {
                return Some(r);
            }
        }
        if let (Some(item), Some(items)) = (&f.items, v.as_array()) {
            for v in items {
                if let Some(r) = contains_unrepresentable(
                    std::slice::from_ref(item),
                    &json!({item.name.clone():v}),
                ) {
                    return Some(r);
                }
            }
        }
    }
    None
}
fn disagreement_rule(shape: &TypedShape, payload: &Value) -> &'static str {
    let budget = shape.structured()
        && crate::structured_values::validate_value_budget(payload.as_object().unwrap()).is_err();
    let rule = if budget {
        Some("value_budget")
    } else {
        contains_unrepresentable(&shape.fields, payload)
    }
    .unwrap_or_else(|| {
        panic!(
            "unexplained disagreement: {} {} {payload}",
            shape.pin.value_string(),
            shape.kind
        )
    });
    assert!(shape.non_expressible.iter().any(|n| n.rule == rule));
    rule
}
fn integer_definition_witness() -> String {
    json!({"family":"shape.integer","version":1,"interpreter":"native.defn/3",
        "primary_type":"Item","kinds":[{"token":"item","description":"Integer witness.",
        "maturity":"current","identity":{"mode":"record"},"fields":[
        {"name":"count","type":"integer","required":false}],"links":[]}]})
    .to_string()
}
#[test]
fn integer_spelling_exception_requires_integral_value() {
    let bytes = integer_definition_witness();
    let shape = TypedShape::from_bytes(&bytes, "item").unwrap();
    let schema = shape.create_schema(&["home".into()]);
    let precise = jsonschema::validator_for(&schema).unwrap();
    // Mutation witness: a broken emitter must not hide fractional values behind
    // integer_spelling, even though integral float/exponent spellings are excepted.
    let mut weakened = schema.clone();
    weakened["properties"]["fields"]["properties"]["count"] = json!({"type":"number"});
    let permissive = jsonschema::validator_for(&weakened).unwrap();
    for spelling in ["2.0", "2e0", "1.5", "-1.5"] {
        let number: Value = serde_json::from_str(spelling).unwrap();
        let payload = json!({"count":number});
        let input = json!({"home":"home","fields":payload});
        assert!(permissive.is_valid(&input));
        assert!(!crate::kernel::definition_shape_accepts(
            &bytes,
            "item",
            payload.as_object().unwrap()
        ));
        if number.as_f64().unwrap().fract() == 0.0 {
            assert!(precise.is_valid(&input));
            assert_eq!(disagreement_rule(&shape, &payload), "integer_spelling");
        } else {
            assert!(!precise.is_valid(&input));
            assert!(std::panic::catch_unwind(|| disagreement_rule(&shape, &payload)).is_err());
        }
    }
}
fn definition_corpus() -> Vec<String> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut fixtures = vec![];
    for dir in ["src/v2_standard", "docs/prototypes/slice2_trial"] {
        for entry in std::fs::read_dir(root.join(dir)).unwrap() {
            let path = entry.unwrap().path();
            if path.to_string_lossy().ends_with(".defn.json") {
                fixtures.push(std::fs::read_to_string(path).unwrap());
            }
        }
    }
    // Exercise all six language markers, structured nesting and every frozen format.
    for version in 1..=6 {
        let mut doc = json!({"family":"shape.proof","version":version,"interpreter":format!("native.defn/{version}"),"primary_type":"Proof","kinds":[{"token":"item","description":"Proof.","maturity":"current","identity":{"field":"code"},"fields":[{"name":"code","type":"text","required":true},{"name":"count","type":"integer","required":false},{"name":"when","type":"time","required":false}],"links":[]}]});
        if version == 1 {
            doc["kinds"] = json!(["item"]);
            doc.as_object_mut().unwrap().remove("interpreter");
        }
        if version >= 3 {
            doc["kinds"][0]["fields"]
                .as_array_mut()
                .unwrap()
                .push(json!({"name":"date","type":"date","required":false}));
        }
        if version >= 5 {
            doc["kinds"][0]["fields"].as_array_mut().unwrap().extend([
            json!({"name":"obj","type":"object","required":false,"fields":[{"name":"label","type":"text","required":true},{"name":"optional","type":"text","required":false}]}),
            json!({"name":"rows","type":"list","required":false,"max_items":3,"items":{"type":"object","fields":[{"name":"count","type":"integer","required":true}]}}),
            json!({"name":"texts","type":"list","required":false,"max_items":128,"items":{"type":"text"}}),
            json!({"name":"many","type":"list","required":false,"max_items":128,"items":{"type":"object","fields":(0..9).map(|n|json!({"name":format!("f{n}"),"type":"text","required":false})).collect::<Vec<_>>()}})
        ]);
        }
        if version == 6 {
            for fmt in crate::structured_values::text_formats::TEXT_FORMATS {
                doc["kinds"][0]["fields"].as_array_mut().unwrap().push(json!({"name":fmt.name,"type":"text","required":false,"text_format":fmt.name,"max_length":40}));
            }
        }
        if version == 3 {
            doc["kinds"][0]["refines"] = json!("base");
            doc["kinds"].as_array_mut().unwrap().push(json!({"token":"base","description":"Metadata base.","maturity":"current","identity":{"mode":"record"},"fields":[{"name":"inherited","type":"text","required":true}],"links":[]}));
        }
        fixtures.push(doc.to_string());
        if version == 2 {
            doc["kinds"][0]["fields"][0]["required"] = json!(false);
            fixtures.push(doc.to_string());
        }
    }
    fixtures.push(integer_definition_witness());
    // /1 accepts opaque metadata and arbitrary kind-array entries. These are
    // shared with discovery so future schema work cannot silently drop them.
    for links in [
        json!([false]),
        json!(false),
        json!([null, 0, "opaque", [], {}, {"target":false}, {"target":[]}]),
    ] {
        fixtures.push(
            json!({"family":"shape.opaque","version":1,"primary_type":"Item",
            "kinds":[false, 3, null, [], {}, {"token":false},
                {"token":"item","links":links,"fields":false,"identity":false}]})
            .to_string(),
        );
    }
    fixtures
}
fn kind_tokens(doc: &Value) -> Vec<&str> {
    doc["kinds"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|k| k.as_str().or_else(|| k["token"].as_str()))
        .filter(|token| !token.is_empty())
        .collect()
}
#[test]
fn differential_create_conformance() {
    let fixtures = definition_corpus();
    let mut count = 0;
    let mut exceptions = std::collections::BTreeMap::<String, usize>::new();
    for bytes in fixtures {
        let doc: Value = serde_json::from_str(&bytes).unwrap();
        for token in kind_tokens(&doc) {
            let shape = TypedShape::from_bytes(&bytes, token).unwrap();
            let schema = shape.create_schema(&["home".into()]);
            let validator = jsonschema::validator_for(&schema).unwrap();
            let base = Value::Object(
                shape
                    .fields
                    .iter()
                    .map(|f| (f.name.clone(), sample(f)))
                    .collect(),
            );
            let mut corpus = vec![base.clone(), json!({})];
            for unknown in [Value::Null, json!(true)] {
                let mut v = base.clone();
                v["unknown"] = unknown;
                corpus.push(v);
            }
            for f in &shape.fields {
                let mut missing = base.clone();
                missing.as_object_mut().unwrap().remove(&f.name);
                corpus.push(missing);
                for variant in mutations(f, &base[&f.name]) {
                    let mut v = base.clone();
                    v[&f.name] = variant;
                    corpus.push(v);
                }
            }
            for payload in corpus {
                count += 1;
                let kernel = crate::kernel::definition_shape_accepts(
                    &bytes,
                    token,
                    payload.as_object().unwrap(),
                );
                let schema = validator.is_valid(&json!({"home":"home","fields":payload}));
                if kernel == schema {
                    continue;
                }
                // Exceptions are one-way and require an independent, concrete witness.
                assert!(
                    schema && !kernel,
                    "schema tightened kernel semantics: {} {token} {payload}",
                    shape.pin.value_string()
                );
                let rule = disagreement_rule(&shape, &payload);
                *exceptions.entry(rule.into()).or_default() += 1;
            }
        }
    }
    eprintln!("Compared {count} payloads; explicit schema-only exceptions: {exceptions:?}");
    assert!(count > 1000);
}

#[tokio::test]
async fn typed_discovery_covers_the_entire_conformance_corpus() {
    use crate::{events::KERNEL_ROOT_ID as ROOT, kernel};
    let dir = tempfile::tempdir().unwrap();
    let fixtures = definition_corpus();
    for (index, bytes) in fixtures.iter().enumerate() {
        artifact::validate_kernel_definition_bytes(bytes).unwrap();
        let envelope = artifact::parse_artifact_envelope(bytes).unwrap();
        let (db, admin) = kernel::create_v2_database(
            dir.path()
                .join(format!("fixture-{index}.db"))
                .to_str()
                .unwrap(),
            "account",
            "Admin",
            "shape:admin",
        )
        .await
        .unwrap();
        // Keep reserved standard fixtures byte-identical. Namespace/package
        // admission is tested elsewhere; here the registry seeds the read view.
        let pin = crate::definition_registry::install_definition_artifact(
            &db,
            &envelope.family,
            envelope.version,
            bytes.as_bytes(),
        )
        .await
        .unwrap();
        kernel::adopt_definition_at(&db, &admin, &envelope.family, Some(&pin), ROOT)
            .await
            .unwrap();
        let tools = typed_tools_for(&db, &admin, None)
            .await
            .unwrap_or_else(|error| panic!("fixture {index} {}: {error}", pin.value_string()));
        let doc: Value = serde_json::from_str(bytes).unwrap();
        assert_eq!(tools.len(), kind_tokens(&doc).len() * 3, "fixture {index}");
        serde_json::to_value(&tools).unwrap();
        for tool in tools {
            jsonschema::validator_for(&tool.input_schema).unwrap();
        }
    }
    eprintln!("Typed discovery covered {} definitions", fixtures.len());
}
