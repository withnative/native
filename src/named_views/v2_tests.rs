use super::*;
use serde_json::Value;

#[cfg(not(feature = "v2-kernel-probe"))]
#[tokio::test]
async fn named_view_v2_nonprobe_live_profile_refuses_but_canonical_reader_accepts() {
    let mut conn = connection().await;
    let event = v2_revision_for("bearer", 1);
    ReplayChecker::default().apply(&event).unwrap();
    let mut live = storage::load_live(&mut conn, 0, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    let error = live
        .apply_new_on(&mut conn, &event, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "named view: view_profile_unsupported");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(&mut conn)
            .await
            .unwrap(),
        0
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn named_view_v2_authenticated_import_is_canonical_not_live_emission() {
    for global in [false, true] {
        let db = crate::kernel::create_kernel_database(":memory:")
            .await
            .unwrap();
        let revision = if global {
            global_revision_for("bearer", 1)
        } else {
            v2_revision_for("bearer", 1)
        };
        let active = v2_activation(2, &revision, None);
        for e in [&revision, &active] {
            gate::testing(
                false,
                crate::store::exercise_named_view_import(&db, e.clone()),
            )
            .await
            .unwrap();
        }
        let mut conn = db.pool().acquire().await.unwrap();
        let state = storage::load_prefix(&mut conn, i64::MAX, None)
            .await
            .unwrap();
        assert_eq!(state.bindings.len(), 1);
        assert!(state.revisions.contains_key(&revision.id));
        drop(conn);
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let mut bad = v2_activation(3, &revision, Some(active.id.clone()));
        let mut transition: Transition = decode(&bad, 2048).unwrap();
        if let Action::Activate { pin, .. } = &mut transition.action {
            pin.definition_sha256 = "f".repeat(64);
        }
        bad.payload = Some(serde_json::to_string(&transition).unwrap());
        let error = gate::testing(false, crate::store::exercise_named_view_import(&db, bad))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("revision pin mismatch"),
            "{error}"
        );
        let candidate = if global {
            global_revision_for("bearer", 4)
        } else {
            v2_revision_for("bearer", 4)
        };
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut acts = crate::act::ActAllocation::new();
        let error = gate::testing(
            true,
            crate::store::append_in(
                &db,
                &mut tx,
                crate::store::AppendSpec {
                    record_id: "bearer".into(),
                    event_type: REVISION.into(),
                    payload: serde_json::from_str(candidate.payload.as_ref().unwrap()).unwrap(),
                    actor: None,
                },
                &mut acts,
            ),
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("view_validation_changed"),
            "{error}"
        );
        tx.rollback().await.unwrap();
        assert_eq!(
            before,
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
    }
}

pub(in crate::named_views) fn v2_revision_for(record: &str, seq: i64) -> EventRow {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/facet-manifest-v1.json")).unwrap();
    let selector = String::from_utf8(native_artifact_runtime::mdx_v2::canonical_json_bytes(
        &json!({"context":manifest["context"],"selection":manifest["selection"]}),
    ))
    .unwrap();
    let mut definition = definition_fixture();
    definition["origin"] = json!({"kind":"generated","generator":"native.declared-relational-defaults","version":"facet-1","source_identity":"fixture-task","selector":selector});
    definition["generated"] = manifest;
    let mut revision = Revision {
        v: 2,
        view_id: format!("native.named-view:{record}"),
        definition_sha256: String::new(),
        definition,
    };
    revision.definition_sha256 = revision.digest();
    let mut e = event(seq, REVISION, serde_json::to_value(revision).unwrap());
    e.record_id = record.into();
    e
}
pub(in crate::named_views) fn global_revision_for(record: &str, seq: i64) -> EventRow {
    revise_v2(v2_revision_for(record, seq), |r| {
        let manifest: Value =
            serde_json::from_str(include_str!("fixtures/facet-manifest-global-v1.json")).unwrap();
        r.definition["origin"]["version"] = json!("facet-global-1");
        r.definition["origin"]["source_identity"] = manifest["context"]["logical_home_id"].clone();
        r.definition["origin"]["selector"] = json!(String::from_utf8(
            native_artifact_runtime::mdx_v2::canonical_json_bytes(
                &json!({"context":manifest["context"],"selection":manifest["selection"]})
            )
        )
        .unwrap());
        r.definition["generated"] = manifest;
    })
}

#[test]
fn named_view_global_closed_profile_pairs_and_structure() {
    let event = global_revision_for("global", 1);
    let r: Revision = decode(&event, MAX_CARRIER_BYTES).unwrap();
    r.validate_retained(&event).unwrap();
    assert_eq!(
        serde_json::to_value(
            serde_json::from_value::<v2::Definition<v2::GlobalManifest>>(r.definition.clone())
                .unwrap()
        )
        .unwrap(),
        r.definition
    );
    // STEP3b: the global pair is now an accepted closed profile; recognition
    // no longer refuses it. Structural validity is still enforced above.
    let old = v2_revision_for("global", 1);
    let old_rev: Revision = decode(&old, MAX_CARRIER_BYTES).unwrap();
    assert_ne!(old_rev.generated_name(), r.generated_name());
    let legacy: v2::Definition = serde_json::from_value(old_rev.definition.clone()).unwrap();
    assert_eq!(serde_json::to_value(legacy).unwrap(), old_rev.definition);
    for (pointer, value) in [
        ("/origin/version", json!("facet-1")),
        ("/origin/version", json!("facet-global-2")),
        ("/origin/source_identity", json!("other-home")),
        ("/generated/format", json!("native.generated-facets.v3")),
        ("/generated/context/declaration_scope", json!("home")),
        ("/generated/context/extra", json!(true)),
        (
            "/generated/slots/4/fragments",
            r.definition["generated"]["slots"][0]["fragments"].clone(),
        ),
        ("/generated/sources/0/anchor", json!("H")),
        ("/generated/slots/0/fragments/0/source", json!(99)),
        ("/generated/slots/0/fragments/0/decl", Value::Null),
        (
            "/generated/vocabularies/0/values/0/canonical_id",
            json!("missing"),
        ),
        (
            "/generated/governance_basis",
            json!([{"source":0,"shape_key":"WorkItem","lineage":null,"created_at":"2026-10-26T00:00:00Z"}]),
        ),
    ] {
        let bad = revise_v2(event.clone(), |r| {
            // Unknown-field insertion needs an object rather than pointer_mut.
            if pointer.ends_with("/extra") {
                r.definition["generated"]["context"]["extra"] = value;
            } else {
                *r.definition.pointer_mut(pointer).unwrap() = value;
            }
        });
        let bad_rev: Revision = decode(&bad, MAX_CARRIER_BYTES).unwrap();
        assert!(bad_rev.validate_retained(&bad).is_err(), "{pointer}");
    }
    let mismatch = revise_v2(old, |r| {
        r.definition["origin"]["version"] = json!("facet-global-1")
    });
    assert!(ReplayChecker::default().apply(&mismatch).is_err());
}

pub(super) fn v2_activation(seq: i64, r: &EventRow, expected: Option<String>) -> EventRow {
    let mut a = activation(seq, r, expected);
    a.record_id = r.record_id.clone();
    let mut t: Transition = decode(&a, 2048).unwrap();
    if let Action::Activate { name, .. } = &mut t.action {
        let revision: Revision = decode(r, MAX_CARRIER_BYTES).unwrap();
        *name = revision.generated_name().unwrap();
    }
    a.payload = Some(serde_json::to_string(&t).unwrap());
    a
}
fn revise_v2(mut event: EventRow, edit: impl FnOnce(&mut Revision)) -> EventRow {
    let mut revision: Revision = decode(&event, MAX_CARRIER_BYTES).unwrap();
    edit(&mut revision);
    revision.definition_sha256 = revision.digest();
    event.payload = Some(serde_json::to_string(&revision).unwrap());
    event
}

#[test]
fn named_view_v2_closed_roundtrip_digest_and_cross_references() {
    let e = v2_revision_for("bearer", 1);
    let r: Revision = decode(&e, MAX_CARRIER_BYTES).unwrap();
    r.validate_retained(&e).unwrap();
    let mut state = ReplayChecker::default();
    state.apply(&e).unwrap();
    let mut wrong_name = v2_activation(2, &e, None);
    let mut wire: serde_json::Value =
        serde_json::from_str(wrong_name.payload.as_ref().unwrap()).unwrap();
    wire["name"] = json!("view_gen_other");
    wrong_name.payload = Some(wire.to_string());
    assert!(state
        .apply(&wrong_name)
        .unwrap_err()
        .to_string()
        .contains("generated revision name mismatch"));
    assert!(
        serde_json::from_value::<contract::Definition>(r.definition.clone()).is_err(),
        "old v1 body decoder cannot certify this definition"
    );

    r.validate_retained(&e).unwrap(); // Current readers understand the closed body.
                                      // Older v1 decoders still refuse above; no rollback parity is implied.
    let mut bad_digest = r.clone();
    bad_digest.v = 1;
    assert_ne!(
        bad_digest.digest(),
        r.digest(),
        "payload version is in digest domain"
    );
    for (pointer, value) in [
        ("/generated/extra", json!("opaque")),
        ("/generated/format", json!("native.artifacts.v1")),
        ("/generated/sources/0/event_id", json!("not-an-event")),
        ("/generated/sources/0/event_sha256", json!("F".repeat(64))),
        ("/generated/sources/1/anchor", json!("another-home")),
        ("/generated/slots/0/fragments/0/source", json!(999)),
        (
            "/generated/slots/0/fragments/0/decl/vocab_ref",
            json!("rec:missing"),
        ),
        (
            "/generated/vocabularies/0/values/0/canonical_id",
            json!("missing"),
        ),
        (
            "/generated/vocabularies/0/values/0/status",
            json!("unknown"),
        ),
        ("/generated/governance_basis", json!([])),
        ("/origin/selector", json!("free text")),
        ("/origin/kind", json!("authored")),
        (
            "/source_pins",
            json!([{"record_id":"old","revision_id":uuid::Uuid::new_v4().to_string(),"sha256":"a".repeat(64)}]),
        ),
    ] {
        let changed = revise_v2(e.clone(), |r| {
            if pointer == "/generated/extra" {
                r.definition["generated"]["extra"] = value;
            } else {
                *r.definition.pointer_mut(pointer).unwrap() = value;
            }
        });
        assert!(
            ReplayChecker::default().apply(&changed).is_err(),
            "{pointer}"
        );
    }
    // Absence is an omitted fragment, never an explicit null overriding a
    // usable global declaration. Later non-null winners remain supported.
    let absent = e.clone();
    ReplayChecker::default().apply(&absent).unwrap();
    let later = revise_v2(e.clone(), |r| {
        let mut fragment = r.definition["generated"]["slots"][0]["fragments"][0].clone();
        fragment["source"] = json!(1);
        r.definition["generated"]["slots"][4]["fragments"] = json!([fragment]);
    });
    ReplayChecker::default().apply(&later).unwrap();
    let null_override = revise_v2(later, |r| {
        r.definition["generated"]["slots"][4]["fragments"][0]["decl"] = json!(null);
    });
    assert!(ReplayChecker::default().apply(&null_override).is_err());
    let missing = revise_v2(e.clone(), |r| {
        r.definition["generated"]["context"]
            .as_object_mut()
            .unwrap()
            .remove("kind");
    });
    assert!(ReplayChecker::default()
        .apply(&missing)
        .unwrap_err()
        .to_string()
        .contains("non-canonical"));
    let tampered = event(1, REVISION, {
        let mut v = serde_json::to_value(&r).unwrap();
        v["definition"]["description"] = json!("tampered");
        v
    });
    assert!(ReplayChecker::default().apply(&tampered).is_err());
}

#[test]
fn named_view_v2_category_and_carrier_bounds_allow_full_vocabulary_capacity() {
    let e = revise_v2(v2_revision_for("bearer", 1), |r| {
        let m = &mut r.definition["generated"];
        let mut sources = vec![m["sources"][0].clone(), m["sources"][1].clone()];
        // 28 schema sources plus 4 vocabularies, all referenced, and 256 value rows.
        for n in 2..28 {
            let mut s = sources[0].clone();
            s["source_id"] = json!(format!("[\"schema-{n}\"]"));
            s["row_id"] = json!(format!("schema-{n}"));
            sources.push(s);
        }
        let mut fragments = Vec::new();
        let mut vocabularies = Vec::new();
        let keys: Vec<String> = (0..4).map(|n| format!("key-{n}")).collect();
        for (n, key) in keys.iter().enumerate() {
            let mut source = m["sources"][2].clone();
            source["source_id"] = json!(format!("[\"vocab-{n}\"]"));
            source["row_id"] = json!(format!("vocab-{n}"));
            sources.push(source);
            let mut decl = m["slots"][0]["fragments"][0].clone();
            decl["key"] = json!(key);
            decl["decl"]["vocab_ref"] = json!(format!("rec:vocab-{n}"));
            fragments.push(decl);
            vocabularies.push(json!({"field":key,"source":28+n,"values":[]}));
        }
        let mut extra = Vec::new();
        for n in 2..28 {
            for fragment in &fragments {
                let mut explicit = fragment.clone();
                explicit["source"] = json!(n);
                extra.push(explicit);
            }
        }
        fragments.extend(extra);
        for (n, vocab) in vocabularies.iter_mut().enumerate() {
            for k in 0..64 {
                let id = format!("value-{n}-{k}");
                let mut source = m["sources"][3].clone();
                source["source_id"] = json!(format!("[\"{id}\"]"));
                source["row_id"] = json!(id);
                vocab["values"].as_array_mut().unwrap().push(json!({"source":sources.len(),"id":id,"token":id,"status":"active","alias_of":null,"canonical_id":id,"canonical_token":id}));
                sources.push(source);
            }
        }
        m["selection"] = json!({"kind":"keys","keys":keys});
        m["sources"] = json!(sources);
        m["slots"][0]["fragments"] = json!(fragments);
        m["vocabularies"] = json!(vocabularies);
        let selector = String::from_utf8(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &json!({"context":m["context"],"selection":m["selection"]}),
        ))
        .unwrap();
        r.definition["origin"]["selector"] = json!(selector);
    });
    assert!(e.payload.as_ref().unwrap().len() < MAX_CARRIER_BYTES);
    ReplayChecker::default().apply(&e).unwrap();
    for section in ["schema_config", "vocabulary_values"] {
        let exceeded = revise_v2(e.clone(), |r| {
            let mut s = r.definition["generated"]["sources"][0].clone();
            s["section"] = json!(section);
            s["source_id"] = json!("[\"overflow\"]");
            r.definition["generated"]["sources"]
                .as_array_mut()
                .unwrap()
                .push(s);
        });
        assert!(ReplayChecker::default().apply(&exceeded).is_err());
    }
    let mut over_vocab = v2_revision_for("bearer", 1);
    over_vocab = revise_v2(over_vocab, |r| {
        let v = r.definition["generated"]["vocabularies"][0]["values"][0].clone();
        r.definition["generated"]["vocabularies"][0]["values"] = json!(vec![v; 65]);
    });
    assert!(ReplayChecker::default().apply(&over_vocab).is_err());
    for (section, count) in [("schema_config", 31), ("vocabulary_values", 256)] {
        let exceeded = revise_v2(v2_revision_for("bearer", 1), |r| {
            for n in 0..count {
                let mut source = r.definition["generated"]["sources"][0].clone();
                source["section"] = json!(section);
                source["source_id"] = json!(format!("[\"extra-{n}\"]"));
                source["row_id"] = json!(format!("extra-{n}"));
                r.definition["generated"]["sources"]
                    .as_array_mut()
                    .unwrap()
                    .push(source);
            }
        });
        assert!(ReplayChecker::default()
            .apply(&exceeded)
            .unwrap_err()
            .to_string()
            .contains("source category bound"));
    }
    let huge = revise_v2(e.clone(), |r| {
        r.definition["generated"]["vocabularies"][0]["values"][0]["token"] =
            json!("x".repeat(MAX_CARRIER_BYTES));
    });
    assert!(ReplayChecker::default()
        .apply(&huge)
        .unwrap_err()
        .to_string()
        .contains("payload exceeds bound"));
}

#[tokio::test]
async fn named_view_v2_unconditional_mixed_prefix_tail_parser_and_projector() {
    let mut conn = connection().await;
    let old = revision(1);
    let r = v2_revision_for("generated", 2);
    let global = global_revision_for("global", 3);
    let global_active = v2_activation(4, &global, None);
    let mut events = vec![old, r.clone(), global, global_active];
    let mut last = None;
    for seq in 5..=142 {
        let a = v2_activation(seq, &r, last);
        last = Some(a.id.clone());
        events.push(a);
    }
    let mut full = ReplayChecker::default();
    for e in &events {
        insert(&mut conn, e).await;
        let intent = crate::domain_transaction::ProjectorIntent::from_event(e).unwrap();
        crate::projector::project_intent(&mut conn, e, &intent)
            .await
            .unwrap();
        full.apply(e).unwrap();
    }
    for indexed in [false, true] {
        if indexed {
            sqlx::query(INDEX_DDL).execute(&mut conn).await.unwrap();
        }
        for split in [1, 2, 128, 142] {
            let mut tail = load_prefix(&mut conn, split, None).await.unwrap();
            for e in events.iter().filter(|e| e.local_seq > split) {
                tail.apply(e).unwrap();
            }
            assert_eq!(full.revisions, tail.revisions);
            assert_eq!(full.bindings, tail.bindings);
            let live =
                storage::load_live(&mut conn, split, Instant::now() + Duration::from_secs(2))
                    .await
                    .unwrap();
            let canonical_prefix = load_prefix(&mut conn, split, None).await.unwrap();
            assert_eq!(
                live.bindings(),
                &canonical_prefix.bindings,
                "live reduction preserves canonical mixed-version namespace"
            );
        }
    }
    // The old header-only query can see these fields despite payload version 2.
    // Our loader additionally validates the version/body before certification.
    let old_header: (String,String,String) = sqlx::query_as("SELECT json_extract(payload,'$.definition_sha256'),json_extract(payload,'$.definition.query.output.schema_sha256'),json_extract(payload,'$.definition.origin.kind') FROM content_events WHERE id=?")
        .bind(&r.id).fetch_one(&mut conn).await.unwrap();
    assert_eq!(old_header.2, "generated");
    assert_eq!(old_header.1, schema_digest());
    for version in [
        json!(0),
        json!(3),
        json!(true),
        json!(1.5),
        serde_json::Value::Null,
    ] {
        let mut changed: serde_json::Value =
            serde_json::from_str(r.payload.as_ref().unwrap()).unwrap();
        changed["v"] = version.clone();
        sqlx::query("UPDATE content_events SET payload=? WHERE id=?")
            .bind(changed.to_string())
            .bind(&r.id)
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            load_prefix(&mut conn, 142, None).await.is_err(),
            "uncertified header version {version}"
        );
    }
    let changed = revise_v2(r.clone(), |r| {
        r.definition["generated"]["governance_basis"] = json!([])
    });
    sqlx::query("UPDATE content_events SET payload=? WHERE id=?")
        .bind(changed.payload)
        .bind(&r.id)
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(
        load_prefix(&mut conn, 142, None).await.is_err(),
        "v2 must pass structural validation before prefix certification"
    );
}

/// Models a future reader-first FULL/delta; deliberately bypasses every producer.
/// Only cfg(test) code can create these fixtures. Never opens the emission gate.
#[cfg(feature = "v2-kernel-probe")]
pub(in crate::named_views) async fn inject_v2_reader_fixture(db: &crate::Db, bearer: &str) -> Pin {
    inject_reader_fixture(db, bearer, false, false).await
}
#[cfg(feature = "v2-kernel-probe")]
pub(in crate::named_views) async fn inject_global_reader_fixture(
    db: &crate::Db,
    bearer: &str,
) -> Pin {
    inject_reader_fixture(db, bearer, true, false).await
}
#[cfg(feature = "v2-kernel-probe")]
pub(in crate::named_views) async fn inject_global_name_reader_fixture(
    db: &crate::Db,
    bearer: &str,
) -> Pin {
    inject_reader_fixture(db, bearer, true, true).await
}
#[cfg(feature = "v2-kernel-probe")]
async fn inject_reader_fixture(db: &crate::Db, bearer: &str, global: bool, name: bool) -> Pin {
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let r = if global {
        let base = global_revision_for(bearer, head + 1);
        if name {
            // Name-bound variant: bare `priority` retained against `voc:priority`.
            revise_v2(base, |r| {
                r.definition["generated"]["slots"][0]["fragments"][0]["decl"]["vocab_ref"] =
                    json!("priority");
                r.definition["generated"]["sources"][1]["row_id"] = json!("voc:priority");
                r.definition["generated"]["sources"][1]["source_id"] = json!("[\"voc:priority\"]");
            })
        } else {
            base
        }
    } else {
        assert!(!name, "name binding is global-profile only");
        v2_revision_for(bearer, head + 1)
    };
    let previous = load_prefix(&mut tx, head, None)
        .await
        .unwrap()
        .bindings
        .get(&format!("native.named-view:{bearer}"))
        .map(|b| b.event_id.clone());
    let a = v2_activation(head + 2, &r, previous);
    let act = crate::act::ActAllocation::new()
        .get_or_allocate(&mut tx)
        .await
        .unwrap();
    for e in [&r, &a] {
        sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown',?)")
            .bind(e.local_seq).bind(&e.id).bind(&e.record_id).bind(&e.event_type).bind(&e.payload).bind(&e.actor).bind(&e.created_at).bind(act).execute(&mut *tx).await.unwrap();
        crate::projector::project(&mut tx, e).await.unwrap();
    }
    tx.commit().await.unwrap();
    let t: Transition = decode(&a, 2048).unwrap();
    let Action::Activate { pin, .. } = t.action else {
        unreachable!()
    };
    pin
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn named_view_v2_untrusted_context_refuses_reads_and_appends_require_generated_preflight() {
    use crate::{kernel, mcp::kernel_v2, store};
    let (db, actor) = kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
        .await
        .unwrap();
    let home = kernel::create_home(
        &db,
        crate::events::KERNEL_ROOT_ID,
        Some(&[(&actor, "manage")]),
        &actor,
    )
    .await
    .unwrap();
    let bearer = kernel::create_record_as(&db, &actor, &home).await.unwrap();
    let pin = inject_v2_reader_fixture(&db, &bearer).await;
    let revision: Revision = decode(&v2_revision_for(&bearer, 1), MAX_CARRIER_BYTES).unwrap();
    let name = revision.generated_name().unwrap();
    let args = json!({"sql":"SELECT relation_name FROM catalog_relations ORDER BY relation_name"});
    let result = kernel_v2::sql::query_sql(&db, &actor, args).await.unwrap();
    assert!(result["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["relation_name"] == "records"));
    assert!(!result["rows"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["relation_name"] == name));
    assert!(
        result.get("notices").is_none(),
        "inaccessible fixture anchors must not disclose a retained view"
    );
    let visitor = kernel::create_principal(&db, "account", "Visitor", "acct:visitor", &actor)
        .await
        .unwrap();
    let hidden_catalog = kernel_v2::sql::query_sql(
        &db,
        &visitor,
        json!({"sql":"SELECT relation_name FROM catalog_relations"}),
    )
    .await
    .unwrap();
    assert!(
        hidden_catalog.get("notices").is_none(),
        "a hidden v2 root must not create a version-specific notice"
    );
    let hidden = kernel_v2::sql::query_sql(
        &db,
        &visitor,
        json!({"sql":format!("SELECT id FROM {name}")}),
    )
    .await
    .unwrap_err()
    .to_string();
    let missing = kernel_v2::sql::query_sql(
        &db,
        &visitor,
        json!({"sql":"SELECT id FROM view_nonexistent"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(hidden, missing);
    let error =
        kernel_v2::sql::query_sql(&db, &actor, json!({"sql":format!("SELECT id FROM {name}")}))
            .await
            .unwrap_err()
            .to_string();
    assert!(error.contains("view_missing"), "{error}");
    let (_, outer) = planned(
        "outer",
        &format!("SELECT id FROM {name}"),
        BTreeMap::from([(name, contract::Dependency::View(pin.clone()))]),
    );
    assert!(kernel_v2::query_pinned_saved_sql(&db, &actor, &outer.query)
        .await
        .unwrap_err()
        .to_string()
        .contains("view_missing"));
    let mut tx = db.pool().begin().await.unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let error = details::get_on(&mut tx, &actor, &pin.view_id, &pin.revision_id, deadline)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("view_missing"));
    let list = details::list_on(&mut tx, &actor, &pin.view_id, 8, None, deadline)
        .await
        .unwrap();
    assert_eq!(list["revisions"][0]["available"], false);
    assert_eq!(list["revisions"][0]["diagnostic"], "view_missing");
    assert!(list["revisions"][0].get("definition").is_none());
    tx.rollback().await.unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    gate::testing(true, async {
        let event = v2_revision_for(&bearer, 1);
        let spec = || store::AppendSpec {
            record_id: bearer.clone(),
            event_type: REVISION.into(),
            payload: serde_json::from_str(event.payload.as_ref().unwrap()).unwrap(),
            actor: Some(actor.clone()),
        };
        assert!(
            store::append(&db, spec()).await.is_err(),
            "public append never emits retained views"
        );
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut acts = crate::act::ActAllocation::new();
        let error = store::append_in(&db, &mut tx, spec(), &mut acts)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("view_validation_changed"), "{error}");
        assert!(store::append_migration_on(
            &mut tx,
            uuid::Uuid::new_v4().to_string(),
            spec(),
            "2026-10-26"
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("view_validation_changed"));
        let activation = v2_activation(
            1,
            &read_event(&mut tx, &pin.revision_id, i64::MAX)
                .await
                .unwrap(),
            None,
        );
        assert!(storage::admit_on(&mut tx, &activation)
            .await
            .unwrap_err()
            .to_string()
            .contains("view_validation_changed"));
        tx.rollback().await.unwrap();
    })
    .await;
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    kernel::replay_all_projections(&db).await.unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn named_view_global_reader_refuses_without_sealed_workspace() {
    use crate::{kernel, mcp::kernel_v2};
    let (db, actor) = kernel::create_v2_database(":memory:", "account", "Owner", "acct:owner")
        .await
        .unwrap();
    let bearer = kernel::create_record_as(&db, &actor, crate::events::KERNEL_ROOT_ID)
        .await
        .unwrap();
    let pin = inject_global_reader_fixture(&db, &bearer).await;
    let event = global_revision_for(&bearer, 1);
    let revision: Revision = decode(&event, MAX_CARRIER_BYTES).unwrap();
    let name = revision.generated_name().unwrap();
    // STEP3b opens the trusted global preparation path, but this fixture's
    // workspace differs from the host kernel identity, so trusted resolution
    // refuses rather than accepting caller-supplied evidence. Emission stays
    // gated at draft/activation below.
    let error = gate::testing(
        true,
        generated::prepare(
            &db,
            &actor,
            &bearer,
            &revision.definition,
            Instant::now() + Duration::from_secs(2),
        ),
    )
    .await
    .err()
    .unwrap();
    assert!(
        error.to_string().contains("view_source_changed")
            || error.to_string().contains("view_missing"),
        "{error}"
    );
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    for sql in [
        format!("SELECT id FROM {name}"),
        "SELECT relation_name FROM catalog_view_definitions".into(),
    ] {
        let result = kernel_v2::sql::query_sql(&db, &actor, json!({"sql":sql})).await;
        if sql.starts_with("SELECT id") {
            // STEP3a dispatches global format; fixture workspace mismatch
            // surfaces as view_missing, identical to facet-1 fixtures.
            assert!(result.unwrap_err().to_string().contains("view_missing"));
        } else {
            let result = result.unwrap();
            assert!(result["rows"].as_array().unwrap().is_empty());
            // STEP3a supports the format; workspace mismatch omits silently,
            // without a version-specific incomplete notice.
            assert!(!result["notices"]
                .to_string()
                .contains("view_revision_unavailable"));
        }
    }
    let mut conn = db.pool().begin().await.unwrap();
    let detail = super::super::details::get_on(
        &mut conn,
        &actor,
        &pin.view_id,
        &pin.revision_id,
        Instant::now() + Duration::from_secs(2),
    )
    .await;
    // Same workspace-mismatch refusal as facet-1, not a format fence.
    assert!(detail.unwrap_err().to_string().contains("view_missing"));
    conn.rollback().await.unwrap();
    let visitor = kernel::create_principal(&db, "account", "Visitor", "acct:visitor", &actor)
        .await
        .unwrap();
    // Root policy does not grant this visitor View on the bearer.
    let hidden = kernel_v2::sql::query_sql(
        &db,
        &visitor,
        json!({"sql":format!("SELECT id FROM {name}")}),
    )
    .await
    .unwrap_err()
    .to_string();
    let absent = kernel_v2::sql::query_sql(
        &db,
        &visitor,
        json!({"sql":"SELECT id FROM view_nonexistent"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(hidden, absent);
    let catalog = kernel_v2::sql::query_sql(
        &db,
        &visitor,
        json!({"sql":"SELECT relation_name FROM catalog_relations"}),
    )
    .await
    .unwrap();
    assert!(catalog.get("notices").is_none());
    // SavedSQL via pinned dependency refuses identically (workspace mismatch).
    let (_, outer) = crate::named_views::tests::planned(
        "outer",
        &format!("SELECT id FROM {name}"),
        BTreeMap::from([(name.clone(), contract::Dependency::View(pin.clone()))]),
    );
    assert!(kernel_v2::query_pinned_saved_sql(&db, &actor, &outer.query)
        .await
        .unwrap_err()
        .to_string()
        .contains("view_missing"));
    // Revision listing skips advisory scans; workspace mismatch is unavailable.
    let mut tx = db.pool().begin().await.unwrap();
    let list = super::super::details::list_on(
        &mut tx,
        &actor,
        &pin.view_id,
        8,
        None,
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(list["revisions"][0]["available"], false);
    assert_eq!(list["revisions"][0]["diagnostic"], "view_missing");
    assert!(list["revisions"][0].get("definition").is_none());
    tx.rollback().await.unwrap();
    // Producer gate OFF retains the same refused reads (no live import).
    gate::testing(
        false,
        kernel_v2::sql::query_sql(&db, &actor, json!({"sql":format!("SELECT id FROM {name}")})),
    )
    .await
    .unwrap_err();
    // Name-bound fixture refuses identically; frozen spelling is retained.
    let named_pin = inject_global_name_reader_fixture(&db, &bearer).await;
    let named_event = global_revision_for(&bearer, 1);
    let named_revision: Revision = decode(&named_event, MAX_CARRIER_BYTES).unwrap();
    let named_name = named_revision.generated_name().unwrap();
    assert_eq!(named_name, name);
    // Load the injected name-bound revision (bare `priority` retained).
    let named_payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
        .bind(&named_pin.revision_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    let named_stored: Revision = serde_json::from_str(&named_payload).unwrap();
    let named_def: v2::Definition<v2::GlobalManifest> =
        serde_json::from_value(named_stored.definition.clone()).unwrap();
    let named_decl = named_def
        .generated
        .slots
        .iter()
        .flat_map(|s| &s.fragments)
        .find(|f| f.key == "priority")
        .unwrap()
        .decl
        .clone();
    assert_eq!(named_decl.vocab_ref.as_deref(), Some("priority"));
    let named_vocab_source =
        &named_def.generated.sources[named_def.generated.vocabularies[0].source];
    assert_eq!(named_vocab_source.row_id, "voc:priority");
    let named_err = kernel_v2::sql::query_sql(
        &db,
        &actor,
        json!({"sql":format!("SELECT id FROM {named_name}")}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(named_err.contains("view_missing"), "{named_err}");
    let _ = named_pin;
    // Principal creation above is an intentional fixture effect, so compare
    // immediately around public append instead of including that setup.
    let after_setup: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(after_setup >= before);
    let rejected = crate::store::append(
        &db,
        crate::store::AppendSpec {
            record_id: bearer,
            event_type: REVISION.into(),
            payload: serde_json::from_str(event.payload.as_ref().unwrap()).unwrap(),
            actor: None,
        },
    )
    .await;
    assert!(rejected.is_err());
    assert_eq!(
        after_setup,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap()
    );
}

#[test]
fn named_view_global_canonical_name_spelling_accepts_and_refuses() {
    let set_global = |event: EventRow, vocab: Value, vocab_ref: Value, source_row: &str| {
        revise_v2(event, |r| {
            r.definition["generated"]["slots"][0]["fragments"][0]["decl"]["vocab"] = vocab;
            r.definition["generated"]["slots"][0]["fragments"][0]["decl"]["vocab_ref"] = vocab_ref;
            r.definition["generated"]["sources"][1]["row_id"] = json!(source_row);
            r.definition["generated"]["sources"][1]["source_id"] =
                json!(format!("[\"{source_row}\"]"));
        })
    };
    let base = global_revision_for("bearer", 1);
    ReplayChecker::default().apply(&base).unwrap();
    for (vocab, vocab_ref, source_row) in [
        (json!(null), json!("priority"), "priority"),
        (json!("priority"), json!(null), "priority"),
        (json!("priority"), json!("priority"), "priority"),
    ] {
        let e = set_global(base.clone(), vocab, vocab_ref, source_row);
        assert!(ReplayChecker::default().apply(&e).is_ok(), "{source_row}");
    }
    for (vocab, vocab_ref, source_row) in [
        (json!(null), json!("priority"), "voc:priority"),
        (json!("priority"), json!(null), "voc:priority"),
        (json!("priority"), json!("priority"), "voc:priority"),
        (json!(null), json!("voc:priority"), "voc:priority"),
        (json!(null), json!("rec:voc:priority"), "voc:priority"),
        (json!(null), json!("area"), "voc:area"),
        (json!(null), json!("team:area"), "voc:team:area"),
        (json!(null), json!("rec:custom-id"), "custom-id"),
    ] {
        let e = set_global(base.clone(), vocab, vocab_ref, source_row);
        assert!(ReplayChecker::default().apply(&e).is_ok(), "{source_row}");
    }
    for (vocab, vocab_ref, source_row) in [
        (json!(null), json!("rec:priority"), "voc:priority"),
        (json!(null), json!("rec:area"), "voc:area"),
        (json!(null), json!("rec:team:area"), "voc:team:area"),
        (json!(null), json!("unknown"), "priority"),
        (json!(null), json!("unknown"), "voc:priority"),
        (json!(null), json!("custom-name"), "custom-id"),
        (json!("priority"), json!("rec:other"), "priority"),
        (json!("priority"), json!("rec:other"), "voc:priority"),
    ] {
        let e = set_global(base.clone(), vocab, vocab_ref, source_row);
        let error = ReplayChecker::default().apply(&e).unwrap_err();
        assert!(error.to_string().contains("v2 "), "{error}");
    }
}

#[test]
fn named_view_facet1_rejects_canonical_name_parity() {
    let set_facet1 = |event: EventRow, vocab_ref: Value, source_row: &str| {
        revise_v2(event, |r| {
            r.definition["generated"]["slots"][0]["fragments"][0]["decl"]["vocab_ref"] = vocab_ref;
            r.definition["generated"]["sources"][2]["row_id"] = json!(source_row);
            r.definition["generated"]["sources"][2]["source_id"] =
                json!(format!("[\"{source_row}\"]"));
        })
    };
    let base = v2_revision_for("bearer", 1);
    ReplayChecker::default().apply(&base).unwrap();
    let bare = set_facet1(base.clone(), json!("priority"), "priority");
    ReplayChecker::default().apply(&bare).unwrap();
    let rec_id = set_facet1(base.clone(), json!("rec:priority"), "priority");
    ReplayChecker::default().apply(&rec_id).unwrap();
    for vocab_ref in [json!("priority"), json!("area"), json!("team:area")] {
        let source_row = if vocab_ref == json!("priority") {
            "voc:priority"
        } else if vocab_ref == json!("area") {
            "voc:area"
        } else {
            "voc:team:area"
        };
        let e = set_facet1(base.clone(), vocab_ref, source_row);
        let error = ReplayChecker::default().apply(&e).unwrap_err();
        assert!(error.to_string().contains("v2 vocabulary"), "{error}");
    }
    let rec_name = set_facet1(base.clone(), json!("rec:priority"), "voc:priority");
    assert!(ReplayChecker::default().apply(&rec_name).is_err());
    let rec_colon = set_facet1(base.clone(), json!("rec:team:area"), "voc:team:area");
    assert!(ReplayChecker::default().apply(&rec_colon).is_err());
}
