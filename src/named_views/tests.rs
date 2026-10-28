use super::*;
use serde_json::json;
use sqlx::Connection;

fn schema_digest() -> String {
    format!(
        "{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &json!([{"name":"id","type":"identifier","nullable":false}])
        ))
    )
}
pub(super) fn definition_fixture() -> serde_json::Value {
    use native_query_contract::sql_contract as q;
    let profile = q::QuerySqlProfile::SqliteLocal.contract();
    let records = q::LOGICAL_RELATIONS
        .iter()
        .find(|r| r.name == "records")
        .unwrap();
    json!({"query":{"v":"1.2","kind":"governed_sql","profile":{"id":profile.id,"revision":profile.revision},"catalog_revision":q::LOGICAL_CATALOG_REVISION,
        "relations":{"records":{"identity":records.identity,"semantic_version":records.semantic_version}},"sql":"SELECT id FROM records","parameters":[],
        "output":{"columns":[{"name":"id","type":"identifier","nullable":false}],"schema_sha256":schema_digest(),"row_identity":["id"],"order":[{"column":"id","direction":"asc"}]},"bounds":{"rows":100}},
        "origin":{"kind":"authored"},"description":"Visible record identities","scope":{"description":"Caller-visible records","cardinality":"one row per record","default_inclusion":"all caller-visible records"},
        "columns":{"id":{"meaning":"Stable record identity","source_mapping":"records.id","vocabulary":null,"unit":null,"encoding":null}},"source_pins":[]})
}
fn event(seq: i64, kind: &str, payload: serde_json::Value) -> EventRow {
    EventRow {
        local_seq: seq,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: "bearer".into(),
        event_type: kind.into(),
        payload: Some(payload.to_string()),
        actor: Some("actor".into()),
        run_key: None,
        parent_key: None,
        intent: None,
        created_at: "2026-10-25T00:00:00Z".into(),
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
        act: None,
    }
}
fn revision(seq: i64) -> EventRow {
    let mut r = Revision {
        v: 1,
        view_id: "native.named-view:bearer".into(),
        definition_sha256: String::new(),
        definition: definition_fixture(),
    };
    r.definition_sha256 = r.digest();
    event(seq, REVISION, serde_json::to_value(r).unwrap())
}
fn activation(seq: i64, r: &EventRow, expected: Option<String>) -> EventRow {
    let rev: Revision = serde_json::from_str(r.payload.as_ref().unwrap()).unwrap();
    event(
        seq,
        TRANSITION,
        serde_json::to_value(Transition {
            v: 1,
            view_id: rev.view_id.clone(),
            expected,
            action: Action::Activate {
                name: "view_tasks".into(),
                pin: Pin {
                    view_id: rev.view_id,
                    revision_id: r.id.clone(),
                    definition_sha256: rev.definition_sha256,
                    schema_sha256: schema_digest(),
                },
            },
        })
        .unwrap(),
    )
}
async fn connection() -> SqliteConnection {
    let mut conn = SqliteConnection::connect(":memory:").await.unwrap();
    sqlx::query("CREATE TABLE content_events(seq INTEGER PRIMARY KEY,id TEXT UNIQUE,record_id TEXT,type TEXT,payload TEXT,actor TEXT,created_at TEXT)").execute(&mut conn).await.unwrap();
    sqlx::query("CREATE TABLE kernel_record_metadata(record_id TEXT,last_activity_at TEXT,event_seq INTEGER)").execute(&mut conn).await.unwrap();
    sqlx::query("CREATE TABLE kernel_facets(record_id TEXT,key TEXT,value TEXT,as_of TEXT,event_seq INTEGER)").execute(&mut conn).await.unwrap();
    conn
}
async fn insert(conn: &mut SqliteConnection, e: &EventRow) {
    sqlx::query("INSERT INTO content_events VALUES(?,?,?,?,?,?,?)")
        .bind(e.local_seq)
        .bind(&e.id)
        .bind(&e.record_id)
        .bind(&e.event_type)
        .bind(&e.payload)
        .bind(&e.actor)
        .bind(&e.created_at)
        .execute(conn)
        .await
        .unwrap();
}

#[tokio::test]
async fn named_view_unconditional_interpreters_and_prior_prefix() {
    let mut conn = connection().await;
    let r = revision(1);
    let a = activation(2, &r, None);
    for e in [&r, &a] {
        insert(&mut conn, e).await;
        let intent = crate::domain_transaction::ProjectorIntent::from_event(e).unwrap();
        crate::projector::project_intent(&mut conn, e, &intent)
            .await
            .unwrap();
    }
    let legacy = event(
        3,
        LEGACY,
        json!({"v":1,"name":"view_old","definition_sha256":"b".repeat(64),"origin":"authored"}),
    );
    insert(&mut conn, &legacy).await;
    crate::projector::project(&mut conn, &legacy).await.unwrap();
    let value: String = sqlx::query_scalar("SELECT value FROM kernel_facets")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert!(value.contains("view_old"));
    let state = load_prefix(&mut conn, 2, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(state.transitions, 1);
    assert!(!state.legacy);
    let mut early = ReplayChecker::default();
    assert!(
        early.apply(&a).is_err(),
        "later inserted revision cannot satisfy prior prefix"
    );
    assert!(read_event(&mut conn, &r.id, 0).await.is_err());
}

#[test]
fn named_view_replay_cas_and_unpublish_keep_revision() {
    let r = revision(1);
    let a = activation(2, &r, None);
    let mut state = ReplayChecker::default();
    state.apply(&r).unwrap();
    state.apply(&a).unwrap();
    assert!(state.clone().apply(&activation(3, &r, None)).is_err());
    let unpublish = event(
        3,
        TRANSITION,
        serde_json::to_value(Transition {
            v: 1,
            view_id: "native.named-view:bearer".into(),
            expected: Some(a.id),
            action: Action::Unpublish,
        })
        .unwrap(),
    );
    state.apply(&unpublish).unwrap();
    assert_eq!(state.revisions.len(), 1);
    assert!(state.bindings.values().all(|b| b.active.is_none()));
    let mut corrupt = r.clone();
    corrupt.payload = Some("{}".into());
    assert!(ReplayChecker::default().apply(&corrupt).is_err());
}

#[test]
fn named_view_gate_is_closed_for_every_new_event() {
    for kind in [REVISION, TRANSITION] {
        assert!(admit(kind).unwrap_err().to_string().contains("disabled"));
    }
    assert!(admit("record.created").is_ok());
}

#[tokio::test]
async fn named_view_index_and_fallback_agree_and_refuse_partial_prefixes() {
    let mut conn = connection().await;
    let r = revision(1);
    let a = activation(2, &r, None);
    insert(&mut conn, &r).await;
    insert(&mut conn, &a).await;
    let fallback = load_prefix(&mut conn, 2, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    sqlx::query(INDEX_DDL).execute(&mut conn).await.unwrap();
    let indexed = load_prefix(&mut conn, 2, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(
        fallback.bindings["native.named-view:bearer"].event_id,
        indexed.bindings["native.named-view:bearer"].event_id
    );
    let plans: Vec<(i64, i64, i64, String)> =
        sqlx::query_as(&format!("EXPLAIN QUERY PLAN {}", storage::prefix_query()))
            .bind(2_i64)
            .fetch_all(&mut conn)
            .await
            .unwrap();
    assert!(
        plans
            .iter()
            .any(|p| p.3.contains("idx_kernel_named_view_lifecycle")),
        "{plans:?}"
    );
    sqlx::query("DROP INDEX idx_kernel_named_view_lifecycle")
        .execute(&mut conn)
        .await
        .unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (SELECT 3 UNION ALL SELECT x+1 FROM n WHERE x<65537) INSERT INTO content_events(seq,id,record_id,type,payload,created_at) SELECT x,'unrelated-'||x,'r','record.updated','{}','2026-10-25' FROM n").execute(&mut conn).await.unwrap();
    // Canonical replay has no wall-clock deadline. Test its exact scan cap
    // independently of host contention; deadline refusal is checked below.
    let error = load_prefix(&mut conn, 65537, None).await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("view_registry_scan_budget_exceeded"),
        "{error}"
    );
    sqlx::query(INDEX_DDL).execute(&mut conn).await.unwrap();
    assert_eq!(
        load_prefix(&mut conn, 65537, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap()
            .transitions,
        1
    );
    let deadline = Instant::now() - Duration::from_millis(1);
    assert!(load_prefix(&mut conn, 65537, deadline).await.is_err());
}

#[test]
fn named_view_history_reserves_unpublish_and_refuses_duplicate_names() {
    let r = revision(1);
    let a = activation(2, &r, None);
    let mut state = ReplayChecker::default();
    state.apply(&r).unwrap();
    state.apply(&a).unwrap();
    state.transitions = 504;
    let mut next = activation(3, &r, Some(a.id.clone()));
    assert!(state.clone().apply(&next).is_err());
    next.payload = Some(
        serde_json::to_string(&Transition {
            v: 1,
            view_id: "native.named-view:bearer".into(),
            expected: Some(a.id),
            action: Action::Unpublish,
        })
        .unwrap(),
    );
    state.apply(&next).unwrap();
    assert_eq!(state.transitions, 505);
    let mut other = revision(4);
    other.record_id = "other".into();
    let mut rev: Revision = serde_json::from_str(other.payload.as_ref().unwrap()).unwrap();
    rev.view_id = "native.named-view:other".into();
    rev.definition_sha256 = rev.digest();
    other.payload = Some(serde_json::to_string(&rev).unwrap());
    let mut state = ReplayChecker::default();
    state.apply(&r).unwrap();
    let a = activation(2, &r, None);
    state.apply(&a).unwrap();
    state.apply(&other).unwrap();
    let mut colliding = activation(5, &other, None);
    colliding.record_id = "other".into();
    assert!(state
        .apply(&colliding)
        .unwrap_err()
        .to_string()
        .contains("name unavailable"));
}

#[test]
fn named_view_revision_contract_and_exact_pins_are_versioned() {
    let mut def: contract::Definition = serde_json::from_value(definition_fixture()).unwrap();
    def.validate_retained().unwrap();
    def.validate_current().unwrap();
    assert!(contract::authored_name("view_gen_taken").is_err());
    assert!(contract::authored_name("view_tasks").is_ok());
    let mut unpinned = def.clone();
    let static_pin = unpinned.query.relations.remove("records").unwrap();
    unpinned
        .query
        .relations
        .insert("view_tasks".into(), static_pin);
    assert!(unpinned.validate_retained().is_err());
    let name = contract::generated_name("workspace", "generator", "source", "selector");
    assert_eq!(
        name,
        contract::generated_name("workspace", "generator", "source", "selector")
    );
    assert_ne!(
        name,
        contract::generated_name("workspace", "generator", "source", "other")
    );
    def.query.output.schema_sha256 = "0".repeat(64);
    assert!(def.validate_retained().is_err());
    let mut value = definition_fixture();
    value["columns"]["id"]["meaning"] = json!("");
    assert!(serde_json::from_value::<contract::Definition>(value)
        .unwrap()
        .validate_retained()
        .is_err());
    let mut value = definition_fixture();
    value["query"]["relations"]["view_tasks"] = json!({"view_id":"native.named-view:bearer","revision_id":uuid::Uuid::new_v4().to_string(),"definition_sha256":"b".repeat(64),"schema_sha256":schema_digest()});
    value["query"]["relations"]
        .as_object_mut()
        .unwrap()
        .remove("records");
    value["query"]["sql"] = json!("SELECT id FROM view_tasks");
    let def: contract::Definition = serde_json::from_value(value.clone()).unwrap();
    def.validate_current().unwrap();
    value["query"]["relations"]["view_tasks"]
        .as_object_mut()
        .unwrap()
        .remove("revision_id");
    assert!(serde_json::from_value::<contract::Definition>(value).is_err());
}

fn planned(
    record: &str,
    sql: &str,
    deps: BTreeMap<String, contract::Dependency>,
) -> (Pin, contract::Definition) {
    let mut def: contract::Definition = serde_json::from_value(definition_fixture()).unwrap();
    def.query.sql = sql.into();
    def.query.relations = deps;
    let r = Revision {
        v: 1,
        view_id: format!("native.named-view:{record}"),
        definition_sha256: String::new(),
        definition: serde_json::to_value(&def).unwrap(),
    };
    let pin = Pin {
        view_id: r.view_id.clone(),
        revision_id: uuid::Uuid::new_v4().to_string(),
        definition_sha256: r.digest(),
        schema_sha256: schema_digest(),
    };
    (pin, def)
}
fn static_records() -> BTreeMap<String, contract::Dependency> {
    let d: contract::Definition = serde_json::from_value(definition_fixture()).unwrap();
    d.query.relations
}
#[test]
fn named_view_closure_keeps_two_revisions_and_pins_nested_names() {
    let (a1, d1) = planned("a", "SELECT id FROM records", static_records());
    let (a2, d2) = planned(
        "a",
        "SELECT id FROM records WHERE type='Document'",
        static_records(),
    );
    let (b, db) = planned(
        "b",
        "SELECT view_a.id FROM view_a",
        BTreeMap::from([("view_a".into(), contract::Dependency::View(a1.clone()))]),
    );
    let definitions = BTreeMap::from([(a1.clone(), d1), (a2.clone(), d2), (b.clone(), db)]);
    let roots = BTreeMap::from([("view_a".into(), a2.clone()), ("view_b".into(), b.clone())]);
    let plan = closure::build(&roots, &definitions).unwrap();
    assert_eq!(plan.nodes.len(), 3);
    let nested = plan.nodes.iter().find(|n| n.pin == b).unwrap();
    let old = plan.nodes.iter().find(|n| n.pin == a1).unwrap();
    let new = plan.nodes.iter().find(|n| n.pin == a2).unwrap();
    assert_ne!(old.alias, new.alias);
    assert_eq!(old.sql, "SELECT id FROM records");
    assert!(nested.sql.contains(&old.alias));
    assert!(!nested.sql.contains(&new.alias));
    #[cfg(feature = "v2-kernel-probe")]
    {
        let reads = plan.validate_schema().unwrap();
        assert!(reads.contains(&("records".into(), "id".into())));
        assert!(reads.contains(&("records".into(), "type".into())));
    }
    let (a3, d3) = planned(
        "a",
        "SELECT id FROM view_b",
        BTreeMap::from([("view_b".into(), contract::Dependency::View(b.clone()))]),
    );
    let mut defs = definitions;
    defs.insert(a3.clone(), d3);
    assert!(
        closure::build(&BTreeMap::from([("view_a".into(), a3)]), &defs)
            .err()
            .unwrap()
            .to_string()
            .contains("view_cycle")
    );
}

#[test]
fn named_view_ast_rebinding_preserves_literals_aliases_and_nested_references() {
    let bindings = BTreeMap::from([("view_tasks".into(), "_native_view_fixed".into())]);
    let sql="SELECT t.id FROM view_tasks t WHERE EXISTS (SELECT 1 FROM view_tasks u WHERE u.id=t.id AND 'view_tasks'='view_tasks')";
    let rewritten = crate::query::turso_ast_rules::rebind_definition(sql, &bindings).unwrap();
    assert_eq!(rewritten.matches("_native_view_fixed").count(), 2);
    assert!(rewritten.contains("'view_tasks'"));
    let implicit = crate::query::turso_ast_rules::rebind_definition(
        "SELECT view_tasks.* FROM view_tasks",
        &bindings,
    )
    .unwrap();
    assert!(implicit.contains("AS view_tasks"));
    assert!(crate::query::turso_ast_rules::rebind_definition(
        "WITH view_tasks AS (SELECT id FROM records) SELECT id FROM view_tasks",
        &bindings
    )
    .is_err());
    assert!(crate::query::turso_ast_rules::rebind_definition(
        "SELECT id FROM main.view_tasks",
        &bindings
    )
    .is_err());
}

#[test]
fn named_view_closure_rechecks_shared_subtree_depth_and_byte_budget() {
    let (leaf, d) = planned("leaf", "SELECT id FROM records", static_records());
    let mut defs = BTreeMap::from([(leaf.clone(), d)]);
    let mut child = leaf.clone();
    for i in 0..4 {
        let (p, d) = planned(
            &format!("node{i}"),
            "SELECT id FROM view_child",
            BTreeMap::from([("view_child".into(), contract::Dependency::View(child))]),
        );
        defs.insert(p.clone(), d);
        child = p;
    }
    let roots = BTreeMap::from([("view_a_leaf".into(), leaf), ("view_z_deep".into(), child)]);
    assert!(closure::build(&roots, &defs)
        .err()
        .unwrap()
        .to_string()
        .contains("depth"));
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn named_view_gate_stays_closed_inside_app_dispatch() {
    use crate::mcp::{app_attribution::AppAttribution, registry::Caller};
    let caller = Caller::authenticated("acct:admin")
        .with_host_asserted_app(AppAttribution::new("test.app", "1.0.0", "installation").unwrap());
    let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
        &caller,
        "records_write",
        &json!({}),
        None,
    );
    let (db, _) = crate::kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    dispatch
        .scope(async {
            assert!(crate::provenance::current_app_claim().is_some());
            for kind in [REVISION, TRANSITION] {
                let spec = || crate::store::AppendSpec {
                    record_id: "bearer".into(),
                    event_type: kind.into(),
                    payload: json!({}),
                    actor: None,
                };
                assert!(crate::store::append(&db, spec()).await.is_err());
                let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
                let mut acts = crate::act::ActAllocation::new();
                assert!(crate::store::append_in(&db, &mut tx, spec(), &mut acts)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("disabled"));
                assert!(crate::store::append_migration_on(
                    &mut tx,
                    uuid::Uuid::new_v4().to_string(),
                    spec(),
                    "2026-10-25"
                )
                .await
                .unwrap_err()
                .to_string()
                .contains("disabled"));
                tx.rollback().await.unwrap();
            }
        })
        .await;
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn named_view_snapshot_resolution_and_full_tail_replay_match() {
    use crate::{db::begin_write, events::KERNEL_ROOT_ID, kernel};
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
        .await
        .unwrap();
    let home = kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(&admin, "manage"), (&viewer, "view")]),
        &admin,
    )
    .await
    .unwrap();
    let record = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let generated_bearer = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let base: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let (pin, def) = planned(&record, "SELECT id FROM records", static_records());
    let rev = Revision {
        v: 1,
        view_id: pin.view_id.clone(),
        definition_sha256: pin.definition_sha256.clone(),
        definition: serde_json::to_value(def).unwrap(),
    };
    let mut r = event(base + 1, REVISION, serde_json::to_value(rev).unwrap());
    r.id = pin.revision_id.clone();
    r.record_id = record.clone();
    let mut a = activation(base + 2, &r, None);
    a.record_id = record.clone();
    for e in [&r, &a] {
        sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown')")
            .bind(e.local_seq).bind(&e.id).bind(&e.record_id).bind(&e.event_type).bind(&e.payload).bind(&e.actor).bind(&e.created_at).execute(&mut *tx).await.unwrap();
    }
    // More than one full-replay page, with CAS transitions crossing page boundaries.
    let mut last = a.id.clone();
    for offset in 3..=140 {
        let mut next = activation(base + offset, &r, Some(last));
        next.record_id = record.clone();
        last = next.id.clone();
        sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown')")
            .bind(next.local_seq).bind(&next.id).bind(&next.record_id).bind(&next.event_type).bind(&next.payload).bind(&next.actor).bind(&next.created_at).execute(&mut *tx).await.unwrap();
    }
    // V2 lands beyond the first 128-event page in this actual kernel replay.
    let v2 = v2_tests::v2_revision_for(&generated_bearer, base + 141);
    for e in [&v2, &v2_tests::v2_activation(base + 142, &v2, None)] {
        sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown')")
            .bind(e.local_seq).bind(&e.id).bind(&e.record_id).bind(&e.event_type).bind(&e.payload).bind(&e.actor).bind(&e.created_at).execute(&mut *tx).await.unwrap();
    }
    let split = base + 130;
    let mut tail_checker = load_prefix(&mut tx, split, None).await.unwrap();
    let tail_events = crate::conformance::rebuild::read_events_after_seq(&mut tx, split)
        .await
        .unwrap();
    for e in &tail_events {
        tail_checker.apply(e).unwrap();
    }
    let events = crate::conformance::rebuild::read_events_after_seq(&mut tx, 0)
        .await
        .unwrap();
    assert!(events.len() > 128);
    let mut full_checker = ReplayChecker::default();
    let mut after = 0;
    loop {
        let page = crate::conformance::rebuild::read_event_page_after_seq(&mut tx, after, 128)
            .await
            .unwrap();
        if page.is_empty() {
            break;
        }
        after = page.last().unwrap().local_seq;
        for e in &page {
            full_checker.apply(e).unwrap();
        }
    }
    assert!(full_checker.revisions.contains_key(&v2.id));
    assert_eq!(full_checker.bindings, tail_checker.bindings);
    assert_eq!(full_checker.revisions, tail_checker.revisions);
    kernel::replay_projection_tail_on(&mut tx, base, 0)
        .await
        .unwrap();
    let tail = kernel::projection_dump::dump_on(&mut tx).await.unwrap();
    let roots = BTreeMap::from([("view_tasks".into(), pin.clone())]);
    let plan = closure::resolve_on(
        &mut tx,
        &viewer,
        &roots,
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(plan.nodes.len(), 1);
    plan.validate_schema().unwrap();
    kernel::replay_all_projections_on(&mut tx).await.unwrap();
    assert_eq!(
        kernel::projection_dump::dump_on(&mut tx).await.unwrap(),
        tail
    );
    tx.commit().await.unwrap();
    kernel::replace_home_policy(&db, &admin, &home, &[(&admin, "manage")])
        .await
        .unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    assert!(closure::resolve_on(
        &mut tx,
        &viewer,
        &roots,
        Instant::now() + Duration::from_secs(2)
    )
    .await
    .err()
    .unwrap()
    .to_string()
    .contains("view_missing"));
}

fn revision_for(seq: i64, record: &str) -> EventRow {
    let mut r = revision(seq);
    r.record_id = record.into();
    let mut rev: Revision = serde_json::from_str(r.payload.as_ref().unwrap()).unwrap();
    rev.view_id = format!("native.named-view:{record}");
    rev.definition_sha256 = rev.digest();
    r.payload = Some(serde_json::to_string(&rev).unwrap());
    r
}
#[test]
fn named_view_workspace_and_bearer_caps_and_complete_unpublish_reserve() {
    let mut workspace = ReplayChecker::default();
    for i in 1..=256 {
        workspace
            .apply(&revision_for(i, &format!("bearer_{i}")))
            .unwrap();
    }
    assert!(workspace.apply(&revision_for(257, "another")).is_err());
    let mut bearer = ReplayChecker::default();
    for i in 1..=128 {
        bearer.apply(&revision_for(i, "same")).unwrap();
    }
    assert!(bearer.apply(&revision_for(129, "same")).is_err());
    let mut active = ReplayChecker::default();
    let mut seq = 0;
    for i in 0..8 {
        seq += 1;
        let r = revision_for(seq, &format!("bearer_{i}"));
        active.apply(&r).unwrap();
        seq += 1;
        let mut a = activation(seq, &r, None);
        a.record_id = r.record_id.clone();
        let mut payload: serde_json::Value =
            serde_json::from_str(a.payload.as_ref().unwrap()).unwrap();
        payload["name"] = json!(format!("view_tasks_{i}"));
        a.payload = Some(payload.to_string());
        active.apply(&a).unwrap();
    }
    seq += 1;
    let r = revision_for(seq, "ninth");
    active.apply(&r).unwrap();
    seq += 1;
    let mut ninth = activation(seq, &r, None);
    ninth.record_id = r.record_id;
    assert!(active
        .clone()
        .apply(&ninth)
        .unwrap_err()
        .to_string()
        .contains("limit"));
    active.transitions = 504;
    for (view_id, binding) in active.bindings.clone() {
        seq += 1;
        let mut e = event(
            seq,
            TRANSITION,
            serde_json::to_value(Transition {
                v: 1,
                view_id: view_id.clone(),
                expected: Some(binding.event_id),
                action: Action::Unpublish,
            })
            .unwrap(),
        );
        e.record_id = view_id.strip_prefix("native.named-view:").unwrap().into();
        active.apply(&e).unwrap();
    }
    assert_eq!(active.transitions, 512);
    assert!(active.bindings.values().all(|b| b.active.is_none()));
}

#[test]
fn revision_rejects_omitted_round_trip_fields() {
    for path in ["parameters", "vocabulary"] {
        let mut r: Revision =
            serde_json::from_str(revision(1).payload.as_deref().unwrap()).unwrap();
        if path == "parameters" {
            r.definition["query"].as_object_mut().unwrap().remove(path);
        } else {
            r.definition["columns"]["id"]
                .as_object_mut()
                .unwrap()
                .remove(path);
        }
        r.definition_sha256 = r.digest();
        let e = event(1, REVISION, serde_json::to_value(&r).unwrap());
        assert!(r
            .validate_retained(&e)
            .unwrap_err()
            .to_string()
            .contains("non-canonical"));
    }
}

#[test]
fn cached_descendant_cycles_are_independent_of_root_and_relation_order() {
    let (a1, d1) = planned("a", "SELECT id FROM records", static_records());
    let (b, db) = planned(
        "b",
        "SELECT id FROM view_a",
        BTreeMap::from([("view_a".into(), contract::Dependency::View(a1.clone()))]),
    );
    for reverse in [false, true] {
        let names = if reverse {
            ["view_z", "view_a"]
        } else {
            ["view_a", "view_z"]
        };
        let (a2, d2) = planned(
            "a",
            &format!(
                "SELECT x.id FROM {} x JOIN {} y ON x.id=y.id",
                names[0], names[1]
            ),
            BTreeMap::from([
                (names[0].into(), contract::Dependency::View(b.clone())),
                (names[1].into(), contract::Dependency::View(a1.clone())),
            ]),
        );
        let defs = BTreeMap::from([
            (a1.clone(), d1.clone()),
            (b.clone(), db.clone()),
            (a2.clone(), d2),
        ]);
        for reverse_roots in [false, true] {
            let roots = if reverse_roots {
                [b.clone(), a2.clone()]
            } else {
                [a2.clone(), b.clone()]
            };
            let roots = BTreeMap::from([
                ("view_first".into(), roots[0].clone()),
                ("view_second".into(), roots[1].clone()),
            ]);
            assert!(closure::build(&roots, &defs)
                .err()
                .unwrap()
                .to_string()
                .contains("view_cycle"));
        }
    }
}

#[test]
fn dependent_definitions_enforce_determinism_rules() {
    let (leaf, _) = planned("leaf", "SELECT id FROM records", static_records());
    for sql in [
        "SELECT id FROM view_child LIMIT 1",
        "SELECT id FROM view_child GROUP BY id || ''",
    ] {
        let (_, def) = planned(
            "dependent",
            sql,
            BTreeMap::from([(
                "view_child".into(),
                contract::Dependency::View(leaf.clone()),
            )]),
        );
        assert!(def.validate_current().is_err(), "{sql}");
    }
}

#[test]
fn named_view_diamond_expands_shared_leaf_once() {
    let (a, da) = planned("a", "SELECT id FROM records", static_records());
    let mut defs = BTreeMap::from([(a.clone(), da)]);
    let mut branches = Vec::new();
    for name in ["b", "c"] {
        let (p, d) = planned(
            name,
            "SELECT id FROM view_leaf",
            BTreeMap::from([("view_leaf".into(), contract::Dependency::View(a.clone()))]),
        );
        defs.insert(p.clone(), d);
        branches.push(p);
    }
    let (root, d) = planned(
        "root",
        "SELECT b.id FROM view_b b JOIN view_c c ON b.id=c.id",
        BTreeMap::from([
            (
                "view_b".into(),
                contract::Dependency::View(branches[0].clone()),
            ),
            (
                "view_c".into(),
                contract::Dependency::View(branches[1].clone()),
            ),
        ]),
    );
    defs.insert(root.clone(), d);
    let closure = closure::build(&BTreeMap::from([("view_root".into(), root)]), &defs).unwrap();
    assert_eq!(closure.nodes.len(), 4);
    assert_eq!(closure.nodes.iter().filter(|n| n.pin == a).count(), 1);
    #[cfg(feature = "v2-kernel-probe")]
    closure.validate_schema().unwrap();
}

#[tokio::test]
async fn legacy_history_has_a_separate_budget() {
    let mut conn = connection().await;
    for seq in 1..=8 {
        insert(&mut conn, &event(seq, LEGACY, json!({"v":1,"name":"view_legacy","definition_sha256":"a".repeat(64),"origin":"authored"}))).await;
    }
    for seq in 9..=264 {
        insert(&mut conn, &revision_for(seq, &format!("record_{seq}"))).await;
    }
    for indexed in [false, true] {
        if indexed {
            sqlx::query(INDEX_DDL).execute(&mut conn).await.unwrap();
        }
        let state = load_prefix(&mut conn, 264, None).await.unwrap();
        assert!(state.legacy);
        assert_eq!(state.revisions.len(), MAX_REVISIONS);
    }
    insert(&mut conn, &event(265, LEGACY, json!({}))).await;
    assert!(load_prefix(&mut conn, 265, None)
        .await
        .unwrap_err()
        .to_string()
        .contains("legacy admission history limit"));
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn named_view_node_cap_checks_pending_visibility_without_decoding() {
    use crate::{events::KERNEL_ROOT_ID, kernel};
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
        .await
        .unwrap();
    let public = kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(&admin, "manage"), (&viewer, "view")]),
        &admin,
    )
    .await
    .unwrap();
    let private = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let visible = kernel::create_record_as(&db, &admin, &public)
        .await
        .unwrap();
    let hidden = kernel::create_record_as(&db, &admin, &private)
        .await
        .unwrap();
    for hidden_dependency in [false, true] {
        let mut defs = Vec::new();
        let mut deps = BTreeMap::new();
        for i in 0..18 {
            let record = if i == 0 && hidden_dependency {
                &hidden
            } else {
                &visible
            };
            let (pin, def) = planned(
                record,
                &format!("SELECT id FROM records WHERE id <> '{i}'"),
                static_records(),
            );
            let name = if i == 0 {
                "view_a_hidden".into()
            } else {
                format!("view_z_{i:02}")
            };
            deps.insert(name, contract::Dependency::View(pin.clone()));
            defs.push((pin, def));
        }
        let sql = format!(
            "SELECT view_a_hidden.id FROM {}",
            deps.keys().cloned().collect::<Vec<_>>().join(", ")
        );
        let (root, def) = planned(&visible, &sql, deps);
        defs.push((root.clone(), def));
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        for (i, (pin, def)) in defs.into_iter().enumerate() {
            let revision = Revision {
                v: 1,
                view_id: pin.view_id.clone(),
                definition_sha256: pin.definition_sha256,
                definition: serde_json::to_value(def).unwrap(),
            };
            // The first three leaves are discovered last. Poison their payloads:
            // correct node-cap refusal must never fetch/decode any of them.
            let payload = if i < 3 {
                "not JSON".into()
            } else {
                serde_json::to_string(&revision).unwrap()
            };
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')")
            .bind(pin.revision_id).bind(pin.view_id.strip_prefix("native.named-view:").unwrap()).bind(REVISION).bind(payload).bind("2026-10-25").execute(&mut *tx).await.unwrap();
        }
        let result = closure::resolve_on(
            &mut tx,
            &viewer,
            &BTreeMap::from([("view_root".into(), root)]),
            Instant::now() + Duration::from_secs(2),
        )
        .await;
        let expected = if hidden_dependency {
            "view_missing"
        } else {
            "view_budget_exceeded: nodes"
        };
        assert!(result.err().unwrap().to_string().contains(expected));
        tx.rollback().await.unwrap();
    }
}

#[test]
fn generated_revision_only_activates_generated_namespace() {
    let mut r = revision(1);
    let mut revision: Revision = serde_json::from_str(r.payload.as_deref().unwrap()).unwrap();
    revision.definition["origin"] = json!({"kind":"generated","generator":"g","version":"1","source_identity":"s","selector":"q"});
    revision.definition_sha256 = revision.digest();
    r.payload = Some(serde_json::to_string(&revision).unwrap());
    let mut a = activation(2, &r, None);
    let mut state = ReplayChecker::default();
    state.apply(&r).unwrap();
    assert!(state
        .clone()
        .apply(&a)
        .unwrap_err()
        .to_string()
        .contains("view_gen_"));
    let mut value: serde_json::Value = serde_json::from_str(a.payload.as_deref().unwrap()).unwrap();
    value["name"] = json!("view_gen_fixture");
    a.payload = Some(value.to_string());
    state.apply(&a).unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn named_view_exact_lookup_needs_no_index_on_large_log() {
    use crate::{events::KERNEL_ROOT_ID, kernel};
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let record = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let (pin, def) = planned(&record, "SELECT id FROM records", static_records());
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    sqlx::query("DROP INDEX idx_kernel_named_view_lifecycle")
        .execute(&mut *tx)
        .await
        .unwrap();
    insert_retained_definition(&mut tx, &pin, &def, None).await;
    sqlx::query("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<65537) INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) SELECT 'unrelated-'||x,'unrelated','record.updated','{}','2026-10-25',1,'legacy_unknown' FROM n").execute(&mut *tx).await.unwrap();
    assert!(!storage::verify_index_on(&mut tx).await.unwrap());
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert!(count > 65536);
    let plan = closure::resolve_on(
        &mut tx,
        &admin,
        &BTreeMap::from([("view_root".into(), pin)]),
        Instant::now() + Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(plan.nodes.len(), 1);
}

#[cfg(feature = "v2-kernel-probe")]
async fn insert_retained_definition(
    conn: &mut SqliteConnection,
    pin: &Pin,
    def: &contract::Definition,
    payload_override: Option<String>,
) {
    let revision = Revision {
        v: 1,
        view_id: pin.view_id.clone(),
        definition_sha256: pin.definition_sha256.clone(),
        definition: serde_json::to_value(def).unwrap(),
    };
    let payload = payload_override.unwrap_or_else(|| serde_json::to_string(&revision).unwrap());
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')")
        .bind(&pin.revision_id).bind(pin.view_id.strip_prefix("native.named-view:").unwrap()).bind(REVISION).bind(payload).bind("2026-10-25").execute(conn).await.unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn named_view_byte_cap_precedes_payload_allocation_and_decode() {
    use crate::{events::KERNEL_ROOT_ID, kernel};
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&admin, "manage")]), &admin)
        .await
        .unwrap();
    let record = kernel::create_record_as(&db, &admin, &home).await.unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut deps = BTreeMap::new();
    for i in 0..3 {
        let (pin, def) = planned(
            &record,
            &format!("SELECT id FROM records WHERE id <> '{i}'"),
            static_records(),
        );
        let revision = Revision {
            v: 1,
            view_id: pin.view_id.clone(),
            definition_sha256: pin.definition_sha256.clone(),
            definition: serde_json::to_value(&def).unwrap(),
        };
        let mut payload = if i == 0 {
            "not JSON".to_owned()
        } else {
            serde_json::to_string(&revision).unwrap()
        };
        payload.extend(std::iter::repeat_n(' ', 200 * 1024 - payload.len()));
        insert_retained_definition(&mut tx, &pin, &def, Some(payload)).await;
        deps.insert(format!("view_child_{i}"), contract::Dependency::View(pin));
    }
    let (root, def) = planned(
        &record,
        "SELECT view_child_0.id FROM view_child_0, view_child_1, view_child_2",
        deps,
    );
    insert_retained_definition(&mut tx, &root, &def, None).await;
    let result = closure::resolve_on(
        &mut tx,
        &admin,
        &BTreeMap::from([("view_root".into(), root)]),
        Instant::now() + Duration::from_secs(2),
    )
    .await;
    // Two 200 KiB carriers fit. The next one's invalid JSON must not be
    // allocated/decoded: it would produce a different error if read.
    assert!(result
        .err()
        .unwrap()
        .to_string()
        .contains("view_budget_exceeded: closure bytes"));
}

#[cfg(feature = "v2-kernel-probe")]
#[path = "execution_tests.rs"]
mod execution_tests;

#[path = "v2_tests.rs"]
pub(super) mod v2_tests;

#[tokio::test]
async fn named_view_live_namespace_skips_cap_sized_historical_bodies() {
    for active in [0, 8] {
        let mut conn = connection().await;
        sqlx::query(INDEX_DDL).execute(&mut conn).await.unwrap();
        let mut roots = Vec::new();
        for seq in 1..=256 {
            let mut r = revision(seq);
            r.record_id = format!("bearer-{seq}");
            let mut payload: Revision = decode(&r, MAX_CARRIER_BYTES).unwrap();
            payload.view_id = format!("native.named-view:{}", r.record_id);
            payload.definition_sha256 = payload.digest();
            r.payload = Some(serde_json::to_string(&payload).unwrap());
            if seq <= active {
                roots.push(r.clone());
            } else {
                // Near carrier byte cap, deliberately not JSON. Any historical
                // JSON extraction or body certification would refuse this log.
                r.payload = Some("!".repeat(MAX_CARRIER_BYTES - 1));
            }
            insert(&mut conn, &r).await;
        }
        for (i, r) in roots.iter().enumerate() {
            let revision: Revision = decode(r, MAX_CARRIER_BYTES).unwrap();
            let mut a = event(
                257 + i as i64,
                TRANSITION,
                json!({"v":1,"view_id":revision.view_id,"expected":null,"action":"activate","name":format!("view_root_{i}"),"pin":{"view_id":revision.view_id,"revision_id":r.id,"definition_sha256":revision.definition_sha256,"schema_sha256":schema_digest()}}),
            );
            a.record_id = r.record_id.clone();
            insert(&mut conn, &a).await;
        }
        let started = Instant::now();
        let (result, reads) = measured_revision_reads(storage::load_live(
            &mut conn,
            i64::MAX,
            Instant::now() + Duration::from_secs(2),
        ))
        .await;
        let state = result.unwrap();
        eprintln!("live indexed: revisions=256 roots={active} inactive_bytes={} elapsed_ms={} historical_revision_reads={reads}",(256-active) as usize*(MAX_CARRIER_BYTES-1),started.elapsed().as_millis());
        assert_eq!(state.bindings().len(), active as usize);
        assert_eq!(reads, 0, "historical revision bodies must not be opened");
        assert!(
            load_prefix(&mut conn, i64::MAX, None).await.is_err(),
            "canonical prefix remains strict"
        );
    }
}

#[tokio::test]
async fn named_view_live_namespace_checks_new_references_and_transition_structure() {
    let mut conn = connection().await;
    sqlx::query(INDEX_DDL).execute(&mut conn).await.unwrap();
    let r = revision(1);
    insert(&mut conn, &r).await;
    let mut a = activation(2, &r, None);
    let mut live = storage::load_live(&mut conn, 1, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    live.apply_new_on(&mut conn, &a, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    sqlx::query("UPDATE content_events SET payload='not json' WHERE id=?")
        .bind(&r.id)
        .execute(&mut conn)
        .await
        .unwrap();
    let mut live = storage::load_live(&mut conn, 1, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap();
    assert!(live
        .apply_new_on(&mut conn, &a, Instant::now() + Duration::from_secs(2))
        .await
        .is_err());
    let mut unknown: Revision = decode(&r, MAX_CARRIER_BYTES).unwrap();
    unknown.v = 99;
    sqlx::query("UPDATE content_events SET payload=? WHERE id=?")
        .bind(serde_json::to_string(&unknown).unwrap())
        .bind(&r.id)
        .execute(&mut conn)
        .await
        .unwrap();
    assert!(live
        .apply_new_on(&mut conn, &a, Instant::now() + Duration::from_secs(2))
        .await
        .unwrap_err()
        .to_string()
        .contains("view_revision_unavailable"));
    a.payload = Some("{}".into());
    insert(&mut conn, &a).await;
    assert!(
        storage::load_live(&mut conn, 2, Instant::now() + Duration::from_secs(2))
            .await
            .is_err()
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn named_view_governed_import_refuses_historic_mismatched_pin_canonically() {
    // This established kernel constructor includes the governed-import source
    // provenance tables; owned hosted-v2 files deliberately omit them.
    let db = crate::kernel::create_kernel_database(":memory:")
        .await
        .unwrap();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let r = revision(1);
    // Existing indexed identities are trusted by live reconstruction, but an
    // imported event must go through canonical history verification instead.
    for e in [&r, &{
        let mut a = activation(2, &r, None);
        let mut t: Transition = decode(&a, 2048).unwrap();
        if let Action::Activate { pin, .. } = &mut t.action {
            pin.definition_sha256 = "f".repeat(64);
        }
        a.payload = Some(serde_json::to_string(&t).unwrap());
        a
    }] {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')")
            .bind(&e.id).bind(&e.record_id).bind(&e.event_type).bind(&e.payload).bind(&e.created_at).execute(&mut *tx).await.unwrap();
    }
    let head = sqlx::query_scalar::<_, i64>("SELECT max(seq) FROM content_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert!(
        storage::load_live(&mut tx, head, Instant::now() + Duration::from_secs(2))
            .await
            .is_ok()
    );
    tx.commit().await.unwrap();
    let imported = revision(head + 1);
    let id = imported.id.clone();
    let error = gate::testing(
        true,
        crate::store::exercise_named_view_import(&db, imported),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("revision pin mismatch"),
        "{error}"
    );
    assert!(!sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM content_events WHERE id=?)"
    )
    .bind(id)
    .fetch_one(db.pool())
    .await
    .unwrap());
}
