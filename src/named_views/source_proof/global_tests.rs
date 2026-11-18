//! Private global resolver coverage (probe-only).
//!
//! Uses the shared source_proof fixture machinery with vocabulary names.
//! Facet-1 golden semantics are untouched; only the global profile binds
//! bare names through the complete snapshot union.
use super::{deadline, generated_request, Fixture, KERNEL_ROOT_ID};
use crate::named_views::{
    facet_resolver, read_event,
    retained_facets::inspect_global_on,
    retained_facets::{ComparisonSnapshot, Drift},
    v2, Pin, REVISION,
};
use serde_json::json;

async fn global_declared(f: &Fixture) {
    // Pack-global declarations; the home collection carries nothing, so the
    // global profile (no applicable H governance) admits the candidate.
    f.import("schema_config","global",Some(json!({"id":"global","layer":"pack","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area":{"description":"Area","vocab_ref":"area"},"other":{"description":"Other","vocab_ref":"rec:area"},"unknownf":{"description":"Unknown","vocab_ref":"nope"},"customf":{"description":"Custom","vocab_ref":"custom"},"dupf":{"description":"Dup","vocab_ref":"dupname"},"conff":{"description":"Conflict","vocab":"priority","vocab_ref":"rec:area"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":"G1","created_at":"2026-10-26T00:00:00Z"}))).await;
    f.import(
        "vocabularies",
        "voc:area",
        Some(json!({"id":"voc:area","name":"area"})),
    )
    .await;
    for (id, token) in [("high", "high"), ("low", "low")] {
        f.import(
            "vocabulary_values",
            id,
            Some(
                json!({"id":id,"vocabulary_id":"voc:area","value":token,"status":"active","alias_of":null}),
            ),
        )
        .await;
    }
    f.import(
        "vocabularies",
        "custom-id",
        Some(json!({"id":"custom-id","name":"custom"})),
    )
    .await;
    for (id, name) in [("voc:dup-a", "dupname"), ("voc:dup-b", "dupname")] {
        f.import("vocabularies", id, Some(json!({"id":id,"name":name})))
            .await;
    }
}

async fn global_candidate(
    f: &Fixture,
    keys: &[&str],
) -> Result<facet_resolver::Prepared, crate::Error> {
    facet_resolver::prepare_profile(
        &f.db,
        &f.actor,
        "trusted-workspace",
        &f.anchor,
        generated_request(KERNEL_ROOT_ID, keys),
        crate::query::generated_facets::Profile::Global1,
        deadline(),
    )
    .await
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_resolver_binds_bare_name_to_canonical_id() {
    let f = Fixture::new().await;
    global_declared(&f).await;
    let p = global_candidate(&f, &["area"]).await.unwrap();
    // Retained carrier validates under the amended closed reader and keeps
    // the original declaration spelling against the canonical source.
    let def: v2::Definition<v2::GlobalManifest> =
        serde_json::from_value(p.revision.definition.clone()).unwrap();
    def.validate_global().unwrap();
    assert_eq!(def.generated.format, "native.generated-facets.v2");
    let decl = &def
        .generated
        .slots
        .iter()
        .flat_map(|s| &s.fragments)
        .find(|f| f.key == "area")
        .unwrap()
        .decl;
    assert_eq!(decl.vocab_ref.as_deref(), Some("area"));
    let vocab = def
        .generated
        .vocabularies
        .iter()
        .find(|v| v.field == "area")
        .unwrap();
    let source = &def.generated.sources[vocab.source];
    assert_eq!(source.row_id, "voc:area");
    assert_eq!(source.source_id, "[\"voc:area\"]");
    // Frozen SQL admits exactly the three name-binding spellings.
    let sql = p.revision.definition["query"]["sql"].as_str().unwrap();
    assert!(sql.contains("IN ('area', 'rec:voc:area', 'voc:area')"));
    assert!(!sql.contains("'rec:area'"));
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_resolver_refuses_guessing_collisions_and_conflicts() {
    let f = Fixture::new().await;
    global_declared(&f).await;
    // rec:<name> never guesses a canonical ID.
    for key in ["other"] {
        let error = global_candidate(&f, &[key])
            .await
            .err()
            .expect("rec:name must refuse");
        assert!(
            error
                .to_string()
                .contains("required vocabulary unavailable"),
            "{error}"
        );
    }
    // Unknown references and custom-ID name mappings refuse.
    for (key, fragment) in [
        ("unknownf", "unknown vocabulary reference"),
        ("customf", "unbound vocabulary name"),
    ] {
        let error = global_candidate(&f, &[key])
            .await
            .err()
            .expect("unknown/custom must refuse");
        assert!(error.to_string().contains(fragment), "{error}");
    }
    // Duplicate names across distinct rows are ambiguous, not first-wins.
    let error = global_candidate(&f, &["dupf"])
        .await
        .err()
        .expect("duplicates must refuse");
    assert!(
        error.to_string().contains("ambiguous vocabulary reference"),
        "{error}"
    );
    // Conflicting dual declarations refuse before any snapshot binding.
    let error = global_candidate(&f, &["conff"])
        .await
        .err()
        .expect("conflicting dual must refuse");
    assert!(
        error
            .to_string()
            .contains("conflicting vocabulary declaration"),
        "{error}"
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_resolver_shares_one_source_across_spellings() {
    let f = Fixture::new().await;
    global_declared(&f).await;
    // Same vocabulary through three declaration spellings.
    f.import("schema_config","global-shared",Some(json!({"id":"global-shared","layer":"pack","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area_shared":{"vocab_ref":"area"},"area_mixed":{"vocab_ref":"voc:area"},"area_rec":{"vocab_ref":"rec:voc:area"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":"G1b","created_at":"2026-10-26T00:00:01Z"}))).await;
    let p = global_candidate(&f, &["area", "area_shared", "area_mixed", "area_rec"])
        .await
        .unwrap();
    let def: v2::Definition<v2::GlobalManifest> =
        serde_json::from_value(p.revision.definition.clone()).unwrap();
    def.validate_global().unwrap();
    // One vocabulary source shared by all four fields.
    assert_eq!(def.generated.vocabularies.len(), 4);
    let row_ids: std::collections::BTreeSet<_> = def
        .generated
        .vocabularies
        .iter()
        .map(|v| def.generated.sources[v.source].row_id.clone())
        .collect();
    assert_eq!(row_ids.len(), 1);
    assert!(row_ids.contains("voc:area"));
    // Exact per-field guards: bare spellings admit three, ID spellings two.
    // (Each guard shape occurs three times in the frozen SQL: value CASE,
    // status NOT-guard, and the embedded usable CASE.)
    let sql = p.revision.definition["query"]["sql"].as_str().unwrap();
    assert_eq!(
        sql.matches("IN ('area', 'rec:voc:area', 'voc:area')")
            .count(),
        2 * 3
    );
    assert_eq!(
        sql.matches("IN ('rec:voc:area', 'voc:area')").count(),
        2 * 3
    );
    assert!(!sql.contains("'rec:area'"));
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_retained_follows_winning_pack_user_spelling() {
    let f = Fixture::new().await;
    global_declared(&f).await;
    // Pack declares the bare name; a global user row overrides the same
    // field with the ID spelling. The winner governs membership.
    f.import("schema_config","global-user",Some(json!({"id":"global-user","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area":{"vocab_ref":"voc:area"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":"G2","created_at":"2026-10-26T00:00:02Z"}))).await;
    // A competing row collides with the superseded pack spelling only.
    f.import(
        "vocabularies",
        "voc:evil",
        Some(json!({"id":"voc:evil","name":"area"})),
    )
    .await;
    let p = global_candidate(&f, &["area"]).await.unwrap();
    let def: v2::Definition<v2::GlobalManifest> =
        serde_json::from_value(p.revision.definition.clone()).unwrap();
    def.validate_global().unwrap();
    // The user slot carries the winning spelling.
    let user_decl = def
        .generated
        .slots
        .iter()
        .flat_map(|s| &s.fragments)
        .rfind(|frag| frag.key == "area")
        .unwrap()
        .decl
        .vocab_ref
        .clone();
    assert_eq!(user_decl.as_deref(), Some("voc:area"));
    let pin = commit_global(&f, &p).await;
    // First-match evaluation would flag the irrelevant pack-only collision;
    // winner-relative membership stays unchanged.
    assert_eq!(global_drift(&f, &pin).await.unwrap(), Drift::Unchanged);
}

async fn commit_global(f: &Fixture, p: &facet_resolver::Prepared) -> Pin {
    // Mirrors retain_revision: commit the revision through the real projector
    // (no activation needed for retained comparison).
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let act = crate::act::ActAllocation::new()
        .get_or_allocate(&mut tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,'2026-10-26T00:00:00Z',1,'legacy_unknown',?)")
        .bind(&id).bind(&f.anchor).bind(REVISION).bind(serde_json::to_string(&p.revision).unwrap()).bind(act).execute(&mut *tx).await.unwrap();
    let e = read_event(&mut tx, &id, i64::MAX).await.unwrap();
    crate::projector::project(&mut tx, &e).await.unwrap();
    tx.commit().await.unwrap();
    Pin {
        view_id: p.revision.view_id.clone(),
        revision_id: id,
        definition_sha256: p.revision.definition_sha256.clone(),
        schema_sha256: p.revision.definition["query"]["output"]["schema_sha256"]
            .as_str()
            .unwrap()
            .into(),
    }
}

/// Real-workspace E2E world for STEP3a serving. Sealed global schema/vocab via
/// global_declared; H direct members with name-bound area cells; activation via
/// canonical revision+transition projector path (no public admission/live import).
/// Shared setup for real global E2E: sealed schema/vocab + H members.
/// Returns fixture, H, other home, and real workspace. No preparation/commit.
async fn real_global_setup() -> (Fixture, String, String, String) {
    let f = Fixture::new().await;
    let package = crate::v2_standard::v1_compat::package();
    let installed = crate::kernel::install_package_as(&f.db, &f.actor, &package)
        .await
        .unwrap();
    crate::kernel::adopt_package_at(
        &f.db,
        &f.actor,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &[],
    )
    .await
    .unwrap();
    let workspace =
        crate::named_views::generated::workspace_on(&mut f.db.pool().acquire().await.unwrap())
            .await
            .unwrap();
    let home = crate::kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    let other = crate::kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    global_declared(&f).await;
    for (id, value, vocab_ref, target_home) in [
        ("rec-area-bare", Some("high"), Some("area"), None),
        ("rec-area-id", Some("high"), Some("voc:area"), None),
        ("rec-area-rec", Some("high"), Some("rec:voc:area"), None),
        ("rec-area-bad", Some("high"), Some("rec:area"), None),
        ("rec-other-home", Some("high"), Some("area"), Some("other")),
    ] {
        let home_id = if target_home == Some("other") {
            &other
        } else {
            &home
        };
        let facets = value
            .map(|v| crate::kernel::FacetObservation {
                key: "area".into(),
                value: Some(v.into()),
                value_num: None,
                vocab_ref: vocab_ref.map(str::to_owned),
                as_of: "2026-10-26T00:00:00Z".into(),
            })
            .into_iter()
            .collect::<Vec<_>>();
        crate::kernel::import_record_as(
            &f.db,
            &f.host,
            id,
            home_id,
            Some(&f.actor),
            &crate::kernel::ImportRecordState {
                definition: Some(crate::kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: crate::v2_standard::v1_compat::FAMILY.into(),
                        version: 1,
                        digest: crate::meta::definition_artifact::digest_artifact_bytes(
                            crate::v2_standard::v1_compat::DEFINITION.as_bytes(),
                        ),
                    },
                    primary_type: "V1".into(),
                    kind: "record".into(),
                    fields: serde_json::json!({"v1_type":"WorkItem","v1_kind":"task","title":id})
                        .as_object()
                        .unwrap()
                        .clone(),
                }),
                facets,
                archived: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    (f, home, other, workspace)
}

async fn real_global_world() -> (Fixture, String, String, Pin, String) {
    let f = Fixture::new().await;
    let package = crate::v2_standard::v1_compat::package();
    let installed = crate::kernel::install_package_as(&f.db, &f.actor, &package)
        .await
        .unwrap();
    crate::kernel::adopt_package_at(
        &f.db,
        &f.actor,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &[],
    )
    .await
    .unwrap();
    let workspace =
        crate::named_views::generated::workspace_on(&mut f.db.pool().acquire().await.unwrap())
            .await
            .unwrap();
    let home = crate::kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    let other = crate::kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    global_declared(&f).await;
    for (id, value, vocab_ref, target_home) in [
        ("rec-area-bare", Some("high"), Some("area"), None),
        ("rec-area-id", Some("high"), Some("voc:area"), None),
        ("rec-area-rec", Some("high"), Some("rec:voc:area"), None),
        ("rec-area-bad", Some("high"), Some("rec:area"), None),
        ("rec-other-home", Some("high"), Some("area"), Some("other")),
    ] {
        let home_id = if target_home == Some("other") {
            &other
        } else {
            &home
        };
        let facets = value
            .map(|v| crate::kernel::FacetObservation {
                key: "area".into(),
                value: Some(v.into()),
                value_num: None,
                vocab_ref: vocab_ref.map(str::to_owned),
                as_of: "2026-10-26T00:00:00Z".into(),
            })
            .into_iter()
            .collect::<Vec<_>>();
        crate::kernel::import_record_as(
            &f.db,
            &f.host,
            id,
            home_id,
            Some(&f.actor),
            &crate::kernel::ImportRecordState {
                definition: Some(crate::kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: crate::v2_standard::v1_compat::FAMILY.into(),
                        version: 1,
                        digest: crate::meta::definition_artifact::digest_artifact_bytes(
                            crate::v2_standard::v1_compat::DEFINITION.as_bytes(),
                        ),
                    },
                    primary_type: "V1".into(),
                    kind: "record".into(),
                    fields: serde_json::json!({"v1_type":"WorkItem","v1_kind":"task","title":id})
                        .as_object()
                        .unwrap()
                        .clone(),
                }),
                facets,
                archived: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let p = facet_resolver::prepare_profile(
        &f.db,
        &f.actor,
        &workspace,
        &f.anchor,
        crate::named_views::facet_resolver::Request {
            record_type: "WorkItem".into(),
            kind: Some("task".into()),
            home: home.clone(),
            selection: crate::query::generated_facets::Selection::Keys(
                ["area".to_string()].into_iter().collect(),
            ),
        },
        crate::query::generated_facets::Profile::Global1,
        deadline(),
    )
    .await
    .unwrap();
    let name = p.name.clone();
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let act = crate::act::ActAllocation::new()
        .get_or_allocate(&mut tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown',?)")
        .bind(head + 1).bind(&id).bind(&f.anchor).bind(REVISION).bind(serde_json::to_string(&p.revision).unwrap()).bind(&f.actor).bind("2026-10-26T00:00:00Z").bind(act).execute(&mut *tx).await.unwrap();
    let r = read_event(&mut tx, &id, i64::MAX).await.unwrap();
    crate::projector::project(&mut tx, &r).await.unwrap();
    let previous = crate::named_views::storage::load_prefix(&mut tx, head, None)
        .await
        .unwrap()
        .bindings
        .get(&format!("native.named-view:{}", f.anchor))
        .map(|b| b.event_id.clone());
    let pin = Pin {
        view_id: p.revision.view_id.clone(),
        revision_id: id.clone(),
        definition_sha256: p.revision.definition_sha256.clone(),
        schema_sha256: p.revision.definition["query"]["output"]["schema_sha256"]
            .as_str()
            .unwrap()
            .into(),
    };
    let transition = serde_json::to_value(crate::named_views::Transition {
        v: 1,
        view_id: p.revision.view_id.clone(),
        expected: previous,
        action: crate::named_views::Action::Activate {
            name: name.clone(),
            pin: pin.clone(),
        },
    })
    .unwrap();
    let aid = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown',?)")
        .bind(head + 2).bind(&aid).bind(&f.anchor).bind(crate::named_views::TRANSITION).bind(serde_json::to_string(&transition).unwrap()).bind(&f.actor).bind("2026-10-26T00:00:00Z").bind(act).execute(&mut *tx).await.unwrap();
    let a = read_event(&mut tx, &aid, i64::MAX).await.unwrap();
    crate::projector::project(&mut tx, &a).await.unwrap();
    tx.commit().await.unwrap();
    (f, home, other, pin, name)
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_serving_select_returns_h_members_with_name_mapping() {
    let (f, _home, _other, pin, name) = real_global_world().await;
    let result = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &f.actor,
        serde_json::json!({"sql": format!("SELECT id, area FROM {name} ORDER BY id")}),
    )
    .await
    .unwrap();
    let rows = result["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 4, "{rows:?}");
    let by_id = |id: &str| rows.iter().find(|r| r["id"] == id).unwrap().clone();
    for id in ["rec-area-bare", "rec-area-id", "rec-area-rec"] {
        assert_eq!(by_id(id)["area"], serde_json::json!("high"), "{id}");
    }
    assert!(by_id("rec-area-bad")["area"].is_null());
    assert!(rows.iter().all(|r| r["id"] != "rec-other-home"));
    let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
        .bind(&pin.revision_id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert!(payload.contains("IN ('area'"));
    assert!(payload.contains("'rec:voc:area'"));
    assert!(payload.contains("'voc:area'"));
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_serving_saved_sql_matches_select_exactly() {
    let (f, _home, _other, pin, name) = real_global_world().await;
    let select = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &f.actor,
        serde_json::json!({"sql": format!("SELECT id, area FROM {name} ORDER BY id")}),
    )
    .await
    .unwrap();
    let (_, outer) = crate::named_views::tests::planned(
        "outer",
        &format!("SELECT id, area FROM {name} ORDER BY id"),
        std::collections::BTreeMap::from([(
            name.clone(),
            crate::named_views::contract::Dependency::View(pin),
        )]),
    );
    let saved = crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &outer.query)
        .await
        .unwrap();
    assert_eq!(saved["rows"], select["rows"]);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_serving_details_and_list_show_unchanged() {
    let (f, _home, _other, pin, _name) = real_global_world().await;
    let mut tx = f.db.pool().begin().await.unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let detail = crate::named_views::details::get_on(
        &mut tx,
        &f.actor,
        &pin.view_id,
        &pin.revision_id,
        deadline,
    )
    .await
    .unwrap();
    assert!(detail["diagnostic"].is_null());
    assert_eq!(detail["source_drift"], serde_json::json!("unchanged"));
    let list = crate::named_views::details::list_on(
        &mut tx,
        &f.actor,
        &pin.view_id,
        8,
        None,
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    )
    .await
    .unwrap();
    assert_eq!(list["revisions"][0]["available"], serde_json::json!(true));
    assert!(list["revisions"][0]["diagnostic"].is_null());
    assert_eq!(
        list["revisions"][0]["advisory_comparison"],
        serde_json::json!("not_requested")
    );
    tx.rollback().await.unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_serving_provenance_changed_unknown_and_missing_refuses() {
    let (f, _home, _other, pin, name) = real_global_world().await;
    let view_id = pin.view_id.clone();
    let rev_id = pin.revision_id.clone();
    let drift_now = {
        let mut tx = f.db.pool().begin().await.unwrap();
        let out = crate::named_views::details::get_on(
            &mut tx,
            &f.actor,
            &view_id,
            &rev_id,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
        .unwrap()["source_drift"]
            .clone();
        tx.rollback().await.unwrap();
        out
    };
    assert_eq!(drift_now, serde_json::json!("unchanged"));
    f.import(
        "vocabularies",
        "voc:other",
        Some(serde_json::json!({"id":"voc:other","name":"area"})),
    )
    .await;
    let changed = {
        let mut tx = f.db.pool().begin().await.unwrap();
        let out = crate::named_views::details::get_on(
            &mut tx,
            &f.actor,
            &view_id,
            &rev_id,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        out
    };
    assert_eq!(changed["source_drift"], serde_json::json!("changed"));
    let select = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &f.actor,
        serde_json::json!({"sql": format!("SELECT id FROM {name} ORDER BY id")}),
    )
    .await
    .unwrap();
    assert_eq!(select["rows"].as_array().unwrap().len(), 4);
    for n in 0..1100 {
        let id = format!("voc:pad-{n:04}");
        f.import(
            "vocabularies",
            &id,
            Some(serde_json::json!({"id":id,"name":format!("pad-{n:04}")})),
        )
        .await;
    }
    let unknown = {
        let mut tx = f.db.pool().begin().await.unwrap();
        let out = crate::named_views::details::get_on(
            &mut tx,
            &f.actor,
            &view_id,
            &rev_id,
            std::time::Instant::now() + std::time::Duration::from_secs(2),
        )
        .await
        .unwrap();
        tx.rollback().await.unwrap();
        out
    };
    assert_eq!(unknown["source_drift"], serde_json::json!("unknown"));
    let (g, _h, _o, qpin, _n) = real_global_world().await;
    g.import("vocabularies", "voc:area", None).await;
    let mut tx = g.db.pool().begin().await.unwrap();
    let err = crate::named_views::details::get_on(
        &mut tx,
        &g.actor,
        &qpin.view_id,
        &qpin.revision_id,
        std::time::Instant::now() + std::time::Duration::from_secs(2),
    )
    .await
    .unwrap_err()
    .to_string();
    tx.rollback().await.unwrap();
    assert!(err.contains("view_missing"), "{err}");
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_serving_receipt_rolls_up_global_and_authored_roots() {
    let (f, home, _other, pin, name) = real_global_world().await;
    let mut tx = f.db.pool().begin().await.unwrap();
    let plan = crate::named_views::closure::resolve_on(
        &mut tx,
        &f.actor,
        &std::collections::BTreeMap::from([("view_global".into(), pin.clone())]),
        deadline(),
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    let summary = crate::named_views::receipt::generated_summaries(&plan)
        .unwrap()
        .unwrap();
    assert_eq!(
        summary,
        serde_json::json!([{"root":"view_global","drift":"unchanged","unknown_reason":null}])
    );
    assert!(!summary.to_string().contains(&pin.revision_id));
    let author_bearer = crate::kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    let (_outer_pin, outer_def) = crate::named_views::tests::planned(
        &author_bearer,
        &format!("SELECT id FROM {name} ORDER BY id"),
        std::collections::BTreeMap::from([(
            name.clone(),
            crate::named_views::contract::Dependency::View(pin.clone()),
        )]),
    );
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let rev = crate::named_views::Revision {
        v: 1,
        view_id: format!("native.named-view:{author_bearer}"),
        definition_sha256: String::new(),
        definition: serde_json::to_value(&outer_def).unwrap(),
    };
    let digest = rev.digest();
    let rev = crate::named_views::Revision {
        definition_sha256: digest,
        ..rev
    };
    let rid = uuid::Uuid::new_v4().to_string();
    let act = crate::act::ActAllocation::new()
        .get_or_allocate(&mut tx)
        .await
        .unwrap();
    let schema = outer_def.query.output.schema_sha256.clone();
    sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown',?)")
        .bind(head + 1).bind(&rid).bind(&author_bearer).bind(crate::named_views::REVISION).bind(serde_json::to_string(&rev).unwrap()).bind(&f.actor).bind("2026-10-26T00:00:00Z").bind(act).execute(&mut *tx).await.unwrap();
    let re = crate::named_views::read_event(&mut tx, &rid, i64::MAX)
        .await
        .unwrap();
    crate::projector::project(&mut tx, &re).await.unwrap();
    let apin = crate::named_views::Pin {
        view_id: rev.view_id.clone(),
        revision_id: rid.clone(),
        definition_sha256: rev.definition_sha256.clone(),
        schema_sha256: schema,
    };
    let transition = serde_json::to_value(crate::named_views::Transition {
        v: 1,
        view_id: rev.view_id.clone(),
        expected: None,
        action: crate::named_views::Action::Activate {
            name: "view_authored_over_global".into(),
            pin: apin.clone(),
        },
    })
    .unwrap();
    let aid = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown',?)")
        .bind(head + 2).bind(&aid).bind(&author_bearer).bind(crate::named_views::TRANSITION).bind(serde_json::to_string(&transition).unwrap()).bind(&f.actor).bind("2026-10-26T00:00:00Z").bind(act).execute(&mut *tx).await.unwrap();
    let ae = crate::named_views::read_event(&mut tx, &aid, i64::MAX)
        .await
        .unwrap();
    crate::projector::project(&mut tx, &ae).await.unwrap();
    tx.commit().await.unwrap();
    let mut tx = f.db.pool().begin().await.unwrap();
    let both = crate::named_views::closure::resolve_on(
        &mut tx,
        &f.actor,
        &std::collections::BTreeMap::from([
            ("view_global".into(), pin.clone()),
            ("view_authored_over_global".into(), apin.clone()),
        ]),
        deadline(),
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    let both_summary = crate::named_views::receipt::generated_summaries(&both)
        .unwrap()
        .unwrap();
    assert_eq!(
        both_summary,
        serde_json::json!([
            {"root":"view_authored_over_global","drift":"unchanged","unknown_reason":null},
            {"root":"view_global","drift":"unchanged","unknown_reason":null}
        ])
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_serving_hidden_matches_missing_and_producer_off_still_serves() {
    let (f, _home, _other, _pin, name) = real_global_world().await;
    let visitor =
        crate::kernel::create_principal(&f.db, "account", "Visitor", "acct:visitor", &f.actor)
            .await
            .unwrap();
    let hidden = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &visitor,
        serde_json::json!({"sql": format!("SELECT id FROM {name}")}),
    )
    .await
    .unwrap_err()
    .to_string();
    let absent = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &visitor,
        serde_json::json!({"sql": "SELECT id FROM view_nonexistent"}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(hidden, absent);
    let served = crate::named_views::gate::testing(
        false,
        crate::mcp::kernel_v2::sql::query_sql(
            &f.db,
            &f.actor,
            serde_json::json!({"sql": format!("SELECT id FROM {name} ORDER BY id")}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(served["rows"].as_array().unwrap().len(), 4);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_serving_artifact_port_v3_matches_receipt() {
    let (f, home, _other, pin, name) = real_global_world().await;
    let author_bearer = crate::kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    let (_o_pin, outer_def) = crate::named_views::tests::planned(
        &author_bearer,
        &format!("SELECT id FROM {name} ORDER BY id"),
        std::collections::BTreeMap::from([(
            name.clone(),
            crate::named_views::contract::Dependency::View(pin.clone()),
        )]),
    );
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let rev = crate::named_views::Revision {
        v: 1,
        view_id: format!("native.named-view:{author_bearer}"),
        definition_sha256: String::new(),
        definition: serde_json::to_value(&outer_def).unwrap(),
    };
    let digest = rev.digest();
    let rev = crate::named_views::Revision {
        definition_sha256: digest,
        ..rev
    };
    let rid = uuid::Uuid::new_v4().to_string();
    let act = crate::act::ActAllocation::new()
        .get_or_allocate(&mut tx)
        .await
        .unwrap();
    let schema = outer_def.query.output.schema_sha256.clone();
    sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown',?)")
        .bind(head + 1).bind(&rid).bind(&author_bearer).bind(crate::named_views::REVISION).bind(serde_json::to_string(&rev).unwrap()).bind(&f.actor).bind("2026-10-26T00:00:00Z").bind(act).execute(&mut *tx).await.unwrap();
    let re = crate::named_views::read_event(&mut tx, &rid, i64::MAX)
        .await
        .unwrap();
    crate::projector::project(&mut tx, &re).await.unwrap();
    let apin = crate::named_views::Pin {
        view_id: rev.view_id.clone(),
        revision_id: rid.clone(),
        definition_sha256: rev.definition_sha256.clone(),
        schema_sha256: schema,
    };
    let authored_name = "view_authored_over_global";
    let transition = serde_json::to_value(crate::named_views::Transition {
        v: 1,
        view_id: rev.view_id.clone(),
        expected: None,
        action: crate::named_views::Action::Activate {
            name: authored_name.into(),
            pin: apin.clone(),
        },
    })
    .unwrap();
    let aid = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown',?)")
        .bind(head + 2).bind(&aid).bind(&author_bearer).bind(crate::named_views::TRANSITION).bind(serde_json::to_string(&transition).unwrap()).bind(&f.actor).bind("2026-10-26T00:00:00Z").bind(act).execute(&mut *tx).await.unwrap();
    let ae = crate::named_views::read_event(&mut tx, &aid, i64::MAX)
        .await
        .unwrap();
    crate::projector::project(&mut tx, &ae).await.unwrap();
    tx.commit().await.unwrap();
    for (label, view_name, view_pin) in [
        ("global", name.clone(), pin.clone()),
        ("authored", authored_name.to_string(), apin.clone()),
    ] {
        let (_q_pin, q_def) = crate::named_views::tests::planned(
            "outer-port",
            &format!("SELECT id FROM {view_name} ORDER BY id"),
            std::collections::BTreeMap::from([(
                view_name.clone(),
                crate::named_views::contract::Dependency::View(view_pin),
            )]),
        );
        let q = q_def.query.clone();
        let record = crate::kernel::create_record_as(&f.db, &f.actor, &home)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kernel_facets(record_id,key,value,as_of,event_seq) VALUES(?,'query',?,'2026-10-26',0)")
            .bind(&record)
            .bind(serde_json::to_string(&q).unwrap())
            .execute(f.db.write_pool())
            .await
            .unwrap();
        let envelope = crate::mcp::kernel_v2::artifacts::testing_governed_sql_input(
            &f.db,
            &f.actor,
            &record,
            &q.output.schema_sha256,
        )
        .await
        .unwrap();
        assert_eq!(
            envelope["source"]["execution_receipt"]["version"],
            serde_json::json!("native.governed-sql-port-receipt.v3"),
            "{label}"
        );
        let diags = envelope["source"]["execution_receipt"]["view_provenance"]
            ["generated_diagnostics"]
            .clone();
        let expected_root = if label == "global" {
            name.clone()
        } else {
            authored_name.to_string()
        };
        assert_eq!(
            diags,
            serde_json::json!([{"root":expected_root,"drift":"unchanged","unknown_reason":null}]),
            "{label}"
        );
        assert!(!diags.to_string().contains(&rid));
        assert!(!diags.to_string().contains(&pin.revision_id));
        let compiled = native_artifact_runtime::mdx::compile_v2_source(
            "<Metric label=\"Receipt\" value={1} />",
        )
        .unwrap();
        native_artifact_runtime::mdx_v2::render_verified(
            &compiled,
            Default::default(),
            &serde_json::json!({"version":native_artifact_runtime::mdx_v2::NAMED_INPUT_ABI,"mode":"named","inputs":{"rows":envelope},"records":[]}),
            &serde_json::json!({"$root":{"inputs":{"rows":envelope}}}),
        )
        .unwrap();
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_serving_import_then_select_serves() {
    let (f, home, _other, workspace) = real_global_setup().await;
    let bearer = crate::kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    let p = facet_resolver::prepare_profile(
        &f.db,
        &f.actor,
        &workspace,
        &bearer,
        crate::named_views::facet_resolver::Request {
            record_type: "WorkItem".into(),
            kind: Some("task".into()),
            home: home.clone(),
            selection: crate::query::generated_facets::Selection::Keys(
                ["area".to_string()].into_iter().collect(),
            ),
        },
        crate::query::generated_facets::Profile::Global1,
        deadline(),
    )
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS content_event_sources (event_id TEXT PRIMARY KEY REFERENCES content_events(id) ON DELETE CASCADE, origin_database_id TEXT NOT NULL, source_seq INTEGER NOT NULL, source_record_id TEXT NOT NULL, source_principal TEXT NOT NULL, source_fingerprint TEXT NOT NULL)",
    )
    .execute(f.db.write_pool())
    .await
    .unwrap();
    let view_id = p.revision.view_id.clone();
    let revision_id = uuid::Uuid::new_v4().to_string();
    let revision_event = crate::events::EventRow {
        local_seq: 1,
        id: revision_id.clone(),
        record_id: bearer.clone(),
        event_type: crate::named_views::REVISION.into(),
        payload: Some(serde_json::to_string(&p.revision).unwrap()),
        actor: None,
        created_at: "2026-10-26T00:00:00Z".into(),
        run_key: None,
        parent_key: None,
        intent: None,
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
        act: None,
    };
    crate::named_views::gate::testing(
        false,
        crate::store::exercise_named_view_import(&f.db, revision_event),
    )
    .await
    .unwrap();
    let pin = Pin {
        view_id: view_id.clone(),
        revision_id: revision_id.clone(),
        definition_sha256: p.revision.definition_sha256.clone(),
        schema_sha256: p.revision.definition["query"]["output"]["schema_sha256"]
            .as_str()
            .unwrap()
            .into(),
    };
    let name = p.name.clone();
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let previous = crate::named_views::storage::load_prefix(
        &mut f.db.pool().acquire().await.unwrap(),
        head,
        None,
    )
    .await
    .unwrap()
    .bindings
    .get(&view_id)
    .map(|b| b.event_id.clone());
    let transition = serde_json::to_value(crate::named_views::Transition {
        v: 1,
        view_id: view_id.clone(),
        expected: previous,
        action: crate::named_views::Action::Activate {
            name: name.clone(),
            pin: pin.clone(),
        },
    })
    .unwrap();
    let activation_event = crate::events::EventRow {
        local_seq: 1,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: bearer.clone(),
        event_type: crate::named_views::TRANSITION.into(),
        payload: Some(serde_json::to_string(&transition).unwrap()),
        actor: None,
        created_at: "2026-10-26T00:00:00Z".into(),
        run_key: None,
        parent_key: None,
        intent: None,
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
        act: None,
    };
    crate::named_views::gate::testing(
        false,
        crate::store::exercise_named_view_import(&f.db, activation_event),
    )
    .await
    .unwrap();
    let result = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &f.actor,
        serde_json::json!({"sql": format!("SELECT id FROM {name} ORDER BY id")}),
    )
    .await
    .unwrap();
    assert_eq!(result["rows"].as_array().unwrap().len(), 4);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_proposal_explicit_profile_reads_with_gate_off_and_no_effects() {
    let (f, home, _other, _workspace) = real_global_setup().await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let caller = crate::mcp::Caller::authenticated(&f.actor)
        .with_run_context(Some("eclipse-guitar-9z68bz".into()), None);
    // Producer flag stays OFF: this is a read, not an emission.
    let out = crate::named_views::gate::testing(
        false,
        crate::named_views::proposal::execute(
            &f.db,
            &f.actor,
            &caller,
            serde_json::json!({"action":"propose_view","id":f.anchor,
                "record_type":"WorkItem","kind":"task","home":home,
                "selection":{"kind":"keys","keys":["area"]},
                "profile":"facet-global-1"}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(
        out["definition"]["generated"]["format"],
        serde_json::json!("native.generated-facets.v2")
    );
    assert_eq!(
        out["definition"]["origin"]["version"],
        serde_json::json!("facet-global-1")
    );
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(f.db.pool())
            .await
            .unwrap()
    );
    // Facet-1 stays the default and never auto-switches; the diagnostic names
    // the explicit profile only after the View/existence checks. Use an
    // ID-bound declaration so facet-1 reaches its missing-H-governance check.
    f.import("schema_config","hint-id",Some(serde_json::json!({"id":"hint-id","layer":"pack","name":null,"data":serde_json::json!({"shapes":{"WorkItem:task":{"facets":{"other":{"vocab_ref":"rec:voc:area"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":"H1","created_at":"2026-10-26T00:00:02Z"}))).await;
    let error = crate::named_views::gate::testing(
        false,
        crate::named_views::proposal::execute(
            &f.db,
            &f.actor,
            &caller,
            serde_json::json!({"action":"propose_view","id":f.anchor,
                "record_type":"WorkItem","kind":"task","home":home,
                "selection":{"kind":"keys","keys":["other"]}}),
        ),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("profile=facet-global-1"), "{error}");
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_proposal_refuses_mismatched_origin_manifest_pair() {
    let (f, home, _other, _workspace) = real_global_setup().await;
    let mut def = facet_resolver::prepare_profile(
        &f.db,
        &f.actor,
        &crate::named_views::generated::workspace_on(&mut f.db.pool().acquire().await.unwrap())
            .await
            .unwrap(),
        &f.anchor,
        crate::named_views::facet_resolver::Request {
            record_type: "WorkItem".into(),
            kind: Some("task".into()),
            home: home.clone(),
            selection: crate::query::generated_facets::Selection::Keys(
                ["area".to_string()].into_iter().collect(),
            ),
        },
        crate::query::generated_facets::Profile::Global1,
        deadline(),
    )
    .await
    .unwrap()
    .revision
    .definition;
    def["origin"]["version"] = serde_json::json!("facet-1");
    let error =
        match crate::named_views::generated::prepare(&f.db, &f.actor, &f.anchor, &def, deadline())
            .await
        {
            Ok(_) => panic!("pair mismatch must refuse"),
            Err(error) => error.to_string(),
        };
    assert!(error.contains("pair mismatch"), "{error}");
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_prepare_mutate_writer_recheck_refuses_with_zero_effects() {
    // Each case: real prepare, then a mutation, then Writer::begin + recheck.
    // Refusal must leave content_events untouched.
    async fn case(mutate: impl AsyncFnOnce(&Fixture, &str)) -> String {
        let (f, home, _other, workspace) = real_global_setup().await;
        let p = facet_resolver::prepare_profile(
            &f.db,
            &f.actor,
            &workspace,
            &f.anchor,
            crate::named_views::facet_resolver::Request {
                record_type: "WorkItem".into(),
                kind: Some("task".into()),
                home: home.clone(),
                selection: crate::query::generated_facets::Selection::Keys(
                    ["area".to_string()].into_iter().collect(),
                ),
            },
            crate::query::generated_facets::Profile::Global1,
            deadline(),
        )
        .await
        .unwrap();
        mutate(&f, &home).await;
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        let mut writer = crate::named_views::source_proof::Writer::begin(&f.db, deadline())
            .await
            .unwrap();
        let error = match p.proof.recheck_on(&f.db, &mut writer, &f.actor).await {
            Ok(_) => panic!("mutation must refuse before writer effect"),
            Err(error) => error.to_string(),
        };
        drop(writer);
        assert_eq!(
            before,
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(f.db.pool())
                .await
                .unwrap(),
            "refusal must leave no write effects"
        );
        error
    }
    // New vocabulary row whose name collides with the admitted bare name.
    let collision = case(async |f, _home| {
        f.import(
            "vocabularies",
            "voc:other",
            Some(serde_json::json!({"id":"voc:other","name":"area"})),
        )
        .await;
    })
    .await;
    assert!(
        collision.contains("import since preparation") || collision.contains("reference changed"),
        "{collision}"
    );
    // Rename the retained vocabulary row.
    let rename = case(async |f, _home| {
        f.import(
            "vocabularies",
            "voc:area",
            Some(serde_json::json!({"id":"voc:area","name":"other"})),
        )
        .await;
    })
    .await;
    assert!(
        rename.contains("import since preparation") || rename.contains("reference changed"),
        "{rename}"
    );
    // Delete then reinsert the retained vocabulary row (ID rebind evidence).
    let rebind = case(async |f, _home| {
        f.import("vocabularies", "voc:area", None).await;
        f.import(
            "vocabularies",
            "voc:area",
            Some(serde_json::json!({"id":"voc:area","name":"area"})),
        )
        .await;
    })
    .await;
    assert!(
        rebind.contains("import since preparation") || rebind.contains("reference changed"),
        "{rebind}"
    );
    // New H-anchored shape (H becomes directly governed).
    let home_shape = case(async |f, home| {
        f.import("schema_config","home-new",Some(serde_json::json!({"id":"home-new","layer":"pack","name":null,"data":serde_json::json!({"shapes":{"WorkItem:task":{"facets":{"area":{"description":"H"}}}}}).to_string(),"applies_to_collection_id":home,"version_lineage":"H9","created_at":"2026-10-26T00:00:03Z"}))).await;
    })
    .await;
    assert!(
        home_shape.contains("import since preparation") || home_shape.contains("reference changed"),
        "{home_shape}"
    );
    // Changed/stale global winning declaration.
    let stale = case(async |f, _home| {
        f.import("schema_config","global",Some(serde_json::json!({"id":"global","layer":"pack","name":null,"data":serde_json::json!({"shapes":{"WorkItem:task":{"facets":{"area":{"description":"Changed","vocab_ref":"area"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":"G2","created_at":"2026-10-26T00:00:04Z"}))).await;
    })
    .await;
    assert!(
        stale.contains("import since preparation") || stale.contains("reference changed"),
        "{stale}"
    );
    // Positive control: an unrelated ordinary write does not trip the window.
    let (f, home, _other, workspace) = real_global_setup().await;
    let p = facet_resolver::prepare_profile(
        &f.db,
        &f.actor,
        &workspace,
        &f.anchor,
        crate::named_views::facet_resolver::Request {
            record_type: "WorkItem".into(),
            kind: Some("task".into()),
            home: home.clone(),
            selection: crate::query::generated_facets::Selection::Keys(
                ["area".to_string()].into_iter().collect(),
            ),
        },
        crate::query::generated_facets::Profile::Global1,
        deadline(),
    )
    .await
    .unwrap();
    crate::kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    let mut writer = crate::named_views::source_proof::Writer::begin(&f.db, deadline())
        .await
        .unwrap();
    p.proof
        .recheck_on(&f.db, &mut writer, &f.actor)
        .await
        .expect("unrelated write keeps the same-section window clean");
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_public_workflow_proposal_draft_activation_select() {
    let (f, home, _other, _workspace) = real_global_setup().await;
    let caller = crate::mcp::Caller::authenticated(&f.actor)
        .with_run_context(Some("eclipse-guitar-9z68bz".into()), None);
    let args = || {
        serde_json::json!({"action":"propose_view","id":f.anchor,
            "record_type":"WorkItem","kind":"task","home":home,
            "selection":{"kind":"keys","keys":["area"]},
            "profile":"facet-global-1"})
    };
    // Proposal is a read: gate OFF still returns the exact definition.
    let proposal = crate::named_views::gate::testing(
        false,
        crate::named_views::proposal::execute(&f.db, &f.actor, &caller, args()),
    )
    .await
    .unwrap();
    let definition = proposal["definition"].clone();
    let name = proposal["name"].as_str().unwrap().to_owned();
    // Gate OFF: draft refuses without effects.
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let off = crate::named_views::gate::testing(
        false,
        super::generated_operation(
            &f,
            serde_json::json!({"action":"record_view_revision","id":f.anchor,
                "definition":definition.clone(),"idempotency_key":"step3b-off"}),
        ),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(off.contains("disabled"), "{off}");
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(f.db.pool())
            .await
            .unwrap()
    );
    // Gate ON: the trusted candidate drafts and the owner activates it.
    let draft = crate::named_views::gate::testing(
        true,
        super::generated_operation(
            &f,
            serde_json::json!({"action":"record_view_revision","id":f.anchor,
                "definition":definition,"idempotency_key":"step3b-draft"}),
        ),
    )
    .await
    .unwrap();
    let pin = draft["pin"].clone();
    // Activation still refuses while the producer flag is OFF.
    let activation_off = crate::named_views::gate::testing(
        false,
        super::generated_operation(
            &f,
            serde_json::json!({"action":"activate_view","id":f.anchor,"pin":pin.clone(),
                "name":name,"expected_binding_event_id":null,"idempotency_key":"step3b-act-off"}),
        ),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(activation_off.contains("disabled"), "{activation_off}");
    crate::named_views::gate::testing(
        true,
        super::generated_operation(
            &f,
            serde_json::json!({"action":"activate_view","id":f.anchor,"pin":pin,
                "name":name,"expected_binding_event_id":null,"idempotency_key":"step3b-act"}),
        ),
    )
    .await
    .unwrap();
    let result = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &f.actor,
        serde_json::json!({"sql": format!("SELECT id, area FROM {name} ORDER BY id")}),
    )
    .await
    .unwrap();
    let rows = result["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 4, "{rows:?}");
    assert!(rows
        .iter()
        .filter(|r| r["id"] != "rec-area-bad")
        .all(|r| r["area"] == serde_json::json!("high")));
    // A stale proposal is recomputed and refuses deterministically.
    let stale = crate::named_views::gate::testing(
        false,
        crate::named_views::proposal::execute(&f.db, &f.actor, &caller, args()),
    )
    .await
    .unwrap()["definition"]
        .clone();
    f.import(
        "vocabularies",
        "voc:other",
        Some(serde_json::json!({"id":"voc:other","name":"area"})),
    )
    .await;
    let stale_error = crate::named_views::gate::testing(
        true,
        super::generated_operation(
            &f,
            serde_json::json!({"action":"record_view_revision","id":f.anchor,
                "definition":stale,"idempotency_key":"step3b-stale"}),
        ),
    )
    .await
    .unwrap_err()
    .to_string();
    // Fresh trusted resolution may refuse the new ambiguity before comparing
    // the stale candidate; either way the stale proposal cannot draft.
    assert!(
        stale_error.contains("view_source_changed")
            || stale_error.contains("ambiguous vocabulary reference"),
        "{stale_error}"
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_activation_referenced_guard_detects_import_races() {
    use crate::mcp::registry::{Caller, EngineHandle, ToolRegistry, WritePlanExecution};
    for change in ["delete_vocab", "new_h_shape", "collision"] {
        let (f, home, _other, _workspace) = real_global_setup().await;
        let p = facet_resolver::prepare_profile(
            &f.db,
            &f.actor,
            &crate::named_views::generated::workspace_on(&mut f.db.pool().acquire().await.unwrap())
                .await
                .unwrap(),
            &f.anchor,
            crate::named_views::facet_resolver::Request {
                record_type: "WorkItem".into(),
                kind: Some("task".into()),
                home: home.clone(),
                selection: crate::query::generated_facets::Selection::Keys(
                    ["area".to_string()].into_iter().collect(),
                ),
            },
            crate::query::generated_facets::Profile::Global1,
            deadline(),
        )
        .await
        .unwrap();
        let name = p.name.clone();
        let draft = crate::named_views::gate::testing(
            true,
            super::generated_operation(
                &f,
                serde_json::json!({"action":"record_view_revision","id":f.anchor,
                    "definition":p.revision.definition,"idempotency_key":format!("race-draft-{change}")}),
            ),
        )
        .await
        .unwrap();
        let pin = draft["pin"].clone();
        let args = serde_json::json!({"action":"activate_view","id":f.anchor,"pin":pin,
            "name":name,"expected_binding_event_id":null,
            "idempotency_key":format!("race-act-{change}")});
        let caller = Caller::authenticated("acct:proof")
            .with_hosting_context("proof", "workspace")
            .with_hosting_owner(true)
            .with_write_plan_execution(WritePlanExecution {
                plan_id: format!("global-race-{change}"),
                effect_digest: format!("global-race-effect-{change}"),
                executor: "records_write".into(),
                operation: "activate_view".into(),
            });
        // Activation preflight carries the referenced proof, not the draft proof.
        let prepared = crate::named_views::gate::testing(
            true,
            crate::mcp::kernel_v2::writes::named_views::prepare_commit(
                &f.db, &f.actor, &caller, &args,
            ),
        )
        .await
        .unwrap();
        match change {
            "delete_vocab" => f.import("vocabularies", "voc:area", None).await,
            "new_h_shape" => {
                f.import("schema_config","race-home",Some(serde_json::json!({"id":"race-home","layer":"pack","name":null,"data":serde_json::json!({"shapes":{"WorkItem:task":{"facets":{"area":{"description":"H"}}}}}).to_string(),"applies_to_collection_id":home,"version_lineage":"H9","created_at":"2026-10-26T00:00:05Z"}))).await;
            }
            _ => {
                f.import(
                    "vocabularies",
                    "voc:other",
                    Some(serde_json::json!({"id":"voc:other","name":"area"})),
                )
                .await;
            }
        }
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).unwrap();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
        let error = crate::named_views::gate::testing(
            true,
            crate::mcp::kernel_v2::writes::named_views::with_prevalidated(
                prepared,
                registry.call_engine(
                    EngineHandle::KernelV2(f.db.clone()),
                    caller,
                    "manage_named_views",
                    args,
                ),
            ),
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(
            before,
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(f.db.pool())
                .await
                .unwrap(),
            "{change} refusal must leave no write effects"
        );
        assert!(
            error.contains("reference changed")
                || error.contains("import since preparation")
                || error.contains("anchor placement changed"),
            "{change}: {error}"
        );
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_export_is_deterministic_canonical_and_side_effect_free() {
    let (f, home, _other, _workspace) = real_global_setup().await;
    let path = super::export_copy(&f, "global-export.db").await;
    let file_before = std::fs::read(&path).unwrap();
    let dir_before: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    let request = || -> crate::named_views::export::Request {
        serde_json::from_value(serde_json::json!({"actor":f.actor,"bearer":f.anchor,
            "record_type":"WorkItem","kind":"task","home":home,
            "selection":{"kind":"keys","keys":["area"]},
            "profile":"facet-global-1"}))
        .unwrap()
    };
    let before_events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let first = crate::named_views::export::export_file(&path, request())
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(
        first,
        native_artifact_runtime::mdx_v2::canonical_json_bytes(&value),
        "export bytes must be canonical"
    );
    assert_eq!(
        value["definition"]["origin"]["version"],
        serde_json::json!("facet-global-1")
    );
    assert_eq!(
        value["definition"]["generated"]["format"],
        serde_json::json!("native.generated-facets.v2")
    );
    let second = crate::named_views::export::export_file(&path, request())
        .await
        .unwrap();
    assert_eq!(first, second, "export must be deterministic");
    assert_eq!(
        file_before,
        std::fs::read(&path).unwrap(),
        "offline copy bytes must not change"
    );
    let mut dir_after: Vec<_> = std::fs::read_dir(path.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    dir_after.sort();
    let mut dir_before = dir_before;
    dir_before.sort();
    assert_eq!(dir_before, dir_after, "no sidecar files may appear");
    assert_eq!(
        before_events,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(f.db.pool())
            .await
            .unwrap(),
        "export must not mutate the source database"
    );
    // Unknown profile refuses before any preparation or effect.
    let unknown: crate::named_views::export::Request =
        serde_json::from_value(serde_json::json!({"actor":f.actor,"bearer":f.anchor,
            "record_type":"WorkItem","kind":"task","home":home,
            "selection":{"kind":"keys","keys":["area"]},
            "profile":"facet-9"}))
        .unwrap();
    let error = crate::named_views::export::export_file(&path, unknown)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("view_profile_unsupported"), "{error}");
    assert_eq!(file_before, std::fs::read(&path).unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_proposal_hidden_bearer_matches_missing_without_disclosure() {
    let (f, home, _other, _workspace) = real_global_setup().await;
    let visitor =
        crate::kernel::create_principal(&f.db, "account", "Visitor", "acct:visitor", &f.actor)
            .await
            .unwrap();
    let caller = crate::mcp::Caller::authenticated(&visitor)
        .with_run_context(Some("eclipse-guitar-9z68bz".into()), None);
    let request = |id: &str| {
        serde_json::json!({"action":"propose_view","id":id,
            "record_type":"WorkItem","kind":"task","home":home,
            "selection":{"kind":"keys","keys":["area"]},
            "profile":"facet-global-1"})
    };
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let hidden = crate::named_views::gate::testing(
        false,
        crate::named_views::proposal::execute(&f.db, &visitor, &caller, request(&f.anchor)),
    )
    .await
    .unwrap_err()
    .to_string();
    let absent = crate::named_views::gate::testing(
        false,
        crate::named_views::proposal::execute(
            &f.db,
            &visitor,
            &caller,
            request(&uuid::Uuid::new_v4().to_string()),
        ),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(hidden, absent, "hidden bearer must be indistinguishable");
    for leak in [
        "facet-global-1",
        "governing declaration",
        "generated-facets.v2",
        "profile=",
    ] {
        assert!(
            !hidden.contains(leak),
            "hidden refusal leaked {leak}: {hidden}"
        );
    }
    assert_eq!(
        before,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(f.db.pool())
            .await
            .unwrap()
    );
}

/// Isolated HQ single-home world: faithful `hq-global.json` declarations copied
/// verbatim, synthetic H plus another home with synthetic task members.
async fn hq_global_world() -> (Fixture, String, String, Pin, String) {
    let f = Fixture::new().await;
    let package = crate::v2_standard::v1_compat::package();
    let installed = crate::kernel::install_package_as(&f.db, &f.actor, &package)
        .await
        .unwrap();
    crate::kernel::adopt_package_at(
        &f.db,
        &f.actor,
        KERNEL_ROOT_ID,
        &package,
        Some(&installed),
        &[],
    )
    .await
    .unwrap();
    let workspace =
        crate::named_views::generated::workspace_on(&mut f.db.pool().acquire().await.unwrap())
            .await
            .unwrap();
    let home = crate::kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    let other = crate::kernel::create_home(
        &f.db,
        KERNEL_ROOT_ID,
        Some(&[(&f.actor, "manage")]),
        &f.actor,
    )
    .await
    .unwrap();
    let hq: serde_json::Value = serde_json::from_str(include_str!(
        "../../query/generated_facets/fixtures/hq-global.json"
    ))
    .unwrap();
    // Source-only fixture provenance: caller-visible declarations at seq90923.
    assert_eq!(hq["observation"]["as_of_seq"], serde_json::json!(90923));
    for row in hq["schema"].as_array().unwrap() {
        let mut row = row.clone();
        if row.get("name").is_none() {
            row["name"] = serde_json::Value::Null;
        }
        let id = row["id"].as_str().unwrap().to_owned();
        f.import("schema_config", &id, Some(row)).await;
    }
    for vocab in hq["vocabularies"].as_array().unwrap() {
        f.import(
            "vocabularies",
            vocab["id"].as_str().unwrap(),
            Some(vocab.clone()),
        )
        .await;
    }
    for value in hq["values"].as_array().unwrap() {
        f.import(
            "vocabulary_values",
            value["id"].as_str().unwrap(),
            Some(value.clone()),
        )
        .await;
    }
    for (id, home_id, area, lane) in [
        ("hq-task-1", &home, "ci", "direction"),
        ("hq-task-2", &home, "mcp", "platform"),
        ("hq-other-1", &other, "ci", "direction"),
    ] {
        let facets = vec![
            crate::kernel::FacetObservation {
                key: "area".into(),
                value: Some(area.into()),
                value_num: None,
                vocab_ref: Some("area".into()),
                as_of: "2026-10-26T00:00:00Z".into(),
            },
            crate::kernel::FacetObservation {
                key: "strategy_lane".into(),
                value: Some(lane.into()),
                value_num: None,
                vocab_ref: Some("strategy-lane".into()),
                as_of: "2026-10-26T00:00:00Z".into(),
            },
        ];
        crate::kernel::import_record_as(
            &f.db,
            &f.host,
            id,
            home_id,
            Some(&f.actor),
            &crate::kernel::ImportRecordState {
                definition: Some(crate::kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: crate::v2_standard::v1_compat::FAMILY.into(),
                        version: 1,
                        digest: crate::meta::definition_artifact::digest_artifact_bytes(
                            crate::v2_standard::v1_compat::DEFINITION.as_bytes(),
                        ),
                    },
                    primary_type: "V1".into(),
                    kind: "record".into(),
                    fields: serde_json::json!({"v1_type":"WorkItem","v1_kind":"task","title":id})
                        .as_object()
                        .unwrap()
                        .clone(),
                }),
                facets,
                archived: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let p = facet_resolver::prepare_profile(
        &f.db,
        &f.actor,
        &workspace,
        &f.anchor,
        crate::named_views::facet_resolver::Request {
            record_type: "WorkItem".into(),
            kind: Some("task".into()),
            home: home.clone(),
            selection: crate::query::generated_facets::Selection::Keys(
                ["area".to_string(), "strategy_lane".to_string()]
                    .into_iter()
                    .collect(),
            ),
        },
        crate::query::generated_facets::Profile::Global1,
        deadline(),
    )
    .await
    .unwrap();
    let name = p.name.clone();
    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
    let head: i64 = sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let act = crate::act::ActAllocation::new()
        .get_or_allocate(&mut tx)
        .await
        .unwrap();
    sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown',?)")
        .bind(head + 1).bind(&id).bind(&f.anchor).bind(REVISION).bind(serde_json::to_string(&p.revision).unwrap()).bind(&f.actor).bind("2026-10-26T00:00:00Z").bind(act).execute(&mut *tx).await.unwrap();
    let r = read_event(&mut tx, &id, i64::MAX).await.unwrap();
    crate::projector::project(&mut tx, &r).await.unwrap();
    let pin = Pin {
        view_id: p.revision.view_id.clone(),
        revision_id: id.clone(),
        definition_sha256: p.revision.definition_sha256.clone(),
        schema_sha256: p.revision.definition["query"]["output"]["schema_sha256"]
            .as_str()
            .unwrap()
            .into(),
    };
    let transition = serde_json::to_value(crate::named_views::Transition {
        v: 1,
        view_id: p.revision.view_id.clone(),
        expected: None,
        action: crate::named_views::Action::Activate {
            name: name.clone(),
            pin: pin.clone(),
        },
    })
    .unwrap();
    let aid = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO content_events(seq,id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status,act) VALUES(?,?,?,?,?,?,?,1,'legacy_unknown',?)")
        .bind(head + 2).bind(&aid).bind(&f.anchor).bind(crate::named_views::TRANSITION).bind(serde_json::to_string(&transition).unwrap()).bind(&f.actor).bind("2026-10-26T00:00:00Z").bind(act).execute(&mut *tx).await.unwrap();
    let a = read_event(&mut tx, &aid, i64::MAX).await.unwrap();
    crate::projector::project(&mut tx, &a).await.unwrap();
    tx.commit().await.unwrap();
    (f, home, other, pin, name)
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_hq_single_home_proposal_export_and_select() {
    let (f, home, _other, pin, name) = hq_global_world().await;
    let caller = crate::mcp::Caller::authenticated(&f.actor)
        .with_run_context(Some("eclipse-guitar-9z68bz".into()), None);
    let args = |profile: &str| {
        serde_json::json!({"action":"propose_view","id":f.anchor,
            "record_type":"WorkItem","kind":"task","home":home,
            "selection":{"kind":"keys","keys":["area","strategy_lane"]},
            "profile":profile})
    };
    let proposal = crate::named_views::gate::testing(
        false,
        crate::named_views::proposal::execute(&f.db, &f.actor, &caller, args("facet-global-1")),
    )
    .await
    .unwrap();
    assert_eq!(
        proposal["definition"]["generated"]["format"],
        serde_json::json!("native.generated-facets.v2")
    );
    assert_eq!(
        proposal["definition"]["origin"]["version"],
        serde_json::json!("facet-global-1")
    );
    // Default facet-1 refuses and creates no candidate. HQ bare-name area and
    // strategy-lane references fail facet-1 vocabulary binding (ID-only), so
    // this path does NOT reach the global-profile hint; the ID-bound hint test
    // covers that diagnostic separately. Product ordering is unchanged.
    let before_events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let facet1 = crate::named_views::gate::testing(
        false,
        crate::named_views::proposal::execute(
            &f.db,
            &f.actor,
            &caller,
            serde_json::json!({"action":"propose_view","id":f.anchor,
                "record_type":"WorkItem","kind":"task","home":home,
                "selection":{"kind":"keys","keys":["area","strategy_lane"]}}),
        ),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        facet1.contains("required vocabulary unavailable"),
        "facet-1 must refuse at vocabulary binding: {facet1}"
    );
    assert!(!facet1.contains("profile=facet-global-1"), "{facet1}");
    assert_eq!(
        before_events,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(f.db.pool())
            .await
            .unwrap()
    );
    // Export on an immutable VACUUM INTO copy: exact pair, deterministic.
    let path = super::export_copy(&f, "hq-global-export.db").await;
    let before = std::fs::read(&path).unwrap();
    let request = || -> crate::named_views::export::Request {
        serde_json::from_value(serde_json::json!({"actor":f.actor,"bearer":f.anchor,
            "record_type":"WorkItem","kind":"task","home":home,
            "selection":{"kind":"keys","keys":["area","strategy_lane"]},
            "profile":"facet-global-1"}))
        .unwrap()
    };
    let first = crate::named_views::export::export_file(&path, request())
        .await
        .unwrap();
    let second = crate::named_views::export::export_file(&path, request())
        .await
        .unwrap();
    assert_eq!(first, second, "export must be deterministic");
    let value: serde_json::Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(value["definition"], proposal["definition"]);
    assert_eq!(before, std::fs::read(&path).unwrap());
    // The activated view serves only H direct members with exact mappings.
    let result = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &f.actor,
        serde_json::json!({"sql": format!(
            "SELECT id, area, strategy_lane FROM {name} ORDER BY id"
        )}),
    )
    .await
    .unwrap();
    let rows = result["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0]["id"], serde_json::json!("hq-task-1"));
    assert_eq!(rows[0]["area"], serde_json::json!("ci"));
    assert_eq!(rows[0]["strategy_lane"], serde_json::json!("direction"));
    assert_eq!(rows[1]["area"], serde_json::json!("mcp"));
    assert_eq!(rows[1]["strategy_lane"], serde_json::json!("platform"));
    let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
        .bind(&pin.revision_id)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert!(
        payload.contains("IN ('area', 'rec:voc:area', 'voc:area')"),
        "{payload}"
    );
    assert!(
        payload.contains("IN ('rec:voc:strategy-lane', 'strategy-lane', 'voc:strategy-lane')"),
        "{payload}"
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_attention_subset_selection_rules() {
    let (f, home, _other, _workspace) = real_global_setup().await;
    // Representative HQ attention-v1 carrier classes, not a verbatim capture of
    // the private declaration: for_person/ask/slip_count plus due:when,
    // instant, inline-choice and object classes. hq-global.json task
    // declarations remain the verbatim seq90923 copy.
    f.import("schema_config","attention-global",Some(serde_json::json!({"id":"attention-global","layer":"user","name":null,
        "data":serde_json::json!({"shapes":{"WorkItem:attention":{"facets":{
        "for_person":{"required":true},"ask":{"required":true},"slip_count":{"type":"number"},
        "due":{"type":"when"},"snoozed_until":{"type":"instant"},
        "attention_kind":{"values":["decision","review","unblock","input"],"required":true},
        "options":{"type":"object","json_schema":{"type":"object"}}
    }}}}).to_string(),"applies_to_collection_id":null,"version_lineage":"attention-v1","created_at":"2026-10-26T00:00:00Z"}))).await;
    for (id, with_person) in [("att-full", true), ("att-missing-person", false)] {
        let mut facets = vec![crate::kernel::FacetObservation {
            key: "ask".into(),
            value: Some("review".into()),
            value_num: None,
            vocab_ref: None,
            as_of: "2026-10-26T00:00:00Z".into(),
        }];
        if with_person {
            facets.push(crate::kernel::FacetObservation {
                key: "for_person".into(),
                value: Some("acct:proof".into()),
                value_num: None,
                vocab_ref: None,
                as_of: "2026-10-26T00:00:00Z".into(),
            });
        }
        facets.push(crate::kernel::FacetObservation {
            key: "slip_count".into(),
            value: Some("2".into()),
            value_num: Some(2.0),
            vocab_ref: None,
            as_of: "2026-10-26T00:00:00Z".into(),
        });
        crate::kernel::import_record_as(
            &f.db,
            &f.host,
            id,
            &home,
            Some(&f.actor),
            &crate::kernel::ImportRecordState {
                definition: Some(crate::kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: crate::v2_standard::v1_compat::FAMILY.into(),
                        version: 1,
                        digest: crate::meta::definition_artifact::digest_artifact_bytes(
                            crate::v2_standard::v1_compat::DEFINITION.as_bytes(),
                        ),
                    },
                    primary_type: "V1".into(),
                    kind: "record".into(),
                    fields:
                        serde_json::json!({"v1_type":"WorkItem","v1_kind":"attention","title":id})
                            .as_object()
                            .unwrap()
                            .clone(),
                }),
                facets,
                archived: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    let workspace =
        crate::named_views::generated::workspace_on(&mut f.db.pool().acquire().await.unwrap())
            .await
            .unwrap();
    async fn prepare(
        f: &Fixture,
        workspace: &str,
        home: &str,
        selection: crate::query::generated_facets::Selection,
    ) -> Result<facet_resolver::Prepared, crate::Error> {
        facet_resolver::prepare_profile(
            &f.db,
            &f.actor,
            workspace,
            &f.anchor,
            crate::named_views::facet_resolver::Request {
                record_type: "WorkItem".into(),
                kind: Some("attention".into()),
                home: home.into(),
                selection,
            },
            crate::query::generated_facets::Profile::Global1,
            deadline(),
        )
        .await
    }
    let keys = |items: &[&str]| {
        crate::query::generated_facets::Selection::Keys(
            items.iter().map(|s| s.to_string()).collect(),
        )
    };
    let p = prepare(
        &f,
        &workspace,
        &home,
        keys(&["for_person", "ask", "slip_count"]),
    )
    .await
    .unwrap();
    let def: v2::Definition<v2::GlobalManifest> =
        serde_json::from_value(p.revision.definition.clone()).unwrap();
    let selected: std::collections::BTreeSet<_> = def
        .generated
        .slots
        .iter()
        .flat_map(|s| s.fragments.iter().map(|f| f.key.clone()))
        .collect();
    assert_eq!(
        selected,
        ["ask", "for_person", "slip_count"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    // required:true is not enforced: the member missing for_person still returns.
    let validated = p.validate(deadline()).await.unwrap();
    let rows =
        crate::mcp::kernel_v2::query_pinned_saved_sql(&f.db, &f.actor, &validated.definition.query)
            .await
            .unwrap();
    let rows = rows["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{rows:?}");
    let missing = rows
        .iter()
        .find(|r| r["id"] == serde_json::json!("att-missing-person"))
        .unwrap();
    assert!(missing["for_person"].is_null());
    assert_eq!(missing["for_person__status"], serde_json::json!("missing"));
    // Each unsupported carrier refuses on its own; all includes them and refuses.
    for key in ["due", "snoozed_until", "attention_kind", "options"] {
        let error = prepare(&f, &workspace, &home, keys(&[key]))
            .await
            .err()
            .expect("unsupported carrier must refuse")
            .to_string();
        assert!(error.contains("Unsupported"), "{key}: {error}");
    }
    let error = prepare(
        &f,
        &workspace,
        &home,
        crate::query::generated_facets::Selection::All,
    )
    .await
    .err()
    .expect("all must refuse")
    .to_string();
    assert!(error.contains("Unsupported"), "{error}");
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_hq_compose_part_of_and_history_statement() {
    let (f, home, _other, _pin, name) = hq_global_world().await;
    let parent_a = crate::kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    let parent_b = crate::kernel::create_record_as(&f.db, &f.actor, &home)
        .await
        .unwrap();
    crate::kernel::add_generic_link_as(&f.db, &f.actor, "hq-task-2", &parent_a, "part_of", None)
        .await
        .unwrap();
    crate::kernel::add_generic_link_as(&f.db, &f.actor, "hq-task-2", &parent_b, "part_of", None)
        .await
        .unwrap();
    // Hidden parent/edge coverage stays with the existing published part_of
    // fixture; this case adds 0/1/many and COUNT privacy only.
    let composed = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &f.actor,
        serde_json::json!({"sql": format!(
            "SELECT v.id AS id, l.target_id AS parent_id FROM {name} v \
             LEFT JOIN links l ON l.source_id=v.id AND l.relationship='part_of' \
             ORDER BY v.id, l.target_id"
        )}),
    )
    .await
    .unwrap();
    let rows = composed["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{rows:?}");
    assert_eq!(rows[0]["id"], serde_json::json!("hq-task-1"));
    assert!(rows[0]["parent_id"].is_null());
    assert_eq!(rows[1]["id"], serde_json::json!("hq-task-2"));
    let mut parents = [parent_a.clone(), parent_b.clone()];
    parents.sort();
    assert_eq!(rows[1]["parent_id"], serde_json::json!(parents[0]));
    assert_eq!(rows[2]["parent_id"], serde_json::json!(parents[1]));
    // COUNT privacy: one row per task, not one per parent.
    let counts = crate::mcp::kernel_v2::sql::query_sql(
        &f.db,
        &f.actor,
        serde_json::json!({"sql": format!(
            "SELECT v.id AS id, COUNT(l.target_id) AS parents FROM {name} v \
             LEFT JOIN links l ON l.source_id=v.id AND l.relationship='part_of' \
             GROUP BY v.id ORDER BY v.id"
        )}),
    )
    .await
    .unwrap();
    let counts = counts["rows"].as_array().unwrap();
    assert_eq!(counts.len(), 2, "{counts:?}");
    assert_eq!(counts[0]["parents"], serde_json::json!(0));
    assert_eq!(counts[1]["parents"], serde_json::json!(2));
    // History is a separate caller statement, never a named relation, and is
    // scoped by caller history disclosure. Visible actor sees a record's own
    // events; an imported row with no own events is empty (not hidden). A
    // principal without View on a record that has own events must be
    // indistinguishable from a nonexistent record: no local_seq/type leak.
    let history = |actor: String, id: String| {
        let f = &f;
        async move {
            crate::mcp::kernel_v2::sql::query_sql(
                &f.db,
                &actor,
                serde_json::json!({"sql":"SELECT local_seq,id,type,created_at FROM content_events WHERE record_id=?1 ORDER BY local_seq DESC,id LIMIT 20","parameters":[id]}),
            )
            .await
        }
    };
    let parent_history = history(f.actor.clone(), parent_a.clone()).await.unwrap();
    let rows = parent_history["rows"].as_array().unwrap();
    assert!(!rows.is_empty());
    let seqs: Vec<i64> = rows
        .iter()
        .map(|r| r["local_seq"].as_i64().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[0] >= w[1]), "{seqs:?}");
    assert!(seqs.len() <= 20);
    // local_seq is unique per record, so no artificial tie is possible here.
    let unique: std::collections::BTreeSet<_> = seqs.iter().collect();
    assert_eq!(
        unique.len(),
        seqs.len(),
        "local_seq must be unique per record"
    );
    // Imported view rows carry no own events: empty because absent, not hidden.
    let imported = history(f.actor.clone(), "hq-task-1".into()).await.unwrap();
    assert!(
        imported["rows"].as_array().unwrap().is_empty(),
        "imported row has no own events (not a hidden record)"
    );
    // A principal without View on parent_a (which has own events) matches a
    // nonexistent record exactly.
    let visitor = crate::kernel::create_principal(
        &f.db,
        "account",
        "Visitor",
        "acct:visitor-history",
        &f.actor,
    )
    .await
    .unwrap();
    let denied = history(visitor.clone(), parent_a.clone()).await;
    let absent = history(visitor, "no-such-record".into()).await;
    match (denied, absent) {
        (Ok(denied), Ok(absent)) => {
            // No row values leak; the closed column shape is identical too.
            assert!(denied["rows"].as_array().unwrap().is_empty());
            assert_eq!(denied["rows"], absent["rows"]);
            assert_eq!(denied["columns"], absent["columns"]);
        }
        (Err(denied), Err(absent)) => assert_eq!(denied.to_string(), absent.to_string()),
        (denied, absent) => panic!("history disclosure differs: {denied:?} vs {absent:?}"),
    }
}

async fn global_drift(f: &Fixture, pin: &Pin) -> Result<Drift, crate::Error> {
    let mut tx = f.db.governed_pool().begin().await.unwrap();
    let mut snapshot = ComparisonSnapshot::default();
    let result = inspect_global_on(
        &mut tx,
        &f.actor,
        "trusted-workspace",
        pin,
        deadline(),
        &mut snapshot,
    )
    .await
    .map(|c| c.drift);
    tx.rollback().await.unwrap();
    result
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_retained_freezes_names_and_detects_change() {
    // Baseline: present old ID, faithful snapshot — continuity, no drift.
    let f = Fixture::new().await;
    global_declared(&f).await;
    let p = global_candidate(&f, &["area"]).await.unwrap();
    let pin = commit_global(&f, &p).await;
    assert_eq!(global_drift(&f, &pin).await.unwrap(), Drift::Unchanged);
    // Irrelevant rows never move the frozen assessment.
    f.import(
        "vocabularies",
        "voc:unrelated",
        Some(json!({"id":"voc:unrelated","name":"unrelated"})),
    )
    .await;
    assert_eq!(global_drift(&f, &pin).await.unwrap(), Drift::Unchanged);
    // A present old ID with a new name is advisory Changed, never retargeting.
    f.import(
        "vocabularies",
        "voc:area",
        Some(json!({"id":"voc:area","name":"other"})),
    )
    .await;
    assert_eq!(global_drift(&f, &pin).await.unwrap(), Drift::Changed);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_retained_collision_absence_and_home_governance() {
    // A new competing row for the admitted name is Changed even though the
    // old references did not change.
    let f = Fixture::new().await;
    global_declared(&f).await;
    let p = global_candidate(&f, &["area"]).await.unwrap();
    let pin = commit_global(&f, &p).await;
    f.import(
        "vocabularies",
        "voc:other",
        Some(json!({"id":"voc:other","name":"area"})),
    )
    .await;
    assert_eq!(global_drift(&f, &pin).await.unwrap(), Drift::Changed);
    // A missing required vocabulary is a refusal, never silent absence.
    let g = Fixture::new().await;
    global_declared(&g).await;
    let q = global_candidate(&g, &["area"]).await.unwrap();
    let qpin = commit_global(&g, &q).await;
    g.import("vocabularies", "voc:area", None).await;
    let error = global_drift(&g, &qpin).await.unwrap_err();
    assert!(error.to_string().contains("missing"), "{error}");
    // Direct H governance is Changed; the name carrier stays frozen.
    let h = Fixture::new().await;
    global_declared(&h).await;
    let r = global_candidate(&h, &["area"]).await.unwrap();
    let rpin = commit_global(&h, &r).await;
    let home = r.revision.definition["generated"]["context"]["logical_home_id"]
        .as_str()
        .unwrap()
        .to_owned();
    h.import("schema_config","home-shape",Some(json!({"id":"home-shape","layer":"pack","name":null,"data":json!({"shapes":{"WorkItem":{"facets":{"area":{"description":"Governed directly"}}}}}).to_string(),"applies_to_collection_id":home,"version_lineage":"H9","created_at":"2026-10-26T00:00:01Z"}))).await;
    assert_eq!(global_drift(&h, &rpin).await.unwrap(), Drift::Changed);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_retained_malformed_home_is_unknown_after_mandatory_checks() {
    use crate::named_views::source_proof::ComparisonReason;
    let f = Fixture::new().await;
    global_declared(&f).await;
    let p = global_candidate(&f, &["area"]).await.unwrap();
    let pin = commit_global(&f, &p).await;
    let home = p.revision.definition["generated"]["context"]["logical_home_id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Malformed current home shapes are advisory Unknown, not refusal.
    f.import("schema_config","home-bad",Some(json!({"id":"home-bad","layer":"pack","name":null,"data":json!({"shapes":"not-an-object"}).to_string(),"applies_to_collection_id":home,"version_lineage":"H9","created_at":"2026-10-26T00:00:03Z"}))).await;
    let mut tx = f.db.governed_pool().begin().await.unwrap();
    let mut snapshot = ComparisonSnapshot::default();
    let checked = inspect_global_on(
        &mut tx,
        &f.actor,
        "trusted-workspace",
        &pin,
        deadline(),
        &mut snapshot,
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(checked.drift, Drift::Unknown);
    assert_eq!(checked.unknown_reason, Some(ComparisonReason::Unsupported));
    // Mandatory authority checks still refuse first with a malformed home
    // present: no Unknown laundering of a missing workspace grant.
    let mut tx = f.db.governed_pool().begin().await.unwrap();
    let mut snapshot = ComparisonSnapshot::default();
    let error = inspect_global_on(
        &mut tx,
        &f.actor,
        "wrong-workspace",
        &pin,
        deadline(),
        &mut snapshot,
    )
    .await
    .err()
    .expect("mandatory checks must refuse first");
    tx.rollback().await.unwrap();
    assert!(error.to_string().contains("view_missing"), "{error}");
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_retained_scan_exhaustion_is_unknown_not_absence() {
    use crate::named_views::source_proof::ComparisonReason;
    let f = Fixture::new().await;
    global_declared(&f).await;
    let p = global_candidate(&f, &["area"]).await.unwrap();
    let pin = commit_global(&f, &p).await;
    // Flood the snapshot with irrelevant vocabulary rows. None of them
    // matches the admitted binding, but uniqueness can no longer be proved
    // within the scan bound.
    for n in 0..1100 {
        let id = format!("voc:pad-{n:04}");
        f.import(
            "vocabularies",
            &id,
            Some(json!({"id":id,"name":format!("pad-{n:04}")})),
        )
        .await;
    }
    let mut tx = f.db.governed_pool().begin().await.unwrap();
    let mut snapshot = ComparisonSnapshot::default();
    let checked = inspect_global_on(
        &mut tx,
        &f.actor,
        "trusted-workspace",
        &pin,
        deadline(),
        &mut snapshot,
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(checked.drift, Drift::Unknown);
    assert_eq!(checked.unknown_reason, Some(ComparisonReason::Budget));
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_retained_reverse_winner_flags_relevant_collision() {
    // Pack declares the ID spelling; the global user row wins with the bare
    // name. A new row colliding with the winner's bare name is Changed.
    let f = Fixture::new().await;
    f.import("schema_config","global-id",Some(json!({"id":"global-id","layer":"pack","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area":{"description":"Area","vocab_ref":"voc:area"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":"G1","created_at":"2026-10-26T00:00:00Z"}))).await;
    f.import("schema_config","global-user-bare",Some(json!({"id":"global-user-bare","layer":"user","name":null,"data":json!({"shapes":{"WorkItem:task":{"facets":{"area":{"description":"Area","vocab_ref":"area"}}}}}).to_string(),"applies_to_collection_id":null,"version_lineage":"G2","created_at":"2026-10-26T00:00:01Z"}))).await;
    f.import(
        "vocabularies",
        "voc:area",
        Some(json!({"id":"voc:area","name":"area"})),
    )
    .await;
    for (id, token) in [("high", "high"), ("low", "low")] {
        f.import(
            "vocabulary_values",
            id,
            Some(json!({"id":id,"vocabulary_id":"voc:area","value":token,"status":"active","alias_of":null})),
        )
        .await;
    }
    let p = global_candidate(&f, &["area"]).await.unwrap();
    let pin = commit_global(&f, &p).await;
    assert_eq!(global_drift(&f, &pin).await.unwrap(), Drift::Unchanged);
    // First-match evaluation would use the superseded pack spelling and miss
    // this winner-relevant collision.
    f.import(
        "vocabularies",
        "voc:evil2",
        Some(json!({"id":"voc:evil2","name":"area"})),
    )
    .await;
    assert_eq!(global_drift(&f, &pin).await.unwrap(), Drift::Changed);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn global_retained_below_scan_bound_stays_current() {
    // ~1000 irrelevant rows stay under the 1024-row membership scan bound:
    // the same Unknown verdict at 1100 rows is the bound, not another cap.
    let f = Fixture::new().await;
    global_declared(&f).await;
    let p = global_candidate(&f, &["area"]).await.unwrap();
    let pin = commit_global(&f, &p).await;
    for n in 0..1000 {
        let id = format!("voc:pad-{n:04}");
        f.import(
            "vocabularies",
            &id,
            Some(json!({"id":id,"name":format!("pad-{n:04}")})),
        )
        .await;
    }
    assert_eq!(global_drift(&f, &pin).await.unwrap(), Drift::Unchanged);
}
