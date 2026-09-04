//! Stage-1 read layer (`query::*`) + the new `store` primitives (batch append,
//! conditional lifecycle write). Task dd515a9.

use native_ce::conformance::rebuild_and_diff;
use native_ce::events::{FacetSetPayload, LinkAddedPayload};
use native_ce::mcp::Caller;
use native_ce::meta::{alias_value, seed_pack_schema_config};
use native_ce::meta::{
    create_vocabulary, list_values, promote_value, propose_value,
    propose_value_with_kind_metadata_as, seed_vocabularies, write_user_schema_config,
    KindMetadataV1, ListValuesOptions, SchemaConfigOptions, VocabularyValueTerminality,
};
use native_ce::query::{cascade, events, fts, pipeline, read, sql, tree};
use native_ce::store::{
    add_link, append_batch, archive_record, create_record, delete_record, set_facet, update_record,
    update_record_when_lifecycle, AppendSpec, LifecycleCas,
};
use native_ce::{create_database, Db};
use serde_json::json;

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

async fn govern_kind(db: &Db, record_type: &str, token: &str) {
    let id = propose_value_with_kind_metadata_as(
        db,
        &format!("kind:{record_type}"),
        token,
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy(record_type, token)),
        None,
    )
    .await
    .unwrap();
    promote_value(db, &id).await.unwrap();
}

fn facet(key: &str, value: &str) -> FacetSetPayload {
    FacetSetPayload {
        key: key.into(),
        value: Some(value.into()),
        vocab_ref: None,
        as_of: None,
        observation_only: false,
    }
}

fn link(source: &str, target: &str, relationship: &str) -> LinkAddedPayload {
    LinkAddedPayload {
        id: None,
        source_id: source.into(),
        target_id: target.into(),
        relationship: relationship.into(),
        note: None,
    }
}

/// A small tree: root folder > task A [running], doc B, archived empty folder
/// C, and live doc D. Plus a standalone outcome linked from task A.
async fn seed(db: &Db) -> (String, String, String, String, String, String) {
    let root = create_record(
        db,
        json!({ "type": "Collection", "kind": "folder", "name": "Programme" }),
    )
    .await
    .unwrap();
    let a = create_record(
        db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Keep running the mill", "home_id": root,
                "body": "Punched cards for the running computation.", "lifecycle": "active" }),
    )
    .await
    .unwrap();
    let b = create_record(
        db,
        json!({ "type": "Document", "kind": "note", "name": "Weaving notes", "home_id": root,
                "body": "Algebraic patterns woven nightly." }),
    )
    .await
    .unwrap();
    let c = create_record(
        db,
        json!({ "type": "Collection", "kind": "folder", "name": "Obsolete survey", "home_id": root }),
    )
    .await
    .unwrap();
    let d = create_record(
        db,
        json!({ "type": "Document", "kind": "note", "name": "Survey appendix", "home_id": root }),
    )
    .await
    .unwrap();
    let goal = create_record(
        db,
        json!({ "type": "Outcome", "kind": "target", "name": "Bernoulli numbers" }),
    )
    .await
    .unwrap();
    set_facet(db, &a, facet("confidence", "likely"))
        .await
        .unwrap();
    add_link(db, link(&a, &goal, "part_of")).await.unwrap();
    archive_record(db, &c).await.unwrap();
    (root, a, b, c, d, goal)
}

// ---- store: batch append ---------------------------------------------------

#[tokio::test]
async fn append_batch_is_atomic_on_success() {
    let db = db().await;
    let id = "90e70000-0000-4000-8000-000000000001".to_string();
    let events = append_batch(
        &db,
        vec![
            AppendSpec {
                record_id: id.clone(),
                event_type: "record.created".into(),
                payload: json!({ "type": "WorkItem", "kind": "task", "name": "Batched" }),
                actor: None,
            },
            AppendSpec {
                record_id: id.clone(),
                event_type: "facet.set".into(),
                payload: json!({ "key": "confidence", "value": "likely" }),
                actor: None,
            },
        ],
    )
    .await
    .unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1].local_seq, events[0].local_seq + 1);
    let record = read::get_record(&db, &id).await.unwrap().unwrap();
    assert_eq!(record.facets.len(), 1);
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn append_batch_rolls_back_whole_batch_on_failure() {
    let db = db().await;
    let id = "90e70000-0000-4000-8000-000000000002".to_string();
    // Second event fails the app-layer vocab_ref guard -> whole batch gone.
    let err = append_batch(
        &db,
        vec![
            AppendSpec {
                record_id: id.clone(),
                event_type: "record.created".into(),
                payload: json!({ "type": "WorkItem", "kind": "task", "name": "Doomed" }),
                actor: None,
            },
            AppendSpec {
                record_id: id.clone(),
                event_type: "facet.set".into(),
                payload: json!({ "key": "confidence", "value": "likely",
                                  "vocab_ref": "rec:no-such-vocab" }),
                actor: None,
            },
        ],
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("does not resolve"));
    // NOT a partial write: neither the record nor its event landed.
    assert!(read::get_record(&db, &id).await.unwrap().is_none());
    assert_eq!(
        crate::common::count(&db, "SELECT COUNT(*) AS n FROM content_events").await,
        2
    );
}

#[tokio::test]
async fn append_batch_rejects_empty() {
    let db = db().await;
    assert!(append_batch(&db, vec![]).await.is_err());
}

// ---- store: generic conditional lifecycle write ----------------------------

#[tokio::test]
async fn lifecycle_cas_applies_when_precondition_holds() {
    let db = db().await;
    let id = create_record(
        db_ref(&db),
        json!({ "type": "WorkItem", "kind": "task", "name": "Claimable" }),
    )
    .await
    .unwrap();
    let outcome = update_record_when_lifecycle(&db, &id, None, json!({ "lifecycle": "active" }))
        .await
        .unwrap();
    assert!(matches!(outcome, LifecycleCas::Applied(_)));
    let record = read::get_record(&db, &id).await.unwrap().unwrap();
    assert_eq!(record.record.lifecycle.as_deref(), Some("active"));
}

#[tokio::test]
async fn lifecycle_cas_refuses_when_precondition_does_not_hold() {
    let db = db().await;
    let id = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Contested" }),
    )
    .await
    .unwrap();
    update_record(&db, &id, json!({ "lifecycle": "active" }))
        .await
        .unwrap();
    // A caller expecting None must refuse rather than overwrite.
    let outcome = update_record_when_lifecycle(&db, &id, None, json!({ "lifecycle": "active" }))
        .await
        .unwrap();
    match outcome {
        LifecycleCas::Conflict { current, .. } => assert_eq!(current.as_deref(), Some("active")),
        other => panic!("expected conflict, got {other:?}"),
    }
    // And nothing was appended for the refused update.
    let history = events::events_for_record(&db, &id, None, 100)
        .await
        .unwrap();
    assert_eq!(history.events.len(), 2); // created + first lifecycle set
}

#[tokio::test]
async fn lifecycle_cas_errors_on_missing_and_tombstoned() {
    let db = db().await;
    assert!(
        update_record_when_lifecycle(&db, "ghost", None, json!({ "lifecycle": "x" }))
            .await
            .is_err()
    );
    let id = create_record(
        &db,
        json!({ "type": "WorkItem", "kind": "task", "name": "Gone" }),
    )
    .await
    .unwrap();
    delete_record(&db, &id).await.unwrap();
    let err = update_record_when_lifecycle(&db, &id, None, json!({ "lifecycle": "x" }))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("tombstoned"));
}

fn db_ref(db: &Db) -> &Db {
    db
}

// ---- query::read -----------------------------------------------------------

#[tokio::test]
async fn get_record_enriches_fully() {
    let db = db().await;
    let (root, a, _b, c, _d, goal) = seed(&db).await;
    let rec = read::get_record(&db, &a).await.unwrap().unwrap();
    assert_eq!(rec.record.name, "Keep running the mill");
    assert_eq!(rec.record.lifecycle.as_deref(), Some("active"));
    assert!(!rec.archived);
    assert_eq!(rec.facets.len(), 1);
    assert_eq!(rec.facets[0].key, "confidence");
    assert_eq!(rec.links_out.len(), 1);
    assert_eq!(rec.links_out[0].target_id, goal);
    assert_eq!(rec.ancestors.len(), 3);
    assert_eq!(rec.ancestors.last().unwrap().id, root);
    // The goal sees the same link inbound.
    let goal_rec = read::get_record(&db, &goal).await.unwrap().unwrap();
    assert_eq!(goal_rec.links_in.len(), 1);
    assert_eq!(goal_rec.links_in[0].source_id, a);
    // Children of root: a, b, c, d — with c flagged archived, not hidden.
    let root_rec = read::get_record(&db, &root).await.unwrap().unwrap();
    assert_eq!(root_rec.children.len(), 4);
    let archived_child = root_rec.children.iter().find(|ch| ch.id == c).unwrap();
    assert!(archived_child.archived);
    // Direct fetch returns archived records too, flagged.
    let c_rec = read::get_record(&db, &c).await.unwrap().unwrap();
    assert!(c_rec.archived);
    assert!(c_rec.facets.is_empty()); // `archived` surfaces as the flag, not a facet
}

/// A container wide enough that the bound is the only thing standing between
/// `get_record` and the whole subtree. 512 rather than a round 500 so an
/// off-by-one in the window cannot coincide with the cap.
async fn seed_wide_container(db: &Db, n: usize) -> String {
    let root = create_record(
        db,
        json!({ "type": "Collection", "kind": "folder", "name": "Wide" }),
    )
    .await
    .unwrap();
    for i in 0..n {
        // Zero-padded so (name, id) order is the obvious one to assert on.
        create_record(
            db,
            json!({ "type": "WorkItem", "kind": "task", "name": format!("Child {i:04}"), "home_id": root }),
        )
        .await
        .unwrap();
    }
    root
}

#[tokio::test]
async fn enrichment_windows_children_and_reports_the_true_total() {
    let db = db().await;
    let root = seed_wide_container(&db, 512).await;

    // The default window is a window, and child_count says what onto.
    let rec = read::get_record(&db, &root).await.unwrap().unwrap();
    assert_eq!(rec.children.len(), read::DEFAULT_ENRICH_LIMIT as usize);
    assert_eq!(rec.child_count, 512);
    assert_eq!(rec.children[0].name, "Child 0000");

    // offset pages it, and the last page is short rather than wrapping.
    let opts = read::EnrichOptions {
        children_limit: 200,
        children_offset: 400,
        ..Default::default()
    };
    let page3 = read::get_record_with(&db, &root, opts)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(page3.children.len(), 112);
    assert_eq!(page3.child_count, 512);
    assert_eq!(page3.children[0].name, "Child 0400");

    // limit: 0 is a legitimate question — "how many?", paying for none of them.
    let counted = read::get_record_with(
        &db,
        &root,
        read::EnrichOptions {
            children_limit: 0,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert!(counted.children.is_empty());
    assert_eq!(counted.child_count, 512);
}

#[tokio::test]
async fn enrichment_refuses_to_be_talked_out_of_its_bound() {
    let db = db().await;
    let root = seed_wide_container(&db, 4).await;
    // The ceiling is what makes the section bounded rather than defaulted:
    // asking for everything is an error, not a large answer.
    let err = read::get_record_with(
        &db,
        &root,
        read::EnrichOptions {
            children_limit: read::MAX_ENRICH_LIMIT + 1,
            ..Default::default()
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("children limit must be <="), "{err}");
    assert!(
        err.contains("children_offset"),
        "the error names a way out that is actually reachable today: {err}"
    );

    for bad in [
        read::EnrichOptions {
            children_offset: -1,
            ..Default::default()
        },
        read::EnrichOptions {
            links_limit: -1,
            ..Default::default()
        },
    ] {
        assert!(read::get_record_with(&db, &root, bad).await.is_err());
    }
}

/// Paging links is only meaningful over a total order, and `(relationship,
/// created_at)` is not one: `links.created_at` defaults to a millisecond-
/// resolution `strftime`, so a batch of links collides on it whenever the batch
/// is fast enough. "Fast enough" is a property of the machine, not of the code,
/// so the collision is manufactured here rather than hoped for: the links are
/// still built the real way (`append_batch` → projector), then every row is
/// pinned to one literal timestamp. That collapses the middle sort term and
/// puts the entire ordering burden on `id` — the degenerate case the paging
/// assertions below exist to guard.
///
/// Honest about what this test can and cannot do: it passes with or without the
/// tie-breaker today, because SQLite's tie order is deterministic for an
/// unchanged query plan. What the tie-breaker buys is that it stays correct
/// when the plan changes — a new index, an `ANALYZE`, a vacuum. So read this as
/// stating the invariant, not as a regression test that would have caught the
/// bug; a test that provoked a plan change to prove the point would be testing
/// SQLite rather than us.
#[tokio::test]
async fn link_paging_is_stable_across_timestamp_collisions() {
    let db = db().await;
    let hub = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "Hub" }),
    )
    .await
    .unwrap();
    // One batch, one relationship: every link shares `relationship`.
    let mut specs = Vec::new();
    for i in 0..30 {
        let spoke = create_record(
            &db,
            json!({ "type": "WorkItem", "kind": "task", "name": format!("Spoke {i:02}") }),
        )
        .await
        .unwrap();
        specs.push(AppendSpec {
            record_id: spoke.clone(),
            event_type: "link.added".into(),
            payload: json!({ "source_id": spoke, "target_id": hub,
                             "relationship": "part_of" }),
            actor: None,
        });
    }
    append_batch(&db, specs).await.unwrap();

    // Manufacture the collision instead of racing the clock for it: whether a
    // 30-row batch fits inside one millisecond depends on how loaded the
    // machine is, and a precondition that only holds on an idle machine is a
    // flake, not a guard.
    let pinned = sqlx::query(
        "UPDATE links SET created_at = '2026-08-10T00:00:00.000Z' \
         WHERE relationship = 'part_of'",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap()
    .rows_affected();
    assert_eq!(pinned, 30, "expected to pin all 30 batch-built links");

    // The precondition this whole test exists for: the non-id part of the
    // ordering key carries no information at all, so only `id` can order these
    // rows.
    let distinct_ts = crate::common::count(
        &db,
        "SELECT COUNT(DISTINCT created_at) AS n FROM links WHERE relationship = 'part_of'",
    )
    .await;
    assert_eq!(
        distinct_ts, 1,
        "expected every batch link pinned to one created_at, got {distinct_ts} distinct values \
         — if timestamps became unique, this test no longer guards what it claims to"
    );

    // Walk the whole set in pages of 7 and assert the union is exactly the set:
    // no duplicate, no omission.
    let mut seen: Vec<String> = Vec::new();
    for page in 0..5 {
        let rec = read::get_record_with(
            &db,
            &hub,
            read::EnrichOptions {
                links_limit: 7,
                links_offset: page * 7,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(rec.links_in_count, 30);
        seen.extend(rec.links_in.iter().map(|l| l.id.clone()));
    }
    assert_eq!(seen.len(), 30, "pages overlapped or skipped");
    let unique: std::collections::HashSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), 30, "a link appeared on two pages");
}

#[tokio::test]
async fn enrichment_windows_links_both_directions() {
    let db = db().await;
    let hub = create_record(
        &db,
        json!({ "type": "Outcome", "kind": "target", "name": "Hub" }),
    )
    .await
    .unwrap();
    for i in 0..12 {
        let spoke = create_record(
            &db,
            json!({ "type": "WorkItem", "kind": "task", "name": format!("Spoke {i:02}") }),
        )
        .await
        .unwrap();
        add_link(&db, link(&spoke, &hub, "part_of")).await.unwrap();
        add_link(&db, link(&hub, &spoke, "renders")).await.unwrap();
    }
    let windowed = read::get_record_with(
        &db,
        &hub,
        read::EnrichOptions {
            links_limit: 5,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(windowed.links_in.len(), 5);
    assert_eq!(windowed.links_in_count, 12);
    assert_eq!(windowed.links_out.len(), 5);
    assert_eq!(windowed.links_out_count, 12);
    // Unwindowed sections stay whole — they do not grow with the brain.
    assert_eq!(windowed.ancestors.len(), 2);
    assert_eq!(windowed.ancestors[0].id, native_ce::schema::ROOT_RECORD_ID);
    assert_eq!(
        windowed.ancestors[1].id,
        native_ce::schema::UNFILED_RECORD_ID
    );
}

#[tokio::test]
async fn batch_get_partial_success_in_input_order() {
    let db = db().await;
    let (_root, a, b, ..) = seed(&db).await;
    let items = read::get_records(&db, &[a.clone(), "missing".into(), b.clone()])
        .await
        .unwrap();
    assert_eq!(items.len(), 3);
    assert!(matches!(&items[0], read::BatchGetItem::Found(r) if r.record.id == a));
    assert!(matches!(&items[1], read::BatchGetItem::NotFound { id } if id == "missing"));
    assert!(matches!(&items[2], read::BatchGetItem::Found(r) if r.record.id == b));
}

// ---- query::tree -----------------------------------------------------------

#[tokio::test]
async fn tree_walk_depth_limits_with_counts_and_archive_rule() {
    let db = db().await;
    let (root, _a, _b, c, d, _goal) = seed(&db).await;
    // Default: archived c is omitted while its sibling d remains visible.
    let nodes = tree::descendants(&db, &root, tree::TreeOptions::default())
        .await
        .unwrap();
    let ids: Vec<&str> = nodes.iter().map(|n| n.id.as_str()).collect();
    assert!(ids.contains(&root.as_str()));
    assert!(!ids.contains(&c.as_str()));
    assert!(ids.contains(&d.as_str()));
    let root_node = &nodes[0];
    assert_eq!(root_node.depth, 0);
    assert_eq!(root_node.child_count, 3); // archived child not counted by default
                                          // include_archived: all four direct children appear.
    let nodes = tree::descendants(
        &db,
        &root,
        tree::TreeOptions {
            max_depth: 1,
            include_archived: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let c_node = nodes.iter().find(|n| n.id == c).unwrap();
    assert!(c_node.archived);
    assert_eq!(c_node.child_count, 0);
    assert!(nodes.iter().any(|n| n.id == d));
}

#[tokio::test]
async fn tree_walk_caps_siblings_per_node_and_prunes_beneath_the_cap() {
    let db = db().await;
    let root = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Wide" }),
    )
    .await
    .unwrap();
    let mut kids = Vec::new();
    for i in 0..10 {
        let shape = if i == 9 {
            json!({ "type": "Collection", "kind": "folder", "name": format!("Child {i:02}"), "home_id": root })
        } else {
            json!({ "type": "WorkItem", "kind": "task", "name": format!("Child {i:02}"), "home_id": root })
        };
        kids.push(create_record(&db, shape).await.unwrap());
    }
    // A grandchild under a child that WILL be cut by a cap of 3.
    create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Buried", "home_id": kids[9] }),
    )
    .await
    .unwrap();

    let nodes = tree::descendants(
        &db,
        &root,
        tree::TreeOptions {
            max_depth: 3,
            max_children_per_node: 3,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Root + 3 of its 10 children. Nothing under the cut children — a capped
    // walk returns a subtree, never a forest with orphans floating in it.
    assert_eq!(nodes.len(), 4);
    assert!(!nodes.iter().any(|n| n.name == "Buried"));
    // The count still tells the truth about what was cut.
    let root_node = nodes.iter().find(|n| n.id == root).unwrap();
    assert_eq!(root_node.child_count, 10);

    // The cap keys on (name, id) — the SAME key `read`'s children window uses,
    // so a capped container has one membership, not one per call.
    let walked: Vec<&str> = nodes
        .iter()
        .filter(|n| n.id != root)
        .map(|n| n.name.as_str())
        .collect();
    let enriched = read::get_record_with(
        &db,
        &root,
        read::EnrichOptions {
            children_limit: 3,
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    let paned: Vec<&str> = enriched.children.iter().map(|c| c.name.as_str()).collect();
    let mut sorted = walked.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, paned, "tree and record pane disagree on membership");
}

#[tokio::test]
async fn tree_walk_rejects_a_cap_above_the_ceiling() {
    let db = db().await;
    let (root, ..) = seed(&db).await;
    let err = tree::descendants(
        &db,
        &root,
        tree::TreeOptions {
            max_children_per_node: tree::MAX_CHILDREN_PER_NODE + 1,
            ..Default::default()
        },
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(err.contains("max_children_per_node must be <="), "{err}");
}

#[tokio::test]
async fn tree_walk_survives_a_malformed_home_cycle() {
    let db = db().await;
    let x = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "X" }),
    )
    .await
    .unwrap();
    let y = create_record(
        &db,
        json!({ "type": "Collection", "kind": "folder", "name": "Y", "home_id": x }),
    )
    .await
    .unwrap();
    // The write path rejects this shape. Corrupt/imported projections must
    // still not make a defensive read hang or duplicate.
    sqlx::query("UPDATE records SET home_id = ? WHERE id = ?")
        .bind(&y)
        .bind(&x)
        .execute(&crate::common::fixture_write_pool(&db).await)
        .await
        .unwrap();
    let nodes = tree::descendants(
        &db,
        &x,
        tree::TreeOptions {
            max_depth: 50,
            include_archived: false,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(nodes.len(), 2);
    let ancestors = tree::ancestors(&db, &x).await.unwrap();
    assert!(ancestors.len() <= 2);
}

// ---- query::events ---------------------------------------------------------

#[tokio::test]
async fn events_reader_pages_by_seq() {
    let db = db().await;
    let (_root, a, ..) = seed(&db).await;
    let first = events::events_for_record(&db, &a, None, 2).await.unwrap();
    assert_eq!(first.events.len(), 2);
    let next = first.next_after_seq.expect("more pages");
    let rest = events::events_for_record(&db, &a, Some(next), 100)
        .await
        .unwrap();
    assert!(rest.next_after_seq.is_none());
    // created + facet.set + link.added = 3 events under record a.
    assert_eq!(first.events.len() + rest.events.len(), 3);
    assert!(first.events[0].local_seq < first.events[1].local_seq);

    let all = events::all_events(&db, None, 1000).await.unwrap();
    let prefix = events::log_prefix(&db, all.events[2].local_seq)
        .await
        .unwrap();
    assert_eq!(prefix.len(), 3);
}

// ---- query::fts ------------------------------------------------------------

#[tokio::test]
async fn fts_search_stems_and_applies_default_visibility() {
    let db = db().await;
    let (_root, a, _b, c, _d, _goal) = seed(&db).await;
    // porter: query 'runs' stems to 'run', matching 'running' in name/body.
    let hits = fts::search(&db, "test-account", "runs", &fts::FtsOptions::default())
        .await
        .unwrap();
    assert!(hits.iter().any(|h| h.id == a));
    // Archived record excluded by default…
    let hits = fts::search(
        &db,
        "test-account",
        "obsolete survey",
        &fts::FtsOptions::default(),
    )
    .await
    .unwrap();
    assert!(hits.is_empty());
    // …included on request.
    let hits = fts::search(
        &db,
        "test-account",
        "obsolete survey",
        &fts::FtsOptions {
            include_archived: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(hits.iter().any(|h| h.id == c));
    // Tombstoned records never come back (triggers keep them indexed).
    delete_record(&db, &a).await.unwrap();
    let hits = fts::search(&db, "test-account", "runs", &fts::FtsOptions::default())
        .await
        .unwrap();
    assert!(!hits.iter().any(|h| h.id == a));
}

#[tokio::test]
async fn fts_neutralizes_query_syntax_and_scopes_to_subtree() {
    let db = db().await;
    let (root, _a, b, ..) = seed(&db).await;
    let standalone = create_record(
        &db,
        json!({ "type": "Document", "kind": "note", "name": "Weaving elsewhere", "body": "weaving patterns" }),
    )
    .await
    .unwrap();
    // FTS5 syntax in user input must not error or subvert.
    for hostile in [
        "weaving OR",
        "\"unbalanced",
        "col:weaving",
        "(weaving",
        "-weaving",
    ] {
        let _ = fts::search(&db, "test-account", hostile, &fts::FtsOptions::default())
            .await
            .unwrap();
    }
    // Subtree scope: only the in-tree hit.
    let hits = fts::search(
        &db,
        "test-account",
        "weaving",
        &fts::FtsOptions {
            scope: Some(root.clone()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(hits.iter().any(|h| h.id == b));
    assert!(!hits.iter().any(|h| h.id == standalone));
}

#[tokio::test]
async fn name_prefix_matches_unstemmed() {
    let db = db().await;
    let (_root, a, ..) = seed(&db).await;
    // porter stores 'running' as 'run', so 'runni*' fails on records_fts —
    // the unstemmed sibling is exactly for this (3c40677).
    let hits = fts::name_prefix(&db, "test-account", "runni", &fts::FtsOptions::default())
        .await
        .unwrap();
    assert!(hits.iter().any(|h| h.id == a));
}

// ---- query::sql ------------------------------------------------------------

#[tokio::test]
async fn sql_validator_rejects_everything_it_must() {
    for (bad, why) in [
        ("INSERT INTO records VALUES (1)", "INSERT"),
        ("UPDATE records SET name = 'x'", "UPDATE"),
        ("DELETE FROM records", "DELETE"),
        ("DROP TABLE records", "DROP"),
        ("PRAGMA user_version = 10", "PRAGMA"),
        ("ATTACH DATABASE '/tmp/x' AS other", "ATTACH"),
        ("SELECT 1; SELECT 2", "single statement"),
        ("SELECT * FROM sqlite_master", "prohibited"),
        // Alias must not whitelist the aliased relation (review finding, PR 15).
        ("SELECT * FROM sqlite_master AS sm", "prohibited"),
        // Comma-joins are relations too (round 2).
        ("SELECT * FROM records, sqlite_master", "prohibited"),
        (
            "SELECT * FROM records, pragma_table_info('records')",
            "prohibited",
        ),
        // FTS5 shadow tables (round 2).
        (
            "SELECT count(*) FROM records, records_fts_data",
            "prohibited",
        ),
        ("SELECT * FROM records_name_idx_config", "prohibited"),
        ("SELECT * FROM dbstat", "dbstat"),
        // A quoted alias is an identifier, not a clause keyword — the comma
        // after it is still relation position (round 3; this bypassed the
        // token scanner, which is why the authorizer replaced it).
        (
            "SELECT * FROM records AS \"where\", json_each('[1]')",
            "prohibited",
        ),
        ("SELECT * FROM json_each('[1]')", "prohibited"),
        ("SELECT load_extension('evil')", "prohibited"),
        // Parenthesized join-lists and post-subquery commas (round 2).
        // generate_series may or may not be compiled in — denied or unknown,
        // it never validates.
        (
            "SELECT * FROM (records, generate_series(1,3))",
            "generate_series",
        ),
        ("SELECT * FROM (SELECT 1), json_each('[1]')", "prohibited"),
        // Unknown tables fail prepare outright.
        (
            "SELECT * FROM records JOIN nonexistent ON 1=1",
            "no such table",
        ),
        ("SELECT * FROM records, nonexistent", "no such table"),
        (
            "WITH x AS (SELECT 1) DELETE FROM records",
            "unsafe_statement",
        ),
        ("", "empty"),
    ] {
        let err = sql::validate(bad).unwrap_err().to_string();
        let lower = err.to_lowercase();
        let matched = lower.contains(&why.to_lowercase())
            || (why == "prohibited" && lower.contains("not authorized"));
        assert!(matched, "{bad}: expected '{why}' in '{err}'");
    }
    // Literals cannot smuggle: the word 'delete' in a string is fine…
    sql::validate("SELECT * FROM records WHERE name = 'delete me'").unwrap();
    // …and comments are stripped for the single-statement check, which also
    // makes a trailing `; -- comment` a single statement, acceptably.
    sql::validate("SELECT id FROM records -- update nothing").unwrap();
    sql::validate("SELECT * FROM records; -- trailing comment").unwrap();
    // Aliases, CTEs (plain, column-list, materialized) all parse natively.
    sql::validate("SELECT r.name FROM records AS r").unwrap();
    sql::validate("WITH t(a) AS (SELECT name FROM records) SELECT a FROM t").unwrap();
    sql::validate("WITH t AS MATERIALIZED (SELECT 1) SELECT * FROM t").unwrap();
    sql::validate("WITH t AS NOT MATERIALIZED (SELECT 1) SELECT * FROM t").unwrap();
    // A quoted alias that collides with a keyword is legal (round 3).
    sql::validate("SELECT * FROM records AS \"where\"").unwrap();
    // Commas outside FROM clauses, subqueries, comma-joins of allowed tables.
    sql::validate("SELECT name, body, count(*) FROM records GROUP BY name, body").unwrap();
    sql::validate("SELECT * FROM (SELECT name, body FROM records) s").unwrap();
    sql::validate(
        "SELECT r.id AS record_id, l.id AS link_id
         FROM records r, links l WHERE r.id = l.source_id",
    )
    .unwrap();
    // Raw FTS is trusted-query-only: its corpus-wide BM25/IDF leaks hidden
    // rows and therefore cannot be named by arbitrary SQL.
    sql::validate("SELECT rowid FROM records_fts WHERE records_fts MATCH 'x'").unwrap_err();
}

#[tokio::test]
async fn sql_row_cap_bounds_runaway_queries() {
    let db = db().await;
    // An unbounded-ish recursive CTE: streamed execution must stop at the cap
    // instead of materializing the whole set.
    let result = sql::query_sql(
        &db,
        &Caller::authenticated("test-account"),
        "WITH RECURSIVE cnt(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM cnt WHERE x < 100000)
          SELECT x FROM cnt",
    )
    .await
    .unwrap();
    assert!(result.truncated);
    assert_eq!(result.rows.len(), 1000);
    assert_eq!(result.rows[999]["x"], json!(1000));
}

#[tokio::test]
async fn sql_executes_selects_with_ctes_and_json_rows() {
    let db = db().await;
    seed(&db).await;
    let result = sql::query_sql(
        &db,
        &Caller::authenticated("test-account"),
        "WITH tasks AS (SELECT * FROM records WHERE type = 'WorkItem')
          SELECT t.name, COUNT(*) AS n FROM tasks t GROUP BY t.name ORDER BY t.name",
    )
    .await
    .unwrap();
    assert!(!result.truncated);
    assert_eq!(result.rows.len(), 1);
    assert!(result.columns.contains(&"name".to_string()));
    // The logical relation applies current caller capability and excludes
    // tombstones; it is not a raw-base escape hatch.
    let all = sql::query_sql(
        &db,
        &Caller::authenticated("test-account"),
        "SELECT COUNT(*) AS n FROM records",
    )
    .await
    .unwrap();
    assert_eq!(all.rows[0]["n"], json!(8));
}

// ---- query::cascade + schema_config read path ------------------------------

#[tokio::test]
async fn cascade_resolves_pack_then_user_closest_wins() {
    let db = db().await;
    govern_kind(&db, "WorkItem", "chore").await;
    govern_kind(&db, "WorkItem", "errand").await;
    seed_pack_schema_config(
        &db,
        "@test/query-cascade",
        json!({ "shapes": {
            "WorkItem": { "facets": { "confidence": { "vocab": "confidence" },
                                  "effort": { "values": ["s", "m", "l"] } } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    write_user_schema_config(
        &db,
        json!({ "shapes": {
            "WorkItem": { "facets": { "effort": { "values": ["s", "m", "l", "xl"] } } },
            "Outcome": { "facets": { "horizon": {} } } } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    let rows = cascade::schema_config_rows(&db, None).await.unwrap();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].layer, "pack"); // application order

    let resolved = cascade::resolve(&db).await.unwrap();
    // User facet key wins wholesale; untouched pack keys survive.
    let task_facets = cascade::resolve_for_type(&db, "WorkItem", None)
        .await
        .unwrap();
    assert_eq!(task_facets["effort"]["values"].as_array().unwrap().len(), 4);
    assert_eq!(task_facets["confidence"]["vocab"], json!("confidence"));
    // Pack view stays pristine for the interop-floor judgement.
    assert_eq!(
        resolved.pack["shapes"]["WorkItem"]["facets"]["effort"]["values"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    // User-only type appears in resolved, not in pack.
    assert!(resolved.pack["shapes"].get("Outcome").is_none());
    assert!(resolved.resolved["shapes"]["Outcome"]["facets"]
        .get("horizon")
        .is_some());
    // Governing-vocab resolution for tool 15.
    let vocab = cascade::governing_vocab(&db, "WorkItem", None, "confidence")
        .await
        .unwrap();
    assert_eq!(vocab.as_deref(), Some("confidence"));
    assert!(cascade::governing_vocab(&db, "WorkItem", None, "effort")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn cascade_resolves_kind_specificity_after_equal_specificity_layers() {
    let db = db().await;
    govern_kind(&db, "Outcome", "objective").await;
    govern_kind(&db, "Outcome", "key_result").await;
    seed_pack_schema_config(
        &db,
        "@test/query-kind-cascade",
        json!({ "shapes": {
            "Outcome": {
                "facets": {
                    "confidence": { "required": false, "source": "pack-base" }
                }
            },
            "Outcome:key_result": {
                "facets": {
                    "confidence": { "required": true, "source": "pack-kind" },
                    "effort": { "values": ["s", "m", "l"], "source": "pack-kind" }
                }
            }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    write_user_schema_config(
        &db,
        json!({ "shapes": {
            "Outcome": {
                "facets": {
                    "confidence": { "required": false, "source": "user-base" }
                }
            },
            "Outcome:key_result": {
                "facets": {
                    "effort": { "values": ["xs", "s", "m", "l"], "source": "user-kind" }
                }
            }
        } }),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();

    // No kind preserves today's base-only behaviour.
    let base = cascade::resolve_for_type(&db, "Outcome", None)
        .await
        .unwrap();
    assert_eq!(base["confidence"]["source"], "user-base");
    assert!(base.get("effort").is_none());

    let key_result = cascade::resolve_for_type(&db, "Outcome", Some("key_result"))
        .await
        .unwrap();
    // Kind specificity beats the user base layer.
    assert_eq!(key_result["confidence"]["source"], "pack-kind");
    assert_eq!(key_result["confidence"]["required"], true);
    // At equal specificity, user still beats pack.
    assert_eq!(key_result["effort"]["source"], "user-kind");
    assert_eq!(key_result["effort"]["values"], json!(["xs", "s", "m", "l"]));
}

// ---- meta::vocabulary::list_values -----------------------------------------

#[tokio::test]
async fn list_values_filters_status_and_resolves_aliases() {
    let db = db().await;
    seed_vocabularies(&db).await.unwrap();
    create_vocabulary(&db, "theme", None).await.unwrap();
    let offsite = propose_value(&db, "theme", "offsite", None).await.unwrap();
    let away_day = propose_value(&db, "theme", "away day", None).await.unwrap();
    native_ce::meta::promote_value(&db, &offsite).await.unwrap();
    native_ce::meta::promote_value(&db, &away_day)
        .await
        .unwrap();
    alias_value(&db, &away_day, &offsite).await.unwrap();

    let all = list_values(&db, "theme", ListValuesOptions::default())
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
    let active = list_values(
        &db,
        "theme",
        ListValuesOptions {
            status: Some("active".into()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].row.value, "offsite");
    let resolved = list_values(
        &db,
        "theme",
        ListValuesOptions {
            status: None,
            resolve_aliases: true,
        },
    )
    .await
    .unwrap();
    let alias_row = resolved.iter().find(|v| v.row.value == "away day").unwrap();
    assert_eq!(alias_row.canonical.as_ref().unwrap().value, "offsite");
    // Seeded vocab reads fine through the same path.
    let maturity = list_values(&db, "maturity", ListValuesOptions::default())
        .await
        .unwrap();
    assert_eq!(maturity.len(), 5);
    // Missing vocabulary errors like the lifecycle verbs do.
    assert!(list_values(&db, "no-such", ListValuesOptions::default())
        .await
        .is_err());
}

// ---- query::pipeline -------------------------------------------------------

#[tokio::test]
async fn pipeline_filters_traverses_and_counts() {
    let db = db().await;
    let (root, a, _b, _c, _d, goal) = seed(&db).await;

    // Filter: live tasks (archived c excluded by default).
    let out = pipeline::run(
        &db,
        &[pipeline::Step::filter(pipeline::Filter {
            types: vec!["WorkItem".into()],
            ..Default::default()
        })],
        None,
        &pipeline::PipelineOptions::default(),
    )
    .await
    .unwrap();
    match out {
        pipeline::PipelineOutput::Records { total, records, .. } => {
            assert_eq!(total, 1);
            assert_eq!(records[0].id, a);
        }
        other => panic!("expected records, got {other:?}"),
    }

    // Facet filter + link traversal: tasks with confidence=likely -> part_of -> goal.
    let out = pipeline::run(
        &db,
        &[
            pipeline::Step::filter(pipeline::Filter {
                facets: vec![pipeline::FacetFilter {
                    key: "confidence".into(),
                    op: pipeline::FacetOp::Eq(json!("likely")),
                }],
                ..Default::default()
            }),
            pipeline::Step::traverse(pipeline::Traverse::Links {
                relationship: Some("part_of".into()),
                direction: pipeline::Direction::Out,
            }),
        ],
        None,
        &pipeline::PipelineOptions::default(),
    )
    .await
    .unwrap();
    match out {
        pipeline::PipelineOutput::Records { records, .. } => {
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].id, goal);
        }
        other => panic!("expected records, got {other:?}"),
    }

    // Subtree constraint + counts by type (archived excluded).
    let out = pipeline::run(
        &db,
        &[pipeline::Step::filter(pipeline::Filter {
            ancestor_id: Some(root.clone()),
            ..Default::default()
        })],
        Some(pipeline::CountAxis::Type),
        &pipeline::PipelineOptions::default(),
    )
    .await
    .unwrap();
    match out {
        pipeline::PipelineOutput::Counts { total, buckets } => {
            // root + a + b + d: the archived empty folder c is excluded while
            // its live sibling d remains in scope.
            assert_eq!(total, 4);
            assert!(buckets
                .iter()
                .any(|b| b.key.as_deref() == Some("WorkItem") && b.count == 1));
        }
        other => panic!("expected counts, got {other:?}"),
    }

    // Children traversal from the root set, archived child visible when asked.
    let out = pipeline::run(
        &db,
        &[
            pipeline::Step::filter(pipeline::Filter {
                types: vec!["Collection".into()],
                name_contains: Some("Programme".into()),
                ..Default::default()
            }),
            pipeline::Step::traverse(pipeline::Traverse::Children),
            pipeline::Step::filter(pipeline::Filter {
                include_archived: true,
                ..Default::default()
            }),
        ],
        None,
        &pipeline::PipelineOptions {
            order: pipeline::Order::NameAsc,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    match out {
        pipeline::PipelineOutput::Records { total, .. } => assert_eq!(total, 4),
        other => panic!("expected records, got {other:?}"),
    }
}

/// Presence-only facet filtering (`FacetOp::Exists`) — "the facet
/// is set at all", whatever it holds. Distinct from the value-match lane above,
/// and the lane a capability derived from held state runs on: whether a key is
/// present is a property the record either has or does not, needing no
/// agreement about the value.
#[tokio::test]
async fn facet_filter_matches_on_presence_regardless_of_value() {
    let db = db().await;
    let (_root, a, b, _c, _d, _goal) = seed(&db).await;
    // `a` carries confidence=likely from the seed; give `b` the SAME key with a
    // DIFFERENT value, so a presence hit cannot be a disguised value hit.
    set_facet(&db, &b, facet("confidence", "unlikely"))
        .await
        .unwrap();

    let presence = |key: &str| {
        pipeline::Step::filter(pipeline::Filter {
            facets: vec![pipeline::FacetFilter {
                key: key.into(),
                op: pipeline::FacetOp::Exists,
            }],
            ..Default::default()
        })
    };

    let out = pipeline::run(
        &db,
        &[presence("confidence")],
        None,
        &pipeline::PipelineOptions::default(),
    )
    .await
    .unwrap();
    match out {
        pipeline::PipelineOutput::Records { total, records, .. } => {
            assert_eq!(total, 2, "both values match — presence ignores the value");
            let mut got: Vec<&str> = records.iter().map(|r| r.id.as_str()).collect();
            got.sort_unstable();
            let mut want = vec![a.as_str(), b.as_str()];
            want.sort_unstable();
            assert_eq!(got, want);
        }
        other => panic!("expected records, got {other:?}"),
    }

    // A key nothing carries matches nothing — presence is not vacuously true.
    let out = pipeline::run(
        &db,
        &[presence("no-such-key")],
        None,
        &pipeline::PipelineOptions::default(),
    )
    .await
    .unwrap();
    match out {
        pipeline::PipelineOutput::Records { total, .. } => assert_eq!(total, 0),
        other => panic!("expected records, got {other:?}"),
    }
}

#[tokio::test]
async fn pipeline_pages_and_orders() {
    let db = db().await;
    for i in 0..7 {
        create_record(
            &db,
            json!({ "type": "Entity", "kind": "person", "name": format!("e{i}") }),
        )
        .await
        .unwrap();
    }
    let steps = [pipeline::Step::filter(pipeline::Filter {
        types: vec!["Entity".into()],
        ..Default::default()
    })];
    let out = pipeline::run(
        &db,
        &steps,
        None,
        &pipeline::PipelineOptions {
            facet_order: None,
            order: pipeline::Order::NameAsc,
            limit: 3,
            offset: 3,
        },
    )
    .await
    .unwrap();
    match out {
        pipeline::PipelineOutput::Records { total, records, .. } => {
            assert_eq!(total, 7);
            let names: Vec<&str> = records.iter().map(|r| r.name.as_str()).collect();
            assert_eq!(names, ["e3", "e4", "e5"]);
        }
        other => panic!("expected records, got {other:?}"),
    }
    // A traverse-first pipeline is a caller error.
    assert!(pipeline::run(
        &db,
        &[pipeline::Step::traverse(pipeline::Traverse::Children)],
        None,
        &pipeline::PipelineOptions::default(),
    )
    .await
    .is_err());
}

// ---- the whole-surface invariant ------------------------------------------

#[tokio::test]
async fn rebuild_and_diff_passes_after_stage1_primitives() {
    let db = db().await;
    let (_root, a, ..) = seed(&db).await;
    append_batch(
        &db,
        vec![
            AppendSpec {
                record_id: a.clone(),
                event_type: "record.updated".into(),
                payload: json!({ "summary": "batched touch" }),
                actor: Some("stage1-test".into()),
            },
            AppendSpec {
                record_id: a.clone(),
                event_type: "facet.set".into(),
                payload: json!({ "key": "confidence", "value": "confident" }),
                actor: Some("stage1-test".into()),
            },
        ],
    )
    .await
    .unwrap();
    let _ = update_record_when_lifecycle(&db, &a, Some("active"), json!({ "lifecycle": "done" }))
        .await
        .unwrap();
    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}
