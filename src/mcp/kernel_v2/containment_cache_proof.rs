//! Synthetic fixtures exercise the production resolver, without a second walk.
use super::*;
use crate::kernel::read_cache;
use crate::mcp::kernel_v2::read_surface::{containment_path_visible_on, measured_containment};

// Synthetic logical-filing events retain the real policy home, View checks,
// original placement helper, and immutable event-head invalidation.
async fn file_on(conn: &mut sqlx::SqliteConnection, id: &str, home: Option<&str>) {
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,causal_envelope_version,causal_status) VALUES(?,?,'kernel.record_rehomed.v2',?,1,'legacy_unknown')")
        .bind(uuid::Uuid::new_v4().to_string()).bind(id)
        .bind(json!({"logical_home_id":home}).to_string()).execute(conn).await.unwrap();
}

#[tokio::test]
async fn containment_metadata_cache_reuses_labels_keeps_placement_and_admission() {
    let w = world().await;
    let mut source = w.db.write_pool().acquire().await.unwrap();
    // Two distinct selected children share one visible physical ancestor.
    file_on(&mut source, &w.first, Some(&w.second)).await;
    file_on(&mut source, &w.second, Some(KERNEL_ROOT_ID)).await;
    file_on(&mut source, &w.hidden, Some(&w.second)).await;
    let ids = [&w.first, &w.hidden, &w.first, &w.second];
    let (expected, baseline) = measured_containment(async {
        let mut result = Vec::new();
        for id in ids {
            result.push(
                containment_path_visible_on(&mut source, &w.admin, id)
                    .await
                    .unwrap(),
            );
        }
        result
    })
    .await;
    let (actual, cached) = measured_containment(read_cache::scope_member_metadata(async {
        let mut result = Vec::new();
        for id in ids {
            result.push(
                containment_path_visible_on(&mut source, &w.admin, id)
                    .await
                    .unwrap(),
            );
        }
        result
    }))
    .await;
    assert_eq!(actual, expected);
    assert!(actual.iter().all(|value| *value));
    assert_eq!(baseline.initial_placements, ids.len());
    assert_eq!(cached.initial_placements, baseline.initial_placements);
    assert_eq!(
        cached.admissions, baseline.admissions,
        "admission precedes every cached return"
    );
    assert!(
        cached.descriptor_loads < baseline.descriptor_loads,
        "actual shared descriptor hydration is reduced"
    );
    drop(source);
    w.db.close().await;
}

#[tokio::test]
async fn containment_metadata_cache_preserves_closed_walk_edges_and_live_heads() {
    let w = world().await;
    // 101 physical nodes, all in the same real policy home. Logical filing can
    // then exercise the resolver's exact 100-step boundary without 100 ACLs.
    let mut chain = vec![w.first.clone(), w.second.clone()];
    for n in 2..101 {
        chain.push(
            kernel::create_as(
                &w.db,
                &w.admin,
                "fixture.mcp",
                "note",
                json!({"title":format!("chain {n}")}).as_object().unwrap(),
                KERNEL_ROOT_ID,
            )
            .await
            .unwrap(),
        );
    }
    let mut source = w.db.write_pool().acquire().await.unwrap();
    for pair in chain.windows(2) {
        file_on(&mut source, &pair[0], Some(&pair[1])).await;
    }
    file_on(&mut source, chain.last().unwrap(), Some(KERNEL_ROOT_ID)).await;
    // 100 physical descriptors exhaust the loop; 98 plus virtual root finish.
    let cases = vec![
        (w.admin.as_str(), chain[0].as_str(), false),
        (w.admin.as_str(), chain[1].as_str(), false),
        (w.admin.as_str(), chain[2].as_str(), true),
        (w.admin.as_str(), KERNEL_ROOT_ID, true),
        (w.admin.as_str(), "missing:synthetic", false),
        (w.viewer.as_str(), w.hidden.as_str(), false),
    ];
    // Keep the hidden record physically private despite its logical filing.
    file_on(&mut source, &w.hidden, Some(KERNEL_ROOT_ID)).await;
    for (actor, id, wanted) in cases {
        let before = containment_path_visible_on(&mut source, actor, id)
            .await
            .unwrap();
        let after = read_cache::scope_member_metadata(async {
            let first = containment_path_visible_on(&mut source, actor, id)
                .await
                .unwrap();
            assert_eq!(
                containment_path_visible_on(&mut source, actor, id)
                    .await
                    .unwrap(),
                first
            );
            first
        })
        .await;
        assert_eq!(before, wanted, "fixture edge {id}");
        assert_eq!(after, before);
    }
    read_cache::scope_member_metadata(async {
        // Same actor/DB, but every synthetic append changes the live main head.
        file_on(&mut source, &w.first, Some(KERNEL_ROOT_ID)).await;
        assert!(containment_path_visible_on(&mut source, &w.admin, &w.first)
            .await
            .unwrap());
        file_on(&mut source, &w.first, Some(&w.first)).await;
        assert!(
            !containment_path_visible_on(&mut source, &w.admin, &w.first)
                .await
                .unwrap(),
            "cycle must not reuse a prior head"
        );
        file_on(&mut source, &w.first, Some(&w.hidden)).await;
        assert!(
            !containment_path_visible_on(&mut source, &w.viewer, &w.first)
                .await
                .unwrap(),
            "hidden ancestor stays closed"
        );
        assert!(
            containment_path_visible_on(&mut source, &w.admin, &w.first)
                .await
                .unwrap(),
            "actor identity differs"
        );
    })
    .await;
    // This ordinary note has no native Direct-message unfiled witness. The
    // unchanged resolver refuses that synthetic filing; caching must do so too.
    file_on(&mut source, &w.first, Some("native:unfiled")).await;
    let unfiled = containment_path_visible_on(&mut source, &w.admin, &w.first)
        .await
        .unwrap_err();
    assert!(unfiled.to_string().contains(kernel::HIDDEN_OR_MISSING));
    let cached_unfiled = read_cache::scope_member_metadata(containment_path_visible_on(
        &mut source,
        &w.admin,
        &w.first,
    ))
    .await
    .unwrap_err();
    assert_eq!(cached_unfiled.to_string(), unfiled.to_string());

    // A null logical home follows the original placement fallback. Compare
    // both value and refusal without inventing root or unfiled semantics.
    file_on(&mut source, &w.first, None).await;
    let nullable = containment_path_visible_on(&mut source, &w.admin, &w.first)
        .await
        .map_err(|error| error.to_string());
    let cached_nullable = read_cache::scope_member_metadata(containment_path_visible_on(
        &mut source,
        &w.admin,
        &w.first,
    ))
    .await
    .map_err(|error| error.to_string());
    assert_eq!(cached_nullable, nullable);
    drop(source);
    w.db.close().await;
}

/// The metadata view carries no body lane while the full view does, and both
/// agree on the label-relevant fields. Body text is written through the body
/// lane (`set_body_as`), not the `body` text field.
#[tokio::test]
async fn ancestor_metadata_view_carries_no_body_lane() {
    // Heap-allocate the large debug futures so this test fits the default stack.
    let w = Box::pin(world()).await;
    let id = Box::pin(kernel::create_as(
        &w.db,
        &w.admin,
        "fixture.mcp",
        "note",
        json!({"title": "bodied"}).as_object().unwrap(),
        KERNEL_ROOT_ID,
    ))
    .await
    .unwrap();
    let revision = Box::pin(kernel::read_record_as(&w.db, &w.admin, &id))
        .await
        .unwrap()
        .unwrap()
        .revision;
    Box::pin(kernel::set_body_as(
        &w.db,
        &w.admin,
        &id,
        &"y".repeat(64 * 1024),
        revision,
    ))
    .await
    .unwrap();

    let mut probe = w.db.write_pool().acquire().await.unwrap();
    let meta = Box::pin(kernel::read_record_metadata_on(&mut probe, &w.admin, &id))
        .await
        .unwrap()
        .expect("ancestor metadata");
    assert!(meta.body.is_none());
    let full = Box::pin(kernel::read_record_on(&mut probe, &w.admin, &id))
        .await
        .unwrap()
        .expect("ancestor full view");
    assert_eq!(full.body.as_deref(), Some(&*"y".repeat(64 * 1024)));
    assert_eq!(meta.fields.get("title"), full.fields.get("title"));
    assert_eq!(meta.fields.get("name"), full.fields.get("name"));
    drop(probe);
    w.db.close().await;
}
