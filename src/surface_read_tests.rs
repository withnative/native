//! Gated S3 surface-read tests: fixed read-only behaviour through adopted
//! packages under viewer authority. No package code runs; the host serves
//! bounded pages or the named fallback. No v1 schema, events, or tools.

use crate::events::KERNEL_ROOT_ID;
use crate::kernel::{
    adopt_package_at, create_principal, create_v2_database, install_package_as, surface_read_as,
    SurfaceReadOutcome, SURFACE_FALLBACK_VIEW,
};
use crate::package_manifest::{
    BehaviourDescriptor, DefinitionEntry, PackageManifest, SurfaceDescriptor, BEHAVIOUR_KIND,
    SURFACE_KIND,
};

const READ: &str = "linked_record:view";
const FAMILY: &str = "demo.notes";
const KIND: &str = "note";

fn defn2_entry() -> DefinitionEntry {
    let bytes = serde_json::json!({
        "family": FAMILY, "version": 1,
        "interpreter": "native.defn/2", "primary_type": "note",
        "kinds": [{"token": KIND,
            "fields": [{"name": "title", "type": "text", "required": true}],
            "identity": {"field": "title"},
            "links": [{"predicate": "relates_to",
                "target": {"primary_type": "note", "kind": "note"},
                "direction": "either"}],
            "maturity": "current", "description": "A note."}],
    })
    .to_string();
    let digest = crate::meta::definition_artifact::digest_artifact_bytes(bytes.as_bytes());
    DefinitionEntry {
        family: FAMILY.to_string(),
        version: 1,
        artifact_bytes: bytes,
        digest,
    }
}

fn manifest_with_fallback(fallback: &str) -> PackageManifest {
    PackageManifest {
        namespace: "acme".to_string(),
        name: "notes".to_string(),
        version: 1,
        definitions: vec![defn2_entry()],
        behaviour: Some(BehaviourDescriptor {
            kind: BEHAVIOUR_KIND.to_string(),
            reads: vec![READ.to_string()],
            effects: vec![],
        }),
        surface: Some(SurfaceDescriptor {
            kind: SURFACE_KIND.to_string(),
            view: "notes.view".to_string(),
            fallback: fallback.to_string(),
        }),
        declared_reads: vec![READ.to_string()],
    }
}

fn manifest() -> PackageManifest {
    manifest_with_fallback("pack.unavailable")
}

/// A definitions-only (K5) package: same definition revision, no behaviour,
/// no surface, and an empty declared-read set.
fn definitions_only_manifest() -> PackageManifest {
    PackageManifest {
        namespace: "acme".to_string(),
        name: "shapes".to_string(),
        version: 1,
        definitions: vec![defn2_entry()],
        behaviour: None,
        surface: None,
        declared_reads: vec![],
    }
}

fn fields(title: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "title".to_string(),
        serde_json::Value::String(title.to_string()),
    );
    map
}

async fn setup() -> (
    crate::db::Db,
    String,
    PackageManifest,
    crate::package_manifest::ManifestIdentity,
) {
    let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let m = manifest();
    let id = install_package_as(&db, &admin, &m).await.unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &m,
        Some(&id),
        &m.declared_reads,
    )
    .await
    .unwrap();
    (db, admin, m, id)
}

async fn make_record(db: &crate::db::Db, creator: &str, home: &str, title: &str) -> String {
    crate::kernel::create_as(db, creator, FAMILY, KIND, &fields(title), home)
        .await
        .unwrap()
}

async fn link(db: &crate::db::Db, creator: &str, source: &str, target: &str) {
    crate::kernel::link_records_as(db, creator, source, target)
        .await
        .unwrap();
}

fn linked_to(target: &str) -> Option<(&str, &str, &str)> {
    Some(("relates_to", target, "out"))
}

#[tokio::test]
async fn authorized_rows_served_with_receipt() {
    let (db, admin, m, id) = setup().await;
    let target = make_record(&db, &admin, KERNEL_ROOT_ID, "Target").await;
    let s1 = make_record(&db, &admin, KERNEL_ROOT_ID, "S1").await;
    let s2 = make_record(&db, &admin, KERNEL_ROOT_ID, "S2").await;
    link(&db, &admin, &s1, &target).await;
    link(&db, &admin, &s2, &target).await;
    match surface_read_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap()
    {
        SurfaceReadOutcome::Hits {
            hits,
            cursor,
            receipt,
        } => {
            assert_eq!(hits.len(), 2);
            assert_eq!(cursor, None);
            assert_eq!(receipt.package_digest, id.digest);
            assert_eq!(receipt.package_version, 1);
            assert!(receipt.ack_event_seq >= 1 && receipt.served_content_seq >= 1);
            let _ = m;
        }
        SurfaceReadOutcome::Fallback { fallback_view } => {
            panic!("expected hits, got fallback {fallback_view}")
        }
    }
    db.close().await;
}

#[tokio::test]
async fn private_target_indistinguishable_from_missing() {
    // Dedicated viewer: root View, no hidden-home grant. The viewer owns
    // nothing, so no owner floor can leak the hidden scope.
    let (db, admin, _, _) = setup().await;
    let viewer = create_principal(&db, "account", "Viewer", "test:viewer", &admin)
        .await
        .unwrap();
    crate::kernel::replace_home_policy(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &[(admin.as_str(), "manage"), (viewer.as_str(), "view")],
    )
    .await
    .unwrap();
    let stranger = create_principal(&db, "account", "Stranger", "test:stranger", &admin)
        .await
        .unwrap();
    let hidden_home = crate::kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(stranger.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    // Both ends live in the hidden home, owned and linked by its manager:
    // the viewer can View neither, so the linked-target gate answers empty
    // before any candidate scan — no cross-policy link required.
    let hidden = make_record(&db, &stranger, &hidden_home, "Hidden").await;
    let hidden_src = make_record(&db, &stranger, &hidden_home, "HiddenSrc").await;
    link(&db, &stranger, &hidden_src, &hidden).await;
    let via_hidden = surface_read_as(
        &db,
        &viewer,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&hidden),
        10,
        None,
    )
    .await
    .unwrap();
    let via_missing = surface_read_as(
        &db,
        &viewer,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to("00000000-0000-0000-0000-000000000000"),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(via_hidden, via_missing);
    match via_hidden {
        SurfaceReadOutcome::Hits { hits, cursor, .. } => {
            assert!(hits.is_empty() && cursor.is_none());
        }
        SurfaceReadOutcome::Fallback { fallback_view } => {
            panic!("expected empty hits, got fallback {fallback_view}")
        }
    }
    db.close().await;
}

#[tokio::test]
async fn visible_pagination_carries_no_totals() {
    let (db, admin, _, _) = setup().await;
    // Dedicated viewer owns nothing: root View only, so no owner floor can
    // leak the hidden home into the page.
    let viewer = create_principal(&db, "account", "Viewer", "test:viewer", &admin)
        .await
        .unwrap();
    crate::kernel::replace_home_policy(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &[(admin.as_str(), "manage"), (viewer.as_str(), "view")],
    )
    .await
    .unwrap();
    let stranger = create_principal(&db, "account", "Stranger", "test:stranger", &admin)
        .await
        .unwrap();
    let hidden_home = crate::kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(stranger.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    let target = make_record(&db, &admin, KERNEL_ROOT_ID, "Target").await;
    for title in ["V1", "V2", "V3"] {
        let id = make_record(&db, &admin, KERNEL_ROOT_ID, title).await;
        link(&db, &admin, &id, &target).await;
    }
    // Hidden records link among themselves (no principal holds authority
    // across both homes, so cross links are unmakable by design) and stay
    // link-filtered out of admin's page. This test covers visible cursor
    // pagination and the absence of totals; per-row authority skipping is
    // query_as's pre-existing, slice-2-tested machinery, not re-proven here.
    let hidden_target = make_record(&db, &stranger, &hidden_home, "HTarget").await;
    for title in ["H1", "H2"] {
        let id = make_record(&db, &stranger, &hidden_home, title).await;
        link(&db, &stranger, &id, &hidden_target).await;
    }
    let page1 = surface_read_as(
        &db,
        &viewer,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        2,
        None,
    )
    .await
    .unwrap();
    let (hits1, cursor1) = match page1 {
        SurfaceReadOutcome::Hits { hits, cursor, .. } => (hits, cursor),
        SurfaceReadOutcome::Fallback { fallback_view } => {
            panic!("expected hits, got fallback {fallback_view}")
        }
    };
    assert_eq!(hits1.len(), 2);
    let cursor = cursor1.expect("more visible hits remain");
    let page2 = surface_read_as(
        &db,
        &viewer,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        2,
        Some(&cursor),
    )
    .await
    .unwrap();
    match page2 {
        SurfaceReadOutcome::Hits { hits, cursor, .. } => {
            assert_eq!(hits.len(), 1);
            assert_eq!(cursor, None);
            let titles: Vec<String> = hits1
                .iter()
                .chain(hits.iter())
                .map(|h| h.fields["title"].as_str().unwrap().to_string())
                .collect();
            assert_eq!(titles, vec!["V1", "V2", "V3"]);
        }
        SurfaceReadOutcome::Fallback { fallback_view } => {
            panic!("expected hits, got fallback {fallback_view}")
        }
    }
    db.close().await;
}

#[tokio::test]
async fn undeclared_token_targetless_family_kind_fall_back() {
    let (db, admin, m, _) = setup().await;
    let target = make_record(&db, &admin, KERNEL_ROOT_ID, "Target").await;
    // Undeclared token.
    let out = surface_read_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        "resolution:view",
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        SurfaceReadOutcome::Fallback {
            fallback_view: m.surface.as_ref().unwrap().fallback.clone()
        }
    );
    // Targetless call with the fixed token.
    let out = surface_read_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        None,
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        SurfaceReadOutcome::Fallback {
            fallback_view: m.surface.as_ref().unwrap().fallback.clone()
        }
    );
    // Family outside the package.
    let out = surface_read_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        "demo.other",
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        SurfaceReadOutcome::Fallback {
            fallback_view: m.surface.as_ref().unwrap().fallback.clone()
        }
    );
    // Kind outside the embedded revision.
    let out = surface_read_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        "other",
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        SurfaceReadOutcome::Fallback {
            fallback_view: m.surface.as_ref().unwrap().fallback.clone()
        }
    );
    db.close().await;
}

#[tokio::test]
async fn disable_falls_back_and_keeps_v1_name_after_v2_install() {
    let (db, admin, m, id) = setup().await;
    let target = make_record(&db, &admin, KERNEL_ROOT_ID, "Target").await;
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &m,
        Some(&id),
        &m.declared_reads,
    )
    .await
    .unwrap();
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, None, &[])
        .await
        .unwrap();
    let v1fallback = m.surface.as_ref().unwrap().fallback.clone();
    // Install v2 with a different fallback without adopting: the disabled
    // read must still name v1's stored snapshot fallback.
    let mut v2 = manifest_with_fallback("pack.v2view");
    v2.version = 2;
    crate::kernel::install_package_as(&db, &admin, &v2)
        .await
        .unwrap();
    let out = surface_read_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        SurfaceReadOutcome::Fallback {
            fallback_view: v1fallback
        }
    );
    db.close().await;
}

#[tokio::test]
async fn freshness_receipt_invalidates_on_readopt() {
    let (db, admin, m, id) = setup().await;
    let target = make_record(&db, &admin, KERNEL_ROOT_ID, "Target").await;
    let stranger = create_principal(&db, "account", "Stranger", "test:stranger", &admin)
        .await
        .unwrap();
    let home = crate::kernel::create_home(
        &db,
        KERNEL_ROOT_ID,
        Some(&[(admin.as_str(), "manage"), (stranger.as_str(), "manage")]),
        &admin,
    )
    .await
    .unwrap();
    adopt_package_at(&db, &admin, &home, &m, Some(&id), &m.declared_reads)
        .await
        .unwrap();
    // Same scope for both receipts: only re-adoption may invalidate.
    let first = surface_read_as(
        &db,
        &admin,
        &home,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    let receipt1 = match first {
        SurfaceReadOutcome::Hits { receipt, .. } => receipt,
        SurfaceReadOutcome::Fallback { fallback_view } => {
            panic!("expected hits, got fallback {fallback_view}")
        }
    };
    adopt_package_at(&db, &stranger, &home, &m, Some(&id), &m.declared_reads)
        .await
        .unwrap();
    let second = surface_read_as(
        &db,
        &admin,
        &home,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    let receipt2 = match second {
        SurfaceReadOutcome::Hits { receipt, .. } => receipt,
        SurfaceReadOutcome::Fallback { fallback_view } => {
            panic!("expected hits, got fallback {fallback_view}")
        }
    };
    assert_ne!(receipt1.ack_event_seq, receipt2.ack_event_seq);
    // The fence, not a snapshot: receipt1's seq no longer matches live state.
    let mut conn = db.write_pool().acquire().await.unwrap();
    let live = crate::kernel::read_package_selection_in(&mut conn, &home, "acme", "notes")
        .await
        .unwrap()
        .unwrap();
    drop(conn);
    assert_eq!(live.event_seq, receipt2.ack_event_seq);
    assert_ne!(live.event_seq, receipt1.ack_event_seq);
    db.close().await;
}

#[tokio::test]
async fn two_packages_share_one_host_api() {
    let (db, admin, _, _) = setup().await;
    let mut other = manifest();
    other.name = "other".to_string();
    let other_id = install_package_as(&db, &admin, &other).await.unwrap();
    adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &other,
        Some(&other_id),
        &other.declared_reads,
    )
    .await
    .unwrap();
    let target = make_record(&db, &admin, KERNEL_ROOT_ID, "Target").await;
    for (ns, name) in [("acme", "notes"), ("acme", "other")] {
        match surface_read_as(
            &db,
            &admin,
            KERNEL_ROOT_ID,
            ns,
            name,
            READ,
            FAMILY,
            KIND,
            &[],
            linked_to(&target),
            10,
            None,
        )
        .await
        .unwrap()
        {
            SurfaceReadOutcome::Hits { receipt, .. } => assert_eq!(receipt.name, name),
            SurfaceReadOutcome::Fallback { fallback_view } => {
                panic!("expected hits for {ns}/{name}, got fallback {fallback_view}")
            }
        }
    }
    db.close().await;
}

fn defn2_bytes_version(version: u32) -> String {
    serde_json::json!({
        "family": FAMILY, "version": version,
        "interpreter": "native.defn/2", "primary_type": "note",
        "kinds": [{"token": KIND,
            "fields": [{"name": "title", "type": "text", "required": true}],
            "identity": {"field": "title"},
            "links": [{"predicate": "relates_to",
                "target": {"primary_type": "note", "kind": "note"},
                "direction": "either"}],
            "maturity": "current", "description": "A note."}],
    })
    .to_string()
}

#[tokio::test]
async fn pinned_package_serves_only_its_revision() {
    use crate::meta::definition_artifact::RevisionIdentity;
    let (db, admin, m, _id) = setup().await;
    // Second revision, same family and kind, installed and adopted in a home
    // scope so v2 records exist; the root package stays pinned to v1.
    let v2bytes = defn2_bytes_version(2);
    let v2digest = crate::meta::definition_artifact::digest_artifact_bytes(v2bytes.as_bytes());
    crate::kernel::install_definition_as(&db, &admin, FAMILY, 2, v2bytes.as_bytes())
        .await
        .unwrap();
    let target = make_record(&db, &admin, KERNEL_ROOT_ID, "Target").await;
    for title in ["R1a", "R1b"] {
        let id = make_record(&db, &admin, KERNEL_ROOT_ID, title).await;
        link(&db, &admin, &id, &target).await;
    }
    // v2 records live in a home scope where v2 is effectively adopted; the
    // root-scoped package stays pinned to v1 throughout (no re-adopt needed
    // and none performed, so the v1 pins are never disturbed).
    let v2home = crate::kernel::create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    // Remove the inherited v1 surface before choosing a different pin in
    // this child. The root package remains active and pinned to v1.
    adopt_package_at(&db, &admin, &v2home, &m, None, &[])
        .await
        .unwrap();
    crate::kernel::adopt_definition_at(
        &db,
        &admin,
        FAMILY,
        Some(&RevisionIdentity {
            family: FAMILY.to_string(),
            version: 2,
            digest: v2digest,
        }),
        &v2home,
    )
    .await
    .unwrap();
    let r2 = make_record(&db, &admin, &v2home, "R2a").await;
    link(&db, &admin, &r2, &target).await;
    let read = |limit: usize, cursor: Option<String>| {
        let db = &db;
        let admin = &admin;
        let target = &target;
        async move {
            surface_read_as(
                db,
                admin,
                KERNEL_ROOT_ID,
                "acme",
                "notes",
                READ,
                FAMILY,
                KIND,
                &[],
                linked_to(target),
                limit,
                cursor.as_deref(),
            )
            .await
            .unwrap()
        }
    };
    let titles = |outcome: SurfaceReadOutcome| match outcome {
        SurfaceReadOutcome::Hits { hits, .. } => hits
            .iter()
            .map(|h| h.fields["title"].as_str().unwrap().to_string())
            .collect::<Vec<_>>(),
        SurfaceReadOutcome::Fallback { fallback_view } => {
            panic!("expected hits, got fallback {fallback_view}")
        }
    };
    // Full page: v1 rows only, no cursor (v2 never enters the scan).
    assert_eq!(titles(read(10, None).await), vec!["R1a", "R1b"]);
    // Paginated: cursor chains visible v1 rows only.
    let page1 = surface_read_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        1,
        None,
    )
    .await
    .unwrap();
    let cursor = match page1 {
        SurfaceReadOutcome::Hits { hits, cursor, .. } => {
            assert_eq!(hits.len(), 1);
            cursor.expect("second visible v1 row remains")
        }
        SurfaceReadOutcome::Fallback { fallback_view } => {
            panic!("expected hits, got fallback {fallback_view}")
        }
    };
    assert_eq!(titles(read(1, Some(cursor)).await), vec!["R1b"]);
    db.close().await;
}

#[tokio::test]
async fn malformed_cursor_answers_named_fallback() {
    // Query-leg errors (here: undecodable cursor) map to the known manifest
    // fallback rather than surfacing Err kinds. The scan bound shares this
    // arm: it counts pre-authority candidates, so Err would leak a
    // threshold; the bound itself is exercised by construction, not by
    // materializing 5000+ rows in this focused suite.
    let (db, admin, m, _) = setup().await;
    let target = make_record(&db, &admin, KERNEL_ROOT_ID, "Target").await;
    let out = surface_read_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        Some("!!!not-a-cursor!!!"),
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        SurfaceReadOutcome::Fallback {
            fallback_view: m.surface.as_ref().unwrap().fallback.clone()
        }
    );
    db.close().await;
}

#[tokio::test]
async fn child_displacement_names_ancestor_snapshot_fallback() {
    use crate::meta::definition_artifact::RevisionIdentity;
    let (db, admin, m, id) = setup().await;
    let child = crate::kernel::create_home(&db, KERNEL_ROOT_ID, None, &admin)
        .await
        .unwrap();
    // Recreate a canonical pre-enforcement displacement in the child.
    // The supported adoption path now refuses this state; the read gate
    // must still give the ancestor's named fallback for retained history.
    let v2bytes = defn2_bytes_version(2);
    let v2digest = crate::meta::definition_artifact::digest_artifact_bytes(v2bytes.as_bytes());
    crate::kernel::install_definition_as(&db, &admin, FAMILY, 2, v2bytes.as_bytes())
        .await
        .unwrap();
    crate::dependency_tests::legacy_override(
        &db,
        &admin,
        &child,
        &RevisionIdentity {
            family: FAMILY.to_string(),
            version: 2,
            digest: v2digest,
        },
    )
    .await;
    let target = make_record(&db, &admin, KERNEL_ROOT_ID, "Target").await;
    let out = surface_read_as(
        &db,
        &admin,
        &child,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    // No local package-selection events exist, so naming walks to the root's selected
    // v1 snapshot rather than the generic view.
    assert_eq!(
        out,
        SurfaceReadOutcome::Fallback {
            fallback_view: m.surface.as_ref().unwrap().fallback.clone()
        }
    );
    let _ = id;
    db.close().await;
}

#[tokio::test]
async fn hidden_scope_and_missing_package_answer_generic_fallback() {
    let (db, admin, _, _) = setup().await;
    let stranger = create_principal(&db, "account", "Stranger", "test:stranger", &admin)
        .await
        .unwrap();
    let target = make_record(&db, &admin, KERNEL_ROOT_ID, "Target").await;
    // Stranger holds no View on the root scope: generic fallback, with no
    // package metadata (not even the named view) crossing the boundary.
    let out = surface_read_as(
        &db,
        &stranger,
        KERNEL_ROOT_ID,
        "acme",
        "notes",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        SurfaceReadOutcome::Fallback {
            fallback_view: SURFACE_FALLBACK_VIEW.to_string()
        }
    );
    // Never-installed package for an authorized viewer: generic too.
    let out = surface_read_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "ghost",
        READ,
        FAMILY,
        KIND,
        &[],
        linked_to(&target),
        10,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        SurfaceReadOutcome::Fallback {
            fallback_view: SURFACE_FALLBACK_VIEW.to_string()
        }
    );
    db.close().await;
}

/// A definitions-only package has no behaviour or surface: the surface read
/// and the rendered model report that cleanly instead of naming a fallback
/// that does not exist or refusing the adoption.
#[tokio::test]
async fn definitions_only_package_surface_read_reports_no_surface() {
    let (db, admin) = create_v2_database(":memory:", "account", "Admin", "test:admin")
        .await
        .unwrap();
    let m = definitions_only_manifest();
    let id = install_package_as(&db, &admin, &m).await.unwrap();
    adopt_package_at(&db, &admin, KERNEL_ROOT_ID, &m, Some(&id), &[])
        .await
        .unwrap();

    let out = surface_read_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "shapes",
        READ,
        FAMILY,
        KIND,
        &[],
        None,
        20,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        out,
        SurfaceReadOutcome::Fallback {
            fallback_view: crate::kernel::SURFACE_NONE_VIEW.to_string()
        }
    );

    let model = crate::kernel::render_package_surface_as(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        "acme",
        "shapes",
        READ,
        FAMILY,
        KIND,
        &[],
        None,
        20,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        model,
        crate::kernel::SurfaceViewModel::Notice {
            notice: crate::kernel::SURFACE_NONE_VIEW.to_string()
        }
    );
    db.close().await;
}
