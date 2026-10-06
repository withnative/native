//! SECOND- and THIRD-slice probes for Native task 7907284 (`:memory:` only).
//!
//! `bare_genesis_refuses_without_collection_root` pins the ordinary-path
//! refusals on a schema-only database: no Collection root is seeded and no
//! Document/WorkItem disguise is used.
//!
//! `kernel_mode_neutral_root_with_policy_anchor` builds the isolated test-only
//! kernel mode: real content and policy logs, one structurally neutral root,
//! and zero v1 domain rows. A separate v1 control verifies ordinary genesis.

use crate::mcp::{Caller, ToolRegistry};
use crate::store::{append, AppendSpec};

fn surface_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    crate::mcp::register_surface_tools(&mut registry).unwrap();
    registry
}

#[tokio::test]
async fn bare_genesis_refuses_without_collection_root() {
    let db = crate::db::open_database(":memory:").await.unwrap();
    crate::db::apply_schema(&db).await.unwrap();

    let records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(records, 0, "schema-only must hold zero records");

    // 1. Root policy genesis requires the canonical root row.
    let policy_err = crate::policy::seed_root_policy(&db)
        .await
        .unwrap_err()
        .to_string();
    println!("POLICY_REFUSAL: {policy_err}");
    assert!(
        policy_err.contains("canonical root content record"),
        "{policy_err}"
    );

    // 2. Authoring a bare primary type through the real tool surface.
    let create_err = surface_registry()
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            serde_json::json!({
                "type": "KernelNote", "kind": "bare-note",
                "reason": "Bare-kernel probe: no Collection root, no disguise.",
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    println!("CREATE_REFUSAL: {create_err}");
    assert!(create_err.contains("is not a spine type"), "{create_err}");

    // 3. Event seam: bare record.created with null home through projector.
    let bare_id = uuid::Uuid::new_v4().to_string();
    let append_err = append(
        &db,
        AppendSpec {
            record_id: bare_id,
            event_type: "record.created".into(),
            payload: serde_json::json!({
                "type": "KernelNote", "kind": "bare-note", "home_id": null,
            }),
            actor: Some("test:bare-kernel".into()),
        },
    )
    .await
    .unwrap_err()
    .to_string();
    println!("APPEND_REFUSAL: {append_err}");
    assert!(!append_err.is_empty(), "append must refuse");

    // 4. DDL floor: raw rogue insert must trip the closed CHECK.
    let rogue: Result<_, sqlx::Error> =
        sqlx::query("INSERT INTO records (id, type, kind) VALUES (?, ?, ?)")
            .bind(format!("rogue-{}", uuid::Uuid::new_v4()))
            .bind("KernelNote")
            .bind("bare-note")
            .execute(db.write_pool())
            .await;
    let ddl_err = rogue.unwrap_err().to_string();
    println!("DDL_REFUSAL: {ddl_err}");
    assert!(ddl_err.contains("CHECK"), "{ddl_err}");

    // Edge: no endpoints exist, so no directed edge is attempted; blocked
    // downstream of record creation by the refusals above.
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(left, 0, "refused probe must store zero records");
}

#[tokio::test]
async fn kernel_mode_neutral_root_with_policy_anchor() {
    use crate::events::{KERNEL_GENESIS_ACTOR, KERNEL_GENESIS_EVENT, KERNEL_ROOT_ID};

    // Kernel mode uses the current frozen engine schema.
    assert_eq!(crate::schema::DDL_STATEMENTS.len(), 358);
    assert_eq!(
        crate::schema::ddl_sha256(),
        crate::schema::FROZEN_DDL_SHA256,
        "frozen DDL fingerprint must not move for the kernel slice",
    );

    let db = crate::kernel::create_kernel_database(":memory:")
        .await
        .unwrap();

    // Zero domain rows: no records at all (hence no Collection), no seeded
    // vocabulary or kind values.
    let records: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(records, 0, "kernel DB must hold zero records");
    let vocabs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vocabularies")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(vocabs, 0, "kernel DB seeds no vocabularies");
    let kinds: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vocabulary_values")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(kinds, 0, "kernel DB seeds no kinds");

    // Exactly one neutral root, and its columns carry no ontology.
    let root: (String, i64, String) =
        sqlx::query_as("SELECT root_id, created_seq, created_at FROM kernel_roots")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
    println!("KERNEL_ROOT: {root:?}");
    assert_eq!(root.0, KERNEL_ROOT_ID);
    assert_eq!(root.1, 1, "genesis must be content event one");
    assert!(!root.2.trim().is_empty());

    // History readable through the real content log: exactly the genesis.
    let event: (i64, String, String, String, Option<String>, String) = sqlx::query_as(
        "SELECT seq, type, record_id, actor, payload, causal_status FROM content_events",
    )
    .fetch_one(db.write_pool())
    .await
    .unwrap();
    println!("KERNEL_HISTORY: {event:?}");
    assert_eq!(event.0, 1);
    assert_eq!(event.1, KERNEL_GENESIS_EVENT);
    assert_eq!(event.2, KERNEL_ROOT_ID);
    assert_eq!(event.3, KERNEL_GENESIS_ACTOR);
    assert_eq!(event.4.as_deref(), Some("{}"));
    assert_eq!(event.5, "complete");

    // The unchanged policy event log now folds into the separate neutral
    // kernel anchor, without a Collection row or v1 policy projection.
    let policies: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(policies, 1);
    let anchors: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM record_policies")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(anchors, 0);
    let kernel_entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_policy_entries")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(kernel_entries, 1);

    // Control: ordinary v1 creation on a separate database still seeds the
    // canonical Collection roots.
    let v1 = crate::db::create_database(":memory:").await.unwrap();
    let roots: Vec<(String, String)> = sqlx::query_as(
        "SELECT id, type FROM records WHERE id IN ('native:root', 'native:unfiled')",
    )
    .fetch_all(v1.write_pool())
    .await
    .unwrap();
    assert_eq!(roots.len(), 2, "v1 control keeps both roots");
    assert!(roots.iter().all(|(_, t)| t == "Collection"), "{roots:?}");
}

#[tokio::test]
async fn bare_record_link_and_package_pinned_specimen() {
    let db = crate::kernel::create_kernel_database(":memory:")
        .await
        .unwrap();
    let first = crate::kernel::create_bare_record(&db).await.unwrap();
    let second = crate::kernel::create_bare_record(&db).await.unwrap();
    crate::kernel::link_records(&db, &first, &second)
        .await
        .unwrap();

    let before = crate::kernel::create_package_record(
        &db,
        "Specimen",
        "field-sample",
        "LAB-001",
        "lab.specimen",
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(before.contains("not adopted"), "{before}");

    let family = "lab.specimen";
    let bytes = serde_json::json!({
        "family": family, "version": 1, "primary_type": "Specimen",
        "kinds": [{"token": "field-sample"}, {"token": "lab-aliquot"}],
    })
    .to_string()
    .into_bytes();
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let installed = crate::definition_registry::install_definition_artifact_in(
        &mut tx, family, 1, &bytes, &mut acts,
    )
    .await
    .unwrap();
    crate::meta::adoption::append_definition_adoption_in(
        &mut tx,
        family,
        Some(&installed.identity),
        &mut acts,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let wrong_type =
        crate::kernel::create_package_record(&db, "Jar", "field-sample", "LAB-X", family)
            .await
            .unwrap_err()
            .to_string();
    assert!(
        wrong_type.contains("disagrees with selected definition"),
        "{wrong_type}"
    );
    let wrong_kind =
        crate::kernel::create_package_record(&db, "Specimen", "unknown-kind", "LAB-X", family)
            .await
            .unwrap_err()
            .to_string();
    assert!(
        wrong_kind.contains("absent from selected definition"),
        "{wrong_kind}"
    );

    let specimen =
        crate::kernel::create_package_record(&db, "Specimen", "field-sample", "LAB-001", family)
            .await
            .unwrap();
    #[allow(clippy::type_complexity)]
    let row: (Option<String>, Option<String>, Option<String>, Option<i64>, Option<String>) = sqlx::query_as(
        "SELECT primary_type, kind, pin_family, pin_version, pin_digest FROM kernel_records WHERE id = ?",
    ).bind(&specimen).fetch_one(db.write_pool()).await.unwrap();
    assert_eq!(row.0.as_deref(), Some("Specimen"));
    assert_eq!(row.1.as_deref(), Some("field-sample"));
    assert_eq!(row.2.as_deref(), Some(family));
    assert_eq!(row.3, Some(1));
    assert_eq!(row.4.as_deref(), Some(installed.identity.digest.as_str()));
    let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_links WHERE source_id = ? AND target_id = ? AND relationship = 'relates_to'")
        .bind(&first).bind(&second).fetch_one(db.write_pool()).await.unwrap();
    assert_eq!(links, 1);
    let ordinary_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(ordinary_rows, 0);
    let history: Vec<String> = sqlx::query_scalar("SELECT type FROM content_events ORDER BY seq")
        .fetch_all(db.write_pool())
        .await
        .unwrap();
    assert_eq!(
        history,
        vec![
            "kernel.root_created.v1",
            "kernel.record_created.v1",
            "kernel.record_created.v1",
            "kernel.link_added.v1",
            "kernel.record_created.v1"
        ]
    );

    // A policy event removes members/edit; the same authoring path refuses.
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    crate::policy::append_replaced_in(
        &mut tx,
        crate::events::KERNEL_ROOT_ID,
        vec![],
        crate::events::KERNEL_GENESIS_ACTOR,
        "close kernel test authority",
        &mut acts,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let denied = crate::kernel::create_bare_record(&db)
        .await
        .unwrap_err()
        .to_string();
    assert!(denied.contains("lacks members/edit authority"), "{denied}");
}
