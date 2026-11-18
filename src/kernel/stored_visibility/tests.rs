//! Runtime marking tests (73ad275 §9.6–§9.8): the compiled objects, real
//! write paths, every conflict form on every input, lifecycle and data
//! survival, and the writer contract on a real handle.

use super::*;
use std::collections::BTreeSet;

type Key = (String, String);

fn key(kind: KeyKind, key: &str) -> Key {
    (kind.as_str().to_owned(), key.to_owned())
}

struct Fixture {
    db: Db,
    admin: String,
    _dir: tempfile::TempDir,
}

async fn fixture(marking: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("marking.db").display()),
        "account",
        "Admin",
        "admin",
    )
    .await
    .unwrap();
    if marking {
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        install_on(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
    }
    Fixture {
        db,
        admin,
        _dir: dir,
    }
}

async fn dirty(db: &Db) -> BTreeSet<Key> {
    let mut conn = db.write_pool().acquire().await.unwrap();
    dirty_keys_on(&mut conn)
        .await
        .unwrap()
        .into_iter()
        .collect()
}

async fn clear(db: &Db) {
    sqlx::query("DELETE FROM main.p_dirty")
        .execute(db.write_pool())
        .await
        .unwrap();
}

async fn state(db: &Db) -> ObjectState {
    let mut conn = db.write_pool().acquire().await.unwrap();
    object_state_on(&mut conn).await.unwrap()
}

async fn marking_row(db: &Db) -> MarkingRow {
    let mut conn = db.write_pool().acquire().await.unwrap();
    marking_row_on(&mut conn).await.unwrap().unwrap()
}

#[track_caller]
fn assert_marked(dirty: &BTreeSet<Key>, expected: &[Key]) {
    for k in expected {
        assert!(dirty.contains(k), "missing {k:?} in {dirty:?}");
    }
}

#[test]
fn triggers_cover_exactly_the_input_tables_for_every_operation() {
    let mut covered = BTreeSet::new();
    for (name, table, sql) in triggers() {
        assert!(name.starts_with("p_mark_"), "{name}");
        assert!(sql.contains(&format!(" ON {table} WHEN ")), "{sql}");
        assert!(
            sql.contains(ENABLED_GUARD),
            "{name} lacks the enabled guard"
        );
        // M1: only the upsert form; no lookup or JSON in any body.
        let body = sql.split_once(" BEGIN ").unwrap().1;
        assert!(
            !body.contains("OR IGNORE") && !body.contains("REPLACE"),
            "{name}"
        );
        assert!(!body.contains("json"), "{name}");
        assert_eq!(
            body.matches("INSERT INTO p_dirty(kind, key) SELECT")
                .count(),
            body.matches("ON CONFLICT(kind, key) DO NOTHING;").count(),
            "{name}"
        );
        for op in ["insert", "update", "delete"] {
            if name.ends_with(op) {
                covered.insert((*table, op));
            }
        }
    }
    let expected: BTreeSet<_> = MARKED_INPUT_TABLES
        .iter()
        .flat_map(|t| ["insert", "update", "delete"].map(|op| (*t, op)))
        .collect();
    assert_eq!(covered, expected);
}

#[test]
fn every_accelerator_table_is_excluded_from_projection_digests() {
    for table in TABLES {
        assert!(
            super::super::projection_dump::EXCLUDED_TABLES.contains(&table),
            "{table}"
        );
    }
}

#[test]
fn fingerprint_moves_with_any_trigger_text() {
    let base = fingerprint().to_owned();
    let mut objects = expected_objects().to_vec();
    let with_sql = objects.iter().position(|o| o.3.is_some()).unwrap();
    objects[with_sql].3 = Some(format!("{} ", objects[with_sql].3.clone().unwrap()));
    let changed = hex::encode(Sha256::digest(
        serde_json::to_vec(&(MARKING_VERSION, &objects)).unwrap(),
    ));
    assert_ne!(base, changed);
    let bumped = hex::encode(Sha256::digest(
        serde_json::to_vec(&(MARKING_VERSION + 1, expected_objects())).unwrap(),
    ));
    assert_ne!(base, bumped);
}

/// M8 is generated from the access fence: every `RecomputeAll` stem gets an
/// explicit scope, every scope names a classified stem, and the hosted
/// template and frontier types the visibility gate reads mark their anchor.
#[test]
fn typed_event_marks_are_generated_from_the_access_fence() {
    use super::super::access_fence::{AccessClass, STEM_CLASSES};
    for (stem, kind) in EVENT_SCOPES {
        assert!(
            STEM_CLASSES.iter().any(|(s, _)| s == stem),
            "{stem} is not classified"
        );
        assert!(matches!(
            kind,
            KeyKind::Anchor | KeyKind::Roster | KeyKind::Ws
        ));
    }
    for (stem, class) in STEM_CLASSES {
        if *class == AccessClass::RecomputeAll {
            assert!(
                EVENT_SCOPES.iter().any(|(s, _)| s == stem),
                "RecomputeAll stem {stem} needs an explicit marking scope"
            );
        }
    }
    let anchors = event_stems(KeyKind::Anchor);
    let gate_sql = [
        super::super::hosted_identity::POLICY_TEMPLATES_SQL,
        super::super::hosted_identity::POLICY_FRONTIERS_SQL,
    ]
    .join(" ");
    let mut read_types: Vec<String> = gate_sql
        .split('\'')
        .filter(|s| s.starts_with("kernel.") && s.matches('.').count() == 2)
        .map(str::to_owned)
        .collect();
    read_types.push(super::super::hosted_identity::POLICY_EVENT.to_owned());
    assert!(read_types.len() >= 5, "{read_types:?}");
    for event_type in read_types {
        let stem = super::super::access_fence::stem_of(&event_type).unwrap();
        assert!(anchors.contains(&stem), "{event_type} must mark its anchor");
    }
    let roster = event_stems(KeyKind::Roster);
    let roster_event = super::super::hosted_identity::ROSTER_EVENT;
    assert!(roster.contains(&super::super::access_fence::stem_of(roster_event).unwrap()));
}

#[tokio::test]
async fn fresh_file_has_no_accelerators_and_install_is_exact_and_idempotent() {
    let fx = fixture(false).await;
    assert_eq!(state(&fx.db).await, ObjectState::Absent);
    for _ in 0..2 {
        let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
        install_on(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(state(&fx.db).await, ObjectState::Exact);
    }
    let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM main.content_events")
        .fetch_one(fx.db.pool())
        .await
        .unwrap();
    let row = marking_row(&fx.db).await;
    assert!(row.enabled);
    assert_eq!(row.marking_since_seq, head);
    assert_eq!(row.fingerprint, fingerprint());
    assert!(dirty(&fx.db).await.is_empty());
}

#[tokio::test]
async fn install_requires_a_transaction_and_a_kernel_v2_file() {
    let fx = fixture(false).await;
    let mut conn = fx.db.write_pool().acquire().await.unwrap();
    assert!(install_on(&mut conn).await.is_err());
    drop(conn);
    let v1 = crate::db::create_database(":memory:").await.unwrap();
    let mut tx = begin_write(v1.write_pool()).await.unwrap();
    let error = install_on(&mut tx).await.unwrap_err().to_string();
    assert!(error.contains("kernel v2"), "{error}");
}

#[tokio::test]
async fn drift_is_detected_and_reinstall_or_drop_repairs_it() {
    let fx = fixture(true).await;
    sqlx::query("DROP TRIGGER main.p_mark_kernel_records_insert")
        .execute(fx.db.write_pool())
        .await
        .unwrap();
    assert_eq!(state(&fx.db).await, ObjectState::Drifted);
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    install_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(state(&fx.db).await, ObjectState::Exact);

    // A changed definition with the right name is drift, not a match.
    sqlx::query("DROP TRIGGER main.p_mark_kernel_lifecycle_delete; CREATE TRIGGER p_mark_kernel_lifecycle_delete AFTER DELETE ON kernel_lifecycle BEGIN SELECT 1; END")
        .execute(fx.db.write_pool())
        .await
        .unwrap();
    assert_eq!(state(&fx.db).await, ObjectState::Drifted);
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    drop_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(state(&fx.db).await, ObjectState::Absent);
    // Writes keep working with marking gone.
    create_record_as(&fx.db, &fx.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
}

/// Marking through the real engine write paths: each canonical change marks
/// the keys §2.2 assigns it, old and new.
#[tokio::test]
async fn real_write_paths_mark_their_keys() {
    let fx = fixture(true).await;
    let (db, admin) = (&fx.db, fx.admin.as_str());

    let member = create_principal(db, "account", "Member", "member", admin)
        .await
        .unwrap();
    assert_marked(&dirty(db).await, &[key(KeyKind::Principal, &member)]);

    clear(db).await;
    let home = create_home(db, KERNEL_ROOT_ID, Some(&[(&member, "view")]), admin)
        .await
        .unwrap();
    assert_marked(
        &dirty(db).await,
        &[
            key(KeyKind::Home, &home),
            key(KeyKind::Anchor, &home),
            key(KeyKind::Rec, &home),
        ],
    );

    clear(db).await;
    let other = create_home(db, KERNEL_ROOT_ID, None, admin).await.unwrap();
    let record = create_record_as(db, admin, &home).await.unwrap();
    let comment = create_record_as(db, admin, &home).await.unwrap();
    assert_marked(
        &dirty(db).await,
        &[
            key(KeyKind::Home, &other),
            key(KeyKind::Rec, &record),
            key(KeyKind::Rec, &comment),
        ],
    );

    clear(db).await;
    super::super::generic_links::add_generic_link_as(db, admin, &comment, &record, "part_of", None)
        .await
        .unwrap();
    assert_marked(
        &dirty(db).await,
        &[key(KeyKind::Rec, &comment), key(KeyKind::Rec, &record)],
    );

    clear(db).await;
    rehome_record_as(db, admin, &record, &other).await.unwrap();
    assert_marked(
        &dirty(db).await,
        &[
            key(KeyKind::Rec, &record),
            key(KeyKind::Home, &home),
            key(KeyKind::Home, &other),
        ],
    );

    clear(db).await;
    replace_home_policy(db, admin, &home, &[(&member, "edit")])
        .await
        .unwrap();
    assert_marked(&dirty(db).await, &[key(KeyKind::Anchor, &home)]);

    clear(db).await;
    let revision = read_record_as(db, admin, &record)
        .await
        .unwrap()
        .unwrap()
        .revision;
    super::super::hq::set_body_as(db, admin, &record, "body", revision)
        .await
        .unwrap();
    assert_marked(&dirty(db).await, &[key(KeyKind::Rec, &record)]);

    let marked = dirty(db).await;
    assert!(
        !marked.contains(&key(KeyKind::Ws, "")),
        "ordinary writes never take the coarse key: {marked:?}"
    );
}

/// Event-type marks (M8) on synthetic appends: templates and frontiers mark
/// their anchor, roster events mark `roster`, unknown types mark `ws`.
#[tokio::test]
async fn content_event_types_mark_typed_keys() {
    let fx = fixture(true).await;
    let cases = [
        ("kernel.body_set.v1", vec![key(KeyKind::Rec, "h")]),
        (
            "kernel.import_member_policy.v1",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Anchor, "h")],
        ),
        (
            "kernel.home_policy_replaced.v1",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Anchor, "h")],
        ),
        (
            "kernel.import_home.v1",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Anchor, "h")],
        ),
        (
            "kernel.hosted_membership.v1",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Roster, "")],
        ),
        (
            "kernel.hosted_offboarding.v1",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Roster, "")],
        ),
        (
            "kernel.import_members_roster.v1",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Roster, "")],
        ),
        ("kernel.hcp_read.v1", vec![key(KeyKind::Rec, "h")]),
        (
            "kernel.root_created.v1",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Ws, "")],
        ),
        (
            "kernel.not_a_real_type.v9",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Ws, "")],
        ),
        // The access fence classifies by prefix, dots and all.
        ("kernel.hcp_read.v1.extra", vec![key(KeyKind::Rec, "h")]),
        (
            "kernel.hcp_",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Ws, "")],
        ),
        (
            "policy.replaced",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Ws, "")],
        ),
        (
            "kernel..v1",
            vec![key(KeyKind::Rec, "h"), key(KeyKind::Ws, "")],
        ),
    ];
    for (event_type, expected) in cases {
        clear(&fx.db).await;
        let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
        sqlx::query("INSERT INTO content_events(id, record_id, type, payload, causal_envelope_version, causal_status) VALUES(?, 'h', ?, '{}', 1, 'complete')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(event_type)
            .execute(&mut *tx)
            .await
            .unwrap();
        let marked: BTreeSet<Key> = dirty_keys_on(&mut tx).await.unwrap().into_iter().collect();
        tx.rollback().await.unwrap();
        assert_eq!(
            marked,
            expected.into_iter().collect::<BTreeSet<_>>(),
            "{event_type}"
        );
    }
}

/// The trigger's typed marks equal the Rust model built on the access fence,
/// for every classified stem and a set of adversarial shapes.
#[tokio::test]
async fn content_event_marks_match_the_access_fence_exactly() {
    use super::super::access_fence::{
        class_of, stem_of, AccessClass, PREFIX_CLASSES, STEM_CLASSES,
    };
    let expected = |event_type: &str| -> BTreeSet<Key> {
        let mut keys = BTreeSet::from([key(KeyKind::Rec, "h")]);
        match class_of(event_type) {
            None => {
                keys.insert(key(KeyKind::Ws, ""));
            }
            Some(class) => {
                let stem = stem_of(event_type).unwrap();
                if let Some((_, kind)) = EVENT_SCOPES.iter().find(|(s, _)| *s == stem) {
                    let k = if *kind == KeyKind::Anchor { "h" } else { "" };
                    keys.insert(key(*kind, k));
                } else if class == AccessClass::RecomputePrincipals {
                    keys.insert(key(KeyKind::Roster, ""));
                }
            }
        }
        keys
    };
    let mut types: Vec<String> = Vec::new();
    for (stem, _) in STEM_CLASSES {
        for version in ["v1", "v2", "", "v1.x"] {
            types.push(format!("kernel.{stem}.{version}"));
        }
        types.push(format!("kernel.{stem}"));
        types.push(format!("Kernel.{stem}.v1"));
        types.push(format!("kernel.{stem}x.v1"));
        types.push(format!("xkernel.{stem}.v1"));
    }
    for (prefix, _) in PREFIX_CLASSES {
        for tail in ["x.v1", ".v1", "a.b.c", "", "x"] {
            types.push(format!("kernel.{prefix}{tail}"));
        }
    }
    types.extend(
        [
            "",
            ".",
            "kernel.",
            "kernel..",
            "kernel...v1",
            "policy.replaced",
            "kernel.é.v1",
            "kernel.body_set.v1\u{0}",
        ]
        .map(str::to_owned),
    );
    let fx = fixture(true).await;
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    for event_type in &types {
        sqlx::query("DELETE FROM main.p_dirty")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO content_events(id, record_id, type, payload, causal_envelope_version, causal_status) VALUES(?, 'h', ?, '{}', 1, 'complete')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(event_type)
            .execute(&mut *tx)
            .await
            .unwrap();
        let marked: BTreeSet<Key> = dirty_keys_on(&mut tx).await.unwrap().into_iter().collect();
        if event_type.contains('\0') {
            // SQLite string functions stop at NUL; the trigger then marks
            // `ws`, the safe direction.
            assert!(marked.is_superset(&expected(event_type)), "{event_type:?}");
        } else {
            assert_eq!(marked, expected(event_type), "{event_type:?}");
        }
    }
    tx.rollback().await.unwrap();
}

/// Every production HQ event type is classified, so only the bootstrap
/// types reach the coarse key.
#[tokio::test]
async fn hq_event_types_never_mark_ws_except_bootstrap() {
    let fx = fixture(true).await;
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    for (stem, _) in super::super::access_fence::STEM_CLASSES {
        sqlx::query("DELETE FROM main.p_dirty")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO content_events(id, record_id, type, payload, causal_envelope_version, causal_status) VALUES(?, 'h', ?, '{}', 1, 'complete')")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(format!("kernel.{stem}.v1"))
            .execute(&mut *tx)
            .await
            .unwrap();
        let ws = dirty_keys_on(&mut tx)
            .await
            .unwrap()
            .contains(&key(KeyKind::Ws, ""));
        let bootstrap = EVENT_SCOPES.contains(&(*stem, KeyKind::Ws));
        assert_eq!(ws, bootstrap, "{stem}");
    }
    tx.rollback().await.unwrap();
}

/// One synthetic row per input: `(insert, the key column, its old and new
/// value, the expected kinds)`. Values satisfy every CHECK; foreign keys are
/// off on the test connection.
struct Row {
    table: &'static str,
    insert: &'static str,
    pk: &'static str,
    key_column: &'static str,
    upsert: &'static str,
    kinds: &'static [KeyKind],
}

const ROWS: &[Row] = &[
    Row { table: "kernel_records", insert: "INSERT INTO kernel_records(id, home_id, created_seq, created_at) VALUES('k1', 'hx', 1, 't')", pk: "id", key_column: "id", upsert: "home_id = excluded.home_id", kinds: &[KeyKind::Rec] },
    Row { table: "kernel_roots", insert: "INSERT INTO kernel_roots(root_id, parent_id, created_seq, created_at) VALUES('k1', NULL, 1, 't')", pk: "root_id", key_column: "root_id", upsert: "created_at = excluded.created_at", kinds: &[KeyKind::Home] },
    Row { table: "kernel_policies", insert: "INSERT INTO kernel_policies(root_id, created_at) VALUES('k1', 't')", pk: "root_id", key_column: "root_id", upsert: "created_at = excluded.created_at", kinds: &[KeyKind::Anchor, KeyKind::Home] },
    Row { table: "kernel_policy_entries", insert: "INSERT INTO kernel_policy_entries(root_id, subject_kind, subject_id, effect, capability) VALUES('k1', 'account', 's', 'allow', 'view')", pk: "root_id, subject_kind, subject_id, capability", key_column: "root_id", upsert: "effect = excluded.effect", kinds: &[KeyKind::Anchor] },
    Row { table: "kernel_principals", insert: "INSERT INTO kernel_principals(principal_id, kind, display_label, auth_binding) VALUES('k1', 'account', 'l', 'b-k1')", pk: "principal_id", key_column: "principal_id", upsert: "display_label = excluded.display_label", kinds: &[KeyKind::Principal] },
    Row { table: "kernel_generic_links", insert: "INSERT INTO kernel_generic_links(link_id, source_id, target_id, relationship, created_at, active, event_seq, imported) VALUES('l1', 'k1', 'tgt', 'part_of', 't', 1, 1, 0)", pk: "link_id", key_column: "source_id", upsert: "active = excluded.active", kinds: &[KeyKind::Rec] },
    Row { table: "kernel_import_tombstones", insert: "INSERT INTO kernel_import_tombstones(record_id, deleted_at, event_seq) VALUES('k1', 't', 1)", pk: "record_id", key_column: "record_id", upsert: "deleted_at = excluded.deleted_at", kinds: &[KeyKind::Rec] },
    Row { table: "kernel_record_fields", insert: "INSERT INTO kernel_record_fields(record_id, name, value_json, created_seq) VALUES('k1', 'title', '\"x\"', 1)", pk: "record_id, name", key_column: "record_id", upsert: "value_json = excluded.value_json", kinds: &[KeyKind::Rec] },
    Row { table: "kernel_messages", insert: "INSERT INTO kernel_messages(message_id, state, event_seq) VALUES('k1', '{}', 1)", pk: "message_id", key_column: "message_id", upsert: "state = excluded.state", kinds: &[KeyKind::Rec] },
    Row { table: "kernel_facets", insert: "INSERT INTO kernel_facets(record_id, key, value, as_of, event_seq) VALUES('k1', 'f', 'v', 't', 1)", pk: "record_id, key", key_column: "record_id", upsert: "value = excluded.value", kinds: &[KeyKind::Rec] },
    Row { table: "kernel_record_metadata", insert: "INSERT INTO kernel_record_metadata(record_id, persistence, last_activity_at, event_seq) VALUES('k1', 'enduring', 't', 1)", pk: "record_id", key_column: "record_id", upsert: "last_activity_at = excluded.last_activity_at", kinds: &[KeyKind::Rec] },
    Row { table: "kernel_lifecycle", insert: "INSERT INTO kernel_lifecycle(record_id, archived) VALUES('k1', 0)", pk: "record_id", key_column: "record_id", upsert: "archived = excluded.archived", kinds: &[KeyKind::Rec] },
    Row { table: "kernel_legacy_sql_events", insert: "INSERT INTO kernel_legacy_sql_events(seq, source_id, record_id, event_type, created_at, source_stream) VALUES(999999, 's', 'k1', 'e', 't', 'content_events')", pk: "seq", key_column: "record_id", upsert: "event_type = excluded.event_type", kinds: &[KeyKind::Rec] },
    Row { table: "kernel_record_bodies", insert: "INSERT INTO kernel_record_bodies(record_id, body, event_seq) VALUES('k1', 'b', 1)", pk: "record_id", key_column: "record_id", upsert: "body = excluded.body", kinds: &[KeyKind::Rec] },
];

async fn matrix_conn(db: &Db) -> sqlx::pool::PoolConnection<sqlx::Sqlite> {
    let mut conn = db.write_pool().acquire().await.unwrap();
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await
        .unwrap();
    conn
}

async fn exec(conn: &mut SqliteConnection, sql: &str) -> std::result::Result<(), String> {
    sqlx::query(sql)
        .execute(&mut *conn)
        .await
        .map(|_| ())
        .map_err(|e| format!("{sql}: {e}"))
}

async fn conn_dirty(conn: &mut SqliteConnection) -> BTreeSet<Key> {
    dirty_keys_on(conn).await.unwrap().into_iter().collect()
}

/// §9.6: every input's writes succeed under every conflict form, with keys
/// already dirty (the case rev 1 got wrong), and mark OLD and NEW keys.
#[tokio::test]
async fn runtime_matrix_every_conflict_form_succeeds_and_marks_old_and_new() {
    let fx = fixture(true).await;
    let mut conn = matrix_conn(&fx.db).await;
    for row in ROWS {
        let expect =
            |value: &str| -> Vec<Key> { row.kinds.iter().map(|k| key(*k, value)).collect() };
        // Plain INSERT marks NEW.
        exec(&mut conn, "BEGIN IMMEDIATE").await.unwrap();
        exec(&mut conn, row.insert).await.unwrap();
        assert_marked(&conn_dirty(&mut conn).await, &expect("k1"));
        // Every form below runs with the keys already dirty.
        let forms = [
            row.insert
                .replacen("INSERT INTO", "INSERT OR IGNORE INTO", 1),
            format!(
                "{} ON CONFLICT({}) DO UPDATE SET {}",
                row.insert, row.pk, row.upsert
            ),
            format!(
                "UPDATE OR ABORT {} SET {} = {} WHERE {} = 'k1'",
                row.table, row.key_column, row.key_column, row.key_column
            ),
            format!(
                "UPDATE OR FAIL {} SET {} = {} WHERE {} = 'k1'",
                row.table, row.key_column, row.key_column, row.key_column
            ),
            format!(
                "UPDATE OR ROLLBACK {} SET {} = {} WHERE {} = 'k1'",
                row.table, row.key_column, row.key_column, row.key_column
            ),
            format!(
                "UPDATE OR IGNORE {} SET {} = {} WHERE {} = 'k1'",
                row.table, row.key_column, row.key_column, row.key_column
            ),
        ];
        for form in &forms {
            exec(&mut conn, form)
                .await
                .unwrap_or_else(|e| panic!("{e}"));
        }
        exec(&mut conn, "COMMIT").await.unwrap();

        // UPDATE of the key column marks OLD and NEW.
        exec(&mut conn, "DELETE FROM main.p_dirty").await.unwrap();
        exec(
            &mut conn,
            &format!(
                "UPDATE {} SET {} = 'k2' WHERE {} = 'k1'",
                row.table, row.key_column, row.key_column
            ),
        )
        .await
        .unwrap();
        let marked = conn_dirty(&mut conn).await;
        assert_marked(&marked, &expect("k1"));
        assert_marked(&marked, &expect("k2"));
        // DELETE marks OLD.
        exec(&mut conn, "DELETE FROM main.p_dirty").await.unwrap();
        exec(
            &mut conn,
            &format!("DELETE FROM {} WHERE {} = 'k2'", row.table, row.key_column),
        )
        .await
        .unwrap();
        assert_marked(&conn_dirty(&mut conn).await, &expect("k2"));
        exec(&mut conn, "DELETE FROM main.p_dirty").await.unwrap();
    }
    // The app-install scope key and the dependent-key columns.
    exec(&mut conn, "INSERT INTO kernel_app_installs(principal, package, row_json, generation, status, executable, event_seq) VALUES('p', 'pkg', '{}', 'g', 'active', 1, 1)").await.unwrap();
    exec(&mut conn, "INSERT INTO kernel_app_installs(principal, package, row_json, generation, status, executable, event_seq) VALUES('p', 'pkg', '{}', 'g2', 'active', 1, 1) ON CONFLICT(principal, package) DO UPDATE SET generation = excluded.generation").await.unwrap();
    exec(
        &mut conn,
        "UPDATE OR ROLLBACK kernel_app_installs SET package = 'pkg2'",
    )
    .await
    .unwrap();
    assert_marked(
        &conn_dirty(&mut conn).await,
        &[
            key(KeyKind::Scope, "p\u{1f}pkg"),
            key(KeyKind::Scope, "p\u{1f}pkg2"),
        ],
    );
    exec(&mut conn, "DELETE FROM main.p_dirty").await.unwrap();
    exec(&mut conn, "INSERT INTO kernel_records(id, home_id, created_seq, created_at) VALUES('r', 'h1', 1, 't')").await.unwrap();
    exec(
        &mut conn,
        "UPDATE kernel_records SET home_id = 'h2' WHERE id = 'r'",
    )
    .await
    .unwrap();
    exec(&mut conn, "INSERT INTO kernel_roots(root_id, parent_id, created_seq, created_at) VALUES('c', 'p1', 1, 't')").await.unwrap();
    exec(
        &mut conn,
        "UPDATE kernel_roots SET parent_id = 'p2' WHERE root_id = 'c'",
    )
    .await
    .unwrap();
    exec(
        &mut conn,
        "UPDATE kernel_generic_links SET target_id = 't2'",
    )
    .await
    .unwrap();
    let marked = conn_dirty(&mut conn).await;
    assert_marked(
        &marked,
        &[
            key(KeyKind::Home, "h1"),
            key(KeyKind::Home, "h2"),
            key(KeyKind::Home, "p1"),
            key(KeyKind::Home, "p2"),
        ],
    );
    // A note-only link rewrite changes no derived value and marks nothing.
    exec(&mut conn, "INSERT INTO kernel_generic_links(link_id, source_id, target_id, relationship, created_at, active, event_seq, imported) VALUES('l9', 's9', 't9', 'part_of', 't', 1, 1, 0)").await.unwrap();
    exec(&mut conn, "DELETE FROM main.p_dirty").await.unwrap();
    exec(
        &mut conn,
        "UPDATE kernel_generic_links SET note = 'n', event_seq = 2 WHERE link_id = 'l9'",
    )
    .await
    .unwrap();
    assert!(conn_dirty(&mut conn).await.is_empty());
    // A NULL key is skipped, never a constraint failure.
    exec(
        &mut conn,
        "UPDATE kernel_roots SET parent_id = NULL WHERE root_id = 'c'",
    )
    .await
    .unwrap();
    assert!(conn_dirty(&mut conn)
        .await
        .contains(&key(KeyKind::Home, "p2")));
}

/// Data survival: an outer rollback leaves `p_*` exactly as it was, and the
/// same writes produce the same canonical tables with marking on or off.
#[tokio::test]
async fn rollback_reverts_marks_and_marking_never_changes_canonical_rows() {
    let fx = fixture(true).await;
    let record = create_record_as(&fx.db, &fx.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    clear(&fx.db).await;
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    sqlx::query("UPDATE kernel_records SET created_at = created_at WHERE id = ?")
        .bind(&record)
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(!dirty_keys_on(&mut tx).await.unwrap().is_empty());
    tx.rollback().await.unwrap();
    assert!(dirty(&fx.db).await.is_empty());

    async fn script(fx: &Fixture) -> Vec<(String, u64)> {
        let home = create_home(&fx.db, KERNEL_ROOT_ID, None, &fx.admin)
            .await
            .unwrap();
        let a = create_record_as(&fx.db, &fx.admin, &home).await.unwrap();
        let b = create_record_as(&fx.db, &fx.admin, &home).await.unwrap();
        super::super::generic_links::add_generic_link_as(
            &fx.db, &fx.admin, &b, &a, "part_of", None,
        )
        .await
        .unwrap();
        rehome_record_as(&fx.db, &fx.admin, &a, KERNEL_ROOT_ID)
            .await
            .unwrap();
        super::super::projection_dump::dump(&fx.db)
            .await
            .unwrap()
            .tables
            .into_iter()
            .map(|t| (t.name, t.rows))
            .collect()
    }
    let (marked, unmarked) = (fixture(true).await, fixture(false).await);
    assert_eq!(script(&marked).await, script(&unmarked).await);
    assert!(!dirty(&marked.db).await.is_empty());
}

/// Full replay (§2.3) suspends marking, then clears `p_dirty`, restarts at
/// the head and invalidates, all in its own transaction.
#[tokio::test]
async fn full_replay_resets_marking_and_invalidates() {
    let fx = fixture(true).await;
    create_record_as(&fx.db, &fx.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    sqlx::query("UPDATE main.p_state SET ready = 1, build_after = 'x'")
        .execute(fx.db.write_pool())
        .await
        .unwrap();
    let before = marking_row(&fx.db).await;
    assert!(!dirty(&fx.db).await.is_empty());
    replay_all_projections(&fx.db).await.unwrap();
    let after = marking_row(&fx.db).await;
    let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM main.content_events")
        .fetch_one(fx.db.pool())
        .await
        .unwrap();
    assert!(dirty(&fx.db).await.is_empty());
    assert!(after.enabled);
    assert_eq!(after.marking_since_seq, head);
    assert_ne!(after.invalidation_epoch, before.invalidation_epoch);
    let family: (i64, Option<String>) =
        sqlx::query_as("SELECT ready, build_after FROM main.p_state")
            .fetch_one(fx.db.pool())
            .await
            .unwrap();
    assert_eq!(family, (0, None));
    assert_eq!(state(&fx.db).await, ObjectState::Exact);
    let record = create_record_as(&fx.db, &fx.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    assert_marked(&dirty(&fx.db).await, &[key(KeyKind::Rec, &record)]);
}

#[tokio::test]
async fn disabling_marking_invalidates_and_reenabling_restarts_at_head() {
    let fx = fixture(true).await;
    let epoch = marking_row(&fx.db).await.invalidation_epoch;
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    set_enabled_on(&mut tx, false).await.unwrap();
    tx.commit().await.unwrap();
    assert_ne!(marking_row(&fx.db).await.invalidation_epoch, epoch);
    create_record_as(&fx.db, &fx.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    assert!(dirty(&fx.db).await.is_empty(), "disabled marking is inert");
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    set_enabled_on(&mut tx, true).await.unwrap();
    tx.commit().await.unwrap();
    let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM main.content_events")
        .fetch_one(fx.db.pool())
        .await
        .unwrap();
    let row = marking_row(&fx.db).await;
    assert!(row.enabled);
    assert_eq!(row.marking_since_seq, head);
}

#[tokio::test]
async fn invalidation_tolerates_absent_and_partial_objects() {
    let fx = fixture(false).await;
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    invalidate_all_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let fx = fixture(true).await;
    sqlx::query("DROP TABLE main.p_state")
        .execute(fx.db.write_pool())
        .await
        .unwrap();
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    invalidate_all_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
}

#[test]
fn certification_exempts_exactly_the_compiled_objects() {
    for object in expected_objects() {
        assert!(certification_object(object), "{object:?}");
        let mut drifted = object.clone();
        // A constraint autoindex has no SQL; giving it some is drift too.
        drifted.3 = Some(match &drifted.3 {
            Some(sql) => format!("{} ", sql.replace("DO NOTHING", "DO NOTHING ")),
            None => "CREATE INDEX x ON y(z)".into(),
        });
        assert!(!certification_object(&drifted), "{object:?}");
        let mut renamed = object.clone();
        renamed.1.push('x');
        assert!(!certification_object(&renamed));
    }
    let unknown: SchemaObject = (
        "table".into(),
        "p_unknown".into(),
        "p_unknown".into(),
        Some("CREATE TABLE p_unknown(x)".into()),
    );
    assert!(!certification_object(&unknown));
}

/// M4 on a real handle: a pooled writer with a TEMP shadow is discarded at
/// checkout, and the next write lands in main and is marked.
#[tokio::test]
async fn shadowed_writer_connection_is_replaced_before_the_write() {
    let fx = fixture(true).await;
    // Plant a shadow on every pooled writer, so the next checkout must meet
    // one whichever idle connection the pool hands out.
    let mut held = Vec::new();
    for _ in 0..5 {
        let mut conn = fx.db.write_pool().acquire().await.unwrap();
        // Planted with the lease guard off: checkout is the second line.
        crate::db::writer_contract::bypass_guard_for_test(&mut conn, true).await;
        sqlx::query("CREATE TEMP TABLE kernel_records(id TEXT, home_id TEXT)")
            .execute(&mut *conn)
            .await
            .unwrap();
        held.push(conn);
    }
    drop(held);
    let refused = crate::db::writer_contract::refused_checkouts();
    let record = create_record_as(&fx.db, &fx.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    assert!(crate::db::writer_contract::refused_checkouts() > refused);
    let main: i64 = sqlx::query_scalar("SELECT count(*) FROM main.kernel_records WHERE id = ?")
        .bind(&record)
        .fetch_one(fx.db.pool())
        .await
        .unwrap();
    assert_eq!(main, 1);
    assert_marked(&dirty(&fx.db).await, &[key(KeyKind::Rec, &record)]);
}

/// Rev 2.1 M4: a protected TEMP shadow created *mid-lease* on a real pooled
/// writer must not produce a false save. Each probe first runs with the lease
/// guard bypassed, which proves the regression: the write is captured or
/// skipped, the commit succeeds and main is unchanged. With the guard, the
/// shadow cannot be created at all.
#[tokio::test]
async fn mid_lease_shadows_cannot_produce_a_false_save() {
    let fx = fixture(true).await;
    let record = create_record_as(&fx.db, &fx.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let probes = [
        // No update-hook notification for WITHOUT ROWID tables.
        "CREATE TEMP TABLE kernel_lifecycle(record_id TEXT PRIMARY KEY, archived INTEGER) WITHOUT ROWID",
        // Skips the row silently; nothing is written anywhere.
        "CREATE TEMP TRIGGER skip_lifecycle BEFORE INSERT ON main.kernel_lifecycle BEGIN SELECT RAISE(IGNORE); END",
    ];
    let lifecycle = |db: Db, record: String| async move {
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM main.kernel_lifecycle WHERE record_id = ?",
        )
        .bind(record)
        .fetch_one(db.pool())
        .await
        .unwrap()
    };
    for probe in probes {
        sqlx::query("DELETE FROM main.kernel_lifecycle")
            .execute(fx.db.write_pool())
            .await
            .unwrap();
        // Without the guard: the false save the contract exists to prevent.
        let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
        crate::db::writer_contract::bypass_guard_for_test(&mut tx, true).await;
        sqlx::query(probe).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_lifecycle(record_id, archived) VALUES(?, 1)")
            .bind(&record)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit()
            .await
            .expect("without the guard the commit is acknowledged");
        assert_eq!(
            lifecycle(fx.db.clone(), record.clone()).await,
            0,
            "{probe}: without the guard an acknowledged write never reached main"
        );
        // With the guard: the shadow is refused at prepare time, and the
        // write that follows lands in main and is marked.
        let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
        let refused = sqlx::query(probe).execute(&mut *tx).await;
        assert!(refused.is_err(), "{probe}: the lease guard must refuse it");
        sqlx::query("DELETE FROM main.p_dirty")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO kernel_lifecycle(record_id, archived) VALUES(?, 1)")
            .bind(&record)
            .execute(&mut *tx)
            .await
            .unwrap();
        assert!(dirty_keys_on(&mut tx)
            .await
            .unwrap()
            .contains(&key(KeyKind::Rec, &record)));
        tx.commit().await.unwrap();
        assert_eq!(lifecycle(fx.db.clone(), record.clone()).await, 1, "{probe}");
    }
    // Renaming a TEMP table into a protected name is refused too.
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    sqlx::query("CREATE TEMP TABLE scratch_rename(x)")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert!(
        sqlx::query("ALTER TABLE temp.scratch_rename RENAME TO kernel_records")
            .execute(&mut *tx)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
}

/// The write budget (fb924ec Q6): the p99 write-lock hold (each critical
/// section from BEGIN IMMEDIATE to connection release) with marking may grow
/// by at most 10% or 2 ms absolute. Timing is host-dependent, so this is a
/// measurement, not a gate: it runs only when `NATIVE_MEASURE_WRITE_BUDGET=1`,
/// for example
/// `NATIVE_MEASURE_WRITE_BUDGET=1 cargo test --lib stored_visibility::tests::write_budget -- --nocapture`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_budget() {
    if std::env::var_os("NATIVE_MEASURE_WRITE_BUDGET").is_none() {
        return;
    }
    const ROUNDS: usize = 20;
    const PER_ROUND: usize = 50;
    let marked = fixture(true).await;
    let plain = fixture(false).await;
    // A realistic hot path: create, part_of link, body edit, archive, move.
    async fn one(fx: &Fixture, home: &str, samples: &mut Vec<std::time::Duration>) {
        let timed = |start: std::time::Instant, samples: &mut Vec<_>| samples.push(start.elapsed());
        let t = std::time::Instant::now();
        let a = create_record_as(&fx.db, &fx.admin, home).await.unwrap();
        timed(t, samples);
        let t = std::time::Instant::now();
        let b = create_record_as(&fx.db, &fx.admin, home).await.unwrap();
        timed(t, samples);
        let t = std::time::Instant::now();
        super::super::generic_links::add_generic_link_as(
            &fx.db, &fx.admin, &b, &a, "part_of", None,
        )
        .await
        .unwrap();
        timed(t, samples);
        let revision = read_record_as(&fx.db, &fx.admin, &a)
            .await
            .unwrap()
            .unwrap()
            .revision;
        let t = std::time::Instant::now();
        super::super::hq::set_body_as(&fx.db, &fx.admin, &a, "a body", revision)
            .await
            .unwrap();
        timed(t, samples);
        let t = std::time::Instant::now();
        rehome_record_as(&fx.db, &fx.admin, &a, KERNEL_ROOT_ID)
            .await
            .unwrap();
        timed(t, samples);
    }
    let homes = [
        create_home(&marked.db, KERNEL_ROOT_ID, None, &marked.admin)
            .await
            .unwrap(),
        create_home(&plain.db, KERNEL_ROOT_ID, None, &plain.admin)
            .await
            .unwrap(),
    ];
    for _ in 0..PER_ROUND {
        one(&marked, &homes[0], &mut Vec::new()).await;
        one(&plain, &homes[1], &mut Vec::new()).await;
    }
    // Every workspace critical section (BEGIN IMMEDIATE to connection
    // release), captured exactly; the arms run serially, so each drain
    // belongs to the arm that just ran.
    crate::write_contention::held_samples::start();
    let (mut calls, mut holds) = ([Vec::new(), Vec::new()], [Vec::new(), Vec::new()]);
    for iteration in 0..ROUNDS * PER_ROUND {
        // Interleave per iteration, alternating order, so host noise is
        // common to both arms.
        for arm in [iteration % 2, 1 - iteration % 2] {
            let _ = crate::write_contention::held_samples::take();
            if arm == 0 {
                one(&marked, &homes[0], &mut calls[0]).await;
            } else {
                one(&plain, &homes[1], &mut calls[1]).await;
            }
            holds[arm].extend(crate::write_contention::held_samples::take());
        }
    }
    let stats = |samples: &mut Vec<std::time::Duration>| {
        samples.sort();
        let at = |q: f64| samples[((samples.len() as f64 - 1.0) * q).round() as usize];
        let mean = samples.iter().sum::<std::time::Duration>() / samples.len() as u32;
        (samples.len(), mean, at(0.50), at(0.90), at(0.99))
    };
    let [hold_on, hold_off] = holds.each_mut().map(stats);
    let [call_on, call_off] = calls.each_mut().map(stats);
    let delta = |on: std::time::Duration, off: std::time::Duration| {
        (on.as_secs_f64() / off.as_secs_f64() - 1.0) * 100.0
    };
    println!(
        "write budget: write-lock hold (n off={}, on={}): mean {:?} -> {:?} ({:+.1}%), p50 {:?} -> {:?}, p90 {:?} -> {:?}, p99 {:?} -> {:?} ({:+.1}%, {:?})",
        hold_off.0, hold_on.0,
        hold_off.1, hold_on.1, delta(hold_on.1, hold_off.1),
        hold_off.2, hold_on.2, hold_off.3, hold_on.3,
        hold_off.4, hold_on.4, delta(hold_on.4, hold_off.4), hold_on.4.saturating_sub(hold_off.4),
    );
    println!(
        "write budget: whole API call (n={}): p50 {:?} -> {:?}, p99 {:?} -> {:?}; dirty keys after run={}",
        call_on.0, call_off.2, call_on.2, call_off.4, call_on.4,
        dirty(&marked.db).await.len()
    );
    let budget = hold_off
        .4
        .mul_f64(1.10)
        .max(hold_off.4 + std::time::Duration::from_millis(2));
    assert!(
        hold_on.4 <= budget,
        "p99 write-lock hold {:?} exceeds budget {budget:?}",
        hold_on.4
    );
}

async fn schema_rows(path: &std::path::Path) -> Vec<SchemaObject> {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .read_only(true);
    let mut conn = sqlx::ConnectOptions::connect(&options).await.unwrap();
    let mut rows: Vec<SchemaObject> = sqlx::query_as(
        "SELECT type, name, tbl_name, sql FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(&mut conn)
    .await
    .unwrap();
    rows.sort();
    sqlx::Connection::close(conn).await.unwrap();
    rows
}

/// Slice 2a egress strip (fb924ec Q4): an export of a marked workspace has
/// exactly the schema of the same workspace unmarked. Canonical rows, the
/// projection digest and the source are untouched; the source keeps marking.
#[tokio::test]
async fn exports_of_a_marked_workspace_carry_no_accelerators() {
    let fx = fixture(false).await;
    create_record_as(&fx.db, &fx.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let unmarked = crate::export::export_connected_db(&fx.db, None)
        .await
        .unwrap();
    let unmarked_schema = schema_rows(&unmarked.path()).await;
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    install_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    let digest = crate::kernel::projection_dump::dump(&fx.db)
        .await
        .unwrap()
        .sha256;
    let marked = crate::export::export_connected_db(&fx.db, None)
        .await
        .unwrap();
    assert_eq!(schema_rows(&marked.path()).await, unmarked_schema);
    let exported = open_v2_database(marked.path().to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        crate::kernel::projection_dump::dump(&exported)
            .await
            .unwrap()
            .sha256,
        digest,
        "canonical state survives the strip"
    );
    exported.close().await;
    assert_eq!(
        state(&fx.db).await,
        ObjectState::Exact,
        "the live source keeps marking"
    );
    marked.cleanup().await;
    unmarked.cleanup().await;
}

/// Drift anywhere in the accelerator inventory leaves the export exactly as
/// the source: nothing is stripped, so receivers keep refusing the drift.
/// This includes unknown triggers and indexes attached to an exact marking
/// table, under prefixed and unprefixed names, which `DROP TABLE` would
/// otherwise erase silently.
#[tokio::test]
async fn egress_strip_ships_any_drift_unchanged_for_refusal() {
    for drift in [
        "DROP TRIGGER main.p_mark_kernel_lifecycle_delete; CREATE TRIGGER p_mark_kernel_lifecycle_delete AFTER DELETE ON kernel_lifecycle BEGIN SELECT 1; END",
        "CREATE TABLE p_unknown(x)",
        "CREATE TRIGGER p_evil AFTER INSERT ON p_dirty BEGIN SELECT 1; END",
        "CREATE TRIGGER evil AFTER INSERT ON p_dirty BEGIN SELECT 1; END",
        "CREATE INDEX p_dirty_by_key ON p_dirty(key)",
        "CREATE INDEX dirty_by_key ON p_dirty(key)",
    ] {
        let fx = fixture(true).await;
        sqlx::query(drift).execute(fx.db.write_pool()).await.unwrap();
        let source: Vec<SchemaObject> = {
            let mut conn = fx.db.pool().acquire().await.unwrap();
            let mut rows: Vec<SchemaObject> = sqlx::query_as(
                "SELECT type, name, tbl_name, sql FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            )
            .fetch_all(&mut *conn)
            .await
            .unwrap();
            rows.sort();
            rows
        };
        assert_eq!(state(&fx.db).await, ObjectState::Drifted, "{drift}");
        let export = crate::export::export_connected_db(&fx.db, None).await.unwrap();
        assert_eq!(
            schema_rows(&export.path()).await,
            source,
            "{drift}: the drifted copy ships unchanged"
        );
        export.cleanup().await;
        assert_eq!(state(&fx.db).await, ObjectState::Drifted, "{drift}: source untouched");
    }
}

/// The whole-set guard is what keeps attached unknown DDL: without it, the
/// exact table drop erases an unprefixed index silently.
#[tokio::test]
async fn without_the_dependency_guard_a_table_drop_hides_attached_drift() {
    let fx = fixture(true).await;
    sqlx::query("CREATE INDEX dirty_by_key ON p_dirty(key)")
        .execute(fx.db.write_pool())
        .await
        .unwrap();
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    assert_eq!(strip_exact_on(&mut tx).await.unwrap(), 0);
    let dropped = strip_without_dependency_guard_for_test(&mut tx)
        .await
        .unwrap();
    assert!(dropped > 0);
    let index_left: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name = 'dirty_by_key')",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    assert!(
        !index_left,
        "the unguarded drop silently removed the unknown index"
    );
    tx.rollback().await.unwrap();
}

#[tokio::test]
async fn strip_exact_requires_a_transaction() {
    let fx = fixture(true).await;
    let mut conn = fx.db.write_pool().acquire().await.unwrap();
    assert!(strip_exact_on(&mut conn).await.is_err());
}
