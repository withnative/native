//! The hook-inventory coverage test (73ad275 §9.4), made mechanical in the
//! way `authorization_trigger_coverage` is: run the real visibility gate with
//! a SQLite authorizer recording every `(table, column)` it reads, then
//! require that each pair is covered by a marking trigger (insert, delete,
//! and an update trigger whose `UPDATE OF` list includes the column) or by a
//! commented exemption. Unused exemptions fail too, so the list cannot rot.
//!
//! What this proves: every main-schema input the gate reads today is marked.
//! What it does not prove: conflict modes, suppression, TEMP shadows and
//! OLD-versus-NEW keys. Those are the runtime matrix in `tests.rs`.

use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{c_char, c_int, c_void, CStr};
use std::sync::Mutex;

static READS: Mutex<BTreeSet<(String, String)>> = Mutex::new(BTreeSet::new());

unsafe extern "C" fn record_reads(
    _: *mut c_void,
    action: c_int,
    table: *const c_char,
    column: *const c_char,
    database: *const c_char,
    _: *const c_char,
) -> c_int {
    if action == libsqlite3_sys::SQLITE_READ
        && !table.is_null()
        && !column.is_null()
        && !database.is_null()
    {
        // SAFETY: SQLite passes NUL-terminated strings live for the call.
        let (table, column, database) = unsafe {
            (
                CStr::from_ptr(table).to_string_lossy().into_owned(),
                CStr::from_ptr(column).to_string_lossy().into_owned(),
                CStr::from_ptr(database).to_string_lossy(),
            )
        };
        if database == "main" {
            READS.lock().unwrap().insert((table, column));
        }
    }
    libsqlite3_sys::SQLITE_OK
}

/// A table the gate reads that marking deliberately does not watch.
struct Exemption {
    table: &'static str,
    /// `None` exempts every column.
    column: Option<&'static str>,
    reason: &'static str,
}

/// Empty today: every main-schema table the gate reads is marked.
const EXEMPTIONS: &[Exemption] = &[];

/// `table -> (insert, delete, update columns or None for every column)`.
fn coverage() -> BTreeMap<&'static str, (bool, bool, Option<BTreeSet<&'static str>>)> {
    let mut map = BTreeMap::new();
    for spec in KERNEL_INPUTS {
        map.insert(
            spec.table,
            (
                true,
                true,
                spec.update_of.map(|c| c.iter().copied().collect()),
            ),
        );
    }
    map.insert("content_events", (true, true, None));
    map
}

/// A hosted workspace: an activated roster (so admission and the hosted
/// template and frontier reads run), nested homes with an explicit policy, a
/// derived comment chain. The record predicate always runs with the message
/// guard on.
async fn fixture() -> (Db, String, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("inventory.db");
    let (db, admin) = create_v2_database(
        &format!("sqlite://{}", path.display()),
        "account",
        "Admin",
        "portable-owner",
    )
    .await
    .unwrap();
    let member = create_principal(&db, "account", "Member", "portable-member", &admin)
        .await
        .unwrap();
    let host = resolve_principal_by_binding(&db, HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    super::super::hosted_identity::import_accounts(
        &db,
        &host,
        vec![
            ("owner@example.test".into(), "portable-owner".into()),
            ("member@example.test".into(), "portable-member".into()),
        ],
    )
    .await
    .unwrap();
    super::super::hosted_identity::reconcile_hosted_caller(&db, |_| async move {
        let users = std::collections::BTreeMap::from([
            ("catalog-owner".to_owned(), "owner@example.test".to_owned()),
            (
                "catalog-member".to_owned(),
                "member@example.test".to_owned(),
            ),
        ]);
        // SAFETY: complete synthetic catalogue snapshot; no tool input.
        Ok(unsafe {
            super::super::hosted_identity::VerifiedHostedMembership::from_catalog_unchecked(
                "catalog-owner".into(),
                users,
                std::collections::BTreeMap::new(),
            )
        })
    })
    .await
    .unwrap();
    let home = create_home(&db, KERNEL_ROOT_ID, Some(&[(&member, "view")]), &admin)
        .await
        .unwrap();
    let child = create_home(&db, &home, None, &admin).await.unwrap();
    let record = create_record_as(&db, &admin, &child).await.unwrap();
    let comment = create_record_as(&db, &admin, &child).await.unwrap();
    super::super::generic_links::add_generic_link_as(
        &db, &admin, &comment, &record, "part_of", None,
    )
    .await
    .unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    install_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    (db, admin, member, dir)
}

/// The gate's reads, on one connection with the authorizer installed: the
/// bulk home evaluation (roster, admission, topology, policies, hosted
/// templates and frontiers), the workspace message probe, and the record
/// predicate with the message guard, for an admin and a member.
async fn gate_reads(db: &Db, principals: &[&str]) -> BTreeSet<(String, String)> {
    READS.lock().unwrap().clear();
    let mut conn = db.pool().acquire().await.unwrap();
    sqlx::Connection::clear_cached_statements(&mut *conn)
        .await
        .unwrap();
    {
        let mut handle = conn.lock_handle().await.unwrap();
        // SAFETY: exclusive locked handle; callback state is static.
        unsafe {
            libsqlite3_sys::sqlite3_set_authorizer(
                handle.as_raw_handle().as_ptr(),
                Some(record_reads),
                std::ptr::null_mut(),
            );
        }
    }
    let mut tx = sqlx::Connection::begin(&mut *conn).await.unwrap();
    for principal in principals {
        let anchors = visible_home_anchors_as(&mut tx, principal).await.unwrap();
        assert!(!anchors.homes.is_empty());
        let homes = anchors
            .homes
            .iter()
            .map(|h| {
                format!(
                    "SELECT '{}' AS id, {} AS view",
                    h.home_id.replace('\'', "''"),
                    i64::from(h.policy_view)
                )
            })
            .collect::<Vec<_>>()
            .join(" UNION ALL ");
        let probe: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_messages) OR EXISTS(SELECT 1 FROM main.kernel_records WHERE primary_type='Message') OR EXISTS(SELECT 1 FROM main.kernel_record_fields WHERE name='v1_type' AND value_json='\"Message\"')")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let _ = probe;
        let visible: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT r.id FROM main.kernel_records r WHERE {}",
            sql_record_visible("r", "?1", &homes, true)
        ))
        .bind(*principal)
        .fetch_all(&mut *tx)
        .await
        .unwrap();
        assert!(!visible.is_empty());
    }
    tx.rollback().await.unwrap();
    {
        let mut handle = conn.lock_handle().await.unwrap();
        // SAFETY: as above; removing the authorizer.
        unsafe {
            libsqlite3_sys::sqlite3_set_authorizer(
                handle.as_raw_handle().as_ptr(),
                None,
                std::ptr::null_mut(),
            );
        }
    }
    sqlx::Connection::clear_cached_statements(&mut *conn)
        .await
        .unwrap();
    std::mem::take(&mut *READS.lock().unwrap())
}

#[tokio::test]
async fn every_input_the_visibility_gate_reads_is_marked() {
    let (db, admin, member, _dir) = fixture().await;
    let reads = gate_reads(&db, &[&admin, &member]).await;
    // The authorizer really observed the gate, not a cached answer.
    for expected in [
        ("kernel_roots", "parent_id"),
        ("kernel_policy_entries", "subject_id"),
        ("kernel_records", "home_id"),
        ("kernel_generic_links", "relationship"),
        ("content_events", "payload"),
    ] {
        assert!(
            reads.contains(&(expected.0.to_owned(), expected.1.to_owned())),
            "gate read {expected:?} not observed: {reads:?}"
        );
    }
    let coverage = coverage();
    let mut used = BTreeSet::new();
    let mut gaps = Vec::new();
    for (table, column) in &reads {
        let exempt = EXEMPTIONS
            .iter()
            .position(|e| e.table == table && e.column.is_none_or(|c| c == column));
        if let Some(index) = exempt {
            used.insert(index);
            continue;
        }
        match coverage.get(table.as_str()) {
            None => gaps.push(format!("{table}.{column}: table has no marking triggers")),
            Some((insert, delete, update)) => {
                if !insert || !delete {
                    gaps.push(format!("{table}: insert/delete unmarked"));
                }
                if update
                    .as_ref()
                    .is_some_and(|cols| !cols.contains(column.as_str()))
                {
                    gaps.push(format!("{table}.{column}: update not in UPDATE OF list"));
                }
            }
        }
    }
    for (index, exemption) in EXEMPTIONS.iter().enumerate() {
        assert!(!exemption.reason.is_empty());
        if !used.contains(&index) {
            gaps.push(format!("stale exemption for {}", exemption.table));
        }
    }
    assert!(
        gaps.is_empty(),
        "visibility gate inputs without marking (73ad275 §9.4):\n{}",
        gaps.join("\n")
    );
}
