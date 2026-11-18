//! Slice 2b.2a: the Principal family (spike B X6) through the generic
//! family dispatch, on file-backed databases through the real pools.
//!
//! The property ([`violations`]): in one reader snapshot, every trusted
//! `p_principal` row equals the live admission fence and the live transform
//! predicate, and a caller without a `kernel_principals` row is never
//! trusted.

use super::drain::{catch_up, BatchOutcome, Budget, Defect, Hooks};
use super::fence::{
    home_anchor_lookup_on, principal_lookup_on, HomeAnchorLookup, PrincipalLookup, Untrusted,
};
use super::*;
use crate::kernel::hosted_identity::{self, HOST_ADMISSION_BINDINGS, ROSTER_EVENT};
use crate::kernel::relates_to_port::HOST_TRANSFORM_BINDING;
use std::collections::BTreeMap;

struct Fx {
    db: Db,
    p: BTreeMap<&'static str, String>,
    _dir: tempfile::TempDir,
}

/// The ten non-app callers of spike B's matrix. The three folder-scoped app
/// callers belong to the app-scope family (X1, slice 2b.4).
const ROSTERED: [&str; 6] = [
    "admin",
    "member",
    "grantee",
    "owner_nv",
    "owner_inv",
    "noperson",
];

impl Fx {
    async fn new() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = create_v2_database(
            &format!("sqlite://{}", dir.path().join("principal.db").display()),
            "account",
            "Admin",
            "admin",
        )
        .await
        .unwrap();
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        install_on(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
        let mut p = BTreeMap::new();
        for label in [
            "member",
            "grantee",
            "owner_nv",
            "owner_inv",
            "former",
            "outsider",
            "noperson",
        ] {
            let id = create_principal(&db, "account", label, &format!("account:{label}"), &admin)
                .await
                .unwrap();
            p.insert(label, id);
        }
        for (label, binding) in [
            ("host_import", "host:v1-import"),
            ("transform", HOST_TRANSFORM_BINDING),
        ] {
            let id: String = sqlx::query_scalar(
                "SELECT principal_id FROM main.kernel_principals WHERE auth_binding = ?",
            )
            .bind(binding)
            .fetch_one(db.pool())
            .await
            .unwrap();
            p.insert(label, id);
        }
        p.insert("admin", admin);
        Fx { db, p, _dir: dir }
    }

    async fn write(&self, sql: &str, binds: &[&str]) {
        let mut tx = begin_write(self.db.write_pool()).await.unwrap();
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&mut *tx)
            .await
            .ok();
        let mut query = sqlx::query(sql);
        for bind in binds {
            query = query.bind(*bind);
        }
        query.execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
    }

    /// A hosted roster as `kernel.hosted_membership.v1`, read directly from
    /// the log by admission. `extra` adds a roster-only member id with no
    /// `kernel_principals` row.
    async fn roster(&self, labels: &[&str], extra: &[&str]) {
        let mut members: BTreeMap<String, String> = labels
            .iter()
            .map(|label| (format!("account:{label}"), self.p[label].clone()))
            .collect();
        for id in extra {
            members.insert(format!("account:{id}"), (*id).to_owned());
        }
        let payload = serde_json::json!({"members": members, "catalog_accounts": {}}).to_string();
        self.write(
            "INSERT INTO main.content_events (id, record_id, type, payload, actor, causal_envelope_version, causal_status) VALUES (?, ?, ?, ?, NULL, 1, 'complete')",
            &[&uuid::Uuid::new_v4().to_string(), KERNEL_ROOT_ID, ROSTER_EVENT, &payload],
        )
        .await;
    }

    async fn quiet(&self) -> BatchOutcome {
        catch_up(&self.db, &Budget::default(), &Hooks::default())
            .await
            .unwrap()
    }
}

/// The admission rule as it was before the `admitted_with` extraction,
/// written from the raw log and the literal host bindings.
async fn previous_admitted(conn: &mut SqliteConnection, principal: &str) -> bool {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM main.content_events WHERE record_id = ? AND type = ? ORDER BY seq DESC LIMIT 1",
    )
    .bind(KERNEL_ROOT_ID)
    .bind(ROSTER_EVENT)
    .fetch_optional(&mut *conn)
    .await
    .unwrap();
    let Some(raw) = raw else {
        return true;
    };
    let host: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_principals WHERE principal_id=? AND auth_binding IN ('host:v1-import','host:relates-to:transform'))")
        .bind(principal)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
    let roster: serde_json::Value = serde_json::from_str(&raw).unwrap();
    host || roster["members"]
        .as_object()
        .unwrap()
        .values()
        .any(|id| id.as_str() == Some(principal))
}

/// The transform predicate exactly as `messaging::sql_guard` refuses on.
async fn live_transform(conn: &mut SqliteConnection, principal: &str) -> bool {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_principals service WHERE service.principal_id=? AND service.auth_binding='host:relates-to:transform')")
        .bind(principal)
        .fetch_one(&mut *conn)
        .await
        .unwrap()
}

/// Trusted-but-wrong principal rows, and trusted rows for callers without a
/// principal, in one reader snapshot. Also checks the extracted admission
/// rule against the previous one for every principal.
async fn violations(db: &Db) -> Vec<String> {
    let mut read = db.pool().begin().await.unwrap();
    let principals: Vec<String> =
        sqlx::query_scalar("SELECT principal_id FROM main.kernel_principals ORDER BY principal_id")
            .fetch_all(&mut *read)
            .await
            .unwrap();
    let mut found = Vec::new();
    for principal in &principals {
        let admitted = hosted_identity::admitted(&mut read, principal)
            .await
            .unwrap();
        assert_eq!(
            admitted,
            previous_admitted(&mut read, principal).await,
            "the extracted admission rule changed for {principal}"
        );
        let transform = live_transform(&mut read, principal).await;
        if let PrincipalLookup::Trusted {
            admitted: a,
            transform: t,
        } = principal_lookup_on(&mut read, principal).await.unwrap()
        {
            if (a, t) != (admitted, transform) {
                found.push(format!(
                    "{principal}: stored ({a}, {t}), live ({admitted}, {transform})"
                ));
            }
        }
    }
    for absent in ["roster-only", "anonymous"] {
        if let PrincipalLookup::Trusted { .. } =
            principal_lookup_on(&mut read, absent).await.unwrap()
        {
            found.push(format!("{absent}: trusted without a principal row"));
        }
    }
    found
}

async fn lookup(db: &Db, principal: &str) -> PrincipalLookup {
    let mut read = db.pool().begin().await.unwrap();
    principal_lookup_on(&mut read, principal).await.unwrap()
}

async fn principal_state(db: &Db) -> (bool, Option<String>) {
    sqlx::query_as(
        "SELECT ready, build_after FROM main.p_state WHERE generation = 1 AND family = 'principal'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap()
}

#[test]
fn the_shared_bindings_match_both_live_literals() {
    for binding in HOST_ADMISSION_BINDINGS {
        assert!(
            hosted_identity::ADMITTED_HOST_SQL.contains(&format!("'{binding}'")),
            "{binding}"
        );
    }
    assert_eq!(HOST_ADMISSION_BINDINGS[1], HOST_TRANSFORM_BINDING);
    let guard = crate::kernel::messaging::sql_guard("r", "?1", "h", false);
    assert!(
        guard.contains(&format!("service.auth_binding='{HOST_TRANSFORM_BINDING}'")),
        "the transform predicate the guard refuses on moved"
    );
}

/// Without a hosted roster, every principal is admitted.
#[tokio::test]
async fn without_a_roster_every_principal_is_admitted() {
    let fx = Fx::new().await;
    assert_eq!(fx.quiet().await, BatchOutcome::Idle);
    assert!(violations(&fx.db).await.is_empty());
    assert_eq!(
        lookup(&fx.db, &fx.p["outsider"]).await,
        PrincipalLookup::Trusted {
            admitted: true,
            transform: false
        }
    );
}

#[tokio::test]
async fn the_principal_matrix_matches_live_admission_and_transform() {
    let fx = Fx::new().await;
    fx.roster(&ROSTERED, &["roster-only"]).await;
    assert_eq!(fx.quiet().await, BatchOutcome::Idle);
    assert!(violations(&fx.db).await.is_empty());
    let expect = |admitted, transform| PrincipalLookup::Trusted {
        admitted,
        transform,
    };
    for label in ROSTERED {
        assert_eq!(
            lookup(&fx.db, &fx.p[label]).await,
            expect(true, false),
            "{label}"
        );
    }
    for label in ["former", "outsider"] {
        assert_eq!(
            lookup(&fx.db, &fx.p[label]).await,
            expect(false, false),
            "{label}"
        );
    }
    assert_eq!(
        lookup(&fx.db, &fx.p["host_import"]).await,
        expect(true, false)
    );
    assert_eq!(lookup(&fx.db, &fx.p["transform"]).await, expect(true, true));
    assert_eq!(
        lookup(&fx.db, "roster-only").await,
        PrincipalLookup::Untrusted(Untrusted::Missing),
        "a roster member without a principal row falls back"
    );
}

/// Offboarding and readmission escalate Principal only; the property holds
/// after every partial batch, and HomeAnchor stays trusted throughout.
#[tokio::test]
async fn roster_changes_escalate_only_principal_and_partial_batches_hold() {
    let fx = Fx::new().await;
    let mut rostered: Vec<&str> = ROSTERED.to_vec();
    fx.roster(&rostered, &[]).await;
    fx.quiet().await;
    rostered.retain(|l| *l != "member");
    rostered.push("former");
    fx.roster(&rostered, &[]).await;
    let mut batches = 0;
    loop {
        batches += 1;
        assert!(batches < 200);
        let outcome = catch_up(
            &fx.db,
            &Budget {
                keys: 64,
                rows: 2,
                batches: 1,
            },
            &Hooks::default(),
        )
        .await
        .unwrap();
        assert!(violations(&fx.db).await.is_empty(), "batch {batches}");
        let mut read = fx.db.pool().begin().await.unwrap();
        assert!(
            matches!(
                home_anchor_lookup_on(&mut read, KERNEL_ROOT_ID)
                    .await
                    .unwrap(),
                HomeAnchorLookup::Trusted { .. }
            ),
            "a roster change must not untrust HomeAnchor"
        );
        drop(read);
        if outcome == BatchOutcome::Idle {
            break;
        }
    }
    assert!(batches > 2, "the rebuild ran in several partial batches");
    assert_eq!(
        lookup(&fx.db, &fx.p["member"]).await,
        PrincipalLookup::Trusted {
            admitted: false,
            transform: false
        }
    );
    assert_eq!(
        lookup(&fx.db, &fx.p["former"]).await,
        PrincipalLookup::Trusted {
            admitted: true,
            transform: false
        }
    );
}

/// A principal's own key refreshes its own row in the same batch, with no
/// escalation: the family stays ready with its cursor at rest.
#[tokio::test]
async fn a_new_principal_is_targeted_without_escalation() {
    let fx = Fx::new().await;
    fx.roster(&ROSTERED, &[]).await;
    fx.quiet().await;
    let created = create_principal(&fx.db, "agent", "Agent", "agent:new", &fx.p["admin"])
        .await
        .unwrap();
    let outcome = catch_up(
        &fx.db,
        &Budget {
            batches: 1,
            ..Budget::default()
        },
        &Hooks::default(),
    )
    .await
    .unwrap();
    assert!(
        matches!(
            outcome,
            BatchOutcome::Progress {
                escalated: false,
                rows_targeted: 1,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(principal_state(&fx.db).await, (true, None));
    assert_eq!(
        lookup(&fx.db, &created).await,
        PrincipalLookup::Trusted {
            admitted: false,
            transform: false
        }
    );
    assert!(violations(&fx.db).await.is_empty());
}

/// A deleted principal's row goes with its key; skipping the targeted
/// refresh is exactly the bug the property catches.
#[tokio::test]
async fn a_deleted_principal_loses_its_row_and_a_skipped_target_is_caught() {
    for defect in [None, Some(Defect::SkipTarget)] {
        let fx = Fx::new().await;
        fx.roster(&ROSTERED, &[]).await;
        fx.quiet().await;
        fx.write(
            "DELETE FROM main.kernel_principals WHERE principal_id = ?",
            &[&fx.p["outsider"]],
        )
        .await;
        let hooks = Hooks { gate: None, defect };
        assert_eq!(
            catch_up(&fx.db, &Budget::default(), &hooks).await.unwrap(),
            BatchOutcome::Idle
        );
        let stored = lookup(&fx.db, &fx.p["outsider"]).await;
        if defect.is_none() {
            assert_eq!(stored, PrincipalLookup::Untrusted(Untrusted::Missing));
        } else {
            assert!(
                matches!(stored, PrincipalLookup::Trusted { .. }),
                "the control must leave a trusted row for a principal that no longer exists"
            );
        }
    }
}

/// Skipping the roster escalation leaves an offboarded member admitted:
/// caught.
#[tokio::test]
async fn a_skipped_roster_escalation_is_caught() {
    for defect in [None, Some(Defect::SkipEscalation)] {
        let fx = Fx::new().await;
        fx.roster(&ROSTERED, &[]).await;
        fx.quiet().await;
        let without: Vec<&str> = ROSTERED
            .iter()
            .copied()
            .filter(|l| *l != "member")
            .collect();
        fx.roster(&without, &[]).await;
        let hooks = Hooks { gate: None, defect };
        assert_eq!(
            catch_up(&fx.db, &Budget::default(), &hooks).await.unwrap(),
            BatchOutcome::Idle
        );
        assert_eq!(
            violations(&fx.db).await.is_empty(),
            defect.is_none(),
            "{defect:?}"
        );
    }
}

/// A roster change behind the Principal rebuild cursor restarts the
/// rebuild; continuing from the cursor instead would trust a stale row.
#[tokio::test]
async fn a_roster_change_behind_the_cursor_restarts_and_continuing_is_caught() {
    for defect in [None, Some(Defect::ContinueCursor)] {
        let fx = Fx::new().await;
        fx.roster(&ROSTERED, &[]).await;
        fx.quiet().await;
        let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
        invalidate_all_on(&mut tx).await.unwrap();
        tx.commit().await.unwrap();
        let hooks = Hooks { gate: None, defect };
        let step = Budget {
            keys: 64,
            rows: 3,
            batches: 1,
        };
        catch_up(&fx.db, &step, &hooks).await.unwrap();
        catch_up(&fx.db, &step, &hooks).await.unwrap();
        let (ready, after) = principal_state(&fx.db).await;
        let after = after.expect("mid-rebuild");
        assert!(!ready);
        let behind = ROSTERED
            .iter()
            .filter(|l| fx.p[*l].as_str() <= after.as_str())
            .min_by_key(|l| fx.p[*l].clone())
            .expect("a rostered principal behind the cursor");
        let without: Vec<&str> = ROSTERED.iter().copied().filter(|l| l != behind).collect();
        fx.roster(&without, &[]).await;
        let mut all = step;
        all.batches = 1_000;
        assert_eq!(
            catch_up(&fx.db, &all, &hooks).await.unwrap(),
            BatchOutcome::Idle
        );
        assert_eq!(
            violations(&fx.db).await.is_empty(),
            defect.is_none(),
            "{defect:?}"
        );
    }
}

/// One batch's work stays within its stated aggregate bound: at most
/// `keys` keys, `keys × G` targeted rows and `rows` per rebuilding family.
#[tokio::test]
async fn one_batch_stays_within_its_aggregate_bound() {
    let fx = Fx::new().await;
    fx.quiet().await;
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    invalidate_all_on(&mut tx).await.unwrap();
    for i in 0..50 {
        sqlx::query("INSERT INTO main.kernel_principals (principal_id, kind, display_label, auth_binding) VALUES (?, 'agent', 'Bulk', ?)")
            .bind(format!("bulk-{i:02}"))
            .bind(format!("agent:bulk-{i:02}"))
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    tx.commit().await.unwrap();
    let budget = Budget {
        keys: 10,
        rows: 3,
        batches: 1,
    };
    let outcome = catch_up(&fx.db, &budget, &Hooks::default()).await.unwrap();
    let BatchOutcome::Progress {
        keys_cleared,
        rows_targeted,
        rows_derived,
        rows_deleted,
        ..
    } = outcome
    else {
        panic!("{outcome:?}");
    };
    assert_eq!(keys_cleared, 10);
    assert!(rows_targeted <= 10, "{rows_targeted}");
    assert!(
        rows_derived + rows_deleted <= Family::ALL.len() * 3,
        "{rows_derived} + {rows_deleted}"
    );
    assert_eq!(fx.quiet().await, BatchOutcome::Idle);
    assert!(violations(&fx.db).await.is_empty());
}

/// The Principal rebuild continuations are index seeks on the bundled
/// SQLite: their VM steps do not grow with the principals already
/// processed. The disjunctive cursor form is the control.
#[test]
fn principal_continuations_seek_past_any_prefix() {
    const KEYS: usize = 20_000;
    fn steps(c: &rusqlite::Connection, sql: &str, params: &[&dyn rusqlite::ToSql]) -> i32 {
        let mut statement = c.prepare(sql).unwrap();
        {
            let mut rows = statement.query(params).unwrap();
            while rows.next().unwrap().is_some() {}
        }
        statement.get_status(rusqlite::StatementStatus::VmStep)
    }
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch(crate::kernel::KERNEL_PRINCIPALS_DDL)
        .unwrap();
    c.execute_batch(TABLE_DDL[5].1).unwrap();
    c.execute_batch("BEGIN").unwrap();
    for i in 0..KEYS {
        let id = format!("p{i:06}");
        c.execute(
            "INSERT INTO kernel_principals VALUES (?1, 'agent', 'P', 'agent:' || ?1)",
            [&id],
        )
        .unwrap();
        c.execute("INSERT INTO p_principal VALUES (1, ?1, 1, 0)", [&id])
            .unwrap();
    }
    c.execute_batch("COMMIT").unwrap();
    let cursor = format!("p{:06}", KEYS - 10);
    for (sql, params) in [
        (
            derive::PRINCIPALS_AFTER_SQL,
            vec![&cursor as &dyn rusqlite::ToSql, &2],
        ),
        (derive::PRINCIPAL_STORED_AFTER_SQL, vec![&1, &cursor, &2]),
        (derive::PRINCIPALS_FIRST_SQL, vec![&2]),
        (derive::PRINCIPAL_STORED_FIRST_SQL, vec![&1, &2]),
    ] {
        let n = steps(&c, sql, &params);
        assert!(n < 200, "{sql}: {n} steps");
    }
    let control = steps(
        &c,
        "SELECT principal_id FROM kernel_principals WHERE ?1 IS NULL OR principal_id > ?1 ORDER BY principal_id LIMIT ?2",
        &[&cursor, &2],
    );
    assert!(control > KEYS as i32, "the control must scan: {control}");
}
