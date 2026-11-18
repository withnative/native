//! Parity of the live home census after removing its duplicate reads
//! (`kernel_roots` once; bulk account subjects from the physical entries the
//! census already loaded): every principal's `VisibleHomeAnchors` (homes,
//! flags, order, failed homes) and hosted policy rows equal the previous
//! implementation, kept verbatim as a test-only reference, in the same
//! snapshot, across roster, template, frontier, subject, malformed-grant,
//! orphan-home, folder-scope and loader-error transitions.

use super::app_installs::scope::{with_scope_override, AppScope};
use super::*;

type Flat = (Vec<(String, bool, bool, bool)>, usize);

fn flat(census: VisibleHomeAnchors) -> Flat {
    (
        census
            .homes
            .into_iter()
            .map(|h| (h.home_id, h.policy_valid, h.policy_view, h.home_view))
            .collect(),
        census.failed_homes,
    )
}

struct Fx {
    db: Db,
    admin: String,
    p: std::collections::BTreeMap<&'static str, String>,
    _dir: tempfile::TempDir,
}

impl Fx {
    async fn new() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = create_v2_database(
            &format!("sqlite://{}", dir.path().join("census.db").display()),
            "account",
            "Admin",
            "acct:admin",
        )
        .await
        .unwrap();
        let mut p = std::collections::BTreeMap::new();
        for label in [
            "member",
            "grantee",
            "owner_nv",
            "owner_inv",
            "former",
            "outsider",
            "noperson",
        ] {
            p.insert(
                label,
                create_principal(&db, "account", label, &format!("acct:{label}"), &admin)
                    .await
                    .unwrap(),
            );
        }
        p.insert("admin", admin.clone());
        Fx {
            db,
            admin,
            p,
            _dir: dir,
        }
    }

    async fn sql(&self, sql: &str, binds: &[&str]) {
        let mut conn = self.db.write_pool().acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        let mut query = sqlx::query(sql);
        for bind in binds {
            query = query.bind(*bind);
        }
        let result = query.execute(&mut *conn).await;
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut *conn)
            .await
            .unwrap();
        result.unwrap();
    }

    async fn event(&self, record: &str, event_type: &str, payload: serde_json::Value) {
        self.sql(
            "INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?,?,?,?,NULL,1,'complete')",
            &[&uuid::Uuid::new_v4().to_string(), record, event_type, &payload.to_string()],
        )
        .await;
    }

    async fn roster(&self, labels: &[&str]) {
        let members: std::collections::BTreeMap<String, String> = labels
            .iter()
            .map(|l| (format!("acct:{l}"), self.p[l].clone()))
            .collect();
        self.event(
            KERNEL_ROOT_ID,
            hosted_identity::ROSTER_EVENT,
            serde_json::json!({"members": members, "catalog_accounts": {}}),
        )
        .await;
    }

    async fn frontier(&self, home: &str) -> i64 {
        sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1','kernel.home_policy_replaced.v1')")
            .bind(home)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }

    async fn template(&self, home: &str, explicit: &[(&str, &str)], members: Option<&str>) {
        let seq = self.frontier(home).await;
        let explicit: std::collections::BTreeMap<String, String> = explicit
            .iter()
            .map(|(id, cap)| ((*id).to_owned(), (*cap).to_owned()))
            .collect();
        self.event(
            home,
            hosted_identity::POLICY_EVENT,
            serde_json::json!({"policy_seq": seq, "explicit": explicit, "members": members}),
        )
        .await;
    }

    async fn home(&self, parent: &str, entries: &[(&str, &str)]) -> String {
        create_home(&self.db, parent, Some(entries), &self.admin)
            .await
            .unwrap()
    }
}

/// Every principal (and an unknown one): the new census and hosted rows
/// against the previous ones, in one reader snapshot.
async fn assert_parity(fx: &Fx, what: &str, scope: Option<&[String]>) {
    let mut read = fx.db.pool().begin().await.unwrap();
    let mut principals: Vec<String> =
        sqlx::query_scalar("SELECT principal_id FROM kernel_principals ORDER BY principal_id")
            .fetch_all(&mut *read)
            .await
            .unwrap();
    principals.push("no-such-principal".into());
    for principal in &principals {
        let (new, old) = match scope {
            Some(folders) => {
                let new = with_scope_override(
                    principal,
                    AppScope::Folders(folders.to_vec()),
                    visible_home_anchors_as(&mut read, principal),
                )
                .await;
                let old = with_scope_override(
                    principal,
                    AppScope::Folders(folders.to_vec()),
                    visible_home_anchors_previous_for_test(&mut read, principal),
                )
                .await;
                (new, old)
            }
            None => (
                visible_home_anchors_as(&mut read, principal).await,
                visible_home_anchors_previous_for_test(&mut read, principal).await,
            ),
        };
        // Hosted rows: the ordinary bulk loader, and the census's variant
        // given subjects derived here from a raw read of the entries.
        let previous =
            hosted_identity::policy_rows_loaded_previous_for_test(&mut read, principal, None).await;
        let ordinary = hosted_identity::policy_rows_bulk_on(&mut read, principal).await;
        let mut subjects = hosted_identity::AccountSubjects::new();
        for (home, subject) in sqlx::query_as::<_, (String, String)>(
            "SELECT root_id,subject_id FROM kernel_policy_entries WHERE subject_kind='account'",
        )
        .fetch_all(&mut *read)
        .await
        .unwrap()
        {
            subjects.entry(home).or_default().insert(subject);
        }
        let census =
            hosted_identity::policy_rows_bulk_with_subjects_on(&mut read, principal, &subjects)
                .await;
        for (name, rows) in [("ordinary", ordinary), ("census", census)] {
            match (&rows, &previous) {
                (Ok(rows), Ok(previous)) => {
                    assert_eq!(rows, previous, "{what}: {name} hosted rows for {principal}")
                }
                (Err(a), Err(b)) => {
                    assert_eq!(a.to_string(), b.to_string(), "{what}: {name} {principal}")
                }
                _ => panic!("{what}: {name} hosted rows for {principal}: {rows:?} vs {previous:?}"),
            }
        }
        match (new, old) {
            (Ok(new), Ok(old)) => {
                assert_eq!(flat(new), flat(old), "{what}: census for {principal}")
            }
            (Err(new), Err(old)) => {
                assert_eq!(new.to_string(), old.to_string(), "{what}: {principal}")
            }
            (new, old) => panic!(
                "{what}: {principal}: new {:?} old {:?}",
                new.map(flat),
                old.map(flat)
            ),
        }
    }
}

#[tokio::test]
async fn the_deduplicated_census_matches_the_previous_census_through_transitions() {
    let fx = Fx::new().await;
    assert_parity(&fx, "fresh workspace, no roster", None).await;
    let admin = fx.admin.clone();
    let team = fx
        .home(
            KERNEL_ROOT_ID,
            &[(&admin, "manage"), (&fx.p["grantee"], "view")],
        )
        .await;
    let nested = fx.home(&team, &[]).await;
    let _child = create_home(&fx.db, &nested, None, &admin).await.unwrap();
    let templ = fx
        .home(
            KERNEL_ROOT_ID,
            &[(&admin, "manage"), (&fx.p["grantee"], "view")],
        )
        .await;
    let lagged = fx.home(KERNEL_ROOT_ID, &[(&admin, "manage")]).await;
    let private = fx.home(KERNEL_ROOT_ID, &[(&admin, "manage")]).await;
    for _ in 0..20 {
        fx.home(KERNEL_ROOT_ID, &[(&admin, "manage")]).await;
    }
    assert_parity(&fx, "homes and policies, no roster", None).await;

    let rostered = [
        "admin",
        "member",
        "grantee",
        "owner_nv",
        "owner_inv",
        "noperson",
    ];
    fx.roster(&rostered).await;
    assert_parity(&fx, "roster", None).await;
    fx.template(
        &templ,
        &[(&fx.p["grantee"], "edit"), (&fx.p["outsider"], "view")],
        Some("view"),
    )
    .await;
    fx.template(&lagged, &[], Some("view")).await;
    fx.event(
        &lagged,
        "kernel.import_home_delta.v1",
        serde_json::json!({}),
    )
    .await;
    assert_parity(&fx, "current and lagging templates", None).await;

    // Subject cleanup: the physical subject behind an explicit template
    // grant goes away.
    fx.sql(
        "DELETE FROM kernel_policy_entries WHERE root_id=? AND subject_id=?",
        &[&templ, &fx.p["grantee"]],
    )
    .await;
    assert_parity(&fx, "subject cleanup", None).await;
    // A non-account subject never counts as a physical account subject.
    fx.sql(
        "INSERT INTO kernel_policy_entries(root_id,subject_kind,subject_id,effect,capability) VALUES(?,'group',?,'allow','view')",
        &[&templ, &fx.p["outsider"]],
    )
    .await;
    assert_parity(&fx, "non-account subject", None).await;

    // A malformed grant naming one owner: a failed home for them only.
    fx.sql(
        "INSERT INTO kernel_policy_entries(root_id,subject_kind,subject_id,effect,capability) VALUES(?,'account',?,'allow','bogus')",
        &[&team, &fx.p["owner_inv"]],
    )
    .await;
    assert_parity(&fx, "malformed grant", None).await;

    // Roster change and readmission.
    fx.roster(&[
        "admin",
        "grantee",
        "owner_nv",
        "owner_inv",
        "noperson",
        "former",
    ])
    .await;
    assert_parity(&fx, "offboard and readmit", None).await;

    // Record homes without a root row, and a broken parent chain.
    let record = create_record_as(&fx.db, &admin, &private).await.unwrap();
    fx.sql(
        "UPDATE kernel_records SET home_id='orphan-home' WHERE id=?",
        &[&record],
    )
    .await;
    fx.sql(
        "UPDATE kernel_roots SET parent_id='missing-parent' WHERE root_id=?",
        &[&nested],
    )
    .await;
    assert_parity(&fx, "orphan home and broken chain", None).await;

    // A folder-scoped app through the real scope check.
    assert_parity(&fx, "folder scope", Some(std::slice::from_ref(&team))).await;
    assert_parity(&fx, "empty folder scope", Some(&[])).await;

    // A malformed hosted template: both fail the same way.
    fx.event(
        &templ,
        hosted_identity::POLICY_EVENT,
        serde_json::json!({"not": "a template"}),
    )
    .await;
    assert_parity(&fx, "loader error", None).await;
}
