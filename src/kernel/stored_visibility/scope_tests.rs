//! Slice 2b.2b: the ScopeAccess family (spike B X1), on file-backed
//! databases through the real pools, policy writers and hosted events.
//!
//! The property ([`violations`]): in one reader snapshot, every trusted
//! `p_scope_access` pair equals the live evaluator for that principal at
//! that anchor, computed independently of the drain with the **previous**
//! hosted loader and `evaluate_homes`; and no pair of a principal or anchor
//! that does not exist is trusted. It also checks the shared loader's
//! results against the previous loader for every principal.

use super::derive::{self, Access};
use super::drain::{catch_up, BatchOutcome, Budget, Defect, Gate, Hooks};
use super::fence::{
    home_anchor_lookup_on, principal_lookup_on, scope_access_lookup_on, HomeAnchorLookup,
    PrincipalLookup, ScopeAccessLookup, Untrusted,
};
use super::*;
use crate::kernel::hosted_identity::{self, POLICY_EVENT, ROSTER_EVENT};
use crate::kernel::relates_to_port::HOST_TRANSFORM_BINDING;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

const ROSTERED: [&str; 6] = [
    "admin",
    "member",
    "grantee",
    "owner_nv",
    "owner_inv",
    "noperson",
];

struct Fx {
    db: Db,
    p: BTreeMap<&'static str, String>,
    _dir: tempfile::TempDir,
}

/// The ten non-app callers and a workspace of anchors that exercise each
/// policy source: physical entries (with a malformed grant naming one
/// owner), a member template at its frontier, a template lagging its
/// frontier, and an explicit template grant to a non-subject.
struct World {
    team: String,
    templ: String,
    lagged: String,
    private: String,
}

impl Fx {
    async fn new() -> Fx {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = create_v2_database(
            &format!("sqlite://{}", dir.path().join("scope.db").display()),
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
        let mut query = sqlx::query(sql);
        for bind in binds {
            query = query.bind(*bind);
        }
        query.execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
    }

    async fn event(&self, record: &str, event_type: &str, payload: serde_json::Value) {
        self.write(
            "INSERT INTO main.content_events (id, record_id, type, payload, actor, causal_envelope_version, causal_status) VALUES (?, ?, ?, ?, NULL, 1, 'complete')",
            &[&uuid::Uuid::new_v4().to_string(), record, event_type, &payload.to_string()],
        )
        .await;
    }

    async fn roster(&self, labels: &[&str]) {
        let members: BTreeMap<String, String> = labels
            .iter()
            .map(|label| (format!("account:{label}"), self.p[label].clone()))
            .collect();
        self.event(
            KERNEL_ROOT_ID,
            ROSTER_EVENT,
            serde_json::json!({"members": members, "catalog_accounts": {}}),
        )
        .await;
    }

    async fn frontier(&self, home: &str) -> i64 {
        sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events WHERE record_id=? AND type IN ('kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1','kernel.home_policy_replaced.v1')")
            .bind(home)
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }

    /// A hosted member template; `policy_seq` defaults to the frontier.
    async fn template(
        &self,
        home: &str,
        explicit: &[(&str, &str)],
        members: Option<&str>,
        seq: Option<i64>,
    ) {
        let seq = match seq {
            Some(seq) => seq,
            None => self.frontier(home).await,
        };
        let explicit: BTreeMap<String, String> = explicit
            .iter()
            .map(|(id, cap)| ((*id).to_owned(), (*cap).to_owned()))
            .collect();
        self.event(
            home,
            POLICY_EVENT,
            serde_json::json!({"policy_seq": seq, "explicit": explicit, "members": members}),
        )
        .await;
    }

    async fn move_frontier(&self, home: &str) {
        self.event(home, "kernel.import_home_delta.v1", serde_json::json!({}))
            .await;
    }

    async fn home(&self, entries: &[(&str, &str)]) -> String {
        create_home(&self.db, KERNEL_ROOT_ID, Some(entries), &self.p["admin"])
            .await
            .unwrap()
    }

    async fn world(&self) -> World {
        self.roster(&ROSTERED).await;
        let admin = self.p["admin"].clone();
        let team = self
            .home(&[(&admin, "manage"), (&self.p["grantee"], "view")])
            .await;
        // A malformed grant naming one owner: invalid for them only.
        self.write(
            "INSERT INTO main.kernel_policy_entries (root_id, subject_kind, subject_id, effect, capability) VALUES (?, 'account', ?, 'allow', 'bogus')",
            &[&team, &self.p["owner_inv"]],
        )
        .await;
        let templ = self
            .home(&[(&admin, "manage"), (&self.p["grantee"], "view")])
            .await;
        // Members view, plus explicit grants to a physical subject and to a
        // non-subject (dropped by the subject filter).
        self.template(
            &templ,
            &[(&self.p["grantee"], "edit"), (&self.p["outsider"], "view")],
            Some("view"),
            None,
        )
        .await;
        let lagged = self.home(&[(&admin, "manage")]).await;
        self.template(&lagged, &[], Some("view"), None).await;
        self.move_frontier(&lagged).await;
        let private = self.home(&[(&admin, "manage")]).await;
        World {
            team,
            templ,
            lagged,
            private,
        }
    }

    async fn quiet(&self) -> BatchOutcome {
        catch_up(&self.db, &Budget::default(), &Hooks::default())
            .await
            .unwrap()
    }
}

fn access_of(valid: bool, view: bool) -> Access {
    match (valid, view) {
        (false, _) => Access::Invalid,
        (true, true) => Access::View,
        (true, false) => Access::ValidNoView,
    }
}

/// Wrong trusted pairs, and trusted pairs of nonexistent principals or
/// anchors, in one reader snapshot. Also: the shared loader equals the
/// previous one for every principal, whole-workspace and anchor-driven.
async fn violations(db: &Db) -> Vec<String> {
    let mut read = db.pool().begin().await.unwrap();
    let parents: BTreeMap<String, Option<String>> =
        sqlx::query_as("SELECT root_id, parent_id FROM main.kernel_roots")
            .fetch_all(&mut *read)
            .await
            .unwrap()
            .into_iter()
            .collect();
    let anchors: BTreeSet<String> = sqlx::query_scalar("SELECT root_id FROM main.kernel_policies")
        .fetch_all(&mut *read)
        .await
        .unwrap()
        .into_iter()
        .collect();
    let mut entries: BTreeMap<String, Vec<(String, String, String, String)>> = BTreeMap::new();
    for (home, kind, id, effect, cap) in sqlx::query_as::<_, (String, String, String, String, String)>(
        "SELECT root_id, subject_kind, subject_id, effect, capability FROM main.kernel_policy_entries",
    )
    .fetch_all(&mut *read)
    .await
    .unwrap()
    {
        entries.entry(home).or_default().push((kind, id, effect, cap));
    }
    let principals: Vec<String> =
        sqlx::query_scalar("SELECT principal_id FROM main.kernel_principals ORDER BY principal_id")
            .fetch_all(&mut *read)
            .await
            .unwrap();
    let mut found = Vec::new();
    for principal in &principals {
        let previous =
            hosted_identity::policy_rows_loaded_previous_for_test(&mut read, principal, None)
                .await
                .unwrap();
        assert_eq!(
            hosted_identity::policy_rows_bulk_on(&mut read, principal)
                .await
                .unwrap(),
            previous,
            "the shared loader changed the bulk result for {principal}"
        );
        assert_eq!(
            hosted_identity::policy_rows_for_anchors_on(&mut read, principal, &anchors)
                .await
                .unwrap(),
            hosted_identity::policy_rows_loaded_previous_for_test(
                &mut read,
                principal,
                Some(&anchors)
            )
            .await
            .unwrap(),
            "the shared loader changed the anchor-driven result for {principal}"
        );
        let mut policies = entries.clone();
        policies.extend(previous);
        for anchor in &anchors {
            let live = crate::kernel::evaluate_homes(
                principal,
                vec![(anchor.clone(), None)],
                &parents,
                &anchors,
                &policies,
                None,
            )
            .unwrap();
            let live = access_of(live.homes[0].policy_valid, live.homes[0].policy_view);
            if let ScopeAccessLookup::Trusted(stored) =
                scope_access_lookup_on(&mut read, principal, anchor)
                    .await
                    .unwrap()
            {
                if stored != live {
                    found.push(format!(
                        "({principal}, {anchor}): stored {stored:?}, live {live:?}"
                    ));
                }
            }
        }
        if let ScopeAccessLookup::Trusted(_) =
            scope_access_lookup_on(&mut read, principal, "no-such-anchor")
                .await
                .unwrap()
        {
            found.push(format!("({principal}, no-such-anchor): trusted"));
        }
    }
    for anchor in &anchors {
        if let ScopeAccessLookup::Trusted(_) =
            scope_access_lookup_on(&mut read, "no-such-principal", anchor)
                .await
                .unwrap()
        {
            found.push(format!("(no-such-principal, {anchor}): trusted"));
        }
    }
    found
}

async fn lookup(db: &Db, principal: &str, anchor: &str) -> ScopeAccessLookup {
    let mut read = db.pool().begin().await.unwrap();
    scope_access_lookup_on(&mut read, principal, anchor)
        .await
        .unwrap()
}

async fn scope_state(db: &Db) -> (bool, Option<String>) {
    sqlx::query_as(
        "SELECT ready, build_after FROM main.p_state WHERE generation = 1 AND family = 'scope_access'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap()
}

async fn stored_pairs(db: &Db) -> Vec<(String, String, i64)> {
    sqlx::query_as("SELECT principal, anchor, access FROM main.p_scope_access ORDER BY 1, 2")
        .fetch_all(db.pool())
        .await
        .unwrap()
}

/// Drive with partial batches, checking the property after every one.
async fn drain_checked(db: &Db, budget: Budget) -> usize {
    let mut batches = 0;
    loop {
        batches += 1;
        assert!(batches < 2_000, "the drain must finish once writes stop");
        let outcome = catch_up(
            db,
            &Budget {
                batches: 1,
                ..budget
            },
            &Hooks::default(),
        )
        .await
        .unwrap();
        let found = violations(db).await;
        assert!(found.is_empty(), "batch {batches}: {found:?}");
        match outcome {
            BatchOutcome::Idle => return batches,
            BatchOutcome::Refused(r) => panic!("{r:?}"),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_principal_matrix_matches_the_live_evaluator_at_every_anchor() {
    let fx = Fx::new().await;
    let w = fx.world().await;
    assert_eq!(fx.quiet().await, BatchOutcome::Idle);
    assert!(violations(&fx.db).await.is_empty());
    let at = |label: &'static str, anchor: String| {
        let db = fx.db.clone();
        let principal = fx.p[label].clone();
        async move { lookup(&db, &principal, &anchor).await }
    };
    use ScopeAccessLookup::Trusted;
    assert_eq!(at("grantee", w.team.clone()).await, Trusted(Access::View));
    assert_eq!(
        at("owner_inv", w.team.clone()).await,
        Trusted(Access::Invalid),
        "a malformed grant naming the owner is invalid for them"
    );
    assert_eq!(
        at("grantee", w.private.clone()).await,
        Trusted(Access::ValidNoView)
    );
    assert_eq!(
        at("member", w.templ.clone()).await,
        Trusted(Access::View),
        "members template"
    );
    assert_eq!(
        at("outsider", w.templ.clone()).await,
        Trusted(Access::ValidNoView),
        "an explicit template grant to a non-subject is dropped"
    );
    assert_eq!(
        at("member", w.lagged.clone()).await,
        Trusted(Access::ValidNoView),
        "a template behind its frontier is no override"
    );
}

/// Roster, template, frontier, subject and entry changes, private anchors
/// and deletions, each drained in partial batches with the property after
/// every batch.
#[tokio::test]
async fn transitions_keep_every_trusted_pair_live_through_partial_batches() {
    let fx = Fx::new().await;
    let w = fx.world().await;
    fx.quiet().await;
    let small = Budget {
        keys: 4,
        rows: 3,
        batches: 1,
    };

    // Offboard and readmit (roster: escalates ScopeAccess and Principal).
    let without: Vec<&str> = ROSTERED
        .iter()
        .copied()
        .filter(|l| *l != "member")
        .collect();
    fx.roster(&without).await;
    drain_checked(&fx.db, small).await;
    let mut readmitted = ROSTERED.to_vec();
    readmitted.push("former");
    fx.roster(&readmitted).await;
    drain_checked(&fx.db, small).await;

    // Template change and frontier lag then advance (anchor keys).
    fx.template(&w.templ, &[], Some("edit"), None).await;
    drain_checked(&fx.db, small).await;
    fx.move_frontier(&w.templ).await;
    drain_checked(&fx.db, small).await;
    fx.template(&w.lagged, &[(&fx.p["grantee"], "view")], None, None)
        .await;
    drain_checked(&fx.db, small).await;

    // Subject cleanup: the physical subject behind an explicit template
    // grant goes away.
    fx.template(&w.templ, &[(&fx.p["grantee"], "edit")], None, None)
        .await;
    drain_checked(&fx.db, small).await;
    fx.write(
        "DELETE FROM main.kernel_policy_entries WHERE root_id = ? AND subject_id = ?",
        &[&w.templ, &fx.p["grantee"]],
    )
    .await;
    drain_checked(&fx.db, small).await;

    // An entry change through the real policy writer.
    replace_home_policy(
        &fx.db,
        &fx.p["admin"],
        &w.team,
        &[(&fx.p["admin"], "manage"), (&fx.p["owner_nv"], "view")],
    )
    .await
    .unwrap();
    drain_checked(&fx.db, small).await;

    // Principal and anchor deletion.
    fx.write(
        "DELETE FROM main.kernel_policy_entries WHERE root_id = ?",
        &[&w.private],
    )
    .await;
    fx.write(
        "DELETE FROM main.kernel_policies WHERE root_id = ?",
        &[&w.private],
    )
    .await;
    drain_checked(&fx.db, small).await;
    assert_eq!(
        lookup(&fx.db, &fx.p["admin"], &w.private).await,
        ScopeAccessLookup::Untrusted(Untrusted::Missing)
    );
    assert!(!stored_pairs(&fx.db)
        .await
        .iter()
        .any(|(_, a, _)| a == &w.private));
}

/// A new private anchor's pairs stay Missing (oracle) while the family is
/// ready: targets refresh only stored pairs and never fill.
#[tokio::test]
async fn a_new_anchor_is_missing_never_valid_no_view() {
    let fx = Fx::new().await;
    fx.world().await;
    fx.quiet().await;
    let new = fx.home(&[(&fx.p["admin"], "manage")]).await;
    let outcome = catch_up(&fx.db, &Budget::default(), &Hooks::default())
        .await
        .unwrap();
    assert_eq!(outcome, BatchOutcome::Idle);
    assert_eq!(
        scope_state(&fx.db).await,
        (true, None),
        "no escalation for a new anchor"
    );
    for label in ["admin", "grantee", "outsider"] {
        assert_eq!(
            lookup(&fx.db, &fx.p[label], &new).await,
            ScopeAccessLookup::Untrusted(Untrusted::Missing),
            "{label}"
        );
    }
    assert!(violations(&fx.db).await.is_empty());
}

/// An entry change whose stored pairs fit the allowance is refreshed in
/// place; one that does not fit escalates before its key is cleared.
#[tokio::test]
async fn targets_refresh_within_the_allowance_and_escalate_beyond_it() {
    let fx = Fx::new().await;
    let w = fx.world().await;
    fx.quiet().await;
    replace_home_policy(
        &fx.db,
        &fx.p["admin"],
        &w.team,
        &[(&fx.p["admin"], "manage")],
    )
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
        matches!(outcome, BatchOutcome::Progress { rows_targeted, .. } if rows_targeted > 0),
        "{outcome:?}"
    );
    assert_eq!(
        scope_state(&fx.db).await,
        (true, None),
        "refreshed in place, not escalated"
    );
    assert!(violations(&fx.db).await.is_empty());

    replace_home_policy(
        &fx.db,
        &fx.p["admin"],
        &w.team,
        &[(&fx.p["admin"], "manage"), (&fx.p["grantee"], "view")],
    )
    .await
    .unwrap();
    let principals: i64 = sqlx::query_scalar("SELECT count(*) FROM main.kernel_principals")
        .fetch_one(fx.db.pool())
        .await
        .unwrap();
    let tight = Budget {
        keys: 64,
        rows: principals - 1,
        batches: 1,
    };
    let outcome = catch_up(&fx.db, &tight, &Hooks::default()).await.unwrap();
    assert!(
        matches!(outcome, BatchOutcome::Progress { .. }),
        "{outcome:?}"
    );
    let dirty: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.p_dirty WHERE kind = 'anchor' AND key = ?)",
    )
    .bind(&w.team)
    .fetch_one(fx.db.pool())
    .await
    .unwrap();
    assert!(
        !dirty,
        "the key is cleared only together with the escalation"
    );
    assert!(!scope_state(&fx.db).await.0);
    assert!(violations(&fx.db).await.is_empty());
    drain_checked(&fx.db, Budget::default()).await;
}

/// Mixed families: an anchor change leaves Principal and HomeAnchor
/// trusted; a roster change untrusts Principal and ScopeAccess only.
#[tokio::test]
async fn families_become_unready_independently() {
    let fx = Fx::new().await;
    let w = fx.world().await;
    fx.quiet().await;
    let trusted = |db: Db, admin: String| async move {
        let mut read = db.pool().begin().await.unwrap();
        (
            matches!(
                home_anchor_lookup_on(&mut read, KERNEL_ROOT_ID)
                    .await
                    .unwrap(),
                HomeAnchorLookup::Trusted { .. }
            ),
            matches!(
                principal_lookup_on(&mut read, &admin).await.unwrap(),
                PrincipalLookup::Trusted { .. }
            ),
        )
    };
    let without: Vec<&str> = ROSTERED
        .iter()
        .copied()
        .filter(|l| *l != "member")
        .collect();
    fx.roster(&without).await;
    catch_up(
        &fx.db,
        &Budget {
            keys: 64,
            rows: 1,
            batches: 1,
        },
        &Hooks::default(),
    )
    .await
    .unwrap();
    assert!(
        trusted(fx.db.clone(), fx.p["admin"].clone()).await.0,
        "a roster change must not untrust HomeAnchor"
    );
    assert!(!scope_state(&fx.db).await.0);
    drain_checked(&fx.db, Budget::default()).await;
    fx.template(&w.templ, &[], Some("edit"), None).await;
    catch_up(&fx.db, &Budget::default(), &Hooks::default())
        .await
        .unwrap();
    assert_eq!(
        trusted(fx.db.clone(), fx.p["admin"].clone()).await,
        (true, true)
    );
    assert_eq!(scope_state(&fx.db).await, (true, None));
}

/// Principal and anchor ids with JSON- and separator-significant
/// characters: the tuple cursor round-trips and the rebuild completes.
/// A cursor this family could not have written resets the family.
#[tokio::test]
async fn the_tuple_cursor_is_unambiguous_and_a_malformed_one_resets() {
    let fx = Fx::new().await;
    fx.world().await;
    for (i, id) in ["a\",\"b", "a", "a\u{1f}b", "a]", "[\"x\"]", "a\\", "a,b"]
        .iter()
        .enumerate()
    {
        fx.write(
            "INSERT INTO main.kernel_principals (principal_id, kind, display_label, auth_binding) VALUES (?, 'agent', 'Odd', ?)",
            &[id, &format!("agent:odd-{i}")],
        )
        .await;
        let key = derive::Key::Pair((*id).to_owned(), "anchor\"]".to_owned());
        assert_eq!(
            derive::Key::decode(Family::ScopeAccess, &key.encode()),
            Some(key)
        );
    }
    // A full rebuild walks every odd id through the tuple cursor.
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    invalidate_all_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    drain_checked(
        &fx.db,
        Budget {
            keys: 64,
            rows: 2,
            batches: 1,
        },
    )
    .await;
    let odd: i64 =
        sqlx::query_scalar("SELECT count(*) FROM main.p_scope_access WHERE principal LIKE 'a%'")
            .fetch_one(fx.db.pool())
            .await
            .unwrap();
    assert!(odd > 0, "the odd principals' pairs were built");
    fx.write(
        "UPDATE main.p_state SET ready = 0, build_after = 'not a pair' WHERE family = 'scope_access'",
        &[],
    )
    .await;
    catch_up(
        &fx.db,
        &Budget {
            batches: 1,
            ..Budget::default()
        },
        &Hooks::default(),
    )
    .await
    .unwrap();
    let (ready, after) = scope_state(&fx.db).await;
    assert!(
        after.as_deref() != Some("not a pair"),
        "reset, not trusted or retried as is: {ready} {after:?}"
    );
    assert_eq!(fx.quiet().await, BatchOutcome::Idle);
    assert!(violations(&fx.db).await.is_empty());
}

/// Stored pairs with no base at all, and a deleted tail, are purged by
/// bounded steps; ready only when both streams are exhausted.
#[tokio::test]
async fn an_empty_pair_base_purges_in_bounded_steps() {
    use sqlx::Connection;
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    for ddl in [
        crate::kernel::KERNEL_PRINCIPALS_DDL,
        "CREATE TABLE kernel_policies (root_id TEXT PRIMARY KEY)",
        "CREATE TABLE kernel_policy_entries (root_id TEXT, subject_kind TEXT, subject_id TEXT, effect TEXT, capability TEXT)",
        "CREATE TABLE kernel_roots (root_id TEXT PRIMARY KEY, parent_id TEXT)",
        "CREATE TABLE content_events (seq INTEGER PRIMARY KEY, id TEXT, record_id TEXT, type TEXT, payload TEXT)",
        TABLE_DDL[6].1,
    ] {
        sqlx::query(ddl).execute(&mut conn).await.unwrap();
    }
    sqlx::query("INSERT INTO kernel_principals VALUES ('p1', 'agent', 'P', 'agent:p1')")
        .execute(&mut conn)
        .await
        .unwrap();
    for (principal, anchor) in [
        ("p0", "a"),
        ("p1", "a"),
        ("p1", "b"),
        ("p2", "a"),
        ("p3", "z"),
    ] {
        for generation in [1, 2] {
            sqlx::query("INSERT INTO main.p_scope_access VALUES (?, ?, ?, 1)")
                .bind(generation)
                .bind(principal)
                .bind(anchor)
                .execute(&mut conn)
                .await
                .unwrap();
        }
    }
    let mut cursor = None;
    let mut steps = 0;
    loop {
        let mut cache = derive::BatchCache::default();
        let step = derive::rebuild_step_on(
            &mut conn,
            Family::ScopeAccess,
            1,
            cursor.as_deref(),
            2,
            &mut cache,
        )
        .await
        .unwrap();
        assert!(step.derived.is_empty() && step.deleted.len() <= 2 && !step.restart);
        derive::apply_step_on(&mut conn, Family::ScopeAccess, 1, &step)
            .await
            .unwrap();
        steps += 1;
        cursor = step.cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(steps, 3);
    let left: Vec<(i64, i64)> =
        sqlx::query_as("SELECT generation, count(*) FROM main.p_scope_access GROUP BY generation")
            .fetch_all(&mut conn)
            .await
            .unwrap();
    assert_eq!(left, vec![(2, 5)]);
}

// ---------------------------------------------------------------------------
// Sensitivity controls and errors
// ---------------------------------------------------------------------------

/// Skipping a targeted refresh (an entry change) is caught.
#[tokio::test]
async fn a_skipped_pair_target_is_caught() {
    for defect in [None, Some(Defect::SkipTarget)] {
        let fx = Fx::new().await;
        let w = fx.world().await;
        fx.quiet().await;
        replace_home_policy(
            &fx.db,
            &fx.p["admin"],
            &w.team,
            &[(&fx.p["admin"], "manage")],
        )
        .await
        .unwrap();
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

/// The live evaluator for one pair, independently of the drain: the
/// previous hosted loader and `evaluate_homes`, in one reader snapshot.
async fn live_access(db: &Db, principal: &str, anchor: &str) -> Access {
    let mut read = db.pool().begin().await.unwrap();
    let parents: BTreeMap<String, Option<String>> =
        sqlx::query_as("SELECT root_id, parent_id FROM main.kernel_roots")
            .fetch_all(&mut *read)
            .await
            .unwrap()
            .into_iter()
            .collect();
    let anchors: BTreeSet<String> = sqlx::query_scalar("SELECT root_id FROM main.kernel_policies")
        .fetch_all(&mut *read)
        .await
        .unwrap()
        .into_iter()
        .collect();
    let mut policies: BTreeMap<String, Vec<(String, String, String, String)>> = BTreeMap::new();
    for (home, kind, id, effect, cap) in sqlx::query_as::<_, (String, String, String, String, String)>(
        "SELECT root_id, subject_kind, subject_id, effect, capability FROM main.kernel_policy_entries",
    )
    .fetch_all(&mut *read)
    .await
    .unwrap()
    {
        policies.entry(home).or_default().push((kind, id, effect, cap));
    }
    policies.extend(
        hosted_identity::policy_rows_loaded_previous_for_test(&mut read, principal, None)
            .await
            .unwrap(),
    );
    let live = crate::kernel::evaluate_homes(
        principal,
        vec![(anchor.to_owned(), None)],
        &parents,
        &anchors,
        &policies,
        None,
    )
    .unwrap();
    access_of(live.homes[0].policy_valid, live.homes[0].policy_view)
}

/// Skipping the roster escalation is caught. Continuing a rebuild from its
/// cursor after a roster change behind it, instead of restarting, is caught
/// too, from the same partial checkpoint the correct arm resumes from.
///
/// The victim is fixed: `member` holds access at `templ` only through the
/// members template, so offboarding it provably moves that pair from view to
/// valid-without-view (asserted on the live evaluator). A victim with an
/// explicit template grant (`grantee`) would leave every pair unchanged and
/// make the injected defect unobservable.
#[tokio::test]
async fn skipped_escalation_and_a_continued_pair_cursor_are_caught() {
    for defect in [
        None,
        Some(Defect::SkipEscalation),
        Some(Defect::ContinueCursor),
    ] {
        let fx = Fx::new().await;
        let w = fx.world().await;
        fx.quiet().await;
        let (member, templ) = (fx.p["member"].clone(), w.templ.clone());
        assert_eq!(
            live_access(&fx.db, &member, &templ).await,
            Access::View,
            "the members template grants the victim view"
        );
        if defect != Some(Defect::SkipEscalation) {
            // The shared partial checkpoint: a fresh rebuild, one row per
            // batch, stopped once the pair cursor reaches (member, templ).
            // With one row per step the target pair always leaves a cursor
            // behind it, even when it is the last pair.
            let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
            invalidate_all_on(&mut tx).await.unwrap();
            tx.commit().await.unwrap();
            let target = derive::Key::Pair(member.clone(), templ.clone());
            let mut reached = false;
            for _ in 0..10_000 {
                catch_up(
                    &fx.db,
                    &Budget {
                        keys: 64,
                        rows: 1,
                        batches: 1,
                    },
                    &Hooks::default(),
                )
                .await
                .unwrap();
                if let (false, Some(after)) = scope_state(&fx.db).await {
                    if derive::Key::decode(Family::ScopeAccess, &after).unwrap() >= target {
                        reached = true;
                        break;
                    }
                }
            }
            assert!(reached, "the rebuild reached the target pair");
            assert!(!scope_state(&fx.db).await.0, "ScopeAccess is mid-rebuild");
            let stored: Option<i64> = sqlx::query_scalar(
                "SELECT access FROM main.p_scope_access WHERE generation = 1 AND principal = ? AND anchor = ?",
            )
            .bind(&member)
            .bind(&templ)
            .fetch_optional(fx.db.pool())
            .await
            .unwrap();
            assert_eq!(
                stored,
                Some(Access::View.code()),
                "the target pair is materialized behind the cursor"
            );
        }
        let without: Vec<&str> = ROSTERED
            .iter()
            .copied()
            .filter(|l| *l != "member")
            .collect();
        fx.roster(&without).await;
        assert_eq!(
            live_access(&fx.db, &member, &templ).await,
            Access::ValidNoView,
            "offboarding moves the live pair"
        );
        let hooks = Hooks { gate: None, defect };
        assert_eq!(
            catch_up(
                &fx.db,
                &Budget {
                    batches: 10_000,
                    ..Budget::default()
                },
                &hooks
            )
            .await
            .unwrap(),
            BatchOutcome::Idle
        );
        let caught = !violations(&fx.db).await.is_empty();
        assert_eq!(caught, defect.is_some(), "{defect:?}");
        if defect.is_none() {
            assert_eq!(
                lookup(&fx.db, &member, &templ).await,
                ScopeAccessLookup::Trusted(Access::ValidNoView)
            );
        }
    }
}

/// A loader error (a malformed hosted template) and an injected failure
/// roll the batch back: no pair is written, nothing becomes Invalid, and
/// the keys stay dirty.
#[tokio::test]
async fn loader_and_injected_errors_roll_back_without_inventing_invalid() {
    let fx = Fx::new().await;
    let w = fx.world().await;
    fx.quiet().await;
    let pairs = stored_pairs(&fx.db).await;
    fx.event(
        &w.templ,
        POLICY_EVENT,
        serde_json::json!({"not": "a template"}),
    )
    .await;
    assert!(catch_up(&fx.db, &Budget::default(), &Hooks::default())
        .await
        .is_err());
    assert_eq!(stored_pairs(&fx.db).await, pairs);
    let dirty: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.p_dirty WHERE kind = 'anchor' AND key = ?)",
    )
    .bind(&w.templ)
    .fetch_one(fx.db.pool())
    .await
    .unwrap();
    assert!(dirty, "the key survives the failed batch");

    let fx = Fx::new().await;
    fx.world().await;
    let hooks = Hooks {
        gate: Some(Arc::new(|g| {
            Box::pin(async move {
                if g == Gate::Derived {
                    Err(Error::engine("injected"))
                } else {
                    Ok(())
                }
            })
        })),
        defect: None,
    };
    assert!(catch_up(&fx.db, &Budget::default(), &hooks).await.is_err());
    assert!(stored_pairs(&fx.db).await.is_empty());
    assert_eq!(fx.quiet().await, BatchOutcome::Idle);
    assert!(violations(&fx.db).await.is_empty());
}

/// Pair continuations, the anchor index range and the base generator's
/// seeks are index seeks on the bundled SQLite: VM steps do not grow with
/// a 20,000-pair prefix. (This bounds the seeks, not policy JSON or
/// history.) The disjunctive cursor form is the control.
#[test]
fn pair_continuations_and_the_anchor_index_seek_past_any_prefix() {
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
    c.execute_batch("CREATE TABLE kernel_policies (root_id TEXT PRIMARY KEY)")
        .unwrap();
    c.execute_batch(TABLE_DDL[6].1).unwrap();
    c.execute_batch(INDEX_DDL[0].2).unwrap();
    c.execute_batch("BEGIN").unwrap();
    for i in 0..KEYS {
        let p = format!("p{i:06}");
        c.execute(
            "INSERT INTO kernel_principals VALUES (?1, 'agent', 'P', 'agent:' || ?1)",
            [&p],
        )
        .unwrap();
        c.execute(
            "INSERT INTO kernel_policies VALUES (?1)",
            [&format!("a{i:06}")],
        )
        .unwrap();
        c.execute(
            "INSERT INTO p_scope_access VALUES (1, ?1, 'a000001', 1)",
            [&p],
        )
        .unwrap();
        c.execute(
            "INSERT INTO p_scope_access VALUES (1, 'p000001', ?1, 1)",
            [&format!("a{i:06}")],
        )
        .ok();
    }
    c.execute_batch("COMMIT").unwrap();
    let p = format!("p{:06}", KEYS - 10);
    let a = format!("a{:06}", KEYS - 10);
    let bound = 200;
    for (sql, params) in [
        (
            derive::PAIRS_SAME_PRINCIPAL_SQL,
            vec![&1 as &dyn rusqlite::ToSql, &"p000001", &a, &2],
        ),
        (
            derive::PAIRS_LATER_PRINCIPALS_SQL,
            vec![&1 as &dyn rusqlite::ToSql, &p, &2],
        ),
        (
            derive::PAIRS_OF_ANCHOR_SQL,
            vec![&1 as &dyn rusqlite::ToSql, &"a000001", &2],
        ),
        (
            derive::PAIRS_OF_PRINCIPAL_SQL,
            vec![&1 as &dyn rusqlite::ToSql, &"p000001", &2],
        ),
        (
            derive::PAIRS_FIRST_SQL,
            vec![&1 as &dyn rusqlite::ToSql, &2],
        ),
        (derive::NEXT_PRINCIPAL_SQL, vec![&p as &dyn rusqlite::ToSql]),
        (
            derive::ANCHORS_AFTER_SQL,
            vec![&a as &dyn rusqlite::ToSql, &2],
        ),
        (derive::ANCHORS_FIRST_SQL, vec![&2 as &dyn rusqlite::ToSql]),
        (derive::ANY_ANCHOR_SQL, vec![]),
    ] {
        let n = steps(&c, sql, &params);
        assert!(n < bound, "{sql}: {n} steps");
    }
    let control = steps(
        &c,
        "SELECT principal, anchor FROM p_scope_access WHERE generation = ?1 AND (?2 IS NULL OR principal > ?2) ORDER BY principal, anchor LIMIT ?3",
        &[&1, &p, &2],
    );
    assert!(control > KEYS as i32, "the control must scan: {control}");
}
