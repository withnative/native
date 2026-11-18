//! Slice 2b.1 (brief 87a004f): the HomeAnchor derivation, its drain and the
//! Level 0 trust check, on file-backed databases through the real pools.
//!
//! The safety property every witness checks ([`violations`]): in one reader
//! snapshot, no stored row that differs from the live gate's own walk is
//! trusted, and a home without a stored row is never trusted. Each witness
//! with a deliberate defect must make the property fail.

use super::drain::{catch_up, drain_batch_on, BatchOutcome, Budget, Defect, Gate, Hooks, Refusal};
use super::fence::{home_anchor_lookup_on, level0_trust_on, HomeAnchorLookup, Trust, Untrusted};
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

struct Fixture {
    db: Db,
    admin: String,
    _dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = create_v2_database(
        &format!("sqlite://{}", dir.path().join("drain.db").display()),
        "account",
        "Admin",
        "admin",
    )
    .await
    .unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    install_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    Fixture {
        db,
        admin,
        _dir: dir,
    }
}

/// A canonical write through the write pool's real (trigger-bearing)
/// writer connection, for mutations no public API exposes directly.
async fn write(db: &Db, sql: &str, binds: &[&str]) {
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut query = sqlx::query(sql);
    for bind in binds {
        query = query.bind(*bind);
    }
    query.execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}

async fn reparent(db: &Db, home: &str, parent: &str) {
    write(
        db,
        "UPDATE main.kernel_roots SET parent_id = ? WHERE root_id = ?",
        &[parent, home],
    )
    .await;
}

async fn home(fx: &Fixture, parent: &str, policy: bool) -> String {
    let entries: &[(&str, &str)] = &[(&fx.admin, "edit")];
    create_home(&fx.db, parent, policy.then_some(entries), &fx.admin)
        .await
        .unwrap()
}

async fn quiet(db: &Db) -> BatchOutcome {
    catch_up(db, &Budget::default(), &Hooks::default())
        .await
        .unwrap()
}

/// The live walk over full maps, in the caller's snapshot.
async fn live_anchors(conn: &mut SqliteConnection) -> BTreeMap<String, Option<String>> {
    let parents: BTreeMap<String, Option<String>> =
        sqlx::query_as("SELECT root_id, parent_id FROM main.kernel_roots")
            .fetch_all(&mut *conn)
            .await
            .unwrap()
            .into_iter()
            .collect();
    let boundaries: BTreeSet<String> =
        sqlx::query_scalar("SELECT root_id FROM main.kernel_policies")
            .fetch_all(&mut *conn)
            .await
            .unwrap()
            .into_iter()
            .collect();
    parents
        .keys()
        .map(|home| {
            (
                home.clone(),
                crate::kernel::nearest_anchor(home, &parents, &boundaries).map(str::to_owned),
            )
        })
        .collect()
}

/// Trusted-but-wrong rows, plus any trusted lookup of a home without a
/// root row, in one reader snapshot.
async fn violations(db: &Db) -> Vec<String> {
    let mut read = db.pool().begin().await.unwrap();
    let live = live_anchors(&mut read).await;
    let mut found = Vec::new();
    for (home, anchor) in &live {
        if let HomeAnchorLookup::Trusted { anchor: stored } =
            home_anchor_lookup_on(&mut read, home).await.unwrap()
        {
            if &stored != anchor {
                found.push(format!("{home}: stored {stored:?}, live {anchor:?}"));
            }
        }
    }
    for absent in ["no-such-home", "orphan-record-home"] {
        if let HomeAnchorLookup::Trusted { .. } =
            home_anchor_lookup_on(&mut read, absent).await.unwrap()
        {
            found.push(format!("{absent}: trusted without a row"));
        }
    }
    found
}

async fn trust(db: &Db) -> Trust {
    let mut read = db.pool().begin().await.unwrap();
    level0_trust_on(&mut read, Family::HomeAnchor)
        .await
        .unwrap()
}

async fn stored(db: &Db) -> BTreeMap<String, Option<String>> {
    sqlx::query_as("SELECT home, anchor FROM main.p_home_anchor WHERE generation = 1")
        .fetch_all(db.pool())
        .await
        .unwrap()
        .into_iter()
        .collect()
}

async fn cursor(db: &Db) -> (bool, Option<String>) {
    sqlx::query_as(
        "SELECT ready, build_after FROM main.p_state WHERE generation = 1 AND family = 'home_anchor'",
    )
    .fetch_one(db.pool())
        .await
        .unwrap()
}

/// Everything the drain may write, for no-write assertions.
async fn accelerator_rows(db: &Db) -> Vec<String> {
    let mut rows = Vec::new();
    for sql in [
        "SELECT kind || '/' || key FROM main.p_dirty ORDER BY 1",
        "SELECT home || '/' || coalesce(anchor, '-') FROM main.p_home_anchor ORDER BY 1",
        "SELECT generation || '/' || family || '/' || derivation_version || '/' || fingerprint || '/' || ready || '/' || coalesce(build_after, '-') || '/' || written_at FROM main.p_state ORDER BY 1",
        "SELECT generation || '/' || role || '/' || marking_since_seq || '/' || invalidation_epoch FROM main.p_generation ORDER BY 1",
    ] {
        rows.extend(
            sqlx::query_scalar::<_, String>(sql)
                .fetch_all(db.pool())
                .await
                .unwrap(),
        );
    }
    rows
}

fn gate(
    f: impl Fn(Gate) -> futures::future::BoxFuture<'static, Result<()>> + Send + Sync + 'static,
) -> Hooks {
    Hooks {
        gate: Some(Arc::new(f)),
        defect: None,
    }
}

fn small(rows: i64) -> Budget {
    Budget {
        keys: 64,
        rows,
        batches: 1,
    }
}

/// A workspace with a policy home `p`, plain homes under the root and under
/// `p`, and a two-home cycle (a broken rooted walk, stored as NULL).
struct Tree {
    p: String,
    plain: Vec<String>,
    under_p: Vec<String>,
}

async fn tree(fx: &Fixture) -> Tree {
    let p = home(fx, KERNEL_ROOT_ID, true).await;
    let mut plain = Vec::new();
    for _ in 0..6 {
        plain.push(home(fx, KERNEL_ROOT_ID, false).await);
    }
    let mut under_p = Vec::new();
    for _ in 0..3 {
        under_p.push(home(fx, &p, false).await);
    }
    Tree { p, plain, under_p }
}

// ---------------------------------------------------------------------------
// The shared walk
// ---------------------------------------------------------------------------

/// The inline walk `evaluate_homes` ran before the extraction, verbatim.
fn previous_inline_walk<'a>(
    home: &'a str,
    parents: &'a BTreeMap<String, Option<String>>,
    boundaries: &BTreeSet<String>,
) -> Option<&'a str> {
    let mut anchor = home;
    let mut depth = 0usize;
    while !boundaries.contains(anchor) {
        depth += 1;
        if depth > MAX_HOME_DEPTH {
            return None;
        }
        anchor = parents.get(anchor).and_then(|p| p.as_deref())?;
    }
    Some(anchor)
}

#[test]
fn nearest_anchor_matches_the_previous_inline_walk() {
    let mut parents = BTreeMap::new();
    let mut boundaries = BTreeSet::new();
    // A chain h0 <- h1 <- ... <- h104 with the anchor at h0.
    boundaries.insert("h0".to_owned());
    parents.insert("h0".to_owned(), None);
    for i in 1..=104 {
        parents.insert(format!("h{i}"), Some(format!("h{}", i - 1)));
    }
    // A home whose parent has no root row, one with a NULL parent and no
    // anchor, a two-home cycle, and a boundary home without any root row
    // (the boundary test runs before the parent lookup).
    parents.insert("dangling".into(), Some("missing".into()));
    parents.insert("top".into(), None);
    parents.insert("c1".into(), Some("c2".into()));
    parents.insert("c2".into(), Some("c1".into()));
    boundaries.insert("rootless-anchor".into());
    let mut homes: Vec<String> = parents.keys().cloned().collect();
    homes.extend(["missing", "rootless-anchor", "unknown"].map(String::from));
    for home in &homes {
        assert_eq!(
            crate::kernel::nearest_anchor(home, &parents, &boundaries),
            previous_inline_walk(home, &parents, &boundaries),
            "{home}"
        );
    }
    // Depth: 100 hops reach the anchor, 101 do not.
    assert_eq!(
        crate::kernel::nearest_anchor("h100", &parents, &boundaries),
        Some("h0")
    );
    assert_eq!(
        crate::kernel::nearest_anchor("h101", &parents, &boundaries),
        None
    );
    assert_eq!(
        crate::kernel::nearest_anchor("rootless-anchor", &parents, &boundaries),
        Some("rootless-anchor")
    );
    assert_eq!(
        crate::kernel::nearest_anchor("c1", &parents, &boundaries),
        None
    );
}

/// The batch's bounded probes give the full-map answer for every home,
/// including depth 100/101 and a cycle.
#[tokio::test]
async fn probe_walk_matches_the_full_map_walk_for_every_root() {
    let fx = fixture().await;
    let t = tree(&fx).await;
    // A chain 100 hops below `p` (the deepest the API creates), then one
    // more home moved beneath it, 101 hops away: a broken walk.
    let mut parent = t.p.clone();
    for _ in 0..100 {
        parent = home(&fx, &parent, false).await;
    }
    let too_deep = home(&fx, KERNEL_ROOT_ID, false).await;
    reparent(&fx.db, &too_deep, &parent).await;
    reparent(&fx.db, &t.plain[0], &t.plain[1]).await;
    reparent(&fx.db, &t.plain[1], &t.plain[0]).await;
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    let live = live_anchors(&mut tx).await;
    let mut probes = derive::AncestorProbes::default();
    for (home, anchor) in &live {
        assert_eq!(
            &probes.anchor_of(&mut tx, home).await.unwrap(),
            anchor,
            "{home}"
        );
    }
    assert_eq!(
        live[&parent],
        Some(t.p.clone()),
        "100 hops reach the anchor"
    );
    assert_eq!(live[&too_deep], None, "101 hops do not");
    assert_eq!(live[&t.plain[0]], None, "a cycle is broken");
}

// ---------------------------------------------------------------------------
// Lifecycle and schema
// ---------------------------------------------------------------------------

#[tokio::test]
async fn install_creates_the_exact_set_with_its_constraint_autoindex() {
    let autoindex: SchemaObject = (
        "index".into(),
        "sqlite_autoindex_p_generation_1".into(),
        "p_generation".into(),
        None,
    );
    assert!(expected_objects().contains(&autoindex));
    assert!(certification_object(&autoindex));
    let fx = fixture().await;
    let mut conn = fx.db.write_pool().acquire().await.unwrap();
    assert_eq!(
        object_state_on(&mut conn).await.unwrap(),
        ObjectState::Exact
    );
    let generation: (i64, String) =
        sqlx::query_as("SELECT generation, role FROM main.p_generation")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
    assert_eq!(generation, (1, "building".into()));
    assert_eq!(
        sqlx::query_as::<_, (String, i64, String, bool, Option<String>)>(
            "SELECT family, derivation_version, fingerprint, ready, build_after FROM main.p_state ORDER BY family"
        )
        .fetch_all(&mut *conn)
        .await
        .unwrap(),
        Family::ALL
            .iter()
            .map(|f| (
                f.as_str().to_owned(),
                f.derivation_version(),
                f.fingerprint().to_owned(),
                false,
                None
            ))
            .collect::<Vec<_>>()
    );
    // Drop and strip never drop the constraint autoindex directly.
    let mut tx = sqlx::Connection::begin(&mut *conn).await.unwrap();
    assert!(strip_exact_on(&mut tx).await.unwrap() > 0);
    assert_eq!(object_state_on(&mut tx).await.unwrap(), ObjectState::Absent);
    tx.rollback().await.unwrap();
    let mut tx = sqlx::Connection::begin(&mut *conn).await.unwrap();
    drop_on(&mut tx).await.unwrap();
    assert_eq!(object_state_on(&mut tx).await.unwrap(), ObjectState::Absent);
    tx.commit().await.unwrap();
    // An unknown explicit index on a canonical table under the prefix is
    // drift, and the drop path removes it.
    let mut tx = sqlx::Connection::begin(&mut *conn).await.unwrap();
    install_on(&mut tx).await.unwrap();
    sqlx::query("CREATE INDEX main.p_unknown_roots ON kernel_roots(parent_id)")
        .execute(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        object_state_on(&mut tx).await.unwrap(),
        ObjectState::Drifted
    );
    drop_on(&mut tx).await.unwrap();
    assert_eq!(object_state_on(&mut tx).await.unwrap(), ObjectState::Absent);
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn a_quiet_drain_completes_and_every_rooted_home_matches_live() {
    let fx = fixture().await;
    tree(&fx).await;
    assert_eq!(
        trust(&fx.db).await,
        Trust::Untrusted(Untrusted::NoLiveGeneration)
    );
    assert_eq!(quiet(&fx.db).await, BatchOutcome::Idle);
    assert!(matches!(
        trust(&fx.db).await,
        Trust::Trusted { generation: 1 }
    ));
    let mut read = fx.db.pool().begin().await.unwrap();
    let live = live_anchors(&mut read).await;
    drop(read);
    assert_eq!(stored(&fx.db).await, live);
    assert!(violations(&fx.db).await.is_empty());
    let role: String = sqlx::query_scalar("SELECT role FROM main.p_generation")
        .fetch_one(fx.db.pool())
        .await
        .unwrap();
    assert_eq!(role, "live");
    // A second drain has nothing to do.
    assert_eq!(quiet(&fx.db).await, BatchOutcome::Idle);
}

/// Absent and stored NULL are different answers: a home without a row is
/// untrusted; a broken rooted walk is a trusted NULL, as the live gate fails
/// closed for it.
#[tokio::test]
async fn a_missing_home_is_untrusted_and_a_stored_null_is_distinct() {
    let fx = fixture().await;
    let t = tree(&fx).await;
    reparent(&fx.db, &t.plain[2], &t.plain[3]).await;
    reparent(&fx.db, &t.plain[3], &t.plain[2]).await;
    quiet(&fx.db).await;
    let mut read = fx.db.pool().begin().await.unwrap();
    assert_eq!(
        home_anchor_lookup_on(&mut read, &t.plain[2]).await.unwrap(),
        HomeAnchorLookup::Trusted { anchor: None }
    );
    assert_eq!(
        home_anchor_lookup_on(&mut read, "not-a-rooted-home")
            .await
            .unwrap(),
        HomeAnchorLookup::Untrusted(Untrusted::Missing)
    );
    assert_eq!(
        home_anchor_lookup_on(&mut read, &t.under_p[0])
            .await
            .unwrap(),
        HomeAnchorLookup::Trusted {
            anchor: Some(t.p.clone())
        }
    );
}

/// The fence reports why, for each family check.
#[tokio::test]
async fn the_fence_names_each_failed_check() {
    let fx = fixture().await;
    quiet(&fx.db).await;
    assert!(matches!(trust(&fx.db).await, Trust::Trusted { .. }));
    home(&fx, KERNEL_ROOT_ID, false).await;
    assert_eq!(trust(&fx.db).await, Trust::Untrusted(Untrusted::Dirty));
    quiet(&fx.db).await;
    // Keys of kinds the family ignores never untrust it, however many.
    write(
        &fx.db,
        "INSERT INTO main.p_dirty (kind, key) VALUES ('rec', 'a'), ('rec', 'b'), ('principal', 'p'), ('scope', 's')",
        &[],
    )
    .await;
    assert!(matches!(trust(&fx.db).await, Trust::Trusted { .. }));
    write(
        &fx.db,
        "INSERT INTO main.p_dirty (kind, key) VALUES ('from-a-newer-binary', 'k')",
        &[],
    )
    .await;
    assert_eq!(trust(&fx.db).await, Trust::Untrusted(Untrusted::Dirty));
    quiet(&fx.db).await;
    assert!(matches!(trust(&fx.db).await, Trust::Trusted { .. }));
    write(
        &fx.db,
        "UPDATE main.p_state SET fingerprint = 'other' WHERE family = 'home_anchor'",
        &[],
    )
    .await;
    assert_eq!(trust(&fx.db).await, Trust::Untrusted(Untrusted::State));
    write(
        &fx.db,
        "UPDATE main.p_state SET fingerprint = ? WHERE family = 'home_anchor'",
        &[Family::HomeAnchor.fingerprint()],
    )
    .await;
    write(
        &fx.db,
        "UPDATE main.p_marking SET marking_since_seq = marking_since_seq + 1",
        &[],
    )
    .await;
    assert_eq!(trust(&fx.db).await, Trust::Untrusted(Untrusted::Era));
    let mut read = fx.db.pool().acquire().await.unwrap();
    assert!(
        level0_trust_on(&mut read, Family::HomeAnchor)
            .await
            .is_err(),
        "needs a snapshot"
    );
    drop(read);
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    set_enabled_on(&mut tx, false).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(trust(&fx.db).await, Trust::Untrusted(Untrusted::MarkingOff));
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    drop_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(trust(&fx.db).await, Trust::Untrusted(Untrusted::Absent));
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

/// Deleted homes, including the highest keys, lose their rows; a stored row
/// with no base at all is purged by bounded steps.
#[tokio::test]
async fn deleted_homes_and_the_deleted_tail_are_purged() {
    let fx = fixture().await;
    let t = tree(&fx).await;
    quiet(&fx.db).await;
    let mut doomed: Vec<String> = t.plain.clone();
    doomed.sort();
    let doomed = &doomed[doomed.len() - 3..];
    for home in doomed {
        write(
            &fx.db,
            "DELETE FROM main.kernel_roots WHERE root_id = ?",
            &[home],
        )
        .await;
    }
    // Rows past every remaining root, as an interrupted build might leave.
    write(
        &fx.db,
        "INSERT INTO main.p_home_anchor VALUES (1, '~~~ tail', NULL), (1, '~~~ tail 2', 'x')",
        &[],
    )
    .await;
    write(
        &fx.db,
        "INSERT INTO main.p_dirty (kind, key) VALUES ('home', 'tail')",
        &[],
    )
    .await;
    let mut budget = small(1);
    budget.batches = 10_000;
    assert_eq!(
        catch_up(&fx.db, &budget, &Hooks::default()).await.unwrap(),
        BatchOutcome::Idle
    );
    let rows = stored(&fx.db).await;
    for home in doomed {
        assert!(!rows.contains_key(home), "{home}");
    }
    assert!(!rows.keys().any(|h| h.starts_with("~~~")));
    assert!(violations(&fx.db).await.is_empty());
}

/// An empty base: every stored row is deleted by bounded steps, and the
/// family is ready only when both streams are exhausted. Other generations
/// are untouched.
#[tokio::test]
async fn an_empty_base_purges_every_stored_row_in_bounded_steps() {
    use sqlx::Connection;
    let mut conn = SqliteConnection::connect("sqlite::memory:").await.unwrap();
    for ddl in [
        "CREATE TABLE kernel_roots (root_id TEXT PRIMARY KEY, parent_id TEXT)",
        "CREATE TABLE kernel_policies (root_id TEXT PRIMARY KEY)",
        TABLE_DDL[4].1,
    ] {
        sqlx::query(ddl).execute(&mut conn).await.unwrap();
    }
    for i in 0..5 {
        for generation in [1, 2] {
            sqlx::query("INSERT INTO main.p_home_anchor VALUES (?, ?, NULL)")
                .bind(generation)
                .bind(format!("h{i}"))
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
            Family::HomeAnchor,
            1,
            cursor.as_deref(),
            2,
            &mut cache,
        )
        .await
        .unwrap();
        assert!(step.derived.is_empty() && step.deleted.len() <= 2);
        derive::apply_step_on(&mut conn, Family::HomeAnchor, 1, &step)
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
        sqlx::query_as("SELECT generation, count(*) FROM main.p_home_anchor GROUP BY generation")
            .fetch_all(&mut conn)
            .await
            .unwrap();
    assert_eq!(left, vec![(2, 5)]);
}

/// After mutations stop, a drain completes even with the smallest batches.
#[tokio::test]
async fn bounded_batches_complete_after_mutations_stop() {
    let fx = fixture().await;
    tree(&fx).await;
    let mut batches = 0;
    loop {
        batches += 1;
        assert!(batches < 1_000, "the drain must finish");
        match catch_up(
            &fx.db,
            &Budget {
                keys: 1,
                rows: 1,
                batches: 1,
            },
            &Hooks::default(),
        )
        .await
        .unwrap()
        {
            BatchOutcome::Idle => break,
            BatchOutcome::Refused(r) => panic!("{r:?}"),
            _ => {}
        }
    }
    assert!(matches!(trust(&fx.db).await, Trust::Trusted { .. }));
    assert!(violations(&fx.db).await.is_empty());
}

// ---------------------------------------------------------------------------
// Compatibility, era and epoch
// ---------------------------------------------------------------------------

/// Unknown, missing, newer or same-version-different state: no write, no
/// key loss, and an immediate return rather than a retry loop.
#[tokio::test]
async fn incompatible_state_refuses_without_writes_or_spinning() {
    for tamper in [
        "UPDATE main.p_state SET derivation_version = derivation_version + 1",
        "UPDATE main.p_state SET fingerprint = 'same-version-other-derivation'",
        "DELETE FROM main.p_state",
        "INSERT INTO main.p_state VALUES (1, 'family_from_a_newer_binary', 1, 'f', 0, NULL, 0, 0)",
    ] {
        let fx = fixture().await;
        tree(&fx).await;
        write(&fx.db, tamper, &[]).await;
        let before = accelerator_rows(&fx.db).await;
        assert!(before.iter().any(|r| r.starts_with("home/")), "{tamper}");
        let started = std::time::Instant::now();
        assert_eq!(
            quiet(&fx.db).await,
            BatchOutcome::Refused(Refusal::IncompatibleState),
            "{tamper}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(accelerator_rows(&fx.db).await, before, "{tamper}");
    }
}

/// A generation that missed an epoch or era change (a raw or foreign
/// invalidation) is reset and adopts the current values under the lease;
/// its old rows are never trusted on the strength of the old epoch.
#[tokio::test]
async fn a_missed_epoch_or_era_is_adopted_with_a_full_reset() {
    for foreign in [
        "UPDATE main.p_marking SET invalidation_epoch = invalidation_epoch + 1",
        "UPDATE main.p_marking SET marking_since_seq = marking_since_seq + 1",
    ] {
        let fx = fixture().await;
        let t = tree(&fx).await;
        quiet(&fx.db).await;
        write(&fx.db, foreign, &[]).await;
        assert!(matches!(
            trust(&fx.db).await,
            Trust::Untrusted(Untrusted::Epoch | Untrusted::Era)
        ));
        let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
        assert_eq!(
            drain_batch_on(&mut tx, &Budget::default(), &Hooks::default())
                .await
                .unwrap(),
            BatchOutcome::Adopted
        );
        tx.commit().await.unwrap();
        assert_eq!(cursor(&fx.db).await, (false, None), "{foreign}");
        assert_eq!(trust(&fx.db).await, Trust::Untrusted(Untrusted::NotReady));
        reparent(&fx.db, &t.plain[0], &t.p).await;
        assert_eq!(quiet(&fx.db).await, BatchOutcome::Idle);
        assert!(matches!(trust(&fx.db).await, Trust::Trusted { .. }));
        assert!(violations(&fx.db).await.is_empty());
    }
}

async fn assert_reset_and_adopted(db: &Db, what: &str) {
    let states: Vec<(String, bool, Option<String>)> =
        sqlx::query_as("SELECT family, ready, build_after FROM main.p_state ORDER BY family")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(states.len(), Family::ALL.len(), "{what}");
    for (family, ready, after) in states {
        assert!(!ready && after.is_none(), "{what}: {family}");
    }
    let (since, epoch): (i64, i64) = sqlx::query_as(
        "SELECT marking_since_seq, invalidation_epoch FROM main.p_marking WHERE singleton = 1",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let generation: (i64, i64) =
        sqlx::query_as("SELECT marking_since_seq, invalidation_epoch FROM main.p_generation")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(generation, (since, epoch), "{what}");
}

/// Leave the family mid-rebuild: ready, then a write, then one small batch.
async fn mid_rebuild(fx: &Fixture) {
    assert_eq!(quiet(&fx.db).await, BatchOutcome::Idle);
    home(fx, KERNEL_ROOT_ID, false).await;
    catch_up(&fx.db, &small(2), &Hooks::default())
        .await
        .unwrap();
    let (ready, after) = cursor(&fx.db).await;
    assert!(!ready && after.is_some(), "mid-rebuild");
}

/// M6 (SQLx and raw), disabling, enabling and replay completion all reset
/// every family and cursor and adopt the new era and epoch atomically.
#[tokio::test]
async fn every_invalidation_path_resets_cursors_and_adopts_atomically() {
    let fx = fixture().await;
    tree(&fx).await;

    mid_rebuild(&fx).await;
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    invalidate_all_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    assert_reset_and_adopted(&fx.db, "invalidate_all_on").await;

    mid_rebuild(&fx).await;
    let raw = rusqlite::Connection::open(fx._dir.path().join("drain.db")).unwrap();
    raw.execute_batch("BEGIN IMMEDIATE").unwrap();
    invalidate_all_raw(&raw).unwrap();
    raw.execute_batch("COMMIT").unwrap();
    drop(raw);
    assert_reset_and_adopted(&fx.db, "invalidate_all_raw").await;

    mid_rebuild(&fx).await;
    for enabled in [false, true] {
        let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
        set_enabled_on(&mut tx, enabled).await.unwrap();
        tx.commit().await.unwrap();
        assert_reset_and_adopted(&fx.db, "enablement").await;
    }

    mid_rebuild(&fx).await;
    replay_all_projections(&fx.db).await.unwrap();
    assert_reset_and_adopted(&fx.db, "replay").await;
    assert_eq!(quiet(&fx.db).await, BatchOutcome::Idle);
    assert!(violations(&fx.db).await.is_empty());
}

// ---------------------------------------------------------------------------
// Witnesses W1–W8
// ---------------------------------------------------------------------------

/// W1: a write that commits between the read preflight and the writer
/// lease is seen by the batch's own snapshot and never lost.
#[tokio::test]
async fn w1_a_write_after_the_preflight_is_never_lost() {
    let fx = fixture().await;
    let t = tree(&fx).await;
    quiet(&fx.db).await;
    home(&fx, KERNEL_ROOT_ID, false).await;
    let fired = Arc::new(Mutex::new(false));
    let (db, moved, to) = (fx.db.clone(), t.plain[0].clone(), t.p.clone());
    let once = fired.clone();
    let hooks = gate(move |g| {
        let (db, moved, to, once) = (db.clone(), moved.clone(), to.clone(), once.clone());
        Box::pin(async move {
            if g == Gate::Preflighted && !std::mem::replace(&mut *once.lock().unwrap(), true) {
                reparent(&db, &moved, &to).await;
            }
            Ok(())
        })
    });
    assert_eq!(
        catch_up(&fx.db, &Budget::default(), &hooks).await.unwrap(),
        BatchOutcome::Idle
    );
    assert!(*fired.lock().unwrap());
    assert_eq!(
        stored(&fx.db).await.get(&t.plain[0]),
        Some(&Some(t.p.clone()))
    );
    assert!(violations(&fx.db).await.is_empty());
}

/// W2: while a batch holds the writer lease between derivation and commit,
/// a real writer cannot commit; afterwards it commits and its keys are
/// still dirty, so nothing it changed is trusted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w2_a_writer_waits_for_the_batch_and_stays_dirty() {
    let fx = fixture().await;
    tree(&fx).await;
    let writer: Arc<Mutex<Option<tokio::task::JoinHandle<String>>>> = Arc::default();
    let (db, admin, slot) = (fx.db.clone(), fx.admin.clone(), writer.clone());
    let hooks = gate(move |g| {
        let (db, admin, slot) = (db.clone(), admin.clone(), slot.clone());
        Box::pin(async move {
            if g == Gate::Derived && slot.lock().unwrap().is_none() {
                let handle = tokio::spawn(async move {
                    create_home(&db, KERNEL_ROOT_ID, None, &admin)
                        .await
                        .unwrap()
                });
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                assert!(
                    !handle.is_finished(),
                    "a writer committed inside the drain's lease"
                );
                *slot.lock().unwrap() = Some(handle);
            }
            Ok(())
        })
    });
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    assert!(matches!(
        drain_batch_on(&mut tx, &Budget::default(), &hooks)
            .await
            .unwrap(),
        BatchOutcome::Progress { .. }
    ));
    tx.commit().await.unwrap();
    let handle = writer.lock().unwrap().take().expect("the gate ran");
    let created = handle.await.unwrap();
    let dirty: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.p_dirty WHERE kind = 'home' AND key = ?)",
    )
    .bind(&created)
    .fetch_one(fx.db.pool())
    .await
    .unwrap();
    assert!(dirty);
    assert!(violations(&fx.db).await.is_empty());
    quiet(&fx.db).await;
    assert!(stored(&fx.db).await.contains_key(&created));
}

/// W3: a drain failure rolls back only the drain; the earlier canonical
/// write survives, its keys stay dirty, and the next run completes.
#[tokio::test]
async fn w3_a_drain_failure_rolls_back_only_the_drain() {
    for failing in [Gate::Escalated, Gate::Derived, Gate::RebuildAdvanced] {
        let fx = fixture().await;
        tree(&fx).await;
        quiet(&fx.db).await;
        let created = home(&fx, KERNEL_ROOT_ID, false).await;
        let before = accelerator_rows(&fx.db).await;
        let hooks = gate(move |g| {
            Box::pin(async move {
                if g == failing {
                    Err(Error::engine("injected drain failure"))
                } else {
                    Ok(())
                }
            })
        });
        assert!(
            catch_up(&fx.db, &Budget::default(), &hooks).await.is_err(),
            "{failing:?}"
        );
        assert_eq!(accelerator_rows(&fx.db).await, before, "{failing:?}");
        // The canonical write before the failed drain survives it.
        assert!(sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM main.kernel_roots WHERE root_id = ?)"
        )
        .bind(&created)
        .fetch_one(fx.db.pool())
        .await
        .unwrap());
        assert!(violations(&fx.db).await.is_empty());
        assert_eq!(quiet(&fx.db).await, BatchOutcome::Idle);
        assert!(stored(&fx.db).await.contains_key(&created));
    }
}

/// W4: the property holds after every partial batch, with writes between
/// batches.
#[tokio::test]
async fn w4_every_partial_batch_keeps_the_property() {
    let fx = fixture().await;
    let t = tree(&fx).await;
    for round in 0..40 {
        if round % 7 == 3 {
            reparent(&fx.db, &t.plain[round % t.plain.len()], &t.p).await;
        }
        let outcome = catch_up(
            &fx.db,
            &Budget {
                keys: 1,
                rows: 2,
                batches: 1,
            },
            &Hooks::default(),
        )
        .await
        .unwrap();
        assert!(violations(&fx.db).await.is_empty(), "round {round}");
        if outcome == BatchOutcome::Idle && round > 30 {
            break;
        }
    }
    assert_eq!(quiet(&fx.db).await, BatchOutcome::Idle);
    assert!(violations(&fx.db).await.is_empty());
}

/// Drive a fresh rebuild to mid-way, then move a home the cursor has
/// already passed under the policy home.
async fn change_behind_cursor(fx: &Fixture, t: &Tree, hooks: &Hooks) -> Vec<String> {
    quiet(&fx.db).await;
    let mut tx = begin_write(fx.db.write_pool()).await.unwrap();
    invalidate_all_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    for _ in 0..3 {
        catch_up(&fx.db, &small(2), hooks).await.unwrap();
    }
    let (_, after) = cursor(&fx.db).await;
    let after = after.expect("mid-rebuild");
    let (behind, to) = t
        .plain
        .iter()
        .map(|h| (h, t.p.as_str()))
        .chain(t.under_p.iter().map(|h| (h, KERNEL_ROOT_ID)))
        .filter(|(h, _)| h.as_str() <= after.as_str())
        .min()
        .expect("a home behind the cursor");
    reparent(&fx.db, behind, to).await;
    let mut budget = small(2);
    budget.batches = 10_000;
    assert_eq!(
        catch_up(&fx.db, &budget, hooks).await.unwrap(),
        BatchOutcome::Idle
    );
    violations(&fx.db).await
}

/// W5: escalation restarts the rebuild from the start. Continuing from the
/// cursor instead would trust a row derived before the change.
#[tokio::test]
async fn w5_escalation_restarts_the_rebuild_and_continuing_is_caught() {
    let fx = fixture().await;
    let t = tree(&fx).await;
    assert!(change_behind_cursor(&fx, &t, &Hooks::default())
        .await
        .is_empty());
    let fx = fixture().await;
    let t = tree(&fx).await;
    let defective = Hooks {
        gate: None,
        defect: Some(Defect::ContinueCursor),
    };
    assert!(
        !change_behind_cursor(&fx, &t, &defective).await.is_empty(),
        "the witness must catch a cursor that is not restarted"
    );
}

async fn parent_of(db: &Db, home: &str) -> Option<String> {
    sqlx::query_scalar("SELECT parent_id FROM main.kernel_roots WHERE root_id = ?")
        .bind(home)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

/// W6: at every build checkpoint, a home behind the cursor and one ahead of
/// it change anchor (alternately), and the property holds throughout.
#[tokio::test]
async fn w6_writes_around_every_build_checkpoint_keep_the_property() {
    let fx = fixture().await;
    let t = tree(&fx).await;
    let mut plain = t.plain.clone();
    plain.sort();
    let mut behind = false;
    let mut moved = 0;
    for _ in 0..200 {
        let outcome = catch_up(&fx.db, &small(1), &Hooks::default())
            .await
            .unwrap();
        assert!(violations(&fx.db).await.is_empty());
        if outcome == BatchOutcome::Idle {
            break;
        }
        if moved >= 8 {
            continue;
        }
        if let (false, Some(after)) = cursor(&fx.db).await {
            let target = if behind {
                plain.iter().find(|h| h.as_str() <= after.as_str())
            } else {
                plain.iter().find(|h| h.as_str() > after.as_str())
            };
            if let Some(target) = target {
                let to = if parent_of(&fx.db, target).await.as_deref() == Some(t.p.as_str()) {
                    KERNEL_ROOT_ID
                } else {
                    t.p.as_str()
                };
                reparent(&fx.db, target, to).await;
                moved += 1;
            }
            behind = !behind;
        }
    }
    assert!(moved > 0);
    assert_eq!(quiet(&fx.db).await, BatchOutcome::Idle);
    assert!(violations(&fx.db).await.is_empty());
}

/// W7: dropping the objects or disabling marking while a drain waits for
/// the lease wins: the batch writes nothing and recreates nothing.
#[tokio::test]
async fn w7_off_and_drop_win_over_a_pending_drain() {
    for drop in [true, false] {
        let fx = fixture().await;
        tree(&fx).await;
        let rows_before = stored(&fx.db).await;
        let mut conn = fx.db.write_pool().acquire().await.unwrap();
        let dirty_before = dirty_keys_on(&mut conn).await.unwrap();
        std::mem::drop(conn);
        let db = fx.db.clone();
        let hooks = gate(move |g| {
            let db = db.clone();
            Box::pin(async move {
                if g == Gate::Preflighted {
                    let mut tx = begin_write(db.write_pool()).await?;
                    if drop {
                        drop_on(&mut tx).await?;
                    } else {
                        set_enabled_on(&mut tx, false).await?;
                    }
                    tx.commit().await?;
                }
                Ok(())
            })
        });
        let expected = if drop {
            Refusal::Absent
        } else {
            Refusal::MarkingOff
        };
        assert_eq!(
            catch_up(&fx.db, &Budget::default(), &hooks).await.unwrap(),
            BatchOutcome::Refused(expected)
        );
        let mut conn = fx.db.write_pool().acquire().await.unwrap();
        if drop {
            assert_eq!(
                object_state_on(&mut conn).await.unwrap(),
                ObjectState::Absent
            );
        } else {
            assert_eq!(
                object_state_on(&mut conn).await.unwrap(),
                ObjectState::Exact
            );
            assert!(!marking_row_on(&mut conn).await.unwrap().unwrap().enabled);
            assert_eq!(dirty_keys_on(&mut conn).await.unwrap(), dirty_before);
            std::mem::drop(conn);
            assert_eq!(stored(&fx.db).await, rows_before);
            assert_eq!(cursor(&fx.db).await, (false, None));
        }
    }
}

/// W8: deleting a dirty key without escalating is exactly the bug the
/// property exists to catch.
#[tokio::test]
async fn w8_skipping_escalation_is_caught() {
    for defect in [None, Some(Defect::SkipEscalation)] {
        let fx = fixture().await;
        let t = tree(&fx).await;
        quiet(&fx.db).await;
        reparent(&fx.db, &t.plain[0], &t.p).await;
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

// ---------------------------------------------------------------------------
// Boundedness evidence on the bundled SQLite
// ---------------------------------------------------------------------------

/// Run a statement to completion and return its rows and VM steps.
fn vm_steps(c: &rusqlite::Connection, sql: &str, params: &[&dyn rusqlite::ToSql]) -> (usize, i32) {
    let mut statement = c.prepare(sql).unwrap();
    let mut rows = 0;
    {
        let mut cursor = statement.query(params).unwrap();
        while cursor.next().unwrap().is_some() {
            rows += 1;
        }
    }
    (
        rows,
        statement.get_status(rusqlite::StatementStatus::VmStep),
    )
}

/// Rebuild continuations and the fence's kind walk are index seeks: their
/// cost does not grow with the keys already processed or with irrelevant
/// dirty keys. The previous `?1 IS NULL OR key > ?1` form is the
/// sensitivity control: it scans the processed prefix.
#[test]
fn continuations_and_kind_probes_seek_past_any_prefix() {
    const KEYS: usize = 20_000;
    let c = rusqlite::Connection::open_in_memory().unwrap();
    c.execute_batch("CREATE TABLE kernel_roots (root_id TEXT PRIMARY KEY, parent_id TEXT)")
        .unwrap();
    c.execute_batch(TABLE_DDL[0].1).unwrap();
    c.execute_batch(TABLE_DDL[4].1).unwrap();
    c.execute_batch("BEGIN").unwrap();
    for i in 0..KEYS {
        let key = format!("r{i:06}");
        c.execute("INSERT INTO kernel_roots VALUES (?1, NULL)", [&key])
            .unwrap();
        for generation in [1, 2] {
            c.execute(
                "INSERT INTO p_home_anchor VALUES (?1, ?2, NULL)",
                rusqlite::params![generation, key],
            )
            .unwrap();
        }
        c.execute("INSERT INTO p_dirty VALUES ('rec', ?1)", [&key])
            .unwrap();
    }
    c.execute_batch("INSERT INTO p_dirty VALUES ('principal', 'p'); COMMIT")
        .unwrap();
    let cursor = format!("r{:06}", KEYS - 10);
    let bound = 200;

    let (rows, steps) = vm_steps(&c, derive::ROOTS_AFTER_SQL, &[&cursor, &2]);
    assert_eq!(rows, 2);
    assert!(steps < bound, "roots continuation took {steps} steps");
    let (rows, steps) = vm_steps(&c, derive::STORED_AFTER_SQL, &[&1, &cursor, &2]);
    assert_eq!(rows, 2);
    assert!(steps < bound, "stored continuation took {steps} steps");
    let (_, steps) = vm_steps(&c, derive::ROOTS_FIRST_SQL, &[&2]);
    assert!(steps < bound, "first page took {steps} steps");
    let (_, steps) = vm_steps(&c, derive::STORED_FIRST_SQL, &[&2, &2]);
    assert!(
        steps < bound,
        "first stored page of generation 2 took {steps} steps"
    );

    // The fence skips all 20,000 `rec` keys with one seek per kind.
    let (_, steps) = vm_steps(&c, super::fence::FIRST_KIND_SQL, &[]);
    assert!(steps < bound, "first kind took {steps} steps");
    for kind in ["principal", "rec"] {
        let (_, steps) = vm_steps(&c, super::fence::NEXT_KIND_SQL, &[&kind]);
        assert!(steps < bound, "next kind after {kind} took {steps} steps");
    }

    // Sensitivity: the disjunctive cursor form rescans the prefix.
    let (_, steps) = vm_steps(
        &c,
        "SELECT root_id FROM kernel_roots WHERE ?1 IS NULL OR root_id > ?1 ORDER BY root_id LIMIT ?2",
        &[&cursor, &2],
    );
    assert!(steps > KEYS as i32, "the control must scan: {steps} steps");
}
