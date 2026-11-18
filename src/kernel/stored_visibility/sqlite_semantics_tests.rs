//! The SQLite behaviours the marking design rests on (73ad275 rev 2 E1–E10),
//! pinned on the bundled SQLite the product ships. Rev 2 observed them on
//! 3.45.1; rev 2.1 requires them on the bundled version before any
//! implementation merges. If an upgrade changes one, this fails first.

use rusqlite::{Connection, ErrorCode};

fn open() -> Connection {
    let c = Connection::open_in_memory().unwrap();
    c.execute_batch("PRAGMA recursive_triggers = OFF").unwrap();
    c
}

fn count(c: &Connection, sql: &str) -> i64 {
    c.query_row(sql, [], |r| r.get(0)).unwrap()
}

/// A long-running INSERT … SELECT for the interrupt experiments.
const LONG_INSERT: &str = "INSERT INTO scratch(v) SELECT x FROM (WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 1000000) SELECT x FROM n)";
const LONG_SELECT: &str = "SELECT count(*) FROM (WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 1000000) SELECT x FROM n)";

fn with_interrupt<T>(c: &Connection, f: impl FnOnce() -> T) -> T {
    c.progress_handler(1000, Some(|| true));
    let result = f();
    c.progress_handler(1000, None::<fn() -> bool>);
    result
}

fn interrupted(result: rusqlite::Result<usize>) -> bool {
    matches!(result, Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::OperationInterrupted)
}

#[test]
fn bundled_sqlite_is_the_version_these_semantics_were_pinned_on() {
    assert_eq!(rusqlite::version(), "3.46.0");
}

/// E1: interrupting DML inside a savepoint rolls back the *outer*
/// transaction. Derivation must therefore never run DML under a progress
/// handler in a canonical write transaction (D1).
#[test]
fn e1_interrupted_dml_rolls_back_the_outer_transaction() {
    let c = open();
    c.execute_batch("CREATE TABLE canon(v); CREATE TABLE scratch(v); BEGIN IMMEDIATE; INSERT INTO canon VALUES(1); SAVEPOINT p_flush;").unwrap();
    assert!(interrupted(
        with_interrupt(&c, || c.execute(LONG_INSERT, []))
    ));
    assert!(c.is_autocommit(), "the outer transaction is gone");
    assert!(c.execute_batch("ROLLBACK TO p_flush").is_err());
    assert!(c.execute_batch("COMMIT").is_err());
    assert_eq!(count(&c, "SELECT count(*) FROM canon"), 0);
}

/// E2: an interrupted read-only SELECT ends only that statement.
#[test]
fn e2_interrupted_select_keeps_the_transaction() {
    let c = open();
    c.execute_batch(
        "CREATE TABLE canon(v); BEGIN IMMEDIATE; INSERT INTO canon VALUES(1); SAVEPOINT p_flush;",
    )
    .unwrap();
    let result = with_interrupt(&c, || c.query_row(LONG_SELECT, [], |r| r.get::<_, i64>(0)));
    assert!(
        matches!(result, Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::OperationInterrupted)
    );
    assert!(!c.is_autocommit());
    c.execute_batch("ROLLBACK TO p_flush; RELEASE p_flush; COMMIT")
        .unwrap();
    assert_eq!(count(&c, "SELECT count(*) FROM canon"), 1);
}

/// E3: even a small interrupted UPDATE loses the outer transaction, while a
/// statement-level constraint abort inside a savepoint does not.
#[test]
fn e3_small_interrupted_update_loses_the_transaction_but_abort_does_not() {
    let c = open();
    c.execute_batch("CREATE TABLE canon(v); CREATE TABLE u(k PRIMARY KEY); INSERT INTO u VALUES(1),(2); BEGIN IMMEDIATE; INSERT INTO canon VALUES(1); SAVEPOINT p_flush;").unwrap();
    c.progress_handler(1, Some(|| true));
    let result = c.execute("UPDATE u SET k = k + 10", []);
    c.progress_handler(1, None::<fn() -> bool>);
    assert!(interrupted(result));
    assert!(c.is_autocommit());
    assert_eq!(count(&c, "SELECT count(*) FROM canon"), 0);

    c.execute_batch("BEGIN IMMEDIATE; INSERT INTO canon VALUES(1); SAVEPOINT p_flush;")
        .unwrap();
    let unique = c.execute("INSERT INTO u VALUES(1)", []);
    assert!(
        matches!(unique, Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::ConstraintViolation)
    );
    assert!(!c.is_autocommit());
    c.execute_batch("ROLLBACK TO p_flush; RELEASE p_flush; COMMIT")
        .unwrap();
    assert_eq!(count(&c, "SELECT count(*) FROM canon"), 1);
}

/// E4: a main trigger's unqualified target resolves to main even with a TEMP
/// table of the same name, but an unqualified *read* resolves to TEMP. Hence
/// M5: every non-trigger reader names `main.`.
#[test]
fn e4_trigger_writes_main_but_unqualified_reads_see_temp() {
    let c = open();
    c.execute_batch("CREATE TABLE t(id PRIMARY KEY); CREATE TABLE p_dirty(kind, key, PRIMARY KEY(kind, key)); CREATE TRIGGER m AFTER INSERT ON t BEGIN INSERT INTO p_dirty VALUES('rec', NEW.id); END; CREATE TEMP TABLE p_dirty(kind, key);").unwrap();
    c.execute("INSERT INTO main.t VALUES('a')", []).unwrap();
    assert_eq!(count(&c, "SELECT count(*) FROM main.p_dirty"), 1);
    assert_eq!(count(&c, "SELECT count(*) FROM p_dirty"), 0);
}

const MARK_OR_IGNORE: &str = "CREATE TRIGGER m AFTER UPDATE ON t BEGIN INSERT OR IGNORE INTO p_dirty VALUES('rec', NEW.id); END";
const MARK_DO_NOTHING: &str = "CREATE TRIGGER m AFTER UPDATE ON t BEGIN INSERT INTO p_dirty(kind, key) SELECT 'rec', NEW.id WHERE NEW.id IS NOT NULL ON CONFLICT(kind, key) DO NOTHING; END";
const MARK_NOT_EXISTS: &str = "CREATE TRIGGER m AFTER UPDATE ON t BEGIN INSERT INTO p_dirty(kind, key) SELECT 'rec', NEW.id WHERE NOT EXISTS (SELECT 1 FROM p_dirty WHERE kind = 'rec' AND key = NEW.id); END";

fn marked_table(trigger: &str) -> Connection {
    let c = open();
    c.execute_batch(&format!("CREATE TABLE t(id TEXT PRIMARY KEY, v); INSERT INTO t VALUES('a', 0); CREATE TABLE p_dirty(kind TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY(kind, key)) WITHOUT ROWID; INSERT INTO p_dirty VALUES('rec', 'a'); {trigger};")).unwrap();
    c
}

/// Every outer conflict form a writer may use. The key is already dirty, so
/// each one makes the trigger body hit its conflict.
const OUTER_FORMS: &[&str] = &[
    "UPDATE t SET v = v + 1 WHERE id = 'a'",
    "UPDATE OR ABORT t SET v = v + 1 WHERE id = 'a'",
    "UPDATE OR FAIL t SET v = v + 1 WHERE id = 'a'",
    "UPDATE OR ROLLBACK t SET v = v + 1 WHERE id = 'a'",
    "UPDATE OR IGNORE t SET v = v + 1 WHERE id = 'a'",
    "UPDATE OR REPLACE t SET v = v + 1 WHERE id = 'a'",
    "INSERT INTO t VALUES('a', 9) ON CONFLICT(id) DO UPDATE SET v = excluded.v",
    "INSERT OR ROLLBACK INTO t VALUES('a', 9) ON CONFLICT(id) DO UPDATE SET v = excluded.v",
];

/// E5: an `OR IGNORE` trigger body is overridden by the outer statement's
/// conflict policy, so ordinary writes fail, and `OR ROLLBACK` loses the whole
/// transaction. This is the defect rev 2 removed.
#[test]
fn e5_or_ignore_bodies_are_overridden_by_outer_conflict_policy() {
    let outcomes: Vec<(&str, bool)> = OUTER_FORMS
        .iter()
        .map(|form| {
            let c = marked_table(MARK_OR_IGNORE);
            c.execute_batch("BEGIN IMMEDIATE").unwrap();
            let ok = c.execute(form, []).is_ok();
            (*form, ok)
        })
        .collect();
    let failed: Vec<&str> = outcomes
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(f, _)| *f)
        .collect();
    assert!(
        failed.contains(&OUTER_FORMS[1]),
        "UPDATE OR ABORT: {outcomes:?}"
    );
    assert!(
        failed.contains(&OUTER_FORMS[3]),
        "UPDATE OR ROLLBACK: {outcomes:?}"
    );
    assert!(
        failed.contains(&OUTER_FORMS[6]),
        "upsert DO UPDATE: {outcomes:?}"
    );
    assert!(
        !failed.contains(&OUTER_FORMS[0]),
        "plain UPDATE: {outcomes:?}"
    );

    let c = marked_table(MARK_OR_IGNORE);
    c.execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES('b', 1);")
        .unwrap();
    assert!(c.execute(OUTER_FORMS[3], []).is_err());
    assert!(c.is_autocommit(), "OR ROLLBACK lost the transaction");
}

/// E6: an upsert `DO NOTHING` body (the production form) and a
/// `WHERE NOT EXISTS` body tolerate every outer conflict form.
#[test]
fn e6_do_nothing_and_not_exists_bodies_tolerate_every_outer_form() {
    for trigger in [MARK_DO_NOTHING, MARK_NOT_EXISTS] {
        for form in OUTER_FORMS {
            let c = marked_table(trigger);
            c.execute_batch("BEGIN IMMEDIATE").unwrap();
            c.execute(form, [])
                .unwrap_or_else(|e| panic!("{trigger} under {form}: {e}"));
            c.execute_batch("COMMIT").unwrap();
            assert_eq!(count(&c, "SELECT count(*) FROM p_dirty"), 1, "{form}");
        }
    }
}

/// E7: a TEMP table with an input's name captures an unqualified write; the
/// main trigger never fires. Trigger bodies cannot qualify a table name, so
/// the defence is the writer contract (M4), not the trigger.
#[test]
fn e7_temp_shadow_captures_unqualified_writes_and_bodies_cannot_qualify() {
    let c = open();
    c.execute_batch("CREATE TABLE t(id PRIMARY KEY); CREATE TABLE p_dirty(kind, key, PRIMARY KEY(kind, key)); CREATE TRIGGER m AFTER INSERT ON t BEGIN INSERT INTO p_dirty VALUES('rec', NEW.id); END; CREATE TEMP TABLE t(id);").unwrap();
    c.execute("INSERT INTO t VALUES('a')", []).unwrap();
    assert_eq!(count(&c, "SELECT count(*) FROM temp.t"), 1);
    assert_eq!(count(&c, "SELECT count(*) FROM main.t"), 0);
    assert_eq!(count(&c, "SELECT count(*) FROM main.p_dirty"), 0);
    let qualified = c.execute_batch("CREATE TRIGGER q AFTER INSERT ON main.t BEGIN INSERT INTO main.p_dirty VALUES('rec', NEW.id); END");
    assert!(
        qualified.is_err(),
        "trigger bodies must refuse qualified names"
    );
}

/// E8: with `recursive_triggers` off (production), a REPLACE that evicts a
/// row through a UNIQUE column fires no delete trigger: the evicted key is
/// missed. Hence M3, the REPLACE ban.
#[test]
fn e8_replace_eviction_is_unmarked_without_recursive_triggers() {
    for (recursive, expected) in [(false, 1), (true, 2)] {
        let c = open();
        c.execute_batch(&format!("PRAGMA recursive_triggers = {}; CREATE TABLE t(id TEXT PRIMARY KEY, u UNIQUE); CREATE TABLE p_dirty(kind, key, PRIMARY KEY(kind, key)); INSERT INTO t VALUES('old', 1); CREATE TRIGGER mi AFTER INSERT ON t BEGIN INSERT INTO p_dirty(kind, key) SELECT 'rec', NEW.id WHERE 1 ON CONFLICT DO NOTHING; END; CREATE TRIGGER md AFTER DELETE ON t BEGIN INSERT INTO p_dirty(kind, key) SELECT 'rec', OLD.id WHERE 1 ON CONFLICT DO NOTHING; END;", if recursive { "ON" } else { "OFF" })).unwrap();
        c.execute("INSERT OR REPLACE INTO t VALUES('new', 1)", [])
            .unwrap();
        assert_eq!(
            count(&c, "SELECT count(*) FROM p_dirty"),
            expected,
            "recursive={recursive}"
        );
    }
}

/// E10: a foreign-key `ON DELETE CASCADE` fires the child's delete trigger
/// even with `recursive_triggers` off, so cascades are marked.
#[test]
fn e10_cascade_fires_child_delete_triggers() {
    let c = open();
    c.execute_batch("PRAGMA foreign_keys = ON; CREATE TABLE parent(id TEXT PRIMARY KEY); CREATE TABLE child(id TEXT PRIMARY KEY, p TEXT REFERENCES parent(id) ON DELETE CASCADE); CREATE TABLE p_dirty(kind, key, PRIMARY KEY(kind, key)); INSERT INTO parent VALUES('h'); INSERT INTO child VALUES('c', 'h'); CREATE TRIGGER md AFTER DELETE ON child BEGIN INSERT INTO p_dirty(kind, key) SELECT 'anchor', OLD.p WHERE 1 ON CONFLICT DO NOTHING; END;").unwrap();
    c.execute("DELETE FROM parent", []).unwrap();
    assert_eq!(count(&c, "SELECT count(*) FROM child"), 0);
    assert_eq!(count(&c, "SELECT count(*) FROM p_dirty"), 1);
}
