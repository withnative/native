//! The one place that knows how to take a current-DDL database back to an
//! older engine schema.
//!
//! Many tests rebuild a historical database by starting from the current DDL,
//! removing everything added since the target version, then stamping
//! `PRAGMA user_version`. This module is that knowledge, kept in one data
//! table so a new migration needs exactly one edit here instead of one per
//! test: add an [`EngineAddition`] for the new version to [`ADDITIONS`].
//!
//! The table is data only (no sqlx/rusqlite/turso types) so every backend and
//! the separate `held/` crates can read it. Each backend runs
//! [`statements`] through its own driver; the sqlx path additionally verifies
//! the result against the frozen structural pin for the target version.
//!
//! The frozen shape pins the helper verifies against must be measured from the
//! released engine DDL before the next migration lands, never by running this
//! helper; see the note on [`ADDITIONS`].
//!
//! Scope: targets from [`LOWEST_STEP_DOWN_TARGET`] up. Below it, edges rebuild
//! tables and are never extended again, so fixtures that reach further back
//! keep their own frozen tail and call this for the part that grows.

/// An object a migration added, undone by dropping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    Table(&'static str),
    Index(&'static str),
    View(&'static str),
    Trigger(&'static str),
    /// A column appended with `ALTER TABLE .. ADD COLUMN`.
    Column {
        table: &'static str,
        column: &'static str,
    },
    /// The closed `records.type` CHECK gained `Configuration` (engine 87).
    /// SQLite cannot alter a CHECK, so it is undone by rebuilding `records`
    /// under the previous definition; see [`records_type_check_statements`].
    RecordsTypeCheck,
}

/// Everything the migration edge `(version - 1) -> version` added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineAddition {
    pub version: i64,
    pub added: &'static [Added],
}

/// The lowest engine version [`statements`] can reach.
pub const LOWEST_STEP_DOWN_TARGET: i64 = 74;

/// Version -> objects that version added, ascending. Extend this (and only
/// this) when adding an engine migration; `step_down::tests` fails if the
/// current version has no entry, if an edge has no entry, or if the stepped
/// down database does not match the frozen pin of its target.
///
/// Objects that vanish with their table (its indexes and triggers) are not
/// listed. A trigger on another table, or an index on a surviving table, is.
///
/// # Pin ordering: never measure a pin with this table
/// Before adding engine N+1, record the frozen `ENGINE_N` shape pin
/// (`db.rs`) and `FROZEN_DDL_SHA256_PRE_N+1` (`schema/contract.rs`) **from the
/// current engine-N DDL**, as the migration checklist already requires. Do
/// not obtain them by stepping an N+1 database down with this helper: the
/// helper verifies its result against those pins, so a pin measured that way
/// would agree with whatever this table says, right or wrong, and the check
/// would be circular.
pub const ADDITIONS: &[EngineAddition] = &[
    EngineAddition {
        version: 75,
        added: &[Added::Table("body_blocks")],
    },
    EngineAddition {
        version: 76,
        added: &[Added::Table("vocabulary_value_json_nodes")],
    },
    EngineAddition {
        version: 77,
        added: &[
            Added::Trigger("content_event_reaction_meta_insert"),
            Added::Table("content_event_reaction_meta"),
        ],
    },
    EngineAddition {
        version: 78,
        added: &[Added::Column {
            table: "alpha_tab_installs",
            column: "adoption_provenance",
        }],
    },
    EngineAddition {
        version: 79,
        added: &[Added::Column {
            table: "alpha_tab_installs",
            column: "body_read_admission_event_id",
        }],
    },
    EngineAddition {
        version: 80,
        added: &[Added::Table("workspace_rule_installations")],
    },
    EngineAddition {
        version: 81,
        added: &[Added::Table("schema_config_json_nodes")],
    },
    EngineAddition {
        version: 82,
        added: &[Added::Table("facet_value_json_nodes")],
    },
    EngineAddition {
        version: 83,
        added: &[Added::Table("message_speakers"), Added::Table("personas")],
    },
    EngineAddition {
        version: 84,
        added: &[Added::Table("provenance_action_app_attributions")],
    },
    EngineAddition {
        version: 85,
        added: &[Added::Table("facet_observation_json_nodes")],
    },
    EngineAddition {
        version: 86,
        added: &[Added::Table("record_body_json_nodes")],
    },
    EngineAddition {
        version: 87,
        added: &[Added::RecordsTypeCheck],
    },
    EngineAddition {
        version: 88,
        added: &[Added::Column {
            table: "message_preferences",
            column: "unread_override",
        }],
    },
    EngineAddition {
        version: 89,
        added: &[Added::Table("account_configs")],
    },
    EngineAddition {
        version: 90,
        added: &[Added::Table("sql_write_receipts")],
    },
];

/// The columns of `records`, in definition order, copied (with `rowid`) when
/// the table is rebuilt. A test pins this against the current table.
pub const RECORDS_COLUMNS: &[&str] = &[
    "id",
    "type",
    "kind",
    "name",
    "body",
    "home_id",
    "lifecycle",
    "owner_id",
    "claimed_by_account",
    "claimed_run_key",
    "claimed_at",
    "policy_anchor_id",
    "persistence",
    "maturity",
    "summary",
    "last_activity_at",
    "created_at",
    "updated_at",
    "deleted_at",
    "archived",
    "is_current",
    "successor_count",
];

/// Statements that rebuild `records` under the engine-86 type CHECK (without
/// `Configuration`), keeping every row, rowid, index and trigger. Indexes and
/// triggers are taken from the current DDL, which is what a step-down fixture
/// starts from. Foreign keys are switched off for the rebuild (SQLite rewrites
/// the references of other tables on rename whenever they are on, and
/// `records` references itself) and **left off**: [`step_down_with`] and
/// [`step_down_rusqlite`] restore the connection's setting; a caller running
/// the statements itself must do the same.
pub fn records_type_check_statements() -> Vec<String> {
    let current = crate::schema::ddl::RECORDS_DDL;
    let previous = current.replace(",'Annotation','Configuration')", ",'Annotation')");
    assert_ne!(
        previous, current,
        "RECORDS_DDL no longer names Configuration"
    );
    let columns = RECORDS_COLUMNS.join(", ");
    let on_records = |statement: &str| {
        let statement = statement.trim_start();
        (statement.starts_with("CREATE INDEX") || statement.starts_with("CREATE TRIGGER"))
            && statement.match_indices(" ON records").any(|(at, text)| {
                statement[at + text.len()..]
                    .chars()
                    .next()
                    .is_some_and(|next| next.is_whitespace() || next == '(')
            })
    };
    let mut statements = vec![
        "PRAGMA foreign_keys=OFF".to_owned(),
        "PRAGMA legacy_alter_table=ON".to_owned(),
        "ALTER TABLE records RENAME TO records_step_down".to_owned(),
        previous,
        format!(
            "INSERT INTO records (rowid, {columns}) SELECT rowid, {columns} FROM records_step_down ORDER BY rowid"
        ),
        "DROP TABLE records_step_down".to_owned(),
    ];
    statements.extend(
        crate::schema::DDL_STATEMENTS
            .iter()
            .copied()
            .filter(|statement| on_records(statement))
            .map(str::to_owned),
    );
    statements.push("PRAGMA legacy_alter_table=OFF".to_owned());
    statements
}

impl Added {
    /// The `sqlite_schema` `(type, name)` of a whole object; `None` for a column.
    fn object(self) -> Option<(&'static str, &'static str)> {
        match self {
            Added::Table(name) => Some(("table", name)),
            Added::Index(name) => Some(("index", name)),
            Added::View(name) => Some(("view", name)),
            Added::Trigger(name) => Some(("trigger", name)),
            Added::Column { .. } | Added::RecordsTypeCheck => None,
        }
    }

    fn drop_sql(self, if_exists: bool) -> Vec<String> {
        let guard = if if_exists { "IF EXISTS " } else { "" };
        match self {
            Added::Column { table, column } => {
                vec![format!("ALTER TABLE {table} DROP COLUMN {column}")]
            }
            Added::RecordsTypeCheck => records_type_check_statements(),
            object => {
                let (kind, name) = object.object().expect("non-column objects have a name");
                vec![format!("DROP {} {guard}{name}", kind.to_uppercase())]
            }
        }
    }

    /// Drop order inside one version: dependents before what they hang off.
    fn rank(self) -> u8 {
        match self {
            Added::Trigger(_) => 0,
            Added::View(_) => 1,
            Added::Index(_) => 2,
            Added::Column { .. } => 3,
            Added::Table(_) => 4,
            Added::RecordsTypeCheck => 5,
        }
    }
}

/// What must be undone to go from `current` down to `target`, newest version
/// first and in drop order inside each version.
fn undo_for(additions: &[EngineAddition], current: i64, target: i64) -> Vec<Added> {
    assert!(
        (LOWEST_STEP_DOWN_TARGET..=current).contains(&target),
        "cannot step down to engine {target}: supported targets are \
         {LOWEST_STEP_DOWN_TARGET}..={current}"
    );
    let mut undo = Vec::new();
    for version in ((target + 1)..=current).rev() {
        let entry = additions
            .iter()
            .find(|entry| entry.version == version)
            .unwrap_or_else(|| {
                panic!(
                    "no step-down entry for engine {version}: add an EngineAddition to \
                     schema::step_down::ADDITIONS listing what that migration added"
                )
            });
        let mut added = entry.added.to_vec();
        added.sort_by_key(|object| object.rank());
        undo.extend(added);
    }
    undo
}

/// The statements that take a database at `current` DDL down to `target`,
/// newest version first, ending with the `PRAGMA user_version` stamp.
///
/// # Panics
/// If `target` is outside `LOWEST_STEP_DOWN_TARGET..=current`, or `additions`
/// has no entry for a version that must be undone.
pub fn statements_for(additions: &[EngineAddition], current: i64, target: i64) -> Vec<String> {
    let mut statements: Vec<String> = undo_for(additions, current, target)
        .into_iter()
        .flat_map(|object| object.drop_sql(false))
        .collect();
    statements.push(format!("PRAGMA user_version={target}"));
    statements
}

/// The whole-object drops (tables, indexes, views, triggers) from the current
/// version down to `target`, without column drops or a version stamp, for
/// fixtures that rebuild affected tables themselves (e.g. on Turso, where
/// `DROP COLUMN` is limited). With `if_exists`, a fixture that may peel the
/// same edge twice tolerates objects already gone.
pub fn object_drop_statements(target: i64, if_exists: bool) -> Vec<String> {
    undo_for(ADDITIONS, crate::db::CURRENT_ENGINE_SCHEMA_VERSION, target)
        .into_iter()
        .filter(|object| object.object().is_some())
        .flat_map(|object| object.drop_sql(if_exists))
        .collect()
}

/// `(sqlite_schema type, name)` of every whole object
/// [`object_drop_statements`] removes, so a fixture can assert they are gone.
pub fn dropped_objects(target: i64) -> Vec<(&'static str, &'static str)> {
    undo_for(ADDITIONS, crate::db::CURRENT_ENGINE_SCHEMA_VERSION, target)
        .into_iter()
        .filter_map(Added::object)
        .collect()
}

/// [`statements_for`] over the production table and current engine version.
pub fn statements(target: i64) -> Vec<String> {
    statements_from(crate::db::CURRENT_ENGINE_SCHEMA_VERSION, target)
}

/// Like [`statements`] for a database already stepped down to `from` (for
/// fixtures that descend in stages and check each stage).
pub fn statements_from(from: i64, target: i64) -> Vec<String> {
    statements_for(ADDITIONS, from, target)
}

/// [`statements_from`] joined for `execute_batch`-style drivers.
pub fn sql_batch_from(from: i64, target: i64) -> String {
    let mut batch = statements_from(from, target).join(";\n");
    batch.push(';');
    batch
}

/// [`statements`] joined for `execute_batch`-style drivers.
pub fn sql_batch(target: i64) -> String {
    sql_batch_from(crate::db::CURRENT_ENGINE_SCHEMA_VERSION, target)
}

/// Problems that make a table unusable for stepping down: it must cover every
/// version in `(LOWEST_STEP_DOWN_TARGET, current]` exactly once, and every
/// migration edge that lands in that range.
pub fn coverage_problems(
    additions: &[EngineAddition],
    current: i64,
    edge_targets: &[i64],
) -> Vec<String> {
    let mut problems = Vec::new();
    for version in (LOWEST_STEP_DOWN_TARGET + 1)..=current {
        match additions.iter().filter(|e| e.version == version).count() {
            1 => {}
            0 => problems.push(format!(
                "engine {version} has no step-down entry (current is {current})"
            )),
            n => problems.push(format!("engine {version} has {n} step-down entries")),
        }
    }
    for entry in additions {
        if !((LOWEST_STEP_DOWN_TARGET + 1)..=current).contains(&entry.version) {
            problems.push(format!(
                "step-down entry for engine {} is outside {}..={current}",
                entry.version,
                LOWEST_STEP_DOWN_TARGET + 1
            ));
        }
    }
    for &to in edge_targets {
        if to > LOWEST_STEP_DOWN_TARGET && !additions.iter().any(|e| e.version == to) {
            problems.push(format!(
                "migration edge {} -> {to} exists without a step-down entry",
                to - 1
            ));
        }
    }
    problems
}

/// Step an open sqlx connection (at current DDL) down to `target` and verify
/// it is exactly the frozen structural shape of that version.
#[cfg(test)]
pub(crate) async fn step_down(
    connection: &mut sqlx::SqliteConnection,
    target: i64,
) -> crate::error::Result<()> {
    step_down_with(
        connection,
        ADDITIONS,
        crate::db::CURRENT_ENGINE_SCHEMA_VERSION,
        target,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn step_down_with(
    connection: &mut sqlx::SqliteConnection,
    additions: &[EngineAddition],
    current: i64,
    target: i64,
) -> crate::error::Result<()> {
    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&mut *connection)
        .await?;
    for statement in statements_for(additions, current, target) {
        sqlx::query(&statement).execute(&mut *connection).await?;
    }
    sqlx::query(&format!("PRAGMA foreign_keys={foreign_keys}"))
        .execute(&mut *connection)
        .await?;
    if target != current
        && !crate::db::validate_engine_shape_on_for_test(connection, target).await?
    {
        return Err(crate::error::Error::engine(format!(
            "step-down to engine {target} does not match its frozen shape; \
             schema::step_down::ADDITIONS is missing something a migration added"
        )));
    }
    Ok(())
}

/// Step a rusqlite connection down. Not shape-verified (callers on this path
/// reshape the file for another backend); the statements are the ones the
/// sqlx path verifies.
#[cfg(test)]
pub(crate) fn step_down_rusqlite(connection: &rusqlite::Connection, target: i64) {
    let foreign_keys: i64 = connection
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .unwrap();
    connection.execute_batch(&sql_batch(target)).unwrap();
    connection
        .execute_batch(&format!("PRAGMA foreign_keys={foreign_keys};"))
        .unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::CURRENT_ENGINE_SCHEMA_VERSION as CURRENT;
    use sqlx::Connection;

    fn edge_targets() -> Vec<i64> {
        crate::migrations::EngineMigrationRegistry::production()
            .pending(LOWEST_STEP_DOWN_TARGET, CURRENT)
            .unwrap()
            .iter()
            .map(|edge| edge.to())
            .collect()
    }

    #[test]
    fn table_covers_current_version_and_every_migration_edge() {
        let problems = coverage_problems(ADDITIONS, CURRENT, &edge_targets());
        assert!(problems.is_empty(), "{problems:#?}");
    }

    #[test]
    fn missing_entries_are_reported() {
        // The next migration, whose author forgot the table.
        let problems = coverage_problems(ADDITIONS, CURRENT + 1, &[CURRENT + 1]);
        assert_eq!(problems.len(), 2, "{problems:#?}");
        assert!(problems[0].contains(&format!("engine {} has no step-down", CURRENT + 1)));
        assert!(problems[1].contains("without a step-down entry"));
        let gap: Vec<_> = ADDITIONS
            .iter()
            .copied()
            .filter(|e| e.version != 80)
            .collect();
        assert_eq!(coverage_problems(&gap, CURRENT, &[]).len(), 1);
    }

    #[test]
    #[should_panic(expected = "no step-down entry for engine")]
    fn statements_refuse_to_skip_a_version_without_an_entry() {
        statements_for(ADDITIONS, CURRENT + 1, CURRENT);
    }

    #[test]
    fn object_drops_skip_columns_and_can_tolerate_missing_objects() {
        let drops = object_drop_statements(LOWEST_STEP_DOWN_TARGET, true);
        assert!(
            drops.iter().all(|sql| sql.contains(" IF EXISTS ")),
            "{drops:?}"
        );
        assert!(
            drops.iter().all(|sql| !sql.starts_with("ALTER")),
            "{drops:?}"
        );
        assert!(
            drops.contains(&"DROP TRIGGER IF EXISTS content_event_reaction_meta_insert".to_owned())
        );
        assert_eq!(object_drop_statements(CURRENT, false), Vec::<String>::new());
        assert_eq!(
            dropped_objects(CURRENT - 1),
            vec![("table", "sql_write_receipts")]
        );
    }

    #[tokio::test]
    async fn records_columns_match_the_current_table() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut connection = db.write_pool().acquire().await.unwrap();
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('records')")
                .fetch_all(&mut *connection)
                .await
                .unwrap();
        assert_eq!(columns, RECORDS_COLUMNS);
        drop(connection);
        db.close().await;
    }

    #[tokio::test]
    async fn every_listed_object_exists_in_the_current_ddl() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut connection = db.write_pool().acquire().await.unwrap();
        for entry in ADDITIONS {
            for added in entry.added {
                let (kind, name) = match added {
                    Added::Table(name) => ("table", *name),
                    Added::Index(name) => ("index", *name),
                    Added::View(name) => ("view", *name),
                    Added::Trigger(name) => ("trigger", *name),
                    Added::RecordsTypeCheck => {
                        let sql: String = sqlx::query_scalar(
                            "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'records'",
                        )
                        .fetch_one(&mut *connection)
                        .await
                        .unwrap();
                        assert!(sql.contains("'Annotation','Configuration'"));
                        continue;
                    }
                    Added::Column { table, column } => {
                        let found: i64 = sqlx::query_scalar(
                            "SELECT count(*) FROM pragma_table_xinfo(?) WHERE name = ?",
                        )
                        .bind(table)
                        .bind(column)
                        .fetch_one(&mut *connection)
                        .await
                        .unwrap();
                        assert_eq!(found, 1, "engine {}: {table}.{column}", entry.version);
                        continue;
                    }
                };
                let found: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM sqlite_schema WHERE type = ? AND name = ?",
                )
                .bind(kind)
                .bind(name)
                .fetch_one(&mut *connection)
                .await
                .unwrap();
                assert_eq!(found, 1, "engine {}: {kind} {name}", entry.version);
            }
        }
        drop(connection);
        db.close().await;
    }

    #[tokio::test]
    async fn stepping_down_to_every_target_matches_its_frozen_shape() {
        for target in LOWEST_STEP_DOWN_TARGET..=CURRENT {
            let db = crate::db::create_database(":memory:").await.unwrap();
            let mut connection = db.write_pool().acquire().await.unwrap();
            step_down(&mut connection, target)
                .await
                .unwrap_or_else(|error| panic!("engine {target}: {error}"));
            let stamped: i64 = sqlx::query_scalar("PRAGMA user_version")
                .fetch_one(&mut *connection)
                .await
                .unwrap();
            assert_eq!(stamped, target);
            // The same database must be a valid migration source for its edge.
            if target < CURRENT {
                crate::db::validate_supported_engine_migration_source(&mut connection, target)
                    .await
                    .unwrap();
            }
            drop(connection);
            db.close().await;
        }
    }

    #[tokio::test]
    async fn descending_in_stages_matches_each_stage_shape() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut connection = db.write_pool().acquire().await.unwrap();
        let mut from = CURRENT;
        for target in [82, 80, 78, 74] {
            step_down_with(&mut connection, ADDITIONS, from, target)
                .await
                .unwrap_or_else(|error| panic!("{from} -> {target}: {error}"));
            from = target;
        }
        drop(connection);
        db.close().await;
    }

    #[tokio::test]
    async fn a_forgotten_drop_fails_at_the_helper() {
        // The newest entry loses its table, as if a migration landed without it.
        let forgetful: Vec<_> = ADDITIONS
            .iter()
            .map(|entry| EngineAddition {
                version: entry.version,
                added: if entry.version == CURRENT {
                    &[]
                } else {
                    entry.added
                },
            })
            .collect();
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut connection = db.write_pool().acquire().await.unwrap();
        let error = step_down_with(&mut connection, &forgetful, CURRENT, CURRENT - 1)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match its frozen shape"),
            "{error}"
        );
        drop(connection);
        db.close().await;
    }

    #[tokio::test]
    async fn rusqlite_adapter_runs_the_same_statements() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rusqlite-step-down.db");
        crate::db::create_database(path.to_str().unwrap())
            .await
            .unwrap()
            .close()
            .await;
        let connection = rusqlite::Connection::open(&path).unwrap();
        step_down_rusqlite(&connection, 78);
        drop(connection);
        let mut sqlx_connection =
            sqlx::SqliteConnection::connect(&format!("sqlite:{}", path.display()))
                .await
                .unwrap();
        crate::db::validate_supported_engine_migration_source(&mut sqlx_connection, 78)
            .await
            .unwrap();
    }
}
