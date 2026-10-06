//! Mechanical trigger-coverage test for both authorization counters.
//!
//! Slice F-B of the member-offline contract (§4.1, "Mechanical
//! trigger-coverage test"). Test-only module (`#[cfg(test)]` in
//! `lib.rs`): no production behaviour change.
//!
//! The test prepares authorization SQL — the rendered `auth_statement(...)`
//! templates, the bulk preload statements, and the governed fence view
//! bodies — on a fresh engine database, with a SQLite authorizer callback
//! recording every `(table, column)` read under `SQLITE_READ` (the same
//! hook the SQL port uses). It then parses the live `sqlite_master`
//! trigger SQL and checks two properties:
//!
//! * Per counter: for each recorded pair, insert/update(column)/delete
//!   on EACH of `authorization_revision` (broad cache fence) and
//!   `authorization_grant_revision` (grant-only realtime fence) must be
//!   covered or waived by a commented `EXEMPTIONS` entry.
//! * Union safety net (`unwatched_by_both`): for each recorded pair and
//!   each operation, AT LEAST ONE counter fires (only the hardcoded
//!   766ede6 `unit_id` exception).
//!
//! "Covered" for an update means the column is in the `UPDATE OF` list
//! or the `WHEN` predicate (`OLD.`/`NEW.` references) of an update
//! trigger whose body bumps that counter's table, plus table-level
//! insert and delete triggers. Trigger shapes or bodies that cannot be
//! parsed fail the test loudly rather than passing.
//!
//! Provenance notes (read before extending). The prepared SQL texts come
//! from the real builders, not hand copies — but the DRIVEN SITE LIST
//! is hand-maintained in
//! `collect_authorization_templates_for_coverage` and guarded by
//! `collector_covers_every_auth_statement_site`, which fails when a new
//! `auth_statement(` call site appears in `src/authorization.rs`. The
//! fence view set is discovered from `TEMP_CONTRACT` by name pattern
//! (`is_authorization_coverage_view`), which fails loudly when it
//! matches nothing. The governed schema checks
//! (`authorization_revision` / `authorization_grant` state_violations)
//! are re-run on the fresh database under analysis — the same checks
//! `create_database` already enforces at open — so a dropped trigger
//! fails closed at creation time; a trigger dropped at runtime after
//! opening is NOT simulated here.
//!
//! Anything not covered must appear in `EXEMPTIONS` with a comment.
//! Unused exemption entries also fail, so the list cannot silently rot.

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
use rusqlite::{Connection, OpenFlags};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Counter {
    Broad,
    Grant,
}

impl Counter {
    fn prefix(self) -> &'static str {
        match self {
            Counter::Broad => "authorization_revision_",
            Counter::Grant => "authorization_grant_",
        }
    }

    fn all() -> [Counter; 2] {
        [Counter::Broad, Counter::Grant]
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum GapKind {
    Insert,
    Delete,
    Update,
}

struct Exemption {
    table: &'static str,
    /// `None` waives the gap for every column of the table (used for the
    /// table-level insert/delete requirements).
    column: Option<&'static str>,
    /// `None` waives the gap on both counters.
    counter: Option<Counter>,
    /// Empty waives every gap kind for the (table, column, counter) cell.
    gaps: &'static [GapKind],
    reason: &'static str,
}

/// Checked-in, commented exemption list (§4.1). Every entry names the
/// counter gap it waives and why the member fence stays sound without
/// it. Unused entries fail via `stale` below, so the list cannot
/// silently rot.
const EXEMPTIONS: &[Exemption] = &[
    // §4.1 known entry 1: `records` insert moves the broad counter only.
    // Intentional — a new record is not a grant change.
    Exemption {
        table: "records",
        column: None,
        counter: Some(Counter::Grant),
        gaps: &[GapKind::Insert],
        reason: "§4.1: intentional; a new record is not a grant change",
    },
    // RESOLVED (task 766ede6, P2a): not a hole in the member fence. A
    // `semantic_units.unit_id` update is watched by NEITHER counter (the
    // broad counter has no `semantic_units` triggers at all; the grant
    // counter watches `authority_bearer_record_id` only). E(m) nevertheless
    // reads `unit_id` (`_query_sql_visible_records`, `src/query/sql.rs`), so
    // member copies cover it fence-side: `MemberCopyRegistry` folds every
    // `semantic_units` row into the workspace fence's `units_state_digest`
    // and `check_download` re-evaluates E(m) whenever it moves
    // (`src/member_copy_registry.rs`, `UNITS_STATE_FENCE_COVERS_UNIT_ID`).
    //
    // MUST BE REVISITED if the authorization counters become the only fence
    // input: then a real `AFTER UPDATE OF unit_id ON semantic_units` trigger
    // (or an equivalent) is required.
    Exemption {
        table: "semantic_units",
        column: Some("unit_id"),
        counter: None,
        gaps: &[],
        reason: "§4.1/§4.2: not watched by either counter; member fence covers it via MemberCopyRegistry units_state_digest — revisit if counters become the only fence input",
    },
    // RESOLVED (orchestrator): documented exemption, not a gap. The
    // checker found `(records, id)` unwatched by the broad counter's
    // update trigger (`authorization_revision_records_update`,
    // `src/schema/ddl.rs`: its `UPDATE OF` list and `WHEN` predicate
    // name owner, anchor, type, kind and deleted_at only). The member
    // fence reads BOTH counters (contract §4.2), so a change is
    // detected when at least one counter moves — and the grant counter
    // does watch this pair (`OLD.id` in its records-update `WHEN`).
    Exemption {
        table: "records",
        column: Some("id"),
        counter: Some(Counter::Broad),
        gaps: &[GapKind::Update],
        reason: "§4.1/§4.2: grant counter watches (records, id); fence reads both",
    },
    // RESOLVED (orchestrator): documented exemption, not a gap. The
    // broad counter has no `semantic_units` triggers at all (all 15
    // `AUTHORIZATION_REVISION_TRIGGERS` cover records, record_policies,
    // policy_entries, bindings and links only), so
    // `(semantic_units, authority_bearer_record_id)` is grant-only.
    // This is exactly contract finding F-a (§4.1: "the fence takes both
    // counters"), and the member fence reads BOTH counters (§4.2), so a
    // bearer change is detected when the grant counter moves.
    Exemption {
        table: "semantic_units",
        column: None,
        counter: Some(Counter::Broad),
        gaps: &[],
        reason: "§4.1 F-a / §4.2: grant counter watches unit bearers; fence reads both",
    },
];
/// One recorded authorizer observation: (schema, table, column).
/// `column` is empty for column-less population reads (`COUNT(*)` /
/// `EXISTS(SELECT 1 ...)` report the table with an empty column).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct TableRead {
    schema: String,
    table: String,
    column: String,
}

/// Prepare each SQL text on `conn` under an allow-all recording
/// authorizer and return every `(schema, table, column)` read observed
/// via `SQLITE_READ`. Names are lowercased: SQLite preserves statement
/// case, while DDL and trigger SQL are lowercase by convention.
fn record_reads(conn: &Connection, statements: &[String]) -> Vec<TableRead> {
    let mut reads = BTreeSet::new();
    for sql in statements {
        // Same hook shape the SQL port uses: an owned observer shared
        // into a `'static` authorizer, installed for one prepare, then
        // cleared before the next statement.
        let pending =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::<(String, String, String)>::new()));
        let seen = pending.clone();
        conn.authorizer(Some(move |context: AuthContext<'_>| {
            if let AuthAction::Read {
                table_name,
                column_name,
            } = context.action
            {
                seen.lock().expect("read lock").push((
                    context.database_name.unwrap_or("main").to_owned(),
                    table_name.to_owned(),
                    column_name.to_owned(),
                ));
            }
            Authorization::Allow
        }));
        let prepared = conn.prepare(sql);
        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
        prepared.unwrap_or_else(|error| panic!("coverage SQL prepares: {sql}\n{error}"));
        let pending = std::sync::Arc::try_unwrap(pending)
            .expect("authorizer releases observer")
            .into_inner()
            .expect("read lock");
        for (schema, table, column) in pending {
            reads.insert(TableRead {
                schema: schema.to_ascii_lowercase(),
                table: table.to_ascii_lowercase(),
                column: column.to_ascii_lowercase(),
            });
        }
    }
    reads.into_iter().collect()
}

/// Parsed coverage facts for one counter derived from live trigger SQL.
#[derive(Default, Debug)]
struct CounterCoverage {
    insert_tables: BTreeSet<String>,
    delete_tables: BTreeSet<String>,
    /// (table, column) pairs named by an `UPDATE OF` list or a `WHEN`
    /// predicate of an update trigger bumping this counter.
    update_columns: BTreeSet<(String, String)>,
}

/// Strip single-quoted literals (`'it''s'`-escaped) so predicate text
/// like `'part_of'` can never contribute a phantom `OLD.`/`NEW.` hit.
fn strip_sqlite_literals(sql: &str) -> Result<String, String> {
    let mut out = String::with_capacity(sql.len());
    let mut chars = sql.chars().peekable();
    while let Some(char) = chars.next() {
        if char != '\'' {
            out.push(char);
            continue;
        }
        let mut closed = false;
        while let Some(next) = chars.next() {
            if next == '\'' {
                if chars.peek() == Some(&'\'') {
                    chars.next();
                    continue;
                }
                closed = true;
                break;
            }
        }
        if !closed {
            return Err("unbalanced single quote in trigger SQL".to_owned());
        }
        out.push(' ');
    }
    Ok(out)
}

/// Collect `OLD.<col>` / `NEW.<col>` references (case-insensitive) from
/// literal-stripped predicate text. `OLD.`/`NEW.` match only at a left
/// word boundary (start of text or a preceding byte outside
/// `[A-Za-z0-9_.]`), so identifiers such as `RENEW.id` or `xOLD.y`
/// never contribute a phantom watched column — a false "watched" would
/// pass the test when it should fail.
fn when_columns(predicate: &str) -> BTreeSet<String> {
    let upper = predicate.to_ascii_uppercase();
    let bytes = upper.as_bytes();
    let mut columns = BTreeSet::new();
    let mut index = 0;
    while index + 4 < bytes.len() {
        let is_old = bytes[index..].starts_with(b"OLD.");
        let is_new = bytes[index..].starts_with(b"NEW.");
        let at_boundary = index == 0
            || !(bytes[index - 1].is_ascii_alphanumeric()
                || bytes[index - 1] == b'_'
                || bytes[index - 1] == b'.');
        if (!is_old && !is_new) || !at_boundary {
            index += 1;
            continue;
        }
        let mut end = index + 4;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        if end > index + 4 {
            columns.insert(upper[index + 4..end].to_ascii_lowercase());
        }
        index = end;
    }
    columns
}
/// Reads outside counter enforcement by design (not durable engine
/// tables): `temp` per-request state, and the `json_each` built-in
/// table-valued function applied to bind parameters. The bulk preload
/// path filters already-loaded id sets through `json_each(?)`; those
/// inputs are not fresh authorization state, and the underlying tables
/// are covered separately. A new synthetic source fails loudly as an
/// uncovered gap until it is listed here with its reason.
fn is_synthetic_scope(read: &TableRead) -> bool {
    read.schema != "main" || read.table == "json_each"
}
/// A parsed trigger:
/// `(counter, table, is_insert, is_delete, update_columns_or_none)`.
type ParsedAuthTrigger = (Counter, String, bool, bool, Option<BTreeSet<String>>);

/// Parse one live authorization trigger. Returns
/// `(counter, table, is_insert, is_delete, update_columns_or_none)`.
/// `update_columns_or_none` is `Some` for update triggers (possibly
/// empty, which the caller treats as covering nothing) and `None` for
/// insert/delete triggers. Every unrecognized shape is an error: the
/// test fails loudly rather than passing on a trigger it cannot read.
fn parse_auth_trigger(name: &str, sql: &str) -> Result<ParsedAuthTrigger, String> {
    let counter = Counter::all()
        .into_iter()
        .find(|counter| name.starts_with(counter.prefix()))
        .ok_or_else(|| format!("trigger '{name}' has no counter prefix"))?;
    let sql = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let after_create = sql
        .strip_prefix(&format!("CREATE TRIGGER {name} "))
        .or_else(|| sql.strip_prefix(&format!("CREATE TRIGGER IF NOT EXISTS {name} ")))
        .ok_or_else(|| format!("trigger '{name}' has unrecognized CREATE prefix: {sql}"))?;
    // Longest alternatives first so `UPDATE OF` wins over `UPDATE`.
    let (kind, rest) = [
        ("AFTER UPDATE OF ", "update_of"),
        ("AFTER UPDATE ON ", "update"),
        ("AFTER INSERT ON ", "insert"),
        ("AFTER DELETE ON ", "delete"),
        ("BEFORE DELETE ON ", "delete"),
    ]
    .into_iter()
    .find_map(|(token, kind)| after_create.strip_prefix(token).map(|rest| (kind, rest)))
    .ok_or_else(|| format!("trigger '{name}' has unrecognized timing/event: {after_create}"))?;
    let (table, of_list, tail) = match kind {
        "update_of" => {
            // `rest` starts with the column list: `<cols> ON <table> ...`.
            let on = rest
                .find(" ON ")
                .ok_or_else(|| format!("trigger '{name}' UPDATE OF list has no ON: {rest}"))?;
            let after_on = rest[on + " ON ".len()..].trim_start().to_owned();
            let end = after_on.find(' ').unwrap_or(after_on.len());
            (
                after_on[..end].to_owned(),
                Some(rest[..on].to_owned()),
                after_on[end..].trim_start().to_owned(),
            )
        }
        _ => {
            let end = rest.find(' ').unwrap_or(rest.len());
            (
                rest[..end].to_owned(),
                None,
                rest[end..].trim_start().to_owned(),
            )
        }
    };
    if table.is_empty()
        || table.contains(|char: char| !(char.is_ascii_alphanumeric() || char == '_'))
    {
        return Err(format!(
            "trigger '{name}' names unparseable table '{table}'"
        ));
    }
    let mut of_columns = BTreeSet::new();
    if let Some(of_list) = of_list {
        for column in of_list.split(',') {
            let column = column.trim().to_ascii_lowercase();
            if column.is_empty()
                || column.contains(|char: char| !(char.is_ascii_alphanumeric() || char == '_'))
            {
                return Err(format!(
                    "trigger '{name}' has unparseable UPDATE OF column '{column}'"
                ));
            }
            of_columns.insert(column);
        }
    }
    let begin = tail
        .find("BEGIN")
        .ok_or_else(|| format!("trigger '{name}' has no BEGIN: {tail}"))?;
    // Defense in depth: the counter is attributed by name, but the
    // trigger only watches anything if its body actually bumps that
    // counter's table. A right name with a non-bumping body (which the
    // governed byte-comparison would accept if it ever matched the
    // frozen DDL) must fail here, not count as coverage.
    let body = tail[begin..].to_ascii_uppercase();
    let bump = match counter {
        Counter::Broad => "UPDATE AUTHORIZATION_REVISION SET EPOCH",
        Counter::Grant => "UPDATE AUTHORIZATION_GRANT_REVISION SET EPOCH",
    };
    if !body.contains(bump) {
        return Err(format!(
            "trigger '{name}' body does not bump its {counter:?} counter table"
        ));
    }
    let head = tail[..begin].trim().to_owned();
    let predicate = if head.is_empty() {
        None
    } else if let Some(predicate) = head.strip_prefix("WHEN ") {
        Some(predicate.to_owned())
    } else {
        return Err(format!("trigger '{name}' has unrecognized head '{head}'"));
    };
    let when_columns = match predicate {
        Some(predicate) => when_columns(&strip_sqlite_literals(&predicate)?),
        None => BTreeSet::new(),
    };
    let table = table.to_ascii_lowercase();
    match kind {
        "insert" => Ok((counter, table, true, false, None)),
        "delete" => Ok((counter, table, false, true, None)),
        _ => {
            // Update trigger: a column is watched when it is in the
            // `UPDATE OF` list or the `WHEN` predicate. A full
            // `AFTER UPDATE ON t` with no `OF` list contributes only
            // its `WHEN` references — a change to an unlisted column
            // does not bump the counter, so it must not count.
            let mut watched = of_columns;
            for column in when_columns {
                watched.insert(column);
            }
            Ok((counter, table, false, false, Some(watched)))
        }
    }
}
/// Load per-counter coverage from the live schema. Only triggers in
/// the two counter families are considered; every other trigger
/// (FTS, append-only guards, …) is out of scope for this test.
fn load_coverage(conn: &Connection) -> Result<BTreeMap<Counter, CounterCoverage>, String> {
    let mut coverage: BTreeMap<Counter, CounterCoverage> = BTreeMap::new();
    let mut query = conn
        .prepare(
            "SELECT name, sql FROM sqlite_master WHERE type = 'trigger' \
             AND (name LIKE 'authorization\\_revision\\_%' ESCAPE '\\' \
               OR name LIKE 'authorization\\_grant\\_%' ESCAPE '\\') \
             ORDER BY name",
        )
        .map_err(|error| format!("cannot list live triggers: {error}"))?;
    let triggers: Vec<(String, Option<String>)> = query
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|error| format!("cannot read live triggers: {error}"))?
        .collect::<Result<_, _>>()
        .map_err(|error| format!("cannot read live triggers: {error}"))?;
    if triggers.is_empty() {
        return Err("no authorization triggers in live schema".to_owned());
    }
    for (name, sql) in &triggers {
        let sql = sql
            .as_deref()
            .ok_or_else(|| format!("trigger '{name}' has NULL sql"))?;
        let (counter, table, is_insert, is_delete, update_columns) = parse_auth_trigger(name, sql)?;
        let entry = coverage.entry(counter).or_default();
        if is_insert {
            entry.insert_tables.insert(table);
        } else if is_delete {
            entry.delete_tables.insert(table);
        } else {
            for column in update_columns.unwrap_or_default() {
                entry.update_columns.insert((table.clone(), column));
            }
        }
    }
    Ok(coverage)
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct Gap {
    table: String,
    /// Empty for the table-level insert/delete requirements.
    column: String,
    counter: Counter,
    gap: GapKind,
}

fn exemption_covers(exemption: &Exemption, gap: &Gap) -> bool {
    if exemption.table != gap.table {
        return false;
    }
    match (exemption.column, gap.column.as_str()) {
        // A column-specific entry never waives a table-level gap.
        (Some(_), "") => return false,
        (Some(entry_column), gap_column) if entry_column != gap_column => return false,
        _ => {}
    }
    if exemption
        .counter
        .is_some_and(|counter| counter != gap.counter)
    {
        return false;
    }
    exemption.gaps.is_empty() || exemption.gaps.contains(&gap.gap)
}

/// Evaluate every recorded main-schema read against both counters.
/// Returns `(uncovered_gaps, stale_exemptions)`. Reads from any other
/// schema (`temp` per-request state) are out of scope: the counters
/// watch durable engine tables only.
fn evaluate(
    reads: &[TableRead],
    coverage: &BTreeMap<Counter, CounterCoverage>,
) -> (Vec<Gap>, Vec<&'static str>) {
    let mut gaps = BTreeSet::new();
    let empty = CounterCoverage::default();
    for read in reads {
        if is_synthetic_scope(read) {
            continue;
        }
        for counter in Counter::all() {
            let counter_coverage = coverage.get(&counter).unwrap_or(&empty);
            if !counter_coverage.insert_tables.contains(&read.table) {
                gaps.insert(Gap {
                    table: read.table.clone(),
                    column: String::new(),
                    counter,
                    gap: GapKind::Insert,
                });
            }
            if !counter_coverage.delete_tables.contains(&read.table) {
                gaps.insert(Gap {
                    table: read.table.clone(),
                    column: String::new(),
                    counter,
                    gap: GapKind::Delete,
                });
            }
            if !read.column.is_empty()
                && !counter_coverage
                    .update_columns
                    .contains(&(read.table.clone(), read.column.clone()))
            {
                gaps.insert(Gap {
                    table: read.table.clone(),
                    column: read.column.clone(),
                    counter,
                    gap: GapKind::Update,
                });
            }
        }
    }
    let mut used = vec![false; EXEMPTIONS.len()];
    let mut uncovered = Vec::new();
    for gap in gaps {
        let mut waived = false;
        for (index, exemption) in EXEMPTIONS.iter().enumerate() {
            if exemption_covers(exemption, &gap) {
                used[index] = true;
                waived = true;
            }
        }
        if !waived {
            uncovered.push(gap);
        }
    }
    let stale = EXEMPTIONS
        .iter()
        .zip(used)
        .filter(|(_, used)| !used)
        .map(|(exemption, _)| exemption.reason)
        .collect();
    (uncovered, stale)
}

/// Safety net so the exemption list above can never mask a real hole:
/// the property the member fence actually relies on, per operation
/// across the UNION of counters. For every recorded main-schema
/// `(table, column)` pair and for EACH of insert, update(column) and
/// delete, AT LEAST ONE counter fires: the fence reads both counters
/// (§4.2), so a change is detected when the operation's counter moves.
/// `(records, id)` satisfies this split across counters (insert: broad;
/// update: grant; delete: both). Column-less population reads carry
/// only the insert/delete dimensions. Returns every
/// `(table, column, operation)` cell no counter covers.
///
/// One pair is unwatched by both counters but covered fence-side:
/// `(semantic_units, unit_id)` — `MemberCopyRegistry` folds the units state
/// into its workspace fence (see `UNITS_STATE_FENCE_COVERS_UNIT_ID` and the
/// `EXEMPTIONS` entry). The skip references that claim, so flipping it off
/// makes this function report the pair and the safety-net test fail.
fn unwatched_by_both(
    reads: &[TableRead],
    coverage: &BTreeMap<Counter, CounterCoverage>,
) -> Vec<(String, String, GapKind)> {
    let empty = CounterCoverage::default();
    let mut unwatched = BTreeSet::new();
    for read in reads {
        if is_synthetic_scope(read) {
            continue;
        }
        if read.table == "semantic_units"
            && read.column == "unit_id"
            && crate::member_copy_registry::UNITS_STATE_FENCE_COVERS_UNIT_ID
        {
            continue;
        }
        let fires = |gap: GapKind| {
            Counter::all().into_iter().any(|counter| {
                let counter_coverage = coverage.get(&counter).unwrap_or(&empty);
                match gap {
                    GapKind::Insert => counter_coverage.insert_tables.contains(&read.table),
                    GapKind::Delete => counter_coverage.delete_tables.contains(&read.table),
                    GapKind::Update => {
                        !read.column.is_empty()
                            && counter_coverage
                                .update_columns
                                .contains(&(read.table.clone(), read.column.clone()))
                    }
                }
            })
        };
        for gap in [GapKind::Insert, GapKind::Delete, GapKind::Update] {
            // A population read has no column to update-watch; its
            // table-level insert/delete cells are still union-checked.
            if gap == GapKind::Update && read.column.is_empty() {
                continue;
            }
            if !fires(gap) {
                unwatched.insert((read.table.clone(), read.column.clone(), gap));
            }
        }
    }
    unwatched.into_iter().collect()
}
/// Render the full recorded set with per-counter watch state, for the
/// failure message and the worker report.
fn render_report(
    reads: &[TableRead],
    coverage: &BTreeMap<Counter, CounterCoverage>,
    uncovered: &[Gap],
    stale: &[&str],
) -> String {
    let empty = CounterCoverage::default();
    let mut report = String::from("authorization trigger coverage\n");
    for read in reads {
        if is_synthetic_scope(read) {
            report.push_str(&format!(
                "  {}.{}.{} — synthetic/out of scope (temp state or json_each bind filter)\n",
                read.schema, read.table, read.column
            ));
            continue;
        }
        let mut cells = Vec::new();
        for counter in Counter::all() {
            let counter_coverage = coverage.get(&counter).unwrap_or(&empty);
            let update = read.column.is_empty()
                || counter_coverage
                    .update_columns
                    .contains(&(read.table.clone(), read.column.clone()));
            let cell = match (
                counter_coverage.insert_tables.contains(&read.table),
                counter_coverage.delete_tables.contains(&read.table),
                update,
            ) {
                (true, true, true) => "watched",
                (insert, delete, update) => &format!(
                    "MISSING{}{}{}",
                    if insert { "" } else { " insert" },
                    if delete { "" } else { " delete" },
                    if update { "" } else { " update" },
                ),
            };
            cells.push(format!("{counter:?}={cell}"));
        }
        let shown_column = if read.column.is_empty() {
            "(population read)"
        } else {
            &read.column
        };
        report.push_str(&format!(
            "  {}.{} — {}\n",
            read.table,
            shown_column,
            cells.join(" ")
        ));
    }
    if !uncovered.is_empty() {
        report.push_str("uncovered gaps:\n");
        for gap in uncovered {
            let column = if gap.column.is_empty() {
                "(table)".to_owned()
            } else {
                gap.column.clone()
            };
            report.push_str(&format!(
                "  {:?} {}.{} missing {:?}\n",
                gap.counter, gap.table, column, gap.gap
            ));
        }
    }
    if !stale.is_empty() {
        report.push_str("stale exemptions (match nothing):\n");
        for reason in stale {
            report.push_str(&format!("  {reason}\n"));
        }
    }
    report
}

/// Collect every authorization SQL text to prepare under the recording
/// authorizer: the rendered `auth_statement(...)` templates, the bulk
/// preload statements (same `const`s the production path executes),
/// and the governed view bodies.
async fn coverage_statements() -> (Vec<String>, Vec<String>, Vec<(String, String)>) {
    use crate::portable_sql::Dialect;
    let templates = crate::authorization::collect_authorization_templates_for_coverage().await;
    assert!(
        !templates.is_empty(),
        "auth template collector returned no statements"
    );
    let relations: BTreeSet<&'static str> = templates
        .iter()
        .map(|template| template.relation())
        .collect();
    for expected in [
        "records",
        "links",
        "semantic_units",
        "record_policies",
        "policy_entries",
        "bindings",
    ] {
        assert!(
            relations.contains(expected),
            "collector drives the {expected} read (got {relations:?})"
        );
    }
    let mut statements = BTreeSet::new();
    for template in &templates {
        let rendered = template
            .render(Dialect::Sqlite)
            .expect("auth template renders for SQLite");
        statements.insert(rendered.sql);
    }
    let views = crate::query::sql::authorization_view_coverage_selects();
    let bulk = crate::authorization::preloaded_bulk_coverage_statements();
    assert!(!bulk.is_empty(), "bulk preload path contributes statements");
    (statements.into_iter().collect(), bulk, views)
}
/// Prepare templates, bulk preload statements and view bodies on
/// `conn` under the recording authorizer and evaluate both counters.
/// `conn` must already carry the engine schema plus the minimal temp
/// stubs the view bodies reference.
fn run_checker(
    conn: &Connection,
    templates: &[String],
    bulk: &[String],
    views: &[(String, String)],
) -> (
    Vec<TableRead>,
    BTreeMap<Counter, CounterCoverage>,
    Vec<Gap>,
    Vec<&'static str>,
) {
    let mut statements = templates.to_vec();
    statements.extend(bulk.iter().cloned());
    for (_, select) in views {
        statements.push(select.clone());
    }
    let reads = record_reads(conn, &statements);
    assert!(!reads.is_empty(), "authorizer recorded no reads");
    let coverage = load_coverage(conn).expect("live authorization triggers parse");
    let (uncovered, stale) = evaluate(&reads, &coverage);
    (reads, coverage, uncovered, stale)
}

fn install_temp_stubs(conn: &Connection, views: &[(String, String)]) {
    // Per-request temp state the governed views read. Recorded under a
    // `temp` schema and excluded from counter enforcement by design:
    // the counters watch durable engine tables only.
    conn.execute_batch(
        "CREATE TEMP TABLE _query_sql_principal (\
           singleton INTEGER PRIMARY KEY, account_id TEXT, \
           trusted_local_bypass INTEGER, activity_read INTEGER, \
           is_member INTEGER, observed_at TEXT)",
    )
    .expect("temp principal stub");
    // Install every discovered authorization view in contract order, so
    // bodies that reference an earlier fence view (visible records
    // reads the subjects view) prepare. Bodies are prepared
    // individually under the recorder in `run_checker`, never executed
    // here.
    for (name, select) in views {
        conn.execute_batch(&format!("CREATE TEMP VIEW {name} AS {select}"))
            .unwrap_or_else(|error| panic!("fence view {name} installs: {error}"));
    }
}

#[tokio::test]
async fn authorization_trigger_coverage() {
    // Fresh engine database through the production path, so the
    // governed schema checks in `authorization_revision.rs` /
    // `authorization_grant.rs` have applied (§4.1 last paragraph): a
    // trigger dropped at runtime fails closed here, before the checker
    // even runs.
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().join("trigger-coverage.db");
    let db = crate::db::create_database(path.to_str().unwrap())
        .await
        .expect("fresh engine database");
    assert!(
        crate::authorization_revision::state_violations(&db)
            .await
            .expect("revision check runs")
            .is_empty(),
        "broad counter governed schema checks pass on the fresh database"
    );
    assert!(
        crate::authorization_grant::state_violations(&db)
            .await
            .expect("grant check runs")
            .is_empty(),
        "grant counter governed schema checks pass on the fresh database"
    );
    db.close().await;
    let conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("reopen engine database read-only");
    let (templates, bulk, views) = coverage_statements().await;
    install_temp_stubs(&conn, &views);
    let (reads, coverage, uncovered, stale) = run_checker(&conn, &templates, &bulk, &views);
    let report = render_report(&reads, &coverage, &uncovered, &stale);
    assert!(
        uncovered.is_empty(),
        "uncovered authorization reads:\n{report}"
    );
    assert!(stale.is_empty(), "stale exemptions:\n{report}");
    // Safety net: no exemption may leave a pair watched by neither
    // counter (except the hardcoded 766ede6 `unit_id` exception).
    let neither = unwatched_by_both(&reads, &coverage);
    assert!(
        neither.is_empty(),
        "reads watched by neither counter:\n{neither:?}\n{report}"
    );
}
/// F1 guard: the collector's driven-site list is hand-maintained, so
/// a source scan asserts every `auth_statement(` call site in
/// `src/authorization.rs` (the only file in the crate that calls it —
/// `auth_statement` is private to that module) is actually driven by
/// `collect_authorization_templates_for_coverage`. A new site nobody
/// adds to the collector fails here with instructions, instead of
/// silently escaping the checker. A new column appended to an existing
/// template needs no collector change: its SQL flows through the same
/// call, and the checker reports the column unless a trigger watches
/// it. Comment lines and the `fn` definition are not call sites.
#[tokio::test]
async fn collector_covers_every_auth_statement_site() {
    let source = include_str!("authorization.rs");
    let mut sites = 0;
    for line in source.lines() {
        if !line.contains("auth_statement(") {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("fn ") || trimmed.starts_with("//") {
            continue;
        }
        sites += 1;
    }
    let templates = crate::authorization::collect_authorization_templates_for_coverage().await;
    assert_eq!(
        sites,
        templates.len(),
        "auth_statement call-site count ({sites}) != collected templates ({}): \
         a new authorization read was added without driving it in \
         collect_authorization_templates_for_coverage; add the site there",
        templates.len()
    );
}
fn apply_ddl(conn: &Connection, mutate: impl Fn(&str) -> String) {
    for statement in crate::schema::DDL_STATEMENTS {
        let statement = mutate(statement);
        conn.execute_batch(&statement)
            .unwrap_or_else(|error| panic!("apply DDL: {statement}\n{error}"));
    }
}

/// Negative self-test: narrow one trigger's `UPDATE OF` list (and its
/// `WHEN` predicate) and assert the checker reports exactly that
/// column on exactly that counter.
#[test]
fn checker_detects_narrowed_update_trigger() {
    let conn = Connection::open_in_memory().expect("memory database");
    apply_ddl(&conn, |statement| {
        if statement.contains("authorization_revision_records_update") {
            let narrowed = statement
                .replace(
                    "owner_id, policy_anchor_id, deleted_at, type, kind",
                    "owner_id, policy_anchor_id, deleted_at, type",
                )
                .replace("OR OLD.kind IS NOT NEW.kind", "");
            assert!(!narrowed.contains("kind"), "narrowing removes kind");
            narrowed
        } else {
            statement.to_owned()
        }
    });
    // Minimal probe set: one statement reading `records.kind` (plus the
    // `id` lookup every authorization read performs). The grant counter
    // still watches `kind`, so only the broad gap may be reported.
    let reads = record_reads(
        &conn,
        &["SELECT kind FROM \"records\" WHERE id = ?1".to_owned()],
    );
    assert!(
        reads
            .iter()
            .any(|read| read.table == "records" && read.column == "kind"),
        "probe records (records, kind): {reads:?}"
    );
    let coverage = load_coverage(&conn).expect("narrowed triggers still parse");
    let (uncovered, _) = evaluate(&reads, &coverage);
    assert!(
        uncovered.iter().any(|gap| gap.table == "records"
            && gap.column == "kind"
            && gap.counter == Counter::Broad
            && gap.gap == GapKind::Update),
        "narrowed broad trigger reports (records, kind): {uncovered:?}"
    );
    assert!(
        !uncovered.iter().any(|gap| gap.table == "records"
            && gap.column == "kind"
            && gap.counter == Counter::Grant),
        "grant counter still watches (records, kind): {uncovered:?}"
    );
}

/// The safety net must fire on a pair no counter update-watches, while the
/// fence-covered `(semantic_units, unit_id)` pair stays silent because the
/// registry claims it (`UNITS_STATE_FENCE_COVERS_UNIT_ID`).
#[test]
fn safety_net_catches_pair_watched_by_neither_counter() {
    fn read(table: &str, column: &str) -> Vec<TableRead> {
        vec![TableRead {
            schema: "main".to_owned(),
            table: table.to_owned(),
            column: column.to_owned(),
        }]
    }
    // Split union coverage passes: insert+delete fire on broad, update
    // on grant — the `(records, id)` shape.
    let mut coverage = BTreeMap::new();
    coverage.insert(
        Counter::Broad,
        CounterCoverage {
            insert_tables: BTreeSet::from(["t".to_owned()]),
            delete_tables: BTreeSet::from(["t".to_owned()]),
            update_columns: BTreeSet::new(),
        },
    );
    coverage.insert(
        Counter::Grant,
        CounterCoverage {
            insert_tables: BTreeSet::new(),
            delete_tables: BTreeSet::new(),
            update_columns: BTreeSet::from([("t".to_owned(), "c".to_owned())]),
        },
    );
    assert!(unwatched_by_both(&read("t", "c"), &coverage).is_empty());
    // One operation missing on BOTH counters is reported with its
    // operation: drop the grant update and only Update is uncovered.
    coverage.insert(Counter::Grant, CounterCoverage::default());
    assert_eq!(
        unwatched_by_both(&read("t", "c"), &coverage),
        vec![("t".to_owned(), "c".to_owned(), GapKind::Update)]
    );
    // Nothing covered anywhere reports all three operations.
    assert_eq!(
        unwatched_by_both(&read("t", "c"), &BTreeMap::new()),
        vec![
            ("t".to_owned(), "c".to_owned(), GapKind::Insert),
            ("t".to_owned(), "c".to_owned(), GapKind::Delete),
            ("t".to_owned(), "c".to_owned(), GapKind::Update),
        ]
    );
    // The fence-covered `(semantic_units, unit_id)` pair stays silent. This is
    // non-vacuous: the skip in `unwatched_by_both` is gated on the registry's
    // coverage claim, so withdrawing it makes this assert report the pair.
    assert!(unwatched_by_both(&read("semantic_units", "unit_id"), &BTreeMap::new()).is_empty());
}

/// The trigger parser must reject shapes it does not understand rather
/// than silently covering nothing.
#[test]
fn trigger_parser_fails_loudly_on_unknown_shapes() {
    assert!(parse_auth_trigger(
        "authorization_revision_x",
        "CREATE TRIGGER authorization_revision_x AFTER UPDATE OF a ON t \
         BEGIN UPDATE authorization_revision SET epoch = epoch + 1 WHERE id = 1; END",
    )
    .is_ok());
    assert!(parse_auth_trigger(
        "authorization_revision_x",
        "CREATE TRIGGER authorization_revision_x INSTEAD OF INSERT ON v BEGIN SELECT 1; END",
    )
    .is_err());
    assert!(parse_auth_trigger(
        "records_fts_ai",
        "CREATE TRIGGER records_fts_ai AFTER INSERT ON records BEGIN SELECT 1; END"
    )
    .is_err());
    assert!(parse_auth_trigger(
        "authorization_grant_x",
        "CREATE TRIGGER authorization_grant_x AFTER UPDATE ON t WHEN OLD.a = 'it''s' \
         BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END",
    )
    .is_ok());
    // F2: a right name with a body that bumps nothing — or the other
    // counter's table — is rejected, not counted as coverage.
    assert!(parse_auth_trigger(
        "authorization_revision_x",
        "CREATE TRIGGER authorization_revision_x AFTER UPDATE OF a ON t BEGIN SELECT 1; END",
    )
    .is_err());
    assert!(parse_auth_trigger(
        "authorization_revision_x",
        "CREATE TRIGGER authorization_revision_x AFTER INSERT ON t \
         BEGIN UPDATE authorization_grant_revision SET epoch = epoch + 1 WHERE id = 1; END",
    )
    .is_err());
    // F5: `RENEW.id` and `xOLD.y` need a left word boundary; only the
    // true `OLD.a` / `NEW.a` references count.
    assert_eq!(
        when_columns("OLD.a IS NOT NEW.a OR RENEW.b = 1 OR xOLD.y = 2"),
        BTreeSet::from(["a".to_owned()]),
    );
}
