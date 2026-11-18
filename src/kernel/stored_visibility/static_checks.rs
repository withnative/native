//! Static enforcement of the marking contract over the production source
//! (73ad275 M3, M5, M6): no REPLACE on any input, every trigger-suppression
//! or input-rebuild site registered with its handling, and every non-trigger
//! accelerator read qualified with `main.`.
//!
//! The scan reads every `.rs` file under `src/`, drops test-only files and
//! `#[cfg(test)]`-gated items, and inspects the string literals that remain.
//! It is deliberately over-inclusive: a false positive costs a registry entry
//! with a reason; a false negative would cost a missed mark.

use crate::db::writer_contract::MARKED_INPUT_TABLES;
use std::path::{Path, PathBuf};

struct Source {
    path: String,
    /// Production text: test-only items blanked out.
    text: String,
}

fn is_test_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    path.components().any(|c| c.as_os_str() == "tests")
        || name == "tests.rs"
        || name.ends_with("_tests.rs")
        || name.ends_with("_test.rs")
        || name.ends_with("_spike.rs")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The directory holding `file`'s child modules.
fn module_dir(file: &Path) -> PathBuf {
    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let parent = file.parent().unwrap();
    if matches!(stem, "mod" | "lib" | "main") {
        parent.to_path_buf()
    } else {
        parent.join(stem)
    }
}

fn sources() -> &'static [Source] {
    static SOURCES: std::sync::OnceLock<Vec<Source>> = std::sync::OnceLock::new();
    SOURCES.get_or_init(|| load_sources(&["src"]))
}

/// The root crate plus the held hosting, runtime and workbench crates, for
/// checks whose subject (database egress) lives on both sides.
fn workspace_sources() -> &'static [Source] {
    static SOURCES: std::sync::OnceLock<Vec<Source>> = std::sync::OnceLock::new();
    SOURCES.get_or_init(|| {
        load_sources(&[
            "src",
            "held/hosting/src",
            "held/runtime/src",
            "held/workbench/src",
        ])
    })
}

fn load_sources(roots: &[&str]) -> Vec<Source> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    for dir in roots {
        let dir = root.join(dir);
        if dir.is_dir() {
            walk(&dir, &mut files);
        }
    }
    files.sort();
    let mut texts = std::collections::BTreeMap::new();
    let mut test_modules = std::collections::BTreeSet::new();
    for path in &files {
        let raw = std::fs::read_to_string(path).unwrap();
        let (text, gated) = strip_test_items(&raw);
        for module in gated {
            let dir = module_dir(path);
            test_modules.insert(dir.join(format!("{module}.rs")));
            test_modules.insert(dir.join(&module).join("mod.rs"));
        }
        texts.insert(path.clone(), text);
    }
    // A file is test-only if its own name says so or if a `cfg(test)`
    // module declaration (transitively) includes it.
    let excluded = |path: &Path| {
        is_test_file(path)
            || path
                .ancestors()
                .any(|a| test_modules.contains(a) || test_modules.contains(&a.with_extension("rs")))
    };
    texts
        .into_iter()
        .filter(|(path, _)| !excluded(path))
        .map(|(path, text)| Source {
            path: path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/"),
            text,
        })
        .collect()
}

/// One lexical token class the scanner cares about.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    Code,
    Comment,
    Literal,
}

/// Classify every byte of Rust source as code, comment or string literal
/// content. Handles nested block comments, escapes, raw strings, byte
/// strings, char literals and lifetimes.
fn classify(src: &str) -> Vec<Class> {
    let b = src.as_bytes();
    let mut class = vec![Class::Code; b.len()];
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < b.len() && b[i] != b'\n' {
                    class[i] = Class::Comment;
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 0;
                while i < b.len() {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        class[i] = Class::Comment;
                        class[i + 1] = Class::Comment;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        class[i] = Class::Comment;
                        class[i + 1] = Class::Comment;
                        i += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        class[i] = Class::Comment;
                        i += 1;
                    }
                }
            }
            b'r' | b'b'
                if {
                    // Raw (byte) string: r"…", r#"…"#, br"…".
                    let mut j = i + 1;
                    if b[i] == b'b' && b.get(j) == Some(&b'r') {
                        j += 1;
                    }
                    (b[i] == b'r' || b.get(i + 1) == Some(&b'r'))
                        && (i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_'))
                        && {
                            while b.get(j) == Some(&b'#') {
                                j += 1;
                            }
                            b.get(j) == Some(&b'"')
                        }
                } =>
            {
                let mut j = i + 1;
                if b[i] == b'b' {
                    j += 1;
                }
                let mut hashes = 0;
                while b[j] == b'#' {
                    hashes += 1;
                    j += 1;
                }
                j += 1; // opening quote
                let start = j;
                let closing: Vec<u8> = std::iter::once(b'"')
                    .chain(std::iter::repeat_n(b'#', hashes))
                    .collect();
                while j < b.len() && !b[j..].starts_with(&closing) {
                    j += 1;
                }
                for c in &mut class[start..j] {
                    *c = Class::Literal;
                }
                i = j + closing.len();
            }
            b'"' => {
                let mut j = i + 1;
                while j < b.len() && b[j] != b'"' {
                    if b[j] == b'\\' {
                        class[j] = Class::Literal;
                        j += 1;
                    }
                    if j < b.len() {
                        class[j] = Class::Literal;
                    }
                    j += 1;
                }
                i = j + 1;
            }
            b'\'' => {
                // Char literal ('x', '\n', '\u{..}', '"') or a lifetime.
                if b.get(i + 1) == Some(&b'\\') {
                    let mut j = i + 2;
                    while j < b.len() && b[j] != b'\'' {
                        j += 1;
                    }
                    i = j + 1;
                } else {
                    let next = src[i + 1..].chars().next().map_or(1, char::len_utf8);
                    if b.get(i + 1 + next) == Some(&b'\'') {
                        i += 2 + next;
                    } else {
                        i += 1;
                    }
                }
            }
            _ => i += 1,
        }
    }
    class
}

/// Blank every item gated on `cfg(test)` (or `cfg(all(test, …))`), keeping
/// byte offsets and line numbers. Also returns the names of gated
/// out-of-line `mod name;` declarations, whose files are test-only.
fn strip_test_items(src: &str) -> (String, Vec<String>) {
    let mut gated_modules = Vec::new();
    let class = classify(src);
    let b = src.as_bytes();
    let mut out = b.to_vec();
    let mut i = 0;
    while let Some(found) = src[i..].find("#[cfg(") {
        let at = i + found;
        i = at + 1;
        if class[at] != Class::Code {
            continue;
        }
        let close = at + src[at..].find(']').unwrap();
        let attr = &src[at..=close];
        let gated = attr == "#[cfg(test)]" || attr.starts_with("#[cfg(all(test,");
        if !gated {
            continue;
        }
        // The item ends at its first top-level `;` or its matching `}`.
        let mut j = close + 1;
        let mut depth = 0i32;
        let mut end = None;
        while j < b.len() {
            if class[j] == Class::Code {
                match b[j] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = Some(j);
                            break;
                        }
                    }
                    b';' if depth == 0 => {
                        end = Some(j);
                        break;
                    }
                    _ => {}
                }
            }
            j += 1;
        }
        let end = end.unwrap_or(b.len() - 1);
        if b[end] == b';' {
            let item = src[close + 1..end].split_whitespace().collect::<Vec<_>>();
            if let [.., "mod", name] = item.as_slice() {
                gated_modules.push((*name).to_owned());
            }
        }
        for byte in &mut out[at..=end] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
        i = end + 1;
    }
    (String::from_utf8(out).unwrap(), gated_modules)
}

/// `(line, text)` of every string literal in production text.
fn literals(text: &str) -> Vec<(usize, String)> {
    let class = classify(text);
    let mut out = Vec::new();
    let mut i = 0;
    while i < class.len() {
        if class[i] == Class::Literal {
            let start = i;
            while i < class.len() && class[i] == Class::Literal {
                i += 1;
            }
            let line = text[..start].matches('\n').count() + 1;
            out.push((line, text[start..i].to_owned()));
        } else {
            i += 1;
        }
    }
    out
}

/// Upper-cased SQL words of a literal, with identifier quoting and schema
/// qualification normalised away (`"main"."kernel_records"` → KERNEL_RECORDS).
fn sql_words(literal: &str) -> Vec<String> {
    literal
        .replace("\\\"", "")
        .replace(['"', '`', '[', ']'], "")
        .split(|c: char| {
            !(c.is_ascii_alphanumeric() || c == '_' || c == '{' || c == '}' || c == '.')
        })
        .filter(|w| !w.is_empty())
        .map(|w| {
            let w = w.to_ascii_uppercase();
            w.strip_prefix("MAIN.").map(str::to_owned).unwrap_or(w)
        })
        .collect()
}

fn is_input(word: &str) -> bool {
    MARKED_INPUT_TABLES
        .iter()
        .any(|t| t.eq_ignore_ascii_case(word))
}

/// M3: REPLACE never targets an input, in statements or in table DDL.
fn is_replace_input(word: &str) -> bool {
    is_input(word) || word.eq_ignore_ascii_case("kernel_mcp_write_receipts")
}
fn replace_violations(literal: &str) -> Vec<String> {
    let words = sql_words(literal);
    let mut found = Vec::new();
    for (i, w) in words.iter().enumerate() {
        if w != "REPLACE" {
            continue;
        }
        let rest = &words[i + 1..];
        let target = match rest {
            [into, t, ..] if into == "INTO" => Some(t),
            [t, ..]
                if i > 0
                    && words[i - 1] == "OR"
                    && words.get(i.wrapping_sub(2)).is_some_and(|u| u == "UPDATE") =>
            {
                Some(t)
            }
            _ => None,
        };
        if let Some(t) = target {
            if is_replace_input(t) || t.starts_with('{') {
                found.push(format!("REPLACE targets {t}"));
            }
        }
    }
    let creates_input = words
        .windows(3)
        .any(|w| w[0] == "CREATE" && w[1] == "TABLE" && is_replace_input(&w[2]))
        || words.windows(6).any(|w| {
            w[0] == "CREATE"
                && w[1] == "TABLE"
                && w[2] == "IF"
                && w[3] == "NOT"
                && w[4] == "EXISTS"
                && is_replace_input(&w[5])
        });
    if creates_input
        && words
            .windows(2)
            .any(|w| w[0] == "CONFLICT" && w[1] == "REPLACE")
    {
        found.push("input table DDL declares ON CONFLICT REPLACE".into());
    }
    found
}

#[test]
fn scanner_understands_rust_lexing() {
    let src = "fn a() { let s = \"REPLACE INTO kernel_records\"; } // \"comment\"\n#[cfg(test)]\nmod t { fn x() { let _ = \"INSERT OR REPLACE INTO kernel_roots\"; let _ = '}'; } }\nconst R: &str = r#\"UPDATE OR REPLACE \"main\".\"content_events\" SET\"#; fn l<'a>(x: &'a str) {}";
    let (stripped, gated) = strip_test_items(src);
    assert!(gated.is_empty());
    assert_eq!(
        strip_test_items("#[cfg(test)]\nmod helpers;\nfn x() {}").1,
        vec!["helpers".to_owned()]
    );
    let found: Vec<String> = literals(&stripped)
        .into_iter()
        .flat_map(|(_, l)| replace_violations(&l))
        .collect();
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(!stripped.contains("kernel_roots"));
    assert!(
        replace_violations(
            "CREATE TABLE kernel_lifecycle (record_id TEXT PRIMARY KEY ON CONFLICT REPLACE)"
        )
        .len()
            == 1
    );
    assert!(
        replace_violations("INSERT OR REPLACE INTO kernel_sql_record_projection VALUES(1)")
            .is_empty()
    );
    assert!(replace_violations("SELECT replace(name, 'a', 'b') FROM kernel_records").is_empty());
    assert!(!replace_violations("INSERT OR REPLACE INTO {table} VALUES(1)").is_empty());
}

/// M3. None exists today (rev 2 E.2); this keeps it that way.
#[test]
fn no_production_sql_replaces_into_an_input_table() {
    let mut violations = Vec::new();
    for source in sources() {
        for (line, literal) in literals(&source.text) {
            for v in replace_violations(&literal) {
                violations.push(format!("{}:{line}: {v}", source.path));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "REPLACE on a marked input misses the evicted key with recursive_triggers off (73ad275 M3, E8); use an upsert:\n{}",
        violations.join("\n")
    );
}

/// How a registered site keeps stored visibility correct (M6).
#[derive(Debug)]
enum Handling {
    /// It invalidates in the same transaction; `call` must appear in the file.
    Invalidates { call: &'static str },
    /// It never runs on a file that can carry marking objects.
    NeverMarked,
}

/// What a site does that triggers cannot see.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Pattern {
    /// `SQLITE_DBCONFIG_ENABLE_TRIGGER` set to false.
    TriggersSuppressed,
    /// `DROP TRIGGER` of a marking trigger.
    DropsMarkingTrigger,
    /// An input table renamed or dropped: its triggers go with it.
    RebuildsInput,
}

struct Site {
    file: &'static str,
    pattern: Pattern,
    count: usize,
    handling: Handling,
    reason: &'static str,
}

/// Every production site that suppresses triggers or removes them from an
/// input. A new site fails the test until it is registered with handling.
const REGISTRY: &[Site] = &[
    Site {
        file: "src/kernel/working_undo.rs",
        pattern: Pattern::TriggersSuppressed,
        count: 1,
        handling: Handling::Invalidates { call: "stored_visibility::invalidate_all_raw" },
        reason: "the undo inverse writes kernel inputs with triggers off, then invalidates in the inverse savepoint",
    },
    Site {
        file: "src/fork/rebase.rs",
        pattern: Pattern::TriggersSuppressed,
        count: 1,
        handling: Handling::NeverMarked,
        reason: "rebase replays the opt-in v1 node working copy; marking objects exist only in kernel v2 files (install_on refuses others)",
    },
    Site {
        file: "src/migrations.rs",
        pattern: Pattern::RebuildsInput,
        count: 1,
        handling: Handling::NeverMarked,
        reason: "the engine 45→46 content_events rebuild runs only on files far older than the marking engine floor",
    },
];

fn pattern_hits(source: &Source) -> Vec<(Pattern, usize)> {
    let mut hits = Vec::new();
    let class = classify(&source.text);
    // Code: set_db_config(…ENABLE_TRIGGER, false) or sqlite3_db_config(…, 0).
    for (at, _) in source.text.match_indices("SQLITE_DBCONFIG_ENABLE_TRIGGER") {
        if class[at] != Class::Code {
            continue;
        }
        let tail: String = source.text[at..].chars().take(80).collect();
        let args = tail.split_once(')').map_or(tail.as_str(), |(a, _)| a);
        if args.contains("false") || args.contains(", 0") {
            hits.push((
                Pattern::TriggersSuppressed,
                source.text[..at].matches('\n').count() + 1,
            ));
        }
    }
    for (line, literal) in literals(&source.text) {
        let words = sql_words(&literal);
        for (i, w) in words.iter().enumerate() {
            if w == "DROP" && words.get(i + 1).is_some_and(|t| t == "TRIGGER") {
                let target = words[i + 2..]
                    .iter()
                    .find(|t| !matches!(t.as_str(), "IF" | "EXISTS"));
                // `drop_on` drops by queried name, never by literal.
                if target.is_some_and(|t| t.starts_with("P_")) {
                    hits.push((Pattern::DropsMarkingTrigger, line));
                }
            }
            if w == "DROP" && words.get(i + 1).is_some_and(|t| t == "TABLE") {
                let target = words[i + 2..]
                    .iter()
                    .find(|t| !matches!(t.as_str(), "IF" | "EXISTS"));
                if target.is_some_and(|t| is_input(t)) {
                    hits.push((Pattern::RebuildsInput, line));
                }
            }
            if w == "ALTER"
                && words.get(i + 1).is_some_and(|t| t == "TABLE")
                && words.get(i + 2).is_some_and(|t| is_input(t))
                && words.get(i + 3).is_some_and(|t| t == "RENAME")
                && words.get(i + 4).is_some_and(|t| t == "TO")
            {
                hits.push((Pattern::RebuildsInput, line));
            }
        }
    }
    hits
}

/// M6: every site is registered, counts match, and invalidating sites
/// actually contain their invalidation call.
#[test]
fn trigger_suppression_and_input_rebuild_sites_are_registered() {
    let mut problems = Vec::new();
    let mut seen = std::collections::BTreeMap::<(String, Pattern), Vec<usize>>::new();
    for source in sources() {
        for (pattern, line) in pattern_hits(source) {
            seen.entry((source.path.clone(), pattern))
                .or_default()
                .push(line);
        }
    }
    for ((file, pattern), lines) in &seen {
        match REGISTRY.iter().find(|s| s.file == file && s.pattern == *pattern) {
            None => problems.push(format!(
                "{file} lines {lines:?}: unregistered {pattern:?}; it must mark its keys or call stored_visibility::invalidate_all_on in the same transaction, then be registered"
            )),
            Some(site) if site.count != lines.len() => problems.push(format!(
                "{file}: {pattern:?} registered {} times, found {} at {lines:?}",
                site.count,
                lines.len()
            )),
            Some(_) => {}
        }
    }
    for site in REGISTRY {
        assert!(!site.reason.is_empty());
        if !seen.contains_key(&(site.file.to_owned(), site.pattern)) {
            problems.push(format!(
                "{}: stale {:?} registration",
                site.file, site.pattern
            ));
        }
        if let Handling::Invalidates { call } = site.handling {
            let text = sources()
                .iter()
                .find(|s| s.path == site.file)
                .map(|s| s.text.as_str());
            if !text.is_some_and(|t| t.contains(call)) {
                problems.push(format!(
                    "{}: registered as invalidating but never calls {call}",
                    site.file
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// M5: outside trigger bodies and DDL, every reference to an accelerator
/// table is qualified with `main.`, so a TEMP shadow can never answer.
#[test]
fn accelerator_reads_are_main_qualified() {
    let mut problems = Vec::new();
    for source in sources() {
        for (line, literal) in literals(&source.text) {
            let trimmed = literal.trim_start();
            // DDL and the trigger WHEN guard cannot be qualified.
            if trimmed.starts_with("CREATE TABLE p_")
                || trimmed.starts_with("CREATE INDEX p_")
                || trimmed.starts_with("CREATE TRIGGER p_")
                || literal == super::ENABLED_GUARD
            {
                continue;
            }
            for table in super::TABLES {
                for (at, _) in literal.match_indices(table) {
                    let before = &literal[..at];
                    let boundary_after = literal[at + table.len()..]
                        .chars()
                        .next()
                        .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
                    let boundary_before = before
                        .chars()
                        .last()
                        .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'));
                    if boundary_after && boundary_before && !before.ends_with("main.") {
                        // A bare table name used as a bound value or label is fine.
                        if literal.trim() == table {
                            continue;
                        }
                        problems.push(format!(
                            "{}:{line}: unqualified {table} in {literal:?}",
                            source.path
                        ));
                    }
                }
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// Files allowed to install a SQLite authorizer directly. Writer connections
/// hold the writer contract's lease guard (M4); SQLite keeps one authorizer
/// per connection, so anything installed directly on a writer would silently
/// replace it. Everything below runs on its own validator or member-copy
/// connection, never a pooled writer; writer-side policies compose through
/// `db::writer_contract::set_authorizer`.
const DIRECT_AUTHORIZERS: &[(&str, &str)] = &[
    (
        "src/db/writer_contract.rs",
        "the lease guard itself and the composing setter",
    ),
    (
        "src/query/sql.rs",
        "thread-local in-memory query validators",
    ),
    (
        "src/query/sql/named_views.rs",
        "named-view validator worker connections",
    ),
    (
        "src/query/sql/view_validation.rs",
        "named-view validator worker connections",
    ),
    (
        "src/member_copy_kernel_v2/profile/query.rs",
        "member-copy file connections, not workspace writers",
    ),
    (
        "src/member_copy_kernel_v2/profile/metadata_performance_proof.rs",
        "member-copy destination connections in the metadata proof",
    ),
];

#[test]
fn writer_authorizers_compose_through_the_contract() {
    let mut problems = Vec::new();
    for source in sources() {
        let class = classify(&source.text);
        let direct = ["sqlite3_set_authorizer(", ".authorizer("]
            .iter()
            .flat_map(|needle| source.text.match_indices(needle))
            .filter(|(at, _)| class[*at] == Class::Code)
            .count();
        if direct > 0
            && !DIRECT_AUTHORIZERS
                .iter()
                .any(|(file, _)| *file == source.path)
        {
            problems.push(format!(
                "{}: installs a SQLite authorizer directly ({direct} site(s)); on a writer connection use db::writer_contract::set_authorizer so the lease guard stays in front, or register a non-writer connection here",
                source.path
            ));
        }
    }
    for (file, reason) in DIRECT_AUTHORIZERS {
        assert!(!reason.is_empty());
        if !sources().iter().any(|s| s.path == *file) {
            problems.push(format!("{file}: stale authorizer registration"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

/// How an inventoried database-copy site treats local accelerators.
#[derive(Debug)]
enum Copy {
    /// The copy leaves this process (export, standby FULL, backup, bundle
    /// upload): the file must call the egress strip.
    Egress,
    /// The copy stays private (scratch, verification, speculative fork,
    /// receiver-local generation, inbound staging) or its source can never
    /// be a marked kernel v2 file. Stripping it would be wrong or pointless.
    Private,
    /// A shared helper whose callers are inventoried individually.
    Helper,
}

/// Every production site that copies a SQLite database file (plan 5b21bd7,
/// slice 2a). A new site fails the test until it is classified.
const COPY_SITES: &[(&str, usize, Copy, &str)] = &[
    (
        "src/export.rs",
        1,
        Copy::Egress,
        "export_connection_snapshot: every Export (user download, MCP and binary standby FULL, tenant backup, eject, local stdio) strips before any digest or manifest",
    ),
    (
        "held/hosting/src/operator.rs",
        2,
        Copy::Egress,
        "snapshot_at fleet capture strips each workspace copy before its digest is pinned; the second site copies catalog.db, never a workspace file",
    ),
    (
        "held/hosting/src/hosting/v2_preparation.rs",
        1,
        Copy::Egress,
        "index-preparation preimage uploaded to the backup store as a recovery image",
    ),
    (
        "held/hosting/src/hosting/backup.rs",
        1,
        Copy::Helper,
        "vacuum_snapshot_read_only and the catalog backup (catalog.db); workspace callers are classified individually",
    ),
    (
        "held/hosting/src/hosting/history_verification.rs",
        1,
        Copy::Private,
        "private conformance copy of a managed v1 database, read locally and deleted",
    ),
    (
        "held/hosting/src/hosting/v2_provision.rs",
        1,
        Copy::Private,
        "inbound: a freshly imported scratch file becoming the live primary, never an export",
    ),
    (
        "src/fork.rs",
        1,
        Copy::Private,
        "speculative local fork that runs writes; its triggers must stay so its own marks stay correct",
    ),
    (
        "src/migrations.rs",
        1,
        Copy::Private,
        "capture_preimage runs only for v1 engine migration; probe_database refuses kernel v2 files before it",
    ),
    (
        "src/standby/generation_store.rs",
        1,
        Copy::Private,
        "receiver-side verification and delta scratch of a generation received from the primary, which is already stripped",
    ),
    (
        "src/mcp/kernel_v2/sql_event_bench.rs",
        1,
        Copy::Private,
        "benchmark module included only from a test module via #[path]",
    ),
];

const STRIP_CALL: &str = "strip_marking_from_snapshot(";

/// Code or literal occurrences that make a database file copy.
fn copy_sites(source: &Source) -> usize {
    let class = classify(&source.text);
    let literal_vacuum = literals(&source.text)
        .iter()
        .filter(|(_, literal)| literal.to_ascii_uppercase().contains("VACUUM INTO"))
        .count();
    let code_calls = [
        "vacuum_snapshot_read_only(",
        "sqlite3_backup_init(",
        ".backup(\"",
    ]
    .iter()
    .flat_map(|needle| source.text.match_indices(needle))
    .filter(|(at, _)| class[*at] == Class::Code)
    .filter(|(at, _)| !source.text[..*at].trim_end().ends_with("fn"))
    .count();
    literal_vacuum + code_calls
}

/// Slice 2a: no database copy leaves this process carrying local
/// accelerators. Each copy site is classified; egress sites call the strip.
#[test]
fn every_database_copy_site_is_classified_and_egress_strips() {
    let mut problems = Vec::new();
    let mut seen = std::collections::BTreeMap::new();
    for source in workspace_sources() {
        let count = copy_sites(source);
        if count > 0 {
            seen.insert(source.path.clone(), count);
        }
    }
    for (path, count) in &seen {
        match COPY_SITES.iter().find(|(file, ..)| file == path) {
            None => problems.push(format!(
                "{path}: {count} unclassified database copy site(s)"
            )),
            Some((_, expected, ..)) if expected != count => problems.push(format!(
                "{path}: classified {expected} copy site(s), found {count}"
            )),
            Some((_, _, Copy::Egress, _)) => {
                let text = &workspace_sources()
                    .iter()
                    .find(|s| &s.path == path)
                    .unwrap()
                    .text;
                if !text.contains(STRIP_CALL) {
                    problems.push(format!("{path}: egress copy without {STRIP_CALL}"));
                }
            }
            Some(_) => {}
        }
    }
    for (file, _, _, reason) in COPY_SITES {
        assert!(!reason.is_empty(), "{file}");
        if !seen.contains_key(*file) {
            problems.push(format!("{file}: stale copy-site registration"));
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

#[test]
fn copy_scanner_counts_copies_and_ignores_definitions_and_comments() {
    let source = Source {
        path: "x.rs".into(),
        text: "pub async fn vacuum_snapshot_read_only(a: &P) {}\n// VACUUM INTO in a comment\nfn f() { let _ = \"VACUUM INTO ?\"; vacuum_snapshot_read_only(a, b); }".into(),
    };
    assert_eq!(copy_sites(&source), 2);
}

/// Every privileged receipt refusal/exclusion must also protect terminal facts.
#[test]
fn original_settlement_event_guard_and_exclusion_census() {
    let mut guards = 0;
    let mut exclusions = 0;
    for source in sources() {
        if source.path.ends_with("src/store.rs")
            || source.path.ends_with("src/domain_transaction.rs")
        {
            // Inspect raw decoder too: test-item stripping removes its cfg arm.
            let raw =
                std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(&source.path))
                    .unwrap();
            for suffix in raw
                .split("\"kernel.mcp_write_receipt_recorded.v1\"")
                .skip(1)
            {
                assert!(
                    suffix
                        .trim_start()
                        .starts_with("| \"kernel.mcp_write_fenced.v1\""),
                    "{}: privileged receipt guard/decoder missing terminal counterpart",
                    source.path
                );
                guards += 1;
            }
        }
        for (line, literal) in literals(&source.text) {
            if literal.contains("kernel.mcp_write_receipt_recorded.v1")
                && (literal.contains("NOT IN")
                    || literal.contains("'kernel.identity_binding_added.v1'"))
            {
                assert!(
                    literal.contains("kernel.mcp_write_fenced.v1"),
                    "{}:{line}: private receipt exclusion missing fence",
                    source.path
                );
                exclusions += 1;
            }
        }
    }
    assert!(
        guards >= 7,
        "all three store and four domain guards/decoder must be inspected, got {guards}"
    );
    assert!(
        exclusions >= 4,
        "both SQL constants, history and kernel history must be inspected"
    );
    let classes = include_str!("../access_fence.rs");
    assert!(classes.contains("(\"mcp_write_fenced\", NoEffect)"));
    assert!(
        !replace_violations("INSERT OR REPLACE INTO kernel_mcp_write_receipts VALUES(1)")
            .is_empty()
    );
}

#[test]
fn original_settlement_receipt_writer_and_guarded_batch_census() {
    let expected = std::collections::BTreeMap::from([
        ("src/mcp/kernel_v2/merge_body.rs", 1),
        ("src/mcp/kernel_v2/record_images.rs", 1),
        ("src/mcp/kernel_v2/suggestions.rs", 1),
        ("src/mcp/kernel_v2/writes.rs", 2),
        ("src/mcp/kernel_v2/writes/batch.rs", 1),
        ("src/mcp/kernel_v2/writes/create_many.rs", 1),
        ("src/mcp/kernel_v2/writes/named_views.rs", 2),
        ("src/mcp/kernel_v2/writes/url_attachment.rs", 2),
    ]);
    let actual = sources()
        .iter()
        .filter_map(|source| {
            let count = source
                .text
                .matches("mcp_write_receipts::record_on(")
                .count();
            if count == 0 {
                return None;
            }
            assert!(
                source.text.contains("fences::refuse_key_on("),
                "{} has receipts without early namespace admission",
                source.path
            );
            Some((source.path.as_str(), count))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        actual, expected,
        "review every new writer/namespace, not only its receipt count"
    );
    let batch = &sources()
        .iter()
        .find(|s| s.path == "src/mcp/kernel_v2/writes/batch.rs")
        .unwrap()
        .text;
    let begin = batch.find("KernelTransaction::begin").unwrap();
    let parts = batch.find("transaction.parts()").unwrap();
    let principal = batch.find("super::super::principal_on").unwrap();
    let fence = batch.find("::refuse_key_on(").unwrap();
    assert!(begin < parts && parts < principal && principal < fence);
    for step in [
        "admit_dispatched_on(",
        "sqlx::query(RECEIPTS)",
        "SELECT request_json,receipt_json",
        "source_basis::resolve_on(",
        "start_app_action_in(",
        "update_with_context(",
        "mutate_link(",
        "archive(db,",
        "mcp_write_receipts::record_on(",
    ] {
        assert!(
            fence < batch.find(step).unwrap(),
            "batch must fence before {step}"
        );
    }
    for body in ["body_set", "body_append", "body_replace"] {
        assert!(
            batch.contains(body),
            "new guarded body family missing from census"
        );
    }
    assert!(
        !batch.contains("create_record("),
        "batch record creation needs explicit retirement review"
    );
}
