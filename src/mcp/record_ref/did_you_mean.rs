//! "Did you mean" hints for refusals that name a record which is not there.
//!
//! Agents writing links and sources sometimes pass ids that do not exist: a
//! one- or two-character slip in a full UUID, the right first eight characters
//! spliced onto another record's tail, or a short token lifted from a record's
//! *name*. Prefix resolution cannot help (a full 36-character id that misses is
//! not an abbreviation), and silently re-pointing the id would be wrong — two
//! of the observed splices would have resolved to the wrong record. So the
//! refusal stays a refusal and merely *names* the likely real records, which
//! makes the retry one cheap step.
//!
//! Three rules keep this safe to leave on:
//!
//! 1. **Never resolve.** The hint is appended to the handler's own refusal; it
//!    never changes whether a call succeeds, and the refusal text itself is
//!    never replaced. A name match is a suggestion only.
//! 2. **No oracle.** Every candidate passes the visibility check resolution
//!    uses — not an attribution record, and `View` for the caller. A record the
//!    caller cannot see is never named, so "nothing visible matched" yields no
//!    hint and the text is byte-identical to a build without this module. An
//!    id that exists but is invisible is treated exactly like one that does not
//!    exist.
//! 3. **A failed lookup is no failure.** Any error while building the hint
//!    returns the original refusal unchanged.
//!
//! Hints are a write-path aid: the registry asks for them only on calls it
//! classifies as mutations. A read refusal stays bare, which also keeps a
//! hosted read and the same read served from a member copy (whose slice has no
//! policy tables to compute a hint from) returning identical text.
//!
//! The success path pays one in-memory walk of the arguments (to remember the
//! id-keyed strings, since the handler consumes them) and no database work.

use std::collections::HashSet;

use serde_json::Value;

use super::{
    is_canonical_uuid, prefix_candidates_with, record_is_live_with, record_ref_rows,
    record_ref_statement, walk_with_path, MIN_PREFIX_HEX,
};
use crate::authorization::Capability;
use crate::mcp::registry::{Caller, EngineHandle};
use crate::portable_sql::{
    BindValue, BorrowedSqliteStatementExecutor, ColumnSpec, DomainStatementExecutor, LogicalType,
    NormalizedValue,
};
use crate::{Error, Result};

/// Most candidates named for one bad value.
const MAX_SUGGESTIONS: usize = 3;
/// Most distinct bad values a single refusal gets hints for.
const MAX_HINTED_VALUES: usize = 8;
/// Id-keyed strings remembered per call. Bounds the success path's memory.
const MAX_REMEMBERED: usize = 32;
/// Longer strings are not plausibly ids or tokens; skip them.
const MAX_VALUE_BYTES: usize = 128;
/// Rows fetched by the name query before the visibility filter.
const NAME_SCAN_LIMIT: i64 = 16;
/// Name matching is for short tokens only. Below the floor it matches
/// everything; above the ceiling it is a sentence or a UUID, not a token.
const MIN_TOKEN: usize = MIN_PREFIX_HEX;
const MAX_TOKEN: usize = 24;
const MAX_NAME_CHARS: usize = 60;

/// One id-keyed argument string and where the caller wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecordIdArgument {
    pub(crate) path: String,
    pub(crate) value: String,
}

/// Remember every record-id-keyed string in `arguments`, post-resolution.
///
/// Uses the resolver's own [`walk_with_path`], so the keys, the top-level `id`
/// gating and the principal-`target_id` exclusion are exactly the resolver's.
pub(crate) fn record_id_arguments(arguments: &mut Value, tool: &str) -> Vec<RecordIdArgument> {
    let mut found = Vec::new();
    walk_with_path(arguments, true, tool, &mut |path, text| {
        remember(&mut found, path, text);
    });
    // A bare string in `sources` is a record id too (`SourceBasisInput::Bare`),
    // but `sources` is not a resolver key: it is a read-only extra here, and
    // prefix resolution is deliberately left as it was.
    collect_bare_sources(arguments, &mut String::new(), &mut found);
    found
}

fn remember(found: &mut Vec<RecordIdArgument>, path: &str, text: &str) {
    if found.len() < MAX_REMEMBERED && !text.is_empty() && text.len() <= MAX_VALUE_BYTES {
        found.push(RecordIdArgument {
            path: path.to_owned(),
            value: text.to_owned(),
        });
    }
}

fn collect_bare_sources(value: &Value, path: &mut String, found: &mut Vec<RecordIdArgument>) {
    use std::fmt::Write;
    match value {
        Value::Object(map) => {
            for (key, entry) in map {
                let mark = path.len();
                if !path.is_empty() {
                    path.push('.');
                }
                path.push_str(key);
                if key == "sources" {
                    if let Value::Array(items) = entry {
                        for (index, item) in items.iter().enumerate() {
                            if let Value::String(text) = item {
                                let item_mark = path.len();
                                let _ = write!(path, "[{index}]");
                                remember(found, path, text);
                                path.truncate(item_mark);
                            }
                        }
                    }
                }
                collect_bare_sources(entry, path, found);
                path.truncate(mark);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let mark = path.len();
                let _ = write!(path, "[{index}]");
                collect_bare_sources(item, path, found);
                path.truncate(mark);
            }
        }
        _ => {}
    }
}

/// The text of a plain-message refusal, if that is what this is. Only the two
/// plain-message variants are ever touched: anything typed (auth, standby,
/// replay) keeps its exact shape.
fn plain_message(error: &Error) -> Option<&str> {
    match error {
        Error::Engine(message) | Error::Conflict(message) => Some(message),
        _ => None,
    }
}

/// Is this refusal the "that record is not there" kind?
///
/// The handlers phrase it in dozens of places ("record X does not exist",
/// "sources[0] names a record that does not exist or is not visible to the
/// caller"), none of them typed, so the trigger is the phrase.
fn is_missing_record_refusal(message: &str) -> bool {
    !message.contains("Did you mean:")
        && (message.contains("does not exist")
            || message.contains("not found")
            || message.contains("not visible"))
}

/// Is the refusal about *this* value? Either it quotes the value, or it
/// points at the argument by path — the opaque `sources[N] names a record…`
/// form carries no id, only the position, so the path (or its nearest indexed
/// container, `links[0]` for `links[0].target_id`) counts too. A refusal that
/// merely contains "not found" for some other argument names neither.
///
/// Both kinds of match are word-bounded, so `notebook` is not found inside
/// `notebooks`, `id` not inside `invalid`, and `sources[0]` not inside
/// `other_sources[0]`. Outer containers (`records[0]` for
/// `records[0].links[1].target_id`) deliberately do not count: they would
/// also match refusals about the item's other fields.
fn refusal_is_about(message: &str, argument: &RecordIdArgument) -> bool {
    let value_char = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '-');
    let path_lead = |c: char| c.is_ascii_alphanumeric() || matches!(c, '_' | '.');
    let path_tail = |c: char| c.is_ascii_alphanumeric() || c == '_';
    if mentions(message, &argument.value, value_char, value_char) {
        return true;
    }
    if mentions(message, &argument.path, path_lead, path_tail) {
        return true;
    }
    match argument.path.rfind(']') {
        Some(end) if end + 1 < argument.path.len() => {
            mentions(message, &argument.path[..=end], path_lead, path_tail)
        }
        _ => false,
    }
}

/// Does `needle` occur in `message` with no `lead` character before it and no
/// `tail` character after it?
fn mentions(
    message: &str,
    needle: &str,
    lead: impl Fn(char) -> bool,
    tail: impl Fn(char) -> bool,
) -> bool {
    message.match_indices(needle).any(|(start, found)| {
        let before = message[..start].chars().next_back();
        let after = message[start + found.len()..].chars().next();
        !before.is_some_and(&lead) && !after.is_some_and(&tail)
    })
}

/// Append a "did you mean" hint to a missing-record refusal, or return it
/// untouched. Never fails: see rule 3 in the module docs.
pub(crate) async fn with_did_you_mean(
    engine: &EngineHandle,
    caller: &Caller,
    error: Error,
    remembered: &[RecordIdArgument],
) -> Error {
    let Some(message) = plain_message(&error).filter(|m| is_missing_record_refusal(m)) else {
        return error;
    };
    let relevant: Vec<RecordIdArgument> = remembered
        .iter()
        .filter(|argument| refusal_is_about(message, argument))
        .cloned()
        .collect();
    if relevant.is_empty() {
        return error;
    }
    let remembered = relevant.as_slice();
    let hint = match engine {
        EngineHandle::Sqlite(db) => match sqlite_hint(db, caller, remembered).await {
            Ok(Some(hint)) => hint,
            Ok(None) => return error,
            Err(lookup_error) => {
                tracing::debug!(%lookup_error, "did-you-mean lookup failed; refusal unchanged");
                return error;
            }
        },
        // The hint needs `records` reads through a snapshot of the engine's
        // own executor. Only the SQLite path is wired; the others are a
        // deliberate no-op rather than a second implementation to keep in step.
        #[cfg(feature = "v2-kernel-probe")]
        EngineHandle::KernelV2(_) => return error,
        #[cfg(feature = "postgres")]
        EngineHandle::Postgres(_) => return error,
        #[cfg(feature = "turso-local")]
        EngineHandle::TursoLocal(_) => return error,
    };
    append(error, &hint)
}

fn append(error: Error, hint: &str) -> Error {
    let join = |message: String| {
        if message.ends_with('.') {
            format!("{message} {hint}")
        } else {
            format!("{message}. {hint}")
        }
    };
    match error {
        Error::Engine(message) => Error::Engine(join(message)),
        Error::Conflict(message) => Error::Conflict(join(message)),
        other => other,
    }
}

#[cfg(test)]
std::thread_local! {
    static HINT_LOOKUPS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Test hook: how many hint lookups opened a database snapshot on this thread.
#[cfg(test)]
pub(crate) fn hint_lookup_count() -> usize {
    HINT_LOOKUPS.with(|count| count.get())
}

async fn sqlite_hint(
    db: &crate::db::Db,
    caller: &Caller,
    remembered: &[RecordIdArgument],
) -> Result<Option<String>> {
    #[cfg(test)]
    HINT_LOOKUPS.with(|count| count.set(count.get() + 1));
    let mut snapshot = db.pool().begin().await?;
    let hint = {
        let mut executor = BorrowedSqliteStatementExecutor::new(&mut snapshot);
        did_you_mean_with(&mut executor, caller, remembered).await
    };
    let cleanup = snapshot.rollback().await;
    match hint {
        Ok(hint) => {
            cleanup?;
            Ok(hint)
        }
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
    }
}

/// Build `Did you mean: <path> → <id> ("name") or <id>; <path> → …?`, or
/// `None` when no bad value has a visible candidate.
pub(crate) async fn did_you_mean_with<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    remembered: &[RecordIdArgument],
) -> Result<Option<String>> {
    let mut seen = HashSet::new();
    let mut parts = Vec::new();
    for argument in remembered {
        if parts.len() >= MAX_HINTED_VALUES {
            break;
        }
        if !seen.insert(argument.value.as_str()) {
            continue;
        }
        // The value as written is a real record the caller can see: it is not
        // the one the refusal is about.
        if is_visible_record(executor, caller, &argument.value).await? {
            continue;
        }
        let suggestions = suggest(executor, caller, &argument.value).await?;
        if suggestions.is_empty() {
            continue;
        }
        let mut rendered = Vec::with_capacity(suggestions.len());
        for id in &suggestions {
            rendered.push(render_suggestion(executor, id).await?);
        }
        parts.push(format!("{} → {}", argument.path, rendered.join(" or ")));
    }
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(Some(format!("Did you mean: {}?", parts.join("; "))))
}

/// The same gate resolution applies to every candidate it would consider.
async fn is_suggestible<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    id: &str,
) -> Result<bool> {
    Ok(
        !crate::authorization::is_attribution_record_with(executor, id).await?
            && crate::authorization::allows_record_with(
                executor,
                crate::mcp::tools::principal(caller),
                id,
                Capability::View,
            )
            .await?,
    )
}

async fn is_visible_record<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    id: &str,
) -> Result<bool> {
    Ok(record_is_live_with(executor, id).await? && is_suggestible(executor, caller, id).await?)
}

/// Up to [`MAX_SUGGESTIONS`] visible live records that `value` plausibly meant.
async fn suggest<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    value: &str,
) -> Result<Vec<String>> {
    let lower = value.to_ascii_lowercase();
    if let Some(prefix) = leading_hex(&lower) {
        let mut candidates = prefix_candidates_with(executor, &prefix).await?;
        // Closest first: the longest run of leading characters shared with
        // what was written. Stable, so ties keep id order.
        candidates.sort_by_key(|id| std::cmp::Reverse(shared_leading(&lower, id)));
        let mut visible = Vec::new();
        for id in candidates {
            if visible.len() == MAX_SUGGESTIONS {
                break;
            }
            if is_suggestible(executor, caller, &id).await? {
                visible.push(id);
            }
        }
        if !visible.is_empty() {
            return Ok(visible);
        }
    }
    if !is_name_token(value) {
        return Ok(Vec::new());
    }
    let mut visible = Vec::new();
    for id in records_named_like(executor, value).await? {
        if visible.len() == MAX_SUGGESTIONS {
            break;
        }
        if is_suggestible(executor, caller, &id).await? {
            visible.push(id);
        }
    }
    Ok(visible)
}

/// The prefix to scan for: the first eight characters when they are all
/// lowercase hex (the UUID-typo and splice cases), or the whole value when it
/// is a shorter hex run at or above the abbreviation floor.
fn leading_hex(lower: &str) -> Option<String> {
    let is_hex = |byte: &u8| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f');
    let bytes = lower.as_bytes();
    if bytes.len() >= 8 && bytes[..8].iter().all(is_hex) {
        return Some(lower[..8].to_owned());
    }
    if (MIN_PREFIX_HEX..8).contains(&bytes.len()) && bytes.iter().all(is_hex) {
        return Some(lower.to_owned());
    }
    None
}

fn shared_leading(lower: &str, id: &str) -> usize {
    lower
        .bytes()
        .zip(id.bytes())
        .take_while(|(left, right)| left == right)
        .count()
}

/// A short single token with no whitespace, and not UUID-shaped.
fn is_name_token(value: &str) -> bool {
    (MIN_TOKEN..=MAX_TOKEN).contains(&value.len())
        && !is_canonical_uuid(value)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

/// Live records whose name contains `token`: one bounded `LIKE` over `name`,
/// on the refusal path only.
async fn records_named_like<E: DomainStatementExecutor>(
    executor: &mut E,
    token: &str,
) -> Result<Vec<String>> {
    let mut pattern = String::with_capacity(token.len() + 2);
    pattern.push('%');
    for character in token.chars() {
        if matches!(character, '%' | '_' | '!') {
            pattern.push('!');
        }
        pattern.push(character);
    }
    pattern.push('%');
    let statement = record_ref_statement(&[
        "SELECT id FROM {{relation}} WHERE deleted_at IS NULL AND name LIKE ",
        " ESCAPE '!' ORDER BY id LIMIT ",
        "",
    ])?;
    record_ref_rows(
        executor,
        &statement,
        &[
            BindValue::Text(pattern),
            BindValue::Integer(NAME_SCAN_LIMIT),
        ],
    )
    .await
}

async fn render_suggestion<E: DomainStatementExecutor>(
    executor: &mut E,
    id: &str,
) -> Result<String> {
    let statement =
        record_ref_statement(&["SELECT name FROM {{relation}} WHERE id = ", " LIMIT 1"])?;
    let rows = executor
        .fetch_all(
            &statement,
            &[BindValue::Text(id.into())],
            &[ColumnSpec::nullable("name", LogicalType::Text)],
        )
        .await
        .map_err(|error| {
            crate::domain_transaction::stable_storage_error("resolve record reference", &error)
        })?;
    let name = rows.first().and_then(|row| match row.get("name") {
        Some(NormalizedValue::Text(name)) => Some(name.as_str()),
        _ => None,
    });
    Ok(
        match name
            .map(tidy_name)
            .filter(|name| !name.is_empty() && name != id)
        {
            Some(name) => format!("{id} (\"{name}\")"),
            None => id.to_owned(),
        },
    )
}

/// One line, bounded, and unable to close its own quotes.
fn tidy_name(name: &str) -> String {
    let flat = name
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('"', "'");
    let mut chars = flat.chars();
    let head: String = chars.by_ref().take(MAX_NAME_CHARS).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;
    use crate::mcp::registry::ToolRegistry;
    use serde_json::json;

    /// The three real ids from the benchmark-load failures, plus a record whose
    /// *name* carries the short token an agent used as an id.
    const STATE_RECORD: &str = "05c77a45-9fec-429d-b318-c887cd9ad823";
    const SPLICE_HEAD: &str = "592fdc7f-a124-4ffb-ba26-0e291e7a7161";
    const SPLICE_TAIL: &str = "27cb3535-3c9c-4404-b843-0339d01f5fd5";
    const TYPO: &str = "05c77a45-9f9e-429d-b318-c887cd9ad823";
    const SPLICE: &str = "592fdc7f-3c9c-4404-b843-0339d01f5fd5";
    const TOKEN: &str = "28e88ef7";

    async fn call(
        registry: &ToolRegistry,
        db: &Db,
        caller: Caller,
        tool: &str,
        mut args: Value,
    ) -> Result<Value> {
        args["reason"] = json!("did-you-mean fixture");
        registry.call(db.clone(), caller, tool, args).await
    }

    async fn make(registry: &ToolRegistry, db: &Db, id: &str, name: &str) {
        call(
            registry,
            db,
            Caller::local(),
            "create_record",
            json!({"id": id, "type": "Document", "kind": "note", "name": name, "body": "x"}),
        )
        .await
        .unwrap();
    }

    async fn world() -> (Db, ToolRegistry) {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        make(
            &registry,
            &db,
            STATE_RECORD,
            "06c70de4 state 2: click('168')",
        )
        .await;
        make(&registry, &db, SPLICE_HEAD, "Splice head").await;
        make(&registry, &db, SPLICE_TAIL, "Splice tail").await;
        make(
            &registry,
            &db,
            "0b7e1d52-3f6a-4c8e-9a41-7d2c5e8f1a63",
            "Trajectory 28e88ef7",
        )
        .await;
        (db, registry)
    }

    fn link_to(target: &str) -> Value {
        json!({"type": "Document", "kind": "note", "name": "new", "body": "y",
               "links": [{"target_id": target, "relationship": "relates_to"}]})
    }

    async fn refusal(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> String {
        call(registry, db, Caller::local(), tool, args)
            .await
            .expect_err("the call must be refused")
            .to_string()
    }

    #[tokio::test]
    async fn a_typo_in_a_link_target_names_the_real_record() {
        let (db, registry) = world().await;
        let message = refusal(&registry, &db, "create_record", link_to(TYPO)).await;
        assert!(
            message.starts_with(&format!("create_record: record {TYPO} does not exist")),
            "the original refusal leads, unreplaced: {message}"
        );
        assert!(
            message.contains(&format!(
                "Did you mean: links[0].target_id → {STATE_RECORD} (\"06c70de4 state 2: click('168')\")?"
            )),
            "{message}"
        );
        eprintln!("replay typo     : {message}");
    }

    #[tokio::test]
    async fn a_splice_in_sources_names_the_record_sharing_the_first_eight() {
        let (db, registry) = world().await;
        let message = refusal(
            &registry,
            &db,
            "update_record",
            json!({"id": SPLICE_TAIL, "body": "edited",
                   "sources": [{"record_id": SPLICE, "reason": "read it", "role": "context"}]}),
        )
        .await;
        assert!(
            message.contains("sources[0] names a record that does not exist"),
            "{message}"
        );
        assert!(
            message.contains(&format!(
                "Did you mean: sources[0].record_id → {SPLICE_HEAD} (\"Splice head\")?"
            )),
            "{message}"
        );
        // The tail belongs to a different record that shares nothing but its
        // last 28 characters with the intent; it must not be offered.
        assert!(
            !message.contains("27cb3535-3c9c-4404-b843-0339d01f5fd5 ("),
            "{message}"
        );
        eprintln!("replay splice   : {message}");
    }

    #[tokio::test]
    async fn a_short_token_from_a_record_name_suggests_that_record() {
        let (db, registry) = world().await;
        let message = refusal(&registry, &db, "create_record", link_to(TOKEN)).await;
        assert!(
            message.contains(
                "Did you mean: links[0].target_id → 0b7e1d52-3f6a-4c8e-9a41-7d2c5e8f1a63 (\"Trajectory 28e88ef7\")?"
            ),
            "{message}"
        );
        eprintln!("replay token    : {message}");
    }

    #[tokio::test]
    async fn no_candidates_leaves_the_refusal_byte_identical() {
        let (db, registry) = world().await;
        let unknown = "deadbeef-0000-4000-8000-000000000000";
        let message = refusal(&registry, &db, "create_record", link_to(unknown)).await;
        assert_eq!(
            message,
            format!("create_record: record {unknown} does not exist"),
            "no visible candidate means no hint and no change"
        );
        // A refusal that is not about a missing record is never decorated,
        // even with a bad-looking id in the arguments.
        let engine = EngineHandle::Sqlite(db.clone());
        let remembered = vec![RecordIdArgument {
            path: "ids[0]".into(),
            value: TYPO.into(),
        }];
        let other = Error::engine("create_record: name is required");
        assert_eq!(
            with_did_you_mean(&engine, &Caller::local(), other, &remembered)
                .await
                .to_string(),
            "create_record: name is required"
        );
    }

    #[tokio::test]
    async fn a_candidate_the_caller_cannot_view_is_never_named() {
        use crate::authorization::{replace_explicit_policy, AllowEntry};

        let db = crate::create_database(":memory:").await.unwrap();
        // Same first eight characters: one the caller may see, one they may not.
        let visible = "a11ceee1-1111-4000-8000-000000000001";
        let hidden = "a11ceee1-2222-4000-8000-000000000002";
        for (id, name) in [(visible, "Visible one"), (hidden, "Hidden secret plan")] {
            sqlx::query(
                "INSERT INTO records (id, type, name, created_at, updated_at) \
                 VALUES (?, 'Document', ?, '2026-08-12', '2026-08-12')",
            )
            .bind(id)
            .bind(name)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        replace_explicit_policy(
            &db,
            "test:did-you-mean",
            visible,
            vec![AllowEntry::account("acct:bea", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:did-you-mean",
            hidden,
            vec![AllowEntry::account("acct:other", Capability::View)],
        )
        .await
        .unwrap();
        let engine = EngineHandle::Sqlite(db.clone());
        let bea = Caller::authenticated("acct:bea");
        let refusal =
            || Error::engine("create_record: links[0] names a record that does not exist");
        let ask = |value: &str| {
            vec![RecordIdArgument {
                path: "links[0].target_id".into(),
                value: value.into(),
            }]
        };

        // By id prefix: only the visible sibling is named.
        let message = with_did_you_mean(
            &engine,
            &bea,
            refusal(),
            &ask("a11ceee1-9999-4000-8000-000000000009"),
        )
        .await
        .to_string();
        assert!(message.contains(visible), "{message}");
        assert!(!message.contains(hidden), "{message}");
        assert!(!message.contains("Hidden"), "{message}");

        // The hidden record itself, written exactly: treated like any missing id,
        // so the answer is indistinguishable from a made-up id with that prefix.
        let exact_hidden = with_did_you_mean(&engine, &bea, refusal(), &ask(hidden))
            .await
            .to_string();
        let made_up = with_did_you_mean(
            &engine,
            &bea,
            refusal(),
            &ask("a11ceee1-9999-4000-8000-000000000009"),
        )
        .await
        .to_string();
        assert_eq!(
            exact_hidden.split("Did you mean").nth(1),
            made_up.split("Did you mean").nth(1),
        );

        // By name: a token that only a hidden record's name carries yields no
        // hint at all, not even an empty one.
        let by_name = with_did_you_mean(&engine, &bea, refusal(), &ask("secretplan"))
            .await
            .to_string();
        assert_eq!(by_name, refusal().to_string());
        let hidden_name_token = with_did_you_mean(&engine, &bea, refusal(), &ask("Hidden"))
            .await
            .to_string();
        assert_eq!(hidden_name_token, refusal().to_string());
        db.close().await;
    }

    #[tokio::test]
    async fn a_successful_call_does_no_hint_work() {
        let (db, registry) = world().await;
        let before = hint_lookup_count();
        // A link to a real record, and an id-keyed value that exists.
        call(
            &registry,
            &db,
            Caller::local(),
            "create_record",
            link_to(STATE_RECORD),
        )
        .await
        .unwrap();
        assert_eq!(hint_lookup_count(), before, "no refusal, no hint lookup");
        // A refusal with no id-keyed argument does none either.
        let _ = call(
            &registry,
            &db,
            Caller::local(),
            "create_record",
            json!({"type": "Document"}),
        )
        .await;
        assert_eq!(hint_lookup_count(), before);
        // And one with a bad id does exactly one.
        let _ = refusal(&registry, &db, "create_record", link_to(TYPO)).await;
        assert_eq!(hint_lookup_count(), before + 1);
    }

    #[tokio::test]
    async fn a_failed_lookup_returns_the_original_refusal() {
        let (db, _registry) = world().await;
        let engine = EngineHandle::Sqlite(db.clone());
        db.close().await;
        let original = format!("create_record: record {TYPO} does not exist");
        let remembered = vec![RecordIdArgument {
            path: "links[0].target_id".into(),
            value: TYPO.into(),
        }];
        let out = with_did_you_mean(
            &engine,
            &Caller::local(),
            Error::engine(original.clone()),
            &remembered,
        )
        .await;
        assert_eq!(out.to_string(), original);
    }

    #[tokio::test]
    async fn a_refusal_about_something_else_gets_no_hint() {
        let (db, registry) = world().await;
        // The invalid type is the refusal; the mistyped link is incidental.
        let message = refusal(
            &registry,
            &db,
            "create_record",
            json!({"type": "not found", "kind": "note", "name": "new", "body": "y",
                   "links": [{"target_id": TYPO, "relationship": "relates_to"}]}),
        )
        .await;
        eprintln!("unrelated refusal: {message}");
        assert!(!message.contains("Did you mean"), "{message}");

        // Directly, with a refusal that matches the trigger phrase but names
        // neither the value nor its path.
        let engine = EngineHandle::Sqlite(db.clone());
        let remembered = vec![RecordIdArgument {
            path: "links[0].target_id".into(),
            value: TYPO.into(),
        }];
        let unrelated = "create_record: type 'not found' does not exist in the vocabulary";
        assert_eq!(
            with_did_you_mean(
                &engine,
                &Caller::local(),
                Error::engine(unrelated),
                &remembered
            )
            .await
            .to_string(),
            unrelated
        );
        // The same refusal quoting the value, or pointing at its path, does.
        for about in [
            format!("create_record: record {TYPO} does not exist"),
            "create_record: links[0] names a record that does not exist".to_owned(),
            "create_record: links[0].target_id does not exist".to_owned(),
        ] {
            let hinted = with_did_you_mean(
                &engine,
                &Caller::local(),
                Error::engine(about.clone()),
                &remembered,
            )
            .await
            .to_string();
            assert!(hinted.contains(STATE_RECORD), "{about} -> {hinted}");
        }
    }

    #[test]
    fn relevance_matching_respects_word_and_path_boundaries() {
        let about = |message: &str, path: &str, value: &str| {
            refusal_is_about(
                message,
                &RecordIdArgument {
                    path: path.into(),
                    value: value.into(),
                },
            )
        };
        // A value inside a longer word is not the value.
        assert!(!about(
            "create_record: type \"not found notebooks\" does not exist",
            "links[0].target_id",
            "notebook"
        ));
        assert!(about(
            "create_record: record notebook does not exist",
            "links[0].target_id",
            "notebook"
        ));
        assert!(about(
            "record notebook. does not exist",
            "ids[0]",
            "notebook"
        ));
        // `id` is not the tail of "invalid".
        assert!(!about(
            "update_record: invalid type, not found",
            "id",
            "abcdef01"
        ));
        assert!(about("update_record: id does not exist", "id", "abcdef01"));
        // `sources[0]` is not the tail of `other_sources[0]`.
        assert!(!about(
            "update_record: other_sources[0] does not exist",
            "sources[0]",
            "abcdef01"
        ));
        assert!(about(
            "update_record: sources[0] names a record that does not exist",
            "sources[0]",
            "abcdef01"
        ));
        // The nearest indexed container counts; an outer one does not.
        assert!(about(
            "create_many: records[0].links[1] names a record that does not exist",
            "records[0].links[1].target_id",
            "abcdef01"
        ));
        assert!(!about(
            "create_record: records[0].type does not exist",
            "records[0].links[1].target_id",
            "abcdef01"
        ));
        assert!(about(
            "create_record: records[0].links[1].target_id does not exist",
            "records[0].links[1].target_id",
            "abcdef01"
        ));
        assert!(!about(
            "create_record: records[0] has a field that is not found",
            "records[0].links[1].target_id",
            "abcdef01"
        ));
    }

    #[tokio::test]
    async fn bare_string_sources_get_a_hint_at_their_index() {
        let (db, registry) = world().await;
        let message = refusal(
            &registry,
            &db,
            "update_record",
            json!({"id": SPLICE_TAIL, "body": "edited", "sources": [SPLICE_HEAD, SPLICE]}),
        )
        .await;
        assert!(
            message.contains(&format!(
                "Did you mean: sources[1] → {SPLICE_HEAD} (\"Splice head\")?"
            )),
            "{message}"
        );
        // The collector sees bare strings under `sources`, at any depth, and
        // leaves object entries to the record-id walk.
        let mut arguments = json!({
            "sources": ["aaaaaaaa", {"record_id": "bbbbbbbb", "reason": "r"}],
            "records": [{"sources": ["cccccccc"]}],
        });
        let mut found = record_id_arguments(&mut arguments, "create_many")
            .into_iter()
            .map(|argument| (argument.path, argument.value))
            .collect::<Vec<_>>();
        found.sort();
        assert_eq!(
            found,
            [
                ("records[0].sources[0]".to_owned(), "cccccccc".to_owned()),
                ("sources[0]".to_owned(), "aaaaaaaa".to_owned()),
                ("sources[1].record_id".to_owned(), "bbbbbbbb".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn an_attribution_record_is_never_named() {
        let db = crate::create_database(":memory:").await.unwrap();
        let note = "c0ffee00-1111-4000-8000-000000000001";
        let attribution = "c0ffee00-2222-4000-8000-000000000002";
        for (id, record_type, kind, name) in [
            (note, "Document", "note", "Ordinary note"),
            (
                attribution,
                "Annotation",
                "attribution",
                "Attribution marker",
            ),
        ] {
            sqlx::query(
                "INSERT INTO records (id, type, kind, name, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, '2026-08-12', '2026-08-12')",
            )
            .bind(id)
            .bind(record_type)
            .bind(kind)
            .bind(name)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        let engine = EngineHandle::Sqlite(db.clone());
        let remembered = vec![RecordIdArgument {
            path: "links[0].target_id".into(),
            value: "c0ffee00-9999-4000-8000-000000000009".into(),
        }];
        let message = with_did_you_mean(
            &engine,
            &Caller::local(),
            Error::engine("create_record: links[0] names a record that does not exist"),
            &remembered,
        )
        .await
        .to_string();
        assert!(message.contains(note), "{message}");
        assert!(!message.contains(attribution), "{message}");
        assert!(!message.contains("Attribution marker"), "{message}");
        db.close().await;
    }

    #[tokio::test]
    async fn a_candidate_without_a_distinct_name_is_not_named_twice() {
        let db = crate::create_database(":memory:").await.unwrap();
        let same = "d0d0d0d0-1111-4000-8000-000000000001";
        let named = "d0d0d0d0-2222-4000-8000-000000000002";
        for (id, name) in [(same, same), (named, "Real name")] {
            sqlx::query(
                "INSERT INTO records (id, type, name, created_at, updated_at) \
                 VALUES (?, 'Document', ?, '2026-08-12', '2026-08-12')",
            )
            .bind(id)
            .bind(name)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        let engine = EngineHandle::Sqlite(db.clone());
        let remembered = vec![RecordIdArgument {
            path: "links[0].target_id".into(),
            value: "d0d0d0d0-9999-4000-8000-000000000009".into(),
        }];
        let message = with_did_you_mean(
            &engine,
            &Caller::local(),
            Error::engine("create_record: links[0] names a record that does not exist"),
            &remembered,
        )
        .await
        .to_string();
        assert!(
            message.ends_with(&format!(
                "links[0].target_id → {same} or {named} (\"Real name\")?"
            )),
            "{message}"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn read_refusals_stay_bare() {
        let (db, registry) = world().await;
        // `open_collection` refuses (rather than returning an empty item) for a
        // missing id, and TYPO shares its first eight characters with a visible
        // record, so a hint would be offered if reads still got one.
        let before = hint_lookup_count();
        let error = registry
            .call(
                db.clone(),
                Caller::local(),
                "open_collection",
                json!({"id": TYPO}),
            )
            .await
            .expect_err("a missing collection is refused");
        assert_eq!(
            error.to_string(),
            format!("open_collection: record {TYPO} does not exist")
        );
        assert_eq!(hint_lookup_count(), before, "reads do no hint work");
    }

    #[tokio::test]
    async fn the_error_variant_survives_the_hint() {
        let (db, _registry) = world().await;
        let engine = EngineHandle::Sqlite(db.clone());
        let remembered = vec![RecordIdArgument {
            path: "links[0].target_id".into(),
            value: TYPO.into(),
        }];
        let text = format!("create_record: record {TYPO} does not exist");
        let engine_error = with_did_you_mean(
            &engine,
            &Caller::local(),
            Error::engine(text.clone()),
            &remembered,
        )
        .await;
        assert!(matches!(&engine_error, Error::Engine(m) if m.contains("Did you mean")));
        let conflict = with_did_you_mean(
            &engine,
            &Caller::local(),
            Error::conflict(text),
            &remembered,
        )
        .await;
        assert!(matches!(&conflict, Error::Conflict(m) if m.contains("Did you mean")));
    }

    #[test]
    fn paths_are_spelled_the_way_the_caller_wrote_them() {
        let mut arguments = json!({
            "id": "unused",
            "links": [{"target_id": "aaaaaaaa"}, {"target_id": "bbbbbbbb"}],
            "context_record_ids": ["cccccccc", "dddddddd"],
            "mentions": [{"target_kind": "principal", "target_id": "someone"}],
        });
        let found = record_id_arguments(&mut arguments, "create_record");
        let mut paths = found
            .iter()
            .map(|argument| (argument.path.as_str(), argument.value.as_str()))
            .collect::<Vec<_>>();
        paths.sort();
        assert_eq!(
            paths,
            [
                ("context_record_ids[0]", "cccccccc"),
                ("context_record_ids[1]", "dddddddd"),
                ("links[0].target_id", "aaaaaaaa"),
                ("links[1].target_id", "bbbbbbbb"),
            ]
        );
    }
}
