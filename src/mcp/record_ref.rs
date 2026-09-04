//! Unique-prefix resolution for caller-supplied record ids.
//!
//! Every id-accepting tool addresses a record by its full `records.id`, which
//! in practice is a 36-character UUIDv4. Quoting all 36 characters is a real
//! cost at the agent boundary, so this module admits a *leading substring* of
//! the record's own id and resolves it by unique-prefix match, exactly as git
//! resolves an abbreviated commit hash.
//!
//! Nothing is minted and nothing is stored. There is no new column, no binding
//! row and no new vocabulary: this is purely a resolution step at the argument
//! boundary. [`resolve_record_ids`] runs *before* the handler, so by the time
//! any handler — and therefore any link row, mention row or projected write —
//! sees the value, it is already the full id. A prefix can never reach durable
//! state.
//!
//! Three rules govern the resolution, and each one is load-bearing:
//!
//! 1. **Exact match always beats prefix match.** The full id is probed first;
//!    only a miss falls through to prefix matching.
//! 2. **Prefix matching applies only to canonical-UUID-shaped ids**, on both
//!    sides. A non-UUID `records.id` is no longer something a caller can
//!    choose: `crate::domain_transaction::validate_record_id` now admits only
//!    a canonical lowercase UUIDv4/v7 or a reserved `native:` constant. The
//!    non-UUID namespace is therefore *historical plus reserved* — records
//!    written by builds predating that rule (`order-one`, `old-home`), which
//!    still replay from their events unchanged, and `native:root` and friends.
//!    Both kinds genuinely exist in live databases, so this rule is still
//!    live and still needed; it is not a compatibility shim awaiting deletion.
//!    Prefix matching assumes uniformly distributed identifiers, and these ids
//!    cluster — `order` prefixes both `order-one` and `order-two` — so the two
//!    namespaces are kept from ever contending. This is git's
//!    refs-before-hashes precedence.
//! 3. **Resolution is scoped to what the caller can already see.** Reporting
//!    "ambiguous" for a prefix that straddles a record the caller cannot read
//!    would turn resolution into an existence oracle, so candidates are
//!    filtered through the same `View` capability the tools themselves apply,
//!    and "matched nothing you can see" is indistinguishable from "matched
//!    nothing".

use std::collections::HashMap;
use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::authorization::Capability;
use crate::db::Db;
use crate::mcp::registry::{Caller, EngineHandle};
use crate::portable_sql::{
    BindValue, BorrowedSqliteStatementExecutor, ColumnSpec, DomainStatementExecutor, LogicalType,
    NormalizedRow, NormalizedValue, StatementKind, StatementTemplate,
};
use crate::{Error, Result};

/// Shortest abbreviation admitted on input.
///
/// Six hex digits is git's own default abbreviation floor scaled to this id
/// domain: it discriminates 16.7M values, which keeps accidental collisions
/// rare enough that the ambiguity error stays an exception rather than the
/// common case. Below this the input is left untouched, so a short
/// caller-chosen id keeps behaving exactly as it did before.
const MIN_PREFIX_HEX: usize = 6;

/// Shortest abbreviation this module will *offer* as a record's reference.
///
/// Deliberately one digit above [`MIN_PREFIX_HEX`], and the asymmetry is the
/// point: input is lenient because a human retyping a reference should not be
/// punished for dropping a character, while output is conservative because a
/// reference this module hands out ends up in a URL — durable state outside
/// the database, which no later write can migrate. The extra digit buys a 16x
/// larger space (268M values) against the one failure mode that matters here:
/// a reference that is unique when it is minted and ambiguous a year later.
///
/// Seven also matches the short form already used across Native's own record
/// vocabulary, so a reference read out of one surface is recognisable in the
/// other.
const MIN_DISPLAY_HEX: usize = 7;

/// A canonical UUID carries exactly 32 hex digits.
///
/// A caller who supplies all 32 has supplied a *whole* id, not an
/// abbreviation, so it is passed through untouched and the handler's existing
/// not-found path fires unchanged. Treating a complete UUID as a prefix would
/// silently rewrite every existing "record X does not exist" outcome.
const UUID_HEX: usize = 32;

/// Length of the canonical dashed rendering (8-4-4-4-12 plus four dashes).
const UUID_LEN: usize = 36;

/// Result of resolving a reference against one caller-visible database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ReferenceResolution {
    Unresolved,
    Resolved(String),
    Ambiguous,
}

/// Resolve one reference for a hosted caller, preserving the anti-oracle
/// contract (invisible records are indistinguishable from absent records).
pub(crate) async fn resolve_reference(
    db: &Db,
    caller: &Caller,
    reference: &str,
) -> Result<ReferenceResolution> {
    let mut snapshot = db.write_pool().begin().await?;
    let result = {
        let mut executor = BorrowedSqliteStatementExecutor::new(&mut snapshot);
        resolve_reference_with(&mut executor, caller, reference).await
    };
    let cleanup = snapshot.rollback().await;
    match result {
        Ok(result) => {
            cleanup?;
            Ok(result)
        }
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
    }
}

async fn resolve_reference_with<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    reference: &str,
) -> Result<ReferenceResolution> {
    if is_canonical_uuid(reference) {
        // `record_is_live_with`, not `record_exists_with`, and the difference
        // is the whole point. The tool boundary probes with tombstones visible
        // so an abbreviation can never step over a deleted record onto a live
        // one — see `resolve_one_with`. A URL has no such error to fire: an
        // address that resolves is an address that opens, so answering
        // `Resolved` for a deleted record hands the workbench something it
        // cannot render and the reader sees a dead landing rather than an
        // honest one. The prefix scan below already excludes tombstones
        // (`deleted_at IS NULL` in `CANDIDATE_SQL`); this makes the exact
        // probe agree with it at the same boundary.
        if record_is_live_with(executor, reference).await?
            && !crate::authorization::is_attribution_record_with(executor, reference).await?
            && crate::authorization::allows_record_with(
                executor,
                crate::mcp::tools::principal(caller),
                reference,
                Capability::View,
            )
            .await?
        {
            return Ok(ReferenceResolution::Resolved(reference.to_owned()));
        }
        return Ok(ReferenceResolution::Unresolved);
    }
    let Some(prefix) = canonical_prefix(reference) else {
        return Ok(ReferenceResolution::Unresolved);
    };
    let mut visible = Vec::new();
    for candidate in prefix_candidates_with(executor, &prefix).await? {
        if !crate::authorization::is_attribution_record_with(executor, &candidate).await?
            && crate::authorization::allows_record_with(
                executor,
                crate::mcp::tools::principal(caller),
                &candidate,
                Capability::View,
            )
            .await?
        {
            visible.push(candidate);
        }
    }
    Ok(match visible.as_slice() {
        [] => ReferenceResolution::Unresolved,
        [id] => ReferenceResolution::Resolved(id.clone()),
        _ => ReferenceResolution::Ambiguous,
    })
}

/// Upper bound on candidates fetched for one prefix.
///
/// The prefix scan is bounded rather than counted so a degenerate prefix
/// cannot walk the table. With a 6-hex-digit floor, more than this many
/// colliding UUIDs is not reachable in practice; if it ever were, the extra
/// rows only make an already-ambiguous prefix ambiguous, which is the correct
/// answer anyway.
const MAX_CANDIDATES: i64 = 32;

/// Exclusive upper bound character for the prefix range scan.
///
/// `records.id` is `TEXT PRIMARY KEY`. A correlated `LIKE prefix || '%'` is
/// not reliably foldable into index bounds, so the scan is expressed as an
/// explicit half-open range `id >= prefix AND id < prefix || SENTINEL`, which
/// every substrate can satisfy from the primary-key index.
///
/// The sentinel must sort after every character that can follow the prefix
/// *within the domain being matched*. That domain is deliberately narrower
/// than `records.id` at large: the scan only ever admits canonical
/// lowercase-hex UUIDs (see [`is_canonical_uuid`]), whose remaining characters
/// are drawn from `[0-9a-f-]` — ASCII `-` (0x2D), `0`-`9` (0x30..0x39) and
/// `a`-`f` (0x61..0x66). `g` (0x67) is the immediate successor of the maximum
/// of that set, so the bound is both correct and tight.
///
/// This reasoning does **not** survive being generalised. The full stored id
/// domain — `validate_record_id`'s shape gate, which is what historical and
/// reserved ids were admitted under — is `[A-Za-z0-9._:-]`, which reaches `z`
/// (0x7A); an id such as `abc123zebra` sorts *after* `abc123g` and would fall
/// outside this range. That is harmless only because such an id is not
/// canonical-UUID-shaped and is therefore not a candidate by rule 2. Widen the
/// shape gate and this sentinel becomes wrong.
const PREFIX_SENTINEL: char = 'g';

/// JSON keys whose value addresses an **existing** record.
///
/// The tool surface has no shared argument parse: every tool deserialises its
/// own typed struct, and id-shaped parameters appear in 20 of the 27 modules
/// under `src/mcp/tools/` under roughly 19 distinct names. Rather than call a
/// resolver at each of those ~200 sites — a rollout that provably decays, and
/// that every new tool would have to remember — resolution happens once, here,
/// on the way into the handler.
///
/// That makes the question "which JSON keys are record ids?" and this table is
/// the answer. It is a key-name allowlist rather than a schema-driven marker
/// because a marker is per-tool work on 62 tools; the allowlist is one place a
/// future reader can read, audit and revise. Every name here was checked
/// against the generated tool schemas (`web/generated/tools.d.ts`)
/// and against the DDL: each one is a `records(id)` reference at every site it
/// appears. Names that merely *look* like record ids and are not — `citation_id`,
/// `suggestion_ids`, `member_id`, `programme_id`, `intervention_id`,
/// `binding_id`, `value_id`, `export_id`, and every `*_event_id` — are
/// deliberately absent.
///
/// Keys are matched at any depth, which is what makes `links[].target_id`,
/// `mentions[].target_id` and `target.target_record_id` work without naming
/// their containers.
///
/// `scope` is the one overloaded name kept in the list. On `search`, `scan`
/// and `get_dashboard` it is "the subtree rooted at this record"; on
/// `manage_instructions` it is the enum `workspace | member`, which is never
/// hex-shaped, and on `manage_artifact_module_grants` it is an object, which
/// carries no string to visit. The overload is therefore inert rather than
/// merely unlikely.
const RECORD_ID_KEYS: &[&str] = &[
    "ancestor_id",
    "annotation_id",
    "applies_to_collection_id",
    "artifact_id",
    "attachment_id",
    "authority_evidence_record_id",
    "bearer_id",
    "collection_id",
    "context_record_ids",
    "conversation_id",
    "expected_source_record_id",
    "from_conversation_id",
    "home_id",
    "ids",
    "message_id",
    "message_ids",
    "module_id",
    "owner_id",
    "person_record_id",
    "record_id",
    "root_id",
    "scope",
    "scope_record_id",
    "source_id",
    "source_record_id",
    "subject_record_id",
    "target_id",
    "target_record_id",
    "to_conversation_id",
];

/// Tools whose **top-level** `id` addresses an existing record.
///
/// `id` is the one key whose meaning depends on its tool, so it is gated by
/// tool name instead of by key name. The exclusions are the point of the list:
///
/// - `create_record.id` asserts a *new* id. It is not a lookup, and resolving
///   it would be incoherent — it stays on `record_id_for_create` untouched.
/// - `manage_messages.id` is the same assertion for `action: "send"`.
/// - `create_attribution.id` likewise mints the annotation record.
/// - `manage_vocabularies.id` and `manage_schema_config.id` name rows in other
///   tables entirely.
///
/// Only the top level is gated this way; a nested `id` (there is none on the
/// current surface that addresses a record) is never resolved.
const TOP_LEVEL_ID_ADDRESSES_A_RECORD: &[&str] = &[
    "archive_record",
    "delete_record",
    "open_collection",
    "render_artifact",
    "render_record",
    "update_record",
    "verify_artifact",
];

/// Resolve every abbreviated record id in one tool's arguments.
///
/// Returns the arguments unchanged when nothing looks like an abbreviation,
/// which is the overwhelmingly common case: a full 36-character id costs no
/// database round trip at all.
pub(crate) async fn resolve_record_ids(
    engine: &EngineHandle,
    caller: &Caller,
    tool: &str,
    mut arguments: Value,
) -> Result<Value> {
    // Exceptional ownership recovery admits exact ids only. Its handler must
    // check host-owner authority before any target-dependent lookup, while
    // prefix resolution necessarily reads candidate records first.
    if tool == "claim_unowned_record" {
        return Ok(arguments);
    }
    // Keep the overwhelmingly common path pure. Full ids, human ids, and
    // tools without record-addressing arguments must not admit a backend
    // snapshot merely to discover that there is nothing to resolve.
    let mut abbreviations = HashSet::new();
    walk(&mut arguments, true, tool, &mut |text| {
        if let Some(prefix) = canonical_prefix(text) {
            abbreviations.insert((text.clone(), prefix));
        }
    });
    if abbreviations.is_empty() {
        return Ok(arguments);
    }
    let abbreviations = abbreviations.into_iter().collect::<Vec<_>>();

    match engine {
        EngineHandle::Sqlite(db) => {
            let mut snapshot = db.write_pool().begin().await?;
            let resolved = {
                let mut executor = BorrowedSqliteStatementExecutor::new(&mut snapshot);
                resolve_record_ids_with(&mut executor, caller, tool, arguments, abbreviations).await
            };
            let cleanup = snapshot.rollback().await;
            match resolved {
                Ok(arguments) => {
                    cleanup?;
                    Ok(arguments)
                }
                Err(error) => {
                    let _ = cleanup;
                    Err(error)
                }
            }
        }
        #[cfg(feature = "postgres")]
        EngineHandle::Postgres(db) => {
            crate::postgres::resolve_record_ids(db, caller, tool, arguments, abbreviations).await
        }
        #[cfg(feature = "turso-local")]
        EngineHandle::TursoLocal(db) => {
            crate::turso_local::resolve_record_ids(db, caller, tool, arguments, abbreviations).await
        }
    }
}

/// Resolve record references inside one already-admitted backend snapshot.
pub(crate) async fn resolve_record_ids_with<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    tool: &str,
    mut arguments: Value,
    abbreviations: Vec<(String, String)>,
) -> Result<Value> {
    let mut resolved: HashMap<String, String> = HashMap::new();
    for (input, prefix) in abbreviations {
        if let Some(id) = resolve_one_with(executor, caller, tool, &input, &prefix).await? {
            resolved.insert(input, id);
        }
    }
    if resolved.is_empty() {
        return Ok(arguments);
    }

    walk(&mut arguments, true, tool, &mut |text| {
        if let Some(id) = resolved.get(text.as_str()) {
            text.clone_from(id);
        }
    });
    Ok(arguments)
}

/// Resolve one abbreviation, or `None` to leave the caller's value alone.
///
/// A prefix that matches nothing visible is *not* an error here. Passing it
/// through unchanged means the handler's own "record does not exist" path
/// fires, so resolution never invents a new failure mode and — critically —
/// a prefix that matches only records the caller cannot see is answered
/// identically to a prefix that matches nothing at all.
async fn resolve_one_with<E: DomainStatementExecutor>(
    executor: &mut E,
    caller: &Caller,
    tool: &str,
    input: &str,
    prefix: &str,
) -> Result<Option<String>> {
    // Rule 1. An id that exists is itself, whatever it looks like. The probe
    // deliberately ignores `deleted_at`: a tombstoned exact id must still
    // reach the handler as written rather than being re-pointed at a live
    // record that happens to share its opening characters.
    if record_exists_with(executor, input).await? {
        return Ok(None);
    }
    let mut visible = Vec::new();
    for candidate in prefix_candidates_with(executor, prefix).await? {
        if !crate::authorization::is_attribution_record_with(executor, &candidate).await?
            && crate::authorization::allows_record_with(
                executor,
                crate::mcp::tools::principal(caller),
                &candidate,
                Capability::View,
            )
            .await?
        {
            visible.push(candidate);
        }
    }
    match visible.len() {
        0 => Ok(None),
        1 => Ok(visible.pop()),
        _ => Err(Error::engine(format!(
            "{tool}: record id prefix '{input}' is ambiguous; it matches {} records: {}",
            visible.len(),
            visible.join(", ")
        ))),
    }
}

fn record_ref_statement(fragments: &'static [&'static str]) -> Result<StatementTemplate> {
    StatementTemplate::new(StatementKind::Select, "records", fragments).map_err(|error| {
        crate::domain_transaction::stable_storage_error("resolve record reference", &error)
    })
}

/// The exact probe with tombstones excluded, for the URL boundary.
///
/// Deliberately a second function rather than a flag on [`record_exists_with`]:
/// the two callers ask genuinely different questions. "Is this id taken?" is
/// what abbreviation resolution needs; "is there something here to open?" is
/// what a shared link needs. One function with a boolean would make every call
/// site re-derive which it meant.
async fn record_is_live_with<E: DomainStatementExecutor>(
    executor: &mut E,
    id: &str,
) -> Result<bool> {
    let statement = record_ref_statement(&[
        "SELECT id FROM {{relation}} WHERE id = ",
        " AND deleted_at IS NULL LIMIT 1",
    ])?;
    Ok(
        !record_ref_rows(executor, &statement, &[BindValue::Text(id.into())])
            .await?
            .is_empty(),
    )
}

async fn record_exists_with<E: DomainStatementExecutor>(
    executor: &mut E,
    id: &str,
) -> Result<bool> {
    let statement = record_ref_statement(&["SELECT id FROM {{relation}} WHERE id = ", " LIMIT 1"])?;
    Ok(
        !record_ref_rows(executor, &statement, &[BindValue::Text(id.into())])
            .await?
            .is_empty(),
    )
}

/// The candidate scan, named so a query-plan test can hold it to the index.
///
/// The half-open range on `id` is the whole point: it is what a driver can
/// fold into primary-key bounds. `length(id) = 36` is a cheap SQL-side
/// discriminator so a caller-chosen id that merely opens with hex digits does
/// not have to be carried back into Rust; the authoritative shape gate is
/// [`is_canonical_uuid`].
#[cfg(test)]
const CANDIDATE_SQL: &str = "SELECT id FROM records \
     WHERE id >= ? AND id < ? AND deleted_at IS NULL AND length(id) = ? \
     ORDER BY id LIMIT ?";

#[cfg(test)]
std::thread_local! {
    static PREFIX_ROW_QUERY_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_prefix_row_query_count() {
    PREFIX_ROW_QUERY_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn prefix_row_query_count() -> usize {
    PREFIX_ROW_QUERY_COUNT.with(|count| count.get())
}

/// Live rows in the prefix's range, bounded but not yet shape-gated.
///
/// Kept separate from [`prefix_candidates`] because the *row count* carries
/// information the filtered list has lost: it is the only way to tell "this is
/// every match" from "this is the first [`MAX_CANDIDATES`] of them", and
/// [`display_reference`] cannot answer correctly without knowing which it has.
#[cfg(test)]
async fn prefix_rows(db: &Db, prefix: &str) -> Result<Vec<String>> {
    let mut snapshot = db.write_pool().begin().await?;
    let rows = {
        let mut executor = BorrowedSqliteStatementExecutor::new(&mut snapshot);
        prefix_rows_with(&mut executor, prefix).await
    };
    let cleanup = snapshot.rollback().await;
    match rows {
        Ok(rows) => {
            cleanup?;
            Ok(rows)
        }
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
    }
}

async fn prefix_rows_with<E: DomainStatementExecutor>(
    executor: &mut E,
    prefix: &str,
) -> Result<Vec<String>> {
    #[cfg(test)]
    PREFIX_ROW_QUERY_COUNT.with(|count| count.set(count.get() + 1));
    let upper = format!("{prefix}{PREFIX_SENTINEL}");
    let statement = candidate_statement()?;
    record_ref_rows(
        executor,
        &statement,
        &[
            BindValue::Text(prefix.into()),
            BindValue::Text(upper),
            BindValue::Integer(UUID_LEN as i64),
            BindValue::Integer(MAX_CANDIDATES),
        ],
    )
    .await
}

fn candidate_statement() -> Result<StatementTemplate> {
    record_ref_statement(&[
        "SELECT id FROM {{relation}} WHERE id >= ",
        " AND id < ",
        " AND deleted_at IS NULL AND length(id) = ",
        " ORDER BY id LIMIT ",
        "",
    ])
}

async fn record_ref_rows<E: DomainStatementExecutor>(
    executor: &mut E,
    statement: &StatementTemplate,
    bindings: &[BindValue],
) -> Result<Vec<String>> {
    executor
        .fetch_all(
            statement,
            bindings,
            &[ColumnSpec::required("id", LogicalType::Text)],
        )
        .await
        .map_err(|error| {
            crate::domain_transaction::stable_storage_error("resolve record reference", &error)
        })?
        .iter()
        .map(record_ref_row_id)
        .collect()
}

fn record_ref_row_id(row: &NormalizedRow) -> Result<String> {
    match row.get("id") {
        Some(NormalizedValue::Text(id)) => Ok(id.clone()),
        _ => Err(Error::engine("record reference row has invalid id")),
    }
}

/// Live records whose id starts with `prefix`, bounded and shape-gated.
#[cfg(test)]
async fn prefix_candidates(db: &Db, prefix: &str) -> Result<Vec<String>> {
    Ok(prefix_rows(db, prefix)
        .await?
        .into_iter()
        .filter(|id| is_canonical_uuid(id))
        .collect())
}

async fn prefix_candidates_with<E: DomainStatementExecutor>(
    executor: &mut E,
    prefix: &str,
) -> Result<Vec<String>> {
    Ok(prefix_rows_with(executor, prefix)
        .await?
        .into_iter()
        .filter(|id| is_canonical_uuid(id))
        .collect())
}

/// The shortest abbreviation that addresses `id` and nothing else, if one
/// exists — the inverse of [`resolve_one`], and the only reference form this
/// engine will advertise.
///
/// Every other function here *consumes* a prefix the caller already had. This
/// one produces the prefix, which is a different problem with a different
/// safety profile: a consumed prefix that stops resolving is one failed tool
/// call, whereas a produced prefix lands in a URL and outlives the process that
/// minted it. Three decisions follow from that, and each is deliberate.
///
/// **It is computed over every live record, not over the records the caller can
/// see.** That is the opposite of resolution's rule 3, and on purpose: a
/// reference is minted to be *shared*, so it has to be unambiguous for the
/// reader as well as the author. A visibility-scoped reference would be the
/// shortest form that happens to work for whoever loaded the page, and would
/// break — silently, later, for someone else — exactly when the private record
/// it stepped over became visible to them. The disclosure this trades away is
/// close to nothing: a reference one digit longer than the floor says only that
/// *some* UUID shares seven leading hex digits with this one. It names no
/// record, and it is not an oracle for any record the caller asked about, which
/// is the property rule 3 exists to protect.
///
/// **Only live records count**, matching [`prefix_candidates`] exactly. The
/// symmetry is the requirement, not the filter: a reference is worth minting
/// only if resolution would accept it, so both sides must agree on the
/// candidate set.
///
/// **`None` means "no reference", never "guess".** Two cases reach it — a
/// caller-chosen id, which rule 2 keeps out of prefix matching entirely and for
/// which an abbreviation would therefore be an address that cannot resolve; and
/// a saturated candidate scan, where the answer is unknown rather than long.
/// Callers degrade to the full id, which is always correct.
pub(crate) async fn display_reference(db: &Db, id: &str) -> Result<Option<String>> {
    Ok(display_references(db, &[id]).await?.remove(id).flatten())
}

fn uuid_hex(id: &str) -> String {
    id.chars().filter(|character| *character != '-').collect()
}

/// Shortest unique prefix for `id` given an already-fetched candidate row set.
///
/// Saturation is decided from the raw row count before shape-gating, matching
/// [`prefix_rows_with`]'s contract: a batch must not pool rows across prefixes
/// and then apply its own limit.
fn display_reference_from_rows(id: &str, rows: &[String]) -> Option<String> {
    if rows.len() as i64 >= MAX_CANDIDATES {
        return None;
    }
    let hex = uuid_hex(id);
    let mut length = MIN_DISPLAY_HEX;
    for other in rows.iter().filter(|row| row.as_str() != id) {
        if !is_canonical_uuid(other) {
            continue;
        }
        let shared = hex
            .bytes()
            .zip(other.bytes().filter(|byte| *byte != b'-'))
            .take_while(|(mine, theirs)| mine == theirs)
            .count();
        length = length.max(shared + 1);
    }
    // Unreachable for distinct UUIDs — sharing 31 hex digits leaves one digit
    // to differ, so `length` cannot exceed 32 — but the bound is asserted
    // rather than assumed because at 32 the result stops being an abbreviation
    // and `canonical_prefix` would refuse to resolve it.
    if length >= UUID_HEX {
        return None;
    }
    Some(hex[..length].to_string())
}

/// Resolve display references for many ids in one backend round trip.
///
/// Canonical UUIDs sharing the same seven-hex seed share one prefix scan; each
/// prefix group keeps its own saturation boundary so a saturated id in one group
/// cannot shorten a correct answer in another.
pub(crate) async fn display_references(
    db: &Db,
    ids: &[&str],
) -> Result<HashMap<String, Option<String>>> {
    display_references_in_pool(db.write_pool(), ids).await
}

pub(crate) async fn display_references_in_pool(
    pool: &sqlx::SqlitePool,
    ids: &[&str],
) -> Result<HashMap<String, Option<String>>> {
    let mut result = HashMap::with_capacity(ids.len());
    let mut by_prefix: HashMap<String, Vec<&str>> = HashMap::new();
    for id in ids {
        if !is_canonical_uuid(id) {
            result.insert((*id).to_owned(), None);
            continue;
        }
        let hex = uuid_hex(id);
        by_prefix
            .entry(hex[..MIN_DISPLAY_HEX].to_string())
            .or_default()
            .push(id);
    }
    if by_prefix.is_empty() {
        return Ok(result);
    }

    let mut snapshot = pool.begin().await?;
    let batch = {
        let mut executor = BorrowedSqliteStatementExecutor::new(&mut snapshot);
        display_references_with(&mut executor, &by_prefix).await
    };
    let cleanup = snapshot.rollback().await;
    match batch {
        Ok(references) => {
            cleanup?;
            result.extend(references);
            Ok(result)
        }
        Err(error) => {
            let _ = cleanup;
            Err(error)
        }
    }
}

async fn display_references_with<E: DomainStatementExecutor>(
    executor: &mut E,
    by_prefix: &HashMap<String, Vec<&str>>,
) -> Result<HashMap<String, Option<String>>> {
    let mut result = HashMap::new();
    for (prefix, group_ids) in by_prefix {
        let rows = prefix_rows_with(executor, prefix).await?;
        for id in group_ids {
            result.insert(id.to_string(), display_reference_from_rows(id, &rows));
        }
    }
    Ok(result)
}

/// The canonical dashed prefix an abbreviation stands for, if it is one.
///
/// `records.id` stores the dashed rendering, and below eight characters a
/// dash-free abbreviation is indistinguishable from the raw id — they only
/// diverge at the ninth. Caller input is therefore normalised by stripping
/// dashes and re-inserting them at the canonical positions, so `a1b2c3d4e` and
/// `a1b2c3d4-e` both compare against the stored form.
///
/// Uppercase hex is accepted on input and folded down. The *stored* domain
/// stays lowercase-only: a UUID minted by the engine is `Uuid::to_string`,
/// which is lowercase, and an uppercase id could only have arrived through
/// caller-supplied `create_record.id` — the caller-chosen namespace, which
/// rule 2 keeps out of prefix matching entirely.
fn canonical_prefix(input: &str) -> Option<String> {
    let mut hex = String::with_capacity(UUID_HEX);
    for byte in input.bytes() {
        match byte {
            b'-' => {}
            b'0'..=b'9' | b'a'..=b'f' => hex.push(byte as char),
            b'A'..=b'F' => hex.push(byte.to_ascii_lowercase() as char),
            _ => return None,
        }
    }
    if hex.len() < MIN_PREFIX_HEX || hex.len() >= UUID_HEX {
        return None;
    }
    let mut prefix = String::with_capacity(hex.len() + 4);
    for (index, character) in hex.chars().enumerate() {
        if matches!(index, 8 | 12 | 16 | 20) {
            prefix.push('-');
        }
        prefix.push(character);
    }
    Some(prefix)
}

/// The stored shape prefix matching is allowed to see: 8-4-4-4-12 lowercase
/// hex. Everything else in `records.id` — `native:root`, `order-one`, an
/// uppercase UUID a caller minted by hand — belongs to the caller-chosen
/// namespace and is reachable only by its exact id.
pub(crate) fn is_canonical_uuid_v4_or_v7(id: &str) -> bool {
    let Ok(uuid) = uuid::Uuid::parse_str(id) else {
        return false;
    };
    matches!(
        uuid.get_version(),
        Some(uuid::Version::Random | uuid::Version::SortRand)
    ) && uuid.hyphenated().to_string() == id
}

fn is_canonical_uuid(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.len() != UUID_LEN {
        return false;
    }
    bytes.iter().enumerate().all(|(index, byte)| {
        if matches!(index, 8 | 13 | 18 | 23) {
            *byte == b'-'
        } else {
            byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
        }
    })
}

/// Visit every argument value that addresses an existing record.
fn walk(value: &mut Value, top_level: bool, tool: &str, visit: &mut impl FnMut(&mut String)) {
    match value {
        Value::Object(map) => walk_object(map, top_level, tool, visit),
        Value::Array(items) => {
            for item in items {
                walk(item, false, tool, visit);
            }
        }
        _ => {}
    }
}

fn walk_object(
    map: &mut Map<String, Value>,
    top_level: bool,
    tool: &str,
    visit: &mut impl FnMut(&mut String),
) {
    // A mention's `target_id` is a principal, not a record, when its sibling
    // discriminator says so. This is the one place on the surface where an
    // allowlisted key changes namespace, and it is read off the same object
    // rather than off a per-tool table.
    let principal_target = matches!(
        map.get("target_kind").and_then(Value::as_str),
        Some("principal")
    );
    for (key, entry) in map.iter_mut() {
        let addresses_a_record = if top_level && tool == "update_record" && key == "ids" {
            // The bounded homogeneous form deliberately requires exact full
            // target ids. Keep singular update_record.id and its human-friendly
            // prefix resolution unchanged, and continue resolving other record
            // arguments such as the shared home_id.
            false
        } else if key == "id" {
            top_level && TOP_LEVEL_ID_ADDRESSES_A_RECORD.contains(&tool)
        } else if key == "target_id" && principal_target {
            false
        } else {
            RECORD_ID_KEYS.contains(&key.as_str())
        };
        if addresses_a_record {
            visit_strings(entry, visit);
        }
        walk(entry, false, tool, visit);
    }
}

fn visit_strings(value: &mut Value, visit: &mut impl FnMut(&mut String)) {
    match value {
        Value::String(text) => visit(text),
        Value::Array(items) => {
            for item in items {
                if let Value::String(text) = item {
                    visit(text);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn abbreviations_are_recognised_only_between_the_floor_and_a_whole_uuid() {
        assert_eq!(canonical_prefix("abc12"), None, "below the six-hex floor");
        assert_eq!(canonical_prefix("abc123").as_deref(), Some("abc123"));
        assert_eq!(
            canonical_prefix("0123456789").as_deref(),
            Some("01234567-89"),
            "the dash is re-inserted at the canonical position"
        );
        assert_eq!(
            canonical_prefix("01234567-89").as_deref(),
            Some("01234567-89"),
            "a dashed abbreviation normalises to the same prefix"
        );
        assert_eq!(
            canonical_prefix("ABC123").as_deref(),
            Some("abc123"),
            "uppercase hex folds to the stored lowercase domain"
        );
        assert_eq!(canonical_prefix("order-one"), None, "not hex");
        assert_eq!(canonical_prefix("native:root"), None, "not hex");
        assert_eq!(
            canonical_prefix("0123456789abcdef0123456789abcdef"),
            None,
            "a whole UUID is not an abbreviation"
        );
    }

    #[test]
    fn the_sentinel_bounds_every_character_a_canonical_uuid_can_continue_with() {
        // The bound is only sound because the matched domain is exactly this
        // set. Anything admitted here that sorts at or above the sentinel
        // would silently fall out of the range scan.
        for character in "0123456789abcdef-".chars() {
            assert!(
                character < PREFIX_SENTINEL,
                "{character:?} escapes the prefix range bound"
            );
        }
    }

    /// The range bound exists for one reason and it is not readability.
    ///
    /// `records.id` is `TEXT PRIMARY KEY`, and the obvious spelling —
    /// `id LIKE ? || '%'` — does not fold into index bounds: the planner
    /// degrades it to a scan of the whole table. This asserts the difference
    /// directly, so a future simplification back to `LIKE` fails here instead
    /// of quietly turning every abbreviated id into a table scan.
    #[tokio::test]
    async fn the_candidate_scan_searches_the_primary_key_rather_than_scanning() {
        use sqlx::Row as _;
        let db = crate::create_database(":memory:").await.unwrap();
        let bounded: String = sqlx::query(&format!("EXPLAIN QUERY PLAN {CANDIDATE_SQL}"))
            .bind("abc123")
            .bind("abc123g")
            .bind(UUID_LEN as i64)
            .bind(MAX_CANDIDATES)
            .fetch_one(db.pool())
            .await
            .unwrap()
            .get("detail");
        assert!(
            bounded.contains("SEARCH") && bounded.contains("id>? AND id<?"),
            "the range bound must reach the primary key index: {bounded}"
        );

        let liked: String =
            sqlx::query("EXPLAIN QUERY PLAN SELECT id FROM records WHERE id LIKE ? || '%'")
                .bind("abc123")
                .fetch_one(db.pool())
                .await
                .unwrap()
                .get("detail");
        assert!(
            liked.contains("SCAN"),
            "the LIKE spelling is supposed to be the slow one: {liked}"
        );

        // The portable authorization fold must retain the governed
        // attribution carve-out while it is using the bounded range.
        let attribution_id = "a7700011-0000-4000-8000-000000000001";
        sqlx::query(
            "INSERT INTO records(id,type,kind,name,created_at,updated_at) \
             VALUES(?,'Annotation','attribution','Hidden attribution','2026-08-16','2026-08-16')",
        )
        .bind(attribution_id)
        .execute(db.write_pool())
        .await
        .unwrap();

        let resolved = resolve_record_ids(
            &EngineHandle::Sqlite(db.clone()),
            &Caller::local(),
            "get_record",
            json!({"ids":["a77000"]}),
        )
        .await
        .unwrap();
        assert_eq!(resolved["ids"][0], "a77000");

        let closed_engine = EngineHandle::Sqlite(db.clone());
        db.close().await;
        let untouched = resolve_record_ids(
            &closed_engine,
            &Caller::local(),
            "get_record",
            json!({"ids":["native:root", attribution_id]}),
        )
        .await
        .expect("the no-abbreviation path must not enter the closed backend");
        assert_eq!(untouched, json!({"ids":["native:root", attribution_id]}));
    }

    #[test]
    fn only_the_canonical_lowercase_shape_is_a_prefix_candidate() {
        assert!(is_canonical_uuid("0189d4c6-1f2a-4a1b-9c3d-5e6f70819293"));
        assert!(is_canonical_uuid("0189d4c6-1f2a-7a1b-9c3d-5e6f70819293"));
        assert!(is_canonical_uuid("0189d4c6-1f2a-1a1b-9c3d-5e6f70819293"));
        assert!(is_canonical_uuid("0189d4c6-1f2a-5a1b-9c3d-5e6f70819293"));
        assert!(!is_canonical_uuid("0189D4C6-1F2A-4A1B-9C3D-5E6F70819293"));
        assert!(!is_canonical_uuid("0189d4c61f2a4a1b9c3d5e6f70819293"));
        assert!(!is_canonical_uuid("native:root"));
        assert!(!is_canonical_uuid("order-one"));
    }

    #[test]
    fn exact_record_ids_accept_only_canonical_lowercase_uuid_v4_or_v7() {
        assert!(is_canonical_uuid_v4_or_v7(
            "0189d4c6-1f2a-4a1b-9c3d-5e6f70819293"
        ));
        assert!(is_canonical_uuid_v4_or_v7(
            "0189d4c6-1f2a-7a1b-9c3d-5e6f70819293"
        ));
        assert!(!is_canonical_uuid_v4_or_v7(
            "0189d4c6-1f2a-1a1b-9c3d-5e6f70819293"
        ));
        assert!(!is_canonical_uuid_v4_or_v7(
            "0189d4c6-1f2a-5a1b-9c3d-5e6f70819293"
        ));
        assert!(!is_canonical_uuid_v4_or_v7(
            "0189D4C6-1F2A-4A1B-9C3D-5E6F70819293"
        ));
    }

    /// Insert bare rows straight into `records`, bypassing the write path.
    ///
    /// `display_reference` reads exactly three columns and the projection has
    /// no say in any of them, so seeding through `create_record` would only add
    /// a slower way to arrive at the same table.
    async fn seed(db: &Db, ids: &[&str]) {
        for id in ids {
            sqlx::query(
                "INSERT INTO records (id, type, name, created_at, updated_at) \
                 VALUES (?, 'Document', 'seed', '2026-08-12', '2026-08-12')",
            )
            .bind(id)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn a_reference_is_seven_digits_until_a_collision_forces_it_longer() {
        let db = crate::create_database(":memory:").await.unwrap();
        let lonely = "0189d4c6-1f2a-4a1b-9c3d-5e6f70819293";
        // Shares six digits with `lonely`, which is one short of the floor and
        // must therefore leave the reference at seven.
        let near = "0189d4a0-1f2a-4a1b-9c3d-5e6f70819293";
        // Shares eight, so seven and eight are both ambiguous and the answer is
        // nine — the shortest that discriminates, not merely a longer one.
        let colliding = "0189d4c6-2f2a-4a1b-9c3d-5e6f70819293";
        seed(&db, &[lonely, near]).await;
        assert_eq!(
            display_reference(&db, lonely).await.unwrap().as_deref(),
            Some("0189d4c"),
            "a six-digit neighbour does not reach the floor"
        );

        seed(&db, &[colliding]).await;
        assert_eq!(
            display_reference(&db, lonely).await.unwrap().as_deref(),
            Some("0189d4c61"),
            "eight shared digits push the reference to nine"
        );
        assert_eq!(
            display_reference(&db, colliding).await.unwrap().as_deref(),
            Some("0189d4c62"),
            "and the record it collided with lengthens with it, to its own prefix"
        );
        db.close().await;
    }

    /// The two halves have to agree, or the affordance mints dead addresses.
    #[tokio::test]
    async fn every_reference_minted_here_resolves_back_to_its_own_record() {
        let db = crate::create_database(":memory:").await.unwrap();
        let ids = [
            "0189d4c6-1f2a-4a1b-9c3d-5e6f70819293",
            "0189d4c6-1f2b-4a1b-9c3d-5e6f70819293",
            "7f3e21a9-0000-4000-8000-000000000001",
        ];
        seed(&db, &ids).await;
        for id in ids {
            let reference = display_reference(&db, id).await.unwrap().unwrap();
            let prefix = canonical_prefix(&reference)
                .expect("a minted reference must still read as an abbreviation");
            assert_eq!(
                prefix_candidates(&db, &prefix).await.unwrap(),
                vec![id.to_string()],
                "reference {reference} must match {id} alone"
            );
        }
        db.close().await;
    }

    /// A shared link to a deleted record must not resolve.
    ///
    /// The one place the URL boundary parts company with the tool boundary.
    /// `record_exists_with` sees tombstones on purpose so an abbreviation
    /// cannot step over a deleted record onto a live one; a whole id arriving
    /// in a link is asking to be opened, and `Resolved` would hand the
    /// workbench a record it cannot render. Both spellings must answer alike,
    /// and the tool boundary must be untouched.
    #[tokio::test]
    async fn a_tombstoned_record_does_not_resolve_at_the_url_boundary() {
        let db = crate::create_database(":memory:").await.unwrap();
        let live = "0189d4c6-1f2a-4a1b-9c3d-5e6f70819293";
        let tombstoned = "7f3e21a9-0000-4000-8000-000000000001";
        seed(&db, &[live, tombstoned]).await;
        sqlx::query("UPDATE records SET deleted_at = '2026-08-12' WHERE id = ?")
            .bind(tombstoned)
            .execute(db.write_pool())
            .await
            .unwrap();

        for reference in [tombstoned, "7f3e21a"] {
            assert!(
                matches!(
                    resolve_reference(&db, &Caller::local(), reference)
                        .await
                        .unwrap(),
                    ReferenceResolution::Unresolved
                ),
                "{reference} must not resolve"
            );
        }
        assert!(matches!(
            resolve_reference(&db, &Caller::local(), live).await.unwrap(),
            ReferenceResolution::Resolved(id) if id == live
        ));

        // The tool boundary is unchanged: the id is still taken, so it passes
        // through untouched rather than resolving onto anything.
        assert_eq!(
            resolve_record_ids(
                &EngineHandle::Sqlite(db.clone()),
                &Caller::local(),
                "get_record",
                json!({ "id": tombstoned }),
            )
            .await
            .unwrap(),
            json!({ "id": tombstoned })
        );
        db.close().await;
    }

    #[tokio::test]
    async fn deleted_records_are_invisible_to_both_halves_alike() {
        let db = crate::create_database(":memory:").await.unwrap();
        let live = "0189d4c6-1f2a-4a1b-9c3d-5e6f70819293";
        let tombstoned = "0189d4c6-1f2b-4a1b-9c3d-5e6f70819293";
        seed(&db, &[live, tombstoned]).await;
        sqlx::query("UPDATE records SET deleted_at = '2026-08-12' WHERE id = ?")
            .bind(tombstoned)
            .execute(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            display_reference(&db, live).await.unwrap().as_deref(),
            Some("0189d4c"),
            "a tombstoned collision cannot lengthen a reference resolution ignores"
        );
        db.close().await;
    }

    /// The ambiguity message is a parsed interface, not just prose.
    ///
    /// `web/workbench/src/model/recordReference.ts::parseAmbiguousReference`
    /// reads this string to build the workbench's ambiguity surface — the one
    /// that names the candidates instead of showing a bare error card. There is
    /// no structured error payload for it to read instead, so the wording is
    /// load-bearing, and a rename would otherwise degrade that surface silently:
    /// the parser returns `null`, the UI quietly falls back, and every suite
    /// stays green. **This test exists so that a wording change fails here
    /// instead.**
    ///
    /// It pins only the three facts the parser actually extracts. The rest of
    /// the sentence is deliberately left free — pinning it whole would build a
    /// golden that fails on harmless edits and trains people to update it
    /// without reading why it broke.
    #[tokio::test]
    async fn the_ambiguity_message_keeps_the_three_facts_its_reader_parses() {
        let db = crate::create_database(":memory:").await.unwrap();
        // Two ids sharing exactly seven leading hex digits, so the reference at
        // the display floor genuinely matches both. Provoked through
        // `resolve_record_ids` rather than by hand-building the string, which
        // is the whole point: the assertion has to see what the engine emits.
        let twins = [
            "0189aabb-1111-4000-8000-000000000001",
            "0189aabc-2222-4000-8000-000000000002",
        ];
        seed(&db, &twins).await;
        let error = resolve_record_ids(
            &EngineHandle::Sqlite(db.clone()),
            &Caller::local(),
            "get_record",
            json!({ "ids": ["0189aab"] }),
        )
        .await
        .expect_err("a reference matching both twins must not resolve to either");
        let message = error.to_string();

        assert!(
            message.contains("ambiguous"),
            "the parser gates on the word 'ambiguous': {message}"
        );
        assert!(
            message.contains("prefix '0189aab'"),
            "the parser reads the reference back out of `prefix '<ref>'`: {message}"
        );
        let named = message
            .split([' ', ','])
            .filter(|token| is_canonical_uuid(token))
            .count();
        assert!(
            named >= 2,
            "the surface can only offer a choice if the message names every \
             candidate as a full dashed id; found {named} in: {message}"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn caller_chosen_ids_are_offered_no_reference_at_all() {
        let db = crate::create_database(":memory:").await.unwrap();
        // Uppercase is the interesting one: it is UUID-*shaped* yet outside the
        // stored domain rule 2 admits, so an abbreviation of it would be an
        // address `resolve_one` could never honour.
        seed(&db, &["order-one", "0189D4C6-1F2A-4A1B-9C3D-5E6F70819293"]).await;
        // `native:root` needs no seeding — genesis installs it, which is the
        // reminder that this namespace is not hypothetical.
        for id in [
            "order-one",
            crate::schema::contract::ROOT_RECORD_ID,
            "0189D4C6-1F2A-4A1B-9C3D-5E6F70819293",
        ] {
            assert_eq!(
                display_reference(&db, id).await.unwrap(),
                None,
                "{id} is not prefix-addressable"
            );
        }
        db.close().await;
    }

    #[tokio::test]
    async fn batch_display_references_share_one_prefix_scan_per_seed() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut ids = Vec::new();
        for index in 0..20 {
            ids.push(format!(
                "0189d4c{:x}-{:04x}-4a1b-9c3d-5e6f708192a3",
                index % 16,
                index / 16
            ));
            assert!(
                is_canonical_uuid(ids.last().unwrap()),
                "fixture ids must be canonical UUIDs"
            );
        }
        seed(&db, &ids.iter().map(String::as_str).collect::<Vec<_>>()).await;
        let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();

        reset_prefix_row_query_count();
        let references = display_references(&db, &id_refs).await.unwrap();
        assert_eq!(references.len(), ids.len());
        for id in &ids {
            assert!(
                references
                    .get(id)
                    .is_some_and(|reference| reference.is_some()),
                "{id} must resolve to a short reference in an unsaturated batch"
            );
        }
        assert_eq!(
            prefix_row_query_count(),
            1,
            "every id shares one seven-hex seed, so one prefix scan must suffice"
        );

        reset_prefix_row_query_count();
        let doubled: Vec<&str> = id_refs
            .iter()
            .copied()
            .chain(id_refs.iter().copied())
            .collect();
        display_references(&db, &doubled).await.unwrap();
        assert_eq!(
            prefix_row_query_count(),
            1,
            "doubling N must not double prefix scans when the seed is shared"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn batch_display_references_keep_saturation_per_prefix_group() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut saturated_ids = Vec::new();
        for index in 0..=MAX_CANDIDATES as usize {
            saturated_ids.push(format!(
                "0189d4c{:x}-{:04x}-4000-8000-000000000001",
                index % 16,
                index / 16
            ));
        }
        seed(
            &db,
            &saturated_ids.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .await;
        let lonely = "7f3e21a9-0000-4000-8000-000000000001";
        seed(&db, &[lonely]).await;

        let batch = display_references(
            &db,
            &[saturated_ids[0].as_str(), lonely, saturated_ids[1].as_str()],
        )
        .await
        .unwrap();
        assert_eq!(batch.get(&saturated_ids[0]), Some(&None));
        assert_eq!(batch.get(&saturated_ids[1]), Some(&None));
        assert_eq!(
            batch.get(lonely).map(Option::as_deref),
            Some(Some("7f3e21a")),
            "an unsaturated prefix group must not inherit saturation from another"
        );
        db.close().await;
    }

    fn collected(tool: &str, mut arguments: Value) -> Vec<String> {
        let mut seen = Vec::new();
        walk(&mut arguments, true, tool, &mut |text| {
            seen.push(text.clone());
        });
        seen.sort();
        seen
    }

    #[test]
    fn create_record_addresses_records_everywhere_except_its_own_new_id() {
        let seen = collected(
            "create_record",
            json!({
                "id": "assert-new",
                "type": "Document",
                "kind": "note",
                "home_id": "home",
                "owner_id": "owner",
                "links": [{ "target_id": "linked", "relationship": "relates_to" }],
                "mentions": [
                    { "mention_id": "mint", "target_kind": "record", "target_id": "mentioned" },
                    { "mention_id": "mint", "target_kind": "principal", "target_id": "acct:someone" }
                ],
                "target": { "target_record_id": "annotated" }
            }),
        );
        assert_eq!(
            seen,
            vec!["annotated", "home", "linked", "mentioned", "owner"],
            "`id`, `mention_id` and a principal `target_id` must never resolve"
        );
    }

    #[test]
    fn top_level_id_is_gated_by_tool() {
        assert_eq!(collected("update_record", json!({ "id": "x" })), ["x"]);
        assert!(collected("manage_vocabularies", json!({ "id": "x" })).is_empty());
        assert!(collected("manage_messages", json!({ "id": "x" })).is_empty());
    }

    #[test]
    fn arrays_of_ids_are_visited_element_by_element() {
        assert_eq!(
            collected("get_record", json!({ "ids": ["one", "two"] })),
            ["one", "two"]
        );
        assert_eq!(
            collected(
                "query_record",
                json!({ "steps": [{ "step": "filter", "ids": ["deep"], "ancestor_id": "root" }] })
            ),
            ["deep", "root"]
        );
        assert_eq!(
            collected(
                "update_record",
                json!({ "ids": ["exact-only"], "home_id": "destination" })
            ),
            ["destination"],
            "multi-target ids remain exact while the shared destination keeps ordinary resolution"
        );
    }
}
