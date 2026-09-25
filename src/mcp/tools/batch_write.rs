//! Tool — `batch_write`: one atomic batch of existing single-record writes.
//!
//! Experiment 0 of the write-side note (E4 M0): a list of `update_record`
//! field/facet patches, `manage_links.add` link additions and
//! `archive_record` transitions, submitted under one `reason`, one
//! batch-level `sources` basis and one `idempotency_key`, committing all or
//! nothing. Events are built by the same leaf helpers as the singular paths
//! (`parse_facet_entry`, `facet_set_spec`, `append_in`, the legacy link
//! adapter); the batch owns only the shared transaction, the per-item
//! orchestration, and the per-item/batch attestations.
//!
//! SQLite only: like `create_many`/`create_exploration`, this tool registers
//! on the SQLite surface alone. Turso-local and Postgres registries list
//! every supported tool explicitly and do not register it.

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::Capability;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::events::LinkAddedPayload;
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::mcp::ToolKind;
use crate::provenance::ActionOutput;
use crate::store::{append_in, AppendSpec};

use super::lifecycle::{
    assert_facet_value_predicates_in, assert_home_target_in, assert_no_containment_cycle_in,
    attach_basis_feedback, body_digest, facet_set_spec, facet_state_in, parse_facet_entry,
    required_violations_in, resolve_source_basis_in, source_basis_input_schema,
    stale_body_digest_error, stale_unmodified_since_error, BodyGuardTarget, SourceBasisInput,
};
use super::links::relationship_owned_in;
use super::{
    attested_act_in, echo_act, parse_args, previous_record_seq_in, require_nonblank_reason,
    require_record_in, require_workspace_rename_authority, REASON_DESCRIPTION,
};

const TOOL: &str = "batch_write";
/// One batch covers at most 25 heterogeneous items: bounded validation,
/// bounded diagnostics, and a bounded single-writer critical section.
pub(crate) const MAX_BATCH_WRITE: usize = 25;
/// Atomic rejections keep diagnostics useful without echoing an unbounded
/// batch through the error channel (mirrors the multi-update cap).
const MAX_BATCH_WRITE_FAILURE_DETAILS: usize = 20;

/// Deserialize a present-but-null field as `Some(Null)` (mirrors the
/// `present` helper on `update_record`'s arguments): absent means untouched,
/// explicit null means clear.
fn present<'de, D>(deserializer: D) -> std::result::Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchWriteArgs {
    reason: String,
    sources: Option<Vec<SourceBasisInput>>,
    idempotency_key: Option<String>,
    items: Vec<BatchItem>,
}

#[derive(Deserialize)]
#[allow(clippy::large_enum_variant)] // request-shape enum; the Update arm is large but batches are small
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum BatchItem {
    Update {
        id: String,
        #[serde(default, deserialize_with = "present")]
        name: Option<Value>,
        #[serde(default, deserialize_with = "present")]
        summary: Option<Value>,
        #[serde(default, deserialize_with = "present")]
        maturity: Option<Value>,
        home_id: Option<String>,
        facets: Option<Map<String, Value>>,
        if_facets: Option<Map<String, Value>>,
        #[serde(default, deserialize_with = "present")]
        if_maturity: Option<Value>,
        if_home_id: Option<String>,
        if_body_digest: Option<String>,
        if_unmodified_since: Option<String>,
    },
    AddLink {
        source_id: String,
        target_id: String,
        relationship: String,
        note: Option<String>,
    },
    Archive {
        id: String,
        archived: Option<bool>,
    },
}

impl BatchItem {
    fn op(&self) -> &'static str {
        match self {
            BatchItem::Update { .. } => "update",
            BatchItem::AddLink { .. } => "add_link",
            BatchItem::Archive { .. } => "archive",
        }
    }

    fn id(&self) -> &str {
        match self {
            BatchItem::Update { id, .. } | BatchItem::Archive { id, .. } => id,
            BatchItem::AddLink { source_id, .. } => source_id,
        }
    }
}

struct BatchIssue {
    index: usize,
    op: &'static str,
    id: String,
    classification: &'static str,
    message: String,
}

pub fn register_batch_write_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::BatchWrite,
        "Atomic batch of up to 25 existing-record writes under one reason and idempotency key: update_record-style field/facet patches (name, summary, maturity, home_id, facets), manage_links.add link additions, and archive_record transitions. Every item authorizes and validates first; one failing item refuses the whole batch with nothing written, naming the item index. A keyed replay re-checks View on every disclosed record and returns the original receipt without writing, so a caller demoted since the first call can still replay but cannot execute a new batch. Body operations are refused in M0 — use update_record for body edits. SQLite only; Turso-local and Postgres do not offer this tool.",
        json!({
            "type": "object",
            "properties": {
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION },
                "sources": source_basis_input_schema(),
                "idempotency_key": { "type": "string", "description": "Retry-safety key for the whole batch: on ambiguous failure, retry with the SAME key, never a fresh one. An identical retry returns the original receipt and appends nothing; the same key with different content is rejected. With no key, every call writes." },
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "description": "Heterogeneous write items, applied in order; at most 25 per call.",
                    "items": {
                        "oneOf": [
                            {
                                "type": "object",
                                "properties": {
                                    "op": { "const": "update" },
                                    "id": { "type": "string" },
                                    "name": { "type": "string" },
                                    "summary": { "type": ["string", "null"] },
                                    "maturity": { "type": ["string", "null"] },
                                    "home_id": { "type": "string" },
                                    "facets": { "type": "object", "additionalProperties": true },
                                    "if_facets": { "type": "object", "additionalProperties": true },
                                    "if_maturity": { "type": ["string", "null"] },
                                    "if_home_id": { "type": "string" },
                                    "if_body_digest": { "type": "string" },
                                    "if_unmodified_since": { "type": "string" }
                                },
                                "required": ["op", "id"],
                                "additionalProperties": false
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "op": { "const": "add_link" },
                                    "source_id": { "type": "string" },
                                    "target_id": { "type": "string" },
                                    "relationship": { "type": "string" },
                                    "note": { "type": "string" }
                                },
                                "required": ["op", "source_id", "target_id", "relationship"],
                                "additionalProperties": false
                            },
                            {
                                "type": "object",
                                "properties": {
                                    "op": { "const": "archive" },
                                    "id": { "type": "string" },
                                    "archived": { "type": "boolean" }
                                },
                                "required": ["op", "id"],
                                "additionalProperties": false
                            }
                        ]
                    }
                }
            },
            "required": ["reason", "items"],
            "additionalProperties": false
        }),
        batch_write,
    )
}

async fn batch_write(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    // The provenance digests run over the raw tool arguments: no server-minted
    // id enters the conflict detector, or every retry would conflict with the
    // call it repeats. Run-context keys are stripped by the digest itself.
    let provenance_arguments = arguments.clone();
    let args: BatchWriteArgs = parse_args(TOOL, arguments)?;
    require_nonblank_reason(TOOL, &args.reason)?;
    if args.items.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: items must contain at least one item"
        )));
    }
    if args.items.len() > MAX_BATCH_WRITE {
        return Err(Error::engine(format!(
            "{TOOL}: at most {MAX_BATCH_WRITE} items may be written per call (got {}); split the batch",
            args.items.len()
        )));
    }
    let key = match args.idempotency_key.as_deref() {
        None | Some("") => None,
        Some(key) if key.trim().is_empty() => None,
        Some(key) if key.len() > 200 => {
            return Err(Error::engine(format!(
                "{TOOL}: idempotency_key must be 1..200 characters"
            )));
        }
        Some(key) => Some(key.to_string()),
    };
    for (index, item) in args.items.iter().enumerate() {
        match item {
            BatchItem::Update {
                id,
                name,
                summary,
                maturity,
                home_id,
                facets,
                if_facets,
                ..
            } => {
                if !crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(id) {
                    return Err(Error::engine(format!(
                        "{TOOL}: items[{index}].id must be an exact canonical lowercase UUID of version 4 or 7"
                    )));
                }
                // An update item that changes nothing is refused up front,
                // following the singular no-changes guard rather than silently
                // riding the batch as unchanged.
                if name.is_none()
                    && summary.is_none()
                    && maturity.is_none()
                    && home_id.is_none()
                    && facets.as_ref().is_none_or(Map::is_empty)
                {
                    return Err(Error::engine(format!(
                        "{TOOL}: items[{index}] names no changes — pass at least one field or facet"
                    )));
                }
                if if_facets.as_ref().is_some_and(Map::is_empty) {
                    return Err(Error::engine(format!(
                        "{TOOL}: items[{index}].if_facets must not be empty when supplied"
                    )));
                }
            }
            BatchItem::Archive { id, .. } => {
                if !crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(id) {
                    return Err(Error::engine(format!(
                        "{TOOL}: items[{index}].id must be an exact canonical lowercase UUID of version 4 or 7"
                    )));
                }
            }
            BatchItem::AddLink {
                source_id,
                target_id,
                ..
            } => {
                for (field, value) in [("source_id", source_id), ("target_id", target_id)] {
                    if !crate::mcp::record_ref::is_canonical_uuid_v4_or_v7(value) {
                        return Err(Error::engine(format!(
                            "{TOOL}: items[{index}].{field} must be an exact canonical lowercase UUID of version 4 or 7"
                        )));
                    }
                }
            }
        }
    }
    // One record per batch: a record mutated twice would make guards,
    // previous seqs, and the replay receipt order-dependent. Link targets
    // are not mutated, so many-to-one fans (W2) stay legal.
    {
        let mut seen = std::collections::BTreeMap::new();
        for (index, item) in args.items.iter().enumerate() {
            let primary: &str = match item {
                BatchItem::Update { id, .. } | BatchItem::Archive { id, .. } => id,
                BatchItem::AddLink { source_id, .. } => source_id,
            };
            if let Some(first) = seen.insert(primary, index) {
                return Err(Error::engine(format!(
                    "{TOOL}: items[{index}] duplicates items[{first}] ({primary}); a record may appear in only one item per batch"
                )));
            }
        }
    }

    // ONE transaction. Authorization for the whole cohort completes before any
    // lookup or mutation; every item's appends then apply in order inside the
    // same `BEGIN IMMEDIATE` transaction, so any failure rolls everything
    // back and the batch commits all or nothing.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    let basis = resolve_source_basis_in(&mut tx, &caller, TOOL, args.sources.as_deref()).await?;
    let schema_rows = crate::query::cascade::schema_config_rows_in(&mut tx).await?;
    let mut issues = Vec::new();
    authorize_cohort_in(&mut tx, &caller, &args.items, &mut issues).await?;

    // Idempotent replay, after shape validation, basis resolution and the
    // cohort authorization attempt. On a miss the cohort issues refuse the
    // call, so the tool cannot become a command-existence oracle. On a hit
    // the cohort issues are set aside: the anchor's whole-request digest
    // proves the identical request already committed under this principal,
    // and only View on every disclosed record is re-checked. A replay
    // returns a past receipt and performs no new write, so a caller demoted
    // since the original call can still replay it but cannot execute a new
    // batch.
    if let Some(key_str) = key.as_deref() {
        if let Some(hit) = lookup_batch_hit_in(
            &mut tx,
            &caller,
            &provenance_arguments,
            &args.items,
            key_str,
        )
        .await?
        {
            for (index, item) in args.items.iter().enumerate() {
                let ids: Vec<&str> = match item {
                    BatchItem::Update { id, .. } | BatchItem::Archive { id, .. } => vec![id],
                    BatchItem::AddLink {
                        source_id,
                        target_id,
                        ..
                    } => vec![source_id, target_id],
                };
                for id in ids {
                    if require_record_in(&mut tx, &caller, TOOL, id, Capability::View)
                        .await
                        .is_err()
                    {
                        return Err(batch_rejection(
                            args.items.len(),
                            vec![unavailable_issue(&args.items, index)],
                        ));
                    }
                }
            }
            let receipt = rebuild_hit_receipt_in(&db, &mut tx, &caller, &args, &hit).await?;
            tx.rollback().await?;
            for (_, attestation_id) in &hit.found {
                crate::provenance::note_replayed_action_attestation(attestation_id.clone());
            }
            crate::provenance::note_replayed_action_attestation(hit.anchor.clone());
            return Ok(receipt);
        }
    }
    if !issues.is_empty() {
        return Err(batch_rejection(args.items.len(), issues));
    }

    let touched: Vec<&str> = args
        .items
        .iter()
        .filter(|item| !matches!(item, BatchItem::AddLink { .. }))
        .map(BatchItem::id)
        .collect();
    let before = required_violations_in(&mut tx, &schema_rows, &touched).await?;
    let mut state = BatchState::new(&args.reason, basis);
    for (index, item) in args.items.iter().enumerate() {
        if let Err(issue) = apply_item_in(
            &db,
            &mut tx,
            &caller,
            &schema_rows,
            &key,
            &mut state,
            &mut act_alloc,
            index,
            item,
        )
        .await
        {
            issues.push(issue);
            break;
        }
    }
    if !issues.is_empty() {
        return Err(batch_rejection(args.items.len(), issues));
    }
    // The batch anchor: one output-less command attestation per keyed
    // batch, even an all-unchanged one, so every key leaves exactly one row
    // the key lookup finds. Per-item rows alone cannot do this — unchanged
    // items store none.
    if key.is_some() {
        crate::provenance::issue_empty_command_attestation_in(&mut tx).await?;
    }
    // Each projected home change already refreshes its subtree. Repeat the
    // refreshes after the complete cohort has reached its final graph — same
    // as update_record_multi — so inherited anchors cannot depend on the
    // event order of related targets.
    for id in &state.relocated {
        crate::authorization::refresh_policy_anchor_subtree(&mut tx, id).await?;
    }
    let after = required_violations_in(&mut tx, &schema_rows, &touched).await?;
    crate::domain_transaction::assert_required_not_worsened(TOOL, &before, &after)?;
    db.commit_content(tx).await?;

    let mut receipt = json!({
        "requested": args.items.len(),
        "changed": state.changed,
        "unchanged": args.items.len() - state.changed,
        "results": state.results,
    });
    if !state.warnings.is_empty() {
        receipt["warnings"] = Value::Array(state.warnings);
    }
    receipt = echo_act(receipt, act_alloc.get())?;
    let mut receipt = receipt;
    attach_basis_feedback(
        &db,
        &caller,
        &mut receipt,
        args.sources.as_ref().map(Vec::len),
        false,
    )
    .await;
    Ok(receipt)
}

struct BatchState {
    reason: String,
    basis: Option<Value>,
    changed: usize,
    results: Vec<Value>,
    warnings: Vec<Value>,
    relocated: Vec<String>,
}

impl BatchState {
    fn new(reason: &str, basis: Option<Value>) -> Self {
        Self {
            reason: reason.to_string(),
            basis,
            changed: 0,
            results: Vec::new(),
            warnings: Vec::new(),
            relocated: Vec::new(),
        }
    }
}

fn unavailable_issue(items: &[BatchItem], index: usize) -> BatchIssue {
    BatchIssue {
        index,
        op: items[index].op(),
        id: items[index].id().to_string(),
        classification: "unavailable",
        message: "record is unavailable".into(),
    }
}

/// Authorize the whole cohort before any lookup or mutation, mirroring
/// `update_record_multi`: relocation can change inherited policy anchors, so
/// authority must not depend on request order. Every failure — missing,
/// hidden, or under-authorized — reports `unavailable` with the item index.
async fn authorize_cohort_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    items: &[BatchItem],
    issues: &mut Vec<BatchIssue>,
) -> Result<()> {
    for (index, item) in items.iter().enumerate() {
        let authorized = match item {
            BatchItem::Update { id, home_id, .. } => {
                // A named home makes the write structural, following the
                // singular path: Manage is required whether or not the value
                // relocates, so Edit callers cannot probe home validity.
                let required = if home_id.is_some() {
                    Capability::Manage
                } else {
                    Capability::Edit
                };
                require_record_in(tx, caller, TOOL, id, required)
                    .await
                    .is_ok()
            }
            BatchItem::AddLink {
                source_id,
                target_id,
                ..
            } => {
                require_record_in(tx, caller, TOOL, source_id, Capability::Edit)
                    .await
                    .is_ok()
                    && require_record_in(tx, caller, TOOL, target_id, Capability::View)
                        .await
                        .is_ok()
            }
            BatchItem::Archive { id, .. } => {
                require_record_in(tx, caller, TOOL, id, Capability::Manage)
                    .await
                    .is_ok()
            }
        };
        if !authorized {
            issues.push(unavailable_issue(items, index));
        }
    }
    Ok(())
}

fn batch_rejection(requested: usize, issues: Vec<BatchIssue>) -> Error {
    let conflicted = issues
        .iter()
        .filter(|issue| issue.classification == "conflict")
        .count();
    let failed = issues.len() - conflicted;
    let omitted = issues.len().saturating_sub(MAX_BATCH_WRITE_FAILURE_DETAILS);
    let mut message = format!(
        "{TOOL}: atomic batch refused; nothing was written; requested={requested}, \
         changed=0, conflicted={conflicted}, failed={failed}"
    );
    for issue in issues.into_iter().take(MAX_BATCH_WRITE_FAILURE_DETAILS) {
        message.push_str(&format!(
            "\n  [{}] {} {} {}: {}",
            issue.index, issue.op, issue.id, issue.classification, issue.message
        ));
    }
    if omitted > 0 {
        message.push_str(&format!(
            "\n  details truncated; omitted_detail_count={omitted}"
        ));
    }
    if failed == 0 {
        Error::conflict(message)
    } else {
        Error::engine(message)
    }
}

/// Per-item command-identity digest: the batch key bound to the item index.
/// Distinct items never share a digest, and the batch-level content is bound
/// separately by the whole-request `action_digest` check on any found row —
/// so no batch-level attestation row (and no schema change) is needed.
fn item_digest(key: &str, index: usize) -> String {
    crate::provenance::digest_json(&json!({"batch_write_key": key, "item": index}))
}

struct BatchHit {
    anchor: String,
    /// (item index, attestation id) for every changed item's attestation.
    /// Changed items always have rows; unchanged items never do.
    found: Vec<(usize, String)>,
}

/// Look up this exact batch by its anchor row, then load every changed
/// item's attestation. The anchor carries the whole-request digests, so a
/// match proves the identical request already committed; per-item rows
/// missing from the load are unchanged items. This closes two holes in a
/// per-item-only lookup: a retry with fewer changed items, and an
/// all-unchanged first call, both of which would otherwise miss every row
/// and commit a second effect under one key.
async fn lookup_batch_hit_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    provenance_arguments: &Value,
    items: &[BatchItem],
    key: &str,
) -> Result<Option<BatchHit>> {
    let Some(anchor) = crate::provenance::lookup_authorized_command_attestation_in(
        tx,
        caller.credential(),
        TOOL,
        provenance_arguments,
        caller.intent(),
    )
    .await?
    else {
        return Ok(None);
    };
    let digests: Vec<String> = (0..items.len()).map(|i| item_digest(key, i)).collect();
    let placeholders = digests.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
    let sql = format!(
        "SELECT a.id,l.command_identity_digest
           FROM provenance_action_attestations a
           JOIN provenance_local_attestation_authority l ON l.attestation_id=a.id
          WHERE l.principal=? AND l.operation=? AND l.command_identity_digest IN ({placeholders})"
    );
    let mut query = sqlx::query(&sql).bind(caller.credential()).bind(TOOL);
    for digest in &digests {
        query = query.bind(digest);
    }
    let mut found = Vec::new();
    for row in query.fetch_all(&mut **tx).await? {
        let digest: String = row.try_get("command_identity_digest")?;
        let Some(index) = digests.iter().position(|candidate| *candidate == digest) else {
            continue;
        };
        found.push((index, row.try_get("id")?));
    }
    found.sort_by_key(|(index, _)| *index);
    Ok(Some(BatchHit { anchor, found }))
}

fn issue(
    index: usize,
    item: &BatchItem,
    classification: &'static str,
    message: String,
) -> BatchIssue {
    BatchIssue {
        index,
        op: item.op(),
        id: item.id().to_string(),
        classification,
        message,
    }
}

/// Attest one item's outputs under its own identity: the batch key bound to
/// the item index when keyed (so a retry can locate every item without a
/// batch-level row), unkeyed otherwise. Items that appended nothing are
/// never attested.
async fn attest_item_in(
    tx: &mut Transaction<'static, Sqlite>,
    key: &Option<String>,
    index: usize,
    outputs: &[ActionOutput],
) -> Result<()> {
    if outputs.is_empty() {
        return Ok(());
    }
    let draft = match key {
        Some(key) => {
            crate::provenance::reserve_detached_action_attestation(Some(item_digest(key, index)))?
        }
        None => crate::provenance::reserve_unkeyed_action_attestation()?,
    };
    crate::provenance::issue_action_attestation_outputs_in(tx, draft, outputs).await?;
    Ok(())
}

/// Validate one item and append its events, in input order. Any error becomes
/// a whole-batch issue: the caller drops the transaction uncommitted, so the
/// batch commits all or nothing.
#[allow(clippy::too_many_arguments)]
async fn apply_item_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    schema_rows: &[crate::query::cascade::SchemaConfigRow],
    key: &Option<String>,
    state: &mut BatchState,
    act_alloc: &mut crate::act::ActAllocation,
    index: usize,
    item: &BatchItem,
) -> std::result::Result<(), BatchIssue> {
    match item {
        BatchItem::Update {
            id,
            name,
            summary,
            maturity,
            home_id,
            facets,
            if_facets,
            if_maturity,
            if_home_id,
            if_body_digest,
            if_unmodified_since,
        } => {
            apply_update_item_in(
                db,
                tx,
                caller,
                schema_rows,
                key,
                state,
                act_alloc,
                index,
                item,
                id,
                name,
                summary,
                maturity,
                home_id,
                facets,
                if_facets,
                if_maturity,
                if_home_id,
                if_body_digest,
                if_unmodified_since,
            )
            .await
        }
        BatchItem::AddLink {
            source_id,
            target_id,
            relationship,
            note,
        } => {
            apply_add_link_item_in(
                db,
                tx,
                caller,
                key,
                state,
                act_alloc,
                index,
                item,
                source_id,
                target_id,
                relationship,
                note,
            )
            .await
        }
        BatchItem::Archive { id, archived } => {
            apply_archive_item_in(
                db,
                tx,
                caller,
                key,
                state,
                act_alloc,
                index,
                item,
                id,
                archived.unwrap_or(true),
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn apply_update_item_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    schema_rows: &[crate::query::cascade::SchemaConfigRow],
    key: &Option<String>,
    state: &mut BatchState,
    act_alloc: &mut crate::act::ActAllocation,
    index: usize,
    item: &BatchItem,
    id: &str,
    name: &Option<Value>,
    summary: &Option<Value>,
    maturity: &Option<Value>,
    home_id: &Option<String>,
    facets: &Option<Map<String, Value>>,
    if_facets: &Option<Map<String, Value>>,
    if_maturity: &Option<Value>,
    if_home_id: &Option<String>,
    if_body_digest: &Option<String>,
    if_unmodified_since: &Option<String>,
) -> std::result::Result<(), BatchIssue> {
    let invalid = |message: String| issue(index, item, "invalid", message);
    let conflict = |message: String| issue(index, item, "conflict", message);
    if let Some(value) = name {
        if value.is_null() {
            return Err(invalid(format!(
                "{TOOL}: 'name' cannot be null — set an empty string to clear it"
            )));
        }
        if !value.is_string() {
            return Err(invalid(format!(
                "{TOOL}: 'name' must be a string, got {value}"
            )));
        }
    }
    for (field, value) in [("summary", summary), ("maturity", maturity)] {
        if let Some(value) = value {
            if !matches!(value, Value::String(_) | Value::Null) {
                return Err(invalid(format!(
                    "{TOOL}: '{field}' must be a string or null, got {value}"
                )));
            }
        }
    }
    if let Some(value) = home_id {
        if value.is_empty() {
            return Err(invalid(format!(
                "{TOOL}: 'home_id' must name a live folder; clearing it is reserved to the engine root"
            )));
        }
    }
    require_workspace_rename_authority(TOOL, caller, id, name.as_ref())
        .map_err(|error| invalid(error.to_string()))?;
    let mut facet_sets = Vec::new();
    let mut facet_unsets = Vec::new();
    for (facet_key, facet_value) in facets.iter().flatten() {
        match parse_facet_entry(TOOL, facet_key, facet_value, true)
            .map_err(|error| invalid(error.to_string()))?
        {
            Some(facet) => facet_sets.push(facet),
            None => facet_unsets.push(facet_key.clone()),
        }
    }
    let row = sqlx::query(
        "SELECT type, kind, maturity, home_id, body, name, summary, updated_at
           FROM records WHERE id = ? AND deleted_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| invalid(error.to_string()))?;
    let Some(row) = row else {
        return Err(issue(
            index,
            item,
            "unavailable",
            "record is unavailable".into(),
        ));
    };
    let record_type: String = row
        .try_get("type")
        .map_err(|error| invalid(error.to_string()))?;
    let kind: Option<String> = row
        .try_get("kind")
        .map_err(|error| invalid(error.to_string()))?;
    let current_maturity: Option<String> = row
        .try_get("maturity")
        .map_err(|error| invalid(error.to_string()))?;
    let current_home: Option<String> = row
        .try_get("home_id")
        .map_err(|error| invalid(error.to_string()))?;
    let current_body: Option<String> = row
        .try_get("body")
        .map_err(|error| invalid(error.to_string()))?;
    let current_name: Option<String> = row
        .try_get("name")
        .map_err(|error| invalid(error.to_string()))?;
    let current_summary: Option<String> = row
        .try_get("summary")
        .map_err(|error| invalid(error.to_string()))?;
    let current_updated: String = row
        .try_get("updated_at")
        .map_err(|error| invalid(error.to_string()))?;
    if facets.as_ref().is_some_and(|facets| {
        facets.contains_key(crate::message_expectation::EXPECTATION_FACET_KEY)
    }) && record_type == "Message"
    {
        return Err(invalid(
            "update_record: Message expectation is immutable sender-authored content; create a superseding Message to correct it"
                .into(),
        ));
    }
    let mut governed_sets = facet_sets.clone();
    assert_facet_value_predicates_in(
        tx,
        schema_rows,
        TOOL,
        &record_type,
        kind.as_deref(),
        None,
        &mut governed_sets,
    )
    .await
    .map_err(|error| invalid(error.to_string()))?;

    let mut expected_sets = Vec::new();
    let mut expected_absent = Vec::new();
    for (facet_key, facet_value) in if_facets.iter().flatten() {
        match parse_facet_entry(TOOL, facet_key, facet_value, true)
            .map_err(|error| invalid(error.to_string()))?
        {
            Some(facet) => expected_sets.push(facet),
            None => expected_absent.push(facet_key.clone()),
        }
    }
    let mut governed_expected = expected_sets.clone();
    assert_facet_value_predicates_in(
        tx,
        schema_rows,
        TOOL,
        &record_type,
        kind.as_deref(),
        None,
        &mut governed_expected,
    )
    .await
    .map_err(|error| invalid(error.to_string()))?;
    for expected in &governed_expected {
        let current = facet_state_in(tx, id, &expected.key)
            .await
            .map_err(|error| invalid(error.to_string()))?;
        if current.as_ref() != Some(&(expected.stored_value(), expected.vocab_ref.clone())) {
            return Err(conflict(format!(
                "facet '{}' no longer has the expected current value",
                expected.key
            )));
        }
    }
    for facet_key in &expected_absent {
        if facet_state_in(tx, id, facet_key)
            .await
            .map_err(|error| invalid(error.to_string()))?
            .is_some()
        {
            return Err(conflict(format!("facet '{facet_key}' is no longer absent")));
        }
    }
    if let Some(expected) = if_maturity {
        let matches = match expected {
            Value::String(expected) => current_maturity.as_deref() == Some(expected.as_str()),
            Value::Null => current_maturity.is_none(),
            _ => {
                return Err(invalid(format!(
                    "{TOOL}: 'if_maturity' must be a string or null"
                )));
            }
        };
        if !matches {
            return Err(conflict(
                "maturity no longer has the expected current value".into(),
            ));
        }
    }
    if let Some(expected) = if_home_id {
        if current_home.as_deref() != Some(expected.as_str()) {
            return Err(conflict(
                "home_id no longer has the expected current value".into(),
            ));
        }
    }
    // Body operations are out of scope for M0, but the guards remain usable
    // as pure preconditions, resolved against current state in-transaction
    // exactly as the singular path resolves them.
    if let Some(expected) = if_body_digest {
        if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid(format!(
                "{TOOL}: 'if_body_digest' must be a 64-character hexadecimal SHA-256 digest"
            )));
        }
    }
    let target = BodyGuardTarget {
        id: id.to_string(),
        name: current_name.clone(),
        display_reference: None,
        body_digest: body_digest(current_body.as_deref()),
        updated_at: current_updated.clone(),
    };
    if let Some(expected) = if_body_digest {
        if !expected.eq_ignore_ascii_case(&target.body_digest) {
            return Err(conflict(stale_body_digest_error(TOOL, &target).to_string()));
        }
    }
    if let Some(expected_raw) = if_unmodified_since {
        let expected = chrono::DateTime::parse_from_rfc3339(expected_raw).map_err(|_| {
            invalid(format!(
                "{TOOL}: 'if_unmodified_since' must be an RFC3339 timestamp"
            ))
        })?;
        let current = chrono::DateTime::parse_from_rfc3339(&current_updated).map_err(|_| {
            invalid(format!(
                "{TOOL}: record {id} has an invalid stored updated_at timestamp"
            ))
        })?;
        if expected != current {
            return Err(conflict(
                stale_unmodified_since_error(TOOL, &target).to_string(),
            ));
        }
    }
    // Change detection follows the multi-target form (identical values are
    // skipped, the item reports unchanged) rather than the singular form.
    let mut fields = Map::new();
    if let Some(Value::String(desired)) = name {
        if current_name.as_deref() != Some(desired.as_str()) {
            fields.insert("name".into(), Value::String(desired.clone()));
        }
    }
    if let Some(desired) = summary {
        let changed = match desired {
            Value::String(desired) => current_summary.as_deref() != Some(desired.as_str()),
            Value::Null => current_summary.is_some(),
            _ => false,
        };
        if changed {
            fields.insert("summary".into(), desired.clone());
        }
    }
    if let Some(desired) = maturity {
        let changed = match desired {
            Value::String(desired) => current_maturity.as_deref() != Some(desired.as_str()),
            Value::Null => current_maturity.is_some(),
            _ => false,
        };
        if changed {
            fields.insert("maturity".into(), desired.clone());
        }
    }
    if let Some(desired) = home_id {
        if desired == id {
            return Err(invalid(format!(
                "{TOOL}: record {id} cannot be its own home"
            )));
        }
        if current_home.as_deref() != Some(desired.as_str()) {
            if require_record_in(tx, caller, TOOL, desired, Capability::Edit)
                .await
                .is_err()
            {
                return Err(issue(
                    index,
                    item,
                    "unavailable",
                    "record is unavailable".into(),
                ));
            }
            assert_home_target_in(tx, TOOL, desired)
                .await
                .map_err(|error| invalid(error.to_string()))?;
            let origin = sqlx::query(
                "SELECT status, origin_type, collection_id FROM message_origin_state WHERE message_id = ?",
            )
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(|error| invalid(error.to_string()))?;
            if origin.as_ref().is_some_and(|origin| {
                origin.try_get::<String, _>("status").ok().as_deref() == Some("declared")
                    && origin
                        .try_get::<Option<String>, _>("origin_type")
                        .ok()
                        .flatten()
                        .as_deref()
                        == Some("collection")
                    && origin
                        .try_get::<Option<String>, _>("collection_id")
                        .ok()
                        .flatten()
                        .as_deref()
                        != Some(desired.as_str())
            }) {
                return Err(invalid(
                    "a Collection-origin Message must remain filed in its authored Collection"
                        .into(),
                ));
            }
            assert_no_containment_cycle_in(tx, TOOL, id, desired)
                .await
                .map_err(|error| invalid(error.to_string()))?;
            fields.insert("home_id".into(), json!(desired));
            state.relocated.push(id.to_string());
        }
    }
    let mut changed_sets = Vec::new();
    for facet in governed_sets {
        let current = facet_state_in(tx, id, &facet.key)
            .await
            .map_err(|error| invalid(error.to_string()))?;
        if current.as_ref() != Some(&(facet.stored_value(), facet.vocab_ref.clone())) {
            changed_sets.push(facet);
        }
    }
    let mut changed_unsets = Vec::new();
    for facet_key in &facet_unsets {
        if facet_state_in(tx, id, facet_key)
            .await
            .map_err(|error| invalid(error.to_string()))?
            .is_some()
        {
            changed_unsets.push(facet_key.clone());
        }
    }
    if fields.is_empty() && changed_sets.is_empty() && changed_unsets.is_empty() {
        let previous_seq = previous_record_seq_in(tx, id)
            .await
            .map_err(|error| invalid(error.to_string()))?;
        state.results.push(json!({
            "index": index, "op": "update", "id": id,
            "status": "unchanged", "previous_seq": previous_seq,
        }));
        return Ok(());
    }
    let previous_seq = previous_record_seq_in(tx, id)
        .await
        .map_err(|error| invalid(error.to_string()))?;
    let mut outputs: Vec<ActionOutput> = Vec::new();
    let field_event = !fields.is_empty();
    if field_event {
        fields.insert("reason".into(), json!(&state.reason));
        if let Some(basis) = &state.basis {
            fields.insert("basis".into(), basis.clone());
        }
        let event = append_in(
            db,
            tx,
            AppendSpec {
                record_id: id.to_string(),
                event_type: "record.updated".into(),
                payload: Value::Object(fields),
                actor: Some(caller.actor().into()),
            },
            act_alloc,
        )
        .await
        .map_err(|error| invalid(error.to_string()))?;
        outputs.push(ActionOutput::content(event.id));
    }
    let mut first_facet = true;
    for facet in changed_sets {
        let mut spec = facet_set_spec(id, &facet, caller.actor());
        if !field_event && first_facet {
            spec.payload["reason"] = json!(&state.reason);
            if let Some(basis) = &state.basis {
                spec.payload["basis"] = basis.clone();
            }
        }
        first_facet = false;
        let event = append_in(db, tx, spec, act_alloc)
            .await
            .map_err(|error| invalid(error.to_string()))?;
        outputs.push(ActionOutput::content(event.id));
    }
    for facet_key in changed_unsets {
        let mut payload = json!({ "key": facet_key });
        if !field_event && first_facet {
            payload["reason"] = json!(&state.reason);
            if let Some(basis) = &state.basis {
                payload["basis"] = basis.clone();
            }
        }
        first_facet = false;
        let event = append_in(
            db,
            tx,
            AppendSpec {
                record_id: id.to_string(),
                event_type: "facet.unset".into(),
                payload,
                actor: Some(caller.actor().into()),
            },
            act_alloc,
        )
        .await
        .map_err(|error| invalid(error.to_string()))?;
        outputs.push(ActionOutput::content(event.id));
    }
    for warning in crate::domain_transaction::governed_alias_warnings_for_sets(
        &facet_sets,
        &record_type,
        kind.as_deref(),
    ) {
        state
            .warnings
            .push(crate::domain_transaction::index_warning_for_batch(
                index, id, warning,
            ));
    }
    attest_item_in(tx, key, index, &outputs)
        .await
        .map_err(|error| invalid(error.to_string()))?;
    state.changed += 1;
    state.results.push(json!({
        "index": index, "op": "update", "id": id,
        "status": "changed", "previous_seq": previous_seq,
    }));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn apply_add_link_item_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    key: &Option<String>,
    state: &mut BatchState,
    act_alloc: &mut crate::act::ActAllocation,
    index: usize,
    item: &BatchItem,
    source_id: &str,
    target_id: &str,
    relationship: &str,
    note: &Option<String>,
) -> std::result::Result<(), BatchIssue> {
    let invalid = |message: String| issue(index, item, "invalid", message);
    if relationship.trim().is_empty() {
        return Err(invalid(
            "link relationship must contain non-whitespace text".into(),
        ));
    }
    crate::surface_binding::refuse_reserved_surface_binding(TOOL, relationship)
        .map_err(|error| invalid(error.to_string()))?;
    crate::comments::assert_bearer_immutable_on(tx, TOOL, source_id, relationship)
        .await
        .map_err(|error| invalid(error.to_string()))?;
    let previous_seq = previous_record_seq_in(tx, source_id)
        .await
        .map_err(|error| invalid(error.to_string()))?;
    // Endpoints were authorized in the cohort pass, so this classification
    // read cannot meet a missing record; any failure is still reported as
    // unavailable rather than leaking which side is hidden.
    let owned = relationship_owned_in(tx, source_id, target_id, relationship)
        .await
        .map_err(|_| issue(index, item, "unavailable", "record is unavailable".into()))?;
    let mut outputs: Vec<ActionOutput> = Vec::new();
    if owned {
        let draft = match key {
            Some(key) => crate::provenance::reserve_detached_action_attestation(Some(item_digest(
                key, index,
            ))),
            None => crate::provenance::reserve_unkeyed_action_attestation(),
        }
        .map_err(|error| invalid(error.to_string()))?;
        let (_, relationship_outputs) =
            // The singular operation identity: the capability checked is
            // identical (edit source, view target), and the string lands in
            // the relationship event's auth digest and rationale, so only
            // "manage_links" keeps batch and singular events equivalent.
            crate::relationship::legacy::mutate_with_reserved_attestation_in(
                tx,
                caller,
                source_id,
                target_id,
                relationship,
                note.clone(),
                true,
                "manage_links",
                &draft,
                act_alloc,
            )
            .await
            .map_err(|error| invalid(error.to_string()))?;
        crate::provenance::issue_action_attestation_outputs_in(tx, draft, &relationship_outputs)
            .await
            .map_err(|error| invalid(error.to_string()))?;
        outputs.extend(relationship_outputs);
    } else {
        let mut payload = serde_json::to_value(LinkAddedPayload {
            id: None,
            source_id: source_id.to_string(),
            target_id: target_id.to_string(),
            relationship: relationship.to_string(),
            note: note.clone(),
        })
        .map_err(|error| invalid(error.to_string()))?;
        // The batch's reason and basis ride the item's event. The singular
        // link path carries neither (it takes no reason or sources); stamping
        // them here is the Q2 reading — one batch-level declaration applied
        // uniformly — and the projector ignores the extra keys.
        if let Some(object) = payload.as_object_mut() {
            object.insert("reason".into(), json!(&state.reason));
            if let Some(basis) = &state.basis {
                object.insert("basis".into(), basis.clone());
            }
        }
        let event = append_in(
            db,
            tx,
            AppendSpec {
                record_id: source_id.to_string(),
                event_type: "link.added".into(),
                payload,
                actor: Some(caller.actor().into()),
            },
            act_alloc,
        )
        .await
        .map_err(|error| invalid(error.to_string()))?;
        outputs.push(ActionOutput::content(event.id));
        attest_item_in(tx, key, index, &outputs)
            .await
            .map_err(|error| invalid(error.to_string()))?;
    }
    state.changed += 1;
    state.results.push(json!({
        "index": index, "op": "add_link", "id": source_id, "target_id": target_id,
        "status": "changed", "previous_seq": previous_seq,
    }));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn apply_archive_item_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    key: &Option<String>,
    state: &mut BatchState,
    act_alloc: &mut crate::act::ActAllocation,
    index: usize,
    item: &BatchItem,
    id: &str,
    want_archived: bool,
) -> std::result::Result<(), BatchIssue> {
    let invalid = |message: String| issue(index, item, "invalid", message);
    let previous_seq = previous_record_seq_in(tx, id)
        .await
        .map_err(|error| invalid(error.to_string()))?;
    let row = sqlx::query(
        "SELECT r.deleted_at,
                EXISTS (SELECT 1 FROM facet_values av
                         WHERE av.record_id = r.id AND av.key = ?) AS archived
           FROM records r WHERE r.id = ?",
    )
    .bind(crate::schema::ARCHIVED_FACET_KEY)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|error| invalid(error.to_string()))?;
    let Some(row) = row else {
        return Err(issue(
            index,
            item,
            "unavailable",
            "record is unavailable".into(),
        ));
    };
    if row
        .try_get::<Option<String>, _>("deleted_at")
        .map_err(|error| invalid(error.to_string()))?
        .is_some()
    {
        return Err(invalid(format!(
            "{TOOL}: record {id} is deleted (tombstoned)"
        )));
    }
    let is_archived = row
        .try_get::<i64, _>("archived")
        .map_err(|error| invalid(error.to_string()))?
        != 0;
    if is_archived == want_archived {
        state.results.push(json!({
            "index": index, "op": "archive", "id": id,
            "status": "unchanged", "previous_seq": previous_seq,
        }));
        return Ok(());
    }
    // Reason rides the facet payload exactly as the singular path carries
    // it; the batch basis rides beside it, which the fold ignores.
    let mut payload = if want_archived {
        json!({
            "key": crate::schema::ARCHIVED_FACET_KEY,
            "value": "true",
            "reason": &state.reason,
        })
    } else {
        json!({
            "key": crate::schema::ARCHIVED_FACET_KEY,
            "reason": &state.reason,
        })
    };
    if let Some(object) = payload.as_object_mut() {
        if let Some(basis) = &state.basis {
            object.insert("basis".into(), basis.clone());
        }
    }
    let event = append_in(
        db,
        tx,
        AppendSpec {
            record_id: id.to_string(),
            event_type: if want_archived {
                "facet.set"
            } else {
                "facet.unset"
            }
            .into(),
            payload,
            actor: Some(caller.actor().into()),
        },
        act_alloc,
    )
    .await
    .map_err(|error| invalid(error.to_string()))?;
    let outputs = vec![ActionOutput::content(event.id)];
    attest_item_in(tx, key, index, &outputs)
        .await
        .map_err(|error| invalid(error.to_string()))?;
    state.changed += 1;
    state.results.push(json!({
        "index": index, "op": "archive", "id": id,
        "status": "changed", "previous_seq": previous_seq,
    }));
    Ok(())
}

async fn attestation_outputs_in(
    tx: &mut Transaction<'static, Sqlite>,
    attestation_id: &str,
) -> Result<Vec<(String, String)>> {
    let rows = sqlx::query(
        "SELECT output_domain, output_event_id FROM provenance_action_outputs
          WHERE action_attestation_id = ? ORDER BY ordinal",
    )
    .bind(attestation_id)
    .fetch_all(&mut **tx)
    .await?;
    rows.iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("output_domain")?,
                row.try_get::<String, _>("output_event_id")?,
            ))
        })
        .collect()
}

/// Rebuild the original receipt from the attested batch. Per-item previous
/// seqs re-derive exactly: the highest content seq for the record below the
/// item's first attested event (in-batch predecessors included, since they
/// committed in order). Relationship-only and unchanged items read the
/// current content head, which no link append moves.
async fn rebuild_hit_receipt_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    args: &BatchWriteArgs,
    hit: &BatchHit,
) -> Result<Value> {
    let mut results = Vec::new();
    let mut changed = 0usize;
    let mut warnings = Vec::new();
    let mut acts = Vec::new();
    for (index, item) in args.items.iter().enumerate() {
        let (primary, target_id): (&str, Option<&str>) = match item {
            BatchItem::Update { id, .. } | BatchItem::Archive { id, .. } => (id, None),
            BatchItem::AddLink {
                source_id,
                target_id,
                ..
            } => (source_id, Some(target_id)),
        };
        let attestation = hit
            .found
            .iter()
            .find(|(i, _)| *i == index)
            .map(|(_, id)| id);
        let Some(attestation_id) = attestation else {
            let previous_seq = previous_record_seq_in(tx, primary).await?;
            let mut outcome = json!({
                "index": index, "op": item.op(), "id": primary,
                "status": "unchanged", "previous_seq": previous_seq,
            });
            if let Some(target) = target_id {
                outcome["target_id"] = json!(target);
            }
            results.push(outcome);
            continue;
        };
        let outputs = attestation_outputs_in(tx, attestation_id).await?;
        if outputs.is_empty() {
            return Err(Error::engine(format!(
                "{TOOL}: attested batch item {index} has no outputs"
            )));
        }
        let content_ids: Vec<&str> = outputs
            .iter()
            .filter(|(domain, _)| domain == "content")
            .map(|(_, id)| id.as_str())
            .collect();
        let previous_seq: Option<i64> = if content_ids.is_empty() {
            previous_record_seq_in(tx, primary).await?
        } else {
            let placeholders = content_ids
                .iter()
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(", ");
            let sql = format!("SELECT id, seq FROM content_events WHERE id IN ({placeholders})");
            let mut query = sqlx::query(&sql);
            for id in &content_ids {
                query = query.bind(id);
            }
            let rows = query.fetch_all(&mut **tx).await?;
            let first = rows
                .iter()
                .map(|row| row.try_get::<i64, _>("seq"))
                .collect::<std::result::Result<Vec<_>, _>>()?
                .into_iter()
                .min();
            let Some(first) = first else {
                return Err(Error::engine(format!(
                    "{TOOL}: attested batch item {index} names missing events"
                )));
            };
            sqlx::query_scalar(
                "SELECT MAX(seq) FROM content_events WHERE record_id = ? AND seq < ?",
            )
            .bind(primary)
            .bind(first)
            .fetch_one(&mut **tx)
            .await?
        };
        if let BatchItem::Update { facets, .. } = item {
            let row = sqlx::query("SELECT type, kind FROM records WHERE id = ?")
                .bind(primary)
                .fetch_optional(&mut **tx)
                .await?;
            if let Some(row) = row {
                let record_type: String = row.try_get("type")?;
                let kind: Option<String> = row.try_get("kind")?;
                let mut sets = Vec::new();
                for (facet_key, facet_value) in facets.iter().flatten() {
                    if let Some(facet) = parse_facet_entry(TOOL, facet_key, facet_value, true)? {
                        sets.push(facet);
                    }
                }
                for warning in crate::domain_transaction::governed_alias_warnings_for_sets(
                    &sets,
                    &record_type,
                    kind.as_deref(),
                ) {
                    warnings.push(crate::domain_transaction::index_warning_for_batch(
                        index, primary, warning,
                    ));
                }
            }
        }
        acts.push(attested_act_in(&mut *tx, attestation_id).await?);
        changed += 1;
        let mut outcome = json!({
            "index": index, "op": item.op(), "id": primary,
            "status": "changed", "previous_seq": previous_seq,
        });
        if let Some(target) = target_id {
            outcome["target_id"] = json!(target);
        }
        results.push(outcome);
    }
    let mut receipt = json!({
        "requested": args.items.len(),
        "changed": changed,
        "unchanged": args.items.len() - changed,
        "results": results,
    });
    if !warnings.is_empty() {
        receipt["warnings"] = Value::Array(warnings);
    }
    let act = acts.into_iter().flatten().max();
    receipt = echo_act(receipt, act)?;
    attach_basis_feedback(
        db,
        caller,
        &mut receipt,
        args.sources.as_ref().map(Vec::len),
        true,
    )
    .await;
    Ok(receipt)
}
