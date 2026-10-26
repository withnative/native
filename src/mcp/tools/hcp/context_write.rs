//! `proposeContextItem` and `resolveContextItem` (slice 4b, Layer 3 writes).
//!
//! **The rule for every write here: one atomic, guarded Native operation.**
//! No write is followed by a check that could undo it, nothing is ever
//! compensated, and a failure after a write may have committed is reported as
//! unconfirmed, never as "nothing changed". What each operation is made of:
//!
//! | Operation | The one Native call | What makes it atomic |
//! |---|---|---|
//! | propose, with `target` | `create_record` of an `Annotation/suggestion` | One call. The digest precondition travels in the record's own facets and the engine enforces it when the suggestion is resolved. |
//! | propose, new item | `create_record` at `maturity: proposed`, with every link in `links` | One call; the record and its links commit together. |
//! | accept a proposed record | `update_record` to `maturity: decided` | `if_unmodified_since` (the `updated_at` of the read the revision was checked against) is checked inside the write transaction; Native refuses with a `Conflict` if the record moved. |
//! | supersede | `batch_write` of two items | The batch commits all or nothing: the old record's update (carrying `if_body_digest` and `if_unmodified_since`) and the replacement's `supersedes` link. |
//!
//! A change proposal (a suggestion) is **not** resolved here: Native's
//! `resolve_suggestions` cannot guard the proposal record and flushes a live
//! session in a transaction of its own, so accept and reject answer
//! `RESOLVE_IN_NATIVE`. Once a write call is invoked, any error but a certified
//! pre-write one (`Conflict`, the read-only fence) is reported as unconfirmed.
//!
//! Anything Native has no atomic guard for is refused with a stated code and
//! nothing attempted (see the module docs in `docs/hosted-mcp.md`).
//!
//! Permission is Native's own, nothing added: a caller (person or agent) may
//! resolve wherever their access allows, and the provenance says who acted.

use serde_json::{json, Map, Value};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;

use super::context_item::{self, short_ref};
use super::extensions::preference_pointer;
use super::store::{
    cell, optional_text, sha256_hex, text, Committed, Store, FACET_CLIENT, FACET_CORRELATION,
    FACET_PERSON,
};
use super::{failure, fault, pause, refused_if_not_configured};

/// Longest statement accepted: a decision or rule, not a document.
const STATEMENT_MAX_CHARS: usize = 8_000;
/// Longest reason accepted on a resolution.
const REASON_MAX_CHARS: usize = 2_000;
/// Longest title derived from a statement.
const TITLE_MAX_CHARS: usize = 120;
/// Links of each kind one proposal may carry.
const LINKS_MAX: usize = 20;
/// Longest evidence text.
const EVIDENCE_TEXT_MAX_CHARS: usize = 2_000;

/// Test pause points: between the last read and the guarded write, where a
/// concurrent Native edit would land.
pub(super) const PAUSE_BEFORE_RESOLVE_WRITE: &str = "context_resolve_before_write";
/// Test fault point just after a write has committed: an error here is an
/// error after a committed write, which must read as unconfirmed.
pub(super) const FAULT_AFTER_WRITE: &str = "context_written";

// ---- shared pieces ------------------------------------------------------

/// The refusal for a record the caller cannot read, identical to one that does
/// not exist.
fn not_found() -> Value {
    json!({ "success": false, "code": "NOT_FOUND", "error": "Context item not found" })
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Whether the caller may edit `id`, asked of Native's own authorisation
/// before anything is written. A refusal here can only ever refuse; once a write
/// has been invoked no error is read as a permission refusal.
async fn may_edit(store: &Store<'_>, id: &str) -> Result<bool> {
    match super::super::require_record(
        store.db,
        store.caller,
        "resolveContextItem",
        id,
        crate::authorization::Capability::Edit,
    )
    .await
    {
        Ok(()) => Ok(true),
        Err(Error::Engine(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

/// The record fields these tools decide on, read through the caller's own
/// authorised `query_sql`.
#[derive(Clone, Debug)]
struct RecordState {
    id: String,
    record_type: String,
    kind: String,
    body: String,
    maturity: Option<String>,
    archived: bool,
    updated_at: String,
}

impl RecordState {
    /// The revision callers pass back: the digest `if_body_digest` checks.
    fn revision(&self) -> String {
        sha256_hex(&self.body)
    }

    fn is_suggestion(&self) -> bool {
        self.record_type == "Annotation" && self.kind == "suggestion"
    }

    fn is_proposed(&self) -> bool {
        self.maturity.as_deref() == Some("proposed")
    }

    /// An accepted context item: a record at `decided` maturity or any
    /// `Resolution` that is not proposed or superseded. Suggestions, archived
    /// records and preferences are not items that are accepted or superseded
    /// this way.
    fn is_accepted(&self) -> bool {
        !self.archived
            && !self.is_suggestion()
            && !(self.record_type == "Resolution" && self.kind == "preference")
            && !matches!(self.maturity.as_deref(), Some("proposed" | "superseded"))
            && (self.maturity.as_deref() == Some("decided") || self.record_type == "Resolution")
    }
}

async fn record_state(store: &Store<'_>, id: &str) -> Result<Option<RecordState>> {
    let (columns, rows) = store
        .query(
            &format!(
                "SELECT id, type, kind, body, maturity, archived, updated_at \
                   FROM records r WHERE r.id = ?1 AND r.deleted_at IS NULL{}",
                super::extensions::host_exclusion_sql("r"),
            ),
            vec![json!(id)],
        )
        .await?;
    Ok(rows.first().map(|row| RecordState {
        id: text(row, &columns, "id"),
        record_type: text(row, &columns, "type"),
        kind: text(row, &columns, "kind"),
        body: text(row, &columns, "body"),
        maturity: optional_text(row, &columns, "maturity").filter(|value| !value.is_empty()),
        archived: cell(row, &columns, "archived").is_some_and(|value| {
            value.as_bool() == Some(true) || value.as_i64().is_some_and(|flag| flag != 0)
        }),
        updated_at: text(row, &columns, "updated_at"),
    }))
}

/// A caller-supplied reference, resolved to a record the caller can read.
/// `None` for a missing, ambiguous or unreadable reference alike.
async fn resolve_readable(store: &Store<'_>, reference: &str) -> Result<Option<RecordState>> {
    let id = match super::context_search::resolve_input_ref(store.db, store.caller, reference).await
    {
        Ok(Some(id)) => id,
        Ok(None) | Err(Error::Engine(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    record_state(store, &id).await
}

/// The record a suggestion is `part_of`, when it has exactly one and the caller
/// can read it.
async fn suggestion_target(store: &Store<'_>, id: &str) -> Result<Option<RecordState>> {
    let (columns, rows) = store
        .query(
            "SELECT target_id FROM links WHERE source_id = ?1 AND relationship = 'part_of' \
              ORDER BY target_id LIMIT 2",
            vec![json!(id)],
        )
        .await?;
    let target = if rows.len() == 1 {
        optional_text(&rows[0], &columns, "target_id")
    } else {
        None
    };
    match target {
        Some(target) => record_state(store, &target).await,
        None => Ok(None),
    }
}

/// Whether anything readable already supersedes `id`.
async fn has_successor(store: &Store<'_>, id: &str) -> Result<bool> {
    let (_, rows) = store
        .query(
            &format!(
                "SELECT 1 AS found FROM links l JOIN records s ON s.id = l.source_id \
                  WHERE l.target_id = ?1 AND l.relationship = 'supersedes'{} LIMIT 1",
                super::extensions::host_exclusion_sql("s"),
            ),
            vec![json!(id)],
        )
        .await?;
    Ok(!rows.is_empty())
}

/// The `ContextItem` for a record after a write, or `None` when it cannot be
/// built: a write that already committed is never turned into an error by a
/// failed read-back.
async fn item_for(db: &Db, caller: &Caller, id: &str) -> Option<Value> {
    let traced = super::context_trace::trace_context_item(
        db.clone(),
        caller.clone(),
        json!({ "ref": id, "include": [] }),
    )
    .await
    .ok()?;
    traced.get("item").cloned()
}

async fn short_reference(store: &Store<'_>, id: &str) -> String {
    match store.context(&[id.to_string()]).await {
        Ok(context) => short_ref(&context.references, id),
        Err(_) => id.to_string(),
    }
}

// ---- proposeContextItem -------------------------------------------------

/// A refusal before anything was written.
fn propose_refusal(code: &str, error: impl Into<String>) -> Value {
    let mut body = failure(code, error);
    body["changed"] = json!(false);
    body
}

/// The write may have landed.
fn propose_uncertain() -> Value {
    let mut body = failure(
        "OUTCOME_UNCERTAIN",
        "The proposal may or may not have been created; search for it before retrying",
    );
    body["changed"] = Value::Null;
    body
}

struct EvidenceIn {
    reference: Option<String>,
    text: Option<String>,
}

struct ProposeArgs {
    kind: Option<String>,
    statement: String,
    subject: Option<String>,
    applies_to: Vec<String>,
    evidence: Vec<EvidenceIn>,
    target: Option<(String, String)>,
}

fn string_field(map: &Map<String, Value>, key: &str) -> std::result::Result<Option<String>, Value> {
    match map.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(_) => Err(propose_refusal(
            "INVALID_CONTEXT_INPUT",
            format!("{key} must be a non-empty string"),
        )),
    }
}

fn parse_propose(arguments: &Value) -> std::result::Result<ProposeArgs, Value> {
    let invalid = |message: &str| propose_refusal("INVALID_CONTEXT_INPUT", message);
    let args = arguments
        .as_object()
        .ok_or_else(|| invalid("arguments must be an object"))?;
    let statement =
        string_field(args, "statement")?.ok_or_else(|| invalid("statement is required"))?;
    if statement.chars().count() > STATEMENT_MAX_CHARS {
        return Err(invalid(&format!(
            "statement is longer than {STATEMENT_MAX_CHARS} characters"
        )));
    }
    if args.get("value").is_some_and(|value| !value.is_null()) {
        return Err(invalid(if super::extensions::on_hcp_v2_host() {
            "value is not supported here: put the content in statement"
        } else {
            "value is not supported here: a preference is proposed with mutatePreferences (SUGGEST_PREFERENCE); put the content in statement"
        }));
    }
    let mut applies_to = Vec::new();
    match args.get("appliesTo") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                match item.as_str().filter(|item| !item.trim().is_empty()) {
                    Some(item) => applies_to.push(item.to_string()),
                    None => return Err(invalid("appliesTo must be an array of references")),
                }
            }
        }
        Some(_) => return Err(invalid("appliesTo must be an array of references")),
    }
    let mut evidence = Vec::new();
    match args.get("evidence") {
        None | Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            for item in items {
                let entry = item
                    .as_object()
                    .ok_or_else(|| invalid("evidence entries must be objects"))?;
                let reference = string_field(entry, "ref")?;
                let text = string_field(entry, "text")?;
                if reference.is_none() && text.is_none() {
                    return Err(invalid("each evidence entry needs a ref or a text"));
                }
                if text
                    .as_deref()
                    .is_some_and(|text| text.chars().count() > EVIDENCE_TEXT_MAX_CHARS)
                {
                    return Err(invalid(&format!(
                        "evidence text is longer than {EVIDENCE_TEXT_MAX_CHARS} characters"
                    )));
                }
                evidence.push(EvidenceIn { reference, text });
            }
        }
        Some(_) => return Err(invalid("evidence must be an array")),
    }
    if applies_to.len() > LINKS_MAX || evidence.len() > LINKS_MAX {
        return Err(invalid(&format!(
            "appliesTo and evidence take at most {LINKS_MAX} entries each"
        )));
    }
    let target = match args.get("target") {
        None | Some(Value::Null) => None,
        Some(Value::Object(target)) => {
            let reference =
                string_field(target, "ref")?.ok_or_else(|| invalid("target.ref is required"))?;
            let expected = string_field(target, "expectedRevision")?
                .ok_or_else(|| invalid("target.expectedRevision is required"))?;
            if !is_sha256_hex(&expected) {
                return Err(invalid(
                    "target.expectedRevision must be the revision you read: a 64-character hex digest",
                ));
            }
            Some((reference, expected.to_ascii_lowercase()))
        }
        Some(_) => return Err(invalid("target must be an object")),
    };
    Ok(ProposeArgs {
        kind: string_field(args, "kind")?,
        statement,
        subject: string_field(args, "subject")?,
        applies_to,
        evidence,
        target,
    })
}

/// A requested kind as Native's own `type` and `kind`. Only `Resolution` and
/// `Document` records can be proposed; a preference is a Layer 1 record with a
/// definition and is proposed with `mutatePreferences`.
fn native_kind(requested: &str) -> std::result::Result<(String, String), Value> {
    let bad = |message: String| propose_refusal("INVALID_CONTEXT_INPUT", message);
    let (record_type, kind) = match requested.split_once('/') {
        Some((record_type, kind)) => (record_type.to_string(), kind.to_string()),
        None => match requested {
            "decision" | "rule" => ("Resolution".to_string(), requested.to_string()),
            "note" => ("Document".to_string(), requested.to_string()),
            "fact" => ("Document".to_string(), "finding".to_string()),
            "preference" => {
                return Err(bad(preference_pointer(
                    "a preference is proposed with mutatePreferences (SUGGEST_PREFERENCE), which keeps it attached to its definition",
                )
                .to_string()))
            }
            other => {
                return Err(bad(format!(
                    "kind {other:?} is not a Native Type/kind; use for example Resolution/decision, Resolution/rule or Document/note"
                )))
            }
        },
    };
    let token_ok = !kind.is_empty()
        && kind.len() <= 64
        && kind.starts_with(|c: char| c.is_ascii_lowercase())
        && kind
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
    if !matches!(record_type.as_str(), "Resolution" | "Document") || !token_ok {
        return Err(bad(format!(
            "kind {requested:?} cannot be proposed: only Resolution/<kind> and Document/<kind> records can"
        )));
    }
    if record_type == "Resolution" && kind == "preference" {
        return Err(bad(preference_pointer(
            "a preference is proposed with mutatePreferences (SUGGEST_PREFERENCE), which keeps it attached to its definition",
        )
        .to_string()));
    }
    Ok((record_type, kind))
}

fn title_of(statement: &str) -> String {
    let first = statement
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    context_item::truncate_chars(first, TITLE_MAX_CHARS)
}

/// The facets that record who proposed, exactly as Layer 1 writes them: the
/// account (hashed), the OAuth client, and the correlation of this call.
fn proposal_facets(store: &Store<'_>, args: &ProposeArgs) -> Map<String, Value> {
    let mut facets = Map::new();
    facets.insert(FACET_PERSON.into(), json!(store.person));
    facets.insert(FACET_CLIENT.into(), json!(store.client));
    facets.insert(FACET_CORRELATION.into(), json!(store.correlation_id));
    let texts: Vec<&str> = args
        .evidence
        .iter()
        .filter_map(|entry| entry.text.as_deref())
        .collect();
    if !texts.is_empty() {
        facets.insert(
            "hcp.evidence_text".into(),
            json!(serde_json::to_string(&texts).unwrap_or_default()),
        );
    }
    facets
}

/// One resolved link target the caller can read.
struct Linked {
    relationship: &'static str,
    id: String,
}

/// Resolve every reference the proposal names to a readable record. Any that is
/// missing, ambiguous or unreadable refuses the whole call with the same
/// `NOT_FOUND`, before anything is written.
async fn resolve_links(
    store: &Store<'_>,
    args: &ProposeArgs,
    with_subject_and_scope: bool,
) -> Result<std::result::Result<Vec<Linked>, Value>> {
    let mut links: Vec<Linked> = Vec::new();
    let mut push = |relationship: &'static str, id: String| {
        if !links
            .iter()
            .any(|link| link.relationship == relationship && link.id == id)
        {
            links.push(Linked { relationship, id });
        }
    };
    if with_subject_and_scope {
        if let Some(subject) = &args.subject {
            let Some(state) = resolve_readable(store, subject).await? else {
                return Ok(Err(propose_refusal("NOT_FOUND", "Context item not found")));
            };
            if state.record_type != "Entity" || state.kind != "person" {
                return Ok(Err(propose_refusal(
                    "INVALID_CONTEXT_INPUT",
                    "subject must be a person record",
                )));
            }
            push("subject", state.id);
        }
        for reference in &args.applies_to {
            let Some(state) = resolve_readable(store, reference).await? else {
                return Ok(Err(propose_refusal("NOT_FOUND", "Context item not found")));
            };
            push("applies_to", state.id);
        }
    }
    for entry in &args.evidence {
        if let Some(reference) = &entry.reference {
            let Some(state) = resolve_readable(store, reference).await? else {
                return Ok(Err(propose_refusal("NOT_FOUND", "Context item not found")));
            };
            push("evidence", state.id);
        }
    }
    Ok(Ok(links))
}

fn links_json(links: &[Linked]) -> Vec<Value> {
    links
        .iter()
        .map(|link| json!({ "target_id": link.id, "relationship": link.relationship }))
        .collect()
}

pub(super) async fn propose_context_item(
    db: Db,
    caller: Caller,
    arguments: Value,
) -> Result<Value> {
    if let Some(refusal) = refused_if_not_configured(&db).await? {
        return Ok(refusal);
    }
    let args = match parse_propose(&arguments) {
        Ok(args) => args,
        Err(body) => return Ok(body),
    };
    let store = Store::new(&db, &caller);
    let body = match &args.target {
        Some(target) => propose_change(&store, &args, target).await,
        None => propose_new(&store, &args).await,
    };
    match body {
        Ok(body) => Ok(body),
        // A write was issued and then something failed: it may have landed.
        Err(error) if store.outcome_uncertain() => {
            eprintln!("[native-ce] hcp: error after a proposal write was issued: {error}");
            Ok(propose_uncertain())
        }
        Err(error @ (Error::DeploymentReadOnly(_) | Error::DeploymentDraining(_))) => Err(error),
        Err(Error::Sqlx(sqlx::Error::PoolTimedOut)) => Err(Error::Sqlx(sqlx::Error::PoolTimedOut)),
        Err(error) => {
            eprintln!("[native-ce] hcp: propose error: {error}");
            Ok(propose_refusal("INTERNAL_ERROR", "Internal error"))
        }
    }
}

/// A proposed change to an existing record: one `Annotation/suggestion`,
/// created in one call, whose digest precondition is the revision the caller
/// read. The engine enforces it when the suggestion is resolved, so a target
/// that moves after this call makes the proposal stale rather than letting it
/// overwrite. The comparison below only declines to create a proposal that is
/// already stale; it guards nothing.
async fn propose_change(
    store: &Store<'_>,
    args: &ProposeArgs,
    (reference, expected): &(String, String),
) -> Result<Value> {
    if args.subject.is_some() || !args.applies_to.is_empty() {
        return Ok(propose_refusal(
            "INVALID_CONTEXT_INPUT",
            "subject and appliesTo describe a new item; a change proposal replaces the target's text and takes only evidence",
        ));
    }
    let Some(target) = resolve_readable(store, reference).await? else {
        return Ok(not_found());
    };
    if target.archived || target.is_suggestion() {
        return Ok(propose_refusal(
            "UNSUPPORTED_TARGET",
            "the target is archived or is itself a suggestion; propose against the record it is about",
        ));
    }
    let hcp_owned = {
        let facets = super::context_search::hcp_facets(
            store.db,
            store.caller,
            std::slice::from_ref(&target.id),
        )
        .await?;
        facets.get(&target.id).is_some_and(|facets| {
            facets.contains_key("hcp.role") || facets.contains_key("hcp.slug")
        })
    };
    if hcp_owned || (target.record_type == "Resolution" && target.kind == "preference") {
        return Ok(propose_refusal(
            "UNSUPPORTED_TARGET",
            "preferences and their catalog are changed with mutatePreferences (SUGGEST_PREFERENCE), which validates the value against its definition",
        ));
    }
    if let Some(kind) = &args.kind {
        let actual = format!("{}/{}", target.record_type, target.kind);
        let matches = native_kind(kind)
            .is_ok_and(|(record_type, kind)| format!("{record_type}/{kind}") == actual);
        if !matches {
            return Ok(propose_refusal(
                "INVALID_CONTEXT_INPUT",
                format!("kind does not match the target ({actual}); a proposal cannot change a record's kind"),
            ));
        }
    }
    let current = target.revision();
    if *expected != current {
        let mut refusal = propose_refusal(
            "STALE_REVISION",
            "expectedRevision is stale: the target changed since it was read; re-read it and propose again",
        );
        refusal["current"] = json!({ "revision": current });
        return Ok(refusal);
    }
    let links = match resolve_links(store, args, false).await? {
        Ok(links) => links,
        Err(refusal) => return Ok(refusal),
    };
    let mut facets = proposal_facets(store, args);
    facets.insert("proposal.precondition".into(), json!("digest"));
    facets.insert("anchor.base_digest".into(), json!(expected));
    let mut all_links = vec![json!({ "target_id": target.id, "relationship": "part_of" })];
    all_links.extend(links_json(&links));
    let created = Box::pin(super::super::lifecycle::create_record(
        store.db.clone(),
        store.caller.clone(),
        json!({
            "type": "Annotation",
            "kind": "suggestion",
            "lifecycle": "open",
            "body": args.statement,
            "links": all_links,
            "facets": facets,
            "reason": store.reason("proposeContextItem (change)"),
            "sources": [],
        }),
    ))
    .committed_strict(store)
    .await?;
    fault(FAULT_AFTER_WRITE)?;
    let id = Store::record_id(&created)?;
    let mut proposal = Map::new();
    proposal.insert("ref".into(), json!(short_reference(store, &id).await));
    proposal.insert("status".into(), json!("proposed"));
    proposal.insert(
        "targetRef".into(),
        json!(short_reference(store, &target.id).await),
    );
    Ok(proposed_body(proposal))
}

/// A new proposed item: one record of the requested Native `Type/kind` at
/// `maturity: proposed`, with its subject, scope and evidence links in the same
/// `create_record` call. Native's `proposed` maturity is a state of its own
/// that `searchContext` reports as `proposed` and never as `accepted`.
async fn propose_new(store: &Store<'_>, args: &ProposeArgs) -> Result<Value> {
    let Some(kind) = &args.kind else {
        return Ok(propose_refusal(
            "INVALID_CONTEXT_INPUT",
            "kind is required when proposing a new item",
        ));
    };
    let (record_type, kind) = match native_kind(kind) {
        Ok(kind) => kind,
        Err(refusal) => return Ok(refusal),
    };
    if super::extensions::is_hidden_destination(store.db, &record_type, &kind).await? {
        return Ok(propose_refusal(
            "INVALID_CONTEXT_INPUT",
            super::extensions::hidden_destination_refusal(),
        ));
    }
    let links = match resolve_links(store, args, true).await? {
        Ok(links) => links,
        Err(refusal) => return Ok(refusal),
    };
    let created = Box::pin(super::super::lifecycle::create_record(
        store.db.clone(),
        store.caller.clone(),
        json!({
            "type": record_type,
            "kind": kind,
            "name": title_of(&args.statement),
            "body": args.statement,
            "maturity": "proposed",
            "links": links_json(&links),
            "facets": proposal_facets(store, args),
            "reason": store.reason("proposeContextItem (new)"),
            "sources": [],
        }),
    ))
    .committed_strict(store)
    .await?;
    fault(FAULT_AFTER_WRITE)?;
    let id = Store::record_id(&created)?;
    let mut proposal = Map::new();
    proposal.insert("ref".into(), json!(short_reference(store, &id).await));
    proposal.insert("status".into(), json!("proposed"));
    Ok(proposed_body(proposal))
}

fn proposed_body(proposal: Map<String, Value>) -> Value {
    json!({ "success": true, "outcome": "proposed", "proposal": proposal })
}

// ---- resolveContextItem -------------------------------------------------

/// A resolution that did not happen, and nothing was changed.
fn refused(code: &str, error: impl Into<String>) -> Value {
    json!({
        "success": false,
        "outcome": "refused",
        "code": code,
        "error": error.into(),
        "changed": false,
    })
}

/// A resolution declined because the thing moved: nothing the caller asked for
/// was applied.
fn conflict(code: &str, error: impl Into<String>, current_revision: Option<String>) -> Value {
    let mut body = json!({
        "success": false,
        "outcome": "conflict",
        "code": code,
        "error": error.into(),
    });
    if let Some(revision) = current_revision {
        body["current"] = json!({ "revision": revision });
    }
    body
}

/// The write may have landed: the client must re-read, never retry blindly.
pub(super) fn unconfirmed() -> Value {
    json!({
        "success": false,
        "outcome": "unconfirmed",
        "code": "OUTCOME_UNCERTAIN",
        "error": "The resolution may or may not have been applied; re-read the item before retrying",
        "changed": null,
    })
}

struct ResolveArgs {
    reference: String,
    action: String,
    expected: Option<String>,
    replacement: Option<Replacement>,
    reason: String,
}

struct Replacement {
    reference: Option<String>,
    expected: Option<String>,
    inline: bool,
}

fn parse_resolve(arguments: &Value) -> std::result::Result<ResolveArgs, Value> {
    let invalid = |message: &str| refused("INVALID_CONTEXT_INPUT", message);
    let args = arguments
        .as_object()
        .ok_or_else(|| invalid("arguments must be an object"))?;
    let string = |key: &str| -> std::result::Result<Option<String>, Value> {
        match args.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
            Some(_) => Err(invalid(&format!("{key} must be a non-empty string"))),
        }
    };
    let reference = string("ref")?.ok_or_else(|| invalid("ref is required"))?;
    let action = string("action")?.ok_or_else(|| invalid("action is required"))?;
    if !matches!(action.as_str(), "accept" | "reject" | "supersede") {
        return Err(invalid("action must be accept, reject or supersede"));
    }
    let reason = string("reason")?.ok_or_else(|| invalid("reason is required"))?;
    if reason.chars().count() > REASON_MAX_CHARS {
        return Err(invalid(&format!(
            "reason is longer than {REASON_MAX_CHARS} characters"
        )));
    }
    let expected = string("expectedRevision")?;
    if expected
        .as_deref()
        .is_some_and(|value| !is_sha256_hex(value))
    {
        return Err(invalid(
            "expectedRevision must be the revision you read: a 64-character hex digest",
        ));
    }
    let replacement = match args.get("replacement") {
        None | Some(Value::Null) => None,
        Some(Value::Object(map)) => {
            let reference = match map.get("ref") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) if !value.trim().is_empty() => Some(value.clone()),
                Some(_) => return Err(invalid("replacement.ref must be a non-empty string")),
            };
            let expected = match map.get("expectedRevision") {
                None | Some(Value::Null) => None,
                Some(Value::String(value)) if is_sha256_hex(value) => {
                    Some(value.to_ascii_lowercase())
                }
                Some(_) => {
                    return Err(invalid(
                        "replacement.expectedRevision must be a 64-character hex digest",
                    ))
                }
            };
            Some(Replacement {
                inline: map.contains_key("statement")
                    || map.contains_key("value")
                    || map.contains_key("evidence"),
                reference,
                expected,
            })
        }
        Some(_) => return Err(invalid("replacement must be an object")),
    };
    Ok(ResolveArgs {
        reference,
        action,
        expected: expected.map(|value| value.to_ascii_lowercase()),
        replacement,
        reason,
    })
}

pub(super) async fn resolve_context_item(
    db: Db,
    caller: Caller,
    arguments: Value,
) -> Result<Value> {
    if let Some(refusal) = refused_if_not_configured(&db).await? {
        return Ok(refusal);
    }
    let args = match parse_resolve(&arguments) {
        Ok(args) => args,
        Err(body) => return Ok(body),
    };
    let store = Store::new(&db, &caller);
    let body = resolve(&store, &args).await;
    match body {
        Ok(body) => Ok(body),
        // A write was issued and then something failed: it may have landed.
        Err(error) if store.outcome_uncertain() => {
            eprintln!("[native-ce] hcp: error after a resolution write was issued: {error}");
            Ok(unconfirmed())
        }
        Err(error @ (Error::DeploymentReadOnly(_) | Error::DeploymentDraining(_))) => Err(error),
        Err(Error::Sqlx(sqlx::Error::PoolTimedOut)) => Err(Error::Sqlx(sqlx::Error::PoolTimedOut)),
        Err(error) => {
            eprintln!("[native-ce] hcp: resolve error: {error}");
            Ok(refused("INTERNAL_ERROR", "Internal error"))
        }
    }
}

async fn resolve(store: &Store<'_>, args: &ResolveArgs) -> Result<Value> {
    let Some(state) = resolve_readable(store, &args.reference).await? else {
        return Ok(json!({
            "success": false, "outcome": "refused", "code": "NOT_FOUND",
            "error": "Context item not found", "changed": false,
        }));
    };
    if state.is_suggestion() {
        return resolve_in_native(store, args, &state).await;
    }
    if state.archived {
        return Ok(refused("UNSUPPORTED_ITEM", "the item is archived"));
    }
    if state.record_type == "Resolution" && state.kind == "preference" {
        return Ok(refused(
            "UNSUPPORTED_ITEM",
            "a preference is revised in place with mutatePreferences; it is not accepted or superseded as a context item",
        ));
    }
    if state.is_proposed() {
        return match args.action.as_str() {
            "accept" => accept_proposed(store, args, &state).await,
            "reject" => Ok(refused(
                "UNSUPPORTED_ACTION",
                "a proposed new item cannot be rejected here: Native has no rejected state for a record, and archiving it would hide it rather than decide it",
            )),
            _ => Ok(refused(
                "UNSUPPORTED_ACTION",
                "a proposed item is not yet accepted, so there is nothing to supersede; accept it first",
            )),
        };
    }
    if !state.is_accepted() {
        return Ok(refused(
            "UNSUPPORTED_ITEM",
            "the item is not a proposal and not an accepted item that can be superseded",
        ));
    }
    match args.action.as_str() {
        "supersede" => supersede(store, args, &state).await,
        _ => Ok(refused(
            "UNSUPPORTED_ACTION",
            "the item is already accepted; supersede it with a replacement instead",
        )),
    }
}

/// A change proposal is not resolved over `/hcp`: Native's `resolve_suggestions`
/// cannot guard the proposal record itself, and it flushes a live co-editing
/// session in a transaction of its own before the guarded one, so a stale accept
/// could already have changed the stored body. Nothing is attempted: no read of
/// the proposal's precondition, no call to `resolve_suggestions`, so no
/// stale-marking and no flush. The person accepts or rejects it in Native, where
/// the slice 3 provenance records who did.
async fn resolve_in_native(
    store: &Store<'_>,
    args: &ResolveArgs,
    state: &RecordState,
) -> Result<Value> {
    if args.action == "supersede" {
        return Ok(refused(
            "UNSUPPORTED_ACTION",
            "a proposal is accepted or rejected in Native; it cannot be superseded",
        ));
    }
    let target = suggestion_target(store, &state.id).await?;
    let mut body = refused(
        "RESOLVE_IN_NATIVE",
        "A change proposal must be accepted or rejected in Native, not over /hcp. Nothing was attempted and nothing changed.",
    );
    if let Some(target) = target {
        let reference = short_reference(store, &target.id).await;
        body["error"] = json!(format!(
            "A change proposal must be accepted or rejected in Native, not over /hcp: open its target record at `/{reference}` and resolve it there. Nothing was attempted and nothing changed."
        ));
        body["target"] = json!({ "ref": reference, "url": format!("/{reference}") });
    }
    Ok(body)
}

fn resolved(outcome: &str, item: Option<Value>, superseded: Option<String>) -> Value {
    let mut body = json!({ "success": true, "outcome": outcome });
    if let Some(item) = item {
        body["item"] = item;
    }
    if let Some(superseded) = superseded {
        body["superseded"] = json!(superseded);
    }
    body
}

/// Why a guarded write that Native refused with a conflict was refused, read
/// from the record afterwards: a changed body is a stale revision, any other
/// change since the read is a concurrent change. The refusal itself is already
/// certain (the error is a `Conflict`, which Native raises before it writes); this
/// only describes it.
async fn explain_conflict(store: &Store<'_>, read: &RecordState, expected: &str) -> Result<Value> {
    Ok(match record_state(store, &read.id).await? {
        None => refused("NOT_FOUND", "Context item not found"),
        Some(now) if now.revision() != expected => conflict(
            "STALE_REVISION",
            "the item changed since it was read, so nothing was changed; re-read it",
            Some(now.revision()),
        ),
        Some(now) => conflict(
            "CONCURRENT_CHANGE",
            "the item was changed by someone else after it was read, so nothing was changed; re-read it",
            Some(now.revision()),
        ),
    })
}

/// Accept a proposed new item: one `update_record` to `maturity: decided`.
/// `expectedRevision` is compared with the body just read, and
/// `if_unmodified_since` carries the `updated_at` of that same read into the
/// write transaction, where Native refuses with a `Conflict` unless the record
/// has not been touched since (`updated_at` moves on every change, the body
/// included). So the record is accepted only if it is exactly as the caller saw
/// it, and a refusal is certain by its variant.
async fn accept_proposed(
    store: &Store<'_>,
    args: &ResolveArgs,
    state: &RecordState,
) -> Result<Value> {
    let Some(expected) = &args.expected else {
        return Ok(refused(
            "INVALID_CONTEXT_INPUT",
            "expectedRevision is required to accept",
        ));
    };
    if *expected != state.revision() {
        return Ok(conflict(
            "STALE_REVISION",
            "expectedRevision is stale: the item changed since it was read; re-read it",
            Some(state.revision()),
        ));
    }
    if !may_edit(store, &state.id).await? {
        return Ok(refused("MCP_PERMISSION_DENIED", "Permission denied"));
    }
    pause(PAUSE_BEFORE_RESOLVE_WRITE).await;
    let written = Box::pin(super::super::lifecycle::update_record(
        store.db.clone(),
        store.caller.clone(),
        json!({
            "id": state.id,
            "maturity": "decided",
            "if_unmodified_since": state.updated_at,
            "reason": format!("{} ({})", args.reason, store.reason("resolveContextItem accept")),
            "sources": [],
        }),
    ))
    .committed_strict(store)
    .await;
    match written {
        Ok(_) => {
            fault(FAULT_AFTER_WRITE)?;
            let item = item_for(store.db, store.caller, &state.id).await;
            Ok(resolved("accepted", item, None))
        }
        Err(Error::Conflict(_)) => explain_conflict(store, state, expected.as_str()).await,
        Err(error) => Err(error),
    }
}

/// Supersede an accepted item with a replacement that already exists.
///
/// `create_record` has no way to check that the old record is still at the
/// revision the caller read, so a replacement created inside this call could
/// only be checked afterwards, which is not allowed. Instead the replacement
/// must already exist, and one `batch_write` then does both of the following or
/// neither: marks the old record `superseded` (guarded by `if_body_digest` and
/// `if_unmodified_since`) and adds the replacement's `supersedes` link to it.
///
/// The replacement may be proposed or accepted: nothing about its state is
/// decided here, because anything read outside the transaction could be stale
/// by the time it commits. The read side reports its own status as it is, so a
/// superseded item whose successor is still `proposed` reads exactly that. The
/// replacement's own revision cannot be guarded (`batch_write` allows one
/// mutation per record, and a guarded update of the link's source would be a
/// second one), so `replacement.expectedRevision` is refused rather than
/// checked loosely.
async fn supersede(store: &Store<'_>, args: &ResolveArgs, old: &RecordState) -> Result<Value> {
    let Some(expected) = &args.expected else {
        return Ok(refused(
            "INVALID_CONTEXT_INPUT",
            "expectedRevision is required to supersede",
        ));
    };
    let replacement = match &args.replacement {
        Some(replacement) if !replacement.inline => replacement,
        Some(_) => {
            return Ok(refused(
                "UNSUPPORTED_INLINE_REPLACEMENT",
                "supersede takes a replacement that already exists: propose it with proposeContextItem, then pass { ref } here. Native cannot create a record and check the old one's revision in one atomic call, so an inline replacement is refused and nothing was created",
            ))
        }
        None => {
            return Ok(refused(
                "INVALID_CONTEXT_INPUT",
                "replacement is required to supersede: { ref } of an existing item",
            ))
        }
    };
    if replacement.expected.is_some() {
        return Ok(refused(
            "UNSUPPORTED_EXPECTED_REVISION",
            "replacement.expectedRevision is not supported: the replacement is only linked to, and Native's batch cannot also guard a record it links from. Omit it; nothing was attempted",
        ));
    }
    let Some(reference) = &replacement.reference else {
        return Ok(refused(
            "INVALID_CONTEXT_INPUT",
            "replacement.ref is required to supersede",
        ));
    };
    if has_successor(store, &old.id).await? {
        return Ok(refused(
            "ALREADY_SUPERSEDED",
            "the item already has a successor",
        ));
    }
    if *expected != old.revision() {
        return Ok(conflict(
            "STALE_REVISION",
            "expectedRevision is stale: the item changed since it was read; re-read it",
            Some(old.revision()),
        ));
    }
    let Some(new) = resolve_readable(store, reference).await? else {
        return Ok(json!({
            "success": false, "outcome": "refused", "code": "NOT_FOUND",
            "error": "Context item not found", "changed": false,
        }));
    };
    // Only what can never make sense: an item replacing itself, or something that
    // is not a context item at all (a proposal text or a preference value).
    if new.id == old.id
        || new.is_suggestion()
        || (new.record_type == "Resolution" && new.kind == "preference")
    {
        return Ok(refused(
            "INVALID_REPLACEMENT",
            "the replacement must be a different item, not a proposal or a preference",
        ));
    }
    if !may_edit(store, &old.id).await? || !may_edit(store, &new.id).await? {
        return Ok(refused("MCP_PERMISSION_DENIED", "Permission denied"));
    }
    pause(PAUSE_BEFORE_RESOLVE_WRITE).await;
    let written = Box::pin(super::super::batch_write::batch_write(
        store.db.clone(),
        store.caller.clone(),
        json!({
            "reason": format!("{} ({})", args.reason, store.reason("resolveContextItem supersede")),
            "items": [
                {
                    "op": "update", "id": old.id, "maturity": "superseded",
                    "if_body_digest": expected, "if_unmodified_since": old.updated_at,
                },
                {
                    "op": "add_link", "source_id": new.id, "target_id": old.id,
                    "relationship": "supersedes",
                },
            ],
        }),
    ))
    .committed_strict(store)
    .await;
    match written {
        Ok(_) => {
            fault(FAULT_AFTER_WRITE)?;
            let item = item_for(store.db, store.caller, &new.id).await;
            let old_ref = short_reference(store, &old.id).await;
            Ok(resolved("superseded", item, Some(old_ref)))
        }
        Err(Error::Conflict(_)) => explain_conflict(store, old, expected.as_str()).await,
        Err(error) => Err(error),
    }
}
