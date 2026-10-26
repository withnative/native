//! The four Native context tools as labelled extensions on the HCP v2 host
//! (`hcp.withnative.ai`).
//!
//! HCP v2 defines five tools over the person's private entries. The
//! `/hcp` Layer 3 tools (`searchContext`, `traceContextItem`,
//! `proposeContextItem`, `resolveContextItem`) cover what the spec does not:
//! shared workspace context with provenance, applicability and supersession.
//! They are registered here under `native_` names, with descriptions that say
//! they are Native extensions and not part of HCP, by
//! [`register_hcp_v2_extensions`]. The implementations are the `/hcp` ones,
//! not copies; what differs on this host is decided here and read by those
//! implementations through [`on_hcp_v2_host`]:
//!
//! * **Opt-in.** The workspace gate is the host's own (`Resolution/hcp_entry`
//!   active), not `/hcp`'s `Resolution/preference`.
//! * **No HCP entry is ever read or returned.** An entry is the person's
//!   private context, and the spec tools alone decide what a client may see of
//!   it (redaction, pseudonyms, the minimization report). Every place the
//!   implementations load a record, resolve a reference or name a linked record
//!   drops `Resolution/hcp_entry` records, so an entry is "not found" here
//!   exactly as an unreadable record is, and never reaches the ranking model.
//! * **No per-client grants**, as on `/hcp`: the person's ordinary Native
//!   access, with the OAuth client id recorded for attribution only. A call
//!   with no client id is refused, as the spec tools do.
//! * **Ranking** is model-assisted only when a model key is configured and
//!   falls back to lexical order otherwise, as on `/hcp` (the response says
//!   which it used).
//!
//! Results are the tool's body, framed by the registry like any other tool's:
//! a refusal is `success: false` with a `code` and an `error`.

use serde_json::{json, Value};

use crate::db::Db;
use crate::error::Result;
use crate::mcp::interactions::{CustomInteractionPolicy, ToolExposure};
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::meta::kind::{resolve_on, KindClassification};

pub const NATIVE_SEARCH_CONTEXT: &str = "native_searchContext";
pub const NATIVE_TRACE_CONTEXT_ITEM: &str = "native_traceContextItem";
pub const NATIVE_PROPOSE_CONTEXT_ITEM: &str = "native_proposeContextItem";
pub const NATIVE_RESOLVE_CONTEXT_ITEM: &str = "native_resolveContextItem";

/// The extension tools, in `tools/list` order.
pub const EXTENSION_TOOL_NAMES: [&str; 4] = [
    NATIVE_SEARCH_CONTEXT,
    NATIVE_TRACE_CONTEXT_ITEM,
    NATIVE_PROPOSE_CONTEXT_ITEM,
    NATIVE_RESOLVE_CONTEXT_ITEM,
];

/// The kind the HCP v2 spec tools store entries in (`Resolution/hcp_entry`).
const ENTRY_TYPE: &str = "Resolution";
const ENTRY_KIND: &str = "hcp_entry";
/// Records of the stopped `/hcp` preference surface (`Resolution/preference`).
/// They are the person's old preferences, and the HCP v2 spec tools do not
/// know them; they are hidden here like entries.
const PREFERENCE_KIND: &str = "preference";
/// What the extensions never read or return on this host, as (type, kind).
const HIDDEN: [(&str, &str); 2] = [(ENTRY_TYPE, ENTRY_KIND), (ENTRY_TYPE, PREFERENCE_KIND)];

/// Error `code` for a workspace that has not enabled the HCP v2 interface,
/// the same word the spec tools use for the same refusal.
const NOT_CONFIGURED: &str = "native:not-configured";
/// Error `code` for a call no client can be held accountable for.
const NO_CLIENT: &str = "native:client-required";

tokio::task_local! {
    /// Set for the duration of an extension call. The `/hcp` implementations
    /// read it to apply the HCP v2 host's rules; outside it they behave as
    /// they always have.
    static HCP_V2_HOST: ();
}

/// Whether this call is an extension call on the HCP v2 host.
pub(super) fn on_hcp_v2_host() -> bool {
    HCP_V2_HOST.try_with(|_| ()).is_ok()
}

/// Whether a record of this type and kind must be hidden: it is an HCP v2
/// entry (or an old `/hcp` preference) and this is an extension call on the
/// HCP v2 host. A hidden record is treated exactly as an unreadable one:
/// never loaded, named, counted or linked to, and never sent to the ranking
/// model.
///
/// What is hidden is defined once, by [`hidden_sql`]; this is its cheap
/// in-memory half, for the part that needs no query (the record's own kind).
pub(super) fn hides(record_type: &str, kind: &str) -> bool {
    on_hcp_v2_host() && HIDDEN.contains(&(record_type, kind))
}

/// SQL boolean expression, over the `records` row `alias`, that is true when
/// that record is hidden from the extensions:
///
/// * its own type and kind are hidden (an HCP v2 entry, an old preference);
/// * it is the `/hcp` preference catalog document (a note marked by the
///   `hcp.role` facet, holding the old preference definitions); or
/// * it hangs off a hidden record, however deep: its bearer chain reaches one.
///
/// A bearer chain is Native's own: an `Annotation` (a comment, a reply to a
/// comment, a suggestion) or a `Document` of kind `attachment` is borne by the
/// record its `part_of` link names, and that bearer may itself be such a
/// record (this is the walk its visibility rules make, with the same depth
/// limit). A reply to a comment on an entry, an attachment on an entry and a
/// comment on that attachment are all hidden with the entry, because what they
/// say is the entry's private discussion. Records filed under a record by home
/// cannot be hidden this way: only folders can be a home, and no hidden record
/// is one. Semantic units never reach a generic read at all.
///
/// Constants only, so it can be spliced into a statement (and into the search
/// match query). Not host-gated: callers decide whether to apply it. The walk
/// is upwards from the one record, so its cost follows that record's own
/// bearer chain, not the size of the hidden set.
pub(super) fn hidden_sql(alias: &str) -> String {
    let kinds = |a: &str| {
        HIDDEN
            .iter()
            .map(|(record_type, kind)| {
                format!("({a}.type = '{record_type}' AND {a}.kind = '{kind}')")
            })
            .collect::<Vec<_>>()
            .join(" OR ")
    };
    let catalog = |a: &str, facet: &str| {
        format!(
            "EXISTS (SELECT 1 FROM facet_values {facet} WHERE {facet}.record_id = {a}.id \
             AND {facet}.key = '{role}' AND {facet}.value = '{catalog}')",
            role = super::store::FACET_ROLE,
            catalog = super::store::CATALOG_ROLE,
        )
    };
    format!(
        "({own_kind} OR {own_catalog} OR EXISTS (\
           WITH RECURSIVE hidden_walk(id, depth) AS (\
             SELECT {alias}.id, 0 \
             UNION \
             SELECT hidden_edge.target_id, hidden_walk.depth + 1 \
               FROM hidden_walk \
               JOIN records hidden_node ON hidden_node.id = hidden_walk.id \
               JOIN links hidden_edge ON hidden_edge.source_id = hidden_node.id \
                AND hidden_edge.relationship = 'part_of' \
              WHERE (hidden_node.type = 'Annotation' \
                     OR (hidden_node.type = 'Document' AND hidden_node.kind = 'attachment')) \
                AND hidden_walk.depth < {depth}) \
           SELECT 1 FROM hidden_walk JOIN records hidden_bearer ON hidden_bearer.id = hidden_walk.id \
            WHERE hidden_walk.depth > 0 \
              AND ({bearer_kind} OR {bearer_catalog})))",
        own_kind = kinds(alias),
        own_catalog = catalog(alias, "hidden_own_facet"),
        bearer_kind = kinds("hidden_bearer"),
        bearer_catalog = catalog("hidden_bearer", "hidden_bearer_facet"),
        depth = crate::authorization::MAX_DERIVED_BEARER_DEPTH,
    )
}

/// ` AND NOT (hidden)` over `alias` on the HCP v2 host, for appending to a
/// `WHERE`; empty elsewhere.
pub(super) fn host_exclusion_sql(alias: &str) -> String {
    if on_hcp_v2_host() {
        format!(" AND NOT {}", hidden_sql(alias))
    } else {
        String::new()
    }
}

/// The predicate to hand to search so hidden records are not hits at all
/// (before its candidate pool, its ranking and its caps); `None` off the HCP
/// v2 host.
pub(super) fn search_exclusion() -> Option<String> {
    on_hcp_v2_host().then(|| hidden_sql("r"))
}

/// Drop the hidden records from a loaded set (defence in depth after the
/// query-level exclusions, and the only line for a record loaded by id). If
/// the check cannot run, the error goes up and nothing is returned.
pub(super) async fn without_hidden(
    db: &Db,
    caller: &Caller,
    mut records: Vec<Value>,
) -> Result<Vec<Value>> {
    if !on_hcp_v2_host() {
        return Ok(records);
    }
    records.retain(|record| {
        let field = |key| record.get(key).and_then(Value::as_str).unwrap_or_default();
        !hides(field("type"), field("kind"))
    });
    let ids: Vec<String> = records
        .iter()
        .filter_map(|record| record.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let mut hidden = std::collections::HashSet::new();
    for chunk in ids.chunks(super::super::lifecycle::MAX_BATCH_GET) {
        let placeholders = (1..=chunk.len())
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        let outcome = super::super::querying::query_sql(
            db.clone(),
            caller.clone(),
            json!({
                "sql": format!(
                    "SELECT r.id AS id FROM records r WHERE r.id IN ({placeholders}) AND {}",
                    hidden_sql("r"),
                ),
                "parameters": chunk,
            }),
        )
        .await?;
        for row in outcome
            .get("rows")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = match row {
                Value::Object(map) => map.get("id").and_then(Value::as_str),
                Value::Array(cells) => cells.first().and_then(Value::as_str),
                _ => None,
            };
            if let Some(id) = id {
                hidden.insert(id.to_string());
            }
        }
    }
    records.retain(|record| {
        !record
            .get("id")
            .and_then(Value::as_str)
            .is_some_and(|id| hidden.contains(id))
    });
    Ok(records)
}

/// What a refused creation says: the person's own context is written with the
/// spec tools, not proposed through this one.
pub(super) fn hidden_destination_refusal() -> &'static str {
    "that kind holds the person's own HCP context and is not created through this tool: write it with hcp_addPreference"
}

/// Whether a record about to be created in this type and kind would be a
/// hidden one. A kind can be named by a deprecated alias, so the canonical
/// kind is resolved first and both are checked.
pub(super) async fn is_hidden_destination(db: &Db, record_type: &str, kind: &str) -> Result<bool> {
    if !on_hcp_v2_host() {
        return Ok(false);
    }
    let mut conn = db.pool().acquire().await?;
    let resolution = resolve_on(&mut conn, record_type, kind).await?;
    let canonical = resolution.canonical_kind.as_deref().unwrap_or(kind);
    Ok(hides(record_type, kind) || hides(record_type, canonical))
}

/// Where `/hcp` says a preference is proposed with `mutatePreferences`, this
/// host says what is true here: the person's preferences are HCP entries,
/// which the spec tools write.
pub(super) fn preference_pointer(hcp: &'static str) -> &'static str {
    if on_hcp_v2_host() {
        "preferences are not context items here: the person's own preferences are HCP entries, written with hcp_addPreference"
    } else {
        hcp
    }
}

/// The refusal body when `Resolution/hcp_entry` is not an active kind in this
/// workspace, specific to the kind's current state. The `/hcp` implementations
/// call this, in place of their own opt-in check, on this host.
pub(super) async fn not_configured(db: &Db) -> Result<Option<Value>> {
    let mut conn = db.pool().acquire().await?;
    let resolution = resolve_on(&mut conn, ENTRY_TYPE, ENTRY_KIND).await?;
    let state = match resolution.classification {
        KindClassification::ActiveCanonical => return Ok(None),
        KindClassification::Proposed => {
            "the `hcp_entry` kind is proposed but has not been promoted, so a workspace \
             admin must promote it"
        }
        KindClassification::DeprecatedAlias | KindClassification::DeprecatedNonAlias => {
            "the `hcp_entry` kind has been deprecated, so a workspace admin must define \
             it again"
        }
        KindClassification::Unknown => {
            "the `hcp_entry` kind is not defined, so a workspace admin must define it \
             (propose it in the kind:Resolution vocabulary, then promote it)"
        }
    };
    Ok(Some(super::failure(
        NOT_CONFIGURED,
        format!("HCP is not enabled in this workspace: {state}."),
    )))
}

// ---- descriptions and schemas ---------------------------------------------

/// The `/hcp` tool an extension is, by name.
fn hcp_name(name: &str) -> &'static str {
    match name {
        NATIVE_SEARCH_CONTEXT => super::SEARCH_CONTEXT,
        NATIVE_TRACE_CONTEXT_ITEM => super::TRACE_CONTEXT_ITEM,
        NATIVE_PROPOSE_CONTEXT_ITEM => super::PROPOSE_CONTEXT_ITEM,
        _ => super::RESOLVE_CONTEXT_ITEM,
    }
}

fn description(name: &str) -> &'static str {
    match name {
        NATIVE_SEARCH_CONTEXT => "Native extension, not part of HCP: it adds shared workspace context, which HCP does not cover. Finds decisions, facts, commitments and other records you can read that are relevant to a natural-language task, each with its provenance, its status (accepted, proposed or superseded) and what it supersedes. Candidates come only from authorised reads. Ranked by a model only when the server has a model key configured; then a request is sent to Anthropic containing the task text, the requested limit, fixed instructions, and for each candidate record its ref, kind, title, summary and status (the summary is the record's own, or an excerpt of its body, up to 500 characters, shorter when there are many candidates; titles up to 200). Nothing else about the records is sent. Without a key the order is lexical and nothing leaves the server. `ranking: lexical` can also come after a failed model request, so a request may have been sent even then; the response's `ranking` says which order was used. Never returns the person's HCP entries: use hcp_searchPreferences for those.",
        NATIVE_TRACE_CONTEXT_ITEM => "Native extension, not part of HCP: it adds provenance and supersession for shared workspace context, which HCP does not cover. Follows one context item through authorised reads: the item itself plus its evidence links, revision history and what it supersedes or is superseded by. Unreadable records are refused without revealing that they exist. The person's HCP entries are not context items here: use hcp_getPreference for those.",
        NATIVE_PROPOSE_CONTEXT_ITEM => "Native extension, not part of HCP: it adds proposals to shared workspace context, which HCP does not cover. Proposes a context item without making it current. With `target` ({ ref, expectedRevision }) it creates one Native suggestion on that record, anchored to the revision you read; Native refuses to apply it if the target has since changed. Without `target` it creates one new record of the given Type/kind at Native's `proposed` maturity (native_searchContext reports it as `proposed`, never accepted, until it is resolved), with its subject, appliesTo and evidence links written in the same call. Returns the proposal's ref. Never writes the person's HCP entries: use hcp_addPreference for those.",
        _ => "Native extension, not part of HCP: it adds supersession and acceptance for shared workspace context, which HCP does not cover. Accepts a proposed new item, or supersedes an accepted one by an existing replacement `{ ref }`, each as one atomic Native write; anything that could not be made atomic is refused and nothing is attempted. A change proposal (a suggestion on an existing record) is not resolved here: accept and reject answer RESOLVE_IN_NATIVE with the target record's url and change nothing, because the person resolves it in Native. Permission is Native's own: you can resolve what your access lets you edit, and the item records who accepted it. Outcomes: accepted, superseded, conflict (nothing changed; STALE_REVISION carries the current revision), refused (nothing changed), unconfirmed (the write may have landed: re-read before retrying).",
    }
}

/// The `/hcp` input schema, minus its pointers to `/hcp`-only tools.
fn input_schema(name: &str) -> Value {
    let mut schema = super::input_schema(hcp_name(name)).to_string();
    for (from, to) in [
        (" A preference is proposed with mutatePreferences.", ""),
        (
            "Not supported: a preference value is proposed with mutatePreferences.",
            "Not supported.",
        ),
    ] {
        schema = schema.replace(from, to);
    }
    serde_json::from_str(&schema).expect("a schema stays JSON")
}

fn is_mutator(name: &str) -> bool {
    matches!(
        name,
        NATIVE_PROPOSE_CONTEXT_ITEM | NATIVE_RESOLVE_CONTEXT_ITEM
    )
}

/// MCP descriptors for the extension tools: what `tools/list` carries.
pub fn hcp_v2_extension_descriptors() -> Vec<Value> {
    EXTENSION_TOOL_NAMES
        .iter()
        .map(|name| {
            let mutator = is_mutator(name);
            let mut annotations = json!({ "readOnlyHint": !mutator, "openWorldHint": false });
            if mutator {
                annotations["idempotentHint"] = json!(false);
            }
            json!({
                "name": name,
                "description": description(name),
                "inputSchema": input_schema(name),
                "annotations": annotations,
            })
        })
        .collect()
}

// ---- registration -----------------------------------------------------------

/// Register the four extension tools in the HCP v2 registry, next to
/// `register_hcp_v2_tools`. They are extension tools like the spec ones: not
/// shipped-tool kinds, no record-interaction logging. The two readers never
/// write, so a frozen deployment keeps serving them; the proposer and
/// resolver are mutations.
///
/// Call this after the registry's link origins are set
/// (`copy_link_origins_from`): the tools read them here, once, to give record
/// URLs the deployment's origin, which registry dispatch does not do for tools
/// outside its own set.
pub fn register_hcp_v2_extensions(registry: &mut ToolRegistry) -> Result<()> {
    let origin = registry
        .share_origin()
        .or_else(|| registry.public_origin())
        .map(str::to_string);
    macro_rules! register {
        ($name:expr, $handler:path) => {
            registry.register_custom(
                $name,
                CustomInteractionPolicy::NoRecordInteractions,
                ToolExposure::extension(true),
                description($name),
                input_schema($name),
                {
                    let origin = origin.clone();
                    move |db: Db, caller: Caller, arguments: Value| {
                        let origin = origin.clone();
                        async move { run(db, caller, origin, $handler, arguments).await }
                    }
                },
            )?
        };
    }
    register!(NATIVE_SEARCH_CONTEXT, super::context_search::search_context);
    register!(
        NATIVE_TRACE_CONTEXT_ITEM,
        super::context_trace::trace_context_item
    );
    register!(
        NATIVE_PROPOSE_CONTEXT_ITEM,
        super::context_write::propose_context_item
    );
    register!(
        NATIVE_RESOLVE_CONTEXT_ITEM,
        super::context_write::resolve_context_item
    );
    for name in [NATIVE_SEARCH_CONTEXT, NATIVE_TRACE_CONTEXT_ITEM] {
        registry.declare_read_only(name)?;
    }
    Ok(())
}

/// Run one `/hcp` implementation under the HCP v2 host's rules. The result is
/// the tool's body, framed by the registry like any other tool's (a refusal is
/// `success: false` with a `code` and an `error`). Only deployment fences
/// escape as `Err`.
async fn run<F, Fut>(
    db: Db,
    caller: Caller,
    origin: Option<String>,
    handler: F,
    arguments: Value,
) -> Result<Value>
where
    F: FnOnce(Db, Caller, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value>>,
{
    // A call no client can be held accountable for is refused, whatever it
    // asks (HCP v2 §3.11, invariant 5), as it is for the spec tools.
    if caller.oauth_client_id().is_none() {
        return Ok(super::failure(
            NO_CLIENT,
            "This request names no client, so it cannot be attributed.",
        ));
    }
    let mut body = HCP_V2_HOST
        .scope((), handler(db, caller, arguments))
        .await?;
    super::absolutize_record_urls(
        &|path| origin.as_ref().map(|origin| format!("{origin}{path}")),
        &mut body,
    );
    Ok(body)
}
